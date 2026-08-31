# shellcheck shell=bash
#
# Shared setup for the CI test drivers, tests/test.sh and tests/soak.sh. Sourcing
# this installs the "not on your own box" guard and the teardown trap; it does no
# real work until spire_setup is called.

LIBPATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${LIBPATH}/.." && pwd)"
SCRIPTPATH="${LIBPATH}"

SPIRE_SERVER_SOCKET=/run/spire/server/sockets/main/private/api.sock
SPIFFEFS_MOUNT=/tmp/mnt
SOAK_LOG_DIR=/tmp/soak-logs
SOAK_CLIENT=/usr/libexec/spiffefs-soak-client

# Set by start_spiffefs so teardown knows which log to dump.
SPIFFEFS_LOG=""

if [ "x${GITHUB_JOB}" != "x" ]; then
  echo "Running in GitHub"
else
  echo "Do not run this script on your own box."
  exit 1
fi

teardown() {
  echo ---------------------------
  if [ "$1" -ne 0 ]; then
    systemctl status spire-server@main || true
    systemctl status spire-controller-manager@main || true
    systemctl status spire-server@other || true
    systemctl status spire-agent@main || true
    sudo spire-server entry show || true
    for unit in test1 test2 test3 test4; do
      systemctl status "${unit}" || true
    done

    if [ -n "${SPIFFEFS_LOG}" ] && [ -f "${SPIFFEFS_LOG}" ]; then
      echo "--- tail of ${SPIFFEFS_LOG} ---"
      tail -n 200 "${SPIFFEFS_LOG}" || true
    fi

    # The soak leaves a log per workload. Only the failures are worth reading,
    # and soak.sh has already named them.
    if [ -s "${SOAK_LOG_DIR}/failed" ]; then
      echo "--- failed soak workloads ---"
      while read -r name; do
        echo "--- ${name} ---"
        cat "${SOAK_LOG_DIR}/${name}.log" || true
      done < "${SOAK_LOG_DIR}/failed"
    fi
  fi
}

trap 'EC=$? && trap - SIGTERM && teardown $EC' SIGINT SIGTERM EXIT

wait_for_healthcheck() {
  local app="$1"
  local socket="$2"
  local timeout=30
  local count=0
  while [ "$count" -lt "$timeout" ]; do
    rc=0
    sudo "$app" healthcheck -socketPath "$socket" || rc=$?
    if [ "$rc" -eq 0 ]; then
      return 0
    fi
    sleep 1
    ((count++)) || true
  done
  return 1
}

wait_for_trust_sync() {
  local socket="$1"
  local timeout=30
  local count=0
  while [ "$count" -lt "$timeout" ]; do
    entries=$(sudo spire-server bundle list -socketPath "$socket" | wc -l)
    if [ "$entries" -ne 0 ]; then
      return 0
    fi
    sleep 1
    ((count++)) || true
  done
  return 1
}

wait_for_jwt() {
  local socket="$1"
  local timeout=30
  local count=0
  while [ "$count" -lt "$timeout" ]; do
      rc=0
      sudo spire-agent api fetch jwt -audience test -socketPath "$socket" || rc=$?
      if [ "$rc" -eq 0 ]; then
        return 0
      fi
      sleep 1
      ((count++)) || true
  done
  return 1
}

# spire_setup installs and starts both SPIRE servers, the controller manager and
# the agent, and builds everything the drivers run. It leaves spiffefs itself
# stopped: which mode to start is the driver's call.
spire_setup() {
  # Get the package repo and install the packages. The package repo is published
  # per architecture, so take it from the machine rather than pinning one.
  DEB_ARCH="$(dpkg --print-architecture)"
  sudo curl -s -o /etc/apt/sources.list.d/spire-examples.list "https://raw.githubusercontent.com/spiffe/spire-examples/refs/heads/main/examples/debs/${DEB_ARCH}/spire-examples.list"
  sudo apt-get update
  sudo apt-get install -y spire-common spire-agent spire-server spire-controller-manager

  # Configure things
  sudo /bin/bash -c "echo SPIRE_BIND_PORT=8082 > /etc/spire/server/other.env"
  sudo /bin/bash -c "echo SPIFFE_TRUST_DOMAIN=other.org >> /etc/spire/server/other.env"
  sudo sed -i 's/spire-ha-agent/spiffefs/' /etc/spire/agent/default.conf

  # Enable the agent's Broker API endpoint and allowlist us on it. The packaged
  # config only wires up the delegated API, and broker mode is what spiffefs runs
  # by default. The block goes inside the agent block, so insert it before that
  # block's closing brace -- the first line in the file that is a bare "}".
  # ${SPIFFE_TRUST_DOMAIN} is left unexpanded on purpose: the agent runs with
  # -expandEnv and fills it in itself, exactly as it does for authorized_delegates.
  sudo awk '
    !inserted && /^}$/ {
      print "    experimental {"
      print "        broker {"
      print "            socket_path = \"/run/spire/agent/sockets/main/broker/broker.sock\""
      print "            brokers = ["
      print "                {"
      print "                    id = \"spiffe://${SPIFFE_TRUST_DOMAIN}/spiffefs\""
      print "                    allowed_reference_types = ["
      print "                        {"
      print "                            type_url = \"type.googleapis.com/spiffe.broker.WorkloadPIDReference\""
      print "                        },"
      print "                    ]"
      print "                },"
      print "            ]"
      print "        }"
      print "    }"
      inserted = 1
    }
    { print }
  ' /etc/spire/agent/default.conf > /tmp/agent-default.conf
  sudo cp /tmp/agent-default.conf /etc/spire/agent/default.conf
  cat /etc/spire/agent/default.conf

  # Startup the servers
  sudo systemctl start spire-server@main spire-server@other spire-controller-manager@main

  # Register some workloads with the spire server using manifests
  sudo mkdir -p /etc/spire/server/main/manifests/
  sudo cp "${SCRIPTPATH}/manifests"/* /etc/spire/server/main/manifests/

  # Startup servers and make sure they are ready
  wait_for_healthcheck spire-server "${SPIRE_SERVER_SOCKET}"
  wait_for_healthcheck spire-server /run/spire/server/sockets/other/private/api.sock

  sudo spire-server bundle show -instance other | sudo spire-server bundle set -id other.org

  sudo spire-server bundle list

  # Configure agent. For the test, create join tokens for both agents. You should really use a node attestor other then join tokens such as tpm-direct, http_challenge, or a cloud provider one
  JOIN_TOKEN=$(sudo spire-server token generate -spiffeID spiffe://example.org/agent/node1 | awk '{print "\""$2"\""}')
  export JOIN_TOKEN
  sudo /bin/bash -c "echo JOIN_TOKEN=${JOIN_TOKEN} > /etc/spire/agent/main.env"

  # Startup the agent. SPIRE creates the broker socket but not the directory it
  # lives in, and that directory may not be the one holding the workload API
  # socket, so it has to exist up front.
  sudo mkdir -p /run/spire/agent/sockets/main/broker
  sudo systemctl start spire-agent@main
  wait_for_healthcheck spire-agent /var/run/spire/agent/sockets/main/public/api.sock

  # Build the code. The soak client is a workload rather than a test binary, so
  # it gets installed where a systemd unit can exec it.
  (
    cd "${REPO_ROOT}" || exit 1
    go build -o spiffefs .
    go build -o /tmp/spiffefs-soak-client ./tests/soak
  )
  sudo install -m 0755 /tmp/spiffefs-soak-client "${SOAK_CLIENT}"

  mkdir -p "${SPIFFEFS_MOUNT}"
}

# Wait for what the tests actually need, rather than guessing at a duration. The
# mount appears within a second or two, but the trust bundles arrive separately:
# they come from a stream that backs off and retries, so credentials can be
# served before any bundle is. A fixed sleep raced that and failed on the slower
# runners.
wait_for_spiffefs() {
  local timeout=120
  local count=0
  while [ "${count}" -lt "${timeout}" ]; do
    if mountpoint -q "${SPIFFEFS_MOUNT}" &&
       [ -s "${SPIFFEFS_MOUNT}/hints.json" ] &&
       [ -s "${SPIFFEFS_MOUNT}/example.org.spiffe-trust-bundle.x509.pem" ]; then
      return 0
    fi
    sleep 2
    count=$((count + 2))
  done
  echo "spiffefs did not serve a trust bundle within ${timeout}s"
  ls -la "${SPIFFEFS_MOUNT}/" || true
  return 1
}

start_spiffefs() {
  local mode="$1"
  SPIFFEFS_LOG="/tmp/spiffefs-${mode}.log"
  : > "${SPIFFEFS_LOG}"

  # -umount so each run owns the mount point: it clears whatever the previous
  # mode left behind, and tears its own mount down on the way out.
  #
  # Tee rather than redirect: the job log still shows what spiffefs did, and the
  # soak's convergence check needs a file it can grep.
  sudo "${REPO_ROOT}/spiffefs" -umount -mode="${mode}" "${SPIFFEFS_MOUNT}" 2>&1 | tee -a "${SPIFFEFS_LOG}" &
  wait_for_spiffefs
}

stop_spiffefs() {
  # The shell's background job is sudo, not spiffefs, so signal the process
  # itself rather than the job.
  sudo pkill -TERM -x spiffefs || true

  local count=0
  while mountpoint -q "${SPIFFEFS_MOUNT}" && [ "${count}" -lt 30 ]; do
    sleep 1
    count=$((count + 1))
  done
  if mountpoint -q "${SPIFFEFS_MOUNT}"; then
    echo "spiffefs did not release ${SPIFFEFS_MOUNT}"
    return 1
  fi
}
