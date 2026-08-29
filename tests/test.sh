#!/usr/bin/env bash

set -xe

SCRIPT="$(readlink -f "$0")"
SCRIPTPATH="$(dirname "${SCRIPT}")"
TESTDIR="${SCRIPTPATH}/../../.github/tests"

CLEANUP=1

if [ "x${GITHUB_JOB}" != "x" ]; then
  echo "Running in GitHub"
else
  echo "Do not run this script on your own box."
  exit 1
fi

teardown() {
  echo ---------------------------
  if [ $1 -ne 0 ]; then
    systemctl status spire-server@main || true
    systemctl status spire-controller-manager@main || true
    systemctl status spire-server@other || true
    systemctl status spire-agent@main || true
    sudo spire-server entry show || true
    systemctl status test1 || true
    systemctl status test2 || true
    systemctl status test3 || true
    systemctl status test4 || true
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

# Startup the servers
sudo systemctl start spire-server@main spire-server@other spire-controller-manager@main

# Register some workloads with the spire server using manifests
sudo mkdir -p /etc/spire/server/main/manifests/
sudo cp "${SCRIPTPATH}/manifests"/* /etc/spire/server/main/manifests/

# Startup servers and make sure they are ready
wait_for_healthcheck spire-server /run/spire/server/sockets/main/private/api.sock
wait_for_healthcheck spire-server /run/spire/server/sockets/other/private/api.sock

sudo spire-server bundle show -instance other | sudo spire-server bundle set -id other.org

sudo spire-server bundle list

# Configure agent. For the test, create join tokens for both agents. You should really use a node attestor other then join tokens such as tpm-direct, http_challenge, or a cloud provider one
JOIN_TOKEN=$(sudo spire-server token generate -spiffeID spiffe://example.org/agent/node1 | awk '{print "\""$2"\""}')
export JOIN_TOKEN
sudo /bin/bash -c "echo JOIN_TOKEN=${JOIN_TOKEN} > /etc/spire/agent/main.env"

# Startup the agent
sudo systemctl start spire-agent@main
wait_for_healthcheck spire-agent /var/run/spire/agent/sockets/main/public/api.sock

# Build the code
go build -o spiffefs .

# Start it up
mkdir -p /tmp/mnt
sudo ./spiffefs /tmp/mnt &

# Wait for what the tests actually need, rather than guessing at a duration. The
# mount appears within a second or two, but the trust bundles arrive separately:
# they come from a stream that backs off and retries, so credentials can be
# served before any bundle is. A fixed sleep raced that and failed on the slower
# runners.
wait_for_spiffefs() {
  local timeout=120
  local count=0
  while [ "${count}" -lt "${timeout}" ]; do
    if mountpoint -q /tmp/mnt &&
       [ -s /tmp/mnt/hints.json ] &&
       [ -s /tmp/mnt/example.org.spiffe-trust-bundle.x509.pem ]; then
      return 0
    fi
    sleep 2
    count=$((count + 2))
  done
  echo "spiffefs did not serve a trust bundle within ${timeout}s"
  ls -la /tmp/mnt/ || true
  return 1
}
wait_for_spiffefs

sudo cp tests/test*.sh /usr/libexec/
sudo cp tests/systemd/test*.service /etc/systemd/system
sudo systemctl daemon-reload
sudo systemctl start --wait test1
sudo systemctl status test1 || true
sudo systemctl start --wait test2
sudo systemctl status test2 || true
sudo systemctl start --wait test3
sudo systemctl status test3 || true
sudo systemctl start --wait test4
sudo systemctl status test4 || true
