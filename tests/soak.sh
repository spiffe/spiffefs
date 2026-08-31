#!/usr/bin/env bash
#
# Time-bound churn test. For a fixed wall-clock budget this keeps a bounded
# number of randomly named systemd units running at once, each with freshly
# created registration entries, and each asserting that spiffefs served it its
# own identities and nothing else. Then it converges: stops launching, drains,
# cleans up, and checks that spiffefs reclaimed the per-caller state it made.
#
# test1-test4 run one workload at a time, so none of them can catch a workload
# being served another's credentials. That is what this is for.

set -xe

# shellcheck source=tests/lib.sh
source "$(dirname "$(readlink -f "$0")")/lib.sh"

# `wait -n -p` is how a finished worker is attributed back to its unit name.
if [ "${BASH_VERSINFO[0]}" -lt 5 ] ||
   { [ "${BASH_VERSINFO[0]}" -eq 5 ] && [ "${BASH_VERSINFO[1]}" -lt 1 ]; }; then
  echo "soak needs bash 5.1+ for 'wait -n -p', have ${BASH_VERSION}"
  exit 1
fi

# Every knob is an environment variable so the ceiling can be raised to see how
# spiffefs behaves under more pressure without editing anything.
SOAK_SECONDS="${SOAK_SECONDS:-300}"
SOAK_CONCURRENCY="${SOAK_CONCURRENCY:-6}"
SOAK_MAX_WAIT_MS="${SOAK_MAX_WAIT_MS:-3000}"
SOAK_MODE="${SOAK_MODE:-broker}"
SOAK_CLIENT_DEADLINE="${SOAK_CLIENT_DEADLINE:-60s}"

TRUST_DOMAIN=example.org
FEDERATED_DOMAIN=other.org
PARENT_ID="spiffe://${TRUST_DOMAIN}/agent/node1"

spire_setup

rm -rf "${SOAK_LOG_DIR}"
mkdir -p "${SOAK_LOG_DIR}"

start_spiffefs "${SOAK_MODE}"

declare -A JOB_NAME
launched=0
passed=0
failed=0

# Which thread each workload read from. Tallied so a green run can show the
# worker-thread path was actually taken: a client that silently fell back to the
# group leader every time would otherwise look identical to one that did not.
declare -A READERS

# Random, and valid both as a systemd unit name and as a SPIRE entry ID, so one
# token names the unit and its entries and cleanup needs no bookkeeping.
new_name() {
  printf 'soak-%06d-%s' "$1" "$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
}

# Entries are created with an explicit -entryID so they can be deleted by name
# rather than by parsing the create output.
create_entries() {
  local name="$1" federate="$2" two="$3"
  local -a common=(
    -socketPath "${SPIRE_SERVER_SOCKET}"
    -parentID "${PARENT_ID}"
    -selector "systemd:id:${name}.service"
  )
  local -a fed=()
  if [ "${federate}" = "yes" ]; then
    fed=(-federatesWith "spiffe://${FEDERATED_DOMAIN}")
  fi

  if [ "${two}" = "yes" ]; then
    # Two entries on one selector: the workload should be served both, told
    # them apart by hint. Only the first federates, so the workload's trust
    # domains are the union across its entries.
    sudo spire-server entry create "${common[@]}" "${fed[@]}" \
      -entryID "${name}" \
      -spiffeID "spiffe://${TRUST_DOMAIN}/soak/${name}/main" \
      -hint main > /dev/null
    sudo spire-server entry create "${common[@]}" \
      -entryID "${name}-other" \
      -spiffeID "spiffe://${TRUST_DOMAIN}/soak/${name}/other" \
      -hint other > /dev/null
  else
    sudo spire-server entry create "${common[@]}" "${fed[@]}" \
      -entryID "${name}" \
      -spiffeID "spiffe://${TRUST_DOMAIN}/soak/${name}" > /dev/null
  fi
}

delete_entries() {
  local name="$1"
  sudo spire-server entry delete -socketPath "${SPIRE_SERVER_SOCKET}" -entryID "${name}" > /dev/null 2>&1 || true
  sudo spire-server entry delete -socketPath "${SPIRE_SERVER_SOCKET}" -entryID "${name}-other" > /dev/null 2>&1 || true
}

# The expectation is the complete truth about what this workload should see. The
# client fails on anything served that is not in here.
write_expectation() {
  local name="$1" federate="$2" two="$3"
  local -a domains=("${TRUST_DOMAIN}")
  if [ "${federate}" = "yes" ]; then
    domains+=("${FEDERATED_DOMAIN}")
  fi
  local domains_json
  domains_json="$(printf '%s\n' "${domains[@]}" | jq -R . | jq -s -c .)"

  if [ "${two}" = "yes" ]; then
    jq -n -c \
      --arg main "spiffe://${TRUST_DOMAIN}/soak/${name}/main" \
      --arg other "spiffe://${TRUST_DOMAIN}/soak/${name}/other" \
      --argjson domains "${domains_json}" \
      '{svids: [{hint: "main", spiffe_id: $main}, {hint: "other", spiffe_id: $other}], trust_domains: $domains}'
  else
    jq -n -c \
      --arg id "spiffe://${TRUST_DOMAIN}/soak/${name}" \
      --argjson domains "${domains_json}" \
      '{svids: [{hint: "", spiffe_id: $id}], trust_domains: $domains}'
  fi > "${SOAK_LOG_DIR}/${name}.json"
}

# --wait makes the shell job's exit status the workload's, --collect reaps the
# transient unit so they do not pile up, and --pipe puts the client's output in
# a file we can show for a failure instead of only in the journal.
launch() {
  local name="$1"
  # SC2024: the redirect being the unprivileged shell's is the point. The log
  # lives in a directory this user owns, and --pipe hands the already-open fd to
  # the service, so root writes to it without needing to open it.
  # shellcheck disable=SC2024
  sudo systemd-run --unit="${name}" --collect --pipe --wait \
    "${SOAK_CLIENT}" \
      -name "${name}" \
      -mount "${SPIFFEFS_MOUNT}" \
      -expect-file "${SOAK_LOG_DIR}/${name}.json" \
      -max-wait "${SOAK_MAX_WAIT_MS}ms" \
      -deadline "${SOAK_CLIENT_DEADLINE}" \
    < /dev/null > "${SOAK_LOG_DIR}/${name}.log" 2>&1 &
  JOB_NAME[$!]="${name}"
}

reap_one() {
  local pid rc=0
  wait -n -p pid || rc=$?

  local name="${JOB_NAME[${pid}]:-unknown-pid-${pid}}"
  unset "JOB_NAME[${pid}]"

  # Deleting as we go keeps the live entry count near the concurrency limit
  # rather than growing into the hundreds, and exercises entry removal
  # alongside creation.
  delete_entries "${name}"

  local reader
  reader="$(sed -n 's/^soak-reader: //p' "${SOAK_LOG_DIR}/${name}.log" | head -n 1)"
  READERS[${reader:-none}]=$(( ${READERS[${reader:-none}]:-0} + 1 ))

  if [ "${rc}" -eq 0 ]; then
    passed=$((passed + 1))
  else
    failed=$((failed + 1))
    echo "${name}" >> "${SOAK_LOG_DIR}/failed"
    echo "soak: ${name} FAILED (rc=${rc})"
  fi
}

# Hundreds of workloads at three sudo calls each would bury the job log, so the
# churn loop runs quietly and reports progress instead.
set +x

echo "soak: ${SOAK_SECONDS}s, concurrency ${SOAK_CONCURRENCY}, mode ${SOAK_MODE}"

soak_deadline=$((SECONDS + SOAK_SECONDS))
counter=0

while [ "${SECONDS}" -lt "${soak_deadline}" ]; do
  while [ "${#JOB_NAME[@]}" -ge "${SOAK_CONCURRENCY}" ]; do
    reap_one
  done

  counter=$((counter + 1))
  name="$(new_name "${counter}")"

  # Note the plain `if`: `[ ... ] && x=y` would be the last command in the
  # list, so a false test would exit the script under `set -e`.
  federate=no
  if [ $((RANDOM % 2)) -eq 0 ]; then
    federate=yes
  fi
  two=no
  if [ $((RANDOM % 3)) -eq 0 ]; then
    two=yes
  fi

  create_entries "${name}" "${federate}" "${two}"
  write_expectation "${name}" "${federate}" "${two}"
  launch "${name}"
  launched=$((launched + 1))

  if [ $((launched % 25)) -eq 0 ]; then
    echo "soak: ${SECONDS}s elapsed, launched=${launched} passed=${passed} failed=${failed} inflight=${#JOB_NAME[@]}"
  fi
done

echo "soak: budget spent, draining ${#JOB_NAME[@]} in flight"
while [ "${#JOB_NAME[@]}" -gt 0 ]; do
  reap_one
done

set -x

echo "soak: launched=${launched} passed=${passed} failed=${failed}"

for reader in "${!READERS[@]}"; do
  echo "soak: ${READERS[${reader}]} workloads read from ${reader}"
done

# fuse reports the calling thread, not the calling process, so reads from a
# non-leader thread are a distinct path through spiffefs. A run where none
# happened has not tested it, however green it looks.
if [ "${READERS[worker]:-0}" -eq 0 ]; then
  echo "soak: no workload read from a worker thread; that path went untested"
  exit 1
fi
if [ "${READERS[leader]:-0}" -eq 0 ]; then
  echo "soak: no workload read from the group leader; that path went untested"
  exit 1
fi

# Nothing should be left behind: every reaped worker deleted its own entries.
remaining="$(sudo spire-server entry show -socketPath "${SPIRE_SERVER_SOCKET}" | grep -c "spiffe://${TRUST_DOMAIN}/soak/" || true)"
if [ "${remaining}" -ne 0 ]; then
  echo "soak: ${remaining} soak entries were left on the server"
  exit 1
fi

# spiffefs logs an eviction whenever the pidfd reaper reclaims a caller's state.
# Fewer evictions than workloads means per-caller state is piling up, which is
# the leak only a churn test is in a position to notice. Other callers -- the
# driver's own shells -- evict too, so this is a floor rather than an equality.
sleep 10
evictions="$(grep -cE 'Evicting state|Inline eviction' "${SPIFFEFS_LOG}" || true)"
echo "soak: spiffefs evicted ${evictions} caller states for ${launched} workloads"
if [ "${evictions}" -lt "${launched}" ]; then
  echo "soak: per-caller state is not being reclaimed"
  exit 1
fi

# The mount has to still serve a plain reader normally after all of that.
wait_for_spiffefs

stop_spiffefs

if [ "${failed}" -ne 0 ]; then
  echo "soak: ${failed} of ${launched} workloads failed"
  exit 1
fi

echo "soak: ${passed} workloads passed"
