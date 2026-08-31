#!/usr/bin/env bash

set -xe

# shellcheck source=tests/lib.sh
source "$(dirname "$(readlink -f "$0")")/lib.sh"

spire_setup

run_workload_tests() {
  for unit in test1 test2 test3 test4; do
    sudo systemctl start --wait "${unit}"
    sudo systemctl status "${unit}" || true
  done
}

sudo cp "${SCRIPTPATH}"/test*.sh /usr/libexec/
sudo cp "${SCRIPTPATH}"/systemd/test*.service /etc/systemd/system
sudo systemctl daemon-reload

# Broker mode is the default, so it is what the assertions have to hold for
# first.
echo "=== spiffefs -mode=broker ==="
start_spiffefs broker
run_workload_tests
stop_spiffefs

# Delegated mode is deprecated and slated for removal, but until it goes it has
# to keep passing the same assertions. Deleting this stanza goes with deleting
# delegated.go.
echo "=== spiffefs -mode=delegated ==="
start_spiffefs delegated
run_workload_tests
stop_spiffefs
