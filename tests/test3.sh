#!/bin/bash -xe

# Check for no svids. hints.json is always delivered, so the root holds only it.

MNT=/tmp/mnt

diff -u <(echo hints.json) <(ls -A "${MNT}")
[[ $(jq '.hints | length' "${MNT}/hints.json") == 0 ]]
