#!/bin/bash -xe

# Check for only one svid without hints.

MNT=/tmp/mnt

ls -l "${MNT}"
openssl x509 -in "${MNT}/credential-bundle.private-key.x509.pem" -noout -text | grep URI:spiffe://example.org/test1
openssl x509 -in "${MNT}/example.org.spiffe-trust-bundle.x509.pem" -noout -text | grep URI:spiffe://example.org

# Only one svid, so no indexed credential bundle.
[[ ! -e "${MNT}/1.credential-bundle.private-key.x509.pem" ]]

# hints.json is always present. One entry, no hint, id 0.
cat "${MNT}/hints.json"
[[ $(jq '.hints | length' "${MNT}/hints.json") == 1 ]]
[[ $(jq -r '.hints[0].hint' "${MNT}/hints.json") == "" ]]
[[ $(jq -r '.hints[0].id' "${MNT}/hints.json") == 0 ]]

# The advertised fingerprint has to match the credential bundle it points at.
fingerprint=$(openssl x509 -in "${MNT}/credential-bundle.private-key.x509.pem" -noout -fingerprint -sha256 | sed 's/^SHA256 Fingerprint=/sha256:/')
[[ $(jq -r '.hints[0].fingerprint' "${MNT}/hints.json") == "${fingerprint}" ]]
