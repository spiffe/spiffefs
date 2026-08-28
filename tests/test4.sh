#!/bin/bash -xe

# Check for reading with busybox cat. It uses splice which broke before.

MNT=/tmp/mnt

busybox cat "${MNT}/credential-bundle.private-key.x509.pem" > /tmp/credential-bundle.pem
busybox cat "${MNT}/example.org.spiffe-trust-bundle.x509.pem" > /tmp/example.org.spiffe-trust-bundle.pem
busybox cat "${MNT}/hints.json" > /tmp/hints.json

openssl x509 -in /tmp/credential-bundle.pem -noout -text | grep URI:spiffe://example.org/test4
openssl x509 -in /tmp/example.org.spiffe-trust-bundle.pem -noout -text | grep URI:spiffe://example.org
[[ $(jq '.hints | length' /tmp/hints.json) == 1 ]]
