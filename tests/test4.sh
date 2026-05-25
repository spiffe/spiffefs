#!/bin/bash -xe

# Check for reading with busybox cat. It uses splice which broke before.

busybox cat /tmp/mnt/x509/0/credential-bundle.pem > /tmp/credential-bundle.pem
busybox cat /tmp/mnt/x509/0/example.org.spiffe-trust-bundle.pem > /tmp/example.org.spiffe-trust-bundle.pem

openssl x509 -in /tmp/credential-bundle.pem -noout -text | grep URI:spiffe://example.org/test4
openssl x509 -in /tmp/example.org.spiffe-trust-bundle.pem -noout -text | grep URI:spiffe://example.org
