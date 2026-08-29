#!/bin/bash -xe

# Check reading with busybox cat. It uses sendfile/splice rather than read,
# which has broken twice in different ways.

MNT=/tmp/mnt

busybox cat "${MNT}/credential-bundle.private-key.x509.pem" > /tmp/credential-bundle.pem
busybox cat "${MNT}/example.org.spiffe-trust-bundle.x509.pem" > /tmp/example.org.spiffe-trust-bundle.pem
busybox cat "${MNT}/hints.json" > /tmp/hints.json

openssl x509 -in /tmp/credential-bundle.pem -noout -text | grep URI:spiffe://example.org/test4
openssl x509 -in /tmp/example.org.spiffe-trust-bundle.pem -noout -text | grep URI:spiffe://example.org
[[ $(jq '.hints | length' /tmp/hints.json) == 1 ]]

# Piping is a different path from redirecting to a file. Redirecting makes
# sendfile fail, so the reader falls back to read(); piping makes it succeed
# with zero bytes if the kernel believes the file is empty, and the reader
# treats that as end of file and silently delivers nothing. Check every file
# with both readers, since the two implementations splice differently.
for F in "${MNT}/credential-bundle.private-key.x509.pem" \
         "${MNT}/example.org.spiffe-trust-bundle.x509.pem" \
         "${MNT}/hints.json"; do
  SIZE=$(wc -c < "${F}")
  [[ "${SIZE}" -gt 0 ]]
  [[ $(busybox cat "${F}" | wc -c) -eq "${SIZE}" ]]
  [[ $(cat "${F}" | wc -c) -eq "${SIZE}" ]]
done
