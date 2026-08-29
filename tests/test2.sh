#!/bin/bash -xe

# Check for 2 svids, both with hints. Main is federated.

MNT=/tmp/mnt

ls -l "${MNT}"
cat "${MNT}/hints.json"

# Both svids are listed, with the expected hints.
[[ $(jq '.hints | length' "${MNT}/hints.json") == 2 ]]
diff -u <(echo main; echo other) <(jq -r '.hints[].hint' "${MNT}/hints.json" | sort -u)

# hints.json maps a hint to an id; id 0 is delivered under the unindexed name.
bundle_for_hint() {
	local id
	id=$(jq -r --arg hint "$1" '.hints[] | select(.hint == $hint) | .id' "${MNT}/hints.json")
	if [ "${id}" -eq 0 ]; then
		echo "${MNT}/credential-bundle.private-key.x509.pem"
	else
		echo "${MNT}/${id}.credential-bundle.private-key.x509.pem"
	fi
}

main=$(bundle_for_hint main)
other=$(bundle_for_hint other)

openssl x509 -in "${main}" -noout -text | grep URI:spiffe://example.org/test2/main
openssl x509 -in "${other}" -noout -text | grep URI:spiffe://example.org/test2/other

# Each bundle's key and cert have to belong together, and chain to the trust bundle.
for bundle in "${main}" "${other}"; do
	cat "${bundle}" > /tmp/credential-bundle.pem
	[[ $(openssl x509 -noout -in /tmp/credential-bundle.pem | openssl md5) == $(openssl pkey -noout -in /tmp/credential-bundle.pem | openssl md5) ]]
	openssl verify -CAfile "${MNT}/example.org.spiffe-trust-bundle.x509.pem" -untrusted /tmp/credential-bundle.pem /tmp/credential-bundle.pem
done

# Each advertised fingerprint has to match a plain hash of the bundle file it
# points at. This is what lets a reader detect a rotation between reading
# hints.json and reading a bundle, without parsing any PEM.
for hint in main other; do
	bundle=$(bundle_for_hint "${hint}")
	fingerprint="sha256:$(sha256sum "${bundle}" | cut -d' ' -f1)"
	[[ $(jq -r --arg hint "${hint}" '.hints[] | select(.hint == $hint) | .fingerprint' "${MNT}/hints.json") == "${fingerprint}" ]]
done

# The federated trust bundle shows up at the root alongside our own.
openssl x509 -in "${MNT}/other.org.spiffe-trust-bundle.x509.pem" -noout -text | grep URI:spiffe://other.org
