#!/bin/bash
# Make a payload that must be refused (ADR-0044 refusal proofs): a hard-linked copy of a good payload whose manifest
# has a different bundle_seq, so its signature no longer verifies. Usage: tamper-payload.sh GOOD_PAYLOAD BAD_PAYLOAD
set -euo pipefail
GOOD="${1:?good payload}"; BAD="${2:?bad payload (must not exist)}"
[ ! -e "$BAD" ] || { echo "$BAD exists" >&2; exit 2; }
mkdir "$BAD"; cp -al "$GOOD/host-oci" "$BAD/host-oci"; cp "$GOOD/release-manifest.json.sig" "$BAD/"
sed 's/"bundle_seq":1,/"bundle_seq":2,/' "$GOOD/release-manifest.json" > "$BAD/release-manifest.json"
! cmp -s "$GOOD/release-manifest.json" "$BAD/release-manifest.json" || { echo "the manifest was not changed" >&2; exit 1; }
