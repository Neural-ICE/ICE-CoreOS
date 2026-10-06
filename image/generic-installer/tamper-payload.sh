#!/bin/bash
# Make a payload that must be refused (ADR-0044 refusal proofs): a hard-linked copy of a good payload with ONE change,
# made copy-on-write so the good payload is never touched.
#   manifest  a different bundle_seq in release-manifest.json: its signature no longer verifies
#   layer     one byte changed (size kept) in the last layer blob of the host image: skopeo must refuse it while unpacking
# Usage: tamper-payload.sh MODE GOOD_PAYLOAD BAD_PAYLOAD
set -euo pipefail
MODE="${1:?manifest|layer}"; GOOD="${2:?good payload}"; BAD="${3:?bad payload (must not exist)}"
[ ! -e "$BAD" ] || { echo "$BAD exists" >&2; exit 2; }
mkdir "$BAD"; cp -al "$GOOD/host-oci" "$BAD/host-oci"; cp "$GOOD/release-manifest.json" "$GOOD/release-manifest.json.sig" "$BAD/"
case "$MODE" in
  manifest)
    sed 's/"bundle_seq":1,/"bundle_seq":2,/' "$GOOD/release-manifest.json" > "$BAD/release-manifest.json.new"
    ! cmp -s "$GOOD/release-manifest.json" "$BAD/release-manifest.json.new" || { echo "the manifest was not changed" >&2; exit 1; }
    mv -f "$BAD/release-manifest.json.new" "$BAD/release-manifest.json" ;;
  layer)
    child="$(jq -r '.manifests[0].digest' "$GOOD/host-oci/index.json")"
    child="$(jq -r '.manifests[0].digest' "$GOOD/host-oci/blobs/sha256/${child#sha256:}")"
    layer="$(jq -r '.layers[-1].digest' "$GOOD/host-oci/blobs/sha256/${child#sha256:}")"
    f="$BAD/host-oci/blobs/sha256/${layer#sha256:}"
    cp --remove-destination -- "$GOOD/host-oci/blobs/sha256/${layer#sha256:}" "$f"      # break the hard link first
    size="$(stat -c %s "$f")"; [ "$size" -ge 2 ] || { echo "layer too small to flip a byte inside" >&2; exit 1; }
    pos=$(( size / 2 )); byte="$(dd if="$f" bs=1 skip=$pos count=1 status=none | od -An -tu1 | tr -d ' ')"
    printf "\\$(printf '%03o' $(( (byte + 1) % 256 )))" | dd of="$f" bs=1 seek=$pos conv=notrunc status=none      # same size, one byte different
    ! cmp -s "$GOOD/host-oci/blobs/sha256/${layer#sha256:}" "$f" || { echo "the layer was not changed" >&2; exit 1; } ;;
  *) echo "unknown mode $MODE" >&2; exit 2 ;;
esac
