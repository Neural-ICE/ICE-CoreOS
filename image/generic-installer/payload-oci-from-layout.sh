#!/bin/bash
# Cut ONE image out of an OCI layout (a zot data directory, for instance) into a minimal OCI layout for the
# payload partition (ADR-0044): index.json names exactly the image index the signed release manifest names,
# and blobs/ holds that index, its arm64 child manifest, the config and the layers, each byte-checked.
# Usage: payload-oci-from-layout.sh SRC_LAYOUT INDEX_DIGEST(sha256:...) DST_DIR   (DST_DIR must not exist)
set -euo pipefail
SRC="${1:?source oci layout}"; DIGEST="${2:?index digest}"; DST="${3:?destination}"
[[ "$DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "digest must be sha256:<64 hex>" >&2; exit 2; }
[ ! -e "$DST" ] || { echo "$DST exists" >&2; exit 2; }
blob() { echo "$SRC/blobs/sha256/${1#sha256:}"; }
take() { # digest: copy one blob and prove it is the bytes its name says
  local d="$1" f; f="$(blob "$d")"
  [ -f "$f" ] && [ ! -L "$f" ] || { echo "missing blob $d" >&2; exit 1; }
  [ "$(sha256sum "$f" | cut -d' ' -f1)" = "${d#sha256:}" ] || { echo "blob $d does not hash to its name" >&2; exit 1; }
  [ -e "$DST/blobs/sha256/${d#sha256:}" ] || cp -- "$f" "$DST/blobs/sha256/${d#sha256:}"
}
mkdir -p "$DST/blobs/sha256"
take "$DIGEST"
jq -e '.mediaType == "application/vnd.oci.image.index.v1+json"' "$(blob "$DIGEST")" >/dev/null
for child in $(jq -r '.manifests[] | select(.platform.architecture == "arm64" and .platform.os == "linux") | .digest' "$(blob "$DIGEST")"); do
  take "$child"
  take "$(jq -r .config.digest "$(blob "$child")")"
  for l in $(jq -r '.layers[].digest' "$(blob "$child")"); do take "$l"; done
done
size="$(stat -c %s "$(blob "$DIGEST")")"
printf '{"schemaVersion":2,"manifests":[{"mediaType":"application/vnd.oci.image.index.v1+json","digest":"%s","size":%s}]}\n' "$DIGEST" "$size" > "$DST/index.json"
printf '{"imageLayoutVersion":"1.0.0"}\n' > "$DST/oci-layout"
du -sh "$DST"
