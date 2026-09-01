#!/usr/bin/env bash
#
# Assemble the SEALED INSTALLER PAYLOAD: one raw extent carrying the installer
# root image, the container store image and a dm-verity hash tree for each,
# described by a header whose SHA-256 the signed UKI seals.
#
# WHY THIS STEP IS ITS OWN SCRIPT (review 2026-09-01, P0 #1). The UKI build used
# to run `veritysetup format` itself, which made "the thing that is protected" a
# side effect of "the thing that signs". With a second protected object (the
# store) that arrangement had no room for the second hash, and nothing off-device
# could read either object out of a produced medium. Here every extent is
# computed once, hashed once, and DESCRIBED once -- and the description is the
# only thing the signature has to carry.
#
#   header  (4096 B, NUL padded)   image/lib/installer-payload.sh renders it
#   root-image     the installer root squashfs      -> dm-verity, hash SEALED in .cmdline
#   root-hash      its hash tree
#   store-image    the containers-storage squashfs  -> dm-verity, hash in the HEADER
#   store-hash     its hash tree
#
# WHY THE STORE'S ROOT HASH LIVES IN THE HEADER AND NOT IN THE CMDLINE. The
# cmdline is the trust anchor's five-field statement about what this medium IS;
# growing it per protected object would make the anchor a table of contents. The
# header is that table of contents, and sealing ITS digest binds every entry
# transitively -- one signed value, any number of protected extents.
#
# DETERMINISM. Two builds of the same two images must produce the same payload
# bytes: the verity salt is fixed (it is a domain separator, not a secret), the
# region order is a constant, and every offset is computed from the previous
# region's end rather than discovered.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=image/lib/installer-payload.sh
. "$REPO_ROOT/image/lib/installer-payload.sh"

die() { echo "build-installer-payload: ERROR: $*" >&2; exit 1; }

ROOT_IMAGE="${ROOT_IMAGE:-}"
STORE_IMAGE="${STORE_IMAGE:-}"
STORE_IMAGE_NAME="${STORE_IMAGE_NAME:-localhost/bootc}"
PAYLOAD_OUT="${PAYLOAD_OUT:-}"           # the assembled raw extent
HEADER_OUT="${HEADER_OUT:-${PAYLOAD_OUT}.header}"
MANIFEST_OUT="${MANIFEST_OUT:-${PAYLOAD_OUT}.manifest}"
# A FIXED salt. veritysetup defaults to a random one, which would make the root
# hash -- and therefore the sealed cmdline, and therefore the signed binary --
# different on every build of identical bytes. The salt is not a secret: it is a
# domain separator, and it is published here on purpose.
VERITY_SALT="${VERITY_SALT:-6e657572616c2d6963652d696e7374616c6c65722d726f6f742d76657269747931}"
# A FIXED UUID, for the same reason as the salt and for a reason the previous
# revision could not see. `veritysetup format` writes a verity SUPERBLOCK at the
# start of the hash tree, and its UUID is random by default -- so two builds of
# identical bytes produced identical ROOT HASHES and different HASH TREES. That
# was invisible while only the root hash was recorded; now the tree is hashed
# into the sealed header, and a non-reproducible tree would make every rebuild
# look like a substitution. Caught by image/test-installer-payload.sh.
VERITY_UUID="${VERITY_UUID:-6e657572-616c-4963-9e69-6e7374616c6c}"

TOOL_DIR="${NI_INSTALLER_PAYLOAD_TEST_TOOLS:-}"
if [[ -n "$TOOL_DIR" ]]; then
  [[ "${NI_INSTALLER_PAYLOAD_TESTING:-}" == 1 && "${EUID:-$(id -u)}" -ne 0 ]] \
    || die "a tool override is forbidden in a privileged process"
fi
tool() { # $1=name
  if [[ -n "$TOOL_DIR" ]]; then
    [[ -x "$TOOL_DIR/$1" ]] || die "required tool is unavailable: $TOOL_DIR/$1"
    printf '%s' "$TOOL_DIR/$1"
    return 0
  fi
  command -v -- "$1" >/dev/null 2>&1 || die "required tool is unavailable: $1"
  command -v -- "$1"
}

for required in ROOT_IMAGE STORE_IMAGE PAYLOAD_OUT; do
  [[ -n "${!required}" ]] || die "$required is required"
done
for input in "$ROOT_IMAGE" "$STORE_IMAGE"; do
  [[ -f "$input" && ! -L "$input" && -s "$input" ]] \
    || die "input is missing, empty or not a regular file: $input"
done

# 🔴 EVERY BYTE MUST BE COVERED. `veritysetup format` protects
# floor(size / data_block_size) blocks and IGNORES a trailing partial block, so
# an image whose length is not a multiple of 4096 ends in bytes dm-verity never
# checks -- inside the very extent the signature is supposed to authenticate.
# Pad rather than refuse: both images are squashfs, which ignores trailing bytes,
# and the padding is hashed and sealed like everything else.
pad_to_block() { # $1=path
  local size padded
  size="$(wc -c < "$1" | tr -d '[:space:]')"
  padded=$(( ( size + NEURAL_ICE_PAYLOAD_ALIGNMENT - 1 ) / NEURAL_ICE_PAYLOAD_ALIGNMENT * NEURAL_ICE_PAYLOAD_ALIGNMENT ))
  if (( padded != size )); then
    echo "==> padding $1 from $size to $padded bytes so dm-verity covers every byte"
    "$(tool truncate)" -s "$padded" "$1" || die "cannot pad $1 to a whole number of verity blocks"
  fi
}
pad_to_block "$ROOT_IMAGE"
pad_to_block "$STORE_IMAGE"
[[ "$VERITY_SALT" =~ ^[0-9a-f]{2,128}$ ]] || die "VERITY_SALT must be lowercase hex"
[[ "$VERITY_UUID" =~ ^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$ ]] \
  || die "VERITY_UUID must be a lowercase UUID"
payload_is_local_image_name "$STORE_IMAGE_NAME" \
  || die "STORE_IMAGE_NAME is not a plain local image name: $STORE_IMAGE_NAME"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/ni-payload.XXXXXX")"
trap 'rm -rf -- "$WORK"' EXIT

# --------------------------------------------------------------------------- #
# 1) dm-verity over both images.
# --------------------------------------------------------------------------- #
format_verity() { # $1=data image  $2=hash tree output -> prints the root hash
  local output root
  output="$("$(tool veritysetup)" format --salt "$VERITY_SALT" --uuid "$VERITY_UUID" \
    --hash sha256 --data-block-size 4096 --hash-block-size 4096 \
    "$1" "$2")" || die "veritysetup format failed for $1"
  root="$(awk 'tolower($1) == "root" && tolower($2) == "hash:" {print tolower($3)}' <<<"$output")"
  payload_is_sha256_hex "$root" || die "veritysetup produced no usable root hash for $1"
  printf '%s' "$root"
}
echo "==> veritysetup format (installer root)"
ROOT_HASH_IMAGE="$WORK/root.hash"
ROOT_VERITY_HASH="$(format_verity "$ROOT_IMAGE" "$ROOT_HASH_IMAGE")"
echo "    root verity hash : $ROOT_VERITY_HASH"
echo "==> veritysetup format (image store)"
STORE_HASH_IMAGE="$WORK/store.hash"
STORE_VERITY_HASH="$(format_verity "$STORE_IMAGE" "$STORE_HASH_IMAGE")"
echo "    store verity hash: $STORE_VERITY_HASH"

# --------------------------------------------------------------------------- #
# 2) Lay the regions out. Offsets are a function of the input sizes alone.
# --------------------------------------------------------------------------- #
align_up() { echo $(( ( $1 + NEURAL_ICE_PAYLOAD_ALIGNMENT - 1 ) / NEURAL_ICE_PAYLOAD_ALIGNMENT * NEURAL_ICE_PAYLOAD_ALIGNMENT )); }
sha256_of() { "$(tool sha256sum)" "$1" | awk '{print tolower($1)}'; }

declare -A REGION_SOURCE=(
  [root-image]="$ROOT_IMAGE"
  [root-hash]="$ROOT_HASH_IMAGE"
  [store-image]="$STORE_IMAGE"
  [store-hash]="$STORE_HASH_IMAGE"
)
declare -A REGION_OFFSET REGION_SIZE REGION_SHA
offset=$NEURAL_ICE_PAYLOAD_HEADER_BYTES
for region in $NEURAL_ICE_PAYLOAD_REGIONS; do
  source_path="${REGION_SOURCE[$region]}"
  size="$(wc -c < "$source_path" | tr -d '[:space:]')"
  (( size > 0 )) || die "region '$region' is empty"
  REGION_OFFSET[$region]=$offset
  REGION_SIZE[$region]=$size
  REGION_SHA[$region]="$(sha256_of "$source_path")"
  offset=$(( $(align_up $(( offset + size )) ) ))
done
PAYLOAD_BYTES=$offset

# --------------------------------------------------------------------------- #
# 3) Write the extent: header block first, then every region at its offset.
# --------------------------------------------------------------------------- #
HEADER_TEXT="$(payload_header_render "$STORE_IMAGE_NAME" "$VERITY_SALT" \
  "$ROOT_VERITY_HASH" "$STORE_VERITY_HASH" \
  "root-image:${REGION_OFFSET[root-image]}:${REGION_SIZE[root-image]}:${REGION_SHA[root-image]}" \
  "root-hash:${REGION_OFFSET[root-hash]}:${REGION_SIZE[root-hash]}:${REGION_SHA[root-hash]}" \
  "store-image:${REGION_OFFSET[store-image]}:${REGION_SIZE[store-image]}:${REGION_SHA[store-image]}" \
  "store-hash:${REGION_OFFSET[store-hash]}:${REGION_SIZE[store-hash]}:${REGION_SHA[store-hash]}")" \
  || die "cannot render the sealed payload header"
PAYLOAD_DIGEST="$(payload_header_digest "$HEADER_TEXT")"

echo "==> assembling ${PAYLOAD_OUT} (${PAYLOAD_BYTES} bytes)"
rm -f -- "$PAYLOAD_OUT"
# A sparse file first, so the alignment padding costs nothing on disk and the
# holes read back as the zeros the header implies they are.
"$(tool truncate)" -s "$PAYLOAD_BYTES" "$PAYLOAD_OUT" || die "cannot size the payload extent"
printf '%s' "$HEADER_TEXT" > "$WORK/header.txt"
(( $(wc -c < "$WORK/header.txt") < NEURAL_ICE_PAYLOAD_HEADER_BYTES )) \
  || die "the payload header does not fit in one ${NEURAL_ICE_PAYLOAD_HEADER_BYTES}-byte block"
"$(tool dd)" if="$WORK/header.txt" of="$PAYLOAD_OUT" conv=notrunc status=none \
  || die "cannot write the payload header"
for region in $NEURAL_ICE_PAYLOAD_REGIONS; do
  "$(tool dd)" if="${REGION_SOURCE[$region]}" of="$PAYLOAD_OUT" conv=notrunc status=none \
    bs="$NEURAL_ICE_PAYLOAD_ALIGNMENT" seek=$(( REGION_OFFSET[$region] / NEURAL_ICE_PAYLOAD_ALIGNMENT )) \
    || die "cannot write region '$region' into the payload extent"
done

# --------------------------------------------------------------------------- #
# 4) READ BACK WHAT LANDED, through the same library every runtime reader uses.
#    A payload this tree's own parser refuses would produce a medium that dies in
#    the initramfs, on the appliance, after the operator has flashed it.
# --------------------------------------------------------------------------- #
READBACK="$(payload_header_read "$PAYLOAD_OUT" 0)" \
  || die "the assembled payload does not parse as $NEURAL_ICE_PAYLOAD_SCHEMA"
[[ "$READBACK" == "$HEADER_TEXT" ]] \
  || die "the payload header read back differently than it was rendered"
for region in $NEURAL_ICE_PAYLOAD_REGIONS; do
  landed="$(payload_region_digest "$PAYLOAD_OUT" 0 "${REGION_OFFSET[$region]}" "${REGION_SIZE[$region]}")"
  [[ "$landed" == "${REGION_SHA[$region]}" ]] \
    || die "region '$region' hashes to $landed in the assembled payload, not the ${REGION_SHA[$region]} its header records"
done
printf '%s' "$HEADER_TEXT" > "$HEADER_OUT"

{
  printf 'schema=%s\n' "neural-ice-installer-payload-manifest-v1"
  printf 'payload_bytes=%s\n' "$PAYLOAD_BYTES"
  printf 'payload_header_sha256=%s\n' "$PAYLOAD_DIGEST"
  printf 'root_verity_hash=%s\n' "$ROOT_VERITY_HASH"
  printf 'store_image_name=%s\n' "$STORE_IMAGE_NAME"
  printf 'store_verity_hash=%s\n' "$STORE_VERITY_HASH"
  printf 'verity_salt=%s\n' "$VERITY_SALT"
  printf 'verity_uuid=%s\n' "$VERITY_UUID"
  for region in $NEURAL_ICE_PAYLOAD_REGIONS; do
    printf 'region.%s=offset:%s,size:%s,sha256:%s\n' "$region" \
      "${REGION_OFFSET[$region]}" "${REGION_SIZE[$region]}" "${REGION_SHA[$region]}"
  done
} > "$MANIFEST_OUT"
echo "==> manifest: $MANIFEST_OUT"
cat "$MANIFEST_OUT"
