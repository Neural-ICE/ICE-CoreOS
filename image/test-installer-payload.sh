#!/usr/bin/env bash
# shellcheck disable=SC2016 # literal source-contract assertions below
# THE SEALED INSTALLER PAYLOAD: the header contract, the assembled extent, and
# the agreement between the THREE readers that must never disagree about it --
# the POSIX sh library (build, initramfs, installer), the assembler, and the
# off-device Python inspector.
#
# 🔴 WHY THIS SUITE EXISTS (review 2026-09-01, P0 #1). The medium used to stage
# an unauthenticated `store/` directory whose hash lived only in a build manifest
# nobody read at runtime, and nothing off-device could read any of it. Every
# assertion below is about bytes that are actually in the extent.
#
# veritysetup is REAL here when it is available, because the whole construction
# rests on the root hashes it computes; when it is not, the suite says so rather
# than reporting green on a mock.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIB="$ROOT/image/lib/installer-payload.sh"
BUILD="$ROOT/image/build-installer-payload.sh"
INSPECT="$ROOT/image/inspect-installer-media.py"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/ni-payload.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

for t in python3 sha256sum dd truncate od; do
  command -v "$t" >/dev/null 2>&1 \
    || fail "$t is unavailable; this suite proves nothing without it and must not report green"
done

# shellcheck source=image/lib/installer-payload.sh
. "$LIB"

H1="$(printf 'root' | sha256sum | awk '{print $1}')"
H2="$(printf 'store' | sha256sum | awk '{print $1}')"
R1="$(printf 'r1' | sha256sum | awk '{print $1}')"
R2="$(printf 'r2' | sha256sum | awk '{print $1}')"
R3="$(printf 'r3' | sha256sum | awk '{print $1}')"
R4="$(printf 'r4' | sha256sum | awk '{print $1}')"
render() {
  payload_header_render localhost/bootc 6e6575 "$H1" "$H2" \
    "root-image:${1:-4096}:100:$R1" "root-hash:${2:-8192}:200:$R2" \
    "store-image:${3:-12288}:300:$R3" "store-hash:${4:-16384}:400:$R4"
}

# --------------------------------------------------------------------------- #
# 1) THE HEADER IS CANONICAL AND DETERMINISTIC. Its SHA-256 is what the signed
#    UKI seals, so two renders of the same inputs producing different bytes would
#    make the medium unsignable in any reviewable way.
# --------------------------------------------------------------------------- #
A="$(render)"; B="$(render)"
[ "$A" = "$B" ] || fail "the rendered payload header is not deterministic"
[ "$(printf '%s\n' "$A" | sort)" = "$A" ] \
  || fail "the payload header is not in canonical key order"
payload_header_is_valid "$A" || fail "the renderer produced a header its own reader refuses"
DIGEST="$(payload_header_digest "$A")"
[[ "$DIGEST" =~ ^[0-9a-f]{64}$ ]] || fail "the header digest is not 64 lowercase hex"
[ "$(payload_header_field "$A" store_verity_hash)" = "$H2" ] \
  || fail "the header does not carry the store verity hash"
[ "$(payload_region_field "$A" store-image offset)" = 12288 ] \
  || fail "the header does not carry the store image offset"

# Overlap, misalignment and emptiness are refusals: overlapping regions would let
# one set of bytes satisfy two digests.
render 4096 4096 >/dev/null 2>&1 && fail "overlapping regions were accepted"
render 4097 >/dev/null 2>&1 && fail "an unaligned region was accepted"
payload_header_render localhost/bootc 6e6575 "$H1" "$H2" \
  "root-image:4096:0:$R1" "root-hash:8192:200:$R2" \
  "store-image:12288:300:$R3" "store-hash:16384:400:$R4" >/dev/null 2>&1 \
  && fail "an empty region was accepted"
payload_header_render localhost/bootc 6e6575 "$H1" not-a-hash \
  "root-image:4096:100:$R1" "root-hash:8192:200:$R2" \
  "store-image:12288:300:$R3" "store-hash:16384:400:$R4" >/dev/null 2>&1 \
  && fail "a malformed store verity hash was sealed into a header"
payload_header_render 'not a name' 6e6575 "$H1" "$H2" \
  "root-image:4096:100:$R1" "root-hash:8192:200:$R2" \
  "store-image:12288:300:$R3" "store-hash:16384:400:$R4" >/dev/null 2>&1 \
  && fail "a store image name that is not a plain local name was sealed"

# A field that appears twice, a key set that differs, and an out-of-order
# document are all refusals -- a header that can be shadowed by appending to it
# is not a header.
payload_header_is_valid "$A
schema=$NEURAL_ICE_PAYLOAD_SCHEMA" 2>/dev/null \
  && fail "a duplicated field was accepted"
payload_header_is_valid "$A
zzz_unknown=1" 2>/dev/null && fail "an unknown field was accepted"
payload_header_is_valid "$(printf '%s\n' "$A" | sort -r)" 2>/dev/null \
  && fail "an out-of-order header was accepted"
payload_header_is_valid "$(printf 'schema=%s' "$NEURAL_ICE_PAYLOAD_SCHEMA")" 2>/dev/null \
  && fail "a header missing every region was accepted"

# --------------------------------------------------------------------------- #
# 2) THE ASSEMBLED EXTENT. Real veritysetup, real dd, real hashes.
# --------------------------------------------------------------------------- #
if ! command -v veritysetup >/dev/null 2>&1; then
  echo "PAYLOAD_TEST_SKIPPED_ASSEMBLY (veritysetup unavailable; the header contract above still ran)" >&2
  echo "INSTALLER_PAYLOAD_TEST_OK (header contract only)"
  exit 0
fi

IN="$TMP/in"; mkdir -p "$IN"
# Multi-block images so the verity tree has more than one level to get wrong.
head -c 700000 /dev/urandom > "$IN/root.img"
head -c 300000 /dev/urandom > "$IN/store.img"
assemble() { # $1=output dir
  mkdir -p "$1"
  env ROOT_IMAGE="$IN/root.img" STORE_IMAGE="$IN/store.img" \
    PAYLOAD_OUT="$1/payload.img" bash "$BUILD"
}
assemble "$TMP/a" >/dev/null || fail "the payload assembly failed"
assemble "$TMP/b" >/dev/null || fail "the second payload assembly failed"
cmp -s "$TMP/a/payload.img" "$TMP/b/payload.img" \
  || fail "the assembled payload is not reproducible; a rebuild cannot be told from a substitution"

MANIFEST="$TMP/a/payload.img.manifest"
PAYLOAD_DIGEST="$(sed -n 's/^payload_header_sha256=//p' "$MANIFEST")"
ROOT_HASH="$(sed -n 's/^root_verity_hash=//p' "$MANIFEST")"
STORE_HASH="$(sed -n 's/^store_verity_hash=//p' "$MANIFEST")"
for value in "$PAYLOAD_DIGEST" "$ROOT_HASH" "$STORE_HASH"; do
  [[ "$value" =~ ^[0-9a-f]{64}$ ]] || fail "the payload manifest carries a malformed digest"
done
[ "$ROOT_HASH" != "$STORE_HASH" ] || fail "two different images produced one verity root hash"

# THE READER THE INITRAMFS USES, over the produced extent.
HEADER="$(payload_header_read "$TMP/a/payload.img" 0)" \
  || fail "the assembled payload does not parse as a sealed header"
[ "$(payload_header_digest "$HEADER")" = "$PAYLOAD_DIGEST" ] \
  || fail "the header on the extent does not hash to the digest the manifest records"
[ "$(payload_header_field "$HEADER" root_verity_hash)" = "$ROOT_HASH" ] \
  || fail "the header on the extent carries a different root verity hash"

# Every region hashes to what the header says, off the extent.
for region in root-image root-hash store-image store-hash; do
  off="$(payload_region_field "$HEADER" "$region" offset)"
  size="$(payload_region_field "$HEADER" "$region" size)"
  want="$(payload_region_field "$HEADER" "$region" sha256)"
  got="$(payload_region_digest "$TMP/a/payload.img" 0 "$off" "$size")"
  [ "$got" = "$want" ] || fail "region '$region' does not hash to what its header records"
done

# The verity hashes must be the ones veritysetup itself computes over the data
# regions -- not merely self-consistent numbers the assembler invented.
off="$(payload_region_field "$HEADER" root-image offset)"
size="$(payload_region_field "$HEADER" root-image size)"
dd if="$TMP/a/payload.img" of="$TMP/root-extract.img" bs=4096 \
  skip=$(( off / 4096 )) count=$(( (size + 4095) / 4096 )) status=none
truncate -s "$size" "$TMP/root-extract.img"
cmp -s "$TMP/root-extract.img" "$IN/root.img" \
  || fail "the root image region on the extent is not the image that was sealed"

# --------------------------------------------------------------------------- #
# 3) THE THREE READERS AGREE. image/lib/installer-payload.sh is deliberately the
#    ONE parser the build, the initramfs and the installer share; the Python
#    inspector deliberately re-derives the contract instead of importing it. An
#    inspector that re-used the producer's code would only confirm that the
#    producer is self-consistent, which is not the question.
# --------------------------------------------------------------------------- #
python3 - "$INSPECT" "$TMP/a/payload.img" "$PAYLOAD_DIGEST" "$ROOT_HASH" "$STORE_HASH" <<'PY' \
  || fail "the Python inspector and the shell library disagree about the same header"
import hashlib, importlib.util, sys

spec = importlib.util.spec_from_file_location("inspector", sys.argv[1])
inspector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inspector)

path, digest, root_hash, store_hash = sys.argv[2:6]
with open(path, "rb") as handle:
    block = handle.read(inspector.PAYLOAD_HEADER_BYTES)
    fields = inspector.parse_payload_header(block)
    text = block.rstrip(b"\x00")
    assert hashlib.sha256(text).hexdigest() == digest, "header digest disagreement"
    assert fields["root_verity_hash"] == root_hash, "root verity hash disagreement"
    assert fields["store_verity_hash"] == store_hash, "store verity hash disagreement"
    salt = bytes.fromhex(fields["verity_salt"])
    for name, expected in (("root-image", root_hash), ("store-image", store_hash)):
        offset, size, region_digest = inspector.parse_region(fields, name)
        landed = inspector.hash_extent(handle, offset, size)
        assert landed == region_digest, f"{name} region digest disagreement"
        # The independent recomputation: a dm-verity Merkle root from the data
        # bytes alone, with no reference to the hash tree that ships beside them.
        recomputed = inspector.verity_root_hash(handle, offset, size, salt)
        assert recomputed == expected, f"{name} verity root recomputation disagreement"
PY

# --------------------------------------------------------------------------- #
# 4) A MUTATED EXTENT IS CAUGHT. One flipped byte in the store image -- the
#    payload an attacker actually wants to change, because it is what gets
#    written onto the customer's disk.
# --------------------------------------------------------------------------- #
cp "$TMP/a/payload.img" "$TMP/mutated.img"
off="$(payload_region_field "$HEADER" store-image offset)"
printf '\xff' | dd of="$TMP/mutated.img" bs=1 seek="$off" conv=notrunc status=none
mutated="$(payload_region_digest "$TMP/mutated.img" 0 "$off" \
  "$(payload_region_field "$HEADER" store-image size)")"
[ "$mutated" != "$(payload_region_field "$HEADER" store-image sha256)" ] \
  || fail "a flipped byte in the store image did not change its digest"
python3 - "$INSPECT" "$TMP/mutated.img" <<'PY' \
  || fail "the inspector accepted a mutated store image"
import importlib.util, sys
spec = importlib.util.spec_from_file_location("inspector", sys.argv[1])
inspector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inspector)
with open(sys.argv[2], "rb") as handle:
    fields = inspector.parse_payload_header(handle.read(inspector.PAYLOAD_HEADER_BYTES))
    offset, size, region_digest = inspector.parse_region(fields, "store-image")
    if inspector.hash_extent(handle, offset, size) == region_digest:
        raise SystemExit(1)
    salt = bytes.fromhex(fields["verity_salt"])
    if inspector.verity_root_hash(handle, offset, size, salt) == fields["store_verity_hash"]:
        raise SystemExit(1)
PY

# A header whose digest does not match what a UKI seals is the whole binding.
[ "$(payload_header_digest "$HEADER")" != "$(printf 'x' | sha256sum | awk '{print $1}')" ] \
  || fail "the header digest is a constant"

# --------------------------------------------------------------------------- #
# 5) THE PRODUCER MUST ACTUALLY USE ALL OF IT.
# --------------------------------------------------------------------------- #
USB="$ROOT/image/build-installer-usb.sh"
grep -Fq 'image/build-installer-payload.sh' "$USB" \
  || fail "the media producer never assembles the sealed payload"
grep -Fq 'PAYLOAD_DIGEST="$PAYLOAD_DIGEST"' "$USB" \
  || fail "the media producer does not seal the payload digest into the UKI"
grep -Fq 'sfdisk --part-label "$LOOP" "$PAYLOADPART_NUM" ni-installer-payload' "$USB" \
  || fail "the media producer does not name the payload partition"
grep -Fq 'installer-payload.sh' "$ROOT/image/initramfs/90neural-ice-installer-verity/module-setup.sh" \
  || fail "the initramfs does not ship the one payload parser"
grep -Fq 'neuralice.payload' "$ROOT/image/initramfs/90neural-ice-installer-verity/neural-ice-installer-verity.sh" \
  || fail "the initramfs never reads the sealed payload digest"

echo "INSTALLER_PAYLOAD_TEST_OK"
