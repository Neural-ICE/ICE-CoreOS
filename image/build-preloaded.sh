#!/usr/bin/env bash
#
#
# Build the PRELOADED installer: the normal sealed installer raw plus one
# `ni-seed` partition carrying the exact Fabric release pack and every object
# its signed closure names. No Podman overlay store, tag or loose model path is
# accepted: build-seed-v2 stages one content-addressed namespace and proves it
# with the same verifier the installer and first boot run.
#
# TODO(perf): store the seed COMPRESSED in ni-seed (zstd) and have the autoinstall decompress it
# on-the-fly while writing to the fast NVMe data volume — smaller USB payload + leverages NVMe
# write speed. Models compress little (safetensors) but archives do.
#
# Run on an ARM64 build host with the seed staged locally. Needs sudo (losetup/mount/mkfs).
#   RELEASE_MANIFEST_FILE=/release/release-manifest.json \
#   RELEASE_CLOSURE_FILE=/release/release-closure.json \
#   SEED_OBJECT_ROOTS=/release/objects:/release/evidence \
#   BASE_IMAGE=<registry>/<org>/<appliance-image>@sha256:<digest> \
#   # LAB-MANAGED media only: the base image's immutable access policy must permit
#   # installer SSH provisioning, and the appliance re-checks it twice anyway.
#   SSH_AUTHORIZED_KEYS_FILE=$HOME/.ssh/id_ed25519.pub \
#   SSH_AUTHORIZED_KEYS_SHA256=<approved-public-key-file-sha256> \
#   LAB_BASELINE_BOM_FILE=/path/to/<train>.bom.json \
#   LAB_BASELINE_BOM_SHA256=<approved-bom-sha256> \
#   LAB_BASELINE_SIGNATURE_FILE=/path/to/<train>.bom.sig \
#   LAB_BASELINE_SIGNATURE_SHA256=<approved-signature-sha256> \
#   COMPRESS=zstd-fast ./image/build-preloaded.sh
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; cd "$REPO_ROOT"
# shellcheck source=image/lib/preloaded-sizing.sh
source "$REPO_ROOT/image/lib/preloaded-sizing.sh"
# shellcheck source=image/lib/preloaded-output-set.sh
source "$REPO_ROOT/image/lib/preloaded-output-set.sh"

RELEASE_MANIFEST_FILE="${RELEASE_MANIFEST_FILE:-}"
RELEASE_CLOSURE_FILE="${RELEASE_CLOSURE_FILE:-}"
RELEASE_AUTHORIZATION_FILE="${RELEASE_AUTHORIZATION_FILE:-}"
RELEASE_AUTHORIZATION_SIGNATURE_FILE="${RELEASE_AUTHORIZATION_SIGNATURE_FILE:-}"
DELEGATION_SNAPSHOT_FILE="${DELEGATION_SNAPSHOT_FILE:-}"
DELEGATION_SNAPSHOT_SIGNATURE_FILE="${DELEGATION_SNAPSHOT_SIGNATURE_FILE:-}"
RELEASE_ROOT_PUBLIC_KEY_FILE="${RELEASE_ROOT_PUBLIC_KEY_FILE:-}"
SEED_OBJECT_ROOTS="${SEED_OBJECT_ROOTS:-}"
SEED_TRUSTED_NOW="${SEED_TRUSTED_NOW:-}"
RELEASE_AUTHORITY="${RELEASE_AUTHORITY:-}"
ACCESS_PROFILE="${ACCESS_PROFILE:-}"
DEVICE_CHANNEL="${DEVICE_CHANNEL:-lab}"
HF_CACHE="${SEED_HF_CACHE:?SEED_HF_CACHE is required for a self-sufficient vLLM seed}"
MODEL_PROFILES="${SEED_MODEL_PROFILES:?SEED_MODEL_PROFILES is required}"
MODEL_CATALOGUE="${SEED_MODEL_CATALOGUE:?SEED_MODEL_CATALOGUE is required}"
TRUST_POLICY_ID="${TRUST_POLICY_ID:-}"
PCR_POLICY_DIGEST="${PCR_POLICY_DIGEST:-}"
PCR_POLICY_PUBLIC_KEY_FILE="${PCR_POLICY_PUBLIC_KEY_FILE:-}"
PCR_POLICY_PUBLIC_KEY_SHA256="${PCR_POLICY_PUBLIC_KEY_SHA256:-}"
PCR_POLICY_SIGNATURE_FILE="${PCR_POLICY_SIGNATURE_FILE:-}"
PCR_POLICY_SIGNATURE_SHA256="${PCR_POLICY_SIGNATURE_SHA256:-}"
PCR_POLICY_SEQ="${PCR_POLICY_SEQ:-}"
NI_OTA_VERIFY="${NI_OTA_VERIFY:-$REPO_ROOT/tools/ni-ota-verify/target/release/ni-ota-verify}"
BASE_IMAGE="${BASE_IMAGE:-}"
TARGET_IMGREF="${TARGET_IMGREF:-}"
TARGET_PROOF_REF="${TARGET_PROOF_REF:-}"
OUT="${OUT:-ice-coreos-installer-preloaded-$(tr -d '[:space:]' < VERSION)}"
COMPRESS="${COMPRESS:-zstd-fast}"
LAB_BASELINE_BOM_SHA256="${LAB_BASELINE_BOM_SHA256:-}"
LAB_BASELINE_SIGNATURE_SHA256="${LAB_BASELINE_SIGNATURE_SHA256:-}"
# Forwarded to build-installer-usb.sh through the environment; declared here so
# the final-media gate can be told which key — if any — was approved for this
# medium. Without that, the gate would accept whatever key happened to be staged.
SSH_AUTHORIZED_KEYS_SHA256="${SSH_AUTHORIZED_KEYS_SHA256:-}"
# The sealed boot path (docs/ADR-0015). These are mandatory in
# build-installer-usb.sh and have no defaults there on purpose -- a default
# would be a silent decision about what a medium may install -- so they are
# forwarded verbatim rather than reinvented here.
VARIANT="${VARIANT:-}"
HARDWARE_TARGET="${HARDWARE_TARGET:-}"
HARDWARE_IDENTITY_FILE="${HARDWARE_IDENTITY_FILE:-}"
UKI_SIGNING_KEY="${UKI_SIGNING_KEY:-}"
UKI_SIGNING_CERT="${UKI_SIGNING_CERT:-}"
ALLOW_UNSIGNED_MEDIA="${ALLOW_UNSIGNED_MEDIA:-0}"

# Refuse a reused OUT before bootc-image-builder replaces the raw or any large seed work starts.
# Failed builds remain evidence; retries use a fresh output name after diagnosis.
preloaded_require_fresh_output_set "$REPO_ROOT" "$OUT" "$COMPRESS"

[[ "$BASE_IMAGE" =~ @sha256:[0-9a-f]{64}$ ]] \
  || { echo "BASE_IMAGE is required as the signed train's digest-pinned appliance ref" >&2; exit 1; }
for variable in RELEASE_MANIFEST_FILE RELEASE_CLOSURE_FILE RELEASE_AUTHORIZATION_FILE \
  RELEASE_AUTHORIZATION_SIGNATURE_FILE DELEGATION_SNAPSHOT_FILE \
  DELEGATION_SNAPSHOT_SIGNATURE_FILE RELEASE_ROOT_PUBLIC_KEY_FILE SEED_OBJECT_ROOTS \
  SEED_TRUSTED_NOW RELEASE_AUTHORITY HARDWARE_TARGET ACCESS_PROFILE TRUST_POLICY_ID; do
  [[ -n ${!variable} ]] || { echo "missing required $variable" >&2; exit 1; }
done
for variable in PCR_POLICY_DIGEST PCR_POLICY_PUBLIC_KEY_FILE PCR_POLICY_PUBLIC_KEY_SHA256 \
  PCR_POLICY_SIGNATURE_FILE PCR_POLICY_SIGNATURE_SHA256 PCR_POLICY_SEQ; do
  [[ -n ${!variable} ]] || { echo "missing required $variable" >&2; exit 1; }
done
[[ -x $NI_OTA_VERIFY ]] || { echo "missing built ni-ota-verify: $NI_OTA_VERIFY" >&2; exit 1; }

# Stage and prove the seed BEFORE building/signing the base medium, because its
# closure hash is itself a sealed UKI input. Colon-separated roots are explicit
# build inputs; each is imported by observed digest, never by its source name.
SEED_STAGE="$(mktemp -d "${TMPDIR:-/tmp}/neural-ice-seed-v2.XXXXXX")"
seedcleanup() { rm -rf -- "$SEED_STAGE"; }
trap seedcleanup EXIT
seed_args=()
IFS=: read -r -a seed_roots <<<"$SEED_OBJECT_ROOTS"
for root in "${seed_roots[@]}"; do seed_args+=(--objects "$root"); done
seed_output="$(./image/build-seed-v2.sh --output "$SEED_STAGE" \
  --release-manifest "$RELEASE_MANIFEST_FILE" --release-closure "$RELEASE_CLOSURE_FILE" \
  --authorization "$RELEASE_AUTHORIZATION_FILE" --authorization-sig "$RELEASE_AUTHORIZATION_SIGNATURE_FILE" \
  --delegation "$DELEGATION_SNAPSHOT_FILE" --delegation-sig "$DELEGATION_SNAPSHOT_SIGNATURE_FILE" \
  --root-pubkey "$RELEASE_ROOT_PUBLIC_KEY_FILE" --registry-host "$RELEASE_AUTHORITY" \
  --hardware-target "$HARDWARE_TARGET" --access-profile "$ACCESS_PROFILE" \
  --device-channel "$DEVICE_CHANNEL" \
  --hf-cache "$HF_CACHE" --model-profiles "$MODEL_PROFILES" \
  --model-catalogue "$MODEL_CATALOGUE" \
  --trust-policy-id "$TRUST_POLICY_ID" --trusted-now "$SEED_TRUSTED_NOW" \
  --pcr-policy-digest "$PCR_POLICY_DIGEST" \
  --pcr-policy-public-key-sha256 "$PCR_POLICY_PUBLIC_KEY_SHA256" \
  --pcr-policy-signature-sha256 "$PCR_POLICY_SIGNATURE_SHA256" --pcr-policy-seq "$PCR_POLICY_SEQ" \
  --verifier "$NI_OTA_VERIFY" "${seed_args[@]}")"
SEED_CLOSURE="$(awk -F= '$1=="release_closure_sha256"{print $2}' <<<"$seed_output")"
SEED_ROOT="$SEED_STAGE/seed/$SEED_CLOSURE"
[[ $SEED_CLOSURE =~ ^[0-9a-f]{64}$ && -f $SEED_ROOT/READY ]] \
  || { echo "seed-v2 producer returned no proved closure" >&2; exit 1; }

echo "==> 1. build the base installer raw FROM ${BASE_IMAGE}  (uncompressed)"
# OUT means "output NAME" here but "bib output DIR" in build-installer-usb.sh —
# drop it from the child env so an exported OUT never leaks in as a bogus bib dir.
# TARGET_IMGREF is the OTA origin RECORDED on the installed system; BASE_IMAGE
# is what the medium is BUILT from. They differ on purpose: the build plane
# reads GHCR, the appliance pulls the sovereign. Forwarding it here is what
# lets a media build need no appliance credential at all -- the medium carries
# nothing about any appliance, so building it must not require one.
env -u OUT BASE_IMAGE="$BASE_IMAGE" TARGET_IMGREF="${TARGET_IMGREF:-$BASE_IMAGE}" \
  TARGET_PROOF_REF="${TARGET_PROOF_REF:-${TARGET_IMGREF:-$BASE_IMAGE}}" \
  VARIANT="$VARIANT" HARDWARE_TARGET="$HARDWARE_TARGET" \
  HARDWARE_IDENTITY_FILE="$HARDWARE_IDENTITY_FILE" \
  UKI_SIGNING_KEY="$UKI_SIGNING_KEY" UKI_SIGNING_CERT="$UKI_SIGNING_CERT" \
  ALLOW_UNSIGNED_MEDIA="$ALLOW_UNSIGNED_MEDIA" \
  SEED_CLOSURE="$SEED_CLOSURE" SEED_TRUSTED_NOW="$SEED_TRUSTED_NOW" \
  RELEASE_MANIFEST_FILE="$RELEASE_MANIFEST_FILE" \
  RELEASE_CLOSURE_FILE="$RELEASE_CLOSURE_FILE" \
  DELEGATION_SNAPSHOT_FILE="$DELEGATION_SNAPSHOT_FILE" \
  DELEGATION_SNAPSHOT_SIGNATURE_FILE="$DELEGATION_SNAPSHOT_SIGNATURE_FILE" \
  PCR_POLICY_DIGEST="$PCR_POLICY_DIGEST" PCR_POLICY_PUBLIC_KEY_FILE="$PCR_POLICY_PUBLIC_KEY_FILE" \
  PCR_POLICY_PUBLIC_KEY_SHA256="$PCR_POLICY_PUBLIC_KEY_SHA256" \
  PCR_POLICY_SIGNATURE_FILE="$PCR_POLICY_SIGNATURE_FILE" PCR_POLICY_SIGNATURE_SHA256="$PCR_POLICY_SIGNATURE_SHA256" \
  PCR_POLICY_SEQ="$PCR_POLICY_SEQ" \
  OUT_NAME="$OUT" ./image/build-installer-usb.sh
RAW="${REPO_ROOT}/${OUT}.img"
[ -f "$RAW" ] || { echo "base raw not produced ($RAW)" >&2; exit 1; }
# WHAT THE SIGNED UKI ON THIS RAW SEALS (review 2026-09-01, P1 #4). Everything
# below keeps WRITING to $RAW -- it grows the file, rewrites the GPT and appends
# a ~20 GB ni-seed partition -- so the final gate has to inspect the sealed core
# again on the FINISHED raw. These are the values it checks against, produced by
# the build that sealed them; they are read here and forwarded, never recomputed.
SEALED_CORE_FACTS="${RAW}.sealed-core.json"
if [ ! -f "$SEALED_CORE_FACTS" ] || [ -L "$SEALED_CORE_FACTS" ]; then
  echo "the base media build declared no sealed-core facts at $SEALED_CORE_FACTS; refusing to finalize a medium whose boot path nothing would re-inspect" >&2
  exit 1
fi
# A command substitution, not a process substitution: `mapfile` always succeeds,
# so a python failure behind `< <(...)` would be silently read as an empty array.
SEALED_CORE_ARG_TEXT="$(python3 - "$SEALED_CORE_FACTS" <<'PY'
import json
import re
import sys

document = json.load(open(sys.argv[1], encoding="ascii"))
if document.get("schema") != "neural-ice-sealed-core-facts-v1":
    raise SystemExit("the sealed-core facts are not neural-ice-sealed-core-facts-v1")
for key in ("verity_root_hash", "payload_digest"):
    if not re.fullmatch(r"[0-9a-f]{64}", str(document.get(key, ""))):
        raise SystemExit(f"the sealed-core facts carry no usable {key}")
if document.get("media_mode") not in ("install", "live"):
    raise SystemExit("the sealed-core facts carry no usable media mode")
for flag, key in (
    ("--expect-verity-root-hash", "verity_root_hash"),
    ("--expect-payload-digest", "payload_digest"),
    ("--expect-mode", "media_mode"),
    ("--expect-access-profile", "access_profile"),
    ("--expect-hardware-target", "hardware_target"),
    ("--expect-trust-policy-id", "trust_policy_id"),
):
    value = str(document.get(key, ""))
    if not value:
        raise SystemExit(f"the sealed-core facts carry no {key}")
    print(flag)
    print(value)
if document.get("allow_unsigned") is True:
    print("--allow-unsigned")
PY
)" || { echo "the sealed-core facts alongside $RAW are unusable" >&2; exit 1; }
mapfile -t SEALED_CORE_ARGS <<<"$SEALED_CORE_ARG_TEXT"
[ "${#SEALED_CORE_ARGS[@]}" -ge 12 ] \
  || { echo "the sealed-core facts alongside $RAW are incomplete" >&2; exit 1; }

echo "==> 2. size the already-verified SEED v2 release pack"
EXPECTED_SEED_MANIFEST="$SEED_STAGE/expected-seed-manifest.json"
python3 image/seed-tree-manifest.py --tree "seed=${SEED_STAGE}/seed" \
  --output "$EXPECTED_SEED_MANIFEST"
SEED_BYTES="$(du -sb "$SEED_STAGE/seed" | cut -f1)"
GROW="$(preloaded_seed_growth_bytes "$SEED_BYTES" 0 0)"
echo "    seed-v2 ≈ $((SEED_BYTES/1024/1024/1024)) GiB → grow raw by $((GROW/1024/1024/1024)) GiB"
truncate -s "+${GROW}" "$RAW"

echo "==> 3. relocate GPT backup header + append the ni-seed partition"
sudo sgdisk -e "$RAW"
# bootc raw ships unnamed GPT entries; the media gate matches PARTLABEL.
# Persistent-layout analysis (AGENTS.md §media): this names partition 1 of the
# GENERATED media raw at build time — additive GPT metadata only (no offsets,
# type GUIDs or data move; UEFI boots the ESP by type GUID, never by name).
# Recovery: sgdisk failure fails the build before the media gate — nothing
# ships. One-version rollback: media built WITHOUT this line is refused by the
# media gate itself ("exactly one EFI-SYSTEM child partition") and never
# ships; installed systems are untouched (the installer re-partitions the
# internal disk with its own labels — this line concerns only the USB media).
sudo sgdisk -c 1:EFI-SYSTEM "$RAW"
sudo sgdisk -n 0:0:0 -c 0:ni-seed -t 0:8300 "$RAW"          # new part = all free space
SEEDNUM="$(sudo sgdisk -p "$RAW" | awk '/ni-seed/{n=$1} END{print n}')"
[ -n "$SEEDNUM" ] || { echo "ni-seed partition not created" >&2; exit 1; }
echo "    ni-seed = partition #${SEEDNUM}"

echo "==> 4. mkfs + copy the exact release pack into ni-seed"
LOOP=''
SEEDPART=''
MOUNT_DIR="$(sudo mktemp -d /run/ni-seed-build.XXXXXX)"
MOUNTED=0
RAW_INO="$(stat -Lc '%i' "$RAW")"
RAW_DEV="$(python3 - "$RAW" <<'PY'
import os
import sys

metadata = os.stat(sys.argv[1])
print(f"{os.major(metadata.st_dev)}:{os.minor(metadata.st_dev)}")
PY
)"
loop_is_ours() {
  [ -n "$LOOP" ] || return 1
  sudo losetup --json --list --output NAME,BACK-INO,BACK-MAJ:MIN |
    python3 -c '
import json
import sys
loop, inode, device = sys.argv[1:]
document = json.load(sys.stdin)
raise SystemExit(0 if any(
    entry.get("name") == loop
    and str(entry.get("back-ino")) == inode
    and entry.get("back-maj:min") == device
    for entry in document.get("loopdevices", [])
) else 1)
' "$LOOP" "$RAW_INO" "$RAW_DEV"
}
cleanup() {
  set +e
  if (( MOUNTED )) && [ -n "$MOUNT_DIR" ]; then
    source="$(sudo findmnt -n -o SOURCE --target "$MOUNT_DIR" 2>/dev/null || true)"
    if [ "$source" = "$SEEDPART" ]; then
      sudo umount "$MOUNT_DIR" 2>/dev/null || true
    fi
  fi
  MOUNTED=0
  if [ -n "$LOOP" ] && loop_is_ours; then
    sudo losetup -d "$LOOP" 2>/dev/null || true
  fi
  LOOP=''
  SEEDPART=''
  if [ -n "$MOUNT_DIR" ]; then
    sudo rmdir "$MOUNT_DIR" 2>/dev/null || true
  fi
  seedcleanup
}
trap cleanup EXIT
LOOP="$(sudo losetup --find --show -P "$RAW")"; sudo udevadm settle
SEEDPART="${LOOP}p${SEEDNUM}"
sudo mkfs.xfs -q -L ni-seed "$SEEDPART"
sudo mount "$SEEDPART" "$MOUNT_DIR"
MOUNTED=1
sudo install -d -m 0755 "$MOUNT_DIR/seed"
sudo cp -a "$SEED_STAGE/seed/." "$MOUNT_DIR/seed/"
sudo sync
echo "    ni-seed content:"; sudo du -sh "$MOUNT_DIR/seed"
sudo umount "$MOUNT_DIR"
MOUNTED=0
loop_is_ours || { echo "refusing to detach a loop whose backing identity changed" >&2; exit 1; }
sudo losetup -d "$LOOP"
LOOP=''
SEEDPART=''
sudo rmdir "$MOUNT_DIR"
MOUNT_DIR=''

case "$COMPRESS" in
  zstd-fast|zstd-max) ART="${REPO_ROOT}/${OUT}.img.zst" ;;
  xz)                 ART="${REPO_ROOT}/${OUT}.img.xz" ;;
  none)               ART="$RAW" ;;
  *) echo "invalid COMPRESS" >&2; exit 2 ;;
esac
ART_CHECKSUM="${ART}.sha256"
FINAL_MEDIA_RECEIPT="${RAW}.final-media.json"
FINAL_MEDIA_RECEIPT_CHECKSUM="${FINAL_MEDIA_RECEIPT}.sha256"

echo "==> 5. accept the exact raw and build the digest-bound release artifact"
final_media_baseline_args=()
if [[ -n "$LAB_BASELINE_BOM_SHA256" || -n "$LAB_BASELINE_SIGNATURE_SHA256" ]]; then
  [[ "$LAB_BASELINE_BOM_SHA256" =~ ^[0-9a-f]{64}$ \
     && "$LAB_BASELINE_SIGNATURE_SHA256" =~ ^[0-9a-f]{64}$ ]] \
    || { echo "invalid or incomplete LAB baseline SHA-256 inputs" >&2; exit 1; }
  final_media_baseline_args=(
    --lab-baseline-bom-sha256 "$LAB_BASELINE_BOM_SHA256"
    --lab-baseline-signature-sha256 "$LAB_BASELINE_SIGNATURE_SHA256"
  )
fi
final_media_ssh_key_args=()
if [[ -n "$SSH_AUTHORIZED_KEYS_SHA256" ]]; then
  final_media_ssh_key_args=(--esp-authorized-keys-sha256 "$SSH_AUTHORIZED_KEYS_SHA256")
fi
# THE FULL SEALED-CORE INSPECTION HAPPENS INSIDE THIS GATE, under the exclusive
# lock it holds on the finished raw and before it publishes anything: the
# artifact, its checksum, the receipt and the receipt's checksum all come after
# it. That ordering is the whole of P1 #4 -- the sealed core used to be inspected
# only on the LIGHT raw, i.e. before steps 2-4 above grew the file, rewrote the
# GPT and appended ni-seed.
sudo python3 image/verify-preloaded-media.py \
  --raw "$RAW" \
  --expected-manifest "$EXPECTED_SEED_MANIFEST" \
  --release-closure-sha256 "$SEED_CLOSURE" \
  --release-manifest-sha256 "$(sha256sum -- "$RELEASE_MANIFEST_FILE" | awk '{print tolower($1)}')" \
  --artifact "$ART" \
  --artifact-checksum "$ART_CHECKSUM" \
  --compression "$COMPRESS" \
  --receipt "$FINAL_MEDIA_RECEIPT" \
  --receipt-checksum "$FINAL_MEDIA_RECEIPT_CHECKSUM" \
  "${SEALED_CORE_ARGS[@]}" \
  "${final_media_baseline_args[@]}" "${final_media_ssh_key_args[@]}"
seedcleanup; trap - EXIT

echo "==> PRELOADED installer ready: ${ART}"
ls -lh "$ART" "$ART_CHECKSUM" "$FINAL_MEDIA_RECEIPT" "$FINAL_MEDIA_RECEIPT_CHECKSUM"
