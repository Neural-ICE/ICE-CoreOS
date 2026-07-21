#!/usr/bin/env bash
#
#
# Build the PRELOADED installer: the normal (LIGHT) installer raw + an extra `ni-seed`
# partition carrying a READY podman overlay image store + the base HF models. The autoinstall
# stages that partition onto the encrypted data volume and registers the store as a read-only
# additional image store — so the appliance starts fully offline (no registry pulls) with
# ZERO first-boot import: the `podman load` (untar + sha256 of ~20 GB) happens once here on
# the build host, never on the client.
#
# TODO(perf): store the seed COMPRESSED in ni-seed (zstd) and have the autoinstall decompress it
# on-the-fly while writing to the fast NVMe data volume — smaller USB payload + leverages NVMe
# write speed. Models compress little (safetensors) but archives do.
#
# Run on an ARM64 build host with the seed staged locally. Needs sudo (losetup/mount/mkfs).
#   SEED_IMAGES=$HOME/ice-seed/images \
#   SEED_MODELS=$HOME/ice-seed/models \
#   BASE_IMAGE=registry.neural-ice.ch/neural-ice/neural-ice-appliance@sha256:<digest> \
#   SSH_AUTHORIZED_KEYS_FILE=$HOME/.ssh/id_ed25519.pub \
#   SSH_AUTHORIZED_KEYS_SHA256=<approved-public-key-file-sha256> \
#   COMPRESS=zstd-fast ./image/build-preloaded.sh
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; cd "$REPO_ROOT"

SEED_IMAGES="${SEED_IMAGES:-${HOME}/ice-seed/images}"
SEED_MODELS="${SEED_MODELS:-${HOME}/ice-seed/models}"
# Optional payload dir (a directory containing an executable apply.sh): staged onto the
# data volume by the autoinstall, applied once on first boot by the image's generic
# neural-ice-payload-apply.service. KB-sized — headroom covers it.
SEED_PAYLOAD="${SEED_PAYLOAD:-}"
BASE_IMAGE="${BASE_IMAGE:-}"
OUT="${OUT:-ice-coreos-installer-preloaded-$(tr -d '[:space:]' < VERSION)}"
COMPRESS="${COMPRESS:-zstd-fast}"

[[ "$BASE_IMAGE" =~ @sha256:[0-9a-f]{64}$ ]] \
  || { echo "BASE_IMAGE is required as the signed train's digest-pinned appliance ref" >&2; exit 1; }
[ -d "$SEED_IMAGES" ] || { echo "missing SEED_IMAGES $SEED_IMAGES" >&2; exit 1; }
[ -d "$SEED_MODELS" ] || { echo "missing SEED_MODELS $SEED_MODELS" >&2; exit 1; }
[ -z "$SEED_PAYLOAD" ] || [ -x "$SEED_PAYLOAD/apply.sh" ] || { echo "SEED_PAYLOAD set but $SEED_PAYLOAD/apply.sh missing/not executable" >&2; exit 1; }
# The qualified cache is commonly exposed through a stable symlink. Resolve
# each root once so `du` sizes the actual tree rather than the tiny symlink
# inode, and the later copy consumes the same namespace that was sized.
SEED_IMAGES="$(cd -- "$SEED_IMAGES" && pwd -P)"
SEED_MODELS="$(cd -- "$SEED_MODELS" && pwd -P)"
if [ -n "$SEED_PAYLOAD" ]; then
  SEED_PAYLOAD="$(cd -- "$SEED_PAYLOAD" && pwd -P)"
fi

echo "==> 1. build the base installer raw FROM ${BASE_IMAGE}  (uncompressed)"
# OUT means "output NAME" here but "bib output DIR" in build-installer-usb.sh —
# drop it from the child env so an exported OUT never leaks in as a bogus bib dir.
env -u OUT BASE_IMAGE="$BASE_IMAGE" OUT_NAME="$OUT" ./image/build-installer-usb.sh
RAW="${REPO_ROOT}/${OUT}.img"
[ -f "$RAW" ] || { echo "base raw not produced ($RAW)" >&2; exit 1; }

echo "==> 2. build the READY overlay image store (ONCE, here) + size the seed"
# The untar + sha256 of the images happens once here on the build host — never on the client.
# Build to a TEMP store first so we can measure its REAL (extracted) size: a loaded overlay store
# is much bigger than the *.tar archives (a large image can extract to several times its packed
# size), so the ni-seed partition MUST be sized from the store, not the archives. Image refs are
# preserved so the Quadlets resolve them offline.
# Both dirs are created with sudo (root-owned): /run is not user-writable, and rootful podman
# wants a root-owned graphroot. All reads/copies/cleanup below therefore go through sudo.
STORE_TMP="$(sudo mktemp -d /var/tmp/ni-seed-store.XXXXXX)"
RUNROOT="$(sudo mktemp -d /run/ni-seed-runroot.XXXXXX)"
VERIFY_TMP="$(sudo mktemp -d /var/tmp/ni-seed-verify.XXXXXX)"
EXPECTED_SEED_MANIFEST="${VERIFY_TMP}/expected-seed-manifest.json"
storecleanup(){ sudo rm -rf "$STORE_TMP" "$RUNROOT" "$VERIFY_TMP" 2>/dev/null||true; }
trap storecleanup EXIT
shopt -s nullglob
archives=("$SEED_IMAGES"/*.tar)
[ ${#archives[@]} -gt 0 ] || { echo "no *.tar archives in $SEED_IMAGES" >&2; exit 1; }
for a in "${archives[@]}"; do
  echo "    + loading $(basename "$a") into the overlay store"
  sudo podman --root "$STORE_TMP" --runroot "$RUNROOT" --storage-driver overlay load -i "$a"
done
echo "    store images:"
sudo podman --root "$STORE_TMP" --runroot "$RUNROOT" --storage-driver overlay images

# Freeze the complete approved source namespace before copying it. The final-media gate below
# re-creates this manifest from the finalized XFS partition through a genuinely read-only loop.
# Any concurrent source mutation therefore makes the build refuse instead of silently changing
# the installer payload.
manifest_args=(
  --tree "store=${STORE_TMP}"
  --tree "models=${SEED_MODELS}"
)
if [ -n "$SEED_PAYLOAD" ]; then
  manifest_args+=(--tree "payload=${SEED_PAYLOAD}")
fi
sudo python3 image/seed-tree-manifest.py \
  "${manifest_args[@]}" \
  --output "$EXPECTED_SEED_MANIFEST"

STORE_BYTES="$(sudo du -sb "$STORE_TMP" | cut -f1)"
MODELS_BYTES="$(sudo du -sb "$SEED_MODELS" | cut -f1)"
SEED_BYTES=$(( STORE_BYTES + MODELS_BYTES ))
GROW=$(( SEED_BYTES + SEED_BYTES/10 + 4*1024*1024*1024 ))   # store+models + 10% + 4 GiB headroom
GROW=$(( (GROW + 1048575) / 1048576 * 1048576 ))            # round up to 1 MiB (avoid sub-sector GPT gaps)
echo "    store ≈ $((STORE_BYTES/1024/1024/1024)) GiB, models ≈ $((MODELS_BYTES/1024/1024/1024)) GiB → grow raw by $((GROW/1024/1024/1024)) GiB"
truncate -s "+${GROW}" "$RAW"

echo "==> 3. relocate GPT backup header + append the ni-seed partition"
sudo sgdisk -e "$RAW"
sudo sgdisk -n 0:0:0 -c 0:ni-seed -t 0:8300 "$RAW"          # new part = all free space
SEEDNUM="$(sudo sgdisk -p "$RAW" | awk '/ni-seed/{n=$1} END{print n}')"
[ -n "$SEEDNUM" ] || { echo "ni-seed partition not created" >&2; exit 1; }
echo "    ni-seed = partition #${SEEDNUM}"

echo "==> 4. mkfs + copy the store + models into ni-seed"
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
  storecleanup
}
trap cleanup EXIT
LOOP="$(sudo losetup --find --show -P "$RAW")"; sudo udevadm settle
SEEDPART="${LOOP}p${SEEDNUM}"
sudo mkfs.xfs -q -L ni-seed "$SEEDPART"
sudo mount "$SEEDPART" "$MOUNT_DIR"
MOUNTED=1
sudo mkdir -p "$MOUNT_DIR/store" "$MOUNT_DIR/models"
# cp -a preserves the overlay store faithfully (hardlinks + trusted.* xattrs, hence sudo).
sudo cp -a "$STORE_TMP/." "$MOUNT_DIR/store/"
sudo cp -a "$SEED_MODELS/." "$MOUNT_DIR/models/"
if [ -n "$SEED_PAYLOAD" ]; then
  sudo mkdir -p "$MOUNT_DIR/payload"
  sudo cp -a "$SEED_PAYLOAD/." "$MOUNT_DIR/payload/"
  echo "    payload: $(basename "$SEED_PAYLOAD") ($(sudo du -sh "$MOUNT_DIR/payload" | cut -f1))"
fi
sudo sync
echo "    ni-seed content:"; sudo du -sh "$MOUNT_DIR/store" "$MOUNT_DIR/models"
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
sudo python3 image/verify-preloaded-media.py \
  --raw "$RAW" \
  --expected-manifest "$EXPECTED_SEED_MANIFEST" \
  --artifact "$ART" \
  --artifact-checksum "$ART_CHECKSUM" \
  --compression "$COMPRESS" \
  --receipt "$FINAL_MEDIA_RECEIPT" \
  --receipt-checksum "$FINAL_MEDIA_RECEIPT_CHECKSUM"
storecleanup; trap - EXIT

echo "==> PRELOADED installer ready: ${ART}"
ls -lh "$ART" "$ART_CHECKSUM" "$FINAL_MEDIA_RECEIPT" "$FINAL_MEDIA_RECEIPT_CHECKSUM"
