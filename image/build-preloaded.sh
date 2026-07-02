#!/usr/bin/env bash
#
# Build the PRELOADED installer: the normal (LIGHT) installer raw + an extra `ni-seed`
# partition carrying the appliance's container-image OCI archives and the base HF models.
# The autoinstall stages that partition onto the encrypted data volume; first boot imports
# the images into podman storage → the appliance starts fully offline (no registry pulls).
#
# Run on the .63 ARM64 build host (has the seed + models). Needs sudo (losetup/mount/mkfs).
#   SEED_IMAGES=/home/user/ice-seed/images \
#   SEED_MODELS=/data/models/.../huggingface/hub \
#   BASE_IMAGE=ghcr.io/neural-ice/neural-ice-coreos:alpha-debug \
#   VARIANT=debug COMPRESS=zstd-fast ./image/build-preloaded.sh
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; cd "$REPO_ROOT"

SEED_IMAGES="${SEED_IMAGES:-/home/user/ice-seed/images}"
SEED_MODELS="${SEED_MODELS:-/data/models/Neural-ICE_cache_models/local/model-assets/huggingface/hub}"
BASE_IMAGE="${BASE_IMAGE:-ghcr.io/neural-ice/neural-ice-coreos:alpha-debug}"
OUT="${OUT:-ice-coreos-installer-preloaded-$(tr -d '[:space:]' < VERSION)}"
COMPRESS="${COMPRESS:-zstd-fast}"

[ -d "$SEED_IMAGES" ] || { echo "missing SEED_IMAGES $SEED_IMAGES" >&2; exit 1; }
[ -d "$SEED_MODELS" ] || { echo "missing SEED_MODELS $SEED_MODELS" >&2; exit 1; }

echo "==> 1. build the base installer raw FROM ${BASE_IMAGE}  (uncompressed)"
BASE_IMAGE="$BASE_IMAGE" OUT_NAME="$OUT" ./image/build-installer-usb.sh
RAW="${REPO_ROOT}/${OUT}.img"
[ -f "$RAW" ] || { echo "base raw not produced ($RAW)" >&2; exit 1; }

echo "==> 2. grow the raw to fit the seed"
SEED_BYTES="$(du -sbc "$SEED_IMAGES" "$SEED_MODELS" | tail -1 | cut -f1)"
GROW=$(( SEED_BYTES + SEED_BYTES/20 + 3*1024*1024*1024 ))   # seed + 5% + 3 GiB headroom
echo "    seed ≈ $((SEED_BYTES/1024/1024/1024)) GiB → grow raw by $((GROW/1024/1024/1024)) GiB"
truncate -s "+${GROW}" "$RAW"

echo "==> 3. relocate GPT backup header + append the ni-seed partition"
sudo sgdisk -e "$RAW"
sudo sgdisk -n 0:0:0 -c 0:ni-seed -t 0:8300 "$RAW"          # new part = all free space
SEEDNUM="$(sudo sgdisk -p "$RAW" | awk '/ni-seed/{n=$1} END{print n}')"
[ -n "$SEEDNUM" ] || { echo "ni-seed partition not created" >&2; exit 1; }
echo "    ni-seed = partition #${SEEDNUM}"

echo "==> 4. mkfs + copy the seed into ni-seed"
LOOP="$(sudo losetup --find --show -P "$RAW")"; sudo udevadm settle
cleanup(){ sudo umount /mnt/ni-seed 2>/dev/null||true; sudo losetup -d "$LOOP" 2>/dev/null||true; }
trap cleanup EXIT
SEEDPART="${LOOP}p${SEEDNUM}"
sudo mkfs.xfs -q -L ni-seed "$SEEDPART"
sudo mkdir -p /mnt/ni-seed; sudo mount "$SEEDPART" /mnt/ni-seed
sudo mkdir -p /mnt/ni-seed/images /mnt/ni-seed/models
sudo cp -a "$SEED_IMAGES/." /mnt/ni-seed/images/
sudo cp -a "$SEED_MODELS/." /mnt/ni-seed/models/
sudo sync
echo "    ni-seed content:"; sudo du -sh /mnt/ni-seed/images /mnt/ni-seed/models
sudo umount /mnt/ni-seed; sudo losetup -d "$LOOP"; trap - EXIT

echo "==> 5. compress (${COMPRESS})"
case "$COMPRESS" in
  zstd-fast) zstd -3 -T0 -c "$RAW" > "${OUT}.img.zst"; ART="${OUT}.img.zst" ;;
  zstd-max)  zstd -19 --long -T0 -c "$RAW" > "${OUT}.img.zst"; ART="${OUT}.img.zst" ;;
  none)      ART="$RAW" ;;
  xz)        xz -T0 -1 -c "$RAW" > "${OUT}.img.xz"; ART="${OUT}.img.xz" ;;
  *) echo "invalid COMPRESS"; exit 2 ;;
esac
[ "$COMPRESS" = none ] || sha256sum "$ART" > "${ART}.sha256"
echo "==> PRELOADED installer ready: ${REPO_ROOT}/${ART}"
ls -lh "${REPO_ROOT}/${ART}"
