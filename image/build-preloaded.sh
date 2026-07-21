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
#   VARIANT=debug COMPRESS=zstd-fast ./image/build-preloaded.sh
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
storecleanup(){ sudo rm -rf "$STORE_TMP" "$RUNROOT" 2>/dev/null||true; }
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
LOOP="$(sudo losetup --find --show -P "$RAW")"; sudo udevadm settle
cleanup(){ sudo umount /mnt/ni-seed 2>/dev/null||true; sudo losetup -d "$LOOP" 2>/dev/null||true; storecleanup; }
trap cleanup EXIT
SEEDPART="${LOOP}p${SEEDNUM}"
sudo mkfs.xfs -q -L ni-seed "$SEEDPART"
sudo mkdir -p /mnt/ni-seed; sudo mount "$SEEDPART" /mnt/ni-seed
sudo mkdir -p /mnt/ni-seed/store /mnt/ni-seed/models
# cp -a preserves the overlay store faithfully (hardlinks + trusted.* xattrs, hence sudo).
sudo cp -a "$STORE_TMP/." /mnt/ni-seed/store/
sudo cp -a "$SEED_MODELS/." /mnt/ni-seed/models/
if [ -n "$SEED_PAYLOAD" ]; then
  sudo mkdir -p /mnt/ni-seed/payload
  sudo cp -a "$SEED_PAYLOAD/." /mnt/ni-seed/payload/
  echo "    payload: $(basename "$SEED_PAYLOAD") ($(sudo du -sh /mnt/ni-seed/payload | cut -f1))"
fi
sudo sync
echo "    ni-seed content:"; sudo du -sh /mnt/ni-seed/store /mnt/ni-seed/models
sudo umount /mnt/ni-seed; sudo losetup -d "$LOOP"; storecleanup; trap - EXIT

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
