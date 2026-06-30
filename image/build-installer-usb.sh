#!/usr/bin/env bash
#
# Neural ICE CoreOS — build the dual-mode (Live + Install) installer USB image.
#
#   1) bootc-image-builder --type raw on the SIGNED installer image
#   2) post-process the raw's GRUB:
#        - "Neural ICE CoreOS"  (Live, default — boots without touching disks)
#        - "Neural ICE - Install (wipes the internal disk)"  (adds neuralice.autoinstall=1)
#        - background image + visible 30s menu
#
# Produces a flashable raw at $OUT/image/disk.raw. Flash with:
#   sudo dd if=<raw> of=/dev/sdX bs=64M oflag=direct conv=fsync status=progress
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# Channel base the installer is built on (vanilla, no baked key for community).
BASE_IMAGE="${BASE_IMAGE:-ghcr.io/neural-ice/neural-ice-coreos:prod}"
INSTALLER_IMG="${INSTALLER_IMG:-localhost/ice-coreos-installer:local}"
# bib output (root-owned, ~40 GiB) lives OUTSIDE the checkout so it never
# pollutes the workspace (a root-owned file there breaks the next CI checkout).
OUT="${OUT:-${RUNNER_TEMP:-/var/tmp}/ice-coreos-bib}"
OUT_NAME="${OUT_NAME:-}"            # if set, copy the final raw to <REPO>/<OUT_NAME>.img
BG_SRC="${BG_SRC:-${REPO_ROOT}/image/branding/grub-bg.png}"
CONFIG="${CONFIG:-${REPO_ROOT}/image/config-installer.toml}"
BIB="${BIB:-quay.io/centos-bootc/bootc-image-builder:latest}"

[[ -f "$CONFIG" ]] || { echo "ERROR: missing bib config $CONFIG" >&2; exit 1; }

# Build the dual-mode installer image FROM the chosen channel base.
echo "==> build installer image  FROM ${BASE_IMAGE}"
sudo podman pull "$BASE_IMAGE" 2>/dev/null || echo "    (using local ${BASE_IMAGE})"
sudo podman build --platform linux/arm64 \
  --build-arg "BASE_IMAGE=${BASE_IMAGE}" \
  -f image/Containerfile.installer -t "${INSTALLER_IMG}" "${REPO_ROOT}"

echo "==> bootc-image-builder --type raw  (${INSTALLER_IMG})  config=${CONFIG}"
sudo rm -rf "$OUT"; mkdir -p "$OUT"
sudo podman run --rm --privileged --security-opt label=type:unconfined_t \
  -v /var/lib/containers/storage:/var/lib/containers/storage \
  -v "$OUT":/output \
  -v "$CONFIG":/config.toml:ro \
  "$BIB" build --type raw --local --config /config.toml "$INSTALLER_IMG"

RAW="$OUT/image/disk.raw"
[[ -f "$RAW" ]] || { echo "ERROR: raw not produced ($RAW)" >&2; exit 1; }

echo "==> post-process GRUB (dual-mode Live + Install)"
LOOP="$(sudo losetup --find --show -P "$RAW")"; sudo udevadm settle
MNT=/mnt/ni-postproc
cleanup(){ sudo umount "$MNT" 2>/dev/null || true; sudo losetup -d "$LOOP" 2>/dev/null || true; }
trap cleanup EXIT

# Boot partition = the one labelled "boot".
BOOTPART=""
for p in "${LOOP}"p*; do
  [[ "$(sudo blkid -s LABEL -o value "$p" 2>/dev/null)" == "boot" ]] && { BOOTPART="$p"; break; }
done
[[ -n "$BOOTPART" ]] || { echo "ERROR: boot partition not found" >&2; exit 1; }
sudo mkdir -p "$MNT"; sudo mount "$BOOTPART" "$MNT"

ENTRIES="$MNT/loader/entries"
live="$(find "$ENTRIES" -name 'ostree-*.conf' ! -name '*install*' | head -1)"
[[ -n "$live" ]] || { echo "ERROR: no BLS entry produced by bib" >&2; exit 1; }

# Live entry is the default (highest version). Title already branded via os-release.
sudo sed -i 's/^version .*/version 1/' "$live"

# Install entry = Live + autoinstall karg, lower version (shown second).
inst="$ENTRIES/ostree-0-install.conf"
sudo cp "$live" "$inst"
sudo sed -i \
  -e 's/^title .*/title Neural ICE - Install (wipes the internal disk)/' \
  -e 's/^version .*/version 0/' \
  "$inst"
# Append the autoinstall karg + boot the installer SELinux-permissive (bootc
# install needs to relabel the target; the enforcing live policy denies it).
sudo grep -q 'neuralice.autoinstall=1' "$inst" || \
  sudo sed -i 's@^\(options .*\)$@\1 neuralice.autoinstall=1@' "$inst"
sudo grep -q 'enforcing=0' "$inst" || \
  sudo sed -i 's@^\(options .*\)$@\1 enforcing=0@' "$inst"

# Background + visible 30s menu.
if [[ -f "$BG_SRC" ]]; then sudo cp "$BG_SRC" "$MNT/grub2/neural-ice-bg.png"; fi
GCFG="$MNT/grub2/grub.cfg"
sudo grep -q 'background_image /grub2/neural-ice-bg.png' "$GCFG" || \
  sudo sed -i '0,/^set timeout=/s//if background_image \/grub2\/neural-ice-bg.png ; then true ; fi\nset timeout=/' "$GCFG"
sudo sed -i -e 's/^set timeout=.*/set timeout=30/' -e 's/^set timeout_style=.*/set timeout_style=menu/' "$GCFG"

sync
echo "==> Dual-mode entries:"
echo "    [default] $(sudo sed -n 's/^title //p' "$live")"
echo "    [install] $(sudo sed -n 's/^title //p' "$inst")"

if [[ -n "$OUT_NAME" ]]; then
  cp "$RAW" "${REPO_ROOT}/${OUT_NAME}.img"
  sudo chown "$(id -u):$(id -g)" "${REPO_ROOT}/${OUT_NAME}.img" 2>/dev/null || true
  echo "==> Flashable image: ${REPO_ROOT}/${OUT_NAME}.img"
else
  echo "==> Done. Flashable raw: $RAW"
fi
