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
# LOCAL-FIRST (lesson 2026-07-04): a freshly built local tag MUST NOT be clobbered
# by a stale registry pull — the parity flash installed an old GHCR alpha-debug
# because the unconditional pull replaced the just-built local image. Refresh
# explicitly (podman pull) when a newer remote is wanted.
echo "==> build installer image  FROM ${BASE_IMAGE}"
if sudo podman image exists "$BASE_IMAGE"; then
  echo "    (using LOCAL ${BASE_IMAGE} — pull explicitly to refresh from the registry)"
else
  sudo podman pull "$BASE_IMAGE"
fi
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

# Live entry is the default. Distinct title so the USB menu can never be
# confused with the installed NVMe menu (field note: identical titles).
sudo sed -i \
  -e 's/^title .*/title Neural ICE Installer (Live)/' \
  -e 's/^version .*/version 1/' \
  "$live"
sudo rm -f "$ENTRIES/ostree-0-install.conf"   # legacy BLS clone (rendered non-deterministically)

# Install entry = STATIC menuentry in grub.cfg, NOT a BLS clone: blscfg rendering
# of a cloned entry is not deterministic (bootloader-update.service regenerates
# entries between boots) — a static entry is always rendered, always second.
# kargs: autoinstall gate + SELinux-permissive (bootc install relabels the
# target; the enforcing live policy denies it).
klinux="$(sudo sed -n 's/^linux //p' "$live" | head -1)"
kinitrd="$(sudo sed -n 's/^initrd //p' "$live" | head -1)"
kopts="$(sudo sed -n 's/^options //p' "$live" | head -1)"
[[ -n "$klinux" && -n "$kinitrd" ]] || { echo "ERROR: cannot parse kernel/initrd from $live" >&2; exit 1; }

# Background + visible 30s menu.
if [[ -f "$BG_SRC" ]]; then sudo cp "$BG_SRC" "$MNT/grub2/neural-ice-bg.png"; fi
GCFG="$MNT/grub2/grub.cfg"
sudo grep -q 'background_image /grub2/neural-ice-bg.png' "$GCFG" || \
  sudo sed -i '0,/^set timeout=/s//if background_image \/grub2\/neural-ice-bg.png ; then true ; fi\nset timeout=/' "$GCFG"
sudo sed -i -e 's/^set timeout=.*/set timeout=30/' -e 's/^set timeout_style=.*/set timeout_style=menu/' "$GCFG"

if ! sudo grep -q 'neural-ice-install' "$GCFG"; then
  sudo tee -a "$GCFG" >/dev/null <<EOF

# Neural ICE static install entry (deterministic — see docs/INSTALLER-UX-HARDENING.md)
menuentry 'Neural ICE - Install (wipes the internal disk)' --id neural-ice-install {
    linux ${klinux} ${kopts} neuralice.autoinstall=1 enforcing=0
    initrd ${kinitrd}
}
EOF
fi

sync
echo "==> Dual-mode entries:"
echo "    [default] $(sudo sed -n 's/^title //p' "$live")  (BLS)"
echo "    [install] Neural ICE - Install (wipes the internal disk)  (static grub.cfg)"
sudo umount "$MNT"

# Installer ESP: kill the shim fallback dance. \EFI\BOOT\BOOTAA64.EFI chain-loads
# fbaa64.efi, which re-creates NVRAM entries from BOOTAA64.CSV (labelled "Red Hat
# Enterprise Linux") and RESETS the machine — the scary "restore" screen. A
# one-shot installer must never touch the machine's NVRAM: remove the fallback
# binary + CSVs so the firmware boot-menu entry goes straight to our GRUB.
ESPPART=""
for p in "${LOOP}"p*; do
  [[ "$(sudo blkid -s LABEL -o value "$p" 2>/dev/null)" == "EFI-SYSTEM" ]] && { ESPPART="$p"; break; }
done
[[ -n "$ESPPART" ]] || { echo "ERROR: installer ESP not found" >&2; exit 1; }
sudo mount "$ESPPART" "$MNT"
sudo find "$MNT/EFI" -maxdepth 2 \( -iname 'fbaa64.efi' -o -iname 'BOOT*.CSV' \) -print -delete
sync
sudo umount "$MNT"; sudo losetup -d "$LOOP"; trap - EXIT

if [[ -n "$OUT_NAME" ]]; then
  cp "$RAW" "${REPO_ROOT}/${OUT_NAME}.img"
  sudo chown "$(id -u):$(id -g)" "${REPO_ROOT}/${OUT_NAME}.img" 2>/dev/null || true
  echo "==> Flashable image: ${REPO_ROOT}/${OUT_NAME}.img"
else
  echo "==> Done. Flashable raw: $RAW"
fi
