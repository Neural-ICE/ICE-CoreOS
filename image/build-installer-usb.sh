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

# Exact base the installer is built on. No mutable or legacy default is allowed.
BASE_IMAGE="${BASE_IMAGE:-}"
# Exact imgref installed by the autoinstaller. The source artifact's native timer is
# masked; later movement is owned by the signed Fabric train controller via bootc switch.
# Defaulting to the exact BASE_IMAGE preserves byte identity through installation.
TARGET_IMGREF="${TARGET_IMGREF:-$BASE_IMAGE}"
INSTALLER_IMG="${INSTALLER_IMG:-localhost/ice-coreos-installer:local}"
# bib output (root-owned, ~40 GiB) lives OUTSIDE the checkout so it never
# pollutes the workspace (a root-owned file there breaks the next CI checkout).
OUT="${OUT:-${RUNNER_TEMP:-/var/tmp}/ice-coreos-bib}"
OUT_NAME="${OUT_NAME:-}"            # if set, copy the final raw to <REPO>/<OUT_NAME>.img
BG_SRC="${BG_SRC:-${REPO_ROOT}/image/branding/grub-bg.png}"
CONFIG="${CONFIG:-${REPO_ROOT}/image/config-installer.toml}"
BIB="${BIB:-quay.io/centos-bootc/bootc-image-builder:latest@sha256:2b52843ea2bfda73b0a08d97e76b734393b1d3a804681b9fabb26723bd3a2f0b}"
# Debug media may carry an operator public key on the ESP. The expected hash is
# mandatory so a mutable build-host pathname cannot silently change the key.
SSH_AUTHORIZED_KEYS_FILE="${SSH_AUTHORIZED_KEYS_FILE:-}"
SSH_AUTHORIZED_KEYS_SHA256="${SSH_AUTHORIZED_KEYS_SHA256:-}"
LAB_BASELINE_BOM_FILE="${LAB_BASELINE_BOM_FILE:-}"
LAB_BASELINE_BOM_SHA256="${LAB_BASELINE_BOM_SHA256:-}"
LAB_BASELINE_SIGNATURE_FILE="${LAB_BASELINE_SIGNATURE_FILE:-}"
LAB_BASELINE_SIGNATURE_SHA256="${LAB_BASELINE_SIGNATURE_SHA256:-}"
LAB_BASELINE_STAGE_ROOT=""
LAB_BASELINE_HELPER="$REPO_ROOT/ota/neural-ice-lab-baseline-handoff.sh"
# shellcheck source=image/lib/debug-ssh-key.sh
source "$REPO_ROOT/image/lib/debug-ssh-key.sh"

cleanup_lab_baseline_stage() {
  if [[ -n "$LAB_BASELINE_STAGE_ROOT" ]]; then
    chmod -R u+w -- "$LAB_BASELINE_STAGE_ROOT" 2>/dev/null || true
    rm -rf -- "$LAB_BASELINE_STAGE_ROOT"
    LAB_BASELINE_STAGE_ROOT=""
  fi
}

[[ -f "$CONFIG" ]] || { echo "ERROR: missing bib config $CONFIG" >&2; exit 1; }
[[ "$BASE_IMAGE" =~ @sha256:[0-9a-f]{64}$ ]] \
  || { echo "ERROR: BASE_IMAGE is required as a digest-pinned OCI reference" >&2; exit 1; }
[[ "$TARGET_IMGREF" =~ @sha256:[0-9a-f]{64}$ ]] \
  || { echo "ERROR: TARGET_IMGREF must be a digest-pinned OCI reference" >&2; exit 1; }
# The installer records TARGET_IMGREF as the OTA origin WITHOUT fetching it
# (bootc --skip-fetch-check: the install env is air-gapped by design). The
# publication proof therefore lives HERE, at media staging, where the network
# exists: a target that differs from the staged base must resolve in its
# registry, or a mistyped/unpublished digest would be silently recorded as
# the installed system's origin. Equality with BASE_IMAGE needs no fetch —
# the staged base is already content-addressed locally.
if [[ "$TARGET_IMGREF" != "$BASE_IMAGE" ]]; then
  if command -v skopeo >/dev/null 2>&1; then
    sudo skopeo inspect --raw "docker://${TARGET_IMGREF}" >/dev/null \
      || { echo "ERROR: TARGET_IMGREF does not resolve in its registry (unpublished or mistyped digest?): ${TARGET_IMGREF}" >&2; exit 1; }
  else
    sudo podman manifest inspect "docker://${TARGET_IMGREF}" >/dev/null 2>&1 \
      || sudo podman image exists "$TARGET_IMGREF" \
      || { echo "ERROR: TARGET_IMGREF does not resolve (no skopeo; podman could not find it): ${TARGET_IMGREF}" >&2; exit 1; }
  fi
fi
debug_ssh_key_validate "$SSH_AUTHORIZED_KEYS_FILE" "$SSH_AUTHORIZED_KEYS_SHA256" \
  || { echo "ERROR: invalid debug SSH key input" >&2; exit 1; }
debug_ssh_key_require_debug_target "$SSH_AUTHORIZED_KEYS_FILE" "$BASE_IMAGE" "$TARGET_IMGREF" \
  || { echo "ERROR: debug SSH key cannot be bound to this install target" >&2; exit 1; }
lab_baseline_input_count=0
for lab_baseline_input in "$LAB_BASELINE_BOM_FILE" "$LAB_BASELINE_BOM_SHA256" \
  "$LAB_BASELINE_SIGNATURE_FILE" "$LAB_BASELINE_SIGNATURE_SHA256"; do
  [[ -z "$lab_baseline_input" ]] || lab_baseline_input_count=$((lab_baseline_input_count + 1))
done
case "$lab_baseline_input_count" in
  0) ;;
  4)
    [[ "$BASE_IMAGE" == "$TARGET_IMGREF" ]] \
      || { echo "ERROR: LAB baseline must be bound to the exact installed image digest" >&2; exit 1; }
    LAB_BASELINE_STAGE_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/ni-lab-baseline-media.XXXXXX")"
    chmod 0700 "$LAB_BASELINE_STAGE_ROOT"
    trap cleanup_lab_baseline_stage EXIT
    bash "$LAB_BASELINE_HELPER" stage-media \
      "$LAB_BASELINE_BOM_FILE" "$LAB_BASELINE_BOM_SHA256" \
      "$LAB_BASELINE_SIGNATURE_FILE" "$LAB_BASELINE_SIGNATURE_SHA256" \
      "$LAB_BASELINE_STAGE_ROOT"
    ;;
  *)
    echo "ERROR: LAB baseline requires BOM, signature and both exact SHA-256 values" >&2
    exit 1
    ;;
esac

# Build the dual-mode installer image FROM the chosen immutable base. Reusing a
# locally present digest is safe because the content address cannot drift.
echo "==> build installer image  FROM ${BASE_IMAGE}"
if sudo podman image exists "$BASE_IMAGE"; then
  echo "    (using local content-addressed ${BASE_IMAGE})"
else
  sudo podman pull "$BASE_IMAGE"
fi
if [[ -n "$SSH_AUTHORIZED_KEYS_FILE" || -n "$LAB_BASELINE_STAGE_ROOT" ]]; then
  sudo podman run --rm --network none --read-only \
    --entrypoint /usr/bin/grep "$BASE_IMAGE" \
    -qx 'PRETTY_NAME="Neural ICE CoreOS (debug)"' /usr/lib/os-release \
    || { echo "ERROR: LAB-only ESP inputs require a debug base image" >&2; exit 1; }
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
cleanup(){
  sudo umount "$MNT" 2>/dev/null || true
  sudo losetup -d "$LOOP" 2>/dev/null || true
  cleanup_lab_baseline_stage
}
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
# target; the enforcing live policy denies it) + the explicit OTA target
# (neuralice.imgref= — see TARGET_IMGREF above; never rely on the baked default).
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
    linux ${klinux} ${kopts} neuralice.autoinstall=1 enforcing=0 neuralice.imgref=${TARGET_IMGREF}
    initrd ${kinitrd}
}
EOF
fi

sync
echo "==> Dual-mode entries:"
echo "    [default] $(sudo sed -n 's/^title //p' "$live")  (BLS)"
echo "    [install] Neural ICE - Install (wipes the internal disk)  (static grub.cfg)"
echo "    [install] OTA target: neuralice.imgref=${TARGET_IMGREF}"
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
if [[ -n "$SSH_AUTHORIZED_KEYS_FILE" ]]; then
  sudo bash "$REPO_ROOT/image/lib/debug-ssh-key.sh" install \
    "$SSH_AUTHORIZED_KEYS_FILE" "$SSH_AUTHORIZED_KEYS_SHA256" "$MNT"
fi
if [[ -n "$LAB_BASELINE_STAGE_ROOT" ]]; then
  sudo bash "$LAB_BASELINE_HELPER" stage-media \
    "$LAB_BASELINE_STAGE_ROOT/ice-coreos/ota-lab-baseline.json" \
    "$LAB_BASELINE_BOM_SHA256" \
    "$LAB_BASELINE_STAGE_ROOT/ice-coreos/ota-lab-baseline.sig" \
    "$LAB_BASELINE_SIGNATURE_SHA256" "$MNT"
fi
sync
sudo umount "$MNT"; sudo losetup -d "$LOOP"
cleanup_lab_baseline_stage
trap - EXIT

if [[ -n "$OUT_NAME" ]]; then
  cp "$RAW" "${REPO_ROOT}/${OUT_NAME}.img"
  sudo chown "$(id -u):$(id -g)" "${REPO_ROOT}/${OUT_NAME}.img" 2>/dev/null || true
  echo "==> Flashable image: ${REPO_ROOT}/${OUT_NAME}.img"
else
  echo "==> Done. Flashable raw: $RAW"
fi
