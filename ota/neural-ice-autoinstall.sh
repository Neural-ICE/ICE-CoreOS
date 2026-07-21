#!/usr/bin/env bash
#
# Neural ICE CoreOS — dual-mode installer (GRUB "Install" entry)
# Runs ONLY when the kernel was booted with `neuralice.autoinstall=1`
# (gated via ConditionKernelCommandLine in neural-ice-autoinstall.service).
#
# Installs the booted (live USB) image onto the auto-detected INTERNAL disk
# with FULL-DISK ENCRYPTION (two LUKS2 volumes, both TPM2/PCR7 auto-unlock):
#
#   p1 ESP   (1 GiB, clear)   signed EFI binaries (public)
#   p2 /boot (1 GiB, clear)   signed kernel + initramfs (public)
#   p3 LUKS  "system" 300 GiB ostree + /var          -> TPM PCR7 + recovery (internal escrow)
#   p4 LUKS  "data"   rest    /var/lib/neural-ice/data-> TPM PCR7 + recovery (CLIENT key)
#
# Recovery model: the OS is reinstallable from GHCR (nothing irreplaceable),
# so its recovery key is an internal Neural ICE escrow. Client DATA is
# irreplaceable, so the data recovery key is handed to the operator: shown on
# screen AND backed up to the USB. If the board/TPM is replaced, PCR7 changes
# and TPM auto-unlock stops; the recovery key restores access.
#
# Safe disk detection: the live media (USB) is EXCLUDED, an ambiguous target is
# REFUSED, and the operator removes the USB + presses Enter before reboot.
#
set -euo pipefail

readonly LOG_TAG="neural-ice-autoinstall"
log()  { logger -t "$LOG_TAG" -- "$*"; printf '\n[%s] %s\n' "$LOG_TAG" "$*" > /dev/console 2>/dev/null || true; printf '[%s] %s\n' "$LOG_TAG" "$*" >&2; }
die()  { log "FAILED: $*"; exit 1; }

# OTA origin recorded on the installed system = the PUBLIC channel tag, so
# `bootc upgrade` follows that channel from GHCR. Default = the imgref the CI baked into
# THIS image (channel+variant self-description, e.g. :<channel>-debug), so a debug install
# stays on the debug channel instead of jumping to :stable. Overridable via neuralice.imgref=.
# USB installers ALWAYS pass neuralice.imgref=<packaged channel> (build-installer-usb.sh):
# a promoted :stable image still carries its build channel (:beta) in the baked file
# (promotion re-tags by digest, no rebuild — ADR-0005), so the karg is authoritative here.
IMGREF="ghcr.io/neural-ice/neural-ice-coreos:stable"
if [ -r /usr/lib/neural-ice/ota-imgref ]; then
  IMGREF="$(tr -d '[:space:]' < /usr/lib/neural-ice/ota-imgref)"
fi
if grep -qE 'neuralice\.imgref=([^ ]+)' /proc/cmdline; then
  IMGREF="$(sed -n 's/.*neuralice\.imgref=\([^ ]*\).*/\1/p' /proc/cmdline)"
fi

# System (root) LUKS volume size. Data volume takes the remaining space.
# Overridable via neuralice.systemsize=<GiB>.
SYSTEM_GIB=300
if grep -qE 'neuralice\.systemsize=([0-9]+)' /proc/cmdline; then
  SYSTEM_GIB="$(sed -n 's/.*neuralice\.systemsize=\([0-9]*\).*/\1/p' /proc/cmdline)"
fi

readonly DATA_MOUNT="/var/lib/neural-ice/data"

# --------------------------------------------------------------------------- #
# 0) Preconditions: a usable TPM2 must be present (PCR7 = Secure Boot state).
# --------------------------------------------------------------------------- #
[[ -e /dev/tpmrm0 || -e /dev/tpm0 ]] || die "no TPM2 device (/dev/tpm*) — cannot enroll tpm2-luks. Enable the TPM in firmware setup."
systemd-cryptenroll --tpm2-device=list >/dev/null 2>&1 || die "systemd-cryptenroll cannot see a TPM2 device"

# Stop the boot splash so install progress (and the recovery key) is visible on
# the console — the operator must not be blind during a destructive install.
plymouth quit 2>/dev/null || true
chvt 1 2>/dev/null || true

# bootc install must set SELinux labels on the target (needs mac_admin), which
# the enforcing live policy denies. The Install GRUB entry boots permissive
# (enforcing=0 karg); force it here too as a safety net. The INSTALLED system
# keeps enforcing — bootc writes correct labels from the image policy.
setenforce 0 2>/dev/null || true

# --------------------------------------------------------------------------- #
# 1) Identify the live media disk (must NOT be touched)
# --------------------------------------------------------------------------- #
live_src="$(findmnt -no SOURCE /sysroot 2>/dev/null || findmnt -no SOURCE / 2>/dev/null)"
[[ -n "$live_src" ]] || die "cannot determine the live root device"
live_disk="$(lsblk -no PKNAME "$live_src" 2>/dev/null | head -1)"
[[ -n "$live_disk" ]] || die "cannot determine the live disk (PKNAME)"
log "Live media = /dev/$live_disk (excluded from target)"

# --------------------------------------------------------------------------- #
# 1b) Operator SSH key for the installed system (vanilla image bakes none).
#     Sources, in order: a live `neuralice.sshkey=<base64>` karg, or a plain
#     `ice-coreos/authorized_keys` file the operator dropped on the USB EFI
#     partition. Passed on to the installed system as a karg; a baked first-boot
#     service provisions it for 'core'. Empty => no key (manage later/Ignition).
# --------------------------------------------------------------------------- #
SSHKEY_B64=""
if grep -qE 'neuralice\.sshkey=([^ ]+)' /proc/cmdline; then
  SSHKEY_B64="$(sed -n 's/.*neuralice\.sshkey=\([^ ]*\).*/\1/p' /proc/cmdline)"
else
  _usb_esp="$(lsblk -rno NAME,FSTYPE "/dev/$live_disk" 2>/dev/null | awk '$2=="vfat"{print $1; exit}')"
  if [[ -n "${_usb_esp:-}" ]]; then
    _esp_mp="$(findmnt -nfo TARGET "/dev/$_usb_esp" 2>/dev/null | head -1)"
    if [[ -n "$_esp_mp" && -f "$_esp_mp/ice-coreos/authorized_keys" ]]; then
      SSHKEY_B64="$(base64 -w0 < "$_esp_mp/ice-coreos/authorized_keys")"
    fi
  fi
fi
if [[ -n "$SSHKEY_B64" ]]; then
  log "Operator SSH key found — will provision 'core' on first boot."
else
  log "No operator SSH key provided (vanilla); none will be set."
fi

# --------------------------------------------------------------------------- #
# 1c) Optional root-signed LAB baseline receipt for the installed OTA service.
#     The installer only snapshots a structurally safe byte pair; it does not
#     parse the JSON or make any signature/trust decision. ICE-Fabric owns that
#     verification after first boot. A partial or unsafe pair aborts BEFORE the
#     internal disk is touched; an absent pair preserves ordinary installs.
# --------------------------------------------------------------------------- #
readonly LAB_BASELINE_HANDOFF="/usr/local/libexec/neural-ice-lab-baseline-handoff"
readonly LAB_BASELINE_SNAPSHOT="/run/neural-ice-installer/lab-baseline"
LAB_BASELINE_PRESENT=0
_lab_usb_esp="$(lsblk -rno NAME,FSTYPE "/dev/$live_disk" 2>/dev/null | awk '$2=="vfat"{print $1; exit}')"
if [[ -n "${_lab_usb_esp:-}" ]]; then
  _lab_esp_mp="$(findmnt -nfo TARGET "/dev/$_lab_usb_esp" 2>/dev/null | head -1)"
  _lab_esp_we_mounted=0
  if [[ -z "$_lab_esp_mp" ]]; then
    _lab_esp_mp="/run/neural-ice-lab-esp"
    install -d -m 0700 "$_lab_esp_mp"
    mount -o ro "/dev/$_lab_usb_esp" "$_lab_esp_mp" \
      || die "cannot mount the installer ESP read-only for LAB baseline preflight"
    _lab_esp_we_mounted=1
  fi

  _lab_snapshot_rc=0
  "$LAB_BASELINE_HANDOFF" snapshot "$_lab_esp_mp" "$LAB_BASELINE_SNAPSHOT" \
    || _lab_snapshot_rc=$?
  if (( _lab_esp_we_mounted == 1 )); then
    umount "$_lab_esp_mp" || die "cannot unmount the installer ESP after LAB baseline preflight"
  fi
  case "$_lab_snapshot_rc" in
    0)
      LAB_BASELINE_PRESENT=1
      log "Optional LAB baseline receipt pair found and safely snapshotted."
      ;;
    3)
      log "No optional LAB baseline receipt pair on the installer ESP."
      ;;
    *)
      die "optional LAB baseline receipt pair failed structural preflight"
      ;;
  esac
else
  log "No installer ESP found for the optional LAB baseline receipt pair."
fi

# --------------------------------------------------------------------------- #
# 2) Pick the internal target disk: type=disk, != live, transport != usb
#    -> largest candidate ; ambiguity = abort (unless neuralice.target= given).
# --------------------------------------------------------------------------- #
mapfile -t candidates < <(
  lsblk -dnbo NAME,TYPE,TRAN,SIZE 2>/dev/null | \
  awk -v live="$live_disk" '$2=="disk" && $1!=live && $3!="usb" {print $4, $1}' | \
  sort -rn
)
[[ "${#candidates[@]}" -ge 1 ]] || die "no internal target disk found (excluding live/USB)"

target="/dev/$(echo "${candidates[0]}" | awk '{print $2}')"
if [[ "${#candidates[@]}" -gt 1 ]]; then
  if grep -qE 'neuralice\.target=([^ ]+)' /proc/cmdline; then
    target="$(sed -n 's/.*neuralice\.target=\([^ ]*\).*/\1/p' /proc/cmdline)"
    log "Multiple disks — explicit target via kernel arg: $target"
  else
    log "Candidate disks: ${candidates[*]}"
    die "multiple internal disks — pass neuralice.target=/dev/XXX to disambiguate"
  fi
fi
[[ -b "$target" ]] || die "invalid target: $target"
target_serial="$(lsblk -dno SERIAL "$target" 2>/dev/null | head -1 || true)"
: "${target_serial:=unknown}"

# Provision/attest the dedicated device root before the selected target is
# touched.  A malformed occupied handle is therefore a non-destructive
# refusal rather than an error after repartitioning.  The preflight receipt is
# deliberately ephemeral: after bootc has created the stateroot, the exact
# same helper attests that handle again and persists its public receipt below.
readonly DEVICE_ROOT_PREFLIGHT_IDENTITY="/run/neural-ice-installer/device-root-preflight-v1.json"
install -d -m 0700 "$(dirname -- "$DEVICE_ROOT_PREFLIGHT_IDENTITY")"
/usr/libexec/neural-ice-device-root ensure \
  --identity "$DEVICE_ROOT_PREFLIGHT_IDENTITY" \
  >/dev/null \
  || die "cannot preflight the dedicated TPM device-root before disk writes"
log "Dedicated TPM device-root preflight passed."

log "Internal target disk = $target (serial $target_serial) — WIPING + ENCRYPTING in 5s…"
sleep 5

# --------------------------------------------------------------------------- #
# 3) Partition the target (GPT): ESP, /boot, LUKS system, LUKS data
# --------------------------------------------------------------------------- #
# Partition device name helper (nvme0n1 -> nvme0n1pN ; sda -> sdaN)
partdev() { case "$target" in *[0-9]) echo "${target}p$1";; *) echo "${target}$1";; esac; }
ESP="$(partdev 1)"; BOOT="$(partdev 2)"; SYSP="$(partdev 3)"; DATAP="$(partdev 4)"

# Target mountpoint for the install (real dir; /mnt is a dangling symlink in
# the bootc container image — see the install step below).
readonly TGT=/var/tmp/nitarget
mkdir -p "$TGT"

# Clean any leftovers from a previous failed attempt on this target so the
# wipe/partitioning is not blocked by open LUKS mappers or stale mounts.
umount -R "$TGT" 2>/dev/null || true
for m in system data; do
  cryptsetup close "$m" 2>/dev/null || true
  if [[ -e "/dev/mapper/$m" ]]; then
    dmsetup remove --force "$m" 2>/dev/null || true
  fi
done
udevadm settle

log "Partitioning $target (ESP 1G, /boot 1G, system ${SYSTEM_GIB}G LUKS, data rest LUKS)…"
wipefs -a "$target" >/dev/null 2>&1 || true
# GPT via sfdisk (util-linux) — type GUIDs are cosmetic here (LUKS is opened
# explicitly), the EFI System type is the only one that must be correct.
# --force overrules the "disk in use" safety check (we own this target and have
# just freed it above) so a retried install is not blocked by stale holders.
sfdisk --force --wipe always --wipe-partitions always "$target" <<EOF
label: gpt
size=1GiB, type=uefi, name="EFI-SYSTEM"
size=1GiB, type=linux, name="boot"
size=${SYSTEM_GIB}GiB, type=linux, name="system-luks"
type=linux, name="data-luks"
EOF
partx -u "$target" 2>/dev/null || true
udevadm settle
for p in "$ESP" "$BOOT" "$SYSP" "$DATAP"; do [[ -b "$p" ]] || die "partition $p missing after sfdisk"; done

mkfs.fat -F32 -n EFI-SYSTEM "$ESP" >/dev/null
mkfs.ext4 -q -L boot "$BOOT"

# --------------------------------------------------------------------------- #
# 4) Encrypt: format LUKS2, enroll TPM2/PCR7, add a recovery key, drop bootstrap
# --------------------------------------------------------------------------- #
# Enrolls one LUKS2 volume: TPM2(PCR7) auto-unlock + a printed recovery key.
# Echoes the recovery key on stdout. Leaves the volume OPEN as /dev/mapper/$2.
enroll_luks() {  # $1=partition  $2=mapper-name
  local part="$1" name="$2" kf rec
  kf="$(mktemp /run/nialuks.XXXXXX)"; head -c 64 /dev/urandom > "$kf"
  cryptsetup luksFormat --type luks2 --batch-mode --pbkdf argon2id "$part" "$kf" >/dev/null
  cryptsetup open "$part" "$name" --key-file "$kf" >/dev/null
  # TPM2 sealed to PCR7 (Secure Boot state) -> survives kernel/bootc upgrades.
  # Bootstrap keyfile = slot 0, TPM = slot 1, recovery = slot 2.
  systemd-cryptenroll --unlock-key-file="$kf" --tpm2-device=auto --tpm2-pcrs=7 "$part" >/dev/null
  # Escrow / client recovery key — the key is printed on stdout, prose on stderr.
  rec="$(systemd-cryptenroll --unlock-key-file="$kf" --recovery-key "$part" 2>/dev/null)"
  # Drop the bootstrap keyfile slot (slot 0): only TPM + recovery remain.
  # (cryptsetup refuses to kill a slot using that slot's own key; cryptenroll does.)
  systemd-cryptenroll --unlock-key-file="$kf" --wipe-slot=0 "$part" >/dev/null
  shred -u "$kf" 2>/dev/null || rm -f "$kf"
  printf '%s' "$rec"
}

log "Encrypting system volume (TPM PCR7 + recovery)…"
SYS_RECOVERY="$(enroll_luks "$SYSP" system)"
log "Encrypting data volume (TPM PCR7 + CLIENT recovery)…"
DATA_RECOVERY="$(enroll_luks "$DATAP" data)"

mkfs.xfs -q -L sysroot /dev/mapper/system
mkfs.xfs -q -L data    /dev/mapper/data

# Root (system) is unlocked in the initramfs via rd.luks kargs (below). The data
# volume is unlocked by the image-baked /etc/crypttab (by GPT label data-luks)
# and mounted via the systemd.mount-extra karg — so only these are needed here.
SYS_LUKS_UUID="$(cryptsetup luksUUID "$SYSP")"
SYS_FS_UUID="$(blkid -s UUID -o value /dev/mapper/system)"
BOOT_UUID="$(blkid -s UUID -o value "$BOOT")"

# --------------------------------------------------------------------------- #
# 5) Install the live image onto the encrypted root (native bootc method)
# --------------------------------------------------------------------------- #
log "Copying the booted image into podman storage (copy-to-storage)…"
# NOTE: the live USB root is sized large enough (see image/config-installer.toml,
# filesystem "/" minsize) to hold this image copy; copy-to-storage uses the
# normal, correctly-SELinux-labelled /var/lib/containers + /var/tmp.
bootc image copy-to-storage || die "bootc image copy-to-storage failed"

# bootc/ostree images symlink /mnt -> /var/mnt (dangling inside the install
# container) so a bind onto /mnt fails ("creating /mnt: No such file"). Use a
# real directory whose parent exists in the container image instead.
mount /dev/mapper/system "$TGT"
mkdir -p "$TGT/boot"
mount "$BOOT" "$TGT/boot"
mkdir -p "$TGT/boot/efi"
mount "$ESP" "$TGT/boot/efi"
# Make the target (+ submounts) shared so they propagate into the container.
mount --rbind "$TGT" "$TGT"
mount --make-rshared "$TGT"

# Optional operator SSH key, provisioned by the baked first-boot service.
sshkey_karg=()
[[ -n "$SSHKEY_B64" ]] && sshkey_karg=(--karg "neuralice.sshkey=$SSHKEY_B64")

log "bootc install to-filesystem (encrypted root, OTA origin: $IMGREF)…"
podman run --rm --privileged --pid=host \
  --security-opt label=type:unconfined_t \
  -v /dev:/dev -v /var/lib/containers:/var/lib/containers \
  --mount "type=bind,source=$TGT,target=$TGT,bind-propagation=rshared" \
  localhost/bootc \
  bootc install to-filesystem \
    --source-imgref containers-storage:localhost/bootc \
    --target-imgref "$IMGREF" \
    --root-mount-spec "UUID=$SYS_FS_UUID" \
    --boot-mount-spec "UUID=$BOOT_UUID" \
    --karg "rd.luks.uuid=luks-$SYS_LUKS_UUID" \
    --karg "rd.luks.options=$SYS_LUKS_UUID=tpm2-device=auto" \
    --karg "systemd.mount-extra=/dev/mapper/data:$DATA_MOUNT:xfs:nofail" \
    "${sshkey_karg[@]}" \
    "$TGT" \
  || die "bootc install to-filesystem failed"

# --------------------------------------------------------------------------- #
# 5a) Firmware boot-menu hygiene (docs/INSTALLER-UX-HARDENING.md):
#     - branded shim CSV on the INSTALLED ESP: if fallback.efi ever runs (NVRAM
#       loss), the recreated entry says "Neural ICE", never "Red Hat Enterprise
#       Linux" (the label baked into our RHEL-sourced signed shim).
#     - our own NVRAM entry "Neural ICE", first in BootOrder.
#     - drop stale HD() entries pointing at partitions that no longer exist
#       (wiped OSes) or at the live USB (a one-shot installer leaves no trace).
#     Best-effort: NVRAM quirks must never fail a successful install.
# --------------------------------------------------------------------------- #
shim_rel=""
shim_abs="$(find "$TGT/boot/efi/EFI" -maxdepth 2 -iname 'shimaa64.efi' 2>/dev/null | head -1)"
[[ -n "$shim_abs" ]] && shim_rel="${shim_abs#"$TGT"/boot/efi}"
for csv in "$TGT"/boot/efi/EFI/*/BOOT*.CSV; do
  [[ -f "$csv" ]] || continue
  loader="$(iconv -f UTF-16 -t UTF-8 "$csv" 2>/dev/null | head -1 | cut -d, -f1 | tr -d '\r\n')"
  : "${loader:=shimaa64.efi}"
  if { printf '\xff\xfe'
    printf '%s,Neural ICE,,Neural ICE CoreOS appliance\r\n' "$loader" | iconv -f UTF-8 -t UTF-16LE
  } > "$csv" 2>/dev/null; then
    log "Branded shim CSV: ${csv#"$TGT"/boot/efi/} -> Neural ICE"
  fi
done
if command -v efibootmgr >/dev/null && [[ -d /sys/firmware/efi/efivars && -n "$shim_rel" ]]; then
  present_guids="$(lsblk -rno PARTUUID | tr '[:upper:]' '[:lower:]')"
  usb_guids="$(lsblk -rno PARTUUID "/dev/$live_disk" | tr '[:upper:]' '[:lower:]')"
  while IFS= read -r line; do
    num="$(sed -n 's/^Boot\([0-9A-Fa-f]\{4\}\).*/\1/p' <<<"$line")"; [[ -n "$num" ]] || continue
    label="$(sed -e 's/^Boot[0-9A-Fa-f]\{4\}[* ]*//' -e 's/\t.*//' <<<"$line")"
    guid="$(sed -n 's/.*HD([0-9]*,GPT,\([0-9a-fA-F-]*\),.*/\1/p' <<<"$line" | tr '[:upper:]' '[:lower:]')"
    if [[ "$label" == "Neural ICE" ]] \
       || { [[ -n "$guid" ]] && ! grep -qx "$guid" <<<"$present_guids"; } \
       || { [[ -n "$guid" ]] && grep -qx "$guid" <<<"$usb_guids"; }; then
      if efibootmgr -b "$num" -B >/dev/null 2>&1; then
        log "NVRAM: dropped entry Boot$num ($label)"
      fi
    fi
  done < <(efibootmgr -v 2>/dev/null | grep '^Boot[0-9A-Fa-f]\{4\}')
  if efibootmgr --create --disk "$target" --part 1 --label "Neural ICE" \
       --loader "${shim_rel//\//\\}" >/dev/null 2>&1; then
    log "NVRAM: created 'Neural ICE' boot entry (first in BootOrder)"
  else
    log "warn: efibootmgr create failed — firmware will fall back to the branded CSV on first boot"
  fi
else
  log "warn: efibootmgr/efivars/shim unavailable — skipping NVRAM branding (CSV fallback stays branded)"
fi

# --------------------------------------------------------------------------- #
# 5b) PRELOADED seed staging (only if the installer media carries a seed partition).
#     Copy the READY podman overlay store + the base HF models onto the (already-
#     formatted, open) encrypted data volume. The image's storage.conf.d drop-in
#     registers /var/lib/neural-ice/data/seed-store as a READ-ONLY additional image
#     store, so the appliance sees the images INSTANTLY at first boot — no import,
#     no `podman load`. The store files get the container_ro_file_t SELinux label so
#     the container runtime can read them (the data volume is mounted without a
#     context= override, so per-file xattr labels persist).
# --------------------------------------------------------------------------- #
SEED_PART="/dev/disk/by-partlabel/ni-seed"
# The seed-store dir must exist on the data volume in ALL editions — containers-storage
# HARD-FAILS on a missing additionalimagestores path (no silent skip). LIGHT gets an empty
# store; PRELOADED fills it below. (tmpfiles.d also recreates it on every boot.)
mkdir -p /run/seed-dst
mount /dev/mapper/data /run/seed-dst
mkdir -p /run/seed-dst/seed-store
if [ -b "$SEED_PART" ]; then
  log "PRELOADED: staging seed (overlay store + base models) onto the data volume…"
  mkdir -p /run/seed-src
  mount -o ro "$SEED_PART" /run/seed-src
  if [ -d /run/seed-src/store ]; then
    cp -a /run/seed-src/store/. /run/seed-dst/seed-store/
    # Label for the container runtime. Prefer the read-only image-store type; fall back to the
    # universally-present container_file_t (readable by container_t). The store is used
    # read-only via podman's additionalimagestores regardless of the exact type. The data
    # volume is mounted without a context= override, so these per-file xattr labels persist.
    chcon -R -t container_ro_file_t /run/seed-dst/seed-store 2>/dev/null \
      || chcon -R -t container_file_t /run/seed-dst/seed-store 2>/dev/null \
      || log "  warn: chcon on seed-store failed (SELinux off in installer?) — relabel on first boot if needed"
    log "  images: staged as ready overlay store (zero first-boot import)"
  fi
  if [ -d /run/seed-src/models ]; then
    mkdir -p /run/seed-dst/huggingface
    cp -a /run/seed-src/models/. /run/seed-dst/huggingface/
    log "  models: staged into data/huggingface"
  fi
  if [ -d /run/seed-src/payload ]; then
    # Product payload (e.g. a private appliance layer). Applied ONCE on first
    # boot by the image's generic neural-ice-payload-apply.service — the target
    # /etc is read-only here (§6), so the installer only STAGES it on data.
    mkdir -p /run/seed-dst/payload
    cp -a /run/seed-src/payload/. /run/seed-dst/payload/
    log "  payload: staged (applied on first boot by neural-ice-payload-apply)"
  fi
  sync
  umount /run/seed-dst; umount /run/seed-src
  log "PRELOADED: seed staged."
fi

# --------------------------------------------------------------------------- #
# 5c) SELinux: label EVERYTHING this install created, with the TARGET's policy.
#     The installer runs permissive (§0) and bootc labels the image content, but
#     the deployment's /etc DIRECTORY itself and everything staged by this
#     script (payload, models, data dirs) end up unlabeled_t. On the first
#     ENFORCING boot a single unlabeled /etc is fatal: every confined service
#     (dbus-broker, journald, avahi, podman) is denied { search } on /etc and
#     the whole userspace collapses (root-caused live on the .72 GB10,
#     2026-07-13). Label with setfiles -F against the deployment's own
#     file_contexts, then VERIFY — an unlabeled install must not ship.
# --------------------------------------------------------------------------- #
log "SELinux: labeling deployment /etc,/var,/boot + data volume (target policy)…"
command -v setfiles >/dev/null || die "setfiles not available in the installer image"
# The deployment names are bootc/ostree-controlled and cannot contain hostile
# shell characters; ls keeps the established first-deployment selection here.
# shellcheck disable=SC2012
dep="$(ls -d "$TGT"/ostree/deploy/*/deploy/*.0 2>/dev/null | head -1)"
[[ -n "$dep" && -d "$dep" ]] || die "cannot locate the ostree deployment under $TGT"
stateroot="$(dirname "$(dirname "$dep")")"   # …/ostree/deploy/<name>
setype="$(sed -n 's/^SELINUXTYPE=//p' "$dep/usr/etc/selinux/config" 2>/dev/null | head -1)"
: "${setype:=targeted}"
fc="$dep/usr/etc/selinux/$setype/contexts/files/file_contexts"
[[ -f "$fc" ]] || die "target policy file_contexts not found: $fc"
# Create the exact non-exportable device-root on the installed machine's TPM
# and persist only its public identity in the new stateroot. The same image-
# baked helper attests it idempotently on every boot. An occupied/malformed
# 0x81010005 refuses; neither the PKI handle 0x81010004 nor the EK is touched.
/usr/libexec/neural-ice-device-root ensure \
  --identity "$stateroot/var/lib/neural-ice/ota/device-root-v1.json" \
  >/dev/null \
  || die "cannot provision and attest the dedicated TPM device-root"
log "Dedicated TPM device-root provisioned and attested at 0x81010005."
if (( LAB_BASELINE_PRESENT == 1 )); then
  "$LAB_BASELINE_HANDOFF" install "$LAB_BASELINE_SNAPSHOT" "$stateroot/var" \
    || die "cannot persist the optional LAB baseline receipt pair"
  log "Optional LAB baseline receipt pair persisted for post-install verification."
fi
# Deployment /etc (the runtime /etc): -r makes paths match the policy as /etc/…
setfiles -F -r "$dep" "$fc" "$dep/etc" || die "setfiles failed on deployment /etc"
# Stateroot /var (the runtime /var): pre-created dirs get their policy labels.
setfiles -F -r "$stateroot" "$fc" "$stateroot/var" || die "setfiles failed on stateroot /var"
# /boot (kernel/initramfs/BLS entries; the ESP is vfat = no xattrs, skipped).
setfiles -F -r "$TGT" "$fc" "$TGT/boot" || true
# Data volume: bind it at its RUNTIME path under a fake root so file_contexts
# matches /var/lib/neural-ice/data/…; EXCLUDE seed-store (chcon'd to
# container_ro_file_t in §5b — the policy has no entry for it and -F would
# strip that label back to var_lib_t).
mountpoint -q /run/seed-dst || mount /dev/mapper/data /run/seed-dst
mkdir -p /run/nid-root/var/lib/neural-ice/data
mount --bind /run/seed-dst /run/nid-root/var/lib/neural-ice/data
setfiles -F -r /run/nid-root -e /run/nid-root/var/lib/neural-ice/data/seed-store \
  "$fc" /run/nid-root/var/lib/neural-ice/data \
  || die "setfiles failed on the data volume"
umount /run/nid-root/var/lib/neural-ice/data
# seed-store label for ALL editions. LIGHT creates the (empty) dir too but
# never runs the §5b chcon (seed branch only) — and podman stats this
# additionalimagestores path on EVERY invocation, so an unlabeled_t dir is
# denied under enforcing (Codex P1, PR #18). Idempotent for PRELOADED.
chcon -R -t container_ro_file_t /run/seed-dst/seed-store 2>/dev/null \
  || chcon -R -t container_file_t /run/seed-dst/seed-store 2>/dev/null \
  || die "cannot label seed-store for the container runtime"
# VERIFY (fail-closed): the two labels whose absence bricked the enforcing boot.
stat -c %C "$dep/etc" | grep -q ':etc_t:' \
  || die "deployment /etc is still not etc_t after setfiles — refusing to ship"
stat -c %C /run/seed-dst | grep -Eq ':(var_lib_t|var_t):' \
  || die "data volume root is still unlabeled after setfiles — refusing to ship"
umount /run/seed-dst 2>/dev/null || true
log "SELinux: labels applied and verified (deployment /etc = etc_t, data = policy defaults)."

# --------------------------------------------------------------------------- #
# 6) DATA volume config is NOT written post-install (an ostree deployment's /etc
#    is read-only right after bootc finalizes it). Unlock is image-baked
#    (/etc/crypttab by GPT label) and the mount is a systemd.mount-extra karg
#    (both supported bootc mechanisms) — nothing to do here but unmount.
# --------------------------------------------------------------------------- #
sync
umount -R "$TGT" 2>/dev/null || true
cryptsetup close data 2>/dev/null || true
cryptsetup close system 2>/dev/null || true

# --------------------------------------------------------------------------- #
# 7) Escrow the recovery keys: back up to the USB ESP + show the CLIENT key.
# --------------------------------------------------------------------------- #
stamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
usb_esp="$(lsblk -rno NAME,FSTYPE "/dev/$live_disk" 2>/dev/null | awk '$2=="vfat"{print $1; exit}')"
usb_saved="(USB backup FAILED — record the key shown below NOW)"
esp_mp=""; esp_we_mounted=0
if [[ -n "${usb_esp:-}" ]]; then
  # The live system ALREADY mounts the USB EFI partition (e.g. at /boot/efi), so
  # mounting it a second time fails. Reuse the existing mountpoint (remount rw);
  # only mount it ourselves if it is not mounted yet.
  esp_mp="$(findmnt -nfo TARGET "/dev/$usb_esp" 2>/dev/null | head -1)"
  if [[ -n "$esp_mp" ]]; then
    mount -o remount,rw "$esp_mp" 2>/dev/null || true
  else
    mkdir -p /run/usb-esp
    mount "/dev/$usb_esp" /run/usb-esp 2>/dev/null && { esp_mp=/run/usb-esp; esp_we_mounted=1; }
  fi
fi
if [[ -n "$esp_mp" ]] && ( : > "$esp_mp/.ni-wtest" ) 2>/dev/null; then
  rm -f "$esp_mp/.ni-wtest"
  recfile="$esp_mp/NEURAL-ICE-RECOVERY-${target_serial}.txt"
  {
    printf 'NEURAL ICE CoreOS — disk encryption recovery keys\r\n'
    printf 'Generated: %s\r\n' "$stamp"
    printf 'Appliance disk serial: %s\r\n\r\n' "$target_serial"
    printf '[CLIENT] DATA volume recovery key (keep this safe):\r\n  %s\r\n\r\n' "$DATA_RECOVERY"
    printf '[INTERNAL] SYSTEM volume recovery key (Neural ICE support):\r\n  %s\r\n\r\n' "$SYS_RECOVERY"
    printf 'Use: cryptsetup open <partition> <name>  then enter the recovery key.\r\n'
  } > "$recfile"
  sync
  usb_saved="Saved on the USB EFI partition: $(basename "$recfile")"
  if [[ "$esp_we_mounted" -eq 1 ]]; then
    umount /run/usb-esp 2>/dev/null || true
  fi
fi

# --------------------------------------------------------------------------- #
# 8) Done: prompt the operator (show CLIENT recovery key), then reboot.
# --------------------------------------------------------------------------- #
readonly TTY=/dev/tty1
{
  printf '\n\n'
  printf '  ============================================================\n'
  printf '   \033[1;32m✅  NEURAL ICE — INSTALLATION COMPLETE (ENCRYPTED)\033[0m\n'
  printf '  ------------------------------------------------------------\n'
  printf '   Full-disk encryption: system + data (TPM2, auto-unlock)\n'
  printf '\n'
  printf '   \033[1;33mCLIENT DATA RECOVERY KEY — write it down and keep it safe:\033[0m\n'
  printf '       \033[1;37m%s\033[0m\n' "$DATA_RECOVERY"
  printf '   %s\n' "$usb_saved"
  printf '  ------------------------------------------------------------\n'
  printf '   1) Press [Enter] to reboot onto the internal disk\n'
  printf '   2) Remove the USB drive DURING the reboot (once the screen clears)\n'
  printf '      — do NOT pull it before pressing Enter: the live installer runs\n'
  printf '        FROM the USB and needs it until the machine actually resets.\n'
  printf '  ============================================================\n\n'
} > "$TTY" 2>/dev/null || log "Installation complete (encrypted) — DATA recovery key: $DATA_RECOVERY"

if read -r _ < "$TTY" 2>/dev/null; then
  log "Confirmed — rebooting onto the internal disk…"
  # Cleanly unmount the TARGET filesystems FIRST — this flushes them, so the forced
  # reset below never leaves the freshly-installed system/data XFS dirty. The LIGHT
  # path leaves the data volume mounted at /run/seed-dst (its umount lives only in the
  # seed-present branch), and $TGT may still hold system/boot/esp. `umount` flushes,
  # so no separate global `sync` (a bare `sync` would also hit the USB live-root/ESP
  # and thrash if the operator pulls the USB a moment early — Codex #15).
  umount -R /run/seed-dst 2>/dev/null || true
  umount -R "$TGT"        2>/dev/null || true
  # IMMEDIATE forced reset: does NOT depend on writing/unmounting the USB fs (the
  # discarded installer media), so it survives an operator who pulls the USB a moment
  # too early instead of thrashing on I/O errors. Targets are already flushed above.
  systemctl reboot -ff || reboot -f
  # No interactive console: do NOT reboot (avoids the loop).
  log "No interactive console: remove the USB and power-cycle manually."
fi
