#!/usr/bin/env bash
# Read the first-boot journal off a KVM-rehearsed target disk, on the bench host.
#
# After `image/bench-rehearse-medium.sh --medium-overlay` the work directory holds
# the target disk (target.qcow2) and the medium overlay (medium.qcow2) whose ESP
# received the SYSTEM recovery-key escrow in phase 8 -- the same escrow a real
# USB stick carries, and the only thing that opens the LUKS2 system volume
# without the rehearsal's TPM. This tool does on the host exactly what a LAB
# medium's preflight does before the wipe (ota/neural-ice-autoinstall.sh,
# log_previous_firstboot_journal): read the escrow, open the system volume
# READ-ONLY, mount the deployment's /var read-only without journal replay, and
# print the ceremony unit's last lines plus the error-level tail.
#
# The rehearsed target is never written: the medium overlay is attached
# read-only; the target is read through a throw-away qcow2 overlay of its own
# (target.journal-read.qcow2, deleted on exit) because XFS must replay its log
# to show what a hard-stopped first boot wrote -- system.journal of the C15
# rehearsal was an unreadable inode under norecovery on 2026-09-10. The key
# file is shredded on every exit path.
# Root is required for nbd, device-mapper and mount. The rehearsal VM must have
# ended (a live guest still owns the disks).
set -euo pipefail

usage() {
  cat <<'USAGE'
bench-read-rehearsed-firstboot-journal.sh --work-dir DIR [--unit UNIT] [--lines N]
  --work-dir DIR   the --work-dir of a finished bench-rehearse-medium.sh run made
                   with --medium-overlay (needs DIR/medium.qcow2 and DIR/target.qcow2)
  --unit UNIT      journal unit to print (default neural-ice-firstboot-tpm-ceremony.service)
  --lines N        lines of that unit to print (default 120)
USAGE
}

die() { printf 'bench-read-rehearsed-firstboot-journal: REFUSED: %s\n' "$*" >&2; exit 1; }
say() { printf 'bench-read-rehearsed-firstboot-journal: %s\n' "$*"; }

work_dir="" unit=neural-ice-firstboot-tpm-ceremony.service lines=120
while (( $# )); do
  case "$1" in
    --work-dir) work_dir=${2:-}; shift 2 ;;
    --unit) unit=${2:-}; shift 2 ;;
    --lines) lines=${2:-}; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done
[[ -n "$work_dir" && "$work_dir" == /* && -d "$work_dir" ]] || die "--work-dir must be an existing absolute directory"
[[ "$lines" =~ ^[1-9][0-9]{0,3}$ ]] || die "--lines must be 1..9999"
[[ "$unit" =~ ^[A-Za-z0-9@._-]+$ ]] || die "--unit is not a unit name"
[[ $EUID -eq 0 ]] || die "nbd, device-mapper and mount need root"
medium=$work_dir/medium.qcow2; target=$work_dir/target.qcow2
[[ -f "$medium" ]] || die "$medium is absent: the rehearsal was not run with --medium-overlay, so no escrow exists"
[[ -f "$target" ]] || die "$target is absent"
! pgrep -f "[q]emu-system-aarch64.*$work_dir" >/dev/null || die "a QEMU guest still owns $work_dir"
for tool in qemu-nbd cryptsetup lsblk findmnt journalctl partprobe shred; do
  command -v "$tool" >/dev/null || die "missing tool: $tool"
done
modprobe nbd max_part=16 2>/dev/null || true

free_nbd() { # -> first /dev/nbdN with no backing
  local n
  for n in /sys/block/nbd*; do
    [[ -e "$n/size" ]] || continue
    [[ "$(<"$n/size")" == 0 ]] || continue
    [[ -e "$n/pid" ]] && continue
    printf '/dev/%s\n' "${n##*/}"; return 0
  done
  return 1
}

scratch=$(mktemp -d /run/ni-bench-journal.XXXXXX); chmod 0700 "$scratch"
keyfile=$scratch/key; esp_mnt=$scratch/esp; sys_mnt=$scratch/system
mapper=ni-rehearsed-system-$$
nbd_medium="" nbd_target="" target_overlay=""
cleanup() {
  set +e
  findmnt -n "$sys_mnt" >/dev/null 2>&1 && umount "$sys_mnt"
  [[ -e /dev/mapper/$mapper ]] && cryptsetup close "$mapper"
  findmnt -n "$esp_mnt" >/dev/null 2>&1 && umount "$esp_mnt"
  [[ -n "$nbd_target" ]] && qemu-nbd -d "$nbd_target" >/dev/null 2>&1
  [[ -n "$nbd_medium" ]] && qemu-nbd -d "$nbd_medium" >/dev/null 2>&1
  [[ -n "$target_overlay" && -e "$target_overlay" ]] && rm -f -- "$target_overlay"
  [[ -e "$keyfile" ]] && shred -u -- "$keyfile"
  rm -rf -- "$scratch"
}
trap cleanup EXIT

# 1. The escrow, off the overlay's ESP.
nbd_medium=$(free_nbd) || die "no free /dev/nbd device"
qemu-nbd --read-only -c "$nbd_medium" "$medium" || die "cannot attach $medium read-only"
partprobe "$nbd_medium" >/dev/null 2>&1 || true; udevadm settle 2>/dev/null || true
esp=$(lsblk -rno NAME,FSTYPE "$nbd_medium" | awk '$2 == "vfat" && !f { print $1; f=1 }')
[[ -n "$esp" ]] || die "the medium overlay has no vfat partition"
mkdir -m 0700 "$esp_mnt"
mount -o ro,nodev,nosuid,noexec "/dev/$esp" "$esp_mnt" || die "cannot mount the medium ESP read-only"
recfile=$(find "$esp_mnt" -maxdepth 1 -name 'NEURAL-ICE-RECOVERY-*.txt' -type f | head -1)
[[ -n "$recfile" ]] || die "no NEURAL-ICE-RECOVERY-<serial>.txt on the medium ESP: phase 8 never escrowed (did the install complete?)"
key=$(tr -d '\r' < "$recfile" | awk '/^\[INTERNAL\] SYSTEM volume recovery key/ { getline; gsub(/^[ \t]+|[ \t]+$/, ""); print; exit }')
[[ "$key" =~ ^[A-Za-z0-9-]{16,128}$ ]] || die "the escrow carries no well-formed SYSTEM recovery key"
(umask 077; printf '%s' "$key" > "$keyfile"); unset key
say "escrow read from ${recfile##*/} (key material stays in $scratch, shredded on exit)"
umount "$esp_mnt"; qemu-nbd -d "$nbd_medium" >/dev/null; nbd_medium=""

# 2. The system volume, read-only, and the deployment's persistent journal.
nbd_target=$(free_nbd) || die "no free /dev/nbd device"
target_overlay=$work_dir/target.journal-read.qcow2
[[ ! -e "$target_overlay" ]] || die "$target_overlay already exists; a previous read did not clean up"
qemu-img create -q -f qcow2 -b "$target" -F qcow2 "$target_overlay" \
  || die "cannot create the throw-away overlay of $target"
qemu-nbd -c "$nbd_target" "$target_overlay" || die "cannot attach the target overlay"
partprobe "$nbd_target" >/dev/null 2>&1 || true; udevadm settle 2>/dev/null || true
sysp=${nbd_target}p3
[[ -b "$sysp" ]] || die "$sysp is not a block device: the target carries no partition 3 (system)"
cryptsetup isLuks "$sysp" || die "$sysp is not LUKS: the target was never installed"
cryptsetup open --type luks2 --key-file "$keyfile" "$sysp" "$mapper" \
  || die "the escrowed key does not open $sysp"
shred -u -- "$keyfile"
mkdir -m 0700 "$sys_mnt"
# ro without norecovery: XFS replays its log into the throw-away overlay only.
mount -o ro,nodev,nosuid,noexec "/dev/mapper/$mapper" "$sys_mnt" || die "the system volume did not mount read-only"
journal_dir=$(find "$sys_mnt/ostree/deploy" -maxdepth 4 -type d -path '*/var/log/journal' 2>/dev/null | head -1)
[[ -n "$journal_dir" ]] || die "no persistent journal under the deployed /var (never booted?)"
say "journal: ${journal_dir#"$sys_mnt"}"
say "boots recorded:"
journalctl -D "$journal_dir" --list-boots --no-pager 2>/dev/null | sed 's/^/    | /' || true
say "$unit, last $lines lines:"
journalctl -D "$journal_dir" -u "$unit" -n "$lines" --no-pager -o short-iso 2>/dev/null | sed 's/^/    | /' || true
say "error-level entries, last 60:"
journalctl -D "$journal_dir" -p err -n 60 --no-pager -o short-iso 2>/dev/null | sed 's/^/    | /' || true
