#!/usr/bin/env bash
#
# THE LIVE MODE'S ONLY PRODUCT SURFACE: a bounded, fixed, READ-ONLY diagnostic
# summary printed once on tty1.
#
# 🔴 WHAT LIVE IS, AND WHAT IT DELIBERATELY IS NOT.
#
# `neural-ice-live.target` used to reach basic.target and stop. That was safe and
# operationally indistinguishable from a hung machine: no login, no UI, no
# result, no stated way to end the boot (independent review 2026-09-02, product
# question 1). Live is a NON-DESTRUCTIVE READ-ONLY DIAGNOSTICS MODE, and this is
# the whole of it.
#
# It has, on purpose and by construction:
#
#   no shell           there is no interactive process anywhere in this file, and
#                      the runtime generator masks getty@, serial-getty@, autovt@,
#                      console-getty, container-getty@, getty.target,
#                      systemd-user-sessions, user@, debug-shell, emergency and
#                      rescue on a Live boot;
#   no login, no SSH   sshd.service and sshd.socket are masked in the same place;
#   no installer       neural-ice-installer.target and neural-ice-autoinstall.service
#                      are masked on every boot that is not the exact Install grammar;
#   no arbitrary command, no operator input, no argument of any kind: this script
#                      takes none and reads none. Every probe below is a literal;
#   no customer data   nothing under /var/lib/neural-ice/data, no filesystem on
#                      an internal disk, no LUKS header and no TPM object is
#                      opened, mounted, unlocked or read. Storage is enumerated
#                      from the block layer's own metadata, never from content.
#
# 🔴 EVERY PROBE IS READ-ONLY AND EVERY OUTPUT IS SANITISED.
#
# The values below come from /proc, /sys and lsblk. Several of them are
# ATTACKER-INFLUENCED -- a device-tree model string, a disk model, an interface
# name -- so nothing is printed raw: `field` strips every byte outside a narrow
# printable set, collapses whitespace and truncates. A terminal escape sequence
# in a disk's model string is otherwise a way to rewrite what the operator sees
# on the console this mode exists to be trusted on.
#
# Resource bounds live in the unit (TimeoutStartSec, MemoryMax, TasksMax,
# IPAddressDeny) rather than here, so they hold even if this script is wrong.
set -uo pipefail

# Test seam: available only to an unprivileged process outside a release image.
readonly RELEASE_IMAGE_MARKER=/usr/lib/neural-ice/release-image
if [[ -n ${NEURALICE_LIVE_DIAG_ROOT:-} || -n ${NEURALICE_LIVE_DIAG_CMDLINE:-} \
   || -n ${NEURALICE_LIVE_DIAG_BOUNDARY_ROOT:-} ]]; then
  [[ $EUID -ne 0 ]] || { printf 'neural-ice-live-diagnostics: test overrides are forbidden to root\n' >&2; exit 2; }
  [[ ! -e $RELEASE_IMAGE_MARKER ]] \
    || { printf 'neural-ice-live-diagnostics: test overrides are forbidden in a release image\n' >&2; exit 2; }
fi
SYSROOT="${NEURALICE_LIVE_DIAG_ROOT:-}"
SYSROOT="${SYSROOT%/}"
readonly SYSROOT
readonly CMDLINE_FILE="${NEURALICE_LIVE_DIAG_CMDLINE:-${SYSROOT}/proc/cmdline}"

# Hard output bounds. A console summary an operator reads at a glance is a
# product requirement, and an unbounded one is a denial of that requirement as
# much as it is a resource question.
readonly FIELD_MAX=72
readonly LIST_MAX=8

# One sanitiser, applied to EVERY value that did not originate in this file.
field() { # $1=raw value  -> bounded, printable, single-line
  local value=${1:-}
  value="${value//[^[:print:]]/ }"
  value="$(printf '%s' "$value" | tr -s '[:space:]' ' ')"
  value="${value# }"; value="${value% }"
  [ -n "$value" ] || value="(unavailable)"
  if [ "${#value}" -gt "$FIELD_MAX" ]; then
    value="${value:0:FIELD_MAX}…"
  fi
  printf '%s' "$value"
}

read_first_line() { # $1=path
  local path=$1
  [ -r "$path" ] || return 1
  head -c 4096 -- "$path" 2>/dev/null | head -n 1
}

row() { printf '  %-22s %s\n' "$1" "$(field "${2:-}")"; }

rule() { printf '  %s\n' '----------------------------------------------------------------------'; }

# --------------------------------------------------------------------------- #
# 🔴 THE WRITE BOUNDARY IS PROVED ON THE MACHINE, BEFORE ANYTHING IS PRINTED
# (independent review 2026-09-02, P1 #7).
#
# The unit states the boundary -- ProtectSystem=strict, ProtectHome, an empty
# ReadWritePaths=, PrivateDevices, no PrivateTmp, User=nobody, an empty
# CapabilityBoundingSet. A unit file is a REQUEST, though, and the previous
# revision's own directives did not deliver what its comment claimed: PrivateTmp=
# put a writable tmpfs back over /tmp and /var/tmp.
#
# So the script asks the kernel. It tries to CREATE one fixed file in each
# location a Linux system leaves writable by default, and if any of them
# succeeds it refuses to produce a summary at all. A Live medium whose sandbox
# was weakened -- by an edit here, by a systemd release that renamed a directive,
# by a distribution that dropped one -- then reports that fact on the console of
# the machine it is standing on, instead of quietly being able to write to it.
#
# It cannot be a probe of a path the script also needs: every probe below is in a
# directory this summary never reads. The name is fixed, and any file the probe
# managed to create is removed immediately -- a boundary check must not itself be
# the mutation it is looking for.
# --------------------------------------------------------------------------- #
readonly -a WRITE_BOUNDARY_PATHS=(
  /
  /etc
  /usr
  /var
  /var/tmp
  /var/lib
  /run
  /tmp
  /home
  /root
  /dev/shm
)
readonly WRITE_PROBE_NAME=.neural-ice-live-write-boundary-probe
# A seam of its OWN, distinct from the fixture sysroot: the suite has to drive a
# writable tree (the boundary is gone -> refuse) and a read-only one (the
# boundary holds -> summarise) against the SAME fixture of /proc and /sys
# probes. The installed unit sets neither variable, so on a medium this is the
# real filesystem root.
BOUNDARY_ROOT="${NEURALICE_LIVE_DIAG_BOUNDARY_ROOT:-$SYSROOT}"
readonly BOUNDARY_ROOT="${BOUNDARY_ROOT%/}"

prove_write_boundary() { # -> prints every location that accepted a write
  local dir probe
  for dir in "${WRITE_BOUNDARY_PATHS[@]}"; do
    probe="${BOUNDARY_ROOT}${dir%/}/$WRITE_PROBE_NAME"
    [ -d "${BOUNDARY_ROOT}${dir%/}" ] || [ "$dir" = / ] || continue
    if ( : > "$probe" ) 2>/dev/null; then
      rm -f -- "$probe" 2>/dev/null || true
      printf '%s\n' "$dir"
    fi
  done
  return 0
}

writable=""
while IFS= read -r line; do
  [ -n "$line" ] || continue
  writable="$writable $(field "$line")"
done < <(prove_write_boundary)

if [ -n "$writable" ]; then
  printf '\n'
  printf '  Neural ICE CoreOS — LIVE (read-only diagnostics)\n'
  rule
  printf '  REFUSED: this Live boot is NOT read-only.\n'
  printf '\n'
  printf '  A write succeeded in:%s\n' "$writable"
  printf '\n'
  printf '  Live exists to be safe to boot on a machine holding customer data,\n'
  printf '  and that safety is the kernel-enforced read-only boundary this unit\n'
  printf '  declares -- not a promise about what this script happens to run. The\n'
  printf '  boundary is absent, so no diagnostics are produced.\n'
  printf '\n'
  printf '  Press the power button to power off. Report this to Neural ICE: a\n'
  printf '  medium in this state must not be used.\n'
  rule
  printf '\n'
  exit 1
fi

# --------------------------------------------------------------------------- #
# The sealed anchor. These words are what the SIGNATURE says this medium is, so
# they are the first thing an operator needs and the only ones here that are not
# guesses. Digests are shown truncated: the full value is on the medium and in
# the build manifest, and a console is for recognising a mismatch, not for
# transcribing 64 hex characters.
# --------------------------------------------------------------------------- #
sealed() { # $1=key
  local key=$1 value
  value="$(awk -v k="$key=" '{for (i = 1; i <= NF; i++) if (index($i, k) == 1) { print substr($i, length(k) + 1); exit }}' \
    "$CMDLINE_FILE" 2>/dev/null)" || return 1
  printf '%s' "$value"
}

short_digest() { # $1=64-hex or anything
  local value=${1:-}
  if [ "${#value}" -ge 16 ]; then
    printf '%s…%s' "${value:0:8}" "${value: -8}"
  else
    printf '%s' "$value"
  fi
}

printf '\n'
printf '  Neural ICE CoreOS — LIVE (read-only diagnostics)\n'
rule
printf '  This medium is NOT installing anything. No internal disk has been\n'
printf '  partitioned, encrypted, mounted or written, and none will be.\n'
rule

printf '\n  MEDIUM AND TRUST\n'
row 'boot mode'          "live (signed selector: $(sealed neuralice.live 2>/dev/null || printf 'absent'))"
row 'access profile'     "$(sealed neuralice.access_profile || true)"
row 'hardware target'    "$(sealed neuralice.hardware_target || true)"
row 'trust policy'       "$(sealed neuralice.trust_policy_id || true)"
row 'trust anchor'       "$(sealed neuralice.trust || true)"
row 'root verity hash'   "$(short_digest "$(sealed neuralice.rootverity || true)")"
row 'payload digest'     "$(short_digest "$(sealed neuralice.payload || true)")"

# Secure Boot state, straight out of the EFI variable. `od` because the variable
# is a 4-byte attribute prefix followed by one boolean byte, and because reading
# it as text would print whatever those bytes happen to be.
secureboot='(no EFI variables — not a UEFI boot, or efivarfs is not mounted)'
sb_var="$(printf '%s' "${SYSROOT}/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c")"
if [ -r "$sb_var" ]; then
  sb_byte="$(od -An -tu1 -j4 -N1 -- "$sb_var" 2>/dev/null | tr -d '[:space:]')"
  case "$sb_byte" in
    1) secureboot='enabled' ;;
    0) secureboot='DISABLED — this medium booted unverified' ;;
    *) secureboot='unreadable' ;;
  esac
fi
row 'secure boot'        "$secureboot"

# The dm-verity mapping the initramfs set up, named from sysfs alone. Its
# presence is what says the root this boot is running IS the sealed extent.
verity_names=''
for dm in "${SYSROOT}"/sys/block/dm-*/dm/name; do
  [ -r "$dm" ] || continue
  verity_names="$verity_names $(read_first_line "$dm" || true)"
done
row 'device-mapper'      "${verity_names:-(none)}"

printf '\n  HARDWARE\n'
model="$(read_first_line "${SYSROOT}/sys/firmware/devicetree/base/model" 2>/dev/null || true)"
[ -n "$model" ] || model="$(read_first_line "${SYSROOT}/sys/class/dmi/id/product_name" 2>/dev/null || true)"
row 'model'              "$model"
row 'cpus'               "$(grep -c '^processor' "${SYSROOT}/proc/cpuinfo" 2>/dev/null || true)"
row 'memory'             "$(awk '/^MemTotal:/ {printf "%.1f GiB", $2 / 1048576; exit}' \
                              "${SYSROOT}/proc/meminfo" 2>/dev/null || true)"
tpm=''
for chip in "${SYSROOT}"/sys/class/tpm/tpm*; do
  [ -e "$chip" ] || continue
  tpm="$tpm ${chip##*/}"
done
row 'tpm'                "${tpm:-(none detected)}"

# STORAGE IS ENUMERATED, NEVER OPENED. `lsblk` reads the block layer's own
# metadata; it does not read a partition table's contents, mount anything or
# touch a LUKS header. `--nodeps` keeps it to whole devices.
printf '\n  STORAGE (enumerated only — nothing mounted, unlocked or read)\n'
storage_lines=0
if command -v lsblk >/dev/null 2>&1; then
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    storage_lines=$(( storage_lines + 1 ))
    if [ "$storage_lines" -gt "$LIST_MAX" ]; then
      printf '  %-22s %s\n' '' "… further devices omitted"
      break
    fi
    printf '  %-22s %s\n' '' "$(field "$line")"
  done < <(lsblk --nodeps --noheadings --output NAME,SIZE,TYPE,TRAN,MODEL 2>/dev/null || true)
fi
[ "$storage_lines" -gt 0 ] || printf '  %-22s %s\n' '' '(no block devices enumerated)'

# NETWORK READINESS, NOT NETWORKING. Link state is read from sysfs. Nothing is
# configured, no address is requested and no packet is sent: the unit denies all
# IP traffic outright (IPAddressDeny=any).
printf '\n  NETWORK READINESS (link state only — no address is requested)\n'
net_lines=0
for iface in "${SYSROOT}"/sys/class/net/*; do
  [ -d "$iface" ] || continue
  name="${iface##*/}"
  [ "$name" != lo ] || continue
  net_lines=$(( net_lines + 1 ))
  if [ "$net_lines" -gt "$LIST_MAX" ]; then
    printf '  %-22s %s\n' '' "… further interfaces omitted"
    break
  fi
  operstate="$(read_first_line "$iface/operstate" 2>/dev/null || true)"
  carrier="$(read_first_line "$iface/carrier" 2>/dev/null || true)"
  case "$carrier" in
    1) carrier='carrier' ;;
    0) carrier='no-carrier' ;;
    *) carrier='carrier unknown' ;;
  esac
  printf '  %-22s %s\n' '' "$(field "$name")  $(field "$operstate")  $(field "$carrier")"
done
[ "$net_lines" -gt 0 ] || printf '  %-22s %s\n' '' '(no network interfaces)'

printf '\n'
rule
printf '  HOW TO END THIS BOOT. There is no login, no shell and no SSH on a Live\n'
printf '  medium — that is what makes it safe to boot on a customer appliance.\n'
printf '  Press the power button briefly to power off, or hold it to force off.\n'
printf '  Nothing on this machine has been modified, so either is safe.\n'
printf '  To INSTALL, cut a separate Install medium: the mode is sealed into the\n'
printf '  signature and cannot be changed on this one.\n'
rule
printf '\n'
