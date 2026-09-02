#!/usr/bin/env bash
# THE LIVE MODE'S PRODUCT SURFACE, AND ITS BOUNDS.
#
# Live is a non-destructive READ-ONLY DIAGNOSTICS mode (independent review
# 2026-09-02, product question 1: before this, neural-ice-live.target reached
# basic.target and stopped, which is safe and operationally indistinguishable
# from a hung machine). This suite holds both halves of that decision:
#
#   USEFUL   the summary actually states the medium's trust anchor, the mode, the
#            Secure Boot state, the hardware, the storage it enumerated and the
#            network link state, and it tells the operator how to end the boot.
#   BOUNDED  it takes no input, spawns no shell, opens no listener, reads nothing
#            an internal disk holds, sanitises every value it did not author, and
#            truncates every list and field.
#
# It needs no root, no medium, no TPM and no network.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIAG="$ROOT/image/installer/neural-ice-live-diagnostics.sh"
UNIT="$ROOT/image/installer/neural-ice-live-diagnostics.service"
LIVE_TARGET="$ROOT/image/installer/neural-ice-live.target"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/ni-live-diag.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

for required in "$DIAG" "$UNIT" "$LIVE_TARGET"; do
  [ -f "$required" ] || fail "missing input: $required"
done

# --------------------------------------------------------------------------- #
# A SYNTHETIC SYSROOT. Every probe reads a file, so every probe can be driven --
# including the hostile values, which is the point.
# --------------------------------------------------------------------------- #
SYS="$TMP/sysroot"
mkdir -p "$SYS/proc" "$SYS/sys/class/net/eth0" "$SYS/sys/class/net/lo" \
  "$SYS/sys/class/tpm/tpm0" "$SYS/sys/block/dm-0/dm" \
  "$SYS/sys/firmware/efi/efivars" "$SYS/sys/firmware/devicetree/base"
printf 'processor\t: 0\nprocessor\t: 1\n' > "$SYS/proc/cpuinfo"
printf 'MemTotal:      131072000 kB\n' > "$SYS/proc/meminfo"
printf 'up\n'   > "$SYS/sys/class/net/eth0/operstate"
printf '1\n'    > "$SYS/sys/class/net/eth0/carrier"
printf 'down\n' > "$SYS/sys/class/net/lo/operstate"
printf '0\n'    > "$SYS/sys/class/net/lo/carrier"
printf 'ni-installer-root\n' > "$SYS/sys/block/dm-0/dm/name"
# Secure Boot = enabled: four attribute bytes then the boolean.
printf '\006\000\000\000\001' > "$SYS/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"

ANCHOR="neuralice.trust=neural-ice-installer-trust-v1"
ANCHOR="$ANCHOR neuralice.access_profile=lab-managed"
ANCHOR="$ANCHOR neuralice.hardware_target=nvidia-gb10-arm64"
ANCHOR="$ANCHOR neuralice.payload=$(printf 'a%.0s' {1..64})"
ANCHOR="$ANCHOR neuralice.relauth_keyid=$(printf 'b%.0s' {1..64})"
ANCHOR="$ANCHOR neuralice.relauth_schema=neural-ice-installer-release-authorization-v2"
ANCHOR="$ANCHOR neuralice.rootverity=$(printf 'c%.0s' {1..64})"
ANCHOR="$ANCHOR neuralice.trust_policy_id=neural-ice-secureboot-lab-v1"
printf '%s quiet systemd.unit=neural-ice-live.target neuralice.live=1\n' "$ANCHOR" \
  > "$TMP/cmdline"

# --------------------------------------------------------------------------- #
# 🔴 THE READ-ONLY BOUNDARY IS A SEPARATE FIXTURE FROM THE PROBE SYSROOT.
#
# The summary refuses to run at all when it can write. This suite has to drive
# BOTH answers against the same /proc and /sys probes, and the probe fixture is
# necessarily writable (every hostile-value case below rewrites it). So the
# boundary gets its own root: an empty, read-only tree for the nominal case and a
# writable one for the mutation.
#
# When this suite runs as root, no mode bit refuses root, so the script is run as
# `nobody` -- which is also the identity the shipped unit gives it (User=nobody).
# There is no SKIP path: if that is impossible, this is a failure.
# --------------------------------------------------------------------------- #
chmod 0755 "$TMP"
BOUNDARY_RO="$TMP/boundary-ro"
BOUNDARY_RW="$TMP/boundary-rw"
mkdir -p "$BOUNDARY_RO" "$BOUNDARY_RW/var/tmp" "$BOUNDARY_RW/run"

run_diag_as() { # $1=boundary root, rest: extra argv for the script
  local boundary=$1; shift
  local -a command=(env "NEURALICE_LIVE_DIAG_ROOT=$SYS"
    "NEURALICE_LIVE_DIAG_CMDLINE=$TMP/cmdline"
    "NEURALICE_LIVE_DIAG_BOUNDARY_ROOT=$boundary"
    bash "$DIAG" "$@")
  if (( EUID == 0 )); then
    chmod -R a+rX "$SYS" "$TMP/cmdline" "$DIAG" 2>/dev/null || true
    runuser -u nobody -- "${command[@]}"
  else
    "${command[@]}"
  fi
}

# shellcheck disable=SC2120 # callers below pass extra argv when they need to
run_diag() { run_diag_as "$BOUNDARY_RO" "$@"; }

# The read-only fixture is made read-only only now: everything above created it.
chmod 0555 "$BOUNDARY_RO"
chmod 0777 "$BOUNDARY_RW" "$BOUNDARY_RW/var" "$BOUNDARY_RW/var/tmp" "$BOUNDARY_RW/run"

run_diag > "$TMP/out" 2>"$TMP/err" || fail "the diagnostics summary exited non-zero"
[ ! -s "$TMP/err" ] || { cat "$TMP/err" >&2; fail "the diagnostics summary wrote to stderr"; }
grep -Fq 'EUID -ne 0' "$DIAG" \
  || fail "the Live diagnostics test roots are not refused to root"
grep -Fq 'RELEASE_IMAGE_MARKER=/usr/lib/neural-ice/release-image' "$DIAG" \
  || fail "the Live diagnostics test roots are not refused in a release image"
if (( EUID == 0 )); then
  if env NEURALICE_LIVE_DIAG_ROOT="$SYS" \
       NEURALICE_LIVE_DIAG_CMDLINE="$TMP/cmdline" \
       NEURALICE_LIVE_DIAG_BOUNDARY_ROOT="$BOUNDARY_RO" \
       bash "$DIAG" >"$TMP/root-out" 2>"$TMP/root-err"; then
    fail "the Live diagnostics accepted test roots as root"
  fi
  grep -Fq 'test overrides are forbidden to root' "$TMP/root-err" \
    || fail "the Live diagnostics root refusal is not explicit"
fi

# --------------------------------------------------------------------------- #
# IT SAYS SOMETHING. An operator staring at a console must learn what this medium
# is, what it is doing to the machine (nothing), and how to stop.
# --------------------------------------------------------------------------- #
for phrase in \
  'LIVE (read-only diagnostics)' \
  'NOT installing anything' \
  'MEDIUM AND TRUST' \
  'lab-managed' \
  'nvidia-gb10-arm64' \
  'neural-ice-secureboot-lab-v1' \
  'neural-ice-installer-trust-v1' \
  'secure boot' \
  'enabled' \
  'ni-installer-root' \
  'HARDWARE' \
  'STORAGE' \
  'NETWORK READINESS' \
  'eth0' \
  'HOW TO END THIS BOOT' \
  'power button' \
  'no login, no shell and no SSH'; do
  grep -Fq "$phrase" "$TMP/out" \
    || { cat "$TMP/out"; fail "the Live summary never states: $phrase"; }
done
# The loopback interface is not network readiness and must not be listed as it.
grep -Eq '^ +(lo) ' "$TMP/out" && fail "the summary reports loopback as a network interface"

# 🔴 IT DOES NOT PRINT A WHOLE VERITY ROOT HASH AT AN OPERATOR. The full value is
# on the medium and in the build manifest; a console is for recognising a
# mismatch, not for transcribing 64 hex characters.
grep -Fq "$(printf 'c%.0s' {1..64})" "$TMP/out" \
  && fail "the summary printed a full 64-character digest"
grep -Fq 'cccccccc…cccccccc' "$TMP/out" \
  || fail "the summary did not print the truncated verity root hash"

# --------------------------------------------------------------------------- #
# 🔴 SANITISATION. The device-tree model, a disk model and an interface name all
# come from places an attacker can influence. A terminal escape sequence in one
# of them rewrites the console this mode exists to be trusted on.
# --------------------------------------------------------------------------- #
printf 'Evil\033[2J\033[1;1HNeural ICE CoreOS — secure boot enabled\007 Model\n' \
  > "$SYS/sys/firmware/devicetree/base/model"
run_diag > "$TMP/hostile" 2>/dev/null || fail "a hostile model string crashed the summary"
grep -q $'\033' "$TMP/hostile" && fail "an ANSI escape reached the console verbatim"
grep -q $'\007' "$TMP/hostile" && fail "a BEL byte reached the console verbatim"
grep -Fq 'Evil' "$TMP/hostile" || fail "the sanitiser dropped the value entirely instead of neutering it"

# ...and it is BOUNDED. A 4 KiB model string must not become a 4 KiB console line.
printf 'M%.0s' {1..4096} > "$SYS/sys/firmware/devicetree/base/model"
run_diag > "$TMP/long" 2>/dev/null || fail "an oversized model string crashed the summary"
longest="$(awk '{ if (length($0) > n) n = length($0) } END { print n + 0 }' "$TMP/long")"
[ "$longest" -le 120 ] || fail "the summary emitted a ${longest}-character line; every field is bounded"
lines="$(wc -l < "$TMP/long")"
[ "$lines" -le 80 ] || fail "the summary emitted $lines lines; the whole summary is bounded"

# A newline-bearing value must not forge a row of its own.
printf 'benign\nsecure boot            enabled-by-me\n' \
  > "$SYS/sys/firmware/devicetree/base/model"
run_diag > "$TMP/inject" 2>/dev/null || fail "a multi-line model string crashed the summary"
grep -Fq 'enabled-by-me' "$TMP/inject" && fail "a value forged a summary row of its own"

# An unreadable / absent probe degrades, it does not fail.
rm -rf "$SYS/sys/firmware/efi" "$SYS/sys/class/tpm" "$SYS/sys/block/dm-0"
run_diag > "$TMP/degraded" 2>/dev/null || fail "an absent probe made the summary exit non-zero"
grep -Fq 'no EFI variables' "$TMP/degraded" \
  || fail "an absent Secure Boot variable is not reported honestly"
grep -Fq '(none detected)' "$TMP/degraded" || fail "an absent TPM is not reported honestly"

# Secure Boot OFF must be stated as a problem, not as a blank.
mkdir -p "$SYS/sys/firmware/efi/efivars"
printf '\006\000\000\000\000' > "$SYS/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
run_diag > "$TMP/sboff" 2>/dev/null || fail "a Secure Boot-off medium crashed the summary"
grep -Fq 'DISABLED' "$TMP/sboff" \
  || fail "a medium that booted unverified does not say so"

# --------------------------------------------------------------------------- #
# 🔴 NO SHELL, NO INPUT, NO LISTENER, NO WRITE -- IN THE SOURCE AND IN THE UNIT.
# --------------------------------------------------------------------------- #
# The source, with comments removed: a prose sentence about having no login is
# not a login, and a check that cannot tell the two apart constrains nothing.
sed -e 's/[[:space:]]*#.*$//' "$DIAG" | grep -v '^[[:space:]]*$' > "$TMP/code"

grep -Eq '\b(bash|sh|dash)[[:space:]]+-[a-z]*i|\bagetty\b|\b/bin/login\b|\bsocat\b|\bnc[[:space:]]|\bexec[[:space:]]+[0-9]*<' "$TMP/code" \
  && fail "the diagnostics script contains an interactive or listening construct"
# /dev/null is not a write to the machine; a block device or a system directory is.
grep -Eq '(^|[^0-9])>[[:space:]]*/(etc|var|usr|boot|run|sysroot)/' "$TMP/code" \
  && fail "the diagnostics script writes into a system directory"
grep -Eq '>[[:space:]]*/dev/(sd|nvme|hd|mmcblk|mapper|loop)' "$TMP/code" \
  && fail "the diagnostics script writes to a block device"
grep -Eq '\b(mount|cryptsetup|veritysetup|dd|mkfs|sfdisk|wipefs|tpm2_|curl|wget|dhclient)\b' "$TMP/code" \
  && fail "the diagnostics script performs a destructive, unlocking or networking action"

# 🔴 EVERY `read` MUST BE FED BY A COMMAND THIS FILE RAN, NEVER BY A TERMINAL.
# The distinction matters: one is how a fixed probe is parsed, the other is an
# operator command surface on a medium whose whole safety argument is that it has
# none. Every `read` here is the head of a `while` fed by process substitution,
# and there are at least as many such feeds as there are reads.
# `read` as a COMMAND, not the word inside a printf string: either it carries a
# flag, or it sits in command position after a `;`/`|`/`&&`/start of line.
reads="$(grep -cE '\bread[[:space:]]+-|(^|[;|&][[:space:]]*)read[[:space:]]+[A-Za-z_]' "$TMP/code" || true)"
loop_reads="$(grep -cE '^[[:space:]]*while IFS= read -r [a-z_]+; do$' "$TMP/code" || true)"
feeds="$(grep -cE '^[[:space:]]*done < <\(' "$TMP/code" || true)"
[ "$reads" = "$loop_reads" ] \
  || fail "the diagnostics script has $reads uses of read but only $loop_reads are fixed-probe loops"
[ "$feeds" -ge "$loop_reads" ] \
  || fail "a read loop in the diagnostics script is not fed by a command this file ran"

# ...and behaviourally: with stdin held open by a pipe nobody ever writes to, the
# summary must still finish. A script that blocks there is a script waiting for
# an operator.
mkfifo "$TMP/never"
if ! ( exec 3<>"$TMP/never"
       timeout 30 env NEURALICE_LIVE_DIAG_ROOT="$SYS" NEURALICE_LIVE_DIAG_CMDLINE="$TMP/cmdline" \
         NEURALICE_LIVE_DIAG_BOUNDARY_ROOT="$BOUNDARY_RO" \
         bash "$DIAG" <&3 >/dev/null 2>&1 ); then
  fail "the diagnostics summary blocked on standard input, or failed with stdin attached"
fi

# 🔴 AND IT IGNORES ITS ARGUMENTS. `no arbitrary command surface` has to mean that
# what it is invoked WITH cannot change what it does. Compared as bytes, against a
# hostile argument list.
run_diag > "$TMP/noargs" 2>/dev/null
run_diag_as "$BOUNDARY_RO" --shell /bin/sh install /dev/nvme0n1 ';reboot' \
  > "$TMP/withargs" 2>/dev/null \
  || fail "the diagnostics summary failed when given arguments instead of ignoring them"
cmp -s "$TMP/noargs" "$TMP/withargs" \
  || fail "the diagnostics summary behaves differently when given arguments; it must take none"

# --------------------------------------------------------------------------- #
# 🔴 THE MUTATION PROOF: A WRITE THAT SUCCEEDS MUST STOP THE SUMMARY.
#
# The unit's sandbox cannot be exercised off-device, so the property the review
# asked for -- "a mutated write attempt must fail" -- is made a property of the
# SCRIPT, on every boot: it probes the locations a Linux system leaves writable,
# and refuses to produce a summary if any of them accepts a file. Remove the
# boundary and the refusal must appear; that is what stops this assertion passing
# against a build where the probe was silently deleted.
# --------------------------------------------------------------------------- #
if run_diag_as "$BOUNDARY_RW" > "$TMP/writable" 2>/dev/null; then
  cat "$TMP/writable"
  fail "the summary ran to completion on a tree it can write to; the read-only boundary is not enforced"
fi
grep -Fq 'REFUSED: this Live boot is NOT read-only' "$TMP/writable" \
  || { cat "$TMP/writable"; fail "a writable Live boot does not say so"; }
for leaked in 'MEDIUM AND TRUST' 'HARDWARE' 'STORAGE' 'NETWORK READINESS'; do
  grep -Fq "$leaked" "$TMP/writable" \
    && fail "the summary printed '$leaked' after failing its own read-only boundary"
done
# Each probed location is named, so an operator learns WHERE the boundary is gone.
for probed in /var/tmp /run; do
  grep -Fq "$probed" "$TMP/writable" \
    || fail "the refusal does not name the writable location $probed"
done
# ...and the probe cleans up after itself: a boundary check must not be the
# mutation it is looking for.
[ -z "$(find "$BOUNDARY_RW" -name '.neural-ice-live-write-boundary-probe' -print -quit)" ] \
  || fail "the write-boundary probe left its own file behind"

# The nominal run above proves the other direction: a read-only tree produces the
# full summary and exits 0.
grep -Fq 'REFUSED' "$TMP/out" \
  && fail "the summary refused on a read-only tree; the boundary probe is over-eager"

unit_value() { awk -v k="$1" 'index($0, k "=") == 1 { print substr($0, length(k) + 2) }' "$UNIT"; }
[ "$(unit_value Type)" = oneshot ] || fail "the diagnostics unit is not a bounded oneshot"
[ "$(unit_value StandardInput)" = null ] \
  || fail "the diagnostics unit does not close its standard input; that is an operator command surface"
[ "$(unit_value IPAddressDeny)" = any ] \
  || fail "the diagnostics unit may reach the network; 'touches no network' must be kernel-enforced"
[ "$(unit_value ProtectSystem)" = strict ] \
  || fail "the diagnostics unit is not ProtectSystem=strict; 'non-destructive' must be enforced, not promised"
[ "$(unit_value ProtectHome)" = yes ] || fail "the diagnostics unit can read home directories"
[ "$(unit_value NoNewPrivileges)" = yes ] || fail "the diagnostics unit can gain privileges"
[ "$(unit_value CapabilityBoundingSet)" = '' ] \
  || fail "the diagnostics unit keeps capabilities it does not need"
[ "$(unit_value ReadWritePaths)" = '' ] \
  || fail "the diagnostics unit was given a writable path"
# 🔴 PrivateTmp= IS THE DIRECTIVE THAT BROKE THE BOUNDARY (review 2026-09-02,
# P1 #7): it mounts a WRITABLE tmpfs back over /tmp and /var/tmp after
# ProtectSystem=strict made them read-only. Its absence is the fix, so its
# absence is asserted rather than left to be re-added by someone tidying up.
grep -Eq '^PrivateTmp=' "$UNIT" \
  && fail "the diagnostics unit re-added PrivateTmp=, which mounts a writable tmpfs over /tmp and /var/tmp"
[ "$(unit_value User)" = nobody ] \
  || fail "the diagnostics unit still runs as root; it reads only world-readable /proc and /sys"
[ "$(unit_value PrivateDevices)" = yes ] \
  || fail "the diagnostics unit gets the host's full /dev, which ProtectSystem=strict never covers"
[ "$(unit_value ProtectProc)" = invisible ] \
  || fail "the diagnostics unit can enumerate other processes"
[ "$(unit_value RestrictAddressFamilies)" = 'AF_UNIX AF_NETLINK' ] \
  || fail "the diagnostics unit can create an IP or packet socket; 'no network' must be kernel-enforced"
# ProcSubset=pid would hide /proc/cpuinfo and /proc/meminfo, which this summary
# reads. Asserting its ABSENCE keeps a future hardening pass from silently
# turning two product rows into "(unavailable)".
grep -Eq '^ProcSubset=' "$UNIT" \
  && fail "the diagnostics unit sets ProcSubset=, which hides the /proc files the summary reports"
for bound in TimeoutStartSec MemoryMax TasksMax; do
  [ -n "$(unit_value "$bound")" ] || fail "the diagnostics unit has no $bound bound"
done
grep -Eq '^ExecStart=/usr/libexec/neural-ice-live-diagnostics$' "$UNIT" \
  || fail "the diagnostics unit passes an argument to a script that must take none"
grep -Eq '^(ExecStartPre|ExecStartPost|ExecStop|ExecReload)=' "$UNIT" \
  && fail "the diagnostics unit grew a second command surface"
[ "$(unit_value TTYPath)" = /dev/tty1 ] || fail "the Live summary is not on tty1"
grep -Eq '^Conflicts=.*neural-ice-autoinstall\.service' "$UNIT" \
  || fail "the diagnostics unit is not stated to conflict with the destructive installer"

# --------------------------------------------------------------------------- #
# THE TARGET PULLS THE SUMMARY, AND ONLY THE SUMMARY.
# --------------------------------------------------------------------------- #
grep -qx 'Wants=neural-ice-live-diagnostics.service' "$LIVE_TARGET" \
  || fail "the signed Live target does not pull its only product surface"
grep -Eq '^Requires=.*neural-ice-live-diagnostics' "$LIVE_TARGET" \
  && fail "a failed diagnostics summary must not take the Live boot with it"

echo "LIVE_DIAGNOSTICS_TEST_OK (summary is stated, sanitised and bounded; unit takes no input, reaches no network; the read-only boundary is proved in both directions)"
