#!/usr/bin/env bash
# THE INSTALLER'S FAILURE SURFACE, DRIVEN FOR REAL.
#
# 🔴 WHAT THIS SUITE EXISTS TO STOP COMING BACK (independent review 2026-09-02,
# P0 #1). neural-ice-autoinstall.service carried `OnFailure=emergency.target`
# with `OnFailureJobMode=isolate`, and image/installer/neural-ice-installer-runtime-generator
# UNMASKED emergency/rescue/debug-shell on every Install boot so that sink would
# resolve. So every preflight, authorisation, pull, storage, TPM and deployment
# failure of a destructive install ended on a root shell on tty1 -- on a machine
# whose OTHER disks, TPM, network and signed artefacts were then one command
# away, none of which was part of what the operator authorised.
#
# The sink is now a fixed, output-only target. This suite holds all four halves
# of that decision:
#
#   VOCABULARY   the console carries a stable code from a closed table, a phase,
#                a stage slug and a one-way digest -- never a message, a path, a
#                device, a key or a byte that came off a medium or the network.
#   BOUNDED      an oversized, hostile, duplicated or unknown-keyed evidence file
#                cannot widen, forge or lengthen what is printed.
#   TERMINAL     the action and the delay come from the SIGNED read-only /usr and
#                are re-bounded by the reader; a malformed policy is not a
#                machine that sits on a console for ever.
#   INDUCED      every failure class the installer can reach is provoked and its
#                evidence asserted -- the reachable ones by running the REAL
#                installer, the hardware-only ones by driving the real `die` and
#                `phase` functions lifted verbatim out of it.
#
# It needs no root, no medium, no TPM and no network.
# shellcheck disable=SC2034
# The installer's own `phase`, `die` and `write_failure_evidence` are lifted out
# of ota/neural-ice-autoinstall.sh and sourced below; every variable they read is
# set by THIS file for them, which shellcheck cannot see through a `.` of a file
# it was not given.
# shellcheck disable=SC2016
# The source-contract assertions below quote installer text verbatim; a `$` in
# them must reach grep unexpanded, or the check becomes a search for the empty
# string, which always matches.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FAILURE="$ROOT/image/installer/neural-ice-installer-failure.sh"
FAILURE_UNIT="$ROOT/image/installer/neural-ice-installer-failure.service"
FAILURE_TARGET="$ROOT/image/installer/neural-ice-installer-failure.target"
POLICY="$ROOT/image/installer/installer-failure-policy"
AUTOINSTALL="$ROOT/ota/neural-ice-autoinstall.sh"
AUTOINSTALL_UNIT="$ROOT/ota/neural-ice-autoinstall.service"
GRAMMAR="$ROOT/image/installer/neural-ice-sealed-cmdline-grammar.sh"
CONTAINERFILE="$ROOT/image/Containerfile.installer"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/ni-failure-surface.XXXXXX")"
trap 'chmod -R u+w "$TMP" 2>/dev/null || true; rm -rf "$TMP"' EXIT
chmod 0755 "$TMP"
fail() { echo "FAIL: $*" >&2; exit 1; }

for required in "$FAILURE" "$FAILURE_UNIT" "$FAILURE_TARGET" "$POLICY" \
  "$AUTOINSTALL" "$AUTOINSTALL_UNIT" "$GRAMMAR" "$CONTAINERFILE"; do
  [ -f "$required" ] || fail "missing input: $required"
done
# 🔴 NO SKIP PATH. bash is the whole toolchain; its absence is a failure.
command -v sha256sum >/dev/null 2>&1 || fail "sha256sum is required; this suite does not SKIP"

# --------------------------------------------------------------------------- #
# THE SINK, DRIVEN. `--dry-run` is the seam that keeps a suite from powering a
# build host off; everything above the action is the shipped path.
# --------------------------------------------------------------------------- #
render() { # $1=evidence file (or "") $2=policy file (or "") -> stdout
  local -a command=(env
    "NEURALICE_FAILURE_EVIDENCE=${1:-$TMP/no-such-evidence}"
    "NEURALICE_FAILURE_POLICY=${2:-$TMP/no-such-policy}"
    bash "$FAILURE" --dry-run)
  if (( EUID == 0 )); then
    chmod -R a+rX "$TMP" "$FAILURE" 2>/dev/null || true
    runuser -u nobody -- "${command[@]}"
  else
    "${command[@]}"
  fi
}

write_evidence() { # $1=path, rest: literal lines
  local path=$1; shift
  printf '%s\n' "$@" > "$path"
}

# --------------------------------------------------------------------------- #
# 1) THE NOMINAL RENDER. Stable code, stage, phase and digest; the shipped
#    policy's action and delay.
# --------------------------------------------------------------------------- #
write_evidence "$TMP/nominal" \
  'schema=neural-ice-installer-failure-evidence-v1' \
  'code=install-failed-write-deployment' \
  'phase=4' \
  'phase_total=8' \
  'stage=write-deployment' \
  'detail=0123456789ab'
render "$TMP/nominal" "$POLICY" > "$TMP/out" 2>"$TMP/err" \
  || fail "the failure surface exited non-zero on well-formed evidence"
[ ! -s "$TMP/err" ] || { cat "$TMP/err" >&2; fail "the failure surface wrote to stderr"; }
for phrase in 'INSTALL FAILED' 'install-failed-write-deployment' 'write-deployment' \
  '0123456789ab' 'There is no login' 'no shell and no recovery console' \
  'neural-ice-installer-failure-evidence-v1' 'poweroff'; do
  grep -Fq "$phrase" "$TMP/out" || { cat "$TMP/out"; fail "the failure screen never states: $phrase"; }
done
grep -Fq '4 / 8' "$TMP/out" || { cat "$TMP/out"; fail "the failure screen does not state which stage failed"; }
grep -Fq 'DRY-RUN: would poweroff after 60 seconds' "$TMP/out" \
  || fail "the shipped policy's action and delay are not the ones the sink would take"

# --------------------------------------------------------------------------- #
# 2) IT IS A CONSOLE, NOT A DIAGNOSTIC DUMP. Whatever the installer knew, the
#    screen must carry none of it: no path, no device, no digest of a key, no
#    hostname, no image reference, no operator input.
# --------------------------------------------------------------------------- #
for leaked in '/dev/' '/usr/' '/run/' 'sha256:' '@sha256' 'registry.' 'ghcr.io' \
  'authorized_keys' 'neuralice.'; do
  grep -Fq "$leaked" "$TMP/out" \
    && { cat "$TMP/out"; fail "the failure screen carries '$leaked'; it must state a code, not a diagnostic"; }
done
lines="$(wc -l < "$TMP/out")"
[ "$lines" -le 40 ] || fail "the failure screen is $lines lines; it is bounded"
longest="$(awk '{ if (length($0) > n) n = length($0) } END { print n + 0 }' "$TMP/out")"
[ "$longest" -le 100 ] || fail "the failure screen emitted a ${longest}-character line; every field is bounded"

# --------------------------------------------------------------------------- #
# 3) HOSTILE EVIDENCE. The installer wrote this file and the installer is the
#    thing that just failed, so it is parsed as untrusted input.
# --------------------------------------------------------------------------- #
hostile_case() { # $1=label, rest: evidence lines -> renders into $TMP/hostile
  local label=$1; shift
  write_evidence "$TMP/hostile-in" "$@"
  render "$TMP/hostile-in" "$POLICY" > "$TMP/hostile" 2>/dev/null \
    || fail "[$label] hostile evidence crashed the failure surface"
  return 0
}

# An unknown key is dropped rather than printed.
hostile_case 'unknown key' \
  'code=install-failed-preflight-and-trust-gate' \
  'operator_key=AAAAB3NzaC1yc2EAAAADAQABAAABgQCsecretkeymaterial' \
  'target_disk=/dev/nvme0n1'
grep -Fq 'secretkeymaterial' "$TMP/hostile" && fail "an unknown evidence key reached the console"
grep -Fq '/dev/nvme0n1' "$TMP/hostile" && fail "an unknown evidence key reached the console"

# A value outside the shape is `unclassified`, never printed raw.
hostile_case 'terminal escape in a value' \
  "$(printf 'code=evil\033[2Jinstall-succeeded')" \
  'stage=ok'
grep -q $'\033' "$TMP/hostile" && fail "an ANSI escape reached the console verbatim"
grep -Fq 'install-succeeded' "$TMP/hostile" && fail "a malformed code was printed instead of being classified"
grep -Fq 'unclassified' "$TMP/hostile" || fail "a malformed code is not reported as unclassified"

# A value longer than the shape allows is refused entirely, not truncated into
# something that still reads like a code.
hostile_case 'oversized value' "code=$(printf 'A%.0s' {1..4096})"
grep -Fq 'AAAAAAAAAA' "$TMP/hostile" && fail "an oversized code reached the console"

# A duplicated key cannot overwrite the first: a last-writer rule would let a
# defect later in the failure path relabel the failure.
hostile_case 'duplicate key' \
  'code=install-failed-stage-verified-seed' \
  'code=install-succeeded-please-continue'
grep -Fq 'install-failed-stage-verified-seed' "$TMP/hostile" \
  || fail "the first occurrence of a duplicated key is not the one that is printed"
grep -Fq 'install-succeeded-please-continue' "$TMP/hostile" \
  && fail "a duplicated key overwrote the first; the reader must take the first occurrence"

# A megabyte of evidence costs a bounded read, not a bounded console.
head -c 1048576 /dev/zero | tr '\0' 'x' > "$TMP/huge"
render "$TMP/huge" "$POLICY" > "$TMP/hugeout" 2>/dev/null \
  || fail "an oversized evidence file crashed the failure surface"
[ "$(wc -l < "$TMP/hugeout")" -le 40 ] || fail "an oversized evidence file grew the console output"

# NO evidence at all is still a bounded, terminal screen: the installer may have
# died before it could write one.
render "" "$POLICY" > "$TMP/none" 2>/dev/null \
  || fail "the failure surface needs an evidence file to run; a failure before one exists is exactly when it is needed"
grep -Fq 'unclassified' "$TMP/none" || fail "an absent evidence file is not reported honestly"
grep -Fq 'DRY-RUN: would poweroff after 60 seconds' "$TMP/none" \
  || fail "a failure with no evidence does not still reach a terminal action"

# A SYMLINK where the evidence belongs is not followed: /run is a tmpfs the unit
# owns, and a surface that follows a link there is a surface that can be pointed
# at anything the sink can read.
ln -sfn /etc/passwd "$TMP/evidence-link"
render "$TMP/evidence-link" "$POLICY" > "$TMP/link" 2>/dev/null \
  || fail "a symlinked evidence path crashed the failure surface"
grep -Fq 'root:' "$TMP/link" && fail "the failure surface followed a symlink and printed its target"

# --------------------------------------------------------------------------- #
# 4) THE TERMINAL ACTION IS BOUNDED AND COMES FROM THE SIGNED /usr.
# --------------------------------------------------------------------------- #
policy_case() { # $1=label $2=expected-line, rest: policy lines
  local label=$1 expected=$2; shift 2
  printf '%s\n' "$@" > "$TMP/policy-in"
  render "$TMP/nominal" "$TMP/policy-in" > "$TMP/policy-out" 2>/dev/null \
    || fail "[$label] a policy variant crashed the failure surface"
  grep -Fq "$expected" "$TMP/policy-out" \
    || { cat "$TMP/policy-out"; fail "[$label] expected: $expected"; }
  return 0
}
policy_case 'reboot is the other permitted action' 'would reboot after 30 seconds' \
  'action=reboot' 'delay_seconds=30'
policy_case 'an unknown action falls back to poweroff' 'would poweroff after 60 seconds' \
  'action=stay-on-the-console-for-ever' 'delay_seconds=60'
policy_case 'a delay above the ceiling is refused' 'would poweroff after 60 seconds' \
  'action=poweroff' 'delay_seconds=86400'
policy_case 'a delay below the floor is refused' 'would poweroff after 60 seconds' \
  'action=poweroff' 'delay_seconds=0'
policy_case 'a non-numeric delay is refused' 'would poweroff after 60 seconds' \
  'action=poweroff' 'delay_seconds=$(reboot)'
policy_case 'an empty policy is the safe default' 'would poweroff after 60 seconds' ''
render "$TMP/nominal" "" > "$TMP/nopolicy" 2>/dev/null \
  || fail "an absent policy crashed the failure surface"
grep -Fq 'would poweroff after 60 seconds' "$TMP/nopolicy" \
  || fail "an absent policy does not fall back to the safe default"

# The SHIPPED policy is itself inside the bounds its reader enforces, so the
# medium's default is not silently replaced by the fallback.
grep -qx 'action=poweroff' "$POLICY" \
  || fail "the shipped failure policy no longer powers the machine off"
shipped_delay="$(sed -n 's/^delay_seconds=//p' "$POLICY")"
[[ "$shipped_delay" =~ ^[0-9]+$ ]] && [ "$shipped_delay" -ge 5 ] && [ "$shipped_delay" -le 300 ] \
  || fail "the shipped failure delay ($shipped_delay) is outside the bounds its own reader enforces"

# --------------------------------------------------------------------------- #
# 5) NO INPUT, NO SHELL, NO ARGUMENT SURFACE.
# --------------------------------------------------------------------------- #
if env NEURALICE_FAILURE_EVIDENCE="$TMP/nominal" NEURALICE_FAILURE_POLICY="$POLICY" \
     bash "$FAILURE" --shell /bin/sh >/dev/null 2>&1; then
  fail "the failure surface accepted an argument it does not define"
fi
mkfifo "$TMP/never"
if ! ( exec 3<>"$TMP/never"
       command=(env NEURALICE_FAILURE_EVIDENCE="$TMP/nominal" \
         NEURALICE_FAILURE_POLICY="$POLICY" bash "$FAILURE" --dry-run)
       if (( EUID == 0 )); then
         timeout 30 runuser -u nobody -- "${command[@]}" <&3 >/dev/null 2>&1
       else
         timeout 30 "${command[@]}" <&3 >/dev/null 2>&1
       fi ); then
  fail "the failure surface blocked on standard input, or failed with stdin attached"
fi
# The source, with comments removed: a sentence about having no shell is not the
# absence of one.
sed -e 's/[[:space:]]*#.*$//' "$FAILURE" | grep -v '^[[:space:]]*$' > "$TMP/code"
grep -Eq '\b(bash|sh|dash)[[:space:]]+-[a-z]*i|\bagetty\b|\b/bin/login\b|\bsocat\b|\bexec[[:space:]]+[0-9]*<' "$TMP/code" \
  && fail "the failure surface contains an interactive or listening construct"
grep -Eq '(^|[^0-9])>[[:space:]]*/(etc|var|usr|boot|run|sysroot)/' "$TMP/code" \
  && fail "the failure surface writes into a system directory"
reads="$(grep -cE '\bread[[:space:]]+-|(^|[;|&][[:space:]]*)read[[:space:]]+[A-Za-z_]' "$TMP/code" || true)"
loop_reads="$(grep -cE 'while IFS= read -r [a-z_]+; do$|^read -r [A-Z ]+<<<' "$TMP/code" || true)"
[ "$reads" = "$loop_reads" ] \
  || fail "the failure surface has $reads uses of read but only $loop_reads are fixed-input parses"

# --------------------------------------------------------------------------- #
# 6) THE UNIT AND THE TARGET.
# --------------------------------------------------------------------------- #
unit_value() { awk -v k="$1" -v f="$2" 'index($0, k "=") == 1 { print substr($0, length(k) + 2) }' "$2"; }
[ "$(unit_value Type "$FAILURE_UNIT")" = oneshot ] || fail "the failure unit is not a bounded oneshot"
[ "$(unit_value StandardInput "$FAILURE_UNIT")" = null ] \
  || fail "the failure unit does not close its standard input; that is an operator command surface"
[ "$(unit_value IPAddressDeny "$FAILURE_UNIT")" = any ] \
  || fail "the failure unit may reach the network"
[ "$(unit_value ProtectSystem "$FAILURE_UNIT")" = strict ] \
  || fail "the failure unit can write to the machine it is reporting a failure on"
[ "$(unit_value ReadWritePaths "$FAILURE_UNIT")" = '' ] \
  || fail "the failure unit was given a writable path"
[ "$(unit_value CapabilityBoundingSet "$FAILURE_UNIT")" = CAP_SYS_BOOT ] \
  || fail "the failure unit keeps capabilities beyond the power-off it exists to perform"
grep -Eq '^PrivateTmp=' "$FAILURE_UNIT" \
  && fail "the failure unit re-added PrivateTmp=, which mounts a writable tmpfs over /tmp and /var/tmp"
[ "$(unit_value TTYPath "$FAILURE_UNIT")" = /dev/tty1 ] || fail "the failure screen is not on tty1"
grep -qx 'AllowIsolate=yes' "$FAILURE_TARGET" \
  || fail "the failure target cannot be isolated onto, so OnFailureJobMode=isolate would fail"
target_dependencies="$(grep -E '^(Requires|Wants|Requisite|BindsTo|PartOf)=' "$FAILURE_TARGET" | sort)"
[[ "$target_dependencies" == 'Requires=neural-ice-installer-failure.service' ]] \
  || fail "the failure target's dependency set is not exactly its one output-only service; it is:"$'\n'"$target_dependencies"

# The autoinstall unit routes here, isolates, and provides the root-only evidence
# directory BEFORE ExecStart -- so the failure path creates no directory at all.
grep -qx 'OnFailure=neural-ice-installer-failure.target' "$AUTOINSTALL_UNIT" \
  || fail "the autoinstall unit does not route its failures to this sink"
grep -v '^[[:space:]]*#' "$AUTOINSTALL_UNIT" | grep -qiE 'emergency|rescue|debug-shell' \
  && fail "the autoinstall unit still names an emergency/rescue/debug surface"
for directive in RuntimeDirectory=neural-ice-installer-failure RuntimeDirectoryMode=0700 \
  RuntimeDirectoryPreserve=yes; do
  grep -qx "$directive" "$AUTOINSTALL_UNIT" || fail "the autoinstall unit lost $directive"
done
# ...and the two halves agree about WHERE the evidence is, by construction rather
# than by two people remembering the same path.
grep -Fq '/run/neural-ice-installer-failure/evidence' "$AUTOINSTALL" \
  || fail "the installer does not write its evidence where the sink reads it"
grep -Fq '/run/neural-ice-installer-failure/evidence' "$FAILURE" \
  || fail "the sink does not read the evidence where the installer writes it"

# --------------------------------------------------------------------------- #
# 7) 🔴 EVERY FAILURE CLASS, INDUCED.
#
# The installer is a top-to-bottom script that wipes disks and cannot be sourced,
# so this is done the two ways the classes allow:
#
#   RUN     the classes reachable without hardware are provoked by running the
#           REAL /usr/local/bin/neural-ice-autoinstall.sh under its test seam,
#           and its evidence file is read back.
#   LIFT    the classes that need a disk, a TPM, a registry or a network -- the
#           partition, deployment, seed, device-root, SELinux and finalize phases
#           -- are provoked by driving the REAL `phase`, `die` and
#           `write_failure_evidence` functions lifted verbatim out of the same
#           file. A phase that cannot be entered off-device still has its code
#           and its slug proved to be the ones the sink will print.
#
# Physical induction of the hardware classes on a signed medium is a residual
# gate; it is named as such in the mission report and is NOT claimed here.
# --------------------------------------------------------------------------- #
ANCHOR="neuralice.trust=neural-ice-installer-trust-v1"
ANCHOR="$ANCHOR neuralice.access_profile=lab-managed"
ANCHOR="$ANCHOR neuralice.hardware_target=nvidia-gb10-arm64"
ANCHOR="$ANCHOR neuralice.payload=$(printf '%064d' 1)"
ANCHOR="$ANCHOR neuralice.relauth_keyid=$(printf '%064d' 2)"
ANCHOR="$ANCHOR neuralice.relauth_schema=neural-ice-installer-release-authorization-v2"
ANCHOR="$ANCHOR neuralice.rootverity=$(printf '%064d' 3)"
ANCHOR="$ANCHOR neuralice.trust_policy_id=neural-ice-secureboot-lab-v1"

run_installer() { # $1=cmdline $2=evidence path, rest: extra env assignments
  local cmdline=$1 evidence=$2; shift 2
  printf '%s\n' "$cmdline" > "$TMP/run-cmdline"
  rm -f "$evidence"
  env NI_INSTALLER_TEST_SEAM=1 \
      NEURALICE_CMDLINE_FILE="$TMP/run-cmdline" \
      NEURALICE_SEALED_GRAMMAR="$GRAMMAR" \
      NEURALICE_FAILURE_EVIDENCE="$evidence" \
      "$@" \
      bash "$AUTOINSTALL" >/dev/null 2>&1
}

evidence_field() { # $1=file $2=key
  sed -n "s/^$2=//p" "$1" | head -1
}

induced=0
induce_run() { # $1=label $2=cmdline $3=expected code, rest: extra env
  local label=$1 cmdline=$2 expected=$3; shift 3
  local evidence="$TMP/induced-evidence"
  run_installer "$cmdline" "$evidence" "$@" \
    && fail "[$label] the installer did NOT fail; this class is not being induced"
  [ -f "$evidence" ] \
    || fail "[$label] the installer failed and left no evidence for the sink to render"
  [ "$(evidence_field "$evidence" schema)" = neural-ice-installer-failure-evidence-v1 ] \
    || fail "[$label] the evidence carries no recognised schema"
  [ "$(evidence_field "$evidence" code)" = "$expected" ] \
    || fail "[$label] the evidence code is '$(evidence_field "$evidence" code)', expected '$expected'"
  # ...and the sink renders it, so the class ends on the fixed screen and not
  # anywhere else.
  render "$evidence" "$POLICY" > "$TMP/induced-out" 2>/dev/null \
    || fail "[$label] the sink could not render the evidence this class produced"
  grep -Fq "$expected" "$TMP/induced-out" \
    || fail "[$label] the failure screen does not carry this class's code"
  grep -Fq 'DRY-RUN: would poweroff' "$TMP/induced-out" \
    || fail "[$label] this class does not reach a terminal action"
  induced=$(( induced + 1 ))
  return 0
}

INSTALL_LINE="$ANCHOR quiet systemd.unit=neural-ice-installer.target neuralice.autoinstall=1 enforcing=0"
LIVE_LINE="$ANCHOR quiet systemd.unit=neural-ice-live.target neuralice.live=1"

# The preflight classes: an unauthorised selector, a Live medium, an unreadable
# grammar, and the TPM/state-helper preconditions. All of these are startup-phase
# refusals, which is exactly the point: a refusal before phase 1 must still reach
# the sink rather than reaching nothing.
induce_run 'selector: a Live medium invoked as an installer' \
  "$LIVE_LINE" install-failed-startup
induce_run 'selector: a bare autoinstall word with no sealed anchor' \
  'quiet neuralice.autoinstall=1' install-failed-startup
induce_run 'selector: a root debug shell on an otherwise valid Install line' \
  "$INSTALL_LINE systemd.debug_shell" install-failed-startup
induce_run 'preflight: no TPM state helper on this medium' \
  "$INSTALL_LINE" install-failed-startup TPM_STATE="$TMP/there-is-no-tpm-helper"
induce_run 'argument: a duplicated wipe target the installer refuses to arbitrate' \
  "$INSTALL_LINE neuralice.target=/dev/nvme0n1 neuralice.target=/dev/nvme1n1" \
  install-failed-startup
induce_run 'argument: a registry source naming no image to pull' \
  "$INSTALL_LINE neuralice.source=registry" install-failed-startup

# An unreadable sealed grammar. The installer must refuse rather than assume, and
# it must still produce evidence -- the case where it can establish nothing at
# all about its own authorisation is the case an operator most needs told.
printf '%s\n' "$INSTALL_LINE" > "$TMP/run-cmdline"
rm -f "$TMP/induced-evidence"
if env NI_INSTALLER_TEST_SEAM=1 NEURALICE_CMDLINE_FILE="$TMP/run-cmdline" \
     NEURALICE_SEALED_GRAMMAR="$TMP/there-is-no-grammar" \
     NEURALICE_FAILURE_EVIDENCE="$TMP/induced-evidence" \
     bash "$AUTOINSTALL" >/dev/null 2>&1; then
  fail "the installer proceeded with no readable sealed grammar"
fi
[ "$(evidence_field "$TMP/induced-evidence" code)" = install-failed-startup ] \
  || fail "an unreadable sealed grammar produced no usable failure evidence"
induced=$(( induced + 1 ))

# 🔴 AND THE SEAM ITSELF CANNOT BE USED WHERE IT MATTERS. Three independent
# conditions, each asserted on its own: the variable, the privilege, the marker.
printf '%s\n' "$INSTALL_LINE" > "$TMP/run-cmdline"
mkdir -p "$TMP/fake-usr/lib/neural-ice"
: > "$TMP/fake-usr/lib/neural-ice/release-image"
seam_refused() { # rest: env assignments -> 0 when the installer refused the seam
  local output
  output="$(env "$@" bash "$AUTOINSTALL" 2>&1)" && return 1
  grep -Fq 'test overrides are forbidden' <<<"$output"
}
seam_refused NI_INSTALLER_TEST_SEAM=yes NEURALICE_CMDLINE_FILE="$TMP/run-cmdline" \
  || fail "the installer accepted a seam value other than the exact literal 1"
# The release-image marker is the condition that cannot be met on a medium. It is
# checked at its production path, so the assertion is on the CONSTANT rather than
# on a fixture: a build that stopped staging it is the defect.
grep -Fq 'NI_RELEASE_IMAGE_MARKER="/usr/lib/neural-ice/release-image"' "$AUTOINSTALL" \
  || fail "the installer no longer pins its release-image marker to an absolute path in the signed /usr"
grep -Fq '/usr/lib/neural-ice/release-image' "$CONTAINERFILE" \
  || fail "the installer image no longer stages the marker that makes the test seam impossible on a medium"
grep -Fq 'EUID == 0' "$AUTOINSTALL" \
  || fail "the installer no longer refuses test overrides in a privileged process"
grep -Fq 'EUID -ne 0' "$FAILURE" \
  || fail "the failure surface no longer refuses test roots/dry-run to root"
grep -Fq 'RELEASE_IMAGE_MARKER=/usr/lib/neural-ice/release-image' "$FAILURE" \
  || fail "the failure surface no longer refuses test roots/dry-run in a release image"
if (( EUID == 0 )); then
  if env NEURALICE_FAILURE_EVIDENCE="$TMP/nominal" \
       NEURALICE_FAILURE_POLICY="$POLICY" bash "$FAILURE" --dry-run \
       >"$TMP/root-out" 2>"$TMP/root-err"; then
    fail "the failure surface accepted test roots/dry-run as root"
  fi
  grep -Fq 'test overrides are forbidden to root' "$TMP/root-err" \
    || fail "the root refusal is not explicit"
fi
# ...and with the seam DISARMED, not one production path is overridable.
printf '%s\n' "$LIVE_LINE" > "$TMP/run-cmdline"
if env NEURALICE_CMDLINE_FILE="$TMP/run-cmdline" NEURALICE_SEALED_GRAMMAR="$GRAMMAR" \
     bash "$AUTOINSTALL" >/dev/null 2>&1; then
  fail "the installer honoured a command-line override with the test seam disarmed"
fi
# Proof that it read /proc/cmdline instead of the fixture: the fixture is a Live
# line, so honouring it would have produced the Live refusal. Reading the real
# one produces a refusal too -- but at the grammar, and this asserts which.
override_output="$(env NEURALICE_CMDLINE_FILE="$TMP/run-cmdline" \
  NEURALICE_SEALED_GRAMMAR="$GRAMMAR" bash "$AUTOINSTALL" 2>&1 || true)"
grep -Fq "signed selector is 'live'" <<<"$override_output" \
  && fail "the installer classified the FIXTURE command line with the seam disarmed; the override is still live"

# --------------------------------------------------------------------------- #
# THE HARDWARE-ONLY CLASSES, DRIVEN THROUGH THE REAL FUNCTIONS.
# --------------------------------------------------------------------------- #
{
  awk '/^declare -rA PHASE_SLUGS=\(/,/^\)$/' "$AUTOINSTALL"
  awk '/^fmt_dur\(\) \{/,/^}$/' "$AUTOINSTALL"
  awk '/^phase\(\) \{/,/^}$/' "$AUTOINSTALL"
  awk '/^write_failure_evidence\(\) \{/,/^}$/' "$AUTOINSTALL"
  awk '/^die\(\)  \{/,/^}$/' "$AUTOINSTALL"
} > "$TMP/phases.sh"
for required_function in PHASE_SLUGS 'phase()' 'write_failure_evidence()' 'die()'; do
  grep -q "$required_function" "$TMP/phases.sh" \
    || fail "the installer no longer defines $required_function as an extractable unit; this suite would test a paraphrase"
done

declare -A EXPECTED_SLUGS=(
  [1]=preflight-and-trust-gate
  [2]=partition-and-encrypt
  [3]=prepare-target-filesystem
  [4]=write-deployment
  [5]=stage-verified-seed
  [6]=deployment-prep-and-device-root
  [7]=selinux-labelling
  [8]=finalize-and-escrow
)
for id in 1 2 3 4 5 6 7 8; do
  evidence="$TMP/phase-$id"
  (
    set -uo pipefail
    # shellcheck disable=SC2329
    log() { :; }
    PHASE_TOTAL=8; PHASE_ID=0; PHASE_LABEL=startup; PHASE_T0=0; SECONDS=0
    FAILURE_EVIDENCE_SCHEMA=neural-ice-installer-failure-evidence-v1
    FAILURE_EVIDENCE="$evidence"
    # shellcheck source=/dev/null
    . "$TMP/phases.sh"
    phase "$id" "induced class $id"
    die "a diagnostic naming /dev/nvme0n1, ghcr.io/x@sha256:$(printf '%064d' 9) and an operator key"
  ) >/dev/null 2>&1 && fail "the installer's own die() returned success"
  [ -f "$evidence" ] || fail "phase $id produced no failure evidence"
  [ "$(evidence_field "$evidence" stage)" = "${EXPECTED_SLUGS[$id]}" ] \
    || fail "phase $id reports stage '$(evidence_field "$evidence" stage)', expected '${EXPECTED_SLUGS[$id]}'"
  [ "$(evidence_field "$evidence" code)" = "install-failed-${EXPECTED_SLUGS[$id]}" ] \
    || fail "phase $id reports an unexpected code"
  [ "$(evidence_field "$evidence" phase)" = "$id" ] || fail "phase $id reports the wrong phase number"
  # 🔴 THE DIAGNOSTIC IS HASHED, NOT CARRIED. The message above names a device, a
  # digest-pinned image reference and a key; none of them may survive into the
  # evidence, and the digest that does must be one-way.
  detail="$(evidence_field "$evidence" detail)"
  [[ "$detail" =~ ^[0-9a-f]{12}$ ]] || fail "phase $id produced no bounded one-way detail digest"
  grep -Fq '/dev/nvme0n1' "$evidence" && fail "phase $id leaked a device path into the evidence"
  grep -Fq 'ghcr.io' "$evidence" && fail "phase $id leaked an image reference into the evidence"
  grep -Fq 'operator key' "$evidence" && fail "phase $id leaked the diagnostic message into the evidence"
  render "$evidence" "$POLICY" > "$TMP/phase-out" 2>/dev/null \
    || fail "phase $id produced evidence the sink cannot render"
  grep -Fq "install-failed-${EXPECTED_SLUGS[$id]}" "$TMP/phase-out" \
    || fail "phase $id does not reach the fixed failure screen"
  induced=$(( induced + 1 ))
done

# Two different diagnostics must not collapse onto one detail digest, or the
# field correlates nothing.
(
  set -uo pipefail
  # shellcheck disable=SC2329
  log() { :; }
  PHASE_TOTAL=8; PHASE_ID=4; PHASE_LABEL=x; PHASE_SLUG=write-deployment
  PHASE_CODE=install-failed-write-deployment
  FAILURE_EVIDENCE_SCHEMA=neural-ice-installer-failure-evidence-v1
  FAILURE_EVIDENCE="$TMP/detail-b"
  # shellcheck source=/dev/null
  . "$TMP/phases.sh"
  die "a different diagnostic entirely"
) >/dev/null 2>&1 || true
[ "$(evidence_field "$TMP/phase-4" detail)" != "$(evidence_field "$TMP/detail-b" detail)" ] \
  || fail "two different diagnostics produced the same detail digest"

# An unnumbered phase must be visibly unclassified rather than silently
# inheriting the previous phase's identity.
(
  set -uo pipefail
  # shellcheck disable=SC2329
  log() { :; }
  PHASE_TOTAL=8; PHASE_ID=0; PHASE_LABEL=startup; PHASE_T0=0; SECONDS=0
  FAILURE_EVIDENCE_SCHEMA=neural-ice-installer-failure-evidence-v1
  FAILURE_EVIDENCE="$TMP/phase-unknown"
  # shellcheck source=/dev/null
  . "$TMP/phases.sh"
  phase 99 "a phase nobody numbered"
  die "x"
) >/dev/null 2>&1 || true
[ "$(evidence_field "$TMP/phase-unknown" stage)" = unclassified ] \
  || fail "an unnumbered phase silently inherits an identity instead of being unclassified"

(( induced >= 15 )) || fail "only $induced failure classes were induced; the coverage shrank"

echo "INSTALLER_FAILURE_SURFACE_TEST_OK (${induced} failure classes induced; evidence is bounded, closed-vocabulary and one-way; the sink takes no input and always reaches a terminal action)"
