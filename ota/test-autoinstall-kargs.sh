#!/usr/bin/env bash
# shellcheck disable=SC2016 # literal source-contract assertions below
# EVERY DESTRUCTIVE INPUT IS READ EXACTLY ONCE, OR NOT AT ALL.
#
# 🔴 THE HOLE THIS CLOSES. The six sealed fields and the SSH key already refused
# a second occurrence. Everything else used
# `grep -qE 'KEY=' && sed -n 's/.*KEY=\([^ ]*\).*/\1/p'` -- a GREEDY match that
# silently keeps the LAST occurrence. An appended `neuralice.target=/dev/nvme1n1`
# is not a sealed-field duplicate, so the trust gate still succeeded, and the
# winner that greedy sed picked steered the WIPE. The same held for the image
# reference, the mirror, the install source and the system size.
#
# This suite EXERCISES the reader against a fixture command line rather than
# grepping the installer's source: a source-shape assertion cannot tell you which
# value a parser would have chosen.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AUTOINSTALL="$ROOT/ota/neural-ice-autoinstall.sh"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/ni-kargs.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

# The installer is a top-to-bottom script that wipes disks; it cannot be sourced.
# Extract exactly the two functions under test, verbatim, so the suite runs the
# SAME code the appliance runs rather than a paraphrase of it.
awk '/^karg_count\(\) \{/,/^}$/' "$AUTOINSTALL" > "$TMP/reader.sh"
awk '/^karg_once\(\) \{/,/^}$/'  "$AUTOINSTALL" >> "$TMP/reader.sh"
grep -q '^karg_count()' "$TMP/reader.sh" || fail "cannot extract karg_count from the installer"
grep -q '^karg_once()'  "$TMP/reader.sh" || fail "cannot extract karg_once from the installer"

CMDLINE="$TMP/cmdline"
die() { echo "die: $*" >&2; exit 1; }
# Consumed by the extracted reader below, not by this file — hence the disable.
# shellcheck disable=SC2034
NEURALICE_CMDLINE_FILE="$CMDLINE"
# shellcheck source=/dev/null
source "$TMP/reader.sh"

set_cmdline() { printf '%s\n' "$*" > "$CMDLINE"; }

# --------------------------------------------------------------------------- #
# 1) ABSENT is empty, PRESENT ONCE is the value, PRESENT TWICE is a refusal.
# --------------------------------------------------------------------------- #
set_cmdline "quiet enforcing=0"
[ -z "$(karg_once neuralice.target)" ] || fail "an absent argument produced a value"

set_cmdline "quiet neuralice.target=/dev/nvme0n1 enforcing=0"
[ "$(karg_once neuralice.target)" = /dev/nvme0n1 ] || fail "a single argument was not read"

# 🔴 THE ATTACK. Appending a second `neuralice.target=` used to steer the wipe
# while every other gate still succeeded. Neither the first nor the last may win.
set_cmdline "neuralice.target=/dev/nvme0n1 quiet neuralice.target=/dev/sda"
( karg_once neuralice.target ) >/dev/null 2>&1 \
  && fail "a duplicated wipe target was resolved instead of refused"
set_cmdline "neuralice.target=/dev/sda quiet neuralice.target=/dev/nvme0n1"
( karg_once neuralice.target ) >/dev/null 2>&1 \
  && fail "a prepended duplicate wipe target was resolved instead of refused"

# Every security-relevant argument, both orders. A list is only a control if it
# is complete, so each one is exercised rather than assumed to share code.
for key in neuralice.target neuralice.imgref neuralice.osimage neuralice.mirror \
  neuralice.source neuralice.systemsize neuralice.sshkey; do
  set_cmdline "quiet ${key}=first ${key}=second"
  ( karg_once "$key" ) >/dev/null 2>&1 \
    && fail "a duplicated $key was resolved instead of refused"
  [ "$(karg_count "$key")" = 2 ] || fail "karg_count miscounted a duplicated $key"
  set_cmdline "quiet ${key}=only"
  [ "$(karg_once "$key")" = only ] || fail "$key was not read when present exactly once"
done

# A key that merely CONTAINS another key's name must not be counted as it: a
# substring match would make `neuralice.targetfoo=` shadow `neuralice.target=`.
set_cmdline "quiet neuralice.targeting=x neuralice.target=/dev/nvme0n1"
[ "$(karg_once neuralice.target)" = /dev/nvme0n1 ] \
  || fail "a similarly-named argument was confused with the real one"
# ...and a value that happens to contain the key name is still one occurrence.
set_cmdline "quiet neuralice.imgref=example.test/x:neuralice.imgref=y"
[ "$(karg_count neuralice.imgref)" = 1 ] \
  || fail "a value containing the key name was counted twice"

# --------------------------------------------------------------------------- #
# 2) THE INSTALLER MUST USE IT, and must not have kept a greedy reader anywhere.
# --------------------------------------------------------------------------- #
for key in neuralice.imgref neuralice.osimage neuralice.mirror neuralice.source \
  neuralice.systemsize neuralice.target; do
  grep -Fq "karg_once $key" "$AUTOINSTALL" \
    || fail "the installer does not read $key through the single-occurrence reader"
done
# The old shape, in any spelling, must be gone rather than merely unused.
grep -nE "sed -n 's/\.\*neuralice\\\\?\." "$AUTOINSTALL" \
  && fail "the installer still parses a kernel argument with a greedy sed"
grep -nE "grep -qE 'neuralice\\\\?\." "$AUTOINSTALL" \
  && fail "the installer still probes for a kernel argument with grep instead of counting it"

# --------------------------------------------------------------------------- #
# 3) THE VALUES ARE CONSTRAINED, not merely unique. A unique argument that names
#    something other than what a reader of the command line sees is the same
#    defect one step later.
# --------------------------------------------------------------------------- #
grep -Fq 'neuralice.target must name a plain block device under /dev' "$AUTOINSTALL" \
  || fail "the wipe target is not constrained to a plain /dev node"
grep -Fq 'neuralice.systemsize must be a whole number of GiB' "$AUTOINSTALL" \
  || fail "the system size interpolated into sfdisk is not constrained"
grep -Fq 'neuralice.imgref is not a usable image reference' "$AUTOINSTALL" \
  || fail "the recorded OTA origin is not constrained"

# All installer-created firstboot inputs are atomically published and fsynced
# before the recovery-key prompt can permit the first installed boot.
for required in \
  'persist_ceremony_input "$INTENDED_SRK_PUBLIC" srk-v1.tpm2b_public' \
  'persist_ceremony_input "$_intent_tmp" owner-ceremony-intent-v1' \
  'persist_ceremony_input "$_identity_tmp" owner-ceremony-install-identity-v1.json' \
  'sync -f "$ota_state/$_ceremony_input"' \
  'sync -f "$ota_state"'; do
  grep -Fq -- "$required" "$AUTOINSTALL" \
    || fail "the installed ceremony inputs are not durably published: $required"
done

echo "AUTOINSTALL_KARGS_TEST_OK"
