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
{
  awk '/^karg_count\(\) \{/,/^}$/' "$AUTOINSTALL"
  awk '/^karg_once\(\) \{/,/^}$/' "$AUTOINSTALL"
  awk '/^candidate_ota_state_profile\(\) \{/,/^}$/' "$AUTOINSTALL"
  awk '/^require_medium_source_profile\(\) \{/,/^}$/' "$AUTOINSTALL"
  awk '/^verify_installed_preseal_candidate\(\) \{/,/^}$/' "$AUTOINSTALL"
} > "$TMP/reader.sh"
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

# The medium source has no authenticated eight-file transport. Its historical
# unmarked image remains supported, while an owner-profile or malformed marker
# refuses before the first destructive call. Exercise the production helpers;
# the marker is read from the real usr/lib layout of a mounted candidate.
medium_root="$TMP/medium-root"
mkdir -p "$medium_root/usr/lib/neural-ice"
destructive="$TMP/destructive-called"
medium_attempt() (
  profile="$(candidate_ota_state_profile "$medium_root")" || exit 1
  require_medium_source_profile "$profile"
  : > "$destructive"
)
medium_attempt || fail "the historical unmarked medium source was refused"
[[ -e "$destructive" ]] || fail "the admitted legacy medium did not reach the synthetic destructive boundary"
rm -f "$destructive"
printf '%s\n' owner-sealed-ota-state-v1 > "$medium_root/usr/lib/neural-ice/ota-state-profile"
medium_attempt >/dev/null 2>&1 && fail "an owner-profile medium without preseal transport was admitted"
[[ ! -e "$destructive" ]] || fail "an owner-profile medium reached the destructive boundary"
printf '%s\n' owner-sealed-ota-state-v1 malformed > "$medium_root/usr/lib/neural-ice/ota-state-profile"
medium_attempt >/dev/null 2>&1 && fail "a malformed medium OTA-state profile was admitted"
[[ ! -e "$destructive" ]] || fail "a malformed medium profile reached the destructive boundary"

# The post-bootc verifier consumes the resolved deployment root, not the
# /var/tmp/nitarget OSTree sysroot. Make the distinction executable with the
# actual directory shape and marker locations the Rust verifier reads.
TGT="$TMP/nitarget"
dep="$TGT/ostree/deploy/neuralice/deploy/0123456789abcdef.0"
mkdir -p "$dep/usr/lib/neural-ice/product-payload"
printf '%s\n' owner-sealed-ota-state-v1 > "$dep/usr/lib/neural-ice/ota-state-profile"
printf '%040d\n' 6 > "$dep/usr/lib/neural-ice/product-payload/PAYLOAD_ID"
verify_preseal_candidate() {
  [[ "$1" == "$TMP/installed-inputs" \
     && "$2" == "$dep" \
     && "$(cat "$2/usr/lib/neural-ice/ota-state-profile")" == owner-sealed-ota-state-v1 \
     && "$(cat "$2/usr/lib/neural-ice/product-payload/PAYLOAD_ID")" == "$(printf '%040d' 6)" \
     && "$3" == "$(printf '%040d' 6)" \
     && "$4" == "$TMP/installed.conf" \
     && "$5" == "$TMP/receipt.json" ]] || return 1
  printf '%s\n' 7
}
[[ "$(verify_installed_preseal_candidate "$TMP/installed-inputs" \
  "$(printf '%040d' 6)" "$TMP/installed.conf" "$TMP/receipt.json")" == 7 ]] \
  || fail "the installed preseal verifier did not receive the resolved OSTree deployment root"

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
  neuralice.source neuralice.systemsize neuralice.sshkey neuralice.preseal; do
  set_cmdline "quiet ${key}=first ${key}=second"
  ( karg_once "$key" ) >/dev/null 2>&1 \
    && fail "a duplicated $key was resolved instead of refused"
  [ "$(karg_count "$key")" = 2 ] || fail "karg_count miscounted a duplicated $key"
  set_cmdline "quiet ${key}=only"
  [ "$(karg_once "$key")" = only ] || fail "$key was not read when present exactly once"
done

# Owner-profile installs carry eight authenticated inputs across the wipe. The
# snapshot and the complete cryptographic candidate proof must both precede the
# first destructive command; post-bootc only the same protected bytes may be
# published and reverified before TPM NV preparation.
line_of() { grep -nF -- "$1" "$AUTOINSTALL" | head -1 | cut -d: -f1 || true; }
preseal_snapshot_line="$(line_of 'snapshot_preseal_from_esp "$PRESEAL_SNAPSHOT"')"
preseal_preflight_line="$(line_of 'PRESEAL_BUNDLE_SEQ="$(verify_preseal_candidate "$PRESEAL_SNAPSHOT"')"
medium_profile_gate_line="$(line_of 'require_medium_source_profile "$_medium_ota_profile"')"
wipe_line="$(grep -nE '^[[:space:]]*wipefs -a "\$target"' "$AUTOINSTALL" | head -1 | cut -d: -f1)"
bootc_line="$(awk '$1 == "bootc" && $2 == "install" && $3 == "to-filesystem" { print NR; exit }' "$AUTOINSTALL")"
handoff_line="$(line_of '"$PRESEAL_HANDOFF" install-persistent')"
installed_verify_line="$(line_of '_installed_preseal_floor="$(verify_installed_preseal_candidate "$PRESEAL_INSTALLED_INPUTS"')"
prepare_line="$(line_of '"$OTA_TPM_STATE" prepare "$PRESEAL_BUNDLE_SEQ"')"
inspect_line="$(line_of '"$OTA_TPM_STATE" inspect-v2')"
status_line="$(line_of '"$TPM_STATE" provisioning-status)" == preseal-prepared')"
[[ -n "$preseal_snapshot_line" && -n "$preseal_preflight_line" \
   && -n "$medium_profile_gate_line" && -n "$wipe_line" \
   && -n "$bootc_line" && -n "$handoff_line" && -n "$installed_verify_line" \
   && -n "$prepare_line" && -n "$inspect_line" && -n "$status_line" \
   && "$preseal_snapshot_line" -lt "$preseal_preflight_line" \
   && "$preseal_preflight_line" -lt "$wipe_line" \
   && "$medium_profile_gate_line" -lt "$wipe_line" \
   && "$wipe_line" -lt "$bootc_line" && "$bootc_line" -lt "$handoff_line" \
   && "$handoff_line" -lt "$installed_verify_line" \
   && "$installed_verify_line" -lt "$prepare_line" \
   && "$prepare_line" -lt "$inspect_line" && "$inspect_line" -lt "$status_line" ]] \
  || fail "the authenticated eight-input preseal handoff is not ordered around the wipe and bootc install"

for required in \
  'the selected owner-sealed appliance has no UKI-bound preseal inputs' \
  'the selected legacy appliance cannot consume this medium' \
  'the UKI-bound preseal inputs do not authenticate the selected appliance before disk mutation' \
  '--current-os-ref "$OS_IMAGE"' \
  '--current-os-manifest-digest "$got_manifest"' \
  '--current-seed-ref "$current_seed"' \
  '--candidate-root "$candidate_root"' \
  '"$PRESEAL_HANDOFF" verify-persistent' \
  'cmp -- "$PRESEAL_PREFLIGHT_RECEIPT" "$PRESEAL_INSTALLED_RECEIPT"' \
  'sync -f "$PRESEAL_INSTALLED_INPUTS"' \
  'sync -f "$ota_state"' \
  'the complete TPM state is not the exact preseal-prepared lifecycle checkpoint'; do
  grep -Fq -- "$required" "$AUTOINSTALL" \
    || fail "the owner-profile preseal contract is incomplete: $required"
done
unset -f line_of

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
# 🔴 ONE CANONICAL ORIGIN, NO DEFAULT (independent review 2026-09-02, P0 #3).
# The compiled-in fallback was `ghcr.io/neural-ice/neural-ice-coreos:stable` -- a
# MUTABLE TAG on a registry that is not the release authority -- and an appliance
# whose medium sealed no origin followed it for its whole life. Both halves are
# asserted: the constraint exists, and the fallback is gone.
grep -Fq 'the OTA origin must be <sealed release authority>/<repo>@sha256:<digest>' "$AUTOINSTALL" \
  || fail "the recorded OTA origin is not constrained to the sealed digest-pinned authority"
# 🔴 AND THE AUTHORITY IS NOT A LITERAL IN THIS TREE. ICE-CoreOS is open core;
# ci/test-open-core-boundary.sh refuses the sovereign endpoint's bytes in every
# Git-visible file. The authority therefore arrives on the SIGNED command line,
# which is stronger than a constant: it is one value the signature covers rather
# than one a fork can edit.
grep -Fq 'NEURALICE_RELEASE_AUTHORITY="$(karg_once neuralice.release_authority)"' "$AUTOINSTALL" \
  || fail "the installer no longer reads its release authority from the sealed command line"
grep -Fq 'refusing to install an appliance with no update path rather than inventing a default' "$AUTOINSTALL" \
  || fail "the installer still invents an OTA origin when the medium seals none"
grep -vE '^[[:space:]]*#' "$AUTOINSTALL" | grep -Fq 'ghcr.io' \
  && fail "the installer still carries a GHCR reference outside its comments"
grep -Fq 'DEVICE_CHANNEL="$(karg_once neuralice.device_channel)"' "$AUTOINSTALL" \
  || fail "the installer does not consume the device channel sealed by the UKI"
grep -Fq 'printf '\''%s\n'\'' "$DEVICE_CHANNEL" > /run/seed-dst/release/CHANNEL' "$AUTOINSTALL" \
  || fail "the verified seed handoff does not retain its signed device channel"

# Literal current PCR7 is forbidden. The TPM slot must use PolicyAuthorize,
# with the policy generation sealed in the UKI and checked before disk mutation.
grep -vE '^[[:space:]]*#' "$AUTOINSTALL" | grep -Fq -- '--tpm2-pcrs=7' \
  && fail "the installer still seals LUKS to the mutable current PCR7 value"
for required in '--tpm2-pcrs=' '--tpm2-public-key="$PCR_POLICY_KEY_RUNTIME"' \
  '--tpm2-public-key-pcrs=7' 'karg_once neuralice.pcr_policy_seq' \
  'esp_staged_file tpm2-pcr-signature.json'; do
  grep -Fq -- "$required" "$AUTOINSTALL" \
    || fail "the signed PCR policy install gate is incomplete: $required"
done

# The live value is converted with the same immutable helper that authors
# policies, and every failure reaches one stable field diagnostic. Functional
# covered/uncovered/malformed tests and destructive-order proof live in the
# focused suite wired beside this one.
grep -Fq '"$TPM_POLICY_TOOL" --pcr 7 --alg sha256 verify-live-coverage' "$AUTOINSTALL" \
  || fail "the installer does not use the authoritative helper for live PCR7 coverage"
grep -Fq 'NI-P7-COVERAGE: live SHA-256 PCR7 is unreadable, malformed, unsigned, signed by another key, or uncovered' "$AUTOINSTALL" \
  || fail "the live PCR7 refusal has no stable diagnostic"

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
