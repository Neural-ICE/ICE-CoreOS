#!/usr/bin/env bash
# Shared v2 owner-seal library (mission B, DESIGN-B §2; contract:
# docs/ota/V2-RELEASE-ATTESTATION.md, "Shell library"). SOURCED, never executed:
# by ota/neural-ice-autoinstall.sh (adapter A1), by the generic installer's
# install-host.sh (adapter A2, OS-0044) and, for v2seal_verify_retained, by the
# first-boot ceremony. It replaces the v1 preseal attestation for a host whose
# image marker is owner-sealed-ota-state-v2; it never touches the TPM objects'
# semantics (ota-tpm-state.sh / tpm-state.sh are called, not changed).
#
# Entry points (inputs are V2SEAL_* variables the caller sets; the full table, the
# outputs and the verifier flags each maps to are in the contract document):
#   v2seal_preflight        BEFORE any destructive write. Runs
#                           `ni-ota-verify verify-v2-release`; leaves
#                           V2SEAL_BUNDLE_SEQ and V2SEAL_RECEIPT_SHA256 and the
#                           receipt file named by V2SEAL_RECEIPT.
#   v2seal_commit           AFTER the deployment is written and mounted at
#                           V2SEAL_TARGET_ROOT. Persists the input directory and
#                           the receipt, re-verifies them against the target,
#                           byte-compares the receipt with the preflight one, runs
#                           `ota-tpm-state prepare "$V2SEAL_BUNDLE_SEQ"`, checks
#                           inspect-v2 (floor == bundle_seq, anchor pristine) and
#                           provisioning-status == preseal-prepared; leaves
#                           V2SEAL_RELEASE_IDENTITY_SHA256 (= manifest_sha256).
#   v2seal_verify_retained  Ceremony and every boot. Runs
#                           `ni-ota-verify verify-retained-v2-release` on the
#                           live root against the persisted pair and receipt.
#   v2seal_refusal MSG...   Prints "v2seal: refused: MSG" on stderr and EXITS 1.
#
# Exit codes (the verifier's, preseal.rs): 0 pass; 1 refusal; 2 internal error.
# Nothing else. A refusal is final: THERE IS NO RELAXED BRANCH. This library must
# never read the sealed-OTA-state posture variable (ADR-0050 lever B is a v1-only
# posture); test-neural-ice-v2-owner-seal.sh enforces it.
#
# Two additions to the T0 contract, both opt-in and neither changing an exit code:
#   * an optional hook `v2seal_on_refusal MSG`, called (and ignored if it fails)
#     just before a refusal or internal error exits, so a caller with its own
#     failure surface (the installer's evidence word and recovery line) is not
#     bypassed by the library's `exit`;
#   * V2SEAL_TARGET_OTA_DIR for v2seal_commit: the installed OTA state directory
#     (stateroot var/lib/neural-ice/ota), which on an ostree deployment is NOT
#     under V2SEAL_TARGET_ROOT (the deployment root the candidate markers are read
#     from).

# Idempotent: sourcing twice is a no-op.
[[ -z "${_V2SEAL_LIBRARY_LOADED:-}" ]] || return 0
_V2SEAL_LIBRARY_LOADED=1

_V2SEAL_MAX_SEQ=9007199254740991 # 2^53-1, the bound of ota-tpm-state.sh

# $1=exit code, rest=message. The only two ways out of this library.
_v2seal_exit() {
  local code=$1 prefix='v2seal: refused:'
  shift
  [[ "$code" == 1 ]] || prefix='v2seal: internal error:'
  printf '%s %s\n' "$prefix" "$*" >&2
  if declare -F v2seal_on_refusal >/dev/null 2>&1; then
    v2seal_on_refusal "$*" || true
  fi
  exit "$code"
}

v2seal_refusal() { _v2seal_exit 1 "$@"; }
_v2seal_internal() { _v2seal_exit 2 "$@"; }

# A path of the persisted layout (contract §5) and the live release key. Fixed
# production literals; the override exists for the suite only and is refused for a
# privileged process and on any release image, as ota/neural-ice-autoinstall.sh's
# ni_path is.
_v2seal_path() { # $1=override variable name $2=production value
  if [[ "${V2SEAL_TEST_SEAM:-}" == 1 && "$EUID" -ne 0 && ! -e /usr/lib/neural-ice/release-image \
        && -n "${!1:-}" ]]; then
    printf '%s' "${!1}"
  else
    printf '%s' "$2"
  fi
}

_v2seal_require() { # names... : unset or empty is a refusal, never a default
  local name
  for name in "$@"; do
    [[ -n "${!name:-}" ]] || v2seal_refusal "$name is unset or empty; this library never substitutes a default"
  done
}

_v2seal_require_hex64() {
  local name
  for name in "$@"; do
    [[ "${!name:-}" =~ ^[0-9a-f]{64}$ ]] || v2seal_refusal "$name is not a lowercase sha256"
  done
}

_v2seal_require_digest() {
  local name
  for name in "$@"; do
    [[ "${!name:-}" =~ ^sha256:[0-9a-f]{64}$ ]] || v2seal_refusal "$name is not a sha256:<64 lowercase hex> digest"
  done
}

_v2seal_seq_ok() { # $1=value -> 0 if an integer in 1..2^53-1
  [[ "$1" =~ ^[1-9][0-9]{0,15}$ ]] && (( $1 <= _V2SEAL_MAX_SEQ ))
}

_v2seal_require_file() { # $1=variable name holding a path: a plain regular file
  local path="${!1:-}"
  [[ -f "$path" && ! -L "$path" ]] || v2seal_refusal "$1 does not name a regular file"
}

_v2seal_require_private_dir() { # $1=path $2=description
  local mode owner
  [[ -d "$1" && ! -L "$1" ]] || v2seal_refusal "$2 is not a directory"
  mode="$(stat -c '%a' -- "$1")" || _v2seal_internal "cannot stat $2"
  owner="$(stat -c '%u' -- "$1")" || _v2seal_internal "cannot stat $2"
  [[ "$mode" == 700 && "$owner" == "$EUID" ]] \
    || v2seal_refusal "$2 is not a private (0700) directory owned by the caller"
}

_v2seal_sha256() { # $1=file -> hex
  local out
  out="$(sha256sum -- "$1")" || _v2seal_internal "cannot hash $1"
  printf '%s' "${out%% *}"
}

# The common verb inputs, validated; used by preflight and by commit's second
# verification so the two are the same question about different bytes.
_v2seal_require_seal_inputs() {
  _v2seal_require V2SEAL_OTA_VERIFY V2SEAL_MODE V2SEAL_RELEASE_KEY V2SEAL_KEY_SHA256 \
    V2SEAL_HARDWARE_TARGET V2SEAL_ACCESS_PROFILE V2SEAL_TRUST_POLICY_ID V2SEAL_VARIANT \
    V2SEAL_RELEASE_AUTHORITY V2SEAL_HOST_INDEX_DIGEST V2SEAL_HOST_MANIFEST_DIGEST
  [[ -x "$V2SEAL_OTA_VERIFY" && ! -d "$V2SEAL_OTA_VERIFY" ]] \
    || v2seal_refusal "V2SEAL_OTA_VERIFY is not an executable verifier"
  _v2seal_require_file V2SEAL_RELEASE_KEY
  _v2seal_require_hex64 V2SEAL_KEY_SHA256
  _v2seal_require_digest V2SEAL_HOST_INDEX_DIGEST V2SEAL_HOST_MANIFEST_DIGEST
  case "$V2SEAL_MODE" in
    manifest-digest)
      _v2seal_require V2SEAL_MANIFEST_SHA256 V2SEAL_MANIFEST_SIG_SHA256
      _v2seal_require_hex64 V2SEAL_MANIFEST_SHA256 V2SEAL_MANIFEST_SIG_SHA256
      [[ -z "${V2SEAL_MIN_BUNDLE_SEQ:-}" ]] \
        || v2seal_refusal "the manifest-digest mode carries no minimum bundle_seq; exactly one seal mode is accepted"
      ;;
    floor)
      _v2seal_require V2SEAL_MIN_BUNDLE_SEQ
      _v2seal_seq_ok "$V2SEAL_MIN_BUNDLE_SEQ" || v2seal_refusal "V2SEAL_MIN_BUNDLE_SEQ is not an integer in 1..2^53-1"
      [[ -z "${V2SEAL_MANIFEST_SHA256:-}" && -z "${V2SEAL_MANIFEST_SIG_SHA256:-}" ]] \
        || v2seal_refusal "the floor mode carries no sealed manifest digest; exactly one seal mode is accepted"
      ;;
    *) v2seal_refusal "V2SEAL_MODE is '${V2SEAL_MODE}', not manifest-digest or floor" ;;
  esac
}

# Runs verify-v2-release. $1=manifest $2=signature $3=candidate root $4=receipt
# path $5=where stdout/stderr scratch files go. On success sets
# _V2SEAL_VERIFIED_SEQ, _V2SEAL_VERIFIED_IDEMPOTENT and _V2SEAL_VERIFIED_SHA256.
_v2seal_run_verify() {
  local manifest=$1 signature=$2 candidate=$3 receipt=$4 scratch=$5
  local -a command=("$V2SEAL_OTA_VERIFY" verify-v2-release
    --manifest "$manifest" --manifest-sig "$signature"
    --release-key "$V2SEAL_RELEASE_KEY" --sealed-key-sha256 "$V2SEAL_KEY_SHA256")
  if [[ "$V2SEAL_MODE" == manifest-digest ]]; then
    command+=(--sealed-manifest-sha256 "$V2SEAL_MANIFEST_SHA256"
      --sealed-manifest-sig-sha256 "$V2SEAL_MANIFEST_SIG_SHA256")
  else
    command+=(--sealed-min-bundle-seq "$V2SEAL_MIN_BUNDLE_SEQ")
  fi
  command+=(--hardware-target "$V2SEAL_HARDWARE_TARGET" --access-profile "$V2SEAL_ACCESS_PROFILE"
    --trust-policy-id "$V2SEAL_TRUST_POLICY_ID" --variant "$V2SEAL_VARIANT"
    --release-authority "$V2SEAL_RELEASE_AUTHORITY" --candidate-root "$candidate"
    --host-index-digest "$V2SEAL_HOST_INDEX_DIGEST" --host-manifest-digest "$V2SEAL_HOST_MANIFEST_DIGEST"
    --receipt "$receipt")
  _v2seal_run_checked "$scratch" "${command[@]}"
  [[ "$_V2SEAL_STDOUT" =~ ^\{\"bundle_seq\":([1-9][0-9]*),\"idempotent\":(true|false),\"receipt_sha256\":\"([0-9a-f]{64})\",\"verdict\":\"pass\"\}$ ]] \
    || v2seal_refusal "the release verifier's stdout is not its contract line"
  _V2SEAL_VERIFIED_SEQ="${BASH_REMATCH[1]}"
  _V2SEAL_VERIFIED_IDEMPOTENT="${BASH_REMATCH[2]}"
  _V2SEAL_VERIFIED_SHA256="${BASH_REMATCH[3]}"
  _v2seal_seq_ok "$_V2SEAL_VERIFIED_SEQ" || v2seal_refusal "the release verifier reported a bundle_seq outside 1..2^53-1"
  [[ -f "$receipt" && ! -L "$receipt" ]] || v2seal_refusal "the release verifier passed without leaving its receipt"
  (( "$(wc -c < "$receipt")" <= 4096 )) || v2seal_refusal "the receipt exceeds its 4 KiB bound"
  [[ "$(_v2seal_sha256 "$receipt")" == "$_V2SEAL_VERIFIED_SHA256" ]] \
    || v2seal_refusal "the receipt on disk is not the one the verifier reported"
}

# $1=scratch dir, rest=command. stdout -> _V2SEAL_STDOUT; stderr passes through
# (and is kept in $1/verify.err). Exit mapping is the verifier's: 0 pass, 1
# refusal, anything else (2, a signal, a missing binary) internal.
_v2seal_run_checked() {
  local scratch=$1 rc=0
  shift
  _V2SEAL_STDOUT="$("$@" 2>"$scratch/verify.err")" || rc=$?
  [[ ! -s "$scratch/verify.err" ]] || cat -- "$scratch/verify.err" >&2
  case "$rc" in
    0) ;;
    1) v2seal_refusal "the release verifier refused: $(head -n 1 -- "$scratch/verify.err" 2>/dev/null)" ;;
    *) _v2seal_internal "the release verifier failed with status $rc" ;;
  esac
}

v2seal_preflight() {
  _v2seal_require V2SEAL_MANIFEST V2SEAL_MANIFEST_SIG V2SEAL_CANDIDATE_ROOT V2SEAL_WORK V2SEAL_RECEIPT
  _v2seal_require_seal_inputs
  _v2seal_require_file V2SEAL_MANIFEST
  _v2seal_require_file V2SEAL_MANIFEST_SIG
  [[ -d "$V2SEAL_CANDIDATE_ROOT" ]] || v2seal_refusal "V2SEAL_CANDIDATE_ROOT is not a directory"
  _v2seal_require_private_dir "$V2SEAL_WORK" "V2SEAL_WORK"
  [[ "$V2SEAL_RECEIPT" == "$V2SEAL_WORK"/* && "$V2SEAL_RECEIPT" != *..* ]] \
    || v2seal_refusal "V2SEAL_RECEIPT is not under V2SEAL_WORK"
  _v2seal_run_verify "$V2SEAL_MANIFEST" "$V2SEAL_MANIFEST_SIG" "$V2SEAL_CANDIDATE_ROOT" \
    "$V2SEAL_RECEIPT" "$V2SEAL_WORK"
  _v2seal_cross_check_receipt "$V2SEAL_RECEIPT" "$_V2SEAL_VERIFIED_SEQ"
  V2SEAL_BUNDLE_SEQ="$_V2SEAL_VERIFIED_SEQ"
  V2SEAL_RECEIPT_SHA256="$_V2SEAL_VERIFIED_SHA256"
}

# The receipt is canonical JSON (sorted keys, compact): read the two fields this
# library relies on by their exact bytes, and refuse a verifier whose stdout and
# receipt disagree. $1=receipt $2=bundle_seq the verifier reported.
_v2seal_cross_check_receipt() {
  local text
  text="$(cat -- "$1")" || _v2seal_internal "cannot read the receipt"
  [[ "$text" == *"\"bundle_seq\":$2,"* ]] \
    || v2seal_refusal "the receipt's bundle_seq is not the one the verifier reported"
  if [[ "$V2SEAL_MODE" == manifest-digest ]]; then
    [[ "$text" == *"\"manifest_sha256\":\"$V2SEAL_MANIFEST_SHA256\""* ]] \
      || v2seal_refusal "the receipt does not name the manifest this medium seals"
  fi
}

_v2seal_byte_equal_file() { # $1=source $2=existing destination: a plain regular file with the same bytes
  [[ -f "$2" && ! -L "$2" ]] || return 1
  cmp -s -- "$1" "$2"
}

# Create-if-absent by hard link of a private staged file; byte-equal otherwise.
_v2seal_publish() { # $1=source $2=destination
  local tmp
  if [[ -e "$2" || -L "$2" ]]; then
    _v2seal_byte_equal_file "$1" "$2" \
      || v2seal_refusal "$2 already exists and is not byte-equal to the attested file; never overwritten"
    return 0
  fi
  tmp="$(mktemp "$(dirname -- "$2")/.v2seal.XXXXXX")" || _v2seal_internal "cannot stage $2"
  install -m 0600 -- "$1" "$tmp" || { rm -f -- "$tmp"; _v2seal_internal "cannot stage $2"; }
  sync -f "$tmp" || { rm -f -- "$tmp"; _v2seal_internal "cannot fsync the staged $2"; }
  if ! ln -- "$tmp" "$2" 2>/dev/null; then
    rm -f -- "$tmp"
    _v2seal_byte_equal_file "$1" "$2" \
      || v2seal_refusal "$2 appeared during publication and is not byte-equal; never overwritten"
    return 0
  fi
  rm -f -- "$tmp"
}

_v2seal_make_private_dir() { # $1=path
  if [[ -e "$1" || -L "$1" ]]; then
    _v2seal_require_private_dir "$1" "$1"
  else
    install -d -m 0700 -- "$1" || _v2seal_internal "cannot create $1"
  fi
}

# The closed public contract of `ota-tpm-state inspect-v2` after `prepare`: the
# floor written, the anchor pristine, no Clear protection yet. These constants are
# the TPM objects' own (ota-tpm-state.sh) and are identical to the v1 lane's
# check in ota/neural-ice-autoinstall.sh; test-neural-ice-v2-owner-seal.sh
# asserts the two copies are the same bytes.
_v2seal_check_inspection() { # $1=inspect-v2 JSON $2=bundle_seq
  python3 -I - "$1" "$2" <<'V2SEAL_INSPECTION_PY' || return 1
import json
import sys

def closed_pairs(items):
    result = {}
    for key, item in items:
        if key in result:
            raise ValueError(f"duplicate field: {key}")
        result[key] = item
    return result

value = json.loads(sys.argv[1], object_pairs_hook=closed_pairs)
expected = {
    "anchor_attributes": "0x2060048",
    "anchor_index": "0x01500002",
    "anchor_name": "000b038de2091c1c8ef2e8fd8869f17bef3a576ae287530fa17f05ae3b9712014b5d",
    "anchor_policy_sha256": "b6a2e7142ee56fd978047488483daa5b42b8dc4cc7ddcceddfb91793cf1ff1b7",
    "anchor_sha256": None,
    "anchor_size": 32,
    "anchor_state": "pristine",
    "baseline_floor": int(sys.argv[2]),
    "clear_protected": False,
    "floor_attributes": "0x62008",
    "floor_index": "0x01500001",
    "floor_name": "000be283f20a38b93f8cef085efb4aee9f5944cc3b3b28b850bf3c0eeb2054cd7fc4",
    "floor_policy_sha256": "f83217e5a2a04342f7daa55ccfb3cd4b8a1f1e8ebb28c7719a9abbdbd638a230",
    "floor_size": 8,
    "owner_sealed": False,
    "profile": "owner-sealed-ota-state-v1",
    "schema": "neural-ice-owner-ota-state-inspection-v2",
}
if value != expected:
    raise SystemExit(1)
V2SEAL_INSPECTION_PY
}

v2seal_commit() {
  local ota_dir input_dir receipt_dir persisted_manifest persisted_sig persisted_receipt inspection file
  _v2seal_require V2SEAL_MANIFEST V2SEAL_MANIFEST_SIG V2SEAL_RECEIPT V2SEAL_BUNDLE_SEQ \
    V2SEAL_RECEIPT_SHA256 V2SEAL_WORK V2SEAL_TARGET_ROOT V2SEAL_TARGET_OTA_DIR V2SEAL_OTA_TPM_STATE V2SEAL_TPM_STATE
  _v2seal_require_seal_inputs
  _v2seal_require_hex64 V2SEAL_RECEIPT_SHA256
  _v2seal_seq_ok "$V2SEAL_BUNDLE_SEQ" || v2seal_refusal "V2SEAL_BUNDLE_SEQ is not an integer in 1..2^53-1"
  _v2seal_require_file V2SEAL_MANIFEST
  _v2seal_require_file V2SEAL_MANIFEST_SIG
  _v2seal_require_file V2SEAL_RECEIPT
  _v2seal_require_private_dir "$V2SEAL_WORK" "V2SEAL_WORK"
  [[ -d "$V2SEAL_TARGET_ROOT" && -d "$V2SEAL_TARGET_OTA_DIR" && ! -L "$V2SEAL_TARGET_OTA_DIR" ]] \
    || v2seal_refusal "the target root or its OTA state directory is not a directory"
  [[ -x "$V2SEAL_OTA_TPM_STATE" && -x "$V2SEAL_TPM_STATE" ]] \
    || v2seal_refusal "the owner OTA-state or TPM-state helper is not executable"
  # The preflight receipt is the reference of every later comparison: it must
  # still be exactly what the preflight authenticated.
  [[ "$(_v2seal_sha256 "$V2SEAL_RECEIPT")" == "$V2SEAL_RECEIPT_SHA256" ]] \
    || v2seal_refusal "the pre-wipe receipt changed between the preflight and the commit"

  ota_dir="$V2SEAL_TARGET_OTA_DIR"
  input_dir="$ota_dir/v2-release-input-v1"
  receipt_dir="$ota_dir/v2-release"
  persisted_manifest="$input_dir/release-manifest.json"
  persisted_sig="$input_dir/release-manifest.json.sig"
  persisted_receipt="$receipt_dir/receipt.json"
  _v2seal_make_private_dir "$input_dir"
  _v2seal_make_private_dir "$receipt_dir"
  _v2seal_publish "$V2SEAL_MANIFEST" "$persisted_manifest"
  _v2seal_publish "$V2SEAL_MANIFEST_SIG" "$persisted_sig"

  # Re-authenticate the PERSISTED bytes against the DEPLOYED candidate. The
  # shipped verifier has no live-root seam (verify-retained-v2-release reads /),
  # so the second pass is the same verb over the persisted pair and the
  # deployment root; the receipt it publishes is byte-compared with the
  # pre-wipe one.
  _v2seal_run_verify "$persisted_manifest" "$persisted_sig" "$V2SEAL_TARGET_ROOT" \
    "$persisted_receipt" "$V2SEAL_WORK"
  [[ "$_V2SEAL_VERIFIED_SEQ" == "$V2SEAL_BUNDLE_SEQ" && "$_V2SEAL_VERIFIED_SHA256" == "$V2SEAL_RECEIPT_SHA256" ]] \
    || v2seal_refusal "the deployed candidate re-authenticates to a different bundle_seq or receipt than the pre-wipe one"
  cmp -- "$V2SEAL_RECEIPT" "$persisted_receipt" \
    || v2seal_refusal "the installed v2 receipt differs from the authenticated pre-wipe receipt"
  [[ "$(_v2seal_sha256 "$persisted_manifest")" == "$(_v2seal_sha256 "$V2SEAL_MANIFEST")" ]] \
    || v2seal_refusal "the persisted manifest is not the attested one"
  V2SEAL_RELEASE_IDENTITY_SHA256="$(_v2seal_sha256 "$persisted_manifest")"
  if [[ "$V2SEAL_MODE" == manifest-digest && "$V2SEAL_RELEASE_IDENTITY_SHA256" != "$V2SEAL_MANIFEST_SHA256" ]]; then
    v2seal_refusal "the persisted manifest is not the one this medium seals"
  fi

  # Only now is the TPM touched: floor = the signed manifest's bundle_seq.
  [[ "$("$V2SEAL_OTA_TPM_STATE" prepare "$V2SEAL_BUNDLE_SEQ")" == prepared ]] \
    || v2seal_refusal "cannot prepare the owner-sealed OTA baseline state"
  inspection="$("$V2SEAL_OTA_TPM_STATE" inspect-v2)" \
    || v2seal_refusal "cannot inspect the prepared owner-sealed OTA baseline state"
  _v2seal_check_inspection "$inspection" "$V2SEAL_BUNDLE_SEQ" \
    || v2seal_refusal "the prepared owner-sealed OTA baseline state differs from its closed public contract"
  [[ "$("$V2SEAL_TPM_STATE" provisioning-status)" == preseal-prepared ]] \
    || v2seal_refusal "the complete TPM state is not the exact preseal-prepared lifecycle checkpoint"

  for file in "$persisted_manifest" "$persisted_sig" "$persisted_receipt"; do
    [[ -f "$file" && ! -L "$file" ]] || v2seal_refusal "an installed v2 release file is no longer a regular file"
    sync -f "$file" || _v2seal_internal "cannot fsync an installed v2 release file"
  done
  for file in "$input_dir" "$receipt_dir" "$ota_dir"; do
    sync -f "$file" || _v2seal_internal "cannot fsync an installed v2 release directory"
  done
}

v2seal_verify_retained() {
  local ota_dir key manifest signature receipt file seq vouched
  _v2seal_require V2SEAL_OTA_VERIFY V2SEAL_EXPECTED_RECEIPT_SHA256 V2SEAL_SCRATCH_DIR
  [[ -x "$V2SEAL_OTA_VERIFY" && ! -d "$V2SEAL_OTA_VERIFY" ]] \
    || v2seal_refusal "V2SEAL_OTA_VERIFY is not an executable verifier"
  _v2seal_require_hex64 V2SEAL_EXPECTED_RECEIPT_SHA256
  _v2seal_require_private_dir "$V2SEAL_SCRATCH_DIR" "V2SEAL_SCRATCH_DIR"
  ota_dir="$(_v2seal_path V2SEAL_PERSIST_DIR /var/lib/neural-ice/ota)"
  key="$(_v2seal_path V2SEAL_RETAINED_KEY /usr/lib/neural-ice/keys/release-authorization.pub)"
  manifest="$ota_dir/v2-release-input-v1/release-manifest.json"
  signature="$ota_dir/v2-release-input-v1/release-manifest.json.sig"
  receipt="$ota_dir/v2-release/receipt.json"
  for file in "$manifest" "$signature" "$receipt" "$key"; do
    [[ -f "$file" && ! -L "$file" ]] || v2seal_refusal "the persisted v2 release attestation is incomplete: $file"
  done
  _v2seal_run_checked "$V2SEAL_SCRATCH_DIR" "$V2SEAL_OTA_VERIFY" verify-retained-v2-release \
    --manifest "$manifest" --manifest-sig "$signature" --release-key "$key" \
    --expected-receipt-sha256 "$V2SEAL_EXPECTED_RECEIPT_SHA256" --receipt "$receipt" \
    --scratch-dir "$V2SEAL_SCRATCH_DIR"
  [[ "$_V2SEAL_STDOUT" =~ ^\{\"bundle_seq\":([1-9][0-9]*),\"receipt_sha256\":\"([0-9a-f]{64})\",\"verdict\":\"pass\"\}$ ]] \
    || v2seal_refusal "the retained-release verifier's stdout is not its contract line"
  seq="${BASH_REMATCH[1]}"
  vouched="${BASH_REMATCH[2]}"
  _v2seal_seq_ok "$seq" || v2seal_refusal "the retained-release verifier reported a bundle_seq outside 1..2^53-1"
  [[ "$vouched" == "$V2SEAL_EXPECTED_RECEIPT_SHA256" ]] \
    || v2seal_refusal "the retained-release verifier vouched for another receipt than the one expected"
  V2SEAL_BUNDLE_SEQ="$seq"
}
