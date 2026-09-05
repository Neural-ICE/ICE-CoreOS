#!/usr/bin/env bash
# Fresh-install OTA state primitives for the owner-sealed NV profile.
#
# This helper deliberately has no release, licensing, or baseline authority. A
# future pre-seal caller must authenticate those inputs before invoking prepare.
# Here we only create and attest the two fixed TPM public areas, set clear
# protection, and extend the runtime anchor. There is no repair, undefine,
# reset, Clear, hierarchy-auth change, or applied-state writer in this file.
set -euo pipefail
umask 077

readonly FLOOR_INDEX=0x01500001
readonly ANCHOR_INDEX=0x01500002
readonly MAX_SAFE_INTEGER=9007199254740991

readonly FLOOR_ATTRIBUTES=0x62008
readonly ANCHOR_ATTRIBUTES=0x2060048
readonly ATTRIBUTE_DYNAMIC_MASK=$(( 0x30000800 ))
readonly NV_WRITELOCKED=$(( 0x800 ))
readonly NV_WRITTEN=$(( 0x20000000 ))
readonly FLOOR_COMPLETE_BITS=$(( NV_WRITELOCKED | NV_WRITTEN ))

readonly POLICY_WRITE_BRANCH=1c4f7107dcaf23ce00756448508558683104bd9e203e93749c227b451270438f
readonly POLICY_WRITELOCK_BRANCH=c8905eb3b7302fc69bb1a52843b142f3e2faf66386f04f89b86cf6399b30e301
readonly POLICY_FLOOR=f83217e5a2a04342f7daa55ccfb3cd4b8a1f1e8ebb28c7719a9abbdbd638a230
readonly POLICY_EXTEND=b6a2e7142ee56fd978047488483daa5b42b8dc4cc7ddcceddfb91793cf1ff1b7

# These are TPM-computed Names for the complete public areas above. Dynamic
# WRITTEN/WRITELOCKED bits are part of a Name, hence the two anchor states.
readonly FLOOR_NAME=000be283f20a38b93f8cef085efb4aee9f5944cc3b3b28b850bf3c0eeb2054cd7fc4
readonly ANCHOR_PRISTINE_NAME=000b038de2091c1c8ef2e8fd8869f17bef3a576ae287530fa17f05ae3b9712014b5d
readonly ANCHOR_WRITTEN_NAME=000b11afd155aca82a503f2029cc11395389654c3a25fc54b9eca6d33abdff498d56

die() { printf 'neural-ice-ota-tpm-state: refused: %s\n' "$*" >&2; exit 1; }

if [[ -n "${NI_OTA_TPM_STATE_TEST_TOOLS:-}" ]]; then
  [[ "${NI_OTA_TPM_STATE_TESTING:-}" == 1 && "$EUID" -ne 0 ]] \
    || die "test tool override is forbidden in a privileged process"
  [[ ! -e /usr/lib/neural-ice/release-image ]] \
    || die "test tool override is forbidden in a release image"
  readonly TOOL_DIR="$NI_OTA_TPM_STATE_TEST_TOOLS"
  readonly RUN_DIR="${NI_OTA_TPM_STATE_TEST_RUN_DIR:?test run directory is required}"
else
  [[ "$EUID" -eq 0 ]] || die "must run as root"
  readonly TOOL_DIR=/usr/bin
  readonly RUN_DIR=/run/neural-ice-ota-tpm-state
fi

if [[ -n "${NI_OTA_TPM_STATE_TEST_TOOLS:-}" ]]; then
  NV_PUBLIC_PARSER="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/../image/lib/tpm2-nv-public.sh"
else
  NV_PUBLIC_PARSER=/usr/lib/neural-ice/lib/tpm2-nv-public.sh
fi
readonly NV_PUBLIC_PARSER
[[ -r "$NV_PUBLIC_PARSER" ]] || die "the TPM public-area parser is unavailable"
# shellcheck source=image/lib/tpm2-nv-public.sh
source "$NV_PUBLIC_PARSER"

tool() {
  local path="$TOOL_DIR/$1"
  [[ -x "$path" ]] || die "required tool is unavailable: $path"
  printf '%s' "$path"
}

SESSION=""
WORK=""
session_close() {
  if [[ -n "$SESSION" ]]; then
    "$(tool tpm2_flushcontext)" "$SESSION" >/dev/null 2>&1 || true
    SESSION=""
  fi
}

with_workspace() {
  install -d -m 0700 "$RUN_DIR"
  exec 9>"$RUN_DIR/operation.lock"
  "$(tool flock)" -x 9
  WORK="$(mktemp -d "$RUN_DIR/work.XXXXXX")"
  trap 'session_close; rm -rf -- "$WORK"' EXIT
}

hex_of() { od -An -tx1 -v "$1" | tr -d '[:space:]' | tr 'A-F' 'a-f'; }

trial_command_code() {
  local command_code=$1 output=$2 trial="$WORK/trial.ctx"
  "$(tool tpm2_startauthsession)" -S "$trial" >/dev/null 2>&1 \
    || die "the TPM refused a trial policy session"
  "$(tool tpm2_policycommandcode)" -S "$trial" -L "$output" "$command_code" \
    >/dev/null 2>&1 || {
      "$(tool tpm2_flushcontext)" "$trial" >/dev/null 2>&1 || true
      die "the TPM refused PolicyCommandCode($command_code) derivation"
    }
  "$(tool tpm2_flushcontext)" "$trial" >/dev/null 2>&1 || true
}

compute_policies() {
  trial_command_code TPM2_CC_NV_Write "$WORK/write.digest"
  trial_command_code TPM2_CC_NV_WriteLock "$WORK/writelock.digest"
  trial_command_code TPM2_CC_NV_Extend "$WORK/extend.digest"
  local trial="$WORK/or.ctx"
  "$(tool tpm2_startauthsession)" -S "$trial" >/dev/null 2>&1 \
    || die "the TPM refused a trial PolicyOR session"
  "$(tool tpm2_policyor)" -S "$trial" -L "$WORK/floor.digest" \
    "sha256:$WORK/write.digest,$WORK/writelock.digest" >/dev/null 2>&1 || {
      "$(tool tpm2_flushcontext)" "$trial" >/dev/null 2>&1 || true
      die "the TPM refused the floor PolicyOR derivation"
    }
  "$(tool tpm2_flushcontext)" "$trial" >/dev/null 2>&1 || true

  [[ "$(hex_of "$WORK/write.digest")" == "$POLICY_WRITE_BRANCH" ]] \
    || die "PolicyCommandCode(NV_Write) is not the documented digest"
  [[ "$(hex_of "$WORK/writelock.digest")" == "$POLICY_WRITELOCK_BRANCH" ]] \
    || die "PolicyCommandCode(NV_WriteLock) is not the documented digest"
  [[ "$(hex_of "$WORK/floor.digest")" == "$POLICY_FLOOR" ]] \
    || die "the floor PolicyOR is not the documented digest"
  [[ "$(hex_of "$WORK/extend.digest")" == "$POLICY_EXTEND" ]] \
    || die "PolicyCommandCode(NV_Extend) is not the documented digest"
}

session_for() {
  local command_code=$1 mode=$2
  session_close
  SESSION="$WORK/session.ctx"
  "$(tool tpm2_startauthsession)" --policy-session -S "$SESSION" >/dev/null 2>&1 \
    || { SESSION=""; die "the TPM refused a policy session"; }
  "$(tool tpm2_policycommandcode)" -S "$SESSION" "$command_code" >/dev/null 2>&1 \
    || die "the TPM refused PolicyCommandCode($command_code)"
  if [[ "$mode" == or ]]; then
    "$(tool tpm2_policyor)" -S "$SESSION" \
      "sha256:$WORK/write.digest,$WORK/writelock.digest" >/dev/null 2>&1 \
      || die "the TPM refused the floor PolicyOR"
  fi
}

permanent_property() {
  local name=$1 properties value
  properties="$("$(tool tpm2_getcap)" properties-variable 2>/dev/null)" \
    || die "the TPM will not report its permanent properties"
  value="$(awk -F: -v wanted="$name" '
    $1 ~ "^[[:space:]]*" wanted "[[:space:]]*$" {
      gsub(/[[:space:]]/, "", $2)
      if ($2 !~ /^[01]$/ || found) exit 2
      value=$2; found=1
    }
    END { if (!found) exit 1; print value }
  ' <<<"$properties")" || die "the TPM reports no unambiguous $name property"
  printf '%s\n' "$value"
}

index_present() {
  local handles want line normalized
  handles="$("$(tool tpm2_getcap)" handles-nv-index 2>/dev/null)" \
    || die "cannot enumerate TPM NV indices"
  want=$(( 16#${1#0x} ))
  while read -r line; do
    line="${line//[ -]/}"
    [[ "$line" =~ ^0[xX][0-9a-fA-F]+$ ]] || continue
    normalized=$(( 16#${line#0[xX]} ))
    (( normalized == want )) && return 0
  done <<<"$handles"
  return 1
}

nv_contract() {
  local public
  public="$("$(tool tpm2_nvreadpublic)" "$1" 2>/dev/null)" \
    || die "the TPM will not describe $1"
  ni_tpm2_nv_public_parse "$1" <<<"$public" \
    || die "$1 does not present the exact public-area grammar"
}

assert_index() { # index attrs size policy required-bits permitted-name...
  local index=$1 expected_attrs=$2 expected_size=$3 expected_policy=$4 required=$5
  shift 5
  local contract attrs size policy name raw candidate accepted=0
  contract="$(nv_contract "$index")" || exit 1
  read -r attrs size policy name <<<"$contract"
  raw=$(( 16#${attrs#0x} ))
  (( ( raw & ~ATTRIBUTE_DYNAMIC_MASK ) == 16#${expected_attrs#0x} )) \
    || die "$index carries foreign attributes $attrs"
  [[ "$size" == "$expected_size" ]] || die "$index has a foreign size"
  [[ "$policy" == "$expected_policy" ]] || die "$index carries a foreign authorization policy"
  (( ( raw & required ) == required )) || die "$index is incomplete"
  for candidate in "$@"; do [[ "$name" == "$candidate" ]] && accepted=1; done
  (( accepted == 1 )) || die "$index carries a foreign TPM-computed Name"
}

assert_floor() {
  assert_index "$FLOOR_INDEX" "$FLOOR_ATTRIBUTES" 8 "$POLICY_FLOOR" \
    "$FLOOR_COMPLETE_BITS" "$FLOOR_NAME"
}

anchor_state() {
  local contract attrs _size _policy name raw
  contract="$(nv_contract "$ANCHOR_INDEX")" || exit 1
  read -r attrs _size _policy name <<<"$contract"
  raw=$(( 16#${attrs#0x} ))
  if (( ( raw & NV_WRITTEN ) == 0 )); then
    assert_index "$ANCHOR_INDEX" "$ANCHOR_ATTRIBUTES" 32 "$POLICY_EXTEND" 0 \
      "$ANCHOR_PRISTINE_NAME"
    printf 'pristine\n'
  else
    assert_index "$ANCHOR_INDEX" "$ANCHOR_ATTRIBUTES" 32 "$POLICY_EXTEND" \
      "$NV_WRITTEN" "$ANCHOR_WRITTEN_NAME"
    printf 'written\n'
  fi
}

read_exact() {
  local index=$1 size=$2 output=$3
  "$(tool tpm2_nvread)" "$index" -C "$index" -s "$size" -o "$output" \
    >/dev/null 2>&1 || die "$index cannot be read"
  [[ "$(wc -c < "$output" | tr -d '[:space:]')" == "$size" ]] \
    || die "$index returned a short value"
}

floor_value() {
  read_exact "$FLOOR_INDEX" 8 "$WORK/floor-read.bin"
  "$(tool python3)" - "$WORK/floor-read.bin" <<'PY'
import struct, sys
blob = open(sys.argv[1], "rb").read()
value, = struct.unpack(">Q", blob)
if not 0 < value <= 9007199254740991:
    raise SystemExit(1)
print(value)
PY
}

anchor_value() {
  read_exact "$ANCHOR_INDEX" 32 "$WORK/anchor-read.bin"
  hex_of "$WORK/anchor-read.bin"
}

prepare() {
  (( $# == 1 )) || die "prepare requires one baseline floor"
  if ! [[ "$1" =~ ^[1-9][0-9]{0,15}$ ]] || (( 10#$1 > MAX_SAFE_INTEGER )); then
    die "baseline floor is not a positive safe integer"
  fi
  local floor=$1
  with_workspace; compute_policies
  [[ "$(permanent_property ownerAuthSet)" == 0 ]] \
    || die "owner authorization is already sealed"
  [[ "$(permanent_property lockoutAuthSet)" == 0 ]] \
    || die "lockout authorization is not EmptyAuth"
  [[ "$(permanent_property disableClear)" == 0 ]] \
    || die "disableClear was set before OTA NV provisioning"
  if index_present "$FLOOR_INDEX" || index_present "$ANCHOR_INDEX"; then
    die "OTA NV provisioning already began; partial or existing state requires physical recovery"
  fi

  "$(tool python3)" - "$floor" "$WORK/floor.bin" <<'PY'
import struct, sys
open(sys.argv[2], "wb").write(struct.pack(">Q", int(sys.argv[1])))
PY
  "$(tool tpm2_nvdefine)" "$FLOOR_INDEX" -C o -s 8 -g sha256 \
    -a "policywrite|authread|ownerread|writedefine" -L "$WORK/floor.digest" \
    >/dev/null 2>&1 || die "the TPM refused the floor definition"
  session_for TPM2_CC_NV_Write or
  "$(tool tpm2_nvwrite)" "$FLOOR_INDEX" -C "$FLOOR_INDEX" \
    -P "session:$SESSION" -i "$WORK/floor.bin" >/dev/null 2>&1 \
    || die "the TPM refused the floor write"
  session_close
  session_for TPM2_CC_NV_WriteLock or
  "$(tool tpm2_nvwritelock)" "$FLOOR_INDEX" -C "$FLOOR_INDEX" \
    -P "session:$SESSION" >/dev/null 2>&1 \
    || die "the TPM refused the permanent floor write-lock"
  session_close
  assert_floor
  [[ "$(floor_value)" == "$floor" ]] || die "the floor did not read back exactly"

  "$(tool tpm2_nvdefine)" "$ANCHOR_INDEX" -C o -s 32 -g sha256 \
    -a "policywrite|authread|ownerread|no_da|nt=extend" -L "$WORK/extend.digest" \
    >/dev/null 2>&1 || die "the TPM refused the anchor definition"
  [[ "$(anchor_state)" == pristine ]] || die "the new anchor is not pristine"
  assert_floor
  [[ "$(floor_value)" == "$floor" ]] || die "the floor changed during anchor provisioning"
  printf 'prepared\n'
}

inspect() {
  (( $# == 0 )) || die "inspect takes no arguments"
  with_workspace; compute_policies
  if ! index_present "$FLOOR_INDEX" || ! index_present "$ANCHOR_INDEX"; then
    die "OTA NV state is absent or partial"
  fi
  assert_floor
  local floor anchor state owner protected
  floor="$(floor_value)"; state="$(anchor_state)"
  if [[ "$state" == written ]]; then anchor="$(anchor_value)"; else anchor=-; fi
  owner="$(permanent_property ownerAuthSet)"
  protected="$(permanent_property disableClear)"
  "$(tool python3)" - "$floor" "$anchor" "$state" "$owner" "$protected" <<'PY'
import json, sys
floor, anchor, state, owner, protected = sys.argv[1:]
print(json.dumps({"anchor_sha256": None if anchor == "-" else anchor, "anchor_state": state,
 "baseline_floor": int(floor), "clear_protected": protected == "1",
 "owner_sealed": owner == "1", "profile": "owner-sealed-ota-state-v1",
 "schema": "neural-ice-owner-ota-state-inspection-v1"},
 sort_keys=True, separators=(",", ":")))
PY
}

clear_protection() {
  (( $# == 0 )) || die "clear-protection takes no arguments"
  with_workspace; compute_policies
  [[ "$(permanent_property ownerAuthSet)" == 0 ]] \
    || die "owner authorization is already sealed"
  [[ "$(permanent_property lockoutAuthSet)" == 0 ]] \
    || die "lockout authorization is not EmptyAuth"
  [[ "$(permanent_property disableClear)" == 0 ]] \
    || die "clear protection was already set outside this transition"
  if ! index_present "$FLOOR_INDEX" || ! index_present "$ANCHOR_INDEX"; then
    die "cannot protect absent or partial OTA NV state"
  fi
  assert_floor
  [[ "$(anchor_state)" == pristine ]] \
    || die "clear protection requires the pristine pre-seal anchor"
  "$(tool tpm2_clearcontrol)" -C l s >/dev/null 2>&1 \
    || die "the TPM refused to set disableClear under Lockout EmptyAuth"
  [[ "$(permanent_property disableClear)" == 1 ]] \
    || die "the TPM did not retain disableClear=1"
  assert_floor
  [[ "$(anchor_state)" == pristine ]] \
    || die "OTA NV state changed while clear protection was being set"
  printf 'protected\n'
}

extend_anchor() {
  (( $# == 1 )) || die "extend requires one SHA-256 digest"
  [[ "$1" =~ ^[0-9a-f]{64}$ ]] || die "anchor input is not canonical SHA-256 hex"
  local input=$1 before expected after state
  with_workspace; compute_policies
  [[ "$(permanent_property ownerAuthSet)" == 1 ]] \
    || die "runtime anchor extension requires a sealed owner hierarchy"
  [[ "$(permanent_property disableClear)" == 1 ]] \
    || die "runtime anchor extension requires disableClear=1"
  if ! index_present "$FLOOR_INDEX" || ! index_present "$ANCHOR_INDEX"; then
    die "runtime OTA NV state is absent or partial"
  fi
  assert_floor
  state="$(anchor_state)"
  if [[ "$state" == pristine ]]; then
    before="$(printf '00%.0s' {1..32})"
  else
    before="$(anchor_value)"
  fi
  "$(tool python3)" - "$input" "$before" "$WORK/input.bin" <<'PY'
import sys
value = bytes.fromhex(sys.argv[1])
open(sys.argv[3], "wb").write(value)
PY
  expected="$("$(tool python3)" - "$input" "$before" <<'PY'
import hashlib, sys
print(hashlib.sha256(bytes.fromhex(sys.argv[2]) + bytes.fromhex(sys.argv[1])).hexdigest())
PY
)"
  session_for TPM2_CC_NV_Extend plain
  "$(tool tpm2_nvextend)" "$ANCHOR_INDEX" -C "$ANCHOR_INDEX" \
    -P "session:$SESSION" -i "$WORK/input.bin" >/dev/null 2>&1 \
    || die "the TPM refused the policy-bound anchor extension"
  session_close
  [[ "$(anchor_state)" == written ]] || die "the extended anchor is not written"
  after="$(anchor_value)"
  [[ "$after" == "$expected" ]] || die "the anchor extension did not read back exactly"
  printf '%s\n' "$after"
}

usage() {
  cat >&2 <<'EOF'
usage:
  neural-ice-ota-tpm-state prepare BASELINE_FLOOR
  neural-ice-ota-tpm-state inspect
  neural-ice-ota-tpm-state clear-protection
  neural-ice-ota-tpm-state extend SHA256
EOF
  exit 2
}

command_name=${1:-}
shift || true
case "$command_name" in
  prepare) prepare "$@" ;;
  inspect) inspect "$@" ;;
  clear-protection) clear_protection "$@" ;;
  extend) extend_anchor "$@" ;;
  *) usage ;;
esac
