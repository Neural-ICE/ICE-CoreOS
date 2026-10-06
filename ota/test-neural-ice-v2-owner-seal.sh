#!/usr/bin/env bash
# Interface contract of ota/neural-ice-v2-owner-seal.sh (mission B, T0;
# docs/ota/V2-RELEASE-ATTESTATION.md §Shell library).
#
# T0 froze the NAMES, the EXIT CODES and the fail-closed default; T3b fills the
# bodies. This suite asserts, at every stage:
#   - the library is sourceable without side effect and defines the contract's
#     four functions;
#   - `v2seal_refusal` ALWAYS refuses (exit 1), whatever NEURALICE_SEALED_OTA_STATE
#     says: the v2 lane has no relaxed branch (ADR-0050 lever B stays v1-only);
#   - with no input every entry point refuses (1) or fails internally (2), never 0
#     -- a body that returned success would let an installer wipe a disk on an
#     unauthenticated release;
#   - the library never reads the posture variable in code;
# and, from T3b on, the BEHAVIOUR of the three entry points against a mock
# verifier and mock TPM helpers that follow the contract (CLI §3, receipt §4,
# layout §5, library §7) and the golden vectors of T0.
set -euo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIB="$ROOT/ota/neural-ice-v2-owner-seal.sh"
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
pass() { printf 'ok: %s\n' "$*"; }

[[ -f "$LIB" ]] || fail "missing $LIB"
bash -n "$LIB" || fail "syntax error in $LIB"

# --- sourcing is inert and idempotent ------------------------------------------
for posture in "" relaxed strict; do
  out="$(NEURALICE_SEALED_OTA_STATE="$posture" bash -c "source '$LIB'; source '$LIB'; declare -F" 2>&1)" \
    || fail "sourcing the library failed (posture='$posture')"
  for fn in v2seal_refusal v2seal_preflight v2seal_commit v2seal_verify_retained; do
    grep -q "^declare -f $fn\$" <<<"$out" || fail "function $fn is not defined (posture='$posture')"
  done
done
pass "sourcing defines v2seal_refusal/preflight/commit/verify_retained, with no side effect"

# --- v2seal_refusal never relaxes ----------------------------------------------
for posture in "" relaxed strict; do
  set +e
  err="$(NEURALICE_SEALED_OTA_STATE="$posture" bash -c "source '$LIB'; v2seal_refusal 'test refusal'; echo SURVIVED" 2>&1)"
  rc=$?
  set -e
  [[ "$rc" -eq 1 ]] || fail "v2seal_refusal exited $rc, not 1 (posture='$posture')"
  grep -q 'SURVIVED' <<<"$err" && fail "v2seal_refusal returned to its caller (posture='$posture')"
  grep -q 'v2seal: refused: test refusal' <<<"$err" || fail "refusal message not exact: $err"
done
pass "v2seal_refusal exits 1 in unset, relaxed and strict postures and never returns"

# --- no input, no success --------------------------------------------------------
for posture in "" relaxed strict; do
  for fn in v2seal_preflight v2seal_commit v2seal_verify_retained; do
    set +e
    err="$(NEURALICE_SEALED_OTA_STATE="$posture" bash -c "source '$LIB'; $fn; echo SURVIVED:\$?" 2>&1)"
    rc=$?
    set -e
    [[ "$rc" -ne 0 ]] || fail "$fn succeeded with no input (posture='$posture')"
    grep -q "^SURVIVED:0\$" <<<"$err" && fail "$fn returned success (posture='$posture')"
    # exit 1 = refusal, 2 = internal error; nothing else is in the contract
    [[ "$rc" -eq 1 || "$rc" -eq 2 ]] || fail "$fn exited $rc, outside the contract {1,2}"
  done
done
pass "every entry point exits 1 or 2, never 0, with no input, in every posture"

# --- the library never consults the posture ------------------------------------
code="$(grep -v '^[[:space:]]*#' "$LIB")"
if grep -Eq 'NEURALICE_SEALED_OTA_STATE|SEALED_OTA_STATE|relaxed' <<<"$code"; then
  fail "the v2 library reads the relaxed/strict posture; it must have no such branch"
fi
pass "no code line of the library mentions the posture"

# =========================================================================== #
# BEHAVIOUR (T3b). Mock verifier and mock TPM helpers that follow the contract.
# =========================================================================== #
FIX="$ROOT/tools/ni-ota-verify/tests/fixtures/v2-release"
[[ -f "$FIX/golden.json" ]] || fail "missing the T0 golden vectors under $FIX"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/ni-v2seal.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
golden() { python3 -I -c 'import json,sys
d=json.load(open(sys.argv[1]))
for k in sys.argv[2].split("."): d=d[k]
print(d if not isinstance(d,(dict,list)) else json.dumps(d,sort_keys=True,separators=(",",":")))' "$FIX/golden.json" "$1"; }
export_golden() { # <variable> <golden path>
  local value
  value="$(golden "$2")"
  export "$1=$value"
}
G_SEQ="$(golden expected.bundle_seq)"
G_MANIFEST_SHA="$(golden inputs.sealed_manifest_sha256)"
G_SIG_SHA="$(golden inputs.sealed_manifest_sig_sha256)"
G_KEY_SHA="$(golden inputs.sealed_key_sha256)"
G_MIN="$(golden inputs.sealed_min_bundle_seq)"
G_RECEIPT_MD="$(golden expected.receipt_sha256.manifest-digest)"
G_RECEIPT_FLOOR="$(golden expected.receipt_sha256.floor)"

# --- the mock verifier: strict flags (a usage error is exit 2), golden outputs --
cat > "$TMP/ni-ota-verify" <<'MOCK_VERIFIER'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$MOCK_LOG"
printf 'VERIFIER\n' >> "$MOCK_CALLS"
verb="${1:-}"; shift || true
declare -A flag=()
while (($#)); do
  case "$1" in --*) ;; *) echo "mock: stray argument $1" >&2; exit 2 ;; esac
  [[ $# -ge 2 && -z "${flag[$1]+x}" ]] || { echo "mock: valueless or repeated $1" >&2; exit 2; }
  flag[$1]=$2; shift 2
done
need() { for k in "$@"; do [[ -n "${flag[$k]+x}" ]] || { echo "mock: missing $k" >&2; exit 2; }; done; }
fixture="$MOCK_FIXTURES"
case "$verb" in
verify-v2-release)
  need --manifest --manifest-sig --release-key --sealed-key-sha256 --hardware-target --access-profile \
    --trust-policy-id --variant --release-authority --candidate-root --host-index-digest \
    --host-manifest-digest --receipt
  if [[ -n "${flag[--sealed-manifest-sha256]+x}" ]]; then
    mode=manifest-digest; need --sealed-manifest-sig-sha256
    [[ -z "${flag[--sealed-min-bundle-seq]+x}" ]] || { echo "mock: both modes" >&2; exit 1; }
  elif [[ -n "${flag[--sealed-min-bundle-seq]+x}" ]]; then
    mode=floor
  else
    echo "ni-ota-verify: v2 release REFUSED: mode: neither seal mode" >&2; exit 1
  fi
  [[ "${flag[--variant]}" == sealed-lab ]] || { echo "ni-ota-verify: v2 release REFUSED: candidate-marker: variant" >&2; exit 1; }
  [[ -z "${MOCK_EXIT:-}" ]] || exit "$MOCK_EXIT"
  if [[ -n "${MOCK_REFUSE:-}" ]] || [[ -n "${MOCK_REFUSE_ROOT:-}" && "${flag[--candidate-root]}" == "$MOCK_REFUSE_ROOT" ]]; then
    echo "ni-ota-verify: v2 release REFUSED: ${MOCK_REFUSE:-candidate-key}: mock" >&2; exit 1
  fi
  [[ "$(sha256sum < "${flag[--manifest]}" | cut -d' ' -f1)" == "${MOCK_EXPECT_MANIFEST_SHA:-$(sha256sum < "$fixture/release-manifest.json" | cut -d' ' -f1)}" ]] \
    || { echo "ni-ota-verify: v2 release REFUSED: manifest-digest: mock" >&2; exit 1; }
  receipt="$fixture/expected-receipt-$mode.json"
  [[ -z "${MOCK_RECEIPT_ON_ROOT:-}" || "${flag[--candidate-root]}" != "$MOCK_RECEIPT_ON_ROOT" ]] || receipt="$MOCK_RECEIPT_FILE"
  idem=false
  if [[ -e "${flag[--receipt]}" ]]; then
    cmp -s "$receipt" "${flag[--receipt]}" || { echo "ni-ota-verify: v2 release REFUSED: receipt-conflict: mock" >&2; exit 1; }
    idem=true
  else
    install -m 0600 "$receipt" "${flag[--receipt]}"
  fi
  sha="$(sha256sum < "$receipt" | cut -d' ' -f1)"
  seq="$(python3 -I -c 'import json,sys;print(json.load(open(sys.argv[1]))["bundle_seq"])' "$receipt")"
  if [[ -n "${MOCK_STDOUT+x}" ]]; then printf '%s\n' "$MOCK_STDOUT"; exit 0; fi
  printf '{"bundle_seq":%s,"idempotent":%s,"receipt_sha256":"%s","verdict":"pass"}\n' "${MOCK_SEQ_OUT:-$seq}" "$idem" "${MOCK_SHA_OUT:-$sha}"
  ;;
verify-retained-v2-release)
  need --manifest --manifest-sig --release-key --expected-receipt-sha256 --receipt --scratch-dir
  [[ -z "${MOCK_EXIT:-}" ]] || exit "$MOCK_EXIT"
  [[ -z "${MOCK_REFUSE:-}" ]] || { echo "ni-ota-verify: v2 release REFUSED: ${MOCK_REFUSE}: mock" >&2; exit 1; }
  sha="$(sha256sum < "${flag[--receipt]}" | cut -d' ' -f1)"
  [[ "$sha" == "${flag[--expected-receipt-sha256]}" ]] || { echo "ni-ota-verify: v2 release REFUSED: receipt-digest: mock" >&2; exit 1; }
  seq="$(python3 -I -c 'import json,sys;print(json.load(open(sys.argv[1]))["bundle_seq"])' "${flag[--receipt]}")"
  printf '{"bundle_seq":%s,"receipt_sha256":"%s","verdict":"pass"}\n' "$seq" "${MOCK_SHA_OUT:-$sha}"
  ;;
*) echo "mock: unknown verb $verb" >&2; exit 2 ;;
esac
MOCK_VERIFIER
chmod 0755 "$TMP/ni-ota-verify"

# --- the mock TPM helpers: the closed public output of ota/neural-ice-ota-tpm-state.sh
cat > "$TMP/ota-tpm-state" <<'MOCK_OTA_TPM'
#!/usr/bin/env bash
set -euo pipefail
printf 'OTA-TPM %s\n' "$*" >> "$MOCK_CALLS"
case "${1:-}" in
  prepare)
    [[ -z "${MOCK_PREPARE_OUT:-}" ]] || { printf '%s\n' "$MOCK_PREPARE_OUT"; exit 0; }
    printf '%s\n' "$2" > "$MOCK_TPM_FLOOR"; echo prepared ;;
  inspect-v2)
    floor="$(cat "$MOCK_TPM_FLOOR")"
    python3 -I - "$floor" "${MOCK_INSPECT_TWEAK:-}" <<'PY'
import json, sys
v = {
    "anchor_attributes": "0x2060048", "anchor_index": "0x01500002",
    "anchor_name": "000b038de2091c1c8ef2e8fd8869f17bef3a576ae287530fa17f05ae3b9712014b5d",
    "anchor_policy_sha256": "b6a2e7142ee56fd978047488483daa5b42b8dc4cc7ddcceddfb91793cf1ff1b7",
    "anchor_sha256": None, "anchor_size": 32, "anchor_state": "pristine",
    "baseline_floor": int(sys.argv[1]), "clear_protected": False,
    "floor_attributes": "0x62008", "floor_index": "0x01500001",
    "floor_name": "000be283f20a38b93f8cef085efb4aee9f5944cc3b3b28b850bf3c0eeb2054cd7fc4",
    "floor_policy_sha256": "f83217e5a2a04342f7daa55ccfb3cd4b8a1f1e8ebb28c7719a9abbdbd638a230",
    "floor_size": 8, "owner_sealed": False, "profile": "owner-sealed-ota-state-v1",
    "schema": "neural-ice-owner-ota-state-inspection-v2",
}
tweak = sys.argv[2]
if tweak == "anchor-written": v["anchor_state"] = "written"; v["anchor_sha256"] = "0" * 64
elif tweak == "floor+1": v["baseline_floor"] += 1
elif tweak == "extra-field": v["extra"] = 1
elif tweak == "clear-protected": v["clear_protected"] = True
print(json.dumps(v, sort_keys=True, separators=(",", ":")))
PY
    ;;
  *) exit 2 ;;
esac
MOCK_OTA_TPM
cat > "$TMP/tpm-state" <<'MOCK_TPM'
#!/usr/bin/env bash
printf 'TPM-STATE %s\n' "$*" >> "$MOCK_CALLS"
[[ "${1:-}" == provisioning-status ]] || exit 2
printf '%s\n' "${MOCK_TPM_STATUS:-preseal-prepared}"
MOCK_TPM
chmod 0755 "$TMP/ota-tpm-state" "$TMP/tpm-state"

export MOCK_FIXTURES="$FIX" MOCK_LOG="$TMP/verifier.log" MOCK_CALLS="$TMP/calls.log" MOCK_TPM_FLOOR="$TMP/tpm-floor"

# The environment a caller sets (contract §7), from the golden inputs.
v2_env() { # exports V2SEAL_* for the manifest-digest mode (or floor if $1 == floor)
  local mode=${1:-manifest-digest}
  rm -rf -- "$TMP/work"; install -d -m 0700 "$TMP/work"
  : > "$MOCK_LOG"; : > "$MOCK_CALLS"
  export V2SEAL_OTA_VERIFY="$TMP/ni-ota-verify" V2SEAL_MODE="$mode"
  export V2SEAL_MANIFEST="$FIX/release-manifest.json" V2SEAL_MANIFEST_SIG="$FIX/release-manifest.json.sig"
  export V2SEAL_RELEASE_KEY="$FIX/release-authorization.pub" V2SEAL_KEY_SHA256="$G_KEY_SHA"
  if [[ "$mode" == floor ]]; then
    export V2SEAL_MIN_BUNDLE_SEQ="$G_MIN"
    unset V2SEAL_MANIFEST_SHA256 V2SEAL_MANIFEST_SIG_SHA256
  else
    export V2SEAL_MANIFEST_SHA256="$G_MANIFEST_SHA" V2SEAL_MANIFEST_SIG_SHA256="$G_SIG_SHA"
    unset V2SEAL_MIN_BUNDLE_SEQ
  fi
  export_golden V2SEAL_HARDWARE_TARGET inputs.hardware_target
  export_golden V2SEAL_ACCESS_PROFILE inputs.access_profile
  export_golden V2SEAL_TRUST_POLICY_ID inputs.trust_policy_id
  export_golden V2SEAL_VARIANT inputs.variant
  export_golden V2SEAL_RELEASE_AUTHORITY inputs.release_authority
  export V2SEAL_CANDIDATE_ROOT="$FIX/candidate-root"
  export_golden V2SEAL_HOST_INDEX_DIGEST inputs.host_index_digest
  export_golden V2SEAL_HOST_MANIFEST_DIGEST inputs.host_manifest_digest
  export V2SEAL_WORK="$TMP/work" V2SEAL_RECEIPT="$TMP/work/receipt.json"
  unset MOCK_EXIT MOCK_REFUSE MOCK_REFUSE_ROOT MOCK_STDOUT MOCK_SEQ_OUT MOCK_SHA_OUT MOCK_RECEIPT_ON_ROOT \
    MOCK_RECEIPT_FILE MOCK_EXPECT_MANIFEST_SHA MOCK_PREPARE_OUT MOCK_INSPECT_TWEAK MOCK_TPM_STATUS
}
# run <function> -> sets RC, OUT (stdout), ERR (stderr); the library `exit`s, so a subshell.
run_lib() {
  local fn=$1 extra=${2:-}
  set +e
  OUT="$(bash -c "source '$LIB'; set -a; $extra set +a; $fn; printf 'SURVIVED:%s\n' \"\$V2SEAL_BUNDLE_SEQ|\$V2SEAL_RECEIPT_SHA256\"" 2>"$TMP/err")"
  RC=$?
  set -e
  ERR="$(cat "$TMP/err")"
}
expect_rc() { # <rc> <stderr needle or ''> <description>
  [[ "$RC" -eq "$1" ]] || fail "$3: exit $RC, wanted $1 (stderr: $ERR)"
  [[ -z "$2" ]] || grep -Fq -- "$2" <<<"$ERR" || fail "$3: stderr lacks '$2' (got: $ERR)"
  if [[ "$1" -ne 0 ]]; then
    grep -q '^SURVIVED:' <<<"$OUT" && fail "$3: the library returned to its caller after a failure"
  fi
  return 0
}
expect_flow_refusal() { # <stderr needle> <description>: RC/ERR of the last run_flow
  [[ "$RC" -eq 1 ]] || fail "$2: exit $RC, wanted 1 (stderr: $ERR)"
  grep -Fq -- "$1" <<<"$ERR" || fail "$2: refused for another reason (wanted '$1', got: $ERR)"
}
verifier_calls() { grep -c '^VERIFIER$' "$MOCK_CALLS" || true; }

# --- preflight: both modes, golden receipts, exact verifier arguments ------------
v2_env
run_lib v2seal_preflight
expect_rc 0 "" "preflight (manifest-digest)"
[[ "$OUT" == "SURVIVED:$G_SEQ|$G_RECEIPT_MD" ]] || fail "preflight outputs are '$OUT', wanted bundle_seq $G_SEQ and receipt $G_RECEIPT_MD"
cmp -s "$TMP/work/receipt.json" "$FIX/expected-receipt-manifest-digest.json" \
  || fail "the preflight receipt is not the golden receipt bytes"
args="$(cat "$MOCK_LOG")"
for pair in "--manifest $FIX/release-manifest.json" "--manifest-sig $FIX/release-manifest.json.sig" \
  "--release-key $FIX/release-authorization.pub" "--sealed-key-sha256 $G_KEY_SHA" \
  "--sealed-manifest-sha256 $G_MANIFEST_SHA" "--sealed-manifest-sig-sha256 $G_SIG_SHA" \
  "--hardware-target $V2SEAL_HARDWARE_TARGET" "--access-profile $V2SEAL_ACCESS_PROFILE" \
  "--trust-policy-id $V2SEAL_TRUST_POLICY_ID" "--variant sealed-lab" \
  "--release-authority $V2SEAL_RELEASE_AUTHORITY" "--candidate-root $FIX/candidate-root" \
  "--host-index-digest $V2SEAL_HOST_INDEX_DIGEST" "--host-manifest-digest $V2SEAL_HOST_MANIFEST_DIGEST" \
  "--receipt $TMP/work/receipt.json"; do
  grep -Fq -- " $pair" <<<" $args" || fail "the verifier was not given '$pair' (got: $args)"
done
grep -Fq -- '--sealed-min-bundle-seq' <<<"$args" && fail "manifest-digest mode passed a minimum bundle_seq"
grep -Fq -- '--freshness' <<<"$args" && fail "the reserved freshness flags were passed"
grep -q '^verify-v2-release ' <<<"$args" || fail "the verb is not verify-v2-release"
pass "preflight (manifest-digest): golden receipt, outputs, and every contract flag passed through"

run_lib v2seal_preflight   # same receipt present: idempotent replay
expect_rc 0 "" "preflight replay (idempotent)"
pass "preflight replay over the same receipt is accepted"

v2_env floor
run_lib v2seal_preflight
expect_rc 0 "" "preflight (floor)"
[[ "$OUT" == "SURVIVED:$G_SEQ|$G_RECEIPT_FLOOR" ]] || fail "floor-mode outputs are '$OUT'"
grep -Fq -- "--sealed-min-bundle-seq $G_MIN" "$MOCK_LOG" || fail "floor mode did not pass the sealed minimum"
grep -Fq -- '--sealed-manifest-sha256' "$MOCK_LOG" && fail "floor mode passed a sealed manifest digest"
pass "preflight (floor): golden receipt and the sealed minimum"

# --- preflight: every required input, unset and empty, refuses BEFORE the verifier
for var in V2SEAL_OTA_VERIFY V2SEAL_MODE V2SEAL_MANIFEST V2SEAL_MANIFEST_SIG V2SEAL_RELEASE_KEY \
  V2SEAL_KEY_SHA256 V2SEAL_MANIFEST_SHA256 V2SEAL_MANIFEST_SIG_SHA256 V2SEAL_HARDWARE_TARGET \
  V2SEAL_ACCESS_PROFILE V2SEAL_TRUST_POLICY_ID V2SEAL_VARIANT V2SEAL_RELEASE_AUTHORITY \
  V2SEAL_CANDIDATE_ROOT V2SEAL_HOST_INDEX_DIGEST V2SEAL_HOST_MANIFEST_DIGEST V2SEAL_WORK V2SEAL_RECEIPT; do
  v2_env
  run_lib v2seal_preflight "unset $var;"
  expect_rc 1 "$var" "preflight with $var unset"
  [[ "$(verifier_calls)" == 0 ]] || fail "the verifier ran with $var unset"
  v2_env
  run_lib v2seal_preflight "$var=;"
  expect_rc 1 "$var" "preflight with $var empty"
  [[ "$(verifier_calls)" == 0 ]] || fail "the verifier ran with $var empty"
done
v2_env floor
run_lib v2seal_preflight "unset V2SEAL_MIN_BUNDLE_SEQ;"
expect_rc 1 V2SEAL_MIN_BUNDLE_SEQ "floor mode without its minimum"
pass "every required input, unset or empty, is a refusal naming it, before the verifier runs"

# --- preflight: malformed values and mode confusion never reach the verifier
refuse_before_verifier() { # <description> <assignments>
  v2_env "${3:-manifest-digest}"
  run_lib v2seal_preflight "$2"
  expect_rc 1 "" "$1"
  [[ "$(verifier_calls)" == 0 ]] || fail "$1: the verifier ran"
}
refuse_before_verifier "an uppercase sealed manifest digest" "V2SEAL_MANIFEST_SHA256=${G_MANIFEST_SHA^^};"
refuse_before_verifier "a short sealed signature digest" "V2SEAL_MANIFEST_SIG_SHA256=abc;"
refuse_before_verifier "a malformed key digest" "V2SEAL_KEY_SHA256=zz${G_KEY_SHA:2};"
refuse_before_verifier "a host digest without the sha256: prefix" "V2SEAL_HOST_INDEX_DIGEST=${V2SEAL_HOST_INDEX_DIGEST#sha256:};"
refuse_before_verifier "an unknown mode" "V2SEAL_MODE=both;"
refuse_before_verifier "both seal modes at once (manifest-digest + minimum)" "V2SEAL_MIN_BUNDLE_SEQ=2;"
refuse_before_verifier "both seal modes at once (floor + manifest digest)" "V2SEAL_MANIFEST_SHA256=$G_MANIFEST_SHA;" floor
refuse_before_verifier "a zero minimum bundle_seq" "V2SEAL_MIN_BUNDLE_SEQ=0;" floor
refuse_before_verifier "a minimum above 2^53-1" "V2SEAL_MIN_BUNDLE_SEQ=9007199254740992;" floor
refuse_before_verifier "a non-numeric minimum" "V2SEAL_MIN_BUNDLE_SEQ=2x;" floor
refuse_before_verifier "a manifest that is a symlink" "ln -s '$FIX/release-manifest.json' '$TMP/link.json'; V2SEAL_MANIFEST='$TMP/link.json';"
refuse_before_verifier "a missing candidate root" "V2SEAL_CANDIDATE_ROOT='$TMP/nope';"
refuse_before_verifier "a receipt outside the work directory" "V2SEAL_RECEIPT='$TMP/elsewhere.json';"
refuse_before_verifier "a receipt that climbs out of the work directory" "V2SEAL_RECEIPT='$TMP/work/../x.json';"
refuse_before_verifier "a non-executable verifier" "V2SEAL_OTA_VERIFY='$FIX/release-manifest.json';"
chmod 0755 "$TMP/work" 2>/dev/null || true
v2_env
chmod 0750 "$TMP/work"
run_lib v2seal_preflight
expect_rc 1 "private" "a work directory that is not 0700"
[[ "$(verifier_calls)" == 0 ]] || fail "the verifier ran with a non-private work directory"
pass "malformed values, mode confusion, symlinks and non-private work refuse before the verifier"

# --- preflight: verifier verdicts map to the contract exit codes -----------------
for class in key-digest signature bundle-seq hardware-target candidate-key candidate-anchor receipt-conflict; do
  v2_env
  run_lib v2seal_preflight "MOCK_REFUSE=$class;"
  expect_rc 1 "REFUSED: $class" "a verifier refusal of class $class"
  expect_rc 1 "v2seal: refused:" "the library names the refusal"
done
v2_env; run_lib v2seal_preflight "MOCK_EXIT=2;"
expect_rc 2 "" "a verifier internal error"
v2_env; run_lib v2seal_preflight "MOCK_EXIT=127;"
expect_rc 2 "" "a verifier that dies with an unexpected status"
v2_env; run_lib v2seal_preflight "V2SEAL_OTA_VERIFY='$TMP/absent-verifier';"
expect_rc 1 "executable" "an absent verifier binary"
for stdout in 'garbage' '' '{"bundle_seq":3,"idempotent":false,"receipt_sha256":"'"$G_RECEIPT_MD"'","verdict":"fail"}' \
  '{"bundle_seq":0,"idempotent":false,"receipt_sha256":"'"$G_RECEIPT_MD"'","verdict":"pass"}' \
  '{"bundle_seq":9007199254740992,"idempotent":false,"receipt_sha256":"'"$G_RECEIPT_MD"'","verdict":"pass"}' \
  '{"idempotent":false,"bundle_seq":3,"receipt_sha256":"'"$G_RECEIPT_MD"'","verdict":"pass"}' \
  '{"bundle_seq":3,"idempotent":false,"receipt_sha256":"'"$G_RECEIPT_MD"'","verdict":"pass","extra":1}'; do
  v2_env
  run_lib v2seal_preflight "MOCK_STDOUT='$stdout';"
  expect_rc 1 "v2seal: refused:" "a verifier stdout that is not the contract line ($stdout)"
done
v2_env; run_lib v2seal_preflight "MOCK_SHA_OUT=$(printf 'f%.0s' {1..64});"
expect_rc 1 "not the one the verifier reported" "a receipt sha the verifier misreports"
v2_env; run_lib v2seal_preflight "MOCK_SEQ_OUT=4;"
expect_rc 1 "bundle_seq" "a bundle_seq on stdout that is not the receipt's"
v2_env; run_lib v2seal_preflight "MOCK_EXPECT_MANIFEST_SHA=$(printf '0%.0s' {1..64});"
expect_rc 1 "REFUSED: manifest-digest" "a manifest whose bytes are not the sealed ones (verifier side)"
pass "verifier exit 1 -> refusal 1, anything else -> 2, and a stdout that is not the contract line is refused"

# --- no relaxed branch: the posture changes nothing ------------------------------
for posture in relaxed strict ""; do
  v2_env; run_lib v2seal_preflight "NEURALICE_SEALED_OTA_STATE='$posture'; MOCK_REFUSE=signature;"
  expect_rc 1 "REFUSED: signature" "a refusal under posture '$posture'"
done
pass "a verifier refusal is final under relaxed, strict and unset postures"

# --- the failure hook: the caller's failure surface is not bypassed --------------
v2_env
set +e
hook_out="$(bash -c "source '$LIB'; v2seal_on_refusal() { echo \"HOOK:\$1\"; return 1; }; MOCK_REFUSE=signature; export MOCK_REFUSE; v2seal_preflight" 2>/dev/null)"
hook_rc=$?
set -e
[[ "$hook_rc" -eq 1 ]] || fail "a failing hook changed the exit code to $hook_rc"
grep -q '^HOOK:the release verifier refused' <<<"$hook_out" || fail "the on-refusal hook was not called with the message (got: $hook_out)"
pass "v2seal_on_refusal is called, a failing hook cannot change the exit code"

# --- commit: persists, re-verifies on the deployment, compares, then touches the TPM
make_target() {
  rm -rf -- "$TMP/target" "$TMP/ota"; mkdir -p "$TMP/target"
  cp -a "$FIX/candidate-root/." "$TMP/target/"
  install -d -m 0700 "$TMP/ota"
  rm -f "$TMP/tpm-floor"
}
v2_commit_env() {
  v2_env
  make_target
  export V2SEAL_TARGET_ROOT="$TMP/target" V2SEAL_TARGET_OTA_DIR="$TMP/ota"
  export V2SEAL_OTA_TPM_STATE="$TMP/ota-tpm-state" V2SEAL_TPM_STATE="$TMP/tpm-state"
}
# Preflight, then commit, in the SAME process (the outputs are shell variables).
run_flow() { # <extra assignments for the commit phase>
  local extra=${1:-}
  set +e
  OUT="$(bash -c "source '$LIB'; v2seal_preflight; set -a; $extra set +a; v2seal_commit; printf 'COMMITTED:%s\n' \"\$V2SEAL_RELEASE_IDENTITY_SHA256\"" 2>"$TMP/err")"
  RC=$?
  set -e
  ERR="$(cat "$TMP/err")"
}
v2_commit_env
run_flow
[[ "$RC" -eq 0 ]] || fail "a complete preflight + commit failed: $ERR"
[[ "$OUT" == "COMMITTED:$G_MANIFEST_SHA" ]] || fail "the release identity is '$OUT', wanted the manifest sha256 $G_MANIFEST_SHA"
for f in v2-release-input-v1/release-manifest.json v2-release-input-v1/release-manifest.json.sig v2-release/receipt.json; do
  [[ -f "$TMP/ota/$f" && ! -L "$TMP/ota/$f" ]] || fail "$f was not persisted"
  [[ "$(stat -c %a "$TMP/ota/$f")" == 600 ]] || fail "$f is not 0600"
done
for d in v2-release-input-v1 v2-release; do
  [[ "$(stat -c %a "$TMP/ota/$d")" == 700 ]] || fail "$d is not 0700"
done
cmp -s "$TMP/ota/v2-release-input-v1/release-manifest.json" "$FIX/release-manifest.json" || fail "the persisted manifest differs"
cmp -s "$TMP/ota/v2-release-input-v1/release-manifest.json.sig" "$FIX/release-manifest.json.sig" || fail "the persisted signature differs"
cmp -s "$TMP/ota/v2-release/receipt.json" "$FIX/expected-receipt-manifest-digest.json" || fail "the persisted receipt is not the golden receipt"
[[ "$(cat "$TMP/tpm-floor")" == "$G_SEQ" ]] || fail "the TPM floor was not prepared with the manifest's bundle_seq"
# the order the contract demands: verify (pre-wipe), verify (deployed), prepare, inspect, status
order="$(tr '\n' ' ' < "$MOCK_CALLS")"
[[ "$order" == "VERIFIER VERIFIER OTA-TPM prepare $G_SEQ OTA-TPM inspect-v2 TPM-STATE provisioning-status " ]] \
  || fail "the call order is not verify, verify, prepare, inspect-v2, provisioning-status (got: $order)"
grep -Fq -- "--candidate-root $TMP/target" "$MOCK_LOG" || fail "the second verification did not target the deployment"
grep -Fq -- "--manifest $TMP/ota/v2-release-input-v1/release-manifest.json" "$MOCK_LOG" \
  || fail "the second verification did not use the persisted manifest"
[[ ! -e "$TMP/ota/v2-release/verify.err" ]] || fail "verifier scratch leaked into the persisted state"
pass "commit: persisted 0600/0700 layout, deployment re-verified, receipt golden, TPM floor = bundle_seq, identity = manifest sha"

# replay: everything already persisted and byte-equal
run_flow
[[ "$RC" -eq 0 ]] || fail "a replayed commit over byte-equal state was refused: $ERR"
pass "commit replay over byte-equal persisted state is accepted"

# the second verification refuses -> the TPM is NEVER touched
v2_commit_env
run_flow "MOCK_REFUSE_ROOT='$TMP/target'; export MOCK_REFUSE_ROOT;"
[[ "$RC" -eq 1 ]] || fail "a refusal on the deployed candidate exited $RC, wanted 1 ($ERR)"
grep -q 'OTA-TPM' "$MOCK_CALLS" && fail "the TPM was touched although the deployed candidate was refused"
pass "a deployed candidate that is refused never reaches the TPM"

# a receipt that differs from the pre-wipe one -> refusal, TPM untouched
v2_commit_env
printf '%s\n' '{"schema":"other"}' > "$TMP/other-receipt.json"
run_flow "MOCK_RECEIPT_ON_ROOT='$TMP/target'; MOCK_RECEIPT_FILE='$TMP/other-receipt.json'; export MOCK_RECEIPT_ON_ROOT MOCK_RECEIPT_FILE;"
[[ "$RC" -eq 1 ]] || fail "a divergent installed receipt exited $RC ($ERR)"
grep -q 'OTA-TPM' "$MOCK_CALLS" && fail "the TPM was touched although the installed receipt diverged"
pass "an installed receipt that differs from the pre-wipe one is refused before the TPM"

# a planted, different manifest in the persisted directory is never overwritten
v2_commit_env
install -d -m 0700 "$TMP/ota/v2-release-input-v1"
printf 'planted' > "$TMP/ota/v2-release-input-v1/release-manifest.json"
run_flow
[[ "$RC" -eq 1 ]] || fail "a planted persisted manifest exited $RC ($ERR)"
[[ "$(cat "$TMP/ota/v2-release-input-v1/release-manifest.json")" == planted ]] || fail "a planted manifest was overwritten"
grep -q 'OTA-TPM' "$MOCK_CALLS" && fail "the TPM was touched over a planted manifest"
# a planted symlink and a world-readable persisted directory are refused too
v2_commit_env
ln -s /nonexistent "$TMP/ota/v2-release"
run_flow
[[ "$RC" -eq 1 ]] || fail "a symlinked receipt directory exited $RC ($ERR)"
v2_commit_env
install -d -m 0755 "$TMP/ota/v2-release-input-v1"
run_flow
[[ "$RC" -eq 1 ]] || fail "a 0755 persisted directory exited $RC ($ERR)"
pass "planted bytes, a symlinked directory and a non-private directory are refused, never overwritten"

# TPM-side checks: each deviation of the closed public contract refuses
for tweak in anchor-written floor+1 extra-field clear-protected; do
  v2_commit_env
  run_flow "MOCK_INSPECT_TWEAK=$tweak; export MOCK_INSPECT_TWEAK;"
  [[ "$RC" -eq 1 ]] || fail "inspect-v2 deviation '$tweak' exited $RC, wanted 1 ($ERR)"
  grep -q 'closed public contract' <<<"$ERR" || fail "inspect-v2 deviation '$tweak' refused for another reason: $ERR"
done
v2_commit_env
run_flow "MOCK_TPM_STATUS=virgin; export MOCK_TPM_STATUS;"
expect_flow_refusal 'preseal-prepared' "a provisioning status other than preseal-prepared"
v2_commit_env
run_flow "MOCK_PREPARE_OUT=nope; export MOCK_PREPARE_OUT;"
expect_flow_refusal 'cannot prepare' "a prepare that does not print 'prepared'"
pass "inspect-v2 deviations (anchor, floor, extra field, Clear protection), a wrong provisioning checkpoint and a failed prepare refuse"

# commit inputs are not defaults either
for var in V2SEAL_TARGET_ROOT V2SEAL_TARGET_OTA_DIR V2SEAL_OTA_TPM_STATE V2SEAL_TPM_STATE V2SEAL_WORK; do
  v2_commit_env
  run_flow "unset $var;"
  expect_flow_refusal "$var" "commit without $var"
done
# the receipt the preflight authenticated must be unchanged when commit runs
v2_commit_env
run_flow "printf tampered >> \"\$V2SEAL_RECEIPT\";"
expect_flow_refusal 'changed between' "a pre-wipe receipt altered before the commit"
pass "commit refuses missing inputs and a pre-wipe receipt altered after the preflight"

# the inspect-v2 contract is the SAME bytes as the v1 lane's check in the installer
extract_expected() { awk '/^expected = \{/,/^\}/' "$1"; }
[[ -n "$(extract_expected "$LIB")" ]] || fail "cannot extract the library's inspect-v2 contract"
[[ "$(extract_expected "$LIB")" == "$(extract_expected "$ROOT/ota/neural-ice-autoinstall.sh")" ]] \
  || fail "the library's inspect-v2 contract has drifted from the installer's v1-lane contract"
pass "the inspect-v2 contract is byte-identical to the installer's (no drift)"

# --- verify_retained: ceremony and every boot ------------------------------------
persist="$TMP/persist"
rm -rf "$persist"; mkdir -p "$persist/v2-release-input-v1" "$persist/v2-release"
cp "$FIX/release-manifest.json" "$FIX/release-manifest.json.sig" "$persist/v2-release-input-v1/"
cp "$FIX/expected-receipt-manifest-digest.json" "$persist/v2-release/receipt.json"
install -d -m 0700 "$TMP/scratch"
retained_env() {
  : > "$MOCK_LOG"; : > "$MOCK_CALLS"
  unset MOCK_EXIT MOCK_REFUSE MOCK_SHA_OUT
  export V2SEAL_OTA_VERIFY="$TMP/ni-ota-verify" V2SEAL_EXPECTED_RECEIPT_SHA256="$G_RECEIPT_MD" V2SEAL_SCRATCH_DIR="$TMP/scratch"
  export V2SEAL_TEST_SEAM=1 V2SEAL_PERSIST_DIR="$persist" V2SEAL_RETAINED_KEY="$FIX/release-authorization.pub"
}
retained_env
run_lib v2seal_verify_retained
if [[ "$(id -u)" -eq 0 ]]; then
  expect_rc 1 "/var/lib/neural-ice/ota" "the persisted-path seam is refused for a privileged process"
else
  expect_rc 0 "" "verify_retained over the persisted layout"
  [[ "$OUT" == "SURVIVED:$G_SEQ|"* ]] || fail "verify_retained did not set V2SEAL_BUNDLE_SEQ ($OUT)"
  for pair in "--manifest $persist/v2-release-input-v1/release-manifest.json" \
    "--manifest-sig $persist/v2-release-input-v1/release-manifest.json.sig" \
    "--release-key $FIX/release-authorization.pub" "--expected-receipt-sha256 $G_RECEIPT_MD" \
    "--receipt $persist/v2-release/receipt.json" "--scratch-dir $TMP/scratch"; do
    grep -Fq -- " $pair" <<<" $(cat "$MOCK_LOG")" || fail "verify-retained-v2-release was not given '$pair'"
  done
  grep -q '^verify-retained-v2-release ' "$MOCK_LOG" || fail "the verb is not verify-retained-v2-release"
  pass "verify_retained: persisted layout, expected receipt digest and scratch passed to the retained verb"
fi
# without the armed seam the override is IGNORED: the fixed production paths are read
retained_env; unset V2SEAL_TEST_SEAM
run_lib v2seal_verify_retained
expect_rc 1 "/var/lib/neural-ice/ota" "an unarmed persisted-path override"
[[ "$(verifier_calls)" == 0 ]] || fail "the verifier ran against an overridden path without the armed seam"
pass "an unarmed V2SEAL_PERSIST_DIR is ignored: the fixed /var/lib/neural-ice/ota is read"
if [[ "$(id -u)" -ne 0 ]]; then
  retained_env; run_lib v2seal_verify_retained "V2SEAL_EXPECTED_RECEIPT_SHA256=$(printf '1%.0s' {1..64});"
  expect_rc 1 "REFUSED: receipt-digest" "a receipt whose digest is not the TPM-bound one"
  retained_env; run_lib v2seal_verify_retained "MOCK_SHA_OUT=$(printf 'f%.0s' {1..64});"
  expect_rc 1 "another receipt" "a verifier vouching for another receipt"
  retained_env; run_lib v2seal_verify_retained "MOCK_EXIT=2;"
  expect_rc 2 "" "a retained verifier internal error"
  for posture in relaxed strict; do
    retained_env; run_lib v2seal_verify_retained "NEURALICE_SEALED_OTA_STATE=$posture; MOCK_REFUSE=signature;"
    expect_rc 1 "REFUSED: signature" "a retained refusal under posture $posture"
  done
  retained_env; rm "$persist/v2-release/receipt.json"
  run_lib v2seal_verify_retained
  expect_rc 1 "incomplete" "a missing persisted receipt"
  cp "$FIX/expected-receipt-manifest-digest.json" "$persist/v2-release/receipt.json"
  retained_env; run_lib v2seal_verify_retained "V2SEAL_SCRATCH_DIR='$TMP/work2';"
  expect_rc 1 "directory" "a scratch directory that does not exist"
  for var in V2SEAL_OTA_VERIFY V2SEAL_EXPECTED_RECEIPT_SHA256 V2SEAL_SCRATCH_DIR; do
    retained_env; run_lib v2seal_verify_retained "unset $var;"
    expect_rc 1 "$var" "verify_retained with $var unset"
  done
  pass "verify_retained: digest mismatch, other receipt, internal error, missing files and inputs, every posture -- refused or failed closed"
fi

# --- OPTIONAL integration: the REAL verifier (T1), same golden vectors ---------------
# NI_V2_REAL_VERIFIER=/path/to/ni-ota-verify (built from the T1 branch, cosign on PATH)
# replays the library against the real `verify-v2-release`. Unset: skipped, and said so.
if [[ -n "${NI_V2_REAL_VERIFIER:-}" ]]; then
  [[ -x "$NI_V2_REAL_VERIFIER" ]] || fail "NI_V2_REAL_VERIFIER is not executable"
  command -v cosign >/dev/null 2>&1 || fail "the real verifier needs cosign on PATH"
  real_env() { v2_env "${1:-manifest-digest}"; export V2SEAL_OTA_VERIFY="$NI_V2_REAL_VERIFIER"; }
  real_env
  run_lib v2seal_preflight
  expect_rc 0 "" "preflight against the real verifier"
  [[ "$OUT" == "SURVIVED:$G_SEQ|$G_RECEIPT_MD" ]] || fail "the real verifier's outputs are '$OUT', not the golden ones"
  cmp -s "$TMP/work/receipt.json" "$FIX/expected-receipt-manifest-digest.json" \
    || fail "the real verifier wrote a receipt that is not the golden bytes"
  real_env floor
  run_lib v2seal_preflight
  expect_rc 0 "" "floor-mode preflight against the real verifier"
  [[ "$OUT" == "SURVIVED:$G_SEQ|$G_RECEIPT_FLOOR" ]] || fail "the real verifier's floor outputs are '$OUT'"
  # one flipped byte in the manifest: refused by the real verifier, never reaching a pass
  real_env
  { cat "$FIX/release-manifest.json"; printf '\n'; } > "$TMP/altered-real.json"
  run_lib v2seal_preflight "V2SEAL_MANIFEST='$TMP/altered-real.json';"
  expect_rc 1 "REFUSED" "an altered manifest against the real verifier"
  # a candidate carrying the v1 anchor
  real_env
  rm -rf "$TMP/real-cand"; cp -a "$FIX/candidate-root" "$TMP/real-cand"
  mkdir -p "$TMP/real-cand/etc/neural-ice/keys"; : > "$TMP/real-cand/etc/neural-ice/keys/ota-root.pub"
  run_lib v2seal_preflight "V2SEAL_CANDIDATE_ROOT='$TMP/real-cand';"
  expect_rc 1 "candidate-anchor" "a candidate with ota-root.pub against the real verifier"
  # the full flow with the real verifier and the mock TPM
  v2_commit_env
  export V2SEAL_OTA_VERIFY="$NI_V2_REAL_VERIFIER"
  run_flow
  [[ "$RC" -eq 0 ]] || fail "preflight + commit against the real verifier failed: $ERR"
  cmp -s "$TMP/ota/v2-release/receipt.json" "$FIX/expected-receipt-manifest-digest.json" \
    || fail "the persisted receipt is not the golden one with the real verifier"
  pass "REAL verifier (T1): golden receipts in both modes, altered manifest and v1 anchor refused, full preflight+commit"
else
  printf 'SKIP: real-verifier integration (set NI_V2_REAL_VERIFIER to a T1-built ni-ota-verify)\n'
fi

# --- static hygiene ------------------------------------------------------------
if command -v shellcheck >/dev/null 2>&1; then
  shellcheck -x "$LIB" || fail "shellcheck refused the library"
  pass "shellcheck clean"
fi
printf 'PASS: v2 owner-seal library contract\n'
