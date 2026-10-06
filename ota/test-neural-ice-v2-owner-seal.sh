#!/usr/bin/env bash
# Interface contract of ota/neural-ice-v2-owner-seal.sh (mission B, T0;
# docs/ota/V2-RELEASE-ATTESTATION.md §Shell library).
#
# T0 freezes the NAMES, the EXIT CODES and the fail-closed default; T3b fills the
# bodies. This suite therefore asserts what must hold at every stage:
#   - the library is sourceable without side effect and defines the contract's
#     four functions;
#   - `v2seal_refusal` ALWAYS refuses (exit 1), whatever NEURALICE_SEALED_OTA_STATE
#     says: the v2 lane has no relaxed branch (ADR-0050 lever B stays v1-only);
#   - until a body exists, every entry point fails CLOSED with exit 2 ("internal /
#     not implemented"), never 0 -- a stub that returned success would let an
#     installer wipe a disk on an unauthenticated release;
#   - the library never reads the posture variable in code.
# T3b replaces the "stub fails closed" cases by the behavioural suite; the
# refusal and no-relaxed cases stay.
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

# --- a stub fails closed -------------------------------------------------------
for posture in "" relaxed strict; do
  for fn in v2seal_preflight v2seal_commit v2seal_verify_retained; do
    set +e
    err="$(NEURALICE_SEALED_OTA_STATE="$posture" bash -c "source '$LIB'; $fn; echo SURVIVED:\$?" 2>&1)"
    rc=$?
    set -e
    [[ "$rc" -ne 0 ]] || fail "$fn succeeded (posture='$posture'): a stub must fail closed"
    grep -q "^SURVIVED:0\$" <<<"$err" && fail "$fn returned success (posture='$posture')"
    # exit 1 = refusal, 2 = internal / not implemented; nothing else is in the contract
    [[ "$rc" -eq 1 || "$rc" -eq 2 ]] || fail "$fn exited $rc, outside the contract {1,2}"
  done
done
pass "every entry point exits 1 or 2, never 0, in every posture"

# --- the library never consults the posture ------------------------------------
code="$(grep -v '^[[:space:]]*#' "$LIB")"
if grep -Eq 'NEURALICE_SEALED_OTA_STATE|SEALED_OTA_STATE|relaxed' <<<"$code"; then
  fail "the v2 library reads the relaxed/strict posture; it must have no such branch"
fi
pass "no code line of the library mentions the posture"

# --- static hygiene ------------------------------------------------------------
if command -v shellcheck >/dev/null 2>&1; then
  shellcheck -x "$LIB" || fail "shellcheck refused the library"
  pass "shellcheck clean"
fi
printf 'PASS: v2 owner-seal library contract\n'
