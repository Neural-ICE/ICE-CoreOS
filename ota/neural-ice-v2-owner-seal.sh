#!/usr/bin/env bash
# Shared v2 owner-seal library (mission B, DESIGN-B §2; contract:
# docs/ota/V2-RELEASE-ATTESTATION.md, "Shell library"). SOURCED, never executed:
# by ota/neural-ice-autoinstall.sh (adapter A1), by the generic installer's
# install-host.sh (adapter A2, OS-0044) and, for v2seal_verify_retained, by the
# first-boot ceremony. It replaces the v1 preseal attestation for a host whose
# image marker is owner-sealed-ota-state-v2; it never touches the TPM objects'
# semantics (ota-tpm-state.sh / tpm-state.sh are called, not changed).
#
# STATUS: T0 STUB. The interface below is frozen; every entry point FAILS CLOSED
# with exit 2 until T3b supplies its body. A caller wired to the stub therefore
# stops the install instead of wiping a disk on an unauthenticated release.
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
#                           provisioning-status == preseal-prepared.
#   v2seal_verify_retained  Ceremony and every boot. Runs
#                           `ni-ota-verify verify-retained-v2-release` on the
#                           live root against the persisted pair and receipt.
#   v2seal_refusal MSG...   Prints "v2seal: refused: MSG" on stderr and EXITS 1.
#
# Exit codes (the verifier's, preseal.rs): 0 pass; 1 refusal; 2 internal error or
# not implemented. Nothing else. A refusal is final: THERE IS NO RELAXED BRANCH.
# This library must never read NEURALICE_SEALED_OTA_STATE (ADR-0050 lever B is a
# v1-only posture); test-neural-ice-v2-owner-seal.sh enforces it.

# Idempotent: sourcing twice is a no-op.
[[ -z "${_V2SEAL_LIBRARY_LOADED:-}" ]] || return 0
_V2SEAL_LIBRARY_LOADED=1

v2seal_refusal() {
  printf 'v2seal: refused: %s\n' "$*" >&2
  exit 1
}

# Exit 2: the contract's "internal error" code, here "not implemented".
_v2seal_not_implemented() {
  printf 'v2seal: %s is not implemented (T0 contract stub); failing closed\n' "$1" >&2
  exit 2
}

v2seal_preflight() { _v2seal_not_implemented v2seal_preflight; }
v2seal_commit() { _v2seal_not_implemented v2seal_commit; }
v2seal_verify_retained() { _v2seal_not_implemented v2seal_verify_retained; }
