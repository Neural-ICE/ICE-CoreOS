#!/usr/bin/env bash
# ADR-0050 lab-trust, lever B: the mandatory first-boot TPM ceremony must
# FAIL-OPEN on a sealed OTA-state / preseal verification failure in the relaxed
# posture (the MVP 1.0 default), and reproduce the historical refusal in strict.
#
# On 2026-09-17 appliance .67 `die`d in the preseal block on a verification
# refusal, tripping the unit's OnFailure=emergency.target and dropping the boot
# into emergency mode (root locked). This suite proves the ORCHESTRATION seam
# without a real TPM: every helper the ceremony execs is a stub, so it measures
# which trust anchors still gate (KEEP) and which preseal step is skipped, not
# TPM cryptography (that stays in the swtpm suites). The stub OTA verifier
# always refuses verify-preseal-baseline -- exactly the .67 refusal -- so:
#   (a) strict  -> the ceremony `die`s with the preseal refusal, as today;
#   (b) relaxed -> the ceremony logs the RELAXED marker, exits 0, AND still
#                  runs: it reaches the preseal verifier, tolerates its refusal,
#                  performs the TPM ceremony and enrols the access-profile
#                  anchor.  Failing open on one anchor is not skipping the unit;
#   (c) relaxed -> a KEEP anchor (device-root, SRK) still fails closed.
set -euo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CEREMONY="$ROOT/ota/neural-ice-firstboot-tpm-ceremony.sh"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/ni-failopen.XXXXXX")"
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
cleanup() { rm -rf -- "$TMP"; }
trap cleanup EXIT

[[ "$EUID" -ne 0 ]] || fail "run this stubbed ceremony suite as a non-root user"
[[ -f "$CEREMONY" ]] || fail "ceremony under test is absent: $CEREMONY"
for tool in bash python3 sha256sum flock awk; do
  command -v "$tool" >/dev/null 2>&1 || fail "$tool is required; this suite does not SKIP"
done

readonly PROFILE=customer-locked
readonly TARGET=nvidia-gb10-arm64
readonly POLICY=neural-ice-secureboot-lab-v1
ZERO64="$(printf '%064d' 0)"
ZERO40="$(printf '%040d' 0)"
readonly OSREF="release.example.test/neural-ice/neural-ice-appliance@sha256:$ZERO64"
readonly MANIFEST="sha256:$ZERO64"

STATE="$TMP/state"
RUN="$TMP/run"
TOOLS="$TMP/tools"
MARKERS="$TMP/markers"
CANDIDATE="$TMP/candidate"
SRK="$TMP/srk-canonical.bin"
OTA_VERIFY_CALLED="$TMP/ota-verify-called"
TPM_PREPARE_CALLED="$TMP/tpm-prepare-called"
ANCHOR_ENROLLED="$TMP/anchor-enrolled"

mkdir -p "$TOOLS" "$MARKERS" "$CANDIDATE" "$RUN"
printf 'canonical-srk-bytes\n' > "$SRK"

# --------------------------------------------------------------------------- #
# Stub helpers. Each is what the ceremony execs; none talks to a real TPM.
# --------------------------------------------------------------------------- #
cat > "$TOOLS/device-root" <<EOF
#!/bin/sh
# attest --identity <path>: succeed unless a KEEP-anchor case asks us to fail.
[ "\${NI_STUB_DEVICE_ROOT_FAIL:-}" != 1 ] || exit 1
[ "\$1" = attest ] && [ "\$2" = --identity ] || exit 2
exit 0
EOF

cat > "$TOOLS/systemd-analyze" <<EOF
#!/bin/sh
[ "\$1" = srk ] || exit 2
cat "$SRK"
EOF

cat > "$TOOLS/cryptsetup" <<'EOF'
#!/bin/sh
[ "$1" = luksDump ] || exit 2
printf '{}\n'
EOF

cat > "$TOOLS/luks-evidence" <<'EOF'
#!/bin/sh
printf '{}\n'
EOF

cat > "$TOOLS/tpm2-readpublic" <<'EOF'
#!/bin/sh
# `-n <path>` / `-o <path>` are outputs the ceremony reads back later, so the
# stub has to produce them, not just exit 0.
prev=
for arg in "$@"; do
  case "$prev" in
    -n|-o) printf 'stub-public-bytes\n' > "$arg" ;;
  esac
  prev="$arg"
done
exit 0
EOF

cat > "$TOOLS/profile-anchor" <<EOF
#!/bin/sh
# Record the one-time enrolment so a posture can be measured by what it
# PRODUCES, not only by what it refuses, and write the three files the
# evidence builder digests -- the ceremony's later steps read them back.
if [ "\$1" = enroll ]; then
  : > "$ANCHOR_ENROLLED"
  printf '{"anchor_seq":1,"schema":"neural-ice-access-profile-anchor-v1"}\n' > "\$3/access-profile-v1.json"
  printf 'stub-signature\n' > "\$3/access-profile-v1.sig"
  printf 'stub-spki\n' > "\$3/access-profile-v1.spki"
fi
exit 0
EOF

cat > "$TOOLS/tpm-state" <<EOF
#!/bin/sh
case "\$1" in
  completion-status) exit 1 ;;                       # first boot: not complete
  provisioning-status) echo preseal-prepared ;;
  ceremony-prepare-v2|ceremony-prepare)
    : > "$TPM_PREPARE_CALLED"; printf '1 0 %s\n' "$ZERO64" ;;
  state-snapshot)
    printf '{"freshness_counter":1,"install_counter":1,"schema":"neural-ice-tpm-state-snapshot-v1"}\n' ;;
  completion-inspect)
    # Recompute the digest the ceremony just sealed, rather than hard-coding
    # one: a fixture that answers with a constant would pass whatever the
    # ceremony actually wrote.
    python3 - "$STATE/owner-ceremony-evidence-v2.json" <<'PY'
import hashlib,json,sys
blob=open(sys.argv[1],"rb").read()
digest=hashlib.sha256(b"neural-ice:tpm:owner-ceremony-completion:v2\0"+blob).hexdigest()
print(json.dumps({"completion_version":2,"evidence_digest_sha256":digest,
                  "schema":"neural-ice-owner-ceremony-completion-inspection-v1"},
                 sort_keys=True,separators=(",",":")))
PY
    ;;
  *) exit 0 ;;
esac
EOF

# inspect-v2 is what the v2 evidence builder validates: the completion anchor
# must be pristine and the owner state protected at the signed floor (the
# fixture's bundle_seq).
cat > "$TOOLS/ota-state" <<'EOF'
#!/bin/sh
case "$1" in
  inspect-v2)
    printf '{"anchor_attributes":"stub","anchor_index":"0x1500003","anchor_name":"stub-name","anchor_policy_sha256":"stub-policy","anchor_sha256":null,"anchor_size":64,"anchor_state":"pristine","baseline_floor":42,"clear_protected":true,"floor_attributes":"stub","floor_index":"0x1500004","floor_name":"stub-floor-name","floor_policy_sha256":"stub-floor-policy","floor_size":8,"owner_sealed":false,"profile":"lab-managed"}\n'
    ;;
  *) exit 0 ;;
esac
EOF

cat > "$TOOLS/ota-verify" <<EOF
#!/bin/sh
: > "$OTA_VERIFY_CALLED"
# verify-preseal-baseline is the .67 refusal path: always fail here.
exit 1
EOF

cat > "$TOOLS/bootc" <<EOF
#!/bin/sh
[ "\$#" -eq 2 ] && [ "\$1" = status ] && [ "\$2" = --json ] || exit 97
printf '{"spec":{"image":{"image":"%s"}},"status":{"booted":{"image":{"image":{"image":"%s"},"imageDigest":"%s"}}}}\n' \
  '$OSREF' '$OSREF' '$MANIFEST'
EOF

chmod +x "$TOOLS"/*

# --------------------------------------------------------------------------- #
# An owner-profile, preseal-prepared first-boot fixture whose preseal metadata
# is internally consistent, so the ceremony reaches the preseal VERIFIER.
# --------------------------------------------------------------------------- #
build_fixture() {
  local set_hash
  rm -rf -- "$STATE" "$MARKERS"
  mkdir -m 0700 "$STATE"
  mkdir -m 0700 "$STATE/preseal-input-v1" "$STATE/preseal"
  mkdir -p "$MARKERS"
  printf 'access_profile=%s\nhardware_target=%s\nsigned_boot_trust_policy_id=%s\ninitial_issuance_seq=1\n' \
    "$PROFILE" "$TARGET" "$POLICY" > "$STATE/owner-ceremony-intent-v1"
  printf '{"install_source":"medium","installed_at":"2026-09-01T00:00:00Z","installer_sealed_identity_sha256":"%s","release_identity_sha256":"%s","schema":"neural-ice-owner-ceremony-install-identity-v1"}\n' \
    "$ZERO64" "$ZERO64" > "$STATE/owner-ceremony-install-identity-v1.json"
  cp "$SRK" "$STATE/device-root-v1.json"
  cp "$SRK" "$STATE/srk-v1.tpm2b_public"
  printf '%s\n' "$PROFILE" > "$MARKERS/access-policy"
  printf '%s\n' "$TARGET" > "$MARKERS/hardware-target"
  printf '%s\n' "$POLICY" > "$MARKERS/signed-boot-trust-policy-id"
  printf 'owner-sealed-ota-state-v1\n' > "$TMP/ota-state-profile"
  : > "$TMP/system-luks"; : > "$TMP/data-luks"
  printf 'enforce=1\nstate_dir=%s\n' "$STATE" > "$TMP/ota.conf"
  local name
  for name in delegation-snapshot.json delegation-snapshot.sig \
    ota-release-authorization.json ota-release-authorization.sig bom.json \
    installer-release-authorization-v2.sig; do
    printf '{}\n' > "$STATE/preseal-input-v1/$name"
  done
  printf '{"image_manifest_digest":"%s"}\n' "$MANIFEST" \
    > "$STATE/preseal-input-v1/installer-release-authorization-v2.json"
  printf '{"bundle_seq":42,"installer_authorization_sha256":"%s","installer_authorization_signature_sha256":"%s","schema":"neural-ice-installer-preseal-set-v1","seed_ref":"%s","target_os_ref":"%s"}\n' \
    "$ZERO64" "$ZERO64" "$ZERO40" "$OSREF" > "$STATE/preseal-input-v1/preseal-set.json"
  set_hash="$(sha256sum "$STATE/preseal-input-v1/preseal-set.json" | awk '{print $1}')"
  printf '{"bundle_seq":42,"installer_authorization_sha256":"%s","preseal_set_sha256":"%s","schema":"neural-ice-ota-preseal-receipt-v1"}\n' \
    "$ZERO64" "$set_hash" > "$STATE/preseal/receipt.json"
  rm -f -- "$OTA_VERIFY_CALLED" "$TPM_PREPARE_CALLED" "$ANCHOR_ENROLLED"
}

run_ceremony() { # $1=posture, rest=script args
  local posture=$1
  shift
  env NI_FIRSTBOOT_TPM_TESTING=1 \
    NEURALICE_SEALED_OTA_STATE="$posture" \
    NI_FIRSTBOOT_TPM_TEST_STATE_DIR="$STATE" \
    NI_FIRSTBOOT_TPM_TEST_STATE="$TOOLS/tpm-state" \
    NI_FIRSTBOOT_TPM_TEST_DEVICE_ROOT="$TOOLS/device-root" \
    NI_FIRSTBOOT_TPM_TEST_PROFILE_ANCHOR="$TOOLS/profile-anchor" \
    NI_FIRSTBOOT_TPM_TEST_SYSTEM_LUKS="$TMP/system-luks" \
    NI_FIRSTBOOT_TPM_TEST_DATA_LUKS="$TMP/data-luks" \
    NI_FIRSTBOOT_TPM_TEST_ACCESS_POLICY="$MARKERS/access-policy" \
    NI_FIRSTBOOT_TPM_TEST_HARDWARE_TARGET="$MARKERS/hardware-target" \
    NI_FIRSTBOOT_TPM_TEST_TRUST_POLICY="$MARKERS/signed-boot-trust-policy-id" \
    NI_FIRSTBOOT_TPM_TEST_SYSTEMD_ANALYZE="$TOOLS/systemd-analyze" \
    NI_FIRSTBOOT_TPM_TEST_CRYPTSETUP="$TOOLS/cryptsetup" \
    NI_FIRSTBOOT_TPM_TEST_TPM2_READPUBLIC="$TOOLS/tpm2-readpublic" \
    NI_FIRSTBOOT_TPM_TEST_LUKS_EVIDENCE="$TOOLS/luks-evidence" \
    NI_FIRSTBOOT_TPM_TEST_RUN_ROOT="$RUN" \
    NI_FIRSTBOOT_TPM_TEST_OTA_STATE="$TOOLS/ota-state" \
    NI_FIRSTBOOT_TPM_TEST_OTA_VERIFY="$TOOLS/ota-verify" \
    NI_FIRSTBOOT_TPM_TEST_OTA_CONFIG="$TMP/ota.conf" \
    NI_FIRSTBOOT_TPM_TEST_OTA_PROFILE="$TMP/ota-state-profile" \
    NI_FIRSTBOOT_TPM_TEST_CANDIDATE_ROOT="$CANDIDATE" \
    NI_FIRSTBOOT_TPM_TEST_BOOTC="$TOOLS/bootc" \
    bash "$CEREMONY" "$@"
}

# --------------------------------------------------------------------------- #
# (a) STRICT reproduces the historical .67 refusal, byte-for-byte behaviour.
# --------------------------------------------------------------------------- #
build_fixture
if out="$(run_ceremony strict boot 2>&1)"; then
  fail "strict posture did not refuse a failing preseal verification"
fi
grep -Fq 'installed candidate does not match the authenticated preseal baseline' <<<"$out" \
  || fail "strict refused for the wrong reason: $out"
[[ -e "$OTA_VERIFY_CALLED" ]] || fail "strict never reached the preseal verifier"
[[ ! -e "$TPM_PREPARE_CALLED" ]] || fail "strict mutated the TPM after a preseal refusal"

# --------------------------------------------------------------------------- #
# (b) RELAXED fails open on the SAME preseal-would-die fixture: exit 0 and the
#     RELAXED marker -- AND still performs the ceremony it exists to perform.
#
#     Until 2026-09-18 this case asserted the opposite: that relaxed reached
#     neither the preseal verifier nor any TPM mutation.  That made the lever
#     indistinguishable from "do not run the ceremony", and the suite kept it
#     that way.  Every appliance built with the MVP default posture therefore
#     shipped with no access-profile anchor and no completion record, so
#     `ni-ota-verify device-policy` refused, `neural-ice-model-fetch` refused,
#     and the appliance could serve no model -- reinstalling included, since it
#     replayed the same empty ceremony (.67, 2026-09-18).
#
#     A posture is measured by what it PRODUCES, not only by what it tolerates.
# --------------------------------------------------------------------------- #
build_fixture
out="$(run_ceremony relaxed boot 2>&1)" \
  || fail "relaxed posture refused a boot it must fail open on: $out"
grep -Fq 'preseal attestation RELAXED (ADR-0050 lab-trust), continuing' <<<"$out" \
  || fail "relaxed did not log the fail-open marker: $out"
[[ -e "$OTA_VERIFY_CALLED" ]] \
  || fail "relaxed never reached the preseal verifier, so it tolerated nothing"
[[ -e "$TPM_PREPARE_CALLED" ]] \
  || fail "relaxed skipped the TPM ceremony instead of tolerating the preseal refusal"
[[ -e "$ANCHOR_ENROLLED" ]] \
  || fail "relaxed did not enrol the access-profile anchor, so no model can ever load"

# --------------------------------------------------------------------------- #
# (c) RELAXED does NOT weaken the KEEP anchors: a persistent device-root
#     mismatch still fails closed (this check runs before the fail-open exit).
# --------------------------------------------------------------------------- #
build_fixture
if out="$(NI_STUB_DEVICE_ROOT_FAIL=1 run_ceremony relaxed boot 2>&1)"; then
  fail "relaxed swallowed a persistent device-root mismatch (KEEP anchor weakened)"
fi
grep -Fq 'persistent device root does not match installer evidence' <<<"$out" \
  || fail "relaxed device-root violation refused for the wrong reason: $out"

# --------------------------------------------------------------------------- #
# (c') RELAXED still enforces the LUKS/SRK class: an SRK mismatch fails closed.
# --------------------------------------------------------------------------- #
build_fixture
printf 'tampered-srk\n' > "$STATE/srk-v1.tpm2b_public"
if out="$(run_ceremony relaxed boot 2>&1)"; then
  fail "relaxed swallowed an SRK mismatch (KEEP anchor weakened)"
fi
grep -Fq 'persistent SRK does not match installer intent' <<<"$out" \
  || fail "relaxed SRK violation refused for the wrong reason: $out"

# --------------------------------------------------------------------------- #
# A misconfigured posture value is a fail-closed configuration error.
# --------------------------------------------------------------------------- #
build_fixture
if out="$(run_ceremony bogus boot 2>&1)"; then
  fail "an invalid NEURALICE_SEALED_OTA_STATE value was accepted"
fi
grep -Fq 'NEURALICE_SEALED_OTA_STATE must be relaxed or strict' <<<"$out" \
  || fail "an invalid posture value refused for the wrong reason: $out"

echo "FIRSTBOOT_CEREMONY_FAILOPEN_OK (relaxed tolerates a preseal refusal AND still runs the ceremony, mutates the TPM and enrols the anchor; strict refuses; KEEP anchors and config validation stay fail-closed; stubs only, no TPM)"
