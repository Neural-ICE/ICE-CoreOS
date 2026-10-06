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
#
# Mission B (owner-sealed v2 host, lane 2): an image marked
# owner-sealed-ota-state-v2 is attested by the v2 release receipt, not by a
# preseal set. The v2 checks have NO relaxed branch (docs/ota/
# V2-RELEASE-ATTESTATION.md section 9): the cases at the end of this file prove
# that a forced `relaxed` still refuses a v2-lane failure, never reaches the
# preseal verifier, and logs no RELAXED marker. The v2 verifier below is a
# contract-conformant FAKE (section 3.2 flags, exit codes and stdout); the
# real one is ni-ota-verify verify-retained-v2-release (T1).
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
printf '%s\n' "\$*" >> "$TMP/tpm-calls"
case "\$1" in
  completion-status) [ -e "$TMP/completed" ] ;;      # first boot: not complete
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
  rm -f -- "$OTA_VERIFY_CALLED" "$TPM_PREPARE_CALLED" "$ANCHOR_ENROLLED" \
    "$TMP/tpm-calls" "$TMP/completed" "$TMP/verifier-refuse" "$TMP/verifier-calls" \
    "$TMP/verifier-lie" "$TMP/verifier-swap"
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
    NI_FIRSTBOOT_TPM_TEST_OTA_VERIFY="${NI_TEST_VERIFIER:-$TOOLS/ota-verify}" \
    NI_FIRSTBOOT_TPM_TEST_RELEASE_KEY="$TMP/release-authorization.pub" \
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

# --------------------------------------------------------------------------- #
# Mission B, lane 2: the owner-sealed v2 host. Contract-conformant FAKE of
# `ni-ota-verify verify-retained-v2-release` (docs/ota/V2-RELEASE-ATTESTATION.md
# 3.2): the exact flag set (an unknown, repeated, valueless or missing flag is a
# usage error, exit 2), the receipt digest, the receipt-to-manifest/signature/key
# bindings and the live-root markers; exit 0 pass / 1 refusal / 2 usage; stdout
# {"bundle_seq":N,"receipt_sha256":HEX,"verdict":"pass"}. The ECDSA signature is
# NOT recomputed here (T1 owns the cryptography); `verifier-refuse` makes the
# fake refuse with the `signature` class, the way a bad signature would.
# --------------------------------------------------------------------------- #
cat > "$TOOLS/ota-verify-v2" <<'EOF'
#!/usr/bin/env python3
import hashlib, json, os, re, sys
calls = os.environ["NI_TEST_VERIFIER_CALLS"]
def refuse(cls, detail="fixture"):
    sys.stderr.write("ni-ota-verify: v2 release REFUSED: %s: %s\n" % (cls, detail)); sys.exit(1)
def usage(msg):
    sys.stderr.write("ni-ota-verify: usage: %s\n" % msg); sys.exit(2)
open(calls, "a").write(" ".join(sys.argv[1:]) + "\n")
if len(sys.argv) < 2 or sys.argv[1] != "verify-retained-v2-release":
    usage("unknown verb")
required = ["--manifest", "--manifest-sig", "--release-key", "--expected-receipt-sha256",
            "--receipt", "--scratch-dir"]
flags = {}
args = sys.argv[2:]
if len(args) % 2: usage("valueless flag")
for i in range(0, len(args), 2):
    k, v = args[i], args[i + 1]
    if k in flags: usage("repeated flag " + k)
    if k not in required + ["--root"]: usage("unknown flag " + k)
    flags[k] = v
for k in required:
    if k not in flags: usage("missing flag " + k)
if not re.fullmatch(r"[0-9a-f]{64}", flags["--expected-receipt-sha256"]): usage("bad digest")
if not os.path.isdir(flags["--scratch-dir"]): usage("scratch dir")
root = flags.get("--root", "/")
sha = lambda path: hashlib.sha256(open(path, "rb").read()).hexdigest()
raw = open(flags["--receipt"], "rb").read()
if hashlib.sha256(raw).hexdigest() != flags["--expected-receipt-sha256"]:
    refuse("receipt-digest")
try:
    r = json.loads(raw)
except ValueError:
    refuse("receipt-malformed")
if r.get("schema") != "neural-ice-v2-release-receipt-v1": refuse("receipt-malformed")
if sha(flags["--manifest"]) != r["manifest_sha256"]: refuse("manifest-digest")
if sha(flags["--manifest-sig"]) != r["manifest_sig_sha256"]: refuse("sig-digest")
if sha(flags["--release-key"]) != r["release_key_sha256"]: refuse("key-digest")
if os.path.exists(os.path.join(os.path.dirname(calls), "verifier-refuse")): refuse("signature")
def marker(name):
    return open(os.path.join(root, "usr/lib/neural-ice", name)).read().strip()
if marker("ota-state-profile") != "owner-sealed-ota-state-v2": refuse("candidate-marker")
for name, key in (("hardware-target", "hardware_target"), ("appliance-variant", "variant"),
                  ("signed-boot-trust-policy-id", "signed_boot_trust_policy_id"),
                  ("access-policy", "access_profile")):
    if marker(name) != r[key]: refuse("candidate-marker", name)
if os.path.exists(os.path.join(root, "etc/neural-ice/keys/ota-root.pub")): refuse("candidate-anchor")
state = os.path.dirname(calls)
seq = r["bundle_seq"] + (1 if os.path.exists(os.path.join(state, "verifier-lie")) else 0)
if os.path.exists(os.path.join(state, "verifier-swap")):
    # a swap AFTER the verification, only in a field the evidence does not carry
    r["host_repository"] = "registry.example.test/neural-ice-test/swapped"
    open(flags["--receipt"], "w").write(json.dumps(r, sort_keys=True, separators=(",", ":")) + "\n")
print(json.dumps({"bundle_seq": seq, "receipt_sha256": flags["--expected-receipt-sha256"],
                  "verdict": "pass"}, sort_keys=True, separators=(",", ":")))
EOF
chmod +x "$TOOLS/ota-verify-v2"

build_fixture_v2() { # [bundle_seq of the receipt, default 42 = the stub inspect-v2 floor]
  local seq=${1:-42} manifest_sha sig_sha key_sha
  build_fixture
  rm -rf -- "${STATE:?}/preseal-input-v1" "${STATE:?}/preseal"
  mkdir -m 0700 "$STATE/v2-release-input-v1" "$STATE/v2-release"
  printf '{"schema":"neural-ice-release-manifest-v1","bundle_seq":%s}' "$seq" \
    > "$STATE/v2-release-input-v1/release-manifest.json"
  printf 'c2lnbmF0dXJlLWZpeHR1cmU=' > "$STATE/v2-release-input-v1/release-manifest.json.sig"
  printf -- '-----BEGIN PUBLIC KEY-----\nfixture\n-----END PUBLIC KEY-----\n' > "$TMP/release-authorization.pub"
  manifest_sha="$(sha256sum "$STATE/v2-release-input-v1/release-manifest.json" | awk '{print $1}')"
  sig_sha="$(sha256sum "$STATE/v2-release-input-v1/release-manifest.json.sig" | awk '{print $1}')"
  key_sha="$(sha256sum "$TMP/release-authorization.pub" | awk '{print $1}')"
  python3 - "$STATE/v2-release/receipt.json" "$seq" "$manifest_sha" "$sig_sha" "$key_sha" \
    "$PROFILE" "$TARGET" "$POLICY" <<'PY'
import json, sys
path, seq, m, sg, k, profile, target, policy = sys.argv[1:]
r = {"access_profile": profile, "bundle_seq": int(seq), "hardware_target": target,
     "host_index_digest": "sha256:" + "a1" * 32, "host_manifest_digest": "sha256:" + "b2" * 32,
     "host_repository": "registry.example.test/neural-ice-test/host-appliance",
     "manifest_sha256": m, "manifest_sig_sha256": sg, "release_id": "v2-test-train-3",
     "release_key_sha256": k, "schema": "neural-ice-v2-release-receipt-v1",
     "seal": {"min_bundle_seq": None, "mode": "manifest-digest", "sealed_manifest_sha256": m},
     "signed_boot_trust_policy_id": policy, "variant": "sealed-lab"}
open(path, "w").write(json.dumps(r, sort_keys=True, separators=(",", ":")) + "\n")
PY
  chmod 0600 "$STATE/v2-release-input-v1"/* "$STATE/v2-release/receipt.json"
  # the install identity binds the manifest (release_identity_sha256 == manifest_sha256)
  printf '{"install_source":"medium","installed_at":"1970-01-01T00:00:00Z","installer_sealed_identity_sha256":"%s","release_identity_sha256":"%s","schema":"neural-ice-owner-ceremony-install-identity-v1"}\n' \
    "$ZERO64" "$manifest_sha" > "$STATE/owner-ceremony-install-identity-v1.json"
  # the v2 image marker and the live root the verifier re-reads
  printf 'owner-sealed-ota-state-v2\n' > "$TMP/ota-state-profile"
  rm -rf -- "${CANDIDATE:?}"
  mkdir -p "$CANDIDATE/usr/lib/neural-ice/keys"
  printf '%s\n' "$PROFILE" > "$CANDIDATE/usr/lib/neural-ice/access-policy"
  printf '%s\n' "$TARGET" > "$CANDIDATE/usr/lib/neural-ice/hardware-target"
  printf '%s\n' "$POLICY" > "$CANDIDATE/usr/lib/neural-ice/signed-boot-trust-policy-id"
  printf 'sealed-lab\n' > "$CANDIDATE/usr/lib/neural-ice/appliance-variant"
  printf 'owner-sealed-ota-state-v2\n' > "$CANDIDATE/usr/lib/neural-ice/ota-state-profile"
  cp "$TMP/release-authorization.pub" "$CANDIDATE/usr/lib/neural-ice/keys/release-authorization.pub"
}
run_v2() { NI_TEST_VERIFIER="$TOOLS/ota-verify-v2" NI_TEST_VERIFIER_CALLS="$TMP/verifier-calls" run_ceremony "$@"; }
verifier_verbs() { awk '{print $1}' "$TMP/verifier-calls" 2>/dev/null | tr '\n' ' '; }
evidence_field() { # <python expression over d>
  python3 - "$STATE/owner-ceremony-evidence-v2.json" "$1" <<'PY'
import json, sys
d = json.load(open(sys.argv[1])); print(eval(sys.argv[2]))
PY
}
expect_v2_refusal() { # <label> <fragment> <posture> [args...]  (against the current fixture)
  local label=$1 fragment=$2 posture=$3
  shift 3
  if out="$(run_v2 "$posture" "$@" 2>&1)"; then fail "$label: the v2 lane accepted it ($posture)"; fi
  grep -Fq "$fragment" <<<"$out" || fail "$label: refused for the wrong reason ($posture): $out"
  if grep -Fq RELAXED <<<"$out"; then fail "$label: the v2 lane logged a RELAXED fail-open ($posture): $out"; fi
  [[ ! -e "$TPM_PREPARE_CALLED" ]] || fail "$label: the TPM was mutated after a v2-lane refusal ($posture)"
  [[ ! -e "$ANCHOR_ENROLLED" ]] || fail "$label: the anchor was enrolled after a v2-lane refusal ($posture)"
  # the preseal attestation does not exist on this lane: it is never consulted
  [[ ! -e "$OTA_VERIFY_CALLED" ]] || fail "$label: the v1 preseal verifier was consulted on the v2 lane"
}

# (d) strict, healthy v2 host: the ceremony completes with lane-2 evidence and
#     authenticates through the v2 verifier only.
build_fixture_v2
out="$(run_v2 strict boot 2>&1)" || fail "strict refused a healthy owner-sealed v2 first boot: $out"
[[ "$(verifier_verbs)" == "verify-retained-v2-release verify-retained-v2-release " ]] \
  || fail "the v2 lane did not authenticate twice through the v2 verifier (before and after finalization): $(verifier_verbs)"
[[ ! -e "$OTA_VERIFY_CALLED" ]] || fail "the v2 lane consulted the v1 preseal verifier"
if grep -Fq 'bootstrap-from-preseal' "$TMP/verifier-calls"; then fail "the v2 lane seeded a v1 OTA baseline"; fi
[[ -e "$TPM_PREPARE_CALLED" && -e "$ANCHOR_ENROLLED" ]] || fail "the v2 lane did not run the owner ceremony"
grep -Eq '^ceremony-prepare-v2 customer-locked nvidia-gb10-arm64 neural-ice-secureboot-lab-v1 1 42$' "$TMP/tpm-calls" \
  || fail "the floor given to ceremony-prepare-v2 is not the receipt bundle_seq: $(grep ceremony-prepare "$TMP/tpm-calls")"
grep -Fq -- "--root $CANDIDATE" "$TMP/verifier-calls" \
  || fail "the test seam did not hand the candidate root to the verifier"
[[ "$(evidence_field 'd["schema"]')" == neural-ice-owner-ceremony-evidence-v2-lane2 ]] \
  || fail "the v2 lane wrote the wrong evidence schema"
[[ "$(evidence_field '"ota_preseal" in d')" == False ]] || fail "lane-2 evidence still carries ota_preseal"
[[ "$(evidence_field 'sorted(d["v2_release"])')" == "['bundle_seq', 'manifest_sha256', 'manifest_sig_sha256', 'receipt_schema', 'receipt_sha256', 'release_id', 'release_key_sha256']" ]] \
  || fail "lane-2 v2_release is not the closed contract object"
[[ "$(evidence_field 'd["v2_release"]["bundle_seq"] == d["ota_state"]["baseline_floor"] == 42')" == True ]] \
  || fail "baseline_floor != v2_release.bundle_seq"
[[ "$(evidence_field 'd["v2_release"]["receipt_sha256"]')" == "$(sha256sum "$STATE/v2-release/receipt.json" | awk '{print $1}')" ]] \
  || fail "v2_release.receipt_sha256 is not the digest of the persisted receipt"
[[ "$(evidence_field 'd["install_identity"]["release_identity_sha256"] == d["v2_release"]["manifest_sha256"]')" == True ]] \
  || fail "release_identity_sha256 != manifest_sha256"
# the second boot revalidates the TPM-bound evidence through the retained verifier
: > "$TMP/completed"; rm -f "$TMP/verifier-calls"
[[ "$(run_v2 strict status 2>&1)" == complete ]] || fail "strict second boot did not revalidate the v2 completion"
[[ "$(verifier_verbs)" == "verify-retained-v2-release " ]] || fail "second boot did not use the retained v2 verifier: $(verifier_verbs)"

# (e) a failing v2 verifier is a refusal in strict AND in relaxed -- relaxed is
#     a v1-only posture: forcing it changes nothing for the v2 lane.
for posture in strict relaxed; do
  build_fixture_v2
  : > "$TMP/verifier-refuse"
  expect_v2_refusal "failing v2 verifier" 'v2 release attestation' "$posture" boot
  [[ -e "$TMP/verifier-calls" ]] || fail "the v2 verifier was never reached ($posture)"
done

# (f) relaxed on a healthy v2 host: no RELAXED marker, same lane-2 completion.
build_fixture_v2
out="$(run_v2 relaxed boot 2>&1)" || fail "relaxed refused a healthy owner-sealed v2 first boot: $out"
if grep -Fq RELAXED <<<"$out"; then fail "relaxed logged a fail-open on a healthy v2 lane: $out"; fi
[[ "$(evidence_field 'd["schema"]')" == neural-ice-owner-ceremony-evidence-v2-lane2 ]] \
  || fail "relaxed wrote the wrong evidence schema on the v2 lane"

# (g) every v2 input is mandatory, in both postures, before any TPM mutation.
for posture in strict relaxed; do
  for missing in v2-release-input-v1/release-manifest.json v2-release-input-v1/release-manifest.json.sig v2-release/receipt.json; do
    build_fixture_v2
    rm -f -- "${STATE:?}/${missing:?}"
    expect_v2_refusal "missing $missing" 'v2 release' "$posture" boot
  done
  build_fixture_v2
  rm -f -- "${TMP:?}/release-authorization.pub"
  expect_v2_refusal "missing release key" 'v2 release' "$posture" boot
  build_fixture_v2
  rm -rf -- "${STATE:?}/v2-release-input-v1" "${STATE:?}/v2-release"
  expect_v2_refusal "preseal-less v2 host without v2 inputs" 'v2 release' "$posture" boot
done

# (h) a receipt that is not the one the installer persisted (not bound to its
#     manifest, manifest swapped, wrong markers on the live root) never reaches
#     the TPM, in either posture.
for posture in strict relaxed; do
  build_fixture_v2
  python3 - "$STATE/v2-release/receipt.json" <<'PY'
import json, sys
p = sys.argv[1]; r = json.loads(open(p).read()); r["manifest_sha256"] = "0" * 64
open(p, "w").write(json.dumps(r, sort_keys=True, separators=(",", ":")) + "\n")
PY
  expect_v2_refusal "receipt not bound to its manifest" 'v2 release' "$posture" boot
  build_fixture_v2
  printf 'tampered' >> "$STATE/v2-release-input-v1/release-manifest.json"
  expect_v2_refusal "manifest swapped after the install" 'v2 release' "$posture" boot
  build_fixture_v2
  printf 'legacy-unmarked\n' > "$CANDIDATE/usr/lib/neural-ice/ota-state-profile"
  expect_v2_refusal "live root without the v2 lane marker" 'v2 release' "$posture" boot
done

# (i) the lane is selected by the immutable image marker and cross-checked
#     against the evidence: no cross-lane reading, either way.
build_fixture_v2
printf 'owner-sealed-ota-state-v1\n' > "$TMP/ota-state-profile"
if out="$(run_v2 strict boot 2>&1)"; then fail "a v1 marker was accepted with v2 inputs and no preseal set"; fi
grep -Fq 'preseal input directory is unsafe or absent' <<<"$out" \
  || fail "a v1 marker did not demand the preseal set: $out"
[[ ! -e "$TPM_PREPARE_CALLED" ]] || fail "the v1 lane mutated the TPM without a preseal set"
build_fixture_v2
run_v2 strict boot >/dev/null 2>&1 || fail "fixture boot (lane-2 evidence for the cross-lane case) failed"
: > "$TMP/completed"
printf 'owner-sealed-ota-state-v1\n' > "$TMP/ota-state-profile"
if out="$(run_v2 strict status 2>&1)"; then fail "lane-2 evidence was accepted under a v1 marker"; fi
grep -Fq 'completion evidence lane differs from the immutable OTA state profile' <<<"$out" \
  || fail "lane-2 evidence under a v1 marker refused for the wrong reason: $out"
printf 'owner-sealed-ota-state-v2\n' > "$TMP/ota-state-profile"
python3 - "$STATE/owner-ceremony-evidence-v2.json" <<'PY'
import json, sys
p = sys.argv[1]; d = json.load(open(p))
d["ota_preseal"] = {"receipt_schema": "neural-ice-ota-preseal-receipt-v1", "receipt_sha256": "0" * 64, "set_sha256": "0" * 64}
d["schema"] = "neural-ice-owner-ceremony-evidence-v2"; d.pop("v2_release")
open(p, "w").write(json.dumps(d, sort_keys=True, separators=(",", ":")) + "\n")
PY
for posture in strict relaxed; do
  if out="$(run_v2 "$posture" status 2>&1)"; then fail "preseal evidence was accepted under a v2 marker ($posture)"; fi
  grep -Fq 'completion evidence lane differs from the immutable OTA state profile' <<<"$out" \
    || fail "preseal evidence under a v2 marker refused for the wrong reason ($posture): $out"
  if grep -Fq RELAXED <<<"$out"; then fail "a v2-marker/preseal-evidence mismatch fell open ($posture): $out"; fi
done

# (j) retained validation: a refusing verifier, a receipt that no longer matches
#     the TPM-bound digest and altered evidence all refuse, in relaxed too.
#     Evidence is rebuilt from authenticated inputs and compared byte-exact.
build_fixture_v2
run_v2 strict boot >/dev/null 2>&1 || fail "fixture boot for retained validation failed"
: > "$TMP/completed"
cp "$STATE/owner-ceremony-evidence-v2.json" "$TMP/evidence.good"
cp "$STATE/v2-release/receipt.json" "$TMP/receipt.good"
for posture in strict relaxed; do
  : > "$TMP/verifier-refuse"
  if out="$(run_v2 "$posture" status 2>&1)"; then fail "retained v2 validation fell open on a refusing verifier ($posture)"; fi
  if grep -Fq RELAXED <<<"$out"; then fail "retained v2 validation logged RELAXED ($posture)"; fi
  rm -f "$TMP/verifier-refuse"
  printf '\n' >> "$STATE/v2-release/receipt.json"
  if out="$(run_v2 "$posture" status 2>&1)"; then fail "a receipt that is not the TPM-bound one was accepted ($posture)"; fi
  cp "$TMP/receipt.good" "$STATE/v2-release/receipt.json"
  python3 - "$STATE/owner-ceremony-evidence-v2.json" <<'PY'
import json, sys
p = sys.argv[1]; d = json.load(open(p)); d["v2_release"]["bundle_seq"] = 41
open(p, "w").write(json.dumps(d, sort_keys=True, separators=(",", ":")) + "\n")
PY
  if out="$(run_v2 "$posture" status 2>&1)"; then fail "altered v2 evidence was accepted ($posture)"; fi
  cp "$TMP/evidence.good" "$STATE/owner-ceremony-evidence-v2.json"
  [[ "$(run_v2 "$posture" status 2>&1)" == complete ]] || fail "the restored v2 completion no longer validates ($posture)"
done

# (j2) the verdict is cross-checked, and the receipt is the one that was verified:
#      a verifier that answers another bundle_seq, or a receipt swapped after the
#      verification, are refusals in both postures.
for posture in strict relaxed; do
  : > "$TMP/verifier-lie"
  if out="$(run_v2 "$posture" status 2>&1)"; then fail "a verdict bundle_seq different from the completion floor was accepted ($posture)"; fi
  grep -Fq 'differs from the authenticated completion floor' <<<"$out" \
    || fail "verdict/floor mismatch refused for the wrong reason ($posture): $out"
  rm -f "$TMP/verifier-lie"
  : > "$TMP/verifier-swap"
  if out="$(run_v2 "$posture" status 2>&1)"; then fail "a receipt swapped after its verification was accepted ($posture)"; fi
  grep -Fq 'cannot reconstruct canonical v2 lane-2 completion evidence' <<<"$out" \
    || fail "receipt swap refused for the wrong reason ($posture): $out"
  cp "$TMP/receipt.good" "$STATE/v2-release/receipt.json"
  rm -f "$TMP/verifier-swap"
done

# (j3) the install identity must name the manifest, and that is judged BEFORE the
#      one-time TPM mutation (the floor is write-locked for good).
for posture in strict relaxed; do
  build_fixture_v2
  printf '{"install_source":"medium","installed_at":"1970-01-01T00:00:00Z","installer_sealed_identity_sha256":"%s","release_identity_sha256":"%s","schema":"neural-ice-owner-ceremony-install-identity-v1"}\n' \
    "$ZERO64" "$ZERO64" > "$STATE/owner-ceremony-install-identity-v1.json"
  expect_v2_refusal "install identity not bound to the manifest" 'release identity' "$posture" boot
done

# (j4) the installer identity as a whole is judged before the one-time TPM
#      mutation too, not only its release digest: a non-canonical document, a
#      timestamp that is not the installer stamp and a non-medium source all
#      refuse with the TPM untouched (expect_v2_refusal asserts no prepare/enroll).
write_identity() { # <source> <installed_at> [raw-suffix]
  local manifest_sha; manifest_sha="$(sha256sum "$STATE/v2-release-input-v1/release-manifest.json" | awk '{print $1}')"
  printf '{"install_source":"%s","installed_at":"%s","installer_sealed_identity_sha256":"%s","release_identity_sha256":"%s","schema":"neural-ice-owner-ceremony-install-identity-v1"}\n%s' \
    "$1" "$2" "$ZERO64" "$manifest_sha" "${3:-}" > "$STATE/owner-ceremony-install-identity-v1.json"
}
for posture in strict relaxed; do
  build_fixture_v2
  write_identity medium 1970-01-01T00:00:00Z
  printf '{"schema":"neural-ice-owner-ceremony-install-identity-v1", "install_source":"medium"}\n' > "$TMP/noncanonical.json"
  cp "$TMP/noncanonical.json" "$STATE/owner-ceremony-install-identity-v1.json"; chmod 0600 "$STATE/owner-ceremony-install-identity-v1.json"
  expect_v2_refusal "non-closed install identity" 'installer identity is not canonical' "$posture" boot
  build_fixture_v2
  write_identity medium 1970-01-01T00:00:00Z ' '
  chmod 0600 "$STATE/owner-ceremony-install-identity-v1.json"
  expect_v2_refusal "non-canonical install identity bytes" 'installer identity is not canonical' "$posture" boot
  build_fixture_v2
  write_identity medium 2099-12-31T23:59:59Z; chmod 0600 "$STATE/owner-ceremony-install-identity-v1.json"
  expect_v2_refusal "installed_at is not the installer stamp" 'v2 medium identity' "$posture" boot
  build_fixture_v2
  write_identity registry 1970-01-01T00:00:00Z; chmod 0600 "$STATE/owner-ceremony-install-identity-v1.json"
  expect_v2_refusal "registry source on the v2 lane" 'v2 medium identity' "$posture" boot
  build_fixture_v2
  write_identity medium 1970-01-01T00:00:00Z; chmod 0600 "$STATE/owner-ceremony-install-identity-v1.json"
  sed -i 's/1970-01-01T00:00:00Z/1970-13-99/' "$STATE/owner-ceremony-install-identity-v1.json"
  expect_v2_refusal "malformed installed_at" 'installer identity is not canonical' "$posture" boot
done

# (k) the floor is the receipt's bundle_seq: when the TPM reports another floor
#     (inspect-v2 says 42, the receipt 41) the ceremony refuses even in relaxed.
for posture in strict relaxed; do
  build_fixture_v2 41
  if out="$(run_v2 "$posture" boot 2>&1)"; then fail "a TPM floor different from the receipt bundle_seq was accepted ($posture)"; fi
  if grep -Fq RELAXED <<<"$out"; then fail "a floor mismatch fell open ($posture): $out"; fi
  grep -Fq 'owner state is not protected at the signed floor' <<<"$out" \
    || fail "floor mismatch refused for the wrong reason ($posture): $out"
done

echo "FIRSTBOOT_CEREMONY_FAILOPEN_OK (relaxed tolerates a preseal refusal AND still runs the ceremony, mutates the TPM and enrols the anchor; strict refuses; KEEP anchors and config validation stay fail-closed; stubs only, no TPM; the v2 lane refuses even under relaxed)"
