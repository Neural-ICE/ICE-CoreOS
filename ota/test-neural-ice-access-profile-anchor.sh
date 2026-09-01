#!/usr/bin/env bash
# shellcheck disable=SC2016 # literal source-contract assertions below
# THE INSTALL-TIME ACCESS-PROFILE ANCHOR (DESIGN-NOTE-0001, Finding 3).
#
# The TPM is mocked — there is none on a CI runner — but the CRYPTOGRAPHY IS
# REAL: the fake `tpm2_sign` produces a genuine ECDSA P-256 signature over the
# exact payload the helper hands it, in the raw r||s form a TPM emits, and the
# helper's own DER encoder round-trips it back for openssl. So a defect in the
# domain separation, the canonical serialisation or the r||s -> DER conversion
# fails here instead of passing a stub. Same mock-tools shape as
# ota/test-neural-ice-device-root-tpm.sh.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT/ota/neural-ice-access-profile-anchor.sh"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/ni-access-anchor.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
# 🔴 NOT A SKIP. This suite used to exit 0 when a prerequisite was missing, which
# means a runner without openssl reported the whole access-profile anchor as
# green while testing nothing at all. A missing prerequisite is a broken
# environment, and a broken environment must look like a failure -- the CI job
# installs these four explicitly.
for t in openssl python3 sha256sum base64; do
  command -v "$t" >/dev/null 2>&1 \
    || fail "$t is unavailable; this suite proves nothing without it and must not report green"
done

TOOLS="$TMP/tools"; RUN="$TMP/run"; STATE="$TMP/state"
mkdir -p "$TOOLS" "$RUN" "$STATE"

# The "TPM": one non-exportable key that only the mock tools can reach, plus a
# second one standing in for a DIFFERENT machine's device root.
openssl ecparam -name prime256v1 -genkey -noout -out "$TMP/device-root.key" 2>/dev/null
openssl ec -in "$TMP/device-root.key" -pubout -outform DER -out "$TMP/device-root.der" 2>/dev/null
openssl ecparam -name prime256v1 -genkey -noout -out "$TMP/other-machine.key" 2>/dev/null
openssl ec -in "$TMP/other-machine.key" -pubout -outform DER -out "$TMP/other-machine.der" 2>/dev/null
SPKI_SHA256="$(sha256sum "$TMP/device-root.der" | awk '{print $1}')"
DR_NAME="000b$(printf 'device-root-public-area' | sha256sum | awk '{print $1}')"

for real in python3 sha256sum base64 openssl; do
  ln -sf "$(command -v "$real")" "$TOOLS/$real"
done
cat > "$TOOLS/flock" <<'EOF'
#!/usr/bin/env bash
[[ "$1" == -x && "$2" == 9 ]]
EOF
cat > "$TOOLS/sync" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
# `tpm2_readpublic -f der -o <path>` exports the SPKI. Which key it exports is
# switchable so the suite can simulate a TPM that is not the attested one.
cat > "$TOOLS/tpm2_readpublic" <<'EOF'
#!/usr/bin/env bash
out=""
while (( $# )); do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    -c|-f|-n|-q) shift 2 ;;
    *) shift ;;
  esac
done
[[ -n "$out" ]] || exit 2
cp "$MOCK_TPM_KEY_DER" "$out"
EOF
# A real TPM emits ECDSA as raw r||s with `-f plain`. Producing exactly that
# shape is what makes the helper's DER encoder a tested component rather than an
# assumption.
cat > "$TOOLS/tpm2_sign" <<'EOF'
#!/usr/bin/env bash
out=""; message=""
while (( $# )); do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    -c|-g|-s|-f) shift 2 ;;
    -Q) shift ;;
    *) message="$1"; shift ;;
  esac
done
[[ -n "$out" && -n "$message" ]] || exit 2
[[ ! -e "$MOCK_STATE/sign-fail" ]] || exit 7
tmp="$(mktemp)"
openssl dgst -sha256 -sign "$MOCK_TPM_KEY" -out "$tmp" "$message" || exit 2
python3 - "$tmp" "$out" <<'PY'
import sys

der = open(sys.argv[1], "rb").read()
# Minimal DER SEQUENCE{INTEGER r, INTEGER s} -> the 64-byte r||s a TPM returns.
assert der[0] == 0x30
body = der[2:] if der[1] < 0x80 else der[2 + (der[1] & 0x7F):]
out = b""
index = 0
for _ in range(2):
    assert body[index] == 0x02
    length = body[index + 1]
    value = body[index + 2 : index + 2 + length].lstrip(b"\x00")
    out += value.rjust(32, b"\x00")
    index += 2 + length
open(sys.argv[2], "wb").write(out)
PY
rm -f "$tmp"
EOF
chmod +x "$TOOLS"/flock "$TOOLS"/sync "$TOOLS"/tpm2_readpublic "$TOOLS"/tpm2_sign

export NI_ACCESS_PROFILE_ANCHOR_TESTING=1
export NI_ACCESS_PROFILE_ANCHOR_TEST_TOOLS="$TOOLS"
export NI_ACCESS_PROFILE_ANCHOR_TEST_RUN_DIR="$RUN"
export MOCK_STATE="$TMP"
export MOCK_TPM_KEY="$TMP/device-root.key"
export MOCK_TPM_KEY_DER="$TMP/device-root.der"

identity() { # $1=path  [$2=name]  [$3=spki hash]
  printf '{"attributes":"fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign|noda","curve":"nist-p256","handle":"0x81010005","hierarchy":"endorsement","name":"%s","name_algorithm":"sha256","public_area_sha256":"%s","qualified_name":"%s","schema":"neural-ice-device-root-tpm-v1","scheme":"ecdsa-sha256","spki_sha256":"%s"}\n' \
    "${2:-$DR_NAME}" "${DR_NAME#000b}" "$DR_NAME" "${3:-$SPKI_SHA256}" > "$1"
  chmod 0600 "$1"
}
identity "$STATE/device-root-v1.json"
anchor() { bash "$SCRIPT" "$@"; }
TS=2026-08-31T12:00:00Z

# --------------------------------------------------------------------------- #
# 1) ENROL, then READ BACK through the same verifier the OTA path uses.
# --------------------------------------------------------------------------- #
anchor enroll "$STATE/device-root-v1.json" "$STATE" customer-locked \
  nvidia-gb10-arm64 neural-ice-secureboot-lab-v1 1 "$TS" >/dev/null \
  || fail "a well-formed enrolment was refused"
for artefact in access-profile-v1.json access-profile-v1.sig access-profile-v1.spki; do
  [ -f "$STATE/$artefact" ] || fail "enrolment did not produce $artefact"
done
[ "$(anchor verify "$STATE/device-root-v1.json" "$STATE")" = customer-locked ] \
  || fail "the anchor does not read back as what was enrolled"

# ENROLMENT IS ONCE PER INSTALLATION. An anchor that can be re-enrolled in place
# is not an anchor: it is a mutable file with a signature on it.
anchor enroll "$STATE/device-root-v1.json" "$STATE" lab-managed \
  nvidia-gb10-arm64 neural-ice-secureboot-lab-v1 2 "$TS" >/dev/null 2>&1 \
  && fail "an existing anchor was silently re-enrolled"
[ "$(anchor verify "$STATE/device-root-v1.json" "$STATE")" = customer-locked ] \
  || fail "the refused re-enrolment nonetheless changed the anchor"

# --------------------------------------------------------------------------- #
# 2) THE GATE. Matching applies; anything else is "reinstall required", exit 3.
# --------------------------------------------------------------------------- #
# --------------------------------------------------------------------------- #
# The MONOTONIC INSTALL COUNTER. It used to be an optional argument defaulting
# to zero that no production caller ever passed, while the installer wrote the
# literal sequence 1 -- so every anchor was seq 1 and every gate compared it
# with 0. The counter now comes from TPM NV and the gate READS it; this mock is
# that TPM, and moving MOCK_COUNTER is how the suite ages a machine.
# It also serves the WRITE-ONCE ACCESS-PROFILE BINDING the gate now treats as the
# profile's authority: `profile-digest` computes it, `profile-read` is what the
# machine's TPM holds, and MOCK_BOUND_PROFILE is how the suite makes a perfectly
# signed anchor disagree with the hardware (review 2026-09-01, P1 #3).
TPM_STATE_MOCK="$TMP/tpm-state"
cat > "$TPM_STATE_MOCK" <<'EOF'
#!/usr/bin/env bash
binding() { printf '%s\0%s\0%s\0%s' \
  "neural-ice:tpm:access-profile-binding:v1" "$1" "$2" "$3" \
  | sha256sum | awk '{print tolower($1)}'; }
case "${1:-}" in
  counter-read)
    [[ -z "${MOCK_COUNTER_UNREADABLE:-}" ]] || exit 1
    printf '%s\n' "${MOCK_COUNTER:-1}"
    ;;
  profile-digest) binding "$2" "$3" "$4" ;;
  profile-read)
    [[ -z "${MOCK_BINDING_UNREADABLE:-}" ]] || exit 1
    if [[ "${MOCK_BINDING_ABSENT:-}" == 1 ]]; then printf 'none\n'; exit 0; fi
    binding "${MOCK_BOUND_PROFILE:-customer-locked}" \
      "${MOCK_BOUND_TARGET:-nvidia-gb10-arm64}" \
      "${MOCK_BOUND_POLICY:-neural-ice-secureboot-lab-v1}"
    ;;
  *) exit 2 ;;
esac
EOF
chmod +x "$TPM_STATE_MOCK"
export NI_ACCESS_PROFILE_ANCHOR_TEST_TPM_STATE="$TPM_STATE_MOCK"

gate() { anchor gate "$STATE/device-root-v1.json" "$STATE" "$@" >/dev/null 2>&1; }
gate customer-locked || fail "a matching release was refused"

# 🔴 lab -> customer and customer -> lab, the two directions ADR-0014 exists for.
set +e
out="$(anchor gate "$STATE/device-root-v1.json" "$STATE" lab-managed 2>&1)"; rc=$?
set -e
[ "$rc" = 3 ] || fail "a profile-changing release did not exit 3 (got $rc)"
grep -q 'reinstall required' <<<"$out" \
  || fail "a profile-changing release was refused without the words 'reinstall required': $out"
gate developer-diagnostic && fail "a developer-diagnostic release was applied to a customer appliance"
gate wide-open && fail "an unrecognised release profile was accepted"

# --------------------------------------------------------------------------- #
# 3) REPLAY. The signature alone stops a forgery, not a REPLAY: an appliance
#    legitimately reinstalled from lab-managed to customer-locked leaves an old,
#    genuinely device-root-signed lab-managed bundle in an attacker's hands.
# --------------------------------------------------------------------------- #
MOCK_COUNTER=1 gate customer-locked \
  || fail "the anchor for this machine's current install sequence was refused"
# The machine has been reinstalled since; its TPM counter has moved on. The
# bundle is authentic and it is this machine's -- it is simply not the current
# installation, which is exactly the replay the counter exists to refuse.
MOCK_COUNTER=2 gate customer-locked \
  && fail "an anchor from a previous installation was accepted (replay)"
# An anchor claiming a sequence the TPM has never issued is a bundle from
# somewhere else, not a newer one.
MOCK_COUNTER=0 gate customer-locked \
  && fail "an anchor ahead of this machine's install counter was accepted"
# A TPM that will not answer is not permission to proceed.
MOCK_COUNTER_UNREADABLE=1 gate customer-locked \
  && fail "an unreadable install counter was treated as zero"

OLD="$TMP/old-install"; mkdir -p "$OLD"
cp "$STATE/device-root-v1.json" "$OLD/"
anchor enroll "$OLD/device-root-v1.json" "$OLD" lab-managed \
  nvidia-gb10-arm64 neural-ice-secureboot-lab-v1 1 "$TS" >/dev/null
# Genuinely signed by THIS machine's device root, and still refused for a
# customer-locked release — and refused again by sequence once the high-water
# mark has moved past it.
anchor gate "$OLD/device-root-v1.json" "$OLD" customer-locked >/dev/null 2>&1 \
  && fail "an authentic bundle from a previous installation authorised a customer release"
MOCK_COUNTER=2 anchor gate "$OLD/device-root-v1.json" "$OLD" lab-managed >/dev/null 2>&1 \
  && fail "an authentic older bundle survived the TPM install counter"

# The helper itself must be REQUIRED. An optional freshness source is one every
# caller forgets, and this one forgot for the whole life of the feature.
NI_ACCESS_PROFILE_ANCHOR_TEST_TPM_STATE="$TMP/does-not-exist" \
  anchor gate "$STATE/device-root-v1.json" "$STATE" customer-locked >/dev/null 2>&1 \
  && fail "the gate ran without any source of monotonic state"
grep -Fq 'the TPM state helper is unavailable' "$SCRIPT" \
  || fail "the anchor gate does not refuse when it cannot read the install counter"

# --------------------------------------------------------------------------- #
# 3b) THE AUTHORITY, not the signature (review 2026-09-01, P1 #3). Every check
#     above is satisfied by an anchor the DEVICE ROOT signed -- and that key has
#     an empty authorization policy, so a privileged runtime attacker can make it
#     sign a replacement anchor carrying any profile at the current counter. The
#     write-once TPM record is the thing they cannot rewrite, so the gate must
#     refuse an anchor the hardware does not back.
# --------------------------------------------------------------------------- #
MOCK_BOUND_PROFILE=lab-managed gate customer-locked \
  && fail "a device-root-signed anchor the TPM does not bind was accepted"
set +e
out="$(MOCK_BOUND_PROFILE=lab-managed anchor gate "$STATE/device-root-v1.json" "$STATE" customer-locked 2>&1)"; rc=$?
set -e
[ "$rc" = 3 ] || fail "an anchor the TPM does not bind did not exit 3 (got $rc)"
grep -q 'write-once binding in this machine' <<<"$out" \
  || fail "the refusal does not name the TPM binding: $out"
MOCK_BOUND_TARGET=some-other-box gate customer-locked \
  && fail "an anchor bound to another hardware target was accepted"
MOCK_BOUND_POLICY=neural-ice-secureboot-other-v1 gate customer-locked \
  && fail "an anchor bound under another Secure Boot trust policy was accepted"
MOCK_BINDING_ABSENT=1 gate customer-locked \
  && fail "an appliance with no TPM access-profile binding was allowed to prove what it is"
MOCK_BINDING_UNREADABLE=1 gate customer-locked \
  && fail "an unreadable TPM binding was treated as agreement"
gate customer-locked || fail "the restored good binding was refused"

# ...and the mandatory ceremony must take the sequence returned by the newly
# provisioned TPM install counter rather than from a literal. Enrollment moved
# out of the installer so owner sealing and anchor publication have one
# fail-closed readiness boundary.
AUTOINSTALL="$ROOT/ota/neural-ice-autoinstall.sh"
CEREMONY="$ROOT/ota/neural-ice-firstboot-tpm-ceremony.sh"
grep -Fq '"$TPM_STATE" ceremony-prepare' "$CEREMONY" \
  || fail "first boot does not obtain anchor evidence from the TPM ceremony"
grep -Fq 'read -r anchor_seq freshness_at binding' "$CEREMONY" \
  || fail "anchor sequence is not the ceremony install-counter value"
grep -Fq '"$TPM_STATE" ceremony-finalize' "$CEREMONY" \
  || fail "first boot does not authenticate completion before owner sealing"
grep -Fq '"$PROFILE_ANCHOR" enroll' "$CEREMONY" \
  || fail "the ceremony does not enroll the access-profile anchor"
grep -Fq '/usr/libexec/neural-ice-access-profile-anchor enroll' "$AUTOINSTALL" \
  && fail "the installer enrolls an anchor before the mandatory owner ceremony"
grep -Eq '^\s+1 "\$\(date -u \+%Y-%m-%dT%H:%M:%SZ\)" \\$' "$AUTOINSTALL" \
  && fail "the installer still enrols the literal sequence 1"

# --------------------------------------------------------------------------- #
# 4) ABSENCE AND TAMPERING. Each of these is something an attacker with offline
#    write access to /var can actually do.
# --------------------------------------------------------------------------- #
GONE="$TMP/absent"; mkdir -p "$GONE"; cp "$STATE/device-root-v1.json" "$GONE/"
set +e; out="$(anchor verify "$GONE/device-root-v1.json" "$GONE" 2>&1)"; rc=$?; set -e
[ "$rc" = 3 ] || fail "an absent anchor did not refuse with exit 3"
grep -q 'reinstall required' <<<"$out" || fail "an absent anchor refused without the right words"

tamper_case() { # $1=label  $2=mutation command over a fresh copy in $D
  D="$TMP/case-$1"; rm -rf "$D"; mkdir -p "$D"
  cp "$STATE"/access-profile-v1.* "$STATE"/device-root-v1.json "$D/"
  chmod 0600 "$D"/*
  eval "$2"
  anchor verify "$D/device-root-v1.json" "$D" >/dev/null 2>&1 \
    && fail "$1 was accepted"
  # `set -e` exempts a failing command in an AND-OR list at TOP level, but the
  # function's own non-zero return is not exempt at the call site. Verified by
  # experiment: without this the first refusal silently ends the suite as a
  # "pass". Same trap as refuse_enrol below.
  return 0
}

# The single most valuable edit an attacker can make.
tamper_case profile-flip \
  'sed -i "s/customer-locked/lab-managed   /" "$D/access-profile-v1.json"'
# Same fields, different order: identical to a human, a different byte string to
# a signature, and only one of the two was ever signed.
tamper_case reordered \
  'python3 -c "
import json,sys
d=json.load(open(sys.argv[1]))
body=\",\".join(json.dumps(k)+\":\"+json.dumps(v) for k,v in sorted(d.items(), reverse=True))
open(sys.argv[1],\"w\").write(\"{\"+body+\"}\"+chr(10))
" "$D/access-profile-v1.json"'
# The sequence, moved upward so an old bundle outranks a new one.
tamper_case seq-bump \
  'sed -i "s/\"anchor_seq\":1/\"anchor_seq\":9/" "$D/access-profile-v1.json"'
# The hardware target and the trust policy travel in the signed document too.
tamper_case target-swap \
  'sed -i "s/nvidia-gb10-arm64/some-other-boxxx/" "$D/access-profile-v1.json"'
tamper_case trust-swap \
  'sed -i "s/neural-ice-secureboot-lab-v1/neural-ice-secureboot-xxx-v9/" "$D/access-profile-v1.json"'
# A truncated or absent signature must not read as "nothing to check".
tamper_case empty-signature ': > "$D/access-profile-v1.sig"'
tamper_case corrupt-signature 'printf "not-base64!!\n" > "$D/access-profile-v1.sig"'
# 🔴 THE FULL FORGERY: rewrite the document AND re-sign it with a key of the
# attacker's choosing, then swap the stored SPKI to match. The anchor's
# device_root_spki_sha256 still names THIS machine's key, and the identity file
# — re-attested against the live TPM on every boot — still records it.
tamper_case foreign-signer '
  sed -i "s/customer-locked/lab-managed   /" "$D/access-profile-v1.json"
  { printf "%s\0" "neural-ice:ota:access-profile-anchor:v1"; head -c -1 "$D/access-profile-v1.json"; } > "$D/payload"
  openssl dgst -sha256 -sign "'"$TMP"'/other-machine.key" -out "$D/sig.der" "$D/payload"
  base64 -w0 < "$D/sig.der" > "$D/access-profile-v1.sig"
  cp "'"$TMP"'/other-machine.der" "$D/spki.der"
  base64 -w0 < "$D/spki.der" > "$D/access-profile-v1.spki"'
# ...and the same forgery with the anchor ALSO restating the foreign key hash,
# so only the device-root identity — the thing the TPM attests — still disagrees.
tamper_case foreign-signer-consistent '
  other_hash="$(sha256sum "'"$TMP"'/other-machine.der" | awk "{print \$1}")"
  sed -i "s/customer-locked/lab-managed   /; s/\"device_root_spki_sha256\":\"'"$SPKI_SHA256"'\"/\"device_root_spki_sha256\":\"$other_hash\"/" \
    "$D/access-profile-v1.json"
  { printf "%s\0" "neural-ice:ota:access-profile-anchor:v1"; head -c -1 "$D/access-profile-v1.json"; } > "$D/payload"
  openssl dgst -sha256 -sign "'"$TMP"'/other-machine.key" -out "$D/sig.der" "$D/payload"
  base64 -w0 < "$D/sig.der" > "$D/access-profile-v1.sig"
  base64 -w0 < "'"$TMP"'/other-machine.der" > "$D/access-profile-v1.spki"'

# A symlinked anchor: an attacker who cannot write the file may still be able to
# redirect it.
D="$TMP/case-symlink"; rm -rf "$D"; mkdir -p "$D"
cp "$STATE"/access-profile-v1.sig "$STATE"/access-profile-v1.spki "$STATE"/device-root-v1.json "$D/"
ln -s "$STATE/access-profile-v1.json" "$D/access-profile-v1.json"
anchor verify "$D/device-root-v1.json" "$D" >/dev/null 2>&1 \
  && fail "a symlinked anchor was accepted"

# --------------------------------------------------------------------------- #
# 5) THE ENROLLER MUST NOT PUBLISH SOMETHING THAT WILL NOT VERIFY. An anchor
#    that does not check out would, on the next upgrade, be indistinguishable
#    from tampering and would refuse "reinstall required" for a DEFECT rather
#    than an attack.
# --------------------------------------------------------------------------- #
BROKEN="$TMP/broken"; mkdir -p "$BROKEN"
identity "$BROKEN/device-root-v1.json"
MOCK_TPM_KEY="$TMP/other-machine.key" \
  anchor enroll "$BROKEN/device-root-v1.json" "$BROKEN" customer-locked \
  nvidia-gb10-arm64 neural-ice-secureboot-lab-v1 1 "$TS" >/dev/null 2>&1 \
  && fail "enrolment published an anchor signed by a key it could not verify"
[ ! -e "$BROKEN/access-profile-v1.json" ] \
  || fail "a failed enrolment left an anchor behind"

# A TPM whose exported key is not the attested identity must refuse BEFORE
# signing anything.
UNATTESTED="$TMP/unattested"; mkdir -p "$UNATTESTED"
identity "$UNATTESTED/device-root-v1.json"
MOCK_TPM_KEY_DER="$TMP/other-machine.der" \
  anchor enroll "$UNATTESTED/device-root-v1.json" "$UNATTESTED" customer-locked \
  nvidia-gb10-arm64 neural-ice-secureboot-lab-v1 1 "$TS" >/dev/null 2>&1 \
  && fail "enrolment proceeded against a device root that is not the attested identity"

# Malformed inputs refuse rather than default.
FRESH="$TMP/fresh"; mkdir -p "$FRESH"; identity "$FRESH/device-root-v1.json"
refuse_enrol() { # each argument stays a single word, so a value containing a
                 # space is tested as ONE bad value rather than as two arguments
  anchor enroll "$FRESH/device-root-v1.json" "$FRESH" "$@" >/dev/null 2>&1 \
    && fail "enrolment accepted a malformed argument vector: $*"
  return 0
}
refuse_enrol wide-open       nvidia-gb10-arm64 neural-ice-secureboot-lab-v1 1 "$TS"
refuse_enrol customer-locked 'bad target'      neural-ice-secureboot-lab-v1 1 "$TS"
refuse_enrol customer-locked nvidia-gb10-arm64 not-a-policy                 1 "$TS"
refuse_enrol customer-locked nvidia-gb10-arm64 neural-ice-secureboot-lab-v1 0 "$TS"
refuse_enrol customer-locked nvidia-gb10-arm64 neural-ice-secureboot-lab-v1 1 yesterday
refuse_enrol customer-locked nvidia-gb10-arm64 neural-ice-secureboot-lab-v1 1 "$TS" extra

# --------------------------------------------------------------------------- #
# 6) THE TEST OVERRIDE MUST NOT BE A PRODUCTION BYPASS.
# --------------------------------------------------------------------------- #
grep -Fq 'test tool override is forbidden in a privileged process' "$SCRIPT" \
  || fail "the tool override is not refused under a privileged process"
grep -Fq 'die_reinstall' "$SCRIPT" || fail "the helper has no distinct reinstall-required refusal"
# The domain MUST match the Rust verifier's, byte for byte.
grep -Fq "readonly ANCHOR_DOMAIN='neural-ice:ota:access-profile-anchor:v1'" "$SCRIPT" \
  || fail "the anchor signing domain changed without the Rust verifier"
grep -Fq 'b"neural-ice:ota:access-profile-anchor:v1\0"' \
  "$ROOT/tools/ni-ota-verify/src/access_profile_anchor.rs" \
  || fail "the Rust verifier's anchor domain does not match the helper's"

echo "ACCESS_PROFILE_ANCHOR_TEST_OK"
