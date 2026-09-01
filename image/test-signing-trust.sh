#!/usr/bin/env bash
# shellcheck disable=SC2016 # literal source-contract assertions below
# THE SIGNING CERTIFICATE IS THE TRUST POLICY. `TRUST_POLICY_ID` used to be a
# caller-supplied string, and the UKI build verified the produced binary against
# the SAME certificate it had just signed it with — a tautology any self-signed
# key satisfies. A medium could therefore claim `neural-ice-secureboot-lab-v1`
# while being signed by a key that policy has never heard of, and every
# downstream comparison then agreed about a word that meant nothing.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIB="$ROOT/image/lib/signing-trust.sh"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/ni-signing-trust.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

command -v openssl >/dev/null 2>&1 \
  || fail "openssl is unavailable; this suite proves nothing without it and must not report green"

# --------------------------------------------------------------------------- #
# 1) THE REAL, IN-TREE POLICY. Its anchors are pinned by SHA-256 inside the
#    policy executable, and they must resolve through this library unchanged.
# --------------------------------------------------------------------------- #
REAL_ROOT="$ROOT/secureboot/trust-policies"
anchors="$(bash "$LIB" anchors neural-ice-secureboot-lab-v1 "$REAL_ROOT")" \
  || fail "the in-tree lab trust policy does not resolve its own anchors"
[ "$(grep -c . <<<"$anchors")" -ge 1 ] || fail "the lab trust policy resolved no anchors"
while read -r fingerprint path; do
  [[ "$fingerprint" =~ ^[0-9a-f]{64}$ ]] || fail "anchor $path produced no usable fingerprint"
done <<<"$anchors"

# An anchor IS itself: a certificate that is the policy's own anchor is approved.
ca="$REAL_ROOT/neural-ice-secureboot-lab-v1.d/neural-ice-ca.crt"
bash "$LIB" assert-cert neural-ice-secureboot-lab-v1 "$REAL_ROOT" "$ca" >/dev/null \
  || fail "the policy's own CA was not accepted as one of its anchors"

# --------------------------------------------------------------------------- #
# 2) THE REFUSAL THIS EXISTS FOR. A self-signed certificate nobody pinned must
#    not be able to produce a medium claiming a real policy.
# --------------------------------------------------------------------------- #
openssl req -x509 -newkey rsa:2048 -keyout "$TMP/rogue.key" -out "$TMP/rogue.crt" \
  -days 1 -nodes -subj "/CN=Rogue" >/dev/null 2>&1
bash "$LIB" assert-cert neural-ice-secureboot-lab-v1 "$REAL_ROOT" "$TMP/rogue.crt" >/dev/null 2>&1 \
  && fail "a certificate no policy pins was approved"

# --------------------------------------------------------------------------- #
# 3) A LEAF ISSUED BY AN ANCHOR is the ordinary production case: the CA sits in
#    db and the medium is signed by a certificate that CA issued.
# --------------------------------------------------------------------------- #
POLICY_ROOT="$TMP/policies"
POLICY_ID=neural-ice-secureboot-test-v1
mkdir -p "$POLICY_ROOT/$POLICY_ID.d"
openssl req -x509 -newkey rsa:2048 -keyout "$TMP/ca.key" -out "$TMP/ca.crt" \
  -days 1 -nodes -subj "/CN=Test CA" >/dev/null 2>&1
openssl req -newkey rsa:2048 -keyout "$TMP/leaf.key" -out "$TMP/leaf.csr" \
  -nodes -subj "/CN=Leaf" >/dev/null 2>&1
openssl x509 -req -in "$TMP/leaf.csr" -CA "$TMP/ca.crt" -CAkey "$TMP/ca.key" \
  -CAcreateserial -out "$TMP/leaf.crt" -days 1 >/dev/null 2>&1
cp "$TMP/ca.crt" "$POLICY_ROOT/$POLICY_ID.d/anchor.crt"
write_policy() { # $1=pinned sha256
  printf '#!/usr/bin/bash -p\nANCHOR_SHA256="%s"\n' "$1" > "$POLICY_ROOT/$POLICY_ID"
  chmod 0755 "$POLICY_ROOT/$POLICY_ID"
}
write_policy "$(sha256sum "$POLICY_ROOT/$POLICY_ID.d/anchor.crt" | awk '{print $1}')"
bash "$LIB" assert-cert "$POLICY_ID" "$POLICY_ROOT" "$TMP/leaf.crt" >/dev/null \
  || fail "a leaf issued by the policy's anchor was refused"
bash "$LIB" assert-cert "$POLICY_ID" "$POLICY_ROOT" "$TMP/rogue.crt" >/dev/null 2>&1 \
  && fail "a rogue certificate was approved by the test policy"

# --------------------------------------------------------------------------- #
# 4) THE ANCHOR DIRECTORY IS NOT A FREE INPUT. Swapping it for a lookalike must
#    be caught here rather than at a shim review: the policy executable pins each
#    anchor file's SHA-256, and an unpinned anchor is not this policy's anchor.
# --------------------------------------------------------------------------- #
cp "$TMP/rogue.crt" "$POLICY_ROOT/$POLICY_ID.d/anchor.crt"
bash "$LIB" anchors "$POLICY_ID" "$POLICY_ROOT" >/dev/null 2>&1 \
  && fail "an anchor the policy does not pin was accepted"
bash "$LIB" assert-cert "$POLICY_ID" "$POLICY_ROOT" "$TMP/rogue.crt" >/dev/null 2>&1 \
  && fail "a swapped anchor directory approved its own certificate"
cp "$TMP/ca.crt" "$POLICY_ROOT/$POLICY_ID.d/anchor.crt"

# A policy with no anchor directory, and one with no anchors, are both refusals.
rm -rf "$POLICY_ROOT/$POLICY_ID.d"
bash "$LIB" anchors "$POLICY_ID" "$POLICY_ROOT" >/dev/null 2>&1 \
  && fail "a policy with no anchor directory resolved anchors"
mkdir -p "$POLICY_ROOT/$POLICY_ID.d"
bash "$LIB" anchors "$POLICY_ID" "$POLICY_ROOT" >/dev/null 2>&1 \
  && fail "a policy with an EMPTY anchor directory resolved anchors"
# A policy id that is not a policy id never reaches the filesystem.
for bad in '' 'not-a-policy' '../../etc' 'neural-ice-secureboot-'; do
  bash "$LIB" anchors "$bad" "$POLICY_ROOT" >/dev/null 2>&1 \
    && fail "policy id '$bad' was resolved"
done

# --------------------------------------------------------------------------- #
# 5) FINGERPRINTS ARE OVER DER, so one certificate has one identity whether it
#    travels as PEM or as DER.
# --------------------------------------------------------------------------- #
openssl x509 -in "$TMP/ca.crt" -outform DER -out "$TMP/ca.der"
[ "$(bash "$LIB" fingerprint "$TMP/ca.crt")" = "$(bash "$LIB" fingerprint "$TMP/ca.der")" ] \
  || fail "the same certificate has two identities depending on its encoding"
printf 'not a certificate\n' > "$TMP/junk"
bash "$LIB" fingerprint "$TMP/junk" >/dev/null 2>&1 \
  && fail "a file that is not a certificate produced a fingerprint"

# --------------------------------------------------------------------------- #
# 6) THE WIRING.
# --------------------------------------------------------------------------- #
grep -Fq 'signing_trust_assert_cert "$TRUST_POLICY_ID" "$TRUST_POLICY_ROOT" "$UKI_SIGNING_CERT"' \
  "$ROOT/image/build-installer-uki.sh" \
  || fail "the UKI build does not bind its signing certificate to the named trust policy"
grep -Fq 'TRUST_POLICY_ID="$img_policy_id"' "$ROOT/image/build-installer-usb.sh" \
  || fail "the media build takes its trust policy id from somewhere other than the image"

echo "SIGNING_TRUST_TEST_OK"
