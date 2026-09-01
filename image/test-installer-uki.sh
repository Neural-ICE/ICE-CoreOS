#!/usr/bin/env bash
# shellcheck disable=SC2016 # literal source-contract assertions below
# THE SEALED INSTALLER UKI BUILD: deterministic outputs, and refusals that fire
# at build time where refusing is free.
#
# objcopy/objdump and sbsign are mocked: the point of this suite is
# that the BUILD is a function of its inputs alone, and that is asserted on the
# arguments the builder computes rather than on 40 MiB of PE. The mocks record
# what they were asked to do, so a change to the section layout, the salt or the
# cmdline shows up as a one-line diff.
#
# NOTHING HERE SIGNS WITH A REAL KEY, and the unsigned path is the default.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="$ROOT/image/build-installer-uki.sh"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/ni-uki.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

TOOLS="$TMP/tools"; mkdir -p "$TOOLS"
ln -sf "$(command -v sha256sum)" "$TOOLS/sha256sum"
ln -sf "$(command -v awk)" "$TOOLS/awk" 2>/dev/null || true

# The stub's image extent. Fixed, so the computed offsets are reproducible.
cat > "$TOOLS/objdump" <<'EOF'
#!/usr/bin/env bash
printf 'Sections:\nIdx Name          Size      VMA\n'
printf '  0 .text         00001000  00001000  00001000  00000200  2**4\n'
EOF
cat > "$TOOLS/objcopy" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$MOCK_STATE/objcopy.args"
out="${*: -1}"
printf 'mock-uki\n' > "$out"
EOF
cat > "$TOOLS/sbsign" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$MOCK_STATE/sbsign.args"
out=""
while (( $# )); do case "$1" in --output) out="$2"; shift 2 ;; *) shift ;; esac; done
printf 'mock-signed-uki\n' > "$out"
EOF
cat > "$TOOLS/sbverify" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$MOCK_STATE/sbverify.args"
exit 0
EOF
chmod +x "$TOOLS"/objdump "$TOOLS"/objcopy "$TOOLS"/sbsign "$TOOLS"/sbverify

IN="$TMP/in"; mkdir -p "$IN"
printf 'vmlinuz-bytes\n'   > "$IN/vmlinuz"
printf 'initramfs-bytes\n' > "$IN/initrd"
printf 'stub-bytes\n'      > "$IN/stub.efi"
printf 'NAME="Neural ICE"\n' > "$IN/os-release"
# The two values image/build-installer-payload.sh computes and this build SEALS.
# They are inputs here, not outputs: the object they describe already exists and
# is already hashed, so this build cannot silently sign a different one.
ROOT_VERITY_HASH="$(printf 'installer-root-image-bytes' | sha256sum | awk '{print $1}')"
PAYLOAD_DIGEST="$(printf 'installer-payload-header' | sha256sum | awk '{print $1}')"
printf -- '-----BEGIN PUBLIC KEY-----\ntestkey\n-----END PUBLIC KEY-----\n' > "$IN/relauth.pub"
KEYID="$(sha256sum "$IN/relauth.pub" | awk '{print $1}')"
# The measured-identity list for the sealed hardware target. A target no machine
# can be measured against is a word, not a binding, so the build refuses without
# one -- and this fixture is what proves that refusal is wired up.
printf '# measured on the reference appliance\n%s\n' \
  "$(printf 'devicetree:nvidia,gb10' | sha256sum | awk '{print $1}')" > "$IN/gb10.fingerprints"

# A throwaway trust policy that PINS a throwaway certificate. TRUST_POLICY_ID
# used to be a caller-supplied caption and the signing branch verified the
# binary against the same certificate it had just signed it with -- a tautology
# any self-signed key satisfies.
POLICY_ROOT="$TMP/trust-policies"
POLICY_ID=neural-ice-secureboot-test-v1
mkdir -p "$POLICY_ROOT/$POLICY_ID.d"
if command -v openssl >/dev/null 2>&1; then
  openssl req -x509 -newkey rsa:2048 -keyout "$TMP/uki.key" -out "$TMP/uki.crt" \
    -days 1 -nodes -subj "/CN=Neural ICE test UKI" >/dev/null 2>&1
  cp "$TMP/uki.crt" "$POLICY_ROOT/$POLICY_ID.d/anchor.crt"
  printf '#!/usr/bin/bash -p\nANCHOR_SHA256="%s"\n' \
    "$(sha256sum "$POLICY_ROOT/$POLICY_ID.d/anchor.crt" | awk '{print $1}')" \
    > "$POLICY_ROOT/$POLICY_ID"
  chmod 0755 "$POLICY_ROOT/$POLICY_ID"
  HAVE_OPENSSL=1
else
  HAVE_OPENSSL=0
fi

export NI_UKI_TESTING=1 NI_UKI_TEST_TOOLS="$TOOLS"
build() { # $1=output dir, rest=env overrides as VAR=value
  local out=$1; shift
  mkdir -p "$out"
  env MOCK_STATE="$out" \
    KERNEL="$IN/vmlinuz" INITRD="$IN/initrd" STUB="$IN/stub.efi" OSREL="$IN/os-release" \
    ROOT_VERITY_HASH="$ROOT_VERITY_HASH" PAYLOAD_DIGEST="$PAYLOAD_DIGEST" \
    VARIANT=prod HARDWARE_TARGET=nvidia-gb10-arm64 \
    HARDWARE_IDENTITY_FILE="$IN/gb10.fingerprints" \
    TRUST_POLICY_ID=neural-ice-secureboot-lab-v1 \
    TRUST_POLICY_ROOT="$ROOT/secureboot/trust-policies" \
    RELEASE_AUTH_PUBKEY="$IN/relauth.pub" \
    UKI_OUT="$out/installer.efi" \
    "$@" bash "$BUILD"
}

# --------------------------------------------------------------------------- #
# 1) DETERMINISM. Two builds of identical inputs must produce identical
#    manifests. Without this nobody can tell a rebuild from a substitution.
# --------------------------------------------------------------------------- #
build "$TMP/a" >/dev/null || fail "the first build failed"
build "$TMP/b" >/dev/null || fail "the second build failed"
# The manifest names its own output path; compare everything else.
diff <(grep -v '^section\.' "$TMP/a/installer.efi.manifest") \
     <(grep -v '^section\.' "$TMP/b/installer.efi.manifest") \
  || fail "the UKI build manifest is not reproducible"
diff "$TMP/a/installer.efi.manifest" "$TMP/b/installer.efi.manifest" \
  || fail "the UKI section layout is not reproducible"
# The objcopy ARGUMENT ORDER and the computed addresses must be reproducible.
# Absolute paths are normalised to basenames first: the scratch directory and
# the output path are properties of where the build ran, not of what it built,
# and pinning them would make this assertion fail for the wrong reason.
strip_paths() { sed -E 's#(=| )/[^ ]*/([^/ ]+)#\1\2#g' "$1"; }
diff <(strip_paths "$TMP/a/objcopy.args") <(strip_paths "$TMP/b/objcopy.args") \
  || fail "the objcopy invocation is not reproducible"

manifest="$TMP/a/installer.efi.manifest"
grep -qx 'access_profile=customer-locked' "$manifest" \
  || fail "the manifest does not record the DERIVED access profile"
grep -qx 'variant=prod' "$manifest" || fail "the manifest does not record the variant"
grep -qx 'signed=no' "$manifest" || fail "an unsigned build did not say so"
grep -qx "relauth_keyid=$KEYID" "$manifest" \
  || fail "the manifest does not pin the release-authorization key identity"
grep -qx 'release_authorization_schema=neural-ice-installer-release-authorization-v2' "$manifest" \
  || fail "the manifest does not pin the exact release-authorization schema"
grep -q '^verity_root_hash=[0-9a-f]\{64\}$' "$manifest" \
  || fail "the manifest carries no verity root hash"
grep -q "^payload_header_sha256=$PAYLOAD_DIGEST\$" "$manifest" \
  || fail "the manifest does not record the sealed payload header digest"
# 🔴 THE UKI NO LONGER FORMATS VERITY ITSELF (review 2026-09-01, P0 #1). It used
# to, which made the protected extent a side effect of the signing step and left
# no room for the SECOND protected extent a medium carries. Assert the removal:
# a builder that still ran veritysetup would be deciding what it signs.
if grep -vE '^[[:space:]]*#' "$BUILD" | grep -q 'veritysetup'; then
  fail "the UKI builder still formats dm-verity; the payload builder owns that"
fi

# The cmdline in the manifest must BE the sealed anchor, and must parse as one.
CMDLINE="$(sed -n 's/^cmdline=//p' "$manifest")"
bash "$ROOT/image/lib/installer-trust.sh" read-sealed "$CMDLINE" >/dev/null \
  || fail "the manifest's cmdline does not parse as a sealed trust anchor"
[ "$(bash "$ROOT/image/lib/installer-trust.sh" field neuralice.access_profile "$CMDLINE")" = customer-locked ] \
  || fail "the sealed cmdline does not carry the derived access profile"
[ "$(bash "$ROOT/image/lib/installer-trust.sh" field neuralice.relauth_schema "$CMDLINE")" = neural-ice-installer-release-authorization-v2 ] \
  || fail "the sealed cmdline does not require the v2 release-authorization contract"
[ "$(bash "$ROOT/image/lib/installer-trust.sh" field neuralice.rootverity "$CMDLINE")" \
  = "$(sed -n 's/^verity_root_hash=//p' "$manifest")" ] \
  || fail "the sealed cmdline and the manifest disagree about the verity root hash"
# 🔴 AND THE PAYLOAD DIGEST IS SEALED TOO. One signed value binds every extent on
# the medium -- root image, root hash tree, container store image and its hash
# tree -- transitively, through the header it names.
[ "$(bash "$ROOT/image/lib/installer-trust.sh" field neuralice.payload "$CMDLINE")" \
  = "$PAYLOAD_DIGEST" ] \
  || fail "the sealed cmdline does not carry the payload header digest"

# --------------------------------------------------------------------------- #
# 2) THE INITRAMFS AND THE CMDLINE MUST BE INSIDE THE SIGNED BINARY. That is the
#    entire difference between Design A and Design B: an initrd the signature
#    does not cover makes the verifying key as editable as the thing it verifies.
# --------------------------------------------------------------------------- #
args="$(cat "$TMP/a/objcopy.args")"
for section in .osrel .cmdline .linux .initrd; do
  grep -Fq -- "--add-section $section=" <<<"$args" \
    || fail "the UKI does not embed the $section section"
done
# Section addresses must be computed and page-aligned, not left to objcopy.
grep -Fq -- '--change-section-vma .cmdline=' <<<"$args" \
  || fail "the UKI does not place .cmdline at a computed address"
while read -r off; do
  (( off % 4096 == 0 )) || fail "a UKI section is placed at unaligned offset $off"
done < <(sed -n 's/^section\.[a-z]*=offset:\([0-9]*\),.*/\1/p' "$manifest")

# --------------------------------------------------------------------------- #
# 3) THE ROOT HASH MUST FOLLOW THE ROOT IMAGE. A build that sealed a stale hash
#    would produce a medium that refuses to boot — or worse, one whose hash
#    describes a tree it is not standing on.
# --------------------------------------------------------------------------- #
OTHER_ROOT_HASH="$(printf 'a-different-installer-root' | sha256sum | awk '{print $1}')"
OTHER_PAYLOAD="$(printf 'a-different-payload-header' | sha256sum | awk '{print $1}')"
build "$TMP/c" ROOT_VERITY_HASH="$OTHER_ROOT_HASH" >/dev/null || fail "the third build failed"
[ "$(sed -n 's/^verity_root_hash=//p' "$TMP/c/installer.efi.manifest")" \
  != "$(sed -n 's/^verity_root_hash=//p' "$manifest")" ] \
  || fail "changing the installer root hash did not change the sealed cmdline"
build "$TMP/d" PAYLOAD_DIGEST="$OTHER_PAYLOAD" >/dev/null || fail "the fourth build failed"
[ "$(sed -n 's/^cmdline=//p' "$TMP/d/installer.efi.manifest")" \
  != "$(sed -n 's/^cmdline=//p' "$manifest")" ] \
  || fail "changing the sealed payload digest did not change the sealed cmdline"
# Malformed sealed values are refused at build time, where refusing is free.
build "$TMP/badroot" ROOT_VERITY_HASH=deadbeef >/dev/null 2>&1 \
  && fail "a malformed verity root hash was sealed"
build "$TMP/badpayload" PAYLOAD_DIGEST=not-a-digest >/dev/null 2>&1 \
  && fail "a malformed payload digest was sealed"

# --------------------------------------------------------------------------- #
# 4) THE PROFILE IS DERIVED, NEVER PASSED IN, and an unknown variant refuses.
# --------------------------------------------------------------------------- #
build "$TMP/lab" VARIANT=sealed-lab >/dev/null || fail "the sealed-lab build failed"
grep -qx 'access_profile=lab-managed' "$TMP/lab/installer.efi.manifest" \
  || fail "sealed-lab did not derive lab-managed"
build "$TMP/bad" VARIANT=wide-open >/dev/null 2>&1 \
  && fail "an unknown variant produced a UKI"
grep -Fq 'ACCESS_PROFILE="$(access_policy_for_variant "$VARIANT")"' "$BUILD" \
  || fail "the builder does not derive the profile from the single source of truth"
grep -Fq 'ARG SIGNED_BOOT_TRUST_POLICY_ID' "$ROOT/image/Containerfile.bootc" \
  || fail "the image build does not declare its Secure Boot trust policy"

# --------------------------------------------------------------------------- #
# 5) SIGNING IS OPT-IN, AND HALF A KEY IS A REFUSAL. A build that quietly
#    emitted an unsigned binary where a signed one was asked for is the failure
#    mode this branch exists to prevent.
# --------------------------------------------------------------------------- #
printf 'not-a-real-key\n' > "$TMP/fake.key"
printf 'not-a-real-cert\n' > "$TMP/fake.crt"
build "$TMP/half" UKI_SIGNING_KEY="$TMP/fake.key" >/dev/null 2>&1 \
  && fail "a build with a key but no certificate produced a UKI"
# 🔴 A CERTIFICATE THE NAMED POLICY DOES NOT APPROVE MUST NOT PRODUCE A MEDIUM.
# This used to succeed: the build verified the binary against the very cert it
# had just signed it with, so any file could claim any trust policy.
build "$TMP/unapproved" UKI_SIGNING_KEY="$TMP/fake.key" UKI_SIGNING_CERT="$TMP/fake.crt" \
  >/dev/null 2>&1 \
  && fail "a certificate the trust policy does not approve produced a UKI"
if [ "$HAVE_OPENSSL" = 1 ]; then
  build "$TMP/signed" TRUST_POLICY_ID="$POLICY_ID" TRUST_POLICY_ROOT="$POLICY_ROOT" \
    UKI_SIGNING_KEY="$TMP/uki.key" UKI_SIGNING_CERT="$TMP/uki.crt" >/dev/null \
    || fail "a build signed with a policy-approved certificate failed"
  grep -qx 'signed=yes' "$TMP/signed/installer.efi.manifest" || fail "the signed build did not say so"
  grep -q '^signing_cert_sha256=[0-9a-f]\{64\}$' "$TMP/signed/installer.efi.manifest" \
    || fail "the manifest does not record which certificate signed the medium"
  grep -qx 'signing_cert_anchor=anchor.crt' "$TMP/signed/installer.efi.manifest" \
    || fail "the manifest does not record which trust anchor approved that certificate"
  [ -f "$TMP/signed/sbverify.args" ] \
    || fail "the builder does not verify the UKI it just signed against the certificate it used"
else
  echo "  (openssl unavailable: the certificate/trust-policy binding is not exercised)" >&2
fi

# A hardware target with no measured-identity list is a word, not a binding.
build "$TMP/noidentity" HARDWARE_IDENTITY_FILE= >/dev/null 2>&1 \
  && fail "a build with no measured-identity list produced a UKI"
printf 'not-a-fingerprint\n' > "$TMP/bad.fingerprints"
build "$TMP/badidentity" HARDWARE_IDENTITY_FILE="$TMP/bad.fingerprints" >/dev/null 2>&1 \
  && fail "a build with a malformed measured-identity list produced a UKI"
grep -q '^hardware_identity_sha256=[0-9a-f]\{64\}$' "$manifest" \
  || fail "the manifest does not pin the measured-identity list it sealed a target against"

# --------------------------------------------------------------------------- #
# 6) THE TOOL OVERRIDE MUST NOT BE A PRODUCTION BYPASS, and every input is
#    mandatory: a default here would be a silent decision about what a medium is
#    allowed to install.
# --------------------------------------------------------------------------- #
grep -Fq 'a tool override is forbidden in a privileged process' "$BUILD" \
  || fail "the builder's tool override is not refused under a privileged process"
# TRUST_POLICY_ROOT is deliberately absent from this list: it defaults to the
# in-tree policy directory, so it cannot be emptied from the environment. What
# matters about it is exercised above — a certificate the named policy does not
# approve is refused.
for missing in KERNEL INITRD STUB OSREL ROOT_VERITY_HASH PAYLOAD_DIGEST VARIANT \
  HARDWARE_TARGET HARDWARE_IDENTITY_FILE TRUST_POLICY_ID RELEASE_AUTH_PUBKEY; do
  build "$TMP/miss-$missing" "$missing=" >/dev/null 2>&1 \
    && fail "the builder accepted an empty $missing"
done

echo "INSTALLER_UKI_TEST_OK"
