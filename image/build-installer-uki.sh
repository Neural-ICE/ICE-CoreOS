#!/usr/bin/env bash
#
# Build the SEALED INSTALLER UKI: one PE binary carrying the kernel, the
# initramfs and the trust anchor, signed as a whole.
#
# WHY A UKI AND NOT A BLS ENTRY (DESIGN-NOTE-0001, Finding 1, Design A).
# Secure Boot authenticates EFI binaries and the kernel; it says nothing about
# the root filesystem those binaries later mount, and nothing at all about the
# kernel command line typed at a GRUB prompt. Putting the dm-verity root hash
# and the access profile in a .cmdline section INSIDE the signed PE binary makes
# both of them covered by the same signature as the kernel: editing either word
# invalidates it and the firmware refuses to boot. The initramfs travels inside
# that same binary, so the code that sets dm-verity up before switch-root is
# authenticated too -- which is exactly what Design B (a signed manifest plus a
# key in an unverified initrd) cannot claim.
#
# WHICH KEY. The LAB-v1 DIRECT UEFI PATH, unchanged: the UKI is signed with the
# Neural ICE UEFI Secure Boot CA -- the same anchor that already signs vmlinuz
# and grub today (secureboot/trust-policies/neural-ice-secureboot-lab-v1) --
# and validated by firmware that carries that certificate in db. It does NOT
# go through the MS-signed shim, because `neural-ice-secureboot-prod-v1` does
# not exist yet. That is a gap in PRODUCTION-CHAIN EVIDENCE, not a gap in the
# lab trust proof: on lab media the property "the cmdline is authenticated" is
# established by the same signature that already authenticates the kernel.
#
# WHAT THIS SCRIPT NO LONGER DOES (review 2026-09-01, P0 #1). It used to run
# `veritysetup format` itself, which made the protected extent a side effect of
# the signing step and left no room for the SECOND protected extent a medium now
# carries -- the container store the install actually reads from. Both extents,
# both hash trees and the header that names them are produced by
# image/build-installer-payload.sh; this script seals two values that step
# computed: the root's dm-verity hash and the SHA-256 of that header. One signed
# digest therefore binds every byte on the medium, transitively.
#
# DETERMINISM IS A REVIEWABILITY REQUIREMENT. Two builds of the same inputs must
# produce the same bytes, or nobody can tell a rebuild from a substitution. Every
# input is pinned: section offsets are computed rather than discovered, and the
# cmdline is rendered by a function whose key order is a constant
# (image/lib/installer-trust.sh).
#
# THIS SCRIPT NEVER SIGNS WITH A PRODUCTION KEY BY ITSELF. Signing happens only
# when UKI_SIGNING_KEY and UKI_SIGNING_CERT are both supplied; unset, it emits
# the unsigned PE plus its manifest, which is what CI diffs and what the test
# suite exercises.
#
# THE TRUST POLICY ID IS NOT A CAPTION. It used to be a caller-supplied string,
# and the signing branch verified the produced binary against the SAME
# certificate it had just signed it with -- a tautology any self-signed key
# satisfies. The certificate is now bound to the NAMED policy before anything is
# signed (image/lib/signing-trust.sh): it must be an anchor that policy pins, or
# be issued by one. A medium may no longer claim a trust policy it was not
# actually signed under.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=image/lib/access-policy.sh
source "$REPO_ROOT/image/lib/access-policy.sh"
# shellcheck source=image/lib/installer-trust.sh
source "$REPO_ROOT/image/lib/installer-trust.sh"
# shellcheck source=image/lib/hardware-identity.sh
source "$REPO_ROOT/image/lib/hardware-identity.sh"
# shellcheck source=image/lib/signing-trust.sh
source "$REPO_ROOT/image/lib/signing-trust.sh"

die() { echo "build-installer-uki: ERROR: $*" >&2; exit 1; }

# --------------------------------------------------------------------------- #
# Inputs. All mandatory, all explicit: a default here would be a silent decision
# about what a medium is allowed to install.
# --------------------------------------------------------------------------- #
KERNEL="${KERNEL:-}"                       # vmlinuz-to-seal (EFI stub not required; the stub wraps it)
INITRD="${INITRD:-}"                       # the installer initramfs, WITH the verity setup hook
STUB="${STUB:-}"                           # systemd-stub (linuxaa64.efi.stub)
OSREL="${OSREL:-}"                         # os-release to embed as .osrel
# The two values build-installer-payload.sh computed. They are INPUTS here, not
# outputs: the object they describe already exists and is already hashed, so this
# script cannot silently sign a different one.
ROOT_VERITY_HASH="${ROOT_VERITY_HASH:-}"   # dm-verity root hash of the installer root image
PAYLOAD_DIGEST="${PAYLOAD_DIGEST:-}"       # SHA-256 of the sealed payload header
VARIANT="${VARIANT:-}"                     # prod | sealed-lab | debug -> derives the access profile
HARDWARE_TARGET="${HARDWARE_TARGET:-}"
TRUST_POLICY_ID="${TRUST_POLICY_ID:-}"
RELEASE_AUTH_PUBKEY="${RELEASE_AUTH_PUBKEY:-}"
# The measured-identity fingerprint list for HARDWARE_TARGET. Sealing a hardware
# target that no machine can be measured against is sealing a word; the list is
# what turns it into a binding, so it is required here and not merely inside the
# root image (image/lib/hardware-identity.sh).
HARDWARE_IDENTITY_FILE="${HARDWARE_IDENTITY_FILE:-}"
# Where the named Secure Boot trust policy and its pinned anchors live.
TRUST_POLICY_ROOT="${TRUST_POLICY_ROOT:-$REPO_ROOT/secureboot/trust-policies}"
UKI_OUT="${UKI_OUT:-}"
EXTRA_KARGS="${EXTRA_KARGS:-quiet}"
UKI_SIGNING_KEY="${UKI_SIGNING_KEY:-}"
UKI_SIGNING_CERT="${UKI_SIGNING_CERT:-}"
# Tool overrides exist so the suite can drive every branch without a kernel, a
# device-mapper target or a signing key. They are refused under a privileged
# process, exactly as in the device-root helper.
TOOL_DIR="${NI_UKI_TEST_TOOLS:-}"
if [[ -n "$TOOL_DIR" ]]; then
  [[ "${NI_UKI_TESTING:-}" == 1 && "${EUID:-$(id -u)}" -ne 0 ]] \
    || die "a tool override is forbidden in a privileged process"
fi

tool() { # $1=name
  if [[ -n "$TOOL_DIR" ]]; then
    [[ -x "$TOOL_DIR/$1" ]] || die "required tool is unavailable: $TOOL_DIR/$1"
    printf '%s' "$TOOL_DIR/$1"
    return 0
  fi
  command -v -- "$1" >/dev/null 2>&1 || die "required tool is unavailable: $1"
  command -v -- "$1"
}

for required in KERNEL INITRD STUB OSREL ROOT_VERITY_HASH PAYLOAD_DIGEST VARIANT \
  HARDWARE_TARGET TRUST_POLICY_ID TRUST_POLICY_ROOT HARDWARE_IDENTITY_FILE \
  RELEASE_AUTH_PUBKEY UKI_OUT; do
  [[ -n "${!required}" ]] || die "$required is required"
done
for input in "$KERNEL" "$INITRD" "$STUB" "$OSREL" "$RELEASE_AUTH_PUBKEY" \
  "$HARDWARE_IDENTITY_FILE"; do
  [[ -f "$input" && ! -L "$input" ]] || die "input is missing or not a regular file: $input"
done
installer_trust_value_is_valid neuralice.rootverity "$ROOT_VERITY_HASH" \
  || die "ROOT_VERITY_HASH is not a dm-verity root hash: $ROOT_VERITY_HASH"
installer_trust_value_is_valid neuralice.payload "$PAYLOAD_DIGEST" \
  || die "PAYLOAD_DIGEST is not a sealed payload header digest: $PAYLOAD_DIGEST"
installer_trust_value_is_valid neuralice.hardware_target "$HARDWARE_TARGET" \
  || die "HARDWARE_TARGET is not a valid hardware target: $HARDWARE_TARGET"
installer_trust_value_is_valid neuralice.trust_policy_id "$TRUST_POLICY_ID" \
  || die "TRUST_POLICY_ID is not a valid signed-boot trust policy id: $TRUST_POLICY_ID"
# The identity list is read through the SAME reader the appliance uses, against a
# throwaway root, so a list this build accepts is a list that machine will accept.
_identity_root="$(mktemp -d "${TMPDIR:-/tmp}/ni-uki-identity.XXXXXX")"
mkdir -p "$_identity_root/$NEURAL_ICE_HARDWARE_IDENTITY_RELDIR"
cp -- "$HARDWARE_IDENTITY_FILE" "$_identity_root/$NEURAL_ICE_HARDWARE_IDENTITY_RELDIR/$HARDWARE_TARGET.fingerprints"
HARDWARE_IDENTITY_COUNT="$(hardware_identity_read_fingerprints "$_identity_root" "$HARDWARE_TARGET" | grep -c .)" || {
  rm -rf -- "$_identity_root"
  die "HARDWARE_IDENTITY_FILE is not a usable measured-identity fingerprint list for '$HARDWARE_TARGET'"
}
HARDWARE_IDENTITY_SHA256="$("$(tool sha256sum)" "$HARDWARE_IDENTITY_FILE" | awk '{print tolower($1)}')"
rm -rf -- "$_identity_root"

# THE CERTIFICATE IS THE POLICY. Bind before doing any work: refusing a medium
# that names a policy it cannot be signed under is free here and expensive on an
# appliance. The binding is required whenever a certificate is supplied at all,
# so a half-configured signing run cannot slip past it.
SIGNING_CERT_FINGERPRINT=""
SIGNING_CERT_ANCHOR=""
if [[ -n "$UKI_SIGNING_CERT" ]]; then
  _bound="$(signing_trust_assert_cert "$TRUST_POLICY_ID" "$TRUST_POLICY_ROOT" "$UKI_SIGNING_CERT")" \
    || die "the signing certificate is not one trust policy '$TRUST_POLICY_ID' approves"
  SIGNING_CERT_FINGERPRINT="$(awk '{print $2}' <<<"$_bound")"
  SIGNING_CERT_ANCHOR="$(awk '{print $3}' <<<"$_bound")"
  echo "==> signing certificate bound to ${TRUST_POLICY_ID} via ${SIGNING_CERT_ANCHOR} (${SIGNING_CERT_FINGERPRINT})"
fi

# The access profile is DERIVED from the variant, never passed in. A build arg
# would be one more thing an operator can get wrong, and the whole point of the
# marker is that nobody outside the build gets a vote on it.
ACCESS_PROFILE="$(access_policy_for_variant "$VARIANT")" \
  || die "no access policy is defined for variant '$VARIANT'"

# The release-authorization key IDENTITY is its SHA-256. Sealing the hash rather
# than the key keeps the cmdline short and makes substitution detectable: a
# different key file is a different id, and the installer refuses.
RELAUTH_KEYID="$("$(tool sha256sum)" "$RELEASE_AUTH_PUBKEY" | awk '{print tolower($1)}')"

ROOT_HASH="$ROOT_VERITY_HASH"

# --------------------------------------------------------------------------- #
# 1) The sealed cmdline. One function, one key order, no build-host state.
# --------------------------------------------------------------------------- #
# shellcheck disable=SC2086 # EXTRA_KARGS is a deliberate word list, validated by the renderer
CMDLINE="$(installer_trust_render_cmdline "$ACCESS_PROFILE" "$HARDWARE_TARGET" \
  "$RELAUTH_KEYID" "$ROOT_HASH" "$PAYLOAD_DIGEST" "$TRUST_POLICY_ID" $EXTRA_KARGS)" \
  || die "cannot render the sealed installer command line"
echo "==> sealed cmdline: $CMDLINE"

# Re-read what was rendered rather than trusting the renderer's return. This is
# the same fail-closed readback the image build performs on the access-policy
# marker: a mapping that lives in one place must break the BUILD if it ever
# stops agreeing with what this file says it means.
sealed="$(installer_trust_read_sealed "$CMDLINE")" || die "the rendered cmdline does not parse as a sealed anchor"
[[ "$(sed -n 's/^neuralice\.access_profile=//p' <<<"$sealed")" == "$ACCESS_PROFILE" ]] \
  || die "the rendered cmdline does not seal the derived access profile"
[[ "$(sed -n 's/^neuralice\.rootverity=//p' <<<"$sealed")" == "$ROOT_HASH" ]] \
  || die "the rendered cmdline does not seal the computed verity root hash"
[[ "$(sed -n 's/^neuralice\.payload=//p' <<<"$sealed")" == "$PAYLOAD_DIGEST" ]] \
  || die "the rendered cmdline does not seal the sealed payload header digest"
[[ "$(sed -n 's/^neuralice\.relauth_schema=//p' <<<"$sealed")" == "$NEURAL_ICE_INSTALLER_RELAUTH_SCHEMA" ]] \
  || die "the rendered cmdline does not seal the installer release-authorization schema"

# --------------------------------------------------------------------------- #
# 2) Assemble the PE. Section addresses are computed from the previous section's
#    end, aligned to the PE section alignment, so the layout is a function of the
#    input sizes alone.
# --------------------------------------------------------------------------- #
WORK="$(mktemp -d "${TMPDIR:-/tmp}/ni-uki.XXXXXX")"
trap 'rm -rf -- "$WORK"' EXIT
printf '%s' "$CMDLINE" > "$WORK/cmdline"
printf '%s\n' "$ROOT_HASH" > "$WORK/roothash"

readonly SECTION_ALIGNMENT=4096
# systemd-stub reads these section names; the order is the conventional one and
# is fixed here so two builds cannot differ by section ordering alone.
SECTIONS=(
  ".osrel:$OSREL"
  ".cmdline:$WORK/cmdline"
  ".linux:$KERNEL"
  ".initrd:$INITRD"
)

# The stub's own image ends somewhere; start appending after it, aligned.
# The hex arithmetic is done in the SHELL, not in awk: `strtonum()` is a gawk
# extension and the CI runner's default awk is mawk, where it silently evaluates
# to 0 -- which would make every section land at offset 0 and the failure would
# look like a corrupt stub rather than a missing feature.
stub_end=0
while read -r size vma; do
  [[ "$size" =~ ^[0-9a-fA-F]+$ && "$vma" =~ ^[0-9a-fA-F]+$ ]] || continue
  end=$(( 16#$vma + 16#$size ))
  # An `if`, not `(( … )) && …`: as the last command of a loop body a false
  # arithmetic test is a non-zero status, and under `set -e` that ends the loop
  # silently with a plausible-looking partial result.
  if (( end > stub_end )); then stub_end=$end; fi
done < <("$(tool objdump)" -h "$STUB" | awk '/^ +[0-9]+ /{print $3, $4}')
[[ "$stub_end" =~ ^[0-9]+$ && "$stub_end" -gt 0 ]] || die "cannot determine the stub's image extent"
offset=$(( (stub_end + SECTION_ALIGNMENT - 1) / SECTION_ALIGNMENT * SECTION_ALIGNMENT ))

objcopy_args=()
manifest="$WORK/manifest"
: > "$manifest"
for entry in "${SECTIONS[@]}"; do
  name="${entry%%:*}"; file="${entry#*:}"
  [[ -f "$file" ]] || die "section source is missing: $name <- $file"
  size="$(wc -c < "$file" | tr -d '[:space:]')"
  objcopy_args+=(--add-section "$name=$file" --change-section-vma "$name=$offset")
  printf '%s %s %s %s\n' "$name" "$offset" "$size" \
    "$("$(tool sha256sum)" "$file" | awk '{print $1}')" >> "$manifest"
  offset=$(( (offset + size + SECTION_ALIGNMENT - 1) / SECTION_ALIGNMENT * SECTION_ALIGNMENT ))
done

echo "==> objcopy: assembling ${UKI_OUT}"
"$(tool objcopy)" "${objcopy_args[@]}" "$STUB" "$UKI_OUT" || die "objcopy failed to assemble the UKI"

# --------------------------------------------------------------------------- #
# 3) Sign, only if a key was explicitly supplied.
# --------------------------------------------------------------------------- #
if [[ -n "$UKI_SIGNING_KEY" || -n "$UKI_SIGNING_CERT" ]]; then
  [[ -n "$UKI_SIGNING_KEY" && -n "$UKI_SIGNING_CERT" ]] \
    || die "signing requires BOTH UKI_SIGNING_KEY and UKI_SIGNING_CERT"
  echo "==> sbsign ${UKI_OUT}"
  "$(tool sbsign)" --key "$UKI_SIGNING_KEY" --cert "$UKI_SIGNING_CERT" \
    --output "$WORK/signed.efi" "$UKI_OUT" || die "sbsign failed"
  mv -f -- "$WORK/signed.efi" "$UKI_OUT"
  "$(tool sbverify)" --cert "$UKI_SIGNING_CERT" "$UKI_OUT" >/dev/null \
    || die "the produced UKI does not verify against the certificate it was signed with"
  echo "    signed and verified against ${UKI_SIGNING_CERT}"
else
  echo "==> UNSIGNED (no UKI_SIGNING_KEY/UKI_SIGNING_CERT supplied)"
fi

# --------------------------------------------------------------------------- #
# 4) The build manifest. This is the artefact CI diffs between builds: identical
#    inputs must produce an identical manifest, and a changed root hash or
#    cmdline must show up as a one-line diff rather than as 40 MiB of PE.
# --------------------------------------------------------------------------- #
MANIFEST_OUT="${UKI_OUT}.manifest"
{
  printf 'schema=%s\n' "neural-ice-installer-uki-manifest-v1"
  printf 'access_profile=%s\n' "$ACCESS_PROFILE"
  printf 'cmdline=%s\n' "$CMDLINE"
  printf 'hardware_identity_count=%s\n' "$HARDWARE_IDENTITY_COUNT"
  printf 'hardware_identity_sha256=%s\n' "$HARDWARE_IDENTITY_SHA256"
  printf 'hardware_target=%s\n' "$HARDWARE_TARGET"
  printf 'payload_header_sha256=%s\n' "$PAYLOAD_DIGEST"
  printf 'relauth_keyid=%s\n' "$RELAUTH_KEYID"
  printf 'release_authorization_schema=%s\n' "$NEURAL_ICE_INSTALLER_RELAUTH_SCHEMA"
  printf 'signed=%s\n' "$([[ -n "$UKI_SIGNING_KEY" ]] && echo yes || echo no)"
  printf 'signing_cert_anchor=%s\n' "${SIGNING_CERT_ANCHOR:-none}"
  printf 'signing_cert_sha256=%s\n' "${SIGNING_CERT_FINGERPRINT:-none}"
  printf 'trust_policy_id=%s\n' "$TRUST_POLICY_ID"
  printf 'variant=%s\n' "$VARIANT"
  printf 'verity_root_hash=%s\n' "$ROOT_HASH"
  sort "$manifest" | while read -r name off size hash; do
    printf 'section.%s=offset:%s,size:%s,sha256:%s\n' "${name#.}" "$off" "$size" "$hash"
  done
} > "$MANIFEST_OUT"
echo "==> manifest: $MANIFEST_OUT"
cat "$MANIFEST_OUT"
