#!/bin/bash
# Bind a finalized GB10 artifact generation to the exact Secure Boot policy
# approved for the requested image variant. This gate is deliberately backed by
# version-controlled policy executables, never repository variables or secrets.
PATH='/usr/sbin:/usr/bin:/sbin:/bin'; export PATH
LC_ALL=C; export LC_ALL
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
POLICY_ROOT="$REPO_ROOT/secureboot/trust-policies"

die() { echo "ERROR: $*" >&2; exit 1; }
run_trust_policy() {
  /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C "$@"
}
hash_file() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  else shasum -a 256 "$1" | awk '{print $1}'
  fi
}
metadata_value() {
  local key="$1" file="$2"
  awk -F= -v key="$key" '$1 == key {sub(/^[^=]*=/, ""); print; found++} END {exit found == 1 ? 0 : 1}' "$file"
}
output_value() {
  local key="$1"
  awk -F= -v key="$key" '$1 == key {sub(/^[^=]*=/, ""); print; found++} END {exit found == 1 ? 0 : 1}'
}

[[ "$#" == 2 ]] || die "usage: $0 CONTEXT_DIR {debug|prod}"
context="$1"
variant="$2"
[[ -d "$context" && ! -L "$context" ]] || die "build context must be a real directory"

case "$variant" in
  debug) expected_policy_id=neural-ice-secureboot-lab-v1 ;;
  prod) expected_policy_id=neural-ice-secureboot-prod-v1 ;;
  *) die "invalid VARIANT '$variant' (debug|prod); no default is permitted" ;;
esac

policy_bin="$POLICY_ROOT/$expected_policy_id"
[[ -f "$policy_bin" && ! -L "$policy_bin" && -x "$policy_bin" ]] \
  || die "approved $variant trust policy executable is unavailable: '$policy_bin'"
expected_policy_hash="$(hash_file "$policy_bin")"
[[ "$expected_policy_hash" =~ ^[0-9a-f]{64}$ ]] || die "cannot hash approved trust policy executable"

verification="$("$REPO_ROOT/ci/artifact-generation.sh" verify-context \
  "$context" "$expected_policy_id" "$expected_policy_hash")" \
  || die "artifact generation is not bound to the approved $variant trust policy"
generation="$(output_value CURRENT_GENERATION <<< "$verification")" \
  || die "verified context did not report one generation"
policy_id="$(output_value SIGNED_BOOT_TRUST_POLICY_ID <<< "$verification")" \
  || die "verified context did not report one trust policy id"
policy_hash="$(output_value SIGNED_BOOT_TRUST_POLICY_SHA256 <<< "$verification")" \
  || die "verified context did not report one trust policy hash"
[[ "$generation" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ \
  && "$policy_id" == "$expected_policy_id" \
  && "$policy_hash" == "$expected_policy_hash" ]] \
  || die "verified build context returned an inconsistent trust binding"
manifest_hash="$(hash_file "$context/manifest.sha256")"
[[ "$manifest_hash" =~ ^[0-9a-f]{64}$ ]] || die "cannot hash artifact manifest"

# Re-run the exact reviewed policy at consumption time. The generation manifest
# makes the signed tree immutable, while this check proves the signer mapping is
# still accepted by the source revision that is about to build the image.
kernel_uname="$(metadata_value kernel_uname_r "$context/generation.env")" \
  || die "invalid kernel uname in build context"
run_trust_policy "$policy_bin" "$context/signed-boot" "$kernel_uname" >/dev/null \
  || die "approved $variant trust policy rejected the staged signed-boot tree"

# Treat the policy executable as an untrusted parser: it must not be able to
# mutate the already-verified build context as a side effect. Re-hash the full
# payload and require the exact same binding after it returns.
post_verification="$("$REPO_ROOT/ci/artifact-generation.sh" verify-context \
  "$context" "$expected_policy_id" "$expected_policy_hash")" \
  || die "build context changed while the $variant trust policy was running"
[[ "$post_verification" == "$verification" ]] \
  || die "build context trust binding changed while the policy was running"
[[ "$(hash_file "$context/manifest.sha256")" == "$manifest_hash" ]] \
  || die "artifact manifest changed while the policy was running"
[[ "$(hash_file "$policy_bin")" == "$expected_policy_hash" ]] \
  || die "approved trust policy executable changed while it was running"

echo "CURRENT_GENERATION=$generation"
echo "ARTIFACT_MANIFEST_SHA256=$manifest_hash"
echo "SIGNED_BOOT_TRUST_POLICY_ID=$policy_id"
echo "SIGNED_BOOT_TRUST_POLICY_SHA256=$policy_hash"
