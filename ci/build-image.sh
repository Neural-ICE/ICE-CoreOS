#!/usr/bin/env bash
#
# Build (and optionally push) the ICE-CoreOS bootc OS image.
# Shared by the GitHub Actions workflow and local builds.
#
# Env:
#   REGISTRY            registry/namespace      (default ghcr.io/neural-ice)
#   IMAGE               package name            (default neural-ice-coreos)
#   VARIANT             prod | debug             (required; debug => -debug tags,
#                                                 sshd on, serial console, permissive)
#   BUILD_ID            unique build identity    (required when PUSH=1)
#   SOURCE_REVISION     source commit SHA         (required when PUSH=1; defaults to GITHUB_SHA)
#   ARTIFACT_GENERATION expected finalized artifact generation (optional consistency check)
#   SSH_AUTHORIZED_KEY  bake an admin key        (empty => VANILLA, no key)
#   PUSH                "1" to push after build  (default 0)
#   PLATFORM            OCI platform             (default linux/arm64)
#   SOURCE_URL          org.opencontainers.image.source label (default the ICE-CoreOS repo) — WITHOUT
#                       it GitHub cannot link the package to its repo (orphan package).
#
# The build context must contain the staged GB10 artifacts (gitignored):
#   image/rpms/  image/nvidia-userspace/  image/signed-boot/
# These are materialized from a finalized generation by ci/artifact-generation.sh.
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

REGISTRY="${REGISTRY:-ghcr.io/neural-ice}"
IMAGE="${IMAGE:-neural-ice-coreos}"
VARIANT="${VARIANT:-}"
BUILD_ID="${BUILD_ID:-}"
SOURCE_REVISION="${SOURCE_REVISION:-${GITHUB_SHA:-}}"
PLATFORM="${PLATFORM:-linux/arm64}"
SSH_AUTHORIZED_KEY="${SSH_AUTHORIZED_KEY:-}"
PUSH="${PUSH:-0}"
SOURCE_URL="${SOURCE_URL:-https://github.com/Neural-ICE/ICE-CoreOS}"

output_value() {
  local key="$1"
  awk -F= -v key="$key" '$1 == key {sub(/^[^=]*=/, ""); print; found++} END {exit found == 1 ? 0 : 1}'
}

case "$VARIANT" in prod) SUFFIX="" ;; debug) SUFFIX="-debug" ;; *) echo "ERROR: invalid VARIANT '$VARIANT' (prod|debug)" >&2; exit 2 ;; esac
case "$PUSH" in 0|1) ;; *) echo "ERROR: PUSH must be 0 or 1" >&2; exit 2 ;; esac

if [ -n "$BUILD_ID" ] && [[ ! "$BUILD_ID" =~ ^[A-Za-z0-9._-]+$ ]]; then
  echo "ERROR: BUILD_ID contains characters that are unsafe in an OCI tag" >&2
  exit 2
fi
if [ -n "$SOURCE_REVISION" ] && [[ ! "$SOURCE_REVISION" =~ ^[0-9a-fA-F]{7,64}$ ]]; then
  echo "ERROR: SOURCE_REVISION must be a hexadecimal commit identifier" >&2
  exit 2
fi
if [ "$PUSH" = "1" ] && { [ -z "$BUILD_ID" ] || [ -z "$SOURCE_REVISION" ]; }; then
  echo "ERROR: PUSH=1 requires BUILD_ID and SOURCE_REVISION so the published tag is immutable" >&2
  exit 2
fi

VERSION="$(tr -d '[:space:]' < VERSION)"
if [ -n "$SOURCE_REVISION" ]; then
  BUILD_LABEL="git.${SOURCE_REVISION:0:12}${BUILD_ID:+.${BUILD_ID}}"
else
  BUILD_LABEL="local${BUILD_ID:+.${BUILD_ID}}"
fi
SEMVER="${VERSION}-${BUILD_LABEL}${SUFFIX}"
REF="${REGISTRY}/${IMAGE}"

# Fail early with a clear message if the heavy artifacts are not staged.
for d in image/rpms image/nvidia-userspace image/signed-boot; do
  if [ ! -d "$d" ] || [ -z "$(ls -A "$d" 2>/dev/null)" ]; then
    echo "ERROR: missing staged GB10 artifacts in '$d'." >&2
    echo "       Build/stage them first (GB10 kernel (4k) RPMs incl. kernel-modules-nvidia-open," >&2
    echo "       nvidia userspace, signed boot binaries). See README + ci/build-kernel.sh." >&2
    exit 3
  fi
done

# Directory presence is not provenance. Require the finalized generation
# metadata, re-hash every byte and re-check the signed vmlinuz binding before
# podman receives the build context.
CONTEXT_VERIFICATION="$(./ci/verify-build-context.sh image "$VARIANT")" || {
  echo "ERROR: staged GB10 artifacts are not approved for the requested image variant." >&2
  exit 3
}
VERIFIED_ARTIFACT_GENERATION="$(output_value CURRENT_GENERATION <<< "$CONTEXT_VERIFICATION")" || {
  echo "ERROR: verified GB10 artifacts did not report exactly one generation." >&2
  exit 3
}
ARTIFACT_MANIFEST_SHA256="$(output_value ARTIFACT_MANIFEST_SHA256 <<< "$CONTEXT_VERIFICATION")" || {
  echo "ERROR: verified GB10 artifacts did not report exactly one manifest hash." >&2
  exit 3
}
SIGNED_BOOT_TRUST_POLICY_ID="$(output_value SIGNED_BOOT_TRUST_POLICY_ID <<< "$CONTEXT_VERIFICATION")" || {
  echo "ERROR: verified GB10 artifacts did not report exactly one trust policy id." >&2
  exit 3
}
SIGNED_BOOT_TRUST_POLICY_SHA256="$(output_value SIGNED_BOOT_TRUST_POLICY_SHA256 <<< "$CONTEXT_VERIFICATION")" || {
  echo "ERROR: verified GB10 artifacts did not report exactly one trust policy hash." >&2
  exit 3
}
[[ "$VERIFIED_ARTIFACT_GENERATION" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || {
  echo "ERROR: verified GB10 artifacts did not report a safe generation ID." >&2
  exit 3
}
[[ "$ARTIFACT_MANIFEST_SHA256" =~ ^[0-9a-f]{64}$ \
  && "$SIGNED_BOOT_TRUST_POLICY_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ \
  && "$SIGNED_BOOT_TRUST_POLICY_SHA256" =~ ^[0-9a-f]{64}$ ]] || {
  echo "ERROR: verified GB10 artifacts reported an invalid trust/provenance binding." >&2
  exit 3
}
if [ -n "${ARTIFACT_GENERATION:-}" ] && [ "$ARTIFACT_GENERATION" != "$VERIFIED_ARTIFACT_GENERATION" ]; then
  echo "ERROR: staged generation '$VERIFIED_ARTIFACT_GENERATION' differs from expected '$ARTIFACT_GENERATION'." >&2
  exit 3
fi
ARTIFACT_GENERATION="$VERIFIED_ARTIFACT_GENERATION"

# Console TUI: PRODUCT code — its source lives out of this vanilla OS repo.
# The console TUI is product code (ICE-Console) composed onto this vanilla base by
# ICE-Fabric — it is deliberately NOT staged or COPYd here.

# Use the root container store (matches bib --local and caches the base) when
# PODMAN_SUDO=1 (CI); rootless otherwise (local dev).
if [ "${PODMAN_SUDO:-0}" = "1" ]; then PODMAN=(sudo podman); else PODMAN=(podman); fi

echo "==> Building ${REF}:${SEMVER}  variant=${VARIANT}  key=$([ -n "$SSH_AUTHORIZED_KEY" ] && echo baked || echo vanilla)"
BUILD_ARGS=(
  --platform "$PLATFORM"
  --build-arg "SSH_AUTHORIZED_KEY=${SSH_AUTHORIZED_KEY}"
  --build-arg "VARIANT=${VARIANT}"
  --build-arg "OTA_IMGREF=${REF}:${SEMVER}"
  --build-arg "OS_VERSION=${SEMVER}"
  --label "org.opencontainers.image.source=${SOURCE_URL}"
  --label "org.opencontainers.image.version=${SEMVER}"
  --label "ch.neural-ice.artifact-generation=${ARTIFACT_GENERATION}"
  --label "ch.neural-ice.artifact-manifest-sha256=${ARTIFACT_MANIFEST_SHA256}"
  --label "ch.neural-ice.signed-boot-trust-policy-id=${SIGNED_BOOT_TRUST_POLICY_ID}"
  --label "ch.neural-ice.signed-boot-trust-policy-sha256=${SIGNED_BOOT_TRUST_POLICY_SHA256}"
)
if [ -n "$SOURCE_REVISION" ]; then
  BUILD_ARGS+=(--label "org.opencontainers.image.revision=${SOURCE_REVISION}")
fi
"${PODMAN[@]}" build "${BUILD_ARGS[@]}" \
  -f image/Containerfile.bootc \
  -t "${REF}:${SEMVER}" \
  .

echo "SEMVER=${SEMVER}"
echo "REF=${REF}"
echo "ARTIFACT_GENERATION=${ARTIFACT_GENERATION}"
echo "ARTIFACT_MANIFEST_SHA256=${ARTIFACT_MANIFEST_SHA256}"
echo "SIGNED_BOOT_TRUST_POLICY_ID=${SIGNED_BOOT_TRUST_POLICY_ID}"
echo "SIGNED_BOOT_TRUST_POLICY_SHA256=${SIGNED_BOOT_TRUST_POLICY_SHA256}"

if [ "$PUSH" = "1" ]; then
  # Producers publish one run-unique immutable GHCR tag. Mirroring and product
  # channel movement belong to ICE-Fabric's centralized, signed release train.
  if [ "${PODMAN_SUDO:-0}" = "1" ]; then
    digest_file="$(sudo mktemp "${TMPDIR:-/tmp}/ice-coreos-digest.XXXXXX")"
  else
    digest_file="$(mktemp "${TMPDIR:-/tmp}/ice-coreos-digest.XXXXXX")"
  fi
  cleanup_digest_file() {
    if [ "${PODMAN_SUDO:-0}" = "1" ]; then sudo rm -f "$digest_file"
    else rm -f "$digest_file"
    fi
  }
  trap cleanup_digest_file EXIT
  echo "==> Pushing immutable source ${REF}:${SEMVER}"
  "${PODMAN[@]}" push --digestfile "$digest_file" "${REF}:${SEMVER}"
  if [ "${PODMAN_SUDO:-0}" = "1" ]; then DIGEST="$(sudo cat "$digest_file")"
  else DIGEST="$(cat "$digest_file")"
  fi
  [[ "$DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]] \
    || { echo "ERROR: push returned invalid digest '$DIGEST'" >&2; exit 4; }
  echo "DIGEST=${DIGEST}"
  cleanup_digest_file
  trap - EXIT
fi
