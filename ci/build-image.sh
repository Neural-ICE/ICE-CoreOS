#!/bin/sh
# shellcheck shell=bash
# Keep inherited shell hooks and PATH from running before the final trust gate.
case $- in
  *p*) ;;
  *) _neural_ice_caller_path=${PATH:-/usr/sbin:/usr/bin:/sbin:/bin}
     exec /usr/bin/env -u BASH_ENV -u ENV PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C \
       _NEURAL_ICE_CALLER_PATH="$_neural_ice_caller_path" \
       /bin/bash --noprofile --norc -p "$0" "$@" ;;
esac
#
# Build (and optionally push) the ICE-CoreOS bootc OS image.
# Shared by the GitHub Actions workflow and local builds.
#
# Env:
#   REGISTRY            registry/namespace      (default ghcr.io/neural-ice)
#   IMAGE               package name            (default neural-ice-coreos)
#   VARIANT             prod | sealed-lab | debug  (required; suffixes the tags,
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
PATH='/usr/sbin:/usr/bin:/sbin:/bin'; export PATH
LC_ALL=C; export LC_ALL
set -euo pipefail
CALLER_PATH="${_NEURAL_ICE_CALLER_PATH:-/usr/sbin:/usr/bin:/sbin:/bin}"
unset _NEURAL_ICE_CALLER_PATH

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

# The tag suffix follows the VARIANT. `sealed-lab` carries the sealed posture of
# `prod` on the LAB Secure Boot anchor, so it must be distinguishable from both:
# from `prod` because its chain is only trusted where the key was enrolled by
# hand, and from `debug` because it has no shell at all.
case "$VARIANT" in
  prod)       SUFFIX="" ;;
  sealed-lab) SUFFIX="-sealed-lab" ;;
  debug)      SUFFIX="-debug" ;;
  *) echo "ERROR: invalid VARIANT '$VARIANT' (prod|sealed-lab|debug)" >&2; exit 2 ;;
esac
case "$PUSH" in 0|1) ;; *) echo "ERROR: PUSH must be 0 or 1" >&2; exit 2 ;; esac
case "${PODMAN_SUDO:-0}" in 0|1) ;; *) echo "ERROR: PODMAN_SUDO must be 0 or 1" >&2; exit 2 ;; esac

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

# The two staged inputs the installer TRUST construction cannot work without
# (docs/ADR-0015). They are git-ignored on purpose: a fingerprint nobody measured
# and a key nobody generated are worse than none, because they look like checks.
# `COPY` would fail on them anyway; failing HERE says which one and why.
if [ ! -s image/keys/release-authorization.pub ]; then
  echo "ERROR: no release-authorization public key staged at image/keys/release-authorization.pub." >&2
  echo "       The installer seals its SHA-256 in the signed UKI and refuses a registry" >&2
  echo "       install without it. Stage the public half of the release-authorization key." >&2
  exit 3
fi
_hw_target="$(tr -d '[:space:]' < image/bootc-overlay/usr/lib/neural-ice/hardware-target)"
if [ ! -s "image/hardware-identity/${_hw_target}.fingerprints" ]; then
  echo "ERROR: no measured-identity list at image/hardware-identity/${_hw_target}.fingerprints." >&2
  echo "       A hardware target no machine can be measured against is a word, not a binding." >&2
  echo "       Produce it with 'bash image/lib/hardware-identity.sh fingerprint' ON the" >&2
  echo "       reference appliance — see image/hardware-identity/README.md." >&2
  exit 3
fi

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
NVIDIA_DRIVER_VERSION="$(output_value nvidia_driver_version < image/generation.env)" || {
  echo "ERROR: verified GB10 artifacts did not report exactly one NVIDIA driver version." >&2
  exit 3
}
[[ "$NVIDIA_DRIVER_VERSION" =~ ^[0-9]+([.][0-9]+)+$ ]] || {
  echo "ERROR: verified GB10 artifacts reported an invalid NVIDIA driver version." >&2
  exit 3
}

# Console TUI: PRODUCT code — its source lives out of this vanilla OS repo.
# The console TUI is product code (ICE-Console) composed onto this vanilla base by
# ICE-Fabric — it is deliberately NOT staged or COPYd here.

# A publishing job never trusts the caller PATH for its registry writer. Local
# PUSH=0 builds retain rootless/Homebrew compatibility, but only after the full
# provenance and trust-policy gate above has succeeded.
if [ "$PUSH" = "1" ]; then
  PODMAN_BIN=/usr/bin/podman
else
  PODMAN_BIN="$(PATH="$CALLER_PATH" command -v podman 2>/dev/null || true)"
fi
[[ "$PODMAN_BIN" == /* && -f "$PODMAN_BIN" && -x "$PODMAN_BIN" ]] \
  || { echo "ERROR: an executable absolute podman path is required" >&2; exit 2; }
if [ "${PODMAN_SUDO:-0}" = "1" ]; then
  [[ -f /usr/bin/sudo && -x /usr/bin/sudo ]] \
    || { echo "ERROR: /usr/bin/sudo is required when PODMAN_SUDO=1" >&2; exit 2; }
  PODMAN=(/usr/bin/sudo "$PODMAN_BIN")
else
  PODMAN=("$PODMAN_BIN")
fi

echo "==> Building ${REF}:${SEMVER}  variant=${VARIANT}  key=$([ -n "$SSH_AUTHORIZED_KEY" ] && echo baked || echo vanilla)"
BUILD_ARGS=(
  --platform "$PLATFORM"
  --build-arg "SSH_AUTHORIZED_KEY=${SSH_AUTHORIZED_KEY}"
  --build-arg "VARIANT=${VARIANT}"
  --build-arg "NVIDIA_DRIVER_VERSION=${NVIDIA_DRIVER_VERSION}"
  --build-arg "OTA_IMGREF=${REF}:${SEMVER}"
  --build-arg "OS_VERSION=${SEMVER}"
  # 🔴 PASSED, not merely labelled. This value is VERIFIED above by the trust
  # policy that approved the staged signed-boot tree, and it was then used only
  # as an OCI label — metadata anyone can set — while the FILE the installer
  # actually cross-checks
  # (/usr/lib/neural-ice/signed-boot-trust-policy-id) silently kept the
  # Containerfile's `lab-v1` default. An image whose label and whose immutable
  # marker name different policies is an image whose two halves disagree about
  # which chain signed it, and the medium seals the marker.
  --build-arg "SIGNED_BOOT_TRUST_POLICY_ID=${SIGNED_BOOT_TRUST_POLICY_ID}"
  # Ancre de confiance de l heure fiable : elle vient de la CONFIGURATION du
  # depot, jamais du source — c est ce qui garde l open-core neutre.
  # `:-` deliberement : ce script tourne en `set -u`, et le harnais de contrat
  # l invoque sans la variable. Le FAIL-CLOSED vit dans le Containerfile
  # (`test -n`), c est-a-dire la ou une valeur absente doit empecher une IMAGE
  # d exister — pas la ou elle empecherait un test de forme de tourner.
  --build-arg "NI_TRUSTED_TIME_ISSUER=${NI_TRUSTED_TIME_ISSUER:-}"
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

# READ THE MARKER BACK off the built image. The build argument above and the
# label are two statements about the same thing; this asserts the third — the
# file in the read-only /usr that the installer's sealed anchor is compared
# against — actually says the same word. The whole defect this replaces was a
# silent disagreement between exactly these three.
built_policy_id="$("${PODMAN[@]}" run --rm --entrypoint '' --net=none "${REF}:${SEMVER}" \
  cat /usr/lib/neural-ice/signed-boot-trust-policy-id 2>/dev/null | tr -d '[:space:]')"
if [ "$built_policy_id" != "$SIGNED_BOOT_TRUST_POLICY_ID" ]; then
  echo "ERROR: the built image states trust policy '${built_policy_id:-none}' but the verified staged artifacts report '${SIGNED_BOOT_TRUST_POLICY_ID}'." >&2
  exit 3
fi
echo "==> immutable signed-boot trust policy marker: ${built_policy_id}"

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
  # 🔴 THE PUBLICATION SHAPE, SAID OUT LOUD (review 2026-09-01, P1 #5). `podman
  # push` of a single-platform build publishes ONE arm64 manifest, so the
  # repository digest printed above and the platform manifest digest are the SAME
  # object. An installer release authorization describing this artefact must
  # therefore declare `image_publication_shape: "single-manifest"` and repeat that
  # digest in BOTH `image_index_digest` and `image_manifest_digest`
  # (image/lib/release-authorization.sh). Declaring `index` here, or splitting the
  # digests, is refused by the parser -- as is declaring `single-manifest` for a
  # real multi-arch index, which still needs a distinct, recursively signed index
  # and child.
  echo "PUBLICATION_SHAPE=single-manifest"
  cleanup_digest_file
  trap - EXIT
fi
