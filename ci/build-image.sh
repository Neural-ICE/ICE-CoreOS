#!/usr/bin/env bash
#
# Build (and optionally push) the ICE-CoreOS bootc OS image.
# Shared by the GitHub Actions workflow and local builds.
#
# Env:
#   REGISTRY            registry/namespace      (default ghcr.io/neural-ice)
#   IMAGE               package name            (default neural-ice-coreos)
#   CHANNEL             alpha | beta | prod      (default alpha)
#   VARIANT             prod | debug             (default prod; debug => -debug tags,
#                                                 sshd on, serial console, permissive)
#   BUILD_ID            build counter suffix     (e.g. CI run number; optional)
#   SSH_AUTHORIZED_KEY  bake an admin key        (empty => VANILLA, no key)
#   PUSH                "1" to push after build  (default 0)
#   PLATFORM            OCI platform             (default linux/arm64)
#   OTA_REGISTRY        registry/ns the FLEET OTAs from (default = REGISTRY). CI sets this to
#                       registry.neural-ice.ch/neural-ice so bootc upgrade follows the sovereign
#                       registry (ADR-0023); it is baked into the image as the OTA imgref.
#   MIRROR              "1" to ALSO push to OTA_REGISTRY (the fleet OTA target). Requires a prior
#                       `podman login` to that registry. Default 0. Must be 1 whenever OTA_REGISTRY
#                       != REGISTRY, else the baked OTA imgref would point at a place we never pushed.
#   SOURCE_URL          org.opencontainers.image.source label (default the ICE-CoreOS repo) — WITHOUT
#                       it GitHub cannot link the package to its repo (orphan package, ADR-0023 §0).
#
# The build context must contain the staged GB10 artifacts (gitignored):
#   image/rpms/  image/driver-modules/  image/nvidia-userspace/  image/signed-boot/
# These are produced rarely by the kernel/driver build (see ci/build-kernel.sh).
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

REGISTRY="${REGISTRY:-ghcr.io/neural-ice}"
IMAGE="${IMAGE:-neural-ice-coreos}"
CHANNEL="${CHANNEL:-alpha}"
VARIANT="${VARIANT:-prod}"
PLATFORM="${PLATFORM:-linux/arm64}"
SSH_AUTHORIZED_KEY="${SSH_AUTHORIZED_KEY:-}"
PUSH="${PUSH:-0}"
# Default OTA_REGISTRY = REGISTRY so LOCAL/community builds keep bootc following GHCR (no surprise,
# no dependency on a registry the dev cannot push to). CI overrides it to the sovereign registry
# and sets MIRROR=1 (ADR-0023 — the appliance fleet OTAs from registry.neural-ice.ch).
OTA_REGISTRY="${OTA_REGISTRY:-$REGISTRY}"
MIRROR="${MIRROR:-0}"
SOURCE_URL="${SOURCE_URL:-https://github.com/Neural-ICE/ICE-CoreOS}"

case "$CHANNEL" in alpha|beta|prod) ;; *) echo "ERROR: invalid CHANNEL '$CHANNEL' (alpha|beta|prod)" >&2; exit 2 ;; esac
case "$VARIANT" in prod) SUFFIX="" ;; debug) SUFFIX="-debug" ;; *) echo "ERROR: invalid VARIANT '$VARIANT' (prod|debug)" >&2; exit 2 ;; esac

VERSION="$(tr -d '[:space:]' < VERSION)"
SEMVER="${VERSION}-${CHANNEL}${BUILD_ID:+.${BUILD_ID}}${SUFFIX}"
REF="${REGISTRY}/${IMAGE}"            # GHCR push target (upstream + community pull)
OTA_REF="${OTA_REGISTRY}/${IMAGE}"    # what the fleet OTAs from (baked as the OTA imgref)

# Guard: baking a sovereign OTA imgref we never mirror to would brick fleet OTA.
if [ "$OTA_REF" != "$REF" ] && [ "$MIRROR" != "1" ]; then
  echo "ERROR: OTA_REGISTRY ($OTA_REGISTRY) differs from REGISTRY ($REGISTRY) but MIRROR!=1 —" >&2
  echo "       the baked OTA imgref would point at a registry we never push to. Set MIRROR=1." >&2
  exit 2
fi

# Fail early with a clear message if the heavy artifacts are not staged.
for d in image/rpms image/driver-modules image/nvidia-userspace image/signed-boot; do
  if [ ! -d "$d" ] || [ -z "$(ls -A "$d" 2>/dev/null)" ]; then
    echo "ERROR: missing staged GB10 artifacts in '$d'." >&2
    echo "       Build/stage them first (GB10 kernel (4k) RPMs, signed driver modules," >&2
    echo "       nvidia userspace, signed boot binaries). See README + ci/build-kernel.sh." >&2
    exit 3
  fi
done

# Console TUI: PRODUCT code — its source lives out of this vanilla OS repo.
# The pre-built ARM64 binary must be staged where the Containerfile COPYs it —
# same "stage then COPY" pattern as the GB10 artifacts (from the product repo:
# `make -C tui-rust stage COREOS_DIR=<this repo>`).
if [ ! -f image/tui/neural-ice-tui ]; then
  echo "ERROR: missing staged console TUI binary 'image/tui/neural-ice-tui'." >&2
  echo "       Build it from the product repo: make -C tui-rust stage COREOS_DIR=$PWD" >&2
  exit 4
fi
echo "    staged image/tui/neural-ice-tui ($(du -h image/tui/neural-ice-tui | cut -f1))"

# Use the root container store (matches bib --local and caches the base) when
# PODMAN_SUDO=1 (CI); rootless otherwise (local dev).
if [ "${PODMAN_SUDO:-0}" = "1" ]; then PODMAN=(sudo podman); else PODMAN=(podman); fi

echo "==> Building ${REF}:${SEMVER}  (channel ${REF}:${CHANNEL}${SUFFIX})  OTA imgref ${OTA_REF}:${CHANNEL}${SUFFIX}  variant=${VARIANT}  key=$([ -n "$SSH_AUTHORIZED_KEY" ] && echo baked || echo vanilla)"
"${PODMAN[@]}" build \
  --platform "$PLATFORM" \
  --build-arg "SSH_AUTHORIZED_KEY=${SSH_AUTHORIZED_KEY}" \
  --build-arg "VARIANT=${VARIANT}" \
  --build-arg "OTA_IMGREF=${OTA_REF}:${CHANNEL}${SUFFIX}" \
  --build-arg "OS_VERSION=${SEMVER}" \
  --label "org.opencontainers.image.source=${SOURCE_URL}" \
  --label "org.opencontainers.image.version=${SEMVER}" \
  ${GITHUB_SHA:+--label "org.opencontainers.image.revision=${GITHUB_SHA}"} \
  -f image/Containerfile.bootc \
  -t "${REF}:${SEMVER}" \
  -t "${REF}:${CHANNEL}${SUFFIX}" \
  .

echo "SEMVER=${SEMVER}"
echo "REF=${REF}"

if [ "$PUSH" = "1" ]; then
  # ORDER MATTERS (Codex #8 P2): advance the *moving* channel tags LAST, and the GHCR community
  # channel only AFTER the sovereign channel exists. Otherwise a mirror failure would leave the
  # GHCR channel pointing at an image whose baked OTA origin is the sovereign registry, while the
  # sovereign channel was never updated — a fresh community install would then track a stale/missing
  # sovereign tag. Sequence: GHCR :SEMVER (immutable) → sovereign :SEMVER + :CHANNEL → GHCR :CHANNEL.
  echo "==> Pushing ${REF}:${SEMVER} (GHCR immutable)"
  "${PODMAN[@]}" push "${REF}:${SEMVER}"
  DIGEST="$("${PODMAN[@]}" image inspect "${REF}:${SEMVER}" --format '{{.Digest}}' 2>/dev/null || true)"
  echo "DIGEST=${DIGEST}"

  # Mirror the SAME local image (same digest) to the sovereign registry — the fleet OTA target
  # (ADR-0023). OS is PUBLIC (no PI), so a direct dual-push from the self-hosted build is fine and
  # keeps build+mirror atomic (the OS uses channel tags, not quadlet digest pins, so Fabric's
  # quadlet mirror does not cover it). Requires a prior `podman login "$OTA_REGISTRY host"`.
  if [ "$MIRROR" = "1" ]; then
    echo "==> Mirroring to ${OTA_REF}:${SEMVER} and ${OTA_REF}:${CHANNEL}${SUFFIX} (fleet OTA target)"
    "${PODMAN[@]}" push "${REF}:${SEMVER}"           "docker://${OTA_REF}:${SEMVER}"
    "${PODMAN[@]}" push "${REF}:${CHANNEL}${SUFFIX}" "docker://${OTA_REF}:${CHANNEL}${SUFFIX}"
    echo "OTA_REF=${OTA_REF}"
  fi

  # GHCR moving channel LAST — only now that the immutable + sovereign channel are in place.
  echo "==> Pushing ${REF}:${CHANNEL}${SUFFIX} (GHCR community channel)"
  "${PODMAN[@]}" push "${REF}:${CHANNEL}${SUFFIX}"

  # ⚠ Channel-promotion caveat (Codex #8 P1): this build bakes OTA_IMGREF = the BUILD channel
  # (${OTA_REF}:${CHANNEL}${SUFFIX}). promote.yml re-tags a validated digest across channels by COPY
  # (ADR-0005: no rebuild), so a promoted :beta/:prod image still carries the *build* channel in
  # /usr/lib/neural-ice/ota-imgref. Fleet appliances must therefore be INSTALLED with the target
  # channel set explicitly (BASE_IMAGE=…:prod + kernel arg `neuralice.imgref=…:prod`, which the
  # installer honours over the baked default) — see ota/neural-ice-autoinstall.sh and the README.
fi
