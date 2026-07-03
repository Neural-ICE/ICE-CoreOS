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

case "$CHANNEL" in alpha|beta|prod) ;; *) echo "ERROR: invalid CHANNEL '$CHANNEL' (alpha|beta|prod)" >&2; exit 2 ;; esac
case "$VARIANT" in prod) SUFFIX="" ;; debug) SUFFIX="-debug" ;; *) echo "ERROR: invalid VARIANT '$VARIANT' (prod|debug)" >&2; exit 2 ;; esac

VERSION="$(tr -d '[:space:]' < VERSION)"
SEMVER="${VERSION}-${CHANNEL}${BUILD_ID:+.${BUILD_ID}}${SUFFIX}"
REF="${REGISTRY}/${IMAGE}"

# Fail early with a clear message if the heavy artifacts are not staged.
for d in image/rpms image/driver-modules image/nvidia-userspace image/signed-boot; do
  if [ ! -d "$d" ] || [ -z "$(ls -A "$d" 2>/dev/null)" ]; then
    echo "ERROR: missing staged GB10 artifacts in '$d'." >&2
    echo "       Build/stage them first (GB10 kernel (4k) RPMs, signed driver modules," >&2
    echo "       nvidia userspace, signed boot binaries). See README + ci/build-kernel.sh." >&2
    exit 3
  fi
done

# Console TUI: PRODUCT code — its source lives in ICE-AC1 (tui-rust/), not in this vanilla
# OS repo. The pre-built ARM64 binary must be staged where the Containerfile COPYs it —
# same "stage then COPY" pattern as the GB10 artifacts (from an ICE-AC1 checkout:
# `make -C tui-rust stage COREOS_DIR=<this repo>`).
if [ ! -f image/tui/neural-ice-tui ]; then
  echo "ERROR: missing staged console TUI binary 'image/tui/neural-ice-tui'." >&2
  echo "       Build it from ICE-AC1 (product repo): make -C tui-rust stage COREOS_DIR=$PWD" >&2
  exit 4
fi
echo "    staged image/tui/neural-ice-tui ($(du -h image/tui/neural-ice-tui | cut -f1))"

# Use the root container store (matches bib --local and caches the base) when
# PODMAN_SUDO=1 (CI); rootless otherwise (local dev).
if [ "${PODMAN_SUDO:-0}" = "1" ]; then PODMAN=(sudo podman); else PODMAN=(podman); fi

echo "==> Building ${REF}:${SEMVER}  (channel ${REF}:${CHANNEL}${SUFFIX})  variant=${VARIANT}  key=$([ -n "$SSH_AUTHORIZED_KEY" ] && echo baked || echo vanilla)"
"${PODMAN[@]}" build \
  --platform "$PLATFORM" \
  --build-arg "SSH_AUTHORIZED_KEY=${SSH_AUTHORIZED_KEY}" \
  --build-arg "VARIANT=${VARIANT}" \
  --build-arg "OTA_IMGREF=${REF}:${CHANNEL}${SUFFIX}" \
  --build-arg "OS_VERSION=${SEMVER}" \
  -f image/Containerfile.bootc \
  -t "${REF}:${SEMVER}" \
  -t "${REF}:${CHANNEL}${SUFFIX}" \
  .

echo "SEMVER=${SEMVER}"
echo "REF=${REF}"

if [ "$PUSH" = "1" ]; then
  echo "==> Pushing ${REF}:${SEMVER} and ${REF}:${CHANNEL}${SUFFIX}"
  "${PODMAN[@]}" push "${REF}:${SEMVER}"
  "${PODMAN[@]}" push "${REF}:${CHANNEL}${SUFFIX}"
  DIGEST="$("${PODMAN[@]}" image inspect "${REF}:${SEMVER}" --format '{{.Digest}}' 2>/dev/null || true)"
  echo "DIGEST=${DIGEST}"
fi
