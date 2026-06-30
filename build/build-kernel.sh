#!/usr/bin/env bash
#
# Neural ICE CoreOS — Deliverable 1
# Compilation orchestrator: GB10 kernel (kernel-64k / standard) + NVIDIA r595
# driver, inside an isolated Podman container.
#
# Designed for the ARM64 build host : <user>@<arm64-build-host> (DGX Spark)
# Portable as-is to the x86_64 host : <x86_64-build-host>.
#
# Usage :
#   ./build/build-kernel.sh <aarch64|x86_64> [--shell] [--no-driver]
#
# Typical remote execution (from the dev workstation):
#   ssh <user>@<arm64-build-host> 'bash -s' < build/build-kernel.sh aarch64
#   # or, repo already synced on the Spark:
#   ssh <user>@<arm64-build-host> '/srv/neural-ice/build/build-kernel.sh aarch64'
#
set -euo pipefail

# --------------------------------------------------------------------------- #
# Parameters
# --------------------------------------------------------------------------- #
ARCH="${1:-}"
shift || true

OPEN_SHELL="false"
BUILD_DRIVER="true"
for arg in "$@"; do
  case "$arg" in
    --shell)      OPEN_SHELL="true" ;;
    --no-driver)  BUILD_DRIVER="false" ;;
    *) echo "Unknown argument: $arg" >&2; exit 2 ;;
  esac
done

# Configuration (overridable via the environment)
KERNEL_REPO="${KERNEL_REPO:-https://gitlab.com/redhat/edge/kernel/nvidia-gb10.git}"
KERNEL_BRANCH="${KERNEL_BRANCH:-main}"                 # edge/kernel/nvidia-gb10 branch
NVIDIA_DRIVER_VERSION="${NVIDIA_DRIVER_VERSION:-595.58.03}"
BUILDER_IMAGE="${BUILDER_IMAGE:-neural-ice/kernel-builder:stream10}"
WORKSPACE="${WORKSPACE:-${HOME}/neural-ice-build}"     # persistent across runs (git cache)
OUTPUT_DIR="${OUTPUT_DIR:-${WORKSPACE}/output}"        # final RPMs collected here

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# --------------------------------------------------------------------------- #
# Validation
# --------------------------------------------------------------------------- #
case "$ARCH" in
  aarch64) KERNEL_FLAVOR="64k"  ; RPM_GLOB="kernel-64k-*.rpm" ;;
  x86_64)  KERNEL_FLAVOR="std"  ; RPM_GLOB="kernel-*.rpm"     ;;
  *) echo "Usage: $0 <aarch64|x86_64> [--shell] [--no-driver]" >&2; exit 2 ;;
esac

HOST_ARCH="$(uname -m)"
if [[ "$HOST_ARCH" != "$ARCH" ]]; then
  echo "WARNING: requested arch ($ARCH) != host arch ($HOST_ARCH)." >&2
  echo "Kernel compilation must be NATIVE. Run this script on the $ARCH host." >&2
  echo "  aarch64 -> <user>@<arm64-build-host> (DGX Spark)   |   x86_64 -> <x86_64-build-host>" >&2
  exit 3
fi

command -v podman >/dev/null || { echo "podman not found" >&2; exit 4; }

echo "==> Neural ICE | kernel build"
echo "    arch=$ARCH flavor=$KERNEL_FLAVOR driver=r${NVIDIA_DRIVER_VERSION%%.*} ($NVIDIA_DRIVER_VERSION)"
echo "    workspace=$WORKSPACE output=$OUTPUT_DIR"

mkdir -p "$WORKSPACE" "$OUTPUT_DIR"

# --------------------------------------------------------------------------- #
# Build image (built if absent)
# --------------------------------------------------------------------------- #
if ! podman image exists "$BUILDER_IMAGE"; then
  echo "==> Building the build image $BUILDER_IMAGE"
  podman build -t "$BUILDER_IMAGE" -f "${SCRIPT_DIR}/Containerfile.builder" "${SCRIPT_DIR}"
fi

# --------------------------------------------------------------------------- #
# Script executed INSIDE the isolated container
# --------------------------------------------------------------------------- #
read -r -d '' INNER_SCRIPT <<INNER || true
set -euo pipefail
ARCH="$ARCH"
KERNEL_FLAVOR="$KERNEL_FLAVOR"
KERNEL_REPO="$KERNEL_REPO"
KERNEL_BRANCH="$KERNEL_BRANCH"
NVIDIA_DRIVER_VERSION="$NVIDIA_DRIVER_VERSION"
BUILD_DRIVER="$BUILD_DRIVER"

cd /workspace

# 1) Clone/update of the kernel source (persistent cache via the volume)
if [[ -d nvidia-gb10/.git ]]; then
  echo "==> Source present: git fetch"
  git -C nvidia-gb10 fetch --depth=1 origin "\${KERNEL_BRANCH}"
  git -C nvidia-gb10 checkout "\${KERNEL_BRANCH}"
  git -C nvidia-gb10 reset --hard "origin/\${KERNEL_BRANCH}"
else
  echo "==> Clone \${KERNEL_REPO} (\${KERNEL_BRANCH})"
  git clone --depth=1 --branch "\${KERNEL_BRANCH}" "\${KERNEL_REPO}" nvidia-gb10
fi

cd nvidia-gb10/redhat

# 2) Dynamic resolution of the kernel BuildRequires (source of truth = the source)
echo "==> Resolving build dependencies (make dist-get-buildreqs)"
MISSING="\$(make dist-get-buildreqs 2>/dev/null | grep 'Missing dependencies:' | cut -d: -f2- || true)"
if [[ -n "\${MISSING// /}" ]]; then
  echo "    Missing dependencies: \${MISSING}"
  echo "    -> to be installed in the build image (re-run after adding to the Containerfile)."
  echo "    Attempting transient installation (requires root in the container):"
  sudo dnf -y install \${MISSING} 2>/dev/null || \
    echo "    (transient installation not possible as non-root: complete Containerfile.builder)"
fi

# 3) Empty localversion to avoid a stray version suffix
: > localversion || true

# 4) Compilation + RPM packaging
echo "==> Compiling the kernel (make dist-rpms) — may take a while"
make dist-rpms

# 5) Collecting the kernel RPMs
RPMDIR="\$(pwd)/rpm/RPMS/\${ARCH}"
echo "==> Kernel RPMs produced in \${RPMDIR}"
ls -1 "\${RPMDIR}" | sed 's/^/      /'
cp -v "\${RPMDIR}"/*.rpm /output/

# 6) NVIDIA r595 driver (open GPU kernel modules) via kmod spec
if [[ "\${BUILD_DRIVER}" == "true" ]]; then
  echo "==> Build NVIDIA open driver r\${NVIDIA_DRIVER_VERSION} (kmod-nvidia-open)"
  SPEC="/workspace/kmod-nvidia-open.spec"
  if [[ -f "\${SPEC}" ]]; then
    rpmbuild -bb --define "_disable_source_fetch 0" \
             --define "kver \$(rpm -qp --qf '%{VERSION}-%{RELEASE}.%{ARCH}' \\
                        \$(ls /output/kernel-*-core-*.rpm | head -1))" \
             "\${SPEC}" || echo "    (driver build failed — check the .spec and network access)"
    cp -v "\${HOME}"/rpmbuild/RPMS/\${ARCH}/kmod-nvidia-open-*.rpm /output/ 2>/dev/null || true
  else
    echo "    kmod-nvidia-open.spec missing from /workspace: driver step skipped."
    echo "    Drop the .spec (r\${NVIDIA_DRIVER_VERSION}) into /workspace to enable it."
  fi
fi

echo "==> Done. Contents of /output:"
ls -1 /output | sed 's/^/      /'
INNER

# --------------------------------------------------------------------------- #
# Launching the isolated container
# --------------------------------------------------------------------------- #
# Isolation: rootless, no-new-privileges, network required (clone + buildreqs),
# volumes limited to the workspace and the output. No host mounts beyond that.
PODMAN_RUN=(podman run --rm
  --name "neural-ice-kbuild-${ARCH}"
  --hostname "kbuild-${ARCH}"
  --security-opt no-new-privileges
  --cap-drop ALL
  --userns keep-id
  -v "${WORKSPACE}:/workspace:Z"
  -v "${OUTPUT_DIR}:/output:Z"
  -e "TERM=${TERM:-xterm}"
)

if [[ "$OPEN_SHELL" == "true" ]]; then
  echo "==> Interactive shell in the build container"
  exec "${PODMAN_RUN[@]}" -it "$BUILDER_IMAGE"
fi

echo "==> Launching the isolated compilation"
"${PODMAN_RUN[@]}" "$BUILDER_IMAGE" -lc "$INNER_SCRIPT"

echo ""
echo "============================================================"
echo " Final RPMs available in: $OUTPUT_DIR"
echo "   (expected pattern: $RPM_GLOB + kmod-nvidia-open-*.rpm)"
echo " Next step: ./image/build-and-push.sh $ARCH"
echo "============================================================"
