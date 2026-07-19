#!/usr/bin/env bash
#
# Neural ICE CoreOS — Deliverable 1
# Compilation orchestrator: GB10 kernel (STANDARD 4k flavor) + NVIDIA r595
# driver, inside an isolated Podman container. 4k pages (NOT kernel-64k) for
# userspace compatibility with the container AI stack (qdrant/vLLM/...). The GB10
# SoC is not in the stock el10 kernel, hence we still build from the Red Hat
# `nvidia-gb10` tree — just the 4k flavor. See ADR-0006 (and ADR-0002 signing).
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
# Full upstream commit only. A branch such as `latest` is mutable and cannot
# identify the source of a persistent artifact generation.
KERNEL_REF="${KERNEL_REF:-fa4faa0227e00c2291e47b120e71c7aed0fe27b7}"
NVIDIA_DRIVER_VERSION="${NVIDIA_DRIVER_VERSION:-595.58.03}"
NVIDIA_OPEN_SRC="${NVIDIA_OPEN_SRC:-}"                 # path to NVIDIA .../kernel-open (Option D: modules built in-tree & ephemeral-signed)
WORKSPACE="${WORKSPACE:-${HOME}/neural-ice-build}"     # persistent across runs (git cache)
OUTPUT_DIR="${OUTPUT_DIR:-${WORKSPACE}/output}"        # final RPMs collected here

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILDER_DEFINITION_SHA256="$(sha256sum "${SCRIPT_DIR}/Containerfile.builder" | awk '{print $1}')"
BUILDER_IMAGE="${BUILDER_IMAGE:-neural-ice/kernel-builder:stream10-${BUILDER_DEFINITION_SHA256:0:12}}"

# --------------------------------------------------------------------------- #
# Validation
# --------------------------------------------------------------------------- #
# aarch64 now builds the STANDARD 4k `kernel` flavor (was `kernel-64k`). The
# nvidia-gb10 tree emits both flavors from `make dist-rpms`; downstream we select
# the 4k `kernel*` RPMs (see image/Containerfile.bootc). See ADR-0006.
case "$ARCH" in
  aarch64) KERNEL_FLAVOR="std"  ; RPM_GLOB="kernel-*.rpm" ;;
  x86_64)  KERNEL_FLAVOR="std"  ; RPM_GLOB="kernel-*.rpm" ;;
  *) echo "Usage: $0 <aarch64|x86_64> [--shell] [--no-driver]" >&2; exit 2 ;;
esac

HOST_ARCH="$(uname -m)"
if [[ "$HOST_ARCH" != "$ARCH" ]]; then
  echo "WARNING: requested arch ($ARCH) != host arch ($HOST_ARCH)." >&2
  echo "Kernel compilation must be NATIVE. Run this script on the $ARCH host." >&2
  echo "  aarch64 -> <user>@<arm64-build-host> (DGX Spark)   |   x86_64 -> <x86_64-build-host>" >&2
  exit 3
fi

for required_command in podman sbverify sbattach sha256sum; do
  command -v "$required_command" >/dev/null || { echo "$required_command not found" >&2; exit 4; }
done
[[ "$KERNEL_REF" =~ ^[0-9a-f]{40}$ ]] || {
  echo "ERROR: KERNEL_REF must be a full 40-character upstream commit SHA." >&2; exit 5; }
[[ "$NVIDIA_DRIVER_VERSION" =~ ^[0-9]+([.][0-9]+)+$ ]] || {
  echo "ERROR: NVIDIA_DRIVER_VERSION must be a dotted numeric version." >&2; exit 5; }

# Option D prerequisites: the NVIDIA open source (built in-tree) and the template
# patch that wires it into the kernel spec. Skipped with --no-driver.
if [[ "$BUILD_DRIVER" == "true" ]]; then
  [[ -d "$NVIDIA_OPEN_SRC" && "$(basename "$NVIDIA_OPEN_SRC")" == "kernel-open" ]] || {
    echo "ERROR: set NVIDIA_OPEN_SRC to the NVIDIA .../kernel-open dir (Option D), or pass --no-driver." >&2; exit 6; }
  [[ -f "${SCRIPT_DIR}/patches/nvidia-open-inline-sign.patch" ]] || {
    echo "ERROR: missing build/patches/nvidia-open-inline-sign.patch" >&2; exit 6; }
fi
NVIDIA_OPEN_SOURCE_SHA256="none"
if [[ "$BUILD_DRIVER" == "true" ]]; then
  NVIDIA_OPEN_SOURCE_SHA256="$(
    tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner \
      -C "$(dirname "$NVIDIA_OPEN_SRC")" -cf - "$(basename "$NVIDIA_OPEN_SRC")" | sha256sum | awk '{print $1}'
  )"
fi

echo "==> Neural ICE | kernel build"
echo "    arch=$ARCH flavor=$KERNEL_FLAVOR driver=r${NVIDIA_DRIVER_VERSION%%.*} ($NVIDIA_DRIVER_VERSION)"
echo "    workspace=$WORKSPACE output=$OUTPUT_DIR"

mkdir -p "$WORKSPACE" "$OUTPUT_DIR"

# --------------------------------------------------------------------------- #
# Build image (built if absent)
# --------------------------------------------------------------------------- #
if ! podman image exists "$BUILDER_IMAGE"; then
  echo "==> Building the build image $BUILDER_IMAGE"
  podman build --label "ch.neural-ice.builder-definition-sha256=$BUILDER_DEFINITION_SHA256" \
    -t "$BUILDER_IMAGE" -f "${SCRIPT_DIR}/Containerfile.builder" "${SCRIPT_DIR}"
fi
BUILDER_LABEL="$(podman image inspect "$BUILDER_IMAGE" --format '{{index .Labels "ch.neural-ice.builder-definition-sha256"}}')"
[[ "$BUILDER_LABEL" == "$BUILDER_DEFINITION_SHA256" ]] || {
  echo "ERROR: cached builder image does not match Containerfile.builder" >&2; exit 4; }
BUILDER_IMAGE_ID="$(podman image inspect "$BUILDER_IMAGE" --format '{{.Id}}')"
[[ "$BUILDER_IMAGE_ID" =~ ^[0-9a-f]{64}$ ]] || { echo "ERROR: invalid builder image id" >&2; exit 4; }

# --------------------------------------------------------------------------- #
# Script executed INSIDE the isolated container
# --------------------------------------------------------------------------- #
read -r -d '' INNER_SCRIPT <<INNER || true
set -euo pipefail
ARCH="$ARCH"
KERNEL_FLAVOR="$KERNEL_FLAVOR"
KERNEL_REPO="$KERNEL_REPO"
KERNEL_REF="$KERNEL_REF"
NVIDIA_DRIVER_VERSION="$NVIDIA_DRIVER_VERSION"
BUILD_DRIVER="$BUILD_DRIVER"

cd /workspace

# 1) Clone/update of the kernel source (persistent object cache via the volume)
if [[ -d nvidia-gb10/.git ]]; then
  echo "==> Source present: fetch exact commit \${KERNEL_REF}"
  git -C nvidia-gb10 remote set-url origin "\${KERNEL_REPO}"
else
  echo "==> Initialize \${KERNEL_REPO}"
  git init nvidia-gb10
  git -C nvidia-gb10 remote add origin "\${KERNEL_REPO}"
fi
git -C nvidia-gb10 fetch --depth=1 origin "\${KERNEL_REF}"
git -C nvidia-gb10 checkout --detach --force FETCH_HEAD
git -C nvidia-gb10 clean -ffdx
[[ "\$(git -C nvidia-gb10 rev-parse HEAD)" == "\${KERNEL_REF}" ]] || {
  echo "ERROR: fetched kernel revision does not match KERNEL_REF" >&2; exit 4; }

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

# 3b) Force the STANDARD 4k aarch64 flavor (ADR-0006). The nvidia-gb10 tree ships
#     "aarch64 64k only": redhat/Makefile sets BUILDOPTS with -arm64_4k, which
#     forces with_up=0 (no 4k 'up' kernel; see kernel.spec.template). We flip that
#     token to -arm64_64k and add -debug, so the build produces the 4k kernel and
#     drops the 64k and debug variants we don't ship (debug ~doubles build time).
#     Patched here (not via a tree commit) because
#     build-kernel.sh does a hard git reset every run.
if grep -qE '^BUILDOPTS \+=.*-arm64_4k' Makefile; then
  sed -i -E '/^BUILDOPTS \+=/ s/-arm64_4k\b/-arm64_64k -debug/' Makefile
  echo "==> Patched BUILDOPTS: build aarch64 4k, drop 64k + debug:"
  grep -E '^BUILDOPTS \+=' Makefile | sed 's/^/      /'
else
  echo "WARN: '-arm64_4k' not found in redhat/Makefile BUILDOPTS — upstream flavor" >&2
  echo "      selection changed; verify the 4k kernel is actually built below." >&2
fi

# 3c) Option D — build the NVIDIA open modules INSIDE this kernel rpmbuild, so the
#     kernel's own __modsign_install_post signs them with the per-build EPHEMERAL
#     module key (no key ever handled by us; see secureboot/signing-pipeline.md).
#     We stage the NVIDIA source as a spec Source and apply the template patch
#     AFTER the reset, exactly like the BUILDOPTS flip in 3b.
if [[ "\${BUILD_DRIVER}" == "true" ]]; then
  echo "==> Option D: stage NVIDIA open source + apply inline-signing patch"
  tar -C /nvsrc-parent --transform "s,^kernel-open,nvidia-open-gpu-\${NVIDIA_DRIVER_VERSION}," -cf - kernel-open \
    | xz -T0 -6 > rhel_files/nvidia-open-gpu-\${NVIDIA_DRIVER_VERSION}.tar.xz
  # Idempotent: the reused checkout carries local mods across 'git checkout -B',
  # so on a second run the template is already patched — skip re-applying.
  if git -C /workspace/nvidia-gb10 apply --reverse --check /patches/nvidia-open-inline-sign.patch 2>/dev/null; then
    echo "    kernel.spec.template already patched — skipping git apply"
  else
    git -C /workspace/nvidia-gb10 apply --verbose /patches/nvidia-open-inline-sign.patch
  fi
  # Keep the spec Source version in lock-step with the tarball we just staged.
  sed -i "s/^%global nvidia_open_ver .*/%global nvidia_open_ver \${NVIDIA_DRIVER_VERSION}/" kernel.spec.template
  echo "    staged rhel_files/nvidia-open-gpu-\${NVIDIA_DRIVER_VERSION}.tar.xz + patched kernel.spec.template"
fi

# 4) Compilation + RPM packaging (with Option D, the same run also builds and
#    ephemeral-signs the NVIDIA modules into kernel-modules-nvidia-open)
echo "==> Compiling the kernel (make dist-rpms) — may take a while"
make dist-rpms

# 5) Collecting the kernel RPMs
RPMDIR="\$(pwd)/rpm/RPMS/\${ARCH}"
echo "==> Kernel RPMs produced in \${RPMDIR}"
ls -1 "\${RPMDIR}" | sed 's/^/      /'
# Guard: the 4k 'up' kernel MUST be present (kernel-core-*), else the flavor flip
# failed and the image build would break later. Fail here, loudly, not silently.
if ! ls "\${RPMDIR}"/kernel-core-*.rpm >/dev/null 2>&1; then
  echo "ERROR: no 4k kernel-core-*.rpm produced — 4k flavor not built (see ADR-0006)." >&2
  exit 5
fi
# With Option D the NVIDIA modules are produced by the same rpmbuild; require the
# subpackage so a silently-dropped inline-signing step fails the build loudly.
if [[ "\${BUILD_DRIVER}" == "true" ]] && ! ls "\${RPMDIR}"/kernel-modules-nvidia-open-*.rpm >/dev/null 2>&1; then
  echo "ERROR: kernel-modules-nvidia-open-*.rpm missing — Option D inline signing failed." >&2
  exit 7
fi
cp -v "\${RPMDIR}"/*.rpm /output/

# Emit a content-bound metadata inventory while rpm is available inside the
# CentOS builder. The Ubuntu Spark host never needs RPM tooling to validate or
# consume a generation.
: > /output/rpm-metadata.tsv
for rpm_file in /output/*.rpm; do
  checksum="\$(sha256sum "\${rpm_file}" | awk '{print \$1}')"
  filename="\$(basename "\${rpm_file}")"
  metadata="\$(rpm -qp --qf '%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}' "\${rpm_file}")"
  printf '%s\t%s\t%s\n' "\${checksum}" "\${filename}" "\${metadata}" >> /output/rpm-metadata.tsv
done
LC_ALL=C sort -o /output/rpm-metadata.tsv /output/rpm-metadata.tsv

# Bind the later signed vmlinuz to this exact candidate. The signing pipeline
# carries this hash into signed-boot-provenance.env; finalization requires that
# provenance, so an older same-name boot payload cannot be paired accidentally.
VERIFY_DIR="\$(mktemp -d)"
trap 'rm -rf "\${VERIFY_DIR}"' EXIT
kernel_core_rpm="\$(rpm -qp --qf '%{NAME}\t%{VERSION}-%{RELEASE}.%{ARCH}\n' /output/*.rpm \
  | awk -F '\t' '\$1 == "kernel-core" {print \$2}')"
[[ -n "\${kernel_core_rpm}" ]] || { echo "ERROR: cannot resolve kernel-core uname" >&2; exit 8; }
(
  cd "\${VERIFY_DIR}"
  rpm2cpio /output/kernel-core-*.rpm | cpio -idm --quiet
)
VMLINUX="\${VERIFY_DIR}/lib/modules/\${kernel_core_rpm}/vmlinuz"
[[ -f "\${VMLINUX}" ]] || { echo "ERROR: kernel-core lacks expected vmlinuz for \${kernel_core_rpm}" >&2; exit 8; }
cp "\${VMLINUX}" /output/vmlinuz-to-sign
cat > /output/kernel-payload.env <<EOF_PAYLOAD
kernel_uname_r=\${kernel_core_rpm}
EOF_PAYLOAD
rm -rf "\${VERIFY_DIR}"
trap - EXIT

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

# Option D mounts: NVIDIA open source (its parent, read-only) + the template patch.
if [[ "$BUILD_DRIVER" == "true" ]]; then
  PODMAN_RUN+=(
    -v "$(dirname "$NVIDIA_OPEN_SRC"):/nvsrc-parent:ro,Z"
    -v "${SCRIPT_DIR}/patches:/patches:ro,Z"
  )
fi

if [[ "$OPEN_SHELL" == "true" ]]; then
  echo "==> Interactive shell in the build container"
  exec "${PODMAN_RUN[@]}" -it "$BUILDER_IMAGE"
fi

echo "==> Launching the isolated compilation"
"${PODMAN_RUN[@]}" "$BUILDER_IMAGE" -lc "$INNER_SCRIPT"

# Canonicalize the already distro-signed vmlinuz by removing every signature
# table, then bind that stable PE hash to the candidate. The original file is
# preserved as vmlinuz-to-sign for the Owner-controlled signing pipeline.
VMLINUX_CANONICAL="$(mktemp "${TMPDIR:-/tmp}/ice-coreos-vmlinuz.XXXXXX")"
trap 'rm -f "$VMLINUX_CANONICAL"' EXIT
"${SCRIPT_DIR}/../ci/canonicalize-vmlinuz.sh" "$OUTPUT_DIR/vmlinuz-to-sign" "$VMLINUX_CANONICAL"
printf 'vmlinuz_unsigned_sha256=%s\n' "$(sha256sum "$VMLINUX_CANONICAL" | awk '{print $1}')" \
  >> "$OUTPUT_DIR/kernel-payload.env"
cat >> "$OUTPUT_DIR/kernel-payload.env" <<EOF_PAYLOAD
builder_definition_sha256=$BUILDER_DEFINITION_SHA256
builder_image_id=$BUILDER_IMAGE_ID
nvidia_open_source_sha256=$NVIDIA_OPEN_SOURCE_SHA256
kernel_source_revision=$KERNEL_REF
nvidia_driver_version=$NVIDIA_DRIVER_VERSION
EOF_PAYLOAD
rm -f "$VMLINUX_CANONICAL"
trap - EXIT

echo ""
echo "============================================================"
echo " Final RPMs available in: $OUTPUT_DIR"
echo "   (expected pattern: $RPM_GLOB + kernel-modules-nvidia-open-*.rpm)"
echo " Kernel source revision: $KERNEL_REF"
echo " Next step: publish a verified artifact generation with ci/stage-artifacts.sh"
echo "============================================================"
