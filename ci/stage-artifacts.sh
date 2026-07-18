#!/usr/bin/env bash
#
# Stage the heavy, gitignored GB10 artifacts into the image/ build tree so that
# ci/build-image.sh (and bootc-image-builder) can consume them.
#
# These artifacts are produced rarely by the kernel/driver build (build-kernel)
# and live OUTSIDE git. Point the *_SRC env vars at where they were produced on
# the build host. Defaults match the lab build host layout.
#
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

RPM_SRC="${RPM_SRC:-$HOME/neural-ice-build/output}"   # kernel-*.rpm (4k flavor) incl. kernel-modules-nvidia-open-*.rpm (ephemeral-signed)
USERSPACE_SRC="${USERSPACE_SRC:-$HOME/neural-ice-build/nvidia-userspace}"  # usr/ tree
SIGNEDBOOT_SRC="${SIGNEDBOOT_SRC:-$HOME/neural-ice-build/signed-boot}"     # signed vmlinuz/shim/grub + DER

stage() {  # $1=label  $2=src  $3=dest  $4=glob
  local label="$1" src="$2" dest="$3" glob="${4:-*}"
  install -d "$dest"
  shopt -s nullglob
  # shellcheck disable=SC2206  # intentional glob expansion (nullglob set)
  local files=( "$src"/$glob )
  shopt -u nullglob
  if [ "${#files[@]}" -eq 0 ]; then
    echo "WARN: no $label artifacts in $src (glob '$glob')" >&2
    return 0
  fi
  cp -v "${files[@]}" "$dest/"
  echo "staged ${#files[@]} $label file(s) -> $dest"
}

rm -rf image/rpms image/nvidia-userspace image/signed-boot

# The NVIDIA modules now ship inside kernel-modules-nvidia-open-*.rpm (ephemeral-
# signed by the kernel build), caught by the *.rpm glob — no loose .ko to stage.
stage "kernel RPM" "$RPM_SRC"       image/rpms            '*.rpm'
# userspace + signed-boot are directory trees (usr/...), copy recursively
if [ -d "$USERSPACE_SRC" ]; then install -d image/nvidia-userspace; cp -a "$USERSPACE_SRC/." image/nvidia-userspace/; echo "staged nvidia-userspace tree"; else echo "WARN: no nvidia-userspace at $USERSPACE_SRC" >&2; fi
if [ -d "$SIGNEDBOOT_SRC" ]; then install -d image/signed-boot;     cp -a "$SIGNEDBOOT_SRC/." image/signed-boot/;     echo "staged signed-boot tree"; else echo "WARN: no signed-boot at $SIGNEDBOOT_SRC" >&2; fi

echo "==> staging complete"
