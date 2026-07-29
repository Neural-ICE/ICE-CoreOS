#!/usr/bin/env bash
#
# Materialize the minimal NVIDIA userspace/firmware payload from one official
# extracted .run bundle. The destination is immutable-by-construction: it must
# not exist and is published only after every version-matched input is present.
set -euo pipefail

SOURCE_DIR="${1:-}"
DEST_DIR="${2:-}"
NVIDIA_DRIVER_VERSION="${3:-}"

die() {
  echo "ERROR: $*" >&2
  exit 2
}

[[ "$NVIDIA_DRIVER_VERSION" =~ ^[0-9]+([.][0-9]+)+$ ]] \
  || die "NVIDIA driver version must be dotted numeric"
[[ -n "$SOURCE_DIR" && "$SOURCE_DIR" == /* && -d "$SOURCE_DIR" && ! -L "$SOURCE_DIR" ]] \
  || die "source must be an absolute, existing, non-symlink directory"
[[ -n "$DEST_DIR" && "$DEST_DIR" == /* && ! -e "$DEST_DIR" && ! -L "$DEST_DIR" ]] \
  || die "destination must be an absolute path that does not exist"

SOURCE_DIR="$(cd "$SOURCE_DIR" && pwd -P)"
DEST_PARENT="$(dirname "$DEST_DIR")"
DEST_NAME="$(basename "$DEST_DIR")"
install -d -m 0755 "$DEST_PARENT"
DEST_PARENT="$(cd "$DEST_PARENT" && pwd -P)"
[[ "$DEST_NAME" != "." && "$DEST_NAME" != ".." && -n "$DEST_NAME" ]] \
  || die "unsafe destination name"

TMP_DIR="$DEST_PARENT/.${DEST_NAME}.preparing.$$"
[[ ! -e "$TMP_DIR" ]] || die "temporary destination already exists"
cleanup() {
  rm -rf -- "$TMP_DIR"
}
trap cleanup EXIT

install -d -m 0755 \
  "$TMP_DIR/usr/bin" \
  "$TMP_DIR/usr/lib64" \
  "$TMP_DIR/usr/lib/firmware/nvidia/$NVIDIA_DRIVER_VERSION"

for binary in nvidia-smi nvidia-modprobe nvidia-persistenced; do
  [[ -f "$SOURCE_DIR/$binary" && ! -L "$SOURCE_DIR/$binary" ]] \
    || die "missing NVIDIA binary: $binary"
  install -m 0755 "$SOURCE_DIR/$binary" "$TMP_DIR/usr/bin/$binary"
done

for library in libcuda libnvidia-ml libnvidia-cfg libnvidia-ptxjitcompiler; do
  file="${library}.so.${NVIDIA_DRIVER_VERSION}"
  [[ -f "$SOURCE_DIR/$file" && ! -L "$SOURCE_DIR/$file" ]] \
    || die "missing version-matched NVIDIA library: $file"
  install -m 0755 "$SOURCE_DIR/$file" "$TMP_DIR/usr/lib64/$file"
done

for firmware in gsp_ga10x.bin gsp_tu10x.bin; do
  [[ -f "$SOURCE_DIR/firmware/$firmware" && ! -L "$SOURCE_DIR/firmware/$firmware" ]] \
    || die "missing NVIDIA firmware: firmware/$firmware"
  install -m 0644 "$SOURCE_DIR/firmware/$firmware" \
    "$TMP_DIR/usr/lib/firmware/nvidia/$NVIDIA_DRIVER_VERSION/$firmware"
done

mv -- "$TMP_DIR" "$DEST_DIR"
trap - EXIT
echo "NVIDIA_USERSPACE_SRC=$DEST_DIR"
echo "NVIDIA_DRIVER_VERSION=$NVIDIA_DRIVER_VERSION"
