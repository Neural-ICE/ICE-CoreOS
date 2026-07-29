#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$REPO_ROOT/ci/stage-nvidia-userspace.sh"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/ice-coreos-nvidia-userspace-test.XXXXXX")"
trap 'chmod -R u+w "$TMP" 2>/dev/null || true; rm -rf "$TMP"' EXIT

fail() {
  echo "FAIL: $*" >&2
  exit 1
}
expect_failure() {
  if "$@" >"$TMP/unexpected.out" 2>&1; then
    cat "$TMP/unexpected.out" >&2
    fail "command unexpectedly succeeded: $*"
  fi
}

VERSION=580.159.03
SOURCE="$TMP/NVIDIA-Linux-aarch64-$VERSION"
install -d "$SOURCE/firmware"
for binary in nvidia-smi nvidia-modprobe nvidia-persistenced; do
  printf 'binary %s\n' "$binary" > "$SOURCE/$binary"
done
for library in libcuda libnvidia-ml libnvidia-cfg libnvidia-ptxjitcompiler; do
  printf 'library %s\n' "$library" > "$SOURCE/${library}.so.$VERSION"
done
for firmware in gsp_ga10x.bin gsp_tu10x.bin; do
  printf 'firmware %s\n' "$firmware" > "$SOURCE/firmware/$firmware"
done

DEST="$TMP/staged"
"$SCRIPT" "$SOURCE" "$DEST" "$VERSION" >/dev/null
[[ -x "$DEST/usr/bin/nvidia-smi" ]] || fail "nvidia-smi not executable"
[[ -x "$DEST/usr/lib64/libcuda.so.$VERSION" ]] || fail "versioned libcuda missing"
[[ "$(stat -c '%a' "$DEST/usr/lib/firmware/nvidia/$VERSION/gsp_ga10x.bin")" == 644 ]] \
  || fail "firmware mode is not 0644"
[[ "$(find "$DEST" -type f | wc -l)" == 9 ]] || fail "unexpected staged file set"
expect_failure "$SCRIPT" "$SOURCE" "$DEST" "$VERSION"

MISSING="$TMP/missing"
cp -a "$SOURCE" "$MISSING"
rm "$MISSING/libcuda.so.$VERSION"
expect_failure "$SCRIPT" "$MISSING" "$TMP/missing-dest" "$VERSION"
[[ ! -e "$TMP/missing-dest" ]] || fail "failed staging published a destination"

expect_failure "$SCRIPT" "$SOURCE" "$TMP/wrong-version" 595.58.03
[[ ! -e "$TMP/wrong-version" ]] || fail "mixed-version staging published a destination"

echo "NVIDIA userspace staging tests: PASS"
