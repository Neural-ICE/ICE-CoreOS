#!/usr/bin/env bash
# Linux integration test for the finalized raw-media acceptance boundary.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ "$(uname -s)" != Linux ]]; then
  echo "SKIP: final-media loop test requires Linux"
  exit 0
fi
if [[ $EUID -ne 0 ]]; then
  exec sudo --non-interactive --preserve-env=PATH bash "$0" "$@"
fi

for command in blockdev findmnt losetup lsblk mkfs.xfs mknod mount python3 sgdisk truncate udevadm umount unshare; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "missing integration-test command: $command" >&2
    exit 1
  }
done

work="$(mktemp -d /var/tmp/ni-final-media-test.XXXXXX)"
loop=''
mountpoint="$work/mnt"
cleanup() {
  umount "$mountpoint" 2>/dev/null || true
  if [[ -n "$loop" ]]; then losetup --detach "$loop" 2>/dev/null || true; fi
  rm -rf "$work"
}
trap cleanup EXIT

mkdir -p "$work/source/store/overlay" "$work/source/models/model-a" "$work/source/payload" "$mountpoint"
printf 'layer' > "$work/source/store/overlay/layer"
mknod "$work/source/store/overlay/.wh.removed" c 0 0
printf 'weights' > "$work/source/models/model-a/weights"
ln "$work/source/models/model-a/weights" "$work/source/models/model-a/weights-hardlink"
ln -s weights "$work/source/models/model-a/current"
printf '#!/bin/sh\nexit 0\n' > "$work/source/payload/apply.sh"
chmod 0755 "$work/source/payload/apply.sh"
for number in $(seq 1 1100); do
  printf '%s' "$number" > "$work/source/models/model-a/file-$number"
done

python3 "$ROOT/image/seed-tree-manifest.py" \
  --tree "store=$work/source/store" \
  --tree "models=$work/source/models" \
  --tree "payload=$work/source/payload" \
  --output "$work/expected.json"

raw="$work/preloaded.img"
truncate -s 512M "$raw"
sgdisk --clear "$raw" >/dev/null
sgdisk --new 1:2048:+320M --change-name 1:ni-seed --typecode 1:8300 "$raw" >/dev/null
sgdisk --new 2:0:+128M --change-name 2:spare --typecode 2:8300 "$raw" >/dev/null
loop="$(losetup --find --show --partscan "$raw")"
udevadm settle
mkfs.xfs -q -L ni-seed "${loop}p1"
mount "${loop}p1" "$mountpoint"
cp -a "$work/source/." "$mountpoint/"
sync
umount "$mountpoint"
losetup --detach "$loop"
loop=''

ulimit -n 64
python3 "$ROOT/image/verify-preloaded-media.py" \
  --raw "$raw" \
  --expected-manifest "$work/expected.json" \
  --receipt "$work/receipt.json"
python3 - "$work/receipt.json" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="ascii") as stream:
    receipt = json.load(stream)
assert receipt["schema"] == "neural-ice-preloaded-final-media-receipt-v1"
assert receipt["raw"]["size"] == 512 * 1024 * 1024
assert receipt["ni_seed"]["fstype"] == "xfs"
PY

loop="$(losetup --find --show "$raw")"
if python3 "$ROOT/image/verify-preloaded-media.py" \
  --raw "$raw" --expected-manifest "$work/expected.json" --receipt "$work/should-not-exist.json"; then
  echo "gate accepted a raw with an existing writable loop" >&2
  exit 1
fi
losetup --detach "$loop"
loop=''

loop="$(losetup --find --show --partscan "$raw")"
udevadm settle
sgdisk --change-name 2:ni-seed "$loop" >/dev/null
losetup --detach "$loop"
loop=''
if python3 "$ROOT/image/verify-preloaded-media.py" \
  --raw "$raw" --expected-manifest "$work/expected.json" --receipt "$work/ambiguous.json"; then
  echo "gate accepted two ni-seed partitions" >&2
  exit 1
fi

echo "FINAL_MEDIA_INTEGRATION_TEST_OK"
