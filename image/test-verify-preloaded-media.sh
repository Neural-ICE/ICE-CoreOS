#!/usr/bin/env bash
# Linux integration test for the finalized raw-media acceptance boundary.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ "$(uname -s)" != Linux ]]; then
  echo "SKIP: final-media loop test requires Linux"
  exit 0
fi
if [[ $EUID -ne 0 ]]; then
  echo "run through: sudo unshare --mount --propagation private -- bash $0" >&2
  exit 1
fi
[[ "$(findmnt -n -o PROPAGATION /)" == private ]] || {
  echo "integration fixture requires a private mount namespace" >&2
  exit 1
}

for command in blockdev findmnt losetup lsblk mkfs.xfs mknod mount python3 sgdisk truncate udevadm umount zstd; do
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
artifact="$work/preloaded.img.zst"
artifact_checksum="$artifact.sha256"
receipt="$work/receipt.json"
receipt_checksum="$receipt.sha256"
python3 "$ROOT/image/verify-preloaded-media.py" \
  --raw "$raw" \
  --expected-manifest "$work/expected.json" \
  --artifact "$artifact" \
  --artifact-checksum "$artifact_checksum" \
  --compression zstd-fast \
  --receipt "$receipt" \
  --receipt-checksum "$receipt_checksum"
(
  cd "$work"
  sha256sum -c "$(basename "$artifact_checksum")"
  sha256sum -c "$(basename "$receipt_checksum")"
)
python3 - "$receipt" "$artifact" "$raw" <<'PY'
import hashlib
import json
import sys

receipt_path, artifact_path, raw_path = sys.argv[1:]
with open(receipt_path, encoding="ascii") as stream:
    receipt = json.load(stream)
assert receipt["schema"] == "neural-ice-preloaded-final-media-receipt-v1"
assert receipt["raw"]["size"] == 512 * 1024 * 1024
assert receipt["ni_seed"]["fstype"] == "xfs"
assert receipt["artifact"]["compression"] == "zstd-fast"
assert receipt["artifact"]["filename"] == artifact_path.rsplit("/", 1)[-1]
for path, expected in ((artifact_path, receipt["artifact"]), (raw_path, receipt["raw"])):
    digest = hashlib.sha256()
    size = 0
    with open(path, "rb", buffering=0) as stream:
        while chunk := stream.read(8 * 1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
    assert {"sha256": digest.hexdigest(), "size": size} == {
        "sha256": expected["sha256"],
        "size": expected["size"],
    }
PY
test "$(zstd -q -d -c "$artifact" | sha256sum | cut -d' ' -f1)" = \
  "$(sha256sum "$raw" | cut -d' ' -f1)"

printf 'owner-data\n' > "$work/owned-receipt.json"
if python3 "$ROOT/image/verify-preloaded-media.py" \
  --raw "$raw" \
  --expected-manifest "$work/expected.json" \
  --artifact "$raw" \
  --artifact-checksum "$work/uncompressed.img.sha256" \
  --compression none \
  --receipt "$work/owned-receipt.json" \
  --receipt-checksum "$work/owned-receipt.json.sha256"; then
  echo "gate overwrote an existing receipt" >&2
  exit 1
fi
test "$(cat "$work/owned-receipt.json")" = owner-data

python3 "$ROOT/image/seed-tree-manifest.py" \
  --tree "store=$work/source/store" \
  --tree "models=$work/source/models" \
  --output "$work/missing-payload.json"
if python3 "$ROOT/image/verify-preloaded-media.py" \
  --raw "$raw" \
  --expected-manifest "$work/missing-payload.json" \
  --artifact "$work/root-injection.img.zst" \
  --artifact-checksum "$work/root-injection.img.zst.sha256" \
  --compression zstd-fast \
  --receipt "$work/root-injection.json" \
  --receipt-checksum "$work/root-injection.json.sha256"; then
  echo "gate accepted an unapproved payload root" >&2
  exit 1
fi

loop="$(losetup --find --show "$raw")"
if python3 "$ROOT/image/verify-preloaded-media.py" \
  --raw "$raw" \
  --expected-manifest "$work/expected.json" \
  --artifact "$work/existing-loop.img.zst" \
  --artifact-checksum "$work/existing-loop.img.zst.sha256" \
  --compression zstd-fast \
  --receipt "$work/should-not-exist.json" \
  --receipt-checksum "$work/should-not-exist.json.sha256"; then
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
  --raw "$raw" \
  --expected-manifest "$work/expected.json" \
  --artifact "$work/ambiguous.img.zst" \
  --artifact-checksum "$work/ambiguous.img.zst.sha256" \
  --compression zstd-fast \
  --receipt "$work/ambiguous.json" \
  --receipt-checksum "$work/ambiguous.json.sha256"; then
  echo "gate accepted two ni-seed partitions" >&2
  exit 1
fi

echo "FINAL_MEDIA_INTEGRATION_TEST_OK"
