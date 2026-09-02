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

for command in blockdev findmnt losetup lsblk mkfs.vfat mkfs.xfs mknod mount python3 sgdisk truncate udevadm umount zstd; do
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

printf '{"schema":"neural-ice-ota-lab-baseline-v1"}\n' > "$work/ota-lab-baseline.json"
printf '\001detached-signature-fixture\000\377' > "$work/ota-lab-baseline.sig"
bom_sha256="$(sha256sum "$work/ota-lab-baseline.json" | cut -d' ' -f1)"
signature_sha256="$(sha256sum "$work/ota-lab-baseline.sig" | cut -d' ' -f1)"
baseline_args=(
  --lab-baseline-bom-sha256 "$bom_sha256"
  --lab-baseline-signature-sha256 "$signature_sha256"
)

# A LAB-MANAGED medium may carry exactly one approved operator public key. The
# gate must accept precisely that key and refuse every other state: a key nobody
# approved, a key that drifted, and an approved key that never made it onto the
# medium.
ssh-keygen -q -t ed25519 -N '' -f "$work/operator" </dev/null
operator_key="$work/operator.pub"
operator_sha256="$(sha256sum "$operator_key" | cut -d' ' -f1)"
esp_key_args=(--esp-authorized-keys-sha256 "$operator_sha256")

expect_baseline_refusal() {
  local name="$1"
  shift
  if python3 "$ROOT/image/verify-preloaded-media.py" \
    --raw "$raw" \
    --expected-manifest "$work/expected.json" \
    --artifact "$raw" \
    --artifact-checksum "$work/$name.img.sha256" \
    --compression none \
    --receipt "$work/$name.json" \
    --receipt-checksum "$work/$name.json.sha256" \
    "${sealed_core_args[@]}" "${esp_key_args[@]}" "$@"; then
    echo "gate accepted forbidden LAB baseline state: $name" >&2
    exit 1
  fi
  test ! -e "$work/$name.img.sha256"
  test ! -e "$work/$name.json"
}

# --------------------------------------------------------------------------- #
# THE FIXTURE IS A REAL SEALED MEDIUM, FINISHED THE WAY PRELOADED FINISHES ONE
# (review 2026-09-01, P1 #4).
#
# 🔴 WHY IT IS NO LONGER THREE EMPTY PARTITIONS. The gate now runs the FULL
# sealed-core inspector on the finished raw, under the exclusive lock it holds,
# before it publishes the artifact, the checksum or the receipt. A fixture with
# no signed UKI and no sealed payload could only ever exercise the seed and ESP
# halves of this gate -- which is precisely the coverage that let the sealed core
# go uninspected after the seed phase.
#
# So the fixture is built by the same library image/test-installer-media.sh uses
# (one definition of "a sealed medium"), and then FINISHED here exactly as
# image/build-preloaded.sh finishes one: grow the file, relocate the GPT backup
# header, append `ni-seed`, mkfs it and copy the seed tree in.
# --------------------------------------------------------------------------- #
TMP="$work/fixture"; mkdir -p "$TMP"
fail() { echo "FAIL: $*" >&2; exit 1; }
# shellcheck source=image/test-lib/sealed-medium-fixture.sh
source "$ROOT/image/test-lib/sealed-medium-fixture.sh"
sealed_core_args=(
  --expect-verity-root-hash "$ROOT_HASH"
  --expect-payload-digest "$PAYLOAD_DIGEST"
  --expect-mode install
  --expect-access-profile lab-managed
  --expect-hardware-target nvidia-gb10-arm64
  --expect-trust-policy-id "$POLICY_ID"
)

raw="$work/preloaded.img"
cp "$RAW" "$raw"
truncate -s "+384M" "$raw"
sgdisk -e "$raw" >/dev/null
sgdisk -n 0:0:0 -c 0:ni-seed -t 0:8300 "$raw" >/dev/null
seed_number="$(sgdisk -p "$raw" | awk '/ni-seed/{n=$1} END{print n}')"
[ -n "$seed_number" ] || { echo "ni-seed partition not created" >&2; exit 1; }
loop="$(losetup --find --show --partscan "$raw")"
udevadm settle
mount "${loop}p1" "$mountpoint"
"$ROOT/ota/neural-ice-lab-baseline-handoff.sh" stage-media \
  "$work/ota-lab-baseline.json" "$bom_sha256" \
  "$work/ota-lab-baseline.sig" "$signature_sha256" "$mountpoint"
"$ROOT/image/lib/installer-ssh-key.sh" install \
  "$operator_key" "$operator_sha256" "$mountpoint"
sync
umount "$mountpoint"
mkfs.xfs -q -L ni-seed "${loop}p${seed_number}"
mount "${loop}p${seed_number}" "$mountpoint"
cp -a "$work/source/." "$mountpoint/"
sync
umount "$mountpoint"
losetup --detach "$loop"
loop=''
raw_bytes="$(stat -c '%s' "$raw")"

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
  --receipt-checksum "$receipt_checksum" \
  "${sealed_core_args[@]}" "${baseline_args[@]}" "${esp_key_args[@]}"
(
  cd "$work"
  sha256sum -c "$(basename "$artifact_checksum")"
  sha256sum -c "$(basename "$receipt_checksum")"
)
python3 - "$receipt" "$artifact" "$raw" "$bom_sha256" "$signature_sha256" "$operator_sha256" \
  "$raw_bytes" "$ROOT_HASH" "$PAYLOAD_DIGEST" "$POLICY_ID" <<'PY'
import hashlib
import json
import sys

(
    receipt_path,
    artifact_path,
    raw_path,
    bom_sha256,
    signature_sha256,
    operator_sha256,
    raw_bytes,
    root_hash,
    payload_digest,
    policy_id,
) = sys.argv[1:]
with open(receipt_path, encoding="ascii") as stream:
    receipt = json.load(stream)
assert receipt["schema"] == "neural-ice-preloaded-final-media-receipt-v2"
assert receipt["raw"]["size"] == int(raw_bytes)
# The receipt now RECORDS what the sealed-core inspection established, so a
# medium blessed without one is visible in the receipt rather than only in the
# gate's exit status.
assert receipt["sealed_core"] == {
    "access_profile": "lab-managed",
    "hardware_target": "nvidia-gb10-arm64",
    "inspected": "after-final-write",
    "media_mode": "install",
    "payload_digest": payload_digest,
    "signed": True,
    "trust_policy_id": policy_id,
    "verity_root_hash": root_hash,
}
assert receipt["ni_seed"]["fstype"] == "xfs"
assert receipt["artifact"]["compression"] == "zstd-fast"
assert receipt["artifact"]["filename"] == artifact_path.rsplit("/", 1)[-1]
assert receipt["lab_baseline"]["bom"] == {
    "path": "ice-coreos/ota-lab-baseline.json",
    "sha256": bom_sha256,
    "size": 44,
}
assert receipt["lab_baseline"]["signature"] == {
    "path": "ice-coreos/ota-lab-baseline.sig",
    "sha256": signature_sha256,
    "size": 29,
}
assert receipt["esp_authorized_keys"]["path"] == "ice-coreos/authorized_keys"
assert receipt["esp_authorized_keys"]["sha256"] == operator_sha256
assert receipt["lab_baseline"]["esp"]["fstype"] == "vfat"
assert receipt["lab_baseline"]["esp"]["partuuid"]
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

# A pair that was not explicitly approved by exact hashes must never be
# accepted into a final-media receipt.
expect_baseline_refusal unapproved

# Drift and absence on the finalized ESP are checked from a read-only loop,
# before any artifact or receipt is published.
loop="$(losetup --find --show --partscan "$raw")"
udevadm settle
mount "${loop}p1" "$mountpoint"
printf 'drift\n' > "$mountpoint/ice-coreos/ota-lab-baseline.json"
sync
umount "$mountpoint"
losetup --detach "$loop"
loop=''
expect_baseline_refusal drift "${baseline_args[@]}"

loop="$(losetup --find --show --partscan "$raw")"
udevadm settle
mount "${loop}p1" "$mountpoint"
rm -f "$mountpoint/ice-coreos/ota-lab-baseline.json" \
  "$mountpoint/ice-coreos/ota-lab-baseline.sig"
sync
umount "$mountpoint"
losetup --detach "$loop"
loop=''
expect_baseline_refusal absent "${baseline_args[@]}"

loop="$(losetup --find --show --partscan "$raw")"
udevadm settle
mount "${loop}p1" "$mountpoint"
"$ROOT/ota/neural-ice-lab-baseline-handoff.sh" stage-media \
  "$work/ota-lab-baseline.json" "$bom_sha256" \
  "$work/ota-lab-baseline.sig" "$signature_sha256" "$mountpoint"
sync
umount "$mountpoint"
losetup --detach "$loop"
loop=''

# --- the installer SSH key on the ESP -------------------------------------- #
# An approved key that is present must still be REFUSED when the caller approved
# nothing: media that carries a key nobody signed off on must not be published.
expect_media_refusal() { # <name> <message> [extra args...]
  local name="$1" message="$2"
  shift 2
  if python3 "$ROOT/image/verify-preloaded-media.py" \
    --raw "$raw" \
    --expected-manifest "$work/expected.json" \
    --artifact "$raw" \
    --artifact-checksum "$work/$name.img.sha256" \
    --compression none \
    --receipt "$work/$name.json" \
    --receipt-checksum "$work/$name.json.sha256" "${sealed_core_args[@]}" "$@"; then
    echo "$message" >&2
    exit 1
  fi
  test ! -e "$work/$name.img.sha256"
  test ! -e "$work/$name.json"
}

expect_media_refusal esp-key-unapproved \
  "gate published a medium carrying an unapproved installer SSH key" \
  "${baseline_args[@]}"

wrong_sha256="$(printf 'not-the-operator-key' | sha256sum | cut -d' ' -f1)"
expect_media_refusal esp-key-drift \
  "gate accepted an installer SSH key that differs from the approved hash" \
  "${baseline_args[@]}" --esp-authorized-keys-sha256 "$wrong_sha256"

expect_media_refusal esp-key-malformed-hash \
  "gate accepted a malformed approved-key hash" \
  "${baseline_args[@]}" --esp-authorized-keys-sha256 deadbeef

# A key that was approved but never staged: the medium is unreachable in the lab
# and the operator would only find out on hardware.
loop="$(losetup --find --show --partscan "$raw")"
udevadm settle
mount "${loop}p1" "$mountpoint"
mv "$mountpoint/ice-coreos/authorized_keys" "$work/removed-key"
sync
umount "$mountpoint"
losetup --detach "$loop"
loop=''
expect_media_refusal esp-key-absent \
  "gate accepted a medium missing its approved installer SSH key" \
  "${sealed_core_args[@]}" "${baseline_args[@]}" "${esp_key_args[@]}"

# A MODIFIED ESP. vfat cannot hold a symlink, so the modification an attacker
# actually has on this filesystem is a padded/appended payload -- and the gate
# bounds the read at the same 512 bytes the key validator does.
loop="$(losetup --find --show --partscan "$raw")"
udevadm settle
mount "${loop}p1" "$mountpoint"
{ cat "$work/removed-key"; head -c 4096 /dev/zero | tr '\0' 'A'; } \
  > "$mountpoint/ice-coreos/authorized_keys"
sync
umount "$mountpoint"
losetup --detach "$loop"
loop=''
expect_media_refusal esp-key-oversized \
  "gate accepted an oversized installer SSH key on the ESP" \
  "${sealed_core_args[@]}" "${baseline_args[@]}" "${esp_key_args[@]}"

# Restore the approved key so every refusal below stays attributable to the
# state it is actually testing rather than to a leftover modified ESP.
loop="$(losetup --find --show --partscan "$raw")"
udevadm settle
mount "${loop}p1" "$mountpoint"
rm -f "$mountpoint/ice-coreos/authorized_keys"
"$ROOT/image/lib/installer-ssh-key.sh" install \
  "$operator_key" "$operator_sha256" "$mountpoint"
sync
umount "$mountpoint"
losetup --detach "$loop"
loop=''

printf 'owner-data\n' > "$work/owned-receipt.json"
if python3 "$ROOT/image/verify-preloaded-media.py" \
  --raw "$raw" \
  --expected-manifest "$work/expected.json" \
  --artifact "$raw" \
  --artifact-checksum "$work/uncompressed.img.sha256" \
  --compression none \
  --receipt "$work/owned-receipt.json" \
  --receipt-checksum "$work/owned-receipt.json.sha256" \
  "${sealed_core_args[@]}" "${baseline_args[@]}" "${esp_key_args[@]}"; then
  echo "gate overwrote an existing receipt" >&2
  exit 1
fi
test "$(cat "$work/owned-receipt.json")" = owner-data
test ! -e "$work/uncompressed.img.sha256"

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
  --receipt-checksum "$work/root-injection.json.sha256" \
  "${sealed_core_args[@]}" "${baseline_args[@]}" "${esp_key_args[@]}"; then
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
  --receipt-checksum "$work/should-not-exist.json.sha256" \
  "${sealed_core_args[@]}" "${baseline_args[@]}" "${esp_key_args[@]}"; then
  echo "gate accepted a raw with an existing writable loop" >&2
  exit 1
fi
losetup --detach "$loop"
loop=''

mkdir "$work/fake-bin"
cat > "$work/fake-bin/findmnt" <<'EOF'
#!/bin/sh
printf '%s\n' '{"filesystems":[]}'
EOF
chmod 0755 "$work/fake-bin/findmnt"
before_mount_dirs="$(find /run -maxdepth 1 -type d -name 'neural-ice-ni-seed.*' -print | sort)"
if env PATH="$work/fake-bin:$PATH" python3 "$ROOT/image/verify-preloaded-media.py" \
  --raw "$raw" \
  --expected-manifest "$work/expected.json" \
  --artifact "$work/bad-mount.img.zst" \
  --artifact-checksum "$work/bad-mount.img.zst.sha256" \
  --compression zstd-fast \
  --receipt "$work/bad-mount.json" \
  --receipt-checksum "$work/bad-mount.json.sha256" \
  "${sealed_core_args[@]}" "${baseline_args[@]}" "${esp_key_args[@]}"; then
  echo "gate accepted ambiguous post-mount verification" >&2
  exit 1
fi
after_mount_dirs="$(find /run -maxdepth 1 -type d -name 'neural-ice-ni-seed.*' -print | sort)"
test "$after_mount_dirs" = "$before_mount_dirs"
test -z "$(losetup --associated "$raw" --noheadings --output NAME)"

# --------------------------------------------------------------------------- #
# THE SEALED CORE, MUTATED AFTER THE SEED PHASE (review 2026-09-01, P1 #4).
#
# This is the window the finding is about: build-preloaded.sh holds the raw open
# for writing long after the only inspection that used to happen, and the receipt
# and checksum were published without looking at the boot path again. Each
# mutation below is applied to the FINISHED raw and must stop finalization dead --
# no artifact, no checksum, no receipt.
# --------------------------------------------------------------------------- #
sealed_core_mutation() { # <name> <python mutation> <message>
  local name="$1" mutation="$2" message="$3"
  python3 - "$raw" "$work/$name.restore" "$mutation" <<'PY'
import struct
import sys

raw, restore, mutation = sys.argv[1:]
with open(raw, "rb") as handle:
    handle.seek(512)
    header = handle.read(512)
if header[:8] != b"EFI PART":
    raise SystemExit("the fixture has no GPT at LBA 1")
entries_lba, = struct.unpack_from("<Q", header, 72)
count, size = struct.unpack_from("<II", header, 80)
partitions = {}
with open(raw, "rb") as handle:
    handle.seek(entries_lba * 512)
    for _ in range(count):
        entry = handle.read(size)
        name = entry[56:128].decode("utf-16-le").rstrip("\x00")
        if name:
            first, = struct.unpack_from("<Q", entry, 32)
            partitions[name] = first * 512
if mutation == "payload":
    # The first byte of the first REGION, past the 4096-byte header: its recorded
    # sha256 and its recomputed dm-verity root hash must both stop matching.
    offset = partitions["ni-installer-payload"] + 4096
elif mutation == "void":
    # The emptied remains of what bootc-image-builder wrote. It is OVERWRITTEN,
    # not deleted, and anything written back into it is a boot authority nothing
    # signed.
    offset = partitions["ni-installer-void"]
else:
    raise SystemExit(f"unknown mutation {mutation}")
with open(raw, "r+b") as handle:
    handle.seek(offset)
    original = handle.read(16)
    with open(restore, "wb") as saved:
        saved.write(struct.pack("<Q", offset) + original)
    handle.seek(offset)
    handle.write(bytes(byte ^ 0xFF for byte in original))
PY
  expect_media_refusal "$name" "$message" "${baseline_args[@]}" "${esp_key_args[@]}"
  python3 - "$raw" "$work/$name.restore" <<'PY'
import struct
import sys

raw, restore = sys.argv[1:]
blob = open(restore, "rb").read()
offset, = struct.unpack_from("<Q", blob, 0)
with open(raw, "r+b") as handle:
    handle.seek(offset)
    handle.write(blob[8:])
PY
}

sealed_core_mutation payload-mutated payload \
  "gate published a medium whose sealed payload changed after the seed phase"
sealed_core_mutation void-repopulated void \
  "gate published a medium whose emptied boot partition was written to after the seed phase"

# ...and the restored medium is still accepted, so both refusals are about the
# mutation and not about the fixture having drifted.
python3 "$ROOT/image/verify-preloaded-media.py" \
  --raw "$raw" \
  --expected-manifest "$work/expected.json" \
  --artifact "$work/restored.img" \
  --artifact-checksum "$work/restored.img.sha256" \
  --compression none \
  --receipt "$work/restored.json" \
  --receipt-checksum "$work/restored.json.sha256" \
  "${sealed_core_args[@]}" "${baseline_args[@]}" "${esp_key_args[@]}"
test -s "$work/restored.json"

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
  --receipt-checksum "$work/ambiguous.json.sha256" \
  "${sealed_core_args[@]}" "${baseline_args[@]}" "${esp_key_args[@]}"; then
  echo "gate accepted two ni-seed partitions" >&2
  exit 1
fi

echo "FINAL_MEDIA_INTEGRATION_TEST_OK"
