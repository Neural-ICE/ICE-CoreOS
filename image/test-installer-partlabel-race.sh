#!/usr/bin/env bash
# shellcheck disable=SC2016 # literal source-contract assertions below
#
# The sealed-medium producer renames partitions on a LOOP device
# (`sfdisk --part-label "$LOOP" N name`) and then looks the next partition up by
# label. Each rename makes the kernel re-read the loop's partition table, the
# ${LOOP}pN nodes are removed and re-created, and a blkid that runs before the
# table has settled reads an absent node as "no label": run 37522252563 died at
# "ERROR: installer ESP not found" on a build that had passed with the same code.
#
#   1. SOURCE CONTRACT -- the producer re-syncs and waits (partitions_settle)
#      after EVERY partition-table change, and reads labels with the probing,
#      fail-loud part_label. No sleep.
#   2. BEHAVIOUR -- the producer's own lifted functions drive the producer's own
#      rename sequence on a real GPT loop device, N times, and every lookup must
#      find its partition. Needs `sudo -n`, losetup -P, sfdisk, mkfs.vfat and
#      mkfs.ext4; without them part 2 SKIPs (NI_PARTLABEL_REQUIRE_TOOLS=1 turns
#      the skip into a failure). NI_PARTLABEL_ITERATIONS sets N (default 25).
#      NI_PARTLABEL_LEGACY=1 swaps in the pre-fix lookup, with no settle, to
#      MEASURE the race it fixed (that run is expected to fail; it is not CI).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
USB="$ROOT/image/build-installer-usb.sh"
ITER="${NI_PARTLABEL_ITERATIONS:-25}"
fail() { echo "FAIL: $*" >&2; exit 1; }

# --- 1. source contract ---------------------------------------------------- #
lift() {
  awk -v n="$1" '$0 ~ "^"n"\\(\\) \\{" {p=1} p {print} p && /^}$/ {exit}' "$USB"
}
for fn in partitions_settle part_label; do
  [[ -n "$(lift "$fn")" ]] || fail "$fn is not defined in image/build-installer-usb.sh"
done
! grep -Eq 'blkid -s LABEL' "$USB" || fail "a label is read without blkid -p (stale blkid cache / udev database)"
grep -Fq 'sudo blkid -p -s LABEL' "$USB" || fail "part_label does not probe the node with blkid -p"
! grep -Eq '^[[:space:]]*sleep[[:space:]]' <(lift partitions_settle; lift part_label) \
  || fail "the partition-table wait is a sleep, not a deterministic settle"
# Every partition-table change on the loop device is followed, before the next
# statement that is not a continuation of it, by partitions_settle.
python3 - "$USB" <<'PYEOF' || fail "a partition-table change on \$LOOP is not followed by partitions_settle"
import re
import sys

lines = open(sys.argv[1], encoding="utf-8").read().splitlines()
bad = 0
seen = 0
for i, line in enumerate(lines):
    code = line.split("#", 1)[0]
    if re.search(r'sfdisk\b.*--part-(label|type)\b.*"\$LOOP"', code):
        seen += 1
        j = i
        while lines[j].rstrip().endswith("\\"):
            j += 1
        # the failure handler is the continuation line `|| { ...; }`
        while j + 1 < len(lines) and lines[j + 1].lstrip().startswith("||"):
            j += 1
        if 'partitions_settle "$LOOP"' not in lines[j + 1]:
            print(f"line {i + 1}: no partitions_settle after: {line.strip()}", file=sys.stderr)
            bad += 1
if seen < 2:
    print("expected at least two sfdisk --part-label on $LOOP", file=sys.stderr)
    bad += 1
sys.exit(1 if bad else 0)
PYEOF
echo "ok: every partition-table change on \$LOOP is followed by partitions_settle"

# --- 2. behaviour ----------------------------------------------------------- #
skip() {
  if [[ "${NI_PARTLABEL_REQUIRE_TOOLS:-0}" == 1 ]]; then fail "$1 (NI_PARTLABEL_REQUIRE_TOOLS=1)"; fi
  echo "SKIP: $1 -- behavioural part not run"; exit 0
}
for tool in losetup sfdisk partx udevadm blkid mkfs.vfat mkfs.ext4 truncate; do
  command -v "$tool" >/dev/null 2>&1 || skip "$tool is missing"
done
sudo -n true 2>/dev/null || skip "sudo -n is not available"

work="$(mktemp -d "${TMPDIR:-/tmp}/ni-partlabel-race.XXXXXX")"
LOOP=""
cleanup() {
  [[ -z "$LOOP" ]] || sudo losetup -d "$LOOP" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT
RAW="$work/raw.img"
# bib's shape: an ESP (vfat EFI-SYSTEM), an ext4 `boot`, a root. Sizes are small.
truncate -s 300M "$RAW"
sfdisk --quiet "$RAW" <<'SFDISK'
label: gpt
start=2048, size=64MiB, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B, name="EFI-SYSTEM"
size=64MiB, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, name="boot"
type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, name="root"
SFDISK
LOOP="$(sudo losetup --find --show -P "$RAW")"
sudo udevadm settle
sudo mkfs.vfat -F32 -n EFI-SYSTEM "${LOOP}p1" >/dev/null
sudo mkfs.ext4 -q -L boot "${LOOP}p2"
sudo mkfs.ext4 -q -L root "${LOOP}p3"
sudo udevadm settle

if [[ "${NI_PARTLABEL_LEGACY:-0}" == 1 ]]; then
  part_label() { sudo blkid -s LABEL -o value "$1" 2>/dev/null || true; }
  partitions_settle() { :; }
  echo "LEGACY lookup (no settle): measuring the race, a failure is expected"
else
  # shellcheck disable=SC1090
  source <(lift partitions_settle; lift part_label)
fi

# The producer's own sequence: name the payload, find boot, name it void, find
# the ESP. Restored each round so the next one starts from the same table.
find_by_label() {
  local want="$1" p label
  for p in "${LOOP}"p*; do
    label="$(part_label "$p")" || return 2
    [[ "$label" == "$want" ]] && { echo "$p"; return 0; }
  done
  return 1
}
failures=0
for ((i = 1; i <= ITER; i++)); do
  ok=1
  sudo sfdisk --quiet --part-label "$LOOP" 3 ni-installer-payload >/dev/null 2>&1 || ok=0
  partitions_settle "$LOOP"
  boot="$(find_by_label boot)" || { ok=0; echo "round $i: boot not found" >&2; }
  sudo sfdisk --quiet --part-label "$LOOP" 2 ni-installer-void >/dev/null 2>&1 || ok=0
  partitions_settle "$LOOP"
  esp="$(find_by_label EFI-SYSTEM)" || { ok=0; echo "round $i: ESP not found" >&2; }
  [[ "$ok" == 1 && "$boot" == "${LOOP}p2" && "$esp" == "${LOOP}p1" ]] || failures=$((failures + 1))
  sudo sfdisk --quiet --part-label "$LOOP" 3 root >/dev/null 2>&1 || true
  sudo sfdisk --quiet --part-label "$LOOP" 2 boot >/dev/null 2>&1 || true
  partitions_settle "$LOOP"
done
echo "iterations=$ITER failures=$failures"
(( failures == 0 )) || fail "$failures of $ITER lookups did not find their partition"

# A node that is not there is an ERROR, never an empty label.
if part_label "${LOOP}p99" 2>/dev/null; then
  [[ "${NI_PARTLABEL_LEGACY:-0}" == 1 ]] || fail "part_label accepted an absent node"
fi
echo "test-installer-partlabel-race: OK"
