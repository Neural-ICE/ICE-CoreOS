#!/usr/bin/env bash
# shellcheck disable=SC2016 # literal source-contract assertions below
# The SEALED INSTALLER TRUST ANCHOR: the cmdline contract, the dm-verity
# assertion, the composite gate, and the ordering in the autoinstaller that
# makes all three mean something.
#
# Every negative below is a mutation an attacker holding a correctly signed
# installer USB could actually perform (DESIGN-NOTE-0001, Finding 1).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIB="$ROOT/image/lib/installer-trust.sh"
work="$(mktemp -d "${TMPDIR:-/tmp}/ni-installer-trust.XXXXXX")"
trap 'rm -rf "$work"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }

# shellcheck source=image/lib/access-policy.sh
source "$ROOT/image/lib/access-policy.sh"
# shellcheck source=image/lib/hardware-identity.sh
source "$ROOT/image/lib/hardware-identity.sh"
# shellcheck source=image/lib/installer-trust.sh
source "$LIB"

GOOD_HASH="$(printf 'installer-root' | sha256sum | awk '{print $1}')"
OTHER_HASH="$(printf 'someone-elses-root' | sha256sum | awk '{print $1}')"
# The SHA-256 of the sealed payload header — the value that binds every extent on
# the medium (root image, root hash tree, container store image, store hash tree)
# to this signature. See image/lib/installer-payload.sh.
PAYLOAD_DIGEST="$(printf 'installer-payload-header' | sha256sum | awk '{print $1}')"
KEY_BYTES='-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEtestkeytestkeytestkeytestkeyt
-----END PUBLIC KEY-----'
printf '%s\n' "$KEY_BYTES" > "$work/relauth.pub"
KEYID="$(sha256sum "$work/relauth.pub" | awk '{print $1}')"
POLICY_ID=neural-ice-secureboot-lab-v1
TARGET=nvidia-gb10-arm64

# --------------------------------------------------------------------------- #
# 1) DETERMINISTIC RENDER. Two builds of the same inputs must produce the same
#    bytes: a signed artefact whose contents differ run to run cannot be
#    reviewed, and a reviewer cannot tell a rebuild from a substitution.
# --------------------------------------------------------------------------- #
render() { bash "$LIB" render-cmdline "$@"; }
A="$(render customer-locked "$TARGET" "$KEYID" "$GOOD_HASH" "$PAYLOAD_DIGEST" "$POLICY_ID" quiet enforcing=0)"
B="$(render customer-locked "$TARGET" "$KEYID" "$GOOD_HASH" "$PAYLOAD_DIGEST" "$POLICY_ID" quiet enforcing=0)"
[ "$A" = "$B" ] || fail "the rendered cmdline is not deterministic"
# The key order is a CONSTANT, asserted literally: if it ever becomes
# input-dependent, every previously reviewed manifest silently stops matching.
expected="neuralice.trust=neural-ice-installer-trust-v1 neuralice.access_profile=customer-locked neuralice.hardware_target=$TARGET neuralice.payload=$PAYLOAD_DIGEST neuralice.relauth_keyid=$KEYID neuralice.relauth_schema=neural-ice-installer-release-authorization-v2 neuralice.rootverity=$GOOD_HASH neuralice.trust_policy_id=$POLICY_ID quiet enforcing=0"
[ "$A" = "$expected" ] || fail "the sealed cmdline is not in its canonical form:
  got:      $A
  expected: $expected"

# Values that could smuggle a second karg, traverse a path or express a policy
# this installer does not understand are refused AT BUILD TIME, where refusing
# is free.
render 'lab managed' "$TARGET" "$KEYID" "$GOOD_HASH" "$PAYLOAD_DIGEST" "$POLICY_ID" >/dev/null 2>&1 \
  && fail "a profile containing a space was sealed"
render wide-open "$TARGET" "$KEYID" "$GOOD_HASH" "$PAYLOAD_DIGEST" "$POLICY_ID" >/dev/null 2>&1 \
  && fail "an unknown access profile was sealed"
render customer-locked '../../etc' "$KEYID" "$GOOD_HASH" "$PAYLOAD_DIGEST" "$POLICY_ID" >/dev/null 2>&1 \
  && fail "a traversal-shaped hardware target was sealed"
render customer-locked "$TARGET" "$KEYID" deadbeef "$PAYLOAD_DIGEST" "$POLICY_ID" >/dev/null 2>&1 \
  && fail "a truncated verity root hash was sealed"
render customer-locked "$TARGET" "$KEYID" "$GOOD_HASH" "$PAYLOAD_DIGEST" some-other-policy >/dev/null 2>&1 \
  && fail "an unrecognised trust policy id was sealed"
render customer-locked "$TARGET" "$KEYID" "$GOOD_HASH" "$PAYLOAD_DIGEST" "$POLICY_ID" 'neuralice.access_profile=lab-managed' >/dev/null 2>&1 \
  && fail "an extra karg restating a sealed field was sealed"
render customer-locked "$TARGET" "$KEYID" "$GOOD_HASH" "$PAYLOAD_DIGEST" "$POLICY_ID" 'neuralice.relauth_schema=neural-ice-installer-release-authorization-v1' >/dev/null 2>&1 \
  && fail "an extra karg restating the sealed authorization schema was sealed"

# --------------------------------------------------------------------------- #
# 2) SHADOWING. systemd-stub honours the embedded .cmdline and ignores an
#    externally supplied one ONLY while Secure Boot is enforcing. With Secure
#    Boot off — a state physical access can reach — the two are concatenated.
#    A second occurrence must therefore REFUSE, not win and not lose.
# --------------------------------------------------------------------------- #
for key in neuralice.access_profile neuralice.rootverity neuralice.hardware_target \
  neuralice.trust_policy_id neuralice.relauth_keyid neuralice.relauth_schema neuralice.trust; do
  case "$key" in
    neuralice.access_profile) shadow="$key=lab-managed" ;;
    neuralice.rootverity)     shadow="$key=$OTHER_HASH" ;;
    neuralice.hardware_target) shadow="$key=some-other-box" ;;
    neuralice.trust_policy_id) shadow="$key=neural-ice-secureboot-prod-v1" ;;
    neuralice.relauth_keyid)  shadow="$key=$OTHER_HASH" ;;
    neuralice.relauth_schema) shadow="$key=neural-ice-installer-release-authorization-v1" ;;
    *)                        shadow="$key=neural-ice-installer-trust-v1" ;;
  esac
  bash "$LIB" field "$key" "$A $shadow" >/dev/null 2>&1 \
    && fail "a shadowed $key was resolved instead of refused"
  # ...and prepended, so this cannot be a "last one wins" accident either.
  bash "$LIB" field "$key" "$shadow $A" >/dev/null 2>&1 \
    && fail "a prepended $key was resolved instead of refused"
done
# A missing field is a refusal too: a partially sealed medium is not a medium
# this installer can reason about.
bash "$LIB" read-sealed "quiet enforcing=0" >/dev/null 2>&1 \
  && fail "a cmdline with no sealed anchor was accepted"
# An implausibly long cmdline is a corrupted or padded section, not a cmdline.
bash "$LIB" field neuralice.access_profile "$A $(head -c 5000 /dev/zero | tr '\0' 'x')" >/dev/null 2>&1 \
  && fail "an oversized cmdline was parsed"

# --------------------------------------------------------------------------- #
# 3) dm-verity. Three independent properties; any one alone is bypassable.
# --------------------------------------------------------------------------- #
export NEURAL_ICE_INSTALLER_TRUST_TESTING=1
export NEURAL_ICE_VERITY_STATUS_CMD="$work/verity-status"
export NEURAL_ICE_DMSETUP_CMD="$work/dmsetup"
export NEURAL_ICE_FINDMNT_CMD="$work/findmnt"
write_status() { cat > "$work/verity-status"; chmod +x "$work/verity-status"; }

# --------------------------------------------------------------------------- #
# THE TOPOLOGY MOCKS. `veritysetup status` describes a NAMED target; it says
# nothing about what is mounted. These two answer the question that was missing:
# which device serves the root, and what is that device actually made of.
#
# Both are functions of variables the test sets, so every case below is one
# concrete machine state rather than a rewritten script.
# --------------------------------------------------------------------------- #
DM_DEVNO="252:0"       # the verity mapper's device number
MOUNT_DEVNO="252:0"    # the device the root is actually mounted from
DM_TABLE_TYPE=verity   # what the mapper's dm table is made of
DM_TABLE_HASH=""       # the root hash inside that table
DM_TABLE_LINES=1       # how many segments the table has
write_topology() {
  cat > "$work/dmsetup" <<EOF
#!/usr/bin/env bash
case "\$1" in
  table)
    for _i in \$(seq 1 $DM_TABLE_LINES); do
      printf '0 8192 %s 1 7:0 7:1 4096 4096 1024 1 sha256 %s %s\\n' \
        '$DM_TABLE_TYPE' '$DM_TABLE_HASH' 'deadbeef'
    done
    ;;
  info) printf '  %s\\n' '$DM_DEVNO' ;;
  *) exit 2 ;;
esac
EOF
  cat > "$work/findmnt" <<EOF
#!/usr/bin/env bash
printf '%s\\n' '$MOUNT_DEVNO'
EOF
  chmod +x "$work/dmsetup" "$work/findmnt"
}

write_status <<EOF
#!/usr/bin/env bash
cat <<STATUS
/dev/mapper/\$1 is active and is in use.
  type:        VERITY
  status:      verified
  hash type:   1
  data block:  4096
  root hash:   $GOOD_HASH
STATUS
EOF
DM_TABLE_HASH="$GOOD_HASH"; write_topology
bash "$LIB" assert-root-verity "$GOOD_HASH" neuralice-installer-root >/dev/null \
  || fail "an active verity target with the sealed hash was refused"
bash "$LIB" assert-root-verity "$OTHER_HASH" neuralice-installer-root >/dev/null 2>&1 \
  && fail "a verity target over the WRONG tree was accepted"

# 🔴 THE FINDING THIS SECTION EXISTS FOR. A correct, active, correctly-hashed
# verity mapper can sit beside a completely different mutable root: the mapper
# answers, the hash matches, and every policy file is then read out of whatever
# `/` actually is. Proving a mapper exists is not proving it is the root.
MOUNT_DEVNO="8:2"; write_topology
bash "$LIB" assert-root-verity "$GOOD_HASH" neuralice-installer-root / >/dev/null 2>&1 \
  && fail "a verified mapper that is NOT the mounted root was accepted"
MOUNT_DEVNO="252:0"; write_topology

# The mapper's table must be a single verity target. A linear segment over a
# verity one, or two segments, is a device whose contents are not wholly
# verified even though `veritysetup status` describes it happily.
DM_TABLE_TYPE=linear; write_topology
bash "$LIB" assert-root-verity "$GOOD_HASH" neuralice-installer-root / >/dev/null 2>&1 \
  && fail "a mapper whose dm target is not verity was accepted"
DM_TABLE_TYPE=verity; DM_TABLE_LINES=2; write_topology
bash "$LIB" assert-root-verity "$GOOD_HASH" neuralice-installer-root / >/dev/null 2>&1 \
  && fail "a mapper with a stacked dm table was accepted"
DM_TABLE_LINES=1; write_topology

# The table's OWN root hash must be the sealed one too. `veritysetup status` and
# the dm table are two readings of one device; a disagreement between them is
# not something to resolve by preferring the friendlier answer.
DM_TABLE_HASH="$OTHER_HASH"; write_topology
bash "$LIB" assert-root-verity "$GOOD_HASH" neuralice-installer-root / >/dev/null 2>&1 \
  && fail "a mapper whose dm table carries another root hash was accepted"
DM_TABLE_HASH="$GOOD_HASH"; write_topology

# The target does not exist: an initramfs that failed to set verity up leaves
# exactly this state, and it proves nothing.
write_status <<'EOF'
#!/usr/bin/env bash
echo "Device $1 not found" >&2
exit 4
EOF
bash "$LIB" assert-root-verity "$GOOD_HASH" >/dev/null 2>&1 \
  && fail "a missing verity target was accepted"

# Present but inactive.
write_status <<EOF
#!/usr/bin/env bash
cat <<STATUS
/dev/mapper/\$1 is inactive.
  type:        VERITY
  status:      corrupted
  root hash:   $GOOD_HASH
STATUS
EOF
bash "$LIB" assert-root-verity "$GOOD_HASH" >/dev/null 2>&1 \
  && fail "a corrupted verity target was accepted"

# Active, correct hash, but activated to LOG corruption rather than refuse it.
# A medium that boots past a modified block is a medium whose verification is
# decorative.
write_status <<EOF
#!/usr/bin/env bash
cat <<STATUS
/dev/mapper/\$1 is active and is in use.
  type:        VERITY
  status:      verified
  root hash:   $GOOD_HASH
  flags:       ignore_corruption
STATUS
EOF
bash "$LIB" assert-root-verity "$GOOD_HASH" >/dev/null 2>&1 \
  && fail "a verity target activated with corruption ignored was accepted"

# --------------------------------------------------------------------------- #
# 4) THE COMPOSITE GATE. Order matters: the root must be proven BEFORE its
#    files are read, or the check is verifying a copy of the answer.
# --------------------------------------------------------------------------- #
# The MACHINE the medium is standing on. `hardware_target` used to be a word
# compared only with another copy of itself; the gate now measures the hardware
# and requires the answer to be one the sealed target admits.
SYSFS="$work/sys-gb10"
mkdir -p "$SYSFS/sys/firmware/devicetree/base"
printf 'nvidia,gb10\0' > "$SYSFS/sys/firmware/devicetree/base/compatible"
GB10_FINGERPRINT="$(bash "$ROOT/image/lib/hardware-identity.sh" fingerprint "$SYSFS")"
[ -n "$GB10_FINGERPRINT" ] || fail "cannot measure the fixture machine"
OTHER_SYSFS="$work/sys-other"
mkdir -p "$OTHER_SYSFS/sys/firmware/devicetree/base"
printf 'acme,someothersbc\0' > "$OTHER_SYSFS/sys/firmware/devicetree/base/compatible"
BLIND_SYSFS="$work/sys-blind"
mkdir -p "$BLIND_SYSFS"

make_root() { # <dir> <profile> <target> <policy-id> <keyfile>
  local dir=$1
  mkdir -p "$dir/usr/lib/neural-ice/keys" "$dir/usr/lib/neural-ice/hardware-identity"
  printf '%s\n' "$2" > "$dir/usr/lib/neural-ice/access-policy"
  printf '%s\n' "$3" > "$dir/usr/lib/neural-ice/hardware-target"
  printf '%s\n' "$4" > "$dir/usr/lib/neural-ice/signed-boot-trust-policy-id"
  printf '%s\n' "$GB10_FINGERPRINT" \
    > "$dir/usr/lib/neural-ice/hardware-identity/$3.fingerprints"
  cp "$5" "$dir/usr/lib/neural-ice/keys/release-authorization.pub"
}

# Every gate call names the mount point AND the machine, because those are the
# two things the anchor is a statement about.
gate() { # <root> <cmdline> [sysfs]
  bash "$LIB" gate "$1" "$2" neuralice-installer-root / "${3:-$SYSFS}"
}
write_status <<EOF
#!/usr/bin/env bash
cat <<STATUS
/dev/mapper/\$1 is active and is in use.
  type:        VERITY
  status:      verified
  root hash:   $GOOD_HASH
STATUS
EOF

good="$work/root-good"
make_root "$good" customer-locked "$TARGET" "$POLICY_ID" "$work/relauth.pub"
gate "$good" "$A" >/dev/null || fail "a consistent medium was refused"

# 🔴 THE ORIGINAL ATTACK: rewrite the marker on a correctly signed USB.
tampered="$work/root-tampered-profile"
make_root "$tampered" lab-managed "$TARGET" "$POLICY_ID" "$work/relauth.pub"
gate "$tampered" "$A" >/dev/null 2>&1 \
  && fail "a medium whose access-policy marker was flipped to lab-managed was accepted"

# The hardware target: a medium for one box must not install onto another.
wrong_target="$work/root-wrong-target"
make_root "$wrong_target" customer-locked some-other-box "$POLICY_ID" "$work/relauth.pub"
gate "$wrong_target" "$A" >/dev/null 2>&1 \
  && fail "a medium built for another hardware target was accepted"

# The Secure Boot trust policy: a lab-anchored medium claiming a prod chain.
wrong_policy="$work/root-wrong-policy"
make_root "$wrong_policy" customer-locked "$TARGET" neural-ice-secureboot-prod-v1 "$work/relauth.pub"
gate "$wrong_policy" "$A" >/dev/null 2>&1 \
  && fail "a medium whose trust-policy marker disagrees with the UKI was accepted"

# 🔴 THE VERIFIER'S OWN KEY. Substituting the release-authorization key would
# make the Finding-2 gate verify a statement the attacker signed. Its identity
# is sealed as a SHA-256, so a different key file is a different id.
swapped_key="$work/root-swapped-key"
printf 'a completely different key\n' > "$work/other.pub"
make_root "$swapped_key" customer-locked "$TARGET" "$POLICY_ID" "$work/other.pub"
gate "$swapped_key" "$A" >/dev/null 2>&1 \
  && fail "a substituted release-authorization key was accepted"
rm -f "$swapped_key/usr/lib/neural-ice/keys/release-authorization.pub"
gate "$swapped_key" "$A" >/dev/null 2>&1 \
  && fail "a medium with no release-authorization key was accepted"

# 🔴 THE ROOT ITSELF. A perfectly consistent set of markers over a tree the UKI
# never named is exactly the "correct verity target over the wrong bytes" case.
write_status <<EOF
#!/usr/bin/env bash
cat <<STATUS
/dev/mapper/\$1 is active and is in use.
  type:        VERITY
  status:      verified
  root hash:   $OTHER_HASH
STATUS
EOF
gate "$good" "$A" >/dev/null 2>&1 \
  && fail "a medium whose verity root hash is not the sealed one was accepted"

# 🔴 THE MACHINE. Everything above compared two build-time words with each
# other. A medium built for a GB10 must not be able to wipe some other arm64 box
# that happens to boot it, and a machine that cannot be identified at all must
# not be repartitioned on the strength of "no evidence either way".
write_status <<EOF
#!/usr/bin/env bash
cat <<STATUS
/dev/mapper/\$1 is active and is in use.
  type:        VERITY
  status:      verified
  root hash:   $GOOD_HASH
STATUS
EOF
DM_TABLE_HASH="$GOOD_HASH"; write_topology
gate "$good" "$A" >/dev/null || fail "the consistent medium was refused on its own hardware"
gate "$good" "$A" "$OTHER_SYSFS" >/dev/null 2>&1 \
  && fail "a medium sealed for one hardware target ran on a different machine"
gate "$good" "$A" "$BLIND_SYSFS" >/dev/null 2>&1 \
  && fail "a machine that cannot be identified at all was accepted"
# An empty or absent fingerprint list is absence, and absence fails closed.
: > "$good/usr/lib/neural-ice/hardware-identity/$TARGET.fingerprints"
gate "$good" "$A" >/dev/null 2>&1 \
  && fail "an empty measured-identity list was treated as 'anything goes'"
rm -f "$good/usr/lib/neural-ice/hardware-identity/$TARGET.fingerprints"
gate "$good" "$A" >/dev/null 2>&1 \
  && fail "a missing measured-identity list was treated as 'anything goes'"
printf '%s\n' "$GB10_FINGERPRINT" > "$good/usr/lib/neural-ice/hardware-identity/$TARGET.fingerprints"

# --------------------------------------------------------------------------- #
# 5) THE OVERRIDE MUST NOT BE A RUNTIME BYPASS. If the verity status command
#    could be injected in a privileged process, the whole assertion would be a
#    suggestion.
# --------------------------------------------------------------------------- #
grep -Fq 'a verity status override is forbidden in a privileged process' "$LIB" \
  || fail "the verity status override is not refused under a privileged process"
grep -Fq 'NEURAL_ICE_INSTALLER_TRUST_TESTING' "$LIB" \
  || fail "the verity status override is not gated on the test harness flag"
grep -Fq 'a dmsetup override is forbidden in a privileged process' "$LIB" \
  || fail "the dmsetup override is not refused under a privileged process"
grep -Fq 'a findmnt override is forbidden in a privileged process' "$LIB" \
  || fail "the findmnt override is not refused under a privileged process"

# --------------------------------------------------------------------------- #
# 5b) THE WRITABLE RUNTIME (review 2026-09-01, P0 #1). A dm-verity squashfs
#     cannot be written to, so the installer runs from an overlay over it. That
#     arrangement is only safe if its shape is proved: exactly one lower layer,
#     which is the verified mount, and an upper layer on a tmpfs — because a
#     tmpfs is empty at every boot and a disk-backed directory is not.
# --------------------------------------------------------------------------- #
LOWER=/run/neural-ice-installer/verity-root
mountinfo() { # write a /proc/self/mountinfo fixture and point the library at it
  printf '%s\n' "$@" > "$work/mountinfo"
  NEURAL_ICE_MOUNTINFO_FILE="$work/mountinfo" \
    NEURAL_ICE_INSTALLER_TRUST_TESTING=1 \
    bash "$LIB" assert-overlay-root "$LOWER" /
}
TMPFS_LINE="40 1 0:40 / /run/neural-ice-installer/rw rw,nosuid,nodev - tmpfs neural-ice-installer-rw rw,size=50%"
GOOD_OVERLAY="41 1 0:41 / / ro,relatime - overlay neural-ice-installer-root rw,lowerdir=$LOWER,upperdir=/run/neural-ice-installer/rw/upper,workdir=/run/neural-ice-installer/rw/work"

mountinfo "$TMPFS_LINE" "$GOOD_OVERLAY" >/dev/null \
  || fail "a correct overlay over the verified root was refused"

# The root is not an overlay at all: the medium booted the squashfs directly and
# the installer cannot write, or something else entirely is mounted there.
mountinfo "42 1 0:42 / / ro,relatime - squashfs /dev/mapper/neuralice-installer-root ro" >/dev/null 2>&1 \
  && fail "a non-overlay root was accepted as a writable runtime"

# The lower layer is NOT the verified mount. Every marker read afterwards would
# come from a tree nothing authenticated.
mountinfo "$TMPFS_LINE" \
  "41 1 0:41 / / ro,relatime - overlay x rw,lowerdir=/var/lib/attacker,upperdir=/run/neural-ice-installer/rw/upper,workdir=/run/neural-ice-installer/rw/work" \
  >/dev/null 2>&1 \
  && fail "an overlay over an unverified lower layer was accepted"

# TWO lower layers. A stacked layer above the verified one can shadow any file in
# it, so a `:`-separated list is a refusal rather than a choice of winner — and
# the refusal must SAY that, because "not the verified root" would send a reader
# looking for the wrong defect.
stacked="$(mountinfo "$TMPFS_LINE" \
  "41 1 0:41 / / ro,relatime - overlay x rw,lowerdir=$LOWER:/var/lib/attacker,upperdir=/run/neural-ice-installer/rw/upper,workdir=/run/neural-ice-installer/rw/work" 2>&1)" \
  && fail "an overlay with a second lower layer was accepted"
grep -q 'stacks several lower layers' <<<"$stacked" \
  || fail "a stacked lower layer was refused for the wrong reason: $stacked"

# The upper layer is DISK-BACKED. That is a directory an attacker can populate
# with the medium in hand, before this machine ever boots — which is exactly the
# state the tmpfs requirement exists to exclude.
mountinfo "43 1 0:43 / /mnt/persist rw,relatime - ext4 /dev/sda9 rw" \
  "41 1 0:41 / / ro,relatime - overlay x rw,lowerdir=$LOWER,upperdir=/mnt/persist/upper,workdir=/mnt/persist/work" \
  >/dev/null 2>&1 \
  && fail "an overlay whose upper layer is on disk was accepted"

# A LATER mount shadowing `/`: the last entry for a mount point is what is
# actually visible there, and that is the one an attacker would add.
mountinfo "$TMPFS_LINE" "$GOOD_OVERLAY" \
  "44 1 0:44 / / rw,relatime - tmpfs shadow rw" \
  >/dev/null 2>&1 \
  && fail "a later mount over / was ignored in favour of the earlier overlay"

# And the override that makes all of this testable must never be a runtime
# bypass: without the harness flag the library reads the real mount table.
NEURAL_ICE_MOUNTINFO_FILE="$work/mountinfo" bash "$LIB" assert-overlay-root "$LOWER" / \
  >/dev/null 2>&1 \
  && fail "the mountinfo override worked without the test-harness flag"

# --------------------------------------------------------------------------- #
# 5c) WHICH DISK THIS MACHINE BOOTED FROM (review 2026-09-01, P0 #1).
#
# 🔴 THE BUG. The installer asked `findmnt -no SOURCE /` and handed the answer to
# `lsblk -no PKNAME`. Section 5b above is the reason that could never work: `/`
# IS an overlay after switch-root, so `findmnt /` answers
# `neural-ice-installer-root` and PKNAME is empty. Every sealed Install medium
# died there.
#
# This section builds the state a REAL post-switch-root installer stands in --
# the overlay root, the initramfs breadcrumbs, a sysfs tree with a partition and
# its parent disk, and a payload extent carrying a real, canonical header -- and
# then mutates each part of it in turn. A fixture, not a source grep: the
# question is which DEVICE the lookup resolves, and no source assertion answers
# that.
# --------------------------------------------------------------------------- #
# shellcheck source=image/lib/installer-payload.sh
source "$ROOT/image/lib/installer-payload.sh"

medium="$work/medium"
mkdir -p "$medium/state" "$medium/dev" "$medium/sys/class/block" \
  "$medium/sys/devices/pci/nvme0/nvme0n1/nvme0n1p3" \
  "$medium/sys/devices/pci/nvme0/nvme0n1/nvme0n1p1"
# sysfs as the kernel presents it: /sys/class/block/<name> is a symlink into the
# device tree, and a partition's PARENT directory is its whole disk. That
# relationship is the whole of the derivation, so the fixture has to have it.
: > "$medium/sys/devices/pci/nvme0/nvme0n1/dev"
printf '259:0\n' > "$medium/sys/devices/pci/nvme0/nvme0n1/dev"
printf '259:3\n' > "$medium/sys/devices/pci/nvme0/nvme0n1/nvme0n1p3/dev"
printf '3\n'     > "$medium/sys/devices/pci/nvme0/nvme0n1/nvme0n1p3/partition"
printf '259:1\n' > "$medium/sys/devices/pci/nvme0/nvme0n1/nvme0n1p1/dev"
printf '1\n'     > "$medium/sys/devices/pci/nvme0/nvme0n1/nvme0n1p1/partition"
ln -sf ../../devices/pci/nvme0/nvme0n1 "$medium/sys/class/block/nvme0n1"
ln -sf ../../devices/pci/nvme0/nvme0n1/nvme0n1p3 "$medium/sys/class/block/nvme0n1p3"
ln -sf ../../devices/pci/nvme0/nvme0n1/nvme0n1p1 "$medium/sys/class/block/nvme0n1p1"

# A REAL sealed payload extent, rendered by the one parser this tree has, so the
# digest below is the digest an initramfs would have computed off the medium.
zero64="$(printf '%064d' 0)"
region_sha="$(printf 'region' | sha256sum | awk '{print $1}')"
MEDIUM_HEADER="$(payload_header_render localhost/bootc deadbeef "$zero64" "$zero64" \
  "root-image:4096:4096:$region_sha" \
  "root-hash:8192:4096:$region_sha" \
  "store-image:12288:4096:$region_sha" \
  "store-hash:16384:4096:$region_sha")" || fail "cannot render a payload header fixture"
MEDIUM_DIGEST="$(payload_header_digest "$MEDIUM_HEADER")"
write_payload_extent() { # $1=destination  $2=header text
  printf '%s' "$2" > "$1"
  # NUL-pad to the 4096-byte header block, exactly as the producer lays it out.
  local written; written="$(wc -c < "$1")"
  dd if=/dev/zero bs=1 count=$(( 4096 - written )) >> "$1" 2>/dev/null
}
write_payload_extent "$medium/dev/nvme0n1p3" "$MEDIUM_HEADER"
write_payload_extent "$medium/dev/nvme0n1p1" "$MEDIUM_HEADER"
: > "$medium/dev/nvme0n1"

reset_breadcrumbs() {
  printf '%s\n' "$medium/dev/nvme0n1p3" > "$medium/state/payload-device"
  printf '259:3\n' > "$medium/state/payload-device-devno"
}
# The fixture's "/dev" is a directory inside $work, so the production
# `^/dev/…` shape check would refuse every path here. Point the library's
# recorded-path grammar at the fixture root the same way every other override in
# this file works: through the harness flag, refused in a privileged process.
sealed_disk() { # -> "<node> <devno> <parent>"
  NEURAL_ICE_INSTALLER_TRUST_TESTING=1 \
  NEURAL_ICE_BLOCK_DEVICE_FIXTURE=1 \
  NEURAL_ICE_SYSFS_ROOT="$medium/sys" \
  NEURAL_ICE_DEV_PREFIX="$medium/dev" \
    bash "$LIB" sealed-medium-disk "$medium/state" "${1:-$MEDIUM_DIGEST}"
}

reset_breadcrumbs
good="$(sealed_disk)" || fail "a correct post-switch-root medium was not identified"
[ "$good" = "$medium/dev/nvme0n1p3 259:3 nvme0n1" ] \
  || fail "the sealed medium lookup returned '$good', not the payload partition and its parent disk"

# 🔴 THE REGRESSION ITSELF. `findmnt /` on this system answers with an overlay,
# and an overlay has no parent block device. Prove the installer no longer asks:
# the lookup above succeeded with NO mount table consulted at all.
# 🔴 AND THE INSTALLER MUST NOT ASK THE MOUNT TABLE AGAIN. `findmnt /` after
# switch-root answers with the overlay; a single surviving `lsblk -no PKNAME` on
# such a source is the whole finding.
# Executable lines only: the comments above the replacement deliberately quote
# the old shape, and a check that forbade naming the defect would forbid
# explaining it.
autoinstall_code() { grep -vE '^[[:space:]]*#' "$ROOT/ota/neural-ice-autoinstall.sh"; }
autoinstall_code | grep -Eq 'findmnt[^|]*(-no SOURCE|--output SOURCE)' \
  && fail "the autoinstaller still infers a device from findmnt's SOURCE column"
autoinstall_code | grep -Fq 'lsblk -no PKNAME' \
  && fail "the autoinstaller still derives its live disk from a mount source's PKNAME"
grep -Fq 'installer_trust_sealed_medium_disk "$INSTALLER_STATE_DIR" "$SEALED_PAYLOAD_DIGEST"' \
  "$ROOT/ota/neural-ice-autoinstall.sh" \
  || fail "the autoinstaller does not identify its medium from the authenticated payload partition"

# The breadcrumb is absent: this system did not boot from a sealed medium.
mv "$medium/state/payload-device" "$medium/state/payload-device.away"
sealed_disk >/dev/null 2>&1 && fail "a medium with no recorded payload device was identified anyway"
mv "$medium/state/payload-device.away" "$medium/state/payload-device"

# The breadcrumb is a SYMLINK. An installer that followed one would read whatever
# a root shell on the overlay pointed it at.
rm -f "$medium/state/payload-device"
ln -s "$medium/state/payload-device-devno" "$medium/state/payload-device"
sealed_disk >/dev/null 2>&1 && fail "a symlinked payload-device breadcrumb was followed"
rm -f "$medium/state/payload-device"; reset_breadcrumbs

# TWO lines. A breadcrumb that can be appended to is a breadcrumb that can be
# shadowed — the same rule the sealed command line follows.
printf '%s\n%s\n' "$medium/dev/nvme0n1p3" "$medium/dev/nvme0n1p1" > "$medium/state/payload-device"
sealed_disk >/dev/null 2>&1 && fail "a two-line payload-device breadcrumb was resolved instead of refused"
reset_breadcrumbs

# TRAVERSAL. `/dev/../etc/passwd` is not a block device, and the grammar must say
# so before anything opens it.
printf '%s\n' "$medium/dev/../state/payload-device" > "$medium/state/payload-device"
sealed_disk >/dev/null 2>&1 && fail "a traversing payload-device path was accepted"
reset_breadcrumbs

# A WHOLE DISK, not a partition. There is no parent to exclude, and excluding
# nothing means the wipe can take the medium it booted from.
printf '%s\n' "$medium/dev/nvme0n1" > "$medium/state/payload-device"
printf '259:0\n' > "$medium/state/payload-device-devno"
sealed_disk >/dev/null 2>&1 && fail "a whole disk was accepted as the sealed payload partition"
reset_breadcrumbs

# THE DEVICE NUMBER DRIFTED. A udev symlink repointed at a second medium after
# switch-root is exactly this: the same path, a different device.
printf '259:9\n' > "$medium/state/payload-device-devno"
drift="$(sealed_disk 2>&1)" && fail "a payload device whose number changed was accepted"
grep -q 'moved under this installer' <<<"$drift" \
  || fail "a drifted payload device was refused for the wrong reason: $drift"
reset_breadcrumbs

# A DEVICE THE KERNEL DOES NOT KNOW.
printf '%s\n' "$medium/dev/nvme9n9p9" > "$medium/state/payload-device"
sealed_disk >/dev/null 2>&1 && fail "a payload device absent from sysfs was accepted"
reset_breadcrumbs

# THE PAYLOAD IS NOT THIS MEDIUM'S. Every structural check above passes and the
# device still carries a header the signature does not seal — which is what a
# second, attacker-supplied medium plugged into the same machine looks like.
mismatch="$(sealed_disk "$(printf 'some-other-medium' | sha256sum | awk '{print $1}')" 2>&1)" \
  && fail "a partition carrying another medium's payload was accepted as this one"
grep -q 'not the medium this kernel booted' <<<"$mismatch" \
  || fail "a foreign payload was refused for the wrong reason: $mismatch"

# THE HEADER IS CORRUPT. dm-verity protects the regions; the header itself is
# protected by this digest comparison and by nothing else.
printf 'garbage' > "$medium/dev/nvme0n1p3"
sealed_disk >/dev/null 2>&1 && fail "a partition with an unreadable payload header was accepted"
write_payload_extent "$medium/dev/nvme0n1p3" "$MEDIUM_HEADER"
[ -n "$(sealed_disk)" ] || fail "the restored medium fixture was refused"

# THE PARENT IS ITSELF A PARTITION. A sysfs shape this reader does not understand
# must not be guessed at: the derived "disk" would be excluded from the wipe
# while the real disk was not.
mkdir -p "$medium/sys/devices/pci/nvme0/nvme0n1/nvme0n1p3/nvme0n1p3x"
printf '259:7\n' > "$medium/sys/devices/pci/nvme0/nvme0n1/nvme0n1p3/nvme0n1p3x/dev"
printf '7\n' > "$medium/sys/devices/pci/nvme0/nvme0n1/nvme0n1p3/nvme0n1p3x/partition"
ln -sf ../../devices/pci/nvme0/nvme0n1/nvme0n1p3/nvme0n1p3x "$medium/sys/class/block/nvme0n1p3x"
write_payload_extent "$medium/dev/nvme0n1p3x" "$MEDIUM_HEADER"
printf '%s\n' "$medium/dev/nvme0n1p3x" > "$medium/state/payload-device"
printf '259:7\n' > "$medium/state/payload-device-devno"
nested="$(sealed_disk 2>&1)" && fail "a partition whose parent is a partition was resolved anyway"
grep -q 'is itself a partition' <<<"$nested" \
  || fail "a nested partition was refused for the wrong reason: $nested"
reset_breadcrumbs

# AND THE OVERRIDES THAT MAKE THIS TESTABLE MUST NOT BE A RUNTIME BYPASS.
env -u NEURAL_ICE_INSTALLER_TRUST_TESTING \
  NEURAL_ICE_SYSFS_ROOT="$medium/sys" NEURAL_ICE_BLOCK_DEVICE_FIXTURE=1 \
  NEURAL_ICE_DEV_PREFIX="$medium/dev" \
  bash "$LIB" sealed-medium-disk "$medium/state" "$MEDIUM_DIGEST" >/dev/null 2>&1 \
  && fail "the sysfs override worked without the test-harness flag"
# ...and the regular-file stand-in for a block device must be equally unreachable:
# without the harness flag the library asks the kernel, and a file is not a device.
env -u NEURAL_ICE_INSTALLER_TRUST_TESTING NEURAL_ICE_BLOCK_DEVICE_FIXTURE=1 \
  bash -c 'source "$1"; installer_trust_is_block_device "$2"' _ "$LIB" "$medium/dev/nvme0n1p3" \
  && fail "a regular file passed as a block device without the test-harness flag"

# --------------------------------------------------------------------------- #
# 6) THE AUTOINSTALLER'S ORDERING. A gate that runs after the root has been read
#    is not a gate; it is a report. And a gate that runs after the disk is gone
#    cannot mean "leave the machine as it was".
# --------------------------------------------------------------------------- #
AUTOINSTALL="$ROOT/ota/neural-ice-autoinstall.sh"
line_of() { grep -n -- "$1" "$AUTOINSTALL" | head -1 | cut -d: -f1; }

trust_gate_line="$(line_of 'SEALED_ANCHOR="$(installer_trust_gate')"
[ -n "$trust_gate_line" ] || fail "the autoinstaller never runs the sealed trust gate"
policy_read_line="$(line_of 'ACCESS_POLICY="$(access_policy_read')"
[ -n "$policy_read_line" ] || fail "the autoinstaller never reads the immutable access policy"
[ "$trust_gate_line" -lt "$policy_read_line" ] \
  || fail "the autoinstaller reads the access policy at line $policy_read_line BEFORE proving the root at line $trust_gate_line"

destructive_line="$(grep -nE '^[[:space:]]*(wipefs|sfdisk|mkfs\.|cryptsetup luksFormat)' \
  "$AUTOINSTALL" | head -1 | cut -d: -f1)"
[ -n "$destructive_line" ] || fail "cannot locate the autoinstaller's first destructive command"
[ "$trust_gate_line" -lt "$destructive_line" ] \
  || fail "the sealed trust gate runs at line $trust_gate_line, AFTER the first disk write at line $destructive_line"

# The medium's sealed profile must be what the installer acts on, and the marker
# must be required to agree rather than merely consulted.
grep -Fq '[[ "$ACCESS_POLICY" == "$SEALED_ACCESS_PROFILE" ]]' "$AUTOINSTALL" \
  || fail "the autoinstaller does not require the /usr marker to agree with the signed UKI"
# …and it must hand the gate the ROOT IT IS STANDING ON, not just a mapper name.
# Without the mount point the gate can only prove that a correct verity device
# exists somewhere, which is the finding this section closes.
grep -Fq 'installer_trust_gate "$VERITY_ROOT_MOUNT" "$INSTALLER_CMDLINE"' "$AUTOINSTALL" \
  || fail "the autoinstaller does not read its markers out of the read-only verity mount"
grep -Fq '"$VERITY_MAPPER" "$VERITY_ROOT_MOUNT")"' "$AUTOINSTALL" \
  || fail "the autoinstaller does not tell the gate which mount point to prove"
# 🔴 AND IT MUST PROVE THE OVERLAY IT IS EXECUTING FROM (review 2026-09-01,
# P0 #1). The verified root is read-only, so `/` is an overlay over it; an
# installer that never checked the overlay's shape would be running code from
# whatever the upper layer happened to be.
grep -Fq 'installer_trust_assert_overlay_root "$VERITY_ROOT_MOUNT" /' "$AUTOINSTALL" \
  || fail "the autoinstaller does not prove its writable runtime is an overlay over the verified root"
# ...and the SEALED PAYLOAD's store must be re-proved after switch-root, or
# `--source-imgref` names bytes only a breadcrumb vouched for.
grep -Fq 'installer_trust_assert_root_verity "$STORE_VERITY_HASH" "$STORE_MAPPER" "$STORE_MOUNT"' "$AUTOINSTALL" \
  || fail "the autoinstaller does not re-prove the sealed image store after switch-root"

echo "INSTALLER_TRUST_TEST_OK"
