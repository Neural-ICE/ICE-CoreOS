#!/bin/sh
# Build the installer's root out of the SEALED PAYLOAD, or fail the boot.
#
# Runs in the pre-mount hook, i.e. before dracut mounts anything as the real
# root, and it does all of the following inside the signed initramfs:
#
#   1. read the two sealed digests off the command line (closed world);
#   2. read the payload header off the `ni-installer-payload` partition and
#      require its SHA-256 to be the one the UKI sealed;
#   3. open BOTH protected extents through dm-verity -- the installer root
#      against the hash in the cmdline, the container store against the hash in
#      the now-authenticated header;
#   4. mount both read-only, and give the system a writable runtime: a BOUNDED
#      tmpfs as the upper layer of an overlay over the verified root.
#
# WHY STEP 4 EXISTS AT ALL (review 2026-09-01, P0 #1). A dm-verity squashfs
# cannot be written to, and the previous revision mounted it straight as `/`.
# The installer writes /etc drop-ins, /var scratch and podman state, so that
# medium could verify perfectly and then fail to install -- the sealed boot path
# was unreachable in practice. The upper layer is a tmpfs created HERE, empty, on
# every boot: nothing an attacker wrote to the medium can be in it, and nothing
# written during an install survives a power cycle.
#
# CLOSED-WORLD CMDLINE PARSING, for the same reason installer-trust.sh does it:
# with Secure Boot disabled systemd-stub CONCATENATES an externally supplied
# command line onto the sealed one, so a second `neuralice.rootverity=` is
# exactly how an attacker would shadow the anchor. Two occurrences is a refusal,
# never a choice of winner.

# shellcheck source=/dev/null # dracut's own library, present only in the initramfs
type getarg >/dev/null 2>&1 && . /lib/dracut-lib.sh 2>/dev/null
# The ONE payload parser this tree has. See module-setup.sh.
# shellcheck source=image/lib/installer-payload.sh
. /lib/neural-ice-installer-payload.sh

NI_ROOT_MAPPER=neuralice-installer-root
NI_STORE_MAPPER=neuralice-installer-store
NI_STATE=/run/neural-ice-installer
NI_VERITY_ROOT="$NI_STATE/verity-root"
NI_STORE_MOUNT="$NI_STATE/store"
NI_RW="$NI_STATE/rw"
# The writable runtime is BOUNDED, and the bound is stated here rather than left
# to a kernel default: an unbounded tmpfs upper layer is a way to exhaust the
# machine's memory from a file the installer copies. 50% of RAM is the tmpfs
# default made explicit, and it is ample -- the install writes drop-ins and
# podman metadata, never the ~10 GiB image (that is read from the store extent
# in place, as a read-only additional image store).
NI_RW_OPTIONS="size=50%,nr_inodes=1m,mode=0755,nodev,nosuid"
NI_NEWROOT="${NEWROOT:-/sysroot}"

# THE COMMAND LINE THIS HOOK READS. `/proc/cmdline` in production, always; the
# override exists so image/test-installer-media.sh can drive every refusal below
# against a fixture instead of asserting that a string appears in this file. It
# is refused in a privileged process, which is every process in an initramfs --
# the same guard shape image/lib/installer-trust.sh uses for its tool overrides.
NI_CMDLINE_FILE=/proc/cmdline
if [ -n "${NEURAL_ICE_INITRAMFS_TEST_CMDLINE:-}" ]; then
    if [ "${NEURAL_ICE_INITRAMFS_TESTING:-}" = 1 ] && [ "$(id -u)" -ne 0 ]; then
        NI_CMDLINE_FILE="$NEURAL_ICE_INITRAMFS_TEST_CMDLINE"
    else
        printf 'neural-ice-installer-verity: REFUSED: a command-line override is forbidden in a privileged process\n' >&2
        exit 1
    fi
fi


ni_die() {
    printf 'neural-ice-installer-verity: REFUSED: %s\n' "$*" >&2
    # `die` is dracut's own fatal path: it drops to the emergency shell or
    # reboots according to policy. Either way the install never runs.
    if type die >/dev/null 2>&1; then
        die "neural-ice-installer-verity: $*"
    fi
    exit 1
}

# Exactly one occurrence of a key, or a refusal. awk's default field splitting IS
# kernel-command-line splitting.
ni_single_karg() { # $1=key
    _ni_count=$(awk -v k="$1=" 'BEGIN{n=0}{for (i=1;i<=NF;i++) if (index($i,k)==1) n++} END{print n+0}' "$NI_CMDLINE_FILE")
    if [ "$_ni_count" -ne 1 ]; then
        ni_die "the command line carries $_ni_count occurrences of $1; the sealed anchor may be shadowed"
    fi
    awk -v k="$1=" '{for (i=1;i<=NF;i++) if (index($i,k)==1) print substr($i, length(k)+1)}' "$NI_CMDLINE_FILE"
}

NI_SCHEMA=$(ni_single_karg neuralice.trust) || exit 1
[ "$NI_SCHEMA" = "neural-ice-installer-trust-v1" ] \
    || ni_die "the command line carries no neural-ice-installer-trust-v1 anchor"

NI_ROOT_HASH=$(ni_single_karg neuralice.rootverity) || exit 1
payload_is_sha256_hex "$NI_ROOT_HASH" || ni_die "the sealed dm-verity root hash is malformed"
NI_PAYLOAD_DIGEST=$(ni_single_karg neuralice.payload) || exit 1
payload_is_sha256_hex "$NI_PAYLOAD_DIGEST" || ni_die "the sealed payload digest is malformed"

# --------------------------------------------------------------------------- #
# The payload extent. It is found by a GPT partition NAME the producer sets, not
# by a filesystem label: a filesystem label is inside attacker-writable data, and
# the partition name at least travels in the (equally writable, but distinct)
# GPT. NEITHER IS A TRUST INPUT -- the sealed header digest is. This lookup only
# has to find a candidate; a wrong candidate simply fails to verify.
# --------------------------------------------------------------------------- #
NI_PAYLOAD_DEV="/dev/disk/by-partlabel/$NEURAL_ICE_PAYLOAD_PARTLABEL"
if [ ! -b "$NI_PAYLOAD_DEV" ]; then
    udevadm settle --timeout=30 >/dev/null 2>&1 || true
fi
[ -b "$NI_PAYLOAD_DEV" ] || ni_die "no installer payload partition named $NEURAL_ICE_PAYLOAD_PARTLABEL"

NI_HEADER="$(payload_header_read "$NI_PAYLOAD_DEV" 0)" \
    || ni_die "the installer payload carries no readable $NEURAL_ICE_PAYLOAD_SCHEMA header"
NI_HEADER_DIGEST="$(payload_header_digest "$NI_HEADER")"
[ "$NI_HEADER_DIGEST" = "$NI_PAYLOAD_DIGEST" ] \
    || ni_die "the payload header on this medium hashes to $NI_HEADER_DIGEST, not the $NI_PAYLOAD_DIGEST the signed UKI seals"

# From here the header is AUTHENTICATED, so its offsets and hashes are evidence.
NI_STORE_HASH="$(payload_header_field "$NI_HEADER" store_verity_hash)" \
    || ni_die "the authenticated payload header names no store verity hash"

# --------------------------------------------------------------------------- #
# Attach every region read-only. `losetup -o/--sizelimit` reads a region of a
# partition directly: no filesystem, no driver, and nothing on the medium is
# mounted before it has been verified.
# --------------------------------------------------------------------------- #
ni_attach_region() { # $1=region name -> prints the loop device
    _ni_off="$(payload_region_field "$NI_HEADER" "$1" offset)" || ni_die "the payload header has no offset for '$1'"
    _ni_size="$(payload_region_field "$NI_HEADER" "$1" size)" || ni_die "the payload header has no size for '$1'"
    losetup --find --show --read-only --offset "$_ni_off" --sizelimit "$_ni_size" \
        "$NI_PAYLOAD_DEV" || ni_die "cannot attach the '$1' region of the installer payload"
}
NI_ROOT_LOOP="$(ni_attach_region root-image)" || exit 1
NI_ROOT_HASH_LOOP="$(ni_attach_region root-hash)" || exit 1
NI_STORE_LOOP="$(ni_attach_region store-image)" || exit 1
NI_STORE_HASH_LOOP="$(ni_attach_region store-hash)" || exit 1

# --panic-on-corruption, not --ignore-corruption. A medium that boots past a
# modified block is a medium whose verification is decorative, and the runtime
# gate refuses the ignore flags anyway -- so activating with them would only move
# the refusal later, after the operator has been shown an installer prompt.
veritysetup open "$NI_ROOT_LOOP" "$NI_ROOT_MAPPER" "$NI_ROOT_HASH_LOOP" "$NI_ROOT_HASH" \
    --panic-on-corruption \
    || ni_die "the installer root does not verify against the hash the signed UKI seals"
[ -b "/dev/mapper/$NI_ROOT_MAPPER" ] || ni_die "$NI_ROOT_MAPPER did not appear after veritysetup open"

# THE STORE IS PROTECTED THE SAME WAY, and this is the whole of P0 #1's second
# half: the ~10 GiB the installer writes onto a customer's disk are now behind a
# dm-verity target whose root hash comes from a header the signature covers. A
# modified block is an I/O error at read time -- not a 10 GiB up-front hash, and
# no window between "verified" and "used".
veritysetup open "$NI_STORE_LOOP" "$NI_STORE_MAPPER" "$NI_STORE_HASH_LOOP" "$NI_STORE_HASH" \
    --panic-on-corruption \
    || ni_die "the installer image store does not verify against the hash the sealed payload header carries"
[ -b "/dev/mapper/$NI_STORE_MAPPER" ] || ni_die "$NI_STORE_MAPPER did not appear after veritysetup open"

# --------------------------------------------------------------------------- #
# Mount both verified extents read-only, then build the writable runtime.
# --------------------------------------------------------------------------- #
mkdir -p "$NI_VERITY_ROOT" "$NI_STORE_MOUNT" "$NI_RW" || ni_die "cannot create $NI_STATE"
mount -t squashfs -o ro "/dev/mapper/$NI_ROOT_MAPPER" "$NI_VERITY_ROOT" \
    || ni_die "cannot mount the verified installer root"
mount -t squashfs -o ro,nodev,nosuid "/dev/mapper/$NI_STORE_MAPPER" "$NI_STORE_MOUNT" \
    || ni_die "cannot mount the verified installer image store"

mount -t tmpfs -o "$NI_RW_OPTIONS" neural-ice-installer-rw "$NI_RW" \
    || ni_die "cannot create the bounded writable runtime"
mkdir -p "$NI_RW/upper" "$NI_RW/work" || ni_die "cannot lay out the writable runtime"
mkdir -p "$NI_NEWROOT" || ni_die "cannot create $NI_NEWROOT"
mount -t overlay neural-ice-installer-root \
    -o "lowerdir=$NI_VERITY_ROOT,upperdir=$NI_RW/upper,workdir=$NI_RW/work" \
    "$NI_NEWROOT" \
    || ni_die "cannot assemble the installer root overlay"

# ASSERT THE SHAPE THAT WAS JUST BUILT, rather than the exit status of the
# command that built it. The installer re-proves this independently after
# switch-root (installer_trust_assert_overlay_root); this is the same statement
# made where it can still stop the boot.
awk -v t="$NI_NEWROOT" '$5 == t { last = $0 } END { exit last !~ / - overlay / }' \
    /proc/self/mountinfo \
    || ni_die "$NI_NEWROOT is not served by the overlay this hook just mounted"

# --------------------------------------------------------------------------- #
# THE PAYLOAD DEVICE, RESOLVED (review 2026-09-01, P0 #1).
#
# 🔴 WHY THE RESOLVED NODE AND NOT THE by-partlabel PATH. After switch-root the
# installer has to know WHICH DISK it booted from, so it can exclude it from the
# wipe. It used to ask `findmnt /` -- which, since this hook mounts an overlay
# there, answers `neural-ice-installer-root`: a name, not a block device. The
# installer therefore died identifying its own medium, before any trust check.
#
# The answer it needs is here, and it must be recorded in a form that cannot
# drift: `/dev/disk/by-partlabel/…` is a udev symlink that can be repointed at a
# second medium carrying the same partition name, so recording the symlink would
# hand the installer a name it re-resolves later, possibly to another disk. The
# RESOLVED node is recorded, together with the device number sysfs reports for
# it, and the installer requires the two to still agree.
#
# NONE OF IT IS A TRUST INPUT. The installer re-reads the payload header off
# whatever device these breadcrumbs name and requires its digest to be the one
# the signed UKI seals; a breadcrumb pointing anywhere else simply fails that.
# --------------------------------------------------------------------------- #
NI_PAYLOAD_NODE="$(readlink -f "$NI_PAYLOAD_DEV" 2>/dev/null || printf '%s' "$NI_PAYLOAD_DEV")"
[ -b "$NI_PAYLOAD_NODE" ] || ni_die "the installer payload partition does not resolve to a block device"
NI_PAYLOAD_KNAME="${NI_PAYLOAD_NODE##*/}"
[ -f "/sys/class/block/$NI_PAYLOAD_KNAME/dev" ] \
    || ni_die "the kernel knows no block device named $NI_PAYLOAD_KNAME"
# A PARTITION, not a whole disk: the installer derives the disk to exclude from
# this node's parent, and a whole-disk payload would leave it nothing to derive.
[ -f "/sys/class/block/$NI_PAYLOAD_KNAME/partition" ] \
    || ni_die "$NI_PAYLOAD_KNAME is not a partition; this medium's layout is not the one the sealed payload describes"
NI_PAYLOAD_DEVNO="$(cat "/sys/class/block/$NI_PAYLOAD_KNAME/dev")"

# Breadcrumbs the installer reads instead of re-discovering the medium. None of
# them is a trust input: every one is re-proved after switch-root against the
# kernel's own view of the device-mapper, sysfs and mount tables.
printf '%s\n' "$NI_PAYLOAD_NODE" > "$NI_STATE/payload-device"
printf '%s\n' "$NI_PAYLOAD_DEVNO" > "$NI_STATE/payload-device-devno"
printf '%s\n' "$NI_ROOT_HASH" > "$NI_STATE/root-verity-hash"
printf '%s\n' "$NI_STORE_HASH" > "$NI_STATE/store-verity-hash"
printf '%s\n' "$NI_HEADER_DIGEST" > "$NI_STATE/payload-digest"
printf '%s\n' "$NI_HEADER" > "$NI_STATE/payload-header"

printf 'neural-ice-installer-verity: %s and %s opened and verified; writable runtime on tmpfs\n' \
    "$NI_ROOT_MAPPER" "$NI_STORE_MAPPER" >&2
