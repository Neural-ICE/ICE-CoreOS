#!/usr/bin/env bash
#
# The INSTALLER TRUST ANCHOR: what the Secure Boot signature actually says.
#
# WHY THIS FILE EXISTS. ADR-0014 moved the remote-access trust anchor into
# /usr/lib/neural-ice/access-policy, "covered by whatever signs the image". That
# sentence is true of a deployed, OTA-managed appliance. It is NOT true of the
# removable installation medium, and the installer is where the policy is first
# read (DESIGN-NOTE-0001, Finding 1). Secure Boot authenticates EFI binaries and
# the kernel; it says nothing about the root filesystem those binaries mount. An
# attacker holding a correctly signed installer USB could rewrite
# /usr/lib/neural-ice/access-policy from customer-locked to lab-managed, or
# rewrite the autoinstaller so the gate is never consulted, and both survived
# Secure Boot untouched.
#
# WHAT REPLACES IT (DESIGN-NOTE-0001 Design A). The installer root is a
# dm-verity image. Its root hash, together with the access profile, the hardware
# target, the Secure Boot trust-policy id and the identity of the key that
# authorises releases, is written into the .cmdline section of a UKI -- one PE
# binary carrying kernel + initramfs + cmdline, signed as a whole. Editing any
# one of those words invalidates the PE signature and the firmware refuses to
# boot. The initramfs, being INSIDE that signed binary, sets dm-verity up before
# switch-root, so a byte changed anywhere in the installer /usr fails
# verification and the install never starts.
#
#   sealed field                 what it pins
#   ---------------------------- --------------------------------------------
#   neuralice.rootverity         the dm-verity root hash of the installer root
#   neuralice.payload            the SHA-256 of the sealed payload header, which
#                                names and hashes every extent on the medium --
#                                root image, root hash tree, container store
#                                image and its hash tree (installer-payload.sh)
#   neuralice.access_profile     the profile the medium is allowed to act on
#   neuralice.hardware_target    the hardware this medium may install onto
#   neuralice.trust_policy_id    which Secure Boot trust policy signed this
#   neuralice.relauth_keyid      which key may authorise an installable release
#   neuralice.relauth_schema     which closed release-authorization contract
#                                that key is allowed to sign for this medium
#
# THE /usr MARKER BECOMES A CROSS-CHECK, NOT THE AUTHORITY. The installer reads
# the profile from the signed cmdline and ADDITIONALLY requires the file in the
# now-verity-protected /usr to state the same value. Redundancy is cheap;
# ambiguity about which one wins is not.
#
# PROVING THE ROOT, NOT MERELY THAT A VERITY DEVICE EXISTS. An earlier version
# of this file asked `veritysetup status` about a NAMED mapper and stopped there.
# A correct verity target can coexist with a completely different, mutable root:
# the mapper answered, the hash matched, and the policy files were then read out
# of whatever `/` actually was. So the gate now proves a TOPOLOGY --
#
#   the dm device that serves the mounted root  ==  the mapper we verified
#
# -- by comparing the mount's backing device NUMBER (findmnt MAJ:MIN) with the
# mapper's own (dmsetup info), and by requiring the mapper's whole dm table to be
# a single `verity` target carrying the sealed root hash. Nothing may be stacked
# on top of it, and no other device may be mounted at the root we are about to
# read policy from.
#
# CLOSED-WORLD PARSING IS LOAD-BEARING. systemd-stub honours the embedded
# .cmdline and ignores an externally supplied one only while Secure Boot is
# enforcing. With Secure Boot off -- a state an attacker with physical access
# can reach -- the two are concatenated. So every reader below refuses a SECOND
# occurrence of any sealed key rather than taking the first or the last: an
# anchor that can be shadowed by appending to it is not an anchor. This is the
# same lesson as the `neuralice.sshkey=` duplicate count in the autoinstaller.

if [[ -z "${NEURAL_ICE_INSTALLER_TRUST_LIB_LOADED:-}" ]]; then
  NEURAL_ICE_INSTALLER_TRUST_LIB_LOADED=1

  readonly NEURAL_ICE_INSTALLER_TRUST_SCHEMA="neural-ice-installer-trust-v1"
  readonly NEURAL_ICE_INSTALLER_RELAUTH_SCHEMA="neural-ice-installer-release-authorization-v2"
  # The sealed keys, in the canonical order the renderer emits and the tests
  # assert. Sorted so the rendered cmdline is a deterministic function of its
  # inputs alone -- a build output that differs run to run cannot be reviewed.
  readonly NEURAL_ICE_INSTALLER_TRUST_KEYS=(
    neuralice.trust
    neuralice.access_profile
    neuralice.hardware_target
    neuralice.payload
    neuralice.relauth_keyid
    neuralice.relauth_schema
    neuralice.rootverity
    neuralice.trust_policy_id
  )
  # Paths RELATIVE to a root prefix, so the same code serves the running system
  # (prefix "") and a test root, with no second code path for the tests.
  readonly NEURAL_ICE_HARDWARE_TARGET_RELPATH="usr/lib/neural-ice/hardware-target"
  readonly NEURAL_ICE_TRUST_POLICY_ID_RELPATH="usr/lib/neural-ice/signed-boot-trust-policy-id"
  readonly NEURAL_ICE_RELAUTH_KEY_RELPATH="usr/lib/neural-ice/keys/release-authorization.pub"
  # A kernel command line is bounded by the kernel itself; anything longer than
  # this is a corrupted or padded section, not a cmdline we should parse.
  readonly NEURAL_ICE_INSTALLER_TRUST_MAX_CMDLINE_BYTES=4096
fi

# --------------------------------------------------------------------------- #
# Field syntax. Each sealed value is constrained to the narrowest character set
# that can express it, so a value can never carry a space (which would smuggle a
# second karg), a shell metacharacter, or a path traversal.
# --------------------------------------------------------------------------- #
installer_trust_value_is_valid() { # $1=key $2=value
  local key=$1 value=$2
  case "$key" in
    neuralice.trust)
      [[ "$value" == "$NEURAL_ICE_INSTALLER_TRUST_SCHEMA" ]] ;;
    neuralice.access_profile)
      # Delegated to the single source of truth. A profile this installer does
      # not understand must not be sealed into a medium at all.
      access_policy_is_known "$value" ;;
    neuralice.hardware_target)
      # Same shape ni-ota-verify's immutable_hardware_target() enforces on the
      # appliance: lowercase alphanumerics, '-' and '_', alphanumeric at both
      # ends, at most 64 bytes. Two readers of the same identity must not
      # disagree about what a valid identity looks like.
      [[ "$value" =~ ^[a-z0-9]([a-z0-9_-]{0,62}[a-z0-9])?$ ]] ;;
    neuralice.payload | neuralice.relauth_keyid | neuralice.rootverity)
      [[ "$value" =~ ^[0-9a-f]{64}$ ]] ;;
    neuralice.relauth_schema)
      [[ "$value" == "$NEURAL_ICE_INSTALLER_RELAUTH_SCHEMA" ]] ;;
    neuralice.trust_policy_id)
      [[ "$value" =~ ^neural-ice-secureboot-[a-z0-9-]{1,32}$ ]] ;;
    *)
      return 1 ;;
  esac
}

# --------------------------------------------------------------------------- #
# Render the sealed cmdline. This is the BUILD side: it produces the exact bytes
# that go into the UKI's .cmdline section. Deterministic by construction --
# fixed key order, single spaces, no trailing newline, no build-host state.
#
#   $1 access profile   $2 hardware target   $3 release-authorization key id
#   $4 dm-verity root hash   $5 sealed payload header digest
#   $6 signed-boot trust policy id
#   $7.. extra boot kargs, appended verbatim AFTER the sealed fields
# --------------------------------------------------------------------------- #
installer_trust_render_cmdline() {
  if (( $# < 6 )); then
    echo "installer_trust_render_cmdline requires profile, target, key id, root hash, payload digest and trust policy id" >&2
    return 2
  fi
  local profile=$1 target=$2 keyid=$3 roothash=$4 payload=$5 policy_id=$6
  shift 6

  local -a pairs=(
    "neuralice.trust=$NEURAL_ICE_INSTALLER_TRUST_SCHEMA"
    "neuralice.access_profile=$profile"
    "neuralice.hardware_target=$target"
    "neuralice.payload=$payload"
    "neuralice.relauth_keyid=$keyid"
    "neuralice.relauth_schema=$NEURAL_ICE_INSTALLER_RELAUTH_SCHEMA"
    "neuralice.rootverity=$roothash"
    "neuralice.trust_policy_id=$policy_id"
  )
  local pair key value
  for pair in "${pairs[@]}"; do
    key=${pair%%=*}; value=${pair#*=}
    installer_trust_value_is_valid "$key" "$value" || {
      echo "refusing to seal an invalid value into the UKI cmdline: $key='$value'" >&2
      return 1
    }
  done

  # Extra kargs are the ordinary boot options (console=, enforcing=0, …). They
  # are NOT trusted input: one of them must never be able to introduce a second
  # occurrence of a sealed key, because the reader would then refuse every boot
  # -- or, worse, a future reader that took the first match would be steered.
  local karg
  for karg in "$@"; do
    [[ "$karg" =~ ^[A-Za-z0-9._:=,/@+-]+$ ]] || {
      echo "refusing an unrepresentable extra karg: '$karg'" >&2
      return 1
    }
    case "${karg%%=*}" in
      neuralice.trust | neuralice.access_profile | neuralice.hardware_target \
        | neuralice.payload | neuralice.relauth_keyid | neuralice.relauth_schema \
        | neuralice.rootverity \
        | neuralice.trust_policy_id)
        echo "an extra karg may not restate a sealed field: '$karg'" >&2
        return 1
        ;;
    esac
    pairs+=("$karg")
  done

  local IFS=' '
  printf '%s' "${pairs[*]}"
}

# --------------------------------------------------------------------------- #
# Read exactly one sealed field out of a cmdline. Refuses zero occurrences and
# refuses two or more. awk's default field splitting IS kernel-command-line
# splitting, and unlike a greedy `sed .*` it can SEE a second occurrence instead
# of silently keeping the last one.
#   $1 field key   $2 cmdline string
# --------------------------------------------------------------------------- #
installer_trust_field() {
  if (( $# != 2 )); then
    echo "installer_trust_field requires a key and a cmdline" >&2
    return 2
  fi
  local key=$1 cmdline=$2

  (( ${#cmdline} <= NEURAL_ICE_INSTALLER_TRUST_MAX_CMDLINE_BYTES )) || {
    echo "the installer command line is implausibly long (${#cmdline} bytes)" >&2
    return 1
  }
  local count
  count="$(awk -v k="$key=" 'BEGIN{n=0} {for (i = 1; i <= NF; i++) if (index($i, k) == 1) n++} END{print n + 0}' <<<"$cmdline")"
  case "$count" in
    1) ;;
    0)
      echo "the installer command line carries no $key" >&2
      return 1
      ;;
    *)
      # THE reason this function exists. With Secure Boot disabled, systemd-stub
      # concatenates an externally supplied cmdline onto the sealed one, so a
      # second occurrence is exactly how an attacker would try to shadow the
      # anchor. Refuse; never pick a winner.
      echo "the installer command line carries $count occurrences of $key; the sealed anchor may be shadowed" >&2
      return 1
      ;;
  esac
  local value
  value="$(awk -v k="$key=" '{for (i = 1; i <= NF; i++) if (index($i, k) == 1) {print substr($i, length(k) + 1)}}' <<<"$cmdline")"
  installer_trust_value_is_valid "$key" "$value" || {
    echo "the sealed field $key carries an unacceptable value: '$value'" >&2
    return 1
  }
  printf '%s\n' "$value"
}

# Read every sealed field, in canonical order, as `key=value` lines. One
# unreadable field fails the whole read: a partially sealed medium is not a
# medium this installer knows how to reason about.
installer_trust_read_sealed() {
  if (( $# != 1 )); then
    echo "installer_trust_read_sealed requires a cmdline" >&2
    return 2
  fi
  local cmdline=$1 key value
  for key in "${NEURAL_ICE_INSTALLER_TRUST_KEYS[@]}"; do
    value="$(installer_trust_field "$key" "$cmdline")" || return 1
    printf '%s=%s\n' "$key" "$value"
  done
}

# --------------------------------------------------------------------------- #
# dm-verity. Three tools, three questions, all injectable so the suite can drive
# every refusal without a device-mapper target -- and every injection refused in
# a privileged process so it can never become a runtime bypass (same guard shape
# as the device-root helper's test tools).
#
#   veritysetup status  what the target IS      (active, sealed hash, no ignore)
#   dmsetup             what the target's TABLE is  (one verity target, nothing stacked)
#   findmnt             what the mounted root RUNS ON   (the same device number)
# --------------------------------------------------------------------------- #
installer_trust_tool_override_allowed() {
  [[ "${NEURAL_ICE_INSTALLER_TRUST_TESTING:-}" == 1 && "${EUID:-$(id -u)}" -ne 0 ]]
}

installer_trust_verity_status() { # $1=mapper name
  local name=$1
  if [[ -n "${NEURAL_ICE_VERITY_STATUS_CMD:-}" ]]; then
    installer_trust_tool_override_allowed || {
      echo "a verity status override is forbidden in a privileged process" >&2
      return 1
    }
    "$NEURAL_ICE_VERITY_STATUS_CMD" "$name"
    return
  fi
  veritysetup status "$name"
}

installer_trust_dmsetup() { # $@=dmsetup arguments
  if [[ -n "${NEURAL_ICE_DMSETUP_CMD:-}" ]]; then
    installer_trust_tool_override_allowed || {
      echo "a dmsetup override is forbidden in a privileged process" >&2
      return 1
    }
    "$NEURAL_ICE_DMSETUP_CMD" "$@"
    return
  fi
  dmsetup "$@"
}

# The kernel's own view of what is mounted where, and OVER WHAT. `findmnt` can
# answer "which device serves this mount"; only mountinfo carries an overlay's
# lowerdir/upperdir, and that is the pair the writable-runtime proof is about.
installer_trust_mountinfo() {
  if [[ -n "${NEURAL_ICE_MOUNTINFO_FILE:-}" ]]; then
    installer_trust_tool_override_allowed || {
      echo "a mountinfo override is forbidden in a privileged process" >&2
      return 1
    }
    cat -- "$NEURAL_ICE_MOUNTINFO_FILE"
    return
  fi
  cat /proc/self/mountinfo
}

installer_trust_findmnt() { # $@=findmnt arguments
  if [[ -n "${NEURAL_ICE_FINDMNT_CMD:-}" ]]; then
    installer_trust_tool_override_allowed || {
      echo "a findmnt override is forbidden in a privileged process" >&2
      return 1
    }
    "$NEURAL_ICE_FINDMNT_CMD" "$@"
    return
  fi
  findmnt "$@"
}

# The mapper's dm TABLE, as the kernel reports it. Returns the single table line
# and refuses anything that is not exactly one `verity` target: a mapper whose
# table has two segments, or a linear segment sitting over a verity one, is a
# device whose contents are not wholly verified even though `veritysetup status`
# is perfectly happy to describe it.
#   $1 mapper name   $2 expected root hash
installer_trust_verity_table_root_hash() {
  local name=$1 expected=$2 table lines type roothash
  table="$(installer_trust_dmsetup table "$name" 2>/dev/null)" || {
    echo "the device-mapper table of '$name' cannot be read" >&2
    return 1
  }
  lines="$(grep -c . <<<"$table")"
  [[ "$lines" == 1 ]] || {
    echo "the device-mapper table of '$name' has $lines segments; a partially verified root is not a verified root" >&2
    return 1
  }
  # `<logical_start> <num_sectors> verity <version> <data_dev> <hash_dev>
  #  <data_block_size> <hash_block_size> <num_data_blocks> <hash_start_block>
  #  <algorithm> <digest> <salt> ...`  -- the digest is field 12.
  type="$(awk '{print tolower($3)}' <<<"$table")"
  [[ "$type" == verity ]] || {
    echo "the device-mapper target serving '$name' is '${type:-unknown}', not verity" >&2
    return 1
  }
  roothash="$(awk '{print tolower($12)}' <<<"$table")"
  [[ "$roothash" == "$expected" ]] || {
    echo "the dm-verity table of '$name' carries root hash '${roothash:-none}', not the sealed one ($expected)" >&2
    return 1
  }
  printf '%s\n' "$roothash"
}

# The device NUMBER of a mapper, as `major:minor`. Comparing numbers rather than
# path strings is what makes the topology proof independent of how the mount was
# spelled: a bind mount, a symlinked /dev/mapper entry or a renamed node cannot
# make two different devices look like one.
installer_trust_mapper_devno() { # $1=mapper name
  local name=$1 info devno
  info="$(installer_trust_dmsetup info -c --noheadings -o major,minor -- "$name" 2>/dev/null)" || {
    echo "device-mapper knows no target named '$name'" >&2
    return 1
  }
  devno="$(tr -d '[:space:]' <<<"$info")"
  [[ "$devno" =~ ^[0-9]{1,7}:[0-9]{1,7}$ ]] || {
    echo "device-mapper reports no usable device number for '$name'" >&2
    return 1
  }
  printf '%s\n' "$devno"
}

# The device NUMBER the given mount point actually runs on.
installer_trust_mount_devno() { # $1=mount target
  local target=$1 out lines devno
  out="$(installer_trust_findmnt --noheadings --nofsroot --output MAJ:MIN --mountpoint "$target" 2>/dev/null)" || {
    echo "'$target' is not a mount point; there is no root here to verify" >&2
    return 1
  }
  lines="$(grep -c . <<<"$out")"
  [[ "$lines" == 1 ]] || {
    echo "'$target' resolves to $lines mounts; refusing to guess which one carries the installer root" >&2
    return 1
  }
  devno="$(tr -d '[:space:]' <<<"$out")"
  [[ "$devno" =~ ^[0-9]{1,7}:[0-9]{1,7}$ ]] || {
    echo "the mount at '$target' reports no usable device number" >&2
    return 1
  }
  printf '%s\n' "$devno"
}

# Assert that the installer root really is the dm-verity target the UKI sealed.
#   $1 expected root hash (from the signed cmdline)
#   $2 mapper name    (default: the installer's own verity root)
#   $3 mount target   (default: "/" -- the root the caller is standing on)
#
# FIVE independent properties, because any subset is bypassable:
#   - the target is ACTIVE (an initramfs that failed open leaves exactly the
#     opposite, and it proves nothing);
#   - its root hash EQUALS the sealed one (a correct verity target over the
#     WRONG tree is the attack this whole note is about);
#   - corruption is not ignored. dm-verity can be asked to log corruption and
#     carry on; a medium that boots past a modified block is a medium whose
#     verification is decorative;
#   - its dm TABLE is one verity target with that same hash, so nothing is
#     stacked over the verified extent;
#   - and the MOUNTED ROOT RUNS ON THAT EXACT DEVICE. Without this last one a
#     perfectly correct verity mapper can sit idle beside a mutable root, and
#     every policy file read afterwards comes from the mutable one.
installer_trust_assert_root_verity() {
  if (( $# < 1 || $# > 4 )); then
    echo "installer_trust_assert_root_verity requires the sealed root hash" >&2
    return 2
  fi
  local expected=$1 name=${2:-neuralice-installer-root} mount_target=${3:-/} status
  # The MEDIUM carries two verity-protected extents now (the installer root and
  # the container store it installs from), and both get this same five-property
  # proof. The label only changes the words an operator reads.
  local label=${4:-installer root}

  [[ "$expected" =~ ^[0-9a-f]{64}$ ]] || {
    echo "the sealed dm-verity root hash is malformed" >&2
    return 1
  }
  status="$(installer_trust_verity_status "$name" 2>/dev/null)" || {
    echo "the $label is not a dm-verity target ('$name' is unknown); refusing to read anything from it" >&2
    return 1
  }
  grep -Eqi '^[[:space:]]*status:[[:space:]]*(active|verified)[[:space:]]*$' <<<"$status" || {
    echo "the $label dm-verity target is not active" >&2
    return 1
  }
  local actual
  actual="$(awk 'tolower($1) == "root" && tolower($2) == "hash:" {print tolower($3); found = 1} END{exit !found}' <<<"$status")" || {
    echo "the $label dm-verity target reports no root hash" >&2
    return 1
  }
  [[ "$actual" == "$expected" ]] || {
    echo "the $label dm-verity hash ($actual) is not the sealed one ($expected)" >&2
    return 1
  }
  # `veritysetup status` prints the flags it was activated with. Either of these
  # turns a refusal into a log line.
  if grep -Eqi 'ignore_corruption|ignore_zero_blocks' <<<"$status"; then
    echo "the $label dm-verity target was activated with corruption ignored" >&2
    return 1
  fi

  installer_trust_verity_table_root_hash "$name" "$expected" >/dev/null || return 1

  local mapper_devno mount_devno
  mapper_devno="$(installer_trust_mapper_devno "$name")" || return 1
  mount_devno="$(installer_trust_mount_devno "$mount_target")" || return 1
  [[ "$mapper_devno" == "$mount_devno" ]] || {
    echo "the $label mounted at '$mount_target' runs on device $mount_devno, not on the verified dm-verity target '$name' ($mapper_devno); a verified mapper that is not the mount proves nothing" >&2
    return 1
  }
  printf '%s\n' "$actual"
}

# --------------------------------------------------------------------------- #
# THE WRITABLE RUNTIME, PROVED (review 2026-09-01, P0 #1).
#
# A dm-verity squashfs cannot be written to, and an installer that cannot write
# /etc or /var cannot install: it has drop-ins to place, a container store to
# register and scratch state to keep. The initramfs therefore mounts the verified
# root READ-ONLY at a fixed path and gives the system an overlay over it whose
# upper layer is a BOUNDED tmpfs -- created empty, inside the signed initramfs,
# on every boot.
#
# THAT ARRANGEMENT IS ONLY SAFE IF ITS SHAPE IS PROVED. An overlay whose lower
# layer is something other than the verified mount, or whose upper layer is a
# DISK-BACKED directory an attacker pre-populated before the machine ever booted,
# would hand the installer files nothing authenticated. So this asserts four
# things about `/`:
#
#   * it is an `overlay`, not a filesystem pretending to be one;
#   * it has EXACTLY ONE lower layer (a `:`-separated list is a refusal, not a
#     choice of which layer wins);
#   * that lower layer is the verity mount the caller just proved;
#   * and its upper layer sits on a `tmpfs`, which is what makes "empty at every
#     boot" a property of the kernel rather than of a comment.
#
# The POLICY is never read from here regardless -- installer_trust_gate reads it
# out of the read-only verity mount. This proof exists so that the CODE the
# installer executes is, itself, the code the signature covers.
#
#   $1 the verity mount path that must be the only lower layer
#   $2 the overlay mount point (optional, default "/")
# --------------------------------------------------------------------------- #
installer_trust_assert_overlay_root() {
  if (( $# < 1 || $# > 2 )); then
    echo "installer_trust_assert_overlay_root requires the verified lower mount" >&2
    return 2
  fi
  local lower=${1%/} target=${2:-/} info line fstype superopts lowerdir upperdir
  lower=${lower:-/}
  info="$(installer_trust_mountinfo)" || {
    echo "the kernel's mount table cannot be read; the writable runtime cannot be proved" >&2
    return 1
  }
  # mountinfo: id parent maj:min root MOUNTPOINT options [tags…] - FSTYPE source SUPEROPTS
  # The LAST entry for a mount point is the one currently visible there, which is
  # exactly the one an attacker would try to shadow with a later mount.
  line="$(awk -v t="$target" '$5 == t { last = $0 } END { if (last == "") exit 1; print last }' <<<"$info")" || {
    echo "'$target' is not a mount point; there is no writable runtime to prove" >&2
    return 1
  }
  fstype="$(awk -F' - ' '{print $2}' <<<"$line" | awk '{print $1}')"
  [[ "$fstype" == overlay ]] || {
    echo "'$target' is served by '${fstype:-unknown}', not by an overlay over the verified installer root" >&2
    return 1
  }
  superopts="$(awk -F' - ' '{print $2}' <<<"$line" | awk '{print $3}')"
  lowerdir="$(tr ',' '\n' <<<"$superopts" | sed -n 's/^lowerdir=//p')"
  [[ "$(grep -c . <<<"$lowerdir")" == 1 ]] || {
    echo "the overlay at '$target' declares no single lower layer" >&2
    return 1
  }
  case "$lowerdir" in
    *:*)
      echo "the overlay at '$target' stacks several lower layers ($lowerdir); only the verified installer root may be below it" >&2
      return 1 ;;
  esac
  [[ "${lowerdir%/}" == "$lower" ]] || {
    echo "the overlay at '$target' is stacked over '$lowerdir', not over the verified installer root at '$lower'" >&2
    return 1
  }
  upperdir="$(tr ',' '\n' <<<"$superopts" | sed -n 's/^upperdir=//p')"
  [[ "$(grep -c . <<<"$upperdir")" == 1 && "${upperdir:0:1}" == "/" ]] || {
    echo "the overlay at '$target' declares no single absolute upper layer" >&2
    return 1
  }
  # The upper layer must live on a tmpfs. Find the mount whose mount point is the
  # LONGEST prefix of the upper directory -- that is the filesystem the kernel
  # actually writes those bytes to.
  local carrier
  carrier="$(awk -v u="$upperdir" '
    {
      mp = $5
      if (mp == "/" || substr(u, 1, length(mp) + 1) == mp "/" || u == mp) {
        if (length(mp) >= best) { best = length(mp); line = $0 }
      }
    }
    END { if (line == "") exit 1; print line }' <<<"$info")" || {
    echo "nothing in the mount table carries the overlay upper layer '$upperdir'" >&2
    return 1
  }
  local carrier_fstype
  carrier_fstype="$(awk -F' - ' '{print $2}' <<<"$carrier" | awk '{print $1}')"
  [[ "$carrier_fstype" == tmpfs ]] || {
    echo "the overlay upper layer '$upperdir' is on '${carrier_fstype:-unknown}', not on a tmpfs; a disk-backed upper layer is writable before this machine boots" >&2
    return 1
  }
  printf 'overlay:%s lower:%s upper:%s\n' "$target" "$lowerdir" "$upperdir"
}

# --------------------------------------------------------------------------- #
# WHICH DISK THIS MACHINE BOOTED FROM (review 2026-09-01, P0 #1).
#
# 🔴 THE BUG THIS REPLACES. The installer asked `findmnt -no SOURCE /` and fed
# the answer to `lsblk -no PKNAME`. Since the signed initramfs deliberately
# switch-roots onto an OVERLAY over the verified squashfs, `findmnt /` answers
# `neural-ice-installer-root` -- an overlay source, not a block device -- so
# `PKNAME` was empty and EVERY sealed Install medium died identifying its own
# disk, before the trust gate and before any disk was touched.
#
# WHAT RUNS INSTEAD. The signed initramfs already resolved the authenticated
# payload partition and recorded it. That breadcrumb is consumed here, and it is
# consumed the way every other breadcrumb in this tree is: as a CANDIDATE, never
# as authority. Five things are required of it, and any one of them failing is a
# refusal rather than a fallback:
#
#   1. the breadcrumb is a small, regular, non-symlink file holding ONE plain
#      path under /dev -- no traversal, no whitespace, no second line;
#   2. that path is a block device the kernel knows, whose device number is the
#      one the initramfs recorded (a udev symlink repointed at a second medium
#      after switch-root cannot smuggle another disk in here);
#   3. sysfs says it is a PARTITION, so there is a parent disk to derive at all;
#   4. its parent in sysfs is a whole disk (no `partition` attribute of its own);
#   5. and -- the part that makes it THIS medium rather than any medium -- the
#      payload header read straight off that partition hashes to the digest the
#      signed UKI seals. A device that does not carry the authenticated payload
#      is not the medium this kernel booted, whatever a breadcrumb says.
#
# Prints `<node> <devno> <parent-disk-kernel-name>`.
#
#   $1 the initramfs state directory holding the breadcrumbs
#   $2 the sealed payload digest, already proved against the signed cmdline
# --------------------------------------------------------------------------- #
# Where block device nodes live. `/dev` in production, always; the override is
# what lets the harness stand a directory of regular files in for a device tree
# it has no right to mknod, and it is refused in a privileged process exactly
# like every other override in this file.
installer_trust_dev_prefix() {
  if [[ -n "${NEURAL_ICE_DEV_PREFIX:-}" ]]; then
    installer_trust_tool_override_allowed || {
      echo "a device-tree override is forbidden in a privileged process" >&2
      return 1
    }
    printf '%s' "${NEURAL_ICE_DEV_PREFIX%/}"
    return 0
  fi
  printf '/dev'
}

installer_trust_sysfs_root() {
  if [[ -n "${NEURAL_ICE_SYSFS_ROOT:-}" ]]; then
    installer_trust_tool_override_allowed || {
      echo "a sysfs override is forbidden in a privileged process" >&2
      return 1
    }
    printf '%s' "${NEURAL_ICE_SYSFS_ROOT%/}"
    return 0
  fi
  printf '/sys'
}

# In production a payload partition is a block device and nothing else. Under the
# harness -- which has no right to mknod and must still drive every refusal above
# -- a regular file standing in for one is accepted, and ONLY there: the override
# is refused in a privileged process exactly like every other one in this file.
installer_trust_is_block_device() { # $1=path
  [[ -b "$1" ]] && return 0
  if [[ "${NEURAL_ICE_BLOCK_DEVICE_FIXTURE:-}" == 1 ]] && installer_trust_tool_override_allowed; then
    [[ -f "$1" && ! -L "$1" ]] && return 0
  fi
  return 1
}

installer_trust_sealed_medium_disk() {
  if (( $# != 2 )); then
    echo "installer_trust_sealed_medium_disk requires the initramfs state directory and the sealed payload digest" >&2
    return 2
  fi
  local state=${1%/} sealed_digest=$2 sysfs devprefix node recorded_devno kname actual_devno
  local breadcrumb="$state/payload-device" devno_file="$state/payload-device-devno"

  [[ "$sealed_digest" =~ ^[0-9a-f]{64}$ ]] || {
    echo "the sealed payload digest handed to the medium lookup is malformed" >&2
    return 1
  }
  if ! declare -F payload_header_read >/dev/null || ! declare -F payload_header_digest >/dev/null; then
    echo "the sealed payload parser is not loaded; refusing to identify this medium with a second implementation" >&2
    return 1
  fi
  sysfs="$(installer_trust_sysfs_root)" || return 1
  devprefix="$(installer_trust_dev_prefix)" || return 1

  local file
  for file in "$breadcrumb" "$devno_file"; do
    [[ -f "$file" && ! -L "$file" ]] || {
      echo "the signed initramfs recorded no payload device at $file; this system did not boot from a sealed medium" >&2
      return 1
    }
    (( "$(wc -c < "$file")" <= 4096 )) || {
      echo "the payload device breadcrumb at $file is not a one-line record" >&2
      return 1
    }
    [[ "$(grep -c . < "$file")" == 1 ]] || {
      echo "the payload device breadcrumb at $file does not hold exactly one line" >&2
      return 1
    }
  done
  node="$(tr -d '[:space:]' < "$breadcrumb")"
  recorded_devno="$(tr -d '[:space:]' < "$devno_file")"

  # A PLAIN /dev NODE. `..` would let a breadcrumb name anything on the system,
  # and a name with a shell-significant byte in it is not a device this kernel
  # created.
  [[ "$node" == "$devprefix/"* \
     && "${node#"$devprefix/"}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*(/[A-Za-z0-9][A-Za-z0-9._-]*)*$ ]] || {
    echo "the initramfs recorded '$node', which is not a plain block device path under $devprefix" >&2
    return 1
  }
  case "$node" in
    */../* | */.. | */./* ) echo "the recorded payload device path is not canonical: $node" >&2; return 1 ;;
  esac
  [[ "$recorded_devno" =~ ^[0-9]{1,7}:[0-9]{1,7}$ ]] || {
    echo "the initramfs recorded no usable device number for the payload partition" >&2
    return 1
  }
  installer_trust_is_block_device "$node" || {
    echo "'$node' is not a block device on this system; the recorded payload partition is gone" >&2
    return 1
  }

  kname="${node##*/}"
  [[ -f "$sysfs/class/block/$kname/dev" ]] || {
    echo "the kernel knows no block device named '$kname'" >&2
    return 1
  }
  actual_devno="$(tr -d '[:space:]' < "$sysfs/class/block/$kname/dev")"
  [[ "$actual_devno" == "$recorded_devno" ]] || {
    echo "'$node' is device $actual_devno now and was $recorded_devno when the signed initramfs verified it; the payload device moved under this installer" >&2
    return 1
  }
  # A PARTITION. A whole disk has no parent to exclude, and a device-mapper or
  # loop node is not something a medium is flashed onto.
  [[ -f "$sysfs/class/block/$kname/partition" ]] || {
    echo "'$node' is not a partition; there is no parent disk to exclude from the wipe" >&2
    return 1
  }

  local resolved parent
  resolved="$(readlink -f "$sysfs/class/block/$kname" 2>/dev/null)" || resolved=""
  [[ -n "$resolved" && -d "$resolved" ]] || {
    echo "sysfs does not place '$kname' under a parent device" >&2
    return 1
  }
  parent="$(basename -- "$(dirname -- "$resolved")")"
  [[ "$parent" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ && -d "$sysfs/class/block/$parent" ]] || {
    echo "'$kname' has no whole-disk parent in sysfs" >&2
    return 1
  }
  [[ ! -e "$sysfs/class/block/$parent/partition" ]] || {
    echo "the parent of '$kname' is itself a partition ('$parent'); refusing to guess this medium's disk" >&2
    return 1
  }

  # THE AUTHENTICATED PAYLOAD, READ OFF THE DEVICE ITSELF. Everything above is
  # topology; this is identity. A breadcrumb that survived every structural check
  # while naming some other disk fails here, because that disk does not carry the
  # payload the signature covers.
  local header actual_digest
  header="$(payload_header_read "$node" 0)" || {
    echo "'$node' carries no readable sealed payload header; it is not the medium this kernel booted" >&2
    return 1
  }
  actual_digest="$(payload_header_digest "$header")"
  [[ "$actual_digest" == "$sealed_digest" ]] || {
    echo "'$node' carries payload header $actual_digest, not the $sealed_digest the signed UKI seals; it is not the medium this kernel booted" >&2
    return 1
  }

  printf '%s %s %s\n' "$node" "$actual_devno" "$parent"
}

# --------------------------------------------------------------------------- #
# A small, regular, non-symlink, allowlisted-value marker under a root prefix.
# The same shape access_policy_read() enforces, generalised so the hardware
# target and the trust-policy id get the same treatment instead of a `cat`.
# --------------------------------------------------------------------------- #
installer_trust_read_marker() { # $1=root prefix  $2=relpath  $3=field key it must satisfy
  if (( $# != 3 )); then
    echo "installer_trust_read_marker requires a root, a relative path and a field key" >&2
    return 2
  fi
  local root=${1%/} relpath=$2 key=$3 value size path
  path="$root/$relpath"

  [[ -f "$path" && ! -L "$path" ]] || {
    echo "immutable marker is missing or not a regular file: $path" >&2
    return 1
  }
  size="$(wc -c < "$path")"
  (( size > 0 && size <= 128 )) || {
    echo "immutable marker has an implausible size: $path" >&2
    return 1
  }
  value="$(tr -d '[:space:]' < "$path")"
  installer_trust_value_is_valid "$key" "$value" || {
    echo "immutable marker is not a valid $key: '$value' in $path" >&2
    return 1
  }
  printf '%s\n' "$value"
}

# --------------------------------------------------------------------------- #
# THE GATE. Everything above, composed, in the order the ordering matters:
#
#   1. read the sealed anchor out of the signed cmdline;
#   2. prove the root the anchor describes is the root we are standing on;
#   3. ONLY THEN read the in-root markers, and require them to agree.
#
# Step 3 after step 2 is the entire point. Reading a policy out of an
# unauthenticated root and then verifying the root would be verifying a copy of
# the answer, not the answer.
#
#   4. and prove the MACHINE is one the sealed hardware target admits.
#
# Step 4 is not redundant with step 3: the marker and the sealed word are both
# build inputs, so two copies of the same string agreeing says nothing about
# where the medium was plugged in. The measured identity comes from the hardware
# (image/lib/hardware-identity.sh) and is compared against a list that lives in
# the now-verity-protected /usr.
#
# WHERE THE MARKERS ARE READ FROM, since the runtime root is an overlay
# (review 2026-09-01, P0 #1). The installer needs a writable /etc and /var, so
# `/` is an overlay whose LOWER layer is the verity mount. Reading policy off `/`
# would therefore read it out of a tmpfs anybody with root can write. The caller
# passes the READ-ONLY VERITY MOUNT as both the root prefix and the mount target,
# so every marker below is read from the extent the signature covers -- and calls
# installer_trust_assert_overlay_root separately to prove the overlay's shape.
#
#   $1 root prefix ("" = the running system; normally the verity mount)
#   $2 cmdline string
#   $3 verity mapper name (optional)
#   $4 mount target the root prefix is served from (optional, default "/")
#   $5 sysfs prefix for the measured identity (optional, tests only)
# Prints the agreed `key=value` lines on success.
# --------------------------------------------------------------------------- #
installer_trust_gate() {
  if (( $# < 2 || $# > 5 )); then
    echo "installer_trust_gate requires a root prefix and a cmdline" >&2
    return 2
  fi
  local root=$1 cmdline=$2 mapper=${3:-neuralice-installer-root}
  local mount_target=${4:-/} sysfs=${5:-}
  local sealed
  sealed="$(installer_trust_read_sealed "$cmdline")" || {
    echo "this medium carries no readable sealed installer trust anchor" >&2
    return 1
  }
  local sealed_profile sealed_target sealed_policy_id sealed_roothash sealed_keyid
  sealed_profile="$(sed -n 's/^neuralice\.access_profile=//p' <<<"$sealed")"
  sealed_target="$(sed -n 's/^neuralice\.hardware_target=//p' <<<"$sealed")"
  sealed_policy_id="$(sed -n 's/^neuralice\.trust_policy_id=//p' <<<"$sealed")"
  sealed_roothash="$(sed -n 's/^neuralice\.rootverity=//p' <<<"$sealed")"
  sealed_keyid="$(sed -n 's/^neuralice\.relauth_keyid=//p' <<<"$sealed")"

  installer_trust_assert_root_verity "$sealed_roothash" "$mapper" "$mount_target" >/dev/null || {
    echo "the installer root is not authenticated by the boot signature; refusing to read its access policy" >&2
    return 1
  }

  # From here the root is authenticated, so its files are evidence.
  local marker_profile marker_target marker_policy_id
  marker_profile="$(access_policy_read "$root")" || {
    echo "the verified installer root carries no readable immutable access policy" >&2
    return 1
  }
  [[ "$marker_profile" == "$sealed_profile" ]] || {
    echo "the verified installer root states access profile '$marker_profile' but the signed cmdline seals '$sealed_profile'" >&2
    return 1
  }
  marker_target="$(installer_trust_read_marker "$root" "$NEURAL_ICE_HARDWARE_TARGET_RELPATH" neuralice.hardware_target)" || return 1
  [[ "$marker_target" == "$sealed_target" ]] || {
    echo "the verified installer root states hardware target '$marker_target' but the signed cmdline seals '$sealed_target'" >&2
    return 1
  }
  marker_policy_id="$(installer_trust_read_marker "$root" "$NEURAL_ICE_TRUST_POLICY_ID_RELPATH" neuralice.trust_policy_id)" || return 1
  [[ "$marker_policy_id" == "$sealed_policy_id" ]] || {
    echo "the verified installer root states trust policy '$marker_policy_id' but the signed cmdline seals '$sealed_policy_id'" >&2
    return 1
  }

  # The release-authorization key is the one input the markers cannot restate:
  # its identity is the SHA-256 of the key file, so a substituted key is a
  # different id and the sealed value no longer matches. Without this the
  # verifying key would be as editable as the thing it verifies.
  local keypath actual_keyid
  keypath="${root%/}/$NEURAL_ICE_RELAUTH_KEY_RELPATH"
  [[ -f "$keypath" && ! -L "$keypath" ]] || {
    echo "the verified installer root carries no release-authorization public key at $keypath" >&2
    return 1
  }
  actual_keyid="$(sha256sum "$keypath" | awk '{print tolower($1)}')"
  [[ "$actual_keyid" == "$sealed_keyid" ]] || {
    echo "the release-authorization key in the installer root ($actual_keyid) is not the one the UKI sealed ($sealed_keyid)" >&2
    return 1
  }

  # THE MACHINE ITSELF. Everything above compared build inputs with each other.
  # This asks the hardware what it is and requires the answer to be one the
  # sealed target admits -- so a medium built for a GB10 cannot wipe some other
  # arm64 box that happens to boot it. A machine that cannot be identified at all
  # is a refusal: "I do not know what this is" is not a licence to repartition it.
  local measured
  measured="$(hardware_identity_assert_target "$root" "$sealed_target" "$sysfs")" || {
    echo "this machine is not one the sealed hardware target '$sealed_target' admits; refusing to act on it" >&2
    return 1
  }
  printf 'neuralice.measured_identity=%s\n' "$measured" >&2

  printf '%s\n' "$sealed"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  _trust_self_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  # shellcheck source=image/lib/access-policy.sh
  source "$_trust_self_dir/access-policy.sh"
  # shellcheck source=image/lib/hardware-identity.sh
  source "$_trust_self_dir/hardware-identity.sh"
  # The ONE payload parser. sealed-medium-disk re-reads the header off the block
  # device the initramfs named, and it must do so with the same code the build,
  # the initramfs and the installer use -- a second parser is a second answer.
  # shellcheck source=image/lib/installer-payload.sh
  source "$_trust_self_dir/installer-payload.sh"
  command_name=${1:-}
  shift || true
  case "$command_name" in
    render-cmdline) installer_trust_render_cmdline "$@" ;;
    field) installer_trust_field "$@" ;;
    read-sealed) installer_trust_read_sealed "$@" ;;
    assert-root-verity) installer_trust_assert_root_verity "$@" ;;
    assert-overlay-root) installer_trust_assert_overlay_root "$@" ;;
    sealed-medium-disk) installer_trust_sealed_medium_disk "$@" ;;
    verity-table) installer_trust_verity_table_root_hash "$@" ;;
    read-marker) installer_trust_read_marker "$@" ;;
    gate) installer_trust_gate "$@" ;;
    *)
      echo "usage: $0 {render-cmdline PROFILE TARGET KEYID ROOTHASH PAYLOAD POLICY_ID [KARG…]|field KEY CMDLINE|read-sealed CMDLINE|assert-root-verity HASH [MAPPER] [MOUNT] [LABEL]|assert-overlay-root LOWER [TARGET]|sealed-medium-disk STATE_DIR PAYLOAD_DIGEST|verity-table MAPPER HASH|read-marker ROOT RELPATH KEY|gate ROOT CMDLINE [MAPPER] [MOUNT] [SYSFS]}" >&2
      exit 2
      ;;
  esac
fi
