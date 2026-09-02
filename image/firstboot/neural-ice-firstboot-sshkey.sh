#!/usr/bin/env bash
#
# First-boot provisioning AND activation of the operator SSH key for 'core'.
#
# The vanilla public image bakes no key. A LAB-MANAGED installation medium can
# inject one at install time by adding `neuralice.sshkey=<base64-of-authorized_keys>`
# to the installed system's kernel command line; this service decodes it on first
# boot and writes it to ~core/.ssh/authorized_keys (which the sshd config already
# honors). A provisioned key also UNMASKS sshd, because every sealed variant
# ships it masked. Without that, the operator's key lands on a sealed image and
# nothing listens.
#
# 🔴 THIS IS THE SECOND OF TWO INDEPENDENT GATES, AND IT DOES NOT TRUST THE FIRST.
#
# It used to honour that karg on EVERY non-debug image. The karg is written by
# the installer, the installer took it from an unsigned file on a mutable vfat
# ESP, and nothing downstream re-checked anything -- so editing one file on an
# otherwise correctly signed installer USB opened SSH on a `prod` appliance. The
# build-time lab-anchor check in build-installer-usb.sh never ran on that path;
# it runs on a build host, not on the customer's machine.
#
# So the karg is now EVIDENCE, not authority. The authority is
# /usr/lib/neural-ice/access-policy: written at image build time from ${VARIANT},
# carried in the read-only ostree /usr, covered by whatever signs the image, and
# unreachable from the medium. On `customer-locked` a karg is refused outright --
# no authorized_keys, no systemctl, nothing -- because on a customer appliance
# its only possible origin is tampering. An unreadable or unknown policy is
# refused the same way: fail closed, never fail open.
#
# 🔴 TWO PHASES, TWO UNITS, AND THE SYSTEMD ORDERING IS THE WHOLE POINT.
#
#   provision   neural-ice-firstboot-sshkey.service, ordered Before=sshd.service.
#               Decides, validates, writes authorized_keys, unmasks and enables
#               sshd -- and NEVER starts or polls it. Being ordered before sshd
#               means systemd holds the sshd start job until this oneshot exits,
#               so a poll here CANNOT succeed even when everything worked.
#               A single unit doing both is the defect this split fixes: it
#               queued sshd, waited ten seconds for a job the manager was
#               holding open on its own exit, then recorded failure on a healthy
#               lab appliance while sshd came up a moment later.
#   activate    neural-ice-firstboot-sshkey-activate.service, ordered After= the
#               provisioning unit AND After=sshd.service, conditioned on the
#               handoff directory provisioning leaves behind. Ordered after sshd,
#               it may start sshd and watch it actually come up. It alone writes
#               the success marker, and only after that proof.
#               If sshd does not come up it ROLLS THE PROVISIONING BACK: it
#               removes exactly the key it added and restores exactly the sshd
#               enablement state it changed, then leaves the marker unwritten so
#               the next boot retries from the karg. A lab appliance that cannot
#               serve the key must not be left holding it.
#
set -euo pipefail

# Test seams are accepted only by an explicit unprivileged test process, outside
# both the immutable release image and an alternate root marked as one.  A root
# service must never let environment injection redirect its filesystem,
# evidence, timeout, or crash boundary.
if [[ -n "${NEURALICE_FIRSTBOOT_TESTING+x}${NEURALICE_FIRSTBOOT_ROOT+x}${NEURALICE_FIRSTBOOT_CMDLINE+x}${NEURALICE_FIRSTBOOT_SSHD_TIMEOUT+x}${NEURALICE_FIRSTBOOT_CRASH_AT+x}" ]]; then
  [[ "${NEURALICE_FIRSTBOOT_TESTING:-}" == 1 && "$EUID" -ne 0 ]] \
    || { echo "neural-ice-firstboot: test seams require a non-root process" >&2; exit 1; }
  [[ -n "${NEURALICE_FIRSTBOOT_ROOT:-}" ]] \
    || { echo "neural-ice-firstboot: test root is required" >&2; exit 1; }
  [[ ! -e /usr/lib/neural-ice/release-image \
      && ! -e "${NEURALICE_FIRSTBOOT_ROOT%/}/usr/lib/neural-ice/release-image" ]] \
    || { echo "neural-ice-firstboot: test seams are forbidden in a release image" >&2; exit 1; }
fi

ROOT="${NEURALICE_FIRSTBOOT_ROOT:-}"
CMDLINE="${NEURALICE_FIRSTBOOT_CMDLINE:-/proc/cmdline}"
# How long activation waits for sshd to report active. Ten seconds on a real
# appliance; the suite shortens it so a dozen negative cases do not cost two
# minutes of wall clock.
SSHD_TIMEOUT="${NEURALICE_FIRSTBOOT_SSHD_TIMEOUT:-10}"
ROOT="${ROOT%/}"

# The libraries live in the same immutable /usr as the policy marker they read,
# so resolving them through $ROOT is what makes the tests exercise the real
# lookup rather than a special-cased one.
LIB_DIR="$ROOT/usr/lib/neural-ice/lib"
# shellcheck source=image/lib/access-policy.sh
. "$LIB_DIR/access-policy.sh"
# shellcheck source=image/lib/installer-ssh-key.sh
. "$LIB_DIR/installer-ssh-key.sh"

STATE_DIR="$ROOT/var/lib/neural-ice"
marker="$STATE_DIR/.sshkey-provisioned"
receipt="$STATE_DIR/access-provisioning-receipt.json"
# The provision -> activate handoff. Its path is also the activation unit's
# ConditionPathExists, which is what keeps activation a no-op on every boot that
# staged nothing: a refusal, a keyless appliance, or an already-provisioned host.
pending="$STATE_DIR/sshkey-activation-pending"
# The journal is BUILT here and becomes $pending by one rename. It is never
# populated under its public name: a power loss during the several writes that
# make a journal complete would otherwise publish a PARTIAL one, and the next
# boot would refuse forever over a transaction that never touched anything
# (review 2026-09-02, P2). Same directory as $pending, so the rename is inside
# one filesystem and is therefore atomic.
staging="$STATE_DIR/.sshkey-activation-pending.staging"
scratch="$ROOT/run/neural-ice-firstboot"
authorized_dir="$ROOT/var/home/core/.ssh"
authorized="$authorized_dir/authorized_keys"
# Both temporary names belong to this gate by construction, and both live in the
# TARGET directory: /run is a tmpfs, so a rename from there to /var/home is a
# cross-device copy, and a power loss inside one would leave an authorized_keys
# matching neither journalled image -- exactly the state rollback cannot classify.
authorized_new="$authorized_dir/.neural-ice-authorized_keys.new"
# 🔴 NOT A COPY. `cp -p` preserves mode, owner and timestamps and silently drops
# the ACL, the SELinux context, every other xattr, the hard-link identity and the
# inode identity (review 2026-09-02, P2). A HARD LINK preserves all of them
# exactly, because it is not a second file: it is a second NAME for the one the
# operator's other path created. Rollback renames that name back over
# authorized_keys, so what is restored is the original inode itself.
authorized_backup="$authorized_dir/.neural-ice-authorized_keys.backup"
provisioning_lock="$STATE_DIR/sshkey-provisioning.lock"
JOURNAL_SCHEMA=neural-ice-sshkey-rollback-journal-v2

note() { logger -t neural-ice-firstboot "$*" || true; }

# --------------------------------------------------------------------------- #
# 🔴 THE JOURNAL DIRECTORY IS ROOT-CUSTODIED, AND ITS IDENTITY IS PINNED
# (independent review 2026-09-02, P1 #5).
#
# The journal decides whether this gate rolls back, refuses for ever, or writes
# the marker. Nothing about it was checked: not that its parents are directories
# rather than symlinks, not that they belong to this process's own uid, not that
# they are unwritable by anyone else -- and not that the directory validated
# under the lock is the same one that is later removed. A journal an unprivileged
# writer can replace between two of these steps is a journal that decides the
# outcome.
#
# `require_custody` walks every component from $ROOT down and refuses a symlink,
# a non-directory, foreign ownership or group/other write. `path_identity`
# pins the (device, inode) pair; commit_rollback re-reads it immediately before
# the removal and refuses if it moved.
#
# Ownership is compared against THIS PROCESS's euid rather than a literal 0: in
# production that IS root, and under an alternate $ROOT it is the suite's own
# user -- which is the same property, "no other unprivileged user owns the path
# that decides this".
# --------------------------------------------------------------------------- #
# `%a` is three digits, or four when a setuid/setgid/sticky bit is set. Both
# forms are read the same way: the LAST three are always owner/group/other. No
# arithmetic anywhere -- `0755` in a numeric context is octal, and nothing here
# may depend on someone noticing that.
mode_bits() { # $1=path -> "<special><owner><group><other>" or non-zero
  local mode
  mode="$(stat -c '%a' -- "$1")" || return 1
  case "${#mode}" in
    3) printf '0%s' "$mode" ;;
    4) printf '%s' "$mode" ;;
    *) return 1 ;;
  esac
}

writable_by() { # $1=four-digit mode $2=1 for group, 2 for other -> 0 when writable
  local bits=$1 index=$2 digit
  digit="${bits:$(( index + 1 )):1}"
  case "$digit" in 2|3|6|7) return 0 ;; esac
  return 1
}

# 🔴 TWO DIFFERENT REQUIREMENTS, BECAUSE THEY PROTECT TWO DIFFERENT THINGS.
#
#   ANCESTORS   are the distribution's (`/var`, `/var/lib`). This gate does not
#               own their mode and must not fail because a vendor ships one
#               group-writable to a root-adjacent group. What it MUST refuse is
#               an ancestor any user can rename components of -- world-writable
#               without the sticky bit -- because that is the path substitution
#               this check exists to stop.
#   THE TARGET  is created and owned by this gate. It gets the strict rule: no
#               group write, no other write, and owned by this process.
#
# `$ROOT` is never traversed: under an alternate root it is the suite's own
# scratch directory, and in production it is empty.
require_custody() { # $1=absolute path that must exist  -> non-zero with a reason
  local target=$1 euid relative component walked bits owner
  euid="$(id -u)"
  walked="${ROOT:-}"
  relative="${target#"${ROOT:-}"}"
  # No `..`, no empty component: a path this file composed cannot contain one,
  # and a path that does is not one this file composed.
  case "$relative" in
    */../*|*/..|../*|..) return 1 ;;
  esac
  local IFS=/
  # shellcheck disable=SC2086 # deliberate split on '/'
  set -- $relative
  unset IFS
  for component in "$@"; do
    [ -n "$component" ] || continue
    walked="$walked/$component"
    [ ! -L "$walked" ] || return 1
    [ -d "$walked" ] || return 1
    bits="$(mode_bits "$walked")" || return 1
    if [ "$walked" = "$target" ]; then
      owner="$(stat -c '%u' -- "$walked")" || return 1
      [ "$owner" = "$euid" ] || return 1
      ! writable_by "$bits" 1 || return 1
      ! writable_by "$bits" 2 || return 1
    elif writable_by "$bits" 2; then
      # World-writable is only acceptable with the sticky bit, which is what
      # stops one user renaming another's entry.
      case "${bits:0:1}" in 1|3|5|7) ;; *) return 1 ;; esac
    fi
  done
  [ -d "$target" ] || return 1
  return 0
}

# One writer at a time across provision and activate. The lock file is created
# root-only BEFORE it is opened: creating it through the redirection first would
# publish a 0644 file for as long as the chmod took.
#
# 🔴 AND CUSTODY IS ESTABLISHED BEFORE THE LOCK IS TAKEN, not after: a lock held
# on a file inside a directory somebody else can rename is not a lock.
# 🔴 CREATE EVERY COMPONENT WITH AN EXPLICIT MODE. GNU `install -d -m MODE a/b/c`
# applies MODE to `c` ONLY; `a` and `b` get whatever the process umask allows. On
# a first boot inheriting a 002 umask that is a group-writable /var/lib, and the
# custody check below would then -- correctly -- refuse to run at all. The state
# directory this gate owns must not depend on the umask it inherited.
install_custodied_dir() { # $1=absolute path under $ROOT
  local target=$1 relative component walked
  walked="${ROOT:-}"
  relative="${target#"${ROOT:-}"}"
  local IFS=/
  # shellcheck disable=SC2086 # deliberate split on '/'
  set -- $relative
  unset IFS
  for component in "$@"; do
    [ -n "$component" ] || continue
    walked="$walked/$component"
    if [ "$walked" = "$target" ]; then
      # 🔴 THE GATE OWNS THIS ONE, so it states its mode unconditionally rather
      # than inheriting whatever created it first. `install -d -m` chmods an
      # existing directory, which is the fail-closed action for the directory
      # that holds this transaction's journal, its lock and its receipt: an
      # appliance whose /var/lib/neural-ice arrived group-writable is tightened,
      # not refused for ever. It still refuses if it is not this process's to
      # tighten -- `install -d` fails, and require_custody re-reads the result.
      install -d -m 0755 "$walked" || return 1
    else
      # Ancestors belong to the distribution. Create them if they are missing;
      # never restate the mode of a directory this gate does not own.
      [ -d "$walked" ] || install -d -m 0755 "$walked" || return 1
    fi
  done
  return 0
}

lock_provisioning() {
  install_custodied_dir "$STATE_DIR" \
    || { note "REFUSED: cannot create ${STATE_DIR} with a custodied mode"; exit 1; }
  require_custody "$STATE_DIR" \
    || { note "REFUSED: ${STATE_DIR} is not root-custodied (a symlinked, foreign-owned or group/other-writable component)"; exit 1; }
  [ -f "$provisioning_lock" ] || ( umask 077; : > "$provisioning_lock" )
  [ ! -L "$provisioning_lock" ] \
    || { note "REFUSED: the provisioning lock path is a symlink"; exit 1; }
  chmod 0600 "$provisioning_lock"
  exec 9>"$provisioning_lock"
  flock -x 9
}

# The (device, inode) of the published journal, captured under the lock. Used by
# commit_rollback to refuse removing a directory that is no longer the one this
# boot validated.
JOURNAL_IDENTITY=""

# Pin only. Whether an unusable handoff is a refusal, and WHICH refusal, belongs
# to the caller that also writes the receipt -- a helper that exited here would
# produce a refusal with no recorded decision, which is the state an operator
# cannot act on.
pin_journal_identity() {
  JOURNAL_IDENTITY=""
  { [ -d "$pending" ] && [ ! -L "$pending" ]; } || return 0
  JOURNAL_IDENTITY="$(path_identity "$pending")" || JOURNAL_IDENTITY=""
  return 0
}

# Read one journal field without letting a truncated or tampered handoff abort
# the caller through `set -e`. An unreadable field is REPORTED as unusable and
# refused; it is never defaulted, because every default here is a guess about
# what was already done to authorized_keys.
journal_field() { # $1=name  -> value on stdout, non-zero when unusable
  local file="$pending/$1" value
  { [ -f "$file" ] && [ ! -L "$file" ]; } || return 1
  value="$(cat -- "$file")" || return 1
  printf '%s' "$value"
}

journal_flag() { # $1=name  -> 0|1 on stdout, non-zero when unusable
  local value
  value="$(journal_field "$1")" || return 1
  { [ "$value" = 0 ] || [ "$value" = 1 ]; } || return 1
  printf '%s' "$value"
}

# The journal is only a journal once it is on the medium. `sync FILE` fsyncs
# exactly that object (coreutils >= 8.24) and `sync DIR` fsyncs the directory,
# which is what makes a rename or an unlink survive a power loss rather than the
# page cache. An older coreutils falls back to a whole-system sync: slower, and
# strictly stronger, so the fallback can never be the weaker answer.
fsync_path() { # $1=path
  sync -- "$1" 2>/dev/null || sync
}

# 🔴 POWER-LOSS INJECTION SEAM. It exists because "every crash state reconciles
# idempotently" is a claim about states no ordinary test can reach: the suite
# needs to stop this script BETWEEN two instructions and then run the next boot.
# It is inert unless an ALTERNATE ROOT is in force, which the installed units
# never set, so on an appliance this function is one comparison against an empty
# string.
crash_seam() { # $1=phase name
  [ -n "$ROOT" ] || return 0
  [ "${NEURALICE_FIRSTBOOT_CRASH_AT:-}" = "$1" ] || return 0
  note "TEST: simulated power loss at phase '$1'"
  exit 99
}

# --------------------------------------------------------------------------- #
# 🔴 EVERY METADATA OPERATION IS CHECKED, AND "TIMES" MEANS EXACTLY atime/mtime
# (independent review 2026-09-02, P1 #3).
#
# WHAT THIS REPLACES. `touch`, `chmod`, `chown` and the directory removal were
# all suffixed `2>/dev/null || true`, and a missing or malformed journal field
# `return 0`-ed as if the restoration had happened. So an I/O error, a read-only
# remount, a filesystem that lost the field, or a journal replaced between
# validation and restoration all produced a SUCCESSFUL rollback in which the
# file's or the directory's metadata had not been restored -- and commit_rollback
# then deleted the journal, which was the only remaining record of what had been
# changed. Bytes restored, metadata not, evidence gone.
#
# Now: every operation returns its status, every absent or malformed field is a
# refusal rather than a no-op, and the restored state is READ BACK and compared
# against the journalled one. A rollback that cannot prove it restored what it
# recorded returns non-zero, and the caller keeps the journal.
#
# 🔴 AND THE CONTRACT SAYS WHAT IS RESTORABLE. Linux offers no interface to set
# ctime, so ctime is NOT restored and is not claimed to be. What is restored, and
# proved: the bytes, the inode identity, the link count, uid, gid, mode, atime,
# mtime, and -- because rollback renames the ORIGINAL INODE back rather than
# copying its bytes -- the ACL, the extended attributes and the SELinux context,
# which never went anywhere. Each of those is compared after the fact against the
# capture taken before the transaction started.
# --------------------------------------------------------------------------- #

# Mode, owner, group, link count and the two restorable timestamps, as words a
# journal can hold and `chmod`/`chown`/`touch` can put back.
path_metadata() { # $1=path -> "<mode> <uid> <gid> <nlink> <mtime-ns> <atime-ns>"
  stat -c '%a %u %g %h %.9Y %.9X' -- "$1"
}

dir_metadata() { path_metadata "$1"; }

# The identity of the inode itself. A rollback that produced the right BYTES at a
# different inode has not restored the operator's file: its external hard links
# would still point at the old one, and its ACL/xattrs/context would be whatever
# the new one happened to get.
path_identity() { # $1=path -> "<device>:<inode>"
  stat -c '%d:%i' -- "$1"
}

# The attributes a rename preserves for free and a copy silently drops. Each is
# optional -- not every filesystem or build has getfacl/getfattr, and the suite
# says so out loud rather than pretending -- but when one IS available before the
# transaction it MUST still match after it.
path_acl() { # $1=path -> stable ACL text, or non-zero when unavailable
  command -v getfacl >/dev/null 2>&1 || return 1
  getfacl --absolute-names --omit-header -- "$1" 2>/dev/null | LC_ALL=C sort | tr '\n' ';'
}

path_xattrs() { # $1=path -> stable xattr dump, or non-zero when unavailable
  command -v getfattr >/dev/null 2>&1 || return 1
  getfattr --absolute-names --dump --match=- -- "$1" 2>/dev/null \
    | grep -v '^# file:' | LC_ALL=C sort | tr '\n' ';'
}

path_selinux() { # $1=path -> SELinux context, or non-zero when unavailable
  local context
  context="$(stat -c '%C' -- "$1" 2>/dev/null)" || return 1
  [ -n "$context" ] && [ "$context" != '?' ] || return 1
  printf '%s' "$context"
}

# 🔴 NOT `|| true`. A timestamp this gate recorded and cannot put back is a
# rollback that did not happen, and the caller must learn that rather than go on
# to delete the journal.
restore_times() { # $1=path $2=mtime-ns $3=atime-ns
  [ -e "$1" ] || return 1
  [ -n "${2:-}" ] && [ -n "${3:-}" ] || return 1
  touch -m -d "@$2" -- "$1" || return 1
  touch -a -d "@$3" -- "$1" || return 1
  return 0
}

sha_of() { # $1=path -> sha256 hex, or non-zero when it is not a plain file
  { [ -f "$1" ] && [ ! -L "$1" ]; } || return 1
  sha256sum -- "$1" | awk '{print $1}'
}

# The bytes provisioning INTENDS to write, hashed without writing them anywhere.
# Computing the "after" image by materialising it in ~core/.ssh would mutate that
# directory before the journal recording its metadata was durable, which is the
# one ordering this transaction may not have.
compose_after_sha256() { # $1=existing-or-empty  $2=approved record
  {
    if [ -n "$1" ] && [ -s "$1" ]; then
      cat -- "$1"
      # A pre-existing file whose last record has no terminating newline would
      # otherwise be JOINED to the appended one, destroying both records.
      if [ "$(tail -c 1 -- "$1" | od -An -tu1 | tr -d '[:space:]')" != 10 ]; then
        printf '\n'
      fi
    fi
    cat -- "$2"
  } | sha256sum | awk '{print $1}'
}

# --------------------------------------------------------------------------- #
# PUBLISH THE JOURNAL: fsync every part, fsync the staging directory, then make
# it visible by ONE rename inside one filesystem, then fsync the directory that
# rename happened in. Before the rename there is no journal; after it there is a
# complete one. There is no instant at which a partial journal exists under the
# public name, which is the property the previous revision did not have.
# --------------------------------------------------------------------------- #
publish_journal() {
  local part
  for part in "$staging"/* "$staging"/.[!.]*; do
    [ -e "$part" ] || continue
    fsync_path "$part"
  done
  fsync_path "$staging"
  rm -rf -- "$pending"
  mv -fT "$staging" "$pending"
  fsync_path "$STATE_DIR"
}

# The OPERATOR RECOVERY CONTRACT, written into the journal itself. A gate that
# can refuse forever must say, on the machine, what a human is expected to do
# about it -- otherwise "fail closed" is indistinguishable from "broken"
# (review 2026-09-02, product question 3). It names no key material: the
# fingerprint is in `fingerprint`, the bytes are in `key.pub`, and both are
# already root-only.
write_recovery_contract() {
  cat <<'RECOVERY_CONTRACT_EOF'
Neural ICE — operator SSH provisioning rollback journal
======================================================

This directory exists because a first-boot SSH provisioning transaction was
started. It is REMOVED automatically once that transaction is either proven
(sshd active) or fully rolled back and made durable. If you are reading it, one
of those two has not happened yet.

While it exists:
  * /var/lib/neural-ice/.sshkey-provisioned is NOT written, so the next boot
    replays this journal before it re-decides anything;
  * sshd's enablement state has already been restored to what it was;
  * ~core/.ssh/authorized_keys is either the file that was there before, or the
    file this transaction wrote — never a partial one.

WHAT EACH FILE MEANS
  schema              the journal format this appliance wrote
  key_added           1 = this transaction appended a record; 0 = the approved
                      record was already present and NOTHING was written
  authorized_existed  1 = ~core/.ssh/authorized_keys existed beforehand
  before_sha256       SHA-256 of that prior file
  after_sha256        SHA-256 of the file this transaction intended to write
  dir_metadata        mode uid gid nlink mtime-ns atime-ns of ~core/.ssh beforehand
  file_metadata       the same six words for authorized_keys beforehand
  file_identity       device:inode of the file that was there beforehand
  file_acl            its ACL, when this filesystem offers one
  file_xattrs         its extended attributes, when this filesystem offers them
  file_selinux        its SELinux context, when one is readable
  fingerprint         the approved public key's SHA256 fingerprint

WHAT IS RESTORED, AND WHAT IS NOT
  Restored and PROVED: the bytes, the inode identity, the link count, uid, gid,
  mode, atime and mtime of authorized_keys, and the mode, uid, gid, atime and
  mtime of ~core/.ssh. Because rollback renames the ORIGINAL INODE back rather
  than copying its bytes, the ACL, the extended attributes and the SELinux
  context are preserved too, and each is compared against the capture above.
  NOT restored: ctime. Linux offers no interface to set it. Nothing here claims
  otherwise, and a rollback is never reported as complete on the strength of it.

WHAT TO DO ABOUT IT
  1. Read the decision in /var/lib/neural-ice/access-provisioning-receipt.json.
  2. If it says `stale-handoff-unrecoverable`, ~core/.ssh/authorized_keys
     matches NEITHER before_sha256 NOR after_sha256: something other than this
     gate owns those bytes now. Only a human can say which are authority. This
     appliance will keep refusing to provision until one does.
  3. Compare `sha256sum ~core/.ssh/authorized_keys` against the two hashes above
     and decide. Then remove this directory to allow provisioning to run again.
  4. ~core/.ssh/.neural-ice-authorized_keys.backup, when present, is a HARD LINK
     to the file that was there before this transaction: same inode, same mode,
     owner, ACL, SELinux context and xattrs. Restoring it is
     `mv -fT ~core/.ssh/.neural-ice-authorized_keys.backup ~core/.ssh/authorized_keys`.

Nothing here is deleted automatically while it cannot be interpreted: an
unreadable journal is evidence, and evidence is not disposable scratch.
RECOVERY_CONTRACT_EOF
}

# A bounded, root-only receipt of the ACCESS DECISION. It records what was
# decided and which key was accepted, never the key itself: authorized_keys and
# the operator's own ESP payload are the only places the key bytes belong.
#
# No timestamp. First boot has no trusted time source -- the RTC is whatever the
# firmware said, NTP has not run, and the OTA verifier's trusted-time challenge
# is not available synchronously here. A field that would only ever hold an
# attacker-influenced number is worse than an absent one, so it is null and says
# why. Likewise `source_installer_identity`: nothing the installer hands the
# installed system today identifies the medium in a way that survives an
# attacker who controls that medium, so it stays null until such an identity
# exists. `image_ota_imgref` IS trustworthy -- it comes from the same signed /usr
# as the policy -- so that is what is recorded.
write_receipt() { # $1=policy $2=ssh_provisioned $3=decision $4=key_sha256 $5=fingerprint
  local policy=$1 provisioned=$2 decision=$3 key_sha256=$4 fingerprint=$5
  local imgref=null tmp="$receipt.new"

  if [ -f "$ROOT/usr/lib/neural-ice/ota-imgref" ]; then
    local raw
    raw="$(tr -d '[:space:]' < "$ROOT/usr/lib/neural-ice/ota-imgref")"
    if [ "${#raw}" -le 256 ] && [[ "$raw" =~ ^[A-Za-z0-9._/:@-]+$ ]]; then
      imgref="\"$raw\""
    fi
  fi
  [ -n "$policy" ] || policy=unknown
  # Every value below is either drawn from a closed allowlist or matched against
  # a strict pattern before it reaches the document, so the receipt cannot be
  # made to carry attacker-chosen JSON and cannot grow unbounded.
  local sha_json=null fingerprint_json=null
  if [[ "$key_sha256" =~ ^[0-9a-f]{64}$ ]]; then sha_json="\"$key_sha256\""; fi
  if [[ "$fingerprint" =~ ^SHA256:[A-Za-z0-9+/]{43}$ ]]; then fingerprint_json="\"$fingerprint\""; fi

  ( umask 077
    printf '{"access_policy":"%s","decision":"%s","image_ota_imgref":%s,"public_key_fingerprint":%s,"public_key_sha256":%s,"recorded_at":null,"schema":"neural-ice-access-provisioning-receipt-v1","source_installer_identity":null,"ssh_provisioned":%s}\n' \
      "$policy" "$decision" "$imgref" "$fingerprint_json" "$sha_json" "$provisioned" \
      > "$tmp" )
  chmod 0600 "$tmp"
  chown 0:0 "$tmp" 2>/dev/null || [ -n "$ROOT" ]
  mv -f "$tmp" "$receipt"
}

# =========================================================================== #
# PHASE 1 -- provision. Runs BEFORE sshd. Touches no unit state it cannot undo,
# starts nothing, waits for nothing.
# =========================================================================== #
provision() {
  if [ -e "$marker" ]; then
    exit 0
  fi
  lock_provisioning
  # 🔴 RECHECK EVERY TERMINAL STATE AFTER THE LOCK (independent review
  # 2026-09-02, P1 #5). The marker test above happens BEFORE flock. A second
  # provisioner that observed "no marker" and then blocked would, on waking,
  # continue as if nothing had happened -- while the process that held the lock
  # had already completed the transaction and published the marker. It would then
  # re-decide from the karg, re-journal, and mutate a file the first transaction
  # had just finished with. Everything the lock protects is therefore re-read
  # once the lock is actually held.
  if [ -e "$marker" ]; then
    note "another provisioner completed while this one waited for the lock; nothing to do"
    exit 0
  fi
  pin_journal_identity
  # A handoff left behind by a power loss after -- or DURING -- the
  # authorized_keys mutation is a rollback journal, not disposable scratch.
  # Replay it before this boot re-decides from the signed karg: deleting it is
  # precisely what would strand the previous attempt's key on disk with no
  # record that this gate is the thing that put it there.
  if [ -e "$pending" ] || [ -L "$pending" ]; then
    if [ ! -d "$pending" ] || [ -L "$pending" ]; then
      note "REFUSED: the SSH activation handoff path is not a directory"
      write_receipt "" false invalid-handoff-path "" ""
      exit 1
    fi
    # 🔴 THE JOURNAL DECIDES WHAT HAPPENS TO authorized_keys, so a journal any
    # other user could have written or replaced decides it too. This gate
    # publishes its journal at 0700 by one rename; one that is group- or
    # world-writable, foreign-owned or reached through a symlink is not one this
    # gate published, and it is REFUSED rather than replayed. It is also kept:
    # an uninterpretable journal is evidence.
    if ! require_custody "$pending"; then
      note "REFUSED: the SSH activation handoff is not root-custodied (a symlinked, foreign-owned or group/world-writable path); keeping it for inspection"
      write_receipt "" false invalid-handoff-path "" ""
      exit 1
    fi
    local stale_sshd_was_masked stale_rolled_back=0
    if stale_sshd_was_masked="$(journal_flag sshd_was_masked)" \
      && rollback_provisioning "$stale_sshd_was_masked"; then
      stale_rolled_back=1
    fi
    if [ "$stale_rolled_back" = 0 ]; then
      # Fail closed and KEEP the journal: authorized_keys matches neither image
      # this gate recorded, so a third writer touched it and only a human can
      # say which bytes are authority. sshd enablement was still restored, and
      # $pending/RECOVERY states, on the machine, what a human is expected to do.
      note "REFUSED: a previous SSH provisioning attempt left a handoff this boot cannot replay; authorized_keys is not known to be clean and the handoff is kept for inspection (see ${pending}/RECOVERY)"
      write_receipt "" false stale-handoff-unrecoverable "" ""
      exit 1
    fi
    # The undo reaches the target filesystem BEFORE the journal stops existing
    # on the state filesystem. Never the other way round. A refusal here means
    # the journal was replaced or lost custody since this boot validated it, and
    # it is kept rather than removed.
    if ! commit_rollback; then
      write_receipt "" false stale-handoff-unrecoverable "" ""
      exit 1
    fi
  fi
  # A staging directory is a journal that was never published, so nothing it
  # describes was ever done: no mutation happens until after the rename. It is
  # the one piece of state here that IS disposable scratch.
  rm -rf -- "$staging"
  # ...and a temporary name stranded in ~core/.ssh by the same interruption is
  # removed only once the journal above has been replayed and retired. Removing
  # the held-inode backup while a journal still referenced it would destroy the
  # only remaining link to the operator's original file.
  rm -f -- "$authorized_new" "$authorized_backup"

  # ------------------------------------------------------------------------- #
  # 1) The immutable policy. Unreadable or unrecognised = refuse and say so; an
  #    image whose access posture cannot be determined gets no remote access.
  # ------------------------------------------------------------------------- #
  local policy=""
  if ! policy="$(access_policy_read "$ROOT" 2>/dev/null)"; then
    note "REFUSED: no readable immutable access policy — SSH provisioning is unavailable on this image"
    write_receipt "" false policy-unreadable "" ""
    exit 1
  fi

  # ------------------------------------------------------------------------- #
  # 2) The karg. Exactly zero or one occurrence; more than one is ambiguous and
  #    a `sed` that silently keeps the last match is how an operator's key gets
  #    replaced by an appended one.
  # ------------------------------------------------------------------------- #
  local encoded="" occurrences
  # awk's default field splitting is exactly kernel-command-line splitting, and
  # unlike a greedy `sed .*` it can SEE a second occurrence instead of silently
  # keeping the last one.
  occurrences="$(awk '{for (i = 1; i <= NF; i++) if ($i ~ /^neuralice\.sshkey=/) n++} END {print n + 0}' "$CMDLINE")"
  if [ "$occurrences" -gt 1 ]; then
    note "REFUSED: the kernel command line carries ${occurrences} neuralice.sshkey arguments"
    write_receipt "$policy" false ambiguous-karg "" ""
    exit 1
  fi
  if [ "$occurrences" -eq 1 ]; then
    encoded="$(awk '{for (i = 1; i <= NF; i++) if ($i ~ /^neuralice\.sshkey=/) {sub(/^neuralice\.sshkey=/, "", $i); print $i}}' "$CMDLINE")"
  fi

  if [ -z "$encoded" ]; then
    # No key was offered. This is the normal customer appliance and the normal
    # vanilla install alike: nothing to decide, nothing to touch, nothing to
    # activate -- so no handoff is staged and the marker is written here.
    note "no operator SSH key on the kernel command line (policy=${policy}); sshd is untouched"
    write_receipt "$policy" false no-key-offered "" ""
    : > "$marker"
    exit 0
  fi

  # ------------------------------------------------------------------------- #
  # 3) A key WAS offered. On customer-locked this is the tampering case, and it
  #    is refused BEFORE anything is written or any unit is touched.
  # ------------------------------------------------------------------------- #
  if ! access_policy_permits_installer_ssh "$policy"; then
    note "REFUSED: access policy '${policy}' forbids installer SSH provisioning; an SSH karg was present and was NOT honoured"
    write_receipt "$policy" false policy-forbids-ssh "" ""
    exit 1
  fi

  # ------------------------------------------------------------------------- #
  # 4) lab-managed / developer-diagnostic: validate the key as strictly as the
  #    build-time path does, minus the approved hash it has no way to know.
  # ------------------------------------------------------------------------- #
  install -d -m 0700 "$scratch"
  local candidate="$scratch/authorized_keys.candidate"
  rm -f "$candidate"

  refuse_key() {
    rm -f "$candidate"
    note "REFUSED: $1"
    write_receipt "$policy" false "$2" "" ""
    exit 1
  }

  [[ "$encoded" =~ ^[A-Za-z0-9+/=]{1,1024}$ ]] \
    || refuse_key "the neuralice.sshkey argument is not plain base64" malformed-karg
  ( umask 077; printf '%s' "$encoded" | base64 -d > "$candidate" 2>/dev/null ) \
    || refuse_key "the neuralice.sshkey argument is not decodable base64" malformed-karg
  installer_ssh_key_validate_file "$candidate" 2>/dev/null \
    || refuse_key "the provisioned key is not exactly one plain OpenSSH public key" invalid-key

  local key_sha256 fingerprint
  key_sha256="$(sha256sum "$candidate" | awk '{print $1}')"
  fingerprint="$(ssh-keygen -l -f "$candidate" | awk '{print $2}')"

  # Decide under the lifecycle lock whether this exact record already exists.
  # Existing content is authority from another provisioning path: do not sort,
  # rewrite, chmod or chown it merely because the medium approved the same key.
  if [[ -e "$authorized" || -L "$authorized" ]] \
    && [[ ! -f "$authorized" || -L "$authorized" ]]; then
    refuse_key "the existing authorized_keys path is not a regular file" invalid-existing-authorized-keys
  fi
  local key_added=1 authorized_existed=0
  if [ -f "$authorized" ]; then
    authorized_existed=1
    if grep -qxF -f "$candidate" "$authorized"; then
      key_added=0
    fi
  fi

  local sshd_was_masked=0
  if [ "$(systemctl is-enabled sshd.service 2>/dev/null)" = masked ]; then
    sshd_was_masked=1
  fi

  # ------------------------------------------------------------------------- #
  # 🔴 EVERYTHING THIS TRANSACTION WILL DO IS DECIDED, HASHED AND MADE DURABLE
  # BEFORE ANY OF IT HAPPENS -- INCLUDING THE DIRECTORY.
  #
  # The previous revision hashed nothing, copied the prior file with `cp -p`, and
  # created its temporary names in ~core/.ssh BEFORE the journal existed. Three
  # consequences, all of them real (review 2026-09-02, P2):
  #
  #   - the journal was written under its PUBLIC name across six separate
  #     writes, so a power loss inside them published a PARTIAL journal that the
  #     next boot could not classify and would refuse forever -- over a
  #     transaction that had not touched authorized_keys at all;
  #   - `cp -p` kept mode, owner and times and dropped the ACL, the SELinux
  #     context, every other xattr, the hard-link identity and the inode identity;
  #   - creating a temporary name in a PRE-EXISTING ~core/.ssh changed that
  #     directory's mtime with nothing recording what it had been.
  #
  # So: read everything (no writes), hash both images (no writes), record the
  # directory's own metadata (no writes), build the journal under a private
  # staging name, fsync it, and publish it by ONE rename. Only then is anything
  # in ~core/.ssh touched, and by then every byte of it is recoverable.
  # ------------------------------------------------------------------------- #
  local before_sha256='' after_sha256='' dir_existed=0 dir_meta='' file_meta=''
  local file_identity='' file_acl='' file_xattrs='' file_selinux=''
  if [ -d "$authorized_dir" ] && [ ! -L "$authorized_dir" ]; then
    dir_existed=1
    dir_meta="$(dir_metadata "$authorized_dir")"
  fi
  if [ "$authorized_existed" = 1 ]; then
    before_sha256="$(sha_of "$authorized")" \
      || refuse_key "the existing authorized_keys could not be read for journalling" \
           unreadable-existing-authorized-keys
    # 🔴 EVERYTHING A ROLLBACK MUST BE ABLE TO PROVE IT PUT BACK. Bytes and inode
    # identity, the link count (so external hard links are provably preserved),
    # mode/uid/gid, the two restorable timestamps, and -- where the filesystem
    # offers them -- the ACL, the extended attributes and the SELinux context.
    # ctime is absent because Linux offers no way to set it; the recovery
    # contract in the journal says so rather than implying otherwise.
    file_meta="$(path_metadata "$authorized")"
    file_identity="$(path_identity "$authorized")"
    file_acl="$(path_acl "$authorized")" || file_acl=''
    file_xattrs="$(path_xattrs "$authorized")" || file_xattrs=''
    file_selinux="$(path_selinux "$authorized")" || file_selinux=''
  fi
  if [ "$key_added" = 1 ]; then
    if [ "$authorized_existed" = 1 ]; then
      after_sha256="$(compose_after_sha256 "$authorized" "$candidate")"
    else
      after_sha256="$(compose_after_sha256 '' "$candidate")"
    fi
  fi

  rm -rf -- "$staging"
  install -d -m 0700 "$staging"
  install -m 0600 "$candidate" "$staging/key.pub"
  ( umask 077
    printf '%s\n' "$JOURNAL_SCHEMA"     > "$staging/schema"
    printf '%s\n' "$policy"             > "$staging/policy"
    printf '%s\n' "$key_sha256"         > "$staging/key_sha256"
    printf '%s\n' "$fingerprint"        > "$staging/fingerprint"
    printf '%s\n' "$sshd_was_masked"    > "$staging/sshd_was_masked"
    printf '%s\n' "$key_added"          > "$staging/key_added"
    printf '%s\n' "$authorized_existed" > "$staging/authorized_existed"
    printf '%s\n' "$dir_existed"        > "$staging/dir_existed"
    [ -z "$dir_meta" ]       || printf '%s\n' "$dir_meta"       > "$staging/dir_metadata"
    [ -z "$file_meta" ]      || printf '%s\n' "$file_meta"      > "$staging/file_metadata"
    [ -z "$file_identity" ]  || printf '%s\n' "$file_identity"  > "$staging/file_identity"
    [ -z "$file_acl" ]       || printf '%s\n' "$file_acl"       > "$staging/file_acl"
    [ -z "$file_xattrs" ]    || printf '%s\n' "$file_xattrs"    > "$staging/file_xattrs"
    [ -z "$file_selinux" ]   || printf '%s\n' "$file_selinux"   > "$staging/file_selinux"
    [ -z "$before_sha256" ]  || printf '%s\n' "$before_sha256"  > "$staging/before_sha256"
    [ -z "$after_sha256" ]   || printf '%s\n' "$after_sha256"   > "$staging/after_sha256"
    write_recovery_contract > "$staging/RECOVERY" )
  crash_seam journal-staged
  publish_journal
  crash_seam journal-published

  if [ "$key_added" = 1 ]; then
    if [ "$dir_existed" = 0 ]; then
      install -d -m 0700 "$authorized_dir"
      chown core:core "$authorized_dir" 2>/dev/null || [ -n "$ROOT" ]
    fi
    if [ "$authorized_existed" = 1 ]; then
      # The held inode. From here until rollback removes it, the operator's
      # original file has two names in one directory -- same inode, same mode,
      # same owner, same ACL, same context, same xattrs -- and rollback restores
      # it by renaming this name back, not by copying anything anywhere.
      ln -- "$authorized" "$authorized_backup" \
        || refuse_key "the prior authorized_keys could not be held for rollback" \
             rollback-backup-unavailable
      crash_seam backup-linked
    fi
    # Composed from the HELD INODE and the journalled key, by exactly the rule
    # compose_after_sha256 hashed -- so the two cannot drift, and the assertion
    # below is a real comparison rather than a restatement.
    rm -f -- "$authorized_new"
    ( umask 077
      : > "$authorized_new"
      if [ "$authorized_existed" = 1 ] && [ -s "$authorized_backup" ]; then
        cat -- "$authorized_backup" > "$authorized_new"
        # A pre-existing file whose last record has no terminating newline would
        # otherwise be JOINED to the appended one, destroying both records.
        if [ "$(tail -c 1 -- "$authorized_backup" | od -An -tu1 | tr -d '[:space:]')" != 10 ]; then
          printf '\n' >> "$authorized_new"
        fi
      fi
      cat -- "$pending/key.pub" >> "$authorized_new" )
    chmod 0600 "$authorized_new"
    chown core:core "$authorized_new" 2>/dev/null || [ -n "$ROOT" ]
    # The composed bytes must hash to the image the journal published, or this
    # boot is about to write something rollback could not later classify.
    [ "$(sha_of "$authorized_new")" = "$after_sha256" ] \
      || refuse_key "the composed authorized_keys does not match the journalled image" \
           journalled-image-mismatch
    crash_seam new-written
    mv -fT "$authorized_new" "$authorized"
    crash_seam mutated
    fsync_path "$authorized"
    fsync_path "$authorized_dir"
    crash_seam mutated-synced
    note "provisioned operator SSH key for 'core' (policy=${policy}, ${fingerprint})"
  else
    note "approved operator SSH key already present for 'core'; authorized_keys left byte-for-byte unchanged"
  fi

  # Every sealed variant masks sshd (Containerfile.bootc, ADR-0003), so on a
  # lab-managed image the whole chain above lands a key that NOTHING serves: the
  # operator drops authorized_keys on the installer ESP, the autoinstaller turns
  # it into the karg, this service writes it -- and the port stays shut. That is
  # the half that supplies, finished, behind a half that demands.
  #
  # Unmasking HERE and only HERE is what keeps one sealed posture for customers
  # and for us: the shipped bytes stay sealed and keyless, and the privilege
  # travels on the physical installation medium AND is authorised by the image's
  # own immutable policy. A customer-locked appliance never reaches this line.
  if [ "$sshd_was_masked" = 1 ]; then
    systemctl unmask sshd.service
    # `unmask` removes the /etc symlink, but systemd keeps its in-memory view
    # until it is told to look again. Without this reload the unit is still
    # MASKED as far as the manager is concerned, so any later start is a no-op
    # THAT RETURNS SUCCESS -- measured on GB10 2026-08-20: sshd was unmasked one
    # second into the first boot, never started, and only came up on the next
    # reboot. The `|| logger` on the old one-liner never fired, because nothing
    # had failed; only the effect was missing.
    systemctl daemon-reload
    note "unmasked sshd: a lab-managed image was given an operator key by its installation medium"
  fi
  systemctl enable sshd.service 2>/dev/null || true

  # NOT `systemctl start`, and NOT a poll. This unit is Before=sshd.service, so
  # the manager holds the sshd job until it exits: starting here can only ever
  # be a queued job this unit is structurally unable to observe. Hand the proof
  # obligation to the activation unit, which is ordered where it can be met.
  rm -f "$candidate"

  # ssh_provisioned is FALSE here on purpose: the key is on disk and nothing is
  # serving it yet. The receipt states the appliance's actual posture at every
  # instant, not the one it is expected to reach.
  write_receipt "$policy" false provisioned-pending-activation "$key_sha256" "$fingerprint"
  note "operator SSH key staged; sshd activation is deferred to neural-ice-firstboot-sshkey-activate.service"
}

# =========================================================================== #
# PHASE 2 -- activate. Runs AFTER the provisioning unit and AFTER sshd, so the
# manager is free to run the sshd job while this one watches for its effect.
# =========================================================================== #

# Undo exactly the authorized_keys record provisioning added, and nothing else.
#
# 🔴 THE THREE CASES ARE NOT THE SAME, AND CONFLATING THEM IS THE DEFECT THIS
# REPLACES. Deleting "the line that matches the key" destroyed a pre-existing
# IDENTICAL record that this gate never added, and rewriting the survivors
# through a command substitution rewrote the file's bytes -- final newline,
# blank lines, duplicate records and ordering -- even when nothing matched.
#
#   key_added=0            an identical record was already there. Provisioning
#                          wrote nothing, so rollback restores nothing: not one
#                          byte, not the mode, not the owner, not the mtime.
#   key_added=1, existed   restore the exact journalled `before` image, whose
#                          bytes AND metadata were captured with `cp -p`.
#   key_added=1, absent    restore absence.
#
# In the two mutating cases the current file must still be recognisably one of
# the two journalled images. Anything else means a third writer owns those bytes
# now, and this function refuses rather than overwriting an unrelated change.
rollback_authorized_keys() {
  local schema key_added authorized_existed dir_existed
  schema="$(journal_field schema)" || return 1
  [ "$schema" = "$JOURNAL_SCHEMA" ] || return 1
  key_added="$(journal_flag key_added)" || return 1
  authorized_existed="$(journal_flag authorized_existed)" || return 1
  dir_existed="$(journal_flag dir_existed)" || return 1

  # `.new` is this gate's by construction and is never authority: it is either a
  # composition that was interrupted before its rename, or nothing.
  rm -f -- "$authorized_new"

  if [ "$key_added" = 0 ]; then
    # The approved record was ALREADY there. Provisioning wrote nothing: not one
    # byte, not the mode, not the owner, not the mtime -- and the directory was
    # never touched either, so there is nothing here to restore.
    restore_authorized_dir_metadata "$dir_existed" || return 1
    return 0
  fi

  local before_sha256='' after_sha256='' current_sha256=''
  after_sha256="$(journal_field after_sha256)" || return 1
  [[ "$after_sha256" =~ ^[0-9a-f]{64}$ ]] || return 1
  if [ "$authorized_existed" = 1 ]; then
    before_sha256="$(journal_field before_sha256)" || return 1
    [[ "$before_sha256" =~ ^[0-9a-f]{64}$ ]] || return 1
  fi
  # An absent file hashes to nothing; a symlink or a device node where a regular
  # file belongs is not a state this gate will overwrite.
  if [ -e "$authorized" ] || [ -L "$authorized" ]; then
    current_sha256="$(sha_of "$authorized")" || return 1
  fi

  if [ "$authorized_existed" = 1 ]; then
    if [ "$current_sha256" = "$before_sha256" ]; then
      # The interruption preceded the mutation, or rollback already ran. The
      # held inode, if it is still linked, is now a duplicate NAME for the file
      # that is already in place -- remove the name, never the content.
      release_authorized_backup || return 1
      verify_authorized_identity || return 1
      restore_authorized_file_times || return 1
      verify_authorized_preserved_attributes || return 1
      restore_authorized_dir_metadata "$dir_existed" || return 1
      return 0
    fi
    [ "$current_sha256" = "$after_sha256" ] || return 1
    # 🔴 THE RESTORE IS A RENAME OF THE ORIGINAL INODE, not a copy of its bytes.
    # Mode, uid, gid, mtime, ACL, SELinux context, every xattr and the inode
    # number itself come back because they never went anywhere: this is the same
    # inode the operator's other provisioning path created. ctime is the one
    # thing Linux offers no way to restore, and this comment is where that is
    # admitted rather than glossed.
    { [ -f "$authorized_backup" ] && [ ! -L "$authorized_backup" ]; } || return 1
    [ "$(sha_of "$authorized_backup")" = "$before_sha256" ] || return 1
    mv -fT "$authorized_backup" "$authorized" || return 1
    # 🔴 THE RESTORATION IS PROVED, NOT ASSUMED. Every one of these returns its
    # status, and the caller keeps the journal when any of them refuses.
    verify_authorized_identity || return 1
    restore_authorized_file_times || return 1
    verify_authorized_preserved_attributes || return 1
    restore_authorized_dir_metadata "$dir_existed" || return 1
    return 0
  fi

  if [ -z "$current_sha256" ]; then
    # Restoring absence, already done.
    release_authorized_backup || return 1
    restore_authorized_dir_metadata "$dir_existed" || return 1
    return 0
  fi
  [ "$current_sha256" = "$after_sha256" ] || return 1
  rm -f -- "$authorized" || return 1
  [ ! -e "$authorized" ] && [ ! -L "$authorized" ] || return 1
  release_authorized_backup || return 1
  restore_authorized_dir_metadata "$dir_existed" || return 1
  return 0
}

# The held inode's extra NAME, removed once it is no longer the only one. This
# never removes content: either authorized_keys is that same inode (so the file
# survives under its real name), or the journal has already established that the
# transaction never mutated anything.
release_authorized_backup() {
  [ -e "$authorized_backup" ] || [ -L "$authorized_backup" ] || return 0
  rm -f -- "$authorized_backup" || return 1
  # The name is gone, or it is not: an unlink that reports success and leaves the
  # name is a leaked link to the operator's prior key bytes.
  [ ! -e "$authorized_backup" ] && [ ! -L "$authorized_backup" ]
}

# 🔴 EVERY FIELD IS REQUIRED, AND THE RESULT IS READ BACK (review 2026-09-02,
# P1 #3). A missing or malformed field used to `return 0` -- reported as a
# successful restoration of metadata that was never restored -- and the caller
# then deleted the journal.
restore_authorized_file_times() {
  local metadata restored
  metadata="$(journal_field file_metadata)" || return 1
  # shellcheck disable=SC2086 # deliberate split of the six recorded words
  set -- $metadata
  [ $# -eq 6 ] || return 1
  { [ -f "$authorized" ] && [ ! -L "$authorized" ]; } || return 1
  chmod "$1" -- "$authorized" || return 1
  chown "$2:$3" -- "$authorized" 2>/dev/null || [ -n "$ROOT" ] || return 1
  restore_times "$authorized" "$5" "$6" || return 1
  # 🔴 THE LINK COUNT IS PART OF THE FILE. A restored file whose link count does
  # not match the one recorded is a file whose external hard links were not
  # preserved -- which is the whole reason rollback renames the original inode
  # instead of copying its bytes.
  restored="$(path_metadata "$authorized")" || return 1
  # shellcheck disable=SC2086
  set -- $restored
  local restored_mode=$1 restored_uid=$2 restored_gid=$3 restored_nlink=$4
  local restored_mtime=$5 restored_atime=$6
  # shellcheck disable=SC2086
  set -- $metadata
  [ "$restored_mode" = "$1" ] || return 1
  if [ -z "$ROOT" ]; then
    [ "$restored_uid" = "$2" ] && [ "$restored_gid" = "$3" ] || return 1
  fi
  [ "$restored_nlink" = "$4" ] || return 1
  [ "$restored_mtime" = "$5" ] || return 1
  [ "$restored_atime" = "$6" ] || return 1
  return 0
}

# The attributes a rename preserves and a copy drops. Recorded before the
# transaction when the filesystem offers them; compared after it when they were
# recorded. An attribute that was available BEFORE and is unreadable AFTER is a
# refusal, not a shrug: it is exactly the state in which the operator's file has
# quietly lost something.
verify_authorized_preserved_attributes() {
  local recorded observed name
  for name in acl xattrs selinux; do
    recorded="$(journal_field "file_$name")" || continue
    case "$name" in
      acl)     observed="$(path_acl "$authorized")" || return 1 ;;
      xattrs)  observed="$(path_xattrs "$authorized")" || return 1 ;;
      selinux) observed="$(path_selinux "$authorized")" || return 1 ;;
    esac
    [ "$observed" = "$recorded" ] || return 1
  done
  return 0
}

# The inode itself, not merely its bytes. The journal records the identity of the
# file that was there before; after a rollback the name must resolve to THAT
# inode again.
verify_authorized_identity() {
  local recorded observed
  recorded="$(journal_field file_identity)" || return 1
  observed="$(path_identity "$authorized")" || return 1
  [ "$observed" = "$recorded" ]
}

# 🔴 A DIRECTORY IS STATE TOO. Adding and removing names in ~core/.ssh changes
# its mtime, and the previous revision changed it with nothing recording what it
# had been (review 2026-09-02, P2). If the directory did not exist beforehand it
# is removed again -- but only when it is empty, because a directory this gate
# created and something else then populated is not this gate's to delete.
restore_authorized_dir_metadata() { # $1=dir_existed
  if [ "${1:-1}" = 0 ]; then
    # A directory this gate created and something else then populated is not
    # this gate's to delete -- but a NON-EMPTY one it created is still a change
    # it made and could not undo, so it is reported rather than swallowed.
    [ -d "$authorized_dir" ] && [ ! -L "$authorized_dir" ] || return 0
    rmdir -- "$authorized_dir" 2>/dev/null && return 0
    [ -n "$(find "$authorized_dir" -mindepth 1 -print -quit 2>/dev/null)" ] || return 1
    note "the ~core/.ssh this transaction created is no longer empty; leaving it and keeping the journal"
    return 1
  fi
  { [ -d "$authorized_dir" ] && [ ! -L "$authorized_dir" ]; } || return 1
  local meta restored
  meta="$(journal_field dir_metadata)" || return 1
  # shellcheck disable=SC2086 # deliberate split of the six recorded words
  set -- $meta
  [ $# -eq 6 ] || return 1
  chmod "$1" -- "$authorized_dir" || return 1
  chown "$2:$3" -- "$authorized_dir" 2>/dev/null || [ -n "$ROOT" ] || return 1
  restore_times "$authorized_dir" "$5" "$6" || return 1
  # 🔴 THE PARENT IS STATE TOO, AND IT IS VERIFIED. Adding and removing names in
  # ~core/.ssh changes its mtime; restoring that and not checking it is the same
  # unverified claim the file's own metadata used to make.
  restored="$(path_metadata "$authorized_dir")" || return 1
  # shellcheck disable=SC2086
  set -- $restored
  local restored_mode=$1 restored_uid=$2 restored_gid=$3 restored_mtime=$5 restored_atime=$6
  # shellcheck disable=SC2086
  set -- $meta
  [ "$restored_mode" = "$1" ] || return 1
  if [ -z "$ROOT" ]; then
    [ "$restored_uid" = "$2" ] && [ "$restored_gid" = "$3" ] || return 1
  fi
  [ "$restored_mtime" = "$5" ] || return 1
  [ "$restored_atime" = "$6" ] || return 1
  return 0
}

# 🔴 THE JOURNAL OUTLIVES THE UNDO UNTIL THE UNDO IS ON THE DISK.
#
# WHAT THIS CLOSES (review 2026-09-02, P1 #2). Rollback restored or deleted
# authorized_keys and then removed the journal -- with neither the file nor its
# parent directory fsynced. /var/lib and /var/home can be different filesystems,
# and journal removal reaching stable storage while the ~core/.ssh unlink did not
# is a boot that comes up with the injected key still present and NO record that
# this gate put it there. The next boot then classifies that identical key as
# pre-existing (key_added=0), so rollback would deliberately never remove it
# again. The key would be permanent.
#
# The order below is the whole fix and it is structural, not commentary: the undo
# is made durable on the TARGET filesystem first, and only then does the journal
# stop existing on the STATE filesystem.
commit_rollback() {
  if [ -e "$authorized" ]; then
    fsync_path "$authorized"
  fi
  if [ -d "$authorized_dir" ]; then
    fsync_path "$authorized_dir"
  else
    fsync_path "$(dirname -- "$authorized_dir")"
  fi
  crash_seam rolled-back
  # 🔴 REPLACEMENT DETECTION. The journal removed here must be the directory this
  # boot pinned under the lock. A journal swapped between validation and removal
  # is one whose removal destroys evidence of a transaction this boot never made.
  if [ -d "$pending" ] && [ ! -L "$pending" ]; then
    local now
    now="$(path_identity "$pending")" || now=''
    if [ -n "$JOURNAL_IDENTITY" ] && [ "$now" != "$JOURNAL_IDENTITY" ]; then
      note "REFUSED: the SSH activation handoff was replaced since this boot validated it; keeping it for inspection"
      return 1
    fi
    require_custody "$pending" || {
      note "REFUSED: the SSH activation handoff is no longer root-custodied; keeping it for inspection"
      return 1
    }
  fi
  rm -rf -- "$pending"
  fsync_path "$STATE_DIR"
  return 0
}

# Restore the enablement state provisioning changed -- and only if it changed
# it. developer-diagnostic ships sshd enabled and unmasked; remasking it there
# would be this script inventing a posture nobody asked for.
rollback_sshd_enablement() { # $1=sshd_was_masked
  if [ "${1:-}" = 1 ]; then
    systemctl disable sshd.service 2>/dev/null || true
    systemctl mask sshd.service 2>/dev/null || true
    systemctl daemon-reload 2>/dev/null || true
  fi
  return 0
}

# The listener is closed even when the FILE cannot be classified: an unmasked
# sshd is the half of the posture that costs attack surface, and it is the half
# whose prior state is unambiguous. Report the file's verdict to the caller.
rollback_provisioning() { # $1=sshd_was_masked
  local rc=0
  rollback_authorized_keys || rc=1
  rollback_sshd_enablement "${1:-}"
  return "$rc"
}

# 🔴 WHAT A SUCCESSFUL TRANSACTION STILL OWES (review 2026-09-02, P1 #4).
#
#   release   the hard-link backup is unlinked. It is a second NAME for the
#             operator's PRIOR file; the new authorized_keys is a different
#             inode, so this removes no content that authorized_keys refers to.
#   prove     the link counts are what the journal says they must now be: the
#             file this boot published has exactly one name, and the prior inode
#             has exactly the number it had before this transaction MINUS the one
#             name (`authorized_keys`) that this transaction took from it. Any
#             external hard links the operator had are untouched, which is the
#             property the whole hard-link design exists to preserve.
#   durable   both the file and its parent directory reach stable storage before
#             the journal is removed.
#
# key_added=0 transactions took no backup and wrote nothing, so they owe nothing.
finish_successful_transaction() {
  local key_added authorized_existed before_meta before_nlink prior_nlink now_nlink
  key_added="$(journal_flag key_added)" || return 1
  authorized_existed="$(journal_flag authorized_existed)" || return 1
  if [ "$key_added" = 0 ]; then
    # Nothing was written and nothing was held. The file on disk is the
    # operator's own, byte for byte, and this gate must not touch it.
    return 0
  fi

  if [ "$authorized_existed" = 1 ]; then
    before_meta="$(journal_field file_metadata)" || return 1
    # shellcheck disable=SC2086 # deliberate split of the six recorded words
    set -- $before_meta
    [ $# -eq 6 ] || return 1
    before_nlink=$4
    [ -f "$authorized_backup" ] && [ ! -L "$authorized_backup" ] || return 1
    prior_nlink="$(stat -c '%h' -- "$authorized_backup")" || return 1
    # Before the release: the prior inode carries its original names plus the
    # backup, minus `authorized_keys`, which the publish rename took away.
    [ "$prior_nlink" = "$before_nlink" ] || return 1
    release_authorized_backup || return 1
  else
    # There was no prior file, so there is no backup -- and a name of that shape
    # existing anyway is a stray this gate must not leave behind.
    release_authorized_backup || return 1
  fi

  { [ -f "$authorized" ] && [ ! -L "$authorized" ]; } || return 1
  now_nlink="$(stat -c '%h' -- "$authorized")" || return 1
  [ "$now_nlink" = 1 ] || return 1

  fsync_path "$authorized"
  fsync_path "$authorized_dir"
  return 0
}

activate() {
  if [ ! -d "$pending" ]; then
    # Provisioning staged nothing: it refused, it was given no key, or this is
    # not a first boot. Activation has nothing to activate. (The unit carries
    # the same test as ConditionPathExists; this is the script refusing to
    # depend on the unit file being right.)
    exit 0
  fi
  lock_provisioning
  # The same recheck, for the same reason: a waiter that observed a handoff
  # before blocking must not act on it after another process has completed the
  # transaction, published the marker and removed the journal.
  if [ -e "$marker" ]; then
    note "another activation completed while this one waited for the lock; nothing to do"
    exit 0
  fi
  { [ -d "$pending" ] && [ ! -L "$pending" ]; } || exit 0
  if ! require_custody "$pending"; then
    note "REFUSED: the SSH activation handoff is not root-custodied; leaving it for inspection rather than acting on it"
    exit 1
  fi
  pin_journal_identity

  local schema policy key_sha256 fingerprint sshd_was_masked
  if ! schema="$(journal_field schema)" \
    || [ "$schema" != "$JOURNAL_SCHEMA" ] \
    || ! policy="$(journal_field policy)" \
    || ! key_sha256="$(journal_field key_sha256)" \
    || ! fingerprint="$(journal_field fingerprint)" \
    || ! sshd_was_masked="$(journal_flag sshd_was_masked)"; then
    # Nothing here may be defaulted: every field says what provisioning already
    # did. Leave the handoff and the marker alone so the next boot replays it
    # under the same lock instead of this boot inventing a state.
    note "REFUSED: the SSH activation handoff is incomplete or unreadable; leaving it for the next boot to replay"
    exit 1
  fi

  # --no-block, kept even though this unit is ordered AFTER sshd and a blocking
  # start would no longer deadlock. A queued start plus an assertion on the
  # EFFECT is never weaker than a blocking start, and it cannot reintroduce the
  # GB10 2026-08-20 hang if this unit's ordering is ever edited again.
  systemctl start --no-block sshd.service 2>/dev/null || true

  # ASSERT THE EFFECT, NOT THE COMMAND. Every step above can return 0 while
  # leaving sshd down, and a medium whose whole purpose is remote lab access
  # must not report success in that state. Unlike the pre-split unit, this poll
  # can actually succeed: nothing orders sshd after this service.
  local waited=0
  while [ "$(systemctl is-active sshd.service 2>/dev/null)" != active ] \
    && [ "$waited" -lt "$SSHD_TIMEOUT" ]; do
    sleep 1
    waited=$((waited + 1))
  done

  if [ "$(systemctl is-active sshd.service 2>/dev/null)" = active ]; then
    note "sshd is active; the provisioned operator key is usable (policy=${policy}, ${fingerprint})"
    # 🔴 SUCCESS HAS A CLEANUP, AND IT USED TO BE MISSING (independent review
    # 2026-09-02, P1 #4).
    #
    # A pre-existing authorized_keys is held across the transaction as a HARD
    # LINK named `.neural-ice-authorized_keys.backup`. Rollback renames that name
    # back; SUCCESS never touched it. So on every successful provisioning of an
    # appliance that already had an operator key, the old key BYTES stayed on
    # disk under a second name, the old inode stayed reachable, and its link
    # count never returned to its pre-transaction value. The existing success
    # tests started from no prior file, so none of them could see it.
    #
    # The order is the same one rollback uses and for the same reason: the undo
    # -- here, the release -- is made durable on the TARGET filesystem before the
    # only record of the transaction stops existing on the STATE filesystem.
    if ! finish_successful_transaction; then
      note "REFUSED: the operator key is served, but this transaction could not release its hard-link backup or prove the resulting link count; keeping the journal (see ${pending}/RECOVERY)"
      write_receipt "$policy" true provisioned-cleanup-failed "$key_sha256" "$fingerprint"
      exit 1
    fi
    write_receipt "$policy" true provisioned "$key_sha256" "$fingerprint"
    # The marker is written HERE and only here: after proof, never before it.
    : > "$marker"
    fsync_path "$marker"
    # There is nothing to undo, so the journal has done its job -- but the same
    # ordering applies: the authorized_keys this boot wrote is made durable
    # before the only record of having written it is removed.
    commit_rollback || exit 1
    exit 0
  fi

  # The key is on disk and sshd is NOT serving it. Do not leave the appliance in
  # that state: an unmasked sshd and an unused authorized_keys is strictly more
  # attack surface than the sealed posture it replaced, for zero access. Undo
  # both, record it honestly, and leave the marker unwritten so the next boot
  # retries from the karg rather than inheriting a silent half-open appliance.
  note "WARNING: sshd is NOT active after ${SSHD_TIMEOUT}s — rolling the operator key provisioning back"
  if ! rollback_provisioning "$sshd_was_masked"; then
    # sshd enablement HAS been restored; authorized_keys has not, because it
    # matches neither image this transaction journalled. Say exactly that, and
    # KEEP the handoff: it is the only record of what this boot changed, and
    # deleting it would report a rollback that did not happen.
    note "REFUSED: sshd is not active AND the operator key provisioning could not be rolled back — authorized_keys matches neither journalled image; the handoff is kept for the next boot (see ${pending}/RECOVERY)"
    write_receipt "$policy" false activation-failed-rollback-refused "$key_sha256" "$fingerprint"
    exit 1
  fi
  write_receipt "$policy" false activation-failed-rolled-back "$key_sha256" "$fingerprint"
  commit_rollback || note "the rollback completed but its journal could not be retired; it is kept for inspection"
  note "removed the provisioned operator key and restored the sshd enablement state"
  exit 1
}

case "${1:-}" in
  provision) provision ;;
  activate)  activate ;;
  *)
    echo "usage: $0 {provision|activate}" >&2
    exit 2
    ;;
esac
