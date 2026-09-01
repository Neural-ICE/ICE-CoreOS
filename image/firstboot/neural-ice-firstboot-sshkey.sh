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

# Test seams. All default to the real system, so the installed units are
# unaffected; the suite sets them to exercise this file rather than a copy of
# its logic -- a test that reimplements the script proves nothing about it.
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
scratch="$ROOT/run/neural-ice-firstboot"
authorized_dir="$ROOT/var/home/core/.ssh"
authorized="$authorized_dir/authorized_keys"

note() { logger -t neural-ice-firstboot "$*" || true; }

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
  install -d -m 0755 "$STATE_DIR"
  # A handoff left by an earlier boot whose activation never completed is stale
  # by definition: this boot re-decides from the karg, from scratch.
  rm -rf "$pending"

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

  # Append rather than replace, and de-duplicate: the community path can have
  # placed a key here through Ignition, and destroying it would be a regression
  # unrelated to anything this gate is about. "Exactly one key" is a constraint
  # on what the MEDIUM may supply -- enforced above -- not on the file's
  # contents. The rollback in phase 2 is the same promise read backwards: it
  # removes this record and nothing else.
  install -d -m 0700 "$authorized_dir"
  cat "$candidate" >> "$authorized"
  sort -u -o "$authorized" "$authorized"
  chmod 0600 "$authorized"
  chown -R core:core "$authorized_dir" 2>/dev/null || [ -n "$ROOT" ]
  note "provisioned operator SSH key for 'core' (policy=${policy}, ${fingerprint})"

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
  local sshd_was_masked=0
  if [ "$(systemctl is-enabled sshd.service 2>/dev/null)" = masked ]; then
    sshd_was_masked=1
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
  install -d -m 0700 "$pending"
  install -m 0600 "$candidate" "$pending/key.pub"
  ( umask 077
    printf '%s\n' "$policy"          > "$pending/policy"
    printf '%s\n' "$key_sha256"      > "$pending/key_sha256"
    printf '%s\n' "$fingerprint"     > "$pending/fingerprint"
    printf '%s\n' "$sshd_was_masked" > "$pending/sshd_was_masked" )
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

# Undo exactly what provisioning did, and nothing else.
rollback_provisioning() { # $1=sshd_was_masked
  local sshd_was_masked=$1

  # Remove precisely the record provisioning appended. A blanket truncate would
  # also destroy an Ignition-placed community key that was here first and had
  # nothing to do with this decision.
  if [ -f "$authorized" ]; then
    local remaining
    remaining="$(grep -vxF -f "$pending/key.pub" "$authorized" || true)"
    if [ -n "$(printf '%s' "$remaining" | tr -d '[:space:]')" ]; then
      printf '%s\n' "$remaining" > "$authorized"
      chmod 0600 "$authorized"
    else
      rm -f "$authorized"
    fi
  fi

  # Restore the enablement state provisioning changed -- and only if it changed
  # it. developer-diagnostic ships sshd enabled and unmasked; remasking it there
  # would be this script inventing a posture nobody asked for.
  if [ "$sshd_was_masked" = 1 ]; then
    systemctl disable sshd.service 2>/dev/null || true
    systemctl mask sshd.service 2>/dev/null || true
    systemctl daemon-reload 2>/dev/null || true
  fi
}

activate() {
  if [ ! -d "$pending" ]; then
    # Provisioning staged nothing: it refused, it was given no key, or this is
    # not a first boot. Activation has nothing to activate. (The unit carries
    # the same test as ConditionPathExists; this is the script refusing to
    # depend on the unit file being right.)
    exit 0
  fi

  local policy key_sha256 fingerprint sshd_was_masked
  policy="$(cat "$pending/policy")"
  key_sha256="$(cat "$pending/key_sha256")"
  fingerprint="$(cat "$pending/fingerprint")"
  sshd_was_masked="$(cat "$pending/sshd_was_masked")"

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
    write_receipt "$policy" true provisioned "$key_sha256" "$fingerprint"
    # The marker is written HERE and only here: after proof, never before it.
    : > "$marker"
    rm -rf "$pending"
    exit 0
  fi

  # The key is on disk and sshd is NOT serving it. Do not leave the appliance in
  # that state: an unmasked sshd and an unused authorized_keys is strictly more
  # attack surface than the sealed posture it replaced, for zero access. Undo
  # both, record it honestly, and leave the marker unwritten so the next boot
  # retries from the karg rather than inheriting a silent half-open appliance.
  note "WARNING: sshd is NOT active after ${SSHD_TIMEOUT}s — rolling the operator key provisioning back"
  rollback_provisioning "$sshd_was_masked"
  write_receipt "$policy" false activation-failed-rolled-back "$key_sha256" "$fingerprint"
  rm -rf "$pending"
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
