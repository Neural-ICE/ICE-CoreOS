#!/usr/bin/env bash
#
# First-boot provisioning of the operator SSH key for the 'core' user.
#
# The vanilla public image bakes no key. The installer can inject one at install
# time by adding a kernel argument `neuralice.sshkey=<base64-of-authorized_keys>`
# to the installed system; this service decodes it on first boot and writes it to
# ~core/.ssh/authorized_keys (which the sshd config already honors). A build that
# bakes a key (SSH_AUTHORIZED_KEY build-arg) simply has no karg and this is a no-op.
#
# A provisioned key also UNMASKS sshd, because every non-debug variant ships it
# masked. Without that, the operator's key lands on a sealed image and nothing
# listens. This is what lets customers and Neural ICE run the SAME sealed image:
# the difference is a key on the installation medium, not a build variant.
#
set -euo pipefail

# Test seams. Both default to the real system, so the installed unit is
# unaffected; the suite sets them to exercise this file rather than a copy of
# its logic -- a test that reimplements the script proves nothing about it.
ROOT="${NEURALICE_FIRSTBOOT_ROOT:-}"
CMDLINE="${NEURALICE_FIRSTBOOT_CMDLINE:-/proc/cmdline}"

marker="$ROOT/var/lib/neural-ice/.sshkey-provisioned"
[ -e "$marker" ] && exit 0
install -d -m 0755 "$ROOT/var/lib/neural-ice"

key=""
if grep -qE 'neuralice\.sshkey=' "$CMDLINE"; then
  key="$(sed -n 's/.*neuralice\.sshkey=\([^ ]*\).*/\1/p' "$CMDLINE" | base64 -d 2>/dev/null || true)"
fi

if [ -n "$key" ]; then
  install -d -m 0700 "$ROOT/var/home/core/.ssh"
  printf '%s\n' "$key" >> "$ROOT/var/home/core/.ssh/authorized_keys"
  sort -u -o "$ROOT/var/home/core/.ssh/authorized_keys" "$ROOT/var/home/core/.ssh/authorized_keys"
  chmod 0600 "$ROOT/var/home/core/.ssh/authorized_keys"
  chown -R core:core "$ROOT/var/home/core/.ssh" 2>/dev/null || [ -n "$ROOT" ]
  logger -t neural-ice-firstboot "provisioned operator SSH key for 'core'"

  # Every non-debug variant masks sshd (Containerfile.bootc, ADR-0003), so on a
  # sealed image the whole chain above lands a key that NOTHING serves: the
  # operator drops authorized_keys on the installer ESP, the autoinstaller turns
  # it into the karg, this service writes it -- and the port stays shut. That is
  # the half that supplies, finished, behind a half that demands.
  #
  # Unmasking HERE and only HERE is what keeps one image for customers and for
  # us: the shipped bytes stay sealed and keyless, and the privilege travels on
  # the physical installation medium. A customer appliance carries no key, takes
  # no karg, and never reaches this branch -- sshd stays masked on it.
  if [ "$(systemctl is-enabled sshd.service 2>/dev/null)" = masked ]; then
    systemctl unmask sshd.service
    logger -t neural-ice-firstboot "unmasked sshd: an operator key was provisioned by the installation medium"
  fi
  systemctl enable --now sshd.service || \
    logger -t neural-ice-firstboot "WARNING: sshd could not be started; the provisioned key is unusable"
fi

: > "$marker"
