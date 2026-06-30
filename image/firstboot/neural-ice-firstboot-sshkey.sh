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
set -euo pipefail

marker=/var/lib/neural-ice/.sshkey-provisioned
[ -e "$marker" ] && exit 0
install -d -m 0755 /var/lib/neural-ice

key=""
if grep -qE 'neuralice\.sshkey=' /proc/cmdline; then
  key="$(sed -n 's/.*neuralice\.sshkey=\([^ ]*\).*/\1/p' /proc/cmdline | base64 -d 2>/dev/null || true)"
fi

if [ -n "$key" ]; then
  install -d -m 0700 /var/home/core/.ssh
  printf '%s\n' "$key" >> /var/home/core/.ssh/authorized_keys
  sort -u -o /var/home/core/.ssh/authorized_keys /var/home/core/.ssh/authorized_keys
  chmod 0600 /var/home/core/.ssh/authorized_keys
  chown -R core:core /var/home/core/.ssh
  logger -t neural-ice-firstboot "provisioned operator SSH key for 'core'"
fi

: > "$marker"
