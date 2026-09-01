#!/usr/bin/env bash
# Installer-image-only systemd generator.  The signed UKI selects the dedicated
# target; this generator prevents inherited appliance/listener units from being
# started manually or through an unexpected dependency while that target runs.
# It writes only below /run, so none of these masks can reach the installed OS.
set -euo pipefail

die() { printf 'neural-ice-installer-runtime-generator: refused: %s\n' "$*" >&2; exit 1; }

if [[ -n "${NI_INSTALLER_GENERATOR_TESTING:-}" ]]; then
  [[ "$NI_INSTALLER_GENERATOR_TESTING" == 1 && "$EUID" -ne 0 ]] \
    || die "test overrides are forbidden in a privileged process"
  readonly CMDLINE_FILE="${NI_INSTALLER_GENERATOR_TEST_CMDLINE:?}"
else
  readonly CMDLINE_FILE=/proc/cmdline
fi

count_word() { # $1=exact kernel-command-line word
  awk -v wanted="$1" 'BEGIN{n=0}{for(i=1;i<=NF;i++) if($i==wanted)n++}END{print n+0}' \
    "$CMDLINE_FILE"
}

count_key() { # $1=kernel-command-line key
  awk -v prefix="$1=" 'BEGIN{n=0}{for(i=1;i<=NF;i++) if(index($i,prefix)==1)n++}END{print n+0}' \
    "$CMDLINE_FILE"
}

exact_install_cmdline() {
  [[ "$(count_key neuralice.autoinstall)" == 1 \
    && "$(count_word neuralice.autoinstall=1)" == 1 \
    && "$(count_key systemd.unit)" == 1 \
    && "$(count_word systemd.unit=neural-ice-installer.target)" == 1 ]]
}

installer_hint_present() {
  (( $(count_key neuralice.autoinstall) > 0 )) \
    || (( $(count_word systemd.unit=neural-ice-installer.target) > 0 ))
}

if [[ "${1:-}" == --check ]]; then
  exact_install_cmdline \
    || die "the signed command line must contain exactly neuralice.autoinstall=1 and systemd.unit=neural-ice-installer.target"
  exit 0
fi

# No installer selector on an installed appliance: emit nothing.  This is the
# property that keeps the inherited ceremony enabled for first installed boot.
installer_hint_present || exit 0

(( $# >= 2 )) || die "systemd did not provide normal and early generator directories"
readonly EARLY_DIR="$2"
[[ "$EARLY_DIR" == /* ]] || die "the early generator directory is not absolute"
install -d -m 0755 "$EARLY_DIR"

# NetworkManager and the network targets are deliberately not masked: a
# digest-pinned registry install may need them.  They are not pulled by the
# dedicated target itself.  Everything below is an appliance runtime,
# listener/session surface, OTA path, or root-capable extension mechanism.
readonly -a MASKED_UNITS=(
  neural-ice-firstboot-tpm-ceremony.service
  neural-ice-firstboot-sshkey.service
  neural-ice-firstboot-sshkey-activate.service
  neural-ice-payload-apply.service
  neural-ice-hostname-init.service
  neural-ice-dhcp-retry.service
  neural-ice-device-root.service
  nvidia-device-nodes.service
  nvidia-cdi-generate.service
  avahi-daemon.service
  avahi-daemon.socket
  sshd.service
  sshd.socket
  getty@.service
  serial-getty@.service
  autovt@.service
  systemd-user-sessions.service
  user@.service
  bootc-fetch-apply-updates.service
  bootc-fetch-apply-updates.timer
  systemd-sysext.service
  systemd-confext.service
)
for unit in "${MASKED_UNITS[@]}"; do
  ln -sfn /dev/null "$EARLY_DIR/$unit"
done

# A partial/duplicated selector is never allowed to fall through to an
# appliance target.  The preflight below will fail the proper installer target;
# masking the general targets also makes malformed alternate selections fail.
if ! exact_install_cmdline; then
  for unit in default.target multi-user.target graphical.target; do
    ln -sfn /dev/null "$EARLY_DIR/$unit"
  done
fi
