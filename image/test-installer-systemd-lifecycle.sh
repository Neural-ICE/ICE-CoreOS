#!/usr/bin/env bash
# Offline proof of the split lifecycle between the signed live installer and
# the installed appliance.  No host manager is modified and no TPM is opened.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GENERATOR="$ROOT/image/installer/neural-ice-installer-runtime-generator.sh"
TARGET="$ROOT/image/installer/neural-ice-installer.target"
AUTOINSTALL_UNIT="$ROOT/ota/neural-ice-autoinstall.service"
INSTALLER_CF="$ROOT/image/Containerfile.installer"
APPLIANCE_CF="$ROOT/image/Containerfile.bootc"
CEREMONY_UNIT="$ROOT/image/firstboot/neural-ice-firstboot-tpm-ceremony.service"
GATE_TEST="$ROOT/image/test-tpm-ceremony-systemd.sh"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/ni-installer-systemd.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

chmod 0755 "$TMP"
run_generator() { # $1=cmdline $2=output-root [--check]
  local cmdline=$1 output=$2 mode=${3:-generate}
  install -d -m 0755 "$output/normal" "$output/early" "$output/late"
  printf '%s\n' "$cmdline" > "$output/cmdline"
  chmod -R a+rX "$output"
  local -a command=(env NI_INSTALLER_GENERATOR_TESTING=1
    NI_INSTALLER_GENERATOR_TEST_CMDLINE="$output/cmdline" "$GENERATOR")
  if [[ "$mode" == --check ]]; then
    command+=(--check)
  else
    command+=("$output/normal" "$output/early" "$output/late")
  fi
  if (( EUID == 0 )); then
    chown -R nobody:nogroup "$output" 2>/dev/null || chown -R nobody:nobody "$output"
    runuser -u nobody -- "${command[@]}"
  else
    "${command[@]}"
  fi
}

install_cmdline='quiet systemd.unit=neural-ice-installer.target neuralice.autoinstall=1 enforcing=0'
run_generator "$install_cmdline" "$TMP/install"
run_generator "$install_cmdline" "$TMP/check" --check

masked_units=(
  neural-ice-firstboot-tpm-ceremony.service
  neural-ice-firstboot-sshkey.service neural-ice-firstboot-sshkey-activate.service
  neural-ice-payload-apply.service neural-ice-hostname-init.service
  neural-ice-dhcp-retry.service neural-ice-device-root.service
  nvidia-device-nodes.service nvidia-cdi-generate.service
  avahi-daemon.service avahi-daemon.socket sshd.service sshd.socket
  getty@.service serial-getty@.service autovt@.service
  systemd-user-sessions.service user@.service
  bootc-fetch-apply-updates.service bootc-fetch-apply-updates.timer
  systemd-sysext.service systemd-confext.service
)
for unit in "${masked_units[@]}"; do
  [[ -L "$TMP/install/early/$unit" && "$(readlink "$TMP/install/early/$unit")" == /dev/null ]] \
    || fail "installer mode did not transiently mask $unit"
done
[[ ! -e "$TMP/install/early/NetworkManager.service" ]] \
  || fail "the registry install's network dependency was masked"

# Closed list shared with the installed-appliance dependency proof: exactly the
# 24 consumers reviewed for runtime/SSH/OTA readiness.  Five network units are
# suppressed by the dedicated target rather than masked because registry-mode
# autoinstall may legitimately activate networking as its own dependency.
consumer_units=(
  sshd.service sshd.socket getty@.service serial-getty@.service autovt@.service
  network-pre.target network.target network-online.target NetworkManager.service
  NetworkManager-wait-online.service avahi-daemon.service avahi-daemon.socket
  systemd-user-sessions.service user@.service neural-ice-payload-apply.service
  neural-ice-hostname-init.service neural-ice-dhcp-retry.service
  nvidia-device-nodes.service nvidia-cdi-generate.service
  neural-ice-device-root.service bootc-fetch-apply-updates.service
  bootc-fetch-apply-updates.timer systemd-sysext.service systemd-confext.service
)
[[ "${#consumer_units[@]}" == 24 ]] || fail "the audited installed consumer set is no longer 24"
for network_unit in network-pre.target network.target network-online.target \
  NetworkManager.service NetworkManager-wait-online.service; do
  grep -Eq "^(Requires|Wants)=.*${network_unit//./\\.}" "$TARGET" \
    && fail "the installer target directly pulls installed consumer $network_unit"
done

# Installed boot has neither installer selector.  The installer image may be
# the source deployment, so zero generated masks is the decisive proof that the
# first installed boot retains the appliance ceremony and its 24+ consumers.
run_generator 'quiet rd.luks=1' "$TMP/installed"
[[ -z "$(find "$TMP/installed/early" -mindepth 1 -print -quit)" ]] \
  || fail "installer-only masks leaked into the installed boot"
run_generator 'quiet neuralice.autoinstall=1' "$TMP/partial" || true
for target in default.target multi-user.target graphical.target; do
  [[ -L "$TMP/partial/early/$target" ]] \
    || fail "a partial installer selector can fall through to $target"
done
run_generator 'quiet neuralice.autoinstall=1' "$TMP/partial-check" --check >/dev/null 2>&1 \
  && fail "a partial installer selector passed executable preflight"
run_generator 'quiet systemd.unit=neural-ice-installer.target neuralice.autoinstall=1 neuralice.autoinstall=1' \
  "$TMP/duplicate-check" --check >/dev/null 2>&1 \
  && fail "a duplicated installer selector passed executable preflight"

# Dependency semantics: the signed target hard-requires autoinstall, and the
# service fails/isolate rather than Condition-skipping when the selector or its
# target inputs are absent.  It is not attached to basic/multi-user.
grep -Eq '^Requires=.*neural-ice-autoinstall\.service' "$TARGET" \
  || fail "the installer target does not require autoinstall success"
grep -Eq '^After=.*neural-ice-autoinstall\.service' "$TARGET" \
  || fail "the installer target can become active before autoinstall completes"
grep -qx 'ExecStartPre=/usr/lib/systemd/system-generators/neural-ice-installer-runtime-generator --check' "$AUTOINSTALL_UNIT" \
  || fail "autoinstall has no executable signed-cmdline preflight"
grep -qx 'OnFailure=emergency.target' "$AUTOINSTALL_UNIT" \
  || fail "autoinstall failure does not enter recovery"
grep -qx 'OnFailureJobMode=isolate' "$AUTOINSTALL_UNIT" \
  || fail "autoinstall failure does not isolate recovery"
grep -q '^ConditionKernelCommandLine=' "$AUTOINSTALL_UNIT" \
  && fail "autoinstall can be condition-skipped instead of failing its target"
grep -Eq '^(WantedBy|RequiredBy)=(basic|multi-user)\.target' "$AUTOINSTALL_UNIT" \
  && fail "autoinstall is still inherited by a general-purpose target"
if command -v systemd-analyze >/dev/null 2>&1; then
  # The source Exec paths exist only inside the composed installer image.  Feed
  # systemd the exact units with only Exec*= replaced by /bin/true; the source
  # paths were asserted above, while the native parser now checks the real unit
  # directives and dependency graph without requiring a composed rootfs.
  install -d "$TMP/verify-units"
  cp "$TARGET" "$TMP/verify-units/neural-ice-installer.target"
  sed -E 's#^(ExecStartPre|ExecStart)=.*#\1=/bin/true#' "$AUTOINSTALL_UNIT" \
    > "$TMP/verify-units/neural-ice-autoinstall.service"
  if ! SYSTEMD_UNIT_PATH="$TMP/verify-units:/usr/lib/systemd/system:/lib/systemd/system" \
    systemd-analyze verify "$TMP/verify-units/neural-ice-installer.target" \
      "$TMP/verify-units/neural-ice-autoinstall.service" 2>"$TMP/systemd-verify.err"; then
    # Ubuntu 26.04's verifier needs userdb ancillary-data socket options that
    # the repository sandbox denies.  Only that exact environment refusal may
    # defer the native parser; every other diagnostic is a unit failure.
    if [[ "$(wc -l < "$TMP/systemd-verify.err")" == 2 ]] \
      && grep -Fq 'Failed to turn off SO_PASSRIGHTS on user lookup socket' "$TMP/systemd-verify.err" \
      && grep -Fq 'Failed to enable SO_PASSCRED on handoff timestamp socket' "$TMP/systemd-verify.err"; then
      echo "  (systemd-analyze verify unavailable: sandbox denies userdb socket options)" >&2
    else
      cat "$TMP/systemd-verify.err" >&2
      fail "systemd rejected the offline installer unit graph"
    fi
  fi
fi

# Image-layer split: installer files are present, but no persistent ceremony
# mask/disable/default-target mutation is baked.  The appliance layer remains
# the sole source of the multi-user enablement used on first installed boot.
for source in neural-ice-installer.target neural-ice-installer-runtime-generator.sh; do
  grep -Fq "image/installer/$source" "$INSTALLER_CF" \
    || fail "the installer image does not contain $source"
done
grep -Fq 'systemctl enable neural-ice-autoinstall.service' "$INSTALLER_CF" \
  || fail "the installer image does not attach autoinstall to its dedicated target"
grep -Eq 'systemctl (mask|disable).*neural-ice-firstboot-tpm-ceremony' "$INSTALLER_CF" \
  && fail "the installer layer persistently weakens the installed ceremony"
grep -Fq 'neural-ice-firstboot-tpm-ceremony.service' "$APPLIANCE_CF" \
  || fail "the installed appliance no longer enables its mandatory ceremony"
grep -qx 'RequiredBy=multi-user.target' "$CEREMONY_UNIT" \
  || fail "the installed target no longer hard-requires ceremony success"

# Missing installed inputs make the ceremony fail; its isolated failure and all
# consumer Requires edges are checked by the existing closed-world gate suite.
bash "$GATE_TEST" >/dev/null

echo "INSTALLER_SYSTEMD_LIFECYCLE_TEST_OK (${#consumer_units[@]} consumers suppressed; ${#masked_units[@]} transient masks; installed boot emits none)"
