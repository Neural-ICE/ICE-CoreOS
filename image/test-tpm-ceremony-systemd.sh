#!/usr/bin/env bash
# Offline proof that every image-enabled readiness/listener/root-extension path
# has a failure-propagating dependency on the TPM ceremony success gate.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CF="$ROOT/image/Containerfile.bootc"
DROPIN="$ROOT/image/firstboot/50-neural-ice-tpm-ceremony-sshd.conf"
UNIT="$ROOT/image/firstboot/neural-ice-firstboot-tpm-ceremony.service"
fail() { echo "FAIL: $*" >&2; exit 1; }

grep -qx 'Requires=neural-ice-firstboot-tpm-ceremony.service' "$DROPIN" || fail "gate drop-in has no hard Requires edge"
grep -qx 'After=neural-ice-firstboot-tpm-ceremony.service' "$DROPIN" || fail "gate drop-in has no ordering edge"
grep -qx 'OnFailure=emergency.target' "$UNIT" || fail "ceremony failure does not enter recovery"
grep -qx 'OnFailureJobMode=isolate' "$UNIT" || fail "ceremony failure does not isolate recovery"
grep -qx 'RequiredBy=multi-user.target' "$UNIT" || fail "multi-user readiness does not require ceremony success"

dropin_units=(
  sshd.service sshd.socket getty@.service serial-getty@.service autovt@.service
  network-pre.target network.target network-online.target NetworkManager.service
  NetworkManager-wait-online.service avahi-daemon.service avahi-daemon.socket
  systemd-user-sessions.service user@.service neural-ice-payload-apply.service
  neural-ice-hostname-init.service neural-ice-dhcp-retry.service
  nvidia-device-nodes.service nvidia-cdi-generate.service
  neural-ice-device-root.service bootc-fetch-apply-updates.service
  bootc-fetch-apply-updates.timer systemd-sysext.service systemd-confext.service
)
for unit in "${dropin_units[@]}"; do
  destination="/usr/lib/systemd/system/$unit.d/50-neural-ice-tpm-ceremony.conf"
  grep -Fq "COPY image/firstboot/50-neural-ice-tpm-ceremony-sshd.conf $destination" "$CF" \
    || fail "$unit has no immutable hard-gate drop-in"
done

# These image-enabled firstboot units carry the dependency in their source so
# the proof covers the exact bytes systemd loads, not just the build recipe.
for source in \
  "$ROOT/image/firstboot/neural-ice-firstboot-sshkey.service" \
  "$ROOT/image/firstboot/neural-ice-firstboot-sshkey-activate.service" \
  "$ROOT/image/bootc-overlay/usr/lib/systemd/system/neural-ice-device-root.service"; do
  grep -Fq 'Requires=neural-ice-firstboot-tpm-ceremony.service' "$source" \
    || fail "$(basename "$source") lacks its hard ceremony edge"
done

# Guard the enabled set itself: adding a root-capable image unit without adding
# it to the gate list must make this suite fail during review.
enable_block="$(sed -n '/systemctl enable nvidia-device-nodes.service/,/avahi-daemon.service;/p' "$CF")"
for enabled in nvidia-device-nodes.service nvidia-cdi-generate.service \
  neural-ice-firstboot-sshkey.service neural-ice-firstboot-sshkey-activate.service \
  neural-ice-hostname-init.service neural-ice-payload-apply.service avahi-daemon.service; do
  grep -Fq "$enabled" <<<"$enable_block" || fail "$enabled disappeared from the audited enabled set"
  if [[ "$enabled" != neural-ice-firstboot-sshkey.service && "$enabled" != neural-ice-firstboot-sshkey-activate.service ]]; then
    printf '%s\n' "${dropin_units[@]}" | grep -qx "$enabled" || fail "$enabled is enabled but not hard-gated"
  fi
done

echo "TPM_CEREMONY_SYSTEMD_OFFLINE_TEST_OK (${#dropin_units[@]} direct consumers plus firstboot chain)"
