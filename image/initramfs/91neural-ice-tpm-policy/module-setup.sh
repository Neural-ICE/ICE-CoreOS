#!/bin/sh
# shellcheck disable=SC2154 # dracut defines moddir before sourcing module-setup.sh
check() { return 0; }
depends() { echo crypt; }
install() {
  inst_multiple mount umount sha256sum awk blkid cp chmod mkdir dirname tr od wc udevadm sleep \
    tpm2_getcap tpm2_nvreadpublic tpm2_nvread
  inst_simple "$moddir/tpm2-nv-public.sh" /lib/neural-ice-tpm2-nv-public.sh
  if [ -f "$moddir/installer-media" ]; then
    inst_simple "$moddir/installer-media" /etc/neural-ice/installer-media
  fi
  inst_simple "$moddir/neural-ice-tpm-policy.service" \
    /usr/lib/systemd/system/neural-ice-tpm-policy.service
  inst_dir /etc/systemd/system/systemd-cryptsetup@.service.d
  inst_simple "$moddir/systemd-cryptsetup-policy.conf" \
    /etc/systemd/system/systemd-cryptsetup@.service.d/10-neural-ice-policy.conf
  mkdir -p "$initdir/etc/systemd/system/cryptsetup-pre.target.requires"
  ln -sfn /usr/lib/systemd/system/neural-ice-tpm-policy.service \
    "$initdir/etc/systemd/system/cryptsetup-pre.target.requires/neural-ice-tpm-policy.service"
  inst_hook pre-trigger 01 "$moddir/neural-ice-tpm-policy.sh"
}
