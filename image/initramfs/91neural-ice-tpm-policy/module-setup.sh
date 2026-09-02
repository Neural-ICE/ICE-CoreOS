#!/bin/sh
# shellcheck disable=SC2154 # dracut defines moddir before sourcing module-setup.sh
check() { return 0; }
depends() { echo crypt; }
install() {
  inst_multiple mount umount sha256sum awk cp chmod mkdir dirname tr od wc \
    tpm2_nvreadpublic tpm2_nvread
  inst_simple "$moddir/tpm2-nv-public.sh" /lib/neural-ice-tpm2-nv-public.sh
  inst_hook pre-trigger 01 "$moddir/neural-ice-tpm-policy.sh"
}
