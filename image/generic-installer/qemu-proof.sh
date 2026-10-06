#!/bin/bash
# QEMU proof of a generic installer medium (ADR-0044): AAVMF (no Secure Boot yet) + swtpm + KVM, the medium
# attached read-only. Prints the installer's verdict line. Usage (root, for /dev/kvm): qemu-proof.sh IMG LOG
set -u
IMG="${1:?image}"; LOG="${2:?log}"; R="$(mktemp -d /tmp/ni-geninst-q.XXXXXX)"   # swtpm's AppArmor profile allows /tmp
cp /usr/share/AAVMF/AAVMF_VARS.fd "$R/vars.fd"
swtpm socket --tpm2 --tpmstate dir="$R" --ctrl type=unixio,path="$R/swtpm.sock" --daemon
timeout 150 qemu-system-aarch64 -M virt -cpu host -enable-kvm -m 4096 -smp 4 -nographic -no-reboot \
  -drive if=pflash,format=raw,readonly=on,file=/usr/share/AAVMF/AAVMF_CODE.no-secboot.fd \
  -drive if=pflash,format=raw,file="$R/vars.fd" \
  -chardev socket,id=chrtpm,path="$R/swtpm.sock" -tpmdev emulator,id=tpm0,chardev=chrtpm -device tpm-tis-device,tpmdev=tpm0 \
  -drive file="$IMG",if=virtio,format=raw,readonly=on > "$LOG" 2>&1
pkill -f -- "--tpmstate dir=$R" 2>/dev/null || true
rm -rf -- "$R"
sed 's/\x1b\[[0-9;?]*[a-zA-Z]//g' "$LOG" | grep -aE '^ni-generic: ' | head -3
