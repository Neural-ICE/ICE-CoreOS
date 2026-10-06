#!/bin/bash
# QEMU proof of a generic installer medium (ADR-0044): AAVMF (no Secure Boot yet) + swtpm + KVM, media attached
# read-only. Exit 0 only when QEMU ran to its time budget (the prototype never powers off) and the installer
# printed exactly one verdict, the OK one. Usage (root, for /dev/kvm): qemu-proof.sh LOG IMG [IMG...]
set -euo pipefail
LOG="${1:?log}"; shift; [ $# -ge 1 ] || { echo "no image" >&2; exit 2; }
R="$(mktemp -d /tmp/ni-geninst-q.XXXXXX)"   # swtpm's AppArmor profile allows /tmp
trap 'pkill -f -- "--tpmstate dir=$R" 2>/dev/null || true; rm -rf -- "$R"' EXIT
cp /usr/share/AAVMF/AAVMF_VARS.fd "$R/vars.fd"
swtpm socket --tpm2 --tpmstate dir="$R" --ctrl type=unixio,path="$R/swtpm.sock" --daemon
drives=(); for i in "$@"; do drives+=(-drive "file=$i,if=virtio,format=raw,readonly=on"); done
rc=0
timeout 120 qemu-system-aarch64 -M virt -cpu host -enable-kvm -m 4096 -smp 4 -nographic -no-reboot \
  -drive if=pflash,format=raw,readonly=on,file=/usr/share/AAVMF/AAVMF_CODE.no-secboot.fd \
  -drive if=pflash,format=raw,file="$R/vars.fd" \
  -chardev socket,id=chrtpm,path="$R/swtpm.sock" -tpmdev emulator,id=tpm0,chardev=chrtpm -device tpm-tis-device,tpmdev=tpm0 \
  "${drives[@]}" > "$LOG" 2>&1 || rc=$?
[ "$rc" = 124 ] || { echo "qemu ended with $rc, not the time budget" >&2; exit 1; }
verdicts="$(sed 's/\x1b\[[0-9;?]*[a-zA-Z]//g' "$LOG" | grep -aE '^ni-generic: (NI-GENERIC-PAYLOAD-OK|REFUSED)' || true)"
printf '%s\n' "$verdicts"
[ "$(printf '%s\n' "$verdicts" | grep -c .)" = 1 ] && grep -q '^ni-generic: NI-GENERIC-PAYLOAD-OK' <<<"$verdicts"
