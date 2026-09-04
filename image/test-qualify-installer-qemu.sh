#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
HARNESS="$ROOT/image/qualify-installer-qemu.sh"
fail() { echo "FAIL: $*" >&2; exit 1; }

[[ -x "$HARNESS" ]] || fail "the QEMU qualification harness is not executable"
"$HARNESS" --help | grep -Fq 'firstboot --work-dir DIR' \
  || fail "the harness does not expose its reusable install/firstboot contract"

if "$HARNESS" install --work-dir relative >/dev/null 2>&1; then
  fail "the harness accepted a relative work directory"
fi
if "$HARNESS" install --work-dir /tmp/ni-qemu-test --tpm-state invented >/dev/null 2>&1; then
  fail "the harness accepted an unknown TPM state"
fi
if "$HARNESS" install --work-dir /tmp/ni-qemu-test --source-transport invented >/dev/null 2>&1; then
  fail "the harness accepted an unknown source transport"
fi

# shellcheck disable=SC2016 # literal source contracts are being matched
for contract in \
  'readonly=on,file=$raw' \
  'virt,accel=kvm,gic-version=3' \
  'swtpm socket --tpm2' \
  'tpm_ctrl=$tpm_server.ctrl' \
  'AAVMF_CODE.secboot.fd' \
  'manufacturer=NVIDIA,product=NVIDIA_DGX_Spark' \
  'manufacturer=NVIDIA,product=P4242' \
  'nvme,drive=target,serial=NIQEMUTARGET' \
  'user,model=virtio-net-pci,restrict=on' \
  '[8/8] done — install completed' \
  'qemu-img compare -q' \
  'install work directory already exists' \
  'firstboot artifacts are incomplete'; do
  grep -Fq "$contract" "$HARNESS" || fail "the harness lost: $contract"
done

for state in virgin provisioned replay partial owner-auth; do
  grep -Fq "$state" "$HARNESS" || fail "the harness lost TPM scenario $state"
done

grep -Fq 'Tegra xHCI driver, which QEMU virt cannot emulate' "$HARNESS" \
  || fail "the harness hides the synthetic USB-controller limitation"
# shellcheck disable=SC2016 # literal source contract is being matched
grep -Fq '[[ "$qemu_rc" -ne 124 ]]' "$HARNESS" \
  || fail "the harness can report green after a timeout"

echo "INSTALLER_QEMU_HARNESS_TEST_OK"
