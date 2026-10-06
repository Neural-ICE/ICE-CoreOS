#!/bin/bash
# QEMU proof of a real install by the generic installer (ADR-0044): phase 1 boots the medium (read-only) with a blank
# virtual target disk and waits for the installer to install and reboot; phase 2 boots ONLY the installed disk
# (same firmware variables, same swtpm state) until the system reaches multi-user or the budget ends.
# AAVMF without Secure Boot, KVM, swtpm TPM 2.0. Run as root (/dev/kvm).
# Usage: qemu-install-proof.sh OUTDIR MEDIUM.img [TARGET_GIB] [INSTALL_BUDGET_S] [BOOT_BUDGET_S]
# Refusal proof: EXPECT_REFUSAL='<regex of the refusal text>' makes phase 1 succeed only when the installer prints
# exactly that refusal, no install verdict, and leaves the target disk untouched (nothing allocated, all zeros).
# EXPECT_RELEASE and EXPECT_HOST_DIGEST pin the release the install verdict must name (set them in CI).
# Exit codes: 0 proven, 1 not proven, 2 installed and booted, but the host's own trust gate refused (NI-E02).
set -euo pipefail
OUT="${1:?outdir}"; MEDIUM="${2:?medium image}"; GIB="${3:-64}"; IB="${4:-2400}"; BB="${5:-420}"
mkdir -p "$OUT"; R="$(mktemp -d /tmp/ni-geninst-q.XXXXXX)"   # swtpm's AppArmor profile allows /tmp
trap 'pkill -f -- "--tpmstate dir=$R" 2>/dev/null || true; rm -rf -- "$R"' EXIT
TARGET="$OUT/target.raw"; rm -f "$TARGET"; truncate -s "${GIB}G" "$TARGET"
cp /usr/share/AAVMF/AAVMF_VARS.fd "$R/vars.fd"
tpm() { swtpm socket --tpm2 --tpmstate dir="$R" --ctrl type=unixio,path="$R/swtpm.sock" --daemon; }   # exits when QEMU disconnects; the state stays in $R
qemu() { # $1 log, $2 budget, then drives; stops early when the log has the marker named by $MARK
  local log="$1" budget="$2"; shift 2
  tpm
  qemu-system-aarch64 -M virt -cpu host -enable-kvm -m 16384 -smp 4 -nographic -no-reboot \
    -drive if=pflash,format=raw,readonly=on,file=/usr/share/AAVMF/AAVMF_CODE.no-secboot.fd \
    -drive if=pflash,format=raw,file="$R/vars.fd" \
    -chardev socket,id=chrtpm,path="$R/swtpm.sock" -tpmdev emulator,id=tpm0,chardev=chrtpm -device tpm-tis-device,tpmdev=tpm0 \
    "$@" > "$log" 2>&1 &
  local pid=$! t=0
  while kill -0 "$pid" 2>/dev/null && [ "$t" -lt "$budget" ]; do
    sleep 2; t=$((t + 2))
    if [ -n "${MARK:-}" ] && sed 's/\x1b\[[0-9;?]*[a-zA-Z]//g' "$log" | grep -aqE "$MARK"; then sleep 5; break; fi
  done
  if kill -0 "$pid" 2>/dev/null; then kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; echo "qemu stopped after ${t}s (marker or budget)"; else wait "$pid" 2>/dev/null || true; echo "qemu exited by itself after ${t}s"; fi
}
clean() { sed 's/\x1b\[[0-9;?]*[a-zA-Z]//g' "$1"; }
echo "== phase 1: install"; t0=$SECONDS; MARK="ni-generic(-install)?: REFUSED" qemu "$OUT/phase1.log" "$IB" \
  -drive "file=$MEDIUM,if=none,id=med,format=raw,readonly=on" -device virtio-blk-pci,drive=med,serial=ni-medium \
  -drive "file=$TARGET,if=none,id=tgt,format=raw" -device virtio-blk-pci,drive=tgt,serial=ni-target
echo "phase 1 seconds: $(( SECONDS - t0 ))"
clean "$OUT/phase1.log" | grep -aE '^ni-generic(-install)?:' > "$OUT/phase1.verdicts" || true
cat "$OUT/phase1.verdicts"
if [ -n "${EXPECT_REFUSAL:-}" ]; then
  [ "$(grep -c 'REFUSED' "$OUT/phase1.verdicts")" = 1 ] && grep -qE "REFUSED: .*(${EXPECT_REFUSAL})" "$OUT/phase1.verdicts" && ! grep -q 'INSTALL-OK' "$OUT/phase1.verdicts" \
    || { echo "REFUSAL NOT PROVEN"; exit 1; }
  [ "$(du -s --block-size=1 "$TARGET" | cut -f1)" = 0 ] || { echo "TARGET DISK WAS WRITTEN"; exit 1; }
  LC_ALL=C cmp -s -n "$(stat -c %s "$TARGET")" "$TARGET" /dev/zero || { echo "TARGET DISK WAS WRITTEN"; exit 1; }
  echo "REFUSAL PROVEN, target disk untouched"; exit 0
fi
[ "$(grep -c 'NI-GENERIC-PAYLOAD-OK' "$OUT/phase1.verdicts")" = 1 ] && [ "$(grep -c 'NI-GENERIC-INSTALL-OK' "$OUT/phase1.verdicts")" = 1 ] && ! grep -q 'REFUSED' "$OUT/phase1.verdicts" \
  && grep -qE "^ni-generic-install: NI-GENERIC-INSTALL-OK release=${EXPECT_RELEASE:-[A-Za-z0-9._-]+} host=.*@${EXPECT_HOST_DIGEST:-sha256:[0-9a-f]+} " "$OUT/phase1.verdicts" \
  || { echo "INSTALL NOT PROVEN"; exit 1; }
echo "target allocated: $(du -h --apparent-size "$TARGET" | cut -f1) apparent, $(du -h "$TARGET" | cut -f1) on disk"
echo "== phase 2: first boot of the installed disk"; t1=$SECONDS
MARK='Reached target .*Multi-User|login: |You are in emergency mode' qemu "$OUT/phase2.log" "$BB" \
  -drive "file=$TARGET,if=none,id=tgt,format=raw" -device virtio-blk-pci,drive=tgt,serial=ni-target
echo "phase 2 seconds: $(( SECONDS - t1 ))"
clean "$OUT/phase2.log" > "$OUT/phase2.clean.log"
grep -aE 'Reached target .*(Multi-User|Basic System|Initrd Root)|login:|Welcome to|ostree-prepare-root|panic|emergency|NI-E0|Failed to start' "$OUT/phase2.clean.log" | head -30
if grep -aqE 'Reached target .*Multi-User|login: ' "$OUT/phase2.clean.log"; then echo "FIRST BOOT REACHED MULTI-USER"
elif grep -aq 'Welcome to Neural ICE CoreOS' "$OUT/phase2.clean.log" \
     && grep -aq 'FAILURE NI-E02 (TPM ceremony) unit=neural-ice-firstboot-tpm-ceremony.service' "$OUT/phase2.clean.log" \
     && [ -z "$(grep -aE 'NI-E0[0-9]' "$OUT/phase2.clean.log" | grep -av 'NI-E02')" ]; then
  # The installed host switched root and ran its own first-boot trust gate, which refused: the installer does not yet
  # provision the TPM ceremony, the PCR policy or the LUKS data volume (ADR-0044 release-blocking items).
  echo "FIRST BOOT: HOST RAN, ITS TRUST GATE REFUSED (NI-E02, provisioning not wired)"; exit 2
else echo "FIRST BOOT NOT PROVEN"; exit 1; fi
