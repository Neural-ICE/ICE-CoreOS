#!/bin/bash
# shellcheck disable=SC2034 # variables consumed by the code extracted from the installer
# PID 1 of the e2e guest (image/e2e-pcr-rules-qemu). It runs the installer's REAL
# NI-P7-RULES gate -- the code extracted verbatim from ota/neural-ice-autoinstall.sh
# into /gate.sh -- against the guest's real TPM, its real TCG event log and its real
# efivarfs, then, only if the gate accepts, the installer's real enrolment function on a
# scratch disk. Every result line starts with E2E: and goes to the serial console.
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export DM_DISABLE_UDEV=1 LANG=C
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev
mount -t securityfs none /sys/kernel/security
mount -t efivarfs efivarfs /sys/firmware/efi/efivars
mount -t tmpfs tmpfs /run
mount -t tmpfs tmpfs /tmp
install -d -m 0700 /run/neural-ice-installer
exec 2>&1

finish() {
  local rc=$?
  echo "E2E: exit status $rc"
  echo "E2E: END"
  sync
  poweroff -f
}
trap finish EXIT

cmdline="$(cat /proc/cmdline)"
word() { for w in $cmdline; do case "$w" in "$1="*) printf '%s' "${w#*=}"; return 0;; esac; done; return 1; }
MODE="$(word e2e.mode || echo install)"
echo "E2E: kernel $(uname -r) mode=$MODE scenario=$(word e2e.scenario || echo ?)"
modprobe nls_iso8859-1 2>/dev/null; modprobe nls_utf8 2>/dev/null
modprobe dm-crypt 2>/dev/null || echo "E2E-WARN: dm-crypt module did not load"
[[ -e /dev/tpmrm0 ]] || { echo "E2E-FAIL: no /dev/tpmrm0"; exit 90; }
echo "E2E: SecureBoot=$(od -An -tu1 -j4 -N1 /sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c 2>/dev/null | tr -d ' ') SetupMode=$(od -An -tu1 -j4 -N1 /sys/firmware/efi/efivars/SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c 2>/dev/null | tr -d ' ')"
echo "E2E: live PCR7 $(tpm2_pcrread sha256:7 2>/dev/null | tr -d '\n ')"
echo "E2E: eventlog bytes $(wc -c < /sys/kernel/security/tpm0/binary_bios_measurements)"

if [[ "$MODE" == debug ]]; then
  ls -l /dev/vd* /dev/tpm* 2>&1
  modprobe -v nls_iso8859-1 2>&1; ls /usr/lib/modules/*/ 2>&1 | head; ls -R /usr/lib/modules | head -20
  mkdir -p /mnt; mount -o ro,nodev,nosuid,noexec /dev/vda /mnt 2>&1; echo "mount rc=$?"
  ls -lR /mnt 2>&1 | head -20
  dmesg | tail -15
  exit 0
fi
if [[ "$MODE" == ids ]]; then
  python3 -I /usr/lib/neural-ice/pcr-rules/tools/ni-pcr-rules/ni-pcr-rules.py ids
  exit 0
fi

# --- the installer's own functions and gate block, unmodified ------------------------------
NEURALICE_CMDLINE_FILE=/proc/cmdline
NI_INSTALLER_TEST_SEAM=""
PHASE_CODE=install-failed-preflight-and-trust-gate PHASE_ID=1 PHASE_TOTAL=8
PHASE_SLUG=preflight-and-trust-gate PHASE_LABEL="Preflight and trust gate"
FAILURE_EVIDENCE_SCHEMA=neural-ice-installer-failure-evidence-v1
FAILURE_EVIDENCE=/run/failure-evidence
EFI_FAILURE_EVIDENCE=/sys/firmware/efi/efivars/NeuralICEInstallerFailure-870a0500-25d2-574e-a1cc-79a69630bf96
INSTALLER_STATE_DIR=/run/neural-ice-installer
log() { printf '[neural-ice-autoinstall] %s\n' "$*"; }
# The medium: a whole-disk FAT image on the first virtio disk.
live_disk=vda
media_vfat_partition() { echo vda; }
mounted_at() { return 0; }
# shellcheck source=/dev/null
. /gate.sh

TARGET=/dev/vdb
before="$(sha256sum "$TARGET" | awk '{print $1}')"
echo "E2E: target sha256 before $before"

# Production order: the Owner key is staged against its sealed hash, then the gates.
PCR_POLICY_KEY_SHA256="$(karg_once neuralice.pcr_policy_key)"
PCR_POLICY_KEY_RUNTIME=/run/neural-ice-installer/tpm2-pcr-public-key.pem
esp_staged_file tpm2-pcr-public-key.pem "$PCR_POLICY_KEY_SHA256" "$PCR_POLICY_KEY_RUNTIME"

report_target() {
  echo "E2E: target sha256 after $(sha256sum "$TARGET" | awk '{print $1}')"
}
trap 'report_target; finish' EXIT

# --- the gate (the extracted block from `PCR_RULES_DIGEST=` to `readonly PCR_RULES_STATE`) ---
. /gate-block.sh
echo "E2E: gate state=$PCR_RULES_STATE rules_sha=${PCR_RULES_RULES_SHA256:0:16} seq=$PCR_RULES_SEQUENCE binding=$PCR_RULES_BINDING observed=$PCR_RULES_OBSERVED"

# --- install: only reached when the gate accepted -----------------------------------------------
echo "E2E: INSTALLING on $TARGET"
tpm2_createprimary -C o -G ecc -g sha256 -c /tmp/srk.ctx >/dev/null || { echo "E2E-FAIL: SRK"; exit 91; }
tpm2_evictcontrol -C o -c /tmp/srk.ctx 0x81000001 >/dev/null || { echo "E2E-FAIL: SRK persist"; exit 92; }
sfdisk --force --wipe always --wipe-partitions always "$TARGET" <<PART
label: gpt
size=64MiB, type=linux, name="system-luks"
PART
partx -u "$TARGET" 2>/dev/null || true
for _ in 1 2 3 4 5; do [[ -b ${TARGET}1 ]] && break; sleep 1; done
[[ -b ${TARGET}1 ]] || { mdev -s 2>/dev/null; sleep 1; }
[[ -b ${TARGET}1 ]] || { echo "E2E-FAIL: no ${TARGET}1"; exit 93; }
# shellcheck source=/dev/null
. /enroll.sh
SYS_RECOVERY="$(enroll_luks "${TARGET}1" system)" || { echo "E2E-FAIL: enroll_luks"; exit 94; }
cryptsetup luksDump --dump-json-metadata "${TARGET}1" > /tmp/luks.json
python3 -I - /tmp/luks.json <<'PY'
import json, sys
meta = json.load(open(sys.argv[1]))
tokens = [t for t in meta["tokens"].values() if t.get("type") == "systemd-tpm2"]
print("E2E: tpm2 tokens", len(tokens),
      "pubkey-bound", sum(1 for t in tokens if t.get("tpm2_pubkey")),
      "pubkey-pcrs", [t.get("tpm2_pubkey_pcrs") for t in tokens],
      "pcrs", [t.get("tpm2-pcrs") for t in tokens])
sys.exit(0 if tokens else 1)
PY
[[ $? -eq 0 ]] || { echo "E2E-FAIL: the enrolled volume carries no systemd-tpm2 token"; exit 95; }
[[ -n "$SYS_RECOVERY" ]] && echo "E2E: recovery key issued"
# The record the installer leaves on the installed ESP, written by its own code.
TGT=/tmp/tgt; install -d "$TGT/boot/efi/EFI/neural-ice"
# shellcheck source=/dev/null
. /evidence.sh
echo "E2E: record $(tr '\n' ' ' < "$TGT/boot/efi/EFI/neural-ice/pcr-rules-at-install.txt")"
echo "E2E: installed rules sha256 $(sha256sum < "$TGT/boot/efi/EFI/neural-ice/pcr-rules/rules.json" | awk '{print $1}')"
echo "E2E: ENROLLED"   # printed only after the readback above found its tokens (see run-e2e.sh checks)
cryptsetup close system 2>/dev/null || true
exit 0
