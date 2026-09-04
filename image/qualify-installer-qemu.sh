#!/usr/bin/env bash
# Reusable ARM64/KVM gate for a sealed Neural ICE installer.
#
# This harness never writes the supplied raw. The install phase creates a fresh
# swtpm state, AAVMF variable store and disposable qcow2 target. A later
# firstboot phase reuses only those task-owned artifacts and omits the installer.
set -euo pipefail
umask 077

usage() {
  cat <<'EOF'
Usage:
  qualify-installer-qemu.sh install --raw FILE --work-dir DIR --firmware-vars FILE [options]
  qualify-installer-qemu.sh firstboot --work-dir DIR [options]

Options:
  --firmware-code FILE      AAVMF code image (default: AAVMF_CODE.secboot.fd)
  --source-transport TYPE   usb, virtio, or nvme (default: usb)
  --tpm-state STATE         virgin, provisioned, replay, partial, or owner-auth
  --policy-sequence N       signed media sequence (default: 1)
  --target-size SIZE        qemu-img size (default: 1T)
  --timeout SECONDS         bounded QEMU runtime (default: 900)
  --network MODE            none or restricted-user (default: none)
  --ssh-port PORT           localhost forward to guest TCP/22
  --expect REGEX            require a console match; may be repeated
  --reject REGEX            reject a console match; may be repeated

`usb` proves AAVMF removable-media loading. The GB10 kernel currently ships only
the Tegra xHCI driver, which QEMU virt cannot emulate; use `virtio` for the
synthetic installer matrix and keep that limitation explicit in the evidence.
EOF
}

die() { printf 'qualify-installer-qemu: REFUSED: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "$1 is unavailable"; }

(( $# >= 1 )) || { usage >&2; exit 2; }
case "$1" in -h|--help) usage; exit 0 ;; esac
phase=$1
shift
case "$phase" in install|firstboot) ;; *) usage >&2; exit 2 ;; esac

raw=
work_dir=
firmware_code=/usr/share/AAVMF/AAVMF_CODE.secboot.fd
firmware_vars=
source_transport=usb
tpm_state=virgin
policy_sequence=1
target_size=1T
timeout_seconds=900
network=none
ssh_port=
declare -a expects=() rejects=()

while (( $# )); do
  case "$1" in
    --raw|--work-dir|--firmware-code|--firmware-vars|--source-transport|--tpm-state|--policy-sequence|--target-size|--timeout|--network|--ssh-port)
      (( $# >= 2 )) || die "$1 requires a value"
      key=$1 value=$2
      shift 2
      case "$key" in
        --raw) raw=$value ;;
        --work-dir) work_dir=$value ;;
        --firmware-code) firmware_code=$value ;;
        --firmware-vars) firmware_vars=$value ;;
        --source-transport) source_transport=$value ;;
        --tpm-state) tpm_state=$value ;;
        --policy-sequence) policy_sequence=$value ;;
        --target-size) target_size=$value ;;
        --timeout) timeout_seconds=$value ;;
        --network) network=$value ;;
        --ssh-port) ssh_port=$value ;;
      esac
      ;;
    --expect|--reject)
      (( $# >= 2 )) || die "$1 requires a regular expression"
      if [[ "$1" == --expect ]]; then expects+=("$2"); else rejects+=("$2"); fi
      shift 2
      ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[[ -n "$work_dir" && "$work_dir" == /* && "$work_dir" != / ]] \
  || die "--work-dir must be an absolute non-root path"
[[ "$timeout_seconds" =~ ^[1-9][0-9]{0,4}$ ]] || die "--timeout is malformed"
[[ "$policy_sequence" =~ ^[1-9][0-9]{0,9}$ ]] || die "--policy-sequence is malformed"
[[ "$target_size" =~ ^[1-9][0-9]*[KMGT]$ ]] || die "--target-size is malformed"
case "$source_transport" in usb|virtio|nvme) ;; *) die "unsupported source transport" ;; esac
case "$tpm_state" in virgin|provisioned|replay|partial|owner-auth) ;; *) die "unsupported TPM state" ;; esac
case "$network" in none|restricted-user) ;; *) die "unsupported network mode" ;; esac
if [[ -n "$ssh_port" ]]; then
  [[ "$ssh_port" =~ ^[1-9][0-9]{3,4}$ && "$ssh_port" -le 65535 ]] \
    || die "--ssh-port is malformed"
  [[ "$network" == restricted-user ]] \
    || die "--ssh-port requires --network restricted-user"
fi

for tool in qemu-system-aarch64 qemu-img swtpm timeout grep pgrep; do need "$tool"; done
[[ "$(uname -m)" == aarch64 ]] || die "the QEMU gate requires an ARM64 host"
[[ -r /dev/kvm && -w /dev/kvm ]] || die "/dev/kvm is unavailable"
[[ -f "$firmware_code" && -r "$firmware_code" ]] || die "AAVMF code is unreadable"

target=$work_dir/target.qcow2
vars=$work_dir/AAVMF_VARS.fd
tpm_dir=$work_dir/tpmstate
tpm_server=$work_dir/swtpm.sock
tpm_ctrl=$tpm_server.ctrl
tpm_pidfile=$work_dir/swtpm.pid
console=$work_dir/${phase}.console.log
qemu_stderr=$work_dir/${phase}.qemu.stderr

if [[ "$phase" == install ]]; then
  [[ -n "$raw" && -f "$raw" && ! -L "$raw" && -r "$raw" ]] \
    || die "--raw must name one readable regular file"
  [[ -n "$firmware_vars" && -f "$firmware_vars" && ! -L "$firmware_vars" && -r "$firmware_vars" ]] \
    || die "--firmware-vars must name one readable regular file"
  [[ ! -e "$work_dir" ]] || die "install work directory already exists"
  mkdir -m 0700 "$work_dir" "$tpm_dir"
  cp --reflink=auto -- "$firmware_vars" "$vars"
  qemu-img create -q -f qcow2 "$target" "$target_size"
  if [[ "$tpm_state" != virgin ]]; then
    cp --reflink=auto -- "$target" "$work_dir/target.empty.qcow2"
  fi
else
  [[ -d "$work_dir" && ! -L "$work_dir" ]] || die "firstboot work directory is unavailable"
  [[ -f "$target" && ! -L "$target" && -f "$vars" && ! -L "$vars" && -d "$tpm_dir" ]] \
    || die "firstboot artifacts are incomplete"
  [[ "$tpm_state" == virgin ]] \
    || die "--tpm-state applies only while creating an install scenario"
fi

rm -f -- "$tpm_server" "$tpm_ctrl" "$tpm_pidfile"
swtpm socket --tpm2 --tpmstate "dir=$tpm_dir" \
  --server "type=unixio,path=$tpm_server,mode=0600" \
  --ctrl "type=unixio,path=$tpm_ctrl,mode=0600" \
  --pid "file=$tpm_pidfile" --flags not-need-init,startup-clear --daemon

cleanup() {
  if [[ -f "$tpm_pidfile" ]]; then
    pid=$(<"$tpm_pidfile")
    if [[ "$pid" =~ ^[1-9][0-9]*$ ]]; then
      kill "$pid" 2>/dev/null || true
    fi
  fi
}
trap cleanup EXIT
for _ in {1..50}; do [[ -S "$tpm_server" && -S "$tpm_ctrl" ]] && break; sleep 0.1; done
[[ -S "$tpm_server" && -S "$tpm_ctrl" ]] || die "swtpm sockets did not appear"

export TPM2TOOLS_TCTI="swtpm:path=$tpm_server"
if [[ "$phase" == install && "$tpm_state" != virgin ]]; then
  for tool in tpm2_getcap tpm2_nvdefine tpm2_changeauth; do need "$tool"; done
  for _ in {1..50}; do tpm2_getcap properties-fixed >/dev/null 2>&1 && break; sleep 0.1; done
  tpm2_getcap properties-fixed >/dev/null 2>&1 || die "tpm2-tools cannot reach swtpm"
  case "$tpm_state" in
    partial)
      tpm2_nvdefine 0x01500003 -C o -s 8 -a ownerread\|ownerwrite >/dev/null
      ;;
    owner-auth)
      tpm2_changeauth -c o neural-ice-qemu-synthetic-owner >/dev/null
      ;;
    provisioned|replay)
      helper="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)/ota/neural-ice-tpm-state.sh"
      [[ -x "$helper" ]] || die "TPM state helper is unavailable"
      tools=$work_dir/tpm-tools
      mkdir -m 0700 "$tools"
      for tool in python3 flock sha256sum od head wc awk tpm2_getcap tpm2_nvdefine \
        tpm2_nvincrement tpm2_nvread tpm2_nvwrite tpm2_nvwritelock \
        tpm2_nvreadpublic tpm2_startauthsession tpm2_policycommandcode \
        tpm2_policyor tpm2_flushcontext tpm2_changeauth; do
        need "$tool"
        ln -s "$(command -v "$tool")" "$tools/$tool"
      done
      sequence=$policy_sequence
      [[ "$tpm_state" == replay ]] && sequence=$((policy_sequence + 1))
      NI_TPM_STATE_TESTING=1 NI_TPM_STATE_TEST_TOOLS="$tools" \
        NI_TPM_STATE_TEST_RUN_DIR="$work_dir/tpm-run" \
        "$helper" pcr-policy-activate "$sequence" >/dev/null
      ;;
  esac
fi
unset TPM2TOOLS_TCTI

# QEMU speaks the swtpm control protocol and supplies the TPM data channel
# itself. A swtpm server socket is needed only for tpm2-tools provisioning; it
# must not still own the data channel when QEMU sends CMD_SET_DATAFD.
provisioning_pid=$(<"$tpm_pidfile")
kill "$provisioning_pid"
for _ in {1..50}; do
  kill -0 "$provisioning_pid" 2>/dev/null || break
  sleep 0.1
done
kill -0 "$provisioning_pid" 2>/dev/null \
  && die "provisioning swtpm did not stop"
rm -f -- "$tpm_server" "$tpm_ctrl" "$tpm_pidfile"
swtpm socket --tpm2 --tpmstate "dir=$tpm_dir" \
  --ctrl "type=unixio,path=$tpm_ctrl,mode=0600" \
  --pid "file=$tpm_pidfile" --flags startup-clear --daemon
for _ in {1..50}; do [[ -S "$tpm_ctrl" ]] && break; sleep 0.1; done
[[ -S "$tpm_ctrl" ]] || die "QEMU swtpm control socket did not appear"

declare -a qemu=(
  qemu-system-aarch64
  -name "neural-ice-installer-${phase}-${tpm_state}"
  -machine "virt,accel=kvm,gic-version=3"
  -cpu host -smp 8 -m 8192
  -smbios "type=1,manufacturer=NVIDIA,product=NVIDIA_DGX_Spark"
  -smbios "type=2,manufacturer=NVIDIA,product=P4242"
  -drive "if=pflash,format=raw,unit=0,readonly=on,file=$firmware_code"
  -drive "if=pflash,format=raw,unit=1,file=$vars"
  -chardev "socket,id=chrtpm,path=$tpm_ctrl"
  -tpmdev "emulator,id=tpm0,chardev=chrtpm"
  -device "tpm-tis-device,tpmdev=tpm0"
)

if [[ "$phase" == install ]]; then
  qemu+=(-drive "if=none,id=installer,format=raw,readonly=on,file=$raw")
  case "$source_transport" in
    usb)
      qemu+=(-device "qemu-xhci,id=xhci" -device "usb-storage,drive=installer,bootindex=1,removable=on")
      ;;
    virtio)
      qemu+=(-device "virtio-blk-pci,drive=installer,bootindex=1")
      ;;
    nvme)
      qemu+=(-device "nvme,drive=installer,serial=NIINSTALLER,bootindex=1")
      ;;
  esac
fi
qemu+=(
  -drive "if=none,id=target,format=qcow2,file=$target,discard=unmap"
  -device "nvme,drive=target,serial=NIQEMUTARGET,bootindex=2"
  -nographic -no-reboot
)
if [[ "$network" == none ]]; then
  qemu+=(-nic none)
else
  nic="user,model=virtio-net-pci,restrict=on"
  [[ -z "$ssh_port" ]] || nic+=",hostfwd=tcp:127.0.0.1:${ssh_port}-:22"
  qemu+=(-nic "$nic")
fi

if [[ "$phase" == firstboot && ${#expects[@]} -eq 0 ]]; then
  die "firstboot requires at least one explicit success expression"
fi

case "$tpm_state" in
  # The detailed completion screen is intentionally tty1-only because it carries
  # the recovery key. The serial-safe log marker contains no secret and is the
  # durable automation boundary the headless harness can observe.
  virgin) scenario_pattern='[8/8] done — install completed' ;;
  provisioned) scenario_pattern='the TPM is not virgin' ;;
  replay) scenario_pattern='PCR policy sequence does not equal the durable TPM high-water' ;;
  partial) scenario_pattern='PCR policy state is absent while another appliance state index exists' ;;
  owner-auth) scenario_pattern='PCR policy high-water is absent after owner authorization was sealed' ;;
esac

all_expected_patterns_seen() {
  local pattern
  for pattern in "${expects[@]}"; do
    grep -Eq -- "$pattern" "$console" || return 1
  done
}

set +e
timeout "$timeout_seconds" "${qemu[@]}" >"$console" 2>"$qemu_stderr" &
timeout_pid=$!
while kill -0 "$timeout_pid" 2>/dev/null; do
  stop=0
  for pattern in "${rejects[@]}"; do
    if grep -Eq -- "$pattern" "$console" 2>/dev/null; then
      stop=1
      break
    fi
  done
  if (( stop == 0 )); then
    if [[ "$phase" == install ]]; then
      grep -Fq -- "$scenario_pattern" "$console" 2>/dev/null \
        && all_expected_patterns_seen && stop=1
    elif all_expected_patterns_seen; then
      stop=1
    fi
  fi
  if (( stop == 1 )); then
    # The appliance intentionally waits for a physical Enter key at the end of
    # installation, and first boot remains running after it becomes healthy.
    # Once the required terminal evidence is durable in the console, terminate
    # only this task-owned VM; QEMU flushes its block backend on SIGTERM.
    sleep 2
    qemu_pid="$(pgrep -P "$timeout_pid" 2>/dev/null || true)"
    [[ -z "$qemu_pid" ]] || kill "$qemu_pid" 2>/dev/null
    break
  fi
  sleep 1
done
wait "$timeout_pid"
qemu_rc=$?
set -e

for pattern in "${expects[@]}"; do
  grep -Eq -- "$pattern" "$console" \
    || die "console did not match required expression: $pattern"
done
for pattern in "${rejects[@]}"; do
  ! grep -Eq -- "$pattern" "$console" \
    || die "console matched forbidden expression: $pattern"
done

if [[ "$phase" == install ]]; then
  case "$tpm_state" in
    virgin)
      grep -Fq '[8/8] done — install completed' "$console" \
        || die "virgin scenario did not complete the installation"
      ! grep -Eq '(^|[^A-Z])(FAILED|REFUSED|FATAL)([^A-Z]|$)' "$console" \
        || die "virgin scenario emitted a failure after starting"
      ;;
    provisioned)
      grep -Fq 'the TPM is not virgin' "$console" \
        || die "provisioned scenario was not refused at installer preflight"
      ;;
    replay)
      grep -Fq 'PCR policy sequence does not equal the durable TPM high-water' "$console" \
        || die "replayed PCR policy sequence was not refused"
      ;;
    partial)
      grep -Fq 'PCR policy state is absent while another appliance state index exists' "$console" \
        || die "partial TPM state was not refused"
      ;;
    owner-auth)
      grep -Fq 'PCR policy high-water is absent after owner authorization was sealed' "$console" \
        || die "owner-authorized partial state was not refused"
      ;;
  esac
  if [[ "$tpm_state" != virgin ]]; then
    qemu-img compare -q "$target" "$work_dir/target.empty.qcow2" \
      || die "$tpm_state refusal modified the virtual target"
  fi
else
  :
fi

printf 'QEMU_PHASE=%s\nTPM_STATE=%s\nSOURCE_TRANSPORT=%s\nQEMU_EXIT=%s\n' \
  "$phase" "$tpm_state" "$source_transport" "$qemu_rc"
printf 'CONSOLE=%s\nQEMU_STDERR=%s\nTARGET=%s\n' "$console" "$qemu_stderr" "$target"
[[ "$qemu_rc" -ne 124 ]] || die "QEMU exceeded the bounded timeout"
