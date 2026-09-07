#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
HARNESS="$ROOT/image/qualify-installer-qemu.sh"
fail() { echo "FAIL: $*" >&2; exit 1; }
TMP="$(mktemp -d)"
cleanup() {
  [[ -z "${SERVER_PID:-}" ]] || kill "$SERVER_PID" 2>/dev/null || true
  rm -rf -- "$TMP"
}
trap cleanup EXIT

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

for state in virgin preceremony equal replay partial owner-auth; do
  grep -Fq "$state" "$HARNESS" || fail "the harness lost TPM scenario $state"
done

# shellcheck disable=SC2016 # literal source contract is being matched
grep -Fq 'sequence=$((policy_sequence - 1))' "$HARNESS" \
  || fail "the harness has no explicit higher-policy pre-ceremony retry fixture"

grep -Fq 'Tegra xHCI driver, which QEMU virt cannot emulate' "$HARNESS" \
  || fail "the harness hides the synthetic USB-controller limitation"
# shellcheck disable=SC2016 # literal source contract is being matched
grep -Fq '[[ "$qemu_rc" -ne 124 ]]' "$HARNESS" \
  || fail "the harness can report green after a timeout"
shutdown_line="$(grep -nF 'tpm2_shutdown -c' "$HARNESS" | cut -d: -f1)"
# shellcheck disable=SC2016 # literal source contract is being matched
provisioning_stop_line="$(grep -nF 'stop_task_process "$provisioning_pid"' "$HARNESS" | cut -d: -f1)"
[[ "$shutdown_line" =~ ^[0-9]+$ && "$provisioning_stop_line" =~ ^[0-9]+$ \
    && "$shutdown_line" -lt "$provisioning_stop_line" ]] \
  || fail "the provisioning TPM is not shut down orderly before swtpm stops"

# Exercise the production QMP helper against a protocol stub. The capture proves
# the greeting is consumed and capabilities are negotiated before powerdown.
run_qmp_server() { # $1=socket $2=capture $3=ok|error
  python3 - "$1" "$2" "$3" <<'PY' &
import json
import os
import socket
import sys

path, capture, mode = sys.argv[1:]
server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
server.bind(path)
server.listen(1)
connection, _ = server.accept()
stream = connection.makefile("rwb", buffering=0)
stream.write(b'{"QMP":{"version":{},"capabilities":[]}}\r\n')
commands = []
for expected in ("qmp_capabilities", "guest-request"):
    request = json.loads(stream.readline(65537))
    commands.append(request)
    if mode == "error" and expected == "qmp_capabilities":
        stream.write(b'{"error":{"class":"GenericError","desc":"refused"}}\r\n')
        break
    stream.write(b'{"return":{}}\r\n')
with open(capture, "w", encoding="utf-8") as output:
    json.dump(commands, output, sort_keys=True, separators=(",", ":"))
connection.close()
server.close()
os.unlink(path)
PY
  SERVER_PID=$!
  for _ in {1..100}; do [[ -S "$1" ]] && return 0; sleep 0.01; done
  fail "QMP protocol stub did not start"
}

(
  # shellcheck source=image/qualify-installer-qemu.sh
  NI_QEMU_HARNESS_SOURCE_ONLY=1 source "$HARNESS"
  socket="$TMP/qmp-ok.sock"
  capture="$TMP/qmp-ok.json"
  run_qmp_server "$socket" "$capture" ok
  qmp_guest_request "$socket" system_powerdown
  wait "$SERVER_PID"
  [[ "$(<"$capture")" == \
    '[{"execute":"qmp_capabilities"},{"execute":"system_powerdown"}]' ]] \
    || fail "QMP commands were not negotiated in the required order"
)

(
  # shellcheck source=image/qualify-installer-qemu.sh
  NI_QEMU_HARNESS_SOURCE_ONLY=1 source "$HARNESS"
  socket="$TMP/qmp-error.sock"
  capture="$TMP/qmp-error.json"
  run_qmp_server "$socket" "$capture" error
  if qmp_guest_request "$socket" system_powerdown >/dev/null 2>&1; then
    fail "QMP helper accepted a capabilities refusal"
  fi
  wait "$SERVER_PID"
)

(
  # shellcheck source=image/qualify-installer-qemu.sh
  NI_QEMU_HARNESS_SOURCE_ONLY=1 source "$HARNESS"
  socket="$TMP/qmp-enter.sock"
  capture="$TMP/qmp-enter.json"
  run_qmp_server "$socket" "$capture" ok
  qmp_guest_request "$socket" send-key-ret
  wait "$SERVER_PID"
  [[ "$(<"$capture")" == \
    '[{"execute":"qmp_capabilities"},{"arguments":{"keys":[{"data":"ret","type":"qcode"}]},"execute":"send-key"}]' ]] \
    || fail "QMP installer completion did not send the Enter key contract"
)

# Exercise the exact process-session cleanup helper with a wrapper and a nested
# child, matching the shape that broke direct-child PID discovery under sudo.
(
  # shellcheck source=image/qualify-installer-qemu.sh
  NI_QEMU_HARNESS_SOURCE_ONLY=1 source "$HARNESS"
  child_pid_file="$TMP/nested.pid"
  # shellcheck disable=SC2016 # expansions belong to the nested shells
  setsid --wait bash -c '
    trap "exit 0" TERM
    bash -c '\''trap "exit 0" TERM; while :; do sleep 1; done'\'' &
    printf "%s\n" "$!" >"$1"
    wait
  ' qemu-wrapper "$child_pid_file" >/dev/null 2>&1 &
  leader=$!
  for _ in {1..100}; do [[ -s "$child_pid_file" ]] && break; sleep 0.01; done
  [[ -s "$child_pid_file" ]] || fail "nested cleanup fixture did not start"
  nested="$(<"$child_pid_file")"
  terminate_qemu_session "$leader" || fail "session cleanup failed"
  wait "$leader" 2>/dev/null || true
  ! kill -0 "$leader" 2>/dev/null || fail "session leader survived cleanup"
  ! kill -0 "$nested" 2>/dev/null || fail "nested QEMU stand-in survived cleanup"
)

# Exercise the exact bounded helper used for both provisioning and EXIT-trap
# swtpm cleanup; returning success requires the selected PID to be gone.
(
  # shellcheck source=image/qualify-installer-qemu.sh
  NI_QEMU_HARNESS_SOURCE_ONLY=1 source "$HARNESS"
  sleep 60 &
  swtpm_standin=$!
  stop_task_process "$swtpm_standin" swtpm \
    || fail "bounded swtpm stop helper failed"
  wait "$swtpm_standin" 2>/dev/null || true
  ! kill -0 "$swtpm_standin" 2>/dev/null \
    || fail "bounded swtpm stop helper returned with a live PID"
  if stop_task_process malformed swtpm >/dev/null 2>&1; then
    fail "bounded swtpm stop helper accepted a malformed PID"
  fi
)

# Exercise the production final-success predicate directly. A success marker can
# already be in the console when QEMU exits or crashes between polling cycles;
# neither rc=0 nor rc!=0 may pass without the phase's guest-driven shutdown.
(
  # shellcheck source=image/qualify-installer-qemu.sh
  NI_QEMU_HARNESS_SOURCE_ONLY=1 source "$HARNESS"
  for scenario in 'install virgin send-key-ret' \
                  'install preceremony send-key-ret' \
                  'firstboot virgin system_powerdown'; do
    read -r phase state expected <<<"$scenario"
    for rc in 0 1; do
      if successful_scenario_completed "$phase" "$state" none "$rc"; then
        fail "$phase/$state accepted shutdown_mode=none with qemu_rc=$rc"
      fi
    done
    successful_scenario_completed "$phase" "$state" "$expected" 0 \
      || fail "$phase/$state refused its clean phase-specific exit"
    if successful_scenario_completed "$phase" "$state" "$expected" 1; then
      fail "$phase/$state accepted a nonzero QEMU exit after $expected"
    fi
  done
  successful_scenario_completed install equal forced-after-terminal-refusal 143 \
    || fail "the success predicate changed expected-negative forced cleanup"
)

echo "INSTALLER_QEMU_HARNESS_TEST_OK"
