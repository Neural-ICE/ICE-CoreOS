#!/usr/bin/env bash
#
# The bench rehearsal's OFFLINE suite: the serial-log parsers over fixtures of
# the four real 2026-09-09 failures plus a success, the argument refusals, and
# the load-bearing contracts of the driver itself.
#
# It boots nothing. The rehearsal it guards runs only on the KVM-capable GB10
# bench, which is exactly why the part that reads its evidence must be provable
# here: a parser that mis-reads a refusal turns a measured defect into "we do not
# know what happened", and that is the failure mode this whole task exists to end.
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
DRIVER="$ROOT/image/bench-rehearse-medium.sh"
FIXTURES="$ROOT/image/test-lib/bench-serial"
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "  ok   $*"; }

TMP="$(mktemp -d)"
trap 'rm -rf -- "$TMP"' EXIT

[[ -x "$DRIVER" ]] || fail "the bench rehearsal driver is not executable"
[[ -d "$FIXTURES" ]] || fail "the serial-log fixtures are missing"

# shellcheck source=image/bench-rehearse-medium.sh
NI_BENCH_HARNESS_SOURCE_ONLY=1 source "$DRIVER"

echo "== the source-only seam is a seam, not a bypass"
if NI_BENCH_HARNESS_SOURCE_ONLY=1 "$DRIVER" --help >/dev/null 2>&1; then
  fail "source-only mode was accepted on a direct invocation"
fi
pass "source-only mode refuses a direct invocation"

# --------------------------------------------------------------------------- #
# The parsers, over the four measured failures of 2026-09-09 and one success.
# --------------------------------------------------------------------------- #
expect_field() { # $1=facts file $2=key $3=exact expected value
  local got
  got="$(awk -F= -v k="$2" '$1==k{sub(/^[^=]*=/, ""); print; exit}' "$1")"
  [[ "$got" == "$3" ]] || fail "$(basename "$1"): $2 = '$got', expected '$3'"
}

parse_install() { # $1=fixture basename -> $TMP/facts
  ni_bench_parse_install_log "$FIXTURES/$1" > "$TMP/facts"
  [[ -s "$TMP/facts" ]] || fail "$1: the install parser produced nothing"
}

echo "== install parser: 2026-09-09 #162, the operator key on two transports"
parse_install install-162-operator-key-two-transports.log
expect_field "$TMP/facts" outcome failed
expect_field "$TMP/facts" failure_code install-failed-preflight-and-trust-gate
expect_field "$TMP/facts" failure_phase 1
expect_field "$TMP/facts" failure_phase_total 8
expect_field "$TMP/facts" failure_source serial-refusal-line
expect_field "$TMP/facts" phase_reached 1
expect_field "$TMP/facts" complete_line 0
pass "phase 1 refusal, code and phase read off the UART line"

echo "== install parser: 2026-09-09 P1.5a, the PCR policy counter floor"
parse_install install-p15a-pcr-policy-floor.log
expect_field "$TMP/facts" outcome failed
expect_field "$TMP/facts" failure_code install-failed-partition-and-encrypt
expect_field "$TMP/facts" failure_phase 2
expect_field "$TMP/facts" phase_reached 2
expect_field "$TMP/facts" pcr7_live b7f0f2a4c1d6e8093a5b2c7d4e1f8a6b0c3d9e2f5a8b1c4d7e0f3a6b9c2d5e81
expect_field "$TMP/facts" pcr7_policy f064008d40a05956e631f57623a476b6be7a52ff9afe647cc5fc11d790f2a6f4
expect_field "$TMP/facts" pcr7_available f064008d40a05956e631f57623a476b6be7a52ff9afe647cc5fc11d790f2a6f4,0d1c2b3a49586776859493a2b1c0dfee0d1c2b3a49586776859493a2b1c0dfee
pass "the destructive phase 2 refusal is distinguished from a phase 1 one"

echo "== install parser: 2026-09-09 #163, fuse-overlayfs absent from the container"
parse_install install-163-fuse-overlayfs-missing.log
expect_field "$TMP/facts" outcome failed
expect_field "$TMP/facts" failure_code install-failed-preflight-and-trust-gate
expect_field "$TMP/facts" failure_phase 1
expect_field "$TMP/facts" pcr7_live_source serial-log
pass "the pre-wipe container probe refusal stays in phase 1"

echo "== install parser: 2026-09-09 #164, --log-driver=passthrough on a TTY (LF-only capture)"
parse_install install-164-log-driver-passthrough-tty.log
expect_field "$TMP/facts" outcome failed
expect_field "$TMP/facts" failure_code install-failed-preflight-and-trust-gate
expect_field "$TMP/facts" failure_phase 1
pass "a console captured without CR is read identically"

echo "== install parser: the success this rehearsal exists to reach"
parse_install install-success.log
expect_field "$TMP/facts" outcome complete
expect_field "$TMP/facts" phase_reached 8
expect_field "$TMP/facts" failure_code none
expect_field "$TMP/facts" failure_line 0
expect_field "$TMP/facts" pcr7_live b7f0f2a4c1d6e8093a5b2c7d4e1f8a6b0c3d9e2f5a8b1c4d7e0f3a6b9c2d5e81
pass "the completion marker and the live PCR7 are both read"

echo "== install parser: the tty1 failure block, when a console is mirrored"
parse_install install-tty1-failure-block.log
expect_field "$TMP/facts" outcome failed
expect_field "$TMP/facts" failure_source tty1-failure-block
expect_field "$TMP/facts" failure_stage_name preflight-and-trust-gate
expect_field "$TMP/facts" failure_detail 4b1d9a70c3e2
expect_field "$TMP/facts" pcr7_live_source tty1-failure-block
expect_field "$TMP/facts" pcr7_verified_count 2
pass "the closed-vocabulary block is read without a UART refusal line"

echo "== install parser: an empty and a noise-only console are not a success"
: > "$TMP/empty.log"
ni_bench_parse_install_log "$TMP/empty.log" > "$TMP/facts"
expect_field "$TMP/facts" outcome incomplete
expect_field "$TMP/facts" phase_reached 0
printf 'nothing to see\ninstall completed successfully, honest\n' > "$TMP/noise.log"
ni_bench_parse_install_log "$TMP/noise.log" > "$TMP/facts"
expect_field "$TMP/facts" outcome incomplete
pass "silence and a lookalike sentence both read as incomplete, never complete"

echo "== install parser: a malformed value is dropped, never forwarded"
{
  printf '[neural-ice-autoinstall] [1/8] Preflight (t+0s)\r\n'
  printf '  Neural ICE CoreOS — INSTALL FAILED\r\n'
  printf '  failure code       install-failed-preflight-and-trust-gate; rm -rf /\r\n'
  printf '  live PCR7          not-a-digest\r\n'
  printf '  verified count     99999999\r\n'
  printf '  schema             neural-ice-installer-failure-evidence-v1\r\n'
} > "$TMP/dirty.log"
ni_bench_parse_install_log "$TMP/dirty.log" > "$TMP/facts"
expect_field "$TMP/facts" failure_code none
expect_field "$TMP/facts" pcr7_live none
expect_field "$TMP/facts" pcr7_verified_count none
pass "out-of-shape values become 'none' instead of reaching the receipt"

echo "== install parser: an unreadable log is a refusal, not an empty result"
if ni_bench_parse_install_log "$TMP/definitely-absent.log" >/dev/null 2>&1; then
  fail "the install parser accepted a missing log"
fi
if ni_bench_parse_firstboot_log "$TMP/definitely-absent.log" >/dev/null 2>&1; then
  fail "the first-boot parser accepted a missing log"
fi
pass "both parsers refuse a log they cannot read"

echo "== first-boot parser: a sealed, READY appliance"
ni_bench_parse_firstboot_log "$FIXTURES/firstboot-ready.log" > "$TMP/facts"
expect_field "$TMP/facts" firstboot_ready yes
expect_field "$TMP/facts" firstboot_status_failure none
expect_field "$TMP/facts" firstboot_device_trust_mark '[ OK ]'
expect_field "$TMP/facts" firstboot_device_trust 'device trust: sealed'
expect_field "$TMP/facts" firstboot_core_services '4/4 done'
pass "the ceremony and the core-service verdicts are read off the status mirror"

echo "== first-boot parser: a ceremony that never completed"
ni_bench_parse_firstboot_log "$FIXTURES/firstboot-ceremony-failure.log" > "$TMP/facts"
expect_field "$TMP/facts" firstboot_ready no
expect_field "$TMP/facts" firstboot_status_failure NI-E02
expect_field "$TMP/facts" firstboot_status_failure_unit neural-ice-firstboot-tpm-ceremony.service
expect_field "$TMP/facts" firstboot_device_trust_mark '[FAIL]'
pass "NI-E02 and its unit are named, and READY is withheld"

echo "== first-boot parser: the LAST state of a line wins, because the mirror is on change"
{
  printf 'neural-ice-status: [ .. ] Device trust: TPM owner ceremony running (3s)\r\n'
  printf 'neural-ice-status: [ OK ] Device trust: device trust: sealed\r\n'
} > "$TMP/change.log"
ni_bench_parse_firstboot_log "$TMP/change.log" > "$TMP/facts"
expect_field "$TMP/facts" firstboot_device_trust 'device trust: sealed'
pass "a superseded line does not survive into the receipt"

# --------------------------------------------------------------------------- #
# Argument refusals. Every one of these is checked before the driver looks at
# the host, so they run on any architecture, with no KVM and no medium.
# --------------------------------------------------------------------------- #
echo "== the driver refuses what it cannot bound"
refuses() { # $1=description, rest=arguments
  local description=$1
  shift
  if "$DRIVER" "$@" >/dev/null 2>&1; then
    fail "the driver accepted $description"
  fi
  pass "refuses $description"
}
MEDIUM="$TMP/medium.img"; : > "$MEDIUM"
VARS="$TMP/vars.fd"; : > "$VARS"
CODE="$TMP/code.fd"; : > "$CODE"
BASE=(--raw "$MEDIUM" --firmware-vars "$VARS" --firmware-code "$CODE")

refuses "no arguments at all"
refuses "a relative work directory" "${BASE[@]}" --work-dir relative
refuses "the root directory as a work directory" "${BASE[@]}" --work-dir /
refuses "a missing medium" --raw "$TMP/absent.img" --firmware-vars "$VARS" --work-dir /var/tmp/ni-bench
refuses "a missing variable store" --raw "$MEDIUM" --firmware-vars "$TMP/absent.fd" --work-dir /var/tmp/ni-bench
refuses "an unknown source transport" "${BASE[@]}" --work-dir /var/tmp/ni-bench --source-transport invented
refuses "an unknown target transport" "${BASE[@]}" --work-dir /var/tmp/ni-bench --target-transport invented
refuses "an unknown network mode" "${BASE[@]}" --work-dir /var/tmp/ni-bench --network bridged
refuses "a malformed target size" "${BASE[@]}" --work-dir /var/tmp/ni-bench --target-size huge
refuses "an unbounded install timeout" "${BASE[@]}" --work-dir /var/tmp/ni-bench --install-timeout 0
refuses "a malformed mirror address" "${BASE[@]}" --work-dir /var/tmp/ni-bench --mirror-ip registry.example
refuses "a mirror on an isolated network" "${BASE[@]}" --work-dir /var/tmp/ni-bench --network isolated --mirror-ip 10.0.0.1
refuses "a malformed enrolment owner GUID" "${BASE[@]}" --work-dir /var/tmp/ni-bench --enrol-cert "$CODE" --enrol-owner-guid nope
refuses "an unknown argument" "${BASE[@]}" --work-dir /var/tmp/ni-bench --wipe-the-host

# 🔴 The CI harness this driver sources also defines a `usage`. If the bench
# help is ever named `usage` again, sourcing silently replaces it and --help
# starts documenting arguments this script does not accept.
"$DRIVER" --help > "$TMP/help.txt"
grep -Fq -- 'bench-rehearse-medium.sh --raw FILE' "$TMP/help.txt" \
  || fail "--help prints another script's usage"
grep -Fq -- '--mirror-ip IP' "$TMP/help.txt" \
  || fail "the driver does not document its mirror argument"
grep -Fq -- 'qualify-installer-qemu.sh install' "$TMP/help.txt" \
  && fail "--help was replaced by the sourced CI harness's usage"
pass "--help states the bench contract and survives the sourced harness"

# --------------------------------------------------------------------------- #
# The contracts a future edit must not quietly drop. Same discipline as
# image/test-qualify-installer-qemu.sh: literal source strings, matched exactly.
# --------------------------------------------------------------------------- #
echo "== the driver keeps its load-bearing contracts"
# shellcheck disable=SC2016 # literal source contracts are being matched
for contract in \
  'readonly=on,file=$raw' \
  '-b "$raw" -F raw "$medium_overlay_file"' \
  'medium_overlay_file=$work_dir/medium.qcow2' \
  'virt,accel=kvm,gic-version=3' \
  'manufacturer=NVIDIA,product=NVIDIA_DGX_Spark' \
  'manufacturer=NVIDIA,product=P4242' \
  'swtpm socket --tpm2 --tpmstate "dir=$tpm_dir"' \
  'type=unixio,path=$tpm_ctrl,mode=0600' \
  '-nographic -no-reboot' \
  'user,model=virtio-net-pci' \
  'hostfwd=tcp:127.0.0.1:${ssh_port}-:22' \
  'trap cleanup EXIT' \
  'terminate_qemu_session "$timeout_pid"' \
  'stop_task_process "$pid" swtpm' \
  '--set-pk "$enrol_owner_guid" "$enrol_cert"' \
  '--secure-boot' \
  'SecureBootEnable +: bool: ON' \
  'the work directory already exists' \
  'this rehearsal does not need root' \
  'NeuralICEInstallerFailure' \
  '870a0500-25d2-574e-a1cc-79a69630bf96' \
  'bench-rehearsal-receipt.json'; do
  grep -Fq -- "$contract" "$DRIVER" || fail "the driver lost: $contract"
done
pass "medium read-only, KVM machine, DMI identity, swtpm, bounds and receipt"

# 🔴 A NEGATIVE GREP MUST NOT MEASURE THE COMMENT THAT EXPLAINS IT. The prose
# above each of these checks names the very string being forbidden, so the code
# is separated from the comments on BOTH sides — and the separation is then
# SABOTAGED to prove the check still fires.
code_only() { grep -v '^[[:space:]]*#' "$1"; }

sabotage="$TMP/sabotaged-driver.sh"
cp -- "$DRIVER" "$sabotage"
printf 'nic="user,model=virtio-net-pci,restrict=on"\n' >> "$sabotage"
code_only "$sabotage" | grep -Fq 'restrict=on' \
  || fail "the isolation check cannot see a real restrict=on and proves nothing"
pass "the isolation check fires on a sabotaged copy"

# restrict=on is the one thing this driver must NOT inherit from the CI harness:
# QEMU documents it as "the guest will be isolated ... no guest IP packets will
# be routed over the host to the outside" (qemu-system.1, -netdev user), which is
# precisely the bench mirror becoming unreachable.
if code_only "$DRIVER" | grep -Fq 'restrict=on'; then
  fail "the bench driver isolates the guest and can never reach the LAN mirror"
fi
pass "the guest is not slirp-isolated, so the bench mirror is reachable"

# The verdict must be the exit code. A rehearsal that did not install is a failed
# rehearsal even when every process was cleaned up.
# shellcheck disable=SC2016 # literal source contract is being matched
grep -Fq 'die "the medium did not complete its installation' "$DRIVER" \
  || fail "the driver can report success after a medium that did not install"
# shellcheck disable=SC2016 # literal source contract is being matched
grep -Fq 'die "the installed appliance never opened TCP/22' "$DRIVER" \
  || fail "the driver can report success after a first boot that never served SSH"
pass "the exit code is the verdict, for both phases"

# Nothing outside the work directory: every artefact path is derived from it.
# shellcheck disable=SC2016 # literal source contracts are being matched
grep -Eq '^receipt=\$work_dir/bench-rehearsal-receipt\.json$' "$DRIVER" \
  || fail "the receipt is not written inside the work directory"
# shellcheck disable=SC2016 # literal source contract is being matched
grep -Eq '^target=\$work_dir/target\.qcow2$' "$DRIVER" \
  || fail "the target disk is not created inside the work directory"
# shellcheck disable=SC2016 # literal source contract is being matched
grep -Eq '^vars=\$work_dir/AAVMF_VARS\.fd$' "$DRIVER" \
  || fail "the variable store is not copied inside the work directory"
# shellcheck disable=SC2016 # literal source contract is being matched
grep -Eq '^tpm_dir=\$work_dir/tpmstate$' "$DRIVER" \
  || fail "the software TPM state is not kept inside the work directory"
pass "every artefact this run creates lives under --work-dir"

# The bench's hardware TPM is never named, let alone opened. Comments are
# excluded on both sides for the same reason as above.
for device in /dev/tpm0 /dev/tpmrm0; do
  if code_only "$DRIVER" | grep -Fq -- "$device"; then
    fail "the driver reaches for the bench hardware TPM at $device"
  fi
done
printf 'swtpm --tpmstate dir=/dev/tpm0\n' >> "$sabotage"
code_only "$sabotage" | grep -Fq -- '/dev/tpm0' \
  || fail "the hardware-TPM check cannot see a real reference and proves nothing"
pass "the bench hardware TPM is never referenced, and the check fires when it is"

echo "BENCH_REHEARSAL_PARSER_OK"
