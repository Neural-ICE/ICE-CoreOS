#!/usr/bin/env bash
# Real TPM 2.0 qualification for the dormant owner-sealed OTA NV helper.
# This suite always selects a task-owned SWTPM socket; it never probes /dev/tpm.
set -euo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HELPER="$ROOT/ota/neural-ice-ota-tpm-state.sh"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/ni-owner-ota-swtpm.XXXXXX")"
SWTPM_PID=""
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
expect_refusal() {
  local why=$1
  shift
  if "$@" >"$TMP/refused.stdout" 2>"$TMP/refused.stderr"; then fail "$why"; fi
  : >"$TMP/refused.stdout"; : >"$TMP/refused.stderr"
}
expect_tpm_refusal() {
  local why=$1 expected_code=$2
  shift 2
  if "$@" >"$TMP/refused.stdout" 2>"$TMP/refused.stderr"; then fail "$why"; fi
  if grep -Eqi 'usage:|could not load tcti|invalid option|unknown option|no such file' \
      "$TMP/refused.stdout" "$TMP/refused.stderr"; then
    fail "$why failed in the CLI/TCTI instead of the TPM"
  fi
  grep -Eqi '(TPM|Esys_).*(0x[0-9a-f]+|TPM_RC_)|(0x[0-9a-f]+|TPM_RC_).*(TPM|Esys_)' \
    "$TMP/refused.stdout" "$TMP/refused.stderr" \
    || fail "$why produced no classified TPM/TSS refusal"
  grep -Eqi "0x0*$expected_code([^0-9a-f]|$)" "$TMP/refused.stdout" "$TMP/refused.stderr" \
    || fail "$why did not return expected TPM code 0x$expected_code"
  printf 'TPM_REFUSAL %s [0x%s]\n' "$why" "$expected_code" >>"$TMP/tpm-refusals.log"
}
cleanup() {
  if [[ -n "$SWTPM_PID" ]]; then
    kill "$SWTPM_PID" 2>/dev/null || true
    wait "$SWTPM_PID" 2>/dev/null || true
  fi
  rm -rf -- "$TMP"
}
trap cleanup EXIT

for command in swtpm tpm2_startup tpm2_shutdown tpm2_getcap tpm2_nvdefine \
  tpm2_nvundefine tpm2_nvread tpm2_nvwrite tpm2_nvwritelock tpm2_nvincrement \
  tpm2_nvextend tpm2_nvreadpublic tpm2_startauthsession tpm2_policycommandcode \
  tpm2_policyor tpm2_flushcontext tpm2_clearcontrol tpm2_clear tpm2_changeauth \
  python3 flock sha256sum od wc awk cmp; do
  command -v "$command" >/dev/null 2>&1 \
    || fail "$command is unavailable; the real-TPM suite cannot report green"
done
[[ "$EUID" -ne 0 ]] || fail "run this isolated SWTPM suite as a non-root user"

TOOLS="$TMP/tools"; mkdir -m 0700 "$TOOLS"
for command in tpm2_getcap tpm2_nvdefine tpm2_nvread tpm2_nvwrite \
  tpm2_nvwritelock tpm2_nvextend tpm2_nvreadpublic tpm2_startauthsession \
  tpm2_policycommandcode tpm2_policyor tpm2_flushcontext tpm2_clearcontrol \
  python3 flock; do ln -s "$(command -v "$command")" "$TOOLS/$command"; done
export NI_OTA_TPM_STATE_TESTING=1
export NI_OTA_TPM_STATE_TEST_TOOLS="$TOOLS"
export NI_OTA_TPM_STATE_TEST_RUN_DIR="$TMP/run"
ota() { bash "$HELPER" "$@"; }

stop_swtpm() {
  if [[ -n "$SWTPM_PID" ]]; then
    kill "$SWTPM_PID" 2>/dev/null || true
    wait "$SWTPM_PID" 2>/dev/null || true
    SWTPM_PID=""
  fi
  rm -f -- "$TMP/tpm.sock" "$TMP/tpm.sock.ctrl"
}
start_swtpm() {
  local state=$1 startup=${2:-yes}
  stop_swtpm
  install -d -m 0700 "$state"
  swtpm socket --tpm2 --tpmstate "dir=$state" \
    --ctrl "type=unixio,path=$TMP/tpm.sock.ctrl" \
    --server "type=unixio,path=$TMP/tpm.sock" \
    --flags not-need-init,startup-clear >"$TMP/swtpm.log" 2>&1 &
  SWTPM_PID=$!
  for _ in $(seq 1 50); do [[ -S "$TMP/tpm.sock" ]] && break; sleep 0.1; done
  [[ -S "$TMP/tpm.sock" ]] || fail "SWTPM socket did not appear"
  export TPM2TOOLS_TCTI="swtpm:path=$TMP/tpm.sock"
  if [[ "$startup" == yes ]]; then
    tpm2_startup -c >/dev/null 2>&1 || true
  fi
  tpm2_getcap properties-fixed >/dev/null 2>&1 || fail "tpm2-tools cannot reach SWTPM"
}
shutdown_swtpm() {
  tpm2_shutdown -c >/dev/null
  stop_swtpm
}
property() {
  local name=$1
  tpm2_getcap properties-variable | awk -F: -v wanted="$name" '
    $1 ~ "^[[:space:]]*" wanted "[[:space:]]*$" {gsub(/[^0-9]/,"",$2); print $2}'
}
policy_digest() {
  local command_code=$1 output=$2
  tpm2_startauthsession -S "$TMP/trial.ctx" >/dev/null
  tpm2_policycommandcode -S "$TMP/trial.ctx" -L "$output" "$command_code" >/dev/null
  tpm2_flushcontext "$TMP/trial.ctx" >/dev/null 2>&1 || true
}
policy_extend() {
  rm -f "$TMP/extend.ctx"
  tpm2_startauthsession --policy-session -S "$TMP/extend.ctx" >/dev/null
  tpm2_policycommandcode -S "$TMP/extend.ctx" TPM2_CC_NV_Extend >/dev/null
}
policy_floor_write() {
  policy_digest TPM2_CC_NV_Write "$TMP/write.digest"
  policy_digest TPM2_CC_NV_WriteLock "$TMP/writelock.digest"
  rm -f "$TMP/floor-write.ctx"
  tpm2_startauthsession --policy-session -S "$TMP/floor-write.ctx" >/dev/null
  tpm2_policycommandcode -S "$TMP/floor-write.ctx" TPM2_CC_NV_Write >/dev/null
  tpm2_policyor -S "$TMP/floor-write.ctx" \
    "sha256:$TMP/write.digest,$TMP/writelock.digest" >/dev/null
}
snapshot_nv() {
  local prefix=$1
  tpm2_nvreadpublic 0x01500001 >"$prefix.floor.public"
  tpm2_nvreadpublic 0x01500002 >"$prefix.anchor.public"
  tpm2_nvread 0x01500001 -C 0x01500001 -s 8 -o "$prefix.floor.bin" >/dev/null
  if ! tpm2_nvread 0x01500002 -C 0x01500002 -s 32 -o "$prefix.anchor.bin" \
      >/dev/null 2>&1; then
    rm -f -- "$prefix.anchor.bin"
  fi
}
compare_nv() {
  local before=$1 after=$2 part
  for part in floor.public anchor.public floor.bin; do
    cmp "$before.$part" "$after.$part" || fail "refused TPM operation changed $part"
  done
  if [[ -e "$before.anchor.bin" ]]; then
    [[ -e "$after.anchor.bin" ]] || fail "refused TPM operation uninitialized the anchor"
    cmp "$before.anchor.bin" "$after.anchor.bin" || fail "refused TPM operation changed anchor.bin"
  else
    [[ ! -e "$after.anchor.bin" ]] || fail "refused TPM operation initialized the anchor"
  fi
}

# Main lifecycle. A prior counter reaches a nonzero TPM-wide high-water, while
# the baseline floor remains the exact ordinary 8-byte value supplied by the
# authenticated future caller.
MAIN="$TMP/main-state"; start_swtpm "$MAIN"
policy_digest TPM2_CC_NV_Increment "$TMP/increment.digest"
tpm2_nvdefine 0x0150000e -C o -s 8 -g sha256 \
  -a 'policywrite|authread|ownerread|nt=counter' -L "$TMP/increment.digest" >/dev/null
for _ in 1 2 3 4; do
  tpm2_startauthsession --policy-session -S "$TMP/increment.ctx" >/dev/null
  tpm2_policycommandcode -S "$TMP/increment.ctx" TPM2_CC_NV_Increment >/dev/null
  tpm2_nvincrement 0x0150000e -C 0x0150000e -P "session:$TMP/increment.ctx" >/dev/null
  tpm2_flushcontext "$TMP/increment.ctx" >/dev/null 2>&1 || true
done
tpm2_nvundefine 0x0150000e -C o >/dev/null

[[ "$(ota prepare 42)" == prepared ]] || fail "real TPM prepare did not complete"
inspection="$(ota inspect)"
python3 - "$inspection" <<'PY'
import json,sys
value=json.loads(sys.argv[1])
assert value["baseline_floor"] == 42
assert value["anchor_sha256"] is None
assert value["anchor_state"] == "pristine"
assert value["owner_sealed"] is False and value["clear_protected"] is False
PY
tpm2_nvread 0x01500001 -C 0x01500001 -s 8 -o "$TMP/floor.bin" >/dev/null
python3 - "$TMP/floor.bin" <<'PY'
import struct,sys
assert struct.unpack(">Q",open(sys.argv[1],"rb").read())[0] == 42
PY

# The only anchor write authority is PolicyCommandCode(NV_Extend).
python3 - "$TMP/input.bin" <<'PY'
import sys
open(sys.argv[1],"wb").write(bytes(32))
PY
snapshot_nv "$TMP/password.before"
expect_tpm_refusal "password-authorized NV_Extend succeeded" 12f \
  tpm2_nvextend 0x01500002 -C 0x01500002 -i "$TMP/input.bin"
snapshot_nv "$TMP/password.after"; compare_nv "$TMP/password.before" "$TMP/password.after"
expect_refusal "runtime extension succeeded before owner sealing" ota extend "$(printf '11%.0s' {1..32})"
[[ "$(ota clear-protection)" == protected ]] || fail "disableClear was not set"
[[ "$(property disableClear)" == 1 ]] || fail "disableClear did not read back"
expect_refusal "clear-protection replay was accepted" ota clear-protection

python3 - "$TMP/owner.auth" <<'PY'
import os,sys
open(sys.argv[1],"wb").write(os.urandom(32))
PY
tpm2_changeauth -c o "file:$TMP/owner.auth" >/dev/null
python3 - "$TMP/owner.auth" <<'PY'
import os,sys
p=sys.argv[1]
with open(p,"r+b") as f: f.write(bytes(32)); f.flush(); os.fsync(f.fileno())
os.unlink(p)
PY
[[ "$(property ownerAuthSet)" == 1 ]] || fail "test owner hierarchy was not sealed"
first="$(ota extend "$(printf '11%.0s' {1..32})")"
[[ "$first" == 8878b15a7d6a3a4f464e8f9f42591dbc0cf4bedea0ec309003d2b2ee53655ef8 ]] \
  || fail "first real anchor extension mismatched"

snapshot_nv "$TMP/sealed.before"
policy_floor_write
expect_tpm_refusal "write-locked floor accepted policy-authorized NV_Write" 148 \
  tpm2_nvwrite 0x01500001 -C 0x01500001 -P "session:$TMP/floor-write.ctx" -i "$TMP/floor.bin"
tpm2_flushcontext "$TMP/floor-write.ctx" >/dev/null 2>&1 || true
policy_extend
expect_tpm_refusal "anchor accepted NV_ChangeAuth under its Extend policy" 9a4 \
  tpm2_changeauth -c 0x01500002 -p "session:$TMP/extend.ctx" str:attacker
tpm2_flushcontext "$TMP/extend.ctx" >/dev/null 2>&1 || true
policy_extend
expect_tpm_refusal "anchor accepted NV_Write under its Extend policy" 9a4 \
  tpm2_nvwrite 0x01500002 -C 0x01500002 -P "session:$TMP/extend.ctx" -i "$TMP/input.bin"
tpm2_flushcontext "$TMP/extend.ctx" >/dev/null 2>&1 || true
expect_tpm_refusal "runtime owner undefined floor" 9a2 tpm2_nvundefine 0x01500001 -C o
expect_tpm_refusal "runtime owner undefined anchor" 9a2 tpm2_nvundefine 0x01500002 -C o
expect_tpm_refusal "runtime owner redefined an NV index" 9a2 \
  tpm2_nvdefine 0x0150000e -C o -s 8 -a 'ownerread|ownerwrite'
snapshot_nv "$TMP/sealed.after"; compare_nv "$TMP/sealed.before" "$TMP/sealed.after"

# The exact public state, protection, and policy-only writer survive an orderly
# TPM restart. Lockout cannot Clear while disableClear is set.
tpm2_nvreadpublic 0x01500001 >"$TMP/floor.before"
tpm2_nvreadpublic 0x01500002 >"$TMP/anchor.before"
shutdown_swtpm; start_swtpm "$MAIN"
cmp "$TMP/floor.before" <(tpm2_nvreadpublic 0x01500001) \
  || fail "floor public area changed across restart"
cmp "$TMP/anchor.before" <(tpm2_nvreadpublic 0x01500002) \
  || fail "anchor public area changed across restart"
[[ "$(property disableClear)" == 1 ]] || fail "disableClear did not survive restart"
snapshot_nv "$TMP/restart-write.before"
policy_floor_write
expect_tpm_refusal "restarted write-locked floor accepted policy-authorized NV_Write" 148 \
  tpm2_nvwrite 0x01500001 -C 0x01500001 -P "session:$TMP/floor-write.ctx" -i "$TMP/floor.bin"
tpm2_flushcontext "$TMP/floor-write.ctx" >/dev/null 2>&1 || true
snapshot_nv "$TMP/restart-write.after"
compare_nv "$TMP/restart-write.before" "$TMP/restart-write.after"
second="$(ota extend "$(printf '22%.0s' {1..32})")"
[[ "$second" == 78830000e1197790a7e1884139a65721210d642ad112e6c9899a05cb214027a5 ]] \
  || fail "post-restart anchor extension mismatched"
snapshot_nv "$TMP/clear.before"
expect_tpm_refusal "Lockout Clear succeeded despite disableClear" 120 tpm2_clear -c l
snapshot_nv "$TMP/clear.after"; compare_nv "$TMP/clear.before" "$TMP/clear.after"
shutdown_swtpm

# A prepared-but-unprotected state cannot be used by a sealed runtime.
UNPROTECTED="$TMP/unprotected-state"; start_swtpm "$UNPROTECTED"
ota prepare 42 >/dev/null
python3 - "$TMP/owner.auth" <<'PY'
import os,sys
open(sys.argv[1],"wb").write(os.urandom(32))
PY
tpm2_changeauth -c o "file:$TMP/owner.auth" >/dev/null
rm -f "$TMP/owner.auth"
expect_refusal "sealed runtime extended without disableClear" ota extend "$(printf '33%.0s' {1..32})"
shutdown_swtpm

# Partial state is never completed. Compare handles around the refusal so the
# test proves the helper did not define the missing companion index.
PARTIAL="$TMP/partial-state"; start_swtpm "$PARTIAL"
policy_digest TPM2_CC_NV_Write "$TMP/write.digest"
tpm2_nvdefine 0x01500001 -C o -s 8 -g sha256 \
  -a 'policywrite|authread|ownerread|writedefine' -L "$TMP/write.digest" >/dev/null
tpm2_getcap handles-nv-index >"$TMP/partial.before"
expect_refusal "partial state was repaired" ota prepare 42
tpm2_getcap handles-nv-index >"$TMP/partial.after"
cmp "$TMP/partial.before" "$TMP/partial.after" || fail "partial refusal changed NV handles"
shutdown_swtpm

# Two present indices with a foreign public area are refused by every reader
# before clear protection can mutate a permanent TPM property.
FOREIGN="$TMP/foreign-state"; start_swtpm "$FOREIGN"
policy_digest TPM2_CC_NV_Write "$TMP/write.digest"
policy_digest TPM2_CC_NV_Extend "$TMP/extend.digest"
tpm2_nvdefine 0x01500001 -C o -s 8 -g sha256 \
  -a 'ownerwrite|ownerread|authread' -L "$TMP/write.digest" >/dev/null
tpm2_nvdefine 0x01500002 -C o -s 32 -g sha256 \
  -a 'policywrite|authread|ownerread|no_da|nt=extend' -L "$TMP/extend.digest" >/dev/null
expect_refusal "foreign public area passed inspect" ota inspect
expect_refusal "foreign public area reached ClearControl" ota clear-protection
[[ "$(property disableClear)" == 0 ]] || fail "foreign state changed disableClear"
tpm2_shutdown -c >/dev/null

# Product code contains no reset/recovery primitive; Clear is test-driver-only.
! grep -Eq 'tpm2_clear([^a-z]|$)|tpm2_nvundefine|clearcontrol.*[[:space:]]c([[:space:]]|$)' "$HELPER" \
  || fail "the product helper contains a forbidden Clear/undefine path"
cat "$TMP/tpm-refusals.log"
printf 'SWTPM_OWNER_OTA_STATE_TEST_OK\n'
