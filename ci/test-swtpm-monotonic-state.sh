#!/usr/bin/env bash
# Exercise the appliance TPM lifecycle against a real TPM 2.0 implementation.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HELPER="$ROOT/ota/neural-ice-tpm-state.sh"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/ni-swtpm.XXXXXX")"
fail() { echo "FAIL: $*" >&2; exit 1; }
SWTPM_PID=""
cleanup() {
  if [[ -n "$SWTPM_PID" ]]; then
    kill "$SWTPM_PID" 2>/dev/null || true
    wait "$SWTPM_PID" 2>/dev/null || true
  fi
  rm -rf "$TMP"
}
trap cleanup EXIT

for tool in swtpm tpm2_getcap tpm2_nvdefine tpm2_nvincrement tpm2_nvundefine \
  tpm2_nvread tpm2_nvwrite tpm2_nvwritelock tpm2_nvreadpublic \
  tpm2_startauthsession tpm2_policycommandcode tpm2_policyor tpm2_flushcontext \
  tpm2_changeauth tpm2_clear tpm2_createprimary tpm2_evictcontrol \
  tpm2_readpublic cryptsetup truncate python3 flock sha256sum od head wc awk cmp; do
  command -v "$tool" >/dev/null 2>&1 \
    || fail "$tool is unavailable; the real-TPM suite must not report green without it"
done

mkdir -p "$TMP/state"
start_swtpm() {
  rm -f "$TMP/swtpm.sock" "$TMP/swtpm.sock.ctrl"
  swtpm socket --tpm2 --tpmstate "dir=$TMP/state" \
    --ctrl "type=unixio,path=$TMP/swtpm.sock.ctrl" \
    --server "type=unixio,path=$TMP/swtpm.sock" \
    --flags not-need-init,startup-clear >>"$TMP/swtpm.log" 2>&1 &
  SWTPM_PID=$!
  for _ in $(seq 1 50); do
    [[ -S "$TMP/swtpm.sock" ]] && break
    sleep 0.1
  done
  [[ -S "$TMP/swtpm.sock" ]] || fail "swtpm did not come up"
  export TPM2TOOLS_TCTI="swtpm:path=$TMP/swtpm.sock"
  for _ in $(seq 1 50); do
    tpm2_getcap properties-fixed >/dev/null 2>&1 && return
    sleep 0.1
  done
  fail "tpm2-tools cannot talk to swtpm"
}
stop_swtpm() {
  kill "$SWTPM_PID" 2>/dev/null || true
  wait "$SWTPM_PID" 2>/dev/null || true
  SWTPM_PID=""
}
start_swtpm

TOOLS="$TMP/tools"
mkdir -p "$TOOLS"
for tool in python3 flock sha256sum od head wc awk tpm2_getcap tpm2_nvdefine \
  tpm2_nvincrement tpm2_nvread tpm2_nvwrite tpm2_nvwritelock tpm2_nvreadpublic \
  tpm2_startauthsession tpm2_policycommandcode tpm2_policyor tpm2_flushcontext; do
  ln -sf "$(command -v "$tool")" "$TOOLS/$tool"
done
REAL_CHANGEAUTH="$(command -v tpm2_changeauth)"
cat > "$TOOLS/tpm2_changeauth" <<EOF
#!/bin/sh
[ "\${NI_TEST_CHANGEAUTH_FAIL:-}" != 1 ] || exit 97
exec "$REAL_CHANGEAUTH" "\$@"
EOF
chmod +x "$TOOLS/tpm2_changeauth"
export NI_TPM_STATE_TESTING=1
export NI_TPM_STATE_TEST_TOOLS="$TOOLS"
export NI_TPM_STATE_TEST_RUN_DIR="$TMP/run"
hw() { bash "$HELPER" "$@"; }
readonly PROFILE=customer-locked
readonly TARGET=nvidia-gb10-arm64
readonly POLICY=neural-ice-secureboot-lab-v1
readonly FIRSTBOOT="$ROOT/ota/neural-ice-firstboot-tpm-ceremony.sh"
PCR_POLICY_CANDIDATE=1

clear_tpm() {
  tpm2_clear -c l >/dev/null 2>&1 || tpm2_clear -c p >/dev/null 2>&1 \
    || fail "the TPM clear recovery path failed"
}
persist_prerequisites() {
  tpm2_createprimary -C e -g sha256 -G ecc \
    -c "$TMP/device-root.ctx" >/dev/null
  tpm2_evictcontrol -C o -c "$TMP/device-root.ctx" 0x81010005 >/dev/null
  tpm2_flushcontext "$TMP/device-root.ctx" >/dev/null 2>&1 || true
  tpm2_flushcontext -t >/dev/null 2>&1 || true
  tpm2_createprimary -C o -g sha256 -G rsa \
    -c "$TMP/srk.ctx" >/dev/null
  tpm2_evictcontrol -C o -c "$TMP/srk.ctx" 0x81000001 >/dev/null
  tpm2_flushcontext "$TMP/srk.ctx" >/dev/null 2>&1 || true
  tpm2_flushcontext -t >/dev/null 2>&1 || true
  if ! tpm2_nvreadpublic 0x01500007 >/dev/null 2>&1; then
    local candidate="$PCR_POLICY_CANDIDATE"
    [[ "$(hw pcr-policy-check "$candidate")" == 0 ]] \
      || fail "virgin signed PCR policy was refused"
    [[ "$(hw pcr-policy-activate "$candidate")" == "$candidate" ]] \
      || fail "signed PCR policy activation did not commit"
    expect_refusal "activated PCR policy sequence replayed" \
      hw pcr-policy-check "$candidate"
    if (( candidate > 1 )); then
      expect_refusal "lower PCR policy sequence replayed" \
        hw pcr-policy-check "$(( candidate - 1 ))"
    fi
    [[ "$(hw pcr-policy-check "$(( candidate + 1 ))")" == "$candidate" ]] \
      || fail "the next PCR policy generation was not eligible without mutation"
    PCR_POLICY_CANDIDATE=$(( candidate + 1 ))
  fi
}
abs_counter() {
  tpm2_nvread "$1" -C "$1" -s 8 -o "$TMP/value.bin" >/dev/null
  python3 - "$TMP/value.bin" <<'PY'
import struct, sys
print(struct.unpack(">Q", open(sys.argv[1], "rb").read())[0])
PY
}
expect_refusal() {
  local description="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    fail "$description"
  fi
}
interrupt_before_owner_auth() {
  local output prepared install_at freshness_at
  prepared="$(hw ceremony-prepare "$PROFILE" "$TARGET" "$POLICY" 0)"
  read -r install_at freshness_at _ <<<"$prepared"
  output="$(NI_TEST_CHANGEAUTH_FAIL=1 hw ceremony-finalize "$PROFILE" "$TARGET" "$POLICY" \
    aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    "$install_at" "$freshness_at" 2>&1)" \
    && fail "injected owner-auth interruption succeeded"
  grep -Fq 'TPM refused to take a new owner authorization' <<<"$output" \
    || fail "ceremony failed before the injected owner-auth interruption: $output"
  for index in 0x01500003 0x01500004 0x01500005 0x01500006 0x01500007; do
    tpm2_nvreadpublic "$index" >/dev/null \
      || fail "injected interruption did not leave completed fixed state at $index"
  done
}

# Policy constants and platform-only delete semantics are measured, not mocked.
policy_digest() {
  tpm2_startauthsession -S "$TMP/trial.ctx" >/dev/null
  tpm2_policycommandcode -S "$TMP/trial.ctx" -L "$TMP/p.digest" "$1" >/dev/null
  tpm2_flushcontext "$TMP/trial.ctx" >/dev/null 2>&1 || true
  od -An -tx1 -v "$TMP/p.digest" | tr -d '[:space:]'
}
[[ "$(policy_digest TPM2_CC_NV_Increment)" == e8c02d3c5e701670cbaa327db1a2e9f3f41b2c22793e5c669a6e7f44b912f6c0 ]] \
  || fail "unexpected NV_Increment policy digest"
tpm2_nvdefine 0x0150000f -C o -s 8 \
  -a "policywrite|authread|ownerread|policydelete|nt=counter" -L "$TMP/p.digest" \
  >/dev/null 2>&1 && fail "owner hierarchy accepted TPMA_NV_POLICY_DELETE"

# Runtime absence is fail-closed; only an explicit ceremony preflight may call
# an entirely empty TPM state virgin.
[[ "$(hw provisioning-status)" == virgin ]] || fail "empty TPM is not virgin"
expect_refusal "runtime read accepted missing install state" hw counter-read
expect_refusal "runtime read accepted missing freshness state" hw freshness-read
expect_refusal "profile-bind created missing runtime state" hw profile-bind "$PROFILE" "$TARGET" "$POLICY"
for index in 0x01500003 0x01500004 0x01500005 0x01500006 0x01500007; do
  expect_refusal "a runtime read created $index" tpm2_nvreadpublic "$index"
done

# An interruption after fixed state creation but before owner authorization
# leaves permanent evidence. Deleting record alone, then record+freshness, may
# never manufacture a new virgin transition.
persist_prerequisites
interrupt_before_owner_auth
[[ "$(tpm2_getcap properties-variable | awk -F: '/ownerAuthSet/{gsub(/[^0-9]/,"",$2); print $2}')" == 0 ]] \
  || fail "interrupted ceremony changed owner authorization"
tpm2_nvundefine 0x01500005 -C o >/dev/null
expect_refusal "record-only deletion before seal was accepted as virgin" hw provisioning-status
expect_refusal "record-only deletion before seal restarted ceremony" hw ceremony-prepare "$PROFILE" "$TARGET" "$POLICY" 0
tpm2_nvundefine 0x01500004 -C o >/dev/null
expect_refusal "record+freshness deletion before seal was accepted as virgin" hw provisioning-status
expect_refusal "record+freshness deletion before seal restarted ceremony" hw ceremony-prepare "$PROFILE" "$TARGET" "$POLICY" 0

# Stage a real written-but-unlocked record and prove no path completes it.
clear_tpm
persist_prerequisites
interrupt_before_owner_auth
tpm2_nvundefine 0x01500005 -C o >/dev/null
tpm2_startauthsession -S "$TMP/trial.ctx" >/dev/null
tpm2_policycommandcode -S "$TMP/trial.ctx" -L "$TMP/write.digest" TPM2_CC_NV_Write >/dev/null
tpm2_flushcontext "$TMP/trial.ctx" >/dev/null 2>&1 || true
tpm2_startauthsession -S "$TMP/trial.ctx" >/dev/null
tpm2_policycommandcode -S "$TMP/trial.ctx" -L "$TMP/lock.digest" TPM2_CC_NV_WriteLock >/dev/null
tpm2_flushcontext "$TMP/trial.ctx" >/dev/null 2>&1 || true
tpm2_startauthsession -S "$TMP/trial.ctx" >/dev/null
tpm2_policyor -S "$TMP/trial.ctx" -L "$TMP/record.policy" \
  "sha256:$TMP/write.digest,$TMP/lock.digest" >/dev/null
tpm2_flushcontext "$TMP/trial.ctx" >/dev/null 2>&1 || true
tpm2_nvdefine 0x01500005 -C o -s 64 \
  -a "policywrite|authread|ownerread|writedefine" -L "$TMP/record.policy" >/dev/null
digest="$(hw profile-digest "$PROFILE" "$TARGET" "$POLICY")"
python3 - "$digest" "$TMP/record.bin" <<'PY'
import sys
open(sys.argv[2], "wb").write((b"NI-TPM02" + bytes.fromhex(sys.argv[1])).ljust(64, b"\0"))
PY
tpm2_startauthsession --policy-session -S "$TMP/write.ctx" >/dev/null
tpm2_policycommandcode -S "$TMP/write.ctx" TPM2_CC_NV_Write >/dev/null
tpm2_policyor -S "$TMP/write.ctx" "sha256:$TMP/write.digest,$TMP/lock.digest" >/dev/null
tpm2_nvwrite 0x01500005 -C 0x01500005 -P "session:$TMP/write.ctx" \
  -i "$TMP/record.bin" >/dev/null
tpm2_flushcontext "$TMP/write.ctx" >/dev/null 2>&1 || true
expect_refusal "profile-read accepted written-but-unlocked state" hw profile-read
expect_refusal "profile-bind completed written-but-unlocked state" hw profile-bind "$PROFILE" "$TARGET" "$POLICY"
expect_refusal "ceremony completed written-but-unlocked state" hw ceremony-prepare "$PROFILE" "$TARGET" "$POLICY" 0

# An attacker-known pre-existing owner authorization is not ceremony evidence.
clear_tpm
persist_prerequisites
"$REAL_CHANGEAUTH" -c o str:attacker-known >/dev/null
expect_refusal "attacker-known owner auth was accepted" hw ceremony-prepare "$PROFILE" "$TARGET" "$POLICY" 0
clear_tpm

# Exercise the mandatory wrapper against the real TPM. Its test paths are
# accepted only for an unprivileged process; the production root path remains
# pinned to the immutable image and real LUKS devices.
FB_TOOLS="$TMP/firstboot-tools"
FB_STATE="$TMP/firstboot-state"
FB_RUN="$TMP/firstboot-run"
FB_SYSTEM_LUKS="$TMP/system-luks"
FB_DATA_LUKS="$TMP/data-luks"
FB_ACCESS_POLICY="$TMP/access-policy"
FB_HARDWARE_TARGET="$TMP/hardware-target"
FB_TRUST_POLICY="$TMP/trust-policy"
mkdir -p "$FB_TOOLS" "$FB_RUN"
: > "$FB_SYSTEM_LUKS"; : > "$FB_DATA_LUKS"
printf '%s\n' "$PROFILE" > "$FB_ACCESS_POLICY"
printf '%s\n' "$TARGET" > "$FB_HARDWARE_TARGET"
printf '%s\n' "$POLICY" > "$FB_TRUST_POLICY"
cat > "$FB_TOOLS/tpm-state" <<EOF
#!/bin/sh
exec bash "$HELPER" "\$@"
EOF
cat > "$FB_TOOLS/device-root" <<'EOF'
#!/bin/sh
[ "$1" = attest ] && [ "$2" = --identity ] || exit 2
tmp="${TMPDIR:-/tmp}/ni-device-root-live.$$"
trap 'rm -f -- "$tmp"' EXIT
tpm2_readpublic -Q -c 0x81010005 -f tpmt -o "$tmp" || exit 1
cmp -s "$tmp" "$3"
EOF
cat > "$FB_TOOLS/systemd-analyze" <<'EOF'
#!/bin/sh
[ "$1" = srk ] || exit 2
# The real systemd-analyze srk emits the marshalled TPM2B_PUBLIC (size-prefixed),
# which is what the installer persists as srk-v1.tpm2b_public and what the
# LUKS token's Esys serialization embeds. tpm2_readpublic -f tpmt lacks the size.
tpm2_readpublic -Q -c 0x81000001 -f tpmt -o /dev/stdout \
  | python3 -c 'import struct,sys; b=sys.stdin.buffer.read(); sys.stdout.buffer.write(struct.pack(">H", len(b)) + b)'
EOF
cat > "$FB_TOOLS/profile-anchor" <<'EOF'
#!/bin/sh
case "$1" in
  enroll)
    printf '%s\n' "$4" > "$3/test-anchor-profile"
    printf '{"profile":"%s"}\n' "$4" > "$3/access-profile-v1.json"
    printf 'synthetic-signature\n' > "$3/access-profile-v1.sig"
    printf 'synthetic-spki\n' > "$3/access-profile-v1.spki" ;;
  verify) cat "$3/test-anchor-profile" ;;
  *) exit 2 ;;
esac
EOF
chmod +x "$FB_TOOLS"/*

prepare_firstboot_fixture() {
  rm -rf -- "$FB_STATE"
  mkdir -m 0700 "$FB_STATE"
  tpm2_readpublic -Q -c 0x81010005 -f tpmt -o "$FB_STATE/device-root-v1.json"
  "$FB_TOOLS/systemd-analyze" srk > "$FB_STATE/srk-v1.tpm2b_public"
  printf 'access_profile=%s\nhardware_target=%s\nsigned_boot_trust_policy_id=%s\ninitial_issuance_seq=0\n' \
    "$PROFILE" "$TARGET" "$POLICY" > "$FB_STATE/owner-ceremony-intent-v1"
  printf '{"install_source":"medium","installed_at":"1970-01-01T00:00:00Z","installer_sealed_identity_sha256":"%064d","release_identity_sha256":"%064d","schema":"neural-ice-owner-ceremony-install-identity-v1"}\n' \
    0 0 > "$FB_STATE/owner-ceremony-install-identity-v1.json"
  chmod 0600 "$FB_STATE"/*
  for luks in "$FB_SYSTEM_LUKS" "$FB_DATA_LUKS"; do
    truncate -s 16M "$luks"
    printf 'fixture-key' > "$FB_RUN/luks.key"
    cryptsetup luksFormat --type luks2 --batch-mode --key-file "$FB_RUN/luks.key" "$luks" >/dev/null
  done
  python3 - "$FB_STATE/srk-v1.tpm2b_public" "$FB_RUN/system-token.json" "$FB_RUN/data-token.json" <<'PY'
import base64, hashlib, json, struct, sys
# tpm2_srk is systemd's Esys_TR_Serialize() record of the SRK:
# handle || TPM2B_NAME(sha256) || has-resource=1 || TPM2B_PUBLIC.
tpm2b = open(sys.argv[1], "rb").read()
name = b"\x00\x0b" + hashlib.sha256(tpm2b[2:]).digest()
srk = base64.b64encode(struct.pack(">I", 0x81000001) + struct.pack(">H", len(name)) + name + struct.pack(">I", 1) + tpm2b).decode("ascii")
# The shape the installer enrols (ota/neural-ice-autoinstall.sh, systemd-cryptenroll
# --tpm2-pcrs= --tpm2-public-key=... --tpm2-public-key-pcrs=7): a SIGNED PCR7
# policy, no literal PCR list. neural-ice-luks-token-evidence refuses anything else.
for path,label,byte in ((sys.argv[2],"system",b"S"),(sys.argv[3],"data",b"D")):
    token={"keyslots":["0"],"tpm2-blob":base64.b64encode(byte*64).decode(),
           "tpm2-pcr-bank":"sha256","tpm2-pcrs":[],"tpm2-policy-hash":byte.hex()*32,
           "tpm2_pubkey":base64.b64encode(b"P"*91).decode(),"tpm2_pubkey_pcrs":[7],
           "tpm2_srk":srk,"type":"systemd-tpm2"}
    open(path,"w").write(json.dumps(token,sort_keys=True,separators=(",",":"))+"\n")
PY
  cryptsetup token import --token-id 0 --json-file "$FB_RUN/system-token.json" "$FB_SYSTEM_LUKS" >/dev/null
  cryptsetup token import --token-id 0 --json-file "$FB_RUN/data-token.json" "$FB_DATA_LUKS" >/dev/null
}
firstboot() {
  env NI_FIRSTBOOT_TPM_TESTING=1 \
    NI_FIRSTBOOT_TPM_TEST_STATE_DIR="$FB_STATE" \
    NI_FIRSTBOOT_TPM_TEST_STATE="$FB_TOOLS/tpm-state" \
    NI_FIRSTBOOT_TPM_TEST_DEVICE_ROOT="$FB_TOOLS/device-root" \
    NI_FIRSTBOOT_TPM_TEST_PROFILE_ANCHOR="$FB_TOOLS/profile-anchor" \
    NI_FIRSTBOOT_TPM_TEST_SYSTEM_LUKS="$FB_SYSTEM_LUKS" \
    NI_FIRSTBOOT_TPM_TEST_DATA_LUKS="$FB_DATA_LUKS" \
    NI_FIRSTBOOT_TPM_TEST_ACCESS_POLICY="$FB_ACCESS_POLICY" \
    NI_FIRSTBOOT_TPM_TEST_HARDWARE_TARGET="$FB_HARDWARE_TARGET" \
    NI_FIRSTBOOT_TPM_TEST_TRUST_POLICY="$FB_TRUST_POLICY" \
    NI_FIRSTBOOT_TPM_TEST_SYSTEMD_ANALYZE="$FB_TOOLS/systemd-analyze" \
    NI_FIRSTBOOT_TPM_TEST_CRYPTSETUP="$(command -v cryptsetup)" \
    NI_FIRSTBOOT_TPM_TEST_LUKS_EVIDENCE="$ROOT/ota/neural-ice-luks-token-evidence.py" \
    NI_FIRSTBOOT_TPM_TEST_TPM2_READPUBLIC="$(command -v tpm2_readpublic)" \
    NI_FIRSTBOOT_TPM_TEST_RUN_ROOT="$FB_RUN" \
    bash "$FIRSTBOOT" "$@"
}
runtime_complete() {
  local evidence_digest install_at freshness_at
  evidence_digest="$(sha256sum "$FB_STATE/owner-ceremony-evidence-v1.json" | awk '{print $1}')"
  read -r install_at freshness_at < <(python3 - "$FB_STATE/owner-ceremony-evidence-v1.json" <<'PY'
import json,sys
s=json.load(open(sys.argv[1]))["tpm_state"]
print(s["install_counter"],s["freshness_counter"])
PY
)
  hw runtime-status "$PROFILE" "$TARGET" "$POLICY" "$evidence_digest" "$install_at" "$freshness_at"
}

# Autoinstall publishes four mandatory installed-root inputs atomically.  If a
# power loss leaves any one absent, first boot must refuse before creating NV
# state or changing owner authorization; the unit's OnFailure=isolate then keeps
# every runtime consumer down (proved independently by the offline systemd
# suite).  Exercise each absent final input against the real swtpm wrapper.
persist_prerequisites
prepare_firstboot_fixture
for missing_input in device-root-v1.json srk-v1.tpm2b_public \
  owner-ceremony-intent-v1 owner-ceremony-install-identity-v1.json; do
  mv "$FB_STATE/$missing_input" "$FB_RUN/$missing_input.absent"
  expect_refusal "firstboot accepted missing installed input $missing_input" firstboot
  [[ "$(hw provisioning-status)" == pcr-policy-activated ]] \
    || fail "missing $missing_input mutated TPM provisioning state"
  mv "$FB_RUN/$missing_input.absent" "$FB_STATE/$missing_input"
done
clear_tpm

# A complete install may fail before the owner ceremony. Reinstall from a
# strictly higher signed policy generation without clearing the TPM: only the
# PCR policy counter moves, both persistent public identities remain byte-for-
# byte stable, and the ordinary one-time ceremony still succeeds afterward.
# Use the live absolute value: TPM Clear does not promise to reset the internal
# counter floor, so fixed fixture numbers would make this real-TPM test false.
persist_prerequisites
[[ "$(hw provisioning-status)" == pcr-policy-activated ]] \
  || fail "activated PCR policy was not identified as pre-ceremony state"
tpm2_readpublic -Q -c 0x81010005 -f tpmt -o "$TMP/retry-device-root.before"
tpm2_readpublic -Q -c 0x81000001 -f tpmt -o "$TMP/retry-srk.before"
retry_high_water="$(abs_counter 0x01500007)"
[[ "$retry_high_water" =~ ^[1-9][0-9]*$ ]] \
  || fail "pre-ceremony fixture has no usable absolute PCR policy high-water"
retry_candidate=$((retry_high_water + 1))
[[ "$(hw pcr-policy-check "$retry_candidate")" == "$retry_high_water" ]] \
  || fail "higher signed policy was not eligible for pre-ceremony retry"
[[ "$(hw pcr-policy-activate "$retry_candidate")" == "$retry_candidate" ]] \
  || fail "pre-ceremony retry did not activate the next policy generation"
[[ "$(hw provisioning-status)" == pcr-policy-activated ]] \
  || fail "higher policy activation changed the pre-ceremony state class"
tpm2_readpublic -Q -c 0x81010005 -f tpmt -o "$TMP/retry-device-root.after"
tpm2_readpublic -Q -c 0x81000001 -f tpmt -o "$TMP/retry-srk.after"
cmp -s "$TMP/retry-device-root.before" "$TMP/retry-device-root.after" \
  || fail "higher policy activation changed the device-root public identity"
cmp -s "$TMP/retry-srk.before" "$TMP/retry-srk.after" \
  || fail "higher policy activation changed the SRK public identity"
prepare_firstboot_fixture
firstboot >/dev/null \
  || fail "mandatory ceremony failed after pre-ceremony retry"
[[ "$(firstboot status)" == complete ]] \
  || fail "mandatory ceremony was not complete after pre-ceremony retry"
[[ "$(runtime_complete)" == complete ]] \
  || fail "runtime rejected the ceremony completed after pre-ceremony retry"
# Keep later fixtures above the TPM's process-lifetime counter floor.
PCR_POLICY_CANDIDATE=$((retry_candidate + 1))
clear_tpm

# A forged legacy receipt and attacker-known owner authorization together are
# still not completion: only the write-locked TPM completion record selects the
# read-only path, and a non-virgin owner hierarchy cannot enter provisioning.
persist_prerequisites
prepare_firstboot_fixture
printf '{"forged":"ownerAuthSet-is-not-ceremony"}\n' > "$FB_STATE/owner-ceremony-receipt-v1.json"
"$REAL_CHANGEAUTH" -c o str:attacker-known >/dev/null
expect_refusal "forged receipt plus attacker-known owner auth bypassed ceremony" firstboot
clear_tpm

# Device-root replacement must fail through the wrapper's real comparison.
persist_prerequisites
prepare_firstboot_fixture
tpm2_evictcontrol -C o -c 0x81010005 >/dev/null
tpm2_createprimary -C e -g sha256 -G rsa -c "$TMP/replacement.ctx" >/dev/null
tpm2_evictcontrol -C o -c "$TMP/replacement.ctx" 0x81010005 >/dev/null
tpm2_flushcontext "$TMP/replacement.ctx" >/dev/null 2>&1 || true
tpm2_flushcontext -t >/dev/null 2>&1 || true
expect_refusal "replacement device root passed firstboot intent" firstboot

# SRK replacement is independently rejected before any NV state is created.
clear_tpm
persist_prerequisites
prepare_firstboot_fixture
tpm2_evictcontrol -C o -c 0x81000001 >/dev/null
tpm2_createprimary -C o -g sha256 -G ecc -c "$TMP/replacement-srk.ctx" >/dev/null
tpm2_evictcontrol -C o -c "$TMP/replacement-srk.ctx" 0x81000001 >/dev/null
tpm2_flushcontext "$TMP/replacement-srk.ctx" >/dev/null 2>&1 || true
tpm2_flushcontext -t >/dev/null 2>&1 || true
expect_refusal "replacement SRK passed firstboot intent" firstboot
clear_tpm

# Successful ceremony uses the absolute counter value as high-water.
persist_prerequisites
prepare_firstboot_fixture
printf '{"forged":"root-writable-receipt"}\n' > "$FB_STATE/owner-ceremony-receipt-v1.json"
chmod 0600 "$FB_STATE/owner-ceremony-receipt-v1.json"
post_changeauth_output="$(NI_TEST_INTERRUPT_AFTER_CHANGEAUTH=1 firstboot 2>&1)" && {
  fail "injected interruption after successful changeauth reported success"
}
grep -Fq 'injected interruption after successful owner changeauth' <<<"$post_changeauth_output" \
  || fail "ceremony failed before the injected post-changeauth interruption: $post_changeauth_output"
[[ "$(firstboot status)" == complete ]] \
  || fail "interruption after changeauth did not recover from TPM-authenticated completion"
[[ "$(firstboot)" == complete ]] || fail "mandatory firstboot ceremony did not complete"
cp "$FB_STATE/owner-ceremony-evidence-v1.json" "$TMP/authenticated-evidence.json"
python3 - "$FB_STATE/owner-ceremony-evidence-v1.json" <<'PY'
import json,sys
p=sys.argv[1]; d=json.load(open(p)); d["install_identity"]["release_identity_sha256"]="22"*32
open(p,"w").write(json.dumps(d,sort_keys=True,separators=(",",":"))+"\n")
PY
expect_refusal "forged mutable lifecycle evidence selected runtime readiness" firstboot status
cp "$TMP/authenticated-evidence.json" "$FB_STATE/owner-ceremony-evidence-v1.json"
install_value="$(hw counter-read)"
high_water="$(hw freshness-read)"
bound_digest="$(hw profile-read)"
[[ "$install_value" =~ ^[1-9][0-9]*$ ]] || fail "invalid install counter: $install_value"
[[ "$high_water" =~ ^[1-9][0-9]*$ && "$bound_digest" == "$digest" ]] \
  || fail "invalid ceremony evidence: $install_value $high_water $bound_digest"
[[ "$(runtime_complete)" == complete ]] \
  || fail "runtime rejected completed ceremony"
[[ "$(hw freshness-read)" == "$(abs_counter 0x01500004)" ]] \
  || fail "freshness is not the absolute NV counter"
expect_refusal "consumed issuance sequence N replayed" hw freshness-consume "$high_water"
next_high_water=$(( high_water + 1 ))
[[ "$(hw freshness-consume "$next_high_water")" == "$next_high_water" ]] || fail "N+1 was not consumed"
expect_refusal "second ceremony was idempotent success" hw ceremony-prepare "$PROFILE" "$TARGET" "$POLICY" 0
[[ "$(firstboot status)" == complete ]] || fail "TPM-authenticated second boot was refused"

# Runtime root cannot delete/recreate NV state or persistent objects after seal.
for index in 0x01500003 0x01500004 0x01500005 0x01500006 0x01500007; do
  expect_refusal "runtime root undefined $index after seal" tpm2_nvundefine "$index" -C o
  tpm2_nvreadpublic "$index" >/dev/null || fail "$index disappeared after refused undefine"
done
expect_refusal "runtime root defined a new NV index after seal" \
  tpm2_nvdefine 0x0150000e -C o -s 8 -a "policywrite|authread|ownerread|nt=counter" -L "$TMP/p.digest"
expect_refusal "runtime root evicted device root after seal" tpm2_evictcontrol -C o -c 0x81010005
expect_refusal "runtime root evicted SRK after seal" tpm2_evictcontrol -C o -c 0x81000001

# Second boot requires and retains the exact completed evidence.
stop_swtpm
start_swtpm
[[ "$(runtime_complete)" == complete ]] \
  || fail "second boot rejected exact completed state"
[[ "$(firstboot status)" == complete ]] || fail "wrapper rejected exact evidence after TPM restart"
[[ "$(hw freshness-read)" == "$next_high_water" ]] || fail "high-water did not survive restart"
expect_refusal "consumed N replayed after restart" hw freshness-consume "$high_water"
expect_refusal "consumed N+1 replayed after restart" hw freshness-consume "$next_high_water"

# TPM clear is the measured physical-reset primitive; runtime remains closed
# until a signed physical reinstall completes a new ceremony.
clear_tpm
[[ "$(hw provisioning-status)" == virgin ]] || fail "TPM clear did not restore virgin hardware state"
expect_refusal "runtime became ready immediately after TPM clear" runtime_complete
expect_refusal "mutable evidence made TPM clear look complete" firstboot status

echo "SWTPM_TPM_STATE_TEST_OK (real TPM 2.0 + real cryptsetup LUKS2 headers; anchor signer fixture is explicitly synthetic; signed physical recovery and GB10 gates remain)"
