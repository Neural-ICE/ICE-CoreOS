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
  tpm2_clearcontrol tpm2_nvextend \
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
for tool in tpm2_clearcontrol tpm2_nvextend; do
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
# ADR-0015 O: start at the C32 label (1105) so the real TPM proves that a
# first activation costs ONE increment whatever the label; the sealed record
# carries (born, label) and the generation reads label + (counter - born).
PCR_POLICY_CANDIDATE=1105

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
    local activation_t0=$SECONDS
    [[ "$(hw pcr-policy-activate "$candidate")" == "$candidate" ]] \
      || fail "signed PCR policy activation did not commit"
    (( SECONDS - activation_t0 <= 60 )) \
      || fail "activating label $candidate took $(( SECONDS - activation_t0 )) s on a fresh TPM; it must cost one increment (ADR-0015 O)"
    tpm2_nvread 0x01500008 -C 0x01500008 -s 64 -o "$TMP/generation.bin" >/dev/null || fail "cannot read the generation base"
    read -r sealed_born sealed_label < <(python3 -c 'import struct,sys; b=open(sys.argv[1],"rb").read(); print(*struct.unpack(">QQ", b[8:24]))' "$TMP/generation.bin")
    [[ "$sealed_label" == "$candidate" ]] || fail "the generation record does not seal the activated label: $sealed_label"
    [[ "$(abs_counter 0x01500007)" == "$sealed_born" ]] \
      || fail "the first activation spun the counter past its sealed birth value"
    # ADR-0015 N and O: the generation is the sealed label plus the counter's
    # distance from its sealed birth value; before the owner ceremony a retry
    # at or above it is allowed and the check prints generation - 1, a lower
    # label is refused.
    [[ "$(hw pcr-policy-generation)" == "$candidate" ]] \
      || fail "the activated generation is not the sealed label plus the counter's distance"
    [[ "$(hw pcr-policy-check "$candidate")" == "$(( candidate - 1 ))" ]] \
      || fail "pre-ceremony retry of the activated generation was refused"
    if (( candidate > 1 )); then
      expect_refusal "lower generation accepted before the ceremony" \
        hw pcr-policy-check "$(( candidate - 1 ))"
    fi
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
  # This suite qualifies the historical full TPM lifecycle (v1 and owner-profile
  # completion). Pin the strict posture so it is not silenced by the ADR-0050
  # lab-trust relaxed default (lever B); the relaxed fail-open is proved
  # independently by ota/test-firstboot-ceremony-failopen.sh.
  env NI_FIRSTBOOT_TPM_TESTING=1 \
    NEURALICE_SEALED_OTA_STATE="${NI_CEREMONY_POSTURE:-strict}" \
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
    NI_FIRSTBOOT_TPM_TEST_OTA_STATE="${FB_OTA_STATE:-}" \
    NI_FIRSTBOOT_TPM_TEST_OTA_VERIFY="${FB_OTA_VERIFY:-}" \
    NI_FIRSTBOOT_TPM_TEST_OTA_CONFIG="${FB_OTA_CONFIG:-}" \
    NI_FIRSTBOOT_TPM_TEST_OTA_PROFILE="${FB_OTA_PROFILE:-}" \
    NI_FIRSTBOOT_TPM_TEST_CANDIDATE_ROOT="${FB_CANDIDATE_ROOT:-}" \
    NI_FIRSTBOOT_TPM_TEST_BOOTC="${FB_BOOTC:-}" \
    NI_TPM_STATE_TEST_OTA_HELPER="${FB_OTA_STATE:-}" \
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
retry_generation="$(hw pcr-policy-generation)"
retry_candidate=$retry_generation
[[ "$(hw pcr-policy-check "$retry_candidate")" == "$(( retry_generation - 1 ))" ]] \
  || fail "the activated generation was not eligible for pre-ceremony retry"
[[ "$(hw pcr-policy-activate "$retry_candidate")" == "$retry_candidate" ]] \
  || fail "pre-ceremony retry of the activated generation did not activate"
[[ "$(abs_counter 0x01500007)" == "$retry_high_water" ]] \
  || fail "re-activating the same generation moved the counter"
retry_candidate=$(( retry_generation + 1 ))
[[ "$(hw pcr-policy-activate "$retry_candidate")" == "$retry_candidate" ]] \
  || fail "pre-ceremony retry of the next generation did not activate"
[[ "$(abs_counter 0x01500007)" == "$((retry_high_water + 1))" ]] \
  || fail "the next generation did not advance the counter by exactly one"
[[ "$(hw pcr-policy-generation)" == "$retry_candidate" ]] \
  || fail "the generation did not follow the counter on a real TPM"
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
expect_refusal "a provisioned device accepted a factory install without TPM2_Clear" hw pcr-policy-check 1
expect_refusal "a provisioned device activated a factory generation without TPM2_Clear" hw pcr-policy-activate 1
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
[[ "$high_water" =~ ^(0|[1-9][0-9]*)$ && "$bound_digest" == "$digest" ]] \
  || fail "invalid ceremony evidence: $install_value $high_water $bound_digest"
[[ "$(runtime_complete)" == complete ]] \
  || fail "runtime rejected completed ceremony"
# ADR-0015 M: the high-water is the NV counter minus the base sealed in the
# write-once record (bytes 40..47), because a real TPM is born wherever its
# largest counter ever went. The real TPM is the only witness of both values.
tpm2_nvread 0x01500005 -C 0x01500005 -s 64 -o "$TMP/record.bin" >/dev/null || fail "cannot read the sealed record"
sealed_base="$(python3 -c 'import struct,sys; print(struct.unpack(">Q", open(sys.argv[1],"rb").read()[40:48])[0])' "$TMP/record.bin")"
sealed_origin="$(python3 -c 'import struct,sys; print(struct.unpack(">Q", open(sys.argv[1],"rb").read()[48:56])[0])' "$TMP/record.bin")"
[[ "$sealed_base" =~ ^[1-9][0-9]*$ ]] || fail "the record seals no freshness base: $sealed_base"
[[ "$sealed_origin" =~ ^(0|[1-9][0-9]*)$ ]] || fail "the record seals no freshness origin: $sealed_origin"
# ADR-0015 O: the ceremony seals the issuance sequence as the origin and never
# spins the counter to it; the high-water is origin + (counter - base).
[[ "$(( $(hw freshness-read) - sealed_origin + sealed_base ))" == "$(abs_counter 0x01500004)" ]] \
  || fail "freshness is not the sealed origin plus the NV counter minus the sealed base"
[[ "$(abs_counter 0x01500004)" == "$sealed_base" ]] \
  || fail "the ceremony spun the freshness counter past its sealed base"
expect_refusal "consumed issuance sequence N replayed" hw freshness-consume "$high_water"
next_high_water=$(( high_water + 1 ))
[[ "$(hw freshness-consume "$next_high_water")" == "$next_high_water" ]] || fail "N+1 was not consumed"
expect_refusal "second ceremony was idempotent success" hw ceremony-prepare "$PROFILE" "$TARGET" "$POLICY" 0
[[ "$(firstboot status)" == complete ]] || fail "TPM-authenticated second boot was refused"

# Runtime root cannot delete/recreate NV state or persistent objects after seal.
for index in 0x01500003 0x01500004 0x01500005 0x01500006 0x01500007 0x01500008; do
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

# Fresh owner-profile ceremony: real SWTPM exercises the exact preseal-prepared
# classification, ClearControl-before-NV06 ordering, NI-DONE2 domain binding,
# OwnerAuth destruction, orderly restart, and read-only retained validation.
# Delegated signature verification is covered with real OpenSSL keys by the
# Rust preseal integration suite; this orchestration seam uses an explicit mock.
# TPM Clear does not reset the TPM-wide counter allocator. Select a safely
# bounded sequence above every counter this fixture has allocated so the added
# fresh install remains a valid signed-policy candidate.
PCR_POLICY_CANDIDATE=$((PCR_POLICY_CANDIDATE + 32))
persist_prerequisites
FB_OTA_STATE="$FB_TOOLS/ota-state"
FB_OTA_VERIFY="$FB_TOOLS/ota-verify"
FB_OTA_CONFIG="$TMP/ota.conf"
FB_OTA_PROFILE="$TMP/ota-state-profile"
FB_CANDIDATE_ROOT="$TMP/candidate"
FB_BOOTC="$FB_TOOLS/bootc"
cat > "$FB_OTA_STATE" <<EOF
#!/bin/sh
exec env NI_OTA_TPM_STATE_TESTING=1 NI_OTA_TPM_STATE_TEST_TOOLS="$TOOLS" \
  NI_OTA_TPM_STATE_TEST_RUN_DIR="$TMP/owner-ota-run" \
  bash "$ROOT/ota/neural-ice-ota-tpm-state.sh" "\$@"
EOF
cat > "$FB_OTA_VERIFY" <<EOF
#!/bin/sh
case "\$1" in
  verify-preseal-baseline|verify-retained-preseal-baseline)
    printf '%s\n' "\$1" >> "$TMP/preseal-calls"
    if [ "\$1" = verify-retained-preseal-baseline ] && [ -e "$TMP/swap-completion-evidence" ]; then
      mv "$TMP/replacement-completion-evidence.json" "$FB_STATE/owner-ceremony-evidence-v2.json" || exit 98
      rm -f "$TMP/swap-completion-evidence"
    fi
    exit 0
    ;;
  bootstrap-from-preseal)
    # ICE-CoreOS issue 206: the first boot seeds the applied baseline from
    # the receipt, with the retained verification's inputs. Record the call
    # and its binding flags; refuse on demand so the ceremony's fail-closed
    # ordering (before any TPM mutation) is measured, not assumed.
    printf '%s\n' "\$1" >> "$TMP/preseal-calls"
    printf '%s\n' "\$*" > "$TMP/seed-args"
    [ ! -e "$TMP/seed-refuse" ] || exit 1
    exit 0
    ;;
  *) exit 97 ;;
esac
EOF
cat > "$FB_BOOTC" <<EOF
#!/bin/sh
[ "\$#" -eq 2 ] && [ "\$1" = status ] && [ "\$2" = --json ] || exit 97
digit=0; [ ! -e "$TMP/bootc-mismatch" ] || digit=1
printf '{"spec":{"image":{"image":"release.example.test/neural-ice/neural-ice-appliance@sha256:%064d"}},"status":{"booted":{"image":{"image":{"image":"release.example.test/neural-ice/neural-ice-appliance@sha256:%064d"},"imageDigest":"sha256:%064d"}}}}\n' 0 0 "\$digit"
EOF
chmod +x "$FB_OTA_STATE" "$FB_OTA_VERIFY" "$FB_BOOTC"
printf 'owner-sealed-ota-state-v1\n' > "$FB_OTA_PROFILE"
prepare_firstboot_fixture
mkdir -p "$FB_CANDIDATE_ROOT" "$FB_STATE/preseal-input-v1" "$FB_STATE/preseal"
printf 'enforce=1\nstate_dir=%s\n' "$FB_STATE" > "$FB_OTA_CONFIG"
for name in delegation-snapshot.json delegation-snapshot.sig \
  ota-release-authorization.json ota-release-authorization.sig bom.json \
  installer-release-authorization-v2.sig; do printf '{}\n' > "$FB_STATE/preseal-input-v1/$name"; done
printf '{"image_manifest_digest":"sha256:%064d"}\n' 0 \
  > "$FB_STATE/preseal-input-v1/installer-release-authorization-v2.json"
printf '{"bundle_seq":42,"installer_authorization_sha256":"%064d","installer_authorization_signature_sha256":"%064d","schema":"neural-ice-installer-preseal-set-v1","seed_ref":"%040d","target_os_ref":"release.example.test/neural-ice/neural-ice-appliance@sha256:%064d"}\n' \
  0 0 0 0 > "$FB_STATE/preseal-input-v1/preseal-set.json"
set_hash="$(sha256sum "$FB_STATE/preseal-input-v1/preseal-set.json" | awk '{print $1}')"
printf '{"bundle_seq":42,"installer_authorization_sha256":"%064d","preseal_set_sha256":"%s","schema":"neural-ice-ota-preseal-receipt-v1"}\n' \
  0 "$set_hash" > "$FB_STATE/preseal/receipt.json"
chmod 0600 "$FB_STATE/preseal-input-v1"/* "$FB_STATE/preseal/receipt.json"
"$FB_OTA_STATE" prepare 42 >/dev/null
[[ "$(NI_TPM_STATE_TEST_OTA_HELPER="$FB_OTA_STATE" hw provisioning-status)" == preseal-prepared ]] \
  || fail "real owner preseal state was not classified exactly"
printf 'owner-sealed-ota-state-v1\n\n' > "$FB_OTA_PROFILE"
expect_refusal "owner ceremony accepted a noncanonical immutable profile marker" firstboot
[[ "$(NI_TPM_STATE_TEST_OTA_HELPER="$FB_OTA_STATE" hw provisioning-status)" == preseal-prepared ]] \
  || fail "noncanonical profile marker mutated owner TPM state"
printf 'owner-sealed-ota-state-v1\n' > "$FB_OTA_PROFILE"
mv "$FB_STATE/preseal-input-v1/bom.json" "$TMP/bom.absent"
expect_refusal "owner ceremony accepted an incomplete retained preseal set" firstboot
[[ "$(NI_TPM_STATE_TEST_OTA_HELPER="$FB_OTA_STATE" hw provisioning-status)" == preseal-prepared ]] \
  || fail "missing preseal input mutated owner TPM state"
mv "$TMP/bom.absent" "$FB_STATE/preseal-input-v1/bom.json"
touch "$TMP/bootc-mismatch"
expect_refusal "owner ceremony accepted a different booted manifest" firstboot
[[ "$(NI_TPM_STATE_TEST_OTA_HELPER="$FB_OTA_STATE" hw provisioning-status)" == preseal-prepared ]] \
  || fail "booted-image mismatch mutated owner TPM state"
rm -f "$TMP/bootc-mismatch"
# A refused applied-baseline seeding dies AFTER the candidate is
# authenticated and BEFORE ceremony-prepare-v2: the TPM stays exactly
# preseal-prepared and the next boot retries the whole ceremony.
: > "$TMP/seed-refuse"
expect_refusal "owner ceremony continued past a refused applied-baseline seeding" firstboot
[[ "$(NI_TPM_STATE_TEST_OTA_HELPER="$FB_OTA_STATE" hw provisioning-status)" == preseal-prepared ]] \
  || fail "refused applied-baseline seeding mutated owner TPM state"
mapfile -t preseal_calls < "$TMP/preseal-calls"
[[ "${preseal_calls[*]}" == "verify-preseal-baseline bootstrap-from-preseal" ]] \
  || fail "the applied baseline was not seeded right after the candidate was authenticated: ${preseal_calls[*]}"
rm -f "$TMP/seed-refuse" "$TMP/preseal-calls"
firstboot >/dev/null || fail "owner-profile firstboot ceremony did not complete"
mapfile -t preseal_calls < "$TMP/preseal-calls"
[[ "${preseal_calls[*]}" == "verify-preseal-baseline bootstrap-from-preseal verify-preseal-baseline" ]] \
  || fail "owner ceremony did not authenticate the installed candidate, seed the applied baseline, and re-authenticate after finalization: ${preseal_calls[*]}"
seed_args="$(cat "$TMP/seed-args")"
set_hash="$(sha256sum "$FB_STATE/preseal-input-v1/preseal-set.json" | awk '{print $1}')"
receipt_hash="$(sha256sum "$FB_STATE/preseal/receipt.json" | awk '{print $1}')"
for expected in "--receipt $FB_STATE/preseal/receipt.json" "--expected-set-sha256 $set_hash" \
  "--expected-receipt-sha256 $receipt_hash" "--bom $FB_STATE/preseal-input-v1/bom.json" \
  "--config $FB_OTA_CONFIG"; do
  [[ "$seed_args" == *"$expected"* ]] \
    || fail "applied-baseline seeding was not bound to the authenticated preseal inputs: $seed_args"
done
[[ "$(firstboot status)" == complete ]] || fail "owner-profile completion did not validate"
mapfile -t preseal_calls < "$TMP/preseal-calls"
[[ "${preseal_calls[*]}" == "verify-preseal-baseline bootstrap-from-preseal verify-preseal-baseline verify-retained-preseal-baseline" ]] \
  || fail "later owner status did not use the retained nonpublishing verifier"
cp "$FB_STATE/owner-ceremony-evidence-v2.json" "$TMP/authenticated-owner-evidence-v2.json"
printf '{"attacker":"pathname replacement"}\n' > "$TMP/replacement-completion-evidence.json"
: > "$TMP/swap-completion-evidence"
[[ "$(firstboot status)" == complete ]] \
  || fail "a pathname replacement after the evidence snapshot changed the current validation decision"
grep -Fq 'pathname replacement' "$FB_STATE/owner-ceremony-evidence-v2.json" \
  || fail "the deterministic pathname-swap fixture did not execute"
cp "$TMP/authenticated-owner-evidence-v2.json" "$FB_STATE/owner-ceremony-evidence-v2.json"
mv "$FB_OTA_PROFILE" "$TMP/ota-state-profile.absent"
expect_refusal "owner completion was selected without immutable reader support" firstboot status
mv "$TMP/ota-state-profile.absent" "$FB_OTA_PROFILE"
grep -q '^NI-DONE2' < <(tpm2_nvread 0x01500006 -C 0x01500006 -s 8 2>/dev/null) \
  || fail "owner-profile ceremony did not persist NI-DONE2"
stop_swtpm
start_swtpm
[[ "$(firstboot status)" == complete ]] \
  || fail "owner-profile retained validation failed after orderly SWTPM restart"
read -r v2_digest v2_install v2_freshness < <(python3 - "$FB_STATE/owner-ceremony-evidence-v2.json" <<'PY'
import hashlib,json,sys
raw=open(sys.argv[1],"rb").read(); state=json.loads(raw)["tpm_state"]
print(hashlib.sha256(b"neural-ice:tpm:owner-ceremony-completion:v2\0"+raw).hexdigest(),state["install_counter"],state["freshness_counter"])
PY
)
expect_refusal "v1 runtime reader accepted NI-DONE2" \
  hw runtime-status "$PROFILE" "$TARGET" "$POLICY" "$v2_digest" "$v2_install" "$v2_freshness"

# --------------------------------------------------------------------------- #
# Mission B, lane 2: an owner-sealed v2 host (image marker
# owner-sealed-ota-state-v2, docs/ota/V2-RELEASE-ATTESTATION.md) on a real TPM.
# The TPM objects (floor 0x01500001, anchor 0x01500002), ClearControl-before-NV06
# ordering, NI-DONE2, OwnerAuth destruction and the NV write lock are the real
# ones and identical to the preseal lane above; only the attestation that names
# the floor differs: the v2 release receipt, authenticated by a contract
# conformant FAKE of `ni-ota-verify verify-retained-v2-release` (the real verb is
# T1's; its cryptography is not exercised here). The v2 lane has no relaxed
# branch: every refusal below also runs under NEURALICE_SEALED_OTA_STATE=relaxed.
# --------------------------------------------------------------------------- #
tpm2_clearcontrol -C p c >/dev/null 2>&1 || fail "cannot lift disableClear with platform authorization for the next fixture"
clear_tpm
PCR_POLICY_CANDIDATE=$((PCR_POLICY_CANDIDATE + 32))
persist_prerequisites
FB_V2_CALLS="$TMP/v2-calls"
cat > "$FB_OTA_VERIFY" <<'EOF'
#!/usr/bin/env python3
import hashlib, json, os, re, sys
calls = os.environ["NI_TEST_V2_CALLS"]
def refuse(cls):
    sys.stderr.write("ni-ota-verify: v2 release REFUSED: %s: fixture\n" % cls); sys.exit(1)
open(calls, "a").write(" ".join(sys.argv[1:]) + "\n")
if sys.argv[1:2] != ["verify-retained-v2-release"]: sys.exit(2)
need = ["--manifest", "--manifest-sig", "--release-key", "--expected-receipt-sha256", "--receipt", "--scratch-dir"]
a = sys.argv[2:]
f = dict(zip(a[0::2], a[1::2]))
if len(a) % 2 or len(f) != len(a) // 2 or set(f) - set(need + ["--root"]) or set(need) - set(f): sys.exit(2)
sha = lambda p: hashlib.sha256(open(p, "rb").read()).hexdigest()
raw = open(f["--receipt"], "rb").read()
if hashlib.sha256(raw).hexdigest() != f["--expected-receipt-sha256"]: refuse("receipt-digest")
r = json.loads(raw)
if (sha(f["--manifest"]), sha(f["--manifest-sig"]), sha(f["--release-key"])) != (r["manifest_sha256"], r["manifest_sig_sha256"], r["release_key_sha256"]):
    refuse("manifest-digest")
if os.path.exists(os.environ["NI_TEST_V2_REFUSE"]): refuse("signature")
m = lambda n: open(os.path.join(f["--root"], "usr/lib/neural-ice", n)).read().strip()
if (m("ota-state-profile"), m("access-policy"), m("hardware-target"), m("signed-boot-trust-policy-id")) != (
        "owner-sealed-ota-state-v2", r["access_profile"], r["hardware_target"], r["signed_boot_trust_policy_id"]):
    refuse("candidate-marker")
print(json.dumps({"bundle_seq": r["bundle_seq"], "receipt_sha256": f["--expected-receipt-sha256"], "verdict": "pass"},
                 sort_keys=True, separators=(",", ":")))
EOF
chmod +x "$FB_OTA_VERIFY"
export NI_TEST_V2_CALLS="$FB_V2_CALLS" NI_TEST_V2_REFUSE="$TMP/v2-refuse"
FB_OTA_PROFILE="$TMP/ota-state-profile-v2"
FB_CANDIDATE_ROOT="$TMP/candidate-v2"
FB_RELEASE_KEY="$TMP/release-authorization.pub"
v2_firstboot() { NI_FIRSTBOOT_TPM_TEST_RELEASE_KEY="$FB_RELEASE_KEY" firstboot "$@"; }
v2_expect_refusal() { # <description> <args...>: refused under strict AND relaxed, TPM still preseal-prepared
  local description=$1 posture
  shift
  for posture in strict relaxed; do
    NI_CEREMONY_POSTURE="$posture" expect_refusal "$description ($posture)" v2_firstboot "$@"
    [[ "$(NI_TPM_STATE_TEST_OTA_HELPER="$FB_OTA_STATE" hw provisioning-status)" == preseal-prepared ]] \
      || fail "$description ($posture) mutated the owner TPM state"
  done
}
prepare_v2_state() { # <bundle_seq of the receipt>
  local seq=$1 msha ssha ksha
  prepare_firstboot_fixture
  mkdir -m 0700 "$FB_STATE/v2-release-input-v1" "$FB_STATE/v2-release"
  printf '{"schema":"neural-ice-release-manifest-v1","bundle_seq":%s}' "$seq" > "$FB_STATE/v2-release-input-v1/release-manifest.json"
  printf 'c2lnbmF0dXJl' > "$FB_STATE/v2-release-input-v1/release-manifest.json.sig"
  printf 'fixture release key\n' > "$FB_RELEASE_KEY"
  msha="$(sha256sum "$FB_STATE/v2-release-input-v1/release-manifest.json" | awk '{print $1}')"
  ssha="$(sha256sum "$FB_STATE/v2-release-input-v1/release-manifest.json.sig" | awk '{print $1}')"
  ksha="$(sha256sum "$FB_RELEASE_KEY" | awk '{print $1}')"
  python3 - "$FB_STATE/v2-release/receipt.json" "$seq" "$msha" "$ssha" "$ksha" "$PROFILE" "$TARGET" "$POLICY" <<'PY'
import json, sys
path, seq, m, sg, k, profile, target, policy = sys.argv[1:]
r = {"access_profile": profile, "bundle_seq": int(seq), "hardware_target": target,
     "host_index_digest": "sha256:" + "a1" * 32, "host_manifest_digest": "sha256:" + "b2" * 32,
     "host_repository": "registry.example.test/neural-ice-test/host-appliance",
     "manifest_sha256": m, "manifest_sig_sha256": sg, "release_id": "v2-test-train-3",
     "release_key_sha256": k, "schema": "neural-ice-v2-release-receipt-v1",
     "seal": {"min_bundle_seq": None, "mode": "manifest-digest", "sealed_manifest_sha256": m},
     "signed_boot_trust_policy_id": policy, "variant": "sealed-lab"}
open(path, "w").write(json.dumps(r, sort_keys=True, separators=(",", ":")) + "\n")
PY
  chmod 0600 "$FB_STATE/v2-release-input-v1"/* "$FB_STATE/v2-release/receipt.json"
  printf '{"install_source":"medium","installed_at":"1970-01-01T00:00:00Z","installer_sealed_identity_sha256":"%064d","release_identity_sha256":"%s","schema":"neural-ice-owner-ceremony-install-identity-v1"}\n' \
    0 "$msha" > "$FB_STATE/owner-ceremony-install-identity-v1.json"
  chmod 0600 "$FB_STATE/owner-ceremony-install-identity-v1.json"
  rm -rf -- "${FB_CANDIDATE_ROOT:?}"
  mkdir -p "$FB_CANDIDATE_ROOT/usr/lib/neural-ice"
  printf '%s\n' "$PROFILE" > "$FB_CANDIDATE_ROOT/usr/lib/neural-ice/access-policy"
  printf '%s\n' "$TARGET" > "$FB_CANDIDATE_ROOT/usr/lib/neural-ice/hardware-target"
  printf '%s\n' "$POLICY" > "$FB_CANDIDATE_ROOT/usr/lib/neural-ice/signed-boot-trust-policy-id"
  printf 'owner-sealed-ota-state-v2\n' > "$FB_CANDIDATE_ROOT/usr/lib/neural-ice/ota-state-profile"
  printf 'owner-sealed-ota-state-v2\n' > "$FB_OTA_PROFILE"
  rm -f "$FB_V2_CALLS" "$TMP/v2-refuse"
}

# Receipt and TPM floor disagree: the real helper refuses before it mutates.
prepare_v2_state 41
"$FB_OTA_STATE" prepare 42 >/dev/null
[[ "$(NI_TPM_STATE_TEST_OTA_HELPER="$FB_OTA_STATE" hw provisioning-status)" == preseal-prepared ]] \
  || fail "real owner state for the v2 lane was not classified exactly"
v2_expect_refusal "a receipt bundle_seq different from the TPM floor was accepted" boot
# From here the receipt names the TPM floor.
prepare_v2_state 42
printf 'owner-sealed-ota-state-v2\n\n' > "$FB_OTA_PROFILE"
v2_expect_refusal "a noncanonical v2 profile marker was accepted" boot
printf 'owner-sealed-ota-state-v2\n' > "$FB_OTA_PROFILE"
printf 'owner-sealed-ota-state-v1\n' > "$FB_OTA_PROFILE"
v2_expect_refusal "a v1 marker was accepted for a host that carries only the v2 inputs" boot
printf 'owner-sealed-ota-state-v2\n' > "$FB_OTA_PROFILE"
for missing in v2-release-input-v1/release-manifest.json v2-release-input-v1/release-manifest.json.sig v2-release/receipt.json; do
  mv "$FB_STATE/$missing" "$TMP/v2-input.absent"
  v2_expect_refusal "an absent persisted v2 input ($missing) was accepted" boot
  mv "$TMP/v2-input.absent" "$FB_STATE/$missing"
done
: > "$TMP/v2-refuse"
v2_expect_refusal "a failing v2 verifier was tolerated" boot
rm -f "$TMP/v2-refuse"
printf 'owner-sealed-ota-state-v1\n' > "$FB_CANDIDATE_ROOT/usr/lib/neural-ice/ota-state-profile"
v2_expect_refusal "a live root that is not on the v2 lane was accepted" boot
printf 'owner-sealed-ota-state-v2\n' > "$FB_CANDIDATE_ROOT/usr/lib/neural-ice/ota-state-profile"
[[ ! -e "$FB_STATE/owner-ceremony-evidence-v2.json" ]] || fail "a refused v2 ceremony left completion evidence behind"
! grep -Eq 'preseal' "$FB_V2_CALLS" || fail "the v2 lane called a preseal verb: $(cat "$FB_V2_CALLS")"

# The legitimate first boot (relaxed on purpose: the posture must change nothing).
rm -f "$FB_V2_CALLS"
NI_CEREMONY_POSTURE=relaxed v2_firstboot >/dev/null || fail "owner-sealed v2 first boot did not complete"
[[ "$(wc -l < "$FB_V2_CALLS" | tr -d ' ')" == 2 ]] \
  || fail "the v2 lane did not authenticate before and after finalization: $(cat "$FB_V2_CALLS")"
[[ "$(NI_CEREMONY_POSTURE=relaxed v2_firstboot status)" == complete ]] || fail "owner-sealed v2 completion did not validate"
[[ "$(wc -l < "$FB_V2_CALLS" | tr -d ' ')" == 3 ]] || fail "the retained check did not re-verify the receipt"
v2_evidence="$FB_STATE/owner-ceremony-evidence-v2.json"
python3 - "$v2_evidence" "$FB_STATE/v2-release/receipt.json" <<'PY' || fail "the lane-2 evidence is not the contract object"
import hashlib, json, sys
raw = open(sys.argv[1], "rb").read(); d = json.loads(raw); r = open(sys.argv[2], "rb").read()
v = d["v2_release"]
assert d["schema"] == "neural-ice-owner-ceremony-evidence-v2-lane2" and "ota_preseal" not in d
assert set(v) == {"bundle_seq", "manifest_sha256", "manifest_sig_sha256", "receipt_schema", "receipt_sha256", "release_id", "release_key_sha256"}
assert v["bundle_seq"] == d["ota_state"]["baseline_floor"] == 42 and v["receipt_sha256"] == hashlib.sha256(r).hexdigest()
assert d["install_identity"]["release_identity_sha256"] == v["manifest_sha256"]
assert d["ota_state"]["clear_protected_at_completion"] is True and d["ota_state"]["anchor_state_at_completion"] == "pristine"
PY
grep -q '^NI-DONE2' < <(tpm2_nvread 0x01500006 -C 0x01500006 -s 8 2>/dev/null) \
  || fail "owner-sealed v2 ceremony did not persist NI-DONE2"

# The TPM protections are the real ones: no Clear, no NV floor write, no undefine.
expect_refusal "tpm2_clear (lockout) succeeded on a v2-lane appliance" tpm2_clear -c l
expect_refusal "tpm2_clear (platform) succeeded on a v2-lane appliance" tpm2_clear -c p
printf '\000\000\000\000\000\000\000\001' > "$TMP/floor-rollback.bin"
expect_refusal "the NV floor was rewritten on a v2-lane appliance" \
  tpm2_nvwrite 0x01500001 -C o -i "$TMP/floor-rollback.bin"
expect_refusal "the NV floor was undefined on a v2-lane appliance" tpm2_nvundefine 0x01500001 -C o
[[ "$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["baseline_floor"])' "$("$FB_OTA_STATE" inspect-v2)")" == 42 ]] \
  || fail "the NV floor does not hold the receipt bundle_seq"

# Second boot after an orderly TPM restart; then every integrity break refuses,
# in relaxed too: evidence, receipt, manifest, verifier and the lane marker.
stop_swtpm
start_swtpm
for posture in strict relaxed; do
  [[ "$(NI_CEREMONY_POSTURE=$posture v2_firstboot status)" == complete ]] \
    || fail "v2-lane retained validation failed after an orderly SWTPM restart ($posture)"
done
cp "$v2_evidence" "$TMP/v2-evidence.good"
cp "$FB_STATE/v2-release/receipt.json" "$TMP/v2-receipt.good"
cp "$FB_STATE/v2-release-input-v1/release-manifest.json" "$TMP/v2-manifest.good"
for posture in strict relaxed; do
  export NI_CEREMONY_POSTURE=$posture
  python3 - "$v2_evidence" <<'PY'
import json, sys
p = sys.argv[1]; d = json.load(open(p)); d["v2_release"]["release_id"] = "forged"
open(p, "w").write(json.dumps(d, sort_keys=True, separators=(",", ":")) + "\n")
PY
  expect_refusal "altered v2 completion evidence validated ($posture)" v2_firstboot status
  cp "$TMP/v2-evidence.good" "$v2_evidence"
  printf '\n' >> "$FB_STATE/v2-release/receipt.json"
  expect_refusal "a receipt that is not the TPM-bound one validated ($posture)" v2_firstboot status
  cp "$TMP/v2-receipt.good" "$FB_STATE/v2-release/receipt.json"
  printf 'x' >> "$FB_STATE/v2-release-input-v1/release-manifest.json"
  expect_refusal "a manifest swapped after the install validated ($posture)" v2_firstboot status
  cp "$TMP/v2-manifest.good" "$FB_STATE/v2-release-input-v1/release-manifest.json"
  : > "$TMP/v2-refuse"
  expect_refusal "a refusing v2 verifier validated ($posture)" v2_firstboot status
  rm -f "$TMP/v2-refuse"
  printf 'owner-sealed-ota-state-v1\n' > "$FB_OTA_PROFILE"
  expect_refusal "lane-2 evidence validated under a v1 marker ($posture)" v2_firstboot status
  printf 'owner-sealed-ota-state-v2\n' > "$FB_OTA_PROFILE"
  [[ "$(v2_firstboot status)" == complete ]] || fail "the restored v2 completion no longer validates ($posture)"
done
unset NI_CEREMONY_POSTURE
expect_refusal "the v1 runtime reader accepted the lane-2 completion" \
  hw runtime-status "$PROFILE" "$TARGET" "$POLICY" \
  "$(python3 -c 'import hashlib,sys; print(hashlib.sha256(b"neural-ice:tpm:owner-ceremony-completion:v2\0"+open(sys.argv[1],"rb").read()).hexdigest())' "$v2_evidence")" 1 1

echo "SWTPM_TPM_STATE_TEST_OK (real TPM 2.0 + real cryptsetup LUKS2 headers; owner-sealed v2 lane with a contract-conformant fake of the v2 verifier; anchor signer fixture is explicitly synthetic; signed physical recovery and GB10 gates remain)"
