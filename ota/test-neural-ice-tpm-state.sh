#!/usr/bin/env bash
# shellcheck disable=SC2016 # literal source-contract assertions below
# THE TPM-BACKED APPLIANCE STATE. Three indices, one property: an attacker who
# wipes the disk must not be able to wipe what the machine remembers, and an
# attacker who owns the running system must not be able to restate what the
# appliance IS.
#
# The TPM is mocked here -- a CI runner has none -- but the mock is a real,
# persistent store with the semantics tpm2-tools has: per-index attributes and
# authorization policy, policy SESSIONS that must satisfy the index's policy AND
# name the right command, counters that only increment, and a write-lock that is
# permanent. Every refusal below is decided by the helper, not by the mock.
#
# 🔴 THIS SUITE DOES NOT PROVE THE TPM AGREES. ci/test-swtpm-monotonic-state.sh
# drives the same helper against a REAL TPM 2.0 and is the only thing that can
# say `nt=counter`, `writedefine` and PolicyOR behave as this file assumes.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT/ota/neural-ice-tpm-state.sh"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/ni-tpm-state.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

for t in python3 flock sha256sum; do
  command -v "$t" >/dev/null 2>&1 \
    || fail "$t is unavailable; this suite proves nothing without it and must not report green"
done

TOOLS="$TMP/tools"; NV="$TMP/nv"; SESS="$TMP/sessions"; PERSIST="$TMP/persistent"
OWNER_AUTH_MARK="$TMP/owner-auth"
mkdir -p "$TOOLS" "$NV" "$SESS" "$PERSIST"
for t in python3 flock sha256sum od head wc awk; do ln -sf "$(command -v "$t")" "$TOOLS/$t"; done

# --------------------------------------------------------------------------- #
# The "TPM". Each defined index is a directory: `data`, `attrs`, `policy`,
# `size`, and `locked` once TPM2_NV_WriteLock has been honoured.
# --------------------------------------------------------------------------- #
cat > "$TOOLS/tpm2_getcap" <<EOF
#!/usr/bin/env bash
case "\$1" in
  handles-nv-index)
    for d in "$NV"/*; do
      [[ -d "\$d" ]] || continue
      printf -- '- 0x%s\n' "\$(basename "\$d")"
    done ;;
  handles-persistent)
    for h in "$PERSIST"/*; do
      [[ -e "\$h" ]] || continue
      printf -- '- 0x%s\n' "\$(basename "\$h")"
    done ;;
  properties-variable)
    # TPM2_PT_PERMANENT, as tpm2-tools renders it. \`ownerAuthSet\` is the TPM's
    # own answer to "does the owner hierarchy still take an empty password".
    printf 'TPM2_PT_PERMANENT:\n'
    if [[ -e "$OWNER_AUTH_MARK" ]]; then
      printf '  ownerAuthSet:              1\n'
    else
      printf '  ownerAuthSet:              0\n'
    fi
    printf '  lockoutAuthSet:            0\n' ;;
  *) exit 2 ;;
esac
EOF
# TPM2_NV_UndefineSpace under OWNER authorization: the residual this tree
# documents, and the move the mutations below are about. The TPM refuses it once
# the owner hierarchy carries a non-empty authorization the caller cannot supply.
cat > "$TOOLS/tpm2_nvundefine" <<EOF
#!/usr/bin/env bash
index=""; auth_supplied=0
while (( \$# )); do
  case "\$1" in
    -C) shift 2 ;;
    -P) auth_supplied=1; shift 2 ;;
    0x*) index="\${1#0x}"; shift ;;
    *) shift ;;
  esac
done
[[ -d "$NV/\$index" ]] || exit 1
if [[ -e "$OWNER_AUTH_MARK" && "\$auth_supplied" != 1 ]]; then exit 1; fi
rm -rf "$NV/\$index"
EOF
cat > "$TOOLS/tpm2_changeauth" <<EOF
#!/usr/bin/env bash
# Only the OWNER hierarchy, and only BY FILE: an authorization value passed as an
# argument sits in /proc for every process on the machine to read.
[[ "\$1" == -c && "\$2" == o ]] || exit 2
[[ "\$3" == file:* ]] || exit 2
value="\${3#file:}"
[[ -f "\$value" ]] || exit 1
[[ "\$(wc -c < "\$value" | tr -d '[:space:]')" == 32 ]] || exit 1
[[ ! -e "$OWNER_AUTH_MARK" ]] || exit 1
[[ "\${NI_TEST_CHANGEAUTH_FAIL:-}" != 1 ]] || exit 1
: > "$OWNER_AUTH_MARK"
EOF
cat > "$TOOLS/tpm2_nvdefine" <<EOF
#!/usr/bin/env bash
index=""; size=""; attrs=""; policy=""
auth_supplied=0
while (( \$# )); do
  case "\$1" in
    -s) size="\$2"; shift 2 ;;
    -a) attrs="\$2"; shift 2 ;;
    -L) policy="\$2"; shift 2 ;;
    -C) shift 2 ;;
    -P) auth_supplied=1; shift 2 ;;
    0x*) index="\${1#0x}"; shift ;;
    *) shift ;;
  esac
done
[[ -n "\$index" && -n "\$size" && -n "\$attrs" ]] || exit 2
# A NON-EMPTY POLICY IS THE CONTRACT. The mock refuses a definition without one
# for the same reason the helper must never emit one: an index whose own
# authorization is empty is an index anybody can use.
[[ -n "\$policy" ]] || exit 1
if [[ -e "$OWNER_AUTH_MARK" && "\$auth_supplied" != 1 ]]; then exit 1; fi
[[ ! -d "$NV/\$index" ]] || exit 1
mkdir -p "$NV/\$index"
printf '%s' "\$attrs" > "$NV/\$index/attrs"
printf '%s' "\$size" > "$NV/\$index/size"
cp "\$policy" "$NV/\$index/policy"
if [[ "\$attrs" == *"nt=counter"* ]]; then
  # TPM 2.0 (Part 1, NV counters): a new counter is initialised to the largest
  # value any counter of this TPM ever held, and that value survives TPM2_Clear.
  # Measured on the lab GX10 on 2026-09-09 (index absent, born at 9) and on
  # 2026-09-10 (freshness counter born at 21).
  python3 -c 'import struct,sys,os; m=int(open(sys.argv[2]).read()) if os.path.exists(sys.argv[2]) else 0; open(sys.argv[1],"wb").write(struct.pack(">Q",m))' "$NV/\$index/data" "$NV/.max-ever"
else
  head -c "\$size" /dev/zero > "$NV/\$index/data"
fi
printf 'nv-index: 0x%s\n' "\$index"
EOF
# `tpm2_nvreadpublic` renders the same YAML-ish shape tpm2-tools emits, which is
# what the helper parses to prove an index still has the SHAPE it defined.
cat > "$TOOLS/tpm2_nvreadpublic" <<EOF
#!/usr/bin/env bash
index=""; name_out=""
while (( \$# )); do
  case "\$1" in
    -n) name_out="\$2"; shift 2 ;;
    0x*) index="\${1#0x}"; shift ;;
    *) shift ;;
  esac
done
[[ -d "$NV/\$index" ]] || exit 1
attrs="\$(cat "$NV/\$index/attrs")"
raw=0
case "\$attrs" in *policywrite*) raw=\$(( raw | 0x8 ));; esac
case "\$attrs" in *"nt=counter"*) raw=\$(( raw | 0x10 ));; esac
case "\$attrs" in *writedefine*) raw=\$(( raw | 0x2000 ));; esac
case "\$attrs" in *ownerread*) raw=\$(( raw | 0x20000 ));; esac
case "\$attrs" in *authread*) raw=\$(( raw | 0x40000 ));; esac
case "\$attrs" in *ownerwrite*) raw=\$(( raw | 0x2 ));; esac
[[ -e "$NV/\$index/locked" ]] && raw=\$(( raw | 0x800 ))
# TPMA_NV_WRITTEN — the TPM sets it the first time an index is written or
# incremented, and clears it only when the index is undefined and redefined.
[[ -e "$NV/\$index/written" ]] && raw=\$(( raw | 0x20000000 ))
printf '0x%s:\n' "\$index"
name="\$( { printf '%s:%x:' "\$index" "\$raw"; cat "$NV/\$index/policy"; } | sha256sum | awk '{print \$1}')"
printf '  name: 000b%s\n' "\${name:0:64}"
printf '  hash algorithm:\n    friendly: sha256\n    value: 0xB\n'
printf '  attributes:\n    friendly: %s\n    value: 0x%x\n' "\$attrs" "\$raw"
printf '  size: %s\n' "\$(cat "$NV/\$index/size")"
printf '  authorization policy: %s\n' "\$(od -An -tx1 -v "$NV/\$index/policy" | tr -d '[:space:]')"
if [[ -n "\$name_out" ]]; then
  printf 'mock-nv-name:%s:%x:' "\$index" "\$raw" > "\$name_out"
  cat "$NV/\$index/policy" >> "\$name_out"
fi
EOF
# Policy sessions. A session accumulates a digest and remembers the command code
# it was built for; an operation must present a session whose digest equals the
# index's policy AND whose command code is the operation being attempted.
cat > "$TOOLS/tpm2_startauthsession" <<EOF
#!/usr/bin/env bash
ctx=""
while (( \$# )); do
  case "\$1" in -S) ctx="\$2"; shift 2 ;; *) shift ;; esac
done
[[ -n "\$ctx" ]] || exit 2
name="\$(printf '%s' "\$ctx" | sha256sum | awk '{print \$1}')"
mkdir -p "$SESS"
: > "$SESS/\$name.cc"
: > "$SESS/\$name.digest"
printf '%s' "\$name" > "\$ctx"
EOF
cat > "$TOOLS/tpm2_policycommandcode" <<EOF
#!/usr/bin/env bash
# The digests below are the ones a REAL TPM computes for these policies over a
# zero starting digest -- they are properties of the TPM specification, and
# ci/test-swtpm-monotonic-state.sh is what proves this mock did not invent them.
# The helper cross-checks them against its own constants, so a mock that made
# them up would make that cross-check untestable.
ctx=""; out=""; cc=""
while (( \$# )); do
  case "\$1" in
    -S) ctx="\$2"; shift 2 ;;
    -L) out="\$2"; shift 2 ;;
    *) cc="\$1"; shift ;;
  esac
done
[[ -n "\$ctx" && -n "\$cc" ]] || exit 2
case "\$cc" in
  TPM2_CC_NV_Increment) digest=e8c02d3c5e701670cbaa327db1a2e9f3f41b2c22793e5c669a6e7f44b912f6c0 ;;
  TPM2_CC_NV_Write)     digest=1c4f7107dcaf23ce00756448508558683104bd9e203e93749c227b451270438f ;;
  TPM2_CC_NV_WriteLock) digest=c8905eb3b7302fc69bb1a52843b142f3e2faf66386f04f89b86cf6399b30e301 ;;
  *) exit 2 ;;
esac
name="\$(cat "\$ctx")"
printf '%s' "\$cc" > "$SESS/\$name.cc"
printf '%s' "\$digest" > "$SESS/\$name.digest"
[[ -z "\$out" ]] || python3 -c 'import sys; open(sys.argv[1],"wb").write(bytes.fromhex(sys.argv[2]))' "\$out" "\$digest"
EOF
cat > "$TOOLS/tpm2_policyor" <<EOF
#!/usr/bin/env bash
ctx=""; out=""; branches=""
while (( \$# )); do
  case "\$1" in
    -S) ctx="\$2"; shift 2 ;;
    -L) out="\$2"; shift 2 ;;
    sha256:*) branches="\${1#sha256:}"; shift ;;
    *) shift ;;
  esac
done
[[ -n "\$ctx" && -n "\$branches" ]] || exit 2
name="\$(cat "\$ctx")"
concat=""
IFS=',' read -ra parts <<< "\$branches"
for part in "\${parts[@]}"; do
  concat="\$concat\$(od -An -tx1 -v "\$part" | tr -d '[:space:]')"
done
# The one PolicyOR this tree uses: NV_Write OR NV_WriteLock. Any other branch set
# is not something the helper is allowed to build, so the mock refuses it rather
# than inventing a digest nobody could check.
[[ "\$concat" == 1c4f7107dcaf23ce00756448508558683104bd9e203e93749c227b451270438fc8905eb3b7302fc69bb1a52843b142f3e2faf66386f04f89b86cf6399b30e301 ]] || exit 2
digest=f83217e5a2a04342f7daa55ccfb3cd4b8a1f1e8ebb28c7719a9abbdbd638a230
current="\$(cat "$SESS/\$name.digest")"
# A PolicyOR only satisfies the index if the session's current digest is one of
# the branches -- exactly the TPM's rule, and the reason a NV_WriteLock session
# cannot masquerade as a NV_Write one.
found=0
for part in "\${parts[@]}"; do
  [[ "\$(od -An -tx1 -v "\$part" | tr -d '[:space:]')" == "\$current" ]] && found=1
done
if [[ -z "\$out" && "\$found" != 1 ]]; then exit 1; fi
printf '%s' "\$digest" > "$SESS/\$name.digest"
[[ -z "\$out" ]] || python3 -c 'import sys; open(sys.argv[1],"wb").write(bytes.fromhex(sys.argv[2]))' "\$out" "\$digest"
EOF
cat > "$TOOLS/tpm2_flushcontext" <<EOF
#!/usr/bin/env bash
[[ -f "\$1" ]] || exit 0
name="\$(cat "\$1")"
rm -f "$SESS/\$name.cc" "$SESS/\$name.digest" "\$1"
EOF
# The three operations. Each requires a policy session that satisfies the index.
cat > "$TOOLS/_ni_check_session" <<EOF
#!/usr/bin/env bash
# \$1=index \$2=session spec (session:CTX) \$3=required command code
index="\$1"; spec="\$2"; want="\$3"
[[ "\$spec" == session:* ]] || exit 1
ctx="\${spec#session:}"
[[ -f "\$ctx" ]] || exit 1
name="\$(cat "\$ctx")"
[[ "\$(cat "$SESS/\$name.cc" 2>/dev/null)" == "\$want" ]] || exit 1
have="\$(cat "$SESS/\$name.digest" 2>/dev/null)"
[[ "\$have" == "\$(od -An -tx1 -v "$NV/\$index/policy" | tr -d '[:space:]')" ]] || exit 1
EOF
cat > "$TOOLS/tpm2_nvincrement" <<EOF
#!/usr/bin/env bash
index=""; auth=""
while (( \$# )); do
  case "\$1" in
    -P) auth="\$2"; shift 2 ;;
    -C) shift 2 ;;
    0x*) index="\${1#0x}"; shift ;;
    *) shift ;;
  esac
done
[[ -d "$NV/\$index" ]] || exit 1
[[ "\$(cat "$NV/\$index/attrs")" == *"nt=counter"* ]] || exit 1
bash "$TOOLS/_ni_check_session" "\$index" "\$auth" TPM2_CC_NV_Increment || exit 1
[[ -z "\${NI_TEST_INCREMENT_TRACE:-}" ]] || printf '%s\n' "\$index" >> "\$NI_TEST_INCREMENT_TRACE"
python3 - "$NV/\$index/data" "$NV/.max-ever" <<'PY'
import os, struct, sys
path, max_path = sys.argv[1], sys.argv[2]
value, = struct.unpack(">Q", open(path, "rb").read())
open(path, "wb").write(struct.pack(">Q", value + 1))
previous = int(open(max_path).read()) if os.path.exists(max_path) else 0
open(max_path, "w").write(str(max(previous, value + 1)))
PY
: > "$NV/\$index/written"
EOF
cat > "$TOOLS/tpm2_nvwrite" <<EOF
#!/usr/bin/env bash
index=""; input=""; auth=""
while (( \$# )); do
  case "\$1" in
    -i) input="\$2"; shift 2 ;;
    -P) auth="\$2"; shift 2 ;;
    -C) shift 2 ;;
    0x*) index="\${1#0x}"; shift ;;
    *) shift ;;
  esac
done
[[ -d "$NV/\$index" && -n "\$input" ]] || exit 1
# A counter refuses an ordinary write; a locked index refuses every write. Both
# are the TPM's own rules, not this helper's.
[[ "\$(cat "$NV/\$index/attrs")" == *"nt=counter"* ]] && exit 1
[[ -e "$NV/\$index/locked" ]] && exit 1
bash "$TOOLS/_ni_check_session" "\$index" "\$auth" TPM2_CC_NV_Write || exit 1
cp "\$input" "$NV/\$index/data"
: > "$NV/\$index/written"
EOF
cat > "$TOOLS/tpm2_nvwritelock" <<EOF
#!/usr/bin/env bash
index=""; auth=""
while (( \$# )); do
  case "\$1" in
    -P) auth="\$2"; shift 2 ;;
    -C) shift 2 ;;
    0x*) index="\${1#0x}"; shift ;;
    *) shift ;;
  esac
done
[[ -d "$NV/\$index" ]] || exit 1
[[ "\$(cat "$NV/\$index/attrs")" == *writedefine* ]] || exit 1
bash "$TOOLS/_ni_check_session" "\$index" "\$auth" TPM2_CC_NV_WriteLock || exit 1
: > "$NV/\$index/locked"
EOF
cat > "$TOOLS/tpm2_nvread" <<EOF
#!/usr/bin/env bash
index=""; out=""; size=""
while (( \$# )); do
  case "\$1" in
    -o) out="\$2"; shift 2 ;;
    -s) size="\$2"; shift 2 ;;
    -C) shift 2 ;;
    0x*) index="\${1#0x}"; shift ;;
    *) shift ;;
  esac
done
[[ -n "\$index" && -n "\$out" ]] || exit 2
[[ -d "$NV/\$index" ]] || exit 1
head -c "\${size:-8}" "$NV/\$index/data" > "\$out"
EOF
chmod +x "$TOOLS"/tpm2_* "$TOOLS/_ni_check_session"
export PATH="$TOOLS:$PATH"

export NI_TPM_STATE_TESTING=1
export NI_TPM_STATE_TEST_TOOLS="$TOOLS"
export NI_TPM_STATE_TEST_RUN_DIR="$TMP/run"
OWNER_OTA_FLOOR="$TMP/owner-ota-floor"
OWNER_OTA_CLEAR="$TMP/owner-ota-clear"
cat > "$TOOLS/owner-ota-helper" <<EOF
#!/usr/bin/env bash
set -euo pipefail
[[ "\${1:-}" == inspect-v2 && \$# == 1 ]]
python3 - "$OWNER_OTA_FLOOR" "$OWNER_OTA_CLEAR" "$OWNER_AUTH_MARK" <<'PY'
import json,pathlib,sys
floor=int(pathlib.Path(sys.argv[1]).read_text())
clear=pathlib.Path(sys.argv[2]).read_text().strip()=="1"
owner=pathlib.Path(sys.argv[3]).exists()
print(json.dumps({
 "anchor_attributes":"0x2060048","anchor_index":"0x01500002",
 "anchor_name":"000b038de2091c1c8ef2e8fd8869f17bef3a576ae287530fa17f05ae3b9712014b5d",
 "anchor_policy_sha256":"b6a2e7142ee56fd978047488483daa5b42b8dc4cc7ddcceddfb91793cf1ff1b7",
 "anchor_sha256":None,"anchor_size":32,"anchor_state":"pristine",
 "baseline_floor":floor,"clear_protected":clear,"floor_attributes":"0x62008",
 "floor_index":"0x01500001",
 "floor_name":"000be283f20a38b93f8cef085efb4aee9f5944cc3b3b28b850bf3c0eeb2054cd7fc4",
 "floor_policy_sha256":"f83217e5a2a04342f7daa55ccfb3cd4b8a1f1e8ebb28c7719a9abbdbd638a230",
 "floor_size":8,"owner_sealed":owner,"profile":"owner-sealed-ota-state-v1",
 "schema":"neural-ice-owner-ota-state-inspection-v2"},sort_keys=True,separators=(",",":")))
PY
EOF
chmod 0700 "$TOOLS/owner-ota-helper"
export NI_TPM_STATE_TEST_OTA_HELPER="$TOOLS/owner-ota-helper"
st() { bash "$SCRIPT" "$@"; }
activate_pcr_policy() {
  [ "$(st pcr-policy-check 1)" = 0 ] || fail "virgin PCR policy high-water check failed"
  [ ! -d "$NV/01500008" ] || fail "the read-only check sealed a generation base"
  [ "$(st pcr-policy-activate 1)" = 1 ] || fail "initial PCR policy activation failed"
  [ -d "$NV/01500008" ] || fail "activation did not seal the generation base"
  [ "$(st pcr-policy-generation)" = 1 ] || fail "the activated generation is not the sealed label plus the counter's distance"
}

TARGET=nvidia-gb10-arm64
POLICY=neural-ice-secureboot-lab-v1

# Runtime readers and profile-bind never create missing state.
[ "$(st provisioning-status)" = virgin ] || fail "an exact virgin TPM was refused"
for command in counter-read freshness-read profile-read; do
  st "$command" >/dev/null 2>&1 && fail "$command treated absence as usable state"
done
st profile-bind customer-locked "$TARGET" "$POLICY" >/dev/null 2>&1 \
  && fail "profile-bind created missing provisioning state"
if [ -d "$NV/01500004" ] || [ -d "$NV/01500005" ]; then
  fail "a runtime command created state"
fi

EXPECT="$(st profile-digest customer-locked "$TARGET" "$POLICY")"
: > "$OWNER_AUTH_MARK"
out="$(st ceremony-prepare customer-locked "$TARGET" "$POLICY" 4 2>&1)" \
  && fail "an attacker-known pre-set owner authorization was accepted"
grep -Fq 'ownerAuthSet=1 before the trusted ceremony' <<<"$out" \
  || fail "pre-set auth was refused for the wrong reason: $out"
rm -f "$OWNER_AUTH_MARK"

# Exact prerequisites, not handle names alone, are checked by the firstboot
# wrapper; the TPM helper at least refuses absent persistent objects.
st ceremony-prepare customer-locked "$TARGET" "$POLICY" 4 >/dev/null 2>&1 \
  && fail "ceremony ran without device root and SRK"
: > "$PERSIST/81010005"; : > "$PERSIST/81000001"
activate_pcr_policy
[ "$(st provisioning-status)" = pcr-policy-activated ] \
  || fail "PCR-only pre-ceremony state was not identified"
prerequisite_digest="$(sha256sum "$PERSIST/81010005" "$PERSIST/81000001")"

# ADR-0015 N and O: installation is a factory operation. The generation lives in
# label + (counter - born), both sealed at 0x01500008 by the first activation,
# which therefore costs ONE increment whatever the label. Before the owner
# ceremony a retry is allowed at or above the activated generation: the check
# writes nothing and prints generation - 1, an equal label advances the counter
# by nothing, a higher label by the difference (bounded), a lower label is refused.
counter_value_of() { python3 -c 'import struct,sys; print(struct.unpack(">Q",open(sys.argv[1],"rb").read())[0])' "$NV/$1/data"; }
base_value_of() { python3 -c 'import struct,sys; print(struct.unpack(">Q",open(sys.argv[1],"rb").read()[8:16])[0])' "$NV/01500008/data"; }
label_value_of() { python3 -c 'import struct,sys; print(struct.unpack(">Q",open(sys.argv[1],"rb").read()[16:24])[0])' "$NV/01500008/data"; }
before="$(counter_value_of 01500007)"
[ "$(counter_value_of 01500007)" = "$(base_value_of)" ] || fail "the first activation spun the counter instead of sealing the label"
[ "$(label_value_of)" = 1 ] || fail "the sealed label is not the activated generation"
[ "$(st pcr-policy-check 1)" = 0 ] || fail "pre-ceremony retry of the same generation was refused"
st pcr-policy-check 0 >/dev/null 2>&1 && fail "zero PCR policy sequence was accepted"
[ "$(counter_value_of 01500007)" = "$before" ] || fail "the read-only check moved the activation counter"
[ "$(st pcr-policy-check 2)" = 0 ] || fail "pre-ceremony retry of a higher generation was refused"
[ "$(st pcr-policy-activate 1)" = 1 ] || fail "pre-ceremony retry of the same generation did not activate"
[ "$(counter_value_of 01500007)" = "$before" ] || fail "re-activating the same generation moved the counter"
[ "$(st pcr-policy-activate 2)" = 2 ] || fail "pre-ceremony retry of a higher generation did not activate"
[ "$(counter_value_of 01500007)" = "$((before + 1))" ] || fail "activating the next generation did not advance the counter by exactly one"
[ "$(st pcr-policy-generation)" = 2 ] || fail "the generation did not follow the counter"
st pcr-policy-check 1 >/dev/null 2>&1 && fail "a generation below the activated one passed the check"
st pcr-policy-activate 1 >/dev/null 2>&1 && fail "a generation below the activated one was activated"
[ "$(counter_value_of 01500007)" = "$((before + 1))" ] || fail "a refused activation moved the counter"
[ "$(st provisioning-status)" = pcr-policy-activated ] \
  || fail "pre-ceremony retries left the supported pre-ceremony state"
[ "$(sha256sum "$PERSIST/81010005" "$PERSIST/81000001")" = "$prerequisite_digest" ] \
  || fail "pre-ceremony retries changed persistent prerequisites"

# THE C30/C32 CASE (GX10, 2026-09-11): the PCR policy index is absent after a
# TPM Clear but the chip's counters already reached 1050 (the previous cycle's
# issuance). A factory medium sealed at generation 1004 must install with ONE
# increment (C32 spun the counter 1105 times, minutes of silence on a discrete
# TPM): the counter is born at 1050, reads 1051, and the record seals
# (1051, 1004); the initramfs reads label + (counter - born), never the
# absolute value.
rm -rf "${NV:?}"/* "${NV:?}/.max-ever"
printf '1050' > "$NV/.max-ever"
[ "$(st pcr-policy-check 1004)" = 0 ] || fail "a factory medium was compared to the chip's counter history"
[ ! -d "$NV/01500007" ] || fail "the read-only check created the activation counter"
trace="$NI_TPM_STATE_TEST_RUN_DIR/increment-trace"; rm -f "$trace"
[ "$(NI_TEST_INCREMENT_TRACE="$trace" st pcr-policy-activate 1004)" = 1004 ] || fail "a factory generation below the chip's max-ever did not activate"
[ "$(grep -c . "$trace")" = 1 ] || fail "the first activation cost $(grep -c . "$trace") counter increments instead of one (ADR-0015 O)"
[ "$(base_value_of)" = 1051 ] || fail "the sealed base is not the counter value at first activation"
[ "$(label_value_of)" = 1004 ] || fail "the sealed label is not the activated generation"
[ "$(counter_value_of 01500007)" = 1051 ] || fail "the first activation spun the counter"
[ "$(st pcr-policy-generation)" = 1004 ] || fail "the C30 generation is not the sealed label plus the counter's distance"
[ "$(st pcr-policy-activate 1004)" = 1004 ] || fail "re-activating the C30 generation was refused"
[ "$(counter_value_of 01500007)" = 1051 ] || fail "re-activating the C30 generation moved the counter"
st pcr-policy-activate 1003 >/dev/null 2>&1 && fail "a lower generation was activated on the C30 chip"
[ "$(st pcr-policy-activate 1010)" = 1010 ] || fail "a higher generation was refused on the C30 chip"
[ "$(counter_value_of 01500007)" = 1057 ] || fail "the higher generation did not advance the counter by its difference"
[ "$(st pcr-policy-generation)" = 1010 ] || fail "the generation did not follow the counter's distance"
out="$(st pcr-policy-check 1075 2>&1)" && fail "a retry 65 generations ahead was accepted by the check"
grep -Fq 'clear the TPM' <<<"$out" || fail "the bounded-retry refusal does not name the TPM clear: $out"
out="$(st pcr-policy-activate 1075 2>&1)" && fail "a retry 65 generations ahead was activated"
grep -Fq 'clear the TPM' <<<"$out" || fail "the bounded-activation refusal does not name the TPM clear: $out"
[ "$(counter_value_of 01500007)" = 1057 ] || fail "a refused bounded activation moved the counter"
[ "$(st pcr-policy-check 1074)" = 1009 ] || fail "a retry 64 generations ahead was refused"
[ "$(st provisioning-status)" = pcr-policy-activated ] || fail "the C30 install was not identified as pre-ceremony state"
# A record written before amendment O carries a zero label: the old reading.
python3 - "$NV/01500008/data" <<'PY'
import sys
p = sys.argv[1]; b = bytearray(open(p, "rb").read()); b[16:24] = bytes(8); open(p, "wb").write(bytes(b))
PY
[ "$(st pcr-policy-generation)" = 6 ] || fail "a zero sealed label did not read as counter minus born"
rm -rf "${NV:?}"/* "${NV:?}/.max-ever"; rm -f "$OWNER_AUTH_MARK"
# The largest label of the activation window still costs one increment.
rm -f "$trace"
[ "$(NI_TEST_INCREMENT_TRACE="$trace" st pcr-policy-activate 4096)" = 4096 ] || fail "the largest window label did not activate"
[ "$(grep -c . "$trace")" = 1 ] || fail "label 4096 cost $(grep -c . "$trace") increments instead of one"
rm -rf "${NV:?}"/* "${NV:?}/.max-ever"; rm -f "$OWNER_AUTH_MARK" "$trace"
activate_pcr_policy

# Interrupted ceremony: fixed state landed, owner auth did not. Deleting record
# only, then record+freshness, must never make the mock call the TPM virgin once
# provisioning began because the install counter survives both attacks.
result="$(st ceremony-prepare customer-locked "$TARGET" "$POLICY" 4)"
read -r install_at freshness_at _ <<<"$result"
NI_TEST_CHANGEAUTH_FAIL=1 st ceremony-finalize customer-locked "$TARGET" "$POLICY" \
  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa "$install_at" "$freshness_at" >/dev/null 2>&1 \
  && fail "the injected owner-auth failure succeeded"
"$TOOLS/tpm2_nvundefine" 0x01500005 -C o || fail "could not delete record before seal"
st provisioning-status >/dev/null 2>&1 && fail "record deletion became virgin"
st ceremony-prepare customer-locked "$TARGET" "$POLICY" 4 >/dev/null 2>&1 \
  && fail "ceremony recreated a deleted record"
rm -rf "${NV:?}"/* "${NV:?}/.max-ever"
activate_pcr_policy

# A process loss after successful changeauth is already a completed lifecycle:
# the completion record and evidence digest were locked before the last
# irreversible operation, and no mutable publication remains afterward.
result="$(st ceremony-prepare customer-locked "$TARGET" "$POLICY" 4)"
read -r install_at freshness_at _ <<<"$result"
NI_TEST_INTERRUPT_AFTER_CHANGEAUTH=1 st ceremony-finalize customer-locked "$TARGET" "$POLICY" \
  bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
  "$install_at" "$freshness_at" >/dev/null 2>&1 \
  && fail "the injected post-changeauth interruption reported success"
[ "$(st runtime-status customer-locked "$TARGET" "$POLICY" \
  bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
  "$install_at" "$freshness_at")" = complete ] \
  || fail "post-changeauth interruption was not recoverable as authenticated complete"
rm -rf "${NV:?}"/* "${NV:?}/.max-ever"; rm -f "$OWNER_AUTH_MARK"
activate_pcr_policy

result="$(st ceremony-prepare customer-locked "$TARGET" "$POLICY" 4)"
read -r install_at freshness_at _ <<<"$result"
NI_TEST_CHANGEAUTH_FAIL=1 st ceremony-finalize customer-locked "$TARGET" "$POLICY" \
  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa "$install_at" "$freshness_at" >/dev/null 2>&1 \
  && fail "the second injected owner-auth failure succeeded"
"$TOOLS/tpm2_nvundefine" 0x01500005 -C o || fail "could not delete record before seal"
"$TOOLS/tpm2_nvundefine" 0x01500004 -C o || fail "could not delete freshness before seal"
st provisioning-status >/dev/null 2>&1 && fail "deleting record+freshness became virgin"
st ceremony-prepare customer-locked "$TARGET" "$POLICY" 4 >/dev/null 2>&1 \
  && fail "ceremony recreated both deleted indices"
rm -rf "${NV:?}"/* "${NV:?}/.max-ever"
activate_pcr_policy

# THE GX10 CASE (2026-09-10, NI-E02 on every first boot): the chip's counters
# already went to 21 (PCR policy sequences of the bench, before a TPM Clear), so the freshness
# and install counters are BORN at 21 while the release's issuance sequence is 4. The
# ceremony must bind and report the high-water from the sealed base, not refuse --
# and (ADR-0015 O) seal the issuance sequence as the ORIGIN instead of spinning
# the counter to it: C29 spun the GX10's counter 1050 times at first boot.
printf '21' > "$NV/.max-ever"
rm -f "$trace"
result="$(NI_TEST_INCREMENT_TRACE="$trace" st ceremony-prepare customer-locked "$TARGET" "$POLICY" 4)"
[ "$(grep -c . "$trace")" = 2 ] || fail "the ceremony cost $(grep -c . "$trace") counter increments instead of two (install + freshness WRITTEN)"
[ "$result" = "22 4 $EXPECT" ] || fail "ceremony returned unexpected evidence: $result"
st ceremony-finalize customer-locked "$TARGET" "$POLICY" \
  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 22 4 >/dev/null
snapshot="$(st state-snapshot customer-locked "$TARGET" "$POLICY")"
python3 - "$snapshot" <<'PY' || fail "state snapshot does not bind both exact NV public Names and values"
import json,re,sys
d=json.loads(sys.argv[1])
assert d["install_counter"] == 22 and d["freshness_counter"] == 4
assert re.fullmatch(r"[0-9a-f]{64}",d["install_public_sha256"])
assert re.fullmatch(r"[0-9a-f]{64}",d["freshness_public_sha256"])
assert d["install_public_sha256"] != d["freshness_public_sha256"]
PY
[ "$(st runtime-status customer-locked "$TARGET" "$POLICY" \
  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 22 4)" = complete ] \
  || fail "completed state did not pass runtime status"
out="$(st pcr-policy-check 4096 2>&1)" && fail "a provisioned device accepted a factory install without TPM2_Clear"
grep -Fq 'requires TPM2_Clear' <<<"$out" || fail "the provisioned-device refusal does not name TPM2_Clear: $out"
st pcr-policy-activate 4096 >/dev/null 2>&1 && fail "a provisioned device activated a factory generation without TPM2_Clear"
[ "$(st counter-read)" = 22 ] || fail "install counter mismatch"
[ "$(st freshness-read)" = 4 ] || fail "freshness is not counted from the sealed base"
python3 - "$NV/01500004/data" "$NV/01500005/data" <<'PY' || fail "the counter was not born at the chip's max-ever, or the record does not seal that base and origin"
import struct, sys
counter, = struct.unpack(">Q", open(sys.argv[1], "rb").read())
record = open(sys.argv[2], "rb").read()
base, origin = struct.unpack(">QQ", record[40:56])
assert base == 23, base          # install counter born at 21 -> 22 (max-ever 22); freshness born at 22, +1 for WRITTEN
assert origin == 4, origin       # the issuance sequence is sealed, not spun (ADR-0015 O)
assert counter == 23, counter    # the base: nothing was spun
assert record[56:] == bytes(8), record[56:].hex()
PY
[ "$(st profile-read)" = "$EXPECT" ] || fail "profile binding mismatch"
[ "$(st profile-bind customer-locked "$TARGET" "$POLICY")" = "$EXPECT" ] \
  || fail "read-only profile-bind refused exact state"
st profile-bind lab-managed "$TARGET" "$POLICY" >/dev/null 2>&1 \
  && fail "profile-bind accepted a different profile"
st freshness-consume 4 >/dev/null 2>&1 && fail "consumed N replayed"
rm -f "$trace"
[ "$(NI_TEST_INCREMENT_TRACE="$trace" st freshness-consume 5)" = 5 ] || fail "next absolute issuance did not consume"
[ "$(grep -c . "$trace")" = 1 ] || fail "consuming the next issuance cost $(grep -c . "$trace") increments instead of one"
[ "$(st freshness-read)" = 5 ] || fail "absolute high-water did not advance"
out="$(st freshness-consume 70 2>&1)" && fail "an issuance 65 ahead was consumed"
grep -Fq 'signed physical recovery' <<<"$out" || fail "the bounded-consumption refusal does not name the recovery: $out"
[ "$(st freshness-read)" = 5 ] || fail "a refused bounded consumption moved the high-water"
# A record written before amendment O carries a zero origin: the old reading.
python3 - "$NV/01500005/data" <<'PY'
import sys
p = sys.argv[1]; b = bytearray(open(p, "rb").read()); b[48:56] = bytes(8); open(p, "wb").write(bytes(b))
PY
[ "$(st freshness-read)" = 1 ] || fail "a zero sealed origin did not read as counter minus base"
python3 - "$NV/01500005/data" <<'PY'
import struct, sys
p = sys.argv[1]; b = bytearray(open(p, "rb").read()); b[48:56] = struct.pack(">Q", 4); open(p, "wb").write(bytes(b))
PY
[ "$(st freshness-read)" = 5 ] || fail "restoring the origin did not restore the high-water"

# A second ceremony is always refusal; subsequent boots use read-only status.
st ceremony-prepare customer-locked "$TARGET" "$POLICY" 5 >/dev/null 2>&1 \
  && fail "one-time ceremony became idempotent acceptance"
[ "$(st runtime-status customer-locked "$TARGET" "$POLICY" \
  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 22 4)" = complete ] \
  || fail "second-boot runtime status failed"

# Runtime root cannot delete record only, delete both, recreate an index, or
# replace a persistent object once the random owner authorization is destroyed.
for index in 0x01500005 0x01500004; do
  "$TOOLS/tpm2_nvundefine" "$index" -C o 2>/dev/null \
    && fail "runtime root deleted $index after seal"
done
"$TOOLS/tpm2_nvdefine" 0x0150000e -C o -s 8 -a 'policywrite|authread|ownerread|nt=counter' \
  -L "$NV/01500003/policy" >/dev/null 2>&1 \
  && fail "runtime root recreated an owner object after seal"
rm -f "$PERSIST/81000001"
st runtime-status customer-locked "$TARGET" "$POLICY" \
  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 22 4 >/dev/null 2>&1 \
  && fail "persistent SRK mismatch was accepted"
: > "$PERSIST/81000001"
rm -f "$PERSIST/81010005"
st runtime-status customer-locked "$TARGET" "$POLICY" \
  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 22 4 >/dev/null 2>&1 \
  && fail "persistent device-root mismatch was accepted"
: > "$PERSIST/81010005"

# Interrupted record state is never completed by profile-bind.
rm -f "$NV/01500005/locked"
st profile-bind customer-locked "$TARGET" "$POLICY" >/dev/null 2>&1 \
  && fail "profile-bind completed an interrupted record"
: > "$NV/01500005/locked"

# Owner-profile completion uses an exact preseal-prepared discriminator and a
# separately versioned completion record. It must neither weaken nor reinterpret
# the retained v1 commands above.
rm -rf "${NV:?}"/* "${NV:?}/.max-ever"; rm -f "$OWNER_AUTH_MARK"
activate_pcr_policy
printf '42\n' > "$OWNER_OTA_FLOOR"
printf '0\n' > "$OWNER_OTA_CLEAR"
mkdir "$NV/01500001"
st provisioning-status >/dev/null 2>&1 \
  && fail "a partial owner floor was classified as preseal-prepared"
mkdir "$NV/01500002"
rm -f "$PERSIST/81000001"
st provisioning-status >/dev/null 2>&1 \
  && fail "owner preseal state without the persistent SRK was classified as prepared"
: > "$PERSIST/81000001"
rm -f "$PERSIST/81010005"
st provisioning-status >/dev/null 2>&1 \
  && fail "owner preseal state without the device root was classified as prepared"
: > "$PERSIST/81010005"
[ "$(st provisioning-status)" = preseal-prepared ] \
  || fail "the exact owner preseal state was not classified"
result="$(st ceremony-prepare-v2 customer-locked "$TARGET" "$POLICY" 4 42)"
read -r install_at freshness_at _ <<<"$result"
printf '1\n' > "$OWNER_OTA_CLEAR"
NI_TEST_CHANGEAUTH_FAIL=1 st ceremony-finalize-v2 customer-locked "$TARGET" "$POLICY" \
  cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc \
  "$install_at" "$freshness_at" 42 >/dev/null 2>&1 \
  && fail "v2 finalize reported success when OwnerAuth destruction failed"
st completion-inspect >/dev/null 2>&1 \
  && fail "write-locked NI-DONE2 without OwnerAuth destruction became completion"
st provisioning-status >/dev/null 2>&1 \
  && fail "partial v2 finalize was reclassified as a resumable preseal state"

# A partial post-NV03 ceremony is recovery-only. Reset this filesystem mock to
# model the separately approved physical reinstall before the successful case.
rm -rf "${NV:?}"/* "${NV:?}/.max-ever"; rm -f "$OWNER_AUTH_MARK"
activate_pcr_policy
printf '42\n' > "$OWNER_OTA_FLOOR"
printf '0\n' > "$OWNER_OTA_CLEAR"
mkdir "$NV/01500001" "$NV/01500002"
result="$(st ceremony-prepare-v2 customer-locked "$TARGET" "$POLICY" 4 42)"
read -r install_at freshness_at _ <<<"$result"
printf '1\n' > "$OWNER_OTA_CLEAR"
st ceremony-finalize-v2 customer-locked "$TARGET" "$POLICY" \
  cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc \
  "$install_at" "$freshness_at" 42 >/dev/null
inspection="$(st completion-inspect)"
python3 - "$inspection" <<'PY' || fail "v2 completion inspection is not exact"
import json,sys
assert json.loads(sys.argv[1]) == {
 "completion_version":2,
 "evidence_digest_sha256":"c"*64,
 "schema":"neural-ice-owner-ceremony-completion-inspection-v1"}
PY
cp "$NV/01500006/data" "$TMP/completion-v2.data"
python3 - "$NV/01500006/data" <<'PY'
import sys
p=sys.argv[1]; value=bytearray(open(p,"rb").read()); value[0]^=1; open(p,"wb").write(value)
PY
st completion-inspect >/dev/null 2>&1 && fail "v2 completion accepted foreign magic"
cp "$TMP/completion-v2.data" "$NV/01500006/data"
python3 - "$NV/01500006/data" <<'PY'
import sys
p=sys.argv[1]; value=bytearray(open(p,"rb").read()); value[-1]=1; open(p,"wb").write(value)
PY
st completion-inspect >/dev/null 2>&1 && fail "v2 completion accepted nonzero reserved bytes"
cp "$TMP/completion-v2.data" "$NV/01500006/data"
rm "$NV/01500006/locked"
st completion-inspect >/dev/null 2>&1 && fail "v2 completion accepted an unlocked public area"
: > "$NV/01500006/locked"
printf 63 > "$NV/01500006/size"
st completion-inspect >/dev/null 2>&1 && fail "v2 completion accepted a foreign public size"
printf 64 > "$NV/01500006/size"
cp "$NV/01500006/policy" "$TMP/completion-v2.policy"
printf '\0' > "$NV/01500006/policy"
st completion-inspect >/dev/null 2>&1 && fail "v2 completion accepted a foreign public policy"
cp "$TMP/completion-v2.policy" "$NV/01500006/policy"
[ "$(st runtime-status-v2 customer-locked "$TARGET" "$POLICY" \
  cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc \
  "$install_at" "$freshness_at" 42)" = complete ] \
  || fail "v2 completion did not pass its exact runtime status"
st runtime-status customer-locked "$TARGET" "$POLICY" \
  cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc \
  "$install_at" "$freshness_at" >/dev/null 2>&1 \
  && fail "the retained v1 status accepted NI-DONE2"

grep -Fq 'os.urandom(32)' "$SCRIPT" || fail "owner auth is not 32-byte CSPRNG output"
find "$NI_TPM_STATE_TEST_RUN_DIR" -name 'owner-auth*' -print 2>/dev/null | grep -q . \
  && fail "owner authorization survived ceremony"
grep -vE '^[[:space:]]*#' "$SCRIPT" | grep -Eq 'current[[:space:]]*-' \
  && fail "an ad hoc subtraction outside freshness_value would be a second freshness contract"
[ "$(grep -vE '^[[:space:]]*#' "$SCRIPT" | grep -c 'counter - base')" = 1 ] \
  || fail "the freshness high-water must be counter minus the sealed base, in exactly one place (ADR-0015 M)"
grep -Fq 'read()[40:48]' "$SCRIPT" || fail "the freshness base is not read from record bytes 40..47"
grep -Fq 'read()[48:56]' "$SCRIPT" || fail "the freshness origin is not read from record bytes 48..55 (ADR-0015 O)"
[ "$(grep -vE '^[[:space:]]*#' "$SCRIPT" | grep -c 'increment_counter "$PCR_POLICY_INDEX"')" = 2 ] \
  || fail "the PCR policy counter must be incremented in exactly two places: WRITTEN at provisioning and the bounded retry loop"
grep -Fq 'tpm2_nvundefine' "$SCRIPT" && fail "runtime helper can undefine state"
grep -Fq 'ota/neural-ice-tpm-state.sh /usr/libexec/neural-ice-tpm-state' \
  "$ROOT/image/Containerfile.bootc" || fail "image does not ship TPM helper"

echo "TPM_STATE_TEST_OK (mocked lifecycle; real swtpm suite proves TPM semantics)"
