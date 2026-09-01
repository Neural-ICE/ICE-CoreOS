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
  python3 -c 'import struct,sys; open(sys.argv[1],"wb").write(struct.pack(">Q",0))' "$NV/\$index/data"
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
printf '  attributes:\n    value: 0x%x\n' "\$raw"
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
python3 - "$NV/\$index/data" <<'PY'
import struct, sys
path = sys.argv[1]
value, = struct.unpack(">Q", open(path, "rb").read())
open(path, "wb").write(struct.pack(">Q", value + 1))
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
st() { bash "$SCRIPT" "$@"; }

TARGET=nvidia-gb10-arm64
POLICY=neural-ice-secureboot-lab-v1

# Runtime readers and profile-bind never create missing state.
[ "$(st provisioning-status)" = virgin ] || fail "an exact virgin TPM was refused"
for command in counter-read freshness-read profile-read; do
  st "$command" >/dev/null 2>&1 && fail "$command treated absence as usable state"
done
st profile-bind customer-locked "$TARGET" "$POLICY" >/dev/null 2>&1 \
  && fail "profile-bind created missing provisioning state"
[ ! -d "$NV/01500004" ] && [ ! -d "$NV/01500005" ] \
  || fail "a runtime command created state"

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
rm -rf "${NV:?}"/*

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
rm -rf "${NV:?}"/*; rm -f "$OWNER_AUTH_MARK"

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
rm -rf "${NV:?}"/*

result="$(st ceremony-prepare customer-locked "$TARGET" "$POLICY" 4)"
[ "$result" = "1 4 $EXPECT" ] || fail "ceremony returned unexpected evidence: $result"
st ceremony-finalize customer-locked "$TARGET" "$POLICY" \
  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 1 4 >/dev/null
snapshot="$(st state-snapshot customer-locked "$TARGET" "$POLICY")"
python3 - "$snapshot" <<'PY' || fail "state snapshot does not bind both exact NV public Names and values"
import json,re,sys
d=json.loads(sys.argv[1])
assert d["install_counter"] == 1 and d["freshness_counter"] == 4
assert re.fullmatch(r"[0-9a-f]{64}",d["install_public_sha256"])
assert re.fullmatch(r"[0-9a-f]{64}",d["freshness_public_sha256"])
assert d["install_public_sha256"] != d["freshness_public_sha256"]
PY
[ "$(st runtime-status customer-locked "$TARGET" "$POLICY" \
  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 1 4)" = complete ] \
  || fail "completed state did not pass runtime status"
[ "$(st counter-read)" = 1 ] || fail "install counter mismatch"
[ "$(st freshness-read)" = 4 ] || fail "freshness is not the absolute TPM value"
[ "$(st profile-read)" = "$EXPECT" ] || fail "profile binding mismatch"
[ "$(st profile-bind customer-locked "$TARGET" "$POLICY")" = "$EXPECT" ] \
  || fail "read-only profile-bind refused exact state"
st profile-bind lab-managed "$TARGET" "$POLICY" >/dev/null 2>&1 \
  && fail "profile-bind accepted a different profile"
st freshness-consume 4 >/dev/null 2>&1 && fail "consumed N replayed"
[ "$(st freshness-consume 5)" = 5 ] || fail "next absolute issuance did not consume"
[ "$(st freshness-read)" = 5 ] || fail "absolute high-water did not advance"

# A second ceremony is always refusal; subsequent boots use read-only status.
st ceremony-prepare customer-locked "$TARGET" "$POLICY" 5 >/dev/null 2>&1 \
  && fail "one-time ceremony became idempotent acceptance"
[ "$(st runtime-status customer-locked "$TARGET" "$POLICY" \
  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 1 4)" = complete ] \
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
  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 1 4 >/dev/null 2>&1 \
  && fail "persistent SRK mismatch was accepted"
: > "$PERSIST/81000001"
rm -f "$PERSIST/81010005"
st runtime-status customer-locked "$TARGET" "$POLICY" \
  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 1 4 >/dev/null 2>&1 \
  && fail "persistent device-root mismatch was accepted"
: > "$PERSIST/81010005"

# Interrupted record state is never completed by profile-bind.
rm -f "$NV/01500005/locked"
st profile-bind customer-locked "$TARGET" "$POLICY" >/dev/null 2>&1 \
  && fail "profile-bind completed an interrupted record"
: > "$NV/01500005/locked"

grep -Fq 'os.urandom(32)' "$SCRIPT" || fail "owner auth is not 32-byte CSPRNG output"
find "$NI_TPM_STATE_TEST_RUN_DIR" -name 'owner-auth*' -print 2>/dev/null | grep -q . \
  && fail "owner authorization survived ceremony"
grep -vE '^[[:space:]]*#' "$SCRIPT" | grep -Eq 'baseline|current[[:space:]]*-' \
  && fail "baseline arithmetic remains executable"
grep -Fq 'tpm2_nvundefine' "$SCRIPT" && fail "runtime helper can undefine state"
grep -Fq 'ota/neural-ice-tpm-state.sh /usr/libexec/neural-ice-tpm-state' \
  "$ROOT/image/Containerfile.bootc" || fail "image does not ship TPM helper"

echo "TPM_STATE_TEST_OK (mocked lifecycle; real swtpm suite proves TPM semantics)"
