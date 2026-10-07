#!/usr/bin/env bash
# The installer's NI-P7-RULES gate, driven on the real GB10 fixtures of
# tools/ni-pcr-rules: it must evaluate the Owner-signed rules against the live
# EFI variables and event log BEFORE any destructive step, refuse with one slug of
# a closed vocabulary, and decide on the very bytes it staged.
#
# The production functions are extracted from ota/neural-ice-autoinstall.sh and
# run for real; only the TPM read (`tpm2_pcrread sha256:7`, the documented
# stdout contract) and the target-mutating tools are faked. All rules arithmetic
# is the production engine's.
# shellcheck disable=SC2016,SC2034,SC2317,SC2329
# Literal source-contract assertions and variables consumed by extracted code.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AUTOINSTALL="$ROOT/ota/neural-ice-autoinstall.sh"
CONTAINERFILE="$ROOT/image/Containerfile.installer"
ENGINE="$ROOT/tools/ni-pcr-rules/ni-pcr-rules.py"
FIX="$ROOT/tools/ni-pcr-rules/fixtures"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/ni-pcr-rules-gate.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

command -v openssl >/dev/null || { echo "SKIP: openssl unavailable" >&2; exit 0; }

LIVE_PCR7="$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["ni67"]["live_pcr7_sha256"])' "$FIX/expected.json")"

# --- the world: key, rules, signature, event log, EFI variables ----------------
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$TMP/owner.key" >/dev/null 2>&1
openssl pkey -in "$TMP/owner.key" -pubout -out "$TMP/owner.pub" >/dev/null 2>&1
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$TMP/other.key" >/dev/null 2>&1
mkdir -p "$TMP/bin" "$TMP/efivars" "$TMP/state"
python3 -I - "$FIX/ni67.efivars.b64" "$TMP/efivars" <<'PY'
import base64, pathlib, sys
out = pathlib.Path(sys.argv[2])
for line in pathlib.Path(sys.argv[1]).read_text().splitlines():
    name, blob = line.split()
    (out / name).write_bytes(base64.b64decode(blob))
# The GB10 capture predates SetupMode/AuditMode: a deployed machine's values (synthetic).
for name in ("SetupMode", "AuditMode"):
    (out / f"{name}-8be4df61-93ca-11d2-aa0d-00e098032b8c").write_bytes(b"\x06\x00\x00\x00\x00")
PY
cp "$FIX/ni67.pcr7-only.eventlog.bin" "$TMP/eventlog.bin"
cp "$FIX/ni67.rules.json" "$TMP/rules.json"
sign_rules() { # $1=rules $2=key $3=out
  python3 -I "$ENGINE" sign --rules "$1" --key "$2" --out "$3" >/dev/null
}
sign_rules "$TMP/rules.json" "$TMP/owner.key" "$TMP/rules.json.sig"
RULES_SHA="$(sha256sum "$TMP/rules.json" | awk '{print $1}')"

cat > "$TMP/bin/tpm2_pcrread" <<'FAKE'
#!/usr/bin/env bash
[[ "${1:-}" == sha256:7 ]] || exit 64
printf '  sha256:\n    7 : 0x%s\n' "${PCRREAD_VALUE:?}"
FAKE
chmod 0755 "$TMP/bin/tpm2_pcrread"

# Every target-mutating tool records its call and fails: a refusal must reach
# die() before any of them runs.
mkdir "$TMP/mutate-bin"
for command in wipefs sfdisk cryptsetup systemd-cryptenroll dmsetup mkfs.fat \
  mkfs.ext4 mkfs.xfs bootc blkdiscard dd parted sgdisk; do
  cat > "$TMP/mutate-bin/$command" <<'STUB'
#!/usr/bin/env bash
printf '%s %s\n' "${0##*/}" "$*" >> "${MUTATION_TRACE:?}"
exit 99
STUB
  chmod 0755 "$TMP/mutate-bin/$command"
done

# --- extract the production functions --------------------------------------------
{
  awk '/^write_failure_evidence\(\) \{/,/^}$/' "$AUTOINSTALL"
  awk '/^die\(\)  \{/,/^}$/' "$AUTOINSTALL"
  awk '/^verify_pcr_rules\(\) \{/,/^}$/' "$AUTOINSTALL"
} > "$TMP/gate-functions.sh"
grep -q '^verify_pcr_rules() {' "$TMP/gate-functions.sh" \
  || fail "ota/neural-ice-autoinstall.sh defines no verify_pcr_rules"

# One run of the gate in a clean shell. Output: stdout = "rc=N" then the globals
# on success; stderr = the die message. $1=label; remaining args are NAME=VALUE
# overrides applied after the defaults.
run_gate() {
  local label=$1; shift
  local trace="$TMP/mutations-$label"
  : > "$trace"
  (
    set -uo pipefail
    log() { printf 'LOG: %s\n' "$*" >&2; }
    FAILURE_EVIDENCE_SCHEMA=neural-ice-installer-failure-evidence-v1
    FAILURE_EVIDENCE="$TMP/evidence-$label"
    EFI_FAILURE_EVIDENCE="$TMP/no-efi-$label"
    PHASE_CODE=install-failed-preflight-and-trust-gate
    PHASE_ID=1; PHASE_TOTAL=8; PHASE_SLUG=preflight-and-trust-gate
    PHASE_LABEL="Preflight and trust gate"
    NI_INSTALLER_TEST_SEAM=1
    INSTALLER_STATE_DIR="$TMP/state"
    PCR_RULES_TOOL="$ENGINE"
    PCR_RULES_RUNTIME="$TMP/rules.json"
    PCR_RULES_VERDICT_RUNTIME="$TMP/state/verdict.json"
    PCR_RULES_SIGNATURE_RUNTIME="$TMP/rules.json.sig"
    PCR_POLICY_KEY_RUNTIME="$TMP/owner.pub"
    PCR_RULES_DIGEST="$RULES_SHA"
    PCR_RULES_SEQ=1
    PCR_RULES_EVENTLOG="$TMP/eventlog.bin"
    PCR_RULES_EFIVARS="$TMP/efivars"
    PCRREAD_VALUE="$LIVE_PCR7"
    MUTATION_TRACE="$trace"
    export PCRREAD_VALUE MUTATION_TRACE
    for assignment in "$@"; do eval "$assignment"; done
    PATH="$TMP/bin:$TMP/mutate-bin:$PATH"
    export PATH
    # shellcheck source=/dev/null
    . "$TMP/gate-functions.sh"
    verify_pcr_rules
    echo "rules_sha=$PCR_RULES_RULES_SHA256 seq=$PCR_RULES_SEQUENCE binding=$PCR_RULES_BINDING observed=$PCR_RULES_OBSERVED"
    # Reached only on accept: the destructive steps that follow in production.
    wipefs -a /dev/target; sfdisk /dev/target; cryptsetup luksFormat /dev/target
  ) >"$TMP/out-$label" 2>"$TMP/err-$label" </dev/null
  echo $?
}

expect_refusal() { # $1=label $2=class $3...=overrides
  local label=$1 class=$2; shift 2
  local rc
  rc="$(run_gate "$label" "$@")"
  [[ "$rc" == 1 ]] || { cat "$TMP/err-$label" >&2; fail "[$label] exited $rc, not a die()"; }
  grep -Fq "FAILED in phase 1/8" "$TMP/err-$label" \
    || { cat "$TMP/err-$label" >&2; fail "[$label] did not reach die()"; }
  grep -Fq "[install-failed-preflight-and-trust-gate]: NI-P7-RULES: $class" "$TMP/err-$label" \
    || { cat "$TMP/err-$label" >&2; fail "[$label] was not refused as NI-P7-RULES: $class"; }
  if grep -E 'NI-P7-RULES: ' "$TMP/err-$label" | grep -Eq "NI-P7-RULES: ${class}[^[:space:]]"; then
    fail "[$label] the refusal carries more than its closed-vocabulary slug"
  fi
  [[ ! -s "$TMP/mutations-$label" ]] \
    || { cat "$TMP/mutations-$label" >&2; fail "[$label] a target-mutating tool ran before the refusal"; }
}

# --- conforming: accepted, and the verdict is not over-claimed ----------------------
rc="$(run_gate conforming)"
[[ "$rc" == 99 ]] \
  || { cat "$TMP/err-conforming" >&2; fail "the conforming GB10 state was refused (rc=$rc, want 99 = reached the destructive stubs)"; }
grep -Fq "rules_sha=$RULES_SHA seq=7 binding=names-only" "$TMP/out-conforming" \
  || { cat "$TMP/out-conforming" >&2; fail "accept did not report the rules digest, their sequence and the names-only binding"; }
grep -Eq 'observed=.*(secure-boot|pk-approved|db-subset-of-approved)' "$TMP/out-conforming" \
  || fail "accept did not list the observed (unattested) checks"
grep -Fq 'NI-P7-RULES: accepted' "$TMP/err-conforming" || fail "the console log does not say the gate accepted"
grep -Fq 'names-only' "$TMP/err-conforming" \
  || fail "the console log hides that the variable contents are only observed"

# --- one refusal per class of the closed vocabulary ---------------------------------
# Lying variables: the log replays to another PCR7 than the TPM's.
expect_refusal replay-mismatch eventlog-mismatch "PCRREAD_VALUE=$(printf '%064d' 1)"
# Rules signed by a key other than the pinned Owner key.
sign_rules "$TMP/rules.json" "$TMP/other.key" "$TMP/rules.other.sig"
expect_refusal wrong-signer rules-signature "PCR_RULES_SIGNATURE_RUNTIME=$TMP/rules.other.sig"
# Rollback: the sealed floor is above the signed sequence.
expect_refusal rollback rules-rollback "PCR_RULES_SEQ=8"
# The signed bytes are not the ones the medium seals.
expect_refusal digest rules-digest "PCR_RULES_DIGEST=$(printf '%064d' 2)"
# Malformed rules (signed, but outside the schema).
python3 -I - "$TMP/rules.json" "$TMP/schema.rules.json" <<'PY'
import json, sys
r = json.load(open(sys.argv[1])); r["surprise"] = 1
json.dump(r, open(sys.argv[2], "w"))
PY
# The Owner's tool refuses to sign a schema violation: sign the raw bytes, as a buggy signer would.
{ printf 'neural-ice-pcr-rules/v1\0'; cat "$TMP/schema.rules.json"; } \
  | openssl dgst -sha256 -sign "$TMP/owner.key" | base64 -w0 > "$TMP/schema.rules.json.sig"
expect_refusal schema rules-schema "PCR_RULES_RUNTIME=$TMP/schema.rules.json" \
  "PCR_RULES_SIGNATURE_RUNTIME=$TMP/schema.rules.json.sig" \
  "PCR_RULES_DIGEST=$(sha256sum "$TMP/schema.rules.json" | awk '{print $1}')"
# Rules that refuse a firmware measuring only variable names.
python3 -I - "$TMP/rules.json" "$TMP/strict.rules.json" <<'PY'
import json, sys
r = json.load(open(sys.argv[1])); r["unbound_variables"] = "refuse"
json.dump(r, open(sys.argv[2], "w"))
PY
sign_rules "$TMP/strict.rules.json" "$TMP/owner.key" "$TMP/strict.rules.json.sig"
expect_refusal strict unbound-variables-refused "PCR_RULES_RUNTIME=$TMP/strict.rules.json" \
  "PCR_RULES_SIGNATURE_RUNTIME=$TMP/strict.rules.json.sig" \
  "PCR_RULES_DIGEST=$(sha256sum "$TMP/strict.rules.json" | awk '{print $1}')"

# Variable states: a copy of the EFI variables per mutation.
mutate_vars() { # $1=name $2=python mutation of `data` (bytes, after the 4 attribute bytes)
  local name=$1 body=$2 dir="$TMP/efivars-$1"
  rm -rf "$dir"; cp -r "$TMP/efivars" "$dir"
  python3 -I - "$dir" "$name" "$body" <<'PY'
import glob, sys
directory, name, body = sys.argv[1:]
(path,) = glob.glob(f"{directory}/{name}-*")
raw = open(path, "rb").read()
attr, data = raw[:4], raw[4:]
data = eval(body, {"data": data})
open(path, "wb").write(attr + data)
PY
  printf '%s' "$dir"
}
expect_refusal setup-mode secure-boot-state \
  "PCR_RULES_EFIVARS=$(mutate_vars SetupMode 'b"\x01"')"
# Two failures at once (strict rules on a names-only log AND setup mode): the most
# specific class wins, so the operator is told about setup mode, not about names.
expect_refusal setup-and-strict secure-boot-state "PCR_RULES_RUNTIME=$TMP/strict.rules.json" \
  "PCR_RULES_SIGNATURE_RUNTIME=$TMP/strict.rules.json.sig" \
  "PCR_RULES_DIGEST=$(sha256sum "$TMP/strict.rules.json" | awk '{print $1}')" \
  "PCR_RULES_EFIVARS=$(mutate_vars SetupMode 'b"\x01"')"
expect_refusal secure-boot-off secure-boot-state \
  "PCR_RULES_EFIVARS=$(mutate_vars SecureBoot 'b"\x00"')"
expect_refusal pk-removed secure-boot-state \
  "PCR_RULES_EFIVARS=$(mutate_vars PK 'b""')"
expect_refusal dbx-below-floor variable-rule \
  "PCR_RULES_EFIVARS=$(mutate_vars dbx 'b""')"
expect_refusal db-emptied variable-rule \
  "PCR_RULES_EFIVARS=$(mutate_vars db 'b""')"
expect_refusal no-efivars state-unreadable "PCR_RULES_EFIVARS=$TMP/does-not-exist"
expect_refusal no-eventlog state-unreadable "PCR_RULES_EVENTLOG=$TMP/does-not-exist"

# An engine that answers nonsense, or exits 0 without evidence, is not an accept.
cat > "$TMP/fake-engine-nonsense.py" <<'PY'
import sys
print("accepted")
PY
expect_refusal nonsense-verdict verdict-malformed "PCR_RULES_TOOL=$TMP/fake-engine-nonsense.py"
cat > "$TMP/fake-engine-lax.py" <<'PY'
import json, sys
print(json.dumps({"accepted": True, "binding": "contents", "observed": [], "rules_sha256": "0"*64,
                  "sequence": 99, "checks": []}))
PY
expect_refusal lax-engine verdict-malformed "PCR_RULES_TOOL=$TMP/fake-engine-lax.py"
RULES_FOR_FAKE="$RULES_SHA"
cat > "$TMP/fake-engine-dropped.py" <<PY
import json, sys
print(json.dumps({"accepted": True, "binding": "contents", "observed": [], "rules_sha256": "$RULES_FOR_FAKE",
                  "sequence": 7, "checks": [{"name": "rules-signature", "ok": True, "binding": "attested", "detail": ""}]}))
PY
expect_refusal dropped-checks verdict-malformed "PCR_RULES_TOOL=$TMP/fake-engine-dropped.py"
expect_refusal missing-engine verdict-malformed "PCR_RULES_TOOL=$TMP/no-such-engine.py"

# A real engine whose verdict is edited on the way out: the installer's own reading of
# the verdict must not depend on the engine being right (review of PR #252).
cat > "$TMP/mutating-engine.py" <<'PY'
import json, os, subprocess, sys
real = subprocess.run([sys.executable, "-I", os.environ["REAL_ENGINE"], *sys.argv[1:]],
                      capture_output=True, text=True)
verdict = json.loads(real.stdout)
mode = os.environ["MUTATE"]
if mode == "setup-mode-attested":
    for check in verdict["checks"]:
        if check["name"] == "setup-mode":
            check["binding"] = "attested"
    verdict["observed"] = [c["name"] for c in verdict["checks"] if c["binding"] == "observed"]
elif mode == "unknown-check":
    verdict["checks"].append({"name": "surprise", "ok": True, "binding": "attested", "detail": ""})
elif mode == "huge-sequence":
    verdict["sequence"] = 10 ** 25
elif mode == "escape-on-stderr":
    sys.stderr.write("refused: \x1b[2J\x1b]0;pwned\x07 authority name from the firmware log\n")
sys.stdout.write(json.dumps(verdict))
sys.exit(real.returncode)
PY
for mutation in setup-mode-attested unknown-check huge-sequence; do
  expect_refusal "mutated-$mutation" verdict-malformed "PCR_RULES_TOOL=$TMP/mutating-engine.py" \
    "REAL_ENGINE=$ENGINE" "MUTATE=$mutation" "export REAL_ENGINE MUTATE"
done
# An accepted run with hostile bytes on the engine's stderr: they must not reach the console.
rc="$(run_gate escape "PCR_RULES_TOOL=$TMP/mutating-engine.py" "REAL_ENGINE=$ENGINE" \
  "MUTATE=escape-on-stderr" "export REAL_ENGINE MUTATE")"
[[ "$rc" == 99 ]] || fail "the escape-on-stderr run was refused (rc=$rc)"
if LC_ALL=C grep -q $'\x1b' "$TMP/err-escape"; then
  fail "a control character from the engine's diagnostics reached the console log"
fi
grep -Fq 'authority name from the firmware log' "$TMP/err-escape" \
  || fail "the engine's printable diagnostics were dropped from the log"

# payload-unavailable carries a FIXED message: the digest it would otherwise quote varies.
mkdir -p "$TMP/esp/ice-coreos/pcr-rules"
cp "$TMP/rules.json" "$TMP/esp/ice-coreos/pcr-rules/rules.json"
cp "$TMP/rules.json.sig" "$TMP/esp/ice-coreos/pcr-rules/rules.json.sig"
{
  awk '/^write_failure_evidence\(\) \{/,/^}$/' "$AUTOINSTALL"
  awk '/^die\(\)  \{/,/^}$/' "$AUTOINSTALL"
  awk '/^esp_die\(\) \{/,/^}$/' "$AUTOINSTALL"
  awk '/^esp_snapshot_file\(\) \{/,/^}$/' "$AUTOINSTALL"
  awk '/^esp_staged_file\(\) \{/,/^}$/' "$AUTOINSTALL"
  awk '/^esp_staged_file_unsealed\(\) \{/,/^}$/' "$AUTOINSTALL"
} > "$TMP/esp-functions.sh"
run_esp() { # $1=label $2=sealed digest $3=file name -> prints rc; die text in $TMP/err-$1
  (
    set -uo pipefail
    log() { printf 'LOG: %s\n' "$*" >&2; }
    FAILURE_EVIDENCE_SCHEMA=x FAILURE_EVIDENCE="$TMP/evidence-$1" EFI_FAILURE_EVIDENCE="$TMP/no-efi-$1"
    PHASE_CODE=install-failed-preflight-and-trust-gate PHASE_ID=1 PHASE_TOTAL=8 PHASE_SLUG=s PHASE_LABEL=l
    media_vfat_partition() { echo fake; }
    mounted_at() { echo "$TMP/esp"; }
    # shellcheck source=/dev/null
    . "$TMP/esp-functions.sh"
    esp_staged_file "$3" "$2" "$TMP/staged-$1" "NI-P7-RULES: payload-unavailable"
  ) >/dev/null 2>"$TMP/err-$1" </dev/null
  echo $?
}
[[ "$(run_esp esp-ok "$RULES_SHA" pcr-rules/rules.json)" == 0 ]] || fail "a matching ESP file was refused"
[[ "$(run_esp esp-hash "$(printf '%064d' 3)" pcr-rules/rules.json)" == 1 ]] || fail "a hash mismatch was accepted"
grep -Fq '[install-failed-preflight-and-trust-gate]: NI-P7-RULES: payload-unavailable' "$TMP/err-esp-hash" \
  || fail "a hash mismatch was not classified payload-unavailable"
if grep -E 'FAILED in phase' "$TMP/err-esp-hash" | grep -Eq 'payload-unavailable[: ]'; then
  fail "payload-unavailable quotes more than its slug (the digest would make its detail vary)"
fi
grep -Fq 'hashes to' "$TMP/err-esp-hash" || fail "the hash-mismatch detail is not in the journal"
[[ "$(run_esp esp-missing "$RULES_SHA" pcr-rules/absent.json)" == 1 ]] || fail "a missing ESP file was accepted"
grep -Fq 'NI-P7-RULES: payload-unavailable' "$TMP/err-esp-missing" || fail "a missing ESP file was not payload-unavailable"

# The call block: absent means ABSENT (no karg at all); an empty value is not that.
{
  awk '/^write_failure_evidence\(\) \{/,/^}$/' "$AUTOINSTALL"
  awk '/^die\(\)  \{/,/^}$/' "$AUTOINSTALL"
  awk '/^ni_path\(\) \{/,/^}$/' "$AUTOINSTALL"
  awk '/^karg_count\(\) \{/,/^}$/' "$AUTOINSTALL"
  awk '/^karg_once\(\) \{/,/^}$/' "$AUTOINSTALL"
  awk '/^PCR_RULES_DIGEST=/,/^readonly PCR_RULES_STATE$/' "$AUTOINSTALL"
} > "$TMP/block-functions.sh"
run_block() { # $1=label $2=cmdline -> rc
  printf '%s\n' "$2" > "$TMP/cmdline-$1"
  (
    set -uo pipefail
    log() { printf 'LOG: %s\n' "$*" >&2; }
    NI_INSTALLER_TEST_SEAM=""
    NEURALICE_CMDLINE_FILE="$TMP/cmdline-$1"
    FAILURE_EVIDENCE_SCHEMA=x FAILURE_EVIDENCE="$TMP/evidence-$1" EFI_FAILURE_EVIDENCE="$TMP/no-efi-$1"
    PHASE_CODE=install-failed-preflight-and-trust-gate PHASE_ID=1 PHASE_TOTAL=8 PHASE_SLUG=s PHASE_LABEL=l
    # shellcheck source=/dev/null
    . "$TMP/block-functions.sh"
    echo "state=$PCR_RULES_STATE"
  ) >"$TMP/out-$1" 2>"$TMP/err-$1" </dev/null
  echo $?
}
[[ "$(run_block absent 'quiet neuralice.autoinstall=1')" == 0 ]] || fail "a medium with no rules karg was refused"
grep -Fq 'state=absent' "$TMP/out-absent" || fail "no rules karg did not leave state=absent"
grep -Fq 'seals no PCR rules' "$TMP/err-absent" || fail "the absent state is silent"
[[ "$(run_block empty 'quiet neuralice.pcr_rules= neuralice.pcr_rules_seq=')" == 1 ]] \
  || fail "empty rules kargs were taken for absent rules"
grep -Fq 'NI-P7-RULES: payload-unavailable' "$TMP/err-empty" || fail "empty rules kargs were not payload-unavailable"
[[ "$(run_block half "quiet neuralice.pcr_rules_seq=7")" == 1 ]] || fail "a sequence without a digest was taken for absent rules"

# The classification is closed: the die messages above are the ONLY vocabulary.
python3 -I - "$AUTOINSTALL" <<'PY'
import pathlib, re, sys
text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
used = set(re.findall(r'NI-P7-RULES: ([a-z][a-z-]*)"', text))
declared = {"state-unreadable", "rules-signature", "rules-schema", "rules-rollback", "rules-digest",
            "eventlog-mismatch", "variables-contradict-log", "unbound-variables-refused",
            "secure-boot-state", "variable-rule", "authority-rule", "verdict-malformed",
            "payload-unavailable", "accepted"}
extra = used - declared
if extra:
    raise SystemExit(f"FAIL: NI-P7-RULES slugs outside the closed vocabulary: {sorted(extra)}")
print("PCR_RULES_VOCABULARY_OK")
PY

# --- the gate dominates every destructive step, and sits beside NI-P7-COVERAGE ---------
python3 -I - "$AUTOINSTALL" <<'PY'
import pathlib, re, sys
text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
coverage = text.index("\nverify_live_pcr7_coverage\n")
found = re.search(r"\n  verify_pcr_rules\n", text)
gate = found.start() if found else -1
if gate < 0:
    raise SystemExit("FAIL: the installer never calls verify_pcr_rules")
if gate < coverage:
    raise SystemExit("FAIL: NI-P7-RULES runs before NI-P7-COVERAGE; the old gate must stay first")
classes = {
    "target announcement": r'log "Internal target disk = \$target',
    "wipefs": r"(?m)^\s*wipefs\s",
    "partition writers": r"(?m)^\s*(?:sfdisk|parted|sgdisk)\s",
    "filesystem formatters": r"(?m)^\s*mkfs\.[A-Za-z0-9_-]+\s",
    "LUKS format/open": r"(?m)^\s*cryptsetup\s+(?:luksFormat|open)\s",
    "LUKS enrollment": r"(?m)^\s*systemd-cryptenroll\s+--unlock-key-file=",
    "device mapper mutation": r"(?m)^\s*dmsetup\s+(?:create|remove|reload|resume)\s",
    "bootc install": r"(?m)^\s*bootc\s+install\s",
    "block discard": r"(?m)^\s*blkdiscard\s",
    "raw target writer": r"(?m)^\s*dd\s+.*\bof=",
}
for label, pattern in classes.items():
    for match in re.finditer(pattern, text):
        if gate >= match.start():
            raise SystemExit(f"FAIL: the NI-P7-RULES gate does not precede {label}: {match.group(0).strip()!r}")
print("PCR_RULES_DESTRUCTIVE_ORDER_OK")
PY

# --- the gate evaluates the bytes it staged ---------------------------------------------
# The rules are snapshotted from the ESP, their digest is compared with the sealed
# one AFTER the copy (esp_staged_file), and the engine is handed that same file plus
# the same digest as a pin: no second read of the medium.
grep -Fq 'esp_staged_file pcr-rules/rules.json "$PCR_RULES_DIGEST" "$PCR_RULES_RUNTIME"' "$AUTOINSTALL" \
  || fail "the rules are not staged through the hash-checked ESP snapshot"
grep -Fq -- '--expect-rules-sha256 "$PCR_RULES_DIGEST"' "$AUTOINSTALL" \
  || fail "the engine is not pinned to the sealed rules digest"
grep -Fq -- '--min-sequence "$PCR_RULES_SEQ"' "$AUTOINSTALL" \
  || fail "the engine is not given the sealed sequence floor"
grep -Fq -- '--live' "$AUTOINSTALL" || fail "the engine is not asked for the live PCR7"
if awk '/^verify_pcr_rules\(\) \{/,/^}$/' "$AUTOINSTALL" | grep -Fq -- '--pcr7'; then
  fail "the gate passes a caller-supplied PCR7 to the engine"
fi
grep -Fq 'de5e81e4' "$AUTOINSTALL" \
  || fail "the gate does not check that the EFI variables come from efivarfs"
# Neither the seam variables nor an environment can steer the production gate.
grep -Fq 'ni_path NEURALICE_PCR_RULES_TOOL' "$AUTOINSTALL" \
  || fail "the engine path is not behind the armed test seam"
grep -Fq 'ni_path NEURALICE_EFIVARS_DIR' "$AUTOINSTALL" \
  || fail "the EFI variable directory is not behind the armed test seam"

# --- the engine ships in the installer image ---------------------------------------------
grep -Fq 'tools/ni-pcr-rules/ni-pcr-rules.py' "$CONTAINERFILE" \
  || fail "the rules engine is absent from the installer image"
grep -Fq 'pcr-rules/tools/ni-pcr-rules/ni-pcr-rules.py' "$AUTOINSTALL" \
  || fail "the installer does not call the engine at its shipped path"

# --- installed evidence ------------------------------------------------------------------
grep -Fq 'pcr-rules-at-install.txt' "$AUTOINSTALL" \
  || fail "the installed ESP carries no record of the rules decision"

echo "INSTALLER_PCR_RULES_TEST_OK"
