#!/usr/bin/env bash
# Exercise the installer's live-PCR7 fail-closed gate without touching a TPM or
# a disk. The fake implements only the documented `tpm2_pcrread sha256:7`
# stdout contract; all PolicyPCR arithmetic comes from the production helper.
# shellcheck disable=SC2016,SC2034,SC2317,SC2329
# Literal source-contract assertions and functions/variables consumed after
# sourcing extracted production functions.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOL="$ROOT/ota/neural-ice-tpm-policy.py"
AUTOINSTALL="$ROOT/ota/neural-ice-autoinstall.sh"
CONTAINERFILE="$ROOT/image/Containerfile.installer"
FAILURE_SURFACE="$ROOT/image/installer/neural-ice-installer-failure.sh"
FAILURE_POLICY="$ROOT/image/installer/installer-failure-policy"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/ni-pcr7-coverage.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

mkdir -p "$TMP/bin"
cat > "$TMP/bin/tpm2_pcrread" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
[[ "${1:-}" == sha256:7 ]] || exit 64
case "${PCRREAD_MODE:-ok}" in
  ok)
    printf '  sha256:\n    7 : 0x%s\n' "${PCRREAD_VALUE:?}"
    ;;
  malformed)
    printf '  sha256:\n    7 : 0x1234\n'
    ;;
  duplicate)
    printf '  sha256:\n    7 : 0x%s\n    7 : 0x%s\n' \
      "${PCRREAD_VALUE:?}" "${PCRREAD_VALUE:?}"
    ;;
  unreadable)
    exit 5
    ;;
  *)
    exit 64
    ;;
esac
FAKE
chmod 0755 "$TMP/bin/tpm2_pcrread"

PCR7="$(printf 'live installer PCR7 fixture' | sha256sum | awk '{print $1}')"
LIVE_POLICY="$(python3 "$TOOL" --pcr 7 --alg sha256 policy-digest --value "$PCR7")"
SEALED_POLICY="$(printf 'sealed policy generation fixture' | sha256sum | awk '{print $1}')"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
  -out "$TMP/policy.key" >/dev/null 2>&1
openssl pkey -in "$TMP/policy.key" -pubout -out "$TMP/policy.pub" >/dev/null 2>&1
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
  -out "$TMP/wrong.key" >/dev/null 2>&1
openssl pkey -in "$TMP/wrong.key" -pubout -out "$TMP/wrong.pub" >/dev/null 2>&1
for policy in "$SEALED_POLICY" "$LIVE_POLICY"; do
  python3 "$TOOL" sign-request --pol "$policy" --out "$TMP/$policy.bin" >/dev/null
  openssl dgst -sha256 -sign "$TMP/policy.key" \
    -out "$TMP/$policy.sig" "$TMP/$policy.bin"
done
python3 "$TOOL" --pcr 7 --alg sha256 emit --pubkey "$TMP/policy.pub" \
  --pol "$SEALED_POLICY" --sig "$TMP/$SEALED_POLICY.sig" \
  --out "$TMP/covered.json" >/dev/null
python3 "$TOOL" --pcr 7 --alg sha256 emit --pubkey "$TMP/policy.pub" \
  --pol "$LIVE_POLICY" --sig "$TMP/$LIVE_POLICY.sig" \
  --merge "$TMP/covered.json" --out "$TMP/covered.json" >/dev/null

run_guard() {
  PCRREAD_MODE="${1:?}" PCRREAD_VALUE="$PCR7" PATH="$TMP/bin:$PATH" \
    python3 "$TOOL" --pcr 7 --alg sha256 verify-live-coverage \
      --signature-json "${2:?}" --public-key "${3:-$TMP/policy.pub}" \
      --required-policy-digest "$SEALED_POLICY"
}

# Positive: the live machine may be a different authorised entry from the one
# naming the signed generation. Multi-entry policy JSON is the supported bridge.
run_guard ok "$TMP/covered.json" >"$TMP/out" 2>"$TMP/err" \
  || { cat "$TMP/err" >&2; fail "covered live PCR7 was refused"; }
read -r got_pcr got_policy got_available < "$TMP/out"
[[ "$got_pcr" == "$PCR7" ]] || fail "the guard returned the wrong live PCR7"
[[ "$got_policy" == "$LIVE_POLICY" ]] || fail "the guard returned the wrong PolicyPCR digest"
IFS=, read -r -a available_policies <<<"$got_available"
[[ "${#available_policies[@]}" == 2 ]] \
  || fail "the guard returned the wrong number of available policy digests"
for expected in "$SEALED_POLICY" "$LIVE_POLICY"; do
  found=0
  for available in "${available_policies[@]}"; do
    [[ "$available" == "$expected" ]] && found=1
  done
  (( found == 1 )) || fail "the guard omitted available policy digest $expected"
done
grep -Fq "live sha256 PCR 7: $PCR7" "$TMP/err" \
  || fail "the field diagnostic omits live PCR7"
grep -Fq "computed PolicyPCR digest: $LIVE_POLICY" "$TMP/err" \
  || fail "the field diagnostic omits the computed PolicyPCR digest"
grep -Fq "2 verified PolicyPCR digest(s):" "$TMP/err" \
  || fail "the field diagnostic omits cryptographically verified policy digests"

# Negative: a valid multi-entry file that covers only another machine must stop.
python3 "$TOOL" --pcr 7 --alg sha256 emit --pubkey "$TMP/policy.pub" \
  --pol "$SEALED_POLICY" --sig "$TMP/$SEALED_POLICY.sig" \
  --out "$TMP/uncovered.json" >/dev/null
if run_guard ok "$TMP/uncovered.json" >"$TMP/out" 2>"$TMP/err"; then
  fail "an uncovered live PCR7 was accepted"
fi
grep -Fq "is not covered" "$TMP/err" \
  || fail "uncovered PCR7 did not produce a clear diagnostic"
grep -Fq "$SEALED_POLICY" "$TMP/err" \
  || fail "uncovered PCR7 did not list the available policy digest"

# A digest under the wrong PCR selection does not cover PolicyPCR(sha256:7).
python3 - "$TMP/covered.json" "$TMP/wrong-selection.json" "$LIVE_POLICY" <<'PY'
import json, sys
document = json.load(open(sys.argv[1], encoding="ascii"))
for entry in document["sha256"]:
    if entry["pol"] == sys.argv[3]:
        entry["pcrs"] = [11]
json.dump(document, open(sys.argv[2], "w", encoding="ascii"), separators=(",", ":"))
PY
if run_guard ok "$TMP/wrong-selection.json" >/dev/null 2>"$TMP/err"; then
  fail "a PolicyPCR digest under pcrs=[11] covered live PCR7"
fi

python3 - "$TMP/covered.json" "$TMP/wrong-required-selection.json" "$SEALED_POLICY" <<'PY'
import json, sys
document = json.load(open(sys.argv[1], encoding="ascii"))
for entry in document["sha256"]:
    if entry["pol"] == sys.argv[3]:
        entry["pcrs"] = [11]
json.dump(document, open(sys.argv[2], "w", encoding="ascii"), separators=(",", ":"))
PY
if run_guard ok "$TMP/wrong-required-selection.json" >/dev/null 2>"$TMP/err"; then
  fail "the sealed generation digest was accepted under pcrs=[11]"
fi
grep -Fq "under pcrs=[7]" "$TMP/err" \
  || fail "wrong sealed-generation PCR selection produced no clear diagnostic"

# Membership without systemd-compatible authorization is not coverage. Exercise
# both the live and sealed-generation entry, strict base64, pkfp binding, key
# binding, and the signature's binding to this exact PolicyPCR digest.
python3 - "$TMP/covered.json" "$TMP" "$SEALED_POLICY" "$LIVE_POLICY" <<'PY'
import copy, json, pathlib, sys
source, out_dir, sealed, live = sys.argv[1:]
document = json.load(open(source, encoding="ascii"))
entries = {entry["pol"]: entry for entry in document["sha256"]}

def write(name, mutate):
    candidate = copy.deepcopy(document)
    by_policy = {entry["pol"]: entry for entry in candidate["sha256"]}
    mutate(by_policy)
    pathlib.Path(out_dir, name).write_text(
        json.dumps(candidate, separators=(",", ":")), encoding="ascii"
    )

def prepend(name, entry):
    candidate = copy.deepcopy(document)
    candidate["sha256"].insert(0, entry)
    pathlib.Path(out_dir, name).write_text(
        json.dumps(candidate, separators=(",", ":")), encoding="ascii"
    )

write("missing-live-signature.json", lambda e: e[live].pop("sig"))
write("missing-sealed-signature.json", lambda e: e[sealed].pop("sig"))
write("malformed-signature.json", lambda e: e[live].__setitem__("sig", "***"))
write("wrong-fingerprint.json", lambda e: e[live].__setitem__("pkfp", "0" * 64))
write(
    "signature-for-another-policy.json",
    lambda e: e[live].__setitem__("sig", entries[sealed]["sig"]),
)
prepend("non-object-before-valid.json", "not-an-entry")
for field, value in (
    ("pcrs", [True]),
    ("pkfp", "not-a-fingerprint"),
    ("pol", "not-a-policy"),
    ("sig", "***"),
):
    malformed = copy.deepcopy(entries[sealed])
    malformed[field] = value
    prepend(f"malformed-{field}-before-valid.json", malformed)
invalid_signature = copy.deepcopy(entries[sealed])
invalid_signature["sig"] = entries[live]["sig"]
prepend("invalid-signature-before-valid.json", invalid_signature)
PY
for mutation in missing-live-signature missing-sealed-signature \
  malformed-signature wrong-fingerprint signature-for-another-policy; do
  if run_guard ok "$TMP/$mutation.json" >/dev/null 2>"$TMP/err"; then
    fail "$mutation was accepted as cryptographically authorised coverage"
  fi
done
for mutation in non-object-before-valid malformed-pcrs-before-valid \
  malformed-pkfp-before-valid malformed-pol-before-valid \
  malformed-sig-before-valid invalid-signature-before-valid; do
  if run_guard ok "$TMP/$mutation.json" >/dev/null 2>"$TMP/err"; then
    fail "$mutation was skipped before a later valid signed entry"
  fi
  grep -Fq "entry 0" "$TMP/err" \
    || fail "$mutation did not report the deterministic malformed entry index"
done
if run_guard ok "$TMP/covered.json" "$TMP/wrong.pub" >/dev/null 2>"$TMP/err"; then
  fail "entries signed by another RSA key were accepted"
fi
grep -Fq "0 verified PolicyPCR digest(s):" "$TMP/err" \
  || fail "wrong-key diagnostics claimed an unverified policy was available"

# Drive the actual helper refusal through the installer's bounded writer and
# shipped failure surface. This is the powered-off preflight path, not a test
# formatter: the EFI payload and tty output must retain the non-secret values.
if run_guard ok "$TMP/covered.json" "$TMP/wrong.pub" \
  >"$TMP/refusal-machine" 2>"$TMP/refusal-journal"; then
  fail "the wrong-key fixture unexpectedly passed before failure evidence"
fi
read -r refusal_pcr refusal_policy refusal_available < "$TMP/refusal-machine"
{
  awk '/^record_pcr7_failure_evidence\(\) \{/,/^}$/' "$AUTOINSTALL"
  awk '/^write_failure_evidence\(\) \{/,/^}$/' "$AUTOINSTALL"
  awk '/^die\(\)  \{/,/^}$/' "$AUTOINSTALL"
} > "$TMP/failure-functions.sh"
(
  set -uo pipefail
  log() { :; }
  FAILURE_EVIDENCE_SCHEMA=neural-ice-installer-failure-evidence-v1
  FAILURE_EVIDENCE="$TMP/pcr-failure-evidence"
  EFI_FAILURE_EVIDENCE="$TMP/pcr-failure-efi"
  PHASE_CODE=install-failed-preflight-and-trust-gate
  PHASE_ID=1
  PHASE_TOTAL=8
  PHASE_SLUG=preflight-and-trust-gate
  PHASE_LABEL="Preflight and trust gate"
  # shellcheck source=/dev/null
  . "$TMP/failure-functions.sh"
  record_pcr7_failure_evidence \
    "$refusal_pcr" "$refusal_policy" "$refusal_available"
  die "NI-P7-COVERAGE"
) >/dev/null 2>&1 || true
mkdir "$TMP/render-efi"
chmod 0777 "$TMP/render-efi"
render_command=(env
  "NEURALICE_FAILURE_EVIDENCE=$TMP/pcr-failure-evidence"
  "NEURALICE_FAILURE_POLICY=$FAILURE_POLICY"
  "NEURALICE_EFI_FAILURE_EVIDENCE=$TMP/render-efi/rendered-pcr-failure-efi"
  bash "$FAILURE_SURFACE" --dry-run)
if (( EUID == 0 )); then
  chmod -R a+rX "$TMP" "$FAILURE_SURFACE" "$FAILURE_POLICY" 2>/dev/null || true
  runuser -u nobody -- "${render_command[@]}" > "$TMP/pcr-failure-screen"
else
  "${render_command[@]}" > "$TMP/pcr-failure-screen"
fi
for expected in "$PCR7" "$LIVE_POLICY" 'verified count     0'; do
  grep -Fq "$expected" "$TMP/pcr-failure-screen" \
    || fail "the stable failure surface omitted PCR diagnostic: $expected"
done
dd if="$TMP/render-efi/rendered-pcr-failure-efi" bs=1 skip=4 status=none \
  > "$TMP/rendered-pcr-failure-payload"
for expected in "pcr7=$PCR7" "pcr7_policy=$LIVE_POLICY" 'pcr7_verified=none'; do
  grep -Fq "$expected" "$TMP/rendered-pcr-failure-payload" \
    || fail "persistent EFI failure evidence omitted $expected"
done

# Execute the production preflight function with every target-mutating command
# stubbed. Each refusal must exit through die() before a stub can record even
# one invocation. The class list intentionally includes obvious future storage
# tools, so adding one after this gate requires keeping the harness green.
mkdir "$TMP/mutate-bin"
for command in wipefs sfdisk cryptsetup systemd-cryptenroll dmsetup \
  mkfs.fat mkfs.ext4 mkfs.xfs mkfs.btrfs bootc blkdiscard dd parted sgdisk \
  pvcreate vgcreate lvcreate; do
  cat > "$TMP/mutate-bin/$command" <<'STUB'
#!/usr/bin/env bash
printf '%s %s\n' "${0##*/}" "$*" >> "${MUTATION_TRACE:?}"
exit 99
STUB
  chmod 0755 "$TMP/mutate-bin/$command"
done
{
  awk '/^record_pcr7_failure_evidence\(\) \{/,/^}$/' "$AUTOINSTALL"
  awk '/^write_failure_evidence\(\) \{/,/^}$/' "$AUTOINSTALL"
  awk '/^die\(\)  \{/,/^}$/' "$AUTOINSTALL"
  awk '/^verify_live_pcr7_coverage\(\) \{/,/^}$/' "$AUTOINSTALL"
} > "$TMP/preflight-functions.sh"

assert_zero_target_mutations() { # label pcr-mode json public-key
  local label=$1 mode=$2 document=$3 public_key=$4
  local trace="$TMP/mutations-$label" evidence="$TMP/evidence-$label"
  : > "$trace"
  if (
    set -uo pipefail
    log() { :; }
    FAILURE_EVIDENCE_SCHEMA=neural-ice-installer-failure-evidence-v1
    FAILURE_EVIDENCE="$evidence"
    EFI_FAILURE_EVIDENCE="$TMP/no-efi-$label"
    PHASE_CODE=install-failed-preflight-and-trust-gate
    PHASE_ID=1
    PHASE_TOTAL=8
    PHASE_SLUG=preflight-and-trust-gate
    PHASE_LABEL="Preflight and trust gate"
    TPM_POLICY_TOOL="$TOOL"
    PCR_POLICY_SIGNATURE_RUNTIME="$document"
    PCR_POLICY_KEY_RUNTIME="$public_key"
    PCR_POLICY_DIGEST="$SEALED_POLICY"
    PCRREAD_MODE="$mode"
    PCRREAD_VALUE="$PCR7"
    MUTATION_TRACE="$trace"
    export PCRREAD_MODE PCRREAD_VALUE MUTATION_TRACE
    PATH="$TMP/bin:$TMP/mutate-bin:$PATH"
    export PATH
    # shellcheck source=/dev/null
    . "$TMP/preflight-functions.sh"
    verify_live_pcr7_coverage
    wipefs -a /dev/target
    sfdisk --wipe always /dev/target
    cryptsetup luksFormat /dev/target
    systemd-cryptenroll --unlock-key-file=/run/key /dev/target
    dmsetup remove target
    mkfs.fat /dev/target
    mkfs.ext4 /dev/target
    mkfs.xfs /dev/target
    mkfs.btrfs /dev/target
    bootc install to-filesystem /target
    blkdiscard /dev/target
    dd if=/dev/zero of=/dev/target
    parted /dev/target
    sgdisk --clear /dev/target
    pvcreate /dev/target
    vgcreate target-vg /dev/target
    lvcreate -n target-lv target-vg
  ) >/dev/null 2>&1; then
    fail "[$label] PCR7 refusal returned success"
  fi
  [ ! -s "$trace" ] \
    || { cat "$trace" >&2; fail "[$label] invoked a target-mutating command"; }
}

assert_zero_target_mutations unreadable unreadable "$TMP/covered.json" "$TMP/policy.pub"
assert_zero_target_mutations malformed malformed "$TMP/covered.json" "$TMP/policy.pub"
assert_zero_target_mutations unsigned ok "$TMP/missing-live-signature.json" "$TMP/policy.pub"
assert_zero_target_mutations wrong-key ok "$TMP/covered.json" "$TMP/wrong.pub"
assert_zero_target_mutations uncovered ok "$TMP/uncovered.json" "$TMP/policy.pub"

if run_guard malformed "$TMP/covered.json" >/dev/null 2>"$TMP/err"; then
  fail "a short malformed PCR7 was accepted"
fi
grep -Fq "expected exactly one" "$TMP/err" \
  || fail "malformed PCR7 did not produce a clear diagnostic"

if run_guard duplicate "$TMP/covered.json" >/dev/null 2>"$TMP/err"; then
  fail "duplicate PCR7 output was accepted"
fi
if run_guard unreadable "$TMP/covered.json" >/dev/null 2>"$TMP/err"; then
  fail "an unreadable PCR7 was accepted"
fi
grep -Fq "failed with status 5" "$TMP/err" \
  || fail "unreadable PCR7 did not preserve the tpm2_pcrread failure status"

printf '{"sha256":[' > "$TMP/malformed.json"
if run_guard ok "$TMP/malformed.json" >/dev/null 2>"$TMP/err"; then
  fail "malformed signature JSON was accepted"
fi

# The build-plane assertion accepts a multi-entry document whose sealed digest
# is not first, but rejects malformed or uncovered material even when its file
# hash could otherwise be sealed into a UKI command line.
python3 - "$ROOT/image/inspect-installer-media.py" "$SEALED_POLICY" \
  "$TMP/covered.json" "$TMP/policy.pub" "$TMP/wrong.pub" <<'PY'
import copy
import importlib.util
import json
import pathlib
import sys

spec = importlib.util.spec_from_file_location("installer_media", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
expected, document_path, public_key_path, wrong_key_path = sys.argv[2:]
signature_path = "ice-coreos/tpm2-pcr-signature.json"
key_path = "ice-coreos/tpm2-pcr-public-key.pem"
cmdline = f"neuralice.pcr_policy={expected}"
covered = pathlib.Path(document_path).read_bytes()
public_key = pathlib.Path(public_key_path).read_bytes()
wrong_key = pathlib.Path(wrong_key_path).read_bytes()
paths = {signature_path, key_path}

def check(document, key=public_key):
    files = {signature_path: document, key_path: key}
    module.check_tpm_policy_document(paths, files.__getitem__, cmdline)

check(covered)
parsed = json.loads(covered)
entries = {entry["pol"]: entry for entry in parsed["sha256"]}
other = next(policy for policy in entries if policy != expected)

unsigned = copy.deepcopy(parsed)
next(entry for entry in unsigned["sha256"] if entry["pol"] == expected).pop("sig")
wrong_signature = copy.deepcopy(parsed)
next(
    entry for entry in wrong_signature["sha256"] if entry["pol"] == expected
)["sig"] = entries[other]["sig"]
malformed_before_valid = copy.deepcopy(parsed)
malformed_before_valid["sha256"].insert(0, "not-an-entry")
uncovered = copy.deepcopy(parsed)
uncovered["sha256"] = [entries[other]]

for label, refused, key in (
    ("unsigned", json.dumps(unsigned).encode(), public_key),
    ("wrong key", covered, wrong_key),
    ("signature for another policy", json.dumps(wrong_signature).encode(), public_key),
    ("malformed before valid", json.dumps(malformed_before_valid).encode(), public_key),
    ("uncovered", json.dumps(uncovered).encode(), public_key),
    ("malformed JSON", b'{"sha256":[', public_key),
):
    try:
        check(refused, key)
    except module.InspectionError:
        pass
    else:
        raise SystemExit(f"FAIL: artifact inspection accepted {label} policy JSON")
print("PCR7_ARTIFACT_INSPECTION_OK")
PY

# The gate is only useful if it dominates every destructive storage operation.
python3 - "$AUTOINSTALL" <<'PY'
import pathlib
import re
import sys

text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
guard = text.index("\nverify_live_pcr7_coverage\n")
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
    "LVM writers": r"(?m)^\s*(?:pvcreate|vgcreate|lvcreate)\s",
}
for label, pattern in classes.items():
    matches = list(re.finditer(pattern, text))
    for match in matches:
        if guard >= match.start():
            snippet = match.group(0).strip()
            raise SystemExit(
                f"FAIL: live PCR7 coverage gate does not precede {label}: {snippet!r}"
            )
    if label in {
        "target announcement", "wipefs", "partition writers",
        "filesystem formatters", "LUKS format/open", "LUKS enrollment",
        "device mapper mutation", "bootc install",
    } and not matches:
        raise SystemExit(
            f"FAIL: destructive-order class disappeared from coverage: {label}"
        )
print("PCR7_DESTRUCTIVE_ORDER_OK")
PY

# Artifact and evidence assertions: the exact helper is immutable in the
# installer image, and successful offline installs retain both observed values.
grep -Fq 'COPY ota/neural-ice-tpm-policy.py /usr/lib/neural-ice/tpm-policy.py' \
  "$CONTAINERFILE" || fail "the authoritative policy helper is absent from the installer image"
grep -Fq 'printf '\''%s\n'\'' "$LIVE_PCR7" > /run/seed-dst/release/PCR7-LIVE' \
  "$AUTOINSTALL" || fail "offline install evidence omits live PCR7"
grep -Fq 'printf '\''%s\n'\'' "$LIVE_PCR7_POLICY" > /run/seed-dst/release/PCR7-POLICY' \
  "$AUTOINSTALL" || fail "offline install evidence omits computed PolicyPCR"
grep -Fq 'printf '\''%s\n'\'' "$AVAILABLE_PCR7_POLICIES" > /run/seed-dst/release/PCR7-POLICIES' \
  "$AUTOINSTALL" || fail "offline install evidence omits available policies"
grep -Fq 'tpm2-pcr7-at-install.txt' "$AUTOINSTALL" \
  || fail "installed ESP evidence omits the PCR7 coverage decision"

echo "INSTALLER_PCR7_COVERAGE_TEST_OK"
