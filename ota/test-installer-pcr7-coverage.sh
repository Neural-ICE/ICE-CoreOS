#!/usr/bin/env bash
# Exercise the installer's live-PCR7 fail-closed gate without touching a TPM or
# a disk. The fake implements only the documented `tpm2_pcrread sha256:7`
# stdout contract; all PolicyPCR arithmetic comes from the production helper.
# shellcheck disable=SC2016 # literal source-contract assertions below
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOL="$ROOT/ota/neural-ice-tpm-policy.py"
AUTOINSTALL="$ROOT/ota/neural-ice-autoinstall.sh"
CONTAINERFILE="$ROOT/image/Containerfile.installer"
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
cat > "$TMP/covered.json" <<EOF
{"sha256":[
  {"pcrs":[7],"pol":"$SEALED_POLICY"},
  {"pcrs":[7],"pol":"$LIVE_POLICY"}
]}
EOF

run_guard() {
  PCRREAD_MODE="${1:?}" PCRREAD_VALUE="$PCR7" PATH="$TMP/bin:$PATH" \
    python3 "$TOOL" --pcr 7 --alg sha256 verify-live-coverage \
      --signature-json "${2:?}" --required-policy-digest "$SEALED_POLICY"
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
grep -Fq "available PolicyPCR digests:" "$TMP/err" \
  || fail "the field diagnostic omits available policy digests"

# Negative: a valid multi-entry file that covers only another machine must stop.
cat > "$TMP/uncovered.json" <<EOF
{"sha256":[{"pcrs":[7],"pol":"$SEALED_POLICY"}]}
EOF
if run_guard ok "$TMP/uncovered.json" >"$TMP/out" 2>"$TMP/err"; then
  fail "an uncovered live PCR7 was accepted"
fi
grep -Fq "is not covered" "$TMP/err" \
  || fail "uncovered PCR7 did not produce a clear diagnostic"
grep -Fq "$SEALED_POLICY" "$TMP/err" \
  || fail "uncovered PCR7 did not list the available policy digest"

# A digest under the wrong PCR selection does not cover PolicyPCR(sha256:7).
cat > "$TMP/wrong-selection.json" <<EOF
{"sha256":[
  {"pcrs":[7],"pol":"$SEALED_POLICY"},
  {"pcrs":[11],"pol":"$LIVE_POLICY"}
]}
EOF
if run_guard ok "$TMP/wrong-selection.json" >/dev/null 2>"$TMP/err"; then
  fail "a PolicyPCR digest under pcrs=[11] covered live PCR7"
fi

cat > "$TMP/wrong-required-selection.json" <<EOF
{"sha256":[
  {"pcrs":[11],"pol":"$SEALED_POLICY"},
  {"pcrs":[7],"pol":"$LIVE_POLICY"}
]}
EOF
if run_guard ok "$TMP/wrong-required-selection.json" >/dev/null 2>"$TMP/err"; then
  fail "the sealed generation digest was accepted under pcrs=[11]"
fi
grep -Fq "under pcrs=[7]" "$TMP/err" \
  || fail "wrong sealed-generation PCR selection produced no clear diagnostic"

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
python3 - "$ROOT/image/inspect-installer-media.py" "$SEALED_POLICY" "$LIVE_POLICY" <<'PY'
import importlib.util
import pathlib
import sys

spec = importlib.util.spec_from_file_location("installer_media", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
expected, other = sys.argv[2:]
path = "ice-coreos/tpm2-pcr-signature.json"
cmdline = f"neuralice.pcr_policy={expected}"

covered = (
    f'{{"sha256":[{{"pcrs":[7],"pol":"{other}"}},'
    f'{{"pcrs":[7],"pol":"{expected}"}}]}}\n'
).encode("ascii")
module.check_tpm_policy_document({path}, lambda unused: covered, cmdline)

for refused in (
    f'{{"sha256":[{{"pcrs":[11],"pol":"{expected}"}}]}}'.encode("ascii"),
    b'{"sha256":[',
):
    try:
        module.check_tpm_policy_document({path}, lambda unused, data=refused: data, cmdline)
    except module.InspectionError:
        pass
    else:
        raise SystemExit("FAIL: artifact inspection accepted invalid TPM policy JSON")
print("PCR7_ARTIFACT_INSPECTION_OK")
PY

# The gate is only useful if it dominates every destructive storage operation.
python3 - "$AUTOINSTALL" <<'PY'
import pathlib
import sys

text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
guard = text.index(
    '"$TPM_POLICY_TOOL" --pcr 7 --alg sha256 verify-live-coverage'
)
for destructive in (
    'log "Internal target disk = $target',
    'wipefs -a "$target"',
    'sfdisk --force --wipe always',
    'cryptsetup luksFormat --type luks2',
    'systemd-cryptenroll --unlock-key-file="$kf"',
):
    position = text.index(destructive)
    if guard >= position:
        raise SystemExit(
            f"FAIL: live PCR7 coverage gate does not precede {destructive!r}"
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
