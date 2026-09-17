#!/usr/bin/env bash
#
# The end-to-end bench rehearsal's OFFLINE suite: the receipt schema and phase
# order, the readers of the appliance's own JSON surfaces (authenticated OTA
# status, the durable transaction, the enrolment response), the sealed
# command-line reader, the argument refusals and the load-bearing contracts of
# the driver itself.
#
# It boots nothing and reaches no appliance. The rehearsal it guards runs only
# on the KVM-capable GB10 bench; the part that decides what the evidence MEANS
# is what is proved here, because a reader that mistakes a rollback for a
# completion turns a measured defect into a green receipt.
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
DRIVER="$ROOT/image/bench-rehearse-e2e.sh"
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "  ok   $*"; }

TMP="$(mktemp -d)"
trap 'rm -rf -- "$TMP"' EXIT

[[ -x "$DRIVER" ]] || fail "the e2e rehearsal driver is not executable"

# shellcheck source=image/bench-rehearse-e2e.sh
NI_E2E_HARNESS_SOURCE_ONLY=1 source "$DRIVER"

echo "== the source-only seam is a seam, not a bypass"
if NI_E2E_HARNESS_SOURCE_ONLY=1 "$DRIVER" --help >/dev/null 2>&1; then
  fail "source-only mode was accepted on a direct invocation"
fi
pass "source-only mode refuses a direct invocation"

expect_field() { # $1=facts file $2=key $3=exact expected value
  local got
  got="$(awk -F= -v k="$2" '$1==k{sub(/^[^=]*=/, ""); print; exit}' "$1")"
  [[ "$got" == "$3" ]] || fail "$(basename "$1"): $2 = '$got', expected '$3'"
}

# --------------------------------------------------------------------------- #
# Phase order: the five phases, in the order the product lives them.
# --------------------------------------------------------------------------- #
echo "== the phase order is medium install firstboot onboard ota"
[[ "${NI_E2E_PHASES[*]}" == "medium install firstboot onboard ota" ]] \
  || fail "phase order changed: ${NI_E2E_PHASES[*]}"
[[ "$(ni_e2e_phase_index medium)" == 0 && "$(ni_e2e_phase_index ota)" == 4 ]] \
  || fail "phase indices are not positional"
ni_e2e_phase_index reboot >/dev/null 2>&1 && fail "an unknown phase has an index"
pass "five phases, positional, unknown names refused"

# --------------------------------------------------------------------------- #
# The receipt: one object per phase, superseded on re-run, never duplicated.
# --------------------------------------------------------------------------- #
echo "== the receipt carries one object per phase with the fixed fields"
R="$TMP/receipt.json"
printf 'first line\n\tsecond line with a tab\n' > "$TMP/ev1"
ni_e2e_receipt_write "$R" medium 2026-09-17T00:00:00Z 2026-09-17T00:01:00Z 0 passed "$TMP/ev1" "/tmp/it's a work dir"
ni_e2e_receipt_write "$R" install 2026-09-17T00:01:00Z none none running "$TMP/ev1"
python3 - "$R" <<'PY' || fail "receipt shape"
import json, sys
r = json.load(open(sys.argv[1]))
assert r["schema"] == "neural-ice-bench-e2e-receipt-v1", r["schema"]
assert r["phase_order"] == ["medium", "install", "firstboot", "onboard", "ota"]
assert r["work_dir"] == "/tmp/it's a work dir"
names = [p["name"] for p in r["phases"]]
assert names == ["medium", "install"], names
first = r["phases"][0]
assert set(first) == {"name", "started", "ended", "rc", "status", "evidence"}, set(first)
assert first["rc"] == 0 and first["status"] == "passed"
assert first["evidence"] == ["first line", "second line with a tab"], first["evidence"]
second = r["phases"][1]
assert second["rc"] is None and second["ended"] == "none" and second["status"] == "running"
PY
pass "schema, order, work dir with a quote, evidence lines, running phase"

echo "== a re-run of a phase supersedes its object and keeps the order"
printf 'refused for a reason\n' > "$TMP/ev2"
ni_e2e_receipt_write "$R" install 2026-09-17T00:01:00Z 2026-09-17T00:09:00Z 1 failed "$TMP/ev2"
ni_e2e_receipt_write "$R" firstboot 2026-09-17T00:09:00Z 2026-09-17T00:09:00Z none skipped "$TMP/ev2"
ni_e2e_receipt_write "$R" medium 2026-09-17T00:10:00Z 2026-09-17T00:11:00Z 0 passed "$TMP/ev1"
python3 - "$R" <<'PY' || fail "receipt supersede"
import json, sys
r = json.load(open(sys.argv[1]))
names = [p["name"] for p in r["phases"]]
assert names == ["medium", "install", "firstboot"], names
assert r["phases"][0]["started"] == "2026-09-17T00:10:00Z"
assert r["phases"][1]["rc"] == 1 and r["phases"][1]["status"] == "failed"
assert r["phases"][1]["evidence"] == ["refused for a reason"]
assert r["phases"][2]["status"] == "skipped" and r["phases"][2]["rc"] is None
PY
pass "one object per phase after a re-run; failed and skipped recorded"

echo "== the receipt refuses what is not a phase, a status or a stamp"
ni_e2e_receipt_write "$R" reboot 2026-09-17T00:00:00Z none none running "$TMP/ev1" >/dev/null 2>&1 \
  && fail "an unknown phase was written"
ni_e2e_receipt_write "$R" ota 2026-09-17T00:00:00Z none none green "$TMP/ev1" >/dev/null 2>&1 \
  && fail "an unknown status was written"
ni_e2e_receipt_write "$R" ota yesterday none none running "$TMP/ev1" >/dev/null 2>&1 \
  && fail "a non-ISO stamp was written"
pass "unknown phase, status and stamp are refused"

echo "== evidence is bounded: printable ASCII, 400 chars, 400 lines"
python3 -c 'print("x" * 1000 + "é\x07"); [print(f"line {i}") for i in range(500)]' > "$TMP/ev3"
ni_e2e_receipt_write "$R" ota 2026-09-17T00:00:00Z 2026-09-17T00:00:00Z 0 passed "$TMP/ev3"
python3 - "$R" <<'PY' || fail "evidence bounds"
import json, sys
r = json.load(open(sys.argv[1]))
ev = [p for p in r["phases"] if p["name"] == "ota"][0]["evidence"]
assert len(ev[0]) == 400 and ev[0] == "x" * 400, len(ev[0])
assert len(ev) == 401 and ev[-1].startswith("... evidence truncated"), len(ev)
assert all(all(32 <= ord(c) < 127 for c in line) for line in ev)
PY
pass "oversized and non-printable evidence never reaches the receipt whole"

# --------------------------------------------------------------------------- #
# The readers of the appliance's own JSON surfaces.
# --------------------------------------------------------------------------- #
echo "== authenticated-ota-status: the pristine contract, a committed one, garbage"
# The exact bytes tools/ni-ota-verify/src/state_v1.rs asserts for a pristine
# owner-sealed appliance (owner_pristine_status_has_the_exact_null_false_contract).
printf '{"committed_generation":null,"completion_version":2,"enforce_ready_verified":false,"profile":"owner-sealed-ota-state-v1","schema":"neural-ice-authenticated-ota-status-v1"}\n' > "$TMP/pristine.json"
ni_e2e_parse_ota_status "$TMP/pristine.json" > "$TMP/facts"
expect_field "$TMP/facts" ota_status parsed
expect_field "$TMP/facts" committed_generation null
expect_field "$TMP/facts" enforce_ready_verified false
expect_field "$TMP/facts" ota_status_profile owner-sealed-ota-state-v1
expect_field "$TMP/facts" ota_status_schema neural-ice-authenticated-ota-status-v1
printf '{"committed_generation":26,"enforce_ready_verified":true,"schema":"neural-ice-authenticated-ota-status-v1"}\n' > "$TMP/committed.json"
ni_e2e_parse_ota_status "$TMP/committed.json" > "$TMP/facts"
expect_field "$TMP/facts" committed_generation 26
expect_field "$TMP/facts" enforce_ready_verified true
printf 'ni-ota-verify: authenticated OTA status REFUSED: persistent OTA state has unsafe mode/owner/type metadata; expected 0600\n' > "$TMP/refused.txt"
ni_e2e_parse_ota_status "$TMP/refused.txt" > "$TMP/facts"
expect_field "$TMP/facts" ota_status unparseable
printf '{"committed_generation":"26","enforce_ready_verified":"yes","profile":"x; rm -rf /","schema":[1]}\n' > "$TMP/shapes.json"
ni_e2e_parse_ota_status "$TMP/shapes.json" > "$TMP/facts"
expect_field "$TMP/facts" committed_generation none
expect_field "$TMP/facts" enforce_ready_verified none
expect_field "$TMP/facts" ota_status_profile none
expect_field "$TMP/facts" ota_status_schema none
pass "pristine {null,false} read exactly; a refusal reads as unparseable; out-of-shape values become none"

echo "== the durable transaction: every phase of the engine, and only those"
for phase in prepared pending_reboot activating activated finalizing committing completed rollback_armed rolled_back recovery_required aborted; do
  printf '{"phase":"%s","train":"0.61.2","channel":"lab","previous_ring":"lab","failure_reason":"health_timeout"}\n' "$phase" > "$TMP/tx.json"
  ni_e2e_parse_tx_state "$TMP/tx.json" > "$TMP/facts"
  expect_field "$TMP/facts" tx_phase "$phase"
done
expect_field "$TMP/facts" tx_train 0.61.2
expect_field "$TMP/facts" tx_failure_reason health_timeout
printf '{"phase":"done"}\n' > "$TMP/tx.json"
ni_e2e_parse_tx_state "$TMP/tx.json" > "$TMP/facts"
expect_field "$TMP/facts" tx_phase none
expect_field "$TMP/facts" tx_failure_reason none
: > "$TMP/tx.json"
ni_e2e_parse_tx_state "$TMP/tx.json" > "$TMP/facts"
expect_field "$TMP/facts" tx_state unparseable
pass "the engine's eleven phases are read; a phase outside the vocabulary is none, an empty file unparseable"

echo "== the enrolment response: licence facts without the certificate"
cat > "$TMP/enrol.json" <<'JSON'
{"status":"enrolled","license":{"id":"lic_1","tier":"professional","status":"active","entitlements":["ICE-CORE","ICE-CASELAW-CH","ICE-CORE","bad code"]},
 "user":{"id":"u","email":"op@example.test","name":"Op","role":"admin"},
 "certificate":"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----","ca_certificate":"x",
 "fingerprint":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","offline_pending":false,"offline_ready":true}
JSON
ni_e2e_parse_enrol_response "$TMP/enrol.json" > "$TMP/facts"
expect_field "$TMP/facts" enrol_status enrolled
expect_field "$TMP/facts" license_tier professional
expect_field "$TMP/facts" license_status active
expect_field "$TMP/facts" entitlements ICE-CASELAW-CH,ICE-CORE
expect_field "$TMP/facts" fingerprint_prefix 0123456789abcdef
expect_field "$TMP/facts" offline_ready true
grep -q 'BEGIN CERTIFICATE' "$TMP/facts" && fail "the certificate leaked into the facts"
printf '{"error":"Invalid or missing console pairing code. Read the code displayed on the appliance screen and try again."}\n' > "$TMP/enrol-refused.json"
ni_e2e_parse_enrol_response "$TMP/enrol-refused.json" > "$TMP/facts"
expect_field "$TMP/facts" enrol_status none
expect_field "$TMP/facts" entitlements none
expect_field "$TMP/facts" enrol_detail 'Invalid or missing console pairing code. Read the code displayed on the appliance screen and try again.'
pass "entitlements sorted and deduplicated, malformed codes dropped, the refusal's detail kept"

echo "== failed units: the allow-list removes exactly the named units"
printf 'license-check.service loaded failed failed Neural ICE licence check\nneural-ice-model-fetch.service loaded failed failed model fetch\n' > "$TMP/failed.txt"
ni_e2e_failed_units "$TMP/failed.txt" license-check.service > "$TMP/out"
[[ "$(cat "$TMP/out")" == "neural-ice-model-fetch.service" ]] || fail "allow-list filtering: $(cat "$TMP/out")"
ni_e2e_failed_units "$TMP/failed.txt" "" | grep -c . | grep -qx 2 || fail "an empty allow-list keeps everything"
ni_e2e_failed_units "$TMP/failed.txt" license-check.service,neural-ice-model-fetch.service > "$TMP/out"
[[ ! -s "$TMP/out" ]] || fail "a full allow-list leaves nothing"
: > "$TMP/none.txt"
[[ -z "$(ni_e2e_failed_units "$TMP/none.txt" x)" ]] || fail "no failed units is no failed units"
pass "allow-listed units are removed, others kept, an empty listing is clean"

echo "== the mirror probe summary is read off warm-release-closure's last line"
printf 'present neural-ice/x sha256:aa\nwarm: objects=1328 present=1328 fetched=0 failed=0\n' > "$TMP/warm.log"
ni_e2e_warm_summary "$TMP/warm.log" > "$TMP/facts"
expect_field "$TMP/facts" warm_summary present
expect_field "$TMP/facts" warm_objects 1328
expect_field "$TMP/facts" warm_failed 0
printf 'REFUSED: warm-release-closure: x\nwarm: objects=5 present=4 fetched=0 failed=1\n' > "$TMP/warm.log"
ni_e2e_warm_summary "$TMP/warm.log" > "$TMP/facts"
expect_field "$TMP/facts" warm_failed 1
printf 'nothing\n' > "$TMP/warm.log"
ni_e2e_warm_summary "$TMP/warm.log" > "$TMP/facts"
expect_field "$TMP/facts" warm_summary absent
pass "present, failed and absent summaries"

echo "== the sealed command line: values by key, shapes enforced"
cat > "$TMP/inspect.txt" <<'EOF'
inspect-installer-media: OK
  EFI authority   : EFI/BOOT/BOOTAA64.EFI (the only bootable file on the medium)
  sealed cmdline  : neuralice.trust=neural-ice-installer-trust-v1 neuralice.device_channel=lab neuralice.imgref=registry.example.test/neural-ice/neural-ice-appliance@sha256:ff13e6e2751f992098d638191a147c1dcf3c025132e11e12dac9b15a461e6da9 neuralice.sshkey=c3NoLWVkMjU1MTkgQUFBQQo= neuralice.pcr_policy_seq=1109 neuralice.mirror=192.168.178.63:5055 neuralice.mirror_generation=12 neuralice.seed_closure=721c677cb681b04739e9f9a36464cd92ba55f72d46ad1b96fa0b277559645ea9 neuralice.seed_source=mirror
EOF
[[ "$(ni_e2e_sealed_value "$TMP/inspect.txt" seed_closure)" == 721c677cb681b04739e9f9a36464cd92ba55f72d46ad1b96fa0b277559645ea9 ]] || fail "seed_closure"
[[ "$(ni_e2e_sealed_value "$TMP/inspect.txt" mirror)" == 192.168.178.63:5055 ]] || fail "mirror"
[[ "$(ni_e2e_sealed_value "$TMP/inspect.txt" device_channel)" == lab ]] || fail "device_channel"
[[ "$(ni_e2e_sealed_value "$TMP/inspect.txt" pcr_policy_seq)" == 1109 ]] || fail "pcr_policy_seq"
[[ "$(ni_e2e_sealed_value "$TMP/inspect.txt" imgref)" == registry.example.test/neural-ice/neural-ice-appliance@sha256:ff13e6e2751f992098d638191a147c1dcf3c025132e11e12dac9b15a461e6da9 ]] || fail "imgref"
ni_e2e_sealed_value "$TMP/inspect.txt" seed_source >/dev/null 2>&1 && fail "a key without a shape was accepted"
ni_e2e_sealed_value "$TMP/inspect.txt" preseal >/dev/null 2>&1 && fail "an absent key was accepted"
sed 's/neuralice.seed_closure=721c/neuralice.seed_closure=ZZZZ/' "$TMP/inspect.txt" > "$TMP/inspect-bad.txt"
ni_e2e_sealed_value "$TMP/inspect-bad.txt" seed_closure >/dev/null 2>&1 && fail "a malformed closure hash was accepted"
ni_e2e_sealed_value "$TMP/absent.txt" mirror >/dev/null 2>&1 && fail "a missing report was accepted"
pass "keys read by name; unknown, absent and malformed values refused"

# --------------------------------------------------------------------------- #
# Argument refusals. Every one of these is checked before the driver looks at
# the host, so they run on any architecture, with no KVM and no medium.
# --------------------------------------------------------------------------- #
echo "== the driver refuses what it cannot bound"
refuses() { # $1=description $2=expected refusal fragment, rest=arguments
  local description=$1 fragment=$2 out
  shift 2
  if out="$("$DRIVER" "$@" 2>&1)"; then
    fail "the driver accepted $description"
  fi
  [[ "$out" == *"$fragment"* ]] || fail "$description: refusal does not name the cause: $out"
  pass "refuses $description"
}
MEDIUM="$TMP/medium.img"; : > "$MEDIUM"
VARS="$TMP/vars.fd"; : > "$VARS"
SECRET="$TMP/key.txt"; printf 'NI-XXXXX\n' > "$SECRET"; chmod 0600 "$SECRET"
LOOSE="$TMP/loose.txt"; printf 'NI-XXXXX\n' > "$LOOSE"; chmod 0644 "$LOOSE"
BASE=(--medium "$MEDIUM" --firmware-vars "$VARS")

refuses "no arguments at all" "Usage"
refuses "a relative work directory" "absolute" "${BASE[@]}" --work-dir relative
refuses "the root directory as a work directory" "absolute" "${BASE[@]}" --work-dir /
refuses "a missing medium" "--medium" --medium "$TMP/absent.img" --firmware-vars "$VARS" --work-dir /var/tmp/ni-e2e
refuses "a missing variable store" "--firmware-vars" --medium "$MEDIUM" --firmware-vars "$TMP/absent.fd" --work-dir /var/tmp/ni-e2e
refuses "an unknown --skip-to phase" "--skip-to must be one of" "${BASE[@]}" --work-dir /var/tmp/ni-e2e --skip-to reboot
refuses "an unknown --stop-after phase" "--stop-after must be one of" "${BASE[@]}" --work-dir /var/tmp/ni-e2e --stop-after reboot
refuses "a --stop-after before --skip-to" "comes before" "${BASE[@]}" --work-dir /var/tmp/ni-e2e --skip-to ota --stop-after medium
refuses "a licence key file readable by others" "--license-key-file must not be readable" "${BASE[@]}" --work-dir /var/tmp/ni-e2e --license-key-file "$LOOSE"
refuses "a missing licence key file" "--license-key-file" "${BASE[@]}" --work-dir /var/tmp/ni-e2e --license-key-file "$TMP/absent.key"
refuses "an unknown ring" "--ring" "${BASE[@]}" --work-dir /var/tmp/ni-e2e --ring nightly
refuses "a malformed target train" "--target-train" "${BASE[@]}" --work-dir /var/tmp/ni-e2e --target-train '0.61.2; rm -rf /'
refuses "a malformed mirror" "--mirror" "${BASE[@]}" --work-dir /var/tmp/ni-e2e --mirror 'https://x:5055'
refuses "an unbounded OTA budget" "--ota-budget" "${BASE[@]}" --work-dir /var/tmp/ni-e2e --ota-budget 0
refuses "a privileged SSH forward port" "--ssh-port" "${BASE[@]}" --work-dir /var/tmp/ni-e2e --ssh-port 22
refuses "a malformed operator email" "--operator-email" "${BASE[@]}" --work-dir /var/tmp/ni-e2e --operator-email nobody
refuses "an allow-list with a shell word" "--allow-failed-units" "${BASE[@]}" --work-dir /var/tmp/ni-e2e --allow-failed-units 'a.service;b'
refuses "an unknown argument" "unknown argument" "${BASE[@]}" --work-dir /var/tmp/ni-e2e --wipe-the-host
refuses "a value-less option" "requires a value" "${BASE[@]}" --work-dir

"$DRIVER" --help > "$TMP/help.txt"
grep -Fq -- 'bench-rehearse-e2e.sh --work-dir DIR --medium IMG' "$TMP/help.txt" \
  || fail "--help prints another script's usage"
for option in --closure --license-key-file --target-train --bom-sig-file --skip-to --stop-after --vm-keep --require-inference --ota-budget; do
  grep -Fq -- "$option" "$TMP/help.txt" || fail "--help does not document $option"
done
grep -Fq -- 'qualify-installer-qemu.sh install' "$TMP/help.txt" \
  && fail "--help was replaced by the sourced CI harness's usage"
grep -Fq -- 'bench-rehearse-medium.sh --raw FILE' "$TMP/help.txt" \
  && fail "--help was replaced by the sourced medium driver's usage"
pass "--help states the e2e contract and survives both sourced scripts"

# --------------------------------------------------------------------------- #
# The contracts a future edit must not quietly drop.
# --------------------------------------------------------------------------- #
echo "== the driver keeps its load-bearing contracts"
# shellcheck disable=SC2016 # literal source contracts are being matched
for contract in \
  'NI_BENCH_HARNESS_SOURCE_ONLY=1 source "$MEDIUM_DRIVER"' \
  'NI_QEMU_HARNESS_SOURCE_ONLY=1 source "$QEMU_HARNESS"' \
  '--medium-overlay --skip-firstboot --allow-root' \
  'virt,accel=kvm,gic-version=3' \
  'manufacturer=NVIDIA,product=NVIDIA_DGX_Spark' \
  'manufacturer=NVIDIA,product=P4242' \
  'swtpm socket --tpm2 --tpmstate "dir=$tpm_dir"' \
  'hostfwd=tcp:127.0.0.1:${ssh_port}-:22' \
  '-nographic -no-reboot' \
  'trap cleanup EXIT' \
  'terminate_qemu_session "$vm_pid"' \
  'ni-ota-verify authenticated-ota-status' \
  'ni-ota-verify bootstrap --bom "$bom" --bom-sig "$d/bom.sig"' \
  '--bundle "$train" --channel "$ring"' \
  'OTA_AUTH_FILE="$d/auth" OTA_ENTITLEMENTS_FILE="$d/entitlements"' \
  '/api/v1/license/enroll' \
  '--resolve "$host:443:127.0.0.1"' \
  'die "[$phase_name] $*"' \
  'the work directory already exists; a run from the medium phase never reuses one' \
  'pass --license-key-file FILE' \
  'pass --bom-sig-file with the Owner' \
  'bench-e2e-receipt.json'; do
  grep -Fq -- "$contract" "$DRIVER" || fail "the driver lost: $contract"
done
pass "medium driver reuse, KVM machine, DMI identity, swtpm, forward, verbs, named refusals"

# 🔴 A NEGATIVE GREP MUST NOT MEASURE THE COMMENT THAT EXPLAINS IT: comments
# are stripped on both sides, and the separation is SABOTAGED to prove the
# check still fires.
code_only() { grep -v '^[[:space:]]*#' "$1"; }
sabotage="$TMP/sabotaged-driver.sh"
cp -- "$DRIVER" "$sabotage"

printf 'nic="user,model=virtio-net-pci,restrict=on"\n' >> "$sabotage"
code_only "$sabotage" | grep -Fq 'restrict=on' || fail "the isolation check cannot see a real restrict=on"
if code_only "$DRIVER" | grep -Fq 'restrict=on'; then
  fail "the driver isolates the guest; the appliance could reach neither the mirror nor the registry"
fi
pass "the guest is not slirp-isolated, and the check fires on a sabotaged copy"

for device in /dev/tpm0 /dev/tpmrm0; do
  if code_only "$DRIVER" | grep -Fq -- "$device"; then
    fail "the driver reaches for the bench hardware TPM at $device"
  fi
done
printf 'swtpm --tpmstate dir=/dev/tpm0\n' >> "$sabotage"
code_only "$sabotage" | grep -Fq -- '/dev/tpm0' || fail "the hardware-TPM check cannot see a real reference"
pass "the bench hardware TPM is never referenced, and the check fires when it is"

# The secrets never reach the evidence: the pairing code and the licence key
# are read into a python process and a 0600 body file, and `ev` never sees
# them. `curl -k` would bypass the appliance's PKI: the edge is trusted through
# its own root certificate.
# shellcheck disable=SC2016 # a literal source pattern is being matched
secret_evidence='ev "[^"]*\$(code|key|lic|fp)\b'
if code_only "$DRIVER" | grep -E "$secret_evidence" >/dev/null; then
  fail "an evidence line carries a secret variable"
fi
# shellcheck disable=SC2016 # the sabotage line is literal source text
printf 'ev "pairing $code"\n' >> "$sabotage"
code_only "$sabotage" | grep -E "$secret_evidence" >/dev/null || fail "the secret-evidence check cannot see a real leak"
if code_only "$DRIVER" | grep -E 'curl [^|]*(-k |--insecure)' >/dev/null; then
  fail "the enrolment bypasses the appliance's PKI"
fi
# shellcheck disable=SC2016 # literal source contract is being matched
grep -Fq -- 'rm -f -- "$body"' "$DRIVER" || fail "the request body holding the licence key is not removed"
pass "no secret in the evidence, no -k, the request body is removed"

# The verdict is the exit code: a phase failure dies after writing the receipt.
grep -Fq 'fail_phase() {' "$DRIVER" || fail "no single refusal path"
grep -Ezq 'fail_phase\(\) \{[^}]*ni_e2e_receipt_write[^}]*die ' "$DRIVER" \
  || fail "fail_phase does not write the receipt before dying"
pass "every refusal writes the receipt, then exits non-zero"

echo "BENCH_E2E_CONTRACT_OK"
