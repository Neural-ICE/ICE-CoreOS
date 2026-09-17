#!/usr/bin/env bash
#
# ONE BENCH REHEARSAL THAT CHAINS THE WHOLE APPLIANCE LIFE FROM NOTHING:
#   medium -> KVM install -> first boot -> onboarding (pairing + licence
#   enrolment) -> OTA to a target train -> activation -> finalize -> applied
#   state advanced.
#
# 🔴 WHY THIS EXISTS (measured on .67, 2026-09-16/17). An OTA on a FRESHLY
# installed appliance failed one gate after another, each gate having only ever
# been exercised on a lab box that carried hand repairs: the ring missing from
# ota.conf (ICE-CoreOS 201), the OTA gate unseeded after a media install (206),
# bootc reading its pull secret from /run/ostree/auth.json only (ICE-Fabric 664),
# last-verdict.json written 0644 into a 0600-only state directory (208), and a
# licence-gate <-> finalize cycle that rolled every OTA back (ICE-Fabric 665).
# None of that is reachable by a rehearsal that stops at the installation. This
# driver goes on, phase by phase, and stops at the FIRST failure with the exact
# refusal, so the next hardware attempt starts from a bench-green chain.
#
# 🔴 WHAT THIS IS NOT. There is no `if vm` here and none is wanted in the
# product. Everything that differs between the VM and the GB10 is an INPUT (the
# Secure Boot variable store, the DMI identity, the mirror address) exactly as
# image/bench-rehearse-medium.sh states. What cannot be rehearsed in QEMU virt
# is REPORTED, never worked around: the NVIDIA GPU stack (no vllm completion in
# this VM), and every operator secret or Owner ceremony (a licence key, a
# cosign signature of the sealed BOM) is a NAMED refusal with the exact thing
# needed, never something this script invents.
#
# RELATION TO image/bench-rehearse-medium.sh. That driver owns the install
# phase (the varstore, swtpm, the sparse target, the serial parsers, its own
# receipt) and its first-boot phase powers the VM off as soon as TCP/22 opens,
# because that is all a medium rehearsal needs to know. This script REUSES it
# unchanged for phase 2, then boots the installed target ITSELF for the phases
# that need the appliance to stay up and to be driven over SSH. It sources the
# same QEMU process-group / QMP / swtpm helpers and the same serial parsers,
# rather than copying them.
set -euo pipefail
umask 077

readonly NI_E2E_RECEIPT_SCHEMA=neural-ice-bench-e2e-receipt-v1
readonly -a NI_E2E_PHASES=(medium install firstboot onboard ota)
# Where the appliance keeps what the phases read. Each is the producer's own
# path (see the comment next to each use); none is invented here.
readonly NI_E2E_APPLIED_STATE=/var/lib/neural-ice/ota/applied.json
readonly NI_E2E_TX_STATE=/var/lib/neural-ice/ota/transaction/state.json
readonly NI_E2E_OTA_CONF=/etc/neural-ice/ota.conf
readonly NI_E2E_OTA_CONTROLLER=/etc/neural-ice/bin/appliance-ota-mvp.sh
readonly NI_E2E_LICENSE_CONF=/var/lib/neural-ice/data/icecore/license/license.conf
readonly NI_E2E_PAIRING_CODE=/var/lib/neural-ice/data/icecore/pairing/console-code
readonly NI_E2E_EDGE_ROOT_CRT=/var/lib/neural-ice/data/icecore/pki/root/root.crt
readonly NI_E2E_HEALTH_MANIFEST=/usr/lib/neural-ice/product-payload/TARGET_HEALTH.json
readonly NI_E2E_VERSION_FILE=/etc/neural-ice/version

e2e_usage() {
  cat <<'EOF'
Usage:
  bench-rehearse-e2e.sh --work-dir DIR --medium IMG --firmware-vars FILE [options]

Phases, in order (the run stops at the first failure with the exact refusal):
  medium     inspect the medium, check the closure hashes to the sealed
             neuralice.seed_closure, prove the LAN mirror serves the closure
  install    image/bench-rehearse-medium.sh: KVM install from the medium onto a
             fresh virtual disk with a fresh software TPM
  firstboot  boot the installed disk, wait for the operator key on TCP/22,
             assert 0 failed units (allow-list), pairing code published,
             `ni-ota-verify authenticated-ota-status` answers, applied state
  onboard    POST /api/v1/license/enroll with the pairing code and the licence
             key file; assert 201 within --enrol-budget, licensed.target up
  ota        appliance-ota-mvp.sh --bundle TRAIN --channel RING, pending_reboot,
             reboot, wait for the durable transaction to reach `completed`,
             applied state advanced, 0 failed units, licensed plane active

Required:
  --work-dir DIR           absolute path; created on the first phase, REUSED by
                           --skip-to (target disk, TPM state, facts, receipt)
  --medium IMG             the installation medium (raw); opened read-only
  --firmware-vars FILE     AAVMF variable store that ALREADY carries the lab
                           Secure Boot db whose PCR7 the sealed policy covers

Inputs the phases need (each missing one is a named refusal, not a guess):
  --closure FILE           release closure JSON; its sha256 must equal the
                           sealed neuralice.seed_closure          (medium)
  --warm-script FILE       ICE-Fabric scripts/warm-release-closure.sh; without
                           it a bounded HEAD walk of the closure runs (medium)
  --mirror HOST:PORT       default: the sealed neuralice.mirror     (medium)
  --mirror-ca FILE         default /etc/neural-ice/lan-mirror/tls/ca.crt
  --mirror-authfile FILE   reader credential for the mirror, 0600 (optional)
  --ssh-identity FILE      operator private key matching the sealed
                           neuralice.sshkey; default: the SSH agent (firstboot+)
  --license-key-file FILE  0600 regular file, one line: the licence key (onboard)
  --operator-email ADDR    first admin user of the appliance         (onboard)
  --operator-name NAME     default "Bench Operator"                  (onboard)
  --target-train TRAIN     the train the OTA must reach                  (ota)
  --ring lab|beta|stable   default: device_channel of the appliance     (ota)
  --entitlements-file FILE default: the codes the enrolment returned    (ota)
  --bom-sig-file FILE      cosign signature of the sealed preseal BOM by the
                           OTA root key: seeds the applied state through
                           `ni-ota-verify bootstrap` when a media install left
                           it unseeded (ICE-CoreOS 206)                 (ota)

Bounds and iteration:
  --skip-to PHASE          start at PHASE on a work directory whose earlier
                           phases already ran (their facts are reloaded)
  --stop-after PHASE       end the run after PHASE (with --vm-keep, the
                           appliance stays up for the next --skip-to)
  --vm-keep                leave the appliance VM running at the end, with its
                           SSH forward, for inspection
  --require-inference      fail the ota phase unless vllm-inference is active
                           and icecore-api served a first completion (QEMU virt
                           has no GB10 GPU: off by default, recorded either way)
  --ssh-port PORT          loopback forward to guest TCP/22 (default 22222)
  --smp N / --memory MiB   guest vCPUs / memory (default 8 / 32768)
  --install-timeout SEC    bound on the install VM (default 5400)
  --firstboot-ssh-wait SEC how long first boot may take to open TCP/22
                           (default 3600: sshd waits for seed-import)
  --enrol-budget SEC       the 201 must arrive within (default 10)
  --licensed-wait SEC      licensed.target must be active within (default 420)
  --ota-budget SEC         from the controller start to `completed` (default 5400)
  --vm-timeout SEC         hard bound on any single appliance boot (default 21600)
  --allow-failed-units CSV units tolerated at first boot before enrolment
                           (default license-check.service)
  --serial-max-bytes N     per-boot serial log ceiling (default 16777216)
  -h, --help               this text

Output, all inside --work-dir:
  bench-e2e-receipt.json   one object per phase: name, started, ended, rc,
                           status, evidence lines
  medium/                  image/bench-rehearse-medium.sh's own work directory
  logs/<boot>.console.log  every appliance boot's serial console
  facts/<phase>.env        the non-secret facts later phases reload
  onboard/, ota/           per-phase evidence (0600; never a secret)

Runs as root on the bench (the medium driver is given --allow-root). The
operator key stays wherever it is: pass --ssh-identity, or forward the agent
(`ssh -A`, then `sudo -n --preserve-env=SSH_AUTH_SOCK`).
EOF
}

# --------------------------------------------------------------------------- #
# PURE FUNCTIONS. No globals, no processes killed, nothing written outside the
# path they are given. image/test-bench-rehearse-e2e.sh sources them through
# the seam below and proves them over fixtures, because they decide what the
# evidence MEANS.
# --------------------------------------------------------------------------- #

# $1=phase name -> its 0-based index on stdout; 1 if unknown.
ni_e2e_phase_index() {
  local i
  for i in "${!NI_E2E_PHASES[@]}"; do
    [[ "${NI_E2E_PHASES[$i]}" == "$1" ]] && { printf '%s\n' "$i"; return 0; }
  done
  return 1
}

# $1=inspect-installer-media.py output $2=sealed key (without `neuralice.`).
# Prints the value only if it has the shape the key admits; 1 otherwise. The
# shapes are the grammar's (image/installer/neural-ice-sealed-cmdline-grammar.sh).
ni_e2e_sealed_value() {
  local report=$1 key=$2 line value
  [[ -f "$report" && ! -L "$report" && -r "$report" ]] || return 1
  line="$(grep -F -m1 'sealed cmdline' -- "$report")" || return 1
  value="$(printf '%s\n' "$line" | tr ' ' '\n' | sed -n "s/^neuralice\.${key}=//p" | head -n1)"
  [[ -n "$value" ]] || return 1
  case "$key" in
    seed_closure|payload|rootverity|preseal|mirror_ca_sha256|pcr_policy)
      [[ "$value" =~ ^[0-9a-f]{64}$ ]] || return 1 ;;
    mirror)
      [[ "$value" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?(:[1-9][0-9]{0,4})?$ ]] || return 1 ;;
    imgref|osimage)
      [[ "$value" =~ ^[a-z0-9.-]+(:[0-9]+)?(/[a-z0-9._-]+)+@sha256:[0-9a-f]{64}$ ]] || return 1 ;;
    device_channel)
      [[ "$value" =~ ^(lab|beta|stable)$ ]] || return 1 ;;
    sshkey)
      [[ "$value" =~ ^[A-Za-z0-9+/=]{1,1024}$ ]] || return 1 ;;
    mirror_generation|pcr_policy_seq)
      [[ "$value" =~ ^[1-9][0-9]{0,18}$ ]] || return 1 ;;
    *) return 1 ;;
  esac
  printf '%s\n' "$value"
}

# $1=receipt path $2=phase $3=started $4=ended $5=rc $6=status $7=evidence file
# [$8=work dir]. Rewrites the receipt with this phase's object replacing any
# earlier object of the same name (a --skip-to re-run supersedes, never
# duplicates). Values cross through the environment, never through
# interpolation, so a path with a quote cannot break the JSON.
ni_e2e_receipt_write() {
  NI_E2E_R_PATH="$1" NI_E2E_R_NAME="$2" NI_E2E_R_STARTED="$3" NI_E2E_R_ENDED="$4" \
  NI_E2E_R_RC="$5" NI_E2E_R_STATUS="$6" NI_E2E_R_EVIDENCE="$7" NI_E2E_R_WORK="${8:-}" \
  NI_E2E_R_SCHEMA="$NI_E2E_RECEIPT_SCHEMA" NI_E2E_R_ORDER="${NI_E2E_PHASES[*]}" \
  python3 - <<'PY'
import json
import os
import re

path = os.environ["NI_E2E_R_PATH"]
name = os.environ["NI_E2E_R_NAME"]
order = os.environ["NI_E2E_R_ORDER"].split()
if name not in order:
    raise SystemExit(f"receipt: unknown phase {name!r}")
status = os.environ["NI_E2E_R_STATUS"]
if status not in ("passed", "failed", "skipped", "running"):
    raise SystemExit(f"receipt: unknown status {status!r}")
rc_raw = os.environ["NI_E2E_R_RC"]
rc = int(rc_raw) if re.fullmatch(r"-?[0-9]{1,5}", rc_raw) else None
stamp = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z|none")
started, ended = os.environ["NI_E2E_R_STARTED"], os.environ["NI_E2E_R_ENDED"]
for label, value in (("started", started), ("ended", ended)):
    if not stamp.fullmatch(value):
        raise SystemExit(f"receipt: {label} is not an ISO-8601 UTC stamp: {value!r}")

evidence = []
evidence_path = os.environ["NI_E2E_R_EVIDENCE"]
if evidence_path and os.path.isfile(evidence_path):
    with open(evidence_path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = "".join(ch for ch in line.rstrip("\n") if 32 <= ord(ch) < 127)
            if line:
                evidence.append(line[:400])
            if len(evidence) >= 400:
                evidence.append("... evidence truncated at 400 lines")
                break

receipt = {"schema": os.environ["NI_E2E_R_SCHEMA"], "phase_order": order, "phases": []}
if os.path.isfile(path):
    with open(path, "r", encoding="utf-8") as handle:
        loaded = json.load(handle)
    if isinstance(loaded, dict) and loaded.get("schema") == receipt["schema"]:
        receipt["phases"] = [p for p in loaded.get("phases", []) if isinstance(p, dict)]
        if isinstance(loaded.get("work_dir"), str):
            receipt["work_dir"] = loaded["work_dir"]
work = os.environ["NI_E2E_R_WORK"]
if work:
    receipt["work_dir"] = work
receipt["phases"] = [p for p in receipt["phases"] if p.get("name") != name]
receipt["phases"].append({
    "name": name, "started": started, "ended": ended, "rc": rc,
    "status": status, "evidence": evidence,
})
receipt["phases"].sort(key=lambda p: order.index(p["name"]) if p.get("name") in order else 99)
tmp = path + ".tmp"
with open(tmp, "w", encoding="utf-8") as handle:
    json.dump(receipt, handle, indent=2, sort_keys=True)
    handle.write("\n")
os.chmod(tmp, 0o600)
os.replace(tmp, path)
PY
}

# Bounded readers of the appliance's own JSON surfaces. Each emits key=value
# lines from a closed set; a value outside its shape becomes `unparseable` or
# `none`, never an unbounded string. A missing or non-JSON file is reported the
# same way (the caller decides whether that is a failure).
ni_e2e_parse_ota_status() { # $1=authenticated-ota-status stdout
  python3 - "$1" <<'PY'
import json
import re
import sys

path = sys.argv[1]
try:
    with open(path, "r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError
except (OSError, ValueError):
    print("ota_status=unparseable")
    raise SystemExit(0)
print("ota_status=parsed")
token = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,63}")
schema = value.get("schema")
print("ota_status_schema=" + (schema if isinstance(schema, str) and token.fullmatch(schema) else "none"))
profile = value.get("profile")
print("ota_status_profile=" + (profile if isinstance(profile, str) and token.fullmatch(profile) else "none"))
enforce = value.get("enforce_ready_verified")
print("enforce_ready_verified=" + ("true" if enforce is True else "false" if enforce is False else "none"))
generation = value.get("committed_generation")
if generation is None:
    print("committed_generation=null")
elif isinstance(generation, int) and not isinstance(generation, bool) and 0 <= generation < 10**12:
    print(f"committed_generation={generation}")
else:
    print("committed_generation=none")
PY
}

ni_e2e_parse_tx_state() { # $1=transaction state.json
  python3 - "$1" <<'PY'
import json
import re
import sys

path = sys.argv[1]
try:
    with open(path, "r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError
except (OSError, ValueError):
    print("tx_state=unparseable")
    raise SystemExit(0)
print("tx_state=parsed")
phases = {"prepared", "pending_reboot", "activating", "activated", "finalizing",
          "committing", "completed", "rollback_armed", "rolled_back",
          "recovery_required", "aborted"}
phase = value.get("phase")
print("tx_phase=" + (phase if isinstance(phase, str) and phase in phases else "none"))
token = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._-]{0,127}")
for key in ("train", "channel", "previous_ring", "failure_reason"):
    raw = value.get(key)
    print(f"tx_{key}=" + (raw if isinstance(raw, str) and token.fullmatch(raw) else "none"))
PY
}

ni_e2e_parse_enrol_response() { # $1=enrol response body -> never the certificate
  python3 - "$1" <<'PY'
import json
import re
import sys

path = sys.argv[1]
try:
    with open(path, "r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError
except (OSError, ValueError):
    print("enrol_response=unparseable")
    raise SystemExit(0)
print("enrol_response=parsed")
token = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
status = value.get("status")
print("enrol_status=" + (status if isinstance(status, str) and token.fullmatch(status) else "none"))
licence = value.get("license") if isinstance(value.get("license"), dict) else {}
for key in ("tier", "status"):
    raw = licence.get(key)
    print(f"license_{key}=" + (raw if isinstance(raw, str) and token.fullmatch(raw) else "none"))
codes = licence.get("entitlements")
kept = sorted({c for c in codes if isinstance(c, str) and token.fullmatch(c)}) if isinstance(codes, list) else []
print("entitlements=" + (",".join(kept) if kept else "none"))
fingerprint = value.get("fingerprint")
if isinstance(fingerprint, str) and re.fullmatch(r"[0-9a-f]{64}", fingerprint):
    print("fingerprint_prefix=" + fingerprint[:16])
else:
    print("fingerprint_prefix=none")
ready = value.get("offline_ready")
print("offline_ready=" + ("true" if ready is True else "false" if ready is False else "none"))
detail = value.get("error") if isinstance(value.get("error"), str) else value.get("message")
if isinstance(detail, str):
    detail = "".join(ch for ch in detail if 32 <= ord(ch) < 127)[:200]
    print("enrol_detail=" + detail)
PY
}

# $1=`systemctl --failed --no-legend --plain` output $2=CSV allow-list.
# Prints the failed units that are NOT allow-listed, one per line.
ni_e2e_failed_units() {
  local listing=$1 allow=$2 unit
  [[ -f "$listing" && ! -L "$listing" && -r "$listing" ]] || return 1
  while read -r unit _; do
    [[ "$unit" =~ ^[A-Za-z0-9@._:\\-]{1,255}$ ]] || continue
    [[ ",$allow," == *",$unit,"* ]] && continue
    printf '%s\n' "$unit"
  done < "$listing"
  return 0
}

# $1=warm-release-closure.sh output -> objects/present/fetched/failed from its
# LAST summary line, exactly as the script prints it.
ni_e2e_warm_summary() {
  local log=$1 line
  [[ -f "$log" && ! -L "$log" && -r "$log" ]] || return 1
  line="$(grep -E '^warm: objects=[0-9]+ present=[0-9]+ fetched=[0-9]+ failed=[0-9]+$' -- "$log" | tail -n1)" || true
  [[ -n "$line" ]] || { printf 'warm_summary=absent\n'; return 0; }
  printf 'warm_summary=present\n'
  printf '%s\n' "${line#warm: }" | tr ' ' '\n' | sed 's/^/warm_/'
}

# The behavioural test sources these exact functions. This cannot turn a bench
# invocation into a test: it is accepted only while the file is being sourced.
if [[ "${NI_E2E_HARNESS_SOURCE_ONLY:-}" == 1 ]]; then
  [[ "${BASH_SOURCE[0]}" != "$0" ]] || {
    printf 'bench-rehearse-e2e: source-only mode requires sourcing this file\n' >&2
    exit 2
  }
  return 0
fi

# --------------------------------------------------------------------------- #
# From here down: the bench driver.
# --------------------------------------------------------------------------- #
E2E_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly E2E_DIR
readonly MEDIUM_DRIVER="$E2E_DIR/bench-rehearse-medium.sh"
readonly QEMU_HARNESS="$E2E_DIR/qualify-installer-qemu.sh"
readonly MEDIA_INSPECTOR="$E2E_DIR/inspect-installer-media.py"
for helper in "$MEDIUM_DRIVER" "$QEMU_HARNESS" "$MEDIA_INSPECTOR"; do
  [[ -f "$helper" && ! -L "$helper" ]] || {
    printf 'bench-rehearse-e2e: REFUSED: missing helper next to this script: %s\n' "$helper" >&2
    exit 1
  }
done
# The serial parsers (ni_bench_parse_firstboot_log) come from the medium driver;
# the process-group, QMP and swtpm helpers from the CI harness. Both seams
# return before either script parses arguments or touches the host.
# shellcheck source=image/bench-rehearse-medium.sh
NI_BENCH_HARNESS_SOURCE_ONLY=1 source "$MEDIUM_DRIVER"
# shellcheck source=image/qualify-installer-qemu.sh
NI_QEMU_HARNESS_SOURCE_ONLY=1 source "$QEMU_HARNESS"

die() { printf 'bench-rehearse-e2e: REFUSED: %s\n' "$*" >&2; exit 1; }
say() { printf 'bench-rehearse-e2e: %s\n' "$*"; }
need() { command -v "$1" >/dev/null 2>&1 || die "$1 is unavailable"; }
now() { date -u +%Y-%m-%dT%H:%M:%SZ; }

(( $# >= 1 )) || { e2e_usage >&2; exit 2; }

work_dir='' medium='' firmware_vars='' closure='' warm_script='' mirror='' mirror_authfile=''
mirror_ca=/etc/neural-ice/lan-mirror/tls/ca.crt
ssh_identity='' license_key_file='' operator_email='' operator_name="Bench Operator"
target_train='' ring='' entitlements_file='' bom_sig_file='' skip_to=medium stop_after=ota
vm_keep=0 require_inference=0
ssh_port=22222 smp=8 memory=32768
install_timeout=5400 firstboot_ssh_wait=3600 enrol_budget=10 licensed_wait=420
ota_budget=5400 vm_timeout=21600 serial_max_bytes=16777216
allow_failed_units=license-check.service

while (( $# )); do
  case "$1" in
    --work-dir|--medium|--firmware-vars|--closure|--warm-script|--mirror|--mirror-ca \
    |--mirror-authfile|--ssh-identity|--license-key-file|--operator-email|--operator-name \
    |--target-train|--ring|--entitlements-file|--bom-sig-file|--skip-to|--stop-after|--ssh-port|--smp \
    |--memory|--install-timeout|--firstboot-ssh-wait|--enrol-budget|--licensed-wait \
    |--ota-budget|--vm-timeout|--allow-failed-units|--serial-max-bytes)
      (( $# >= 2 )) || die "$1 requires a value"
      key=$1 value=$2
      shift 2
      case "$key" in
        --work-dir) work_dir=$value ;;
        --medium) medium=$value ;;
        --firmware-vars) firmware_vars=$value ;;
        --closure) closure=$value ;;
        --warm-script) warm_script=$value ;;
        --mirror) mirror=$value ;;
        --mirror-ca) mirror_ca=$value ;;
        --mirror-authfile) mirror_authfile=$value ;;
        --ssh-identity) ssh_identity=$value ;;
        --license-key-file) license_key_file=$value ;;
        --operator-email) operator_email=$value ;;
        --operator-name) operator_name=$value ;;
        --target-train) target_train=$value ;;
        --ring) ring=$value ;;
        --entitlements-file) entitlements_file=$value ;;
        --bom-sig-file) bom_sig_file=$value ;;
        --skip-to) skip_to=$value ;;
        --stop-after) stop_after=$value ;;
        --ssh-port) ssh_port=$value ;;
        --smp) smp=$value ;;
        --memory) memory=$value ;;
        --install-timeout) install_timeout=$value ;;
        --firstboot-ssh-wait) firstboot_ssh_wait=$value ;;
        --enrol-budget) enrol_budget=$value ;;
        --licensed-wait) licensed_wait=$value ;;
        --ota-budget) ota_budget=$value ;;
        --vm-timeout) vm_timeout=$value ;;
        --allow-failed-units) allow_failed_units=$value ;;
        --serial-max-bytes) serial_max_bytes=$value ;;
      esac
      ;;
    --vm-keep) vm_keep=1; shift ;;
    --require-inference) require_inference=1; shift ;;
    -h|--help) e2e_usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

# --- argument refusals: all before the host is looked at -------------------- #
[[ -n "$work_dir" && "$work_dir" == /* && "$work_dir" != / ]] \
  || die "--work-dir must be an absolute non-root path"
[[ -n "$medium" && -f "$medium" && ! -L "$medium" && -r "$medium" ]] \
  || die "--medium must name one readable regular file"
[[ -n "$firmware_vars" && -f "$firmware_vars" && ! -L "$firmware_vars" && -r "$firmware_vars" ]] \
  || die "--firmware-vars must name one readable regular file"
skip_index="$(ni_e2e_phase_index "$skip_to")" \
  || die "--skip-to must be one of: ${NI_E2E_PHASES[*]}"
stop_index="$(ni_e2e_phase_index "$stop_after")" \
  || die "--stop-after must be one of: ${NI_E2E_PHASES[*]}"
(( stop_index >= skip_index )) || die "--stop-after $stop_after comes before --skip-to $skip_to"
for bound in ssh_port smp memory install_timeout firstboot_ssh_wait enrol_budget \
             licensed_wait ota_budget vm_timeout; do
  [[ "${!bound}" =~ ^[1-9][0-9]{0,5}$ ]] || die "--${bound//_/-} is malformed"
done
[[ "$ssh_port" -ge 1024 && "$ssh_port" -le 65535 ]] || die "--ssh-port must be 1024..65535"
[[ "$serial_max_bytes" =~ ^[1-9][0-9]{4,10}$ ]] || die "--serial-max-bytes is malformed"
[[ -z "$ring" || "$ring" =~ ^(lab|beta|stable)$ ]] || die "--ring must be lab, beta or stable"
[[ -z "$target_train" || "$target_train" =~ ^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$ ]] \
  || die "--target-train is malformed"
[[ -z "$mirror" || "$mirror" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?(:[1-9][0-9]{0,4})?$ ]] \
  || die "--mirror must be HOST[:PORT]"
[[ "$allow_failed_units" =~ ^([A-Za-z0-9@._:-]+(,[A-Za-z0-9@._:-]+)*)?$ ]] \
  || die "--allow-failed-units must be a comma-separated list of unit names"
[[ -z "$operator_email" || "$operator_email" =~ ^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$ ]] \
  || die "--operator-email is malformed"
[[ "$operator_name" =~ ^[[:print:]]{1,64}$ ]] || die "--operator-name is malformed"
private_regular() { # $1=path $2=option name — a 0600 root-only regular file
  local mode
  [[ -n "$1" ]] || return 0
  [[ -f "$1" && ! -L "$1" && -r "$1" && -s "$1" ]] || die "$2 must name one readable, non-empty regular file"
  mode="$(stat -c %a -- "$1")"
  (( (8#$mode & 077) == 0 )) || die "$2 must not be readable by group or other (mode $mode)"
}
private_regular "$license_key_file" --license-key-file
private_regular "$mirror_authfile" --mirror-authfile
private_regular "$ssh_identity" --ssh-identity
for optional in closure warm_script bom_sig_file entitlements_file; do
  [[ -z "${!optional}" ]] && continue
  [[ -f "${!optional}" && ! -L "${!optional}" && -r "${!optional}" ]] \
    || die "--${optional//_/-} must name one readable regular file"
done
[[ -f "$mirror_ca" && ! -L "$mirror_ca" && -r "$mirror_ca" ]] \
  || die "--mirror-ca must name one readable regular file"

(( EUID == 0 )) || die "run as root on the bench (sudo -n --preserve-env=SSH_AUTH_SOCK); the medium driver is given --allow-root on purpose"
for tool in qemu-system-aarch64 qemu-img swtpm timeout setsid python3 awk stat ssh ssh-keygen \
            curl openssl jq sha256sum base64 flock; do need "$tool"; done
[[ "$(uname -m)" == aarch64 ]] || die "the rehearsal boots an ARM64 medium and requires an ARM64 host"
[[ -r /dev/kvm && -w /dev/kvm ]] || die "/dev/kvm is unreadable or unwritable"

# --- the work directory ----------------------------------------------------- #
if [[ -e "$work_dir" ]]; then
  [[ -d "$work_dir" && ! -L "$work_dir" ]] || die "the work directory exists and is not a directory"
  (( skip_index > 0 )) || die "the work directory already exists; a run from the medium phase never reuses one (use --skip-to)"
else
  (( skip_index == 0 )) || die "--skip-to $skip_to needs a work directory whose earlier phases already ran"
  mkdir -m 0700 -- "$work_dir"
fi
for sub in logs facts onboard ota; do install -d -m 0700 -- "$work_dir/$sub"; done
receipt=$work_dir/bench-e2e-receipt.json
medium_work=$work_dir/medium
tpm_dir=$medium_work/tpmstate
target=$medium_work/target.qcow2
vars=$medium_work/AAVMF_VARS.fd
tpm_ctrl=$work_dir/swtpm.ctrl
tpm_pidfile=$work_dir/swtpm.pid
vm_pidfile=$work_dir/vm.pid
known_hosts=$work_dir/ssh_known_hosts
firmware_code=/usr/share/AAVMF/AAVMF_CODE.secboot.fd
[[ -f "$firmware_code" && -r "$firmware_code" ]] || die "AAVMF code is unreadable: $firmware_code"

# Facts: the NON-SECRET values a phase leaves for the next (and for --skip-to).
save_fact() { # $1=phase $2=key $3=value
  [[ "$2" =~ ^[a-z_]+$ ]] || die "internal: fact key $2"
  [[ "$3" =~ ^[[:print:]]{0,512}$ ]] || die "internal: fact value for $2 is out of shape"
  local file=$work_dir/facts/$1.env
  touch -- "$file"; chmod 0600 -- "$file"
  { grep -v "^$2=" -- "$file" 2>/dev/null || true; printf '%s=%s\n' "$2" "$3"; } > "$file.tmp"
  mv -f -- "$file.tmp" "$file"
}
fact() { # $1=phase $2=key -> value or empty
  local file=$work_dir/facts/$1.env
  [[ -f "$file" ]] || return 0
  sed -n "s/^$2=//p" -- "$file" | tail -n1
}

# --------------------------------------------------------------------------- #
# Phase runner and evidence. `ev` appends one bounded line to the phase's
# evidence file; `fail_phase` is the ONLY way out of a phase with a refusal:
# it writes the receipt, then dies with the exact reason.
# --------------------------------------------------------------------------- #
phase_name='' phase_started='' phase_evidence=''
ev() { printf '%s\n' "$*" >> "$phase_evidence"; say "  $*"; }
begin_phase() {
  phase_name=$1
  phase_started="$(now)"
  phase_evidence=$work_dir/logs/$1.evidence
  : > "$phase_evidence"
  ni_e2e_receipt_write "$receipt" "$phase_name" "$phase_started" none none running "$phase_evidence" "$work_dir"
  say "== phase $phase_name started $phase_started"
}
end_phase() {
  ni_e2e_receipt_write "$receipt" "$phase_name" "$phase_started" "$(now)" 0 passed "$phase_evidence" "$work_dir"
  say "== phase $phase_name PASSED"
}
fail_phase() { # $*=the exact refusal
  ev "REFUSED: $*"
  ni_e2e_receipt_write "$receipt" "$phase_name" "$phase_started" "$(now)" 1 failed "$phase_evidence" "$work_dir"
  die "[$phase_name] $*"
}
skip_phase() {
  local stamp; stamp="$(now)"
  printf 'skipped by --skip-to %s\n' "$skip_to" > "$work_dir/logs/$1.evidence"
  ni_e2e_receipt_write "$receipt" "$1" "$stamp" "$stamp" none skipped "$work_dir/logs/$1.evidence" "$work_dir"
}

# --------------------------------------------------------------------------- #
# The appliance VM. Same machine, firmware, DMI identity, software TPM and
# user-mode NAT as image/bench-rehearse-medium.sh's first-boot phase — that is
# what keeps PCR7 covered and the TPM-sealed LUKS volume unlockable. Each boot
# is a fresh QEMU process (-no-reboot: a guest reboot ends the process and the
# driver starts the next boot), so every boot has its own serial log and every
# reboot is a real power cycle.
# --------------------------------------------------------------------------- #
vm_pid='' vm_boot_name='' qmp_socket='' swtpm_pidfile=''
cleanup() {
  local rc=$? pid
  trap - EXIT
  if (( vm_keep )) && [[ -n "$vm_pid" ]] && process_group_exists "$vm_pid"; then
    printf '%s\n' "$vm_pid" > "$vm_pidfile"
    say "VM kept running (--vm-keep): ssh -p $ssh_port core@127.0.0.1 ; QEMU session $vm_pid ; swtpm pid file $tpm_pidfile"
    exit "$rc"
  fi
  if [[ -n "$vm_pid" ]]; then
    terminate_qemu_session "$vm_pid" || say "the QEMU session $vm_pid survived cleanup"
  fi
  if [[ -n "$swtpm_pidfile" && -f "$swtpm_pidfile" ]]; then
    pid=$(<"$swtpm_pidfile")
    stop_task_process "$pid" swtpm || true
  fi
  [[ -z "$qmp_socket" ]] || rm -f -- "$qmp_socket"
  rm -f -- "$vm_pidfile"
  exit "$rc"
}
trap cleanup EXIT

start_swtpm() {
  rm -f -- "$tpm_ctrl" "$tpm_pidfile"
  swtpm socket --tpm2 --tpmstate "dir=$tpm_dir" \
    --ctrl "type=unixio,path=$tpm_ctrl,mode=0600" \
    --pid "file=$tpm_pidfile" --flags startup-clear --daemon \
    || die "swtpm refused to start"
  swtpm_pidfile=$tpm_pidfile
  local _
  for _ in {1..50}; do [[ -S "$tpm_ctrl" ]] && break; sleep 0.1; done
  [[ -S "$tpm_ctrl" ]] || die "the swtpm control socket did not appear"
}
stop_swtpm() {
  local pid
  [[ -n "$swtpm_pidfile" && -f "$swtpm_pidfile" ]] || { swtpm_pidfile=; return 0; }
  pid=$(<"$swtpm_pidfile"); swtpm_pidfile=
  stop_task_process "$pid" swtpm || die "swtpm survived a bounded shutdown"
  rm -f -- "$tpm_ctrl" "$tpm_pidfile"
}

vm_alive() { [[ -n "$vm_pid" ]] && process_group_exists "$vm_pid"; }
vm_console() { printf '%s/logs/%s.console.log\n' "$work_dir" "$vm_boot_name"; }

vm_boot() { # $1=boot name
  local name=$1 console stderr_log
  vm_boot_name=$name
  console="$(vm_console)"; stderr_log=$work_dir/logs/$name.qemu.stderr
  [[ ! -e "$console" ]] || die "a boot named $name already has a console log in $work_dir/logs"
  qmp_socket=$work_dir/$name.qmp.sock
  rm -f -- "$qmp_socket"
  start_swtpm
  local -a qemu=(
    qemu-system-aarch64
    -name "neural-ice-bench-e2e-$name"
    -machine "virt,accel=kvm,gic-version=3"
    -cpu host -smp "$smp" -m "$memory"
    -smbios "type=1,manufacturer=NVIDIA,product=NVIDIA_DGX_Spark"
    -smbios "type=2,manufacturer=NVIDIA,product=P4242"
    -drive "if=pflash,format=raw,unit=0,readonly=on,file=$firmware_code"
    -drive "if=pflash,format=raw,unit=1,file=$vars"
    -chardev "socket,id=chrtpm,path=$tpm_ctrl"
    -tpmdev "emulator,id=tpm0,chardev=chrtpm"
    -device "tpm-tis-device,tpmdev=tpm0"
    -device "virtio-keyboard-pci"
    -qmp "unix:$qmp_socket,server=on,wait=off"
    -drive "if=none,id=target,format=qcow2,file=$target,discard=unmap"
    -device "nvme,drive=target,serial=NIBENCHTARGET,bootindex=2"
    -nic "user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:${ssh_port}-:22"
    -nographic -no-reboot
  )
  set +e
  setsid --wait timeout --foreground "$vm_timeout" "${qemu[@]}" >"$console" 2>"$stderr_log" &
  vm_pid=$!
  set -e
  printf '%s\n' "$vm_pid" > "$vm_pidfile"
  say "boot $name: QEMU session $vm_pid, console $console"
}

# Waits for the guest to end its own boot (reboot/poweroff under -no-reboot).
vm_wait_exit() { # $1=seconds
  local deadline=$(( SECONDS + $1 ))
  while vm_alive; do
    (( SECONDS < deadline )) || return 1
    sleep 2
  done
  wait "$vm_pid" 2>/dev/null || true
  vm_pid=
  rm -f -- "$qmp_socket" "$vm_pidfile"; qmp_socket=
  stop_swtpm
  return 0
}

vm_stop() { # bounded: ask the OS, then QMP, then the process group
  vm_alive || { vm_pid=; stop_swtpm; return 0; }
  vm_ssh_root 'systemctl poweroff' </dev/null >/dev/null 2>&1 || true
  vm_wait_exit 120 && return 0
  if [[ -n "$qmp_socket" ]]; then qmp_guest_request "$qmp_socket" system_powerdown || true; fi
  vm_wait_exit 60 && return 0
  terminate_qemu_session "$vm_pid" || true
  vm_wait_exit 30 || die "the QEMU session $vm_pid survived a bounded shutdown"
}

vm_ssh() { # $@=remote command words; stdin passes through
  local -a opts=(-p "$ssh_port" -o BatchMode=yes -o ConnectTimeout=15 -o ServerAliveInterval=15
                 -o ServerAliveCountMax=4 -o StrictHostKeyChecking=no -o "UserKnownHostsFile=$known_hosts"
                 -o LogLevel=ERROR)
  [[ -z "$ssh_identity" ]] || opts+=(-i "$ssh_identity" -o IdentitiesOnly=yes)
  ssh "${opts[@]}" core@127.0.0.1 -- "$@"
}
# $1=a bash script run as root on the appliance, $2..=its positional
# parameters; stdin passes through to it. %q-quoting keeps every word intact
# through ssh's remote shell (bash: image/Containerfile.bootc gives core
# /bin/bash), so no value is ever interpolated into the script text.
vm_ssh_root() {
  local script=$1 word
  local -a quoted=()
  shift
  for word in "$@"; do quoted+=("$(printf '%q' "$word")"); done
  vm_ssh sudo -n bash -c "$(printf '%q' "$script")" _ "${quoted[@]}"
}

# Waits for TCP/22 to answer AND the operator key to authenticate. Meanwhile
# the serial console is watched for the status screen's FAILURE line (NI-Exx)
# and the process for an early exit, so a dead boot is reported in seconds
# rather than at the deadline.
vm_wait_ssh() { # $1=seconds
  local deadline=$(( SECONDS + $1 )) console size facts
  console="$(vm_console)"
  while (( SECONDS < deadline )); do
    vm_alive || return 2
    size=$(stat -c %s -- "$console" 2>/dev/null || echo 0)
    (( size <= serial_max_bytes )) || return 3
    if grep -Fq 'neural-ice-status: FAILURE' "$console" 2>/dev/null; then
      facts="$(ni_bench_parse_firstboot_log "$console")"
      ev "status screen: $(printf '%s\n' "$facts" | grep -E '^firstboot_status_failure' | tr '\n' ' ')"
      return 4
    fi
    # shellcheck disable=SC2016 # $1 is the child shell's positional parameter
    if timeout 2 bash -c 'exec 3<>/dev/tcp/127.0.0.1/"$1"' _ "$ssh_port" 2>/dev/null \
       && vm_ssh true </dev/null >/dev/null 2>&1; then
      return 0
    fi
    sleep 5
  done
  return 1
}

vm_wait_converged() { # bounded `systemctl is-system-running --wait`
  local state
  state="$(vm_ssh_root 'timeout 900 systemctl is-system-running --wait || true' </dev/null 2>/dev/null | tr -d '[:space:]')"
  ev "system state: ${state:-unknown}"
}

# Boots the installed target unless a kept VM from an earlier invocation still
# answers on the forward.
vm_ensure() { # $1=boot name if a boot is needed
  if [[ -f "$vm_pidfile" ]]; then
    local pid; pid=$(<"$vm_pidfile")
    if [[ "$pid" =~ ^[1-9][0-9]*$ ]] && process_group_exists "$pid" && vm_ssh true </dev/null >/dev/null 2>&1; then
      vm_pid=$pid; vm_boot_name=resumed
      [[ -f "$tpm_pidfile" ]] && swtpm_pidfile=$tpm_pidfile
      ev "appliance VM: reused the running session $pid on 127.0.0.1:$ssh_port"
      return 0
    fi
  fi
  [[ -f "$target" && -d "$tpm_dir" && -f "$vars" ]] \
    || fail_phase "no installed target under $medium_work (target.qcow2, tpmstate/, AAVMF_VARS.fd); run the install phase first"
  vm_boot "$1"
  local rc=0
  vm_wait_ssh "$firstboot_ssh_wait" || rc=$?
  case "$rc" in
    0) ev "ssh: operator key answered on 127.0.0.1:$ssh_port" ;;
    1) fail_phase "the appliance did not answer on TCP/22 with the operator key within ${firstboot_ssh_wait}s (boot $1; console $(vm_console))" ;;
    2) fail_phase "the appliance VM exited before TCP/22 opened (boot $1; console $(vm_console))" ;;
    3) fail_phase "the serial console exceeded --serial-max-bytes during boot $1" ;;
    4) fail_phase "the status screen reported a first-boot FAILURE (see the evidence line and $(vm_console))" ;;
  esac
}

# --------------------------------------------------------------------------- #
# Phase 1 — medium.
# --------------------------------------------------------------------------- #
inspect_medium() { # -> $work_dir/logs/inspect.txt
  local sidecar="${medium}.sealed-core.json" verity report=$work_dir/logs/inspect.txt
  [[ -f "$sidecar" && ! -L "$sidecar" ]] \
    || fail_phase "the medium has no sealed-core sidecar (${sidecar}); it is what names the verity root hash the inspector must be told"
  verity="$(jq -er '.verity_root_hash | select(test("^[0-9a-f]{64}$"))' "$sidecar" 2>/dev/null)" \
    || fail_phase "the sidecar carries no verity_root_hash"
  if ! python3 "$MEDIA_INSPECTOR" --raw "$medium" --expect-verity-root-hash "$verity" > "$report" 2>&1; then
    tail -n 5 "$report" | while IFS= read -r line; do ev "inspect: $line"; done
    fail_phase "inspect-installer-media.py refused the medium (see $report)"
  fi
  ev "inspect: $(head -n1 "$report")"
}
sealed() { # $1=key -> value, or a refusal naming the key
  ni_e2e_sealed_value "$work_dir/logs/inspect.txt" "$1" \
    || fail_phase "the sealed command line carries no well-formed neuralice.$1"
}

phase_medium() {
  begin_phase medium
  local medium_size closure_hash sealed_closure sealed_mirror sealed_imgref sealed_channel key_sha
  medium_size="$(stat -c %s -- "$medium")"
  ev "medium: $medium ($medium_size bytes)"
  inspect_medium
  sealed_closure="$(sealed seed_closure)"
  sealed_mirror="$(sealed mirror)"
  sealed_imgref="$(sealed imgref)"
  sealed_channel="$(sealed device_channel)"
  key_sha="$(sealed sshkey | sha256sum | awk '{print $1}')"
  ev "sealed: seed_closure=$sealed_closure mirror=$sealed_mirror device_channel=$sealed_channel"
  ev "sealed: imgref=$sealed_imgref"
  ev "sealed: pcr_policy_seq=$(sealed pcr_policy_seq) mirror_generation=$(sealed mirror_generation) sshkey_sha256=${key_sha:0:16}"
  save_fact medium seed_closure "$sealed_closure"
  save_fact medium mirror "$sealed_mirror"
  save_fact medium imgref "$sealed_imgref"
  save_fact medium device_channel "$sealed_channel"
  [[ -n "$mirror" ]] || mirror=$sealed_mirror
  [[ -n "$closure" ]] \
    || fail_phase "pass --closure FILE: the release closure the medium was cut from (sha256 $sealed_closure); the bench copies live under the cut's authority/build-inputs/seed-v2/release-closure.json"
  closure_hash="$(sha256sum -- "$closure" | awk '{print $1}')"
  [[ "$closure_hash" == "$sealed_closure" ]] \
    || fail_phase "--closure hashes to $closure_hash, the medium seals $sealed_closure: not the closure this medium installs"
  ev "closure: $closure hashes to the sealed seed_closure"
  local mirror_host=${mirror%%:*} mirror_port=${mirror##*:}
  [[ "$mirror" == *:* ]] || mirror_port=443
  # shellcheck disable=SC2016 # $1/$2 are the child shell's positional parameters
  timeout 5 bash -c 'exec 3<>/dev/tcp/"$1"/"$2"' _ "$mirror_host" "$mirror_port" 2>/dev/null \
    || fail_phase "the bench host cannot open ${mirror_host}:${mirror_port}; the guest will not reach it either"
  local warm_log=$work_dir/logs/medium.warm.log summary
  if [[ -n "$warm_script" ]]; then
    ev "mirror probe: $warm_script (ICE-Fabric warm-release-closure)"
    local -a warm=("$warm_script" --closure "$closure" --mirror "$mirror" --ca "$mirror_ca")
    [[ -z "$mirror_authfile" ]] || warm+=(--authfile "$mirror_authfile")
    local warm_rc=0
    "${warm[@]}" > "$warm_log" 2>&1 || warm_rc=$?
    summary="$(ni_e2e_warm_summary "$warm_log")"
    printf '%s\n' "$summary" | while IFS= read -r line; do ev "$line"; done
    if (( warm_rc != 0 )); then
      grep -E '^REFUSED|^(missing|404|FAIL)' "$warm_log" | head -n 5 | while IFS= read -r line; do ev "warm: $line"; done
      fail_phase "the mirror does not serve the whole closure (warm-release-closure rc=$warm_rc, $warm_log)"
    fi
    [[ "$summary" == *'warm_failed=0'* ]] || fail_phase "warm-release-closure reported failures ($warm_log)"
  else
    ev "mirror probe: bounded HEAD walk of every closure node and attachment (no --warm-script)"
    local -a walk=(python3 - "$closure" "$mirror" "$mirror_ca")
    if ! "${walk[@]}" > "$warm_log" 2>&1 <<'PY'
import hashlib
import json
import ssl
import sys
import urllib.error
import urllib.request

closure_path, mirror, ca = sys.argv[1:4]
MAX_OBJECTS = 20000
with open(closure_path, "r", encoding="utf-8") as handle:
    closure = json.load(handle)
context = ssl.create_default_context(cafile=ca)
objects = []
for artifact in closure.get("artifacts", []):
    for node in artifact.get("nodes", []):
        repo = str(node.get("repository", "")).split("/", 1)
        if len(repo) != 2 or not str(node.get("digest", "")).startswith("sha256:"):
            continue
        kind = "manifests" if node.get("kind") in ("index", "manifest") else "blobs"
        objects.append((repo[1], kind, node["digest"]))
    repo = str(artifact.get("repository", "")).split("/", 1)
    for attachment in artifact.get("attachments", []):
        if len(repo) != 2:
            continue
        digest = attachment.get("manifest_digest")
        if isinstance(digest, str) and digest.startswith("sha256:"):
            objects.append((repo[1], "manifests", digest))
        for layer in attachment.get("layer_digests", []) or []:
            if isinstance(layer, str) and layer.startswith("sha256:"):
                objects.append((repo[1], "blobs", layer))
objects = sorted(set(objects))
if len(objects) > MAX_OBJECTS:
    print(f"REFUSED: closure names {len(objects)} objects, more than the {MAX_OBJECTS} bound")
    raise SystemExit(1)
present = failed = 0
for repo, kind, digest in objects:
    url = f"https://{mirror}/v2/{repo}/{kind}/{digest}"
    request = urllib.request.Request(url, method="HEAD", headers={
        "Accept": "application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, */*"})
    try:
        with urllib.request.urlopen(request, timeout=30, context=context) as response:
            code = response.status
    except urllib.error.HTTPError as error:
        code = error.code
    except (urllib.error.URLError, OSError) as error:
        code = f"error {error}"
    if code == 200:
        present += 1
    else:
        failed += 1
        print(f"missing {code} {repo} {kind} {digest}")
print(f"warm: objects={len(objects)} present={present} fetched=0 failed={failed}")
raise SystemExit(0 if failed == 0 else 1)
PY
    then
      summary="$(ni_e2e_warm_summary "$warm_log")"
      printf '%s\n' "$summary" | while IFS= read -r line; do ev "$line"; done
      grep -E '^missing|^REFUSED' "$warm_log" | head -n 5 | while IFS= read -r line; do ev "$line"; done
      fail_phase "the mirror does not serve the whole closure ($warm_log)"
    fi
    summary="$(ni_e2e_warm_summary "$warm_log")"
    printf '%s\n' "$summary" | while IFS= read -r line; do ev "$line"; done
  fi
  save_fact medium mirror_probe "$(printf '%s' "$summary" | tr '\n' ' ')"
  end_phase
}

# --------------------------------------------------------------------------- #
# Phase 2 — install, through image/bench-rehearse-medium.sh unchanged.
# --------------------------------------------------------------------------- #
phase_install() {
  begin_phase install
  [[ ! -e "$medium_work" ]] \
    || fail_phase "$medium_work already exists; the medium driver never reuses one (remove it, or --skip-to firstboot)"
  local sealed_mirror mirror_host mirror_port driver_log=$work_dir/logs/install-driver.log rc=0
  sealed_mirror="$(fact medium mirror)"
  [[ -n "$sealed_mirror" ]] || { inspect_medium; sealed_mirror="$(sealed mirror)"; save_fact medium mirror "$sealed_mirror"; }
  mirror_host=${sealed_mirror%%:*}; mirror_port=${sealed_mirror##*:}
  [[ "$sealed_mirror" == *:* ]] || mirror_port=443
  local -a driver=("$MEDIUM_DRIVER" --raw "$medium" --work-dir "$medium_work"
                   --firmware-vars "$firmware_vars" --medium-overlay --skip-firstboot --allow-root
                   --smp "$smp" --memory "$memory" --install-timeout "$install_timeout"
                   --ssh-port "$ssh_port" --serial-max-bytes "$serial_max_bytes")
  if [[ "$mirror_host" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    driver+=(--mirror-ip "$mirror_host" --mirror-port "$mirror_port")
  else
    ev "mirror is sealed by name ($sealed_mirror): the driver's host-side reachability check is skipped (user-mode NAT carries no mDNS)"
  fi
  ev "driver: ${driver[*]}"
  "${driver[@]}" > "$driver_log" 2>&1 || rc=$?
  local driver_receipt=$medium_work/bench-rehearsal-receipt.json
  [[ -f "$driver_receipt" ]] || {
    tail -n 5 "$driver_log" | while IFS= read -r line; do ev "driver: $line"; done
    fail_phase "the medium driver left no receipt (rc=$rc, $driver_log)"
  }
  local outcome
  outcome="$(jq -r '.install | "outcome=\(.outcome) phase_reached=\(.phase_reached)/\(.phase_total) stop=\(.stop_reason) qemu_exit=\(.qemu_exit) failure_code=\(.failure_code) pcr7_live=\(.pcr7_live)"' "$driver_receipt")"
  ev "install: $outcome"
  ev "install: driver rc=$rc receipt=$driver_receipt"
  [[ "$outcome" == outcome=complete* ]] \
    || fail_phase "the medium did not complete its installation ($outcome; $driver_log)"
  end_phase
}

# --------------------------------------------------------------------------- #
# Phase 3 — first boot.
# --------------------------------------------------------------------------- #
assert_operator_key() {
  local sealed_key key_line fingerprint comment held=
  [[ -f "$work_dir/logs/inspect.txt" ]] || inspect_medium
  sealed_key="$(sealed sshkey)"
  key_line="$(printf '%s' "$sealed_key" | base64 -d 2>/dev/null | head -n1)" \
    || fail_phase "the sealed neuralice.sshkey is not base64"
  fingerprint="$(printf '%s\n' "$key_line" | ssh-keygen -lf - 2>/dev/null | awk '{print $2}')"
  comment="$(printf '%s\n' "$key_line" | awk '{print $3}')"
  [[ "$fingerprint" =~ ^SHA256:[A-Za-z0-9+/=]+$ ]] || fail_phase "the sealed operator key is not a public key ssh-keygen can read"
  if [[ -n "$ssh_identity" ]]; then
    held="$(ssh-keygen -y -f "$ssh_identity" 2>/dev/null | ssh-keygen -lf - 2>/dev/null | awk '{print $2}')"
    [[ "$held" == "$fingerprint" ]] \
      || fail_phase "--ssh-identity does not hold the sealed operator key $fingerprint ($comment)"
    ev "operator key: $fingerprint ($comment) held by --ssh-identity"
  else
    [[ -n "${SSH_AUTH_SOCK:-}" && -S "${SSH_AUTH_SOCK:-}" ]] \
      || fail_phase "the medium seals operator key $fingerprint ($comment); pass --ssh-identity, or forward an agent that holds it (SSH_AUTH_SOCK is unset)"
    ssh-add -l 2>/dev/null | awk '{print $2}' | grep -Fxq -- "$fingerprint" \
      || fail_phase "the SSH agent does not hold the sealed operator key $fingerprint ($comment)"
    ev "operator key: $fingerprint ($comment) held by the SSH agent"
  fi
}

# Read-only facts every boot reports the same way. Written to a file so the
# phase can read fields without a second round trip.
appliance_snapshot() { # $1=destination file
  # shellcheck disable=SC2016 # the script runs on the appliance; $1..$4 are ITS positional parameters
  vm_ssh_root '
set -u
version_file=$1 pairing_code=$2 ota_conf=$3 applied_state=$4
echo "hostname=$(hostname)"
echo "version=$(tr -d "[:space:]" < "$version_file" 2>/dev/null || echo none)"
echo "booted_digest=$(bootc status --json 2>/dev/null | jq -r ".status.booted.image.imageDigest // \"none\"")"
echo "containers=$(podman ps -q 2>/dev/null | wc -l | tr -d " ")"
echo "licensed_target=$(systemctl is-active neural-ice-licensed.target 2>/dev/null || true)"
echo "license_gate=$(systemctl is-active neural-ice-license-gate.service 2>/dev/null || true)"
echo "license_check=$(systemctl is-active license-check.service 2>/dev/null || true)"
echo "vllm_inference=$(systemctl is-active vllm-inference.service 2>/dev/null || true)"
echo "icecore_api=$(systemctl is-active icecore-api.service 2>/dev/null || true)"
echo "pairing_code=$([ -s "$pairing_code" ] && echo published || echo absent)"
echo "enrolled_marker=$([ -e /var/lib/neural-ice/data/icecore/enrolled ] && echo present || echo absent)"
echo "device_channel=$(sed -n "s/^device_channel=//p" "$ota_conf" 2>/dev/null | tail -n1)"
if [ -f "$applied_state" ]; then
  echo "applied_state=seeded"
  echo "applied_bundle_seq=$(jq -r ".bundle_seq // \"none\"" "$applied_state" 2>/dev/null)"
  echo "applied_ring=$(jq -r ".active_ring // \"none\"" "$applied_state" 2>/dev/null)"
else
  echo "applied_state=unseeded"
fi
echo "ota_state_modes=$(ls -l /var/lib/neural-ice/ota 2>/dev/null | awk "NR>1 {print \$1\":\"\$NF}" | tr "\n" " ")"
echo "warmup_ready=$(journalctl -b -u icecore-api.service --no-pager 2>/dev/null | grep -Fc "warm-up: READY")"
echo "---failed---"
systemctl --failed --no-legend --plain 2>/dev/null || true
echo "---ota-status---"
timeout 300 ni-ota-verify authenticated-ota-status 2>&1 || echo "authenticated-ota-status rc=$?"
' "$NI_E2E_VERSION_FILE" "$NI_E2E_PAIRING_CODE" "$NI_E2E_OTA_CONF" "$NI_E2E_APPLIED_STATE" \
    </dev/null > "$1" 2>&1
}
snapshot_value() { sed -n "s/^$2=//p" -- "$1" | head -n1; }
snapshot_section() { # $1=file $2=section name -> the lines between that marker and the next
  awk -v s="---$2---" 'index($0, s)==1 {on=1; next} /^---/ {on=0} on' "$1"
}

phase_firstboot() {
  begin_phase firstboot
  assert_operator_key
  vm_ensure firstboot
  vm_wait_converged
  local snap=$work_dir/logs/firstboot.snapshot failed status_facts rc=0
  appliance_snapshot "$snap"
  ev "appliance: hostname=$(snapshot_value "$snap" hostname) version=$(snapshot_value "$snap" version) booted=$(snapshot_value "$snap" booted_digest | cut -c1-19) containers=$(snapshot_value "$snap" containers)"
  snapshot_section "$snap" failed > "$work_dir/logs/firstboot.failed"
  failed="$(ni_e2e_failed_units "$work_dir/logs/firstboot.failed" "$allow_failed_units" | tr '\n' ' ')"
  ev "failed units: $(wc -l < "$work_dir/logs/firstboot.failed" | tr -d ' ') listed; outside allow-list [$allow_failed_units]: ${failed:-none}"
  ev "pairing code: $(snapshot_value "$snap" pairing_code) at $NI_E2E_PAIRING_CODE"
  ev "ota.conf device_channel=$(snapshot_value "$snap" device_channel) (ICE-CoreOS 201: empty means the verifier has no ring)"
  ev "applied state: $(snapshot_value "$snap" applied_state) bundle_seq=$(snapshot_value "$snap" applied_bundle_seq) (ICE-CoreOS 206: a media install leaves it unseeded until first boot derives it)"
  ev "ota state dir modes: $(snapshot_value "$snap" ota_state_modes)"
  snapshot_section "$snap" ota-status > "$work_dir/logs/firstboot.ota-status"
  status_facts="$(ni_e2e_parse_ota_status "$work_dir/logs/firstboot.ota-status")"
  ev "authenticated-ota-status: $(printf '%s' "$status_facts" | tr '\n' ' ')"
  if grep -q '^ota_status=unparseable' <<<"$status_facts"; then
    head -c 300 "$work_dir/logs/firstboot.ota-status" | tr -d '\r' | while IFS= read -r line; do ev "ota-status: $line"; done
  fi
  if [[ -f "$(vm_console)" ]]; then
    ev "status screen: $(ni_bench_parse_firstboot_log "$(vm_console)" | grep -E '^firstboot_(ready|status_failure|device_trust|core_services)=' | tr '\n' ' ')"
  fi
  save_fact firstboot hostname "$(snapshot_value "$snap" hostname)"
  save_fact firstboot version "$(snapshot_value "$snap" version)"
  save_fact firstboot applied_state "$(snapshot_value "$snap" applied_state)"
  save_fact firstboot applied_bundle_seq "$(snapshot_value "$snap" applied_bundle_seq)"
  save_fact firstboot device_channel "$(snapshot_value "$snap" device_channel)"
  [[ -z "$failed" ]] || rc=1
  (( rc == 0 )) || fail_phase "failed units outside the allow-list: $failed"
  [[ "$(snapshot_value "$snap" pairing_code)" == published ]] \
    || fail_phase "no pairing code published at $NI_E2E_PAIRING_CODE (icecore-api arms it at boot; onboarding is impossible without it)"
  grep -q '^ota_status=parsed' <<<"$status_facts" \
    || fail_phase "ni-ota-verify authenticated-ota-status did not answer (see $work_dir/logs/firstboot.ota-status)"
  if ! { grep -q '^committed_generation=null' <<<"$status_facts" && grep -q '^enforce_ready_verified=false' <<<"$status_facts"; }; then
    ev "note: the status is not the pristine {committed_generation:null, enforce_ready_verified:false} contract"
  fi
  end_phase
}

# --------------------------------------------------------------------------- #
# Phase 4 — onboarding: pairing code + licence key -> POST /api/v1/license/enroll.
# The request shape is ICE-AC1's EnrollLicenseRequest (icecore-api
# src/api/license/contracts.rs): license_key, csr, user_email, user_name,
# console_code. The CSR's private key is generated here and stays here: the
# appliance only forwards the CSR to its issuer, exactly like the thin client.
# --------------------------------------------------------------------------- #
phase_onboard() {
  begin_phase onboard
  [[ -n "$license_key_file" ]] \
    || fail_phase "pass --license-key-file FILE (0600, one line): the licence key is an operator secret this rehearsal never invents; create the lab licence through the customer portal"
  [[ -n "$operator_email" ]] || fail_phase "pass --operator-email ADDR: the first admin user the enrolment creates"
  vm_ensure onboard
  local dir=$work_dir/onboard device_key=$work_dir/onboard/operator.key csr=$work_dir/onboard/operator.csr
  local body=$work_dir/onboard/request.json response=$work_dir/onboard/response.json
  rm -f -- "$body"
  if [[ ! -f "$device_key" ]]; then
    openssl ecparam -name prime256v1 -genkey -noout -out "$device_key" 2>/dev/null || fail_phase "openssl could not generate the operator device key"
    chmod 0600 -- "$device_key"
  fi
  openssl req -new -key "$device_key" -subj "/CN=bench-rehearsal-operator/O=Neural ICE bench" -out "$csr" 2>/dev/null \
    || fail_phase "openssl could not build the CSR"
  ev "operator device: EC P-256 key at $device_key (never leaves the bench), CSR $csr"
  local snap=$dir/before.snapshot
  appliance_snapshot "$snap"
  [[ "$(snapshot_value "$snap" pairing_code)" == published ]] \
    || fail_phase "no pairing code published at $NI_E2E_PAIRING_CODE; enrolment needs the physical-presence proof"
  ev "before: containers=$(snapshot_value "$snap" containers) licensed_target=$(snapshot_value "$snap" licensed_target) enrolled_marker=$(snapshot_value "$snap" enrolled_marker)"
  # The pairing code and the licence key exist in memory of this python process
  # and in the 0600 body file for the seconds the request takes: never in argv,
  # never in the evidence, never in a log.
  local code
  code="$(vm_ssh_root "cat $NI_E2E_PAIRING_CODE" </dev/null 2>/dev/null | tr -d '[:space:]')"
  [[ "$code" =~ ^[A-Za-z0-9-]{4,32}$ ]] || fail_phase "the published pairing code is not in the shape icecore-api publishes"
  NI_E2E_KEY_FILE="$license_key_file" NI_E2E_CSR="$csr" NI_E2E_EMAIL="$operator_email" \
  NI_E2E_NAME="$operator_name" NI_E2E_CODE="$code" NI_E2E_BODY="$body" python3 - <<'PY'
import json
import os

with open(os.environ["NI_E2E_KEY_FILE"], "r", encoding="utf-8") as handle:
    key = handle.readline().strip()
if not key or any(ch.isspace() for ch in key):
    raise SystemExit("the licence key file must hold exactly one non-empty line")
with open(os.environ["NI_E2E_CSR"], "r", encoding="utf-8") as handle:
    csr = handle.read()
body = {
    "license_key": key,
    "csr": csr,
    "user_email": os.environ["NI_E2E_EMAIL"],
    "user_name": os.environ["NI_E2E_NAME"],
    "console_code": os.environ["NI_E2E_CODE"],
}
fd = os.open(os.environ["NI_E2E_BODY"], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as handle:
    json.dump(body, handle)
PY
  code=
  # Sent from INSIDE the appliance so the edge is reached the way a client
  # reaches it: TLS to the appliance's own hostname (the SNI Caddy serves),
  # trusting the appliance's PKI root. The response is read back verbatim.
  local rc=0 outcome http time_total
  # shellcheck disable=SC2016 # runs on the appliance; $1 is ITS positional parameter
  vm_ssh_root '
set -u; umask 077
root_crt=$1
d=$(mktemp -d /run/ni-e2e-enrol.XXXXXX) || exit 90
trap "rm -rf -- \"$d\"" EXIT
cat > "$d/body.json"
[ -r "$root_crt" ] || { echo "OUTCOME no-edge-root-crt"; exit 91; }
host=$(hostname)
w=$(curl -sS --max-time 120 -o "$d/resp.json" -w "%{http_code} %{time_total}" \
      -X POST -H "content-type: application/json" --data-binary @"$d/body.json" \
      --cacert "$root_crt" --resolve "$host:443:127.0.0.1" \
      "https://$host/api/v1/license/enroll" 2>"$d/curl.err") || { echo "OUTCOME curl-failed $(tr -d "\n" < "$d/curl.err" | cut -c1-200)"; exit 92; }
echo "OUTCOME http $w"
echo "---RESPONSE---"
cat "$d/resp.json"
' "$NI_E2E_EDGE_ROOT_CRT" < "$body" > "$dir/enrol.out" 2>"$dir/enrol.err" || rc=$?
  rm -f -- "$body"
  outcome="$(grep -m1 '^OUTCOME ' "$dir/enrol.out" || true)"
  sed -n '/^---RESPONSE---$/,$p' "$dir/enrol.out" | sed '1d' > "$response"
  chmod 0600 -- "$response" "$dir/enrol.out" "$dir/enrol.err"
  [[ "$outcome" == "OUTCOME http "* ]] || fail_phase "the enrolment request never got an HTTP answer (${outcome:-ssh rc=$rc}; $dir/enrol.err)"
  http="$(awk '{print $3}' <<<"$outcome")"; time_total="$(awk '{print $4}' <<<"$outcome")"
  ev "enrol: HTTP $http in ${time_total}s (budget ${enrol_budget}s)"
  local facts; facts="$(ni_e2e_parse_enrol_response "$response")"
  ev "enrol: $(printf '%s' "$facts" | tr '\n' ' ')"
  [[ "$http" == 201 ]] || fail_phase "enrolment answered HTTP $http ($(sed -n 's/^enrol_detail=//p' <<<"$facts" | head -n1)); response at $response"
  local budget_ok
  budget_ok="$(awk -v t="$time_total" -v b="$enrol_budget" 'BEGIN{print (t+0 <= b+0) ? "yes" : "no"}')"
  local entitlements; entitlements="$(sed -n 's/^entitlements=//p' <<<"$facts" | head -n1)"
  save_fact onboard entitlements "$entitlements"
  save_fact onboard enrol_seconds "$time_total"
  [[ "$budget_ok" == yes ]] \
    || fail_phase "the 201 took ${time_total}s, over the ${enrol_budget}s budget (on 0.61.0 the handler blocks on restart_license_check/enable_ai_stack: no host controller, NEURALICE_APPLIANCE_CONTROL_TIMEOUT_SECS defaults to 90)"
  # The licensed plane: neural-ice-license-gate.service authenticates the OTA
  # state and starts neural-ice-licensed.target. Bounded by --licensed-wait
  # (the gate's own TimeoutStartSec is 300 s).
  local deadline=$(( SECONDS + licensed_wait )) state=inactive
  while (( SECONDS < deadline )); do
    state="$(vm_ssh_root 'systemctl is-active neural-ice-licensed.target 2>/dev/null || true' </dev/null 2>/dev/null | tr -d '[:space:]')"
    [[ "$state" == active ]] && break
    sleep 10
  done
  local after=$dir/after.snapshot
  appliance_snapshot "$after"
  ev "after: licensed_target=${state:-unknown} license_gate=$(snapshot_value "$after" license_gate) license_check=$(snapshot_value "$after" license_check) containers=$(snapshot_value "$after" containers) enrolled_marker=$(snapshot_value "$after" enrolled_marker)"
  ev "after: ota state dir modes: $(snapshot_value "$after" ota_state_modes) (ICE-CoreOS 208: a 0644 entry closes the gate)"
  snapshot_section "$after" ota-status > "$dir/after.ota-status"
  ev "after: authenticated-ota-status: $(ni_e2e_parse_ota_status "$dir/after.ota-status" | tr '\n' ' ')"
  vm_ssh_root 'journalctl -b -u neural-ice-license-gate.service --no-pager -n 12 2>/dev/null' </dev/null > "$dir/license-gate.journal" 2>&1 || true
  tail -n 3 "$dir/license-gate.journal" | cut -c1-300 | while IFS= read -r line; do ev "license-gate: $line"; done
  [[ "$state" == active ]] \
    || fail_phase "neural-ice-licensed.target is '$state' ${licensed_wait}s after a 201 enrolment (license gate: $(snapshot_value "$after" license_gate); journal at $dir/license-gate.journal)"
  end_phase
}

# --------------------------------------------------------------------------- #
# Phase 5 — OTA to the target train, reboot, durable transaction to `completed`.
# --------------------------------------------------------------------------- #
phase_ota() {
  begin_phase ota
  [[ -n "$target_train" ]] || fail_phase "pass --target-train TRAIN: the train the ring must name and the OTA must reach"
  vm_ensure ota
  local dir=$work_dir/ota snap=$work_dir/ota/before.snapshot entitlements ring_used previous_seq
  appliance_snapshot "$snap"
  ring_used=$ring
  [[ -n "$ring_used" ]] || ring_used="$(snapshot_value "$snap" device_channel)"
  [[ "$ring_used" =~ ^(lab|beta|stable)$ ]] \
    || fail_phase "no ring: --ring not given and ota.conf carries no device_channel= (ICE-CoreOS 201)"
  if [[ -n "$entitlements_file" ]]; then
    entitlements="$(LC_ALL=C sort -u -- "$entitlements_file" | grep -E '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$' | paste -sd, -)"
  else
    entitlements="$(fact onboard entitlements)"
  fi
  [[ -n "$entitlements" && "$entitlements" != none ]] \
    || fail_phase "no entitlement codes: the enrolment left none and --entitlements-file was not given (the controller requires ICE-CORE among them)"
  ev "target: train=$target_train ring=$ring_used entitlements=$entitlements current_version=$(snapshot_value "$snap" version)"
  ev "before: applied_state=$(snapshot_value "$snap" applied_state) bundle_seq=$(snapshot_value "$snap" applied_bundle_seq) licensed_target=$(snapshot_value "$snap" licensed_target) containers=$(snapshot_value "$snap" containers)"
  [[ "$(snapshot_value "$snap" enrolled_marker)" == present ]] \
    || fail_phase "the appliance is not enrolled (no enrolled marker): the OTA identity is fingerprint:licence from license.conf"
  # ICE-CoreOS 206: a media install leaves the v1 gate unseeded. Seeding is an
  # Owner ceremony (a cosign signature of the sealed preseal BOM by the OTA
  # root key). With --bom-sig-file the verified bootstrap verb seeds it; the
  # BOM and its receipt are located by content, never by a guessed path.
  if [[ "$(snapshot_value "$snap" applied_state)" == unseeded ]]; then
    [[ -n "$bom_sig_file" ]] \
      || fail_phase "the OTA gate is unseeded (no $NI_E2E_APPLIED_STATE; ICE-CoreOS 206): pass --bom-sig-file with the Owner's cosign signature of the sealed preseal BOM, or cut the medium from a CoreOS whose first boot derives the applied state from the preseal receipt"
    local seed_out=$dir/bootstrap.out rc=0
    # shellcheck disable=SC2016 # runs on the appliance; $1 is ITS positional parameter
    vm_ssh_root '
set -u; umask 077
ota_conf=$1
d=$(mktemp -d /run/ni-e2e-bootstrap.XXXXXX) || exit 90
trap "rm -rf -- \"$d\"" EXIT
cat > "$d/bom.sig"
receipt=$(find /var/lib/neural-ice -maxdepth 5 -type f -path "*/preseal/receipt.json" 2>/dev/null | head -n1)
[ -n "$receipt" ] || { echo "BOOTSTRAP no-preseal-receipt"; exit 91; }
want=$(jq -r ".bom_sha256 // empty" "$receipt")
train=$(jq -r ".train // empty" "$receipt")
os_ref=$(jq -r ".target_os_ref // .os_ref // empty" "$receipt")
seed_ref=$(jq -r ".seed_ref // empty" "$receipt")
echo "BOOTSTRAP receipt=$receipt train=$train seed_ref=$seed_ref bom_sha256=$want"
bom=""
for c in $(find /var/lib/neural-ice /run -maxdepth 6 -type f -name bom.json 2>/dev/null); do
  [ "$(sha256sum "$c" | cut -c1-64)" = "$want" ] && { bom=$c; break; }
done
[ -n "$bom" ] || { echo "BOOTSTRAP no-bom-matching-receipt"; exit 92; }
echo "BOOTSTRAP bom=$bom"
ni-ota-verify bootstrap --bom "$bom" --bom-sig "$d/bom.sig" --expected-train "$train" \
  --current-os-ref "$os_ref" --current-seed-ref "$seed_ref" --config "$ota_conf" 2>&1 \
  && echo "BOOTSTRAP rc=0" || echo "BOOTSTRAP rc=$?"
' "$NI_E2E_OTA_CONF" < "$bom_sig_file" > "$seed_out" 2>&1 || rc=$?
    grep '^BOOTSTRAP' "$seed_out" | cut -c1-300 | while IFS= read -r line; do ev "$line"; done
    grep -q '^BOOTSTRAP rc=0' "$seed_out" || fail_phase "ni-ota-verify bootstrap did not seed the applied state (see $seed_out)"
    appliance_snapshot "$snap"
    ev "seeded: applied bundle_seq=$(snapshot_value "$snap" applied_bundle_seq) ring=$(snapshot_value "$snap" applied_ring)"
  fi
  previous_seq="$(snapshot_value "$snap" applied_bundle_seq)"
  [[ "$previous_seq" =~ ^[0-9]+$ ]] || previous_seq=0
  # The controller, exactly as the host bridge (ICE-Fabric config/bin/
  # appliance-ota-control.sh) invokes it: OTA_AUTH_FILE = fingerprint:licence
  # from license.conf, OTA_ENTITLEMENTS_FILE = the sorted codes, --bundle
  # TRAIN --channel RING. Both files live in a private /run directory of the
  # appliance for the controller's lifetime; no value leaves the appliance.
  # ICE-Fabric 664: bootc reads its pull secret from /run/ostree/auth.json
  # only; a controller predating that fix is given the same bytes there for
  # the run, and the fact is recorded.
  local controller_log=$dir/controller.log rc=0 started_at
  started_at=$SECONDS
  ev "controller: $NI_E2E_OTA_CONTROLLER --bundle $target_train --channel $ring_used (budget ${ota_budget}s, log $controller_log)"
  # shellcheck disable=SC2016 # runs on the appliance; $1..$7 are ITS positional parameters
  vm_ssh_root '
set -u; umask 077
controller=$1 license_conf=$2 ota_conf=$3 entitlements=$4 budget=$5 train=$6 ring=$7
d=$(mktemp -d /run/ni-e2e-ota.XXXXXX) || exit 90
staged=0
cleanup() { [ "$staged" = 1 ] && rm -f /run/ostree/auth.json; rm -rf -- "$d"; }
trap cleanup EXIT
[ -x "$controller" ] || { echo "CONTROLLER absent"; exit 91; }
fp=$(sed -n "s/^KEYGEN_MACHINE_FINGERPRINT=//p" "$license_conf" | tail -n1)
lic=$(sed -n "s/^KEYGEN_LICENSE_KEY=//p" "$license_conf" | tail -n1)
case "$fp" in *[!0-9a-f]*|"") echo "CONTROLLER no-fingerprint-in-license.conf"; exit 92;; esac
[ -n "$lic" ] || { echo "CONTROLLER no-licence-in-license.conf"; exit 93; }
printf "%s:%s\n" "$fp" "$lic" > "$d/auth"
printf "%s\n" "$entitlements" | tr "," "\n" | LC_ALL=C sort -u > "$d/entitlements"
if ! grep -q "stage_ostree_pull_secret" "$controller"; then
  if [ -e /run/ostree/auth.json ]; then echo "CONTROLLER foreign-/run/ostree/auth.json"; exit 94; fi
  mkdir -p -m 0700 /run/ostree
  printf "{\"auths\":{\"%s\":{\"auth\":\"%s\"}}}\n" "$(sed -n "s/^registry=//p" "$ota_conf" | tail -n1)" "$(printf "%s:%s" "$fp" "$lic" | base64 -w0)" > "$d/ostree-auth.json"
  install -m 0600 "$d/ostree-auth.json" /run/ostree/auth.json && staged=1
  echo "CONTROLLER ostree-pull-secret=staged-by-harness (controller predates ICE-Fabric 664)"
else
  echo "CONTROLLER ostree-pull-secret=controller-stages-it"
fi
echo "CONTROLLER start $(date -u +%FT%TZ)"
OTA_AUTH_FILE="$d/auth" OTA_ENTITLEMENTS_FILE="$d/entitlements" OTA_REQUIRE_ENFORCE=1 \
  timeout "$budget" "$controller" --bundle "$train" --channel "$ring" 2>&1
echo "CONTROLLER rc=$? $(date -u +%FT%TZ)"
' "$NI_E2E_OTA_CONTROLLER" "$NI_E2E_LICENSE_CONF" "$NI_E2E_OTA_CONF" "$entitlements" "$ota_budget" "$target_train" "$ring_used" \
    </dev/null > "$controller_log" 2>&1 || rc=$?
  chmod 0600 -- "$controller_log"
  ev "controller: finished in $(( SECONDS - started_at ))s (ssh rc=$rc)"
  grep -E '^CONTROLLER|^>> \[bundle|^OK|^!!|^FAIL|REFUSED' "$controller_log" | cut -c1-300 | tail -n 12 \
    | while IFS= read -r line; do ev "$line"; done
  grep -q '^CONTROLLER rc=0' "$controller_log" \
    || fail_phase "the OTA controller did not stage the train ($(grep -E '^!!|^CONTROLLER rc=|^CONTROLLER [a-z-]+$' "$controller_log" | tail -n1 | cut -c1-200); $controller_log)"
  local tx=$dir/tx.before-reboot.json tx_facts
  vm_ssh_root "cat $NI_E2E_TX_STATE" </dev/null > "$tx" 2>/dev/null || true
  tx_facts="$(ni_e2e_parse_tx_state "$tx")"
  ev "transaction before reboot: $(printf '%s' "$tx_facts" | tr '\n' ' ')"
  grep -q '^tx_phase=pending_reboot' <<<"$tx_facts" \
    || fail_phase "the durable transaction is not pending_reboot after staging ($(grep '^tx_phase=' <<<"$tx_facts"))"
  # Reboot: the guest ends the QEMU process (-no-reboot); the next boot is a
  # fresh process on the same disk and TPM state.
  ev "reboot: requested $(now)"
  vm_ssh_root 'systemctl reboot' </dev/null >/dev/null 2>&1 || true
  vm_wait_exit 300 || fail_phase "the appliance did not go down for its reboot within 300s"
  local boot=ota-boot1 boots=1 deadline=$(( started_at + ota_budget )) phase=none last_phase=none
  vm_boot "$boot"
  local wrc=0
  vm_wait_ssh $(( deadline - SECONDS > 60 ? deadline - SECONDS : 60 )) || wrc=$?
  (( wrc == 0 )) || fail_phase "after the OTA reboot the appliance did not answer on TCP/22 (code $wrc; console $(vm_console))"
  ev "reboot: ssh back $(now) on boot $boot"
  # Poll the durable transaction until a terminal phase. A rollback reboots
  # the appliance again (bootc rollback --apply): the loop re-boots the VM and
  # keeps reading, so the terminal phase on the previous deployment is seen.
  while (( SECONDS < deadline )); do
    if ! vm_alive; then
      (( boots < 4 )) || fail_phase "the appliance rebooted more than 3 times during the transaction"
      vm_wait_exit 5 || true
      boots=$(( boots + 1 )); boot=ota-boot$boots
      ev "reboot: the appliance went down on its own; booting $boot $(now)"
      vm_boot "$boot"
      wrc=0; vm_wait_ssh $(( deadline - SECONDS > 60 ? deadline - SECONDS : 60 )) || wrc=$?
      (( wrc == 0 )) || fail_phase "boot $boot never answered on TCP/22 (code $wrc; console $(vm_console))"
      ev "reboot: ssh back $(now) on boot $boot"
    fi
    if vm_ssh_root "cat $NI_E2E_TX_STATE" </dev/null > "$dir/tx.json" 2>/dev/null; then
      phase="$(ni_e2e_parse_tx_state "$dir/tx.json" | sed -n 's/^tx_phase=//p')"
    else
      phase=unreadable
    fi
    if [[ "$phase" != "$last_phase" ]]; then
      ev "t+$(( SECONDS - started_at ))s transaction phase=$phase"
      last_phase=$phase
    fi
    case "$phase" in
      completed|rolled_back|aborted|recovery_required) break ;;
    esac
    sleep 20
  done
  local after=$dir/after.snapshot
  appliance_snapshot "$after"
  ev "after: version=$(snapshot_value "$after" version) booted=$(snapshot_value "$after" booted_digest | cut -c1-19) applied_state=$(snapshot_value "$after" applied_state) bundle_seq=$(snapshot_value "$after" applied_bundle_seq) licensed_target=$(snapshot_value "$after" licensed_target) containers=$(snapshot_value "$after" containers)"
  ev "after: vllm_inference=$(snapshot_value "$after" vllm_inference) icecore_api=$(snapshot_value "$after" icecore_api) warmup_ready_lines=$(snapshot_value "$after" warmup_ready)"
  if [[ "$phase" != completed ]]; then
    # The dump: the transaction, the health manifest it probed, the failing
    # unit journals, the failed units and the state directory's modes.
    local dump=$dir/dump; install -d -m 0700 -- "$dump"
    cp -f -- "$dir/tx.json" "$dump/state.json" 2>/dev/null || true
    vm_ssh_root "cat $NI_E2E_HEALTH_MANIFEST 2>/dev/null" </dev/null > "$dump/TARGET_HEALTH.json" 2>&1 || true
    vm_ssh_root 'journalctl -b -u neural-ice-ota-activate.service -u neural-ice-ota-finalize.service -u neural-ice-license-gate.service -u license-check.service -u neural-ice-model-fetch.service --no-pager -n 600 2>/dev/null' </dev/null > "$dump/journals.txt" 2>&1 || true
    vm_ssh_root 'systemctl --failed --no-legend --plain; echo ---; ls -l /var/lib/neural-ice/ota /var/lib/neural-ice/ota/transaction 2>/dev/null; echo ---; bootc status 2>/dev/null' </dev/null > "$dump/units-and-state.txt" 2>&1 || true
    chmod 0600 -- "$dump"/* 2>/dev/null || true
    ev "dump: $dump (state.json, TARGET_HEALTH.json, journals.txt, units-and-state.txt)"
    grep -E 'health|rollback|REFUSED|refused|unavailable|failed' "$dump/journals.txt" | tail -n 6 | cut -c1-300 \
      | while IFS= read -r line; do ev "journal: $line"; done
    fail_phase "the transaction ended in phase '$phase' ($(ni_e2e_parse_tx_state "$dir/tx.json" | sed -n 's/^tx_failure_reason=//p' | head -n1)) instead of completed within ${ota_budget}s"
  fi
  local new_seq; new_seq="$(snapshot_value "$after" applied_bundle_seq)"
  [[ "$new_seq" =~ ^[0-9]+$ && "$new_seq" -gt "$previous_seq" ]] \
    || fail_phase "applied.json did not advance (bundle_seq before=$previous_seq after=$new_seq)"
  [[ "$(snapshot_value "$after" version)" == "$target_train" ]] \
    || fail_phase "/etc/neural-ice/version is '$(snapshot_value "$after" version)', not the target train $target_train"
  snapshot_section "$after" failed > "$dir/after.failed"
  local failed; failed="$(ni_e2e_failed_units "$dir/after.failed" "" | tr '\n' ' ')"
  [[ -z "$failed" ]] || fail_phase "failed units after the OTA: $failed"
  [[ "$(snapshot_value "$after" licensed_target)" == active ]] \
    || fail_phase "neural-ice-licensed.target is not active after the OTA"
  if (( require_inference )); then
    [[ "$(snapshot_value "$after" vllm_inference)" == active && "$(snapshot_value "$after" warmup_ready)" -ge 1 ]] \
      || fail_phase "vllm-inference is '$(snapshot_value "$after" vllm_inference)' and icecore-api logged $(snapshot_value "$after" warmup_ready) warm-up READY line(s)"
  else
    ev "inference: not asserted (--require-inference off; QEMU virt carries no GB10 GPU) — recorded above"
  fi
  save_fact ota applied_bundle_seq "$new_seq"
  end_phase
}

# --------------------------------------------------------------------------- #
# Run.
# --------------------------------------------------------------------------- #
say "work dir $work_dir; phases from $skip_to; receipt $receipt"
for i in "${!NI_E2E_PHASES[@]}"; do
  name=${NI_E2E_PHASES[$i]}
  if (( i < skip_index )); then skip_phase "$name"; continue; fi
  (( i <= stop_index )) || break
  "phase_$name"
done
if (( vm_keep == 0 )) && vm_alive; then vm_stop; fi
say "receipt: $receipt"
say "REHEARSAL COMPLETE (phases ${NI_E2E_PHASES[$skip_index]}..${NI_E2E_PHASES[$stop_index]})"
