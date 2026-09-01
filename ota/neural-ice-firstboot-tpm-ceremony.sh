#!/usr/bin/env bash
# Mandatory first-boot TPM lifecycle.  The only persistent completion marker is
# the write-locked TPM NV record created by neural-ice-tpm-state; the JSON below
# is evidence whose exact digest that record authenticates, never a selector.
set -euo pipefail
umask 077

die() { printf 'neural-ice-firstboot-tpm-ceremony: refused: %s\n' "$*" >&2; exit 1; }

if [[ -n "${NI_FIRSTBOOT_TPM_TESTING:-}" ]]; then
  [[ "$NI_FIRSTBOOT_TPM_TESTING" == 1 && "$EUID" -ne 0 ]] \
    || die "test overrides are forbidden in a privileged process"
  readonly STATE_DIR="${NI_FIRSTBOOT_TPM_TEST_STATE_DIR:?}"
  readonly TPM_STATE="${NI_FIRSTBOOT_TPM_TEST_STATE:?}"
  readonly DEVICE_ROOT_TOOL="${NI_FIRSTBOOT_TPM_TEST_DEVICE_ROOT:?}"
  readonly PROFILE_ANCHOR="${NI_FIRSTBOOT_TPM_TEST_PROFILE_ANCHOR:?}"
  readonly SYSTEM_LUKS="${NI_FIRSTBOOT_TPM_TEST_SYSTEM_LUKS:?}"
  readonly DATA_LUKS="${NI_FIRSTBOOT_TPM_TEST_DATA_LUKS:?}"
  readonly ACCESS_POLICY="${NI_FIRSTBOOT_TPM_TEST_ACCESS_POLICY:?}"
  readonly HARDWARE_TARGET_PATH="${NI_FIRSTBOOT_TPM_TEST_HARDWARE_TARGET:?}"
  readonly TRUST_POLICY_PATH="${NI_FIRSTBOOT_TPM_TEST_TRUST_POLICY:?}"
  readonly SYSTEMD_ANALYZE="${NI_FIRSTBOOT_TPM_TEST_SYSTEMD_ANALYZE:?}"
  readonly CRYPTSETUP="${NI_FIRSTBOOT_TPM_TEST_CRYPTSETUP:?}"
  readonly TPM2_READPUBLIC="${NI_FIRSTBOOT_TPM_TEST_TPM2_READPUBLIC:-/usr/bin/tpm2_readpublic}"
  readonly LUKS_EVIDENCE="${NI_FIRSTBOOT_TPM_TEST_LUKS_EVIDENCE:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/neural-ice-luks-token-evidence.py}"
  readonly RUN_ROOT="${NI_FIRSTBOOT_TPM_TEST_RUN_ROOT:?}"
  readonly REQUIRED_OWNER_UID="$EUID"
  readonly VALIDATE_FILE_METADATA="${NI_FIRSTBOOT_TPM_TEST_VALIDATE_FILE_METADATA:-0}"
  [[ "$VALIDATE_FILE_METADATA" == 0 || "$VALIDATE_FILE_METADATA" == 1 ]] \
    || die "test metadata validation selector must be 0 or 1"
else
  [[ "$EUID" -eq 0 ]] || die "must run as root"
  readonly STATE_DIR=/var/lib/neural-ice/ota
  readonly TPM_STATE=/usr/libexec/neural-ice-tpm-state
  readonly DEVICE_ROOT_TOOL=/usr/libexec/neural-ice-device-root
  readonly PROFILE_ANCHOR=/usr/libexec/neural-ice-access-profile-anchor
  readonly SYSTEM_LUKS=/dev/disk/by-partlabel/system-luks
  readonly DATA_LUKS=/dev/disk/by-partlabel/data-luks
  readonly ACCESS_POLICY=/usr/lib/neural-ice/access-policy
  readonly HARDWARE_TARGET_PATH=/usr/lib/neural-ice/hardware-target
  readonly TRUST_POLICY_PATH=/usr/lib/neural-ice/signed-boot-trust-policy-id
  readonly SYSTEMD_ANALYZE=/usr/bin/systemd-analyze
  readonly CRYPTSETUP=/usr/sbin/cryptsetup
  readonly TPM2_READPUBLIC=/usr/bin/tpm2_readpublic
  readonly LUKS_EVIDENCE=/usr/libexec/neural-ice-luks-token-evidence
  readonly RUN_ROOT=/run/neural-ice-owner-ceremony
  readonly REQUIRED_OWNER_UID=0
  readonly VALIDATE_FILE_METADATA=1
fi

readonly INTENT="$STATE_DIR/owner-ceremony-intent-v1"
readonly INSTALL_IDENTITY="$STATE_DIR/owner-ceremony-install-identity-v1.json"
readonly DEVICE_ROOT="$STATE_DIR/device-root-v1.json"
readonly SRK_PUBLIC="$STATE_DIR/srk-v1.tpm2b_public"
readonly EVIDENCE="$STATE_DIR/owner-ceremony-evidence-v1.json"

for executable in "$TPM_STATE" "$DEVICE_ROOT_TOOL" "$PROFILE_ANCHOR" \
  "$SYSTEMD_ANALYZE" "$CRYPTSETUP" "$TPM2_READPUBLIC" "$LUKS_EVIDENCE"; do
  [[ -x "$executable" ]] || die "required immutable helper is unavailable: $executable"
done

secure_file() {
  [[ -f "$1" && ! -L "$1" ]] || die "required mutable evidence is not a regular file: $1"
  if [[ "$VALIDATE_FILE_METADATA" == 1 ]]; then
    [[ "$(stat -c '%u' -- "$1")" == "$REQUIRED_OWNER_UID" ]] \
      || die "required mutable evidence has the wrong owner: $1"
    [[ "$(stat -c '%a' -- "$1")" == 600 ]] \
      || die "required mutable evidence is not mode 0600: $1"
  fi
}

immutable_marker() {
  [[ -f "$1" && ! -L "$1" ]] || die "required immutable marker is not a regular file: $1"
  if [[ "$VALIDATE_FILE_METADATA" == 1 ]]; then
    [[ "$(stat -c '%u' -- "$1")" == "$REQUIRED_OWNER_UID" ]] \
      || die "required immutable marker has the wrong owner: $1"
    [[ "$(stat -c '%a' -- "$1")" == 444 ]] \
      || die "required immutable marker is not mode 0444: $1"
  fi
}

for required in "$INTENT" "$INSTALL_IDENTITY" "$DEVICE_ROOT" "$SRK_PUBLIC"; do
  secure_file "$required"
done
for required in "$ACCESS_POLICY" "$HARDWARE_TARGET_PATH" "$TRUST_POLICY_PATH"; do
  immutable_marker "$required"
done

install -d -m 0700 "$RUN_ROOT"
exec 9>"$RUN_ROOT/lifecycle.lock"
flock -x 9
WORK="$(mktemp -d "$RUN_ROOT/work.XXXXXX")"
trap 'rm -rf -- "$WORK"' EXIT

# Parse the closed installer intent without sourcing root-writable shell text.
eval "$(python3 - "$INTENT" <<'PY'
import re, shlex, sys
allowed={"access_profile","hardware_target","signed_boot_trust_policy_id","initial_issuance_seq"}
values={}
for line in open(sys.argv[1], encoding="ascii"):
    if line.count("=") != 1: raise SystemExit("malformed ceremony intent")
    key,value=line.rstrip("\n").split("=",1)
    if key not in allowed or key in values: raise SystemExit("closed ceremony intent violated")
    values[key]=value
if set(values) != allowed: raise SystemExit("incomplete ceremony intent")
for key,value in values.items():
    if not re.fullmatch(r"[A-Za-z0-9_.:+-]{1,128}", value): raise SystemExit("invalid ceremony intent value")
    print(key.upper()+"="+shlex.quote(value))
PY
)" || die "the installer ceremony intent is malformed"

[[ "$(<"$ACCESS_POLICY")" == "$ACCESS_PROFILE" ]] || die "immutable access profile differs from installer intent"
[[ "$(<"$HARDWARE_TARGET_PATH")" == "$HARDWARE_TARGET" ]] || die "immutable hardware target differs from installer intent"
[[ "$(<"$TRUST_POLICY_PATH")" == "$SIGNED_BOOT_TRUST_POLICY_ID" ]] || die "immutable trust policy differs from installer intent"

"$DEVICE_ROOT_TOOL" attest --identity "$DEVICE_ROOT" >/dev/null \
  || die "persistent device root does not match installer evidence"
"$SYSTEMD_ANALYZE" srk > "$WORK/live-srk.tpm2b_public" \
  || die "cannot read the intended persistent SRK"
cmp -s "$WORK/live-srk.tpm2b_public" "$SRK_PUBLIC" \
  || die "persistent SRK does not match installer intent"

for item in "system:$SYSTEM_LUKS" "data:$DATA_LUKS"; do
  label="${item%%:*}"; device="${item#*:}"
  "$CRYPTSETUP" luksDump --dump-json-metadata "$device" > "$WORK/$label-luks.json" 2>/dev/null \
    || die "cannot read $label LUKS2 metadata"
  "$LUKS_EVIDENCE" "$WORK/$label-luks.json" "$SRK_PUBLIC" > "$WORK/$label-luks-evidence.json" \
    || die "$label LUKS2 token does not match the closed TPM contract"
done

"$TPM2_READPUBLIC" -Q -c 0x81000001 -n "$WORK/srk.name" >/dev/null \
  || die "cannot read the persistent SRK Name"
"$TPM2_READPUBLIC" -Q -c 0x81010005 -n "$WORK/device-root.name" >/dev/null \
  || die "cannot read the persistent device-root Name"

build_evidence() { # $1=TPM state snapshot
  python3 - "$1" "$INSTALL_IDENTITY" "$WORK/system-luks-evidence.json" \
    "$WORK/data-luks-evidence.json" "$WORK/srk.name" "$WORK/device-root.name" \
    "$STATE_DIR/access-profile-v1.json" "$STATE_DIR/access-profile-v1.sig" \
    "$STATE_DIR/access-profile-v1.spki" <<'PY'
import hashlib,json,re,sys
def pairs(items):
    out={}
    for k,v in items:
        if k in out: raise ValueError("duplicate JSON key")
        out[k]=v
    return out
def load(path):
    with open(path,encoding="utf-8") as f: return json.load(f,object_pairs_hook=pairs)
snapshot=json.loads(sys.argv[1],object_pairs_hook=pairs)
identity=load(sys.argv[2]); system=load(sys.argv[3]); data=load(sys.argv[4])
identity_keys={"install_source","installed_at","installer_sealed_identity_sha256","release_identity_sha256","schema"}
if set(identity) != identity_keys: raise SystemExit("installer identity is not a closed document")
if identity.get("schema") != "neural-ice-owner-ceremony-install-identity-v1": raise SystemExit("wrong installer identity schema")
if identity["install_source"] not in ("medium","registry"): raise SystemExit("wrong install source")
if not re.fullmatch(r"[0-9a-f]{64}",identity["installer_sealed_identity_sha256"]): raise SystemExit("bad sealed identity digest")
if not re.fullmatch(r"[0-9a-f]{64}",identity["release_identity_sha256"]): raise SystemExit("bad release identity digest")
if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",identity["installed_at"]): raise SystemExit("bad install timestamp")
canonical=(json.dumps(identity,sort_keys=True,separators=(",",":"))+"\n").encode()
if open(sys.argv[2],"rb").read() != canonical: raise SystemExit("installer identity is not canonical")
if snapshot.get("schema") != "neural-ice-tpm-state-snapshot-v1": raise SystemExit("wrong TPM snapshot schema")
def digest(path): return hashlib.sha256(open(path,"rb").read()).hexdigest()
obj={"access_profile_anchor":{"json_sha256":digest(sys.argv[7]),"signature_sha256":digest(sys.argv[8]),"spki_sha256":digest(sys.argv[9])},
 "data_luks":data,"device_root_name":open(sys.argv[6],"rb").read().hex(),
 "install_identity":identity,"schema":"neural-ice-owner-ceremony-evidence-v1",
 "srk_name":open(sys.argv[5],"rb").read().hex(),"system_luks":system,"tpm_state":snapshot}
print(json.dumps(obj,sort_keys=True,separators=(",",":")))
PY
}

validate_complete() {
  secure_file "$EVIDENCE"
  evidence_digest="$(sha256sum "$EVIDENCE" | awk '{print tolower($1)}')"
  read -r install_at freshness_at < <(python3 - "$EVIDENCE" <<'PY'
import json,sys
d=json.load(open(sys.argv[1])); s=d["tpm_state"]
print(s["install_counter"],s["freshness_counter"])
PY
)
  snapshot="$(python3 - "$EVIDENCE" <<'PY'
import json,sys
d=json.load(open(sys.argv[1])); print(json.dumps(d["tpm_state"],sort_keys=True,separators=(",",":")))
PY
)"
  rebuilt="$(build_evidence "$snapshot")" || die "cannot reconstruct canonical completion evidence"
  [[ "$rebuilt"$'\n' == "$(cat "$EVIDENCE")"$'\n' ]] \
    || die "mutable lifecycle evidence no longer matches its authenticated canonical inputs"
  "$PROFILE_ANCHOR" verify "$DEVICE_ROOT" "$STATE_DIR" >/dev/null \
    || die "authenticated access-profile anchor does not verify"
  "$TPM_STATE" runtime-status "$ACCESS_PROFILE" "$HARDWARE_TARGET" \
    "$SIGNED_BOOT_TRUST_POLICY_ID" "$evidence_digest" "$install_at" "$freshness_at" >/dev/null
  printf 'complete\n'
}

mode="${1:-boot}"
[[ "$mode" == boot || "$mode" == status ]] || die "usage: ${0##*/} [status]"
if "$TPM_STATE" completion-status >/dev/null 2>&1; then
  validate_complete
  exit 0
fi
[[ "$mode" == boot ]] || die "authenticated TPM completion evidence is absent"

# Only an exactly virgin TPM may enter the one-time mutation path.  In
# particular ownerAuthSet=1, or any single surviving index, refuses here.
"$TPM_STATE" provisioning-status >/dev/null \
  || die "TPM is neither authenticated-complete nor virgin; signed physical recovery is required"
read -r anchor_seq freshness_at binding < <(
  "$TPM_STATE" ceremony-prepare "$ACCESS_PROFILE" "$HARDWARE_TARGET" \
    "$SIGNED_BOOT_TRUST_POLICY_ID" "$INITIAL_ISSUANCE_SEQ"
)
[[ "$anchor_seq" =~ ^[1-9][0-9]*$ && "$freshness_at" =~ ^[1-9][0-9]*$ && "$binding" =~ ^[0-9a-f]{64}$ ]] \
  || die "TPM ceremony preparation returned malformed evidence"

enrolled_at="$(python3 - "$INSTALL_IDENTITY" <<'PY'
import json,sys
d=json.load(open(sys.argv[1])); print(d["installed_at"])
PY
)"
"$PROFILE_ANCHOR" enroll "$DEVICE_ROOT" "$STATE_DIR" "$ACCESS_PROFILE" \
  "$HARDWARE_TARGET" "$SIGNED_BOOT_TRUST_POLICY_ID" "$anchor_seq" "$enrolled_at" >/dev/null \
  || die "cannot enroll the one-time access-profile anchor"
"$PROFILE_ANCHOR" verify "$DEVICE_ROOT" "$STATE_DIR" >/dev/null \
  || die "new access-profile anchor does not verify"

snapshot="$($TPM_STATE state-snapshot "$ACCESS_PROFILE" "$HARDWARE_TARGET" "$SIGNED_BOOT_TRUST_POLICY_ID")"
build_evidence "$snapshot" > "$WORK/evidence.json" \
  || die "cannot construct canonical lifecycle evidence"
[[ ! -e "$EVIDENCE" && ! -L "$EVIDENCE" ]] || die "lifecycle evidence existed before the trusted ceremony"
install -m 0600 "$WORK/evidence.json" "$EVIDENCE"
sync -f "$EVIDENCE"; sync -f "$STATE_DIR"
evidence_digest="$(sha256sum "$EVIDENCE" | awk '{print tolower($1)}')"
"$TPM_STATE" ceremony-finalize "$ACCESS_PROFILE" "$HARDWARE_TARGET" \
  "$SIGNED_BOOT_TRUST_POLICY_ID" "$evidence_digest" "$anchor_seq" "$freshness_at"
validate_complete
