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
  readonly OTA_STATE="${NI_FIRSTBOOT_TPM_TEST_OTA_STATE:-}"
  readonly OTA_VERIFY="${NI_FIRSTBOOT_TPM_TEST_OTA_VERIFY:-}"
  readonly OTA_CONFIG="${NI_FIRSTBOOT_TPM_TEST_OTA_CONFIG:-}"
  readonly OTA_PROFILE_PATH="${NI_FIRSTBOOT_TPM_TEST_OTA_PROFILE:-}"
  readonly CANDIDATE_ROOT="${NI_FIRSTBOOT_TPM_TEST_CANDIDATE_ROOT:-}"
  readonly BOOTC="${NI_FIRSTBOOT_TPM_TEST_BOOTC:-}"
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
  readonly OTA_STATE=/usr/libexec/neural-ice-ota-tpm-state
  readonly OTA_VERIFY=/usr/bin/ni-ota-verify
  readonly OTA_CONFIG=/etc/neural-ice/ota.conf
  readonly OTA_PROFILE_PATH=/usr/lib/neural-ice/ota-state-profile
  readonly CANDIDATE_ROOT=/
  readonly BOOTC=/usr/bin/bootc
  readonly REQUIRED_OWNER_UID=0
  readonly VALIDATE_FILE_METADATA=1
fi

readonly INTENT="$STATE_DIR/owner-ceremony-intent-v1"
readonly INSTALL_IDENTITY="$STATE_DIR/owner-ceremony-install-identity-v1.json"
readonly DEVICE_ROOT="$STATE_DIR/device-root-v1.json"
readonly SRK_PUBLIC="$STATE_DIR/srk-v1.tpm2b_public"
readonly EVIDENCE_V1="$STATE_DIR/owner-ceremony-evidence-v1.json"
readonly EVIDENCE_V2="$STATE_DIR/owner-ceremony-evidence-v2.json"
readonly PRESEAL_INPUT="$STATE_DIR/preseal-input-v1"
readonly PRESEAL_RECEIPT="$STATE_DIR/preseal/receipt.json"

for executable in "$TPM_STATE" "$DEVICE_ROOT_TOOL" "$PROFILE_ANCHOR" \
  "$SYSTEMD_ANALYZE" "$CRYPTSETUP" "$TPM2_READPUBLIC" "$LUKS_EVIDENCE"; do
  [[ -x "$executable" ]] || die "required immutable helper is unavailable: $executable"
done

owner_profile_supported() {
  [[ -n "$OTA_PROFILE_PATH" && -e "$OTA_PROFILE_PATH" ]] || return 1
  immutable_marker "$OTA_PROFILE_PATH"
  [[ "$(wc -c < "$OTA_PROFILE_PATH" | tr -d '[:space:]')" == 26 \
    && "$(<"$OTA_PROFILE_PATH")" == owner-sealed-ota-state-v1 ]] \
    || die "immutable OTA state profile is unsupported"
}

secure_file() {
  [[ -f "$1" && ! -L "$1" ]] || die "required mutable evidence is not a regular file: $1"
  if [[ "$VALIDATE_FILE_METADATA" == 1 ]]; then
    [[ "$(stat -c '%u' -- "$1")" == "$REQUIRED_OWNER_UID" ]] \
      || die "required mutable evidence has the wrong owner: $1"
    [[ "$(stat -c '%a' -- "$1")" == 600 ]] \
      || die "required mutable evidence is not mode 0600: $1"
  fi
}

snapshot_completion_evidence() { # source, private destination
  python3 - "$1" "$2" "$REQUIRED_OWNER_UID" "$VALIDATE_FILE_METADATA" <<'PY'
import os,stat,sys
source,destination,required_uid,validate_metadata=sys.argv[1:]
maximum=65536
before=os.lstat(source)
if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 < before.st_size <= maximum:
    raise SystemExit("unsafe completion evidence")
if validate_metadata == "1" and (before.st_uid != int(required_uid) or stat.S_IMODE(before.st_mode) != 0o600):
    raise SystemExit("unsafe completion evidence metadata")
fd=os.open(source,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
try:
    opened=os.fstat(fd)
    chunks=[]; remaining=maximum+1
    while remaining:
        part=os.read(fd,remaining)
        if not part: break
        chunks.append(part); remaining-=len(part)
    raw=b"".join(chunks)
finally:
    os.close(fd)
after=os.lstat(source)
identity=lambda value:(value.st_dev,value.st_ino,value.st_mode,value.st_uid,value.st_gid,
                       value.st_nlink,value.st_size,value.st_mtime_ns,value.st_ctime_ns)
if (not stat.S_ISREG(opened.st_mode) or not stat.S_ISREG(after.st_mode) or
    identity(before) != identity(opened) or identity(before) != identity(after) or
    len(raw) != before.st_size or not 0 < len(raw) <= maximum):
    raise SystemExit("unstable completion evidence")
out=os.open(destination,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
try:
    view=memoryview(raw)
    while view:
        written=os.write(out,view)
        if written <= 0: raise SystemExit("cannot snapshot completion evidence")
        view=view[written:]
    os.fsync(out)
finally:
    os.close(out)
PY
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

preseal_files() {
  printf '%s\n' \
    "$PRESEAL_INPUT/preseal-set.json" \
    "$PRESEAL_INPUT/delegation-snapshot.json" \
    "$PRESEAL_INPUT/delegation-snapshot.sig" \
    "$PRESEAL_INPUT/ota-release-authorization.json" \
    "$PRESEAL_INPUT/ota-release-authorization.sig" \
    "$PRESEAL_INPUT/bom.json" \
    "$PRESEAL_INPUT/installer-release-authorization-v2.json" \
    "$PRESEAL_INPUT/installer-release-authorization-v2.sig"
}

require_preseal_inputs() {
  [[ -n "$OTA_STATE" && -x "$OTA_STATE" && -n "$OTA_VERIFY" && -x "$OTA_VERIFY" ]] \
    || die "owner-profile preseal verifier or TPM helper is unavailable"
  [[ -n "$OTA_CONFIG" ]] \
    || die "owner-profile verifier paths are incomplete"
  [[ -d "$PRESEAL_INPUT" && ! -L "$PRESEAL_INPUT" ]] || die "preseal input directory is unsafe or absent"
  if [[ "$VALIDATE_FILE_METADATA" == 1 ]]; then
    [[ "$(stat -c '%u:%a' -- "$PRESEAL_INPUT")" == "$REQUIRED_OWNER_UID:700" ]] \
      || die "preseal input directory has unsafe metadata"
  fi
  local input
  while IFS= read -r input; do secure_file "$input"; done < <(preseal_files)
  secure_file "$PRESEAL_RECEIPT"
}

preseal_metadata() {
  python3 - "$PRESEAL_INPUT/preseal-set.json" \
    "$PRESEAL_INPUT/installer-release-authorization-v2.json" "$PRESEAL_RECEIPT" <<'PY'
import hashlib,json,os,re,stat,sys
def pairs(items):
    out={}
    for key,value in items:
        if key in out: raise SystemExit("duplicate preseal field")
        out[key]=value
    return out
def load(path,maximum):
    before=os.lstat(path)
    if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= maximum: raise SystemExit("unsafe preseal input")
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        opened=os.fstat(fd); chunks=[]; remaining=maximum+1
        while remaining:
            part=os.read(fd,remaining)
            if not part: break
            chunks.append(part); remaining-=len(part)
        raw=b"".join(chunks)
    finally: os.close(fd)
    after=os.lstat(path)
    if not stat.S_ISREG(after.st_mode) or (opened.st_dev,opened.st_ino)!=(before.st_dev,before.st_ino) or (after.st_dev,after.st_ino)!=(before.st_dev,before.st_ino) or not 0 < len(raw) <= maximum: raise SystemExit("unstable preseal input")
    value=json.loads(raw,object_pairs_hook=pairs)
    return raw,value
set_raw,s=load(sys.argv[1],16384); _,installer=load(sys.argv[2],1024); receipt_raw,r=load(sys.argv[3],16384)
required=(r.get("schema")=="neural-ice-ota-preseal-receipt-v1" and
 s.get("schema")=="neural-ice-installer-preseal-set-v1" and
 r.get("preseal_set_sha256")==hashlib.sha256(set_raw).hexdigest() and
 r.get("installer_authorization_sha256")==s.get("installer_authorization_sha256") and
 r.get("bundle_seq")==s.get("bundle_seq") and isinstance(r.get("bundle_seq"),int) and
 0 < r["bundle_seq"] <= 9007199254740991)
if not required: raise SystemExit("preseal receipt does not bind the installed set")
values=[hashlib.sha256(receipt_raw).hexdigest(),r["preseal_set_sha256"],
 r["installer_authorization_sha256"],s.get("installer_authorization_signature_sha256"),
 s.get("target_os_ref"),installer.get("image_manifest_digest"),s.get("seed_ref"),str(r["bundle_seq"])]
if not all(isinstance(v,str) and v and not re.search(r"\s",v) for v in values):
    raise SystemExit("preseal metadata is malformed")
print(" ".join(values))
PY
}

verify_preseal_initial() {
  require_preseal_inputs
  [[ -n "$CANDIDATE_ROOT" && -n "$BOOTC" && -x "$BOOTC" ]] \
    || die "booted deployment inspector or candidate root is unavailable"
  local receipt_hash set_hash installer_hash installer_sig_hash signed_os signed_manifest seed floor
  local os_ref manifest bootc_status
  read -r receipt_hash set_hash installer_hash installer_sig_hash signed_os signed_manifest seed floor \
    < <(preseal_metadata) || die "cannot parse installed preseal metadata"
  bootc_status="$($BOOTC status --json)" || die "cannot inspect the booted bootc deployment"
  read -r os_ref manifest < <(python3 - "$bootc_status" <<'PY'
import json,re,sys
d=json.loads(sys.argv[1]); status=d.get("status",{}); booted=status.get("booted",{}).get("image",{})
spec=d.get("spec",{}).get("image",{}).get("image")
running=booted.get("image",{}).get("image"); digest=booted.get("imageDigest")
if spec != running or not isinstance(running,str) or re.fullmatch(r"sha256:[0-9a-f]{64}",digest or "") is None:
    raise SystemExit("bootc status does not identify one booted registry image")
print(running,digest)
PY
  ) || die "bootc status has no exact booted image identity"
  [[ "$os_ref" == "$signed_os" && "$manifest" == "$signed_manifest" ]] \
    || die "booted deployment differs from the installed preseal selection"
  "$OTA_VERIFY" verify-preseal-baseline \
    --set "$PRESEAL_INPUT/preseal-set.json" \
    --snapshot "$PRESEAL_INPUT/delegation-snapshot.json" \
    --snapshot-sig "$PRESEAL_INPUT/delegation-snapshot.sig" \
    --release "$PRESEAL_INPUT/ota-release-authorization.json" \
    --release-sig "$PRESEAL_INPUT/ota-release-authorization.sig" \
    --bom "$PRESEAL_INPUT/bom.json" \
    --installer-authorization "$PRESEAL_INPUT/installer-release-authorization-v2.json" \
    --installer-authorization-sig "$PRESEAL_INPUT/installer-release-authorization-v2.sig" \
    --sealed-set-sha256 "$set_hash" \
    --sealed-installer-authorization-sha256 "$installer_hash" \
    --sealed-installer-authorization-signature-sha256 "$installer_sig_hash" \
    --current-os-ref "$os_ref" --current-os-manifest-digest "$manifest" \
    --current-seed-ref "$seed" --candidate-root "$CANDIDATE_ROOT" \
    --receipt-out "$PRESEAL_RECEIPT" --config "$OTA_CONFIG" >/dev/null \
    || die "installed candidate does not match the authenticated preseal baseline"
  printf '%s %s %s\n' "$receipt_hash" "$set_hash" "$floor"
}

verify_preseal_retained() { # expected receipt hash, set hash
  require_preseal_inputs
  "$OTA_VERIFY" verify-retained-preseal-baseline \
    --set "$PRESEAL_INPUT/preseal-set.json" \
    --snapshot "$PRESEAL_INPUT/delegation-snapshot.json" \
    --snapshot-sig "$PRESEAL_INPUT/delegation-snapshot.sig" \
    --release "$PRESEAL_INPUT/ota-release-authorization.json" \
    --release-sig "$PRESEAL_INPUT/ota-release-authorization.sig" \
    --bom "$PRESEAL_INPUT/bom.json" \
    --installer-authorization "$PRESEAL_INPUT/installer-release-authorization-v2.json" \
    --installer-authorization-sig "$PRESEAL_INPUT/installer-release-authorization-v2.sig" \
    --expected-set-sha256 "$2" --expected-receipt-sha256 "$1" \
    --receipt "$PRESEAL_RECEIPT" --scratch-dir "$WORK" \
    --config "$OTA_CONFIG" >/dev/null \
    || die "retained preseal baseline does not match authenticated completion evidence"
}

build_evidence_v2() { # snapshot, receipt hash, set hash, floor, completion ota_state JSON
  local base; base="$(build_evidence "$1")" || return
  python3 - "$base" "$2" "$3" "$4" "$5" <<'PY'
import json,sys
base=json.loads(sys.argv[1]); inspection=json.loads(sys.argv[5])
if inspection.get("anchor_state") != "pristine" or inspection.get("anchor_sha256") is not None:
    raise SystemExit("completion anchor must be pristine")
if inspection.get("baseline_floor") != int(sys.argv[4]) or not inspection.get("clear_protected") or inspection.get("owner_sealed"):
    raise SystemExit("completion owner state is not protected at the signed floor")
base["schema"]="neural-ice-owner-ceremony-evidence-v2"
base["ota_preseal"]={"receipt_schema":"neural-ice-ota-preseal-receipt-v1","receipt_sha256":sys.argv[2],"set_sha256":sys.argv[3]}
base["ota_state"]={
 "anchor_attributes":inspection["anchor_attributes"],"anchor_index":inspection["anchor_index"],
 "anchor_name_at_completion":inspection["anchor_name"],"anchor_policy_sha256":inspection["anchor_policy_sha256"],
 "anchor_pristine_name":"000b038de2091c1c8ef2e8fd8869f17bef3a576ae287530fa17f05ae3b9712014b5d",
 "anchor_size":inspection["anchor_size"],"anchor_state_at_completion":inspection["anchor_state"],
 "anchor_written_name":"000b11afd155aca82a503f2029cc11395389654c3a25fc54b9eca6d33abdff498d56",
 "baseline_floor":inspection["baseline_floor"],"clear_protected_at_completion":inspection["clear_protected"],
 "floor_attributes":inspection["floor_attributes"],"floor_index":inspection["floor_index"],
 "floor_name":inspection["floor_name"],"floor_policy_sha256":inspection["floor_policy_sha256"],
 "floor_size":inspection["floor_size"],"profile":inspection["profile"]}
print(json.dumps(base,sort_keys=True,separators=(",",":")))
PY
}

validate_complete() {
  local validation_mode="${1:-retained}"
  [[ "$validation_mode" == initial || "$validation_mode" == retained ]] \
    || die "internal completion validation mode is invalid"
  local completion version evidence_digest evidence evidence_source install_at freshness_at snapshot rebuilt
  local receipt_hash set_hash floor owner_inspection initial_metadata
  completion="$($TPM_STATE completion-inspect)" \
    || die "authenticated TPM completion evidence is absent"
  read -r version evidence_digest < <(python3 - "$completion" <<'PY'
import json,re,sys
d=json.loads(sys.argv[1])
if set(d)!={"completion_version","evidence_digest_sha256","schema"} or d.get("schema")!="neural-ice-owner-ceremony-completion-inspection-v1" or d.get("completion_version") not in (1,2) or not re.fullmatch(r"[0-9a-f]{64}",d.get("evidence_digest_sha256","")): raise SystemExit(1)
print(d["completion_version"],d["evidence_digest_sha256"])
PY
  ) || die "authenticated TPM completion inspection is malformed"
  evidence_source="$EVIDENCE_V1"; [[ "$version" == 2 ]] && evidence_source="$EVIDENCE_V2"
  if [[ "$version" == 2 ]]; then
    owner_profile_supported \
      || die "authenticated owner-profile completion lacks immutable reader support"
  fi
  secure_file "$evidence_source"
  evidence="$WORK/completion-evidence.json"
  snapshot_completion_evidence "$evidence_source" "$evidence" \
    || die "cannot freeze stable completion evidence"
  if [[ "$version" == 1 ]]; then
    [[ "$(sha256sum "$evidence" | awk '{print tolower($1)}')" == "$evidence_digest" ]] \
      || die "v1 completion evidence differs from TPM"
  else
    [[ "$(python3 - "$evidence" <<'PY'
import hashlib,sys
print(hashlib.sha256(b"neural-ice:tpm:owner-ceremony-completion:v2\0"+open(sys.argv[1],"rb").read()).hexdigest())
PY
)" == "$evidence_digest" ]] || die "v2 completion evidence differs from TPM"
  fi
  read -r install_at freshness_at < <(python3 - "$evidence" <<'PY'
import json,sys
d=json.load(open(sys.argv[1])); s=d["tpm_state"]
print(s["install_counter"],s["freshness_counter"])
PY
)
  snapshot="$(python3 - "$evidence" <<'PY'
import json,sys
d=json.load(open(sys.argv[1])); print(json.dumps(d["tpm_state"],sort_keys=True,separators=(",",":")))
PY
)"
  if [[ "$version" == 1 ]]; then
    rebuilt="$(build_evidence "$snapshot")" || die "cannot reconstruct canonical completion evidence"
  else
    read -r receipt_hash set_hash floor owner_inspection < <(python3 - "$evidence" <<'PY'
import json,sys
d=json.load(open(sys.argv[1])); p=d["ota_preseal"]; o=d["ota_state"]
print(p["receipt_sha256"],p["set_sha256"],o["baseline_floor"],json.dumps({
 "anchor_attributes":o["anchor_attributes"],"anchor_index":o["anchor_index"],"anchor_name":o["anchor_name_at_completion"],
 "anchor_policy_sha256":o["anchor_policy_sha256"],"anchor_sha256":None,"anchor_size":o["anchor_size"],"anchor_state":o["anchor_state_at_completion"],
 "baseline_floor":o["baseline_floor"],"clear_protected":o["clear_protected_at_completion"],
 "floor_attributes":o["floor_attributes"],"floor_index":o["floor_index"],"floor_name":o["floor_name"],
 "floor_policy_sha256":o["floor_policy_sha256"],"floor_size":o["floor_size"],"owner_sealed":False,
 "profile":o["profile"],"schema":"neural-ice-owner-ota-state-inspection-v2"},sort_keys=True,separators=(",",":")))
PY
    ) || die "authenticated v2 completion evidence is malformed"
    if [[ "$validation_mode" == initial ]]; then
      initial_metadata="$(verify_preseal_initial)" \
        || die "cannot reauthenticate the installed candidate after owner finalization"
      [[ "$initial_metadata" == "$receipt_hash $set_hash $floor" ]] \
        || die "post-finalization candidate evidence differs from authenticated completion"
    else
      verify_preseal_retained "$receipt_hash" "$set_hash"
    fi
    rebuilt="$(build_evidence_v2 "$snapshot" "$receipt_hash" "$set_hash" "$floor" "$owner_inspection")" \
      || die "cannot reconstruct canonical v2 completion evidence"
  fi
  [[ "$rebuilt"$'\n' == "$(cat "$evidence")"$'\n' ]] \
    || die "mutable lifecycle evidence no longer matches its authenticated canonical inputs"
  "$PROFILE_ANCHOR" verify "$DEVICE_ROOT" "$STATE_DIR" >/dev/null \
    || die "authenticated access-profile anchor does not verify"
  if [[ "$version" == 1 ]]; then
    "$TPM_STATE" runtime-status "$ACCESS_PROFILE" "$HARDWARE_TARGET" \
      "$SIGNED_BOOT_TRUST_POLICY_ID" "$evidence_digest" "$install_at" "$freshness_at" >/dev/null
  else
    "$TPM_STATE" runtime-status-v2 "$ACCESS_PROFILE" "$HARDWARE_TARGET" \
      "$SIGNED_BOOT_TRUST_POLICY_ID" "$evidence_digest" "$install_at" "$freshness_at" "$floor" >/dev/null
  fi
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
provisioning="$($TPM_STATE provisioning-status)" \
  || die "TPM is neither authenticated-complete nor an exact supported pre-ceremony state; signed physical recovery is required"
owner_profile=0
if owner_profile_supported; then
  [[ "$provisioning" == preseal-prepared ]] \
    || die "owner-profile first boot requires the exact preseal-prepared TPM state"
  owner_profile=1
  initial_metadata="$(verify_preseal_initial)" \
    || die "cannot authenticate the installed candidate before owner ceremony"
  read -r receipt_hash set_hash baseline_floor <<<"$initial_metadata"
else
  [[ "$provisioning" == virgin || "$provisioning" == pcr-policy-activated ]] \
    || die "historical first boot requires an exact legacy provisioning state"
fi
read -r anchor_seq freshness_at binding < <(
  if (( owner_profile )); then
    "$TPM_STATE" ceremony-prepare-v2 "$ACCESS_PROFILE" "$HARDWARE_TARGET" \
      "$SIGNED_BOOT_TRUST_POLICY_ID" "$INITIAL_ISSUANCE_SEQ" "$baseline_floor"
  else
    "$TPM_STATE" ceremony-prepare "$ACCESS_PROFILE" "$HARDWARE_TARGET" \
      "$SIGNED_BOOT_TRUST_POLICY_ID" "$INITIAL_ISSUANCE_SEQ"
  fi
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
if (( owner_profile )); then
  "$OTA_STATE" clear-protection >/dev/null || die "cannot protect the TPM against runtime Clear"
  owner_inspection="$($OTA_STATE inspect-v2)" || die "cannot attest protected owner OTA state"
  build_evidence_v2 "$snapshot" "$receipt_hash" "$set_hash" "$baseline_floor" "$owner_inspection" > "$WORK/evidence.json" \
    || die "cannot construct canonical v2 lifecycle evidence"
  evidence="$EVIDENCE_V2"
else
  build_evidence "$snapshot" > "$WORK/evidence.json" \
    || die "cannot construct canonical lifecycle evidence"
  evidence="$EVIDENCE_V1"
fi
[[ ! -e "$evidence" && ! -L "$evidence" ]] || die "lifecycle evidence existed before the trusted ceremony"
install -m 0600 "$WORK/evidence.json" "$evidence"
sync -f "$evidence"; sync -f "$STATE_DIR"
if (( owner_profile )); then
  evidence_digest="$(python3 - "$evidence" <<'PY'
import hashlib,sys
print(hashlib.sha256(b"neural-ice:tpm:owner-ceremony-completion:v2\0"+open(sys.argv[1],"rb").read()).hexdigest())
PY
)"
  "$TPM_STATE" ceremony-finalize-v2 "$ACCESS_PROFILE" "$HARDWARE_TARGET" \
    "$SIGNED_BOOT_TRUST_POLICY_ID" "$evidence_digest" "$anchor_seq" "$freshness_at" "$baseline_floor"
else
  evidence_digest="$(sha256sum "$evidence" | awk '{print tolower($1)}')"
  "$TPM_STATE" ceremony-finalize "$ACCESS_PROFILE" "$HARDWARE_TARGET" \
    "$SIGNED_BOOT_TRUST_POLICY_ID" "$evidence_digest" "$anchor_seq" "$freshness_at"
fi
if (( owner_profile )); then
  validate_complete initial
else
  validate_complete
fi
