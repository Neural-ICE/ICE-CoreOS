#!/usr/bin/env bash
# Stage the exact Fabric release pack and its complete object set as SEED v2.
# This is unprivileged and never writes media. READY is written last and is not
# authority; ni-ota-verify re-hashes and re-verifies every byte on consumption.
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: build-seed-v2.sh --output DIR
  --release-manifest FILE --release-closure FILE
  --authorization FILE --authorization-sig FILE
  --delegation FILE --delegation-sig FILE --root-pubkey FILE
  --registry-host HOST --hardware-target ID --access-profile PROFILE --device-channel RING
  --trust-policy-id ID --trusted-now YYYY-MM-DDTHH:MM:SSZ
  --pcr-policy-digest HEX --pcr-policy-public-key-sha256 HEX
  --pcr-policy-signature-sha256 HEX --pcr-policy-seq N
  --objects DIR [--objects DIR ...]
  --hf-cache DIR --model-profiles FILE --model-catalogue FILE
  [--verifier PATH] [--model-helper PATH]

Every regular file below an --objects directory is imported by its observed
SHA-256. The verifier requires the resulting set to equal the signed closure;
source names, tags and OCI index.json files have no authority.
EOF
  exit 2
}

OUTPUT='' RELEASE_MANIFEST='' RELEASE_CLOSURE='' AUTHORIZATION='' AUTHORIZATION_SIG=''
DELEGATION='' DELEGATION_SIG='' ROOT_PUBKEY='' REGISTRY_HOST='' HARDWARE_TARGET=''
ACCESS_PROFILE='' TRUST_POLICY_ID='' TRUSTED_NOW=''
DEVICE_CHANNEL=''
PCR_POLICY_DIGEST='' PCR_POLICY_PUBLIC_KEY_SHA256='' PCR_POLICY_SIGNATURE_SHA256='' PCR_POLICY_SEQ=''
VERIFIER="${NI_OTA_VERIFY:-/usr/bin/ni-ota-verify}"
MODEL_HELPER="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/model-cache-contract.py"
HF_CACHE='' MODEL_PROFILES='' MODEL_CATALOGUE=''
declare -a OBJECT_ROOTS=()

while (($#)); do
  case "$1" in
    --output) OUTPUT=${2:?}; shift 2 ;;
    --release-manifest) RELEASE_MANIFEST=${2:?}; shift 2 ;;
    --release-closure) RELEASE_CLOSURE=${2:?}; shift 2 ;;
    --authorization) AUTHORIZATION=${2:?}; shift 2 ;;
    --authorization-sig) AUTHORIZATION_SIG=${2:?}; shift 2 ;;
    --delegation) DELEGATION=${2:?}; shift 2 ;;
    --delegation-sig) DELEGATION_SIG=${2:?}; shift 2 ;;
    --root-pubkey) ROOT_PUBKEY=${2:?}; shift 2 ;;
    --registry-host) REGISTRY_HOST=${2:?}; shift 2 ;;
    --hardware-target) HARDWARE_TARGET=${2:?}; shift 2 ;;
    --access-profile) ACCESS_PROFILE=${2:?}; shift 2 ;;
    --device-channel) DEVICE_CHANNEL=${2:?}; shift 2 ;;
    --trust-policy-id) TRUST_POLICY_ID=${2:?}; shift 2 ;;
    --trusted-now) TRUSTED_NOW=${2:?}; shift 2 ;;
    --pcr-policy-digest) PCR_POLICY_DIGEST=${2:?}; shift 2 ;;
    --pcr-policy-public-key-sha256) PCR_POLICY_PUBLIC_KEY_SHA256=${2:?}; shift 2 ;;
    --pcr-policy-signature-sha256) PCR_POLICY_SIGNATURE_SHA256=${2:?}; shift 2 ;;
    --pcr-policy-seq) PCR_POLICY_SEQ=${2:?}; shift 2 ;;
    --objects) OBJECT_ROOTS+=("${2:?}"); shift 2 ;;
    --hf-cache) HF_CACHE=${2:?}; shift 2 ;;
    --model-profiles) MODEL_PROFILES=${2:?}; shift 2 ;;
    --model-catalogue) MODEL_CATALOGUE=${2:?}; shift 2 ;;
    --verifier) VERIFIER=${2:?}; shift 2 ;;
    --model-helper) MODEL_HELPER=${2:?}; shift 2 ;;
    *) echo "ERROR: unknown option: $1" >&2; usage ;;
  esac
done

die() { echo "ERROR: $*" >&2; exit 1; }
for variable in OUTPUT RELEASE_MANIFEST RELEASE_CLOSURE AUTHORIZATION AUTHORIZATION_SIG \
  DELEGATION DELEGATION_SIG ROOT_PUBKEY REGISTRY_HOST HARDWARE_TARGET ACCESS_PROFILE DEVICE_CHANNEL \
  TRUST_POLICY_ID TRUSTED_NOW HF_CACHE MODEL_PROFILES MODEL_CATALOGUE; do
  [[ -n ${!variable} ]] || die "missing required --${variable,,}"
done
for variable in PCR_POLICY_DIGEST PCR_POLICY_PUBLIC_KEY_SHA256 PCR_POLICY_SIGNATURE_SHA256 PCR_POLICY_SEQ; do
  [[ -n ${!variable} ]] || die "missing required --${variable,,}"
done
((${#OBJECT_ROOTS[@]})) || die "at least one --objects directory is required"
[[ -x $VERIFIER ]] || die "verifier is not executable: $VERIFIER"
[[ -x $MODEL_HELPER ]] || die "model-cache contract helper is not executable: $MODEL_HELPER"
for file in "$RELEASE_MANIFEST" "$RELEASE_CLOSURE" "$AUTHORIZATION" \
  "$AUTHORIZATION_SIG" "$DELEGATION" "$DELEGATION_SIG" "$ROOT_PUBKEY"; do
  [[ -f $file && ! -L $file ]] || die "input is not a regular non-symlink file: $file"
done
for directory in "${OBJECT_ROOTS[@]}"; do
  [[ -d $directory && ! -L $directory ]] || die "object root is not a directory: $directory"
done
[[ -d $HF_CACHE && ! -L $HF_CACHE ]] || die "HF cache is not a directory"
for file in "$MODEL_PROFILES" "$MODEL_CATALOGUE"; do
  [[ -f $file && ! -L $file ]] || die "model catalogue input is not a regular file: $file"
done

closure_hex=$(sha256sum -- "$RELEASE_CLOSURE" | awk '{print tolower($1)}')
manifest_hex=$(sha256sum -- "$RELEASE_MANIFEST" | awk '{print tolower($1)}')
[[ $closure_hex =~ ^[0-9a-f]{64}$ && $manifest_hex =~ ^[0-9a-f]{64}$ ]] \
  || die "cannot derive release-pack hashes"

seed_parent="$OUTPUT/seed"
root="$seed_parent/$closure_hex"
staging="$seed_parent/.${closure_hex}.staging.$$"
[[ ! -e $root && ! -L $root ]] || die "refusing to merge with existing seed generation: $root"
install -d -m 0755 "$seed_parent" "$staging/objects/sha256"
trap 'rm -rf -- "$staging"' EXIT

install -m 0444 "$RELEASE_MANIFEST" "$staging/release-manifest.json"
install -m 0444 "$RELEASE_CLOSURE" "$staging/release-closure.json"
install -m 0444 "$AUTHORIZATION" "$staging/release-authorization.json"
install -m 0444 "$AUTHORIZATION_SIG" "$staging/release-authorization.json.sig"
install -m 0444 "$DELEGATION" "$staging/delegation-snapshot.json"
install -m 0444 "$DELEGATION_SIG" "$staging/delegation-snapshot.json.sig"

# Model cards are content, never loose path authority. Generate their canonical
# per-file manifests and copy every observed snapshot byte into the same CAS;
# the signed closure must enumerate these exact digests or the verifier below
# refuses the seed. This producer performs no signing and cannot widen a pack.
model_objects=$(mktemp -d "${TMPDIR:-/tmp}/seed-v2-models.XXXXXX")
trap 'rm -rf -- "$staging" "$model_objects"' EXIT
"$MODEL_HELPER" produce --hf-cache "$HF_CACHE" --profiles "$MODEL_PROFILES" \
  --catalogue "$MODEL_CATALOGUE" --objects "$model_objects" >&2
OBJECT_ROOTS+=("$model_objects")

object_count=0
for directory in "${OBJECT_ROOTS[@]}"; do
  while IFS= read -r -d '' source; do
    [[ -f $source && ! -L $source ]] || die "object input is not a regular file: $source"
    hex=$(sha256sum -- "$source" | awk '{print tolower($1)}')
    destination="$staging/objects/sha256/$hex"
    if [[ -e $destination ]]; then
      cmp -s -- "$source" "$destination" || die "digest collision while importing $source"
      continue
    fi
    install -m 0444 "$source" "$destination"
    object_count=$((object_count + 1))
  done < <(find "$directory" -type f -print0 | sort -z)
done

# The verifier requires the final directory name before it evaluates the pack.
mv -T -- "$staging" "$root"
staging=$root

verify=("$VERIFIER" verify-seed-closure --seed-root "$root" --pubkey "$ROOT_PUBKEY"
  --registry-host "$REGISTRY_HOST" --hardware-target "$HARDWARE_TARGET"
  --access-profile "$ACCESS_PROFILE" --device-channel "$DEVICE_CHANNEL" --trust-policy-id "$TRUST_POLICY_ID"
  --expect-closure "$closure_hex" --trusted-now "$TRUSTED_NOW")
verify+=(--expect-manifest "$manifest_hex")
verify+=(--pcr-policy-digest "$PCR_POLICY_DIGEST" \
  --pcr-policy-public-key-sha256 "$PCR_POLICY_PUBLIC_KEY_SHA256" \
  --pcr-policy-signature-sha256 "$PCR_POLICY_SIGNATURE_SHA256" \
  --pcr-policy-seq "$PCR_POLICY_SEQ")

error=$(mktemp "${TMPDIR:-/tmp}/seed-v2-pre-ready.XXXXXX")
if "${verify[@]}" >/dev/null 2>"$error"; then
  die "verifier passed before READY existed"
fi
if ! grep -q 'READY' "$error"; then
  cat "$error" >&2
  rm -f -- "$error"
  die "release pack/object set refused before READY publication"
fi
rm -f -- "$error"

python3 - "$root/READY" "$closure_hex" "$manifest_hex" "$object_count" <<'PY'
import json, os, sys
path, closure, manifest, count = sys.argv[1:]
body = json.dumps({
    "object_count": int(count),
    "release_closure_sha256": closure,
    "release_manifest_sha256": manifest,
    "schema": "neural-ice-seed-closure-ready-v1",
}, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
with open(path, "xb") as handle:
    handle.write(body)
    handle.flush()
    os.fsync(handle.fileno())
PY
chmod 0444 "$root/READY"
sync -f "$root/READY"
sync -f "$root"
"${verify[@]}" >/dev/null || die "finished seed failed its read-back verification"

rm -rf -- "$model_objects"
trap - EXIT
printf '%s\n' "seed_root=$root" "release_closure_sha256=$closure_hex" \
  "release_manifest_sha256=$manifest_hex" "objects=$object_count"
