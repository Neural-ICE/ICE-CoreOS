#!/usr/bin/env bash
# Provision and attest the dedicated OTA/licensing device-root TPM key.
set -euo pipefail
umask 077

readonly HANDLE="0x81010005"
readonly FORBIDDEN_PKI_HANDLE="0x81010004"
readonly ATTRIBUTES="fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign|noda"
readonly ATTRIBUTES_RAW="0x40472"
readonly IDENTITY_SCHEMA="neural-ice-device-root-tpm-v1"
readonly RECOVERY_SCHEMA="neural-ice-device-root-recovery-v1"
readonly RECOVERY_DOMAIN="neural-ice:ota:device-root-recovery:v1"
readonly DEFAULT_IDENTITY="/var/lib/neural-ice/ota/device-root-v1.json"
readonly DEFAULT_PENDING="/var/lib/neural-ice/ota/device-root-recovery-pending-v1.json"
readonly DEFAULT_ROOT_KEY="/etc/neural-ice/keys/ota-root.pub"

die() { printf 'neural-ice-device-root: refused: %s\n' "$*" >&2; exit 1; }
[[ "$HANDLE" != "$FORBIDDEN_PKI_HANDLE" ]] || die "device-root handle overlaps the PKI root"

if [[ -n "${NI_DEVICE_ROOT_TEST_TOOLS:-}" ]]; then
  [[ "${NI_DEVICE_ROOT_TESTING:-}" == 1 && "$EUID" -ne 0 ]] \
    || die "test tool override is forbidden in a privileged process"
  readonly TEST_MODE=1
  readonly TOOL_DIR="$NI_DEVICE_ROOT_TEST_TOOLS"
  readonly RUN_DIR="${NI_DEVICE_ROOT_TEST_RUN_DIR:?test run directory is required}"
  readonly ROOT_KEY="${NI_DEVICE_ROOT_TEST_ROOT_KEY:?test root key is required}"
else
  [[ "$EUID" -eq 0 ]] || die "must run as root"
  readonly TEST_MODE=0
  readonly TOOL_DIR="/usr/bin"
  readonly RUN_DIR="/run/neural-ice-device-root"
  readonly ROOT_KEY="$DEFAULT_ROOT_KEY"
fi

tool() {
  local path="$TOOL_DIR/$1"
  [[ -x "$path" ]] || die "required tool is unavailable: $path"
  printf '%s' "$path"
}

secure_regular() {
  local path="$1"
  [[ -f "$path" && ! -L "$path" ]] || die "not a regular file: $path"
  [[ "$TEST_MODE" == 1 ]] && return 0
  [[ "$(stat -c '%u:%a' -- "$path")" == "0:600" ]] \
    || die "file must be root-owned mode 0600: $path"
}

atomic_write() {
  local path="$1" bytes="$2" parent tmp
  parent="$(dirname -- "$path")"
  install -d -m 0700 -- "$parent"
  [[ -d "$parent" && ! -L "$parent" ]] || die "unsafe output directory: $parent"
  if [[ -e "$path" || -L "$path" ]]; then secure_regular "$path"; fi
  tmp="$(mktemp "$parent/.device-root.XXXXXX")"
  printf '%s\n' "$bytes" > "$tmp"
  chmod 0600 "$tmp"
  sync -f "$tmp"
  mv -f -- "$tmp" "$path"
  sync -f "$parent"
}

handle_present() {
  local handles
  handles="$("$(tool tpm2_getcap)" handles-persistent 2>/dev/null)" \
    || die "cannot enumerate persistent TPM handles"
  printf '%s\n' "$handles" \
    | sed -n 's/^[[:space:]-]*\(0x[0-9A-Fa-f]\{8\}\)[[:space:]]*$/\1/p' \
    | tr '[:upper:]' '[:lower:]' \
    | grep -qx "$HANDLE"
}

section_value() {
  local section="$1" field="$2" file="$3"
  awk -v section="$section" -v field="$field" '
    $0 == section ":" { active=1; next }
    active && $0 !~ /^[[:space:]]/ { exit }
    active && $1 == field ":" { print $2; exit }
  ' "$file"
}

hex_file() {
  od -An -tx1 -v "$1" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]'
}

sha256_file() {
  "$(tool sha256sum)" "$1" | awk '{print tolower($1)}'
}

identity_json() {
  local name="$1" qualified="$2" public_hash="$3" spki_hash="$4"
  printf '{"attributes":"%s","curve":"nist-p256","handle":"%s","hierarchy":"endorsement","name":"%s","name_algorithm":"sha256","public_area_sha256":"%s","qualified_name":"%s","schema":"%s","scheme":"ecdsa-sha256","spki_sha256":"%s"}\n' \
    "$ATTRIBUTES" "$HANDLE" "$name" "$public_hash" "$qualified" \
    "$IDENTITY_SCHEMA" "$spki_hash"
}

capture_identity() {
  local dir="$1" yaml name qualified public_hash spki_hash expected_name expected_qualified
  yaml="$dir/public.yaml"
  "$(tool tpm2_readpublic)" -Q -c "$HANDLE" -f tpmt -o "$dir/public.tpmt" \
    -n "$dir/name.bin" -q "$dir/qualified-name.bin" || die "cannot read $HANDLE"
  "$(tool tpm2_print)" -t TPMT_PUBLIC "$dir/public.tpmt" > "$yaml" \
    || die "cannot decode the device-root public area"
  "$(tool tpm2_readpublic)" -Q -c "$HANDLE" -f der -o "$dir/public.der" \
    -n "$dir/name-second.bin" || die "cannot export the device-root SPKI"
  cmp -s "$dir/name.bin" "$dir/name-second.bin" \
    || die "device-root changed during attestation"

  [[ "$(section_value name-alg raw "$yaml" | tr '[:upper:]' '[:lower:]')" == 0xb ]] \
    || die "device-root name algorithm is not sha256"
  [[ "$(section_value attributes raw "$yaml" | tr '[:upper:]' '[:lower:]')" == "$ATTRIBUTES_RAW" ]] \
    || die "device-root attributes differ from the closed template"
  [[ "$(grep -Ec '^authorization policy:[[:space:]]*$' "$yaml")" == 1 ]] \
    || die "device-root authorization policy is not empty"
  [[ "$(section_value type raw "$yaml" | tr '[:upper:]' '[:lower:]')" == 0x23 ]] \
    || die "device-root type is not ECC"
  [[ "$(section_value curve-id raw "$yaml" | tr '[:upper:]' '[:lower:]')" == 0x3 ]] \
    || die "device-root curve is not NIST P-256"
  [[ "$(section_value scheme raw "$yaml" | tr '[:upper:]' '[:lower:]')" == 0x18 ]] \
    || die "device-root scheme is not ECDSA"
  [[ "$(section_value scheme-halg raw "$yaml" | tr '[:upper:]' '[:lower:]')" == 0xb ]] \
    || die "device-root signing hash is not sha256"
  [[ "$(section_value sym-alg raw "$yaml" | tr '[:upper:]' '[:lower:]')" == 0x10 ]] \
    || die "device-root symmetric algorithm is not null"
  [[ "$(section_value kdfa-alg raw "$yaml" | tr '[:upper:]' '[:lower:]')" == 0x10 ]] \
    || die "device-root KDF is not null"

  name="$(hex_file "$dir/name.bin")"
  qualified="$(hex_file "$dir/qualified-name.bin")"
  [[ "$name" =~ ^000b[0-9a-f]{64}$ ]] || die "device-root Name is malformed"
  [[ "$qualified" =~ ^000b[0-9a-f]{64}$ ]] || die "device-root qualified Name is malformed"
  public_hash="$(sha256_file "$dir/public.tpmt")"
  expected_name="000b${public_hash}"
  [[ "$name" == "$expected_name" ]] || die "device-root Name does not hash its exact public area"
  # A primary object's qualified Name is H(hierarchy-handle || Name). Binding
  # it to TPM_RH_ENDORSEMENT (0x4000000b) proves this is not an otherwise
  # identical primary created under the owner/platform hierarchy.
  { printf '\x40\x00\x00\x0b'; cat "$dir/name.bin"; } > "$dir/qualified-input.bin"
  expected_qualified="000b$(sha256_file "$dir/qualified-input.bin")"
  [[ "$qualified" == "$expected_qualified" ]] \
    || die "device-root qualified Name is not rooted in the endorsement hierarchy"
  spki_hash="$(sha256_file "$dir/public.der")"
  [[ "$spki_hash" =~ ^[0-9a-f]{64}$ ]] || die "device-root SPKI hash is malformed"
  identity_json "$name" "$qualified" "$public_hash" "$spki_hash"
}

provision() {
  local dir="$1"
  handle_present && die "$HANDLE is already occupied"
  "$(tool tpm2_createprimary)" -Q -C e -g sha256 -G ecc256:ecdsa-sha256 \
    -a "$ATTRIBUTES" -c "$dir/device-root.ctx" \
    || die "cannot create the device-root primary"
  "$(tool tpm2_evictcontrol)" -Q -C o -c "$dir/device-root.ctx" "$HANDLE" \
    || die "cannot persist the device-root at $HANDLE"
  "$(tool tpm2_flushcontext)" "$dir/device-root.ctx" \
    || die "cannot flush the transient device-root context"
}

with_workspace() {
  install -d -m 0700 "$RUN_DIR"
  exec 9>"$RUN_DIR/operation.lock"
  "$(tool flock)" -x 9
  WORK="$(mktemp -d "$RUN_DIR/work.XXXXXX")"
  trap 'rm -rf -- "$WORK"' EXIT
}

ensure_identity() {
  local identity="$1" actual
  with_workspace
  if ! handle_present; then
    [[ ! -e "$identity" ]] \
      || die "$HANDLE is absent for an established identity; root-signed recovery is required"
    provision "$WORK"
  fi
  actual="$(capture_identity "$WORK")"
  if [[ -e "$identity" ]]; then
    secure_regular "$identity"
    cmp -s <(printf '%s\n' "$actual") "$identity" \
      || die "persisted identity does not match the exact TPM public area"
  else
    atomic_write "$identity" "$actual"
  fi
  printf '%s\n' "$actual"
}

attest_identity() {
  local identity="$1" actual
  with_workspace
  handle_present || die "$HANDLE is absent"
  actual="$(capture_identity "$WORK")"
  secure_regular "$identity"
  cmp -s <(printf '%s\n' "$actual") "$identity" \
    || die "persisted identity does not match the exact TPM public area"
  printf '%s\n' "$actual"
}

recovery_json() {
  local nonce="$1" name="$2" spki="$3"
  printf '{"device_root_handle":"%s","nonce":"%s","previous_name":"%s","previous_spki_sha256":"%s","schema":"%s"}\n' \
    "$HANDLE" "$nonce" "$name" "$spki" "$RECOVERY_SCHEMA"
}

identity_fields() {
  local identity="$1" line public_hash qualified expected
  secure_regular "$identity"
  IFS= read -r line < "$identity" || die "cannot read identity"
  [[ "$(wc -l < "$identity" | tr -d ' ')" == 1 ]] || die "identity is not canonical"
  CURRENT_NAME="$(printf '%s\n' "$line" | sed -n 's/^.*"name":"\([^"]*\)".*$/\1/p')"
  public_hash="$(printf '%s\n' "$line" | sed -n 's/^.*"public_area_sha256":"\([^"]*\)".*$/\1/p')"
  qualified="$(printf '%s\n' "$line" | sed -n 's/^.*"qualified_name":"\([^"]*\)".*$/\1/p')"
  CURRENT_SPKI="$(printf '%s\n' "$line" | sed -n 's/^.*"spki_sha256":"\([^"]*\)".*$/\1/p')"
  [[ "$CURRENT_NAME" =~ ^000b[0-9a-f]{64}$ \
    && "$qualified" =~ ^000b[0-9a-f]{64}$ \
    && "$public_hash" =~ ^[0-9a-f]{64}$ \
    && "$CURRENT_SPKI" =~ ^[0-9a-f]{64}$ ]] \
    || die "identity is not the closed canonical contract"
  expected="$(identity_json "$CURRENT_NAME" "$qualified" "$public_hash" "$CURRENT_SPKI")"
  cmp -s <(printf '%s\n' "$expected") "$identity" \
    || die "identity is not the closed canonical contract"
}

pending_fields() {
  local pending="$1" line expected
  secure_regular "$pending"
  IFS= read -r line < "$pending" || die "cannot read pending recovery challenge"
  [[ "$(wc -l < "$pending" | tr -d ' ')" == 1 ]] \
    || die "pending recovery challenge is not canonical"
  PENDING_NONCE="$(printf '%s\n' "$line" | sed -n 's/^.*"nonce":"\([^"]*\)".*$/\1/p')"
  PREVIOUS_NAME="$(printf '%s\n' "$line" | sed -n 's/^.*"previous_name":"\([^"]*\)".*$/\1/p')"
  PREVIOUS_SPKI="$(printf '%s\n' "$line" | sed -n 's/^.*"previous_spki_sha256":"\([^"]*\)".*$/\1/p')"
  [[ "$PENDING_NONCE" =~ ^[0-9a-f]{64}$ \
    && "$PREVIOUS_NAME" =~ ^000b[0-9a-f]{64}$ \
    && "$PREVIOUS_SPKI" =~ ^[0-9a-f]{64}$ ]] \
    || die "pending recovery challenge is not canonical"
  expected="$(recovery_json "$PENDING_NONCE" "$PREVIOUS_NAME" "$PREVIOUS_SPKI")"
  cmp -s <(printf '%s\n' "$expected") "$pending" \
    || die "pending recovery challenge is not canonical"
}

freeze_recovery_input() {
  local source="$1" destination="$2"
  [[ -f "$source" && ! -L "$source" ]] || die "invalid recovery input"
  # `--no-dereference` turns a replacement by symlink into a failure.  All
  # subsequent comparison and signature verification use this single private
  # copy, never a caller-controlled recovery-media pathname.
  cp --no-dereference -- "$source" "$destination" \
    || die "cannot freeze recovery input"
  [[ -f "$destination" && ! -L "$destination" ]] \
    || die "cannot freeze recovery input"
  chmod 0600 -- "$destination" || die "cannot protect recovery input"
}

create_challenge() {
  local identity="$1" pending="$2" nonce
  with_workspace
  [[ ! -e "$pending" ]] || die "a recovery challenge is already pending"
  identity_fields "$identity"
  "$(tool tpm2_getrandom)" 32 -o "$WORK/nonce.bin" \
    || die "cannot obtain a nonce from the TPM"
  nonce="$(hex_file "$WORK/nonce.bin")"
  [[ "$nonce" =~ ^[0-9a-f]{64}$ ]] || die "TPM recovery nonce is not exactly 32 bytes"
  atomic_write "$pending" "$(recovery_json "$nonce" "$CURRENT_NAME" "$CURRENT_SPKI")"
  cat -- "$pending"
}

recover_identity() {
  local identity="$1" pending="$2" authorization="$3" signature="$4" actual
  with_workspace
  pending_fields "$pending"
  [[ -f "$ROOT_KEY" && ! -L "$ROOT_KEY" ]] || die "immutable OTA root public key is absent"
  freeze_recovery_input "$authorization" "$WORK/authorization.json"
  freeze_recovery_input "$signature" "$WORK/signature"
  cmp -s "$pending" "$WORK/authorization.json" \
    || die "root authorization does not match the exact pending challenge"

  { printf '%s\0' "$RECOVERY_DOMAIN"; cat -- "$WORK/authorization.json"; } > "$WORK/signing-bytes"
  "$(tool base64)" -w0 "$WORK/signature" > "$WORK/signature.base64"
  printf '\n' >> "$WORK/signature.base64"
  "$(tool cosign)" verify-blob --key "$ROOT_KEY" --insecure-ignore-tlog=true \
    --signature "$WORK/signature.base64" "$WORK/signing-bytes" >/dev/null 2>&1 \
    || die "OTA root signature rejected the recovery authorization"

  identity_fields "$identity"
  if handle_present; then
    # A signed authorization names the *receipt* it is allowed to replace. A
    # later receipt may only consume a surviving marker when the TPM still
    # attests that same receipt; it must never adopt an unrelated third key.
    # Conversely, when the receipt is still the signed prior identity, a
    # malformed object at this exact dedicated handle is recoverable: signed
    # recovery may evict it without first trusting its public area.
    if actual="$(capture_identity "$WORK" 2>"$WORK/capture.err")"; then
      rm -f -- "$WORK/capture.err"
      if ! cmp -s <(printf '%s\n' "$actual") "$identity"; then
        if [[ "$CURRENT_NAME" != "$PREVIOUS_NAME" || "$CURRENT_SPKI" != "$PREVIOUS_SPKI" ]]; then
          die "recovery authorization is stale for the current identity"
        fi
        # Authorized recovery created and attested a replacement but crashed
        # before publishing its receipt. Finalize that exact replacement.
        atomic_write "$identity" "$actual"
        rm -f -- "$pending"
        sync -f "$(dirname -- "$pending")"
        printf '%s\n' "$actual"
        return 0
      fi
      if [[ "$CURRENT_NAME" != "$PREVIOUS_NAME" || "$CURRENT_SPKI" != "$PREVIOUS_SPKI" ]]; then
        # Receipt and TPM already describe the authorized replacement; only
        # the one-use pending marker survived the prior crash.
        rm -f -- "$pending"
        sync -f "$(dirname -- "$pending")"
        printf '%s\n' "$actual"
        return 0
      fi
    else
      rm -f -- "$WORK/capture.err"
      [[ "$CURRENT_NAME" == "$PREVIOUS_NAME" && "$CURRENT_SPKI" == "$PREVIOUS_SPKI" ]] \
        || die "recovery authorization is stale for the current identity"
    fi
    "$(tool tpm2_evictcontrol)" -Q -C o -c "$HANDLE" \
      || die "cannot evict the authorized device-root"
  elif [[ "$CURRENT_NAME" != "$PREVIOUS_NAME" || "$CURRENT_SPKI" != "$PREVIOUS_SPKI" ]]; then
    die "replacement receipt exists but the device-root handle is absent"
  fi
  provision "$WORK"
  actual="$(capture_identity "$WORK")"
  atomic_write "$identity" "$actual"
  rm -f -- "$pending"
  sync -f "$(dirname -- "$pending")"
  printf '%s\n' "$actual"
}

usage() {
  cat >&2 <<'EOF'
usage:
  neural-ice-device-root ensure [--identity PATH]
  neural-ice-device-root attest [--identity PATH]
  neural-ice-device-root recovery-challenge [--identity PATH] [--pending PATH]
  neural-ice-device-root recover --authorization PATH --signature PATH
                                 [--identity PATH] [--pending PATH]
EOF
  exit 2
}

command="${1:-}"; [[ -n "$command" ]] || usage; shift
identity="$DEFAULT_IDENTITY"; pending="$DEFAULT_PENDING"; authorization=""; signature=""
while (( $# )); do
  case "$1" in
    --identity) identity="${2:-}"; shift 2 ;;
    --pending) pending="${2:-}"; shift 2 ;;
    --authorization) authorization="${2:-}"; shift 2 ;;
    --signature) signature="${2:-}"; shift 2 ;;
    *) usage ;;
  esac
done

case "$command" in
  ensure) [[ -z "$authorization$signature" ]] || usage; ensure_identity "$identity" ;;
  attest) [[ -z "$authorization$signature" ]] || usage; attest_identity "$identity" ;;
  recovery-challenge) [[ -z "$authorization$signature" ]] || usage; create_challenge "$identity" "$pending" ;;
  recover)
    [[ -n "$authorization" && -n "$signature" ]] || usage
    recover_identity "$identity" "$pending" "$authorization" "$signature"
    ;;
  *) usage ;;
esac
