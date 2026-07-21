#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT/ota/neural-ice-device-root-tpm.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
TOOLS="$TMP/tools"
STATE="$TMP/state"
RUN="$TMP/run"
mkdir -p "$TOOLS" "$STATE" "$RUN"
printf '0\n' > "$STATE/present"
printf 'valid\n' > "$STATE/public-mode"
printf 'v1\n' > "$STATE/public-version"
: > "$STATE/calls"

REAL_OPENSSL="$(command -v openssl)"
REAL_SHA256SUM="$(command -v sha256sum)"
ln -s "$REAL_SHA256SUM" "$TOOLS/sha256sum"
cat > "$TOOLS/base64" <<'EOF'
#!/usr/bin/env bash
[[ "$1" == -w0 ]]
/usr/bin/base64 < "$2" | tr -d '\n'
EOF
cat > "$TOOLS/cosign" <<'EOF'
#!/usr/bin/env bash
signature= message=
while (( $# )); do
  case "$1" in
    --signature) signature="$2"; shift 2 ;;
    --key|--insecure-ignore-tlog=true) [[ "$1" == --key ]] && shift 2 || shift ;;
    verify-blob) shift ;;
    *) message="$1"; shift ;;
  esac
done
if /usr/bin/base64 --decode </dev/null >/dev/null 2>&1; then
  /usr/bin/base64 --decode < "$signature" > "$MOCK_STATE/signature.der"
else
  /usr/bin/base64 -D < "$signature" > "$MOCK_STATE/signature.der"
fi
"$MOCK_OPENSSL" dgst -sha256 -verify "$NI_DEVICE_ROOT_TEST_ROOT_KEY" \
  -signature "$MOCK_STATE/signature.der" "$message" >/dev/null 2>&1
EOF
cat > "$TOOLS/flock" <<'EOF'
#!/usr/bin/env bash
[[ "$1" == -x && "$2" == 9 ]]
EOF
cat > "$TOOLS/sync" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x "$TOOLS/base64" "$TOOLS/cosign" "$TOOLS/flock" "$TOOLS/sync"

cat > "$TOOLS/tpm2_getcap" <<'EOF'
#!/usr/bin/env bash
printf -- '- 0x81010004\n'
[[ ! -e "$MOCK_STATE/getcap-fail" ]] || exit 6
[[ "$(cat "$MOCK_STATE/present")" == 1 ]] && printf -- '- 0x81010005\n'
exit 0
EOF

cat > "$TOOLS/tpm2_createprimary" <<'EOF'
#!/usr/bin/env bash
printf 'createprimary %s\n' "$*" >> "$MOCK_STATE/calls"
[[ ! -e "$MOCK_STATE/create-fail" ]] || exit 7
while (( $# )); do
  if [[ "$1" == -c ]]; then printf context > "$2"; break; fi
  shift
done
EOF

cat > "$TOOLS/tpm2_flushcontext" <<'EOF'
#!/usr/bin/env bash
printf 'flushcontext %s\n' "$*" >> "$MOCK_STATE/calls"
EOF

cat > "$TOOLS/tpm2_evictcontrol" <<'EOF'
#!/usr/bin/env bash
printf 'evictcontrol %s\n' "$*" >> "$MOCK_STATE/calls"
if [[ " $* " == *' -c 0x81010005 '* ]]; then
  printf '0\n' > "$MOCK_STATE/present"
else
  [[ "${*: -1}" == 0x81010005 ]] || exit 4
  printf '1\n' > "$MOCK_STATE/present"
fi
EOF

cat > "$TOOLS/tpm2_readpublic" <<'EOF'
#!/usr/bin/env bash
fmt= out= name= qualified=
while (( $# )); do
  case "$1" in
    -f) fmt="$2"; shift 2 ;;
    -o) out="$2"; shift 2 ;;
    -n) name="$2"; shift 2 ;;
    -q) qualified="$2"; shift 2 ;;
    *) shift ;;
  esac
done
[[ "$(cat "$MOCK_STATE/present")" == 1 ]] || exit 5
version="$(cat "$MOCK_STATE/public-version")"
printf 'TPMT_PUBLIC_TEST_%s' "$version" > "$MOCK_STATE/public.tpmt"
if [[ "$fmt" == tpmt ]]; then cp "$MOCK_STATE/public.tpmt" "$out"; else printf 'DER_SPKI_TEST_%s' "$version" > "$out"; fi
digest="$(sha256sum "$MOCK_STATE/public.tpmt" | awk '{print $1}')"
printf '000b%s' "$digest" | xxd -r -p > "$name"
if [[ -n "$qualified" ]]; then
  { printf '\x40\x00\x00\x0b'; cat "$name"; } > "$MOCK_STATE/qualified-input"
  qdigest="$(sha256sum "$MOCK_STATE/qualified-input" | awk '{print $1}')"
  [[ "$(cat "$MOCK_STATE/public-mode")" != hierarchy ]] || qdigest="f${qdigest:1}"
  printf '000b%s' "$qdigest" \
    | xxd -r -p > "$qualified"
fi
EOF

cat > "$TOOLS/tpm2_print" <<'EOF'
#!/usr/bin/env bash
attrs=0x40472 curve='NIST p256' curve_raw=0x3 scheme=ecdsa scheme_raw=0x18 policy= kdf_raw=0x10
case "$(cat "$MOCK_STATE/public-mode")" in
  attributes) attrs=0x40432 ;;
  curve) curve='NIST p384'; curve_raw=0x4 ;;
  scheme) scheme=ecdh; scheme_raw=0x19 ;;
  policy) policy=00 ;;
  kdf) kdf_raw=0x11 ;;
esac
cat <<YAML
name-alg:
  value: sha256
  raw: 0xb
attributes:
  value: fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign|noda
  raw: $attrs
authorization policy: $policy
type:
  value: ecc
  raw: 0x23
curve-id:
  value: $curve
  raw: $curve_raw
scheme:
  value: $scheme
  raw: $scheme_raw
scheme-halg:
  value: sha256
  raw: 0xb
sym-alg:
  value: null
  raw: 0x10
kdfa-alg:
  value: null
  raw: $kdf_raw
YAML
EOF

cat > "$TOOLS/tpm2_getrandom" <<'EOF'
#!/usr/bin/env bash
out=
while (( $# )); do
  [[ "$1" == -o ]] && { out="$2"; break; }
  shift
done
printf '0123456789abcdef0123456789abcdef' > "$out"
EOF
chmod +x "$TOOLS"/tpm2_*

"$REAL_OPENSSL" ecparam -name prime256v1 -genkey -noout -out "$TMP/root-private.pem" 2>/dev/null
"$REAL_OPENSSL" ec -in "$TMP/root-private.pem" -pubout -out "$TMP/root-public.pem" 2>/dev/null

run() {
  MOCK_STATE="$STATE" \
  MOCK_OPENSSL="$REAL_OPENSSL" \
  NI_DEVICE_ROOT_TESTING=1 \
  NI_DEVICE_ROOT_TEST_TOOLS="$TOOLS" \
  NI_DEVICE_ROOT_TEST_RUN_DIR="$RUN" \
  NI_DEVICE_ROOT_TEST_ROOT_KEY="$TMP/root-public.pem" \
  PATH="$TOOLS:$PATH" \
    "$SCRIPT" "$@"
}

expect_refuse() {
  local expected="$1"; shift
  if run "$@" >"$TMP/out" 2>"$TMP/err"; then
    echo "expected refusal: $*" >&2; exit 1
  fi
  grep -Fq "$expected" "$TMP/err"
}

IDENTITY="$TMP/device-root.json"
PENDING="$TMP/pending.json"
AUTH="$TMP/authorization.json"
SIG="$TMP/authorization.sig"

# Both immutable image assembly and installer invoke the same helper; no
# second provisioning implementation can drift from this contract.
grep -Fq 'COPY ota/neural-ice-device-root-tpm.sh /usr/libexec/neural-ice-device-root' \
  "$ROOT/image/Containerfile.bootc"
grep -Fq 'systemctl enable neural-ice-device-root.service' "$ROOT/image/Containerfile.bootc"
grep -Fq '/usr/libexec/neural-ice-device-root ensure' "$ROOT/ota/neural-ice-autoinstall.sh"
grep -Fq 'ExecStart=/usr/libexec/neural-ice-device-root ensure' \
  "$ROOT/image/bootc-overlay/usr/lib/systemd/system/neural-ice-device-root.service"

# Fresh provisioning creates only 0x81010005 and produces a closed identity.
run ensure --identity "$IDENTITY" >/dev/null
grep -q 'evictcontrol .* 0x81010005$' "$STATE/calls"
if grep -q 'evictcontrol .*0x81010004' "$STATE/calls"; then exit 1; fi
grep -q '"handle":"0x81010005"' "$IDENTITY"
first_calls="$(wc -l < "$STATE/calls")"
run ensure --identity "$IDENTITY" >/dev/null
[[ "$(wc -l < "$STATE/calls")" == "$first_calls" ]]
touch "$STATE/getcap-fail"
expect_refuse 'cannot enumerate persistent TPM handles' attest --identity "$IDENTITY"
rm "$STATE/getcap-fail"

# Every exact public-area field and the persisted identity are fail-closed.
for hostile in attributes curve scheme hierarchy policy kdf; do
  printf '%s\n' "$hostile" > "$STATE/public-mode"
  expect_refuse 'device-root' attest --identity "$IDENTITY"
done
printf 'valid\n' > "$STATE/public-mode"
cp "$IDENTITY" "$TMP/tampered.json"
sed -i.bak 's/"spki_sha256":"./"spki_sha256":"f/' "$TMP/tampered.json"
expect_refuse 'persisted identity does not match' attest --identity "$TMP/tampered.json"
printf '{"attributes":"fixedtpmTHIS_IS_NOT_CANONICAL"}\n' > "$TMP/regex-hostile.json"
expect_refuse 'identity is not the closed canonical contract' recovery-challenge \
  --identity "$TMP/regex-hostile.json" --pending "$TMP/hostile-pending.json"

# Losing the established handle cannot silently reprovision it.
printf '0\n' > "$STATE/present"
before="$(wc -l < "$STATE/calls")"
expect_refuse 'root-signed recovery is required' ensure --identity "$IDENTITY"
[[ "$(wc -l < "$STATE/calls")" == "$before" ]]
printf '1\n' > "$STATE/present"

# Recovery uses one fresh TPM nonce and the exact root-signed canonical bytes.
run recovery-challenge --identity "$IDENTITY" --pending "$PENDING" >/dev/null
cp "$PENDING" "$AUTH"
{ printf 'neural-ice:ota:device-root-recovery:v1\0'; cat "$AUTH"; } > "$TMP/signing-bytes"
"$REAL_OPENSSL" dgst -sha256 -sign "$TMP/root-private.pem" -out "$SIG" "$TMP/signing-bytes"
printf x >> "$AUTH"
expect_refuse 'does not match the exact pending challenge' recover --identity "$IDENTITY" \
  --pending "$PENDING" --authorization "$AUTH" --signature "$SIG"
cp "$PENDING" "$AUTH"
printf invalid > "$SIG"
expect_refuse 'OTA root signature rejected' recover --identity "$IDENTITY" \
  --pending "$PENDING" --authorization "$AUTH" --signature "$SIG"
"$REAL_OPENSSL" dgst -sha256 -sign "$TMP/root-private.pem" -out "$SIG" "$TMP/signing-bytes"
touch "$STATE/create-fail"
expect_refuse 'cannot create the device-root primary' recover --identity "$IDENTITY" \
  --pending "$PENDING" --authorization "$AUTH" --signature "$SIG"
[[ -e "$PENDING" ]]
rm "$STATE/create-fail"
run recover --identity "$IDENTITY" --pending "$PENDING" \
  --authorization "$AUTH" --signature "$SIG" >/dev/null
[[ ! -e "$PENDING" ]]
expect_refuse 'not a regular file' recover --identity "$IDENTITY" --pending "$PENDING" \
  --authorization "$AUTH" --signature "$SIG"
if grep -q 'evictcontrol .*0x81010004' "$STATE/calls"; then exit 1; fi

# A crash after a replacement was attested/published but before pending-marker
# deletion is finalized without a second eviction, even when the new TPM seed
# gives the replacement a different public identity.
run recovery-challenge --identity "$IDENTITY" --pending "$PENDING" >/dev/null
cp "$PENDING" "$AUTH"
{ printf 'neural-ice:ota:device-root-recovery:v1\0'; cat "$AUTH"; } > "$TMP/signing-bytes"
"$REAL_OPENSSL" dgst -sha256 -sign "$TMP/root-private.pem" -out "$SIG" "$TMP/signing-bytes"
printf 'v2\n' > "$STATE/public-version"
rm "$IDENTITY"
run ensure --identity "$IDENTITY" >/dev/null
before="$(grep -c '^evictcontrol' "$STATE/calls")"
run recover --identity "$IDENTITY" --pending "$PENDING" \
  --authorization "$AUTH" --signature "$SIG" >/dev/null
[[ ! -e "$PENDING" ]]
[[ "$(grep -c '^evictcontrol' "$STATE/calls")" == "$before" ]]

echo 'device-root TPM v1 tests: PASS'
