#!/usr/bin/env bash
# The INSTALL-TIME ACCESS-PROFILE ANCHOR, signed by the dedicated TPM device root.
#
# WHY THIS FILE EXISTS (DESIGN-NOTE-0001, Finding 3). ni-ota-verify refuses a
# release whose `variant` differs from the host's immutable
# /usr/lib/neural-ice/appliance-variant. ADR-0014's continuity argument then
# leans on a third premise -- "the variant -> policy mapping is a total
# function, so equal variants imply an equal access policy". That premise is a
# property of TODAY'S SOURCE TREE (image/lib/access-policy.sh), not of anything
# signed. A later, correctly signed, SAME-VARIANT OTA can rewrite that mapping,
# or the marker itself, and the appliance's access posture changes with no
# signature ever having stated the old one. The binding is *variant*; the thing
# that must be immutable is *profile*.
#
# WHAT THIS ANCHOR IS. The profile observed at install time, written into the
# STATEROOT -- outside the candidate deployment, so a deployment can never
# restate its own authority -- and signed by the non-exportable device root at
# 0x81010005 (ADR-0013). An attacker who can edit /var offline can rewrite the
# JSON, but cannot produce the signature: the private key never leaves the TPM.
#
# WHAT A MISMATCH MEANS. "reinstall required", deliberately not "re-enrol". A
# profile change is a change of what the appliance IS, and the only honest path
# back is signed physical media (ADR-0014). An appliance shipped customer-locked
# therefore cannot be walked to lab-managed by any OTA, however well signed.
#
# WHY A SEQUENCE NUMBER AS WELL. The signature alone stops a forgery, not a
# REPLAY: a machine that was legitimately reinstalled from lab-managed to
# customer-locked still has an old, genuinely device-root-signed lab-managed
# bundle in an attacker's hands. `anchor_seq` is monotonic per machine and the
# gate refuses anything below the high-water mark, so yesterday's authentic
# bundle cannot be put back.
#
# 🔴 WHERE THE HIGH-WATER LIVES, AND WHY THAT IS THE WHOLE POINT. It used to be
# an OPTIONAL argument with a default of 0, and no production caller ever passed
# it — while the installer wrote the literal sequence `1` on every install. Both
# halves were therefore decorative: every anchor was seq 1 and every gate
# compared it with 0. The counter now comes from TPM NV (`nt=counter`, via
# ota/neural-ice-tpm-state.sh), which the TPM itself keeps monotonic across
# reinstalls and across the full-disk wipe an attacker performs before replaying.
# An unreadable counter is a REFUSAL, not a zero: a machine that cannot prove
# where it is in its own history must not apply an OTA.
#
# 🔴 AND THE DEVICE-ROOT SIGNATURE IS NO LONGER THE PROFILE'S AUTHORITY (review
# 2026-09-01, P1 #3). The device root at 0x81010005 has `userwithauth` and an
# EMPTY authorization policy, so anything running as root on the appliance can
# make it sign — including a REPLACEMENT anchor carrying a different profile at
# the current counter value. The profile is therefore bound to a WRITE-ONCE,
# policy-protected TPM NV record, and the gate below requires the anchor's
# (profile, target, trust policy) triple to hash to what that record holds. The
# signature proves DEVICE BINDING; the record is the AUTHORITY. `ni-ota-verify`
# makes the same comparison independently, in Rust, against the same TPM.
set -euo pipefail
umask 077

readonly ANCHOR_SCHEMA="neural-ice-access-profile-anchor-v1"
# Must match ni-ota-verify's ACCESS_PROFILE_ANCHOR_DOMAIN byte for byte,
# trailing NUL included: two verifiers of one signature that disagree about the
# domain do not both verify it, they each verify a different statement.
readonly ANCHOR_DOMAIN='neural-ice:ota:access-profile-anchor:v1'
readonly DEVICE_ROOT_HANDLE="0x81010005"
readonly DEVICE_ROOT_IDENTITY_SCHEMA="neural-ice-device-root-tpm-v1"
readonly ANCHOR_BASENAME="access-profile-v1"
# The monotonic install counter this machine keeps in TPM NV. Overridable only so
# the suite can point at a mock; the override is refused in a privileged process
# by the same guard as the tool directory below.
DEFAULT_TPM_STATE_HELPER="/usr/libexec/neural-ice-tpm-state"
readonly MAX_ANCHOR_BYTES=1024
readonly MAX_SIGNATURE_BYTES=1024
readonly MAX_SPKI_BYTES=1024

die() { printf 'neural-ice-access-profile-anchor: refused: %s\n' "$*" >&2; exit 1; }
# The one refusal the OTA path must be able to recognise by its exact words.
die_reinstall() { printf 'neural-ice-access-profile-anchor: reinstall required: %s\n' "$*" >&2; exit 3; }

if [[ -n "${NI_ACCESS_PROFILE_ANCHOR_TEST_TOOLS:-}" ]]; then
  [[ "${NI_ACCESS_PROFILE_ANCHOR_TESTING:-}" == 1 && "$EUID" -ne 0 ]] \
    || die "test tool override is forbidden in a privileged process"
  readonly TEST_MODE=1
  readonly TOOL_DIR="$NI_ACCESS_PROFILE_ANCHOR_TEST_TOOLS"
  readonly RUN_DIR="${NI_ACCESS_PROFILE_ANCHOR_TEST_RUN_DIR:?test run directory is required}"
  readonly TPM_STATE_HELPER="${NI_ACCESS_PROFILE_ANCHOR_TEST_TPM_STATE:-$DEFAULT_TPM_STATE_HELPER}"
else
  [[ "$EUID" -eq 0 ]] || die "must run as root"
  readonly TEST_MODE=0
  readonly TOOL_DIR="/usr/bin"
  readonly RUN_DIR="/run/neural-ice-access-profile-anchor"
  readonly TPM_STATE_HELPER="$DEFAULT_TPM_STATE_HELPER"
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

bounded_read() { # $1=path  $2=max bytes — refuses a symlink, a directory and a padded file
  local path="$1" maximum="$2" size
  secure_regular "$path"
  size="$(wc -c < "$path" | tr -d '[:space:]')"
  [[ "$size" =~ ^[0-9]+$ && "$size" -gt 0 && "$size" -le "$maximum" ]] \
    || die "implausible size for $path ($size bytes)"
  cat -- "$path"
}

atomic_write() {
  local path="$1" bytes="$2" parent tmp
  parent="$(dirname -- "$path")"
  install -d -m 0700 -- "$parent"
  [[ -d "$parent" && ! -L "$parent" ]] || die "unsafe output directory: $parent"
  [[ ! -e "$path" && ! -L "$path" ]] || die "refusing to overwrite an existing anchor artefact: $path"
  tmp="$(mktemp "$parent/.access-profile.XXXXXX")"
  printf '%s' "$bytes" > "$tmp"
  chmod 0600 "$tmp"
  "$(tool sync)" || die "cannot flush $path"
  mv -f -- "$tmp" "$path" || die "cannot publish $path"
}

with_workspace() {
  install -d -m 0700 "$RUN_DIR"
  exec 9>"$RUN_DIR/operation.lock"
  "$(tool flock)" -x 9
  WORK="$(mktemp -d "$RUN_DIR/work.XXXXXX")"
  trap 'rm -rf -- "$WORK"' EXIT
}

# --------------------------------------------------------------------------- #
# Canonical persisted bytes: sorted keys, no optional whitespace or final LF.
# anchor_json emits a display LF; enroll command substitution removes it before
# signing and atomic_write. Rust must match these already-issued bytes exactly.
# --------------------------------------------------------------------------- #
anchor_json() { # profile target policy_id seq name spki_sha256 enrolled_at
  printf '{"access_profile":"%s","anchor_seq":%s,"device_root_handle":"%s","device_root_name":"%s","device_root_spki_sha256":"%s","enrolled_at":"%s","hardware_target":"%s","schema":"%s","signed_boot_trust_policy_id":"%s"}\n' \
    "$1" "$4" "$DEVICE_ROOT_HANDLE" "$5" "$6" "$7" "$2" "$ANCHOR_SCHEMA" "$3"
}

json_field() { # $1=json  $2=key — string values only, exact key, no regex surprises
  "$(tool python3)" -c '
import json, sys
doc = json.loads(sys.stdin.read())
value = doc.get(sys.argv[1])
if value is None:
    raise SystemExit(1)
print(value)
' "$2" <<<"$1"
}

validate_profile() {
  case "$1" in
    lab-managed | customer-locked | developer-diagnostic) ;;
    *) die "'$1' is not a recognised access profile" ;;
  esac
}

validate_target() {
  [[ "$1" =~ ^[a-z0-9]([a-z0-9_-]{0,62}[a-z0-9])?$ ]] || die "'$1' is not a valid hardware target"
}

validate_policy_id() {
  [[ "$1" =~ ^neural-ice-secureboot-[a-z0-9-]{1,32}$ ]] \
    || die "'$1' is not a valid signed-boot trust policy id"
}

validate_seq() {
  # Bounded by the same IEEE-754 safe integer the OTA contract uses everywhere
  # else, so a sequence cannot be a value one reader rounds and another does not.
  [[ "$1" =~ ^[0-9]{1,16}$ && "$1" -ge 1 && "$1" -le 9007199254740991 ]] \
    || die "'$1' is not a valid anchor sequence"
}

# --------------------------------------------------------------------------- #
# The device root, as the existing helper recorded it. That identity JSON is
# re-attested against the live TPM on every boot by
# /usr/libexec/neural-ice-device-root, so trusting it here adds no new
# assumption -- it inherits that one.
# --------------------------------------------------------------------------- #
device_root_fields() { # $1=identity path -> sets DR_NAME, DR_SPKI_SHA256
  local identity="$1" json schema handle
  json="$(bounded_read "$identity" 4096)"
  schema="$(json_field "$json" schema)" || die "device-root identity has no schema"
  [[ "$schema" == "$DEVICE_ROOT_IDENTITY_SCHEMA" ]] \
    || die "device-root identity is not $DEVICE_ROOT_IDENTITY_SCHEMA"
  handle="$(json_field "$json" handle)" || die "device-root identity has no handle"
  [[ "$handle" == "$DEVICE_ROOT_HANDLE" ]] \
    || die "device-root identity is for handle $handle, not $DEVICE_ROOT_HANDLE"
  DR_NAME="$(json_field "$json" name)" || die "device-root identity has no name"
  DR_SPKI_SHA256="$(json_field "$json" spki_sha256)" || die "device-root identity has no SPKI hash"
  [[ "$DR_NAME" =~ ^000b[0-9a-f]{64}$ ]] || die "device-root Name is malformed"
  [[ "$DR_SPKI_SHA256" =~ ^[0-9a-f]{64}$ ]] || die "device-root SPKI hash is malformed"
}

# The exact bytes that are signed: domain, a NUL, then the JSON WITHOUT its
# trailing LF. Identical construction on both sides of the wire.
signing_payload() { # $1=json (canonical bytes, no LF)  $2=output path
  { printf '%s\0' "$ANCHOR_DOMAIN"; printf '%s' "${1%$'\n'}"; } > "$2"
}

# The signature is requested as `-f tss`: the TCG-marshalled TPMT_SIGNATURE
# (sigAlg, hashAlg, TPM2B r, TPM2B s), which is fixed by the TPM 2.0 Library
# spec and does not move between tpm2-tools releases. (`-f plain` is NOT stable:
# tpm2-tools 5.6 emits DER for ECDSA, earlier releases emitted raw r||s, and a
# QEMU first boot refused on exactly that drift.) Every verifier in this tree
# (cosign, openssl, ni-ota-verify) speaks DER; convert once, here, refusing
# any algorithm, hash or length other than the ECDSA-P256/SHA-256 contract.
tss_to_der() { # $1=TPMT_SIGNATURE path (tpm2_sign -f tss)  $2=output DER path
  "$(tool python3)" - "$1" "$2" <<'PYEOF'
import sys

TPM_ALG_ECDSA = 0x0018
TPM_ALG_SHA256 = 0x000B
CURVE_BYTES = 32


def refuse(reason: str) -> None:
    print(f"TPM signature is not an ECDSA-P256/SHA-256 TPMT_SIGNATURE: {reason}", file=sys.stderr)
    raise SystemExit(1)


tss = open(sys.argv[1], "rb").read()
if len(tss) != 4 + 2 * (2 + CURVE_BYTES):
    refuse(f"{len(tss)} bytes")
if int.from_bytes(tss[0:2], "big") != TPM_ALG_ECDSA:
    refuse("sigAlg is not TPM_ALG_ECDSA")
if int.from_bytes(tss[2:4], "big") != TPM_ALG_SHA256:
    refuse("hashAlg is not TPM_ALG_SHA256")


def parameter(offset: int) -> tuple[bytes, int]:
    size = int.from_bytes(tss[offset : offset + 2], "big")
    if size != CURVE_BYTES:
        refuse(f"ECC parameter is {size} bytes")
    return tss[offset + 2 : offset + 2 + size], offset + 2 + size


r, offset = parameter(4)
s, offset = parameter(offset)
if offset != len(tss):
    refuse("trailing bytes")


def integer(value: bytes) -> bytes:
    trimmed = value.lstrip(b"\x00") or b"\x00"
    if trimmed[0] & 0x80:
        trimmed = b"\x00" + trimmed
    return b"\x02" + bytes([len(trimmed)]) + trimmed


body = integer(r) + integer(s)
open(sys.argv[2], "wb").write(b"\x30" + bytes([len(body)]) + body)
PYEOF
}

hex_sha256() { "$(tool sha256sum)" "$1" | awk '{print tolower($1)}'; }

anchor_paths() { # $1=anchor directory
  ANCHOR_JSON="$1/$ANCHOR_BASENAME.json"
  ANCHOR_SIG="$1/$ANCHOR_BASENAME.sig"
  ANCHOR_SPKI="$1/$ANCHOR_BASENAME.spki"
}

# --------------------------------------------------------------------------- #
# enroll IDENTITY DIR PROFILE TARGET TRUST_POLICY_ID SEQ ENROLLED_AT
#
# Runs at INSTALL TIME, against the stateroot the installer just created. It
# refuses to overwrite: an anchor that can be re-enrolled in place is not an
# anchor, and the installer is the only thing allowed to create one.
# --------------------------------------------------------------------------- #
enroll() {
  (( $# == 7 )) || die "enroll requires identity, directory, profile, target, trust policy id, sequence and timestamp"
  local identity="$1" dir="$2" profile="$3" target="$4" policy_id="$5" seq="$6" stamp="$7"
  validate_profile "$profile"; validate_target "$target"; validate_policy_id "$policy_id"
  validate_seq "$seq"
  [[ "$stamp" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] \
    || die "'$stamp' is not an RFC 3339 UTC timestamp"

  with_workspace
  device_root_fields "$identity"
  anchor_paths "$dir"
  for existing in "$ANCHOR_JSON" "$ANCHOR_SIG" "$ANCHOR_SPKI"; do
    [[ ! -e "$existing" && ! -L "$existing" ]] \
      || die "an access-profile anchor already exists at $existing; enrolment is once per installation"
  done

  # Export the device root's SPKI and prove it is the SAME key the attested
  # identity describes. Without this the anchor could be signed by any key whose
  # SPKI we happened to write next to it.
  "$(tool tpm2_readpublic)" -Q -c "$DEVICE_ROOT_HANDLE" -f der -o "$WORK/spki.der" \
    || die "cannot export the device-root public key"
  local spki_hash; spki_hash="$(hex_sha256 "$WORK/spki.der")"
  [[ "$spki_hash" == "$DR_SPKI_SHA256" ]] \
    || die "the device root at $DEVICE_ROOT_HANDLE is not the attested identity"

  local json; json="$(anchor_json "$profile" "$target" "$policy_id" "$seq" "$DR_NAME" "$DR_SPKI_SHA256" "$stamp")"
  signing_payload "$json" "$WORK/payload"
  "$(tool tpm2_sign)" -Q -c "$DEVICE_ROOT_HANDLE" -g sha256 -s ecdsa -f tss \
    -o "$WORK/signature.tss" "$WORK/payload" \
    || die "the device root refused to sign the access-profile anchor"
  tss_to_der "$WORK/signature.tss" "$WORK/signature.der" \
    || die "cannot encode the device-root signature"

  # VERIFY WHAT WAS PRODUCED, not what was requested. An anchor whose signature
  # does not check out must never reach the stateroot: on the next boot it would
  # be indistinguishable from tampering and would brick the appliance's OTA path
  # with "reinstall required" -- for a defect, not an attack.
  "$(tool openssl)" dgst -sha256 -verify <("$(tool openssl)" pkey -pubin -inform DER -in "$WORK/spki.der") \
    -signature "$WORK/signature.der" "$WORK/payload" >/dev/null 2>&1 \
    || die "the device-root signature over the new anchor does not verify"

  local encoded_sig encoded_spki
  encoded_sig="$("$(tool base64)" -w0 "$WORK/signature.der")"
  encoded_spki="$("$(tool base64)" -w0 "$WORK/spki.der")"
  atomic_write "$ANCHOR_SPKI" "$encoded_spki"
  atomic_write "$ANCHOR_SIG" "$encoded_sig"
  atomic_write "$ANCHOR_JSON" "$json"
  printf '%s' "$json"
}

# --------------------------------------------------------------------------- #
# verify IDENTITY DIR  -> prints the anchored access profile
#
# Every check here is a refusal, never a repair. Absence included: an appliance
# with no anchor cannot prove what it was installed as, and the OTA path must
# not guess.
# --------------------------------------------------------------------------- #
verify() {
  (( $# == 2 )) || die "verify requires an identity and an anchor directory"
  local identity="$1" dir="$2"
  with_workspace
  device_root_fields "$identity"
  anchor_paths "$dir"

  for required in "$ANCHOR_JSON" "$ANCHOR_SIG" "$ANCHOR_SPKI"; do
    [[ -e "$required" ]] || die_reinstall "the access-profile anchor is absent (${required##*/})"
  done

  local json encoded_sig encoded_spki
  json="$(bounded_read "$ANCHOR_JSON" "$MAX_ANCHOR_BYTES")"
  encoded_sig="$(bounded_read "$ANCHOR_SIG" "$MAX_SIGNATURE_BYTES")"
  encoded_spki="$(bounded_read "$ANCHOR_SPKI" "$MAX_SPKI_BYTES")"

  local schema profile target policy_id seq name spki_hash
  schema="$(json_field "$json" schema)" || die_reinstall "the anchor carries no schema"
  [[ "$schema" == "$ANCHOR_SCHEMA" ]] || die_reinstall "the anchor is not $ANCHOR_SCHEMA"
  profile="$(json_field "$json" access_profile)" || die_reinstall "the anchor carries no access profile"
  target="$(json_field "$json" hardware_target)" || die_reinstall "the anchor carries no hardware target"
  policy_id="$(json_field "$json" signed_boot_trust_policy_id)" || die_reinstall "the anchor carries no trust policy id"
  seq="$(json_field "$json" anchor_seq)" || die_reinstall "the anchor carries no sequence"
  name="$(json_field "$json" device_root_name)" || die_reinstall "the anchor names no device root"
  spki_hash="$(json_field "$json" device_root_spki_sha256)" || die_reinstall "the anchor carries no device-root SPKI hash"
  validate_profile "$profile"; validate_target "$target"; validate_policy_id "$policy_id"
  validate_seq "$seq"

  # The anchor must name THIS machine's device root. An anchor lifted from
  # another appliance is a valid signature over a statement about a different
  # machine.
  [[ "$name" == "$DR_NAME" ]] \
    || die_reinstall "the anchor was signed by a different device root than this machine's"
  [[ "$spki_hash" == "$DR_SPKI_SHA256" ]] \
    || die_reinstall "the anchor's device-root key is not this machine's"

  printf '%s' "$encoded_spki" | "$(tool base64)" -d > "$WORK/spki.der" 2>/dev/null \
    || die_reinstall "the anchor's device-root key is not decodable"
  [[ "$(hex_sha256 "$WORK/spki.der")" == "$spki_hash" ]] \
    || die_reinstall "the stored device-root key is not the one the anchor names"
  printf '%s' "$encoded_sig" | "$(tool base64)" -d > "$WORK/signature.der" 2>/dev/null \
    || die_reinstall "the anchor signature is not decodable"

  # Byte-for-byte reconstruction. Verifying the signature over the FILE would
  # accept any document the file happened to contain; verifying it over the
  # document rebuilt from the parsed fields means an unparsed byte cannot ride
  # along.
  local rebuilt
  rebuilt="$(anchor_json "$profile" "$target" "$policy_id" "$seq" "$name" "$spki_hash" \
    "$(json_field "$json" enrolled_at)")"
  [[ "$rebuilt" == "$json" ]] && cmp -s -- "$ANCHOR_JSON" <(printf '%s' "$rebuilt") \
    || die_reinstall "the anchor is not in its canonical form"
  signing_payload "$json" "$WORK/payload"
  "$(tool openssl)" dgst -sha256 -verify <("$(tool openssl)" pkey -pubin -inform DER -in "$WORK/spki.der") \
    -signature "$WORK/signature.der" "$WORK/payload" >/dev/null 2>&1 \
    || die_reinstall "the access-profile anchor is not signed by this machine's device root"

  printf '%s\n' "$profile"
}

# --------------------------------------------------------------------------- #
# gate IDENTITY DIR RELEASE_PROFILE [HIGH_WATER_SEQ]
#
# The OTA-side decision. Exit 3 and the words "reinstall required" on any
# mismatch: a profile change is a change of what the appliance is.
# --------------------------------------------------------------------------- #
gate() {
  (( $# == 3 )) || die "gate requires an identity, an anchor directory and the release access profile"
  local identity="$1" dir="$2" release_profile="$3" high_water
  validate_profile "$release_profile"

  # THE HIGH-WATER IS READ, NEVER PASSED IN. An optional argument defaulting to
  # zero is a control every caller can forget, and every caller did.
  [[ -x "$TPM_STATE_HELPER" ]] \
    || die "the TPM state helper is unavailable at $TPM_STATE_HELPER; refusing to judge an anchor's freshness or authority without it"
  high_water="$("$TPM_STATE_HELPER" counter-read)" \
    || die "cannot read this machine's monotonic install counter from the TPM"
  [[ "$high_water" =~ ^[0-9]{1,16}$ ]] \
    || die "the TPM returned an unusable install counter: '$high_water'"

  local anchored
  anchored="$(verify "$identity" "$dir")"

  anchor_paths "$dir"
  local seq
  seq="$(json_field "$(cat -- "$ANCHOR_JSON")" anchor_seq)"
  # Equal is the CURRENT anchor -- this installation is the latest one the TPM
  # counter has handed out, which is the ordinary case. Anything BELOW is an
  # authentic bundle from a previous installation being put back, which is the
  # replay this counter exists for. Anything ABOVE is an anchor claiming a
  # sequence this machine's TPM has never issued, i.e. a bundle from elsewhere.
  (( seq == high_water )) \
    || die_reinstall "the access-profile anchor sequence $seq is not this machine's current install sequence $high_water"

  # THE AUTHORITY, LAST AND DECISIVE. Everything above establishes that this
  # anchor is an authentic, current statement by THIS machine's device root. None
  # of it establishes that the device root was ENTITLED to make it: an
  # empty-policy TPM key signs whatever a root shell asks it to. The write-once
  # NV record is the one thing here a privileged runtime attacker cannot rewrite.
  local target policy_id expected_binding actual_binding
  target="$(json_field "$(cat -- "$ANCHOR_JSON")" hardware_target)"
  policy_id="$(json_field "$(cat -- "$ANCHOR_JSON")" signed_boot_trust_policy_id)"
  expected_binding="$("$TPM_STATE_HELPER" profile-digest "$anchored" "$target" "$policy_id")" \
    || die "cannot derive the access-profile binding this anchor claims"
  actual_binding="$("$TPM_STATE_HELPER" profile-read)" \
    || die "cannot read this machine's access-profile binding from the TPM"
  [[ "$actual_binding" != none ]] \
    || die_reinstall "this machine's TPM holds no access-profile binding; a device-root signature alone cannot state what this appliance is"
  [[ "$actual_binding" == "$expected_binding" ]] \
    || die_reinstall "the access-profile anchor does not match the write-once binding in this machine's TPM"

  [[ "$anchored" == "$release_profile" ]] \
    || die_reinstall "this appliance was installed as '$anchored'; a release carrying access profile '$release_profile' cannot be applied by OTA"
  printf '%s\n' "$anchored"
}

usage() {
  cat >&2 <<'EOF'
usage:
  neural-ice-access-profile-anchor enroll IDENTITY DIR PROFILE TARGET TRUST_POLICY_ID SEQ ENROLLED_AT
  neural-ice-access-profile-anchor verify IDENTITY DIR
  neural-ice-access-profile-anchor gate   IDENTITY DIR RELEASE_PROFILE
EOF
  exit 2
}

command_name="${1:-}"
shift || true
case "$command_name" in
  enroll) enroll "$@" ;;
  verify) verify "$@" ;;
  gate) gate "$@" ;;
  *) usage ;;
esac
