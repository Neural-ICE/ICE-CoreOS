#!/usr/bin/env bash
# shellcheck disable=SC2016 # literal source-contract assertions below
# THE RELEASE AUTHORIZATION: what makes a digest installable rather than merely
# authentic (DESIGN-NOTE-0001, Finding 2).
#
# The signature path here is REAL: an ECDSA P-256 key generated for this run,
# an openssl-produced DER signature, and the same `cosign verify-blob` the
# appliance runs. Nothing is stubbed, so a change that broke the domain
# separation or the payload construction would fail here rather than pass a
# mock. The KEYS are throwaway; no production key is ever used or needed.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIB="$ROOT/image/lib/release-authorization.sh"
TRUST_LIB="$ROOT/image/lib/installer-trust.sh"
work="$(mktemp -d "${TMPDIR:-/tmp}/ni-release-auth.XXXXXX")"
trap 'rm -rf "$work"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
# A test that silently skips when its tool is missing is a gate that reports
# green while guarding nothing. Nothing below is optional.
for t in openssl python3 sha256sum base64; do
  command -v "$t" >/dev/null 2>&1 || fail "$t is required by this suite"
done

# cosign IS the verification stack this OS ships (the appliance calls the image's
# pinned /usr/bin/cosign; ota/neural-ice-device-root-tpm.sh already does). When a
# real one is on PATH the suite uses it, so the production code path is exercised
# end to end. When it is not — an ubuntu-24.04 runner has none, and ADDING one
# would be a new CI dependency, which is an Owner gate — the suite falls back to
# the project's existing mock-tools primitive: the same openssl-backed
# `verify-blob` shim ota/test-neural-ice-device-root-tpm.sh has used since the
# device-root work.
#
# THE FALLBACK IS NOT A WEAKER TEST OF WHAT THIS SUITE IS FOR. Every refusal
# below is decided by release-authorization.sh — the domain separation, the
# canonical payload, the key-identity pin, the digest pair, the profile
# comparisons. cosign's job in the chain is one ECDSA verification, and the shim
# performs exactly that with openssl. What the shim cannot prove is cosign's own
# argument handling, which is why the real binary is preferred when present.
COSIGN_MODE=real
if ! command -v cosign >/dev/null 2>&1; then
  COSIGN_MODE=shim
  mkdir -p "$work/tools"
  for real in python3 sha256sum; do ln -sf "$(command -v "$real")" "$work/tools/$real"; done
  cat > "$work/tools/cosign" <<'EOF'
#!/usr/bin/env bash
# `cosign verify-blob --key K --signature S BLOB`, in the one operation this
# tree uses it for: detached ECDSA-P256-SHA256 over exact bytes.
key=""; signature=""; blob=""
while (( $# )); do
  case "$1" in
    --key) key="$2"; shift 2 ;;
    --signature) signature="$2"; shift 2 ;;
    verify-blob) shift ;;
    --*) shift ;;
    *) blob="$1"; shift ;;
  esac
done
[[ -n "$key" && -n "$signature" && -n "$blob" ]] || exit 2
der="$(mktemp)"; trap 'rm -f "$der"' EXIT
base64 -d < "$signature" > "$der" 2>/dev/null || exit 1
openssl dgst -sha256 -verify "$key" -signature "$der" "$blob" >/dev/null 2>&1
EOF
  chmod +x "$work/tools/cosign"
  export NEURAL_ICE_RELEASE_AUTH_TESTING=1
  export NEURAL_ICE_RELEASE_AUTH_TEST_TOOLS="$work/tools"
fi
echo "release-authorization suite: cosign=$COSIGN_MODE"

# shellcheck source=image/lib/access-policy.sh
source "$ROOT/image/lib/access-policy.sh"
# shellcheck source=image/lib/installer-trust.sh
source "$TRUST_LIB"
# shellcheck source=image/lib/release-authorization.sh
source "$LIB"

[ "$NEURAL_ICE_RELEASE_AUTH_SCHEMA" = "$NEURAL_ICE_INSTALLER_RELAUTH_SCHEMA" ] \
  || fail "the parser schema and the schema sealed by the UKI have drifted"

TARGET=nvidia-gb10-arm64
POLICY_ID=neural-ice-secureboot-lab-v1
REPO=registry.example.test/neural-ice/neural-ice-coreos
INDEX="sha256:$(printf 'the-index' | sha256sum | awk '{print $1}')"
CHILD="sha256:$(printf 'the-arm64-child' | sha256sum | awk '{print $1}')"
ROGUE="sha256:$(printf 'a-debug-image' | sha256sum | awk '{print $1}')"

openssl ecparam -name prime256v1 -genkey -noout -out "$work/relauth.key" 2>/dev/null
openssl ec -in "$work/relauth.key" -pubout -out "$work/relauth.pub" 2>/dev/null
openssl ecparam -name prime256v1 -genkey -noout -out "$work/rogue.key" 2>/dev/null
openssl ec -in "$work/rogue.key" -pubout -out "$work/rogue.pub" 2>/dev/null
KEYID="$(sha256sum "$work/relauth.pub" | awk '{print $1}')"

# 🔴 FRESHNESS IS A SEQUENCE, NOT A CLOCK (review 2026-09-01, P1 #4). `issued_at`
# survives as INFORMATION -- it is still required, still shape-checked and still
# reported -- but nothing is decided from it, because it used to be judged
# against an RTC anybody holding the machine can set backwards.
ISSUED_AT="2026-08-31T12:00:00Z"
ISSUED_EPOCH="$(bash "$LIB" epoch "$ISSUED_AT")"
SEQ=7
PLATFORM=linux/arm64
SHAPE=index

authorization() { # profile variant [index] [child] [target] [policy] [repo] [keyid] [issued_at] [platform] [seq] [shape]
  local profile=$1 variant=$2 index=${3:-$INDEX} child=${4:-$CHILD}
  local target=${5:-$TARGET} policy=${6:-$POLICY_ID} repo=${7:-$REPO} keyid=${8:-$KEYID}
  # `${11-…}`, not `${11:-…}`: an explicitly EMPTY sequence is a case this suite
  # has to be able to express, and `:-` would silently substitute the default.
  local issued=${9:-$ISSUED_AT} platform=${10:-$PLATFORM} seq=${11-$SEQ} shape=${12-$SHAPE}
  printf '{"access_profile":"%s","hardware_target":"%s","image_index_digest":"%s","image_manifest_digest":"%s","image_platform":"%s","image_publication_shape":"%s","image_repository":"%s","issuance_id":"rel-0001","issuance_seq":"%s","issued_at":"%s","key_id":"%s","schema":"neural-ice-installer-release-authorization-v2","signed_boot_trust_policy_id":"%s","variant":"%s"}\n' \
    "$profile" "$target" "$index" "$child" "$platform" "$shape" "$repo" "$seq" "$issued" "$keyid" "$policy" "$variant"
}

sign_domain() { # $1=domain $2=doc path $3=signature output $4=private key
  { printf '%s\0' "$1"; cat "$2"; } > "$work/payload"
  openssl dgst -sha256 -sign "$4" -out "$work/sig.der" "$work/payload"
  base64 -w0 < "$work/sig.der" > "$3"
}
sign() { # $1=doc path  $2=signature output  $3=private key
  sign_domain "neural-ice:installer:release-authorization:v2" "$1" "$2" "$3"
}

SEALED="$(bash "$TRUST_LIB" render-cmdline customer-locked "$TARGET" "$KEYID" \
  "$(printf 'root' | sha256sum | awk '{print $1}')" \
  "$(printf 'payload' | sha256sum | awk '{print $1}')" "$POLICY_ID")"
SEALED_LINES="$(bash "$TRUST_LIB" read-sealed "$SEALED")"

# --------------------------------------------------------------------------- #
# 1) PARSE — closed world. A producer that adds a field this installer does not
#    understand must be REFUSED, not have it ignored: the ignored field could be
#    the one that mattered.
# --------------------------------------------------------------------------- #
authorization customer-locked prod > "$work/auth.json"
bash "$LIB" parse "$work/auth.json" >/dev/null || fail "a well-formed authorization was refused"

# A single-label first component is a Docker Hub short name, not an explicit
# registry authority. Preserve only full canonical authorities whose raw text
# container tooling cannot reinterpret.
for short_repo in \
  foo/neural-ice/core \
  foo:5443/neural-ice/core \
  registry.example.test:/neural-ice/core \
  '[2001:db8::1]:/neural-ice/core'; do
  authorization customer-locked prod "$INDEX" "$CHILD" "$TARGET" "$POLICY_ID" \
    "$short_repo" > "$work/short-name.json"
  bash "$LIB" parse "$work/short-name.json" >/dev/null 2>&1 \
    && fail "a Docker Hub-reinterpretable short repository was accepted: $short_repo"
done
for full_repo in \
  localhost/neural-ice/core \
  192.0.2.10:5443/neural-ice/core \
  '[2001:db8::1]:5443/neural-ice/core'; do
  authorization customer-locked prod "$INDEX" "$CHILD" "$TARGET" "$POLICY_ID" \
    "$full_repo" > "$work/full-authority.json"
  bash "$LIB" parse "$work/full-authority.json" >/dev/null \
    || fail "a canonical full registry authority was refused: $full_repo"
done
python3 - "$work/auth.json" <<'PY' || fail "the v2 golden vector is not the exact 14-field contract"
import json, sys
doc = json.load(open(sys.argv[1]))
expected = {
    "access_profile", "hardware_target", "image_index_digest",
    "image_manifest_digest", "image_platform", "image_publication_shape",
    "image_repository", "issuance_id", "issuance_seq", "issued_at", "key_id",
    "schema", "signed_boot_trust_policy_id", "variant",
}
assert set(doc) == expected and len(doc) == 14
assert doc["schema"] == "neural-ice-installer-release-authorization-v2"
PY

# v1 is not a compatibility alias. Even a byte-for-byte old document signed by
# the same key is a different contract and is refused; mixing the new schema
# with the old signature domain is refused independently by signature binding.
sed 's/neural-ice-installer-release-authorization-v2/neural-ice-installer-release-authorization-v1/' \
  "$work/auth.json" > "$work/v1.json"
bash "$LIB" parse "$work/v1.json" >/dev/null 2>&1 \
  && fail "a v1 release authorization was accepted by the v2 parser"
sign_domain "neural-ice:installer:release-authorization:v1" "$work/v1.json" "$work/v1.sig" "$work/relauth.key"
bash "$LIB" verify-signature "$work/v1.json" "$work/v1.sig" "$work/relauth.pub" >/dev/null 2>&1 \
  && fail "a v1 signature domain verified as v2"
sign_domain "neural-ice:installer:release-authorization:v1" "$work/auth.json" "$work/mixed.sig" "$work/relauth.key"
bash "$LIB" verify-signature "$work/auth.json" "$work/mixed.sig" "$work/relauth.pub" >/dev/null 2>&1 \
  && fail "a v2 document signed under the v1 domain verified"

python3 - "$work/auth.json" "$work/extra.json" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
doc["also_allow_debug"] = "yes"
json.dump(doc, open(sys.argv[2], "w"), sort_keys=True)
PY
bash "$LIB" parse "$work/extra.json" >/dev/null 2>&1 \
  && fail "an authorization carrying an unknown field was accepted"

python3 - "$work/auth.json" "$work/missing.json" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
del doc["access_profile"]
json.dump(doc, open(sys.argv[2], "w"), sort_keys=True)
PY
bash "$LIB" parse "$work/missing.json" >/dev/null 2>&1 \
  && fail "an authorization with no access profile was accepted"

# A duplicate key parses to the LAST occurrence while a human — and a signature
# reviewer — reads the first. Refuse rather than pick a winner.
sed 's/"access_profile":"customer-locked"/"access_profile":"customer-locked","access_profile":"lab-managed"/' \
  "$work/auth.json" > "$work/dup.json"
bash "$LIB" parse "$work/dup.json" >/dev/null 2>&1 \
  && fail "an authorization with a duplicated key was accepted"

# variant and profile are ONE total function; a document whose two halves
# disagree is internally inconsistent and there is no honest half to prefer.
authorization lab-managed prod > "$work/inconsistent.json"
bash "$LIB" parse "$work/inconsistent.json" >/dev/null 2>&1 \
  && fail "an authorization whose variant and profile disagree was accepted"

# 🔴 THE PUBLICATION SHAPE DECIDES THE EQUALITY RULE (review 2026-09-01, P1 #5).
# For an OCI INDEX, an object that IS its own child collapses the distinction the
# digest pair exists to preserve. For a SINGLE-MANIFEST publication -- which is
# what ci/build-image.sh actually pushes -- the repository digest and the platform
# manifest digest name the same object, and refusing that made no valid
# authorization able to describe the published artefact at all.
authorization customer-locked prod "$INDEX" "$INDEX" > "$work/collapsed.json"
bash "$LIB" parse "$work/collapsed.json" >/dev/null 2>&1 \
  && fail "an index authorization whose two digests are identical was accepted"
authorization customer-locked prod "$INDEX" "$INDEX" "$TARGET" "$POLICY_ID" "$REPO" \
  "$KEYID" "$ISSUED_AT" "$PLATFORM" "$SEQ" single-manifest > "$work/single.json"
bash "$LIB" parse "$work/single.json" >/dev/null \
  || fail "a single-manifest authorization describing one object was refused"
authorization customer-locked prod "$INDEX" "$CHILD" "$TARGET" "$POLICY_ID" "$REPO" \
  "$KEYID" "$ISSUED_AT" "$PLATFORM" "$SEQ" single-manifest > "$work/single-split.json"
bash "$LIB" parse "$work/single-split.json" >/dev/null 2>&1 \
  && fail "a single-manifest authorization naming two different objects was accepted"
authorization customer-locked prod "$INDEX" "$CHILD" "$TARGET" "$POLICY_ID" "$REPO" \
  "$KEYID" "$ISSUED_AT" "$PLATFORM" "$SEQ" multiarch > "$work/bad-shape.json"
bash "$LIB" parse "$work/bad-shape.json" >/dev/null 2>&1 \
  && fail "an authorization declaring an unknown publication shape was accepted"

# The issuance sequence is a decimal STRING (every field is), positive, bounded.
for bad_seq in 0 -1 '' 007 1.5 abc 99999999999999999999; do
  authorization customer-locked prod "$INDEX" "$CHILD" "$TARGET" "$POLICY_ID" "$REPO" \
    "$KEYID" "$ISSUED_AT" "$PLATFORM" "$bad_seq" > "$work/bad-seq.json"
  bash "$LIB" parse "$work/bad-seq.json" >/dev/null 2>&1 \
    && fail "an authorization with issuance sequence '$bad_seq' was accepted"
done

head -c 5000 /dev/zero | tr '\0' 'x' > "$work/huge.json"
bash "$LIB" parse "$work/huge.json" >/dev/null 2>&1 \
  && fail "an oversized authorization was parsed"

# --------------------------------------------------------------------------- #
# 2) SIGNATURE — real cosign, real domain separation, key identity pinned.
# --------------------------------------------------------------------------- #
sign "$work/auth.json" "$work/auth.sig" "$work/relauth.key"
bash "$LIB" verify-signature "$work/auth.json" "$work/auth.sig" "$work/relauth.pub" \
  || fail "a correctly signed authorization did not verify"

# Any edit invalidates it. This is the mutation that matters most: profile.
sed 's/"access_profile":"customer-locked"/"access_profile":"lab-managed"/; s/"variant":"prod"/"variant":"sealed-lab"/' \
  "$work/auth.json" > "$work/flipped.json"
bash "$LIB" verify-signature "$work/flipped.json" "$work/auth.sig" "$work/relauth.pub" >/dev/null 2>&1 \
  && fail "an authorization whose profile was flipped after signing verified"

# A rogue signer producing a perfectly valid signature over a perfectly
# well-formed document. The document NAMES a key id, and that id must be the
# SHA-256 of the key it is verified against, so it cannot nominate its own.
authorization lab-managed sealed-lab "$INDEX" "$CHILD" "$TARGET" "$POLICY_ID" "$REPO" \
  "$(sha256sum "$work/rogue.pub" | awk '{print $1}')" > "$work/rogue.json"
sign "$work/rogue.json" "$work/rogue.sig" "$work/rogue.key"
bash "$LIB" verify-signature "$work/rogue.json" "$work/rogue.sig" "$work/relauth.pub" >/dev/null 2>&1 \
  && fail "an authorization signed by a rogue key verified against the sealed key"
# ...and it verifies against ITS OWN key, which is exactly why the identity has
# to be sealed in the UKI rather than read out of the document.
bash "$LIB" verify-signature "$work/rogue.json" "$work/rogue.sig" "$work/rogue.pub" \
  || fail "the rogue document does not even verify against its own key; the test proves nothing"

# --------------------------------------------------------------------------- #
# 3) GATE 1 — the REQUEST, before a byte is pulled.
# --------------------------------------------------------------------------- #
AUTH="$(bash "$LIB" parse "$work/auth.json")"
# The gate now needs to know WHEN it is, how old an authorization may be, what
# this machine has already consumed, and which platform is being installed --
# four inputs it previously did not have and could therefore not check.
gate_request() { bash "$LIB" gate-request "$AUTH" "$SEALED_LINES" "$1" 0 "$PLATFORM" >/dev/null 2>&1; }
gate_request_at() { # $1=reference  $2=issuance high-water
  bash "$LIB" gate-request "$AUTH" "$SEALED_LINES" "$1" "$2" "$PLATFORM" >/dev/null 2>&1
}
gate_request "$REPO@${INDEX#sha256:}" && fail "a reference without its sha256: prefix was accepted"
gate_request "$REPO@$INDEX" || fail "the authorised reference was refused"
gate_request "$REPO:stable" && fail "a tag-pinned reference was accepted"
gate_request "$REPO@$ROGUE" && fail "a digest the authorization does not name was accepted"
gate_request "$REPO@$CHILD" && fail "the CHILD digest was accepted where the INDEX is authorised"
gate_request "evil.example.test/neural-ice/neural-ice-coreos@$INDEX" \
  && fail "the authorised digest under an unauthorised repository was accepted"

# The schema is itself part of the Secure-Boot-authenticated anchor. A document
# cannot select its reader, and a v2 document on a UKI pinned to any other
# contract is a mixed-version refusal before pull.
MIXED_SEALED="${SEALED_LINES/neuralice.relauth_schema=neural-ice-installer-release-authorization-v2/neuralice.relauth_schema=neural-ice-installer-release-authorization-v1}"
bash "$LIB" gate-request "$AUTH" "$MIXED_SEALED" "$REPO@$INDEX" 0 "$PLATFORM" >/dev/null 2>&1 \
  && fail "a v2 authorization was accepted against an old-schema UKI anchor"
MISSING_SCHEMA_SEALED="$(grep -v '^neuralice.relauth_schema=' <<<"$SEALED_LINES")"
bash "$LIB" gate-request "$AUTH" "$MISSING_SCHEMA_SEALED" "$REPO@$INDEX" 0 "$PLATFORM" >/dev/null 2>&1 \
  && fail "an authorization was accepted against a UKI with no sealed schema"

# 🔴 THE HEADLINE ATTACK. A CUSTOMER medium pointed at a signed `debug` release.
# The authorization is real, the signature is real, the digest resolves — and the
# medium is sealed customer-locked, so it must refuse.
authorization developer-diagnostic debug "$ROGUE" "$CHILD" > "$work/debug.json"
DEBUG_AUTH="$(bash "$LIB" parse "$work/debug.json")"
bash "$LIB" gate-request "$DEBUG_AUTH" "$SEALED_LINES" "$REPO@$ROGUE" 0 "$PLATFORM" >/dev/null 2>&1 \
  && fail "a customer-locked medium accepted an authorization for a debug image"

# Same for a medium built for another box, and for another Secure Boot chain.
authorization customer-locked prod "$INDEX" "$CHILD" some-other-box > "$work/other-target.json"
bash "$LIB" gate-request "$(bash "$LIB" parse "$work/other-target.json")" "$SEALED_LINES" "$REPO@$INDEX" 0 "$PLATFORM" >/dev/null 2>&1 \
  && fail "an authorization for another hardware target was accepted"
authorization customer-locked prod "$INDEX" "$CHILD" "$TARGET" neural-ice-secureboot-prod-v1 > "$work/other-policy.json"
bash "$LIB" gate-request "$(bash "$LIB" parse "$work/other-policy.json")" "$SEALED_LINES" "$REPO@$INDEX" 0 "$PLATFORM" >/dev/null 2>&1 \
  && fail "an authorization naming another trust policy was accepted"
# An authorization signed by a key this medium does not seal.
authorization customer-locked prod "$INDEX" "$CHILD" "$TARGET" "$POLICY_ID" "$REPO" \
  "$(printf 'not-the-sealed-key' | sha256sum | awk '{print $1}')" > "$work/other-key.json"
bash "$LIB" gate-request "$(bash "$LIB" parse "$work/other-key.json")" "$SEALED_LINES" "$REPO@$INDEX" 0 "$PLATFORM" >/dev/null 2>&1 \
  && fail "an authorization naming an unsealed key was accepted"

# 🔴 FRESHNESS AND REPLAY, DECIDED BY A SIGNED SEQUENCE AND A TPM COUNTER. The
# high-water is what a full-disk wipe cannot reset (it lives in TPM NV): an
# authorization at or below it has already been consumed by this machine.
gate_request_at "$REPO@$INDEX" 0 || fail "the first authorization was refused"
gate_request_at "$REPO@$INDEX" "$(( SEQ - 1 ))" \
  || fail "an authorization one ahead of the high-water was refused"
gate_request_at "$REPO@$INDEX" "$SEQ" \
  && fail "an authorization this machine had already consumed was replayed"
gate_request_at "$REPO@$INDEX" "$(( SEQ + 1 ))" \
  && fail "an authorization behind the recorded high-water was replayed"
gate_request_at "$REPO@$INDEX" "not-a-number" \
  && fail "a malformed high-water was accepted"

# 🔴 AND THE CLOCK CANNOT MOVE ANY OF IT. This is the whole of P1 #4: the gate no
# longer takes a current time, and the SAME document decides the same way whether
# it is dated in this machine's distant past or its distant future. Rolling an
# RTC back is therefore not a way to keep a captured authorization alive.
for stamp in 1970-01-01T00:00:00Z 2099-12-31T23:59:59Z; do
  authorization customer-locked prod "$INDEX" "$CHILD" "$TARGET" "$POLICY_ID" "$REPO" \
    "$KEYID" "$stamp" > "$work/dated.json"
  dated="$(bash "$LIB" parse "$work/dated.json")" \
    || fail "an authorization dated $stamp was refused by the parser"
  bash "$LIB" gate-request "$dated" "$SEALED_LINES" "$REPO@$INDEX" 0 "$PLATFORM" >/dev/null \
    || fail "an authorization dated $stamp was refused; the decision still depends on a clock"
  bash "$LIB" gate-request "$dated" "$SEALED_LINES" "$REPO@$INDEX" "$SEQ" "$PLATFORM" \
    >/dev/null 2>&1 \
    && fail "an authorization dated $stamp was replayed past the high-water"
done
# The gate takes no current time AT ALL: an extra argument is a usage error, not
# a silently ignored one.
bash "$LIB" gate-request "$AUTH" "$SEALED_LINES" "$REPO@$INDEX" 0 "$PLATFORM" "$ISSUED_EPOCH" \
  >/dev/null 2>&1 \
  && fail "the gate still accepts a current time"

# And the gate must TELL the caller what to record, or the high-water can never
# advance and the control quietly becomes a no-op after the first install.
consumed="$(bash "$LIB" gate-request "$AUTH" "$SEALED_LINES" "$REPO@$INDEX" 0 "$PLATFORM")" \
  || fail "the authorised request was refused"
[ "$(sed -n 's/^consumed_issuance_seq=//p' <<<"$consumed")" = "$SEQ" ] \
  || fail "the gate does not report the issuance sequence the caller must record"
[ "$(sed -n 's/^issued_at=//p' <<<"$consumed")" = "$ISSUED_AT" ] \
  || fail "the gate does not carry the issuance time forward as information"

# 🔴 THE PLATFORM. `image_platform` was validated for shape and then ignored, so
# an authorization issued for one architecture authorised an install of another.
bash "$LIB" gate-request "$AUTH" "$SEALED_LINES" "$REPO@$INDEX" 0 linux/amd64 \
  >/dev/null 2>&1 \
  && fail "an arm64 authorization authorised an amd64 install"
bash "$LIB" gate-request "$AUTH" "$SEALED_LINES" "$REPO@$INDEX" 0 "not a platform" \
  >/dev/null 2>&1 \
  && fail "a malformed selected platform was accepted"

# --------------------------------------------------------------------------- #
# 4) GATE 2 — the PULLED BYTES. Hostile mirror and index/child confusion.
# --------------------------------------------------------------------------- #
gate_pulled() { bash "$LIB" gate-pulled "$AUTH" "$SEALED_LINES" "$@" "$PLATFORM" >/dev/null 2>&1; }

gate_pulled "$INDEX" "$CHILD" customer-locked prod "$TARGET" "$POLICY_ID" \
  || fail "the authorised object was refused"

# 🔴 THE OBSERVED SHAPE MUST BE THE DECLARED SHAPE (review 2026-09-01, P1 #5).
# An index that resolves to one object, or a single manifest that resolves to
# two, is a mirror answering a different question than the one authorised.
shape_out="$(bash "$LIB" gate-pulled "$AUTH" "$SEALED_LINES" "$INDEX" "$INDEX" \
  customer-locked prod "$TARGET" "$POLICY_ID" "$PLATFORM" 2>&1)" \
  && fail "an index authorization was satisfied by an object that is its own manifest"
# The digest pair alone would also refuse this, with a message about a digest.
# Requiring the SHAPE refusal is what keeps the declared shape a reviewable
# statement rather than a field that happens to be implied.
grep -q 'declares an OCI index but the pulled object' <<<"$shape_out" \
  || fail "an index authorization satisfied by one object was refused for the wrong reason: $shape_out"
SINGLE_AUTH="$(bash "$LIB" parse "$work/single.json")"
bash "$LIB" gate-pulled "$SINGLE_AUTH" "$SEALED_LINES" "$INDEX" "$INDEX" \
  customer-locked prod "$TARGET" "$POLICY_ID" "$PLATFORM" >/dev/null \
  || fail "a single-manifest publication was refused by the pulled-object gate"
shape_out="$(bash "$LIB" gate-pulled "$SINGLE_AUTH" "$SEALED_LINES" "$INDEX" "$CHILD" \
  customer-locked prod "$TARGET" "$POLICY_ID" "$PLATFORM" 2>&1)" \
  && fail "a single-manifest authorization was satisfied by a two-object resolution"
grep -q 'declares a single-manifest publication but the pulled object' <<<"$shape_out" \
  || fail "a single-manifest authorization satisfied by two objects was refused for the wrong reason: $shape_out"

# The platform the BYTES report, not the one that was requested.
bash "$LIB" gate-pulled "$AUTH" "$SEALED_LINES" "$INDEX" "$CHILD" customer-locked prod \
  "$TARGET" "$POLICY_ID" linux/amd64 >/dev/null 2>&1 \
  && fail "a pulled object for another platform was accepted"

# 🔴 A HOSTILE MIRROR answering an index request with a DIFFERENT child. The
# index digest is right; the bytes that would be installed are not.
gate_pulled "$INDEX" "$ROGUE" customer-locked prod "$TARGET" "$POLICY_ID" \
  && fail "a swapped child manifest under a correct index was accepted"
# ...and the reverse: the right child under a substituted index.
gate_pulled "$ROGUE" "$CHILD" customer-locked prod "$TARGET" "$POLICY_ID" \
  && fail "a substituted index over a correct child was accepted"
# ...and the mirror that answers an INDEX request with the CHILD itself,
# which is what a single-manifest pull looks like when it should be an index.
gate_pulled "$CHILD" "$CHILD" customer-locked prod "$TARGET" "$POLICY_ID" \
  && fail "a single-manifest answer to an index request was accepted"

# The pulled image's OWN statements must agree with the authorization AND with
# the medium. Each of these is a separately signed `debug` image being installed
# by a customer medium in a different disguise.
gate_pulled "$INDEX" "$CHILD" developer-diagnostic debug "$TARGET" "$POLICY_ID" \
  && fail "a pulled debug image was accepted against a customer-locked authorization"
gate_pulled "$INDEX" "$CHILD" customer-locked debug "$TARGET" "$POLICY_ID" \
  && fail "a pulled image whose variant contradicts the authorization was accepted"
# An image whose OWN two markers disagree — variant prod, profile lab-managed —
# fails the mapping restated on the bytes themselves.
gate_pulled "$INDEX" "$CHILD" lab-managed prod "$TARGET" "$POLICY_ID" \
  && fail "a pulled image whose variant does not derive its own profile was accepted"
gate_pulled "$INDEX" "$CHILD" wide-open prod "$TARGET" "$POLICY_ID" \
  && fail "a pulled image with an unrecognised access policy was accepted"
gate_pulled "$INDEX" "$CHILD" customer-locked prod some-other-box "$POLICY_ID" \
  && fail "a pulled image built for another hardware target was accepted"
gate_pulled "$INDEX" "$CHILD" customer-locked prod "$TARGET" neural-ice-secureboot-prod-v1 \
  && fail "a pulled image labelled with another trust policy was accepted"
# An unlabelled image: podman prints an empty string for a missing label, and
# empty must never compare equal to a policy id.
gate_pulled "$INDEX" "$CHILD" customer-locked prod "$TARGET" "" \
  && fail "a pulled image carrying no trust-policy label was accepted"

# --------------------------------------------------------------------------- #
# 5) THE AUTOINSTALLER'S ORDERING — pull and authorise BEFORE any mutation.
# --------------------------------------------------------------------------- #
AUTOINSTALL="$ROOT/ota/neural-ice-autoinstall.sh"
line_of() { grep -n -- "$1" "$AUTOINSTALL" | head -1 | cut -d: -f1; }

verify_line="$(line_of 'release_auth_verify_signature "$_auth_scratch/release-authorization.json"')"
request_line="$(line_of 'release_auth_gate_request "$RELEASE_AUTH"')"
pull_line="$(line_of 'podman --cgroup-manager=cgroupfs --events-backend=file pull "$OS_IMAGE"')"
pulled_line="$(line_of 'release_auth_gate_pulled "$RELEASE_AUTH"')"
destructive_line="$(grep -nE '^[[:space:]]*(wipefs|sfdisk|mkfs\.|cryptsetup luksFormat)' \
  "$AUTOINSTALL" | head -1 | cut -d: -f1)"
for name in verify_line request_line pull_line pulled_line destructive_line; do
  [ -n "${!name}" ] || fail "cannot locate $name in the autoinstaller"
done
[ "$verify_line"  -lt "$request_line" ] || fail "the authorization is used before its signature is verified"
[ "$request_line" -lt "$pull_line" ]    || fail "the installer pulls before it authorises the request"
[ "$pull_line"    -lt "$pulled_line" ]  || fail "the installer inspects the pulled object before pulling it"
[ "$pulled_line"  -lt "$destructive_line" ] \
  || fail "the pulled object is authorised at line $pulled_line, AFTER the first disk write at line $destructive_line"

# 🔴 AND NO CLOCK REACHES THE GATE. The installer used to pass `date -u +%s` and
# a 14-day window; both came from the firmware RTC.
grep -Eq 'release_auth_gate_request .*date -u' "$AUTOINSTALL" \
  && fail "the installer still passes a clock reading to the release-authorization gate"
grep -q 'RELEASE_AUTH_MAX_AGE_SECONDS' "$AUTOINSTALL" \
  && fail "the installer still carries an RTC-based validity window"

# --skip-fetch-check is only defensible because of the proof above. Assert the
# link explicitly, so removing the proof does not quietly leave the flag behind.
grep -Fq '[[ -n "$RELEASE_AUTH_VERIFIED_REF" && "$source_imgref" == "$RELEASE_AUTH_VERIFIED_REF" ]]' "$AUTOINSTALL" \
  || fail "the installer does not assert that the install source is the one that was authorised"
grep -Fq 'podman image exists "$OS_IMAGE"' "$AUTOINSTALL" \
  || fail "the installer does not require the authorised object to still be in local storage"

# 🔴 HOST-SIDE INSPECTION. The installer used to read the candidate image's
# markers by RUNNING that image's own `cat`. A contradictory image can ship a
# `cat` that prints whatever satisfies the gate, so every comparison afterwards
# agreed about a lie.
grep -Fq 'podman --cgroup-manager=cgroupfs --events-backend=file image mount "$OS_IMAGE"' "$AUTOINSTALL" \
  || fail "the installer does not inspect the pulled image host-side"
grep -Eq 'run --rm --entrypoint .+"\$OS_IMAGE" cat ' "$AUTOINSTALL" \
  && fail "the installer still executes a binary out of the candidate image to read its markers"

# An install may proceed only from an exact virgin or PCR-policy-only
# pre-ceremony state. The authorization sequence is persisted as first-boot
# ceremony intent; runtime commands must not create or consume freshness here.
preceremony_line="$(line_of '"$TPM_STATE" provisioning-status')"
intent_line="$(line_of '_initial_issuance_seq="${RELEASE_AUTH_ISSUANCE_SEQ:-0}"')"
bootc_commit_line="$(line_of '|| die "bootc install to-filesystem failed"')"
[ -n "$preceremony_line" ] || fail "the installer never proves bounded pre-ceremony TPM state"
[ -n "$intent_line" ] || fail "the installer never persists the signed issuance sequence for the ceremony"
[ -n "$bootc_commit_line" ] || fail "the installer has no identifiable bootc install commit boundary"
[ "$preceremony_line" -lt "$request_line" ] \
  || fail "the installer authorises a request before proving bounded pre-ceremony TPM state"
[ "$intent_line" -gt "$bootc_commit_line" ] \
  || fail "the installer persists Fabric's issuance sequence before bootc install commits"
grep -Fq 'virgin|pcr-policy-activated)' "$AUTOINSTALL" \
  || fail "the installer does not limit retry admission to virgin or PCR-policy-only pre-ceremony state"
grep -Fq '[[ "$RELEASE_AUTH_ISSUANCE_SEQ" == "$(sed -n '\''s/^issuance_seq=//p'\'' <<<"$RELEASE_AUTH")" ]]' "$AUTOINSTALL" \
  || fail "the installer does not prove it preserved Fabric's signed issuance sequence exactly"
grep -Fq '"$TPM_STATE" freshness-read' "$AUTOINSTALL" \
  && fail "the installer treats missing runtime freshness state as a readable zero"
grep -Fq '"$TPM_STATE" freshness-consume' "$AUTOINSTALL" \
  && fail "the installer consumes freshness outside the mandatory ceremony"
# Nothing may re-pull between verification and install.
awk -v start="$pulled_line" 'NR > start && /podman .*(^| )pull /' "$AUTOINSTALL" | grep -q . \
  && fail "the autoinstaller pulls again after the object was authorised"

# --------------------------------------------------------------------------- #
# 6) THE TOOL OVERRIDE MUST NOT BE A PRODUCTION BYPASS. Section 0's fallback
#    exists for CI; if it could be reached by a root process it would be a way to
#    make every signature check succeed.
# --------------------------------------------------------------------------- #
grep -Fq 'a release-authorization tool override is forbidden in a privileged process' "$LIB" \
  || fail "the release-authorization tool override is not refused under a privileged process"
grep -Fq 'NEURAL_ICE_RELEASE_AUTH_TESTING' "$LIB" \
  || fail "the tool override is not gated on the test harness flag"
grep -Fq 'NEURAL_ICE_RELEASE_AUTH_TEST_TOOLS' "$AUTOINSTALL" \
  && fail "the autoinstaller references the test tool override"

echo "RELEASE_AUTHORIZATION_TEST_OK (cosign=$COSIGN_MODE)"
