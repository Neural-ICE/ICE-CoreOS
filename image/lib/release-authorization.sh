#!/usr/bin/env bash
#
# The RELEASE AUTHORIZATION: what makes a digest installable, as opposed to
# merely authentic.
#
# WHY THIS FILE EXISTS (DESIGN-NOTE-0001, Finding 2). The installer already
# proved that the registry served the digest that was asked for, and the signed
# `docker` scopes in policy.json already proved that image-ci signed it. Nothing
# constrained WHICH digest could be asked for. `neuralice.osimage=` was read
# from the live installer's kernel command line -- unauthenticated, and editable
# at the GRUB prompt -- so a CUSTOMER medium could be pointed at a perfectly
# image-ci-signed `debug` digest and would install it: serial root autologin,
# sshd enabled, SELinux permissive. The install-time access gate could not catch
# it, because it deliberately reads the MEDIUM's profile, and on the registry
# path the medium is not the thing being installed. Refusing the medium's SSH
# KEY does not refuse the medium's IMAGE.
#
# THE PROPERTY THIS RESTORES. An image digest D may be installed on a medium
# whose sealed profile is P only if a Neural-ICE-signed statement binds
# (D, variant, access_profile, hardware_target, signed-boot-trust-policy-id)
# and access_profile(D) == P -- checked against the PULLED BYTES, before any
# target mutation.
#
# WHY THE KEY IS NOT THE WEAK LINK. The verifying key lives at
# /usr/lib/neural-ice/keys/release-authorization.pub inside the installer root,
# and that root is dm-verity-enforced against a hash sealed in the signed UKI
# cmdline (installer-trust.sh). Its SHA-256 is ALSO sealed there, so a
# substituted key is a different id and the gate refuses. Without Finding 1
# fixed first this check would be theatre: an editable key verifying an editable
# policy is a circle.
#
# AUTHENTIC IS NOT THE SAME AS CURRENT. An earlier revision validated
# `issued_at` and `image_platform` for SHAPE and then never used either. A
# signed statement that is never checked for freshness is a bearer token with no
# expiry: a hostile mirror holding one formerly-authorised index/child pair could
# serve it for ever, under the right key and the right scope, and every check
# passed. So this file requires two more things of an authorization:
#
#   * its `issuance_seq` must be STRICTLY GREATER than the sequence high-water
#     this machine keeps in TPM NV (ota/neural-ice-tpm-state.sh), precisely
#     because a full-disk wipe is what an attacker does before replaying;
#   * its `image_platform` must be the platform actually being installed, both as
#     requested and as the pulled object reports itself.
#
# 🔴 THE CLOCK IS NOT A SECURITY INPUT (review 2026-09-01, P1 #4). Freshness used
# to be an age window applied to `issued_at`, judged against `date -u +%s` -- the
# firmware RTC, which anybody with the machine in front of them can set. Rolling
# it back kept an unconsumed captured authorization inside its window
# indefinitely, and the NV high-water only helped AFTER consumption. So the
# decision is now made from a SIGNED MONOTONIC SEQUENCE and from a TPM counter,
# neither of which a clock can move. `issued_at` is still required, still
# shape-checked and still logged -- as information. Nothing is decided from it.
#
# INDEX/CHILD CONFUSION IS A NAMED ATTACK HERE, NOT AN EDGE CASE. For an OCI
# INDEX, `podman image inspect .Digest` is the PLATFORM CHILD manifest while
# `.RepoDigests` keeps the INDEX digest that was requested. A check that
# consulted only one of the two would let a hostile mirror answer an index
# request with a child, or swap the child under a correct index. So the
# authorization binds BOTH digests and the gate requires BOTH to match.
#
# 🔴 AND A SINGLE-MANIFEST PUBLICATION IS A FIRST-CLASS SHAPE (review
# 2026-09-01, P1 #5). This file used to refuse any authorization whose two
# digests were equal, on the reasoning that an index which IS its own child
# collapses the distinction. That reasoning is right for an index and wrong for
# the object this repository actually publishes: `ci/build-image.sh` pushes ONE
# arm64 manifest, for which the repository digest and the platform manifest
# digest are the same object -- so no valid authorization could describe the
# published artefact and the secured registry path was unusable. The shape is
# therefore DECLARED, in the signed document, and the equality rule follows from
# it:
#
#   image_publication_shape = single-manifest -> the two digests MUST be equal
#   image_publication_shape = index           -> the two digests MUST differ
#
# Equality is never inferred and never tolerated by accident: an `index`
# authorization whose digests collapse is still refused, and a multi-arch
# publication still requires a distinct, recursively signed index and child.

if [[ -z "${NEURAL_ICE_RELEASE_AUTH_LIB_LOADED:-}" ]]; then
  NEURAL_ICE_RELEASE_AUTH_LIB_LOADED=1

  readonly NEURAL_ICE_RELEASE_AUTH_SCHEMA="neural-ice-installer-release-authorization-v2"
  # Domain separation. The same key must never be usable to make one signed
  # statement stand in for another; the domain is prefixed to the bytes that are
  # actually signed, exactly as the OTA verifier does for its own documents.
  readonly NEURAL_ICE_RELEASE_AUTH_DOMAIN="neural-ice:installer:release-authorization:v2"
  # The authorization is a handful of short fields. Bounding it means a hostile
  # medium cannot hand the installer a gigabyte to parse.
  readonly NEURAL_ICE_RELEASE_AUTH_MAX_BYTES=4096
  readonly NEURAL_ICE_RELEASE_AUTH_MAX_SIGNATURE_BYTES=1024
  # Closed world. `deny_unknown_fields` in one word: a producer that adds a
  # field this installer does not understand must be REFUSED, not silently
  # ignored -- the ignored field could be the one that mattered.
  readonly NEURAL_ICE_RELEASE_AUTH_FIELDS=(
    access_profile
    hardware_target
    image_index_digest
    image_manifest_digest
    image_platform
    image_publication_shape
    image_repository
    issuance_id
    issuance_seq
    issued_at
    key_id
    schema
    signed_boot_trust_policy_id
    variant
  )
  # The largest issuance sequence any reader in this tree will accept -- the same
  # IEEE-754 safe integer the OTA contract uses everywhere else, so a sequence
  # cannot be a value one reader rounds and another does not.
  readonly NEURAL_ICE_RELEASE_AUTH_MAX_SEQ=9007199254740991
fi

release_auth_tool() { # $1=tool name — injectable ONLY under the unprivileged test harness
  local name=$1
  if [[ -n "${NEURAL_ICE_RELEASE_AUTH_TEST_TOOLS:-}" ]]; then
    [[ "${NEURAL_ICE_RELEASE_AUTH_TESTING:-}" == 1 && "${EUID:-$(id -u)}" -ne 0 ]] || {
      echo "a release-authorization tool override is forbidden in a privileged process" >&2
      return 1
    }
    local path="$NEURAL_ICE_RELEASE_AUTH_TEST_TOOLS/$name"
    [[ -x "$path" ]] || { echo "required tool is unavailable: $path" >&2; return 1; }
    printf '%s' "$path"
    return 0
  fi
  command -v -- "$name" >/dev/null 2>&1 || { echo "required tool is unavailable: $name" >&2; return 1; }
  command -v -- "$name"
}

# --------------------------------------------------------------------------- #
# Parse. Strict, closed-world, and it prints the fields as `key=value` lines in
# a fixed order so callers compare values rather than re-parse JSON.
#
# python3 rather than jq: the installer image ships python3 already (the
# autoinstaller uses it for policy.json) and adds no packages by design. Using a
# tool that is not there is a check that silently does not run.
# --------------------------------------------------------------------------- #
release_auth_parse() { # $1=path to the authorization JSON
  if (( $# != 1 )); then
    echo "release_auth_parse requires an authorization path" >&2
    return 2
  fi
  local path=$1 size
  [[ -f "$path" && ! -L "$path" ]] || {
    echo "release authorization is missing or not a regular file: $path" >&2
    return 1
  }
  size="$(wc -c < "$path" | tr -d '[:space:]')"
  (( size > 0 && size <= NEURAL_ICE_RELEASE_AUTH_MAX_BYTES )) || {
    echo "release authorization has an implausible size ($size bytes): $path" >&2
    return 1
  }

  local expected_fields python_bin
  python_bin="$(release_auth_tool python3)" || return 1
  printf -v expected_fields '%s,' "${NEURAL_ICE_RELEASE_AUTH_FIELDS[@]}"
  NEURAL_ICE_RELEASE_AUTH_EXPECTED="${expected_fields%,}" \
  NEURAL_ICE_RELEASE_AUTH_SCHEMA_ENV="$NEURAL_ICE_RELEASE_AUTH_SCHEMA" \
  "$python_bin" - "$path" <<'PYEOF'
import ipaddress, json, os, re, sys

path = sys.argv[1]
expected = os.environ["NEURAL_ICE_RELEASE_AUTH_EXPECTED"].split(",")
schema = os.environ["NEURAL_ICE_RELEASE_AUTH_SCHEMA_ENV"]


def refuse(reason):
    print(f"release authorization is invalid: {reason}", file=sys.stderr)
    raise SystemExit(1)


raw = open(path, "rb").read()
# A duplicate JSON key is not a formatting quirk: json.loads keeps the LAST
# occurrence, so `{"access_profile":"customer-locked","access_profile":"lab-managed"}`
# would parse as lab-managed while a human (and a signature reviewer) reads the
# first. Refuse the document rather than pick a winner.
def no_duplicates(pairs):
    seen = set()
    for key, value in pairs:
        if key in seen:
            refuse(f"duplicate key {key!r}")
        seen.add(key)
    return dict(pairs)


try:
    doc = json.loads(raw.decode("utf-8"), object_pairs_hook=no_duplicates)
except Exception as error:  # noqa: BLE001 - any decode failure is a refusal
    refuse(f"not valid UTF-8 JSON ({error})")

if not isinstance(doc, dict):
    refuse("top level is not an object")
if sorted(doc) != sorted(expected):
    missing = sorted(set(expected) - set(doc))
    unknown = sorted(set(doc) - set(expected))
    refuse(f"field set differs (missing={missing}, unknown={unknown})")
for key, value in doc.items():
    if not isinstance(value, str):
        refuse(f"{key} is not a string")

PATTERNS = {
    "access_profile": r"^(lab-managed|customer-locked|developer-diagnostic)$",
    "hardware_target": r"^[a-z0-9]([a-z0-9_-]{0,62}[a-z0-9])?$",
    "image_index_digest": r"^sha256:[0-9a-f]{64}$",
    "image_manifest_digest": r"^sha256:[0-9a-f]{64}$",
    "image_platform": r"^[a-z0-9]+/[a-z0-9]+(/v[0-9]+)?$",
    "image_publication_shape": r"^(single-manifest|index)$",
    "image_repository": r"^[\x21-\x7e]{3,1024}$",
    "issuance_id": r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$",
    # A decimal string, not a JSON number: every field in this document is a
    # string so that one canonicalisation covers all of them, and so that no
    # reader can round a large integer into a different one.
    "issuance_seq": r"^[1-9][0-9]{0,15}$",
    "issued_at": r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$",
    "key_id": r"^[0-9a-f]{64}$",
    "schema": r"^" + re.escape(schema) + r"$",
    "signed_boot_trust_policy_id": r"^neural-ice-secureboot-[a-z0-9-]{1,32}$",
    "variant": r"^(debug|prod|sealed-lab)$",
}
for key, pattern in PATTERNS.items():
    if not re.match(pattern, doc[key]):
        refuse(f"{key} does not match its required form")


def canonical_registry_authority(repository):
    try:
        authority, path = repository.split("/", 1)
    except ValueError:
        refuse("image_repository has no canonical full registry authority")
    segment = r"[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?"
    parts = path.split("/")
    if not 1 <= len(parts) <= 8 or any(not re.fullmatch(segment, part) for part in parts):
        refuse("image_repository path is not canonical")

    if authority.startswith("["):
        close = authority.find("]")
        if close < 0:
            refuse("image_repository has no canonical full registry authority")
        literal, suffix = authority[1:close], authority[close + 1:]
        try:
            address = ipaddress.IPv6Address(literal)
        except ValueError:
            refuse("image_repository has no canonical full registry authority")
        if address.compressed != literal or (suffix and not suffix.startswith(":")):
            refuse("image_repository has no canonical full registry authority")
        port = suffix[1:] if suffix else ""
        has_port = bool(suffix)
    else:
        if authority.count(":") > 1:
            refuse("image_repository has no canonical full registry authority")
        host, separator, port = authority.rpartition(":")
        if not separator:
            host, port = authority, ""
        has_port = bool(separator)
        if all(char in "0123456789." for char in host):
            try:
                if str(ipaddress.IPv4Address(host)) != host:
                    raise ValueError
            except ValueError:
                refuse("image_repository has no canonical full registry authority")
        elif host != "localhost":
            labels = host.split(".")
            if len(labels) < 2 or len(host) > 253 or any(
                not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                for label in labels
            ):
                refuse("image_repository has no canonical full registry authority")
    if has_port and (not re.fullmatch(r"[1-9][0-9]{0,4}", port) or int(port) > 65535):
        refuse("image_repository has no canonical full registry authority")
    return authority


canonical_registry_authority(doc["image_repository"])

# The variant -> profile mapping is the same total function the image build
# derives the marker from (image/lib/access-policy.sh). An authorization whose
# two fields disagree is internally inconsistent, and the honest response to an
# inconsistent signed statement is to refuse it, not to prefer one half.
MAPPING = {
    "prod": "customer-locked",
    "sealed-lab": "lab-managed",
    "debug": "developer-diagnostic",
}
if MAPPING[doc["variant"]] != doc["access_profile"]:
    refuse(
        f"variant {doc['variant']!r} does not carry access profile {doc['access_profile']!r}"
    )
if int(doc["issuance_seq"]) > 9007199254740991:
    refuse("issuance_seq exceeds the safe integer range")

# THE PUBLICATION SHAPE DECIDES THE EQUALITY RULE, and it is declared rather than
# inferred. A single-manifest publication has ONE object: the repository digest
# and the platform manifest digest name it, so they must be equal. An OCI index
# has two, and an index that IS its own child would collapse the distinction the
# pair exists to preserve.
if doc["image_publication_shape"] == "single-manifest":
    if doc["image_index_digest"] != doc["image_manifest_digest"]:
        refuse(
            "a single-manifest publication names one object, but the repository "
            "digest and the platform manifest digest differ"
        )
elif doc["image_index_digest"] == doc["image_manifest_digest"]:
    refuse("an index publication may not be its own platform manifest")

for key in expected:
    print(f"{key}={doc[key]}")
PYEOF
}

# --------------------------------------------------------------------------- #
# Verify the signature over the DOMAIN-SEPARATED bytes, with the signing key
# pinned by identity. `key_id` inside the document must equal the SHA-256 of the
# public key file used to verify it -- so a document cannot nominate a key it
# was not actually signed with, and the caller can require that same id to equal
# the one sealed in the UKI cmdline.
#   $1 authorization path   $2 detached signature path   $3 public key path
# --------------------------------------------------------------------------- #
release_auth_verify_signature() {
  if (( $# != 3 )); then
    echo "release_auth_verify_signature requires authorization, signature and public key" >&2
    return 2
  fi
  local doc=$1 sig=$2 key=$3 workspace payload actual_keyid claimed_keyid size path
  local sha256_bin cosign_bin

  for path in "$doc" "$sig" "$key"; do
    [[ -f "$path" && ! -L "$path" ]] || {
      echo "release authorization input is missing or not a regular file: $path" >&2
      return 1
    }
  done
  size="$(wc -c < "$sig" | tr -d '[:space:]')"
  (( size > 0 && size <= NEURAL_ICE_RELEASE_AUTH_MAX_SIGNATURE_BYTES )) || {
    echo "release authorization signature has an implausible size ($size bytes)" >&2
    return 1
  }

  sha256_bin="$(release_auth_tool sha256sum)" || return 1
  cosign_bin="$(release_auth_tool cosign)" || return 1

  claimed_keyid="$(release_auth_parse "$doc" | sed -n 's/^key_id=//p')" || return 1
  actual_keyid="$("$sha256_bin" "$key" | awk '{print tolower($1)}')"
  [[ "$claimed_keyid" == "$actual_keyid" ]] || {
    echo "the release authorization names key $claimed_keyid but was verified against $actual_keyid" >&2
    return 1
  }

  workspace="$(mktemp -d "${TMPDIR:-/tmp}/ni-release-auth.XXXXXX")" || return 1
  payload="$workspace/payload"
  { printf '%s\0' "$NEURAL_ICE_RELEASE_AUTH_DOMAIN"; cat -- "$doc"; } > "$payload" || {
    rm -rf -- "$workspace"; return 1
  }
  local rc=0
  "$cosign_bin" verify-blob --key "$key" --insecure-ignore-tlog=true \
    --signature "$sig" "$payload" >/dev/null 2>&1 || rc=$?
  rm -rf -- "$workspace"
  (( rc == 0 )) || {
    echo "the release authorization signature does not verify against the sealed key" >&2
    return 1
  }
}

_release_auth_field() { # $1=parsed lines  $2=key
  sed -n "s/^$2=//p" <<<"$1"
}

# python3 rather than `date -d`: the installer image ships python3 already, and
# GNU `date`'s parser accepts a great deal more than the one syntax this field is
# allowed to be.
# RFC 3339 UTC -> integer seconds. INFORMATIONAL ONLY since P1 #4: it is used to
# render an issuance time in the install log and in the tests, never to decide
# whether an authorization may be used.
release_auth_epoch() { # $1=RFC 3339 'Z' timestamp
  local stamp=$1 python_bin
  [[ "$stamp" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] || {
    echo "'$stamp' is not an RFC 3339 UTC timestamp" >&2
    return 1
  }
  python_bin="$(release_auth_tool python3)" || return 1
  "$python_bin" -c '
import calendar, sys, time
try:
    print(calendar.timegm(time.strptime(sys.argv[1], "%Y-%m-%dT%H:%M:%SZ")))
except ValueError:
    raise SystemExit(1)
' "$stamp"
}

# --------------------------------------------------------------------------- #
# GATE 1 — the REQUEST, evaluated before a single byte is pulled and long before
# anything on the target disk is touched.
#
#   $1 parsed authorization (`key=value` lines from release_auth_parse)
#   $2 sealed anchor        (`key=value` lines from installer_trust_read_sealed)
#   $3 the requested image reference, digest-pinned
#   $4 the issuance-sequence high-water this machine keeps in TPM NV
#   $5 the platform this install selected
#
# The authorization must agree with the medium on all three identities the UKI
# sealed, and the digest the operator asked for must be the one the
# authorization names. That last clause is what stops `neuralice.osimage=` from
# choosing the image: the karg no longer selects, it only has to MATCH.
#
# THERE IS NO CURRENT TIME IN THIS SIGNATURE. It used to take `now` and a maximum
# age and judge `issued_at` against them; both came from the firmware RTC, which
# is exactly what an attacker with the machine in front of them can move. See the
# header note on P1 #4.
# --------------------------------------------------------------------------- #
release_auth_gate_request() {
  if (( $# != 5 )); then
    echo "release_auth_gate_request requires the authorization, the sealed anchor, the requested reference, the consumed issuance high-water and the selected platform" >&2
    return 2
  fi
  local auth=$1 sealed=$2 requested=$3 high_water=$4 platform=$5

  [[ "$high_water" =~ ^[0-9]{1,16}$ ]] || {
    echo "the issuance high-water must be a non-negative integer (got '$high_water')" >&2
    return 1
  }
  [[ "$platform" =~ ^[a-z0-9]+/[a-z0-9]+(/v[0-9]+)?$ ]] || {
    echo "the selected image platform is not a plain os/arch[/variant]: '$platform'" >&2
    return 1
  }

  [[ "$requested" =~ ^[A-Za-z0-9./_:-]+@sha256:[0-9a-f]{64}$ ]] || {
    echo "the requested image reference is not digest-pinned: $requested" >&2
    return 1
  }
  local auth_schema auth_profile auth_target auth_policy auth_keyid auth_index auth_repo
  auth_schema="$(_release_auth_field "$auth" schema)"
  auth_profile="$(_release_auth_field "$auth" access_profile)"
  auth_target="$(_release_auth_field "$auth" hardware_target)"
  auth_policy="$(_release_auth_field "$auth" signed_boot_trust_policy_id)"
  auth_keyid="$(_release_auth_field "$auth" key_id)"
  auth_index="$(_release_auth_field "$auth" image_index_digest)"
  auth_repo="$(_release_auth_field "$auth" image_repository)"

  local sealed_schema sealed_profile sealed_target sealed_policy sealed_keyid
  sealed_schema="$(_release_auth_field "$sealed" neuralice.relauth_schema)"
  sealed_profile="$(_release_auth_field "$sealed" neuralice.access_profile)"
  sealed_target="$(_release_auth_field "$sealed" neuralice.hardware_target)"
  sealed_policy="$(_release_auth_field "$sealed" neuralice.trust_policy_id)"
  sealed_keyid="$(_release_auth_field "$sealed" neuralice.relauth_keyid)"

  [[ -n "$sealed_schema" && -n "$sealed_profile" && -n "$sealed_target" && -n "$sealed_policy" && -n "$sealed_keyid" ]] || {
    echo "the sealed installer trust anchor is incomplete; refusing to authorise anything against it" >&2
    return 1
  }
  [[ "$auth_schema" == "$NEURAL_ICE_RELEASE_AUTH_SCHEMA" && "$auth_schema" == "$sealed_schema" ]] || {
    echo "the release authorization schema '$auth_schema' is not the exact schema '$sealed_schema' sealed by this medium" >&2
    return 1
  }
  [[ "$auth_profile" == "$sealed_profile" ]] || {
    echo "the release authorization is for access profile '$auth_profile' but this medium is sealed to '$sealed_profile'" >&2
    return 1
  }
  [[ "$auth_target" == "$sealed_target" ]] || {
    echo "the release authorization is for hardware target '$auth_target' but this medium is sealed to '$sealed_target'" >&2
    return 1
  }
  [[ "$auth_policy" == "$sealed_policy" ]] || {
    echo "the release authorization names trust policy '$auth_policy' but this medium is sealed to '$sealed_policy'" >&2
    return 1
  }
  [[ "$auth_keyid" == "$sealed_keyid" ]] || {
    echo "the release authorization was signed by key $auth_keyid, which this medium does not seal ($sealed_keyid)" >&2
    return 1
  }
  [[ "${requested##*@}" == "$auth_index" ]] || {
    echo "the requested digest ${requested##*@} is not the authorised release digest $auth_index" >&2
    return 1
  }
  # The repository is bound too. Same digest, different repository is still a
  # different supply chain -- and a mirror is only safe because the digest, not
  # the server, is the authority; that argument needs the name pinned as well.
  [[ "${requested%@*}" == "$auth_repo" ]] || {
    echo "the requested repository ${requested%@*} is not the authorised one $auth_repo" >&2
    return 1
  }

  # THE PLATFORM. `image_platform` was validated for shape and then ignored, so
  # an authorization issued for one architecture authorised an install of
  # another. It is bound here to what this install actually selected, and again
  # in the pulled-object gate to what the bytes say they are.
  local auth_platform
  auth_platform="$(_release_auth_field "$auth" image_platform)"
  [[ "$auth_platform" == "$platform" ]] || {
    echo "the release authorization is for platform '$auth_platform' but this install selected '$platform'" >&2
    return 1
  }

  # FRESHNESS AND REPLAY, decided by a signed monotonic sequence and a TPM
  # counter. An authorization at or below the machine's high-water is a REPLAY of
  # one this machine has already consumed -- including the case where an attacker
  # kept the medium, wiped the disk and rolled the clock back, none of which
  # moves a TPM counter.
  local auth_seq
  auth_seq="$(_release_auth_field "$auth" issuance_seq)"
  [[ "$auth_seq" =~ ^[1-9][0-9]{0,15}$ ]] || {
    echo "the release authorization carries no usable issuance sequence" >&2
    return 1
  }
  (( auth_seq <= NEURAL_ICE_RELEASE_AUTH_MAX_SEQ )) || {
    echo "the release authorization's issuance sequence is out of range" >&2
    return 1
  }
  (( auth_seq > high_water )) || {
    echo "the release authorization is issuance sequence $auth_seq, at or below the $high_water this machine has already consumed; refusing a replay" >&2
    return 1
  }
  # The caller records this as the new high-water AFTER the install commits, so a
  # refused or crashed attempt does not burn a valid authorization. `issued_at`
  # travels with it as INFORMATION -- it is never compared with a clock.
  printf 'consumed_issuance_seq=%s\n' "$auth_seq"
  printf 'issuance_id=%s\n' "$(_release_auth_field "$auth" issuance_id)"
  printf 'issued_at=%s\n' "$(_release_auth_field "$auth" issued_at)"
}

# --------------------------------------------------------------------------- #
# GATE 2 — the PULLED BYTES. Everything above was a statement about an image;
# this is a question asked of the object that actually landed in local storage.
#
#   $1 parsed authorization
#   $2 sealed anchor
#   $3 index digest observed locally      (from .RepoDigests)
#   $4 platform manifest digest observed  (from .Digest)
#   $5 access policy read out of the pulled object's /usr
#   $6 appliance variant read out of the pulled object's /usr
#   $7 hardware target read out of the pulled object's /usr
#   $8 signed-boot trust policy id LABEL on the pulled object
#   $9 platform the pulled object reports (os/arch[/variant])
# --------------------------------------------------------------------------- #
release_auth_gate_pulled() {
  if (( $# != 9 )); then
    echo "release_auth_gate_pulled requires the authorization, the sealed anchor, both observed digests and the five inspected image facts" >&2
    return 2
  fi
  local auth=$1 sealed=$2 got_index=$3 got_manifest=$4
  local img_profile=$5 img_variant=$6 img_target=$7 img_policy=$8 img_platform=$9

  local auth_index auth_manifest auth_profile auth_variant auth_target auth_policy
  auth_index="$(_release_auth_field "$auth" image_index_digest)"
  auth_manifest="$(_release_auth_field "$auth" image_manifest_digest)"
  auth_profile="$(_release_auth_field "$auth" access_profile)"
  auth_variant="$(_release_auth_field "$auth" variant)"
  auth_target="$(_release_auth_field "$auth" hardware_target)"
  auth_policy="$(_release_auth_field "$auth" signed_boot_trust_policy_id)"

  # THE OBSERVED SHAPE MUST BE THE DECLARED SHAPE. A single-manifest publication
  # resolves to one object, so the two observed digests are the same; an index
  # resolves to two, and observing one where two were promised (or the reverse)
  # is a mirror answering a different question than the one that was authorised.
  local auth_shape
  auth_shape="$(_release_auth_field "$auth" image_publication_shape)"
  case "$auth_shape" in
    single-manifest)
      [[ "$got_index" == "$got_manifest" ]] || {
        echo "the authorization declares a single-manifest publication but the pulled object has a repository digest ($got_index) distinct from its platform manifest ($got_manifest)" >&2
        return 1
      }
      ;;
    index)
      [[ "$got_index" != "$got_manifest" ]] || {
        echo "the authorization declares an OCI index but the pulled object's repository digest and platform manifest digest are the same ($got_index)" >&2
        return 1
      }
      ;;
    *)
      echo "the release authorization declares no usable publication shape ('$auth_shape')" >&2
      return 1
      ;;
  esac

  # Both digests, both directions. An index answered with its child, or a child
  # swapped under a correct index, fails exactly one of these two lines.
  [[ "$got_index" == "$auth_index" ]] || {
    echo "the pulled object's index digest ($got_index) is not the authorised one ($auth_index)" >&2
    return 1
  }
  [[ "$got_manifest" == "$auth_manifest" ]] || {
    echo "the pulled object's platform manifest digest ($got_manifest) is not the authorised one ($auth_manifest)" >&2
    return 1
  }

  # The pulled image must SAY what the authorization CLAIMS. A signed statement
  # about an image is not a property of the image until the bytes agree.
  access_policy_is_known "$img_profile" || {
    echo "the pulled image carries no recognised immutable access policy ('$img_profile')" >&2
    return 1
  }
  [[ "$img_profile" == "$auth_profile" ]] || {
    echo "the pulled image states access profile '$img_profile' but the authorization binds '$auth_profile'" >&2
    return 1
  }
  [[ "$img_variant" == "$auth_variant" ]] || {
    echo "the pulled image states variant '$img_variant' but the authorization binds '$auth_variant'" >&2
    return 1
  }
  # And the mapping must still hold on the bytes themselves, independently of
  # what the authorization said about it.
  local derived
  derived="$(access_policy_for_variant "$img_variant" 2>/dev/null)" || {
    echo "the pulled image states a variant with no defined access policy: '$img_variant'" >&2
    return 1
  }
  [[ "$derived" == "$img_profile" ]] || {
    echo "the pulled image's variant '$img_variant' does not derive its own access policy '$img_profile'" >&2
    return 1
  }
  [[ "$img_target" == "$auth_target" ]] || {
    echo "the pulled image is built for hardware target '$img_target' but the authorization binds '$auth_target'" >&2
    return 1
  }
  [[ "$img_policy" == "$auth_policy" ]] || {
    echo "the pulled image is labelled trust policy '$img_policy' but the authorization binds '$auth_policy'" >&2
    return 1
  }
  # The platform the BYTES report, not the one that was requested. An index that
  # answered a linux/arm64 request with a linux/amd64 child fails here even
  # though both digests could be made to line up.
  local auth_platform
  auth_platform="$(_release_auth_field "$auth" image_platform)"
  [[ "$img_platform" == "$auth_platform" ]] || {
    echo "the pulled image reports platform '$img_platform' but the authorization binds '$auth_platform'" >&2
    return 1
  }

  # Finally, the medium. This is the clause that stops a customer-locked medium
  # installing a signed `debug` image: the sealed profile and the image's own
  # profile must be the same word.
  local sealed_profile sealed_target
  sealed_profile="$(_release_auth_field "$sealed" neuralice.access_profile)"
  sealed_target="$(_release_auth_field "$sealed" neuralice.hardware_target)"
  [[ "$img_profile" == "$sealed_profile" ]] || {
    echo "this medium is sealed to access profile '$sealed_profile' and may not install an image whose profile is '$img_profile'" >&2
    return 1
  }
  [[ "$img_target" == "$sealed_target" ]] || {
    echo "this medium is sealed to hardware target '$sealed_target' and may not install an image built for '$img_target'" >&2
    return 1
  }
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  _relauth_self_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  # shellcheck source=image/lib/access-policy.sh
  source "$_relauth_self_dir/access-policy.sh"
  command_name=${1:-}
  shift || true
  case "$command_name" in
    parse) release_auth_parse "$@" ;;
    verify-signature) release_auth_verify_signature "$@" ;;
    gate-request) release_auth_gate_request "$@" ;;
    gate-pulled) release_auth_gate_pulled "$@" ;;
    epoch) release_auth_epoch "$@" ;;
    *)
      echo "usage: $0 {parse DOC|verify-signature DOC SIG KEY|epoch RFC3339|gate-request AUTH SEALED REF HIGH_WATER PLATFORM|gate-pulled AUTH SEALED INDEX MANIFEST PROFILE VARIANT TARGET POLICY PLATFORM}" >&2
      exit 2
      ;;
  esac
fi
