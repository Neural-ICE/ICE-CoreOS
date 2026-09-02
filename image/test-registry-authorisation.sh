#!/usr/bin/env bash
# THE CONTAINER SIGNATURE POLICY READER — ONE IMPLEMENTATION, BOTH CALLERS.
#
# 🔴 WHAT THIS SUITE EXISTS TO STOP COMING BACK (independent review 2026-09-02,
# P1 #2). There were TWO readers of /etc/containers/policy.json with DIFFERENT
# semantics, and both were permissive:
#
#   producer  image/installer/neural-ice-registry-authorisation.py rejected only
#             `insecureAcceptAnything`. A direct probe showed
#             `{"type":"typoThatMustNotAuthorize"}` exiting 0 -- an unknown
#             requirement type authorised a registry install of an appliance.
#   runtime   ota/neural-ice-autoinstall.sh carried nine lines of inline Python
#             that checked only that a covering scope EXISTED under the expected
#             authority. It never read the requirements at all.
#
# So a medium the producer accepted could carry a scope that verified nothing.
# The producer's helper is now THE implementation, staged into the medium's
# signed /usr, and the installer calls it -- twice, the second time with the
# digests the pulled object resolved to.
#
# Every negative below is a class the previous readers passed.
# It needs no root, no medium, no network and no container runtime.
# shellcheck disable=SC2016
# The policy fragments below are JSON literals: a `$` inside one is a byte of
# the document under test, never a shell expansion.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HELPER="$ROOT/image/installer/neural-ice-registry-authorisation.py"
AUTOINSTALL="$ROOT/ota/neural-ice-autoinstall.sh"
PRODUCER="$ROOT/image/build-installer-usb.sh"
CONTAINERFILE="$ROOT/image/Containerfile.installer"
RENDERER="$ROOT/image/policy/render-container-policy.sh"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/ni-registry-auth.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

for required in "$HELPER" "$AUTOINSTALL" "$PRODUCER" "$CONTAINERFILE" "$RENDERER"; do
  [ -f "$required" ] || fail "missing input: $required"
done
command -v python3 >/dev/null 2>&1 || fail "python3 is required; this suite does not SKIP"

REPOSITORY=release.example.test/neural-ice/neural-ice-coreos
AUTHORITY=release.example.test
INDEX="sha256:$(printf '%064d' 1)"
CHILD="sha256:$(printf '%064d' 2)"

ask() { # $1=policy json, rest: extra arguments -> exit status, stderr on fd 2
  printf '%s' "$1" | python3 "$HELPER" \
    --repository "$REPOSITORY" --authority "$AUTHORITY" "${@:2}"
}

accepted=0
refused=0

expect_ok() { # $1=label $2=policy, rest: extra arguments
  local label=$1 policy=$2; shift 2
  ask "$policy" "$@" > "$TMP/out" 2> "$TMP/err" \
    || { cat "$TMP/err" >&2; fail "[$label] a policy that MUST authorise was refused"; }
  accepted=$(( accepted + 1 ))
  return 0
}

expect_refused() { # $1=label $2=policy $3=reason fragment, rest: extra arguments
  local label=$1 policy=$2 fragment=$3; shift 3
  if ask "$policy" "$@" > "$TMP/out" 2> "$TMP/err"; then
    cat "$TMP/out"
    fail "[$label] a policy that must NOT authorise exited 0"
  fi
  grep -Fq "$fragment" "$TMP/err" \
    || { cat "$TMP/err" >&2; fail "[$label] refused, but not for the stated reason ('$fragment')"; }
  refused=$(( refused + 1 ))
  return 0
}

policy_with() { # $1=scope $2=requirements JSON array
  printf '{"default":[{"type":"insecureAcceptAnything"}],"transports":{"docker":{"%s":%s}}}' \
    "$1" "$2"
}

SIGSTORE_EXACT='[{"type":"sigstoreSigned","keyPath":"/usr/lib/neural-ice/keys/image-ci.pub","signedIdentity":{"type":"matchRepoDigestOrExact"}}]'
SIGSTORE_REPOSITORY='[{"type":"sigstoreSigned","keyPath":"/usr/lib/neural-ice/keys/image-ci.pub","signedIdentity":{"type":"matchRepository"}}]'
GPG_EXACT='[{"type":"signedBy","keyType":"GPGKeys","keyPath":"/usr/lib/neural-ice/keys/image-ci.gpg","signedIdentity":{"type":"matchExact"}}]'

# --------------------------------------------------------------------------- #
# 1) WHAT MUST AUTHORISE. The shipped shape, and only shapes as strong as it.
# --------------------------------------------------------------------------- #
expect_ok 'sigstoreSigned, digest-or-exact identity, exact scope' \
  "$(policy_with "$REPOSITORY" "$SIGSTORE_EXACT")" --require-object-binding
expect_ok 'a covering parent scope on a path-segment boundary' \
  "$(policy_with "$AUTHORITY/neural-ice" "$SIGSTORE_EXACT")" --require-object-binding
expect_ok 'signedBy with GPGKeys and matchExact' \
  "$(policy_with "$REPOSITORY" "$GPG_EXACT")" --require-object-binding
expect_ok 'the observed index/child pair, named' \
  "$(policy_with "$REPOSITORY" "$SIGSTORE_EXACT")" \
  --require-object-binding --index-digest "$INDEX" --manifest-digest "$CHILD"
# Repository-bound is acceptable ONLY when nobody asked for the object binding.
expect_ok 'matchRepository, without the object binding' \
  "$(policy_with "$REPOSITORY" "$SIGSTORE_REPOSITORY")"
expect_ok 'matchRepository with exact authenticated closure tuple' \
  "$(policy_with "$REPOSITORY" "$SIGSTORE_REPOSITORY")" \
  --require-object-binding --index-digest "$INDEX" --manifest-digest "$CHILD" \
  --authenticated-repository "$REPOSITORY" \
  --authenticated-index-digest "$INDEX" --authenticated-manifest-digest "$CHILD"

# --------------------------------------------------------------------------- #
# 2) 🔴 THE EXACT DEFECT THE REVIEW PROBED. An unknown or mistyped requirement
#    type used to exit 0.
# --------------------------------------------------------------------------- #
expect_refused 'the review probe: an invented requirement type' \
  "$(policy_with "$REPOSITORY" '[{"type":"typoThatMustNotAuthorize"}]')" \
  'unknown requirement type' --require-object-binding
expect_refused 'a single mistyped character in a real type' \
  "$(policy_with "$REPOSITORY" '[{"type":"sigstoreSinged","keyPath":"/k","signedIdentity":{"type":"matchExact"}}]')" \
  'unknown requirement type' --require-object-binding
expect_refused 'a type that differs only in case' \
  "$(policy_with "$REPOSITORY" '[{"type":"SignedBy","keyType":"GPGKeys","keyPath":"/k","signedIdentity":{"type":"matchExact"}}]')" \
  'unknown requirement type' --require-object-binding

# --------------------------------------------------------------------------- #
# 3) INSECURE AND NON-AUTHORISING TYPES.
# --------------------------------------------------------------------------- #
expect_refused 'insecureAcceptAnything' \
  "$(policy_with "$REPOSITORY" '[{"type":"insecureAcceptAnything"}]')" \
  'absence of an authorisation' --require-object-binding
expect_refused 'reject cannot authorise' \
  "$(policy_with "$REPOSITORY" '[{"type":"reject"}]')" \
  'can never authorise' --require-object-binding
expect_refused 'one strong requirement beside one insecure one' \
  "$(printf '{"transports":{"docker":{"%s":[{"type":"sigstoreSigned","keyPath":"/k","signedIdentity":{"type":"matchExact"}},{"type":"insecureAcceptAnything"}]}}}' "$REPOSITORY")" \
  'absence of an authorisation' --require-object-binding
expect_refused 'a strict narrow scope beside a permissive broad one' \
  "$(printf '{"transports":{"docker":{"%s":%s,"%s":[{"type":"insecureAcceptAnything"}]}}}' \
     "$REPOSITORY" "$SIGSTORE_EXACT" "$AUTHORITY/neural-ice")" \
  'absence of an authorisation' --require-object-binding

# --------------------------------------------------------------------------- #
# 4) EMPTY AND MALFORMED.
# --------------------------------------------------------------------------- #
expect_refused 'no docker transport at all' \
  '{"default":[{"type":"reject"}]}' 'no transports at all' --require-object-binding
expect_refused 'an empty docker transport' \
  '{"transports":{"docker":{}}}' 'no docker transport scopes' --require-object-binding
expect_refused 'a covering scope with an empty requirement list' \
  "$(policy_with "$REPOSITORY" '[]')" 'no signature requirement' --require-object-binding
expect_refused 'a covering scope whose requirements are not a list' \
  "$(policy_with "$REPOSITORY" '{"type":"sigstoreSigned"}')" \
  'no signature requirement' --require-object-binding
expect_refused 'an empty requirement object' \
  "$(policy_with "$REPOSITORY" '[{}]')" 'empty requirement' --require-object-binding
expect_refused 'a requirement with no type' \
  "$(policy_with "$REPOSITORY" '[{"keyPath":"/k"}]')" 'no type' --require-object-binding
expect_refused 'a requirement that is not an object' \
  "$(policy_with "$REPOSITORY" '["sigstoreSigned"]')" 'malformed requirement' --require-object-binding
expect_refused 'a policy that is not JSON' 'not json at all' 'not readable JSON' --require-object-binding
expect_refused 'a policy that is a JSON array' '[]' 'not a JSON object' --require-object-binding

# --------------------------------------------------------------------------- #
# 5) INCOMPLETE KEY / IDENTITY FIELDS. A requirement missing what it needs
#    verifies nothing at runtime, and used to read as complete here.
# --------------------------------------------------------------------------- #
expect_refused 'sigstoreSigned with no key source at all' \
  "$(policy_with "$REPOSITORY" '[{"type":"sigstoreSigned","signedIdentity":{"type":"matchExact"}}]')" \
  'key sources' --require-object-binding
expect_refused 'sigstoreSigned with two key sources' \
  "$(policy_with "$REPOSITORY" '[{"type":"sigstoreSigned","keyPath":"/a","keyData":"AAAA","signedIdentity":{"type":"matchExact"}}]')" \
  'key sources' --require-object-binding
expect_refused 'sigstoreSigned with an empty keyPath' \
  "$(policy_with "$REPOSITORY" '[{"type":"sigstoreSigned","keyPath":"   ","signedIdentity":{"type":"matchExact"}}]')" \
  'empty keyPath' --require-object-binding
expect_refused 'signedBy with no keyType' \
  "$(policy_with "$REPOSITORY" '[{"type":"signedBy","keyPath":"/k","signedIdentity":{"type":"matchExact"}}]')" \
  "missing ['keyType']" --require-object-binding
expect_refused 'signedBy with a keyType containers/image does not honour' \
  "$(policy_with "$REPOSITORY" '[{"type":"signedBy","keyType":"X509","keyPath":"/k","signedIdentity":{"type":"matchExact"}}]')" \
  'the only type containers/image honours' --require-object-binding
expect_refused 'a mistyped field name is not silently ignored' \
  "$(policy_with "$REPOSITORY" '[{"type":"sigstoreSigned","keypath":"/k","signedIdentity":{"type":"matchExact"}}]')" \
  'unknown field' --require-object-binding
expect_refused 'keyless sigstore with no transparency log' \
  "$(policy_with "$REPOSITORY" '[{"type":"sigstoreSigned","fulcio":{"caPath":"/ca","oidcIssuer":"https://issuer.example.test","subjectEmail":"ci@example.test"},"signedIdentity":{"type":"matchExact"}}]')" \
  'no rekor public key' --require-object-binding
expect_refused 'a requirement with no signedIdentity' \
  "$(policy_with "$REPOSITORY" '[{"type":"sigstoreSigned","keyPath":"/k"}]')" \
  'no signedIdentity' --require-object-binding
expect_refused 'a signedIdentity with no type' \
  "$(policy_with "$REPOSITORY" '[{"type":"sigstoreSigned","keyPath":"/k","signedIdentity":{}}]')" \
  'no type' --require-object-binding
expect_refused 'an unknown signedIdentity type' \
  "$(policy_with "$REPOSITORY" '[{"type":"sigstoreSigned","keyPath":"/k","signedIdentity":{"type":"matchWhatever"}}]')" \
  'unknown signedIdentity type' --require-object-binding
expect_refused 'remapIdentity rewrites the name a signature is checked against' \
  "$(policy_with "$REPOSITORY" '[{"type":"sigstoreSigned","keyPath":"/k","signedIdentity":{"type":"remapIdentity","prefix":"a","signedPrefix":"b"}}]')" \
  'rewrites the name' --require-object-binding
expect_refused 'remapIdentity is refused even without the object binding' \
  "$(policy_with "$REPOSITORY" '[{"type":"sigstoreSigned","keyPath":"/k","signedIdentity":{"type":"remapIdentity","prefix":"a","signedPrefix":"b"}}]')" \
  'rewrites the name'

# --------------------------------------------------------------------------- #
# 6) 🔴 WEAK SCOPE AND NON-CANONICAL AUTHORITY.
# --------------------------------------------------------------------------- #
expect_refused 'a bare registry authority authorises everything that registry serves' \
  "$(policy_with "$AUTHORITY" "$SIGSTORE_EXACT")" 'bare registry authority' --require-object-binding
expect_refused 'the docker-transport default scope is not a cover' \
  "$(printf '{"transports":{"docker":{"":%s}}}' "$SIGSTORE_EXACT")" \
  'no configured docker scope covers' --require-object-binding
expect_refused 'a scope for a different registry' \
  "$(policy_with "$REPOSITORY" "$SIGSTORE_EXACT" | sed "s|$AUTHORITY|other.example.test|")" \
  'no configured docker scope covers' --require-object-binding
expect_refused 'a scope with a scheme' \
  "$(printf '{"transports":{"docker":{"https://%s":%s}}}' "$REPOSITORY" "$SIGSTORE_EXACT")" \
  'no configured docker scope covers' --require-object-binding
# Uppercase is not a spelling of the same scope: two readers of one medium must
# not disagree about its host. Built from $AUTHORITY so this file never carries
# an endpoint literal -- ci/test-open-core-boundary.sh scans normalised bytes,
# and a lowercased uppercase literal is the same bytes.
expect_refused 'a scope with an uppercase authority' \
  "$(printf '{"transports":{"docker":{"%s":%s}}}' \
     "$(printf '%s' "$REPOSITORY" | tr '[:lower:]' '[:upper:]')" "$SIGSTORE_EXACT")" \
  'no configured docker scope covers' --require-object-binding
expect_refused 'no covering scope at all' \
  "$(policy_with "$AUTHORITY/vendor" "$SIGSTORE_EXACT")" \
  'no configured docker scope covers' --require-object-binding
# 🔴 THE PATH-SEGMENT BOUNDARY. `…/neural` must never cover `…/neural-ice/x`.
expect_refused 'a prefix that is not a path-segment boundary' \
  "$(policy_with "$AUTHORITY/neural" "$SIGSTORE_EXACT")" \
  'no configured docker scope covers' --require-object-binding

# --------------------------------------------------------------------------- #
# 7) 🔴 THE RECURSIVE OBJECT BINDING. A policy satisfied by ANY image in the
#    repository would accept a correctly signed SIBLING child under a correct
#    index -- exactly the index/child confusion the release authorization exists
#    to close. Scope existence is not a signature over the object pulled.
# --------------------------------------------------------------------------- #
expect_refused 'matchRepository does not bind the pulled object' \
  "$(policy_with "$REPOSITORY" "$SIGSTORE_REPOSITORY")" \
  'satisfied by any image in the repository' \
  --require-object-binding --index-digest "$INDEX" --manifest-digest "$CHILD"
expect_refused 'matchRepository authenticated repository mutation' \
  "$(policy_with "$REPOSITORY" "$SIGSTORE_REPOSITORY")" \
  'differs from the authenticated closure tuple' \
  --require-object-binding --index-digest "$INDEX" --manifest-digest "$CHILD" \
  --authenticated-repository "$AUTHORITY/neural-ice/other" \
  --authenticated-index-digest "$INDEX" --authenticated-manifest-digest "$CHILD"
expect_refused 'matchRepository authenticated digest mutation' \
  "$(policy_with "$REPOSITORY" "$SIGSTORE_REPOSITORY")" \
  'differs from the authenticated closure tuple' \
  --require-object-binding --index-digest "$INDEX" --manifest-digest "$CHILD" \
  --authenticated-repository "$REPOSITORY" \
  --authenticated-index-digest "$CHILD" --authenticated-manifest-digest "$CHILD"
expect_refused 'exactRepository does not bind the pulled object either' \
  "$(policy_with "$REPOSITORY" '[{"type":"sigstoreSigned","keyPath":"/k","signedIdentity":{"type":"exactRepository","dockerRepository":"release.example.test/neural-ice/neural-ice-coreos"}}]')" \
  'satisfied by any image in the repository' --require-object-binding
# ...and supplying only half of the observed pair is a usage error, not a
# quietly weaker check.
if ask "$(policy_with "$REPOSITORY" "$SIGSTORE_EXACT")" --index-digest "$INDEX" >/dev/null 2>"$TMP/err"; then
  fail "the reader accepted an index digest with no platform-child digest"
fi
grep -Fq 'supplied together or not at all' "$TMP/err" \
  || fail "half a digest pair is not reported as a usage error"
if ask "$(policy_with "$REPOSITORY" "$SIGSTORE_EXACT")" \
     --index-digest not-a-digest --manifest-digest "$CHILD" >/dev/null 2>&1; then
  fail "the reader accepted a malformed digest"
fi
# A digest supplied at all implies the object binding, so a caller holding the
# evidence for the strong question cannot accidentally ask the weak one.
if ask "$(policy_with "$REPOSITORY" "$SIGSTORE_REPOSITORY")" \
     --index-digest "$INDEX" --manifest-digest "$CHILD" >/dev/null 2>&1; then
  fail "supplying the observed digests did not imply the object binding"
fi

# --------------------------------------------------------------------------- #
# 8) BOUNDS AND INTERFACE.
# --------------------------------------------------------------------------- #
{ printf '{"transports":{"docker":{"%s":%s}},"pad":"' "$REPOSITORY" "$SIGSTORE_EXACT"
  head -c 2000000 /dev/zero | tr '\0' 'x'
  printf '"}\n'; } > "$TMP/huge"
if python3 "$HELPER" --repository "$REPOSITORY" --authority "$AUTHORITY" \
     --require-object-binding < "$TMP/huge" >/dev/null 2>"$TMP/err"; then
  fail "an oversized policy was accepted"
fi
grep -Fq 'exceeds the byte limit' "$TMP/err" || fail "an oversized policy is not refused for its size"
for bad in --repository --authority; do
  if python3 "$HELPER" "$bad" x < /dev/null >/dev/null 2>&1; then
    fail "the reader ran with only $bad"
  fi
done
if printf '{}' | python3 "$HELPER" --repository "$REPOSITORY" --authority other.example.test >/dev/null 2>&1; then
  fail "the reader accepted a repository not rooted in its authority"
fi
if printf '{}' | python3 "$HELPER" --repository 'REGISTRY/x' --authority 'REGISTRY' >/dev/null 2>&1; then
  fail "the reader accepted a non-canonical authority"
fi
if printf '{}' | python3 "$HELPER" --repository "$REPOSITORY" --authority "$AUTHORITY" --unknown-flag >/dev/null 2>&1; then
  fail "the reader accepted an unknown flag"
fi

# --------------------------------------------------------------------------- #
# 9) 🔴 ONE IMPLEMENTATION, AND BOTH CALLERS REACH IT.
# --------------------------------------------------------------------------- #
grep -Fq 'image/installer/neural-ice-registry-authorisation.py' "$PRODUCER" \
  || fail "the producer no longer calls the shared signature-policy reader"
grep -Fq -- '--require-object-binding' "$PRODUCER" \
  || fail "the producer asks the weaker, repository-bound question; the installer would then refuse the medium it cut"
grep -Fq '/usr/lib/neural-ice/registry-authorisation.py' "$AUTOINSTALL" \
  || fail "the installer no longer calls the shared signature-policy reader"
grep -Fq '/usr/lib/neural-ice/registry-authorisation.py' "$CONTAINERFILE" \
  || fail "the medium no longer stages the shared signature-policy reader into its signed /usr"
grep -Fq -- '--index-digest "$got_index" --manifest-digest "$got_manifest"' "$AUTOINSTALL" \
  || fail "the installer no longer re-asks the reader with the digests the pulled object resolved to"
# 🔴 AND THE OLD INLINE READER IS GONE, not merely bypassed. Its distinguishing
# line was a one-expression scope existence test with no requirement inspection.
grep -Fq 'sys.exit(0 if matches and all(scope.split' "$AUTOINSTALL" \
  && fail "the installer still carries its own weaker inline signature-policy reader"
python3 - "$AUTOINSTALL" <<'PYCHECK' || fail "the installer defines a second signature-policy reader"
import re, sys
source = open(sys.argv[1], encoding="utf-8").read()
# A heredoc-fed python that mentions the policy file is a second reader.
for block in re.findall(r"python3 - .*?<<'PY'\n(.*?)\nPY\n", source, re.S):
    if "policy.json" in block or "insecureAcceptAnything" in block:
        raise SystemExit(1)
PYCHECK

# The RENDERER and this reader must agree about which identities exist, or the
# appliance's own composed policy could be one this reader refuses.
renderer_identities="$(sed -n 's/^  matchRepository|matchRepoDigestOrExact|matchExact) ;;$/ok/p' "$RENDERER")"
[ "$renderer_identities" = ok ] \
  || fail "the policy renderer's accepted signedIdentity set moved; the reader and the renderer must agree"

(( accepted >= 6 )) || fail "the suite no longer proves what a VALID policy looks like"
(( refused >= 30 )) || fail "the suite no longer covers the hostile policy classes ($refused)"

echo "REGISTRY_AUTHORISATION_TEST_OK (${accepted} accepted, ${refused} refused; unknown/typo/insecure/empty/malformed/weak-scope/non-canonical-authority and repository-only identities all refused; producer and installer share one reader)"
