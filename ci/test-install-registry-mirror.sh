#!/usr/bin/env bash
# Constrains the install-time LAN registry mirror (FAB-0040 deployment bench).
#
# The mirror exists so one medium serves both a bench and a customer. Three
# properties carry that, and each one below fails loudly if it is ever dropped:
#   1. the image reference is never rewritten -- only a mirror is added;
#   2. the mirror is digest-only, so a hostile mirror cannot substitute content;
#   3. the mirror does not survive onto the installed appliance.
#
# Property 3 is the one that needs a TEST rather than a comment: it is asserted
# by a block that runs once, at install time, on hardware nobody watches.
# shellcheck disable=SC2016
# Every `$` below is deliberately literal: this file greps the installer for the
# exact source text of its guards, so `"$dep"` and `"$source_imgref"` must reach
# grep unexpanded. Expanding them would silently turn each check into a search
# for the empty string -- which always matches, and would make this whole file
# pass while constraining nothing.
set -euo pipefail
cd "$(dirname "$0")/.."
S=ota/neural-ice-autoinstall.sh
fail=0
check() { # $1=description  $2..=grep args
  local d="$1"; shift
  if grep -q "$@" "$S"; then printf '  ok    %s\n' "$d"
  else printf '  FAIL  %s\n' "$d"; fail=1; fi
}

check "the mirror is read from an explicit kernel argument" -F 'neuralice.mirror='
check "the mirror value is validated as a bare host[:port]" -F '^[A-Za-z0-9._-]+(:[0-9]{1,5})?$'
check "the mirror is digest-only"                           -F 'pull-from-mirror = "digest-only"'
check "the drop-in lands in the LIVE environment only"      -F '/etc/containers/registries.conf.d/99-neural-ice-install-mirror.conf'
check "the target is checked for a leaked mirror drop-in"   -F '"$dep"/etc/containers/registries.conf.d/*neural-ice-install-mirror*'
check "a leaked drop-in is removed, not merely reported"    -E 'rm -f -- "\$\{_leaked\[@\]\}"'

# The original authority comes only from the required digest-pinned image ref.
# There is deliberately no built-in product endpoint or fallback authority.
check "registry authority is parsed from explicit osimage"  -F 'INSTALL_REGISTRY_AUTHORITY="${_image_ref_lines[1]}"'
check "mirror keeps the configured original authority"       -F 'location = "$INSTALL_REGISTRY_AUTHORITY/$_scope"'
check "mirror without registry source fails closed"           -F 'neuralice.mirror requires neuralice.source=registry'
check "short-name fallback is explicitly refused"             -F 'no short-name/default fallback is available'
check "raw and signed authorities must be identical"          -F 'raw registry authority'
check "resolved and configured authorities must be identical" -F 'container tooling resolved authority'
if grep -qF 'INSTALL_REGISTRY_AUTHORITY="${' "$S" && ! grep -qF 'INSTALL_REGISTRY_AUTHORITY="${_image_ref_lines[1]}"' "$S"; then
  printf '  FAIL  registry authority has an implicit default or fallback\n'; fail=1
else
  printf '  ok    registry authority has no implicit default or fallback\n'
fi

# A trailing `[[ ]] && cmd` as the LAST statement of the script would make the
# unit fail on the common path. Cheap to check, impossible to spot in review.
if [ "$(tail -n 1 "$S" | grep -cE '^\[\[.*\]\] &&')" != 0 ]; then
  printf '  FAIL  the script ends on a conditional && list; it would exit non-zero when the condition is false\n'; fail=1
else
  printf '  ok    the script does not end on a conditional && list\n'
fi

# --------------------------------------------------------------------------- #
# The registry install source (FAB-0040 light medium).
#
# This path installs bytes that arrived over the network, so every guard below
# is the difference between "digest-pinned and signature-verified" and "whatever
# the LAN served".
check "the install source is an explicit kernel argument"    -F 'neuralice.source='
check "the appliance image is an explicit kernel argument"   -F 'neuralice.osimage='
check "the appliance image must be digest-pinned"            -F 'sha256:[0-9a-f]{64}'
# 🔴 ONE SIGNATURE-POLICY READER, AND IT IS ASKED TWICE (independent review
# 2026-09-02, P1 #2). The installer used to carry nine lines of inline Python
# that checked only that SOME covering scope existed. It now calls the same
# implementation the producer runs, from the signed read-only /usr -- once before
# the pull, and once with the index and platform-child digests the object
# actually resolved to, which is the recursive proof.
check "a registry install requires a signed docker scope"    -F 'refusing an install nothing would verify'
check "the policy reader is the shared one, from the signed /usr" \
  -F '/usr/lib/neural-ice/registry-authorisation.py'
check "the policy must bind the OBJECT, not just the repository" \
  -F -- '--require-object-binding'
check "the observed index/child pair is re-put to the policy reader" \
  -F -- '--index-digest "$got_index" --manifest-digest "$got_manifest"'
check "matchRepository is tied to the authenticated repository" \
  -F -- '--authenticated-repository "$SIGNED_IMAGE_REPOSITORY"'
check "matchRepository is tied to the authenticated index" \
  -F -- '--authenticated-index-digest "$SIGNED_IMAGE_INDEX_DIGEST"'
check "matchRepository is tied to the authenticated child" \
  -F -- '--authenticated-manifest-digest "$SIGNED_IMAGE_MANIFEST_DIGEST"'
check "optional cache READY uses Fabric store_generation" -F 'generation = document.get("store_generation")'
if grep -q 'document.get("cache_generation")' "$S"; then
  printf '  FAIL  optional cache READY still accepts the superseded cache_generation field\n'; fail=1
else
  printf '  ok    optional cache READY rejects superseded cache_generation\n'
fi
# The pulled bytes are re-checked, and BOTH digests are. For an OCI index,
# `.Digest` is the PLATFORM CHILD manifest while `.RepoDigests` keeps the INDEX
# digest that was asked for. Checking one of the two would let a hostile mirror
# answer an index request with a child, or swap the child under a correct index —
# and a mirror is only safe because the DIGEST, not the server, is the authority.
check "the pulled index digest is OBSERVED, not restated from the karg" \
  -F 'does not carry exactly one repo digest for'
check "the observed index digest is compared to the requested one" \
  -F 'is not the requested one (${OS_IMAGE##*@})'
# The child-manifest comparison lives in the library, next to the index one, so
# the two can never drift apart. Assert it where it is, not where it is called.
if grep -qF 'is not the authorised one ($auth_manifest)' image/lib/release-authorization.sh; then
  printf '  ok    the pulled child manifest digest is re-checked too\n'
else
  printf '  FAIL  the pulled child manifest digest must be re-checked against the authorization\n'; fail=1
fi
check "the installer reads the platform child manifest digest it compares" \
  -F 'got_manifest="$(podman image inspect'
# ...and the mirror's safety argument now rests on more than a digest: the
# digest itself must have been AUTHORISED for this medium before the pull
# (DESIGN-NOTE-0001 Finding 2, ADR-0015). Without this, a mirror that holds a
# perfectly image-ci-signed `debug` image is enough to open a customer appliance.
check "the requested digest must be authorised before it is pulled" \
  -F 'release_auth_gate_request "$RELEASE_AUTH"'
check "the pulled object is inspected against its authorization" \
  -F 'release_auth_gate_pulled "$RELEASE_AUTH"'
check "the authorization is signature-verified with the sealed key" \
  -F 'release_auth_verify_signature'
check "the signed UKI pins the exact v2 authorization reader" \
  -F '[[ "$SEALED_RELAUTH_SCHEMA" == "$NEURAL_ICE_RELEASE_AUTH_SCHEMA" ]]'
if grep -qF 'NEURAL_ICE_RELEASE_AUTH_SCHEMA="neural-ice-installer-release-authorization-v2"' \
    image/lib/release-authorization.sh \
    && ! grep -qF 'NEURAL_ICE_RELEASE_AUTH_SCHEMA="neural-ice-installer-release-authorization-v1"' \
      image/lib/release-authorization.sh; then
  printf '  ok    installer release authorization is strict v2 (no v1 reader)\n'
else
  printf '  FAIL  installer release authorization must be strict v2 and reject v1\n'; fail=1
fi
check "Fabric's signed issuance sequence is preserved exactly" \
  -F 'the release-authorization gate changed Fabric'\''s allocated issuance sequence'
check "bootc consumes the resolved source, not a literal"    -F -e '--source-imgref "$source_imgref"'
check "the install source cannot change after it was authorised" \
  -F '"$source_imgref" == "$RELEASE_AUTH_VERIFIED_REF"'

# THE ORDERING PROPERTY. The pull used to happen in phase 4, AFTER
# wipefs/sfdisk/luksFormat/mkfs: by the time anything about the image was known,
# the target disk was already destroyed, so "refuse" could not mean "leave the
# machine as it was". A comment cannot hold this; a line-number comparison can.
pull_line="$(grep -n 'events-backend=file pull "\$OS_IMAGE"' "$S" | head -1 | cut -d: -f1)"
destructive_line="$(grep -nE '^[[:space:]]*(wipefs|sfdisk|mkfs\.|cryptsetup luksFormat)' "$S" \
  | head -1 | cut -d: -f1)"
if [ -n "$pull_line" ] && [ -n "$destructive_line" ] && [ "$pull_line" -lt "$destructive_line" ]; then
  printf '  ok    the registry pull happens BEFORE the first disk write (line %s < %s)\n' \
    "$pull_line" "$destructive_line"
else
  printf '  FAIL  the registry pull must precede the first disk write (pull=%s, first write=%s)\n' \
    "${pull_line:-none}" "${destructive_line:-none}"; fail=1
fi

# Fabric allocates issuance_seq, but the TPM high-water must not move until the
# installed filesystem exists. The intent publication is the handoff to the
# mandatory firstboot ceremony and must sit after bootc's commit boundary.
bootc_commit_line="$(grep -nF '|| die "bootc install to-filesystem failed"' "$S" | head -1 | cut -d: -f1)"
intent_line="$(grep -nF '_initial_issuance_seq="${RELEASE_AUTH_ISSUANCE_SEQ:-0}"' "$S" | head -1 | cut -d: -f1)"
if [ -n "$bootc_commit_line" ] && [ -n "$intent_line" ] && [ "$intent_line" -gt "$bootc_commit_line" ]; then
  printf '  ok    issuance_seq handoff follows install commit (line %s > %s)\n' \
    "$intent_line" "$bootc_commit_line"
else
  printf '  FAIL  issuance_seq handoff must follow install commit (intent=%s, commit=%s)\n' \
    "${intent_line:-none}" "${bootc_commit_line:-none}"; fail=1
fi

# The default MUST remain the medium. This is the single property that keeps the
# USB path -- the one that installs appliances today -- untouched by all of the
# above.
if grep -qE '^INSTALL_SOURCE=medium$' "$S"; then
  printf '  ok    the default install source is the medium (USB path unchanged)\n'
else
  printf '  FAIL  the default install source must be `medium`; a registry default would break every offline install\n'; fail=1
fi

[ "$fail" = 0 ] || { echo "install registry mirror: FAILED"; exit 1; }
echo "install registry mirror: OK"
