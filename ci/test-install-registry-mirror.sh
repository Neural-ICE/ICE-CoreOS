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
# containers/image resolves sigstore attachments by the physical (mirror)
# location; without this the sealed policy refuses the mirrored image as
# unsigned (bench 2026-09-06).
check "sigstore attachments are enabled for the mirror location" -F '/etc/containers/registries.d/99-neural-ice-install-mirror.yaml'
check "the mirror sigstore entry names the mirror scope"      -F '  $INSTALL_MIRROR/$_scope:'
check "the mirror sigstore entry enables attachments"         -F '    use-sigstore-attachments: true'
# The file is one YAML document: the header is written once, outside the scope
# loop; a header per scope is a duplicate mapping key and a refused pull.
check "the mirror sigstore YAML header is written once, before the loop" -F "printf 'docker:\\n' > /etc/containers/registries.d/99-neural-ice-install-mirror.yaml"
if grep -A3 'registries.d/99-neural-ice-install-mirror.yaml <<EOF' "$S" | grep -q '^docker:$'; then
  printf '  FAIL  the mirror sigstore heredoc repeats the docker: header per scope\n'; fail=1
else
  printf '  ok    the mirror sigstore heredoc carries only scope entries\n'
fi
check "the target is checked for a leaked mirror sigstore file" -F '"$dep"/etc/containers/registries.d/*neural-ice-install-mirror*'
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

# --------------------------------------------------------------------------- #
# The seed that arrives over the LAN (FAB-0057 P1.1, docs/SEED-FROM-MIRROR.md).
# The mirror serves the closure's OBJECTS as well as the OS root, and the same
# argument carries it: nothing is used before it hashes to a sealed name or to
# a name the sealed closure gives it.
check "the seed source is an explicit kernel argument"          -F 'neuralice.seed_source'
check "a mirror-sourced seed refuses a stray ni-seed partition" \
  -F 'seals neuralice.seed_source=mirror and carries an ni-seed partition'
check "a mirror-sourced seed requires the registry source"     \
  -F 'neuralice.seed_source=mirror requires neuralice.source=registry'
check "a mirror-sourced seed requires the pinned mirror CA"    \
  -F 'neuralice.seed_source=mirror requires a LAN mirror whose CA this medium pins'
check "a mirror-sourced seed requires the signed preseal set"  \
  -F 'neuralice.seed_source=mirror requires the signed preseal set'
check "the seed-pack transport is pinned https/TLS1.2 with the sealed CA" \
  -F '"--proto", "=https", "--tlsv1.2", "--cacert", self.cacert,'
check "every fetched object is bounded by --max-filesize"      -F '"--max-filesize", str(max(limit, 1)),'
check "the helper counts bytes itself as the real ceiling"     -F 'if count > limit:'
check "an object is published only by atomic rename"           -F 'os.replace(temporary, destination)'
check "a hash mismatch is a verdict, not a retry"              -F 'not the sha256:{expected_hex} it is named by'
check "the seed-pack closure layer must be the sealed closure" \
  -F "the seed pack's release-closure.json is not the closure this medium seals"
check "the fetched pack is reconciled with the preseal release" \
  -F 'assert_seed_is_the_preseal_release "$SEED_PACK_DIR"'
check "the staged closure is re-hashed against the sealed value before planning" \
  -F 'assert_sealed_document_digest "$destination/release-closure.json" "$SEED_CLOSURE"'
check "READY is written last, by create-new"                    -F 'os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444'
# THE ORDERING PROPERTIES. The documents are fetched BEFORE the first disk
# write, so a refusal there leaves the machine as it was; the objects are
# fetched AFTER the data volume exists, and the verifier runs on what landed.
preflight_line="$(grep -nF 'seed_from_mirror_preflight "$_seed_partuuid"' "$S" | head -1 | cut -d: -f1)"
materialize_line="$(grep -nF 'seed_from_mirror_materialize "$_seed_dst"' "$S" | head -1 | cut -d: -f1)"
luks_line="$(grep -nE '^[[:space:]]*cryptsetup luksFormat' "$S" | head -1 | cut -d: -f1)"
if [ -z "$luks_line" ]; then
  luks_line="$(grep -nF 'enroll_luks "$DATAP" data' "$S" | head -1 | cut -d: -f1)"
fi
staged_verify_line="$(grep -nF -- '--seed-root "$_seed_dst"' "$S" | head -1 | cut -d: -f1)"
if [ -n "$preflight_line" ] && [ -n "$destructive_line" ] && [ "$preflight_line" -lt "$destructive_line" ]; then
  printf '  ok    the seed-pack fetch precedes the first disk write (line %s < %s)\n' "$preflight_line" "$destructive_line"
else
  printf '  FAIL  the seed-pack fetch must precede the first disk write (preflight=%s, first write=%s)\n' \
    "${preflight_line:-none}" "${destructive_line:-none}"; fail=1
fi
if [ -n "$materialize_line" ] && [ -n "$luks_line" ] && [ "$materialize_line" -gt "$luks_line" ] \
   && [ -n "$staged_verify_line" ] && [ "$staged_verify_line" -gt "$materialize_line" ]; then
  printf '  ok    the objects land after LUKS (line %s > %s) and are verified after landing (line %s)\n' \
    "$materialize_line" "$luks_line" "$staged_verify_line"
else
  printf '  FAIL  the objects must land after LUKS and be verified after landing (materialize=%s, luks=%s, verify=%s)\n' \
    "${materialize_line:-none}" "${luks_line:-none}" "${staged_verify_line:-none}"; fail=1
fi

# --------------------------------------------------------------------------- #
# The three implicit terms (FAB-0057 P1.1b). Each was sealed twice; each is now
# derived from a value the signed line already fixes, and the checks that used
# to consume the sealed term are unchanged. What is asserted: the derivation
# exists, it reads a document ALREADY hashed against the sealed value, the
# restatement is refused by the installer itself (not only by the grammar), and
# the order is the one the design needs.
check "rule C: the manifest hash is derived from the closure, never read"  -F 'seed_manifest_hash_from_closure()'
check "rule C: a restated seed_manifest is refused by the installer itself" \
  -F 'this medium restates neuralice.seed_manifest beside the sealed release closure'
check "rule C: the ni-seed closure is hashed before the manifest hash is read from it" \
  -F 'assert_sealed_document_digest "$SEED_VERIFIED_ROOT/release-closure.json" "$SEED_CLOSURE"'
check "rule C: the mirror closure is hashed before the manifest hash is read from it" \
  -F 'assert_sealed_document_digest "$SEED_PACK_DIR/release-closure.json" "$SEED_CLOSURE"'
check "rule C: the fetcher proves the closure before it judges the manifest layer" \
  -F "is not the release manifest the sealed closure names"
check "rule C: the verifier is still handed the expected manifest"     -F -- '--expect-manifest "sha256:${SEED_MANIFEST_SHA256}"'
check "rule C: release/MANIFEST is still written"                       -F '> /run/seed-dst/release/MANIFEST'
check "rule A: with seed_source=mirror the READY pins are the sealed closure" -F 'MIRROR_READY_SHA256="$SEED_CLOSURE"'
check "rule A: ...and the manifest hash that closure carries"            -F 'MIRROR_READY_MANIFEST_SHA256="$SEED_MANIFEST_SHA256"'
check "rule A: a restated READY pin is refused by the installer itself" \
  -F 'restates neuralice.mirror_ready/mirror_manifest'
check "rule B: the pair is read from the preseal set"                    -F 'release_authorization_pins_from_preseal()'
check "rule B: the set is staged and hashed against neuralice.preseal FIRST" \
  -F 'esp_staged_file preseal/preseal-set.json "$PRESEAL_SET_SHA256"'
check "rule B: a restated pair is refused by the installer itself" \
  -F 'restates neuralice.relauth_sha256/relauth_sig_sha256'
# The ESP pair is still staged by the same call, in the same place, for both
# the derived and the sealed pins.
if [ "$(grep -cF 'esp_staged_file release-authorization.json "$RELEASE_AUTH_DOC_SHA256"' "$S")" = 1 ] \
   && [ "$(grep -cF 'esp_staged_file release-authorization.sig "$RELEASE_AUTH_SIG_SHA256"' "$S")" = 1 ]; then
  printf '  ok    rule B: the pair is staged once, by the same esp_staged_file, whichever way the pins arrived\n'
else
  printf '  FAIL  rule B: the pair must be staged exactly once by esp_staged_file\n'; fail=1
fi
# ORDER. The seed pack is fetched from the mirror block, after READY is fetched
# and before READY is judged on all three fields; the pins are derived before
# the pair is staged; and everything is still before the first disk write.
fetch_call_line="$(grep -nF 'seed_from_mirror_fetch_documents "$(seed_partition_partuuid)"' "$S" | head -1 | cut -d: -f1)"
ready_fetch_line="$(grep -nF -- '--output "$_mirror_ready_json" "https://${INSTALL_MIRROR}${MIRROR_READY_PATH}"' "$S" | head -1 | cut -d: -f1)"
ready_judge_line="$(grep -nF '&& "${_mirror_ready_fields[1]:-}" == "$MIRROR_READY_MANIFEST_SHA256"' "$S" | head -1 | cut -d: -f1)"
pins_call_line="$(grep -nF 'release_authorization_pins_from_preseal "$_auth_scratch"' "$S" | head -1 | cut -d: -f1)"
pair_stage_line="$(grep -nF 'esp_staged_file release-authorization.json "$RELEASE_AUTH_DOC_SHA256"' "$S" | head -1 | cut -d: -f1)"
derive_line="$(grep -nF 'SEED_MANIFEST_SHA256="$(seed_manifest_hash_from_closure "$SEED_VERIFIED_ROOT/release-closure.json")"' "$S" | head -1 | cut -d: -f1)"
verify_line="$(grep -nF -- '--seed-root "$SEED_VERIFIED_ROOT"' "$S" | head -1 | cut -d: -f1)"
if [ -n "$fetch_call_line" ] && [ -n "$ready_fetch_line" ] && [ -n "$ready_judge_line" ] \
   && [ "$ready_fetch_line" -lt "$fetch_call_line" ] && [ "$fetch_call_line" -lt "$ready_judge_line" ] \
   && [ "$ready_judge_line" -lt "$destructive_line" ]; then
  printf '  ok    rule A: READY fetched (line %s) < seed pack fetched (line %s) < READY judged on three fields (line %s) < first disk write (line %s)\n' \
    "$ready_fetch_line" "$fetch_call_line" "$ready_judge_line" "$destructive_line"
else
  printf '  FAIL  rule A: the seed pack must be fetched between the READY fetch and the READY judgement, before the first disk write (fetch=%s, pack=%s, judge=%s, write=%s)\n' \
    "${ready_fetch_line:-none}" "${fetch_call_line:-none}" "${ready_judge_line:-none}" "${destructive_line:-none}"; fail=1
fi
if [ -n "$pins_call_line" ] && [ -n "$pair_stage_line" ] && [ "$pins_call_line" -lt "$pair_stage_line" ] \
   && [ "$pair_stage_line" -lt "$destructive_line" ]; then
  printf '  ok    rule B: pins derived from the hashed set (line %s) < pair staged (line %s) < first disk write (line %s)\n' \
    "$pins_call_line" "$pair_stage_line" "$destructive_line"
else
  printf '  FAIL  rule B: the pins must be derived before the pair is staged, before the first disk write (pins=%s, stage=%s, write=%s)\n' \
    "${pins_call_line:-none}" "${pair_stage_line:-none}" "${destructive_line:-none}"; fail=1
fi
if [ -n "$derive_line" ] && [ -n "$verify_line" ] && [ "$derive_line" -lt "$verify_line" ]; then
  printf '  ok    rule C: the ni-seed manifest hash is derived (line %s) before the verifier runs (line %s)\n' "$derive_line" "$verify_line"
else
  printf '  FAIL  rule C: the manifest hash must be derived before the verifier is handed it (derive=%s, verify=%s)\n' \
    "${derive_line:-none}" "${verify_line:-none}"; fail=1
fi

# --------------------------------------------------------------------------- #
# The mirror sealed by `.local` NAME (FAB-0057 P1.1c). The name is proved
# resolvable -- by the NSS path curl/podman/skopeo take, under a timeout --
# before the READY fetch, which is the mirror's first use, and before the first
# disk write; a name that does not resolve is refused BY NAME. The proof is a
# function; the function is also executed below, against a mocked getent.
# --------------------------------------------------------------------------- #
check "the .local test is a function the generator's rule is mirrored by" -F 'mirror_host_is_mdns_name() {'
check "the name proof is a function"                              -F 'assert_mirror_name_resolves() {'
check "the proof goes through NSS, as curl/podman/skopeo do"      -F 'getent ahostsv4 "$host"'
check "the proof is bounded by a timeout"                         -F 'timeout --kill-after=2 "$MIRROR_MDNS_RESOLVE_TIMEOUT_SECONDS" getent ahostsv4'
check "a name that does not resolve is refused by name"           -F 'readonly MIRROR_NAME_UNRESOLVABLE=mirror-name-unresolvable'
check "the refusal names the mechanism"                           -F 'did not resolve by mDNS (avahi-resolve via the resolve-only avahi-daemon'
check "resolution asks the resolve-only avahi directly"           -F 'avahi-resolve -4 -n "$host"'
check "the answer is pinned in the live hosts file for NSS users" -F '> "$NEURALICE_LIVE_HOSTS"'
check "the resolver's absence is the same named refusal"          -F 'offers no socket at ${NEURALICE_AVAHI_SOCKET}'
check "the proof is only asked of a .local mirror"                -F 'if mirror_host_is_mdns_name "$INSTALL_MIRROR"; then'
check "the proof is asked of the sealed mirror karg itself"       -F '    assert_mirror_name_resolves "$INSTALL_MIRROR"'
# No NSS module: nss-mdns is not in the EL10 repositories (build refused,
# 2026-09-09). The installer image must not try to install it, and the
# appliance never inherits any of this (docs/SEED-FROM-MIRROR.md).
if grep -qE "install[[:space:]]+nss-mdns" image/Containerfile.installer; then
  printf '  FAIL  the installer image must not install nss-mdns (absent from the EL10 repositories)\n'; fail=1
else
  printf '  ok    the installer image installs no NSS module for mDNS\n'
fi
if grep -qF nss-mdns image/Containerfile.bootc; then
  printf '  FAIL  nss-mdns reached the appliance image; it is an installer-image dependency only\n'; fail=1
else
  printf '  ok    nss-mdns is not in the appliance image\n'
fi
G=image/installer/neural-ice-installer-runtime-generator.sh
if grep -qx 'disable-publishing=yes' "$G" && grep -qx 'enable-dbus=no' "$G" \
   && ! grep -v '^[[:space:]]*#' "$G" | grep -Eq 'disable-publishing=no|publish-addresses=yes|MulticastDNS=(yes|true)'; then
  printf '  ok    the generator starts avahi resolve-only and never announces\n'
else
  printf '  FAIL  the generator must start avahi with disable-publishing=yes and enable-dbus=no, and no directive may announce\n'; fail=1
fi
# THE ORDERING PROPERTY. The proof precedes the READY fetch (the first use of
# the name) and the first disk write.
proof_line="$(grep -nF '    assert_mirror_name_resolves "$INSTALL_MIRROR"' "$S" | head -1 | cut -d: -f1)"
if [ -n "$proof_line" ] && [ -n "$ready_fetch_line" ] && [ -n "$destructive_line" ] \
   && [ "$proof_line" -lt "$ready_fetch_line" ] && [ "$ready_fetch_line" -lt "$destructive_line" ]; then
  printf '  ok    the name is proved (line %s) before the READY fetch (line %s) and the first disk write (line %s)\n' \
    "$proof_line" "$ready_fetch_line" "$destructive_line"
else
  printf '  FAIL  the name must be proved before the READY fetch and the first disk write (proof=%s, ready=%s, write=%s)\n' \
    "${proof_line:-none}" "${ready_fetch_line:-none}" "${destructive_line:-none}"; fail=1
fi

# THE FUNCTIONS, EXECUTED. Lifted verbatim, as ota/test-autoinstall-kargs.sh
# lifts the argument reader; `getent` is a script on PATH whose behaviour each
# case chooses, and `timeout` is the real one -- a hung resolver is the case
# that matters most.
MDNS_TMP="$(mktemp -d "${TMPDIR:-/tmp}/ni-mirror-mdns.XXXXXX")"
trap 'rm -rf "$MDNS_TMP"' EXIT
{
  awk '/^mirror_host_is_mdns_name\(\) \{/,/^}$/' "$S"
  awk '/^assert_mirror_name_resolves\(\) \{/,/^}$/' "$S"
} > "$MDNS_TMP/proof.sh"
if ! { grep -q '^mirror_host_is_mdns_name()' "$MDNS_TMP/proof.sh" \
       && grep -q '^assert_mirror_name_resolves()' "$MDNS_TMP/proof.sh"; }; then
  printf '  FAIL  cannot extract the name proof from the installer\n'; fail=1
fi
mkdir -p "$MDNS_TMP/bin"
cat > "$MDNS_TMP/bin/getent" <<'GETENT'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${NI_TEST_GETENT_LOG:?}"
case "${NI_TEST_GETENT_MODE:?}" in
  answer)   printf '192.168.178.63  STREAM registry.neural-ice.local\n192.168.178.63  DGRAM  \n192.168.178.63  RAW    \n'; exit 0 ;;
  notfound) exit 2 ;;
  hang)     sleep 60; exit 0 ;;
  garbage)  printf 'not-an-address STREAM registry.neural-ice.local\n'; exit 0 ;;
  zero)     printf '0.0.0.0 STREAM registry.neural-ice.local\n'; exit 0 ;;
  empty)    exit 0 ;;
esac
exit 3
GETENT
chmod 0755 "$MDNS_TMP/bin/getent"
# avahi-resolve is the mechanism; getent is the proof of the pin. Same modes.
cat > "$MDNS_TMP/bin/avahi-resolve" <<'AVAHI'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${NI_TEST_AVAHI_LOG:?}"
case "${NI_TEST_GETENT_MODE:?}" in
  answer)   printf 'registry.neural-ice.local\t192.168.178.63\n'; exit 0 ;;
  notfound) echo "Failed to resolve host name 'registry.neural-ice.local': Timeout reached" >&2; exit 1 ;;
  hang)     sleep 60; exit 0 ;;
  garbage)  printf 'registry.neural-ice.local\tnot-an-address\n'; exit 0 ;;
  zero)     printf 'registry.neural-ice.local\t0.0.0.0\n'; exit 0 ;;
  empty)    exit 0 ;;
esac
exit 3
AVAHI
chmod 0755 "$MDNS_TMP/bin/avahi-resolve"
python3 - "$MDNS_TMP/avahi.socket" <<'PYSOCK'
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(sys.argv[1])
PYSOCK
run_proof() { # $1=getent mode  $2=socket path  $3=host[:port] -> installer rc; stdout+stderr in $MDNS_TMP/out
  local mode=$1 socket=$2 host=$3
  rm -f "$MDNS_TMP/getent.log" "$MDNS_TMP/avahi.log" "$MDNS_TMP/hosts"
  printf '127.0.0.1 localhost\n' > "$MDNS_TMP/hosts"
  (
    set -uo pipefail
    # The installer's own `die`/`log`; the bounds are set short here because the
    # extracted functions read them from the installer's readonly constants,
    # which the extraction deliberately leaves behind.
    # shellcheck disable=SC2329,SC2317,SC2034
    die() { echo "die: $*" >&2; exit 1; }
    # shellcheck disable=SC2329,SC2317
    log() { echo "log: $*"; }
    # shellcheck disable=SC2034
    MIRROR_NAME_UNRESOLVABLE=mirror-name-unresolvable
    # shellcheck disable=SC2034
    MIRROR_MDNS_RESOLVE_ATTEMPTS=2
    # shellcheck disable=SC2034
    MIRROR_MDNS_RESOLVE_TIMEOUT_SECONDS=1
    # shellcheck disable=SC2034
    MIRROR_MDNS_RESOLVE_PAUSE_SECONDS=0
    # shellcheck disable=SC2034
    NEURALICE_AVAHI_SOCKET="$socket"
    # shellcheck disable=SC2034
    NEURALICE_LIVE_HOSTS="$MDNS_TMP/hosts"
    export PATH="$MDNS_TMP/bin:$PATH" NI_TEST_GETENT_MODE="$mode" NI_TEST_GETENT_LOG="$MDNS_TMP/getent.log" NI_TEST_AVAHI_LOG="$MDNS_TMP/avahi.log"
    # shellcheck source=/dev/null
    . "$MDNS_TMP/proof.sh"
    assert_mirror_name_resolves "$host"
  ) > "$MDNS_TMP/out" 2>&1
}
verdict() { # $1=description $2=0|1 (ok when 0)
  if [ "$2" = 0 ]; then printf '  ok    %s\n' "$1"; else printf '  FAIL  %s\n' "$1"; fail=1; fi
}
# A refusal is: a non-zero status, the named code on stderr, and -- when given
# -- one more pattern that says WHICH refusal it was.
expect_refusal() { # $1=description $2=getent mode $3=socket [$4=extra pattern]
  local rc=0
  run_proof "$2" "$3" registry.neural-ice.local:5055 || rc=$?
  if [ "$rc" != 0 ] && grep -q 'die: mirror-name-unresolvable' "$MDNS_TMP/out" \
     && { [ -z "${4:-}" ] || grep -q -- "$4" "$MDNS_TMP/out"; }; then
    verdict "$1" 0
  else
    verdict "$1" 1
  fi
}
# The .local rule, on both sides of the line it draws.
if (
  # shellcheck source=/dev/null
  . "$MDNS_TMP/proof.sh"
  for yes in registry.neural-ice.local:5055 registry.neural-ice.local ni-coreos-93b9.local; do
    mirror_host_is_mdns_name "$yes" || exit 1
  done
  for no in 192.168.178.63:5055 bench.example.test:5000 localhost local .local foo.local.example \
    Registry.Neural-ICE.LOCAL registry.neural-ice.local. -bad.local; do
    mirror_host_is_mdns_name "$no" && exit 1
  done
  exit 0
); then
  verdict "the .local rule accepts exactly the mDNS names the grammar can seal" 0
else
  verdict "the .local rule accepts exactly the mDNS names the grammar can seal" 1
fi
# A name that resolves: accepted, the port stripped, the address logged.
rc=0; run_proof answer "$MDNS_TMP/avahi.socket" registry.neural-ice.local:5055 || rc=$?
if [ "$rc" = 0 ] && grep -q 'log: LAN mirror registry.neural-ice.local resolves by mDNS' "$MDNS_TMP/out" \
   && grep -q ' to 192.168.178.63' "$MDNS_TMP/out" && grep -qx 'ahostsv4 registry.neural-ice.local' "$MDNS_TMP/getent.log" \
   && grep -qx -- '-4 -n registry.neural-ice.local' "$MDNS_TMP/avahi.log" \
   && grep -qx '192.168.178.63 registry.neural-ice.local' "$MDNS_TMP/hosts" \
   && grep -qx '127.0.0.1 localhost' "$MDNS_TMP/hosts"; then
  verdict "a resolving .local mirror is accepted, pinned in the live hosts file and its address logged" 0
else
  verdict "a resolving .local mirror is accepted, pinned in the live hosts file and its address logged" 1
fi
# A name nothing announces: the named refusal, after exactly the bounded attempts.
expect_refusal "an unannounced .local mirror is refused by name (mirror-name-unresolvable)" \
  notfound "$MDNS_TMP/avahi.socket" 'the LAN mirror registry.neural-ice.local did not resolve by mDNS'
if [ "$(grep -c . "$MDNS_TMP/avahi.log")" = 2 ] && [ ! -e "$MDNS_TMP/getent.log" ]; then
  verdict "the unannounced name was asked exactly the bounded number of times" 0
else
  verdict "the unannounced name was asked exactly the bounded number of times" 1
fi
# A resolver that hangs: bounded by the timeout, then the same named refusal.
started=$SECONDS
expect_refusal "a hung resolver is refused by name" hang "$MDNS_TMP/avahi.socket"
elapsed=$(( SECONDS - started ))
if [ "$elapsed" -lt 12 ]; then
  verdict "the hung resolver was bounded by the timeout (${elapsed}s for two 1s attempts)" 0
else
  verdict "the hung resolver was NOT bounded by the timeout (${elapsed}s)" 1
fi
# An answer that is not an IPv4 address, the unspecified one, or nothing at all.
for bad in garbage zero empty; do
  expect_refusal "a resolver answering '$bad' is refused by name" "$bad" "$MDNS_TMP/avahi.socket"
done
# No resolver at all (the generator never started avahi): refused by name
# BEFORE getent is asked, so the message says which mechanism is missing.
expect_refusal "an absent avahi socket is refused by name, naming the socket" \
  answer "$MDNS_TMP/no-such.socket" 'offers no socket at '
if [ ! -e "$MDNS_TMP/getent.log" ] && [ ! -e "$MDNS_TMP/avahi.log" ]; then
  verdict "an absent avahi socket is refused without asking NSS" 0
else
  verdict "an absent avahi socket is refused without asking NSS" 1
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
