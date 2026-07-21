#!/usr/bin/env bash
# The literal shell/YAML fragments below must not expand in this test process.
# shellcheck disable=SC2016
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKFLOW="$REPO_ROOT/.github/workflows/build-image.yml"
BUILDER="$REPO_ROOT/ci/build-image.sh"

fail() { echo "FAIL: $*" >&2; exit 1; }
require_fixed() {
  local needle="$1" file="$2"
  grep -Fq -- "$needle" "$file" || fail "missing contract '$needle' in ${file#"$REPO_ROOT"/}"
}
refute_fixed() {
  local needle="$1" file="$2"
  ! grep -Fq -- "$needle" "$file" || fail "forbidden contract '$needle' in ${file#"$REPO_ROOT"/}"
}

# The UI path has no knobs: it is forced to debug and rejects a branch selected
# in the workflow_dispatch branch picker. repository_dispatch keeps its explicit
# debug|prod API for the default-branch producer.
require_fixed "  workflow_dispatch:" "$WORKFLOW"
require_fixed "  repository_dispatch:" "$WORKFLOW"
require_fixed "VARIANT: \${{ github.event_name == 'workflow_dispatch' && 'debug' || github.event.client_payload.variant }}" "$WORKFLOW"
require_fixed "if: github.event_name != 'workflow_dispatch' || github.ref == 'refs/heads/main'" "$WORKFLOW"
require_fixed 'if [ "$EVENT_NAME" = workflow_dispatch ] && [ "$REQUEST_REF" != refs/heads/main ]; then' "$WORKFLOW"
require_fixed "runs-on: [self-hosted, Linux, ARM64, spark]" "$WORKFLOW"

# The producer authenticates only to GHCR. Product mirroring and channel/alias
# mutation remain outside this repo, in the signed ICE-Fabric release train.
require_fixed "REGISTRY: ghcr.io/neural-ice" "$WORKFLOW"
refute_fixed "registry.neural-ice.ch" "$WORKFLOW"
refute_fixed "OTA_REGISTRY" "$WORKFLOW"
refute_fixed "MIRROR" "$WORKFLOW"

# build-image.sh creates, pushes and reports exactly the run-unique SEMVER tag.
# These fixed anchors intentionally fail if a future edit reintroduces a second
# build tag, a channel push or a non-content-addressed handoff.
require_fixed '-t "${REF}:${SEMVER}"' "$BUILDER"
require_fixed '"${PODMAN[@]}" push --digestfile "$digest_file" "${REF}:${SEMVER}"' "$BUILDER"
require_fixed '[[ "$DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]]' "$BUILDER"
require_fixed '--build-arg "OTA_IMGREF=${REF}:${SEMVER}"' "$BUILDER"
refute_fixed 'registry.neural-ice.ch' "$BUILDER"
refute_fixed 'OTA_REGISTRY' "$BUILDER"
refute_fixed 'MIRROR' "$BUILDER"

tag_count="$(grep -Fc -- '-t "${REF}:${SEMVER}"' "$BUILDER")"
[[ "$tag_count" == 1 ]] || fail "expected exactly one immutable build tag, found $tag_count"
push_count="$(grep -Fc -- '"${PODMAN[@]}" push ' "$BUILDER")"
[[ "$push_count" == 1 ]] || fail "expected exactly one registry push, found $push_count"

echo "build-image dispatch contract tests: PASS"
