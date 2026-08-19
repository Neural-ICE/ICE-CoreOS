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
# debug|sealed-lab|prod API for the default-branch producer.
require_fixed "  workflow_dispatch:" "$WORKFLOW"
require_fixed "  repository_dispatch:" "$WORKFLOW"
require_fixed "VARIANT: \${{ github.event_name == 'workflow_dispatch' && 'debug' || github.event.client_payload.variant }}" "$WORKFLOW"
require_fixed "  validate-request:" "$WORKFLOW"
require_fixed "runs-on: [self-hosted, Linux, X64]" "$WORKFLOW"
require_fixed "permissions: {}" "$WORKFLOW"
require_fixed 'if [ "$EVENT_NAME" = workflow_dispatch ] && [ "$REQUEST_REF" != refs/heads/main ]; then' "$WORKFLOW"
require_fixed "needs: validate-request" "$WORKFLOW"
# `gb10` is part of the contract, not decoration: seven runners answer `spark`
# and only spark-63 holds the immutable artifact store this job materialises
# from. Asserting the label here is what keeps the pin from being dropped as
# noise -- it was previously a comment in the workflow and a lottery in fact.
require_fixed "runs-on: [self-hosted, Linux, ARM64, spark, gb10]" "$WORKFLOW"
# build-kernel shares that store (same concurrency group) and so shares the pin.
# Asserting only one of the pair is how the other drifts back.
require_fixed "runs-on: [self-hosted, Linux, ARM64, spark, gb10]" \
  "$REPO_ROOT/.github/workflows/build-kernel.yml"

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

# --------------------------------------------------------------------------- #
# The variant set is validated in THREE independent places, and nothing made
# them agree. `sealed-lab` was added to two of them and the build failed at the
# third — 26 seconds in, on the real runner, with `invalid VARIANT`. The cost was
# a wasted dispatch; the cost of the same gap on a variant that only diverges
# LATER would be an image built under the wrong posture.
#
# This asserts the three sites accept exactly the same set, whatever that set is.
# --------------------------------------------------------------------------- #
# The three shell sites are EXERCISED, not grepped. Grepping proved vacuous
# twice: first the prose explaining a variant satisfied it as well as the code,
# then — after stripping comments — the variant's own name inside the rejection
# MESSAGE kept satisfying it. A name can appear in a file that refuses it.
#
# An accepted variant fails LATER (missing artifacts, missing context); a
# rejected one fails ON THE VARIANT. That difference is the contract.
for variant in prod sealed-lab debug; do
  # These probes are MEANT to fail — that is the measurement. Without `|| true`
  # `set -e` kills the suite on the first one, and a pipe to tail then hides the
  # exit code so it looks green.
  out="$(VARIANT="$variant" ARTIFACTS_DIR=/nonexistent timeout 20 "$BUILDER" 2>&1 | head -1)" || true
  case "$out" in
    *"invalid VARIANT"*)
      echo "ci/build-image.sh REFUSES variant '$variant' — the variant sites disagree, and the build dies 26s in on the real runner" >&2
      exit 1 ;;
  esac
  ctx="$(mktemp -d)"
  out="$(timeout 20 "$REPO_ROOT/ci/verify-build-context.sh" "$ctx" "$variant" 2>&1 | head -1)" || true
  rmdir "$ctx" 2>/dev/null || true
  case "$out" in
    *"invalid VARIANT"*)
      echo "ci/verify-build-context.sh REFUSES variant '$variant'" >&2
      exit 1 ;;
  esac
done

# …and the check is non-vacuous only if an UNKNOWN variant is still refused.
out="$(VARIANT=definitely-not-a-variant ARTIFACTS_DIR=/nonexistent timeout 20 "$BUILDER" 2>&1 | head -1)" || true
case "$out" in
  *"invalid VARIANT"*) : ;;
  *) echo "ci/build-image.sh ACCEPTED an unknown variant — the gate is open" >&2; exit 1 ;;
esac

# The two declarative sites can only be read, not run.
variant_sites=(
  ".github/workflows/build-image.yml"
  "image/Containerfile.bootc"
)
for variant in prod sealed-lab debug; do
  for site in "${variant_sites[@]}"; do
    [ -f "$REPO_ROOT/$site" ] || { echo "missing variant site: $site" >&2; exit 1; }
    # Comment lines are STRIPPED first. Grepping the whole file made this check
    # vacuous: the prose explaining a variant satisfied it just as well as the
    # code implementing it, and a mutation that deleted the executable line
    # passed because the comment above it survived. Measured, not assumed.
    # NOT `sed … | grep -q`. Under `set -o pipefail`, grep -q exits on the first
    # match, sed dies of SIGPIPE, and the pipeline reports 141 — so a MATCH reads
    # as an ABSENCE. Measured here: every variant reported "unknown" while the
    # code contained it. Capture first, then match.
    site_code="$(sed 's/[[:space:]]*#.*$//' "$REPO_ROOT/$site")"
    grep -Fq -- "$variant" <<<"$site_code" \
      || { echo "variant '$variant' is unknown to the CODE of $site — the variant sites disagree, and a build will fail at whichever one was missed" >&2; exit 1; }
  done
done
echo "variant sites agree on prod|sealed-lab|debug: PASS"
