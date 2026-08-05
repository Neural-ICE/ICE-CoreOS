#!/usr/bin/env bash
# Open-core boundary: no sovereign PRODUCT ENDPOINT may be hardcoded in this repo.
#
# THE RULE, and why it is drawn here rather than somewhere stricter:
#
#   ALLOWED    the project name — `neural-ice`, `/etc/neural-ice/`, unit names
#              like `neural-ice-hostname-init`, and the build registry
#              `ghcr.io/neural-ice` that the producer authenticates to. A name is
#              neither a secret nor an address; renaming the tree would break
#              every installed appliance for no security gain. This is already
#              the de-facto rule enforced by test-build-image-dispatch-contract.sh,
#              which REQUIRES `REGISTRY: ghcr.io/neural-ice` while REFUSING
#              `registry.neural-ice.ch` — this file only writes it down so the
#              question stops being reopened.
#
#   FORBIDDEN  the sovereign product's ENDPOINTS — the registry that serves signed
#              artifacts, the licensing authority, any mirror host. These are
#              deployment identity: a third party must be able to clone, build and
#              run this OS against their own infrastructure. They are supplied by
#              the composer (ICE-Fabric injects them into /etc/neural-ice/ota.conf
#              at appliance composition) or by repository configuration — never by
#              this source tree.
#
# Scope of THIS test: the shipped overlay, the image build inputs and the CI
# entry points. `tools/ni-ota-verify/` is deliberately NOT covered yet — its
# hardcoded trusted-time authority is a security control that must move to a
# compile-time constant rather than simply disappear, and its test fixtures need
# neutral values. Extending this test to that tree is the follow-up; leaving the
# gap silent would be worse than naming it here.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

failures=0
fail() { echo "FAIL: $*" >&2; failures=$((failures + 1)); }

# Endpoints of the sovereign deployment. Extend this list, never shrink it.
FORBIDDEN=(
  "registry.neural-ice.ch"
  "licensing.neural-ice.ch"
)

# Paths that must stay free of them: what the image ships, and what builds it.
COVERED=(
  "image/bootc-overlay"
  "image/build-preloaded.sh"
  "image/build-installer-usb.sh"
  "image/Containerfile.bootc"
  "ci/build-image.sh"
  ".github/workflows"
)

echo "open-core boundary: refusing sovereign endpoints in the shipped tree"
for needle in "${FORBIDDEN[@]}"; do
  for path in "${COVERED[@]}"; do
    [ -e "$path" ] || continue
    # This file necessarily names what it forbids — exclude only itself.
    hits="$(grep -rlF -- "$needle" "$path" 2>/dev/null | grep -v '^ci/test-open-core-boundary\.sh$' || true)"
    if [ -n "$hits" ]; then
      while IFS= read -r hit; do
        [ -n "$hit" ] || continue
        fail "sovereign endpoint '$needle' is hardcoded in $hit"
        grep -nF -- "$needle" "$hit" | sed 's/^/       /' >&2
      done <<< "$hits"
    fi
  done
done

# The three fetch-side keys must stay UNSET in the vanilla overlay: the composer
# supplies them. A commented example is fine; an active assignment is not.
OTA_CONF="image/bootc-overlay/etc/neural-ice/ota.conf"
if [ -f "$OTA_CONF" ]; then
  for key in registry channel_ref bundle_ref; do
    if grep -qE "^[[:space:]]*${key}=" "$OTA_CONF"; then
      fail "$OTA_CONF assigns ${key}= — it is composer-supplied product config, not OS config"
    fi
  done
fi

if [ "$failures" -ne 0 ]; then
  echo "open-core boundary tests: $failures FAILURE(S)" >&2
  exit 1
fi
echo "open-core boundary tests: PASS"
