#!/usr/bin/env bash
# Publish one immutable GB10 kernel candidate. It cannot move `current`: an
# Owner-controlled signing step must pair the exact vmlinuz and finalize it.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

export ARTIFACTS_ROOT="${ARTIFACTS_ROOT:-${HOME}/neural-ice/artifacts}"
export RPM_SRC="${RPM_SRC:-$HOME/neural-ice-build/output}"
export USERSPACE_SRC="${USERSPACE_SRC:-$HOME/neural-ice/image/nvidia-userspace}"
exec "$REPO_ROOT/ci/artifact-generation.sh" candidate
