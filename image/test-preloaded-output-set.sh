#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=image/lib/preloaded-output-set.sh
source "$ROOT/image/lib/preloaded-output-set.sh"

work="$(mktemp -d "${TMPDIR:-/tmp}/ni-preloaded-output-set.XXXXXX")"
trap 'rm -rf "$work"' EXIT

preloaded_require_fresh_output_set "$work" candidate zstd-fast

if preloaded_require_fresh_output_set "$work" missing/candidate zstd-fast >/dev/null 2>&1; then
  echo "missing PRELOADED output parent was accepted" >&2
  exit 1
fi

mkdir "$work/real-parent"
ln -s "$work/real-parent" "$work/linked-parent"
if preloaded_require_fresh_output_set "$work" linked-parent/candidate zstd-fast >/dev/null 2>&1; then
  echo "symlinked PRELOADED output parent was accepted" >&2
  exit 1
fi

touch "$work/candidate.img.final-media.json"
if preloaded_require_fresh_output_set "$work" candidate zstd-fast >/dev/null 2>&1; then
  echo "stale final-media receipt was accepted" >&2
  exit 1
fi

if preloaded_require_fresh_output_set "$work" candidate invalid >/dev/null 2>&1; then
  echo "invalid compression was accepted" >&2
  exit 1
fi

echo "PRELOADED_OUTPUT_SET_TEST_OK"
