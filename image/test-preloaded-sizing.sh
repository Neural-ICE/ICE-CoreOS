#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=image/lib/preloaded-sizing.sh
source "$ROOT/image/lib/preloaded-sizing.sh"

gib=$((1024 * 1024 * 1024))
mib=$((1024 * 1024))
store=$((20 * gib))
models=$((30 * gib))
payload=$((70 * gib))

without_payload="$(preloaded_seed_growth_bytes "$store" "$models" 0)"
with_payload="$(preloaded_seed_growth_bytes "$store" "$models" "$payload")"
expected=$((((store + models + payload) + (store + models + payload) / 10 + 4 * gib + mib - 1) / mib * mib))

[[ "$with_payload" == "$expected" ]]
(( with_payload > without_payload + payload ))
(( with_payload % mib == 0 ))

if preloaded_seed_growth_bytes -1 0 0 >/dev/null 2>&1; then
  echo "negative seed size was accepted" >&2
  exit 1
fi
if preloaded_seed_growth_bytes 9223372036854775807 1 0 >/dev/null 2>&1; then
  echo "overflowing seed size was accepted" >&2
  exit 1
fi

grep -qx 'TimeoutStartSec=2h' "$ROOT/image/payload/neural-ice-payload-apply.service"
echo "PRELOADED_SIZING_TEST_OK"
