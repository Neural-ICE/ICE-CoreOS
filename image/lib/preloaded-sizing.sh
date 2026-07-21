#!/usr/bin/env bash
# Internal sizing helpers for the PRELOADED installer.

PRELOADED_MIB_BYTES=$((1024 * 1024))
PRELOADED_FIXED_HEADROOM_BYTES=$((4 * 1024 * 1024 * 1024))
PRELOADED_MAX_BYTES=9223372036854775807

preloaded_seed_growth_bytes() {
  if (( $# != 3 )); then
    echo "preloaded_seed_growth_bytes requires store, models and payload byte counts" >&2
    return 2
  fi

  local store_bytes=$1
  local models_bytes=$2
  local payload_bytes=$3
  local seed_bytes
  local proportional_headroom
  local grow_bytes
  local value

  for value in "$store_bytes" "$models_bytes" "$payload_bytes"; do
    [[ "$value" =~ ^[0-9]+$ ]] || {
      echo "preloaded seed byte counts must be non-negative integers" >&2
      return 2
    }
  done

  (( store_bytes <= PRELOADED_MAX_BYTES - models_bytes )) || {
    echo "preloaded seed byte count overflow" >&2
    return 2
  }
  seed_bytes=$((store_bytes + models_bytes))
  (( seed_bytes <= PRELOADED_MAX_BYTES - payload_bytes )) || {
    echo "preloaded seed byte count overflow" >&2
    return 2
  }
  seed_bytes=$((seed_bytes + payload_bytes))
  proportional_headroom=$((seed_bytes / 10))
  (( seed_bytes <= PRELOADED_MAX_BYTES - proportional_headroom - PRELOADED_FIXED_HEADROOM_BYTES - PRELOADED_MIB_BYTES + 1 )) || {
    echo "preloaded partition size overflow" >&2
    return 2
  }
  grow_bytes=$((seed_bytes + proportional_headroom + PRELOADED_FIXED_HEADROOM_BYTES))

  printf '%s\n' "$(((grow_bytes + PRELOADED_MIB_BYTES - 1) / PRELOADED_MIB_BYTES * PRELOADED_MIB_BYTES))"
}
