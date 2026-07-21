#!/usr/bin/env bash
# Fail before an expensive build if any final PRELOADED output name is already owned.

preloaded_require_fresh_output_set() {
  if (( $# != 3 )); then
    echo "preloaded_require_fresh_output_set requires repo root, output name and compression" >&2
    return 2
  fi
  local repo_root=$1
  local output_name=$2
  local compression=$3
  local raw="$repo_root/${output_name}.img"
  local artifact
  local path
  local output_parent
  local write_probe

  case "$compression" in
    zstd-fast|zstd-max) artifact="${raw}.zst" ;;
    xz) artifact="${raw}.xz" ;;
    none) artifact="$raw" ;;
    *) echo "invalid COMPRESS: $compression" >&2; return 2 ;;
  esac

  local -a outputs=(
    "$raw"
    "${artifact}.sha256"
    "${raw}.final-media.json"
    "${raw}.final-media.json.sha256"
  )
  if [[ "$artifact" != "$raw" ]]; then
    outputs+=("$artifact")
  fi

  output_parent="$(dirname -- "$raw")"
  if [[ ! -d "$output_parent" || -L "$output_parent" ]]; then
    echo "PRELOADED output parent must be an existing real directory: $output_parent" >&2
    return 1
  fi
  write_probe="$(mktemp "$output_parent/.neural-ice-output-preflight.XXXXXX")" || {
    echo "PRELOADED output parent is not writable: $output_parent" >&2
    return 1
  }
  rm -f -- "$write_probe" || {
    echo "cannot clean PRELOADED output-parent write probe: $write_probe" >&2
    return 1
  }

  for path in "${outputs[@]}"; do
    if [[ -e "$path" || -L "$path" ]]; then
      echo "refusing to overwrite existing PRELOADED output: $path" >&2
      return 1
    fi
  done
}
