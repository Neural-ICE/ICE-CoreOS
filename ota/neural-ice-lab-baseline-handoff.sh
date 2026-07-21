#!/usr/bin/env bash
# Copy the optional root-signed LAB baseline receipt from installer ESP media
# into the installed system. This helper deliberately performs no JSON parsing,
# signature verification, or trust decision: those belong to ICE-Fabric.
set -euo pipefail

readonly RECEIPT_NAME="ota-lab-baseline.json"
readonly SIGNATURE_NAME="ota-lab-baseline.sig"
readonly RECEIPT_MAX_BYTES=$((16 * 1024))
readonly SIGNATURE_MAX_BYTES=$((4 * 1024))
readonly ABSENT=3

fail() {
  printf 'LAB baseline handoff: %s\n' "$*" >&2
  exit 1
}

exists_or_symlink() {
  [[ -e "$1" || -L "$1" ]]
}

file_identity() {
  local path="$1"
  stat -Lc '%i:%s' -- "$path" 2>/dev/null \
    || stat -Lf '%i:%z' -- "$path"
}

owner_group_mode() {
  local path="$1"
  stat -Lc '%u:%g:%a' -- "$path" 2>/dev/null \
    || stat -Lf '%u:%g:%Lp' -- "$path"
}

copy_checked() {
  local source="$1" destination="$2" max_bytes="$3" label="$4"
  local expected_sha256="${5:-}"
  local fd_path source_identity fd_identity final_identity size source_sha256 destination_sha256

  if [[ -n "$expected_sha256" && ! "$expected_sha256" =~ ^[0-9a-f]{64}$ ]]; then
    fail "$label expected SHA-256 is invalid"
  fi

  [[ ! -L "$source" && -f "$source" ]] \
    || fail "$label must be a regular, non-symlink file"

  exec 9<"$source" || fail "cannot open $label"
  fd_path="/proc/self/fd/9"
  [[ -e "$fd_path" ]] || fd_path="/dev/fd/9"
  [[ -e "$fd_path" ]] || fail "cannot inspect the open $label"

  source_identity="$(file_identity "$source")" || fail "cannot stat $label"
  fd_identity="$(file_identity "$fd_path")" || fail "cannot stat the open $label"
  [[ "$source_identity" == "$fd_identity" ]] \
    || fail "$label changed while it was opened"

  size="${fd_identity##*:}"
  [[ "$size" =~ ^[0-9]+$ && "$size" -gt 0 && "$size" -le "$max_bytes" ]] \
    || fail "$label must be non-empty and at most $max_bytes bytes"
  if [[ -n "$expected_sha256" ]]; then
    source_sha256="$(sha256sum <&9 | awk '{print $1}')" \
      || fail "cannot hash the open $label"
    [[ "$source_sha256" == "$expected_sha256" ]] \
      || fail "$label differs from its approved SHA-256"
    # Hashing consumes the shared descriptor offset. Reopen the pathname and
    # prove that it still denotes the exact identity accepted above before
    # copying from the fresh descriptor.
    exec 9<&-
    exec 9<"$source" || fail "cannot reopen $label"
    fd_identity="$(file_identity "$fd_path")" || fail "cannot stat the reopened $label"
    source_identity="$(file_identity "$source")" || fail "cannot re-stat $label"
    [[ ! -L "$source" && -f "$source" && "$source_identity" == "$fd_identity" ]] \
      || fail "$label changed after it was hashed"
  fi

  umask 077
  [[ ! -e "$destination" && ! -L "$destination" ]] \
    || fail "refusing to overwrite handoff staging file"
  cat <&9 >"$destination" || fail "cannot copy $label"
  chmod 0600 "$destination" || fail "cannot protect the copied $label"
  exec 9<&-
  exec 9<"$source" || fail "cannot reopen the copied $label source"
  fd_identity="$(file_identity "$fd_path")" || fail "cannot stat the copied $label source"
  source_identity="$(file_identity "$source")" || fail "cannot re-stat $label"
  [[ ! -L "$source" && -f "$source" && "$source_identity" == "$fd_identity" ]] \
    || fail "$label changed while it was copied"
  cmp -s -- "$fd_path" "$destination" || fail "$label copy differs from its source"
  if [[ -n "$expected_sha256" ]]; then
    destination_sha256="$(sha256sum "$destination" | awk '{print $1}')" \
      || fail "cannot hash the copied $label"
    [[ "$destination_sha256" == "$expected_sha256" ]] \
      || fail "$label changed while it was copied"
  fi

  final_identity="$(file_identity "$source")" || fail "cannot re-stat $label"
  [[ ! -L "$source" && -f "$source" && "$final_identity" == "$fd_identity" ]] \
    || fail "$label changed while it was copied"
  exec 9<&-
}

stage_media_pair() {
  local receipt="$1" receipt_sha256="$2" signature="$3" signature_sha256="$4"
  local esp_root="$5" namespace="$5/ice-coreos" receipt_stage signature_stage

  [[ -d "$esp_root" && ! -L "$esp_root" ]] \
    || fail "ESP root must be an existing, non-symlink directory"
  [[ "$receipt_sha256" =~ ^[0-9a-f]{64}$ \
     && "$signature_sha256" =~ ^[0-9a-f]{64}$ ]] \
    || fail "media staging requires both exact lowercase SHA-256 values"
  if exists_or_symlink "$namespace"; then
    [[ -d "$namespace" && ! -L "$namespace" ]] \
      || fail "ESP ice-coreos namespace must be a real directory"
  else
    install -d -m 0700 -- "$namespace"
  fi
  [[ ! -e "$namespace/$RECEIPT_NAME" && ! -L "$namespace/$RECEIPT_NAME" \
     && ! -e "$namespace/$SIGNATURE_NAME" && ! -L "$namespace/$SIGNATURE_NAME" ]] \
    || fail "refusing to overwrite an existing LAB baseline media path"
  receipt_stage="$namespace/.$RECEIPT_NAME.$$.new"
  signature_stage="$namespace/.$SIGNATURE_NAME.$$.new"

  copy_checked "$receipt" "$receipt_stage" \
    "$RECEIPT_MAX_BYTES" "$RECEIPT_NAME" "$receipt_sha256"
  copy_checked "$signature" "$signature_stage" \
    "$SIGNATURE_MAX_BYTES" "$SIGNATURE_NAME" "$signature_sha256"
  sync -f "$receipt_stage" "$signature_stage"
  mv -n -- "$receipt_stage" "$namespace/$RECEIPT_NAME"
  mv -n -- "$signature_stage" "$namespace/$SIGNATURE_NAME"
  [[ ! -e "$receipt_stage" && ! -L "$receipt_stage" \
     && ! -e "$signature_stage" && ! -L "$signature_stage" ]] \
    || fail "LAB baseline media paths changed during publication"
  [[ ! -L "$namespace/$RECEIPT_NAME" && -f "$namespace/$RECEIPT_NAME" \
     && ! -L "$namespace/$SIGNATURE_NAME" && -f "$namespace/$SIGNATURE_NAME" ]] \
    || fail "published LAB baseline media paths are unsafe"
  sync -f "$namespace/$RECEIPT_NAME" "$namespace/$SIGNATURE_NAME" "$namespace"
}

snapshot_pair() {
  local esp_root="$1" snapshot="$2"
  local receipt="$esp_root/ice-coreos/$RECEIPT_NAME"
  local signature="$esp_root/ice-coreos/$SIGNATURE_NAME"
  local receipt_present=0 signature_present=0 parent stage

  exists_or_symlink "$receipt" && receipt_present=1
  exists_or_symlink "$signature" && signature_present=1

  if (( receipt_present == 0 && signature_present == 0 )); then
    return "$ABSENT"
  fi
  (( receipt_present == 1 && signature_present == 1 )) \
    || fail "ESP must contain both $RECEIPT_NAME and $SIGNATURE_NAME, or neither"
  [[ ! -e "$snapshot" && ! -L "$snapshot" ]] \
    || fail "snapshot destination already exists"

  parent="$(dirname "$snapshot")"
  install -d -m 0700 -- "$parent"
  stage="$parent/.lab-baseline-snapshot.$$.new"
  [[ ! -e "$stage" && ! -L "$stage" ]] || fail "snapshot staging path already exists"
  install -d -m 0700 -- "$stage"

  copy_checked "$receipt" "$stage/$RECEIPT_NAME" "$RECEIPT_MAX_BYTES" "$RECEIPT_NAME"
  copy_checked "$signature" "$stage/$SIGNATURE_NAME" "$SIGNATURE_MAX_BYTES" "$SIGNATURE_NAME"
  sync -f "$stage/$RECEIPT_NAME" "$stage/$SIGNATURE_NAME"
  mv -- "$stage" "$snapshot"
  sync -f "$parent"
}

ensure_root_dir() {
  local path="$1" mode="$2" expected_mode="${2#0}"
  [[ ! -L "$path" ]] || fail "destination directory must not be a symlink: $path"
  install -d -o 0 -g 0 -m "$mode" -- "$path"
  [[ "$(owner_group_mode "$path")" == "0:0:$expected_mode" ]] \
    || fail "destination directory ownership or mode is unsafe: $path"
}

install_pair() {
  local snapshot="$1" target_var="$2"
  local receipt="$snapshot/$RECEIPT_NAME"
  local signature="$snapshot/$SIGNATURE_NAME"
  local ota_dir destination stage

  [[ "$(id -u)" == 0 ]] || fail "install must run as root"
  [[ -d "$target_var" && ! -L "$target_var" ]] \
    || fail "target /var must be an existing, non-symlink directory"
  if ! exists_or_symlink "$receipt" || ! exists_or_symlink "$signature"; then
    fail "volatile snapshot is incomplete"
  fi

  ensure_root_dir "$target_var/lib" 0755
  ensure_root_dir "$target_var/lib/neural-ice" 0755
  ota_dir="$target_var/lib/neural-ice/ota"
  ensure_root_dir "$ota_dir" 0700

  destination="$ota_dir/lab-baseline"
  [[ ! -e "$destination" && ! -L "$destination" ]] \
    || fail "durable LAB baseline destination already exists"
  stage="$ota_dir/.lab-baseline.$$.new"
  [[ ! -e "$stage" && ! -L "$stage" ]] || fail "durable staging path already exists"
  install -d -o 0 -g 0 -m 0700 -- "$stage"

  copy_checked "$receipt" "$stage/$RECEIPT_NAME" "$RECEIPT_MAX_BYTES" "$RECEIPT_NAME"
  copy_checked "$signature" "$stage/$SIGNATURE_NAME" "$SIGNATURE_MAX_BYTES" "$SIGNATURE_NAME"
  chown 0:0 "$stage/$RECEIPT_NAME" "$stage/$SIGNATURE_NAME"
  sync -f "$stage/$RECEIPT_NAME" "$stage/$SIGNATURE_NAME"

  mv -- "$stage" "$destination"
  sync -f "$ota_dir"

  [[ "$(owner_group_mode "$destination")" == "0:0:700" ]] \
    || fail "durable LAB baseline directory is not root:root 0700"
  for name in "$RECEIPT_NAME" "$SIGNATURE_NAME"; do
    [[ ! -L "$destination/$name" && -f "$destination/$name" ]] \
      || fail "durable $name is not a regular, non-symlink file"
    [[ "$(owner_group_mode "$destination/$name")" == "0:0:600" ]] \
      || fail "durable $name is not root:root 0600"
    cmp -s -- "$snapshot/$name" "$destination/$name" \
      || fail "durable $name differs from the ESP snapshot"
  done
  sync -f "$destination/$RECEIPT_NAME" "$destination/$SIGNATURE_NAME" "$destination"
}

usage() {
  printf 'usage: %s snapshot <esp-root> <snapshot-dir>\n' "$0" >&2
  printf '       %s install <snapshot-dir> <target-var>\n' "$0" >&2
  printf '       %s stage-media <bom> <bom-sha256> <signature> <signature-sha256> <esp-root>\n' "$0" >&2
  exit 2
}

operation="${1:-}"
case "$operation" in
  snapshot|install) [[ "$#" -eq 3 ]] || usage ;;
  stage-media) [[ "$#" -eq 6 ]] || usage ;;
  *) usage ;;
esac
case "$operation" in
  snapshot) snapshot_pair "$2" "$3" ;;
  install) install_pair "$2" "$3" ;;
  stage-media) stage_media_pair "$2" "$3" "$4" "$5" "$6" ;;
  *) usage ;;
esac
