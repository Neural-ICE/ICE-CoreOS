#!/bin/sh
# shellcheck shell=sh
#
# THE SEALED INSTALLER PAYLOAD: one authenticated object carrying every byte the
# medium installs from.
#
# WHY THIS FILE EXISTS (review 2026-09-01, P0 #1). The medium used to stage three
# unrelated things on an ordinary filesystem: `installer-root.img`, its verity
# hash tree, and a `store/` directory of container bytes. Only the first was
# authenticated -- the root hash is sealed in the signed UKI cmdline. The store
# was hashed into a BUILD MANIFEST nobody read at runtime, so the bytes the
# installer actually wrote onto a customer's disk were attacker-replaceable on an
# otherwise correctly signed medium. And nothing off-device could check any of
# it: an inspector cannot read an xfs/ext4 tree without root and a filesystem
# driver, so the check that mattered was the one that could not be written.
#
# WHAT REPLACES IT. A single GPT partition, `ni-installer-payload`, whose layout
# is a RAW, SELF-DESCRIBING extent:
#
#   offset 0        a 4096-byte header: canonical `key=value` text, NUL-padded
#   offset 4096..   four 4096-aligned regions, named by the header:
#                     root-image   the installer root squashfs
#                     root-hash    its dm-verity hash tree
#                     store-image  a squashfs of the containers-storage the
#                                  install reads FROM
#                     store-hash   its dm-verity hash tree
#
# The header names each region's offset, size and SHA-256, and carries both
# dm-verity root hashes. THE SHA-256 OF THE HEADER IS SEALED IN THE SIGNED UKI
# (`neuralice.payload=`), so the header authenticates the regions and the
# signature authenticates the header. Nothing on the medium is trusted because
# of where it sits.
#
# WHY RAW AND NOT A FILESYSTEM. Three properties fall out of it and out of
# nothing else:
#   * the initramfs needs no filesystem driver and no mount to reach the root
#     image -- `losetup -o` on a partition is enough, so the code inside the
#     signature is smaller;
#   * an off-device inspector with no root, no loop device and no mount can read
#     and HASH every region straight out of the raw (image/inspect-installer-media.py);
#   * and both squashfs images are opened through dm-verity, so a modified block
#     is an I/O error at read time rather than a silent install of altered bytes
#     -- no 10 GiB up-front hash, and no window between "verified" and "used".
#
# WHY POSIX sh. This file is sourced by THREE readers that must not be allowed to
# disagree: the build (bash), the installer (bash) and the dracut pre-mount hook
# (the initramfs /bin/sh). A second parser is a second answer.

if [ -z "${NEURAL_ICE_INSTALLER_PAYLOAD_LIB_LOADED:-}" ]; then
  NEURAL_ICE_INSTALLER_PAYLOAD_LIB_LOADED=1

  NEURAL_ICE_PAYLOAD_SCHEMA="neural-ice-installer-payload-v1"
  # The header is one block. Bounded so a hostile medium cannot hand any reader
  # an unbounded document, and aligned so every region starts on a 4096 boundary.
  NEURAL_ICE_PAYLOAD_HEADER_BYTES=4096
  NEURAL_ICE_PAYLOAD_ALIGNMENT=4096
  # shellcheck disable=SC2034 # read by the dracut hook and the media builder
  NEURAL_ICE_PAYLOAD_PARTLABEL="ni-installer-payload"
  # The regions, in the canonical order the renderer emits and every reader
  # asserts. A closed world: a header naming a fifth region is refused, because
  # the region this reader does not understand could be the one that mattered.
  NEURAL_ICE_PAYLOAD_REGIONS="root-image root-hash store-image store-hash"
  # The full key set, sorted. `sorted(doc) != sorted(expected)` in one word.
  NEURAL_ICE_PAYLOAD_KEYS="region.root-hash region.root-image region.store-hash region.store-image root_verity_hash schema store_image_name store_verity_hash verity_salt"
fi

# --------------------------------------------------------------------------- #
# Read exactly one key out of the header text. Zero occurrences is a refusal and
# so is two: a header that can be shadowed by appending to it is not a header.
# --------------------------------------------------------------------------- #
payload_header_field() { # $1=header text  $2=key
  _pf_count=$(printf '%s\n' "$1" | awk -v k="$2=" 'BEGIN{n=0} index($0,k)==1 {n++} END{print n+0}')
  if [ "$_pf_count" -ne 1 ]; then
    echo "the installer payload header carries $_pf_count occurrences of $2" >&2
    return 1
  fi
  printf '%s\n' "$1" | awk -v k="$2=" 'index($0,k)==1 {print substr($0, length(k)+1)}'
}

payload_region_field() { # $1=header text  $2=region name  $3=offset|size|sha256
  _prf_value="$(payload_header_field "$1" "region.$2")" || return 1
  printf '%s' "$_prf_value" \
    | awk -v f="$3:" 'BEGIN{RS=","} index($0,f)==1 {print substr($0, length(f)+1); found=1} END{exit !found}' \
    || { echo "the payload header region '$2' carries no $3" >&2; return 1; }
}

# --------------------------------------------------------------------------- #
# Validate the header as a whole: the exact key set, in sorted order, with every
# value in its narrowest form and every region 4096-aligned, non-empty and
# non-overlapping. Prints nothing; a non-zero status is the answer.
# --------------------------------------------------------------------------- #
payload_header_is_valid() { # $1=header text
  _phv_text=$1
  # Printable ASCII only, checked line by line so an embedded control byte is a
  # refusal rather than something a later reader silently drops.
  if printf '%s\n' "$_phv_text" | LC_ALL=C grep -q '[^[:print:]]'; then
    echo "the installer payload header carries bytes outside printable ASCII" >&2
    return 1
  fi
  # Sorted, unique, exactly the expected keys. `sort -c` proves the ORDER a
  # renderer promised, which is what makes the header's digest a function of its
  # values alone.
  _phv_keys="$(printf '%s\n' "$_phv_text" | sed -n 's/^\([a-z0-9._-]*\)=.*/\1/p')"
  [ -n "$_phv_keys" ] || { echo "the installer payload header has no fields" >&2; return 1; }
  printf '%s\n' "$_phv_keys" | LC_ALL=C sort -c 2>/dev/null \
    || { echo "the installer payload header is not in canonical key order" >&2; return 1; }
  # shellcheck disable=SC2086 # the key list is a deliberate word list
  _phv_want="$(printf '%s\n' $NEURAL_ICE_PAYLOAD_KEYS | LC_ALL=C sort)"
  [ "$_phv_keys" = "$_phv_want" ] \
    || { echo "the installer payload header field set differs from $NEURAL_ICE_PAYLOAD_SCHEMA" >&2; return 1; }

  _phv_schema="$(payload_header_field "$_phv_text" schema)" || return 1
  [ "$_phv_schema" = "$NEURAL_ICE_PAYLOAD_SCHEMA" ] \
    || { echo "the installer payload header is not $NEURAL_ICE_PAYLOAD_SCHEMA" >&2; return 1; }

  for _phv_hash_key in root_verity_hash store_verity_hash; do
    _phv_hash="$(payload_header_field "$_phv_text" "$_phv_hash_key")" || return 1
    payload_is_sha256_hex "$_phv_hash" \
      || { echo "the payload header's $_phv_hash_key is not a 64-hex digest" >&2; return 1; }
  done
  _phv_salt="$(payload_header_field "$_phv_text" verity_salt)" || return 1
  case "$_phv_salt" in
    ''|*[!0-9a-f]*) echo "the payload header's verity_salt is not lowercase hex" >&2; return 1 ;;
  esac
  _phv_name="$(payload_header_field "$_phv_text" store_image_name)" || return 1
  payload_is_local_image_name "$_phv_name" \
    || { echo "the payload header's store_image_name is not a plain local image name" >&2; return 1; }

  # Every region: aligned, non-empty, after the header, and disjoint from the
  # region before it. Overlapping regions would let one set of bytes satisfy two
  # digests.
  _phv_end=$NEURAL_ICE_PAYLOAD_HEADER_BYTES
  for _phv_region in $NEURAL_ICE_PAYLOAD_REGIONS; do
    _phv_off="$(payload_region_field "$_phv_text" "$_phv_region" offset)" || return 1
    _phv_size="$(payload_region_field "$_phv_text" "$_phv_region" size)" || return 1
    _phv_sha="$(payload_region_field "$_phv_text" "$_phv_region" sha256)" || return 1
    if ! payload_is_plain_number "$_phv_off" || ! payload_is_plain_number "$_phv_size"; then
      echo "the payload header's region '$_phv_region' has a malformed extent" >&2
      return 1
    fi
    payload_is_sha256_hex "$_phv_sha" \
      || { echo "the payload header's region '$_phv_region' has no 64-hex digest" >&2; return 1; }
    [ "$_phv_size" -gt 0 ] \
      || { echo "the payload header's region '$_phv_region' is empty" >&2; return 1; }
    [ $(( _phv_off % NEURAL_ICE_PAYLOAD_ALIGNMENT )) -eq 0 ] \
      || { echo "the payload header's region '$_phv_region' is not ${NEURAL_ICE_PAYLOAD_ALIGNMENT}-aligned" >&2; return 1; }
    [ "$_phv_off" -ge "$_phv_end" ] \
      || { echo "the payload header's region '$_phv_region' overlaps what precedes it" >&2; return 1; }
    _phv_end=$(( _phv_off + _phv_size ))
  done
  return 0
}

payload_is_sha256_hex() { # $1=candidate
  case "$1" in
    *[!0-9a-f]*|'') return 1 ;;
  esac
  [ "${#1}" -eq 64 ]
}

payload_is_plain_number() { # $1=candidate — a decimal with no sign, no padding games
  case "$1" in
    ''|*[!0-9]*) return 1 ;;
  esac
  [ "${#1}" -le 19 ]
}

payload_is_local_image_name() { # $1=candidate
  printf '%s' "$1" | grep -Eq '^[a-z0-9]([a-z0-9._/-]{0,126}[a-z0-9])?$'
}

# --------------------------------------------------------------------------- #
# Read the header block out of a payload extent (a file, a partition device, or
# a raw image with --offset applied by the caller). The block is fixed-size and
# NUL-padded; a NUL INSIDE the text is a refusal rather than a truncation, so a
# header cannot carry a second document after its terminator.
#   $1 path   [$2 byte offset of the payload extent, default 0]
# --------------------------------------------------------------------------- #
payload_header_read() {
  _phr_path=$1
  _phr_base=${2:-0}
  [ -e "$_phr_path" ] || { echo "no installer payload at $_phr_path" >&2; return 1; }
  _phr_raw="$(dd if="$_phr_path" bs=1 skip="$_phr_base" \
    count="$NEURAL_ICE_PAYLOAD_HEADER_BYTES" 2>/dev/null | tr -d '\000')"
  [ -n "$_phr_raw" ] || { echo "the installer payload header is empty" >&2; return 1; }
  payload_header_is_valid "$_phr_raw" || return 1
  printf '%s' "$_phr_raw"
}

# The identity of the payload, as the UKI seals it: the SHA-256 of the canonical
# header text WITHOUT its NUL padding. Padding is an encoding detail; a digest
# that depended on it would change with the block size.
payload_header_digest() { # $1=header text
  printf '%s' "$1" | sha256sum | awk '{print tolower($1)}'
}

# --------------------------------------------------------------------------- #
# Hash one region straight out of the extent. Used by the build (to assert what
# LANDED), by the installer (belt and braces before dm-verity is opened) and by
# the off-device inspector.
#   $1 path  $2 extent base offset  $3 region offset  $4 region size
# --------------------------------------------------------------------------- #
payload_region_digest() {
  dd if="$1" bs="$NEURAL_ICE_PAYLOAD_ALIGNMENT" \
    skip=$(( ( $2 + $3 ) / NEURAL_ICE_PAYLOAD_ALIGNMENT )) \
    count=$(( ( $4 + NEURAL_ICE_PAYLOAD_ALIGNMENT - 1 ) / NEURAL_ICE_PAYLOAD_ALIGNMENT )) \
    2>/dev/null | head -c "$4" | sha256sum | awk '{print tolower($1)}'
}

# --------------------------------------------------------------------------- #
# Render a canonical header. BUILD SIDE ONLY: it is the one place the byte order
# of the document is decided, and it is a pure function of its arguments.
#   $1 store image name  $2 verity salt  $3 root verity hash  $4 store verity hash
#   $5.. four `name:offset:size:sha256` region triples, in canonical order
# --------------------------------------------------------------------------- #
payload_header_render() {
  if [ "$#" -ne 8 ]; then
    echo "payload_header_render requires the store name, salt, both root hashes and four regions" >&2
    return 2
  fi
  _phw_name=$1 _phw_salt=$2 _phw_root=$3 _phw_store=$4
  shift 4
  _phw_lines=""
  for _phw_region in $NEURAL_ICE_PAYLOAD_REGIONS; do
    _phw_spec=$1; shift
    case "$_phw_spec" in
      "$_phw_region":*) ;;
      *) echo "payload_header_render: region out of canonical order (wanted $_phw_region, got ${_phw_spec%%:*})" >&2; return 1 ;;
    esac
    _phw_rest=${_phw_spec#*:}
    _phw_off=${_phw_rest%%:*}; _phw_rest=${_phw_rest#*:}
    _phw_size=${_phw_rest%%:*}; _phw_sha=${_phw_rest#*:}
    _phw_lines="${_phw_lines}region.${_phw_region}=offset:${_phw_off},size:${_phw_size},sha256:${_phw_sha}
"
  done
  _phw_text="$( { printf '%s' "$_phw_lines"
      printf 'root_verity_hash=%s\n' "$_phw_root"
      printf 'schema=%s\n' "$NEURAL_ICE_PAYLOAD_SCHEMA"
      printf 'store_image_name=%s\n' "$_phw_name"
      printf 'store_verity_hash=%s\n' "$_phw_store"
      printf 'verity_salt=%s\n' "$_phw_salt"
    } | LC_ALL=C sort )"
  # FAIL-CLOSED READBACK. A renderer that emitted something this tree's own
  # reader refuses would produce a medium that dies in the initramfs, on the
  # appliance, after the operator has flashed it.
  payload_header_is_valid "$_phw_text" || {
    echo "payload_header_render produced a header this tree's own reader refuses" >&2
    return 1
  }
  printf '%s\n' "$_phw_text"
}

if [ "${NEURAL_ICE_INSTALLER_PAYLOAD_MAIN:-}" = 1 ]; then
  _pl_command=${1:-}
  [ "$#" -gt 0 ] && shift
  case "$_pl_command" in
    header-read) payload_header_read "$@" ;;
    header-digest) payload_header_digest "$@" ;;
    header-render) payload_header_render "$@" ;;
    header-valid) payload_header_is_valid "$@" ;;
    field) payload_header_field "$@" ;;
    region) payload_region_field "$@" ;;
    region-digest) payload_region_digest "$@" ;;
    *)
      echo "usage: NEURAL_ICE_INSTALLER_PAYLOAD_MAIN=1 installer-payload.sh {header-read PATH [BASE]|header-digest TEXT|header-render NAME SALT ROOT STORE R1 R2 R3 R4|header-valid TEXT|field TEXT KEY|region TEXT NAME FIELD|region-digest PATH BASE OFF SIZE}" >&2
      exit 2 ;;
  esac
fi
