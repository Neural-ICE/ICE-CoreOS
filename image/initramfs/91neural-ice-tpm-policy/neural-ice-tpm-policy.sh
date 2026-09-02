#!/bin/sh
# This pre-trigger runs before cryptsetup.  The signed UKI carries the exact
# PolicyAuthorize generation it was built for; the TPM counter is the durable
# authority for whether that generation is active.  Equality is intentional:
# lower is an old-UKI replay and higher is an interrupted activation.
ni_die() {
  if type die >/dev/null 2>&1; then
    die "neural-ice PCR policy refused: $*"
  fi
  echo "neural-ice PCR policy refused: $*" >&2
  exit 1
}

ni_release_marker=/usr/lib/neural-ice/release-image
ni_root=
ni_tools=/usr/bin
ni_cmdline=/proc/cmdline
if [ -n "${NEURALICE_INITRAMFS_TEST_ROOT:-}${NEURALICE_INITRAMFS_TEST_TOOLS:-}${NEURALICE_INITRAMFS_TEST_CMDLINE:-}" ]; then
  { [ "${NEURALICE_INITRAMFS_TESTING:-}" = 1 ] \
    && [ "$(id -u)" -ne 0 ] \
    && [ ! -e "$ni_release_marker" ] \
    && [ -n "${NEURALICE_INITRAMFS_TEST_ROOT:-}" ] \
    && [ ! -e "${NEURALICE_INITRAMFS_TEST_ROOT%/}$ni_release_marker" ]; } \
    || ni_die "test seams require non-root and an unmarked test root"
  ni_root=${NEURALICE_INITRAMFS_TEST_ROOT%/}
  ni_tools=${NEURALICE_INITRAMFS_TEST_TOOLS:?test tool directory is required}
  ni_cmdline=${NEURALICE_INITRAMFS_TEST_CMDLINE:?test cmdline is required}
fi

ni_index=0x01500007
ni_expected_attributes=393240 # 0x60018
ni_dynamic_mask=805308416     # 0x30000800
ni_written=536870912          # 0x20000000
ni_expected_policy=e8c02d3c5e701670cbaa327db1a2e9f3f41b2c22793e5c669a6e7f44b912f6c0
ni_max=9007199254740991

ni_cmdline_text=$(cat "$ni_cmdline") || ni_die "kernel command line is unreadable"
ni_requested_count=0
ni_requested=
ni_signature_count=0
ni_signature=
for ni_word in $ni_cmdline_text; do
  case "$ni_word" in
    neuralice.pcr_policy_seq=*)
      ni_requested_count=$((ni_requested_count + 1))
      ni_requested=${ni_word#*=}
      ;;
    neuralice.pcr_policy_signature=*)
      ni_signature_count=$((ni_signature_count + 1))
      ni_signature=${ni_word#*=}
      ;;
  esac
done
[ "$ni_requested_count" -eq 1 ] || ni_die "neuralice.pcr_policy_seq must occur exactly once"
case "$ni_requested" in
  0|[1-9]|[1-9][0-9]*) ;;
  *) ni_die "neuralice.pcr_policy_seq is not canonical decimal" ;;
esac
[ "$ni_requested" -le "$ni_max" ] 2>/dev/null \
  || ni_die "neuralice.pcr_policy_seq exceeds the safe integer ceiling"

# The public area is read through the one parser the OTA helper also uses
# (image/lib/tpm2-nv-public.sh, staged by module-setup.sh); it refuses anything
# but the exact nested shape tpm2-tools prints, for exactly this index.
ni_parser=${ni_root}/lib/neural-ice-tpm2-nv-public.sh
[ -r "$ni_parser" ] || ni_die "PCR policy public-area parser is missing from the initramfs"
# shellcheck source=image/lib/tpm2-nv-public.sh
. "$ni_parser"
ni_public=$("$ni_tools/tpm2_nvreadpublic" "$ni_index" 2>/dev/null) \
  || ni_die "PCR policy high-water public area is unavailable"
ni_parsed=$(printf '%s\n' "$ni_public" | ni_tpm2_nv_public_parse "$ni_index") \
  || ni_die "PCR policy high-water public area is not the tpm2-tools contract"
# shellcheck disable=SC2086 # the parser emits exactly four validated words
set -- $ni_parsed
[ "$#" -eq 4 ] || ni_die "PCR policy high-water public area parse is incomplete"
ni_attributes=$1
ni_size=$2
ni_policy=$3
[ "$ni_size" = 8 ] || ni_die "PCR policy high-water has the wrong size"
ni_attributes_value=$((ni_attributes))
[ $((ni_attributes_value & ~ni_dynamic_mask)) -eq "$ni_expected_attributes" ] \
  || ni_die "PCR policy high-water attributes do not match the counter contract"
[ $((ni_attributes_value & ni_written)) -ne 0 ] \
  || ni_die "PCR policy high-water has never been activated"
[ "$ni_policy" = "$ni_expected_policy" ] \
  || ni_die "PCR policy high-water authorization policy is wrong"

ni_counter_file=${ni_root}/run/neural-ice-pcr-policy-counter
mkdir -p "$(dirname "$ni_counter_file")" || ni_die "cannot create counter workspace"
"$ni_tools/tpm2_nvread" -s 8 -o "$ni_counter_file" "$ni_index" >/dev/null 2>&1 \
  || ni_die "PCR policy high-water is unreadable"
[ "$(wc -c < "$ni_counter_file")" -eq 8 ] || ni_die "PCR policy high-water is truncated"
ni_counter_hex=$(od -An -tx1 -v "$ni_counter_file" | tr -d '[:space:]' | tr 'A-F' 'a-f')
case "$ni_counter_hex" in
  [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;;
  *) ni_die "PCR policy high-water is malformed" ;;
esac
case "$ni_counter_hex" in
  000*|001*) ;;
  *) ni_die "PCR policy high-water exceeds the safe integer ceiling" ;;
esac
ni_current=$((0x$ni_counter_hex))
[ "$ni_requested" -eq "$ni_current" ] \
  || ni_die "signed UKI PCR policy sequence does not equal the durable TPM high-water"

[ "$ni_signature_count" -eq 1 ] \
  || ni_die "neuralice.pcr_policy_signature must occur exactly once"
case "$ni_signature" in *[!0-9a-f]*|'') ni_die "PCR policy signature hash is malformed" ;; esac
[ "${#ni_signature}" -eq 64 ] || ni_die "PCR policy signature hash has the wrong length"
ni_device=${ni_root}/dev/disk/by-label/EFI-SYSTEM
if [ -n "$ni_root" ]; then
  [ -e "$ni_device" ] || ni_die "EFI system partition is unavailable"
else
  [ -b "$ni_device" ] || ni_die "EFI system partition is unavailable"
fi
ni_mount=${ni_root}/run/neural-ice-policy-esp
ni_systemd=${ni_root}/run/systemd
mkdir -p "$ni_mount" "$ni_systemd" || ni_die "cannot create policy workspace"
mount -o ro,nodev,nosuid,noexec "$ni_device" "$ni_mount" \
  || ni_die "cannot mount EFI system partition read-only"
ni_source=$ni_mount/EFI/neural-ice/tpm2-pcr-signature.json
ni_observed=$(sha256sum "$ni_source" 2>/dev/null | awk '{print $1}')
if [ "$ni_observed" = "$ni_signature" ]; then
  cp -f "$ni_source" "$ni_systemd/tpm2-pcr-signature.json" \
    || { umount "$ni_mount"; ni_die "cannot stage PCR policy signature"; }
  chmod 0644 "$ni_systemd/tpm2-pcr-signature.json" \
    || { umount "$ni_mount"; ni_die "cannot protect PCR policy signature"; }
else
  umount "$ni_mount"
  ni_die "PCR policy signature hash does not match the signed UKI"
fi
umount "$ni_mount" || ni_die "cannot unmount EFI system partition"
