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

ni_hex64() {
  case "${1:-}" in ''|*[!0-9a-f]*) return 1 ;; esac
  [ "${#1}" -eq 64 ]
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

# dracut sources pre-trigger hooks in one shell. Installed boots are owned by
# the ordered systemd service below, so return before parsing or coldplugging;
# `exit` here would also skip every later pre-trigger hook in dracut's loop.
if [ -z "$ni_root" ] && [ ! -e /etc/neural-ice/installer-media ] \
  && [ "${NEURALICE_TPM_POLICY_SERVICE:-}" != 1 ]; then
  # shellcheck disable=SC2317 # fallback is reached only when this file is executed, not sourced
  return 0 2>/dev/null || exit 0
fi
if [ -z "$ni_root" ]; then
  ni_tpm_wait=0
  while ! "$ni_tools/tpm2_getcap" properties-fixed >/dev/null 2>&1; do
    [ "$ni_tpm_wait" -lt 30 ] || ni_die "TPM did not become ready before policy staging"
    udevadm settle --timeout=1 >/dev/null 2>&1 || true
    sleep 1
    ni_tpm_wait=$((ni_tpm_wait + 1))
  done
fi

ni_index=0x01500007
ni_expected_attributes=393240 # 0x60018
ni_dynamic_mask=805308416     # 0x30000800
ni_written=536870912          # 0x20000000
ni_expected_policy=e8c02d3c5e701670cbaa327db1a2e9f3f41b2c22793e5c669a6e7f44b912f6c0
ni_max=9007199254740991
ni_initial_max=4096

ni_cmdline_text=$(cat "$ni_cmdline") || ni_die "kernel command line is unreadable"
ni_requested_count=0
ni_requested=
ni_signature_count=0
ni_signature=
ni_unit_count=0
ni_unit=
ni_autoinstall_count=0
ni_autoinstall=
ni_trust_count=0
ni_trust=
ni_access_profile_count=0
ni_access_profile=
ni_hardware_target_count=0
ni_hardware_target=
ni_payload_count=0
ni_payload=
ni_relauth_keyid_count=0
ni_relauth_keyid=
ni_relauth_schema_count=0
ni_relauth_schema=
ni_rootverity_count=0
ni_rootverity=
ni_trust_policy_count=0
ni_trust_policy=
ni_live_count=0
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
    systemd.unit=*)
      ni_unit_count=$((ni_unit_count + 1))
      ni_unit=${ni_word#*=}
      ;;
    neuralice.autoinstall=*)
      ni_autoinstall_count=$((ni_autoinstall_count + 1))
      ni_autoinstall=${ni_word#*=}
      ;;
    neuralice.trust=*)
      ni_trust_count=$((ni_trust_count + 1))
      ni_trust=${ni_word#*=}
      ;;
    neuralice.access_profile=*)
      ni_access_profile_count=$((ni_access_profile_count + 1))
      ni_access_profile=${ni_word#*=}
      ;;
    neuralice.hardware_target=*)
      ni_hardware_target_count=$((ni_hardware_target_count + 1))
      ni_hardware_target=${ni_word#*=}
      ;;
    neuralice.payload=*)
      ni_payload_count=$((ni_payload_count + 1))
      ni_payload=${ni_word#*=}
      ;;
    neuralice.relauth_keyid=*)
      ni_relauth_keyid_count=$((ni_relauth_keyid_count + 1))
      ni_relauth_keyid=${ni_word#*=}
      ;;
    neuralice.relauth_schema=*)
      ni_relauth_schema_count=$((ni_relauth_schema_count + 1))
      ni_relauth_schema=${ni_word#*=}
      ;;
    neuralice.rootverity=*)
      ni_rootverity_count=$((ni_rootverity_count + 1))
      ni_rootverity=${ni_word#*=}
      ;;
    neuralice.trust_policy_id=*)
      ni_trust_policy_count=$((ni_trust_policy_count + 1))
      ni_trust_policy=${ni_word#*=}
      ;;
    neuralice.live=*)
      ni_live_count=$((ni_live_count + 1))
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
ni_media_marker=${ni_root}/etc/neural-ice/installer-media
ni_installer_media=0
if [ -e "$ni_media_marker" ] || [ -L "$ni_media_marker" ]; then
  if ! { [ -f "$ni_media_marker" ] && [ ! -L "$ni_media_marker" ] \
    && [ "$(cat "$ni_media_marker" 2>/dev/null)" = neural-ice-signed-installer-initramfs-v1 ]; }; then
    ni_die "signed installer initramfs marker is malformed"
  fi
  ni_installer_media=1
fi
if ni_public=$("$ni_tools/tpm2_nvreadpublic" "$ni_index" 2>/dev/null); then
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
  # -C <index>: authorize the read with the index's own (empty) authValue —
  # the counter is defined `authread|ownerread`. Without -C, tpm2_nvread
  # authorizes through the OWNER hierarchy, which the first-boot ceremony
  # seals; the first reboot after the ceremony then died here with "high-water
  # is unreadable" on QEMU. The OS-side reader (neural-ice-tpm-state) already
  # uses -C <index>; this hook must never authorize with a hierarchy.
  "$ni_tools/tpm2_nvread" -C "$ni_index" -s 8 -o "$ni_counter_file" "$ni_index" >/dev/null 2>&1 \
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
else
  # A signed Install UKI necessarily runs before its first LUKS enrollment can
  # activate this counter. Treat absence as virgin only for that exact mode,
  # only while the owner hierarchy is still empty, and only while no other
  # appliance-state index exists. Every installed boot keeps the equality path
  # above; an unreadable index must not be mistaken for an absent one.
  if [ "$ni_installer_media" -ne 1 ]; then
    ni_die "PCR policy high-water is absent outside a signed installer initramfs"
  fi
  if ! { [ "$ni_unit_count" -eq 1 ] && [ "$ni_unit" = neural-ice-installer.target ] \
    && [ "$ni_autoinstall_count" -eq 1 ] && [ "$ni_autoinstall" = 1 ] \
    && [ "$ni_trust_count" -eq 1 ] && [ "$ni_trust" = neural-ice-installer-trust-v1 ] \
    && [ "$ni_access_profile_count" -eq 1 ] \
    && [ "$ni_hardware_target_count" -eq 1 ] \
    && [ "$ni_payload_count" -eq 1 ] \
    && [ "$ni_relauth_keyid_count" -eq 1 ] \
    && [ "$ni_relauth_schema_count" -eq 1 ] \
    && [ "$ni_relauth_schema" = neural-ice-installer-release-authorization-v2 ] \
    && [ "$ni_rootverity_count" -eq 1 ] \
    && [ "$ni_trust_policy_count" -eq 1 ] \
    && [ "$ni_live_count" -eq 0 ]; }; then
    ni_die "PCR policy high-water public area is unavailable outside an exact Install boot"
  fi
  case "$ni_access_profile" in lab-managed|customer-locked|developer-diagnostic) ;; *)
    ni_die "signed installer access profile is malformed"
  esac
  case "$ni_hardware_target" in ''|*[!A-Za-z0-9._/-]*) ni_die "signed installer hardware target is malformed" ;; esac
  case "$ni_trust_policy" in ''|*[!A-Za-z0-9._/-]*) ni_die "signed installer trust policy is malformed" ;; esac
  ni_hex64 "$ni_payload" || ni_die "signed installer payload digest is malformed"
  ni_hex64 "$ni_relauth_keyid" || ni_die "signed installer release key identity is malformed"
  ni_hex64 "$ni_rootverity" || ni_die "signed installer root verity hash is malformed"
  if ! { [ "$ni_requested" -ge 1 ] 2>/dev/null \
    && [ "$ni_requested" -le "$ni_initial_max" ] 2>/dev/null; }; then
    ni_die "initial signed PCR policy sequence is outside the activation window"
  fi

  ni_handles=$("$ni_tools/tpm2_getcap" handles-nv-index 2>/dev/null) \
    || ni_die "TPM NV handles are unavailable"
  ni_normalized_handles=$(printf '%s\n' "$ni_handles" | awk '
    /^[[:space:]]*-[[:space:]]+0[xX][0-9a-fA-F]+[[:space:]]*$/ {
      gsub(/^[[:space:]]*-[[:space:]]+/, "")
      gsub(/[[:space:]]+$/, "")
      print
      next
    }
    NF { exit 1 }
  ') || ni_die "TPM NV handle list is malformed"
  ni_pcr_index_count=0
  ni_other_state_count=0
  for ni_handle in $ni_normalized_handles; do
    ni_handle_value=$((ni_handle))
    case "$ni_handle_value" in
      "$((0x01500007))") ni_pcr_index_count=$((ni_pcr_index_count + 1)) ;;
      "$((0x01500001))"|"$((0x01500002))"|"$((0x01500003))"|"$((0x01500004))"|"$((0x01500005))"|"$((0x01500006))")
        ni_other_state_count=$((ni_other_state_count + 1))
        ;;
    esac
  done
  [ "$ni_pcr_index_count" -eq 0 ] \
    || ni_die "PCR policy high-water exists but its public area is unreadable"
  [ "$ni_other_state_count" -eq 0 ] \
    || ni_die "PCR policy state is absent while another appliance state index exists"

  ni_properties=$("$ni_tools/tpm2_getcap" properties-variable 2>/dev/null) \
    || ni_die "TPM permanent properties are unavailable"
  ni_owner_auth=$(printf '%s\n' "$ni_properties" | awk -F: '
    /^[[:space:]]*ownerAuthSet:[[:space:]]*[01][[:space:]]*$/ {
      value=$2
      gsub(/[^0-9]/, "", value)
      print value
      found++
    }
    END { exit found != 1 }
  ') || ni_die "TPM owner authorization state is malformed"
  [ "$ni_owner_auth" = 0 ] \
    || ni_die "PCR policy high-water is absent after owner authorization was sealed"
fi

[ "$ni_signature_count" -eq 1 ] \
  || ni_die "neuralice.pcr_policy_signature must occur exactly once"
case "$ni_signature" in *[!0-9a-f]*|'') ni_die "PCR policy signature hash is malformed" ;; esac
[ "${#ni_signature}" -eq 64 ] || ni_die "PCR policy signature hash has the wrong length"
if [ "$ni_installer_media" -eq 1 ]; then
  ni_device_label=NI-INSTALL
  ni_source_relative=ice-coreos/tpm2-pcr-signature.json
else
  ni_device_label=EFI-SYSTEM
  ni_source_relative=EFI/neural-ice/tpm2-pcr-signature.json
fi
if [ -n "$ni_root" ]; then
  ni_device=${ni_root}/dev/disk/by-label/$ni_device_label
  [ -e "$ni_device" ] || ni_die "EFI system partition is unavailable"
else
  ni_device=
  ni_wait=0
  # pre-trigger hooks run immediately before dracut's own udev coldplug. This
  # hook needs the ESP earlier than that, so initiate the same coldplug here
  # instead of waiting for events that have not been queued yet.
  udevadm trigger --type=subsystems --action=add >/dev/null 2>&1 || true
  udevadm trigger --type=devices --action=add >/dev/null 2>&1 || true
  while [ "$ni_wait" -lt 30 ]; do
    ni_devices=$(blkid -t "LABEL=$ni_device_label" -o device 2>/dev/null) || ni_devices=
    # shellcheck disable=SC2086 # blkid emits one whitespace-free device path per line
    set -- $ni_devices
    [ "$#" -le 1 ] || ni_die "EFI system partition label is ambiguous"
    if [ "$#" -eq 1 ] && [ -b "$1" ]; then
      ni_device=$1
      break
    fi
    udevadm settle --timeout=1 >/dev/null 2>&1 || true
    sleep 1
    ni_wait=$((ni_wait + 1))
  done
  [ -n "$ni_device" ] || ni_die "EFI system partition is unavailable"
fi
ni_mount=${ni_root}/run/neural-ice-policy-esp
ni_systemd=${ni_root}/run/systemd
mkdir -p "$ni_mount" "$ni_systemd" || ni_die "cannot create policy workspace"
mount -o ro,nodev,nosuid,noexec "$ni_device" "$ni_mount" \
  || ni_die "cannot mount EFI system partition read-only"
ni_source=$ni_mount/$ni_source_relative
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
