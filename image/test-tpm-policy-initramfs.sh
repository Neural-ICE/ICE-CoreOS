#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
HOOK="$ROOT_DIR/image/initramfs/91neural-ice-tpm-policy/neural-ice-tpm-policy.sh"
PARSER="$ROOT_DIR/image/lib/tpm2-nv-public.sh"
USB_BUILDER="$ROOT_DIR/image/build-installer-usb.sh"
POLICY=e8c02d3c5e701670cbaa327db1a2e9f3f41b2c22793e5c669a6e7f44b912f6c0
HASH=$(printf policy | sha256sum | awk '{print $1}')

grep -Fq 'tpm2_getcap tpm2_nvreadpublic tpm2_nvread' \
  "$ROOT_DIR/image/initramfs/91neural-ice-tpm-policy/module-setup.sh"
# shellcheck disable=SC2016 # literal source text is what is being matched
grep -Fq 'inst_simple "$moddir/tpm2-nv-public.sh" /lib/neural-ice-tpm2-nv-public.sh' \
  "$ROOT_DIR/image/initramfs/91neural-ice-tpm-policy/module-setup.sh"
grep -Fq 'inst_hook pre-trigger 01' \
  "$ROOT_DIR/image/initramfs/91neural-ice-tpm-policy/module-setup.sh"
# shellcheck disable=SC2016 # literal source text is what is being matched
grep -Fq 'inst_simple "$moddir/neural-ice-tpm-policy.service"' \
  "$ROOT_DIR/image/initramfs/91neural-ice-tpm-policy/module-setup.sh"
grep -Fq 'cryptsetup-pre.target.requires/neural-ice-tpm-policy.service' \
  "$ROOT_DIR/image/initramfs/91neural-ice-tpm-policy/module-setup.sh"
grep -Fq 'systemd-cryptsetup@.service.d/10-neural-ice-policy.conf' \
  "$ROOT_DIR/image/initramfs/91neural-ice-tpm-policy/module-setup.sh"
grep -Fq 'Requires=neural-ice-tpm-policy.service' \
  "$ROOT_DIR/image/initramfs/91neural-ice-tpm-policy/systemd-cryptsetup-policy.conf"
grep -Fq 'Before=cryptsetup-pre.target' \
  "$ROOT_DIR/image/initramfs/91neural-ice-tpm-policy/neural-ice-tpm-policy.service"
grep -Fq 'NEURALICE_TPM_POLICY_SERVICE=1' \
  "$ROOT_DIR/image/initramfs/91neural-ice-tpm-policy/neural-ice-tpm-policy.service"
grep -Fq 'ExecStart=/var/lib/dracut/hooks/pre-trigger/01-neural-ice-tpm-policy.sh' \
  "$ROOT_DIR/image/initramfs/91neural-ice-tpm-policy/neural-ice-tpm-policy.service"
grep -Fq 'StandardError=journal+console' \
  "$ROOT_DIR/image/initramfs/91neural-ice-tpm-policy/neural-ice-tpm-policy.service"
# shellcheck disable=SC2016 # literal source text is what is being matched
grep -Fq '[ "${NEURALICE_TPM_POLICY_SERVICE:-}" != 1 ]' "$HOOK"
defer_line=$(grep -nF 'return 0 2>/dev/null || exit 0' "$HOOK" | cut -d: -f1)
# shellcheck disable=SC2016 # literal source text is what is being matched
cmdline_line=$(grep -nF 'ni_cmdline_text=$(cat "$ni_cmdline")' "$HOOK" | cut -d: -f1)
[[ -n "$defer_line" && -n "$cmdline_line" && "$defer_line" -lt "$cmdline_line" ]] \
  || { echo "installed hook deferral does not precede command-line parsing" >&2; exit 1; }
# shellcheck disable=SC2016 # literal source text is what is being matched
grep -Fq '"$ni_tools/tpm2_getcap" properties-fixed' "$HOOK" \
  || { echo "policy staging does not wait for TPM readiness" >&2; exit 1; }
# The parser is staged beside the module for dracut AND installed for the OTA
# helper, from the one source file; the generated initramfs is checked for it.
grep -Fq 'COPY image/lib/tpm2-nv-public.sh /usr/lib/dracut/modules.d/91neural-ice-tpm-policy/tpm2-nv-public.sh' \
  "$ROOT_DIR/image/Containerfile.bootc"
grep -Fq 'COPY image/lib/tpm2-nv-public.sh         /usr/lib/neural-ice/lib/tpm2-nv-public.sh' \
  "$ROOT_DIR/image/Containerfile.bootc"
grep -Fq '01-neural-ice-tpm-policy.sh neural-ice-tpm2-nv-public.sh' \
  "$ROOT_DIR/image/Containerfile.bootc"
# Installer media may target an older immutable appliance digest. The builder
# must overlay this checkout's TPM hook before dracut runs, just as it already
# overlays the installer-verity hook, or a fixed source tree silently emits the
# stale hook from the pinned base image.
# shellcheck disable=SC2016 # literal source text is what is being matched
grep -Fq 'DRACUT_TPM_MODULE="$SEALED_DIR/dracut-module-tpm-policy"' "$USB_BUILDER"
# shellcheck disable=SC2016 # literal source text is what is being matched
grep -Fq 'cp -- "$REPO_ROOT/image/initramfs/91neural-ice-tpm-policy"/*.sh "$DRACUT_TPM_MODULE/"' \
  "$USB_BUILDER"
# shellcheck disable=SC2016 # literal source text is what is being matched
grep -Fq 'cp -- "$REPO_ROOT/image/initramfs/91neural-ice-tpm-policy"/*.service "$DRACUT_TPM_MODULE/"' \
  "$USB_BUILDER"
# shellcheck disable=SC2016 # literal source text is what is being matched
grep -Fq 'cp -- "$REPO_ROOT/image/initramfs/91neural-ice-tpm-policy"/*.conf "$DRACUT_TPM_MODULE/"' \
  "$USB_BUILDER"
# shellcheck disable=SC2016 # literal source text is what is being matched
grep -Fq 'cp -- "$REPO_ROOT/image/lib/tpm2-nv-public.sh" "$DRACUT_TPM_MODULE/tpm2-nv-public.sh"' \
  "$USB_BUILDER"
grep -Fq "printf 'neural-ice-signed-installer-initramfs-v1" "$USB_BUILDER"
# shellcheck disable=SC2016 # literal source text is what is being matched
grep -Fq 'inst_simple "$moddir/installer-media" /etc/neural-ice/installer-media' \
  "$ROOT_DIR/image/initramfs/91neural-ice-tpm-policy/module-setup.sh"
grep -Fq 'cp /ni-dracut-tpm-policy/installer-media /usr/lib/dracut/modules.d/91neural-ice-tpm-policy/' \
  "$USB_BUILDER"
grep -Fq 'lsinitrd -f /var/lib/dracut/hooks/pre-trigger/01-neural-ice-tpm-policy.sh' \
  "$USB_BUILDER"
grep -Fq 'lsinitrd -f /etc/neural-ice/installer-media' "$USB_BUILDER"
grep -Fq -- '--add "neural-ice-installer-verity neural-ice-tpm-policy"' "$USB_BUILDER"
# shellcheck disable=SC2016 # literal source text is what is being matched
grep -Fq 'source "$NV_PUBLIC_PARSER"' "$ROOT_DIR/ota/neural-ice-tpm-state.sh"
# No second parser: nothing else in the tree pulls fields out of the output.
if grep -rn "awk '/value: 0x/\|awk '/^\[\[:space:\]\]\*attributes:" \
    "$ROOT_DIR/image" "$ROOT_DIR/ota" --include='*.sh' | grep -v '^.*test-'; then
  echo "a second tpm2_nvreadpublic parser exists beside image/lib/tpm2-nv-public.sh" >&2
  exit 1
fi

if (( EUID == 0 )); then
  fixture=$(mktemp -d)
  trap 'rm -rf -- "$fixture"' EXIT
  mkdir -p "$fixture/tools"
  : >"$fixture/cmdline"
  if env NEURALICE_INITRAMFS_TESTING=1 \
      NEURALICE_INITRAMFS_TEST_ROOT="$fixture/root" \
      NEURALICE_INITRAMFS_TEST_TOOLS="$fixture/tools" \
      NEURALICE_INITRAMFS_TEST_CMDLINE="$fixture/cmdline" \
      sh "$HOOK" >/dev/null 2>&1; then
    echo "root process accepted initramfs test seams" >&2
    exit 1
  fi
  echo "TPM_POLICY_INITRAMFS_ROOT_SEAM_REFUSAL_OK"
  exit 0
fi

fixture=$(mktemp -d)
trap 'rm -rf -- "$fixture"' EXIT
test_root="$fixture/root"
tools="$fixture/tools"
cmdline="$fixture/cmdline"
mkdir -p "$tools" "$test_root/dev/disk/by-label" "$test_root/lib" \
  "$test_root/run/neural-ice-policy-esp/EFI/neural-ice" \
  "$test_root/run/neural-ice-policy-esp/ice-coreos"
: >"$test_root/dev/disk/by-label/EFI-SYSTEM"
: >"$test_root/dev/disk/by-label/NI-INSTALL"
printf policy >"$test_root/run/neural-ice-policy-esp/EFI/neural-ice/tpm2-pcr-signature.json"
printf policy >"$test_root/run/neural-ice-policy-esp/ice-coreos/tpm2-pcr-signature.json"
# The hook resolves the parser at the path module-setup.sh installs it under.
cp "$PARSER" "$test_root/lib/neural-ice-tpm2-nv-public.sh"

# The mock renders EXACTLY what tpm2-tools 5.7 print_nv_public() emits for the
# high-water counter (tools/tpm2_nvreadpublic.c): unpadded index header,
# lowercase Name, nested hash-algorithm and attributes sections with the word
# on the `value:` line, decimal size, UPPERCASE policy. NI_TEST_NV_SHAPE selects
# a deviation; every deviation must be refused before the counter is read.
cat >"$tools/tpm2_nvreadpublic" <<'EOF2'
#!/bin/sh
test "$1" = 0x01500007 || exit 90
name=000b$(printf 'c%.0s' $(seq 64))
policy=${NI_TEST_NV_POLICY:-E8C02D3C5E701670CBAA327DB1A2E9F3F41B2C22793E5C669A6E7F44B912F6C0}
attributes=${NI_TEST_NV_ATTRIBUTES:-0x20060018}
size=${NI_TEST_NV_SIZE:-8}
header=0x1500007
hash_block='  hash algorithm:
    friendly: sha256
    value: 0xB'
attributes_block="  attributes:
    friendly: ownerwrite|policywrite|nt=0x1|ownerread|written
    value: $attributes"
policy_line="  authorization policy: $policy"
case "${NI_TEST_NV_SHAPE:-real}" in
  real) ;;
  legacy-flat) attributes_block="  attributes: $attributes" ;;
  attributes-value-absent) attributes_block='  attributes:
    friendly: ownerwrite|policywrite|nt=0x1|ownerread|written' ;;
  attributes-section-absent) attributes_block= ;;
  attributes-section-duplicated) attributes_block="$attributes_block
$attributes_block" ;;
  attributes-value-duplicated) attributes_block="$attributes_block
    value: 0x60018" ;;
  attributes-value-not-hex) attributes_block='  attributes:
    friendly: x
    value: 20060018' ;;
  value-outside-section) attributes_block="    value: $attributes" ;;
  wrong-index) header=0x1500008 ;;
  header-absent) header= ;;
  header-duplicated) header="0x1500007:
0x1500007" ;;
  policy-absent) policy_line= ;;
  policy-empty) policy_line='  authorization policy: ' ;;
  size-absent) size= ;;
  unknown-line) policy_line="$policy_line
  nt: counter" ;;
  empty) exit 0 ;;
  *) exit 93 ;;
esac
[ -n "$header" ] && printf '%s:\n' "$header"
printf '  name: %s\n' "$name"
printf '%s\n' "$hash_block"
[ -n "$attributes_block" ] && printf '%s\n' "$attributes_block"
[ -n "$size" ] && printf '  size: %s\n' "$size"
[ -n "$policy_line" ] && printf '%s\n' "$policy_line"
exit 0
EOF2
cat >"$tools/tpm2_nvread" <<'EOF2'
#!/bin/sh
# Models a TPM whose owner hierarchy the first-boot ceremony has sealed: a read
# authorized by a hierarchy (no -C, or -C o/p/e) fails exactly as tpm2_nvread
# does after the ceremony; only the index's own empty authValue reads.
out=; auth=; index=
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) out=$2; shift 2 ;;
    -C) auth=$2; shift 2 ;;
    -s) shift 2 ;;
    0x*) index=$1; shift ;;
    *) shift ;;
  esac
done
test -n "$out" || exit 91
[ -n "$auth" ] && [ "$auth" = "$index" ] || { echo "tpm2_nvread: owner hierarchy authorization failed (sealed)" >&2; exit 93; }
: >"${NI_TEST_NVREAD_TRACE:-/dev/null}"
case "${NI_TEST_COUNTER_SEQ:-7}" in
  7) printf '\000\000\000\000\000\000\000\007' >"$out" ;;
  8) printf '\000\000\000\000\000\000\000\010' >"$out" ;;
  short) printf '\000\007' >"$out" ;;
  *) exit 92 ;;
esac
EOF2
cat >"$tools/tpm2_getcap" <<'EOF2'
#!/bin/sh
case "$1" in
  handles-nv-index)
    [ "${NI_TEST_GETCAP_HANDLES_FAIL:-0}" != 1 ] || exit 94
    printf '%b' "${NI_TEST_NV_HANDLES:-}"
    ;;
  properties-variable)
    [ "${NI_TEST_GETCAP_PROPERTIES_FAIL:-0}" != 1 ] || exit 95
    case "${NI_TEST_OWNER_AUTH_SHAPE:-real}" in
      real) printf 'TPM2_PT_PERMANENT:\n  ownerAuthSet:              %s\n' "${NI_TEST_OWNER_AUTH_SET:-0}" ;;
      duplicate) printf '  ownerAuthSet: 0\n  ownerAuthSet: 0\n' ;;
      missing) printf 'TPM2_PT_PERMANENT:\n  endorsementAuthSet: 0\n' ;;
      malformed) printf '  ownerAuthSet: unknown\n' ;;
      *) exit 96 ;;
    esac
    ;;
  *) exit 97 ;;
esac
EOF2
cat >"$tools/mount" <<'EOF2'
#!/bin/sh
exit 0
EOF2
cat >"$tools/umount" <<'EOF2'
#!/bin/sh
exit 0
EOF2
chmod +x "$tools"/*

# Only TPM commands are redirected by the hook; mount/umount are resolved from
# PATH so the same test doubles exercise the production command invocation.
export PATH="$tools:$PATH"
run_hook() {
  env NEURALICE_INITRAMFS_TESTING=1 \
    NEURALICE_INITRAMFS_TEST_ROOT="$test_root" \
    NEURALICE_INITRAMFS_TEST_TOOLS="$tools" \
    NEURALICE_INITRAMFS_TEST_CMDLINE="$cmdline" \
    "$@" sh "$HOOK"
}
write_cmdline() {
  printf 'quiet neuralice.pcr_policy_seq=%s neuralice.pcr_policy_signature=%s\n' "$1" "$HASH" >"$cmdline"
}
write_install_cmdline() {
  printf 'quiet systemd.unit=neural-ice-installer.target neuralice.autoinstall=1 neuralice.trust=neural-ice-installer-trust-v1 neuralice.access_profile=lab-managed neuralice.hardware_target=nvidia-gb10-arm64 neuralice.payload=%s neuralice.relauth_keyid=%s neuralice.relauth_schema=neural-ice-installer-release-authorization-v2 neuralice.rootverity=%s neuralice.trust_policy_id=neural-ice-secureboot-lab-v1 neuralice.pcr_policy=%s neuralice.pcr_policy_key=%s neuralice.pcr_policy_seq=%s neuralice.pcr_policy_signature=%s %s\n' \
    "$HASH" "$HASH" "$HASH" "$HASH" "$HASH" "$1" "$HASH" "${2:-}" >"$cmdline"
}
cases=0
must_refuse() {
  local label=$1
  shift
  if "$@" >/dev/null 2>&1; then
    echo "$label was accepted" >&2
    exit 1
  fi
  cases=$((cases + 1))
}
must_accept() {
  local label=$1
  shift
  rm -f "$test_root/run/systemd/tpm2-pcr-signature.json"
  "$@" || { echo "$label was refused" >&2; exit 1; }
  cmp "$test_root/run/systemd/tpm2-pcr-signature.json" \
    "$test_root/run/neural-ice-policy-esp/EFI/neural-ice/tpm2-pcr-signature.json"
  cases=$((cases + 1))
}

write_cmdline 7
must_accept real_tpm2_tools_shape run_hook
# The OTA helper suite's mock prints the same fields in lowercase; both
# spellings of the same bytes are the same contract.
must_accept lowercase_policy_and_word run_hook NI_TEST_NV_POLICY="$POLICY" NI_TEST_NV_ATTRIBUTES=0x20060018

# Old signed UKIs and an activation interrupted before the NV advance are both
# rejected.  After the durable boundary advances, only the new UKI can unlock.
write_cmdline 6
must_refuse old_uki run_hook
write_cmdline 8
must_refuse power_before_nv_advance run_hook
must_accept after_nv_advance run_hook NI_TEST_COUNTER_SEQ=8
write_cmdline 7
must_refuse old_uki_after_power_cycle run_hook NI_TEST_COUNTER_SEQ=8

printf 'quiet neuralice.pcr_policy_signature=%s\n' "$HASH" >"$cmdline"
must_refuse absent_sequence run_hook
printf 'neuralice.pcr_policy_seq=7 neuralice.pcr_policy_seq=7 neuralice.pcr_policy_signature=%s\n' "$HASH" >"$cmdline"
must_refuse duplicate_sequence run_hook
write_cmdline 7
must_refuse wrong_size run_hook NI_TEST_NV_SIZE=9
must_refuse wrong_attributes run_hook NI_TEST_NV_ATTRIBUTES=0x20060019
must_refuse unwritten_counter run_hook NI_TEST_NV_ATTRIBUTES=0x60018
must_refuse wrong_policy run_hook NI_TEST_NV_POLICY="${POLICY%?}1"
must_refuse short_counter run_hook NI_TEST_COUNTER_SEQ=short

# 🔴 THE PARSER MUTATIONS (review 2026-09-02, P0). The hook used to read the
# word off the `attributes:` heading, which the real tool never carries, and
# its mock printed that flat form -- green suite, every real unlock refused.
# Each malformed or legacy public area must be refused BEFORE the counter is
# read (the tpm2_nvread double leaves a trace when it runs), so no shape
# reaches the equality check, let alone the LUKS signature staging.
trace="$fixture/nvread-trace"
for shape in legacy-flat attributes-value-absent attributes-section-absent \
    attributes-section-duplicated attributes-value-duplicated attributes-value-not-hex \
    value-outside-section wrong-index header-absent header-duplicated policy-absent \
    policy-empty size-absent unknown-line empty; do
  rm -f "$trace" "$test_root/run/systemd/tpm2-pcr-signature.json"
  must_refuse "public_area_$shape" run_hook NI_TEST_NV_SHAPE="$shape" NI_TEST_NVREAD_TRACE="$trace"
  if [ -e "$trace" ]; then
    echo "public_area_$shape reached the counter read" >&2
    exit 1
  fi
  if [ -e "$test_root/run/systemd/tpm2-pcr-signature.json" ]; then
    echo "public_area_$shape staged the LUKS policy signature" >&2
    exit 1
  fi
done
# A public area the tool refuses to describe is the same refusal.
must_refuse public_area_unavailable run_hook NI_TEST_NV_SHAPE=tool-failure NI_TEST_NVREAD_TRACE="$trace"
[ ! -e "$trace" ] || { echo "unavailable public area reached the counter read" >&2; exit 1; }

# A signed Install UKI reaches this hook before its first LUKS enrollment can
# activate the PCR-policy counter. Absence is accepted only for that exact
# selector, an empty owner hierarchy and no partial Neural ICE appliance state.
write_install_cmdline 1
must_refuse virgin_install_without_media_marker run_hook NI_TEST_NV_SHAPE=tool-failure
mkdir -p "$test_root/etc/neural-ice"
printf 'neural-ice-signed-installer-initramfs-v1\n' >"$test_root/etc/neural-ice/installer-media"
rm -f "$trace"
must_accept virgin_install run_hook NI_TEST_NV_SHAPE=tool-failure NI_TEST_NVREAD_TRACE="$trace"
[ ! -e "$trace" ] || { echo "virgin install tried to read an absent counter" >&2; exit 1; }
must_accept virgin_install_with_unrelated_firmware_indices run_hook \
  NI_TEST_NV_SHAPE=tool-failure \
  NI_TEST_NV_HANDLES='- 0x1C00002\n- 0x1C00016\n'
must_refuse virgin_install_owner_auth_set run_hook \
  NI_TEST_NV_SHAPE=tool-failure NI_TEST_OWNER_AUTH_SET=1
for owner_shape in duplicate missing malformed; do
  must_refuse "virgin_install_owner_$owner_shape" run_hook \
    NI_TEST_NV_SHAPE=tool-failure NI_TEST_OWNER_AUTH_SHAPE="$owner_shape"
done
must_refuse virgin_install_handles_unavailable run_hook \
  NI_TEST_NV_SHAPE=tool-failure NI_TEST_GETCAP_HANDLES_FAIL=1
must_refuse virgin_install_properties_unavailable run_hook \
  NI_TEST_NV_SHAPE=tool-failure NI_TEST_GETCAP_PROPERTIES_FAIL=1
must_refuse virgin_install_malformed_handles run_hook \
  NI_TEST_NV_SHAPE=tool-failure NI_TEST_NV_HANDLES='not-a-handle\n'
must_refuse virgin_install_unreadable_existing_policy run_hook \
  NI_TEST_NV_SHAPE=tool-failure NI_TEST_NV_HANDLES='- 0x1500007\n'
for partial in 0x1500001 0x1500002 0x1500003 0x1500004 0x1500005 0x1500006; do
  must_refuse "virgin_install_partial_${partial#0x}" run_hook \
    NI_TEST_NV_SHAPE=tool-failure NI_TEST_NV_HANDLES="- $partial\n"
done

write_install_cmdline 4097
must_refuse virgin_install_sequence_above_initial_window run_hook NI_TEST_NV_SHAPE=tool-failure
write_install_cmdline 1 'systemd.unit=neural-ice-installer.target'
must_refuse virgin_install_duplicate_unit run_hook NI_TEST_NV_SHAPE=tool-failure
write_install_cmdline 1 'neuralice.autoinstall=0'
must_refuse virgin_install_duplicate_autoinstall run_hook NI_TEST_NV_SHAPE=tool-failure
write_install_cmdline 1 'neuralice.trust=other'
must_refuse virgin_install_duplicate_trust run_hook NI_TEST_NV_SHAPE=tool-failure
write_install_cmdline 1 'neuralice.payload=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
must_refuse virgin_install_duplicate_payload run_hook NI_TEST_NV_SHAPE=tool-failure
write_install_cmdline 1 'neuralice.live=1'
must_refuse virgin_install_live_selector run_hook NI_TEST_NV_SHAPE=tool-failure
printf 'quiet neuralice.autoinstall=1 neuralice.trust=neural-ice-installer-trust-v1 neuralice.pcr_policy_seq=1 neuralice.pcr_policy_signature=%s\n' \
  "$HASH" >"$cmdline"
must_refuse virgin_install_missing_unit run_hook NI_TEST_NV_SHAPE=tool-failure
printf 'wrong-marker\n' >"$test_root/etc/neural-ice/installer-media"
write_install_cmdline 1
must_refuse virgin_install_wrong_media_marker run_hook NI_TEST_NV_SHAPE=tool-failure
printf 'neural-ice-signed-installer-initramfs-v1\n' >"$test_root/etc/neural-ice/installer-media"

# The parser is a dependency of the signed hook, not an optional refinement:
# an initramfs without it refuses rather than falling back to a looser read.
write_cmdline 7
mv "$test_root/lib/neural-ice-tpm2-nv-public.sh" "$fixture/parser.aside"
must_refuse parser_absent run_hook
mv "$fixture/parser.aside" "$test_root/lib/neural-ice-tpm2-nv-public.sh"
must_accept parser_restored run_hook

mkdir -p "$test_root/usr/lib/neural-ice"
: >"$test_root/usr/lib/neural-ice/release-image"
must_refuse release_image_test_seam run_hook

echo "TPM_POLICY_INITRAMFS_TESTS_OK $cases"
