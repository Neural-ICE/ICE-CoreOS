#!/usr/bin/env bash
# shellcheck disable=SC2016 # literal source-contract assertions below
# EVERY DESTRUCTIVE INPUT IS READ EXACTLY ONCE, OR NOT AT ALL.
#
# 🔴 THE HOLE THIS CLOSES. The six sealed fields and the SSH key already refused
# a second occurrence. Everything else used
# `grep -qE 'KEY=' && sed -n 's/.*KEY=\([^ ]*\).*/\1/p'` -- a GREEDY match that
# silently keeps the LAST occurrence. An appended `neuralice.target=/dev/nvme1n1`
# is not a sealed-field duplicate, so the trust gate still succeeded, and the
# winner that greedy sed picked steered the WIPE. The same held for the image
# reference, the mirror, the install source and the system size.
#
# This suite EXERCISES the reader against a fixture command line rather than
# grepping the installer's source: a source-shape assertion cannot tell you which
# value a parser would have chosen.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AUTOINSTALL="$ROOT/ota/neural-ice-autoinstall.sh"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/ni-kargs.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

# The installer is a top-to-bottom script that wipes disks; it cannot be sourced.
# Extract exactly the two functions under test, verbatim, so the suite runs the
# SAME code the appliance runs rather than a paraphrase of it.
{
  awk '/^karg_count\(\) \{/,/^}$/' "$AUTOINSTALL"
  awk '/^karg_once\(\) \{/,/^}$/' "$AUTOINSTALL"
  awk '/^candidate_ota_state_profile\(\) \{/,/^}$/' "$AUTOINSTALL"
  awk '/^require_medium_source_profile\(\) \{/,/^}$/' "$AUTOINSTALL"
  awk '/^verify_installed_preseal_candidate\(\) \{/,/^}$/' "$AUTOINSTALL"
  awk '/^encode_snapshotted_ssh_key\(\) \{/,/^}$/' "$AUTOINSTALL"
} > "$TMP/reader.sh"
grep -q '^karg_count()' "$TMP/reader.sh" || fail "cannot extract karg_count from the installer"
grep -q '^karg_once()'  "$TMP/reader.sh" || fail "cannot extract karg_once from the installer"

CMDLINE="$TMP/cmdline"
die() { echo "die: $*" >&2; exit 1; }
# Consumed by the extracted reader below, not by this file — hence the disable.
# shellcheck disable=SC2034
NEURALICE_CMDLINE_FILE="$CMDLINE"
# shellcheck source=/dev/null
source "$TMP/reader.sh"

# A registry key is snapshotted before the candidate pull and consumed only
# after authentication. Encoding must therefore revalidate the exact snapshot,
# not trust the earlier verdict or reread the mutable ESP path.
grep -q '^encode_snapshotted_ssh_key()' "$TMP/reader.sh" \
  || fail "cannot extract encode_snapshotted_ssh_key from the installer"
# shellcheck source=image/lib/installer-ssh-key.sh
source "$ROOT/image/lib/installer-ssh-key.sh"
key_fixture="$TMP/operator-key"
ssh-keygen -q -t ed25519 -N '' -f "$key_fixture" </dev/null
key_snapshot="$TMP/operator-snapshot.pub"
cp "$key_fixture.pub" "$key_snapshot"
key_snapshot_sha256="$(sha256sum "$key_snapshot" | awk '{print $1}')"
encoded_snapshot="$(encode_snapshotted_ssh_key "$key_snapshot" "$key_snapshot_sha256")" \
  || fail "an unchanged single public-key snapshot was refused"
printf '%s' "$encoded_snapshot" | base64 -d > "$TMP/encoded-snapshot.pub"
cmp -s "$key_snapshot" "$TMP/encoded-snapshot.pub" \
  || fail "the installed SSH karg bytes differ from the validated snapshot"

ssh-keygen -q -t ed25519 -N '' -f "$TMP/other-key" </dev/null
cp "$TMP/other-key.pub" "$key_snapshot"
encode_snapshotted_ssh_key "$key_snapshot" "$key_snapshot_sha256" >/dev/null 2>&1 \
  && fail "a changed SSH snapshot was encoded after its validation verdict"
cat "$key_fixture.pub" "$TMP/other-key.pub" > "$TMP/multiple-keys.pub"
multiple_sha256="$(sha256sum "$TMP/multiple-keys.pub" | awk '{print $1}')"
encode_snapshotted_ssh_key "$TMP/multiple-keys.pub" "$multiple_sha256" >/dev/null 2>&1 \
  && fail "multiple SSH keys were encoded"
printf '%s\n' not-an-openssh-key > "$TMP/malformed-key.pub"
malformed_sha256="$(sha256sum "$TMP/malformed-key.pub" | awk '{print $1}')"
encode_snapshotted_ssh_key "$TMP/malformed-key.pub" "$malformed_sha256" >/dev/null 2>&1 \
  && fail "a malformed SSH snapshot was encoded"
ln -s "$key_fixture.pub" "$TMP/symlink-key.pub"
encode_snapshotted_ssh_key "$TMP/symlink-key.pub" \
  "$(sha256sum "$key_fixture.pub" | awk '{print $1}')" >/dev/null 2>&1 \
  && fail "a symlink SSH snapshot was encoded"
grep -Fq 'sshkey_karg=(--karg "neuralice.sshkey=$SSHKEY_B64")' "$AUTOINSTALL" \
  || fail "the installed kernel argument is not built from the accepted snapshot encoding"

set_cmdline() { printf '%s\n' "$*" > "$CMDLINE"; }

# The medium source has no authenticated eight-file transport. Its historical
# unmarked image remains supported, while an owner-profile or malformed marker
# refuses before the first destructive call. Exercise the production helpers;
# the marker is read from the real usr/lib layout of a mounted candidate.
medium_root="$TMP/medium-root"
mkdir -p "$medium_root/usr/lib/neural-ice"
destructive="$TMP/destructive-called"
medium_attempt() (
  profile="$(candidate_ota_state_profile "$medium_root")" || exit 1
  require_medium_source_profile "$profile"
  : > "$destructive"
)
medium_attempt || fail "the historical unmarked medium source was refused"
[[ -e "$destructive" ]] || fail "the admitted legacy medium did not reach the synthetic destructive boundary"
rm -f "$destructive"
printf '%s\n' owner-sealed-ota-state-v1 > "$medium_root/usr/lib/neural-ice/ota-state-profile"
medium_attempt >/dev/null 2>&1 && fail "an owner-profile medium without preseal transport was admitted"
[[ ! -e "$destructive" ]] || fail "an owner-profile medium reached the destructive boundary"
# Consumed by the exact extracted require_medium_source_profile helper.
# shellcheck disable=SC2034
PRESEAL_SET_SHA256="$(printf '%064d' 8)"
medium_attempt || fail "an owner-profile medium carrying its authenticated preseal transport was refused"
[[ -e "$destructive" ]] \
  || fail "the admitted offline owner-profile medium did not reach the synthetic destructive boundary"
rm -f "$destructive"
unset PRESEAL_SET_SHA256
printf '%s\n' owner-sealed-ota-state-v1 malformed > "$medium_root/usr/lib/neural-ice/ota-state-profile"
medium_attempt >/dev/null 2>&1 && fail "a malformed medium OTA-state profile was admitted"
[[ ! -e "$destructive" ]] || fail "a malformed medium profile reached the destructive boundary"

# Execute the production sealed-store preflight with a fake Podman that refuses
# every create lacking --pull=never. An absent local object must fail here,
# before the synthetic wipe boundary, rather than trigger registry resolution.
printf '%s\n' owner-sealed-ota-state-v1 > "$medium_root/usr/lib/neural-ice/ota-state-profile"
awk '/^podman .* image exists "\$STORE_IMAGE_NAME"/,/^log "Sealed image store registered read-only/' \
  "$AUTOINSTALL" > "$TMP/store-preflight.sh"
grep -q 'create --pull=never' "$TMP/store-preflight.sh" \
  || fail "the extracted store preflight has no no-pull container creation"
# The variables and functions are consumed by the sourced production block;
# ShellCheck does not connect that generated file to this lexical scope.
# shellcheck disable=SC2034,SC2317,SC2329
store_preflight_attempt() (
  local object_present=$1 boundary=$2
  PRESEAL_SET_SHA256="$(printf '%064d' 8)"
  STORE_IMAGE_NAME=localhost/bootc
  STORE_MOUNT="$TMP/store"
  INSTALL_SOURCE=medium
  podman() {
    case " $* " in
      *" image exists "*) (( object_present == 1 )) ;;
      *" image inspect "*) printf 'sha256:%064d\n' 9 ;;
      *" create "*)
        [[ " $* " == *" --pull=never "* ]] || return 97
        (( object_present == 1 ))
        ;;
      *" mount "*) printf '%s\n' "$medium_root" ;;
      *" unmount "*|*" rm "*) return 0 ;;
      *) return 96 ;;
    esac
  }
  log() { :; }
  # shellcheck source=/dev/null
  source "$TMP/store-preflight.sh"
  : > "$boundary"
)
store_preflight_boundary="$TMP/store-preflight-boundary"
store_preflight_attempt 1 "$store_preflight_boundary" \
  || fail "the exact no-pull sealed-store preflight refused its present local object"
[[ -e "$store_preflight_boundary" ]] \
  || fail "the successful local store preflight did not reach its synthetic wipe boundary"
rm -f "$store_preflight_boundary"
store_preflight_attempt 0 "$store_preflight_boundary" >/dev/null 2>&1 \
  && fail "the exact sealed-store preflight admitted an absent local object"
[[ ! -e "$store_preflight_boundary" ]] \
  || fail "an absent local object reached the synthetic wipe boundary"

# Both later consumers are equally forbidden from resolving a network name:
# candidate inspection and the bootc runner must consume only the object proved
# above. Their actual command lines are kept explicit and audited here.
[[ "$(grep -c 'create --pull=never' "$AUTOINSTALL")" == 2 ]] \
  || fail "not every pre-wipe container creation is pinned to the local store"
grep -Fq 'run --pull=never --rm --privileged' "$AUTOINSTALL" \
  || fail "the bootc installer container may apply a registry pull policy"
# The pre-wipe bootc container probe must not depend on the console: podman
# refuses `--log-driver passthrough` on a TTY (hardware, 2026-09-09) and
# `passthrough-tty` off one. Its verdict travels through a file.
grep -Eq -- '--log-driver=passthrough([^-]|$)' "$AUTOINSTALL" \
  && fail "a bootc container invocation uses the non-tty passthrough log driver, which a TTY console refuses"
grep -Fq -- '--log-driver=none' "$AUTOINSTALL" \
  || fail "the pre-wipe bootc container probe does not decouple its verdict from the console"
grep -Fq 'BOOTC-CONTAINER-SOURCE-OK > "$r"' "$AUTOINSTALL" \
  || fail "the pre-wipe bootc container probe does not write its verdict to a file"
# The bootc container reads its source under the INSTALLER's signature policy,
# not the appliance's strict one (which rejects containers-storage), and the
# pre-wipe probe proves that policy admits the transport.
grep -Fq -- '-v "$NEURALICE_CONTAINER_POLICY:/etc/containers/policy.json:ro"' "$AUTOINSTALL" \
  || fail "the bootc container is left with the appliance's strict policy, which rejects the containers-storage source"
grep -Fq 'would reject the containers-storage source' "$AUTOINSTALL" \
  || fail "the pre-wipe probe does not prove the container's policy admits the source"

# The post-bootc verifier consumes the resolved deployment root, not the
# /var/tmp/nitarget OSTree sysroot. Make the distinction executable with the
# actual directory shape and marker locations the Rust verifier reads.
TGT="$TMP/nitarget"
dep="$TGT/ostree/deploy/neuralice/deploy/0123456789abcdef.0"
mkdir -p "$dep/usr/lib/neural-ice/product-payload"
printf '%s\n' owner-sealed-ota-state-v1 > "$dep/usr/lib/neural-ice/ota-state-profile"
printf '%040d\n' 6 > "$dep/usr/lib/neural-ice/product-payload/PAYLOAD_ID"
verify_preseal_candidate() {
  [[ "$1" == "$TMP/installed-inputs" \
     && "$2" == "$dep" \
     && "$(cat "$2/usr/lib/neural-ice/ota-state-profile")" == owner-sealed-ota-state-v1 \
     && "$(cat "$2/usr/lib/neural-ice/product-payload/PAYLOAD_ID")" == "$(printf '%040d' 6)" \
     && "$3" == "$(printf '%040d' 6)" \
     && "$4" == "$TMP/installed.conf" \
     && "$5" == "$TMP/receipt.json" \
     && "$6" == "release.example.test/neural-ice/neural-ice-appliance@sha256:$(printf '%064d' 8)" \
     && "$7" == "sha256:$(printf '%064d' 9)" ]] || return 1
  printf '%s\n' 7
}
[[ "$(verify_installed_preseal_candidate "$TMP/installed-inputs" \
  "$(printf '%040d' 6)" "$TMP/installed.conf" "$TMP/receipt.json" \
  "release.example.test/neural-ice/neural-ice-appliance@sha256:$(printf '%064d' 8)" \
  "sha256:$(printf '%064d' 9)")" == 7 ]] \
  || fail "the installed preseal verifier did not receive the resolved OSTree deployment root"

# --------------------------------------------------------------------------- #
# 1) ABSENT is empty, PRESENT ONCE is the value, PRESENT TWICE is a refusal.
# --------------------------------------------------------------------------- #
set_cmdline "quiet enforcing=0"
[ -z "$(karg_once neuralice.target)" ] || fail "an absent argument produced a value"

set_cmdline "quiet neuralice.target=/dev/nvme0n1 enforcing=0"
[ "$(karg_once neuralice.target)" = /dev/nvme0n1 ] || fail "a single argument was not read"

# 🔴 THE ATTACK. Appending a second `neuralice.target=` used to steer the wipe
# while every other gate still succeeded. Neither the first nor the last may win.
set_cmdline "neuralice.target=/dev/nvme0n1 quiet neuralice.target=/dev/sda"
( karg_once neuralice.target ) >/dev/null 2>&1 \
  && fail "a duplicated wipe target was resolved instead of refused"
set_cmdline "neuralice.target=/dev/sda quiet neuralice.target=/dev/nvme0n1"
( karg_once neuralice.target ) >/dev/null 2>&1 \
  && fail "a prepended duplicate wipe target was resolved instead of refused"

# Every security-relevant argument, both orders. A list is only a control if it
# is complete, so each one is exercised rather than assumed to share code.
for key in neuralice.target neuralice.imgref neuralice.osimage neuralice.mirror \
  neuralice.source neuralice.systemsize neuralice.sshkey neuralice.preseal; do
  set_cmdline "quiet ${key}=first ${key}=second"
  ( karg_once "$key" ) >/dev/null 2>&1 \
    && fail "a duplicated $key was resolved instead of refused"
  [ "$(karg_count "$key")" = 2 ] || fail "karg_count miscounted a duplicated $key"
  set_cmdline "quiet ${key}=only"
  [ "$(karg_once "$key")" = only ] || fail "$key was not read when present exactly once"
done

# Owner-profile installs carry eight authenticated inputs across the wipe. The
# snapshot and the complete cryptographic candidate proof must both precede the
# first destructive command; post-bootc only the same protected bytes may be
# published and reverified before TPM NV preparation.
line_of() { grep -nF -- "$1" "$AUTOINSTALL" | head -1 | cut -d: -f1 || true; }
preseal_snapshot_line="$(line_of 'snapshot_preseal_from_esp "$PRESEAL_SNAPSHOT"')"
preseal_preflight_line="$(line_of 'PRESEAL_BUNDLE_SEQ="$(verify_preseal_candidate "$PRESEAL_SNAPSHOT"')"
medium_profile_gate_line="$(line_of 'require_medium_source_profile "$_medium_ota_profile"')"
wipe_line="$(grep -nE '^[[:space:]]*wipefs -a "\$target"' "$AUTOINSTALL" | head -1 | cut -d: -f1)"
bootc_line="$(awk '$1 == "bootc" && $2 == "install" && $3 == "to-filesystem" { print NR; exit }' "$AUTOINSTALL")"
handoff_line="$(line_of '"$PRESEAL_HANDOFF" install-persistent')"
installed_verify_line="$(line_of '_installed_preseal_floor="$(verify_installed_preseal_candidate "$PRESEAL_INSTALLED_INPUTS"')"
installed_runtime_config_line="$(line_of 'write_preseal_verifier_config "/var/lib/neural-ice/ota"')"
installed_mapped_config_line="$(line_of 'write_preseal_verifier_config "$ota_state" "$PRESEAL_INSTALLED_CONFIG"')"
installed_config_publish_line="$(line_of 'mv -T -- "$INSTALLED_OTA_CONFIG_CANDIDATE" "$INSTALLED_OTA_CONFIG"')"
prepare_line="$(line_of '"$OTA_TPM_STATE" prepare "$PRESEAL_BUNDLE_SEQ"')"
inspect_line="$(line_of '"$OTA_TPM_STATE" inspect-v2')"
status_line="$(line_of '"$TPM_STATE" provisioning-status)" == preseal-prepared')"
[[ -n "$preseal_snapshot_line" && -n "$preseal_preflight_line" \
   && -n "$medium_profile_gate_line" && -n "$wipe_line" \
   && -n "$bootc_line" && -n "$handoff_line" && -n "$installed_verify_line" \
   && -n "$installed_runtime_config_line" && -n "$installed_mapped_config_line" \
   && -n "$installed_config_publish_line" && -n "$prepare_line" \
   && -n "$inspect_line" && -n "$status_line" \
   && "$preseal_snapshot_line" -lt "$preseal_preflight_line" \
   && "$preseal_preflight_line" -lt "$wipe_line" \
   && "$medium_profile_gate_line" -lt "$wipe_line" \
   && "$wipe_line" -lt "$bootc_line" && "$bootc_line" -lt "$handoff_line" \
   && "$handoff_line" -lt "$installed_runtime_config_line" \
   && "$installed_runtime_config_line" -lt "$installed_mapped_config_line" \
   && "$installed_mapped_config_line" -lt "$installed_verify_line" \
   && "$installed_verify_line" -lt "$installed_config_publish_line" \
   && "$installed_config_publish_line" -lt "$prepare_line" \
   && "$prepare_line" -lt "$inspect_line" && "$inspect_line" -lt "$status_line" ]] \
  || fail "the authenticated eight-input preseal handoff is not ordered around the wipe and bootc install"

for required in \
  'the selected owner-sealed appliance has no UKI-bound preseal inputs' \
  'the selected legacy appliance cannot consume this medium' \
  'the UKI-bound preseal inputs do not authenticate the selected appliance before disk mutation' \
  '--current-os-ref "$current_os_ref"' \
  '--current-os-manifest-digest "$current_manifest"' \
  '--current-seed-ref "$current_seed"' \
  '--candidate-root "$candidate_root"' \
  '"$PRESEAL_HANDOFF" verify-persistent' \
  'cmp -- "$PRESEAL_PREFLIGHT_RECEIPT" "$PRESEAL_INSTALLED_RECEIPT"' \
  'sync -f "$PRESEAL_INSTALLED_INPUTS"' \
  'sync -f "$ota_state"' \
  'the complete TPM state is not the exact preseal-prepared lifecycle checkpoint'; do
  grep -Fq -- "$required" "$AUTOINSTALL" \
    || fail "the owner-profile preseal contract is incomplete: $required"
done
# 🔴 A NAME READ BEFORE IT IS ASSIGNED IS A SILENT DEATH, NOT A REFUSAL. The
# installer runs under `set -u`; a top-level reference that precedes the
# assignment exits with no `die`, no evidence and no console line. The first
# registry-mirror medium died exactly so on the bench (2026-09-06): the signature
# policy gate referenced NEURALICE_REGISTRY_AUTHORISATION and
# NEURALICE_CONTAINER_POLICY ~70 lines before either was assigned, and every
# suite had them exported through the test seam, so no test ran this order.
registry_reader_def="$(grep -nE '^NEURALICE_REGISTRY_AUTHORISATION="\$\(ni_path ' "$AUTOINSTALL" | head -1 | cut -d: -f1)"
container_policy_def="$(grep -nE '^NEURALICE_CONTAINER_POLICY="\$\(ni_path ' "$AUTOINSTALL" | head -1 | cut -d: -f1)"
registry_gate_line="$(line_of '[[ -f "$NEURALICE_REGISTRY_AUTHORISATION" && ! -L "$NEURALICE_REGISTRY_AUTHORISATION" ]]')"
container_policy_gate_line="$(line_of '[[ -f "$NEURALICE_CONTAINER_POLICY" && ! -L "$NEURALICE_CONTAINER_POLICY" ]]')"
[[ -n "$registry_reader_def" && -n "$container_policy_def" \
   && -n "$registry_gate_line" && -n "$container_policy_gate_line" \
   && "$registry_reader_def" -lt "$registry_gate_line" \
   && "$container_policy_def" -lt "$container_policy_gate_line" ]] \
  || fail "the registry signature-policy gate reads a name the installer has not assigned yet (set -u kills it silently on a registry medium)"
# The same class, generically: no top-level `$NAME` may precede `NAME=` for any
# ni_path-assigned NAME. Function bodies are skipped because they run later.
while IFS= read -r name; do
  def="$(grep -nE "^${name}=\"\\\$\(ni_path " "$AUTOINSTALL" | head -1 | cut -d: -f1)"
  first_use="$(awk -v n="$name" -v def="$def" '
    /^[A-Za-z_][A-Za-z_0-9]*\(\) *\{/ { infn=1 } infn && /^\}$/ { infn=0; next }
    !infn && NR < def && $0 !~ /^[[:space:]]*#/ && index($0, "$" n) { print NR; exit }' "$AUTOINSTALL")"
  [[ -z "$first_use" ]] \
    || fail "$name is read at line $first_use before its assignment at line $def"
done < <(grep -oE '^[A-Z_][A-Z_0-9]*="\$\(ni_path ' "$AUTOINSTALL" | sed 's/=.*//' | sort -u)
# 🔴 THE PRESEAL VERIFIER CONFIG TAKES DEVICE COMPAT FROM THE UKI-BOUND SET.
# The vanilla image ships device_compat_min/max unset by design; the writer used
# to require them and refused every registry install of a vanilla image
# (bench 2026-09-06). Exercise the real function against fixtures.
{
  awk '/^write_preseal_verifier_config\(\) \{/,/^}$/' "$AUTOINSTALL"
} > "$TMP/preseal-config.sh"
grep -q '^write_preseal_verifier_config()' "$TMP/preseal-config.sh" \
  || fail "cannot extract write_preseal_verifier_config from the installer"
compat_root="$TMP/verity-root"
mkdir -p "$compat_root/etc/neural-ice/keys"
printf 'enforce=0\nroot_pubkey=/etc/neural-ice/keys/ota-root.pub\nstate_dir=/var/lib/neural-ice/ota\nhardware_target=nvidia-gb10-arm64\n#device_compat_min=1\n#device_compat_max=3\n' \
  > "$compat_root/etc/neural-ice/ota.conf"
: > "$compat_root/etc/neural-ice/keys/ota-root.pub"
printf '{"compat_max":5,"compat_min":5,"schema":"neural-ice-installer-preseal-set-v1"}\n' > "$TMP/preseal-set.json"
compat_out="$(
  VERITY_ROOT_MOUNT="$compat_root" bash -c '
    set -euo pipefail
    die() { echo "die: $*" >&2; exit 1; }
    source "$1"
    write_preseal_verifier_config "$2" "$3" "$4"
    cat "$3"
  ' _ "$TMP/preseal-config.sh" "$TMP/state" "$TMP/verifier.conf" "$TMP/preseal-set.json"
)" || fail "the preseal verifier config refused a vanilla image whose compat is unset"
grep -qx 'device_compat_min=5' <<<"$compat_out" \
  || fail "the preseal verifier config did not take device_compat_min from the preseal set"
grep -qx 'device_compat_max=5' <<<"$compat_out" \
  || fail "the preseal verifier config did not take device_compat_max from the preseal set"
grep -qx "state_dir=$TMP/state" <<<"$compat_out" \
  || fail "the preseal verifier config did not rebase state_dir"

# The authenticated compat range must survive into the installed runtime
# configuration, not only the installer's /run verifier file. Start from the
# exact vanilla config shipped by the image; a handcrafted already-correct
# fixture would hide the production regression. The same generated bytes are
# then mapped back to installer-visible paths, matching the post-bootc
# reauthentication that precedes first boot.
installed_root="$TMP/installed-root"
installed_config="$installed_root/etc/neural-ice/ota.conf"
installed_root_key="$installed_root/etc/neural-ice/keys/ota-root.pub"
installed_candidate="$installed_root/etc/neural-ice/.ota.conf.neural-ice-installer"
mkdir -p "$(dirname "$installed_root_key")"
cp "$ROOT/image/bootc-overlay/etc/neural-ice/ota.conf" "$installed_config"
: > "$installed_root_key"
runtime_out="$(
  VERITY_ROOT_MOUNT="$compat_root" bash -c '
    set -euo pipefail
    die() { echo "die: $*" >&2; exit 1; }
    source "$1"
    write_preseal_verifier_config "/var/lib/neural-ice/ota" "$2" "$3" \
      "$4" "/etc/neural-ice/keys/ota-root.pub" "$5"
    cat "$2"
  ' _ "$TMP/preseal-config.sh" "$installed_candidate" "$TMP/preseal-set.json" \
    "$installed_config" "$installed_root_key"
)" || fail "the production helper could not derive installed config from the vanilla target"
grep -qx 'root_pubkey=/etc/neural-ice/keys/ota-root.pub' <<<"$runtime_out" \
  || fail "the installed config retained the installer's root-key path"
grep -qx 'state_dir=/var/lib/neural-ice/ota' <<<"$runtime_out" \
  || fail "the installed config retained the installer's mounted state path"
grep -qx 'device_compat_min=5' <<<"$runtime_out" \
  || fail "the installed config did not persist authenticated device_compat_min"
grep -qx 'device_compat_max=5' <<<"$runtime_out" \
  || fail "the installed config did not persist authenticated device_compat_max"
for adjacent in 'enforce=0' 'nv_index=0x01500001' \
  'state_nv_index=0x01500002' 'hardware_target=nvidia-gb10-arm64'; do
  grep -qx "$adjacent" <<<"$runtime_out" \
    || fail "the installed config lost adjacent runtime key: $adjacent"
done
if grep -Fq "$TMP" <<<"$runtime_out" || grep -q '^root_pubkey=/run/' <<<"$runtime_out"; then
  fail "the installed config persisted an installer-only path"
fi

mv -T -- "$installed_candidate" "$installed_config"
mapped_out="$(
  VERITY_ROOT_MOUNT="$compat_root" bash -c '
    set -euo pipefail
    die() { echo "die: $*" >&2; exit 1; }
    source "$1"
    write_preseal_verifier_config "$2" "$3" "$4" "$5" "$6" "$6"
    cat "$3"
  ' _ "$TMP/preseal-config.sh" "$TMP/installed-state" "$TMP/installed-verifier.conf" \
    "$TMP/preseal-set.json" "$installed_config" "$installed_root_key"
)" || fail "the installed runtime config could not be mapped for post-bootc reauthentication"
grep -qx "root_pubkey=$installed_root_key" <<<"$mapped_out" \
  || fail "the post-bootc config did not map the runtime root key into the deployment"
grep -qx "state_dir=$TMP/installed-state" <<<"$mapped_out" \
  || fail "the post-bootc config did not map runtime state into the installed stateroot"
if ! grep -qx 'device_compat_min=5' <<<"$mapped_out" \
    || ! grep -qx 'device_compat_max=5' <<<"$mapped_out"; then
  fail "the post-bootc mapping changed the persisted authenticated compat range"
fi

# A complete image-declared range remains authoritative input to the verifier.
# The helper must not rewrite a mismatch into apparent success; the production
# verifier's mismatch refusal is covered by preseal_cli.rs and is ordered above
# before publication.
declared_config="$TMP/declared-compat.conf"
sed -e 's/^#device_compat_min=1$/device_compat_min=4/' \
  -e 's/^#device_compat_max=3$/device_compat_max=5/' \
  "$ROOT/image/bootc-overlay/etc/neural-ice/ota.conf" > "$declared_config"
declared_out="$(
  VERITY_ROOT_MOUNT="$compat_root" bash -c '
    set -euo pipefail
    die() { echo "die: $*" >&2; exit 1; }
    source "$1"
    write_preseal_verifier_config "/var/lib/neural-ice/ota" "$2" "$3" \
      "$4" "/etc/neural-ice/keys/ota-root.pub" "$5"
    cat "$2"
  ' _ "$TMP/preseal-config.sh" "$TMP/declared-output.conf" "$TMP/preseal-set.json" \
    "$declared_config" "$installed_root_key"
)" || fail "a complete declared compat range was rejected before authentication"
if ! grep -qx 'device_compat_min=4' <<<"$declared_out" \
    || ! grep -qx 'device_compat_max=5' <<<"$declared_out"; then
  fail "a declared compatibility mismatch was silently rewritten"
fi

symlink_victim="$TMP/symlink-victim"
symlink_destination="$TMP/symlink-config"
printf '%s\n' unchanged > "$symlink_victim"
ln -s "$symlink_victim" "$symlink_destination"
if VERITY_ROOT_MOUNT="$compat_root" bash -c '
    set -euo pipefail
    die() { exit 1; }
    source "$1"
    write_preseal_verifier_config "/var/lib/neural-ice/ota" "$2" "$3" \
      "$4" "/etc/neural-ice/keys/ota-root.pub" "$5"
  ' _ "$TMP/preseal-config.sh" "$symlink_destination" "$TMP/preseal-set.json" \
    "$installed_config" "$installed_root_key" 2>/dev/null; then
  fail "a symlink verifier-config destination was accepted"
fi
[[ "$(cat "$symlink_victim")" == unchanged ]] \
  || fail "the rejected verifier-config symlink write altered its target"

printf 'enforce=0\nroot_pubkey=/x\nstate_dir=/y\ndevice_compat_min=5\n' > "$compat_root/etc/neural-ice/ota.conf"
if VERITY_ROOT_MOUNT="$compat_root" bash -c '
    set -euo pipefail
    die() { exit 1; }
    source "$1"
    write_preseal_verifier_config "$2" "$3" "$4"
  ' _ "$TMP/preseal-config.sh" "$TMP/state" "$TMP/verifier2.conf" "$TMP/preseal-set.json" 2>/dev/null; then
  fail "a half-declared device compat pair was accepted"
fi
unset -f line_of

# A key that merely CONTAINS another key's name must not be counted as it: a
# substring match would make `neuralice.targetfoo=` shadow `neuralice.target=`.
set_cmdline "quiet neuralice.targeting=x neuralice.target=/dev/nvme0n1"
[ "$(karg_once neuralice.target)" = /dev/nvme0n1 ] \
  || fail "a similarly-named argument was confused with the real one"
# ...and a value that happens to contain the key name is still one occurrence.
set_cmdline "quiet neuralice.imgref=example.test/x:neuralice.imgref=y"
[ "$(karg_count neuralice.imgref)" = 1 ] \
  || fail "a value containing the key name was counted twice"

# --------------------------------------------------------------------------- #
# 2) THE INSTALLER MUST USE IT, and must not have kept a greedy reader anywhere.
# --------------------------------------------------------------------------- #
for key in neuralice.imgref neuralice.osimage neuralice.mirror neuralice.source \
  neuralice.systemsize neuralice.target; do
  grep -Fq "karg_once $key" "$AUTOINSTALL" \
    || fail "the installer does not read $key through the single-occurrence reader"
done
# The old shape, in any spelling, must be gone rather than merely unused.
grep -nE "sed -n 's/\.\*neuralice\\\\?\." "$AUTOINSTALL" \
  && fail "the installer still parses a kernel argument with a greedy sed"
grep -nE "grep -qE 'neuralice\\\\?\." "$AUTOINSTALL" \
  && fail "the installer still probes for a kernel argument with grep instead of counting it"

# --------------------------------------------------------------------------- #
# 3) THE VALUES ARE CONSTRAINED, not merely unique. A unique argument that names
#    something other than what a reader of the command line sees is the same
#    defect one step later.
# --------------------------------------------------------------------------- #
grep -Fq 'neuralice.target must name a plain block device under /dev' "$AUTOINSTALL" \
  || fail "the wipe target is not constrained to a plain /dev node"
grep -Fq 'neuralice.systemsize must be a whole number of GiB' "$AUTOINSTALL" \
  || fail "the system size interpolated into sfdisk is not constrained"
# 🔴 ONE CANONICAL ORIGIN, NO DEFAULT (independent review 2026-09-02, P0 #3).
# The compiled-in fallback was `ghcr.io/neural-ice/neural-ice-coreos:stable` -- a
# MUTABLE TAG on a registry that is not the release authority -- and an appliance
# whose medium sealed no origin followed it for its whole life. Both halves are
# asserted: the constraint exists, and the fallback is gone.
grep -Fq 'the OTA origin must be <sealed release authority>/<repo>@sha256:<digest>' "$AUTOINSTALL" \
  || fail "the recorded OTA origin is not constrained to the sealed digest-pinned authority"
# 🔴 AND THE AUTHORITY IS NOT A LITERAL IN THIS TREE. ICE-CoreOS is open core;
# ci/test-open-core-boundary.sh refuses the sovereign endpoint's bytes in every
# Git-visible file. The authority therefore arrives on the SIGNED command line,
# which is stronger than a constant: it is one value the signature covers rather
# than one a fork can edit.
grep -Fq 'NEURALICE_RELEASE_AUTHORITY="$(karg_once neuralice.release_authority)"' "$AUTOINSTALL" \
  || fail "the installer no longer reads its release authority from the sealed command line"
grep -Fq 'refusing to install an appliance with no update path rather than inventing a default' "$AUTOINSTALL" \
  || fail "the installer still invents an OTA origin when the medium seals none"
grep -vE '^[[:space:]]*#' "$AUTOINSTALL" | grep -Fq 'ghcr.io' \
  && fail "the installer still carries a GHCR reference outside its comments"
grep -Fq 'DEVICE_CHANNEL="$(karg_once neuralice.device_channel)"' "$AUTOINSTALL" \
  || fail "the installer does not consume the device channel sealed by the UKI"
grep -Fq 'printf '\''%s\n'\'' "$DEVICE_CHANNEL" > /run/seed-dst/release/CHANNEL' "$AUTOINSTALL" \
  || fail "the verified seed handoff does not retain its signed device channel"

# Literal current PCR7 is forbidden. The TPM slot must use PolicyAuthorize,
# with the policy generation sealed in the UKI and checked before disk mutation.
grep -vE '^[[:space:]]*#' "$AUTOINSTALL" | grep -Fq -- '--tpm2-pcrs=7' \
  && fail "the installer still seals LUKS to the mutable current PCR7 value"
for required in '--tpm2-pcrs=' '--tpm2-public-key="$PCR_POLICY_KEY_RUNTIME"' \
  '--tpm2-public-key-pcrs=7' 'karg_once neuralice.pcr_policy_seq' \
  'esp_staged_file tpm2-pcr-signature.json'; do
  grep -Fq -- "$required" "$AUTOINSTALL" \
    || fail "the signed PCR policy install gate is incomplete: $required"
done

# The live value is converted with the same immutable helper that authors
# policies, and every failure reaches one stable field diagnostic. Functional
# covered/uncovered/malformed tests and destructive-order proof live in the
# focused suite wired beside this one.
grep -Fq '"$TPM_POLICY_TOOL" --pcr 7 --alg sha256 verify-live-coverage' "$AUTOINSTALL" \
  || fail "the installer does not use the authoritative helper for live PCR7 coverage"
grep -Fq 'NI-P7-COVERAGE: live SHA-256 PCR7 is unreadable, malformed, unsigned, signed by another key, or uncovered' "$AUTOINSTALL" \
  || fail "the live PCR7 refusal has no stable diagnostic"

# All installer-created firstboot inputs are atomically published and fsynced
# before the recovery-key prompt can permit the first installed boot.
for required in \
  'persist_ceremony_input "$INTENDED_SRK_PUBLIC" srk-v1.tpm2b_public' \
  'persist_ceremony_input "$_intent_tmp" owner-ceremony-intent-v1' \
  'persist_ceremony_input "$_identity_tmp" owner-ceremony-install-identity-v1.json' \
  'sync -f "$ota_state/$_ceremony_input"' \
  'sync -f "$ota_state"'; do
  grep -Fq -- "$required" "$AUTOINSTALL" \
    || fail "the installed ceremony inputs are not durably published: $required"
done

echo "AUTOINSTALL_KARGS_TEST_OK"
