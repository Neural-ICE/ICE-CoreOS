#!/bin/sh
# shellcheck shell=bash
# A non-interactive POSIX shell does not source BASH_ENV. Re-exec once through a
# clean privileged Bash before parsing any of the Bash implementation below.
case $- in
  *p*) ;;
  *) exec /usr/bin/env -u BASH_ENV -u ENV PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C \
       /bin/bash --noprofile --norc -p "$0" "$@" ;;
esac
# Crash-safe producer/consumer contract for GB10 build-artifact generations.
PATH='/usr/sbin:/usr/bin:/sbin:/bin'; export PATH
LC_ALL=C; export LC_ALL
set -euo pipefail
ROOT="${ARTIFACTS_ROOT:-${HOME}/neural-ice/artifacts}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SBVERIFY_BIN="${SBVERIFY_BIN:-sbverify}"
VMLINUX_CANONICALIZE_BIN="${VMLINUX_CANONICALIZE_BIN:-$SCRIPT_DIR/canonicalize-vmlinuz.sh}"
REQUIRED_RPMS=(kernel kernel-core kernel-modules-core kernel-modules kernel-modules-nvidia-open)
die() { echo "ERROR: $*" >&2; exit 1; }
run_trust_policy() {
  /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C "$@"
}
safe_id() { [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || die "unsafe generation id '$1'"; }
hash_file() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  else shasum -a 256 "$1" | awk '{print $1}'
  fi
}
hash_text() {
  if command -v sha256sum >/dev/null 2>&1; then printf '%s' "$1" | sha256sum | awk '{print $1}'
  else printf '%s' "$1" | shasum -a 256 | awk '{print $1}'
  fi
}
tree_has_payload() { [[ -d "$1" && ! -L "$1" ]] && [[ -n "$(find "$1" \( -type f -o -type l \) -print -quit)" ]]; }

validate_tree() {
  local root="$1" path target
  while IFS= read -r path; do die "unsupported artifact node '$path'"; done \
    < <(find "$root" ! -type d ! -type f ! -type l -print)
  while IFS= read -r path; do
    target="$(readlink "$path")"
    [[ -n "$target" && "$target" != /* ]] || die "unsafe symlink '$path' -> '$target'"
    case "/$target/" in */../*) die "escaping symlink '$path' -> '$target'" ;; esac
    [[ -e "$path" ]] || die "dangling symlink '$path' -> '$target'"
  done < <(find "$root" -type l -print)
}

# Validate a content-bound inventory emitted by the CentOS builder. This avoids
# installing RPM tooling on the Ubuntu Spark host.
select_rpms() {
  local src="$1" dest="${2:-}" metadata checksum filename name epoch version release arch extra
  local req baseline="" selected selected_nevra matches actual
  metadata="$src/rpm-metadata.tsv"
  [[ -f "$metadata" && ! -L "$metadata" ]] || die "RPM metadata is missing from '$src'"
  if [[ -n "$dest" ]]; then : > "$dest/rpm-metadata.tsv"; fi

  for req in "${REQUIRED_RPMS[@]}"; do
    selected=""; selected_nevra=""; matches=0
    while IFS=$'\t' read -r checksum filename name epoch version release arch extra; do
      [[ -n "$checksum" && -n "$filename" && -n "$name" && -z "$extra" ]] || die "invalid RPM metadata row"
      if [[ "$name" == "$req" ]]; then
        [[ "$checksum" =~ ^[0-9a-f]{64}$ ]] || die "invalid RPM checksum for '$filename'"
        [[ "$filename" == "$(basename "$filename")" && "$filename" == *.rpm ]] || die "unsafe RPM filename '$filename'"
        [[ -f "$src/$filename" && ! -L "$src/$filename" ]] || die "RPM '$filename' is unavailable"
        actual="$(hash_file "$src/$filename")"
        [[ "$actual" == "$checksum" ]] || die "RPM checksum mismatch for '$filename'"
        matches=$((matches + 1)); selected="$src/$filename"; selected_nevra="$epoch:$version-$release"
        [[ "$arch" == aarch64 ]] || die "RPM '$name' has arch '$arch', expected aarch64"
      fi
    done < "$metadata"
    ((matches == 1)) || { ((matches == 0)) && die "required RPM '$req' is missing"; die "duplicate required RPM '$req'"; }
    [[ -n "$baseline" ]] || baseline="$selected_nevra"
    [[ "$selected_nevra" == "$baseline" ]] || die "RPM '$req' ($selected_nevra) does not match kernel $baseline"
    if [[ -n "$dest" ]]; then
      cp -p "$selected" "$dest/"
      awk -F '\t' -v package="$req" '$3 == package' "$metadata" >> "$dest/rpm-metadata.tsv"
    fi
  done
  printf '%s\n' "$baseline"
}

write_manifest() {
  local root="$1" output="$2" rel target digest
  local roots=(rpms nvidia-userspace generation.env)
  [[ -d "$root/unsigned-boot" ]] && roots+=(unsigned-boot)
  [[ -d "$root/signed-boot" ]] && roots+=(signed-boot)
  : > "$output"
  while IFS= read -r rel; do
    [[ "$rel" != *$'\t'* && "$rel" != *$'\n'* ]] || die "unsupported artifact path '$rel'"
    if [[ -L "$root/$rel" ]]; then target="$(readlink "$root/$rel")"; digest="$(hash_text "$target")"; printf 'L\t%s\t%s\n' "$digest" "$rel" >> "$output"
    else digest="$(hash_file "$root/$rel")"; printf 'F\t%s\t%s\n' "$digest" "$rel" >> "$output"
    fi
  done < <(cd "$root"; find "${roots[@]}" \( -type f -o -type l \) -print | LC_ALL=C sort)
}

metadata_value() {
  local key="$1" file="$2"
  awk -F= -v key="$key" '$1 == key {sub(/^[^=]*=/, ""); print; found++} END {exit found == 1 ? 0 : 1}' "$file"
}

have_tool() { [[ "$1" == */* && -x "$1" ]] || command -v "$1" >/dev/null 2>&1; }

verify_signed_boot() {
  local root="$1" id="$2" uname_r="$3" unsigned_hash="$4" file output provenance provenance_id provenance_uname provenance_hash canonical count attestation policy_id policy_hash
  file="$root/signed-boot/usr/lib/modules/$uname_r/vmlinuz"
  [[ -f "$file" && ! -L "$file" ]] || die "signed vmlinuz does not match kernel '$uname_r'"
  have_tool "$SBVERIFY_BIN" || die "sbverify is required to verify finalized generations"
  provenance="$root/signed-boot/signed-boot-provenance.env"
  [[ -f "$provenance" && ! -L "$provenance" ]] || die "signed-boot provenance is missing"
  provenance_id="$(metadata_value generation_id "$provenance")" || die "invalid signed-boot generation provenance"
  provenance_uname="$(metadata_value kernel_uname_r "$provenance")" || die "invalid signed-boot uname provenance"
  provenance_hash="$(metadata_value vmlinuz_unsigned_sha256 "$provenance")" || die "invalid signed-boot hash provenance"
  [[ "$provenance_id" == "$id" && "$provenance_uname" == "$uname_r" && "$provenance_hash" == "$unsigned_hash" ]] \
    || die "signed-boot payload was not produced for candidate '$id'"
  attestation="$root/signed-boot/trust-policy.env"
  [[ -f "$attestation" && ! -L "$attestation" ]] || die "signed-boot trust-policy attestation is missing"
  [[ "$(metadata_value generation_id "$attestation")" == "$id" ]] || die "trust-policy generation mismatch"
  policy_id="$(metadata_value policy_id "$attestation")" || die "invalid trust-policy id"
  policy_hash="$(metadata_value policy_sha256 "$attestation")" || die "invalid trust-policy hash"
  [[ "$policy_id" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ && "$policy_hash" =~ ^[0-9a-f]{64}$ ]] \
    || die "invalid trust-policy attestation"
  count="$(find "$root/signed-boot/usr/lib/modules" -type f -name vmlinuz -print | wc -l | tr -d '[:space:]')"
  [[ "$count" == 1 ]] || die "signed-boot must contain exactly one vmlinuz, found $count"
  for file in \
    "$root/signed-boot/usr/lib/modules/$uname_r/vmlinuz" \
    "$root/signed-boot/usr/lib/bootupd/updates/EFI/BOOT/BOOTAA64.EFI" \
    "$root/signed-boot/usr/lib/bootupd/updates/EFI/BOOT/fbaa64.efi" \
    "$root/signed-boot/usr/lib/bootupd/updates/EFI/BOOT/grubaa64.efi" \
    "$root/signed-boot/usr/lib/bootupd/updates/EFI/BOOT/mmaa64.efi" \
    "$root/signed-boot/usr/lib/bootupd/updates/EFI/centos/grubaa64.efi" \
    "$root/signed-boot/usr/lib/bootupd/updates/EFI/centos/mmaa64.efi" \
    "$root/signed-boot/usr/lib/bootupd/updates/EFI/centos/shimaa64.efi"; do
    [[ -f "$file" && ! -L "$file" ]] || die "signed-boot lacks required path '${file#"$root/signed-boot/"}'"
    output="$($SBVERIFY_BIN --list "$file" 2>&1)" || die "signature inspection failed for '${file##*/}'"
    grep -Eq '^signature [0-9]+$' <<< "$output" || die "no Secure Boot signature found on '${file##*/}'"
  done
  while IFS= read -r file; do
    output="$($SBVERIFY_BIN --list "$file" 2>&1)" || die "signature inspection failed for '${file##*/}'"
    grep -Eq '^signature [0-9]+$' <<< "$output" || die "unsigned EFI payload '${file#"$root/signed-boot/"}'"
  done < <(find "$root/signed-boot" -type f \( -iname '*.efi' -o -iname '*.EFI' \) -print)
  canonical="$(mktemp "${TMPDIR:-/tmp}/ice-coreos-vmlinuz.XXXXXX")"; trap 'rm -f "$canonical"' RETURN
  "$VMLINUX_CANONICALIZE_BIN" "$root/signed-boot/usr/lib/modules/$uname_r/vmlinuz" "$canonical" \
    || die "cannot canonicalize signed vmlinuz"
  [[ "$(hash_file "$canonical")" == "$unsigned_hash" ]] || die "signed vmlinuz bytes do not match candidate '$id'"
  rm -f "$canonical"; trap - RETURN
}

verify_payload() {
  local root="$1" expected_id="$2" expected_state="$3" actual id state format hardware platform kernel entry base
  local kernel_source nvidia_version uname_r unsigned_hash builder_definition builder_image nvidia_source tmp expected_uname
  local allow_extra_roots="${4:-0}"
  [[ -d "$root" && ! -L "$root" ]] || die "artifact payload is not a real directory: '$root'"
  tree_has_payload "$root/rpms" || die "artifact payload lacks RPMs"
  tree_has_payload "$root/nvidia-userspace" || die "artifact payload lacks NVIDIA userspace"
  if [[ "$expected_state" == candidate ]]; then
    [[ -f "$root/unsigned-boot/vmlinuz" && ! -L "$root/unsigned-boot/vmlinuz" ]] || die "candidate lacks vmlinuz-to-sign"
  fi
  [[ "$expected_state" == candidate ]] || tree_has_payload "$root/signed-boot" || die "final generation lacks signed-boot payload"
  [[ -f "$root/generation.env" && ! -L "$root/generation.env" && -f "$root/manifest.sha256" && ! -L "$root/manifest.sha256" ]] \
    || die "artifact metadata is incomplete or indirect"
  if [[ "$allow_extra_roots" == 0 ]]; then
    while IFS= read -r entry; do
      base="$(basename "$entry")"
      if [[ "$expected_state" == candidate ]]; then
        case "$base" in rpms|nvidia-userspace|unsigned-boot|generation.env|manifest.sha256) ;; *) die "unexpected candidate root '$base'" ;; esac
      else
        case "$base" in rpms|nvidia-userspace|signed-boot|generation.env|manifest.sha256) ;; *) die "unexpected generation root '$base'" ;; esac
      fi
    done < <(find "$root" -mindepth 1 -maxdepth 1 -print)
  fi
  if [[ "$allow_extra_roots" == 1 ]]; then
    validate_tree "$root/rpms"; validate_tree "$root/nvidia-userspace"; validate_tree "$root/signed-boot"
  else
    validate_tree "$root"
  fi
  format="$(metadata_value format_version "$root/generation.env")" || die "invalid format metadata"
  id="$(metadata_value generation_id "$root/generation.env")" || die "invalid generation id metadata"
  state="$(metadata_value state "$root/generation.env")" || die "invalid state metadata"
  hardware="$(metadata_value hardware_target "$root/generation.env")" || die "invalid hardware metadata"
  platform="$(metadata_value platform "$root/generation.env")" || die "invalid platform metadata"
  kernel="$(metadata_value kernel_nevra "$root/generation.env")" || die "invalid kernel metadata"
  uname_r="$(metadata_value kernel_uname_r "$root/generation.env")" || die "invalid kernel uname metadata"
  unsigned_hash="$(metadata_value vmlinuz_unsigned_sha256 "$root/generation.env")" || die "invalid vmlinuz metadata"
  kernel_source="$(metadata_value kernel_source_revision "$root/generation.env")" || die "invalid kernel source metadata"
  nvidia_version="$(metadata_value nvidia_driver_version "$root/generation.env")" || die "invalid NVIDIA version metadata"
  builder_definition="$(metadata_value builder_definition_sha256 "$root/generation.env")" || die "invalid builder definition metadata"
  builder_image="$(metadata_value builder_image_id "$root/generation.env")" || die "invalid builder image metadata"
  nvidia_source="$(metadata_value nvidia_open_source_sha256 "$root/generation.env")" || die "invalid NVIDIA source metadata"
  [[ "$format" == 1 && "$state" == "$expected_state" ]] || die "unexpected artifact format/state '$format/$state'"
  safe_id "$id"; [[ "$id" == "$expected_id" ]] || die "generation id mismatch"
  [[ "$hardware" == nvidia-gb10-arm64 && "$platform" == linux/arm64 ]] || die "unexpected hardware target '$hardware/$platform'"
  [[ "$kernel_source" =~ ^[0-9a-f]{40}$ && "$unsigned_hash" =~ ^[0-9a-f]{64}$ ]] || die "invalid kernel provenance"
  [[ "$builder_definition" =~ ^[0-9a-f]{64}$ && "$builder_image" =~ ^[0-9a-f]{64}$ && "$nvidia_source" =~ ^[0-9a-f]{64}$ ]] \
    || die "invalid builder/NVIDIA provenance"
  [[ "$nvidia_version" =~ ^[0-9]+([.][0-9]+)+$ ]] || die "invalid NVIDIA driver version"
  [[ -n "$(find "$root/nvidia-userspace" -type f -name "*${nvidia_version}*" -print -quit)" ]] || die "NVIDIA userspace version '$nvidia_version' is absent"
  actual="$(select_rpms "$root/rpms")"; [[ "$actual" == "$kernel" ]] || die "kernel metadata does not match RPMs"
  expected_uname="${kernel#*:}.aarch64"; [[ "$uname_r" == "$expected_uname" ]] || die "kernel uname '$uname_r' does not match '$kernel'"
  if [[ "$state" == candidate ]]; then
    [[ "$(hash_file "$root/unsigned-boot/vmlinuz")" == "$unsigned_hash" ]] || die "candidate vmlinuz hash mismatch"
  fi
  [[ "$state" == candidate ]] || verify_signed_boot "$root" "$id" "$uname_r" "$unsigned_hash"
  tmp="$(mktemp "${TMPDIR:-/tmp}/ice-coreos-manifest.XXXXXX")"; trap 'rm -f "$tmp"' RETURN
  write_manifest "$root" "$tmp"; cmp -s "$root/manifest.sha256" "$tmp" || die "artifact manifest mismatch"
  rm -f "$tmp"; trap - RETURN
}

resolve_current() {
  local target id
  [[ -L "$ROOT/current" ]] || die "'$ROOT/current' is not an atomic generation pointer"
  target="$(readlink "$ROOT/current")"
  [[ "$target" =~ ^generations/([A-Za-z0-9][A-Za-z0-9._-]*)$ ]] || die "unsafe current target '$target'"
  id="${BASH_REMATCH[1]}"; verify_payload "$ROOT/generations/$id" "$id" final; printf '%s\n' "$id"
}

activate_generation() {
  local id="$1" pointer
  safe_id "$id"; verify_payload "$ROOT/generations/$id" "$id" final
  [[ ! -e "$ROOT/current" || -L "$ROOT/current" ]] || die "refusing non-symlink current path"
  pointer="$ROOT/.current.${id}.$$"; ln -s "generations/$id" "$pointer"
  if [[ "$(uname -s)" == Linux ]]; then mv -Tf "$pointer" "$ROOT/current"; else mv -fh "$pointer" "$ROOT/current"; fi
  sync; echo "activated immutable generation '$id'"; echo "CURRENT_GENERATION=$id"
}

create_candidate() {
  local id="${GENERATION_ID:-}" rpm_src="${RPM_SRC:-}" userspace_src="${USERSPACE_SRC:-}"
  local source_revision="${SOURCE_REVISION:-unknown}" kernel_source="${KERNEL_SOURCE_REVISION:-}"
  local nvidia_version="${NVIDIA_DRIVER_VERSION:-}" candidates tmp final kernel uname_r unsigned_hash created
  local builder_definition builder_image nvidia_source payload_kernel_source payload_nvidia_version
  [[ -n "$id" && -n "$rpm_src" && -n "$userspace_src" ]] || die "candidate requires GENERATION_ID, RPM_SRC and USERSPACE_SRC"
  safe_id "$id"; [[ ! -L "$ROOT" ]] || die "artifact store root must not be a symlink"
  [[ "$source_revision" =~ ^([0-9a-fA-F]{7,64}|unknown)$ && "$kernel_source" =~ ^[0-9a-f]{40}$ ]] || die "invalid source revision"
  [[ "$nvidia_version" =~ ^[0-9]+([.][0-9]+)+$ ]] || die "invalid NVIDIA_DRIVER_VERSION"
  tree_has_payload "$userspace_src" || die "NVIDIA userspace source is empty"
  [[ -f "$rpm_src/kernel-payload.env" ]] || die "kernel payload provenance is missing"
  uname_r="$(metadata_value kernel_uname_r "$rpm_src/kernel-payload.env")" || die "invalid kernel payload uname"
  unsigned_hash="$(metadata_value vmlinuz_unsigned_sha256 "$rpm_src/kernel-payload.env")" || die "invalid kernel payload hash"
  builder_definition="$(metadata_value builder_definition_sha256 "$rpm_src/kernel-payload.env")" || die "invalid builder definition"
  builder_image="$(metadata_value builder_image_id "$rpm_src/kernel-payload.env")" || die "invalid builder image"
  nvidia_source="$(metadata_value nvidia_open_source_sha256 "$rpm_src/kernel-payload.env")" || die "invalid NVIDIA source hash"
  payload_kernel_source="$(metadata_value kernel_source_revision "$rpm_src/kernel-payload.env")" || die "invalid payload kernel revision"
  payload_nvidia_version="$(metadata_value nvidia_driver_version "$rpm_src/kernel-payload.env")" || die "invalid payload NVIDIA version"
  [[ "$payload_kernel_source" == "$kernel_source" && "$payload_nvidia_version" == "$nvidia_version" ]] \
    || die "staging provenance does not match the built kernel payload"
  candidates="$ROOT/candidates"; final="$candidates/$id"; tmp="$candidates/.${id}.preparing.$$"
  [[ ! -e "$final" && ! -e "$tmp" ]] || die "candidate '$id' already exists"
  install -d -m 0755 "$candidates" "$tmp/rpms" "$tmp/nvidia-userspace" "$tmp/unsigned-boot"
  trap 'chmod -R u+w "$tmp" 2>/dev/null || true; rm -rf "$tmp"' EXIT
  [[ -f "$rpm_src/vmlinuz-to-sign" ]] || die "candidate vmlinuz-to-sign is missing"
  kernel="$(select_rpms "$rpm_src" "$tmp/rpms")"; cp -a "$userspace_src/." "$tmp/nvidia-userspace/"
  "$VMLINUX_CANONICALIZE_BIN" "$rpm_src/vmlinuz-to-sign" "$tmp/unsigned-boot/vmlinuz" \
    || die "cannot canonicalize candidate vmlinuz"
  created="${CREATED_UTC:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
  cat > "$tmp/generation.env" <<EOF
format_version=1
state=candidate
generation_id=$id
hardware_target=nvidia-gb10-arm64
platform=linux/arm64
kernel_nevra=$kernel
kernel_uname_r=$uname_r
vmlinuz_unsigned_sha256=$unsigned_hash
builder_definition_sha256=$builder_definition
builder_image_id=$builder_image
nvidia_open_source_sha256=$nvidia_source
kernel_source_revision=$kernel_source
nvidia_driver_version=$nvidia_version
source_revision=$source_revision
created_utc=$created
EOF
  write_manifest "$tmp" "$tmp/manifest.sha256"; verify_payload "$tmp" "$id" candidate
  chmod -R a-w "$tmp"; sync; mv "$tmp" "$final"; sync; trap - EXIT
  echo "published immutable candidate '$id'; current was not changed"; echo "CANDIDATE_GENERATION=$id"
}

finalize_candidate() {
  local id="$1" signedboot_src="${SIGNEDBOOT_SRC:-}" policy_bin="${SIGNED_BOOT_TRUST_POLICY_BIN:-}"
  local policy_id="${SIGNED_BOOT_TRUST_POLICY_ID:-}" candidate generations tmp final secret verified
  safe_id "$id"; [[ -n "$signedboot_src" ]] || die "finalize requires SIGNEDBOOT_SRC"
  [[ "$policy_bin" == /* && "$policy_id" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] \
    || die "finalize requires an Owner-approved trust policy binary and id"
  have_tool "$policy_bin" || die "signed-boot trust policy is not executable"
  tree_has_payload "$signedboot_src" || die "signed-boot source is empty"
  secret="$(find "$signedboot_src" -type f \( -iname '*.key' -o -iname '*.key.*' -o -iname '*.p12' -o -iname '*.pfx' -o -iname '*.age' \) -print -quit)"
  [[ -z "$secret" ]] || die "refusing private/encrypted key material in signed-boot source"
  while IFS= read -r secret; do
    if grep -IqlE -- '-----BEGIN ([A-Z0-9 ]+ )?PRIVATE KEY-----' "$secret"; then
      die "refusing PEM private key material in signed-boot source"
    fi
  done < <(find "$signedboot_src" -type f -print)
  candidate="$ROOT/candidates/$id"; verify_payload "$candidate" "$id" candidate
  generations="$ROOT/generations"; final="$generations/$id"; tmp="$generations/.${id}.preparing.$$"
  [[ ! -e "$final" && ! -e "$tmp" ]] || die "generation '$id' already exists"
  install -d -m 0755 "$generations"; cp -a "$candidate" "$tmp"; chmod -R u+w "$tmp"
  trap 'chmod -R u+w "$tmp" 2>/dev/null || true; rm -rf "$tmp"' EXIT
  rm "$tmp/manifest.sha256"; rm -rf "$tmp/unsigned-boot"; install -d -m 0755 "$tmp/signed-boot"; cp -a "$signedboot_src/." "$tmp/signed-boot/"
  sed 's/^state=candidate$/state=final/' "$tmp/generation.env" > "$tmp/generation.env.new"; mv "$tmp/generation.env.new" "$tmp/generation.env"
  run_trust_policy "$policy_bin" "$tmp/signed-boot" "$(metadata_value kernel_uname_r "$tmp/generation.env")" \
    || die "signed-boot trust policy rejected candidate '$id'"
  verified="${VERIFIED_UTC:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
  cat > "$tmp/signed-boot/trust-policy.env" <<EOF
generation_id=$id
policy_id=$policy_id
policy_sha256=$(hash_file "$policy_bin")
verified_utc=$verified
EOF
  write_manifest "$tmp" "$tmp/manifest.sha256"; verify_payload "$tmp" "$id" final
  chmod -R a-w "$tmp"; sync; mv "$tmp" "$final"; sync; trap - EXIT
  echo "finalized immutable generation '$id'"; activate_generation "$id"
}

materialize() {
  local dest="${STAGING_DEST:-}" id gen tmp d
  [[ -n "$dest" && "$(basename "$dest")" == image && ! -L "$dest" ]] || die "materialization destination must be a real image directory"
  id="$(resolve_current)"; gen="$ROOT/generations/$id"; install -d -m 0755 "$dest"
  tmp="$dest/.artifact-materialize.${id}.$$"; install -d -m 0755 "$tmp"
  trap 'chmod -R u+w "$tmp" 2>/dev/null || true; rm -rf "$tmp"' EXIT
  for d in rpms nvidia-userspace signed-boot; do cp -a "$gen/$d" "$tmp/$d"; done
  cp -p "$gen/generation.env" "$gen/manifest.sha256" "$tmp/"; verify_payload "$tmp" "$id" final; chmod -R u+w "$tmp"
  for d in rpms nvidia-userspace signed-boot; do [[ ! -e "$dest/$d" ]] || chmod -R u+w "$dest/$d"; rm -rf "${dest:?}/$d"; mv "$tmp/$d" "$dest/$d"; done
  cp -p "$tmp/generation.env" "$dest/.generation.env.tmp"; mv -f "$dest/.generation.env.tmp" "$dest/generation.env"
  cp -p "$tmp/manifest.sha256" "$dest/.manifest.sha256.tmp"; mv -f "$dest/.manifest.sha256.tmp" "$dest/manifest.sha256"
  rm -rf "$tmp"; trap - EXIT; verify_payload "$dest" "$id" final 1
  echo "materialized immutable generation '$id' into '$dest'"; echo "CURRENT_GENERATION=$id"
}

verify_context() {
  local context="${1:-}" expected_policy_id="${2:-}" expected_policy_hash="${3:-}"
  local context_id attestation policy_id policy_hash
  [[ "$#" == 1 || "$#" == 3 ]] \
    || die "verify-context requires DIR or DIR EXPECTED_POLICY_ID EXPECTED_POLICY_SHA256"
  context_id="$(metadata_value generation_id "$context/generation.env")" \
    || die "invalid context metadata"
  verify_payload "$context" "$context_id" final 1
  attestation="$context/signed-boot/trust-policy.env"
  policy_id="$(metadata_value policy_id "$attestation")" || die "invalid trust-policy id"
  policy_hash="$(metadata_value policy_sha256 "$attestation")" || die "invalid trust-policy hash"
  if [[ "$#" == 3 ]]; then
    [[ "$expected_policy_id" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ \
      && "$expected_policy_hash" =~ ^[0-9a-f]{64}$ ]] \
      || die "invalid expected trust policy binding"
    [[ "$policy_id" == "$expected_policy_id" ]] \
      || die "trust policy '$policy_id' is not approved for this build (expected '$expected_policy_id')"
    [[ "$policy_hash" == "$expected_policy_hash" ]] \
      || die "trust policy executable hash does not match the approved build policy"
  fi
  echo "CURRENT_GENERATION=$context_id"
  echo "SIGNED_BOOT_TRUST_POLICY_ID=$policy_id"
  echo "SIGNED_BOOT_TRUST_POLICY_SHA256=$policy_hash"
}

case "${1:-}" in
  candidate) create_candidate ;;
  finalize) [[ -n "${2:-}" ]] || die "finalize requires a candidate id"; finalize_candidate "$2" ;;
  activate) [[ -n "${2:-}" ]] || die "activate requires a generation id"; activate_generation "$2" ;;
  materialize) materialize ;;
  verify-candidate) [[ -n "${2:-}" ]] || die "verify-candidate requires an id"; verify_payload "$ROOT/candidates/$2" "$2" candidate ;;
  verify-current) current_id="$(resolve_current)"; echo "CURRENT_GENERATION=$current_id" ;;
  verify-context) shift; verify_context "$@" ;;
  *) die "usage: $0 {candidate|finalize ID|activate ID|materialize|verify-candidate ID|verify-current|verify-context DIR [EXPECTED_POLICY_ID EXPECTED_POLICY_SHA256]}" ;;
esac
