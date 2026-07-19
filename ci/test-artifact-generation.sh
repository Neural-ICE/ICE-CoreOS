#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$REPO_ROOT/ci/artifact-generation.sh"
BUILD_CONTEXT_SCRIPT="$REPO_ROOT/ci/verify-build-context.sh"
BUILD_IMAGE_SCRIPT="$REPO_ROOT/ci/build-image.sh"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/ice-coreos-artifacts-test.XXXXXX")"
trap 'chmod -R u+w "$TMP" 2>/dev/null || true; rm -rf "$TMP"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
expect_failure() {
  if "$@" >"$TMP/unexpected.out" 2>&1; then cat "$TMP/unexpected.out" >&2; fail "command unexpectedly succeeded: $*"; fi
}
file_hash() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  else shasum -a 256 "$1" | awk '{print $1}'
  fi
}

FAKE_SBVERIFY="$TMP/sbverify"
FAKE_CANONICALIZE="$TMP/canonicalize"
FAKE_TRUST_POLICY="$TMP/trust-policy"
# shellcheck disable=SC2016 # literal script body expands its own positional args
printf '%s\n' '#!/usr/bin/env bash' \
  'file="${!#}"' \
  'if grep -q UNSIGNED "$file"; then echo "No signature table present"; else echo "signature 1"; fi' \
  > "$FAKE_SBVERIFY"
# shellcheck disable=SC2016 # literal script body expands its own positional args
printf '%s\n' '#!/usr/bin/env bash' 'cp "$1" "$2"' > "$FAKE_CANONICALIZE"
# shellcheck disable=SC2016 # literal script body expands its own environment/arguments
printf '%s\n' '#!/usr/bin/env bash' \
  '[[ "${PATH:-}" == /usr/sbin:/usr/bin:/sbin:/bin ]] || exit 91' \
  '[[ "${LC_ALL:-}" == C ]] || exit 92' \
  '[[ -z "${BASH_ENV:-}" && -z "${ENV:-}" && -z "${POLICY_ENV_POISON:-}" ]] || exit 93' \
  'self_dir="$(cd "$(dirname "$0")" && pwd)"' \
  'if [[ -e "$self_dir/.mutate-policy" ]]; then' \
  '  printf "mutated\n" >> "$1/signed-boot-provenance.env"' \
  'fi' \
  'if [[ -e "$self_dir/.mutate-policy-rehash" ]]; then' \
  '  file="$1/signed-boot-provenance.env"' \
  '  manifest="$(dirname "$1")/manifest.sha256"' \
  '  printf "mutated-and-rehashed\n" >> "$file"' \
  '  if command -v sha256sum >/dev/null 2>&1; then hash="$(sha256sum "$file" | awk "{print \\$1}")"' \
  '  else hash="$(shasum -a 256 "$file" | awk "{print \\$1}")"; fi' \
  '  while read -r kind old path; do' \
  '    if [[ "$path" == "signed-boot/signed-boot-provenance.env" ]]; then old="$hash"; fi' \
  '    printf "%s\t%s\t%s\n" "$kind" "$old" "$path"' \
  '  done < "$manifest" > "$manifest.new"' \
  '  mv "$manifest.new" "$manifest"' \
  'fi' \
  'exit 0' > "$FAKE_TRUST_POLICY"
chmod +x "$FAKE_SBVERIFY" "$FAKE_CANONICALIZE" "$FAKE_TRUST_POLICY"
EVIL_BIN="$TMP/evil-bin"; install -d "$EVIL_BIN"
printf '%s\n' '#!/usr/bin/bash' 'exit 0' > "$EVIL_BIN/bash"; chmod +x "$EVIL_BIN/bash"
BASH_ENV_FILE="$TMP/bash-env"
BASH_ENV_MARKER="$TMP/bash-env-was-sourced"
printf '%s\n' 'export POLICY_ENV_POISON=from-bash-env' \
  ": > \"$BASH_ENV_MARKER\"" > "$BASH_ENV_FILE"
ENV_FILE="$TMP/posix-env"
ENV_MARKER="$TMP/posix-env-was-sourced"
printf '%s\n' 'export POLICY_ENV_POISON=from-posix-env' \
  ": > \"$ENV_MARKER\"" > "$ENV_FILE"
export SBVERIFY_BIN="$FAKE_SBVERIFY" VMLINUX_CANONICALIZE_BIN="$FAKE_CANONICALIZE" \
  SIGNED_BOOT_TRUST_POLICY_BIN="$FAKE_TRUST_POLICY" \
  SIGNED_BOOT_TRUST_POLICY_ID=neural-ice-secureboot-lab-v1
FAKE_TRUST_POLICY_SHA256="$(file_hash "$FAKE_TRUST_POLICY")"

make_sources() {
  local root="$1" release="${2:-1.el10}" name file uname_r
  uname_r="6.12.0-${release}.aarch64"
  mkdir -p "$root/rpms" "$root/userspace/usr/lib64"
  for name in kernel kernel-core kernel-modules-core kernel-modules kernel-modules-nvidia-open; do
    file="$root/rpms/$name-6.12.0-$release.aarch64.rpm"
    printf 'body-%s-%s\n' "$name" "$release" > "$file"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$(file_hash "$file")" "$(basename "$file")" "$name" 0 6.12.0 "$release" aarch64 \
      >> "$root/rpms/rpm-metadata.tsv"
  done
  printf 'unsigned-vmlinuz-%s\n' "$release" > "$root/unsigned-vmlinuz"
  cp "$root/unsigned-vmlinuz" "$root/rpms/vmlinuz-to-sign"
  printf 'kernel_uname_r=%s\nvmlinuz_unsigned_sha256=%s\n' \
    "$uname_r" "$(file_hash "$root/unsigned-vmlinuz")" > "$root/rpms/kernel-payload.env"
  printf 'builder_definition_sha256=%064d\nbuilder_image_id=%064d\nnvidia_open_source_sha256=%064d\nkernel_source_revision=fa4faa0227e00c2291e47b120e71c7aed0fe27b7\nnvidia_driver_version=595.58.03\n' \
    1 2 3 >> "$root/rpms/kernel-payload.env"
  printf 'userspace\n' > "$root/userspace/usr/lib64/libcuda.so.595.58.03"
  ln -s libcuda.so.595.58.03 "$root/userspace/usr/lib64/libcuda.so.1"
}

make_signed_boot() {
  local src="$1" dest="$2" id="$3" uname_r unsigned_hash
  uname_r="$(awk -F= '$1 == "kernel_uname_r" {print $2}' "$src/rpms/kernel-payload.env")"
  unsigned_hash="$(awk -F= '$1 == "vmlinuz_unsigned_sha256" {print $2}' "$src/rpms/kernel-payload.env")"
  mkdir -p "$dest/usr/lib/modules/$uname_r" \
    "$dest/usr/lib/bootupd/updates/EFI/centos" "$dest/usr/lib/bootupd/updates/EFI/BOOT"
  cp "$src/unsigned-vmlinuz" "$dest/usr/lib/modules/$uname_r/vmlinuz"
  for name in shimaa64.efi grubaa64.efi mmaa64.efi; do printf 'signed-%s\n' "$name" > "$dest/usr/lib/bootupd/updates/EFI/centos/$name"; done
  for name in BOOTAA64.EFI fbaa64.efi grubaa64.efi mmaa64.efi; do printf 'signed-%s\n' "$name" > "$dest/usr/lib/bootupd/updates/EFI/BOOT/$name"; done
  printf 'generation_id=%s\nkernel_uname_r=%s\nvmlinuz_unsigned_sha256=%s\n' \
    "$id" "$uname_r" "$unsigned_hash" > "$dest/signed-boot-provenance.env"
}

candidate() {
  local id="$1" src="$2"
  ARTIFACTS_ROOT="$TMP/store" GENERATION_ID="$id" RPM_SRC="$src/rpms" USERSPACE_SRC="$src/userspace" \
    SOURCE_REVISION=0123456789abcdef KERNEL_SOURCE_REVISION=fa4faa0227e00c2291e47b120e71c7aed0fe27b7 \
    NVIDIA_DRIVER_VERSION=595.58.03 CREATED_UTC=2026-07-19T00:00:00Z "$SCRIPT" candidate
}
finalize() { ARTIFACTS_ROOT="$TMP/store" SIGNEDBOOT_SRC="$2" "$SCRIPT" finalize "$1"; }

SRC1="$TMP/src1"; SIGNED1="$TMP/signed1"; make_sources "$SRC1"; make_signed_boot "$SRC1" "$SIGNED1" gen-1
candidate gen-1 "$SRC1" >/dev/null
[[ ! -e "$TMP/store/current" ]] || fail "candidate moved current"
ARTIFACTS_ROOT="$TMP/store" "$SCRIPT" verify-candidate gen-1
env PATH="$EVIL_BIN:$PATH" BASH_ENV="$BASH_ENV_FILE" ENV="$ENV_FILE" POLICY_ENV_POISON=direct \
  ARTIFACTS_ROOT="$TMP/store" SIGNEDBOOT_SRC="$SIGNED1" \
  SIGNED_BOOT_TRUST_POLICY_BIN="$FAKE_TRUST_POLICY" \
  SIGNED_BOOT_TRUST_POLICY_ID=neural-ice-secureboot-lab-v1 \
  "$SCRIPT" finalize gen-1 >/dev/null
[[ ! -e "$BASH_ENV_MARKER" ]] || fail "artifact finalizer sourced inherited BASH_ENV"
[[ ! -e "$ENV_MARKER" ]] || fail "artifact finalizer sourced inherited ENV"
[[ "$(readlink "$TMP/store/current")" == generations/gen-1 ]] || fail "gen-1 not activated"

DEST="$TMP/image"
mkdir -p "$DEST"; printf 'FROM scratch\n' > "$DEST/Containerfile.bootc"
ARTIFACTS_ROOT="$TMP/store" STAGING_DEST="$DEST" "$SCRIPT" materialize >/dev/null
ARTIFACTS_ROOT="$TMP/store" "$SCRIPT" verify-context "$DEST" \
  neural-ice-secureboot-lab-v1 "$FAKE_TRUST_POLICY_SHA256" >/dev/null
# A LAB-finalized context must never satisfy the production build gate, even
# when both policy executables happen to have identical bytes.
expect_failure env ARTIFACTS_ROOT="$TMP/store" "$SCRIPT" verify-context "$DEST" \
  neural-ice-secureboot-prod-v1 "$FAKE_TRUST_POLICY_SHA256"
expect_failure env ARTIFACTS_ROOT="$TMP/store" "$SCRIPT" verify-context "$DEST" \
  neural-ice-secureboot-lab-v1 "$(printf '%064d' 9)"
expect_failure env ARTIFACTS_ROOT="$TMP/store" "$SCRIPT" verify-context "$DEST" \
  neural-ice-secureboot-lab-v1

# The shipping consumer uses a fixed, version-controlled variant allowlist and
# re-runs the approved policy before any registry login or image build.
TEST_REPO="$TMP/build-gate-repo"
install -d "$TEST_REPO/ci" "$TEST_REPO/secureboot/trust-policies"
cp "$SCRIPT" "$BUILD_CONTEXT_SCRIPT" "$BUILD_IMAGE_SCRIPT" "$TEST_REPO/ci/"
cp "$FAKE_TRUST_POLICY" \
  "$TEST_REPO/secureboot/trust-policies/neural-ice-secureboot-lab-v1"
BUILD_GATE="$TEST_REPO/ci/verify-build-context.sh"
gate_output="$(env PATH="$EVIL_BIN:$PATH" BASH_ENV="$BASH_ENV_FILE" ENV="$ENV_FILE" POLICY_ENV_POISON=direct \
  "$BUILD_GATE" "$DEST" debug)"
grep -q '^CURRENT_GENERATION=gen-1$' <<< "$gate_output" \
  || fail "hardened build gate did not execute"
[[ ! -e "$BASH_ENV_MARKER" ]] || fail "build gate sourced inherited BASH_ENV"
[[ ! -e "$ENV_MARKER" ]] || fail "build gate sourced inherited ENV"
expect_failure "$BUILD_GATE" "$DEST" prod
expect_failure "$BUILD_GATE" "$DEST" ""
printf '\n# changed after finalization\n' >> \
  "$TEST_REPO/secureboot/trust-policies/neural-ice-secureboot-lab-v1"
expect_failure "$BUILD_GATE" "$DEST" debug
cp "$FAKE_TRUST_POLICY" \
  "$TEST_REPO/secureboot/trust-policies/neural-ice-secureboot-lab-v1"

# The build wrapper repeats the gate, emits both trust labels and does not reach
# podman for an unavailable production policy.
cp -a "$DEST" "$TEST_REPO/image"
cp "$REPO_ROOT/VERSION" "$TEST_REPO/VERSION"
install -d "$TMP/fake-bin"
# shellcheck disable=SC2016 # literal script body expands its own environment
printf '%s\n' '#!/usr/bin/env bash' 'printf "%s\n" "$@" > "$PODMAN_LOG"' > "$TMP/fake-bin/podman"
chmod +x "$TMP/fake-bin/podman"
rm -f "$TMP/podman-mutating.out"
touch "$TEST_REPO/secureboot/trust-policies/.mutate-policy"
expect_failure env PODMAN_LOG="$TMP/podman-mutating.out" \
  PATH="$TMP/fake-bin:$PATH" VARIANT=debug "$TEST_REPO/ci/build-image.sh"
rm -f "$TEST_REPO/secureboot/trust-policies/.mutate-policy"
[[ ! -e "$TMP/podman-mutating.out" ]] || fail "mutating policy reached podman"
rm -rf "$TEST_REPO/image"
cp -a "$DEST" "$TEST_REPO/image"
rm -f "$TMP/podman-rehashed.out"
touch "$TEST_REPO/secureboot/trust-policies/.mutate-policy-rehash"
expect_failure env PODMAN_LOG="$TMP/podman-rehashed.out" \
  PATH="$TMP/fake-bin:$PATH" VARIANT=debug "$TEST_REPO/ci/build-image.sh"
rm -f "$TEST_REPO/secureboot/trust-policies/.mutate-policy-rehash"
[[ ! -e "$TMP/podman-rehashed.out" ]] || fail "self-rehashing policy reached podman"
rm -rf "$TEST_REPO/image"
cp -a "$DEST" "$TEST_REPO/image"
PODMAN_LOG="$TMP/podman-debug.out" PATH="$TMP/fake-bin:$PATH" VARIANT=debug \
  "$TEST_REPO/ci/build-image.sh" > "$TMP/build-debug.out"
grep -Fx -- "ch.neural-ice.signed-boot-trust-policy-id=neural-ice-secureboot-lab-v1" \
  "$TMP/podman-debug.out" >/dev/null
grep -Fx -- "ch.neural-ice.signed-boot-trust-policy-sha256=$FAKE_TRUST_POLICY_SHA256" \
  "$TMP/podman-debug.out" >/dev/null
rm -f "$TMP/podman-prod.out"
expect_failure env PODMAN_LOG="$TMP/podman-prod.out" PATH="$TMP/fake-bin:$PATH" VARIANT=prod \
  "$TEST_REPO/ci/build-image.sh"
[[ ! -e "$TMP/podman-prod.out" ]] || fail "prod policy failure reached podman"

# Missing NVIDIA RPM and mismatched EVRA never create a candidate or move current.
BROKEN="$TMP/broken"; make_sources "$BROKEN"; rm "$BROKEN/rpms/kernel-modules-nvidia-open-"*.rpm
expect_failure candidate gen-missing "$BROKEN"
[[ "$(readlink "$TMP/store/current")" == generations/gen-1 ]] || fail "missing RPM moved current"
MISMATCH="$TMP/mismatch"; make_sources "$MISMATCH"
old="$MISMATCH/rpms/kernel-modules-6.12.0-1.el10.aarch64.rpm"; printf 'body-mismatch\n' > "$old"
awk -F '\t' -v OFS='\t' -v hash="$(file_hash "$old")" '$3 == "kernel-modules" {$1=hash; $6="2.el10"} {print}' \
  "$MISMATCH/rpms/rpm-metadata.tsv" > "$MISMATCH/rpms/rpm-metadata.tsv.new"
mv "$MISMATCH/rpms/rpm-metadata.tsv.new" "$MISMATCH/rpms/rpm-metadata.tsv"
expect_failure candidate gen-mismatch "$MISMATCH"
for field in nvidia_driver_version kernel_source_revision; do
  PROVENANCE="$TMP/provenance-$field"; make_sources "$PROVENANCE"; awk -F= -v OFS='=' -v field="$field" '$1 == field {$2="mismatch"} {print}' "$PROVENANCE/rpms/kernel-payload.env" > "$PROVENANCE/rpms/kernel-payload.env.new"
  mv "$PROVENANCE/rpms/kernel-payload.env.new" "$PROVENANCE/rpms/kernel-payload.env"
  expect_failure candidate "gen-provenance-$field" "$PROVENANCE"
done
# A stale signed boot set is rejected: the candidate remains, current stays old.
SRC2="$TMP/src2"; SIGNED2="$TMP/signed2"; make_sources "$SRC2" 2.el10; make_signed_boot "$SRC2" "$SIGNED2" gen-2
candidate gen-2 "$SRC2" >/dev/null
expect_failure finalize gen-2 "$SIGNED1"
[[ "$(readlink "$TMP/store/current")" == generations/gen-1 ]] || fail "stale signed boot moved current"
finalize gen-2 "$SIGNED2" >/dev/null

# Signature-list false positives and same-NEVRA/different-vmlinuz payloads fail.
SRC3="$TMP/src3"; SIGNED3="$TMP/signed3"; make_sources "$SRC3" 3.el10; make_signed_boot "$SRC3" "$SIGNED3" gen-3
candidate gen-3 "$SRC3" >/dev/null
expect_failure env ARTIFACTS_ROOT="$TMP/store" SIGNEDBOOT_SRC="$SIGNED3" \
  SIGNED_BOOT_TRUST_POLICY_BIN= SIGNED_BOOT_TRUST_POLICY_ID= "$SCRIPT" finalize gen-3
printf 'private\n' > "$SIGNED3/owner.key"
expect_failure finalize gen-3 "$SIGNED3"
rm "$SIGNED3/owner.key"
printf 'UNSIGNED\n' > "$SIGNED3/usr/lib/bootupd/updates/EFI/BOOT/fbaa64.efi"
expect_failure finalize gen-3 "$SIGNED3"
rm -rf "$SIGNED3"; make_signed_boot "$SRC3" "$SIGNED3" gen-3
printf 'different-vmlinuz\n' > "$SIGNED3/usr/lib/modules/6.12.0-3.el10.aarch64/vmlinuz"
expect_failure finalize gen-3 "$SIGNED3"

# Interrupted preparation and unsafe pointers cannot be consumed.
mkdir -p "$TMP/store/generations/.interrupted.preparing.1"
rm "$TMP/store/current"; ln -s ../outside "$TMP/store/current"
expect_failure env ARTIFACTS_ROOT="$TMP/store" STAGING_DEST="$TMP/unsafe/image" "$SCRIPT" materialize
rm "$TMP/store/current"; ln -s generations/gen-2 "$TMP/store/current"

# Corruption is detected, and explicit reactivation is the verified rollback path.
chmod u+w "$DEST/rpms/kernel-6.12.0-1.el10.aarch64.rpm"; printf 'corrupt\n' >> "$DEST/rpms/kernel-6.12.0-1.el10.aarch64.rpm"
expect_failure env ARTIFACTS_ROOT="$TMP/store" "$SCRIPT" verify-context "$DEST"
ARTIFACTS_ROOT="$TMP/store" "$SCRIPT" activate gen-1 >/dev/null
[[ "$(readlink "$TMP/store/current")" == generations/gen-1 ]] || fail "rollback activation failed"

echo "artifact generation tests: PASS"
