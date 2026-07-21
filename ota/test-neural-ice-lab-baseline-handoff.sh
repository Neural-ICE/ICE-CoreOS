#!/usr/bin/env bash
# Fixed fragments below intentionally remain literal while this test runs.
# shellcheck disable=SC2016
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HELPER="$REPO_ROOT/ota/neural-ice-lab-baseline-handoff.sh"
AUTOINSTALL="$REPO_ROOT/ota/neural-ice-autoinstall.sh"
INSTALLER_CONTAINERFILE="$REPO_ROOT/image/Containerfile.installer"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/ice-coreos-lab-baseline-test.XXXXXX")"
trap 'chmod -R u+w "$TMP" 2>/dev/null || true; rm -rf "$TMP"' EXIT

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

expect_status() {
  local expected="$1"; shift
  local status=0
  "$@" >"$TMP/command.out" 2>&1 || status=$?
  [[ "$status" == "$expected" ]] \
    || { cat "$TMP/command.out" >&2; fail "expected status $expected, got $status: $*"; }
}

new_esp() {
  local name="$1"
  install -d "$TMP/$name/ice-coreos"
  printf '%s\n' "$TMP/$name"
}

mode() {
  stat -Lc '%a' -- "$1" 2>/dev/null || stat -Lf '%Lp' -- "$1"
}

owner_group_mode() {
  stat -Lc '%u:%g:%a' -- "$1" 2>/dev/null || stat -Lf '%u:%g:%Lp' -- "$1"
}

line_of() {
  local needle="$1" file="$2"
  grep -nF -- "$needle" "$file" | head -1 | cut -d: -f1
}

sha256() {
  sha256sum -- "$1" | awk '{print $1}'
}

# Integration ordering is security-sensitive: the snapshot gate must run before
# the first destructive warning/wipe, and the durable copy must land only after
# bootc exposes the target stateroot but before its SELinux relabel.
snapshot_line="$(line_of '"$LAB_BASELINE_HANDOFF" snapshot' "$AUTOINSTALL")"
wipe_line="$(line_of '— WIPING + ENCRYPTING' "$AUTOINSTALL")"
stateroot_line="$(line_of 'stateroot="$(dirname' "$AUTOINSTALL")"
install_line="$(line_of '"$LAB_BASELINE_HANDOFF" install' "$AUTOINSTALL")"
setfiles_line="$(line_of 'setfiles -F -r "$stateroot"' "$AUTOINSTALL")"
[[ -n "$snapshot_line" && -n "$wipe_line" && "$snapshot_line" -lt "$wipe_line" ]] \
  || fail "LAB snapshot gate is not before destructive target handling"
[[ -n "$stateroot_line" && -n "$install_line" && -n "$setfiles_line" \
   && "$stateroot_line" -lt "$install_line" && "$install_line" -lt "$setfiles_line" ]] \
  || fail "durable LAB handoff is not between stateroot discovery and SELinux relabel"
grep -Fq 'COPY ota/neural-ice-lab-baseline-handoff.sh /usr/local/libexec/neural-ice-lab-baseline-handoff' \
  "$INSTALLER_CONTAINERFILE" || fail "installer image does not ship the handoff helper"
if grep -Eq '(^|[[:space:]])(cosign|jq|openssl)([[:space:]]|$)' "$HELPER"; then
  fail "CoreOS handoff helper must not parse or verify the signed receipt"
fi

# Neither file is an ordinary install, reported with the helper's explicit
# ABSENT status. No stale snapshot may appear.
esp="$(new_esp absent)"
expect_status 3 "$HELPER" snapshot "$esp" "$TMP/absent-snapshot"
[[ ! -e "$TMP/absent-snapshot" ]] || fail "absent pair created a snapshot"

# Either half alone fails closed.
esp="$(new_esp receipt-only)"
printf '{}\n' >"$esp/ice-coreos/ota-lab-baseline.json"
expect_status 1 "$HELPER" snapshot "$esp" "$TMP/receipt-only-snapshot"
esp="$(new_esp signature-only)"
printf 'signature\n' >"$esp/ice-coreos/ota-lab-baseline.sig"
expect_status 1 "$HELPER" snapshot "$esp" "$TMP/signature-only-snapshot"

# Unsafe file types, empty files, and files beyond the documented bounds fail.
esp="$(new_esp symlink)"
printf '{}\n' >"$esp/ice-coreos/real.json"
ln -s real.json "$esp/ice-coreos/ota-lab-baseline.json"
printf 'signature\n' >"$esp/ice-coreos/ota-lab-baseline.sig"
expect_status 1 "$HELPER" snapshot "$esp" "$TMP/symlink-snapshot"

esp="$(new_esp empty)"
: >"$esp/ice-coreos/ota-lab-baseline.json"
printf 'signature\n' >"$esp/ice-coreos/ota-lab-baseline.sig"
expect_status 1 "$HELPER" snapshot "$esp" "$TMP/empty-snapshot"

esp="$(new_esp oversized-receipt)"
dd if=/dev/zero of="$esp/ice-coreos/ota-lab-baseline.json" bs=16385 count=1 status=none
printf 'signature\n' >"$esp/ice-coreos/ota-lab-baseline.sig"
expect_status 1 "$HELPER" snapshot "$esp" "$TMP/oversized-receipt-snapshot"

esp="$(new_esp oversized-signature)"
printf '{}\n' >"$esp/ice-coreos/ota-lab-baseline.json"
dd if=/dev/zero of="$esp/ice-coreos/ota-lab-baseline.sig" bs=4097 count=1 status=none
expect_status 1 "$HELPER" snapshot "$esp" "$TMP/oversized-signature-snapshot"

# Arbitrary non-empty bytes are copied exactly: CoreOS must not parse JSON or
# verify the signature because the post-install Fabric service owns trust.
esp="$(new_esp valid)"
printf 'deliberately-not-json\nsecond-line\n' >"$esp/ice-coreos/ota-lab-baseline.json"
printf '\001binary-signature-fixture\000\377' >"$esp/ice-coreos/ota-lab-baseline.sig"
snapshot="$TMP/valid-snapshot"
"$HELPER" snapshot "$esp" "$snapshot"
cmp -s "$esp/ice-coreos/ota-lab-baseline.json" "$snapshot/ota-lab-baseline.json" \
  || fail "receipt snapshot differs"
cmp -s "$esp/ice-coreos/ota-lab-baseline.sig" "$snapshot/ota-lab-baseline.sig" \
  || fail "signature snapshot differs"
[[ "$(mode "$snapshot")" == 700 ]] || fail "snapshot directory mode is not 0700"
[[ "$(mode "$snapshot/ota-lab-baseline.json")" == 600 ]] \
  || fail "receipt snapshot mode is not 0600"
[[ "$(mode "$snapshot/ota-lab-baseline.sig")" == 600 ]] \
  || fail "signature snapshot mode is not 0600"

# The media builder stages only a complete hash-approved pair. The resulting
# fixed paths are write-once for that build, and intermediate files never
# become accepted media paths after an input refusal.
media_source="$TMP/media-source"
install -d -m 0700 "$media_source"
printf '{"schema":"fixture"}\n' >"$media_source/baseline.json"
printf '\001media-signature\000\377' >"$media_source/baseline.sig"
bom_sha256="$(sha256 "$media_source/baseline.json")"
signature_sha256="$(sha256 "$media_source/baseline.sig")"
wrong_bom_sha256="$(printf '0%.0s' {1..64})"
[[ "$wrong_bom_sha256" != "$bom_sha256" ]] || wrong_bom_sha256="$(printf '1%.0s' {1..64})"
media_root="$TMP/media-valid"
install -d -m 0700 "$media_root"
"$HELPER" stage-media \
  "$media_source/baseline.json" "$bom_sha256" \
  "$media_source/baseline.sig" "$signature_sha256" "$media_root"
cmp -s "$media_source/baseline.json" "$media_root/ice-coreos/ota-lab-baseline.json" \
  || fail "staged media receipt differs"
cmp -s "$media_source/baseline.sig" "$media_root/ice-coreos/ota-lab-baseline.sig" \
  || fail "staged media signature differs"
[[ "$(mode "$media_root/ice-coreos")" == 700 ]] \
  || fail "staged media namespace mode is not 0700"
[[ "$(mode "$media_root/ice-coreos/ota-lab-baseline.json")" == 600 ]] \
  || fail "staged media receipt mode is not 0600"
[[ "$(mode "$media_root/ice-coreos/ota-lab-baseline.sig")" == 600 ]] \
  || fail "staged media signature mode is not 0600"
expect_status 1 "$HELPER" stage-media \
  "$media_source/baseline.json" "$bom_sha256" \
  "$media_source/baseline.sig" "$signature_sha256" "$media_root"

media_root="$TMP/media-drift"
install -d -m 0700 "$media_root"
expect_status 1 "$HELPER" stage-media \
  "$media_source/baseline.json" "$wrong_bom_sha256" \
  "$media_source/baseline.sig" "$signature_sha256" "$media_root"
[[ ! -e "$media_root/ice-coreos/ota-lab-baseline.json" \
   && ! -e "$media_root/ice-coreos/ota-lab-baseline.sig" ]] \
  || fail "hash drift published a fixed media path"

ln -s baseline.json "$media_source/baseline-link.json"
media_root="$TMP/media-symlink"
install -d -m 0700 "$media_root"
expect_status 1 "$HELPER" stage-media \
  "$media_source/baseline-link.json" "$bom_sha256" \
  "$media_source/baseline.sig" "$signature_sha256" "$media_root"
[[ ! -e "$media_root/ice-coreos/ota-lab-baseline.json" \
   && ! -e "$media_root/ice-coreos/ota-lab-baseline.sig" ]] \
  || fail "symlink input published a fixed media path"

target_var="$TMP/target-var"
install -d "$target_var"
if [[ "$(id -u)" == 0 ]]; then
  "$HELPER" install "$snapshot" "$target_var"
  destination="$target_var/lib/neural-ice/ota/lab-baseline"
  cmp -s "$snapshot/ota-lab-baseline.json" "$destination/ota-lab-baseline.json" \
    || fail "durable receipt differs"
  cmp -s "$snapshot/ota-lab-baseline.sig" "$destination/ota-lab-baseline.sig" \
    || fail "durable signature differs"
  [[ "$(owner_group_mode "$destination")" == 0:0:700 ]] \
    || fail "durable directory is not root:root 0700"
  [[ "$(owner_group_mode "$destination/ota-lab-baseline.json")" == 0:0:600 ]] \
    || fail "durable receipt is not root:root 0600"
  [[ "$(owner_group_mode "$destination/ota-lab-baseline.sig")" == 0:0:600 ]] \
    || fail "durable signature is not root:root 0600"
  expect_status 1 "$HELPER" install "$snapshot" "$target_var"
else
  expect_status 1 "$HELPER" install "$snapshot" "$target_var"
fi

printf 'LAB baseline ESP handoff tests: PASS (uid=%s)\n' "$(id -u)"
