#!/usr/bin/env bash
# THE INSTALLER-ONLY DEVICE-ROOT GUARD, DRIVEN FOR REAL, PER INSTALL SOURCE.
#
# CONTRACT: the installer-only drop-in must NEVER survive into the installed
# system, and its ABSENCE is the desired end state for every source.
#
# 🔴 THE HOLES THIS CLOSES.
#  - 2026-09-07 (QEMU, LIGHT 0.60.0, source=registry): phase 6 demanded the
#    drop-in in the staged deployment and died when it was absent, in front of
#    a correct deployment.
#  - 2026-10-06 (QEMU, mission B candidate, source=medium): the same demand
#    killed EVERY medium install. The deployment is the sealed store's image,
#    i.e. BASE_IMAGE (the appliance), which never carries the drop-in -- only
#    the installer image does (image/Containerfile.installer). The old premise
#    "the deployment /etc replicates the installer's" no longer holds.
#
# The function is lifted VERBATIM out of the installer (the script wipes disks
# and cannot be sourced), so this exercises the code the appliance runs.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AUTOINSTALL="$ROOT/ota/neural-ice-autoinstall.sh"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/ni-devroot-guard.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

awk '/^remove_installer_device_root_guard\(\) \{/,/^}$/' "$AUTOINSTALL" > "$TMP/guard.sh"
grep -q '^remove_installer_device_root_guard()' "$TMP/guard.sh" \
  || fail "cannot extract remove_installer_device_root_guard from the installer"
# The installer must call it with the deployment it located and the parsed source.
# shellcheck disable=SC2016 # literal source-contract assertion
grep -Fq 'remove_installer_device_root_guard "$dep" "$INSTALL_SOURCE"' "$AUTOINSTALL" \
  || fail "phase 6 no longer routes the guard through remove_installer_device_root_guard"

DROPIN_REL=etc/systemd/system/neural-ice-device-root.service.d/10-installer-only.conf
run_case() { # $1=name $2=source $3=fixture(present|absent|symlink|dir) -> prints die text or OK
  local name=$1 source=$2 fixture=$3
  local dep="$TMP/$name"
  mkdir -p "$dep/$(dirname "$DROPIN_REL")"
  case "$fixture" in
    present) printf '[Unit]\nConditionKernelCommandLine=neuralice.autoinstall\n' >"$dep/$DROPIN_REL" ;;
    symlink) ln -s /dev/null "$dep/$DROPIN_REL" ;;
    dir) mkdir -p "$dep/$DROPIN_REL" ;;
    absent) ;;
  esac
  ( set -euo pipefail
    # Stand-ins for the installer's console helpers; the extracted function
    # calls them (invoked indirectly, hence the two shellcheck directives).
    # shellcheck disable=SC2329,SC2317
    die() { printf 'die: %s\n' "$*"; exit 1; }
    # shellcheck disable=SC2329,SC2317
    log() { printf 'log: %s\n' "$*"; }
    # shellcheck disable=SC1090,SC1091
    source "$TMP/guard.sh"
    remove_installer_device_root_guard "$dep" "$source" && echo OK
  ) >"$TMP/$name.out" 2>&1 || true
  cat "$TMP/$name.out"
}

# medium + present: never allowed to survive -> removed, empty directory pruned.
out="$(run_case medium-present medium present)"
[[ "$out" == OK ]] || fail "medium/present: expected OK, got: $out"
[[ ! -e "$TMP/medium-present/$DROPIN_REL" ]] || fail "medium/present: guard still present"
[[ ! -d "$TMP/medium-present/$(dirname "$DROPIN_REL")" ]] || fail "medium/present: empty drop-in directory not pruned"

# medium + absent: the sealed store's image is the appliance, which never had the
# guard -> the desired end state, nothing to remove, continue (never die).
out="$(run_case medium-absent medium absent)"
grep -Fq 'log: Medium-sourced deployment carries no installer-only device-root guard' <<<"$out" \
  || fail "medium/absent: expected the informational log, got: $out"
grep -Fxq OK <<<"$out" || fail "medium/absent: expected OK, got: $out"
grep -Fq 'missing from the target deployment' <<<"$out" \
  && fail "medium/absent: the retired missing-guard refusal came back: $out"

# registry + absent: the pulled image's own /etc never had the guard -> nothing to remove, continue.
out="$(run_case registry-absent registry absent)"
grep -Fq 'log: Registry-sourced deployment carries no installer-only device-root guard' <<<"$out" \
  || fail "registry/absent: expected the informational log, got: $out"
grep -Fxq OK <<<"$out" || fail "registry/absent: expected OK, got: $out"

# registry + present: foreign content shipped by the pinned appliance -> die, never silently repair.
out="$(run_case registry-present registry present)"
grep -Fq 'die: installer device-root Live guard is present in a registry-sourced deployment' <<<"$out" \
  || fail "registry/present: expected the foreign-guard die, got: $out"
[[ -f "$TMP/registry-present/$DROPIN_REL" ]] || fail "registry/present: the foreign guard was mutated"

# symlink in either mode: refused before any removal.
for source in medium registry; do
  out="$(run_case "symlink-$source" "$source" symlink)"
  grep -Fq 'die: installer device-root Live guard is a symlink in the target deployment' <<<"$out" \
    || fail "$source/symlink: expected the symlink die, got: $out"
done

# medium + non-regular entry (directory): refused, never removed.
out="$(run_case medium-dir medium dir)"
grep -Fq 'die: installer device-root Live guard is not a regular file in the target deployment' <<<"$out" \
  || fail "medium/dir: expected the non-regular die, got: $out"
[[ -d "$TMP/medium-dir/$DROPIN_REL" ]] || fail "medium/dir: the entry was mutated"

# unknown source: refused.
out="$(run_case unknown-source other absent)"
grep -Fq 'die: unknown install source for the device-root Live guard: other' <<<"$out" \
  || fail "unknown source: expected refusal, got: $out"

echo "installer device-root guard tests: PASS"
