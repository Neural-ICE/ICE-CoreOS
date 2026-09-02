#!/usr/bin/env bash
# shellcheck disable=SC2016 # literal source-contract assertions below
# Offline proof of the split lifecycle between the signed live installer and
# the installed appliance.  No host manager is modified and no TPM is opened.
#
# Every `$` inside a single-quoted grep pattern here is DELIBERATELY literal:
# this file greps producer and unit sources for their exact text, so `${OS_IMAGE}`
# must reach grep unexpanded. Expanding it would silently turn the check into a
# search for the empty string -- which always matches, and would make the whole
# assertion pass while constraining nothing.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GENERATOR="$ROOT/image/installer/neural-ice-installer-runtime-generator.sh"
GRAMMAR="$ROOT/image/installer/neural-ice-sealed-cmdline-grammar.sh"
TARGET="$ROOT/image/installer/neural-ice-installer.target"
LIVE_TARGET="$ROOT/image/installer/neural-ice-live.target"
LIVE_DIAG_UNIT="$ROOT/image/installer/neural-ice-live-diagnostics.service"
AUTOINSTALL_UNIT="$ROOT/ota/neural-ice-autoinstall.service"
INSTALLER_CF="$ROOT/image/Containerfile.installer"
APPLIANCE_CF="$ROOT/image/Containerfile.bootc"
CEREMONY_UNIT="$ROOT/image/firstboot/neural-ice-firstboot-tpm-ceremony.service"
CEREMONY_DROPIN="$ROOT/image/firstboot/50-neural-ice-tpm-ceremony-sshd.conf"
UNIT_GRAPH="$ROOT/image/test-lib/unit-graph.py"
GATE_TEST="$ROOT/image/test-tpm-ceremony-systemd.sh"
GRAMMAR_TEST="$ROOT/image/test-installer-selector-grammar.sh"
LIVE_DIAG_TEST="$ROOT/image/test-installer-live-diagnostics.sh"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/ni-installer-systemd.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

chmod 0755 "$TMP"
# The sealed command lines these fixtures use carry the eight trust fields, so
# they are the lines a real medium seals rather than an abbreviation of one. The
# grammar is a closed world: an abbreviated line is refused, and refused is not
# what this suite is about.
ANCHOR="neuralice.trust=neural-ice-installer-trust-v1"
ANCHOR="$ANCHOR neuralice.access_profile=lab-managed"
ANCHOR="$ANCHOR neuralice.hardware_target=nvidia-gb10-arm64"
ANCHOR="$ANCHOR neuralice.payload=$(printf '%064d' 1)"
ANCHOR="$ANCHOR neuralice.relauth_keyid=$(printf '%064d' 2)"
ANCHOR="$ANCHOR neuralice.relauth_schema=neural-ice-installer-release-authorization-v2"
ANCHOR="$ANCHOR neuralice.rootverity=$(printf '%064d' 3)"
ANCHOR="$ANCHOR neuralice.trust_policy_id=neural-ice-secureboot-lab-v1"

run_generator() { # $1=cmdline $2=output-root [--check]
  local cmdline=$1 output=$2 mode=${3:-generate}
  install -d -m 0755 "$output/normal" "$output/early" "$output/late"
  printf '%s\n' "$cmdline" > "$output/cmdline"
  chmod -R a+rX "$output"
  local -a command=(env NI_INSTALLER_GENERATOR_TESTING=1
    NI_INSTALLER_GENERATOR_TEST_CMDLINE="$output/cmdline"
    NI_INSTALLER_GENERATOR_TEST_GRAMMAR="$GRAMMAR" "$GENERATOR")
  if [[ "$mode" == --check ]]; then
    command+=(--check)
  else
    command+=("$output/normal" "$output/early" "$output/late")
  fi
  if (( EUID == 0 )); then
    chown -R nobody:nogroup "$output" 2>/dev/null || chown -R nobody:nobody "$output"
    runuser -u nobody -- "${command[@]}"
  else
    "${command[@]}"
  fi
}

install_cmdline="$ANCHOR quiet systemd.unit=neural-ice-installer.target neuralice.autoinstall=1 enforcing=0"
run_generator "$install_cmdline" "$TMP/install"
run_generator "$install_cmdline" "$TMP/check" --check
live_cmdline="$ANCHOR quiet systemd.unit=neural-ice-live.target neuralice.live=1"
run_generator "$live_cmdline" "$TMP/live"
# The registry-backed Install. Its command line is the only one that seals
# `neuralice.source=registry`, and it is the only one that may request a network.
registry_cmdline="$install_cmdline neuralice.release_authority=release.example.test"
registry_cmdline="$registry_cmdline neuralice.source=registry"
registry_cmdline="$registry_cmdline neuralice.osimage=release.example.test/neural-ice/neural-ice-coreos@sha256:$(printf '%064d' 4)"
# The signed release authorization the ESP must carry, pinned by hash in the same
# line: the grammar refuses a registry medium that seals a source and not both.
registry_cmdline="$registry_cmdline neuralice.relauth_sha256=$(printf '%064d' 5)"
registry_cmdline="$registry_cmdline neuralice.relauth_sig_sha256=$(printf '%064d' 6)"
run_generator "$registry_cmdline" "$TMP/registry"

masked_units=(
  neural-ice-firstboot-tpm-ceremony.service
  neural-ice-firstboot-sshkey.service neural-ice-firstboot-sshkey-activate.service
  neural-ice-payload-apply.service neural-ice-hostname-init.service
  neural-ice-dhcp-retry.service neural-ice-device-root.service
  nvidia-device-nodes.service nvidia-cdi-generate.service
  avahi-daemon.service avahi-daemon.socket sshd.service sshd.socket sshd@.service
  getty@.service serial-getty@.service autovt@.service
  console-getty.service container-getty@.service getty.target
  systemd-user-sessions.service user@.service
  bootc-fetch-apply-updates.service bootc-fetch-apply-updates.timer
  systemd-sysext.service systemd-confext.service
)
for unit in "${masked_units[@]}"; do
  [[ -L "$TMP/install/early/$unit" && "$(readlink "$TMP/install/early/$unit")" == /dev/null ]] \
    || fail "installer mode did not transiently mask $unit"
  [[ -L "$TMP/live/early/$unit" && "$(readlink "$TMP/live/early/$unit")" == /dev/null ]] \
    || fail "Live mode did not transiently mask installed-only unit $unit"
done
[[ ! -e "$TMP/install/early/NetworkManager.service" ]] \
  || fail "the registry install's network dependency was masked"
[[ ! -e "$TMP/live/early/NetworkManager.service" ]] \
  || fail "Live mode masked its intended networking"
[[ ! -e "$TMP/live/early/neural-ice-live.target" ]] \
  || fail "the exact signed Live selector masked its intended target"
grep -Eq 'autologin[[:space:]]+root|agetty.*--autologin' "$GENERATOR" \
  && fail "the Live generator creates a root autologin"

# Every LOGIN-CAPABLE surface, on Live as on Install. The debug image ships a
# serial root autologin drop-in; masking the getty templates and the session
# units is what makes a Live medium unable to inherit it, and is why Live needs
# no console policy of its own.
for login_unit in getty@.service serial-getty@.service autovt@.service \
  console-getty.service container-getty@.service getty.target \
  systemd-user-sessions.service user@.service sshd.service sshd.socket sshd@.service; do
  for mode in install live; do
    [[ -L "$TMP/$mode/early/$login_unit" \
      && "$(readlink "$TMP/$mode/early/$login_unit")" == /dev/null ]] \
      || fail "$mode mode did not mask the login surface $login_unit"
  done
done

# THE DESTRUCTIVE PATH. Live boots the same image the Install medium carries,
# so neural-ice-autoinstall.service is present and enabled on it. Live must mask
# the whole install path; Install must obviously keep it.
for install_unit in neural-ice-installer.target neural-ice-autoinstall.service; do
  [[ -L "$TMP/live/early/$install_unit" \
    && "$(readlink "$TMP/live/early/$install_unit")" == /dev/null ]] \
    || fail "Live mode left the destructive $install_unit reachable"
  [[ ! -e "$TMP/install/early/$install_unit" ]] \
    || fail "Install mode masked its own $install_unit"
done

# --------------------------------------------------------------------------- #
# 🔴 THE ROOT SHELLS, AND THE ASYMMETRY THAT NO LONGER EXISTS.
#
# `systemd.debug_shell` reaches debug-shell.service through
# systemd-debug-generator, which writes into the NORMAL generator directory; this
# generator writes into the EARLY one, which systemd ranks higher, so a mask here
# defeats that Wants=. `emergency` / `rescue` / `single` reach the same place
# through the manager itself.
#
# UNTIL 2026-09-02 INSTALL KEPT THEM (independent review, P0 #1). The
# justification was that neural-ice-autoinstall.service carried
# `OnFailure=emergency.target` and an operator who had authorised a full-disk
# wipe was "not protected by having their failure diagnostics taken away". That
# was wrong: authorising the wipe of ONE disk is not authorising a root shell
# over the whole machine, and every preflight, authorisation, pull, storage, TPM
# and deployment failure reached that shell on the console.
#
# BOTH MODES NOW MASK ALL FIVE, and the Install failure path is a fixed
# output-only sink instead. The assertion is in both directions: the five stay
# masked, AND the sink they were justified by is gone from the unit.
# --------------------------------------------------------------------------- #
debug_surfaces=(debug-shell.service emergency.service emergency.target
  rescue.service rescue.target)
for surface in "${debug_surfaces[@]}"; do
  for mode in install live; do
    [[ -L "$TMP/$mode/early/$surface" \
      && "$(readlink "$TMP/$mode/early/$surface")" == /dev/null ]] \
      || fail "$mode mode can still reach the root shell surface $surface"
  done
done
# Directives only: the unit's comment explains WHY the emergency sink is gone,
# and a check that cannot tell a comment from a directive constrains nothing.
grep -v '^[[:space:]]*#' "$AUTOINSTALL_UNIT" | grep -qiE 'emergency|rescue|debug-shell' \
  && fail "the autoinstall unit still names an emergency/rescue/debug surface; its failure sink must be the fixed output-only target"
grep -qx 'OnFailure=neural-ice-installer-failure.target' "$AUTOINSTALL_UNIT" \
  || fail "the autoinstall unit does not route its failures to the fixed output-only sink"
grep -qx 'OnFailureJobMode=isolate' "$AUTOINSTALL_UNIT" \
  || fail "a failed install no longer stops every other job on the machine"

# --------------------------------------------------------------------------- #
# THE FAILURE SINK IS PART OF THE INSTALL PATH AND OF NOTHING ELSE.
# --------------------------------------------------------------------------- #
for failure_unit in neural-ice-installer-failure.target neural-ice-installer-failure.service; do
  [[ ! -e "$TMP/install/early/$failure_unit" ]] \
    || fail "Install mode masked $failure_unit, the only sink its own failures can reach"
  [[ -L "$TMP/live/early/$failure_unit" \
    && "$(readlink "$TMP/live/early/$failure_unit")" == /dev/null ]] \
    || fail "Live mode left the install failure sink $failure_unit reachable"
done

# ...and it pulls exactly one service and nothing else. An enumeration, not a
# pattern: a pattern only refuses what someone thought of.
FAILURE_TARGET="$ROOT/image/installer/neural-ice-installer-failure.target"
FAILURE_UNIT="$ROOT/image/installer/neural-ice-installer-failure.service"
[ -f "$FAILURE_TARGET" ] && [ -f "$FAILURE_UNIT" ] \
  || fail "the installer failure sink units are missing"
failure_dependencies="$(grep -E '^(Requires|Wants|Requisite|BindsTo|PartOf)=' "$FAILURE_TARGET" | sort)"
[[ "$failure_dependencies" == 'Requires=neural-ice-installer-failure.service' ]] \
  || fail "the installer failure target's dependency set is not exactly its one output-only service; it is:"$'\n'"$failure_dependencies"
grep -qx 'AllowIsolate=yes' "$FAILURE_TARGET" \
  || fail "the installer failure target cannot be isolated onto, so OnFailureJobMode=isolate would fail"
grep -qx 'StandardInput=null' "$FAILURE_UNIT" \
  || fail "the installer failure surface does not close its standard input; that is an operator command surface"
grep -Eq '^ExecStart=/usr/libexec/neural-ice-installer-failure$' "$FAILURE_UNIT" \
  || fail "the installer failure surface takes an argument, or is not the fixed output-only script"
grep -Eq '^(ExecStartPre|ExecStartPost|ExecStop|ExecReload)=' "$FAILURE_UNIT" \
  && fail "the installer failure surface grew a second command surface"
[[ "$(awk -F= '$1 == "CapabilityBoundingSet" { print $2 }' "$FAILURE_UNIT")" == CAP_SYS_BOOT ]] \
  || fail "the installer failure surface keeps capabilities beyond the power-off it exists to perform"

# --------------------------------------------------------------------------- #
# 🔴 THE REGISTRY INSTALL'S NETWORK PATH, RESOLVED AS A GRAPH (review 2026-09-02,
# P1 #3).
#
# The previous assertion was "NetworkManager is not masked", and it was true
# while a registry install had no reachable network at all: the appliance image
# drops `Requires=neural-ice-firstboot-tpm-ceremony.service` into the five
# network units, this generator masks that ceremony on every medium boot, and a
# NetworkManager START TRANSACTION therefore failed on a masked required
# dependency. Nothing about NetworkManager's own mask state could show that.
#
# So the graph is resolved for real: vendor stand-ins for the units this
# repository does not own, the REAL ceremony drop-in and the REAL ceremony unit
# from this checkout, the REAL generator output as the highest-precedence
# directory, and the same precedence and drop-in shadowing systemd uses.
# --------------------------------------------------------------------------- #
build_unit_tree() { # $1=mode  -> prints "<early>:<usr>"
  # Two `local`s: bash expands every word of a command before the builtin runs,
  # so `local a=$1 b=$a` reads an OUTER `a`, not the one being assigned.
  local mode=$1 unit
  local tree="$TMP/graph-$mode"
  rm -rf "$tree"; mkdir -p "$tree/usr"
  # Units this repository does not own, reduced to the edges that matter. A
  # stand-in is honest here: the edge under test is the drop-in THIS repository
  # adds, not NetworkManager's own vendor dependencies.
  printf '[Unit]\nDescription=NetworkManager\nAfter=dbus.service\n' \
    > "$tree/usr/NetworkManager.service"
  printf '[Unit]\nDescription=NetworkManager wait online\nRequires=NetworkManager.service\n' \
    > "$tree/usr/NetworkManager-wait-online.service"
  for unit in network-pre.target network.target network-online.target \
    basic.target sysinit.target dbus.service; do
    printf '[Unit]\nDescription=%s\n' "$unit" > "$tree/usr/$unit"
  done
  # ...and the ones it DOES own, verbatim.
  cp "$CEREMONY_UNIT" "$tree/usr/neural-ice-firstboot-tpm-ceremony.service"
  cp "$TARGET" "$tree/usr/neural-ice-installer.target"
  cp "$LIVE_TARGET" "$tree/usr/neural-ice-live.target"
  cp "$LIVE_DIAG_UNIT" "$tree/usr/neural-ice-live-diagnostics.service"
  cp "$AUTOINSTALL_UNIT" "$tree/usr/neural-ice-autoinstall.service"
  # The appliance's own ceremony drop-in, in exactly the five places
  # image/Containerfile.bootc puts it and under exactly the name it uses there.
  for unit in NetworkManager.service NetworkManager-wait-online.service \
    network-pre.target network.target network-online.target; do
    mkdir -p "$tree/usr/$unit.d"
    cp "$CEREMONY_DROPIN" "$tree/usr/$unit.d/50-neural-ice-tpm-ceremony.conf"
    grep -Fq "COPY image/firstboot/50-neural-ice-tpm-ceremony-sshd.conf /usr/lib/systemd/system/$unit.d/50-neural-ice-tpm-ceremony.conf" \
      "$APPLIANCE_CF" \
      || fail "the appliance no longer installs the ceremony drop-in at $unit.d/50-neural-ice-tpm-ceremony.conf; this fixture models a path that does not exist"
  done
  printf '%s:%s' "$TMP/$mode/early" "$tree/usr"
}

graph_state() { # $1=search-path $2=root-unit $3=unit
  python3 "$UNIT_GRAPH" "$2" "$1" | awk -v u="$3" '$2 == u { print $1 }'
}
graph_masked_members() { # $1=search-path $2=root-unit
  python3 "$UNIT_GRAPH" "$2" "$1" | awk '$1 == "masked" { print $2 }'
}

install_search="$(build_unit_tree install)"
live_search="$(build_unit_tree live)"

# The ceremony IS masked on a medium boot -- that part is deliberate and must
# stay, because the installed-appliance ceremony has nothing to do on a medium.
[[ "$(readlink "$TMP/install/early/neural-ice-firstboot-tpm-ceremony.service")" == /dev/null ]] \
  || fail "the medium boot no longer masks the installed first-boot ceremony"

# ...and NetworkManager is nonetheless STARTABLE, because the generator shadows
# the drop-in that required it. Not one member of the hard-requirement closure
# may be masked; that is what a start transaction actually needs.
nm_masked="$(graph_masked_members "$install_search" NetworkManager.service)"
[[ -z "$nm_masked" ]] \
  || fail "a registry install cannot start NetworkManager: its required closure contains masked units: $nm_masked"
for network_unit in NetworkManager-wait-online.service network-pre.target \
  network.target network-online.target; do
  masked_members="$(graph_masked_members "$install_search" "$network_unit")"
  [[ -z "$masked_members" ]] \
    || fail "a registry install cannot reach $network_unit: masked required units: $masked_members"
done

# --------------------------------------------------------------------------- #
# 🔴 ...AND SOMETHING ACTUALLY ASKS FOR IT (independent review 2026-09-02,
# P1 #1, and P2 #2 on this suite's own wording).
#
# Everything above proves the transaction would RESOLVE. It says nothing about
# whether a registry install ever REQUESTS one, and it did not: neither
# neural-ice-installer.target nor neural-ice-autoinstall.service carried a
# Wants=/After= edge to NetworkManager, so the installer reached `podman pull`
# with no configured link on a bench where the disk had already been authorised
# for a wipe. This suite reported "resolved for real" over that gap.
#
# The generator now emits the edge into /run, and only for the exact sealed word
# that needs it. Both directions are asserted: a registry install requests it, a
# medium install does not, and removing the drop-in removes the request.
# --------------------------------------------------------------------------- #
registry_search="$(build_unit_tree registry)"
registry_wants="$(python3 "$UNIT_GRAPH" --wants neural-ice-autoinstall.service "$registry_search")"
for requested in NetworkManager.service network-online.target; do
  grep -qx "present $requested" <<<"$registry_wants" \
    || fail "a registry install does not request $requested; it would reach podman pull with no configured network."$'\n'"effective Wants= was:"$'\n'"$registry_wants"
done
registry_masked="$(graph_masked_members "$registry_search" neural-ice-installer.target)"
[[ -z "$registry_masked" ]] \
  || fail "the registry Install target cannot start: masked required units: $registry_masked"
# The MEDIUM install is air-gapped by design and must request nothing: a network
# edge there is an install waiting on a link that is deliberately absent.
medium_wants="$(python3 "$UNIT_GRAPH" --wants neural-ice-autoinstall.service "$install_search")"
grep -qE 'NetworkManager|network-online' <<<"$medium_wants" \
  && fail "an air-gapped medium install requests networking it does not need:"$'\n'"$medium_wants"
# Live never requests a network either: its only surface is denied IP traffic
# outright.
live_wants="$(python3 "$UNIT_GRAPH" --wants neural-ice-autoinstall.service "$live_search")"
grep -qE 'NetworkManager|network-online' <<<"$live_wants" \
  && fail "a Live boot requests networking"

# THE MUTATION PROOF for the request itself: delete exactly the drop-in the
# generator wrote, and the request must disappear. Without this the assertion
# above would pass against a unit that had the edge baked in unconditionally,
# which is the change this one deliberately is not.
rm -rf "$TMP/registry-mutation"; mkdir -p "$TMP/registry-mutation"
cp -a "$TMP/registry/early" "$TMP/registry-mutation/early"
rm -f "$TMP/registry-mutation/early/neural-ice-autoinstall.service.d/10-neural-ice-registry-network.conf"
mutated_registry_search="${TMP}/registry-mutation/early:${registry_search#*:}"
python3 "$UNIT_GRAPH" --wants neural-ice-autoinstall.service "$mutated_registry_search" \
  | grep -qE 'NetworkManager|network-online' \
  && fail "the mutation proof did not reproduce the defect: without the generator's drop-in, nothing may request a network"
# The request is under /run only, like everything else this generator writes.
[[ -f "$TMP/registry/early/neural-ice-autoinstall.service.d/10-neural-ice-registry-network.conf" ]] \
  || fail "the registry network request is not a real file the generator emitted"

# 🔴 THE MUTATION PROOF. Remove exactly the shadow the generator writes, and the
# closure must go back to containing the masked ceremony. Without this, the
# assertion above would pass just as happily against a graph that never had the
# edge in the first place -- which is precisely how the original defect survived
# a green test.
mutated_early="$TMP/mutation/early"
rm -rf "$TMP/mutation"; mkdir -p "$TMP/mutation"
cp -a "$TMP/install/early" "$mutated_early"
rm -f "$mutated_early/NetworkManager.service.d/50-neural-ice-tpm-ceremony.conf"
mutated_search="${mutated_early}:${install_search#*:}"
[[ "$(graph_state "$mutated_search" NetworkManager.service neural-ice-firstboot-tpm-ceremony.service)" == masked ]] \
  || fail "the mutation proof did not reproduce the defect: without the generator's shadow, NetworkManager's closure must contain the masked ceremony"
# ...and the shadow is a real file the generator emitted, not an accident.
for unit in NetworkManager.service NetworkManager-wait-online.service \
  network-pre.target network.target network-online.target; do
  for mode in install live; do
    [[ -f "$TMP/$mode/early/$unit.d/50-neural-ice-tpm-ceremony.conf" ]] \
      || fail "$mode mode did not shadow the appliance ceremony drop-in on $unit"
  done
done
# The shadow is under /run only. Nothing this generator writes may name a path
# outside the directory systemd handed it.
grep -rl '/etc/systemd\|/usr/lib/systemd/system/' "$TMP/install/early" >/dev/null 2>&1 \
  && fail "the generator wrote a reference to a persistent unit directory"

# THE INSTALL PATH IS WHOLE, and the LIVE path is whole and separate.
install_masked="$(graph_masked_members "$install_search" neural-ice-installer.target)"
[[ -z "$install_masked" ]] \
  || fail "the signed Install target cannot start: masked required units: $install_masked"
python3 "$UNIT_GRAPH" neural-ice-installer.target "$install_search" \
  | grep -qx 'present neural-ice-autoinstall.service' \
  || fail "the signed Install target no longer hard-requires a startable autoinstall"

live_masked="$(graph_masked_members "$live_search" neural-ice-live.target)"
[[ -z "$live_masked" ]] \
  || fail "the signed Live target cannot start: masked required units: $live_masked"
live_closure="$(python3 "$UNIT_GRAPH" neural-ice-live.target "$live_search" | awk '{print $2}')"
for forbidden in neural-ice-autoinstall.service neural-ice-installer.target \
  neural-ice-firstboot-tpm-ceremony.service multi-user.target getty@.service \
  sshd.service; do
  grep -qx "$forbidden" <<<"$live_closure" \
    && fail "the signed Live target hard-requires $forbidden"
done
# The diagnostics summary is pulled, and it is startable.
[[ "$(graph_state "$live_search" neural-ice-live-diagnostics.service neural-ice-live-diagnostics.service)" == present ]] \
  || fail "a Live boot cannot start its only product surface"

# Closed list shared with the installed-appliance dependency proof: exactly the
# 24 consumers reviewed for runtime/SSH/OTA readiness.  Five network units are
# suppressed by the dedicated target rather than masked because registry-mode
# autoinstall may legitimately activate networking as its own dependency.
consumer_units=(
  sshd.service sshd.socket getty@.service serial-getty@.service autovt@.service
  network-pre.target network.target network-online.target NetworkManager.service
  NetworkManager-wait-online.service avahi-daemon.service avahi-daemon.socket
  systemd-user-sessions.service user@.service neural-ice-payload-apply.service
  neural-ice-hostname-init.service neural-ice-dhcp-retry.service
  nvidia-device-nodes.service nvidia-cdi-generate.service
  neural-ice-device-root.service bootc-fetch-apply-updates.service
  bootc-fetch-apply-updates.timer systemd-sysext.service systemd-confext.service
)
[[ "${#consumer_units[@]}" == 24 ]] || fail "the audited installed consumer set is no longer 24"
for network_unit in network-pre.target network.target network-online.target \
  NetworkManager.service NetworkManager-wait-online.service; do
  grep -Eq "^(Requires|Wants)=.*${network_unit//./\\.}" "$TARGET" \
    && fail "the installer target directly pulls installed consumer $network_unit"
done

# Installed boot has neither installer selector.  The installer image may be
# the source deployment, so zero generated masks is the decisive proof that the
# first installed boot retains the appliance ceremony and its 24+ consumers.
run_generator 'quiet rd.luks=1 root=/dev/mapper/system' "$TMP/installed"
[[ -z "$(find "$TMP/installed/early" -mindepth 1 -print -quit)" ]] \
  || fail "installer-only masks leaked into the installed boot"
run_generator "$ANCHOR quiet neuralice.autoinstall=1" "$TMP/partial" >/dev/null 2>&1 || true
for target in default.target multi-user.target graphical.target \
  neural-ice-installer.target neural-ice-autoinstall.service; do
  [[ -L "$TMP/partial/early/$target" ]] \
    || fail "a partial installer selector can fall through to $target"
done
run_generator "$ANCHOR quiet neuralice.autoinstall=1" "$TMP/partial-check" --check >/dev/null 2>&1 \
  && fail "a partial installer selector passed executable preflight"
run_generator "$ANCHOR quiet systemd.unit=neural-ice-installer.target neuralice.autoinstall=1 neuralice.autoinstall=1" \
  "$TMP/duplicate-check" --check >/dev/null 2>&1 \
  && fail "a duplicated installer selector passed executable preflight"

# Live is a second closed signed grammar, not the absence of Install. Its target
# alone, a missing target, a duplicate selector, or a mixture with autoinstall
# must all suppress every general boot target instead of falling through to the
# inherited appliance lifecycle.
live_mutations=(
  "$ANCHOR quiet systemd.unit=neural-ice-live.target"
  "$ANCHOR quiet neuralice.live=1"
  "$ANCHOR quiet systemd.unit=neural-ice-live.target neuralice.live=1 neuralice.live=1"
  "$ANCHOR quiet systemd.unit=neural-ice-live.target systemd.unit=neural-ice-installer.target neuralice.live=1 neuralice.autoinstall=1"
  # 🔴 THE ONE MIXTURE THAT IS A SINGLE WELL-FORMED TARGET SELECTION. Both mode
  # words on one line with exactly one systemd.unit= is the case an
  # Install-only exactness test cannot see: without the mutual exclusion in
  # exact_install_cmdline/exact_live_cmdline it reads as a valid Install and
  # runs the DESTRUCTIVE autoinstall on a medium that also claims to be Live.
  "$ANCHOR quiet systemd.unit=neural-ice-installer.target neuralice.autoinstall=1 neuralice.live=1"
  "$ANCHOR quiet systemd.unit=neural-ice-live.target neuralice.live=1 neuralice.autoinstall=1"
  # 🔴 THE ESCAPE THE INDEPENDENT REVIEW DEMONSTRATED. Everything about this line
  # is a well-formed Live selection except one extra word, and that word made
  # systemd-debug-generator start an unauthenticated root shell on tty9.
  "$ANCHOR quiet systemd.unit=neural-ice-live.target neuralice.live=1 systemd.debug_shell"
  "$ANCHOR quiet systemd.unit=neural-ice-live.target neuralice.live=1 init=/bin/sh"
  "$ANCHOR quiet systemd.unit=neural-ice-live.target neuralice.live=1 rd.break"
  "$ANCHOR quiet systemd.unit=neural-ice-live.target neuralice.live=1 emergency"
  "$ANCHOR quiet systemd.unit=neural-ice-live.target neuralice.live=1 systemd.mask=neural-ice-live-diagnostics.service"
  "$ANCHOR quiet systemd.unit=neural-ice-live.target neuralice.live=1 enforcing=0"
)
for index in "${!live_mutations[@]}"; do
  output="$TMP/live-mutation-$index"
  run_generator "${live_mutations[$index]}" "$output" >/dev/null 2>&1 \
    && fail "malformed Live selector $index was accepted"
  for target in default.target multi-user.target graphical.target \
    neural-ice-live.target neural-ice-live-diagnostics.service \
    neural-ice-installer.target neural-ice-autoinstall.service \
    debug-shell.service emergency.target emergency.service rescue.target \
    rescue.service getty@.service sshd.service; do
    [[ -L "$output/early/$target" && "$(readlink "$output/early/$target")" == /dev/null ]] \
      || fail "malformed Live selector $index can fall through to $target"
  done
done

# Dependency semantics: the signed target hard-requires autoinstall, and the
# service fails/isolate rather than Condition-skipping when the selector or its
# target inputs are absent.  It is not attached to basic/multi-user.
grep -Eq '^Requires=.*neural-ice-autoinstall\.service' "$TARGET" \
  || fail "the installer target does not require autoinstall success"
grep -Eq '^After=.*neural-ice-autoinstall\.service' "$TARGET" \
  || fail "the installer target can become active before autoinstall completes"
grep -qx 'ExecStartPre=/usr/lib/systemd/system-generators/neural-ice-installer-runtime-generator --check' "$AUTOINSTALL_UNIT" \
  || fail "autoinstall has no executable signed-cmdline preflight"
grep -qx 'OnFailure=neural-ice-installer-failure.target' "$AUTOINSTALL_UNIT" \
  || fail "autoinstall failure does not enter the fixed output-only failure sink"
# The evidence the sink renders is created by THIS unit, root-only, before
# ExecStart -- so the installer's failure path creates no directory and decides
# no mode. Losing these three directives makes the sink render `unclassified`
# for every field, which is a silent loss of the only thing an operator gets.
for evidence_directive in \
  'RuntimeDirectory=neural-ice-installer-failure' \
  'RuntimeDirectoryMode=0700' \
  'RuntimeDirectoryPreserve=yes'; do
  grep -qx "$evidence_directive" "$AUTOINSTALL_UNIT" \
    || fail "autoinstall no longer provides its failure sink with a root-only evidence directory ($evidence_directive)"
done
grep -qx 'OnFailureJobMode=isolate' "$AUTOINSTALL_UNIT" \
  || fail "autoinstall failure does not isolate recovery"
grep -q '^ConditionKernelCommandLine=' "$AUTOINSTALL_UNIT" \
  && fail "autoinstall can be condition-skipped instead of failing its target"
grep -Eq '^(WantedBy|RequiredBy)=(basic|multi-user)\.target' "$AUTOINSTALL_UNIT" \
  && fail "autoinstall is still inherited by a general-purpose target"
if command -v systemd-analyze >/dev/null 2>&1; then
  # The source Exec paths exist only inside the composed installer image.  Feed
  # systemd the exact units with only Exec*= replaced by /bin/true; the source
  # paths were asserted above, while the native parser now checks the real unit
  # directives and dependency graph without requiring a composed rootfs.
  install -d "$TMP/verify-units"
  cp "$TARGET" "$TMP/verify-units/neural-ice-installer.target"
  sed -E 's#^(ExecStartPre|ExecStart)=.*#\1=/bin/true#' "$AUTOINSTALL_UNIT" \
    > "$TMP/verify-units/neural-ice-autoinstall.service"
  if ! SYSTEMD_UNIT_PATH="$TMP/verify-units:/usr/lib/systemd/system:/lib/systemd/system" \
    systemd-analyze verify "$TMP/verify-units/neural-ice-installer.target" \
      "$TMP/verify-units/neural-ice-autoinstall.service" 2>"$TMP/systemd-verify.err"; then
    # Ubuntu 26.04's verifier needs userdb ancillary-data socket options that
    # the repository sandbox denies.  Only that exact environment refusal may
    # defer the native parser; every other diagnostic is a unit failure.
    if [[ "$(wc -l < "$TMP/systemd-verify.err")" == 2 ]] \
      && grep -Fq 'Failed to turn off SO_PASSRIGHTS on user lookup socket' "$TMP/systemd-verify.err" \
      && grep -Fq 'Failed to enable SO_PASSCRED on handoff timestamp socket' "$TMP/systemd-verify.err"; then
      echo "  (systemd-analyze verify unavailable: sandbox denies userdb socket options)" >&2
    else
      cat "$TMP/systemd-verify.err" >&2
      fail "systemd rejected the offline installer unit graph"
    fi
  fi
fi

# Image-layer split: installer files are present, but no persistent ceremony
# mask/disable/default-target mutation is baked.  The appliance layer remains
# the sole source of the multi-user enablement used on first installed boot.
for source in neural-ice-installer.target neural-ice-live.target \
  neural-ice-installer-runtime-generator.sh neural-ice-sealed-cmdline-grammar.sh \
  neural-ice-live-diagnostics.sh neural-ice-live-diagnostics.service; do
  grep -Fq "image/installer/$source" "$INSTALLER_CF" \
    || fail "the installer image does not contain $source"
done
grep -Fq 'systemctl enable neural-ice-autoinstall.service' "$INSTALLER_CF" \
  || fail "the installer image does not attach autoinstall to its dedicated target"
grep -Eq 'systemctl (mask|disable).*neural-ice-firstboot-tpm-ceremony' "$INSTALLER_CF" \
  && fail "the installer layer persistently weakens the installed ceremony"
grep -Fq 'neural-ice-firstboot-tpm-ceremony.service' "$APPLIANCE_CF" \
  || fail "the installed appliance no longer enables its mandatory ceremony"
grep -qx 'RequiredBy=multi-user.target' "$CEREMONY_UNIT" \
  || fail "the installed target no longer hard-requires ceremony success"

# THE PRODUCER SEALS BOTH GRAMMARS. This lives here, not only in
# image/test-installer-media.sh, because that suite SKIPs wherever veritysetup
# is absent -- and the karg set is exactly what the P1 was about: MEDIA_MODE=live
# used to seal `quiet` alone and inherit whatever the image defaulted to.
USB_PRODUCER="$ROOT/image/build-installer-usb.sh"
grep -Fq 'systemd.unit=neural-ice-live.target' "$USB_PRODUCER" \
  || fail "the media producer does not seal the dedicated Live target"
grep -Fq 'neuralice.live=1' "$USB_PRODUCER" \
  || fail "the media producer does not seal an affirmative Live selector"
grep -Fq 'systemd.unit=neural-ice-installer.target' "$USB_PRODUCER" \
  || fail "the media producer no longer seals the fail-closed installer target"
# 🔴 THE REGISTRY-BACKED INSTALL IS SELECTABLE THROUGH THE ONLY SUPPORTED PRODUCER.
# It was documented and implemented in the installer while this producer sealed
# none of it, so the path was unreachable through any supported way of cutting a
# medium (review 2026-09-02, P1 #3).
grep -Fq 'neuralice.source=registry' "$USB_PRODUCER" \
  || fail "the media producer cannot seal a registry install source"
grep -Fq 'neuralice.osimage=${OS_IMAGE}' "$USB_PRODUCER" \
  || fail "the media producer cannot seal the digest-pinned appliance image"
grep -Fq 'neuralice.mirror=${INSTALL_MIRROR}' "$USB_PRODUCER" \
  || fail "the media producer cannot seal the LAN mirror transport"
grep -Fq 'ni_sealed_value_is_valid neuralice.osimage' "$USB_PRODUCER" \
  || fail "the media producer does not validate the appliance image through the sealed grammar"
grep -Fq 'assert_registry_install_authorised' "$USB_PRODUCER" \
  || fail "the media producer cuts a registry medium without checking it carries a signed docker scope"
grep -Fq 'ni_sealed_cmdline_classify "$SEALED_CMDLINE"' "$USB_PRODUCER" \
  || fail "the media producer does not re-read the command line it actually sealed"
grep -Fq 'image/installer/neural-ice-sealed-cmdline-grammar.sh' "$USB_PRODUCER" \
  || fail "the media producer does not use the same grammar the medium boots with"

# Live has a distinct target precisely because multi-user.target carries that
# hard installed-appliance edge. It reaches only the base system and cannot
# grow a login/autologin or destructive installer dependency of its own.
grep -qx 'Requires=basic.target' "$LIVE_TARGET" \
  || fail "the signed Live target does not require the safe base target"
grep -Eq '^(Requires|Wants|Requisite|BindsTo|PartOf)=.*(sshd|getty|user@|multi-user|graphical|neural-ice-installer|neural-ice-autoinstall|neural-ice-firstboot)' \
  "$LIVE_TARGET" \
  && fail "the signed Live target pulls an installed, login-capable or destructive lifecycle"
# ...and the dependency set is ENUMERATED, not merely pattern-checked: basic.target
# plus the one read-only diagnostic summary, and nothing else. A pattern can only
# refuse what someone thought of; an enumeration refuses everything else.
live_dependencies="$(grep -E '^(Requires|Wants|Requisite|BindsTo|PartOf)=' "$LIVE_TARGET" | sort)"
expected_live_dependencies="$(printf '%s\n' 'Requires=basic.target' \
  'Wants=neural-ice-live-diagnostics.service' | sort)"
[[ "$live_dependencies" == "$expected_live_dependencies" ]] \
  || fail "the signed Live target's dependency set is not exactly basic.target + the read-only diagnostics summary; it is:"$'\n'"$live_dependencies"

# Missing installed inputs make the ceremony fail; its isolated failure and all
# consumer Requires edges are checked by the existing closed-world gate suite.
bash "$GATE_TEST" >/dev/null

# 🔴 THE TWO SIBLING SUITES RUN FROM HERE, AND THEY DO NOT SKIP.
# image/test-installer-selector-grammar.sh owns the sealed command-line grammar
# and image/test-installer-live-diagnostics.sh owns the Live product surface.
# Both are pure and need no verity toolchain; running them here is what keeps
# them in every environment that runs this suite, rather than only where a full
# sealed-medium fixture can be built (review 2026-09-02, P3).
bash "$GRAMMAR_TEST" >/dev/null
bash "$LIVE_DIAG_TEST" >/dev/null

echo "INSTALLER_SYSTEMD_LIFECYCLE_TEST_OK (${#consumer_units[@]} consumers suppressed; ${#masked_units[@]} transient masks; installed boot emits none; a registry install both requests NetworkManager and resolves its closure, a medium install requests neither)"
