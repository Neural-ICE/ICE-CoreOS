#!/usr/bin/env bash
# Installer-image-only systemd generator.  The signed UKI selects the dedicated
# target; this generator prevents inherited appliance/listener units from being
# started manually or through an unexpected dependency while that target runs.
# It writes only below /run, so nothing it does can reach the installed OS.
#
# 🔴 IT MASKS FIRST AND UNMASKS SECOND (review 2026-09-02, P1 #1).
#
# The previous revision classified the command line and then decided what to
# mask. Every path that could fail BEFORE that decision -- an unreadable grammar
# library, an argument this file does not understand, a `set -e` abort -- left
# the boot with no masks at all, falling through to the inherited
# installed-appliance default. So the order is now inverted: the moment a media
# selector is seen, EVERYTHING is masked, and a recognised signed grammar is the
# only thing that takes anything back off the list. A refusal, a crash and an
# unreadable library are then the same boot: one that reaches nothing.
#
# 🔴 AND IT VALIDATES THE WHOLE LINE, not three words of it.
#
# The words `neuralice.live`, `neuralice.autoinstall` and `systemd.unit` used to
# be the entire check, so a validly signed Live UKI carrying `systemd.debug_shell`
# passed -- and systemd-debug-generator then started an unauthenticated root
# shell on tty9, from which the destructive installer was one command away.
# image/installer/neural-ice-sealed-cmdline-grammar.sh states the only grammar a
# medium may seal, as a closed world; this file enforces it, and additionally
# masks the debug/emergency/rescue surfaces on every boot that is not the exact
# signed Install selector, so that even a systemd argument nobody anticipated has
# nothing left to activate.
set -euo pipefail

die() { printf 'neural-ice-installer-runtime-generator: refused: %s\n' "$*" >&2; exit 1; }

if [[ -n "${NI_INSTALLER_GENERATOR_TESTING:-}" ]]; then
  [[ "$NI_INSTALLER_GENERATOR_TESTING" == 1 && "$EUID" -ne 0 ]] \
    || die "test overrides are forbidden in a privileged process"
  readonly CMDLINE_FILE="${NI_INSTALLER_GENERATOR_TEST_CMDLINE:?}"
  readonly GRAMMAR_FILE="${NI_INSTALLER_GENERATOR_TEST_GRAMMAR:?}"
  # The two inputs of the mDNS branch are required only where that branch is
  # reached: a suite that never seals a `.local` mirror need not provide them,
  # and one that does and forgets them fails THERE, loudly, with avahi masked.
  readonly NM_CONN_DIR="${NI_INSTALLER_GENERATOR_TEST_NM_CONN_DIR:-}"
  readonly MDNS_RUN_DIR="${NI_INSTALLER_GENERATOR_TEST_MDNS_RUN_DIR:-}"
else
  readonly CMDLINE_FILE=/proc/cmdline
  # Staged by image/Containerfile.installer next to the access policy it is a
  # sibling of: one immutable /usr, one definition of the sealed grammar.
  readonly GRAMMAR_FILE=/usr/lib/neural-ice/sealed-cmdline-grammar.sh
  # The appliance's NetworkManager profiles, inherited by the installer image
  # from its base and served from the dm-verity root at generator time (the
  # overlay's tmpfs upper is still empty: nothing has run yet that could write
  # to it). `mgmt-*.nmconnection` names the management port, by the same rule
  # image/mdns/neural-ice-hostname-init.sh pins the appliance's own avahi to.
  readonly NM_CONN_DIR=/etc/NetworkManager/system-connections
  # Where the resolve-only avahi configuration is generated. Under /run, like
  # everything else this generator writes; a directory of its own because
  # /run/neural-ice-installer is created 0700 by the installer for material a
  # daemon that drops to the `avahi` user must never be able to read.
  readonly MDNS_RUN_DIR=/run/neural-ice-installer-mdns
fi

count_key() { # $1=kernel-command-line key
  awk -v prefix="$1=" 'BEGIN{n=0}{for(i=1;i<=NF;i++) if(index($i,prefix)==1)n++}END{print n+0}' \
    "$CMDLINE_FILE"
}

count_word() { # $1=exact kernel-command-line word
  awk -v wanted="$1" 'BEGIN{n=0}{for(i=1;i<=NF;i++) if($i==wanted)n++}END{print n+0}' \
    "$CMDLINE_FILE"
}

value_once() { # $1=key -> the value when the key occurs exactly once, else nothing
  (( $(count_key "$1") == 1 )) || return 0
  awk -v prefix="$1=" '{for(i=1;i<=NF;i++) if(index($i,prefix)==1) print substr($i, length(prefix)+1)}' \
    "$CMDLINE_FILE"
}

# --------------------------------------------------------------------------- #
# 🔴 THE MEDIA MARKER IS THE SEALED TRUST ANCHOR, NOT THE SELECTOR (independent
# review 2026-09-02, P1 #6).
#
# This used to recognise only the two selector keys and the two exact target
# words. A signed medium whose command line carried the eight sealed trust fields
# but a MISSING or MISSPELLED selector -- `neuralice.autoinstal=1`,
# `systemd.unit=neural-ice-instaler.target`, or the selector dropped entirely by
# a build defect -- was therefore classified as an INSTALLED APPLIANCE boot at
# the `exit 0` below, and this generator emitted no masks at all. A malformed
# signed medium fell all the way through to the inherited appliance default,
# with every login surface, every root shell and the destructive installer
# reachable. That is the one direction a fail-closed design may not fail.
#
# The marker is now every word that ONLY a signed medium can carry. The eight
# `neuralice.<trust field>` keys are rendered exclusively by
# installer_trust_render_cmdline into a UKI .cmdline; the kargs an installed
# appliance receives are written by `bootc install --karg` (rd.luks.*,
# systemd.mount-extra, neuralice.sshkey) and never include one of them. So a line
# carrying any of these is a line claiming to be signed media, and it gets the
# full mask set whether or not the grammar can go on to classify it.
#
# This list is deliberately CRUDE and self-contained: it must give the same
# answer on a command line the grammar will go on to refuse, and it must give an
# answer at all when the grammar library is unreadable. The real classification
# is the grammar's. image/test-installer-selector-grammar.sh extracts this
# function verbatim and asserts the key list covers every field in the grammar's
# own NI_SEALED_TRUST_KEYS, so the two cannot drift apart.
# --------------------------------------------------------------------------- #
readonly -a NI_MEDIA_MARKER_KEYS=(
  neuralice.autoinstall
  neuralice.live
  neuralice.trust
  neuralice.access_profile
  neuralice.hardware_target
  neuralice.payload
  neuralice.relauth_keyid
  neuralice.relauth_schema
  neuralice.rootverity
  neuralice.trust_policy_id
)
readonly -a NI_MEDIA_MARKER_WORDS=(
  systemd.unit=neural-ice-installer.target
  systemd.unit=neural-ice-live.target
)

installer_media_hint_present() {
  local key word
  for key in "${NI_MEDIA_MARKER_KEYS[@]}"; do
    (( $(count_key "$key") > 0 )) && return 0
  done
  for word in "${NI_MEDIA_MARKER_WORDS[@]}"; do
    (( $(count_word "$word") > 0 )) && return 0
  done
  return 1
}

classify() { # -> install|live on stdout; non-zero and a stderr reason otherwise
  [[ -r "$GRAMMAR_FILE" ]] || die "the sealed command-line grammar is unreadable: $GRAMMAR_FILE"
  # shellcheck source=image/installer/neural-ice-sealed-cmdline-grammar.sh
  . "$GRAMMAR_FILE"
  ni_sealed_cmdline_classify_file "$CMDLINE_FILE"
}

# --------------------------------------------------------------------------- #
# The executable preflight neural-ice-autoinstall.service runs before the
# installer. It is a SECOND opinion, not the only one: the installer script
# revalidates the same grammar itself, because a shell can invoke it directly and
# an ExecStartPre only ever guards the unit.
# --------------------------------------------------------------------------- #
if [[ "${1:-}" == --check ]]; then
  mode="$(classify)" \
    || die "the signed command line is not a grammar this medium may boot"
  [[ "$mode" == install ]] \
    || die "the signed command line selects '$mode', not the exact Install grammar"
  exit 0
fi

# No installer selector on an installed appliance: emit nothing.  This is the
# property that keeps the inherited ceremony enabled for first installed boot.
installer_media_hint_present || exit 0

(( $# >= 2 )) || die "systemd did not provide normal and early generator directories"
readonly EARLY_DIR="$2"
[[ "$EARLY_DIR" == /* ]] || die "the early generator directory is not absolute"
install -d -m 0755 "$EARLY_DIR"

# Everything here is an installed-appliance lifecycle, a listener/session
# surface, an OTA path, or a root-capable extension mechanism. Masking the login
# surfaces is also what stops a Live boot inheriting the debug image's tty1/
# serial autologin: Live gets no console login of its own, by design.
readonly -a MASKED_UNITS=(
  neural-ice-firstboot-tpm-ceremony.service
  # The appliance's tty1 boot status screen: on a medium boot tty1 belongs to
  # the installer / Live diagnostics, and the screen would redraw over them.
  neural-ice-status-screen.service
  neural-ice-firstboot-sshkey.service
  neural-ice-firstboot-sshkey-activate.service
  neural-ice-payload-apply.service
  neural-ice-hostname-init.service
  neural-ice-dhcp-retry.service
  neural-ice-device-root.service
  nvidia-device-nodes.service
  nvidia-cdi-generate.service
  avahi-daemon.service
  avahi-daemon.socket
  sshd.service
  sshd.socket
  sshd@.service
  getty@.service
  serial-getty@.service
  autovt@.service
  console-getty.service
  container-getty@.service
  getty.target
  systemd-user-sessions.service
  user@.service
  bootc-fetch-apply-updates.service
  bootc-fetch-apply-updates.timer
  neural-ice-sovereignty-egress.service
  neural-ice-sovereignty-egress.timer
  systemd-sysext.service
  systemd-confext.service
)

# 🔴 THE ROOT SHELLS. `systemd.debug_shell` is handled by systemd-debug-generator,
# which writes into the NORMAL generator directory; this generator writes into
# the EARLY one, which systemd ranks higher, so masking the unit here defeats the
# `Wants=` that generator adds. `emergency` / `rescue` / `single` reach the same
# place through the manager itself.
#
# The sealed grammar already refuses every one of those words, so nothing on a
# correctly produced medium depends on this list. It exists because the grammar
# is a statement about a FILE and this is a statement about the RUNNING MANAGER:
# a systemd release that grows a new way to reach `debug-shell.service` finds the
# unit masked, and a signing or build error that let one word through finds
# nothing to activate.
#
# 🔴 THERE IS NO LONGER AN INSTALL EXCEPTION (independent review 2026-09-02,
# P0 #1). Until now this list was UNMASKED again on an Install boot, because
# neural-ice-autoinstall.service carried `OnFailure=emergency.target` and needed
# that sink to be reachable. The justification was that "an operator who has
# already authorised a full-disk wipe is not protected by taking their failure
# diagnostics away" -- and it was wrong. Authorising a wipe of ONE disk is not
# authorising a root shell on the console: from that shell the machine's OTHER
# disks, its TPM, its network and every signed artefact on the medium are one
# command away, and none of them was part of what was authorised. Any preflight,
# authorisation, pull, storage, TPM or deployment failure reached it.
#
# The sink is now neural-ice-installer-failure.target: fixed evidence, no input,
# no shell, and an automatic poweroff on a delay the signed /usr states. So these
# five stay masked in BOTH modes, and this generator no longer takes any of them
# back off the list on any boot at all.
readonly -a DEBUG_SURFACES=(
  debug-shell.service
  emergency.service
  emergency.target
  rescue.service
  rescue.target
)

# Live boots the same image the Install medium carries, so the destructive
# installer is PRESENT on it -- enabled, and one `systemctl isolate` away. It is
# only unreachable because nothing Live requires it, and "nothing requires it
# today" is not a boundary.
readonly -a INSTALL_PATH_UNITS=(
  neural-ice-installer.target
  neural-ice-autoinstall.service
  neural-ice-installer-failure.target
  neural-ice-installer-failure.service
)

# The general boot targets. Masking them is what turns a selector this generator
# does not recognise into a boot that reaches nothing at all, instead of an
# inherited appliance boot.
readonly -a FALLBACK_TARGETS=(
  default.target
  multi-user.target
  graphical.target
)

readonly -a LIVE_PATH_UNITS=(
  neural-ice-live.target
  neural-ice-live-diagnostics.service
)

# 🔴 THE CEREMONY DROP-IN, NEUTRALISED FOR MEDIA BOOTS ONLY (review 2026-09-02,
# P1 #3). The appliance image drops
# `Requires=neural-ice-firstboot-tpm-ceremony.service` into the five network
# units, and this generator masks that ceremony -- so on a medium boot a
# NetworkManager start transaction failed on a masked required dependency and a
# registry-backed install had no reachable network path at all. Not masking
# NetworkManager was never enough: the edge that broke it is an inherited
# drop-in, not a mask.
#
# A drop-in is neutralised by SHADOWING IT BY NAME from a higher-precedence unit
# directory. /run/systemd/generator.early outranks /usr/lib/systemd/system
# (systemd.unit(5)), so a file of the same name replaces the appliance's
# entirely. This cannot weaken the INSTALLED appliance: this generator emits
# nothing at all on a boot with no media selector, and everything it writes lives
# under /run.
readonly CEREMONY_DROPIN=50-neural-ice-tpm-ceremony.conf
readonly -a CEREMONY_GATED_UNITS=(
  NetworkManager.service
  NetworkManager-wait-online.service
  network-pre.target
  network.target
  network-online.target
)

mask_units() {
  local unit
  for unit in "$@"; do
    ln -sfn /dev/null "$EARLY_DIR/$unit"
  done
}

# Take back a mask this generator itself placed one moment ago, and only that:
# the guard is what keeps an unmask from becoming a way to delete something else
# if this list and the mask list ever stop agreeing.
unmask_units() {
  local unit target
  for unit in "$@"; do
    target="$EARLY_DIR/$unit"
    [[ -L "$target" && "$(readlink -- "$target")" == /dev/null ]] || continue
    unlink "$target"
  done
}

# --------------------------------------------------------------------------- #
# 🔴 A REGISTRY INSTALL MUST ACTUALLY REQUEST NETWORKING (independent review
# 2026-09-02, P1 #1).
#
# Shadowing the appliance's ceremony drop-in made NetworkManager's start
# transaction RESOLVABLE, and the suite proved that much -- but nothing on a
# medium boot ever asked for it. Neither neural-ice-installer.target nor
# neural-ice-autoinstall.service carried a Wants=/After= edge to it, so a
# registry-backed install reached `podman pull` with no configured network and
# failed on a bench, having already been authorised to wipe a disk.
#
# The edge is emitted HERE, into /run, and ONLY for the exact sealed grammar that
# needs it: `neuralice.source=registry`. A medium install is air-gapped by
# design and gets no network edge at all -- adding one unconditionally would make
# every air-gapped install wait on a link that is deliberately absent.
#
# `network-online.target` is the ordering edge that means "addresses are
# configured", not merely "NetworkManager has been told to start"; both are
# requested, because a pull needs the former and the manager needs the latter to
# reach it.
# --------------------------------------------------------------------------- #
readonly REGISTRY_NETWORK_DROPIN=10-neural-ice-registry-network.conf
readonly REGISTRY_SOURCE_WORD='neuralice.source=registry'

request_registry_network() {
  install -d -m 0755 "$EARLY_DIR/neural-ice-autoinstall.service.d"
  cat > "$EARLY_DIR/neural-ice-autoinstall.service.d/$REGISTRY_NETWORK_DROPIN" <<'DROPIN'
# Neural ICE installer medium, generated into /run only.
#
# This boot's SIGNED command line carries `neuralice.source=registry`, so the
# install pulls the appliance image over the network. Without these two edges the
# installer reached `podman pull` with nothing having configured a link -- the
# medium's own generator shadowed the appliance ceremony drop-in that would have
# blocked NetworkManager, but nothing ever requested NetworkManager itself.
#
# Wants=, not Requires=: a link that does not come up must produce the
# installer's own bounded refusal with the target disk untouched, not a systemd
# dependency failure before the installer has said anything.
#
# A medium-source install seals no such word and gets no such drop-in: it is
# air-gapped by design, and waiting on an absent link would be a defect.
[Unit]
Wants=NetworkManager.service network-online.target
After=NetworkManager.service network-online.target
DROPIN
}

# --------------------------------------------------------------------------- #
# 🔴 A MIRROR SEALED BY `.local` NAME MUST BE RESOLVABLE, AND ONLY RESOLVABLE
# (FAB-0057 P1.1c, Owner decision 2026-09-09: media seal the LAN mirror by NAME,
# `registry.neural-ice.local:5055`, and the bench announces that name in mDNS).
#
# WHAT THIS CLOSES. Measured 2026-09-09: the bench LAN's DNS answers NXDOMAIN for
# the name, this generator masks avahi on every medium boot, and the installer
# image carries no NSS module for mDNS at all -- so the READY fetch and the seed
# pack fetch died on name resolution, and a medium sealed by IP had to be cut
# for the day's hardware test. Neither systemd-resolved (not in the image: the
# local systemd rebuild ships systemd/-libs/-pam/-udev only) nor nss-mdns (the
# .67 journal: "No NSS support for mDNS detected") was available to fix it.
#
# THE DESIGN (variant A of the brief). image/Containerfile.installer adds
# nss-mdns to the INSTALLER image only and routes `.local` names through
# `mdns4_minimal`, which talks to avahi over its unix socket. This generator
# takes avahi's two units back off the mask list, shadows the appliance ceremony
# drop-in on them exactly as it does for NetworkManager, and starts the daemon
# on a configuration IT writes under /run: `disable-publishing=yes` (no record
# of any kind, not even the host's address), no HINFO, no workstation, no IPv6,
# no D-Bus, no reflector, pinned to the management port. The installer image
# never ANNOUNCES anything on a customer's LAN: it only asks one question.
#
# THE CONDITION is read off the sealed command line -- exactly one
# `neuralice.mirror=` whose host ends in `.local` -- on a line the grammar has
# already accepted as the exact Install grammar with `neuralice.source=registry`.
# An IP or a non-`.local` name changes nothing: avahi stays masked, nothing is
# written. The installer restates the condition against the same karg and
# PROVES the resolution (getent under a timeout) before the READY fetch and
# before the first disk write; a name that does not resolve is the named refusal
# `mirror-name-unresolvable`, with the target disk untouched.
#
# The installed system is not touched by any of this: the installer image is a
# derivation the appliance never inherits from, and nothing here outlives /run.
# --------------------------------------------------------------------------- #
readonly MIRROR_MDNS_DROPIN=20-neural-ice-mirror-mdns-resolve.conf
readonly AVAHI_RESOLVE_ONLY_DROPIN=10-neural-ice-mirror-mdns-resolve-only.conf
readonly -a MDNS_RESOLVER_UNITS=(
  avahi-daemon.socket
  avahi-daemon.service
)

mirror_host_is_mdns_name() { # $1=host[:port] -> 0 when the host is a `.local` mDNS name
  local host=${1%%:*}
  # The grammar has already bounded the value to lowercase labels; this is the
  # `.local` suffix test and nothing looser, so `foo.local.example` is not it.
  [[ "$host" =~ ^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+local$ ]]
}

management_interfaces() { # -> comma-joined interface names of mgmt-*.nmconnection, or 1
  local profile name
  local -a names=()
  shopt -s nullglob
  for profile in "$NM_CONN_DIR"/mgmt-*.nmconnection; do
    name="$(sed -n 's/^interface-name=//p' "$profile" | head -1)"
    [[ "$name" =~ ^[A-Za-z0-9_.-]{1,15}$ ]] || continue
    names+=("$name")
  done
  shopt -u nullglob
  (( ${#names[@]} > 0 )) || return 1
  local IFS=,
  printf '%s' "${names[*]}"
}

request_mirror_mdns_resolution() { # $1=sealed mirror host[:port]
  local mirror=$1 interfaces
  [[ -n "$NM_CONN_DIR" && -n "$MDNS_RUN_DIR" ]] \
    || die "the sealed mirror ${mirror} is an mDNS name but the resolver inputs are unset (test overrides missing); avahi stays masked"
  interfaces="$(management_interfaces)" \
    || die "the sealed mirror ${mirror} is an mDNS name but no mgmt-*.nmconnection profile names a management port to resolve it on; avahi stays masked"
  install -d -m 0755 "$MDNS_RUN_DIR"
  # Every value below is a directive avahi-daemon.conf(5) documents. The daemon
  # reads this file as root before dropping to `avahi`; it holds no secret.
  cat > "$MDNS_RUN_DIR/avahi-daemon.conf" <<CONF
# Neural ICE installer medium, generated into /run only.
#
# RESOLUTION ONLY. This boot's SIGNED command line seals the LAN mirror as the
# mDNS name ${mirror}; nss-mdns asks this daemon for it and nothing else.
# Publishing is disabled outright, so the medium announces no record of any
# kind on the LAN -- not a host name, not an address, not a service.
[server]
use-ipv4=yes
use-ipv6=no
enable-dbus=no
allow-interfaces=${interfaces}
disallow-other-stacks=no
ratelimit-interval-usec=1000000
ratelimit-burst=1000

[wide-area]
enable-wide-area=no

[publish]
disable-publishing=yes
disable-user-service-publishing=yes
publish-addresses=no
publish-hinfo=no
publish-workstation=no
publish-domain=no
publish-aaaa-on-ipv4=no
publish-a-on-ipv6=no

[reflector]
enable-reflector=no

[rlimits]
rlimit-nproc=3
CONF
  chmod 0644 "$MDNS_RUN_DIR/avahi-daemon.conf"
  # The appliance's ceremony drop-in sits on both avahi units too
  # (image/Containerfile.bootc); unmasked but not shadowed, they would fail their
  # start transaction on the masked ceremony exactly as NetworkManager did.
  neutralise_ceremony_dropin "${MDNS_RESOLVER_UNITS[@]}"
  install -d -m 0755 "$EARLY_DIR/avahi-daemon.service.d"
  cat > "$EARLY_DIR/avahi-daemon.service.d/$AVAHI_RESOLVE_ONLY_DROPIN" <<DROPIN
# Neural ICE installer medium, generated into /run only.
#
# The vendor unit starts avahi on /etc/avahi/avahi-daemon.conf, which publishes
# this host's address record: that is the appliance's job, never a medium's.
# ExecStart= is reset and pointed at the resolve-only configuration this
# generator wrote; Type=dbus is replaced because that configuration turns the
# D-Bus interface off (nss-mdns uses the unix socket, not the bus).
[Service]
Type=simple
BusName=
ExecStart=
ExecStart=/usr/sbin/avahi-daemon --syslog --file=${MDNS_RUN_DIR}/avahi-daemon.conf
ExecReload=
DROPIN
  # ...and the installer asks for it, on this boot only.
  install -d -m 0755 "$EARLY_DIR/neural-ice-autoinstall.service.d"
  cat > "$EARLY_DIR/neural-ice-autoinstall.service.d/$MIRROR_MDNS_DROPIN" <<DROPIN
# Neural ICE installer medium, generated into /run only.
#
# This boot's SIGNED command line seals a LAN mirror by mDNS name, so the
# installer needs a resolver for it before its READY fetch. Wants=, not
# Requires=: a resolver that fails to start must produce the installer's own
# named refusal (mirror-name-unresolvable) with the target disk untouched, not
# a systemd dependency failure before the installer has said anything.
[Unit]
Wants=avahi-daemon.socket avahi-daemon.service
After=avahi-daemon.socket avahi-daemon.service
DROPIN
  # Last, and only now that everything the units need is in place: take the two
  # masks this generator placed back off, and nothing else.
  unmask_units "${MDNS_RESOLVER_UNITS[@]}"
}

neutralise_ceremony_dropin() {
  local unit
  for unit in "$@"; do
    install -d -m 0755 "$EARLY_DIR/$unit.d"
    cat > "$EARLY_DIR/$unit.d/$CEREMONY_DROPIN" <<'DROPIN'
# Neural ICE installer medium, generated into /run only.
#
# Shadows the INSTALLED appliance's drop-in of the same name. That file adds
# `Requires=neural-ice-firstboot-tpm-ceremony.service`, and this generator masks
# that ceremony on every medium boot -- so without this shadow a registry-backed
# install could not start networking at all: the start transaction failed on a
# masked required dependency, whether or not NetworkManager itself was masked.
#
# The installed appliance is untouched: no media selector means this generator
# emits nothing, and nothing it emits outlives /run.
DROPIN
  done
}

# --------------------------------------------------------------------------- #
# 1) MASK EVERYTHING. Nothing below may run before this point.
# --------------------------------------------------------------------------- #
mask_units "${MASKED_UNITS[@]}" "${DEBUG_SURFACES[@]}" "${INSTALL_PATH_UNITS[@]}" \
  "${FALLBACK_TARGETS[@]}" "${LIVE_PATH_UNITS[@]}"
neutralise_ceremony_dropin "${CEREMONY_GATED_UNITS[@]}"

# --------------------------------------------------------------------------- #
# 2) CLASSIFY, and take back only what the recognised grammar allows. Install and
#    Live are two exact signed grammars with no unsigned default between them: a
#    partial, duplicated, mixed or embellished selector is neither, and keeps
#    every mask above.
# --------------------------------------------------------------------------- #
MODE="$(classify)" \
  || die "the signed command line is neither the exact Install nor the exact Live grammar"

case "$MODE" in
  install)
    # The failure sink is part of the Install path and is unmasked with it. The
    # DEBUG_SURFACES are deliberately NOT in this call: an Install boot reaches
    # neural-ice-installer-failure.target when it fails, and nothing else.
    unmask_units "${INSTALL_PATH_UNITS[@]}"
    # ...and only a REGISTRY install asks for a network. The word is read back
    # off the same command line the grammar has just accepted, so this cannot
    # fire on a line the grammar refused.
    if (( $(count_word "$REGISTRY_SOURCE_WORD") == 1 )); then
      request_registry_network
      # ...and only a mirror sealed by `.local` NAME gets a resolver for it. The
      # value is read back off the accepted line, exactly once or not at all.
      sealed_mirror="$(value_once neuralice.mirror)"
      if [[ -n "$sealed_mirror" ]] && mirror_host_is_mdns_name "$sealed_mirror"; then
        request_mirror_mdns_resolution "$sealed_mirror"
      fi
    fi
    ;;
  live)
    unmask_units "${LIVE_PATH_UNITS[@]}"
    ;;
  *)
    die "the sealed grammar reader returned an unknown mode: $MODE"
    ;;
esac
