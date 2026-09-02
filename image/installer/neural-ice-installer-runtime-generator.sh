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
else
  readonly CMDLINE_FILE=/proc/cmdline
  # Staged by image/Containerfile.installer next to the access policy it is a
  # sibling of: one immutable /usr, one definition of the sealed grammar.
  readonly GRAMMAR_FILE=/usr/lib/neural-ice/sealed-cmdline-grammar.sh
fi

count_key() { # $1=kernel-command-line key
  awk -v prefix="$1=" 'BEGIN{n=0}{for(i=1;i<=NF;i++) if(index($i,prefix)==1)n++}END{print n+0}' \
    "$CMDLINE_FILE"
}

count_word() { # $1=exact kernel-command-line word
  awk -v wanted="$1" 'BEGIN{n=0}{for(i=1;i<=NF;i++) if($i==wanted)n++}END{print n+0}' \
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
    fi
    ;;
  live)
    unmask_units "${LIVE_PATH_UNITS[@]}"
    ;;
  *)
    die "the sealed grammar reader returned an unknown mode: $MODE"
    ;;
esac
