#!/usr/bin/env bash
# shellcheck shell=bash
#
# THE SEALED MEDIA COMMAND-LINE GRAMMAR — a CLOSED WORLD, not a blocklist.
#
# 🔴 WHAT THIS REPLACES (independent review 2026-09-02, P1 #1). The previous
# checks validated three WORDS -- `neuralice.autoinstall`, `neuralice.live` and
# `systemd.unit` -- and said nothing about the rest of the line. A validly signed
# Live UKI carrying
#
#     systemd.unit=neural-ice-live.target neuralice.live=1 systemd.debug_shell
#
# therefore passed both the off-device inspector and the early runtime generator,
# and systemd-debug-generator then started an unauthenticated root shell on tty9.
# From that shell the destructive installer was one command away. Every other
# manager-interpreted argument was equally admissible: `init=`, `rd.break`,
# `systemd.mask=`, `systemd.wants=`, `systemd.setenv=`, `emergency`, `rescue`,
# `single`, `selinux=0`, `enforcing=0` on a Live medium, a second `systemd.unit=`.
#
# A blocklist of those words would be whack-a-mole: the kernel and systemd add
# arguments faster than any list is maintained, and one missed word is one root
# shell. So this file states the ONLY grammar a Neural ICE medium may seal, and
# everything outside it is refused -- including words that do not exist yet.
#
# WHERE IT IS ENFORCED. Three independent readers, on purpose:
#
#   producer   image/build-installer-usb.sh sources this file and validates the
#              cmdline it is about to seal, then re-reads what the UKI builder
#              actually rendered. A medium that would be refused at boot is
#              never cut.
#   runtime    image/installer/neural-ice-installer-runtime-generator sources
#              this file in early boot and classifies /proc/cmdline. It masks
#              everything first and unmasks only what the recognised grammar
#              allows, so a refusal cannot fall through.
#   installer  ota/neural-ice-autoinstall.sh sources it again and revalidates
#              before its first mutation. The service's ExecStartPre is not
#              enough: a shell can invoke the script directly.
#
# image/inspect-installer-media.py implements the same grammar a FOURTH time, in
# Python, deliberately: it is the off-device reader of a finished medium and must
# not share code with the thing it audits. image/test-installer-selector-grammar.sh
# runs both implementations over one shared corpus and fails on any disagreement.
#
# 🔴 WHAT THIS CANNOT DEFEND. Arguments consumed BEFORE the real root's
# generators run -- `rd.break`, `rd.systemd.unit=`, dracut's own options -- are
# interpreted inside the initramfs, which this grammar does not gate at runtime.
# For those, the producer and the inspector are the whole defence: an argument
# that is not in this grammar is never sealed, and a medium that carries one is
# refused by image/inspect-installer-media.py before it is ever flashed.

# --------------------------------------------------------------------------- #
# The eight sealed trust fields. Each must appear EXACTLY once. Their VALUES are
# checked by image/lib/installer-trust.sh, which is the single definition of what
# each field means; this file only owns the shape of the line as a whole.
# --------------------------------------------------------------------------- #
NI_SEALED_TRUST_KEYS=(
  neuralice.trust
  neuralice.access_profile
  neuralice.hardware_target
  neuralice.payload
  neuralice.relauth_keyid
  neuralice.relauth_schema
  neuralice.rootverity
  neuralice.trust_policy_id
)

# The two mode selectors, as exact WORDS. A mode is an affirmative pair, and the
# two pairs are mutually exclusive: a line carrying both is neither.
NI_SEALED_INSTALL_TARGET='systemd.unit=neural-ice-installer.target'
NI_SEALED_INSTALL_SELECTOR='neuralice.autoinstall=1'
NI_SEALED_LIVE_TARGET='systemd.unit=neural-ice-live.target'
NI_SEALED_LIVE_SELECTOR='neuralice.live=1'

# --------------------------------------------------------------------------- #
# 🔴 ONE CANONICAL ORIGIN, AND IT IS SEALED RATHER THAN COMPILED IN
# (independent review 2026-09-02, P0 #3).
#
# Every OS/source reference a Neural ICE medium may seal is
# `<release authority>/<repo>@sha256:<digest>`, where the release authority is
# the ONE value `neuralice.release_authority` names on the same signed command
# line. Nothing else is an origin: not a mutable tag, not a second registry, not
# a LAN host.
#
# WHAT THIS REPLACES. `neuralice.osimage` accepted ANY canonical authority, so a
# medium could be cut pinned to an arbitrary registry and the runtime would
# install it. `neuralice.imgref` was worse: it accepted a bare MUTABLE TAG, and
# the installer's compiled-in default was a GHCR tag -- so an appliance whose
# medium sealed no origin recorded a tag anyone able to move it could redirect,
# for the life of the appliance.
#
# 🔴 AND THE AUTHORITY IS AN ARGUMENT, NOT A LITERAL IN THIS TREE. ICE-CoreOS is
# open core: ci/test-open-core-boundary.sh refuses the sovereign endpoint's bytes
# in every Git-visible file, and it is right to -- an open repository that names
# the production registry has published it. So the authority arrives on the
# signed command line, the producer supplies it from outside this tree, and this
# grammar enforces that every origin reference on the line uses exactly that one.
# `tools/ni-ota-verify`'s `--registry-host` is the same decision, already made.
#
# 🔴 THE MIRROR IS TRANSPORT, NEVER ORIGIN. `neuralice.mirror` names a
# lab-managed host that may SERVE those bytes; the reference above is unchanged,
# the pull is digest-only, and the mirror must additionally carry a pinned CA
# digest and the exact READY closure hash it claims to hold. It may not be the
# release authority itself, and a `customer-locked` medium may not name one at
# all -- see the contract in section 4.

# Hard bounds. A sealed cmdline is produced by one function with a fixed key
# order; anything appreciably longer or wider than that is not a medium this
# repository cut, and an unbounded loop over attacker-chosen words is a cost.
NI_SEALED_CMDLINE_MAX_BYTES=4096
NI_SEALED_CMDLINE_MAX_WORDS=64

# The reason the last classification failed. Callers print it; the tests assert
# on it, so refusals have a stable vocabulary rather than a prose message.
# shellcheck disable=SC2034 # read by whoever sources this file, in their shell
NI_SEALED_CMDLINE_REASON=''

# The reason is BOTH a variable and a stderr line. The variable serves a caller
# in the same shell; the line serves every caller that runs the classifier in a
# command substitution -- which is all three of them, and where a variable
# assignment made inside the subshell would be lost. A refusal that cannot say
# why is a refusal an operator reports as "it does not boot".
_ni_sealed_refuse() {
  NI_SEALED_CMDLINE_REASON="$1"
  printf 'neural-ice-sealed-cmdline: refused: %s\n' "$1" >&2
  return 1
}

# --------------------------------------------------------------------------- #
# Value shapes. Each mirrors the validation the consumer of that argument already
# performs, so the grammar cannot admit a value the installer would then die on
# -- and cannot admit one the installer would ACCEPT but a reviewer would not.
# --------------------------------------------------------------------------- #

# A registry authority: bracketed IPv6 literal, dotted-quad IPv4, `localhost`,
# or a DNS name with at least two labels. Optional port, 1-65535. This is the
# bash counterpart of the parser in ota/neural-ice-autoinstall.sh; the corpus
# test proves the two agree.
ni_sealed_authority_is_valid() { # $1=authority
  local authority=$1 host='' port='' rest label
  if [[ "$authority" == \[* ]]; then
    rest="${authority#\[}"
    [[ "$rest" == *\]* ]] || return 1
    host="${rest%%\]*}"
    rest="${rest#*\]}"
    # Canonical compressed IPv6 is lowercase hex and colons, and carries at
    # least one colon. A non-canonical spelling is refused rather than
    # normalised: two readers of one medium must not disagree about its host.
    [[ "$host" =~ ^[0-9a-f:]{2,45}$ && "$host" == *:* ]] || return 1
    [[ "$host" != *:::* ]] || return 1
    if [[ -n "$rest" ]]; then
      [[ "$rest" == :* ]] || return 1
      port="${rest#:}"
    fi
  else
    host="$authority"
    if [[ "$authority" == *:* ]]; then
      # Exactly one colon, or it is not a host:port at all.
      [[ "${authority//[^:]/}" == ':' ]] || return 1
      host="${authority%:*}"
      port="${authority##*:}"
      [[ -n "$port" ]] || return 1
    fi
    if [[ "$host" =~ ^[0-9.]+$ ]]; then
      # Dotted quad, no leading zeros, every octet 0-255.
      [[ "$host" =~ ^([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])){3}$ ]] || return 1
    elif [[ "$host" != localhost ]]; then
      (( ${#host} <= 253 )) || return 1
      [[ "$host" == *.* ]] || return 1
      local IFS=.
      # shellcheck disable=SC2206 # deliberate word split on '.'
      local labels=($host)
      (( ${#labels[@]} >= 2 )) || return 1
      for label in "${labels[@]}"; do
        [[ "$label" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] || return 1
      done
    fi
  fi
  if [[ -n "$port" ]]; then
    [[ "$port" =~ ^[1-9][0-9]{0,4}$ ]] || return 1
    (( port <= 65535 )) || return 1
  fi
  return 0
}

# A digest-pinned appliance image. A MUTABLE TAG IS REFUSED: the digest is what
# makes a LAN mirror safe to consult at all, so accepting a tag here would
# quietly undo the property the mirror depends on.
#
# WHOSE registry it is, is a question about the LINE rather than about this
# value, and it is answered in section 4 against `neuralice.release_authority`.
ni_sealed_osimage_is_valid() { # $1=value
  local value=$1 repository authority path segment='[a-z0-9]+([._-][a-z0-9]+)*'
  [[ "$value" =~ ^(.+)@sha256:[0-9a-f]{64}$ ]] || return 1
  repository="${value%@sha256:*}"
  [[ "$repository" == */* ]] || return 1
  authority="${repository%%/*}"
  path="${repository#*/}"
  [[ "$path" =~ ^${segment}(/${segment})*$ ]] || return 1
  ni_sealed_authority_is_valid "$authority"
}

# The authority of a digest-pinned reference this grammar has already accepted.
ni_sealed_reference_authority() { # $1=value
  local repository=${1%@sha256:*}
  printf '%s' "${repository%%/*}"
}

# THE RELEASE AUTHORITY ITSELF. A DNS name with at least two labels: an origin is
# a name a certificate can be issued for and a signature scope can be written
# against, which an IP literal and `localhost` are not.
ni_sealed_release_authority_is_valid() { # $1=value
  local value=$1 host=${1%%:*}
  ni_sealed_authority_is_valid "$value" || return 1
  [[ "$host" != \[* ]] || return 1
  [[ "$host" != localhost ]] || return 1
  [[ ! "$host" =~ ^[0-9.]+$ ]] || return 1
  [[ "$host" == *.* ]]
}

ni_sealed_value_is_valid() { # $1=key  $2=value
  local key=$1 value=$2
  case "$key" in
    neuralice.imgref)
      # The OTA ORIGIN recorded on the installed appliance and followed by every
      # later `bootc upgrade`. It is held to exactly the same rule as the image
      # this medium installs: canonical authority, digest-pinned, no tag. A
      # mutable tag here is an appliance whose future is decided by whoever can
      # move that tag.
      ni_sealed_osimage_is_valid "$value"
      ;;
    neuralice.source)
      [[ "$value" == medium || "$value" == registry ]]
      ;;
    neuralice.device_channel)
      [[ "$value" == lab || "$value" == beta || "$value" == stable ]]
      ;;
    neuralice.osimage)
      ni_sealed_osimage_is_valid "$value"
      ;;
    neuralice.mirror)
      # A bare host[:port]. This value is interpolated into TOML at install
      # time: a scheme, a path or a quote would smuggle a second directive in.
      # Whether it is the release authority -- which a mirror may never be, a
      # "mirror" of the origin being the origin -- is a question about the LINE,
      # and is answered in section 4.
      [[ "$value" =~ ^[A-Za-z0-9._-]+(:[0-9]{1,5})?$ ]] || return 1
      ni_sealed_authority_is_valid "$value"
      ;;
    neuralice.release_authority)
      ni_sealed_release_authority_is_valid "$value"
      ;;
    neuralice.seed_closure|neuralice.seed_manifest)
      # 🔴 THE OFFLINE SEED'S RELEASE CLOSURE, SEALED (independent review
      # 2026-09-02, P0 #2). The seed root on the medium is a directory NAMED by
      # this hash; the installer mounts it read-only and refuses unless the
      # canonical release manifest inside it canonicalises to exactly this value.
      # Without it, a seed partition was simply trusted for carrying a partlabel.
      [[ "$value" =~ ^[0-9a-f]{64}$ ]]
      ;;
    neuralice.seed_trusted_now)
      [[ "$value" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]]
      ;;
    neuralice.relauth_sha256|neuralice.relauth_sig_sha256|neuralice.mirror_ca_sha256|neuralice.mirror_ready|neuralice.mirror_manifest|neuralice.pcr_policy|neuralice.pcr_policy_key|neuralice.pcr_policy_signature)
      # SHA-256 of an artefact the producer staged on the ESP, or of the exact
      # release closure a mirror declares READY. Sealed into the UKI so the
      # mutable ESP cannot decide any of them.
      [[ "$value" =~ ^[0-9a-f]{64}$ ]]
      ;;
    neuralice.systemsize)
      [[ "$value" =~ ^[0-9]{1,5}$ ]] || return 1
      (( value >= 16 && value <= 65536 ))
      ;;
    neuralice.mirror_generation|neuralice.pcr_policy_seq)
      [[ "$value" =~ ^[1-9][0-9]{0,18}$ ]]
      ;;
    neuralice.target)
      # This value selects the disk that is about to be destroyed.
      [[ "$value" =~ ^/dev/[a-zA-Z0-9]+[a-zA-Z0-9_-]*$ ]]
      ;;
    neuralice.sshkey)
      [[ "$value" =~ ^[A-Za-z0-9+/=]{1,1024}$ ]]
      ;;
    *)
      return 1
      ;;
  esac
}

# The optional keyed arguments each mode admits, each AT MOST once. `enforcing=0`
# is Install-only and is an exact word, not a key: SELinux is left permissive
# only because `bootc install` relabels the target, which a Live boot never does.
_ni_sealed_install_optional_keys=(
  neuralice.release_authority
  neuralice.device_channel
  neuralice.imgref neuralice.source neuralice.osimage neuralice.mirror
  neuralice.systemsize neuralice.target neuralice.sshkey
  neuralice.relauth_sha256 neuralice.relauth_sig_sha256
  neuralice.mirror_ca_sha256 neuralice.mirror_ready neuralice.mirror_manifest
  neuralice.mirror_generation
  neuralice.seed_closure neuralice.seed_manifest neuralice.seed_trusted_now
  neuralice.pcr_policy neuralice.pcr_policy_key neuralice.pcr_policy_signature neuralice.pcr_policy_seq
)

_ni_sealed_contains() { # $1=needle $2..=haystack
  local needle=$1 item
  shift
  for item in "$@"; do
    [[ "$item" == "$needle" ]] && return 0
  done
  return 1
}

# --------------------------------------------------------------------------- #
# ni_sealed_cmdline_classify <cmdline>
#
# Prints `install` or `live` on success. On refusal it prints nothing, sets
# NI_SEALED_CMDLINE_REASON to a stable machine-readable token and returns 1.
#
# The refusal vocabulary is part of the contract: image/test-installer-selector-
# grammar.sh asserts the exact token for every hostile mutation, so a future edit
# cannot turn a specific refusal into a generic one and still look green.
# --------------------------------------------------------------------------- #
ni_sealed_cmdline_classify() { # $1=cmdline string
  # shellcheck disable=SC2034 # read by whoever sources this file, in their shell
  NI_SEALED_CMDLINE_REASON=''
  local cmdline=$1
  (( ${#cmdline} <= NI_SEALED_CMDLINE_MAX_BYTES )) \
    || _ni_sealed_refuse cmdline-too-long || return 1

  # Default field splitting IS kernel-command-line splitting. Quoted values are
  # deliberately NOT supported: the renderer cannot produce one, so a line that
  # needs quoting is not a line this repository sealed.
  local -a words
  read -r -a words <<<"$cmdline"
  (( ${#words[@]} >= 1 )) || _ni_sealed_refuse empty-cmdline || return 1
  (( ${#words[@]} <= NI_SEALED_CMDLINE_MAX_WORDS )) \
    || _ni_sealed_refuse too-many-words || return 1

  local word key value
  local -A seen=()
  for word in "${words[@]}"; do
    # The renderer's own character class. Anything outside it cannot have come
    # from installer_trust_render_cmdline, so it did not come from a build.
    [[ "$word" =~ ^[A-Za-z0-9._:=,/@+-]+$ ]] \
      || _ni_sealed_refuse unrepresentable-word || return 1
    if [[ "$word" == *=* ]]; then
      key="${word%%=*}"
    else
      key="$word"
    fi
    [[ -n "$key" ]] || _ni_sealed_refuse unrepresentable-word || return 1
    seen["$key"]=$(( ${seen["$key"]:-0} + 1 ))
  done

  # 1) The trust anchor. Exactly one of each, always, in both modes.
  for key in "${NI_SEALED_TRUST_KEYS[@]}"; do
    case "${seen[$key]:-0}" in
      1) ;;
      0) _ni_sealed_refuse "missing-sealed-field:$key" ; return 1 ;;
      *) _ni_sealed_refuse "duplicate-sealed-field:$key"; return 1 ;;
    esac
  done

  # 2) The mode. Exactly one systemd.unit=, naming exactly one of the two signed
  #    targets, paired with exactly one matching affirmative selector -- and the
  #    other mode's selector entirely absent.
  (( ${seen[systemd.unit]:-0} == 1 )) \
    || _ni_sealed_refuse ambiguous-boot-target || return 1
  (( ${seen[neuralice.autoinstall]:-0} <= 1 )) \
    || _ni_sealed_refuse duplicate-mode-selector || return 1
  (( ${seen[neuralice.live]:-0} <= 1 )) \
    || _ni_sealed_refuse duplicate-mode-selector || return 1

  local mode=''
  if _ni_sealed_contains "$NI_SEALED_INSTALL_TARGET" "${words[@]}"; then
    mode=install
  elif _ni_sealed_contains "$NI_SEALED_LIVE_TARGET" "${words[@]}"; then
    mode=live
  else
    _ni_sealed_refuse unknown-boot-target
    return 1
  fi

  if [[ "$mode" == install ]]; then
    _ni_sealed_contains "$NI_SEALED_INSTALL_SELECTOR" "${words[@]}" \
      || _ni_sealed_refuse missing-mode-selector || return 1
    (( ${seen[neuralice.live]:-0} == 0 )) \
      || _ni_sealed_refuse mixed-mode-selector || return 1
  else
    _ni_sealed_contains "$NI_SEALED_LIVE_SELECTOR" "${words[@]}" \
      || _ni_sealed_refuse missing-mode-selector || return 1
    (( ${seen[neuralice.autoinstall]:-0} == 0 )) \
      || _ni_sealed_refuse mixed-mode-selector || return 1
  fi

  # 3) THE CLOSED WORLD. Every remaining word must be one this grammar names.
  #    `systemd.debug_shell`, `init=`, `rd.break`, `systemd.mask=`,
  #    `systemd.wants=`, `emergency`, `rescue`, `single`, `selinux=0` and every
  #    argument invented after this file was written all land here.
  local -A optional_seen=()
  for word in "${words[@]}"; do
    if [[ "$word" == *=* ]]; then
      key="${word%%=*}"; value="${word#*=}"
    else
      key="$word"; value=''
    fi
    if _ni_sealed_contains "$key" "${NI_SEALED_TRUST_KEYS[@]}"; then
      continue
    fi
    case "$word" in
      quiet)
        (( ${seen[quiet]:-0} == 1 )) || { _ni_sealed_refuse duplicate-word; return 1; }
        continue
        ;;
      rd.systemd.gpt_auto=0)
        # The signed initramfs mounts its own dm-verity-backed overlay at
        # /sysroot. systemd-gpt-auto must not race it or wait for a second root.
        (( ${seen[rd.systemd.gpt_auto]:-0} == 1 )) \
          || { _ni_sealed_refuse duplicate-word; return 1; }
        continue
        ;;
      luks=0)
        # The verified root is also the appliance image being installed. Its
        # /etc/crypttab belongs to the future target, not to this live boot:
        # reacting to freshly-created *-luks labels would race the installer.
        (( ${seen[luks]:-0} == 1 )) \
          || { _ni_sealed_refuse duplicate-word; return 1; }
        continue
        ;;
      "$NI_SEALED_INSTALL_TARGET"|"$NI_SEALED_LIVE_TARGET")
        continue
        ;;
      "$NI_SEALED_INSTALL_SELECTOR")
        [[ "$mode" == install ]] || { _ni_sealed_refuse mixed-mode-selector; return 1; }
        continue
        ;;
      "$NI_SEALED_LIVE_SELECTOR")
        [[ "$mode" == live ]] || { _ni_sealed_refuse mixed-mode-selector; return 1; }
        continue
        ;;
      enforcing=0)
        # Install only, and only because `bootc install` relabels the target and
        # the enforcing live policy denies it. A Live boot relabels nothing, so
        # a Live medium sealing it is a medium asking for something it cannot use.
        [[ "$mode" == install ]] || { _ni_sealed_refuse word-not-permitted-in-mode; return 1; }
        (( ${seen[enforcing]:-0} == 1 )) || { _ni_sealed_refuse duplicate-word; return 1; }
        continue
        ;;
    esac
    # A keyed optional argument, Install only.
    if [[ "$word" == *=* ]] \
      && _ni_sealed_contains "$key" "${_ni_sealed_install_optional_keys[@]}"; then
      [[ "$mode" == install ]] || { _ni_sealed_refuse word-not-permitted-in-mode; return 1; }
      (( ${seen[$key]:-0} == 1 )) || { _ni_sealed_refuse "duplicate-argument:$key"; return 1; }
      [[ -z "${optional_seen[$key]:-}" ]] || { _ni_sealed_refuse "duplicate-argument:$key"; return 1; }
      optional_seen["$key"]=1
      ni_sealed_value_is_valid "$key" "$value" \
        || { _ni_sealed_refuse "invalid-argument:$key"; return 1; }
      continue
    fi
    _ni_sealed_refuse "word-not-in-grammar:$key"
    return 1
  done

  # Every destructive Install medium carries one complete signed-PCR policy
  # generation. Live media may omit it because they never enroll or unlock a
  # target volume. Keeping these four fields mandatory as a group prevents an
  # Install UKI that is correctly signed yet can only discover its missing
  # recovery contract after selecting a target.
  if [[ "$mode" == install ]]; then
    local policy_key
    for policy_key in neuralice.pcr_policy neuralice.pcr_policy_key \
      neuralice.pcr_policy_signature neuralice.pcr_policy_seq; do
      [[ -n "${optional_seen[$policy_key]:-}" ]] \
        || { _ni_sealed_refuse "missing-install-pcr-policy:$policy_key"; return 1; }
    done
  fi

  # ------------------------------------------------------------------------- #
  # 4) THE REGISTRY-INSTALL CONTRACT, stated once so producer, generator and
  #    installer cannot disagree about which combinations are meaningful.
  #
  # 🔴 EVERY RULE HERE IS A COMBINATION, NOT A VALUE (independent review
  # 2026-09-02, P0 #3). A well-shaped value in the wrong company is how a
  # registry medium was cut that deterministically refused at runtime: the
  # installer required a signed release authorization on the ESP and the
  # producer had no reason to stage one, because nothing in the sealed line said
  # a registry install needed it.
  # ------------------------------------------------------------------------- #
  # ------------------------------------------------------------------------- #
  # 🔴 ONE ORIGIN, NAMED ON THE LINE. Every reference that decides WHICH BYTES an
  # appliance runs -- the image this medium installs and the OTA origin it
  # records -- must carry the authority `neuralice.release_authority` names, and
  # a line that carries such a reference must name one.
  # ------------------------------------------------------------------------- #
  local release_authority=''
  if [[ -n "${optional_seen[neuralice.release_authority]:-}" ]]; then
    release_authority="$(ni_sealed_argument_value neuralice.release_authority "${words[@]}")"
  fi
  local origin_key
  for origin_key in neuralice.imgref neuralice.osimage; do
    [[ -n "${optional_seen[$origin_key]:-}" ]] || continue
    [[ -n "$release_authority" ]] \
      || { _ni_sealed_refuse "origin-without-release-authority:$origin_key"; return 1; }
    local origin_value
    origin_value="$(ni_sealed_argument_value "$origin_key" "${words[@]}")"
    [[ "$(ni_sealed_reference_authority "$origin_value")" == "$release_authority" ]] \
      || { _ni_sealed_refuse "origin-not-the-release-authority:$origin_key"; return 1; }
  done

  local registry_source=0
  if [[ -n "${optional_seen[neuralice.source]:-}" ]]; then
    local source_value
    source_value="$(ni_sealed_argument_value neuralice.source "${words[@]}")"
    [[ "$source_value" == registry ]] && registry_source=1
  fi

  if (( registry_source == 1 )); then
    [[ -n "${optional_seen[neuralice.osimage]:-}" ]] \
      || { _ni_sealed_refuse registry-source-without-osimage; return 1; }
    # 🔴 THE AUTHORIZATION IS PART OF THE MEDIUM, NOT AN AFTERTHOUGHT. The
    # installer refuses a registry install without a Neural-ICE-signed release
    # authorization on the ESP, and the ESP is mutable -- so the two SHA-256
    # values that pin those files are sealed HERE, in the line the UKI signature
    # covers. A medium that seals a registry source and does not seal both is a
    # medium that would refuse itself on a bench with an already-wiped disk.
    [[ -n "${optional_seen[neuralice.relauth_sha256]:-}" ]] \
      || { _ni_sealed_refuse registry-source-without-release-authorization; return 1; }
    [[ -n "${optional_seen[neuralice.relauth_sig_sha256]:-}" ]] \
      || { _ni_sealed_refuse registry-source-without-release-authorization-signature; return 1; }
    # The document and its detached signature are two different objects; a line
    # that pins one hash twice pins nothing.
    [[ "$(ni_sealed_argument_value neuralice.relauth_sha256 "${words[@]}")" \
       != "$(ni_sealed_argument_value neuralice.relauth_sig_sha256 "${words[@]}")" ]] \
      || { _ni_sealed_refuse release-authorization-hashes-identical; return 1; }
  else
    [[ -z "${optional_seen[neuralice.osimage]:-}" ]] \
      || { _ni_sealed_refuse osimage-without-registry-source; return 1; }
    [[ -z "${optional_seen[neuralice.relauth_sha256]:-}" ]] \
      || { _ni_sealed_refuse release-authorization-without-registry-source; return 1; }
    [[ -z "${optional_seen[neuralice.relauth_sig_sha256]:-}" ]] \
      || { _ni_sealed_refuse release-authorization-without-registry-source; return 1; }
  fi

  # ------------------------------------------------------------------------- #
  # THE MIRROR IS LAB TRANSPORT AND NOTHING ELSE.
  #
  # A mirror is only ever consulted for a digest-pinned pull, and the signature
  # policy is still evaluated against the ORIGINAL canonical scope -- so the
  # bytes it serves are no more trusted than the digest. What that argument does
  # NOT survive is a mirror on a CUSTOMER appliance: it would put a lab host in
  # the boot path of a machine that must never depend on one, and there is no
  # digest argument that makes that acceptable. `lab-managed` media only.
  #
  # And a mirror must state WHAT IT IS: the pinned CA the installer will trust
  # for it, and the exact release-closure hash it declares READY. Both are
  # sealed here, so `.63` cannot become an authority by being reachable.
  # ------------------------------------------------------------------------- #
  local mirror_seen="${optional_seen[neuralice.mirror]:-}"
  if [[ -n "$mirror_seen" ]]; then
    (( registry_source == 1 )) \
      || { _ni_sealed_refuse mirror-without-registry-source; return 1; }
    # A "mirror" of the origin IS the origin, and the digest-only/insecure
    # transport rules the installer writes for a mirror must never be applied to
    # the authority its signature scope is written against.
    local mirror_value
    mirror_value="$(ni_sealed_argument_value neuralice.mirror "${words[@]}")"
    [[ "${mirror_value%%:*}" != "${release_authority%%:*}" ]] \
      || { _ni_sealed_refuse mirror-is-the-release-authority; return 1; }
    local sealed_profile
    sealed_profile="$(ni_sealed_argument_value neuralice.access_profile "${words[@]}")"
    [[ "$sealed_profile" == lab-managed ]] \
      || { _ni_sealed_refuse mirror-not-permitted-outside-lab-managed; return 1; }
    [[ -n "${optional_seen[neuralice.mirror_ca_sha256]:-}" ]] \
      || { _ni_sealed_refuse mirror-without-pinned-ca; return 1; }
    [[ -n "${optional_seen[neuralice.mirror_ready]:-}" ]] \
      || { _ni_sealed_refuse mirror-without-ready-closure-hash; return 1; }
    [[ -n "${optional_seen[neuralice.mirror_manifest]:-}" ]] \
      || { _ni_sealed_refuse mirror-without-ready-manifest-hash; return 1; }
    [[ -n "${optional_seen[neuralice.mirror_generation]:-}" ]] \
      || { _ni_sealed_refuse mirror-without-cache-generation; return 1; }
  else
    [[ -z "${optional_seen[neuralice.mirror_ca_sha256]:-}" ]] \
      || { _ni_sealed_refuse mirror-pin-without-mirror; return 1; }
    [[ -z "${optional_seen[neuralice.mirror_ready]:-}" ]] \
      || { _ni_sealed_refuse mirror-pin-without-mirror; return 1; }
    [[ -z "${optional_seen[neuralice.mirror_manifest]:-}" && -z "${optional_seen[neuralice.mirror_generation]:-}" ]] \
      || { _ni_sealed_refuse mirror-pin-without-mirror; return 1; }
  fi

  # ------------------------------------------------------------------------- #
  # THE OFFLINE SEED. A medium either carries one and seals its closure hash, or
  # carries neither. `neuralice.seed_closure` is meaningful only on a MEDIUM
  # install: a registry install pulls its bytes, and a seed staged beside it
  # would be a second, unreconciled source of the same objects.
  # ------------------------------------------------------------------------- #
  if [[ -n "${optional_seen[neuralice.seed_closure]:-}" ]]; then
    (( registry_source == 0 )) \
      || { _ni_sealed_refuse seed-closure-with-registry-source; return 1; }
    # The seed's release manifest names repositories under the release
    # authority, and the verifier is handed that authority explicitly. A medium
    # that seals a closure and not the authority to read it against is a medium
    # whose seed verification has no canonical host to insist on.
    [[ -n "$release_authority" ]] \
      || { _ni_sealed_refuse seed-closure-without-release-authority; return 1; }
    [[ -n "${optional_seen[neuralice.seed_manifest]:-}" ]] \
      || { _ni_sealed_refuse seed-closure-without-manifest-hash; return 1; }
    [[ -n "${optional_seen[neuralice.seed_trusted_now]:-}" ]] \
      || { _ni_sealed_refuse seed-closure-without-trusted-time; return 1; }
  else
    [[ -z "${optional_seen[neuralice.seed_manifest]:-}" \
       && -z "${optional_seen[neuralice.seed_trusted_now]:-}" ]] \
      || { _ni_sealed_refuse seed-manifest-without-closure; return 1; }
  fi

  printf '%s' "$mode"
}

# The single value of one keyed argument, given the already-split words. Only
# meaningful after ni_sealed_cmdline_classify has established there is exactly one.
ni_sealed_argument_value() { # $1=key $2..=words
  local key=$1 word
  shift
  for word in "$@"; do
    if [[ "$word" == "$key="* ]]; then
      printf '%s' "${word#"$key"=}"
      return 0
    fi
  done
  return 1
}

# Classify the cmdline held in a FILE. The one entry point the runtime readers
# use, so "which file is authority" is a single decision.
ni_sealed_cmdline_classify_file() { # $1=path
  local path=$1 contents
  [ -r "$path" ] || { _ni_sealed_refuse unreadable-cmdline; return 1; }
  # `head -c` bounds what an unexpected /proc/cmdline substitute can cost, and
  # `tr` folds the trailing newline the kernel appends.
  contents="$(head -c $(( NI_SEALED_CMDLINE_MAX_BYTES + 1 )) -- "$path" | tr '\n' ' ')" \
    || { _ni_sealed_refuse unreadable-cmdline; return 1; }
  ni_sealed_cmdline_classify "$contents"
}
