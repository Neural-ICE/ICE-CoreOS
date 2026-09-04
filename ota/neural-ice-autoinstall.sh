#!/usr/bin/env bash
#
# Neural ICE CoreOS — dual-mode installer (GRUB "Install" entry)
# Runs ONLY when the kernel was booted with `neuralice.autoinstall=1`
# (gated via ConditionKernelCommandLine in neural-ice-autoinstall.service).
#
# Installs the booted (live USB) image onto the auto-detected INTERNAL disk
# with FULL-DISK ENCRYPTION (two LUKS2 volumes, both TPM2/PCR7 auto-unlock):
#
#   p1 ESP   (1 GiB, clear)   signed EFI binaries (public)
#   p2 /boot (1 GiB, clear)   signed kernel + initramfs (public)
#   p3 LUKS  "system" 300 GiB ostree + /var          -> TPM PCR7 + recovery (internal escrow)
#   p4 LUKS  "data"   rest    /var/lib/neural-ice/data-> TPM PCR7 + recovery (CLIENT key)
#
# Recovery model: the OS is reinstallable from GHCR (nothing irreplaceable),
# so its recovery key is an internal Neural ICE escrow. Client DATA is
# irreplaceable, so the data recovery key is handed to the operator: shown on
# screen AND backed up to the USB. If the board/TPM is replaced, PCR7 changes
# and TPM auto-unlock stops; the recovery key restores access.
#
# Safe disk detection: the live media (USB) is EXCLUDED, an ambiguous target is
# REFUSED, and the operator removes the USB + presses Enter before reboot.
#
set -euo pipefail

# --------------------------------------------------------------------------- #
# 🔴 EVERY PRODUCTION PATH IN THIS FILE IS FIXED AND ROOT-CUSTODIED (independent
# review 2026-09-02, P0 #1, compounding issue).
#
# The command-line file, the sealed grammar, the installer library directory, the
# verity mount points, the store mapper and the TPM state helper were all
# `${VAR:-default}` -- so anything able to set an environment variable and exec
# this script could replace the very inputs the trust gate reads, and the gate
# would then validate a fixture. That was survivable only because it needed a
# shell, and the shell is exactly what the failure-sink change above removes.
#
# The seam is now EXPLICIT and CANNOT EXIST IN A RELEASE IMAGE, on three
# independent conditions, all required:
#
#   1. NI_INSTALLER_TEST_SEAM=1 must be set on purpose. Absent -- which is every
#      boot of every medium -- not one override is consulted and every path below
#      is the compiled-in literal.
#   2. The process must be UNPRIVILEGED. A root process asking for test overrides
#      is refused outright, so a privileged caller cannot use the seam even by
#      setting the variable.
#   3. /usr/lib/neural-ice/release-image must be ABSENT. image/Containerfile.installer
#      stages that marker into the dm-verity-protected read-only /usr of every
#      medium this repository cuts, so on a real medium condition 3 is false and
#      the seam refuses even in the impossible case that 1 and 2 both hold.
#
# image/test-installer-selector-grammar.sh asserts all three, and
# image/Containerfile.installer asserts the marker is present in the built image.
# --------------------------------------------------------------------------- #
readonly NI_RELEASE_IMAGE_MARKER="/usr/lib/neural-ice/release-image"
NI_INSTALLER_TEST_SEAM="${NI_INSTALLER_TEST_SEAM:-}"
if [[ -n "$NI_INSTALLER_TEST_SEAM" ]]; then
  if [[ "$NI_INSTALLER_TEST_SEAM" != 1 ]] || (( EUID == 0 )) || [[ -e "$NI_RELEASE_IMAGE_MARKER" ]]; then
    printf 'neural-ice-autoinstall: refused: test overrides are forbidden in a privileged process and cannot exist in a release image\n' >&2
    exit 1
  fi
fi
readonly NI_INSTALLER_TEST_SEAM

# One production value, one optional override, and the override is reachable only
# behind the armed seam above. Written as a function so a future path cannot be
# added as a plain `${VAR:-default}` without standing out in review.
ni_path() { # $1=environment variable name  $2=the production value
  if [[ -n "$NI_INSTALLER_TEST_SEAM" && -n "${!1:-}" ]]; then
    printf '%s' "${!1}"
  else
    printf '%s' "$2"
  fi
}

readonly LOG_TAG="neural-ice-autoinstall"
log()  { logger -t "$LOG_TAG" -- "$*"; printf '\n[%s] %s\n' "$LOG_TAG" "$*" > /dev/console 2>/dev/null || true; printf '[%s] %s\n' "$LOG_TAG" "$*" >&2; }

# --------------------------------------------------------------------------- #
# 🔴 THE FAILURE EVIDENCE. BOUNDED, STABLE, AND FREE OF EVERYTHING THAT COULD
# CARRY AN OPERATOR'S OR AN ATTACKER'S BYTES.
#
# neural-ice-installer-failure.service is the only thing that renders a failure,
# and it renders THIS file -- not the message. The message goes to the journal,
# where the operator procedures reach it; the console gets:
#
#   code        a token from the closed per-phase vocabulary below. Authored
#               here, never derived from an argument, a device, a digest, a key
#               or anything read off a medium, a disk or the network.
#   phase       the phase number and total, both authored here.
#   stage       the phase's stable slug, from the same closed table.
#   detail      the first 12 hex characters of the SHA-256 of the diagnostic
#               message. It correlates the console with the journal line and is
#               a one-way function of it: it can carry no readable fragment of a
#               path, a key, a hostname or a customer's data.
#
# The directory is created by the unit (RuntimeDirectory=), root-only, BEFORE
# ExecStart -- so there is no directory creation, no mkdir and no mode decision
# anywhere on the failure path.
# --------------------------------------------------------------------------- #
readonly FAILURE_EVIDENCE_SCHEMA=neural-ice-installer-failure-evidence-v1
FAILURE_EVIDENCE="$(ni_path NEURALICE_FAILURE_EVIDENCE /run/neural-ice-installer-failure/evidence)"
readonly FAILURE_EVIDENCE
# A failed installer powers off and its journal is volatile. Preserve the same
# closed-vocabulary evidence -- never the diagnostic message -- in one
# non-volatile EFI variable so a subsequent trusted boot can identify the
# refusing gate even when tty1 was not visible. The GUID is UUIDv5(DNS,
# installer-failure.neural-ice.ch), so this name is deterministic rather than an
# allocation guessed independently by each build.
EFI_FAILURE_EVIDENCE="$(ni_path NEURALICE_EFI_FAILURE_EVIDENCE /sys/firmware/efi/efivars/NeuralICEInstallerFailure-870a0500-25d2-574e-a1cc-79a69630bf96)"
readonly EFI_FAILURE_EVIDENCE

write_failure_evidence() { # $1=the diagnostic message (hashed, never printed)
  local detail evidence
  detail="$(printf '%s' "${1:-}" | sha256sum 2>/dev/null | cut -c1-12)"
  [[ "$detail" =~ ^[0-9a-f]{12}$ ]] || detail=unavailable
  # A single overwrite, never an append: the sink reads the FIRST occurrence of
  # each key, and a failure inside a failure must not be able to grow this file.
  printf -v evidence 'schema=%s\ncode=%s\nphase=%s\nphase_total=%s\nstage=%s\ndetail=%s\n' \
    "$FAILURE_EVIDENCE_SCHEMA" "$PHASE_CODE" "$PHASE_ID" "$PHASE_TOTAL" \
    "$PHASE_SLUG" "$detail"
  printf '%s' "$evidence" > "$FAILURE_EVIDENCE" 2>/dev/null || true

  # efivarfs requires a four-byte little-endian attributes prefix. 0x07 means
  # NON_VOLATILE | BOOTSERVICE_ACCESS | RUNTIME_ACCESS. Never remove or follow
  # an existing object here: this is a best-effort evidence write on an already
  # failing path, not authority to mutate an arbitrary filesystem object.
  if [[ -d "${EFI_FAILURE_EVIDENCE%/*}" && ! -L "$EFI_FAILURE_EVIDENCE" ]]; then
    printf '\x07\x00\x00\x00%s' "$evidence" > "$EFI_FAILURE_EVIDENCE" 2>/dev/null || true
  fi
}

die()  {
  write_failure_evidence "$*"
  log "FAILED in phase ${PHASE_ID}/${PHASE_TOTAL} (${PHASE_LABEL}) [${PHASE_CODE}]: $*"
  exit 1
}

# --------------------------------------------------------------------------- #
# Console UX: the operator watches tty1 during a destructive install, so every
# long phase announces itself ([N/8] banner), its duration is logged at the
# transition, and otherwise-silent commands prove liveness with a periodic
# tick. journald carries wall-clock timestamps; t+ is time since script start.
# --------------------------------------------------------------------------- #
readonly PHASE_TOTAL=8
PHASE_ID=0; PHASE_LABEL="startup"; PHASE_T0=$SECONDS

# 🔴 THE CLOSED FAILURE VOCABULARY. One stable slug and one stable code per
# phase, authored here and nowhere else. `die` puts the CODE on the console and
# the message in the journal, so an operator reports a token this repository owns
# rather than a sentence that may quote a path, a digest or a device.
#
# A number this table does not name is `unclassified`: an unnumbered phase is a
# defect in this file, and it must be visible as one rather than silently
# inheriting the previous phase's identity.
declare -rA PHASE_SLUGS=(
  [0]=startup
  [1]=preflight-and-trust-gate
  [2]=partition-and-encrypt
  [3]=prepare-target-filesystem
  [4]=write-deployment
  [5]=stage-verified-seed
  [6]=deployment-prep-and-device-root
  [7]=selinux-labelling
  [8]=finalize-and-escrow
)
PHASE_SLUG="${PHASE_SLUGS[0]}"
PHASE_CODE="install-failed-${PHASE_SLUGS[0]}"

fmt_dur() { # $1=seconds -> "12s" / "3m05s"
  if (( $1 >= 60 )); then printf '%dm%02ds' "$(( $1 / 60 ))" "$(( $1 % 60 ))"; else printf '%ds' "$1"; fi
}

phase() { # $1=number  $2=label — close the previous phase, open the next
  if (( PHASE_ID > 0 )); then
    log "[${PHASE_ID}/${PHASE_TOTAL}] done in $(fmt_dur $(( SECONDS - PHASE_T0 )))"
  fi
  PHASE_ID="$1"; PHASE_LABEL="$2"; PHASE_T0=$SECONDS
  PHASE_SLUG="${PHASE_SLUGS[$1]:-unclassified}"
  PHASE_CODE="install-failed-${PHASE_SLUG}"
  log "[${PHASE_ID}/${PHASE_TOTAL}] ${PHASE_LABEL} (t+$(fmt_dur "$SECONDS"))"
}

# One background reporter at a time; the EXIT trap reaps it on every path
# (die included), so no stray ticker survives the installer.
BG_PID=""
bg_stop() {
  if [[ -n "$BG_PID" ]]; then
    kill "$BG_PID" 2>/dev/null || true
    wait "$BG_PID" 2>/dev/null || true
    BG_PID=""
  fi
}
trap bg_stop EXIT

heartbeat_start() { # $1=label — proof-of-life tick on the console every 20 s
  bg_stop
  (
    hb=0
    while sleep 20; do
      hb=$(( hb + 20 ))
      printf '[%s] … %s — still running (%s elapsed)\n' \
        "$LOG_TAG" "$1" "$(fmt_dur "$hb")" > /dev/console 2>/dev/null || true
    done
  ) &
  BG_PID=$!
}

# %/rate/ETA reporter for the seed staging. The copy itself stays cp -a: the
# overlay store's hardlink/xattr semantics are load-bearing, and the bootc base
# image ships neither rsync nor pv (verified; the installer adds no packages by
# design — see Containerfile.installer). Progress is derived by polling the
# destination growth against the precomputed source total.
copy_progress_start() { # $1=total-bytes  $2=dst-dir
  bg_stop
  (
    total="$1"; dst="$2"; t0=$SECONDS
    base="$(du -sb "$dst" 2>/dev/null | awk '{print $1}')" || true
    [[ "${base:-}" =~ ^[0-9]+$ ]] || base=0
    while sleep 20; do
      cur="$(du -sb "$dst" 2>/dev/null | awk '{print $1}')" || true
      [[ "${cur:-}" =~ ^[0-9]+$ ]] || continue
      copied=$(( cur - base ))
      if (( copied < 0 )); then copied=0; fi
      elapsed=$(( SECONDS - t0 ))
      if (( elapsed <= 0 )); then continue; fi
      rate=$(( copied / elapsed ))
      eta="?"
      if (( rate > 0 && total > copied )); then
        eta="$(fmt_dur $(( (total - copied) / rate )))"
      fi
      log "$(awk -v c="$copied" -v t="$total" -v r="$rate" 'BEGIN {
        printf "  seed: %3.0f%% — %.1f / %.1f GiB at %.0f MB/s", (t > 0 ? c * 100 / t : 0), c / 2^30, t / 2^30, r / 10^6
      }') — ETA ${eta}"
    done
  ) &
  BG_PID=$!
}

# --------------------------------------------------------------------------- #
# EVERY SECURITY-RELEVANT KERNEL ARGUMENT IS READ THE SAME WAY: exactly once, or
# not at all.
#
# 🔴 WHAT THIS REPLACES. The six sealed fields and the SSH key already refused a
# second occurrence, but everything else used `grep -qE … && sed -n 's/.*KEY=\([^ ]*\).*/\1/p'`
# — a GREEDY match that silently keeps the LAST occurrence. So an appended
# `neuralice.target=/dev/nvme1n1` was not a sealed-field duplicate, the trust
# gate still succeeded, and the winner it chose steered the WIPE. The same held
# for the image reference, the mirror, the install source and the system size.
#
# awk's default field splitting IS kernel-command-line splitting, and unlike a
# greedy sed it can SEE a second occurrence instead of picking a winner. A
# duplicated argument is a refusal here, exactly as it is for the sealed anchor:
# an input that can be shadowed by appending to it is not an input this
# installer can reason about, and this one decides which disk gets destroyed.
# --------------------------------------------------------------------------- #
# The command line is read from ONE place, named once, so the suite can drive
# these two functions against a fixture instead of grepping the source and
# hoping. A control nothing exercises is a control nobody notices the loss of.
NEURALICE_CMDLINE_FILE="$(ni_path NEURALICE_CMDLINE_FILE /proc/cmdline)"
readonly NEURALICE_CMDLINE_FILE

karg_count() { # $1=key -> number of occurrences on the kernel command line
  awk -v k="$1=" 'BEGIN{n=0}{for (i=1;i<=NF;i++) if (index($i,k)==1) n++} END{print n+0}' \
    "$NEURALICE_CMDLINE_FILE"
}

karg_once() { # $1=key -> prints the single value, or nothing when absent
  local key=$1 count
  count="$(karg_count "$key")"
  case "$count" in
    0) return 0 ;;
    1) ;;
    *) die "the installer command line carries $count occurrences of ${key}=; refusing to pick a winner for a security-relevant argument" ;;
  esac
  awk -v k="$key=" '{for (i=1;i<=NF;i++) if (index($i,k)==1) print substr($i, length(k)+1)}' \
    "$NEURALICE_CMDLINE_FILE"
}

# --------------------------------------------------------------------------- #
# 🔴 THE INSTALLER REVALIDATES ITS OWN AUTHORISATION, BEFORE ANYTHING ELSE.
#
# WHAT THIS CLOSES (independent review 2026-09-02, P1 #1). The only check that a
# destructive install had actually been selected lived in the SERVICE:
# neural-ice-autoinstall.service runs the runtime generator's `--check` as an
# ExecStartPre. An ExecStartPre guards a unit, not an executable. Anything with a
# shell -- a `systemd.debug_shell` root console on tty9, an emergency shell, a
# rescue target, or a future defect in any of the above -- could simply run
# /usr/local/bin/neural-ice-autoinstall.sh, and this script would have wiped the
# internal disk without ever asking whether the boot it runs on was authorised to
# install anything.
#
# So the gate is HERE, in the thing that does the destroying, and it runs before
# the first line that reads an argument, writes a file or touches a disk. The
# service keeps its ExecStartPre: two independent readers of one grammar is the
# point, not a duplication to be tidied away.
#
# The grammar is image/installer/neural-ice-sealed-cmdline-grammar.sh -- a CLOSED
# WORLD. `neuralice.autoinstall=1` being present is NOT sufficient and never was:
# a line carrying it plus `systemd.debug_shell`, plus a second `systemd.unit=`,
# plus `neuralice.live=1`, plus an argument nobody has invented yet, is not a line
# this repository sealed, and this installer does not run on one.
# --------------------------------------------------------------------------- #
NEURALICE_SEALED_GRAMMAR="$(ni_path NEURALICE_SEALED_GRAMMAR /usr/lib/neural-ice/sealed-cmdline-grammar.sh)"
readonly NEURALICE_SEALED_GRAMMAR

require_signed_install_cmdline() {
  [[ -r "$NEURALICE_SEALED_GRAMMAR" ]] \
    || die "the sealed command-line grammar is unreadable ($NEURALICE_SEALED_GRAMMAR); this medium cannot establish that it was authorised to install anything"
  # shellcheck source=image/installer/neural-ice-sealed-cmdline-grammar.sh
  source "$NEURALICE_SEALED_GRAMMAR"
  local mode
  mode="$(ni_sealed_cmdline_classify_file "$NEURALICE_CMDLINE_FILE")" \
    || die "the kernel command line is not a signed Neural ICE media grammar; refusing to install"
  [[ "$mode" == install ]] \
    || die "this boot's signed selector is '${mode}', not Install; refusing to install"
  # The two words this script's destructive behaviour is keyed on, read again
  # through this file's OWN reader. The grammar has already established them;
  # asserting them here means a future edit that loosens the grammar still has to
  # get past the installer.
  [[ "$(karg_count neuralice.autoinstall)" == 1 && "$(karg_once neuralice.autoinstall)" == 1 ]] \
    || die "the kernel command line does not carry exactly one neuralice.autoinstall=1; refusing to install"
  [[ "$(karg_count neuralice.live)" == 0 ]] \
    || die "the kernel command line claims a Live medium as well as an Install one; refusing to install"
  log "signed Install selector revalidated by the installer itself (grammar: ${NEURALICE_SEALED_GRAMMAR})"
}
require_signed_install_cmdline

# --------------------------------------------------------------------------- #
# 🔴 THE OTA ORIGIN. ONE CANONICAL AUTHORITY, DIGEST-PINNED, NO DEFAULT
# (independent review 2026-09-02, P0 #3).
#
# WHAT THIS REPLACES. The compiled-in default was
# `ghcr.io/neural-ice/neural-ice-coreos:stable` -- a MUTABLE TAG on a registry
# that is not the release authority. An appliance whose medium sealed no origin
# recorded that value, and every later `bootc upgrade` on that machine then
# followed whatever a GHCR tag pointed at, for the life of the appliance. A
# fallback nobody chose is still a decision, and this one decided the appliance's
# entire future update path.
#
# THERE IS NO DEFAULT NOW. The origin comes from the signed UKI command line, or
# from the file the CI baked into this medium's dm-verity-protected /usr, and
# from nowhere else. Both are held to the SAME rule the sealed grammar enforces:
# `<sealed release authority>/<repo>@sha256:<digest>`. An absent, tagged, or
# foreign-authority origin is a refusal here, with the target disk untouched --
# not an appliance that silently follows someone else's tag.
# --------------------------------------------------------------------------- #
# 🔴 THE AUTHORITY IS SEALED, NOT COMPILED IN. ICE-CoreOS is open core, and
# ci/test-open-core-boundary.sh refuses the sovereign endpoint's bytes in every
# Git-visible file -- an open repository that names the production registry has
# published it. So the release authority arrives on the SIGNED command line, the
# producer supplies it from outside this tree, and every origin reference is held
# to exactly that one. `tools/ni-ota-verify`'s `--registry-host` is the same
# decision, already made.
NEURALICE_RELEASE_AUTHORITY="$(karg_once neuralice.release_authority)"
readonly NEURALICE_RELEASE_AUTHORITY
DEVICE_CHANNEL="$(karg_once neuralice.device_channel)"
readonly DEVICE_CHANNEL
[[ "$DEVICE_CHANNEL" =~ ^(lab|beta|stable)$ ]] \
  || die "this install medium seals no valid lab/beta/stable device channel"
NEURALICE_BAKED_IMGREF="$(ni_path NEURALICE_BAKED_IMGREF /usr/lib/neural-ice/ota-imgref)"
readonly NEURALICE_BAKED_IMGREF

imgref_is_canonical() { # $1=reference
  local reference=$1 repository authority path
  [[ -n "$NEURALICE_RELEASE_AUTHORITY" ]] || return 1
  [[ "$reference" =~ ^(.+)@sha256:[0-9a-f]{64}$ ]] || return 1
  repository="${reference%@sha256:*}"
  [[ "$repository" == */* ]] || return 1
  authority="${repository%%/*}"
  path="${repository#*/}"
  [[ "$authority" == "$NEURALICE_RELEASE_AUTHORITY" ]] || return 1
  [[ "$path" =~ ^[a-z0-9]+([._-][a-z0-9]+)*(/[a-z0-9]+([._-][a-z0-9]+)*)*$ ]]
}

IMGREF=""
if [[ -r "$NEURALICE_BAKED_IMGREF" ]]; then
  IMGREF="$(tr -d '[:space:]' < "$NEURALICE_BAKED_IMGREF")"
fi
# The karg wins when present: a promoted image still carries its BUILD channel in
# the baked file (promotion re-tags by digest, no rebuild -- ADR-0005), and the
# producer seals the packaged origin into the signature.
_imgref_karg="$(karg_once neuralice.imgref)"
if [[ -n "$_imgref_karg" ]]; then
  IMGREF="$_imgref_karg"
fi
[[ -n "$IMGREF" ]] \
  || die "this medium seals no OTA origin and carries no baked one; refusing to install an appliance with no update path rather than inventing a default"
imgref_is_canonical "$IMGREF" \
  || die "the OTA origin must be <sealed release authority>/<repo>@sha256:<digest>; a mutable tag or a foreign registry would decide this appliance's every future upgrade. Got: $IMGREF"

# --------------------------------------------------------------------------- #
# Optional LAN registry mirror, for the deployment-bench path (FAB-0040).
#
# `neuralice.mirror=<host[:port]>` points container pulls at a LAN mirror while
# LEAVING THE IMAGE REFERENCE UNCHANGED. That last part is the whole point: the
# medium built for a bench and the medium shipped to a customer are the same
# bytes, and the customer needs no action -- with no mirror reachable, pulls
# use the explicitly configured primary registry authority on their own.
#
# WHY A MIRROR AND NOT A DNS OVERRIDE. Pointing the configured registry authority
# at a LAN host would force that host to present a TLS certificate for that name: either
# the production private key travels to a bench, or a private CA has to be
# trusted by the image -- and that one would travel all the way to the customer.
# A mirror needs neither.
#
# WHAT KEEPS A HOSTILE MIRROR HARMLESS, per containers-registries.conf(5):
#   - pull-from-mirror = "digest-only": the mirror is consulted ONLY for
#     digest-pinned pulls, so the digest -- not the server -- is the authority;
#   - the signature policy is evaluated against the ORIGINAL scope, so bytes
#     served by the mirror must still satisfy the cosign verification configured
#     for the configured original authority. A bad mirror can only cause a loud failure.
# This is FAB-0040 D2's property ("the authority does not come from the
# transport") applied to the OCI transport that missions A/B/C established.
#
# SCOPE: the live installer environment only. The deployment is written from the
# image, whose /usr/etc holds no such drop-in, so this cannot reach the target --
# and phase 6 asserts that rather than trusting it.
INSTALL_MIRROR="$(karg_once neuralice.mirror)"
if [[ -n "$INSTALL_MIRROR" ]]; then
  # Reject anything that is not a bare host[:port]. This value is interpolated
  # into TOML: a scheme, a path or a quote would either break the file or smuggle
  # a second directive into it.
  [[ "$INSTALL_MIRROR" =~ ^[A-Za-z0-9._-]+(:[0-9]{1,5})?$ ]] \
    || die "neuralice.mirror must be a bare host[:port], got: $INSTALL_MIRROR"
fi

# --------------------------------------------------------------------------- #
# Install source: the medium's own image (default) or a registry pull.
#
# `--source-imgref containers-storage:localhost/bootc` means THE INSTALLED SYSTEM
# IS THE MEDIUM'S OWN IMAGE. `--target-imgref` only records the future OTA
# origin. That is why the medium has to carry every byte it installs, and why a
# preloaded medium is ~222 GiB.
#
# `neuralice.source=registry` installs the APPLIANCE image instead, pulled by
# digest. Combined with neuralice.mirror= this is the deployment-bench model of
# FAB-0040: a light medium boots, and the bytes come off the LAN.
#
# ⚠️ DEFAULT IS `medium`. Without the karg not one line of the USB path changes.
INSTALL_SOURCE=medium
_source_karg="$(karg_once neuralice.source)"
if [[ -n "$_source_karg" ]]; then
  INSTALL_SOURCE="$_source_karg"
  case "$INSTALL_SOURCE" in
    medium|registry) : ;;
    *) die "neuralice.source must be medium or registry, got: $INSTALL_SOURCE" ;;
  esac
fi

# The appliance image to install when INSTALL_SOURCE=registry. It MUST be
# digest-pinned: the digest is what makes a LAN mirror safe to use, so accepting
# a tag here would quietly undo the property the mirror depends on.
OS_IMAGE="$(karg_once neuralice.osimage)"
INSTALL_REGISTRY_AUTHORITY=""
if [ "$INSTALL_SOURCE" = registry ]; then
  [ -n "$OS_IMAGE" ] \
    || die "neuralice.source=registry requires neuralice.osimage=<ref>@sha256:<64-hex>"
  if ! _image_ref_parts="$(python3 - "$OS_IMAGE" <<'PY'
import ipaddress
import re
import sys

reference = sys.argv[1]
match = re.fullmatch(r"(.+)@(sha256:[0-9a-f]{64})", reference)
if not match:
    raise SystemExit(1)
repository = match.group(1)
if "/" not in repository:
    raise SystemExit(1)
authority, path = repository.split("/", 1)
segment = r"[a-z0-9]+(?:[._-][a-z0-9]+)*"
if not re.fullmatch(rf"{segment}(?:/{segment})*", path):
    raise SystemExit(1)
if authority.startswith("["):
    close = authority.find("]")
    if close < 0:
        raise SystemExit(1)
    literal, suffix = authority[1:close], authority[close + 1:]
    try:
        address = ipaddress.IPv6Address(literal)
    except ValueError:
        raise SystemExit(1)
    if address.compressed != literal or (suffix and not suffix.startswith(":")):
        raise SystemExit(1)
    port = suffix[1:] if suffix else ""
    has_port = bool(suffix)
else:
    if authority.count(":") > 1:
        raise SystemExit(1)
    host, separator, port = authority.rpartition(":")
    if not separator:
        host, port = authority, ""
    has_port = bool(separator)
    if all(char in "0123456789." for char in host):
        try:
            if str(ipaddress.IPv4Address(host)) != host:
                raise ValueError
        except ValueError:
            raise SystemExit(1)
    elif host != "localhost":
        labels = host.split(".")
        if len(labels) < 2 or len(host) > 253 or any(
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
            for label in labels
        ):
            raise SystemExit(1)
if has_port and (not re.fullmatch(r"[1-9][0-9]{0,4}", port) or int(port) > 65535):
    raise SystemExit(1)
print(repository)
print(authority)
PY
  )"; then
    die "neuralice.osimage must be digest-pinned and carry a canonical full registry authority; no short-name/default fallback is available: $OS_IMAGE"
  fi
  mapfile -t _image_ref_lines <<< "$_image_ref_parts"
  (( ${#_image_ref_lines[@]} == 2 )) \
    || die "neuralice.osimage parser returned an incomplete repository authority"
  INSTALL_IMAGE_REPOSITORY="${_image_ref_lines[0]}"
  INSTALL_REGISTRY_AUTHORITY="${_image_ref_lines[1]}"
  # --------------------------------------------------------------------------- #
  # 🔴 ONE SIGNATURE-POLICY READER, NOT TWO (independent review 2026-09-02,
  # P1 #2).
  #
  # This used to be nine lines of inline Python that asked only whether SOME
  # scope covering the repository existed under the expected authority. It never
  # looked at the requirements, so a scope stating `insecureAcceptAnything`, a
  # mistyped requirement type, an empty requirement list or a `signedIdentity`
  # that binds nothing all passed -- and the producer's helper, which at least
  # rejected `insecureAcceptAnything`, disagreed with it. Two readers of one file
  # giving two different answers is not defence in depth.
  #
  # image/installer/neural-ice-registry-authorisation.py is now THE
  # implementation, staged into this medium's signed read-only /usr, and this is
  # a call to it. It is invoked TWICE on purpose:
  #
  #   here    before the pull, so a policy that would verify nothing refuses with
  #           the target disk untouched;
  #   below   after the pull, with the index and platform-child digests the
  #           object actually resolved to -- the recursive proof. A policy
  #           satisfied by any image in the repository is refused there even
  #           though it covers exactly the right scope.
  # --------------------------------------------------------------------------- #
  [[ -f "$NEURALICE_REGISTRY_AUTHORISATION" && ! -L "$NEURALICE_REGISTRY_AUTHORISATION" ]] \
    || die "this medium carries no registry signature-policy reader at $NEURALICE_REGISTRY_AUTHORISATION; refusing a registry install nothing would verify"
  [[ -f "$NEURALICE_CONTAINER_POLICY" && ! -L "$NEURALICE_CONTAINER_POLICY" ]] \
    || die "this medium carries no readable container signature policy at $NEURALICE_CONTAINER_POLICY"
  registry_policy_authorised() { # extra arguments are passed through
    python3 "$NEURALICE_REGISTRY_AUTHORISATION" \
      --repository "$INSTALL_IMAGE_REPOSITORY" \
      --authority "$INSTALL_REGISTRY_AUTHORITY" \
      "$@" < "$NEURALICE_CONTAINER_POLICY"
  }
  registry_policy_authorised \
    || die "this medium's container signature policy does not authorise a registry install of $INSTALL_IMAGE_REPOSITORY as a signed object; refusing an install nothing would verify"
fi


# System (root) LUKS volume size. Data volume takes the remaining space.
# Overridable via neuralice.systemsize=<GiB>.
#
# 100 GiB, chosen 2026-08-05 to hold BOTH the current layout and the target one,
# so this value survives the migration to bootc logically bound images and does
# not have to be revisited mid-flight.
#
#   today   ~8 GiB OS  + 66 GiB CH-CASELAW corpus            = ~74 GiB
#   target  ~10 GiB OS + ~45 GiB bound images (2 generations) = ~55 GiB
#
# Measured on the 1 TB SKU (ni-coreos-93b9, 2026-08-05): 74 GiB used of the old
# 300 GiB — 227 GiB immobilised on a 931 GiB disk, i.e. a quarter of the drive
# doing nothing. On the 4 TB SKU 300 GiB was invisible; on 1 TB it is not.
#
# ⚠️ ORDER MATTERS during the migration. The corpus must leave the system volume
# BEFORE the container images arrive on it: 66 + 45 = 111 GiB would overflow.
# Corpus to the data volume first (Owner decision 2026-08-05), bound images after.
#
# The data volume takes everything else, so lowering this figure hands ~200 GiB
# back to models and client documents — the only place that space is ever used.
SYSTEM_GIB=100
_systemsize_karg="$(karg_once neuralice.systemsize)"
if [[ -n "$_systemsize_karg" ]]; then
  SYSTEM_GIB="$_systemsize_karg"
  # A size is interpolated into the sfdisk script that repartitions the target.
  # Anything that is not a plain, plausible number of GiB is refused rather than
  # rounded: sfdisk would otherwise silently reinterpret it.
  if ! [[ "$SYSTEM_GIB" =~ ^[0-9]{1,5}$ ]] || (( SYSTEM_GIB < 16 || SYSTEM_GIB > 65536 )); then
    die "neuralice.systemsize must be a whole number of GiB between 16 and 65536, got: $SYSTEM_GIB"
  fi
fi

readonly DATA_MOUNT="/var/lib/neural-ice/data"

# The TPM-backed monotonic state this machine keeps across a full-disk wipe: the
# install counter that numbers access-profile anchors, and the high-water that
# stops a consumed release authorization being replayed
# (ota/neural-ice-tpm-highwater.sh). A wipe is exactly what an attacker does
# before replaying, so neither can live on the disk being wiped.
TPM_STATE="$(ni_path TPM_STATE /usr/libexec/neural-ice-tpm-state)"
readonly TPM_STATE

# The ONE signature-policy reader, and the file it reads. Both are fixed
# production paths: the reader lives in the dm-verity-protected /usr the UKI
# seals, and the policy is the medium's own, so neither is an argument.
NEURALICE_REGISTRY_AUTHORISATION="$(ni_path NEURALICE_REGISTRY_AUTHORISATION /usr/lib/neural-ice/registry-authorisation.py)"
readonly NEURALICE_REGISTRY_AUTHORISATION
NEURALICE_CONTAINER_POLICY="$(ni_path NEURALICE_CONTAINER_POLICY /etc/containers/policy.json)"
readonly NEURALICE_CONTAINER_POLICY

# WHERE THE SEALED MEDIUM PUT ITSELF. The signed initramfs opened both
# dm-verity extents, mounted them read-only and gave this system an overlay over
# the first one (image/initramfs/90neural-ice-installer-verity). None of these
# paths is a trust input: every one is re-proved below against the kernel's own
# device-mapper and mount tables.
INSTALLER_STATE_DIR="$(ni_path INSTALLER_STATE_DIR /run/neural-ice-installer)"
readonly INSTALLER_STATE_DIR
VERITY_ROOT_MOUNT="$(ni_path VERITY_ROOT_MOUNT "$INSTALLER_STATE_DIR/verity-root")"
readonly VERITY_ROOT_MOUNT
STORE_MOUNT="$(ni_path STORE_MOUNT "$INSTALLER_STATE_DIR/store")"
readonly STORE_MOUNT
STORE_MAPPER="$(ni_path STORE_MAPPER neuralice-installer-store)"
readonly STORE_MAPPER
# The local name the sealed store gives the image this medium installs.
STORE_IMAGE_NAME="$(ni_path STORE_IMAGE_NAME localhost/bootc)"
readonly STORE_IMAGE_NAME

# --------------------------------------------------------------------------- #
# 0) Preconditions: a usable TPM2 must be present (PCR7 = Secure Boot state).
# --------------------------------------------------------------------------- #
[[ -e /dev/tpmrm0 || -e /dev/tpm0 ]] || die "no TPM2 device (/dev/tpm*) — cannot enroll tpm2-luks. Enable the TPM in firmware setup."
systemd-cryptenroll --tpm2-device=list >/dev/null 2>&1 || die "systemd-cryptenroll cannot see a TPM2 device"
# The same TPM has to be usable for the monotonic anti-replay state, not only
# for LUKS. Reading the counter here — before anything is decided — means a TPM
# that cannot hold that state fails the install at preflight rather than after
# the disk is gone.
[[ -x "$TPM_STATE" ]] \
  || die "this medium carries no TPM state helper at $TPM_STATE; refusing an install whose anti-replay state and access-profile binding would have nowhere to live"
[[ "$("$TPM_STATE" provisioning-status)" == virgin ]] \
  || die "the TPM is not virgin; encrypted-volume reset cannot reset anti-rollback state — use signed physical recovery"

# Stop the boot splash so install progress (and the recovery key) is visible on
# the console — the operator must not be blind during a destructive install.
plymouth quit 2>/dev/null || true
chvt 1 2>/dev/null || true

phase 1 "Preflight — TPM2 OK; detecting live media, options and target disk"

# bootc install must set SELinux labels on the target (needs mac_admin), which
# the enforcing live policy denies. The Install GRUB entry boots permissive
# (enforcing=0 karg); force it here too as a safety net. The INSTALLED system
# keeps enforcing — bootc writes correct labels from the image policy.
setenforce 0 2>/dev/null || true

# --------------------------------------------------------------------------- #
# 1) The live medium's own disk is identified further down, from the SEALED
#    PAYLOAD PARTITION the signed initramfs authenticated -- not from `findmnt /`
#    (review 2026-09-01, P0 #1). The lookup needs the sealed payload digest, so
#    it cannot run before the trust gate below; nothing between here and there
#    touches a disk.
# --------------------------------------------------------------------------- #

# --------------------------------------------------------------------------- #
# 1b) Operator SSH key for the installed system (vanilla image bakes none).
#
#     🔴 THE HOLE THIS CLOSES. Both key sources below are ATTACKER-WRITABLE on an
#     otherwise correctly signed installer: `ice-coreos/authorized_keys` sits on
#     a mutable vfat ESP, and a karg can be typed at the GRUB prompt. Until now
#     neither was checked against anything on this machine -- the only guard was
#     a Secure Boot ANCHOR label inspected on the BUILD HOST by
#     build-installer-usb.sh, which is not present at install time. So editing
#     one file on a signed installer USB provisioned SSH on a `prod` image.
#
#     The trust anchor therefore has to be read from the SIGNED IMAGE, at install
#     time. `/usr/lib/neural-ice/access-policy` is written into the read-only
#     /usr at image build time from ${VARIANT}; on the default `medium` path the
#     live installer root IS the image being installed (bootc install
#     to-filesystem --source-imgref containers-storage:localhost/bootc), so the
#     policy read here is exactly the policy of the deployment being written.
#
#     A key offered to a `customer-locked` image is a REFUSAL, not something to
#     drop silently: silently ignoring it hands the operator an appliance they
#     believe is reachable, and hands an attacker a free retry. The refusal
#     happens HERE, before the target disk is selected or touched.
#
#     The first-boot service re-states all of this independently against the
#     installed image's own /usr. Neither gate trusts the other.
# --------------------------------------------------------------------------- #
NEURALICE_INSTALLER_LIB_DIR="$(ni_path NEURALICE_INSTALLER_LIB_DIR /usr/lib/neural-ice/lib)"
# A base image built before the access policy existed has no libraries here, and
# `source` would fail with a message about a missing file rather than about what
# is actually wrong. Say it plainly: this installer cannot reason about that
# image's access posture, so it installs nothing. Fail-closed, before any disk
# write. No compatibility shim — nothing is in production (ADR-0014).
for _ni_lib in access-policy hardware-identity installer-payload installer-ssh-key installer-trust release-authorization; do
  [[ -f "$NEURALICE_INSTALLER_LIB_DIR/${_ni_lib}.sh" ]] \
    || die "the source image predates the immutable access policy (missing ${NEURALICE_INSTALLER_LIB_DIR}/${_ni_lib}.sh); refusing to install"
done
# shellcheck source=image/lib/access-policy.sh
source "$NEURALICE_INSTALLER_LIB_DIR/access-policy.sh"
# shellcheck source=image/lib/hardware-identity.sh
source "$NEURALICE_INSTALLER_LIB_DIR/hardware-identity.sh"
# shellcheck source=image/lib/installer-payload.sh
source "$NEURALICE_INSTALLER_LIB_DIR/installer-payload.sh"
# shellcheck source=image/lib/installer-ssh-key.sh
source "$NEURALICE_INSTALLER_LIB_DIR/installer-ssh-key.sh"
# shellcheck source=image/lib/installer-trust.sh
source "$NEURALICE_INSTALLER_LIB_DIR/installer-trust.sh"
# shellcheck source=image/lib/release-authorization.sh
source "$NEURALICE_INSTALLER_LIB_DIR/release-authorization.sh"

# --------------------------------------------------------------------------- #
# 1a-0) THE SEALED TRUST ANCHOR — the FIRST question this installer asks.
#
#     🔴 WHAT THIS REPLACES. Until now the block below read
#     /usr/lib/neural-ice/access-policy and treated it as authority "because the
#     image signature covers it". That is true of a deployed appliance and FALSE
#     of a removable medium (DESIGN-NOTE-0001, Finding 1): Secure Boot
#     authenticates EFI binaries and the kernel, not the root filesystem they
#     mount. An attacker holding a correctly signed installer USB could rewrite
#     the marker from customer-locked to lab-managed, or rewrite THIS SCRIPT so
#     the gate was never consulted, and both survived Secure Boot untouched.
#
#     WHAT RUNS INSTEAD. The signed UKI's .cmdline carries the dm-verity root
#     hash of this installer root, the access profile, the hardware target, the
#     Secure Boot trust-policy id and the identity of the key that may authorise
#     a release. installer_trust_gate proves the root we are standing on IS that
#     verity target, and only THEN reads the in-root markers and requires them to
#     agree. Any disagreement, and any second occurrence of a sealed key on the
#     command line, is a refusal.
#
#     ORDER IS THE WHOLE POINT. Reading a policy out of an unauthenticated root
#     and verifying the root afterwards would be verifying a copy of the answer.
# --------------------------------------------------------------------------- #
INSTALLER_CMDLINE="$(tr -d '\n' < "$NEURALICE_CMDLINE_FILE")"
VERITY_MAPPER="$(ni_path VERITY_MAPPER neuralice-installer-root)"
readonly VERITY_MAPPER
# The gate is handed the MOUNT POINT the policy will be read from, not just a
# mapper name. Proving that a correctly-hashed verity device exists somewhere
# says nothing about what a policy file came from: the two must be the same
# device, or every file read below comes from a root nothing authenticated.
#
# 🔴 AND THAT MOUNT POINT IS NOT `/` ANY MORE (review 2026-09-01, P0 #1). A
# dm-verity squashfs cannot be written to, and this installer must write /etc
# drop-ins, /var scratch and podman state — so the medium mounts the VERIFIED
# root read-only at $VERITY_ROOT_MOUNT and gives the system an overlay over it
# with a bounded tmpfs on top. Every marker is therefore read from the read-only
# verity mount, never from the overlay a root shell could write.
SEALED_ANCHOR="$(installer_trust_gate "$VERITY_ROOT_MOUNT" "$INSTALLER_CMDLINE" \
  "$VERITY_MAPPER" "$VERITY_ROOT_MOUNT")" \
  || die "this medium carries no verified sealed trust anchor; refusing to install anything from an unauthenticated installer root"
SEALED_ACCESS_PROFILE="$(sed -n 's/^neuralice\.access_profile=//p' <<<"$SEALED_ANCHOR")"
SEALED_HARDWARE_TARGET="$(sed -n 's/^neuralice\.hardware_target=//p' <<<"$SEALED_ANCHOR")"
SEALED_TRUST_POLICY_ID="$(sed -n 's/^neuralice\.trust_policy_id=//p' <<<"$SEALED_ANCHOR")"
SEALED_PAYLOAD_DIGEST="$(sed -n 's/^neuralice\.payload=//p' <<<"$SEALED_ANCHOR")"
SEALED_RELAUTH_SCHEMA="$(sed -n 's/^neuralice\.relauth_schema=//p' <<<"$SEALED_ANCHOR")"
readonly SEALED_ACCESS_PROFILE SEALED_HARDWARE_TARGET SEALED_TRUST_POLICY_ID SEALED_PAYLOAD_DIGEST SEALED_RELAUTH_SCHEMA
[[ "$SEALED_RELAUTH_SCHEMA" == "$NEURAL_ICE_RELEASE_AUTH_SCHEMA" ]] \
  || die "the signed UKI requires release-authorization schema '$SEALED_RELAUTH_SCHEMA', but this verified installer implements '$NEURAL_ICE_RELEASE_AUTH_SCHEMA'"
log "Sealed installer trust anchor: profile=$SEALED_ACCESS_PROFILE target=$SEALED_HARDWARE_TARGET trust=$SEALED_TRUST_POLICY_ID relauth=$SEALED_RELAUTH_SCHEMA (dm-verity enforced)"

# THE WRITABLE RUNTIME, PROVED. The code this script is executing comes off the
# overlay, so the overlay's shape is part of the trust argument: exactly one
# lower layer, which is the verity mount just proved, and an upper layer on a
# tmpfs — created empty by the signed initramfs on every boot, so nothing an
# attacker wrote to the medium can be in it.
installer_trust_assert_overlay_root "$VERITY_ROOT_MOUNT" / >/dev/null \
  || die "this installer is not running from an overlay over the verified installer root; refusing to act on code nothing authenticated"

# THE SEALED PAYLOAD, RE-PROVED AFTER SWITCH-ROOT. The initramfs verified the
# header against the sealed digest and opened the store's own dm-verity target;
# this restates both against the kernel's tables rather than inheriting a
# breadcrumb, and it is the check that makes `--source-imgref` name authenticated
# bytes (review 2026-09-01, P0 #1).
_payload_header_file="$INSTALLER_STATE_DIR/payload-header"
[[ -f "$_payload_header_file" && ! -L "$_payload_header_file" ]] \
  || die "the sealed payload header is absent; this system did not boot from a sealed medium"
PAYLOAD_HEADER="$(payload_header_read "$_payload_header_file" 0)" \
  || die "the sealed payload header recorded by the initramfs is not a valid $NEURAL_ICE_PAYLOAD_SCHEMA header"
_payload_digest="$(payload_header_digest "$PAYLOAD_HEADER")"
[[ "$_payload_digest" == "$SEALED_PAYLOAD_DIGEST" ]] \
  || die "the payload header on this medium hashes to $_payload_digest, not the $SEALED_PAYLOAD_DIGEST the signed UKI seals"
STORE_VERITY_HASH="$(payload_header_field "$PAYLOAD_HEADER" store_verity_hash)" \
  || die "the sealed payload header names no image-store verity hash"
readonly PAYLOAD_HEADER STORE_VERITY_HASH
installer_trust_assert_root_verity "$STORE_VERITY_HASH" "$STORE_MAPPER" "$STORE_MOUNT" \
  "installer image store" >/dev/null \
  || die "the medium's container image store is not the dm-verity target the sealed payload header describes"
log "Sealed payload verified: header=$SEALED_PAYLOAD_DIGEST store-verity=$STORE_VERITY_HASH (dm-verity enforced, read-only)"

# --------------------------------------------------------------------------- #
# 1c) WHICH DISK THIS MACHINE BOOTED FROM — the one disk the wipe must not take.
#
# 🔴 WHAT THIS REPLACES (review 2026-09-01, P0 #1). This used to be
# `findmnt -no SOURCE /` piped into `lsblk -no PKNAME`. The signed initramfs
# switch-roots onto an OVERLAY over the verified squashfs (proved just above), so
# `findmnt /` answers `neural-ice-installer-root`: an overlay source with no
# parent block device. `PKNAME` was therefore empty and every sealed Install
# medium died here — before the trust gate, before any disk was touched, and with
# a message about `PKNAME` that named nothing an operator could act on.
#
# The answer comes from the AUTHENTICATED PAYLOAD PARTITION instead. It runs HERE
# rather than at preflight because it is only meaningful once
# $SEALED_PAYLOAD_DIGEST has been established: the lookup requires the payload
# header read off that partition to hash to the digest the signed UKI seals, so
# the disk being excluded is the disk carrying the bytes this kernel booted, not
# whatever a breadcrumb happened to name.
# --------------------------------------------------------------------------- #
_medium="$(installer_trust_sealed_medium_disk "$INSTALLER_STATE_DIR" "$SEALED_PAYLOAD_DIGEST")" \
  || die "cannot identify the sealed medium this machine booted from; refusing to choose a wipe target without knowing which disk to exclude"
read -r LIVE_PAYLOAD_NODE LIVE_PAYLOAD_DEVNO live_disk <<<"$_medium"
readonly LIVE_PAYLOAD_NODE LIVE_PAYLOAD_DEVNO live_disk
[[ -n "$live_disk" ]] || die "the sealed medium lookup returned no parent disk"
log "Live media = /dev/$live_disk (payload partition $LIVE_PAYLOAD_NODE, $LIVE_PAYLOAD_DEVNO — excluded from target)"

media_vfat_partition() {
  lsblk -rno NAME,FSTYPE "/dev/$live_disk" 2>/dev/null \
    | awk '$2 == "vfat" && !found { print $1; found=1 }'
}
mounted_at() { # $1=device -> first mountpoint, or nothing
  findmnt -nfo TARGET "$1" 2>/dev/null \
    | awk 'NR == 1 { first=$0 } END { if (first != "") print first }'
}

# --------------------------------------------------------------------------- #
# 🔴 WHAT THIS REPLACES (review 2026-09-01, P0 #1). This phase used to run
# `bootc image copy-to-storage`, which duplicated the BOOTED ostree deployment
# (~10 GiB, ~10 minutes) into /var/lib/containers. On a medium whose root is a
# dm-verity squashfs there is no ostree deployment to copy, so that command could
# not work at all — and the medium therefore could not install.
#
# The bytes are staged at BUILD time instead, as a containers-storage frozen into
# its own squashfs, carried inside the sealed payload and opened by the signed
# initramfs behind its own dm-verity target (proved above). Registering it as a
# READ-ONLY ADDITIONAL IMAGE STORE is the same mechanism the PRELOADED seed store
# already uses on the appliance: podman reads the layers in place, so there is no
# import, no copy and no window between "verified" and "used". `--source-imgref`
# then names EXACTLY the extent the signature covers.
# --------------------------------------------------------------------------- #
_store_driver="$(sed -n 's/^[[:space:]]*driver[[:space:]]*=[[:space:]]*"\([a-z0-9]*\)".*/\1/p' \
  "$VERITY_ROOT_MOUNT/etc/containers/storage.conf" 2>/dev/null | head -1)"
[[ "${_store_driver:-overlay}" == overlay ]] \
  || die "the installer image uses the '$_store_driver' storage driver; the sealed store is an overlay store and would not be readable"
[[ -d "$STORE_MOUNT/overlay-images" && -d "$STORE_MOUNT/overlay-layers" ]] \
  || die "the verified image store does not have the layout podman reads as an additional image store"
# A COMPLETE config rather than a drop-in: `CONTAINERS_STORAGE_CONF` is honoured
# by containers/storage itself, so the same file governs this script's podman
# calls AND the bootc container below, which is bind-mounted over its own copy.
# One file, one answer — a drop-in that a given c/storage release ignored would
# fail open, with podman quietly resolving `localhost/bootc` to nothing.
readonly INSTALLER_STORAGE_ROOT=/run/neural-ice-container-runtime
readonly INSTALLER_STORAGE_CONF="$INSTALLER_STORAGE_ROOT/storage.conf"
readonly INSTALLER_STORAGE_DROPINS="$INSTALLER_STORAGE_ROOT/empty-storage-conf.d"
readonly INSTALLER_STORAGE_RUNROOT="$INSTALLER_STORAGE_ROOT/containers-runroot"
readonly INSTALLER_STORAGE_GRAPHROOT="$INSTALLER_STORAGE_ROOT/containers-storage"
# The live / is overlayfs. Merely placing these paths under /run is not enough:
# the deliberately minimal installer boot does not guarantee that /run itself
# has been mounted as tmpfs. containers/storage then sees an overlay graphroot
# backed by overlayfs and `bootc install to-filesystem` refuses it after the
# target has already been wiped. Mount this invocation's complete writable
# storage root explicitly and prove the backing filesystem before Podman can
# inspect the sealed read-only additional image store.
[[ "$INSTALLER_STORAGE_ROOT" != "$INSTALLER_STATE_DIR" \
   && "$INSTALLER_STORAGE_ROOT" != "$INSTALLER_STATE_DIR/"* ]] \
  || die "the writable container runtime would cover the verified installer state"
install -d -m 0755 "$INSTALLER_STORAGE_ROOT"
mount -t tmpfs -o nodev,nosuid,mode=0755 \
  neural-ice-installer-storage "$INSTALLER_STORAGE_ROOT" \
  || die "cannot mount the installer's writable container storage on tmpfs"
install -d -m 0700 "$INSTALLER_STORAGE_RUNROOT" "$INSTALLER_STORAGE_GRAPHROOT"
install -d -m 0755 "$INSTALLER_STORAGE_DROPINS"
[[ "$(findmnt -n -o FSTYPE --target "$INSTALLER_STORAGE_GRAPHROOT" 2>/dev/null)" == tmpfs ]] \
  || die "the installer's writable container storage is not backed by tmpfs"
installer_trust_assert_root_verity "$STORE_VERITY_HASH" "$STORE_MAPPER" "$STORE_MOUNT" \
  "installer image store after writable-runtime mount" >/dev/null \
  || die "the writable container runtime covered or changed the verified image store"
cat > "$INSTALLER_STORAGE_CONF" <<EOF
[storage]
driver = "overlay"
runroot = "$INSTALLER_STORAGE_RUNROOT"
graphroot = "$INSTALLER_STORAGE_GRAPHROOT"

[storage.options]
additionalimagestores = ["$STORE_MOUNT"]

[storage.options.overlay]
mount_program = "/usr/bin/fuse-overlayfs"
mountopt = "nodev"
EOF
export CONTAINERS_STORAGE_CONF="$INSTALLER_STORAGE_CONF"
# The sealed store is produced by the same overlay implementation and carries
# containers/storage's `.has-mount-program` marker. Supplying only driver =
# "overlay" makes metadata inspection appear usable on some hosts, then bootc
# refuses OpenImage after the target wipe. Prove both the helper/device and an
# actual merged mount while this phase is still non-destructive.
command -v fuse-overlayfs >/dev/null \
  || die "the installer image has no fuse-overlayfs helper for its sealed image store"
if [[ ! -c /dev/fuse ]]; then
  modprobe fuse 2>/dev/null || true
  udevadm settle 2>/dev/null || true
fi
[[ -c /dev/fuse ]] \
  || die "the installer cannot access /dev/fuse for its sealed image store"
# ASSERT THE OUTCOME, not the write. A store that podman cannot read produces a
# medium that fails at `bootc install`, after the target disk has been destroyed.
podman --cgroup-manager=cgroupfs --events-backend=file image exists "$STORE_IMAGE_NAME" \
  || die "the verified image store does not offer ${STORE_IMAGE_NAME}; refusing to install from a source podman cannot resolve"
MEDIUM_IMAGE_DIGEST="$(podman --cgroup-manager=cgroupfs --events-backend=file \
  image inspect "$STORE_IMAGE_NAME" --format '{{.Digest}}' 2>/dev/null)" \
  || die "the verified image store's ${STORE_IMAGE_NAME} cannot be inspected"
[[ "$MEDIUM_IMAGE_DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]] \
  || die "the verified image store reports no usable digest for ${STORE_IMAGE_NAME}"
readonly MEDIUM_IMAGE_DIGEST
_medium_probe=neural-ice-installer-store-preflight
podman --cgroup-manager=cgroupfs --events-backend=file \
  create --network=none --name "$_medium_probe" --entrypoint /usr/bin/true \
  "$STORE_IMAGE_NAME" >/dev/null \
  || die "the verified image store cannot create a no-exec preflight container before the target wipe"
_medium_mount="$(podman --cgroup-manager=cgroupfs --events-backend=file \
  mount "$_medium_probe" 2>/dev/null)" \
  || {
    podman --cgroup-manager=cgroupfs --events-backend=file rm -f "$_medium_probe" >/dev/null 2>&1 || true
    die "the verified image store cannot produce a no-exec merged filesystem before the target wipe"
  }
[[ -n "$_medium_mount" && -d "$_medium_mount" ]] \
  || {
    podman --cgroup-manager=cgroupfs --events-backend=file rm -f "$_medium_probe" >/dev/null 2>&1 || true
    die "the verified image store produced no no-exec merged filesystem before the target wipe"
  }
if ! podman --cgroup-manager=cgroupfs --events-backend=file \
    unmount "$_medium_probe" >/dev/null \
  || ! podman --cgroup-manager=cgroupfs --events-backend=file \
    rm "$_medium_probe" >/dev/null; then
  die "the verified image store's no-exec pre-wipe mount cannot be released"
fi
log "Sealed image store registered read-only at $STORE_MOUNT; ${STORE_IMAGE_NAME} = ${MEDIUM_IMAGE_DIGEST} (no copy, dm-verity enforced)"

# --------------------------------------------------------------------------- #
# 1a-1) THE ACCESS PROFILE THIS MACHINE IS ALREADY BOUND TO.
#
# 🔴 WHAT THIS ADDS (review 2026-09-01, P1 #3). The access profile used to be
# authorised by a device-root signature alone. That key is a TPM object with an
# EMPTY authorization policy, so anything running as root on the appliance can
# make it sign — which means "this appliance was installed customer-locked" was a
# statement a privileged runtime attacker could simply re-issue with a different
# word in it. The device root now proves DEVICE BINDING and LIVENESS; the profile
# itself is bound to a WRITE-ONCE, policy-protected TPM NV record
# (ota/neural-ice-tpm-state.sh), which no software on this machine can rewrite.
#
# It is read HERE, before the target disk is touched, so an appliance that is
# already bound to a different profile is a non-destructive refusal with an
# operator-actionable message rather than a wiped disk and a bricked OTA path.
# --------------------------------------------------------------------------- #
TPM_PROFILE_BINDING="$("$TPM_STATE" profile-digest \
  "$SEALED_ACCESS_PROFILE" "$SEALED_HARDWARE_TARGET" "$SEALED_TRUST_POLICY_ID")" \
  || die "cannot derive this medium's access-profile binding"
readonly TPM_PROFILE_BINDING
log "TPM provisioning state is exactly virgin; the mandatory first-boot ceremony will bind $TPM_PROFILE_BINDING."

# The in-root marker is now a CROSS-CHECK, not the authority. The gate above
# already required the two to agree; restating it here keeps the comparison
# visible in the code that acts on it, and keeps the ordering assertion in
# image/test-access-policy.sh checking something real rather than a library call
# it cannot see.
ACCESS_POLICY=""
ACCESS_POLICY="$(access_policy_read "$VERITY_ROOT_MOUNT" 2>/dev/null)" \
  || die "the verified installer root carries no readable immutable access policy (/usr/lib/neural-ice/access-policy)"
[[ "$ACCESS_POLICY" == "$SEALED_ACCESS_PROFILE" ]] \
  || die "the installer root states access policy '$ACCESS_POLICY' but the signed UKI seals '$SEALED_ACCESS_PROFILE'"
log "Immutable image access policy: $ACCESS_POLICY (agrees with the signed UKI)"

# PRESENCE first, CONTENT later. The policy refusal must fire on the mere
# OFFER of a key, before anything reads the supplied bytes: a customer-locked
# appliance must refuse a crafted ESP entry, not first try to parse it.
SSHKEY_B64=""
SSHKEY_ORIGIN=""
SSHKEY_ESP_FILE=""
# awk's default field splitting is exactly kernel-command-line splitting, and
# unlike a greedy `sed .*` it can SEE a second occurrence instead of silently
# keeping the last one.
_sshkey_kargs="$(karg_count neuralice.sshkey)"
(( _sshkey_kargs <= 1 )) \
  || die "the installer command line carries ${_sshkey_kargs} neuralice.sshkey arguments"
if (( _sshkey_kargs == 1 )); then
  SSHKEY_ORIGIN="kernel command line"
else
  _usb_esp="$(media_vfat_partition || true)"
  if [[ -n "${_usb_esp:-}" ]]; then
    _esp_mp="$(mounted_at "/dev/$_usb_esp" || true)"
    if [[ -n "$_esp_mp" ]] && [[ -e "$_esp_mp/ice-coreos/authorized_keys" || -L "$_esp_mp/ice-coreos/authorized_keys" ]]; then
      SSHKEY_ESP_FILE="$_esp_mp/ice-coreos/authorized_keys"
      SSHKEY_ORIGIN="installer ESP"
    fi
  fi
fi

if [[ -n "$SSHKEY_ORIGIN" ]]; then
  # Refuse LOUDLY, and before the disk is touched.
  access_policy_gate_installer_ssh "$ACCESS_POLICY" "$INSTALL_SOURCE" 1 \
    || die "an SSH key was supplied on the ${SSHKEY_ORIGIN} but this image refuses installer SSH provisioning (policy=$ACCESS_POLICY, source=$INSTALL_SOURCE)"

  # The policy says a key MAY be provisioned; it says nothing about whether THIS
  # byte string is a key. Structure is checked here so a malformed, multiple,
  # oversized, symlinked or non-public-key payload never reaches the installed
  # karg -- and, for the ESP path, so an `authorized_keys` symlink pointing at a
  # private file is refused before its bytes are ever read.
  _sshkey_scratch="/run/neural-ice-installer/sshkey"
  install -d -m 0700 "$(dirname -- "$_sshkey_scratch")"
  rm -rf -- "$_sshkey_scratch"
  install -d -m 0700 "$_sshkey_scratch"
  _sshkey_candidate="$_sshkey_scratch/authorized_keys"
  if [[ -n "$SSHKEY_ESP_FILE" ]]; then
    installer_ssh_key_validate_file "$SSHKEY_ESP_FILE" \
      || die "the SSH key supplied on the ${SSHKEY_ORIGIN} is not exactly one plain OpenSSH public key"
    install -m 0600 "$SSHKEY_ESP_FILE" "$_sshkey_candidate"
  else
    _sshkey_encoded="$(karg_once neuralice.sshkey)"
    [[ "$_sshkey_encoded" =~ ^[A-Za-z0-9+/=]{1,1024}$ ]] \
      || die "the SSH key supplied on the ${SSHKEY_ORIGIN} is not plain base64"
    ( umask 077; printf '%s' "$_sshkey_encoded" | base64 -d > "$_sshkey_candidate" 2>/dev/null ) \
      || die "the SSH key supplied on the ${SSHKEY_ORIGIN} is not decodable base64"
    installer_ssh_key_validate_file "$_sshkey_candidate" \
      || die "the SSH key supplied on the ${SSHKEY_ORIGIN} is not exactly one plain OpenSSH public key"
  fi
  # Encode from the VALIDATED bytes, so the karg carries exactly what was checked.
  SSHKEY_B64="$(base64 -w0 < "$_sshkey_candidate")"
  log "Operator SSH key accepted from the ${SSHKEY_ORIGIN} (policy=$ACCESS_POLICY) — 'core' will be provisioned on first boot."
  rm -rf -- "$_sshkey_scratch"
else
  # No key offered. The policy is still validated above, so an image with no
  # recognised access posture never installs at all.
  access_policy_gate_installer_ssh "$ACCESS_POLICY" "$INSTALL_SOURCE" 0 \
    || die "the source image access policy is not acceptable to this installer"
  log "No operator SSH key provided; none will be set (policy=$ACCESS_POLICY)."
fi

# --------------------------------------------------------------------------- #
# 1c) Optional root-signed LAB baseline receipt for the installed OTA service.
#     The installer only snapshots a structurally safe byte pair; it does not
#     parse the JSON or make any signature/trust decision. ICE-Fabric owns that
#     verification after first boot. A partial or unsafe pair aborts BEFORE the
#     internal disk is touched; an absent pair preserves ordinary installs.
# --------------------------------------------------------------------------- #
readonly LAB_BASELINE_HANDOFF="/usr/local/libexec/neural-ice-lab-baseline-handoff"
readonly LAB_BASELINE_SNAPSHOT="/run/neural-ice-installer/lab-baseline"
LAB_BASELINE_PRESENT=0
_lab_usb_esp="$(media_vfat_partition || true)"
if [[ -n "${_lab_usb_esp:-}" ]]; then
  _lab_esp_mp="$(mounted_at "/dev/$_lab_usb_esp" || true)"
  _lab_esp_we_mounted=0
  if [[ -z "$_lab_esp_mp" ]]; then
    _lab_esp_mp="/run/neural-ice-lab-esp"
    install -d -m 0700 "$_lab_esp_mp"
    mount -o ro "/dev/$_lab_usb_esp" "$_lab_esp_mp" \
      || die "cannot mount the installer ESP read-only for LAB baseline preflight"
    _lab_esp_we_mounted=1
  fi

  # Clear a residue from an earlier attempt in this same boot. The handoff
  # refuses to overwrite an existing destination, so without this a RETRY of the
  # installer dies at preflight with "snapshot destination already exists" —
  # after any transient failure the operator could never simply relaunch
  # (grounded 2026-07-23, .72). Both paths are under /run (tmpfs), so a residue
  # can only ever come from this boot; nothing durable is discarded.
  rm -rf -- "$LAB_BASELINE_SNAPSHOT"
  rm -f -- "$LAB_BASELINE_SNAPSHOT".*.new \
           /run/neural-ice-installer/.lab-baseline-snapshot.*.new

  _lab_snapshot_rc=0
  "$LAB_BASELINE_HANDOFF" snapshot "$_lab_esp_mp" "$LAB_BASELINE_SNAPSHOT" \
    || _lab_snapshot_rc=$?
  if (( _lab_esp_we_mounted == 1 )); then
    umount "$_lab_esp_mp" || die "cannot unmount the installer ESP after LAB baseline preflight"
  fi
  case "$_lab_snapshot_rc" in
    0)
      LAB_BASELINE_PRESENT=1
      log "Optional LAB baseline receipt pair found and safely snapshotted."
      ;;
    3)
      log "No optional LAB baseline receipt pair on the installer ESP."
      ;;
    *)
      die "optional LAB baseline receipt pair failed structural preflight"
      ;;
  esac
else
  log "No installer ESP found for the optional LAB baseline receipt pair."
fi

# --------------------------------------------------------------------------- #
# 2) Pick the internal target disk: type=disk, != live, transport != usb
#    -> largest candidate ; ambiguity = abort (unless neuralice.target= given).
# --------------------------------------------------------------------------- #
mapfile -t candidates < <(
  lsblk -dnbo NAME,TYPE,TRAN,SIZE 2>/dev/null | \
  awk -v live="$live_disk" '$2=="disk" && $1!=live && $3!="usb" {print $4, $1}' | \
  sort -rn
)
[[ "${#candidates[@]}" -ge 1 ]] || die "no internal target disk found (excluding live/USB)"

target="/dev/$(echo "${candidates[0]}" | awk '{print $2}')"
if [[ "${#candidates[@]}" -gt 1 ]]; then
  _target_karg="$(karg_once neuralice.target)"
  if [[ -n "$_target_karg" ]]; then
    target="$_target_karg"
    # This value selects the disk that is about to be destroyed. Constrain it to
    # a plain /dev node name: a path with `..`, a glob or a space would let one
    # argument name something other than what a reader of the command line sees.
    [[ "$target" =~ ^/dev/[a-zA-Z0-9]+[a-zA-Z0-9_-]*$ ]] \
      || die "neuralice.target must name a plain block device under /dev, got: $target"
    log "Multiple disks — explicit target via kernel arg: $target"
  else
    log "Candidate disks: ${candidates[*]}"
    die "multiple internal disks — pass neuralice.target=/dev/XXX to disambiguate"
  fi
fi
[[ -b "$target" ]] || die "invalid target: $target"
target_serial="$(lsblk -dno SERIAL "$target" 2>/dev/null | head -1 || true)"
: "${target_serial:=unknown}"

# Provision/attest the dedicated device root before the selected target is
# touched.  A malformed occupied handle is therefore a non-destructive
# refusal rather than an error after repartitioning.  The preflight receipt is
# deliberately ephemeral: after bootc has created the stateroot, the exact
# same helper attests that handle again and persists its public receipt below.
readonly DEVICE_ROOT_PREFLIGHT_IDENTITY="/run/neural-ice-installer/device-root-preflight-v1.json"
install -d -m 0700 "$(dirname -- "$DEVICE_ROOT_PREFLIGHT_IDENTITY")"
/usr/libexec/neural-ice-device-root ensure \
  --identity "$DEVICE_ROOT_PREFLIGHT_IDENTITY" \
  >/dev/null \
  || die "cannot preflight the dedicated TPM device-root before disk writes"
log "Dedicated TPM device-root preflight passed."
# Persist and freeze the exact systemd SRK before either LUKS token is enrolled.
# systemd's documented default handle is 0x81000001; asking for the SRK now
# creates/persists it while owner authorization is still available, and the
# public bytes are carried into the installed stateroot for every boot to attest.
readonly INTENDED_SRK_PUBLIC="/run/neural-ice-installer/srk-v1.tpm2b_public"
systemd-analyze srk > "$INTENDED_SRK_PUBLIC" 2>/dev/null \
  || die "cannot create and read the intended persistent SRK at 0x81000001"
[[ -s "$INTENDED_SRK_PUBLIC" && ! -L "$INTENDED_SRK_PUBLIC" ]] \
  || die "the intended persistent SRK public area is absent"
chmod 0600 "$INTENDED_SRK_PUBLIC"
log "Persistent SRK created and frozen at 0x81000001 before LUKS enrollment."

# --------------------------------------------------------------------------- #
# 2b) PULL AND AUTHORIZE BEFORE ANY TARGET MUTATION.
#
#     🔴 THE HOLE THIS CLOSES (DESIGN-NOTE-0001, Finding 2). The digest
#     comparison used to live in phase 4, AFTER wipefs/sfdisk/luksFormat/mkfs.
#     By the time anything about the image was known, the target disk was
#     already destroyed — so "refuse" could not mean "leave the machine as it
#     was". Worse, nothing constrained WHICH digest could be asked for:
#     `neuralice.osimage=` came off an unauthenticated command line, so a
#     CUSTOMER medium could be pointed at a perfectly image-ci-signed `debug`
#     digest and would install it — serial root autologin, sshd enabled,
#     SELinux permissive. Refusing the medium's SSH KEY does not refuse the
#     medium's IMAGE.
#
#     WHAT RUNS NOW, in this order, with the target disk still untouched:
#       1. verify a Neural-ICE-signed RELEASE AUTHORIZATION with the key sealed
#          in the UKI cmdline (identity pinned by SHA-256, so a substituted key
#          is a different id and refuses);
#       2. require it to agree with the medium on access profile, hardware
#          target and Secure Boot trust policy, and to NAME the digest that was
#          requested — the karg no longer selects an image, it only has to match;
#       3. pull exactly that digest;
#       4. require BOTH observed digests — the index (.RepoDigests) and the
#          platform child (.Digest) — to equal the authorised pair, which is what
#          closes index/child confusion in both directions;
#       5. read the access policy, variant, hardware target and trust-policy
#          LABEL out of the PULLED OBJECT and require exact agreement.
#     A refusal at any step leaves a bootable machine.
# --------------------------------------------------------------------------- #
# 🔴 PLACED HERE ON PURPOSE. This block needs two things the earlier argument
# parsing does not have yet: the SEALED ACCESS PROFILE (established by the trust
# gate, §1a-0) and the LIVE DISK the payload partition identified (§1). Writing
# the mirror transport before either existed is how a customer-locked medium
# could have been given a lab host in its boot path with nothing to compare
# against. It still runs BEFORE the pull and before any target mutation.
# --------------------------------------------------------------------------- #
# 🔴 THE MIRROR IS LAB TRANSPORT, PINNED AND DECLARED (independent review
# 2026-09-02, P0 #3).
#
# WHAT THIS REPLACES. The mirror was written with `insecure = true` -- no CA, no
# identity, nothing but a hostname -- and nothing tied it to the access profile
# or to a stated release closure. Three consequences:
#
#   * a CUSTOMER-LOCKED appliance could be cut with a lab host in its boot path,
#     and no digest argument makes that acceptable: it is a machine that must
#     never depend on `.63`;
#   * `insecure = true` means any host that answers on that name and port is the
#     mirror, so the "transport" was unauthenticated even as transport;
#   * nothing required the mirror to hold the release closure being installed,
#     so a stale or partial cache produced a pull failure on a bench rather than
#     a refusal before the disk was touched.
#
# All three are now sealed decisions. The grammar refuses a mirror outside
# `lab-managed` and refuses one that does not seal both a CA digest and the exact
# READY closure hash; this block re-states the profile rule against the anchor
# it holds, pins the CA by the sealed digest, and requires the mirror to DECLARE
# that exact closure before it is written into the transport configuration.
#
# The CA travels on the ESP because it is bench-specific and the medium is not.
# The ESP is mutable, which is precisely why the digest that pins it is sealed in
# the UKI command line rather than stored beside it.
# --------------------------------------------------------------------------- #
readonly MIRROR_READY_PATH=/v2/_neural-ice/ready
readonly MIRROR_READY_SCHEMA=neural-ice-mirror-ready-v1
readonly MIRROR_READY_MAX_BYTES=4096

esp_staged_file() { # $1=basename $2=expected sha256 $3=destination -> stages it or fails
  local name=$1 expected=$2 destination=$3 esp mountpoint mounted=0 observed
  esp="$(media_vfat_partition || true)"
  [[ -n "${esp:-}" ]] || die "this medium carries no ESP to read ${name} from"
  mountpoint="$(mounted_at "/dev/$esp" || true)"
  if [[ -z "$mountpoint" ]]; then
    mountpoint=/run/neural-ice-installer/esp
    install -d -m 0700 "$mountpoint"
    mount -o ro,nodev,nosuid,noexec "/dev/$esp" "$mountpoint" \
      || die "cannot mount the installer ESP read-only to read ${name}"
    mounted=1
  fi
  if [[ -f "$mountpoint/ice-coreos/$name" && ! -L "$mountpoint/ice-coreos/$name" ]]; then
    install -m 0600 "$mountpoint/ice-coreos/$name" "$destination" \
      || die "cannot snapshot ${name} from the installer ESP"
  else
    (( mounted == 1 )) && umount "$mountpoint"
    die "the installer ESP carries no ${name}; this medium's signature says it must"
  fi
  (( mounted == 1 )) && { umount "$mountpoint" || die "cannot unmount the installer ESP after reading ${name}"; }
  # 🔴 THE HASH IS THE POINT. The ESP is a mutable vfat partition an attacker
  # holding the medium can rewrite; the value it is compared against is inside
  # the UKI's signed .cmdline. Compare AFTER the copy, on the bytes that will
  # actually be used, so the file cannot change between the check and the use.
  observed="$(sha256sum -- "$destination" | awk '{print tolower($1)}')"
  [[ "$observed" == "$expected" ]] \
    || die "the ESP's ${name} hashes to ${observed}, not the ${expected} this medium's signature seals"
  return 0
}

# The TPM slot is authorised by an offline policy key, never by whatever PCR 7
# happens to contain while this installer is running. All four values are in the
# signed UKI command line; the release authorization independently repeats them
# in device_policy for SEED v2.
PCR_POLICY_DIGEST="$(karg_once neuralice.pcr_policy)"
PCR_POLICY_KEY_SHA256="$(karg_once neuralice.pcr_policy_key)"
PCR_POLICY_SIGNATURE_SHA256="$(karg_once neuralice.pcr_policy_signature)"
PCR_POLICY_SEQ="$(karg_once neuralice.pcr_policy_seq)"
[[ "$PCR_POLICY_DIGEST" =~ ^[0-9a-f]{64}$ && "$PCR_POLICY_KEY_SHA256" =~ ^[0-9a-f]{64}$ \
   && "$PCR_POLICY_SIGNATURE_SHA256" =~ ^[0-9a-f]{64}$ && "$PCR_POLICY_SEQ" =~ ^[1-9][0-9]{0,18}$ ]] \
  || die "this install medium does not seal one exact signed PCR policy generation"
PCR_POLICY_KEY_RUNTIME=/run/neural-ice-installer/tpm2-pcr-public-key.pem
PCR_POLICY_SIGNATURE_RUNTIME=/run/neural-ice-installer/tpm2-pcr-signature.json
install -d -m 0700 /run/neural-ice-installer
esp_staged_file tpm2-pcr-public-key.pem "$PCR_POLICY_KEY_SHA256" "$PCR_POLICY_KEY_RUNTIME"
esp_staged_file tpm2-pcr-signature.json "$PCR_POLICY_SIGNATURE_SHA256" "$PCR_POLICY_SIGNATURE_RUNTIME"
openssl pkey -pubin -in "$PCR_POLICY_KEY_RUNTIME" -noout >/dev/null \
  || die "the sealed PCR policy public key is not a usable public key"
if ! python3 - "$PCR_POLICY_SIGNATURE_RUNTIME" "$PCR_POLICY_DIGEST" <<'PCR_POLICY_PY'
import json, re, sys
document=json.load(open(sys.argv[1],encoding="ascii"))
entries=document.get("sha256") if isinstance(document,dict) else None
if not isinstance(entries,list) or not any(
    isinstance(e,dict) and isinstance(e.get("pol"),str)
    and re.fullmatch(r"[0-9a-f]{64}",e["pol"]) and e["pol"]==sys.argv[2]
    for e in entries):
    raise SystemExit(1)
PCR_POLICY_PY
then
  die "the signed PCR policy file does not contain the exact sealed PolicyPCR digest"
fi
PCR_POLICY_HIGH_WATER="$("$TPM_STATE" pcr-policy-check "$PCR_POLICY_SEQ")" \
  || die "signed PCR policy sequence $PCR_POLICY_SEQ is replayed, stale or outside the TPM high-water window"
[[ "$PCR_POLICY_HIGH_WATER" =~ ^[0-9]{1,16}$ && "$PCR_POLICY_SEQ" -gt "$PCR_POLICY_HIGH_WATER" ]] \
  || die "TPM PCR policy high-water check returned malformed state"

if [[ -n "$INSTALL_MIRROR" ]]; then
  [ "$INSTALL_SOURCE" = registry ] \
    || die "neuralice.mirror requires neuralice.source=registry and an explicit digest-pinned neuralice.osimage"
  # The grammar has already refused this combination; the installer re-states it
  # against the anchor IT read, because a gate that only exists in the grammar is
  # a gate a future grammar edit can remove without anything noticing.
  [[ "$SEALED_ACCESS_PROFILE" == lab-managed ]] \
    || die "this medium seals access profile '${SEALED_ACCESS_PROFILE}' and names a LAN mirror; a customer appliance never depends on a lab host"
  MIRROR_CA_SHA256="$(karg_once neuralice.mirror_ca_sha256)"
  MIRROR_READY_SHA256="$(karg_once neuralice.mirror_ready)"
  MIRROR_READY_MANIFEST_SHA256="$(karg_once neuralice.mirror_manifest)"
  MIRROR_CACHE_GENERATION="$(karg_once neuralice.mirror_generation)"
  [[ "$MIRROR_CA_SHA256" =~ ^[0-9a-f]{64}$ ]] \
    || die "a LAN mirror requires a sealed CA digest; this medium seals none"
  [[ "$MIRROR_READY_SHA256" =~ ^[0-9a-f]{64}$ ]] \
    || die "a LAN mirror requires a sealed READY release-closure hash; this medium seals none"
  [[ "$MIRROR_READY_MANIFEST_SHA256" =~ ^[0-9a-f]{64}$ && "$MIRROR_CACHE_GENERATION" =~ ^[1-9][0-9]{0,18}$ ]] \
    || die "a LAN mirror requires a sealed READY manifest hash and positive cache generation"

  MIRROR_CA_FILE=/run/neural-ice-installer/mirror-ca.crt
  install -d -m 0700 /run/neural-ice-installer
  esp_staged_file mirror-ca.crt "$MIRROR_CA_SHA256" "$MIRROR_CA_FILE"

  # 🔴 THE MIRROR MUST DECLARE THE EXACT CLOSURE, over TLS pinned to that CA.
  # A mirror that is merely reachable is not a mirror that holds this release: a
  # stale or partial cache would otherwise be discovered as a pull failure after
  # the disk was gone. `--cacert` with no CA bundle fallback means an unpinned
  # host cannot answer, and the bounded read means a hostile one cannot answer at
  # length.
  _mirror_ready_json=/run/neural-ice-installer/mirror-ready.json
  rm -f -- "$_mirror_ready_json"
  curl --silent --show-error --fail --max-time 30 --max-filesize "$MIRROR_READY_MAX_BYTES" \
    --proto '=https' --tlsv1.2 --cacert "$MIRROR_CA_FILE" \
    --output "$_mirror_ready_json" "https://${INSTALL_MIRROR}${MIRROR_READY_PATH}" \
    || die "the LAN mirror ${INSTALL_MIRROR} did not serve ${MIRROR_READY_PATH} over TLS pinned to this medium's sealed CA"
  _mirror_ready_declared="$(python3 - "$_mirror_ready_json" "$MIRROR_READY_SCHEMA" <<'MIRROR_READY_PY'
import json
import re
import sys

path, schema = sys.argv[1:]
with open(path, "rb") as handle:
    document = json.loads(handle.read(4096))
required = {"schema", "release_closure_sha256", "release_manifest_sha256",
            "store_generation"}
if not isinstance(document, dict) or set(document) != required or document.get("schema") != schema:
    raise SystemExit(1)
closure = document.get("release_closure_sha256")
manifest = document.get("release_manifest_sha256")
generation = document.get("store_generation")
if (not isinstance(closure, str) or not re.fullmatch(r"[0-9a-f]{64}", closure)
    or not isinstance(manifest, str) or not re.fullmatch(r"[0-9a-f]{64}", manifest)
    or not isinstance(generation, int) or isinstance(generation, bool) or generation < 1
    ):
    raise SystemExit(1)
print(closure, manifest, generation, sep="\n")
MIRROR_READY_PY
  )" || die "the LAN mirror's READY receipt is not a bounded ${MIRROR_READY_SCHEMA} document"
  mapfile -t _mirror_ready_fields <<<"$_mirror_ready_declared"
  [[ "${_mirror_ready_fields[0]:-}" == "$MIRROR_READY_SHA256" \
      && "${_mirror_ready_fields[1]:-}" == "$MIRROR_READY_MANIFEST_SHA256" \
      && "${_mirror_ready_fields[2]:-}" == "$MIRROR_CACHE_GENERATION" ]] \
    || die "the LAN mirror READY does not equal this medium's sealed closure/manifest/cache generation"

  # The CA is what the container tooling trusts for this host, so the transport
  # is authenticated as well as digest-pinned. `insecure` is gone: an unpinned
  # host can no longer answer for the mirror name.
  install -d -m 0755 "/etc/containers/certs.d/$INSTALL_MIRROR"
  install -m 0644 "$MIRROR_CA_FILE" "/etc/containers/certs.d/$INSTALL_MIRROR/ca.crt"
  install -d -m 0755 /etc/containers/registries.conf.d
  for _scope in neural-ice vendor; do
    cat >> /etc/containers/registries.conf.d/99-neural-ice-install-mirror.conf <<EOF
[[registry]]
location = "$INSTALL_REGISTRY_AUTHORITY/$_scope"

  [[registry.mirror]]
  location = "$INSTALL_MIRROR/$_scope"
  pull-from-mirror = "digest-only"

EOF
  done
  log "LAN registry mirror enabled for this install only: $INSTALL_MIRROR (digest-only, CA pinned to ${MIRROR_CA_SHA256}, READY for release closure ${MIRROR_READY_SHA256}, canonical authority ${INSTALL_REGISTRY_AUTHORITY} retained)"
fi

RELEASE_AUTH_VERIFIED_REF=""
source_imgref="containers-storage:$STORE_IMAGE_NAME"
if [ "$INSTALL_SOURCE" = registry ]; then
  _relauth_key="$VERITY_ROOT_MOUNT/usr/lib/neural-ice/keys/release-authorization.pub"
  [[ -f "$_relauth_key" && ! -L "$_relauth_key" ]] \
    || die "the verified installer root carries no release-authorization public key"
  # --------------------------------------------------------------------------- #
  # 🔴 THE AUTHORIZATION IS ON A MUTABLE ESP, AND ITS HASH IS IN THE SIGNATURE
  # (independent review 2026-09-02, P0 #3).
  #
  # The document travels on the medium's ESP so a bench can carry a fresh one,
  # and it is verified with the key inside the dm-verity-protected root whose
  # identity the UKI pins by `neuralice.relauth_keyid`. That made the VERIFIER
  # non-editable and left the DOCUMENT selectable: an attacker holding the medium
  # could substitute any other correctly signed authorization -- for a different
  # digest, a different profile, an older issuance -- and every check below would
  # agree with it, because every check below asks about the document it was
  # handed.
  #
  # The producer now hashes both files as it stages them and seals both digests
  # into the UKI's .cmdline. They are compared HERE, on the snapshot that will
  # actually be used, before a single field is parsed. The grammar refuses a
  # registry medium that seals a source and not both digests, so there is no
  # medium on which this check is absent.
  # --------------------------------------------------------------------------- #
  RELEASE_AUTH_DOC_SHA256="$(karg_once neuralice.relauth_sha256)"
  RELEASE_AUTH_SIG_SHA256="$(karg_once neuralice.relauth_sig_sha256)"
  [[ "$RELEASE_AUTH_DOC_SHA256" =~ ^[0-9a-f]{64}$ ]] \
    || die "this medium seals no release-authorization document digest; a registry install would then accept any correctly signed authorization the ESP happened to carry"
  [[ "$RELEASE_AUTH_SIG_SHA256" =~ ^[0-9a-f]{64}$ ]] \
    || die "this medium seals no release-authorization signature digest"
  [[ "$RELEASE_AUTH_DOC_SHA256" != "$RELEASE_AUTH_SIG_SHA256" ]] \
    || die "this medium seals one digest for both the release authorization and its detached signature; that pins neither"

  _auth_scratch=/run/neural-ice-installer/release-auth
  rm -rf -- "$_auth_scratch"; install -d -m 0700 "$_auth_scratch"
  esp_staged_file release-authorization.json "$RELEASE_AUTH_DOC_SHA256" \
    "$_auth_scratch/release-authorization.json"
  esp_staged_file release-authorization.sig "$RELEASE_AUTH_SIG_SHA256" \
    "$_auth_scratch/release-authorization.sig"

  release_auth_verify_signature "$_auth_scratch/release-authorization.json" \
    "$_auth_scratch/release-authorization.sig" "$_relauth_key" \
    || die "the release authorization on this medium is not signed by the key the UKI seals"
  RELEASE_AUTH="$(release_auth_parse "$_auth_scratch/release-authorization.json")" \
    || die "the release authorization on this medium is malformed"
  AUTH_SCHEMA="$(sed -n 's/^schema=//p' <<<"$RELEASE_AUTH")"
  [[ "$AUTH_SCHEMA" == "$SEALED_RELAUTH_SCHEMA" ]] \
    || die "the release authorization schema '$AUTH_SCHEMA' is not the exact schema '$SEALED_RELAUTH_SCHEMA' sealed by this UKI"
  SIGNED_IMAGE_REPOSITORY="$(sed -n 's/^image_repository=//p' <<<"$RELEASE_AUTH")"
  SIGNED_IMAGE_INDEX_DIGEST="$(sed -n 's/^image_index_digest=//p' <<<"$RELEASE_AUTH")"
  SIGNED_IMAGE_MANIFEST_DIGEST="$(sed -n 's/^image_manifest_digest=//p' <<<"$RELEASE_AUTH")"
  SIGNED_REGISTRY_AUTHORITY="${SIGNED_IMAGE_REPOSITORY%%/*}"
  [[ "$SIGNED_IMAGE_REPOSITORY" == "$INSTALL_IMAGE_REPOSITORY" \
      && "$SIGNED_REGISTRY_AUTHORITY" == "$INSTALL_REGISTRY_AUTHORITY" ]] \
    || die "raw registry authority '$INSTALL_REGISTRY_AUTHORITY' does not exactly equal the signed authority '$SIGNED_REGISTRY_AUTHORITY'"

  # 🔴 AUTHENTIC IS NOT CURRENT. `issued_at` and `image_platform` used to be
  # validated for shape and then never used, so one formerly-authorised
  # index/child pair was replayable for ever by a hostile mirror, and an
  # authorization issued for one architecture authorised an install of another.
  #
  # The high-water lives in TPM NV, not on disk, because a full-disk wipe is
  # exactly what an attacker does before replaying. It is READ here and only
  # WRITTEN after the install commits, so a refused or crashed attempt does not
  # burn a valid authorization.
  # The preflight above proved exact virgin state. Runtime freshness-read never
  # maps absence to zero; zero is used only inside this trusted install path.
  RELEASE_AUTH_HIGH_WATER=0
  INSTALL_PLATFORM="$(podman version --format '{{.OsArch}}' 2>/dev/null || true)"
  [[ "$INSTALL_PLATFORM" =~ ^[a-z0-9]+/[a-z0-9]+(/v[0-9]+)?$ ]] \
    || die "cannot determine the platform this install is running on (got '${INSTALL_PLATFORM:-nothing}')"
  # 🔴 NO CLOCK IS PASSED IN (review 2026-09-01, P1 #4). This call used to hand
  # the gate `date -u +%s` and a 14-day window, i.e. it judged freshness with the
  # firmware RTC — which anybody holding the machine can set backwards, keeping an
  # unconsumed captured authorization inside its window for ever. The decision is
  # now made from the document's SIGNED MONOTONIC issuance sequence against a TPM
  # counter, and no reading of the clock can move either.
  RELEASE_AUTH_CONSUMED="$(release_auth_gate_request "$RELEASE_AUTH" "$SEALED_ANCHOR" "$OS_IMAGE" \
    "$RELEASE_AUTH_HIGH_WATER" "$INSTALL_PLATFORM")" \
    || die "the release authorization does not authorise ${OS_IMAGE} on this medium"
  RELEASE_AUTH_ISSUANCE_SEQ="$(sed -n 's/^consumed_issuance_seq=//p' <<<"$RELEASE_AUTH_CONSUMED")"
  [[ "$RELEASE_AUTH_ISSUANCE_SEQ" =~ ^[1-9][0-9]{0,15}$ ]] \
    || die "the release-authorization gate returned no usable issuance sequence"
  [[ "$RELEASE_AUTH_ISSUANCE_SEQ" == "$(sed -n 's/^issuance_seq=//p' <<<"$RELEASE_AUTH")" ]] \
    || die "the release-authorization gate changed Fabric's allocated issuance sequence"
  log "Release authorization verified: $(sed -n 's/^issuance_id=//p' <<<"$RELEASE_AUTH") (profile=$SEALED_ACCESS_PROFILE, target=$SEALED_HARDWARE_TARGET, platform=$INSTALL_PLATFORM, seq=$RELEASE_AUTH_ISSUANCE_SEQ > high-water=$RELEASE_AUTH_HIGH_WATER, issued_at=$(sed -n 's/^issued_at=//p' <<<"$RELEASE_AUTH_CONSUMED") — informational)"

  log "Pulling the authorised appliance image: $OS_IMAGE"
  [ -n "$INSTALL_MIRROR" ] && log "  (a LAN mirror is configured: $INSTALL_MIRROR — the reference above is unchanged)"
  heartbeat_start "podman pull $OS_IMAGE"
  podman --cgroup-manager=cgroupfs --events-backend=file pull "$OS_IMAGE" \
    || die "cannot pull the appliance image; with a mirror configured, check that it holds this digest"
  bg_stop

  # Assert what LANDED, not what was requested: a mirror that served something
  # else must stop the install, not rename it.
  #
  # Both `.Digest` and `.RepoDigests` are read on purpose, and now BOTH are
  # required to match a value the authorization names. The GB10 appliance is a
  # single arm64 manifest today, but the multi-arch doctrine says images become
  # OCI indexes, and for an index `.Digest` is the PLATFORM CHILD while
  # `.RepoDigests` keeps the INDEX digest that was asked for. Checking one of
  # the two would break the day the appliance goes multi-arch, or pass vacuously
  # today — and either way it would let a hostile mirror answer an index request
  # with a child, or swap the child under a correct index.
  got_manifest="$(podman image inspect "$OS_IMAGE" --format '{{.Digest}}' 2>/dev/null)" \
    || die "the pulled appliance image cannot be inspected"
  repodigests="$(podman image inspect "$OS_IMAGE" --format '{{range .RepoDigests}}{{println .}}{{end}}' 2>/dev/null || true)"
  want_repo="${OS_IMAGE%@*}"
  # OBSERVE the index digest, do not restate the request. Echoing "${OS_IMAGE##*@}"
  # back would make the comparison in release_auth_gate_pulled vacuous: it would
  # compare the authorization against the karg it had already been checked
  # against, and would agree even if the local object carried something else.
  # Read it out of the object's own repo digests instead, for the repository the
  # authorization binds — and require EXACTLY ONE, so an object carrying two
  # digests for that repository is a refusal rather than a choice.
  got_repo_digest="$(printf '%s' "$repodigests" | awk -v repo="$want_repo@" \
    'index($0, repo) == 1 {print; n++} END {exit n != 1}')" \
    || die "the pulled object does not carry exactly one repo digest for $want_repo"
  RESOLVED_IMAGE_REPOSITORY="${got_repo_digest%@*}"
  RESOLVED_REGISTRY_AUTHORITY="${RESOLVED_IMAGE_REPOSITORY%%/*}"
  [[ "$RESOLVED_IMAGE_REPOSITORY" == "$INSTALL_IMAGE_REPOSITORY" \
      && "$RESOLVED_REGISTRY_AUTHORITY" == "$INSTALL_REGISTRY_AUTHORITY" ]] \
    || die "container tooling resolved authority '$RESOLVED_REGISTRY_AUTHORITY', not the raw configured authority '$INSTALL_REGISTRY_AUTHORITY'"
  got_index="${got_repo_digest##*@}"
  [[ "$got_index" =~ ^sha256:[0-9a-f]{64}$ ]] \
    || die "the pulled object's repo digest is malformed: $got_index"
  # Belt and braces on the karg itself: the object podman resolved must be the
  # one that was asked for. podman already refuses a digest mismatch on pull;
  # this makes the property visible rather than inherited.
  [[ "$got_index" == "${OS_IMAGE##*@}" ]] \
    || die "the pulled object's index digest ($got_index) is not the requested one (${OS_IMAGE##*@})"
  [[ "$got_manifest" =~ ^sha256:[0-9a-f]{64}$ ]] \
    || die "the pulled object reports a malformed platform manifest digest: $got_manifest"

  # --------------------------------------------------------------------------- #
  # 🔴 THE RECURSIVE PROOF: THE POLICY MUST BIND THE OBJECT, NOT THE REPOSITORY
  # (independent review 2026-09-02, P1 #2).
  #
  # The gate before the pull proved the policy is object-binding in the abstract.
  # This one names the two digests the object ACTUALLY resolved to -- the index
  # that was asked for and the platform child it carries -- and re-asks the same
  # implementation whether the covering scopes bind them.
  #
  # Why it is not the same question twice: a `signedIdentity` of
  # `matchRepository` or `exactRepository` is satisfied by ANY correctly signed
  # image in the repository, so a hostile mirror could answer a correct index
  # request with a correctly signed SIBLING child and every scope check would
  # still agree. Scope existence is not a signature over the object that was
  # pulled. `release_auth_gate_pulled` below then requires those same two digests
  # to be the pair the signed authorization names, so the identity binding and
  # the authorization binding are two independent statements about one object.
  # --------------------------------------------------------------------------- #
  registry_policy_authorised --require-object-binding \
    --index-digest "$got_index" --manifest-digest "$got_manifest" \
    --authenticated-repository "$SIGNED_IMAGE_REPOSITORY" \
    --authenticated-index-digest "$SIGNED_IMAGE_INDEX_DIGEST" \
    --authenticated-manifest-digest "$SIGNED_IMAGE_MANIFEST_DIGEST" \
    || die "this medium's container signature policy does not bind the pulled index/child pair; a policy satisfied by any image in $INSTALL_IMAGE_REPOSITORY cannot prove the recursive signature of this one"

  # Read the image's OWN statements about itself out of the pulled bytes. An
  # authorization is a claim ABOUT an image; it becomes a property OF the image
  # only when the bytes agree.
  #
  # 🔴 HOST-SIDE, WITHOUT EXECUTING ANYTHING FROM THE CANDIDATE. This used to run
  # `podman run … "$OS_IMAGE" cat <path>` — i.e. it asked a not-yet-trusted image
  # to report on itself, using that image's own `cat`. A contradictory image can
  # ship a `cat` that prints `customer-locked` for the marker and anything it
  # likes for the rest, and every comparison below would then agree about a lie.
  # `podman image mount` exposes the merged filesystem to the HOST; the files are
  # read with the installer's own tools and not one byte of the candidate is
  # executed.
  _img_root="$(podman --cgroup-manager=cgroupfs --events-backend=file image mount "$OS_IMAGE" 2>/dev/null)" \
    || die "cannot inspect the pulled image without executing it"
  [[ -n "$_img_root" && -d "$_img_root" ]] \
    || die "the pulled image did not mount to a directory for host-side inspection"
  _img_read() { # $1=path relative to the image root — a plain regular file, read by US
    local path="$_img_root/$1"
    [[ -f "$path" && ! -L "$path" ]] || return 0
    # Bounded: a hostile image must not be able to hand the installer a gigabyte
    # where a one-word marker belongs.
    (( "$(wc -c < "$path")" <= 128 )) || return 0
    tr -d '[:space:]' < "$path"
  }
  img_profile="$(_img_read usr/lib/neural-ice/access-policy)"
  img_variant="$(_img_read usr/lib/neural-ice/appliance-variant)"
  img_target="$(_img_read usr/lib/neural-ice/hardware-target)"
  podman --cgroup-manager=cgroupfs --events-backend=file image umount "$OS_IMAGE" >/dev/null 2>&1 || true
  img_policy="$(podman image inspect "$OS_IMAGE" \
    --format '{{index .Labels "ch.neural-ice.signed-boot-trust-policy-id"}}' 2>/dev/null || true)"
  # The platform the OBJECT reports, from its own config rather than from the
  # request: an index that answered a linux/arm64 request with another
  # architecture's child fails here.
  img_platform="$(podman image inspect "$OS_IMAGE" \
    --format '{{.Os}}/{{.Architecture}}{{with .Variant}}/{{.}}{{end}}' 2>/dev/null || true)"
  release_auth_gate_pulled "$RELEASE_AUTH" "$SEALED_ANCHOR" \
    "$got_index" "$got_manifest" "$img_profile" "$img_variant" "$img_target" "$img_policy" \
    "$img_platform" \
    || die "the pulled image does not match its release authorization or this medium's sealed profile"
  [[ "$img_platform" == "$INSTALL_PLATFORM" ]] \
    || die "the pulled image is for platform '$img_platform' but this machine installs '$INSTALL_PLATFORM'"

  # From here the object in local storage is the ONLY thing that may be
  # installed. Nothing is re-resolved between this proof and the install.
  source_imgref="containers-storage:$OS_IMAGE"
  RELEASE_AUTH_VERIFIED_REF="$source_imgref"
  log "  authorised and verified: index=$got_index manifest=$got_manifest profile=$img_profile variant=$img_variant"
else
  # The medium path installs the medium's own image, whose root this script is
  # standing on and whose verity hash the UKI sealed. The proof is the anchor
  # itself, established above before anything was read out of that root.
  RELEASE_AUTH_VERIFIED_REF="$source_imgref"
fi
readonly RELEASE_AUTH_VERIFIED_REF

# --------------------------------------------------------------------------- #
# 2c) 🔴 THE OFFLINE SEED, VERIFIED IN FULL BEFORE THE FIRST DISK MUTATION
#     (independent review 2026-09-02, P0 #2).
#
# WHAT THIS REPLACES. Phase 5 mounted ANY block device carrying the partlabel
# `ni-seed` and `cp -a`'d its `store`, `models` and `payload` directories onto
# the already-formatted, already-encrypted data volume. There was no signature,
# no release identity, no authorization, no access profile, no hardware target
# and not one per-object digest -- and it happened AFTER wipefs, sfdisk,
# luksFormat and mkfs. So modifying or replacing the mutable seed partition after
# an off-device inspection, leaving the signed UKI untouched, put arbitrary
# store, model and payload bytes inside the installed encrypted appliance; and
# because the target was already destroyed, "refuse" could not mean "leave the
# machine as it was".
#
# The seed is now a SEED v2 tree: content-addressed, signed, and named by the
# release closure hash the UKI seals. Everything about it is proved HERE, with
# the target disk untouched:
#
#   identity     the partition is found on THIS medium -- the disk the sealed
#                payload partition identified -- and mounted read-only by its
#                stable PARTUUID, nodev/nosuid/noexec, never by a name a second
#                device could also claim;
#   authority    tools/ni-ota-verify verifies the canonical release manifest and
#                the release authorization against the key inside the dm-verity
#                root, parses the manifest through the SAME canonical reader the
#                OTA path uses, and requires its canonical digest to equal both
#                the seed root's own name and the hash this UKI seals;
#   closure      it then walks the OCI graph and the content/evidence stores:
#                every referenced object present, every present object reachable,
#                every object's bytes hashing to the name it is stored under, and
#                nothing extra, unknown or unreachable anywhere in the tree;
#   receipt      the seed's READY receipt is required and is NOT authority: not
#                one digest above is skipped because it is present.
#
# A seed partition with no sealed closure, or a sealed closure with no seed, is a
# refusal in both directions: a medium either carries the seed it was cut with or
# carries none.
# --------------------------------------------------------------------------- #
NEURALICE_SEED_VERIFIER="$(ni_path NEURALICE_SEED_VERIFIER /usr/bin/ni-ota-verify)"
readonly NEURALICE_SEED_VERIFIER
readonly SEED_MOUNT="$INSTALLER_STATE_DIR/seed"
SEED_CLOSURE="$(karg_once neuralice.seed_closure)"
readonly SEED_CLOSURE
SEED_MANIFEST_SHA256="$(karg_once neuralice.seed_manifest)"
readonly SEED_MANIFEST_SHA256
SEED_TRUSTED_NOW="$(karg_once neuralice.seed_trusted_now)"
readonly SEED_TRUSTED_NOW
SEED_VERIFIED_ROOT=""

# The seed partition ON THIS MEDIUM, by stable identity. `live_disk` was
# established from the SEALED PAYLOAD PARTITION, not from `findmnt /`, so this
# cannot be pointed at a second USB stick that also carries the partlabel -- and
# the PARTUUID is what is actually mounted, so the answer cannot change between
# the lookup and the mount.
seed_partition_partuuid() { # -> the PARTUUID, or nothing
  local candidates
  candidates="$(lsblk -rno NAME,PARTLABEL,PARTUUID "/dev/$live_disk" 2>/dev/null \
    | awk '$2 == "ni-seed" { print $3 }')"
  [[ -n "$candidates" ]] || return 0
  (( "$(printf '%s\n' "$candidates" | grep -c .)" == 1 )) \
    || die "this medium carries more than one ni-seed partition; refusing to choose which offline closure to install"
  printf '%s' "$candidates"
}

_seed_partuuid="$(seed_partition_partuuid)"
if [[ -n "$SEED_CLOSURE" ]]; then
  [[ -n "$_seed_partuuid" ]] \
    || die "this medium's signature seals offline release closure ${SEED_CLOSURE} and the medium carries no ni-seed partition"
  _seed_device="/dev/disk/by-partuuid/$_seed_partuuid"
  [[ -b "$_seed_device" ]] \
    || die "the ni-seed partition has no stable by-partuuid node ($_seed_device); refusing to mount a seed by a name a second device could claim"
  install -d -m 0700 "$SEED_MOUNT"
  mount -o ro,nodev,nosuid,noexec,norecovery "$_seed_device" "$SEED_MOUNT" \
    || die "cannot mount the offline seed read-only"
  # The seed root is a directory NAMED by the closure hash. Reading it by name
  # rather than searching for "the one directory in there" is what makes the
  # sealed hash decide which tree is mounted-and-read, not the tree itself.
  SEED_VERIFIED_ROOT="$SEED_MOUNT/seed/$SEED_CLOSURE"
  [[ -d "$SEED_VERIFIED_ROOT" && ! -L "$SEED_VERIFIED_ROOT" ]] \
    || die "the offline seed carries no seed/${SEED_CLOSURE} root; this is not the closure this medium was cut with"
  # 🔴 THE HISTORICAL FORMAT IS REFUSED OUTRIGHT. A Podman overlay store is not a
  # format anything can verify object by object, and it was the authority this
  # whole finding is about. A medium carrying one is a medium from before the
  # seed had a closure, and it does not install.
  for _legacy in store models payload; do
    [[ ! -e "$SEED_MOUNT/$_legacy" ]] \
      || die "this seed carries the historical opaque '${_legacy}' tree; a Podman overlay store is not a verifiable offline closure and is no longer an install source"
  done
  [[ -x "$NEURALICE_SEED_VERIFIER" ]] \
    || die "this medium carries no seed-closure verifier at ${NEURALICE_SEED_VERIFIER}; refusing to stage an offline closure nothing would verify"
  _seed_key="$VERITY_ROOT_MOUNT/usr/lib/neural-ice/keys/release-authorization.pub"
  [[ -f "$_seed_key" && ! -L "$_seed_key" ]] \
    || die "the verified installer root carries no release-authorization public key to verify the offline seed with"
  log "Verifying the offline release closure ${SEED_CLOSURE} before the target disk is touched…"
  heartbeat_start "offline seed closure verification"
  "$NEURALICE_SEED_VERIFIER" verify-seed-closure \
    --seed-root "$SEED_VERIFIED_ROOT" \
    --pubkey "$_seed_key" \
    --registry-host "$NEURALICE_RELEASE_AUTHORITY" \
    --hardware-target "$SEALED_HARDWARE_TARGET" \
    --access-profile "$SEALED_ACCESS_PROFILE" \
    --device-channel "$DEVICE_CHANNEL" \
    --trust-policy-id "$SEALED_TRUST_POLICY_ID" \
    --expect-closure "sha256:${SEED_CLOSURE}" \
    --expect-manifest "sha256:${SEED_MANIFEST_SHA256}" \
    --trusted-now "$SEED_TRUSTED_NOW" \
    --pcr-policy-digest "$PCR_POLICY_DIGEST" \
    --pcr-policy-public-key-sha256 "$PCR_POLICY_KEY_SHA256" \
    --pcr-policy-signature-sha256 "$PCR_POLICY_SIGNATURE_SHA256" \
    --pcr-policy-seq "$PCR_POLICY_SEQ" \
    || die "the offline seed is not the signed release closure this medium seals; nothing has been written to the target disk"
  bg_stop
  log "Offline release closure verified in full: sha256:${SEED_CLOSURE} (every manifest, blob, model and evidence object present, reachable and digest-matched; no extra object)"
else
  [[ -z "$_seed_partuuid" ]] \
    || die "this medium carries an ni-seed partition and its signature seals no offline release closure; an unauthorised seed is not staged"
fi
readonly SEED_VERIFIED_ROOT

log "Internal target disk = $target (serial $target_serial) — WIPING + ENCRYPTING in 5s…"
sleep 5

phase 2 "Partition + encrypt (GPT, 2× LUKS2, TPM2/PCR7 enroll)"

# --------------------------------------------------------------------------- #
# 3) Partition the target (GPT): ESP, /boot, LUKS system, LUKS data
# --------------------------------------------------------------------------- #
# Partition device name helper (nvme0n1 -> nvme0n1pN ; sda -> sdaN)
partdev() { case "$target" in *[0-9]) echo "${target}p$1";; *) echo "${target}$1";; esac; }
ESP="$(partdev 1)"; BOOT="$(partdev 2)"; SYSP="$(partdev 3)"; DATAP="$(partdev 4)"

# Target mountpoint for the install (real dir; /mnt is a dangling symlink in
# the bootc container image — see the install step below).
readonly TGT=/var/tmp/nitarget
mkdir -p "$TGT"

# Clean any leftovers from a previous failed attempt on this target so the
# wipe/partitioning is not blocked by open LUKS mappers or stale mounts.
umount -R "$TGT" 2>/dev/null || true
for m in system data; do
  cryptsetup close "$m" 2>/dev/null || true
  if [[ -e "/dev/mapper/$m" ]]; then
    dmsetup remove --force "$m" 2>/dev/null || true
  fi
done
udevadm settle

log "Partitioning $target (ESP 1G, /boot 1G, system ${SYSTEM_GIB}G LUKS, data rest LUKS)…"
wipefs -a "$target" >/dev/null 2>&1 || true
# GPT via sfdisk (util-linux) — type GUIDs are cosmetic here (LUKS is opened
# explicitly), the EFI System type is the only one that must be correct.
# --force overrules the "disk in use" safety check (we own this target and have
# just freed it above) so a retried install is not blocked by stale holders.
sfdisk --force --wipe always --wipe-partitions always "$target" <<EOF
label: gpt
size=1GiB, type=uefi, name="EFI-SYSTEM"
size=1GiB, type=linux, name="boot"
size=${SYSTEM_GIB}GiB, type=linux, name="system-luks"
type=linux, name="data-luks"
EOF
partx -u "$target" 2>/dev/null || true
udevadm settle
for p in "$ESP" "$BOOT" "$SYSP" "$DATAP"; do [[ -b "$p" ]] || die "partition $p missing after sfdisk"; done

mkfs.fat -F32 -n EFI-SYSTEM "$ESP" >/dev/null
mkfs.ext4 -q -L boot "$BOOT"

# --------------------------------------------------------------------------- #
# 4) Encrypt: format LUKS2, enroll TPM2/PCR7, add a recovery key, drop bootstrap
# --------------------------------------------------------------------------- #
# Enrolls one LUKS2 volume: TPM2(PCR7) auto-unlock + a printed recovery key.
# Echoes the recovery key on stdout. Leaves the volume OPEN as /dev/mapper/$2.
enroll_luks() {  # $1=partition  $2=mapper-name
  local part="$1" name="$2" kf rec
  kf="$(mktemp /run/nialuks.XXXXXX)"; head -c 64 /dev/urandom > "$kf"
  cryptsetup luksFormat --type luks2 --batch-mode --pbkdf argon2id "$part" "$kf" >/dev/null
  cryptsetup open "$part" "$name" --key-file "$kf" >/dev/null
  # PolicyAuthorize under the sealed offline key. `--tpm2-pcrs=` MUST be empty:
  # its default is literal PCR7 and would silently reintroduce fleet lockout.
  systemd-cryptenroll --unlock-key-file="$kf" --tpm2-device=auto \
    --tpm2-seal-key-handle=0x81000001 --tpm2-pcrs= \
    --tpm2-public-key="$PCR_POLICY_KEY_RUNTIME" --tpm2-public-key-pcrs=7 "$part" >/dev/null
  # Escrow / client recovery key — the key is printed on stdout, prose on stderr.
  rec="$(systemd-cryptenroll --unlock-key-file="$kf" --recovery-key "$part" 2>/dev/null)"
  # Drop the bootstrap keyfile slot (slot 0): only TPM + recovery remain.
  # (cryptsetup refuses to kill a slot using that slot's own key; cryptenroll does.)
  systemd-cryptenroll --unlock-key-file="$kf" --wipe-slot=0 "$part" >/dev/null
  shred -u "$kf" 2>/dev/null || rm -f "$kf"
  printf '%s' "$rec"
}

assert_luks_srk_token() { # $1=LUKS partition $2=canonical evidence output
  local metadata
  metadata="$(mktemp /run/ni-luks-token.XXXXXX)"
  cryptsetup luksDump --dump-json-metadata "$1" > "$metadata" 2>/dev/null \
    || die "cannot inspect the TPM2 token enrolled on $1"
  /usr/libexec/neural-ice-luks-token-evidence "$metadata" "$INTENDED_SRK_PUBLIC" > "$2" \
    || die "the TPM2 token on $1 is not uniquely bound to the intended SRK, keyslot, PCR7 policy and sealed object"
  rm -f -- "$metadata"
}

log "Encrypting system volume (TPM PCR7 + recovery)…"
SYS_RECOVERY="$(enroll_luks "$SYSP" system)"
log "Encrypting data volume (TPM PCR7 + CLIENT recovery)…"
DATA_RECOVERY="$(enroll_luks "$DATAP" data)"
assert_luks_srk_token "$SYSP" /run/neural-ice-installer/system-luks-evidence.json
assert_luks_srk_token "$DATAP" /run/neural-ice-installer/data-luks-evidence.json
# This is the activation commit: both enrolled tokens have survived exact
# readback under the signed PolicyAuthorize key. Only now may the TPM remember
# the policy generation; a failed or partial enrollment burns no sequence.
[[ "$("$TPM_STATE" pcr-policy-activate "$PCR_POLICY_SEQ")" == "$PCR_POLICY_SEQ" ]] \
  || die "TPM refused to commit the activated PCR policy generation"

mkfs.xfs -q -L sysroot /dev/mapper/system
mkfs.xfs -q -L data    /dev/mapper/data

# Root (system) is unlocked in the initramfs via rd.luks kargs (below). The data
# volume is unlocked by the image-baked /etc/crypttab (by GPT label data-luks)
# and mounted via the systemd.mount-extra karg — so only these are needed here.
SYS_LUKS_UUID="$(cryptsetup luksUUID "$SYSP")"
SYS_FS_UUID="$(blkid -s UUID -o value /dev/mapper/system)"
BOOT_UUID="$(blkid -s UUID -o value "$BOOT")"

# --------------------------------------------------------------------------- #
# 5) Install the live image onto the encrypted root (native bootc method)
# --------------------------------------------------------------------------- #
phase 3 "Prepare the target filesystem for the deployment"
# bootc/ostree images symlink /mnt -> /var/mnt (dangling inside the install
# container) so a bind onto /mnt fails ("creating /mnt: No such file"). Use a
# real directory whose parent exists in the container image instead.
mount /dev/mapper/system "$TGT"
mkdir -p "$TGT/boot"
mount "$BOOT" "$TGT/boot"
mkdir -p "$TGT/boot/efi"
mount "$ESP" "$TGT/boot/efi"
install -d -m 0755 "$TGT/boot/efi/EFI/neural-ice"
install -m 0644 "$PCR_POLICY_SIGNATURE_RUNTIME" "$TGT/boot/efi/EFI/neural-ice/tpm2-pcr-signature.json"
install -m 0644 "$PCR_POLICY_KEY_RUNTIME" "$TGT/boot/efi/EFI/neural-ice/tpm2-pcr-public-key.pem"
# Make the target (+ submounts) shared so they propagate into the container.
mount --rbind "$TGT" "$TGT"
mount --make-rshared "$TGT"

# Optional operator SSH key, provisioned by the baked first-boot service.
sshkey_karg=()
[[ -n "$SSHKEY_B64" ]] && sshkey_karg=(--karg "neuralice.sshkey=$SSHKEY_B64")

phase 4 "bootc install to-filesystem (encrypted root, source: $INSTALL_SOURCE, OTA origin: $IMGREF)"
# --skip-fetch-check: offline/air-gapped install. The source is the local
# containers-storage; the target imgref is only the future OTA origin, not
# reachable from the installer env (no network) — verifying it would hang.
#
# 🔴 THIS FLAG NEVER APPLIES TO UNAUTHENTICATED BYTES. `--skip-fetch-check`
# concerns the TARGET imgref — the future OTA origin, which is not reachable from
# an air-gapped install environment. It says nothing about the SOURCE, and the
# source is the only thing being written to the disk:
#
#   medium path    containers-storage:<store image>, served by a dm-verity target
#                  whose root hash comes from a header the signed UKI seals, and
#                  re-proved against the kernel's tables above (§1a-0);
#   registry path  a digest-pinned object bound by a signed release authorization
#                  and inspected host-side before the disk was touched (§2b).
#
# bootc performs no independent re-verification of the source, which is precisely
# why both proofs are made here, before this line, rather than assumed.
# systemd-decoupled podman flags: the live installer's dbus/journald stack is
# broken (dbus-broker crash-loop), which wedges podman's default
# systemd-coupled subsystems (systemd cgroup manager, netavark bridge,
# journald log/event drivers) in futex_wait BEFORE bootc ever execs. The
# install needs no container network; logs pass straight through to the tty.
# bootc's own output streams to the tty (passthrough-tty) but has silent
# stretches; the heartbeat distinguishes them from a real hang.
# The source was RESOLVED, PULLED AND AUTHORISED in §2b, before the target disk
# was touched. Nothing may re-resolve it here: an image proven in one phase and
# fetched again in another is two different images that happen to share a name.
[[ -n "$RELEASE_AUTH_VERIFIED_REF" && "$source_imgref" == "$RELEASE_AUTH_VERIFIED_REF" ]] \
  || die "the install source changed after it was authorised; refusing to install an unproven object"
if [ "$INSTALL_SOURCE" = registry ]; then
  # The object must still be the local, content-addressed one that was verified.
  podman image exists "$OS_IMAGE" \
    || die "the authorised image is no longer present in local storage; refusing to re-fetch it after verification"
else
  # The medium path installs the sealed store's own image. Re-resolving it here
  # and requiring the SAME digest the registration observed is what stops a
  # second, writable store shadowing `localhost/bootc` between the two phases.
  _medium_now="$(podman --cgroup-manager=cgroupfs --events-backend=file \
    image inspect "$STORE_IMAGE_NAME" --format '{{.Digest}}' 2>/dev/null)" \
    || die "the sealed store's ${STORE_IMAGE_NAME} can no longer be inspected"
  [[ "$_medium_now" == "$MEDIUM_IMAGE_DIGEST" ]] \
    || die "${STORE_IMAGE_NAME} now resolves to $_medium_now, not the verified $MEDIUM_IMAGE_DIGEST; refusing to install an object that changed after it was proved"
fi

# The container that runs `bootc` is itself read out of the sealed store, and it
# must see the SAME storage configuration this script does — otherwise the
# `containers-storage:` source inside it would resolve against the container
# image's own config and find nothing (or, worse, something else). The appliance
# carries a seed-store storage.conf.d drop-in which overrides
# additionalimagestores. Export the complete config explicitly and cover that
# drop-in directory with an immutable empty directory for this one container;
# otherwise bootc resolves localhost/bootc against the future appliance seed
# path rather than the dm-verity store on the installation medium.
# No systemd.mask= karg for sysext/confext here: the ceremony/tmpfiles cycle
# is broken at its source (PrivateTmp=disconnected in the appliance's own
# unit, verified after finalize below), and a mask would have been a permanent
# karg disabling the very root-capable-extension gate the image installs.
heartbeat_start "bootc install to-filesystem"
podman --cgroup-manager=cgroupfs --events-backend=file run --rm --privileged \
  --net=host --log-driver=passthrough-tty --pid=host \
  --security-opt label=type:unconfined_t \
  -e CONTAINERS_STORAGE_CONF=/etc/containers/storage.conf \
  -v /dev:/dev -v /var/lib/containers:/var/lib/containers \
  -v "$STORE_MOUNT:$STORE_MOUNT:ro" \
  -v "$INSTALLER_STORAGE_ROOT:$INSTALLER_STORAGE_ROOT" \
  -v "$INSTALLER_STORAGE_CONF:/etc/containers/storage.conf:ro" \
  -v "$INSTALLER_STORAGE_DROPINS:/etc/containers/storage.conf.d:ro" \
  --mount "type=bind,source=$TGT,target=$TGT,bind-propagation=rshared" \
  "$STORE_IMAGE_NAME" \
  bootc install to-filesystem \
    --skip-fetch-check \
    --source-imgref "$source_imgref" \
    --target-imgref "$IMGREF" \
    --root-mount-spec "UUID=$SYS_FS_UUID" \
    --boot-mount-spec "UUID=$BOOT_UUID" \
    --karg "rd.luks.uuid=luks-$SYS_LUKS_UUID" \
    --karg "rd.luks.options=$SYS_LUKS_UUID=tpm2-device=auto" \
    --karg "systemd.mount-extra=/dev/mapper/data:$DATA_MOUNT:xfs:nofail" \
    --karg "neuralice.pcr_policy=$PCR_POLICY_DIGEST" \
    --karg "neuralice.pcr_policy_key=$PCR_POLICY_KEY_SHA256" \
    --karg "neuralice.pcr_policy_signature=$PCR_POLICY_SIGNATURE_SHA256" \
    --karg "neuralice.pcr_policy_seq=$PCR_POLICY_SEQ" \
    "${sshkey_karg[@]}" \
    "$TGT" \
  || die "bootc install to-filesystem failed"
bg_stop

# --------------------------------------------------------------------------- #
# 5a) Firmware boot-menu hygiene (docs/INSTALLER-UX-HARDENING.md):
#     - branded shim CSV on the INSTALLED ESP: if fallback.efi ever runs (NVRAM
#       loss), the recreated entry says "Neural ICE", never "Red Hat Enterprise
#       Linux" (the label baked into our RHEL-sourced signed shim).
#     - our own NVRAM entry "Neural ICE", first in BootOrder.
#     - drop stale HD() entries pointing at partitions that no longer exist
#       (wiped OSes) or at the live USB (a one-shot installer leaves no trace).
#     Best-effort: NVRAM quirks must never fail a successful install.
# --------------------------------------------------------------------------- #
shim_rel=""
shim_abs="$(find "$TGT/boot/efi/EFI" -maxdepth 2 -iname 'shimaa64.efi' 2>/dev/null | head -1)"
[[ -n "$shim_abs" ]] && shim_rel="${shim_abs#"$TGT"/boot/efi}"
for csv in "$TGT"/boot/efi/EFI/*/BOOT*.CSV; do
  [[ -f "$csv" ]] || continue
  loader="$(iconv -f UTF-16 -t UTF-8 "$csv" 2>/dev/null | head -1 | cut -d, -f1 | tr -d '\r\n')"
  : "${loader:=shimaa64.efi}"
  if { printf '\xff\xfe'
    printf '%s,Neural ICE,,Neural ICE CoreOS appliance\r\n' "$loader" | iconv -f UTF-8 -t UTF-16LE
  } > "$csv" 2>/dev/null; then
    log "Branded shim CSV: ${csv#"$TGT"/boot/efi/} -> Neural ICE"
  fi
done
if command -v efibootmgr >/dev/null && [[ -d /sys/firmware/efi/efivars && -n "$shim_rel" ]]; then
  present_guids="$(lsblk -rno PARTUUID | tr '[:upper:]' '[:lower:]')"
  usb_guids="$(lsblk -rno PARTUUID "/dev/$live_disk" | tr '[:upper:]' '[:lower:]')"
  while IFS= read -r line; do
    num="$(sed -n 's/^Boot\([0-9A-Fa-f]\{4\}\).*/\1/p' <<<"$line")"; [[ -n "$num" ]] || continue
    label="$(sed -e 's/^Boot[0-9A-Fa-f]\{4\}[* ]*//' -e 's/\t.*//' <<<"$line")"
    guid="$(sed -n 's/.*HD([0-9]*,GPT,\([0-9a-fA-F-]*\),.*/\1/p' <<<"$line" | tr '[:upper:]' '[:lower:]')"
    if [[ "$label" == "Neural ICE" ]] \
       || { [[ -n "$guid" ]] && ! grep -qx "$guid" <<<"$present_guids"; } \
       || { [[ -n "$guid" ]] && grep -qx "$guid" <<<"$usb_guids"; }; then
      if efibootmgr -b "$num" -B >/dev/null 2>&1; then
        log "NVRAM: dropped entry Boot$num ($label)"
      fi
    fi
  done < <(efibootmgr -v 2>/dev/null | grep '^Boot[0-9A-Fa-f]\{4\}')
  if efibootmgr --create --disk "$target" --part 1 --label "Neural ICE" \
       --loader "${shim_rel//\//\\}" >/dev/null 2>&1; then
    log "NVRAM: created 'Neural ICE' boot entry (first in BootOrder)"
  else
    log "warn: efibootmgr create failed — firmware will fall back to the branded CSV on first boot"
  fi
else
  log "warn: efibootmgr/efivars/shim unavailable — skipping NVRAM branding (CSV fallback stays branded)"
fi

# --------------------------------------------------------------------------- #
# 5b) OFFLINE RELEASE CLOSURE staging (only when §2c verified one).
#
# This block used to describe copying "the READY podman overlay store + the base
# HF models" onto the data volume, and that is exactly what P0 #2 was about: an
# overlay store is opaque, so "READY" was a claim nothing could check, and the
# copy happened after the disk was already destroyed. The seed is now a
# content-addressed closure verified in §2c, and what follows stages THAT.
# --------------------------------------------------------------------------- #
phase 5 "Seed staging (verified offline release closure -> encrypted data volume)"
# --------------------------------------------------------------------------- #
# 🔴 THE SEED THAT IS STAGED HERE IS THE ONE §2c PROVED, AND IT IS STAGED BY
# DIGEST (independent review 2026-09-02, P0 #2).
#
# WHAT THIS REPLACES. This phase used to mount `/dev/disk/by-partlabel/ni-seed`
# -- any device that claimed the label -- and `cp -a` its `store`, `models` and
# `payload` directories onto the already-encrypted data volume. Nothing about
# those bytes had been checked, and the disk was already gone.
#
# Now nothing is mounted here at all: §2c mounted the seed read-only by stable
# PARTUUID on this medium, verified the whole signed closure, and left it
# mounted. This phase copies the CONTENT-ADDRESSED trees -- the OCI layout and
# the content store, both named by digest -- onto the data volume, and then
# re-reads every staged object and requires it to hash to its own name again.
#
# The re-read is not paranoia about the copy: the verification in §2c proved the
# SOURCE, and this proves that what landed on the ENCRYPTED VOLUME is the same
# set of objects. A `cp` that silently truncated on a full filesystem would
# otherwise be discovered on first boot, on a machine with no installer left.
# --------------------------------------------------------------------------- #
# The seed-store dir must exist on the data volume in ALL editions -- containers-storage
# HARD-FAILS on a missing additionalimagestores path (no silent skip). It stays
# EMPTY here: the appliance's first boot imports from the verified OCI layout
# below, by digest, rather than inheriting an opaque overlay store nothing could
# verify. (tmpfiles.d also recreates it on every boot.)
mkdir -p /run/seed-dst
mount /dev/mapper/data /run/seed-dst
mkdir -p /run/seed-dst/seed-store
if [[ -n "$SEED_VERIFIED_ROOT" ]]; then
  seed_total=0
  seed_total="$(du -sb "$SEED_VERIFIED_ROOT" | awk '{print $1}')"
  install -d -m 0755 /run/seed-dst/release
  _seed_dst="/run/seed-dst/release/$SEED_CLOSURE"
  # A partial destination from an interrupted earlier attempt is not a source of
  # truth and is not merged with: it is removed and rebuilt.
  rm -rf -- "$_seed_dst"
  install -d -m 0755 "$_seed_dst"
  log "OFFLINE: staging the verified release closure sha256:${SEED_CLOSURE} onto the data volume — $(awk -v t="$seed_total" 'BEGIN{printf "%.1f", t / 2^30}') GiB total…"
  copy_progress_start "$seed_total" /run/seed-dst
  cp -a "$SEED_VERIFIED_ROOT/." "$_seed_dst/" \
    || die "cannot stage the verified release pack and object set onto the encrypted data volume"
  bg_stop
  heartbeat_start "seed flush to disk (sync)"
  sync
  bg_stop

  # 🔴 RE-VERIFY WHAT LANDED, not what was sent. The same verifier, the same
  # sealed closure hash, the same key -- now against the copy on the encrypted
  # volume. An install that cannot prove the staged closure must not report
  # success and leave the appliance to discover it on first boot.
  heartbeat_start "verifying the staged release closure on the data volume"
  "$NEURALICE_SEED_VERIFIER" verify-seed-closure \
    --seed-root "$_seed_dst" \
    --pubkey "$VERITY_ROOT_MOUNT/usr/lib/neural-ice/keys/release-authorization.pub" \
    --registry-host "$NEURALICE_RELEASE_AUTHORITY" \
    --hardware-target "$SEALED_HARDWARE_TARGET" \
    --access-profile "$SEALED_ACCESS_PROFILE" \
    --device-channel "$DEVICE_CHANNEL" \
    --trust-policy-id "$SEALED_TRUST_POLICY_ID" \
    --expect-closure "sha256:${SEED_CLOSURE}" \
    --expect-manifest "sha256:${SEED_MANIFEST_SHA256}" \
    --trusted-now "$SEED_TRUSTED_NOW" \
    --pcr-policy-digest "$PCR_POLICY_DIGEST" \
    --pcr-policy-public-key-sha256 "$PCR_POLICY_KEY_SHA256" \
    --pcr-policy-signature-sha256 "$PCR_POLICY_SIGNATURE_SHA256" \
    --pcr-policy-seq "$PCR_POLICY_SEQ" \
    || die "the release closure staged onto the data volume does not verify; refusing to finish an install whose offline objects cannot be proved"
  bg_stop
  # Label for the container runtime. Prefer the read-only image-store type; fall
  # back to the universally-present container_file_t (readable by container_t).
  # The data volume is mounted without a context= override, so these per-file
  # xattr labels persist.
  chcon -R -t container_ro_file_t "$_seed_dst" 2>/dev/null \
    || chcon -R -t container_file_t "$_seed_dst" 2>/dev/null \
    || log "  warn: chcon on the staged release closure failed (SELinux off in installer?) — relabel on first boot if needed"
  # The appliance's own pointer at the closure it was installed with. One line,
  # digest only: first boot resolves the tree from it and re-verifies before it
  # imports anything.
  printf '%s\n' "sha256:${SEED_CLOSURE}" > /run/seed-dst/release/CLOSURE
  printf '%s\n' "$NEURALICE_RELEASE_AUTHORITY" > /run/seed-dst/release/AUTHORITY
  printf '%s\n' "$DEVICE_CHANNEL" > /run/seed-dst/release/CHANNEL
  printf '%s\n' "$SEED_MANIFEST_SHA256" > /run/seed-dst/release/MANIFEST
  printf '%s\n' "$SEED_TRUSTED_NOW" > /run/seed-dst/release/TRUSTED-NOW
  printf '%s\n' "$PCR_POLICY_DIGEST" > /run/seed-dst/release/PCR-POLICY
  printf '%s\n' "$PCR_POLICY_KEY_SHA256" > /run/seed-dst/release/PCR-POLICY-KEY
  printf '%s\n' "$PCR_POLICY_SIGNATURE_SHA256" > /run/seed-dst/release/PCR-POLICY-SIGNATURE
  printf '%s\n' "$PCR_POLICY_SEQ" > /run/seed-dst/release/PCR-POLICY-SEQ
  sync
  log "OFFLINE: release closure staged and re-verified on the encrypted data volume."
  umount /run/seed-dst
  umount "$SEED_MOUNT" || die "cannot unmount the offline seed after staging"
else
  umount /run/seed-dst
  log "No offline release closure on this medium (LIGHT install) — empty seed store only."
fi

# --------------------------------------------------------------------------- #
# 5c) SELinux: label EVERYTHING this install created, with the TARGET's policy.
#     The installer runs permissive (§0) and bootc labels the image content, but
#     the deployment's /etc DIRECTORY itself and everything staged by this
#     script (payload, models, data dirs) end up unlabeled_t. On the first
#     ENFORCING boot a single unlabeled /etc is fatal: every confined service
#     (dbus-broker, journald, avahi, podman) is denied { search } on /etc and
#     the whole userspace collapses (root-caused live on the .72 GB10,
#     2026-07-13). Label with setfiles -F against the deployment's own
#     file_contexts, then VERIFY — an unlabeled install must not ship.
# --------------------------------------------------------------------------- #
phase 6 "Deployment prep + TPM device-root provisioning"
command -v setfiles >/dev/null || die "setfiles not available in the installer image"
# The deployment names are bootc/ostree-controlled and cannot contain hostile
# shell characters; ls keeps the established first-deployment selection here.
# shellcheck disable=SC2012
dep="$(ls -d "$TGT"/ostree/deploy/*/deploy/*.0 2>/dev/null | head -1)"
[[ -n "$dep" && -d "$dep" ]] || die "cannot locate the ostree deployment under $TGT"
stateroot="$(dirname "$(dirname "$dep")")"   # …/ostree/deploy/<name>
# This installer-only Live guard is intentionally not part of the installed
# deployment.  Keeping the base unit enabled makes first-boot and later
# attestation idempotent; leaving the guard would suppress both forever.
installer_device_root_dropin="$dep/etc/systemd/system/neural-ice-device-root.service.d/10-installer-only.conf"
[[ -f "$installer_device_root_dropin" && ! -L "$installer_device_root_dropin" ]] \
  || die "installer device-root Live guard is missing from the target deployment"
# bootc >= 1.16 remounts the target read-only while finalizing the install;
# every post-bootc mutation of the deployment below needs it writable again.
# Recovery: a remount failure dies BEFORE any mutation — the disk then holds a
# fully deployed but unconfigured OS, and the recovery path is unchanged from
# any post-bootc die: boot the one-shot media again and re-run the wipe
# install. A later mutation failure leaves exactly the same states as before
# this change. N-1: on bootc < 1.16 the target is still rw and the remount is
# an idempotent no-op; the change affects only the installer env, never the
# installed system or its upgrade path.
mount -o remount,rw "$TGT" \
  || die "cannot remount the target read-write after bootc finalize"
rm -f -- "$installer_device_root_dropin" \
  || die "cannot remove the installer-only device-root Live guard"
rmdir --ignore-fail-on-non-empty "$(dirname -- "$installer_device_root_dropin")" 2>/dev/null || true

# The first-boot ceremony unit is the pinned appliance's own
# (/usr/lib/systemd/system, shipped by ICE-CoreOS). Appliance digests before
# the 2026-09-04 re-pin ordered it After=systemd-tmpfiles-setup.service
# (explicitly and through PrivateTmp=yes) while systemd-sysext/confext are
# Requires=+After= this gate and Before= tmpfiles-setup: an ordering cycle that
# systemd 257 broke by skipping units at random on first boot. An /etc overlay
# and a generator used to bridge that from the medium; the bridge was retired
# at the re-pin. The installer now REFUSES such an image instead of patching
# it: a medium must not silently repair the appliance it deploys.
ceremony_unit_name=neural-ice-firstboot-tpm-ceremony.service
ceremony_unit="$dep/usr/lib/systemd/system/$ceremony_unit_name"
[[ -f "$ceremony_unit" && ! -L "$ceremony_unit" ]] \
  || die "the pinned appliance image ships no first-boot TPM ceremony unit"
# What systemd will run is the EFFECTIVE configuration: the fragment merged
# with every *.conf drop-in from each unit search path, where a later
# assignment overrides an earlier one, `Key = value` is legal and a trailing
# backslash continues the line. Checking the raw fragment alone would approve a
# unit whose drop-in re-adds the cycle. Normalise the whole set into one
# stream of `Key=value` lines and judge that. The deployment carries no
# /etc or /run override for this unit at all: the appliance ships none, and
# the retired bridge staged exactly such an override from the medium.
for override in \
  "$dep/etc/systemd/system/$ceremony_unit_name" \
  "$dep/etc/systemd/system/$ceremony_unit_name.d" \
  "$dep/etc/systemd/system.control/$ceremony_unit_name" \
  "$dep/etc/systemd/system.control/$ceremony_unit_name.d" \
  "$dep/usr/local/lib/systemd/system/$ceremony_unit_name" \
  "$dep/usr/local/lib/systemd/system/$ceremony_unit_name.d" \
  "$dep/etc/systemd/system-generators/neural-ice-firstboot-ceremony" \
  "$dep/etc/neural-ice/firstboot-tpm-ceremony.service"; do
  [[ ! -e "$override" && ! -L "$override" ]] \
    || die "the deployment overrides the pinned appliance's first-boot ceremony unit at $override (retired medium bridge, or a foreign drop-in); re-pin the medium"
done
ceremony_effective="$(
  {
    cat -- "$ceremony_unit"
    for dropin_dir in "$dep/usr/lib/systemd/system/$ceremony_unit_name.d" \
                      "$dep/usr/lib/systemd/system/service.d" \
                      "$dep/etc/systemd/system/service.d"; do
      [[ -d "$dropin_dir" ]] || continue
      for dropin in "$dropin_dir"/*.conf; do
        [[ -f "$dropin" ]] || continue
        printf '\n'; cat -- "$dropin"
      done
    done
  } | sed -e ':a' -e '/\\$/N; s/\\\n//; ta' \
    | sed -E -e 's/^[[:space:]]+//; s/[[:space:]]+$//' -e '/^[#;]/d' \
             -e 's/^([A-Za-z0-9_]+)[[:space:]]*=[[:space:]]*/\1=/'
)"
ceremony_effective_last() { # last assignment of a directive wins in systemd
  printf '%s\n' "$ceremony_effective" | grep -E "^$1=" | tail -n1 | cut -d= -f2-
}
[[ "$(ceremony_effective_last DefaultDependencies)" == no ]] \
  || die "the pinned appliance's first-boot ceremony unit keeps default dependencies (ordering cycle with sysext/confext); re-pin the medium to a fixed appliance digest"
! printf '%s\n' "$ceremony_effective" | grep -Eq '^(After|Before)=.*systemd-tmpfiles-setup\.service' \
  || die "the pinned appliance's first-boot ceremony unit orders against tmpfiles-setup (ordering cycle with sysext/confext); re-pin the medium"
! printf '%s\n' "$ceremony_effective" | grep -Eq '^(After|Before)=.*sysinit\.target' \
  || die "the pinned appliance's first-boot ceremony unit orders against sysinit.target (cycle with sshd.socket); re-pin the medium"
case "$(ceremony_effective_last PrivateTmp)" in
  ''|no|false|off|0|disconnected) ;;
  *) die "the pinned appliance's first-boot ceremony unit uses PrivateTmp=$(ceremony_effective_last PrivateTmp), which re-adds After=tmpfiles-setup (ordering cycle); re-pin the medium" ;;
esac
unset -f ceremony_effective_last
log "first-boot ceremony unit verified on the pinned appliance (effective config: DefaultDependencies=no, PrivateTmp=disconnected-compatible, no tmpfiles/sysinit edges, no /etc override)"

# The medium runs with a permissive container-signature policy so bootc can read
# its own local image through whatever transport it picks -- containers-storage
# while the media is written, oci:/proc/self/fd/N during copy-to-storage. See
# image/Containerfile.installer. That permissiveness MUST NOT reach the installed
# appliance: the deployment is written from the medium's own image, so without
# this the appliance would boot accepting any unsigned local image.
#
# The strict grafted policy travelled beside it, verbatim. Restoring it here is
# what keeps the exception scoped to the medium, and it is the same shape as the
# device-root guard removed just above: installer-only state, undone before the
# target ever boots.
strict_policy=/usr/lib/neural-ice-policy-strict.json
[[ -f "$strict_policy" && ! -L "$strict_policy" ]] \
  || die "the strict container policy is absent from this medium; refusing to install an appliance that would keep the permissive one"
install -d -m 0755 -- "$dep/etc/containers" \
  || die "cannot prepare /etc/containers on the target deployment"
install -m 0644 -- "$strict_policy" "$dep/etc/containers/policy.json" \
  || die "cannot restore the strict container policy onto the target deployment"
# Assert the restored file, not the copy: a policy that silently stayed
# permissive is exactly the failure this block exists to prevent, and it would
# only surface as an appliance that trusts unsigned images.
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); sys.exit(0 if d.get("default")==[{"type":"reject"}] and "docker" in d.get("transports",{}) else 1)' \
  "$dep/etc/containers/policy.json" \
  || die "the container policy restored onto the target is not the fail-closed grafted one"
echo "[neural-ice-autoinstall] Strict container signature policy restored on the target deployment."
# The mirror is an INSTALL-TIME convenience and must not survive onto the
# appliance: an installed machine that keeps pointing at a bench would silently
# stop being air-gapped the day that bench is gone -- or, worse, keep trusting a
# host nobody maintains. The deployment is written from the image, so no drop-in
# should be there; assert it instead of trusting the mechanism.
#
# This is the lesson of [[control-validates-can-not-is]]: the block above DEMANDS
# a strict policy, and without this one nothing would have CHECKED that the
# mirror stayed behind.
shopt -s nullglob
_leaked=("$dep"/etc/containers/registries.conf.d/*neural-ice-install-mirror*)
shopt -u nullglob
if (( ${#_leaked[@]} )); then
  rm -f -- "${_leaked[@]}" \
    || die "an install-time registry mirror reached the target and could not be removed: ${_leaked[*]}"
  log "WARNING: an install-time mirror drop-in reached the target deployment and was removed (${#_leaked[@]} file(s)); this should be impossible -- investigate the image build"
fi
# An `if`, not `[[ -n "$X" ]] && echo`. The `&&` form is safe HERE -- `set -e`
# exempts a failing command that is not the last of a `&&` list, verified by
# experiment on 2026-08-20 -- but it stops being safe the moment such a line
# becomes the last statement of the script, and this block sits near the end.
# The `if` costs one line and removes the dependence on that positional detail.
if [[ -n "$INSTALL_MIRROR" ]]; then
  echo "[neural-ice-autoinstall] Install-time LAN mirror ($INSTALL_MIRROR) did not travel to the target; it pulls from $INSTALL_REGISTRY_AUTHORITY."
fi
setype="$(sed -n 's/^SELINUXTYPE=//p' "$dep/usr/etc/selinux/config" 2>/dev/null | head -1)"
: "${setype:=targeted}"
fc="$dep/usr/etc/selinux/$setype/contexts/files/file_contexts"
[[ -f "$fc" ]] || die "target policy file_contexts not found: $fc"
# Create the exact non-exportable device-root on the installed machine's TPM
# and persist only its public identity in the new stateroot. The same image-
# baked helper attests it idempotently on every boot. An occupied/malformed
# 0x81010005 refuses; neither the PKI handle 0x81010004 nor the EK is touched.
/usr/libexec/neural-ice-device-root ensure \
  --identity "$stateroot/var/lib/neural-ice/ota/device-root-v1.json" \
  >/dev/null \
  || die "cannot provision and attest the dedicated TPM device-root"
log "Dedicated TPM device-root provisioned and attested at 0x81010005."

# --------------------------------------------------------------------------- #
# 6b) PERSIST THE EXACT FIRST-BOOT CEREMONY INTENT.
# TPM NV creation, access-profile enrollment and owner authorization sealing are
# one mandatory first-boot lifecycle. The installer persists only prerequisites:
# the attested device root, the exact intended SRK used by both LUKS tokens, and
# the signed profile/target/policy/issuance intent. No runtime readiness unit may
# start until that lifecycle creates and locks all fixed NV state, enrolls the
# anchor, locks its canonical evidence digest in TPM NV, then sets
# and destroys the random owner auth. No mutable receipt selects either path.
# --------------------------------------------------------------------------- #
if [ "$INSTALL_SOURCE" = registry ]; then
  _enrolled_profile="$img_profile"
else
  _enrolled_profile="$ACCESS_POLICY"
fi
[[ "$_enrolled_profile" == "$SEALED_ACCESS_PROFILE" ]] \
  || die "the installed image's access profile '$_enrolled_profile' is not the one this medium seals ('$SEALED_ACCESS_PROFILE'); refusing to anchor a posture nothing signed"
ota_state="$stateroot/var/lib/neural-ice/ota"
install -d -m 0700 "$ota_state"

# Publish each installer-created ceremony input atomically.  A power loss may
# leave the temporary file, but can never leave a partial final input that the
# first installed boot could mistake for a complete prerequisite set.
persist_ceremony_input() { # $1=source $2=final basename
  local source=$1 basename=$2 tmp final
  [[ "$basename" =~ ^[A-Za-z0-9_.-]+$ ]] || die "unsafe ceremony input name: $basename"
  final="$ota_state/$basename"
  [[ ! -e "$final" && ! -L "$final" ]] \
    || die "ceremony input already exists before publication: $final"
  tmp="$(mktemp "$ota_state/.ceremony-input.XXXXXX")"
  install -m 0600 -- "$source" "$tmp" \
    || die "cannot stage ceremony input $basename"
  sync -f "$tmp" || die "cannot fsync staged ceremony input $basename"
  mv -f -- "$tmp" "$final" || die "cannot publish ceremony input $basename"
  sync -f "$ota_state" || die "cannot fsync ceremony input directory"
}

persist_ceremony_input "$INTENDED_SRK_PUBLIC" srk-v1.tpm2b_public
# Registry issuance sequences are allocated by Fabric. Preserve that signed
# value exactly; this installed-root intent is published only after bootc has
# committed the install, and only the mandatory firstboot TPM ceremony consumes
# it into the absolute freshness high-water. The live installer never advances
# TPM freshness state.
_initial_issuance_seq="${RELEASE_AUTH_ISSUANCE_SEQ:-0}"
_intent_tmp="$(mktemp /run/neural-ice-installer/owner-ceremony-intent.XXXXXX)"
printf 'access_profile=%s\nhardware_target=%s\nsigned_boot_trust_policy_id=%s\ninitial_issuance_seq=%s\n' \
  "$_enrolled_profile" "$SEALED_HARDWARE_TARGET" "$SEALED_TRUST_POLICY_ID" \
  "$_initial_issuance_seq" > "$_intent_tmp"
persist_ceremony_input "$_intent_tmp" owner-ceremony-intent-v1
rm -f -- "$_intent_tmp"
_sealed_identity_sha256="$(printf '%s' "$SEALED_ANCHOR" | sha256sum | awk '{print tolower($1)}')"
if [[ "$INSTALL_SOURCE" == registry ]]; then
  _release_identity_sha256="$(sha256sum "$_auth_scratch/release-authorization.json" | awk '{print tolower($1)}')"
else
  _release_identity_sha256="$(printf '%s\0%s' "$SEALED_ANCHOR" "$SEALED_PAYLOAD_DIGEST" | sha256sum | awk '{print tolower($1)}')"
fi
_identity_tmp="$(mktemp /run/neural-ice-installer/owner-ceremony-install-identity.XXXXXX)"
python3 - "$INSTALL_SOURCE" "$_sealed_identity_sha256" "$_release_identity_sha256" \
  > "$_identity_tmp" <<'PY'
import json,sys
source,sealed,release=sys.argv[1:]
obj={"install_source":source,"installed_at":"1970-01-01T00:00:00Z","installer_sealed_identity_sha256":sealed,"release_identity_sha256":release,"schema":"neural-ice-owner-ceremony-install-identity-v1"}
print(json.dumps(obj,sort_keys=True,separators=(",",":")))
PY
persist_ceremony_input "$_identity_tmp" owner-ceremony-install-identity-v1.json
rm -f -- "$_identity_tmp"

# device-root-v1.json is created atomically by its immutable helper.  Restate
# durability for the complete required set, then fsync the parent one final time
# before the installer can report success or expose a reboot prompt.
for _ceremony_input in device-root-v1.json srk-v1.tpm2b_public \
  owner-ceremony-intent-v1 owner-ceremony-install-identity-v1.json; do
  [[ -f "$ota_state/$_ceremony_input" && ! -L "$ota_state/$_ceremony_input" ]] \
    || die "mandatory installed ceremony input is absent: $_ceremony_input"
  sync -f "$ota_state/$_ceremony_input" \
    || die "cannot fsync mandatory installed ceremony input: $_ceremony_input"
done
sync -f "$ota_state" || die "cannot fsync completed ceremony input directory"
log "Mandatory first-boot TPM ceremony intent persisted; runtime/SSH/OTA readiness remains blocked until completion."
if (( LAB_BASELINE_PRESENT == 1 )); then
  "$LAB_BASELINE_HANDOFF" install "$LAB_BASELINE_SNAPSHOT" "$stateroot/var" \
    || die "cannot persist the optional LAB baseline receipt pair"
  log "Optional LAB baseline receipt pair persisted for post-install verification."
fi
phase 7 "SELinux labels (deployment /etc,/var,/boot + data volume, target policy)"
# setfiles/chcon walk the whole staged data volume — silent but not hung.
heartbeat_start "SELinux labeling (setfiles/chcon)"
# Deployment /etc (the runtime /etc): -r makes paths match the policy as /etc/…
setfiles -F -r "$dep" "$fc" "$dep/etc" || die "setfiles failed on deployment /etc"
# Stateroot /var (the runtime /var): pre-created dirs get their policy labels.
setfiles -F -r "$stateroot" "$fc" "$stateroot/var" || die "setfiles failed on stateroot /var"
# /boot (kernel/initramfs/BLS entries; the ESP is vfat = no xattrs, skipped).
setfiles -F -r "$TGT" "$fc" "$TGT/boot" || true
# Data volume: bind it at its RUNTIME path under a fake root so file_contexts
# matches /var/lib/neural-ice/data/…; EXCLUDE seed-store (chcon'd to
# container_ro_file_t in §5b — the policy has no entry for it and -F would
# strip that label back to var_lib_t).
mountpoint -q /run/seed-dst || mount /dev/mapper/data /run/seed-dst
mkdir -p /run/nid-root/var/lib/neural-ice/data
mount --bind /run/seed-dst /run/nid-root/var/lib/neural-ice/data
setfiles -F -r /run/nid-root -e /run/nid-root/var/lib/neural-ice/data/seed-store \
  "$fc" /run/nid-root/var/lib/neural-ice/data \
  || die "setfiles failed on the data volume"
umount /run/nid-root/var/lib/neural-ice/data
# seed-store label for ALL editions. LIGHT creates the (empty) dir too but
# never runs the §5b chcon (seed branch only) — and podman stats this
# additionalimagestores path on EVERY invocation, so an unlabeled_t dir is
# denied under enforcing (Codex P1, PR #18). Idempotent for PRELOADED.
chcon -R -t container_ro_file_t /run/seed-dst/seed-store 2>/dev/null \
  || chcon -R -t container_file_t /run/seed-dst/seed-store 2>/dev/null \
  || die "cannot label seed-store for the container runtime"
bg_stop
# VERIFY (fail-closed): the two labels whose absence bricked the enforcing boot.
stat -c %C "$dep/etc" | grep -q ':etc_t:' \
  || die "deployment /etc is still not etc_t after setfiles — refusing to ship"
stat -c %C /run/seed-dst | grep -Eq ':(var_lib_t|var_t):' \
  || die "data volume root is still unlabeled after setfiles — refusing to ship"
umount /run/seed-dst 2>/dev/null || true
log "SELinux: labels applied and verified (deployment /etc = etc_t, data = policy defaults)."

# --------------------------------------------------------------------------- #
# 6) DATA volume config is NOT written post-install (an ostree deployment's /etc
#    is read-only right after bootc finalizes it). Unlock is image-baked
#    (/etc/crypttab by GPT label) and the mount is a systemd.mount-extra karg
#    (both supported bootc mechanisms) — nothing to do here but unmount.
# --------------------------------------------------------------------------- #
phase 8 "Finalize — flush, close volumes, escrow recovery keys"
heartbeat_start "final flush (sync + close volumes)"
sync
umount -R "$TGT" 2>/dev/null || true
cryptsetup close data 2>/dev/null || true
cryptsetup close system 2>/dev/null || true
bg_stop

# --------------------------------------------------------------------------- #
# 7) Escrow the recovery keys: back up to the USB ESP + show the CLIENT key.
# --------------------------------------------------------------------------- #
stamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
usb_esp="$(media_vfat_partition || true)"
usb_saved="(USB backup FAILED — record the key shown below NOW)"
esp_mp=""; esp_we_mounted=0
if [[ -n "${usb_esp:-}" ]]; then
  # The live system ALREADY mounts the USB EFI partition (e.g. at /boot/efi), so
  # mounting it a second time fails. Reuse the existing mountpoint (remount rw);
  # only mount it ourselves if it is not mounted yet.
  esp_mp="$(mounted_at "/dev/$usb_esp" || true)"
  if [[ -n "$esp_mp" ]]; then
    mount -o remount,rw "$esp_mp" 2>/dev/null || true
  else
    mkdir -p /run/usb-esp
    mount "/dev/$usb_esp" /run/usb-esp 2>/dev/null && { esp_mp=/run/usb-esp; esp_we_mounted=1; }
  fi
fi
if [[ -n "$esp_mp" ]] && ( : > "$esp_mp/.ni-wtest" ) 2>/dev/null; then
  rm -f "$esp_mp/.ni-wtest"
  recfile="$esp_mp/NEURAL-ICE-RECOVERY-${target_serial}.txt"
  {
    printf 'NEURAL ICE CoreOS — disk encryption recovery keys\r\n'
    printf 'Generated: %s\r\n' "$stamp"
    printf 'Appliance disk serial: %s\r\n\r\n' "$target_serial"
    printf '[CLIENT] DATA volume recovery key (keep this safe):\r\n  %s\r\n\r\n' "$DATA_RECOVERY"
    printf '[INTERNAL] SYSTEM volume recovery key (Neural ICE support):\r\n  %s\r\n\r\n' "$SYS_RECOVERY"
    printf 'Use: cryptsetup open <partition> <name>  then enter the recovery key.\r\n'
  } > "$recfile"
  sync
  usb_saved="Saved on the USB EFI partition: $(basename "$recfile")"
  if [[ "$esp_we_mounted" -eq 1 ]]; then
    umount /run/usb-esp 2>/dev/null || true
  fi
fi

# --------------------------------------------------------------------------- #
# 8) Done: prompt the operator (show CLIENT recovery key), then reboot.
# --------------------------------------------------------------------------- #
log "[${PHASE_TOTAL}/${PHASE_TOTAL}] done — install completed in $(fmt_dur "$SECONDS") total"
readonly TTY=/dev/tty1
{
  printf '\n\n'
  printf '  ============================================================\n'
  printf '   \033[1;32m✅  NEURAL ICE — INSTALLATION COMPLETE (ENCRYPTED)\033[0m\n'
  printf '  ------------------------------------------------------------\n'
  printf '   Full-disk encryption: system + data (TPM2, auto-unlock)\n'
  printf '\n'
  printf '   \033[1;33mCLIENT DATA RECOVERY KEY — write it down and keep it safe:\033[0m\n'
  printf '       \033[1;37m%s\033[0m\n' "$DATA_RECOVERY"
  printf '   %s\n' "$usb_saved"
  printf '  ------------------------------------------------------------\n'
  printf '   1) Press [Enter] to reboot onto the internal disk\n'
  printf '   2) Remove the USB drive DURING the reboot (once the screen clears)\n'
  printf '      — do NOT pull it before pressing Enter: the live installer runs\n'
  printf '        FROM the USB and needs it until the machine actually resets.\n'
  printf '  ============================================================\n\n'
} > "$TTY" 2>/dev/null || log "Installation complete (encrypted) — DATA recovery key: $DATA_RECOVERY"

if read -r _ < "$TTY" 2>/dev/null; then
  log "Confirmed — rebooting onto the internal disk…"
  # Cleanly unmount the TARGET filesystems FIRST — this flushes them, so the forced
  # reset below never leaves the freshly-installed system/data XFS dirty. The LIGHT
  # path leaves the data volume mounted at /run/seed-dst (its umount lives only in the
  # seed-present branch), and $TGT may still hold system/boot/esp. `umount` flushes,
  # so no separate global `sync` (a bare `sync` would also hit the USB live-root/ESP
  # and thrash if the operator pulls the USB a moment early — Codex #15).
  umount -R /run/seed-dst 2>/dev/null || true
  umount -R "$TGT"        2>/dev/null || true
  # The offline seed is mounted READ-ONLY, so leaving it mounted cannot dirty
  # anything; unmounting it is tidiness, and its failure is not a reason to stop
  # a completed install from rebooting.
  umount -R "$SEED_MOUNT" 2>/dev/null || true
  # IMMEDIATE forced reset: does NOT depend on writing/unmounting the USB fs (the
  # discarded installer media), so it survives an operator who pulls the USB a moment
  # too early instead of thrashing on I/O errors. Targets are already flushed above.
  systemctl reboot -ff || reboot -f
  # No interactive console: do NOT reboot (avoids the loop).
  log "No interactive console: remove the USB and power-cycle manually."
fi
