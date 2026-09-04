#!/usr/bin/env bash
#
# THE INSTALLER'S ONLY FAILURE SURFACE: fixed, output-only, bounded evidence
# followed by an automatic terminal action.
#
# 🔴 WHAT THIS REPLACES (independent review 2026-09-02, P0 #1).
# neural-ice-autoinstall.service carried `OnFailure=emergency.target` with
# `OnFailureJobMode=isolate`, and the early runtime generator UNMASKED
# emergency/rescue/debug on every Install boot to make that sink reachable. So
# any preflight, authorisation, pull, storage, TPM or deployment failure handed
# whoever was standing at the machine a root shell on the console. Authorisation
# to wipe a disk is not authorisation to receive a root shell: the customer's
# other disks, the TPM, the network and every signed artefact on the medium are
# reachable from that shell, and none of them were part of what was authorised.
#
# 🔴 WHAT THIS IS, PRECISELY.
#
#   output only    there is no interactive process in this file, no read, no
#                  argument, no shell, and the unit sets StandardInput=null. The
#                  runtime generator masks getty@, serial-getty@, autovt@,
#                  console-getty, container-getty@, getty.target,
#                  systemd-user-sessions, user@, debug-shell, emergency and
#                  rescue on EVERY medium boot, Install included.
#   bounded         the evidence is a fixed set of keys with a fixed value shape.
#                  Anything else in the file is dropped, so a defect upstream can
#                  cost a missing field and never an unbounded console write.
#   stable          the code is a token from a closed vocabulary this repository
#                  owns; it is not a message, and it never carries an operator's
#                  input, a device path, a key, a digest of customer data or any
#                  byte that came off the network.
#   terminal        the machine powers off (or reboots) after a short delay read
#                  from the SIGNED read-only /usr. A failed install must not leave
#                  a machine sitting on a console indefinitely.
#
# The full diagnostic message stays in the journal, where it is reachable by the
# operator procedures in docs/RUNBOOK-GB10-CONSOLE-BOOT.md and never rendered on
# a console that a bystander can read.
set -uo pipefail

# Test seam: available only to an unprivileged process outside a release image.
readonly RELEASE_IMAGE_MARKER=/usr/lib/neural-ice/release-image
if [[ -n ${NEURALICE_FAILURE_EVIDENCE:-} || -n ${NEURALICE_FAILURE_POLICY:-} \
   || -n ${NEURALICE_EFI_FAILURE_EVIDENCE:-} \
   || ${1:-} == --dry-run ]]; then
  [[ $EUID -ne 0 ]] || { printf 'neural-ice-installer-failure: test overrides are forbidden to root\n' >&2; exit 2; }
  [[ ! -e $RELEASE_IMAGE_MARKER ]] \
    || { printf 'neural-ice-installer-failure: test overrides are forbidden in a release image\n' >&2; exit 2; }
fi
readonly EVIDENCE_FILE="${NEURALICE_FAILURE_EVIDENCE:-/run/neural-ice-installer-failure/evidence}"
readonly POLICY_FILE="${NEURALICE_FAILURE_POLICY:-/usr/lib/neural-ice/installer-failure-policy}"
readonly EFI_EVIDENCE_FILE="${NEURALICE_EFI_FAILURE_EVIDENCE:-/sys/firmware/efi/efivars/NeuralICEInstallerFailure-870a0500-25d2-574e-a1cc-79a69630bf96}"
DRY_RUN=0
case "${1:-}" in
  '')        ;;
  --dry-run) DRY_RUN=1 ;;
  *) printf 'neural-ice-installer-failure: this surface takes no arguments\n' >&2; exit 2 ;;
esac
readonly DRY_RUN

# --------------------------------------------------------------------------- #
# THE CLOSED EVIDENCE VOCABULARY. A key not named here is not printed, and a
# value that is not one plain bounded token is replaced by `unclassified`.
# Neither the installer nor anything it read can widen this.
# --------------------------------------------------------------------------- #
readonly EVIDENCE_SCHEMA=neural-ice-installer-failure-evidence-v1
readonly -a EVIDENCE_KEYS=(
  schema code phase phase_total stage detail
  pcr7 pcr7_policy pcr7_verified pcr7_verified_count
)
readonly VALUE_SHAPE='^[A-Za-z0-9][A-Za-z0-9._:/-]{0,63}$'
readonly EVIDENCE_MAX_BYTES=2048

declare -A EVIDENCE=()

evidence_key_is_known() { # $1=key
  local key
  for key in "${EVIDENCE_KEYS[@]}"; do
    [ "$key" = "$1" ] && return 0
  done
  return 1
}

evidence_value_is_valid() { # $1=key $2=value
  case "$1" in
    pcr7|pcr7_policy)
      [[ "$2" == unavailable || "$2" =~ ^[0-9a-f]{64}$ ]]
      ;;
    pcr7_verified)
      [[ "$2" == none || "$2" =~ ^[0-9a-f]{64}(,[0-9a-f]{64}){0,3}$ ]]
      ;;
    pcr7_verified_count)
      [[ "$2" =~ ^[0-9]{1,4}$ ]]
      ;;
    *)
      [[ "$2" =~ $VALUE_SHAPE ]]
      ;;
  esac
}

# The evidence file lives on a tmpfs the installer's own unit created with
# RuntimeDirectory=; it is root-owned 0700 and is never read from a medium, a
# network or a customer filesystem. It is nonetheless parsed as untrusted input:
# the installer that wrote it is the thing that just failed.
read_evidence() {
  local line key value
  [ -f "$EVIDENCE_FILE" ] && [ ! -L "$EVIDENCE_FILE" ] || return 0
  while IFS= read -r line; do
    case "$line" in *=*) ;; *) continue ;; esac
    key="${line%%=*}"; value="${line#*=}"
    evidence_key_is_known "$key" || continue
    evidence_value_is_valid "$key" "$value" || continue
    [ -z "${EVIDENCE[$key]:-}" ] || continue   # first occurrence wins; no last-writer
    EVIDENCE["$key"]="$value"
  done < <(head -c "$EVIDENCE_MAX_BYTES" -- "$EVIDENCE_FILE" 2>/dev/null | tr -d '\000')
  return 0
}

value() { # $1=key
  local got=${EVIDENCE[$1]:-}
  printf '%s' "${got:-unclassified}"
}

persist_efi_evidence() {
  local payload
  printf -v payload 'schema=%s\ncode=%s\nphase=%s\nphase_total=%s\nstage=%s\ndetail=%s\npcr7=%s\npcr7_policy=%s\npcr7_verified=%s\npcr7_verified_count=%s\n' \
    "$EVIDENCE_SCHEMA" "$(value code)" "$(value phase)" "$(value phase_total)" \
    "$(value stage)" "$(value detail)" "$(value pcr7)" "$(value pcr7_policy)" \
    "$(value pcr7_verified)" "$(value pcr7_verified_count)"
  if [[ -d "${EFI_EVIDENCE_FILE%/*}" && ! -L "$EFI_EVIDENCE_FILE" ]]; then
    printf '\x07\x00\x00\x00%s' "$payload" > "$EFI_EVIDENCE_FILE" 2>/dev/null || true
  fi
}

# --------------------------------------------------------------------------- #
# THE TERMINAL ACTION, READ FROM THE SIGNED ROOT. The policy file lives in the
# dm-verity-protected /usr the UKI's .cmdline seals by root hash, so the action
# and the delay are covered by the medium's signature: neither is an operator's
# choice at failure time, and neither can be edited on the ESP.
# --------------------------------------------------------------------------- #
readonly DEFAULT_ACTION=poweroff
readonly DEFAULT_DELAY=60
readonly DELAY_MIN=5
readonly DELAY_MAX=300

read_policy() { # -> "<action> <delay-seconds>"
  local action=$DEFAULT_ACTION delay=$DEFAULT_DELAY line key raw
  if [ -f "$POLICY_FILE" ] && [ ! -L "$POLICY_FILE" ]; then
    while IFS= read -r line; do
      case "$line" in ''|'#'*) continue ;; *=*) ;; *) continue ;; esac
      key="${line%%=*}"; raw="${line#*=}"
      case "$key" in
        action)
          case "$raw" in poweroff|reboot) action="$raw" ;; esac
          ;;
        delay_seconds)
          if [[ "$raw" =~ ^[0-9]{1,3}$ ]] && [ "$raw" -ge "$DELAY_MIN" ] && [ "$raw" -le "$DELAY_MAX" ]; then
            delay="$raw"
          fi
          ;;
      esac
    done < <(head -c 256 -- "$POLICY_FILE" 2>/dev/null | tr -d '\000')
  fi
  printf '%s %s' "$action" "$delay"
}

read_evidence
persist_efi_evidence
read -r ACTION DELAY <<<"$(read_policy)"
readonly ACTION DELAY

printf '\n'
printf '  Neural ICE CoreOS — INSTALL FAILED\n'
printf '  ----------------------------------------------------------------------\n'
printf '  Nothing further will be attempted on this machine. There is no login,\n'
printf '  no shell and no recovery console on a Neural ICE installation medium.\n'
printf '  ----------------------------------------------------------------------\n'
printf '\n'
printf '  %-18s %s\n' 'failure code'   "$(value code)"
printf '  %-18s %s / %s\n' 'stage'     "$(value phase)" "$(value phase_total)"
printf '  %-18s %s\n' 'stage name'     "$(value stage)"
printf '  %-18s %s\n' 'evidence'       "$(value detail)"
printf '  %-18s %s\n' 'live PCR7'      "$(value pcr7)"
printf '  %-18s %s\n' 'computed policy' "$(value pcr7_policy)"
printf '  %-18s %s\n' 'verified count' "$(value pcr7_verified_count)"
if [[ "$(value pcr7_verified)" != none && "$(value pcr7_verified)" != unclassified ]]; then
  IFS=, read -r -a verified_policies <<<"$(value pcr7_verified)"
  for policy in "${verified_policies[@]}"; do
    printf '  %-18s %s\n' 'verified policy' "$policy"
  done
fi
printf '  %-18s %s\n' 'schema'         "$EVIDENCE_SCHEMA"
printf '\n'
printf '  The full diagnostic is in this boot'"'"'s journal on the medium only. It\n'
printf '  is deliberately not printed here: a console is read by whoever is\n'
printf '  standing at the machine, and this one may hold a customer appliance.\n'
printf '\n'
printf '  Report the failure code and stage above to Neural ICE support. Cut a\n'
printf '  fresh signed medium rather than re-running this one.\n'
printf '\n'
printf '  This machine will %s in %s seconds.\n' "$ACTION" "$DELAY"
printf '\n'

if [ "$DRY_RUN" = 1 ]; then
  printf 'DRY-RUN: would %s after %s seconds\n' "$ACTION" "$DELAY"
  exit 0
fi

sleep "$DELAY"
# `systemctl --force` so a wedged unit cannot hold the transition open: the
# install already failed, and there is nothing on this machine left to shut down
# cleanly. The direct fallbacks exist because a failed install is exactly the
# state in which the manager may itself be unhappy.
systemctl --force "$ACTION" 2>/dev/null \
  || systemctl --force --force "$ACTION" 2>/dev/null \
  || { [ "$ACTION" = reboot ] && reboot -f; } 2>/dev/null \
  || poweroff -f 2>/dev/null \
  || true
# The action above does not return on a healthy machine. Sleeping rather than
# exiting means a manager that ignored it still finds this unit occupied instead
# of finding a completed oneshot and moving on to whatever is next.
while true; do sleep 3600; done
