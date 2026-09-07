#!/usr/bin/env bash
#
# The immutable, image-signed REMOTE-ACCESS POLICY.
#
# WHY THIS FILE EXISTS. Until now the only thing standing between a customer
# appliance and a shell was data on the installer's ESP: `neural-ice-autoinstall`
# accepted `ice-coreos/authorized_keys` from a mutable vfat partition, and the
# first-boot service honoured `neuralice.sshkey=` on EVERY non-debug image. Both
# inputs are attacker-writable on an otherwise correctly signed medium, so
# editing one file on a signed installer USB opened SSH on a `prod` image. The
# build-time lab-anchor check in build-installer-usb.sh does not help: it runs on
# the build host, and nothing re-states it at install time or at first boot.
#
# The anchor therefore has to travel INSIDE the signed image, where an attacker
# with write access to the medium cannot reach it. `/usr/lib/neural-ice/access-policy`
# is written at image build time from ${VARIANT}, lands in the read-only ostree
# /usr, and is covered by whatever signs the image. Every gate below is a
# question asked of that file, never of /etc, never of a label, never of a karg.
#
#   lab-managed          sealed posture (SELinux enforcing, no shell, sshd masked
#                        and keyless) but the installation medium MAY provision
#                        exactly one validated operator public key. This is how
#                        Neural ICE debugs its own lab appliances.
#   customer-locked      sealed posture and SSH provisioning is NEVER permitted.
#                        A karg or an ESP key is a refusal, not something to
#                        ignore: on a customer appliance its only possible origin
#                        is tampering. Software changes are signed OTA only;
#                        recovery is physical signed media, not a hidden shell.
#   developer-diagnostic the `debug` image — SELinux permissive, serial root
#                        autologin, sshd enabled. NOT a release posture: it must
#                        never be published to a channel, and ICE-Fabric maps it
#                        to no product ring. It is kept only as an explicitly
#                        non-release direct-digest developer diagnostic.
#
# The mapping from ${VARIANT} is mechanical and lives here alone so the image
# build, the installer and the first-boot service cannot drift apart.

# Sourced by the autoinstaller alongside installer-ssh-key.sh, and by the
# first-boot service. Guard the readonly constants so a second source is a no-op
# rather than a `readonly variable` failure under `set -e`.
if [[ -z "${NEURAL_ICE_ACCESS_POLICY_LIB_LOADED:-}" ]]; then
  NEURAL_ICE_ACCESS_POLICY_LIB_LOADED=1

  # Path RELATIVE to a root prefix, so the same code serves the running system
  # (prefix "") and a test root, without a second code path for the tests.
  readonly NEURAL_ICE_ACCESS_POLICY_RELPATH="usr/lib/neural-ice/access-policy"
  # The longest allowed value is 20 bytes; the bound exists so a corrupted or
  # substituted marker is refused rather than read into memory.
  readonly NEURAL_ICE_ACCESS_POLICY_MAX_BYTES=64
fi

# The single source of truth for VARIANT -> access policy. Fail-closed: an
# unknown variant yields no policy at all, so a new build flavour cannot inherit
# a permissive default by omission.
access_policy_for_variant() {
  if (( $# != 1 )); then
    echo "access_policy_for_variant requires exactly one VARIANT" >&2
    return 2
  fi
  case "$1" in
    prod) printf '%s\n' customer-locked ;;
    sealed-lab) printf '%s\n' lab-managed ;;
    debug) printf '%s\n' developer-diagnostic ;;
    *)
      echo "no access policy is defined for variant '$1'" >&2
      return 1
      ;;
  esac
}

access_policy_is_known() {
  case "${1:-}" in
    lab-managed | customer-locked | developer-diagnostic) return 0 ;;
    *) return 1 ;;
  esac
}

# Read the immutable marker from an image root. $1 is a root prefix ("" = the
# running system). Prints the policy; refuses anything that is not a small,
# regular, non-symlink file holding exactly one allowlisted value.
access_policy_read() {
  if (( $# != 1 )); then
    echo "access_policy_read requires a root prefix (may be empty)" >&2
    return 2
  fi
  local root=${1%/}
  local path="$root/$NEURAL_ICE_ACCESS_POLICY_RELPATH"

  [[ -f "$path" && ! -L "$path" ]] || {
    echo "immutable access policy is missing or not a regular file: $path" >&2
    return 1
  }
  local size
  size="$(wc -c < "$path")"
  (( size > 0 && size <= NEURAL_ICE_ACCESS_POLICY_MAX_BYTES )) || {
    echo "immutable access policy has an implausible size: $path" >&2
    return 1
  }
  local value
  value="$(tr -d '[:space:]' < "$path")"
  access_policy_is_known "$value" || {
    echo "immutable access policy is not recognised: '${value}' in $path" >&2
    return 1
  }
  printf '%s\n' "$value"
}

# May an installation medium provision an operator SSH key on an image carrying
# this policy? This is the ONLY place that answers that question.
access_policy_permits_installer_ssh() {
  case "${1:-}" in
    lab-managed | developer-diagnostic) return 0 ;;
    *) return 1 ;;
  esac
}

# The installer-side gate, extracted so it can be exercised without a disk.
#   $1 policy from the selected target image (may be empty = unreadable); on a
#      registry install the caller supplies it only after authenticating target
#   $2 install source: medium | registry
#   $3 1 when the medium supplies an SSH key (karg or ESP), 0 otherwise
#   $4 proof context: no-key | verified-medium-root |
#      authenticated-pulled-target
# Returns 0 to allow the install to continue, 1 to refuse. It refuses LOUDLY on
# a supplied key it may not honour: silently dropping it would hand the operator
# an appliance they believe is reachable, and hand an attacker a free retry.
access_policy_gate_installer_ssh() {
  if (( $# != 4 )); then
    echo "access_policy_gate_installer_ssh requires policy, install source, key presence and proof context" >&2
    return 2
  fi
  local policy=$1 install_source=$2 key_present=$3 proof_context=$4

  case "$install_source" in
    medium | registry) ;;
    *)
      echo "unknown install source '$install_source'" >&2
      return 1
      ;;
  esac
  case "$key_present" in
    0 | 1) ;;
    *)
      echo "key presence must be 0 or 1" >&2
      return 1
      ;;
  esac

  # An image with no readable policy is refused whether or not a key is present.
  # A missing marker means the source image is not one this installer
  # understands, and the honest response to that is to install nothing.
  access_policy_is_known "$policy" || {
    echo "the selected image carries no recognised immutable access policy" >&2
    return 1
  }
  if (( key_present == 0 )); then
    [[ "$proof_context" == no-key ]] || {
      echo "a keyless install requires the no-key proof context" >&2
      return 1
    }
    return 0
  fi

  access_policy_permits_installer_ssh "$policy" || {
    echo "access policy '$policy' forbids installer SSH provisioning; the supplied key or karg is refused" >&2
    return 1
  }

  case "$install_source:$proof_context" in
    medium:verified-medium-root) return 0 ;;
    registry:authenticated-pulled-target)
      # Registry provisioning is a LAB operator path only. Debug images are
      # direct-digest diagnostics, not registry release targets.
      [[ "$policy" == lab-managed ]] || {
        echo "registry SSH provisioning requires a lab-managed pulled target" >&2
        return 1
      }
      return 0
      ;;
    registry:*)
      echo "registry SSH provisioning requires the authenticated pulled-target proof" >&2
      return 1
      ;;
    *)
      echo "installer SSH proof context '$proof_context' does not match source '$install_source'" >&2
      return 1
      ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  command_name=${1:-}
  shift || true
  case "$command_name" in
    for-variant) access_policy_for_variant "$@" ;;
    read) access_policy_read "$@" ;;
    permits-installer-ssh) access_policy_permits_installer_ssh "$@" ;;
    gate-installer-ssh) access_policy_gate_installer_ssh "$@" ;;
    *)
      echo "usage: $0 {for-variant VARIANT|read ROOT|permits-installer-ssh POLICY|gate-installer-ssh POLICY SOURCE KEY_PRESENT PROOF_CONTEXT}" >&2
      exit 2
      ;;
  esac
fi
