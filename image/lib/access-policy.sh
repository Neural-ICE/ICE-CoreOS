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
#   $1 policy as read from the SOURCE image (may be empty = unreadable)
#   $2 install source: medium | registry
#   $3 1 when the medium supplies an SSH key (karg or ESP), 0 otherwise
# Returns 0 to allow the install to continue, 1 to refuse. It refuses LOUDLY on
# a supplied key it may not honour: silently dropping it would hand the operator
# an appliance they believe is reachable, and hand an attacker a free retry.
access_policy_gate_installer_ssh() {
  if (( $# != 3 )); then
    echo "access_policy_gate_installer_ssh requires policy, install source and key presence" >&2
    return 2
  fi
  local policy=$1 install_source=$2 key_present=$3

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
    echo "the source image carries no recognised immutable access policy" >&2
    return 1
  }
  (( key_present == 1 )) || return 0

  access_policy_permits_installer_ssh "$policy" || {
    echo "access policy '$policy' forbids installer SSH provisioning; the supplied key or karg is refused" >&2
    return 1
  }

  # On the registry path the deployment is written from an image PULLED at
  # install time, not from this medium -- so the policy read above describes the
  # live installer, not the system being installed. There is no honest way to
  # gate a key against an image we have not fetched yet, and fetching it first
  # would move the decision after the disk is already partitioned. Refuse.
  if [[ "$install_source" == registry ]]; then
    echo "installer SSH provisioning is only available when installing the medium's own image" >&2
    return 1
  fi
  return 0
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
      echo "usage: $0 {for-variant VARIANT|read ROOT|permits-installer-ssh POLICY|gate-installer-ssh POLICY SOURCE KEY_PRESENT}" >&2
      exit 2
      ;;
  esac
fi
