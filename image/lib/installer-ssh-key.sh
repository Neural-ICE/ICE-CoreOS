#!/usr/bin/env bash
# Validate and install the single operator SSH public key a LAB-MANAGED
# installation medium may carry.
#
# Renamed from debug-ssh-key.sh: the key has not been a "debug" facility since
# the first-boot service learned to serve it on a SEALED image. What it actually
# is, is the installer-provisioned operator key of a lab-managed appliance --
# `image/lib/access-policy.sh` decides whether an image accepts one at all, and
# this file decides whether a given byte string is acceptable AS a key.

# The key is base64-encoded into an installed ARM64 kernel command line. Keep
# enough headroom for the installer and bootc arguments within the 2 KiB ARM64
# command-line limit.
if [[ -z "${NEURAL_ICE_INSTALLER_SSH_KEY_LIB_LOADED:-}" ]]; then
  NEURAL_ICE_INSTALLER_SSH_KEY_LIB_LOADED=1
  readonly INSTALLER_SSH_PUBLIC_KEY_MAX_BYTES=512
fi

# Structure only, no approved hash. This is what the RUNTIME gates can check:
# the autoinstaller reads a key off the ESP and the first-boot service decodes
# one out of a karg, and neither has an approved digest to compare against --
# their trust anchor is the immutable access policy, not a hash. Build-time
# callers still go through installer_ssh_key_validate, which pins the hash too.
installer_ssh_key_validate_file() {
  if (( $# != 1 )); then
    echo "installer_ssh_key_validate_file requires a key file" >&2
    return 2
  fi
  local key_file=$1

  [[ -f "$key_file" && ! -L "$key_file" ]] || {
    echo "SSH public-key input must be a regular non-symlink file" >&2
    return 1
  }
  local key_size
  key_size="$(wc -c < "$key_file")"
  (( key_size > 0 && key_size <= INSTALLER_SSH_PUBLIC_KEY_MAX_BYTES )) || {
    echo "SSH public-key input must contain 1..${INSTALLER_SSH_PUBLIC_KEY_MAX_BYTES} bytes" >&2
    return 1
  }
  # Accept exactly one plain OpenSSH public-key record. In particular, do not
  # rely on `ssh-keygen -l` alone: it also fingerprints private-key files.
  if ! awk '
    BEGIN { records = 0 }
    /^[[:space:]]*$/ { next }
    {
      records++
      if (records != 1 || $1 !~ /^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh.com|sk-ecdsa-sha2-nistp256@openssh.com)$/ ||
          $2 !~ /^[A-Za-z0-9+\/]+={0,2}$/) {
        exit 1
      }
    }
    END { if (records != 1) exit 1 }
  ' "$key_file" || ! ssh-keygen -l -f "$key_file" >/dev/null; then
    echo "SSH input must be exactly one valid OpenSSH public key without options" >&2
    return 1
  fi
}

# The SEALED-BUILD assertion: this file must carry no authorized-keys record at
# all. Executable rather than inlined in the Containerfile so the suite can
# exercise the real predicate instead of grepping a Dockerfile for a regex.
#
# It asserts the ABSENCE OF CONTENT, not the absence of a recognised key shape.
# The check it replaces rejected only lines beginning with a key algorithm, so
# `restrict ssh-ed25519 AAAA... lab@host` -- an options-prefixed authorized_keys
# record that sshd accepts exactly like a bare one -- sailed through a build
# that claims to ship keyless. Every future options prefix, every algorithm this
# file has never heard of, and every comment line an operator might smuggle a
# key past a grep with are covered by the same rule: no non-whitespace byte.
# `printf '%s\n' "${SSH_AUTHORIZED_KEY}"` with an empty arg leaves exactly one
# newline behind, which is why whitespace -- and only whitespace -- passes.
installer_ssh_key_assert_keyless() {
  if (( $# != 1 )); then
    echo "installer_ssh_key_assert_keyless requires a keys file" >&2
    return 2
  fi
  local keys_file=$1

  [[ -f "$keys_file" && ! -L "$keys_file" ]] || {
    echo "keyless assertion needs a regular non-symlink file: $keys_file" >&2
    return 1
  }
  local content
  content="$(tr -d '[:space:]' < "$keys_file")"
  [[ -z "$content" ]] || {
    echo "a sealed image must ship no baked authorized key, but $keys_file has content" >&2
    return 1
  }
}

# The build-time path: an explicitly supplied public key, pinned by its exact
# SHA-256 so a mutable build-host pathname cannot silently change the key.
installer_ssh_key_validate() {
  if (( $# != 2 )); then
    echo "installer_ssh_key_validate requires a key file and approved SHA-256" >&2
    return 2
  fi
  local key_file=$1
  local approved_sha256=$2

  if [[ -z "$key_file" && -z "$approved_sha256" ]]; then
    return 0
  fi
  [[ -n "$key_file" ]] || {
    echo "SSH_AUTHORIZED_KEYS_SHA256 requires SSH_AUTHORIZED_KEYS_FILE" >&2
    return 1
  }
  [[ -f "$key_file" && ! -L "$key_file" ]] || {
    echo "SSH_AUTHORIZED_KEYS_FILE must be a regular non-symlink file" >&2
    return 1
  }
  [[ "$approved_sha256" =~ ^[0-9a-f]{64}$ ]] || {
    echo "SSH_AUTHORIZED_KEYS_SHA256 is required with the public key file" >&2
    return 1
  }
  [[ "$(sha256sum "$key_file" | awk '{print $1}')" == "$approved_sha256" ]] || {
    echo "SSH authorized_keys input differs from the approved hash" >&2
    return 1
  }
  installer_ssh_key_validate_file "$key_file"
}

installer_ssh_key_require_matching_target() {
  if (( $# != 3 )); then
    echo "installer_ssh_key_require_matching_target requires key file, base image and target image" >&2
    return 2
  fi
  local key_file=$1
  local base_image=$2
  local target_image=$3

  [[ -z "$key_file" || "$target_image" == "$base_image" ]] || {
    echo "an installer SSH key requires TARGET_IMGREF to equal the staged BASE_IMAGE" >&2
    return 1
  }
}

installer_ssh_key_install() {
  if (( $# != 3 )); then
    echo "installer_ssh_key_install requires a key file, approved SHA-256 and ESP root" >&2
    return 2
  fi
  local key_file=$1
  local approved_sha256=$2
  local esp_root=$3
  local namespace="$esp_root/ice-coreos"
  local destination="$namespace/authorized_keys"

  installer_ssh_key_validate "$key_file" "$approved_sha256"
  [[ -n "$key_file" ]] || {
    echo "installer SSH key install requires a key" >&2
    return 1
  }
  [[ -d "$esp_root" && ! -L "$esp_root" ]] || {
    echo "installer ESP root must be a real directory" >&2
    return 1
  }
  [[ ! -e "$destination" && ! -L "$destination" ]] || {
    echo "installer ESP already contains an SSH authorized_keys path" >&2
    return 1
  }

  if [[ -e "$namespace" || -L "$namespace" ]]; then
    [[ -d "$namespace" && ! -L "$namespace" ]] || {
      echo "installer ESP ice-coreos namespace must be a real directory" >&2
      return 1
    }
  else
    mkdir -m 0755 "$namespace"
  fi
  install -m 0644 "$key_file" "$destination"
  if [[ "$(sha256sum "$destination" | awk '{print $1}')" != "$approved_sha256" ]] ||
    ! installer_ssh_key_validate "$destination" "$approved_sha256"; then
    rm -f "$destination"
    echo "installer ESP SSH key readback failed validation" >&2
    return 1
  fi
  ssh-keygen -l -f "$destination" | sed 's/^/    [installer SSH] /'
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  command_name=${1:-}
  shift || true
  case "$command_name" in
    validate) installer_ssh_key_validate "$@" ;;
    validate-file) installer_ssh_key_validate_file "$@" ;;
    assert-keyless) installer_ssh_key_assert_keyless "$@" ;;
    install) installer_ssh_key_install "$@" ;;
    require-matching-target) installer_ssh_key_require_matching_target "$@" ;;
    *) echo "usage: $0 {validate KEY_FILE SHA256|validate-file KEY_FILE|assert-keyless KEYS_FILE|install KEY_FILE SHA256 ESP_ROOT|require-matching-target KEY_FILE BASE_IMAGE TARGET_IMAGE}" >&2; exit 2 ;;
  esac
fi
