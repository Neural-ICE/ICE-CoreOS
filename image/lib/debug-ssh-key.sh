#!/usr/bin/env bash
# Validate and install an optional operator SSH public key on debug installer media.

# The key is base64-encoded into an installed ARM64 kernel command line. Keep
# enough headroom for the installer and bootc arguments within the 2 KiB ARM64
# command-line limit.
readonly DEBUG_SSH_PUBLIC_KEY_MAX_BYTES=512

debug_ssh_key_validate() {
  if (( $# != 2 )); then
    echo "debug_ssh_key_validate requires a key file and approved SHA-256" >&2
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
  local key_size
  key_size="$(wc -c < "$key_file")"
  (( key_size > 0 && key_size <= DEBUG_SSH_PUBLIC_KEY_MAX_BYTES )) || {
    echo "SSH public-key input must contain 1..${DEBUG_SSH_PUBLIC_KEY_MAX_BYTES} bytes" >&2
    return 1
  }
  [[ "$(sha256sum "$key_file" | awk '{print $1}')" == "$approved_sha256" ]] || {
    echo "SSH authorized_keys input differs from the approved hash" >&2
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

debug_ssh_key_require_debug_target() {
  if (( $# != 3 )); then
    echo "debug_ssh_key_require_debug_target requires key file, base image and target image" >&2
    return 2
  fi
  local key_file=$1
  local base_image=$2
  local target_image=$3

  [[ -z "$key_file" || "$target_image" == "$base_image" ]] || {
    echo "debug SSH key requires TARGET_IMGREF to equal the approved debug BASE_IMAGE" >&2
    return 1
  }
}

debug_ssh_key_install() {
  if (( $# != 3 )); then
    echo "debug_ssh_key_install requires a key file, approved SHA-256 and ESP root" >&2
    return 2
  fi
  local key_file=$1
  local approved_sha256=$2
  local esp_root=$3
  local namespace="$esp_root/ice-coreos"
  local destination="$namespace/authorized_keys"

  debug_ssh_key_validate "$key_file" "$approved_sha256"
  [[ -n "$key_file" ]] || {
    echo "debug SSH key install requires a key" >&2
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
    ! debug_ssh_key_validate "$destination" "$approved_sha256"; then
    rm -f "$destination"
    echo "installer ESP SSH key readback failed validation" >&2
    return 1
  fi
  ssh-keygen -l -f "$destination" | sed 's/^/    [debug SSH] /'
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  command_name=${1:-}
  shift || true
  case "$command_name" in
    validate) debug_ssh_key_validate "$@" ;;
    install) debug_ssh_key_install "$@" ;;
    require-debug-target) debug_ssh_key_require_debug_target "$@" ;;
    *) echo "usage: $0 {validate KEY_FILE SHA256|install KEY_FILE SHA256 ESP_ROOT|require-debug-target KEY_FILE BASE_IMAGE TARGET_IMAGE}" >&2; exit 2 ;;
  esac
fi
