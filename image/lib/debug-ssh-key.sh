#!/usr/bin/env bash
# Validate and install an optional operator SSH public key on debug installer media.

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
  (( key_size > 0 && key_size <= 16384 )) || {
    echo "SSH authorized_keys input must contain 1..16384 bytes" >&2
    return 1
  }
  [[ "$(sha256sum "$key_file" | awk '{print $1}')" == "$approved_sha256" ]] || {
    echo "SSH authorized_keys input differs from the approved hash" >&2
    return 1
  }
  ssh-keygen -l -f "$key_file" >/dev/null || {
    echo "SSH authorized_keys input contains no valid public key" >&2
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
    ! ssh-keygen -l -f "$destination" >/dev/null; then
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
    *) echo "usage: $0 {validate KEY_FILE SHA256|install KEY_FILE SHA256 ESP_ROOT}" >&2; exit 2 ;;
  esac
fi
