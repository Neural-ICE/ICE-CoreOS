#!/usr/bin/env bash
#
# MEASURED HARDWARE IDENTITY — the machine the medium is standing on, as the
# machine itself reports it.
#
# WHY THIS FILE EXISTS. `neuralice.hardware_target=` is sealed in the UKI and
# restated by /usr/lib/neural-ice/hardware-target, and both were compared only
# with EACH OTHER. Two copies of the same caller-supplied word agreeing is not a
# hardware binding: a medium built for `nvidia-gb10-arm64` booted on any other
# arm64 box satisfied every comparison the installer made, then wiped that box's
# disk. The identity has to come from the HARDWARE, not from the build inputs.
#
# WHAT IS MEASURED. In order of authority on this platform:
#
#   devicetree:<compatible>   /sys/firmware/devicetree/base/compatible — the
#                             property the kernel itself matches drivers on, a
#                             NUL-separated list rendered here as one comma
#                             separated string.
#   dmi:<vendor>|<product>|<board>
#                             /sys/class/dmi/id — SMBIOS, on machines that have
#                             it. Three fields, because a vendor string alone is
#                             not an appliance model.
#
# A machine that exposes NEITHER is not a machine this medium can identify, and
# the honest response to "I cannot tell what this is" before a full-disk wipe is
# to refuse. There is no third branch.
#
# WHY A FINGERPRINT LIST AND NOT A VENDOR STRING IN THE SOURCE. This repository
# is OPEN CORE and holds no ground truth about what a GB10 reports; a vendor
# string guessed here would be a check that passes on the wrong hardware or
# fails on the right one. So the accepted identities travel as SHA-256 digests of
# the canonical measurement, produced by running `measure` ON the reference
# appliance and staged into the image at
# /usr/lib/neural-ice/hardware-identity/<target>.fingerprints. An absent or empty
# list is a refusal, never a pass: absence fails closed.

if [[ -z "${NEURAL_ICE_HARDWARE_IDENTITY_LIB_LOADED:-}" ]]; then
  NEURAL_ICE_HARDWARE_IDENTITY_LIB_LOADED=1

  # Relative to a root prefix, so the same code serves the running system
  # (prefix "") and a test root, with no second code path for the tests.
  readonly NEURAL_ICE_HARDWARE_IDENTITY_RELDIR="usr/lib/neural-ice/hardware-identity"
  # A fingerprint list is one hash per line plus comments. Anything larger is a
  # corrupted or padded file, not a list.
  readonly NEURAL_ICE_HARDWARE_IDENTITY_MAX_BYTES=8192
  # A device-tree `compatible` or an SMBIOS triple is short. A megabyte of
  # attacker-controlled sysfs must not be read into memory before we decide.
  readonly NEURAL_ICE_HARDWARE_IDENTITY_MAX_MEASUREMENT_BYTES=1024
fi

# --------------------------------------------------------------------------- #
# Measure. $1 is a sysfs prefix ("" = this machine); the tests pass a directory.
# Prints ONE canonical line. Every byte outside the printable ASCII the two
# sources can legitimately carry is refused rather than normalised: a control
# character in a measured identity is either a corrupt sysfs or an attempt to
# make two different machines hash the same.
# --------------------------------------------------------------------------- #
hardware_identity_measure() {
  if (( $# > 1 )); then
    echo "hardware_identity_measure takes at most a sysfs prefix" >&2
    return 2
  fi
  local prefix=${1:-} value
  prefix=${prefix%/}

  local dt="$prefix/sys/firmware/devicetree/base/compatible"
  if [[ -f "$dt" && ! -L "$dt" ]]; then
    local size
    size="$(wc -c < "$dt")"
    (( size > 0 && size <= NEURAL_ICE_HARDWARE_IDENTITY_MAX_MEASUREMENT_BYTES )) || {
      echo "the device-tree compatible property has an implausible size ($size bytes)" >&2
      return 1
    }
    # NUL-separated strings, with a trailing NUL. tr renders the separators as
    # commas; the trailing one becomes a comma that is stripped below.
    value="$(tr '\0' ',' < "$dt")"
    value="${value%,}"
    hardware_identity_value_is_printable "$value" || {
      echo "the device-tree compatible property is not printable ASCII" >&2
      return 1
    }
    [[ -n "$value" ]] || {
      echo "the device-tree compatible property is empty" >&2
      return 1
    }
    printf 'devicetree:%s\n' "$value"
    return 0
  fi

  local dmi_dir="$prefix/sys/class/dmi/id" field parts=()
  if [[ -d "$dmi_dir" ]]; then
    for field in sys_vendor product_name board_name; do
      local path="$dmi_dir/$field" part
      [[ -f "$path" && ! -L "$path" ]] || {
        echo "SMBIOS exposes no $field; this machine cannot be identified" >&2
        return 1
      }
      local size
      size="$(wc -c < "$path")"
      (( size > 0 && size <= NEURAL_ICE_HARDWARE_IDENTITY_MAX_MEASUREMENT_BYTES )) || {
        echo "SMBIOS $field has an implausible size ($size bytes)" >&2
        return 1
      }
      # Trailing newline only: interior spaces are part of a product name.
      part="$(tr -d '\n' < "$path")"
      hardware_identity_value_is_printable "$part" || {
        echo "SMBIOS $field is not printable ASCII" >&2
        return 1
      }
      [[ -n "$part" ]] || {
        echo "SMBIOS $field is empty; this machine cannot be identified" >&2
        return 1
      }
      parts+=("$part")
    done
    printf 'dmi:%s|%s|%s\n' "${parts[0]}" "${parts[1]}" "${parts[2]}"
    return 0
  fi

  echo "this machine exposes neither a device-tree compatible property nor SMBIOS; it cannot be identified" >&2
  return 1
}

# Printable ASCII without the two characters the canonical form uses as
# separators, so a crafted product name cannot forge a second field.
hardware_identity_value_is_printable() {
  # The pattern lives in a variable: a bracket expression containing a literal
  # space cannot be written inline in [[ =~ ]] without the shell word-splitting
  # it, and a silently mis-parsed allowlist is worse than none.
  # ',' is legitimate — a device-tree compatible entry is `vendor,model` — but
  # '|' is the SMBIOS field separator and is refused everywhere, so a crafted
  # product name cannot forge a second field.
  local allowed='^[A-Za-z0-9._:,+/ -]*$'
  [[ "${1:-}" =~ $allowed ]]
}

hardware_identity_fingerprint() { # $1=sysfs prefix (optional)
  local measured
  measured="$(hardware_identity_measure "$@")" || return 1
  printf '%s' "$measured" | sha256sum | awk '{print tolower($1)}'
}

# --------------------------------------------------------------------------- #
# Read the accepted-fingerprint list for a target out of an image root. The list
# is part of the read-only /usr, so it is covered by whatever signs the image and
# — on the installer — by the dm-verity hash the UKI seals.
#   $1 root prefix   $2 hardware target
# --------------------------------------------------------------------------- #
hardware_identity_read_fingerprints() {
  if (( $# != 2 )); then
    echo "hardware_identity_read_fingerprints requires a root prefix and a hardware target" >&2
    return 2
  fi
  local root=${1%/} target=$2 path size line count=0
  [[ "$target" =~ ^[a-z0-9]([a-z0-9_-]{0,62}[a-z0-9])?$ ]] || {
    echo "'$target' is not a valid hardware target" >&2
    return 1
  }
  path="$root/$NEURAL_ICE_HARDWARE_IDENTITY_RELDIR/$target.fingerprints"
  [[ -f "$path" && ! -L "$path" ]] || {
    echo "no measured-identity fingerprint list for hardware target '$target' at $path" >&2
    return 1
  }
  size="$(wc -c < "$path")"
  (( size > 0 && size <= NEURAL_ICE_HARDWARE_IDENTITY_MAX_BYTES )) || {
    echo "the measured-identity fingerprint list has an implausible size: $path" >&2
    return 1
  }
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%%#*}"
    line="$(tr -d '[:space:]' <<<"$line")"
    [[ -n "$line" ]] || continue
    [[ "$line" =~ ^[0-9a-f]{64}$ ]] || {
      echo "the measured-identity fingerprint list carries a malformed entry: '$line' in $path" >&2
      return 1
    }
    printf '%s\n' "$line"
    count=$((count + 1))
  done < "$path"
  (( count > 0 )) || {
    echo "the measured-identity fingerprint list for '$target' is empty; absence fails closed" >&2
    return 1
  }
}

# --------------------------------------------------------------------------- #
# THE GATE. The machine this code is running on must be one of the machines the
# named target admits.
#   $1 root prefix   $2 hardware target   $3 sysfs prefix (optional, tests)
# Prints the measured identity on success.
# --------------------------------------------------------------------------- #
hardware_identity_assert_target() {
  if (( $# < 2 || $# > 3 )); then
    echo "hardware_identity_assert_target requires a root prefix and a hardware target" >&2
    return 2
  fi
  local root=$1 target=$2 sysfs=${3:-}
  local measured actual accepted
  measured="$(hardware_identity_measure "$sysfs")" || {
    echo "refusing to act as hardware target '$target' on a machine that cannot be identified" >&2
    return 1
  }
  actual="$(printf '%s' "$measured" | sha256sum | awk '{print tolower($1)}')"
  accepted="$(hardware_identity_read_fingerprints "$root" "$target")" || return 1
  grep -qx -- "$actual" <<<"$accepted" || {
    echo "this machine measures as '$measured' ($actual), which hardware target '$target' does not admit" >&2
    return 1
  }
  printf '%s\n' "$measured"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  command_name=${1:-}
  shift || true
  case "$command_name" in
    measure) hardware_identity_measure "$@" ;;
    fingerprint) hardware_identity_fingerprint "$@" ;;
    read-fingerprints) hardware_identity_read_fingerprints "$@" ;;
    assert-target) hardware_identity_assert_target "$@" ;;
    *)
      echo "usage: $0 {measure [SYSFS]|fingerprint [SYSFS]|read-fingerprints ROOT TARGET|assert-target ROOT TARGET [SYSFS]}" >&2
      exit 2
      ;;
  esac
fi
