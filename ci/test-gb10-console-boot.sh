#!/usr/bin/env bash
set -euo pipefail

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

modprobe_config=image/bootc-overlay/usr/lib/modprobe.d/90-neural-ice-nvidia-drm.conf
vconsole_config=image/bootc-overlay/etc/vconsole.conf
modules_load=image/bootc-overlay/etc/modules-load.d/nvidia.conf
containerfile=image/Containerfile.bootc

[[ -f "$modprobe_config" ]] || fail "missing immutable nvidia_drm configuration"
[[ -f "$vconsole_config" ]] || fail "missing vconsole configuration"

mapfile -t modprobe_lines < <(sed '/^[[:space:]]*#/d; /^[[:space:]]*$/d' "$modprobe_config")
[[ "${#modprobe_lines[@]}" -eq 1 ]] || fail "nvidia_drm config must contain one effective line"
[[ "${modprobe_lines[0]}" == "options nvidia_drm modeset=1 fbdev=1" ]] \
  || fail "nvidia_drm must enable modeset and fbdev at initial load"

mapfile -t vconsole_lines < <(sed '/^[[:space:]]*#/d; /^[[:space:]]*$/d' "$vconsole_config")
[[ "${#vconsole_lines[@]}" -eq 1 ]] || fail "vconsole config must contain one effective line"
[[ "${vconsole_lines[0]}" == "FONT=default8x16" ]] \
  || fail "vconsole must select default8x16"

mapfile -t nvidia_modules < <(sed '/^[[:space:]]*#/d; /^[[:space:]]*$/d' "$modules_load")
expected_modules=(nvidia nvidia_modeset nvidia_drm nvidia_uvm)
[[ "${nvidia_modules[*]}" == "${expected_modules[*]}" ]] \
  || fail "NVIDIA modules must load in dependency and console order"

grep -Fq '/usr/lib/modprobe.d/90-neural-ice-nvidia-drm.conf /etc/vconsole.conf %s' \
  "$containerfile" || fail "dracut install_items must carry console configuration"
grep -Fq 'force_drivers+=" nvidia nvidia_modeset nvidia_drm nvidia_uvm "' \
  "$containerfile" || fail "dracut must force the NVIDIA stack at initial load"

for required in \
  'gsp_ga10x.bin' \
  '90-neural-ice-nvidia-drm.conf' \
  'vconsole.conf' \
  'default8x16'; do
  grep -Fq "$required" "$containerfile" \
    || fail "initramfs build assertion missing for $required"
done

printf 'GB10 console boot artifacts: OK\n'
