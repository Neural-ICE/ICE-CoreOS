#!/bin/bash
# Assemble a generic installer medium (ADR-0044): the UNCHANGED signed UKI on the ESP + a payload partition with
# the signed release objects. No root, no loop device, no rebuild. Usage: assemble-media.sh UKI PAYLOAD_DIR OUT.img
set -euo pipefail
UKI="${1:?uki}"; PAY="${2:?payload dir}"; OUT="${3:?out image}"
need_mib() { echo $(( ($(du -sb "$1" | cut -f1) / 1048576) + 64 )); }
esp=$(need_mib "$UKI"); pay=$(need_mib "$PAY")
total=$(( esp + pay + 4 ))
truncate -s "${total}M" "$OUT"
sgdisk -Z "$OUT" >/dev/null
sgdisk -n 1:1M:+${esp}M -t 1:ef00 -c 1:ESP -n 2:0:+${pay}M -t 2:8300 -c 2:ni-payload "$OUT" >/dev/null
part() { sgdisk -i "$1" "$OUT" | awk -v k="$2" '$0 ~ k {print $3}'; }
for n in 1 2; do
  s=$(part $n "First sector"); e=$(part $n "Last sector"); f="$OUT.p$n"
  truncate -s $(( (e - s + 1) * 512 )) "$f"
  if [ $n = 1 ]; then mkfs.vfat -F 32 -n NIESP "$f" >/dev/null; mmd -i "$f" ::EFI ::EFI/BOOT; mcopy -i "$f" "$UKI" ::EFI/BOOT/BOOTAA64.EFI
  else mkfs.vfat -F 32 -n NIPAYLOAD "$f" >/dev/null; mcopy -s -i "$f" "$PAY"/* ::/; fi
  dd if="$f" of="$OUT" bs=512 seek="$s" conv=notrunc status=none; rm -f "$f"
done
sha256sum "$OUT"
