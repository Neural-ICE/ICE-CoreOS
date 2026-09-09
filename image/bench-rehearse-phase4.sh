#!/usr/bin/env bash
# Rehearse phase 4 of the installer -- `bootc install to-filesystem` -- on the
# bench, against a loop-device target laid out exactly as the installer lays out
# the appliance disk (ESP vfat, boot ext4, sysroot xfs, mounted at one target
# with --rbind/--make-rshared), from the SAME container, with the SAME mounts
# the installer gives it: the lent fuse-overlayfs helper, the masked
# bound-images.d and the installer's permissive signature policy.
#
# 2026-09-09: this run reproduced, in 30 s, the hardware refusal of attempt 14
# ("Running image containers-storage:[...] is rejected by policy") and proved
# the fix in 44 s ("Installation complete!"). Nothing here touches a real disk,
# a TPM or the network beyond the local container storage.
#
# Usage (root, on a bench host whose container storage holds the appliance):
#   image/bench-rehearse-phase4.sh --image <appliance ref@digest> \
#       --pcr-policy-signature <json> --pcr-policy-key <pem> [--work-dir DIR] [--size 40G]
set -euo pipefail
IMAGE='' SIG='' KEY='' WORK=/var/tmp/ni-phase4-rehearsal SIZE=40G
while [[ $# -gt 0 ]]; do
  case "$1" in
    --image) IMAGE=$2; shift 2 ;;
    --pcr-policy-signature) SIG=$2; shift 2 ;;
    --pcr-policy-key) KEY=$2; shift 2 ;;
    --work-dir) WORK=$2; shift 2 ;;
    --size) SIZE=$2; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[[ -n "$IMAGE" && -f "$SIG" && -f "$KEY" ]] || { echo "usage: --image REF --pcr-policy-signature FILE --pcr-policy-key FILE" >&2; exit 2; }
[[ "$(id -u)" -eq 0 ]] || { echo "loop devices and mounts need root" >&2; exit 2; }
[[ "$SIZE" =~ ^[0-9]+[GM]$ ]] || { echo "--size must be like 40G" >&2; exit 2; }
for tool in podman losetup sgdisk mkfs.fat mkfs.ext4 mkfs.xfs blkid udevadm; do
  command -v "$tool" >/dev/null || { echo "missing tool: $tool" >&2; exit 2; }
done
[[ -x /usr/bin/fuse-overlayfs ]] || { echo "the bench host must have /usr/bin/fuse-overlayfs to lend, as the installer does" >&2; exit 2; }
podman image exists "$IMAGE" || { echo "the appliance image is not in the local container storage: $IMAGE" >&2; exit 2; }

rm -rf -- "$WORK"; install -d -m 0700 "$WORK"; TGT="$WORK/target"; install -d "$TGT"
LOOP=''
cleanup() {
  umount -R "$TGT" 2>/dev/null || true
  [[ -z "$LOOP" ]] || losetup -d "$LOOP" 2>/dev/null || true
}
trap cleanup EXIT
truncate -s "$SIZE" "$WORK/disk.img"
sgdisk --clear -n 1:0:+1G -t 1:EF00 -n 2:0:+1G -t 2:8300 -n 3:0:0 -t 3:8300 "$WORK/disk.img" >/dev/null
LOOP="$(losetup --find --show -P "$WORK/disk.img")"; udevadm settle
mkfs.fat -F32 -n EFI-SYSTEM "${LOOP}p1" >/dev/null
mkfs.ext4 -q -L boot "${LOOP}p2"
mkfs.xfs -q -L sysroot "${LOOP}p3"
# The installer's phase 3, minus LUKS (a loop file stands in for /dev/mapper/system).
mount "${LOOP}p3" "$TGT"; install -d "$TGT/boot"; mount "${LOOP}p2" "$TGT/boot"
install -d "$TGT/boot/efi"; mount "${LOOP}p1" "$TGT/boot/efi"
install -d -m 0755 "$TGT/boot/efi/EFI/neural-ice"
install -m 0644 "$SIG" "$TGT/boot/efi/EFI/neural-ice/tpm2-pcr-signature.json"
install -m 0644 "$KEY" "$TGT/boot/efi/EFI/neural-ice/tpm2-pcr-public-key.pem"
printf 'schema=1\npcr7_sha256=%s\npolicy_pcr_sha256=%s\navailable_policy_pcr_sha256=%s\n' \
  "$(printf '0%.0s' {1..64})" "$(printf '0%.0s' {1..64})" "$(printf '0%.0s' {1..64})" \
  > "$TGT/boot/efi/EFI/neural-ice/tpm2-pcr7-at-install.txt"
mount --rbind "$TGT" "$TGT"; mount --make-rshared "$TGT"
SYS_UUID="$(blkid -s UUID -o value "${LOOP}p3")"; BOOT_UUID="$(blkid -s UUID -o value "${LOOP}p2")"
install -d -m 0555 "$WORK/bound-images-mask"
# The installer's medium policy: permissive; the source was authorised before
# the wipe by the installer itself (release authorization + signature).
printf '{"default":[{"type":"insecureAcceptAnything"}]}\n' > "$WORK/policy.json"
echo "== bootc install to-filesystem rehearsal on $LOOP ($(date -u +%FT%TZ))"
start=$SECONDS
set +e
podman --cgroup-manager=cgroupfs --events-backend=file run --pull=never --rm --privileged \
  --net=host --pid=host --security-opt label=type:unconfined_t \
  -v /dev:/dev -v /var/lib/containers:/var/lib/containers \
  -v /usr/bin/fuse-overlayfs:/usr/bin/fuse-overlayfs:ro \
  -v "$WORK/bound-images-mask:/usr/lib/bootc/bound-images.d:ro" \
  -v "$WORK/policy.json:/etc/containers/policy.json:ro" \
  --mount "type=bind,source=$TGT,target=$TGT,bind-propagation=rshared" \
  "$IMAGE" bootc install to-filesystem --skip-fetch-check \
    --source-imgref "containers-storage:$IMAGE" --target-imgref "$IMAGE" \
    --root-mount-spec "UUID=$SYS_UUID" --boot-mount-spec "UUID=$BOOT_UUID" \
    --karg "rd.luks.uuid=luks-00000000-0000-0000-0000-000000000000" \
    --karg "neuralice.pcr_policy_seq=1" \
    "$TGT" > "$WORK/bootc.log" 2>&1
rc=$?
set -e
echo "bootc rc=$rc in $((SECONDS - start))s; log: $WORK/bootc.log"
tail -n 8 "$WORK/bootc.log" | cut -c1-200
if (( rc == 0 )) && [[ -d "$TGT/ostree/deploy" && -f "$TGT/boot/efi/EFI/BOOT/BOOTAA64.EFI" || -d "$TGT/boot/efi/EFI/BOOT" ]]; then
  echo "PHASE4_REHEARSAL_OK"
else
  echo "PHASE4_REHEARSAL_FAILED"; exit 1
fi
