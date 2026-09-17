#!/usr/bin/env bash
# Rehearse phase 4 of the installer -- `bootc install to-filesystem` -- on the
# bench, against a loop-device target laid out exactly as the installer lays out
# the appliance disk (ESP vfat, boot ext4, sysroot xfs, mounted at one target
# with --rbind/--make-rshared), from the SAME container, with the SAME mounts
# the installer gives it: the lent fuse-overlayfs helper, the installer's
# permissive signature policy, and the image's OWN bound-images.d, unmasked.
#
# 2026-09-09: this run reproduced, in 30 s, the hardware refusal of attempt 14
# ("Running image containers-storage:[...] is rejected by policy") and proved
# the fix in 44 s ("Installation complete!"). Nothing here touches a real disk,
# a TPM or the network beyond the local container storage and, when asked to
# stage the bound images, the LAN mirror.
#
# 2026-09-17: this run proved that bootc's own install-time copy of the bound
# images cannot land a digest-pinned image out of a containers-storage (22/22
# staged in the bench store, 0/22 copied: `Digest of source image's manifest
# would not match destination reference`; the account is in
# image/lib/bound-images.sh). The installer therefore runs bootc with
# `--bound-images=skip` and copies each image from an OCI layout on the medium
# itself. This rehearsal does the same, with the same library: the layouts
# come from --bound-images-dir (a directory laid out like the medium's sealed
# store, e.g. the store mount itself) or are staged here from --mirror; every
# one is verified before a loop device exists, and every defect is reported in
# ONE refusal. After bootc, each layout is copied into the target's
# ostree/bootc/storage from inside the appliance container, and the target's
# store index must name every reference, or the rehearsal fails.
#
# Usage (root, on a bench host whose container storage holds the appliance):
#   image/bench-rehearse-phase4.sh --image <appliance ref@digest> \
#       --pcr-policy-signature <json> --pcr-policy-key <pem> \
#       { --bound-images-dir DIR | --mirror docker://host:port [--mirror-cert-dir DIR] } \
#       [--work-dir DIR] [--size 60G]
set -euo pipefail
IMAGE='' SIG='' KEY='' WORK=/var/tmp/ni-phase4-rehearsal SIZE=60G LAYOUTS='' MIRROR='' MIRROR_CERT_DIR=''
while [[ $# -gt 0 ]]; do
  case "$1" in
    --image) IMAGE=$2; shift 2 ;;
    --pcr-policy-signature) SIG=$2; shift 2 ;;
    --pcr-policy-key) KEY=$2; shift 2 ;;
    --work-dir) WORK=$2; shift 2 ;;
    --size) SIZE=$2; shift 2 ;;
    --bound-images-dir) LAYOUTS=$2; shift 2 ;;
    --mirror) MIRROR=$2; shift 2 ;;
    --mirror-cert-dir) MIRROR_CERT_DIR=$2; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[[ -n "$IMAGE" && -f "$SIG" && -f "$KEY" ]] || { echo "usage: --image REF --pcr-policy-signature FILE --pcr-policy-key FILE {--bound-images-dir DIR | --mirror docker://host:port}" >&2; exit 2; }
[[ -n "$LAYOUTS" || "$MIRROR" == docker://* ]] || { echo "name the bound image layouts (--bound-images-dir DIR) or the mirror to stage them from (--mirror docker://host:port)" >&2; exit 2; }
[[ "$(id -u)" -eq 0 ]] || { echo "loop devices and mounts need root" >&2; exit 2; }
[[ "$SIZE" =~ ^[0-9]+[GM]$ ]] || { echo "--size must be like 60G" >&2; exit 2; }
for tool in podman skopeo losetup sgdisk mkfs.fat mkfs.ext4 mkfs.xfs blkid udevadm python3; do
  command -v "$tool" >/dev/null || { echo "missing tool: $tool" >&2; exit 2; }
done
[[ -x /usr/bin/fuse-overlayfs ]] || { echo "the bench host must have /usr/bin/fuse-overlayfs to lend, as the installer does" >&2; exit 2; }
podman image exists "$IMAGE" || { echo "the appliance image is not in the local container storage: $IMAGE" >&2; exit 2; }
# shellcheck source=image/lib/bound-images.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/bound-images.sh"
ARCH="$(ni_bound_image_arch)" || { echo "this bench's architecture ($(uname -m)) is not one the medium stages bound images for" >&2; exit 2; }

rm -rf -- "$WORK"; install -d -m 0700 "$WORK"; TGT="$WORK/target"; install -d "$TGT"

# The bound images, exactly as the installer reads them: the container's own
# /usr/lib/bootc/bound-images.d, one Image= per quadlet. Read from inside the
# image because the appliance links with absolute targets that only resolve
# there. Every one must be digest-pinned.
BOUND_LIST="$WORK/bound-images.list"
podman run --rm --pull=never --net=none --entrypoint /bin/sh "$IMAGE" -c '
  for spec in /usr/lib/bootc/bound-images.d/*.image /usr/lib/bootc/bound-images.d/*.container; do
    case "$spec" in *"*"*) continue ;; esac
    [ -e "$spec" ] || { echo "dangling bound image link: $spec" >&2; exit 1; }
    sed -n "s/^Image=//p" "$spec" | head -n 1 | tr -d "[:space:]"; echo
  done' > "$BOUND_LIST" \
  || { echo "cannot read the appliance image's bound images" >&2; exit 2; }
sed -i '/^$/d' "$BOUND_LIST"
BOUND_EXPECTED="$(grep -c . "$BOUND_LIST" || true)"
while IFS= read -r ref; do
  [[ "$ref" =~ $NI_BOUND_IMAGE_REF_GRAMMAR ]] \
    || { echo "bound image is not digest-pinned, cannot be proved present: $ref" >&2; exit 2; }
done < "$BOUND_LIST"

# The layouts: staged from the mirror the way the medium builder stages them
# (two copies, index-only then system for this architecture), or taken from a
# directory laid out like the medium's sealed store.
if [[ -z "$LAYOUTS" ]]; then
  LAYOUTS="$WORK/bound-images"
  cert_args=()
  [[ -z "$MIRROR_CERT_DIR" ]] || cert_args=(--src-cert-dir "$MIRROR_CERT_DIR")
  echo "== staging ${BOUND_EXPECTED} bound image layouts from ${MIRROR} (linux/${ARCH}) into ${LAYOUTS}"
  stage_start=$SECONDS
  while IFS= read -r ref; do
    [[ -n "$ref" ]] || continue
    t0=$SECONDS
    ni_bound_image_stage_layout "${MIRROR}/${ref#*/}" "$(ni_bound_image_layout_dir "$LAYOUTS" "$ref")" "$ARCH" "${cert_args[@]}" --src-no-creds >/dev/null 2>"$WORK/stage.err" \
      || { echo "staging failed for $ref: $(tail -n 2 "$WORK/stage.err" | tr '\n' ' ')" >&2; exit 2; }
    echo "   staged in $((SECONDS - t0))s: $ref"
  done < "$BOUND_LIST"
  echo "== layouts staged in $((SECONDS - stage_start))s, $(du -sh "$LAYOUTS" | cut -f1) on disk (linux/${ARCH} blobs only)"
fi
missing=''; verified=0
while IFS= read -r ref; do
  [[ -n "$ref" ]] || continue
  if defect="$(ni_bound_image_verify_layout "$(ni_bound_image_layout_dir "$LAYOUTS" "$ref")" "${ref##*@sha256:}" "$ARCH")"; then
    verified=$((verified + 1))
  else
    missing+="${missing:+
}   $ref: ${defect:-unreadable layout}"
  fi
done < "$BOUND_LIST"
if [[ -n "$missing" ]]; then
  echo "bound image layouts missing or incomplete under ${LAYOUTS} (linux/${ARCH}); stage them from the mirror as the medium builder does:" >&2
  echo "$missing" >&2
  echo "   image/bench-rehearse-phase4.sh … --mirror docker://registry.neural-ice.local:5055 --mirror-cert-dir <mirror-ca-dir>" >&2
  exit 2
fi
echo "== ${verified}/${BOUND_EXPECTED} bound image layouts verified (index pinned, linux/${ARCH} instance complete)"

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
  -v "$WORK/policy.json:/etc/containers/policy.json:ro" \
  --mount "type=bind,source=$TGT,target=$TGT,bind-propagation=rshared" \
  "$IMAGE" bootc install to-filesystem --skip-fetch-check --bound-images=skip \
    --source-imgref "containers-storage:$IMAGE" --target-imgref "$IMAGE" \
    --root-mount-spec "UUID=$SYS_UUID" --boot-mount-spec "UUID=$BOOT_UUID" \
    --karg "rd.luks.uuid=luks-00000000-0000-0000-0000-000000000000" \
    --karg "neuralice.pcr_policy_seq=1" \
    "$TGT" > "$WORK/bootc.log" 2>&1
rc=$?
set -e
echo "bootc rc=$rc in $((SECONDS - start))s; log: $WORK/bootc.log"
tail -n 8 "$WORK/bootc.log" | cut -c1-200

# THE COPY, THE INSTALLER'S WAY: each layout into the target's ostree/bootc/
# storage (the physical path behind /usr/lib/bootc/storage, bootc store/mod.rs
# BOOTC_ROOT), from inside the appliance container, through a storage
# configuration of the target store's own -- overlay, no mount program, no
# additional stores -- so the writer is the appliance's c/image + c/storage.
BOUND_COPIED=0
if (( rc == 0 )); then
  # bootc finalizes the target read-only at the superblock (install.rs,
  # finalize_filesystem: `mount -o remount,ro`); the installer remounts before
  # its own writes, and so does this rehearsal (0/22 copied without it,
  # 2026-09-17: `storage.lock: read-only file system`).
  mount -o remount,rw "$TGT" || { echo "cannot remount the target read-write after bootc" >&2; exit 1; }
  ls -d "$TGT/ostree/bootc/storage" >/dev/null 2>&1 && echo "== bootc created the deployment's bound image store under --bound-images=skip" \
    || echo "== bootc created NO ostree/bootc/storage on the target"
  printf '[storage]\ndriver = "overlay"\nrunroot = "/run/ni-bootc-store-runroot"\ngraphroot = "%s/ostree/bootc/storage"\n' "$TGT" > "$WORK/target-storage.conf"
  copy_start=$SECONDS
  while IFS= read -r ref; do
    [[ -n "$ref" ]] || continue
    dir="$(ni_bound_image_layout_dir "$LAYOUTS" "$ref")"
    t0=$SECONDS
    if podman --cgroup-manager=cgroupfs --events-backend=file run --pull=never --rm --privileged \
      --net=none --pid=host --security-opt label=type:unconfined_t \
      -v /dev:/dev -v "$LAYOUTS:$LAYOUTS:ro" \
      -v "$WORK/target-storage.conf:/etc/containers/storage.conf:ro" \
      -v "$WORK/policy.json:/etc/containers/policy.json:ro" \
      --mount "type=bind,source=$TGT,target=$TGT,bind-propagation=rshared" \
      "$IMAGE" skopeo --override-os linux --override-arch "$ARCH" copy --preserve-digests "oci:${dir}:${NI_BOUND_IMAGES_LIST_TAG}" "containers-storage:${ref}" \
      >> "$WORK/copy.log" 2>&1; then
      echo "   copied in $((SECONDS - t0))s: $ref"
    else
      echo "   COPY FAILED: $ref ($(tail -n 1 "$WORK/copy.log" | cut -c1-200))"
    fi
  done < "$BOUND_LIST"
  echo "== copy step took $((SECONDS - copy_start))s; log: $WORK/copy.log"
fi
INDEX="$TGT/ostree/bootc/storage/overlay-images/images.json"
if [[ -f "$INDEX" ]]; then
  while IFS= read -r ref; do
    [[ -n "$ref" ]] || continue
    if grep -Fq -- "\"$ref\"" "$INDEX"; then
      BOUND_COPIED=$((BOUND_COPIED + 1))
    else
      echo "NOT IN TARGET STORE: $ref"
    fi
  done < "$BOUND_LIST"
elif (( BOUND_EXPECTED > 0 )); then
  echo "the target has no bound image store index at ostree/bootc/storage"
fi
echo "bound images copied into the target: ${BOUND_COPIED}/${BOUND_EXPECTED}"
echo "target store size: $(du -sh "$TGT/ostree/bootc/storage" 2>/dev/null | cut -f1)"
if (( rc == 0 && BOUND_COPIED == BOUND_EXPECTED )) \
  && [[ -d "$TGT/ostree/deploy" && -f "$TGT/boot/efi/EFI/BOOT/BOOTAA64.EFI" || -d "$TGT/boot/efi/EFI/BOOT" ]]; then
  echo "PHASE4_REHEARSAL_OK"
else
  echo "PHASE4_REHEARSAL_FAILED"; exit 1
fi
