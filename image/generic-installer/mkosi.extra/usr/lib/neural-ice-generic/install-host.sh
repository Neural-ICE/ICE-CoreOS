#!/bin/bash
# Install step of the generic installer (ADR-0044, sequence step 5, payload mode): `bootc install to-disk` from the
# host image that the SIGNED release manifest names, read from the OCI layout on the payload partition.
# It consumes only /run/ni-verified/release.env, written by verify-payload.sh. LAB PROTOTYPE: the gates of
# sequence steps 3-4 and 6 (freshness, PCR 7, TPM NV, LUKS, policy reader) are not wired yet, so the sealed
# `neuralice.install_stage=prototype-ungated` is REQUIRED; a UKI without it refuses to install.
set -euo pipefail
say() { echo "ni-generic-install: $*" > /dev/console; echo "ni-generic-install: $*"; }
die() { say "REFUSED: $*"; exit 1; }
read -r -a ARGS < /proc/cmdline
sealed() { local n=0 v="" a; for a in "${ARGS[@]}"; do case "$a" in "$1="*) n=$((n + 1)); v="${a#*=}";; esac; done
  [ "$n" = 1 ] || die "sealed $1 appears $n times"; [[ "$v" =~ $2 ]] || die "sealed $1 is malformed"; printf '%s' "$v"; }
[ "$(sealed neuralice.install_stage '^[a-z-]+$')" = prototype-ungated ] \
  || die "this installer has no install gates yet; only a prototype-ungated UKI may install"
tdebug="$(sealed neuralice.target_debug '^[01]$')"
s_profile="$(sealed neuralice.access_profile '^[a-z]+(-[a-z]+)*$')"
s_policy="$(sealed neuralice.trust_policy_id '^[a-z0-9]+(-[a-z0-9]+)*$')"
s_target="$(sealed neuralice.hardware_target '^[a-z0-9]+(-[a-z0-9]+)*$')"
env=/run/ni-verified/release.env
[ -f "$env" ] && [ ! -L "$env" ] || die "no verified release"
get() { grep -E "^$1=" "$env" | head -n 1 | cut -d= -f2-; }
rid="$(get RELEASE_ID)"; hostdigest="$(get HOST_DIGEST)"; hostref="$(get HOST_REF)"
[[ "$hostdigest" =~ ^sha256:[0-9a-f]{64}$ ]] || die "verified release carries no host digest"
SRC=/run/ni-payload/host-oci; OCI=/run/ni-verified/host-oci
[ -d "$SRC" ] && [ ! -L "$SRC" ] || die "payload has no host-oci layout"
[ -z "$(find "$SRC" -type l -print -quit)" ] || die "the host layout contains a symlink"
# ONE read of everything that decides WHICH image is installed (ADR-0015 H: one identity, resolved once). The index,
# the image index and the arm64 manifest are copied to RAM, hashed there and used from there. Only the config and the
# layers stay on the medium; the copy below verifies each of them against its digest while it reads it, once.
sblob() { echo "$SRC/blobs/sha256/${1#sha256:}"; }
vblob() { echo "$OCI/blobs/sha256/${1#sha256:}"; }
mkdir -p "$OCI/blobs/sha256"
take() { # digest, max size: bounded copy into RAM, proven to be the bytes its name says
  [ -f "$(sblob "$1")" ] && [ ! -L "$(sblob "$1")" ] || die "missing blob $1"
  [ "$(stat -c %s "$(sblob "$1")")" -le "$2" ] || die "blob $1 is too large"
  cp -- "$(sblob "$1")" "$(vblob "$1")"
  [ "$(sha256sum "$(vblob "$1")" | cut -d' ' -f1)" = "${1#sha256:}" ] || die "blob $1 does not hash to its name"; }
[ -f "$SRC/index.json" ] && [ "$(stat -c %s "$SRC/index.json")" -le 65536 ] || die "index.json is missing or too large"
cp -- "$SRC/index.json" "$OCI/index.json"; printf '{"imageLayoutVersion":"1.0.0"}\n' > "$OCI/oci-layout"
[ "$(jq -r '.manifests | length' "$OCI/index.json")" = 1 ] || die "the host layout must hold exactly one image"
[ "$(jq -r '.manifests[0].digest' "$OCI/index.json")" = "$hostdigest" ] || die "the host layout is not the image the release names"
take "$hostdigest" 1048576
[ "$(jq -r '.mediaType' "$(vblob "$hostdigest")")" = application/vnd.oci.image.index.v1+json ] || die "the release digest is not an image index"
child="$(jq -r '[.manifests[] | select(.platform.architecture == "arm64" and .platform.os == "linux")] | if length == 1 then .[0].digest else "" end' "$(vblob "$hostdigest")")"
[[ "$child" =~ ^sha256:[0-9a-f]{64}$ ]] || die "the index does not carry exactly one linux/arm64 image"
take "$child" 4194304
cfg="$(jq -r '.config.digest // empty' "$(vblob "$child")")"; [[ "$cfg" =~ ^sha256:[0-9a-f]{64}$ ]] || die "the manifest names no config"
take "$cfg" 4194304
mapfile -t layers < <(jq -r '.layers[] | .digest + " " + (.size | tostring)' "$(vblob "$child")")
[ "${#layers[@]}" -ge 1 ] || die "the manifest has no layers"
packed=0; declare -A seen=()
for l in "${layers[@]}"; do
  d="${l%% *}"; sz="${l##* }"
  [[ "$d" =~ ^sha256:[0-9a-f]{64}$ && "$sz" =~ ^[0-9]+$ ]] || die "malformed layer descriptor"
  [ -f "$(sblob "$d")" ] && [ ! -L "$(sblob "$d")" ] && [ "$(stat -c %s "$(sblob "$d")")" = "$sz" ] || die "layer $d is missing or has the wrong size"
  [ -z "${seen[$d]:-}" ] || continue     # a layer repeated in the manifest is stored, and counted, once
  seen[$d]=1; ln -s "$(sblob "$d")" "$(vblob "$d")"; packed=$(( packed + sz ))
done
# Resource bound: the image is unpacked into RAM. Refuse before touching anything when it cannot fit.
need=$(( packed * 3 + 2 * 1024 * 1024 * 1024 ))
avail=$(( $(awk '/^MemAvailable:/ { print $2 }' /proc/meminfo) * 1024 ))
[ "$avail" -ge "$need" ] || die "not enough memory to unpack the host image: need $need bytes, have $avail"
# Target disk: the medium is the disk that holds the payload partition. The target is exactly one other internal,
# writable, non-removable, non-USB disk of at least 32 GiB, in a list that stayed the same for two seconds.
pdev="$(findmnt -no SOURCE /run/ni-payload)"; medium="$(lsblk -no PKNAME "$pdev" | head -n 1)"
[ -n "$medium" ] || die "cannot identify the installation medium"
list() { lsblk -dnbJ -o NAME,TYPE,RO,RM,TRAN,SIZE | jq -r --arg m "$medium" '.blockdevices[]
  | select(.type == "disk" and .name != $m and (.ro | tostring | . == "false" or . == "0") and (.rm | tostring | . == "false" or . == "0")
           and (.tran // "") != "usb" and (.size | tonumber) >= 34359738368) | .name' | sort; }
prev="$(list)" || die "cannot list the disks"; settled=0
for _ in 1 2 3 4 5 6 7 8 9 10; do
  udevadm settle --timeout=30 || true; sleep 2; cur="$(list)" || die "cannot list the disks"
  if [ "$cur" = "$prev" ]; then settled=1; break; fi
  prev="$cur"
done
[ "$settled" = 1 ] || die "the disk list does not settle"
mapfile -t cands <<< "$cur"; [ -n "$cur" ] || cands=()
[ "${#cands[@]}" = 1 ] || die "need exactly one internal writable target disk of at least 32 GiB besides the medium, found ${#cands[@]}"
disk="/dev/${cands[0]}"
say "install: release=$rid host=$hostref target=$disk medium=/dev/$medium packed=$packed unpack-budget=$need"
# Container storage in RAM, sized from the manifest.
install -d /var/lib/containers /run/containers
mount -t tmpfs -o "size=$need,mode=0700" tmpfs /var/lib/containers
# The installer's lent policy: default reject; only the RAM copy of the layout and the storage copy of the image.
t0=$SECONDS
skopeo copy --policy /etc/containers/policy.json "oci:$OCI" "containers-storage:localhost/ni-host:install" \
  || die "cannot unpack the host image from the payload"
# The image now in storage must be the verified manifest, byte for byte.
[ "$(skopeo inspect --raw containers-storage:localhost/ni-host:install | sha256sum | cut -d' ' -f1)" = "${child#sha256:}" ] \
  || die "the unpacked image is not the verified arm64 manifest"
say "unpacked in $(( SECONDS - t0 )) s, free memory $(( $(awk '/^MemAvailable:/ { print $2 }' /proc/meminfo) / 1024 )) MiB"
# Cross-check the sealed values against the markers the host image carries (read only, no code of the image runs).
pm() { podman --cgroup-manager=cgroupfs --events-backend=file "$@"; }
mnt="$(pm image mount localhost/ni-host:install 2>/dev/null)" || die "cannot inspect the host image"
for c in usr usr/lib usr/lib/neural-ice; do [ -d "$mnt/$c" ] && [ ! -L "$mnt/$c" ] || die "the host image has no plain /$c"; done
marker() { [ -f "$mnt/usr/lib/neural-ice/$1" ] && [ ! -L "$mnt/usr/lib/neural-ice/$1" ] && [ "$(stat -c %s "$mnt/usr/lib/neural-ice/$1")" -le 256 ] \
  && tr -d '\n' < "$mnt/usr/lib/neural-ice/$1" || echo MISSING; }
m_profile="$(marker access-policy)"; m_policy="$(marker signed-boot-trust-policy-id)"; m_target="$(marker hardware-target)"
say "host policy.json: $(tr -d '\n ' < "$mnt/etc/containers/policy.json" | cut -c1-400)"
pm image unmount localhost/ni-host:install >/dev/null 2>&1 || true
[ "$m_profile" = "$s_profile" ] || die "the host image access policy '$m_profile' is not the sealed '$s_profile'"
[ "$m_policy" = "$s_policy" ] || die "the host image trust policy '$m_policy' is not the sealed '$s_policy'"
[ "$m_target" = "$s_target" ] || die "the host image hardware target '$m_target' is not the sealed '$s_target'"
kargs=(); [ "$tdebug" = 1 ] && kargs=(--karg systemd.show_status=1 --karg loglevel=6)
t1=$SECONDS
# The installer loads no SELinux policy, so bootc cannot enter install_t; its documented fallback lets it relabel the
# target from the image's own policy (the installed system boots with SELinux as the image configures it).
pm run --pull=never --rm --privileged --net=none --pid=host \
  --security-opt label=disable --log-driver=passthrough \
  -e CONTAINERS_STORAGE_CONF=/etc/containers/storage.conf \
  -e BOOTC_SETENFORCE0_FALLBACK=1 \
  -v /dev:/dev -v /var/lib/containers:/var/lib/containers -v /run/containers:/run/containers \
  -v /etc/containers/storage.conf:/etc/containers/storage.conf:ro -v /etc/containers/policy.json:/etc/containers/policy.json:ro \
  localhost/ni-host:install \
  bootc install to-disk --wipe --skip-fetch-check --bound-images=skip --filesystem xfs \
    --source-imgref containers-storage:localhost/ni-host:install --target-imgref "$hostref" \
    "${kargs[@]}" "$disk" \
  || die "bootc install to-disk failed"
sync
say "NI-GENERIC-INSTALL-OK release=$rid host=$hostref disk=$disk install-seconds=$(( SECONDS - t1 ))"
umount /var/lib/containers || true
# Power off, never reboot: a medium left in the machine must not start the installer again.
systemctl --no-block poweroff
