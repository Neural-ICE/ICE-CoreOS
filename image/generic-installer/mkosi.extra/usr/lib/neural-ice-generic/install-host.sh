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
env=/run/ni-verified/release.env
[ -f "$env" ] && [ ! -L "$env" ] || die "no verified release"
get() { grep -E "^$1=" "$env" | head -n 1 | cut -d= -f2-; }
rid="$(get RELEASE_ID)"; hostdigest="$(get HOST_DIGEST)"; hostref="$(get HOST_REF)"
[[ "$hostdigest" =~ ^sha256:[0-9a-f]{64}$ ]] || die "verified release carries no host digest"
OCI=/run/ni-payload/host-oci
[ -d "$OCI" ] && [ ! -L "$OCI" ] || die "payload has no host-oci layout"
[ -z "$(find "$OCI" -type l -print -quit)" ] || die "the host layout contains a symlink"
# The layout must hold exactly the image index the signed manifest names, and that blob must hash to its name.
idx="$OCI/index.json"; [ "$(stat -c %s "$idx")" -le 65536 ] || die "index.json is too large"
[ "$(jq -r '.manifests | length' "$idx")" = 1 ] || die "the host layout must hold exactly one image"
[ "$(jq -r '.manifests[0].digest' "$idx")" = "$hostdigest" ] || die "the host layout is not the image the release names"
blob() { echo "$OCI/blobs/sha256/${1#sha256:}"; }
chk() { [ -f "$(blob "$1")" ] && [ ! -L "$(blob "$1")" ] || die "missing blob $1"
  [ "$(stat -c %s "$(blob "$1")")" -le "${2:-1048576}" ] || die "blob $1 is too large"
  [ "$(sha256sum "$(blob "$1")" | cut -d' ' -f1)" = "${1#sha256:}" ] || die "blob $1 does not hash to its name"; }
chk "$hostdigest"
[ "$(jq -r '.mediaType' "$(blob "$hostdigest")")" = application/vnd.oci.image.index.v1+json ] || die "the release digest is not an image index"
child="$(jq -r '[.manifests[] | select(.platform.architecture == "arm64" and .platform.os == "linux")] | if length == 1 then .[0].digest else "" end' "$(blob "$hostdigest")")"
[[ "$child" =~ ^sha256:[0-9a-f]{64}$ ]] || die "the index does not carry exactly one linux/arm64 image"
chk "$child" 4194304
packed="$(jq '[.layers[].size] | add' "$(blob "$child")")"
# Resource bound: the image is unpacked into RAM. Refuse before touching anything when it cannot fit.
need=$(( packed * 3 + 2 * 1024 * 1024 * 1024 ))
avail=$(( $(awk '/^MemAvailable:/ { print $2 }' /proc/meminfo) * 1024 ))
[ "$avail" -ge "$need" ] || die "not enough memory to unpack the host image: need $need bytes, have $avail"
# Target disk: the medium is the disk that holds the payload partition; exactly one other writable disk may exist.
pdev="$(findmnt -no SOURCE /run/ni-payload)"; medium="$(lsblk -no PKNAME "$pdev" | head -n 1)"
[ -n "$medium" ] || die "cannot identify the installation medium"
mapfile -t cands < <(lsblk -dnbo NAME,TYPE,RO,SIZE | awk -v m="$medium" '$2 == "disk" && $3 == 0 && $1 != m && $4 >= 34359738368 { print $1 }')
[ "${#cands[@]}" = 1 ] || die "need exactly one writable target disk of at least 32 GiB besides the medium, found ${#cands[@]}"
disk="/dev/${cands[0]}"
say "install: release=$rid host=$hostref target=$disk medium=/dev/$medium packed=$packed unpack-budget=$need"
# Container storage in RAM, sized from the manifest.
install -d /var/lib/containers /run/containers
mount -t tmpfs -o "size=$need,mode=0700" tmpfs /var/lib/containers
# The installer's lent policy: default reject; only the local, digest-verified layout and its storage copy.
t0=$SECONDS
skopeo copy --policy /etc/containers/policy.json "oci:$OCI" "containers-storage:localhost/ni-host:install" \
  || die "cannot unpack the host image from the payload"
say "unpacked in $(( SECONDS - t0 )) s, free memory $(( $(awk '/^MemAvailable:/ { print $2 }' /proc/meminfo) / 1024 )) MiB"
# For the record only (no code of the image runs): the policy the host image carries.
if mnt="$(podman --cgroup-manager=cgroupfs --events-backend=file image mount localhost/ni-host:install 2>/dev/null)"; then
  say "host policy.json: $(tr -d '\n ' < "$mnt/etc/containers/policy.json" | cut -c1-400)"
  podman --cgroup-manager=cgroupfs --events-backend=file image unmount localhost/ni-host:install >/dev/null 2>&1 || true
fi
# The installer loads no SELinux policy, so bootc cannot enter install_t; its documented fallback lets it relabel the
# target from the image's own policy (the installed system boots with SELinux as the image configures it).
kargs=(); [ "$tdebug" = 1 ] && kargs=(--karg systemd.show_status=1 --karg loglevel=6)
t1=$SECONDS
podman --cgroup-manager=cgroupfs --events-backend=file run --pull=never --rm --privileged --net=none --pid=host \
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
systemctl --no-block reboot
