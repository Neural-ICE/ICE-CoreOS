#!/usr/bin/env bash
#
# Build the two IMMUTABLE IMAGES a sealed medium is made of: the installer root
# and the container store it installs FROM. Both come out as squashfs, both are
# later dm-verity protected and both land inside the sealed payload
# (image/build-installer-payload.sh).
#
# WHY A SEPARATE ROOT IMAGE AND NOT "the medium's ostree root". dm-verity
# protects a fixed extent with a fixed hash. An ostree deployment is mutable by
# construction (/etc, /var, the deployment directory itself), so there is no
# stable extent to hash and nothing a signature could pin. The installer root
# therefore becomes its own immutable object: one squashfs, produced from the
# installer container image, hashed once, and named in the signed cmdline.
#
# WHY THE STORE IS ALSO AN IMAGE, AND NOT A DIRECTORY (review 2026-09-01, P0 #1).
# With the root a verity image, the booted system is no longer an ostree
# deployment, so `bootc image copy-to-storage` -- which duplicated ~10 GiB of the
# BOOTED image at install time -- has nothing to copy. The bytes are staged HERE
# instead, at build time, as an ordinary containers-storage. It used to be copied
# onto the medium as a DIRECTORY, hashed only into a build manifest nobody read:
# the bytes actually written onto a customer's disk were replaceable on an
# otherwise correctly signed medium. Wrapping that store in its own squashfs
# turns it into a fixed extent, which is the only shape dm-verity can protect and
# the only shape an off-device inspector can hash.
#
# The store is still consumed with ZERO COPIES: podman reads it as a read-only
# ADDITIONAL IMAGE STORE, the same mechanism the PRELOADED seed store already
# uses on the appliance. Nothing is imported into a tmpfs, and the install source
# is the exact extent the signature covers.
#
# DETERMINISM IS A REVIEWABILITY REQUIREMENT, as in build-installer-uki.sh: two
# builds of the same image must produce the same bytes, or nobody can tell a
# rebuild from a substitution. Every timestamp is pinned to 0 and every ownership
# to root.
set -euo pipefail

die() { echo "build-installer-root: ERROR: $*" >&2; exit 1; }

# THE IMAGE, AS AN IMMUTABLE ID (review 2026-09-01, P1 #1). This used to take a
# local TAG. A tag is a mutable pointer: this script resolved it once for the
# root filesystem and again, later, for the sealed store, and a concurrent build
# or a `podman tag` between the two produced root A plus store B. Both extents
# hash correctly and both are covered by the signature, so nothing downstream
# could see it -- yet bootc installs B while every medium-path check assumes A.
#
# The caller therefore supplies the IMAGE ID (the config digest), which cannot be
# repointed, and this script resolves it exactly ONCE and uses that one value for
# the mount, the store staging and the manifest.
INSTALLER_IMG="${INSTALLER_IMG:-}"       # the image whose rootfs becomes the sealed root
ROOT_IMAGE_OUT="${ROOT_IMAGE_OUT:-}"     # where the root squashfs is written
STORE_IMAGE_OUT="${STORE_IMAGE_OUT:-}"   # where the store squashfs is written
STORE_IMAGE_NAME="${STORE_IMAGE_NAME:-localhost/bootc}"
MANIFEST_OUT="${MANIFEST_OUT:-${ROOT_IMAGE_OUT}.manifest}"

# Tool overrides exist so the suite can drive every branch without podman, a
# 10 GiB image or 4 GiB of scratch. Refused under a privileged process, exactly
# as in build-installer-uki.sh and the device-root helper.
TOOL_DIR="${NI_INSTALLER_ROOT_TEST_TOOLS:-}"
if [[ -n "$TOOL_DIR" ]]; then
  [[ "${NI_INSTALLER_ROOT_TESTING:-}" == 1 && "${EUID:-$(id -u)}" -ne 0 ]] \
    || die "a tool override is forbidden in a privileged process"
fi

tool() { # $1=name
  if [[ -n "$TOOL_DIR" ]]; then
    [[ -x "$TOOL_DIR/$1" ]] || die "required tool is unavailable: $TOOL_DIR/$1"
    printf '%s' "$TOOL_DIR/$1"
    return 0
  fi
  command -v -- "$1" >/dev/null 2>&1 || die "required tool is unavailable: $1"
  command -v -- "$1"
}

for required in INSTALLER_IMG ROOT_IMAGE_OUT STORE_IMAGE_OUT; do
  [[ -n "${!required}" ]] || die "$required is required"
done
[[ "$STORE_IMAGE_NAME" =~ ^[a-z0-9]([a-z0-9._/-]{0,126}[a-z0-9])?$ ]] \
  || die "STORE_IMAGE_NAME is not a plain local image name: $STORE_IMAGE_NAME"

# A MUTABLE REFERENCE IS REFUSED OUTRIGHT, not silently resolved. Resolving a tag
# here would reintroduce exactly the split this script exists to prevent: the
# caller would still be free to move it between its own reads and ours.
[[ "$INSTALLER_IMG" =~ ^(sha256:)?[0-9a-f]{64}$ ]] \
  || die "INSTALLER_IMG must be an immutable local image ID (sha256:<64 hex>), not the mutable reference '$INSTALLER_IMG'; a tag can be repointed between the root and the store and the medium would carry two different images"
INSTALLER_IMAGE_ID="${INSTALLER_IMG#sha256:}"
readonly INSTALLER_IMAGE_ID

PODMAN_BIN="$(tool podman)"
podman_run() { "$PODMAN_BIN" "$@"; }

# The ONE resolution. Everything below names $INSTALLER_IMAGE_ID; nothing names
# a tag, so there is no second lookup that could answer differently.
RESOLVED_IMAGE_ID="$(podman_run image inspect --format '{{.Id}}' "sha256:$INSTALLER_IMAGE_ID" 2>/dev/null \
  | tr -d '[:space:]' | sed 's/^sha256://')" \
  || die "cannot resolve the installer image ID $INSTALLER_IMAGE_ID in local storage"
[[ "$RESOLVED_IMAGE_ID" == "$INSTALLER_IMAGE_ID" ]] \
  || die "local storage resolves $INSTALLER_IMAGE_ID to '$RESOLVED_IMAGE_ID'; refusing to seal an image that is not the one this build was given"

# The exact mksquashfs invocation both images are built with. Every source of
# build-host state is pinned: timestamps to the epoch, ownership to root, and no
# fragment-order dependence on the CPU count.
squash() { # $1=source tree  $2=output image
  rm -f -- "$2"
  "$(tool mksquashfs)" "$1" "$2" \
    -noappend -no-progress -no-recovery -all-root -mkfs-time 0 -all-time 0 \
    -no-exports -xattrs -comp zstd -Xcompression-level 19 -processors 1 \
    || die "mksquashfs failed for $2"
  [[ -s "$2" ]] || die "mksquashfs produced no image at $2"
}

sha256_of() { "$(tool sha256sum)" "$1" | awk '{print tolower($1)}'; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/ni-installer-root.XXXXXX")"
MOUNTED=""
cleanup() {
  if [[ -n "$MOUNTED" ]]; then
    podman_run image umount "sha256:$INSTALLER_IMAGE_ID" >/dev/null 2>&1 || true
    MOUNTED=""
  fi
  rm -rf -- "$WORK"
}
trap cleanup EXIT

# --------------------------------------------------------------------------- #
# 1) The rootfs. `podman image mount` gives the merged, LABELLED tree; `podman
#    export` would flatten a container and lose the image's SELinux xattrs, which
#    the installed system's relabelling depends on.
# --------------------------------------------------------------------------- #
echo "==> mounting sha256:${INSTALLER_IMAGE_ID}"
ROOTFS="$(podman_run image mount "sha256:$INSTALLER_IMAGE_ID")" || die "cannot mount the installer image"
MOUNTED=1
[[ -n "$ROOTFS" && -d "$ROOTFS" ]] || die "the installer image did not mount to a directory"

# Fail-closed readback on the four files the whole trust construction reads out
# of this root. A root image missing one of them would verify perfectly and then
# refuse at install time, on the appliance, after the operator has committed.
for required_path in \
  usr/lib/neural-ice/access-policy \
  usr/lib/neural-ice/hardware-target \
  usr/lib/neural-ice/signed-boot-trust-policy-id \
  usr/lib/neural-ice/keys/release-authorization.pub; do
  [[ -f "$ROOTFS/$required_path" ]] \
    || die "the installer image carries no $required_path; the sealed anchor would have nothing to cross-check"
done

# THE IMMUTABLE MARKERS, HASHED FROM THE ROOT THAT IS ABOUT TO BE SEALED. These
# four files are what the runtime trust gate reads back off the medium; recording
# their digest here is what lets a reviewer -- and the store comparison below --
# say that the root and the store carry the SAME statements about what this
# medium is, rather than that both are internally consistent.
MARKER_DIGEST="$( { for marker_path in \
    usr/lib/neural-ice/access-policy \
    usr/lib/neural-ice/hardware-target \
    usr/lib/neural-ice/signed-boot-trust-policy-id \
    usr/lib/neural-ice/keys/release-authorization.pub; do
    printf '%s=%s\n' "$marker_path" "$(sha256_of "$ROOTFS/$marker_path")"
  done; } | "$(tool sha256sum)" | awk '{print tolower($1)}')"
[[ "$MARKER_DIGEST" =~ ^[0-9a-f]{64}$ ]] || die "cannot hash the installer root's immutable markers"

echo "==> mksquashfs (installer root) -> ${ROOT_IMAGE_OUT}"
squash "$ROOTFS" "$ROOT_IMAGE_OUT"
ROOT_IMAGE_SHA256="$(sha256_of "$ROOT_IMAGE_OUT")"
ROOT_IMAGE_BYTES="$(wc -c < "$ROOT_IMAGE_OUT" | tr -d '[:space:]')"

# --------------------------------------------------------------------------- #
# 2) The store the install reads FROM, staged as a containers-storage and then
#    frozen into its own squashfs.
# --------------------------------------------------------------------------- #
echo "==> staging ${STORE_IMAGE_NAME} into a containers-storage"
STORE_TREE="$WORK/store"
mkdir -p -- "$STORE_TREE" "$WORK/runroot"
"$(tool skopeo)" copy \
  "containers-storage:sha256:${INSTALLER_IMAGE_ID}" \
  "containers-storage:[overlay@${STORE_TREE}+${WORK}/runroot]${STORE_IMAGE_NAME}" \
  || die "cannot stage the installer image into the medium image store"
# A store the installer cannot read is a medium that cannot install. Assert the
# produced LAYOUT rather than the command's exit status: podman consumes this as
# a read-only additional image store and needs all three overlay directories.
for required_dir in overlay-images overlay-layers overlay; do
  [[ -d "$STORE_TREE/$required_dir" ]] \
    || die "the staged image store has no $required_dir directory; podman could not read it as an additional image store"
done
# The store must NAME the image the installer will ask for. Reading it back here
# means a rename or a skopeo behaviour change is a build failure rather than a
# `podman image exists` refusal on the appliance.
grep -Fq "\"$STORE_IMAGE_NAME:" "$STORE_TREE/overlay-images/images.json" 2>/dev/null \
  || grep -Fq "\"$STORE_IMAGE_NAME\"" "$STORE_TREE/overlay-images/images.json" 2>/dev/null \
  || die "the staged image store does not name ${STORE_IMAGE_NAME}"

# --------------------------------------------------------------------------- #
# 🔴 THE SEALED ROOT AND THE STAGED STORE MUST BE THE SAME IMAGE (review
# 2026-09-01, P1 #1). The whole finding is that these two extents are produced by
# two separate resolutions, and that a build which produced root A plus store B
# would be validly hashed and validly signed -- bootc would install B while every
# medium-path check assumed A.
#
# Naming the image ID in both places is necessary and not sufficient: assert the
# OUTCOME. containers-storage records each image under its own immutable ID (the
# config digest), so the store's record must carry exactly the ID this script
# mounted and sealed, and it must carry exactly one image.
# --------------------------------------------------------------------------- #
STORE_IMAGE_ID="$("$(tool python3)" -c '
import json, sys
document = json.load(open(sys.argv[1]))
if not isinstance(document, list):
    raise SystemExit("the staged image store record is not a list")
ids = sorted({str(entry.get("id", "")).lower() for entry in document if isinstance(entry, dict)})
if len(ids) != 1:
    raise SystemExit(f"the staged image store holds {len(ids)} images; a sealed medium carries exactly one")
print(ids[0])
' "$STORE_TREE/overlay-images/images.json")" \
  || die "the staged image store records no single immutable image ID"
[[ "$STORE_IMAGE_ID" =~ ^[0-9a-f]{64}$ ]] \
  || die "the staged image store records '$STORE_IMAGE_ID', which is not an immutable image ID"
[[ "$STORE_IMAGE_ID" == "$INSTALLER_IMAGE_ID" ]] \
  || die "the staged image store holds image $STORE_IMAGE_ID but the sealed installer root was built from $INSTALLER_IMAGE_ID; the medium would install a different image than the one it boots"

echo "==> mksquashfs (image store) -> ${STORE_IMAGE_OUT}"
squash "$STORE_TREE" "$STORE_IMAGE_OUT"
STORE_IMAGE_SHA256="$(sha256_of "$STORE_IMAGE_OUT")"
STORE_IMAGE_BYTES="$(wc -c < "$STORE_IMAGE_OUT" | tr -d '[:space:]')"

podman_run image umount "sha256:$INSTALLER_IMAGE_ID" >/dev/null 2>&1 || true
MOUNTED=""

# --------------------------------------------------------------------------- #
# 3) The manifest CI diffs. A changed image must show up as a one-line diff
#    rather than as several GiB of squashfs.
# --------------------------------------------------------------------------- #
{
  printf 'schema=%s\n' "neural-ice-installer-root-manifest-v3"
  printf 'installer_image_id=%s\n' "$INSTALLER_IMAGE_ID"
  printf 'installer_root_marker_sha256=%s\n' "$MARKER_DIGEST"
  printf 'root_image_bytes=%s\n' "$ROOT_IMAGE_BYTES"
  printf 'root_image_sha256=%s\n' "$ROOT_IMAGE_SHA256"
  printf 'store_image_bytes=%s\n' "$STORE_IMAGE_BYTES"
  printf 'store_image_id=%s\n' "$STORE_IMAGE_ID"
  printf 'store_image_name=%s\n' "$STORE_IMAGE_NAME"
  printf 'store_image_sha256=%s\n' "$STORE_IMAGE_SHA256"
} > "$MANIFEST_OUT"
echo "==> manifest: $MANIFEST_OUT"
cat "$MANIFEST_OUT"
