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
# local TAG. A tag is a mutable pointer, so resolving either the derived live
# installer or the original host through a shared name can silently select new
# bytes during a build. Both extents would still hash correctly and be covered
# by the eventual signature, but their recorded release identity would be false.
#
# The caller therefore supplies both immutable IMAGE IDs. The root is mounted by
# its derived-installer ID; the skopeo-compatible local host name is independently
# checked against the original-host ID and platform manifest immediately before
# store staging.
INSTALLER_IMG="${INSTALLER_IMG:-}"       # the image whose rootfs becomes the sealed root
STORE_IMG="${STORE_IMG:-}"               # the original host image staged for installation
ROOT_IMAGE_OUT="${ROOT_IMAGE_OUT:-}"     # where the root squashfs is written
STORE_IMAGE_OUT="${STORE_IMAGE_OUT:-}"   # where the store squashfs is written
STORE_IMAGE_NAME="${STORE_IMAGE_NAME:-localhost/bootc}"
INSTALLER_STORAGE_NAME="${INSTALLER_STORAGE_NAME:-localhost/ice-coreos-installer:local}"
STORE_STORAGE_NAME="${STORE_STORAGE_NAME:-localhost/ice-coreos-host:local}"
STORE_MANIFEST_DIGEST="${STORE_MANIFEST_DIGEST:-}"
# Optional explicit SOURCE for the digest-preserving store copy: a registry
# reference (`docker://host/repo@sha256:<manifest>`) whose manifest digest must
# equal STORE_MANIFEST_DIGEST and whose config must be the immutable store image
# ID. A containers-storage source cannot always reproduce the original
# compressed layer streams the manifest names ("would require changing layer
# representation", measured 2026-09-09 on the lab builder with skopeo 1.13.3),
# whereas a registry serves the exact blobs; the local named image is still
# resolved and checked as before. Certificates for that registry come from
# STORE_SOURCE_CERT_DIR; no credential is ever passed.
STORE_SOURCE_REF="${STORE_SOURCE_REF:-}"
STORE_SOURCE_CERT_DIR="${STORE_SOURCE_CERT_DIR:-}"
MANIFEST_OUT="${MANIFEST_OUT:-${ROOT_IMAGE_OUT}.manifest}"

# --------------------------------------------------------------------------- #
# 🔴 THE ALREADY-BUILT STORE (FAB-0057 P1.7). The store is a containers-storage
# holding exactly ONE image, named by a digest. Two media cut for two edits of
# the installer root therefore carry byte-identical stores, and producing it
# twice costs a `skopeo copy` of ~8 GiB plus a single-threaded zstd-19
# `mksquashfs` over the result.
#
# The caller (image/build-installer-usb.sh) may hand that extent back instead,
# with the facts a previous build recorded about it. It is a SIX-VALUE TUPLE and
# it is refused in both directions: a path with no facts is bytes nothing
# describes, and facts with no path describe nothing. The installer ROOT is
# never reusable and has no equivalent -- it is what a change to this tree
# changes.
#
# What is re-proved before a reused byte reaches the payload:
#   * the input is a plain, non-empty, non-symlink file;
#   * it is COPIED to $STORE_IMAGE_OUT and the COPY is re-hashed. Hashing the
#     source and then copying it would hash bytes that no longer have to be the
#     bytes that landed;
#   * the copy's size and SHA-256 equal the recorded ones;
#   * the recorded identity -- config ID, platform manifest digest, store image
#     name -- equals the identity THIS invocation was independently given, which
#     the caller resolved live from the digest-pinned base image with podman.
#
# What it does NOT re-prove: that these bytes contain that image. That was
# derived by the build that produced them, from the staged store's images.json
# and podman's own readback, and is carried forward by the SHA-256. The cache
# is therefore only ever as trustworthy as its directory, which the caller
# requires to be the build user's own, unshared and outside the checkout.
# --------------------------------------------------------------------------- #
STORE_IMAGE_REUSE="${STORE_IMAGE_REUSE:-}"
STORE_IMAGE_REUSE_SHA256="${STORE_IMAGE_REUSE_SHA256:-}"
STORE_IMAGE_REUSE_BYTES="${STORE_IMAGE_REUSE_BYTES:-}"
STORE_IMAGE_REUSE_IMAGE_ID="${STORE_IMAGE_REUSE_IMAGE_ID:-}"
STORE_IMAGE_REUSE_MANIFEST_DIGEST="${STORE_IMAGE_REUSE_MANIFEST_DIGEST:-}"
STORE_IMAGE_REUSE_NAME="${STORE_IMAGE_REUSE_NAME:-}"

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

for required in INSTALLER_IMG STORE_IMG ROOT_IMAGE_OUT STORE_IMAGE_OUT STORE_MANIFEST_DIGEST; do
  [[ -n "${!required}" ]] || die "$required is required"
done
[[ "$STORE_IMAGE_NAME" =~ ^[a-z0-9]([a-z0-9._/-]{0,126}[a-z0-9])?$ ]] \
  || die "STORE_IMAGE_NAME is not a plain local image name: $STORE_IMAGE_NAME"
[[ "$INSTALLER_STORAGE_NAME" =~ ^localhost/[a-z0-9]+([._/-][a-z0-9]+)*:[a-z0-9]+([._-][a-z0-9]+)*$ ]] \
  || die "INSTALLER_STORAGE_NAME is not a tagged localhost image name: $INSTALLER_STORAGE_NAME"
[[ "$STORE_STORAGE_NAME" =~ ^localhost/[a-z0-9]+([._/-][a-z0-9]+)*:[a-z0-9]+([._-][a-z0-9]+)*$ ]] \
  || die "STORE_STORAGE_NAME is not a tagged localhost image name: $STORE_STORAGE_NAME"

# A MUTABLE REFERENCE IS REFUSED OUTRIGHT, not silently resolved. Resolving a tag
# here would reintroduce exactly the split this script exists to prevent: the
# caller would still be free to move it between its own reads and ours.
[[ "$INSTALLER_IMG" =~ ^(sha256:)?[0-9a-f]{64}$ ]] \
  || die "INSTALLER_IMG must be an immutable local image ID (sha256:<64 hex>), not the mutable reference '$INSTALLER_IMG'; a tag can be repointed between the root and the store and the medium would carry two different images"
INSTALLER_IMAGE_ID="${INSTALLER_IMG#sha256:}"
readonly INSTALLER_IMAGE_ID
[[ "$STORE_IMG" =~ ^(sha256:)?[0-9a-f]{64}$ ]] \
  || die "STORE_IMG must be an immutable local image ID (sha256:<64 hex>), not the mutable reference '$STORE_IMG'"
EXPECTED_STORE_IMAGE_ID="${STORE_IMG#sha256:}"
[[ "$STORE_MANIFEST_DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]] \
  || die "STORE_MANIFEST_DIGEST must be the observed immutable platform manifest digest"
readonly EXPECTED_STORE_IMAGE_ID STORE_MANIFEST_DIGEST

# The reuse tuple is validated HERE, before podman is asked for anything: a
# half-supplied tuple must never reach the point where it could be interpreted.
store_reuse_supplied=0
for reuse_value in "$STORE_IMAGE_REUSE" "$STORE_IMAGE_REUSE_SHA256" \
  "$STORE_IMAGE_REUSE_BYTES" "$STORE_IMAGE_REUSE_IMAGE_ID" \
  "$STORE_IMAGE_REUSE_MANIFEST_DIGEST" "$STORE_IMAGE_REUSE_NAME"; do
  [[ -z "$reuse_value" ]] || store_reuse_supplied=$((store_reuse_supplied + 1))
done
case "$store_reuse_supplied" in
  0) ;;
  6)
    [[ "$STORE_IMAGE_REUSE" = /* ]] \
      || die "STORE_IMAGE_REUSE must be an absolute path: $STORE_IMAGE_REUSE"
    [[ -f "$STORE_IMAGE_REUSE" && ! -L "$STORE_IMAGE_REUSE" && -s "$STORE_IMAGE_REUSE" ]] \
      || die "STORE_IMAGE_REUSE is missing, empty, or not a plain file: $STORE_IMAGE_REUSE"
    [[ "$STORE_IMAGE_REUSE_SHA256" =~ ^[0-9a-f]{64}$ ]] \
      || die "STORE_IMAGE_REUSE_SHA256 must be a lowercase SHA-256: $STORE_IMAGE_REUSE_SHA256"
    [[ "$STORE_IMAGE_REUSE_BYTES" =~ ^[1-9][0-9]*$ ]] \
      || die "STORE_IMAGE_REUSE_BYTES must be a positive byte count: $STORE_IMAGE_REUSE_BYTES"
    # 🔴 THE REUSED STORE MUST BE THE STORE THIS BUILD SELECTED. The three
    # identity values below were resolved live from the digest-pinned base image
    # by the caller; an entry recorded around any other image is refused before
    # a byte is copied, so a stale cache cannot substitute the appliance a
    # medium installs.
    [[ "$STORE_IMAGE_REUSE_IMAGE_ID" == "$EXPECTED_STORE_IMAGE_ID" ]] \
      || die "the reusable store records image $STORE_IMAGE_REUSE_IMAGE_ID, but this build selected $EXPECTED_STORE_IMAGE_ID"
    [[ "$STORE_IMAGE_REUSE_MANIFEST_DIGEST" == "$STORE_MANIFEST_DIGEST" ]] \
      || die "the reusable store records manifest $STORE_IMAGE_REUSE_MANIFEST_DIGEST, but this build selected $STORE_MANIFEST_DIGEST"
    [[ "$STORE_IMAGE_REUSE_NAME" == "$STORE_IMAGE_NAME" ]] \
      || die "the reusable store offers the image as '$STORE_IMAGE_REUSE_NAME', but this build installs from '$STORE_IMAGE_NAME'"
    ;;
  *)
    die "reusing a store requires all six of STORE_IMAGE_REUSE, _SHA256, _BYTES, _IMAGE_ID, _MANIFEST_DIGEST and _NAME; a half-described extent is bytes nothing accounts for"
    ;;
esac
readonly STORE_IMAGE_REUSE STORE_IMAGE_REUSE_SHA256 STORE_IMAGE_REUSE_BYTES

PODMAN_BIN="$(tool podman)"
MOUNTPOINT_BIN="$(tool mountpoint)"
UMOUNT_BIN="$(tool umount)"
podman_run() { "$PODMAN_BIN" "$@"; }

# Prove the immutable ID itself resolves before reading any root bytes.
RESOLVED_IMAGE_ID="$(podman_run image inspect --format '{{.Id}}' "sha256:$INSTALLER_IMAGE_ID" 2>/dev/null \
  | tr -d '[:space:]' | sed 's/^sha256://')" \
  || die "cannot resolve the installer image ID $INSTALLER_IMAGE_ID in local storage"
[[ "$RESOLVED_IMAGE_ID" == "$INSTALLER_IMAGE_ID" ]] \
  || die "local storage resolves $INSTALLER_IMAGE_ID to '$RESOLVED_IMAGE_ID'; refusing to seal an image that is not the one this build was given"
RESOLVED_STORE_IMAGE_ID="$(podman_run image inspect --format '{{.Id}}' "sha256:$EXPECTED_STORE_IMAGE_ID" 2>/dev/null \
  | tr -d '[:space:]' | sed 's/^sha256://')" \
  || die "cannot resolve the store image ID $EXPECTED_STORE_IMAGE_ID in local storage"
[[ "$RESOLVED_STORE_IMAGE_ID" == "$EXPECTED_STORE_IMAGE_ID" ]] \
  || die "local storage resolves store image $EXPECTED_STORE_IMAGE_ID to '${RESOLVED_STORE_IMAGE_ID:-nothing}'"

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
  local exit_status=$? overlay_mount="$WORK/store/overlay"
  set +e
  if [[ -n "$MOUNTED" ]]; then
    podman_run image umount "sha256:$INSTALLER_IMAGE_ID" >/dev/null 2>&1 || true
    MOUNTED=""
  fi
  # skopeo's destination containers-storage can leave its overlay graphroot
  # mounted after a failed copy. This exact path is inside this invocation's
  # mktemp directory; no host or shared storage mount is ever targeted.
  if "$MOUNTPOINT_BIN" -q -- "$overlay_mount" 2>/dev/null; then
    if ! "$UMOUNT_BIN" -- "$overlay_mount" >/dev/null 2>&1; then
      echo "build-installer-root: WARNING: cannot unmount task-owned $overlay_mount; preserving work directory $WORK" >&2
      return 1
    fi
  fi
  if "$MOUNTPOINT_BIN" -q -- "$overlay_mount" 2>/dev/null; then
    echo "build-installer-root: WARNING: task-owned $overlay_mount remains mounted after unmount; preserving work directory $WORK" >&2
    return 1
  fi
  if ! rm -rf -- "$WORK"; then
    echo "build-installer-root: WARNING: cannot remove task-owned work directory $WORK" >&2
    (( exit_status != 0 )) || exit_status=1
  fi
  return "$exit_status"
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
if [[ -n "$STORE_IMAGE_REUSE" ]]; then
  echo "==> reusing an already-built ${STORE_IMAGE_NAME} store image"
  rm -f -- "$STORE_IMAGE_OUT"
  # --reflink=auto: a copy-on-write clone where the filesystem supports one, a
  # full copy otherwise (cp(1), GNU coreutils). Never a hard link: the payload
  # assembler pads this file in place, which through a shared inode would
  # rewrite the cache entry it was reused from.
  "$(tool cp)" --reflink=auto -- "$STORE_IMAGE_REUSE" "$STORE_IMAGE_OUT" \
    || die "cannot place the reusable store image at $STORE_IMAGE_OUT"
  [[ -f "$STORE_IMAGE_OUT" && ! -L "$STORE_IMAGE_OUT" ]] \
    || die "the reusable store image did not land as a plain file at $STORE_IMAGE_OUT"
  # 🔴 THE COPY IS WHAT IS HASHED. Hashing $STORE_IMAGE_REUSE and then copying
  # it would prove something about bytes that no longer have to be the bytes
  # the payload will seal; these two lines measure the extent this build uses.
  STORE_IMAGE_SHA256="$(sha256_of "$STORE_IMAGE_OUT")"
  STORE_IMAGE_BYTES="$(wc -c < "$STORE_IMAGE_OUT" | tr -d '[:space:]')"
  [[ "$STORE_IMAGE_BYTES" == "$STORE_IMAGE_REUSE_BYTES" ]] \
    || die "the reused store image is $STORE_IMAGE_BYTES bytes, not the $STORE_IMAGE_REUSE_BYTES it is recorded as; refusing to seal an extent nothing accounts for"
  [[ "$STORE_IMAGE_SHA256" == "$STORE_IMAGE_REUSE_SHA256" ]] \
    || die "the reused store image hashes to $STORE_IMAGE_SHA256, not the recorded $STORE_IMAGE_REUSE_SHA256; refusing to seal an extent nothing accounts for"
  STORE_IMAGE_ID="$STORE_IMAGE_REUSE_IMAGE_ID"
  STORE_IMAGE_MANIFEST_DIGEST="$STORE_IMAGE_REUSE_MANIFEST_DIGEST"
  echo "    reused store image: $STORE_IMAGE_BYTES bytes, sha256 $STORE_IMAGE_SHA256"
  echo "    reused store holds: image $STORE_IMAGE_ID, manifest $STORE_IMAGE_MANIFEST_DIGEST, offered as $STORE_IMAGE_NAME"
  podman_run image umount "sha256:$INSTALLER_IMAGE_ID" >/dev/null 2>&1 || true
  MOUNTED=""
else
# The staging arm below is deliberately NOT re-indented under this `else`: it is
# unchanged code, and re-indenting it would turn a reviewable 30-line addition
# into a 70-line diff in which the one line that matters is hard to find.
echo "==> staging ${STORE_IMAGE_NAME} into a containers-storage"
STORE_TREE="$WORK/store"
mkdir -p -- "$STORE_TREE" "$WORK/runroot"
# skopeo 1.13.3 cannot parse a containers-storage source addressed directly by
# config digest. Use the stable local name only as its transport handle, after
# independently proving that the name still resolves to the immutable original
# host selected for the install store.
NAMED_IMAGE_ID="$(podman_run image inspect --format '{{.Id}}' "$STORE_STORAGE_NAME" 2>/dev/null \
  | tr -d '[:space:]' | sed 's/^sha256://')" \
  || die "cannot resolve the host storage name $STORE_STORAGE_NAME"
[[ "$NAMED_IMAGE_ID" == "$EXPECTED_STORE_IMAGE_ID" ]] \
  || die "host storage name $STORE_STORAGE_NAME resolves to '${NAMED_IMAGE_ID:-nothing}', not immutable image $EXPECTED_STORE_IMAGE_ID"
NAMED_MANIFEST_DIGEST="$(podman_run image inspect --format '{{.Digest}}' "$STORE_STORAGE_NAME" 2>/dev/null \
  | tr -d '[:space:]')" \
  || die "cannot resolve the host storage manifest digest for $STORE_STORAGE_NAME"
[[ "$NAMED_MANIFEST_DIGEST" == "$STORE_MANIFEST_DIGEST" ]] \
  || die "host storage name $STORE_STORAGE_NAME resolves to manifest '${NAMED_MANIFEST_DIGEST:-nothing}', not $STORE_MANIFEST_DIGEST"
STORE_COPY_SOURCE="containers-storage:${STORE_STORAGE_NAME}"
STORE_COPY_SOURCE_ARGS=()
if [[ -n "$STORE_SOURCE_REF" ]]; then
  [[ "$STORE_SOURCE_REF" =~ ^docker://[A-Za-z0-9.-]+(:[0-9]{1,5})?/[a-z0-9]+([._-][a-z0-9]+)*(/[a-z0-9]+([._-][a-z0-9]+)*)*@sha256:[0-9a-f]{64}$ ]] \
    || die "STORE_SOURCE_REF must be a digest-pinned registry reference: $STORE_SOURCE_REF"
  [[ "${STORE_SOURCE_REF##*@}" == "$STORE_MANIFEST_DIGEST" ]] \
    || die "STORE_SOURCE_REF names manifest ${STORE_SOURCE_REF##*@}, not the store manifest $STORE_MANIFEST_DIGEST"
  if [[ -n "$STORE_SOURCE_CERT_DIR" ]]; then
    [[ -d "$STORE_SOURCE_CERT_DIR" ]] || die "STORE_SOURCE_CERT_DIR is not a directory: $STORE_SOURCE_CERT_DIR"
    STORE_COPY_SOURCE_ARGS+=(--src-cert-dir "$STORE_SOURCE_CERT_DIR")
  fi
  # The registry's answer is bound to the SAME two identities the local store
  # was: the manifest bytes must hash to STORE_MANIFEST_DIGEST and name the
  # immutable store image as their config. Bounded read; the reference's
  # digest is what the registry is asked for, so a substituted answer cannot
  # pass both checks.
  SOURCE_MANIFEST_RAW="$WORK/store-source-manifest.json"
  "$(tool skopeo)" inspect --raw --no-creds "${STORE_COPY_SOURCE_ARGS[@]/--src-cert-dir/--cert-dir}" "$STORE_SOURCE_REF" \
    | head -c 4194304 > "$SOURCE_MANIFEST_RAW" \
    || die "cannot read the store source manifest from $STORE_SOURCE_REF"
  [[ "sha256:$(sha256_of "$SOURCE_MANIFEST_RAW")" == "$STORE_MANIFEST_DIGEST" ]] \
    || die "the store source at $STORE_SOURCE_REF serves a manifest that does not hash to $STORE_MANIFEST_DIGEST"
  SOURCE_CONFIG_DIGEST="$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d.get("config",{}).get("digest",""))' "$SOURCE_MANIFEST_RAW")" \
    || die "the store source manifest is not a JSON image manifest"
  [[ "$SOURCE_CONFIG_DIGEST" == "sha256:${EXPECTED_STORE_IMAGE_ID}" ]] \
    || die "the store source manifest names config '${SOURCE_CONFIG_DIGEST:-nothing}', not the immutable store image ${EXPECTED_STORE_IMAGE_ID}"
  STORE_COPY_SOURCE="$STORE_SOURCE_REF"
  STORE_COPY_SOURCE_ARGS+=(--src-no-creds)
  echo "    store source: ${STORE_SOURCE_REF} (manifest and config identities verified)"
fi
"$(tool skopeo)" copy \
  --preserve-digests \
  "${STORE_COPY_SOURCE_ARGS[@]}" \
  "$STORE_COPY_SOURCE" \
  "containers-storage:[overlay@${STORE_TREE}+${WORK}/runroot]${STORE_IMAGE_NAME}" \
  || die "cannot stage the original host image into the medium image store"
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
# 🔴 THE STORE MUST HOLD THE EXACT ORIGINAL HOST. The live installer root is a
# derived image, while preseal/current_os_ref authorize BASE_IMAGE. Staging the
# derived installer here would produce a verity-valid medium whose local source
# can never satisfy that authorization. containers-storage records config IDs,
# but that alone is insufficient because a different manifest can reuse the
# same config. Require one image with the selected host config ID, then ask the
# destination store itself for its preserved platform-manifest digest.
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
[[ "$STORE_IMAGE_ID" == "$EXPECTED_STORE_IMAGE_ID" ]] \
  || die "the staged image store holds image $STORE_IMAGE_ID but the build selected $EXPECTED_STORE_IMAGE_ID"
STORE_IMAGE_MANIFEST_DIGEST="$(podman_run --root "$STORE_TREE" --runroot "$WORK/runroot" \
  --storage-driver overlay image inspect --format '{{.Digest}}' "$STORE_IMAGE_NAME" 2>/dev/null \
  | tr -d '[:space:]')" \
  || die "the staged image store cannot read back the host platform manifest digest"
[[ "$STORE_IMAGE_MANIFEST_DIGEST" == "$STORE_MANIFEST_DIGEST" ]] \
  || die "the staged store manifest $STORE_IMAGE_MANIFEST_DIGEST differs from selected host $STORE_MANIFEST_DIGEST"

echo "==> mksquashfs (image store) -> ${STORE_IMAGE_OUT}"
squash "$STORE_TREE" "$STORE_IMAGE_OUT"
STORE_IMAGE_SHA256="$(sha256_of "$STORE_IMAGE_OUT")"
STORE_IMAGE_BYTES="$(wc -c < "$STORE_IMAGE_OUT" | tr -d '[:space:]')"

podman_run image umount "sha256:$INSTALLER_IMAGE_ID" >/dev/null 2>&1 || true
MOUNTED=""
fi

# --------------------------------------------------------------------------- #
# 3) The manifest CI diffs. A changed image must show up as a one-line diff
#    rather than as several GiB of squashfs.
# --------------------------------------------------------------------------- #
{
  printf 'schema=%s\n' "neural-ice-installer-root-manifest-v4"
  printf 'installer_image_id=%s\n' "$INSTALLER_IMAGE_ID"
  printf 'installer_root_marker_sha256=%s\n' "$MARKER_DIGEST"
  printf 'root_image_bytes=%s\n' "$ROOT_IMAGE_BYTES"
  printf 'root_image_sha256=%s\n' "$ROOT_IMAGE_SHA256"
  printf 'store_image_bytes=%s\n' "$STORE_IMAGE_BYTES"
  printf 'store_image_id=%s\n' "$STORE_IMAGE_ID"
  printf 'store_image_manifest_digest=%s\n' "$STORE_IMAGE_MANIFEST_DIGEST"
  printf 'store_image_name=%s\n' "$STORE_IMAGE_NAME"
  printf 'store_image_sha256=%s\n' "$STORE_IMAGE_SHA256"
} > "$MANIFEST_OUT"
echo "==> manifest: $MANIFEST_OUT"
cat "$MANIFEST_OUT"
