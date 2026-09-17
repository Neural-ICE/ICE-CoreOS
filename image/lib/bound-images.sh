# shellcheck shell=bash
# THE APPLIANCE'S LOGICALLY BOUND IMAGES, AS THE MEDIUM CARRIES THEM AND AS THE
# INSTALLER COPIES THEM. One implementation, sourced by the medium builder
# (image/build-installer-root.sh), the installer (ota/neural-ice-autoinstall.sh)
# and the bench rehearsal (image/bench-rehearse-phase4.sh).
#
# 🔴 WHY OCI LAYOUTS AND NOT IMAGES IN THE SEALED containers-storage
# (bench .63, 2026-09-17). bootc install resolves each bound image from the
# container it runs in and copies it into the deployment's own store with
# `podman image push --remove-signatures <ref> containers-storage:[overlay@…]<ref>`
# (bootc v1.16.6 podstorage.rs:449-469). That copy can never land a
# DIGEST-PINNED bound image out of a containers-storage source, for two
# reasons proved on the bench with the appliance's own podman 6.0.2 / skopeo
# 1.23.0:
#   1. libimage resolves the source by name and then hands the copy an ID-only
#      storage reference (containers/common libimage/runtime.go,
#      `ParseStoreReference(r.store, img.ID)`), so the source's top-level
#      manifest is the platform INSTANCE, not the index the quadlet pins
#      (`skopeo inspect --raw containers-storage:@<id>` hashed to the instance,
#      the digested reference to the index);
#   2. a containers-storage source serves layers UNCOMPRESSED, so c/image must
#      rewrite the instance manifest, which it refuses under a digested
#      destination ("Copying this image would require changing layer
#      representation, which we cannot do: Destination specifies a digest").
#   The destination check (c/image storage_dest.go, CommitWithOptions) accepts
#   the pinned digest only if it matches the manifest being written or the
#   source's top-level manifest -- neither can hold. Observed as
#   `Digest of source image's manifest would not match destination reference`
#   after 22/22 images were staged in the bench store, 0/22 copied.
#
# An OCI LAYOUT serves the original compressed blobs verbatim. Written as two
# skopeo copies from the registry -- `--multi-arch index-only` under the tag
# `list` (the index, byte for byte, whose SHA-256 is the pinned digest) and
# `--multi-arch system` for the appliance's architecture under the tag
# `system` (the one instance and its blobs; no other platform's bytes) -- it
# copies into a containers-storage under `<repo>@<index digest>` with
# `--preserve-digests`: the source's top-level manifest IS the index, the
# instance is written unchanged, the check passes. Measured 2026-09-17 on the
# bench for working-memory: layout 12 MiB, 22 blobs, arm64 only; imported into
# a scratch target store by the appliance's skopeo, `podman image exists` 0,
# readback hashed to the index. The installer therefore runs phase 4 with
# `--bound-images=skip` (a hidden but accepted value of bootc 1.16.6,
# install.rs BoundImagesOpt) and performs the copy itself, per image, with the
# same c/image + c/storage writer bootc would have used.
#
# The layouts live inside the sealed store squashfs, beside the
# containers-storage directories, under one directory named by the pinned
# index digest: containers/storage never enumerates the root of an additional
# image store, so the directory is invisible to podman and covered by the same
# dm-verity root hash as the store.

NI_BOUND_IMAGES_SKOPEO="${NI_BOUND_IMAGES_SKOPEO:-skopeo}"
NI_BOUND_IMAGES_PYTHON="${NI_BOUND_IMAGES_PYTHON:-python3}"
NI_BOUND_IMAGES_DIRNAME=neural-ice-bound-images
NI_BOUND_IMAGES_LIST_TAG=list
NI_BOUND_IMAGES_SYSTEM_TAG=system
# A bound image reference the medium can prove: registry, repository path, and
# an index digest. A tag is a name that cannot be proved present. Read by the
# three scripts that source this file, which shellcheck cannot see from here.
# shellcheck disable=SC2034
NI_BOUND_IMAGE_REF_GRAMMAR='^[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?(/[a-z0-9]+([._-][a-z0-9]+)*)+@sha256:[0-9a-f]{64}$'

ni_bound_image_layout_dir() { # $1=store root $2=bound image reference -> the layout directory
  printf '%s/%s/%s' "$1" "$NI_BOUND_IMAGES_DIRNAME" "${2##*@sha256:}"
}

ni_bound_image_arch() { # -> the OCI architecture of THIS machine, or 1
  case "$(uname -m)" in
    aarch64 | arm64) echo arm64 ;;
    x86_64 | amd64) echo amd64 ;;
    *) return 1 ;;
  esac
}

# Stage one bound image as a layout. $1=source reference (docker://… on the
# medium builder; the suite feeds an oci: fixture) $2=layout directory
# $3=OCI architecture of the appliance; the rest are skopeo source options
# (--src-cert-dir, --src-no-creds). Two copies, on purpose: `system` alone
# records the instance as the layout's top-level and the index is lost;
# `all` carries every platform's blobs, which the appliance never boots.
ni_bound_image_stage_layout() {
  local source=$1 dir=$2 arch=$3
  shift 3
  rm -rf -- "$dir" || return 1
  mkdir -p -- "$dir" || return 1
  "$NI_BOUND_IMAGES_SKOPEO" copy --preserve-digests --multi-arch index-only "$@" \
    "$source" "oci:${dir}:${NI_BOUND_IMAGES_LIST_TAG}" || return 1
  "$NI_BOUND_IMAGES_SKOPEO" --override-os linux --override-arch "$arch" \
    copy --preserve-digests --multi-arch system "$@" \
    "$source" "oci:${dir}:${NI_BOUND_IMAGES_SYSTEM_TAG}" || return 1
}

# Prove a layout is what the copy at install needs: the `list` tag hashes to
# the pinned digest; it is either an index naming exactly one linux/<arch>
# instance, or -- for an image published for one platform only, as the
# GB10-specific runtimes are (model-runtime-gb10, paddleocr-vl-api, bench
# 2026-09-17) -- the instance manifest itself, whose config must declare
# linux/<arch>; the `system` tag is that instance and hashes to its digest;
# the instance's config and every layer blob exist at their recorded sizes.
# Layer blobs are not re-hashed here -- on the medium they sit under the
# store's dm-verity root hash, and at build time skopeo has just verified them.
# $1=layout directory $2=pinned digest (64 hex) $3=OCI architecture
# -> 0, or one line naming the first defect on stdout and 1.
ni_bound_image_verify_layout() {
  "$NI_BOUND_IMAGES_PYTHON" - "$1" "$2" "$3" "$NI_BOUND_IMAGES_LIST_TAG" "$NI_BOUND_IMAGES_SYSTEM_TAG" <<'PY'
import hashlib, json, os, sys

layout, pinned, arch, list_tag, system_tag = sys.argv[1:]
REF = "org.opencontainers.image.ref.name"

def refuse(reason):
    print(reason)
    raise SystemExit(1)

def blob_path(digest):
    algorithm, _, hex_digest = digest.partition(":")
    return os.path.join(layout, "blobs", algorithm, hex_digest)

def read_blob(digest, what):
    path = blob_path(digest)
    if not os.path.isfile(path):
        refuse(f"{what} blob {digest} is missing from the layout")
    with open(path, "rb") as handle:
        data = handle.read()
    if "sha256:" + hashlib.sha256(data).hexdigest() != digest:
        refuse(f"{what} blob {digest} does not hash to its name")
    return data

try:
    with open(os.path.join(layout, "index.json"), encoding="utf-8") as handle:
        index = json.load(handle)
except (OSError, ValueError) as error:
    refuse(f"the layout has no readable index.json: {error}")
tags = {}
for entry in index.get("manifests", []):
    name = (entry.get("annotations") or {}).get(REF)
    if name:
        tags[name] = entry
if list_tag not in tags:
    refuse(f"the layout carries no '{list_tag}' tag (the index)")
if system_tag not in tags:
    refuse(f"the layout carries no '{system_tag}' tag (the instance for this machine)")
list_digest = tags[list_tag].get("digest", "")
if list_digest != "sha256:" + pinned:
    refuse(f"the '{list_tag}' tag is {list_digest}, not the pinned sha256:{pinned}")
top = json.loads(read_blob(list_digest, "pinned"))
LISTS = ("application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json")
IMAGES = ("application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json")
top_type = top.get("mediaType") or tags[list_tag].get("mediaType", "")
if top_type in LISTS:
    instances = [
        entry for entry in top.get("manifests", [])
        if (entry.get("platform") or {}).get("os") == "linux"
        and (entry.get("platform") or {}).get("architecture") == arch
    ]
    if len(instances) != 1:
        refuse(f"the index names {len(instances)} linux/{arch} instances; the copy needs exactly one")
    instance_digest = instances[0].get("digest", "")
    instance = json.loads(read_blob(instance_digest, "instance manifest"))
elif top_type in IMAGES:
    # Published for one platform only: the pinned digest IS the instance, and
    # the platform is stated by its config.
    instance_digest, instance = list_digest, top
else:
    refuse(f"the pinned manifest is neither an index nor an image manifest ({top_type or 'no mediaType'})")
system_digest = tags[system_tag].get("digest", "")
if system_digest != instance_digest:
    refuse(f"the '{system_tag}' tag is {system_digest}, not the linux/{arch} instance {instance_digest}")
config = instance.get("config") or {}
config_document = json.loads(read_blob(config.get("digest", ""), "config"))
if top_type in IMAGES and (config_document.get("os"), config_document.get("architecture")) != ("linux", arch):
    refuse(f"the image is {config_document.get('os')}/{config_document.get('architecture')}, not linux/{arch}")
for layer in instance.get("layers", []):
    path = blob_path(layer.get("digest", ""))
    if not os.path.isfile(path):
        refuse(f"layer blob {layer.get('digest')} is missing from the layout")
    if os.path.getsize(path) != layer.get("size"):
        refuse(f"layer blob {layer.get('digest')} is {os.path.getsize(path)} bytes, not the {layer.get('size')} its manifest records")
PY
}

# Copy one layout into a containers-storage under the exact reference the
# quadlet names. $1=layout directory $2=destination (a full
# `containers-storage:[…]<repo>@sha256:<index>` reference). The source is the
# `list` tag, so the copy's top-level manifest is the index and the digested
# destination is accepted.
ni_bound_image_import() {
  "$NI_BOUND_IMAGES_SKOPEO" copy --preserve-digests \
    "oci:${1}:${NI_BOUND_IMAGES_LIST_TAG}" "$2"
}
