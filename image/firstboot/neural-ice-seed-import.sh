#!/usr/bin/env bash
# Crash-safe first-boot publication of a staged, already-verified SEED v2 pack.
set -euo pipefail
umask 077

die() { echo "neural-ice-seed-import: REFUSED: $*" >&2; exit 1; }

# Tests may redirect the complete filesystem only as an unprivileged process and
# only when the immutable release marker is absent. A release/root invocation
# always uses the fixed production paths and cannot select dry-run tooling.
ROOT_PREFIX=/
if [[ -n ${NI_SEED_IMPORT_ROOT:-} || ${NI_SEED_IMPORT_DRY_RUN:-0} != 0 \
   || -n ${NI_SEED_IMPORT_FAIL_AFTER:-} ]]; then
  [[ $EUID -ne 0 ]] || die "test roots and dry-run are forbidden to root"
  [[ ! -e /usr/lib/neural-ice/release-image ]] || die "test roots and dry-run are forbidden in a release image"
  [[ -n ${NI_SEED_IMPORT_ROOT:-} && ${NI_SEED_IMPORT_ROOT:0:1} == / ]] || die "test root must be absolute"
  ROOT_PREFIX=${NI_SEED_IMPORT_ROOT%/}
fi
path() { printf '%s%s' "$ROOT_PREFIX" "$1"; }

case ${NI_SEED_IMPORT_FAIL_AFTER:-} in
  ''|container|content|models|content-caches|hf-cache|relabel|ready|generation|consumer-links|commit) ;;
  *) die "unknown firstboot fault-injection boundary" ;;
esac
durable_boundary() {
  [[ ${NI_SEED_IMPORT_FAIL_AFTER:-} != "$1" ]] \
    || die "test fault injected after durable boundary: $1"
}

DATA=$(path /var/lib/neural-ice/data)
RELEASE="$DATA/release"
POINTER="$RELEASE/CLOSURE"
VERIFIER=$(path /usr/bin/ni-ota-verify)
# containers/image consults /etc/containers/policy.json for every copy, and the
# appliance's is fail-closed: default reject, docker: scopes only. The oci:
# layouts below are assembled by THIS script from objects ni-ota-verify has
# already checked against the signed closure, so the transport needs no second
# signature check -- but the strict file rejects the oci: transport outright
# ("Source image rejected: … is rejected by policy", lab GX10, 2026-09-10).
# Hand skopeo the seed-import policy instead: default reject, one oci: scope
# (the offline-generations directory, a mount, no symlink), nothing for docker:.
# The system policy is never touched.
SEED_POLICY=$(path /usr/lib/neural-ice/seed-import-policy.json)
[[ -f $SEED_POLICY && ! -L $SEED_POLICY ]] || die "seed-import transport policy is missing"
ROOT_KEY=$(path /etc/neural-ice/keys/ota-root.pub)
REGISTRY="$RELEASE/AUTHORITY"
CHANNEL="$RELEASE/CHANNEL"
TRUSTED_NOW="$RELEASE/TRUSTED-NOW"
HARDWARE=$(path /usr/lib/neural-ice/hardware-target)
PROFILE=$(path /usr/lib/neural-ice/access-policy)
POLICY=$(path /usr/lib/neural-ice/signed-boot-trust-policy-id)
MODEL_HELPER=$(path /usr/libexec/neural-ice-model-cache-contract)
CONTENT_CACHE_HELPER=$(path /usr/libexec/neural-ice-content-cache-contract)
# The OS-side bootc store. `bootc install` copies the medium's logically bound
# images into it, and every quadlet lists it FIRST in its
# --storage-opt=additionalimagestore= (the seed store comes second). Handed to
# the engine with the quadlets' spelling, symlink included (bootc points it
# under /sysroot): the runtime and this script must name the same store.
OS_IMAGE_STORE=$(path /usr/lib/bootc/storage)

[[ -f $POINTER && ! -L $POINTER ]] || exit 0
IFS= read -r closure < "$POINTER"
closure=${closure#sha256:}
[[ $closure =~ ^[0-9a-f]{64}$ ]] || die "CLOSURE pointer is malformed"
IFS= read -r manifest < "$RELEASE/MANIFEST"
[[ $manifest =~ ^[0-9a-f]{64}$ ]] || die "MANIFEST pointer is malformed"

generation_base="$DATA/offline-generations"
generation="$generation_base/$closure"
candidate="$generation_base/.${closure}.staging"
commit_pointer="$DATA/offline-current"
# A committed generation was fully verified before its sole publication event.
# Reboots consume that immutable receipt and do not reinterpret an expired
# authorization. This is the idempotent fast path; an incomplete/mixed view
# falls through to full re-verification and recovery.
if [[ -L $commit_pointer \
   && $(readlink -- "$commit_pointer") == "offline-generations/$closure" \
   && -f $generation/READY && ! -L $generation/READY \
   && $(readlink -- "$DATA/seed-store/current" 2>/dev/null || true) == '../offline-current/seed-store/graphroot' \
   && $(readlink -- "$DATA/content/current" 2>/dev/null || true) == '../offline-current/content' \
   && $(readlink -- "$DATA/models/current" 2>/dev/null || true) == '../offline-current/models' \
   && $(readlink -- "$DATA/hf-cache/hub" 2>/dev/null || true) == '../offline-current/hf-cache/hub' \
   && $(readlink -- "$DATA/OFFLINE-READY" 2>/dev/null || true) == 'offline-current/READY' \
   && $(grep -Fxc "release_closure_sha256=$closure" "$generation/READY") == 1 \
   && $(grep -Fxc "release_manifest_sha256=$manifest" "$generation/READY") == 1 ]]; then
  exit 0
fi

source_root="$RELEASE/$closure"
[[ -d $source_root && ! -L $source_root ]] || die "staged closure is absent"
for input in "$ROOT_KEY" "$REGISTRY" "$CHANNEL" "$TRUSTED_NOW" "$HARDWARE" "$PROFILE" "$POLICY"; do
  [[ -f $input && ! -L $input ]] || die "required immutable input is absent: $input"
done
[[ -x $VERIFIER && ! -L $VERIFIER ]] || die "seed verifier is absent or not executable"
[[ -x $MODEL_HELPER && ! -L $MODEL_HELPER ]] || die "model-cache contract helper is absent or not executable"
[[ -x $CONTENT_CACHE_HELPER && ! -L $CONTENT_CACHE_HELPER ]] \
  || die "content-cache contract helper is absent or not executable"
[[ $(sha256sum -- "$source_root/release-manifest.json" | awk '{print tolower($1)}') == "$manifest" ]] \
  || die "staged manifest does not match its sealed pointer"
IFS= read -r pcr_policy < "$RELEASE/PCR-POLICY"
IFS= read -r pcr_key < "$RELEASE/PCR-POLICY-KEY"
IFS= read -r pcr_signature < "$RELEASE/PCR-POLICY-SIGNATURE"
IFS= read -r pcr_seq < "$RELEASE/PCR-POLICY-SEQ"
[[ $pcr_policy =~ ^[0-9a-f]{64}$ && $pcr_key =~ ^[0-9a-f]{64}$ \
   && $pcr_signature =~ ^[0-9a-f]{64}$ && $pcr_seq =~ ^[1-9][0-9]{0,18}$ ]] \
  || die "staged PCR policy pointers are malformed"
IFS= read -r now < "$TRUSTED_NOW"
[[ $now =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] \
  || die "sealed seed trusted time is malformed"
registry_host=$(<"$REGISTRY")
"$VERIFIER" verify-seed-closure --seed-root "$source_root" --pubkey "$ROOT_KEY" \
  --registry-host "$registry_host" --hardware-target "$(<"$HARDWARE")" \
  --access-profile "$(<"$PROFILE")" --trust-policy-id "$(<"$POLICY")" \
  --device-channel "$(<"$CHANNEL")" \
  --expect-closure "$closure" --expect-manifest "$manifest" --trusted-now "$now" \
  --pcr-policy-digest "$pcr_policy" --pcr-policy-public-key-sha256 "$pcr_key" \
  --pcr-policy-signature-sha256 "$pcr_signature" --pcr-policy-seq "$pcr_seq" \
  >/dev/null || die "staged release pack failed first-boot re-verification"

# Every consumer resolves through this one pointer. The fixed compatibility
# links never move; publishing offline-current is the sole visibility event for
# the container store, generic CASes, HF hub and OFFLINE-READY receipt.
install -d -m 0700 "$generation_base" "$DATA/seed-store" "$DATA/content" \
  "$DATA/models" "$DATA/hf-cache" "$DATA/tmp"
# skopeo's staging area for the layers it imports: containers/image ignores
# TMPDIR on Linux and stages under /var/tmp unless --tmpdir says otherwise
# (measured on the lab GX10, 2026-09-10); /var/tmp is read-only in this sandbox
# and on the 100 GiB system volume anyway. The data volume has the room.

ensure_consumer_link() {
  local link=$1 target=$2 temporary
  if [[ -L $link ]]; then
    [[ $(readlink -- "$link") == "$target" ]] \
      || die "consumer path $link bypasses the atomic offline generation pointer"
    return
  fi
  [[ ! -e $link ]] || die "consumer path $link is not the required generation indirection"
  temporary="${link}.new.$$"
  ln -s -- "$target" "$temporary"
  mv -Tf -- "$temporary" "$link"
  sync -f "$(dirname -- "$link")"
}

generation_ready=0
if [[ -f $generation/READY && ! -L $generation/READY ]] \
   && grep -Fqx 'schema=neural-ice-offline-generation-v1' "$generation/READY" \
   && grep -Fqx "release_closure_sha256=$closure" "$generation/READY" \
   && grep -Fqx "release_manifest_sha256=$manifest" "$generation/READY"; then
  generation_ready=1
fi
if [[ $generation_ready == 0 ]]; then
  [[ ! -e $generation ]] || die "generation exists without an exact READY receipt"
  rm -rf -- "$candidate"
  install -d -m 0700 "$candidate/seed-store/graphroot" \
    "$candidate/seed-store/runroot" "$candidate/seed-store/layouts" \
    "$candidate/content/sha256" "$candidate/models/sha256"

# Turn each signed closure root into a minimal OCI layout. index.json is
# generated from the signed root descriptor; no input index.json is copied or
# consulted. The plan is NUL-separated to keep repositories out of shell code.
plan="$candidate/seed-store/import-plan"
python3 - "$source_root/release-closure.json" "$source_root/objects/sha256" \
  "$candidate/seed-store/layouts" "$plan" <<'PY'
import fcntl, json, pathlib, shutil, sys
closure_path, objects_path, layouts_path, plan_path = map(pathlib.Path, sys.argv[1:])
def place(source, target):
    # The staged objects and every published view live on the same XFS volume
    # (reflink=1): a clone shares the extents and costs nothing, a copy is
    # 129 GiB more per view (GX10 .67, 2026-09-12: 434 GB used for one 130 GB
    # seed). Not a hard link: the cache contracts require every staged object
    # to stay a single-link regular file. A filesystem without clones gets the
    # copy, byte for byte.
    FICLONE = 0x40049409
    with open(source, "rb") as src, open(target, "wb") as dst:
        try:
            fcntl.ioctl(dst.fileno(), FICLONE, src.fileno())
            return
        except OSError:
            pass
    shutil.copyfile(source, target)
closure = json.loads(closure_path.read_bytes())
records = []
for number, artifact in enumerate(closure["artifacts"]):
    # The verified closure distinguishes executable components from OS/content
    # artifacts. Models and all signature/SBOM attachments stay in the CAS below;
    # containers-storage cannot import those artifact-specific configurations.
    if not artifact["artifact_key"].startswith("image:"):
        continue
    if artifact["artifact_class"] not in (
        "portable-multiarch-image", "hardware-targeted-manifest",
    ):
        raise SystemExit("component is not an executable image class")
    repository, root_value = artifact["repository"], artifact["root"]
    root = root_value["digest"] if isinstance(root_value, dict) else root_value
    nodes = {node["digest"]: node for node in artifact["nodes"]}
    node = nodes[root]
    imports = [(root, node["media_type"], node["size"], {n["digest"] for n in artifact["nodes"]}, artifact["artifact_key"])]
    for subnumber, (import_root, media_type, size, wanted, label) in enumerate(imports):
        layout = layouts_path / f"{number}-{subnumber}"
        (layout / "blobs/sha256").mkdir(parents=True)
        (layout / "oci-layout").write_text('{"imageLayoutVersion":"1.0.0"}\n', encoding="ascii")
        index = {"schemaVersion": 2, "manifests": [{
            "mediaType": media_type, "digest": import_root, "size": size,
            "annotations": {"org.opencontainers.image.ref.name": "seed"},
        }]}
        (layout / "index.json").write_text(json.dumps(index, sort_keys=True, separators=(",", ":")) + "\n", encoding="ascii")
        for digest in wanted:
            source = objects_path / digest.removeprefix("sha256:")
            target = layout / "blobs/sha256" / source.name
            place(source, target)
        tag = "seed-" + import_root.removeprefix("sha256:")[:16]
        records.append((str(layout), repository, tag, label, import_root))
with plan_path.open("wb") as handle:
    for record in records:
        for value in record:
            if "\0" in value or "\n" in value:
                raise SystemExit("unsafe closure string")
            handle.write(value.encode("ascii") + b"\0")
PY

# An image the OS image already carries is proven, not copied. Measured on the
# lab GX10, 2026-09-16: the skopeo copies of the closure's images took 14 of
# the 31 minutes of first boot. The medium now carries them as bootc logically
# bound images and `bootc install` places them in the OS-side store, which the
# quadlets already read. The proof is the same digest-exact read-back the copy
# path ends with (skopeo inspect of repository@root, Digest == the signed
# root), aimed at that store. `podman image exists` is name-based and would
# count a wrong image as present; it is not used. The read opens the candidate
# store as primary (writable, its own runroot) with the OS store as an
# additional image store -- the quadlets' own access path. A read-only store
# cannot be the primary (skopeo wants its storage.lock there: "read-only file
# system"), and an absent store directory is a hard skopeo error rather than a
# miss, hence the -d guard. Measured 2026-09-17 (skopeo 1.21) with the store
# on a read-only bind mount: exact hit -> Digest is the root; wrong digest or
# wrong repository -> "does not resolve to an image ID"; the strict system
# policy and the seed-import policy both let the inspect through; not one
# mtime, ctime or mode changed in the store. Anything but an exact hit falls
# back to the copy below. The read initialises the candidate store's metadata
# directories, so it runs under the store's umask (022), like the copy.
os_image_carries() { # <repository> <root digest> -> 0 when the OS store holds exactly that image
  local repository=$1 import_root=$2 observed
  [[ -d $OS_IMAGE_STORE ]] || return 1
  observed=$( umask 022 && skopeo inspect \
      "containers-storage:[overlay@${candidate}/seed-store/graphroot+${candidate}/seed-store/runroot:overlay.imagestore=${OS_IMAGE_STORE}]${repository}@${import_root}" \
      | python3 -c 'import json,sys; raw=sys.stdin.read(); print(json.loads(raw).get("Digest", "") if raw.strip() else "")' ) \
    || return 1
  [[ $observed == "$import_root" ]]
}

imported=0
copied=0
carried=0
while IFS= read -r -d '' layout \
  && IFS= read -r -d '' repository \
  && IFS= read -r -d '' tag \
  && IFS= read -r -d '' artifact_key \
  && IFS= read -r -d '' import_root; do
  if [[ ${NI_SEED_IMPORT_DRY_RUN:-0} == 0 ]]; then
    if os_image_carries "$repository" "$import_root"; then
      echo "neural-ice-seed-import: $artifact_key is carried by the OS image at $import_root" >&2
      carried=$((carried + 1))
      imported=$((imported + 1))
      continue
    fi
    echo "neural-ice-seed-import: $artifact_key is not carried by the OS image; importing it" >&2
    destination="containers-storage:[overlay@${candidate}/seed-store/graphroot+${candidate}/seed-store/runroot]${repository}:${tag}"
    # Import this host's platform. containers-storage rejects --all for an
    # index; skopeo retains the original index digest as a local repo digest.
    # The merged root of every container is its top layer's diff directory, so
    # a layer written under this script's umask 077 is a root no non-root
    # container user can traverse: on the GX10 (.67, 2026-09-12, medium C34)
    # all 222 layer roots were dr-x------ and every product container died with
    # "exec … Permission denied" while root-run caddy lived. The store is
    # written under 022; everything else this script writes keeps 077.
    ( umask 022 && skopeo --policy "$SEED_POLICY" copy --tmpdir "$DATA/tmp" --preserve-digests \
        "oci:${layout}:seed" "$destination" ) \
      || die "cannot import signed artifact $artifact_key"
    # Reading by tag reports the selected child digest. The runtime pulls by
    # the signed root digest, so prove that exact repository@root is usable.
    imported_ref="containers-storage:[overlay@${candidate}/seed-store/graphroot+${candidate}/seed-store/runroot]${repository}@${import_root}"
    observed=$(skopeo inspect "$imported_ref" | python3 -c \
      'import json,sys; value=json.load(sys.stdin); print(value.get("Digest", ""))') \
      || die "cannot read back imported artifact $artifact_key"
    [[ $observed == "$import_root" ]] || die "imported artifact read-back digest differs for $artifact_key"
    copied=$((copied + 1))
  fi
  imported=$((imported + 1))
done < "$plan"
((imported > 0)) || die "closure has no importable artifact"
# The layer-root gate reads what a copy wrote. A run whose every image the OS
# image carries copied nothing: its store holds only the metadata the presence
# reads initialised, no layer, and must not be refused for it -- that refusal
# would land ~25 minutes later, after the model and cache work.
if [[ ${NI_SEED_IMPORT_DRY_RUN:-0} == 0 ]] && ((copied > 0)); then
  # Refuse, before anything is published, a store whose layer roots the
  # containers' own users could not traverse (the failure above would otherwise
  # surface only as a dead service after first boot).
  overlay="$candidate/seed-store/graphroot/overlay"
  [[ -d $overlay ]] || die "imported container store has no overlay layers"
  untraversable=$(find "$overlay" -mindepth 2 -maxdepth 2 -type d -name diff ! -perm -o=rx -print | head -3)
  [[ -z $untraversable ]] \
    || die "imported layer roots are not traversable by container users (umask leaked into the store): ${untraversable//$'\n'/ }"
fi
sync -f "$candidate/seed-store"
durable_boundary container

# Generic content/model CAS views live in the same unpublished generation.
for pair in "$candidate/content:all" "$candidate/models:model"; do
  dst=${pair%%:*}; selector=${pair##*:}
  python3 - "$source_root/release-closure.json" "$source_root/release-manifest.json" \
    "$source_root/objects/sha256" "$dst/sha256" "$selector" <<'PY'
import fcntl, json, pathlib, shutil, sys
closure = json.loads(pathlib.Path(sys.argv[1]).read_bytes())
manifest = json.loads(pathlib.Path(sys.argv[2]).read_bytes())
objects, destination, selector = pathlib.Path(sys.argv[3]), pathlib.Path(sys.argv[4]), sys.argv[5]
def place(source, target):
    # The staged objects and every published view live on the same XFS volume
    # (reflink=1): a clone shares the extents and costs nothing, a copy is
    # 129 GiB more per view (GX10 .67, 2026-09-12: 434 GB used for one 130 GB
    # seed). Not a hard link: the cache contracts require every staged object
    # to stay a single-link regular file. A filesystem without clones gets the
    # copy, byte for byte.
    FICLONE = 0x40049409
    with open(source, "rb") as src, open(target, "wb") as dst:
        try:
            fcntl.ioctl(dst.fileno(), FICLONE, src.fileno())
            return
        except OSError:
            pass
    shutil.copyfile(source, target)
cache_roots = {(entry["repository"], entry["digest"])
               for entry in manifest.get("content", [])
               if entry.get("contract") == "content-cache-v1"}
cache_segments, retained = set(), set()
for artifact in closure["artifacts"]:
    root = artifact["root"]["digest"] if isinstance(artifact["root"], dict) else artifact["root"]
    target = cache_segments if (artifact["repository"], root) in cache_roots else retained
    target.update(node["digest"] for node in artifact["nodes"] if node["kind"] == "layer")
    retained.update(node["digest"] for node in artifact["nodes"] if node["kind"] != "layer")
    for attachment in artifact["attachments"]:
        retained.add(attachment["manifest_digest"])
        retained.update(attachment["layer_digests"])
        attachment_manifest = json.loads((objects / attachment["manifest_digest"].removeprefix("sha256:")).read_bytes())
        retained.add(attachment_manifest["config"]["digest"])
if selector == "all":
    excluded = cache_segments - retained
    for source in objects.iterdir():
        if "sha256:" + source.name not in excluded:
            place(source, destination / source.name)
    raise SystemExit(0)
content_roots = {(entry["repository"], entry["digest"]) for entry in manifest.get("content", [])
                 if entry.get("contract") != "content-cache-v1"}
for artifact in closure["artifacts"]:
    root = artifact["root"]["digest"] if isinstance(artifact["root"], dict) else artifact["root"]
    if selector == "model" and (artifact["repository"], root) not in content_roots:
        continue
    digests = {node["digest"] for node in artifact["nodes"]}
    for attachment in artifact["attachments"]:
        digests.add(attachment["manifest_digest"])
        digests.update(attachment["layer_digests"])
        attachment_manifest = json.loads((objects / attachment["manifest_digest"].removeprefix("sha256:")).read_bytes())
        digests.add(attachment_manifest["config"]["digest"])
    for digest in digests:
        source = objects / digest.removeprefix("sha256:")
        target = destination / source.name
        if not target.exists(): place(source, target)
PY
  while IFS= read -r -d '' object; do
    observed=$(sha256sum -- "$object" | awk '{print tolower($1)}')
    [[ $observed == "$(basename -- "$object")" ]] || die "generic CAS read-back failed"
  done < <(find "$dst/sha256" -type f -print0 | sort -z)
  sync -f "$dst/sha256"
  if [[ $selector == all ]]; then durable_boundary content; else durable_boundary models; fi
done

# Reconstruct the two fixed data caches directly from the verified source CAS.
# Their segment blobs stay in the retained release pack and are deliberately
# excluded from the generic candidate CAS above, avoiding a second ~73 GiB
# copy before whole-file materialization.
"$CONTENT_CACHE_HELPER" materialize \
  --closure "$source_root/release-closure.json" \
  --manifest "$source_root/release-manifest.json" \
  --objects "$source_root/objects/sha256" \
  --registry-host "$registry_host" \
  --destination "$candidate/content-caches" >/dev/null \
  || die "cannot materialize the signed content caches"
durable_boundary content-caches

# Reconstruct the exact Hugging Face cache that vLLM mounts. The helper accepts
# only signed, typed OCI model-card artifacts and links each
# digest from the already read-back content candidate.
"$MODEL_HELPER" materialize --closure "$source_root/release-closure.json" \
  --objects "$source_root/objects/sha256" \
  --content "$candidate/content/sha256" \
  --destination "$candidate/hf-cache" >/dev/null \
  || die "cannot materialize the signed HF-cache model cards"
durable_boundary hf-cache

if [[ ${NI_SEED_IMPORT_DRY_RUN:-0} == 0 ]]; then
  # The container label is for the layer content the containers read. A store
  # that received no copy holds no layer: like the shipped empty generation it
  # keeps the volume's own label, which podman reads as root.
  if ((copied > 0)); then
    chcon -R -t container_ro_file_t "$candidate/seed-store/graphroot" 2>/dev/null \
      || chcon -R -t container_file_t "$candidate/seed-store/graphroot" \
      || die "cannot label imported container store"
  fi
  restorecon -RF "$candidate/content" "$candidate/models" "$candidate/content-caches" \
    "$candidate/hf-cache" \
    || die "cannot relabel offline generation"
fi
sync -f "$candidate"
durable_boundary relabel

# imported_artifacts counts every image of the closure made usable by this
# generation; carried_by_os_image is the part of it proven present in the OS
# store and therefore not copied. The two *_sha256 lines are what the fast
# path above greps; nothing before them moves.
printf 'schema=neural-ice-offline-generation-v1\nrelease_closure_sha256=%s\nrelease_manifest_sha256=%s\nimported_artifacts=%s\ncarried_by_os_image=%s\n' \
  "$closure" "$manifest" "$imported" "$carried" > "$candidate/READY"
sync -f "$candidate/READY"
sync -f "$candidate"
durable_boundary ready
mv -T -- "$candidate" "$generation"
sync -f "$generation_base"
durable_boundary generation
fi

# Install immutable indirections before the commit. They either resolve the
# previous generation or remain dangling; no new component becomes visible.
ensure_consumer_link "$DATA/seed-store/current" '../offline-current/seed-store/graphroot'
ensure_consumer_link "$DATA/content/current" '../offline-current/content'
ensure_consumer_link "$DATA/models/current" '../offline-current/models'
ensure_consumer_link "$DATA/hf-cache/hub" '../offline-current/hf-cache/hub'
ensure_consumer_link "$DATA/OFFLINE-READY" 'offline-current/READY'
durable_boundary consumer-links

if [[ -L $commit_pointer && $(readlink -- "$commit_pointer") == "offline-generations/$closure" ]]; then
  exit 0
fi
[[ ! -e $commit_pointer || -L $commit_pointer ]] \
  || die "offline commit pointer is not a symlink"
ln -s "offline-generations/$closure" "$DATA/.offline-current.$$"
sync -f "$DATA"
mv -Tf "$DATA/.offline-current.$$" "$commit_pointer"
sync -f "$DATA"
durable_boundary commit
