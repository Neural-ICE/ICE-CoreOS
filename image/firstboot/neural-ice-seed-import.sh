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
  ''|container|content|models|hf-cache|relabel|ready|generation|consumer-links|commit) ;;
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
ROOT_KEY=$(path /usr/lib/neural-ice/keys/release-authorization.pub)
REGISTRY="$RELEASE/AUTHORITY"
CHANNEL="$RELEASE/CHANNEL"
TRUSTED_NOW="$RELEASE/TRUSTED-NOW"
HARDWARE=$(path /usr/lib/neural-ice/hardware-target)
PROFILE=$(path /usr/lib/neural-ice/access-policy)
POLICY=$(path /usr/lib/neural-ice/signed-boot-trust-policy-id)
MODEL_HELPER=$(path /usr/libexec/neural-ice-model-cache-contract)

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
"$VERIFIER" verify-seed-closure --seed-root "$source_root" --pubkey "$ROOT_KEY" \
  --registry-host "$(<"$REGISTRY")" --hardware-target "$(<"$HARDWARE")" \
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
  "$DATA/models" "$DATA/hf-cache"

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
import json, pathlib, shutil, sys
closure_path, objects_path, layouts_path, plan_path = map(pathlib.Path, sys.argv[1:])
closure = json.loads(closure_path.read_bytes())
records = []
for number, artifact in enumerate(closure["artifacts"]):
    repository, root_value = artifact["repository"], artifact["root"]
    root = root_value["digest"] if isinstance(root_value, dict) else root_value
    nodes = {node["digest"]: node for node in artifact["nodes"]}
    node = nodes[root]
    imports = [(root, node["media_type"], node["size"], {n["digest"] for n in artifact["nodes"]}, artifact["artifact_key"])]
    for attachment in artifact["attachments"]:
        wanted = {attachment["manifest_digest"], *attachment["layer_digests"]}
        body = json.loads((objects_path / attachment["manifest_digest"].removeprefix("sha256:")).read_bytes())
        wanted.add(body["config"]["digest"])
        attachment_size = (objects_path / attachment["manifest_digest"].removeprefix("sha256:")).stat().st_size
        imports.append((attachment["manifest_digest"], attachment["media_type"], attachment_size, wanted,
                        artifact["artifact_key"] + "/" + attachment["kind"]))
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
            shutil.copyfile(source, target)
        tag = "seed-" + import_root.removeprefix("sha256:")[:16]
        records.append((str(layout), repository, tag, label, import_root))
with plan_path.open("wb") as handle:
    for record in records:
        for value in record:
            if "\0" in value or "\n" in value:
                raise SystemExit("unsafe closure string")
            handle.write(value.encode("ascii") + b"\0")
PY

imported=0
while IFS= read -r -d '' layout \
  && IFS= read -r -d '' repository \
  && IFS= read -r -d '' tag \
  && IFS= read -r -d '' artifact_key \
  && IFS= read -r -d '' import_root; do
  if [[ ${NI_SEED_IMPORT_DRY_RUN:-0} == 0 ]]; then
    destination="containers-storage:[overlay@${candidate}/seed-store/graphroot+${candidate}/seed-store/runroot]${repository}:${tag}"
    skopeo copy --all --preserve-digests "oci:${layout}:seed" \
      "$destination" \
      || die "cannot import signed artifact $artifact_key"
    observed=$(skopeo inspect "$destination" | python3 -c \
      'import json,sys; value=json.load(sys.stdin); print(value.get("Digest", ""))') \
      || die "cannot read back imported artifact $artifact_key"
    [[ $observed == "$import_root" ]] || die "imported artifact read-back digest differs for $artifact_key"
  fi
  imported=$((imported + 1))
done < "$plan"
((imported > 0)) || die "closure has no importable artifact"
sync -f "$candidate/seed-store"
durable_boundary container

# Generic content/model CAS views live in the same unpublished generation.
for pair in "$candidate/content:all" "$candidate/models:model"; do
  dst=${pair%%:*}; selector=${pair##*:}
  python3 - "$source_root/release-closure.json" "$source_root/release-manifest.json" \
    "$source_root/objects/sha256" "$dst/sha256" "$selector" <<'PY'
import json, pathlib, shutil, sys
closure = json.loads(pathlib.Path(sys.argv[1]).read_bytes())
manifest = json.loads(pathlib.Path(sys.argv[2]).read_bytes())
objects, destination, selector = pathlib.Path(sys.argv[3]), pathlib.Path(sys.argv[4]), sys.argv[5]
if selector == "all":
    for source in objects.iterdir():
        shutil.copyfile(source, destination / source.name)
    raise SystemExit(0)
content_roots = {(entry["repository"], entry["digest"]) for entry in manifest.get("content", [])}
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
        if not target.exists(): shutil.copyfile(source, target)
PY
  while IFS= read -r -d '' object; do
    observed=$(sha256sum -- "$object" | awk '{print tolower($1)}')
    [[ $observed == "$(basename -- "$object")" ]] || die "generic CAS read-back failed"
  done < <(find "$dst/sha256" -type f -print0 | sort -z)
  sync -f "$dst/sha256"
  if [[ $selector == all ]]; then durable_boundary content; else durable_boundary models; fi
done

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
  chcon -R -t container_ro_file_t "$candidate/seed-store/graphroot" 2>/dev/null \
    || chcon -R -t container_file_t "$candidate/seed-store/graphroot" \
    || die "cannot label imported container store"
  restorecon -RF "$candidate/content" "$candidate/models" "$candidate/hf-cache" \
    || die "cannot relabel offline generation"
fi
sync -f "$candidate"
durable_boundary relabel

printf 'schema=neural-ice-offline-generation-v1\nrelease_closure_sha256=%s\nrelease_manifest_sha256=%s\nimported_artifacts=%s\n' \
  "$closure" "$manifest" "$imported" > "$candidate/READY"
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
