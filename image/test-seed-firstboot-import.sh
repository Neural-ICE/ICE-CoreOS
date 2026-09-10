#!/usr/bin/env bash
set -euo pipefail
ROOT=$(mktemp -d "${TMPDIR:-/tmp}/seed-import-test.XXXXXX")
trap 'rm -rf -- "$ROOT"' EXIT
FAKEBIN="$ROOT/bin"; mkdir -p "$FAKEBIN"
cat > "$FAKEBIN/skopeo" <<'EOF'
#!/bin/sh
[ "${FAIL_SKOPEO:-0}" = 0 ] || exit 42
# skopeo global options precede the verb; the script must hand over its own
# transport policy (the system one rejects oci:), and that file must exist.
policy_seen=0
if [ "${1:-}" = --policy ]; then
  [ -f "${2:-}" ] || { echo "seed-import policy file is absent: ${2:-}" >&2; exit 46; }
  policy_seen=1; shift 2
fi
if [ "${ASSERT_STORAGE_CONTRACT:-0}" = 1 ]; then
  case "${1:-}" in
    copy)
      [ "$policy_seen" = 1 ] || { echo 'copy without the seed-import transport policy' >&2; exit 47; }
      for arg in "$@"; do
        [ "$arg" != --all ] || { echo 'storage transport rejects --all' >&2; exit 43; }
      done
      printf copied > "$COPY_MARKER"
      exit 0 ;;
    inspect)
      [ -f "$COPY_MARKER" ] || exit 44
      case "${2:-}" in
        *@"$EXPECTED_IMPORT_DIGEST")
          printf '{"Digest":"%s"}\n' "${RETURN_IMPORT_DIGEST:-$EXPECTED_IMPORT_DIGEST}" ;;
        *) printf '{"Digest":"sha256:child-digest-not-index"}\n' ;;
      esac
      exit 0 ;;
    *) exit 45 ;;
  esac
fi
if [ "${1:-}" = inspect ]; then
  printf '{"Digest":"%s"}\n' "${EXPECTED_IMPORT_DIGEST:-sha256:missing}"
fi
exit 0
EOF
chmod 0755 "$FAKEBIN/skopeo"

closure=$(printf closure | sha256sum | awk '{print $1}')
manifest=$(printf '{"content":[{"digest":"sha256:placeholder","repository":"registry.example.test/neural-ice/model"}]}\n' | sha256sum | awk '{print $1}')
data="$ROOT/var/lib/neural-ice/data"
source="$data/release/$closure"
mkdir -p "$source/objects/sha256" "$ROOT/usr/bin" "$ROOT/usr/libexec" "$ROOT/usr/lib/neural-ice/keys"
printf '%s\n' "sha256:$closure" > "$data/release/CLOSURE"
printf '%s\n' "$manifest" > "$data/release/MANIFEST"
printf '%s\n' registry.example.test > "$data/release/AUTHORITY"
printf '%s\n' lab > "$data/release/CHANNEL"
printf '%s\n' 2026-09-02T07:00:00Z > "$data/release/TRUSTED-NOW"
for pointer in PCR-POLICY PCR-POLICY-KEY PCR-POLICY-SIGNATURE; do printf '%064d\n' 0 > "$data/release/$pointer"; done
printf '1\n' > "$data/release/PCR-POLICY-SEQ"
printf '%s\n' nvidia-gb10-arm64 > "$ROOT/usr/lib/neural-ice/hardware-target"
printf '%s\n' lab-managed > "$ROOT/usr/lib/neural-ice/access-policy"
printf '%s\n' lab-v1 > "$ROOT/usr/lib/neural-ice/signed-boot-trust-policy-id"
cp image/firstboot/neural-ice-seed-import-policy.json "$ROOT/usr/lib/neural-ice/seed-import-policy.json"
printf delegated-key > "$ROOT/usr/lib/neural-ice/keys/release-authorization.pub"
mkdir -p "$ROOT/etc/neural-ice/keys"
printf ota-root-key > "$ROOT/etc/neural-ice/keys/ota-root.pub"
cat > "$ROOT/usr/bin/ni-ota-verify" <<'EOF'
#!/bin/sh
while [ "$#" -gt 0 ]; do
  if [ "$1" = --pubkey ]; then
    shift
    [ "$(cat "$1")" = ota-root-key ] || exit 61
    exit 0
  fi
  shift
done
exit 62
EOF
chmod 0755 "$ROOT/usr/bin/ni-ota-verify"
install -m 0755 image/model-cache-contract.py "$ROOT/usr/libexec/neural-ice-model-cache-contract"
install -m 0755 image/content-cache-contract.py "$ROOT/usr/libexec/neural-ice-content-cache-contract"

# Feed the same producer contract two staged HF cards, then embed its output
# by digest in the signed-closure stand-in consumed by firstboot.
hf="$ROOT/hf-input"; rev_a=$(printf 'a%.0s' {1..40}); rev_b=$(printf 'b%.0s' {1..40})
for spec in "acme alpha $rev_a alpha-bytes" "acme beta $rev_b beta-bytes"; do
  read -r org name revision bytes <<<"$spec"
  model="$hf/models--$org--$name"; digest=$(printf %s "$bytes" | sha256sum | awk '{print $1}')
  mkdir -p "$model/blobs" "$model/snapshots/$revision"
  printf %s "$bytes" > "$model/blobs/$digest"
  ln -s "../../blobs/$digest" "$model/snapshots/$revision/model.safetensors"
done
cat > "$ROOT/profiles.json" <<EOF
{"profiles":{"alpha":{"catalog_status":"validated","model":"acme/alpha"}},"serving_roles":{"beta":{"catalog_status":"validated","model":"acme/beta"}}}
EOF
cat > "$ROOT/catalogue.json" <<EOF
{"models":[{"catalog_status":"validated","file_count":1,"hf_revision":"$rev_a","id":"alpha","model":"acme/alpha","size_bytes":11},{"catalog_status":"validated","file_count":1,"hf_revision":"$rev_b","id":"beta","model":"acme/beta","size_bytes":10}]}
EOF
image/model-cache-contract.py produce --hf-cache "$hf" --profiles "$ROOT/profiles.json" \
  --catalogue "$ROOT/catalogue.json" --objects "$source/objects/sha256" > "$ROOT/cards"

blob_body='{"config":{"digest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","mediaType":"application/vnd.oci.image.config.v1+json","size":2},"layers":[],"schemaVersion":2}'
blob=$(printf %s "$blob_body" | sha256sum | awk '{print $1}')
printf %s "$blob_body" > "$source/objects/sha256/$blob"
card_a=$(sed -n '1s/.*:sha256:\([0-9a-f]*\):.*/\1/p' "$ROOT/cards")
card_b=$(sed -n '2s/.*:sha256:\([0-9a-f]*\):.*/\1/p' "$ROOT/cards")
printf '{"content":[{"digest":"sha256:%s","repository":"registry.example.test/neural-ice/model"},{"digest":"sha256:%s","repository":"registry.example.test/neural-ice/model-alpha-card"},{"digest":"sha256:%s","repository":"registry.example.test/neural-ice/model-beta-card"}]}\n' "$blob" "$card_a" "$card_b" > "$source/release-manifest.json"
manifest=$(sha256sum -- "$source/release-manifest.json" | awk '{print $1}')
printf '%s\n' "$manifest" > "$data/release/MANIFEST"
python3 - "$source/release-closure.json" "$source/objects/sha256" "$blob" "$card_a" "$card_b" <<'PY'
import json, sys
path, objects, digest, card_a, card_b = sys.argv[1:]
from pathlib import Path
def node(repository, value, kind, media):
    return {"digest":"sha256:"+value,"kind":kind,"media_type":media,"repository":repository,
            "artifact_type":None,"signatures":[],"size":Path(objects,value).stat().st_size}
primary_repo="registry.example.test/neural-ice/model"
artifacts=[{"artifact_class":"hardware-targeted-manifest","artifact_key":"image:runtime-test","attachments":[],
  "nodes":[node(primary_repo,digest,"manifest","application/vnd.oci.image.manifest.v1+json")],
  "repository":primary_repo,"root":{"digest":"sha256:"+digest,"repository":primary_repo}}]
for card_id, card_digest in (("alpha",card_a),("beta",card_b)):
    repo=f"registry.example.test/neural-ice/model-{card_id}-card"
    manifest=json.loads(Path(objects,card_digest).read_bytes())
    config=manifest["config"]; card=json.loads(Path(objects,config["digest"].removeprefix("sha256:")).read_bytes())
    root_node=node(repo,card_digest,"manifest","application/vnd.oci.image.manifest.v1+json")
    root_node["artifact_type"]="application/vnd.neural-ice.hf-cache-model-card.v1"
    nodes=[root_node,node(repo,config["digest"].removeprefix("sha256:"),"config",config["mediaType"])]
    nodes += [node(repo,item["sha256"],"layer","application/vnd.neural-ice.hf-cache.model.file") for item in card["files"]]
    edges=[{"parent_digest":"sha256:"+card_digest,"parent_repository":repo,"edge_kind":"config","position":0,
            "child_digest":config["digest"],"child_repository":repo,"media_type":config["mediaType"],"size":config["size"]}]
    edges += [{"parent_digest":"sha256:"+card_digest,"parent_repository":repo,"edge_kind":"layers","position":i,
               "child_digest":"sha256:"+item["sha256"],"child_repository":repo,
               "media_type":"application/vnd.neural-ice.hf-cache.model.file","size":item["size"]}
              for i,item in enumerate(card["files"])]
    artifacts.append({"artifact_class":"oci-artifact","artifact_key":f"content:{card_id}",
      "attachments":[],"edges":edges,"nodes":nodes,"repository":repo,
      "root":{"digest":"sha256:"+card_digest,"repository":repo}})
document = {"artifacts":artifacts}
open(path,"w",encoding="ascii").write(json.dumps(document,separators=(",",":"),sort_keys=True)+"\n")
PY

# Add the two fixed content-cache-v1 roots with tiny final segments. This drives
# the same helper/importer seam as the real 9-segment CH and 1-segment Paddle
# payloads without allocating appliance-sized test data.
python3 - "$source/release-closure.json" "$source/release-manifest.json" \
  "$source/objects/sha256" <<'PY'
import hashlib, json, pathlib, sys
closure_path, manifest_path, objects = map(pathlib.Path, sys.argv[1:])
closure, release = json.loads(closure_path.read_bytes()), json.loads(manifest_path.read_bytes())
profiles = {
    "ch-caselaw-seed": ("sqlite3", "content-cache-ch-caselaw-seed", "ICE-CASELAW-CH", b"sqlite-cache"),
    "paddlex-cache": ("tar+zstd", "content-cache-paddlex-cache", "ICE-CORE", b"paddlex-cache"),
}
def put(body):
    digest=hashlib.sha256(body).hexdigest(); (objects/digest).write_bytes(body); return digest
def canonical(value): return json.dumps(value,sort_keys=True,separators=(",",":")).encode("ascii")
for content_id,(format_name,repo_name,entitlement,payload) in profiles.items():
    repository="registry.example.test/neural-ice/"+repo_name
    segment=put(payload)
    config=canonical({"content_id":content_id,"format":format_name,
      "schema":"neural-ice-content-cache-v1",
      "segments":[{"digest":"sha256:"+segment,"size":len(payload)}],
      "sha256":segment,"size_bytes":len(payload)})
    config_digest=put(config)
    oci=canonical({"artifactType":"application/vnd.neural-ice.content-cache.v1",
      "config":{"digest":"sha256:"+config_digest,
        "mediaType":"application/vnd.neural-ice.content-cache.v1+json","size":len(config)},
      "layers":[{"digest":"sha256:"+segment,
        "mediaType":"application/vnd.neural-ice.content-cache.segment.v1","size":len(payload)}],
      "mediaType":"application/vnd.oci.image.manifest.v1+json","schemaVersion":2})
    root=put(oci)
    release["content"].append({"content_id":content_id,"contract":"content-cache-v1",
      "digest":"sha256:"+root,"media_type":"application/vnd.neural-ice.content-cache.v1",
      "reboot_required":False,"repository":repository,"required_entitlement":entitlement,
      "restart_scope":[]})
    closure["artifacts"].append({"artifact_class":"oci-artifact",
      "artifact_key":"content:"+content_id,"attachments":[],
      "candidate_repository":"ghcr.io/neural-ice/"+repo_name,
      "nodes":[{"digest":"sha256:"+root,"kind":"manifest"},
               {"digest":"sha256:"+config_digest,"kind":"config"},
               {"digest":"sha256:"+segment,"kind":"layer"}],
      "repository":repository,"required_entitlement":entitlement,
      "root":{"digest":"sha256:"+root,"repository":repository}})
release["compatibility"]={"minimum_reader":1,
  "required_contracts":["content-cache-v1","content-model-v1"]}
closure_path.write_bytes(canonical(closure)+b"\n")
manifest_path.write_bytes(canonical(release)+b"\n")
PY
manifest=$(sha256sum -- "$source/release-manifest.json" | awk '{print $1}')
printf '%s\n' "$manifest" > "$data/release/MANIFEST"

# A delegated installer key is not the root that authenticates the snapshot.
printf delegated-key > "$ROOT/etc/neural-ice/keys/ota-root.pub"
if PATH="$FAKEBIN:$PATH" NI_SEED_IMPORT_ROOT="$ROOT" NI_SEED_IMPORT_DRY_RUN=1 \
  image/firstboot/neural-ice-seed-import.sh >/dev/null 2>&1; then
  echo "substituted delegation root unexpectedly passed" >&2; exit 1
fi
test ! -e "$data/offline-current"
printf ota-root-key > "$ROOT/etc/neural-ice/keys/ota-root.pub"

PATH="$FAKEBIN:$PATH" NI_SEED_IMPORT_ROOT="$ROOT" NI_SEED_IMPORT_DRY_RUN=1 \
  image/firstboot/neural-ice-seed-import.sh
test "$(readlink "$data/offline-current")" = "offline-generations/$closure"
test "$(readlink "$data/seed-store/current")" = '../offline-current/seed-store/graphroot'
test "$(readlink "$data/content/current")" = '../offline-current/content'
test "$(readlink "$data/models/current")" = '../offline-current/models'
test "$(readlink "$data/hf-cache/hub")" = '../offline-current/hf-cache/hub'
test "$(readlink "$data/OFFLINE-READY")" = 'offline-current/READY'
test -f "$data/offline-generations/$closure/READY"
# Only executable component images belong in containers-storage. Model cards
# and their evidence remain in the verified content CAS, never image imports.
python3 - "$data/offline-generations/$closure/seed-store/import-plan" <<'PLAN_CHECK'
import pathlib, sys
fields = pathlib.Path(sys.argv[1]).read_bytes().split(b"\0")
assert fields[-1] == b""
records = [fields[i:i + 5] for i in range(0, len(fields) - 1, 5)]
assert len(records) == 1, records
assert records[0][3] == b"image:runtime-test", records
PLAN_CHECK
test -f "$data/content/current/sha256/$blob"
test -f "$data/models/current/sha256/$blob"
test "$(cat "$data/offline-current/content-caches/ch-caselaw-seed/decisions.db")" = sqlite-cache
test "$(cat "$data/offline-current/content-caches/paddlex-cache/paddlex-cache.tar.zst")" = paddlex-cache
for cache in ch-caselaw-seed paddlex-cache; do
  test -f "$data/offline-current/content-caches/.metadata/$cache.json"
  test "$(tail -c 1 "$data/offline-current/content-caches/.metadata/$cache.json" | od -An -tuC)" = ' 125'
done
# Cache segments remain only in the retained verified source CAS; the candidate
# generic content/model views must not duplicate them.
for payload in sqlite-cache paddlex-cache; do
  cache_digest=$(printf %s "$payload" | sha256sum | awk '{print $1}')
  test ! -e "$data/content/current/sha256/$cache_digest"
  test ! -e "$data/models/current/sha256/$cache_digest"
done
alpha_digest=$(printf %s alpha-bytes | sha256sum | awk '{print $1}')
test "$(readlink "$data/hf-cache/hub/models--acme--alpha/snapshots/$rev_a/model.safetensors")" = "../../blobs/$alpha_digest"
test "$(stat -c %i "$data/content/current/sha256/$alpha_digest")" = \
     "$(stat -c %i "$data/hf-cache/hub/models--acme--alpha/blobs/$alpha_digest")"
test -f "$data/OFFLINE-READY"

# Read refs as raw bytes: command substitution would erase precisely the LF
# regression this proof guards. Resolve both cards with network disabled using
# the same refs -> snapshots -> blobs traversal huggingface_hub performs.
HF_HUB_OFFLINE=1 python3 - "$data/hf-cache/hub" "$rev_a" "$rev_b" <<'PY'
import pathlib, sys
hub, rev_a, rev_b = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3]
for model, revision, expected in (
    ("models--acme--alpha", rev_a, b"alpha-bytes"),
    ("models--acme--beta", rev_b, b"beta-bytes"),
):
    root = hub / model
    raw = (root / "refs/main").read_bytes()
    assert raw == revision.encode("ascii"), (model, raw)
    snapshot = root / "snapshots" / raw.decode("ascii")
    resolved = (snapshot / "model.safetensors").resolve(strict=True)
    assert resolved.parent == (root / "blobs").resolve(strict=True)
    assert resolved.read_bytes() == expected
PY

# Exact retry is idempotent and does not rebuild the published generation.
before=$(stat -c %i "$data/offline-generations/$closure/READY")
PATH="$FAKEBIN:$PATH" NI_SEED_IMPORT_ROOT="$ROOT" NI_SEED_IMPORT_DRY_RUN=1 \
  image/firstboot/neural-ice-seed-import.sh
test "$before" = "$(stat -c %i "$data/offline-generations/$closure/READY")"

# A failed next-generation import cannot move any current pointer or READY.
next_closure=$(printf next-closure | sha256sum | awk '{print $1}')
cp -a -- "$source" "$data/release/$next_closure"
printf 'sha256:%s\n' "$next_closure" > "$data/release/CLOSURE"
before_current=$(readlink "$data/offline-current")
before_ready=$(sha256sum -- "$data/OFFLINE-READY" | awk '{print $1}')
if PATH="$FAKEBIN:$PATH" FAIL_SKOPEO=1 NI_SEED_IMPORT_ROOT="$ROOT" NI_SEED_IMPORT_DRY_RUN=0 \
  image/firstboot/neural-ice-seed-import.sh 2>/dev/null; then
  echo "failed import unexpectedly passed" >&2
  exit 1
fi
test "$before_current" = "$(readlink "$data/offline-current")"
test "$before_ready" = "$(sha256sum -- "$data/OFFLINE-READY" | awk '{print $1}')"

# Power-fail after every durable boundary. All five public views resolve
# through one pointer, so observation is exactly old or exactly new.
active_closure=$closure
for boundary in container content models content-caches hf-cache relabel ready generation consumer-links commit; do
  candidate_closure=$(printf 'boundary-%s' "$boundary" | sha256sum | awk '{print $1}')
  cp -a -- "$source" "$data/release/$candidate_closure"
  printf 'sha256:%s\n' "$candidate_closure" > "$data/release/CLOSURE"
  if PATH="$FAKEBIN:$PATH" NI_SEED_IMPORT_ROOT="$ROOT" NI_SEED_IMPORT_DRY_RUN=1 \
       NI_SEED_IMPORT_FAIL_AFTER="$boundary" image/firstboot/neural-ice-seed-import.sh 2>/dev/null; then
    echo "fault injection at $boundary unexpectedly passed" >&2
    exit 1
  fi
  observed_link=$(readlink "$data/offline-current")
  observed=${observed_link##*/}
  case "$observed" in
    "$active_closure"|"$candidate_closure") ;;
    *) echo "boundary $boundary exposed unknown generation $observed" >&2; exit 1 ;;
  esac
  for view in "$data/seed-store/current" "$data/content/current" "$data/models/current" \
    "$data/hf-cache/hub" "$data/OFFLINE-READY"; do
    readlink -f -- "$view" | grep -Fq "/offline-generations/$observed/" \
      || { echo "boundary $boundary mixed $view away from $observed" >&2; exit 1; }
  done
  grep -Fqx "release_closure_sha256=$observed" "$data/OFFLINE-READY"
  active_closure=$observed
done

# A digest-named model blob whose bytes changed is caught during candidate
# readback; no prior generation or offline marker can move.
tampered_closure=$(printf tampered-closure | sha256sum | awk '{print $1}')
cp -a -- "$source" "$data/release/$tampered_closure"
chmod 0644 "$data/release/$tampered_closure/objects/sha256/$alpha_digest"
printf evil > "$data/release/$tampered_closure/objects/sha256/$alpha_digest"
printf 'sha256:%s\n' "$tampered_closure" > "$data/release/CLOSURE"
if PATH="$FAKEBIN:$PATH" NI_SEED_IMPORT_ROOT="$ROOT" NI_SEED_IMPORT_DRY_RUN=1 \
  image/firstboot/neural-ice-seed-import.sh 2>/dev/null; then
  echo "tampered model object unexpectedly passed" >&2
  exit 1
fi
test "offline-generations/$active_closure" = "$(readlink "$data/offline-current")"

# A root invocation may never redirect production paths or select dry-run.
if command -v setpriv >/dev/null && setpriv --reuid=0 --regid=0 --clear-groups \
  env NI_SEED_IMPORT_ROOT="$ROOT" NI_SEED_IMPORT_DRY_RUN=1 \
  image/firstboot/neural-ice-seed-import.sh 2>/dev/null; then
  echo "root test override unexpectedly passed" >&2
  exit 1
fi

# Exercise the successful storage path, not dry-run: the strict transport fake
# reproduces the measured --all refusal and index-vs-tag digest distinction.
# Relabel commands are stubs because this is an unprivileged filesystem fixture;
# native Skopeo/Podman and SELinux qualification remain separate checks.
for command in chcon restorecon; do
  printf '#!/bin/sh\nexit 0\n' > "$FAKEBIN/$command"
  chmod 0755 "$FAKEBIN/$command"
done
storage_closure=$(printf storage-success | sha256sum | awk '{print $1}')
cp -a -- "$source" "$data/release/$storage_closure"
printf 'sha256:%s\n' "$storage_closure" > "$data/release/CLOSURE"
PATH="$FAKEBIN:$PATH" ASSERT_STORAGE_CONTRACT=1 COPY_MARKER="$ROOT/copied" \
  EXPECTED_IMPORT_DIGEST="sha256:$blob" NI_SEED_IMPORT_ROOT="$ROOT" NI_SEED_IMPORT_DRY_RUN=0 \
  image/firstboot/neural-ice-seed-import.sh
test -f "$ROOT/copied"
test "offline-generations/$storage_closure" = "$(readlink "$data/offline-current")"
grep -Fqx 'imported_artifacts=1' "$data/OFFLINE-READY"

# A transport that returns another digest must not publish its generation.
wrong_closure=$(printf wrong-import-readback | sha256sum | awk '{print $1}')
cp -a -- "$source" "$data/release/$wrong_closure"
printf 'sha256:%s\n' "$wrong_closure" > "$data/release/CLOSURE"
rm -- "$ROOT/copied"
if PATH="$FAKEBIN:$PATH" ASSERT_STORAGE_CONTRACT=1 COPY_MARKER="$ROOT/copied" \
    EXPECTED_IMPORT_DIGEST="sha256:$blob" RETURN_IMPORT_DIGEST=sha256:wrong \
    NI_SEED_IMPORT_ROOT="$ROOT" NI_SEED_IMPORT_DRY_RUN=0 \
    image/firstboot/neural-ice-seed-import.sh 2>/dev/null; then
  echo "wrong storage readback digest unexpectedly passed" >&2
  exit 1
fi
test -f "$ROOT/copied"
test "offline-generations/$storage_closure" = "$(readlink "$data/offline-current")"

echo "seed-firstboot-import: 23 cases passed"
