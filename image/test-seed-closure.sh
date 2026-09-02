#!/usr/bin/env bash
set -euo pipefail
ROOT=$(mktemp -d "${TMPDIR:-/tmp}/seed-producer-test.XXXXXX")
trap 'rm -rf -- "$ROOT"' EXIT
inputs="$ROOT/inputs"; objects="$ROOT/objects"; output="$ROOT/output"
mkdir -p "$inputs" "$objects"
printf '{"release":"fixture"}\n' > "$inputs/release-manifest.json"
printf '{"closure":"fixture"}\n' > "$inputs/release-closure.json"
for name in authorization authorization.sig delegation delegation.sig root.pub; do
  printf '%s\n' "$name" > "$inputs/$name"
done
printf object > "$objects/blob"

# Two validated cards in the same layout emitted by Fabric stage-models.sh.
hf="$ROOT/hf-cache/hub"; rev_a=$(printf 'a%.0s' {1..40}); rev_b=$(printf 'b%.0s' {1..40})
for spec in "acme alpha $rev_a alpha-bytes" "acme beta $rev_b beta-bytes"; do
  read -r org name revision bytes <<<"$spec"
  model="$hf/models--$org--$name"
  digest=$(printf %s "$bytes" | sha256sum | awk '{print $1}')
  mkdir -p "$model/blobs" "$model/snapshots/$revision"
  printf %s "$bytes" > "$model/blobs/$digest"
  ln -s "../../blobs/$digest" "$model/snapshots/$revision/model.safetensors"
done
cat > "$ROOT/profiles.json" <<EOF
{"profiles":{"alpha":{"catalog_status":"validated","model":"acme/alpha"},"beta":{"catalog_status":"validated","model":"acme/beta"}},"serving_roles":{}}
EOF
cat > "$ROOT/catalogue.json" <<EOF
{"models":[{"catalog_status":"validated","file_count":1,"hf_revision":"$rev_a","id":"alpha","model":"acme/alpha","size_bytes":11},{"catalog_status":"validated","file_count":1,"hf_revision":"$rev_b","id":"beta","model":"acme/beta","size_bytes":10}]}
EOF

# Installer-consumer stand-in: first pass must reach ONLY the missing READY
# refusal; second pass validates the producer's exact receipt and object set.
cat > "$ROOT/verifier" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
while (($#)); do
  case "$1" in --seed-root) root=$2; shift 2;; *) shift;; esac
done
[[ -f $root/release-manifest.json && -f $root/release-closure.json \
   && -f $root/release-authorization.json && -f $root/delegation-snapshot.json \
   && -d $root/objects/sha256 ]]
if [[ ! -f $root/READY ]]; then echo 'READY is absent' >&2; exit 1; fi
python3 - "$root/READY" <<'PY'
import json, sys
d=json.load(open(sys.argv[1],encoding="ascii"))
assert set(d)=={"schema","release_closure_sha256","release_manifest_sha256","object_count"}
assert d["schema"]=="neural-ice-seed-closure-ready-v1" and d["object_count"]==7
PY
EOF
chmod 0755 "$ROOT/verifier"

image/build-seed-v2.sh --output "$output" \
  --release-manifest "$inputs/release-manifest.json" --release-closure "$inputs/release-closure.json" \
  --authorization "$inputs/authorization" --authorization-sig "$inputs/authorization.sig" \
  --delegation "$inputs/delegation" --delegation-sig "$inputs/delegation.sig" \
  --root-pubkey "$inputs/root.pub" --registry-host registry.example.test \
  --hardware-target nvidia-gb10-arm64 --access-profile lab-managed \
  --device-channel lab \
  --trust-policy-id lab-v1 --trusted-now 2026-09-02T07:00:00Z \
  --pcr-policy-digest "$(printf p | sha256sum | awk '{print $1}')" \
  --pcr-policy-public-key-sha256 "$(printf k | sha256sum | awk '{print $1}')" \
  --pcr-policy-signature-sha256 "$(printf s | sha256sum | awk '{print $1}')" --pcr-policy-seq 1 \
  --objects "$objects" --hf-cache "$hf" --model-profiles "$ROOT/profiles.json" \
  --model-catalogue "$ROOT/catalogue.json" --verifier "$ROOT/verifier" >/dev/null
closure=$(sha256sum "$inputs/release-closure.json" | awk '{print $1}')
test -f "$output/seed/$closure/READY"
test -f "$output/seed/$closure/objects/sha256/$(sha256sum "$objects/blob" | awk '{print $1}')"
test ! -e "$output/seed/$closure/oci/index.json"

# The historical producer interface and its opaque Podman store are gone.
if image/build-seed-v2.sh --release "$inputs/release-manifest.json" 2>/dev/null; then
  echo "legacy --release interface unexpectedly passed" >&2; exit 1
fi
if rg -n 'podman .*load|SEED_IMAGES|SEED_MODELS|/store/' image/build-preloaded.sh >/dev/null; then
  echo "legacy overlay producer remains in build-preloaded.sh" >&2; exit 1
fi
echo "seed-producer-consumer: 3 cases passed"
