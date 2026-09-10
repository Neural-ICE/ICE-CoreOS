#!/usr/bin/env bash
# ci/test-seed-import-policy.sh — the transport policy seed-import hands skopeo.
#
# WHY THIS EXISTS
#
#   The appliance's /etc/containers/policy.json is fail-closed: default reject,
#   docker: scopes only. neural-ice-seed-import.sh imports the seed's images
#   from oci: layouts it assembles itself from a closure ni-ota-verify has
#   already checked, and containers/image evaluates the policy on the SOURCE
#   transport. MEASURED on the lab GX10, 2026-09-10, first boot C25, after
#   ~23 min of re-verification:
#       Source image rejected: Running image oci:///var/lib/neural-ice/data/
#       offline-generations/….staging/seed-store/layouts/7-0:seed is rejected
#       by policy.
#   image/test-seed-firstboot-import.sh runs a FAKE skopeo, so no test had ever
#   put the real policy engine in front of the real transport. This one does.
#
# WHAT IT PROVES
#
#   1. the shipped file's shape: default reject, exactly one transport (oci),
#      exactly one scope (the offline-generations directory), and the script
#      hands that file to skopeo before the verb;
#   2. against the containers/image engine (real skopeo): the strict system
#      policy refuses the oci: layout (the GX10 failure, reproduced), the
#      seed-import policy accepts it under its scope, refuses it outside the
#      scope, and refuses every other transport (dir:).
set -euo pipefail
cd "$(dirname "$0")/.."

POLICY=image/firstboot/neural-ice-seed-import-policy.json
STRICT=image/bootc-overlay/etc/containers/policy.json
SCRIPT=image/firstboot/neural-ice-seed-import.sh
SCOPE=/var/lib/neural-ice/data/offline-generations
WORK="$(mktemp -d)"
WORK="$(readlink -f "$WORK")"   # oci: scopes must not traverse symlinks
trap 'rm -rf "$WORK"' EXIT
failures=0
ok()   { printf '  ok    %s\n' "$*"; }
fail() { printf '  FAIL  %s\n' "$*" >&2; failures=$((failures + 1)); }

echo "1) the shipped policy and the script that uses it"
python3 - "$POLICY" "$SCOPE" <<'PY' && ok "default=reject, one oci: scope ($SCOPE), nothing for docker:" || fail "policy shape"
import json, sys
policy = json.load(open(sys.argv[1])); scope = sys.argv[2]
assert policy["default"] == [{"type": "reject"}], policy["default"]
assert list(policy["transports"]) == ["oci"], list(policy["transports"])
assert list(policy["transports"]["oci"]) == [scope], list(policy["transports"]["oci"])
assert policy["transports"]["oci"][scope] == [{"type": "insecureAcceptAnything"}]
assert scope.startswith("/") and not scope.endswith("/") and "//" not in scope
PY
grep -q 'skopeo --policy "\$SEED_POLICY" copy ' "$SCRIPT" \
  && ok "the script passes its policy before the copy verb" \
  || fail "the script does not hand skopeo the seed-import policy"
grep -q '^SEED_POLICY=\$(path /usr/lib/neural-ice/seed-import-policy.json)$' "$SCRIPT" \
  && ok "the script reads /usr/lib/neural-ice/seed-import-policy.json" \
  || fail "the script does not read the shipped policy path"
grep -q '^COPY image/firstboot/neural-ice-seed-import-policy.json  */usr/lib/neural-ice/seed-import-policy.json$' image/Containerfile.bootc \
  && ok "the image ships the policy at that path" \
  || fail "Containerfile.bootc does not ship the policy where the script reads it"
grep -q "^generation_base=\"\$DATA/offline-generations\"$" "$SCRIPT" \
  && grep -q '^DATA=$(path /var/lib/neural-ice/data)$' "$SCRIPT" \
  && ok "the scope is the directory the script stages its layouts under" \
  || fail "the script's layout directory no longer matches the policy scope"

echo "2) the decisions, against the containers/image policy engine"
command -v skopeo >/dev/null || { fail "skopeo is required for this test"; exit 1; }
cat > "$WORK/mkimage.py" <<'PY'
"""Build a minimal OCI layout whose index names the tag seed-import uses."""
import gzip, hashlib, io, json, os, sys, tarfile
out = sys.argv[1]; blobs = os.path.join(out, "blobs", "sha256"); os.makedirs(blobs)
def put(data):
    d = hashlib.sha256(data).hexdigest()
    open(os.path.join(blobs, d), "wb").write(data)
    return "sha256:" + d, len(data)
raw = io.BytesIO()
with tarfile.open(fileobj=raw, mode="w") as tf:
    payload = b"seed-import transport policy test\n"
    info = tarfile.TarInfo("hello.txt"); info.size, info.mtime = len(payload), 0
    tf.addfile(info, io.BytesIO(payload))
diff_id = "sha256:" + hashlib.sha256(raw.getvalue()).hexdigest()
layer, layer_size = put(gzip.compress(raw.getvalue(), mtime=0))
config, config_size = put(json.dumps({"architecture": "amd64", "os": "linux", "config": {},
    "rootfs": {"type": "layers", "diff_ids": [diff_id]}}, sort_keys=True).encode())
manifest, manifest_size = put(json.dumps({"schemaVersion": 2,
    "mediaType": "application/vnd.oci.image.manifest.v1+json",
    "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": config, "size": config_size},
    "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": layer, "size": layer_size}]},
    sort_keys=True).encode())
json.dump({"imageLayoutVersion": "1.0.0"}, open(os.path.join(out, "oci-layout"), "w"))
json.dump({"schemaVersion": 2, "manifests": [{"mediaType": "application/vnd.oci.image.manifest.v1+json",
    "digest": manifest, "size": manifest_size,
    "annotations": {"org.opencontainers.image.ref.name": "seed"}}]}, open(os.path.join(out, "index.json"), "w"))
PY
inside="$WORK/scope/.closure.staging/seed-store/layouts/1-0"
outside="$WORK/elsewhere/layouts/1-0"
python3 "$WORK/mkimage.py" "$inside"
python3 "$WORK/mkimage.py" "$outside"
python3 "$WORK/mkimage.py" "$WORK/dirimage-src" && skopeo --insecure-policy copy "oci:$WORK/dirimage-src:seed" "dir:$WORK/dirimage" >/dev/null
# The shipped scope is an absolute production path; the engine is exercised
# with that single key re-pointed at this work directory, nothing else changed.
python3 - "$POLICY" "$SCOPE" "$WORK/scope" "$WORK/seed-policy.json" <<'PY'
import json, sys
policy = json.load(open(sys.argv[1]))
policy["transports"]["oci"] = {sys.argv[3]: policy["transports"]["oci"].pop(sys.argv[2])}
assert list(policy["transports"]["oci"]) == [sys.argv[3]]
json.dump(policy, open(sys.argv[4], "w"))
PY

# verdict <accept|reject> <label> <policy> <source ref> [needle]
verdict() {
  local expect="$1" label="$2" policy="$3" source="$4" needle="${5:-}" out rc
  rm -rf "$WORK/dest"
  set +e; out="$(skopeo --policy "$policy" copy "$source" "dir:$WORK/dest" 2>&1)"; rc=$?; set -e
  if [ "$expect" = accept ]; then
    if [ "$rc" -eq 0 ]; then ok "$label: accepted"; else fail "$label: expected ACCEPT, got exit $rc"; printf '%s\n' "$out" | sed 's/^/       /' >&2; fi
    return
  fi
  if [ "$rc" -eq 0 ]; then fail "$label: expected REJECT, the transfer SUCCEEDED"; return; fi
  if [ -n "$needle" ] && ! printf '%s' "$out" | grep -qF -- "$needle"; then
    fail "$label: refused, but not for the expected reason (wanted '$needle')"; printf '%s\n' "$out" | sed 's/^/       /' >&2; return
  fi
  ok "$label: rejected${needle:+ ($needle)}"
}
verdict reject "strict system policy, oci: layout (the GX10 first-boot failure)" "$STRICT" "oci:$inside:seed" "is rejected by policy"
verdict accept "seed-import policy, oci: layout under its scope" "$WORK/seed-policy.json" "oci:$inside:seed"
verdict reject "seed-import policy, oci: layout outside its scope" "$WORK/seed-policy.json" "oci:$outside:seed" "is rejected by policy"
verdict reject "seed-import policy, dir: transport" "$WORK/seed-policy.json" "dir:$WORK/dirimage" "is rejected by policy"

# The untouched file, when this runner may create the production directory.
if mkdir -p "$SCOPE/.ci-seed-policy.$$/seed-store/layouts" 2>/dev/null; then
  real="$SCOPE/.ci-seed-policy.$$/seed-store/layouts/1-0"
  python3 "$WORK/mkimage.py" "$real"
  verdict accept "the SHIPPED file, unmodified, oci: layout under $SCOPE" "$POLICY" "oci:$real:seed"
  rm -rf "$SCOPE/.ci-seed-policy.$$"
else
  echo "  skip  the shipped file against $SCOPE (directory not creatable here)"
fi

echo
if [ "$failures" -ne 0 ]; then echo "test-seed-import-policy: $failures FAILURE(S)" >&2; exit 1; fi
echo "test-seed-import-policy: OK"
