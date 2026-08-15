#!/usr/bin/env bash
# The container-image signature policy must REFUSE, and must refuse when in doubt.
#
# WHAT THIS GUARDS
#
#   1. The policy this OS ships (image/bootc-overlay/etc/containers/policy.json)
#      has a default of `reject`, is byte-identical to what the renderer emits
#      with no scope, and carries no deployment identity of its own.
#   2. image/policy/render-container-policy.sh cannot be talked into emitting a
#      permissive posture, and refuses — writing NOTHING — when the trusted key
#      is absent, empty, unreadable or relative.
#   3. The four decisions the policy exists to make, executed against the real
#      containers/image policy engine: unsigned REFUSED, signed by another key
#      REFUSED, correctly signed ACCEPTED, and — the case that matters most —
#      every form of DOUBT REFUSED (illegible signature, missing key, missing
#      policy, malformed policy).
#   4. That §3 is not vacuous: the same matrix is re-run against a deliberately
#      permissive default, and the unsigned image must then be ACCEPTED. If it
#      is not, the harness is inert and this script fails rather than reporting
#      a reassuring pass.
#
# WHAT §3 DOES AND DOES NOT REPRODUCE OF THE APPLIANCE
#
#   Same engine, same requirement types (`reject`, `sigstoreSigned`), same key
#   handling, same shipped `default`. DIFFERENT transport: this test signs and
#   verifies over `dir:`, because a `docker:` case needs a live registry, and a
#   registry in CI means pulling registry:2 from Docker Hub on a shared-IP
#   GitHub runner — a rate limit away from a red build that says nothing about
#   this policy. On `dir:` the policy scope is a path, so the signed identity is
#   matched with `exactReference`; the shipped renderer matches with
#   `matchRepository`, which §1/§2 check structurally.
#
#   The `docker:` matrix WAS executed, by hand, against a local registry with
#   cosign-produced attachments; its output is quoted in the pull request that
#   introduced this file. What is NOT reproducible in CI is not silently
#   dropped — it is named here.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

SHIPPED_POLICY="image/bootc-overlay/etc/containers/policy.json"
RENDERER="image/policy/render-container-policy.sh"

failures=0
fail() { echo "FAIL: $*" >&2; failures=$((failures + 1)); }
ok() { echo "  ok: $*"; }

command -v skopeo >/dev/null || { echo "skopeo is required by this test" >&2; exit 3; }
command -v python3 >/dev/null || { echo "python3 is required by this test" >&2; exit 3; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# --------------------------------------------------------------------------- #
# 1) The shipped policy
# --------------------------------------------------------------------------- #
echo "1) the policy this OS ships"

bash "$RENDERER" --policy-out - --registries-d-out '' > "$WORK/vanilla.json"
if ! diff -u "$SHIPPED_POLICY" "$WORK/vanilla.json" > "$WORK/vanilla.diff"; then
  fail "$SHIPPED_POLICY is not what $RENDERER renders with no scope"
  sed 's/^/       /' "$WORK/vanilla.diff" >&2
else
  ok "the shipped policy is exactly the renderer's zero-scope output"
fi

python3 - "$SHIPPED_POLICY" <<'PY' || fail "the shipped policy is not fail-closed"
import json, sys

policy = json.load(open(sys.argv[1]))
problems = []

if policy.get("default") != [{"type": "reject"}]:
    problems.append(f'default is {policy.get("default")!r}, not [{{"type": "reject"}}]')

# Any scope at all in the vanilla image would be deployment identity (FAB-0032),
# and any accepting requirement would be a hole. Walk the whole document rather
# than checking the shapes we happen to expect.
for transport, scopes in (policy.get("transports") or {}).items():
    for scope, reqs in (scopes or {}).items():
        problems.append(f"vanilla policy names scope {scope!r} under transport {transport!r}")
        for req in reqs or []:
            if req.get("type") != "reject":
                problems.append(f"vanilla policy allows {req.get('type')!r} for {scope!r}")

blob = json.dumps(policy)
for forbidden in ("insecureAcceptAnything",):
    if forbidden in blob:
        problems.append(f"the shipped policy contains {forbidden!r}")

for p in problems:
    print(f"FAIL: {p}", file=sys.stderr)
sys.exit(1 if problems else 0)
PY
[ "$failures" -ne 0 ] || ok "default is reject, no scope, no accepting requirement"

# --------------------------------------------------------------------------- #
# 2) The renderer cannot be talked into a permissive posture
# --------------------------------------------------------------------------- #
echo "2) the renderer's fail-closed contract"

: > "$WORK/empty.pub"
printf 'this is not a key\n' > "$WORK/garbage.pub"
printf -- '-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n' > "$WORK/good.pub"

# Each of these must exit non-zero AND leave the output file untouched. A
# renderer that fails loudly but has already written half a policy is not
# fail-closed, it is fail-closed-on-the-next-boot.
refuses() { # refuses <description> <renderer args...>
  local what="$1"; shift
  local out="$WORK/out.json"
  printf 'SENTINEL\n' > "$out"
  if bash "$RENDERER" --policy-out "$out" --registries-d-out '' "$@" >/dev/null 2>&1; then
    fail "the renderer accepted $what"
    return
  fi
  if [ "$(cat "$out")" != "SENTINEL" ]; then
    fail "the renderer wrote output while refusing $what"
    return
  fi
  ok "refuses $what"
}

refuses "a missing key file"        --signed-scope "reg.example.test/org=$WORK/absent.pub"
refuses "an empty key file"         --signed-scope "reg.example.test/org=$WORK/empty.pub"
refuses "a non-PEM key file"        --signed-scope "reg.example.test/org=$WORK/garbage.pub"
refuses "a relative key path"       --signed-scope "reg.example.test/org=good.pub"
refuses "a scope without a key"     --signed-scope "reg.example.test/org"
refuses "an empty scope"            --signed-scope "=$WORK/good.pub"
refuses "a wildcard scope"          --signed-scope "*.example.test=$WORK/good.pub"
refuses "an unknown signed-identity" --signed-identity insecureAcceptAnything \
                                     --signed-scope "reg.example.test/org=$WORK/good.pub"
refuses "an unknown option"         --allow-everything

bash "$RENDERER" --policy-out "$WORK/scoped.json" --registries-d-out "$WORK/scoped.yaml" \
  --signed-scope "reg.example.test/org=$WORK/good.pub"
python3 - "$WORK/scoped.json" <<'PY' || fail "a scoped render is not fail-closed by default"
import json, sys
policy = json.load(open(sys.argv[1]))
assert policy["default"] == [{"type": "reject"}], policy["default"]
reqs = policy["transports"]["docker"]["reg.example.test/org"]
assert [r["type"] for r in reqs] == ["sigstoreSigned"], reqs
# matchRepository is deliberate and measured (see the renderer's header): cosign
# writes a bare-repository identity, so the stricter modes accept NOTHING.
assert reqs[0]["signedIdentity"] == {"type": "matchRepository"}, reqs[0]
PY
ok "a scoped render keeps default=reject and adds only sigstoreSigned"

grep -q 'use-sigstore-attachments: true' "$WORK/scoped.yaml" \
  || fail "the scoped render did not enable sigstore attachments for the scope"
ok "the scoped render enables sigstore attachments (without it, a SIGNED image is refused)"

# --------------------------------------------------------------------------- #
# 3) The four decisions, executed
# --------------------------------------------------------------------------- #
echo "3) the decisions, against the containers/image policy engine"

cat > "$WORK/mkimage.py" <<'PY'
"""Build a minimal, byte-deterministic OCI layout. No network, no base image."""
import gzip, hashlib, io, json, os, sys, tarfile

out = sys.argv[1]
blobs = os.path.join(out, "blobs", "sha256")
os.makedirs(blobs, exist_ok=True)

def put(data):
    digest = hashlib.sha256(data).hexdigest()
    with open(os.path.join(blobs, digest), "wb") as fh:
        fh.write(data)
    return "sha256:" + digest, len(data)

raw = io.BytesIO()
with tarfile.open(fileobj=raw, mode="w") as tf:
    payload = b"neural-ice container signature policy test\n"
    info = tarfile.TarInfo("hello.txt")
    info.size, info.mtime = len(payload), 0
    tf.addfile(info, io.BytesIO(payload))
diff_id = "sha256:" + hashlib.sha256(raw.getvalue()).hexdigest()
layer_digest, layer_size = put(gzip.compress(raw.getvalue(), mtime=0))

config_digest, config_size = put(json.dumps({
    "architecture": "amd64", "os": "linux", "config": {},
    "rootfs": {"type": "layers", "diff_ids": [diff_id]},
}, sort_keys=True).encode())

manifest_digest, manifest_size = put(json.dumps({
    "schemaVersion": 2,
    "mediaType": "application/vnd.oci.image.manifest.v1+json",
    "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
               "digest": config_digest, "size": config_size},
    "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                "digest": layer_digest, "size": layer_size}],
}, sort_keys=True).encode())

json.dump({"imageLayoutVersion": "1.0.0"}, open(os.path.join(out, "oci-layout"), "w"))
json.dump({"schemaVersion": 2, "manifests": [{
    "mediaType": "application/vnd.oci.image.manifest.v1+json",
    "digest": manifest_digest, "size": manifest_size,
    "annotations": {"org.opencontainers.image.ref.name": "v1"}}]},
    open(os.path.join(out, "index.json"), "w"))
PY

cat > "$WORK/scopedir.py" <<'PY'
"""Take the SHIPPED policy and add one dir-transport exception to it.

Everything under test — the default, the requirement types — is the shipped
document. Only the exception is synthesized, because a dir: scope is a path.
"""
import json, sys
shipped, scope, key, identity, dest = sys.argv[1:6]
policy = json.load(open(shipped))
policy.setdefault("transports", {})["dir"] = {scope: [{
    "type": "sigstoreSigned", "keyPath": key,
    "signedIdentity": {"type": "exactReference", "dockerReference": identity}}]}
json.dump(policy, open(dest, "w"), indent=2)
PY

python3 "$WORK/mkimage.py" "$WORK/layout"
: > "$WORK/pass.txt"
skopeo generate-sigstore-key --output-prefix "$WORK/trusted" --passphrase-file "$WORK/pass.txt" >/dev/null
skopeo generate-sigstore-key --output-prefix "$WORK/other"   --passphrase-file "$WORK/pass.txt" >/dev/null

IDENTITY="reg.example.test/ni/app:v1"
sign_into() { # sign_into <dir> <private key or empty>
  local dest="$1" key="${2:-}"
  if [ -n "$key" ]; then
    skopeo --insecure-policy copy "oci:$WORK/layout:v1" "dir:$dest" \
      --sign-by-sigstore-private-key "$key" --sign-passphrase-file "$WORK/pass.txt" \
      --sign-identity "$IDENTITY" >/dev/null
  else
    skopeo --insecure-policy copy "oci:$WORK/layout:v1" "dir:$dest" >/dev/null
  fi
}
sign_into "$WORK/img-trusted" "$WORK/trusted.private"
sign_into "$WORK/img-other"   "$WORK/other.private"
sign_into "$WORK/img-unsigned"

# An image whose signature is present but illegible: the doubt case that a
# missing-signature test does not cover. containers/image stores dir: signatures
# as signature-N blobs; corrupting the body is exactly "I have something that
# claims to be a signature and I cannot make sense of it".
cp -r "$WORK/img-trusted" "$WORK/img-garbled"
printf 'not a signature' > "$WORK/img-garbled/signature-1"

policy_for() { # policy_for <image dir> <public key> <dest>
  python3 "$WORK/scopedir.py" "$SHIPPED_POLICY" "$1" "$2" "$IDENTITY" "$3"
}

# verdict <expect accept|reject> <label> <policy> <image dir> [expected message]
verdict() {
  local expect="$1" label="$2" policy="$3" image="$4" needle="${5:-}"
  local out rc
  rm -rf "$WORK/dest"
  set +e
  out="$(skopeo --policy "$policy" copy "dir:$image" "dir:$WORK/dest" 2>&1)"
  rc=$?
  set -e
  if [ "$expect" = accept ]; then
    if [ "$rc" -ne 0 ]; then
      fail "$label: expected ACCEPT, got exit $rc"
      printf '%s\n' "$out" | sed 's/^/       /' >&2
    else
      ok "$label: accepted"
    fi
    return
  fi
  if [ "$rc" -eq 0 ]; then
    fail "$label: expected REJECT, the transfer SUCCEEDED"
    return
  fi
  if [ -n "$needle" ] && ! printf '%s' "$out" | grep -qF -- "$needle"; then
    fail "$label: refused, but not for the expected reason (wanted '$needle')"
    printf '%s\n' "$out" | sed 's/^/       /' >&2
    return
  fi
  ok "$label: refused — $(printf '%s' "$out" | tail -1 | sed 's/^.*msg="//; s/"$//')"
}

policy_for "$WORK/img-trusted"  "$WORK/trusted.pub" "$WORK/p-trusted.json"
policy_for "$WORK/img-other"    "$WORK/trusted.pub" "$WORK/p-other.json"
policy_for "$WORK/img-unsigned" "$WORK/trusted.pub" "$WORK/p-unsigned.json"
policy_for "$WORK/img-garbled"  "$WORK/trusted.pub" "$WORK/p-garbled.json"

verdict accept "correctly signed"      "$WORK/p-trusted.json"  "$WORK/img-trusted"
verdict reject "unsigned"              "$WORK/p-unsigned.json" "$WORK/img-unsigned" \
        "A signature was required, but no signature exists"
verdict reject "signed by another key" "$WORK/p-other.json"    "$WORK/img-other" \
        "cryptographic signature verification failed"
verdict reject "illegible signature"   "$WORK/p-garbled.json"  "$WORK/img-garbled"

# Doubt: the trusted key itself is gone, empty, or not a key. The renderer
# refuses these at composition (§2); this proves the runtime refuses them too,
# because a key can also disappear after the image is built.
policy_for "$WORK/img-trusted" "$WORK/absent.pub"  "$WORK/p-nokey.json"
policy_for "$WORK/img-trusted" "$WORK/empty.pub"   "$WORK/p-emptykey.json"
policy_for "$WORK/img-trusted" "$WORK/garbage.pub" "$WORK/p-badkey.json"
verdict reject "trusted key file absent"     "$WORK/p-nokey.json"    "$WORK/img-trusted"
verdict reject "trusted key file empty"      "$WORK/p-emptykey.json" "$WORK/img-trusted"
verdict reject "trusted key file unreadable" "$WORK/p-badkey.json"   "$WORK/img-trusted"

# Doubt about the policy itself.
printf '{ "default": [ {"type": "rej' > "$WORK/p-truncated.json"
printf '{ "default": [ {"type": "notAKnownRequirement"} ] }' > "$WORK/p-unknown.json"
verdict reject "policy file absent"    "$WORK/p-does-not-exist.json" "$WORK/img-trusted" \
        "Error loading trust policy"
verdict reject "policy file truncated" "$WORK/p-truncated.json" "$WORK/img-trusted" \
        "Error loading trust policy"
verdict reject "policy names an unknown requirement type" "$WORK/p-unknown.json" \
        "$WORK/img-trusted" "Error loading trust policy"

# Out of scope: a perfectly signed image at a path the policy does not cover
# falls through to the default. This is the case that fails the moment the
# default stops being `reject`.
cp -r "$WORK/img-trusted" "$WORK/img-elsewhere"
policy_for "$WORK/img-trusted" "$WORK/trusted.pub" "$WORK/p-scoped.json"
verdict reject "correctly signed but out of scope" "$WORK/p-scoped.json" "$WORK/img-elsewhere" \
        "is rejected by policy"

# --------------------------------------------------------------------------- #
# 4) Non-vacuity: prove the refusals above come from the default
# --------------------------------------------------------------------------- #
echo "4) non-vacuity — a permissive default must break the matrix"

python3 - "$SHIPPED_POLICY" "$WORK/permissive-shipped.json" <<'PY'
import json, sys
policy = json.load(open(sys.argv[1]))
policy["default"] = [{"type": "insecureAcceptAnything"}]
json.dump(policy, open(sys.argv[2], "w"), indent=2)
PY

rm -rf "$WORK/dest"
if skopeo --policy "$WORK/permissive-shipped.json" \
     copy "dir:$WORK/img-unsigned" "dir:$WORK/dest" >/dev/null 2>&1; then
  ok "with default=insecureAcceptAnything the unsigned image IS accepted — the matrix is live"
else
  fail "the harness rejects the unsigned image even with a permissive default: it is inert, and every pass above is meaningless"
fi

rm -rf "$WORK/dest"
if skopeo --policy "$WORK/permissive-shipped.json" \
     copy "dir:$WORK/img-elsewhere" "dir:$WORK/dest" >/dev/null 2>&1; then
  ok "with default=insecureAcceptAnything the out-of-scope image IS accepted — the default is what refuses it"
else
  fail "the out-of-scope refusal does not come from the default"
fi

if [ "$failures" -ne 0 ]; then
  echo "container signature policy tests: $failures FAILURE(S)" >&2
  exit 1
fi
echo "container signature policy tests: PASS"
