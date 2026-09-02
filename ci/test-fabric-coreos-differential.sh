#!/usr/bin/env bash
# Fail-loud differential gate against the live Fabric release contract/vector tree.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FABRIC_ROOT="${NEURAL_ICE_FABRIC_ROOT:?NEURAL_ICE_FABRIC_ROOT must name the current ICE-Fabric worktree}"
VECTOR_ROOT="$FABRIC_ROOT/release-manifest"

for path in \
  "$VECTOR_ROOT/coreos-ring-differential-v1.json" \
  "$VECTOR_ROOT/coreos-ring-fixtures/index.json" \
  "$VECTOR_ROOT/vectors/index.json" \
  "$VECTOR_ROOT/authorization.py" \
  "$VECTOR_ROOT/closure.py"; do
  [[ -f $path && ! -L $path ]] || { echo "missing Fabric differential input: $path" >&2; exit 1; }
done

mode="${1:-}"
[[ -z "$mode" || "$mode" == --self-test ]] \
  || { echo "usage: $0 [--self-test]" >&2; exit 2; }

python3 - "$VECTOR_ROOT" "$ROOT" "$mode" <<'PY'
import copy, hashlib, json, pathlib, sys
root = pathlib.Path(sys.argv[1])
consumer_root = pathlib.Path(sys.argv[2])
mode = sys.argv[3]
differential = json.loads((root / "coreos-ring-differential-v1.json").read_bytes())
expected_current_files = {
    "image/build-installer-usb.sh",
    "image/build-seed-v2.sh",
    "image/installer/neural-ice-registry-authorisation.py",
    "tools/ni-ota-verify/src/delegated.rs",
    "tools/ni-ota-verify/src/delegated/contract.rs",
    "tools/ni-ota-verify/src/seed_closure.rs",
    "tools/ni-ota-verify/src/seed_closure_tests.rs",
}

def validate_publication(document):
    if document.get("verdict") != "ready":
        raise ValueError(f"Fabric differential verdict is not ready: {document.get('verdict')!r}")
    if document.get("consumer_tree_state") != "clean":
        raise ValueError(
            f"Fabric differential consumer tree is not clean: {document.get('consumer_tree_state')!r}"
        )
    current = document.get("current_files")
    if not isinstance(current, dict) or not current:
        raise ValueError("Fabric differential current_files is absent or empty")
    if set(current) != expected_current_files:
        raise ValueError("Fabric differential current_files inventory is incomplete or widened")
    for relative, expected_hash in sorted(current.items()):
        if not isinstance(relative, str) or relative.startswith("/") or ".." in pathlib.PurePosixPath(relative).parts:
            raise ValueError(f"unsafe Fabric current_files path: {relative!r}")
        path = consumer_root / relative
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"Fabric current_files path is missing or not a regular file: {relative}")
        observed = hashlib.sha256(path.read_bytes()).hexdigest()
        if observed != expected_hash:
            raise ValueError(
                f"Fabric current_files hash mismatch for {relative}: expected {expected_hash}, observed {observed}"
            )

if mode == "--self-test":
    rejected = copy.deepcopy(differential)
    rejected["verdict"] = "consumer-update-required"
    rejected["consumer_tree_state"] = "dirty-read-only-snapshot"
    try:
        validate_publication(rejected)
    except ValueError:
        pass
    else:
        raise SystemExit("rejected/dirty Fabric current was accepted")

    clean = copy.deepcopy(differential)
    clean["verdict"] = "ready"
    clean["consumer_tree_state"] = "clean"
    clean["current_files"] = {
        relative: hashlib.sha256((consumer_root / relative).read_bytes()).hexdigest()
        for relative in differential["current_files"]
    }
    validate_publication(clean)
    mismatched = copy.deepcopy(clean)
    first = sorted(mismatched["current_files"])[0]
    mismatched["current_files"][first] = "0" * 64
    try:
        validate_publication(mismatched)
    except ValueError:
        pass
    else:
        raise SystemExit("Fabric current_files hash mismatch was accepted")
    print("Fabric publication gate: rejected current, clean fixture positive, hash mutation refused")
else:
    try:
        validate_publication(differential)
    except ValueError as error:
        raise SystemExit(str(error))

expected = {
    "authorization_schema": "neural-ice-ota-release-authorization-v2",
    "delegation_schema": "neural-ice-ota-delegation-snapshot-v1",
    "fixture_index": "release-manifest/coreos-ring-fixtures/index.json",
    "projection_formats": [],
    "signing_bytes": "domain-nul-plus-canonical-json-without-lf",
}
if differential.get("canonical_authorities") != expected:
    raise SystemExit("Fabric canonical signing authority/schema contract drifted")
required = {"bundle-digest-v1", "delegated-rings-v1", "transactional-ring-state-v1"}
if not required.issubset(set(differential.get("required_capabilities", []))):
    raise SystemExit("Fabric required capability contract drifted")

fixtures = root / "coreos-ring-fixtures"
index = json.loads((fixtures / "index.json").read_bytes())
for case in index["cases"]:
    auth = json.loads((fixtures / case["authorization"]).read_bytes())
    if case["expect"] == "accept" and auth["signing_role"] != f"release-{auth['ring']}":
        raise SystemExit(f"Fabric emitted split release role in {case['vector_id']}")
if not any(case["vector_id"] == "negative-role" and case["expect"] == "refuse" for case in index["cases"]):
    raise SystemExit("Fabric removed the split release-role negative vector")
negative = fixtures / "negative-split-role-artifact.release-closure.json"
if not negative.is_file():
    raise SystemExit("Fabric removed the split image-role negative vector")

vectors = json.loads((root / "vectors/index.json").read_bytes())
accepted = 0
for vector in vectors["vectors"]:
    if vector.get("kind") != "release" or vector.get("expect") != "accept":
        continue
    closure = json.loads((root / "vectors" / vector["closure"]).read_bytes())
    for artifact in closure["artifacts"]:
        if not isinstance(artifact["root"], dict) or set(artifact["root"]) != {"digest", "repository"}:
            raise SystemExit("Fabric closure root stopped being the closure-v2 object shape")
        if set(artifact.get("vendor") or {}) not in (set(), {"source_repository", "source_digest", "ingested_digest"}):
            raise SystemExit("Fabric vendor closure contract drifted")
        for node in artifact["nodes"]:
            for signature in node["signatures"]:
                if signature["role"] != "image-ci":
                    raise SystemExit("Fabric emitted a split image role")
    accepted += 1
if accepted < 3:
    raise SystemExit("Fabric release vector set lost its positive ring coverage")
print(f"Fabric vector structure: {accepted} positive releases, exact image-ci/object-root/vendor contract")
PY

env NEURAL_ICE_FABRIC_ROOT="$FABRIC_ROOT" \
  cargo test --manifest-path "$ROOT/tools/ni-ota-verify/Cargo.toml" \
    seed_closure::tests::fabric_ring_vectors_bind_exact_domain_separated_bytes \
    -- --exact
env NEURAL_ICE_FABRIC_ROOT="$FABRIC_ROOT" \
  cargo test --manifest-path "$ROOT/tools/ni-ota-verify/Cargo.toml" \
    seed_closure::tests::fabric_generated_closure_is_consumed_when_available \
    -- --exact
env NEURAL_ICE_FABRIC_ROOT="$FABRIC_ROOT" \
  cargo test --manifest-path "$ROOT/tools/ni-ota-verify/Cargo.toml" \
    seed_closure::tests::fabric_platform_negative_vectors_reach_the_production_closure_validator \
    -- --exact
env NEURAL_ICE_FABRIC_ROOT="$FABRIC_ROOT" \
  cargo test --manifest-path "$ROOT/tools/ni-ota-verify/Cargo.toml" \
    seed_closure::tests::fabric_delegation_drives_a_complete_verify_seed_with_fixture \
    -- --exact
# The default-feature build the OS image ships, driven through the real
# verify_seed entry with NI_OTA_COSIGN=/usr/bin/true: root→snapshot, release
# authorization and OCI attestation must all reach the pinned cosign or refuse.
env NEURAL_ICE_FABRIC_ROOT="$FABRIC_ROOT" \
  cargo test --manifest-path "$ROOT/tools/ni-ota-verify/Cargo.toml" \
    seed_closure::tests::production_verifier_ignores_the_cosign_environment_seam \
    -- --exact

echo "FABRIC_COREOS_DIFFERENTIAL_OK"
