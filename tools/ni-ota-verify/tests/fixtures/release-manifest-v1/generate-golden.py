#!/usr/bin/env python3
"""Regenerate the release-manifest v1 cross-contract golden vectors.

The expected values in `golden.json` are produced by the CANONICAL ICE-Fabric
implementation, never by the Rust reader under test.  That is the whole point:
`tools/ni-ota-verify/src/release_manifest.rs` is only correct if it reproduces
these bytes without ever having seen them.

This script is NOT run by CI (the pinned Rust image has no Python).  It is the
documented, re-runnable procedure behind the committed vectors:

    ICE_FABRIC_SHA=e08446d6fc899f670b962f1e013bbf46e7e91497
    mkdir -p /tmp/fabric-v1 && cd /tmp/fabric-v1
    for f in contract.py classifier.py release-manifest-v1.schema.json; do
      gh api "repos/Neural-ICE/ICE-Fabric/contents/release-manifest/$f?ref=$ICE_FABRIC_SHA" \
        --jq .content | base64 -d > "$f"
    done
    PYTHONPATH=/tmp/fabric-v1 python3 \
      tools/ni-ota-verify/tests/fixtures/release-manifest-v1/generate-golden.py

Regenerating must be a no-op unless the Fabric contract itself moved; a dirty
`git diff` here means CoreOS and Fabric disagree and the pin must be re-decided.
"""

from __future__ import annotations

import hashlib
import json
import pathlib

import contract
from contract import ContractRefusal, parse
from classifier import DeviceCompatibility, classify

FABRIC_SHA = "e08446d6fc899f670b962f1e013bbf46e7e91497"
FABRIC_SOURCES = ("contract.py", "classifier.py", "release-manifest-v1.schema.json")

HERE = pathlib.Path(__file__).resolve().parent
MANIFESTS = HERE / "manifests"
# Where the pinned Fabric sources were imported from, so the vectors record the
# exact bytes they were derived from rather than a bare commit claim.
FABRIC_DIR = pathlib.Path(contract.__file__).resolve().parent

HOST_A = "sha256:" + "11" * 32
HOST_B = "sha256:" + "1b" * 32
API_A = "sha256:" + "22" * 32
API_B = "sha256:" + "2b" * 32
AGENT_A = "sha256:" + "33" * 32
AGENT_B = "sha256:" + "3b" * 32
GEMMA_A = "sha256:" + "44" * 32
DOCS_A = "sha256:" + "4c" * 32
BOM = "sha256:" + "55" * 32
ATTESTATION = "sha256:" + "66" * 32

OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"


def host(digest: str = HOST_A) -> dict:
    return {
        "repository": "registry.neural-ice.ch/neural-ice/neural-ice-appliance",
        "digest": digest,
        "contract": "host-bootc-v1",
        "restart_scope": [],
        "reboot_required": True,
        "required_entitlement": "ICE-CORE",
    }


def api(digest: str = API_A, contract: str = "component-oci-v1") -> dict:
    return {
        "component_id": "icecore-api",
        "repository": "registry.neural-ice.ch/neural-ice/icecore-api",
        "digest": digest,
        "contract": contract,
        "restart_scope": ["icecore-api.service"],
        "reboot_required": False,
        "required_entitlement": "ICE-CORE",
    }


# `vendor/` is a first-class Fabric namespace. A reader that rejects it silently
# un-ships every third-party component.
def agentic(digest: str = AGENT_A, scope: list[str] | None = None) -> dict:
    return {
        "component_id": "agentic-core",
        "repository": "registry.neural-ice.ch/vendor/agentic-core",
        "digest": digest,
        "contract": "component-oci-v1",
        "restart_scope": (
            ["ghostunnel-agentic-core.service", "agentic-core.service"]
            if scope is None
            else scope
        ),
        "reboot_required": False,
        "required_entitlement": "ICE-AGENTIC",
    }


def gemma(scope: list[str] | None = None) -> dict:
    return {
        "content_id": "model-gemma",
        "media_type": OCI_MANIFEST,
        "repository": "registry.neural-ice.ch/vendor/models/gemma",
        "digest": GEMMA_A,
        "contract": "content-oci-v1",
        "restart_scope": ["sglang-inference.service"] if scope is None else scope,
        "reboot_required": False,
        "required_entitlement": "ICE-INFERENCE",
    }


def docs() -> dict:
    return {
        "content_id": "kb-corpus",
        "media_type": OCI_MANIFEST,
        "repository": "registry.neural-ice.ch/neural-ice/kb/corpus",
        "digest": DOCS_A,
        "contract": "content-oci-v1",
        "restart_scope": [],
        "reboot_required": False,
        "required_entitlement": "ICE-KB",
    }


def manifest(
    *,
    bundle_seq: int,
    host_payload: dict | None = None,
    components: list[dict] | None = None,
    content: list[dict] | None = None,
    required_contracts: list[str] | None = None,
    minimum_reader: int = 1,
) -> dict:
    return {
        "schema": "neural-ice-release-manifest-v1",
        "release_id": "ice-appliance-0.51.0",
        "bundle_seq": bundle_seq,
        "hardware_target": "nvidia-gb10-arm64",
        "compatibility": {
            "minimum_reader": minimum_reader,
            "required_contracts": (
                ["host-bootc-v1", "content-oci-v1", "component-oci-v1"]
                if required_contracts is None
                else required_contracts
            ),
        },
        "host": host() if host_payload is None else host_payload,
        # Deliberately NOT in sorted order: normalization must fix it.
        "components": [api(), agentic()] if components is None else components,
        "content": [gemma()] if content is None else content,
        "evidence": [
            {"kind": "bom", "digest": BOM},
            {"kind": "attestation", "digest": ATTESTATION},
        ],
    }


def pretty(value: dict) -> bytes:
    """Deliberately NON-canonical bytes: indented, insertion-ordered, no LF."""
    return json.dumps(value, indent=2, ensure_ascii=False).encode("utf-8")


def compact(value: dict) -> bytes:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


BASE = manifest(bundle_seq=41)

VECTORS: dict[str, bytes] = {}

# --- accepted manifests -----------------------------------------------------
VECTORS["base"] = pretty(BASE)

# Same manifest, every set-like array shuffled and every key re-ordered: the
# canonical digest MUST be identical to `base`. This is what makes a raw
# input-bytes hash (the #115 behaviour) impossible to reintroduce silently.
reordered = {
    "evidence": [
        {"digest": ATTESTATION, "kind": "attestation"},
        {"digest": BOM, "kind": "bom"},
    ],
    "content": [gemma(scope=["sglang-inference.service"])],
    "components": [agentic(scope=["agentic-core.service", "ghostunnel-agentic-core.service"]), api()],
    "host": host(),
    "compatibility": {
        "required_contracts": ["component-oci-v1", "host-bootc-v1", "content-oci-v1"],
        "minimum_reader": 1,
    },
    "hardware_target": "nvidia-gb10-arm64",
    "bundle_seq": 41,
    "release_id": "ice-appliance-0.51.0",
    "schema": "neural-ice-release-manifest-v1",
}
VECTORS["base-reordered"] = compact(reordered)

VECTORS["component-content"] = pretty(
    manifest(bundle_seq=42, components=[api(digest=API_B), agentic()])
)
VECTORS["content-added"] = pretty(
    manifest(bundle_seq=42, content=[gemma(), docs()])
)
# Host payload delta AND a component replacement whose restart scope differs on
# each side: the plan must carry the union of the installed and candidate units.
VECTORS["host"] = pretty(
    manifest(
        bundle_seq=42,
        host_payload=host(digest=HOST_B),
        components=[
            api(),
            agentic(
                digest=AGENT_B,
                scope=["agentic-core.service", "ice-agent-runtime.service"],
            ),
        ],
    )
)
# Compatibility-only edit: no host payload delta, yet still a host transition.
VECTORS["compatibility-widened"] = pretty(
    manifest(
        bundle_seq=42,
        required_contracts=[
            "host-bootc-v1",
            "content-oci-v1",
            "component-oci-v1",
            "evidence-v1",
        ],
    )
)
VECTORS["rollback"] = pretty(manifest(bundle_seq=40))
VECTORS["same-seq-divergent"] = pretty(
    manifest(bundle_seq=41, components=[api(digest=API_B), agentic()])
)
VECTORS["component-removed"] = pretty(manifest(bundle_seq=42, components=[api()]))
VECTORS["component-contract-changed"] = pretty(
    manifest(bundle_seq=42, components=[api(contract="content-oci-v1"), agentic()])
)
VECTORS["content-restart-changed"] = pretty(
    manifest(bundle_seq=42, content=[gemma(scope=["vllm-inference.service"])])
)

# --- refused manifests ------------------------------------------------------
release_seq = manifest(bundle_seq=41)
release_seq["release_seq"] = release_seq.pop("bundle_seq")
VECTORS["release-seq"] = pretty(release_seq)

no_compat = manifest(bundle_seq=41)
del no_compat["compatibility"]
VECTORS["missing-compatibility"] = pretty(no_compat)

no_entitlement = manifest(bundle_seq=41)
no_entitlement["components"][0].pop("required_entitlement")
VECTORS["missing-entitlement"] = pretty(no_entitlement)

no_restart = manifest(bundle_seq=41)
no_restart["host"].pop("restart_scope")
VECTORS["missing-restart-scope"] = pretty(no_restart)

foreign = manifest(bundle_seq=41)
foreign["host"]["repository"] = "registry.example.test/neural-ice/neural-ice-appliance"
VECTORS["foreign-registry"] = pretty(foreign)

undeclared = manifest(
    bundle_seq=41, required_contracts=["host-bootc-v1", "content-oci-v1"]
)
VECTORS["undeclared-contract"] = pretty(undeclared)

overflow = manifest(bundle_seq=41)
overflow["host"]["restart_scope"] = [f"unit-{i:02}.service" for i in range(33)]
VECTORS["restart-scope-overflow"] = pretty(overflow)

dup_component = manifest(bundle_seq=41, components=[api(), api(digest=API_B)])
VECTORS["duplicate-component-id"] = pretty(dup_component)

# --- grammar boundaries -----------------------------------------------------
# `^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$` admits exactly 128 bytes, and
# `^[A-Za-z0-9](?:[A-Za-z0-9:_.@-]{0,126}[A-Za-z0-9])?\.(service|...)$` bounds
# the STEM at 128 and requires it to END alphanumeric. Reading either bound off
# the wrong string rejects manifests Fabric signs, or accepts units it refuses.
IDENTIFIER_128 = "i" + "-d" * 63 + "z"
IDENTIFIER_129 = IDENTIFIER_128 + "z"
UNIT_STEM_128 = "u" + "-x" * 63 + "z"
UNIT_STEM_129 = UNIT_STEM_128 + "y"
assert len(IDENTIFIER_128) == 128 and len(IDENTIFIER_129) == 129
assert len(UNIT_STEM_128) == 128 and len(UNIT_STEM_129) == 129

identifier_max = manifest(bundle_seq=41)
identifier_max["release_id"] = IDENTIFIER_128
VECTORS["identifier-max-length"] = pretty(identifier_max)

identifier_over = manifest(bundle_seq=41)
identifier_over["release_id"] = IDENTIFIER_129
VECTORS["identifier-over-length"] = pretty(identifier_over)

# 128-byte stem + ".service" = a legitimate 136-byte unit.
unit_max = manifest(bundle_seq=42)
unit_max["host"]["restart_scope"] = [f"{UNIT_STEM_128}.service"]
VECTORS["unit-max-length"] = pretty(unit_max)

unit_over = manifest(bundle_seq=41)
unit_over["host"]["restart_scope"] = [f"{UNIT_STEM_129}.service"]
VECTORS["unit-over-length"] = pretty(unit_over)

# The stem, not the whole name, must end alphanumeric.
unit_punctuation = manifest(bundle_seq=41)
unit_punctuation["host"]["restart_scope"] = ["foo-.service"]
VECTORS["unit-trailing-punctuation"] = pretty(unit_punctuation)

# An entitlement move is NOT a digest-only change: it needs the host engine.
VECTORS["entitlement-changed"] = pretty(
    manifest(
        bundle_seq=42,
        components=[
            {**api(), "required_entitlement": "ICE-CORE-PLUS"},
            agentic(),
        ],
    )
)
# The same entitlement move, carried by an explicit host delta, is admissible.
VECTORS["entitlement-changed-with-host"] = pretty(
    manifest(
        bundle_seq=42,
        host_payload=host(digest=HOST_B),
        components=[
            {**api(), "required_entitlement": "ICE-CORE-PLUS"},
            agentic(),
        ],
    )
)

VECTORS["float-bundle-seq"] = pretty(BASE).replace(
    b'"bundle_seq": 41', b'"bundle_seq": 41.0'
)
VECTORS["duplicate-json-key"] = pretty(BASE).replace(
    b'"bundle_seq": 41,', b'"bundle_seq": 41,\n  "bundle_seq": 42,'
)
VECTORS["non-finite"] = pretty(BASE).replace(b'"bundle_seq": 41', b'"bundle_seq": NaN')
VECTORS["oversized-integer"] = pretty(BASE).replace(
    b'"bundle_seq": 41', b'"bundle_seq": 99999999999999999'
)

DEVICES = {
    "gb10": {
        "hardware_target": "nvidia-gb10-arm64",
        "reader_version": 1,
        "supported_contracts": [
            "component-oci-v1",
            "content-oci-v1",
            "evidence-v1",
            "host-bootc-v1",
        ],
    },
    "wrong-hardware": {
        "hardware_target": "nvidia-cuda-x86_64",
        "reader_version": 1,
        "supported_contracts": [
            "component-oci-v1",
            "content-oci-v1",
            "evidence-v1",
            "host-bootc-v1",
        ],
    },
    "old-reader": {
        "hardware_target": "nvidia-gb10-arm64",
        "reader_version": 0,
        "supported_contracts": [
            "component-oci-v1",
            "content-oci-v1",
            "evidence-v1",
            "host-bootc-v1",
        ],
    },
    "missing-contract": {
        "hardware_target": "nvidia-gb10-arm64",
        "reader_version": 1,
        "supported_contracts": ["component-oci-v1", "host-bootc-v1"],
    },
}

PLAN_CASES = [
    ("noop-identical", "base", "base", "gb10"),
    ("noop-canonically-equal", "base", "base-reordered", "gb10"),
    ("component-content", "base", "component-content", "gb10"),
    ("content-added", "base", "content-added", "gb10"),
    ("host", "base", "host", "gb10"),
    ("compatibility-widened-is-host", "base", "compatibility-widened", "gb10"),
    ("rollback", "base", "rollback", "gb10"),
    ("same-seq-divergent", "base", "same-seq-divergent", "gb10"),
    ("component-membership-without-host", "base", "component-removed", "gb10"),
    ("component-contract-without-host", "base", "component-contract-changed", "gb10"),
    ("content-contract-without-host", "base", "content-restart-changed", "gb10"),
    ("wrong-hardware", "base", "component-content", "wrong-hardware"),
    ("old-reader", "base", "component-content", "old-reader"),
    ("missing-contract", "base", "component-content", "missing-contract"),
    ("candidate-release-seq", "base", "release-seq", "gb10"),
    ("current-release-seq", "release-seq", "base", "gb10"),
    ("candidate-missing-compatibility", "base", "missing-compatibility", "gb10"),
    ("candidate-missing-entitlement", "base", "missing-entitlement", "gb10"),
    ("candidate-missing-restart-scope", "base", "missing-restart-scope", "gb10"),
    ("candidate-foreign-registry", "base", "foreign-registry", "gb10"),
    ("candidate-undeclared-contract", "base", "undeclared-contract", "gb10"),
    ("candidate-restart-scope-overflow", "base", "restart-scope-overflow", "gb10"),
    ("candidate-duplicate-component-id", "base", "duplicate-component-id", "gb10"),
    ("candidate-float-bundle-seq", "base", "float-bundle-seq", "gb10"),
    ("candidate-duplicate-json-key", "base", "duplicate-json-key", "gb10"),
    ("candidate-non-finite", "base", "non-finite", "gb10"),
    ("candidate-oversized-integer", "base", "oversized-integer", "gb10"),
    ("candidate-identifier-over-length", "base", "identifier-over-length", "gb10"),
    ("candidate-unit-over-length", "base", "unit-over-length", "gb10"),
    ("candidate-unit-trailing-punctuation", "base", "unit-trailing-punctuation", "gb10"),
    ("host-with-max-length-unit", "base", "unit-max-length", "gb10"),
    ("entitlement-only-without-host", "base", "entitlement-changed", "gb10"),
    ("entitlement-with-host-delta", "base", "entitlement-changed-with-host", "gb10"),
]


def plan_bytes(plan) -> str:
    return (
        json.dumps(
            plan.as_dict(),
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    )


def main() -> int:
    MANIFESTS.mkdir(parents=True, exist_ok=True)
    for name, data in VECTORS.items():
        (MANIFESTS / f"{name}.json").write_bytes(data)

    manifests: dict[str, dict] = {}
    for name, data in VECTORS.items():
        entry: dict = {"raw_sha256": "sha256:" + hashlib.sha256(data).hexdigest()}
        try:
            parsed = parse(data)
        except ContractRefusal as error:
            entry["refusal"] = str(error)
        else:
            entry["canonical"] = parsed.canonical_bytes.decode("utf-8")
            entry["digest"] = parsed.digest
        manifests[name] = entry

    plans = {}
    for case, current, candidate, device in PLAN_CASES:
        compat = DeviceCompatibility.create(
            DEVICES[device]["hardware_target"],
            DEVICES[device]["reader_version"],
            DEVICES[device]["supported_contracts"],
        )
        plan = classify(VECTORS[current], VECTORS[candidate], compat)
        plans[case] = {
            "current": current,
            "candidate": candidate,
            "device": device,
            "plan": plan_bytes(plan),
        }

    golden = {
        "provenance": {
            "produced_by": "ICE-Fabric release-manifest/{contract,classifier}.py",
            "fabric_sha": FABRIC_SHA,
            "fabric_source_sha256": {
                name: hashlib.sha256((FABRIC_DIR / name).read_bytes()).hexdigest()
                for name in FABRIC_SOURCES
                if (FABRIC_DIR / name).is_file()
            },
            "regenerate": (
                "PYTHONPATH=<fabric release-manifest checkout at fabric_sha> python3 "
                "tools/ni-ota-verify/tests/fixtures/release-manifest-v1/"
                "generate-golden.py"
            ),
            "note": (
                "Expected values come from the canonical Python contract, never "
                "from the Rust reader under test."
            ),
        },
        "devices": DEVICES,
        "manifests": manifests,
        "plans": plans,
    }
    (HERE / "golden.json").write_text(
        json.dumps(golden, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"wrote {len(VECTORS)} manifests and {len(plans)} plans")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
