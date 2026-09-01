#!/usr/bin/env python3
"""Generate the release-manifest v1 cross-language consumer pack."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from classifier import DeviceCompatibility, classify
from contract import (
    MAX_DNS_HOST_LENGTH,
    REPOSITORY_PATTERN,
    ContractRefusal,
    canonical_bytes,
    normalize,
    parse,
)

ROOT = Path(__file__).resolve().parent
VECTOR_ROOT = ROOT / "vectors"
PACK = ROOT / "consumer-pack" / "release-manifest-v1.json"
EXAMPLE_REGISTRY = "registry.example.test"
PRODUCTION_REGISTRY = "registry.neural-ice.ch"
DNS_HOST_253 = ".".join(("a" * 63, "b" * 63, "c" * 63, "d" * 61))
DNS_HOST_254 = ".".join(("a" * 63, "b" * 63, "c" * 63, "d" * 62))

assert len(DNS_HOST_253) == MAX_DNS_HOST_LENGTH
assert len(DNS_HOST_254) == MAX_DNS_HOST_LENGTH + 1

DEVICE = DeviceCompatibility.create(
    "nvidia-dgx-spark-gb10",
    1,
    {"content-model-v1", "host-bootc-v1", "oci-component-v1"},
)


def digest(character: str) -> str:
    return "sha256:" + character * 64


def payload(repository: str, value: str, contract: str, unit: str) -> dict[str, Any]:
    return {
        "repository": repository,
        "digest": digest(value),
        "contract": contract,
        "restart_scope": [unit],
        "reboot_required": False,
        "required_entitlement": "ICE-CORE",
    }


def manifest(bundle_seq: int = 41, registry: str = EXAMPLE_REGISTRY) -> dict[str, Any]:
    return {
        "schema": "neural-ice-release-manifest-v1",
        "release_id": f"release-{bundle_seq}",
        "bundle_seq": bundle_seq,
        "hardware_target": "nvidia-dgx-spark-gb10",
        "compatibility": {
            "minimum_reader": 1,
            "required_contracts": [
                "content-model-v1",
                "host-bootc-v1",
                "oci-component-v1",
            ],
        },
        "host": payload(
            f"{registry}/neural-ice/neural-ice-appliance",
            "a",
            "host-bootc-v1",
            "bootc-fetch-apply-updates.service",
        ),
        "components": [
            {
                "component_id": "ice-ac1",
                **payload(
                    f"{registry}/neural-ice/ice-ac1",
                    "b",
                    "oci-component-v1",
                    "icecore-api.service",
                ),
            },
            {
                "component_id": "paddleocr-vl",
                **payload(
                    f"{registry}/vendor/paddleocr-vl-api",
                    "c",
                    "oci-component-v1",
                    "paddleocr-vl-api.service",
                ),
            },
        ],
        "content": [
            {
                "content_id": "gemma-4",
                "media_type": "application/vnd.neural-ice.model",
                **payload(
                    f"{registry}/neural-ice/model-gemma-4",
                    "d",
                    "content-model-v1",
                    "vllm-inference.service",
                ),
            }
        ],
        "evidence": [
            {"kind": "bom", "digest": digest("e")},
            {"kind": "attestation", "digest": digest("f")},
        ],
    }


def compact(value: Any) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode("utf-8")


def pretty_noncanonical(value: dict[str, Any]) -> bytes:
    changed = dict(reversed(list(copy.deepcopy(value).items())))
    changed["components"].reverse()
    changed["compatibility"]["required_contracts"].reverse()
    changed["evidence"].reverse()
    return (json.dumps(changed, indent=2) + "\n").encode("utf-8")


def sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def relative(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def generated_schema_bytes() -> bytes:
    path = ROOT / "release-manifest-v1.schema.json"
    text = path.read_text(encoding="utf-8")
    marker = '    "repository": {\n'
    prefix, separator, tail = text.partition(marker)
    if not separator:
        raise AssertionError("repository schema definition is missing")
    replaced, count = re.subn(
        r'^      "pattern": ".*",$',
        lambda _: '      "pattern": ' + json.dumps(REPOSITORY_PATTERN) + ",",
        tail,
        count=1,
        flags=re.MULTILINE,
    )
    if count != 1:
        raise AssertionError("repository schema pattern is missing or ambiguous")
    return (prefix + marker + replaced).encode("utf-8")


def build() -> tuple[dict[Path, bytes], dict[str, Any]]:
    outputs: dict[Path, bytes] = {}

    current = manifest()
    canonical = canonical_bytes(normalize(current, EXAMPLE_REGISTRY))
    production = canonical_bytes(
        normalize(manifest(registry=PRODUCTION_REGISTRY), PRODUCTION_REGISTRY)
    )

    parser_inputs: list[tuple[str, bytes, str, bool]] = [
        ("valid-example-canonical", canonical, EXAMPLE_REGISTRY, True),
        (
            "valid-example-noncanonical",
            pretty_noncanonical(current),
            EXAMPLE_REGISTRY,
            True,
        ),
        ("valid-production-host", production, PRODUCTION_REGISTRY, True),
        (
            "valid-registry-port",
            compact(manifest(registry="registry.example.test:5443")),
            "registry.example.test:5443",
            True,
        ),
        (
            "valid-bracketed-ipv6",
            compact(manifest(registry="[2001:db8::1]:5443")),
            "[2001:db8::1]:5443",
            True,
        ),
        (
            "valid-dns-host-253",
            compact(manifest(registry=DNS_HOST_253)),
            DNS_HOST_253,
            True,
        ),
        (
            "valid-dns-host-253-port",
            compact(manifest(registry=f"{DNS_HOST_253}:65535")),
            f"{DNS_HOST_253}:65535",
            True,
        ),
        (
            "valid-ipv4-mapped-ipv6-c000",
            compact(manifest(registry="[::ffff:c000:201]")),
            "[::ffff:c000:201]",
            True,
        ),
        (
            "valid-ipv4-mapped-ipv6-7f00",
            compact(manifest(registry="[::ffff:7f00:1]")),
            "[::ffff:7f00:1]",
            True,
        ),
        (
            "invalid-duplicate-key",
            b'{"schema":"neural-ice-release-manifest-v1","schema":"duplicate"}',
            EXAMPLE_REGISTRY,
            False,
        ),
        (
            "invalid-malformed-authority",
            compact(
                {
                    **current,
                    "host": {
                        **current["host"],
                        "repository": "https://registry.example.test/neural-ice/neural-ice-appliance",
                    },
                }
            ),
            EXAMPLE_REGISTRY,
            False,
        ),
        (
            "invalid-repository-namespace",
            compact(
                {
                    **current,
                    "host": {
                        **current["host"],
                        "repository": "registry.example.test/other/neural-ice-appliance",
                    },
                }
            ),
            EXAMPLE_REGISTRY,
            False,
        ),
        (
            "invalid-tagged-repository",
            compact(
                {
                    **current,
                    "host": {
                        **current["host"],
                        "repository": "registry.example.test/neural-ice/neural-ice-appliance:stable",
                    },
                }
            ),
            EXAMPLE_REGISTRY,
            False,
        ),
        (
            "invalid-uppercase-authority",
            compact(manifest(registry="Registry.example.test")),
            "Registry.example.test",
            False,
        ),
        (
            "invalid-zero-port",
            compact(manifest(registry="registry.example.test:0")),
            "registry.example.test:0",
            False,
        ),
        (
            "invalid-overflow-port",
            compact(manifest(registry="registry.example.test:65536")),
            "registry.example.test:65536",
            False,
        ),
        (
            "invalid-noncanonical-ipv6",
            compact(manifest(registry="[2001:0db8::1]")),
            "[2001:0db8::1]",
            False,
        ),
        (
            "invalid-ipv6-zone-id",
            compact(manifest(registry="[fe80::1%eth0]")),
            "[fe80::1%eth0]",
            False,
        ),
        (
            "invalid-ipv6-unicode-zone-id",
            compact(manifest(registry="[fe80::1%é]")),
            "[fe80::1%é]",
            False,
        ),
        (
            "invalid-uppercase-ipv6",
            compact(manifest(registry="[2001:DB8::1]")),
            "[2001:DB8::1]",
            False,
        ),
        (
            "invalid-expanded-ipv6-zero-run",
            compact(manifest(registry="[2001:db8:0:0:0:0:0:1]")),
            "[2001:db8:0:0:0:0:0:1]",
            False,
        ),
        (
            "invalid-noncanonical-ipv4",
            compact(manifest(registry="192.0.002.10")),
            "192.0.002.10",
            False,
        ),
        (
            "invalid-nonascii-dns",
            compact(manifest(registry="régistry.example.test")),
            "régistry.example.test",
            False,
        ),
        (
            "invalid-dns-host-254",
            compact(manifest(registry=DNS_HOST_254)),
            DNS_HOST_254,
            False,
        ),
        (
            "invalid-dns-trailing-dot",
            compact(manifest(registry="registry.example.test.")),
            "registry.example.test.",
            False,
        ),
        (
            "invalid-ipv4-mapped-ipv6-dotted",
            compact(manifest(registry="[::ffff:192.0.2.1]")),
            "[::ffff:192.0.2.1]",
            False,
        ),
    ]

    parser_vectors: list[dict[str, Any]] = []
    for identifier, data, registry, accepted in parser_inputs:
        input_path = VECTOR_ROOT / "parser" / f"{identifier}.json"
        outputs[input_path] = data
        record: dict[str, Any] = {
            "accepted": accepted,
            "configured_registry_authority": registry,
            "id": identifier,
            "input": relative(input_path),
            "input_sha256": sha256(data),
        }
        try:
            parsed = parse(data, registry)
        except ContractRefusal as error:
            if accepted:
                raise
            record["refusal_reason"] = str(error)
        else:
            if not accepted:
                raise AssertionError(f"negative parser vector accepted: {identifier}")
            canonical_path = VECTOR_ROOT / "canonical" / f"{identifier}.json"
            outputs[canonical_path] = parsed.canonical_bytes
            record.update(
                {
                    "canonical": relative(canonical_path),
                    "canonical_sha256": parsed.digest,
                }
            )
        parser_vectors.append(record)

    current_path = VECTOR_ROOT / "planner" / "current-example.json"
    outputs[current_path] = canonical
    candidates: dict[str, dict[str, Any]] = {}

    no_op = manifest(42)
    candidates["candidate-no-op"] = no_op
    component = copy.deepcopy(no_op)
    component["components"][0]["digest"] = digest("1")
    candidates["candidate-component"] = component
    host = copy.deepcopy(no_op)
    host["host"]["digest"] = digest("2")
    candidates["candidate-host"] = host
    mixed = copy.deepcopy(no_op)
    mixed["components"][0]["repository"] = "foreign.example.test/neural-ice/ice-ac1"
    candidates["candidate-mixed-host"] = mixed
    current_mixed = copy.deepcopy(current)
    current_mixed["content"][0]["repository"] = (
        "foreign.example.test/neural-ice/model-gemma-4"
    )
    candidates["current-mixed-host"] = current_mixed

    candidate_paths: dict[str, Path] = {}
    for identifier, value in candidates.items():
        path = VECTOR_ROOT / "planner" / f"{identifier}.json"
        outputs[path] = compact(value)
        candidate_paths[identifier] = path

    production_path = VECTOR_ROOT / "planner" / "production-host.json"
    outputs[production_path] = production

    configured_specs = [
        (
            "example-no-op",
            current_path,
            candidate_paths["candidate-no-op"],
            EXAMPLE_REGISTRY,
        ),
        (
            "example-component",
            current_path,
            candidate_paths["candidate-component"],
            EXAMPLE_REGISTRY,
        ),
        (
            "example-host",
            current_path,
            candidate_paths["candidate-host"],
            EXAMPLE_REGISTRY,
        ),
        ("missing-config", current_path, candidate_paths["candidate-no-op"], None),
        (
            "malformed-config",
            current_path,
            candidate_paths["candidate-no-op"],
            "https://registry.example.test",
        ),
        (
            "mismatched-config",
            current_path,
            candidate_paths["candidate-no-op"],
            "foreign.example.test",
        ),
        (
            "candidate-mixed-host",
            current_path,
            candidate_paths["candidate-mixed-host"],
            EXAMPLE_REGISTRY,
        ),
        (
            "current-mixed-host",
            candidate_paths["current-mixed-host"],
            candidate_paths["candidate-no-op"],
            EXAMPLE_REGISTRY,
        ),
        (
            "production-host-compatibility",
            production_path,
            production_path,
            PRODUCTION_REGISTRY,
        ),
    ]

    configured_cases: list[dict[str, Any]] = []
    for identifier, current_file, candidate_file, registry in configured_specs:
        current_bytes = outputs[current_file]
        candidate_bytes = outputs[candidate_file]
        plan = classify(current_bytes, candidate_bytes, DEVICE, registry)  # type: ignore[arg-type]
        configured_cases.append(
            {
                "candidate": relative(candidate_file),
                "candidate_sha256": sha256(candidate_bytes),
                "configured_registry_authority": registry,
                "current": relative(current_file),
                "current_sha256": sha256(current_bytes),
                "expected_plan": plan.as_dict(),
                "id": identifier,
            }
        )

    equivalence_authorities = (
        ("dns", "registry.example.test", True),
        ("single-label-dns", "localhost", True),
        ("dns-port-min", "registry.example.test:1", True),
        ("dns-port-max", "registry.example.test:65535", True),
        ("dns-host-253", DNS_HOST_253, True),
        ("dns-host-253-port", f"{DNS_HOST_253}:65535", True),
        ("dns-host-254", DNS_HOST_254, False),
        ("dns-trailing-dot", "registry.example.test.", False),
        ("ipv4", "192.0.2.10", True),
        ("ipv4-port", "192.0.2.10:5443", True),
        ("ipv6-compressed", "[2001:db8::1]", True),
        ("ipv6-all-zero", "[::]", True),
        ("ipv6-no-zero", "[1:2:3:4:5:6:7:8]", True),
        ("ipv6-port", "[2001:db8::1]:5443", True),
        ("ipv4-mapped-ipv6-c000", "[::ffff:c000:201]", True),
        ("ipv4-mapped-ipv6-7f00", "[::ffff:7f00:1]", True),
        ("ipv4-mapped-ipv6-dotted", "[::ffff:192.0.2.1]", False),
        ("empty", "", False),
        ("scheme", "https://registry.example.test", False),
        ("userinfo", "user@registry.example.test", False),
        ("uppercase-dns", "Registry.example.test", False),
        ("nonascii-dns", "régistry.example.test", False),
        ("leading-hyphen", "-registry.example.test", False),
        ("trailing-hyphen", "registry-.example.test", False),
        ("port-zero", "registry.example.test:0", False),
        ("port-leading-zero", "registry.example.test:0001", False),
        ("port-overflow", "registry.example.test:65536", False),
        ("ipv4-leading-zero", "192.0.002.10", False),
        ("ipv4-overflow", "192.0.2.999", False),
        ("ipv6-unbracketed", "2001:db8::1", False),
        ("ipv6-zone", "[fe80::1%eth0]", False),
        ("ipv6-unicode-zone", "[fe80::1%é]", False),
        ("ipv6-uppercase", "[2001:DB8::1]", False),
        ("ipv6-leading-zero", "[2001:0db8::1]", False),
        ("ipv6-expanded-zero-run", "[2001:db8:0:0:0:0:0:1]", False),
        ("ipv6-compress-shorter-run", "[2001::1:0:0:0:1]", False),
        ("ipv6-compress-later-tie", "[2001:0:0:1::2:3]", False),
    )
    equivalence_vectors = [
        {
            "accepted": accepted,
            "configured_registry_authority": authority,
            "id": identifier,
            "repository": f"{authority}/neural-ice/equivalence"
            if authority
            else "/neural-ice/equivalence",
        }
        for identifier, authority, accepted in equivalence_authorities
    ]

    schema_bytes = generated_schema_bytes()
    outputs[ROOT / "release-manifest-v1.schema.json"] = schema_bytes
    pack = {
        "configured_host_cases": configured_cases,
        "format": "neural-ice-release-manifest-v1-consumer-pack",
        "format_version": 1,
        "path_base": "..",
        "parser_vectors": parser_vectors,
        "repository_grammar": {
            "dns_host_max_ascii_characters": MAX_DNS_HOST_LENGTH,
            "equivalence_vectors": equivalence_vectors,
            "ipv4_mapped_ipv6_text": "lowercase-compressed-hexadecimal-hextets",
            "parser_symbol": "contract.REPOSITORY_PATTERN",
            "pattern_sha256": sha256(REPOSITORY_PATTERN.encode("ascii")),
            "schema_pointer": "#/$defs/repository/pattern",
        },
        "schema": "release-manifest-v1.schema.json",
        "schema_sha256": sha256(schema_bytes),
    }
    outputs[PACK] = (json.dumps(pack, indent=2, sort_keys=True) + "\n").encode()
    return outputs, pack


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    outputs, _ = build()
    stale: list[str] = []
    for path, expected in sorted(outputs.items()):
        if args.check:
            if not path.is_file() or path.read_bytes() != expected:
                stale.append(relative(path))
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(expected)
    if args.check:
        actual = set(VECTOR_ROOT.rglob("*.json"))
        actual.update((ROOT / "consumer-pack").glob("*.json"))
        stale.extend(
            f"unexpected:{relative(path)}" for path in sorted(actual - outputs.keys())
        )
    if stale:
        parser.error("generated consumer pack is stale: " + ", ".join(stale))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
