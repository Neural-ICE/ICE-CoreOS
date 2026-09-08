#!/usr/bin/env python3

import hashlib
import importlib.util
import json
import os
import pathlib
import tempfile
import types
import unittest
from unittest import mock

MODULE_PATH = pathlib.Path(__file__).with_name("content-cache-contract.py")
SPEC = importlib.util.spec_from_file_location("content_cache_contract", MODULE_PATH)
contract = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(contract)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


class Fixture:
    def __init__(self, root, registry="registry.example.test"):
        self.root = pathlib.Path(root)
        self.registry = registry
        self.objects = self.root / "objects"
        self.objects.mkdir(parents=True)
        self.artifacts = []
        self.entries = []
        self.payloads = {}
        self.add("ch-caselaw-seed", b"sqlite-fixture")
        self.add("paddlex-cache", b"paddlex-fixture")
        self.write_documents()

    def put(self, body):
        digest = hashlib.sha256(body).hexdigest()
        (self.objects / digest).write_bytes(body)
        return digest

    def add(self, content_id, body):
        profile = contract.PROFILES[content_id]
        repository = f"{self.registry}/{profile['repository_path']}"
        segment_digest = self.put(body)
        config = {
            "content_id": content_id,
            "format": profile["format"],
            "schema": contract.SCHEMA,
            "segments": [{"digest": "sha256:" + segment_digest, "size": len(body)}],
            "sha256": segment_digest,
            "size_bytes": len(body),
        }
        config_body = canonical(config)
        config_digest = self.put(config_body)
        manifest = {
            "artifactType": contract.ARTIFACT_TYPE,
            "config": {
                "digest": "sha256:" + config_digest,
                "mediaType": contract.CONFIG_MEDIA_TYPE,
                "size": len(config_body),
            },
            "layers": [
                {
                    "digest": "sha256:" + segment_digest,
                    "mediaType": contract.SEGMENT_MEDIA_TYPE,
                    "size": len(body),
                }
            ],
            "mediaType": contract.OCI_MANIFEST,
            "schemaVersion": 2,
        }
        root_digest = self.put(canonical(manifest))
        self.entries.append(
            {
                "content_id": content_id,
                "contract": "content-cache-v1",
                "digest": "sha256:" + root_digest,
                "media_type": contract.ARTIFACT_TYPE,
                "reboot_required": False,
                "repository": repository,
                "required_entitlement": profile["entitlement"],
                "restart_scope": [],
            }
        )
        self.artifacts.append(
            {
                "artifact_class": "oci-artifact",
                "artifact_key": "content:" + content_id,
                "attachments": [],
                "candidate_repository": profile["candidate_repository"],
                "nodes": [
                    {"digest": "sha256:" + root_digest, "kind": "manifest"},
                    {"digest": "sha256:" + config_digest, "kind": "config"},
                    {"digest": "sha256:" + segment_digest, "kind": "layer"},
                ],
                "repository": repository,
                "required_entitlement": profile["entitlement"],
                "root": {
                    "digest": "sha256:" + root_digest,
                    "repository": repository,
                },
            }
        )
        self.payloads[content_id] = body

    def write_documents(self):
        self.closure = self.root / "release-closure.json"
        self.manifest = self.root / "release-manifest.json"
        self.closure.write_bytes(canonical({"artifacts": self.artifacts}) + b"\n")
        self.manifest.write_bytes(
            canonical(
                {
                    "compatibility": {
                        "minimum_reader": 1,
                        "required_contracts": ["content-cache-v1"],
                    },
                    "content": self.entries,
                }
            )
            + b"\n"
        )


class ContentCacheContractTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(
            prefix="ni-content-cache-contract-"
        )
        self.root = pathlib.Path(self.temporary.name)
        self.fixture = Fixture(self.root)

    def tearDown(self):
        self.temporary.cleanup()

    def args(self, destination=None):
        return types.SimpleNamespace(
            closure=str(self.fixture.closure),
            manifest=str(self.fixture.manifest),
            objects=str(self.fixture.objects),
            destination=str(destination or self.root / "candidate"),
            registry_host=self.fixture.registry,
        )

    def test_materializes_both_fixed_whole_files_and_exact_metadata(self):
        destination = self.root / "candidate"
        contract.materialize(self.args(destination))
        for content_id, body in self.fixture.payloads.items():
            profile = contract.PROFILES[content_id]
            self.assertEqual(
                (destination / content_id / profile["filename"]).read_bytes(), body
            )
            proof = (destination / ".metadata" / f"{content_id}.json").read_bytes()
            self.assertFalse(proof.endswith(b"\n"))
            self.assertEqual(
                hashlib.sha256(body).hexdigest(), json.loads(proof)["sha256"]
            )

    def test_refuses_wrong_manifest_media_entitlement_and_missing_fixed_id(self):
        mutations = (
            lambda entry: entry.__setitem__("media_type", "application/octet-stream"),
            lambda entry: entry.__setitem__("required_entitlement", "ICE-CORE"),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                fixture = Fixture(
                    self.root / ("case-" + str(len(list(self.root.iterdir()))))
                )
                mutation(fixture.entries[0])
                fixture.write_documents()
                with self.assertRaises(SystemExit):
                    contract.collect_specs(
                        fixture.closure,
                        fixture.manifest,
                        fixture.objects,
                        fixture.registry,
                    )
        self.fixture.entries.pop()
        self.fixture.write_documents()
        with self.assertRaises(SystemExit):
            contract.collect_specs(
                self.fixture.closure,
                self.fixture.manifest,
                self.fixture.objects,
                self.fixture.registry,
            )

        unsupported = Fixture(self.root / "unsupported-class")
        unsupported.artifacts[0]["artifact_class"] = "chunked-content-artifact"
        unsupported.write_documents()
        with self.assertRaises(SystemExit):
            contract.collect_specs(
                unsupported.closure,
                unsupported.manifest,
                unsupported.objects,
                unsupported.registry,
            )

    def test_registry_authority_is_canonical_and_binds_both_fixed_repositories(self):
        for authority in (
            "registry.example.test",
            "localhost:5055",
            "192.0.2.1:5000",
            "[2001:db8::1]:5000",
        ):
            with self.subTest(authority=authority):
                self.assertTrue(contract.valid_registry_authority(authority))
        for authority in (
            "https://registry.example.test",
            "Registry.example.test",
            "registry.example.test/extra",
            "registry.example.test:05055",
            "[2001:0db8::1]",
            "[fe80::1%eth0]",
        ):
            with self.subTest(authority=authority):
                self.assertFalse(contract.valid_registry_authority(authority))
        alternate = Fixture(self.root / "alternate", "other.example.test")
        self.assertEqual(
            len(
                contract.collect_specs(
                    alternate.closure,
                    alternate.manifest,
                    alternate.objects,
                    alternate.registry,
                )
            ),
            2,
        )
        with self.assertRaises(SystemExit):
            contract.collect_specs(
                self.fixture.closure,
                self.fixture.manifest,
                self.fixture.objects,
                "other.example.test",
            )

    def test_registry_authority_matches_pinned_producer_vectors(self):
        pack = json.loads(
            (
                MODULE_PATH.parent.parent
                / "tools/ni-ota-verify/tests/fixtures/release-manifest-v1/producer/consumer-pack/release-manifest-v1.json"
            ).read_bytes()
        )
        for vector in pack["repository_grammar"]["equivalence_vectors"]:
            authority = vector["repository"].split("/", 1)[0]
            with self.subTest(vector=vector["id"]):
                self.assertEqual(
                    contract.valid_registry_authority(authority), vector["accepted"]
                )

    def test_refuses_segment_order_size_digest_corruption_and_symlink(self):
        entry = self.fixture.entries[0]
        root_digest = entry["digest"][7:]
        manifest = json.loads((self.fixture.objects / root_digest).read_bytes())
        manifest["layers"][0]["size"] += 1
        wrong_manifest_digest = self.fixture.put(canonical(manifest))
        entry["digest"] = "sha256:" + wrong_manifest_digest
        self.fixture.artifacts[0]["root"]["digest"] = entry["digest"]
        self.fixture.write_documents()
        with self.assertRaises(SystemExit):
            contract.collect_specs(
                self.fixture.closure,
                self.fixture.manifest,
                self.fixture.objects,
                self.fixture.registry,
            )

        order = Fixture(self.root / "order")
        entry = order.entries[0]
        manifest = json.loads((order.objects / entry["digest"][7:]).read_bytes())
        config_path = order.objects / manifest["config"]["digest"][7:]
        config = json.loads(config_path.read_bytes())
        original = config["segments"][0]
        synthetic = {"digest": "sha256:" + "a" * 64, "size": contract.MAX_SEGMENT_BYTES}
        config["segments"] = [synthetic, original]
        config["size_bytes"] = contract.MAX_SEGMENT_BYTES + original["size"]
        config["sha256"] = "b" * 64
        config_body = canonical(config)
        config_digest = order.put(config_body)
        manifest["config"] = {
            "digest": "sha256:" + config_digest,
            "mediaType": contract.CONFIG_MEDIA_TYPE,
            "size": len(config_body),
        }
        # Reverse the layer order relative to the authenticated segment array.
        manifest["layers"] = [
            manifest["layers"][0],
            {
                "digest": synthetic["digest"],
                "mediaType": contract.SEGMENT_MEDIA_TYPE,
                "size": synthetic["size"],
            },
        ]
        root_digest = order.put(canonical(manifest))
        entry["digest"] = "sha256:" + root_digest
        order.artifacts[0]["root"]["digest"] = entry["digest"]
        order.write_documents()
        with self.assertRaises(SystemExit):
            contract.collect_specs(
                order.closure, order.manifest, order.objects, order.registry
            )

        corrupt = Fixture(self.root / "corrupt")
        segment_digest = next(
            node["digest"][7:]
            for node in corrupt.artifacts[0]["nodes"]
            if node["kind"] == "layer"
        )
        (corrupt.objects / segment_digest).write_bytes(b"same-length-bad")
        with self.assertRaises(SystemExit):
            contract.materialize(
                types.SimpleNamespace(
                    closure=str(corrupt.closure),
                    manifest=str(corrupt.manifest),
                    objects=str(corrupt.objects),
                    destination=str(corrupt.root / "candidate"),
                    registry_host=corrupt.registry,
                )
            )

        linked = Fixture(self.root / "linked")
        segment_digest = next(
            node["digest"][7:]
            for node in linked.artifacts[0]["nodes"]
            if node["kind"] == "layer"
        )
        segment = linked.objects / segment_digest
        outside = linked.root / "outside"
        outside.write_bytes(segment.read_bytes())
        segment.unlink()
        segment.symlink_to(outside)
        with self.assertRaises(SystemExit):
            contract.materialize(
                types.SimpleNamespace(
                    closure=str(linked.closure),
                    manifest=str(linked.manifest),
                    objects=str(linked.objects),
                    destination=str(linked.root / "candidate"),
                    registry_host=linked.registry,
                )
            )

    def test_refuses_capacity_before_creating_candidate(self):
        unavailable = types.SimpleNamespace(f_bavail=0, f_frsize=4096)
        with mock.patch.object(contract.os, "statvfs", return_value=unavailable):
            with self.assertRaises(SystemExit):
                contract.materialize(self.args())
        self.assertFalse((self.root / "candidate").exists())

    def test_fabric_fixture_materializes_through_the_core_helper_when_available(self):
        configured = os.environ.get("NEURAL_ICE_CONTENT_CACHE_FIXTURE")
        if configured:
            source = pathlib.Path(configured)
        elif root := os.environ.get("NEURAL_ICE_FABRIC_ROOT"):
            source = pathlib.Path(root) / "release-manifest/fixtures/content-cache-v1"
        else:
            self.skipTest("Fabric content-cache fixture path was not configured")
        if not (source / "manifest.json").is_file():
            self.skipTest(f"Fabric content-cache fixture is absent at {source}")
        config_body = (source / "config.json").read_bytes()
        manifest_body = (source / "manifest.json").read_bytes()
        segment_body = (source / "segment.bin").read_bytes()
        config_digest = self.fixture.put(config_body)
        manifest_digest = self.fixture.put(manifest_body)
        segment_digest = self.fixture.put(segment_body)
        self.assertEqual(
            json.loads(manifest_body)["config"]["digest"], "sha256:" + config_digest
        )
        self.assertEqual(
            json.loads(config_body)["segments"][0]["digest"], "sha256:" + segment_digest
        )
        entry = next(
            item
            for item in self.fixture.entries
            if item["content_id"] == "ch-caselaw-seed"
        )
        entry["digest"] = "sha256:" + manifest_digest
        artifact = next(
            item
            for item in self.fixture.artifacts
            if item["artifact_key"] == "content:ch-caselaw-seed"
        )
        artifact["root"]["digest"] = entry["digest"]
        artifact["nodes"] = [
            {"digest": entry["digest"], "kind": "manifest"},
            {"digest": "sha256:" + config_digest, "kind": "config"},
            {"digest": "sha256:" + segment_digest, "kind": "layer"},
        ]
        self.fixture.payloads["ch-caselaw-seed"] = segment_body
        self.fixture.write_documents()
        destination = self.root / "fabric-candidate"
        contract.materialize(self.args(destination))
        self.assertEqual(
            (destination / "ch-caselaw-seed" / "decisions.db").read_bytes(),
            segment_body,
        )

    def test_interrupted_write_never_changes_retained_generation(self):
        retained = self.root / "offline-current"
        retained.write_bytes(b"retained-generation")
        with mock.patch.object(
            contract.os, "write", side_effect=OSError("injected interruption")
        ):
            with self.assertRaises(OSError):
                contract.materialize(self.args())
        self.assertEqual(retained.read_bytes(), b"retained-generation")


if __name__ == "__main__":
    unittest.main()
