#!/usr/bin/env python3
"""Composition boundaries; crypto acceptance is exercised by the native verifier."""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

IMAGE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("preloaded_inputs", IMAGE / "lib/preloaded-inputs.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class Inputs(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ni-preloaded-input-test-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.digest = "sha256:" + "a" * 64
        self.repository = "registry.example.test/neural-ice/appliance"
        self.subject = {"repository": self.repository, "digest": self.digest}
        self.closure = {"host_digest": self.digest, "artifacts": [{"artifact_key": "os:neural-ice-appliance", "root": self.subject}]}
        self.args = argparse.Namespace(
            authorization=self.root / "auth.json", closure=self.root / "closure.json",
            manifest=self.root / "manifest.json", profiles=self.root / "profiles.json",
            catalogue=self.root / "catalogue.json", root_pubkey=self.root / "root.pub",
            base_image="ghcr.io/neural-ice/appliance@" + self.digest,
            target_image=self.repository + "@" + self.digest,
        )
        self.args.closure.write_text(json.dumps(self.closure))
        for path in (self.args.manifest, self.args.profiles, self.args.catalogue):
            path.write_text("{}\n")
        self.args.root_pubkey.write_text("fixture public root")
        self.auth = {
            "schema": "neural-ice-ota-release-authorization-v2", "purpose": "ota", "installer_medium": None,
            "subject": self.subject, "host_digest": self.digest,
            "release_closure_sha256": hashlib.sha256(self.args.closure.read_bytes()).hexdigest(),
            "release_manifest_sha256": hashlib.sha256(self.args.manifest.read_bytes()).hexdigest(),
        }
        self.save()

    def save(self):
        self.args.authorization.write_text(json.dumps(self.auth))

    def test_firstboot_import_has_a_bounded_full_payload_budget(self):
        import configparser
        unit = configparser.ConfigParser(strict=False)
        unit.read(IMAGE / "firstboot/neural-ice-seed-import.service")
        # Qualification still measures actual duration; this prevents default-90s
        # termination of the bulk importer while keeping a finite upper bound.
        self.assertEqual(unit["Service"]["TimeoutStartSec"], "2h")

    def test_same_digest_across_transports(self):
        MODULE.bind(self.args)

    def test_different_host_or_origin_refused(self):
        for field, value in (
            ("base_image", self.args.base_image[:-1] + "b"),
            ("target_image", self.args.base_image),
            ("target_image", self.args.target_image[:-1] + "b"),
        ):
            with self.subTest(field=field, value=value):
                args = argparse.Namespace(**vars(self.args))
                setattr(args, field, value)
                with self.assertRaisesRegex(ValueError, "authorized closure host"):
                    MODULE.bind(args)

    def test_installer_authority_cannot_substitute(self):
        for field, value in (("purpose", "install"), ("installer_medium", {})):
            self.auth[field] = value
            self.save()
            with self.assertRaisesRegex(ValueError, "OTA-v2"):
                MODULE.bind(self.args)
            self.auth[field] = "ota" if field == "purpose" else None

    def test_manifest_and_closure_bytes_bound(self):
        for path in (self.args.manifest, self.args.closure):
            original = path.read_bytes()
            path.write_bytes(original + b"\n")
            with self.assertRaisesRegex(ValueError, "exact input bytes"):
                MODULE.bind(self.args)
            path.write_bytes(original)

    def test_baked_inputs_and_cleanup_after_mismatch(self):
        for mismatch in (None, "model-profiles.json", "catalogue.json", "ota-root.pub"):
            removed = []

            def create(command, **kwargs):
                self.assertEqual(command, ["podman", "create", "--pull=never", "--network=none", "--entrypoint=/bin/true", self.args.base_image])
                return "c" * 64 + "\n"

            def run(command, **kwargs):
                if command[:2] == ["podman", "rm"]:
                    removed.append(command[2])
                else:
                    self.assertEqual(command[:2], ["podman", "cp"])
                    source = command[2]
                    content = b"fixture public root" if source.endswith("ota-root.pub") else b"{}\n"
                    Path(command[3]).write_bytes(b"wrong" if mismatch and source.endswith(mismatch) else content)
                return subprocess.CompletedProcess(command, 0)

            with self.subTest(mismatch=mismatch), patch.object(MODULE.subprocess, "check_output", create), patch.object(MODULE.subprocess, "run", run):
                if mismatch:
                    with self.assertRaisesRegex(ValueError, "differs from the pinned appliance"):
                        MODULE.baked_inputs(self.args)
                else:
                    MODULE.baked_inputs(self.args)
                self.assertEqual(removed, ["c" * 64])

    def test_wrapper_routes_distinct_authorizations(self):
        # Execute the real wrapper through its two child producer interfaces.
        # Stand-ins deliberately do not assert crypto validity or build a raw.
        repo = self.root / "repo"
        (repo / "image/lib").mkdir(parents=True)
        shutil.copy(IMAGE / "build-preloaded.sh", repo / "image")
        for name in ("preloaded-sizing.sh", "preloaded-output-set.sh"):
            shutil.copy(IMAGE / "lib" / name, repo / "image/lib")
        (repo / "VERSION").write_text("0.60.1\n")
        (repo / "image/lib/preloaded-inputs.py").write_text("# Input-binding behavior is tested separately above.\n")
        seed = repo / "image/build-seed-v2.sh"
        seed.write_text('''#!/usr/bin/env python3
import os,sys,pathlib
a=sys.argv[1:]
def arg(name): return a[a.index(name)+1]
assert arg('--authorization')==os.environ['SEED_RELEASE_AUTHORIZATION_FILE']
assert arg('--authorization-sig')==os.environ['SEED_RELEASE_AUTHORIZATION_SIGNATURE_FILE']
assert arg('--authorization')!=os.environ['RELEASE_AUTHORIZATION_FILE']
root=pathlib.Path(arg('--output'))/'seed'/('a'*64)
root.mkdir(parents=True); (root/'READY').touch()
print('release_closure_sha256='+'a'*64)
''')
        installer = repo / "image/build-installer-usb.sh"
        installer.write_text('''#!/usr/bin/env python3
import os,sys
assert os.environ['RELEASE_AUTHORIZATION_FILE'].endswith('/installer.json')
assert os.environ['RELEASE_AUTHORIZATION_SIGNATURE_FILE'].endswith('/installer.sig')
print('installer-domain-reached')
sys.exit(73)
''')
        seed.chmod(0o755)
        installer.chmod(0o755)
        import os
        env = dict(os.environ)
        for name in ("RELEASE_MANIFEST_FILE RELEASE_CLOSURE_FILE DELEGATION_SNAPSHOT_FILE DELEGATION_SNAPSHOT_SIGNATURE_FILE RELEASE_ROOT_PUBLIC_KEY_FILE SEED_OBJECT_ROOTS SEED_TRUSTED_NOW RELEASE_AUTHORITY HARDWARE_TARGET ACCESS_PROFILE TRUST_POLICY_ID PCR_POLICY_DIGEST PCR_POLICY_PUBLIC_KEY_FILE PCR_POLICY_PUBLIC_KEY_SHA256 PCR_POLICY_SIGNATURE_FILE PCR_POLICY_SIGNATURE_SHA256 PCR_POLICY_SEQ SEED_HF_CACHE SEED_MODEL_PROFILES SEED_MODEL_CATALOGUE").split():
            env[name] = "fixture"
        env.update(BASE_IMAGE=self.args.base_image, TARGET_IMGREF=self.args.target_image, NI_OTA_VERIFY="/bin/true", OUT="fixture", COMPRESS="none",
                   SEED_RELEASE_AUTHORIZATION_FILE=str(self.args.authorization), SEED_RELEASE_AUTHORIZATION_SIGNATURE_FILE=str(self.root / "seed.sig"),
                   RELEASE_AUTHORIZATION_FILE=str(self.root / "installer.json"), RELEASE_AUTHORIZATION_SIGNATURE_FILE=str(self.root / "installer.sig"))
        result = subprocess.run(["bash", str(repo / "image/build-preloaded.sh")], env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 73, result.stderr)
        self.assertIn("installer-domain-reached", result.stdout)


if __name__ == "__main__":
    unittest.main()
