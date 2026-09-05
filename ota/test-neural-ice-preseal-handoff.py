#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "preseal_handoff", HERE / "neural-ice-preseal-handoff.py"
)
assert SPEC and SPEC.loader
handoff = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(handoff)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class HandoffTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.auth = self.root / "release-authorization.json"
        self.sig = self.root / "release-authorization.sig"
        self.auth.write_bytes(b'{"schema":"installer-v2"}\n')
        self.sig.write_bytes(b"synthetic detached signature\n")
        bodies = {
            "delegation-snapshot.json": b'{"snapshot":"synthetic"}\n',
            "delegation-snapshot.sig": b"snapshot signature\n",
            "ota-release-authorization.json": b'{"authorization":"synthetic"}\n',
            "ota-release-authorization.sig": b"authorization signature\n",
            "bom.json": b'{"bom":"synthetic"}\n',
        }
        for name, body in bodies.items():
            (self.source / name).write_bytes(body)
        self.document = {
            "access_policy_sha256": "1" * 64,
            "access_profile": "lab-managed",
            "attestation_set_sha256": "2" * 64,
            "bom_file_sha256": sha(bodies["bom.json"]),
            "bom_sha256": "3" * 64,
            "bundle_seq": 7,
            "channel_record_sha256": "4" * 64,
            "compat_max": 9,
            "compat_min": 3,
            "delegation_seq": 2,
            "delegation_snapshot_file_sha256": sha(bodies["delegation-snapshot.json"]),
            "delegation_snapshot_sha256": "3378808da1841f89db7dcc125fa1c7025662e9b3c099cf8f67a69c5f7341dad0",
            "delegation_snapshot_signature_sha256": sha(
                bodies["delegation-snapshot.sig"]
            ),
            "hardware_target": "nvidia-gb10-arm64",
            "installer_authorization_sha256": sha(self.auth.read_bytes()),
            "installer_authorization_signature_sha256": sha(self.sig.read_bytes()),
            "ota_release_authorization_file_sha256": sha(
                bodies["ota-release-authorization.json"]
            ),
            "ota_release_authorization_sha256": "5" * 64,
            "ota_release_authorization_signature_sha256": sha(
                bodies["ota-release-authorization.sig"]
            ),
            "ota_state_profile": "owner-sealed-ota-state-v1",
            "release_key_id": "release-lab-v1",
            "release_signing_role": "release-lab",
            "ring": "lab",
            "schema": "neural-ice-installer-preseal-set-v1",
            "seed_ref": "6" * 40,
            "signed_boot_trust_policy_id": "neural-ice-secureboot-lab-v1",
            "target_os_ref": "release.example.test/neural-ice/neural-ice-appliance@sha256:"
            + "7" * 64,
            "train": "lab-20260905",
            "variant": "sealed-lab",
        }
        self.write_set()

    def tearDown(self):
        self.temp.cleanup()

    def write_set(self):
        raw = (
            json.dumps(self.document, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode()
        (self.source / "preseal-set.json").write_bytes(raw)
        self.expected = sha(raw)

    def load(self):
        return handoff.load(self.source, self.expected, self.auth, self.sig)

    def snapshot_persistent(self, destination: Path):
        subprocess.run(
            [
                str(HERE / "neural-ice-preseal-handoff.py"),
                "snapshot-persistent",
                str(self.source),
                self.expected,
                str(self.auth),
                str(self.sig),
                str(destination),
            ],
            check=True,
        )

    def test_snapshot_media_install_and_exact_retry(self):
        snapshot = self.root / "snapshot"
        command = [
            str(HERE / "neural-ice-preseal-handoff.py"),
            "snapshot",
            str(self.source),
            self.expected,
            str(self.auth),
            str(self.sig),
            str(snapshot),
        ]
        subprocess.run(command, check=True)
        subprocess.run(command, check=True)
        self.assertEqual(stat.S_IMODE(snapshot.stat().st_mode), 0o700)
        self.assertTrue(
            all(
                stat.S_IMODE(path.stat().st_mode) == 0o600
                for path in snapshot.iterdir()
            )
        )
        media = self.root / "media"
        subprocess.run(
            [
                str(HERE / "neural-ice-preseal-handoff.py"),
                "install",
                str(snapshot),
                self.expected,
                str(self.auth),
                str(self.sig),
                str(media),
                "--mode",
                "media",
            ],
            check=True,
        )
        subprocess.run(
            [
                str(HERE / "neural-ice-preseal-handoff.py"),
                "verify",
                str(media),
                self.expected,
                str(self.auth),
                str(self.sig),
            ],
            check=True,
        )
        self.assertEqual(stat.S_IMODE(media.stat().st_mode), 0o755)
        self.assertTrue(
            all(stat.S_IMODE(path.stat().st_mode) == 0o444 for path in media.iterdir())
        )

    def test_each_bound_file_drift_is_refused(self):
        for field, name in handoff.FILE_HASHES.items():
            with self.subTest(field=field):
                original = (self.source / name).read_bytes()
                (self.source / name).write_bytes(original + b"x")
                with self.assertRaisesRegex(handoff.Refusal, f"bind {name}"):
                    self.load()
                (self.source / name).write_bytes(original)

    def test_authorization_pair_drift_is_refused(self):
        self.auth.write_bytes(b"other\n")
        with self.assertRaisesRegex(handoff.Refusal, "authorization bytes"):
            self.load()

    def test_partial_unknown_and_symlink_sets_are_refused(self):
        (self.source / "bom.json").unlink()
        with self.assertRaisesRegex(handoff.Refusal, "exactly the six"):
            self.load()
        (self.source / "bom.json").write_bytes(b'{"bom":"synthetic"}\n')
        (self.source / "unexpected").write_bytes(b"x")
        with self.assertRaisesRegex(handoff.Refusal, "exactly the six"):
            self.load()
        (self.source / "unexpected").unlink()
        target = self.source / "bom.json"
        target.unlink()
        target.symlink_to(self.auth)
        with self.assertRaisesRegex(handoff.Refusal, "cannot open regular"):
            self.load()

    def test_fifo_is_refused_without_blocking(self):
        path = self.source / "delegation-snapshot.sig"
        path.unlink()
        os.mkfifo(path)
        with self.assertRaisesRegex(handoff.Refusal, "regular file"):
            self.load()

    def test_every_rust_consumer_size_bound_is_enforced(self):
        self.assertEqual(
            handoff.FILES,
            {
                "preseal-set.json": 16 * 1024,
                "delegation-snapshot.json": 16 * 1024,
                "delegation-snapshot.sig": 1024,
                "ota-release-authorization.json": 64 * 1024,
                "ota-release-authorization.sig": 1024,
                "bom.json": 128 * 1024,
            },
        )
        bounded = [(self.source / name, limit) for name, limit in handoff.FILES.items()]
        bounded.extend(((self.auth, 1024), (self.sig, 4 * 1024)))
        for path, limit in bounded:
            with self.subTest(path=path.name, limit=limit):
                original = path.read_bytes()
                path.write_bytes(b"x" * (limit + 1))
                with self.assertRaisesRegex(handoff.Refusal, f"at most {limit}"):
                    self.load()
                path.write_bytes(original)

    def test_noncanonical_duplicate_and_wrong_profile_are_refused(self):
        raw = (self.source / "preseal-set.json").read_bytes()
        (self.source / "preseal-set.json").write_bytes(raw.rstrip(b"\n"))
        with self.assertRaisesRegex(handoff.Refusal, "canonical"):
            handoff.load(self.source, sha(raw.rstrip(b"\n")), self.auth, self.sig)
        self.write_set()
        raw = (self.source / "preseal-set.json").read_text()
        (self.source / "preseal-set.json").write_text(
            raw.replace(
                '{"access_policy_sha256":',
                '{"access_profile":"lab-managed","access_policy_sha256":',
            )
        )
        with self.assertRaisesRegex(handoff.Refusal, "duplicate JSON field"):
            handoff.load(
                self.source,
                sha((self.source / "preseal-set.json").read_bytes()),
                self.auth,
                self.sig,
            )
        self.document["unexpected"] = "field"
        self.write_set()
        with self.assertRaisesRegex(handoff.Refusal, "closed field set"):
            self.load()
        del self.document["unexpected"]
        self.document["access_profile"] = "customer-locked"
        self.write_set()
        with self.assertRaisesRegex(handoff.Refusal, "unsupported access_profile"):
            self.load()

    def test_target_must_be_the_canonical_appliance_repository(self):
        self.document["target_os_ref"] = (
            "release.example.test/neural-ice/other@sha256:" + "7" * 64
        )
        self.write_set()
        with self.assertRaisesRegex(handoff.Refusal, "target_os_ref"):
            self.load()

    def test_conflicting_destination_is_never_replaced(self):
        destination = self.root / "destination"
        destination.mkdir()
        marker = destination / "foreign"
        marker.write_bytes(b"keep")
        with self.assertRaisesRegex(handoff.Refusal, "conflicting"):
            handoff.publish(self.load(), handoff.FILES, destination, 0o700, 0o600)
        self.assertEqual(marker.read_bytes(), b"keep")

    def test_symlinked_destination_parent_is_refused(self):
        real = self.root / "real-parent"
        real.mkdir()
        alias = self.root / "parent-alias"
        alias.symlink_to(real, target_is_directory=True)
        with self.assertRaisesRegex(handoff.Refusal, "symlink"):
            handoff.publish(
                self.load(), handoff.FILES, alias / "destination", 0o700, 0o600
            )
        self.assertFalse((real / "destination").exists())

    def test_exact_retry_refuses_weakened_private_mode(self):
        destination = self.root / "private"
        files = self.load()
        handoff.publish(files, handoff.FILES, destination, 0o700, 0o600)
        os.chmod(destination / "bom.json", 0o644)
        with self.assertRaisesRegex(handoff.Refusal, "unsafe ownership or mode"):
            handoff.publish(files, handoff.FILES, destination, 0o700, 0o600)

    def test_persistent_snapshot_has_exact_eight_file_private_layout(self):
        snapshot = self.root / "preseal-input-v1"
        self.snapshot_persistent(snapshot)
        self.snapshot_persistent(snapshot)
        self.assertEqual(set(handoff.PERSISTENT_FILES), {p.name for p in snapshot.iterdir()})
        self.assertEqual(stat.S_IMODE(snapshot.stat().st_mode), 0o700)
        self.assertTrue(
            all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in snapshot.iterdir())
        )
        self.assertEqual(
            (snapshot / handoff.INSTALLER_AUTH_NAME).read_bytes(), self.auth.read_bytes()
        )
        self.assertEqual(
            (snapshot / handoff.INSTALLER_SIG_NAME).read_bytes(), self.sig.read_bytes()
        )
        self.assertEqual(
            handoff.load_persistent(snapshot, self.expected),
            handoff.load_persistent_source(
                self.source, self.expected, self.auth, self.sig
            ),
        )

    def test_persistent_install_is_exact_and_idempotent(self):
        snapshot = self.root / "snapshot"
        destination = self.root / "installed" / "preseal-input-v1"
        destination.parent.mkdir(mode=0o700)
        self.snapshot_persistent(snapshot)
        files = handoff.load_persistent(snapshot, self.expected)
        handoff.publish(
            files, handoff.PERSISTENT_FILES, destination, 0o700, 0o600
        )
        handoff.publish(
            files, handoff.PERSISTENT_FILES, destination, 0o700, 0o600
        )
        self.assertEqual(
            handoff.load_persistent(destination, self.expected),
            handoff.load_persistent(snapshot, self.expected),
        )

    def test_persistent_reader_refuses_public_file_or_directory_mode(self):
        snapshot = self.root / "snapshot"
        self.snapshot_persistent(snapshot)
        os.chmod(snapshot / "bom.json", 0o666)
        with self.assertRaisesRegex(handoff.Refusal, "unsafe ownership or mode"):
            handoff.load_persistent(snapshot, self.expected)

        os.chmod(snapshot / "bom.json", 0o600)
        os.chmod(snapshot, 0o755)
        with self.assertRaisesRegex(handoff.Refusal, "unsafe ownership or mode"):
            handoff.load_persistent(snapshot, self.expected)

    def test_persistent_partial_symlink_fifo_oversize_and_hash_drift_are_refused(self):
        snapshot = self.root / "snapshot"
        self.snapshot_persistent(snapshot)
        cases = (
            ("missing", "bom.json"),
            ("unknown", "foreign.json"),
            ("symlink", handoff.INSTALLER_AUTH_NAME),
            ("fifo", handoff.INSTALLER_SIG_NAME),
            ("oversize", "delegation-snapshot.json"),
            ("drift", "ota-release-authorization.json"),
            ("installer-auth-drift", handoff.INSTALLER_AUTH_NAME),
            ("installer-sig-drift", handoff.INSTALLER_SIG_NAME),
        )
        for kind, name in cases:
            with self.subTest(kind=kind, name=name):
                case = self.root / f"case-{kind}"
                handoff.publish(
                    handoff.load_persistent(snapshot, self.expected),
                    handoff.PERSISTENT_FILES,
                    case,
                    0o700,
                    0o600,
                )
                path = case / name
                if kind == "missing":
                    path.unlink()
                    expected = "exactly the eight"
                elif kind == "unknown":
                    path.write_bytes(b"foreign\n")
                    expected = "exactly the eight"
                elif kind == "symlink":
                    path.unlink()
                    path.symlink_to(self.auth)
                    expected = "regular file"
                elif kind == "fifo":
                    path.unlink()
                    os.mkfifo(path)
                    expected = "regular file"
                elif kind == "oversize":
                    path.write_bytes(b"x" * (handoff.PERSISTENT_FILES[name] + 1))
                    expected = "at most"
                elif kind == "installer-auth-drift":
                    path.write_bytes(path.read_bytes() + b"x")
                    expected = "authorization bytes"
                elif kind == "installer-sig-drift":
                    path.write_bytes(path.read_bytes() + b"x")
                    expected = "authorization signature bytes"
                else:
                    path.write_bytes(path.read_bytes() + b"x")
                    expected = "does not bind"
                with self.assertRaisesRegex(handoff.Refusal, expected):
                    handoff.load_persistent(case, self.expected)

    def test_interrupted_publication_never_exposes_a_partial_set(self):
        files = handoff.load_persistent_source(
            self.source, self.expected, self.auth, self.sig
        )
        destination = self.root / "destination"
        with mock.patch.object(
            handoff, "rename_noreplace", side_effect=handoff.Refusal("cut")
        ):
            with self.assertRaisesRegex(handoff.Refusal, "cut"):
                handoff.publish(
                    files, handoff.PERSISTENT_FILES, destination, 0o700, 0o600
                )
        self.assertFalse(destination.exists())
        self.assertEqual(list(self.root.glob(".destination.*.new")), [])
        handoff.publish(files, handoff.PERSISTENT_FILES, destination, 0o700, 0o600)
        self.assertEqual(handoff.load_persistent(destination, self.expected), files)

    def test_failure_after_atomic_publish_recovers_only_as_exact_retry(self):
        files = handoff.load_persistent_source(
            self.source, self.expected, self.auth, self.sig
        )
        destination = self.root / "destination"
        real_fsync = handoff.fsync_path
        calls = 0

        def fail_parent_sync(path):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("synthetic power cut after rename")
            return real_fsync(path)

        with mock.patch.object(handoff, "fsync_path", side_effect=fail_parent_sync):
            with self.assertRaisesRegex(OSError, "power cut"):
                handoff.publish(
                    files, handoff.PERSISTENT_FILES, destination, 0o700, 0o600
                )
        handoff.publish(files, handoff.PERSISTENT_FILES, destination, 0o700, 0o600)
        self.assertEqual(handoff.load_persistent(destination, self.expected), files)


if __name__ == "__main__":
    unittest.main()
