#!/usr/bin/env python3

from __future__ import annotations

import json
import importlib.util
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


TOOL = Path(__file__).with_name("seed-tree-manifest.py")
SPEC = importlib.util.spec_from_file_location("seed_tree_manifest", TOOL)
assert SPEC is not None and SPEC.loader is not None
MANIFEST_MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MANIFEST_MODULE)


class SeedTreeManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        (self.source / "store" / "overlay").mkdir(parents=True)
        (self.source / "models" / "model-a").mkdir(parents=True)
        (self.source / "payload").mkdir()
        (self.source / "store" / "overlay" / "layer").write_bytes(b"layer\x00bytes")
        model = self.source / "models" / "model-a" / "weights"
        model.write_bytes(b"weights")
        os.link(model, self.source / "models" / "model-a" / "weights-hardlink")
        os.symlink("weights", self.source / "models" / "model-a" / "current")
        (self.source / "payload" / "apply.sh").write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
        os.chmod(self.source / "payload" / "apply.sh", 0o755)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def generate(self, source: Path, output: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            (
                sys.executable,
                str(TOOL),
                "--tree",
                f"store={source / 'store'}",
                "--tree",
                f"models={source / 'models'}",
                "--tree",
                f"payload={source / 'payload'}",
                "--output",
                str(output),
            ),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def test_manifest_is_exact_and_copy_stable(self) -> None:
        first = self.root / "first.json"
        result = self.generate(self.source, first)
        self.assertEqual(result.returncode, 0, result.stderr)
        document = json.loads(first.read_text(encoding="ascii"))
        self.assertEqual(document["schema"], "neural-ice-offline-seed-tree-v1")
        self.assertEqual(document["trees"], ["models", "payload", "store"])
        paths = [entry["path"] for entry in document["entries"]]
        self.assertEqual(paths, sorted(paths))
        hardlinks = {
            entry["path"]: entry.get("hardlink_to")
            for entry in document["entries"]
            if entry["path"].endswith(("weights", "weights-hardlink"))
        }
        self.assertEqual(len(set(hardlinks.values())), 1)

        copied = self.root / "copied"
        subprocess.run(("cp", "-a", str(self.source), str(copied)), check=True)
        # BSD cp(1) does not preserve hard-link topology with -a, while the
        # production GNU cp(1) does. Restore the topology so this portable
        # test compares the contract rather than the host cp implementation.
        copied_hardlink = copied / "models" / "model-a" / "weights-hardlink"
        copied_hardlink.unlink()
        os.link(copied / "models" / "model-a" / "weights", copied_hardlink)
        second = self.root / "second.json"
        result = self.generate(copied, second)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_manifest_globally_sorts_dfs_children_and_siblings(self) -> None:
        bucket = self.source / "models" / "bucket"
        bucket.mkdir()
        (bucket / "child").write_bytes(b"child")
        (self.source / "models" / "bucket-archive").write_bytes(b"sibling")

        output = self.root / "globally-sorted.json"
        result = self.generate(self.source, output)
        self.assertEqual(result.returncode, 0, result.stderr)
        paths = [entry["path"] for entry in json.loads(output.read_bytes())["entries"]]
        self.assertEqual(paths, sorted(paths))
        self.assertLess(
            paths.index("models/bucket-archive"),
            paths.index("models/bucket/child"),
        )

    def test_hard_links_are_grouped_across_input_trees(self) -> None:
        source = self.source / "models" / "model-a" / "weights"
        destination = self.source / "payload" / "weights-cross-tree"
        os.link(source, destination)

        output = self.root / "cross-tree-hardlinks.json"
        result = self.generate(self.source, output)
        self.assertEqual(result.returncode, 0, result.stderr)
        entries = {
            entry["path"]: entry
            for entry in json.loads(output.read_bytes())["entries"]
        }
        linked_paths = (
            "models/model-a/weights",
            "models/model-a/weights-hardlink",
            "payload/weights-cross-tree",
        )
        self.assertEqual(
            {entries[path]["hardlink_to"] for path in linked_paths},
            {"models/model-a/weights"},
        )

    def test_hard_linked_symlinks_preserve_topology(self) -> None:
        source = self.source / "models" / "model-a" / "current"
        destination = self.source / "payload" / "current-cross-tree"
        try:
            os.link(source, destination, follow_symlinks=False)
        except (NotImplementedError, OSError) as error:
            self.skipTest(f"hard-linked symlinks unavailable: {error}")

        output = self.root / "symlink-hardlinks.json"
        result = self.generate(self.source, output)
        self.assertEqual(result.returncode, 0, result.stderr)
        entries = {
            entry["path"]: entry
            for entry in json.loads(output.read_bytes())["entries"]
        }
        self.assertEqual(
            entries["models/model-a/current"]["hardlink_to"],
            "models/model-a/current",
        )
        self.assertEqual(
            entries["payload/current-cross-tree"]["hardlink_to"],
            "models/model-a/current",
        )

    @unittest.skipIf(sys.platform == "darwin", "macOS PATH_MAX is below recursion limit")
    def test_deep_tree_does_not_depend_on_python_recursion(self) -> None:
        deep_root = self.source / "models" / "deep"
        current = deep_root
        current.mkdir()
        try:
            for _ in range(1050):
                current /= "d"
                current.mkdir()
            (current / "leaf").write_bytes(b"deep")

            result = self.generate(self.source, self.root / "deep.json")
            self.assertEqual(result.returncode, 0, result.stderr)
        finally:
            # tempfile/shutil cleanup is itself recursive on some Python
            # versions, so remove this deliberate stress tree iteratively in
            # the platform utility before TemporaryDirectory tears down.
            subprocess.run(("rm", "-rf", str(deep_root)), check=True)

    def test_directory_mutation_during_walk_is_refused(self) -> None:
        original_digest = MANIFEST_MODULE.file_digest
        mutated = False

        def mutate_parent(path: Path, metadata: os.stat_result) -> str:
            nonlocal mutated
            if not mutated:
                mutated = True
                (path.parent / "appeared-during-walk").write_bytes(b"race")
            return original_digest(path, metadata)

        output = self.root / "mutated.json"
        with mock.patch.object(MANIFEST_MODULE, "file_digest", side_effect=mutate_parent):
            with self.assertRaisesRegex(MANIFEST_MODULE.ManifestError, "directory changed"):
                MANIFEST_MODULE.write_manifest(
                    [("models", self.source / "models")],
                    output,
                )
        self.assertFalse(output.exists())

    def test_earlier_file_mutation_during_later_hash_is_refused(self) -> None:
        first = self.source / "models" / "model-a" / "weights"
        later = self.source / "models" / "model-a" / "weights-hardlink"
        later.unlink()
        later.write_bytes(b"later")
        original_digest = MANIFEST_MODULE.file_digest

        def mutate_earlier(path: Path, metadata: os.stat_result) -> str:
            if path == later:
                first.write_bytes(b"changed after its initial validation")
            return original_digest(path, metadata)

        output = self.root / "retained-mutation.json"
        with mock.patch.object(
            MANIFEST_MODULE,
            "file_digest",
            side_effect=mutate_earlier,
        ):
            with self.assertRaisesRegex(MANIFEST_MODULE.ManifestError, "changed while walking"):
                MANIFEST_MODULE.write_manifest(
                    [("models", self.source / "models")],
                    output,
                )
        self.assertFalse(output.exists())

    def test_output_inside_input_tree_is_refused_before_walk(self) -> None:
        output = self.source / "models" / "manifest.json"
        result = self.generate(self.source, output)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("output path is inside input tree", result.stderr)
        self.assertFalse(output.exists())

    def test_output_parent_identity_detects_an_aliased_tree_directory(self) -> None:
        models = self.source / "models"
        alias = self.root / "models-alias"
        alias.symlink_to(models, target_is_directory=True)
        metadata = models.lstat()
        self.assertTrue(
            MANIFEST_MODULE.output_parent_is_manifested_directory(
                alias / "manifest.json",
                [(models, metadata, "directory")],
            )
        )

    def test_failed_manifest_write_removes_partial_output(self) -> None:
        output = self.root / "partial.json"
        with mock.patch.object(
            MANIFEST_MODULE.os,
            "write",
            side_effect=OSError("simulated full filesystem"),
        ):
            with self.assertRaisesRegex(OSError, "simulated full filesystem"):
                MANIFEST_MODULE.write_manifest(
                    [("models", self.source / "models")],
                    output,
                )
        self.assertFalse(output.exists())

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO unavailable")
    def test_fifo_is_rejected_without_reading_it(self) -> None:
        os.mkfifo(self.source / "models" / "model-a" / "hostile")
        result = self.generate(self.source, self.root / "fifo.json")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unsupported seed entry type", result.stderr)

    def test_existing_output_is_not_overwritten(self) -> None:
        output = self.root / "existing.json"
        output.write_text("owner-data", encoding="ascii")
        result = self.generate(self.source, output)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(output.read_text(encoding="ascii"), "owner-data")

    def test_only_reserved_zero_zero_character_device_is_a_whiteout(self) -> None:
        whiteout = SimpleNamespace(st_mode=stat.S_IFCHR, st_rdev=os.makedev(0, 0))
        host_device = SimpleNamespace(st_mode=stat.S_IFCHR, st_rdev=os.makedev(1, 3))
        regular = SimpleNamespace(st_mode=stat.S_IFREG, st_rdev=os.makedev(0, 0))
        self.assertTrue(MANIFEST_MODULE.is_overlay_whiteout(whiteout))
        self.assertFalse(MANIFEST_MODULE.is_overlay_whiteout(host_device))
        self.assertFalse(MANIFEST_MODULE.is_overlay_whiteout(regular))
        self.assertTrue(
            MANIFEST_MODULE.is_allowed_overlay_whiteout(
                "store",
                MANIFEST_MODULE.PurePosixPath("overlay/layer/diff/.wh.deleted"),
                whiteout,
            )
        )
        self.assertFalse(
            MANIFEST_MODULE.is_allowed_overlay_whiteout(
                "models",
                MANIFEST_MODULE.PurePosixPath("overlay/.wh.hostile"),
                whiteout,
            )
        )
        self.assertFalse(
            MANIFEST_MODULE.is_allowed_overlay_whiteout(
                "store",
                MANIFEST_MODULE.PurePosixPath("overlay-images/.wh.hostile"),
                whiteout,
            )
        )


if __name__ == "__main__":
    unittest.main()
