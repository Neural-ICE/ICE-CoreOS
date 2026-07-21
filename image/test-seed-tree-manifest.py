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


if __name__ == "__main__":
    unittest.main()
