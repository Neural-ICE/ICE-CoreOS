#!/usr/bin/env python3

from __future__ import annotations

import json
import importlib.util
import io
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
        # Unit fixtures exercise serialization semantics independently of the
        # runner's backing filesystem. Btrfs refusal has its own explicit test.
        self.original_linux_filesystem_magic = MANIFEST_MODULE.linux_filesystem_magic
        self.filesystem_magic = mock.patch.object(
            MANIFEST_MODULE,
            "linux_filesystem_magic",
            return_value=0xEF53,
        )
        self.filesystem_magic.start()
        self.addCleanup(self.filesystem_magic.stop)
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
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
        arguments = (
            "--tree",
            f"store={source / 'store'}",
            "--tree",
            f"models={source / 'models'}",
            "--tree",
            f"payload={source / 'payload'}",
            "--output",
            str(output),
        )
        try:
            MANIFEST_MODULE.write_manifest(
                [
                    ("store", source / "store"),
                    ("models", source / "models"),
                    ("payload", source / "payload"),
                ],
                output,
            )
        except (MANIFEST_MODULE.ManifestError, OSError) as error:
            return subprocess.CompletedProcess(
                arguments,
                1,
                stdout="",
                stderr=f"REFUSED: {error}\n",
            )
        return subprocess.CompletedProcess(arguments, 0, stdout="", stderr="")

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
    def test_deep_tree_exceeding_path_max_is_descriptor_relative(self) -> None:
        deep_root = self.source / "models" / "deep"
        deep_root.mkdir()
        descriptor = os.open(deep_root, os.O_RDONLY)
        try:
            for _ in range(2100):
                os.mkdir("d", dir_fd=descriptor)
                child = os.open("d", os.O_RDONLY, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
            leaf = os.open(
                "leaf",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=descriptor,
            )
            os.write(leaf, b"deep")
            os.close(leaf)

            result = self.generate(self.source, self.root / "deep.json")
            self.assertEqual(result.returncode, 0, result.stderr)
        finally:
            os.close(descriptor)
            # tempfile/shutil cleanup is itself recursive on some Python
            # versions, so remove this deliberate stress tree iteratively in
            # the platform utility before TemporaryDirectory tears down.
            subprocess.run(("rm", "-rf", str(deep_root)), check=True)

    def test_cli_requires_complete_xattr_visibility_on_linux(self) -> None:
        output = self.root / "unprivileged.json"
        result = subprocess.run(
            (
                sys.executable,
                str(TOOL),
                "--tree",
                f"models={self.source / 'models'}",
                "--output",
                str(output),
            ),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        actual_btrfs = False
        if sys.platform == "linux":
            descriptor = os.open(self.source / "models", os.O_RDONLY)
            try:
                actual_btrfs = (
                    self.original_linux_filesystem_magic(descriptor)
                    == MANIFEST_MODULE.BTRFS_SUPER_MAGIC
                )
            finally:
                os.close(descriptor)
        try:
            MANIFEST_MODULE.require_complete_xattr_visibility()
        except MANIFEST_MODULE.ManifestError as error:
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(str(error), result.stderr)
            self.assertFalse(output.exists())
        else:
            if actual_btrfs:
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("Btrfs input is unsupported", result.stderr)
                self.assertFalse(output.exists())
                return
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(output.is_file())

    def test_output_inside_input_tree_is_refused_before_walk(self) -> None:
        output = self.source / "models" / "manifest.json"
        result = self.generate(self.source, output)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("output path is inside input tree", result.stderr)
        self.assertFalse(output.exists())

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
        self.assertEqual(list(self.root.glob(".seed-manifest-*")), [])

    def test_failed_atomic_publish_removes_private_temporary_output(self) -> None:
        output = self.root / "link-failure.json"
        with mock.patch.object(
            MANIFEST_MODULE.os,
            "link",
            side_effect=OSError("simulated link failure"),
        ):
            with self.assertRaisesRegex(OSError, "simulated link failure"):
                MANIFEST_MODULE.write_manifest(
                    [("models", self.source / "models")],
                    output,
                )
        self.assertFalse(output.exists())
        self.assertEqual(list(self.root.glob(".seed-manifest-*")), [])

    def test_ambiguous_link_failure_removes_the_final_name(self) -> None:
        output = self.root / "ambiguous-link.json"
        original_link = os.link

        def link_then_raise(*args, **kwargs) -> None:
            original_link(*args, **kwargs)
            raise OSError("simulated post-link interruption")

        with mock.patch.object(
            MANIFEST_MODULE.os,
            "link",
            side_effect=link_then_raise,
        ):
            with self.assertRaisesRegex(OSError, "simulated post-link interruption"):
                MANIFEST_MODULE.write_manifest(
                    [("models", self.source / "models")],
                    output,
                )
        self.assertFalse(output.exists())
        self.assertEqual(list(self.root.glob(".seed-manifest-*")), [])

    def test_cleanup_is_synced_after_post_publish_sync_failure(self) -> None:
        output = self.root / "post-publish-sync.json"
        original_fsync = os.fsync
        calls = 0

        failure_call = 4 if sys.platform == "linux" else 5

        def fail_post_unlink_parent_sync(descriptor: int) -> None:
            nonlocal calls
            calls += 1
            if calls == failure_call:
                raise OSError("simulated post-unlink sync failure")
            original_fsync(descriptor)

        with mock.patch.object(
            MANIFEST_MODULE.os,
            "fsync",
            side_effect=fail_post_unlink_parent_sync,
        ):
            with self.assertRaisesRegex(OSError, "simulated post-unlink sync failure"):
                MANIFEST_MODULE.write_manifest(
                    [("models", self.source / "models")],
                    output,
                )
        self.assertGreaterEqual(calls, failure_call + 1)
        self.assertFalse(output.exists())
        self.assertEqual(list(self.root.glob(".seed-manifest-*")), [])

    def test_spool_teardown_failure_does_not_publish_output(self) -> None:
        output = self.root / "spool-teardown.json"
        original_remove_spool = MANIFEST_MODULE.remove_spool
        calls = 0

        def fail_once(*args, **kwargs) -> None:
            nonlocal calls
            calls += 1
            original_remove_spool(*args, **kwargs)
            if calls == 1:
                raise OSError("simulated spool teardown failure")

        with mock.patch.object(
            MANIFEST_MODULE,
            "remove_spool",
            side_effect=fail_once,
        ):
            with self.assertRaisesRegex(OSError, "simulated spool teardown failure"):
                MANIFEST_MODULE.write_manifest(
                    [("models", self.source / "models")],
                    output,
                )
        self.assertFalse(output.exists())
        self.assertEqual(list(self.root.glob(".seed-manifest-*")), [])

    def test_output_parent_change_removes_the_published_inode(self) -> None:
        output = self.root / "parent-change.json"
        with mock.patch.object(
            MANIFEST_MODULE,
            "secure_parent_is_unchanged",
            return_value=False,
        ):
            with self.assertRaisesRegex(
                MANIFEST_MODULE.ManifestError,
                "output directory changed",
            ):
                MANIFEST_MODULE.write_manifest(
                    [("models", self.source / "models")],
                    output,
                )
        self.assertFalse(output.exists())
        self.assertEqual(list(self.root.glob(".seed-manifest-*")), [])

    def test_caller_tmpdir_is_not_used_for_the_spool(self) -> None:
        output = self.root / "safe-spool.json"
        with mock.patch.dict(
            os.environ,
            {
                "TMPDIR": str(self.source / "models"),
                "SQLITE_TMPDIR": str(self.source / "models"),
            },
        ):
            MANIFEST_MODULE.write_manifest(
                [("models", self.source / "models")],
                output,
            )
        self.assertTrue(output.is_file())
        self.assertEqual(list((self.source / "models").glob("etilqs_*")), [])
        self.assertEqual(list(self.root.glob(".seed-manifest-spool-*")), [])

    def test_directory_identity_cycle_is_refused_during_preflight(self) -> None:
        parent_descriptor = os.open(self.root, os.O_RDONLY)
        try:
            parent_metadata = os.fstat(parent_descriptor)
            with self.assertRaisesRegex(
                MANIFEST_MODULE.ManifestError,
                "directory identity revisited",
            ):
                MANIFEST_MODULE.output_parent_aliases_input(
                    [
                        ("models-a", self.source / "models"),
                        ("models-b", self.source / "models"),
                    ],
                    parent_descriptor,
                    parent_metadata,
                )
        finally:
            os.close(parent_descriptor)

    def test_directory_preflight_cap_is_enforced_before_enqueue(self) -> None:
        parent_descriptor = os.open(self.root, os.O_RDONLY)
        try:
            parent_metadata = os.fstat(parent_descriptor)
            with (
                mock.patch.object(MANIFEST_MODULE, "MAX_PREFLIGHT_DIRECTORIES", 1),
                self.assertRaisesRegex(
                    MANIFEST_MODULE.ManifestError,
                    "directory preflight limit exceeded",
                ),
            ):
                MANIFEST_MODULE.output_parent_aliases_input(
                    [
                        ("models", self.source / "models"),
                        ("payload", self.source / "payload"),
                    ],
                    parent_descriptor,
                    parent_metadata,
                )
        finally:
            os.close(parent_descriptor)

    def test_cli_translates_sqlite_failures_to_refused(self) -> None:
        standard_error = io.StringIO()
        with (
            mock.patch.object(
                MANIFEST_MODULE,
                "require_complete_xattr_visibility",
            ),
            mock.patch.object(
                MANIFEST_MODULE,
                "write_manifest",
                side_effect=MANIFEST_MODULE.sqlite3.OperationalError("simulated sqlite failure"),
            ),
            mock.patch.object(
                MANIFEST_MODULE.sys,
                "argv",
                ["seed-tree-manifest.py", "--tree", "models=/tmp", "--output", "/tmp/x"],
            ),
            mock.patch.object(MANIFEST_MODULE.sys, "stderr", standard_error),
        ):
            self.assertEqual(MANIFEST_MODULE.main(), 1)
        self.assertIn("REFUSED: simulated sqlite failure", standard_error.getvalue())

    def test_output_symlink_ancestor_is_refused(self) -> None:
        alias = self.root / "output-alias"
        destination = self.root / "output-destination"
        destination.mkdir()
        alias.symlink_to(destination, target_is_directory=True)
        output = alias / "manifest.json"
        with self.assertRaisesRegex(
            MANIFEST_MODULE.ManifestError,
            "cannot open output directory",
        ):
            MANIFEST_MODULE.write_manifest(
                [("models", self.source / "models")],
                output,
            )
        self.assertFalse((destination / "manifest.json").exists())

    def test_output_mode_is_0600_under_restrictive_umask(self) -> None:
        output = self.root / "mode.json"
        previous_umask = os.umask(0o777)
        try:
            MANIFEST_MODULE.write_manifest(
                [("models", self.source / "models")],
                output,
            )
        finally:
            os.umask(previous_umask)
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)

    def test_failed_mode_enforcement_removes_private_output(self) -> None:
        output = self.root / "mode-failure.json"
        original_fchmod = os.fchmod
        calls = 0

        def fail_manifest_mode(descriptor: int, mode: int) -> None:
            nonlocal calls
            calls += 1
            output_call = 1 if sys.platform == "linux" else 2
            if calls == output_call:
                raise OSError("simulated chmod failure")
            original_fchmod(descriptor, mode)

        with mock.patch.object(
            MANIFEST_MODULE.os,
            "fchmod",
            side_effect=fail_manifest_mode,
        ):
            with self.assertRaisesRegex(OSError, "simulated chmod failure"):
                MANIFEST_MODULE.write_manifest(
                    [("models", self.source / "models")],
                    output,
                )
        self.assertFalse(output.exists())
        self.assertEqual(list(self.root.glob(".seed-manifest-*")), [])

    def test_hard_linked_regular_file_is_hashed_once(self) -> None:
        output = self.root / "hardlink-cache.json"
        original_digest = MANIFEST_MODULE.file_digest
        calls = 0

        def count_digest(path: Path, metadata: os.stat_result) -> str:
            nonlocal calls
            calls += 1
            return original_digest(path, metadata)

        with mock.patch.object(
            MANIFEST_MODULE,
            "file_digest",
            side_effect=count_digest,
        ):
            MANIFEST_MODULE.write_manifest(
                [("models", self.source / "models")],
                output,
            )
        # model-a has one two-name hard-link group and no other regular file.
        self.assertEqual(calls, 1)

    def test_preflight_queue_is_disk_backed(self) -> None:
        parent_descriptor = os.open(self.root, os.O_RDONLY)
        try:
            with MANIFEST_MODULE.open_preflight_queue(parent_descriptor) as queue:
                self.assertFalse(isinstance(queue, io.BytesIO))
                queue.write(b"bounded-on-disk")
                queue.seek(0)
                self.assertEqual(queue.read(), b"bounded-on-disk")
        finally:
            os.close(parent_descriptor)
        self.assertEqual(list(self.root.glob(".seed-manifest-preflight-*")), [])

    @unittest.skipUnless(sys.platform == "linux", "O_TMPFILE is Linux-specific")
    def test_preflight_queue_falls_back_when_otmpfile_is_unsupported(self) -> None:
        parent_descriptor = os.open(self.root, os.O_RDONLY)
        original_open = os.open

        def reject_otmpfile(path, flags, *args, **kwargs):
            if flags & getattr(os, "O_TMPFILE", 0):
                raise OSError(MANIFEST_MODULE.errno.EOPNOTSUPP, "unsupported")
            return original_open(path, flags, *args, **kwargs)

        try:
            with mock.patch.object(
                MANIFEST_MODULE.os,
                "open",
                side_effect=reject_otmpfile,
            ):
                with MANIFEST_MODULE.open_preflight_queue(parent_descriptor) as queue:
                    queue.write(b"fallback")
                    queue.seek(0)
                    self.assertEqual(queue.read(), b"fallback")
        finally:
            os.close(parent_descriptor)
        self.assertEqual(list(self.root.glob(".seed-manifest-preflight-*")), [])

    def test_btrfs_inode_namespace_is_refused(self) -> None:
        parent_descriptor = os.open(self.root, os.O_RDONLY)
        try:
            with (
                mock.patch.object(MANIFEST_MODULE.sys, "platform", "linux"),
                mock.patch.object(
                    MANIFEST_MODULE,
                    "linux_filesystem_magic",
                    return_value=MANIFEST_MODULE.BTRFS_SUPER_MAGIC,
                ),
                self.assertRaisesRegex(
                    MANIFEST_MODULE.ManifestError,
                    "Btrfs input is unsupported",
                ),
            ):
                MANIFEST_MODULE.reject_ambiguous_inode_namespace(
                    parent_descriptor,
                    "models",
                )
        finally:
            os.close(parent_descriptor)

    def test_btrfs_file_mount_is_refused_before_inode_reuse(self) -> None:
        regular_file = self.source / "models" / "model-a" / "weights"
        with (
            mock.patch.object(MANIFEST_MODULE.sys, "platform", "linux"),
            mock.patch.object(
                MANIFEST_MODULE,
                "linux_filesystem_magic",
                return_value=MANIFEST_MODULE.BTRFS_SUPER_MAGIC,
            ),
            self.assertRaisesRegex(
                MANIFEST_MODULE.ManifestError,
                "Btrfs input is unsupported",
            ),
        ):
            MANIFEST_MODULE.reject_ambiguous_inode_path(
                regular_file,
                "models/model-a/weights",
            )

    def test_linux_authoritative_cli_requires_root_and_cap_sys_admin(self) -> None:
        with (
            mock.patch.object(MANIFEST_MODULE.sys, "platform", "linux"),
            mock.patch.object(MANIFEST_MODULE.os, "geteuid", return_value=1000),
            self.assertRaisesRegex(
                MANIFEST_MODULE.ManifestError,
                "require host root",
            ),
        ):
            MANIFEST_MODULE.require_complete_xattr_visibility()

        with (
            mock.patch.object(MANIFEST_MODULE.sys, "platform", "linux"),
            mock.patch.object(MANIFEST_MODULE.os, "geteuid", return_value=0),
            mock.patch.object(
                MANIFEST_MODULE,
                "require_initial_linux_user_namespace",
            ),
            mock.patch.object(
                MANIFEST_MODULE,
                "linux_effective_capabilities",
                return_value=0,
            ),
            self.assertRaisesRegex(
                MANIFEST_MODULE.ManifestError,
                "require CAP_SYS_ADMIN",
            ),
        ):
            MANIFEST_MODULE.require_complete_xattr_visibility()

        with (
            mock.patch.object(MANIFEST_MODULE.sys, "platform", "linux"),
            mock.patch.object(MANIFEST_MODULE.os, "geteuid", return_value=0),
            mock.patch.object(
                MANIFEST_MODULE,
                "require_initial_linux_user_namespace",
            ),
            mock.patch.object(
                MANIFEST_MODULE,
                "linux_effective_capabilities",
                return_value=1 << MANIFEST_MODULE.CAP_SYS_ADMIN,
            ),
        ):
            MANIFEST_MODULE.require_complete_xattr_visibility()

    def test_linux_authoritative_cli_rejects_nested_user_namespace(self) -> None:
        nested_map = ((0, 100000, 65536),)
        with (
            mock.patch.object(
                MANIFEST_MODULE,
                "linux_id_map",
                return_value=nested_map,
            ),
            self.assertRaisesRegex(
                MANIFEST_MODULE.ManifestError,
                "initial host user namespace",
            ),
        ):
            MANIFEST_MODULE.require_initial_linux_user_namespace()

    def test_linux_authoritative_cli_rejects_non_initial_namespace_inode(self) -> None:
        descriptor = os.open(self.root, os.O_RDONLY)
        with (
            mock.patch.object(
                MANIFEST_MODULE,
                "linux_id_map",
                return_value=MANIFEST_MODULE.INITIAL_ID_MAP,
            ),
            mock.patch.object(MANIFEST_MODULE.os, "open", return_value=descriptor),
            mock.patch.object(
                MANIFEST_MODULE.os,
                "fstat",
                return_value=SimpleNamespace(st_ino=12345),
            ),
            self.assertRaisesRegex(
                MANIFEST_MODULE.ManifestError,
                "initial host user namespace",
            ),
        ):
            MANIFEST_MODULE.require_initial_linux_user_namespace()

    def test_serializer_api_refuses_unsafe_tree_names(self) -> None:
        for unsafe_name in ("", ".", "..", "bad/name", "mødels"):
            with self.subTest(name=unsafe_name):
                with self.assertRaisesRegex(
                    MANIFEST_MODULE.ManifestError,
                    "tree names must be safe",
                ):
                    MANIFEST_MODULE.write_manifest(
                        [(unsafe_name, self.source / "models")],
                        self.root / f"unsafe-{len(unsafe_name)}.json",
                    )

    def test_maximum_length_output_basename_is_supported(self) -> None:
        output = self.root / ("m" * 255)
        MANIFEST_MODULE.write_manifest(
            [("models", self.source / "models")],
            output,
        )
        self.assertTrue(output.is_file())

    def test_cleanup_attempts_every_owned_name(self) -> None:
        attempted: list[str] = []

        def remove(
            _parent_descriptor: int,
            name: str,
            _created_identity: tuple[int, int],
            _original_error: BaseException,
        ) -> None:
            attempted.append(name)
            if name == "published":
                raise MANIFEST_MODULE.ManifestError("simulated replacement")

        with (
            mock.patch.object(MANIFEST_MODULE, "remove_owned_name", side_effect=remove),
            mock.patch.object(MANIFEST_MODULE.os, "fsync") as synced,
        ):
            with self.assertRaisesRegex(
                MANIFEST_MODULE.ManifestError,
                "one or more owned manifest files",
            ):
                MANIFEST_MODULE.remove_owned_names(
                    1,
                    [("published", (1, 1)), ("temporary", (1, 1))],
                    OSError("original"),
                )
            synced.assert_called_once_with(1)
        self.assertEqual(attempted, ["published", "temporary"])

    def test_cleanup_syncs_the_parent_after_removal(self) -> None:
        owned = self.root / "owned"
        owned.write_bytes(b"owned")
        metadata = owned.stat()
        parent_descriptor = os.open(self.root, os.O_RDONLY)
        try:
            with mock.patch.object(MANIFEST_MODULE.os, "fsync") as synced:
                MANIFEST_MODULE.remove_owned_names(
                    parent_descriptor,
                    [(owned.name, (metadata.st_dev, metadata.st_ino))],
                    OSError("original"),
                )
            synced.assert_called_once_with(parent_descriptor)
        finally:
            os.close(parent_descriptor)
        self.assertFalse(owned.exists())

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
        self.assertFalse(
            MANIFEST_MODULE.is_allowed_overlay_whiteout(
                "store",
                MANIFEST_MODULE.PurePosixPath("overlay"),
                whiteout,
            )
        )


if __name__ == "__main__":
    unittest.main()
