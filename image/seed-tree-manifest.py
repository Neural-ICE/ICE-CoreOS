#!/usr/bin/env python3
"""Create an exact, deterministic manifest for an offline seed tree.

The manifest deliberately excludes timestamps and inode numbers, which change
when a seed is copied to XFS. It includes every namespace entry, file digest,
mode, owner, symlink target, hard-link relationship and extended attribute.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import sys
from typing import Any


class ManifestError(RuntimeError):
    pass


def parse_tree(value: str) -> tuple[str, Path]:
    name, separator, raw_path = value.partition("=")
    if not separator or not name or not raw_path:
        raise argparse.ArgumentTypeError("tree must be NAME=PATH")
    if not name.replace("-", "").replace("_", "").isalnum():
        raise argparse.ArgumentTypeError(f"unsafe tree name: {name}")
    return name, Path(raw_path)


def stable_path(name: str, relative: PurePosixPath | None = None) -> str:
    if relative is None or str(relative) == ".":
        return name
    return f"{name}/{relative.as_posix()}"


def identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def xattrs(path: Path, *, follow_symlinks: bool) -> dict[str, str]:
    if not hasattr(os, "listxattr"):
        if sys.platform != "darwin" or shutil.which("xattr") is None:
            raise ManifestError("extended-attribute enumeration is unavailable")
        link_option = ["-s"] if not follow_symlinks else []
        try:
            listed = subprocess.run(
                ["xattr", *link_option, os.fspath(path)],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            ).stdout
        except subprocess.CalledProcessError as error:
            raise ManifestError(f"cannot list xattrs for {path}: {error.stderr.strip()}") from error
        values: dict[str, str] = {}
        for name in sorted(line for line in listed.splitlines() if line):
            try:
                encoded = subprocess.run(
                    ["xattr", "-p", *link_option, "-x", name, os.fspath(path)],
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                ).stdout
            except subprocess.CalledProcessError as error:
                raise ManifestError(
                    f"cannot read xattr {name!r} for {path}: {error.stderr.strip()}"
                ) from error
            try:
                raw = bytes.fromhex("".join(encoded.split()))
            except ValueError as error:
                raise ManifestError(f"xattr {name!r} for {path} is not valid hex") from error
            values[name] = base64.b64encode(raw).decode("ascii")
        return values
    try:
        names = sorted(os.listxattr(path, follow_symlinks=follow_symlinks))  # type: ignore[attr-defined]
    except OSError as error:
        raise ManifestError(f"cannot list xattrs for {path}: {error}") from error
    values: dict[str, str] = {}
    for name in names:
        try:
            raw = os.getxattr(path, name, follow_symlinks=follow_symlinks)  # type: ignore[attr-defined]
        except OSError as error:
            raise ManifestError(f"cannot read xattr {name!r} for {path}: {error}") from error
        values[name] = base64.b64encode(raw).decode("ascii")
    return values


def file_digest(path: Path, before: os.stat_result) -> str:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or identity(opened) != identity(before):
            raise ManifestError(f"regular file changed before hashing: {path}")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        after = os.fstat(descriptor)
        if identity(after) != identity(opened):
            raise ManifestError(f"regular file changed while hashing: {path}")
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def metadata_fields(metadata: os.stat_result) -> dict[str, Any]:
    return {
        "gid": metadata.st_gid,
        "mode": stat.S_IMODE(metadata.st_mode),
        "uid": metadata.st_uid,
    }


def is_overlay_whiteout(metadata: os.stat_result) -> bool:
    return (
        stat.S_ISCHR(metadata.st_mode)
        and os.major(metadata.st_rdev) == 0
        and os.minor(metadata.st_rdev) == 0
    )


def walk_tree(name: str, root: Path) -> list[dict[str, Any]]:
    try:
        root_metadata = root.lstat()
    except OSError as error:
        raise ManifestError(f"cannot stat tree root {root}: {error}") from error
    if not stat.S_ISDIR(root_metadata.st_mode) or root.is_symlink():
        raise ManifestError(f"tree root is not a real directory: {root}")

    entries: list[dict[str, Any]] = []
    hardlink_candidates: dict[tuple[int, int], list[str]] = {}

    def visit(path: Path, relative: PurePosixPath | None) -> None:
        try:
            metadata = path.lstat()
        except OSError as error:
            raise ManifestError(f"cannot stat {path}: {error}") from error
        manifest_path = stable_path(name, relative)
        item: dict[str, Any] = {"path": manifest_path, **metadata_fields(metadata)}

        if stat.S_ISDIR(metadata.st_mode):
            item["type"] = "directory"
            item["xattrs"] = xattrs(path, follow_symlinks=False)
            entries.append(item)
            try:
                children = sorted(os.scandir(path), key=lambda child: os.fsencode(child.name))
            except OSError as error:
                raise ManifestError(f"cannot scan directory {path}: {error}") from error
            for child in children:
                child_relative = (
                    PurePosixPath(child.name)
                    if relative is None
                    else relative / child.name
                )
                visit(Path(child.path), child_relative)
            return

        if stat.S_ISREG(metadata.st_mode):
            item.update(
                {
                    "sha256": file_digest(path, metadata),
                    "size": metadata.st_size,
                    "type": "file",
                    "xattrs": xattrs(path, follow_symlinks=False),
                }
            )
            entries.append(item)
            if metadata.st_nlink > 1:
                hardlink_candidates.setdefault((metadata.st_dev, metadata.st_ino), []).append(
                    manifest_path
                )
            return

        if stat.S_ISLNK(metadata.st_mode):
            try:
                target = os.readlink(path)
            except OSError as error:
                raise ManifestError(f"cannot read symlink {path}: {error}") from error
            item.update(
                {
                    "target": target,
                    "type": "symlink",
                    "xattrs": xattrs(path, follow_symlinks=False),
                }
            )
            entries.append(item)
            return

        # containers/storage represents OCI whiteouts in an extracted overlay
        # graphroot as character devices with the reserved 0:0 device number.
        # They are required for a faithful offline image store. No other device
        # node is accepted in a preload tree.
        if stat.S_ISCHR(metadata.st_mode):
            if not is_overlay_whiteout(metadata):
                raise ManifestError(f"unsupported character device at {path}")
            item.update(
                {
                    "device": "0:0",
                    "type": "overlay-whiteout",
                    "xattrs": xattrs(path, follow_symlinks=False),
                }
            )
            entries.append(item)
            return

        raise ManifestError(f"unsupported seed entry type at {path}")

    visit(root, None)
    hardlink_roots: dict[str, str] = {}
    for paths in hardlink_candidates.values():
        if len(paths) < 2:
            raise ManifestError(f"hard-link count changed while walking: {paths[0]}")
        representative = min(paths)
        for path in paths:
            hardlink_roots[path] = representative
    for item in entries:
        if item["path"] in hardlink_roots:
            item["hardlink_to"] = hardlink_roots[item["path"]]
    return entries


def write_manifest(trees: list[tuple[str, Path]], output: Path) -> None:
    names = [name for name, _ in trees]
    if not trees or len(names) != len(set(names)):
        raise ManifestError("tree names must be non-empty and unique")
    entries: list[dict[str, Any]] = []
    for name, root in sorted(trees):
        entries.extend(walk_tree(name, root))
    # A depth-first walk is deterministic but not globally lexicographic.  For
    # example, "tree/bucket-archive" sorts before "tree/bucket/child" even
    # though DFS visits the child before returning to the sibling.  Canonical
    # manifests therefore sort the completed cross-tree namespace explicitly.
    entries.sort(key=lambda entry: entry["path"])
    paths = [entry["path"] for entry in entries]
    if len(paths) != len(set(paths)):
        raise ManifestError("manifest paths are not unique")
    document = {
        "entries": entries,
        "schema": "neural-ice-offline-seed-tree-v1",
        "trees": sorted(names),
    }
    encoded = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(output, flags, 0o600)
    try:
        view = memoryview(encoded)
        while view:
            written = os.write(descriptor, view)
            if written == 0:
                raise ManifestError(f"short write while creating manifest: {output}")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tree", action="append", required=True, type=parse_tree)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        write_manifest(arguments.tree, arguments.output)
    except (ManifestError, OSError) as error:
        print(f"REFUSED: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
