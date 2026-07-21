#!/usr/bin/env python3
"""Create an exact, deterministic manifest for an offline seed tree.

The manifest deliberately excludes timestamps and inode numbers, which change
when a seed is copied to XFS. It includes every namespace entry, file digest,
mode, owner, symlink target, hard-link relationship and extended attribute.

This is an unprivileged serialization primitive. Its caller must supply stable
input trees (normally immutable build outputs or read-only snapshots). The
final-media gate owns mount isolation, topology and capacity enforcement.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
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


def identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_rdev,
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


def is_allowed_overlay_whiteout(
    name: str,
    relative: PurePosixPath | None,
    metadata: os.stat_result,
) -> bool:
    return (
        name == "store"
        and relative is not None
        and len(relative.parts) >= 2
        and relative.parts[0] == "overlay"
        and is_overlay_whiteout(metadata)
    )


def revalidate(path: Path, before: os.stat_result, kind: str) -> None:
    try:
        after = path.lstat()
    except OSError as error:
        raise ManifestError(f"cannot re-stat {kind} {path}: {error}") from error
    if identity(after) != identity(before):
        raise ManifestError(f"{kind} changed while walking: {path}")


def inspect_entry(
    name: str,
    path: Path,
    relative: PurePosixPath | None,
    expected: os.stat_result | None,
) -> tuple[dict[str, Any], os.stat_result]:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ManifestError(f"cannot stat {path}: {error}") from error
    if expected is not None and identity(metadata) != identity(expected):
        raise ManifestError(f"tree root changed before traversal: {path}")
    manifest_path = stable_path(name, relative)
    item: dict[str, Any] = {"path": manifest_path, **metadata_fields(metadata)}

    if stat.S_ISDIR(metadata.st_mode):
        item["type"] = "directory"
        item["xattrs"] = xattrs(path, follow_symlinks=False)
    elif stat.S_ISREG(metadata.st_mode):
        item.update(
            {
                "sha256": file_digest(path, metadata),
                "size": metadata.st_size,
                "type": "file",
                "xattrs": xattrs(path, follow_symlinks=False),
            }
        )
    elif stat.S_ISLNK(metadata.st_mode):
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
    elif stat.S_ISCHR(metadata.st_mode):
        # containers/storage represents OCI whiteouts in an extracted overlay
        # graphroot as character devices with the reserved 0:0 device number.
        if not is_allowed_overlay_whiteout(name, relative, metadata):
            raise ManifestError(f"unsupported character device at {path}")
        item.update(
            {
                "device": "0:0",
                "type": "overlay-whiteout",
                "xattrs": xattrs(path, follow_symlinks=False),
            }
        )
    else:
        raise ManifestError(f"unsupported seed entry type at {path}")

    revalidate(path, metadata, "seed entry")
    return item, metadata


def walk_tree(name: str, root: Path):
    try:
        root_metadata = root.lstat()
    except OSError as error:
        raise ManifestError(f"cannot stat tree root {root}: {error}") from error
    if not stat.S_ISDIR(root_metadata.st_mode):
        raise ManifestError(f"tree root is not a real directory: {root}")

    root_item, opened_root_metadata = inspect_entry(name, root, None, root_metadata)
    yield root_item, opened_root_metadata
    try:
        root_iterator = os.scandir(root)
    except OSError as error:
        raise ManifestError(f"cannot scan directory {root}: {error}") from error

    frames: list[
        tuple[Path, PurePosixPath | None, os.stat_result, os.ScandirIterator[str]]
    ] = [(root, None, root_metadata, root_iterator)]
    try:
        while frames:
            directory, relative, directory_metadata, iterator = frames[-1]
            try:
                child = next(iterator)
            except StopIteration:
                iterator.close()
                frames.pop()
                revalidate(directory, directory_metadata, "seed directory")
                continue
            except OSError as error:
                raise ManifestError(f"cannot scan directory {directory}: {error}") from error

            child_relative = (
                PurePosixPath(child.name) if relative is None else relative / child.name
            )
            child_path = Path(child.path)
            item, metadata = inspect_entry(name, child_path, child_relative, None)
            yield item, metadata
            if stat.S_ISDIR(metadata.st_mode):
                try:
                    child_iterator = os.scandir(child_path)
                except OSError as error:
                    raise ManifestError(
                        f"cannot scan directory {child_path}: {error}"
                    ) from error
                frames.append((child_path, child_relative, metadata, child_iterator))
    finally:
        for _, _, _, iterator in frames:
            iterator.close()


def path_sort_key(path: str) -> bytes:
    return path.encode("utf-8", errors="surrogatepass")


def output_is_within_tree(output: Path, root: Path) -> bool:
    resolved_output = output.resolve(strict=False)
    resolved_root = root.resolve(strict=True)
    try:
        resolved_output.relative_to(resolved_root)
    except ValueError:
        return False
    return True


def open_output_parent(output: Path) -> tuple[int, str, Path, os.stat_result]:
    if not output.name:
        raise ManifestError(f"output must name a file: {output}")
    try:
        parent = output.parent.resolve(strict=True)
        flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(Path(parent.anchor), flags)
        try:
            for component in parent.parts[1:]:
                child = os.open(component, flags, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
        except BaseException:
            os.close(descriptor)
            raise
    except OSError as error:
        raise ManifestError(f"cannot open output directory for {output}: {error}") from error
    metadata = os.fstat(descriptor)
    if not stat.S_ISDIR(metadata.st_mode):
        os.close(descriptor)
        raise ManifestError(f"output parent is not a directory: {parent}")
    return descriptor, output.name, parent, metadata


def remove_owned_name(
    parent_descriptor: int,
    name: str,
    created_identity: tuple[int, int],
    original_error: BaseException,
) -> None:
    try:
        metadata = os.stat(
            name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return
    except OSError as cleanup_error:
        raise ManifestError(
            f"cannot inspect failed manifest file {name}: {cleanup_error}"
        ) from original_error
    if (metadata.st_dev, metadata.st_ino) != created_identity:
        raise ManifestError(
            f"refusing to remove replaced manifest file: {name}"
        ) from original_error
    try:
        os.unlink(name, dir_fd=parent_descriptor)
    except OSError as cleanup_error:
        raise ManifestError(
            f"cannot remove failed manifest file {name}: {cleanup_error}"
        ) from original_error


def write_all(descriptor: int, data: bytes, output: Path) -> None:
    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        if written == 0:
            raise ManifestError(f"short write while creating manifest: {output}")
        view = view[written:]


def secure_parent_is_unchanged(parent: Path, expected: os.stat_result) -> bool:
    descriptor, _, _, current = open_output_parent(parent / "manifest.identity-check")
    os.close(descriptor)
    return (current.st_dev, current.st_ino) == (expected.st_dev, expected.st_ino)


def write_manifest(
    trees: list[tuple[str, Path]],
    output: Path,
) -> None:
    names = [name for name, _ in trees]
    if not trees or len(names) != len(set(names)):
        raise ManifestError("tree names must be non-empty and unique")
    for _, root in trees:
        if output_is_within_tree(output, root):
            raise ManifestError(f"output path is inside input tree: {output}")

    with tempfile.TemporaryDirectory(prefix="seed-tree-manifest-") as spool_directory:
        database_path = Path(spool_directory) / "entries.sqlite3"
        with sqlite3.connect(database_path) as spool:
            spool.execute("PRAGMA temp_store=FILE")
            spool.execute("PRAGMA cache_size=-2048")
            spool.execute(
                "CREATE TABLE entries (path_key BLOB PRIMARY KEY, entry BLOB NOT NULL)"
            )
            spool.execute(
                "CREATE TABLE hardlinks (identity BLOB NOT NULL, path_key BLOB NOT NULL)"
            )
            spool.execute("CREATE INDEX hardlinks_identity ON hardlinks(identity)")
            spool.execute("CREATE INDEX hardlinks_path ON hardlinks(path_key)")
            for name, root in sorted(trees):
                for item, metadata in walk_tree(name, root):
                    manifest_path = item["path"]
                    sort_key = path_sort_key(manifest_path)
                    try:
                        spool.execute(
                            "INSERT INTO entries(path_key, entry) VALUES (?, ?)",
                            (
                                sort_key,
                                json.dumps(
                                    item,
                                    sort_keys=True,
                                    separators=(",", ":"),
                                ).encode("ascii"),
                            ),
                        )
                    except sqlite3.IntegrityError as error:
                        raise ManifestError(
                            f"duplicate manifest path: {manifest_path}"
                        ) from error
                    if metadata.st_nlink > 1 and not stat.S_ISDIR(metadata.st_mode):
                        identity_key = (
                            f"{metadata.st_dev}:{metadata.st_ino}".encode("ascii")
                        )
                        spool.execute(
                            "INSERT INTO hardlinks(identity, path_key) VALUES (?, ?)",
                            (identity_key, sort_key),
                        )

            parent_descriptor, output_name, canonical_parent, parent_metadata = (
                open_output_parent(output)
            )
            temporary_name = f".{output_name}.tmp-{os.getpid()}-{os.urandom(16).hex()}"
            temporary_identity: tuple[int, int] | None = None
            published = False
            descriptor: int | None = None
            try:
                flags = (
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_NOFOLLOW", 0)
                )
                descriptor = os.open(
                    temporary_name,
                    flags,
                    0o600,
                    dir_fd=parent_descriptor,
                )
                created_metadata = os.fstat(descriptor)
                temporary_identity = (created_metadata.st_dev, created_metadata.st_ino)

                write_all(descriptor, b'{"entries":[', output)
                first = True
                for encoded_item, encoded_representative in spool.execute(
                    """
                    WITH groups AS (
                        SELECT identity, MIN(path_key) AS representative
                        FROM hardlinks
                        GROUP BY identity
                        HAVING COUNT(*) > 1
                    )
                    SELECT entry.entry, representative.entry
                    FROM entries AS entry
                    LEFT JOIN hardlinks AS link ON link.path_key = entry.path_key
                    LEFT JOIN groups AS linked_group ON linked_group.identity = link.identity
                    LEFT JOIN entries AS representative
                        ON representative.path_key = linked_group.representative
                    ORDER BY entry.path_key
                    """
                ):
                    item = json.loads(encoded_item)
                    if encoded_representative is not None:
                        item["hardlink_to"] = json.loads(encoded_representative)["path"]
                    if not first:
                        write_all(descriptor, b",", output)
                    write_all(
                        descriptor,
                        json.dumps(
                            item,
                            sort_keys=True,
                            separators=(",", ":"),
                        ).encode("ascii"),
                        output,
                    )
                    first = False
                suffix = (
                    '],"schema":"neural-ice-offline-seed-tree-v1","trees":'
                    + json.dumps(sorted(names), separators=(",", ":"))
                    + "}\n"
                ).encode("ascii")
                write_all(descriptor, suffix, output)
                os.fsync(descriptor)
                os.close(descriptor)
                descriptor = None

                os.link(
                    temporary_name,
                    output_name,
                    src_dir_fd=parent_descriptor,
                    dst_dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
                published = True
                final_metadata = os.stat(
                    output_name,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
                if (final_metadata.st_dev, final_metadata.st_ino) != temporary_identity:
                    raise ManifestError(f"published manifest identity changed: {output}")
                if not secure_parent_is_unchanged(canonical_parent, parent_metadata):
                    raise ManifestError(
                        f"output directory changed while creating manifest: {output}"
                    )
                os.fsync(parent_descriptor)
                os.unlink(temporary_name, dir_fd=parent_descriptor)
                os.fsync(parent_descriptor)
                temporary_identity = None
            except BaseException as error:
                if descriptor is not None:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
                if published and temporary_identity is not None:
                    remove_owned_name(
                        parent_descriptor,
                        output_name,
                        temporary_identity,
                        error,
                    )
                if temporary_identity is not None:
                    remove_owned_name(
                        parent_descriptor,
                        temporary_name,
                        temporary_identity,
                        error,
                    )
                raise
            finally:
                os.close(parent_descriptor)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tree", action="append", required=True, type=parse_tree)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        write_manifest(
            arguments.tree,
            arguments.output,
        )
    except (ManifestError, OSError) as error:
        print(f"REFUSED: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
