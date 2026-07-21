#!/usr/bin/env python3
"""Create an exact, deterministic manifest for an offline seed tree.

The manifest deliberately excludes timestamps and inode numbers, which change
when a seed is copied to XFS. It includes every namespace entry, file digest,
mode, owner, symlink target, hard-link relationship and extended attribute.

This is an unprivileged serialization primitive. Its caller must supply stable
input trees (normally immutable build outputs or read-only snapshots). The
final-media gate owns mount isolation, topology and capacity enforcement.
Identity rechecks detect some accidental changes but are defense in depth, not
a substitute for that caller-provided stable snapshot.
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


def inode_key(metadata: os.stat_result) -> bytes:
    return f"{metadata.st_dev}:{metadata.st_ino}".encode("ascii")


def encode_relative(relative: PurePosixPath | None) -> bytes | None:
    if relative is None:
        return None
    return relative.as_posix().encode("utf-8", errors="surrogatepass")


def decode_relative(encoded: bytes | None) -> PurePosixPath | None:
    if encoded is None:
        return None
    return PurePosixPath(encoded.decode("utf-8", errors="surrogatepass"))


def walk_tree(name: str, root: Path, spool: sqlite3.Connection):
    try:
        root_metadata = root.lstat()
    except OSError as error:
        raise ManifestError(f"cannot stat tree root {root}: {error}") from error
    if not stat.S_ISDIR(root_metadata.st_mode):
        raise ManifestError(f"tree root is not a real directory: {root}")

    spool.execute("DELETE FROM pending")
    spool.execute(
        "INSERT INTO pending(path, relative_path) VALUES (?, ?)",
        (os.fsencode(root), None),
    )
    first = True
    while True:
        pending = spool.execute(
            "SELECT id, path, relative_path FROM pending ORDER BY id LIMIT 1"
        ).fetchone()
        if pending is None:
            break
        row_id, encoded_path, encoded_relative_path = pending
        spool.execute("DELETE FROM pending WHERE id = ?", (row_id,))
        path = Path(os.fsdecode(encoded_path))
        relative = decode_relative(encoded_relative_path)
        expected = root_metadata if first else None
        first = False
        item, metadata = inspect_entry(name, path, relative, expected)
        yield item, metadata
        if not stat.S_ISDIR(metadata.st_mode):
            continue
        try:
            with os.scandir(path) as iterator:
                for child in iterator:
                    child_relative = (
                        PurePosixPath(child.name)
                        if relative is None
                        else relative / child.name
                    )
                    spool.execute(
                        "INSERT INTO pending(path, relative_path) VALUES (?, ?)",
                        (os.fsencode(child.path), encode_relative(child_relative)),
                    )
        except OSError as error:
            raise ManifestError(f"cannot scan directory {path}: {error}") from error
        revalidate(path, metadata, "seed directory")


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
        absolute_output = Path(os.path.abspath(output))
        parent = absolute_output.parent
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
    return descriptor, absolute_output.name, parent, metadata


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


def remove_owned_names(
    parent_descriptor: int,
    owned_names: list[tuple[str, tuple[int, int]]],
    original_error: BaseException,
) -> None:
    cleanup_errors: list[BaseException] = []
    for name, created_identity in owned_names:
        try:
            remove_owned_name(
                parent_descriptor,
                name,
                created_identity,
                original_error,
            )
        except BaseException as cleanup_error:
            cleanup_errors.append(cleanup_error)
    if cleanup_errors:
        raise ManifestError(
            "one or more owned manifest files could not be cleaned up"
        ) from cleanup_errors[0]


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


def directory_was_manifested(
    spool: sqlite3.Connection,
    metadata: os.stat_result,
) -> bool:
    return (
        spool.execute(
            "SELECT 1 FROM directories WHERE identity = ?",
            (inode_key(metadata),),
        ).fetchone()
        is not None
    )


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

    parent_descriptor, output_name, supplied_parent, parent_metadata = open_output_parent(
        output
    )
    temporary_name = f".seed-manifest-{os.urandom(16).hex()}"
    temporary_identity: tuple[int, int] | None = None
    published = False
    descriptor: int | None = None
    try:
        try:
            spool_base = Path(tempfile.gettempdir()).resolve(strict=True)
            spool_base_metadata = spool_base.lstat()
        except OSError as error:
            raise ManifestError(f"cannot inspect temporary directory: {error}") from error
        if not stat.S_ISDIR(spool_base_metadata.st_mode):
            raise ManifestError(f"temporary path is not a directory: {spool_base}")
        for _, root in trees:
            if output_is_within_tree(spool_base / "seed-manifest-spool", root):
                raise ManifestError(f"temporary directory is inside input tree: {spool_base}")

        with tempfile.TemporaryDirectory(
            prefix=".seed-manifest-spool-",
            dir=spool_base,
        ) as spool_directory:
            os.chmod(spool_directory, 0o700)
            database_path = Path(spool_directory) / "entries.sqlite3"
            spool = sqlite3.connect(database_path)
            os.chmod(database_path, 0o600)
            try:
                spool.execute("PRAGMA temp_store=FILE")
                spool.execute("PRAGMA cache_size=-2048")
                spool.execute("PRAGMA journal_mode=OFF")
                spool.execute("PRAGMA synchronous=OFF")
                spool.execute(
                    "CREATE TABLE entries (path_key BLOB PRIMARY KEY, entry BLOB NOT NULL)"
                )
                spool.execute(
                    "CREATE TABLE hardlinks (identity BLOB NOT NULL, path_key BLOB NOT NULL)"
                )
                spool.execute(
                    "CREATE TABLE directories (identity BLOB PRIMARY KEY)"
                )
                spool.execute(
                    """
                    CREATE TABLE pending (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        path BLOB NOT NULL,
                        relative_path BLOB
                    )
                    """
                )
                spool.execute("CREATE INDEX hardlinks_identity ON hardlinks(identity)")
                spool.execute("CREATE INDEX hardlinks_path ON hardlinks(path_key)")
                for name, root in sorted(trees):
                    for item, metadata in walk_tree(name, root, spool):
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
                        if stat.S_ISDIR(metadata.st_mode):
                            spool.execute(
                                "INSERT OR IGNORE INTO directories(identity) VALUES (?)",
                                (inode_key(metadata),),
                            )
                        elif metadata.st_nlink > 1:
                            spool.execute(
                                "INSERT INTO hardlinks(identity, path_key) VALUES (?, ?)",
                                (inode_key(metadata), sort_key),
                            )

                if directory_was_manifested(spool, parent_metadata):
                    raise ManifestError(f"output path is inside input tree: {output}")
                if directory_was_manifested(spool, spool_base_metadata):
                    raise ManifestError(
                        f"temporary directory aliases an input tree: {spool_base}"
                    )

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
                os.fchmod(descriptor, 0o600)

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
            finally:
                try:
                    spool.rollback()
                finally:
                    spool.close()

        if not secure_parent_is_unchanged(supplied_parent, parent_metadata):
            raise ManifestError(f"output directory changed while creating manifest: {output}")
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
        if not secure_parent_is_unchanged(supplied_parent, parent_metadata):
            raise ManifestError(f"output directory changed while creating manifest: {output}")
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
        owned_names: list[tuple[str, tuple[int, int]]] = []
        if published and temporary_identity is not None:
            owned_names.append((output_name, temporary_identity))
        if temporary_identity is not None:
            owned_names.append((temporary_name, temporary_identity))
        remove_owned_names(parent_descriptor, owned_names, error)
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
