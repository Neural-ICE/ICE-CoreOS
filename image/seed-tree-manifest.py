#!/usr/bin/env python3
"""Create an exact, deterministic manifest for an offline seed tree.

The manifest deliberately excludes timestamps and inode numbers, which change
when a seed is copied to XFS. It includes every namespace entry, file digest,
mode, owner, symlink target, hard-link relationship and extended attribute.

Its caller must supply stable input trees (normally immutable build outputs or
read-only snapshots) and a caller-owned exclusive output directory. On Linux,
the authoritative CLI requires host root with CAP_SYS_ADMIN so trusted.*
attributes cannot be silently hidden. The final-media gate owns mount
isolation, topology, workspace exclusivity and capacity enforcement.
Identity rechecks detect some accidental changes but are defense in depth, not
a substitute for that caller-provided stable snapshot.
"""

from __future__ import annotations

import argparse
import base64
import errno
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import sqlite3
import stat
import struct
import subprocess
import sys
from typing import Any


MAX_PREFLIGHT_DIRECTORIES = 1_000_000
CAP_SYS_ADMIN = 21
BTRFS_SUPER_MAGIC = 0x9123683E
INITIAL_ID_MAP = ((0, 0, 4294967295),)


class ManifestError(RuntimeError):
    pass


def linux_effective_capabilities() -> int:
    try:
        for line in Path("/proc/self/status").read_text(encoding="ascii").splitlines():
            name, separator, value = line.partition(":")
            if separator and name == "CapEff":
                return int(value.strip(), 16)
    except (OSError, UnicodeError, ValueError) as error:
        raise ManifestError(f"cannot determine Linux effective capabilities: {error}") from error
    raise ManifestError("cannot determine Linux effective capabilities: CapEff is absent")


def linux_id_map(name: str) -> tuple[tuple[int, int, int], ...]:
    try:
        rows = []
        for line in Path(f"/proc/self/{name}_map").read_text(encoding="ascii").splitlines():
            fields = line.split()
            if len(fields) != 3:
                raise ValueError(f"invalid {name}_map row")
            rows.append(tuple(int(field) for field in fields))
    except (OSError, UnicodeError, ValueError) as error:
        raise ManifestError(f"cannot determine Linux {name} namespace: {error}") from error
    return tuple(rows)


def require_initial_linux_user_namespace() -> None:
    if linux_id_map("uid") != INITIAL_ID_MAP or linux_id_map("gid") != INITIAL_ID_MAP:
        raise ManifestError(
            "authoritative Linux manifests require the initial host user namespace"
        )
    try:
        current_namespace = os.stat("/proc/self/ns/user")
        init_namespace = os.stat("/proc/1/ns/user")
    except OSError as error:
        raise ManifestError(f"cannot verify the Linux host user namespace: {error}") from error
    if (current_namespace.st_dev, current_namespace.st_ino) != (
        init_namespace.st_dev,
        init_namespace.st_ino,
    ):
        raise ManifestError(
            "authoritative Linux manifests require the initial host user namespace"
        )


def require_complete_xattr_visibility() -> None:
    if sys.platform != "linux":
        return
    if os.geteuid() != 0:
        raise ManifestError(
            "authoritative Linux manifests require host root for complete xattr visibility"
        )
    require_initial_linux_user_namespace()
    capabilities = linux_effective_capabilities()
    if not capabilities & (1 << CAP_SYS_ADMIN):
        raise ManifestError(
            "authoritative Linux manifests require CAP_SYS_ADMIN for complete xattr visibility"
        )


def linux_filesystem_magic(descriptor: int) -> int:
    # fstatfs(2) starts with a native long f_type on every supported Linux ABI.
    import ctypes

    buffer = ctypes.create_string_buffer(256)
    libc = ctypes.CDLL(None, use_errno=True)
    result = libc.fstatfs(descriptor, ctypes.byref(buffer))
    if result != 0:
        error_number = ctypes.get_errno()
        raise ManifestError(
            f"cannot identify input filesystem: {os.strerror(error_number)}"
        )
    return ctypes.c_ulong.from_buffer(buffer).value


def reject_ambiguous_inode_namespace(descriptor: int, location: str) -> None:
    if sys.platform != "linux":
        return
    if linux_filesystem_magic(descriptor) == BTRFS_SUPER_MAGIC:
        raise ManifestError(
            "Btrfs input is unsupported because subvolumes can reuse inode identities: "
            f"{location}"
        )


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


def xattrs(path: Path | str, *, follow_symlinks: bool) -> dict[str, str]:
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


def file_digest(path: Path | str, before: os.stat_result) -> str:
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


def revalidate(path: Path | str, before: os.stat_result, kind: str) -> None:
    try:
        after = os.lstat(path)
    except OSError as error:
        raise ManifestError(f"cannot re-stat {kind} {path}: {error}") from error
    if identity(after) != identity(before):
        raise ManifestError(f"{kind} changed while walking: {path}")


def inspect_entry(
    name: str,
    path: Path | str,
    relative: PurePosixPath | None,
    expected: os.stat_result | None,
    spool: sqlite3.Connection,
) -> tuple[dict[str, Any], os.stat_result]:
    try:
        metadata = os.lstat(path)
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
        digest: str | None = None
        linked_identity = inode_key(metadata)
        if metadata.st_nlink > 1:
            cached = spool.execute(
                "SELECT sha256 FROM file_digests WHERE identity = ?",
                (linked_identity,),
            ).fetchone()
            if cached is not None:
                digest = cached[0]
        if digest is None:
            digest = file_digest(path, metadata)
            if metadata.st_nlink > 1:
                spool.execute(
                    "INSERT OR IGNORE INTO file_digests(identity, sha256) VALUES (?, ?)",
                    (linked_identity, digest),
                )
        item.update(
            {
                "sha256": digest,
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


def walk_tree_by_path(name: str, root: Path, spool: sqlite3.Connection):
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
        item, metadata = inspect_entry(name, path, relative, expected, spool)
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


def directory_open_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )


def open_tree_directory(root: Path, relative: PurePosixPath | None) -> int:
    absolute_root = Path(os.path.abspath(root))
    flags = directory_open_flags()
    try:
        descriptor = os.open(Path(absolute_root.anchor), flags)
        try:
            for component in absolute_root.parts[1:]:
                child = os.open(component, flags, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
            if relative is not None:
                for component in relative.parts:
                    child = os.open(component, flags, dir_fd=descriptor)
                    os.close(descriptor)
                    descriptor = child
        except BaseException:
            os.close(descriptor)
            raise
    except OSError as error:
        location = stable_path(os.fspath(root), relative)
        raise ManifestError(f"cannot open tree directory {location}: {error}") from error
    return descriptor


def linux_descriptor_path(descriptor: int, name: str | None = None) -> Path | str:
    if name is None:
        # The trailing slash forces the procfs descriptor symlink to resolve to
        # the retained directory itself. pathlib would normalize a final "."
        # away and lstat the procfs symlink instead.
        return f"/proc/self/fd/{descriptor}/"
    return Path(f"/proc/self/fd/{descriptor}") / name


def walk_tree_by_descriptor(name: str, root: Path, spool: sqlite3.Connection):
    root_descriptor = open_tree_directory(root, None)
    try:
        reject_ambiguous_inode_namespace(root_descriptor, os.fspath(root))
        root_metadata = os.fstat(root_descriptor)
    finally:
        os.close(root_descriptor)
    if not stat.S_ISDIR(root_metadata.st_mode):
        raise ManifestError(f"tree root is not a real directory: {root}")

    spool.execute("DELETE FROM pending")
    spool.execute(
        "INSERT INTO pending(path, relative_path) VALUES (?, ?)",
        (b"", None),
    )
    first = True
    while True:
        pending = spool.execute(
            "SELECT id, relative_path FROM pending ORDER BY id LIMIT 1"
        ).fetchone()
        if pending is None:
            break
        row_id, encoded_relative_path = pending
        spool.execute("DELETE FROM pending WHERE id = ?", (row_id,))
        relative = decode_relative(encoded_relative_path)
        descriptor = open_tree_directory(root, relative)
        directory_path = linux_descriptor_path(descriptor)
        try:
            expected = root_metadata if first else None
            first = False
            item, metadata = inspect_entry(
                name,
                directory_path,
                relative,
                expected,
                spool,
            )
            yield item, metadata
            try:
                with os.scandir(descriptor) as iterator:
                    for child in iterator:
                        child_relative = (
                            PurePosixPath(child.name)
                            if relative is None
                            else relative / child.name
                        )
                        if child.is_dir(follow_symlinks=False):
                            spool.execute(
                                "INSERT INTO pending(path, relative_path) VALUES (?, ?)",
                                (b"", encode_relative(child_relative)),
                            )
                            continue
                        child_path = linux_descriptor_path(descriptor, child.name)
                        child_item, child_metadata = inspect_entry(
                            name,
                            child_path,
                            child_relative,
                            None,
                            spool,
                        )
                        yield child_item, child_metadata
            except OSError as error:
                raise ManifestError(
                    f"cannot scan directory {stable_path(name, relative)}: {error}"
                ) from error
            revalidate(directory_path, metadata, "seed directory")
        finally:
            os.close(descriptor)


def walk_tree(name: str, root: Path, spool: sqlite3.Connection):
    if sys.platform == "linux":
        yield from walk_tree_by_descriptor(name, root, spool)
    else:
        yield from walk_tree_by_path(name, root, spool)


def path_sort_key(path: str) -> bytes:
    return path.encode("utf-8", errors="surrogatepass")


def append_locator(
    queue,
    tree_index: int,
    relative: PurePosixPath | None,
) -> None:
    encoded = encode_relative(relative) or b""
    if len(encoded) > 0xFFFFFFFF:
        raise ManifestError("relative filesystem path is too long to queue")
    queue.seek(0, os.SEEK_END)
    queue.write(struct.pack(">II", tree_index, len(encoded)))
    queue.write(encoded)


def read_locator(
    queue,
    offset: int,
) -> tuple[tuple[int, PurePosixPath | None] | None, int]:
    queue.seek(offset)
    header = queue.read(8)
    if not header:
        return None, offset
    if len(header) != 8:
        raise ManifestError("directory preflight queue is truncated")
    tree_index, length = struct.unpack(">II", header)
    encoded = queue.read(length)
    if len(encoded) != length:
        raise ManifestError("directory preflight queue is truncated")
    relative = decode_relative(encoded) if encoded else None
    return (tree_index, relative), queue.tell()


def open_preflight_queue(parent_descriptor: int):
    close_on_exec = getattr(os, "O_CLOEXEC", 0)
    temporary_flag = getattr(os, "O_TMPFILE", 0) if sys.platform == "linux" else 0
    if temporary_flag:
        flags = os.O_RDWR | temporary_flag | close_on_exec
        try:
            descriptor = os.open(".", flags, 0o600, dir_fd=parent_descriptor)
        except OSError as error:
            if error.errno not in {
                errno.EINVAL,
                errno.EISDIR,
                errno.ENOENT,
                errno.EOPNOTSUPP,
                errno.EPERM,
            }:
                raise ManifestError(
                    f"cannot create anonymous directory preflight storage: {error}"
                ) from error
        else:
            return os.fdopen(descriptor, "w+b", buffering=0)

    temporary_name = f".seed-manifest-preflight-{os.urandom(16).hex()}"
    flags = (
        os.O_RDWR
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | close_on_exec
    )
    descriptor: int | None = None
    try:
        descriptor = os.open(
            temporary_name,
            flags,
            0o600,
            dir_fd=parent_descriptor,
        )
        os.fchmod(descriptor, 0o600)
        os.unlink(temporary_name, dir_fd=parent_descriptor)
        os.fsync(parent_descriptor)
    except OSError as error:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(temporary_name, dir_fd=parent_descriptor)
            os.fsync(parent_descriptor)
        except OSError:
            pass
        raise ManifestError(
            f"cannot create anonymous directory preflight storage: {error}"
        ) from error
    return os.fdopen(descriptor, "w+b", buffering=0)


def output_parent_aliases_input(
    trees: list[tuple[str, Path]],
    parent_descriptor: int,
    parent_metadata: os.stat_result,
) -> bool:
    target_identity = (parent_metadata.st_dev, parent_metadata.st_ino)
    visited: set[tuple[int, int]] = set()
    with open_preflight_queue(parent_descriptor) as queue:
        enqueued = 0
        for tree_index, _ in enumerate(trees):
            enqueued += 1
            if enqueued > MAX_PREFLIGHT_DIRECTORIES:
                raise ManifestError("directory preflight limit exceeded")
            append_locator(queue, tree_index, None)
        offset = 0
        while True:
            locator, offset = read_locator(queue, offset)
            if locator is None:
                return False
            tree_index, relative = locator
            try:
                _, root = trees[tree_index]
            except IndexError as error:
                raise ManifestError("directory preflight queue has an invalid tree") from error
            descriptor = open_tree_directory(root, relative)
            try:
                reject_ambiguous_inode_namespace(
                    descriptor,
                    stable_path(trees[tree_index][0], relative),
                )
                metadata = os.fstat(descriptor)
                directory_identity = (metadata.st_dev, metadata.st_ino)
                if directory_identity == target_identity:
                    return True
                if directory_identity in visited:
                    raise ManifestError(
                        "directory identity revisited during preflight: "
                        f"{stable_path(trees[tree_index][0], relative)}"
                    )
                visited.add(directory_identity)
                if len(visited) > MAX_PREFLIGHT_DIRECTORIES:
                    raise ManifestError("directory preflight limit exceeded")
                with os.scandir(descriptor) as iterator:
                    for child in iterator:
                        if child.is_dir(follow_symlinks=False):
                            enqueued += 1
                            if enqueued > MAX_PREFLIGHT_DIRECTORIES:
                                raise ManifestError("directory preflight limit exceeded")
                            child_relative = (
                                PurePosixPath(child.name)
                                if relative is None
                                else relative / child.name
                            )
                            append_locator(queue, tree_index, child_relative)
            except OSError as error:
                raise ManifestError(
                    "cannot scan directory preflight path "
                    f"{stable_path(trees[tree_index][0], relative)}: {error}"
                ) from error
            finally:
                os.close(descriptor)


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
) -> bool:
    try:
        metadata = os.stat(
            name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return False
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
    return True


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
    if owned_names:
        try:
            os.fsync(parent_descriptor)
        except OSError as cleanup_error:
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


def spool_database_path(spool_descriptor: int, spool_name: str, parent: Path) -> Path:
    if sys.platform == "linux":
        return Path(f"/proc/self/fd/{spool_descriptor}/entries.sqlite3")
    return parent / spool_name / "entries.sqlite3"


def remove_spool(
    parent_descriptor: int,
    spool_descriptor: int,
    spool_name: str,
    spool_identity: tuple[int, int],
    original_error: BaseException | None = None,
) -> None:
    cleanup_errors: list[BaseException] = []
    try:
        os.unlink("entries.sqlite3", dir_fd=spool_descriptor)
    except FileNotFoundError:
        pass
    except OSError as cleanup_error:
        cleanup_errors.append(cleanup_error)
    try:
        metadata = os.stat(
            spool_name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        metadata = None
    except OSError as cleanup_error:
        metadata = None
        cleanup_errors.append(cleanup_error)
    if metadata is not None:
        if (metadata.st_dev, metadata.st_ino) != spool_identity:
            cleanup_errors.append(
                ManifestError(f"refusing to remove replaced manifest spool: {spool_name}")
            )
        else:
            try:
                os.rmdir(spool_name, dir_fd=parent_descriptor)
            except OSError as cleanup_error:
                cleanup_errors.append(cleanup_error)
    try:
        os.fsync(parent_descriptor)
    except OSError as cleanup_error:
        cleanup_errors.append(cleanup_error)
    if cleanup_errors:
        cause = original_error if original_error is not None else cleanup_errors[0]
        raise ManifestError("manifest spool cleanup failed") from cause


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
    descriptor: int | None = None
    spool_name: str | None = None
    spool_created = False
    spool_descriptor: int | None = None
    spool_identity: tuple[int, int] | None = None
    spool: sqlite3.Connection | None = None
    committed = False
    try:
        if output_parent_aliases_input(trees, parent_descriptor, parent_metadata):
            raise ManifestError(f"output path is inside input tree: {output}")
        if not secure_parent_is_unchanged(supplied_parent, parent_metadata):
            raise ManifestError(f"output directory changed before traversal: {output}")

        spool_name = f".seed-manifest-spool-{os.urandom(16).hex()}"
        os.mkdir(spool_name, 0o700, dir_fd=parent_descriptor)
        spool_created = True
        path_only_flag = getattr(os, "O_PATH", 0) if sys.platform == "linux" else 0
        spool_flags = path_only_flag or os.O_RDONLY
        spool_flags |= (
            getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        if not path_only_flag:
            # Non-Linux callers are restricted to the documented exclusive
            # output directory, so this cannot target an attacker replacement.
            os.chmod(spool_name, 0o700, dir_fd=parent_descriptor)
        spool_descriptor = os.open(
            spool_name,
            spool_flags,
            dir_fd=parent_descriptor,
        )
        spool_metadata = os.fstat(spool_descriptor)
        spool_identity = (spool_metadata.st_dev, spool_metadata.st_ino)
        if path_only_flag:
            os.chmod(f"/proc/self/fd/{spool_descriptor}", 0o700)
        if not secure_parent_is_unchanged(supplied_parent, parent_metadata):
            raise ManifestError(f"output directory changed before spool creation: {output}")
        database_path = spool_database_path(
            spool_descriptor,
            spool_name,
            supplied_parent,
        )
        spool = sqlite3.connect(database_path)
        os.chmod(
            "entries.sqlite3",
            0o600,
            dir_fd=spool_descriptor,
        )
        spool.execute("PRAGMA temp_store=MEMORY")
        spool.execute("PRAGMA cache_size=-2048")
        spool.execute("PRAGMA automatic_index=OFF")
        spool.execute("PRAGMA journal_mode=OFF")
        spool.execute("PRAGMA synchronous=OFF")
        spool.execute(
            "CREATE TABLE entries (path_key BLOB PRIMARY KEY, entry BLOB NOT NULL)"
        )
        spool.execute(
            "CREATE TABLE hardlinks (path_key BLOB PRIMARY KEY, identity BLOB NOT NULL)"
        )
        spool.execute(
            "CREATE TABLE file_digests (identity BLOB PRIMARY KEY, sha256 TEXT NOT NULL)"
        )
        spool.execute(
            """
            CREATE TABLE hardlink_groups (
                identity BLOB PRIMARY KEY,
                representative BLOB NOT NULL,
                link_count INTEGER NOT NULL
            )
            """
        )
        spool.execute("CREATE TABLE directories (identity BLOB PRIMARY KEY)")
        spool.execute(
            """
            CREATE TABLE pending (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                path BLOB NOT NULL,
                relative_path BLOB
            )
            """
        )
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
                    raise ManifestError(f"duplicate manifest path: {manifest_path}") from error
                if stat.S_ISDIR(metadata.st_mode):
                    spool.execute(
                        "INSERT OR IGNORE INTO directories(identity) VALUES (?)",
                        (inode_key(metadata),),
                    )
                elif metadata.st_nlink > 1:
                    linked_identity = inode_key(metadata)
                    spool.execute(
                        "INSERT INTO hardlinks(path_key, identity) VALUES (?, ?)",
                        (sort_key, linked_identity),
                    )
                    spool.execute(
                        """
                        INSERT INTO hardlink_groups(identity, representative, link_count)
                        VALUES (?, ?, 1)
                        ON CONFLICT(identity) DO UPDATE SET
                            representative = CASE
                                WHEN excluded.representative < representative
                                THEN excluded.representative
                                ELSE representative
                            END,
                            link_count = link_count + 1
                        """,
                        (linked_identity, sort_key),
                    )

        if directory_was_manifested(spool, parent_metadata):
            raise ManifestError(f"output path is inside input tree: {output}")

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
            SELECT entry.entry, representative.entry
            FROM entries AS entry
            LEFT JOIN hardlinks AS link ON link.path_key = entry.path_key
            LEFT JOIN hardlink_groups AS linked_group
                ON linked_group.identity = link.identity AND linked_group.link_count > 1
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
                json.dumps(item, sort_keys=True, separators=(",", ":")).encode("ascii"),
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
        try:
            spool.rollback()
        finally:
            spool.close()
            spool = None
        remove_spool(
            parent_descriptor,
            spool_descriptor,
            spool_name,
            spool_identity,
        )
        os.close(spool_descriptor)
        spool_descriptor = None
        spool_name = None
        spool_identity = None
        spool_created = False

        if not secure_parent_is_unchanged(supplied_parent, parent_metadata):
            raise ManifestError(f"output directory changed while creating manifest: {output}")
        os.link(
            temporary_name,
            output_name,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
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
        committed = True
    except BaseException as error:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        cleanup_errors: list[BaseException] = []
        if spool is not None:
            try:
                spool.rollback()
            except BaseException as cleanup_error:
                cleanup_errors.append(cleanup_error)
            try:
                spool.close()
            except BaseException as cleanup_error:
                cleanup_errors.append(cleanup_error)
            spool = None
        if (
            spool_name is not None
            and spool_descriptor is not None
            and spool_identity is not None
        ):
            try:
                remove_spool(
                    parent_descriptor,
                    spool_descriptor,
                    spool_name,
                    spool_identity,
                    error,
                )
            except BaseException as cleanup_error:
                cleanup_errors.append(cleanup_error)
        elif spool_created and spool_name is not None:
            try:
                os.rmdir(spool_name, dir_fd=parent_descriptor)
                os.fsync(parent_descriptor)
            except FileNotFoundError:
                pass
            except BaseException as cleanup_error:
                cleanup_errors.append(cleanup_error)
        if spool_descriptor is not None:
            try:
                os.close(spool_descriptor)
            except OSError as cleanup_error:
                cleanup_errors.append(cleanup_error)
            spool_descriptor = None
        owned_names: list[tuple[str, tuple[int, int]]] = []
        if temporary_identity is not None:
            owned_names.append((output_name, temporary_identity))
        if temporary_identity is not None:
            owned_names.append((temporary_name, temporary_identity))
        try:
            remove_owned_names(parent_descriptor, owned_names, error)
        except BaseException as cleanup_error:
            cleanup_errors.append(cleanup_error)
        if cleanup_errors:
            raise ManifestError("manifest failure cleanup was incomplete") from cleanup_errors[0]
        raise
    finally:
        try:
            os.close(parent_descriptor)
        except OSError:
            if not committed:
                raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tree", action="append", required=True, type=parse_tree)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        require_complete_xattr_visibility()
        write_manifest(
            arguments.tree,
            arguments.output,
        )
    except (ManifestError, OSError, sqlite3.Error) as error:
        print(f"REFUSED: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
