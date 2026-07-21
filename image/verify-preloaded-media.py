#!/usr/bin/env python3
"""Fail-closed acceptance gate for a finalized PRELOADED installer raw."""

from __future__ import annotations

import argparse
import ctypes
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Any


class GateError(RuntimeError):
    pass


def run(*command: str, capture: bool = True, pass_fds: tuple[int, ...] = ()) -> str:
    try:
        result = subprocess.run(
            command,
            check=True,
            text=True,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else None,
            pass_fds=pass_fds,
        )
    except subprocess.CalledProcessError as error:
        detail = (error.stderr or error.stdout or "").strip()
        raise GateError(f"command failed: {' '.join(command)}: {detail}") from error
    return result.stdout.strip() if capture else ""


def require_commands(commands: tuple[str, ...]) -> None:
    missing = [command for command in commands if shutil.which(command) is None]
    if missing:
        raise GateError(f"required commands are missing: {', '.join(missing)}")


def fd_identity(descriptor: int) -> tuple[int, int, int, int, int]:
    metadata = os.fstat(descriptor)
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def hash_fd(descriptor: int) -> str:
    digest = hashlib.sha256()
    offset = 0
    while True:
        chunk = os.pread(descriptor, 8 * 1024 * 1024, offset)
        if not chunk:
            break
        digest.update(chunk)
        offset += len(chunk)
    return digest.hexdigest()


def read_regular(path: Path, maximum: int) -> bytes:
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
    )
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
            raise GateError(f"unsafe or oversized regular file: {path}")
        content = bytearray()
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            content.extend(chunk)
            if len(content) > maximum:
                raise GateError(f"oversized regular file: {path}")
        if fd_identity(descriptor) != (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ):
            raise GateError(f"regular file changed while reading: {path}")
        return bytes(content)
    finally:
        os.close(descriptor)


def existing_loop_for(descriptor: int) -> list[dict[str, Any]]:
    output = run(
        "losetup",
        "--json",
        "--list",
        "--output",
        "NAME,BACK-INO,BACK-MAJ:MIN,RO",
    )
    if not output:
        return []
    try:
        document = json.loads(output)
    except json.JSONDecodeError as error:
        raise GateError("losetup returned invalid JSON") from error
    if not isinstance(document, dict) or not isinstance(document.get("loopdevices", []), list):
        raise GateError("losetup returned an invalid device list")
    loops = document.get("loopdevices", [])
    metadata = os.fstat(descriptor)
    backing_device = f"{os.major(metadata.st_dev)}:{os.minor(metadata.st_dev)}"
    matches = []
    for loop in loops:
        if not isinstance(loop, dict):
            continue
        try:
            if (
                int(loop.get("back-ino", -1)) == metadata.st_ino
                and loop.get("back-maj:min") == backing_device
            ):
                matches.append(loop)
        except (TypeError, ValueError):
            continue
    return matches


def flatten_lsblk(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for node in nodes:
        result.append(node)
        result.extend(flatten_lsblk(node.get("children", [])))
    return result


def find_seed_partition(loop: str) -> tuple[str, str]:
    run("udevadm", "settle")
    output = run(
        "lsblk",
        "--json",
        "--paths",
        "--output",
        "NAME,KNAME,TYPE,PKNAME,PARTLABEL,FSTYPE,RO,PARTUUID",
        loop,
    )
    try:
        nodes = flatten_lsblk(json.loads(output)["blockdevices"])
    except (KeyError, json.JSONDecodeError) as error:
        raise GateError("lsblk returned invalid JSON") from error
    loop_name = Path(loop).name
    roots = [node for node in nodes if node.get("name") == loop]
    if len(roots) != 1 or str(roots[0].get("ro")) not in ("1", "True", "true"):
        raise GateError("loop device is not uniquely read-only")
    matches = [
        node
        for node in nodes
        if node.get("type") == "part"
        and Path(str(node.get("pkname", ""))).name == loop_name
        and node.get("partlabel") == "ni-seed"
    ]
    if len(matches) != 1:
        raise GateError("final raw must contain exactly one ni-seed child partition")
    partition = matches[0]
    if partition.get("fstype") != "xfs":
        raise GateError("ni-seed partition is not XFS")
    if str(partition.get("ro")) not in ("1", "True", "true"):
        raise GateError("ni-seed partition is not read-only")
    partuuid = partition.get("partuuid")
    if not isinstance(partuuid, str) or not partuuid:
        raise GateError("ni-seed partition lacks PARTUUID")
    return str(partition["name"]), partuuid.lower()


def verify_mount(partition: str, mountpoint: Path) -> None:
    run(
        "mount",
        "-t",
        "xfs",
        "-o",
        "ro,nosuid,nodev,noexec",
        partition,
        str(mountpoint),
        capture=False,
    )
    output = run("findmnt", "--json", "--target", str(mountpoint), "--output", "SOURCE,FSTYPE,OPTIONS")
    try:
        filesystems = json.loads(output)["filesystems"]
    except (KeyError, json.JSONDecodeError) as error:
        raise GateError("findmnt returned invalid JSON") from error
    if len(filesystems) != 1:
        raise GateError("ni-seed mount is ambiguous")
    filesystem = filesystems[0]
    source = str(filesystem.get("source", "")).split("[")[0]
    options = set(str(filesystem.get("options", "")).split(","))
    if source != partition or filesystem.get("fstype") != "xfs":
        raise GateError("ni-seed mount source or filesystem changed")
    if not {"ro", "nosuid", "nodev", "noexec"}.issubset(options):
        raise GateError("ni-seed mount lacks required read-only options")
    probe = mountpoint / ".neural-ice-write-probe"
    try:
        descriptor = os.open(probe, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as error:
        if error.errno != errno.EROFS:
            raise GateError(f"ni-seed write probe failed for an unexpected reason: {error}") from error
    else:
        os.close(descriptor)
        os.unlink(probe)
        raise GateError("ni-seed accepted a write through the release gate")


def enter_private_mount_namespace() -> None:
    clone_newns = 0x00020000
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.unshare(clone_newns) != 0:
        error_number = ctypes.get_errno()
        raise GateError(f"cannot create private mount namespace: {os.strerror(error_number)}")
    run("mount", "--make-rprivate", "/", capture=False)


def verify_seed_root(mountpoint: Path, trees: Any) -> list[str]:
    if (
        not isinstance(trees, list)
        or not trees
        or any(not isinstance(name, str) or not name for name in trees)
        or trees != sorted(set(trees))
    ):
        raise GateError("expected seed tree set is not sorted and unique")
    if not set(trees).issubset({"models", "payload", "store"}):
        raise GateError("expected seed tree set contains an unsupported root")
    if not {"models", "store"}.issubset(trees):
        raise GateError("expected seed tree set must contain models and store")
    actual: list[str] = []
    for entry in os.scandir(mountpoint):
        metadata = entry.stat(follow_symlinks=False)
        if not stat.S_ISDIR(metadata.st_mode) or entry.is_symlink():
            raise GateError(f"unsafe ni-seed root entry: {entry.name}")
        actual.append(entry.name)
    actual.sort()
    if actual != trees:
        raise GateError("final ni-seed root namespace differs from the approved tree set")
    return trees


def validate_filename(filename: str) -> None:
    if filename in ("", ".", "..") or any(
        character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
        for character in filename
    ):
        raise GateError(f"unsafe output filename: {filename!r}")


def unlink_at(directory_descriptor: int, filename: str) -> None:
    try:
        os.unlink(filename, dir_fd=directory_descriptor)
    except FileNotFoundError:
        pass


def publish_bytes_noreplace(path: Path, content: bytes, mode: int = 0o644) -> None:
    validate_filename(path.name)
    parent = path.parent.resolve(strict=True)
    directory = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    temporary = f".{path.name}.tmp.{os.getpid()}"
    descriptor = -1
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=directory,
        )
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written == 0:
                raise GateError(f"short write while creating output: {path}")
            view = view[written:]
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
        try:
            os.link(
                temporary,
                path.name,
                src_dir_fd=directory,
                dst_dir_fd=directory,
                follow_symlinks=False,
            )
        except FileExistsError as error:
            raise GateError(f"output already exists: {path}") from error
        unlink_at(directory, temporary)
        os.fsync(directory)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        unlink_at(directory, temporary)
        os.close(directory)


def publish_checksum(path: Path, digest: str, filename: str) -> None:
    validate_filename(filename)
    publish_bytes_noreplace(path, f"{digest}  {filename}\n".encode("ascii"))


def artifact_commands(compression: str) -> tuple[list[str], list[str]]:
    if compression == "zstd-fast":
        return ["zstd", "-q", "-3", "-T0", "-c"], ["zstd", "-q", "-d", "-c"]
    if compression == "zstd-max":
        return ["zstd", "-q", "-19", "--long", "-T0", "-c"], ["zstd", "-q", "-d", "-c"]
    if compression == "xz":
        return ["xz", "-T0", "-1", "-c"], ["xz", "-d", "-c"]
    raise GateError(f"unsupported compression: {compression}")


def hash_stream(stream: Any) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    while True:
        chunk = stream.read(8 * 1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
        size += len(chunk)
    return digest.hexdigest(), size


def build_artifact(
    raw_descriptor: int,
    raw_path: Path,
    raw_digest: str,
    raw_size: int,
    artifact_path: Path,
    compression: str,
) -> dict[str, Any]:
    if compression == "none":
        if artifact_path.is_symlink():
            raise GateError("uncompressed artifact path must not be a symlink")
        artifact = artifact_path.resolve(strict=True)
        metadata = os.stat(artifact)
        if artifact != raw_path or fd_identity(raw_descriptor)[:3] != (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
        ):
            raise GateError("uncompressed artifact must be the accepted raw inode")
        return {
            "compression": "none",
            "filename": artifact_path.name,
            "sha256": raw_digest,
            "size": raw_size,
        }

    compress, decompress = artifact_commands(compression)
    require_commands((compress[0],))
    validate_filename(artifact_path.name)
    parent = artifact_path.parent.resolve(strict=True)
    directory = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    temporary = f".{artifact_path.name}.tmp.{os.getpid()}"
    artifact_descriptor = -1
    try:
        artifact_descriptor = os.open(
            temporary,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=directory,
        )
        os.lseek(raw_descriptor, 0, os.SEEK_SET)
        try:
            subprocess.run(
                compress,
                check=True,
                stdin=raw_descriptor,
                stdout=artifact_descriptor,
                stderr=subprocess.PIPE,
                pass_fds=(raw_descriptor, artifact_descriptor),
            )
        except subprocess.CalledProcessError as error:
            raise GateError(
                f"artifact compression failed: {error.stderr.decode(errors='replace').strip()}"
            ) from error
        os.fsync(artifact_descriptor)
        artifact_identity = fd_identity(artifact_descriptor)
        artifact_digest = hash_fd(artifact_descriptor)
        if fd_identity(artifact_descriptor) != artifact_identity:
            raise GateError("compressed artifact changed while hashing")

        os.lseek(artifact_descriptor, 0, os.SEEK_SET)
        process = subprocess.Popen(
            decompress,
            stdin=artifact_descriptor,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            pass_fds=(artifact_descriptor,),
        )
        assert process.stdout is not None
        expanded_digest, expanded_size = hash_stream(process.stdout)
        _, error_output = process.communicate()
        if process.returncode != 0:
            raise GateError(
                f"artifact decompression failed: {error_output.decode(errors='replace').strip()}"
            )
        if expanded_digest != raw_digest or expanded_size != raw_size:
            raise GateError("compressed artifact does not expand to the accepted raw bytes")

        os.fchmod(artifact_descriptor, 0o644)
        os.fsync(artifact_descriptor)
        try:
            os.link(
                temporary,
                artifact_path.name,
                src_dir_fd=directory,
                dst_dir_fd=directory,
                follow_symlinks=False,
            )
        except FileExistsError as error:
            raise GateError(f"artifact already exists: {artifact_path}") from error
        unlink_at(directory, temporary)
        os.fsync(directory)
        return {
            "compression": compression,
            "filename": artifact_path.name,
            "sha256": artifact_digest,
            "size": artifact_identity[2],
        }
    finally:
        if artifact_descriptor >= 0:
            os.close(artifact_descriptor)
        unlink_at(directory, temporary)
        os.close(directory)


def detach_own_loop(loop: str, raw_descriptor: int) -> None:
    matches = existing_loop_for(raw_descriptor)
    if not any(mapping.get("name") == loop for mapping in matches):
        raise GateError("refusing to detach a loop whose backing identity changed")
    run("losetup", "--detach", loop, capture=False)


def verify(arguments: argparse.Namespace) -> None:
    if sys.platform != "linux" or os.geteuid() != 0:
        raise GateError("the final-media gate requires root on Linux")
    enter_private_mount_namespace()
    require_commands(("blockdev", "findmnt", "losetup", "lsblk", "mount", "udevadm", "umount"))

    if arguments.raw.is_symlink():
        raise GateError("raw image path must not be a symlink")
    raw = arguments.raw.resolve(strict=True)
    expected_bytes = read_regular(arguments.expected_manifest, 512 * 1024 * 1024)
    expected_sha = hashlib.sha256(expected_bytes).hexdigest()
    try:
        expected_document = json.loads(expected_bytes)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise GateError("expected seed manifest is invalid JSON") from error
    if (
        not isinstance(expected_document, dict)
        or expected_document.get("schema") != "neural-ice-offline-seed-tree-v1"
    ):
        raise GateError("expected seed manifest schema is invalid")

    descriptor = os.open(raw, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    loop = ""
    mounted = False
    mountpoint_path: Path | None = None
    actual_path: Path | None = None
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise GateError("raw image is already held by another final-media gate") from error
        before_identity = fd_identity(descriptor)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise GateError("raw image is not a regular file")
        if existing_loop_for(descriptor):
            raise GateError("raw image already has a loop mapping")
        before_digest = hash_fd(descriptor)
        loop = run(
            "losetup",
            "--find",
            "--show",
            "--read-only",
            "--partscan",
            f"/proc/self/fd/{descriptor}",
            pass_fds=(descriptor,),
        )
        if run("blockdev", "--getro", loop) != "1":
            raise GateError("loop device is writable")
        mapped = existing_loop_for(descriptor)
        if len(mapped) != 1 or mapped[0].get("name") != loop:
            raise GateError("raw image has an unexpected concurrent loop mapping")
        partition, partuuid = find_seed_partition(loop)
        if run("blockdev", "--getro", partition) != "1":
            raise GateError("ni-seed partition device is writable")

        mountpoint_path = Path(tempfile.mkdtemp(prefix="neural-ice-ni-seed.", dir="/run"))
        verify_mount(partition, mountpoint_path)
        mounted = True
        actual_descriptor, actual_name = tempfile.mkstemp(
            prefix="neural-ice-seed-manifest.", dir="/run"
        )
        os.close(actual_descriptor)
        actual_path = Path(actual_name)
        actual_path.unlink()
        manifest_tool = Path(__file__).with_name("seed-tree-manifest.py")
        trees = expected_document.get("trees")
        verify_seed_root(mountpoint_path, trees)
        command = [sys.executable, str(manifest_tool)]
        for name in trees:
            if not isinstance(name, str) or not name:
                raise GateError("expected seed tree name is invalid")
            command.extend(("--tree", f"{name}={mountpoint_path / name}"))
        command.extend(("--output", str(actual_path)))
        run(*command, capture=False)
        actual_bytes = read_regular(actual_path, 512 * 1024 * 1024)
        if actual_bytes != expected_bytes:
            raise GateError("final read-only ni-seed content differs from the approved manifest")
        mapped = existing_loop_for(descriptor)
        if len(mapped) != 1 or mapped[0].get("name") != loop:
            raise GateError("raw image acquired an unexpected concurrent loop mapping")

        run("umount", str(mountpoint_path), capture=False)
        mounted = False
        detach_own_loop(loop, descriptor)
        loop = ""
        if existing_loop_for(descriptor):
            raise GateError("raw image still has a loop mapping after verification")
        after_identity = fd_identity(descriptor)
        after_digest = hash_fd(descriptor)
        if after_identity != before_identity or after_digest != before_digest:
            raise GateError("raw image changed during final-media verification")

        artifact = build_artifact(
            descriptor,
            raw,
            before_digest,
            metadata.st_size,
            arguments.artifact,
            arguments.compression,
        )
        if fd_identity(descriptor) != before_identity or hash_fd(descriptor) != before_digest:
            raise GateError("raw image changed while producing the release artifact")
        if existing_loop_for(descriptor):
            raise GateError("raw image acquired a loop mapping while producing the artifact")
        publish_checksum(
            arguments.artifact_checksum,
            str(artifact["sha256"]),
            arguments.artifact.name,
        )
        receipt_document = {
            "artifact": artifact,
            "ni_seed": {
                "fstype": "xfs",
                "manifest_sha256": expected_sha,
                "mount_options": ["nodev", "noexec", "nosuid", "ro"],
                "partuuid": partuuid,
            },
            "raw": {"sha256": before_digest, "size": metadata.st_size},
            "schema": "neural-ice-preloaded-final-media-receipt-v1",
        }
        receipt_bytes = (
            json.dumps(receipt_document, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("ascii")
        publish_bytes_noreplace(arguments.receipt, receipt_bytes)
        publish_checksum(
            arguments.receipt_checksum,
            hashlib.sha256(receipt_bytes).hexdigest(),
            arguments.receipt.name,
        )
    finally:
        if mounted and mountpoint_path is not None:
            subprocess.run(("umount", str(mountpoint_path)), check=False)
        if loop:
            try:
                if any(
                    mapping.get("name") == loop
                    for mapping in existing_loop_for(descriptor)
                ):
                    subprocess.run(("losetup", "--detach", loop), check=False)
            except (GateError, OSError):
                pass
        if actual_path is not None:
            actual_path.unlink(missing_ok=True)
        if mountpoint_path is not None:
            try:
                mountpoint_path.rmdir()
            except OSError:
                pass
        os.close(descriptor)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--raw", required=True, type=Path)
    parser.add_argument("--expected-manifest", required=True, type=Path)
    parser.add_argument("--artifact", required=True, type=Path)
    parser.add_argument("--artifact-checksum", required=True, type=Path)
    parser.add_argument(
        "--compression",
        required=True,
        choices=("none", "xz", "zstd-fast", "zstd-max"),
    )
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--receipt-checksum", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        verify(arguments)
    except (GateError, OSError) as error:
        print(f"REFUSED: {error}", file=sys.stderr)
        return 1
    print(f"FINAL_MEDIA_OK artifact={arguments.artifact} receipt={arguments.receipt}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
