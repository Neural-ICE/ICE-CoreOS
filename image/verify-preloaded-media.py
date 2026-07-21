#!/usr/bin/env python3
"""Fail-closed acceptance gate for a finalized PRELOADED installer raw."""

from __future__ import annotations

import argparse
import errno
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


def existing_loop_for(raw: Path) -> list[dict[str, Any]]:
    output = run("losetup", "--json", "--list", "--output", "NAME,BACK-FILE,RO")
    if not output:
        return []
    try:
        loops = json.loads(output).get("loopdevices", [])
    except json.JSONDecodeError as error:
        raise GateError("losetup returned invalid JSON") from error
    raw_real = raw.resolve(strict=True)
    matches = []
    for loop in loops:
        backing = loop.get("back-file") or loop.get("back_file")
        if not backing:
            continue
        try:
            if Path(backing).resolve(strict=True) == raw_real:
                matches.append(loop)
        except OSError:
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


def write_receipt(path: Path, document: dict[str, Any]) -> None:
    if path.exists() or path.is_symlink():
        raise GateError(f"receipt already exists: {path}")
    parent = path.parent.resolve(strict=True)
    destination = parent / path.name
    encoded = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
    temporary = parent / f".{path.name}.tmp.{os.getpid()}"
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        view = memoryview(encoded)
        while view:
            written = os.write(descriptor, view)
            if written == 0:
                raise GateError(f"short write while creating receipt: {path}")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, destination)
    directory = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def verify(arguments: argparse.Namespace) -> None:
    if sys.platform != "linux" or os.geteuid() != 0:
        raise GateError("the final-media gate requires root on Linux")
    if os.environ.get("NEURAL_ICE_MEDIA_GATE_NAMESPACE") != "1":
        environment = os.environ.copy()
        environment["NEURAL_ICE_MEDIA_GATE_NAMESPACE"] = "1"
        os.execvpe(
            "unshare",
            [
                "unshare",
                "--mount",
                "--propagation",
                "private",
                "--",
                sys.executable,
                str(Path(__file__).resolve()),
                *sys.argv[1:],
            ],
            environment,
        )
    require_commands(("blockdev", "findmnt", "losetup", "lsblk", "mount", "udevadm", "umount"))

    raw = arguments.raw.resolve(strict=True)
    if arguments.raw.is_symlink():
        raise GateError("raw image path must not be a symlink")
    expected_bytes = read_regular(arguments.expected_manifest, 512 * 1024 * 1024)
    expected_sha = hashlib.sha256(expected_bytes).hexdigest()
    try:
        expected_document = json.loads(expected_bytes)
    except json.JSONDecodeError as error:
        raise GateError("expected seed manifest is invalid JSON") from error
    if expected_document.get("schema") != "neural-ice-offline-seed-tree-v1":
        raise GateError("expected seed manifest schema is invalid")
    if existing_loop_for(raw):
        raise GateError("raw image already has a loop mapping")

    descriptor = os.open(raw, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    loop = ""
    mounted = False
    mountpoint_path: Path | None = None
    actual_path: Path | None = None
    try:
        before_identity = fd_identity(descriptor)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise GateError("raw image is not a regular file")
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
        mapped = existing_loop_for(raw)
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
        if not isinstance(trees, list) or not trees:
            raise GateError("expected seed manifest has no tree set")
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

        run("umount", str(mountpoint_path), capture=False)
        mounted = False
        run("losetup", "--detach", loop, capture=False)
        loop = ""
        after_identity = fd_identity(descriptor)
        after_digest = hash_fd(descriptor)
        if after_identity != before_identity or after_digest != before_digest:
            raise GateError("raw image changed during final-media verification")
        write_receipt(
            arguments.receipt,
            {
                "ni_seed": {
                    "fstype": "xfs",
                    "manifest_sha256": expected_sha,
                    "mount_options": ["nodev", "noexec", "nosuid", "ro"],
                    "partuuid": partuuid,
                },
                "raw": {"sha256": before_digest, "size": metadata.st_size},
                "schema": "neural-ice-preloaded-final-media-receipt-v1",
            },
        )
    finally:
        if mounted and mountpoint_path is not None:
            subprocess.run(("umount", str(mountpoint_path)), check=False)
        if loop:
            subprocess.run(("losetup", "--detach", loop), check=False)
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
    parser.add_argument("--receipt", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        verify(arguments)
    except (GateError, OSError) as error:
        print(f"REFUSED: {error}", file=sys.stderr)
        return 1
    print(f"FINAL_MEDIA_OK receipt={arguments.receipt}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
