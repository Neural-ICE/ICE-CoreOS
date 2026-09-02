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
import re
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


def find_partition(loop: str, partlabel: str, filesystem: str) -> tuple[str, str]:
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
        and node.get("partlabel") == partlabel
    ]
    if len(matches) != 1:
        raise GateError(f"final raw must contain exactly one {partlabel} child partition")
    partition = matches[0]
    if partition.get("fstype") != filesystem:
        raise GateError(f"{partlabel} partition is not {filesystem}")
    if str(partition.get("ro")) not in ("1", "True", "true"):
        raise GateError(f"{partlabel} partition is not read-only")
    partuuid = partition.get("partuuid")
    if not isinstance(partuuid, str) or not partuuid:
        raise GateError(f"{partlabel} partition lacks PARTUUID")
    return str(partition["name"]), partuuid.lower()


def verify_mount(partition: str, expected_filesystem: str, mountpoint: Path) -> None:
    output = run("findmnt", "--json", "--target", str(mountpoint), "--output", "SOURCE,FSTYPE,OPTIONS")
    try:
        filesystems = json.loads(output)["filesystems"]
    except (KeyError, json.JSONDecodeError) as error:
        raise GateError("findmnt returned invalid JSON") from error
    if len(filesystems) != 1:
        raise GateError("ni-seed mount is ambiguous")
    mounted_filesystem = filesystems[0]
    source = str(mounted_filesystem.get("source", "")).split("[")[0]
    options = set(str(mounted_filesystem.get("options", "")).split(","))
    if source != partition or mounted_filesystem.get("fstype") != expected_filesystem:
        raise GateError("read-only media mount source or filesystem changed")
    if not {"ro", "nosuid", "nodev", "noexec"}.issubset(options):
        raise GateError("media mount lacks required read-only options")
    probe = mountpoint / ".neural-ice-write-probe"
    try:
        descriptor = os.open(probe, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as error:
        if error.errno != errno.EROFS:
            raise GateError(f"media write probe failed for an unexpected reason: {error}") from error
    else:
        os.close(descriptor)
        os.unlink(probe)
        raise GateError("media accepted a write through the release gate")


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


def expected_lab_baseline(arguments: argparse.Namespace) -> tuple[str, str] | None:
    values = (
        arguments.lab_baseline_bom_sha256,
        arguments.lab_baseline_signature_sha256,
    )
    if values == (None, None):
        return None
    if any(value is None for value in values) or any(
        len(value) != 64 or any(character not in "0123456789abcdef" for character in value)
        for value in values
        if value is not None
    ):
        raise GateError("LAB baseline requires both exact lowercase SHA-256 values")
    bom_sha256, signature_sha256 = values
    assert bom_sha256 is not None and signature_sha256 is not None
    return bom_sha256, signature_sha256


def verify_lab_baseline(
    mountpoint: Path, expected: tuple[str, str] | None
) -> dict[str, Any] | None:
    namespace = mountpoint / "ice-coreos"
    bom_path = namespace / "ota-lab-baseline.json"
    signature_path = namespace / "ota-lab-baseline.sig"
    bom_present = bom_path.exists() or bom_path.is_symlink()
    signature_present = signature_path.exists() or signature_path.is_symlink()
    if not bom_present and not signature_present:
        if expected is not None:
            raise GateError("approved LAB baseline pair is absent from the installer ESP")
        return None
    if not bom_present or not signature_present:
        raise GateError("installer ESP contains an incomplete LAB baseline pair")
    if expected is None:
        raise GateError("installer ESP contains an unapproved LAB baseline pair")

    bom = read_regular(bom_path, 16 * 1024)
    signature = read_regular(signature_path, 4 * 1024)
    if not bom or not signature:
        raise GateError("installer ESP LAB baseline files must be non-empty")
    bom_sha256 = hashlib.sha256(bom).hexdigest()
    signature_sha256 = hashlib.sha256(signature).hexdigest()
    if (bom_sha256, signature_sha256) != expected:
        raise GateError("installer ESP LAB baseline differs from the approved hashes")
    return {
        "bom": {
            "path": "ice-coreos/ota-lab-baseline.json",
            "sha256": bom_sha256,
            "size": len(bom),
        },
        "signature": {
            "path": "ice-coreos/ota-lab-baseline.sig",
            "sha256": signature_sha256,
            "size": len(signature),
        },
    }


def expected_esp_authorized_keys(arguments: argparse.Namespace) -> str | None:
    value = arguments.esp_authorized_keys_sha256
    if value is None:
        return None
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise GateError("the approved installer SSH key requires one exact lowercase SHA-256")
    return value


def verify_esp_authorized_keys(
    mountpoint: Path, expected: str | None
) -> dict[str, Any] | None:
    """An operator SSH key may only ship on media that explicitly approved it.

    The installed system refuses an unauthorised key twice over (the immutable
    access policy is checked by the autoinstaller and again at first boot), but
    a key nobody approved has no business leaving the build host at all: it is
    either a staging mistake or a modified ESP, and both are things a release
    gate exists to catch. Absence when one was approved is equally a refusal --
    silently shipping unreachable lab media wastes a hardware trip.
    """
    path = mountpoint / "ice-coreos" / "authorized_keys"
    present = path.exists() or path.is_symlink()
    if not present:
        if expected is not None:
            raise GateError("the approved installer SSH key is absent from the installer ESP")
        return None
    if expected is None:
        raise GateError("installer ESP carries an unapproved SSH authorized_keys file")
    # read_regular opens with O_NOFOLLOW and bounds the size, so a symlinked or
    # padded authorized_keys is refused before its content is considered. The
    # bound matches INSTALLER_SSH_PUBLIC_KEY_MAX_BYTES in image/lib/installer-ssh-key.sh.
    content = read_regular(path, 512)
    if not content:
        raise GateError("installer ESP SSH authorized_keys file must be non-empty")
    sha256 = hashlib.sha256(content).hexdigest()
    if sha256 != expected:
        raise GateError("installer ESP SSH key differs from the approved hash")
    return {
        "path": "ice-coreos/authorized_keys",
        "sha256": sha256,
        "size": len(content),
    }


def validate_filename(filename: str) -> None:
    if filename in ("", ".", "..") or any(
        character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
        for character in filename
    ):
        raise GateError(f"unsafe output filename: {filename!r}")


def require_output_set_available(arguments: argparse.Namespace, raw: Path) -> None:
    outputs = [
        arguments.artifact_checksum,
        arguments.receipt,
        arguments.receipt_checksum,
    ]
    if arguments.compression == "none":
        if arguments.artifact.is_symlink():
            raise GateError("uncompressed artifact path must not be a symlink")
        if arguments.artifact.resolve(strict=True) != raw:
            raise GateError("uncompressed artifact must be the accepted raw path")
    else:
        outputs.insert(0, arguments.artifact)

    canonical_outputs: set[tuple[Path, str]] = set()
    for output in outputs:
        validate_filename(output.name)
        parent = output.parent.resolve(strict=True)
        identity = (parent, output.name)
        if identity in canonical_outputs:
            raise GateError("final-media output paths must be unique")
        canonical_outputs.add(identity)
        if parent / output.name == raw:
            raise GateError("final-media output path collides with the accepted raw")
        directory = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            try:
                os.stat(output.name, dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise GateError(f"output already exists: {output}")
        finally:
            os.close(directory)


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


SEALED_CORE_HEX = ("expect_verity_root_hash", "expect_payload_digest")


def inspect_sealed_core(descriptor: int, arguments: argparse.Namespace) -> dict[str, Any]:
    """Prove the SEALED CORE of the finalized raw, under this gate's own lock.

    Why this runs here and not where it used to
    -------------------------------------------
    ``build-installer-usb.sh`` inspects the raw it produces -- but PRELOADED then
    keeps writing to that raw: it grows the file, rewrites the GPT backup header
    and the partition table, attaches it WRITABLE and copies ~20 GB of seed into
    a new ``ni-seed`` partition (review 2026-09-01, P1 #4). The final acceptance
    gate re-checked the seed and the ESP handoffs and nothing else, so the
    receipt and the checksum could bless a raw whose ``BOOTAA64.EFI``, sealed
    payload or supposedly-zeroed partitions had changed after their only
    inspection.

    The inspector therefore runs HERE: after the last writable phase, before the
    receipt, the checksum and the release artifact, and through
    ``/proc/self/fd/N`` -- i.e. through the very descriptor this gate holds an
    exclusive ``flock`` on and whose identity and digest it brackets. It reads
    the same bytes that are about to be published, not a path that could be
    replaced between the two.

    It is the FULL inspector, not a subset: the ESP allowlist, the signed UKI's
    ``.cmdline``, every payload region hash, both recomputed dm-verity root
    hashes and the "every other partition is entirely zero" check. ``ni-seed`` is
    the one partition it deliberately permits.
    """
    inspector = Path(__file__).with_name("inspect-installer-media.py")
    if not inspector.is_file():
        raise GateError("the sealed-core inspector is missing; refusing to publish an uninspected medium")
    command = [
        sys.executable,
        str(inspector),
        "--raw",
        f"/proc/self/fd/{descriptor}",
        "--expect-verity-root-hash",
        arguments.expect_verity_root_hash,
        "--expect-payload-digest",
        arguments.expect_payload_digest,
        "--expect-mode",
        arguments.expect_mode,
        "--expect-access-profile",
        arguments.expect_access_profile,
        "--expect-hardware-target",
        arguments.expect_hardware_target,
        "--expect-trust-policy-id",
        arguments.expect_trust_policy_id,
    ]
    if arguments.allow_unsigned:
        command.append("--allow-unsigned")
    run(*command, capture=False, pass_fds=(descriptor,))
    return {
        "access_profile": arguments.expect_access_profile,
        "hardware_target": arguments.expect_hardware_target,
        "inspected": "after-final-write",
        "media_mode": arguments.expect_mode,
        "payload_digest": arguments.expect_payload_digest,
        "signed": not arguments.allow_unsigned,
        "trust_policy_id": arguments.expect_trust_policy_id,
        "verity_root_hash": arguments.expect_verity_root_hash,
    }


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
    require_output_set_available(arguments, raw)
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
    if not re.fullmatch(r"[0-9a-f]{64}", arguments.release_closure_sha256):
        raise GateError("expected release closure is not 64 lowercase hex")
    if not re.fullmatch(r"[0-9a-f]{64}", arguments.release_manifest_sha256):
        raise GateError("expected release manifest is not 64 lowercase hex")
    expected_baseline = expected_lab_baseline(arguments)
    expected_esp_key = expected_esp_authorized_keys(arguments)

    descriptor = os.open(raw, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    loop = ""
    mounted = False
    mountpoint_path: Path | None = None
    actual_workspace: Path | None = None
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
        partition, partuuid = find_partition(loop, "ni-seed", "xfs")
        if run("blockdev", "--getro", partition) != "1":
            raise GateError("ni-seed partition device is writable")

        mountpoint_path = Path(tempfile.mkdtemp(prefix="neural-ice-ni-seed.", dir="/run"))
        run(
            "mount",
            "-t",
            "xfs",
            "-o",
            "ro,nosuid,nodev,noexec",
            partition,
            str(mountpoint_path),
            capture=False,
        )
        # Record cleanup responsibility immediately after mount(2) succeeds;
        # all subsequent source/options/write-probe checks may refuse.
        mounted = True
        verify_mount(partition, "xfs", mountpoint_path)
        actual_workspace = Path(
            tempfile.mkdtemp(prefix="neural-ice-seed-manifest.", dir="/run")
        )
        os.chmod(actual_workspace, 0o700)
        actual_path = actual_workspace / "actual.json"
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
        esp_partition, esp_partuuid = find_partition(loop, "EFI-SYSTEM", "vfat")
        if run("blockdev", "--getro", esp_partition) != "1":
            raise GateError("installer ESP partition device is writable")
        run(
            "mount",
            "-t",
            "vfat",
            "-o",
            "ro,nosuid,nodev,noexec",
            esp_partition,
            str(mountpoint_path),
            capture=False,
        )
        mounted = True
        verify_mount(esp_partition, "vfat", mountpoint_path)
        lab_baseline = verify_lab_baseline(mountpoint_path, expected_baseline)
        esp_authorized_keys = verify_esp_authorized_keys(mountpoint_path, expected_esp_key)
        if lab_baseline is not None:
            lab_baseline["esp"] = {
                "fstype": "vfat",
                "mount_options": ["nodev", "noexec", "nosuid", "ro"],
                "partuuid": esp_partuuid,
            }
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

        # THE SEALED CORE, AFTER THE LAST WRITABLE PHASE (review 2026-09-01,
        # P1 #4). Nothing below this line writes to the raw, and everything below
        # it publishes: the artifact, its checksum, the receipt and the receipt's
        # checksum. So this is the last moment at which "what is about to be
        # blessed" and "what was inspected" are the same bytes.
        sealed_core = inspect_sealed_core(descriptor, arguments)
        if fd_identity(descriptor) != before_identity or hash_fd(descriptor) != before_digest:
            raise GateError("raw image changed while its sealed core was inspected")

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
                "release_closure_sha256": arguments.release_closure_sha256,
                "release_manifest_sha256": arguments.release_manifest_sha256,
            },
            "esp_authorized_keys": esp_authorized_keys,
            "lab_baseline": lab_baseline,
            "raw": {"sha256": before_digest, "size": metadata.st_size},
            "schema": "neural-ice-preloaded-final-media-receipt-v2",
            "sealed_core": sealed_core,
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
        if actual_workspace is not None:
            try:
                actual_workspace.rmdir()
            except OSError:
                pass
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
    parser.add_argument("--release-closure-sha256", required=True)
    parser.add_argument("--release-manifest-sha256", required=True)
    parser.add_argument("--artifact", required=True, type=Path)
    parser.add_argument("--artifact-checksum", required=True, type=Path)
    parser.add_argument(
        "--compression",
        required=True,
        choices=("none", "xz", "zstd-fast", "zstd-max"),
    )
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--receipt-checksum", required=True, type=Path)
    parser.add_argument("--esp-authorized-keys-sha256")
    parser.add_argument("--lab-baseline-bom-sha256")
    parser.add_argument("--lab-baseline-signature-sha256")
    # THE SEALED CORE. Required, not optional: a final gate that can be invoked
    # without inspecting what the medium boots and installs is the finding.
    parser.add_argument("--expect-verity-root-hash", required=True)
    parser.add_argument("--expect-payload-digest", required=True)
    parser.add_argument("--expect-mode", required=True, choices=("install", "live"))
    parser.add_argument("--expect-access-profile", required=True)
    parser.add_argument("--expect-hardware-target", required=True)
    parser.add_argument("--expect-trust-policy-id", required=True)
    parser.add_argument("--allow-unsigned", action="store_true")
    arguments = parser.parse_args()
    for name in SEALED_CORE_HEX:
        value = getattr(arguments, name)
        if not re.fullmatch(r"[0-9a-f]{64}", value or ""):
            flag = "--" + name.replace("_", "-")
            print(f"ERROR: {flag} must be 64 lowercase hex", file=sys.stderr)
            return 2
    try:
        verify(arguments)
    except (GateError, OSError) as error:
        print(f"REFUSED: {error}", file=sys.stderr)
        return 1
    print(f"FINAL_MEDIA_OK artifact={arguments.artifact} receipt={arguments.receipt}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
