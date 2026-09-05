#!/usr/bin/env python3
"""Copy a UKI-bound pre-seal evidence set without interpreting its signatures."""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
from pathlib import Path

SET_NAME = "preseal-set.json"
FILES = {
    SET_NAME: 16 * 1024,
    "delegation-snapshot.json": 16 * 1024,
    "delegation-snapshot.sig": 1024,
    "ota-release-authorization.json": 64 * 1024,
    "ota-release-authorization.sig": 1024,
    "bom.json": 128 * 1024,
}
FIELDS = {
    "access_policy_sha256",
    "access_profile",
    "attestation_set_sha256",
    "bom_file_sha256",
    "bom_sha256",
    "bundle_seq",
    "channel_record_sha256",
    "compat_max",
    "compat_min",
    "delegation_seq",
    "delegation_snapshot_file_sha256",
    "delegation_snapshot_sha256",
    "delegation_snapshot_signature_sha256",
    "hardware_target",
    "installer_authorization_sha256",
    "installer_authorization_signature_sha256",
    "ota_release_authorization_file_sha256",
    "ota_release_authorization_sha256",
    "ota_release_authorization_signature_sha256",
    "ota_state_profile",
    "release_key_id",
    "release_signing_role",
    "ring",
    "schema",
    "seed_ref",
    "signed_boot_trust_policy_id",
    "target_os_ref",
    "train",
    "variant",
}
FILE_HASHES = {
    "bom_file_sha256": "bom.json",
    "delegation_snapshot_file_sha256": "delegation-snapshot.json",
    "delegation_snapshot_signature_sha256": "delegation-snapshot.sig",
    "ota_release_authorization_file_sha256": "ota-release-authorization.json",
    "ota_release_authorization_signature_sha256": "ota-release-authorization.sig",
}
HEX64 = re.compile(r"[0-9a-f]{64}")
OCI_REF = re.compile(
    r"(?P<authority>[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::[1-9][0-9]{0,4})?)"
    r"/neural-ice/neural-ice-appliance"
    r"@sha256:[0-9a-f]{64}"
)
SAFE_INTEGER_MAX = 9_007_199_254_740_991


class Refusal(RuntimeError):
    pass


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def target_ref_is_valid(value: object) -> bool:
    if not isinstance(value, str):
        return False
    match = OCI_REF.fullmatch(value)
    if not match:
        return False
    authority = match.group("authority")
    host, separator, port = authority.partition(":")
    if "." not in host or host == "localhost" or re.fullmatch(r"[0-9.]+", host):
        return False
    if separator and int(port) > 65535:
        return False
    return all(
        re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in host.split(".")
    )


def read_regular(path: Path, limit: int) -> bytes:
    try:
        # O_NONBLOCK makes a hostile FIFO inspectable without ever waiting for
        # a writer; fstat below then refuses everything except a regular file.
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as error:
        raise Refusal(
            f"cannot open regular evidence file {path.name}: {error.strerror}"
        ) from error
    try:
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size <= 0
            or before.st_size > limit
        ):
            raise Refusal(
                f"{path.name} must be a non-empty regular file of at most {limit} bytes"
            )
        data = bytearray()
        while len(data) <= limit:
            block = os.read(fd, min(65536, limit + 1 - len(data)))
            if not block:
                break
            data.extend(block)
        after = os.fstat(fd)
        if (
            len(data) > limit
            or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            or len(data) != after.st_size
        ):
            raise Refusal(f"{path.name} changed while it was read")
        return bytes(data)
    finally:
        os.close(fd)


def parse_set(
    raw: bytes,
    files: dict[str, bytes],
    authorization: bytes,
    signature: bytes,
    expected: str,
) -> dict[str, object]:
    if not HEX64.fullmatch(expected) or digest(raw) != expected:
        raise Refusal("preseal-set.json differs from its signed UKI SHA-256")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_closed_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, Refusal) as error:
        raise Refusal(f"preseal-set.json is malformed: {error}") from error
    if not isinstance(value, dict) or set(value) != FIELDS:
        raise Refusal("preseal-set.json does not have the exact closed field set")
    canonical = (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode()
    if raw != canonical:
        raise Refusal("preseal-set.json is not canonical compact sorted JSON plus LF")
    exact = {
        "schema": "neural-ice-installer-preseal-set-v1",
        "ota_state_profile": "owner-sealed-ota-state-v1",
        "hardware_target": "nvidia-gb10-arm64",
        "variant": "sealed-lab",
        "access_profile": "lab-managed",
        "signed_boot_trust_policy_id": "neural-ice-secureboot-lab-v1",
        "ring": "lab",
        "release_signing_role": "release-lab",
        "release_key_id": "release-lab-v1",
        "delegation_seq": 2,
        "delegation_snapshot_sha256": "3378808da1841f89db7dcc125fa1c7025662e9b3c099cf8f67a69c5f7341dad0",
    }
    for key, wanted in exact.items():
        if value.get(key) != wanted:
            raise Refusal(f"preseal-set.json has unsupported {key}")
    for key in ("bundle_seq", "compat_min", "compat_max"):
        number = value.get(key)
        if (
            isinstance(number, bool)
            or not isinstance(number, int)
            or not 0 < number <= SAFE_INTEGER_MAX
        ):
            raise Refusal(f"preseal-set.json {key} is not a positive JSON safe integer")
    if value["compat_min"] > value["compat_max"]:
        raise Refusal("preseal-set.json compatibility interval is empty")
    if not isinstance(value.get("train"), str) or not re.fullmatch(
        r"[a-z0-9][a-z0-9._-]{0,127}", value["train"]
    ):
        raise Refusal("preseal-set.json train is invalid")
    if not isinstance(value.get("seed_ref"), str) or not re.fullmatch(
        r"[0-9a-f]{40}", value["seed_ref"]
    ):
        raise Refusal("preseal-set.json seed_ref is invalid")
    if not target_ref_is_valid(value.get("target_os_ref")):
        raise Refusal(
            "preseal-set.json target_os_ref is not a canonical digest-pinned reference"
        )
    for key in (field for field in FIELDS if field.endswith("_sha256")):
        if not isinstance(value.get(key), str) or not HEX64.fullmatch(value[key]):
            raise Refusal(f"preseal-set.json {key} is not lowercase SHA-256")
    for key, name in FILE_HASHES.items():
        if value[key] != digest(files[name]):
            raise Refusal(f"preseal-set.json does not bind {name}")
    if value["installer_authorization_sha256"] != digest(authorization):
        raise Refusal("preseal-set.json does not bind installer authorization bytes")
    if value["installer_authorization_signature_sha256"] != digest(signature):
        raise Refusal(
            "preseal-set.json does not bind installer authorization signature bytes"
        )
    return value


def _closed_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Refusal(f"duplicate JSON field {key}")
        result[key] = value
    return result


def require_real_directory_path(path: Path, label: str) -> None:
    current = Path(path.absolute().anchor)
    for part in path.absolute().parts[1:]:
        current /= part
        try:
            info = current.lstat()
        except OSError as error:
            raise Refusal(
                f"{label} is not an existing real directory: {error.strerror}"
            ) from error
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise Refusal(f"{label} contains a symlink or non-directory component")


def load(
    root: Path, expected: str, auth_path: Path, sig_path: Path
) -> dict[str, bytes]:
    require_real_directory_path(root, "preseal evidence root")
    names = {entry.name for entry in os.scandir(root)}
    if names != set(FILES):
        raise Refusal("preseal evidence root must contain exactly the six fixed files")
    files = {name: read_regular(root / name, limit) for name, limit in FILES.items()}
    auth = read_regular(auth_path, 1024)
    sig = read_regular(sig_path, 4 * 1024)
    parse_set(files[SET_NAME], files, auth, sig, expected)
    return files


def fsync_path(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def rename_noreplace(source: Path, destination: Path) -> None:
    """Publish a directory without a check/rename overwrite race."""
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise Refusal("renameat2(RENAME_NOREPLACE) is unavailable")
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    if renameat2(-100, os.fsencode(source), -100, os.fsencode(destination), 1) != 0:
        error = ctypes.get_errno()
        if error == errno.EEXIST:
            raise Refusal("preseal destination appeared during publication")
        raise Refusal(f"cannot publish preseal destination: {os.strerror(error)}")


def require_private_layout(directory: Path) -> None:
    info = directory.stat()
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise Refusal("private preseal directory has unsafe ownership or mode")
    for name in FILES:
        info = (directory / name).stat()
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600:
            raise Refusal(f"private {name} has unsafe ownership or mode")


def publish(
    files: dict[str, bytes], destination: Path, directory_mode: int, file_mode: int
) -> None:
    parent = destination.parent
    require_real_directory_path(parent, "destination parent")
    parent_stat = parent.stat()
    if parent_stat.st_uid != os.geteuid() or parent_stat.st_mode & 0o022:
        raise Refusal(
            "destination parent must be owned by the caller and not group/world writable"
        )
    if destination.exists() or destination.is_symlink():
        existing = (
            {
                name: read_regular(destination / name, limit)
                for name, limit in FILES.items()
            }
            if destination.is_dir()
            and not destination.is_symlink()
            and {e.name for e in os.scandir(destination)} == set(FILES)
            else None
        )
        if existing == files:
            if file_mode == 0o600:
                require_private_layout(destination)
            return
        raise Refusal("refusing to replace a conflicting or unsafe preseal destination")
    old_umask = os.umask(0o077)
    stage = Path(
        tempfile.mkdtemp(prefix=f".{destination.name}.", suffix=".new", dir=parent)
    )
    try:
        os.chmod(stage, directory_mode)
        for name, data in files.items():
            path = stage / name
            fd = os.open(
                path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, file_mode
            )
            try:
                view = memoryview(data)
                while view:
                    written = os.write(fd, view)
                    if written <= 0:
                        raise Refusal(f"short write while staging {name}")
                    view = view[written:]
                os.fchmod(fd, file_mode)
                os.fsync(fd)
            finally:
                os.close(fd)
            if read_regular(path, FILES[name]) != data:
                raise Refusal(f"staged {name} failed readback")
        fsync_path(stage)
        rename_noreplace(stage, destination)
        fsync_path(parent)
        for name, data in files.items():
            if read_regular(destination / name, FILES[name]) != data:
                raise Refusal(f"published {name} failed readback")
        if file_mode == 0o600:
            require_private_layout(destination)
    finally:
        os.umask(old_umask)
        if stage.exists():
            shutil.rmtree(stage)


def command(args: argparse.Namespace) -> None:
    source = Path(args.source)
    auth = Path(args.authorization)
    sig = Path(args.authorization_signature)
    files = load(source, args.set_sha256, auth, sig)
    if args.operation == "verify":
        return
    if args.operation == "snapshot":
        publish(files, Path(args.destination), 0o700, 0o600)
    elif args.mode == "media":
        publish(files, Path(args.destination), 0o755, 0o444)
    else:
        if os.geteuid() != 0:
            raise Refusal("private install must run as root")
        publish(files, Path(args.destination), 0o700, 0o600)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    subs = result.add_subparsers(dest="operation", required=True)
    for name in ("snapshot", "verify", "install"):
        sub = subs.add_parser(name)
        sub.add_argument("source")
        sub.add_argument("set_sha256")
        sub.add_argument("authorization")
        sub.add_argument("authorization_signature")
        if name != "verify":
            sub.add_argument("destination")
        if name == "install":
            sub.add_argument("--mode", choices=("media", "private"), default="private")
    return result


def main() -> int:
    try:
        command(parser().parse_args())
    except Refusal as error:
        print(f"preseal handoff refused: {error}", file=os.sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
