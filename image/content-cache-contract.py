#!/usr/bin/env python3
"""Validate and materialize the two signed content-cache-v1 artifacts."""

import argparse
import hashlib
import json
import os
import pathlib
import re
import stat

SCHEMA = "neural-ice-content-cache-v1"
ARTIFACT_TYPE = "application/vnd.neural-ice.content-cache.v1"
CONFIG_MEDIA_TYPE = "application/vnd.neural-ice.content-cache.v1+json"
SEGMENT_MEDIA_TYPE = "application/vnd.neural-ice.content-cache.segment.v1"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
MAX_SEGMENT_BYTES = 8 * 1024 * 1024 * 1024
MAX_SEGMENTS = 64
MAX_CONTENT_BYTES = 128 * 1024 * 1024 * 1024
MAX_CONFIG_BYTES = 64 * 1024
MAX_SAFE_INTEGER = 9_007_199_254_740_991
RESERVE_BYTES = 4 * 1024 * 1024 * 1024
HEX = re.compile(r"^[0-9a-f]{64}$")

PROFILES = {
    "ch-caselaw-seed": {
        "format": "sqlite3",
        "repository": "registry.neural-ice.ch/neural-ice/content-cache-ch-caselaw-seed",
        "candidate_repository": "ghcr.io/neural-ice/content-cache-ch-caselaw-seed",
        "entitlement": "ICE-CASELAW-CH",
        "filename": "decisions.db",
    },
    "paddlex-cache": {
        "format": "tar+zstd",
        "repository": "registry.neural-ice.ch/neural-ice/content-cache-paddlex-cache",
        "candidate_repository": "ghcr.io/neural-ice/content-cache-paddlex-cache",
        "entitlement": "ICE-CORE",
        "filename": "paddlex-cache.tar.zst",
    },
}


def fail(message):
    raise SystemExit(f"content-cache-contract: REFUSED: {message}")


def _identity(metadata):
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _pairs(label):
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                fail(f"duplicate JSON member {key!r} in {label}")
            result[key] = value
        return result

    return pairs


def read_regular(path, limit=None):
    path = pathlib.Path(path)
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as error:
        fail(f"cannot open {path}: {error}")
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            fail(f"{path} is not a single-link regular file")
        if limit is not None and before.st_size > limit:
            fail(f"{path} exceeds its byte bound")
        body = b""
        while block := os.read(descriptor, 1024 * 1024):
            body += block
            if limit is not None and len(body) > limit:
                fail(f"{path} exceeds its byte bound")
        after = os.fstat(descriptor)
        named = os.lstat(path)
        if _identity(before) != _identity(after) or (named.st_dev, named.st_ino) != (
            after.st_dev,
            after.st_ino,
        ):
            fail(f"{path} changed while read")
        return body
    finally:
        os.close(descriptor)


def load_json(path, limit=16 * 1024 * 1024):
    body = read_regular(path, limit)

    def reject_number(value):
        fail(f"{path} carries forbidden JSON number {value}")

    def parse_integer(value):
        parsed = int(value)
        if parsed < 0 or parsed > MAX_SAFE_INTEGER:
            fail(f"{path} carries an integer outside the safe unsigned range")
        return parsed

    try:
        return (
            json.loads(
                body,
                object_pairs_hook=_pairs(path),
                parse_float=reject_number,
                parse_int=parse_integer,
                parse_constant=reject_number,
            ),
            body,
        )
    except (UnicodeDecodeError, ValueError) as error:
        fail(f"cannot parse {path}: {error}")


def canonical_no_lf(value):
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
    except (TypeError, UnicodeEncodeError) as error:
        fail(f"config leaves the canonical ASCII domain: {error}")


def digest_name(value, label):
    if (
        not isinstance(value, str)
        or not value.startswith("sha256:")
        or not HEX.fullmatch(value[7:])
    ):
        fail(f"{label} is not sha256:<64 lowercase hex>")
    return value[7:]


def positive_integer(value, label, maximum=None):
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        fail(f"{label} is not a positive integer")
    if maximum is not None and value > maximum:
        fail(f"{label} exceeds its bound")
    return value


def closed(value, keys, label):
    if not isinstance(value, dict) or set(value) != set(keys):
        fail(f"{label} has the wrong closed schema")


def _artifact_root(artifact):
    root = artifact.get("root")
    closed(root, {"digest", "repository"}, "content-cache closure root")
    return root


def collect_specs(closure_path, manifest_path, objects_path):
    closure, _ = load_json(closure_path)
    manifest, _ = load_json(manifest_path)
    objects = pathlib.Path(objects_path)
    required = manifest.get("compatibility", {}).get("required_contracts", [])
    entries = [
        entry
        for entry in manifest.get("content", [])
        if isinstance(entry, dict) and entry.get("contract") == "content-cache-v1"
    ]
    if "content-cache-v1" not in required:
        if entries:
            fail(
                "manifest carries content-cache-v1 entries without requiring the contract"
            )
        return []
    if len(entries) != len(PROFILES):
        fail("content-cache-v1 requires exactly the two fixed cache identities")
    by_id = {}
    for entry in entries:
        content_id = entry.get("content_id")
        profile = PROFILES.get(content_id)
        if profile is None or content_id in by_id:
            fail("manifest content-cache identity is unknown or duplicated")
        expected = {
            "content_id",
            "contract",
            "digest",
            "media_type",
            "reboot_required",
            "repository",
            "required_entitlement",
            "restart_scope",
        }
        closed(entry, expected, f"manifest cache {content_id}")
        if (
            entry["repository"] != profile["repository"]
            or entry["required_entitlement"] != profile["entitlement"]
            or entry["media_type"] != ARTIFACT_TYPE
            or entry["reboot_required"] is not False
            or entry["restart_scope"] != []
        ):
            fail(
                f"manifest cache {content_id} violates its fixed identity/entitlement profile"
            )
        by_id[content_id] = entry

    artifacts = closure.get("artifacts")
    if not isinstance(artifacts, list):
        fail("closure artifacts is not an array")
    specs = []
    for content_id in sorted(PROFILES):
        entry, profile = by_id[content_id], PROFILES[content_id]
        matches = []
        for artifact in artifacts:
            if not isinstance(artifact, dict):
                continue
            root = artifact.get("root")
            if (
                isinstance(root, dict)
                and root.get("digest") == entry["digest"]
                and root.get("repository") == entry["repository"]
            ):
                matches.append(artifact)
        if len(matches) != 1:
            fail(
                f"manifest cache {content_id} does not select exactly one closure artifact"
            )
        artifact = matches[0]
        root = _artifact_root(artifact)
        if (
            artifact.get("artifact_key") != f"content:{content_id}"
            or artifact.get("artifact_class") != "oci-artifact"
            or artifact.get("repository") != profile["repository"]
            or artifact.get("candidate_repository") != profile["candidate_repository"]
            or artifact.get("required_entitlement") != profile["entitlement"]
        ):
            fail(
                f"closure cache {content_id} violates its fixed class/identity/entitlement profile"
            )
        root_digest = digest_name(root["digest"], f"cache {content_id} root")
        manifest_object, manifest_body = load_json(
            objects / root_digest, MAX_CONFIG_BYTES
        )
        if (
            hashlib.sha256(manifest_body).hexdigest() != root_digest
            or canonical_no_lf(manifest_object) != manifest_body
        ):
            fail(
                f"cache {content_id} OCI manifest is not digest-matched canonical JSON"
            )
        closed(
            manifest_object,
            {"schemaVersion", "mediaType", "artifactType", "config", "layers"},
            f"cache {content_id} OCI manifest",
        )
        if (
            manifest_object["schemaVersion"] != 2
            or manifest_object["mediaType"] != OCI_MANIFEST
            or manifest_object["artifactType"] != ARTIFACT_TYPE
        ):
            fail(f"cache {content_id} OCI manifest type is invalid")
        config_descriptor = manifest_object["config"]
        closed(
            config_descriptor,
            {"digest", "mediaType", "size"},
            f"cache {content_id} config descriptor",
        )
        if config_descriptor["mediaType"] != CONFIG_MEDIA_TYPE:
            fail(f"cache {content_id} config media type is invalid")
        config_size = positive_integer(
            config_descriptor["size"], "config size", MAX_CONFIG_BYTES
        )
        config_digest = digest_name(config_descriptor["digest"], "config digest")
        config, config_body = load_json(objects / config_digest, MAX_CONFIG_BYTES)
        if (
            len(config_body) != config_size
            or hashlib.sha256(config_body).hexdigest() != config_digest
        ):
            fail(f"cache {content_id} config descriptor does not match its object")
        if canonical_no_lf(config) != config_body:
            fail(
                f"cache {content_id} config is not canonical compact sorted JSON without LF"
            )
        closed(
            config,
            {"schema", "content_id", "format", "sha256", "size_bytes", "segments"},
            f"cache {content_id} config",
        )
        if (
            config["schema"] != SCHEMA
            or config["content_id"] != content_id
            or config["format"] != profile["format"]
            or not isinstance(config["sha256"], str)
            or not HEX.fullmatch(config["sha256"])
        ):
            fail(f"cache {content_id} config identity/format/digest is invalid")
        size_bytes = positive_integer(
            config["size_bytes"], "whole content size", MAX_CONTENT_BYTES
        )
        layers, segments = manifest_object["layers"], config["segments"]
        if (
            not isinstance(layers, list)
            or not isinstance(segments, list)
            or not segments
            or len(segments) > MAX_SEGMENTS
            or len(layers) != len(segments)
        ):
            fail(
                f"cache {content_id} segment set is empty, oversized, or differs from OCI layers"
            )
        normalized = []
        total = 0
        for index, (layer, segment) in enumerate(zip(layers, segments, strict=True)):
            closed(
                layer,
                {"digest", "mediaType", "size"},
                f"cache {content_id} layer {index}",
            )
            closed(segment, {"digest", "size"}, f"cache {content_id} segment {index}")
            size = positive_integer(
                segment["size"],
                f"cache {content_id} segment {index} size",
                MAX_SEGMENT_BYTES,
            )
            digest = digest_name(
                segment["digest"], f"cache {content_id} segment {index} digest"
            )
            if layer != {
                "digest": segment["digest"],
                "mediaType": SEGMENT_MEDIA_TYPE,
                "size": size,
            }:
                fail(f"cache {content_id} segment {index} differs from its OCI layer")
            if index + 1 < len(segments) and size != MAX_SEGMENT_BYTES:
                fail(f"cache {content_id} non-final segment is not exactly 8 GiB")
            total += size
            normalized.append((digest, size))
        if total != size_bytes:
            fail(f"cache {content_id} segment sizes do not equal whole content size")
        specs.append(
            (content_id, profile, config_body, config["sha256"], size_bytes, normalized)
        )
    return specs


def _open_segment(objects, digest, expected_size):
    path = objects / digest
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as error:
        fail(f"cannot open segment {digest}: {error}")
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size != expected_size
    ):
        os.close(descriptor)
        fail(f"segment {digest} is not the expected single-link regular file")
    return descriptor, metadata, path


def _segment_stable(descriptor, before, path, digest):
    after = os.fstat(descriptor)
    named = os.lstat(path)
    if _identity(before) != _identity(after) or (named.st_dev, named.st_ino) != (
        after.st_dev,
        after.st_ino,
    ):
        fail(f"segment {digest} changed while read")


def _fsync_directory(path):
    descriptor = os.open(
        path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def materialize(args):
    specs = collect_specs(args.closure, args.manifest, args.objects)
    destination, objects = pathlib.Path(args.destination), pathlib.Path(args.objects)
    if not specs:
        try:
            destination.mkdir(mode=0o700)
        except OSError as error:
            fail(f"cannot create empty content-cache destination: {error}")
        _fsync_directory(destination)
        print("content_caches=0")
        return
    required = sum(spec[4] for spec in specs) + RESERVE_BYTES
    filesystem = os.statvfs(destination.parent)
    available = filesystem.f_bavail * filesystem.f_frsize
    if available < required:
        fail(
            f"insufficient free space: need {required} bytes including reserve, have {available}"
        )
    try:
        destination.mkdir(mode=0o700)
        metadata_root = destination / ".metadata"
        metadata_root.mkdir(mode=0o700)
    except OSError as error:
        fail(f"cannot create owned content-cache destination: {error}")
    for content_id, profile, config_body, whole_digest, whole_size, segments in specs:
        cache = destination / content_id
        cache.mkdir(mode=0o700)
        target = cache / profile["filename"]
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
        output = os.open(target, flags, 0o400)
        whole = hashlib.sha256()
        written = 0
        try:
            for digest, size in segments:
                source, before, source_path = _open_segment(objects, digest, size)
                segment = hashlib.sha256()
                count = 0
                try:
                    while block := os.read(source, 1024 * 1024):
                        segment.update(block)
                        whole.update(block)
                        view = memoryview(block)
                        while view:
                            consumed = os.write(output, view)
                            if consumed <= 0:
                                fail("short write while reconstructing content cache")
                            view = view[consumed:]
                        count += len(block)
                        written += len(block)
                    _segment_stable(source, before, source_path, digest)
                finally:
                    os.close(source)
                if count != size or segment.hexdigest() != digest:
                    fail(f"segment {digest} failed size/hash readback")
            if written != whole_size or whole.hexdigest() != whole_digest:
                fail(
                    f"reconstructed cache {content_id} failed whole-file size/hash readback"
                )
            os.fsync(output)
        finally:
            os.close(output)
        proof = metadata_root / f"{content_id}.json"
        proof_fd = os.open(proof, flags, 0o400)
        try:
            view = memoryview(config_body)
            while view:
                consumed = os.write(proof_fd, view)
                if consumed <= 0:
                    fail("short write while preserving content-cache metadata")
                view = view[consumed:]
            os.fsync(proof_fd)
        finally:
            os.close(proof_fd)
        _fsync_directory(cache)
    _fsync_directory(metadata_root)
    _fsync_directory(destination)
    print(f"content_caches={len(specs)}")


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    install = subparsers.add_parser("materialize")
    install.add_argument("--closure", required=True)
    install.add_argument("--manifest", required=True)
    install.add_argument("--objects", required=True)
    install.add_argument("--destination", required=True)
    install.set_defaults(func=materialize)
    arguments = parser.parse_args()
    arguments.func(arguments)


if __name__ == "__main__":
    main()
