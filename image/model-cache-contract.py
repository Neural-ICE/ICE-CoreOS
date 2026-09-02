#!/usr/bin/env python3
"""Produce and materialize the signed HF-cache model-card contract."""

import argparse
import errno
import hashlib
import json
import os
import pathlib
import re
import shutil
import stat
import sys

SCHEMA = "neural-ice-hf-cache-model-card-v1"
ARTIFACT_TYPE = "application/vnd.neural-ice.hf-cache-model-card.v1"
MEDIA_TYPE = "application/vnd.neural-ice.hf-cache-model-card.v1+json"
FILE_MEDIA_TYPE = "application/vnd.neural-ice.hf-cache.model.file"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
HEX = re.compile(r"^[0-9a-f]{64}$")
REV = re.compile(r"^[0-9a-f]{40}$")
CARD = re.compile(r"^[a-z0-9]+(?:[_-][a-z0-9]+)*$")
MODEL_PART = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def fail(message):
    raise SystemExit(f"model-cache-contract: REFUSED: {message}")


def load(path):
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                fail(f"duplicate JSON member {key!r} in {path}")
            result[key] = value
        return result
    try:
        return json.loads(pathlib.Path(path).read_bytes(), object_pairs_hook=pairs)
    except (OSError, ValueError) as error:
        fail(f"cannot read {path}: {error}")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii") + b"\n"


def digest_file(path):
    hasher, size = hashlib.sha256(), 0
    with path.open("rb") as handle:
        while block := handle.read(1024 * 1024):
            hasher.update(block)
            size += len(block)
    return hasher.hexdigest(), size


def safe_model(model):
    parts = model.split("/")
    if len(parts) != 2 or not all(MODEL_PART.fullmatch(part) for part in parts):
        fail(f"unsafe model repository {model!r}")
    return "models--" + "--".join(parts)


def safe_relative(value):
    path = pathlib.PurePosixPath(value)
    if not value or value.startswith("/") or "\0" in value or "\n" in value or ".." in path.parts:
        fail(f"unsafe model file path {value!r}")
    return path.as_posix()


def validate_card(value):
    if not isinstance(value, dict) or set(value) != {
        "cache_directory", "card_id", "files", "model", "revision", "schema"
    } or value["schema"] != SCHEMA:
        fail("model-card document has the wrong closed schema")
    if not CARD.fullmatch(value["card_id"]) or safe_model(value["model"]) != value["cache_directory"]:
        fail("model-card identity is invalid")
    if not REV.fullmatch(value["revision"]):
        fail("model-card revision is not a pinned forty-character commit")
    files, prior = value["files"], None
    if not isinstance(files, list) or not files:
        fail("model-card has no files")
    for entry in files:
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256", "size"}:
            fail("model-card file entry has the wrong closed schema")
        name = safe_relative(entry["path"])
        if prior is not None and name <= prior:
            fail("model-card files are not a sorted unique set")
        prior = name
        if not isinstance(entry["sha256"], str) or not HEX.fullmatch(entry["sha256"]):
            fail(f"model-card file {name!r} has an invalid digest")
        if not isinstance(entry["size"], int) or isinstance(entry["size"], bool) or entry["size"] < 0:
            fail(f"model-card file {name!r} has an invalid size")
    return value


def install_object(source, objects, expected=None):
    digest, size = digest_file(source)
    if expected is not None and digest != expected:
        fail(f"{source} hashes to {digest}, expected {expected}")
    destination = objects / digest
    if destination.exists():
        observed, observed_size = digest_file(destination)
        if observed != digest or observed_size != size:
            fail(f"existing object {destination} is corrupt")
    else:
        shutil.copyfile(source, destination)
        os.chmod(destination, 0o444)
    return digest, size


def produce(args):
    profiles, catalogue = load(args.profiles), load(args.catalogue)
    objects, cache = pathlib.Path(args.objects), pathlib.Path(args.hf_cache)
    objects.mkdir(parents=True, exist_ok=True)
    cards = profiles.get("profiles")
    if not isinstance(cards, dict):
        fail("model profiles lacks its profiles object")
    selected = [entry for entry in catalogue.get("models", []) if entry.get("catalog_status") == "validated"]
    if not selected:
        fail("model catalogue declares no validated model")
    identifiers = [entry.get("id") for entry in selected]
    if len(identifiers) != len(set(identifiers)):
        fail("model catalogue repeats a validated card id")
    emitted = []
    for entry in sorted(selected, key=lambda item: item.get("id", "")):
        card_id, model, revision = entry.get("id"), entry.get("model"), entry.get("hf_revision")
        if card_id not in cards or cards[card_id].get("catalog_status") != "validated" \
                or cards[card_id].get("model") != model:
            fail(f"catalogue card {card_id!r} disagrees with model profiles")
        directory = safe_model(model)
        snapshot = cache / directory / "snapshots" / str(revision)
        if not REV.fullmatch(str(revision)) or not snapshot.is_dir() or snapshot.is_symlink():
            fail(f"validated card {card_id!r} has no safe pinned snapshot")
        files = []
        for path in sorted(snapshot.rglob("*")):
            if path.is_dir():
                continue
            relative = safe_relative(path.relative_to(snapshot).as_posix())
            resolved = path.resolve(strict=True)
            blobs = (cache / directory / "blobs").resolve(strict=True)
            if blobs not in resolved.parents or not resolved.is_file():
                fail(f"snapshot entry {path} does not resolve to this card's blobs directory")
            digest, size = install_object(resolved, objects)
            files.append({"path": relative, "sha256": digest, "size": size})
        if len(files) != entry.get("file_count") or sum(item["size"] for item in files) != entry.get("size_bytes"):
            fail(f"validated card {card_id!r} file count/size differs from catalogue")
        document = validate_card({
            "cache_directory": directory, "card_id": card_id, "files": files,
            "model": model, "revision": revision, "schema": SCHEMA,
        })
        body = canonical(document)
        digest = hashlib.sha256(body).hexdigest()
        target = objects / digest
        if target.exists() and target.read_bytes() != body:
            fail(f"model-card digest collision for {card_id}")
        target.write_bytes(body)
        os.chmod(target, 0o444)
        layers = [{"digest": "sha256:" + item["sha256"], "mediaType": FILE_MEDIA_TYPE,
                   "size": item["size"]} for item in files]
        manifest = canonical({
            "artifactType": ARTIFACT_TYPE,
            "config": {"digest": "sha256:" + digest, "mediaType": MEDIA_TYPE, "size": len(body)},
            "layers": layers,
            "schemaVersion": 2,
        })
        root_digest = hashlib.sha256(manifest).hexdigest()
        root = objects / root_digest
        if root.exists() and root.read_bytes() != manifest:
            fail(f"model-card OCI manifest digest collision for {card_id}")
        root.write_bytes(manifest)
        os.chmod(root, 0o444)
        emitted.append((card_id, root_digest, len(files)))
    for card_id, digest, count in emitted:
        print(f"model_card={card_id}:sha256:{digest}:{count}")


def closure_cards(closure, objects):
    cards = []
    for artifact in closure.get("artifacts", []):
        if artifact.get("artifact_class") != "oci-artifact":
            continue
        root = artifact.get("root")
        if not isinstance(root, dict) or set(root) != {"digest", "repository"}:
            fail("HF model-card closure root is not the object-valued v2 shape")
        digest = root["digest"].removeprefix("sha256:")
        if not HEX.fullmatch(digest):
            fail("HF model-card closure root digest is invalid")
        nodes = {node.get("digest"): node for node in artifact.get("nodes", [])}
        node = nodes.get(root["digest"])
        if not node or node.get("kind") != "manifest" or node.get("media_type") != OCI_MANIFEST \
                or node.get("artifact_type") != ARTIFACT_TYPE:
            continue
        config_edges = [edge for edge in artifact.get("edges", [])
                        if edge.get("parent_digest") == root["digest"] and edge.get("edge_kind") == "config"]
        layer_edges = [edge for edge in artifact.get("edges", [])
                       if edge.get("parent_digest") == root["digest"] and edge.get("edge_kind") == "layers"]
        if len(config_edges) != 1 or config_edges[0].get("media_type") != MEDIA_TYPE:
            fail("HF model-card artifact lacks its unique typed config")
        card_digest = config_edges[0]["child_digest"].removeprefix("sha256:")
        source = objects / card_digest
        body = source.read_bytes()
        if hashlib.sha256(body).hexdigest() != card_digest or canonical(load(source)) != body:
            fail("HF model-card object is not digest-matched canonical JSON")
        card = validate_card(load(source))
        declared = {edge.get("child_digest") for edge in layer_edges
                    if edge.get("media_type") == FILE_MEDIA_TYPE}
        for entry in card["files"]:
            if "sha256:" + entry["sha256"] not in declared:
                fail(f"model-card file {entry['path']!r} is not a typed layer of its closure artifact")
        cards.append(card)
    if not cards:
        fail("signed closure carries no HF-cache model card")
    return sorted(cards, key=lambda card: card["card_id"])


def durable_tree(root):
    for directory, _, files in os.walk(root, topdown=False, followlinks=False):
        for name in files:
            path = pathlib.Path(directory) / name
            if not path.is_symlink():
                with path.open("rb") as handle:
                    os.fsync(handle.fileno())
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def materialize(args):
    closure, objects = load(args.closure), pathlib.Path(args.objects)
    content, destination = pathlib.Path(args.content), pathlib.Path(args.destination)
    hub = destination / "hub"
    hub.mkdir(parents=True, exist_ok=False)
    for card in closure_cards(closure, objects):
        model_root = hub / card["cache_directory"]
        blobs, snapshot, refs = model_root / "blobs", model_root / "snapshots" / card["revision"], model_root / "refs"
        blobs.mkdir(parents=True)
        snapshot.mkdir(parents=True)
        refs.mkdir()
        for entry in card["files"]:
            source, blob = content / entry["sha256"], blobs / entry["sha256"]
            observed, size = digest_file(source)
            if observed != entry["sha256"] or size != entry["size"]:
                fail(f"content object for {card['card_id']}:{entry['path']} failed readback")
            try:
                os.link(source, blob)
            except OSError as error:
                if error.errno != errno.EXDEV:
                    raise
                shutil.copyfile(source, blob)
            os.chmod(blob, 0o444)
            observed, size = digest_file(blob)
            if observed != entry["sha256"] or size != entry["size"]:
                fail(f"published blob for {card['card_id']}:{entry['path']} failed readback")
            link = snapshot / entry["path"]
            link.parent.mkdir(parents=True, exist_ok=True)
            depth = len(pathlib.PurePosixPath(entry["path"]).parts)
            link.symlink_to("../" * (depth + 1) + "blobs/" + entry["sha256"])
        # huggingface_hub reads refs as opaque revision bytes; a transport LF
        # becomes part of the snapshots/<revision> path and breaks offline
        # resolution. stage-models.sh writes this exact no-LF representation.
        (refs / "main").write_bytes(card["revision"].encode("ascii"))
    durable_tree(destination)
    print(f"model_cards={len(closure_cards(closure, objects))}")


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    generate = sub.add_parser("produce")
    generate.add_argument("--hf-cache", required=True)
    generate.add_argument("--profiles", required=True)
    generate.add_argument("--catalogue", required=True)
    generate.add_argument("--objects", required=True)
    generate.set_defaults(func=produce)
    install = sub.add_parser("materialize")
    install.add_argument("--closure", required=True)
    install.add_argument("--objects", required=True)
    install.add_argument("--content", required=True)
    install.add_argument("--destination", required=True)
    install.set_defaults(func=materialize)
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
