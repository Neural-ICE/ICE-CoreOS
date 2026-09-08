#!/usr/bin/env python3
"""Bind PRELOADED inputs to the pinned appliance before any large seed/raw work.

Signature verification remains the native SEED verifier's responsibility. This
gate prevents composing separately valid inputs from different appliances.
The image is inspected through a never-started, task-owned local container.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


ROOTFUL_PODMAN = ("sudo", "podman")
IMAGE_PROBE_TIMEOUT = 120
IMAGE_PULL_TIMEOUT = 20 * 60


def read(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 64 * 1024 * 1024:
        raise ValueError(f"unsafe or oversized input: {path}")
    return path.read_bytes()


def document(path):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError(f"duplicate member: {key}")
            result[key] = value
        return result
    return json.loads(read(path), object_pairs_hook=pairs)


def reference(value):
    match = re.fullmatch(r"([^\s@]+)@(sha256:[0-9a-f]{64})", value)
    if not match:
        raise ValueError("appliance reference must be digest-pinned")
    return match.groups()


def bind(args):
    auth, closure = document(args.authorization), document(args.closure)
    subject = auth["subject"]
    expected = {"repository": subject["repository"], "digest": subject["digest"]}
    if auth["schema"] != "neural-ice-ota-release-authorization-v2" or auth["purpose"] != "ota" or auth["installer_medium"] is not None:
        raise ValueError("SEED requires Fabric OTA-v2 with no installer medium")
    hosts = [artifact["root"] for artifact in closure["artifacts"] if artifact["artifact_key"].startswith("os:")]
    if hosts != [expected] or auth["host_digest"] != subject["digest"] or closure["host_digest"] != subject["digest"]:
        raise ValueError("SEED subject must be the unique closure host")
    if reference(args.base_image)[1] != subject["digest"] or reference(args.target_image) != (subject["repository"], subject["digest"]):
        raise ValueError("BASE_IMAGE/TARGET_IMGREF differs from authorized closure host")
    for field, path in (("release_closure_sha256", args.closure), ("release_manifest_sha256", args.manifest)):
        if hashlib.sha256(read(path)).hexdigest() != auth[field]:
            raise ValueError(f"{field} differs from exact input bytes")


def acquire_base_image(base_image):
    probe = subprocess.run(
        [*ROOTFUL_PODMAN, "image", "exists", base_image],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=IMAGE_PROBE_TIMEOUT,
    )
    if probe.returncode == 0:
        return
    if probe.returncode != 1:
        raise ValueError(
            f"rootful Podman image probe returned unexpected status {probe.returncode}"
        )

    command = [*ROOTFUL_PODMAN, "pull"]
    authfile = os.environ.get("REGISTRY_AUTH_FILE")
    if authfile:
        command.extend(("--authfile", authfile))
    result = subprocess.run(
        [*command, base_image],
        timeout=IMAGE_PULL_TIMEOUT,
    )
    if result.returncode != 0:
        raise ValueError(
            f"rootful Podman image pull failed with status {result.returncode}"
        )


def baked_inputs(args):
    # Bind has already selected the exact digest. Acquire it in the same rootful
    # store used by the child media builder, then inspect without starting it.
    acquire_base_image(args.base_image)
    container = subprocess.check_output([
        *ROOTFUL_PODMAN, "create", "--pull=never", "--network=none",
        "--entrypoint=/bin/true", args.base_image,
    ], text=True, timeout=120).strip()
    if not re.fullmatch(r"[0-9a-f]{64}", container):
        raise ValueError("podman returned no exact task container identity")
    try:
        with tempfile.TemporaryDirectory(prefix="ni-preloaded-inputs-") as scratch:
            for source, supplied, label in (
                ("/usr/lib/neural-ice/product-payload/etc/neural-ice/inference/model-profiles.json", args.profiles, "profiles"),
                ("/usr/lib/neural-ice/model-baseline-v1/catalogue.json", args.catalogue, "catalogue"),
                ("/etc/neural-ice/keys/ota-root.pub", args.root_pubkey, "OTA root"),
            ):
                target = Path(scratch) / "input"
                subprocess.run([*ROOTFUL_PODMAN, "cp", f"{container}:{source}", str(target)], check=True, timeout=120)
                if read(target) != read(supplied):
                    raise ValueError(f"{label} differs from the pinned appliance")
                target.unlink()
    finally:
        subprocess.run([*ROOTFUL_PODMAN, "rm", container], check=True, stdout=subprocess.DEVNULL, timeout=120)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("authorization", "closure", "manifest", "base-image", "target-image", "profiles", "catalogue", "root-pubkey"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    try:
        bind(args)
        baked_inputs(args)
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError) as error:
        parser.exit(1, f"preloaded-inputs: REFUSED: {error}\n")


if __name__ == "__main__":
    main()
