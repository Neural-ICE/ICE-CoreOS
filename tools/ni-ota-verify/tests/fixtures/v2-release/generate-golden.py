#!/usr/bin/env python3
r"""Regenerate the v2 release attestation golden vectors (mission B, T0).

    python3 -I tools/ni-ota-verify/tests/fixtures/v2-release/generate-golden.py

Needs python3 and the `openssl` CLI only. NOT run by CI (the pinned Rust image
has no Python): it is the documented, re-runnable procedure behind the committed
files, which `tests/v2_release_golden.rs` pins to the contract in
`docs/ota/V2-RELEASE-ATTESTATION.md`.

The signing key is generated here, in a private temporary directory, signs once
and is deleted with it: no private key is ever written under the repository, and
nothing here is, or resembles, a production key. ECDSA signatures are randomised,
so a regeneration changes the key, the signature and every digest derived from
them; reviewers compare the contract (field names, sizes, relations), not the
bytes. Consumers (T1 verifier, T2 ceremony, T3b autoinstall) read `golden.json`
and never hard-code a digest.

Everything is synthetic: the authority `registry.example.test` is the RFC 6761
test domain, the digests are patterns, the release id is a placeholder.
"""

from __future__ import annotations

import base64
import hashlib
import json
import pathlib
import shutil
import subprocess
import tempfile

HERE = pathlib.Path(__file__).resolve().parent

AUTHORITY = "registry.example.test"
HOST_REPOSITORY = f"{AUTHORITY}/neural-ice-test/host-appliance"
HARDWARE_TARGET = "nvidia-gb10-arm64"
ACCESS_PROFILE = "lab-managed"
TRUST_POLICY_ID = "neural-ice-secureboot-lab-v1"
VARIANT = "sealed-lab"
RELEASE_ID = "v2-test-train-3"
BUNDLE_SEQ = 3
# Floor mode seals a MINIMUM; the manifest must be accepted at >= it, so the
# vector deliberately differs from the manifest's own bundle_seq.
SEALED_MIN_BUNDLE_SEQ = 2
HOST_INDEX_DIGEST = "sha256:" + "a1" * 32
HOST_MANIFEST_DIGEST = "sha256:" + "b2" * 32
LANE_MARKER = "owner-sealed-ota-state-v2"

STATUS = (
    b'{"committed_generation":null,"completion_version":2,'
    b'"enforce_ready_verified":false,"profile":"owner-sealed-ota-state-v1",'
    b'"schema":"neural-ice-authenticated-ota-status-v1"}\n'
)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compact(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def openssl(*args: str) -> None:
    subprocess.run(["openssl", *args], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)


def manifest() -> dict:
    def entry(cid: str, digest_byte: str, entitlement: str, scope: list[str]) -> dict:
        return {
            "component_id": cid,
            "contract": "component-oci-v1",
            "digest": "sha256:" + digest_byte * 64,
            "reboot_required": False,
            "repository": f"{AUTHORITY}/neural-ice-test/{cid}",
            "required_entitlement": entitlement,
            "restart_scope": scope,
        }

    return {
        "bundle_seq": BUNDLE_SEQ,
        "compatibility": {
            "minimum_reader": 1,
            "required_contracts": ["component-oci-v1", "host-bootc-v1"],
        },
        "components": [entry("icecore-api", "2", "ICE-CORE", ["icecore-api.service"])],
        "content": [],
        "evidence": [
            {"digest": "sha256:" + "5" * 64, "kind": "attestation"},
            {"digest": "sha256:" + "6" * 64, "kind": "bom"},
        ],
        "hardware_target": HARDWARE_TARGET,
        "host": {
            "contract": "host-bootc-v1",
            "digest": HOST_INDEX_DIGEST,
            "reboot_required": True,
            "repository": HOST_REPOSITORY,
            "required_entitlement": "ICE-CORE",
            "restart_scope": ["bootc-fetch-apply-updates.service"],
        },
        "release_id": RELEASE_ID,
        "schema": "neural-ice-release-manifest-v1",
    }


def write(relative: str, data: bytes) -> None:
    path = HERE / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def main() -> None:
    # Start from a clean tree so a removed vector cannot linger.
    for stale in HERE.iterdir():
        if stale.name != pathlib.Path(__file__).name:
            shutil.rmtree(stale) if stale.is_dir() else stale.unlink()

    manifest_bytes = compact(manifest())  # no trailing LF, as the KMS-signed files
    with tempfile.TemporaryDirectory(prefix="ni-v2-golden-") as work_name:
        work = pathlib.Path(work_name)
        key, pub = work / "key.pem", work / "pub.pem"
        openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(key))
        openssl("ec", "-in", str(key), "-pubout", "-out", str(pub))
        (work / "manifest").write_bytes(manifest_bytes)
        openssl("dgst", "-sha256", "-sign", str(key), "-out", str(work / "sig.der"), str(work / "manifest"))
        sig_bytes = base64.b64encode((work / "sig.der").read_bytes())  # no trailing LF
        pub_bytes = pub.read_bytes()
        openssl("dgst", "-sha256", "-verify", str(pub), "-signature", str(work / "sig.der"), str(work / "manifest"))

    write("release-manifest.json", manifest_bytes)
    write("release-manifest.json.sig", sig_bytes)
    write("release-authorization.pub", pub_bytes)

    manifest_sha, sig_sha, key_sha = sha(manifest_bytes), sha(sig_bytes), sha(pub_bytes)

    # The candidate (installed host) root the verifier probes WITHOUT executing it.
    markers = {
        "hardware-target": HARDWARE_TARGET,
        "appliance-variant": VARIANT,
        "signed-boot-trust-policy-id": TRUST_POLICY_ID,
        "access-policy": ACCESS_PROFILE,
        "ota-state-profile": LANE_MARKER,
    }
    for name, value in markers.items():
        write(f"candidate-root/usr/lib/neural-ice/{name}", f"{value}\n".encode())
    write("candidate-root/usr/lib/neural-ice/keys/release-authorization.pub", pub_bytes)

    def receipt(seal: dict) -> bytes:
        return compact(
            {
                "access_profile": ACCESS_PROFILE,
                "bundle_seq": BUNDLE_SEQ,
                "hardware_target": HARDWARE_TARGET,
                "host_index_digest": HOST_INDEX_DIGEST,
                "host_manifest_digest": HOST_MANIFEST_DIGEST,
                "host_repository": HOST_REPOSITORY,
                "manifest_sha256": manifest_sha,
                "manifest_sig_sha256": sig_sha,
                "release_id": RELEASE_ID,
                "release_key_sha256": key_sha,
                "schema": "neural-ice-v2-release-receipt-v1",
                "seal": seal,
                "signed_boot_trust_policy_id": TRUST_POLICY_ID,
                "variant": VARIANT,
            }
        ) + b"\n"

    digest_receipt = receipt(
        {"min_bundle_seq": None, "mode": "manifest-digest", "sealed_manifest_sha256": manifest_sha}
    )
    floor_receipt = receipt(
        {"min_bundle_seq": SEALED_MIN_BUNDLE_SEQ, "mode": "floor", "sealed_manifest_sha256": None}
    )
    write("expected-receipt-manifest-digest.json", digest_receipt)
    write("expected-receipt-floor.json", floor_receipt)
    write("expected-authenticated-ota-status.json", STATUS)

    golden = {
        "schema": "neural-ice-v2-release-golden-v1",
        "inputs": {
            "access_profile": ACCESS_PROFILE,
            "hardware_target": HARDWARE_TARGET,
            "host_index_digest": HOST_INDEX_DIGEST,
            "host_manifest_digest": HOST_MANIFEST_DIGEST,
            "release_authority": AUTHORITY,
            "sealed_key_sha256": key_sha,
            "sealed_manifest_sha256": manifest_sha,
            "sealed_manifest_sig_sha256": sig_sha,
            "sealed_min_bundle_seq": SEALED_MIN_BUNDLE_SEQ,
            "trust_policy_id": TRUST_POLICY_ID,
            "variant": VARIANT,
        },
        "expected": {
            "bundle_seq": BUNDLE_SEQ,
            "host_repository": HOST_REPOSITORY,
            "receipt_sha256": {
                "manifest-digest": sha(digest_receipt),
                "floor": sha(floor_receipt),
            },
            "release_id": RELEASE_ID,
            "status_sha256": sha(STATUS),
            "verify_stdout": {
                "manifest-digest": {
                    "bundle_seq": BUNDLE_SEQ,
                    "idempotent": False,
                    "receipt_sha256": sha(digest_receipt),
                    "verdict": "pass",
                },
                "floor": {
                    "bundle_seq": BUNDLE_SEQ,
                    "idempotent": False,
                    "receipt_sha256": sha(floor_receipt),
                    "verdict": "pass",
                },
            },
        },
    }
    write("golden.json", json.dumps(golden, indent=2, sort_keys=True).encode() + b"\n")


if __name__ == "__main__":
    main()
