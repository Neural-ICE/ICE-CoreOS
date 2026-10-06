#!/usr/bin/env python3
r"""Regenerate the v2 release attestation golden vectors (mission B, T0).

    python3 -I tools/ni-ota-verify/tests/fixtures/v2-release/generate-golden.py
    python3 -I tools/ni-ota-verify/tests/fixtures/v2-release/generate-golden.py --completed-only

The first form regenerates everything. The second rebuilds only `completed/` and the
`expected.completed` block of `golden.json` from the committed manifest, signature,
key and receipts: it signs nothing and changes no existing digest, so it is the form
to use when the completed-appliance vector (contract section 6.5) changes.

Needs python3 and the `openssl` CLI only. NOT run by CI (the pinned Rust image
has no Python): it is the documented, re-runnable procedure behind the committed
files, which `tests/v2_release_golden.rs` pins to the contract in
`docs/ota/V2-RELEASE-ATTESTATION.md`.

The signing key is generated here, in a private temporary directory, signs once
and is deleted with it: no private key is ever written under the repository, and
nothing here is, or resembles, a production key. ECDSA signatures are randomised,
so a full regeneration changes the key, the signature and every digest derived from
them (regenerable, NOT reproducible); reviewers compare the contract (field names,
sizes, relations), not the bytes. Consumers (T1 verifier, T2 ceremony, T3b autoinstall) read `golden.json`
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
import sys
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


# The completion digest of the TPM-bound evidence (contract 6.1): COMPLETION_MAGIC_V2.
COMPLETION_MAGIC_V2 = b"neural-ice:tpm:owner-ceremony-completion:v2\0"
OTA_DIR = "var/lib/neural-ice/ota"
MODES = ("manifest-digest", "floor")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compact(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def is_high_s(der: bytes) -> bool:
    """True when the DER ECDSA signature's s is above half the curve order."""
    index = 2 if der[1] < 0x80 else 2 + (der[1] & 0x7F)
    assert der[0] == 0x30 and der[index] == 0x02
    index += 2 + der[index + 1]  # skip r
    assert der[index] == 0x02
    s = int.from_bytes(der[index + 2 : index + 2 + der[index + 1]], "big")
    return s > P256_ORDER // 2


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


def luks() -> dict:
    # Placeholders of the right shape (contract 6.5): the reader of the lane judges the
    # key set and the schema of these objects, nothing else.
    return {
        "keyslot": "0",
        "pcr_bank": "sha256",
        "pcrs": [7],
        "policy_hash": "11" * 32,
        "policy_public_key_sha256": "22" * 32,
        "schema": "neural-ice-luks-token-evidence-v1",
        "sealed_object_sha256": "33" * 32,
        "srk_sha256": "44" * 32,
        "token_sha256": "55" * 32,
    }


def ota_state() -> dict:
    # The REAL constants of evidence v2 (access_profile_anchor.rs): the TPM objects of
    # the v2 lane are identical to the v1 lane's.
    pristine = "000b038de2091c1c8ef2e8fd8869f17bef3a576ae287530fa17f05ae3b9712014b5d"
    return {
        "anchor_attributes": "0x2060048",
        "anchor_index": "0x01500002",
        "anchor_name_at_completion": pristine,
        "anchor_policy_sha256": "b6a2e7142ee56fd978047488483daa5b42b8dc4cc7ddcceddfb91793cf1ff1b7",
        "anchor_pristine_name": pristine,
        "anchor_size": 32,
        "anchor_state_at_completion": "pristine",
        "anchor_written_name": "000b11afd155aca82a503f2029cc11395389654c3a25fc54b9eca6d33abdff498d56",
        "baseline_floor": BUNDLE_SEQ,
        "clear_protected_at_completion": True,
        "floor_attributes": "0x62008",
        "floor_index": "0x01500001",
        "floor_name": "000be283f20a38b93f8cef085efb4aee9f5944cc3b3b28b850bf3c0eeb2054cd7fc4",
        "floor_policy_sha256": "f83217e5a2a04342f7daa55ccfb3cd4b8a1f1e8ebb28c7719a9abbdbd638a230",
        "floor_size": 8,
        "profile": "owner-sealed-ota-state-v1",
    }


def completed_fixture() -> dict:
    """The completed-appliance vector (contract 6.5), derived from the committed files."""
    manifest_bytes = (HERE / "release-manifest.json").read_bytes()
    sig_bytes = (HERE / "release-manifest.json.sig").read_bytes()
    manifest_sha, sig_sha = sha(manifest_bytes), sha(sig_bytes)
    key_sha = sha((HERE / "release-authorization.pub").read_bytes())
    shutil.rmtree(HERE / "completed", ignore_errors=True)

    identity = (
        compact(
            {
                "install_source": "medium",
                # The installer has no trusted clock (autoinstall.sh): fixed on purpose.
                "installed_at": "1970-01-01T00:00:00Z",
                "installer_sealed_identity_sha256": "66" * 32,
                "release_identity_sha256": manifest_sha,
                "schema": "neural-ice-owner-ceremony-install-identity-v1",
            }
        )
        + b"\n"
    )
    completed = {}
    for mode in MODES:
        receipt_bytes = (HERE / f"expected-receipt-{mode}.json").read_bytes()
        evidence = (
            compact(
                {
                    "access_profile_anchor": {
                        # Placeholders: sha256 of fixed labels, not of real anchor files.
                        "json_sha256": sha(b"neural-ice-golden:access-profile-v1.json"),
                        "signature_sha256": sha(b"neural-ice-golden:access-profile-v1.sig"),
                        "spki_sha256": sha(b"neural-ice-golden:access-profile-v1.spki"),
                    },
                    "data_luks": luks(),
                    "device_root_name": "000b" + "11" * 32,
                    "install_identity": json.loads(identity),
                    "ota_state": ota_state(),
                    "schema": "neural-ice-owner-ceremony-evidence-v2-lane2",
                    "srk_name": "000b" + "aa" * 32,
                    "system_luks": luks(),
                    "tpm_state": {
                        "freshness_counter": BUNDLE_SEQ,
                        "freshness_public_sha256": "bb" * 32,
                        "install_counter": 1,
                        "install_public_sha256": "cc" * 32,
                        "profile_binding": "dd" * 32,
                        "schema": "neural-ice-tpm-state-snapshot-v1",
                    },
                    "v2_release": {
                        "bundle_seq": BUNDLE_SEQ,
                        "manifest_sha256": manifest_sha,
                        "manifest_sig_sha256": sig_sha,
                        "receipt_schema": "neural-ice-v2-release-receipt-v1",
                        "receipt_sha256": sha(receipt_bytes),
                        "release_id": RELEASE_ID,
                        "release_key_sha256": key_sha,
                    },
                }
            )
            + b"\n"
        )
        completion_digest = sha(COMPLETION_MAGIC_V2 + evidence)
        inspection = (
            compact(
                {
                    "completion_version": 2,
                    "evidence_digest_sha256": completion_digest,
                    "schema": "neural-ice-owner-ceremony-completion-inspection-v1",
                }
            )
            + b"\n"
        )
        root = f"completed/{mode}"
        write(f"{root}/completion-inspection.json", inspection)
        write(f"{root}/{OTA_DIR}/owner-ceremony-evidence-v2.json", evidence)
        write(f"{root}/{OTA_DIR}/owner-ceremony-install-identity-v1.json", identity)
        write(f"{root}/{OTA_DIR}/v2-release-input-v1/release-manifest.json", manifest_bytes)
        write(f"{root}/{OTA_DIR}/v2-release-input-v1/release-manifest.json.sig", sig_bytes)
        write(f"{root}/{OTA_DIR}/v2-release/receipt.json", receipt_bytes)
        completed[mode] = {
            "completion_digest_sha256": completion_digest,
            "evidence_sha256": sha(evidence),
            "receipt_sha256": sha(receipt_bytes),
        }
    return completed


def write_golden(golden: dict) -> None:
    write("golden.json", json.dumps(golden, indent=2, sort_keys=True).encode() + b"\n")


def completed_only() -> None:
    golden = json.loads((HERE / "golden.json").read_bytes())
    golden["expected"]["completed"] = completed_fixture()
    write_golden(golden)


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
        # A KMS signs either form of s, and the lane must accept both (contract 2, "High-S
        # is accepted"). The vector is deliberately HIGH-S so a verifier that pre-filters
        # to low-S fails against it; ECDSA is randomised, so sign until it is.
        for _ in range(64):
            openssl("dgst", "-sha256", "-sign", str(key), "-out", str(work / "sig.der"), str(work / "manifest"))
            if is_high_s((work / "sig.der").read_bytes()):
                break
        else:
            raise SystemExit("no high-S signature in 64 attempts")
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
    golden["expected"]["completed"] = completed_fixture()
    write_golden(golden)


if __name__ == "__main__":
    if sys.argv[1:] == ["--completed-only"]:
        completed_only()
    elif not sys.argv[1:]:
        main()
    else:
        raise SystemExit("usage: generate-golden.py [--completed-only]")
