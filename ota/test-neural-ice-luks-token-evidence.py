#!/usr/bin/env python3
from __future__ import annotations

import base64
import copy
import hashlib
import json
import struct
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "ota/neural-ice-luks-token-evidence.py"
SRK_BODY = bytes(range(90))
SRK = struct.pack(">H", len(SRK_BODY)) + SRK_BODY
SRK_NAME = b"\x00\x0b" + hashlib.sha256(SRK_BODY).digest()
SERIALIZED_SRK = (
    struct.pack(">I", 0x81000001)
    + struct.pack(">H", len(SRK_NAME))
    + SRK_NAME
    + struct.pack(">I", 1)
    + SRK
)
BLOB = bytes(range(96))
PUBKEY = bytes(range(32, 128))
POLICY = "ab" * 32


def token() -> dict[str, object]:
    return {
        "type": "systemd-tpm2",
        "keyslots": ["1"],
        "tpm2-blob": base64.b64encode(BLOB).decode(),
        "tpm2-pcrs": [],
        "tpm2_pubkey": base64.b64encode(PUBKEY).decode(),
        "tpm2_pubkey_pcrs": [7],
        "tpm2-pcr-bank": "sha256",
        "tpm2-policy-hash": POLICY,
        "tpm2_srk": base64.b64encode(SERIALIZED_SRK).decode(),
    }


def metadata(value: dict[str, object] | None = None) -> dict[str, object]:
    return {"keyslots": {"1": {"type": "luks2"}}, "tokens": {"0": value or token()}}


def run(work: Path, value: object, *, raw: str | None = None) -> subprocess.CompletedProcess[str]:
    source = work / "metadata.json"
    source.write_text(raw if raw is not None else json.dumps(value), encoding="utf-8")
    return subprocess.run(
        [str(HELPER), str(source), str(work / "srk")],
        text=True,
        capture_output=True,
        check=False,
    )


def refused(work: Path, value: object, label: str) -> None:
    result = run(work, value)
    assert result.returncode == 1, f"{label} accepted: {result.stdout} {result.stderr}"


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="ni-luks-evidence-") as directory:
        work = Path(directory)
        (work / "srk").write_bytes(SRK)
        honest = run(work, metadata())
        assert honest.returncode == 0, honest.stderr
        parsed = json.loads(honest.stdout)
        assert parsed["schema"] == "neural-ice-luks-token-evidence-v1"
        assert parsed["keyslot"] == "1" and parsed["pcrs"] == [7]
        assert honest.stdout == json.dumps(parsed, sort_keys=True, separators=(",", ":")) + "\n"

        missing = metadata(); missing["tokens"] = {}
        refused(work, missing, "missing token")
        duplicate = metadata(); duplicate["tokens"]["1"] = copy.deepcopy(token())
        refused(work, duplicate, "duplicate token")
        for field in [
            "keyslots",
            "tpm2-pcrs",
            "tpm2-pcr-bank",
            "tpm2-policy-hash",
            "tpm2-blob",
            "tpm2_pubkey",
            "tpm2_pubkey_pcrs",
            "tpm2_srk",
        ]:
            changed = metadata(); del changed["tokens"]["0"][field]
            refused(work, changed, f"missing {field}")
        for field, wrong in [
            ("keyslots", ["2"]),
            ("tpm2-pcrs", [7]),
            ("tpm2_pubkey", "AA=="),
            ("tpm2_pubkey_pcrs", [0, 7]),
            ("tpm2-pcr-bank", "sha1"),
            ("tpm2-policy-hash", "AB" * 32),
            ("tpm2-blob", "AA=="),
            ("tpm2_srk", base64.b64encode(b"wrong").decode()),
        ]:
            changed = metadata(); changed["tokens"]["0"][field] = wrong
            refused(work, changed, f"wrong {field}")

        duplicate_keyslot = metadata(); duplicate_keyslot["tokens"]["0"]["keyslots"] = ["1", "1"]
        refused(work, duplicate_keyslot, "duplicate keyslot binding")

        missing_keyslot = metadata(); missing_keyslot["keyslots"] = {}
        refused(work, missing_keyslot, "missing referenced keyslot")
        noncanonical = metadata(); noncanonical["tokens"]["0"]["tpm2_srk"] += "\n"
        refused(work, noncanonical, "noncanonical base64")
        wrong_handle = metadata()
        wrong_handle["tokens"]["0"]["tpm2_srk"] = base64.b64encode(
            struct.pack(">I", 0x81000002) + SERIALIZED_SRK[4:]
        ).decode()
        refused(work, wrong_handle, "wrong persistent SRK handle")
        wrong_name = metadata()
        changed_name = bytearray(SERIALIZED_SRK)
        changed_name[10] ^= 1
        wrong_name["tokens"]["0"]["tpm2_srk"] = base64.b64encode(changed_name).decode()
        refused(work, wrong_name, "unauthenticated SRK public area")
        duplicate_json = '{"keyslots":{},"keyslots":{},"tokens":{}}'
        result = run(work, {}, raw=duplicate_json)
        assert result.returncode == 1, "duplicate JSON key accepted"

        extended = metadata(); extended["tokens"]["0"]["future-field"] = "bound"
        extended_result = run(work, extended)
        assert extended_result.returncode == 0
        assert json.loads(extended_result.stdout)["token_sha256"] != parsed["token_sha256"]

    print("LUKS_TOKEN_EVIDENCE_TEST_OK")


if __name__ == "__main__":
    main()
