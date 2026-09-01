#!/usr/bin/env python3
"""Emit one canonical, closed proof of a systemd TPM2 LUKS token."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import sys
from pathlib import Path


class Refusal(ValueError):
    pass


def object_without_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise Refusal(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def canonical_base64(value: object, field: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise Refusal(f"{field} is absent or not a string")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as error:
        raise Refusal(f"{field} is not strict base64") from error
    if not decoded or base64.b64encode(decoded).decode("ascii") != value:
        raise Refusal(f"{field} is not canonical base64")
    return decoded


def evidence(metadata_path: Path, expected_srk_path: Path) -> dict[str, object]:
    try:
        metadata = json.loads(
            metadata_path.read_text(encoding="utf-8"),
            object_pairs_hook=object_without_duplicates,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, Refusal) as error:
        raise Refusal(f"LUKS2 metadata is not closed JSON: {error}") from error
    if not isinstance(metadata, dict):
        raise Refusal("LUKS2 metadata is not an object")

    tokens = metadata.get("tokens")
    keyslots = metadata.get("keyslots")
    if not isinstance(tokens, dict) or not isinstance(keyslots, dict):
        raise Refusal("LUKS2 metadata has no token/keyslot maps")
    selected = [value for value in tokens.values() if isinstance(value, dict) and value.get("type") == "systemd-tpm2"]
    if len(selected) != 1:
        raise Refusal("expected exactly one systemd-tpm2 token")
    token = selected[0]

    token_keyslots = token.get("keyslots")
    if (
        not isinstance(token_keyslots, list)
        or len(token_keyslots) != 1
        or not isinstance(token_keyslots[0], str)
        or re.fullmatch(r"0|[1-9][0-9]*", token_keyslots[0]) is None
        or token_keyslots[0] not in keyslots
    ):
        raise Refusal("systemd-tpm2 token does not name one existing canonical keyslot")
    keyslot = token_keyslots[0]

    if token.get("tpm2-pcrs") != [7]:
        raise Refusal("systemd-tpm2 token is not bound to exactly PCR 7")
    if token.get("tpm2-pcr-bank") != "sha256":
        raise Refusal("systemd-tpm2 token does not use the sha256 PCR bank")
    policy_hash = token.get("tpm2-policy-hash")
    if not isinstance(policy_hash, str) or re.fullmatch(r"[0-9a-f]{64}", policy_hash) is None:
        raise Refusal("systemd-tpm2 token has no canonical sha256 policy hash")

    blob = canonical_base64(token.get("tpm2-blob"), "tpm2-blob")
    if len(blob) < 32:
        raise Refusal("systemd-tpm2 sealed object is implausibly short")
    srk = canonical_base64(token.get("tpm2_srk"), "tpm2_srk")
    try:
        expected_srk = expected_srk_path.read_bytes()
    except OSError as error:
        raise Refusal(f"intended SRK is unreadable: {error}") from error
    if not expected_srk or srk != expected_srk:
        raise Refusal("systemd-tpm2 token SRK does not equal installer intent")

    token_bytes = canonical_json(token)
    return {
        "keyslot": keyslot,
        "pcr_bank": "sha256",
        "pcrs": [7],
        "policy_hash": policy_hash,
        "schema": "neural-ice-luks-token-evidence-v1",
        "sealed_object_sha256": hashlib.sha256(blob).hexdigest(),
        "srk_sha256": hashlib.sha256(srk).hexdigest(),
        "token_sha256": hashlib.sha256(token_bytes).hexdigest(),
    }


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: neural-ice-luks-token-evidence.py METADATA_JSON INTENDED_SRK", file=sys.stderr)
        return 2
    try:
        result = evidence(Path(sys.argv[1]), Path(sys.argv[2]))
    except Refusal as error:
        print(f"neural-ice-luks-token-evidence: refused: {error}", file=sys.stderr)
        return 1
    sys.stdout.buffer.write(canonical_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
