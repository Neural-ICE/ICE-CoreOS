"""Canonical Neural ICE release-manifest v1 contract.

This module performs no I/O.  It turns bounded JSON bytes into one normalized
value whose canonical bytes and SHA-256 digest are independent of object-key
and set-like array order.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

SCHEMA = "neural-ice-release-manifest-v1"
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_COMPONENTS = 256
MAX_CONTENT = 1024
MAX_EVIDENCE = 2048
MAX_RESTART_SCOPE = 32
MAX_DNS_HOST_LENGTH = 253

_TOP_KEYS = {
    "schema",
    "release_id",
    "bundle_seq",
    "hardware_target",
    "compatibility",
    "host",
    "components",
    "content",
    "evidence",
}
_COMPATIBILITY_KEYS = {"minimum_reader", "required_contracts"}
_HOST_KEYS = {
    "repository",
    "digest",
    "contract",
    "restart_scope",
    "reboot_required",
    "required_entitlement",
}
_COMPONENT_KEYS = _HOST_KEYS | {"component_id"}
_CONTENT_KEYS = _HOST_KEYS | {"content_id", "media_type"}
_EVIDENCE_KEYS = {"kind", "digest"}
_EVIDENCE_KINDS = {
    "attestation",
    "bom",
    "channel-snapshot",
    "lockfile",
    "receipt",
}

_IDENTIFIER = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$")
_HARDWARE_TARGET = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$")
_CONTRACT = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$")
_ENTITLEMENT = re.compile(r"^[A-Z][A-Z0-9-]{0,63}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_DNS_LABEL_TEXT = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_DNS_TEXT = rf"{_DNS_LABEL_TEXT}(?:\.{_DNS_LABEL_TEXT})*"
_IPV4_OCTET_TEXT = r"(?:0|[1-9][0-9]?|1[0-9]{2}|2[0-4][0-9]|25[0-5])"
_IPV4_TEXT = rf"{_IPV4_OCTET_TEXT}(?:\.{_IPV4_OCTET_TEXT}){{3}}"
_PORT_TEXT = (
    r"(?:[1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|"
    r"65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])"
)
_NONZERO_HEXTET_TEXT = r"[1-9a-f][0-9a-f]{0,3}"


def _canonical_ipv6_text() -> str:
    """Return the exact lowercase RFC 5952 hextet language.

    There are only 256 zero/nonzero shapes for eight hextets. Rendering each
    shape with the first longest zero run compressed makes the regex finite,
    deterministic, and portable without look-around or Unicode character
    classes.
    """

    alternatives: set[str] = set()
    for mask in range(256):
        zero = [bool(mask & (1 << index)) for index in range(8)]
        best_start = -1
        best_length = 0
        index = 0
        while index < 8:
            if not zero[index]:
                index += 1
                continue
            end = index
            while end < 8 and zero[end]:
                end += 1
            length = end - index
            if length > best_length:
                best_start = index
                best_length = length
            index = end

        groups = ["0" if item else _NONZERO_HEXTET_TEXT for item in zero]
        if best_length < 2:
            alternatives.add(":".join(groups))
            continue
        prefix = ":".join(groups[:best_start])
        suffix = ":".join(groups[best_start + best_length :])
        alternatives.add(f"{prefix}::{suffix}")
    return "(?:" + "|".join(sorted(alternatives)) + ")"


_IPV6_TEXT = _canonical_ipv6_text()
_DNS_AUTHORITY_TEXT = (
    rf"(?=[a-z0-9.-]{{1,{MAX_DNS_HOST_LENGTH}}}"
    rf"(?::{_PORT_TEXT})?(?:$|/))"
    rf"(?![0-9.]+(?::{_PORT_TEXT})?(?:$|/)){_DNS_TEXT}"
)
_AUTHORITY_TEXT = (
    rf"(?:{_IPV4_TEXT}|{_DNS_AUTHORITY_TEXT}|\[{_IPV6_TEXT}\])"
    rf"(?::{_PORT_TEXT})?"
)
_REPOSITORY_PATH_TEXT = (
    r"(?:neural-ice|vendor)/[a-z0-9]+(?:[._-][a-z0-9]+)*"
    r"(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*"
)
REGISTRY_AUTHORITY_PATTERN = rf"^{_AUTHORITY_TEXT}$"
REPOSITORY_PATTERN = rf"^{_AUTHORITY_TEXT}/{_REPOSITORY_PATH_TEXT}$"
_REGISTRY_AUTHORITY = re.compile(REGISTRY_AUTHORITY_PATTERN, re.ASCII)
_REPOSITORY = re.compile(REPOSITORY_PATTERN, re.ASCII)
_MEDIA_TYPE = re.compile(
    r"^[a-z0-9][a-z0-9!#$&^_.+-]{0,63}/[a-z0-9][a-z0-9!#$&^_.+-]{0,126}$"
)
_SYSTEMD_UNIT = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9:_.@-]{0,126}[A-Za-z0-9])?"
    r"\.(?:service|socket|target|timer|path|mount)$"
)


class ContractRefusal(ValueError):
    """The supplied bytes cannot be a release-manifest v1 authority."""


@dataclass(frozen=True)
class ParsedManifest:
    value: dict[str, Any]
    canonical_bytes: bytes
    digest: str


def _reject_float(value: str) -> None:
    raise ContractRefusal(f"floating-point JSON number is forbidden: {value}")


def _reject_constant(value: str) -> None:
    raise ContractRefusal(f"non-finite JSON number is forbidden: {value}")


def _strict_integer(value: str) -> int:
    if len(value.removeprefix("-")) > 16:
        raise ContractRefusal("JSON integer exceeds the safe integer range")
    return int(value)


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ContractRefusal(f"duplicate JSON object key: {key}")
        value[key] = item
    return value


def _strict_object(value: Any, keys: set[str], context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContractRefusal(f"{context} must be an object")
    missing = sorted(keys - value.keys())
    unknown = sorted(value.keys() - keys)
    if missing:
        raise ContractRefusal(f"{context} is missing fields: {', '.join(missing)}")
    if unknown:
        raise ContractRefusal(f"{context} has unknown fields: {', '.join(unknown)}")
    return value


def _bounded_list(value: Any, limit: int, context: str) -> list[Any]:
    if not isinstance(value, list):
        raise ContractRefusal(f"{context} must be an array")
    if len(value) > limit:
        raise ContractRefusal(f"{context} exceeds its cardinality limit of {limit}")
    return value


def _string(value: Any, pattern: re.Pattern[str], context: str) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ContractRefusal(f"{context} has an invalid value")
    return value


def _registry_authority(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise ContractRefusal(f"{context} is required")
    if not _REGISTRY_AUTHORITY.fullmatch(value):
        raise ContractRefusal(f"{context} is malformed")
    return value


def validate_registry_authority(value: Any) -> str:
    """Return the one accepted text unchanged; never render an IP alternate form."""

    return _registry_authority(value, "configured registry authority")


def _repository(value: Any, context: str) -> str:
    if not isinstance(value, str) or not _REPOSITORY.fullmatch(value):
        raise ContractRefusal(f"{context} has an invalid value")
    return value


def _repository_authority(repository: str) -> str:
    return repository.partition("/")[0]


def _safe_uint(value: Any, context: str, *, positive: bool = False) -> int:
    minimum = 1 if positive else 0
    if isinstance(value, bool) or not isinstance(value, int):
        raise ContractRefusal(f"{context} must be an integer")
    if value < minimum or value > 9_007_199_254_740_991:
        raise ContractRefusal(f"{context} is outside the safe integer range")
    return value


def _boolean(value: Any, context: str) -> bool:
    if not isinstance(value, bool):
        raise ContractRefusal(f"{context} must be a boolean")
    return value


def _restart_scope(value: Any, context: str) -> list[str]:
    units = _bounded_list(value, MAX_RESTART_SCOPE, context)
    normalized = [_string(unit, _SYSTEMD_UNIT, f"{context} entry") for unit in units]
    if len(normalized) != len(set(normalized)):
        raise ContractRefusal(f"{context} contains duplicate units")
    return sorted(normalized)


def _payload_common(value: dict[str, Any], context: str) -> dict[str, Any]:
    repository = _repository(value["repository"], f"{context}.repository")
    digest = _string(value["digest"], _DIGEST, f"{context}.digest")
    contract = _string(value["contract"], _CONTRACT, f"{context}.contract")
    entitlement = _string(
        value["required_entitlement"], _ENTITLEMENT, f"{context}.required_entitlement"
    )
    return {
        "contract": contract,
        "digest": digest,
        "reboot_required": _boolean(
            value["reboot_required"], f"{context}.reboot_required"
        ),
        "repository": repository,
        "required_entitlement": entitlement,
        "restart_scope": _restart_scope(
            value["restart_scope"], f"{context}.restart_scope"
        ),
    }


def _compatibility(value: Any) -> dict[str, Any]:
    obj = _strict_object(value, _COMPATIBILITY_KEYS, "compatibility")
    contracts = _bounded_list(obj["required_contracts"], 128, "required_contracts")
    normalized = [
        _string(contract, _CONTRACT, "required_contracts entry")
        for contract in contracts
    ]
    if not normalized:
        raise ContractRefusal("required_contracts must not be empty")
    if len(normalized) != len(set(normalized)):
        raise ContractRefusal("required_contracts contains duplicates")
    return {
        "minimum_reader": _safe_uint(
            obj["minimum_reader"], "compatibility.minimum_reader", positive=True
        ),
        "required_contracts": sorted(normalized),
    }


def _host(value: Any) -> dict[str, Any]:
    obj = _strict_object(value, _HOST_KEYS, "host")
    return _payload_common(obj, "host")


def _components(value: Any) -> list[dict[str, Any]]:
    entries = _bounded_list(value, MAX_COMPONENTS, "components")
    normalized: list[dict[str, Any]] = []
    identifiers: set[str] = set()
    for index, item in enumerate(entries):
        context = f"components[{index}]"
        obj = _strict_object(item, _COMPONENT_KEYS, context)
        identifier = _string(
            obj["component_id"], _IDENTIFIER, f"{context}.component_id"
        )
        if identifier in identifiers:
            raise ContractRefusal(f"duplicate component_id: {identifier}")
        identifiers.add(identifier)
        normalized.append({"component_id": identifier, **_payload_common(obj, context)})
    return sorted(normalized, key=lambda item: item["component_id"])


def _content(value: Any) -> list[dict[str, Any]]:
    entries = _bounded_list(value, MAX_CONTENT, "content")
    normalized: list[dict[str, Any]] = []
    identifiers: set[str] = set()
    for index, item in enumerate(entries):
        context = f"content[{index}]"
        obj = _strict_object(item, _CONTENT_KEYS, context)
        identifier = _string(obj["content_id"], _IDENTIFIER, f"{context}.content_id")
        if identifier in identifiers:
            raise ContractRefusal(f"duplicate content_id: {identifier}")
        identifiers.add(identifier)
        normalized.append(
            {
                "content_id": identifier,
                "media_type": _string(
                    obj["media_type"], _MEDIA_TYPE, f"{context}.media_type"
                ),
                **_payload_common(obj, context),
            }
        )
    return sorted(normalized, key=lambda item: item["content_id"])


def _evidence(value: Any) -> list[dict[str, str]]:
    entries = _bounded_list(value, MAX_EVIDENCE, "evidence")
    normalized: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for index, item in enumerate(entries):
        context = f"evidence[{index}]"
        obj = _strict_object(item, _EVIDENCE_KEYS, context)
        kind = obj["kind"]
        if not isinstance(kind, str) or kind not in _EVIDENCE_KINDS:
            raise ContractRefusal(f"{context}.kind is unsupported")
        digest = _string(obj["digest"], _DIGEST, f"{context}.digest")
        identity = (kind, digest)
        if identity in seen:
            raise ContractRefusal(f"duplicate evidence entry: {kind}/{digest}")
        seen.add(identity)
        normalized.append({"digest": digest, "kind": kind})
    return sorted(normalized, key=lambda item: (item["kind"], item["digest"]))


def _require_configured_registry(
    value: dict[str, Any], configured_registry_authority: Any
) -> None:
    authority = validate_registry_authority(configured_registry_authority)
    repositories = [("host.repository", value["host"]["repository"])]
    repositories.extend(
        (f"components[{index}].repository", item["repository"])
        for index, item in enumerate(value["components"])
    )
    repositories.extend(
        (f"content[{index}].repository", item["repository"])
        for index, item in enumerate(value["content"])
    )
    for context, repository in repositories:
        actual = _repository_authority(repository)
        if actual != authority:
            raise ContractRefusal(
                f"{context} authority {actual!r} does not match configured "
                f"registry authority {authority!r}"
            )


def normalize(value: Any, configured_registry_authority: str) -> dict[str, Any]:
    obj = _strict_object(value, _TOP_KEYS, "release manifest")
    if obj["schema"] != SCHEMA:
        raise ContractRefusal("unsupported release manifest schema")
    normalized = {
        "bundle_seq": _safe_uint(obj["bundle_seq"], "bundle_seq", positive=True),
        "compatibility": _compatibility(obj["compatibility"]),
        "components": _components(obj["components"]),
        "content": _content(obj["content"]),
        "evidence": _evidence(obj["evidence"]),
        "hardware_target": _string(
            obj["hardware_target"], _HARDWARE_TARGET, "hardware_target"
        ),
        "host": _host(obj["host"]),
        "release_id": _string(obj["release_id"], _IDENTIFIER, "release_id"),
        "schema": SCHEMA,
    }
    declared = set(normalized["compatibility"]["required_contracts"])
    used = {normalized["host"]["contract"]}
    used.update(item["contract"] for item in normalized["components"])
    used.update(item["contract"] for item in normalized["content"])
    undeclared = sorted(used - declared)
    if undeclared:
        raise ContractRefusal(
            "payload contracts are absent from compatibility.required_contracts: "
            + ", ".join(undeclared)
        )
    _require_configured_registry(normalized, configured_registry_authority)
    return normalized


def canonical_bytes(value: dict[str, Any]) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def parse(data: bytes, configured_registry_authority: str) -> ParsedManifest:
    if len(data) > MAX_MANIFEST_BYTES:
        raise ContractRefusal("release manifest exceeds the byte limit")
    try:
        decoded = data.decode("utf-8", errors="strict")
        raw = json.loads(
            decoded,
            object_pairs_hook=_object_without_duplicates,
            parse_float=_reject_float,
            parse_int=_strict_integer,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise ContractRefusal(
            f"release manifest is not strict UTF-8 JSON: {error}"
        ) from error
    value = normalize(raw, configured_registry_authority)
    encoded = canonical_bytes(value)
    if len(encoded) > MAX_MANIFEST_BYTES:
        raise ContractRefusal("canonical release manifest exceeds the byte limit")
    return ParsedManifest(
        value=value,
        canonical_bytes=encoded,
        digest="sha256:" + hashlib.sha256(encoded).hexdigest(),
    )
