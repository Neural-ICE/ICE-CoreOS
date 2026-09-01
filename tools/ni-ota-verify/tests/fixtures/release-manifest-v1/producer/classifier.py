"""Pure release-manifest v1 delta classifier.

No transport, filesystem, signature, activation, or channel behavior belongs
here.  Refusal is a first-class plan result, not an exception at the boundary.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable

from contract import ContractRefusal, ParsedManifest, parse


class Classification(str, Enum):
    NO_OP = "no-op"
    COMPONENT_CONTENT = "component-content"
    HOST = "host"
    REFUSAL = "refusal"


@dataclass(frozen=True)
class DeviceCompatibility:
    hardware_target: str
    reader_version: int
    supported_contracts: frozenset[str]

    @classmethod
    def create(
        cls,
        hardware_target: str,
        reader_version: int,
        supported_contracts: Iterable[str],
    ) -> "DeviceCompatibility":
        return cls(hardware_target, reader_version, frozenset(supported_contracts))


@dataclass(frozen=True)
class Plan:
    classification: Classification
    current_manifest_digest: str | None
    candidate_manifest_digest: str | None
    bundle_seq: int | None
    changed_components: tuple[str, ...] = ()
    changed_content: tuple[str, ...] = ()
    restart_scope: tuple[str, ...] = ()
    reboot_required: bool = False
    refusal_reason: str | None = None

    def as_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "bundle_seq": self.bundle_seq,
            "candidate_manifest_digest": self.candidate_manifest_digest,
            "changed_components": list(self.changed_components),
            "changed_content": list(self.changed_content),
            "classification": self.classification.value,
            "current_manifest_digest": self.current_manifest_digest,
            "reboot_required": self.reboot_required,
            "restart_scope": list(self.restart_scope),
            "schema": "neural-ice-release-plan-v1",
        }
        if self.refusal_reason is not None:
            value["refusal_reason"] = self.refusal_reason
        return value


def _refusal(
    reason: str,
    current: ParsedManifest | None = None,
    candidate: ParsedManifest | None = None,
) -> Plan:
    return Plan(
        classification=Classification.REFUSAL,
        current_manifest_digest=current.digest if current else None,
        candidate_manifest_digest=candidate.digest if candidate else None,
        bundle_seq=candidate.value["bundle_seq"] if candidate else None,
        refusal_reason=reason,
    )


def _compatible(manifest: ParsedManifest, device: DeviceCompatibility) -> str | None:
    value = manifest.value
    if value["hardware_target"] != device.hardware_target:
        return "manifest hardware_target does not match the device"
    compatibility = value["compatibility"]
    if compatibility["minimum_reader"] > device.reader_version:
        return "manifest requires a newer release-manifest reader"
    missing = sorted(
        set(compatibility["required_contracts"]) - device.supported_contracts
    )
    if missing:
        return "device does not support required contracts: " + ", ".join(missing)
    return None


def _by_id(entries: list[dict[str, Any]], key: str) -> dict[str, dict[str, Any]]:
    return {entry[key]: entry for entry in entries}


def _changed_ids(
    current: dict[str, dict[str, Any]], candidate: dict[str, dict[str, Any]]
) -> tuple[str, ...]:
    return tuple(
        sorted(
            identifier
            for identifier in current.keys() | candidate.keys()
            if current.get(identifier) != candidate.get(identifier)
        )
    )


def _changed_existing_payload_is_digest_only(
    current: dict[str, dict[str, Any]],
    candidate: dict[str, dict[str, Any]],
    changed: tuple[str, ...],
) -> bool:
    for identifier in changed:
        old = current[identifier]
        new = candidate[identifier]
        for key in old.keys() | new.keys():
            if key != "digest" and old.get(key) != new.get(key):
                return False
    return True


def _changed_payloads(
    current: dict[str, dict[str, Any]],
    candidate: dict[str, dict[str, Any]],
    changed: tuple[str, ...],
) -> list[dict[str, Any]]:
    """Return installed and candidate contracts for each changed payload.

    Replacement must preserve the installed contract's deactivation requirements
    as well as the candidate contract's activation requirements. Additions and
    removals naturally contribute only the side that exists.
    """

    payloads: list[dict[str, Any]] = []
    for identifier in changed:
        if identifier in current:
            payloads.append(current[identifier])
        if identifier in candidate:
            payloads.append(candidate[identifier])
    return payloads


def _restart_scope(payloads: Iterable[dict[str, Any]]) -> tuple[str, ...]:
    return tuple(
        sorted({unit for payload in payloads for unit in payload["restart_scope"]})
    )


def classify(
    current_bytes: bytes,
    candidate_bytes: bytes,
    device: DeviceCompatibility,
    configured_registry_authority: str,
) -> Plan:
    """Classify already-authenticated manifest bytes without side effects."""

    try:
        current = parse(current_bytes, configured_registry_authority)
    except ContractRefusal as error:
        return _refusal(f"current manifest refused: {error}")
    try:
        candidate = parse(candidate_bytes, configured_registry_authority)
    except ContractRefusal as error:
        return _refusal(f"candidate manifest refused: {error}", current=current)

    current_error = _compatible(current, device)
    if current_error:
        return _refusal(
            f"current manifest incompatible: {current_error}", current, candidate
        )
    candidate_error = _compatible(candidate, device)
    if candidate_error:
        return _refusal(
            f"candidate manifest incompatible: {candidate_error}", current, candidate
        )

    old_seq = current.value["bundle_seq"]
    new_seq = candidate.value["bundle_seq"]
    if new_seq < old_seq:
        return _refusal(
            "candidate bundle_seq is below the installed floor", current, candidate
        )
    if new_seq == old_seq:
        if current.digest == candidate.digest:
            return Plan(Classification.NO_OP, current.digest, candidate.digest, new_seq)
        return _refusal(
            "the same bundle_seq identifies a different canonical manifest",
            current,
            candidate,
        )

    old = current.value
    new = candidate.value
    old_components = _by_id(old["components"], "component_id")
    new_components = _by_id(new["components"], "component_id")
    old_content = _by_id(old["content"], "content_id")
    new_content = _by_id(new["content"], "content_id")
    changed_components = _changed_ids(old_components, new_components)
    changed_content = _changed_ids(old_content, new_content)
    host_payload_changed = old["host"] != new["host"]
    host_changed = host_payload_changed or old["compatibility"] != new["compatibility"]

    shared_content = tuple(sorted(old_content.keys() & new_content.keys()))
    changed_shared_content = tuple(
        identifier
        for identifier in shared_content
        if old_content[identifier] != new_content[identifier]
    )

    # A compatibility edit is metadata, not an explicit host payload delta. It
    # must never smuggle a structural transition past the host requirement.
    if not host_payload_changed:
        if old_components.keys() != new_components.keys():
            return _refusal(
                "component membership changed without an explicit host delta",
                current,
                candidate,
            )
        if not _changed_existing_payload_is_digest_only(
            old_components, new_components, changed_components
        ):
            return _refusal(
                "component contract changed without an explicit host delta",
                current,
                candidate,
            )
        if not _changed_existing_payload_is_digest_only(
            old_content, new_content, changed_shared_content
        ):
            return _refusal(
                "content contract changed without an explicit host delta",
                current,
                candidate,
            )

    if host_changed:
        changed_payloads = _changed_payloads(
            old_components, new_components, changed_components
        )
        changed_payloads.extend(
            _changed_payloads(old_content, new_content, changed_content)
        )
        transition_payloads = [
            *([old["host"], new["host"]] if host_payload_changed else []),
            *changed_payloads,
        ]
        return Plan(
            Classification.HOST,
            current.digest,
            candidate.digest,
            new_seq,
            changed_components,
            changed_content,
            _restart_scope(transition_payloads),
            any(item["reboot_required"] for item in transition_payloads),
        )

    if changed_components or changed_content:
        changed_payloads = _changed_payloads(
            old_components, new_components, changed_components
        )
        changed_payloads.extend(
            _changed_payloads(old_content, new_content, changed_content)
        )
        return Plan(
            Classification.COMPONENT_CONTENT,
            current.digest,
            candidate.digest,
            new_seq,
            changed_components,
            changed_content,
            _restart_scope(changed_payloads),
            any(item["reboot_required"] for item in changed_payloads),
        )

    # Evidence and bundle_seq are signed facts, but do not select an activation engine.
    return Plan(Classification.NO_OP, current.digest, candidate.digest, new_seq)
