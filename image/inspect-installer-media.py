#!/usr/bin/env python3
"""Prove a produced installer raw CONTAINS -- and contains ONLY -- what it is
supposed to boot and install.

Why this exists
---------------
``image/verify-preloaded-media.py`` is the finalisation gate, and it needs root:
it attaches a loop device and mounts partitions. That makes it unusable as a
routine check -- in CI, in a review, or on a developer's machine -- so in
practice nothing ever asserted that a produced medium carried the signed UKI,
the sealed payload, or nothing else bootable. The UKI/verity work could
therefore be entirely dead code and every green test would stay green.

This reader is deliberately the opposite: **no root, no loop device, no mount**.
It parses the GPT, the FAT ESP and the raw payload extent out of the raw file
with ordinary reads.

What it proves
--------------
* the medium carries exactly one EFI System Partition, one partition named
  ``ni-installer-payload``, and NOTHING ELSE that is not entirely zero;
* the ESP's whole file tree is an allowlist: ``EFI/BOOT/BOOTAA64.EFI`` (the
  signed UKI), its build manifest, and an optional ``ice-coreos/`` handoff
  directory. There is no second ``.efi``, no shim, no GRUB and no configuration
  file for anything to choose between -- which is the property the removal of
  interactive boot authority is *for*;
* ``BOOTAA64.EFI`` is a PE binary whose ``.cmdline`` section parses as a
  ``neural-ice-installer-trust-v1`` anchor sealing the expected verity root
  hash, payload digest, access profile, hardware target and trust policy id;
* an Install medium seals its exact autoinstall selector and a Live medium seals
  its distinct exact ``neuralice.live=1`` selector
  -- so the destructive mode is a property of a signature, not of a keystroke;
* the UKI carries a signature directory (i.e. it was actually signed), unless
  ``--allow-unsigned`` says an unsigned medium was built on purpose;
* the payload header's SHA-256 is the digest the UKI seals, EVERY region hashes
  to what that header says, and -- the part a manifest can never establish --
  the dm-verity root hashes of the installer root image and of the container
  store are RECOMPUTED FROM THE BYTES ON THE MEDIUM and found to be the ones the
  signature and the authenticated header carry.

Why the header contract is re-implemented here
----------------------------------------------
``image/lib/installer-payload.sh`` is the one parser the build, the initramfs
and the installer share -- on purpose, so those three cannot disagree. This file
deliberately does NOT use it. An inspector that re-used the producer's own code
would confirm that the producer is self-consistent, which is not the question;
re-deriving the contract in a second language is what makes a disagreement
visible. ``image/test-installer-media.sh`` drives both over the same bytes and
requires the same answer.

What it does NOT prove
----------------------
That the firmware will accept the signature -- that is a property of a machine's
db, not of a file -- and that the UKI actually boots on GB10. Those need
hardware. This is the strongest statement that can be made off-device, and it is
the one that was missing.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import re
import struct
import sys
from pathlib import Path
from typing import Iterator

GPT_SIGNATURE = b"EFI PART"
ESP_TYPE_GUID = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
SECTOR_CANDIDATES = (512, 4096)
MAX_SECTION_BYTES = 1 << 20

PAYLOAD_SCHEMA = "neural-ice-installer-payload-v1"
PAYLOAD_HEADER_BYTES = 4096
PAYLOAD_ALIGNMENT = 4096
PAYLOAD_PARTITION_NAME = "ni-installer-payload"
# The canonical region order. Same closed world as the shell library: a header
# naming a fifth region is refused, because the region this reader does not
# understand could be the one that mattered.
PAYLOAD_REGIONS = ("root-image", "root-hash", "store-image", "store-hash")
PAYLOAD_KEYS = frozenset(
    ["schema", "store_image_name", "root_verity_hash", "store_verity_hash", "verity_salt"]
    + [f"region.{name}" for name in PAYLOAD_REGIONS]
)

# Everything the ESP of a sealed medium may carry. `EFI/BOOT/BOOTAA64.EFI` is the
# removable-media default path the firmware loads with no boot manager and no
# NVRAM entry; the rest is inert data the installer reads.
ESP_REQUIRED = ("EFI/BOOT/BOOTAA64.EFI",)
ESP_OPTIONAL = frozenset(
    {
        "ice-coreos/authorized_keys",
        "ice-coreos/ota-lab-baseline.json",
        "ice-coreos/ota-lab-baseline.sig",
        "ice-coreos/release-authorization.json",
        "ice-coreos/release-authorization.sig",
        # The bench-specific CA a LAN mirror's TLS is pinned to. Like the
        # release authorization, it lives on the mutable ESP and its digest is
        # sealed in the UKI command line, which is what makes the ESP a carrier
        # rather than a chooser.
        "ice-coreos/mirror-ca.crt",
        # Public TPM policy material is inert data. Its digest is sealed in the
        # signed UKI command line and rechecked below before acceptance.
        "ice-coreos/tpm2-pcr-public-key.pem",
        "ice-coreos/tpm2-pcr-signature.json",
    }
)
# Every ESP artefact whose digest the sealed command line pins, and the karg that
# pins it. `check_esp` recomputes each from the medium and refuses a mismatch --
# a signature that names a document is worth nothing if nobody compares them.
ESP_HASH_BOUND = (
    ("ice-coreos/release-authorization.json", "neuralice.relauth_sha256"),
    ("ice-coreos/release-authorization.sig", "neuralice.relauth_sig_sha256"),
    ("ice-coreos/mirror-ca.crt", "neuralice.mirror_ca_sha256"),
    ("ice-coreos/tpm2-pcr-public-key.pem", "neuralice.pcr_policy_key"),
    ("ice-coreos/tpm2-pcr-signature.json", "neuralice.pcr_policy_signature"),
)
ESP_MANIFEST_RE = re.compile(r"^EFI/neural-ice/installer-(install|live)\.efi\.manifest$")

READ_CHUNK = 8 << 20


class InspectionError(RuntimeError):
    pass


# --------------------------------------------------------------------------- #
# GPT
# --------------------------------------------------------------------------- #
def _guid(raw: bytes) -> str:
    d1, d2, d3 = struct.unpack_from("<IHH", raw, 0)
    d4 = raw[8:10]
    d5 = raw[10:16]
    return f"{d1:08x}-{d2:04x}-{d3:04x}-{d4.hex()}-{d5.hex()}"


class Partition:
    def __init__(self, index: int, type_guid: str, name: str, offset: int, length: int):
        self.index = index
        self.type_guid = type_guid
        self.name = name
        self.offset = offset
        self.length = length

    def __repr__(self) -> str:  # pragma: no cover - diagnostics only
        return f"<partition {self.index} {self.name!r} type={self.type_guid}>"


def read_gpt(raw: Path) -> tuple[int, list[Partition]]:
    with raw.open("rb") as handle:
        for sector in SECTOR_CANDIDATES:
            handle.seek(sector)
            header = handle.read(92)
            if len(header) < 92 or header[:8] != GPT_SIGNATURE:
                continue
            entry_lba, entry_count, entry_size = struct.unpack_from("<QII", header, 72)
            if not (0 < entry_count <= 512) or not (128 <= entry_size <= 4096):
                raise InspectionError("the GPT partition array is not plausible")
            handle.seek(entry_lba * sector)
            table = handle.read(entry_count * entry_size)
            partitions: list[Partition] = []
            for index in range(entry_count):
                entry = table[index * entry_size : (index + 1) * entry_size]
                if len(entry) < 128 or entry[:16] == b"\x00" * 16:
                    continue
                first, last = struct.unpack_from("<QQ", entry, 32)
                name = entry[56:128].decode("utf-16-le", "replace").split("\x00")[0]
                partitions.append(
                    Partition(
                        index + 1,
                        _guid(entry[:16]),
                        name,
                        first * sector,
                        (last - first + 1) * sector,
                    )
                )
            if not partitions:
                raise InspectionError("the GPT declares no partitions")
            return sector, partitions
    raise InspectionError("no GPT header found at any supported sector size")


# --------------------------------------------------------------------------- #
# FAT12/16/32 — enough of it to read one directory tree out of an ESP.
# --------------------------------------------------------------------------- #
class Fat:
    def __init__(self, handle, base: int, size: int):
        self.handle = handle
        self.base = base
        boot = self._read(0, 512)
        self.bytes_per_sector = struct.unpack_from("<H", boot, 11)[0]
        self.sectors_per_cluster = boot[13]
        reserved = struct.unpack_from("<H", boot, 14)[0]
        self.num_fats = boot[16]
        self.root_entries = struct.unpack_from("<H", boot, 17)[0]
        total16 = struct.unpack_from("<H", boot, 19)[0]
        fat16_size = struct.unpack_from("<H", boot, 22)[0]
        total32 = struct.unpack_from("<I", boot, 32)[0]
        fat32_size = struct.unpack_from("<I", boot, 36)[0]
        if self.bytes_per_sector not in (512, 1024, 2048, 4096) or self.sectors_per_cluster == 0:
            raise InspectionError("the EFI System Partition is not a FAT filesystem")
        self.fat_size = fat32_size if fat16_size == 0 else fat16_size
        total_sectors = total32 if total16 == 0 else total16
        self.root_dir_sectors = (
            self.root_entries * 32 + self.bytes_per_sector - 1
        ) // self.bytes_per_sector
        self.first_data_sector = (
            reserved + self.num_fats * self.fat_size + self.root_dir_sectors
        )
        data_sectors = total_sectors - self.first_data_sector
        self.cluster_count = data_sectors // self.sectors_per_cluster
        self.fat_start = reserved * self.bytes_per_sector
        if self.cluster_count < 4085:
            self.bits = 12
        elif self.cluster_count < 65525:
            self.bits = 16
        else:
            self.bits = 32
        self.root_cluster = struct.unpack_from("<I", boot, 44)[0] if self.bits == 32 else 0
        self.size = size

    def _read(self, offset: int, length: int) -> bytes:
        self.handle.seek(self.base + offset)
        return self.handle.read(length)

    def _fat_entry(self, cluster: int) -> int:
        if self.bits == 32:
            raw = self._read(self.fat_start + cluster * 4, 4)
            return struct.unpack("<I", raw)[0] & 0x0FFFFFFF
        if self.bits == 16:
            raw = self._read(self.fat_start + cluster * 2, 2)
            return struct.unpack("<H", raw)[0]
        index = cluster + (cluster // 2)
        raw = self._read(self.fat_start + index, 2)
        value = struct.unpack("<H", raw)[0]
        return (value >> 4) if cluster & 1 else (value & 0x0FFF)

    def _end_marker(self) -> int:
        return {12: 0x0FF8, 16: 0xFFF8, 32: 0x0FFFFFF8}[self.bits]

    def _chain(self, cluster: int) -> Iterator[int]:
        seen = set()
        end = self._end_marker()
        while 2 <= cluster < end and cluster not in seen:
            seen.add(cluster)
            yield cluster
            cluster = self._fat_entry(cluster)

    def _cluster_bytes(self, cluster: int) -> bytes:
        sector = self.first_data_sector + (cluster - 2) * self.sectors_per_cluster
        return self._read(
            sector * self.bytes_per_sector,
            self.sectors_per_cluster * self.bytes_per_sector,
        )

    def _chain_bytes(self, cluster: int, limit: int | None = None) -> bytes:
        out = bytearray()
        for current in self._chain(cluster):
            out += self._cluster_bytes(current)
            if limit is not None and len(out) >= limit:
                break
        return bytes(out)

    def _root_bytes(self) -> bytes:
        if self.bits == 32:
            return self._chain_bytes(self.root_cluster)
        reserved_bytes = self.fat_start + self.num_fats * self.fat_size * self.bytes_per_sector
        return self._read(reserved_bytes, self.root_entries * 32)

    @staticmethod
    def _entries(block: bytes) -> Iterator[tuple[str, int, int, int]]:
        """Yield (name, attributes, first cluster, size) with long names joined."""
        long_name: list[str] = []
        for offset in range(0, len(block) - 31, 32):
            entry = block[offset : offset + 32]
            first = entry[0]
            if first == 0x00:
                break
            if first == 0xE5:
                long_name = []
                continue
            attributes = entry[11]
            if attributes & 0x0F == 0x0F:
                chunk = (entry[1:11] + entry[14:26] + entry[28:32]).decode(
                    "utf-16-le", "replace"
                )
                long_name.insert(0, chunk.split("￿")[0].split("\x00")[0])
                continue
            if long_name:
                name = "".join(long_name)
                long_name = []
            else:
                stem = entry[0:8].decode("ascii", "replace").rstrip()
                suffix = entry[8:11].decode("ascii", "replace").rstrip()
                name = f"{stem}.{suffix}" if suffix else stem
            cluster = (struct.unpack_from("<H", entry, 20)[0] << 16) | struct.unpack_from(
                "<H", entry, 26
            )[0]
            size = struct.unpack_from("<I", entry, 28)[0]
            if name in (".", ".."):
                continue
            yield name, attributes, cluster, size

    def read_file(self, path: str) -> bytes:
        parts = [part for part in path.strip("/").split("/") if part]
        block = self._root_bytes()
        for depth, part in enumerate(parts):
            match = None
            for name, attributes, cluster, size in self._entries(block):
                if name.lower() == part.lower():
                    match = (attributes, cluster, size)
                    break
            if match is None:
                raise InspectionError(f"the ESP carries no /{'/'.join(parts[: depth + 1])}")
            attributes, cluster, size = match
            if depth == len(parts) - 1:
                if attributes & 0x10:
                    raise InspectionError(f"/{path} is a directory, not a file")
                return self._chain_bytes(cluster, size)[:size]
            if not attributes & 0x10:
                raise InspectionError(f"/{'/'.join(parts[: depth + 1])} is not a directory")
            block = self._chain_bytes(cluster)
        raise InspectionError(f"the ESP carries no /{path}")

    def walk(self, prefix: str = "", cluster: int | None = None, depth: int = 0) -> Iterator[str]:
        """Every FILE path on the ESP, so the allowlist can be a closed world.

        A boot manager, a shim, a fallback binary or a second UKI would all show
        up here, whatever they are called and wherever they were hidden.
        """
        if depth > 8:
            raise InspectionError("the ESP directory tree is implausibly deep")
        block = self._root_bytes() if cluster is None else self._chain_bytes(cluster)
        for name, attributes, child, _size in self._entries(block):
            if attributes & 0x08 and not attributes & 0x10:
                continue  # the volume label is not a file
            path = f"{prefix}{name}"
            if attributes & 0x10:
                yield from self.walk(f"{path}/", child, depth + 1)
            else:
                yield path


# --------------------------------------------------------------------------- #
# PE
# --------------------------------------------------------------------------- #
def pe_sections(blob: bytes) -> dict[str, bytes]:
    if blob[:2] != b"MZ":
        raise InspectionError("the UKI is not a PE binary (no MZ header)")
    pe_offset = struct.unpack_from("<I", blob, 0x3C)[0]
    if blob[pe_offset : pe_offset + 4] != b"PE\x00\x00":
        raise InspectionError("the UKI carries no PE signature")
    coff = pe_offset + 4
    section_count, = struct.unpack_from("<H", blob, coff + 2)
    optional_size, = struct.unpack_from("<H", blob, coff + 16)
    table = coff + 20 + optional_size
    sections: dict[str, bytes] = {}
    for index in range(section_count):
        entry = table + index * 40
        name = blob[entry : entry + 8].rstrip(b"\x00").decode("ascii", "replace")
        raw_size, = struct.unpack_from("<I", blob, entry + 16)
        raw_pointer, = struct.unpack_from("<I", blob, entry + 20)
        if raw_size > MAX_SECTION_BYTES:
            sections[name] = b""
            continue
        sections[name] = blob[raw_pointer : raw_pointer + raw_size]
    return sections


def pe_has_signature(blob: bytes) -> bool:
    """True when the PE carries a non-empty certificate table (Authenticode)."""
    pe_offset = struct.unpack_from("<I", blob, 0x3C)[0]
    coff = pe_offset + 4
    optional = coff + 20
    magic, = struct.unpack_from("<H", blob, optional)
    # Data directory 4 is the certificate table. It sits after the fixed part of
    # the optional header, and that part is a different length in the two PE
    # flavours: 96 bytes for PE32 (0x10b), 112 for PE32+ (0x20b, what aarch64
    # and x86-64 UEFI binaries use). Getting this wrong reads a neighbouring
    # directory and would call every binary signed.
    if magic == 0x20B:
        fixed = 112
    elif magic == 0x10B:
        fixed = 96
    else:
        raise InspectionError("the UKI optional header has an unknown magic")
    address, size = struct.unpack_from("<II", blob, optional + fixed + 4 * 8)
    return address != 0 and size != 0


# --------------------------------------------------------------------------- #
# The sealed anchor, parsed the same closed-world way installer-trust.sh does.
# --------------------------------------------------------------------------- #
SEALED_KEYS = (
    "neuralice.trust",
    "neuralice.access_profile",
    "neuralice.hardware_target",
    "neuralice.payload",
    "neuralice.relauth_keyid",
    "neuralice.relauth_schema",
    "neuralice.rootverity",
    "neuralice.trust_policy_id",
)


def sealed_fields(cmdline: str) -> dict[str, str]:
    words = cmdline.split()
    fields: dict[str, str] = {}
    for key in SEALED_KEYS:
        matches = [word[len(key) + 1 :] for word in words if word.startswith(key + "=")]
        if len(matches) != 1:
            raise InspectionError(
                f"the sealed cmdline carries {len(matches)} occurrences of {key}"
            )
        fields[key] = matches[0]
    if fields["neuralice.trust"] != "neural-ice-installer-trust-v1":
        raise InspectionError("the sealed cmdline is not a neural-ice-installer-trust-v1 anchor")
    if fields["neuralice.relauth_schema"] != "neural-ice-installer-release-authorization-v2":
        raise InspectionError(
            "the sealed cmdline does not require neural-ice-installer-release-authorization-v2"
        )
    return fields


# --------------------------------------------------------------------------- #
# THE SEALED MEDIA COMMAND-LINE GRAMMAR, re-implemented.
#
# image/installer/neural-ice-sealed-cmdline-grammar.sh is the definition the
# PRODUCER, the early runtime generator and the installer all share. This is a
# deliberate SECOND implementation, in another language, for the same reason the
# payload header contract is re-implemented below: an inspector that re-used the
# producer's own code would confirm the producer is self-consistent, which is not
# the question. image/test-installer-selector-grammar.sh drives both over one
# shared corpus and fails on any disagreement, in either direction.
#
# It is a CLOSED WORLD. A blocklist of `systemd.debug_shell`, `init=`,
# `rd.break`, `systemd.mask=`, `emergency`, `rescue`, `single`, `selinux=0` ...
# would be whack-a-mole -- the kernel and systemd add arguments faster than any
# list is maintained, and one missed word is one unauthenticated root shell on a
# medium whose entire safety argument is that it has no shell. Every word must
# instead be one this grammar names, so an argument invented tomorrow is refused
# today.
# --------------------------------------------------------------------------- #
SEALED_INSTALL_TARGET = "systemd.unit=neural-ice-installer.target"
SEALED_INSTALL_SELECTOR = "neuralice.autoinstall=1"
SEALED_LIVE_TARGET = "systemd.unit=neural-ice-live.target"
SEALED_LIVE_SELECTOR = "neuralice.live=1"
SEALED_CMDLINE_MAX_BYTES = 4096
SEALED_CMDLINE_MAX_WORDS = 64
# Install only. `bootc install` relabels the target and the enforcing live policy
# denies it; a Live boot relabels nothing, so a Live medium sealing this is a
# medium asking for a relaxation it cannot use.
SEALED_INSTALL_ONLY_WORDS = ("enforcing=0",)
SEALED_INSTALL_OPTIONAL_KEYS = (
    "neuralice.release_authority",
    "neuralice.device_channel",
    "neuralice.imgref",
    "neuralice.source",
    "neuralice.osimage",
    "neuralice.mirror",
    "neuralice.systemsize",
    "neuralice.target",
    "neuralice.sshkey",
    "neuralice.relauth_sha256",
    "neuralice.relauth_sig_sha256",
    "neuralice.mirror_ca_sha256",
    "neuralice.mirror_ready",
    "neuralice.mirror_manifest",
    "neuralice.mirror_generation",
    "neuralice.seed_closure",
    "neuralice.seed_manifest",
    "neuralice.seed_trusted_now",
    "neuralice.pcr_policy",
    "neuralice.pcr_policy_key",
    "neuralice.pcr_policy_signature",
    "neuralice.pcr_policy_seq",
)
# 🔴 ONE CANONICAL ORIGIN, SEALED RATHER THAN COMPILED IN (independent review
# 2026-09-02, P0 #3). Every OS/source reference a medium may seal carries the
# authority `neuralice.release_authority` names on the same signed line: not a
# mutable tag, not a second registry, not a LAN host. The mirror names a lab host
# that may SERVE those bytes and is never an origin.
#
# The authority is an ARGUMENT and not a literal in this tree on purpose:
# ci/test-open-core-boundary.sh refuses the sovereign endpoint's bytes in every
# Git-visible file, and an open repository that names the production registry has
# published it.
_WORD_CHARACTERS = re.compile(r"[A-Za-z0-9._:=,/@+-]+")
_REGISTRY_PATH_SEGMENT = r"[a-z0-9]+(?:[._-][a-z0-9]+)*"


class SelectorRefusal(InspectionError):
    """A sealed command line that is not one this repository could have cut.

    ``reason`` is a stable machine-readable token; the corpus test asserts the
    exact token, so a future edit cannot collapse a specific refusal into a
    generic one and still look green.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(f"the sealed command line is refused: {reason}")
        self.reason = reason


def _authority_is_valid(authority: str) -> bool:
    """A registry authority: bracketed IPv6 literal, dotted quad, ``localhost``
    or a DNS name of at least two labels, with an optional 1-65535 port."""
    port = ""
    if authority.startswith("["):
        close = authority.find("]")
        if close < 0:
            return False
        host, suffix = authority[1:close], authority[close + 1 :]
        # Canonical compressed IPv6 only: a non-canonical spelling is refused
        # rather than normalised, so two readers of one medium cannot disagree
        # about which host it names.
        try:
            address = ipaddress.IPv6Address(host)
        except ValueError:
            return False
        if address.compressed != host:
            return False
        if suffix:
            if not suffix.startswith(":"):
                return False
            port = suffix[1:]
    else:
        host = authority
        if ":" in authority:
            if authority.count(":") != 1:
                return False
            host, port = authority.rsplit(":", 1)
            if not port:
                return False
        if all(character in "0123456789." for character in host):
            try:
                if str(ipaddress.IPv4Address(host)) != host:
                    return False
            except ValueError:
                return False
        elif host != "localhost":
            labels = host.split(".")
            if len(labels) < 2 or len(host) > 253:
                return False
            if any(
                not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                for label in labels
            ):
                return False
    if port:
        if not re.fullmatch(r"[1-9][0-9]{0,4}", port) or int(port) > 65535:
            return False
    return True


def _release_authority_is_valid(value: str) -> bool:
    """The ONE release authority a medium's origin references must carry.

    A DNS name with at least two labels: an origin is a name a certificate can be
    issued for and a signature scope can be written against, which an IP literal
    and ``localhost`` are not.
    """
    host = value.split(":", 1)[0]
    if value.startswith("[") or host == "localhost":
        return False
    if re.fullmatch(r"[0-9.]+", host) or "." not in host:
        return False
    return _authority_is_valid(value)


def _reference_authority(value: str) -> str:
    """The authority of a digest-pinned reference this grammar already accepted."""
    return value.split("@sha256:", 1)[0].split("/", 1)[0]


def _osimage_is_valid(value: str) -> bool:
    """A digest-pinned appliance image.

    A MUTABLE TAG IS REFUSED: the digest is what makes a LAN mirror safe to
    consult, so accepting a tag would quietly undo the property the mirror
    depends on. WHOSE registry it is, is a question about the LINE rather than
    about this value, and is answered against ``neuralice.release_authority``.
    """
    match = re.fullmatch(r"(.+)@sha256:[0-9a-f]{64}", value)
    if not match:
        return False
    repository = match.group(1)
    if "/" not in repository:
        return False
    authority, path = repository.split("/", 1)
    if not re.fullmatch(
        rf"{_REGISTRY_PATH_SEGMENT}(?:/{_REGISTRY_PATH_SEGMENT})*", path
    ):
        return False
    return _authority_is_valid(authority)


def _sealed_value_is_valid(key: str, value: str) -> bool:
    if key == "neuralice.imgref":
        # The OTA ORIGIN recorded on the appliance and followed by every later
        # `bootc upgrade`, held to exactly the rule the installed image is:
        # canonical authority, digest-pinned, no tag. A mutable tag here is an
        # appliance whose future is decided by whoever can move that tag.
        return _osimage_is_valid(value)
    if key == "neuralice.source":
        return value in ("medium", "registry")
    if key == "neuralice.device_channel":
        return value in ("lab", "beta", "stable")
    if key == "neuralice.osimage":
        return _osimage_is_valid(value)
    if key == "neuralice.mirror":
        # Whether it is the release authority -- which a mirror may never be, a
        # "mirror" of the origin being the origin -- is a question about the
        # LINE, and is answered below.
        return bool(
            re.fullmatch(r"[A-Za-z0-9._-]+(:[0-9]{1,5})?", value)
        ) and _authority_is_valid(value)
    if key == "neuralice.release_authority":
        return _release_authority_is_valid(value)
    if key in (
        "neuralice.relauth_sha256",
        "neuralice.relauth_sig_sha256",
        "neuralice.mirror_ca_sha256",
        "neuralice.mirror_ready",
        "neuralice.mirror_manifest",
        # The offline seed's release closure. The seed root is a directory NAMED
        # by this hash and the installer refuses unless the canonical release
        # manifest inside it canonicalises to exactly this value.
        "neuralice.seed_closure",
        "neuralice.seed_manifest",
        "neuralice.pcr_policy",
        "neuralice.pcr_policy_key",
        "neuralice.pcr_policy_signature",
    ):
        return bool(re.fullmatch(r"[0-9a-f]{64}", value))
    if key == "neuralice.systemsize":
        return bool(re.fullmatch(r"[0-9]{1,5}", value)) and 16 <= int(value) <= 65536
    if key in ("neuralice.mirror_generation", "neuralice.pcr_policy_seq"):
        return bool(re.fullmatch(r"[1-9][0-9]{0,18}", value))
    if key == "neuralice.seed_trusted_now":
        return bool(re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", value))
    if key == "neuralice.target":
        # This value selects the disk that is about to be destroyed.
        return bool(re.fullmatch(r"/dev/[a-zA-Z0-9][a-zA-Z0-9_-]*", value))
    if key == "neuralice.sshkey":
        return bool(re.fullmatch(r"[A-Za-z0-9+/=]{1,1024}", value))
    return False


def classify_sealed_cmdline(cmdline: str) -> str:
    """Return ``"install"`` or ``"live"``; raise :class:`SelectorRefusal` for
    anything else, including a line that is merely *almost* one of them."""
    if len(cmdline) > SEALED_CMDLINE_MAX_BYTES:
        raise SelectorRefusal("cmdline-too-long")
    words = cmdline.split()
    if not words:
        raise SelectorRefusal("empty-cmdline")
    if len(words) > SEALED_CMDLINE_MAX_WORDS:
        raise SelectorRefusal("too-many-words")

    counts: dict[str, int] = {}
    for word in words:
        # The renderer's own character class. A word outside it cannot have come
        # from installer_trust_render_cmdline, so it did not come from a build.
        if not _WORD_CHARACTERS.fullmatch(word):
            raise SelectorRefusal("unrepresentable-word")
        key = word.split("=", 1)[0]
        if not key:
            raise SelectorRefusal("unrepresentable-word")
        counts[key] = counts.get(key, 0) + 1

    for key in SEALED_KEYS:
        seen = counts.get(key, 0)
        if seen == 0:
            raise SelectorRefusal(f"missing-sealed-field:{key}")
        if seen > 1:
            raise SelectorRefusal(f"duplicate-sealed-field:{key}")

    if counts.get("systemd.unit", 0) != 1:
        raise SelectorRefusal("ambiguous-boot-target")
    if counts.get("neuralice.autoinstall", 0) > 1:
        raise SelectorRefusal("duplicate-mode-selector")
    if counts.get("neuralice.live", 0) > 1:
        raise SelectorRefusal("duplicate-mode-selector")

    if SEALED_INSTALL_TARGET in words:
        mode = "install"
    elif SEALED_LIVE_TARGET in words:
        mode = "live"
    else:
        raise SelectorRefusal("unknown-boot-target")

    if mode == "install":
        if SEALED_INSTALL_SELECTOR not in words:
            raise SelectorRefusal("missing-mode-selector")
        if counts.get("neuralice.live", 0):
            raise SelectorRefusal("mixed-mode-selector")
    else:
        if SEALED_LIVE_SELECTOR not in words:
            raise SelectorRefusal("missing-mode-selector")
        if counts.get("neuralice.autoinstall", 0):
            raise SelectorRefusal("mixed-mode-selector")

    optional: dict[str, str] = {}
    for word in words:
        key, _, value = word.partition("=")
        if key in SEALED_KEYS:
            continue
        if word == "quiet":
            if counts.get("quiet", 0) != 1:
                raise SelectorRefusal("duplicate-word")
            continue
        if word in (SEALED_INSTALL_TARGET, SEALED_LIVE_TARGET):
            continue
        if word == SEALED_INSTALL_SELECTOR:
            if mode != "install":
                raise SelectorRefusal("mixed-mode-selector")
            continue
        if word == SEALED_LIVE_SELECTOR:
            if mode != "live":
                raise SelectorRefusal("mixed-mode-selector")
            continue
        if word in SEALED_INSTALL_ONLY_WORDS:
            if mode != "install":
                raise SelectorRefusal("word-not-permitted-in-mode")
            if counts.get(key, 0) != 1:
                raise SelectorRefusal("duplicate-word")
            continue
        if "=" in word and key in SEALED_INSTALL_OPTIONAL_KEYS:
            if mode != "install":
                raise SelectorRefusal("word-not-permitted-in-mode")
            if counts.get(key, 0) != 1 or key in optional:
                raise SelectorRefusal(f"duplicate-argument:{key}")
            optional[key] = value
            if not _sealed_value_is_valid(key, value):
                raise SelectorRefusal(f"invalid-argument:{key}")
            continue
        raise SelectorRefusal(f"word-not-in-grammar:{key}")

    # ----------------------------------------------------------------------- #
    # THE REGISTRY-INSTALL CONTRACT, stated once so the producer, the generator
    # and the installer cannot disagree about which combinations are meaningful.
    #
    # 🔴 EVERY RULE HERE IS A COMBINATION, NOT A VALUE (independent review
    # 2026-09-02, P0 #3). A well-shaped value in the wrong company is how a
    # registry medium was cut that deterministically refused at runtime: the
    # installer required a signed release authorization on the ESP and the
    # producer had no reason to stage one.
    # ----------------------------------------------------------------------- #
    # 🔴 ONE ORIGIN, NAMED ON THE LINE. Every reference that decides WHICH BYTES
    # an appliance runs must carry the authority `neuralice.release_authority`
    # names, and a line that carries such a reference must name one.
    release_authority = optional.get("neuralice.release_authority")
    for origin_key in ("neuralice.imgref", "neuralice.osimage"):
        if origin_key not in optional:
            continue
        if release_authority is None:
            raise SelectorRefusal(f"origin-without-release-authority:{origin_key}")
        if _reference_authority(optional[origin_key]) != release_authority:
            raise SelectorRefusal(f"origin-not-the-release-authority:{origin_key}")

    source = optional.get("neuralice.source")
    if source == "registry":
        if "neuralice.osimage" not in optional:
            raise SelectorRefusal("registry-source-without-osimage")
        # The ESP is mutable, so the two SHA-256 values that pin the release
        # authorization document and its detached signature are sealed in the
        # line the UKI signature covers.
        if "neuralice.relauth_sha256" not in optional:
            raise SelectorRefusal("registry-source-without-release-authorization")
        if "neuralice.relauth_sig_sha256" not in optional:
            raise SelectorRefusal(
                "registry-source-without-release-authorization-signature"
            )
        if optional["neuralice.relauth_sha256"] == optional["neuralice.relauth_sig_sha256"]:
            raise SelectorRefusal("release-authorization-hashes-identical")
    else:
        if "neuralice.osimage" in optional:
            raise SelectorRefusal("osimage-without-registry-source")
        for key in ("neuralice.relauth_sha256", "neuralice.relauth_sig_sha256"):
            if key in optional:
                raise SelectorRefusal("release-authorization-without-registry-source")

    # THE MIRROR IS LAB TRANSPORT AND NOTHING ELSE. A mirror on a CUSTOMER
    # appliance puts a lab host in the boot path of a machine that must never
    # depend on one, and no digest argument makes that acceptable.
    if "neuralice.mirror" in optional:
        if source != "registry":
            raise SelectorRefusal("mirror-without-registry-source")
        # A "mirror" of the origin IS the origin, and the digest-only/insecure
        # transport rules the installer writes for a mirror must never be applied
        # to the authority its signature scope is written against.
        if release_authority is not None and optional["neuralice.mirror"].split(":", 1)[0] == (
            release_authority.split(":", 1)[0]
        ):
            raise SelectorRefusal("mirror-is-the-release-authority")
        if sealed_fields(cmdline)["neuralice.access_profile"] != "lab-managed":
            raise SelectorRefusal("mirror-not-permitted-outside-lab-managed")
        if "neuralice.mirror_ca_sha256" not in optional:
            raise SelectorRefusal("mirror-without-pinned-ca")
        if "neuralice.mirror_ready" not in optional:
            raise SelectorRefusal("mirror-without-ready-closure-hash")
        if "neuralice.mirror_manifest" not in optional:
            raise SelectorRefusal("mirror-without-ready-manifest-hash")
        if "neuralice.mirror_generation" not in optional:
            raise SelectorRefusal("mirror-without-cache-generation")
    else:
        for key in ("neuralice.mirror_ca_sha256", "neuralice.mirror_ready", "neuralice.mirror_manifest", "neuralice.mirror_generation"):
            if key in optional:
                raise SelectorRefusal("mirror-pin-without-mirror")

    # A medium either carries an offline seed and seals its closure hash, or
    # carries neither. A registry install pulls its bytes; a seed staged beside
    # it would be a second, unreconciled source of the same objects.
    if "neuralice.seed_closure" in optional:
        if source == "registry":
            raise SelectorRefusal("seed-closure-with-registry-source")
        # The seed's release manifest names repositories under the release
        # authority, and the verifier is handed that authority explicitly.
        if release_authority is None:
            raise SelectorRefusal("seed-closure-without-release-authority")
        if "neuralice.seed_manifest" not in optional:
            raise SelectorRefusal("seed-closure-without-manifest-hash")
        if "neuralice.seed_trusted_now" not in optional:
            raise SelectorRefusal("seed-closure-without-trusted-time")
    elif "neuralice.seed_manifest" in optional or "neuralice.seed_trusted_now" in optional:
        raise SelectorRefusal("seed-manifest-without-closure")
    return mode


# --------------------------------------------------------------------------- #
# The sealed payload: an independent reader of the header contract, and a
# from-scratch recomputation of both dm-verity root hashes.
# --------------------------------------------------------------------------- #
def parse_payload_header(block: bytes) -> dict[str, str]:
    text = block.rstrip(b"\x00")
    if b"\x00" in text:
        raise InspectionError("the payload header carries a NUL inside its text")
    try:
        decoded = text.decode("ascii")
    except UnicodeDecodeError as error:
        raise InspectionError(f"the payload header is not ASCII ({error})") from error
    lines = decoded.splitlines()
    if not lines:
        raise InspectionError("the payload header is empty")
    fields: dict[str, str] = {}
    keys: list[str] = []
    for line in lines:
        if "=" not in line:
            raise InspectionError(f"the payload header carries a non-field line {line!r}")
        key, value = line.split("=", 1)
        if key in fields:
            raise InspectionError(f"the payload header repeats {key!r}")
        fields[key] = value
        keys.append(key)
    if keys != sorted(keys):
        raise InspectionError("the payload header is not in canonical key order")
    if set(keys) != PAYLOAD_KEYS:
        missing = sorted(PAYLOAD_KEYS - set(keys))
        unknown = sorted(set(keys) - PAYLOAD_KEYS)
        raise InspectionError(
            f"the payload header field set differs (missing={missing}, unknown={unknown})"
        )
    if fields["schema"] != PAYLOAD_SCHEMA:
        raise InspectionError(f"the payload header is not {PAYLOAD_SCHEMA}")
    for key in ("root_verity_hash", "store_verity_hash"):
        if not re.fullmatch(r"[0-9a-f]{64}", fields[key]):
            raise InspectionError(f"the payload header's {key} is not a 64-hex digest")
    if not re.fullmatch(r"[0-9a-f]{2,128}", fields["verity_salt"]):
        raise InspectionError("the payload header's verity_salt is not lowercase hex")
    return fields


def parse_region(fields: dict[str, str], name: str) -> tuple[int, int, str]:
    raw = fields[f"region.{name}"]
    match = re.fullmatch(r"offset:(\d{1,19}),size:(\d{1,19}),sha256:([0-9a-f]{64})", raw)
    if not match:
        raise InspectionError(f"the payload header's region {name!r} is malformed")
    offset, size = int(match.group(1)), int(match.group(2))
    if size == 0 or offset % PAYLOAD_ALIGNMENT or offset < PAYLOAD_HEADER_BYTES:
        raise InspectionError(f"the payload header's region {name!r} has an implausible extent")
    return offset, size, match.group(3)


def hash_extent(handle, base: int, size: int) -> str:
    """SHA-256 of `size` bytes at `base`, streamed."""
    digest = hashlib.sha256()
    handle.seek(base)
    remaining = size
    while remaining:
        block = handle.read(min(READ_CHUNK, remaining))
        if not block:
            raise InspectionError("the medium is shorter than the extent it declares")
        digest.update(block)
        remaining -= len(block)
    return digest.hexdigest()


def verity_root_hash(handle, base: int, size: int, salt: bytes) -> str:
    """Recompute a dm-verity v1 sha256 root hash straight from the data bytes.

    This deliberately does NOT read the hash tree that ships beside the image.
    The tree's own bytes are authenticated by the header digest; what a manifest
    can never establish is that the tree and the sealed root hash actually
    DESCRIBE THIS IMAGE. Recomputing the Merkle root from the data alone --
    layout-independent, so no assumption about how cryptsetup arranges levels --
    is the statement that was missing.
    """
    block_size = 4096
    per_block = block_size // 32
    if size % block_size:
        # `veritysetup format` protects floor(size / block_size) blocks and
        # ignores a trailing partial one, so an unaligned region would end in
        # bytes dm-verity never checks. The producer pads for exactly this
        # reason (image/build-installer-payload.sh); a medium that arrives here
        # unaligned was not built by it.
        raise InspectionError(
            f"a verity-protected region is {size} bytes, not a whole number of "
            f"{block_size}-byte blocks; its tail would be unprotected"
        )
    handle.seek(base)
    level: list[bytes] = []
    remaining = size
    while remaining:
        chunk = handle.read(min(block_size, remaining))
        if not chunk:
            raise InspectionError("the medium is shorter than the image it declares")
        remaining -= len(chunk)
        if len(chunk) < block_size:
            chunk = chunk + b"\x00" * (block_size - len(chunk))
        level.append(hashlib.sha256(salt + chunk).digest())
    if not level:
        raise InspectionError("a verity-protected region cannot be empty")
    while len(level) > 1:
        parent: list[bytes] = []
        for start in range(0, len(level), per_block):
            group = b"".join(level[start : start + per_block])
            group = group + b"\x00" * (block_size - len(group))
            parent.append(hashlib.sha256(salt + group).digest())
        level = parent
    return level[0].hex()


def check_payload(
    raw: Path, partition: Partition, arguments: argparse.Namespace, sealed: dict[str, str]
) -> dict[str, str]:
    with raw.open("rb") as handle:
        handle.seek(partition.offset)
        header_block = handle.read(PAYLOAD_HEADER_BYTES)
        if len(header_block) < PAYLOAD_HEADER_BYTES:
            raise InspectionError("the payload partition is shorter than one header block")
        fields = parse_payload_header(header_block)
        header_text = header_block.rstrip(b"\x00")
        digest = hashlib.sha256(header_text).hexdigest()

        # THE BINDING. The header authenticates the regions; the signature
        # authenticates the header. Neither half is worth anything alone.
        if digest != sealed["neuralice.payload"]:
            raise InspectionError(
                f"the payload header on this medium hashes to {digest}, "
                f"not the {sealed['neuralice.payload']} the signed UKI seals"
            )
        if arguments.expect_payload_digest and digest != arguments.expect_payload_digest:
            raise InspectionError(
                f"the payload header hashes to {digest}, not the staged "
                f"{arguments.expect_payload_digest}"
            )
        if fields["root_verity_hash"] != sealed["neuralice.rootverity"]:
            raise InspectionError(
                "the payload header's root verity hash is not the one the signed UKI seals"
            )

        extents: dict[str, tuple[int, int, str]] = {}
        end = PAYLOAD_HEADER_BYTES
        for name in PAYLOAD_REGIONS:
            offset, size, region_digest = parse_region(fields, name)
            if offset < end:
                raise InspectionError(f"the payload region {name!r} overlaps what precedes it")
            if offset + size > partition.length:
                raise InspectionError(
                    f"the payload region {name!r} runs past the end of its partition"
                )
            end = offset + size
            extents[name] = (offset, size, region_digest)

        # Every region, hashed off the medium.
        for name, (offset, size, region_digest) in extents.items():
            landed = hash_extent(handle, partition.offset + offset, size)
            if landed != region_digest:
                raise InspectionError(
                    f"the payload region {name!r} hashes to {landed} on this medium, "
                    f"not the {region_digest} its header records"
                )

        salt = bytes.fromhex(fields["verity_salt"])
        for name, expected_key in (
            ("root-image", "root_verity_hash"),
            ("store-image", "store_verity_hash"),
        ):
            offset, size, _ = extents[name]
            recomputed = verity_root_hash(handle, partition.offset + offset, size, salt)
            if recomputed != fields[expected_key]:
                raise InspectionError(
                    f"the {name} on this medium has dm-verity root hash {recomputed}, "
                    f"not the {fields[expected_key]} the sealed header carries"
                )
    return fields


def assert_zero(raw: Path, partition: Partition) -> None:
    with raw.open("rb") as handle:
        handle.seek(partition.offset)
        remaining = partition.length
        while remaining:
            block = handle.read(min(READ_CHUNK, remaining))
            if not block:
                break
            if block.strip(b"\x00"):
                raise InspectionError(
                    f"partition {partition.index} ({partition.name!r}) is not empty; a sealed "
                    "medium may carry no boot content outside its ESP and its sealed payload"
                )
            remaining -= len(block)


# --------------------------------------------------------------------------- #
# The ESP: exactly one EFI authority, and an allowlisted tree around it.
# --------------------------------------------------------------------------- #
def check_esp_hash_bound(paths: set[str], read_file, cmdline: str) -> None:
    """Every ESP artefact the sealed command line pins must be present and hash
    to the pinned value; every one that is present must be pinned.

    🔴 WHY THIS IS A COMPARISON AND NOT A PRESENCE TEST (independent review
    2026-09-02, P0 #3). A registry medium carries `release-authorization.json`
    and its detached signature, and a lab-managed bench medium also carries the
    mirror CA. All three live on a MUTABLE vfat partition an attacker holding the
    medium can rewrite, while the UKI that seals their digests is signed. The
    installer verifies the authorization's SIGNATURE, which makes the verifier
    non-editable and left the DOCUMENT selectable: any other correctly signed
    authorization -- for a different digest, a different profile, an older
    issuance -- would have been accepted. The digests close that.

    Both directions are refusals. An artefact the signature does not pin is one
    anybody can replace; a pin with no artefact is a medium that would refuse
    itself on a bench with an already-wiped disk.
    """
    sealed_words = dict(word.split("=", 1) for word in cmdline.split() if "=" in word)
    for path, karg in ESP_HASH_BOUND:
        pinned = sealed_words.get(karg)
        present = path in paths
        if pinned is None and present:
            raise InspectionError(
                f"the ESP carries {path} but the sealed command line pins no {karg}; "
                "an artefact nothing pins is an artefact anybody can replace"
            )
        if pinned is None:
            continue
        if not present:
            raise InspectionError(
                f"the sealed command line pins {karg} but the ESP carries no {path}; "
                "this medium would refuse itself at install time"
            )
        observed = hashlib.sha256(read_file(path)).hexdigest()
        if observed != pinned:
            raise InspectionError(
                f"the ESP's {path} hashes to {observed}, not the {pinned} the signed "
                "command line seals"
            )


def check_esp(esp: Fat, arguments: argparse.Namespace) -> tuple[str, dict[str, str]]:
    paths = sorted(esp.walk())
    manifests = [path for path in paths if ESP_MANIFEST_RE.fullmatch(path)]
    if len(manifests) != 1:
        raise InspectionError(
            f"the ESP carries {len(manifests)} UKI build manifests; expected exactly one"
        )
    allowed = set(ESP_REQUIRED) | ESP_OPTIONAL | set(manifests)
    unexpected = [path for path in paths if path not in allowed]
    if unexpected:
        raise InspectionError(
            "the ESP carries files a sealed medium may not: "
            f"{unexpected} — there must be no second EFI binary, boot manager or "
            "boot configuration for anything to choose between"
        )
    for required in ESP_REQUIRED:
        if required not in paths:
            raise InspectionError(f"the ESP carries no {required}")

    mode = "install" if manifests[0].endswith("installer-install.efi.manifest") else "live"
    if arguments.expect_mode and mode != arguments.expect_mode:
        raise InspectionError(
            f"this medium's UKI manifest says it is a {mode} medium, not a {arguments.expect_mode} one"
        )

    blob = esp.read_file("EFI/BOOT/BOOTAA64.EFI")
    manifest_bytes = esp.read_file(manifests[0])
    manifest = dict(
        line.split("=", 1)
        for line in manifest_bytes.decode("utf-8", "replace").splitlines()
        if "=" in line
    )
    sections = pe_sections(blob)
    if ".cmdline" not in sections or ".linux" not in sections or ".initrd" not in sections:
        raise InspectionError(
            "BOOTAA64.EFI does not embed .cmdline, .linux and .initrd; it cannot boot itself"
        )
    cmdline = sections[".cmdline"].rstrip(b"\x00").decode("utf-8", "replace")
    fields = sealed_fields(cmdline)

    if manifest.get("cmdline") != cmdline:
        raise InspectionError("BOOTAA64.EFI's .cmdline section is not the one its manifest records")
    if fields["neuralice.rootverity"] != arguments.expect_verity_root_hash:
        raise InspectionError(
            f"BOOTAA64.EFI seals verity root hash {fields['neuralice.rootverity']}, "
            f"not the staged {arguments.expect_verity_root_hash}"
        )
    for key, expected in (
        ("neuralice.access_profile", arguments.expect_access_profile),
        ("neuralice.hardware_target", arguments.expect_hardware_target),
        ("neuralice.trust_policy_id", arguments.expect_trust_policy_id),
    ):
        if expected is not None and fields[key] != expected:
            raise InspectionError(f"BOOTAA64.EFI seals {key}={fields[key]}, expected {expected}")

    # THE WHOLE LINE, not three words of it. classify_sealed_cmdline is a closed
    # world: every word must be one the grammar names, so `systemd.debug_shell`,
    # `init=`, `rd.break`, `systemd.mask=`, `emergency` and every argument
    # invented after this file was written are refused here -- before a medium
    # carrying one is ever flashed. See image/installer/neural-ice-sealed-cmdline-grammar.sh.
    sealed_mode = classify_sealed_cmdline(cmdline)
    if sealed_mode != mode:
        raise InspectionError(
            f"BOOTAA64.EFI's manifest says this is a {mode} medium, but its sealed "
            f"command line is a {sealed_mode} one"
        )
    # 🔴 THE ESP ARTEFACTS THE SIGNATURE PINS (independent review 2026-09-02,
    # P0 #3). Checked by a pure function so image/test-installer-selector-grammar.sh
    # can drive it on ordinary CI -- this suite needs veritysetup, a loop device
    # and a real medium, and a control that only exists behind that fixture is a
    # control nobody notices the loss of.
    check_esp_hash_bound(set(paths), esp.read_file, cmdline)
    if not arguments.allow_unsigned and not pe_has_signature(blob):
        raise InspectionError("BOOTAA64.EFI carries no signature")
    return cmdline, fields


def main() -> int:
    # A PURE ENTRY POINT for the sealed command-line grammar. It exists so
    # image/test-installer-selector-grammar.sh can drive this implementation --
    # the one that guards a finished medium -- against the shell implementation
    # the producer and the runtime share, on ordinary CI, with no veritysetup, no
    # loop device and no medium. The grammar was previously reachable only
    # through a full sealed-medium fixture, which SKIPs wherever the verity
    # toolchain is absent; a control that disappears with its fixture is a
    # control nobody notices the loss of (review 2026-09-02, P3).
    if sys.argv[1:2] == ["--classify-cmdline"]:
        if len(sys.argv) != 3:
            print("usage: --classify-cmdline <sealed cmdline>", file=sys.stderr)
            return 2
        try:
            print(classify_sealed_cmdline(sys.argv[2]))
        except SelectorRefusal as refusal:
            print(f"REFUSED {refusal.reason}", file=sys.stderr)
            return 1
        return 0

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw", required=True, type=Path)
    parser.add_argument("--expect-verity-root-hash", required=True)
    parser.add_argument("--expect-payload-digest")
    parser.add_argument("--expect-mode", choices=("install", "live"))
    parser.add_argument("--expect-access-profile")
    parser.add_argument("--expect-hardware-target")
    parser.add_argument("--expect-trust-policy-id")
    parser.add_argument("--allow-unsigned", action="store_true")
    parser.add_argument("--payload-partition-name", default=PAYLOAD_PARTITION_NAME)
    arguments = parser.parse_args()

    for value, label in (
        (arguments.expect_verity_root_hash, "--expect-verity-root-hash"),
        (arguments.expect_payload_digest, "--expect-payload-digest"),
    ):
        if value is not None and not re.fullmatch(r"[0-9a-f]{64}", value):
            print(f"ERROR: {label} must be 64 lowercase hex", file=sys.stderr)
            return 2

    try:
        _sector, partitions = read_gpt(arguments.raw)
        payloads = [p for p in partitions if p.name == arguments.payload_partition_name]
        if len(payloads) != 1:
            raise InspectionError(
                f"expected exactly one partition named {arguments.payload_partition_name!r}, "
                f"found {len(payloads)} in {[p.name for p in partitions]}"
            )
        esp_partitions = [p for p in partitions if p.type_guid == ESP_TYPE_GUID]
        if len(esp_partitions) != 1:
            raise InspectionError(
                f"expected exactly one EFI System Partition, found {len(esp_partitions)}"
            )
        with arguments.raw.open("rb") as handle:
            esp = Fat(handle, esp_partitions[0].offset, esp_partitions[0].length)
            cmdline, sealed = check_esp(esp, arguments)
        header = check_payload(arguments.raw, payloads[0], arguments, sealed)

        # EVERY OTHER PARTITION MUST BE EMPTY. The medium's old boot partition and
        # its ostree deployment are overwritten, not deleted, and this is where
        # that is proved: a partition that still carries a kernel, an initramfs
        # or a BLS entry would be a boot authority nothing signed.
        known = {payloads[0].index, esp_partitions[0].index}
        for partition in partitions:
            if partition.index in known or partition.name == "ni-seed":
                continue
            assert_zero(arguments.raw, partition)
    except InspectionError as error:
        print(f"inspect-installer-media: REFUSED: {error}", file=sys.stderr)
        return 1
    except (OSError, struct.error, ValueError) as error:
        print(f"inspect-installer-media: unreadable medium: {error}", file=sys.stderr)
        return 2

    print("inspect-installer-media: OK")
    print(f"  EFI authority   : EFI/BOOT/BOOTAA64.EFI (the only bootable file on the medium)")
    print(f"  sealed cmdline  : {cmdline}")
    print(f"  payload digest  : {sealed['neuralice.payload']}")
    print(f"  root  verity    : {header['root_verity_hash']} (recomputed from the medium)")
    print(f"  store verity    : {header['store_verity_hash']} (recomputed from the medium)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
