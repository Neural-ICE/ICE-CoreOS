#!/usr/bin/env python3
"""Bench snapshot, reference record and signed bench sheet for the PCR 7 policy.

The OEM bench boots ONE gold unit per firmware family, once from the installer
medium and once from the installed system, and records what the firmware measured
into PCR 7. That evidence decides which PCR 7 values a unit of the family may
legitimately boot with, so it is captured, checked and filed under a layout a CI
job and the Owner can both validate.

    capture         one boot path -> a snapshot (variables, PCR 7 events, BIOS)
    build-record    installer + installed snapshots -> the REFERENCE RECORD
    make-sheet      record -> an unsigned BENCH SHEET (pinned firmware, expected PCR 7)
    sheet-payload   the exact bytes the Owner signs (domain-separated)
    store           validate everything, then file it under pcr-reference/<family>/
    validate-store  re-validate a pcr-reference/ tree against a trusted public key
    validate-record / validate-snapshot / verify-sheet   the same checks, one at a time

This tool holds NO signing key and has no signing command: the Owner signs the
payload with `openssl dgst -sha256 -sign` on the Owner's own machine.

Layout (one directory per firmware family, named by the record's family_id):

    pcr-reference/<family_id>/reference-record.json
                              bench-sheet.json
                              bench-sheet.sig
                              snapshots/installer.snapshot.json
                              snapshots/installed.snapshot.json

The record's per-path `pcr7_reference` is the `ni-pcr7-reference/1` description
tools/ni-pcr7-calc consumes (`compute`), so the calculator can start from a stored
record instead of a live machine. This file re-derives and re-checks it with its
own small fold; when ni-pcr7-calc is present it is cross-checked as well.

Python 3 standard library plus the `openssl` binary the installer already needs.
"""

import argparse
import base64
import datetime
import hashlib
import importlib.util
import json
import os
import pathlib
import platform
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import uuid

_HERE = pathlib.Path(__file__).resolve().parent
_POLICY_TOOL = _HERE.parents[1] / "ota" / "neural-ice-tpm-policy.py"
_spec = importlib.util.spec_from_file_location("ni_tpm_policy", _POLICY_TOOL)
policy = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(policy)

TOOL_VERSION = "1"
SNAPSHOT_SCHEMA = "ni-bench-snapshot/1"
RECORD_SCHEMA = "ni-pcr-reference-record/1"
SHEET_SCHEMA = "ni-bench-sheet/1"
REFERENCE_SCHEMA = "ni-pcr7-reference/1"   # tools/ni-pcr7-calc
SHEET_DOMAIN = SHEET_SCHEMA.encode() + b"\n"

PCR = 7
BANK = "sha256"
PATHS = ("installer", "installed")
ORIGINS = ("measured", "synthetic-test")
MEASUREMENTS = ("names-only", "contents")
BOOT_SHAPES = {"uki-direct": ("db",), "shim-grub": ("db", "SbatLevel", "MokListRT")}

GUID_GLOBAL = "8be4df61-93ca-11d2-aa0d-00e098032b8c"
GUID_SECURITY_DB = "d719b2cb-3d3a-4596-a3bc-dad00e67656f"
GUID_SHIM_LOCK = "605dab50-e046-4300-abb6-3dd810dd8b23"
# The ONLY variables ever copied off a machine, in the order they are stored.
# Anything else in efivarfs (boot entries, vendor data) is never read into a file.
VARIABLE_GUIDS = {
    "SecureBoot": GUID_GLOBAL, "SetupMode": GUID_GLOBAL, "AuditMode": GUID_GLOBAL,
    "DeployedMode": GUID_GLOBAL, "PK": GUID_GLOBAL, "KEK": GUID_GLOBAL,
    "db": GUID_SECURITY_DB, "dbx": GUID_SECURITY_DB, "dbt": GUID_SECURITY_DB,
    "dbr": GUID_SECURITY_DB,
    "SbatLevelRT": GUID_SHIM_LOCK, "MokListRT": GUID_SHIM_LOCK,
}
REQUIRED_VARIABLES = ("SecureBoot", "PK", "KEK", "db", "dbx")
# Variables that must be identical on the two boots: they are firmware state.
# SbatLevelRT / MokListRT belong to shim, which the installer medium does not run.
CORE_VARIABLES = ("SecureBoot", "PK", "KEK", "db", "dbx", "dbt", "dbr")
EFIVARS_DIR = "/sys/firmware/efi/efivars"
DEFAULT_EVENTLOG = "/sys/kernel/security/tpm0/binary_bios_measurements"
DMI_DIR = "/sys/class/dmi/id"

EV_NAMES = {policy.EV_EFI_VARIABLE_DRIVER_CONFIG: "config",
            policy.EV_SEPARATOR: "separator",
            policy.EV_EFI_VARIABLE_AUTHORITY: "authority"}

HEX64 = re.compile(r"^[0-9a-f]{64}$")
TOKEN = re.compile(r"^[0-9A-Za-z._+-]{1,64}$")


class BenchError(RuntimeError):
    pass


# --- strict JSON and schema helpers ----------------------------------------

def _reject_duplicates(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise BenchError(f"duplicate JSON key {key!r}")
        out[key] = value
    return out


def _reject_constant(name):
    raise BenchError(f"JSON constant {name} is not allowed")


def load_json_strict(text):
    try:
        return json.loads(text, object_pairs_hook=_reject_duplicates,
                          parse_constant=_reject_constant)
    except json.JSONDecodeError as error:
        raise BenchError(f"not valid JSON: {error}") from error


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _digest(obj):
    return hashlib.sha256(canonical(obj)).hexdigest()


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _keys(obj, required, where, optional=()):
    if not isinstance(obj, dict):
        raise BenchError(f"{where}: must be an object")
    missing = [k for k in required if k not in obj]
    if missing:
        raise BenchError(f"{where}: missing {missing}")
    unknown = sorted(set(obj) - set(required) - set(optional))
    if unknown:
        raise BenchError(f"{where}: unknown field {unknown}")


def _str(value, where, pattern=None, allow_none=False):
    if value is None and allow_none:
        return
    if not isinstance(value, str) or not value:
        raise BenchError(f"{where}: must be a non-empty string")
    if pattern is not None and not pattern.match(value):
        raise BenchError(f"{where}: unexpected format")


def _hex64(value, where):
    if not isinstance(value, str) or not HEX64.match(value):
        raise BenchError(f"{where}: must be 64 lower-case hex characters")


def _b64(value, where):
    try:
        return base64.b64decode(value, validate=True)
    except (TypeError, ValueError) as error:
        raise BenchError(f"{where}: not base64") from error


def _guid(value, where):
    try:
        return str(uuid.UUID(value))
    except (TypeError, ValueError, AttributeError) as error:
        raise BenchError(f"{where}: not a GUID") from error


def _date(value, where):
    try:
        return datetime.date.fromisoformat(value).isoformat()
    except (TypeError, ValueError) as error:
        raise BenchError(f"{where}: not an ISO date (YYYY-MM-DD)") from error


def normalise_bios_date(value):
    """DMI gives MM/DD/YYYY; the record keeps ISO 8601."""
    if not isinstance(value, str):
        raise BenchError("bios_date: missing")
    for fmt in ("%m/%d/%Y", "%Y-%m-%d"):
        try:
            return datetime.datetime.strptime(value.strip(), fmt).date().isoformat()
        except ValueError:
            pass
    raise BenchError(f"bios_date: {value!r} is neither MM/DD/YYYY nor YYYY-MM-DD")


def family_id_of(bios_version):
    return re.sub(r"[^a-z0-9]+", "-", bios_version.lower()).strip("-")


# --- capture -----------------------------------------------------------------

def _variable_from_blob(name, blob, where):
    if len(blob) < 4:
        raise BenchError(f"{where}: shorter than the 4 attribute bytes of an efivarfs file")
    return {"attributes": struct.unpack_from("<I", blob)[0], "data": blob[4:]}


def read_efivars_b64(path):
    """`<name>-<guid> <base64 of the efivarfs file>` per line (the collection format)."""
    found = {}
    try:
        text = pathlib.Path(path).read_text(encoding="ascii")
    except (OSError, UnicodeError) as error:
        raise BenchError(f"cannot read {path}: {error}") from error
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        key, _, b64 = line.partition(" ")
        found[key] = _b64(b64.strip(), f"{path}:{number}")
    return found


def read_efivars_dir(path):
    """Read ONLY the allow-listed variables of an efivarfs directory."""
    found = {}
    for name, guid in VARIABLE_GUIDS.items():
        file = pathlib.Path(path) / f"{name}-{guid}"
        if file.is_symlink():
            raise BenchError(f"{file}: a symlink is not an EFI variable")
        try:
            found[f"{name}-{guid}"] = file.read_bytes()
        except FileNotFoundError:
            continue
        except OSError as error:
            raise BenchError(f"cannot read {file}: {error}") from error
    return found


def _select_variables(raw):
    """Map name -> {guid, attributes, data} for the allow-listed names; a name
    filed under a GUID that is not its own is refused, never silently ignored."""
    chosen = {}
    for key, blob in raw.items():
        name, guid = key[:-37], key[-36:]
        if len(key) < 38 or key[-37] != "-" or name not in VARIABLE_GUIDS:
            continue
        guid = _guid(guid, f"variable {key}")
        if guid != VARIABLE_GUIDS[name]:
            raise BenchError(f"variable {name} is filed under GUID {guid}, "
                             f"not {VARIABLE_GUIDS[name]}")
        entry = _variable_from_blob(name, blob, key)
        entry["guid"] = guid
        chosen[name] = entry
    return chosen


def _read_pcr7(text):
    match = re.search(r"(?m)^\s*7\s*:\s*0x([0-9A-Fa-f]{64})\s*$", text or "")
    if not match:
        raise BenchError("PCR 7 value not found (expected `7 : 0x<64 hex>` as tpm2_pcrread prints it)")
    return match.group(1).lower()


def encode_pcr7_log(blob, events):
    """The log's TCG2 header plus only the PCR 7 events, as the firmware wrote them."""
    header_len = 32 + struct.unpack_from("<I", blob, 28)[0]
    ids = {name: alg for alg, (name, _) in policy.ALGS.items()}
    out = bytearray(blob[:header_len])
    for ev in events:
        out += struct.pack("<III", ev["pcr"], ev["type"], len(ev["digests"]))
        for name, digest in ev["digests"].items():
            out += struct.pack("<H", ids[name]) + digest
        out += struct.pack("<I", len(ev["data"])) + ev["data"]
    return bytes(out)


def _read_file(path, what):
    try:
        return pathlib.Path(path).read_bytes()
    except OSError as error:
        raise BenchError(f"cannot read {what} {path}: {error}") from error


def capture(path, efivars_b64=None, efivars_dir=None, eventlog=None, eventlog_bytes=None,
            pcr7_text=None, bios_version=None, bios_date=None, captured_at=None,
            kernel=None, state_marker=None):
    """One boot path -> snapshot. Refuses anything incomplete: a snapshot that
    cannot be fully checked must never reach the record."""
    if path not in PATHS:
        raise BenchError(f"path must be one of {PATHS}")
    _str(bios_version, "bios_version", TOKEN)
    firmware = {"bios_version": bios_version, "bios_date": normalise_bios_date(bios_date)}

    raw = read_efivars_b64(efivars_b64) if efivars_b64 else read_efivars_dir(efivars_dir or EFIVARS_DIR)
    chosen = _select_variables(raw)
    for name in REQUIRED_VARIABLES:
        if name not in chosen:
            raise BenchError(f"required variable {name} is missing")
    secure_boot = _secure_boot_state(chosen)

    blob = eventlog_bytes if eventlog_bytes is not None else _read_file(eventlog or DEFAULT_EVENTLOG, "event log")
    try:
        events = policy.parse_eventlog(blob)
    except policy.EventLogError as error:
        raise BenchError(f"event log: {error}") from error
    pcr7_events = [e for e in events if e["pcr"] == PCR]
    if not pcr7_events:
        raise BenchError("the event log has no PCR 7 event")
    live = _read_pcr7(pcr7_text)
    try:
        replayed = policy.replay(events, PCR, BANK)[0].hex()
    except policy.EventLogError as error:
        raise BenchError(f"event log: {error}") from error
    if replayed != live:
        raise BenchError(f"the event log replay {replayed} does not reproduce the measured "
                         f"PCR 7 {live}; this snapshot would describe a different boot")
    filtered = encode_pcr7_log(blob, pcr7_events)

    snapshot = {
        "schema": SNAPSHOT_SCHEMA, "origin": "measured", "path": path,
        "captured_at": captured_at or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "firmware": firmware, "secure_boot": secure_boot,
        "variables": {name: _variable_entry(chosen[name]) for name in VARIABLE_GUIDS if name in chosen},
        "pcr7": {"bank": BANK, "value": live,
                 "eventlog_pcr7_b64": base64.b64encode(filtered).decode(),
                 "eventlog_pcr7_sha256": _sha(filtered),
                 "eventlog_full_sha256": _sha(blob)},
        "provenance": {"tool": "ni-bench-snapshot", "tool_version": TOOL_VERSION,
                       "kernel": kernel, "state_marker": state_marker},
    }
    validate_snapshot(snapshot)
    return snapshot


def _variable_entry(var):
    return {"guid": var["guid"], "attributes": var["attributes"], "size": len(var["data"]),
            "sha256": _sha(var["data"]), "data_b64": base64.b64encode(var["data"]).decode()}


def _one_byte(chosen, name):
    if name not in chosen:
        return None
    data = chosen[name]["data"]
    if len(data) != 1 or data[0] not in (0, 1):
        raise BenchError(f"variable {name} must hold exactly one byte, 0 or 1")
    return data[0]


def _secure_boot_state(chosen):
    """Secure Boot must be enforcing with a platform key enrolled. SetupMode is
    captured when the firmware exposes it; when it does not, it is DERIVED from
    the two facts that entail it (UEFI: SecureBoot=1 only outside setup mode) and
    labelled as derived, never presented as a measurement."""
    if _one_byte(chosen, "SecureBoot") != 1:
        raise BenchError("SecureBoot is not enabled (value 1): not a Secure Boot measurement")
    if not chosen["PK"]["data"]:
        raise BenchError("PK is empty: the firmware is in setup mode")
    setup = _one_byte(chosen, "SetupMode")
    if setup == 1:
        raise BenchError("SetupMode is 1: no platform key is enforced")
    origin = "captured"
    if setup is None:
        setup, origin = 0, "derived"
    return {"secure_boot": 1, "setup_mode": setup, "setup_mode_origin": origin,
            "audit_mode": _one_byte(chosen, "AuditMode"),
            "deployed_mode": _one_byte(chosen, "DeployedMode")}


# --- snapshot validation -----------------------------------------------------

def _validate_variables(variables, where, core_present=True):
    if not isinstance(variables, dict):
        raise BenchError(f"{where}: must be an object")
    for name in REQUIRED_VARIABLES:
        if core_present and name not in variables:
            raise BenchError(f"{where}: required variable {name} is missing")
    for name, entry in variables.items():
        if name not in VARIABLE_GUIDS:
            raise BenchError(f"{where}.{name}: not an allow-listed variable")
        _keys(entry, ("guid", "attributes", "size", "sha256", "data_b64"), f"{where}.{name}")
        if _guid(entry["guid"], f"{where}.{name}.guid") != VARIABLE_GUIDS[name]:
            raise BenchError(f"{where}.{name}: wrong vendor GUID")
        if type(entry["attributes"]) is not int or not 0 <= entry["attributes"] < 1 << 32:
            raise BenchError(f"{where}.{name}.attributes: not a 32-bit integer")
        data = _b64(entry["data_b64"], f"{where}.{name}.data_b64")
        if entry["size"] != len(data) or entry["sha256"] != _sha(data):
            raise BenchError(f"{where}.{name}: size or sha256 does not match the data")


def validate_snapshot(snapshot):
    _keys(snapshot, ("schema", "origin", "path", "captured_at", "firmware", "secure_boot",
                     "variables", "pcr7", "provenance"), "snapshot")
    if snapshot["schema"] != SNAPSHOT_SCHEMA:
        raise BenchError(f"snapshot.schema must be {SNAPSHOT_SCHEMA!r}")
    if snapshot["origin"] not in ORIGINS:
        raise BenchError(f"snapshot.origin must be one of {ORIGINS}")
    if snapshot["path"] not in PATHS:
        raise BenchError(f"snapshot.path must be one of {PATHS}")
    _str(snapshot["captured_at"], "snapshot.captured_at",
         re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$"))
    fw = snapshot["firmware"]
    _keys(fw, ("bios_version", "bios_date"), "snapshot.firmware")
    _str(fw["bios_version"], "snapshot.firmware.bios_version", TOKEN)
    _date(fw["bios_date"], "snapshot.firmware.bios_date")
    _validate_variables(snapshot["variables"], "snapshot.variables")
    chosen = {n: {"data": _b64(e["data_b64"], n)} for n, e in snapshot["variables"].items()}
    expected = _secure_boot_state(chosen)
    sb = snapshot["secure_boot"]
    _keys(sb, tuple(expected), "snapshot.secure_boot")
    if sb != expected:
        raise BenchError("snapshot.secure_boot does not follow from the stored variables")
    prov = snapshot["provenance"]
    _keys(prov, ("tool", "tool_version", "kernel", "state_marker"), "snapshot.provenance")
    for field in ("kernel", "state_marker"):
        _str(prov[field], f"snapshot.provenance.{field}", TOKEN, allow_none=True)
    _validate_pcr7(snapshot["pcr7"])


def _validate_pcr7(pcr7):
    _keys(pcr7, ("bank", "value", "eventlog_pcr7_b64", "eventlog_pcr7_sha256",
                 "eventlog_full_sha256"), "snapshot.pcr7")
    if pcr7["bank"] != BANK:
        raise BenchError(f"snapshot.pcr7.bank must be {BANK!r}")
    for field in ("value", "eventlog_pcr7_sha256", "eventlog_full_sha256"):
        _hex64(pcr7[field], f"snapshot.pcr7.{field}")
    blob = _b64(pcr7["eventlog_pcr7_b64"], "snapshot.pcr7.eventlog_pcr7_b64")
    if _sha(blob) != pcr7["eventlog_pcr7_sha256"]:
        raise BenchError("snapshot.pcr7: eventlog_pcr7_sha256 does not match the stored log")
    try:
        events = policy.parse_eventlog(blob)
    except policy.EventLogError as error:
        raise BenchError(f"snapshot.pcr7 log: {error}") from error
    if not events or any(e["pcr"] != PCR for e in events):
        raise BenchError("snapshot.pcr7 log must hold PCR 7 events and nothing else")
    if _fold([e["digests"].get(BANK) for e in events]) != pcr7["value"]:
        raise BenchError("snapshot.pcr7: the stored log replay does not reproduce the PCR 7 value")


def _fold(digests):
    acc = b"\x00" * 32
    for digest in digests:
        if not isinstance(digest, bytes) or len(digest) != 32:
            raise BenchError("an event carries no sha256 digest")
        acc = hashlib.sha256(acc + digest).digest()
    return acc.hex()


# --- the PCR 7 reference description (ni-pcr7-reference/1) ------------------

def _split_variable(data, where):
    if len(data) < 32:
        raise BenchError(f"{where}: shorter than a UEFI_VARIABLE_DATA header")
    name_len, data_len = struct.unpack_from("<QQ", data, 16)
    end = 32 + name_len * 2
    if end + data_len != len(data):
        raise BenchError(f"{where}: UEFI_VARIABLE_DATA lengths do not add up")
    return (str(uuid.UUID(bytes_le=data[:16])), data[32:end].decode("utf-16-le"), data[end:])


def _variable_data(guid, name, data):
    return (uuid.UUID(guid).bytes_le + struct.pack("<QQ", len(name), len(data))
            + name.encode("utf-16-le") + data)


def _decode_events(snapshot):
    """Every PCR 7 event of a snapshot as (kind, name, guid, payload, digest) plus
    the reference description it implies. Refuses a log the description could not
    rebuild digest for digest."""
    blob = base64.b64decode(snapshot["pcr7"]["eventlog_pcr7_b64"])
    events = policy.parse_eventlog(blob)
    variables, authorities, separator, decoded = {}, [], None, []
    for index, ev in enumerate(events, 1):
        where = f"{snapshot['path']} PCR 7 event {index}"
        if ev["digests"].get(BANK) != hashlib.sha256(ev["data"]).digest():
            raise BenchError(f"{where}: the logged digest is not sha256 of the event data")
        kind = EV_NAMES.get(ev["type"])
        if kind is None:
            raise BenchError(f"{where}: event type 0x{ev['type']:08x} is not modelled")
        if kind == "separator":
            if separator is not None:
                raise BenchError(f"{where}: a second separator")
            separator = ev["data"]
            decoded.append({"type": f"0x{ev['type']:08x}", "name": None, "digest": ev["digests"][BANK].hex()})
            continue
        guid, name, payload = _split_variable(ev["data"], where)
        if kind == "config":
            if separator is not None:
                raise BenchError(f"{where}: a config event after the separator is not modelled")
            if name in variables:
                raise BenchError(f"{where}: variable {name} measured twice")
            variables[name] = {"guid": guid, "data": payload}
        else:
            if separator is None:
                raise BenchError(f"{where}: an authority event before the separator is not modelled")
            authorities.append(_authority(name, guid, payload, ev, where))
        decoded.append({"type": f"0x{ev['type']:08x}", "name": name, "digest": ev["digests"][BANK].hex()})
    if separator is None or not variables or not authorities:
        raise BenchError(f"{snapshot['path']}: the log lacks config events, a separator or authority events")
    measured = [bool(v["data"]) for v in variables.values()]
    if not any(measured):
        measurement = "names-only"
    elif all(measured):
        measurement = "contents"
    else:
        raise BenchError(f"{snapshot['path']}: some variables are measured with data and some without")
    reference = {
        "schema": REFERENCE_SCHEMA, "bank": BANK,
        "firmware": {"variable_measurement": measurement},
        "variables": {},
        "separator_hex": separator.hex(),
        "boot_path": next((k for k, v in BOOT_SHAPES.items()
                           if tuple(a["entry"]["name"] for a in authorities) == v), "custom"),
        "authorities": [a["entry"] for a in authorities],
    }
    for name, v in variables.items():
        entry = {"guid": v["guid"]}
        if measurement == "contents":
            entry["data_hex"] = v["data"].hex()
        reference["variables"][name] = entry
    rebuilt = [e for e in reference_events(reference)]
    if rebuilt != [bytes.fromhex(d["digest"]) for d in decoded]:
        raise BenchError(f"{snapshot['path']}: the reference description does not rebuild the log")
    return decoded, reference, authorities


def _authority(name, guid, payload, ev, where):
    entry = {"name": name, "guid": guid}
    out = {"name": name, "guid": guid, "payload_sha256": _sha(payload),
           "digest": ev["digests"][BANK].hex()}
    if name == "SbatLevel":
        try:
            entry["text"] = payload.decode("utf-8")
        except UnicodeDecodeError as error:
            raise BenchError(f"{where}: SbatLevel is not UTF-8") from error
    else:
        if len(payload) <= 16:
            raise BenchError(f"{where}: authority {name} holds no certificate")
        entry["signature_owner"] = str(uuid.UUID(bytes_le=payload[:16]))
        entry["cert_der_hex"] = payload[16:].hex()
        out["signature_owner"] = entry["signature_owner"]
        out["cert_sha256"] = _sha(payload[16:])
    return {"entry": entry, "event": out}


def reference_events(reference):
    """Event digests an `ni-pcr7-reference/1` description produces, in order."""
    if reference.get("schema") != REFERENCE_SCHEMA:
        raise BenchError(f"pcr7_reference.schema must be {REFERENCE_SCHEMA!r}")
    measurement = reference.get("firmware", {}).get("variable_measurement")
    if measurement not in MEASUREMENTS:
        raise BenchError(f"pcr7_reference.firmware.variable_measurement must be one of {MEASUREMENTS}")
    digests = []
    for name, entry in reference["variables"].items():
        data = b""
        if measurement == "contents":
            if "data_hex" not in entry:
                raise BenchError(f"pcr7_reference.variables.{name}: 'contents' needs data_hex")
            data = bytes.fromhex(entry["data_hex"])
        digests.append(hashlib.sha256(_variable_data(_guid(entry["guid"], name), name, data)).digest())
    digests.append(hashlib.sha256(bytes.fromhex(reference["separator_hex"])).digest())
    for index, a in enumerate(reference["authorities"]):
        if "text" in a:
            payload = a["text"].encode("utf-8")
        elif "cert_der_hex" in a:
            payload = uuid.UUID(a["signature_owner"]).bytes_le + bytes.fromhex(a["cert_der_hex"])
        else:
            raise BenchError(f"pcr7_reference.authorities[{index}]: needs text or cert_der_hex")
        digests.append(hashlib.sha256(_variable_data(_guid(a["guid"], a["name"]), a["name"], payload)).digest())
    return digests


# --- the reference record ----------------------------------------------------

def build_record(installer, installed):
    for label, snap in (("installer", installer), ("installed", installed)):
        if snap is None:
            raise BenchError(f"the {label} path snapshot is missing: a reference record needs both "
                             "boot paths, each measured on the same unit")
        validate_snapshot(snap)
        if snap["path"] != label:
            raise BenchError(f"expected the {label} snapshot, got one captured for path {snap['path']!r}")
    if installer["firmware"] != installed["firmware"]:
        raise BenchError("the two paths were captured on different firmware: "
                         f"{installer['firmware']} vs {installed['firmware']}")
    for name in CORE_VARIABLES:
        a, b = installer["variables"].get(name), installed["variables"].get(name)
        if (a or {}).get("sha256") != (b or {}).get("sha256"):
            raise BenchError(f"variable {name} differs between the installer and installed boots; "
                             "this is not one configuration")
    paths, measurements = {}, set()
    for label, snap in (("installer", installer), ("installed", installed)):
        decoded, reference, authorities = _decode_events(snap)
        measurements.add(reference["firmware"]["variable_measurement"])
        paths[label] = {
            "origin": snap["origin"], "boot_path": reference["boot_path"],
            "authority_events": [a["event"] for a in authorities],
            "pcr7_events": decoded, "pcr7": snap["pcr7"]["value"],
            "eventlog_pcr7_sha256": snap["pcr7"]["eventlog_pcr7_sha256"],
            "pcr7_reference": reference,
        }
    if len(measurements) != 1:
        raise BenchError("the two paths disagree on how this firmware measures variables")
    record = {
        "schema": RECORD_SCHEMA,
        "family_id": family_id_of(installed["firmware"]["bios_version"]),
        "firmware": dict(installed["firmware"], variable_measurement=measurements.pop()),
        "secure_boot": dict(installed["secure_boot"]),
        "variables": {n: {k: e[k] for k in ("guid", "attributes", "size", "sha256")}
                      for n, e in installed["variables"].items()},
        "paths": paths,
        "provenance": {
            "tool": "ni-bench-snapshot", "tool_version": TOOL_VERSION,
            "captured_at": {"installer": installer["captured_at"], "installed": installed["captured_at"]},
            "snapshot_sha256": {"installer": _digest(installer), "installed": _digest(installed)},
        },
    }
    if installer["secure_boot"]["setup_mode_origin"] == "derived":
        record["secure_boot"]["setup_mode_origin"] = "derived"
    validate_record(record, allow_synthetic=True)
    return record


def record_digest(record):
    return _digest(record)


_PATH_KEYS = ("origin", "boot_path", "authority_events", "pcr7_events", "pcr7",
              "eventlog_pcr7_sha256", "pcr7_reference")


def validate_record(record, allow_synthetic=False, calc=None):
    _keys(record, ("schema", "family_id", "firmware", "secure_boot", "variables", "paths",
                   "provenance"), "record")
    if record["schema"] != RECORD_SCHEMA:
        raise BenchError(f"record.schema must be {RECORD_SCHEMA!r}")
    fw = record["firmware"]
    _keys(fw, ("bios_version", "bios_date", "variable_measurement"), "record.firmware")
    _str(fw["bios_version"], "record.firmware.bios_version", TOKEN)
    _date(fw["bios_date"], "record.firmware.bios_date")
    if fw["variable_measurement"] not in MEASUREMENTS:
        raise BenchError(f"record.firmware.variable_measurement must be one of {MEASUREMENTS}")
    if record["family_id"] != family_id_of(fw["bios_version"]):
        raise BenchError("record.family_id must be derived from firmware.bios_version "
                         f"({family_id_of(fw['bios_version'])!r})")
    sb = record["secure_boot"]
    _keys(sb, ("secure_boot", "setup_mode", "setup_mode_origin", "audit_mode", "deployed_mode"),
          "record.secure_boot")
    if sb["secure_boot"] != 1 or sb["setup_mode"] != 0 or sb["setup_mode_origin"] not in ("captured", "derived"):
        raise BenchError("record.secure_boot must describe an enforcing, non-setup-mode unit")
    variables = record["variables"]
    if not isinstance(variables, dict):
        raise BenchError("record.variables: must be an object")
    for name in REQUIRED_VARIABLES:
        if name not in variables:
            raise BenchError(f"record.variables: required variable {name} is missing")
    for name, entry in variables.items():
        if name not in VARIABLE_GUIDS:
            raise BenchError(f"record.variables.{name}: not an allow-listed variable")
        _keys(entry, ("guid", "attributes", "size", "sha256"), f"record.variables.{name}")
        _hex64(entry["sha256"], f"record.variables.{name}.sha256")
    paths = record["paths"]
    if not isinstance(paths, dict):
        raise BenchError("record.paths: must be an object")
    for label in PATHS:
        if label not in paths:
            raise BenchError(f"record.paths: the {label} path is missing; both boot paths are required")
    if set(paths) != set(PATHS):
        raise BenchError(f"record.paths: only {PATHS} are allowed")
    for label in PATHS:
        _validate_path(label, paths[label], fw["variable_measurement"], allow_synthetic, calc)
    prov = record["provenance"]
    _keys(prov, ("tool", "tool_version", "captured_at", "snapshot_sha256"), "record.provenance")
    for field in ("captured_at", "snapshot_sha256"):
        _keys(prov[field], PATHS, f"record.provenance.{field}")
    for label in PATHS:
        _hex64(prov["snapshot_sha256"][label], f"record.provenance.snapshot_sha256.{label}")


def _validate_path(label, path, measurement, allow_synthetic, calc):
    where = f"record.paths.{label}"
    _keys(path, _PATH_KEYS, where)
    if path["origin"] not in ORIGINS:
        raise BenchError(f"{where}.origin must be one of {ORIGINS}")
    if path["origin"] != "measured" and not allow_synthetic:
        raise BenchError(f"{where} is {path['origin']}, not a bench measurement: a synthetic "
                         "path can never enter the store")
    _hex64(path["pcr7"], f"{where}.pcr7")
    _hex64(path["eventlog_pcr7_sha256"], f"{where}.eventlog_pcr7_sha256")
    events = path["pcr7_events"]
    if not isinstance(events, list) or not events:
        raise BenchError(f"{where}.pcr7_events: must be a non-empty list")
    digests = []
    for i, ev in enumerate(events):
        _keys(ev, ("type", "name", "digest"), f"{where}.pcr7_events[{i}]")
        _hex64(ev["digest"], f"{where}.pcr7_events[{i}].digest")
        digests.append(bytes.fromhex(ev["digest"]))
    if _fold(digests) != path["pcr7"]:
        raise BenchError(f"{where}: the event digests do not fold to the stated PCR 7")
    ref = path["pcr7_reference"]
    if not isinstance(ref, dict):
        raise BenchError(f"{where}.pcr7_reference: must be an object")
    if ref.get("firmware", {}).get("variable_measurement") != measurement:
        raise BenchError(f"{where}.pcr7_reference disagrees with record.firmware.variable_measurement")
    try:
        rebuilt = reference_events(ref)
    except (KeyError, TypeError, ValueError, AttributeError) as error:
        raise BenchError(f"{where}.pcr7_reference: malformed ({error!r})") from error
    if rebuilt != digests:
        raise BenchError(f"{where}.pcr7_reference does not reproduce the recorded event digests")
    names = tuple(a.get("name") for a in ref["authorities"])
    shape = next((k for k, v in BOOT_SHAPES.items() if names == v), "custom")
    if path["boot_path"] != shape or ref.get("boot_path") != shape:
        raise BenchError(f"{where}.boot_path {path['boot_path']!r} does not match its authority events {list(names)}")
    authority = path["authority_events"]
    if not isinstance(authority, list) or [a.get("name") for a in authority] != list(names):
        raise BenchError(f"{where}.authority_events do not match the reference authorities")
    for i, a in enumerate(authority):
        _keys(a, ("name", "guid", "payload_sha256", "digest"), f"{where}.authority_events[{i}]",
              optional=("signature_owner", "cert_sha256"))
        _hex64(a["digest"], f"{where}.authority_events[{i}].digest")
        _hex64(a["payload_sha256"], f"{where}.authority_events[{i}].payload_sha256")
    if authority and [a["digest"] for a in authority] != [e["digest"] for e in events[-len(authority):]]:
        raise BenchError(f"{where}.authority_events are not the last PCR 7 events")
    calc = calc if calc is not None else load_calc()
    if calc is not None:
        try:
            value = calc.compute(ref).pcr7.hex()
        except Exception as error:  # the calculator's own refusal is a refusal here
            raise BenchError(f"{where}: ni-pcr7-calc refuses this reference: {error}") from error
        if value != path["pcr7"]:
            raise BenchError(f"{where}: ni-pcr7-calc computes {value}, the record says {path['pcr7']}")


def load_calc():
    """T1's calculator (tools/ni-pcr7-calc), when this tree or NI_PCR7_TOOL has it."""
    path = pathlib.Path(os.environ.get("NI_PCR7_TOOL") or _HERE.parent / "ni-pcr7-calc" / "ni-pcr7-calc.py")
    if not path.is_file():
        return None
    spec = importlib.util.spec_from_file_location("ni_pcr7_calc", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# --- the bench sheet ---------------------------------------------------------

def pubkey_fingerprint(pubkey_pem):
    """`pkfp`, as systemd and the installer compute it (sha256 of the RSAPublicKey DER)."""
    try:
        return policy.pubkey_fingerprint(pubkey_pem)
    except policy.EventLogError as error:
        raise BenchError(str(error)) from error


def make_sheet(record, seq, issued_at, pkfp):
    validate_record(record, allow_synthetic=True)
    if type(seq) is not int or seq < 1:
        raise BenchError("seq must be a positive integer")
    _date(issued_at, "issued_at")
    _hex64(pkfp, "pkfp")
    return {
        "schema": SHEET_SCHEMA, "family_id": record["family_id"], "seq": seq,
        "issued_at": issued_at,
        "firmware_pin": {"bios_version": record["firmware"]["bios_version"],
                         "bios_date": record["firmware"]["bios_date"]},
        "expected_pcr7": {label: record["paths"][label]["pcr7"] for label in PATHS},
        "reference_record_sha256": record_digest(record),
        "signer": {"pkfp": pkfp, "algorithm": "rsa-pkcs1-sha256"},
    }


def _validate_sheet(sheet):
    _keys(sheet, ("schema", "family_id", "seq", "issued_at", "firmware_pin", "expected_pcr7",
                  "reference_record_sha256", "signer"), "sheet")
    if sheet["schema"] != SHEET_SCHEMA:
        raise BenchError(f"sheet.schema must be {SHEET_SCHEMA!r}")
    if type(sheet["seq"]) is not int or sheet["seq"] < 1:
        raise BenchError("sheet.seq must be a positive integer")
    _date(sheet["issued_at"], "sheet.issued_at")
    _keys(sheet["firmware_pin"], ("bios_version", "bios_date"), "sheet.firmware_pin")
    _keys(sheet["expected_pcr7"], PATHS, "sheet.expected_pcr7")
    for label in PATHS:
        _hex64(sheet["expected_pcr7"][label], f"sheet.expected_pcr7.{label}")
    _hex64(sheet["reference_record_sha256"], "sheet.reference_record_sha256")
    _keys(sheet["signer"], ("pkfp", "algorithm"), "sheet.signer")
    _hex64(sheet["signer"]["pkfp"], "sheet.signer.pkfp")
    if sheet["signer"]["algorithm"] != "rsa-pkcs1-sha256":
        raise BenchError("sheet.signer.algorithm must be 'rsa-pkcs1-sha256'")


def sheet_payload(sheet):
    """What the Owner signs: a domain tag, then the canonical JSON. The tag stops a
    signature made for any other JSON document from validating a sheet."""
    return SHEET_DOMAIN + canonical(sheet)


def verify_sheet(sheet, signature, pubkey_pem, record, allow_synthetic=False):
    _validate_sheet(sheet)
    if pubkey_fingerprint(pubkey_pem) != sheet["signer"]["pkfp"]:
        raise BenchError("the sheet names a signer that is not the trusted key "
                         f"(sheet signer {sheet['signer']['pkfp'][:16]}…)")
    if not isinstance(signature, bytes) or not 0 < len(signature) <= 1024:
        raise BenchError("signature: missing or implausibly large")
    try:
        ok = policy.verify_detached_policy_signature(pubkey_pem, sheet_payload(sheet), signature)
    except policy.EventLogError as error:
        raise BenchError(str(error)) from error
    if not ok:
        raise BenchError("the sheet signature does not verify under the trusted key")
    validate_record(record, allow_synthetic=allow_synthetic)
    if sheet["reference_record_sha256"] != record_digest(record):
        raise BenchError("sheet.reference_record_sha256 is not the digest of this record")
    if sheet["family_id"] != record["family_id"]:
        raise BenchError("sheet.family_id is not the record's family_id")
    if sheet["firmware_pin"] != {k: record["firmware"][k] for k in ("bios_version", "bios_date")}:
        raise BenchError("sheet.firmware_pin differs from the record's firmware")
    if sheet["expected_pcr7"] != {label: record["paths"][label]["pcr7"] for label in PATHS}:
        raise BenchError("sheet.expected_pcr7 differs from the record's measured PCR 7")


# --- the pcr-reference/ store ------------------------------------------------

MEMBERS = ("reference-record.json", "bench-sheet.json", "bench-sheet.sig",
           "snapshots/installer.snapshot.json", "snapshots/installed.snapshot.json")


def _check_snapshots(record, snapshots, allow_synthetic):
    for label in PATHS:
        snap = (snapshots or {}).get(label)
        if snap is None:
            raise BenchError(f"the {label} snapshot is missing")
        validate_snapshot(snap)
        if snap["path"] != label:
            raise BenchError(f"the {label} snapshot was captured for path {snap['path']!r}")
        if snap["origin"] != "measured" and not allow_synthetic:
            raise BenchError(f"the {label} snapshot is {snap['origin']}, not measured")
        if _digest(snap) != record["provenance"]["snapshot_sha256"][label]:
            raise BenchError(f"the {label} snapshot is not the one the record was built from")


def _dump(obj):
    # Insertion order is kept on purpose: the variables of a pcr7_reference are in
    # LOG order and the fold depends on it. Digests use canonical(), which sorts.
    return (json.dumps(obj, indent=2) + "\n").encode()


def store(root, record, sheet, signature, snapshots, pubkey_pem, allow_synthetic=False):
    """Validate EVERYTHING, then publish one family directory. Nothing is written
    unless every check passes; a replacement needs a strictly higher sheet seq."""
    if not os.path.isdir(root) or os.path.islink(root):
        raise BenchError(f"store root {root} is not a directory")
    validate_record(record, allow_synthetic=allow_synthetic)
    verify_sheet(sheet, signature, pubkey_pem, record, allow_synthetic=allow_synthetic)
    _check_snapshots(record, snapshots, allow_synthetic)
    dest = os.path.join(root, record["family_id"])
    if os.path.lexists(dest):
        try:
            old = load_json_strict((pathlib.Path(dest) / "bench-sheet.json").read_text())
            old_seq = old["seq"]
        except (OSError, BenchError, KeyError) as error:
            raise BenchError(f"{dest} exists and its sheet is unreadable ({error}); "
                             "remove it deliberately") from error
        if type(old_seq) is not int or sheet["seq"] <= old_seq:
            raise BenchError(f"sheet seq {sheet['seq']} does not exceed the stored seq {old_seq}")
    staging = tempfile.mkdtemp(prefix=".staging-", dir=root)
    try:
        os.mkdir(os.path.join(staging, "snapshots"))
        files = {"reference-record.json": _dump(record), "bench-sheet.json": _dump(sheet),
                 "bench-sheet.sig": signature,
                 "snapshots/installer.snapshot.json": _dump(snapshots["installer"]),
                 "snapshots/installed.snapshot.json": _dump(snapshots["installed"])}
        for name, data in files.items():
            member = os.path.join(staging, name)
            with open(member, "wb") as handle:
                handle.write(data)
            os.chmod(member, 0o644)
        for directory in (staging, os.path.join(staging, "snapshots")):
            os.chmod(directory, 0o755)
        backup = None
        if os.path.lexists(dest):
            backup = tempfile.mkdtemp(prefix=".replaced-", dir=root)
            os.replace(dest, os.path.join(backup, "old"))
        os.replace(staging, dest)
        if backup:
            shutil.rmtree(backup, ignore_errors=True)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return dest


def _read_member(directory, name):
    path = pathlib.Path(directory) / name
    if path.is_symlink():
        raise BenchError(f"{path}: a symlink is not allowed in the store")
    try:
        return path.read_bytes()
    except OSError as error:
        raise BenchError(f"{path}: {error}") from error


def validate_store(root, pubkey_pem, allow_synthetic=False):
    """Re-validate a whole pcr-reference/ tree; returns the family ids it holds."""
    if not os.path.isdir(root):
        raise BenchError(f"{root} is not a directory")
    families, strays = [], []
    for entry in sorted(os.listdir(root)):
        full = os.path.join(root, entry)
        if os.path.islink(full):
            raise BenchError(f"{full}: a symlink is not allowed in the store")
        (families if os.path.isdir(full) else strays).append(entry)
    for entry in families:
        _validate_family(os.path.join(root, entry), entry, pubkey_pem, allow_synthetic)
    if strays:
        raise BenchError(f"unexpected file at the store root: {strays}")
    if not families:
        raise BenchError(f"{root}: the store is empty")
    return families


def _validate_family(directory, name, pubkey_pem, allow_synthetic):
    present = set()
    for current, dirs, files in os.walk(directory, followlinks=False):
        for entry in dirs + files:
            full = os.path.join(current, entry)
            if os.path.islink(full):
                raise BenchError(f"{full}: a symlink is not allowed in the store")
        for entry in files:
            present.add(os.path.relpath(os.path.join(current, entry), directory).replace(os.sep, "/"))
    unexpected = sorted(present - set(MEMBERS))
    if unexpected:
        raise BenchError(f"{name}: unexpected file {unexpected}")
    missing = [m for m in MEMBERS if m not in present]
    if missing:
        raise BenchError(f"{name}: missing {missing}")
    record = load_json_strict(_read_member(directory, "reference-record.json").decode())
    sheet = load_json_strict(_read_member(directory, "bench-sheet.json").decode())
    snapshots = {label: load_json_strict(_read_member(directory, f"snapshots/{label}.snapshot.json").decode())
                 for label in PATHS}
    validate_record(record, allow_synthetic=allow_synthetic)
    if record["family_id"] != name:
        raise BenchError(f"directory {name!r} holds the record of family {record['family_id']!r}")
    verify_sheet(sheet, _read_member(directory, "bench-sheet.sig"), pubkey_pem, record,
                 allow_synthetic=allow_synthetic)
    _check_snapshots(record, snapshots, allow_synthetic)


# --- command line ------------------------------------------------------------

def _load(path):
    return load_json_strict(_read_file(path, "file").decode("utf-8", "strict"))


def _write(path, data):
    target = pathlib.Path(path)
    tmp = target.with_name(f".{target.name}.tmp")
    tmp.write_bytes(data)
    os.replace(tmp, target)


def _dmi(name):
    try:
        return pathlib.Path(DMI_DIR, name).read_text().strip()
    except OSError as error:
        raise BenchError(f"cannot read {DMI_DIR}/{name} ({error}); pass --bios-{name.split('_')[1]}") from error


def _pcr7_text(args):
    if args.pcr7:
        return f"7 : 0x{args.pcr7}"
    if args.pcr7_file:
        return _read_file(args.pcr7_file, "PCR 7 file").decode("utf-8", "replace")
    try:
        done = subprocess.run(["tpm2_pcrread", "sha256:7"], capture_output=True, text=True, check=False)
    except OSError as error:
        raise BenchError(f"cannot run tpm2_pcrread ({error}); pass --pcr7 or --pcr7-file") from error
    if done.returncode != 0:
        raise BenchError(f"tpm2_pcrread failed: {done.stderr.strip()}")
    return done.stdout


def cmd_capture(args):
    snapshot = capture(
        args.path, efivars_b64=args.efivars_b64, efivars_dir=args.efivars_dir,
        eventlog=args.eventlog, pcr7_text=_pcr7_text(args),
        bios_version=args.bios_version if args.bios_version is not None else _dmi("bios_version"),
        bios_date=args.bios_date if args.bios_date is not None else _dmi("bios_date"),
        captured_at=args.captured_at, kernel=args.kernel or platform.release(),
        state_marker=args.state_marker)
    _write(args.out, _dump(snapshot))
    print(f"snapshot {args.path}: PCR 7 {snapshot['pcr7']['value']}, "
          f"firmware {snapshot['firmware']['bios_version']} -> {args.out}")


def cmd_build_record(args):
    record = build_record(_load(args.installer), _load(args.installed))
    validate_record(record, allow_synthetic=args.allow_synthetic)
    _write(args.out, _dump(record))
    print(f"record {record['family_id']} -> {args.out}")


def cmd_make_sheet(args):
    record = _load(args.record)
    validate_record(record, allow_synthetic=args.allow_synthetic)
    sheet = make_sheet(record, args.seq, args.issued_at, pubkey_fingerprint(args.pubkey))
    _write(args.out, _dump(sheet))
    print(f"unsigned sheet {sheet['family_id']} seq {sheet['seq']} -> {args.out}")


def cmd_sheet_payload(args):
    sheet = _load(args.sheet)
    _validate_sheet(sheet)
    _write(args.out, sheet_payload(sheet))
    print(f"payload to sign -> {args.out}")
    print(f"  openssl dgst -sha256 -sign <owner-key> -out bench-sheet.sig {args.out}")


def cmd_verify_sheet(args):
    verify_sheet(_load(args.sheet), _read_file(args.signature, "signature"), args.pubkey,
                 _load(args.record), allow_synthetic=args.allow_synthetic)
    print("sheet verifies under the trusted key and agrees with its record")


def cmd_store(args):
    dest = store(args.root, _load(args.record), _load(args.sheet),
                 _read_file(args.signature, "signature"),
                 {"installer": _load(args.installer_snapshot), "installed": _load(args.installed_snapshot)},
                 args.pubkey)
    print(f"stored -> {dest}")


def cmd_validate_store(args):
    families = validate_store(args.root, args.pubkey, allow_synthetic=args.allow_synthetic)
    for family in families:
        print(f"ok {family}")
    print("ni-pcr7-calc cross-check: " + ("active" if load_calc() else "absent (fold + reference rebuild only)"))


def cmd_validate_record(args):
    validate_record(_load(args.record), allow_synthetic=args.allow_synthetic)
    print("record ok")


def cmd_validate_snapshot(args):
    validate_snapshot(_load(args.snapshot))
    print("snapshot ok")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("capture", help="one boot path -> snapshot (read-only on the machine)")
    c.add_argument("--path", required=True, choices=PATHS)
    c.add_argument("--out", required=True)
    source = c.add_mutually_exclusive_group()
    source.add_argument("--efivars-dir", help=f"efivarfs directory (default {EFIVARS_DIR})")
    source.add_argument("--efivars-b64", help="`<name>-<guid> <base64>` per line (collection format)")
    c.add_argument("--eventlog", help=f"TCG2 event log (default {DEFAULT_EVENTLOG})")
    pcr = c.add_mutually_exclusive_group()
    pcr.add_argument("--pcr7", metavar="HEX")
    pcr.add_argument("--pcr7-file", help="tpm2_pcrread output (default: run tpm2_pcrread sha256:7)")
    c.add_argument("--bios-version", help=f"default {DMI_DIR}/bios_version")
    c.add_argument("--bios-date", help=f"default {DMI_DIR}/bios_date")
    c.add_argument("--captured-at")
    c.add_argument("--kernel")
    c.add_argument("--state-marker")
    c.set_defaults(fn=cmd_capture)

    b = sub.add_parser("build-record", help="installer + installed snapshots -> reference record")
    b.add_argument("--installer", required=True)
    b.add_argument("--installed", required=True)
    b.add_argument("--out", required=True)
    b.add_argument("--allow-synthetic", action="store_true", help="test fixtures only")
    b.set_defaults(fn=cmd_build_record)

    m = sub.add_parser("make-sheet", help="record -> unsigned bench sheet")
    m.add_argument("--record", required=True)
    m.add_argument("--seq", required=True, type=int)
    m.add_argument("--issued-at", required=True, metavar="YYYY-MM-DD")
    m.add_argument("--pubkey", required=True, help="the signer's public key (its pkfp is pinned in the sheet)")
    m.add_argument("--out", required=True)
    m.add_argument("--allow-synthetic", action="store_true", help="test fixtures only")
    m.set_defaults(fn=cmd_make_sheet)

    p = sub.add_parser("sheet-payload", help="the bytes the Owner signs")
    p.add_argument("sheet")
    p.add_argument("--out", required=True)
    p.set_defaults(fn=cmd_sheet_payload)

    v = sub.add_parser("verify-sheet", help="signature, signer and agreement with the record")
    v.add_argument("sheet")
    v.add_argument("signature")
    v.add_argument("--record", required=True)
    v.add_argument("--pubkey", required=True)
    v.add_argument("--allow-synthetic", action="store_true", help="test fixtures only")
    v.set_defaults(fn=cmd_verify_sheet)

    s = sub.add_parser("store", help="validate everything, then file under pcr-reference/<family>/")
    s.add_argument("--record", required=True)
    s.add_argument("--sheet", required=True)
    s.add_argument("--signature", required=True)
    s.add_argument("--installer-snapshot", required=True)
    s.add_argument("--installed-snapshot", required=True)
    s.add_argument("--root", required=True)
    s.add_argument("--pubkey", required=True)
    s.set_defaults(fn=cmd_store)

    vs = sub.add_parser("validate-store", help="re-validate a pcr-reference/ tree")
    vs.add_argument("root")
    vs.add_argument("--pubkey", required=True)
    vs.add_argument("--allow-synthetic", action="store_true", help="test fixtures only")
    vs.set_defaults(fn=cmd_validate_store)

    vr = sub.add_parser("validate-record")
    vr.add_argument("record")
    vr.add_argument("--allow-synthetic", action="store_true", help="test fixtures only")
    vr.set_defaults(fn=cmd_validate_record)

    vn = sub.add_parser("validate-snapshot")
    vn.add_argument("snapshot")
    vn.set_defaults(fn=cmd_validate_snapshot)

    args = parser.parse_args(argv)
    try:
        args.fn(args)
    except (BenchError, policy.EventLogError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
