#!/usr/bin/env python3
"""Offline PCR 7 (sha256 bank) calculator for a GB10 appliance boot.

    compute  REFERENCE.json   PCR 7 a boot WOULD produce, from a description
    replay   EVENTLOG         PCR 7 the firmware's own TCG2 log produces
    extract  EVENTLOG         the reference description a log implies
    verify   EVENTLOG         replay == live PCR 7  AND  compute(extract) == live
    filter-log EVENTLOG       the log reduced to one PCR (drops boot options,
                              device paths and GRUB command lines)

PCR 7 is the fold   pcr = H(pcr || H(event_data))   over three kinds of event:

  config     the Secure Boot variables, in log order (SecureBoot, PK, KEK, db,
             dbx): UEFI_VARIABLE_DATA{guid, name, data}
  separator  four zero bytes
  authority  one per certificate that VERIFIED something: the db certificate
             that verified the first image (shim, or the UKI), then -- on the
             shim path -- shim's SbatLevel and the vendor/MOK certificate that
             verified GRUB and the kernel

🔴 What `data` carries in a config event is a FIRMWARE property, not a given.
Measured on two GB10 firmware builds (NVIDIA 5.36_0ACUM018, ASUS GX10DGX.0104):
PK/KEK/db/dbx and SecureBoot are logged with a ZERO-length data, names only. On
that firmware a dbx append, a KEK rotation or a PK swap does NOT move PCR 7; the
authority events do. `firmware.variable_measurement` makes the assumption
explicit, and "contents" (what the TCG PC Client spec and EDK2 describe) is NOT
proven on any GB10.

The event-log parsing and the PCR replay are the ones the installer already
ships (ota/neural-ice-tpm-policy.py); they are imported, not copied.
"""

import argparse
import hashlib
import importlib.util
import json
import pathlib
import re
import struct
import subprocess
import sys
import uuid

_POLICY_TOOL = pathlib.Path(__file__).resolve().parents[2] / "ota" / "neural-ice-tpm-policy.py"
_spec = importlib.util.spec_from_file_location("ni_tpm_policy", _POLICY_TOOL)
policy = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(policy)

PCR = 7
BANK = "sha256"
SCHEMA = "ni-pcr7-reference/1"

GUID_GLOBAL = "8be4df61-93ca-11d2-aa0d-00e098032b8c"
GUID_SECURITY_DB = "d719b2cb-3d3a-4596-a3bc-dad00e67656f"
GUID_SHIM_LOCK = "605dab50-e046-4300-abb6-3dd810dd8b23"
CONFIG_GUID = {"SecureBoot": GUID_GLOBAL, "PK": GUID_GLOBAL, "KEK": GUID_GLOBAL,
               "db": GUID_SECURITY_DB, "dbx": GUID_SECURITY_DB,
               "dbt": GUID_SECURITY_DB, "dbr": GUID_SECURITY_DB}
MEASUREMENTS = ("names-only", "contents")
BOOT_PATHS = ("uki-direct", "shim-grub", "custom")
# The authority events each boot path logs, in order; a "custom" path is free.
BOOT_SHAPES = {"uki-direct": ("db",), "shim-grub": ("db", "SbatLevel", "MokListRT")}
ESL_SIG_TYPE_SHA256 = "c1c41626-504c-4092-aca9-41f936934328"


class Pcr7Error(RuntimeError):
    pass


class Event:
    def __init__(self, kind, name, data):
        self.kind, self.name, self.data = kind, name, data

    @property
    def digest(self):
        return hashlib.sha256(self.data).digest()


class Result:
    def __init__(self, events, measurement):
        self.events, self.measurement = events, measurement
        acc = b"\x00" * 32
        for event in events:
            acc = hashlib.sha256(acc + event.digest).digest()
        self.pcr7 = acc


def variable_data(guid, name, data):
    """UEFI_VARIABLE_DATA: VendorGuid, name length (chars), data length, name, data."""
    return (uuid.UUID(guid).bytes_le
            + struct.pack("<QQ", len(name), len(data))
            + name.encode("utf-16-le") + data)


def signature_data(owner, cert_der):
    """EFI_SIGNATURE_DATA of an X.509 entry: SignatureOwner then the DER."""
    return uuid.UUID(owner).bytes_le + cert_der


def esl_append(esl_hex, entry_hex, sig_type=ESL_SIG_TYPE_SHA256):
    """Append one EFI_SIGNATURE_LIST holding one fixed-size entry
    (owner GUID + data, e.g. an X509 hash) to an ESL given as hex."""
    entry = bytes.fromhex(entry_hex)
    sig_size = len(entry)
    esl = (uuid.UUID(sig_type).bytes_le
           + struct.pack("<III", 28 + sig_size, 0, sig_size) + entry)
    return esl_hex + esl.hex()


def _hex(value, where):
    try:
        return bytes.fromhex(value)
    except (TypeError, ValueError) as error:
        raise Pcr7Error(f"{where}: not a hex string") from error


def _guid(value, where):
    try:
        return str(uuid.UUID(value))
    except (TypeError, ValueError, AttributeError) as error:
        raise Pcr7Error(f"{where}: not a GUID") from error


def authority_payload(authority, where):
    """The measured variable data of one authority entry."""
    if "text" in authority:
        return authority["text"].encode("utf-8")
    if "cert_der_hex" in authority:
        return signature_data(_guid(authority.get("signature_owner"), f"{where}.signature_owner"),
                              _hex(authority["cert_der_hex"], f"{where}.cert_der_hex"))
    raise Pcr7Error(f"{where}: needs 'text' (SbatLevel) or 'cert_der_hex'")


def compute(reference, variable_measurement=None, append_esl=None):
    """PCR 7 a boot would produce. `append_esl` maps a variable name to hex
    appended to its ESL before measuring (what-if)."""
    if reference.get("schema") != SCHEMA:
        raise Pcr7Error(f"schema must be {SCHEMA!r}")
    if reference.get("bank", BANK) != BANK:
        raise Pcr7Error("only the sha256 bank is modelled")
    measurement = variable_measurement or reference.get("firmware", {}).get("variable_measurement")
    if measurement not in MEASUREMENTS:
        raise Pcr7Error(f"firmware.variable_measurement must be one of {MEASUREMENTS}")
    boot_path = reference.get("boot_path")
    if boot_path not in BOOT_PATHS:
        raise Pcr7Error(f"boot_path must be one of {BOOT_PATHS}")
    variables = reference.get("variables")
    if not isinstance(variables, dict) or not variables:
        raise Pcr7Error("variables: missing")

    events = []
    for name, entry in variables.items():
        guid = _guid(entry.get("guid", CONFIG_GUID.get(name)), f"variables.{name}.guid")
        if measurement == "contents":
            if "data_hex" not in entry:
                raise Pcr7Error(f"variables.{name}: 'contents' measurement needs data_hex "
                                "(the variable bytes; ESL for PK/KEK/db/dbx)")
            data_hex = entry["data_hex"] + (append_esl or {}).get(name, "")
            data = _hex(data_hex, f"variables.{name}.data_hex")
        else:
            data = b""
        events.append(Event("config", name, variable_data(guid, name, data)))
    unused = set(append_esl or {}) - set(variables)
    if unused:
        raise Pcr7Error(f"--append-esl names no variable of this reference: {sorted(unused)}")

    events.append(Event("separator", None, _hex(reference.get("separator_hex", "00000000"),
                                                "separator_hex")))

    authorities = reference.get("authorities")
    if not isinstance(authorities, list) or not authorities:
        raise Pcr7Error("authorities: missing")
    shape = BOOT_SHAPES.get(boot_path)
    if shape is not None and tuple(a.get("name") for a in authorities) != shape:
        raise Pcr7Error(f"boot_path {boot_path!r} logs the authority events {list(shape)}, "
                        f"this reference lists {[a.get('name') for a in authorities]}")
    for index, authority in enumerate(authorities):
        where = f"authorities[{index}]"
        name = authority.get("name")
        if not isinstance(name, str) or not name:
            raise Pcr7Error(f"{where}.name: missing")
        guid = _guid(authority.get("guid", GUID_SECURITY_DB if name == "db" else GUID_SHIM_LOCK),
                     f"{where}.guid")
        events.append(Event("authority", name, variable_data(
            guid, name, authority_payload(authority, where))))
    return Result(events, measurement)


# --- event log side ---------------------------------------------------------

def parse_pcr7(blob):
    events = [e for e in policy.parse_eventlog(blob) if e["pcr"] == PCR]
    if not events:
        raise Pcr7Error(f"no event addresses PCR {PCR}")
    return events


def replay_log(blob):
    """PCR 7 by extending every logged digest, in log order."""
    return policy.replay(policy.parse_eventlog(blob), PCR, BANK)[0]


def _split_variable(data):
    """(guid, name, variable data) of a UEFI_VARIABLE_DATA, or Pcr7Error."""
    if len(data) < 32:
        raise Pcr7Error("event data is shorter than a UEFI_VARIABLE_DATA header")
    name_len, data_len = struct.unpack_from("<QQ", data, 16)
    end = 32 + name_len * 2
    if end + data_len != len(data):
        raise Pcr7Error("UEFI_VARIABLE_DATA lengths do not add up to the event data")
    return (str(uuid.UUID(bytes_le=data[:16])),
            data[32:end].decode("utf-16-le"), data[end:])


def extract_reference(blob):
    """The reference description a log implies. Refuses a log the description
    could not reproduce: an unknown layout or a digest that is not H(data)."""
    events = parse_pcr7(blob)
    variables, authorities, separator = {}, [], None
    for index, ev in enumerate(events):
        where = f"PCR {PCR} event {index + 1}"
        if ev["digests"].get(BANK) != hashlib.sha256(ev["data"]).digest():
            raise Pcr7Error(f"{where}: the logged digest is not sha256 of the event data; "
                            "a reference cannot reproduce it")
        if ev["type"] == policy.EV_EFI_VARIABLE_DRIVER_CONFIG:
            if separator is not None:
                raise Pcr7Error(f"{where}: a config event after the separator is not modelled")
            guid, name, data = _split_variable(ev["data"])
            if name in variables:
                raise Pcr7Error(f"{where}: variable {name} measured twice")
            variables[name] = {"guid": guid, "data": data}
        elif ev["type"] == policy.EV_SEPARATOR:
            if separator is not None:
                raise Pcr7Error(f"{where}: second separator")
            separator = ev["data"]
        elif ev["type"] == policy.EV_EFI_VARIABLE_AUTHORITY:
            if separator is None:
                raise Pcr7Error(f"{where}: an authority event before the separator "
                                "(option ROM?) is not modelled")
            authorities.append(_authority_entry(ev["data"], where))
        else:
            raise Pcr7Error(f"{where}: event type 0x{ev['type']:08x} is not modelled")
    if separator is None or not variables or not authorities:
        raise Pcr7Error("the log lacks config events, a separator or authority events")

    measured = [bool(v["data"]) for v in variables.values()]
    if not any(measured):
        measurement = "names-only"
    elif all(measured):
        measurement = "contents"
    else:
        raise Pcr7Error("some variables are measured with data and some without; "
                        "this firmware behaviour is not modelled")
    names = tuple(a["name"] for a in authorities)
    boot_path = next((k for k, v in BOOT_SHAPES.items() if names == v), "custom")
    reference = {
        "schema": SCHEMA, "bank": BANK,
        "firmware": {"variable_measurement": measurement},
        "variables": {},
        "separator_hex": separator.hex(),
        "boot_path": boot_path,
        "authorities": authorities,
    }
    for name, v in variables.items():
        entry = {"guid": v["guid"]}
        if measurement == "contents":
            entry["data_hex"] = v["data"].hex()
        reference["variables"][name] = entry
    # Proof the description is lossless: it must rebuild the very digests logged.
    rebuilt = [e.digest for e in compute(reference).events]
    if rebuilt != [e["digests"][BANK] for e in events]:
        raise Pcr7Error("internal: the extracted reference does not rebuild the log")
    return reference


def _authority_entry(data, where):
    guid, name, payload = _split_variable(data)
    entry = {"name": name, "guid": guid}
    if name == "SbatLevel":
        try:
            entry["text"] = payload.decode("utf-8")
        except UnicodeDecodeError as error:
            raise Pcr7Error(f"{where}: SbatLevel is not UTF-8") from error
    else:
        if len(payload) <= 16:
            raise Pcr7Error(f"{where}: authority {name} holds no certificate")
        entry["signature_owner"] = str(uuid.UUID(bytes_le=payload[:16]))
        entry["cert_der_hex"] = payload[16:].hex()
    return entry


def filter_log(blob, pcr):
    """The log's header plus only the events of one PCR, byte-identical."""
    header_len = 32 + struct.unpack_from("<I", blob, 28)[0]
    ids = {name: alg for alg, (name, _) in policy.ALGS.items()}
    out = bytearray(blob[:header_len])
    for ev in policy.parse_eventlog(blob):
        if ev["pcr"] != pcr:
            continue
        out += struct.pack("<III", ev["pcr"], ev["type"], len(ev["digests"]))
        for name, digest in ev["digests"].items():
            out += struct.pack("<H", ids[name]) + digest
        out += struct.pack("<I", len(ev["data"])) + ev["data"]
    return bytes(out)


def live_pcr7():
    """The TPM's PCR 7: tpm2_pcrread, else the kernel's sysfs mirror."""
    try:
        return policy.live_pcr(PCR, BANK)
    except policy.EventLogError as first:
        try:
            text = pathlib.Path(f"/sys/class/tpm/tpm0/pcr-{BANK}/{PCR}").read_text().strip()
            if re.fullmatch(r"[0-9A-Fa-f]{64}", text):
                return bytes.fromhex(text)
        except OSError:
            pass
        raise Pcr7Error(f"cannot read the live PCR {PCR}: {first}") from first


# --- command line -----------------------------------------------------------

def _expected(args):
    if args.expect and args.live:
        raise Pcr7Error("give --expect or --live, not both")
    if args.live:
        return live_pcr7()
    if args.expect:
        value = _hex(args.expect, "--expect")
        if len(value) != 32:
            raise Pcr7Error("--expect must be 64 hex characters")
        return value
    return None


def _explain(result):
    for i, e in enumerate(result.events, 1):
        label = e.kind if e.name is None else f"{e.kind}:{e.name}"
        print(f"  {i:2d}  {label:<22s} {e.digest.hex()}")


def cmd_compute(args):
    reference = json.loads(pathlib.Path(args.reference).read_text())
    append = {}
    for item in args.append_esl or []:
        name, _, value = item.partition("=")
        append[name] = value
    result = compute(reference, args.variable_measurement, append)
    if append and result.measurement == "names-only":
        print("note: this firmware measures variable NAMES only; --append-esl cannot "
              "move PCR 7 (see 'What the GB10 firmware actually measures')", file=sys.stderr)
    print(result.pcr7.hex())
    if args.explain:
        _explain(result)
    if args.policy_digest:
        print(policy.pcr_policy_digest(PCR, result.pcr7, BANK).hex(), "PolicyPCR digest")
    return 0


def cmd_replay(args):
    blob = pathlib.Path(args.eventlog).read_bytes()
    value = replay_log(blob)
    print(value.hex())
    if args.explain:
        for i, ev in enumerate(parse_pcr7(blob), 1):
            print(f"  {i:2d}  0x{ev['type']:08x} {policy.variable_name(ev) or '':<12s} "
                  f"{ev['digests'][BANK].hex()}")
    expected = _expected(args)
    if expected is not None and expected != value:
        print(f"🔴 replay {value.hex()} is NOT the expected {expected.hex()}", file=sys.stderr)
        return 1
    return 0


def cmd_extract(args):
    reference = extract_reference(pathlib.Path(args.eventlog).read_bytes())
    text = json.dumps(reference, indent=2) + "\n"
    if args.out:
        pathlib.Path(args.out).write_text(text)
    else:
        sys.stdout.write(text)
    return 0


def cmd_verify(args):
    blob = pathlib.Path(args.eventlog).read_bytes()
    expected = _expected(args)
    if expected is None:
        raise Pcr7Error("verify needs --expect HEX or --live")
    replayed = replay_log(blob)
    reference = extract_reference(blob)
    computed = compute(reference).pcr7
    print(f"  expected (live) : {expected.hex()}")
    print(f"  replay(log)     : {replayed.hex()}")
    print(f"  compute(extract): {computed.hex()}")
    print(f"  boot path {reference['boot_path']}, variable measurement "
          f"{reference['firmware']['variable_measurement']}")
    if replayed != expected or computed != expected:
        print("🔴 the calculator does NOT reproduce the live PCR 7 of this log",
              file=sys.stderr)
        return 1
    print("✅ replay(log) == compute(extract(log)) == live PCR 7")
    return 0


def cmd_filter_log(args):
    out = filter_log(pathlib.Path(args.eventlog).read_bytes(), args.pcr)
    pathlib.Path(args.out).write_bytes(out)
    print(f"wrote {args.out}: {len(out)} bytes, PCR {args.pcr} events only")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("compute", help="PCR 7 from a reference description")
    c.add_argument("reference")
    c.add_argument("--explain", action="store_true")
    c.add_argument("--policy-digest", action="store_true",
                   help="also print the PolicyPCR digest the Owner would sign")
    c.add_argument("--variable-measurement", choices=MEASUREMENTS,
                   help="override the firmware assumption of the reference")
    c.add_argument("--append-esl", action="append", metavar="VAR=HEX",
                   help="what-if: append an ESL to a variable before measuring it")
    for name, helptext in (("replay", "PCR 7 from a TCG2 event log"),
                           ("verify", "replay == compute(extract) == expected")):
        p = sub.add_parser(name, help=helptext)
        p.add_argument("eventlog")
        p.add_argument("--expect", metavar="HEX")
        p.add_argument("--live", action="store_true", help="expect the TPM's live PCR 7")
        if name == "replay":
            p.add_argument("--explain", action="store_true")
    e = sub.add_parser("extract", help="reference description from an event log")
    e.add_argument("eventlog")
    e.add_argument("--out")
    f = sub.add_parser("filter-log", help="keep one PCR's events (redacts the rest)")
    f.add_argument("eventlog")
    f.add_argument("--out", required=True)
    f.add_argument("--pcr", type=int, default=PCR)
    args = parser.parse_args(argv)
    try:
        return {"compute": cmd_compute, "replay": cmd_replay, "extract": cmd_extract,
                "verify": cmd_verify, "filter-log": cmd_filter_log}[args.cmd](args)
    except (Pcr7Error, policy.EventLogError, OSError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    except (KeyError, TypeError, AttributeError, ValueError) as error:
        print(f"error: malformed input ({type(error).__name__}: {error})", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
