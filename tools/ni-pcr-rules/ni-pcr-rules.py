#!/usr/bin/env python3
"""PCR 7 rules engine: Owner-signed rules, evaluated on the machine's Secure Boot state.

    sign      RULES --key PEM --out SIG      what the Owner runs, offline
    verify    RULES SIG                      signature, schema, anti-rollback
    evaluate  RULES SIG + the machine state  accept or refuse, with every check
    ids       the machine state              the ids an Owner writes rules from

The rules are a small signed document (`ni-pcr-rules/1`): the certificates `db` may
hold (C), the revocations `dbx` must hold at least (F: the floor), the boot-path
authorities PCR 7 may log (A), and a sequence number. Nothing in it names a machine
or a PCR value, so one signature covers every unit of a firmware family.

What PCR 7 does and does not prove. The engine first demands

    replay(firmware event log) == live PCR 7          <-- the log is the one PCR 7 saw
    sha256(event data) == the logged digest           <-- the data read is what was extended

so the event log is genuine. That says what the firmware MEASURED, nothing more: on a
GB10 it measures SecureBoot, PK, KEK, db and dbx with zero-length data (PR #245), so PCR 7
does not vouch for their contents. The engine then reads the variables directly from
efivars and binds each to what the firmware measured, when it measured anything:

  * a variable the log carries WITH its bytes must equal the EFI variable: a variable
    edited after boot is refused ("attested");
  * a variable the log carries by NAME ONLY (zero-length data, an empty variable
    included) cannot be checked against PCR 7 and is "observed". That is what the GB10
    firmware does for SecureBoot, PK, KEK, db and dbx (ASUS GX10DGX.0104, NVIDIA
    5.36_0ACUM018). The rules choose whether that is acceptable (`unbound_variables`);
    the verdict lists the checks that were only observed (`observed`). On such firmware
    the attested evidence is the authority chain: the certificates that verified the
    boot path.

Observed variables are trusted for a reason that is NOT the TPM: the installer is a
signed UKI running under enforced Secure Boot, an authenticated write to PK/KEK/db/dbx
needs a PK/KEK signature, setup and audit mode are refused, and the firmware setup is
behind the per-device UEFI administrator password. PK and KEK are constrained to the
sets the rules approve. The residual attacks (physical SPI write, firmware bugs) are out
of scope: see the README, "Threat model of the directly read EFI variables".

Callers decide on the verdict's `binding` and `observed`, never on `accepted` alone.

The signature is domain-separated: it covers `neural-ice-pcr-rules/v1\\0 || RULES`
(the exact bytes), so a signature this key made for anything else (a PolicyPCR digest,
a manifest) can never authorise rules, nor the other way round. The installer must
evaluate the very bytes it verified: `load_rules` takes bytes, not a path.

The TCG2 parser and the PCR replay are the installer's (ota/neural-ice-tpm-policy.py),
imported, not copied. Python 3 standard library and the `openssl` binary only.
"""

import argparse
import base64
import binascii
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import struct
import subprocess
import sys
import tempfile
import uuid

_POLICY_TOOL = pathlib.Path(__file__).resolve().parents[2] / "ota" / "neural-ice-tpm-policy.py"
_spec = importlib.util.spec_from_file_location("ni_tpm_policy", _POLICY_TOOL)
policy = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(policy)

PCR = 7
BANK = "sha256"
SCHEMA = "ni-pcr-rules/1"
DOMAIN = b"neural-ice-pcr-rules/v1\x00"
MAX_RULES_BYTES = 1 << 20
MAX_VARIABLE_BYTES = 4 << 20
DEFAULT_EVENTLOG = policy.DEFAULT_EVENTLOG
DEFAULT_EFIVARS = "/sys/firmware/efi/efivars"
# A fixed location first, so a PATH an attacker controls cannot swap the verifier.
OPENSSL = next((p for p in ("/usr/bin/openssl", "/bin/openssl") if os.access(p, os.X_OK)), "openssl")

GUID_GLOBAL = "8be4df61-93ca-11d2-aa0d-00e098032b8c"
GUID_SECURITY_DB = "d719b2cb-3d3a-4596-a3bc-dad00e67656f"
VARIABLES = (("SecureBoot", GUID_GLOBAL), ("PK", GUID_GLOBAL), ("KEK", GUID_GLOBAL),
             ("db", GUID_SECURITY_DB), ("dbx", GUID_SECURITY_DB))
SHIM_GUID = "605dab50-e046-4300-abb6-3dd810dd8b23"
# The vendor GUID an authority event of this name carries. A `db` event under another GUID
# is not the Secure Boot database verifying an image.
AUTHORITY_GUIDS = {"db": GUID_SECURITY_DB, "SbatLevel": SHIM_GUID, "MokListRT": SHIM_GUID}
GUID_X509 = "a5c059a1-94e4-4aa7-87b5-ab155c2bf072"
GUID_SHA256 = "c1c41626-504c-4092-aca9-41f936934328"
GUID_X509_SHA256 = "3bd2a492-96c0-4079-b420-fcf98ef103ed"

ID_RE = re.compile(r"(x509|sha256|x509-tbs-sha256|text-sha256):[0-9a-f]{64}")
CERT_ID_RE = re.compile(r"(x509|sha256):[0-9a-f]{64}")
DBX_ID_RE = re.compile(r"(sha256|x509-tbs-sha256):[0-9a-f]{64}")
HEX64_RE = re.compile(r"[0-9a-f]{64}")


class RulesError(RuntimeError):
    """The rules cannot be trusted. `check` names the verdict line that fails."""

    def __init__(self, check, message):
        super().__init__(message)
        self.check = check


class StateError(RuntimeError):
    """The machine state cannot be read or understood: refuse, never guess."""


# --- the signed rules -------------------------------------------------------

def _no_duplicates(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate key {key!r}")
        out[key] = value
    return out


def _reject_constant(name):
    raise ValueError(f"{name} is not valid JSON")


def _id_list(value, field, pattern):
    if (not isinstance(value, list) or not value
            or any(not isinstance(i, str) or not pattern.fullmatch(i) for i in value)
            or len(set(value)) != len(value)):
        raise RulesError("rules-schema", f"rules schema: {field} must be a non-empty list of "
                                         f"unique ids matching {pattern.pattern}")
    return value


def parse_rules(raw):
    """The validated rules inside `raw` (already verified). Strict: unknown fields,
    duplicate keys and empty sets are refused, so a typo cannot widen or void a rule."""
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicates,
                              parse_constant=_reject_constant)
    except (UnicodeDecodeError, ValueError) as error:
        raise RulesError("rules-schema", f"rules schema: not strict JSON ({error})") from error
    allowed = {"schema", "sequence", "unbound_variables", "approved_certs", "approved_pk",
               "approved_kek", "dbx_floor", "authorities", "note"}
    if not isinstance(document, dict) or set(document) - allowed:
        raise RulesError("rules-schema", "rules schema: expected an object with only "
                                         f"{sorted(allowed)}")
    if document.get("schema") != SCHEMA:
        raise RulesError("rules-schema", f"rules schema: schema must be {SCHEMA!r}")
    sequence = document.get("sequence")
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1:
        raise RulesError("rules-schema", "rules schema: sequence must be an integer >= 1")
    if document.get("unbound_variables") not in ("allow", "refuse"):
        raise RulesError("rules-schema", "rules schema: unbound_variables must be "
                                         "'allow' or 'refuse'")
    note = document.get("note", "")
    if not isinstance(note, str) or len(note) > 200:
        raise RulesError("rules-schema", "rules schema: note must be a string of 200 characters")
    approved = _id_list(document.get("approved_certs"), "approved_certs", CERT_ID_RE)
    approved_pk = _id_list(document.get("approved_pk"), "approved_pk", CERT_ID_RE)
    approved_kek = _id_list(document.get("approved_kek"), "approved_kek", CERT_ID_RE)
    floor = _id_list(document.get("dbx_floor"), "dbx_floor", DBX_ID_RE)
    authorities = document.get("authorities")
    if not isinstance(authorities, list) or not authorities:
        raise RulesError("rules-schema", "rules schema: authorities must be a non-empty list")
    by_name = {}
    for entry in authorities:
        if (not isinstance(entry, dict) or set(entry) != {"name", "ids"}
                or not isinstance(entry["name"], str) or not entry["name"]
                or entry["name"] in by_name):
            raise RulesError("rules-schema", "rules schema: each authority is a unique "
                                             "{name, ids} object")
        by_name[entry["name"]] = frozenset(_id_list(entry["ids"], f"authorities.{entry['name']}",
                                                    ID_RE))
    return {"sequence": sequence, "unbound": document["unbound_variables"],
            "approved": frozenset(approved),
            "approved_pk": frozenset(approved_pk), "approved_kek": frozenset(approved_kek),
            "floor": frozenset(floor), "authorities": by_name}


def _openssl(args, data):
    try:
        return subprocess.run([OPENSSL, *args], input=data, capture_output=True, check=False)
    except OSError as error:
        raise RulesError("rules-signature", f"cannot execute openssl: {error}") from error


def sign_rules(raw, key_path):
    """base64 of the signature the Owner's key makes over DOMAIN || raw."""
    result = _openssl(["dgst", "-sha256", "-sign", str(key_path)], DOMAIN + raw)
    if result.returncode != 0:
        raise RulesError("rules-signature", "openssl could not sign with this key")
    return base64.b64encode(result.stdout).decode("ascii") + "\n"


def _read_pubkey(pubkey_path):
    """The public key bytes, read ONCE: the bytes that are pinned are the bytes that verify."""
    try:
        with open(pubkey_path, "rb") as handle:
            data = handle.read(MAX_RULES_BYTES + 1)
    except OSError as error:
        raise RulesError("rules-signature", f"the public key cannot be read: {error}") from error
    if not data or len(data) > MAX_RULES_BYTES:
        raise RulesError("rules-signature", "the public key cannot be read")
    return data


def spki_sha256(pubkey_pem):
    result = _openssl(["pkey", "-pubin", "-outform", "DER"], pubkey_pem)
    if result.returncode != 0 or not result.stdout:
        raise RulesError("rules-signature", "the public key cannot be read")
    return hashlib.sha256(result.stdout).hexdigest()


def load_rules(raw, signature_text, pubkey_path, min_sequence, pubkey_sha256,
               expect_rules_sha256=None):
    """Verify THEN parse the same bytes. Returns (rules, sha256 hex of the bytes).

    Order matters: nothing in `raw` is interpreted before its signature verifies. The key
    pin is mandatory, and so is a sequence floor >= 1 (0 would switch anti-rollback off)."""
    if len(raw) > MAX_RULES_BYTES:
        raise RulesError("rules-schema", f"rules schema: more than {MAX_RULES_BYTES} bytes")
    if isinstance(min_sequence, bool) or not isinstance(min_sequence, int) or min_sequence < 1:
        raise RulesError("rules-sequence", "rollback: the sequence floor must be an integer >= 1, "
                                           "0 would accept any rules")
    if not isinstance(pubkey_sha256, str) or not HEX64_RE.fullmatch(pubkey_sha256):
        raise RulesError("rules-signature", "signature: the key pin must be 64 hex characters")
    pubkey_pem = _read_pubkey(pubkey_path)
    if spki_sha256(pubkey_pem) != pubkey_sha256:
        raise RulesError("rules-signature", "signature: the public key is not the pinned one")
    try:
        signature = base64.b64decode(signature_text.strip(), validate=True)
    except (binascii.Error, ValueError) as error:
        raise RulesError("rules-signature", "signature: not base64") from error
    if not signature or len(signature) > 1024:
        raise RulesError("rules-signature", "signature: empty or oversized")
    with tempfile.TemporaryDirectory(prefix="ni-pcr-rules-sig.") as scratch:
        sig_file, key_file = pathlib.Path(scratch) / "sig", pathlib.Path(scratch) / "key.pem"
        sig_file.write_bytes(signature)
        key_file.write_bytes(pubkey_pem)
        result = _openssl(["dgst", "-sha256", "-verify", str(key_file), "-signature",
                           str(sig_file)], DOMAIN + raw)
    if result.returncode != 0:
        raise RulesError("rules-signature", "signature: does not verify over the rules "
                                            "under the pcr-rules domain")
    digest = hashlib.sha256(raw).hexdigest()
    rules = parse_rules(raw)
    if rules["sequence"] < min_sequence:
        raise RulesError("rules-sequence", f"rollback: rules sequence {rules['sequence']} is below "
                                           f"the accepted {min_sequence}")
    if expect_rules_sha256 is not None and expect_rules_sha256 != digest:
        raise RulesError("rules-digest", "rules digest: the signed bytes are not the ones the "
                                         "release manifest binds")
    return rules, digest


# --- EFI state --------------------------------------------------------------

def parse_esl(body):
    """[(signature type GUID, owner GUID, data)] of an EFI_SIGNATURE_LIST sequence."""
    out, off = [], 0
    while off < len(body):
        if off + 28 > len(body):
            raise StateError("truncated EFI_SIGNATURE_LIST header")
        sig_type = str(uuid.UUID(bytes_le=body[off:off + 16]))
        list_size, header_size, sig_size = struct.unpack_from("<III", body, off + 16)
        end = off + list_size
        if (list_size < 28 + header_size or end > len(body) or sig_size < 16
                or (list_size - 28 - header_size) % sig_size):
            raise StateError("malformed EFI_SIGNATURE_LIST sizes")
        pos = off + 28 + header_size
        while pos < end:
            out.append((sig_type, str(uuid.UUID(bytes_le=body[pos:pos + 16])),
                        body[pos + 16:pos + sig_size]))
            pos += sig_size
        off = end
    return out


def entry_id(sig_type, data):
    """The identity an ESL entry has in the rules. The owner GUID is metadata, not trust."""
    if sig_type == GUID_X509:
        return "x509:" + hashlib.sha256(data).hexdigest()
    if sig_type == GUID_SHA256 and len(data) == 32:
        return "sha256:" + data.hex()
    if sig_type == GUID_X509_SHA256 and len(data) >= 32:
        return "x509-tbs-sha256:" + data[:32].hex()
    return f"other:{sig_type}:{hashlib.sha256(data).hexdigest()}"


def esl_ids(body):
    return [entry_id(sig_type, data) for sig_type, _, data in parse_esl(body)]


def read_efivar(directory, name, guid):
    """The variable's bytes without its 4 attribute bytes, or None if it does not exist."""
    path = pathlib.Path(directory) / f"{name}-{guid}"
    if path.is_symlink():
        raise StateError(f"{path.name} is a symbolic link")
    try:
        with open(path, "rb") as handle:
            raw = handle.read(MAX_VARIABLE_BYTES + 1)
    except FileNotFoundError:
        return None
    except OSError as error:
        raise StateError(f"cannot read {path.name}: {error}") from error
    if len(raw) > MAX_VARIABLE_BYTES or len(raw) < 4:
        raise StateError(f"{path.name} has an impossible size")
    return raw[4:]


def read_state(efivars_dir):
    if not pathlib.Path(efivars_dir).is_dir():
        raise StateError(f"{efivars_dir} is not a directory")
    state = {name: read_efivar(efivars_dir, name, guid) for name, guid in VARIABLES}
    state["SetupMode"] = read_efivar(efivars_dir, "SetupMode", GUID_GLOBAL)
    state["AuditMode"] = read_efivar(efivars_dir, "AuditMode", GUID_GLOBAL)
    return state


# --- the event log ----------------------------------------------------------

def split_variable(data):
    """(guid, name, variable data) of a UEFI_VARIABLE_DATA."""
    if len(data) < 32:
        raise StateError("event data is shorter than a UEFI_VARIABLE_DATA header")
    name_len, data_len = struct.unpack_from("<QQ", data, 16)
    end = 32 + name_len * 2
    if end + data_len != len(data):
        raise StateError("UEFI_VARIABLE_DATA lengths do not add up to the event data")
    try:
        name = data[32:end].decode("utf-16-le")
    except UnicodeDecodeError as error:
        raise StateError("variable name is not UTF-16") from error
    return str(uuid.UUID(bytes_le=data[:16])), name, data[end:]


def authority_id(name, payload):
    if name == "SbatLevel":
        return "text-sha256:" + hashlib.sha256(payload).hexdigest()
    if len(payload) <= 16:
        raise StateError(f"authority {name} holds no certificate")
    return entry_id(GUID_SHA256 if len(payload) == 48 else GUID_X509, payload[16:])


def read_log(blob):
    """(events of PCR 7, config {name: (guid, data)}, authorities [(name, id, guid)])."""
    events = [e for e in policy.parse_eventlog(blob) if e["pcr"] == PCR]
    config, authorities = {}, []
    for ev in events:
        if ev["type"] == policy.EV_SEPARATOR:
            continue
        if ev["type"] == policy.EV_EFI_VARIABLE_DRIVER_CONFIG:
            guid, name, data = split_variable(ev["data"])
            if name in config:
                raise StateError(f"variable {name} measured twice")
            config[name] = (guid, data)
        elif ev["type"] == policy.EV_EFI_VARIABLE_AUTHORITY:
            guid, name, payload = split_variable(ev["data"])
            authorities.append((name, authority_id(name, payload), guid))
        else:
            raise StateError(f"event type 0x{ev['type']:08x} in PCR {PCR} is not modelled")
    return events, config, authorities


# --- evaluation -------------------------------------------------------------

class Verdict:
    def __init__(self):
        self.checks = []

    def add(self, name, ok, detail="", binding="attested"):
        self.checks.append({"name": name, "ok": bool(ok), "binding": binding, "detail": detail})
        return ok

    @property
    def accepted(self):
        return bool(self.checks) and all(c["ok"] for c in self.checks)


def _first(items, limit=3):
    items = sorted(items)
    return ", ".join(items[:limit]) + (f" (+{len(items) - limit})" if len(items) > limit else "")


def evaluate_state(rules, blob, state, live_pcr7, verdict):
    """Run every check, appending to `verdict`. Returns the binding level."""
    events, config, authorities = read_log(blob)

    replayed, _ = policy.replay(events, PCR, BANK)
    if not verdict.add("replay-equals-live", replayed == live_pcr7,
                       f"replay {replayed.hex()}, live {live_pcr7.hex()}"):
        return None
    bad = [i for i, ev in enumerate(events, 1)
           if ev["digests"].get(BANK) != hashlib.sha256(ev["data"]).digest()]
    if not verdict.add("log-digests-attest-data", not bad,
                       f"PCR {PCR} event(s) {bad} carry data that was not what was extended"):
        return None

    # Bind each variable to what the firmware measured.
    attested, unbound, contradicted = {}, [], []
    for name, guid in VARIABLES:
        logged = config.get(name)
        actual = state[name] or b""
        if logged is None or logged[0] != guid:
            contradicted.append(f"{name}: no config event in the log")
        elif not logged[1]:
            unbound.append(name)       # the log names it without its bytes: nothing to compare
        elif logged[1] == actual:
            attested[name] = True
        else:
            contradicted.append(f"{name}: differs from what the firmware measured")
    verdict.add("variables-bound", not contradicted, "; ".join(contradicted))
    ok_unbound = not unbound or rules["unbound"] == "allow"
    verdict.add("unbound-variables", ok_unbound,
                ("PCR 7 carries only the NAMES of " + ", ".join(unbound) + "; their contents "
                 "are observed, not attested") if unbound else "",
                "observed" if unbound else "attested")

    def binding(name):
        return "attested" if attested.get(name) else "observed"

    try:
        secure_boot = state["SecureBoot"] == b"\x01"
        db_events = sum(n == "db" and g == AUTHORITY_GUIDS["db"] for n, _, g in authorities)
        verdict.add("secure-boot", secure_boot and db_events > 0,
                    f"SecureBoot={state['SecureBoot']!r}, db authority events: {db_events}",
                    binding("SecureBoot"))
        pk = esl_ids(state["PK"]) if state["PK"] else []
        verdict.add("pk-present", bool(pk), f"{len(pk)} platform key(s)", binding("PK"))
        bad_pk = set(pk) - rules["approved_pk"]
        verdict.add("pk-approved", bool(pk) and not bad_pk,
                    f"not approved: {_first(bad_pk)}" if bad_pk else f"{len(pk)} platform key(s)",
                    binding("PK"))
        kek = esl_ids(state["KEK"]) if state["KEK"] else []
        bad_kek = set(kek) - rules["approved_kek"]
        verdict.add("kek-approved", bool(kek) and not bad_kek,
                    f"not approved: {_first(bad_kek)}" if bad_kek else f"{len(kek)} key(s)",
                    binding("KEK"))
        # SetupMode is mandatory in UEFI >= 2.3.1: its absence is not "not in setup mode".
        # AuditMode is absent on some firmware; when present it must be 0.
        setup_clear = (bool(pk) and state["SetupMode"] == b"\x00"
                       and state["AuditMode"] in (None, b"\x00"))
        verdict.add("setup-mode", setup_clear,
                    f"PK entries {len(pk)}, SetupMode={state['SetupMode']!r}, "
                    f"AuditMode={state['AuditMode']!r}", "observed")
        db = esl_ids(state["db"]) if state["db"] else []
        outside = set(db) - rules["approved"]
        verdict.add("db-subset-of-approved", not outside and bool(db),
                    f"not approved: {_first(outside)}" if outside else f"{len(db)} entries",
                    binding("db"))
        dbx = set(esl_ids(state["dbx"])) if state["dbx"] else set()
        missing = rules["floor"] - dbx
        verdict.add("dbx-superset-of-floor", not missing,
                    f"missing from dbx: {_first(missing)}" if missing
                    else f"{len(rules['floor'])} floor entries present", binding("dbx"))
    except StateError as error:
        verdict.add("variables-parse", False, str(error))
        return None

    rejected = [f"{n}={i[:24]}…" for n, i, _ in authorities
                if i not in rules["authorities"].get(n, ())]
    wrong_guid = [f"{n} under {g}" for n, _, g in authorities if AUTHORITY_GUIDS.get(n, g) != g]
    if wrong_guid:
        rejected += wrong_guid
    verdict.add("authorities-approved", not rejected,
                f"not approved: {_first(rejected)}" if rejected
                else f"{len(authorities)} authority events", "attested")
    foreign = [i[:24] + "…" for n, i, _ in authorities if n == "db" and i not in set(db)]
    verdict.add("authority-in-db", not foreign,
                f"verified by a certificate absent from db: {_first(foreign)}" if foreign else "",
                binding("db"))
    return "contents" if not unbound else "names-only"


def evaluate(raw, signature_text, pubkey, min_sequence, blob, efivars_dir, live_pcr7,
             pubkey_sha256, expect_rules_sha256=None):
    """The verdict dict. Never raises: anything unreadable is a refused check."""
    verdict = Verdict()
    out = {"accepted": False, "binding": None, "observed": [], "rules_sha256": None,
           "sequence": None, "checks": verdict.checks}
    try:
        rules, digest = load_rules(raw, signature_text, pubkey, min_sequence, pubkey_sha256,
                                   expect_rules_sha256)
    except RulesError as error:
        verdict.add(error.check, False, str(error))
        return out
    out["rules_sha256"], out["sequence"] = digest, rules["sequence"]
    verdict.add("rules-signature", True, "verified under the pcr-rules domain")
    verdict.add("rules-sequence", True, f"{rules['sequence']} >= {min_sequence}")
    try:
        out["binding"] = evaluate_state(rules, blob, read_state(efivars_dir), live_pcr7, verdict)
    except (StateError, policy.EventLogError) as error:
        verdict.add("inputs", False, str(error))
    out["observed"] = [c["name"] for c in verdict.checks if c["binding"] == "observed"]
    out["accepted"] = verdict.accepted
    return out


# --- command line -----------------------------------------------------------

def _read(path, limit=MAX_RULES_BYTES * 8):
    with open(path, "rb") as handle:
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise OSError(f"{path} is larger than {limit} bytes")
    return data


def _pcr7(args):
    if args.live:
        return policy.live_pcr(PCR, BANK)
    if not HEX64_RE.fullmatch(args.pcr7.lower()):
        raise StateError("--pcr7 must be 64 hex characters")
    return bytes.fromhex(args.pcr7)


def cmd_sign(args):
    raw = _read(args.rules)
    parse_rules(raw)
    pathlib.Path(args.out).write_text(sign_rules(raw, args.key))
    print(f"signed {args.rules}: sha256 {hashlib.sha256(raw).hexdigest()}")
    return 0


def cmd_verify(args):
    rules, digest = load_rules(_read(args.rules), _read(args.signature).decode("ascii", "replace"),
                               args.pubkey, args.min_sequence, args.pubkey_sha256,
                               args.expect_rules_sha256)
    print(json.dumps({"sequence": rules["sequence"], "rules_sha256": digest}))
    return 0


def cmd_evaluate(args):
    try:
        raw = _read(args.rules)
        sig = _read(args.signature).decode("ascii", "replace")
        blob = _read(args.eventlog, 64 << 20)
        live = _pcr7(args)
    except (OSError, StateError, policy.EventLogError) as error:
        print(json.dumps({"accepted": False, "binding": None, "checks": [
            {"name": "inputs", "ok": False, "binding": "attested", "detail": str(error)}]}, indent=2))
        print(f"refused: {error}", file=sys.stderr)
        return 1
    result = evaluate(raw, sig, args.pubkey, args.min_sequence, blob, args.efivars, live,
                      args.pubkey_sha256, args.expect_rules_sha256)
    print(json.dumps(result, indent=2))
    for check in result["checks"]:
        if not check["ok"]:
            print(f"refused: {check['name']}: {check['detail']}", file=sys.stderr)
    return 0 if result["accepted"] else 1


def cmd_ids(args):
    blob = _read(args.eventlog, 64 << 20)
    state = read_state(args.efivars)
    _, _, authorities = read_log(blob)
    print(json.dumps({
        "approved_certs": esl_ids(state["db"] or b""),
        "approved_pk": esl_ids(state["PK"] or b""),
        "approved_kek": esl_ids(state["KEK"] or b""),
        "dbx": esl_ids(state["dbx"] or b""),
        "authorities": [{"name": n, "id": i} for n, i, _ in authorities],
    }, indent=2))
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)

    def trust(p):
        p.add_argument("--rules", required=True)
        p.add_argument("--signature", required=True)
        p.add_argument("--pubkey", required=True, help="Owner public key, PEM")
        p.add_argument("--min-sequence", required=True, type=int,
                       help="lowest rules sequence acceptable, >= 1 (the sealed anti-rollback anchor)")
        p.add_argument("--pubkey-sha256", required=True,
                       help="pin: sha256 of the SubjectPublicKeyInfo DER of the Owner key")
        p.add_argument("--expect-rules-sha256", help="pin: the digest the release manifest binds")

    def state(p):
        p.add_argument("--eventlog", default=DEFAULT_EVENTLOG)
        p.add_argument("--efivars", default=DEFAULT_EFIVARS)

    s = sub.add_parser("sign", help="Owner: sign rules (offline key)")
    s.add_argument("--rules", required=True)
    s.add_argument("--key", required=True)
    s.add_argument("--out", required=True)
    trust(sub.add_parser("verify", help="signature, schema, anti-rollback"))
    e = sub.add_parser("evaluate", help="rules against the machine state")
    trust(e)
    state(e)
    group = e.add_mutually_exclusive_group(required=True)
    group.add_argument("--pcr7", metavar="HEX", help="the live PCR 7 (sha256), as read by the caller")
    group.add_argument("--live", action="store_true", help="read PCR 7 with tpm2_pcrread")
    state(sub.add_parser("ids", help="ids of the observed state, to write rules from"))

    args = parser.parse_args(argv)
    try:
        return {"sign": cmd_sign, "verify": cmd_verify, "evaluate": cmd_evaluate,
                "ids": cmd_ids}[args.cmd](args)
    except RulesError as error:
        print(f"refused: {error}", file=sys.stderr)
        return 1
    except (StateError, policy.EventLogError, OSError) as error:
        print(f"refused: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
