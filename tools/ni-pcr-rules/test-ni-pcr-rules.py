#!/usr/bin/env python3
"""Tests of the PCR 7 rules engine against the real event log of a GB10 machine.

The fixtures are the PCR-7-only TCG2 event log, the Secure Boot variables and the
live PCR 7 of one physical GB10 (ASUS GX10), read at the same boot. The signing
key is generated per run: no key, no serial and no secret is committed.

What the engine must refuse is tested through its command line, the seam the
installer will call; the signature and sequence rules are also tested on the
bytes-in/bytes-out function the CLI wraps.
"""
import base64
import hashlib
import importlib.util
import json
import pathlib
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
import uuid

HERE = pathlib.Path(__file__).resolve().parent
TOOL = HERE / "ni-pcr-rules.py"
FIX = HERE / "fixtures"
LIVE67 = json.loads((FIX / "expected.json").read_text())["ni67"]["live_pcr7_sha256"]

GUID_GLOBAL = "8be4df61-93ca-11d2-aa0d-00e098032b8c"
GUID_SECURITY_DB = "d719b2cb-3d3a-4596-a3bc-dad00e67656f"
GUID_X509 = "a5c059a1-94e4-4aa7-87b5-ab155c2bf072"
GUID_SHA256 = "c1c41626-504c-4092-aca9-41f936934328"
GUID_OWNER = "11111111-2222-3333-4444-555555555555"
GUID_SHIM = "605dab50-e046-4300-abb6-3dd810dd8b23"

spec = importlib.util.spec_from_file_location("ni_pcr_rules", TOOL)
rules_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rules_mod)


def run(*args):
    return subprocess.run([sys.executable, "-I", str(TOOL), *map(str, args)],
                          capture_output=True, text=True, check=False, stdin=subprocess.DEVNULL)


def openssl(*args, stdin=None):
    return subprocess.run(["openssl", *map(str, args)], input=stdin, capture_output=True, check=True)


def new_key(directory, name, kind="ec"):
    key, pub = directory / f"{name}.key.pem", directory / f"{name}.pub.pem"
    if kind == "ec":
        openssl("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", key)
    else:
        openssl("genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", key)
    openssl("pkey", "-in", key, "-pubout", "-out", pub)
    return key, pub


def spki_pin(pub):
    return hashlib.sha256(openssl("pkey", "-pubin", "-in", pub, "-outform", "DER").stdout).hexdigest()


def self_signed_der(common_name):
    with tempfile.TemporaryDirectory() as tmp:
        tmp = pathlib.Path(tmp)
        key = tmp / "k.pem"
        openssl("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", key)
        return openssl("req", "-x509", "-new", "-key", key, "-subj", f"/CN={common_name}",
                       "-days", "30", "-outform", "DER").stdout


# --- efivars / ESL helpers (independent of the tool) ------------------------

def read_b64_efivars(path):
    out = {}
    for line in path.read_text().splitlines():
        name, blob = line.split()
        out[name] = base64.b64decode(blob)
    return out


def write_efivars(directory, variables):
    directory.mkdir(parents=True, exist_ok=True)
    for name, blob in variables.items():
        (directory / name).write_bytes(blob)


def esl_entries(blob):
    """[(type guid, owner guid, data)] of an efivarfs file (4 attribute bytes first)."""
    body, out, off = blob[4:], [], 0
    while off < len(body):
        sig_type = str(uuid.UUID(bytes_le=body[off:off + 16]))
        list_size, hdr_size, sig_size = struct.unpack_from("<III", body, off + 16)
        pos = off + 28 + hdr_size
        while pos < off + list_size:
            out.append((sig_type, str(uuid.UUID(bytes_le=body[pos:pos + 16])),
                        body[pos + 16:pos + sig_size]))
            pos += sig_size
        off += list_size
    return out


def esl_blob(entries, attrs=b"\x27\x00\x00\x00"):
    """An efivarfs file holding one ESL per entry."""
    out = bytearray(attrs)
    for sig_type, owner, data in entries:
        sig = uuid.UUID(owner).bytes_le + data
        out += uuid.UUID(sig_type).bytes_le + struct.pack("<III", 28 + len(sig), 0, len(sig)) + sig
    return bytes(out)


def cert_id(der):
    return "x509:" + hashlib.sha256(der).hexdigest()


# --- synthetic TCG2 log (to exercise a firmware that measures variable CONTENTS) ---

def variable_data(guid, name, data):
    return (uuid.UUID(guid).bytes_le + struct.pack("<QQ", len(name), len(data))
            + name.encode("utf-16-le") + data)


def tcg2_log(events):
    """events: [(pcr, type, data)] -> sha256-only TCG2 log with a legacy spec-id header."""
    header_data = b"\x00" * 4
    out = bytearray(struct.pack("<II", 0, 3) + b"\x00" * 20 + struct.pack("<I", len(header_data)) + header_data)
    for pcr, etype, data in events:
        out += struct.pack("<III", pcr, etype, 1) + struct.pack("<H", 0x000B)
        out += hashlib.sha256(data).digest() + struct.pack("<I", len(data)) + data
    return bytes(out)


def replay7(events):
    acc = b"\x00" * 32
    for pcr, _, data in events:
        if pcr == 7:
            acc = hashlib.sha256(acc + hashlib.sha256(data).digest()).digest()
    return acc


class World:
    """A scratch directory holding rules, signature, key, event log and efivars."""

    def __init__(self, test):
        self.dir = pathlib.Path(tempfile.mkdtemp(prefix="ni-pcr-rules-test."))
        test.addCleanup(shutil.rmtree, self.dir, True)
        self.key, self.pub = new_key(self.dir, "owner")
        self.vars = read_b64_efivars(FIX / "ni67.efivars.b64")
        # The GB10 capture has no SetupMode/AuditMode (it was taken without them), and the
        # engine refuses a missing SetupMode: complete it with the values of a deployed machine.
        # SYNTHETIC, unlike the rest of the fixture; the physical capture is a T5 prerequisite.
        self.vars.setdefault(f"SetupMode-{GUID_GLOBAL}", b"\x06\x00\x00\x00\x00")
        self.vars.setdefault(f"AuditMode-{GUID_GLOBAL}", b"\x06\x00\x00\x00\x00")
        self.log = (FIX / "ni67.pcr7-only.eventlog.bin").read_bytes()
        self.pcr7 = LIVE67
        self.rules = json.loads((FIX / "ni67.rules.json").read_text())
        self.min_sequence = 1

    def sign(self, rules=None, key=None, through_tool=True):
        """Write and sign the rules. `through_tool=False` signs with openssl directly, which
        is how a hostile or buggy signer would produce rules the Owner's tool refuses."""
        self.rules_path = self.dir / "rules.json"
        self.rules_path.write_text(json.dumps(self.rules if rules is None else rules, indent=2) + "\n")
        self.sig_path = self.dir / "rules.json.sig"
        if through_tool:
            result = run("sign", "--rules", self.rules_path, "--key", key or self.key,
                         "--out", self.sig_path)
            assert result.returncode == 0, result.stderr
        else:
            sig = openssl("dgst", "-sha256", "-sign", key or self.key,
                          stdin=b"neural-ice-pcr-rules/v1\0" + self.rules_path.read_bytes()).stdout
            self.sig_path.write_text(base64.b64encode(sig).decode() + "\n")

    def args(self, command="evaluate", extra=()):
        a = [command, "--rules", self.rules_path, "--signature", self.sig_path, "--pubkey", self.pub,
             "--pubkey-sha256", spki_pin(self.pub), "--min-sequence", self.min_sequence]
        if command == "evaluate":
            write_efivars(self.dir / "efivars", self.vars)
            (self.dir / "eventlog.bin").write_bytes(self.log)
            a += ["--eventlog", self.dir / "eventlog.bin", "--efivars", self.dir / "efivars",
                  "--pcr7", self.pcr7]
        return a + list(extra)

    def evaluate(self, extra=()):
        if not hasattr(self, "sig_path"):
            self.sign()
        result = run(*self.args("evaluate", extra))
        try:
            verdict = json.loads(result.stdout)
        except json.JSONDecodeError:
            verdict = None
        return result, verdict


def failed(verdict):
    return {c["name"] for c in verdict["checks"] if not c["ok"]}


class SignatureAndSequence(unittest.TestCase):
    def setUp(self):
        self.w = World(self)
        self.w.sign()

    def verify(self, **changes):
        result = run(*self.w.args("verify"), *changes.get("extra", ()))
        return result

    def test_valid_rules_are_accepted(self):
        result = self.verify()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(self.w.rules["sequence"], [json.loads(result.stdout)["sequence"]])

    def test_rsa_key_works_too(self):
        key, pub = new_key(self.w.dir, "rsa", "rsa")
        self.w.sign(key=key)
        self.w.pub = pub
        self.assertEqual(self.verify().returncode, 0)

    def test_signature_by_another_key_is_refused(self):
        other, _ = new_key(self.w.dir, "other")
        self.w.sign(key=other)
        result = self.verify()
        self.assertEqual(result.returncode, 1)
        self.assertIn("signature", result.stderr)

    def test_tampered_rules_are_refused(self):
        text = self.w.rules_path.read_text().replace('"sequence": 7', '"sequence": 8')
        self.assertNotEqual(text, self.w.rules_path.read_text())
        self.w.rules_path.write_text(text)
        self.assertEqual(self.verify().returncode, 1)

    def test_signature_without_the_domain_prefix_is_refused(self):
        # A signature over the bare payload is what any other tool signing with this key
        # (a PolicyPCR digest, a release manifest) could produce: it must not authorise rules.
        sig = openssl("dgst", "-sha256", "-sign", self.w.key, stdin=self.w.rules_path.read_bytes()).stdout
        self.w.sig_path.write_text(base64.b64encode(sig).decode() + "\n")
        result = self.verify()
        self.assertEqual(result.returncode, 1)
        self.assertIn("signature", result.stderr)

    def test_signature_over_another_domain_is_refused(self):
        payload = b"neural-ice-pcr-rules/v0\0" + self.w.rules_path.read_bytes()
        sig = openssl("dgst", "-sha256", "-sign", self.w.key, stdin=payload).stdout
        self.w.sig_path.write_text(base64.b64encode(sig).decode() + "\n")
        self.assertEqual(self.verify().returncode, 1)

    def test_a_lower_sequence_is_refused(self):
        self.w.min_sequence = self.w.rules["sequence"] + 1
        result = self.verify()
        self.assertEqual(result.returncode, 1)
        self.assertIn("rollback", result.stderr)

    def test_an_equal_sequence_is_accepted(self):
        self.w.min_sequence = self.w.rules["sequence"]
        self.assertEqual(self.verify().returncode, 0)

    def test_the_minimum_sequence_cannot_be_omitted(self):
        args = [a for a in self.w.args("verify")]
        i = args.index("--min-sequence")
        del args[i:i + 2]
        self.assertNotEqual(run(*args).returncode, 0)

    def test_a_pinned_key_fingerprint_must_match(self):
        spki = openssl("pkey", "-pubin", "-in", self.w.pub, "-outform", "DER").stdout
        good = hashlib.sha256(spki).hexdigest()
        self.assertEqual(self.verify(extra=("--pubkey-sha256", good)).returncode, 0)
        self.assertEqual(self.verify(extra=("--pubkey-sha256", "0" * 64)).returncode, 1)

    def test_the_manifest_digest_binding_must_match(self):
        digest = hashlib.sha256(self.w.rules_path.read_bytes()).hexdigest()
        self.assertEqual(self.verify(extra=("--expect-rules-sha256", digest)).returncode, 0)
        self.assertEqual(self.verify(extra=("--expect-rules-sha256", "0" * 64)).returncode, 1)

    def test_garbage_signature_is_refused(self):
        self.w.sig_path.write_text("not base64 !!\n")
        self.assertEqual(self.verify().returncode, 1)

    def test_a_valid_signature_with_foreign_characters_is_refused(self):
        # Lenient base64 would drop the "!" and verify: strict decoding must refuse it.
        good = self.w.sig_path.read_text().strip()
        self.w.sig_path.write_text(good[:10] + "!" + good[10:] + "\n")
        result = self.verify()
        self.assertEqual(result.returncode, 1)
        self.assertIn("not base64", result.stderr)

    def test_an_oversized_signature_is_refused(self):
        self.w.sig_path.write_text(base64.b64encode(b"\x30" * 2000).decode() + "\n")
        result = self.verify()
        self.assertEqual(result.returncode, 1)
        self.assertIn("oversized", result.stderr)

    def test_the_signature_is_checked_before_the_rules_are_read(self):
        # Rules that violate the schema AND carry a bad signature: the refusal must be the
        # signature's. If the document were parsed first, it would be the schema's.
        w = World(self)
        w.rules["surprise"] = 1
        other, _ = new_key(w.dir, "other")
        w.sign(key=other, through_tool=False)
        result = run(*w.args("verify"))
        self.assertEqual(result.returncode, 1)
        self.assertIn("signature", result.stderr)
        self.assertNotIn("schema", result.stderr)

    def test_the_signing_key_pin_is_mandatory(self):
        args = self.w.args("verify")
        i = args.index("--pubkey-sha256")
        del args[i:i + 2]
        self.assertNotEqual(run(*args).returncode, 0)

    def test_a_sequence_floor_below_one_is_refused(self):
        # --min-sequence 0 (or negative) switches the anti-rollback off.
        for floor in (0, -1):
            self.w.min_sequence = floor
            result = self.verify()
            self.assertEqual(result.returncode, 1, floor)
            self.assertIn("rollback", result.stderr)

    def test_a_pin_that_is_not_a_sha256_is_refused(self):
        self.assertEqual(self.verify(extra=("--pubkey-sha256", "abc")).returncode, 1)

    def test_a_signing_key_swapped_after_the_pin_is_read_cannot_verify(self):
        # The key file is read once: the bytes pinned are the bytes that verify.
        raw = self.w.rules_path.read_bytes()
        sig = self.w.sig_path.read_text()
        pin = spki_pin(self.w.pub)
        other, other_pub = new_key(self.w.dir, "other")
        sig_other = openssl("dgst", "-sha256", "-sign", other,
                            stdin=b"neural-ice-pcr-rules/v1\0" + raw).stdout
        with self.assertRaises(rules_mod.RulesError):
            rules_mod.load_rules(raw, base64.b64encode(sig_other).decode(), self.w.pub, 1, pin)
        rules, _ = rules_mod.load_rules(raw, sig, self.w.pub, 1, pin)
        self.assertEqual(rules["sequence"], self.w.rules["sequence"])


class SchemaIsStrict(unittest.TestCase):
    def refuse(self, mutate):
        w = World(self)
        rules = json.loads(json.dumps(w.rules))
        mutate(rules)
        w.sign(rules, through_tool=False)
        result = run(*w.args("verify"))
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("schema", result.stderr)

    def test_unknown_field(self):
        self.refuse(lambda r: r.update(surprise=1))

    def test_wrong_schema_name(self):
        self.refuse(lambda r: r.update(schema="ni-pcr-rules/2"))

    def test_sequence_must_be_a_positive_integer(self):
        self.refuse(lambda r: r.update(sequence=0))
        self.refuse(lambda r: r.update(sequence=True))
        self.refuse(lambda r: r.update(sequence="7"))

    def test_empty_sets_are_refused(self):
        for field in ("approved_certs", "dbx_floor", "authorities"):
            self.refuse(lambda r, f=field: r.update({f: []}))

    def test_pk_and_kek_sets_are_mandatory_and_non_empty(self):
        for field in ("approved_pk", "approved_kek"):
            self.refuse(lambda r, f=field: r.pop(f))
            self.refuse(lambda r, f=field: r.update({f: []}))
            self.refuse(lambda r, f=field: r.update({f: ["x509:XYZ"]}))
            self.refuse(lambda r, f=field: r.update({f: ["text-sha256:" + "0" * 64]}))

    def test_duplicate_ids_are_refused(self):
        for field in ("approved_certs", "approved_pk", "approved_kek", "dbx_floor"):
            self.refuse(lambda r, f=field: r[f].append(r[f][0]))
        self.refuse(lambda r: r["authorities"][0]["ids"].append(r["authorities"][0]["ids"][0]))

    def test_duplicate_authority_names_are_refused(self):
        self.refuse(lambda r: r["authorities"].append(dict(r["authorities"][0])))

    def test_an_authority_with_an_extra_key_is_refused(self):
        self.refuse(lambda r: r["authorities"][0].update(extra=1))

    def test_malformed_ids_are_refused(self):
        self.refuse(lambda r: r["approved_certs"].append("x509:XYZ"))
        self.refuse(lambda r: r["dbx_floor"].append("md5:" + "0" * 32))

    def test_unbound_policy_is_explicit(self):
        self.refuse(lambda r: r.update(unbound_variables="maybe"))
        self.refuse(lambda r: r.pop("unbound_variables"))

    def test_duplicate_keys_are_refused(self):
        w = World(self)
        text = json.dumps(w.rules).rstrip().rstrip("}") + ', "sequence": 99}\n'
        w.rules_path = w.dir / "rules.json"
        w.rules_path.write_text(text)
        w.sig_path = w.dir / "rules.json.sig"
        sig = openssl("dgst", "-sha256", "-sign", w.key,
                      stdin=b"neural-ice-pcr-rules/v1\0" + text.encode()).stdout
        w.sig_path.write_text(base64.b64encode(sig).decode() + "\n")
        result = run(*w.args("verify"))
        self.assertEqual(result.returncode, 1)
        self.assertIn("schema", result.stderr)

    def test_oversized_rules_are_refused_by_size_not_by_schema(self):
        # Valid rules padded with whitespace: only the size ceiling can refuse them.
        w = World(self)
        w.rules_path = w.dir / "rules.json"
        w.rules_path.write_bytes(json.dumps(w.rules).encode() + b" " * (rules_mod.MAX_RULES_BYTES + 1))
        w.sig_path = w.dir / "rules.json.sig"
        sig = openssl("dgst", "-sha256", "-sign", w.key,
                      stdin=b"neural-ice-pcr-rules/v1\0" + w.rules_path.read_bytes()).stdout
        w.sig_path.write_text(base64.b64encode(sig).decode() + "\n")
        result = run(*w.args("verify"))
        self.assertEqual(result.returncode, 1)
        self.assertIn("more than", result.stderr)

    def test_a_long_note_is_refused(self):
        self.refuse(lambda r: r.update(note="x" * 201))

    def test_the_owner_tool_refuses_to_sign_a_bad_document(self):
        w = World(self)
        w.rules["dbx_floor"] = []
        w.rules_path = w.dir / "bad.json"
        w.rules_path.write_text(json.dumps(w.rules))
        result = run("sign", "--rules", w.rules_path, "--key", w.key, "--out", w.dir / "bad.sig")
        self.assertEqual(result.returncode, 1)
        self.assertFalse((w.dir / "bad.sig").exists())


class EvaluateRealGb10(unittest.TestCase):
    def test_valid_rules_accept_the_real_67_state(self):
        result, verdict = World(self).evaluate()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(verdict["accepted"])
        self.assertEqual(verdict["binding"], "names-only")
        by_name = {c["name"]: c for c in verdict["checks"]}
        for name in ("replay-equals-live", "secure-boot", "pk-present", "setup-mode",
                     "db-subset-of-approved", "dbx-superset-of-floor", "authorities-approved"):
            self.assertTrue(by_name[name]["ok"], name)
        # The truth about this firmware: PK/db/dbx contents are NOT attested by PCR 7.
        self.assertEqual(by_name["db-subset-of-approved"]["binding"], "observed")
        self.assertEqual(by_name["authorities-approved"]["binding"], "attested")

    def test_the_firmware_here_is_refused_when_the_rules_demand_attested_variables(self):
        w = World(self)
        w.rules["unbound_variables"] = "refuse"
        w.sign()
        result, verdict = w.evaluate()
        self.assertEqual(result.returncode, 1)
        self.assertIn("unbound-variables", failed(verdict))

    def test_a_wrong_live_pcr7_is_refused(self):
        w = World(self)
        w.pcr7 = LIVE67[:-1] + ("0" if LIVE67[-1] != "0" else "1")
        result, verdict = w.evaluate()
        self.assertEqual(result.returncode, 1)
        self.assertIn("replay-equals-live", failed(verdict))

    def test_a_log_whose_event_data_was_edited_is_refused(self):
        # Edit a byte of the SbatLevel authority text: its digest no longer matches the data.
        w = World(self)
        marker = b"sbat,1,"
        at = w.log.index(marker)
        w.log = w.log[:at + 5] + b"9" + w.log[at + 6:]
        result, verdict = w.evaluate()
        self.assertEqual(result.returncode, 1)
        self.assertIn("log-digests-attest-data", failed(verdict))

    def test_a_forged_log_with_consistent_digests_cannot_reproduce_live_pcr7(self):
        w = World(self)
        events = rules_mod.policy.parse_eventlog(w.log)
        forged = []
        for ev in events:
            data = ev["data"].replace(b"sbat,1,", b"sbat,9,")
            forged.append((ev["pcr"], ev["type"], data))
        w.log = tcg2_log(forged)
        result, verdict = w.evaluate()
        self.assertEqual(result.returncode, 1)
        self.assertIn("replay-equals-live", failed(verdict))

    def test_db_with_a_certificate_outside_the_approved_set_is_refused(self):
        w = World(self)
        db = esl_entries(w.vars[f"db-{GUID_SECURITY_DB}"])
        db.append((GUID_X509, GUID_OWNER, self_signed_der("intruder")))
        w.vars[f"db-{GUID_SECURITY_DB}"] = esl_blob(db)
        result, verdict = w.evaluate()
        self.assertEqual(result.returncode, 1)
        self.assertIn("db-subset-of-approved", failed(verdict))

    def test_dbx_below_the_floor_is_refused(self):
        w = World(self)
        dbx = esl_entries(w.vars[f"dbx-{GUID_SECURITY_DB}"])
        floor_hash = w.rules["dbx_floor"][0].split(":", 1)[1]
        kept = [e for e in dbx if e[2].hex() != floor_hash]
        self.assertEqual(len(kept), len(dbx) - 1)
        w.vars[f"dbx-{GUID_SECURITY_DB}"] = esl_blob(kept)
        result, verdict = w.evaluate()
        self.assertEqual(result.returncode, 1)
        self.assertIn("dbx-superset-of-floor", failed(verdict))

    def test_an_empty_dbx_is_refused(self):
        w = World(self)
        w.vars[f"dbx-{GUID_SECURITY_DB}"] = b"\x27\x00\x00\x00"
        result, verdict = w.evaluate()
        self.assertIn("dbx-superset-of-floor", failed(verdict))

    def test_setup_mode_is_refused(self):
        w = World(self)
        w.vars[f"SetupMode-{GUID_GLOBAL}"] = b"\x06\x00\x00\x00\x01"
        result, verdict = w.evaluate()
        self.assertEqual(result.returncode, 1)
        self.assertIn("setup-mode", failed(verdict))

    def test_an_absent_platform_key_is_refused(self):
        w = World(self)
        w.vars[f"PK-{GUID_GLOBAL}"] = b"\x27\x00\x00\x00"
        result, verdict = w.evaluate()
        self.assertEqual(result.returncode, 1)
        self.assertIn("pk-present", failed(verdict))
        self.assertIn("setup-mode", failed(verdict))

    def test_missing_pk_variable_is_refused(self):
        w = World(self)
        del w.vars[f"PK-{GUID_GLOBAL}"]
        result, verdict = w.evaluate()
        self.assertEqual(result.returncode, 1)
        self.assertIn("pk-present", failed(verdict))

    def test_secure_boot_off_is_refused(self):
        w = World(self)
        w.vars[f"SecureBoot-{GUID_GLOBAL}"] = b"\x06\x00\x00\x00\x00"
        result, verdict = w.evaluate()
        self.assertEqual(result.returncode, 1)
        self.assertIn("secure-boot", failed(verdict))

    def test_no_authority_event_means_no_verified_boot(self):
        w = World(self)
        events = [(ev["pcr"], ev["type"], ev["data"])
                  for ev in rules_mod.policy.parse_eventlog(w.log)
                  if ev["type"] != rules_mod.policy.EV_EFI_VARIABLE_AUTHORITY]
        w.log = tcg2_log(events)
        w.pcr7 = replay7(events).hex()
        result, verdict = w.evaluate()
        self.assertEqual(result.returncode, 1)
        self.assertIn("secure-boot", failed(verdict))

    def test_an_authority_outside_the_approved_boot_path_is_refused(self):
        w = World(self)
        w.rules["authorities"] = [a for a in w.rules["authorities"] if a["name"] != "MokListRT"]
        w.sign()
        result, verdict = w.evaluate()
        self.assertEqual(result.returncode, 1)
        self.assertIn("authorities-approved", failed(verdict))

    def test_an_authority_certificate_missing_from_db_is_refused(self):
        w = World(self)
        db = esl_entries(w.vars[f"db-{GUID_SECURITY_DB}"])
        authority = next(a for a in w.rules["authorities"] if a["name"] == "db")["ids"][0]
        kept = [e for e in db if cert_id(e[2]) != authority]
        self.assertEqual(len(kept), len(db) - 1)
        w.vars[f"db-{GUID_SECURITY_DB}"] = esl_blob(kept)
        result, verdict = w.evaluate()
        self.assertEqual(result.returncode, 1)
        self.assertIn("authority-in-db", failed(verdict))

    def test_bad_signature_or_lower_sequence_stop_before_any_state_is_trusted(self):
        w = World(self)
        w.sign()
        w.min_sequence = w.rules["sequence"] + 1
        result, verdict = w.evaluate()
        self.assertEqual(result.returncode, 1)
        self.assertFalse(verdict["accepted"])
        self.assertIn("rules-sequence", failed(verdict))

        w = World(self)
        other, _ = new_key(w.dir, "other")
        w.sign(key=other)
        result, verdict = w.evaluate()
        self.assertEqual(result.returncode, 1)
        self.assertIn("rules-signature", failed(verdict))

    def test_the_pk_must_be_one_the_rules_approve(self):
        # R1 of the review: a self-signed attacker PK and KEK, db and dbx untouched.
        w = World(self)
        w.vars[f"PK-{GUID_GLOBAL}"] = esl_blob([(GUID_X509, GUID_OWNER, self_signed_der("attacker"))])
        result, verdict = w.evaluate()
        self.assertEqual(result.returncode, 1)
        self.assertIn("pk-approved", failed(verdict))
        self.assertNotIn("kek-approved", failed(verdict))

    def test_the_kek_must_be_ones_the_rules_approve(self):
        w = World(self)
        kek = esl_entries(w.vars[f"KEK-{GUID_GLOBAL}"])
        kek.append((GUID_X509, GUID_OWNER, self_signed_der("attacker")))
        w.vars[f"KEK-{GUID_GLOBAL}"] = esl_blob(kek)
        result, verdict = w.evaluate()
        self.assertEqual(result.returncode, 1)
        self.assertIn("kek-approved", failed(verdict))
        self.assertNotIn("pk-approved", failed(verdict))

    def test_attacker_pk_and_kek_together_are_refused(self):
        w = World(self)
        w.vars[f"PK-{GUID_GLOBAL}"] = esl_blob([(GUID_X509, GUID_OWNER, self_signed_der("a-pk"))])
        w.vars[f"KEK-{GUID_GLOBAL}"] = esl_blob([(GUID_X509, GUID_OWNER, self_signed_der("a-kek"))])
        result, verdict = w.evaluate()
        self.assertEqual(result.returncode, 1)
        self.assertLessEqual({"pk-approved", "kek-approved"}, failed(verdict))

    def test_a_subset_of_the_approved_keks_is_accepted(self):
        w = World(self)
        kek = esl_entries(w.vars[f"KEK-{GUID_GLOBAL}"])
        self.assertGreater(len(kek), 1)
        w.vars[f"KEK-{GUID_GLOBAL}"] = esl_blob(kek[:1])
        result, verdict = w.evaluate()
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_an_empty_or_missing_kek_is_refused(self):
        for blob in (b"\x27\x00\x00\x00", None):
            w = World(self)
            if blob is None:
                del w.vars[f"KEK-{GUID_GLOBAL}"]
            else:
                w.vars[f"KEK-{GUID_GLOBAL}"] = blob
            result, verdict = w.evaluate()
            self.assertEqual(result.returncode, 1)
            self.assertIn("kek-approved", failed(verdict))

    def test_pk_and_kek_on_this_firmware_are_observed_not_attested(self):
        result, verdict = World(self).evaluate()
        by_name = {c["name"]: c for c in verdict["checks"]}
        self.assertTrue(by_name["pk-approved"]["ok"] and by_name["kek-approved"]["ok"])
        self.assertEqual(by_name["pk-approved"]["binding"], "observed")
        self.assertEqual(by_name["kek-approved"]["binding"], "observed")

    def test_an_accepted_verdict_lists_what_was_only_observed(self):
        # The caller must decide on `binding` / `observed`, never on `accepted` alone.
        result, verdict = World(self).evaluate()
        self.assertTrue(verdict["accepted"])
        self.assertEqual(verdict["binding"], "names-only")
        self.assertLessEqual({"pk-approved", "kek-approved", "db-subset-of-approved",
                              "dbx-superset-of-floor", "setup-mode", "unbound-variables"},
                             set(verdict["observed"]))
        self.assertNotIn("authorities-approved", verdict["observed"])

    def test_a_missing_setup_mode_is_refused(self):
        # SetupMode is mandatory in UEFI 2.3.1+: its absence is not "not in setup mode".
        w = World(self)
        del w.vars[f"SetupMode-{GUID_GLOBAL}"]
        result, verdict = w.evaluate()
        self.assertEqual(result.returncode, 1)
        self.assertIn("setup-mode", failed(verdict))

    def test_audit_mode_is_refused(self):
        w = World(self)
        w.vars[f"AuditMode-{GUID_GLOBAL}"] = b"\x06\x00\x00\x00\x01"
        result, verdict = w.evaluate()
        self.assertEqual(result.returncode, 1)
        self.assertIn("setup-mode", failed(verdict))

    def test_audit_mode_may_be_absent_but_not_odd(self):
        # Some firmware has no AuditMode variable at all (the x86 desktop this was written on).
        w = World(self)
        del w.vars[f"AuditMode-{GUID_GLOBAL}"]
        self.assertEqual(w.evaluate()[0].returncode, 0)
        w = World(self)
        w.vars[f"AuditMode-{GUID_GLOBAL}"] = b"\x06\x00\x00\x00\x00\x00"
        self.assertEqual(w.evaluate()[0].returncode, 1)

    def test_an_efivar_that_is_a_symbolic_link_is_refused(self):
        w = World(self)
        w.sign()
        args = w.args("evaluate")
        link = w.dir / "efivars" / f"KEK-{GUID_GLOBAL}"
        target = w.dir / "kek.bin"
        target.write_bytes(link.read_bytes())
        link.unlink()
        link.symlink_to(target)
        result = run(*args)
        self.assertEqual(result.returncode, 1)
        self.assertIn("symbolic link", result.stderr)

    def test_an_efivar_with_an_impossible_size_is_refused(self):
        for blob, label in ((b"\x27\x00", "short"),
                            (b"\x27\x00\x00\x00" + b"\x00" * rules_mod.MAX_VARIABLE_BYTES, "long")):
            w = World(self)
            w.vars[f"KEK-{GUID_GLOBAL}"] = blob
            result, verdict = w.evaluate()
            self.assertEqual(result.returncode, 1, label)
            self.assertIn("impossible size", result.stderr)

    def test_missing_inputs_fail_closed(self):
        w = World(self)
        w.sign()
        args = w.args("evaluate")
        args[args.index("--eventlog") + 1] = w.dir / "no-such-log.bin"
        result = run(*args)
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("Traceback", result.stderr)

        w2 = World(self)
        w2.sign()
        args = w2.args("evaluate")
        args[args.index("--efivars") + 1] = w2.dir / "no-such-dir"
        result = run(*args)
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("Traceback", result.stderr)

    def test_live_pcr7_must_be_given_explicitly(self):
        w = World(self)
        w.sign()
        args = w.args("evaluate")
        i = args.index("--pcr7")
        del args[i:i + 2]
        self.assertNotEqual(run(*args).returncode, 0)


class FirmwareThatMeasuresContents(unittest.TestCase):
    """EDK2 / TCG PC Client behaviour: the variable bytes ARE in the log, hence in PCR 7."""

    def setUp(self):
        self.w = World(self)
        v = self.w.vars
        self.cert = self_signed_der("contents-mode")
        self.db = esl_blob([(GUID_X509, GUID_OWNER, self.cert)])
        self.dbx = esl_blob([(GUID_SHA256, GUID_OWNER, bytes(range(32)))])
        self.pk_der, self.kek_der = self_signed_der("pk"), self_signed_der("kek")
        self.pk = esl_blob([(GUID_X509, GUID_OWNER, self.pk_der)])
        self.kek = esl_blob([(GUID_X509, GUID_OWNER, self.kek_der)])
        v.clear()
        v[f"SetupMode-{GUID_GLOBAL}"] = b"\x06\x00\x00\x00\x00"
        v[f"PK-{GUID_GLOBAL}"] = self.pk
        v[f"KEK-{GUID_GLOBAL}"] = self.kek
        v[f"db-{GUID_SECURITY_DB}"] = self.db
        v[f"dbx-{GUID_SECURITY_DB}"] = self.dbx
        v[f"SecureBoot-{GUID_GLOBAL}"] = b"\x06\x00\x00\x00\x01"
        self.set_log()
        self.w.rules = {
            "schema": "ni-pcr-rules/1", "sequence": 3, "unbound_variables": "refuse",
            "approved_certs": [cert_id(self.cert)],
            "approved_pk": [cert_id(self.pk_der)], "approved_kek": [cert_id(self.kek_der)],
            "dbx_floor": ["sha256:" + bytes(range(32)).hex()],
            "authorities": [{"name": "db", "ids": [cert_id(self.cert)]}],
        }

    def set_log(self, logged=None, guids=None, skip=(), extra=()):
        v = self.w.vars
        logged, guids = logged or {}, guids or {}
        events = []
        for name, guid in (("SecureBoot", GUID_GLOBAL), ("PK", GUID_GLOBAL), ("KEK", GUID_GLOBAL),
                           ("db", GUID_SECURITY_DB), ("dbx", GUID_SECURITY_DB)):
            if name in skip:
                continue
            data = logged.get(name, v[f"{name}-{guid}"][4:])
            events.append((7, rules_mod.policy.EV_EFI_VARIABLE_DRIVER_CONFIG,
                           variable_data(guids.get(name, guid), name, data)))
        events.append((7, rules_mod.policy.EV_SEPARATOR, b"\x00" * 4))
        events.append((7, rules_mod.policy.EV_EFI_VARIABLE_AUTHORITY,
                       variable_data(guids.get("authority", GUID_SECURITY_DB), "db",
                                     uuid.UUID(GUID_OWNER).bytes_le + self.cert)))
        events.extend(extra)
        self.w.log = tcg2_log(events)
        self.w.pcr7 = replay7(events).hex()

    def test_attested_contents_are_accepted_even_when_unbound_variables_are_refused(self):
        result, verdict = self.w.evaluate()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(verdict["binding"], "contents")
        by_name = {c["name"]: c for c in verdict["checks"]}
        self.assertEqual(by_name["db-subset-of-approved"]["binding"], "attested")
        self.assertEqual(by_name["dbx-superset-of-floor"]["binding"], "attested")

    def test_efivars_that_differ_from_what_the_firmware_measured_are_refused(self):
        # The measured db holds the approved cert; the efivar says it holds another one.
        # PCR 7 is genuine, the variable is not what PCR 7 saw: the variable lies.
        self.set_log()
        self.w.vars[f"db-{GUID_SECURITY_DB}"] = esl_blob([(GUID_X509, GUID_OWNER, self_signed_der("liar"))])
        result, verdict = self.w.evaluate()
        self.assertEqual(result.returncode, 1)
        self.assertIn("variables-bound", failed(verdict))

    def test_a_dbx_edited_after_boot_is_refused(self):
        self.w.vars[f"dbx-{GUID_SECURITY_DB}"] = esl_blob([])
        result, verdict = self.w.evaluate()
        self.assertEqual(result.returncode, 1)
        self.assertIn("variables-bound", failed(verdict))

    def test_a_variable_measured_under_another_guid_is_refused(self):
        self.set_log(guids={"db": GUID_OWNER})
        result, verdict = self.w.evaluate()
        self.assertEqual(result.returncode, 1)
        self.assertIn("variables-bound", failed(verdict))

    def test_a_variable_the_log_does_not_carry_is_refused(self):
        self.set_log(skip=("KEK",))
        result, verdict = self.w.evaluate()
        self.assertEqual(result.returncode, 1)
        self.assertIn("variables-bound", failed(verdict))

    def test_a_variable_measured_twice_is_refused(self):
        dup = (7, rules_mod.policy.EV_EFI_VARIABLE_DRIVER_CONFIG,
               variable_data(GUID_SECURITY_DB, "db", self.db))
        self.set_log(extra=[dup])
        result, verdict = self.w.evaluate()
        self.assertEqual(result.returncode, 1)
        self.assertIn("measured twice", result.stderr)

    def test_a_pcr7_event_the_engine_does_not_model_is_refused(self):
        self.set_log(extra=[(7, 0x00000007, b"unmodelled")])   # EV_S_CRTM_VERSION-like type
        result, verdict = self.w.evaluate()
        self.assertEqual(result.returncode, 1)
        self.assertIn("not modelled", result.stderr)

    def test_a_db_authority_event_under_another_guid_is_refused(self):
        self.set_log(guids={"authority": GUID_OWNER})
        result, verdict = self.w.evaluate()
        self.assertEqual(result.returncode, 1)
        self.assertIn("secure-boot", failed(verdict))

    def test_a_zero_length_measurement_never_counts_as_attested(self):
        # The firmware names dbx without its bytes while the variable is empty too: nothing was
        # compared, so this is "observed", not "attested" (vide == vide proves nothing).
        self.w.vars[f"dbx-{GUID_SECURITY_DB}"] = b"\x27\x00\x00\x00"
        self.set_log(logged={"dbx": b""})
        self.w.rules["dbx_floor"] = ["sha256:" + bytes(range(32)).hex()]
        result, verdict = self.w.evaluate()
        by_name = {c["name"]: c for c in verdict["checks"]}
        self.assertEqual(by_name["dbx-superset-of-floor"]["binding"], "observed")
        self.assertIn("unbound-variables", failed(verdict))

    def test_pk_and_kek_measured_with_their_contents_are_attested(self):
        result, verdict = self.w.evaluate()
        by_name = {c["name"]: c for c in verdict["checks"]}
        self.assertEqual(by_name["pk-approved"]["binding"], "attested")
        self.assertEqual(by_name["kek-approved"]["binding"], "attested")


class EslParserIsStrict(unittest.TestCase):
    def esl(self, list_size=None, header=0, sig_size=None, entries=1, payload=b"\x00" * 16):
        sig = payload
        sig_size = len(sig) if sig_size is None else sig_size
        body = sig * entries
        size = 28 + header + len(body) if list_size is None else list_size
        return (uuid.UUID(GUID_X509).bytes_le + struct.pack("<III", size, header, sig_size)
                + b"\x00" * header + body)

    def refused(self, body):
        import signal

        signal.alarm(10)       # a parser that loops forever on sig_size == 0 must fail, not hang
        try:
            with self.assertRaises(rules_mod.StateError):
                rules_mod.parse_esl(body)
        finally:
            signal.alarm(0)

    def test_a_well_formed_list_parses(self):
        self.assertEqual(len(rules_mod.parse_esl(self.esl(payload=b"\x01" * 40, entries=2))), 2)

    def test_truncated_header(self):
        self.refused(self.esl()[:20])

    def test_list_size_smaller_than_the_header(self):
        self.refused(self.esl(list_size=20))

    def test_list_size_beyond_the_data(self):
        self.refused(self.esl(list_size=10_000))

    def test_zero_signature_size_does_not_loop(self):
        self.refused(self.esl(sig_size=0))

    def test_signature_size_below_an_owner_guid(self):
        self.refused(self.esl(sig_size=8))

    def test_signature_area_not_a_multiple_of_the_signature_size(self):
        self.refused(self.esl(payload=b"\x01" * 40, sig_size=32))

    def test_a_header_larger_than_the_list(self):
        self.refused(self.esl(header=4000, list_size=60))


class EventDataIsStrict(unittest.TestCase):
    def test_short_event_data(self):
        with self.assertRaises(rules_mod.StateError):
            rules_mod.split_variable(b"\x00" * 31)

    def test_lengths_that_do_not_add_up(self):
        data = variable_data(GUID_GLOBAL, "PK", b"abc") + b"x"
        with self.assertRaises(rules_mod.StateError):
            rules_mod.split_variable(data)
        with self.assertRaises(rules_mod.StateError):
            rules_mod.split_variable(variable_data(GUID_GLOBAL, "PK", b"abc")[:-1])

    def test_a_name_that_is_not_utf16(self):
        data = (uuid.UUID(GUID_GLOBAL).bytes_le + struct.pack("<QQ", 1, 0) + b"\x00\xd8")
        with self.assertRaises(rules_mod.StateError):
            rules_mod.split_variable(data)

    def test_a_well_formed_event(self):
        self.assertEqual(rules_mod.split_variable(variable_data(GUID_GLOBAL, "PK", b"abc")),
                         (GUID_GLOBAL, "PK", b"abc"))


class WhatTheDocumentationClaims(unittest.TestCase):
    """The engine's own text must not claim more than a GB10's PCR 7 proves (review of #247)."""

    TEXTS = {"README": (HERE / "README.md").read_text(), "tool": TOOL.read_text()}

    def test_no_text_says_pcr7_vouches_for_the_variables(self):
        for name, text in self.TEXTS.items():
            flat = " ".join(text.lower().split())
            for claim in ("pcr 7 vouches", "pcr7 vouches", "the tpm's pcr 7 is the proof",
                          "variables cannot lie"):
                self.assertNotIn(claim, flat, f"{name}: {claim!r}")

    def test_the_readme_states_the_efivar_trust_argument(self):
        flat = " ".join(self.TEXTS["README"].lower().split())
        for needle in ("threat model of the directly read efi variables",
                       "signed uki", "secure boot", "authenticated", "pk", "kek",
                       "setup mode", "audit mode", "uefi administrator password",
                       "zero-length", "out of scope", "spi", "firmware bug",
                       "restore factory keys", "after the unlock"):
            self.assertIn(needle, flat, needle)

    def test_the_readme_marks_each_residual_attack(self):
        text = self.TEXTS["README"]
        for label in ("detected", "agent after unlock", "out of scope"):
            self.assertIn(label, text.lower())


if __name__ == "__main__":
    unittest.main(verbosity=2)
