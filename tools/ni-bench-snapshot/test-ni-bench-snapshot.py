#!/usr/bin/env python3
"""Tests of ni-bench-snapshot: the bench snapshot, the reference record and the
signed bench sheet of the "TPM policy at OEM scale" mission (task T2).

The positive path runs on the real evidence of an ASUS GX10 (GB10) lab unit:
its TCG2 event log, its EFI variables and its live PCR 7, all read from one boot.
Nothing mocks the arithmetic. The only thing that cannot be real is the
INSTALLER-path measurement: no installer-path log exists for that unit yet, so
the tests build a clearly flagged `synthetic-test` one, and prove that the
store refuses it.
"""
import base64
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
TOOL = HERE / "ni-bench-snapshot.py"
FIX = HERE / "fixtures" / "ni67"
POLICY_TOOL = HERE.parents[1] / "ota" / "neural-ice-tpm-policy.py"
# T1's calculator (tools/ni-pcr7-calc, branch feat/pcr7-calculator-20261006).
# Not on main when this was written: the cross-format test runs when it is
# present and says so when it is not.
NI_PCR7 = pathlib.Path(os.environ.get("NI_PCR7_TOOL", HERE.parent / "ni-pcr7-calc" / "ni-pcr7-calc.py"))

spec = importlib.util.spec_from_file_location("ni_bench_snapshot", TOOL)
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)

pspec = importlib.util.spec_from_file_location("ni_tpm_policy", POLICY_TOOL)
policy = importlib.util.module_from_spec(pspec)
pspec.loader.exec_module(policy)

LIVE_PCR7 = "5e0a249205622a1a59fe040082d3591ae18dfb2a78d8c1ff2765ca712eb68437"
BIOS_VERSION = "GX10DGX.0104.2026.0326.1657"
FAMILY = "gx10dgx-0104-2026-0326-1657"
WHEN = "2026-10-06T21:38:00Z"


def cli(*args, **kw):
    return subprocess.run([sys.executable, "-I", str(TOOL), *args],
                          capture_output=True, text=True, check=False,
                          stdin=subprocess.DEVNULL, **kw)


def openssl(*args, data=None):
    return subprocess.run(["openssl", *args], input=data, capture_output=True, check=True)


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def evidence_inputs():
    """The capture inputs of the .67 evidence, as the bench station would pass them."""
    bios = (FIX / "bios.txt").read_text().split()
    return dict(efivars_b64=FIX / "efivars.b64",
                eventlog=FIX / "eventlog.pcr7-only.bin",
                pcr7_text=(FIX / "pcr7-and-state.txt").read_text(),
                bios_version=bios[0], bios_date=bios[1])


def capture_installed(**override):
    kw = dict(evidence_inputs(), path="installed", captured_at=WHEN,
              kernel="6.12.0", state_marker="owner-sealed-ota-state-v1")
    kw.update(override)
    return tool.capture(**kw)


def encode_log(header, events):
    """Independent TCG2 encoder: header bytes, then events as filtered by the tool."""
    ids = {name: alg for alg, (name, _) in policy.ALGS.items()}
    out = bytearray(header)
    for ev in events:
        out += struct.pack("<III", ev["pcr"], ev["type"], len(ev["digests"]))
        for name, digest in ev["digests"].items():
            out += struct.pack("<H", ids[name]) + digest
        out += struct.pack("<I", len(ev["data"])) + ev["data"]
    return bytes(out)


def fold(events):
    acc = b"\x00" * 32
    for ev in events:
        acc = hashlib.sha256(acc + ev["digests"]["sha256"]).digest()
    return acc.hex()


def synthetic_installer(installed):
    """UKI-direct installer path: config events, separator, ONE db authority.
    Flagged synthetic-test: no installer-path log of this unit was captured."""
    blob = base64.b64decode(installed["pcr7"]["eventlog_pcr7_b64"])
    header = blob[:32 + struct.unpack_from("<I", blob, 28)[0]]
    events = policy.parse_eventlog(blob)
    kept = events[:6] + [events[6]]
    assert policy.variable_name(events[6]) == "db"
    log = encode_log(header, kept)
    snap = json.loads(json.dumps(installed))
    snap["origin"] = "synthetic-test"
    snap["path"] = "installer"
    snap["pcr7"].update(value=fold(kept), eventlog_pcr7_b64=base64.b64encode(log).decode(),
                        eventlog_pcr7_sha256=sha256(log))
    return snap


class Keys:
    """Throw-away RSA keys, generated per run. No key material is committed."""
    def __init__(self, root):
        self.root = pathlib.Path(root)

    def make(self, name):
        key = self.root / f"{name}.key"
        pub = self.root / f"{name}.pub.pem"
        openssl("genrsa", "-out", str(key), "2048")
        openssl("rsa", "-in", str(key), "-pubout", "-out", str(pub))
        return key, pub


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = pathlib.Path(tempfile.mkdtemp(prefix="ni-bench-test."))
        cls.keys = Keys(cls.tmp)
        cls.owner_key, cls.owner_pub = cls.keys.make("owner")
        cls.other_key, cls.other_pub = cls.keys.make("other")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def sign(self, sheet, key=None):
        payload = tool.sheet_payload(sheet)
        return openssl("dgst", "-sha256", "-sign", str(key or self.owner_key), data=payload).stdout

    def good_record(self):
        installed = capture_installed()
        installer = synthetic_installer(installed)
        return installer, installed, tool.build_record(installer, installed)


class SnapshotFromEvidence(Base):
    def test_snapshot_of_the_67_evidence_is_valid_and_carries_the_live_pcr7(self):
        snap = capture_installed()
        tool.validate_snapshot(snap)
        self.assertEqual(snap["pcr7"]["value"], LIVE_PCR7)
        self.assertEqual(snap["firmware"]["bios_version"], BIOS_VERSION)
        self.assertEqual(snap["firmware"]["bios_date"], "2026-03-26")
        self.assertEqual(snap["origin"], "measured")
        self.assertEqual(snap["secure_boot"]["secure_boot"], 1)

    def test_variable_digests_are_the_sha256_of_the_efi_variable_data(self):
        snap = capture_installed()
        for line in (FIX / "efivars.b64").read_text().splitlines():
            key, _, b64 = line.partition(" ")
            name = key.split("-", 1)[0]
            if name == "SbatLevelRT":
                name = "SbatLevelRT"
            data = base64.b64decode(b64)[4:]  # efivarfs: 4 attribute bytes, then data
            self.assertEqual(snap["variables"][name]["sha256"], sha256(data), name)
            self.assertEqual(snap["variables"][name]["size"], len(data), name)

    def test_the_embedded_log_replays_to_the_pcr7_and_holds_only_pcr7(self):
        snap = capture_installed()
        blob = base64.b64decode(snap["pcr7"]["eventlog_pcr7_b64"])
        events = policy.parse_eventlog(blob)
        self.assertEqual({e["pcr"] for e in events}, {7})
        self.assertEqual(fold(events), LIVE_PCR7)
        self.assertEqual(snap["pcr7"]["eventlog_pcr7_sha256"], sha256(blob))

    def test_filtering_a_full_log_drops_the_other_pcrs_and_their_payloads(self):
        blob = (FIX / "eventlog.pcr7-only.bin").read_bytes()
        header = blob[:32 + struct.unpack_from("<I", blob, 28)[0]]
        noise = {"pcr": 5, "type": 0x0D, "digests": {"sha256": b"\xaa" * 32},
                 "data": b"/dev/disk/by-id/SECRETSERIAL"}
        full = encode_log(header, [noise] + policy.parse_eventlog(blob))
        snap = tool.capture(**dict(evidence_inputs(), eventlog=None, eventlog_bytes=full,
                                   path="installed", captured_at=WHEN))
        self.assertNotIn(b"SECRETSERIAL", base64.b64decode(snap["pcr7"]["eventlog_pcr7_b64"]))
        self.assertEqual(snap["pcr7"]["value"], LIVE_PCR7)
        self.assertEqual(snap["pcr7"]["eventlog_full_sha256"], sha256(full))

    def test_committed_fixture_is_what_the_tool_produces_from_the_evidence(self):
        committed = json.loads((FIX / "installed.snapshot.json").read_text())
        self.assertEqual(committed, capture_installed())

    def test_setup_mode_absent_from_the_evidence_is_derived_not_invented(self):
        sb = capture_installed()["secure_boot"]
        self.assertEqual((sb["setup_mode"], sb["setup_mode_origin"]), (0, "derived"))
        self.assertIsNone(sb["audit_mode"])
        self.assertIsNone(sb["deployed_mode"])

    def test_the_snapshot_carries_no_serial_hostname_or_ek(self):
        text = json.dumps(capture_installed())
        for word in ("serial", "hostname", "ek_hash", "machine-id"):
            self.assertNotIn(word, text.lower())

    def test_unknown_field_is_refused_by_the_validator(self):
        for place in (lambda s: s, lambda s: s["firmware"], lambda s: s["provenance"]):
            snap = capture_installed()
            place(snap)["serial_number"] = "X"
            with self.assertRaises(tool.BenchError):
                tool.validate_snapshot(snap)


class IncompleteSnapshotsAreRefused(Base):
    def efivars_without(self, tmp, name):
        lines = [l for l in (FIX / "efivars.b64").read_text().splitlines()
                 if not l.startswith(name + "-")]
        path = pathlib.Path(tmp) / "efivars.b64"
        path.write_text("\n".join(lines) + "\n")
        return path

    def test_each_required_variable_is_required(self):
        for name in ("SecureBoot", "PK", "KEK", "db", "dbx"):
            with self.subTest(missing=name), tempfile.TemporaryDirectory() as tmp:
                with self.assertRaisesRegex(tool.BenchError, name):
                    capture_installed(efivars_b64=self.efivars_without(tmp, name))

    def test_secure_boot_disabled_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            lines = []
            for l in (FIX / "efivars.b64").read_text().splitlines():
                if l.startswith("SecureBoot-"):
                    k, _, _v = l.partition(" ")
                    l = k + " " + base64.b64encode(b"\x06\x00\x00\x00\x00").decode()
                lines.append(l)
            path = pathlib.Path(tmp) / "efivars.b64"
            path.write_text("\n".join(lines) + "\n")
            with self.assertRaisesRegex(tool.BenchError, "SecureBoot"):
                capture_installed(efivars_b64=path)

    def test_empty_pk_is_setup_mode_and_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            lines = []
            for l in (FIX / "efivars.b64").read_text().splitlines():
                if l.startswith("PK-"):
                    k, _, _v = l.partition(" ")
                    l = k + " " + base64.b64encode(b"\x27\x00\x00\x00").decode()
                lines.append(l)
            path = pathlib.Path(tmp) / "efivars.b64"
            path.write_text("\n".join(lines) + "\n")
            with self.assertRaisesRegex(tool.BenchError, "PK"):
                capture_installed(efivars_b64=path)

    def test_a_captured_setup_mode_of_one_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "efivars.b64"
            path.write_text((FIX / "efivars.b64").read_text()
                            + "SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c "
                            + base64.b64encode(b"\x06\x00\x00\x00\x01").decode() + "\n")
            with self.assertRaisesRegex(tool.BenchError, "SetupMode"):
                capture_installed(efivars_b64=path)

    def test_a_captured_setup_mode_of_zero_is_recorded_as_captured(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "efivars.b64"
            path.write_text((FIX / "efivars.b64").read_text()
                            + "SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c "
                            + base64.b64encode(b"\x06\x00\x00\x00\x00").decode() + "\n")
            sb = capture_installed(efivars_b64=path)["secure_boot"]
            self.assertEqual((sb["setup_mode"], sb["setup_mode_origin"]), (0, "captured"))

    def test_pcr7_that_the_log_does_not_replay_to_is_refused(self):
        wrong = "sha256:\n  7 : 0x" + "AB" * 32 + "\n"
        with self.assertRaisesRegex(tool.BenchError, "replay"):
            capture_installed(pcr7_text=wrong)

    def test_a_missing_pcr7_value_is_refused(self):
        with self.assertRaisesRegex(tool.BenchError, "PCR 7"):
            capture_installed(pcr7_text="SecureBoot enabled\n")

    def test_missing_bios_version_or_date_is_refused(self):
        for field in ("bios_version", "bios_date"):
            with self.subTest(field=field), self.assertRaisesRegex(tool.BenchError, field):
                capture_installed(**{field: ""})

    def test_unparseable_bios_date_is_refused(self):
        with self.assertRaisesRegex(tool.BenchError, "bios_date"):
            capture_installed(bios_date="last tuesday")

    def test_a_log_without_pcr7_events_is_refused(self):
        blob = (FIX / "eventlog.pcr7-only.bin").read_bytes()
        header = blob[:32 + struct.unpack_from("<I", blob, 28)[0]]
        with self.assertRaisesRegex(tool.BenchError, "PCR 7"):
            tool.capture(**dict(evidence_inputs(), eventlog=None, eventlog_bytes=header,
                                path="installed", captured_at=WHEN))

    def test_a_truncated_log_is_refused(self):
        blob = (FIX / "eventlog.pcr7-only.bin").read_bytes()[:-5]
        with self.assertRaises(tool.BenchError):
            tool.capture(**dict(evidence_inputs(), eventlog=None, eventlog_bytes=blob,
                                path="installed", captured_at=WHEN))

    def test_a_variable_filed_under_the_wrong_guid_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            text = (FIX / "efivars.b64").read_text().replace(
                "db-d719b2cb-3d3a-4596-a3bc-dad00e67656f",
                "db-8be4df61-93ca-11d2-aa0d-00e098032b8c", 1)
            path = pathlib.Path(tmp) / "efivars.b64"
            path.write_text(text)
            with self.assertRaisesRegex(tool.BenchError, "db"):
                capture_installed(efivars_b64=path)

    def test_unknown_path_name_is_refused(self):
        with self.assertRaisesRegex(tool.BenchError, "path"):
            capture_installed(path="pxe")


class ReferenceRecord(Base):
    def test_record_of_two_paths_is_valid_when_synthetic_is_allowed(self):
        _, _, rec = self.good_record()
        tool.validate_record(rec, allow_synthetic=True)
        self.assertEqual(rec["family_id"], FAMILY)
        self.assertEqual(rec["firmware"]["bios_version"], BIOS_VERSION)
        self.assertEqual(rec["firmware"]["variable_measurement"], "names-only")
        self.assertEqual(rec["paths"]["installed"]["pcr7"], LIVE_PCR7)
        self.assertNotEqual(rec["paths"]["installer"]["pcr7"], LIVE_PCR7)

    def test_the_store_refuses_a_record_with_a_synthetic_path(self):
        _, _, rec = self.good_record()
        with self.assertRaisesRegex(tool.BenchError, "synthetic"):
            tool.validate_record(rec)

    def test_record_lists_the_boot_path_authority_events(self):
        _, _, rec = self.good_record()
        installed = rec["paths"]["installed"]
        self.assertEqual(installed["boot_path"], "shim-grub")
        self.assertEqual([a["name"] for a in installed["authority_events"]],
                         ["db", "SbatLevel", "MokListRT"])
        self.assertEqual([a["name"] for a in rec["paths"]["installer"]["authority_events"]], ["db"])
        self.assertEqual(rec["paths"]["installer"]["boot_path"], "uki-direct")
        for a in installed["authority_events"]:
            self.assertRegex(a["digest"], r"^[0-9a-f]{64}$")

    def test_the_installer_path_matches_the_digits_recorded_on_the_bench_in_september(self):
        # 2026-09-04: a GX10 booting the installer USB logged PCR 7 07bd0bb2…eedd1db
        # (only those digits were kept; mission report P0 installer-USB .67, 2026-09-04).
        # The UKI-direct shape (config + separator + the db certificate) reproduces them.
        _, _, rec = self.good_record()
        pcr7 = rec["paths"]["installer"]["pcr7"]
        self.assertTrue(pcr7.startswith("07bd0bb2") and pcr7.endswith("eedd1db"), pcr7)

    def test_record_carries_blob_digests_of_the_secure_boot_variables(self):
        _, installed, rec = self.good_record()
        for name in ("SecureBoot", "PK", "KEK", "db", "dbx"):
            self.assertEqual(rec["variables"][name]["sha256"], installed["variables"][name]["sha256"])
            self.assertNotIn("data_b64", rec["variables"][name])
        self.assertIn("SbatLevelRT", rec["variables"])

    def test_event_digests_fold_to_each_pcr7(self):
        _, _, rec = self.good_record()
        for path in rec["paths"].values():
            self.assertEqual(fold([{"digests": {"sha256": bytes.fromhex(e["digest"])}}
                                   for e in path["pcr7_events"]]), path["pcr7"])

    def test_a_record_that_misstates_its_pcr7_is_refused(self):
        _, _, rec = self.good_record()
        rec["paths"]["installed"]["pcr7"] = "00" * 32
        with self.assertRaisesRegex(tool.BenchError, "fold"):
            tool.validate_record(rec, allow_synthetic=True)

    def test_a_tampered_event_digest_is_refused(self):
        _, _, rec = self.good_record()
        rec["paths"]["installed"]["pcr7_events"][3]["digest"] = "11" * 32
        with self.assertRaises(tool.BenchError):
            tool.validate_record(rec, allow_synthetic=True)

    def test_record_without_the_installer_path_is_refused(self):
        _, installed, rec = self.good_record()
        del rec["paths"]["installer"]
        with self.assertRaisesRegex(tool.BenchError, "installer"):
            tool.validate_record(rec, allow_synthetic=True)
        with self.assertRaisesRegex(tool.BenchError, "installer"):
            tool.build_record(None, installed)

    def test_record_without_the_installed_path_is_refused(self):
        installer, _, rec = self.good_record()
        del rec["paths"]["installed"]
        with self.assertRaisesRegex(tool.BenchError, "installed"):
            tool.validate_record(rec, allow_synthetic=True)
        with self.assertRaisesRegex(tool.BenchError, "installed"):
            tool.build_record(installer, None)

    def test_paths_captured_on_different_firmware_are_refused(self):
        installer, installed, _ = self.good_record()
        installer["firmware"]["bios_version"] = "GX10DGX.0105.2026.0601.0000"
        with self.assertRaisesRegex(tool.BenchError, "firmware"):
            tool.build_record(installer, installed)

    def test_paths_with_different_secure_boot_variables_are_refused(self):
        installer, installed, _ = self.good_record()
        installer["variables"]["dbx"]["sha256"] = "22" * 32
        installer["variables"]["dbx"]["data_b64"] = base64.b64encode(b"x").decode()
        installer["variables"]["dbx"]["size"] = 1
        with self.assertRaisesRegex(tool.BenchError, "dbx"):
            tool.build_record(installer, installed)

    def test_two_snapshots_of_the_same_path_are_refused(self):
        installed = capture_installed()
        with self.assertRaisesRegex(tool.BenchError, "installer"):
            tool.build_record(installed, installed)

    def test_family_id_must_match_the_firmware_version(self):
        _, _, rec = self.good_record()
        rec["family_id"] = "gx10dgx-0999"
        with self.assertRaisesRegex(tool.BenchError, "family_id"):
            tool.validate_record(rec, allow_synthetic=True)

    def test_record_refuses_unknown_fields(self):
        _, _, rec = self.good_record()
        rec["paths"]["installed"]["serial"] = "X"
        with self.assertRaises(tool.BenchError):
            tool.validate_record(rec, allow_synthetic=True)

    def test_the_installed_path_pcr7_reference_has_the_calculator_schema(self):
        _, _, rec = self.good_record()
        ref = rec["paths"]["installed"]["pcr7_reference"]
        self.assertEqual(ref["schema"], "ni-pcr7-reference/1")
        self.assertEqual(ref["bank"], "sha256")
        self.assertEqual(ref["firmware"], {"variable_measurement": "names-only"})
        self.assertEqual(ref["boot_path"], "shim-grub")
        self.assertEqual(ref["separator_hex"], "00000000")
        self.assertEqual(list(ref["variables"]), ["SecureBoot", "PK", "KEK", "db", "dbx"])
        self.assertEqual([a["name"] for a in ref["authorities"]], ["db", "SbatLevel", "MokListRT"])
        self.assertIn("text", ref["authorities"][1])
        self.assertIn("cert_der_hex", ref["authorities"][0])

    @unittest.skipUnless(NI_PCR7.exists(),
                         "T1's tools/ni-pcr7-calc is not on this branch; set NI_PCR7_TOOL")
    def test_the_record_is_what_the_pcr7_calculator_extracts_and_recomputes(self):
        s = importlib.util.spec_from_file_location("ni_pcr7", NI_PCR7)
        calc = importlib.util.module_from_spec(s)
        s.loader.exec_module(calc)
        installer, installed, rec = self.good_record()
        for snap, name in ((installed, "installed"), (installer, "installer")):
            path = rec["paths"][name]
            blob = base64.b64decode(snap["pcr7"]["eventlog_pcr7_b64"])
            if name == "installed":
                self.assertEqual(path["pcr7_reference"], calc.extract_reference(blob))
            self.assertEqual(calc.compute(path["pcr7_reference"]).pcr7.hex(), path["pcr7"])


class BenchSheet(Base):
    def sheet(self, **kw):
        _, _, rec = self.good_record()
        return rec, tool.make_sheet(rec, seq=kw.pop("seq", 1), issued_at="2026-10-06",
                                    pkfp=tool.pubkey_fingerprint(str(self.owner_pub)), **kw)

    def test_sheet_pins_the_firmware_and_the_expected_pcr7_per_path(self):
        rec, sheet = self.sheet()
        self.assertEqual(sheet["schema"], "ni-bench-sheet/1")
        self.assertEqual(sheet["family_id"], FAMILY)
        self.assertEqual(sheet["firmware_pin"], {"bios_version": BIOS_VERSION, "bios_date": "2026-03-26"})
        self.assertEqual(sheet["expected_pcr7"], {"installer": rec["paths"]["installer"]["pcr7"],
                                                  "installed": LIVE_PCR7})
        self.assertEqual(sheet["reference_record_sha256"], tool.record_digest(rec))
        self.assertEqual(sheet["signer"]["pkfp"], tool.pubkey_fingerprint(str(self.owner_pub)))

    def test_the_signed_payload_is_domain_separated_canonical_json(self):
        _, sheet = self.sheet()
        expected = b"ni-bench-sheet/1\n" + json.dumps(
            sheet, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        self.assertEqual(tool.sheet_payload(sheet), expected)

    def test_sheet_signed_by_the_owner_key_verifies(self):
        rec, sheet = self.sheet()
        tool.verify_sheet(sheet, self.sign(sheet), str(self.owner_pub), rec, allow_synthetic=True)

    def test_sheet_signed_by_the_wrong_key_is_refused(self):
        rec, sheet = self.sheet()
        with self.assertRaisesRegex(tool.BenchError, "signature"):
            tool.verify_sheet(sheet, self.sign(sheet, self.other_key), str(self.owner_pub),
                              rec, allow_synthetic=True)

    def test_sheet_that_names_another_signer_is_refused_even_with_a_good_signature(self):
        rec, _ = self.sheet()
        sheet = tool.make_sheet(rec, seq=1, issued_at="2026-10-06",
                                pkfp=tool.pubkey_fingerprint(str(self.other_pub)))
        with self.assertRaisesRegex(tool.BenchError, "signer"):
            tool.verify_sheet(sheet, self.sign(sheet, self.other_key), str(self.owner_pub),
                              rec, allow_synthetic=True)

    def test_a_signature_over_the_bare_json_is_refused(self):
        rec, sheet = self.sheet()
        bare = json.dumps(sheet, sort_keys=True, separators=(",", ":")).encode()
        sig = openssl("dgst", "-sha256", "-sign", str(self.owner_key), data=bare).stdout
        with self.assertRaisesRegex(tool.BenchError, "signature"):
            tool.verify_sheet(sheet, sig, str(self.owner_pub), rec, allow_synthetic=True)

    def test_a_tampered_sheet_is_refused(self):
        rec, sheet = self.sheet()
        sig = self.sign(sheet)
        sheet["expected_pcr7"]["installed"] = "ab" * 32
        with self.assertRaisesRegex(tool.BenchError, "signature"):
            tool.verify_sheet(sheet, sig, str(self.owner_pub), rec, allow_synthetic=True)

    def test_a_properly_signed_sheet_that_contradicts_its_record_is_refused(self):
        rec, sheet = self.sheet()
        sheet["expected_pcr7"]["installed"] = "ab" * 32
        with self.assertRaisesRegex(tool.BenchError, "expected_pcr7"):
            tool.verify_sheet(sheet, self.sign(sheet), str(self.owner_pub), rec, allow_synthetic=True)

    def test_a_sheet_pinning_other_firmware_than_its_record_is_refused(self):
        rec, sheet = self.sheet()
        sheet["firmware_pin"]["bios_version"] = "GX10DGX.0105.2026.0601.0000"
        with self.assertRaisesRegex(tool.BenchError, "firmware_pin"):
            tool.verify_sheet(sheet, self.sign(sheet), str(self.owner_pub), rec, allow_synthetic=True)

    def test_a_sheet_whose_record_digest_differs_is_refused(self):
        rec, sheet = self.sheet()
        rec["provenance"]["tool_version"] = "tampered"
        with self.assertRaisesRegex(tool.BenchError, "reference_record_sha256"):
            tool.verify_sheet(sheet, self.sign(sheet), str(self.owner_pub), rec, allow_synthetic=True)

    def test_empty_or_garbage_signature_is_refused(self):
        rec, sheet = self.sheet()
        for sig in (b"", b"garbage"):
            with self.subTest(sig=sig), self.assertRaises(tool.BenchError):
                tool.verify_sheet(sheet, sig, str(self.owner_pub), rec, allow_synthetic=True)

    def test_a_sheet_with_a_duplicate_json_key_is_refused(self):
        with self.assertRaisesRegex(tool.BenchError, "duplicate"):
            tool.load_json_strict('{"seq": 1, "seq": 2}')

    def test_a_non_positive_sequence_is_refused(self):
        for seq in (0, -1, True, "1"):
            with self.subTest(seq=seq), self.assertRaises(tool.BenchError):
                self.sheet(seq=seq)


class Store(Base):
    def stage(self):
        """Everything `store` takes, for a record that has NO synthetic path:
        both snapshots are re-labelled measured, which the tests of the store
        use only to exercise the layout and the key check."""
        installer, installed, _ = self.good_record()
        installer["origin"] = "measured"
        rec = tool.build_record(installer, installed)
        sheet = tool.make_sheet(rec, seq=1, issued_at="2026-10-06",
                                pkfp=tool.pubkey_fingerprint(str(self.owner_pub)))
        return installer, installed, rec, sheet

    def put(self, root, **kw):
        installer, installed, rec, sheet = self.stage()
        sig = kw.pop("sig", None) or self.sign(sheet)
        return tool.store(root, rec, sheet, sig, {"installer": installer, "installed": installed},
                          str(self.owner_pub), **kw)

    def test_store_writes_the_layout_and_validate_store_accepts_it(self):
        with tempfile.TemporaryDirectory() as root:
            dest = self.put(root)
            self.assertEqual(pathlib.Path(dest).name, FAMILY)
            names = sorted(p.relative_to(dest).as_posix() for p in pathlib.Path(dest).rglob("*") if p.is_file())
            self.assertEqual(names, ["bench-sheet.json", "bench-sheet.sig", "reference-record.json",
                                     "snapshots/installed.snapshot.json",
                                     "snapshots/installer.snapshot.json"])
            self.assertEqual(tool.validate_store(root, str(self.owner_pub)), [FAMILY])

    def test_store_refuses_a_sheet_signed_by_the_wrong_key_and_writes_nothing(self):
        _, _, _, sheet = self.stage()
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaisesRegex(tool.BenchError, "signature"):
                self.put(root, sig=self.sign(sheet, self.other_key))
            self.assertEqual(os.listdir(root), [])

    def test_store_refuses_a_synthetic_installer_measurement(self):
        installer, installed, _ = self.good_record()
        rec = tool.build_record(installer, installed)
        sheet = tool.make_sheet(rec, seq=1, issued_at="2026-10-06",
                                pkfp=tool.pubkey_fingerprint(str(self.owner_pub)))
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaisesRegex(tool.BenchError, "synthetic"):
                tool.store(root, rec, sheet, self.sign(sheet),
                           {"installer": installer, "installed": installed}, str(self.owner_pub))
            self.assertEqual(os.listdir(root), [])

    def test_store_refuses_an_incomplete_record(self):
        installer, installed, rec, sheet = self.stage()
        del rec["paths"]["installer"]
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaisesRegex(tool.BenchError, "installer"):
                tool.store(root, rec, sheet, self.sign(sheet), {"installed": installed},
                           str(self.owner_pub))
            self.assertEqual(os.listdir(root), [])

    def test_store_refuses_snapshots_that_are_not_the_ones_the_record_was_built_from(self):
        installer, installed, rec, sheet = self.stage()
        installed = json.loads(json.dumps(installed))
        installed["provenance"]["kernel"] = "6.12.1"
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaisesRegex(tool.BenchError, "snapshot"):
                tool.store(root, rec, sheet, self.sign(sheet),
                           {"installer": installer, "installed": installed}, str(self.owner_pub))

    def test_a_replacement_needs_a_higher_sequence(self):
        with tempfile.TemporaryDirectory() as root:
            self.put(root)
            with self.assertRaisesRegex(tool.BenchError, "seq"):
                self.put(root)

    def test_a_higher_sequence_replaces_the_stored_sheet(self):
        installer, installed, rec, _ = self.stage()
        with tempfile.TemporaryDirectory() as root:
            self.put(root)
            sheet2 = tool.make_sheet(rec, seq=2, issued_at="2026-10-07",
                                     pkfp=tool.pubkey_fingerprint(str(self.owner_pub)))
            tool.store(root, rec, sheet2, self.sign(sheet2),
                       {"installer": installer, "installed": installed}, str(self.owner_pub))
            stored = json.loads((pathlib.Path(root) / FAMILY / "bench-sheet.json").read_text())
            self.assertEqual(stored["seq"], 2)

    def test_validate_store_refuses_a_directory_named_after_another_family(self):
        with tempfile.TemporaryDirectory() as root:
            self.put(root)
            os.rename(pathlib.Path(root) / FAMILY, pathlib.Path(root) / "another-family")
            with self.assertRaisesRegex(tool.BenchError, "family"):
                tool.validate_store(root, str(self.owner_pub))

    def test_validate_store_refuses_a_stored_sheet_checked_with_another_key(self):
        with tempfile.TemporaryDirectory() as root:
            self.put(root)
            with self.assertRaises(tool.BenchError):
                tool.validate_store(root, str(self.other_pub))

    def test_validate_store_refuses_a_file_nobody_declared(self):
        with tempfile.TemporaryDirectory() as root:
            dest = self.put(root)
            (pathlib.Path(dest) / "notes.txt").write_text("hello")
            with self.assertRaisesRegex(tool.BenchError, "notes.txt"):
                tool.validate_store(root, str(self.owner_pub))

    def test_validate_store_refuses_a_record_edited_after_signing(self):
        with tempfile.TemporaryDirectory() as root:
            dest = pathlib.Path(self.put(root))
            rec = json.loads((dest / "reference-record.json").read_text())
            rec["provenance"]["tool_version"] = "edited"
            (dest / "reference-record.json").write_text(json.dumps(rec))
            with self.assertRaises(tool.BenchError):
                tool.validate_store(root, str(self.owner_pub))

    def test_validate_store_refuses_a_symlinked_member(self):
        with tempfile.TemporaryDirectory() as root:
            dest = pathlib.Path(self.put(root))
            real = dest / "bench-sheet.json"
            moved = pathlib.Path(root) / "elsewhere.json"
            shutil.move(real, moved)
            real.symlink_to(moved)
            with self.assertRaisesRegex(tool.BenchError, "symlink"):
                tool.validate_store(root, str(self.owner_pub))

    def test_an_empty_store_is_refused(self):
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaisesRegex(tool.BenchError, "empty"):
                tool.validate_store(root, str(self.owner_pub))


class CommandLine(Base):
    """The same chain, through the CLI a bench operator and CI would use."""

    def test_capture_build_sheet_sign_store_validate(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = pathlib.Path(tmp)
            ev = evidence_inputs()
            common = ["--efivars-b64", str(ev["efivars_b64"]), "--eventlog", str(ev["eventlog"]),
                      "--pcr7-file", str(FIX / "pcr7-and-state.txt"),
                      "--bios-version", ev["bios_version"], "--bios-date", ev["bios_date"],
                      "--captured-at", WHEN]
            r = cli("capture", "--path", "installed", *common, "--out", str(tmp / "installed.json"))
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(json.loads((tmp / "installed.json").read_text())["pcr7"]["value"], LIVE_PCR7)

            installed = json.loads((tmp / "installed.json").read_text())
            installer = synthetic_installer(installed)
            installer["origin"] = "measured"   # exercise the layout; see Store.stage
            (tmp / "installer.json").write_text(json.dumps(installer))

            r = cli("build-record", "--installer", str(tmp / "installer.json"),
                    "--installed", str(tmp / "installed.json"), "--out", str(tmp / "record.json"))
            self.assertEqual(r.returncode, 0, r.stderr)
            r = cli("make-sheet", "--record", str(tmp / "record.json"), "--seq", "1",
                    "--issued-at", "2026-10-06", "--pubkey", str(self.owner_pub),
                    "--out", str(tmp / "sheet.json"))
            self.assertEqual(r.returncode, 0, r.stderr)
            r = cli("sheet-payload", str(tmp / "sheet.json"), "--out", str(tmp / "payload.bin"))
            self.assertEqual(r.returncode, 0, r.stderr)
            openssl("dgst", "-sha256", "-sign", str(self.owner_key), "-out", str(tmp / "sheet.sig"),
                    str(tmp / "payload.bin"))

            store = tmp / "store"
            store.mkdir()
            args = ["--record", str(tmp / "record.json"), "--sheet", str(tmp / "sheet.json"),
                    "--signature", str(tmp / "sheet.sig"),
                    "--installer-snapshot", str(tmp / "installer.json"),
                    "--installed-snapshot", str(tmp / "installed.json"), "--root", str(store)]
            r = cli("store", *args, "--pubkey", str(self.other_pub))
            self.assertEqual(r.returncode, 1)
            self.assertIn("signature", r.stderr)
            self.assertEqual(os.listdir(store), [])
            r = cli("store", *args, "--pubkey", str(self.owner_pub))
            self.assertEqual(r.returncode, 0, r.stderr)
            r = cli("validate-store", str(store), "--pubkey", str(self.owner_pub))
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn(FAMILY, r.stdout)
            r = cli("validate-store", str(store), "--pubkey", str(self.other_pub))
            self.assertEqual(r.returncode, 1)

    def test_capture_refuses_an_incomplete_snapshot_with_exit_1_and_writes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            ev = evidence_inputs()
            lines = [l for l in (FIX / "efivars.b64").read_text().splitlines() if not l.startswith("db-")]
            (pathlib.Path(tmp) / "e.b64").write_text("\n".join(lines) + "\n")
            out = pathlib.Path(tmp) / "snap.json"
            r = cli("capture", "--path", "installed", "--efivars-b64", str(pathlib.Path(tmp) / "e.b64"),
                    "--eventlog", str(ev["eventlog"]), "--pcr7-file", str(FIX / "pcr7-and-state.txt"),
                    "--bios-version", ev["bios_version"], "--bios-date", ev["bios_date"],
                    "--out", str(out))
            self.assertEqual(r.returncode, 1)
            self.assertIn("db", r.stderr)
            self.assertFalse(out.exists())

    def test_the_tool_holds_no_signing_key_operation(self):
        r = cli("sign")
        self.assertNotEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main()
