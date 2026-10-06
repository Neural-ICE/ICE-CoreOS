#!/usr/bin/env python3
"""Tests of the offline PCR 7 calculator against two real GB10 event logs.

The fixtures are PCR-7-only derivatives of the TCG2 event logs of two physical
GB10 machines, with the live PCR 7 read from the TPM at the same boot. Nothing
here mocks the arithmetic: the expected values come from the hardware.
"""
import hashlib
import importlib.util
import json
import pathlib
import struct
import subprocess
import sys
import tempfile
import unittest
import uuid

HERE = pathlib.Path(__file__).resolve().parent
TOOL = HERE / "ni-pcr7.py"
FIX = HERE / "fixtures"
EXPECTED = json.loads((FIX / "expected.json").read_text())["hosts"]

spec = importlib.util.spec_from_file_location("ni_pcr7", TOOL)
pcr7 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pcr7)

HOSTS = ("ni63", "ni67")


def log_bytes(host):
    return (FIX / f"{host}.pcr7-only.eventlog.bin").read_bytes()


def live(host):
    return bytes.fromhex(EXPECTED[host]["live_pcr7_sha256"])


def cli(*args):
    return subprocess.run([sys.executable, "-I", str(TOOL), *args],
                          capture_output=True, text=True, check=False)


class ReplayAgainstHardware(unittest.TestCase):
    def test_replay_reproduces_the_live_pcr7_of_each_host(self):
        for host in HOSTS:
            with self.subTest(host=host):
                self.assertEqual(pcr7.replay_log(log_bytes(host)), live(host))

    def test_the_two_hosts_have_different_pcr7(self):
        self.assertNotEqual(live("ni63"), live("ni67"))


class ComputeFromExtract(unittest.TestCase):
    def test_compute_of_extract_reproduces_the_live_pcr7(self):
        for host in HOSTS:
            with self.subTest(host=host):
                ref = pcr7.extract_reference(log_bytes(host))
                self.assertEqual(pcr7.compute(ref).pcr7, live(host))

    def test_extract_survives_a_json_round_trip(self):
        ref = pcr7.extract_reference(log_bytes("ni67"))
        again = json.loads(json.dumps(ref))
        self.assertEqual(pcr7.compute(again).pcr7, live("ni67"))

    def test_boot_path_is_recognised(self):
        for host in HOSTS:
            self.assertEqual(
                pcr7.extract_reference(log_bytes(host))["boot_path"], "shim-grub")

    def test_gb10_firmware_measures_variable_names_only(self):
        # The measured finding: PK/KEK/db/dbx are logged with a ZERO-length
        # data, identically on two different firmware builds.
        refs = [pcr7.extract_reference(log_bytes(h)) for h in HOSTS]
        for ref in refs:
            self.assertEqual(ref["firmware"]["variable_measurement"], "names-only")
        digests = [[e.digest for e in pcr7.compute(r).events
                    if e.kind == "config"] for r in refs]
        self.assertEqual(digests[0], digests[1])


class WhatMovesPcr7(unittest.TestCase):
    def reference(self):
        return pcr7.extract_reference(log_bytes("ni67"))

    def test_dbx_append_is_invisible_on_names_only_firmware(self):
        ref = self.reference()
        base = pcr7.compute(ref).pcr7
        ref["variables"]["dbx"]["data_hex"] = pcr7.esl_append(
            ref["variables"]["dbx"].get("data_hex", ""),
            "00" * 16 + "11" * 32)
        self.assertEqual(pcr7.compute(ref).pcr7, base)

    def test_dbx_append_changes_pcr7_when_the_firmware_measures_contents(self):
        ref = self.reference()
        ref["firmware"]["variable_measurement"] = "contents"
        for name in ("SecureBoot", "PK", "KEK", "db", "dbx"):
            ref["variables"][name]["data_hex"] = ref["variables"][name].get(
                "data_hex", "01" if name == "SecureBoot" else "")
        base = pcr7.compute(ref).pcr7
        ref["variables"]["dbx"]["data_hex"] = pcr7.esl_append(
            ref["variables"]["dbx"]["data_hex"], "00" * 16 + "11" * 32)
        self.assertNotEqual(pcr7.compute(ref).pcr7, base)

    def test_a_different_shim_verifying_db_certificate_changes_pcr7(self):
        ref = self.reference()
        other = json.loads(json.dumps(ref))
        other["authorities"][0]["cert_der_hex"] = \
            pcr7.extract_reference(log_bytes("ni63"))["authorities"][0]["cert_der_hex"]
        self.assertNotEqual(pcr7.compute(ref).pcr7, pcr7.compute(other).pcr7)

    def test_sbat_level_changes_pcr7(self):
        ref = self.reference()
        base = pcr7.compute(ref).pcr7
        sbat = next(a for a in ref["authorities"] if a["name"] == "SbatLevel")
        sbat["text"] = sbat["text"].replace("2024040900", "2025010900")
        self.assertNotEqual(pcr7.compute(ref).pcr7, base)

    def test_vendor_certificate_changes_pcr7(self):
        ref = self.reference()
        base = pcr7.compute(ref).pcr7
        mok = next(a for a in ref["authorities"] if a["name"] == "MokListRT")
        mok["cert_der_hex"] = mok["cert_der_hex"][:-2] + "00"
        self.assertNotEqual(pcr7.compute(ref).pcr7, base)

    def test_separator_changes_pcr7(self):
        ref = self.reference()
        base = pcr7.compute(ref).pcr7
        ref["separator_hex"] = "ffffffff"
        self.assertNotEqual(pcr7.compute(ref).pcr7, base)


class InstallerMediumPath(unittest.TestCase):
    """Firmware -> signed UKI directly. No real GB10 log exists for it yet, so
    this pins the structure the calculator emits, with arithmetic written out
    independently of the tool (TCG PC Client: one authority event per image the
    firmware verifies, then nothing from shim)."""

    def test_uki_direct_extends_exactly_the_config_separator_and_one_authority(self):
        ref = pcr7.extract_reference(log_bytes("ni67"))
        db = ref["authorities"][0]
        ref["boot_path"] = "uki-direct"
        ref["authorities"] = [db]
        guid_db = uuid.UUID("d719b2cb-3d3a-4596-a3bc-dad00e67656f").bytes_le
        owner = uuid.UUID(db["signature_owner"]).bytes_le
        name = "db".encode("utf-16-le")
        data = owner + bytes.fromhex(db["cert_der_hex"])
        authority = (guid_db + struct.pack("<QQ", 2, len(data)) + name + data)
        acc = b"\x00" * 32
        for event in [e.data for e in pcr7.compute(
                pcr7.extract_reference(log_bytes("ni67"))).events
                if e.kind in ("config", "separator")] + [authority]:
            acc = hashlib.sha256(acc + hashlib.sha256(event).digest()).digest()
        self.assertEqual(pcr7.compute(ref).pcr7, acc)

    def test_uki_direct_differs_from_shim_grub_on_the_same_firmware(self):
        shim = pcr7.extract_reference(log_bytes("ni67"))
        uki = json.loads(json.dumps(shim))
        uki["boot_path"] = "uki-direct"
        uki["authorities"] = uki["authorities"][:1]
        self.assertNotEqual(pcr7.compute(shim).pcr7, pcr7.compute(uki).pcr7)

    def test_boot_path_shape_is_enforced(self):
        ref = pcr7.extract_reference(log_bytes("ni67"))
        ref["boot_path"] = "uki-direct"  # still carries SbatLevel + MokListRT
        with self.assertRaises(pcr7.Pcr7Error):
            pcr7.compute(ref)


class Refusals(unittest.TestCase):
    def test_truncated_log_is_refused(self):
        with self.assertRaises(Exception):
            pcr7.replay_log(log_bytes("ni67")[:-7])

    def test_log_whose_digest_is_not_the_hash_of_its_data_is_refused_by_extract(self):
        blob = bytearray(log_bytes("ni67"))
        blob[-1] ^= 0x01  # last byte of the last event's data
        with self.assertRaises(pcr7.Pcr7Error):
            pcr7.extract_reference(bytes(blob))

    def test_unknown_boot_path_is_refused(self):
        ref = pcr7.extract_reference(log_bytes("ni67"))
        ref["boot_path"] = "pxe"
        with self.assertRaises(pcr7.Pcr7Error):
            pcr7.compute(ref)

    def test_non_sha256_bank_is_refused(self):
        ref = pcr7.extract_reference(log_bytes("ni67"))
        ref["bank"] = "sha1"
        with self.assertRaises(pcr7.Pcr7Error):
            pcr7.compute(ref)

    def test_log_without_pcr7_events_is_refused(self):
        blob = log_bytes("ni67")
        header = blob[:32 + struct.unpack_from("<I", blob, 28)[0]]
        with self.assertRaises(Exception):
            pcr7.replay_log(header)


class FilterLog(unittest.TestCase):
    def test_filter_keeps_only_pcr7_and_still_replays(self):
        blob = log_bytes("ni63")
        header_len = 32 + struct.unpack_from("<I", blob, 28)[0]
        noise = struct.pack("<III", 8, 0x0D, 1) + struct.pack("<H", 0x000B) \
            + b"\xaa" * 32 + struct.pack("<I", 6) + b"secret"
        mixed = blob[:header_len] + noise + blob[header_len:]
        filtered = pcr7.filter_log(mixed, 7)
        self.assertEqual(filtered, blob)
        self.assertNotIn(b"secret", filtered)


class CommandLine(unittest.TestCase):
    def test_check_succeeds_when_both_proofs_hold(self):
        for host in HOSTS:
            with self.subTest(host=host):
                r = cli("check", str(FIX / f"{host}.pcr7-only.eventlog.bin"),
                        "--expect", live(host).hex())
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertIn(live(host).hex(), r.stdout)

    def test_check_refuses_a_wrong_expected_value(self):
        r = cli("check", str(FIX / "ni67.pcr7-only.eventlog.bin"),
                "--expect", live("ni63").hex())
        self.assertEqual(r.returncode, 1)
        self.assertIn("NOT", r.stderr)

    def test_extract_then_compute_via_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = pathlib.Path(tmp) / "ref.json"
            r = cli("extract", str(FIX / "ni63.pcr7-only.eventlog.bin"), "--out", str(out))
            self.assertEqual(r.returncode, 0, r.stderr)
            r = cli("compute", str(out))
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(r.stdout.split()[0], live("ni63").hex())

    def test_compute_append_esl_flag_reports_unchanged_on_names_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = pathlib.Path(tmp) / "ref.json"
            cli("extract", str(FIX / "ni67.pcr7-only.eventlog.bin"), "--out", str(out))
            r = cli("compute", str(out), "--append-esl", "dbx=" + "00" * 16 + "11" * 32)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(r.stdout.split()[0], live("ni67").hex())

    def test_contents_mode_without_the_variable_bytes_is_refused(self):
        # A reference extracted from a names-only log does not carry the ESLs;
        # asking what a contents-measuring firmware would do needs them.
        with tempfile.TemporaryDirectory() as tmp:
            out = pathlib.Path(tmp) / "ref.json"
            cli("extract", str(FIX / "ni67.pcr7-only.eventlog.bin"), "--out", str(out))
            r = cli("compute", str(out), "--variable-measurement", "contents")
            self.assertEqual(r.returncode, 1)
            self.assertIn("data_hex", r.stderr)


if __name__ == "__main__":
    unittest.main()
