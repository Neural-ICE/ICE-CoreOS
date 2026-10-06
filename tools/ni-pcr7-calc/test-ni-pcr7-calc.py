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
import os
import stat
import tempfile
import unittest
import uuid

HERE = pathlib.Path(__file__).resolve().parent
TOOL = HERE / "ni-pcr7-calc.py"
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
        # What the two fixtures SHOW: PK/KEK/db/dbx are logged with a ZERO-length
        # data, with identical digests on two different firmware builds. What
        # that implies for an update is a deduction, pinned by WhatMovesPcr7.
        refs = [pcr7.extract_reference(log_bytes(h)) for h in HOSTS]
        for ref in refs:
            self.assertEqual(ref["firmware"]["variable_measurement"], "names-only")
        digests = [[e.digest for e in pcr7.compute(r).events
                    if e.kind == "config"] for r in refs]
        self.assertEqual(digests[0], digests[1])


class WhatMovesPcr7(unittest.TestCase):
    def reference(self):
        return pcr7.extract_reference(log_bytes("ni67"))

    def test_model_ignores_dbx_data_when_the_firmware_logs_names_only(self):
        # Pins the MODEL, not an observation: in names-only mode `compute`
        # discards data_hex by construction, so this cannot fail. That a real dbx
        # update leaves PCR 7 unmoved is DEDUCED from the zero-length events of
        # the fixtures; no before/after update was ever measured on hardware.
        ref = self.reference()
        base = pcr7.compute(ref).pcr7
        ref["variables"]["dbx"]["data_hex"] = pcr7.esl_append(
            ref["variables"]["dbx"].get("data_hex", ""),
            "00" * 16 + "11" * 32)
        self.assertEqual(pcr7.compute(ref).pcr7, base)

    def test_model_of_a_contents_firmware_moves_with_dbx(self):
        # The model of a firmware that measures contents (TCG PC Client / EDK2):
        # NOT proven on any GB10.
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


class ConfigEventsAreConstantAcrossTheTwoMachines(unittest.TestCase):
    def test_ni63_variables_with_the_authority_events_logged_by_ni67_give_the_live_pcr7_of_ni67(self):
        # What this shows: the config events are identical on the two logs and the
        # encoding is lossless. It is NOT a prediction from certificates: the
        # authority events (including each SignatureOwner GUID and the SBAT text,
        # which are not derivable from a certificate) are taken from the log of
        # the machine being "predicted".
        ref = pcr7.extract_reference(log_bytes("ni63"))
        ref["authorities"] = pcr7.extract_reference(log_bytes("ni67"))["authorities"]
        self.assertEqual(pcr7.compute(ref).pcr7, live("ni67"))
        self.assertNotEqual(pcr7.compute(ref).pcr7, live("ni63"))


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

    def test_uki_direct_with_the_lab_db_entry_matches_the_digits_recorded_for_the_gx10_installer_on_2026_09_04(self):
        # raw_mission_report_to_ingest/REPORT-p0-installer-usb67-seq4-codex-root-20260904-2235.md
        # (physical GX10, installer USB booted from the firmware): "PCR7 live
        # 07bd0bb2…eedd1db et PolicyPCR b83b5281…217937" -- only the first 8 and
        # last 7 hex digits are recorded there, so only those are compared. The
        # calculator is given the db authority entry of the log of the installed
        # system (the lab certificate AND its SignatureOwner GUID, which comes
        # from the log, not from the certificate); no installer log exists.
        ref = pcr7.extract_reference(log_bytes("ni67"))
        ref["boot_path"] = "uki-direct"
        ref["authorities"] = ref["authorities"][:1]
        value = pcr7.compute(ref).pcr7.hex()
        self.assertTrue(value.startswith("07bd0bb2") and value.endswith("eedd1db"), value)
        policy = pcr7.policy.pcr_policy_digest(7, bytes.fromhex(value)).hex()
        self.assertTrue(policy.startswith("b83b5281") and policy.endswith("217937"), policy)

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


class VariableSynthesis(unittest.TestCase):
    def test_an_empty_database_measured_as_contents_is_the_empty_measurement(self):
        names_only = pcr7.extract_reference(log_bytes("ni67"))
        contents = json.loads(json.dumps(names_only))
        contents["firmware"]["variable_measurement"] = "contents"
        for entry in contents["variables"].values():
            entry["data_hex"] = ""
        self.assertEqual(pcr7.compute(contents).pcr7, pcr7.compute(names_only).pcr7)

    def test_an_unknown_variable_in_append_esl_is_refused(self):
        ref = pcr7.extract_reference(log_bytes("ni67"))
        with self.assertRaises(pcr7.Pcr7Error):
            pcr7.compute(ref, append_esl={"dbX": "00"})

    def test_dbt_and_dbr_are_supported_in_log_order(self):
        ref = pcr7.extract_reference(log_bytes("ni67"))
        base = pcr7.compute(ref).pcr7
        ref["variables"]["dbt"] = {}
        ref["variables"]["dbr"] = {}
        self.assertNotEqual(pcr7.compute(ref).pcr7, base)


class Refusals(unittest.TestCase):
    def test_truncated_log_is_refused(self):
        with self.assertRaises(pcr7.policy.EventLogError):
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
        with self.assertRaises(pcr7.policy.EventLogError):
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


class EslEncoding(unittest.TestCase):
    def test_esl_append_writes_one_signature_list_of_the_right_size(self):
        entry = "00" * 16 + "11" * 32  # owner GUID + SHA-256 hash
        esl = bytes.fromhex(pcr7.esl_append("", entry))
        self.assertEqual(esl[:16], uuid.UUID("c1c41626-504c-4092-aca9-41f936934328").bytes_le)
        list_size, header_size, sig_size = struct.unpack_from("<III", esl, 16)
        self.assertEqual((list_size, header_size, sig_size), (28 + 48, 0, 48))
        self.assertEqual(esl[28:], bytes.fromhex(entry))
        self.assertEqual(len(esl), list_size)

    def test_a_second_append_concatenates_lists(self):
        entry = "00" * 16 + "11" * 32
        once = pcr7.esl_append("", entry)
        self.assertEqual(pcr7.esl_append(once, entry), once + once)


class CommandLine(unittest.TestCase):
    def test_an_empty_expected_value_is_refused_not_ignored(self):
        for command in ("replay", "verify"):
            with self.subTest(command=command):
                r = cli(command, str(FIX / "ni67.pcr7-only.eventlog.bin"), "--expect", "")
                self.assertEqual(r.returncode, 1)

    def test_replay_mismatch_exits_1(self):
        r = cli("replay", str(FIX / "ni67.pcr7-only.eventlog.bin"),
                "--expect", live("ni63").hex())
        self.assertEqual(r.returncode, 1)

    def test_append_esl_needs_var_equals_hex(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = pathlib.Path(tmp) / "ref.json"
            cli("extract", str(FIX / "ni67.pcr7-only.eventlog.bin"), "--out", str(out))
            for bad in ("dbx", "dbx=zz", "=00"):
                with self.subTest(bad=bad):
                    self.assertEqual(cli("compute", str(out), "--append-esl", bad).returncode, 1)

    def test_verify_live_reads_the_tpm_through_tpm2_pcrread(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake = pathlib.Path(tmp) / "tpm2_pcrread"
            fake.write_text("#!/bin/sh\nprintf '  sha256:\\n    7 : 0x%s\\n' "
                            + live("ni67").hex().upper() + "\n")
            fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
            env = dict(os.environ, PATH=f"{tmp}:{os.environ['PATH']}")
            r = subprocess.run([sys.executable, "-I", str(TOOL), "verify",
                                str(FIX / "ni67.pcr7-only.eventlog.bin"), "--live"],
                               capture_output=True, text=True, env=env, check=False)
            self.assertEqual(r.returncode, 0, r.stderr)
    def test_verify_succeeds_when_both_proofs_hold(self):
        for host in HOSTS:
            with self.subTest(host=host):
                r = cli("verify", str(FIX / f"{host}.pcr7-only.eventlog.bin"),
                        "--expect", live(host).hex())
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertIn(live(host).hex(), r.stdout)

    def test_verify_refuses_a_wrong_expected_value(self):
        r = cli("verify", str(FIX / "ni67.pcr7-only.eventlog.bin"),
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

    def test_malformed_reference_is_refused_not_a_traceback(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = pathlib.Path(tmp) / "bad.json"
            bad.write_text(json.dumps({"schema": "ni-pcr7-reference/1",
                                       "firmware": {"variable_measurement": "names-only"},
                                       "boot_path": "shim-grub", "variables": {"PK": 3},
                                       "authorities": [{"name": "db"}]}))
            r = cli("compute", str(bad))
            self.assertEqual(r.returncode, 1)
            self.assertNotIn("Traceback", r.stderr)

    def test_compute_append_esl_flag_reports_unchanged_on_names_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = pathlib.Path(tmp) / "ref.json"
            cli("extract", str(FIX / "ni67.pcr7-only.eventlog.bin"), "--out", str(out))
            r = cli("compute", str(out), "--append-esl", "dbx=" + "00" * 16 + "11" * 32)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(r.stdout.split()[0], live("ni67").hex())
            self.assertIn("NAMES only", r.stderr)

    def test_contents_mode_without_the_variable_bytes_is_refused(self):
        # A reference extracted from a names-only log does not carry the ESLs;
        # asking what a contents-measuring firmware would do needs them.
        with tempfile.TemporaryDirectory() as tmp:
            out = pathlib.Path(tmp) / "ref.json"
            cli("extract", str(FIX / "ni67.pcr7-only.eventlog.bin"), "--out", str(out))
            r = cli("compute", str(out), "--variable-measurement", "contents")
            self.assertEqual(r.returncode, 1)
            self.assertIn("data_hex", r.stderr)


def first_pcr7_event_offset(blob):
    return 32 + struct.unpack_from("<I", blob, 28)[0]


class ReplayBindsEventData(unittest.TestCase):
    """`replay --expect` must not accept a log whose event DATA was altered:
    the logged digest is only trusted once it is H(data)."""

    def flipped_data(self, host):
        # The last byte of the log is the last byte of the last event's data.
        blob = bytearray(log_bytes(host))
        blob[-1] ^= 0x01
        return bytes(blob)

    def test_replay_refuses_data_that_is_not_the_logged_digest_preimage(self):
        for host in HOSTS:
            with self.subTest(host=host):
                with self.assertRaises(pcr7.Pcr7Error):
                    pcr7.replay_log(self.flipped_data(host))

    def test_replay_expect_exits_1_on_altered_event_data(self):
        for host in HOSTS:
            with self.subTest(host=host), tempfile.TemporaryDirectory() as tmp:
                path = pathlib.Path(tmp) / "log.bin"
                path.write_bytes(self.flipped_data(host))
                r = cli("replay", str(path), "--expect", live(host).hex())
                self.assertEqual(r.returncode, 1)
                self.assertNotIn("Traceback", r.stderr)

    def test_every_data_byte_of_every_event_is_bound(self):
        blob = log_bytes("ni67")
        events = pcr7.policy.parse_eventlog(blob)
        # Walk the log to find each event's data span, flip one bit in each.
        off, spans = first_pcr7_event_offset(blob), []
        for ev in events:
            off += 12 + len(ev["digests"]) * 34 + 4
            spans.append((off, off + len(ev["data"])))
            off += len(ev["data"])
        self.assertEqual(off, len(blob))
        for start, end in spans:
            for position in (start, (start + end) // 2, end - 1):
                mutated = bytearray(blob)
                mutated[position] ^= 0x80
                with self.subTest(position=position), self.assertRaises(pcr7.Pcr7Error):
                    pcr7.replay_log(bytes(mutated))

    def test_the_event_type_is_not_bound_by_replay_but_verify_refuses_it(self):
        # Documented limit: a digest hashes the event data only, so the event
        # TYPE (and the PCR index) of a PCR 7 event is not bound by replay.
        blob = bytearray(log_bytes("ni67"))
        blob[first_pcr7_event_offset(blob) + 4] ^= 0x01  # type 0x80000001 -> 0x80000000
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "log.bin"
            path.write_bytes(bytes(blob))
            self.assertEqual(cli("replay", str(path), "--expect", live("ni67").hex()).returncode, 0)
            self.assertEqual(cli("verify", str(path), "--expect", live("ni67").hex()).returncode, 1)


class HeaderIsValidated(unittest.TestCase):
    def mutated(self, offset, bit=0x01):
        blob = bytearray(log_bytes("ni67"))
        blob[offset] ^= bit
        return bytes(blob)

    def test_the_spec_id_header_fields_that_matter_are_checked(self):
        blob = log_bytes("ni67")
        header_len = first_pcr7_event_offset(blob)
        # legacy record pcr, type, the 20-byte digest, then the spec-id signature,
        # spec major version, algorithm count and the listed algorithm id/size.
        offsets = [0, 4, 8, 27, 32, 47, 32 + 21, 32 + 24, 32 + 28, 32 + 30, header_len - 1]
        for offset in offsets:
            with self.subTest(offset=offset):
                with self.assertRaises((pcr7.Pcr7Error, pcr7.policy.EventLogError)):
                    pcr7.replay_log(self.mutated(offset))

    def test_a_clean_header_still_replays(self):
        for host in HOSTS:
            self.assertEqual(pcr7.replay_log(log_bytes(host)), live(host))


class Limits(unittest.TestCase):
    def test_the_signature_owner_of_an_authority_is_an_input_of_pcr7(self):
        # It is logged, not derivable from the certificate: a prediction must be
        # given it (it comes from the log of a machine that did the boot).
        ref = pcr7.extract_reference(log_bytes("ni67"))
        base = pcr7.compute(ref).pcr7
        ref["authorities"][0]["signature_owner"] = str(uuid.uuid4())
        self.assertNotEqual(pcr7.compute(ref).pcr7, base)

    def test_names_only_logs_are_flagged_by_replay_verify_and_compute(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = pathlib.Path(tmp) / "ref.json"
            log = str(FIX / "ni67.pcr7-only.eventlog.bin")
            cli("extract", log, "--out", str(out))
            runs = (cli("replay", log, "--expect", live("ni67").hex()),
                    cli("verify", log, "--expect", live("ni67").hex()),
                    cli("compute", str(out)))
            for r in runs:
                with self.subTest(argv=r.args[3]):
                    self.assertEqual(r.returncode, 0, r.stderr)
                    self.assertIn("NOT evidence", r.stderr)
                    self.assertIn("SecureBoot", r.stderr)
                    self.assertIn("dbx", r.stderr)

    def test_replay_without_expect_says_that_nothing_was_compared(self):
        r = cli("replay", str(FIX / "ni67.pcr7-only.eventlog.bin"))
        self.assertEqual(r.returncode, 0)
        self.assertIn("nothing was compared", r.stderr)


class RobustInputs(unittest.TestCase):
    def test_filter_log_of_a_too_short_log_is_refused_not_a_traceback(self):
        with tempfile.TemporaryDirectory() as tmp:
            for size in (0, 2, 31):
                with self.subTest(size=size):
                    src = pathlib.Path(tmp) / "short.bin"
                    src.write_bytes(b"\x00" * size)
                    r = cli("filter-log", str(src), "--out", str(pathlib.Path(tmp) / "o.bin"))
                    self.assertEqual(r.returncode, 1)
                    self.assertNotIn("Traceback", r.stderr)

    def test_deeply_nested_json_is_refused_not_a_traceback(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = pathlib.Path(tmp) / "deep.json"
            bad.write_text("[" * 200000)
            r = cli("compute", str(bad))
            self.assertEqual(r.returncode, 1)
            self.assertNotIn("Traceback", r.stderr)

    def test_duplicate_json_keys_are_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = pathlib.Path(tmp) / "ref.json"
            cli("extract", str(FIX / "ni67.pcr7-only.eventlog.bin"), "--out", str(out))
            text = out.read_text().replace('"boot_path"', '"boot_path": "custom", "boot_path"', 1)
            dup = pathlib.Path(tmp) / "dup.json"
            dup.write_text(text)
            r = cli("compute", str(dup))
            self.assertEqual(r.returncode, 1)
            self.assertIn("duplicate", r.stderr)

    def test_a_misspelt_key_is_refused_not_defaulted(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = pathlib.Path(tmp) / "ref.json"
            cli("extract", str(FIX / "ni67.pcr7-only.eventlog.bin"), "--out", str(out))
            ref = json.loads(out.read_text())
            typo = dict(ref, separator_hexx=ref["separator_hex"])
            del typo["separator_hex"]
            for label, bad in (
                    ("top-level", typo),
                    ("authority", dict(ref, authorities=[dict(ref["authorities"][0],
                                                              signature_ower="x")]
                                       + ref["authorities"][1:])),
                    ("variable", dict(ref, variables={**ref["variables"],
                                                      "PK": {"guid": ref["variables"]["PK"]["guid"],
                                                             "data_hexx": ""}}))):
                with self.subTest(where=label):
                    path = pathlib.Path(tmp) / f"{label}.json"
                    path.write_text(json.dumps(bad))
                    r = cli("compute", str(path))
                    self.assertEqual(r.returncode, 1)
                    self.assertIn("unknown key", r.stderr)


if __name__ == "__main__":
    unittest.main()
