#!/usr/bin/env python3
"""Tests of ni-support-verify, the Owner-side reader of a support bundle.

The bundles are built here, by a producer that is independent of the tool
(python tarfile + openssl). The signing key and the age identity are generated per
run: no key, no serial and no customer content is committed. Every planted
"customer" string is synthetic.

What the tool must refuse is tested through its command line, the seam the Owner
uses. The canary tests plant customer-content strings in realistic positions and
require the tool to find them (and never to echo them back).
"""
import gzip
import hashlib
import importlib.util
import io
import json
import os
import pathlib
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import unicodedata
import unittest
import zipfile

HERE = pathlib.Path(__file__).resolve().parent
TOOL = HERE / "ni-support-verify.py"
ANCHOR_SCRIPT = HERE.parents[1] / "ota" / "neural-ice-access-profile-anchor.sh"

SCHEMA = "neural-ice-support-bundle-v1"
DOMAIN = SCHEMA.encode() + b"\x00"

# Synthetic stand-ins for customer content: none of these is a real name, address or key.
CANARY_DOC = "Dossier-Succession-Dupont-SA-7731"
CANARY_QUERY = "résumé du contrat Müller & Fils, clause 14"
CANARY_MAIL = "marie.canari@cabinet-exemple.example"
CANARY_LICENCE = "LIC-CANARI-0000-1111-2222-3333"
CANARY_DEVICE = "MacBook-de-Marie-Canari"
CANARIES = [CANARY_DOC, CANARY_QUERY, CANARY_LICENCE, CANARY_DEVICE]

SECTIONS = {
    "identity.json": b'{"device_id":"d-0001","hostname":"ni-spark","os_version":"0.50.37"}',
    "units.json": b'{"neural-ice-license-gate.service":{"ActiveState":"active","NRestarts":0}}',
    "journal-host.jsonl": (
        b'{"ts":"2026-10-06T10:12:13Z","unit":"neural-ice-ota.service","prio":4,"message":"retry 2/5 after 12:34:56"}\n'
        b'{"ts":"2026-10-06T10:12:14Z","unit":"user@1000.service","prio":3,"message":"nvidia-smi 580.95.05 on 6.17.0-1008-nvidia"}\n'
    ),
}


def run(*args, env=None, cwd=None):
    return subprocess.run([sys.executable, "-I", str(TOOL), *map(str, args)],
                          capture_output=True, text=True, check=False, stdin=subprocess.DEVNULL,
                          env=env, cwd=cwd)


def openssl(*args, stdin=None):
    return subprocess.run(["openssl", *map(str, args)], input=stdin, capture_output=True, check=True).stdout


def new_ec_key(directory, name="dev"):
    key = pathlib.Path(directory) / f"{name}.key.pem"
    openssl("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", key)
    return key


def new_rsa_key(directory, name="rsa"):
    key = pathlib.Path(directory) / f"{name}.key.pem"
    openssl("genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", key)
    return key


def spki_der(key):
    return openssl("pkey", "-in", key, "-pubout", "-outform", "DER")


def sign(key, message):
    return openssl("dgst", "-sha256", "-sign", key, stdin=message)


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def sha(data):
    return hashlib.sha256(data).hexdigest()


GENERATED_AT = "2026-10-06T12:00:00Z"
EPOCH = 1791288000  # 2026-10-06T12:00:00Z


def tar_member(name, data=b"", *, type_=tarfile.REGTYPE, linkname="", mode=0o644, mtime=EPOCH):
    ti = tarfile.TarInfo(name)
    ti.size = len(data) if type_ == tarfile.REGTYPE else 0
    ti.type, ti.linkname, ti.mode, ti.mtime = type_, linkname, mode, mtime
    ti.uid = ti.gid = 0
    ti.uname = ti.gname = ""
    return ti, data


def make_tar(members, fmt=tarfile.USTAR_FORMAT):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=fmt) as tf:
        for ti, data in members:
            tf.addfile(ti, io.BytesIO(data) if ti.type == tarfile.REGTYPE else None)
    return buf.getvalue()


def make_gz(raw):
    return gzip.compress(raw, 9, mtime=0)


class Producer:
    """One bundle, assembled the way the host collector will, with hooks to corrupt it."""

    def __init__(self, tmp, files=None):
        self.tmp = pathlib.Path(tmp)
        self.key = new_ec_key(self.tmp)
        self.files = dict(SECTIONS if files is None else files)
        self.spki = spki_der(self.key)
        self.pin = sha(self.spki)

    def manifest(self, **over):
        m = {
            "schema": SCHEMA,
            "bundle_id": "0123456789abcdef0123456789abcdef",
            "case_id": "BETA-12",
            "generated_at": GENERATED_AT,
            "time_source": "host_clock",
            "boot_id": "fedcba98-7654-3210-fedc-ba9876543210",
            "files": [{"path": p, "size": len(d), "sha256": sha(d)} for p, d in sorted(self.files.items())],
            "sections": {"identity": {"included": True, "status": "ok"},
                         "journals": {"included": True, "status": "ok"},
                         "app_excerpts": {"included": False, "status": "declined"}},
            "dropped": {"journal-app": 3},
            "truncated": {"journal-host": False},
            "redaction": {"email": 0},
            "device_root_spki_sha256": self.pin,
            "collector_version": "1.0.0",
        }
        m.update(over)
        return m

    def build(self, *, manifest=None, manifest_bytes=None, signed_with=None, domain=DOMAIN, signature=None,
              spki=None, members=None, extra=(), drop=(), tar_fmt=tarfile.USTAR_FORMAT, mutate_raw=None,
              gz_wrap=make_gz):
        """-> bytes of the tar.gz."""
        mbytes = manifest_bytes if manifest_bytes is not None else canonical(self.manifest() if manifest is None else manifest)
        sig = signature if signature is not None else sign(signed_with or self.key, domain + mbytes)
        entries = [("manifest.json", mbytes), ("manifest.sig", sig),
                   ("device-root.spki.der", self.spki if spki is None else spki)]
        entries += list(self.files.items())
        entries = [(n, d) for n, d in entries if n not in drop]
        entries = sorted(entries)
        tar_members = [tar_member(n, d) for n, d in entries] if members is None else members
        tar_members = list(tar_members) + list(extra)
        raw = make_tar(tar_members, tar_fmt)
        if mutate_raw:
            raw = mutate_raw(raw)
        return gz_wrap(raw)

    def write(self, name, data):
        path = self.tmp / name
        path.write_bytes(data)
        return path


class ToolTest(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.tmp = pathlib.Path(self._td.name)
        self.addCleanup(self._td.cleanup)
        self.prod = Producer(self.tmp)

    # helpers ---------------------------------------------------------------
    def verify(self, gz, *extra, pin=None, name="b.tar.gz"):
        path = self.prod.write(name, gz)
        args = ["verify", path, "--format", "json"]
        args += ["--pin-spki-sha256", pin or self.prod.pin] if pin != "" else []
        return run(*args, *extra)

    def verdict(self, proc):
        return json.loads(proc.stdout)

    def failed_check(self, proc):
        verdict = self.verdict(proc)
        bad = [c["name"] for c in verdict["checks"] if not c["ok"]]
        self.assertEqual(len(bad), 1, verdict)
        return bad[0]

    def assertRefused(self, gz, check, *extra, pin=None):
        proc = self.verify(gz, *extra, pin=pin)
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertEqual(self.verdict(proc)["verdict"], "refused")
        self.assertEqual(self.failed_check(proc), check, proc.stdout)


class ValidBundle(ToolTest):
    def test_valid_bundle_is_verified_and_listed(self):
        proc = self.verify(self.prod.build())
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        v = self.verdict(proc)
        self.assertEqual(v["verdict"], "verified")
        self.assertTrue(all(c["ok"] for c in v["checks"]))
        self.assertEqual({f["path"] for f in v["files"]}, set(SECTIONS))
        self.assertEqual(v["bundle"]["bundle_id"], "0123456789abcdef0123456789abcdef")
        self.assertEqual(v["bundle"]["device_root_spki_sha256"], self.prod.pin)
        self.assertEqual(v["findings"], [])

    def test_text_format_lists_files(self):
        path = self.prod.write("b.tar.gz", self.prod.build())
        proc = run("verify", path, "--pin-spki-sha256", self.prod.pin)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("VERIFIED", proc.stdout)
        for name in SECTIONS:
            self.assertIn(name, proc.stdout)

    def test_pin_is_mandatory_and_never_taken_from_the_bundle(self):
        path = self.prod.write("b.tar.gz", self.prod.build())
        proc = run("verify", path)
        self.assertEqual(proc.returncode, 2, proc.stdout)
        self.assertIn("pin", proc.stderr.lower())

    def test_pins_file_and_several_pins(self):
        path = self.prod.write("b.tar.gz", self.prod.build())
        pins = self.tmp / "pins.txt"
        pins.write_text(f"# spark 2\n{'0' * 64}\n{self.prod.pin}  spark-2 ceremony 06.10\n")
        proc = run("verify", path, "--pins-file", pins, "--format", "json")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.verdict(proc)["bundle"]["pin_label"], "spark-2 ceremony 06.10")

    def test_malformed_pin_is_a_usage_error(self):
        path = self.prod.write("b.tar.gz", self.prod.build())
        for bad in ("abc", "G" * 64, "A" * 64):
            proc = run("verify", path, "--pin-spki-sha256", bad)
            self.assertEqual(proc.returncode, 2, bad)

    def test_x_fields_are_ignored_other_unknown_fields_refused(self):
        ok = self.prod.manifest()
        ok["x-collector-note"] = "ignored"
        self.assertEqual(self.verify(self.prod.build(manifest=ok)).returncode, 0)
        bad = self.prod.manifest()
        bad["surprise"] = 1
        self.assertRefused(self.prod.build(manifest=bad), "manifest")

    def test_unsigned_client_block_is_accepted_and_labelled(self):
        self.prod.files["client.json"] = b'{"client_version":"0.50.37","os":"macOS"}'
        manifest = self.prod.manifest()
        manifest["files"] = [f for f in manifest["files"] if f["path"] != "client.json"]
        proc = self.verify(self.prod.build(manifest=manifest))
        self.assertEqual(proc.returncode, 0, proc.stdout)
        v = self.verdict(proc)
        self.assertEqual(v["unsigned"], ["client.json"])
        self.assertNotIn("client.json", [f["path"] for f in v["files"]])

    def test_declined_section_is_reported_and_its_file_is_absent(self):
        proc = self.verify(self.prod.build())
        self.assertEqual(proc.returncode, 0, proc.stdout)
        sections = self.verdict(proc)["bundle"]["sections"]
        self.assertEqual(sections["app_excerpts"], {"included": False, "status": "declined"})
        path = self.prod.write("b.tar.gz", self.prod.build())
        text = run("verify", path, "--pin-spki-sha256", self.prod.pin).stdout
        self.assertIn("section app_excerpts: not included (declined)", text)

    def test_a_file_entry_with_a_per_file_included_flag_is_refused(self):
        manifest = self.prod.manifest()
        manifest["files"][0]["included"] = False
        self.assertRefused(self.prod.build(manifest=manifest), "manifest")

    def test_sections_table_is_validated(self):
        for label, bad in {
            "status": {"x": {"included": True, "status": "fine"}},
            "extra key": {"x": {"included": True, "status": "ok", "why": "y"}},
            "not bool": {"x": {"included": 1, "status": "ok"}},
            "key syntax": {"X-1": {"included": True, "status": "ok"}},
            "not a table": [],
        }.items():
            with self.subTest(label=label):
                self.assertRefused(self.prod.build(manifest=self.prod.manifest(sections=bad)), "manifest")

    def test_fractional_seconds_in_generated_at_are_accepted(self):
        proc = self.verify(self.prod.build(manifest=self.prod.manifest(generated_at="2026-10-06T12:00:00.250000Z")))
        self.assertEqual(proc.returncode, 0, proc.stdout)

    def test_listed_section_missing_from_archive_is_refused(self):
        self.assertRefused(self.prod.build(drop=("units.json",)), "files")

    def test_ordinary_text_has_no_finding(self):
        files = dict(SECTIONS)
        files["journal-host.jsonl"] = (
            b'{"message":"Started getty@tty1.service - Getty on tty1"}\n'
            b'{"message":"icecore_api::api::health: ready in 12.5 ms (v0.50.37, build 6.17.0-1008-nvidia)"}\n'
            b'{"message":"image sha256:' + b"ab" * 32 + b' pulled; at 10:20:30 and 2026-10-06T10:20:30Z"}\n'
            b'{"message":"std::fmt failed; NI-E03 phase 4/7; nvidia-smi 580.95.05; GB10; unit foo.service failed"}\n'
        )
        self.prod.files = files
        proc = self.verify(self.prod.build())
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.verdict(proc)["findings"], [])


class Refusals(ToolTest):
    """Every way a bundle can be wrong ends with a refusal and a non-zero exit."""

    def test_path_traversal(self):
        for name in ("../escape.json", "/etc/passwd", "a/b.json", "..", "UPPER.json", "sp ace.json", "é.json", ".hidden"):
            with self.subTest(name=name):
                gz = self.prod.build(extra=[tar_member(name, b"{}")])
                self.assertRefused(gz, "tar")

    def test_duplicate_entry(self):
        gz = self.prod.build(extra=[tar_member("units.json", self.prod.files["units.json"])])
        self.assertRefused(gz, "tar")

    def test_links_directories_and_devices(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.DIRTYPE, tarfile.FIFOTYPE):
            with self.subTest(kind=kind):
                gz = self.prod.build(extra=[tar_member("link.json", type_=kind, linkname="units.json")])
                self.assertRefused(gz, "tar")

    def test_entry_not_listed_in_the_manifest(self):
        gz = self.prod.build(extra=[tar_member("extra.json", b'{"leak":true}')])
        self.assertRefused(gz, "files")

    def test_content_modified_one_byte(self):
        sections = dict(SECTIONS)
        tampered = bytearray(sections["identity.json"])
        tampered[-3] ^= 0x01
        gz = self.prod.build(members=[
            tar_member(n, d if n != "identity.json" else bytes(tampered))
            for n, d in sorted({**sections, "manifest.json": canonical(self.prod.manifest()),
                                "manifest.sig": sign(self.prod.key, DOMAIN + canonical(self.prod.manifest())),
                                "device-root.spki.der": self.prod.spki}.items())])
        self.assertRefused(gz, "files")

    def test_size_differs_from_manifest(self):
        manifest = self.prod.manifest()
        manifest["files"][0]["size"] += 1
        self.assertRefused(self.prod.build(manifest=manifest), "files")

    def test_manifest_modified_one_byte_after_signing(self):
        good = canonical(self.prod.manifest())
        sig = sign(self.prod.key, DOMAIN + good)
        tampered = good.replace(b'"BETA-12"', b'"BETA-13"')
        self.assertEqual(len(tampered), len(good))
        self.assertRefused(self.prod.build(manifest_bytes=tampered, signature=sig), "signature")

    def test_signature_of_another_domain(self):
        manifest = canonical(self.prod.manifest())
        anchor_domain = re.search(r"ANCHOR_DOMAIN='([^']+)'", ANCHOR_SCRIPT.read_text()).group(1).encode() + b"\x00"
        self.assertNotEqual(anchor_domain, DOMAIN)
        for label, domain in (("access-profile-anchor", anchor_domain), ("no domain", b""),
                              ("v2 domain", b"neural-ice-support-bundle-v2\x00"),
                              ("no NUL", SCHEMA.encode())):
            with self.subTest(domain=label):
                gz = self.prod.build(manifest_bytes=manifest, signature=sign(self.prod.key, domain + manifest))
                self.assertRefused(gz, "signature")

    def test_signature_from_another_device_with_its_own_spki_in_the_bundle(self):
        """A forged bundle carries its own key: it must fail the PIN, not pass on the embedded key."""
        other = new_ec_key(self.tmp, "other")
        other_spki = spki_der(other)
        manifest = self.prod.manifest(device_root_spki_sha256=sha(other_spki))
        gz = self.prod.build(manifest=manifest, signed_with=other, spki=other_spki)
        self.assertRefused(gz, "pin")

    def test_pinned_spki_but_signed_by_another_key(self):
        other = new_ec_key(self.tmp, "other")
        self.assertRefused(self.prod.build(signed_with=other), "signature")

    def test_manifest_spki_differs_from_the_spki_file(self):
        manifest = self.prod.manifest(device_root_spki_sha256="1" * 64)
        self.assertRefused(self.prod.build(manifest=manifest), "spki_binding")

    def test_spki_is_not_a_p256_key(self):
        rsa = new_rsa_key(self.tmp)
        spki = spki_der(rsa)
        manifest = self.prod.manifest(device_root_spki_sha256=sha(spki))
        gz = self.prod.build(manifest=manifest, signed_with=rsa, spki=spki)
        self.assertRefused(gz, "spki", pin=sha(spki))

    def test_garbage_signature(self):
        self.assertRefused(self.prod.build(signature=b"\x30\x03\x02\x01\x01"), "signature")
        self.assertRefused(self.prod.build(signature=b""), "signature")

    def test_missing_envelope_member(self):
        for name in ("manifest.json", "manifest.sig", "device-root.spki.der"):
            with self.subTest(name=name):
                self.assertRefused(self.prod.build(drop=(name,)), "envelope")

    def test_unknown_major_schema(self):
        self.assertRefused(self.prod.build(manifest=self.prod.manifest(schema="neural-ice-support-bundle-v2")), "manifest")

    def test_duplicate_json_keys_in_the_manifest(self):
        manifest = canonical(self.prod.manifest())
        dup = manifest[:-1] + b',"case_id":"EVIL"}'
        gz = self.prod.build(manifest_bytes=dup, signature=sign(self.prod.key, DOMAIN + dup))
        self.assertRefused(gz, "manifest")

    def test_manifest_field_validation(self):
        cases = {
            "case_id too long": {"case_id": "A" * 33},
            "case_id charset": {"case_id": "a b"},
            "bad time": {"generated_at": "yesterday"},
            "bad time_source": {"time_source": "ntp"},
            "bad bundle_id": {"bundle_id": "xyz"},
            "negative count": {"dropped": {"journal-app": -1}},
            "bool count": {"dropped": {"journal-app": True}},
            "truncated not bool": {"truncated": {"journal-host": 1}},
            "files not list": {"files": {}},
            "trailing newline in case_id": {"case_id": "ABC\n"},
            "trailing newline in version": {"collector_version": "1.0\n"},
            "undashed boot_id": {"boot_id": "fedcba9876543210fedcba9876543210"},
            "bad table key": {"redaction": {"Email": 1}},
        }
        for label, over in cases.items():
            with self.subTest(label=label):
                self.assertRefused(self.prod.build(manifest=self.prod.manifest(**over)), "manifest")

    def test_manifest_file_entries_are_validated(self):
        for label, mutate in {
            "reserved name": lambda m: m["files"].append({"path": "manifest.sig", "size": 1, "sha256": "0" * 64}),
            "bad sha": lambda m: m["files"][0].__setitem__("sha256", "zz"),
            "size too large": lambda m: m["files"][0].__setitem__("size", 3 << 20),
            "duplicate path": lambda m: m["files"].append(dict(m["files"][0])),
            "unknown key": lambda m: m["files"][0].__setitem__("mode", 0o777),
        }.items():
            with self.subTest(label=label):
                manifest = self.prod.manifest()
                mutate(manifest)
                self.assertRefused(self.prod.build(manifest=manifest), "manifest")

    def test_more_than_64_entries(self):
        extra = [tar_member(f"s{i:03d}.json", b"{}") for i in range(65)]
        self.assertRefused(self.prod.build(extra=extra), "tar")

    def test_section_over_two_mebibytes(self):
        big = b'{"a":"' + b"x" * (2 * 1024 * 1024) + b'"}'
        self.prod.files["big.json"] = big
        self.assertRefused(self.prod.build(), "tar")

    def test_compressed_archive_over_eight_mebibytes(self):
        for i in range(5):
            self.prod.files[f"noise{i}.bin"] = os.urandom(2 * 1024 * 1024)
        gz = self.prod.build()
        self.assertGreater(len(gz), 8 * 1024 * 1024)
        self.assertRefused(gz, "archive_size")

    def test_decompression_bomb(self):
        raw = b"\0" * (40 * 1024 * 1024)
        proc = self.verify(make_gz(raw))
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(self.failed_check(proc), "decompress")

    def test_trailing_bytes_after_the_gzip_stream(self):
        self.assertRefused(self.prod.build() + b"trailing", "decompress")
        self.assertRefused(self.prod.build() + make_gz(b"second member"), "decompress")

    def test_truncated_gzip(self):
        gz = self.prod.build()
        self.assertRefused(gz[:-40], "decompress")

    def test_not_a_gzip_not_an_age_not_a_zip(self):
        proc = self.verify(b"hello world, not a bundle")
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(self.failed_check(proc), "input")

    def test_gnu_format_is_refused(self):
        self.assertRefused(self.prod.build(tar_fmt=tarfile.GNU_FORMAT), "tar")

    def test_pax_extended_headers_are_refused(self):
        for headers in ({"comment": "harmless"}, {"path": "../escape.json"}):
            with self.subTest(headers=headers):
                ti, data = tar_member("pax.json", b"{}")
                ti.pax_headers = headers
                gz = self.prod.build(extra=[(ti, data)], tar_fmt=tarfile.PAX_FORMAT)
                self.assertRefused(gz, "tar")

    def test_data_after_the_end_of_archive_marker(self):
        gz = self.prod.build(mutate_raw=lambda raw: raw.rstrip(b"\0") + b"\0" * 1024 + b"smuggled")
        self.assertRefused(gz, "tar")

    def test_metadata_deviations_are_warnings_not_refusals(self):
        members = [tar_member(n, d, mode=0o600, mtime=1) for n, d in sorted({
            "manifest.json": canonical(self.prod.manifest()),
            "manifest.sig": sign(self.prod.key, DOMAIN + canonical(self.prod.manifest())),
            "device-root.spki.der": self.prod.spki, **SECTIONS}.items())]
        proc = self.verify(self.prod.build(members=members))
        self.assertEqual(proc.returncode, 0, proc.stdout)
        warnings = " ".join(self.verdict(proc)["warnings"])
        self.assertIn("mode", warnings)
        self.assertIn("mtime", warnings)


class AgeAndZip(ToolTest):
    def setUp(self):
        super().setUp()
        self.identity = self.tmp / "support.key"
        out = subprocess.run(["age-keygen", "-o", str(self.identity)], capture_output=True, text=True, check=True)
        self.recipient = re.search(r"age1[0-9a-z]+", out.stderr + out.stdout).group(0)
        os.chmod(self.identity, 0o600)

    def encrypt(self, data, recipient=None):
        return subprocess.run(["age", "-r", recipient or self.recipient], input=data, capture_output=True, check=True).stdout

    def zipped(self, age_bytes, name="ni-support-01234567.tar.gz.age", extra=()):
        out = io.BytesIO()
        with zipfile.ZipFile(out, "w", zipfile.ZIP_STORED) as zf:
            zf.writestr(name, age_bytes)
            for n, d in extra:
                zf.writestr(n, d)
        return out.getvalue()

    def test_zip_of_age_decrypts_verifies_and_lists(self):
        data = self.zipped(self.encrypt(self.prod.build()))
        path = self.prod.write("ni-support-01234567.zip", data)
        proc = run("verify", path, "--pin-spki-sha256", self.prod.pin, "--key", self.identity, "--format", "json")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        v = self.verdict(proc)
        self.assertEqual(v["bundle"]["input"], "zip+age")
        self.assertEqual({f["path"] for f in v["files"]}, set(SECTIONS))

    def test_bare_age_file_works(self):
        path = self.prod.write("b.tar.gz.age", self.encrypt(self.prod.build()))
        proc = run("verify", path, "--pin-spki-sha256", self.prod.pin, "--key", self.identity, "--format", "json")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.verdict(proc)["bundle"]["input"], "age")

    def test_wrong_key_is_refused(self):
        other = self.tmp / "other.key"
        subprocess.run(["age-keygen", "-o", str(other)], capture_output=True, check=True)
        path = self.prod.write("b.tar.gz.age", self.encrypt(self.prod.build()))
        proc = run("verify", path, "--pin-spki-sha256", self.prod.pin, "--key", other, "--format", "json")
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(self.failed_check(proc), "decrypt")

    def test_age_without_key_is_a_usage_error(self):
        path = self.prod.write("b.tar.gz.age", self.encrypt(self.prod.build()))
        proc = run("verify", path, "--pin-spki-sha256", self.prod.pin)
        self.assertEqual(proc.returncode, 2)
        self.assertIn("--key", proc.stderr)

    def test_corrupted_age_is_refused(self):
        blob = bytearray(self.encrypt(self.prod.build()))
        blob[-20] ^= 0xFF
        path = self.prod.write("b.tar.gz.age", bytes(blob))
        proc = run("verify", path, "--pin-spki-sha256", self.prod.pin, "--key", self.identity, "--format", "json")
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(self.failed_check(proc), "decrypt")

    def test_zip_layout_is_closed(self):
        age_bytes = self.encrypt(self.prod.build())
        cases = {
            "two members": self.zipped(age_bytes, extra=[("notes.txt", b"hi")]),
            "traversal": self.zipped(age_bytes, name="../x.tar.gz.age"),
            "wrong extension": self.zipped(age_bytes, name="bundle.tar.gz"),
            "no member": b"PK\x05\x06" + b"\0" * 18,
        }
        for label, data in cases.items():
            with self.subTest(label=label):
                path = self.prod.write("z.zip", data)
                proc = run("verify", path, "--pin-spki-sha256", self.prod.pin, "--key", self.identity, "--format", "json")
                self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
                self.assertEqual(self.failed_check(proc), "input")

    def test_zip_bomb_member_is_refused(self):
        out = io.BytesIO()
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("ni-support-01234567.tar.gz.age", b"\0" * (64 * 1024 * 1024))
        path = self.prod.write("z.zip", out.getvalue())
        proc = run("verify", path, "--pin-spki-sha256", self.prod.pin, "--key", self.identity, "--format", "json")
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(self.failed_check(proc), "input")

    def test_nothing_is_written_to_disk_while_verifying(self):
        quiet_tmp, quiet_cwd = self.tmp / "tmpdir", self.tmp / "cwd"
        quiet_tmp.mkdir(), quiet_cwd.mkdir()
        path = self.prod.write("ni-support-01234567.zip", self.zipped(self.encrypt(self.prod.build())))
        env = {**os.environ, "TMPDIR": str(quiet_tmp)}
        proc = run("verify", path, "--pin-spki-sha256", self.prod.pin, "--key", self.identity, env=env, cwd=quiet_cwd)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(list(quiet_tmp.iterdir()), [])
        self.assertEqual(list(quiet_cwd.iterdir()), [])

    def test_a_key_file_readable_by_others_is_a_warning(self):
        os.chmod(self.identity, 0o644)
        path = self.prod.write("b.tar.gz.age", self.encrypt(self.prod.build()))
        proc = run("verify", path, "--pin-spki-sha256", self.prod.pin, "--key", self.identity, "--format", "json")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("chmod 600", " ".join(self.verdict(proc)["warnings"]))

    def test_key_file_content_never_printed(self):
        path = self.prod.write("b.tar.gz.age", self.encrypt(self.prod.build()))
        other = self.tmp / "other.key"
        subprocess.run(["age-keygen", "-o", str(other)], capture_output=True, check=True)
        secret = [line for line in other.read_text().splitlines() if line.startswith("AGE-SECRET-KEY-")][0]
        proc = run("verify", path, "--pin-spki-sha256", self.prod.pin, "--key", other)
        self.assertNotIn(secret, proc.stdout + proc.stderr)


class ShowAndExtract(ToolTest):
    def test_show_prints_a_verified_member_with_control_characters_neutralised(self):
        self.prod.files["journal-host.jsonl"] = b'{"message":"ok"}\n\x1b[2J\x1b]0;pwned\x07 tail\n'
        path = self.prod.write("b.tar.gz", self.prod.build())
        proc = run("show", path, "journal-host.jsonl", "--pin-spki-sha256", self.prod.pin)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("tail", proc.stdout)
        self.assertNotIn("\x1b", proc.stdout)
        self.assertNotIn("\x07", proc.stdout)

    def test_show_refuses_an_unverified_bundle_and_an_unknown_member(self):
        path = self.prod.write("b.tar.gz", self.prod.build())
        self.assertEqual(run("show", path, "identity.json", "--pin-spki-sha256", "0" * 64).returncode, 1)
        proc = run("show", path, "nope.json", "--pin-spki-sha256", self.prod.pin)
        self.assertEqual(proc.returncode, 1)

    def test_extract_writes_verified_members_privately(self):
        path = self.prod.write("b.tar.gz", self.prod.build())
        out = self.tmp / "out"
        proc = run("extract", path, "--out", out, "--pin-spki-sha256", self.prod.pin)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual((out / "identity.json").read_bytes(), SECTIONS["identity.json"])
        self.assertTrue((out / "manifest.json").exists())
        self.assertEqual(stat.S_IMODE(os.stat(out).st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(os.stat(out / "identity.json").st_mode), 0o600)
        self.assertIn("delete", proc.stderr.lower())

    def test_extract_refuses_a_bad_bundle_and_a_dirty_destination(self):
        bad = self.prod.write("bad.tar.gz", self.prod.build(signed_with=new_ec_key(self.tmp, "x")))
        out = self.tmp / "out2"
        self.assertEqual(run("extract", bad, "--out", out, "--pin-spki-sha256", self.prod.pin).returncode, 1)
        self.assertFalse(out.exists())
        good = self.prod.write("b.tar.gz", self.prod.build())
        dirty = self.tmp / "dirty"
        dirty.mkdir()
        (dirty / "old").write_text("x")
        self.assertNotEqual(run("extract", good, "--out", dirty, "--pin-spki-sha256", self.prod.pin).returncode, 0)
        link = self.tmp / "link"
        link.symlink_to(self.tmp / "elsewhere")
        self.assertNotEqual(run("extract", good, "--out", link, "--pin-spki-sha256", self.prod.pin).returncode, 0)


class CanaryAndDenyList(ToolTest):
    """Planted customer content must never be in a bundle: the Owner-side oracle for it."""

    def canary_file(self):
        path = self.tmp / "canaries.txt"
        path.write_text("\n".join(CANARIES) + "\n", encoding="utf-8")
        return path

    def leaky(self, **sections):
        files = dict(SECTIONS)
        files.update(sections)
        self.prod.files = files
        return self.prod.build()

    def assertFound(self, proc, rule=None, path=None):
        self.assertEqual(proc.returncode, 3, proc.stdout + proc.stderr)
        v = self.verdict(proc)
        self.assertEqual(v["verdict"], "findings")
        self.assertTrue(all(c["ok"] for c in v["checks"]), "integrity must still be reported as intact")
        hits = v["findings"]
        self.assertTrue(hits, v)
        if rule:
            self.assertIn(rule, {h["rule"] for h in hits}, hits)
        if path:
            self.assertIn(path, {h["file"] for h in hits}, hits)
        return hits

    def assertNeverEchoed(self, proc, *needles):
        for needle in needles:
            self.assertNotIn(needle, proc.stdout)
            self.assertNotIn(needle, proc.stderr)

    def test_canary_in_every_realistic_position(self):
        positions = {
            "json value": b'{"detail":"%s"}\n' % CANARY_DOC.encode(),
            "json key": b'{"%s":1}\n' % CANARY_DOC.encode(),
            "log line": b"Oct 06 12:00:00 icecore-api[1]: opened " + CANARY_DOC.encode() + b" for reading\n",
            "argument": b'{"message":"cmd --file=/srv/%s.pdf --verbose"}\n' % CANARY_DOC.encode(),
            "unicode": ('{"message":"%s"}\n' % CANARY_QUERY).encode(),
            "json-escaped": ('{"message":%s}\n' % json.dumps(CANARY_QUERY)).encode(),
            "case folded": ('{"message":"%s"}\n' % CANARY_DOC.upper()).encode(),
            "device name": b'{"paired":"%s"}\n' % CANARY_DEVICE.encode(),
            "licence key": b'{"message":"%s"}\n' % CANARY_LICENCE.encode(),
        }
        for label, line in positions.items():
            with self.subTest(position=label):
                gz = self.leaky(**{"journal-app.jsonl": line})
                proc = self.verify(gz, "--canaries", self.canary_file())
                self.assertFound(proc, rule="canary", path="journal-app.jsonl")
                self.assertNeverEchoed(proc, CANARY_DOC, CANARY_QUERY, CANARY_LICENCE, CANARY_DEVICE,
                                       CANARY_DOC.upper())

    def test_canary_in_the_manifest_values(self):
        manifest = self.prod.manifest(case_id="BETA-12", collector_version="1.0.0")
        manifest["x-note"] = CANARY_DOC
        proc = self.verify(self.prod.build(manifest=manifest), "--canaries", self.canary_file())
        self.assertFound(proc, rule="canary", path="manifest.json")

    def test_canary_in_the_unsigned_client_block(self):
        self.prod.files["client.json"] = ('{"host":"%s"}' % CANARY_DEVICE).encode()
        manifest = self.prod.manifest()
        manifest["files"] = [f for f in manifest["files"] if f["path"] != "client.json"]
        proc = self.verify(self.prod.build(manifest=manifest), "--canaries", self.canary_file())
        self.assertFound(proc, rule="canary", path="client.json")

    def test_clean_bundle_passes_the_canary_check(self):
        proc = self.verify(self.prod.build(), "--canaries", self.canary_file())
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.verdict(proc)["bundle"]["canaries_checked"], len(CANARIES))

    def test_canary_file_validation(self):
        path = self.prod.write("b.tar.gz", self.prod.build())
        for content, label in (("ab\n", "too short"), ("", "empty"), ("\n\n", "blank only")):
            with self.subTest(label=label):
                (self.tmp / "c.txt").write_text(content)
                proc = run("verify", path, "--pin-spki-sha256", self.prod.pin, "--canaries", self.tmp / "c.txt")
                self.assertEqual(proc.returncode, 2, proc.stderr)
        proc = run("verify", path, "--pin-spki-sha256", self.prod.pin, "--canaries", self.tmp / "absent.txt")
        self.assertEqual(proc.returncode, 2)

    def test_built_in_deny_list_without_any_canary_file(self):
        leaks = {
            "email": (b'{"message":"sent to %s"}\n' % CANARY_MAIL.encode(), "email"),
            "private ipv4": (b'{"message":"peer 192.168.1.42 refused"}\n', "ip_address"),
            "cgnat ipv4": (b'{"message":"via 100.64.12.9"}\n', "ip_address"),
            "ipv6": (b'{"message":"from fe80::1ff:fe23:4567:890a"}\n', "ip_address"),
            "mac": (b'{"message":"nic 3c:6d:66:aa:bb:cc up"}\n', "mac_address"),
            "pem": (b'{"message":"-----BEGIN PRIVATE KEY-----"}\n', "pem_block"),
            "bearer": (b'{"message":"Authorization: Bearer Zq9XkLm2PvT7wRb4NcY8"}\n', "token"),
            "jwt": (b'{"message":"eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl"}\n', "token"),
            "nicap": (b'{"message":"cap nicap1_AbCdEf0123456789"}\n', "token"),
            "recovery key": (b'{"message":"' + b"-".join([b"cdefghij"] * 8) + b'"}\n', "recovery_key"),
            "password pair": (b'{"message":"password=Tr0ub4dor&3"}\n', "secret_pair"),
            "escape sequence": (b'{"message":"x\\u001b[2Jy"}\n'.replace(b"\\u001b", b"\x1b"), "control_character"),
            "forbidden key": (b'{"license_key":"LIC-ANYTHING"}\n', "deny_key"),
            "forbidden key nested": (b'{"a":{"b":[{"user_email":"x"}]}}\n', "deny_key"),
            "binary": (b'{"message":"ok"}\n\xff\xfe\x00junk\n', "non_text"),
        }
        for label, (line, rule) in leaks.items():
            with self.subTest(leak=label):
                proc = self.verify(self.leaky(**{"journal-app.jsonl": line}))
                self.assertFound(proc, rule=rule, path="journal-app.jsonl")
                self.assertNeverEchoed(proc, "192.168.1.42", CANARY_MAIL, "Tr0ub4dor", "Zq9XkLm2PvT7wRb4NcY8",
                                       "nicap1_AbCdEf", "3c:6d:66:aa:bb:cc", "LIC-ANYTHING")

    def test_empty_forbidden_key_values_are_not_findings(self):
        proc = self.verify(self.leaky(**{"licence.json": b'{"license_key":null,"token":"","email":false}\n'}))
        self.assertEqual(proc.returncode, 0, proc.stdout)

    def test_finding_points_to_the_line(self):
        files = b'{"message":"fine"}\n{"message":"fine"}\n{"message":"mail ' + CANARY_MAIL.encode() + b'"}\n'
        proc = self.verify(self.leaky(**{"journal-app.jsonl": files}))
        hits = self.assertFound(proc, rule="email")
        self.assertEqual([h["line"] for h in hits if h["rule"] == "email"], [3])

    def test_canary_in_raw_archive_bytes_outside_any_listed_file_is_refused_not_hidden(self):
        """Smuggling a canary in a header or padding is an integrity refusal, never a silent pass."""
        gz = self.prod.build(extra=[tar_member("pad.json", CANARY_DOC.encode())])
        proc = self.verify(gz, "--canaries", self.canary_file())
        self.assertEqual(proc.returncode, 1)
        self.assertNeverEchoed(proc, CANARY_DOC)


class GoldenBundle(unittest.TestCase):
    """A committed bundle signed once by a throwaway key that was destroyed: the byte-level contract
    (ustar layout, gzip -n, canonical manifest, domain-separated signature) stays readable across
    Python and OpenSSL versions, and the producers (collector, client) can be tested against it."""

    FIXTURE = HERE / "fixtures" / "golden-v1"

    def test_golden_bundle_verifies_with_its_pin_and_only_with_it(self):
        pin = (self.FIXTURE / "pin.txt").read_text().split()[0]
        bundle = self.FIXTURE / "ni-support-golden.tar.gz"
        proc = run("verify", bundle, "--pin-spki-sha256", pin, "--format", "json")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        verdict = json.loads(proc.stdout)
        self.assertEqual(verdict["verdict"], "verified")
        self.assertEqual(verdict["warnings"], [])
        expected = json.loads((self.FIXTURE / "expected.json").read_text())
        self.assertEqual([f["path"] for f in verdict["files"]], expected["files"])
        self.assertEqual(verdict["bundle"]["bundle_id"], expected["bundle_id"])
        other = run("verify", bundle, "--pin-spki-sha256", "0" * 64, "--format", "json")
        self.assertEqual(other.returncode, 1)

    def test_golden_bundle_is_byte_deterministic(self):
        """The tar inside must be the one `gzip -n` of sorted ustar entries, no timestamp anywhere."""
        data = (self.FIXTURE / "ni-support-golden.tar.gz").read_bytes()
        self.assertEqual(data[:4], b"\x1f\x8b\x08\x00")
        self.assertEqual(data[4:8], b"\0\0\0\0")


class ReviewRegressions(ToolTest):
    """Defects an independent adversarial review reproduced; each one stays fixed."""

    def finding_rules(self, **files):
        self.prod.files = {**SECTIONS, **files}
        proc = self.verify(self.prod.build(), "--format", "json")
        self.assertIn(proc.returncode, (0, 3), proc.stdout + proc.stderr)
        return {f["rule"] for f in self.verdict(proc)["findings"]}

    def test_hostile_line_costs_bounded_time_and_never_kills_the_reader(self):
        hostile = b'{"message":"' + b"-eyJaaaaaaaaa" * 150000 + b'"}\n'
        self.assertLess(len(hostile), 2 << 20)
        started = time.monotonic()
        proc = self.verify(self.prod.build() if self.prod.files.update({"journal-host.jsonl": hostile}) is None else b"")
        self.assertLess(time.monotonic() - started, 90)
        self.assertIn(proc.returncode, (0, 3), proc.stderr[-300:])
        self.assertIn(self.verdict(proc)["verdict"], ("verified", "findings"))

    def test_other_hostile_lines_stay_linear(self):
        for label, line in {
            "email": b"a" * 70 + b"@" + b"b" * (1 << 20),
            "hyphen run": b"a-" * (1 << 19),
            "colon run": b"a:" * (1 << 19),
            "dots": b"1." * (1 << 19),
            "pair": b"token" * (1 << 17) + b"=",
        }.items():
            with self.subTest(label=label):
                self.prod.files = {**SECTIONS, "journal-host.jsonl": b'{"message":"' + line + b'"}\n'}
                started = time.monotonic()
                proc = self.verify(self.prod.build())
                self.assertLess(time.monotonic() - started, 60, label)
                self.assertIn(proc.returncode, (0, 3), proc.stderr[-300:])

    def test_redaction_counts_named_after_a_rule_are_not_a_leak(self):
        manifest = self.prod.manifest(redaction={"email": 3, "token": 2, "ip_address": 1}, dropped={"email": 1})
        proc = self.verify(self.prod.build(manifest=manifest))
        self.assertEqual(proc.returncode, 0, proc.stdout)

    def test_x_fields_of_the_manifest_are_still_scanned(self):
        manifest = self.prod.manifest()
        manifest["x-debug"] = {"token": "s3cr3t-value"}
        proc = self.verify(self.prod.build(manifest=manifest))
        self.assertEqual(proc.returncode, 3, proc.stdout)

    def test_surrogates_in_the_signed_manifest_never_crash_the_reader(self):
        escaped = canonical(self.prod.manifest(**{"x-note": "\ud800"}))
        proc = self.verify(self.prod.build(manifest_bytes=escaped, signature=sign(self.prod.key, DOMAIN + escaped)))
        self.assertNotIn("Traceback", proc.stderr)
        self.assertEqual(proc.returncode, 0, proc.stdout)
        raw = canonical(self.prod.manifest(**{"x-note": "ABC"})).replace(b"ABC", b"\xed\xa0\x80")
        proc = self.verify(self.prod.build(manifest_bytes=raw, signature=sign(self.prod.key, DOMAIN + raw)))
        self.assertNotIn("Traceback", proc.stderr)
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(self.failed_check(proc), "manifest")

    def test_tool_and_destination_errors_are_clean(self):
        path = self.prod.write("b.tar.gz", self.prod.build())
        proc = run("verify", path, "--pin-spki-sha256", self.prod.pin, "--openssl-bin", "/usr/bin")
        self.assertEqual(proc.returncode, 2)
        self.assertNotIn("Traceback", proc.stderr)
        proc = run("extract", path, "--out", "/proc/nope/x", "--pin-spki-sha256", self.prod.pin)
        self.assertEqual(proc.returncode, 2)
        self.assertNotIn("Traceback", proc.stderr)

    def smuggled(self, mutate):
        """A bundle whose gzip/tar bytes were edited where no listed file, hash or signature looks."""
        return self.prod.build(mutate_raw=mutate)

    def test_bytes_hidden_in_tar_padding_or_unused_header_fields_are_refused(self):
        def padding(raw):
            with tarfile.open(fileobj=io.BytesIO(raw)) as tf:
                first = tf.getmembers()[0]
            end = first.offset_data + first.size
            self.assertLess(end % 512, 511)
            return raw[:end] + b"alice@cabinet-exemple.example"[:512 - end % 512] + raw[end + min(29, 512 - end % 512):]

        def header_spare(raw):
            fixed = bytearray(raw)
            fixed[500:506] = b"HIDDEN"
            checksum = sum(fixed[0:148]) + 32 * 8 + sum(fixed[156:512])
            fixed[148:156] = b"%06o\0 " % checksum
            return bytes(fixed)

        for label, mutate in (("padding", padding), ("header spare bytes", header_spare)):
            with self.subTest(label=label):
                self.assertRefused(self.smuggled(mutate), "tar")

    def test_gzip_header_fields_that_can_carry_text_are_refused(self):
        def with_comment(raw):
            body = gzip.compress(raw, 9, mtime=0)
            return body[:3] + bytes([body[3] | 0x10]) + body[4:10] + b"alice@cabinet-exemple.example\0" + body[10:]
        self.assertRefused(self.prod.build(gz_wrap=with_comment), "decompress")

    def test_every_deny_list_regex_is_linear_on_its_own(self):
        """Without the line windows: the windows are a second defence, not the first."""
        spec = importlib.util.spec_from_file_location("ni_support_verify", TOOL)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        hostile = ["-eyJaaaaaaaaa" * 20000, "a" * 70 + "@" + "b" * 260000, "a-" * 130000, "a:" * 130000,
                   "1." * 130000, "token" * 50000 + "=", "ab" * 130000]
        for pattern in (module.TOKEN, module.EMAIL, module.IPV4, module.IPV6_RUN, module.MAC, module.SECRET_PAIR,
                        module.FIELD_PAIR, module.RECOVERY_KEY):
            for text in hostile:
                started = time.monotonic()
                for _ in pattern.finditer(text):
                    pass
                self.assertLess(time.monotonic() - started, 3, (pattern.pattern[:40], text[:12]))

    def test_new_deny_list_shapes(self):
        leaks = {
            "unicode email": b'{"message":"mail jos\xc3\xa9@exemple.fr"}\n',
            "ipv6 then colon": b'{"message":"peer fe80::1: timeout"}\n',
            "ipv6 then dot": b'{"message":"connect to 2001:db8::1."}\n',
            "token pair": b'{"message":"access_token=Zq9XkLm2PvT7wRb4NcY8"}\n',
            "client secret pair": b'{"message":"client_secret=Zq9XkLm2PvT7wRb4NcY8"}\n',
            "basic auth": b'{"message":"Authorization: Basic dXNlcjpwYXNzd29yZA=="}\n',
            "filename pair": b'{"message":"opened filename=Contrat-Dupont.pdf"}\n',
            "escaped json in a string": b'{"message":"{\\"prompt\\":\\"Resume du contrat\\"}"}\n',
            "camel case key": b'{"licenseKey":"LIC-ANYTHING"}\n',
            "hyphen key": b'{"user-email":"x"}\n',
            "duplicate keys": b'{"prompt":"Resume du contrat Dupont SA","prompt":""}\n',
            "very deep key": b'{"a":' * 30 + b'{"prompt":"Resume"}' + b"}" * 30 + b"\n",
        }
        for label, line in leaks.items():
            with self.subTest(leak=label):
                self.assertTrue(self.finding_rules(**{"journal-app.jsonl": line}), label)

    def test_ordinary_journal_text_still_passes_after_the_new_rules(self):
        ordinary = [
            "wpa-style 6.8.0.1-generic booted", "Linux version 6.8.0.1 (builder)", "chrony version 4.5.0.1",
            "package foo-1.2.3.4-1.el9.x86_64 installed", "ostree commit 1.2.3.4 staged",
            "ab-cd-ef-01-23-45.service started", "time 10:20:30:: elapsed", "NVRM: Xid (PCI:0000:01:00): 79",
            "token: ok", "password: required", "tokens=3 refreshed", "token_expires=2026-10-06T10:00:00Z",
            "std::collections::HashMap<K, V>", "src/api/routes/v1.rs:123:45", "user@1000.service: Succeeded",
            "Bearer authentication is configured", "email delivery disabled", "filename policy loaded",
            "image sha256:" + "ab" * 32, "serving on 127.0.0.1:8443 and ::1",
        ]
        body = "".join(json.dumps({"message": text}) + "\n" for text in ordinary).encode()
        self.assertEqual(self.finding_rules(**{"journal-host.jsonl": body}), set())

    def test_canary_matching_is_unicode_aware_and_bom_safe(self):
        canaries = self.tmp / "c.txt"
        canaries.write_bytes(b"\xef\xbb\xbf" + "Müller & Fils, clause 14\n".encode() + b"  Dossier-Succession-7731  \n")
        nfd = unicodedata.normalize("NFD", "CLAUSE: MÜLLER & FILS, CLAUSE 14")
        for label, text in (("upper case + NFD", nfd), ("first canary after the BOM", "Müller & Fils, clause 14"),
                            ("stripped canary", "x dossier-succession-7731 y")):
            with self.subTest(label=label):
                self.prod.files = {**SECTIONS, "journal-app.jsonl": json.dumps({"m": text}, ensure_ascii=False).encode() + b"\n"}
                proc = self.verify(self.prod.build(), "--canaries", canaries)
                self.assertEqual(proc.returncode, 3, proc.stdout)

    def test_zip_comment_and_bytes_outside_the_member_are_refused(self):
        age_like = b"age-encryption.org/v1\n" + b"x" * 40
        out = io.BytesIO()
        with zipfile.ZipFile(out, "w", zipfile.ZIP_STORED) as zf:
            zf.writestr("ni-support-01234567.tar.gz.age", age_like)
            zf.comment = b"alice@cabinet-exemple.example"
        gap = io.BytesIO()
        with zipfile.ZipFile(gap, "w", zipfile.ZIP_STORED) as zf:
            zf.writestr("ni-support-01234567.tar.gz.age", age_like)
        gapped = gap.getvalue()
        start = zipfile.ZipFile(io.BytesIO(gapped)).start_dir
        gapped = gapped[:start] + b"HIDDEN" + gapped[start:]
        key = self.tmp / "k"
        key.write_text("AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ\n")
        for label, data in (("comment", out.getvalue()), ("gap", gapped)):
            with self.subTest(label=label):
                path = self.prod.write("z.zip", data)
                proc = run("verify", path, "--pin-spki-sha256", self.prod.pin, "--key", key, "--format", "json")
                self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
                self.assertEqual(self.failed_check(proc), "input")

    def test_require_encrypted_refuses_a_plain_archive(self):
        self.assertRefused(self.prod.build(), "input", "--require-encrypted")

    def test_unsigned_client_block_is_labelled_when_shown_or_extracted(self):
        self.prod.files["client.json"] = b'{"client_version":"0.50.37"}'
        manifest = self.prod.manifest()
        manifest["files"] = [f for f in manifest["files"] if f["path"] != "client.json"]
        path = self.prod.write("b.tar.gz", self.prod.build(manifest=manifest))
        proc = run("show", path, "client.json", "--pin-spki-sha256", self.prod.pin)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("UNSIGNED", proc.stderr)

    def test_run_through_the_shebang_is_isolated_too(self):
        env = {**os.environ, "PYTHONPATH": str(self.tmp)}
        (self.tmp / "json.py").write_text("raise SystemExit('planted json module imported')\n")
        path = self.prod.write("b.tar.gz", self.prod.build())
        proc = subprocess.run([str(TOOL), "verify", str(path), "--pin-spki-sha256", self.prod.pin],
                              capture_output=True, text=True, env=env, cwd=self.tmp, check=False)
        self.assertNotIn("planted", proc.stdout + proc.stderr)
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_a_high_s_signature_is_a_warning_not_a_refusal(self):
        manifest = canonical(self.prod.manifest())
        order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
        for _ in range(40):
            der = sign(self.prod.key, DOMAIN + manifest)
            r_len = der[3]
            s_at = 4 + r_len + 2
            s_value = int.from_bytes(der[s_at:], "big")
            if s_value <= order // 2:
                high = order - s_value
                s_bytes = high.to_bytes(33, "big").lstrip(b"\0")
                if s_bytes[0] & 0x80:
                    s_bytes = b"\0" + s_bytes
                body = der[2:4 + r_len] + b"\x02" + bytes([len(s_bytes)]) + s_bytes
                sig = b"\x30" + bytes([len(body)]) + body
                break
        else:
            self.fail("could not craft a high-S signature")
        proc = self.verify(self.prod.build(manifest_bytes=manifest, signature=sig))
        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertIn("low-S", " ".join(self.verdict(proc)["warnings"]))


class Hardening(ToolTest):
    def test_tool_runs_isolated_and_without_a_shell(self):
        source = TOOL.read_text()
        self.assertNotIn("shell=True", source)
        self.assertNotIn("os.system", source)
        self.assertNotIn("extractall", source, "members are read in memory, never extracted by tarfile")
        self.assertNotIn("pickle", source)

    def test_openssl_and_age_are_resolved_from_fixed_locations_first(self):
        source = TOOL.read_text()
        self.assertIn("/usr/bin/openssl", source)
        self.assertIn("/usr/bin/age", source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
