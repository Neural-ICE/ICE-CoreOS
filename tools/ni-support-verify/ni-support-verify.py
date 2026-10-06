#!/usr/bin/env python3
"""Owner-side reader of a Neural ICE support bundle: verify, list, show, extract.

    verify   BUNDLE  --pin-spki-sha256 HEX ...   integrity, signature, pin, content scan
    show     BUNDLE MEMBER ...                   one verified member, control characters neutralised
    extract  BUNDLE --out DIR ...                every verified member, into a new private directory

BUNDLE is what the user hands over (design: DESIGN-support-bundle-20261006, sections 2 and 4):

    ni-support-<id8>.zip  ->  one  *.tar.gz.age  member  ->  (age X25519)  ->  tar.gz

or the bare `.tar.gz.age`, or an already decrypted `.tar.gz`. The tar holds `manifest.json`,
`manifest.sig`, `device-root.spki.der`, the sections the manifest lists, and optionally the
client's own unsigned `client.json`. Nothing here needs the device: the signature is checked
against a PIN the Owner took at the device's ceremony, never against the key the bundle carries
(a forged bundle would carry its own).

What is checked, in this order, stopping at the first refusal (exit 1):

    input        the outer file is a zip with exactly one `.age` member, an age file or a gzip
    decrypt      `age -d -i KEY` succeeds (the key file is only ever passed by path)
    archive_size compressed archive <= 8 MiB
    decompress   one gzip stream, no trailing bytes, <= 24 MiB (+ tar framing) once expanded
    tar          strict POSIX ustar: regular files only, flat `[a-z0-9._-]` names, no duplicates,
                 <= 64 entries, <= 2 MiB each, nothing after the end-of-archive marker
    envelope     manifest.json, manifest.sig and device-root.spki.der are present
    spki         device-root.spki.der is an ECDSA P-256 SubjectPublicKeyInfo
    pin          sha256(SPKI) is one of the pins the caller gave
    signature    ECDSA/SHA-256 over  "neural-ice-support-bundle-v1" 0x00 manifest.json  verifies
    manifest     only after the signature: UTF-8 JSON, no duplicate key, closed schema
    spki_binding the manifest's device_root_spki_sha256 is the pinned SPKI's hash
    files        every included section is in the archive with the listed size and sha256, an
                 excluded one is absent, and nothing else is there (but the unsigned client.json)

Then, without changing the verdict of the checks above, the content is scanned (exit 3 if
anything is found): a built-in deny-list from design section 2.3 (e-mail, IP, MAC, PEM, tokens,
recovery key, secret pairs, forbidden JSON keys, control characters, non-text bytes) and the
caller's own canary strings (`--canaries FILE`: one literal per line, such as a document name
or a licence key the Owner knows must never appear). A finding names the file, the line and the
rule: it never echoes the matched text.

Exit codes: 0 verified and clean, 1 refused, 2 usage or missing tool, 3 verified but the
content scan found something (treat the bundle as leaking and tell the product owner).

Python 3 standard library, `openssl` and (for encrypted input) `age`. The decrypted bytes stay
in memory; only `extract` writes them. Core dumps are disabled. For a stricter sandbox run it as
documented in the README (systemd-run with a private network and no writable path).
"""

import argparse
import datetime
import hashlib
import io
import ipaddress
import json
import os
import pathlib
import re
import resource
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile
import zlib

SCHEMA = "neural-ice-support-bundle-v1"
DOMAIN = SCHEMA.encode("ascii") + b"\x00"

MAX_ARCHIVE = 8 << 20          # compressed tar.gz
MAX_TOTAL = 24 << 20           # sum of the entries once expanded
TAR_FRAMING = 256 << 10        # 64 headers, padding and the end-of-archive blocks
MAX_SECTION = 2 << 20
MAX_ENTRIES = 64
MAX_MANIFEST = 256 << 10
MAX_SIGNATURE = 128
SPKI_LENGTH = 91
AGE_OVERHEAD = 64 << 10        # age header and per-chunk tags around a <= 8 MiB payload
MAX_OUTER = MAX_ARCHIVE + AGE_OVERHEAD + (16 << 10)
MAX_KEY_FILE = 64 << 10
MAX_CANARIES = 1000
MIN_CANARY = 6
JSON_DEPTH = 24

ENVELOPE = ("manifest.json", "manifest.sig", "device-root.spki.der")
UNSIGNED = ("client.json",)

# EC P-256 SubjectPublicKeyInfo header: SEQUENCE { SEQUENCE { id-ecPublicKey, prime256v1 },
# BIT STRING (uncompressed point, 65 bytes) }. The whole key is 91 bytes.
SPKI_P256_PREFIX = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200") + b"\x04"

NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
BUNDLE_ID = re.compile(r"^[0-9a-f]{32}$")
BOOT_ID = re.compile(r"^[0-9a-f]{32}$|^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
CASE_ID = re.compile(r"^[A-Za-z0-9-]{0,32}$")
VERSION = re.compile(r"^[A-Za-z0-9._+-]{1,64}$")
STAMP = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
ZIP_MEMBER = re.compile(r"^[A-Za-z0-9._-]{1,128}\.age$")
ZIP_ID8 = re.compile(r"^ni-support-([0-9a-f]{8})")
KEY_NAME = re.compile(r"^[a-z0-9._-]{1,64}$")

MANIFEST_KEYS = {"schema", "bundle_id", "case_id", "generated_at", "time_source", "boot_id", "files",
                 "dropped", "truncated", "redaction", "device_root_spki_sha256", "collector_version"}
FILE_KEYS = {"path", "size", "sha256", "included"}
TIME_SOURCES = {"attested", "host_clock"}

# Fixed locations first, so a PATH an attacker controls cannot swap the verifier or the decryptor.
OPENSSL_PATHS = ("/usr/bin/openssl", "/usr/local/bin/openssl", "/opt/homebrew/bin/openssl",
                 "/home/linuxbrew/.linuxbrew/bin/openssl")
AGE_PATHS = ("/usr/bin/age", "/usr/local/bin/age", "/opt/homebrew/bin/age",
             "/home/linuxbrew/.linuxbrew/bin/age")


class Refusal(Exception):
    def __init__(self, check, detail):
        super().__init__(detail)
        self.check, self.detail = check, detail


class Usage(Exception):
    pass


# --- small helpers ---------------------------------------------------------------------------

def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def find_tool(name, fixed, override):
    if override:
        if not os.access(override, os.X_OK):
            raise Usage(f"{name} is not executable: {override}")
        return override
    for path in fixed:
        if os.access(path, os.X_OK):
            return path
    found = shutil.which(name)
    if not found:
        raise Usage(f"{name} was not found; install it or pass --{name}-bin")
    return found


def clean_env():
    return {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "HOME": "/nonexistent"}


def one_line(text, limit=160):
    """Printable, single-line, bounded: for messages that carry tool output, never bundle content."""
    text = "".join(c if c.isprintable() else "?" for c in text.replace("\n", " "))
    return text[:limit]


class AnonFile:
    """Bytes behind a path, without a file on disk when the platform allows it (memfd)."""

    def __init__(self, data):
        self._dir = None
        if hasattr(os, "memfd_create"):
            self._fd = os.memfd_create("ni-support-verify")
            os.write(self._fd, data)
            self.path = f"/proc/self/fd/{self._fd}"
            self.pass_fds = (self._fd,)
        else:
            self._fd, self.pass_fds = None, ()
            self._dir = tempfile.mkdtemp(prefix="ni-sv-")
            self.path = os.path.join(self._dir, "data")
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)

    def close(self):
        if self._fd is not None:
            os.close(self._fd)
        if self._dir:
            shutil.rmtree(self._dir, ignore_errors=True)


# --- outer layers: zip, age, gzip --------------------------------------------------------------

def read_outer(path):
    try:
        with open(path, "rb") as handle:
            data = handle.read(MAX_OUTER + 1)
    except OSError as exc:
        raise Refusal("input", f"cannot read the bundle: {one_line(str(exc))}")
    if len(data) > MAX_OUTER:
        raise Refusal("archive_size", f"the bundle file is larger than {MAX_OUTER} bytes")
    return data


def unzip_single(data):
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, OSError, ValueError) as exc:
        raise Refusal("input", f"not a readable zip: {one_line(str(exc))}")
    with zf:
        infos = zf.infolist()
        if len(infos) != 1:
            raise Refusal("input", f"the zip must hold exactly one .age member, it holds {len(infos)}")
        info = infos[0]
        if not ZIP_MEMBER.match(info.filename):
            raise Refusal("input", "the zip member name is not a plain *.age name")
        if info.flag_bits & 0x1:
            raise Refusal("input", "the zip member is encrypted")
        if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            raise Refusal("input", "the zip member uses an unsupported compression")
        if info.file_size > MAX_OUTER:
            raise Refusal("input", "the zip member expands beyond the size limit")
        try:
            with zf.open(info) as member:
                content = member.read(MAX_OUTER + 1)
        except (zipfile.BadZipFile, OSError, ValueError, NotImplementedError, zlib.error) as exc:
            raise Refusal("input", f"the zip member is unreadable: {one_line(str(exc))}")
        if len(content) > MAX_OUTER or len(content) != info.file_size:
            raise Refusal("input", "the zip member does not match its declared size")
        return info.filename, content


def age_decrypt(data, key_path, age_bin, warnings):
    try:
        st = os.stat(key_path)
    except OSError as exc:
        raise Usage(f"cannot read the key file: {one_line(str(exc))}")
    if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_KEY_FILE:
        raise Usage("the key file is not a regular file of a sane size")
    if st.st_mode & 0o077:
        warnings.append("the key file is readable by group or others: chmod 600 it")
    try:
        done = subprocess.run([age_bin, "-d", "-i", str(key_path)], input=data, capture_output=True,
                              timeout=120, env=clean_env(), check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise Refusal("decrypt", f"age could not run: {one_line(str(exc))}")
    if done.returncode != 0:
        first = done.stderr.decode("utf-8", "replace").strip().splitlines()[:1]
        raise Refusal("decrypt", "age refused to decrypt (wrong key or damaged file): "
                      + one_line(first[0] if first else "no message"))
    return done.stdout


def load_archive(path, key_path, age_bin_override, warnings):
    """-> (input kind, gzip bytes, outer member name or None)."""
    data = read_outer(path)
    name, kind = None, None
    if data[:4] == b"PK\x03\x04" or data[:4] == b"PK\x05\x06":
        name, data = unzip_single(data)
        kind = "zip+age"
    if data.startswith(b"age-encryption.org/"):
        if key_path is None:
            raise Usage("an age-encrypted bundle needs --key with the support identity file")
        data = age_decrypt(data, key_path, find_tool("age", AGE_PATHS, age_bin_override), warnings)
        kind = kind or "age"
    elif kind:
        raise Refusal("input", "the zip member is not an age file")
    if data[:2] != b"\x1f\x8b":
        raise Refusal("input", "not a zip, an age file or a gzip")
    return kind or "tar.gz", data, name


# --- gzip + tar ----------------------------------------------------------------------------------

def check_archive_size(data):
    if len(data) > MAX_ARCHIVE:
        raise Refusal("archive_size", f"the compressed archive is {len(data)} bytes, the limit is {MAX_ARCHIVE}")


def gunzip_bounded(data, warnings):
    if len(data) < 18 or data[2] != 8:
        raise Refusal("decompress", "not a gzip/deflate stream")
    if data[3] & 0x1E:
        warnings.append("gzip header carries a name, comment or extra field (not written with gzip -n)")
    if data[4:8] != b"\0\0\0\0":
        warnings.append("gzip header carries a timestamp (not written with gzip -n)")
    limit = MAX_TOTAL + TAR_FRAMING
    decoder = zlib.decompressobj(wbits=31)
    out, size, pending = [], 0, data
    try:
        while not decoder.eof:
            chunk = decoder.decompress(pending, 1 << 20)
            pending = decoder.unconsumed_tail
            out.append(chunk)
            size += len(chunk)
            if size > limit:
                raise Refusal("decompress", f"the archive expands beyond {limit} bytes")
            if not chunk and not pending:
                break
    except zlib.error as exc:
        raise Refusal("decompress", f"damaged gzip stream: {one_line(str(exc))}")
    if not decoder.eof:
        raise Refusal("decompress", "truncated gzip stream")
    if decoder.unused_data:
        raise Refusal("decompress", "bytes follow the gzip stream (a second member or trailing data)")
    return b"".join(out)


def read_tar(raw, warnings):
    """-> {name: bytes}, strictly. Members are read in memory, never extracted."""
    try:
        tf = tarfile.open(fileobj=io.BytesIO(raw), mode="r:", errorlevel=2)
    except (tarfile.TarError, OSError, ValueError) as exc:
        raise Refusal("tar", f"not a tar archive: {one_line(str(exc))}")
    members, total, seen = {}, 0, set()
    with tf:
        try:
            for member in tf:
                if len(seen) >= MAX_ENTRIES:
                    raise Refusal("tar", f"more than {MAX_ENTRIES} entries")
                name = member.name
                header = raw[member.offset:member.offset + 512]
                if header[257:265] != b"ustar\x0000":
                    raise Refusal("tar", "an entry is not a POSIX ustar header (GNU or pax extension?)")
                if header[156:157] != b"0" or member.type != tarfile.REGTYPE or member.pax_headers:
                    raise Refusal("tar", "an entry is not a plain regular file (link, directory, device or extension)")
                if not NAME.match(name):
                    raise Refusal("tar", "an entry name is not a flat [a-z0-9._-] name")
                if name in seen:
                    raise Refusal("tar", "duplicate entry name")
                seen.add(name)
                if member.size > MAX_SECTION:
                    raise Refusal("tar", f"an entry is larger than {MAX_SECTION} bytes")
                total += member.size
                if total > MAX_TOTAL:
                    raise Refusal("tar", f"the entries total more than {MAX_TOTAL} bytes")
                for label, value, expected in (("uid", member.uid, 0), ("gid", member.gid, 0),
                                               ("mode", member.mode, 0o644)):
                    if value != expected:
                        warnings.append(f"tar {label} of an entry is {value}, expected {expected}")
                if member.uname or member.gname:
                    warnings.append("tar user/group name is not empty")
                stream = tf.extractfile(member)
                body = stream.read(member.size + 1) if stream else b""
                if len(body) != member.size:
                    raise Refusal("tar", "an entry is shorter than its header says")
                members[name] = (body, member.mtime)
            end = tf.offset
        except tarfile.TarError as exc:
            raise Refusal("tar", f"damaged tar archive: {one_line(str(exc))}")
    if raw[end:].strip(b"\0"):
        raise Refusal("tar", "data follows the end-of-archive marker")
    return members


# --- signature, pin, manifest ---------------------------------------------------------------------

def check_spki(spki):
    if len(spki) != SPKI_LENGTH or not spki.startswith(SPKI_P256_PREFIX):
        raise Refusal("spki", "device-root.spki.der is not an ECDSA P-256 SubjectPublicKeyInfo")


def verify_signature(spki, signature, message, openssl_bin):
    if not 8 <= len(signature) <= MAX_SIGNATURE or signature[0] != 0x30:
        raise Refusal("signature", "manifest.sig is not a DER ECDSA signature")
    env = clean_env()
    pem = subprocess.run([openssl_bin, "pkey", "-pubin", "-inform", "DER", "-outform", "PEM"], input=spki,
                         capture_output=True, env=env, check=False)
    if pem.returncode != 0:
        raise Refusal("spki", "openssl cannot read device-root.spki.der")
    key_file, sig_file = AnonFile(pem.stdout), AnonFile(signature)
    try:
        done = subprocess.run([openssl_bin, "dgst", "-sha256", "-verify", key_file.path,
                               "-signature", sig_file.path], input=message, capture_output=True, env=env,
                              check=False, pass_fds=key_file.pass_fds + sig_file.pass_fds)
    finally:
        key_file.close()
        sig_file.close()
    if done.returncode != 0 or b"Verified OK" not in done.stdout:
        raise Refusal("signature", "the signature does not verify over the domain-separated manifest")


def strict_pairs(pairs):
    keys = [key for key, _ in pairs]
    if len(set(keys)) != len(keys):
        raise ValueError("duplicate key")
    return dict(pairs)


def refuse_constant(token):
    raise ValueError(f"non-finite number {token}")


def parse_manifest(raw, warnings):
    if len(raw) > MAX_MANIFEST:
        raise Refusal("manifest", "manifest.json is too large")
    try:
        text = raw.decode("utf-8")
        manifest = json.loads(text, object_pairs_hook=strict_pairs, parse_constant=refuse_constant)
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise Refusal("manifest", f"manifest.json is not strict JSON: {one_line(str(exc))}")
    if not isinstance(manifest, dict):
        raise Refusal("manifest", "manifest.json is not an object")
    canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    if canonical != raw:
        warnings.append("manifest.json is not in canonical form (sorted keys, no spaces)")
    return manifest


def is_count(value):
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def validate_manifest(m):
    def refuse(detail):
        raise Refusal("manifest", detail)

    unknown = [k for k in m if k not in MANIFEST_KEYS and not k.startswith("x-")]
    if unknown:
        refuse(f"unknown manifest field(s): {', '.join(one_line(k, 40) for k in sorted(unknown)[:5])}")
    missing = sorted(MANIFEST_KEYS - set(m))
    if missing:
        refuse(f"missing manifest field(s): {', '.join(missing)}")
    if m["schema"] != SCHEMA:
        refuse(f"unsupported schema {one_line(str(m['schema']), 60)!r}, this tool reads {SCHEMA}")
    for field, rx in (("bundle_id", BUNDLE_ID), ("boot_id", BOOT_ID), ("case_id", CASE_ID),
                      ("collector_version", VERSION), ("device_root_spki_sha256", HEX64),
                      ("generated_at", STAMP)):
        if not isinstance(m[field], str) or not rx.match(m[field]):
            refuse(f"{field} is malformed")
    try:
        stamp = datetime.datetime.strptime(m["generated_at"], "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        refuse("generated_at is not a calendar time")
    if m["time_source"] not in TIME_SOURCES:
        refuse("time_source is not attested or host_clock")
    for field, check in (("dropped", is_count), ("redaction", is_count),
                         ("truncated", lambda v: isinstance(v, bool))):
        table = m[field]
        if not isinstance(table, dict) or len(table) > MAX_ENTRIES or \
                not all(KEY_NAME.match(k) and check(v) for k, v in table.items()):
            refuse(f"{field} is not a table of section -> {'boolean' if field == 'truncated' else 'count'}")
    files = m["files"]
    if not isinstance(files, list) or len(files) > MAX_ENTRIES:
        refuse("files is not a bounded list")
    paths, listed = [], {}
    for entry in files:
        if not isinstance(entry, dict):
            refuse("a files entry is not an object")
        bad = [k for k in entry if k not in FILE_KEYS and not k.startswith("x-")]
        if bad:
            refuse("a files entry has an unknown field")
        path = entry.get("path")
        if not isinstance(path, str) or not NAME.match(path):
            refuse("a files entry has a malformed path")
        if path in ENVELOPE or path in UNSIGNED:
            refuse(f"{path} cannot be listed as a section")
        if path in listed:
            refuse("a path is listed twice")
        included = entry.get("included", True)
        if not isinstance(included, bool):
            refuse("included is not a boolean")
        if included:
            size, digest = entry.get("size"), entry.get("sha256")
            if not (isinstance(size, int) and not isinstance(size, bool) and 0 <= size <= MAX_SECTION):
                refuse("a files entry has a size outside 0..2 MiB")
            if not isinstance(digest, str) or not HEX64.match(digest):
                refuse("a files entry has a malformed sha256")
        paths.append(path)
        listed[path] = {"path": path, "included": included, "size": entry.get("size"),
                        "sha256": entry.get("sha256")}
    if paths != sorted(paths):
        refuse("files is not sorted by path")
    return stamp, listed


def cross_check_files(members, listed):
    for name in listed:
        entry = listed[name]
        if entry["included"]:
            if name not in members:
                raise Refusal("files", f"{name} is listed but missing from the archive")
            body = members[name][0]
            if len(body) != entry["size"]:
                raise Refusal("files", f"{name} has a different size than the manifest says")
            if sha256_hex(body) != entry["sha256"]:
                raise Refusal("files", f"{name} does not match its sha256 in the manifest")
        elif name in members:
            raise Refusal("files", f"{name} is marked excluded but is in the archive")
    extra = sorted(set(members) - set(ENVELOPE) - set(UNSIGNED) - set(listed))
    if extra:
        raise Refusal("files", f"entries not listed in the manifest: {', '.join(extra[:5])}")


def load_pins(values, pins_file):
    pins = {}
    for value in values or []:
        if not HEX64.match(value):
            raise Usage("--pin-spki-sha256 must be 64 lowercase hex digits")
        pins.setdefault(value, "")
    if pins_file:
        try:
            lines = pathlib.Path(pins_file).read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError) as exc:
            raise Usage(f"cannot read the pins file: {one_line(str(exc))}")
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            digest, _, label = line.partition(" ")
            if not HEX64.match(digest):
                raise Usage("a pins file line must start with 64 lowercase hex digits")
            pins.setdefault(digest, one_line(label.strip(), 80))
    if not pins:
        raise Usage("a pin is mandatory: give --pin-spki-sha256 HEX (or --pins-file) taken at the device's "
                    "ceremony; the key inside the bundle is never trusted")
    return pins


# --- content scan ------------------------------------------------------------------------------------

DENY_KEYS = frozenset("""license_key licence_key hardware_fingerprint fingerprint recovery_key luks_recovery_key
passphrase password secret api_key private_key access_token refresh_token token setup_code pairing_code email
user_email prompt transcript document_name filename file_name paired_device_name""".split())

SYSTEMD_UNIT_SUFFIXES = frozenset("service slice scope socket timer mount path target device automount swap".split())

EMAIL = re.compile(r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.([A-Za-z]{2,})")
IPV4 = re.compile(r"(?<![\w.])((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})(?![\w]|\.\d)")
IPV6_RUN = re.compile(r"(?<![A-Za-z0-9_:.])[0-9A-Fa-f:.]{3,}(?![A-Za-z0-9_:.])")
MAC = re.compile(r"(?<![0-9A-Fa-f:-])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:-])")
PEM = re.compile(r"-----BEGIN [A-Z0-9 ]{3,40}-----")
TOKEN = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}|\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}"
                   r"|\bnicap1_[A-Za-z0-9_-]{4,}")
RECOVERY_KEY = re.compile(r"(?<![a-z-])(?:[a-z]{8}-){7}[a-z]{8}(?![a-z-])")
SECRET_PAIR = re.compile(r"(?i)\b(?:password|passwd|passphrase|secret|api[_-]?key|private[_-]?key|recovery[_-]?key"
                         r"|licen[cs]e[_-]?key)\b[\"']?\s*[:=]\s*[\"']?(?!(?:null|true|false)\b)([^\s\"'<*]{4,})")
CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")


def text_rules(line):
    """Rule names a decoded line breaks. Never returns, logs or echoes the matched text."""
    hits = set()
    if CONTROL.search(line):
        hits.add("control_character")
    for match in EMAIL.finditer(line):
        if match.group(1).lower() not in SYSTEMD_UNIT_SUFFIXES:
            hits.add("email")
    for match in IPV4.finditer(line):
        if not match.group(1).startswith(("127.", "0.0.0.0")):
            hits.add("ip_address")
    for match in IPV6_RUN.finditer(line):
        token = match.group(0)
        if token.count(":") >= 2:
            try:
                address = ipaddress.IPv6Address(token)
            except ValueError:
                continue
            if not (address.is_loopback or address.is_unspecified):
                hits.add("ip_address")
    if MAC.search(line):
        hits.add("mac_address")
    if PEM.search(line):
        hits.add("pem_block")
    if TOKEN.search(line):
        hits.add("token")
    if RECOVERY_KEY.search(line):
        hits.add("recovery_key")
    if SECRET_PAIR.search(line):
        hits.add("secret_pair")
    return hits


def walk_keys(node, depth=0):
    """Forbidden key names holding a non-empty value, anywhere in a JSON value."""
    if depth > JSON_DEPTH:
        return
    if isinstance(node, dict):
        for key, value in node.items():
            if key.lower() in DENY_KEYS and value not in (None, "", False, 0, [], {}):
                yield key
            yield from walk_keys(value, depth + 1)
    elif isinstance(node, list):
        for item in node:
            yield from walk_keys(item, depth + 1)


def load_canaries(path):
    try:
        lines = pathlib.Path(path).read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise Usage(f"cannot read the canary file: {one_line(str(exc))}")
    canaries = [line for line in (raw.rstrip("\r") for raw in lines) if line.strip()]
    if not canaries:
        raise Usage("the canary file has no canary")
    if len(canaries) > MAX_CANARIES:
        raise Usage(f"more than {MAX_CANARIES} canaries")
    if any(len(c) < MIN_CANARY for c in canaries):
        raise Usage(f"every canary must be at least {MIN_CANARY} characters")
    out = []
    for index, canary in enumerate(canaries, 1):
        variants = {canary.encode("utf-8"), json.dumps(canary).strip('"').encode("ascii"),
                    json.dumps(canary, ensure_ascii=False).strip('"').encode("utf-8")}
        out.append((index, {v.lower() for v in variants}))
    return out


def scan_content(documents, canaries):
    """documents: {name: bytes}. -> findings [{file, line, rule}], never the matched text."""
    findings = []

    def add(name, line, rule):
        entry = {"file": name, "line": line, "rule": rule}
        if entry not in findings:
            findings.append(entry)

    for name, body in documents.items():
        lowered = body.lower()
        for index, variants in canaries:
            for variant in variants:
                at = lowered.find(variant)
                if at >= 0:
                    add(name, body.count(b"\n", 0, at) + 1, "canary")
                    break
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError:
            add(name, 0, "non_text")
            text = body.decode("utf-8", "replace")
        for number, line in enumerate(text.split("\n"), 1):
            for rule in sorted(text_rules(line)):
                add(name, number, rule)
        if name.endswith((".json", ".jsonl")):
            chunks = [(0, text)] if name.endswith(".json") else \
                [(n, row) for n, row in enumerate(text.split("\n"), 1) if row.strip()]
            for number, chunk in chunks:
                try:
                    value = json.loads(chunk)
                except (ValueError, RecursionError):
                    continue
                for _ in walk_keys(value):
                    add(name, number, "deny_key")
    return findings


def canary_indexes_in_raw(raw_tar, raw_gz, canaries):
    """A canary in framing, padding or the compressed bytes themselves: the layers a file scan skips."""
    hits = []
    for index, variants in canaries:
        for label, blob in (("tar", raw_tar.lower()), ("gzip", raw_gz.lower())):
            if any(v in blob for v in variants):
                hits.append((index, label))
    return hits


# --- the pipeline ---------------------------------------------------------------------------------------

def ok(checks, name, detail):
    checks.append({"name": name, "ok": True, "detail": detail})


def analyse(args):
    pins = load_pins(args.pin_spki_sha256, args.pins_file)
    canaries = load_canaries(args.canaries) if args.canaries else []
    openssl_bin = find_tool("openssl", OPENSSL_PATHS, args.openssl_bin)
    checks, warnings = [], []
    result = {"checks": checks, "warnings": warnings, "findings": [], "files": [], "unsigned": [], "bundle": {}}

    try:
        kind, gz, outer_name = load_archive(args.bundle, args.key, args.age_bin, warnings)
        ok(checks, "input", kind)
        if kind != "tar.gz":
            ok(checks, "decrypt", "age")
        result["bundle"]["input"] = kind
        check_archive_size(gz)
        ok(checks, "archive_size", f"{len(gz)} bytes")
        raw = gunzip_bounded(gz, warnings)
        ok(checks, "decompress", "single gzip stream within bounds")
        members = read_tar(raw, warnings)
        ok(checks, "tar", "strict ustar, flat names, regular files")
        missing = [n for n in ENVELOPE if n not in members]
        if missing:
            raise Refusal("envelope", f"missing {', '.join(missing)}")
        ok(checks, "envelope", "manifest, signature and SPKI present")
        spki, signature, manifest_raw = (members[n][0] for n in ("device-root.spki.der", "manifest.sig", "manifest.json"))
        check_spki(spki)
        ok(checks, "spki", "ECDSA P-256")
        spki_hash = sha256_hex(spki)
        if spki_hash not in pins:
            raise Refusal("pin", f"the bundle's device key (sha256 {spki_hash}) is not one of the pinned device keys")
        result["bundle"]["pin_label"] = pins[spki_hash]
        ok(checks, "pin", "the device key is pinned")
        verify_signature(spki, signature, DOMAIN + manifest_raw, openssl_bin)
        ok(checks, "signature", "ECDSA-SHA256 over the domain-separated manifest")
        manifest = parse_manifest(manifest_raw, warnings)
        stamp, listed = validate_manifest(manifest)
        ok(checks, "manifest", SCHEMA)
        if manifest["device_root_spki_sha256"] != spki_hash:
            raise Refusal("spki_binding", "the manifest names another device key than the one that signed it")
        ok(checks, "spki_binding", "manifest key == signing key")
        cross_check_files(members, listed)
        ok(checks, "files", "sizes and sha256 match, nothing unlisted")
    except Refusal as refusal:
        checks.append({"name": refusal.check, "ok": False, "detail": refusal.detail})
        result["verdict"] = "refused"
        return result, None

    epoch = int(stamp.replace(tzinfo=datetime.timezone.utc).timestamp())
    if any(mtime != epoch for _, mtime in members.values()):
        warnings.append("tar mtime of an entry differs from generated_at")
    match = ZIP_ID8.match(outer_name or "")
    if match and match.group(1) != manifest["bundle_id"][:8]:
        warnings.append("the zip member name carries another bundle id than the manifest")

    result["bundle"].update({k: manifest[k] for k in (
        "bundle_id", "case_id", "generated_at", "time_source", "boot_id", "collector_version",
        "device_root_spki_sha256", "dropped", "truncated", "redaction")})
    result["bundle"].update({"archive_bytes": len(gz), "expanded_bytes": len(raw)})
    result["files"] = [
        {"path": e["path"], "size": e["size"], "sha256": e["sha256"], "included": e["included"]}
        for e in listed.values()]
    result["unsigned"] = [n for n in UNSIGNED if n in members]

    documents = {n: members[n][0] for n in sorted(members) if n not in ("manifest.sig", "device-root.spki.der")}
    findings = scan_content(documents, canaries)
    if not any(f["rule"] == "canary" for f in findings):
        for index, layer in canary_indexes_in_raw(raw, gz, canaries)[:1]:
            findings.append({"file": f"<{layer}-bytes>", "line": 0, "rule": "canary", "canary": index})
    result["findings"] = findings
    if args.canaries:
        result["bundle"]["canaries_checked"] = len(canaries)
    result["verdict"] = "findings" if findings else "verified"
    return result, members


def render_text(result):
    lines = [f"{result['verdict'].upper()}"]
    for check in result["checks"]:
        lines.append(f"  [{'ok' if check['ok'] else 'FAIL'}] {check['name']}: {check['detail']}")
    bundle = result["bundle"]
    for key in ("bundle_id", "case_id", "generated_at", "time_source", "collector_version", "pin_label"):
        if key in bundle:
            lines.append(f"  {key}: {bundle[key]}")
    for entry in result["files"]:
        size = "excluded" if not entry["included"] else f"{entry['size']} B"
        lines.append(f"  file {entry['path']} ({size})")
    for name in result["unsigned"]:
        lines.append(f"  file {name} (UNSIGNED, produced by the client)")
    for key in ("dropped", "truncated", "redaction"):
        if bundle.get(key):
            lines.append(f"  {key}: {json.dumps(bundle[key], sort_keys=True)}")
    for warning in result["warnings"]:
        lines.append(f"  warning: {warning}")
    for finding in result["findings"]:
        lines.append(f"  FINDING {finding['rule']} in {finding['file']} line {finding['line']}")
    return "\n".join(lines) + "\n"


def emit(result, fmt):
    sys.stdout.write(json.dumps(result, sort_keys=True) + "\n" if fmt == "json" else render_text(result))


def neutralise(body):
    text = body.decode("utf-8", "replace")
    return "".join(c if c in "\n\t" or (c.isprintable() and not 0x7F <= ord(c) <= 0x9F) else "\ufffd" for c in text)


def cmd_show(args, result, members):
    for name in args.members:
        if name not in members or name in ("manifest.sig", "device-root.spki.der"):
            raise Refusal("show", f"{one_line(name, 80)} is not a readable member of this bundle")
    for name in args.members:
        if len(args.members) > 1:
            sys.stdout.write(f"==> {name} <==\n")
        sys.stdout.write(neutralise(members[name][0]))
        if not members[name][0].endswith(b"\n"):
            sys.stdout.write("\n")


def cmd_extract(args, members):
    out = pathlib.Path(args.out)
    if out.is_symlink():
        raise Usage("the destination is a symlink")
    if out.exists():
        if not out.is_dir() or any(out.iterdir()):
            raise Usage("the destination exists and is not an empty directory")
    else:
        out.mkdir(mode=0o700, parents=True)
    os.chmod(out, 0o700)
    for name, (body, _) in sorted(members.items()):
        fd = os.open(out / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(body)
    sys.stderr.write(f"extracted {len(members)} verified members into {out}; delete this directory "
                     "once the case is read (the runbook requires it)\n")


def build_parser():
    parser = argparse.ArgumentParser(prog="ni-support-verify", description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)

    def common(p):
        p.add_argument("bundle", help="ni-support-*.zip, *.tar.gz.age or a decrypted *.tar.gz")
        p.add_argument("--pin-spki-sha256", action="append", metavar="HEX",
                       help="sha256 of the device root SPKI DER pinned at the ceremony (repeatable)")
        p.add_argument("--pins-file", metavar="FILE", help="one pin per line: HEX [label]; # comments")
        p.add_argument("--key", metavar="FILE", help="age identity file of the support key (encrypted input)")
        p.add_argument("--canaries", metavar="FILE", help="strings that must never appear, one per line")
        p.add_argument("--format", choices=("text", "json"), default="text")
        p.add_argument("--age-bin", metavar="PATH")
        p.add_argument("--openssl-bin", metavar="PATH")

    common(sub.add_parser("verify", help="verify and list the bundle"))
    show = sub.add_parser("show", help="print verified members, control characters neutralised")
    common(show)
    show.add_argument("members", nargs="+", metavar="MEMBER")
    extract = sub.add_parser("extract", help="write the verified members into a new private directory")
    common(extract)
    extract.add_argument("--out", required=True, metavar="DIR")
    return parser


def harden():
    os.umask(0o077)
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_CPU, (300, 300))
    except (ValueError, OSError):
        pass


def main(argv=None):
    harden()
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        result, members = analyse(args)
        if result["verdict"] == "refused":
            if args.command == "verify":
                emit(result, args.format)
            else:
                sys.stderr.write("refused: " + "; ".join(
                    f"{c['name']}: {c['detail']}" for c in result["checks"] if not c["ok"]) + "\n")
            return 1
        if args.command == "verify":
            emit(result, args.format)
        else:
            for finding in result["findings"]:
                sys.stderr.write(f"warning: finding {finding['rule']} in {finding['file']} line {finding['line']}\n")
            if args.command == "show":
                cmd_show(args, result, members)
            else:
                cmd_extract(args, members)
            return 0
        return 3 if result["findings"] else 0
    except Usage as exc:
        sys.stderr.write(f"ni-support-verify: {exc}\n")
        return 2
    except Refusal as refusal:
        sys.stderr.write(f"refused: {refusal.check}: {refusal.detail}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
