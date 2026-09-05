#!/usr/bin/env python3
"""Real SWTPM credential regression; never connects to a physical TPM.

Run create against two fresh, caller-owned SWTPM UNIX sockets, restart the first
emulator process retaining its state, then run resume with the same arguments.
The caller supplies an isolated OS/container with machine-id and UID 1000, the
candidate binaries, and a stock v257 creds binary. Evidence stays in --work.
This test intentionally locks ONLY the emulated owner hierarchy.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import stat
import struct
import subprocess


SCHEMA = "neural-ice-systemd-srk-swtpm-matrix-v1"


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("phase", choices=("create", "resume"))
    for name in ("creds", "stock-creds", "measure", "tcti", "other-tcti", "work"):
        p.add_argument("--" + name, required=True)
    a = p.parse_args()
    os.umask(0o077)
    for uri in (a.tcti, a.other_tcti):
        if not re.fullmatch(r"swtpm:path=/[A-Za-z0-9_./-]+", uri):
            p.error("only explicit SWTPM UNIX socket URIs are allowed")
        socket = Path(uri.removeprefix("swtpm:path="))
        try:
            socket_mode = os.lstat(socket).st_mode
        except FileNotFoundError:
            p.error("SWTPM socket is absent")
        if socket.is_symlink() or not stat.S_ISSOCK(socket_mode):
            p.error("SWTPM socket is absent")
    if a.tcti == a.other_tcti:
        p.error("different-TPM control must use a separate emulator")
    if pwd.getpwuid(1000).pw_name != "srk-test":
        p.error("UID 1000 must be the isolated srk-test account")
    binaries = {}
    for label, value in (("candidate_creds", a.creds),
                         ("stock_creds", a.stock_creds),
                         ("candidate_measure", a.measure)):
        path = Path(value)
        if not path.is_absolute() or path.is_symlink() or not path.is_file() \
                or not os.access(path, os.X_OK):
            p.error(label + " must be an absolute executable regular non-symlink file")
        binaries[label] = {"path": str(path), "sha256": sha256_file(path)}
    work = Path(a.work)
    if not work.is_absolute() or work.is_symlink() or work.parent.resolve() != work.parent:
        p.error("work must be an absolute, non-symlink task directory")
    if a.phase == "create":
        work.mkdir(mode=0o700, exist_ok=False)
    elif not (work / "created.json").is_file():
        p.error("resume requires completed create evidence")
    machine_id = Path("/etc/machine-id").read_text().strip()
    if not re.fullmatch(r"[0-9a-f]{32}", machine_id):
        p.error("the isolated container must have one persistent machine-id")
    invocation = {
        "schema": SCHEMA,
        "machine_id": machine_id,
        "tcti": a.tcti,
        "other_tcti": a.other_tcti,
        "harness_sha256": sha256_file(Path(__file__)),
        "binaries": binaries,
    }
    if a.phase == "resume":
        created = json.loads((work / "created.json").read_text())
        if created.get("invocation") != invocation:
            p.error("resume must use the create phase's machine-id, sockets, and binaries")
    env = dict(os.environ, TPM2TOOLS_TCTI=a.tcti,
               SYSTEMD_TPM2_DEVICE=a.tcti,
               SYSTEMD_CREDENTIAL_SECRET=str(work / "host.secret"))
    results = []

    def run(args, *, refuse=False, tcti=None):
        e = env.copy()
        if tcti:
            e.update(TPM2TOOLS_TCTI=tcti, SYSTEMD_TPM2_DEVICE=tcti)
        r = subprocess.run([str(x) for x in args], env=e, capture_output=True, timeout=30)
        if (r.returncode == 0) == refuse:
            # Never include captured credential data or tool arguments in errors.
            raise AssertionError("unexpected command outcome, executable=" + str(args[0]))
        return r.stdout

    def decrypt(file, uid, *, signature=None, name="probe", refuse=False, tcti=None, binary=None):
        cmd = [binary or a.creds, "decrypt", "--name=" + name, *uid]
        if signature:
            cmd.append("--tpm2-signature=" + str(signature))
        result = run([*cmd, file], refuse=refuse, tcti=tcti)
        if refuse:
            assert not result, "refused credential emitted plaintext"
        else:
            assert result == (work / "plain").read_bytes(), "plaintext mismatch"

    # Exact upstream format IDs: TPM, host+TPM, scoped host+TPM, each with/without PK.
    ids = {
        "tpm2": "d4062dfb71ad4c86804b40ef1180f1fc",
        "host+tpm2": "1414258818a240cd900bce862db5c7b9",
        "scoped": "2a1f877a4275431ab3f9ed1f5d8f6601",
        "tpm2-pk": "5e2d5c7603724eaf843c6fb5f64098f5",
        "host+tpm2-pk": "afbfeaaceb6a4a3795419d135c47f37b",
        "scoped-pk": "16e492949f94400286758f94b7c52bc7",
    }
    if a.phase == "create":
        for uri in (a.tcti, a.other_tcti):
            assert not run(["tpm2_getcap", "handles-persistent"], tcti=uri).strip(), "TPM is not fresh"
        (work / "plain").write_bytes(b"synthetic-neural-ice-srk-regression")
        for prefix in ("policy", "wrong-policy"):
            run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048",
                 "-out", work / (prefix + ".key")])
            run(["openssl", "pkey", "-in", work / (prefix + ".key"), "-pubout",
                 "-out", work / (prefix + ".pem")])
            signature = run([a.measure, "sign", "--current", "--phase=:", "--bank=sha256", "--json=short",
                             "--private-key=" + str(work / (prefix + ".key")),
                             "--public-key=" + str(work / (prefix + ".pem"))])
            (work / (prefix + ".json")).write_bytes(signature)
        # Stock legacy format works before lock; candidate retains its reader.
        run([a.stock_creds, "encrypt", "--with-key=tpm2", "--tpm2-pcrs=", "--name=probe",
             work / "plain", work / "legacy.cred"])
        decrypt(work / "legacy.cred", [])
        # Establish the persistent SRK before locking the emulated owner hierarchy.
        run([a.creds, "encrypt", "--with-key=tpm2", "--tpm2-pcrs=", "--name=probe",
             work / "plain", work / "before.cred"])
        (work / "owner.auth").write_bytes(os.urandom(32))
        run(["tpm2_changeauth", "-Q", "-c", "o", "file:" + str(work / "owner.auth")])
        run([a.stock_creds, "encrypt", "--with-key=tpm2", "--tpm2-pcrs=", "--name=probe",
             work / "plain", work / "stock-after.cred"], refuse=True)
        decrypt(work / "before.cred", [])

    def align(value):
        return (value + 7) & ~7

    for mode, expected_id in ids.items():
        pk = mode.endswith("-pk")
        scoped = mode.startswith("scoped")
        uid = ["--uid=1000"] if scoped else []
        key = "host+tpm2" if scoped else mode.removesuffix("-pk")
        if pk:
            key += "-with-public-key"
        file = work / (mode + ".cred")
        signature = work / "policy.json" if pk else None
        if a.phase == "create":
            args = [a.creds, "encrypt", "--with-key=" + key, "--tpm2-pcrs=", "--name=probe", *uid]
            if pk:
                args += ["--tpm2-public-key=" + str(work / "policy.pem"), "--tpm2-public-key-pcrs=11"]
            run([*args, work / "plain", file])
        # systemd-creds wraps Base64 at a fixed line width. Remove ASCII
        # whitespace only; strict decoding still refuses every other foreign
        # byte and malformed padding.
        encoded = b"".join(file.read_bytes().split())
        b = base64.b64decode(encoded, validate=True)
        assert b[:16].hex() == expected_id, "unexpected credential format for " + mode
        decrypt(file, uid, signature=signature)
        decrypt(file, uid, signature=signature, name="wrong", refuse=True)
        decrypt(file, uid, signature=signature, tcti=a.other_tcti, refuse=True)
        decrypt(file, uid, signature=signature, binary=a.stock_creds, refuse=True)
        if scoped:
            decrypt(file, ["--uid=0"], signature=signature, refuse=True)
        assert len(b) >= 32, "credential main header is truncated"
        t = align(32 + struct.unpack_from("<I", b, 24)[0])
        assert len(b) >= t + 20, "TPM2 header is truncated"
        blob, policy = struct.unpack_from("<II", b, t + 12)
        offset = t + align(20 + blob + policy)
        assert offset <= len(b), "TPM2 blob/policy fields exceed the credential"
        cases = {}
        if pk:
            decrypt(file, uid, signature=work / "wrong-policy.json", refuse=True)
            decrypt(file, uid, signature=work / "missing-policy.json", refuse=True)
            size = struct.unpack_from("<I", b, offset + 8)[0]
            assert 0 < size < 16384 and offset + 12 + size <= len(b), \
                "public-key field is outside the credential"
            cases["pk-truncated-header"] = b[:offset + 11]
            cases["pk-truncated-body"] = b[:offset + 12 + size - 1]
            x = bytearray(b)
            x[offset] ^= 1
            cases["pk-altered-mask"] = x
            x = bytearray(b)
            struct.pack_into("<I", x, offset + 8, 0xffffffff)
            cases["pk-oversize"] = x
            offset += align(12 + size)
        size = struct.unpack_from("<I", b, offset)[0]
        assert 0 < size < 16384 and offset + 4 + size <= len(b), \
            "pinned SRK field is outside the credential"
        for label, value in (("srk-empty", 0), ("srk-oversize", 0xffffffff)):
            x = bytearray(b)
            struct.pack_into("<I", x, offset, value)
            cases[label] = x
        cases["srk-truncated-header"] = b[:offset + 3]
        cases["srk-truncated-body"] = b[:offset + 4 + size - 1]
        x = bytearray(b)
        x[offset + 4 + size - 1] ^= 1
        cases["srk-altered"] = x
        x = bytearray(b)
        x[-1] ^= 1
        cases["auth-tag-altered"] = x
        for label, data in cases.items():
            bad = work / (mode + "-" + label + ".cred")
            bad.write_bytes(base64.b64encode(data))
            decrypt(bad, uid, signature=signature, refuse=True)
        results.append({
            "mode": mode,
            "format_id": expected_id,
            "roundtrip": True,
            "wrong_name_refused": True,
            "wrong_uid_refused": scoped,
            "wrong_or_missing_policy_refused": pk,
            "different_tpm_refused": True,
            "stock_reader_refused": True,
            "negative_header_cases": len(cases),
            "phase": a.phase,
        })
    report = {
        "invocation": invocation,
        "results": results,
        "owner_lock_control": "stock writer refused after owner authorization changed in create",
        "auto_modes": "require booted VM; container detection suppresses TPM",
    }
    (work / ("created.json" if a.phase == "create" else "resumed.json")).write_text(json.dumps(report) + "\n")
    print(json.dumps(report))


if __name__ == "__main__":
    main()
