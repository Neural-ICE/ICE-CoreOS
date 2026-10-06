#!/usr/bin/env python3
"""Interop: a bundle made by the REAL host collector (ICE-Fabric-v2, PR-1) read by this tool.

Not part of the CI suite: it needs a checkout of ICE-Fabric-v2 that has the collector, like
ci/test-fabric-coreos-differential.sh needs one. Run it as a release differential:

    NEURAL_ICE_FABRIC_V2_ROOT=/path/to/ICE-Fabric-v2 python3 -I tools/ni-support-verify/test-collector-interop.py

It reuses the collector's own hermetic Sandbox (synthetic sysroot, software device root behind a
`tpm2_sign` stub that speaks the real `-f tss` format), makes bundles, and requires this tool to
verify them against the sandbox's pinned key, with the collector's planted customer strings as
canaries: the collector's leak oracle and this tool's must agree.
"""
import hashlib
import importlib.util
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
TOOL = HERE / "ni-support-verify.py"
ROOT = os.environ.get("NEURAL_ICE_FABRIC_V2_ROOT")
if not ROOT:
    sys.exit("NEURAL_ICE_FABRIC_V2_ROOT is not set: this differential needs an ICE-Fabric-v2 checkout")
BIN = pathlib.Path(ROOT) / "config" / "bin"
spec = importlib.util.spec_from_file_location("collector_tests", BIN / "test_support_bundle.py")
collector_tests = importlib.util.module_from_spec(spec)
sys.modules["collector_tests"] = collector_tests
spec.loader.exec_module(collector_tests)


def run(*args):
    return subprocess.run([sys.executable, "-I", str(TOOL), *map(str, args)], capture_output=True, text=True,
                          check=False, stdin=subprocess.DEVNULL)


class CollectorInterop(unittest.TestCase):
    def sandbox_bundle(self, **request):
        sandbox = collector_tests.Sandbox(self)
        archive = sandbox.make_bundle(sandbox.request(**request))
        tmp = pathlib.Path(tempfile.mkdtemp(prefix="ni-sv-interop."))
        self.addCleanup(shutil.rmtree, tmp, True)
        path = tmp / "bundle.tar.gz"
        path.write_bytes(archive)
        spki = subprocess.run(["openssl", "pkey", "-in", str(sandbox.tpm_key), "-pubout", "-outform", "DER"],
                              check=True, capture_output=True).stdout
        canaries = tmp / "canaries.txt"
        canaries.write_text("\n".join(collector_tests.CANARIES.values()) + "\n", encoding="utf-8")
        return path, hashlib.sha256(spki).hexdigest(), canaries

    def verify(self, **request):
        path, pin, canaries = self.sandbox_bundle(**request)
        proc = run("verify", path, "--pin-spki-sha256", pin, "--canaries", canaries, "--format", "json")
        wrong = run("verify", path, "--pin-spki-sha256", "0" * 64)
        self.assertEqual(wrong.returncode, 1)
        self.assertIn(proc.returncode, (0, 3), proc.stdout + proc.stderr)
        verdict = json.loads(proc.stdout)
        self.assertTrue(all(c["ok"] for c in verdict["checks"]), verdict["checks"])
        self.assertEqual(verdict["warnings"], [], verdict["warnings"])
        self.assertTrue(verdict["files"])
        return verdict

    def test_default_request_is_verified_and_clean(self):
        verdict = self.verify()
        self.assertEqual(verdict["verdict"], "verified", verdict["findings"])

    def test_opted_in_excerpts_are_the_only_place_free_text_can_be(self):
        """Design D2-A: excerpts are free text by design, read by the user line by line. The collector's
        README pins that limit; this tool reports it, and nothing else in the bundle may carry a canary."""
        verdict = self.verify(sections={name: True for name in (
            "versions", "journals", "app_excerpts", "network", "hardware", "licence", "models")})
        self.assertIn("journal-app-excerpts.jsonl", [f["path"] for f in verdict["files"]])
        self.assertEqual({f["file"] for f in verdict["findings"]}, {"journal-app-excerpts.jsonl"},
                         verdict["findings"])


if __name__ == "__main__":
    unittest.main(verbosity=2, argv=[sys.argv[0]])
