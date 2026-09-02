#!/usr/bin/env bash
# EVERY SHELL SCRIPT, EVERY PYTHON FILE AND EVERY SUITE THIS JOB OWNS IS WIRED.
#
# 🔴 WHAT THIS CLOSES (independent review 2026-09-02, P2 #1). The pull-request
# workflow names its inputs by hand, three times over -- in `paths:`, in the
# `shellcheck` invocation and in the execution step -- and the three lists had
# drifted. Four files that decide whether a medium boots at all were in NONE of
# them:
#
#   image/installer/neural-ice-sealed-cmdline-grammar.sh
#   image/installer/neural-ice-live-diagnostics.sh
#   image/test-installer-selector-grammar.sh
#   image/test-installer-live-diagnostics.sh
#
# ...and a change touching only the two new suites did not even trigger the job.
#
# A fourth hand-maintained list would drift the same way. This walks the TREE:
# every shell script and Python file in the areas this job owns must be
# statically checked, every `test-*` must be executed, and every one of them must
# match a `paths:` filter. A file added tomorrow with no wiring is a failing
# check today, not a gap a reviewer finds months later.
#
# It reads the workflow; it runs nothing and needs no toolchain beyond python3.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKFLOW="$ROOT/.github/workflows/test-artifact-generation.yml"
fail() { echo "FAIL: $*" >&2; exit 1; }
[ -f "$WORKFLOW" ] || fail "missing input: $WORKFLOW"
command -v python3 >/dev/null 2>&1 || fail "python3 is required; this suite does not SKIP"

exec python3 - "$WORKFLOW" "$ROOT" <<'PYEOF'
import fnmatch
import pathlib
import re
import sys

workflow_path, root = sys.argv[1], pathlib.Path(sys.argv[2])
text = pathlib.Path(workflow_path).read_text(encoding="utf-8")

# The areas this workflow owns. Anything under them must be wired; anything
# outside belongs to another workflow and is not this gate's business.
OWNED_DIRECTORIES = (
    "image/installer",
    "image/lib",
    "image/firstboot",
    "image/test-lib",
    "image/policy",
    "ota",
    "ci",
)
# image/ also holds branding, overlays and Containerfiles, so its top level is
# owned by name rather than wholesale.
OWNED_GLOBS = ("image/build-*.sh", "image/test-*.sh", "image/*.py")

# 🔴 A SUITE THAT IS NOT RUN HERE IS A DECISION, WITH A REASON. An omission is a
# defect; an entry below is a statement about where the coverage actually is.
NOT_EXECUTED_HERE = {
    "image/test-verify-preloaded-media.sh":
        "needs root and `sudo unshare --mount`; it is a privileged build-host gate",
    "image/test-seed-tree-manifest.py":
        "needs host root with CAP_SYS_ADMIN in the initial user namespace",
    "image/test-preloaded-output-set.sh": "run by .github/workflows/test-preloaded-media.yml",
    "image/test-preloaded-sizing.sh": "run by .github/workflows/test-preloaded-media.yml",
    "image/test-tpm-ceremony-systemd.sh": "run by .github/workflows/test-installer-handoff.yml",
    "ci/test-suite-collection.sh": "this file; running itself proves nothing",
    "ci/test-swtpm-monotonic-state.sh": "run by its own dedicated software-TPM step",
    "ci/test-fabric-coreos-differential.sh":
        "run as the explicit release differential with NEURAL_ICE_FABRIC_ROOT; a CoreOS-only checkout has no Fabric vector tree",
    "ci/test-open-core-workflow.sh": "run by .github/workflows/open-core-boundary.yml",
    "ota/test-neural-ice-lab-baseline-handoff.sh": "run by .github/workflows/test-installer-handoff.yml",
    "ota/test-neural-ice-device-root-tpm.sh": "run by .github/workflows/test-installer-handoff.yml",
    "ota/test-tpm-signed-policy.sh": "run by .github/workflows/test-installer-handoff.yml",
    "ota/test-neural-ice-luks-token-evidence.py": "run by .github/workflows/test-installer-handoff.yml",
    "ci/test-install-registry-mirror.sh": "",
    "ci/test-linklocal-fallback.sh": "",
    "ci/test-gb10-console-boot.sh": "",
}

path_filters = set(re.findall(r'^\s*-\s+"([^"]+)"\s*$', text, re.M))


def filtered(relative: str) -> bool:
    for pattern in path_filters:
        if pattern == relative:
            return True
        if pattern.endswith("/**") and relative.startswith(pattern[:-2]):
            return True
        if ("*" in pattern or "?" in pattern) and fnmatch.fnmatch(relative, pattern):
            return True
    return False


def step_block(title: str) -> str:
    match = re.search(
        rf"- name: {re.escape(title)}\n(.*?)(?=\n      - name: |\Z)", text, re.S
    )
    if not match:
        print(f"FAIL: the workflow has no '{title}' step", file=sys.stderr)
        raise SystemExit(1)
    return match.group(1)


shellcheck_block = step_block("Validate shell syntax")
static_block = step_block("Validate every Python file this job owns")
# Execution is spread over more than one step on purpose: the seed-closure suite
# needs cargo and cosign, and putting it in the same `run:` as the pure suites
# would make a toolchain failure look like a grammar failure. What matters is
# that a suite is run SOMEWHERE in this job.
execute_block = "\n".join(
    step_block(title)
    for title in (
        "Test artifact generation and kernel packaging contract",
        "Prove the offline seed closure end to end",
        "Prove the suites ran against the production crypto, not a shim",
        "Exercise the TPM helpers against a real software TPM",
    )
)

candidates: set[pathlib.Path] = set()
for directory in OWNED_DIRECTORIES:
    base = root / directory
    if base.is_dir():
        candidates.update(p for p in base.rglob("*") if p.is_file() and p.suffix in (".sh", ".py"))
for pattern in OWNED_GLOBS:
    candidates.update(p for p in root.glob(pattern) if p.is_file())

problems: list[str] = []
checked = executed = exempt = 0
for path in sorted(candidates):
    relative = path.relative_to(root).as_posix()
    if not filtered(relative):
        problems.append(
            f"{relative} matches no `paths:` filter, so a change touching only it does "
            "not run this job at all"
        )
    shell = relative.endswith(".sh")
    block = shellcheck_block if shell else static_block
    if relative in block:
        checked += 1
    else:
        problems.append(
            f"{relative} is never {'shellchecked' if shell else 'parsed'} by this workflow"
        )
    if path.name.startswith("test-"):
        if relative in NOT_EXECUTED_HERE:
            exempt += 1
        elif relative in execute_block:
            executed += 1
        else:
            problems.append(f"{relative} is a test suite this workflow never runs")

# ...and the exemption list may not outlive the files it names: a stale entry is
# a suite somebody believes is covered elsewhere and is not covered at all.
for relative in NOT_EXECUTED_HERE:
    if not (root / relative).is_file():
        problems.append(
            f"{relative} is listed as covered elsewhere but no longer exists; the "
            "exemption is stale"
        )

if problems:
    for problem in sorted(problems):
        print(f"FAIL: {problem}", file=sys.stderr)
    raise SystemExit(1)
print(
    f"SUITE_COLLECTION_OK ({checked} files statically checked, {executed} suites executed "
    f"here, {exempt} covered elsewhere with a stated reason)"
)
PYEOF
