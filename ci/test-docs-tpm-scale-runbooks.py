#!/usr/bin/env python3
"""The OEM bench, RMA and firmware-update runbooks (OS-0045, task T11) describe a procedure
whose tooling is partly merged, partly in review, partly planned. Nothing planned may read as
existing, so every step states the status of each tool it relies on, and this check ties that
statement to the tree and to a registry of exact PR numbers.

Docs-only contract: no network, no TPM. When a PR merges or a planned tool lands, the check
fails on purpose (a tool directory appears or disappears) until the registry and the runbooks
are updated together.
Run:  python3 -I ci/test-docs-tpm-scale-runbooks.py
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUNBOOKS = {
    "docs/RUNBOOK-OEM-BENCH.md": "B",
    "docs/RUNBOOK-RMA.md": "R",
    "docs/RUNBOOK-FIRMWARE-UPDATE.md": "F",
}
# name -> (status, reference text that must follow the status, path whose presence proves MERGED)
REGISTRY = {
    "ni-bench-snapshot": ("MERGED", "#246", "tools/ni-bench-snapshot"),
    "ni-pcr7-calc": ("MERGED", "#245", "tools/ni-pcr7-calc"),
    "NI-P7-COVERAGE": ("MERGED", "#129", "ota/test-installer-pcr7-coverage.sh"),
    "signed installer": ("MERGED", "on main, ota/neural-ice-autoinstall.sh", "ota/neural-ice-autoinstall.sh"),
    "owner first-boot ceremony": ("MERGED", "on main, ADR-0015 §K", "ota/neural-ice-firstboot-tpm-ceremony.sh"),
    "ni-pcr-rules": ("MERGED", "#247", "tools/ni-pcr-rules"),
    "per-configuration signing": ("IN REVIEW", "ICE-Fabric-v2 #120", None),
    "NI-P7-RULES": ("PLANNED", "OS-0045 D2, P1", None),
    "pcr_rules manifest field": ("PLANNED", "OS-0045 D4, P1", None),
    "ni-pcr-rekey": ("PLANNED", "OS-0045 D4, P1", "tools/ni-pcr-rekey"),
    "NV policy shard": ("PLANNED", "OS-0045 D3, P1", None),
    "installer re-enrolment": ("PLANNED", "OS-0045 consequences, RMA, P1", None),
    "pinned firmware channel": ("PLANNED", "OS-0045 D4 and Q3, no mechanism defined", None),
    "per-device bench record": ("PLANNED", "OS-0045 D5", None),
    "uefi password escrow": ("PLANNED", "OS-0045 D5 and Q4", None),
}
STATUS_RE = re.compile(r"^\*\*Tooling status:\*\*\s*(.*)$")
ITEM_RE = re.compile(r"`([^`]+)`\s*—\s*(MERGED|IN REVIEW|PLANNED)\s*\(([^)]+)\)")

fail = 0


def bad(msg):
    global fail
    fail = 1
    print("FAIL: " + msg, file=sys.stderr)


def read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read().splitlines()


# The registry itself must match the tree.
for name, (status, ref, path) in REGISTRY.items():
    if path is None:
        continue
    exists = os.path.exists(os.path.join(ROOT, path))
    if status == "MERGED" and not exists:
        bad("registry: %s is MERGED but %s is not on the tree" % (name, path))
    if status != "MERGED" and exists:
        bad("registry: %s is %s but %s is now on the tree: update the registry and the runbooks"
            % (name, status, path))

for rel, letter in RUNBOOKS.items():
    if not os.path.exists(os.path.join(ROOT, rel)):
        bad("%s is missing" % rel)
        continue
    lines = read(rel)
    text = "\n".join(lines)
    if "OS-0045" not in text:
        bad("%s does not point to OS-0045" % rel)
    head = re.compile(r"^### (%s\d+) · " % letter)
    steps = [i for i, l in enumerate(lines) if head.match(l)]
    if len(steps) < 3:
        bad("%s has fewer than 3 steps (### %s<n> · title)" % (rel, letter))
    # No planned or in-review tool name inside a fenced code block: a fenced command reads as existing.
    in_fence = False
    for n, l in enumerate(lines, 1):
        if l.lstrip().startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            for name, (status, _, _) in REGISTRY.items():
                if status != "MERGED" and name in l and not l.lstrip().startswith("#"):
                    bad("%s:%d: %s tool %r inside a code block as if it existed" % (rel, n, status, name))
    for k, start in enumerate(steps):
        end = steps[k + 1] if k + 1 < len(steps) else len(lines)
        block_end = end
        for j in range(start + 1, end):
            if re.match(r"^#{1,3} ", lines[j]):
                block_end = j
                break
        block = lines[start:block_end]
        title = lines[start]
        status_lines = [b for b in block if STATUS_RE.match(b)]
        if len(status_lines) != 1:
            bad("%s: step %r needs exactly one '**Tooling status:**' line" % (rel, title))
            continue
        body = STATUS_RE.match(status_lines[0]).group(1).strip()
        listed = {}
        if body.lower().startswith("none"):
            pass
        else:
            for name, st, ref in ITEM_RE.findall(body):
                listed[name] = (st, ref)
            if not listed:
                bad("%s: step %r: status line is neither 'none' nor `tool` — STATUS (ref)" % (rel, title))
        for name, (st, ref) in listed.items():
            if name not in REGISTRY:
                bad("%s: step %r: unknown tool %r (add it to the registry)" % (rel, title, name))
                continue
            rst, rref, _ = REGISTRY[name]
            if st != rst or ref != rref:
                bad("%s: step %r: %r stated %s (%s), registry says %s (%s)" % (rel, title, name, st, ref, rst, rref))
        prose = "\n".join(b for b in block if not STATUS_RE.match(b))
        for name in REGISTRY:
            if name in prose and name not in listed:
                bad("%s: step %r uses %r but its status line does not list it" % (rel, title, name))
    # Each runbook says up front what exists today.
    if not re.search(r"^## Tooling state at the time of writing", text, re.M):
        bad("%s lacks '## Tooling state at the time of writing'" % rel)

# Open core: no serial, EK, key material or sovereign registry name in the three runbooks.
for rel in RUNBOOKS:
    if not os.path.exists(os.path.join(ROOT, rel)):
        continue
    t = "\n".join(read(rel))
    if re.search(r"BEGIN [A-Z ]*PRIVATE KEY|\b[0-9a-f]{64}\b", t):
        bad("%s carries key material or a raw 64-hex digest" % rel)

if not fail:
    print("PASS: T11 runbooks contract")
sys.exit(fail)
