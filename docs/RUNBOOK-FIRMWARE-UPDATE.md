# Runbook — firmware and Secure Boot database update: predict first, flash only through the OTA

> **Scope.** Changing the firmware (or a Secure Boot database) of fielded GB10 units without
> bricking their unlock. Decided in [OS-0045](adr/ADR-0045-tpm-unlock-policy-signed-rules-local-nv.md)
> (D4 updates; Q3: firmware pinned at the bench, updated **only** through the Neural ICE OTA,
> no autonomous client `fwupd`). Companion runbooks: [OEM bench](RUNBOOK-OEM-BENCH.md), [RMA](RUNBOOK-RMA.md).

## Tooling state at the time of writing

Written 2026-10-06 against `origin/main` at `ea12cca`.

🔴 **Today there is no firmware update path.** The OTA channel carries the OS image; no firmware
capsule channel, no armed state, no commit exists. **Do not flash a fielded unit.** The parts of this
procedure that can be done today are the qualification (F1) and the decision whether PCR 7 moves
(F2). Everything from F4 on is PLANNED: it is the target, not a procedure.

| Tool | State | Reference |
|---|---|---|
| `ni-bench-snapshot`, `ni-pcr7-calc` | MERGED | #246, #245 |
| `ni-pcr-rules` | MERGED | #247 |
| `per-configuration signing` | IN REVIEW | ICE-Fabric-v2 #120 |
| `pcr_rules manifest field`, `ni-pcr-rekey` (armed / commit) | PLANNED | OS-0045 D4, P1 |
| `NV policy shard` | PLANNED | OS-0045 D3, P1 |
| `pinned firmware channel` (the signed way a capsule reaches a unit) | PLANNED | OS-0045 D4 and Q3, no mechanism defined |

## What moves PCR 7 on a GB10

Measured on two firmwares: only a change of the `db` authority that validates shim, of the
`SbatLevel`, of the vendor certificate or of the boot path. A `dbx`, `KEK` or `PK` update does **not**
move PCR 7 (names only are measured), so there is nothing to arm for it, and PCR 7 does not revoke a
`dbx` entry either: a restored old `dbx` still unlocks. That deduction is not measured before/after
an actual variable update. Revoking `dbx` is an agent-side check after unlock (P1), not a TPM refusal.

### F1 · Qualify the new version on the reference unit
**Tooling status:** `ni-bench-snapshot` — MERGED (#246); `ni-pcr7-calc` — MERGED (#245)

Apply the new firmware on the family's reference unit at the bench, then capture both paths as in
B5 of the bench runbook, producing a **new reference record**. Cross-check: the calculator, starting
from the previous record and the announced change, must find the PCR 7 you measured. If it does not,
the version is refused: the model of the firmware is wrong.

```sh
python3 -I tools/ni-pcr7-calc/ni-pcr7-calc.py extract LOG --out ref.json   # LOG: TCG2 event log of the qualified boot
python3 -I tools/ni-pcr7-calc/ni-pcr7-calc.py compute ref.json --explain
```

### F2 · Decide whether PCR 7 moves
**Tooling status:** `ni-pcr7-calc` — MERGED (#245)

Compare the new record's PCR 7 with the old one, per path. Equal on both: the unlock cannot be
affected by this version through PCR 7; go to F8 for the revocation side only. Different: the version
needs F3–F7 before any fielded unit is touched.

### F3 · The Owner signs the new configuration, before anyone flashes
**Tooling status:** `ni-bench-snapshot` — MERGED (#246); `per-configuration signing` — IN REVIEW (ICE-Fabric-v2 #120)

Sign a new bench sheet (sequence strictly above the stored one) as in B6, and — mechanism in force —
an Owner signature covering **both** the old and the new PCR 7, so that a unit is admitted before
and after the flash (the "two updates" ordering of TPM-SIGNED-POLICY-RUNBOOK §4: prepare, verify,
then act). Sign only configurations that are the result of the F1 qualification. The signature file
travels with a signed OTA image. Per-configuration signing and its CI check are in review.

### F4 · OTA no. 1: deliver the transition manifest and the agent — firmware untouched
**Tooling status:** `pcr_rules manifest field` — PLANNED (OS-0045 D4, P1); `ni-pcr-rekey` — PLANNED (OS-0045 D4, P1); `NV policy shard` — PLANNED (OS-0045 D3, P1)

Planned: an image that carries an Owner-signed transition manifest (from: admitted states; to: the
new PCR 7; variable digests; `dbx` floor; sequence) and the agent that checks its signature,
evaluates the rules on the predicted state, writes the "old ∪ new" variant into the NV policy,
re-reads it and reports `armed`. None of these exists. Whether an `armed` policy and an Owner shard
can coexist on one keyslot under systemd 257 is **not proven**.

### F5 · Barrier
**Tooling status:** `ni-pcr-rekey` — PLANNED (OS-0045 D4, P1)

Planned: a unit that is not `armed` is not eligible for the flash; the fleet moves in rings while
the share of armed units is above a threshold. No telemetry of the `armed` state exists.

### F6 · OTA no. 2: the firmware capsule, through the signed channel only
**Tooling status:** `ni-pcr-rekey` — PLANNED (OS-0045 D4, P1); `pinned firmware channel` — PLANNED (OS-0045 D4 and Q3, no mechanism defined)

Planned (Q3): the capsule comes only from the Neural ICE signed channel, whose mechanism (format, signature, delivery) is not defined yet; a client `fwupd` refresh
and its remote are disabled (exact commands not validated; whether the GB10 offers a way to block the
vendor database updates is not established). If Microsoft or the OEM pushes a database through another
path, the unit is simply not `armed`: it falls to recovery at next boot.

### F7 · Commit
**Tooling status:** `ni-pcr-rekey` — PLANNED (OS-0045 D4, P1)

Planned: after a successful unlock under the new PCR 7, the agent removes the old variant only if the
manifest raises the `dbx` floor; otherwise it keeps it until the window ends. Removing a variant
revokes only a state that moves PCR 7.

### F8 · Failure and revocation of `dbx`
**Tooling status:** `ni-pcr-rules` — MERGED (#247); `NV policy shard` — PLANNED (OS-0045 D3, P1)

If the unit does not unlock: the recovery key opens the volumes. For a configuration that is
conformant but not covered, the only mechanism today is a new Owner-signed entry (P0) delivered in
a new image. The break-glass shard of OS-0045 D3 (Q2) is PLANNED and its two-shard unlock is
**not proven**; the ESP is only the manual escape hatch of TPM-SIGNED-POLICY-RUNBOOK, not a
procedure of this runbook. The rules engine (merged) evaluates `dbx ⊇ floor` by reading the EFI
variables, data the TPM does not attest; it is installed on no unit and no installer gate calls it.

## What this runbook does not give you

No procedure to flash a fielded unit exists. Before writing to a customer that "firmware updates are
safe", P1 (`NI-P7-RULES`, the NV policy, the agent) must be merged and proven on hardware (OS-0045,
"Not proven").
