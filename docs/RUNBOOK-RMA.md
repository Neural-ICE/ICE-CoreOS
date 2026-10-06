# Runbook — RMA: replacement board, same pinned firmware, reinstall, re-enrolment

> **Scope.** A returned unit whose board (and so its TPM and its UEFI variables) is replaced.
> Decided in [OS-0045](adr/ADR-0045-tpm-unlock-policy-signed-rules-local-nv.md) (Accepted, Owner,
> 2026-10-06; Q3 pinned firmware, Q4 per-device UEFI password escrowed with the recovery key).
> Starts from the file kept at the end of the [OEM bench](RUNBOOK-OEM-BENCH.md) (step B9).

## Tooling state at the time of writing

Written 2026-10-06 against `origin/main` at `ea12cca`. The bench tooling is the one listed in
[RUNBOOK-OEM-BENCH](RUNBOOK-OEM-BENCH.md). What matters here: **there is no re-enrolment mode.**
Today the only way to put a new TPM under a unit is to reinstall, which wipes the disk. A mode that
re-enrols from the recovery key without erasing (`installer re-enrolment`, OS-0045 consequences, P1) is
PLANNED. The rules engine (`ni-pcr-rules`, MERGED #247) exists but is installed on no unit and no installer gate calls it.

## Cases

| Case | Effect | Section |
|---|---|---|
| **A** board / TPM replaced | new TPM: new SRK, empty NV, new UEFI variables; PCR 7 changes; existing LUKS tokens do not reopen; only the recovery key opens the old disk | R1–R7 |
| **B** disk replaced, TPM intact | data lost; reinstall (possible before the owner ceremony, see TPM-SIGNED-POLICY-RUNBOOK §8bis); after the ceremony a signed physical recovery with TPM Clear | R1, R5 |
| **C** firmware re-flashed in the workshop | PCR 7 may move; the workshop is a bench: pinned firmware | R3, firmware runbook |
| **D** no hardware change | unlock test only; no action | R1 |

### R1 · Receive and triage
**Tooling status:** none (manual, read-only)

Identify the unit by its serial (kept in the bench file, not in this repository). Decide the case.
If the unit still boots, check that it unlocks without prompt; do not clear the TPM, do not reset
Secure Boot, do not change the UEFI password.

### R2 · Secure the recovery material before touching hardware
**Tooling status:** none (manual)

The system volume is reinstallable from the registry (nothing irreplaceable). The **data volume is
not**: on a replaced board it opens only with its recovery key, which was handed to the device owner
at installation (ADR-0004, recovery model). Obtain it from the owner **before** any reinstall. Without it
the data is lost and the owner must be told so before the board is replaced. The unit's UEFI
administrator password (Q4) is retrieved from escrow only to open the firmware menus on the bench.

### R3 · Replacement board: the pinned firmware, nothing else
**Tooling status:** `ni-bench-snapshot` — MERGED (#246); `ni-pcr7-calc` — MERGED (#245); `pinned firmware channel` — PLANNED (OS-0045 D4 and Q3, no mechanism defined)

On the replacement board, redo the bench steps B1–B4 of the [OEM bench runbook](RUNBOOK-OEM-BENCH.md):
record the firmware set; it must already be the **pinned** set of the family. The channel that would
bring a board to it (Q3) is not defined and no tool exists: a board at another set is set aside, and
nothing is flashed with a vendor tool or `fwupd`. TPM clear with physical presence, **a new UEFI
administrator password** escrowed under the unit's serial (the old board's password is retired,
not reused), Secure Boot enabled, production certificate enrolled directly in `db`.
A board that arrives at another firmware set than the pinned one is a case of the firmware runbook,
not of this one.

### R4 · Compare the new board with the family reference
**Tooling status:** `ni-pcr7-calc` — MERGED (#245); `NI-P7-COVERAGE` — MERGED (#129); `per-configuration signing` — IN REVIEW (ICE-Fabric-v2 #120); `per-device bench record` — PLANNED (OS-0045 D5)

Capture the PCR 7 of the new board booted from the installer medium and replay it:

```sh
python3 -I tools/ni-pcr7-calc/ni-pcr7-calc.py replay LOG --expect <live PCR 7>
```

It must reproduce the signed reference PCR 7 of the unit's family (installer path). If it does not,
the board is **not** at the reference configuration: set it aside; do not obtain an emergency
signature. Until the rules gate exists, a PCR 7 not covered by a signed entry makes the installer
refuse in any case (`NI-P7-COVERAGE`); an entry for a new configuration is a firmware-runbook
decision (one Owner signature per reference configuration, in review).

### R5 · Reinstall
**Tooling status:** `signed installer` — MERGED (on main, ota/neural-ice-autoinstall.sh); `owner first-boot ceremony` — MERGED (on main, ADR-0015 §K)

Reinstall from the signed medium; the installer wipes the disk and creates new tokens under the new
TPM. The NV indices and the device root live in the TPM, so the owner ceremony runs again on first
boot. That a replaced board replays the whole ceremony is the expected consequence of a new TPM; it
has **not been exercised on a physical RMA board** and must be rehearsed once on a bench unit before
this runbook is relied on. **Data on the old disk is gone after this step**: copy it off first
(R6) or accept the loss.

### R6 · Keep the owner's data (only if the old disk is kept)
**Tooling status:** `installer re-enrolment` — PLANNED (OS-0045 consequences, RMA, P1)

Planned: an installer mode that takes the recovery key, creates the new tokens and does not touch the
data. It does not exist. Today, to keep data, unlock the old data volume by hand with its recovery key
on a separate machine, copy the data off, reinstall (R5), and restore it. This manual path is not
recorded as rehearsed here; rehearse it on a bench unit with disposable data before using it on a
customer's.

### R7 · Prove, record, ship
**Tooling status:** `per-device bench record` — PLANNED (OS-0045 D5); `uefi password escrow` — PLANNED (OS-0045 D5 and Q4)

After the first boot, check that both LUKS tokens are bound to the Owner public key (a token with
literal PCR values is not compliant) and that unlock without prompt works after a reboot. Update the
unit's file: new firmware record, new escrow reference of the UEFI password, the retired board's
identifiers, the install proof. There is no tool for the file nor for the escrow.

## What this runbook does not give you

No signature-free RMA yet: the rules engine and the NV policy that would make a reinstall "evaluate
the rules and seal locally, no Owner signature" (OS-0045 consequences) are not merged. Today a
replaced board must land on a PCR 7 an Owner signature already covers.
