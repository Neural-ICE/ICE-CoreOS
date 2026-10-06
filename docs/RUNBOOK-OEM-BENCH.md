# Runbook — OEM bench: pinned firmware, reference unit, signed bench sheet

> **Scope.** Preparing a Neural ICE appliance (GB10 families) on an OEM bench so that its
> TPM unlock policy is the one decided in [OS-0045](adr/ADR-0045-tpm-unlock-policy-signed-rules-local-nv.md)
> (Accepted, Owner, 2026-10-06: Q3 pinned firmware, Q4 per-device UEFI administrator password
> escrowed with the recovery key, Q5 one reference unit per firmware family).
> Companion runbooks: [RMA](RUNBOOK-RMA.md), [firmware update](RUNBOOK-FIRMWARE-UPDATE.md).
> The mechanism in force today is [TPM-SIGNED-POLICY-RUNBOOK](TPM-SIGNED-POLICY-RUNBOOK.md).

**How to read the status lines.** Every step ends its heading with a `Tooling status:` line.
`MERGED` = on `main` today. `IN REVIEW` = an open PR, **not usable from `main`**.
`PLANNED` = no code exists; the step is manual or cannot be done yet. A command shown in a
code block is MERGED tooling only. This is checked by `ci/test-docs-tpm-scale-runbooks.py`.

## Tooling state at the time of writing

Written 2026-10-06 against `origin/main` at `c507a8b`.

| Tool | State | Reference |
|---|---|---|
| `ni-bench-snapshot` (capture, reference record, bench sheet) | MERGED | #246 |
| `ni-pcr7-calc` (offline PCR 7 replay / prediction) | MERGED | #245 |
| `NI-P7-COVERAGE` (installer refuses an uncovered live PCR 7 before any write) | MERGED | #129 |
| signed installer and owner first-boot ceremony | MERGED | on main (`ota/`), no single PR |
| `ni-pcr-rules` (Owner-signed rules engine) | IN REVIEW | #247 |
| `per-configuration signing` (one Owner signature per reference configuration, CI check) | IN REVIEW | ICE-Fabric-v2 #120 |
| `NI-P7-RULES` installer gate, `ni-pcr-rekey` agent, NV policy shard, installer re-enrolment, per-device bench record, UEFI password escrow | PLANNED | OS-0045 tasks T5, T7, T8, T10, T11 |

Until `NI-P7-RULES` and the NV policy exist, the admission of a PCR 7 value at install time is
still the signed-entry mechanism (P0 of OS-0045): a unit whose live PCR 7 is not covered is
refused. P0 alone has no revocation and no autonomous update path and **must not be deployed
at scale** (OS-0045, Phasing).

## What PCR 7 does and does not prove on a GB10

On the two firmwares measured (PNY-built `.63`, ASUS `.67`) PCR 7 carries the *names* of
`SecureBoot`, `PK`, `KEK`, `db`, `dbx`, not their contents. It moves with the `db` authority that
validated shim, the `SbatLevel`, the vendor certificate and the boot path. Nothing here claims
more, and nothing here has been shown on a family other than those two.

## Prerequisites

- One **reference (golden) unit per firmware family** (Q5). Current families: ASUS DGX Spark
  (BIOS `GX10DGX.0104…`) and PNY-built DGX Spark Founders Edition (BIOS `5.36_0ACUM018`). The
  boundary between families is an unverified assumption: one ASUS unit exposes no TPM at BIOS
  `GX10DGX.0105…` and another unit was not examined. A unit outside a captured family is a new
  family: it needs its own reference unit before any production unit of it.
- The pinned firmware set (Q3), qualified on the reference unit. Production units are brought to
  exactly that set; nothing newer, nothing older.
- The Owner's public key and the Owner's offline machine. **The bench holds no signing key.**
- The bench station holds no PCR policy key (OS-0045 D5).

### B1 · Record the unit and pin its firmware
**Tooling status:** none (manual; read-only commands of the OS)

Record, outside this repository, the unit's serial and the version of every firmware component
(`fwupdmgr get-devices` is read-only; do not run `refresh` or `update`). Compare with the
pinned set. Any difference is fixed through the Neural ICE channel only (Q3), on the bench,
before going on. Serials and hardware identifiers are kept in the bench record, never in the
open-core tree.

### B2 · Put the unit in factory state
**Tooling status:** none (manual, physical presence)

Clear the TPM with physical presence. Factory Secure Boot state: Secure Boot enabled, platform
key enrolled, user mode. Boot order frozen. The bench station must not reach an update source
for the firmware (no LVFS mirror, no network path for `fwupd`); the exact command that removes
the remote is **not validated yet** — verify it on the reference unit and record it.

### B3 · Set the per-device UEFI administrator password and escrow it (Q4)
**Tooling status:** `uefi password escrow` — PLANNED (T11)

1. Generate a password **per device**, from a CSPRNG, at the bench. Never reuse one across units.
2. Set it in the firmware setup.
3. Escrow it in the same custody as that device's recovery key (ADR-0004, recovery model),
   under the device serial. It never goes into the repository, the snapshot, the bench sheet,
   a log or a ticket.
4. **Verify, do not assume**: with the password set, confirm that the key-management menus
   (*Restore Factory Keys*, *Reset To Setup Mode*, *Expert Key Management*) refuse to act
   without it. Whether the GB10 firmware protects them is **not established** (OS-0045,
   "Not proven"). If a unit does not, it does not meet Q4: stop and escalate to the Owner.

No tooling exists to generate, store or retrieve this secret. Which of the two recovery keys it
travels with (system escrow held by Neural ICE, or the data key handed to the owner) is not
stated by Q4; this runbook assumes the **Neural ICE system escrow**, since the owner must not
hold a secret that changes the firmware trust. Confirm with the Owner.

### B4 · Enrol the production certificate directly in the authorised signature database
**Tooling status:** none (manual, firmware menus)

Direct `db` enrolment of the production signing certificate, nothing else (OS-0044 D4, PR #234,
draft: the decision is not on `main`). Enable Secure Boot. Do not enrol Microsoft certificates
unless the family's reference says so.

### B5 · Reference unit only — capture both boot paths
**Tooling status:** `ni-bench-snapshot` — MERGED (#246); `ni-pcr7-calc` — MERGED (#245)

On the reference unit, once from the installer medium and once from the installed system:

```sh
T=tools/ni-bench-snapshot/ni-bench-snapshot.py
python3 -I $T capture --path installer --out installer.json </dev/null   # on the unit, read-only
python3 -I $T capture --path installed --out installed.json </dev/null   # after the install boot
python3 -I $T build-record --installer installer.json --installed installed.json --out record.json
python3 -I tools/ni-pcr7-calc/ni-pcr7-calc.py replay LOG --expect <live PCR 7>   # replay must equal live
```

`capture` refuses an incomplete snapshot, Secure Boot off, an empty `PK`, a PCR 7 the log does not
replay to. The capture is an **operator attestation**, not a proof: no TPM quote binds it to a live
boot (`ni-bench-snapshot` README, "Honest limits"). No installer-path snapshot of a physical unit
exists yet; the store refuses a synthetic one.

### B6 · Reference unit only — the Owner signs the bench sheet
**Tooling status:** `ni-bench-snapshot` — MERGED (#246); `per-configuration signing` — IN REVIEW (ICE-Fabric-v2 #120)

```sh
python3 -I $T make-sheet --record record.json --seq <n> --issued-at <date> --pubkey owner.pub.pem --out sheet.json
python3 -I $T sheet-payload sheet.json --out payload.bin       # the Owner signs THIS, offline
python3 -I $T store --record record.json --sheet sheet.json --signature sheet.sig \
    --installer-snapshot installer.json --installed-snapshot installed.json \
    --root <repo>/trust/<env>/pcr-reference --pubkey owner.pub.pem
```

The Owner signs `payload.bin` on their own machine (`openssl dgst -sha256 -sign`); the signature
pins the firmware and the expected PCR 7 of each path. The sheet is per **family**, not per
serial. The sheet key also signs PCR policy digests: domain separation keeps them apart, but a
dedicated key is the design's wish. Turning the sheet into the admitted policy entry — one Owner
signature per reference configuration and a CI check that every configuration of the matrix has
one — is in review and not usable from `main`.

### B7 · Production unit — install and compare with the family reference
**Tooling status:** `signed installer` — MERGED (on main, ota/neural-ice-autoinstall.sh); `ni-pcr7-calc` — MERGED (#245); `NI-P7-COVERAGE` — MERGED (#129); `NI-P7-RULES` — PLANNED (T5); `per-device bench record` — PLANNED (T11)

Boot the signed installer medium and install. Today the installer refuses before any write when
the live PCR 7 is not covered by a signed entry (`NI-P7-COVERAGE`). A refusal means the unit is
not at the pinned configuration: **set it aside**; do not ask for an emergency signature. The rules
gate that would replace this per-value test (`NI-P7-RULES`) does not exist.

Comparing each production unit's PCR 7 with the signed family sheet, and keeping a per-unit
record, have no tooling: do it by hand with `ni-pcr7-calc replay` until a per-device record exists.

### B8 · Production unit — owner first-boot ceremony and proof of the policy in force
**Tooling status:** `owner first-boot ceremony` — MERGED (on main, ADR-0015 §K)

After the first boot, check what the Verification clause of OS-0045 asks that exists today: the
LUKS tokens of both volumes are bound to the Owner public key (a token showing literal PCR values
is the old policy: the unit is **not** compliant). The NV index, the rules sequence and the
retrievable bench record of the clause are P1 and cannot be checked yet.

### B9 · Seal, sample, and keep the file
**Tooling status:** none (manual)

Power off and seal. **Sample**: unlock-without-prompt on a share of units chosen by the Owner.
Keep per serial: firmware set, the sheet reference, the UEFI password escrow reference, the
install proof. This file is what the RMA starts from; it lives outside the open-core tree.

## What this runbook does not give you

No revocation, no per-machine update path, no tooling for B3 and for the per-unit parts of B7,
and the rules (`ni-pcr-rules`, IN REVIEW #247) are not installed anywhere. Do not describe the
bench to a partner as policy-at-scale before P1 is merged and proven on hardware.
