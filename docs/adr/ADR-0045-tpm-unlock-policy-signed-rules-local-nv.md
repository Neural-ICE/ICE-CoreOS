# OS-0045 — TPM unlock policy: signed rules and a local NV policy, not a list of PCR7 values

- **Status**: Accepted (2026-10-06, Owner). Decisions Q1–Q5 are recorded below.
- **Date**: 2026-10-06
- **Decider**: Owner (trust model, keys); coding AI (computation, integration, sequencing)
- **Supersedes**: the decision "unlock is a `PolicyAuthorize` under an Owner key whose signature
  file holds one entry per admitted PCR7 value", as written in
  [TPM-SIGNED-POLICY-RUNBOOK](../TPM-SIGNED-POLICY-RUNBOOK.md) (target state), in
  [OS-0004](../ADR-0004-disk-encryption-tpm-luks.md) ("TPM sealing = PCR 7 only"), and the
  `NI-P7-COVERAGE` gate used as the policy mechanism. It also absorbs the unmerged draft
  "OS-0044 firmware path" (its number is taken by OS-0044, PR #234; its content is D4 and D5 here).
  The supersession takes effect with this acceptance.
- **Relates to**: [OS-0015](../ADR-0015-installer-trust-anchor-uki-verity.md) (NV generation counter),
  OS-0044 (D3 payload `pcr-policy/`, D4 direct `db` enrolment at the OEM bench; PR #234, not yet on
  `main`; not verified here whether it has since merged), ICE-Fabric FAB-0064 and FAB-0066.

## Context

Measured on 2026-10-06 on the code at `f7e53d1`:

- LUKS (both volumes) is enrolled with `PolicyAuthorize` under an Owner public key,
  `--tpm2-pcrs=` empty, `--tpm2-public-key-pcrs=7`. The signature file holds one entry per admitted
  PCR7 value (4 entries, sequence 1145).
- A PCR7 value that is not listed makes the installer refuse (`NI-P7-COVERAGE`) before any write. A
  new firmware or authority-chain combination that moves PCR7 (see "Finding of PR #245" for what
  moves it on GB10) therefore needs a human Owner signature *before* installation, a new JSON, a new
  sealed hash and a new sequence. On the measured GB10 firmwares an update of `dbx`, `KEK` or `PK`
  does not move PCR7 and does not trigger `NI-P7-COVERAGE`.
- The existing predictor works only with the target machine's event log and live PCR7.
- A signature cannot be revoked: a signed PCR7 value keeps unlocking as long as a signature that
  covers it was distributed. On the measured GB10 firmwares PCR7 does not see `dbx`: a state with an
  old `dbx` (for example after *Restore Factory Keys*, or a rollback) unlocks even under a literal
  PCR7 seal, so the signature is not the only reason revocation is absent.
- GB10 Secure Boot databases are maintained through fwupd/LVFS (secondary source) and the Microsoft
  2011 certificates expire in 2026 (series 2023 replaces them). Only an update that changes the `db`
  authority that validates shim, the `SbatLevel` or the boot path moves PCR7 (see the finding below);
  the expiry of a certificate does not change the measurement by itself. When such an update
  happens, the fleet's PCR7 moves outside our calendar.

A read-only capture of the GB10 `.67` was taken on 2026-10-06 (BIOS `GX10DGX.0104.2026.0326.1657`):
SHA-256 PCR7 = `5E0A2492…68437`, Secure Boot enabled, host state `owner-sealed-ota-state-v1`. The
capture files (TCG event log, EFI variables, PCR7) are held outside this repository and are not
committed with this ADR. The design report cites another PCR7 for `.67` (`07bd0bb2…`, §12 point 6,
attributed to "repository proofs"). `REPORT-pcr7-calculator-20261006` explains the difference by
the boot path: `07bd0bb2…` is what the calculator predicts for the installer's `uki-direct` path
and `5e0a2492…` is the installed `shim-grub` path. The confirmation is indirect (an 8-digit prefix
and a 7-digit suffix of the 2026-09-04 installer record match, not the 64 digits) and is **not
verified byte for byte**. The calculator exists as PR #245 (draft, not merged), with fixtures
derived from the PCR7 events only.

### Finding of PR #245 (measured on `.63` and `.67`, 2026-10-06)

On the two GB10 firmwares measured (PNY-built `.63`, BIOS 5.36_0ACUM018; ASUS `.67`, BIOS
`GX10DGX.0104.2026.0326.1657`), `SecureBoot`, `PK`, `KEK`, `db` and `dbx` are logged in PCR7 with a
**zero-length variable data**: the firmware measures their *names*, not their *contents*. The five
digests are identical on both machines although the variables differ (`PK` 983 bytes on `.63`,
1289 on `.67`; `dbx` 1280 against 13068). Consequences, measured:

- PCR7 does **not** bind the contents of `SecureBoot`, `PK`, `KEK`, `db` or `dbx`. It does not move
  on a `dbx`, `KEK` or `PK` update.
- PCR7 is driven by the `db` authority certificate that validates shim, the `SbatLevel`, the
  `MokListRT`/vendor certificate that validates GRUB and the kernel, the separator, and the boot
  path (`shim-grub` against `uki-direct`).
- Cross-prediction holds: the `.63` reference with the `.67` authorities replaced reproduces the
  live PCR7 of the `.67` (ASUS `.67` = `5e0a2492…`, PNY `.63` = `d76b3540…`).
- Shown on two firmwares only. The "contents" measurement mode of the calculator (TCG/EDK2
  behaviour) is implemented but not tested on any firmware; it may hold for AAVMF/EDK2, which is
  not verified here.

This model does not scale to OEM production or RMA (Owner decision, 2026-10-06).

## Decision

D1. **Off-machine computation.** PCR7 is recomputed from a *reference record* (TCG event log, EFI
    variables, measured PCR7) captured once per firmware family, plus a delta (authorities,
    `SbatLevel`, boot path). Replay must reproduce the reference PCR before any prediction is
    accepted. PCR7 = hash-chain over the config events `SecureBoot, PK, KEK, db, dbx, [dbt, dbr]`,
    the separator, then the authority events (`db`, `SbatLevel`, `MokListRT`, …). **On the GB10
    firmwares measured, the config events cover the variable names only (zero-length data): the
    variable contents are not in PCR7 and a delta on `dbx`, `KEK` or `PK` has no effect on it.** The
    "contents" derivation described in systemd v257 `pcrlock.c:2924-2995` applies to firmware that
    measures the data; it is not true on GB10 (finding of PR #245). The separator and the
    authority events are not derivable from variables, hence the reference record.
D2. **Signed rules.** The Owner signs a versioned, sequenced rules file: Secure Boot enabled, PK
    present, not in setup mode, `db ⊆ C`, `dbx ⊇ F`, authorities ∈ A. Two classes of rule input:
    *authorities* (`db` certificate validating shim, `SbatLevel`, vendor certificate, boot path)
    are evaluated on data whose replay equals the **live** PCR7. The *variable contents* (`PK`
    present, `db ⊆ C`, `dbx ⊇ F`, setup mode) are **not attested by PCR7 on GB10**: replay == live
    PCR7 says nothing about them. They can only be verified by reading the EFI variables directly
    (efivars), i.e. on data the TPM does not vouch for. That is a stated limitation and a decision
    input, **not a solved problem**: see "Limitation for the rules engine".
D3. **Sealing.** LUKS is sealed to a local NV policy (`PolicyAuthorizeNV`, `systemd-pcrlock`). An
    Owner `PolicyAuthorize` shard is kept as break-glass. *(Q2; the two-shard unlock is
    not proven, see "Not proven")*
D4. **Updates.** Any firmware or Secure Boot database update follows: qualify → signed transition
    manifest → arm (NV variant, "old ∪ new") → flash → commit (old variant removed). Removing an old
    PCR7 variant revokes **only a state that moves PCR7** (another authority, `SbatLevel` or boot
    path). It does not revoke a `dbx` entry on GB10: PCR7 does not see `dbx`, so there is nothing to
    arm for a `dbx` flash and nothing to remove afterwards. `dbx` revocation rests on the agent
    reading the EFI variables after unlock, not on the TPM. No firmware flash without "armed".
    Firmware updates only through the Neural ICE OTA channel (Q3); no autonomous client fwupd.
D5. **OEM bench.** Pinned firmware, direct `db` enrolment (OS-0044 D4), a bench record per device;
    the bench station holds no PCR policy key. Pinned firmware (Q3); a per-device UEFI
    administrator password generated at the bench and escrowed with the recovery key (Q4); one
    golden unit per firmware family (Q5).
D6. **Kernel binding.** The host will move to a UKI with a signed PCR11 policy (`systemd-measure
    sign`). Until then the policy binds the authority path (the `db` certificate that validates
    shim, the vendor certificate, the `SbatLevel`, the boot path), **not the binaries** and, on GB10,
    **not the contents of `PK`, `KEK` or `dbx`**.

Phasing: **P0** = computation (D1) + reference records + one Owner signature per reference
configuration (the current mechanism, fewer entries); **P1** = D2 + D3 + D4; **P2** = D6. P0 alone
has no revocation and no autonomous update path and must not be deployed at scale without P1.

## Recorded Owner decisions

Decided by the Owner on 2026-10-06. Acceptance of the design is not proof of implementation: see
"Not proven".

| # | Question | Decision (Accepted, 2026-10-06, Owner) |
|---|---|---|
| Q1 | Change of trust model: nominal policy is no longer "signed by the Owner per value" but "signed rules + signed OS agent". | Yes. Accepted. |
| Q2 | Keep an Owner `PolicyAuthorize` shard? | Yes: kept as break-glass and for migration. |
| Q3 | Pinned firmware, or firmware updates managed by OTA? | Firmware pinned at the bench; firmware updates only through the Neural ICE OTA. No autonomous client fwupd. |
| Q4 | UEFI administrator password at the bench, and who holds it? | A per-device UEFI administrator password, generated at the bench and escrowed with the recovery key. |
| Q5 | One golden unit per firmware family? | Yes: one reference (golden) unit per firmware family. Current families: ASUS DGX Spark (`.67`, `.77`, `.72`; BIOS `GX10DGX…`) and PNY-built DGX Spark Founders Edition (`.63`). Recorded as decided; the family boundary rests on an unverified assumption: `.77` exposes no TPM (BIOS 0105, not 0104 as `.67`) and `.72` was not examined. |

## Consequences

These are intended effects of the accepted design. None is built or proven: nothing of P1 is merged.

- No Owner signature per machine, per batch, or per new rule-conformant PCR7 value (P1, not proven).
- Revocation of a *PCR7 variant* becomes possible (variant removed from the NV index); the "armed"
  window is bounded and logged (P1, not proven). It does not revoke a `dbx` entry on GB10, which
  PCR7 does not see (finding of PR #245).
- Variable contents (`PK`, `KEK`, `db`, `dbx`) are enforced by the agent reading the EFI variables,
  not by the TPM (see "Limitation for the rules engine").
- Trust moves from per-value signatures to a signed OS agent and signed rules (Q1, accepted).
- NV counter `0x01500007` would become the rules sequence (P1, not proven).
- RMA: reinstall + rules, no signature; the recovery key remains the last resort (P1, not proven).
- Documents that described a list of PCR7 values as the target are rewritten to point here.

## Limitation for the rules engine (decision input, not solved)

On the GB10 firmwares measured, a rule on variable contents (`PK` present, `db ⊆ C`, `dbx ⊇ F`,
not in setup mode) cannot be vouched for by "replay == live PCR7": that equality holds for any
`dbx`, `KEK` or `PK`. Such a rule can only be evaluated by reading the EFI variables directly, on
data the TPM does not attest. The consequences to settle before P1, none of them decided here:

- the rules engine must read the efivars and treat that read as untrusted by the TPM (an attacker
  with root after unlock, or an old `dbx` restored, is not stopped by PCR7);
- revocation of `dbx` is an agent-side check after unlock, not a TPM refusal; the unlock itself
  succeeds with an old `dbx`;
- whether the rules should also cover firmware that does measure the data (AAVMF/EDK2: unverified);
- whether `systemd-pcrlock lock-secureboot-policy`, which predicts the measurement *with* data, can
  be used on GB10 at all (D3): it would diverge from the real event log.

## Alternatives rejected

- Signed list of values (status quo): does not scale, no revocation.
- Literal PCR7 seal: bricks the device at every firmware or Secure Boot update that moves PCR7
  (another `db` authority validating shim, `SbatLevel`, vendor certificate, boot path). On the
  measured GB10 firmwares it does not brick at a `dbx`, `KEK` or `PK` update, and it does not
  revoke `dbx` either.
- Online signing service `rules → signature`: an online key able to authorise anything, no
  revocation. Fallback only if D3 proves infeasible on GB10 / systemd 257.

## Not proven (must not be claimed to a partner)

Nothing in P1 has been executed or merged. Open points, to be settled on hardware: `PolicyAuthorize` +
`PolicyAuthorizeNV` shards on one keyslot under systemd 257; two systemd-tpm2 tokens under 257
(refused under 255); `--unlock-tpm2-device=` to add a shard; ConnectX-7 option-ROM events in PCR7;
GB10 TPM type (fTPM or discrete), PCR banks, UEFI password protecting key menus, a way to block
fwupd database updates; PCR7 stability between boots and between units of the same firmware; the
normative TCG PFP and UEFI §32 text (unreadable when this was written); the exact `.pcrlock` format.
The PCR7 *derivation from variable contents* is **contradicted** by the real GB10 capture (names
only, finding of PR #245); the calculator's "contents" mode is implemented from the TCG/systemd
description and has been confronted with no firmware. Also not proven:
`systemd-pcrlock lock-secureboot-policy` predicts the measurement with data and would diverge from
the real log on GB10, which threatens D3 (untested); the result holds on two firmwares (`.63`,
`.67`) only; the installer-path value `07bd0bb2…` is confirmed indirectly; the `.77` exposes no TPM
(BIOS `GX10DGX.0105.2026.0505.1153`, cause not established) and the `.72` was not examined; no
x86 or other family was tested.

## Verification clause

An installed machine proves the policy **in force**: LUKS token with `tpm2_pcrlock: true` (and a
`tpm2-pubkey` shard if D3 keeps one), NV index present, rules of sequence N, bench record
retrievable. A token with literal PCRs is the old policy: the machine is not compliant. Recovery is
proven on a device whose policy fails on purpose, before any deployment.

## Migration

Accepted, none of it executed. `.67` / `.72` stay installed: step M0 adds entries under the same key (no change of tokens); M1
delivers the agent in observe-only mode; M2 adds the NV shard to the keyslot, subject to proving two
tokens/shards under systemd 257 (a technical proof, not an Owner decision), with replacement-with-recovery-key as fallback; M3 retires the lab
shard only after proof and only if the Owner break-glass is kept (Q2, decided).
