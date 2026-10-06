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
  new firmware / `db` / `dbx` / `KEK` / authority-chain combination therefore needs a human Owner
  signature *before* installation, a new JSON, a new sealed hash and a new sequence.
- The existing predictor works only with the target machine's event log and live PCR7.
- A signature cannot be revoked: a state with an old `dbx` (for example after *Restore Factory
  Keys*) keeps unlocking as long as a signature that covers it was distributed.
- GB10 Secure Boot databases are maintained through fwupd/LVFS (secondary source) and the Microsoft
  2011 certificates expire in 2026 (series 2023 replaces them). PCR7 of the fleet will move, in waves,
  outside our calendar.

A read-only capture of the GB10 `.67` was taken on 2026-10-06 (BIOS `GX10DGX.0104.2026.0326.1657`):
SHA-256 PCR7 = `5E0A2492…68437`, Secure Boot enabled, host state `owner-sealed-ota-state-v1`. The
capture files (TCG event log, EFI variables, PCR7) are held outside this repository and are not
committed with this ADR. The design report cites another PCR7 for `.67` (`07bd0bb2…`, §12 point 6,
attributed to "repository proofs"; not found in this repository at `f7e53d1`); the difference is
not explained and is **not verified**. No PCR7 calculator exists: it is planned (task T1) and would
take captures of this kind as fixtures, which is not done.

This model does not scale to OEM production or RMA (Owner decision, 2026-10-06).

## Decision

D1. **Off-machine computation.** PCR7 is recomputed from a *reference record* (TCG event log, EFI
    variables, measured PCR7) captured once per firmware family, plus a delta (variables,
    authorities). Replay must reproduce the reference PCR before any prediction is accepted.
    PCR7 = hash-chain over `SecureBoot, PK, KEK, db, dbx, [dbt, dbr]`, separator, then authority
    events (systemd v257 `pcrlock.c:2924-2995`). Variables are derivable from their blobs; separator
    and authority events are not, hence the reference record.
D2. **Signed rules.** The Owner signs a versioned, sequenced rules file: Secure Boot enabled, PK
    present, not in setup mode, `db ⊆ C`, `dbx ⊇ F`, authorities ∈ A. Rules are evaluated only on
    data whose replay equals the **live** PCR7, never on raw `efivars`.
D3. **Sealing.** LUKS is sealed to a local NV policy (`PolicyAuthorizeNV`, `systemd-pcrlock`). An
    Owner `PolicyAuthorize` shard is kept as break-glass. *(Q2; the two-shard unlock is
    not proven, see "Not proven")*
D4. **Updates.** Any firmware or Secure Boot database update follows: qualify → signed transition
    manifest → arm (NV variant, "old ∪ new") → flash → commit (old variant removed = revocation).
    No firmware flash without "armed". Firmware updates only through the Neural ICE OTA channel (Q3);
    no autonomous client fwupd.
D5. **OEM bench.** Pinned firmware, direct `db` enrolment (OS-0044 D4), a bench record per device;
    the bench station holds no PCR policy key. Pinned firmware (Q3); a per-device UEFI
    administrator password generated at the bench and escrowed with the recovery key (Q4); one
    golden unit per firmware family (Q5).
D6. **Kernel binding.** The host will move to a UKI with a signed PCR11 policy (`systemd-measure
    sign`). Until then the policy binds the keys and the authority path, **not the binaries**.

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
| Q5 | One golden unit per firmware family? | Yes: one reference (golden) unit per firmware family. Current families: ASUS DGX Spark (`.67`, `.77`, `.72`; BIOS `GX10DGX…`) and PNY-built DGX Spark Founders Edition (`.63`). |

## Consequences

These are intended effects of the accepted design. None is built or proven: nothing of P1 is merged.

- No Owner signature per machine, per batch, or per new rule-conformant PCR7 value (P1, not proven).
- Revocation becomes possible (variant removed from the NV index); the "armed" window is bounded
  and logged (P1, not proven).
- Trust moves from per-value signatures to a signed OS agent and signed rules (Q1, accepted).
- NV counter `0x01500007` would become the rules sequence (P1, not proven).
- RMA: reinstall + rules, no signature; the recovery key remains the last resort (P1, not proven).
- Documents that described a list of PCR7 values as the target are rewritten to point here.

## Alternatives rejected

- Signed list of values (status quo): does not scale, no revocation.
- Literal PCR7 seal: bricks the device at every Secure Boot database or firmware update.
- Online signing service `rules → signature`: an online key able to authorise anything, no
  revocation. Fallback only if D3 proves infeasible on GB10 / systemd 257.

## Not proven (must not be claimed to a partner)

Nothing in P1 has been executed or merged. Open points, to be settled on hardware: `PolicyAuthorize` +
`PolicyAuthorizeNV` shards on one keyslot under systemd 257; two systemd-tpm2 tokens under 257
(refused under 255); `--unlock-tpm2-device=` to add a shard; ConnectX-7 option-ROM events in PCR7;
GB10 TPM type (fTPM or discrete), PCR banks, UEFI password protecting key menus, a way to block
fwupd database updates; PCR7 stability between boots and between units of the same firmware; the
normative TCG PFP and UEFI §32 text (unreadable when this was written); the exact `.pcrlock` format.
The PCR7 *derivation from variables* is read from systemd source and is verified against the real
capture by the calculator's tests, not by this ADR.

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
