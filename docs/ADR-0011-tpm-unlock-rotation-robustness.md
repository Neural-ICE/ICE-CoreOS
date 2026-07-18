# ADR-0011 — TPM/LUKS auto-unlock across Secure Boot rotation

- **Status**: Accepted (Owner GO 2026-07-18); amends [ADR-0004](ADR-0004-disk-encryption-tpm-luks.md)
- **Date**: 2026-07-18
- **Decider**: Business/Security Owner (human)
- **Related to**: [ADR-0004](ADR-0004-disk-encryption-tpm-luks.md) (two-domain TPM2/LUKS),
  [ADR-0002](ADR-0002-secure-boot-zero-touch.md) (Secure Boot — PCR 7)

## Context

ADR-0004 seals both LUKS volumes to the TPM against the **current** PCR 7 value
(`systemd-cryptenroll --tpm2-pcrs=7`), with a recovery key per volume. PCR 7
measures the Secure Boot *policy* (PK/KEK/db + the certificate that authenticated
each image), **not** the kernel hash, so it is **stable across `bootc upgrade`**
when kernels are signed by the same key under the same shim+CA — routine updates
are zero-touch, as intended.

A gap surfaced while writing the disaster-recovery playbook. PCR 7 **necessarily
changes on any Secure Boot *policy* change**: re-signing the shim (new embedded
CA), a **CA rotation after compromise**, a Microsoft SBAT/dbx wave that forces a
new shim, or db/KEK edits. When PCR 7 changes, the TPM refuses to unseal **both**
volumes, and each falls back to its LUKS recovery key. Two problems follow:

1. **The system recovery key is not actually escrowed.** ADR-0004 intended
   "operator escrow" for the system volume, but `ota/neural-ice-autoinstall.sh`
   only **prints** it to the install console (`SYS_RECOVERY`) — it is never
   written, backed up, or transmitted. If it was not transcribed by hand at
   install, a PCR 7 change leaves the root volume openable only by reinstall.
2. **A CA/shim rotation is exactly when you least want per-unit manual toil** —
   "roll the fleet onto the new shim" would turn a security incident into
   fleet-wide recovery-key entry.

There is no escape via "a more stable PCR": any PCR that meaningfully measures the
trust anchor must change when the anchor rotates (one that did not would be blind
to anchor substitution). **The durable anchor cannot be a PCR *value* — it must be
a key.**

## Decision

Move the TPM unlock trust from *a fixed PCR value* to *a signed policy*, in two
stages, keeping the recovery key as the ultimate fallback throughout.

### Stage 1 (interim) — make the recovery reliable

Implement the escrow ADR-0004 already intended: at install, encrypt `SYS_RECOVERY`
(`age`, to a Neural ICE escrow public key) and persist it keyed by machine-id,
instead of only printing it. Provide a re-seal procedure/service that, on a Secure
Boot policy change, uses the escrowed key to unlock and re-run `systemd-cryptenroll
--tpm2-pcrs=7` for the new value. Keeps PCR 7 sealing (no new *boot-trust* key) and
removes the reinstall/lockout risk. Shippable independently of Stage 2.

### Stage 2 (target) — signed PCR policy via UKI + PCR 11

Migrate to a **TPM2 authorized policy** (`systemd-cryptenroll --tpm2-public-key`,
`TPM2_PolicyAuthorize`): the unit is enrolled against a **public key** and unlocks
for **any PCR state signed by the matching private key**. Because PCR 7 is
firmware-dependent and not reliably predictable, the signable measurement is
**PCR 11**, produced deterministically by `systemd-stub` from a **Unified Kernel
Image (UKI)**. The build computes and signs the expected PCR 11 per release
(`systemd-measure sign`); the signature ships with the image; the TPM then unlocks
across shim/CA rotations **with no recovery-key prompt**.

**The PCR-policy signing key** lives on the **same YubiKey 5 FIPS**, in a **new PIV
slot (9d, Key Management — no `CKA_ALWAYS_AUTHENTICATE`, so the build can automate
signing)**, RSA-2048, **distinct** from EV (9a, Microsoft identity) and leaf (9c,
EFI). Rationale: the TPM verifies a **raw keypair** it was enrolled with — it has
no notion of X.509 / SSL.com / Microsoft — so the anchor must be a dedicated key,
not the EV or leaf cert; but it needs **no new hardware**.

The recovery key stays enrolled as the last-resort fallback in both stages.

## Threat model (to be accepted by the decider)

- The **escrow key** (Stage 1) can unlock any fleet root volume → a sensitive
  asset, protected like the leaf (offline/hardware, access-controlled, audited).
- The **PCR-policy key** (Stage 2) can authorize a boot state to unlock the disk.
  It gates **confidentiality** (disk unlock), **not integrity** (Secure Boot) — it
  is *not* in the code-execution trust chain and cannot mint bootable code. Treated
  as a signing key of the leaf's class (FIPS token, audited use).
- Neither key is the CA; neither can produce a binary that boots. Losing either is
  a confidentiality/availability event, never a Secure Boot bypass.

## Consequences

- **+** Stage 2 gives zero-touch LUKS unlock across shim/CA rotations; recovery
  keys become a true last resort, not a routine step.
- **+** Same FIPS token → one physical root of key custody; no new hardware.
- **−** One more signing key in the trust base (counter to "minimize long-lived
  secrets") — accepted deliberately as the price of a durable anchor: you seal
  either to a *value* (which moves) or to a *key* (which you must protect).
- **−** Stage 2 requires **UKI adoption** (the signed boot artifact shifts from
  shim→grub→vmlinuz to a signed UKI) plus enrollment/pipeline rework; it interacts
  with the shim-review chain and must be validated on real GB10 hardware.
- Stage 1 closes the immediate gap and can ship first.

## Options not retained

- **Stay on current-PCR sealing as the end state** — simplest, no extra key, but a
  fleet-wide recovery-key window on every Secure Boot policy change; unacceptable
  at incident time for a sovereign appliance.
- **Sign PCR 7 directly** — firmware/hardware-dependent, not reliably predictable
  at build time; brittle. PCR 11 via UKI is the deterministic, signable measure.
- **`systemd-pcrlock`** — on-device policy management; heavier and less mature on
  the el10 base today. Revisit.
