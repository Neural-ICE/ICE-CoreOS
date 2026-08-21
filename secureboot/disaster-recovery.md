# Secure Boot — disaster recovery

Companion to [key-ceremony.md](key-ceremony.md),
[runbook-shim-signing.md](runbook-shim-signing.md) and
[signing-pipeline.md](signing-pipeline.md). This file answers one question: **for
every asset in the signing chain, what breaks if it is lost or compromised, and
how do we recover?**

**Loss and compromise are different threats.** Losing an asset is an availability
problem; *compromise* — an attacker holds it — can reach deployed units and needs
**revocation**, not just re-issuance. Each playbook below branches the two.

The guiding principle: **only one asset is irreplaceable — the CA private key.**
Everything else can be re-issued or rebuilt. The backup strategy exists to protect
that one key and to make every other *loss* a routine operation.

## Asset map

| Asset | Where it lives | Replaceable on loss? | Blast radius |
|---|---|---|---|
| **Neural ICE UEFI CA (private key)** | offline, passphrase-encrypted backups only | ❌ **no** | catastrophic — new CA ⇒ new shim ⇒ full shim-review (~2–3 months) |
| **Leaf signing key** | YubiKey PIV 9c, non-exportable | ✅ yes | *loss:* none (CA issues a new leaf; already-signed binaries keep booting). *compromise:* can sign bootable binaries under the still-trusted CA — see the lost/stolen branch |
| **EV code-signing key** | YubiKey PIV 9a, non-exportable | ✅ yes | none — CA re-issues onto a new token; existing MS submissions unaffected |
| **Kernel module signing key** | ephemeral, generated & discarded per build | ✅ N/A | none — never persisted (built in-tree & destroyed with the build, see [signing-pipeline.md](signing-pipeline.md)) |
| **Signed shim / GRUB / kernel** | build artifacts + registry | ✅ yes | none — reproducible from source |
| **PGP security-contact keys** | on machines + keyserver | ✅ yes | contact re-verification with the shim-review board |

> The module-signing-key row is harmless **because** the key is now genuinely
> ephemeral (Option D — built inside the kernel `rpmbuild`, signed, and discarded;
> no `signing_key.pem` persists). If a build ever leaves a long-lived module key on
> disk, this row no longer holds and that key must be treated like the leaf.

## What to back up (and where)

Confidentiality of the CA backup is **cryptographic**: an `age`-encrypted blob
whose only secret is the **passphrase**. Hardware-encrypted media (the IronKey)
adds a second layer on copy 1, but copy 2 may be ordinary media — so **the
passphrase is what actually protects the key**, and physical placement is for
**availability and anti-tamper**, not secrecy. The rule is **separation**: no
single event may yield both an encrypted medium *and* the passphrase.

1. **CA key backup, copy 1** — `age` blob on the hardware-encrypted IronKey,
   primary location.
2. **CA key backup, copy 2** — `age` blob on separate media, a **different
   physical location** (so one fire/flood/theft cannot take both).
3. **Passphrase** — the true secret. **Never** stored with either medium;
   memorized, plus a sealed paper copy in a **third** location.
4. **Ceremony record** — date, YubiKey serial, CA certificate SHA-256
   fingerprint. Lets you later prove a backup medium has not been substituted.
5. **PIV PIN/PUK** — sealed paper, at home. Lower stakes (loss is recoverable).
6. **A spare YubiKey 5 FIPS**, blank, kept ready — turns a token failure into a
   30-minute recovery instead of a multi-day wait for hardware.

> **Upgrade path — do NOT co-locate secrets.** Move **copy 2** to a bank safe
> deposit box for anti-tamper, but keep the **passphrase in its own separate
> location**. Never place a medium and the passphrase in the same box: that single
> access or theft would compromise the irreplaceable CA key, not merely protect
> its availability.

## Recovery playbooks

### YubiKey — failed/destroyed vs lost/stolen

**Confirmed failed or destroyed** (you hold the dead token, or it is verifiably
gone): the leaf and EV keys die with it and **nothing downstream breaks** — the
shim trusts the *CA*, not the leaf, so old-leaf binaries keep booting and PCR 7
does not change.

1. Take the spare YubiKey; initialize its PIV applet (new PIN/PUK/mgmt key).
2. **Leaf:** generate a new leaf key on-device, produce a CSR, have the offline CA
   sign it (session below), import the new leaf cert.
3. **EV:** request re-issuance (SSL.com) onto the new token via a new PIV
   attestation. Existing Microsoft submissions are unaffected.

**Lost or stolen** (token unaccounted for, possibly in someone else's hands):
treat the **leaf as potentially compromised**. PIN + touch raise the bar, but a
token plus a known PIN can sign bootable binaries that chain to the still-trusted
CA — and there is **no boot-time CRL** to revoke a single leaf. Response:

1. **Rotate the leaf immediately** (steps above); freeze releases under the old
   leaf so all new releases use the new one.
2. **Per-binary `dbx` is only a stopgap.** Deny-listing the hashes you have already
   found (SBAT-generation bump + submitting them to the UEFI `dbx`, the
   CA-compromise mechanism below) stops *those* binaries — but a usable token can
   mint **fresh** binaries with new hashes that the old shim still accepts, because
   they chain to the unchanged CA and there is **no boot-time leaf revocation**.
3. **A usable token is therefore a CA/shim-rotation event.** Unless you are certain
   the PIN was never exposed (so the token cannot actually be driven), go to the
   **CA-compromise** playbook below: rotating the CA + new shim + revoking the old
   shim is the *only* way to un-trust everything the old leaf can still produce.
   Per-binary `dbx` merely buys time until that lands.
4. Rotate any operator/CI credentials the holder may also have had.

> ⚠️ **Owner risk call:** how hard to escalate a *lost* (vs proven stolen-with-PIN)
> token is a judgement. The default above assumes the PIN may be obtainable;
> downgrade only with justification.

### Build/signing host — failed vs compromised

**Failed / lost hardware** — nothing on the host is irreplaceable:

1. New aarch64 host; install the toolchain (podman, the el10 build container, the
   signing tools).
2. Restore or rebuild the staged GB10 artifacts; re-register the CI runner.
3. Plug in the YubiKey (apply the host's smart-card access fix if needed — see the
   runbook), restore the operator SSH key from backup.
4. First kernel build is re-signed by the existing leaf — no crypto impact.

**Compromised host** (code execution while the YubiKey was attached or the
PIN/touch was cached, or CI/operator secrets may have leaked): replacement alone
is unsafe — the attacker may have **signed malicious artifacts** and
**exfiltrated credentials**.

1. **Assume the leaf was exercised:** rotate it (YubiKey branch) and treat any
   artifact signed during the exposure window as suspect.
2. **Audit & revoke:** rebuild every shippable binary from clean source and
   compare hashes; **`dbx` + SBAT-bump** anything that cannot be accounted for.
3. **Rotate all host/CI secrets:** operator SSH keys, CI runner tokens, registry
   push credentials.
4. Rebuild the host from known-good media, then resume on the new leaf.

### Offline-CA session (needed to sign a new leaf)

Short, air-gapped operation — **not** a full ceremony (no CA generation):

1. Boot the air-gapped live environment; take a CA key backup + passphrase.
2. Decrypt the CA key **into RAM only** (`age -d`), sign the leaf CSR, verify.
3. **Shred** the decrypted key; power off (RAM is cleared). The CA key never
   touches persistent storage in the clear.

### CA key compromised (the only scenario that reaches deployed units)

`vendor_dbx`-ing the known old binaries is **not sufficient**: an attacker with the
CA can mint *new* GRUB/kernel binaries whose hashes you never listed, and the **old
Microsoft-signed shim still embeds and trusts the compromised CA**. Full response:

1. Issue a new CA (full ceremony) and a new leaf; build a new shim embedding the
   new CA.
2. **Revoke the old trust anchor, not just old binaries:**
   - bump the shim **SBAT** generation so the old shim is refused once the new
     `SBAT` policy propagates;
   - submit the **old shim's hash to Microsoft for the UEFI `dbx`** (firmware
     revocation) — until that lands, the old shim + compromised CA remain a bypass
     on any unit that has not updated `dbx`;
   - `vendor_dbx` the previously-signed GRUB/kernel as a stopgap.
3. **TPM PCR 7 — expect a recovery/re-seal step (see [ADR-0011](../docs/ADR-0011-tpm-unlock-rotation-robustness.md)):**
   the new shim/CA changes PCR 7, so the TPM-sealed LUKS auto-unlock breaks on both
   volumes. With today's current-PCR sealing (`--tpm2-pcrs=7`, ADR-0004) a unit can
   only re-seal to the new value *after* it has booted the new shim — so each first
   falls back to its **LUKS recovery key**, then re-seals. ⚠️ For the **system**
   volume that is the `SYS_RECOVERY` escrow, which is **not yet implemented**: if it
   was not captured at install, the root volume is **reprovisioned from GHCR**
   (stateless OS; client `data` recovered via its own operator key). ADR-0011
   (UKI + PCR 11 signed policy) removes this window — the TPM accepts any boot state
   you have signed, so a rotation needs no recovery key.
4. Roll the fleet onto the new shim + updated `dbx`/`SBAT`. This is the worst case,
   and it is exactly why the CA key is generated offline and never exists
   unencrypted at rest.

## Pre-flight checklist (verify the backups actually work)

Do this at the ceremony and re-verify periodically — an untested backup is not a
backup:

- [ ] Both CA-key media restore and decrypt cleanly (`age -d` succeeds on each).
- [ ] **The decrypted private key really is the CA key** — not just that *a* key
      decrypts. Derive its public key and match the CA certificate's: compare
      `openssl pkey -in ca.key -pubout` against `openssl x509 -in ca.crt -pubkey -noout`
      (without `-noout`, `x509` also prints the cert and the compare falsely fails),
      or sign a throwaway CSR and verify it against the CA cert. A substituted
      medium can carry the correct public cert beside a wrong (but decryptable)
      key and pass a fingerprint-only check.
- [ ] The CA certificate fingerprint on each medium matches the ceremony record.
- [ ] The spare YubiKey is present and initializes.
- [ ] The passphrase copy is legible and in its **separate** location (never with
      a medium).
- [ ] The kmod/kernel spec sources needed to rebuild are backed up off the build
      host (a single-host-only source file is a hidden single point of failure).
