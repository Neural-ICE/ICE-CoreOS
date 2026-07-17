# Secure Boot — disaster recovery

Companion to [key-ceremony.md](key-ceremony.md) and
[runbook-shim-signing.md](runbook-shim-signing.md). This file answers one
question: **for every asset in the signing chain, what breaks if it is lost or
compromised, and how do we recover?**

The guiding principle: **only one asset is irreplaceable — the CA private key.**
Everything else can be re-issued or rebuilt. The whole backup strategy exists to
protect that one key, and to make every other recovery a routine operation.

## Asset map

| Asset | Where it lives | Replaceable? | Blast radius if lost |
|---|---|---|---|
| **Neural ICE UEFI CA (private key)** | offline, passphrase-encrypted backups only | ❌ **no** | catastrophic — new CA ⇒ new shim ⇒ full shim-review (~2–3 months) |
| **Leaf signing key** | YubiKey PIV, non-exportable | ✅ yes | none to deployed units — CA issues a new leaf; already-signed binaries keep booting |
| **EV code-signing key** | YubiKey PIV, non-exportable | ✅ yes | none — CA re-issues onto a new token; existing MS submissions unaffected |
| **Kernel module signing key** | ephemeral, per build | ✅ N/A | none — regenerated every build |
| **Signed shim / GRUB / kernel** | build artifacts + registry | ✅ yes | none — reproducible from source |
| **PGP security-contact keys** | on machines + keyserver | ✅ yes | contact re-verification with the shim-review board |

## What to back up (and where)

Because confidentiality is **cryptographic** (the CA key backup is an
`age`-encrypted blob on a PIN-protected hardware-encrypted drive), the goal of
physical placement is **availability and anti-tamper**, not secrecy. The rule is
**separation**, so that no single event (theft, fire, drive failure) can either
compromise or destroy the CA:

1. **CA key backup, copy 1** — encrypted media, primary location.
2. **CA key backup, copy 2** — encrypted media, a **different physical location**
   (so one fire/flood/theft cannot take both).
3. **Passphrase** — never stored with either media copy; memorized, plus a sealed
   paper copy in a **third** location. This is the true secret.
4. **Ceremony record** — date, YubiKey serial, CA certificate SHA-256
   fingerprint. Lets you later prove a backup medium has not been substituted.
5. **PIV PIN/PUK** — sealed paper, at home. Lower stakes (loss is recoverable).
6. **A spare YubiKey 5 FIPS**, blank, kept ready — turns a token failure into a
   30-minute recovery instead of a multi-day wait for hardware.

Later upgrade path: move copy 2 and the passphrase envelope to a **bank safe
deposit box** — nothing to re-generate, just relocate.

## Recovery playbooks

### YubiKey lost / failed / destroyed

The leaf and EV keys are non-exportable and die with the token — but nothing
downstream breaks:

1. Take the spare YubiKey; initialize its PIV applet (new PIN/PUK/mgmt key).
2. **Leaf:** generate a new leaf key on-device, produce a CSR, have the offline
   CA sign it (see the offline-CA session below), import the new leaf cert.
   **Deployed units are unaffected** — the shim trusts the *CA*, not the leaf, so
   binaries signed by the old leaf keep booting and PCR 7 does not change.
3. **EV:** request re-issuance from the CA (SSL.com) onto the new token via a new
   PIV attestation. Existing Microsoft submissions are unaffected.

### Build host lost / failed

Nothing on the build host is irreplaceable:

1. New aarch64 host; install the toolchain (podman, the el10 build container,
   the signing tools).
2. Restore or rebuild the staged GB10 artifacts; re-register the CI runner.
3. Plug in the YubiKey (apply the host's smart-card access fix if needed — see
   the runbook), restore the operator SSH key from backup.
4. First kernel build is re-signed by the existing leaf — no crypto impact.

### Offline-CA session (needed to sign a new leaf)

This is a short, air-gapped operation — **not** a full ceremony (no CA
generation):

1. Boot the air-gapped live environment; take the CA key backup + passphrase.
2. Decrypt the CA key **into RAM only** (`age -d`), sign the leaf CSR, verify.
3. **Shred** the decrypted key; power off (RAM is cleared). The CA key never
   touches persistent storage in the clear.

### CA key compromised (not merely lost)

The only scenario that reaches deployed units. Response:
1. Issue a new CA (full ceremony) and a new leaf.
2. Build a new shim embedding the new CA, add the old signed binaries' hashes to
   `vendor_dbx`, and re-submit to shim-review + Microsoft.
3. Roll the fleet onto the new shim. This is the worst case, and it is precisely
   why the CA key is generated offline and never exists unencrypted at rest.

## Pre-flight checklist (verify the backups actually work)

Do this at the ceremony and re-verify periodically — an untested backup is not a
backup:

- [ ] Both CA-key media restore and decrypt cleanly (`age -d` succeeds on each).
- [ ] The CA certificate fingerprint on each medium matches the ceremony record.
- [ ] The spare YubiKey is present and initializes.
- [ ] The passphrase copy is legible and in its separate location.
- [ ] The kmod/kernel spec sources needed to rebuild are backed up off the build
      host (a single-host-only source file is a hidden single point of failure).
