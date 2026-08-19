# TPM signed policy — replacing the literal PCR 7 seal

> **Status**: target architecture. The mechanism below is established by reading
> the shipped image (see §1); the tooling is under construction. Nothing here is
> deployed yet.
>
> **Owner-reserved**: signing a policy. No automation holds the private key.

## Why this exists

Today both LUKS volumes are sealed to the **literal value** of PCR 7, the digest
of the UEFI Secure Boot state (PK, KEK, `db`, `dbx`, and the certificates that
validated what was loaded).

```
seal today :  "release the key only if PCR 7 == A"
```

The TPM compares and refuses. It has no notion of a *legitimate* change. So every
one of these bricks automatic unlock, fleet-wide, at the same instant:

| event | frequency |
| --- | --- |
| enrolling or removing a Secure Boot key (PK/KEK/db) | at the lab → prod anchor switch |
| **a `dbx` revocation update** | **published by Microsoft periodically** |
| a firmware capsule touching the Secure Boot variables | whenever a firmware path exists |
| switching the signing certificate (lab key → Microsoft-signed shim) | once, for MVP 1.0 |

🔴 The `dbx` row is the one that does not wait for our schedule. Under the literal
seal, applying one revocation locks every appliance that applies it.

This is also why there is **no firmware update path at all** today: opening one
without this policy guarantees the first capsule stops the fleet.

## 1 · The chain, established by reading

Measured on `neural-ice-coreos@sha256:b6b5a9da…`, 2026-08-19:

```
UKI                 none — no .efi under /usr/lib/modules or /boot
kernel + initramfs  SEPARATE: /usr/lib/modules/6.12.0-249.gb10…/{vmlinuz,initramfs.img}
bootloader          /usr/lib/bootupd/updates/EFI/{BOOT,centos}   → GRUB
systemd             257 — --tpm2-public-key, --tpm2-public-key-pcrs,
                          --tpm2-signature, --tpm2-pcrlock all present
                          /usr/lib/systemd/systemd-pcrlock present
```

**It is a GRUB chain, not a UKI.** This decides everything below, which is why the
mission makes it objective 1: a UKI would have measured PCR 11 through
`systemd-stub` and the whole design would differ.

⚠️ **Consequence to know before writing tooling**: `systemd-measure sign`
advertises itself as *"Pre-calculate and sign expected PCR values **for a unified
kernel image (UKI)**"*. It computes PCR 11. **It will not compute PCR 7 for us** —
the prediction tool is ours to write.

## 2 · The mechanism

The TPM primitive is `TPM2_PolicyAuthorize`. Instead of sealing to a value, the
sealed object carries **the name of a public key**:

```
seal target :  "release the key if the presented state is AUTHORISED
                by a signature from public key K"
```

At unlock the machine presents its PCR values **and a signature** attesting that
this state is authorised. The TPM verifies the signature against K, then checks
the PCRs match what was signed.

**What that buys**: whoever holds K's private half can authorise **new** states —
without re-sealing, without touching the machine's TPM, without being on site.

## 3 · Signing a future state

```
D-7   PCR 7 is A (lab key enrolled)
      the value it WILL take under the new anchor is B — deterministic, predictable
      sign an authorisation covering A *and* B with K
      distribute that signature

D-0   switch the anchor. PCR 7 becomes B.
      the machine presents B + the signature → the TPM opens
```

The private key never moves. What travels is a signature.

⭐ **The signature needs neither confidentiality nor a separate integrity
channel.** The TPM validates it against K. A forged one simply fails to verify and
the machine falls back to its recovery key. The worst an attacker achieves by
tampering with it is **denial of service, never unlock** — so it may be
distributed over any path.

⚠️ **Keep the old state authorised.** One signature file may cover several states.
Retire A only once B is proven across the whole fleet: A is the rollback path.

## 4 · 🔴 The ordering rule — never one update

```
❌ ONE update that switches the anchor AND ships the signature
   → the machine reboots into the new state
   → it has not yet read the new signature
   → LOCKED OUT

✅ TWO updates
   1st  ships the signature covering A and B — nothing else changes, still in A
        VERIFY it is in place (§6) before going further
   2nd  switches the anchor → PCR 7 becomes B → the authorisation is already there
```

Same discipline as OTA anti-rollback: prepare, verify, then act.

This does not remove the need for recovery: a machine that misses the first
update and takes the second is locked out. It reduces the population at risk from
"all of them" to "those that skipped a step".

## 5 · Where the signature lives

It must be readable **before** the volume opens, so it cannot live on the
encrypted volume. Three unencrypted homes exist: the initramfs (inside the OS
image), `/boot` (1 GiB), the ESP.

**Chosen: inside the OS image.** The image already arrives through bootc, signed
and verified by `image-ci`, so the signature rides a path that is already trusted
and needs no new one. A newly authorised state is then a new image, i.e. an OTA —
the cadence we already operate.

`/boot` and the ESP remain the out-of-band escape hatch: since the signature is
self-protecting (§3), dropping one there by hand during recovery is safe.

⚠️ **To pin at implementation time**: the exact path `systemd-cryptsetup` reads.
The shipped binary is stripped and does not reveal it; do not guess it — read it
from the systemd 257 source or observe it on a live unlock, and record the answer
here.

## 6 · Verification clause (FAB-0046)

A control that proves the policy **in force** is the expected one. Not that the
mechanism exists — that the machine is running it.

```bash
# The enrolled keyslot must carry a tpm2 token bound to a PUBLIC KEY,
# not to literal PCR values.
cryptsetup luksDump /dev/nvme0n1p3 | sed -n '/Tokens:/,$p'
systemd-cryptenroll /dev/nvme0n1p3 --tpm2-device=auto 2>&1 | head

# Expected: a tpm2 token whose policy references tpm2-pubkey / tpm2-pubkey-pcrs.
# A token showing only tpm2-pcrs is the OLD literal seal — the machine is NOT
# on the signed policy, whatever the image claims.
```

🔴 The failure this catches: an appliance that carries the new image but was never
re-enrolled. It boots, it works, and it is still on the literal seal — invisible
until the day the anchor moves.

## 7 · Recovery — proven BEFORE any deployment

> The policy is **identical on every appliance**. A wrong policy does not break a
> machine, it breaks **the fleet**, on machines nobody can reach.

Recovery must be demonstrated on a machine whose policy fails, and the
demonstration recorded here, **before** any wave is deployed.

```
1. take a machine already installed and unlocking automatically
2. break the policy deliberately — enrol a Secure Boot key so PCR 7 moves
   without a signature covering the new state
3. reboot. Automatic unlock MUST fail.  ← this is the point: it must fail
4. unlock with the recovery key, on the console
5. re-enrol against the correct policy
6. reboot. Automatic unlock works again.
```

**Record the output of every step in §9.** A recovery that was "obviously going to
work" is not proven.

Both recovery keys already exist and are distinct — the system volume's is a
Neural ICE escrow, the data volume's is handed to the owner (ADR-0004). Neither is
replaced by this change: the signed policy makes automatic unlock survive a
legitimate change; it does not remove the last resort.

## 8 · Transition LUKS slot

An independent prerequisite (mission-0024, objective 5): a **third** LUKS slot, so
a new policy can be enrolled **while the old one still opens the volume**.

```
slot 0   recovery key                 never touched
slot 1   current policy               keeps working
slot 2   new policy                   enrolled, tested, THEN slot 1 retired
```

Without it, re-enrolment is a cutover with no way back on a machine that may be
unreachable.

## 9 · Evidence

| date | step | command and output |
| --- | --- | --- |
| 2026-08-19 | §1 chain established by reading | GRUB, no UKI, systemd 257 — see §1 |
| | §7 recovery proven | **not done — blocks every deployment** |
| | §6 clause executed | not done |

## Related

- `docs/ADR-0004-disk-encryption-tpm-luks.md` — to amend with the retained policy
  and its verification clause
- `docs/ADR-0002-secure-boot-zero-touch.md` — the Microsoft shim submission plan,
  which the retained option must not disturb
