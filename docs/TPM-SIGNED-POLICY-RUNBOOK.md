# TPM signed policy — replacing the literal PCR 7 seal

> **Status**: mechanism PROVEN on GB10 hardware 2026-08-19 (§9). What remains is
> proving it at boot on an installed machine, and wiring it into the installer.
>
> Previously: established by reading
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

**Pinned by measurement, 2026-08-19** — `systemd-cryptsetup` reads:

```
/run/systemd/tpm2-pcr-signature.json
```

Established by watching it fail: with the file elsewhere and passed as a
`tpm2-signature=` crypttab option, the debug log says

```
Failed to find TPM PCR signature file 'tpm2-pcr-signature.json': No such file or directory
```

⚠️ The crypttab option did **not** override the search. Place the file at the
path above; do not rely on passing it by option.

## 5bis · What is signed — settled, after one wrong turn

**The signed value IS the plain `PolicyPCR` digest**, computed from a zero
starting digest over the public-key PCRs. Confirmed twice over, 2026-08-19:

```
this tool, policy-digest --value 6039b234…  f064008d40a05956e631f57623a476b6be7a52ff9afe647cc5fc11d790f2a6f4
systemd's own approved_policy               f064008d40a05956e631f57623a476b6be7a52ff9afe647cc5fc11d790f2a6f4
```

and by reading `tpm2_calculate_policy_pcr()` in systemd v257, which computes

```
hash   = H(concatenated PCR values)
digest = H(previous ‖ TPM2_CC_PolicyPCR ‖ TPML_PCR_SELECTION ‖ hash)
```

— the same construction, and `tpm2_build_sealing_policy()` confirms the rest:

```
signature_hash = sha256(approved_policy)        → so `openssl dgst -sha256 -sign`
.sigAlg = TPM2_ALG_RSASSA                       → PKCS#1 v1.5, NOT PSS
find_signature(json, pcr_selection, fp, approved_policy)
                                                → the JSON entry is matched on all three
```

⚠️ **An earlier revision of this section claimed the opposite.** It was written
from a failing test before the cause was known, and it was wrong. Recorded here
rather than quietly deleted: the failure was real, the explanation was not.

## 🔴 5ter · Two flags decide whether this works at all

**The working combination, proven end to end 2026-08-19 on GB10 hardware:**

```bash
systemd-cryptenroll "$DEV" \
  --tpm2-device=auto \
  --tpm2-pcrs=                     # EMPTY — and this is not optional
  --tpm2-public-key=owner.pub \
  --tpm2-public-key-pcrs=7
                                   # and NO --tpm2-signature here
install -m 0644 sig.json /run/systemd/tpm2-pcr-signature.json
```

Neither flag is obvious, and each fails in a different, silent way.

**`--tpm2-pcrs=` must be EMPTY.** Its default is `7`, so an enrolment that only
sets `--tpm2-public-key-pcrs=7` binds the keyslot to BOTH:

```
PolicyAuthorize(pubkey)     ← the signed policy we want
PolicyPCR(7) literal        ← added silently by the default
```

The literal half fails the moment PCR 7 moves, whatever the signature authorises
(`Policy hash mismatch` in the log). **The default silently reintroduces the exact
fragility this document exists to remove**, and works perfectly until the day the
state changes — which is the worst possible failure schedule.

**`--tpm2-signature` must NOT be passed at enrolment.** It makes `cryptenroll`
verify by unsealing immediately, and once `--tpm2-pcrs` is empty that self-check
reads the PCRs with an unset hash bank:

```
Reading PCR selection: [n/a(7)]
Failed to read TPM2 PCRs: hash algorithm not supported or not appropriate
Failed to unseal secret using TPM2: State not recoverable
```

⚠️ The enrolment itself is sound; only its optional verification is not. The error
names unsealing, so it reads as "the policy is broken" when nothing is. Emptying
the literal mask clears the bank the *signed* branch also needed — the two are not
independent, which no flag description suggests.

The signature is supplied at **unlock**, from the path in §5.

## 🔴 5quater · What the proof does NOT cover — the systemd version

**Everything proven in §9 ran on `spark-63`, which is Ubuntu 24.04 (DGX OS) and
whose cryptsetup token plugin announces itself as:**

```
Token handler systemd-tpm2-1.0 systemd-v255 (255.4-1ubuntu8.16)
```

**The appliance ships systemd 257.** The source read in §5bis is v257; the
behaviour measured in §5ter and §9 is v255. They agreed everywhere they were both
observable, but that is not the same as having been checked on 257.

⚠️ **Re-run `ota/test-tpm-signed-policy.sh` on the appliance image before treating
any of this as established for what we ship.** The flags in §5ter are the most
likely thing to move between versions: `--tpm2-pcrs=` emptying the hash bank is a
behaviour, not a documented contract.

**Known difference already observed on 255**: with TWO tpm2 tokens enrolled (the
transition slot of §8), `systemd-cryptsetup` did not open the volume — it reported
both tokens "unusable for segment 0 with desired keyslot priority 2", then tried
token 0 alone. Enrolment is fine (3 keyslots, 2 tokens in the header); it is the
unlock path that did not iterate. **Whether 257 iterates is untested**, and the
transition slot is worth little if it does not.

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

## 8bis · Reinstall before the owner ceremony, without TPM Clear

A signed physical reinstall may preserve TPM state only in the narrow state
where the previous installer activated PCR policy generation N and the mandatory
first-boot owner ceremony never began:

- `ownerAuthSet` is still `0`;
- none of the Neural ICE NV indices `0x01500001` through `0x01500006` exists;
- `0x01500007` is the sole Neural ICE state index and has the exact PCR policy
  counter shape;
- the new signed Install medium requests a generation strictly greater than N,
  with a gap no larger than 4096.

The initramfs proves this state before admitting the Install boot. The installer
then performs the existing read-only `pcr-policy-check` before the target disk is
wiped and advances the counter only after both new LUKS tokens have enrolled and
read back successfully. The existing device-root is attested and reused. The
existing SRK public identity is reused, persisted as ceremony intent, and bound
into both new LUKS tokens; this retry path does not claim to validate a new SRK
template.

An equal or lower generation is replay and is refused. So is a gap above 4096,
an owner authorization already set, any state at `0x01500001` through
`0x01500006`, a malformed or unreadable PCR counter, a Live/recovery selector,
or an Install-looking command line without the signed installer initramfs
marker. A ceremony that began or completed still requires the existing signed
physical recovery path, including TPM Clear with physical presence.

## 9 · Evidence

All of the below on `spark-63`, real GB10 TPM, via `ota/test-tpm-signed-policy.sh`.

| date | step | result |
| --- | --- | --- |
| 2026-08-19 | §1 chain established by reading | GRUB, no UKI, systemd 257 |
| 2026-08-19 | event-log replay reproduces the live PCR 7 | ✅ `d76b3540…` == `d76b3540…` |
| 2026-08-19 | a future PCR 7 is predicted exactly | ✅ predicted value reached to the byte after `tpm2_pcrextend` |
| 2026-08-19 | enrolment against a public key | ✅ header carries `tpm2-pubkey`, `tpm2-pubkey-pcrs: 7` |
| 2026-08-19 | the enrolled state unlocks with no passphrase | ✅ |
| 2026-08-19 | signature JSON matches `systemd-measure` | ✅ byte for byte |
| 2026-08-19 | signature read path | ✅ pinned: `/run/systemd/tpm2-pcr-signature.json` |
| 2026-08-19 | the signed digest is the plain PolicyPCR value | ✅ `f064008d…` == systemd's own `approved_policy`, and confirmed by reading `tpm2_calculate_policy_pcr()` |
| 2026-08-19 | an unauthorised state is refused | ✅ |
| 2026-08-19 | the recovery passphrase opens a volume whose policy fails | ✅ |
| 2026-08-19 | the flag combination | ✅ settled — §5ter, **on systemd 255** (§5quater) |
| 2026-08-19 | 🎯 **a pre-authorised future state unlocks, no re-enrolment** | ✅ **the mechanism holds** |
| 2026-08-19 | transition slot enrolled beside the live one | ✅ 3 keyslots, 2 tokens |
| 2026-08-19 | unlocking with two policy tokens | ❌ refused on systemd 255 — §5quater |
| | the whole harness re-run on systemd 257 | **not done — §5quater** |
| | §7 recovery proven end to end AT BOOT, on an installed machine | not done — the test volume cannot show it |
| | §6 clause executed | not done |
| | third LUKS slot | not done |

### What to try next, in order

1. `--tpm2-pcrs=` empty **plus** whatever `systemd-cryptenroll` needs to skip its
   post-enrolment unseal self-check — that check runs in the current state and may
   simply need the signature file present at the default path *at enrolment time*
   as well as at unlock.
2. Failing that, enrol with `--tpm2-pcrs=` empty on a volume whose signature file
   already covers the current state, and read the self-check's own debug output
   rather than its summary line.
3. Only then re-run `ota/test-tpm-signed-policy.sh` end to end.

## Related

- `docs/ADR-0004-disk-encryption-tpm-luks.md` — to amend with the retained policy
  and its verification clause
- `docs/ADR-0002-secure-boot-zero-touch.md` — the Microsoft shim submission plan,
  which the retained option must not disturb
