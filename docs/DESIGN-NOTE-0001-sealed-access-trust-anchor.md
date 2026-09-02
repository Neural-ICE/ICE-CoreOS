# DESIGN-NOTE-0001 — Anchoring the access profile in the boot signature

- **Status**: **Superseded by [ADR-0015](ADR-0015-installer-trust-anchor-uki-verity.md)**
  (2026-08-31), which implements Design A for Finding 1, the release
  authorization for Finding 2, and the enrolled TPM anchor for Finding 3.
  This note is kept as the problem statement and the reasoning; ADR-0015 is the
  decision. **One release-schema field was added** — `access_profile` on the
  release authorization — reversing the "no schema change" position recorded
  below; see ADR-0015's *Consequences* for why an optional field would have been
  worse than a required one.
- **Date**: 2026-08-31
- **Author**: Solution/Security architecture, for Owner decision
- **Related**: [ADR-0002](ADR-0002-secure-boot-zero-touch.md) (Secure Boot
  anchors, already prefers a UKI), [ADR-0005](ADR-0005-release-channels.md)
  (signed trains, variant gate), [ADR-0012](ADR-0012-atomic-ota-state-v1.md)
  (atomic state), [ADR-0013](ADR-0013-device-root-tpm-v1.md) (device root),
  [ADR-0014](ADR-0014-access-policy-lab-vs-customer.md) (the access policy this
  note is about)

## Why this note exists

ADR-0014 moved the remote-access trust anchor off the mutable ESP and into
`/usr/lib/neural-ice/access-policy`, "covered by whatever signs the image."

That sentence is true of a **deployed, OTA-managed appliance**. It is **not**
true of the **removable installation medium**, and the installer is where the
policy is first read. Three findings follow from that gap. They are stated here
rather than fixed, because closing them changes the signed-artifact architecture
and, for the third, the release schema — decisions that belong to the Owner and
to a separate change, not to the implementation-local corrections shipped
alongside this note.

The two P1s that were **not** architectural (first-boot unit ordering, and the
bypassable "keyless" build assertion) are fixed in the same change as this note
and are described in ADR-0014.

## Ground truth: what the boot signature authenticates today

Verified against this tree, not assumed:

| artefact | authenticated by Secure Boot? |
|---|---|
| shim, GRUB, kernel (`image/signed-boot/`, ADR-0002) | **yes** |
| NVIDIA kernel modules (`sign-file`) | **yes** |
| the live medium's `/usr`, including `/usr/lib/neural-ice/access-policy` | **no** |
| `ota/neural-ice-autoinstall.sh` (the gate code itself) | **no** |
| the `containers-storage:localhost/bootc` object staged on the medium | **no** |
| the installer kernel command line (`neuralice.source=`, `neuralice.osimage=`) | **no** |

The repository contains **no** UKI, **no** dm-verity or fs-verity, **no** IMA
appraisal, and **no** signed-OSTree-root verification (searched:
`uki`/`ukify`, `dm-verity`/`veritysetup`, `fs-verity`/`fsverity`,
`ima_appraise`/`ima_policy` — the only hits are the aspirational UKI mentions in
ADR-0002 and the TPM runbook). `neural-ice-secureboot-prod-v1` does not exist
yet either; today's media carry `neural-ice-secureboot-lab-v1`. **No production
chain evidence can be produced until that key ceremony completes**, which makes
it the first item in the sequencing below.

---

## Finding 1 (P0) — the installer root is not authenticated by the boot signature

**Where.** `image/Containerfile.bootc:89` states that the derived marker "lands
in the read-only ostree `/usr` … covered by whatever signs the image", and
`ota/neural-ice-autoinstall.sh:313` reads exactly that file as its authority.

**Why it fails on a medium.** Secure Boot authenticates EFI binaries and the
kernel. It says nothing about the root filesystem those binaries later mount. An
attacker with physical access to a correctly signed installer USB can, offline:

- rewrite `/usr/lib/neural-ice/access-policy` from `customer-locked` to
  `lab-managed`; **and/or**
- rewrite `ota/neural-ice-autoinstall.sh` so the gate is never consulted.

Both survive Secure Boot untouched. This is the same class of defect ADR-0014
set out to close — an attacker-writable input treated as authority — moved one
layer down: from a vfat ESP file to a squashfs/ostree `/usr` on the same
removable device.

**Required property.**

> P1. The access profile the installer acts on must be a **function of data the
> Secure Boot chain authenticates**, and the code that acts on it must be
> covered by the same authentication.

**Resolved by Design A** — `image/lib/installer-trust.sh` (the sealed cmdline
contract, the dm-verity assertion and the composite gate),
`image/build-installer-uki.sh` (the deterministic build), and
`ota/neural-ice-autoinstall.sh` §1a-0, which runs the gate **before** it reads
any policy. Proof: `image/test-installer-trust.sh`.

### Design A (preferred) — signed UKI carrying a dm-verity root hash and the profile

ADR-0002 already prefers a UKI over GRUB for CVE/SBAT reasons; this makes the
UKI load-bearing for access control too.

1. **Installer root becomes a dm-verity image.** CI builds the installer rootfs
   as a read-only verity target and computes its root hash.
2. **The UKI carries the hash and the profile in its signed `.cmdline`.** One
   PE binary — kernel + initramfs + cmdline — signed by the Neural ICE key that
   the MS-signed shim's `vendor_cert` validates:
   `neuralice.rootverity=<root-hash> neuralice.access_profile=customer-locked`.
   Editing either word invalidates the signature; the firmware refuses to boot.
3. **The initramfs (inside the UKI, therefore signed) sets up dm-verity before
   `switch-root`.** Any byte changed anywhere in the installer `/usr` — the
   policy marker, the autoinstall script, the staged container object — fails
   verification and the install never starts.
4. **The `/usr` marker becomes a cross-check, not the authority.** The installer
   reads the profile from the signed cmdline and *additionally* requires the
   file in the now-verity-protected `/usr` to state the same value. Disagreement
   is a refusal. Redundancy is cheap; ambiguity about which one wins is not.

Cost: a UKI build stage in CI, a verity image build, and the production key
ceremony. No new runtime component on the appliance.

### Design B (fallback) — signed root manifest verified from the initramfs

If the UKI cannot land this cycle: cosign-sign a manifest binding the installer
root's content digest (ostree commit or a `/usr` Merkle root) to an
`access_profile`, ship the verifying public key **inside the initramfs**, and
verify before `switch-root`.

**This is strictly weaker and must be labelled as such.** With shim→GRUB, the
initramfs is authenticated only if GRUB itself verifies it; an unverified initrd
means the verifying key is as editable as the thing it verifies, and the whole
construction is circular. Design B is only defensible if GRUB signature
enforcement is proven on the shipped media first. Design A does not have this
problem, because the initramfs is *inside* the signed PE binary.

### Acceptance evidence (what would let this be closed)

Under **real** Secure Boot on GB10, with a production-signed medium:

1. flip one byte in `/usr/lib/neural-ice/access-policy` on the medium → the
   machine must fail before `neural-ice-autoinstall` runs;
2. flip one byte in `ota/neural-ice-autoinstall.sh` → same;
3. flip one byte in the staged `localhost/bootc` object → same;
4. an unmodified medium boots and installs normally.

---

## Finding 2 (P0) — a digest is verified, an authorization is not

**Where.** `ota/neural-ice-autoinstall.sh`: the access-policy gate reads the
**live medium's** profile at line ~313; the registry pull happens at ~607; the
requested-vs-pulled digest comparison at ~618; `bootc install to-filesystem` at
~630.

**What is actually proven.** The digest comparison — checking both `.Digest` and
`.RepoDigests` so it neither breaks nor passes vacuously when the appliance goes
multi-arch — proves *the registry served the digest that was asked for*. Signed
`docker` scopes in `policy.json` prove *image-ci signed it*.

**What is not proven.** Nothing constrains **which** digest may be asked for.
`neuralice.osimage=` is read from the live installer's kernel command line
(line ~200), which is unauthenticated (Finding 1) and editable at the GRUB
prompt. A **customer** medium can therefore be pointed at a perfectly
image-ci-signed **`debug`** digest and will install it: serial root autologin,
sshd enabled, SELinux permissive. The install-time access gate cannot catch this
— it deliberately reads the *medium's* profile, and on the `registry` path the
medium is not the thing being installed. That is exactly why
`access_policy_gate_installer_ssh` refuses a medium-supplied key on the
`registry` path; but refusing the *key* does not refuse the *image*.

Two further ordering facts matter:

- The pull happens **after** `wipefs`/`sfdisk`/`luksFormat`/`mkfs` (lines
  ~503–550). By the time anything about the image is known, the target disk is
  already destroyed — so "refuse" at that point cannot mean "leave the machine
  as it was".
- `--skip-fetch-check` is passed to `bootc install`, so bootc performs no
  independent re-verification of the source.

**Required property.**

> P2. An image digest D may be installed on a medium whose permitted profile is
> P only if a Neural-ICE-signed **release authorization** binds
> `(D, variant, access_profile, signed-boot-trust-policy-id)` and
> `access_profile(D) == P`, checked against the **pulled bytes**, before any
> target mutation.

**Resolved** — `image/lib/release-authorization.sh` and
`ota/neural-ice-autoinstall.sh` §2b, which pulls, authorises and inspects with
the target disk untouched. The binding was widened beyond the four terms above:
it also carries the **platform manifest digest** alongside the index digest, and
the repository, because a check that consulted one digest would let a hostile
mirror answer an index request with a child. Proof:
`image/test-release-authorization.sh`.

Neither interim mitigation was adopted. (a) — refusing `INSTALL_SOURCE=registry`
on customer media — is generalised instead: a customer medium may install
exactly what it is authorised to install, and nothing else.

### Design

1. **Pull before mutate.** Move the pull, signature verification, digest
   comparison and profile inspection ahead of the first destructive command. A
   refusal must then still leave a bootable machine.
2. **Introduce a release authorization object.** A cosign-signed statement over
   `{image digest, variant, access_profile, signed-boot-trust-policy-id}`,
   verified with a key that lives in the **authenticated** installer root.
   *This depends on Finding 1*: without an authenticated root, the verifying key
   is as editable as the policy it protects, and the check is theatre.
3. **Inspect the pulled image, not the request.** Read
   `/usr/lib/neural-ice/access-policy` and `/usr/lib/neural-ice/appliance-variant`
   out of the pulled object and require exact agreement with the authorization
   **and** with the medium's permitted profile. Any mismatch aborts.
4. **Install the already-verified local object** (`containers-storage:<digest>`),
   so nothing is re-resolved between verification and install.

### Interim mitigations available *without* new schema — Owner decision

Neither is implemented here; both are cheap and reversible, and either would
shrink the window while Finding 1 is being built:

- **(a)** refuse `INSTALL_SOURCE=registry` outright when the medium's profile is
  `customer-locked` — customer media then only ever install the image they
  physically carry;
- **(b)** require `neuralice.osimage` to match a digest **baked into the medium**
  rather than accepting one from the command line.

(a) is the smaller change and closes the stated attack; (b) generalises better if
LAN-mirror installs must keep working on customer media. Both remain trivially
defeatable by editing the medium until Finding 1 is fixed — they raise cost, they
do not restore the property.

---

## Finding 3 (P1, deferred — needs a release-schema field)

**Where.** `tools/ni-ota-verify/src/delegated/beta.rs:189` refuses a release
whose `variant` differs from the host's immutable
`/usr/lib/neural-ice/appliance-variant`.

**Why that is not yet an access-profile binding.** ADR-0014's continuity argument
has three premises; the third is *"the variant → policy mapping is a total
function, so equal variants imply an equal access policy."* That premise is a
property of **today's source tree** (`image/lib/access-policy.sh:55`), not of
anything signed. A later, correctly signed, **same-variant** OTA can rewrite that
mapping — or the `access-policy` marker itself — and the host's access posture
changes with no signature ever having stated the old one. The binding is
*variant*, and the thing that must be immutable is *profile*.

**Required property.**

> P3. `access_profile` is enrolled at install time, outside the candidate
> deployment, and a release may only be applied if its signed `access_profile`
> equals the enrolled value. A change is a refusal, never a silent widening.

**Resolved, and it did take the signed-field change this note deferred.** The
P0 OTA reader remains the strict `neural-ice-ota-release-authorization-v1`
contract: its signed document requires immutable `access_profile` and
`access_policy_sha256`, and refuses old/mixed/partial documents. OTA compares
those fields to the enrolled TPM-bound profile and the candidate's immutable
marker; it never mutates or re-enrols the profile.
`ota/neural-ice-access-profile-anchor.sh` enrols into the stateroot under a
device-root signature; `tools/ni-ota-verify/src/access_profile_anchor.rs` reads
it and every delegated path compares against it. Proofs:
`ota/test-neural-ice-access-profile-anchor.sh` and the lab↔customer OTA-refusal
cases in `tools/ni-ota-verify/tests/cli.rs`.

### Design

1. Add required `access_profile` and `access_policy_sha256` to the **signed OTA
   release authorization**. Both are admission evidence, never instructions to
   rewrite the enrolled profile.
2. Enrol the value at install time into `state-v1` (ADR-0012), **outside** the
   candidate deployment so a deployment cannot restate its own authority, and
   TPM-anchor it per ADR-0013 so an offline edit of `/var` does not move it.
3. In `beta.rs` (and every delegated path), compare `release.access_profile`
   against the enrolled value **in addition to** the existing `variant` check.
4. On mismatch, refuse with **"reinstall required"**. Deliberately not
   "re-enrol": a profile change is a change of what the appliance *is*, and the
   only honest path back is signed physical media (ADR-0014).

Until this lands, ADR-0014's continuity claim rests on a source-tree invariant.
That invariant is worth keeping true — but it is not a control, and this note
exists so nobody later mistakes it for one.

**It has landed.** The invariant is still asserted (the image build breaks if the
mapping drifts, and `release-authorization.sh` restates it on the pulled bytes),
and the installer now uses the separate, strict
`neural-ice-installer-release-authorization-v2` 14-field contract. Its signed
UKI pins that exact schema and key; v1 and mixed-version pairs refuse. Fabric's
signed `issuance_seq` is copied unchanged after install commit and consumed only
by the installed firstboot ceremony through the TPM absolute high-water.
but it is no longer what the property depends on.

---

## Sequencing

The dependencies are real; taking these out of order produces checks that look
like controls and are not.

1. **`neural-ice-secureboot-prod-v1` key ceremony.** Absent today. Blocks every
   production-chain evidence claim below.
2. **Finding 1, Design A** — UKI + dm-verity installer root, with the four
   tamper tests above run under real Secure Boot.
3. **Finding 2** — release authorization, pull-before-mutate, profile inspection
   of the pulled bytes. Requires 2 for its verifying key to mean anything.
4. **Finding 3** — `access_profile` in the signed release plus the enrolled,
   TPM-anchored anchor. Independent of 2–3 in principle; scheduled last because
   it is the only item that forces an ICE-Fabric schema change.

## What this note explicitly did not change *(as written; superseded)*

- ~~**No release-schema field is added.**~~ The Owner approved Finding 3's
  binding, so `access_profile` **was** added to the release authorization, as a
  **required** field. The BOM and the channel record are still untouched.
- ~~**No signed-artefact architecture is implemented or improvised.**~~ The Owner
  chose **Design A**. Design B was not implemented and should not be: with
  shim→GRUB the initramfs is authenticated only if GRUB verifies it, which makes
  the verifying key as editable as the thing it verifies.
- The remaining privileged/physical gates stand as previously recorded:
  finalized raw tamper tests under real Secure Boot, hostile-mirror
  single-manifest and OCI-index pulls, real systemd first boot plus reboot,
  lab↔customer OTA-negative tests, and signed physical recovery with no shell.

---

## Status, 2026-08-31 — Design A is now wired to the producer

The first implementation of this note shipped every component of Design A and
connected almost none of it to `image/build-installer-usb.sh`. A review found the
signed-root path was **dead code**: no production caller of the UKI builder, no
initramfs hook opening `neuralice-installer-root`, no staging of the hash tree,
no boot entry for the UKI, and no release-authorization key in the image — so the
runtime gate refused every medium it was ever handed, correctly and uselessly.

`docs/ADR-0015` §"Amendment, 2026-08-31" records what changed, item by item. In
this note's own terms:

- **Finding 1** is now *implemented*, not merely designed. The medium carries a
  dm-verity installer root and a signed UKI, and the runtime gate proves the
  **mounted root's device number is the verified mapper's**, which the first cut
  did not — it only proved a correct mapper existed somewhere.
- **Finding 2**'s verifying key now actually exists in the image, its
  authorization is checked against a TPM-backed high-water of what this machine
  has already consumed, its `image_platform` is compared with the platform being
  installed, and the candidate's markers are read **host-side** instead of by
  executing the candidate's own `cat`.
- **Finding 3**'s `anchor_seq` is a TPM NV monotonic counter rather than the
  literal `1`, the OTA verifier makes the device root **sign a fresh nonce**
  rather than compare four files that travel together, and the two `state-v2`
  commands — which previously skipped the profile gate entirely — now enforce it
  against the candidate deployment's own immutable marker.

## Second remediation, 2026-09-01 — three of the above were narrower than the prose

A second review found that the delivery was internally consistent and
**unbootable**, and that two controls were narrower than the sentences describing
them. `docs/ADR-0015` §"Amendment, 2026-09-01" records it item by item; in this
note's own terms:

- **Finding 1 was true of the anchor and false of the medium.** A dm-verity
  squashfs mounted as `/` cannot run an installer that writes `/etc` and `/var`,
  so the medium verified perfectly and could not install. And the sentence "GRUB
  survives only as a `chainloader` menu with no kernel of its own" was a claim
  about the generated `grub.cfg`, not about the medium: GRUB itself kept `linux`,
  `initrd` and an editable command line, and the raw still carried the standalone
  kernel, the original initramfs, a shim and a whole ostree deployment. There is
  now **no boot manager at all** — one signed UKI at `\EFI\BOOT\BOOTAA64.EFI`,
  a remade ESP, an overwritten boot partition, and an off-device inspector that
  requires every other partition to be zero. Live and Install are separate media.
- **The bytes the installer writes were not authenticated.** The container store
  the install reads FROM was a directory on an ordinary filesystem, hashed only
  into a build manifest nothing read at runtime. It is now one region of a
  **sealed payload** whose header digest the UKI seals and whose extents are
  opened through dm-verity, and it is installed from **in place** — no
  `copy-to-storage`, no import, no window between "verified" and "used".
- **Finding 3's device-root signature was authority it should not have had.**
  That key has an empty authorization policy, so a privileged runtime attacker
  could re-issue the anchor with a different profile at the current counter. The
  profile is now bound to a **write-once, policy-protected TPM NV record**; the
  signature proves device binding, and changing what an appliance IS requires a
  TPM clear with physical presence followed by a reinstall from signed media.
- **Freshness was the RTC.** An age window judged against `date -u +%s` kept a
  captured authorization alive for as long as somebody was willing to set the
  clock back. It is now a signed monotonic issuance sequence enforced against a
  TPM counter; timestamps are informational.

**Still physical, still not claimed.** No medium has been written and no GB10 has
booted one. The acceptance evidence listed under Finding 1 stands unchanged. A
measured `image/hardware-identity/nvidia-gb10-arm64.fingerprints` has been staged
into a build tree from `ni-coreos-93b9` (2026-08-31, generic DMI identity); it is
provisional until a second GB10 confirms it, and it is git-ignored because this
repository must not carry a machine identity nobody measured.
