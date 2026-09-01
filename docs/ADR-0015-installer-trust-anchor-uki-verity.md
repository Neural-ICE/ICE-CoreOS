# ADR-0015 — Installer trust anchor: signed UKI, dm-verity root, authorized releases

- **Status**: Accepted (implementation complete; production-chain evidence pending)
- **Date**: 2026-08-31
- **Decider**: Business/Security Owner (human)
- **Implements**: [DESIGN-NOTE-0001](DESIGN-NOTE-0001-sealed-access-trust-anchor.md)
  Findings 1 (P0), 2 (P0) and 3 (P1), by the Owner-approved Design A
- **Related**: [ADR-0002](ADR-0002-secure-boot-zero-touch.md) (Secure Boot anchors,
  already prefers a UKI), [ADR-0005](ADR-0005-release-channels.md) (signed trains),
  [ADR-0012](ADR-0012-atomic-ota-state-v1.md) (atomic state),
  [ADR-0013](ADR-0013-device-root-tpm-v1.md) (device root at `0x81010005`),
  [ADR-0014](ADR-0014-access-policy-lab-vs-customer.md) (the access policy this anchors)

## Context

ADR-0014 moved the remote-access trust anchor off the mutable ESP and into
`/usr/lib/neural-ice/access-policy`, "covered by whatever signs the image". That
sentence is true of a **deployed, OTA-managed appliance**. It is not true of the
**removable installation medium**, and the installer is where the policy is first
read.

Three findings followed, and DESIGN-NOTE-0001 recorded them without fixing them
because closing them changes the signed-artefact architecture:

1. **The installer root is not authenticated by the boot signature.** Secure Boot
   authenticates EFI binaries and the kernel; it says nothing about the root
   filesystem those binaries mount. An attacker with physical access to a
   correctly signed installer USB could rewrite the access-policy marker from
   `customer-locked` to `lab-managed`, or rewrite `neural-ice-autoinstall.sh` so
   the gate was never consulted. Both survived Secure Boot untouched.
2. **A digest was verified; an authorization was not.** Nothing constrained which
   digest could be *asked for*. `neuralice.osimage=` came off an unauthenticated
   command line, so a customer medium could be pointed at a perfectly
   image-ci-signed `debug` digest and would install it — serial root autologin,
   sshd enabled, SELinux permissive. Worse, the pull ran *after*
   `wipefs`/`sfdisk`/`luksFormat`/`mkfs`, so "refuse" could not mean "leave the
   machine as it was", and `--skip-fetch-check` meant bootc re-verified nothing.
3. **OTA bound the variant, not the profile.** ADR-0014's continuity argument
   rested on "the variant → policy mapping is a total function". That is a
   property of the source tree, not of anything signed: a later, correctly
   signed, same-variant release could rewrite the mapping and widen the
   appliance's posture with no signature ever having stated the old one.

## Decision

### 1. The installer root becomes dm-verity, and the UKI seals its hash

The installer root ships as a read-only dm-verity image. Its root hash and the
complete installer trust boundary are written into the `.cmdline` section of a **UKI** — one PE
binary carrying kernel, initramfs and cmdline, signed as a whole:

| sealed field | pins |
|---|---|
| `neuralice.rootverity` | the dm-verity root hash of the installer root |
| `neuralice.access_profile` | the profile this medium may act on |
| `neuralice.hardware_target` | the hardware this medium may install onto |
| `neuralice.trust_policy_id` | which Secure Boot trust policy signed this chain |
| `neuralice.relauth_keyid` | SHA-256 of the key that may authorise a release |
| `neuralice.relauth_schema` | the exact closed release-authorization contract (`neural-ice-installer-release-authorization-v2`) |
| `neuralice.payload` | SHA-256 of the canonical payload header binding every protected medium extent |

Editing any one of those words invalidates the PE signature and the firmware
refuses to boot. The initramfs — being *inside* the signed binary — sets dm-verity
up before `switch-root`, so any byte changed anywhere in the installer `/usr`
fails verification and the install never starts.

**The `/usr` marker becomes a cross-check, not the authority.** The installer
reads the profile from the signed cmdline and *additionally* requires the file in
the now-verity-protected `/usr` to state the same value, along with the hardware
target, the trust-policy id and the release-authorization key. Disagreement is a
refusal. Redundancy is cheap; ambiguity about which one wins is not.

**Closed-world parsing is load-bearing.** systemd-stub honours the embedded
`.cmdline` and ignores an externally supplied one *only while Secure Boot is
enforcing*. With Secure Boot off — a state physical access can reach — the two are
concatenated. Every reader therefore refuses a **second occurrence** of any sealed
key rather than taking the first or the last. An anchor that can be shadowed by
appending to it is not an anchor.

**The key path is unchanged: lab-v1, direct UEFI.** The UKI is signed with the
Neural ICE UEFI Secure Boot CA — the same anchor that already signs `vmlinuz` and
`grub` — and validated by firmware carrying that certificate in `db`. It does not
go through the MS-signed shim, because `neural-ice-secureboot-prod-v1` does not
exist. See *Evidence and what is still missing*.

### 2. Pull and authorize before any target mutation

A **release authorization** is a cosign-signed, closed 14-field statement binding
`{schema, index digest, platform manifest digest, publication shape, repository,
platform, access_profile, variant, hardware_target, signed_boot_trust_policy_id,
key_id, issuance_id, issuance_seq, issued_at}`. It is verified
with the key inside the verity-protected root, whose SHA-256 the UKI seals — so a
substituted key is a different id and the gate refuses. Without Finding 1 fixed
first this check would be theatre: an editable key verifying an editable policy is
a circle.

The installer now, **with the target disk untouched**:

1. verifies the authorization's signature over domain-separated bytes;
2. requires it to agree with the medium on profile, hardware target, trust policy
   and key identity, and to **name** the digest that was requested — the karg no
   longer *selects* an image, it only has to *match*;
3. pulls exactly that digest;
4. requires **both** observed digests — the index (`.RepoDigests`) and the platform
   child (`.Digest`) — to equal the authorised pair;
5. reads the access policy, variant and hardware target out of the **pulled
   object**, and its trust-policy **label**, and requires exact agreement;
6. installs only that local, content-addressed object, asserting it is still
   present and that the source did not change between proof and install.

**Both digests, both directions**, because that is what closes index/child
confusion: an index answered with its child, or a child swapped under a correct
index, fails exactly one of the two comparisons. Checking one of them would break
the day the appliance goes multi-arch, or pass vacuously today.

`--skip-fetch-check` is kept and is now defensible: an independent proof
*precedes* the install rather than an assumption *replacing* it. The installer
asserts the link, so removing the proof fails the install rather than quietly
leaving the flag behind.

### 3. The access profile is enrolled at install time and anchored to the TPM

The profile the signed UKI sealed — cross-checked against the image actually
installed — is written into the **stateroot**, deliberately outside the candidate
deployment so a deployment can never restate its own authority, and signed by the
non-exportable device root at `0x81010005`. An attacker who can edit `/var`
offline can rewrite the JSON; they cannot produce the signature.

`ni-ota-verify` reads that anchor on every delegated path and requires the signed
release's new `access_profile` field to equal it. **A mismatch is
"reinstall required"** — deliberately not "re-enrol": a profile change is a change
of what the appliance *is*, and the only honest path back is signed physical media.
A `customer-locked` appliance therefore cannot be walked to `lab-managed` by any
OTA, however well signed.

A monotonic `anchor_seq` guards replay: the signature stops a forgery, not the
re-use of a genuinely device-root-signed bundle from a previous installation of
the same machine.

## Amendment, 2026-08-31 — what the first implementation did not do

The first cut of this ADR shipped every component described above and **wired
almost none of it into the thing that produces media**. A review found the
signed-root implementation was dead code. What follows is what changed; the
sections above describe the design, this one describes the delivery.

> ⚠️ **Items 1, 2, 6 and 7 below are SUPERSEDED** by the 2026-09-01 amendment:
> the medium described here could not boot, its container store was
> unauthenticated, GRUB survived as a real boot authority, and freshness was
> judged against the RTC. They are kept because the reasoning that produced them
> is part of the record — read them with §A–§F of that amendment.

1. *(superseded — see amendment 2026-09-01 §B, §C.)* **`image/build-installer-usb.sh` now builds and installs it.** It produces the
   sealed installer root (`image/build-installer-root.sh`: one deterministic
   squashfs of the installer image, plus the medium-local container store the
   install now reads from), formats its dm-verity hash tree, builds **two** signed
   UKIs — Live and Install, differing only in sealed kargs — stages the root
   image, the hash tree and the store onto the medium, names that partition
   `ni-installer-media`, and installs both UKIs on the ESP. `neuralice.autoinstall=1`
   is now a property of a signature rather than of a keystroke.
2. *(superseded — see amendment 2026-09-01 §C.)* **GRUB loses its kernel.** Every BLS entry is deleted and `grub.cfg` is
   rewritten to two `chainloader` entries. It names no kernel, no initramfs and no
   karg; editing it can at most choose which authenticated binary runs. The build
   reads that back and refuses a medium where any `linux`/`initrd` directive
   survives.
3. **An initramfs hook opens the mapper.** `image/initramfs/90neural-ice-installer-verity`
   travels *inside* the signed PE, refuses a duplicated `neuralice.rootverity=`,
   and activates with `--panic-on-corruption`. It does not fall back.
4. **The verity gate proves a topology, not an existence.** `installer_trust_assert_root_verity`
   now requires the mapper's whole dm table to be a single `verity` target with
   the sealed hash, and requires the **mounted root's device number to equal that
   mapper's**. A correct verity device beside a mutable root no longer satisfies
   anything.
5. **The identities stopped being self-asserted.** The signing certificate must
   resolve to an anchor the named trust policy pins (`image/lib/signing-trust.sh`),
   the trust-policy id comes from the image rather than from a build argument,
   `ci/build-image.sh` passes the verified id as a build arg and reads the
   immutable marker back off the built image, and the hardware target is checked
   against the **measured** device-tree/SMBIOS identity of the machine
   (`image/lib/hardware-identity.sh`). A machine that cannot be identified is a
   refusal.
6. *(freshness superseded — see amendment 2026-09-01 §E; platform and host-side
   inspection stand.)* **Freshness, platform and replay.** The release authorization is now checked
   for age, for `image_platform` against both the selected and the observed
   platform, and against a **TPM-NV high-water** of the last authorization this
   machine consumed. The candidate image's markers are read **host-side** via
   `podman image mount` — the previous code executed the candidate's own `cat`.
7. *(superseded — see amendment 2026-09-01 §D.)* **The anchor sequence is a TPM counter.** `ota/neural-ice-tpm-highwater.sh`
   owns two NV indices: a monotonic install counter (`0x01500003`) that numbers
   access-profile anchors, and an eight-byte high-water (`0x01500004`) for
   consumed release authorizations. The installer no longer writes the literal
   `1`, and the gate no longer defaults its high-water to `0`.
8. **The OTA verifier talks to the TPM.** `access_profile_anchor.rs` makes the
   device root sign a fresh nonce and requires `anchor_seq` to equal the TPM's
   install counter, so a coherent bundle copied from another appliance now fails.
   `guard-state-v2` and `commit-state-v2` gate on the enrolled profile too, and
   all four paths require `--candidate-root` and check the candidate's **own**
   `/usr/lib/neural-ice/access-policy` against the authorization's
   `access_policy_sha256`.
9. **Every security-relevant karg rejects duplicates**, not just the sealed six:
   `neuralice.imgref`, `.mirror`, `.source`, `.osimage`, `.systemsize` and
   `.target` are read exactly once or refused.


## Amendment, 2026-09-01 — the medium could not boot, and its payload was not authenticated

A second review found that the delivery above was internally consistent and
**unbootable**, and that two of its controls were narrower than their prose. What
follows is what changed. Where a claim below replaces an earlier one, the earlier
one is corrected in place rather than left to be believed.

### A. A verity squashfs with no writable runtime cannot run an installer

`neural-ice-installer-verity.sh` mounted the dm-verity mapper directly as `/`.
The installer writes `/etc` drop-ins, `/var` scratch and podman state, so that
medium verified perfectly and then could not install. The initramfs now:

* mounts the verified root **read-only** at `/run/neural-ice-installer/verity-root`;
* creates a **bounded tmpfs** (`size=50%`, `nodev,nosuid`) and mounts an
  `overlay` over the verified root at `$NEWROOT`, with that tmpfs as the upper
  layer — created empty, inside the signed initramfs, on **every** boot;
* refuses a `root=` on the command line outright. Previously it *defaulted* one,
  so with Secure Boot off — where systemd-stub concatenates an externally
  supplied cmdline onto the sealed one — appending `root=/dev/sda2` made dracut
  mount an attacker's root and never touch dm-verity. The sealed anchor was
  intact; it was simply not the thing that decided.

`installer_trust_assert_overlay_root` proves the arrangement after switch-root:
exactly one lower layer, which is the verified mount, and an upper layer on a
`tmpfs`. All policy markers are read from the **verity mount**, never from the
overlay.

### B. The install payload is one authenticated object

The medium used to stage `installer-root.img`, its hash tree and a `store/`
directory on an ordinary filesystem. Only the first was authenticated; the store
— the ~10 GiB actually written onto a customer's disk — was hashed into a build
manifest nobody read at runtime, and no off-device reader could hash any of it.

The three become one **sealed payload**, a raw self-describing extent on a
partition named `ni-installer-payload`:

```
offset 0        header, 4096 B, canonical key=value text, NUL padded
                (image/lib/installer-payload.sh renders and parses it)
offset 4096..   root-image   the installer root squashfs   -> dm-verity
                root-hash    its hash tree
                store-image  the containers-storage squashfs -> dm-verity
                store-hash   its hash tree
```

The header names each region's offset, size and SHA-256 and carries **both**
dm-verity root hashes. **Its SHA-256 is sealed in the signed UKI** as
`neuralice.payload=`, so one signed value binds every byte on the medium
transitively. The initramfs verifies the header against that value, then opens
*both* extents through dm-verity — so the container store is protected per-block
at read time, with no up-front hash and no window between "verified" and "used".

Consequences of that shape:

* **`bootc image copy-to-storage` is gone.** The store is registered as a
  read-only **additional image store** and installed from in place. There is no
  copy, and `--source-imgref` names exactly the extent the signature covers.
  `--skip-fetch-check` remains, and remains about the *target* imgref only.
* **The medium is inspectable off-device.** `image/inspect-installer-media.py`
  hashes every region out of the raw and **recomputes both dm-verity root hashes
  from the bytes on the medium** — layout-independent, so it does not assume how
  cryptsetup arranges levels. That recomputation is checked against real
  `veritysetup` output in `image/test-installer-payload.sh`.
* **The verity UUID is pinned.** `veritysetup format` writes a superblock whose
  UUID is random by default, so two builds of identical bytes produced identical
  root hashes and **different hash trees**. Invisible while only the root hash
  was recorded; a determinism defect now that the tree is sealed.
* **Both images are padded to 4096.** `veritysetup` protects
  `floor(size / 4096)` blocks and ignores a trailing partial one, so an unaligned
  image ended in bytes dm-verity never checked.

### C. The medium is single-purpose, and carries one EFI authority

Amendment §2 above said "GRUB loses its kernel". That was a claim about the
`grub.cfg` this build *wrote*; it was not a claim about the medium. GRUB kept its
`linux`/`initrd` commands and its editable command line, and the raw still
carried the signed standalone vmlinuz, the original initramfs, the BLS-era
`/boot`, a shim and a whole ostree deployment. An operator at the GRUB console
could boot that kernel with kargs of their choosing, and the sealed `.cmdline`,
the dm-verity root, the access profile and the duplicate-karg controls were
simply not in the picture. **§2 of the 2026-08-31 amendment is superseded.**

There is no boot manager any more:

* `MEDIA_MODE` (`install` | `live`) selects **one** UKI, which is installed as
  `\EFI\BOOT\BOOTAA64.EFI` — the removable-media default path the firmware
  loads with no NVRAM entry, no menu and no configuration file;
* the ESP is **zeroed and remade** with `mkfs.fat`, so "there is no shim, no GRUB
  and no fallback binary" is a statement about bytes rather than about directory
  entries;
* the boot partition is **overwritten with zeros** and renamed
  `ni-installer-void`; the data partition is overwritten by the sealed payload;
* the inspector enumerates the whole ESP tree against an allowlist and requires
  every other partition to be **entirely zero**. A second `.efi`, a `grub.cfg` or
  a surviving BLS entry is a refusal.

Live and Install can no longer be chosen at boot. That is the trade this review
authorised: a mutable selector is authority, and the alternative was to weaken
what the UKI seals. An operator who needs both cuts two media.

### D. The device root proves the device; it does not authorize the profile

The device root at `0x81010005` has `userwithauth` and an **empty authorization
policy**, and is persisted under the owner hierarchy with no authentication
secret. Anything running as root on the appliance can make it sign — including a
replacement access-profile anchor carrying a different profile at the current
install-counter value. The liveness challenge does not help: it proves the key is
usable on this machine, which is exactly what the attacker also enjoys.

`ota/neural-ice-tpm-state.sh` (renamed from `neural-ice-tpm-highwater.sh`) now
owns three NV indices, and the profile is bound to the third:

| index | what | authorization |
| --- | --- | --- |
| `0x01500003` | monotonic install counter | `policywrite` + `PolicyCommandCode(NV_Increment)`, `nt=counter` |
| `0x01500004` | release-authorization issuance high-water | same |
| `0x01500005` | 64-byte **write-once record**: `NI-TPM02`, `sha256(domain‖profile‖target‖trust_policy_id)`, then 24 fixed zero bytes | `policywrite` + `PolicyOR(PolicyCommandCode(NV_Write), PolicyCommandCode(NV_WriteLock))`, `writedefine` |

**No index carries `ownerwrite` or `authwrite`.** The installer writes the record
once and immediately `NV_WriteLock`s it; `writedefine` makes that lock permanent
for the life of the index, across TPM restarts. `ni-ota-verify` and the shell
gate both require the anchor's triple to hash to what the record holds, and both
verify the index's **attributes and policy digest** before reading its content —
an index redefined with weaker authorization is a different index wearing the
same address.

Division of labour, plainly: **the NV record is the authority**, the device root
proves **device binding and liveness**, and the install counter proves this is
**not a replay** of an earlier installation.

#### The residual, and the physical recovery

`TPMA_NV_POLICY_DELETE` — the attribute that would make an index undeletable —
may only be set when the index is defined under the **platform hierarchy**
(`TPM_RC_ATTRIBUTES` otherwise, **measured** in
`ci/test-swtpm-monotonic-state.sh`). Platform authorization is not available to
an operating system: TCG PC Client firmware disables the platform hierarchy
before handing off. Empty owner authorization would therefore allow
`TPM2_NV_UndefineSpace`. The mandatory first-boot ceremony closes that window
before runtime readiness: after checking the persisted device root and intended
SRK, it creates the three fixed indices, write-locks the record, replaces owner
authorization with 32 random bytes, and keeps no copy. Runtime root can then
neither undefine/redefine NV state nor evict/recreate persistent objects. Any
partial fixed state before completion is refusal, never a fresh install.

**Operator recovery, when the binding is legitimately gone** — a TPM clear, a
replaced board, or a deliberate change of what the appliance is:

1. the appliance's OTA path refuses with `reinstall required`; nothing is
   silently widened;
2. an operator with **physical presence** clears the TPM at the firmware setup
   screen. This is the gate: no software on the appliance can do it, and no
   remote path exists;
3. the machine is reinstalled from signed physical media, which provisions the
   device root, intended SRK, fixed NV state and owner ceremony as one lifecycle.

Changing a `customer-locked` appliance to `lab-managed` therefore requires
someone standing in front of it with signed media. That is the property ADR-0014
asked for, now enforced by hardware rather than by a signature the appliance can
re-issue.

### E. Freshness is a signed sequence, not the RTC

`release_auth_gate_request` took `date -u +%s` and a 14-day window. Both come
from the firmware RTC, which anybody holding the machine can set: rolling it back
kept an unconsumed captured authorization inside its window indefinitely, and the
NV high-water only helped **after** consumption.

The gate now takes **no current time at all**. The authorization carries
`issuance_seq` — a signed, monotonic decimal — and it must be **strictly greater**
than the sequence high-water this machine keeps in TPM NV. Consuming sequence *N*
advances that NV counter to *N*; a gap larger than 4096 is refused, because a TPM
counter advances by one and an unbounded gap is a hostile document asking the TPM
to work for an hour. `issued_at` is still required, still shape-checked, still
logged — and nothing is decided from it.

### F. Single-manifest publication is a first-class OCI shape

The parser refused any authorization whose index and platform-manifest digests
were equal, reasoning that an index which *is* its own child collapses the
distinction the pair preserves. That reasoning is right for an index and wrong
for the object this repository actually publishes: `ci/build-image.sh` pushes
**one arm64 manifest**, for which the repository digest and the platform manifest
digest name the same object — so no valid authorization could describe the
published artefact and the secured registry path was unusable.

The shape is now **declared** in the signed document, and the equality rule
follows from it:

| `image_publication_shape` | rule |
| --- | --- |
| `single-manifest` | `image_index_digest` **must equal** `image_manifest_digest`, and the pulled object must resolve to one |
| `index` | the two **must differ**, and the pulled object must resolve to two |

Equality is never inferred and never tolerated by accident. Multi-arch
publication still requires a distinct, recursively signed index and child.
`ci/build-image.sh` prints `PUBLICATION_SHAPE=single-manifest` beside the digest
it pushed, so an issuer does not have to infer which value to sign.

#### `neural-ice-installer-release-authorization-v2`, in full

Closed world (`deny_unknown_fields` in one word: an unknown field is a refusal,
because the field this installer does not understand could be the one that
mattered). **Every value is a string**, so one canonicalisation covers all of
them and no reader can round a large integer into a different one. The signature
is over `"neural-ice:installer:release-authorization:v2" ‖ 0x00 ‖ <the file's
exact bytes>`, made by the key whose SHA-256 the UKI seals as
`neuralice.relauth_keyid`. The UKI also seals this exact schema as
`neuralice.relauth_schema`; v1, a missing schema anchor, or any old/new mixture
is refused before a pull. There is no compatibility reader.

| field | form | bound to |
| --- | --- | --- |
| `schema` | `neural-ice-installer-release-authorization-v2` | the exact schema sealed into the signed UKI |
| `access_profile` | `lab-managed` \| `customer-locked` \| `developer-diagnostic` | the medium's sealed profile, and the pulled image's own marker |
| `variant` | `debug` \| `prod` \| `sealed-lab` | must derive `access_profile`; also the pulled image's marker |
| `hardware_target` | `[a-z0-9]([a-z0-9_-]{0,62}[a-z0-9])?` | the medium's sealed target |
| `signed_boot_trust_policy_id` | `neural-ice-secureboot-[a-z0-9-]{1,32}` | the medium's sealed policy id, and the pulled image's label |
| `image_repository` | a plain registry path | the requested reference's repository |
| `image_index_digest` | `sha256:<64 hex>` | the requested digest, and the pulled object's repo digest |
| `image_manifest_digest` | `sha256:<64 hex>` | the pulled object's `.Digest` |
| `image_publication_shape` | `single-manifest` \| `index` | decides whether the two digests must be equal or must differ, on both the document and the resolution |
| `image_platform` | `os/arch[/variant]` | the platform this install selected **and** the platform the pulled bytes report |
| `issuance_id` | `[A-Za-z0-9][A-Za-z0-9._-]{0,63}` | logged; not a decision |
| `issuance_seq` | decimal `[1-9][0-9]{0,15}` | allocated by Fabric; **strictly greater** than the TPM NV issuance high-water; copied unchanged only after `bootc install` commits, then consumed by the mandatory installed firstboot ceremony |
| `issued_at` | RFC 3339 UTC `Z` | **informational only** — never compared with a clock (§E) |
| `key_id` | `[0-9a-f]{64}` | the SHA-256 of the public key it verifies against, which must be the one the UKI seals |

## Amendment, 2026-09-01 (second review) — five code blockers

The review that produced Amendment A–F was re-run against the implementation.
Everything below is a **code** defect it found; the physical gates named in
"Evidence, and what is still missing" are unchanged and still outstanding.

### G. The medium could not identify its own disk

`ota/neural-ice-autoinstall.sh` asked `findmnt -no SOURCE /` and handed the
answer to `lsblk -no PKNAME` to find the disk it must **not** wipe. Amendment A
is why that could never work: the signed initramfs deliberately switch-roots onto
an **overlay** over the verified squashfs, so `findmnt /` answers
`neural-ice-installer-root` — an overlay source with no parent block device.
`PKNAME` was empty and **every sealed Install medium died there**, before the
trust gate and before any disk was touched.

The signed initramfs already resolves the authenticated payload partition. It now
records the **resolved device node** and the **device number sysfs reports for
it** — not the `by-partlabel` symlink, which udev can repoint at a second medium
between the initramfs and switch-root. `installer_trust_sealed_medium_disk`
consumes that breadcrumb as a **candidate** and requires five things of it: a
small regular non-symlink one-line file; a plain `/dev` path that resolves to a
block device whose number is still the recorded one; a **partition** in sysfs; a
**whole-disk parent**; and — the part that makes it *this* medium — a payload
header read straight off that partition whose SHA-256 is the digest the signed
UKI seals. It runs after the sealed payload is proved, so the disk excluded from
the wipe is the disk carrying the bytes this kernel booted.

`image/test-installer-trust.sh` builds a post-switch-root fixture (overlay root,
breadcrumbs, a sysfs tree with a partition and its parent disk, a real payload
extent) and mutates each part of it in turn.

### H. One immutable image identity, resolved once

`image/build-installer-usb.sh` handed `image/build-installer-root.sh` a local
**tag**, and that script resolved it once for the root filesystem and again,
later, for the sealed store. A concurrent build or a `podman tag` between the two
produced **root A plus store B** — both extents validly hashed, both covered by
the signature, and `bootc` installing B while every medium-path check assumed A.

The tag is now resolved to an **image ID** (the config digest) immediately after
the build that produced it, and every subsequent step — the marker reads, the
measured-identity list, the sealed root, the sealed store, the dracut run and
bootc-image-builder — names that ID. `build-installer-root.sh` **refuses a
mutable reference outright** rather than resolving one, records the ID and a
digest of the four immutable markers in its manifest, and requires the staged
store's own recorded image ID to equal the sealed root's. The media build reads
that manifest back and re-checks the tag has not moved after each step.

### I. `WRITTEN` **and** `WRITELOCKED`, required rather than masked

`TPMA_NV_WRITELOCKED` was masked out as a "dynamic" bit and never asked for
again, in `ota/neural-ice-tpm-state.sh` and in
`tools/ni-ota-verify/src/access_profile_anchor.rs` alike. A power loss between
`TPM2_NV_Write` and `TPM2_NV_WriteLock` therefore left a record that is written
and **still rewritable**, which both readers accepted as finished — and
`profile-bind` returned early for it, so the lock was never taken for the life of
the appliance. Both readers now require both bits.

**And provisioning does not "fix" it either.** Until the lock is taken the index
is an ordinary writable index. Across invocations, a record that is
defined-but-unwritten or written-but-unlocked is treated exactly like a removed
one: a refusal and physical recovery. No runtime command completes it.

The residual is stated rather than hidden: a power loss in the window between
`TPM2_NV_DefineSpace` and `TPM2_NV_WriteLock` during a **first** install leaves a
machine that needs a TPM clear at the firmware setup screen before it can be
reinstalled. That is the fail-closed answer, and the window is three TPM commands
long.

### J. The issuance high-water is the absolute TPM value

The freshness contract contains no subtraction or per-install offset. The raw
value of counter `0x01500004` is the issuance high-water, and consuming *N*
increments that counter until its raw value is exactly *N*. Equal or lower
values are replay. `profile-bind` is read-only and never creates missing state;
an absent record, absent counter, or partial pair after provisioning began is
fail-closed signed physical recovery.

### K. Owner authorization is a mandatory first-boot ceremony

The installer first persists the device root at `0x81010005` and the intended
SRK at `0x81000001`, records both public identities, and enrolls both LUKS tokens
against that explicit SRK handle. The mandatory first-boot service verifies
those identities and token bindings, creates the install counter, freshness
counter and write-locked record in fixed order, then sets owner authorization to
32 bytes from the kernel CSPRNG and **keeps no copy**. The temporary value lives
only in a `0700` tmpfs workspace, is passed by `file:`, overwritten and unlinked.

This is not optional and is not idempotent. `ownerAuthSet=1` before the trusted
one-time invocation is refusal: arbitrary authorization selected by an attacker
is not evidence of this ceremony. Subsequent boots use the separate read-only
`runtime-status` path and require `ownerAuthSet=1`, the exact three-index shape,
the exact profile binding, and both persistent handles. The ceremony service is
ordered before networking, user sessions, SSH and local gettys; SSH provisioning
and device-root services require it. OTA verification also checks the live
`ownerAuthSet` property before accepting the anchor.

After sealing, **rotating the device root also requires the physical recovery
path** (TPM clear at the firmware setup screen, then reinstall from signed
media), because `tpm2_evictcontrol` can no longer obtain owner authorization.
That is the same recovery every other "this appliance cannot prove where it is"
case already has, and it is stated here rather than discovered on hardware.

`ci/test-swtpm-monotonic-state.sh` drives J and K against a real TPM 2.0: it
deletes record only and record plus freshness before sealing, stages an
interrupted write, refuses attacker-known owner authorization, detects replaced
persistent-object identities, completes the ceremony, proves the raw counter is
the high-water, refuses replay, proves runtime root cannot delete or recreate NV
or persistent objects, restarts the TPM, and measures clear as the reset
primitive used by signed physical recovery.

### L. The sealed core is inspected after the last write, not before it

`image/build-installer-usb.sh` inspects the raw it produces, and
`image/build-preloaded.sh` then keeps **writing** to that raw: it grows the file,
relocates the GPT backup header, rewrites the partition table, attaches it
writable and copies ~20 GB of seed into a new `ni-seed` partition. Final
acceptance ran `verify-preloaded-media.py`, which checked the seed tree and the
ESP handoffs and **nothing else** — not `BOOTAA64.EFI`, not the payload region
hashes, not the ESP allowlist, not the zeroed partitions. The receipt and the
checksum could therefore bless a raw whose sealed core changed after its only
inspection.

The full inspector now runs **inside** that gate, after the last writable phase
and before the artifact, the checksum and the receipt — through
`/proc/self/fd/N`, i.e. through the very descriptor the gate holds its exclusive
`flock` on and whose identity and digest it brackets. Its expectations are
**required arguments**, produced by the build that sealed them and handed over in
a `sealed-core.json` beside the raw: a final gate that can be invoked without
inspecting what the medium boots is the finding. The receipt records what was
established, so a medium blessed without an inspection is visible in the receipt
and not only in an exit status.

## Consequences

- **The four OTA verification commands gained a required `--candidate-root`.**
  A staged deployment nothing points at cannot have its marker checked, and an
  optional argument is one every caller forgets — which is exactly what happened
  to the anchor's high-water. Until a caller passes it, those commands refuse.
- **The OTA reader remains `neural-ice-ota-release-authorization-v1` for this
  P0 boundary.** Its signed document requires both `access_profile` and
  `access_policy_sha256`; both are **required**, and
  `deny_unknown_fields` means a producer that omits either is refused rather than
  defaulted. The candidate immutable marker must match both the signed profile
  and signed digest. OTA may admit or refuse a candidate; it never mutates or
  re-enrols the device profile. That is deliberate and fail-closed: the
  alternative — an optional field falling back to the variant mapping — would
  reinstate the exact premise Finding 3 exists to replace, silently. Until Fabric
  emits it, no delegated release verifies. Nothing is in production.
- **Installer authorization is a separate v2 contract.** Fabric allocates its
  `issuance_seq`; CoreOS preserves it byte-for-byte and advances the existing
  TPM absolute high-water only from the mandatory first installed boot after the
  install commit. It is never consumed by the live installer.
- The beta publication receipt needs no new field: it binds the release by
  SHA-256, so it binds the profile transitively. Its golden vector moved twice on
  2026-08-31, for that reason — once per required field added to the release.
- ADR-0014's continuity claim now rests on a **control**, not on a source-tree
  invariant. The invariant is still worth keeping true, and the build still breaks
  if the mapping drifts — but it is no longer what the property depends on.
- A registry install now **requires** a signed release authorization on the
  medium's ESP. Media built for a bench must carry one. This is the interim
  mitigation (a) from DESIGN-NOTE-0001 generalised rather than adopted: instead of
  refusing `INSTALL_SOURCE=registry` on customer media outright, the medium may
  install exactly what it is authorised to install.
- Deterministic build outputs. The verity salt is fixed and published, section
  offsets are computed rather than discovered, and the sealed cmdline's key order
  is a constant. `image/build-installer-uki.sh` emits a manifest that CI diffs, so
  a changed root hash or cmdline is a one-line diff rather than 40 MiB of PE.
- **Runtime dependencies, all already in the image.** `veritysetup`, `losetup`
  and the `overlay` module are needed in the INITRAMFS (dracut pulls them in via
  `module-setup.sh`), and `tpm2_nvdefine` / `tpm2_nvincrement` / `tpm2_nvwrite` /
  `tpm2_nvwritelock` / `tpm2_nvreadpublic` / `tpm2_startauthsession` /
  `tpm2_policycommandcode` / `tpm2_policyor` join the tpm2-tools the device root
  already uses. `objcopy`, `mksquashfs` and `skopeo` are build-side only;
  `cosign`, `python3` and `openssl` were already the image's verification stack.
- **The medium's shape changed** (amendment 2026-09-01 §B, §C). Two partitions
  carry anything: an ESP holding exactly `\EFI\BOOT\BOOTAA64.EFI` and one UKI
  build manifest, and `ni-installer-payload` holding the sealed payload. Every
  other partition is zero. `image/config-installer.toml`'s filesystem must be
  sized for the sealed payload, and the build refuses when it does not fit.
- **`bootc image copy-to-storage` is gone.** The booted system is not an ostree
  deployment, so there was nothing for it to copy; the bytes are staged at build
  time and installed from in place through a read-only additional image store.
  This is the change with the least hardware evidence behind it and it is called
  out as such below.

## Evidence, and what is still missing

Automated, and run: `image/test-access-policy.sh`,
`image/test-hardware-identity.sh`, `image/test-signing-trust.sh`,
`image/test-installer-trust.sh`, `image/test-release-authorization.sh`,
`image/test-build-installer-root.sh`, `image/test-installer-uki.sh`,
`image/test-installer-media.sh`, `image/test-installer-payload.sh`,
`ota/test-neural-ice-tpm-state.sh`,
`ota/test-neural-ice-access-profile-anchor.sh`,
`image/test-verify-preloaded-media.sh`, `ci/test-swtpm-monotonic-state.sh`, and
the `ni-ota-verify` suite.

The medium fixture `image/test-installer-media.sh` and
`image/test-verify-preloaded-media.sh` both build is **one library**
(`image/test-lib/sealed-medium-fixture.sh`). Two fixtures would be two
definitions of "a sealed medium", and only one of them could be the one the
producer actually makes.

**What is real in those suites, and what is not.** The distinction matters,
because the previous revision of this section claimed more than it had:

| Real | Substituted |
| --- | --- |
| ECDSA P-256 keys, signatures and DER, throughout | The GB10's discrete TPM (swtpm stands in) |
| `cosign verify-blob` (CI installs the pinned build; the suite refuses to report green on its openssl shim) | The 10 GiB installer image (`build-installer-root.sh`'s mocks) |
| `objdump`/`objcopy` assembling a real PE, `sbsign` signing it, `sbverify` verifying it | Firmware: nothing here proves a machine's `db` accepts the signature |
| `mkfs.vfat`/`mcopy`/`sgdisk` building a real GPT medium, read back **without root** by `image/inspect-installer-media.py` | An actual boot |
| `veritysetup` formatting both protected extents, and the inspector's independent Merkle recomputation checked against it | — |
| A real TPM 2.0 (`swtpm`): the policy digests this tree hard-codes, `nt=counter` monotonicity across undefine/redefine, a permanent `writedefine` lock across a restart, and the platform-hierarchy refusal of `TPMA_NV_POLICY_DELETE` | — |
| A real TPM 2.0, continued (Amendments I–K): pre-seal deletion of record only and record plus freshness, a genuinely interrupted `NV_Write`/`NV_WriteLock`, attacker-known owner authorization refusal, the mandatory ceremony, absolute-counter replay checks, runtime undefine/recreate refusals and a second boot | — |
| The PRELOADED finalization gate's own `inspect_sealed_core`, driven over a real finished medium with the UKI cmdline, a payload region and a zeroed partition each mutated in turn (Amendment L) | Publication itself: the receipt-writing half needs root and runs in the ARM64 integration job |

`image/test-installer-uki.sh` still mocks the toolchain deliberately: it asserts
the BUILDER's arithmetic (determinism, section offsets, refusals) on the
arguments it computes. `image/test-installer-media.sh` is the suite that uses the
real tools end to end, and CI runs both.

**Not producible here, and not claimed:**

- `neural-ice-secureboot-prod-v1` does not exist. Its key ceremony has not
  happened, so **no production-chain evidence can be produced**, and nothing in
  this ADR asserts any. This is a gap in *evidence*, not a hole in the lab trust
  proof: on lab media the cmdline is authenticated by the same signature that
  already authenticates the kernel, via the direct UEFI key path.
- The four tamper tests under **real Secure Boot on GB10** (flip a byte in the
  marker, in the autoinstaller, in the staged container object; and an unmodified
  medium installing normally) require a physical appliance and signed media.
- A real systemd first boot plus reboot, hostile-mirror pulls against a live
  registry, and signed physical recovery with no shell remain physical gates.
- 🔴 **The mandatory owner ceremony has not been run on an appliance.** Its
  preconditions and effects are measured against `swtpm`, but the GB10 campaign
  must establish *systemd's* behaviour: whether
  `systemd-cryptsetup` uses the persistent SRK at `0x81000001` rather than
  deriving a primary under the owner hierarchy at every boot. Until that is
  observed on hardware, sealing the owner hierarchy is an operator decision and
  is wired into no automatic path.
- 🔴 **The medium has not been booted.** The producer, the initramfs hook and the
  runtime gate are complete and tested, but no medium has been written and no
  GB10 has booted one. Specifically unproven: that `dracut --add
  neural-ice-installer-verity` produces an initramfs that finds
  `/dev/disk/by-partlabel/ni-installer-payload` on real hardware; that the
  firmware loads `\EFI\BOOT\BOOTAA64.EFI` and the lab `db` accepts the UKI's
  signature; that the tmpfs-over-verity overlay carries a full install; and that
  the sealed containers-storage, registered as a read-only additional image
  store, satisfies `bootc install to-filesystem --source-imgref
  containers-storage:localhost/bootc`. **`lab-v1` cannot be signed off on this
  evidence alone.**
- 🔴 **`image/hardware-identity/<target>.fingerprints` is a STAGED build input,
  not a source file.** The accepted machine identities are SHA-256 digests of a
  MEASUREMENT taken on the reference appliance
  (`image/lib/hardware-identity.sh measure`), and this repository holds no ground
  truth about what a GB10 reports — a vendor string guessed here would be a check
  that passes on the wrong hardware. The file is git-ignored on purpose. A
  measurement taken on `ni-coreos-93b9` on 2026-08-31 has been staged into a
  build tree; **it is a generic DMI identity and has not been confirmed against a
  second GB10**, so the list is provisional until the hardware campaign runs.
  Without it staged, `image/build-installer-usb.sh` refuses to produce a medium.
- 🔴 **A hardware TPM campaign is still required.** `swtpm` proves the NV
  semantics the design depends on. It cannot prove that the GB10's TPM behaves
  identically, that `0x01500003`/`0x01500004`/`0x01500005` are free on a shipped
  unit, that its firmware really disables the platform hierarchy (which is what
  makes the residual in §D a residual rather than a defect), or that PCR7 sealing
  survives a firmware update.
- 🔴 **`image/keys/release-authorization.pub` is absent.** Its key ceremony has
  not happened, so no medium can be produced and no registry install can be
  authorised. A staging blocker, not a code gap.
