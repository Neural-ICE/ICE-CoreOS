# ADR-0044 — Generic installer: one signed UKI, a signed payload per medium

- **Status:** Proposed (2026-10-06). The target was decided by the Owner on 2026-10-06: "the UKI is signed once; a USB medium is the unchanged UKI plus a signed payload, assembled in minutes". The details below await Owner review.
- **Decider:** Owner (trust anchors, key custody, production target); coding AI (layout, verification, sequencing).
- **Supersedes, on acceptance:** the host-derived installer of `image/build-installer-usb.sh`, `image/Containerfile.installer` and the `build-installer-{root,payload,uki}.sh` chain, for v2 media.
- **Relates to:** ICE-Fabric-v2 FAB-0064, whose D3 is re-decided by Owner option B (keyed sigstore policy on the host), and FAB-0066 (preload, first-boot pull).

## Context (measured 2026-10-06)

The v2 installer is built `FROM ${BASE_IMAGE}`, the host image, and the medium embeds that host:

- the UKI cmdline seals the verity root of an installer root derived from the host, plus a payload header hashing a container store that holds the host;
- any change to the host therefore rebuilds and re-signs the whole installer.

The night of 05→06.10 showed the cost. Seven defects surfaced one per run during the first real lane-2 media build, and the last one (the host's container policy) forced a host rebuild, a new manifest and a new medium.

The Owner wants a production installer that is built and signed once, versioned, and almost never changes.

## Decision (proposed)

### The installer: one UKI

- Built with **mkosi** (`Format=uki`) from **CentOS Stream 10 minimal**. That is the host's el10 lineage: same systemd, cryptsetup, tpm2-tools, podman and bootc.
- For GB10 it uses the **same `nvidia-gb10` 4k kernel and firmware RPMs as the host** (`image/Containerfile.bootc`, step 1), with the GSP firmware in the initramfs (ADR-0041).
- The whole system is the initrd. There is no root filesystem, no embedded host and no verity root to seal.
- It is signed once per installer version: the UEFI signature (lab key now, the MS-signed shim path later) covers the kernel, the initrd and the cmdline.

### The sealed cmdline: only what does not change per release

| Field | Pins |
|---|---|
| `neuralice.relauth_keyid` | sha256 of the release-authorization key file, which is embedded in the initrd and compared at boot |
| `neuralice.relauth_schema` | the closed release-authorization contract |
| `neuralice.min_bundle_seq` | the anti-rollback floor this installer version accepts |
| `neuralice.access_profile`, `neuralice.hardware_target`, `neuralice.trust_policy_id` | unchanged meaning |
| `neuralice.installer_version` | the installer's own version, measured into PCR 11 by systemd-stub |
| install mode | `autoinstall=1`, `source=payload\|mirror\|registry` |

The host reference (`imgref`), the payload hash, the seed and the mirror are **not sealed**. They come from the payload, and that payload is proven by a signature made with the sealed key.

### The payload partition: per medium, assembled in seconds

The payload partition (GPT label `ni-payload`, read-only) carries:

- `release-manifest.json` and `.sig`: the release key's signature. It is the only thing allowed to name the host digest and the component digests;
- `lan-mirror/{mirror-config.json,.sig,ca.crt}`: the existing domain-separated signature;
- `pcr-policy/{policy.env,tpm2-pcr-public-key.pem,tpm2-pcr-signature.json}`. **These are not trusted on their own** (review 234, P1). Either the signed manifest binds them (the policy digest, the sha256 of the public key and of the signature, and the policy sequence), or the PCR-policy public key stays sealed in the UKI as it is today and only the signature JSON and `policy.env` travel on the payload, verified against it. Today's sealed hashes (`build-installer-usb.sh`) and the pre-mutation checks (`neural-ice-autoinstall.sh` around line 1821 and the TPM sequence check around line 1863) remain the reference. Recommendation: keep the PCR key sealed and have the manifest bind the digest and the sequence. This needs a field in the Fabric release-manifest contract.
- optionally, `preload/`: the host and component OCI archives for offline installs, each checked against the digest the manifest names.

### Install sequence

1. systemd-stub measures the UKI.
2. The gate reads the sealed kargs closed-world: each security field exactly once and well-formed. An external cmdline that systemd-stub appends when Secure Boot is off must neither shadow nor duplicate them. This is the rule of `installer-trust.sh`. The gate then verifies the embedded key file against `relauth_keyid`. It requires exactly one `ni-payload` partition, which must be vfat, mounted read-only, nosuid, nodev and noexec. It reads each object once, as a bounded copy in tmpfs, refuses symlinks, and verifies and parses only that copy. Nothing on the payload is read before step 3.
3. It verifies the manifest signature and refuses duplicate keys. It checks `bundle_seq ≥ min_bundle_seq`, that the host reference lies in the v2 namespace and is pinned by digest, and that the manifest's `hardware_target` equals the sealed one. It then checks the measured hardware fingerprint, using the existing hardware-identity files from the initrd.
4. It runs the existing PCR 7 coverage gate (`NI-P7-COVERAGE`) and the TPM NV policy-generation check, before any disk write.
5. It runs `bootc install to-disk` with the host `repository@digest` from the source the install mode names:
   - `payload`: an OCI archive on the payload, digest-checked;
   - `mirror`: the signed mirror configuration, then a pull by digest;
   - `registry`: a pull by digest.
6. Before any disk write, the **existing closed policy reader** (`image/installer/neural-ice-registry-authorisation.py`) checks the installer's and the host's `policy.json`: default reject, the expected key, the exact repository scope, and no weak `signedIdentity` mode. After deployment, the installed policy is validated again (review 234, P2).
7. **Every pull** is checked by the host-side policy of Owner option B: `sigstoreSigned` with `keyPath` set to the v2 image-signing key (Scaleway KMS `ni-v2-image-signing`), with `signedIdentity` restricted to the v2 namespace. The installer's own `/etc/containers/policy.json` is the same policy.
8. It runs the existing LUKS and TPM enrolment, policy activation, strict-policy restore and seed handoff, then reboots.

### Making a medium

```
assemble-media.sh  UKI(installer vN, signed once)  payload/  out.img
```

There is no root and no loop device. It runs sgdisk, mkfs.vfat and mcopy. It took 2.8 s on .63.

## Where each guarantee of today's installer lives

| Guarantee today | Generic installer |
|---|---|
| Signed UKI, cmdline authenticated by the same signature | Unchanged: one signed UKI, signed once per installer version |
| Verity root of the installer root (`rootverity`) | Not needed: the installer is entirely inside the signed UKI (initrd) |
| Sealed payload header: root, store, hash trees (`neuralice.payload`) | Replaced. The host bytes are bound by the signed manifest digest and the keyed sigstore policy at pull time; offline archives are digest-checked |
| `relauth_keyid` and `relauth_schema` | Unchanged, and become the root of the payload trust |
| PCR 7 coverage `NI-P7-COVERAGE` (tpm-policy.py verify-live-coverage) | Unchanged, same script in the initrd, before any disk write |
| TPM NV policy generation (check/activate, factory semantics) | Unchanged (neural-ice-tpm-state.sh) |
| Autoinstall gating, signed `autoinstall=1` | Unchanged: sealed cmdline |
| Access profile (sealed + /usr marker cross-check) | Sealed field; the marker lives in the initrd, which is inside the signature |
| Trusted time (ni-ota-verify with the v2 issuer) | Unchanged binary, built once per installer version |
| Registry authorisation reader (refuses `insecureAcceptAnything`) | Satisfied by option B (keyed sigstore). Applies to the mirror and registry modes alike |
| Strict policy restore on the target | Unchanged: the target gets the host's own policy (option B) |
| Closed-world cmdline (each field once, external cmdline cannot shadow) | Kept, in the generic gate (prototype `verify-payload.sh`) |
| Exact authorization document and signature binding (registry media) | Replaced by signed manifest + floor + currentness (see Anti-rollback). This is a **weakening unless (ii)/(iii) are adopted** |
| Domain-separated signature contracts (manifest, mirror config) | Kept: each object verified under its own domain |
| Index plus platform-child digest binding | Kept: the manifest names the index; the installer pulls the arm64 child and checks it against the index |
| Measured hardware fingerprint enforcement | Kept: fingerprints in the initrd, keyed by the sealed `hardware_target` |
| Mirror CA, READY closure, lab-only use, authority separation | Kept: signed mirror config; mirror mode allowed only for the lab-managed profile |
| Source medium excluded from target selection; GPT/ESP allowlist; no hidden bootable content | Kept: the source disk is identified by its `ni-payload` partition and excluded; `assemble-media` writes exactly ESP + payload; payload inspection checks the layout |
| Seed / preseal / release reconciliation | Preload archives are each checked against the manifest digest; preseal becomes "manifest-bound" |
| Operator SSH key and other destructive parameters | Must be sealed (installer version) or bound by the signed manifest; never read unsigned from the payload |
| `inspect-installer-media.py` | Split into an installer inspection (once per version) and a payload inspection (every medium: signatures, digests, hardware target) |
| Hardware identity fingerprints | Unchanged, read from the initrd, keyed by `hardware_target` |
| Verbose failure surface and diagnostics | Unchanged services in the initrd |

## Consequences

- **A host, component, model or mirror change** needs a new signed manifest and a re-assembled payload (seconds). No installer rebuild.
- **Installer rebuild**: only for a kernel or firmware change, an installer bug or a key rotation. That is rare and gets its own ICE-Release version and ceremony.
- **Anti-rollback, the replay window stated explicitly (review 234, P1).**
  - Today a registry medium seals the exact authorization and signature digests: the medium installs exactly one release.
  - The generic installer accepts any manifest signed by the release key with `bundle_seq` at least the sealed floor. **An older signed release above the floor stays installable, and one valid payload can replace another, until the floor rises.** Raising the floor only with an installer rebuild leaves a long revocation window.
  - Options for the Owner:
    - (i) accept the window and raise the floor at every installer release;
    - (ii) a signed **currentness** object on the payload, signed by the release key with trusted time and a short validity (the trusted-time verifier already exists), which bounds replay to its validity;
    - (iii) a per-medium authorization bound to the target device (TPM EK hash), for customer media.
  - Recommendation: (ii) for all media, plus (iii) for customer deliveries.
  - On an already provisioned appliance, the TPM counters and policy generation still refuse a downgrade, as today.
- **UKI size**: 113 MiB with the prototype package set. The full set (podman, skopeo, bootc, python3, GB10 firmware) is estimated at 300–450 MiB. The ESP is sized from the UKI, and the GB10 firmware must load it. **To verify on .72.** The fallback is a smaller set (python helpers ported to ni-ota-verify).
- **Network in the initrd**: systemd-networkd plus the GB10 NIC driver, needed for the mirror and registry modes only.
- **Offline mode**: preload archives on the payload, same digest checks.
- **Lane 2 / ICE-Release**: the installer UKI is a versioned package (`installer-vN.efi`, signature, SBOM, provenance). Media assembly is a local step of the ceremony station, or a CI step for lab media. The payload is release data, not code.

## Prototype evidence (2026-10-06, branch `feat/generic-installer-mkosi-20261006`)

- `image/generic-installer/`: `mkosi.conf`, `build-uki.sh`, `assemble-media.sh`, `qemu-proof.sh` and a payload gate (`verify-payload.sh`). The prototype boots the stock el10 kernel and does not install yet.
- Build on DGX Spark .77, arm64, mkosi 25.3 in a Fedora 42 container, cold cache: **168 s**. A partly warm run on .63 took 50 s. UKI: **113 MiB**.
- Assembly: **2.8 s** for a 244 MiB medium (176 MiB ESP + 64 MiB payload).
- QEMU on .77 (KVM, AAVMF without Secure Boot, swtpm TPM 2.0):
  - real train-3 payload: `ni-generic: NI-GENERIC-PAYLOAD-OK release=v2-lab-train-3-20261005 seq=1 host=…@sha256:c3414495…`, 2.4 s after kernel start;
  - same medium with `bundle_seq` changed in the manifest: `REFUSED: the release manifest does not verify under the sealed release key`.

## Open questions for the Owner

1. **What is sealed.** Is the field set above complete? In particular, should `hardware_target` stay sealed (one installer per hardware family) or move to the signed manifest?
2. **Anti-rollback floor.** Sealed in the UKI (rare rebuild), or carried by a signed "floor" object with its own sequence?
3. **Secure Boot path.** Keep the lab key until the MS-signed shim exists. Does the generic UKI go through the shim (MOK) in production, or through direct db enrolment at the OEM bench?
4. **Kernel.** Should the installer pin exactly the host's GB10 kernel, which rebuilds the installer on every kernel bump, or an LTS installer kernel independent of the host's?
5. **Size budget.** Is 450 MiB acceptable on the ESP, or do we port the python helpers first?

## Next steps after acceptance

1. Full package set and GB10 kernel. Wire the existing gates (PCR 7, TPM NV, LUKS enrolment, strict-policy restore, failure surface) into the initrd units.
2. `bootc install to-disk` from the payload, mirror and registry modes, checked by the option-B policy.
3. QEMU qualification with Secure Boot (lab db) and swtpm, then a full install to a qcow2 target and first boot.
4. ICE-Release package for the installer; `assemble-media` in the ceremony flow.
5. Cross-model security review. Then the first production medium on hardware.
