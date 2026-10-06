# ADR-0044 — Generic installer: one signed UKI, a signed payload per medium

- **Status:** Accepted (2026-10-06). The target was decided by the Owner on 2026-10-06: "the UKI is signed once; a USB medium is the unchanged UKI plus a signed payload, assembled in minutes". The Owner accepted the six recommendations of review 234 the same day; they are integrated below as D1–D6.
- **Decider:** Owner (trust anchors, key custody, production target); coding AI (layout, verification, sequencing).
- **Supersedes:** the host-derived installer of `image/build-installer-usb.sh`, `image/Containerfile.installer` and the `build-installer-{root,payload,uki}.sh` chain, for v2 media. The sections of [ADR-0015](../ADR-0015-installer-trust-anchor-uki-verity.md) that describe that chain (§1 verity root, amendments A and B) lose their force when the chain is removed; see "Relation to ADR-0015".
- **Relates to:** ICE-Fabric-v2 FAB-0064, whose D3 is re-decided by Owner option B (keyed sigstore policy on the host), and FAB-0066 (preload, first-boot pull).

## Context (measured 2026-10-06)

The v2 installer is built `FROM ${BASE_IMAGE}`, the host image, and the medium embeds that host:

- the UKI cmdline seals the verity root of an installer root derived from the host, plus a payload header hashing a container store that holds the host;
- any change to the host therefore rebuilds and re-signs the whole installer.

The night of 05→06.10 showed the cost. Seven defects surfaced one per run during the first real lane-2 media build, and the last one (the host's container policy) forced a host rebuild, a new manifest and a new medium.

The Owner wants a production installer that is built and signed once, versioned, and almost never changes.

## Owner decisions (2026-10-06)

| # | Decision | Where it lands |
|---|---|---|
| D1 | The hardware target stays **sealed** in the UKI: one installer per hardware family. | sealed cmdline |
| D2 | Anti-rollback uses a **signed freshness object** with a **trusted date**. A sealed floor alone is not enough. | Anti-rollback |
| D3 | The **PCR-policy public key is sealed** in the UKI. The signed manifest binds the policy digest and sequence. | payload partition |
| D4 | **MOK** for the lab; **direct db enrolment at the OEM bench** for production. | Secure Boot path |
| D5 | The installer kernel is **the host's GB10 kernel** (same RPMs, same firmware). | The installer |
| D6 | A UKI of about **450 MiB** is acceptable. Porting the python helpers comes later. | Consequences |

## Decision

### The installer: one UKI

- Built with **mkosi** (`Format=uki`) from **CentOS Stream 10 minimal**. That is the host's el10 lineage: same systemd, cryptsetup, tpm2-tools, podman and bootc.
- It uses the **same `nvidia-gb10` 4k kernel RPMs and GSP firmware as the host** (D5). The kernel RPMs are the staged generation `image/rpms/` that `image/Containerfile.bootc` step 1 installs, checked by the same `ci/verify-build-context.sh`; the firmware is the staged `image/nvidia-userspace` tree (ADR-0041). The installer therefore changes with every kernel bump of the host. `build-in-container.sh` proves after the build that the UKI's kernel has the staged generation's `vmlinuz_unsigned_sha256`, and `host-kernel.env` in the initrd records the kernel NEVRA and the generation id.
- The whole system is the initrd. There is no root filesystem, no embedded host and no verity root to seal.
- It is signed once per installer version: the UEFI signature (lab key now, the MS-signed shim path later) covers the kernel, the initrd and the cmdline.

### The sealed cmdline: only what does not change per release

| Field | Pins |
|---|---|
| `neuralice.relauth_keyid` | sha256 of the release-authorization key file, which is embedded in the initrd and compared at boot |
| `neuralice.relauth_schema` | the closed release-authorization contract (not sealed by the prototype; sealed when the freshness contract exists) |
| `neuralice.min_bundle_seq` | the anti-rollback floor this installer version accepts |
| `neuralice.access_profile`, `neuralice.hardware_target`, `neuralice.trust_policy_id` | unchanged meaning |
| `neuralice.installer_version` | the installer's own version, measured into PCR 11 by systemd-stub |
| `neuralice.install_stage`, `neuralice.target_debug` | **prototype only**: the first lets the UKI install without the gates (`prototype-ungated`), the second asks the installed host for a verbose first boot. Both are removed with the gates |
| `neuralice.pcr_policy_key` | sha256 of the PCR-policy public key, which is embedded in the initrd and compared at boot (D3) |
| install mode | `autoinstall=1`, `source=payload\|mirror\|registry` |

The host reference (`imgref`), the payload hash, the seed and the mirror are **not sealed**. They come from the payload, and that payload is proven by a signature made with the sealed key.

### The payload partition: per medium, assembled in seconds

The payload partition (GPT label `ni-payload`, read-only) carries:

- `release-manifest.json` and `.sig`: the release key's signature. It is the only thing allowed to name the host digest and the component digests;
- `lan-mirror/{mirror-config.json,.sig,ca.crt}`: the existing domain-separated signature;
- `pcr-policy/{policy.env,tpm2-pcr-signature.json}` (D3). The PCR-policy **public key is not on the payload**: it is embedded in the initrd and its sha256 is sealed in the cmdline (`neuralice.pcr_policy_key`), as the release key is. The payload's `policy.env` and signature JSON are verified against that sealed key, and the **signed release manifest binds the policy digest and the policy sequence**; the gate refuses a mismatch before any disk write (review 234, P1). Today's pre-mutation checks (`neural-ice-autoinstall.sh` around line 1821 and the TPM sequence check around line 1863) remain the reference. This needs a `pcr_policy` field (`digest`, `seq`) in the Fabric release-manifest contract: a cross-repository dependency, tracked below.
- `freshness.json` and `.sig` (D2, see Anti-rollback): the signed freshness object.
- optionally, `preload/`: the host and component OCI archives for offline installs, each checked against the digest the manifest names.

### Install sequence

1. systemd-stub measures the UKI.
2. The gate reads the sealed kargs closed-world: each security field exactly once and well-formed. An external cmdline that systemd-stub appends when Secure Boot is off must neither shadow nor duplicate them. This is the rule of `installer-trust.sh`. The gate then verifies the embedded key file against `relauth_keyid`. It requires exactly one `ni-payload` partition, which must be vfat, mounted read-only, nosuid, nodev and noexec. It reads each object once, as a bounded copy in tmpfs, refuses symlinks, and verifies and parses only that copy. Nothing on the payload is read before step 3.
3. It verifies the manifest signature and refuses duplicate keys. It checks `bundle_seq ≥ min_bundle_seq`, that the host reference lies in the v2 namespace and is pinned by digest, and that the manifest's `hardware_target` equals the sealed one. It then checks the measured hardware fingerprint, using the existing hardware-identity files from the initrd. It verifies the signed freshness object against the manifest it accepted and a trusted date (D2). Of these, the prototype implements the manifest signature, the duplicate-key refusal, the floor, the namespace and the hardware target.
4. It runs the existing PCR 7 coverage gate (`NI-P7-COVERAGE`) and the TPM NV policy-generation check, before any disk write.
5. It runs `bootc install to-disk` with the host `repository@digest` from the source the install mode names:
   - `payload`: an **OCI image layout directory** on the payload (`host-oci/`; a single archive could exceed the 4 GiB file limit of FAT32), whose index must be the digest the signed manifest names; unpacked into RAM, bounded by the manifest's layer sizes;
   - `mirror`: the signed mirror configuration, then a pull by digest;
   - `registry`: a pull by digest.
6. Before any disk write, the **existing closed policy reader** (`image/installer/neural-ice-registry-authorisation.py`) checks the installer's and the host's `policy.json`: default reject, the expected key, the exact repository scope, and no weak `signedIdentity` mode. After deployment, the installed policy is validated again (review 234, P2).
   **Prototype exception, declared (review 234, P3):** in payload mode the installer lends a policy of its own: default reject, `insecureAcceptAnything` only for the exact RAM layout `/run/ni-verified/host-oci` and for the `containers-storage` transport, whose store is a fresh tmpfs holding only the verified image. The identity of the bytes is proven by the signed manifest digest, the RAM copy of the index and manifests, and the digest check skopeo makes on every blob it reads, and the installer checks that the unpacked image has the verified manifest's digest. The same file is mounted into the `bootc` container. This is the pattern of the legacy medium path and replaces nothing in the option-B policy: registry modes get no such exception.
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
| Exact authorization document and signature binding (registry media) | Replaced by signed manifest + sealed floor + signed freshness object with a trusted date (D2, see Anti-rollback). Without the freshness object this would be a weakening |
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

## Secure Boot path (D4)

- **Lab:** the UKI is signed by the lab key and enrolled by **MOK** through the shim, as for .67 and .72 today.
- **Production:** the UKI is signed by the production key and the certificate is enrolled **directly in the firmware `db` at the OEM bench**. No shim and no MOK prompt reach the customer.
- A medium therefore belongs to one path; the sealed `neuralice.trust_policy_id` names it, and the installed host's `signed-boot-trust-policy-id` marker must match it. `install-host.sh` checks this, and the access profile and the hardware target, against the markers of the unpacked image before the first disk write.
- **The sealed fields bind only while Secure Boot is enforcing.** With it off, whoever holds the machine controls the command line (systemd-stub appends or replaces the embedded one; the behaviour of the el10 stub was not tested here). The PCR 7 coverage gate is what ties an installation to the Secure Boot state, and it is not wired yet: until it is, `prototype-ungated` is lab only, and no QEMU run of this ADR had Secure Boot on.

## Consequences

- **A host, component, model or mirror change** needs a new signed manifest and a re-assembled payload (seconds). No installer rebuild.
- **Installer rebuild**: only for a kernel or firmware change, an installer bug or a key rotation. That is rare and gets its own ICE-Release version and ceremony.
- **Anti-rollback (D2).**
  - Today a registry medium seals the exact authorization and signature digests: the medium installs exactly one release.
  - A sealed floor alone would leave a replay window (review 234, P1): any older manifest signed by the release key above `min_bundle_seq` stays installable until the next installer rebuild. The Owner decided to close it with a **signed freshness object**:
    - `freshness.json`, schema `neural-ice-installer-freshness-v1`: `release_id`, `bundle_seq`, `manifest_sha256` (the sha256 of the exact `release-manifest.json` bytes), `issued_at`, `not_after`;
    - signed by the release key under its own domain, like the other contracts; verified with the same bounded-copy rules;
    - the gate requires the object to name the very manifest it accepted, and `issued_at <= trusted now <= not_after`;
    - **trusted now** comes from the existing trusted-time contract (`ni-ota-verify`, challenge and signed assertion from the compiled-in issuer), by network or by physical carrier. The RTC is never used. Without a trusted date the installer refuses (fail closed).
  - The residual replay window is therefore the validity of the freshness object, chosen at signing time. A revocation needs a new freshness object, not an installer rebuild; the sealed floor remains the long-term backstop.
  - A per-medium authorization bound to the target device (TPM EK hash) for customer deliveries was not decided. It is a release-blocking item before the first customer delivery (see below).
  - On an already provisioned appliance, the TPM counters and policy generation still refuse a downgrade, as today.
- **UKI size (D6)**: about 450 MiB is acceptable. The measured size of the full set is in "Step 2 evidence". The ESP is sized from the UKI, and the firmware must be able to load it: **to verify on the GB10 itself** (.72), QEMU does not prove it. Porting the python helpers to `ni-ota-verify` to shrink the UKI comes later.
- **Network in the initrd**: systemd-networkd plus the GB10 NIC driver, needed for the mirror and registry modes only.
- **Offline mode**: preload archives on the payload, same digest checks.
- **Lane 2 / ICE-Release**: the installer UKI is a versioned package (`installer-vN.efi`, signature, SBOM, provenance). Media assembly is a local step of the ceremony station, or a CI step for lab media. The payload is release data, not code.

## Prototype evidence (2026-10-06, branch `feat/generic-installer-mkosi-20261006`)

First step (before acceptance): stock el10 kernel, gate only; UKI 113 MiB; real train-3 payload accepted; a manifest with `bundle_seq` changed refused.

### Step 2 (2026-10-06, after acceptance): GB10 kernel, real install, first boot

Build host DGX Spark .77 (arm64, KVM), work directory `/var/tmp/ni-geninst-20261006`, mkosi 25.3 in a Fedora 42 container pinned by digest, host-side `ci/verify-build-context.sh`. QEMU: AAVMF without Secure Boot, swtpm TPM 2.0, 16 GiB RAM, 4 vCPU, a 64 GiB virtual target disk.

| Measure | Value |
|---|---|
| Kernel in the installer | `6.12.0-249.gb10.0.test.el10.aarch64`, from the staged generation `30439159936.1`, the same RPMs `image/Containerfile.bootc` installs |
| Firmware | `nvidia/580.159.03/gsp_ga10x.bin` and `gsp_tu10x.bin` (101 MiB tree), plus `nvidia.ko` of the same kernel, all in the initrd |
| **UKI size, full package set** | **311,242,240 bytes = 296.8 MiB** (initrd 296 MB zstd, 640 MB unpacked; kernel 14.9 MB). Under the 450 MiB budget (D6) |
| Package set | systemd, udev, podman, crun, skopeo, python3, openssl, jq, cryptsetup, tpm2-tools, dosfstools, e2fsprogs |
| Kernel provenance | after the build, the canonical `vmlinuz` of the UKI hashes to the generation's `vmlinuz_unsigned_sha256` `1b2aaddf…` (checked by `build-in-container.sh`) |
| Build, warm package cache | 41 s (UKI build only; the container tool install adds about 1 to 2 min). mkosi 25.3, systemd-ukify 257.13 (versions in the evidence file) |
| Medium assembly | 6.6 s for 2.0 GiB (host image 1.6 GiB included) |
| Gate, from kernel start | payload verified 3.9 s after kernel start |
| Unpack of the host image into RAM | 19 to 30 s; 1.63 GB packed, about 4.7 GiB unpacked in a 6.6 GiB tmpfs; 11 GiB still free |
| `bootc install to-disk` | 38 to 39 s; 2.9 GiB written on the target |
| Phase 1 total (boot, gate, unpack, install, power off) | 72 to 74 s |

Proofs (`qemu-install-proof.sh`, `qemu-proof.sh`):

- **Install**: release `v2-lab-train-3-20261005`, host `host-appliance@sha256:c3414495…`, the real signed train-3 manifest and the OCI layout cut from the LAN mirror store. `ni-generic: NI-GENERIC-PAYLOAD-OK` then `ni-generic-install: NI-GENERIC-INSTALL-OK`, then reboot.
- **Refusals, each scripted (`tamper-payload.sh`, `EXPECT_REFUSAL` in `qemu-install-proof.sh`), target disk asserted untouched (0 bytes allocated, all zeros)**:
  - manifest with `bundle_seq` changed: `REFUSED: the release manifest does not verify under the sealed release key`;
  - good payload, UKI sealing `min_bundle_seq=2`: `REFUSED: bundle_seq 1 below the sealed floor 2`;
  - UKI sealed `install_stage=production`: `REFUSED: this installer has no install gates yet`.
- Review 234 (Sonnet 5.5, high) of this step found one P2 (TOCTOU between verification and `skopeo copy`): fixed, the identity-bearing objects are now read once into RAM and used from there, and the unpacked image digest is checked. Evidence: `raw_mission_report_to_ingest/EVIDENCE-generic-installer-step2-20261006/`.
- **First boot of the installed disk**: GRUB entry `Neural ICE CoreOS (ostree:0)`, initrd, `ostree-prepare-root`, switch root, `Welcome to Neural ICE CoreOS!`. Then the host's own first-boot gate `neural-ice-firstboot-tpm-ceremony.service` fails (`NI-E02`) and the system stops in emergency mode. **This is expected and is not a multi-user boot**: the installer does not yet provision the TPM ceremony, the PCR policy kargs or the LUKS data volume. The host refuses to run without them. It is the first release-blocking item.

What the prototype install deliberately does not do (each is a release-blocking item above): freshness and trusted date, PCR 7 and TPM NV gates, LUKS and TPM enrolment, the closed policy reader, the bound images (`--bound-images=skip`), mirror and registry modes. The host image c3414495 carries `{"default":[{"type":"reject"}],"transports":{"docker":{}}}` as its `policy.json` (the installer logs it); it would fail the option-B policy reader. Secure Boot signing was not exercised: the UKI was not signed, and QEMU ran without Secure Boot.

Findings that shaped the installer (all reproduced in QEMU):

- `crun: pivot_root: Invalid argument`: the initramfs root cannot be pivoted; `containers.conf` sets `no_pivot_root = true`.
- `bootc ... Failed to enter install_t`: the installer loads no SELinux policy; the container gets `BOOTC_SETENFORCE0_FALLBACK=1`, the knob bootc names. The installed system is relabelled from the image's own policy.
- `systemd-networkd` does not exist as an el10 package; the network stack for the mirror and registry modes is to be chosen.
- The memory bound (3 x packed size + 2 GiB) is provisional: measured 4.7 GiB unpacked for 1.63 GB packed.

## Relation to ADR-0015

ADR-0015 stays in force for everything this installer keeps: the access-profile anchor, the closed-world cmdline rule, the TPM device-root and policy-generation amendments (K, M, N, O), the PCR 7 coverage gate and amendment E (freshness is a sequence, not the RTC), which D2 extends with a signed freshness object.

The other amendments of ADR-0015 carry over by intent, and are re-proved for the generic installer rather than assumed: C (single-purpose medium, one EFI authority: `assemble-media.sh` writes exactly ESP and payload), G (the medium identifies its own disk: by its `ni-payload` partition), H (one immutable image identity, resolved once: the RAM copy of the index and manifests, then the digest check after unpacking), I and K (TPM write-lock and owner ceremony) and L (the sealed core is inspected after the last write: to be redone for payload mode, see below).

It describes, and this ADR replaces, the host-derived chain: §1 (dm-verity installer root and the sealed `neuralice.rootverity` and `neuralice.payload` fields), amendment A (verity squashfs runtime) and amendment B (the install payload as one object with a sealed header). Those sections still describe the code of `build-installer-{root,payload,uki,usb}.sh`, which builds the media of the current lane until the generic installer replaces it. **They are removed from ADR-0015 in the same change that removes that chain**; deleting them earlier would leave shipping code without its decision record. That removal is a release-blocking item.

## Release-blocking items (no interim option is an end state)

| Item | Owner | Exit criterion |
|---|---|---|
| Wire the gates into the initrd: freshness and trusted date, PCR 7 coverage, TPM NV generation, LUKS and TPM enrolment, strict-policy restore | coding AI | the install unit no longer needs `neuralice.install_stage=prototype-ungated`; the field is removed |
| `pcr_policy` (`digest`, `seq`) in the Fabric release-manifest contract | coding AI, ICE-Fabric-v2 | the manifest schema and signer carry the field; the gate checks it |
| `freshness.json` signer in ICE-Release | coding AI, ICE-Release | the ceremony station signs and `assemble-media.sh` ships it |
| Per-medium EK binding for customer media | Owner decision | decided, or consciously dropped, before the first customer delivery |
| Remove ADR-0015 §1, A and B with the legacy chain | coding AI | the legacy chain is deleted and no reference remains |
| Installer inspection and payload inspection replace `inspect-installer-media.py` | coding AI | tests of both exist |
| Post-install inspection of the written target (ADR-0015 L), including that the deployed `policy.json` is the image's and not the lent one | coding AI | a check runs after `bootc` and before power off |
| Mirror and registry install modes, checked by the option-B policy; the network stack for them (`systemd-networkd` is not an el10 package) | coding AI | each mode has a QEMU proof |
| Behaviour of the el10 systemd-stub with an external command line, Secure Boot off | coding AI | tested in QEMU with load options, result written here |
| Target disk rule beyond "internal, non-USB, non-removable, exactly one": bind it to the measured hardware fingerprint | coding AI | the rule is in the gate and tested on the GB10 |
| UKI boots with Secure Boot (lab db, MOK) and on the GB10 | coding AI | qualification on .72 |

## Next steps

1. Gates in the initrd (the items above), mirror and registry modes.
2. QEMU qualification with Secure Boot (lab db) and swtpm.
3. ICE-Release package for the installer; `assemble-media` in the ceremony flow.
4. Cross-model security review. Then the first production medium on hardware.
