# shim-review questionnaire — Neural ICE draft answers

Working draft of the `rhboot/shim-review` README template (as of 2026-07).
`[TODO: …]` marks items that need a human/legal input or the final build.
Copy into the fork's `README.md` once every TODO is resolved.

---

### What organization or people are asking to have this signed?

Organization name and website:
**TKRI** (SARL, France), operating under the product brand **Neural ICE** —
website: <https://neural-ice.ch>

### What's the legal data that proves the organization's genuineness?

Company/tax register entries or equivalent:
French commercial register (RCS) entry:
<https://annuaire-entreprises.data.gouv.fr/entreprise/tkri-789990298>
(TKRI, SIREN 789 990 298, registered 2012, Paris, France)

The public details of both your organization and the issuer in the EV
certificate used for signing .cab files at Microsoft Hardware Dev Center:
```
Issuer: C=US, ST=Texas, L=Houston, O=SSL Corp, CN=SSL.com EV Code Signing Intermediate CA ECC R2
Subject: C=FR, ST=Île-de-France, L=Paris, O=TKRI, serialNumber=789990298, CN=TKRI, businessCategory=Private Organization, jurisdictionL=Paris, jurisdictionST=Île-de-France, jurisdictionC=FR
```

(EV Code Signing certificate serial `1EBE4EFD89D56D6DEAB0508C9930468F`, valid
2026-07-14 → 2027-07-14; the private key was generated on-device in a YubiKey
5 FIPS PIV slot and attested at issuance — see the key-protection answer
below.)

### What product or service is this for?

Neural ICE CoreOS: the operating-system layer of the Neural ICE appliance, a
sovereign on-premise AI inference appliance for Swiss and European enterprises,
built on NVIDIA DGX Spark (GB10, aarch64) hardware. It is an image-based
(bootc/ostree) OS derived from CentOS Stream 10, published as open core at
<https://github.com/Neural-ICE/ICE-CoreOS>.

### What's the justification that this really does need to be signed for the whole world to be able to boot it?

The appliance ships to customer premises with Secure Boot enabled as a
non-negotiable security requirement, and installation/updates must be
zero-touch (no human at the console, no per-unit key enrollment). The DGX
Spark firmware trusts the Microsoft UEFI CAs. Our kernel is self-compiled
(NVIDIA GB10/Grace-Blackwell enablement from Red Hat's `nvidia-gb10` tree, not
yet available in any distribution kernel), so no existing distro-signed shim
covers our chain. A Microsoft-signed shim embedding our CA is the only path
that boots on factory Secure Boot on every unit without physical presence.

### Why are you unable to reuse shim from another distro that is already signed?

Signed distro shims (Ubuntu, Fedora/CentOS, …) embed that distro's CA and
therefore only verify binaries signed by that distro. Our kernel and GRUB2 are
built and signed by us (custom GB10 kernel; the CentOS Stream shim is signed
by the CentOS Secure Boot CA, which the DGX Spark firmware does not trust
anyway). MOK enrollment through another distro's shim requires physical
presence per unit, which violates the appliance's zero-touch requirement.

### Who is the primary contact for security updates, etc.?

- Name: `[TODO]`
- Position: `[TODO]`
- Email address: `[TODO: monitored role or personal address]`
- PGP key fingerprint: `[TODO]`
- File/keyserver location: keyserver.ubuntu.com + `<name>.asc` in this repo

### Who is the secondary contact for security updates, etc.?

- Name: `[TODO: second distinct person — required]`
- Position: `[TODO]`
- Email address: `[TODO]`
- PGP key fingerprint: `[TODO]`
- File/keyserver location: keyserver.ubuntu.com + `<name>.asc` in this repo

### Were these binaries created from the 16.1 shim release tar?

Yes. The Dockerfile downloads
`https://github.com/rhboot/shim/releases/download/16.1/shim-16.1.tar.bz2`,
verifies SHA256
`46319cd228d8f2c06c744241c0f342412329a7c630436fce7f82cf6936b1d603` before
extraction, and we verified the detached PGP signature against Peter Jones's
key (`B00B48BC731AA8840FED9FB0EED266B70F4FEF10`).

### URL for a repo that contains the exact code which was built to result in your binary:

`https://github.com/Neural-ICE/shim-review` (tag
`neuralice-shim-aarch64-[TODO: YYYYMMDD]`) — contains the Dockerfile, the
vendor SBAT csv and the vendor certificate; the shim source itself is the
unmodified 16.1 release tarball fetched and checksum-verified at build time.

### What patches are being applied and why:

None. Vanilla shim 16.1; the only build inputs are `VENDOR_CERT_FILE`
(our CA in DER) and an appended vendor SBAT entry (`data/sbat.neuralice.csv`).

### Do you have the NX bit set in your shim? If so, is your entire boot stack NX-compatible and what testing have you done to ensure such compatibility?

No, the NX bit is not set (confirmed on the final build: `post-process-pe`
reports "NX Compatibility flag is not set" for shim, MokManager and fallback).
Our boot stack (GRUB2 from CentOS Stream 10, kernel 6.12 aarch64) follows
current Fedora/CentOS practice, which has not yet declared full NX
compatibility.

### What exact implementation of Secure Boot in GRUB2 do you have?

Downstream RHEL/Fedora-like implementation: our GRUB2 is a rebuild of the
CentOS Stream 10 `grub2` source package (which carries the Red Hat downstream
Secure Boot/lockdown verifier patch set), with our vendor SBAT entry appended
and signed by our CA. `[TODO: exact NVR, e.g. grub2-2.12-XX.el10]`

### Do you have fixes for all the following GRUB2 CVEs applied?

Yes — inherited from the CentOS Stream 10 `grub2` package, which contains the
fixes for all listed CVEs through the February 2025 set (upstream SBAT
generation 5). `[TODO: verify the NVR's changelog covers the Feb 2025 batch
before finalizing.]`

### If shim is loading GRUB2 bootloader, and if these fixes have been applied, is the upstream global SBAT generation in your GRUB2 binary set to 5?

Yes: `grub,5,Free Software Foundation,grub,2.12,https://www.gnu.org/software/grub/`
(see full SBAT listing below). `[TODO: paste from final binary.]`

### Were old shims hashes provided to Microsoft for verification and to be added to future DBX updates? Does your new chain of trust disallow booting old GRUB2 builds affected by the CVEs?

This is our first application; we have no previously signed shim. Our CA is
new, so no older GRUB2 build was ever signed by it.

### If your boot chain of trust includes a Linux kernel: are upstream commits 1957a85b / 75b0cea7 / eadb2f47 applied?

Yes to all three. Our kernel is 6.12-based (el10, Red Hat `nvidia-gb10` tree);
these commits are upstream since v5.4, v5.8 and v5.19 respectively and are
present in the 6.12 source.

### How does your signed kernel enforce lockdown when your system runs with Secure Boot enabled?

The kernel carries the RHEL downstream mechanism that enables integrity-mode
lockdown automatically when booted with Secure Boot enabled. Verified on the
target hardware (DGX Spark, SB on): `/sys/kernel/security/lockdown` reports
`none [integrity] confidentiality`. Unsigned module loading is denied by
module signature enforcement under lockdown.

### Do you build your signed kernel with additional local patches? What do they do?

The kernel is built from Red Hat's public `nvidia-gb10` tree
(<https://gitlab.com/redhat/edge/kernel/nvidia-gb10>), i.e. a RHEL-10 6.12
kernel plus NVIDIA GB10 (Grace-Blackwell) hardware-enablement patches. We add
no patches of our own on top, and nothing touches Secure Boot, lockdown or
module-signing behavior.

### Do you use an ephemeral key for signing kernel modules?

Yes. The module signing key (`certs/signing_key.pem`) is generated during the
kernel build; the NVIDIA open GPU kernel modules (out-of-tree, r595) are
signed with that same key **within the same pipeline run**, after which the
private key is destroyed. Each kernel build therefore only loads modules from
its own build. `[TODO: this is the committed design — confirm the pipeline
change (destroy-after-kmod-signing) is merged before submitting.]`

### If you use vendor_db functionality of providing multiple certificates and/or hashes please briefly describe your certificate setup.

Not used. A single CA certificate is embedded via `VENDOR_CERT_FILE`; no
vendor_db, no allow-listed hashes.

### If you are re-using the CA certificate from your last shim binary…

First application, new CA certificate.

### Is the Dockerfile in your repository the recipe for reproducing the building of your shim binary?

Yes. `docker build .` (or `podman build`) reproduces the exact binaries: the
base image is tag-pinned (`debian:12.11`), the toolchain is Debian 12's
`gcc-aarch64-linux-gnu`, and the shim tarball is checksum-verified. The final
layer prints the SHA256 of the produced binaries.

### Which files in this repo are the logs for your build?

`build.log` (full `make` output, including the toolchain/package setup visible
in the Dockerfile build output) and `SHA256SUMS`.

### What changes were made in the distro's secure boot chain since your SHIM was last signed?

First application — N/A.

### What is the SHA256 hash of your final shim binary?

```
d55327f1810150de037910878c1c8f6d43db9057f4591d25e4bcede38ac9e46c  shimaa64.efi
d03b4a4319daf5d3eb30d6e7b498ba2641a7f4bf48ec805692242aacfcd22f76  mmaa64.efi
f7ffbfca88d49f9043ef98405b9dce9047d2e507a5640358eaeade2668c16bfa  fbaa64.efi
```

(shim 16.1, vendor CA sha256 `44d0de0c…7803` embedded; two independent
`--no-cache` container builds produced byte-identical binaries.)

### How do you manage and protect the keys used in your shim?

Two-tier PKI under a documented ceremony
(<https://github.com/Neural-ICE/ICE-CoreOS/blob/main/secureboot/key-ceremony.md>):

- The **CA private key** was generated on an air-gapped machine and exists
  only as passphrase-encrypted backups stored in a physical safe under dual
  control (no single person holds both the media and the passphrase). It is
  used only to issue leaf signing certificates.
- The **leaf signing key** (signs GRUB2 and the kernel) is generated on-device
  in a YubiKey 5 FIPS (FIPS 140-2 overall Level 2, physical Level 3) PIV slot,
  is non-exportable, and requires PIN + touch to operate.
- The **EV key** used for Microsoft Hardware Dev Center submissions is likewise
  held on FIPS 140-2 L2 hardware per CA/Browser Forum requirements.

### Do you use EV certificates as embedded certificates in the shim?

No (the embedded certificate is our own CA; the EV certificate is used only
for the Microsoft submission process).

### Are you embedding a CA certificate in your shim?

Yes, and it carries `X509v3 Basic Constraints: critical, CA:TRUE`
(plus `keyUsage: critical, keyCertSign, cRLSign, digitalSignature`).

### Do you add a vendor-specific SBAT entry to the SBAT section in each binary that supports SBAT metadata? Please provide the exact SBAT entries for all binaries you are booting directly through shim.

Yes. Shim (`objcopy --only-section .sbat -O binary shimaa64.efi /dev/stdout`):
```
sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
shim,4,UEFI shim,shim,1,https://github.com/rhboot/shim
shim.neuralice,1,Neural ICE,shim,16.1,https://github.com/Neural-ICE/shim-review
```

GRUB2 (upstream + Red Hat downstream entries preserved, ours appended):
```
sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
grub,5,Free Software Foundation,grub,2.12,https://www.gnu.org/software/grub/
grub.rh,4,Red Hat,grub2,[TODO: NVR],mailto:secalert@redhat.com
grub.neuralice,1,Neural ICE,grub2,[TODO: our NVR],https://github.com/Neural-ICE/shim-review
```
The shim entries above are the **real dump from the final binary**
(`shimaa64.efi` sha256 `d55327f1…e46c`, build 2026-07-16).
`[TODO: the GRUB2 entries are the intended layout — paste the real dump once
the c10s grub2 rebuild exists, with its exact NVR.]`

No other binaries are booted through shim (no fwupd EFI binary is shipped).

### If shim is loading GRUB2 bootloader, which modules are built into your signed GRUB2 image?

`[TODO: paste the grub2-mkimage module list from the c10s grub2 rebuild
(the distro spec's module set; do not add net/legacy modules beyond it).]`

### If you are using systemd-boot on arm64 or riscv, is the fix for unverified Devicetree Blob loading included?

N/A — we use GRUB2.

### What is the origin and full version number of your bootloader (GRUB2 or systemd-boot or other)?

GRUB2, rebuilt from the CentOS Stream 10 source package
`[TODO: exact NVR, e.g. grub2-2.12-XX.el10 + our rebuild suffix]`.

### If your shim launches any other components apart from your bootloader, please provide further details on what is launched.

None. Shim launches GRUB2 only (plus its own MokManager/fallback companions
built from the same 16.1 tree).

### If your GRUB2 or systemd-boot launches any other binaries that are not the Linux kernel in SecureBoot mode, please provide further details on what is launched and how it enforces Secureboot lockdown.

None. GRUB2 loads only our signed Linux kernel (BLS entries generated by
bootc; no chainloading, no multiboot targets).

### How do the launched components prevent execution of unauthenticated code?

Shim verifies GRUB2 against the embedded Neural ICE CA; the downstream-patched
GRUB2 verifies the kernel signature through shim's verification protocol and
refuses unsigned kernels under Secure Boot; the kernel boots in
lockdown-integrity and only loads modules signed by its build key. All
user-space updates are delivered as signed bootc (ostree) images; the boot
binaries are replaced only by signed counterparts.

### Does your shim load any loaders that support loading unsigned kernels (e.g. certain GRUB2 configurations)?

No. The RHEL-downstream GRUB2 enforces kernel signature verification whenever
Secure Boot is active, and we ship no configuration that bypasses it.

### What kernel are you using? Which patches and configuration does it include to enforce Secure Boot?

Kernel 6.12 (el10) from Red Hat's public `nvidia-gb10` tree, standard 4k-page
aarch64 flavor, RHEL configuration: `CONFIG_SECURITY_LOCKDOWN_LSM(_EARLY)=y`,
module signature enforcement, and the RHEL mechanism enabling
lockdown-integrity under Secure Boot (verified on hardware). NVIDIA GB10
enablement patches only; no Secure Boot-related modifications.

### What contributions have you made to help us review the applications of other applicants?

`[TODO: start reviewing issues labeled "easy to review" NOW and list them
here — this is the main lever on our own review latency.]`

### Add any additional information you think we may need to validate this shim signing application.

Target hardware is the NVIDIA DGX Spark (GB10). Its firmware db ships both
`Microsoft Corporation UEFI CA 2011` and `Microsoft UEFI CA 2023` (verified on
hardware), so the 2023-signed aarch64 shim boots without enrollment. The OS is
an open-core CentOS Stream 10 bootc derivative; the full boot-chain build is
public at <https://github.com/Neural-ICE/ICE-CoreOS>.
