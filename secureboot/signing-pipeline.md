# Secure Boot — production signing pipeline

How every bootable artifact is signed in the **production** chain, who trusts
whom, and what has to run at build time. Companion to
[key-ceremony.md](key-ceremony.md) and [runbook-shim-signing.md](runbook-shim-signing.md).

## The chain of trust

```
DGX Spark firmware  — trusts →  Microsoft UEFI CA (2011 + 2023), factory-provisioned
        │ verifies the Authenticode signature of
        ▼
   shimaa64.efi      — signed ONCE by Microsoft (after shim-review); embeds the
        │              Neural ICE UEFI CA as VENDOR_CERT
        │ verifies against the embedded CA
        ▼
   grubaa64.efi      — signed by the Neural ICE LEAF (cert chains to the CA)
        │ verifies via shim's protocol
        ▼
   vmlinuz           — signed by the Neural ICE LEAF (cert chains to the CA)
        │ kernel boots with lockdown=integrity; loads only signed modules
        ▼
   *.ko modules      — signed by the kernel build's EPHEMERAL module key,
                       whose public half is built into the kernel
```

Two distinct trust mechanisms are at work, and they must not be confused:

- **EFI Secure Boot** (firmware → shim → grub → vmlinuz): Authenticode PE
  signatures. shim verifies each stage against the **CA it embeds**. Every EFI
  binary below shim is signed by the **leaf** (whose cert chains to that CA).
- **Kernel module signing** (vmlinuz → *.ko): a *separate* PKCS#7 signature
  appended to each `.ko`, verified by the kernel against keys in its keyrings —
  **not** the EFI/leaf key. This is what `lockdown=integrity` enforces.

## What signs what

| Artifact | Signed with | Verified by | When |
|---|---|---|---|
| shim | Microsoft UEFI CA | firmware | once, after shim-review |
| grubaa64.efi | **leaf** (YubiKey 9c) | shim (against the embedded CA) | each grub build |
| vmlinuz | **leaf** (YubiKey 9c) | shim/grub protocol | each kernel build |
| in-tree `.ko` | kernel **ephemeral** key | the kernel itself | during the kernel build |
| NVIDIA out-of-tree `.ko` | the **same** ephemeral key | the kernel itself | in the same kernel `rpmbuild` (built in-tree) |

## Module signing — the ephemeral key (the correct design)

A RHEL-derived kernel build generates a **fresh random module-signing key per
build** (`certs/signing_key.pem`, produced from `x509.genkey`), signs the
in-tree modules with it, and builds its **public half into the kernel**
(`.builtin_trusted_keys`). The private half is meant to be discarded with the
build.

The rule that makes this secure: **a given kernel only trusts the key from its
own build.** Modules signed for kernel A cannot load into kernel B — the keys
differ. This is stronger than relying on `vermagic` alone.

For that to hold, the **out-of-tree NVIDIA modules must be signed with the same
per-build key**. That key is generated *inside* the kernel's `rpmbuild` and
discarded when the build tree is torn down — there is no reliable window to grab
it afterwards. So instead of capturing the key, the NVIDIA modules are built
**inside the same `rpmbuild`** and signed by the kernel spec itself, with no key
ever touching our own scripts:

1. A patch to the RHEL kernel `kernel.spec.template`
   (`build/patches/nvidia-open-inline-sign.patch`) adds the NVIDIA open source
   as a spec `Source`, builds the modules in `%build` against the freshly built
   kernel tree, and stages the unsigned `.ko` under
   `/lib/modules/<kver>/extra/nvidia-open/`.
2. The kernel's own `__modsign_install_post` step then signs **every** `.ko`
   under the module tree — in-tree and NVIDIA alike — with the build's ephemeral
   key, as its last install action.
3. The private half is never handled by us and is discarded with the build tree.
   The NVIDIA `.ko` ship in a `kernel-modules-nvidia-open` subpackage.

This is verifiable on the built RPMs: the NVIDIA `.ko` and the in-tree `.ko`
report the **same** `modinfo -F signer` (the per-build key), and no
`signing_key.pem` remains on disk. Because that key's public half is the one
built into the kernel (`.builtin_trusted_keys`), the modules load under
`lockdown=integrity` with **nothing** enrolled in the firmware `db`.

> **Anti-pattern to avoid (was the lab setup):** signing the NVIDIA modules with
> a *persistent* key (e.g. a fixed `lab.key`) that is reused across builds. Then
> one build's modules can load into another kernel, and the private key must be
> guarded forever. The ephemeral in-build approach removes both problems.

## EFI signing — leaf via the YubiKey

`grubaa64.efi` and `vmlinuz` are signed with the leaf key held in the YubiKey
PIV **slot 9c**. Because slot 9c is the PIV "Digital Signature" slot, it carries
`CKA_ALWAYS_AUTHENTICATE` (a PIN before *every* signature), which the usual EFI
signers (`sbsign`, `osslsigncode`) cannot drive — they hang. The working tool is
**`jsign`** (`--storetype YUBIKEY`), which handles the context-specific PIN and
the touch. Verify every result with `sbverify --cert <ca>.crt <binary>`.

One prerequisite for `vmlinuz`/`grubaa64.efi` produced by an RHEL build: strip
the build's placeholder Certificate Table before signing (the RHEL build reserves
it for the CentOS HSM signature, which our rebuild does not have) — otherwise the
signer rejects the malformed PE.

> **Automation note:** slot 9c's per-signature PIN blocks unattended CI signing.
> For an automated pipeline, re-issue the leaf into a slot **without**
> always-authenticate (PIV **9d**, Key Management), so `sbsign --engine pkcs11`
> can run headless with a cached PIN + touch. That re-issue needs a short
> offline-CA session. Until then, EFI signing is a deliberate manual step.

## Current state vs production (2026-07)

| Link | Production target | Current build reality |
|---|---|---|
| shim | MS-signed | reproducible, awaiting shim-review |
| grub | leaf-signed | ✅ leaf-signed + `sbverify` OK |
| modules | ephemeral key | ✅ NVIDIA + in-tree `.ko` signed by the per-build ephemeral key (same `modinfo -F signer`; no persistent key) |
| vmlinuz | leaf-signed | ⚠️ built test-cert-signed; test sig stripped, staged for the manual leaf-sign |

Only `vmlinuz` remains: the kernel build emits it signed with the RHEL **test**
certificate, so a post-build step strips that signature and re-signs it with the
leaf (the one manual YubiKey action). Once that lands, the boot chain is
production and the shim-review answers about kernel/module signing are literally
true.
