# ADR-0002 — Zero-touch Secure Boot (Neural ICE shim signed by Microsoft)

- **Status**: Accepted (Option A) — implementation **in progress** (see
  [`secureboot/`](../secureboot/); external dependency ~2–4 months)
- **Date**: 2026-06-28
- **Decider**: Business/Security Owner (human)
- **Guiding principle**: *installation must happen WITHOUT human action.*

> **Amendment (2026-07-01, [[ADR-0006-kernel-4k-page-size]])**: the shipped kernel
> is now the **standard 4k-page flavor** of the same `nvidia-gb10` tree, not
> `kernel-64k`. This ADR is otherwise **unchanged**: the kernel is still
> self-compiled → still self-signed, and the Microsoft `shim-review` plan below
> still applies verbatim (page size does not affect signing). Read every
> "kernel-64k" below as "the GB10 kernel (4k)".

## Context

The Neural ICE CoreOS appliance ships an **in-house compiled kernel** (`kernel-64k`
GB10). On the production DGX Spark, **Secure Boot is enabled and cannot be
disabled** (sovereign posture + customer constraint).

Facts verified on the GB10 test hardware and on the media:

| Link | Signed by | Trusted by the DGX Spark firmware? |
|---|---|---|
| `BOOTAA64.EFI` (CentOS Stream shim) | **CentOS Secure Boot CA 8** | ❌ no |
| `grubaa64.efi` | CentOS Secure Boot CA 8 | ❌ (trusted by the shim only) |
| `vmlinuz` (kernel-64k) | **"Red Hat Test Certificate"** (throwaway build key) | ❌ trusted by no one |

The firmware **trusts the Microsoft UEFI CA** (the factory Ubuntu boots via
an MS-signed shim + MOK) **but not the CentOS Stream CA**. Hence the immediate
rejection (`Secure Boot Violation — Invalid signature detected`), at the **firmware**
level, on `BOOTAA64.EFI`.

Structuring constraint: **Secure Boot requires physical presence** to enroll
a key (anti-malware, by design). An appliance cannot enroll its own key
in User Mode without NVIDIA/Microsoft's private KEK key. So "100% software
self-enrollment without presence" is **impossible**.

## Decision — Option A: Neural ICE shim signed by Microsoft

This is the Ubuntu/RHEL/Fedora model, and **the only zero-human-action-PER-INSTALL
path**:

1. The firmware already trusts the **Microsoft CA** → a **Neural ICE shim
   signed by Microsoft** boots **without any enrollment**.
2. This shim **embeds the Neural ICE certificate** (`vendor_cert`) that validates the rest.
3. We **sign with the Neural ICE key**: grub (or a **UKI**), the **kernel-64k**, and
   the **NVIDIA modules** (otherwise refused by the kernel under SB lockdown).
4. Result: `firmware (MS CA) → Neural ICE shim (MS-signed) → kernel (Neural ICE key)`
   → **zero enrollment, Secure Boot ON, OTA OK** (future kernels signed by the
   same key pass without any re-enrollment).

One-time at the **product** level (not per customer), permanent, reusable for all
units and all OTA updates.

## Rejected alternatives

- **Option B — enrolling the Neural ICE keys at provisioning**: zero *customer*
  action, but Neural ICE touches the firmware of **every unit** → that is not
  "zero human action". Kept only as a **fallback** (ultra-sensitive customers
  requiring a 100% sovereign root of trust without the Microsoft CA).
- **Disable Secure Boot**: unacceptable (security posture).
- **MOK via the existing shim**: since the CentOS shim is not trusted by the firmware, we
  never reach MokManager; and MOK remains a manual action.

## `shim-review` process (Microsoft signature)

Public submission on **`github.com/rhboot/shim-review`** (issue + questionnaire).

**Legal/operational prerequisites** (legal entity, EV certificate, Microsoft
Partner Center account, security contacts): see the
[runbook](../secureboot/runbook-shim-signing.md).

**TECHNICAL prerequisites** (implementation package: [`secureboot/`](../secureboot/)):
- [ ] **shim 16.1** from the official tarball, **reproducible build** (`Dockerfile`,
      pinned toolchain → `docker build .` regenerates the exact binary).
- [ ] Neural ICE certificate (CA) in **DER**, embedded as `vendor_cert`.
- [ ] Neural ICE **SBAT** entry (append, do not replace the upstream ones).
- [ ] If GRUB2: up-to-date **CVE** patches (21 CVEs listed Feb 2025) + SBAT generation = 5.
      *(A **UKI/systemd-boot** greatly lightens this part → prefer the UKI.)*
- [ ] **Kernel** with **lockdown** enforcement under Secure Boot (upstream commits).
- [ ] Build logs, SHA256 of the binary, description of the patches.

**MS signature**: after the `accepted` label, the shim is sent to Microsoft and signed
with the **2011 + 2023** keys → we receive **2 signed copies**.

**Bonus**: passing the review **exempts from annual audits** if the shim only loads
**open-source** bootloaders (our case).

## Timeline

- Volunteer review: **~2–3 months**. + MS signature: days/weeks. **Total ~2–4 months.**
- **Cannot gate the HW validation.** The submission is launched **in parallel** as soon as
  the business prerequisites are ready.

## Signing the NVIDIA modules

Under a kernel in SB lockdown, the `.ko` modules must be signed by a key in the
kernel keyring. We sign the open r595 modules with the **kernel build's module
signing key** (`certs/signing_key.pem`, already present in the build tree and whose
public key is embedded in the kernel) — **no kernel rebuild required**.

## Interim — HW validation (decoupled from the product)

On **the test unit only**, lab enrollment (`Security → Secure Boot →
Expert Key Management → db`) of a test key + re-signing the kernel/shim, to validate
**kernel-64k boot + GPU init + network + OTA**. A lab action, **not** the
product flow; it does not contradict the zero-touch principle (carried by Option A in prod).

## Consequences

- (+) **Zero-action** customer install, Secure Boot ON, OTA-compatible.
- (+) **100% Neural ICE** signing root (the key stays yours; MS only signs the shim).
- (−) External dependency **2–4 months** + business/legal prerequisites (private).
- (−) Enriched build pipeline (UKI + shim/kernel/module signing + SBAT).

## References

- Implementation package: [`secureboot/`](../secureboot/) (runbook, key ceremony,
  reproducible shim build, questionnaire draft)
- shim-review: <https://github.com/rhboot/shim-review> · `docs/submitting.md`
- SBAT: <https://github.com/rhboot/shim/blob/main/SBAT.md>
- DGX Spark UEFI — Security Tab: <https://docs.nvidia.com/dgx/dgx-spark-uefi/security-tab.html>
