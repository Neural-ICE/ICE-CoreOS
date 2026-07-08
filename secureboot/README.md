# Secure Boot — Microsoft-signed shim preparation

Implementation package for [ADR-0002](../docs/ADR-0002-secure-boot-zero-touch.md)
(zero-touch Secure Boot, Option A): getting a **Neural ICE shim signed by the
Microsoft UEFI CA** so the appliance boots out of the box on factory Secure Boot
(Microsoft / RHEL / Ubuntu trust model), with the rest of the chain signed by
the Neural ICE key.

## Target chain of trust

```
DGX Spark firmware (db: Microsoft UEFI CA 2023 + Microsoft Corporation UEFI CA 2011)
  └─ shimaa64.efi          — shim 16.1, MS-signed, embeds the Neural ICE UEFI CA (vendor_cert)
       └─ grubaa64.efi     — GRUB2 (CentOS Stream 10 rebuild + Neural ICE SBAT), Neural ICE-signed
            └─ vmlinuz     — GB10 kernel 6.12 (4k), Neural ICE-signed, lockdown=integrity
                 └─ *.ko   — incl. NVIDIA open r595, signed with the kernel build key
```

Facts verified on GB10 hardware (2026-07-08):

- Firmware `db` contains **Microsoft UEFI CA 2023** and **Microsoft Corporation
  UEFI CA 2011** → an MS-signed shim boots with no enrollment. aarch64 shims are
  signed with the **2023** key (no aarch64 history on the 2011 CA), and the 2023
  CA is present, so this works.
- Kernel lockdown is enforced (`integrity`) under Secure Boot on the running
  6.12 el10 kernel.

## Contents

| File | Purpose |
|---|---|
| [runbook-shim-signing.md](runbook-shim-signing.md) | End-to-end runbook: admin prerequisites, key ceremony, build, shim-review submission, Microsoft signing, integration |
| [key-ceremony.md](key-ceremony.md) | Key generation ceremony (YubiKey 5 FIPS): Neural ICE UEFI CA + leaf signing cert + EV cert slots |
| [shim-review-answers.draft.md](shim-review-answers.draft.md) | Pre-filled draft of the official shim-review questionnaire (`rhboot/shim-review` README template) |
| [shim/](shim/) | Reproducible shim 16.1 aarch64 build: `Dockerfile`, vendor SBAT entry, build wrapper |

## Status

- [ ] P0 admin prerequisites (legal entity, EV certificate, Microsoft Partner Center, 2 security contacts + PGP) — see runbook §1
- [ ] Key ceremony executed (CA + leaf on YubiKey FIPS, backups in safe)
- [ ] Reproducible shim build produced (`shim/`) with final SHA256
- [ ] GRUB2 rebuild with appended Neural ICE SBAT (separate pipeline work)
- [ ] Ephemeral kernel-module signing key in the kernel/kmod pipeline (reviewers probe this)
- [ ] Fork of `rhboot/shim-review` populated + tagged `neuralice-shim-aarch64-YYYYMMDD`
- [ ] Issue filed; peer reviews contributed in parallel
- [ ] Microsoft Partner Center UEFI submission after `accepted` label
- [ ] Signed shim integrated in image; TPM PCR 7 re-enrollment path validated (ADR-0004)
