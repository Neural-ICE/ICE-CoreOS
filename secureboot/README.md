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
| [disaster-recovery.md](disaster-recovery.md) | What breaks if each key/host is lost or compromised, and the recovery playbook for each |
| [shim-review-answers.draft.md](shim-review-answers.draft.md) | Pre-filled draft of the official shim-review questionnaire (`rhboot/shim-review` README template) |
| [shim/](shim/) | Reproducible shim 16.1 aarch64 build: `Dockerfile`, vendor SBAT entry, build wrapper |

## Status

- [x] Legal entity verified + **EV code signing certificate** issued
      (2026-07-14, key attested in a YubiKey 5 FIPS) — runbook §1.1–1.2
- [x] **Microsoft Partner Center** hardware account registered, EV certificate
      validated `Active` (2026-07-16) — runbook §1.3
- [ ] **Two security contacts + PGP keys** published — runbook §1.4 (last open
      admin item)
- [x] **Key ceremony executed** (2026-07-16): offline CA
      `Neural ICE UEFI Secure Boot CA 2026` (sha256 `44d0de0c…7803`, valid to
      2046) + leaf in YubiKey PIV 9c; encrypted backups verified by restore test
- [x] **Reproducible shim build** with the production CA: two `--no-cache`
      builds byte-identical, `shimaa64.efi` sha256 `d55327f1…e46c` (2026-07-16)
- [ ] GRUB2 rebuild with appended Neural ICE SBAT (separate pipeline work)
- [ ] Ephemeral kernel-module signing key in the kernel/kmod pipeline (reviewers probe this)
- [ ] Fork of `rhboot/shim-review` populated + tagged `neuralice-shim-aarch64-YYYYMMDD`
- [ ] Issue filed; peer reviews contributed in parallel
- [ ] Microsoft Partner Center UEFI submission after `accepted` label
- [ ] Signed shim integrated in image; TPM PCR 7 re-enrollment path validated (ADR-0004)
