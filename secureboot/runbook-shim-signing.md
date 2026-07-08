# Runbook — getting the Neural ICE shim signed by Microsoft

Companion to [ADR-0002](../docs/ADR-0002-secure-boot-zero-touch.md). Phases 1–2
can run in parallel; phase 3 depends on both. Expect **~2–4 months** end to end,
dominated by the volunteer shim-review queue (2–3 months typical — contributing
reviews to other applicants is the documented way to shorten it).

---

## 1. Administrative prerequisites (P0 — start immediately, longest lead items)

### 1.1 Legal entity

shim-review verifies the organization's genuineness ("company/tax register
entries or equivalent"), and EV certificates are only issued to registered
legal entities.

The operating entity is a French EURL (single-member SARL) — a fully valid
legal entity for this process.

- [x] Public register link for the questionnaire (state-run entry):
  <https://annuaire-entreprises.data.gouv.fr/entreprise/tkri-789990298>
  (**TKRI**, SIREN 789 990 298 — brand: Neural ICE). shim-review only needs a
  verifiable link — do **not** post the Kbis PDF in the public issue (it
  carries the manager's personal details).
- [ ] Keep a **Kbis extract < 3 months** at hand for the EV CA's org
  validation (free for the gérant via <https://monidenum.fr>).
- [ ] The **Organization (O=)** name must be **`TKRI`** (dénomination sociale)
  across: the EV certificate, the Partner Center account, and the certificates
  generated in the key ceremony. "Neural ICE" stays the product/brand name —
  the questionnaire's organization field takes the legal name, with the brand
  mentioned alongside.

### 1.2 EV code-signing certificate

Required by Microsoft for **UEFI firmware signing** submissions (it signs the
`.cab` you upload to Partner Center — it is *not* the certificate embedded in
shim). CA/Browser Forum rules require the EV private key on certified hardware:
the **YubiKey 5C NFC FIPS** (FIPS 140-2 overall L2, physical L3) qualifies.

- [ ] Pick a CA that can issue **onto a customer-provided YubiKey** via PIV
  attestation (SSL.com documents this flow; DigiCert/Sectigo/GlobalSign
  typically ship their own token or cloud HSM — also acceptable, then the
  YubiKey is free for the Secure Boot keys).
- [ ] Complete EV org validation (uses the commercial register entry;
  typically 3–10 business days).
- [ ] Record Issuer/Subject of the EV cert — the questionnaire asks for both.

### 1.3 Microsoft Partner Center (Windows Hardware Developer Program)

- [ ] Create a Microsoft Entra ID tenant for the org (if none).
- [ ] Register at <https://partner.microsoft.com/dashboard/registration/hardware>
  (identity verification is done with the EV certificate).
- [ ] Review the current [Microsoft UEFI signing requirements](https://techcommunity.microsoft.com/blog/hardware-dev-center/updated-microsoft-uefi-signing-requirements/1062916)
  — notably: signing keys protected on **≥ FIPS 140-2 L2** hardware, backed up
  and recoverable only by trusted-role personnel under dual control.
- Note: passing shim-review **exempts from the yearly independent security
  audit** as long as shim only hands off to open-source bootloaders (our case:
  GRUB2).

### 1.4 Security contacts (two people, PGP-verified)

Reviewers send each contact a PGP-encrypted mail with random words; you must
post the decrypted contents in the issue.

- [ ] Designate a **primary and a secondary** security contact (two distinct
  humans — for a small team this may require naming a co-founder/advisor).
- [ ] Each generates a PGP key, uploads it to `keyserver.ubuntu.com`, and the
  `.asc` files are committed to the shim-review fork.
- [ ] Both mailboxes must be monitored long-term (CVE coordination duty).

---

## 2. Technical preparation

### 2.1 Key ceremony

Follow [key-ceremony.md](key-ceremony.md). Outputs:

- `neural-ice-uefi-ca.der` — the CA certificate embedded in shim
  (`VENDOR_CERT_FILE`), X509v3 Basic Constraints **critical, CA:TRUE**.
- A **leaf signing certificate** (EKU codeSigning) whose private key lives in a
  YubiKey FIPS PIV slot — used by the pipeline to sign GRUB2 and the kernel.
- Encrypted CA-key backups under dual control in a safe.

### 2.2 Reproducible shim build

Follow [shim/README.md](shim/README.md). Outputs: `shimaa64.efi`, `build.log`,
SHA256 — all committed to the shim-review fork. `docker build .` must reproduce
the exact binary (reviewers re-run it; a non-reproducible binary is rejected).

### 2.3 Boot-chain conformance (reviewed even though only shim gets signed)

- [ ] **GRUB2**: rebuild the **CentOS Stream 10 `grub2` SRPM** (carries all
  BootHole→2025 CVE fixes, upstream SBAT generation 5), **append** the
  `grub.neuralice` SBAT entry (never replace distro/upstream entries), sign
  `grubaa64.efi` with the Neural ICE leaf key. Record the exact NVR and the
  built-in module list (`grub2-mkimage` invocation) for the questionnaire.
- [ ] **Kernel**: 6.12 el10 (`nvidia-gb10` tree) already includes the three
  lockdown commits the questionnaire asks about (upstream since v5.4/v5.8/v5.19)
  and enforces `lockdown=integrity` under Secure Boot (verified on hardware).
  Sign `vmlinuz` with the Neural ICE leaf key (`sbsign`).
- [ ] **Module signing — make the build key ephemeral.** Current flow keeps
  `certs/signing_key.pem` around to sign the NVIDIA kmods after the kernel
  build. Reviewers explicitly ask about this: sign the NVIDIA modules **in the
  same pipeline run** that builds the kernel, then **destroy the private key**.
  One kernel build must not be able to load modules from another.
- [ ] **No unsigned-kernel path**: the signed GRUB2 must have the downstream
  RHEL-style verification (no `--unrestricted` chainload, no config that boots
  unsigned kernels while SB is on).

---

## 3. shim-review submission

1. Fork <https://github.com/rhboot/shim-review> under the Neural-ICE org.
2. Populate it: completed `README.md` (from
   [shim-review-answers.draft.md](shim-review-answers.draft.md)),
   `shimaa64.efi`, `neural-ice-uefi-ca.der`, the `Dockerfile` + SBAT csv from
   [shim/](shim/), `build.log`, security contacts' `.asc` keys.
3. Tag: `neuralice-shim-aarch64-YYYYMMDD`, push.
4. File the issue using the repo's `ISSUE_TEMPLATE.md` (checklist + tag link +
   shim SHA256).
5. **In parallel, review other applications** — start with issues labeled
   [`easy to review`](https://github.com/rhboot/shim-review/issues?q=is%3Aopen+is%3Aissue+label%3A%22easy+to+review%22).
   This is the single most effective lever on our own queue time.
6. Respond to reviewer feedback; on contact verification, post the decrypted
   random words.
7. Done when the **`accepted`** label lands.

## 4. Microsoft signing (after `accepted`)

1. Package `shimaa64.efi` in a `.cab`, sign it with the **EV certificate**
   (Windows `signtool`, or `osslsigncode` + the YubiKey via PKCS#11 on Linux).
2. Submit in Partner Center (submission type **UEFI**).
3. You receive the shim back signed with **both** the 2011 and 2023 keys (two
   copies). GB10 firmware trusts both; ship the **2023**-signed copy (aarch64
   convention), archive both.
4. Verify: `sbverify --list shimaa64.efi` shows the Microsoft signature;
   `objcopy --dump-section .sbat=/dev/stdout` shows our SBAT entries.

## 5. Integration & rollout

- [ ] Replace the interim lab-key boot set with: MS-signed shim + Neural
  ICE-signed GRUB2/kernel in `image/signed-boot/` staging.
- [ ] **TPM PCR 7 changes** when the boot certificates change → the LUKS
  auto-unlock binding must be re-enrolled (idempotent service per ADR-0004);
  plan the migration for the already-deployed unit before switching it.
- [ ] Remove the lab certificate from firmware `db` on lab units once the
  MS-signed chain is validated (it is a root of trust bypass while present).
- [ ] Archive: signed shims, CA/leaf certs, build logs, shim-review issue URL
  (needed as "previous request" reference for every future re-submission).

## When a re-submission is needed (for later)

New shim-review round required if: shim version bump (security), CA rotation,
or revocation of previously signed components (their hashes then go to
`vendor_dbx`). Kernel/GRUB updates signed by the **same** leaf/CA do **not**
require re-review — that is the whole point of embedding a CA.
