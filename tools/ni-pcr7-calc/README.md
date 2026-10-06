# ni-pcr7-calc — offline PCR 7 calculator

Computes the TPM PCR 7 (sha256 bank) a GB10 boot produces **without the machine**,
from a reference description, and proves itself against a real event log. Python 3
standard library only. The TCG2 parser and the PCR replay are the ones the installer
ships (`ota/neural-ice-tpm-policy.py`), imported, not copied.

```sh
T=tools/ni-pcr7-calc/ni-pcr7-calc.py
python3 -I $T replay   LOG [--expect HEX | --live] [--explain]   # PCR 7 from a TCG2 event log
python3 -I $T extract  LOG [--out ref.json]                      # reference description from a log
python3 -I $T compute  ref.json [--explain] [--policy-digest]    # PCR 7 from a description
python3 -I $T verify   LOG --expect HEX | --live                 # replay == compute(extract) == live
python3 -I $T filter-log LOG --out small.bin [--pcr 7]           # keep one PCR's events (redaction)
```

On a machine: `sudo cat /sys/kernel/security/tpm0/binary_bios_measurements > log` and
`sudo tpm2_pcrread sha256:7` (read-only), then `verify log --expect <hex>` anywhere.

## The reference description (`ni-pcr7-reference/1`)

```json
{ "schema": "ni-pcr7-reference/1", "bank": "sha256",
  "firmware": { "variable_measurement": "names-only" },
  "variables": { "SecureBoot": {}, "PK": {}, "KEK": {}, "db": {}, "dbx": {} },
  "separator_hex": "00000000",
  "boot_path": "shim-grub",
  "authorities": [
    { "name": "db", "signature_owner": "<guid>", "cert_der_hex": "…" },
    { "name": "SbatLevel", "text": "sbat,1,2024040900\nshim,4\n…" },
    { "name": "MokListRT", "signature_owner": "<shim-lock guid>", "cert_der_hex": "…" } ] }
```

* `variables` — order is log order. In `contents` mode each needs `data_hex` (the
  variable bytes: an `EFI_SIGNATURE_LIST` for PK/KEK/db/dbx, one byte for `SecureBoot`).
* `boot_path` — `shim-grub` (installed system: the db certificate that verified shim,
  `SbatLevel`, the vendor/MOK certificate that verified GRUB and the kernel),
  `uki-direct` (installer medium: the single db certificate that verified the signed
  UKI) or `custom`. The two named paths are shape-checked.

## 🔴 What the GB10 firmware actually measures

On the two GB10 logs in `fixtures/` (NVIDIA DGX Spark firmware `5.36_0ACUM018`, ASUS
GX10 firmware `GX10DGX.0104`) the `SecureBoot`, `PK`, `KEK`, `db` and `dbx` events carry a
**zero-length variable data**: the firmware measures their *names*, not their
contents. Their digests are identical on both machines although the variables differ.
So on that firmware **PK/KEK/db/dbx updates do not move PCR 7**; what moves it is the
authority chain (which db certificate verified shim, shim's `SbatLevel`, the vendor
certificate) and the Secure Boot on/off state through the presence of authority events.
`variable_measurement: "contents"` (TCG PC Client, EDK2) is implemented but **not
proven on any GB10**; use `compute --variable-measurement contents` only as a what-if.

## Installer medium (`uki-direct`)

No GB10 event log of the installer medium exists in the fixtures. The calculator
nevertheless reproduces, from the lab db certificate alone, the first 8 and last 7 hex
digits of the PCR 7 and the PolicyPCR digest recorded for a GX10 booting the installer
USB on 2026-09-04 (`07bd0bb2…eedd1db`, `b83b5281…217937`). That is a strong
indirect confirmation, not a byte-exact one: only those digits were recorded. Capture the
installer's own event log (`verify`) to make it byte-exact.

## Tests and fixtures

`python3 -I tools/ni-pcr7-calc/test-ni-pcr7-calc.py`. The fixtures are PCR-7-only
derivatives (`filter-log`) of the event logs of two physical machines, with the live
PCR 7 read at the same boot (`fixtures/expected.json`): the TCG2 header and the PCR 7
events only — public certificates and variable names, no boot options, device paths or
command lines. The installer-medium path (`uki-direct`) has **no hardware fixture yet**.
