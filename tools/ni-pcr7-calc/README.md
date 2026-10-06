# ni-pcr7-calc — offline PCR 7 calculator

Computes the TPM PCR 7 (sha256 bank) a GB10 boot produces **without the machine**,
from a reference description, and is tested against two real event logs. Python 3
standard library only. The TCG2 parser and the PCR replay are the ones the installer
ships (`ota/neural-ice-tpm-policy.py`), imported, not copied: the tool runs from a
checkout of this repository, not as a standalone file.

```sh
T=tools/ni-pcr7-calc/ni-pcr7-calc.py
python3 -I $T replay   LOG [--expect HEX | --live] [--explain]   # PCR 7 from a TCG2 event log (without --expect: prints, compares nothing, exit 0)
python3 -I $T extract  LOG [--out ref.json]                      # reference description from a log
python3 -I $T compute  ref.json [--explain] [--policy-digest]    # PCR 7 from a description
python3 -I $T verify   LOG --expect HEX | --live                 # replay == compute(extract) == live (the second equality is an encoding round-trip)
python3 -I $T filter-log LOG --out small.bin [--pcr 7]           # keep one PCR's events (redaction)
```

On a machine: `sudo cat /sys/kernel/security/tpm0/binary_bios_measurements > log` and
`sudo tpm2_pcrread sha256:7` (read-only), then `verify log --expect <hex>` on any
machine that has a checkout of this repository. `--live` runs `tpm2_pcrread` found
through `PATH`: do not use it with an inherited or untrusted `PATH` (e.g. under
`sudo` keeping the caller's `PATH`); prefer `--expect` with a value you read yourself.

## What `replay` and `verify` bind, and what they do not

* `replay`, `verify` and `extract` require the logged sha256 digest of every PCR 7
  event to be `sha256(event data)`. Hence every data byte of a PCR 7 event is covered
  by the replayed value, and `replay LOG --expect HEX` refuses a log whose event data
  was altered (a flipped data bit used to pass; it no longer does).
* The event **type** and the **PCR index** are not part of any digest, so `replay`
  does not bind the type: a log with a changed PCR 7 event type replays to the same
  value. `verify` and `extract` additionally refuse any type the model does not know
  (config, separator, authority). A changed PCR index changes the replayed value.
  A consumer that reads certificates or SBAT text from a log should take them from a
  log that passed `verify`, not from `replay` alone.
* The TCG2 header is checked for the `Spec ID Event03` record (EV_NO_ACTION, zero
  digest, spec major 2, a consistent algorithm list). `platformClass`, the minor
  version, errata, `uintnSize` and vendor-info bytes are not checked; they enter no
  digest and no PCR value.
* Only the sha256 bank is replayed and checked; other banks in the log are ignored.
* `verify`'s second equality (`compute(extract(log))`) is an encoding round-trip, not
  an independent prediction.

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

**Observed** on the two GB10 logs in `fixtures/` (NVIDIA DGX Spark firmware
`5.36_0ACUM018`, ASUS GX10 firmware `GX10DGX.0104`): the `SecureBoot`, `PK`, `KEK`, `db`
and `dbx` events carry a **zero-length variable data** (events of 52, 36, 38, 36 and 38
bytes: the names only), and their digests are identical on both machines. The
fixtures do not contain the efivars, so that the variables themselves differ between
the two machines is reported by the mission, not checked here.

**Deduced, not measured** (no variable was ever updated and the PCR 7 compared
before/after): since the logged data is empty, nothing about the variables' contents
enters PCR 7 on that firmware, so a `dbx` append, a `KEK` rotation or a `PK` swap
should not move it; what does is the authority chain (which db certificate verified
shim, shim's `SbatLevel`, the vendor/MOK certificate). `variable_measurement:
"contents"` (TCG PC Client, EDK2) is implemented but **not proven on any GB10**; use
`compute --variable-measurement contents` only as a what-if. The tests of the
`names-only` model (`compute` ignoring `data_hex`) pin the model; they are not
observations.

### Limitation: PCR 7 equality does not attest the variables' contents

On such a firmware `replayed PCR 7 == live PCR 7` is **independent of** the value of
`SecureBoot` (always one byte), of whether a `PK` is enrolled (setup/user mode), and of
the contents of `db` and `dbx`. It therefore cannot be used as evidence that Secure
Boot is on, that the platform is out of setup mode, that `db` is a subset of an allowed
set or that `dbx` contains a given revocation: a design that recomputes PCR 7 from
efivars and compares it with the live value (design option B) does not get those
properties from that equality on this firmware. A `db`/`dbx` alteration is visible only
insofar as it changes which certificate verified shim, or shim's `SbatLevel`.
Revocation and rollback of `dbx` ("Restore Factory Keys") are likewise not visible in
PCR 7 when the same shim yields the same authority events. The tool prints a note to
stderr (`replay`, `verify`, `compute`) whenever the log or reference is names-only.

Not tested on hardware (open questions, not findings): whether a state with Secure
Boot disabled can be told apart from an enabled one by PCR 7 alone, and whether
pre-boot EFI code could extend the authority events itself. No fixture contains a
Secure Boot-disabled boot (no authority events).

## Installer medium (`uki-direct`)

No GB10 event log of the installer medium exists in the fixtures. Given the `db`
authority entry of the installed system's log (the lab certificate **and its
`SignatureOwner` GUID**, which comes from the log and cannot be derived from the
certificate), the calculator reproduces the first 8 and last 7 hex digits of the PCR 7
and of the PolicyPCR digest recorded for a GX10 booting the installer USB on 2026-09-04
(`07bd0bb2…eedd1db`, `b83b5281…217937`). Only those digits were recorded, so this is
indirect support for the `uki-direct` shape (about 60 bits per value), not a byte-exact
check and not a prediction from a certificate alone. Capture the installer's own event
log (`verify`) to make it byte-exact.

## What this does not establish

* **Prediction by series.** The only cross-machine test takes the authority events
  (including `SignatureOwner` GUIDs and the SBAT text, which depends on shim's policy
  state) from the log of the machine being predicted. It shows the config events are
  identical on the two logs and the encoding is lossless; it does not show that PCR 7
  can be predicted from certificates, or is stable across units of one series (two
  machines, two firmwares; no two units of the same firmware).
* **Other machines.** `extract` refuses an authority event before the separator (an
  option ROM, e.g. a ConnectX-7), so those machines are not covered. The DGX Spark
  `.63` (stock Ubuntu) is verified by the `Microsoft UEFI CA 2011`, which expired on
  2026-06-27: moving to the 2023 CA will move its PCR 7. A GX10 `.77` exposes no TPM and
  could not be validated.
* **`extract` classification.** A log is `names-only` when every config variable has
  empty data and `contents` when all have data; a mix is refused. A `contents` firmware
  whose variables were all empty could not be told from `names-only` (in practice
  `SecureBoot` is always one byte, so a `SecureBoot` entry with empty data settles it);
  a legitimately empty `dbx` on a `contents` firmware is refused as a mix (fail closed).
* **Reference JSON.** Duplicate keys and unknown keys are refused; a field left out
  takes its documented default (`separator_hex` = `00000000`).

## Tests and fixtures

`python3 -I tools/ni-pcr7-calc/test-ni-pcr7-calc.py`. The fixtures are PCR-7-only
derivatives (`filter-log`) of the event logs of two physical machines, with the live
PCR 7 read at the same boot (`fixtures/expected.json`): the TCG2 header and the PCR 7
events only — public certificates and variable names, no boot options, device paths or
command lines. The installer-medium path (`uki-direct`) has **no hardware fixture yet**.
