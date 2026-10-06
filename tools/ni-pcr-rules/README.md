# ni-pcr-rules — Owner-signed PCR 7 rules, evaluated on the machine's Secure Boot state

Replaces "one signature per admitted PCR 7 value" with "one signature on rules".
Python 3 standard library and the `openssl` binary. The TCG2 parser and the PCR
replay are the installer's (`ota/neural-ice-tpm-policy.py`), imported, not copied.

```sh
T=tools/ni-pcr-rules/ni-pcr-rules.py
python3 -I $T sign     --rules R.json --key owner.key.pem --out R.json.sig        # Owner, offline
python3 -I $T verify   --rules R.json --signature R.json.sig --pubkey owner.pub.pem --min-sequence N --pubkey-sha256 PIN
python3 -I $T evaluate --rules R.json --signature R.json.sig --pubkey owner.pub.pem --min-sequence N \
       --pubkey-sha256 PIN \
       [--eventlog LOG] [--efivars DIR] (--pcr7 HEX | --live)                    # exit 0 accept, 1 refuse
python3 -I $T ids      [--eventlog LOG] [--efivars DIR]                           # ids to write rules from
```

`evaluate` prints a JSON verdict: every check, `ok`, and whether it is `attested`
(bound to PCR 7) or only `observed`; the top-level `observed` lists the latter. Both
anchors are mandatory: `--min-sequence` (>= 1; the sealed anti-rollback anchor, the NV
generation counter in the installed design) and `--pubkey-sha256` (the SPKI DER digest
of the Owner key). `--expect-rules-sha256` binds the exact bytes a release manifest names.

**Contract of the installer (T5), not enforced by this tool:** call `evaluate` with
`--live` (`--pcr7` is a test seam: the gate is only as strong as the value the caller
passes), on the real efivarfs mount (statfs magic `0xde5e81e4`; `--efivars` accepts any
directory), with the pin and the sequence floor taken from sealed state, and **decide on
`binding` and `observed`, never on `accepted` alone**: `accepted: true` with `binding:
"names-only"` means PK, KEK, db, dbx and SecureBoot were only observed.

## Rules (`ni-pcr-rules/1`)

```json
{ "schema": "ni-pcr-rules/1", "sequence": 7, "unbound_variables": "allow",
  "approved_certs": ["x509:<sha256 of the DER>"],           // C: db ⊆ C
  "approved_pk":    ["x509:<sha256 of the DER>"],           // PK ⊆ this, non-empty
  "approved_kek":   ["x509:<sha256 of the DER>"],           // KEK ⊆ this, non-empty
  "dbx_floor":      ["sha256:<image hash>"],                // F: dbx ⊇ F
  "authorities":    [ {"name": "db",        "ids": ["x509:<sha256 of the DER>"]},
                      {"name": "SbatLevel", "ids": ["text-sha256:<sha256 of the text>"]},
                      {"name": "MokListRT", "ids": ["x509:<sha256 of the DER>"]} ] }  // A
```

Strict: unknown fields, duplicate keys, empty sets, malformed ids and a missing
`unbound_variables`, `approved_pk` or `approved_kek` are refused. Always enforced (not
configurable, so a rules file cannot weaken them): SecureBoot on with at least one db
authority event (under the Secure Boot database GUID), PK present and one of
`approved_pk`, KEK non-empty and within `approved_kek`, `SetupMode` present and 0,
`AuditMode` 0 when present (some firmware has none). Each authority event must carry its
vendor GUID (`db`: the security database GUID; `SbatLevel`, `MokListRT`: shim's).

The signature covers `neural-ice-pcr-rules/v1\0 || RULES` (the exact bytes): a
signature the same key made for a PolicyPCR digest or a manifest authorises nothing
here. Nothing is parsed before the signature verifies, and `load_rules` takes bytes
so a caller evaluates the bytes it verified.

## What PCR 7 proves on a GB10, and what it does not

The gate is `replay(event log) == live PCR 7`, plus `sha256(event data) == logged
digest` for every PCR 7 event: the event log is the one PCR 7 saw. That is all it
proves. **PCR 7 does not vouch for the contents of the Secure Boot variables on a GB10**:
on the real log of a GX10 (`GX10DGX.0104`) the `SecureBoot`, `PK`, `KEK`, `db` and `dbx`
events have zero-length data, so PCR 7 binds their *names*, not their contents; the same
holds on the NVIDIA 5.36 firmware (see `tools/ni-pcr7-calc`, PR #245). A variable the log
carries *with its bytes* (firmware that measures contents) must equal the EFI variable
and is then `attested`; any other (zero-length data included) is only `observed`. So on
a GB10:

* `db ⊆ C`, `dbx ⊇ F`, `PK ⊆ approved_pk`, `KEK ⊆ approved_kek`, the SecureBoot value
  and SetupMode/AuditMode are **observed** (read from efivars), not attested.
* The **authority chain** is attested: the certificates that verified shim, SBAT level
  and the vendor/MOK certificate are logged with their bytes. `authorities ∈ A` and
  "the db certificate that verified the boot is in `db`" are attested.
* `unbound_variables: "refuse"` makes the engine refuse such firmware outright;
  `"allow"` accepts it and the verdict says `binding: names-only`. Which to ship is an
  Owner decision, not an engineering one.

## Threat model of the directly read EFI variables

The observed variables are trusted for four reasons, none of them the TPM:

1. **The reader is trusted code.** The installer is a signed UKI booted under enforced
   Secure Boot: what reads the variables is the code the measured boot path verified.
2. **Writing them needs a key.** `PK`, `KEK`, `db` and `dbx` are authenticated
   variables: an update from the OS must be signed by the PK (for `PK`, `KEK`) or a KEK
   (for `db`, `dbx`). `SecureBoot`, `SetupMode`, `AuditMode` are read-only to the OS by
   the UEFI specification. A software attacker without those keys cannot change them.
3. **Setup and audit mode are refused.** Clearing the PK from the firmware menus would
   put the machine in setup mode, where anyone can enrol a PK: the engine refuses
   `SetupMode=1`, a missing `SetupMode`, `AuditMode=1` and a PK outside `approved_pk`.
4. **The firmware setup is behind the per-device UEFI administrator password** (Owner
   decision Q4). That the password really protects *Restore Factory Keys* and the key
   management menus on a GB10 has not been established on this hardware.

Because the PK is a signer of KEK updates and a KEK a signer of `db`/`dbx` updates,
PK and KEK are pinned by the rules (`approved_pk`, `approved_kek`): an attacker PK or
KEK that passes `db ⊆ C` and `dbx ⊇ F` is refused.

| Attack | Outcome |
|---|---|
| Software root at runtime writing the variables | detected: needs a PK/KEK signature; setup/audit mode and a foreign PK/KEK are refused |
| Setup mode, then an attacker PK/KEK with a conforming `db`/`dbx` | detected: PK/KEK outside the approved sets (observed binding, see 1-4) |
| *Restore Factory Keys*, or an old `dbx`, after the installation | agent after unlock: PCR 7 does not see `dbx` on a GB10 (ADR-0045 D4); only an agent that re-runs the engine **after the unlock** can see it |
| Holder of a factory KEK (ASUS, Microsoft) adding to `db`/`dbx` | agent after unlock: `KEK ⊆ approved_kek` does not see a KEK holder's later write; `db ⊆ C` sees it only when it is re-run |
| Physical write of the SPI flash (firmware or variables replaced) | out of scope: not detected |
| Firmware bug (authenticated-write bypass, SMM) | out of scope: not detected |
| Efficacy of the UEFI administrator password against *Restore Factory Keys* on a GB10 | out of scope: not established, assumed |

`DeployedMode` is not checked. The GB10 values of `SetupMode`, `AuditMode` and
`DeployedMode` have not been captured yet (the fixture predates them; the tests complete it
with synthetic values for a deployed machine, labelled in `World`): a physical capture is a
prerequisite of T5, because the engine refuses a machine without `SetupMode`.

## Tests

`python3 -I tools/ni-pcr-rules/test-ni-pcr-rules.py` (88 tests). Fixtures are public
data from one physical GB10: the PCR-7-only event log (byte-identical to the `ni67`
fixture of `tools/ni-pcr7-calc`), its Secure Boot variables, its live PCR 7. The
signing key is generated per run. Firmware that measures variable contents is
exercised with a synthetic log (none was captured on a GB10). `x509-tbs-sha256` ids
ignore `ToBeSignedTime`. The same `sequence` with other content is accepted by the
anti-rollback floor: the release manifest's `--expect-rules-sha256` is what pins the bytes.
