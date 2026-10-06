# ni-pcr-rules — Owner-signed PCR 7 rules, evaluated on a state PCR 7 vouches for

Replaces "one signature per admitted PCR 7 value" with "one signature on rules".
Python 3 standard library and the `openssl` binary. The TCG2 parser and the PCR
replay are the installer's (`ota/neural-ice-tpm-policy.py`), imported, not copied.

```sh
T=tools/ni-pcr-rules/ni-pcr-rules.py
python3 -I $T sign     --rules R.json --key owner.key.pem --out R.json.sig        # Owner, offline
python3 -I $T verify   --rules R.json --signature R.json.sig --pubkey owner.pub.pem --min-sequence N
python3 -I $T evaluate --rules R.json --signature R.json.sig --pubkey owner.pub.pem --min-sequence N \
       [--eventlog LOG] [--efivars DIR] (--pcr7 HEX | --live)                    # exit 0 accept, 1 refuse
python3 -I $T ids      [--eventlog LOG] [--efivars DIR]                           # ids to write rules from
```

`evaluate` prints a JSON verdict: every check, `ok`, and whether it is `attested`
(bound to PCR 7) or only `observed`. `--min-sequence` is mandatory: it is the
sealed anti-rollback anchor (the NV generation counter in the installed design).
`--pubkey-sha256` pins the Owner key (SPKI DER digest); `--expect-rules-sha256`
binds the exact bytes a release manifest names.

## Rules (`ni-pcr-rules/1`)

```json
{ "schema": "ni-pcr-rules/1", "sequence": 7, "unbound_variables": "allow",
  "approved_certs": ["x509:<sha256 of the DER>"],           // C: db ⊆ C
  "dbx_floor":      ["sha256:<image hash>"],                // F: dbx ⊇ F
  "authorities":    [ {"name": "db",        "ids": ["x509:<sha256 of the DER>"]},
                      {"name": "SbatLevel", "ids": ["text-sha256:<sha256 of the text>"]},
                      {"name": "MokListRT", "ids": ["x509:<sha256 of the DER>"]} ] }  // A
```

Strict: unknown fields, duplicate keys, empty sets, malformed ids and a missing
`unbound_variables` are refused. Always enforced (not configurable, so a rules file
cannot weaken them): SecureBoot on with at least one db authority event, PK present,
not in setup/audit mode.

The signature covers `neural-ice-pcr-rules/v1\0 || RULES` (the exact bytes): a
signature the same key made for a PolicyPCR digest or a manifest authorises nothing
here. Nothing is parsed before the signature verifies, and `load_rules` takes bytes
so a caller evaluates the bytes it verified.

## 🔴 "Variables cannot lie" — what is and is not true on a GB10

The gate is `replay(event log) == live PCR 7`, plus `sha256(event data) == logged
digest` for every PCR 7 event. A variable the log carries *with its bytes* must equal
the EFI variable. **The GB10 firmware does not carry them**: on the real log of a
GX10 (`GX10DGX.0104`) the `SecureBoot`, `PK`, `KEK`, `db` and `dbx` events have
zero-length data, so PCR 7 binds their *names*, not their contents, and the same
holds on the NVIDIA 5.36 firmware (see `tools/ni-pcr7-calc`). On that firmware:

* `db ⊆ C`, `dbx ⊇ F`, PK present, SecureBoot value are **observed** (read from
  efivars), not attested. A root attacker able to alter efivars could lie to them.
* The **authority chain** is attested: the certificates that verified shim, SBAT
  level and the vendor/MOK certificate are logged with their bytes. `authorities ∈ A`
  and "the db certificate that verified the boot is in `db`" are attested.
* `unbound_variables: "refuse"` makes the engine refuse such firmware outright;
  `"allow"` accepts it and the verdict says `binding: names-only`. Which to ship is an
  Owner decision (see the T4 report), not an engineering one.

## Tests

`python3 -I tools/ni-pcr-rules/test-ni-pcr-rules.py` (42 tests). Fixtures are public
data from one physical GB10: the PCR-7-only event log (byte-identical to the `ni67`
fixture of `tools/ni-pcr7-calc`), its Secure Boot variables, its live PCR 7. The
signing key is generated per run. Firmware that measures variable contents is
exercised with a synthetic log (none was captured on a GB10).
