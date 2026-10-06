# ni-bench-snapshot — bench snapshot, reference record, signed bench sheet

Evidence side of the PCR 7 policy "at OEM scale" (mission 2026-10-06, task T2). The
bench boots **one gold unit per firmware family**, once from the installer medium and
once from the installed system, and keeps what the firmware measured into PCR 7. The
Owner signs a short **bench sheet** that pins the firmware and the expected PCR 7 of
each path. Python 3 standard library plus `openssl`; **no signing key is ever held
by this tool**.

```sh
T=tools/ni-bench-snapshot/ni-bench-snapshot.py
python3 -I $T capture --path installer --out installer.json          # on the unit, read-only
python3 -I $T capture --path installed --out installed.json          # (after the other boot)
python3 -I $T build-record --installer installer.json --installed installed.json --out record.json
python3 -I $T make-sheet   --record record.json --seq 1 --issued-at 2026-10-07 \
                           --pubkey owner.pub.pem --out sheet.json
python3 -I $T sheet-payload sheet.json --out payload.bin             # the Owner signs THIS
openssl dgst -sha256 -sign owner.key -out sheet.sig payload.bin      # on the Owner's machine
python3 -I $T store --record record.json --sheet sheet.json --signature sheet.sig \
                    --installer-snapshot installer.json --installed-snapshot installed.json \
                    --root <repo>/trust/<env>/pcr-reference --pubkey owner.pub.pem
python3 -I $T validate-store <repo>/trust/<env>/pcr-reference --pubkey owner.pub.pem \
                    --expected-pkfp <pkfp> --min-seq <family_id>=<last accepted seq>
```

`--expected-pkfp` pins the trusted key by value and `--min-seq` (repeatable) is the anti-rollback
floor: a family whose stored sheet is older than the last state the caller accepted, or that has
disappeared, is refused. The tree alone cannot know either; the caller (the T3 CI) supplies them
from the previously accepted state.

`capture` reads `/sys/firmware/efi/efivars`, `/sys/kernel/security/tpm0/binary_bios_measurements`,
`tpm2_pcrread sha256:7` and `/sys/class/dmi/id/bios_*` unless told otherwise.

## What is refused (exit 1, nothing written)

* **Incomplete snapshot**: any of `SecureBoot PK KEK db dbx` missing; Secure Boot off; empty
  `PK` or `SetupMode=1` (setup mode); no PCR 7 event; a PCR 7 value the event log does not
  replay to; no BIOS version/date; a variable filed under the wrong GUID (or the same variable
  listed twice, whatever the case of its GUID); unknown fields; a `PK/KEK/db/dbx/dbt/dbr` that is not
  a well-formed `EFI_SIGNATURE_LIST` run; a `db` authority certificate in the log that the stored
  `db` does not hold (variables and log would be two different boots).
* **Incomplete record**: a missing installer **or** installed path; paths captured on different
  firmware or with different `PK/KEK/db/dbx`; two snapshots of the same path; event digests
  that do not fold to the stated PCR 7; a `pcr7_reference` that does not rebuild them; an
  installer path that is not `uki-direct` (the installer medium is a UKI the firmware boots
  directly: a `shim-grub` installer path means the installed boot was captured twice); a
  `family_id` that is not a slug; authority events that disagree with their own reference.
* **Wrong key**: a sheet whose pinned `signer.pkfp` is not the trusted key, a signature that
  does not verify, a signature made over the bare JSON (the payload is domain-separated:
  `"ni-bench-sheet/1\n" + canonical JSON`), or a signed sheet that contradicts its record
  (firmware pin, expected PCR 7, record digest).
* **Store**: a `synthetic-test` path, a record that is **not what its stored snapshots build**
  (`build_record` is deterministic: `store` and `validate-store` rebuild it from the two snapshots
  and compare it byte for byte, so the Owner's signature over the record digest covers evidence
  that is actually there; `snapshot_sha256` alone bound nothing, the record wrote it itself),
  a replacement whose `seq` does not exceed the stored one, stray files, symlinks, a directory
  not named after the record's `family_id`.

## Layout

```
pcr-reference/<family_id>/reference-record.json     ni-pcr-reference-record/1
                          bench-sheet.json          ni-bench-sheet/1   (what the Owner signs)
                          bench-sheet.sig           raw RSA PKCS#1 v1.5 / SHA-256
                          snapshots/installer.snapshot.json   ni-bench-snapshot/1
                          snapshots/installed.snapshot.json
```

`family_id` is the lower-case BIOS version with non-alphanumerics folded to `-`
(`GX10DGX.0104.2026.0326.1657` → `gx10dgx-0104-2026-0326-1657`). The verifying key is passed
by the caller and its `pkfp` (sha256 of the RSAPublicKey DER, as systemd computes it) is
pinned inside the signed sheet; the store directory carries no key of its own.

## Coordination with `tools/ni-pcr7-calc` (T1)

Each path of the record carries `pcr7_reference`, exactly the `ni-pcr7-reference/1` document
`ni-pcr7-calc extract` produces from the same log (the tests assert equality with T1's
`extract_reference` and `compute(...) == pcr7` when T1's tool is present, via
`NI_PCR7_TOOL` or `tools/ni-pcr7-calc/`). `ni-pcr7-calc compute` therefore starts from a stored
record's path instead of a live machine. Without T1's tool on the tree, this tool still
re-folds the events and rebuilds the reference with its own small fold, and says so.

## Honest limits

* **`origin: measured` is the bench operator's attestation, not a proof.** `capture` labels
  whatever files it is given (`--efivars-b64`, `--eventlog`, `--pcr7`) as measured; no TPM quote
  binds them to a live boot. The `synthetic-test` gate stops a flagged fixture, not a relabelled
  one. What the tool does enforce is shape (installer path `uki-direct`, log replay, variables
  consistent with the log's db authority). The station-level attestation is the bench sheet of a
  later task (T11).
* `validate-record` checks structure and self-consistency only. The binding between a record and
  its evidence is made by `store` / `validate-store`, which hold the snapshots.
* `validate-store` is only as strong as the anchors it is given: without `--min-seq` it cannot
  see a rollback of a whole family directory to an older validly signed state, and without
  `--expected-pkfp` it trusts whichever key the caller hands it.
* The sheet is signed with the Owner key that also signs PCR policy digests. Domain separation
  (`ni-bench-sheet/1\n` prefix) keeps the two apart, but the design (§7, step 8) wants a key with
  no power over PCR 7; a dedicated key needs no change in this tool.
* A firmware that measures some variables with data and some without (an empty `dbx`, say) is
  refused as a whole; on the GB10 all five are zero-length, so this does not occur there.
* When the firmware measures variable **contents**, this tool does not yet compare each logged
  config event with the stored variable (only the `db` authority certificate is cross-checked).

* GB10 firmware measures `SecureBoot/PK/KEK/db/dbx` as **names only** (zero-length data); the record
  stores `variable_measurement: names-only` and the blob digests as provenance. A dbx/db
  update therefore does not move PCR 7 on that firmware; the authority events do.
* `setup_mode` is **derived** (`setup_mode_origin: derived`) when the firmware does not expose
  `SetupMode`, from the facts that entail it (`SecureBoot=1`, `PK` enrolled). The .67 evidence
  was collected without that variable. A bench capture reads it and records `captured`.
* No installer-path event log of a physical unit exists yet. The test fixture of that path is a
  `synthetic-test` one and **the store refuses it**; the committed fixture is the real
  *installed*-path snapshot of a GX10 (`fixtures/ni67/installed.snapshot.json`).
* The fixtures hold PCR 7 events and public Secure Boot variables only: no serial number, no
  EK, no hostname, no boot option or device path (`capture` keeps an allow-list of variables
  and the PCR 7 slice of the log).

Tests: `python3 -I tools/ni-bench-snapshot/test-ni-bench-snapshot.py`.
