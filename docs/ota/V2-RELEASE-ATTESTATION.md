# V2 release attestation — contract (mission B, T0)

Status: **contract, frozen for T1/T2/T3a/T3b**. Nothing here is implemented except
the golden vectors, the fail-closed library stub and their tests. Change this file
and the vectors in one PR; a consumer that needs a byte that is not here is a
contract change, not a local decision.

Background: an owner-sealed **v2** host (built `FROM` this OS) inherits the image
marker `owner-sealed-ota-state-v1` and the installer refuses it without
`neuralice.preseal` (`ota/neural-ice-autoinstall.sh`, `require_medium_source_profile`).
A preseal set needs the v1 OTA authority, which a v2 host forbids by design. The v2
lane therefore authenticates the TPM floor with the **v2 release manifest and its
detached signature** instead, and keeps every TPM protection. Design and rationale:
`DESIGN-B-v2-owner-sealed-install-20261006` (§1–§4, §6); this file is the normative
extract the workers build on.

## 1. The lane, the marker and the two meanings of "profile"

| Name | What it designates | Value on a v2 host |
|---|---|---|
| **image marker** `/usr/lib/neural-ice/ota-state-profile` | the **attestation lane** | `owner-sealed-ota-state-v2` (closed set: `legacy-unmarked`, `owner-sealed-ota-state-v1`, `owner-sealed-ota-state-v2`) |
| `ota_state.profile` in `inspect-v2` / evidence | the **profile of the TPM objects** (floor `0x01500001`, anchor `0x01500002`) | `owner-sealed-ota-state-v1` — unchanged, the objects are identical |
| `profile` in `authenticated-ota-status` | what the licence gate and model-fetch compare | `owner-sealed-ota-state-v1` — **unchanged** (§8) |

The marker is 26 bytes (`owner-sealed-ota-state-v2\n`), `0444 root`. Compatibility,
enforced by the installer (T3b) and the reader (T1; the cmdline keys are §11): marker v2 **requires** the v2
seal and **forbids** `neuralice.preseal`; marker v1 **forbids** the v2 seal;
`legacy-unmarked` + the v2 seal is refused (no silent downgrade). Completion version
stays **2**; the digest `sha256("neural-ice:tpm:owner-ceremony-completion:v2\0" ‖ evidence)`
is unchanged.

## 2. Authenticating object and verification rules

Object: `release-manifest.json` + `release-manifest.json.sig`, schema
`neural-ice-release-manifest-v1`. The signature is a **detached, base64-encoded
ASN.1-DER ECDSA-P256-SHA256 signature over the exact bytes of the manifest** — no
envelope, no domain prefix, no canonicalisation (as `v2-manifest-sign.py` without
`--domain`). A trailing LF is part of the bytes. The signature file carries no
trailing LF (see "Signature file bytes" below for what enforces that).

**High-S is accepted.** The verifier applies no low-S and no minimal-DER pre-filter:
a KMS produces either form of an ECDSA-P256 signature, the golden signature is
high-S, and `cosign verify-blob` accepts both. Rejecting high-S would refuse
genuine KMS output. (The ceremony-bound signature of the access-profile anchor is a
different object that does canonicalise to low-S; this rule is not about it.)

Verification mechanism: the pinned `cosign verify-blob --key … --insecure-ignore-tlog=true`
through `runner::verify_blob`, exactly as `delegated::verify_signature` and
`preseal.rs` already do. **Not** an in-process `p256::ecdsa` verification: the
crate is pulled with `default-features = false, features = ["arithmetic"]`, the
`ecdsa` crate is absent from `Cargo.lock`, and adding it would be a new dependency
(this corrects DESIGN-B §0.3 "aucune nouvelle dépendance"). `sha2` is already a
dependency and is used in-process for every digest of this verb.

**Single read of every input.** `--release-key`, `--manifest` and `--manifest-sig` are
each opened once, without following a symlink, and must be a regular file of at most
their bound (key 4 KiB, manifest 1 MiB, signature 1 KiB; none empty). Each is copied
into a private file (`0600`, in a private directory created for the call) **at the
moment it is first needed** and only that copy is used afterwards: it is hashed
(rules 3-4), verified by `cosign` by path (rule 5) and parsed (rules 6-8). The
source path is never read a second time, so a file rewritten between the in-process
hash and cosign's own read cannot be substituted. The size bound is enforced at
acquisition, **before** cosign ever runs, and is not a parsing rule. A file that is
absent, not regular, a symlink, over its bound, or not stable during the copy
refuses with the class of the digest rule that covers it: `key-digest` (key),
`manifest-digest` (manifest), `sig-digest` (signature), in either seal mode. The
candidate root (rules 13-15) is read the same way: each file once, bounded,
no-follow, never executed. A shell caller (T3b) already works this way
(`esp_staged_file`: copy, then hash the copy) and must hand the verifier the private
copies, never the ESP path.

**Malformed flag values refuse, they are not usage errors.** Exit 2 is for the shape
of the command line (unknown, repeated, valueless or missing flag) and for tooling
failures. A flag that is present but whose value is malformed (a sealed digest that
is not 64 lowercase hex, a `--sealed-min-bundle-seq` that is not a canonical decimal
in `1..=2^53-1`, a digest reference that is not `sha256:<64 lowercase hex>`, a token
outside `[A-Za-z0-9._-]{1,63}`, an authority that is not `[A-Za-z0-9.:-]{1,255}`)
refuses (exit 1) with the class of the rule that consumes it, as listed below.

Rules, a **closed set**, evaluated in this order; the first failure is the refusal
and names its class (§3.1):

| # | Class | Rule |
|---|---|---|
| 1 | `mode` | exactly one of the two seal modes (§3.1), else refuse |
| 2 | `freshness-unsupported` | `--freshness`/`--freshness-sig` are **reserved**: refused in this contract version (the object's schema is T7/OS-0044 work) |
| 3 | `key-digest` | `sha256(file --release-key) == --sealed-key-sha256` (a malformed `--sealed-key-sha256` refuses here) |
| 4 | `manifest-digest` / `sig-digest` | mode manifest-digest only: `sha256(manifest)` and `sha256(sig)` equal the sealed values (a malformed sealed value refuses here) |
| 5 | `signature` | the signature verifies under `--release-key` over the exact manifest bytes |
| 6 | `duplicate-key` | the manifest, which is valid UTF-8 JSON, has no duplicated object key at any depth (the 1 MiB bound is acquisition, above) |
| 7 | `schema` | the manifest is a JSON object; `schema == neural-ice-release-manifest-v1`; `release_id` is present, a string, and matches `[A-Za-z0-9._-]{1,128}`. This rule validates only what the verb **depends on for its own integrity**; the fields rules 8-12 compare are judged by their own rule, and every other field is ignored by this verb |
| 8 | `bundle-seq` | `bundle_seq` is present and an integer (not a float, not a string) in `1..=2^53-1` (the bound of `ota-tpm-state.sh`) |
| 9 | `min-bundle-seq` | mode floor only: `--sealed-min-bundle-seq` is a canonical decimal in `1..=2^53-1` **and** `bundle_seq >= --sealed-min-bundle-seq` |
| 10 | `hardware-target` | `manifest.hardware_target` is present, a string, and equal to `--hardware-target` (itself a token) |
| 11 | `authority` | `manifest.host` is an object, `host.repository` is a present string of printable ASCII, ≤ 255, whose authority (text before the first `/`) is `[A-Za-z0-9.:-]{1,255}` and `== --release-authority` |
| 12 | `host-digest` | `host.digest` is a present string `sha256:<64 lowercase hex>` and `== --host-index-digest`; `--host-manifest-digest` must also be `sha256:<64 lowercase hex>` (refused here: it is compared with nothing, only recorded) |
| 13 | `candidate-marker` | in `--candidate-root`, read **without executing it**: `usr/lib/neural-ice/hardware-target`, `appliance-variant`, `signed-boot-trust-policy-id`, `access-policy`, `ota-state-profile`. Each is a regular, non-symlink file of at most 64 bytes whose bytes are **exactly `<value>\n`**: one value, one final LF, no CR, no other whitespace, no leading or trailing blank, nothing stripped or trimmed. The values are `--hardware-target`, `--variant`, `--trust-policy-id`, `--access-profile` and `owner-sealed-ota-state-v2`; each sealed value is a token `[A-Za-z0-9._-]{1,63}`, and `--variant` is in the closed set. A marker that is absent, not a regular file, or not exactly that form refuses |
| 14 | `candidate-key` | `sha256(candidate usr/lib/neural-ice/keys/release-authorization.pub) == --sealed-key-sha256` (key continuity installer → host) |
| 15 | `candidate-anchor` | the candidate carries **no** `etc/neural-ice/keys/ota-root.pub` and **no** `usr/lib/neural-ice/ota-bootstrap` (defence in depth: the v2 host forbids the v1 anchors) |
| 16 | `receipt-conflict` | publishing the receipt (§3.1) |

No clock is read anywhere. `--host-manifest-digest` is **not** compared with the
manifest (it is the platform child of the index, which the caller resolved); it is
validated as `sha256:<64 lowercase hex>` (rule 12) and recorded in the receipt, where
the reader binds the booted deployment to it (DESIGN-B P4).

**Why rule 13 is stricter than the installer's current marker reader.**
`_img_read` in `ota/neural-ice-autoinstall.sh` deletes **every** whitespace character
(`tr -d '[:space:]'`) and tolerates up to 128 bytes, so `owner-sealed-ota-state-v2`
with a trailing blank, an embedded newline run or a CR would pass there and fail the
verifier (or the reverse for a value the verifier would reject). The verifier is the
only judge of rule 13: T3b must call it, or enforce this exact form byte for byte; it
must not reuse `_img_read` as the decision.

**Signature file bytes.** "No trailing LF" is a property of how the golden and the KMS
write the file, not something cosign or `openssl base64 -d` enforces: both accept one
final LF. It is enforced in mode `manifest-digest` only, by the sealed hash of the
exact bytes; in mode `floor` a signature with a final LF verifies. This is harmless
(no forgery follows: the signed bytes are the manifest's) and is recorded so no test
expects more.

## 3. CLI contract

### 3.1 `verify-v2-release` (installer, before any destructive write)

```
ni-ota-verify verify-v2-release
  --manifest F --manifest-sig F --release-key F --sealed-key-sha256 HEX
  ( --sealed-manifest-sha256 HEX --sealed-manifest-sig-sha256 HEX     # mode manifest-digest (adapter A1, current installer)
  | --sealed-min-bundle-seq N [--freshness F --freshness-sig F] )     # mode floor (adapter A2, generic installer)
  --hardware-target T --access-profile P --trust-policy-id ID --variant sealed-lab
  --release-authority HOST --candidate-root DIR
  --host-index-digest sha256:HEX --host-manifest-digest sha256:HEX
  --receipt OUT
```

* Every flag is required except `--freshness`/`--freshness-sig` (rule 2). An unknown,
  repeated, valueless or missing flag is a **usage error**: exit 2, as `parse_flags`.
* `--variant` is the closed set `{sealed-lab}` in this contract version. The image
  build also accepts `debug` and `prod` (`image/Containerfile.bootc`); this lane is
  **lab-only** and refuses them (rule 13). Opening the lane to `prod` is a contract
  change (and, per the workspace rule on "lab only" options, a tracked release-blocking
  item with a production exit criterion: §12), not a local decision of a consumer.
* `--receipt OUT`: create-if-absent by hard link of a private staged file, then sync
  the directory; if `OUT` already exists it must be **byte-equal** to the receipt
  that would be written, else refuse `receipt-conflict` (same rules as
  `publish_receipt`, `preseal.rs`). The file is `0600`, ≤ 4 KiB.
* stdout, on pass only, one line, keys in this order:
  `{"bundle_seq":N,"idempotent":BOOL,"receipt_sha256":HEX,"verdict":"pass"}` —
  `idempotent` is `false` when this call created the receipt, `true` when it found
  it byte-equal. `receipt_sha256` is the sha256 of the receipt file bytes.
* stderr, on refusal: `ni-ota-verify: v2 release REFUSED: <class>: <detail>` (class
  from §2; the detail is free text, tests match the class only).
* Exit: **0** pass, **1** refusal, **2** internal or usage error.

### 3.2 `verify-retained-v2-release` (ceremony, every boot, reader)

```
ni-ota-verify verify-retained-v2-release
  --manifest F --manifest-sig F --release-key /usr/lib/neural-ice/keys/release-authorization.pub
  --expected-receipt-sha256 HEX --receipt F --scratch-dir DIR
```

Re-verifies the **persisted** pair and receipt against the **live** root `/`:

1. `sha256(receipt bytes) == --expected-receipt-sha256` (the value the TPM-bound
   evidence carries); the receipt parses as §4 canonical bytes, no unknown key.
2. `sha256(manifest) == receipt.manifest_sha256`, `sha256(sig) ==
   receipt.manifest_sig_sha256`, `sha256(--release-key) == receipt.release_key_sha256`;
   in mode `manifest-digest`, `receipt.seal.sealed_manifest_sha256 == receipt.manifest_sha256`.
3. The signature verifies; `bundle_seq`, `release_id`, `hardware_target`,
   `host.digest`, `authority(host.repository)` of the manifest equal the receipt's.
4. The live markers of rule 13 (read from `/`) equal the receipt's `hardware_target`,
   `variant`, `signed_boot_trust_policy_id`, `access_profile`, lane `…-v2`; the live
   key file equals the receipt key; rule 15 holds on `/`.

Same exit codes. stdout on pass: `{"bundle_seq":N,"receipt_sha256":HEX,"verdict":"pass"}`.
Refusal classes: those of §2 plus `receipt-digest` (1) and `receipt-malformed` (1).
`--scratch-dir` is a private directory for the verifier's temporary files
(`/run/...`). The booted-deployment check (the origin the system booted equals
`receipt.host_index_digest`, DESIGN-B P4) belongs to the **reader**
(`state_v1.rs`, T1), not to this verb.

Test seam: a `--root DIR` flag replacing `/` exists **only** under the
`test-path-overrides` feature (like the other seams); it must not exist in the
shipped binary.

## 4. Receipt `neural-ice-v2-release-receipt-v1` (DESIGN-B §3.3)

Canonical JSON: keys sorted at every level, compact separators, UTF-8, **one final
LF**, ≤ 4 KiB, no unknown key, no duplicate key. Golden bytes:
`tests/fixtures/v2-release/expected-receipt-{manifest-digest,floor}.json`.

| Field | Type / value |
|---|---|
| `schema` | `"neural-ice-v2-release-receipt-v1"` |
| `access_profile`, `hardware_target`, `variant`, `signed_boot_trust_policy_id` | the sealed values (strings) |
| `bundle_seq` | integer `1..=2^53-1` |
| `release_id` | `[A-Za-z0-9._-]+` |
| `host_repository` | `manifest.host.repository` |
| `host_index_digest` | `sha256:<64 hex>` (= `manifest.host.digest`) |
| `host_manifest_digest` | `sha256:<64 hex>` (platform child, caller-supplied) |
| `manifest_sha256`, `manifest_sig_sha256`, `release_key_sha256` | 64 lowercase hex |
| `seal` | `{"mode":"manifest-digest","sealed_manifest_sha256":HEX,"min_bundle_seq":null}` or `{"mode":"floor","sealed_manifest_sha256":null,"min_bundle_seq":N}` |

Reserved: a `freshness_sha256` field is **not** emitted in this version (the
freshness object does not exist yet); a reader rejects it as an unknown key until a
`…-v2` receipt schema defines it.

## 5. Persisted layout (created by the installer, `0700 root` directories, `0600` files, never overwritten)

```
/var/lib/neural-ice/ota/v2-release-input-v1/release-manifest.json
/var/lib/neural-ice/ota/v2-release-input-v1/release-manifest.json.sig
/var/lib/neural-ice/ota/v2-release/receipt.json
```

The three files are the **complete** v2-lane footprint of the directory. The lanes are
disjoint on disk too: with lane2 evidence the reader refuses a state directory that also
holds `preseal-input-v1/`, `preseal/` or `state-v1/` (T1 `owner_v2_release_status`), and
with preseal evidence it refuses `v2-release-input-v1/` or `v2-release/`. A completed
instance is `tests/fixtures/v2-release/completed/<mode>/` (§6.5).

Replay is create-if-absent, byte-equal otherwise, refuse on difference. T3b chooses
between extending `neural-ice-preseal-handoff.py` with `--kind v2-release` and a
sibling script; the layout above is the contract.

## 6. Completion evidence `neural-ice-owner-ceremony-evidence-v2-lane2` (T2 writes, T1 reads)

The reference parser is T1's `authenticated_completion` in
`tools/ni-ota-verify/src/access_profile_anchor.rs` (PR #238, head `9a7d220`); this
section states what it accepts, byte for byte, and `tests/fixtures/v2-release/completed/`
is a complete instance. A divergence between this text, that parser and the T2
producer is a defect of one side to be fixed in the same change, never a local choice.

### 6.1 File, selection and digest chain

* File: `/var/lib/neural-ice/ota/owner-ceremony-evidence-v2.json`, the **same name** as
  evidence v2: the TPM completion record (`completion_version` 2) selects the file, the
  `schema` member selects the lane. `0600 root`, ≤ **16384 bytes**.
* Completion record: `neural-ice-tpm-state completion-inspect` prints, and the
  reader requires byte for byte,
  `{"completion_version":2,"evidence_digest_sha256":"<64hex>","schema":"neural-ice-owner-ceremony-completion-inspection-v1"}` + LF.
* `evidence_digest_sha256 = sha256("neural-ice:tpm:owner-ceremony-completion:v2\0" ‖ file bytes)`
  — `COMPLETION_MAGIC_V2` / `ceremony-finalize-v2`, **unchanged**. The reader recomputes
  it over the file it read and refuses on a difference.

### 6.2 Canonical form (what "canonical JSON plus LF" means)

The file is **one line**: a JSON object, then exactly one LF, nothing else.

* Object keys sorted in bytewise (code-point) order **at every depth**; separators `,`
  and `:` only, **no whitespace anywhere**.
* ASCII only. No non-ASCII and no control character in any string, no `\u` or other
  escape other than the ones a producer needs for `"` and `\` (the contract's values
  need none). Integers are plain decimal (no sign, no leading zero, no exponent, no
  fraction: `3`, never `3.0`). `true`/`false` lower case. No `null` in this lane's
  evidence.
* No duplicated key. No key not listed below.
* Producer (shell/python): `json.dumps(obj, sort_keys=True, separators=(",", ":"))`
  then a newline, i.e. the form of `build_evidence_v2`. Reader (Rust): parses the bytes
  to a generic value, **re-serialises** it (sorted, compact) + LF and requires equality
  with the bytes read: any deviation (order, a space, an escape, a float) refuses with
  "not canonical JSON plus LF" before any field is looked at.

### 6.3 Members (closed; each object has exactly these keys)

```json
{"access_profile_anchor":{"json_sha256":"<64hex>","signature_sha256":"<64hex>","spki_sha256":"<64hex>"},
 "data_luks":{LUKS},"device_root_name":"<68hex>",
 "install_identity":{"install_source":"medium","installed_at":"1970-01-01T00:00:00Z",
   "installer_sealed_identity_sha256":"<64hex>","release_identity_sha256":"<manifest_sha256>",
   "schema":"neural-ice-owner-ceremony-install-identity-v1"},
 "ota_state":{OTA},
 "schema":"neural-ice-owner-ceremony-evidence-v2-lane2","srk_name":"<68hex>","system_luks":{LUKS},
 "tpm_state":{TPM},
 "v2_release":{"bundle_seq":3,"manifest_sha256":"<64hex>","manifest_sig_sha256":"<64hex>",
   "receipt_schema":"neural-ice-v2-release-receipt-v1","receipt_sha256":"<64hex>",
   "release_id":"v2-test-train-3","release_key_sha256":"<64hex>"}}
```

* Top level: exactly the ten keys above (`ota_preseal` is **forbidden**: evidence v2 and
  lane2 are disjoint, a reader of one never accepts the other).
* `access_profile_anchor`: the sha256 of `access-profile-v1.json`, `access-profile-v1.sig`
  and `access-profile-v1.spki` (unchanged from evidence v2).
* `device_root_name`, `srk_name`: 68 lowercase hex (`000b` ‖ a 32-byte Name).
* `LUKS` (`data_luks`, `system_luks`): exactly `keyslot`, `pcr_bank`, `pcrs`, `policy_hash`,
  `policy_public_key_sha256`, `schema` = `neural-ice-luks-token-evidence-v1`,
  `sealed_object_sha256`, `srk_sha256`, `token_sha256` (unchanged from evidence v2).
* `TPM` (`tpm_state`): exactly `freshness_counter`, `freshness_public_sha256`,
  `install_counter`, `install_public_sha256`, `profile_binding`, `schema` =
  `neural-ice-tpm-state-snapshot-v1` (unchanged).
* `OTA` (`ota_state`): exactly the sixteen keys of evidence v2, with the **same
  constants**: `profile` `owner-sealed-ota-state-v1`; floor `floor_index` `0x01500001`,
  `floor_attributes` `0x62008`, `floor_size` 8, `floor_policy_sha256` and `floor_name`
  (constants of `access_profile_anchor.rs`); anchor `anchor_index` `0x01500002`,
  `anchor_attributes` `0x2060048`, `anchor_size` 32, `anchor_policy_sha256`,
  `anchor_pristine_name`, `anchor_written_name` (constants);
  `anchor_state_at_completion` `pristine`, `anchor_name_at_completion` =
  `anchor_pristine_name`, `clear_protected_at_completion` `true`, `baseline_floor` an
  integer in `1..=2^53-1`. The golden file shows every constant; none is restated here.
* `install_identity` is the parsed content of the installer's canonical file
  `owner-ceremony-install-identity-v1.json` (itself `json.dumps(sort_keys, compact)` +
  LF, `autoinstall.sh`, "install-identity"), embedded verbatim:
  * `install_source` = `medium` (the v2 seal requires `neuralice.source=medium`, §11);
  * `installed_at` = **`1970-01-01T00:00:00Z`**, a fixed value: the installer has no
    trusted clock, and the ceremony only checks the shape
    `YYYY-MM-DDThh:mm:ssZ` and passes it as the access-profile anchor's `enrolled_at`;
  * `installer_sealed_identity_sha256` = sha256 of the sealed trust-anchor text exactly as
    `printf '%s' "$SEALED_ANCHOR" | sha256sum` computes it today (unchanged);
  * `release_identity_sha256` = **`v2_release.manifest_sha256`** in this lane (the
    medium-without-preseal value `sha256(ANCHOR ‖ 0x00 ‖ PAYLOAD_DIGEST)` does not apply).
* `v2_release`: exactly seven keys. `bundle_seq` integer; `manifest_sha256`,
  `manifest_sig_sha256`, `receipt_sha256`, `release_key_sha256` 64 lowercase hex;
  `receipt_schema` = `neural-ice-v2-release-receipt-v1`; `release_id`
  `[A-Za-z0-9._-]{1,128}`. `receipt_sha256` is the sha256 of the bytes of
  `receipt.json` (§4), the value `verify-retained-v2-release` is given.

### 6.4 Invariants and who enforces them

| Invariant | Enforced by |
|---|---|
| canonical form, closed key sets, constants of `ota_state`, hex shapes, `release_id` shape, `receipt_schema` | T1 parser (`authenticated_completion`) and T2 at build |
| `ota_state.baseline_floor == v2_release.bundle_seq` | T1 parser; T2 at completion |
| `install_identity.release_identity_sha256 == v2_release.manifest_sha256` | T1 parser; T2 at completion |
| `install_identity`: key set and `schema` only | T1 parser. **It does not compare `install_source`, `installed_at` or `installer_sealed_identity_sha256`**: T2's ceremony (regexes) and the golden carry those |
| `TPM inspect-v2.baseline_floor == baseline_floor == receipt.bundle_seq` | T1 reader (`owner_v2_release_status`) at every status |
| `receipt` re-derived from the persisted pair equals `receipt_sha256`; the booted deployment is the receipt's host | T1 reader (`verify_retained`, `verify_running_v2_release`) |
| `preseal-input-v1`, `preseal` and `state-v1` absent from the state directory; anchor pristine | T1 reader |

Rust: `OwnerCeremonyEvidenceV2Lane2` (`deny_unknown_fields`); `VerifiedOwnerCompletion`
carries the attestation enum `{None, Preseal{…}, V2Release{…}}`. The shape of the
`LUKS`/`TPM` sub-objects is that of evidence v2.

### 6.5 Completed-appliance vector (`tests/fixtures/v2-release/completed/<mode>/`)

One tree per seal mode (`manifest-digest`, `floor`), generated by
`generate-golden.py --completed-only` from the committed pair without touching a
signature or an existing digest:

```
completed/<mode>/completion-inspection.json                       # §6.1, what completion-inspect prints
completed/<mode>/var/lib/neural-ice/ota/owner-ceremony-evidence-v2.json
completed/<mode>/var/lib/neural-ice/ota/owner-ceremony-install-identity-v1.json
completed/<mode>/var/lib/neural-ice/ota/v2-release-input-v1/release-manifest.json      # = top-level pair
completed/<mode>/var/lib/neural-ice/ota/v2-release-input-v1/release-manifest.json.sig
completed/<mode>/var/lib/neural-ice/ota/v2-release/receipt.json                        # = expected-receipt-<mode>.json
```

Only the v2-lane entries are pinned; the other files of that directory (device-root,
SRK, intent, access-profile triple, …) are unchanged by this lane and absent here.
`golden.json` `expected.completed.<mode>` gives `evidence_sha256`,
`completion_digest_sha256` and `receipt_sha256`.

**Synthetic parts, stated so no test expects more:** `access_profile_anchor` carries
three fixed placeholder digests, and the `LUKS`/`TPM` members, `device_root_name`,
`srk_name` and `installer_sealed_identity_sha256` are fixed placeholders of the right
shape. A test that runs the **reader** (anchor signature, TPM stubs) must install its
own anchor files, rewrite the three anchor digests, re-canonicalise and recompute the
completion digest, exactly as T1's `v2_evidence` helper does; a test that runs only the
**completion parser** (`owner-completion-test`, `verified_owner_completion`) can use the
tree as is. `ota_state` carries the real constants.

## 7. Shell library `ota/neural-ice-v2-owner-seal.sh`

Sourced, idempotent, no side effect on sourcing. Inputs are `V2SEAL_*` variables set
by the caller (unset or empty ⇒ refusal, never a default). `v2seal_preflight` and
`v2seal_commit` are implemented and driven by `ota/neural-ice-autoinstall.sh`
(`ota/test-neural-ice-v2-owner-seal.sh`); any entry point that is not implemented
exits 2.

| Function | When | Inputs | Outputs | Exit |
|---|---|---|---|---|
| `v2seal_preflight` | before any destructive write | `V2SEAL_OTA_VERIFY`, `V2SEAL_MODE` (`manifest-digest`\|`floor`), `V2SEAL_MANIFEST`, `V2SEAL_MANIFEST_SIG`, `V2SEAL_RELEASE_KEY`, `V2SEAL_KEY_SHA256`, [`V2SEAL_MANIFEST_SHA256`, `V2SEAL_MANIFEST_SIG_SHA256`] \| [`V2SEAL_MIN_BUNDLE_SEQ`], `V2SEAL_HARDWARE_TARGET`, `V2SEAL_ACCESS_PROFILE`, `V2SEAL_TRUST_POLICY_ID`, `V2SEAL_VARIANT`, `V2SEAL_RELEASE_AUTHORITY`, `V2SEAL_CANDIDATE_ROOT`, `V2SEAL_HOST_INDEX_DIGEST`, `V2SEAL_HOST_MANIFEST_DIGEST`, `V2SEAL_WORK` (private dir), `V2SEAL_RECEIPT` (path under it) | sets `V2SEAL_BUNDLE_SEQ`, `V2SEAL_RECEIPT_SHA256`; writes the receipt at `V2SEAL_RECEIPT` | 0 / 1 / 2 |
| `v2seal_commit` | after the deployment is written, mounted at `V2SEAL_TARGET_ROOT` | the preflight outputs + `V2SEAL_TARGET_ROOT`, `V2SEAL_OTA_TPM_STATE`, `V2SEAL_TPM_STATE` (helper paths) | persists §5; re-verifies the PERSISTED manifest pair against the deployed candidate (`verify-v2-release` over the persisted copies and `V2SEAL_TARGET_ROOT`: `verify-retained-v2-release` reads `/` and has no live-root seam, so it stays the boot-time reader of §3.2); `cmp`s the persisted receipt with the preflight one; `ota-tpm-state prepare "$V2SEAL_BUNDLE_SEQ"`; `inspect-v2`: `baseline_floor == bundle_seq`, anchor pristine; `provisioning-status == preseal-prepared`; emits the install-identity inputs (`release_identity_sha256 = manifest_sha256`) | 0 / 1 / 2 |
| `v2seal_verify_retained` | ceremony and every boot | `V2SEAL_OTA_VERIFY`, `V2SEAL_EXPECTED_RECEIPT_SHA256`, `V2SEAL_SCRATCH_DIR` (persisted paths are §5) | `V2SEAL_BUNDLE_SEQ` | 0 / 1 / 2 |
| `v2seal_refusal MSG…` | any failed check | — | stderr `v2seal: refused: MSG` | **exits 1**, never returns |

Exit codes are the verifier's: **0** pass, **1** refusal, **2** internal / not
implemented. The library **never reads `NEURALICE_SEALED_OTA_STATE`**: there is no
`relaxed` branch (§9). The TPM objects, their attributes (floor `0x62008`, anchor
`0x2060048`) and the anti-Clear lock are those of `ota-tpm-state.sh`, which this work
does not modify.

## 8. `authenticated-ota-status` — bytes unchanged

On a completed v2-lane appliance the verb prints **exactly** the bytes of
`tests/fixtures/v2-release/expected-authenticated-ota-status.json`:

```
{"committed_generation":null,"completion_version":2,"enforce_ready_verified":false,"profile":"owner-sealed-ota-state-v1","schema":"neural-ice-authenticated-ota-status-v1"}\n
```

(the literal `HELD_STATUS` of `tests/owner_state_reader.rs`; `v2_release_golden.rs`
fails if the two diverge.) The licence gate and model-fetch compare these bytes and
need **no code change**.

## 9. The `relaxed` posture on the v2 lane

`NEURALICE_SEALED_OTA_STATE` defaults to `relaxed` everywhere (ADR-0050 lever B), which
turns an unreadable attestation into a fail-open. On the v2 lane:

* **The new v2 checks have no `relaxed` branch.** `v2seal_refusal` is `exit 1`;
  `preseal_refusal` (`ota/neural-ice-firstboot-tpm-ceremony.sh`) is **never** called on
  the v2 branch. Forcing `relaxed` changes nothing for the v2 lane.
* The v2 **host** runs `NEURALICE_SEALED_OTA_STATE=strict` for the units below
  (decision O2, recommendation strict; the Owner decides — until then, the first two
  rows of the table are the only ones this repository can show).

| Unit / reader | Where the default lives | Default today | Value on a v2 host | Owner of the change |
|---|---|---|---|---|
| first-boot ceremony | `image/firstboot/neural-ice-firstboot-tpm-ceremony.service:26`; `ota/neural-ice-firstboot-tpm-ceremony.sh:70` | `relaxed` | `strict` (drop-in) **and** the v2 branch ignores it | T4 (drop-in), T2 (branch) |
| OTA commit (`ni-ota-verify`) | `tools/ni-ota-verify/src/config.rs:168` (everything but `strict` is relaxed) | `relaxed` | not applicable: governs the v1 OTA commit only | — |
| licence gate | `config/bin/neural-ice-license-ota-gate.py` (ICE-Fabric-v2) | `relaxed` (statut illisible ⇒ ready) | `strict` | T4 (Fabric-v2) |
| model-fetch | `containers/appliance-os/neural-ice-model-fetch.service` (ICE-Fabric-v2) | `relaxed` | `strict` | T4 |
| `neural-ice-license-gate`, `neural-ice-model-switch`, `neural-ice-primary-engine` | `quadlets/host/*.service` (ICE-Fabric-v2) | `relaxed` | `strict` | T4 |

Rows 3–5 are cited from the design (ICE-Fabric-v2 `38138c2`) and **not re-verified**
by this change, which touches no Fabric-v2 file. `builder/test_v2_model_plane.py:998`
asserts the drop-in does not remove the variable and is T4's to update.

## 10. Golden vectors (`tools/ni-ota-verify/tests/fixtures/v2-release/`)

| File | Content |
|---|---|
| `release-manifest.json`, `.sig` | synthetic manifest (authority `registry.example.test`), signed by a test key; no LF at the end of either |
| `release-authorization.pub` | the test public key (the private key was generated in a temp dir and deleted) |
| `candidate-root/usr/lib/neural-ice/…` | the markers rule 13 reads (lane `owner-sealed-ota-state-v2`) and the key of rule 14; **no** `ota-root.pub`, no `ota-bootstrap` |
| `expected-receipt-manifest-digest.json`, `expected-receipt-floor.json` | the receipt bytes for each seal mode (floor mode seals minimum 2 for a manifest at 3) |
| `expected-authenticated-ota-status.json` | §8 |
| `golden.json` | every input of §3.1 (`inputs`) and every expected value (`expected`: `bundle_seq`, `release_id`, `host_repository`, `receipt_sha256` per mode, `verify_stdout` per mode with `idempotent:false`, `status_sha256`) |
| `completed/{manifest-digest,floor}/…` | a completed-appliance instance (§6.5): lane2 evidence, completion record, install identity, persisted pair and receipt |
| `generate-golden.py` | the regeneration procedure (python3 + openssl): **regenerable, not reproducible** — ECDSA is randomised, so a full regeneration changes the key, the signature and every digest derived from them: read `golden.json`, never hard-code one. `--completed-only` rebuilds `completed/` and the `expected.completed` block from the committed files and changes no existing digest. Not run by CI: only the Rust test keeps the committed bytes coherent |

`tests/v2_release_golden.rs` pins these files to this contract without any verifier
(signature under `openssl`, digests, canonical receipt bytes, markers, status
literal, sensitivity to a flipped byte and to an extra LF).

Replay obligations: **T1** — `verify-v2-release` over `inputs` prints
`expected.verify_stdout[mode]` and writes the golden receipt bytes in both modes; a
second call prints `idempotent:true`; `authenticated-ota-status` on a completed
fixture prints the status bytes (the `completed/` tree of §6.5, with the anchor
digests rewritten as §6.5 says); the refusals of §2 each name their class (≥ 14
negatives, derived from these files by mutation). **T2** — the evidence of §6 built
from the receipt digest equals `completed/<mode>/…/owner-ceremony-evidence-v2.json`
byte for byte once the synthetic members are supplied; a forced `relaxed` still
refuses. **T3a/T5** — the cmdline and ESP of §11. **T3b** — `v2seal_*`
call the verifier with `inputs` and obtain the same receipt. **T6** — the status
bytes for the consumer contract tests.

## 11. Sealed cmdline and ESP carrier (T3a grammar and media, T3b installer, T5 builder)

Source: DESIGN-B §2 (mode manifest-digest, adapter A1) and §4 T3a/T3b/T5. Mode floor
(adapter A2, the generic installer) carries no manifest on this medium and uses none of
this section.

**Keys, exactly** (the ones DESIGN-B names; no other spelling is valid):

| Cmdline key | Value | ESP file (relative to the ESP root) | Hashed value |
|---|---|---|---|
| `neuralice.v2rel_sha256` | 64 lowercase hex | `ice-coreos/v2-release-manifest.json` | `sha256` of the exact bytes of the manifest |
| `neuralice.v2rel_sig_sha256` | 64 lowercase hex | `ice-coreos/v2-release-manifest.json.sig` | `sha256` of the exact bytes of the detached signature |

The installer reads them with `esp_staged_file` **unchanged** (it prepends
`ice-coreos/`, copies to a private file, hashes the **copy** against the sealed value).
The verifier is then called with `--sealed-manifest-sha256` / `--sealed-manifest-sig-sha256`
set to those cmdline values and with the private copies as `--manifest` / `--manifest-sig`.
The key itself is **not** a new token: it is the already-sealed `neuralice.relauth_keyid`
(sha256 of the v2 release key file), passed as `--sealed-key-sha256`.

**Grammar and exclusivity** (T3a, enforced by the shell grammar
`image/installer/neural-ice-sealed-cmdline-grammar.sh` **and** its Python twin
`image/inspect-installer-media.py`, which must agree on one shared corpus):

1. Each key appears **at most once**, and the two appear **together or not at all**.
2. They are **mutually exclusive with `neuralice.preseal`**, and with the registry
   authorisation pair **`neuralice.relauth_sha256` / `neuralice.relauth_sig_sha256`**:
   a v2 line carries neither (the v2 manifest is the authorisation).
3. They require **`neuralice.source=medium`** (a registry source, or no source, refuses).
4. The two values differ (derived from the relauth pair rule "one hash twice pins
   nothing"; DESIGN-B is silent, and an honest medium never trips it).
5. Lane coupling at the installer (T3b, DESIGN-B §3.1, §1 above): image marker
   `owner-sealed-ota-state-v2` **requires** the v2 seal and **forbids** `preseal`;
   marker `owner-sealed-ota-state-v1` **forbids** the v2 seal; `legacy-unmarked` + the
   v2 seal is refused.
6. The inspector's ESP allow-list gains exactly those two file names, and refuses a
   medium whose ESP hash differs from the cmdline value, or that carries one file
   without the other.

**Token order** (T3a renders, T5's `trust/v2-lab/installer-cmdline.template` copies, the
inspector compares). DESIGN-B fixes the keys but leaves the position to the CoreOS
render ("l'ordre exact du rendu CoreOS"); this contract therefore **derives** it from
`image/build-installer-usb.sh` (`UKI_KARGS`, around `seal_install_authorization`) and
fixes it here so T3a and T5 cannot diverge: the pair sits **immediately after
`neuralice.source=medium`**, in the slot where `neuralice.preseal` or the
`neuralice.relauth_*` pair sit today, **`v2rel_sha256` first, then `v2rel_sig_sha256`**,
and before any `neuralice.seed_*` token. In the Fabric-v2 template, whose last token is
`neuralice.source=medium`, that is:

```
… neuralice.source=medium neuralice.v2rel_sha256=@V2REL_SHA@ neuralice.v2rel_sig_sha256=@V2REL_SIG_SHA@
```

(`@V2REL_SHA@`, `@V2REL_SIG_SHA@`: the placeholder names of DESIGN-B T5.) The shell
grammar itself is order-insensitive for optional keys (it counts occurrences), so the
order is enforced where the line is compared byte for byte: the renderer, the
template match in `v2-uki-claims.py`, and the inspector's expected cmdline.

**Budget (estimate, not measured on a real medium).** The grammar caps a line at
`NI_SEALED_CMDLINE_MAX_BYTES=1957` bytes and `NI_SEALED_CMDLINE_MAX_WORDS=64`. The
Fabric-v2 template with plausibly sized placeholders is ≈ 1319 bytes / 24 words; the
two tokens add ≈ 180 bytes / 2 words. T3a must re-measure on the real render.

## 12. Not verified, open

* Nothing here ran against `ni-ota-verify` from this PR (the verbs live in T1, PR #238),
  a TPM, QEMU or hardware. §6 was written from T1's parser at `9a7d220` by reading it;
  the completed-appliance vector (§6.5) was additionally fed to that parser's
  completion reader (`test-inspect-owner-completion`, scratch build of `9a7d220` with
  `test-path-overrides`): both trees are accepted, and a spaced re-serialisation, an
  added `ota_preseal` and a `bundle_seq` ≠ `baseline_floor` are refused. The reader
  (anchor signature, TPM stubs, booted deployment) was not run on the vector.
* `host_manifest_digest` provenance (who resolves the platform child, and from which
  source in each installer) is the caller's; only its format is checked.
* The freshness object (mode floor) and the successor rule for an updated host (T9)
  are out of this contract version.
* **`--variant` is `{sealed-lab}`** while the image build accepts `debug|sealed-lab|prod`.
  Owner of the extension: the coordinator with Thomas; production exit criterion: a
  contract version that admits `prod` (and its marker/receipt values) before the first
  customer delivery. Until then a `prod` image is refused by rule 13.
* **Generic installer (T7) and cosign.** The contract imposes `cosign` for both verbs
  (rule 5). DESIGN-B's T7 line (`mkosi.conf`: `ni-ota-verify`, `ota-tpm-state`, the
  library) does not list it. **Suspected, not verified**: the generic-installer tree
  (`image/generic-installer`, PR #234) is not in this worktree and was not read. T7
  must ship a pinned `cosign` in the initrd/installer root or the verb cannot run there.
* CI runs the golden test through the `openssl` CLI. The pinned
  `rust:1.93-bookworm` image should carry it; the PR's own `pull-request` job passing
  is the only evidence, and no more than that.
