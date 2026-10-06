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
enforced by the installer (T3b) and the reader (T1): marker v2 **requires** the v2
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
trailing LF.

Verification mechanism: the pinned `cosign verify-blob --key … --insecure-ignore-tlog=true`
through `runner::verify_blob`, exactly as `delegated::verify_signature` and
`preseal.rs` already do. **Not** an in-process `p256::ecdsa` verification: the
crate is pulled with `default-features = false, features = ["arithmetic"]`, the
`ecdsa` crate is absent from `Cargo.lock`, and adding it would be a new dependency
(this corrects DESIGN-B §0.3 "aucune nouvelle dépendance"). `sha2` is already a
dependency and is used in-process for every digest of this verb.

Rules, a **closed set**, evaluated in this order; the first failure is the refusal
and names its class (§3.1):

| # | Class | Rule |
|---|---|---|
| 1 | `mode` | exactly one of the two seal modes (§3.1), else refuse |
| 2 | `freshness-unsupported` | `--freshness`/`--freshness-sig` are **reserved**: refused in this contract version (the object's schema is T7/OS-0044 work) |
| 3 | `key-digest` | `sha256(file --release-key) == --sealed-key-sha256` |
| 4 | `manifest-digest` / `sig-digest` | mode manifest-digest only: `sha256(manifest)` and `sha256(sig)` equal the sealed values |
| 5 | `signature` | the signature verifies under `--release-key` over the exact manifest bytes |
| 6 | `duplicate-key` | the manifest is JSON with no duplicated key at any depth, ≤ 1 MiB |
| 7 | `schema` | `schema == neural-ice-release-manifest-v1`; `release_id` matches `[A-Za-z0-9._-]+`; no other field is interpreted by this verb |
| 8 | `bundle-seq` | `bundle_seq` is an integer (not a float, not a string) in `1..=2^53-1` (the bound of `ota-tpm-state.sh`) |
| 9 | `min-bundle-seq` | mode floor only: `bundle_seq >= --sealed-min-bundle-seq` |
| 10 | `hardware-target` | `manifest.hardware_target == --hardware-target` |
| 11 | `authority` | the authority of `host.repository` (text before the first `/`) `== --release-authority` |
| 12 | `host-digest` | `host.digest == --host-index-digest` |
| 13 | `candidate-marker` | in `--candidate-root`, read **without executing it** and each at most 64 bytes: `usr/lib/neural-ice/hardware-target`, `appliance-variant`, `signed-boot-trust-policy-id`, `access-policy`, `ota-state-profile` equal `--hardware-target`, `--variant`, `--trust-policy-id`, `--access-profile` and `owner-sealed-ota-state-v2` (regular files, not symlinks) |
| 14 | `candidate-key` | `sha256(candidate usr/lib/neural-ice/keys/release-authorization.pub) == --sealed-key-sha256` (key continuity installer → host) |
| 15 | `candidate-anchor` | the candidate carries **no** `etc/neural-ice/keys/ota-root.pub` and **no** `usr/lib/neural-ice/ota-bootstrap` (defence in depth: the v2 host forbids the v1 anchors) |
| 16 | `receipt-conflict` | publishing the receipt (§3.1) |

No clock is read anywhere. `--host-manifest-digest` is **not** compared with the
manifest (it is the platform child of the index, which the caller resolved); it is
validated as `sha256:<64 lowercase hex>` and recorded in the receipt, where the
reader binds the booted deployment to it (DESIGN-B P4).

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
* `--variant` is the closed set `{sealed-lab}` in this contract version.
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

Replay is create-if-absent, byte-equal otherwise, refuse on difference. T3b chooses
between extending `neural-ice-preseal-handoff.py` with `--kind v2-release` and a
sibling script; the layout above is the contract.

## 6. Completion evidence `neural-ice-owner-ceremony-evidence-v2-lane2` (T2 / T1 reader)

Built like `build_evidence_v2` with `ota_preseal` **replaced** by `v2_release`
(`ota_preseal` XOR `v2_release`: the schemas are disjoint, no cross-lane reading):

```json
{"access_profile_anchor":{…unchanged…},"data_luks":{…},"device_root_name":"<hex>",
 "install_identity":{"install_source":"medium","installed_at":"1970-01-01T00:00:00Z",
   "installer_sealed_identity_sha256":"<64hex>","release_identity_sha256":"<manifest_sha256>",
   "schema":"neural-ice-owner-ceremony-install-identity-v1"},
 "ota_state":{…identical to evidence-v2: anchor_*, baseline_floor, clear_protected_at_completion,
   floor_*, profile:"owner-sealed-ota-state-v1"…},
 "schema":"neural-ice-owner-ceremony-evidence-v2-lane2","srk_name":"<hex>","system_luks":{…},"tpm_state":{…},
 "v2_release":{"bundle_seq":3,"manifest_sha256":"<64hex>","manifest_sig_sha256":"<64hex>",
   "receipt_schema":"neural-ice-v2-release-receipt-v1","receipt_sha256":"<64hex>",
   "release_id":"…","release_key_sha256":"<64hex>"}}
```

Invariants checked by the ceremony at completion and by the reader at every boot:
`ota_state.baseline_floor == v2_release.bundle_seq == receipt.bundle_seq`;
`v2_release.receipt_sha256` is the digest `verify-retained-v2-release` is given;
`install_identity.release_identity_sha256 == v2_release.manifest_sha256`;
`install_identity.install_source == "medium"` and
`install_identity.installed_at == "1970-01-01T00:00:00Z"` (T2 pins both, and judges the
whole identity before the one-time TPM mutation). Rust:
`OwnerCeremonyEvidenceV2Lane2` with `deny_unknown_fields`; `VerifiedOwnerCompletion`
carries an attestation enum `{Preseal{…}, V2Release{…}}`. (The shape of the
`tpm_state`/`luks` sub-objects is that of evidence v2 and is not restated here.)

## 7. Shell library `ota/neural-ice-v2-owner-seal.sh`

Sourced, idempotent, no side effect on sourcing. Inputs are `V2SEAL_*` variables set
by the caller (unset or empty ⇒ refusal, never a default). Today: **stub, every entry
point exits 2** (`ota/test-neural-ice-v2-owner-seal.sh`).

| Function | When | Inputs | Outputs | Exit |
|---|---|---|---|---|
| `v2seal_preflight` | before any destructive write | `V2SEAL_OTA_VERIFY`, `V2SEAL_MODE` (`manifest-digest`\|`floor`), `V2SEAL_MANIFEST`, `V2SEAL_MANIFEST_SIG`, `V2SEAL_RELEASE_KEY`, `V2SEAL_KEY_SHA256`, [`V2SEAL_MANIFEST_SHA256`, `V2SEAL_MANIFEST_SIG_SHA256`] \| [`V2SEAL_MIN_BUNDLE_SEQ`], `V2SEAL_HARDWARE_TARGET`, `V2SEAL_ACCESS_PROFILE`, `V2SEAL_TRUST_POLICY_ID`, `V2SEAL_VARIANT`, `V2SEAL_RELEASE_AUTHORITY`, `V2SEAL_CANDIDATE_ROOT`, `V2SEAL_HOST_INDEX_DIGEST`, `V2SEAL_HOST_MANIFEST_DIGEST`, `V2SEAL_WORK` (private dir), `V2SEAL_RECEIPT` (path under it) | sets `V2SEAL_BUNDLE_SEQ`, `V2SEAL_RECEIPT_SHA256`; writes the receipt at `V2SEAL_RECEIPT` | 0 / 1 / 2 |
| `v2seal_commit` | after the deployment is written, mounted at `V2SEAL_TARGET_ROOT` | the preflight outputs + `V2SEAL_TARGET_ROOT`, `V2SEAL_OTA_TPM_STATE`, `V2SEAL_TPM_STATE` (helper paths) | persists §5; re-verifies with `verify-retained-v2-release` against the target; `cmp`s the persisted receipt with the preflight one; `ota-tpm-state prepare "$V2SEAL_BUNDLE_SEQ"`; `inspect-v2`: `baseline_floor == bundle_seq`, anchor pristine; `provisioning-status == preseal-prepared`; emits the install-identity inputs (`release_identity_sha256 = manifest_sha256`) | 0 / 1 / 2 |
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
| `generate-golden.py` | the regeneration procedure (python3 + openssl; ECDSA is randomised, so a regeneration changes every digest: read `golden.json`, never hard-code one) |

`tests/v2_release_golden.rs` pins these files to this contract without any verifier
(signature under `openssl`, digests, canonical receipt bytes, markers, status
literal, sensitivity to a flipped byte and to an extra LF).

Replay obligations: **T1** — `verify-v2-release` over `inputs` prints
`expected.verify_stdout[mode]` and writes the golden receipt bytes in both modes; a
second call prints `idempotent:true`; `authenticated-ota-status` on a completed
fixture prints the status bytes; the refusals of §2 each name their class (≥ 14
negatives, derived from these files by mutation). **T2** — the evidence of §6 built
from the receipt digest; a forced `relaxed` still refuses. **T3b** — `v2seal_*`
call the verifier with `inputs` and obtain the same receipt. **T6** — the status
bytes for the consumer contract tests.

## 11. Not verified, open

* Nothing here ran against `ni-ota-verify` (the verbs do not exist yet), a TPM, QEMU
  or hardware.
* `host_manifest_digest` provenance (who resolves the platform child, and from which
  source in each installer) is the caller's; only its format is checked.
* The freshness object (mode floor) and the successor rule for an updated host (T9)
  are out of this contract version.
