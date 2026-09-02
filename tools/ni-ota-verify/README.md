# ni-ota-verify

On-device OTA bundle verifier for Neural ICE appliances (ICE-Fabric,
decision D3: the verifier lives in this open-core OS repo — generic
"verify signed bundle manifest + anti-rollback" logic, zero product IP; only
the keys are secret).

The appliance is treated like a game console: it must verify every update
**by itself** — signature, provenance, anti-rollback — before applying it, with
no reach-back and no operator. This binary is that gate. It verifies **local
files only**; fetching them is the OTA caller's job (see *Caller integration*).

Authority-bearing BOMs describe the installed state, never the installer that
may carry them. Delegated USB verification binds the exact booted OS digest,
Fabric seed commit, signed bundle digest and image-attestation set. It refuses
`appliance.raw_sha256` and `appliance.caibx`: final installer raw/archive and
partition evidence is emitted only by the independent final-media gate after
assembly, avoiding an impossible self-hash cycle. That gate does not currently
bind `caibx`; this release path refuses to treat or distribute a chunk index as
verified media evidence until a separate digest-bound contract is implemented.

## The verification contract

Checks run in the order of the ICE-Fabric plan (§0,
private repo). Each check emits a distinct machine-readable entry; checks keep
running after a failure wherever their inputs allow, so a shadow-mode burn-in
log shows the full diagnostic picture:

| # | check           | refuses when                                                             |
|---|-----------------|--------------------------------------------------------------------------|
| 1 | `record_sig`    | channel-record signature invalid against the baked OTA root pubkey       |
| 2 | `bom_sig`       | BOM signature invalid against the baked OTA root pubkey                  |
| — | `record_parse`  | channel record unreadable / malformed JSON                               |
| — | `bom_parse`     | BOM unreadable / malformed JSON                                          |
| 2b | `bundle_digest` | OCI manifest digest pulled by the caller differs from the canonical `sha256:…` digest in the signed v2 record |
| 3 | `train_match`   | `record.train != bom.train`                                              |
| 4 | `seq_match`     | `record.bundle_seq != bom.bundle_seq` (signed channel↔bundle binding)    |
| 4b | `target_binding` | `record.hardware_target != bom.hardware_target`                         |
| 5 | `channel_match` | `record.channel !=` this device's channel                                |
| 5b | `hardware_target` | signed target differs from `/usr/lib/neural-ice/hardware-target`       |
| 6 | `anti_rollback` | `bom.bundle_seq < applied.bundle_seq`; **or** equal seq with a DIFFERENT BOM hash (two bundles claiming one seq = forgery signal). Equal seq with the **identical** BOM hash passes — the repair carve-out (re-apply of the exact current bundle). |
| — | `unseeded`      | replaces `anti_rollback` when no applied state exists yet: **shadow** = pass WITH warning (the first `commit` seeds it), **enforce** = refuse (enforcement is invalid on an unseeded device — the P3 seeding rule) |
| 7 | `compat_overlap`| `[bom.compat_min, bom.compat_version]` does not overlap the device's supported range |

Missing device-side inputs (device channel, compat range) follow the same
split as `unseeded`: skipped WITH a warning in shadow, refused in enforce.
A missing/empty OTA root pubkey fails the two signature checks (the staged
contract in `/etc/neural-ice/keys/README`) and unconditionally exits `1` — it
is an authenticity refusal, not an internal tooling error.

Signature verification is delegated to the image's version-pinned
`/usr/bin/cosign` (P0) — one verification stack, no crypto re-implemented:

```
cosign verify-blob --key <root_pubkey> --insecure-ignore-tlog=true \
    --signature <sig> <file>
```

(`--insecure-ignore-tlog=true` is private-infrastructure mode:
there is deliberately no public Rekor entry to check.)

Delegation snapshots additionally validate that every canonical uncompressed
P-256 SPKI contains a non-identity point on the curve. This public-key parsing
uses the exactly pinned `p256` 0.13.2 crate with default features disabled and
only its arithmetic feature; Cosign remains the sole signature verifier.

## Output and exit codes

`verify` prints exactly one JSON verdict line on stdout —

```json
{"verdict":"pass|refuse","checks":[{"name":"…","ok":true,"detail":"…"}],"enforce":false}
```

— plus a human summary on stderr, and mirrors the verdict to
`state_dir/last-verdict.json` (best effort) for the posture surface.

| exit | meaning |
|------|---------|
| `0`  | verdict `pass` — or a legacy/non-authority policy refusal in **shadow** mode (`enforce=0`) |
| `1`  | any authority refusal in every mode; any refusal in **enforce** mode (`enforce=1`); all `bootstrap` and `commit` refusals |
| `2`  | internal error (missing cosign, unreadable config, …) — **always**, in every mode: broken tooling never passes, and never masquerades as a clean refusal |

The shadow/enforce distinction affects only non-authority rollout checks such
as compatibility. Signatures, strict record/BOM parsing, signed
record-to-BOM bindings, device channel/target authorization, evaluated
anti-rollback state, and the observed-to-signed bundle digest are authority
checks and always exit `1` on failure in both modes. A deliberately unseeded
device or absent instance channel/compat input remains an explicit warning and
passing check in shadow, then refuses in enforce. Internal errors always exit
`2`; neither authority failures nor internal errors can become shadow success.

## Usage

```
ni-ota-verify verify --bom <path> --bom-sig <path> --record <path> --record-sig <path>
                     --bundle-digest <sha256:64-lowercase-hex>
                     [--config /etc/neural-ice/ota.conf] [--device-channel <ch>]
                     [--device-compat <min,max>] [--applied-state <path>]
ni-ota-verify bootstrap --bom <path> --bom-sig <path> --expected-train <train>
                        --current-os-ref <image@sha256:digest>
                        --current-seed-ref <40-hex-commit>
                        [--config …] [--device-compat <min,max>]
                        [--applied-state <path>]
ni-ota-verify commit --bom <path> [--config …] [--applied-state <path>]
ni-ota-verify verify-delegation-snapshot \
  --snapshot <path> --snapshot-sig <binary-DER-path> \
  --trusted-now <YYYY-MM-DDTHH:MM:SSZ> \
  [--accepted-snapshot <path> --accepted-delegation-seq <n> \
   --accepted-delegation-sha256 <64hex>] [--config …]
ni-ota-verify capabilities
```

Config (`/etc/neural-ice/ota.conf`) supplies `enforce`, `root_pubkey`,
`state_dir` and optionally `device_channel` / `device_compat_min` /
`device_compat_max`; flags override. A missing `enforce` key defaults to
**enforce** (an incomplete config leans strict, never silently log-only). The
hardware target comes from the immutable image marker, not a CLI override.

`capabilities` emits the bounded canonical JSON object
`{"schema":1,"features":["bundle-digest-v1"]}`. The appliance controller uses
this public compatibility handshake before any registry access; unknown output,
missing `bundle-digest-v1`, extra top-level keys or a non-zero exit must fail
closed. The feature states that `verify` requires and authorizes the signed OCI
bundle manifest digest rather than a mutable tag.

The reserved atomic-state TPM index is not itself a protocol capability.
`atomic-state-v1` remains deliberately absent until the same verifier binary
contains the complete pre-apply guard and post-health commit commands and the
installer provisions the attested index. Controllers must never infer atomic
state support from `state_nv_index` configuration or TPM index presence.

The later, complete stack may add the one exact negotiated response
`{"schema":1,"features":["atomic-state-v1","bundle-digest-v1"]}` in the same
change that updates the controller. A controller which understands that
response must treat `features` as a closed set, require `bundle-digest-v1`, and
use the atomic pre-apply and post-health flow whenever `atomic-state-v1` is
present. Older controllers continue to reject that response fail-closed.

The persistent atomic-state layout is closed. Under `${state_dir}/state-v1`,
`current` is exactly `generation-NNNNNNNNNNNNNNNN\n`, and
`enforce-ready.json` binds the current manifest and TPM anchor. Each
`generations/generation-NNNNNNNNNNNNNNNN` directory contains exactly the ten
manifest, state, signed-authority, release, and trusted-time files enumerated
by ADR-0012; no extra entry is accepted. JSON uses canonical encoding with one
final LF, signatures retain their exact bytes, and all entries are root-owned
with modes `0700` for directories and `0600` for files. Recovery and commit
share `.transaction.json.lock`, reread repaired pointers and the TPM before
success, and never lower a floor. An N-1 deployment may keep serving the
retained workload but cannot update or repair this state.

The immediate prior bootc deployment predates this command. A one-version OS
rollback therefore keeps the appliance running but intentionally disables new
registry-backed OTA checks: a non-zero capability probe remains fail-closed.
Recovery is to boot the retained newer deployment or use the separately signed
offline recovery path; a controller must not infer support by scraping usage
text or retry without the digest gate.

### ICE-Fabric ADR-0039 delegation-snapshot trust gate

`verify-delegation-snapshot` is the first device-side delegated-signing gate.
It accepts the exact closed Fabric v1 snapshot bytes only:
unknown or duplicate fields, non-canonical JSON, invalid P-256 SPKI pins,
non-minimal/high-S DER signatures, scope widening, cross-role/cross-ring use,
stale trusted time, snapshot split views and rollback all refuse in both shadow
and enforce modes.

The OTA root verifies only the domain-separated complete delegation snapshot.
Cosign receives protected root-only snapshots of the message, public key and
base64 transport form of the contract's binary DER signature; the authority
signature remains the binary low-S DER artifact.

`verify-delegation-snapshot` always requires the accepted complete snapshot
plus the sequence and canonical hash read from the trusted state
backend are required; this slice deliberately defines no new persisted schema:
the verifier permits an identical retry or exactly `N+1`, checks the previous
canonical hash, preserves tombstones, and prevents retained keys from widening
scope or validity. Multi-snapshot offline catch-up and atomic TPM-backed
delegation-state persistence are deliberately subsequent slices; this command
does not authorize a release, publish a channel, or mutate accepted state.

The sole unseeded exception belongs to the distinct physical
`verify-delegated-usb` path. It is explicitly bound to both the immutable
`/usr/lib/neural-ice/ota-min-delegation-seq` and the exact canonical snapshot
hash in `/usr/lib/neural-ice/ota-bootstrap-delegation-sha256`, and additionally
requires the signed debug target/release/media bindings. A missing, malformed,
or different immutable hash fails closed. Omitting accepted state from the
generic or network verifier is always an authority refusal.

The physical USB command never accepts caller-provided `--accepted-*` state.
Those values are not a trusted persistence boundary and supplying any of them
is an authority refusal; the unseeded USB path always evaluates the exact
image-baked epoch.

The vanilla ICE-CoreOS image intentionally does not choose or embed a Neural
ICE product delegation epoch. The private, branded ICE-Fabric product layer
owns that immutable marker and the matching public snapshot/signature bytes;
it must materialize all three in the final appliance image before an installer
can use this unseeded path. A vanilla image without the product marker remains
usable as a base OS but cannot bootstrap product update authority.

Owner authorization for this gate is recorded in the 2026-07-20/21 task by
the explicit decisions `GO signed-boot LAB debug ... gate LAB/PROD #37`,
`GO ADR délégation OTA v2 — racine offline uniquement pour
délégation/révocation/secours`, and `GO parcours opérateur simplifié —
cérémonie root-only, bootstrap KMS automatisé`. These approvals cover the
delegated trust model and its local verifier only; they authorize no channel
movement.

The closed snapshot contract also reserves a distinct `trusted-time` role for
canonical assertions issued by `licensing.example.test`. It cannot sign images,
releases, receipts or channels. On first bootstrap, the immutable root may
authenticate the physically delivered candidate snapshot before trusted time is
available; the snapshot is accepted only in the later atomic transaction after
an assertion under that candidate's scoped time key proves the snapshot current.
The verifier hashes the supplied canonical snapshot bytes itself, accepts an
`active` or bounded-overlap `retiring` time key, and binds the assertion to the
locally observed TPM safe bit. At consumption it re-reads the TPM tuple:
reset/restart counts must be unchanged, the clock must be monotonic and signed
`valid_until` must remain strictly in the future after conservatively rounded
TPM elapsed time. A delayed response therefore cannot revive expired time.
Subsequent rotations must chain from the persisted snapshot and floors. An N-1
rollback keeps the installed deployment bootable but cannot authorize a new
trusted-time update until the newer state-capable verifier is restored. Loss,
expiry or reset therefore denies only new updates and never lowers accepted
authority, applied-bundle or time floors. The atomic persistence and one-time
freshness mechanism are implemented in the stacked state-v1 change, not by this
contract-only slice.

The separate `licensing-bootstrap` role is closed to
`ota-licensing-bootstrap-v1` and `ota-licensing-recovery-ack-v1`, for both
release rings and every supported hardware target. Snapshot acceptance records
that scoped recovery authority only; it grants no image, release, receipt, or
channel authority.

Recovery is fail-closed but does not stop the installed release. An unavailable,
expired, malformed or rollback snapshot leaves the last accepted snapshot and
the running bootc deployment untouched and denies only the candidate update.
The offline root recovers by signing exactly the next snapshot, chained to the
last accepted canonical hash; compromise recovery tombstones the affected key
in that successor and installs a separately scoped replacement. Sequence floors
are never lowered and accepted history is never deleted. For a one-version OS
rollback, this slice adds no persisted schema and mutates no delegation state,
so the retained prior deployment remains bootable with the existing state. Its
verifier predates the capability handshake, so new OTA remains blocked until
the newer deployment or signed offline recovery path is restored. Recovery of
a newer candidate resumes only after a valid root-signed successor satisfies
both that history and the image-baked minimum. Root-anchor rotation itself is
outside this gate and requires a separately approved image/trust-anchor
transition; accepted snapshot chains keep the immutable root unchanged.

The first epoch-aware debug installer is the transition baseline: no production
device predates it. A rollback to a deployment containing the earlier verifier
keeps the already installed workload bootable, but that verifier must not be
used to authorize a fresh physical bootstrap. Physical recovery during this
transition boots the current signed installer media, whose branded product
layer contains the fixed epoch marker and epoch-aware verifier. After the next
train, the retained N-1 deployment is itself epoch-aware, so normal one-version
rollback preserves this pin. Neither transition path moves a release channel
or lowers accepted delegation state.

`prepare-trusted-time-v2` is the networkless appliance-side preparation step.
It accepts `--snapshot`, `--snapshot-sig`, `--release` and `--release-sig`,
freezes each caller-controlled file as a bounded stable regular file, and
verifies the root and release signatures before writing anything persistent.
The release must match the immutable hardware target, immutable
`debug|prod` appliance variant and beta ring. During a bounded rotation both
`active` and `retiring` release-beta keys remain eligible; all other statuses
refuse. A nonzero TPM state anchor must resolve to one complete generation.
On a clean install the command reads the dedicated non-exportable TPM
device-root at `0x81010005`, provisioned and attested by the installer and
`neural-ice-device-root.service` under ADR-0013; it never reads the appliance
PKI root at `0x81010004`. A missing or malformed device-root is an internal
TPM prerequisite failure (exit `2`) and cannot produce a challenge.

Success atomically replaces the canonical mode-`0600`
`state_dir/state-v1/pending-time-challenge.json` and prints the same challenge
for the controller to send to the allowlisted licensing service. Replacement
supersedes an abandoned attempt but advances no authority, time or bundle
floor. The later transaction must consume the exact challenge; a crash or an
N-1 rollback may leave it unread, but cannot turn it into update authority.
The controller can retry preparation after restoring the current verifier.
Malformed candidate files are refusals (exit `1`); local storage, TPM and
verifier failures are internal errors (exit `2`).

`verify-delegated-beta` composes that same root/chain gate with independently
domain-separated `release-beta` signatures for the closed beta release and its
publication receipt. It requires exact snapshot, target, train, BOM,
attestation, channel-record, compatibility range, bundle sequence,
release-envelope hash and resolved OCI manifest-digest bindings. The release
and receipt issuance times must lie inside both the snapshot and delegated-key
validity windows; the receipt must have been observed during the release
validity window, and both authorities must also be current and explicitly
scoped to this immutable target and beta artifact. Tags remain
non-authoritative; this command returns the signed resolved manifest digest and
does not move a channel or persist state.

The device must explicitly carry `device_channel=beta`; an absent or different
channel is an authority refusal in every mode. The signed release variant must
also equal immutable `/usr/lib/neural-ice/appliance-variant`, written from the
validated `debug|sealed-lab|prod` build argument. This prevents a signed debug
release from entering a sealed production host. A missing or malformed immutable
marker is broken image tooling (exit `2`), never a shadow-mode bypass.

The variant equality above is NOT, by itself, what preserves the ACCESS POLICY
across an OTA. It was believed to be (`docs/ADR-0014-access-policy-lab-vs-customer.md`),
on the premise that the variant → policy mapping is a total function, so equal
variants imply an equal policy. That premise is a property of the SOURCE TREE
(`image/lib/access-policy.sh`), not of anything signed: a later, correctly
signed, SAME-VARIANT release can rewrite the mapping — or the marker — and the
host's access posture changes with no signature ever having stated the old one.

`docs/ADR-0015-installer-trust-anchor-uki-verity.md` closes it, and it needs
**two new fields from ICE-Fabric** plus **one new argument from the caller**:

> **`access_profile`** on the release authorization — REQUIRED, one of
> `lab-managed` | `customer-locked` | `developer-diagnostic`, and it must be the
> value the release's own `variant` derives (`prod` → `customer-locked`,
> `sealed-lab` → `lab-managed`, `debug` → `developer-diagnostic`). A release
> whose two fields disagree is refused as an internally inconsistent signed
> statement.
>
> **`access_policy_sha256`** on the release authorization — REQUIRED, the
> SHA-256 of the CANDIDATE deployment's own
> `/usr/lib/neural-ice/access-policy` file. Spelled as ICE-Fabric's
> `neural-ice-ota-release-authorization-v1` schema spells it, so one fact does
> not acquire two names.
>
> **`--candidate-root <path>`** on `verify-delegated-beta`,
> `verify-delegated-usb`, `guard-state-v2` and `commit-state-v2` — REQUIRED, the
> root of the staged deployment being judged.

Both fields are required rather than optional, and the document keeps
`deny_unknown_fields`, so a producer that omits either is refused rather than
defaulted. That is deliberate: an optional field falling back to the variant
mapping would reinstate the exact premise it replaces, silently. **Until
ICE-Fabric emits them, no delegated release verifies.** Nothing is in production.

This OTA-v1 authorization is distinct from the installer contract sealed into
the signed UKI. Installation accepts only the closed, exactly 14-field
`neural-ice-installer-release-authorization-v2`: it declares either
`single-manifest` or `index`, preserves Fabric's signed `issuance_seq` unchanged,
and advances the TPM absolute high-water only from mandatory first boot after
the install commit. See
`docs/ADR-0015-installer-trust-anchor-uki-verity.md`; neither contract aliases or
silently upgrades the other.

Every delegated path — *and* the two state-v2 commands, which previously skipped
this entirely — then compares that value against the profile ENROLLED AT INSTALL
TIME: written into the stateroot, outside the candidate deployment, and signed by
the TPM device root at `0x81010005`
(`ota/neural-ice-access-profile-anchor.sh`, `src/access_profile_anchor.rs`).

**Why `access_policy_sha256` as well.** `access_profile` is a word in a signed
JSON; the appliance boots with a FILE. A same-variant candidate could ship a
widened `/usr/lib/neural-ice/access-policy` while its signed release kept the old
profile, pass every comparison, and change the appliance's posture on the next
boot. The verifier therefore reads the marker out of `--candidate-root`, requires
its hash to be the authorised one, and requires its CONTENT to be the enrolled
profile.

**Why the TPM is interrogated live.** The anchor, its signature, its SPKI and the
device-root identity all live in `/var`, so a coherent bundle copied from another
appliance satisfied every file comparison. The verifier makes the device root at
`0x81010005` **sign a fresh nonce** — a private key that never leaves a TPM
cannot do that on a second machine — and requires `anchor_seq` to equal the
machine's monotonic install counter in TPM NV `0x01500003`
(`ota/neural-ice-tpm-state.sh`). No TPM, no counter, a foreign key or a key
that will not sign are all refusals; there is no branch where absent evidence
means "carry on".

**Why the device-root signature is not the profile's AUTHORITY** (review
2026-09-01). That key has `userwithauth` and an **empty authorization policy**,
so anything running as root on the appliance can make it sign — including a
replacement anchor carrying a different `access_profile` at the current counter
value. The liveness challenge does not help: it proves the key is usable on this
machine, which is exactly what such an attacker also enjoys.

The profile is therefore bound to a **write-once, policy-protected TPM NV
record** at `0x01500005`, written and locked only by the mandatory first-boot
ceremony after the installer has persisted the device root and intended SRK:

| field | bytes | meaning |
| --- | --- | --- |
| magic | `0..8` | `NI-TPM02` |
| profile binding | `8..40` | `sha256("neural-ice:tpm:access-profile-binding:v1" ‖ 0x00 ‖ profile ‖ 0x00 ‖ hardware_target ‖ 0x00 ‖ signed_boot_trust_policy_id)` |
| reserved | `40..64` | zero |

Index contract, asserted before the content is read:

* attributes `policywrite|writedefine|ownerread|authread` (`0x62008`, with the
  TPM's own `WRITELOCKED`/`READLOCKED`/`WRITTEN` bits masked out) — **no
  `ownerwrite`, no `authwrite`**;
* authorization policy `PolicyOR(PolicyCommandCode(NV_Write),
  PolicyCommandCode(NV_WriteLock))` =
  `f83217e5a2a04342f7daa55ccfb3cd4b8a1f1e8ebb28c7719a9abbdbd638a230`;
* written once and immediately `NV_WriteLock`ed; `writedefine` makes that lock
  permanent for the life of the index, across TPM restarts.

`enrolled_access_profile()` requires the anchor's `(access_profile,
hardware_target, signed_boot_trust_policy_id)` triple to hash to that record. An
index that is absent, redefined with weaker attributes, or under a different
policy is a refusal — reading content without checking shape would hand an
attacker exactly the authority the record exists to remove.

Before the ceremony, any existing or partial fixed state is a refusal rather
than an idempotent success. The ceremony replaces owner authorization with 32
random bytes and retains no copy; after it completes, runtime root cannot
undefine/redefine the indices or evict/recreate the persistent objects. The
freshness high-water is the absolute value of `0x01500004`, and runtime never
creates missing state. Legitimately changing what an appliance is requires a
**TPM clear with physical presence** followed by a reinstall from signed media —
`docs/ADR-0015-installer-trust-anchor-uki-verity.md` §"Amendment, 2026-09-01" §D
documents the operator procedure.

A mismatch, an absent anchor, a non-canonical one, one signed by another
machine's device root, one whose sequence is not this machine's current install,
or a candidate whose own marker disagrees is refused with **"reinstall
required"** — deliberately not "re-enrol": a profile change is a change of what
the appliance *is*, and the only honest path back is signed physical media.
`tests/cli.rs` proves all of it against REAL ECDSA P-256 and a mocked TPM that
signs with the same real key — including a perfectly signed, live, current anchor
whose profile the TPM record does not back, an absent record, a record redefined
with weaker attributes, and one under a different policy.
`ci/test-swtpm-monotonic-state.sh` proves the index contract itself against a
real TPM 2.0.

The beta publication receipt needs no new field: it binds the release by
SHA-256, so it binds both fields transitively.

The device compatibility range is compared with the signed release range.
Unknown or disjoint compatibility refuses when `enforce=1`; during an explicit
shadow rollout (`enforce=0`) it emits a warning while all authority, signature,
digest, ring and target failures continue to refuse. Owner authorization is
recorded by the delegation-v2 and simplified-KMS decisions above plus `GO
bundles OCI adressés par digest v1 — bundle_digest dans le record signé, pulls
appliance exclusivement par digest`; no approval in this slice moves a channel.

Receipt recovery also preserves service. An expired receipt, revoked signing
key, or unavailable/invalid delegation snapshot denies only the candidate and
leaves the running deployment untouched. For expiry, automation may issue a
fresh authorization and receipt only for the same immutable evidence or a new
train under the current delegated key. For compromise, the offline root first
publishes the next hash-chained snapshot with a tombstone and replacement key;
the replacement then reissues both beta artifacts. It never reuses the revoked
identity or lowers sequence state. A one-version rollback uses the already
retained, previously accepted bootc deployment and does not reinterpret an
expired receipt as new authorization. This command persists no state, so the
prior verifier/state format remains usable and rollback cannot erase accepted
delegation history.

`verify-delegated-usb` is the local, receipt-free verification surface for the
physically delivered debug installer. It accepts no URL, channel tag or shell
hook. It verifies the exact root-signed delegation snapshot, exact release-beta
signature, and detached image-ci signature over the canonical image-attestation
set, then binds the release to the raw BOM and channel record bytes, observed
OCI bundle digest, immutable hardware target, immutable `debug` variant,
booted OS digest ref, installed `PAYLOAD_ID`, beta channel, compatibility
range, train and bundle sequence. The channel record is evidence carried inside
the immutable USB bundle; the command cannot fetch or repoint it. Missing receipt evidence is
intentional for this physical bootstrap only and is never accepted by the
network beta verifier.

The image-ci signature uses the domain
`neural-ice:ota:image-attestation-set:v1` over the complete canonical set. All
first-party rows in one set must name the same authorized image-ci key. This
turns their exact image-signature, provenance and SBOM digests into one
independently authenticated envelope: a compromised release-beta key cannot
fabricate those proof identities. Mixed image-ci authorities, an absent
first-party row, or a missing/invalid detached signature fails closed.

The delegated beta/USB commands remain verification-only and are composed with
the atomic-state v2 commands. The controller first calls
`prepare-trusted-time-v2` with the exact root-signed snapshot and signed
release. It sends the returned canonical challenge to the licensing service,
then supplies the short-lived signed assertion to `guard-state-v2` before any
apply. After apply and health pass it calls `commit-state-v2` with the same
immutable proof files. A different/replayed challenge, changed TPM continuity,
or changed release bytes refuses.

`commit-state-v2` persists accepted authority (complete snapshot, signature,
sequence and hash), applied bundle (sequence and exact BOM hash), and trusted
time/TPM continuity as one fsynced generation before extending the state NV
index. Only complete TPM readback consumes the nonce and reports enforcement
ready. Exact crash retry is idempotent; rollback can boot N-1 but never lowers
the retained floors. The verifier performs no network access and none of these
commands resolves or changes a release channel.

The installer assembly pipeline has a separate final-image boundary: after all
payload copies complete, it must mount the final raw image read-only and compare
the exact model manifest, model symlink targets, seed image inventory and
`PAYLOAD_ID` with the signed source inputs before signing the installer. This
post-build hook belongs after `build-preloaded.sh`, never before its copy step;
it changes no OTA schema or channel.

An absent configured `state_dir` is created component by component as mode
`0700`, with every new directory and parent entry synced before use. An
existing directory must already be a real mode-`0700` directory; `verify`
warns and skips its best-effort verdict mirror rather than chmod-repairing an
insecure directory. Every path component is resolved descriptor-relative with
no symlink following; `..`, untrusted owners, and replaceable non-sticky
ancestors are rejected. A root-owned sticky directory such as `/tmp` is only
accepted when the next entry belongs to root or the verifier's EUID. For an
explicit relative `--applied-state applied.json`, `commit` may use an existing
current directory that is not group/world-writable and never changes its mode.
`bootstrap` always requires its state parent to be exactly mode `0700`.

The sole compatibility exception is evaluated by `commit`: the exact legacy
production directory `/var/lib/neural-ice/ota`, if it already exists as a
real root-owned directory with exact mode `0755`, is migrated once to `0700`
through its no-follow directory descriptor and synced before the lock is
opened. No custom path or other mode/owner is repaired. `verify` and
`bootstrap` never perform this migration. The previous root-run verifier can
continue using the more restrictive `0700` directory, so a one-version bootc
rollback does not require reversing the permission migration.

### Signed LAB USB baseline bootstrap

`bootstrap` is the one-time bridge from a physically delivered, signed LAB USB
image to the normal anti-rollback state. It consumes only the signed BOM and
its detached signature: it neither accepts nor creates a channel record and
cannot move a `beta`, `stable`, or product alias. It is exclusively an offline
installation-media path; a registry-backed update must use the signed v2
record and the normal `verify` gate below.

The command always fails closed, including when `ota.conf` has `enforce=0`. It
copies the BOM once to a protected mode-`0600` snapshot, verifies that snapshot
against `root_pubkey`, and parses and hashes the same protected inode. It then
binds all of the following before creating any state:

- `train == --expected-train`;
- BOM `hardware_target` equals the immutable host marker;
- the BOM/device compatibility ranges overlap;
- BOM `appliance.os_base.image@digest == --current-os-ref` (the digest-pinned
  image reported as booted by `bootc status`);
- BOM `sources.seed.ref == --current-seed-ref` (the installed immutable
  `PAYLOAD_ID`).

On a genuinely absent `applied.json`, it durably publishes
`{bundle_seq,bom_sha256}` as mode `0600` with create-if-absent semantics. The
state parent must already be a real directory; for the production root caller,
it must be root-owned mode `0700`. Symlink and non-regular state paths are
refused. A retry for the exact same signed BOM succeeds idempotently after
metadata and content readback, covering a caller crash after publication.
Existing different state, corrupt state, malformed identity inputs, signature
failure, or any binding mismatch is refused without overwriting the state.

Bootstrap and commit serialize the complete state transaction (snapshot,
read/check, publication, and readback) with one exclusive `flock` on a
mode-`0600` inode beside `applied.json`. The inode can remain after a run, but
the lock owner exists only in the kernel and is released on descriptor close or
process crash; there is no stale PID/lock-directory recovery path. `bootstrap`
still requires its secure parent to exist. For compatibility, `commit` may
create an absent custom parent, but it creates it mode `0700` and attests that
it is a real directory (and root-owned for the production root caller) before
opening the lock or state.

Example for a factory/LAB service that has independently read the local booted
identity and installed payload identity:

```sh
ni-ota-verify bootstrap \
  --bom /run/neural-ice/bootstrap/0.44.18.bom.json \
  --bom-sig /run/neural-ice/bootstrap/0.44.18.bom.sig \
  --expected-train 0.44.18 \
  --current-os-ref registry.example.test/neural-ice/neural-ice-appliance@sha256:<64hex> \
  --current-seed-ref <40hex> \
  --device-compat 5,5
```

`commit` records `{bundle_seq, bom_sha256, bom_format}` in
`state_dir/applied.json` **after** the caller's health gate passes, with
`bom_format` fixed to `"media-independent-v1"` (the ADR-0012 baseline format
marker). It refuses (exit 1) any BOM that would lower the recorded seq, an
equal seq with a different hash, and any existing baseline without the
media-independent marker (media-era record — reinstall, no implicit
migration); an equal seq with the identical hash re-commits idempotently
(repair). Bootstrap and
commit both consume protected BOM snapshots and share the same durable writer:
unique mode-`0600` temporary inode, file sync, atomic publication, directory
sync, then metadata and content readback before success is reported.

### Owner authorization, recovery, and one-version rollback

This LAB-only change is covered by the Owner approvals recorded on
2026-07-19: **`GO signed-boot LAB debug sur .72 + policy
neural-ice-secureboot-lab-v1 + gate LAB/PROD #37 — aucun déplacement de canal`**
and **`GO correction staging CoreOS`**. It does not publish, promote, or move a
`beta`, `stable`, or product alias.

Recovery is fail-closed and forward-only:

- a failure before the atomic state publication leaves the device unseeded and
  the exact signed bootstrap can be retried;
- a crash after publication but before the receipt leaves the exact durable
  state, so the same signed bootstrap completes idempotently;
- a process crash while holding the transaction lock releases the kernel lock;
  the persistent mode-`0600` lock inode is harmless on the next invocation;
- the one-time legacy `0755` directory migration is idempotent: interruption
  before the descriptor-relative chmod leaves `0755` for a retry; interruption
  after it leaves the already-secure `0700` directory, which is synced and
  re-attested on the next `commit`. It never modifies state file contents;
- outside that exact legacy directory-mode carve-out, corrupt, insecure, or
  different existing state is never deleted or silently reseeded. Boot
  recovery media, preserve evidence, diagnose the state, then repair with a
  newly signed train whose sequence is strictly higher.

For one-version rollback, the health gate remains before `commit`. If install
or health fails, the caller rolls the bootc deployment back one version while
the prior applied-state sequence remains unchanged. Once `commit` succeeds,
booting an older payload does not lower that sequence and verification refuses
the older BOM; recovery is a forward repair with a higher signed sequence (or
the existing equal-sequence, byte-identical BOM repair carve-out). Thus neither
bootstrap nor concurrent commits can regress the anti-rollback state.

## Release-manifest v1 planner (`release-plan`)

A **pure reader**: two already-authenticated manifests in, one plan out. It
downloads nothing, stages nothing, activates nothing, and never runs `bootc` or
a reboot. `required_entitlement` is carried as a signed fact for a later gate —
reading it is not enforcing it. Signature verification stays where it already
is (`verify`, `verify-delegated-*`); this subcommand assumes its inputs were
authenticated by the caller.

### One contract, not two

The authority is the Owner-approved ICE-Fabric consumer pack copied exactly
under `tests/fixtures/release-manifest-v1/producer/`. `PIN.json` binds the
producer base, schema, parser, classifier, generator, and consumer-pack hashes.
The pack hash consumed by this revision is
`sha256:a2c7a55b52c106a6d5230c3186b8f0685ca4545822b8a96ba9198856f6ef01a0`.
CoreOS does not define a dialect of it. Concretely:

- the sequence field is `bundle_seq`. There is no `release_seq`, and no alias
  for one — an alias would be a second manifest grammar under one signature;
- classification is exactly `no-op`, `component-content`, `host`, `refusal`.
  Components and content share **one** class, so a bundle touching both still
  has an engine;
- the configured registry authority is required and strict generic OCI host
  syntax; both `(neural-ice|vendor)/...` namespaces remain first-class;
- DNS hosts are bounded at exactly 253 ASCII characters (the optional port is
  outside that bound), and a trailing dot is not canonical;
- IPv4-mapped IPv6 is admitted only in the producer's lowercase compressed
  hexadecimal form, such as `[::ffff:c000:201]`; dotted mapped forms are
  refused rather than normalized;
- identity is the SHA-256 of the **canonical** bytes (sorted keys, compact
  separators, normalized set-like arrays, one trailing LF), never of the input
  bytes. Re-indenting a manifest must not mint a new release. That hash is
  computed in-process, so nothing on `PATH` can influence anti-rollback;
- the identifier and systemd-unit grammars mirror Fabric's patterns exactly,
  including the 128-byte identifier bound and the unit's 128-byte **stem** bound
  and "stem ends alphanumeric" rule (`foo-.service` is refused);
- `compatibility`, `evidence`, `required_entitlement`, `restart_scope` and
  `reboot_required` are required fields, not optional extras.

### Semantics

Every host, component, and content repository in both manifests is validated
against the required configured registry authority before compatibility,
sequence, or transition classification. Missing, malformed, foreign, or mixed
authorities refuse. Both manifests are then checked against the device (`hardware_target`,
`minimum_reader` vs the reader version, `required_contracts` vs what the device
supports) before any transition is considered. `bundle_seq` is anti-rollback:
strictly lower refuses, and equality is admitted **only** for the byte-identical
canonical manifest — a re-apply, never a different release wearing the same
sequence.

Without an explicit host payload delta only digests may move; a membership or
contract change refuses and asks for the host engine. A `compatibility` edit on
its own is still a host transition, so it cannot smuggle a structural change
past that requirement.

`restart_scope` on a replacement is the union of the **installed** and
**candidate** payload scopes: the units that must be stopped as well as the ones
that must be started. `reboot_required` is the OR over the same set.

### Usage

```
ni-ota-verify release-plan --current <path> --candidate <path> \
    --registry-host registry.example.test \
    --hardware-target nvidia-gb10-arm64 --reader-version 1 \
    --supported-contracts host-bootc-v1,component-oci-v1,content-oci-v1
```

Registry authority and device capability are passed explicitly and never
defaulted or sniffed from the environment, so an operator can reproduce a
device's plan off-device from the same two files.
The canonical plan document goes to stdout in every case — on a refusal the
reason is the useful part. Exit codes follow the binary's contract: `0` a
transition was classified, `1` the contract refused it, `2` tooling failure.

### Exact producer consumer pack

The `producer/consumer-pack/release-manifest-v1.json` handoff and every referenced
schema/input/canonical/planner vector are exact Fabric bytes. Rust source tests
verify every declared hash, canonical parser result, strict refusal text, and
configured-host plan. `tests/registry_host_cli.rs` repeats the planner cases
through the real binary and proves that an environment variable cannot replace
the required `--registry-host` argument.

The copied producer procedure is standard-library Python and regenerates the
CoreOS-owned copy in place. Run it twice; both runs must leave no diff:

```bash
python3 tools/ni-ota-verify/tests/fixtures/release-manifest-v1/producer/generate_vectors.py
git diff --exit-code -- tools/ni-ota-verify/tests/fixtures/release-manifest-v1/producer
python3 tools/ni-ota-verify/tests/fixtures/release-manifest-v1/producer/generate_vectors.py
git diff --exit-code -- tools/ni-ota-verify/tests/fixtures/release-manifest-v1/producer
```

Regeneration does not refresh `PIN.json`: moving any producer input or pack hash
is a contract update requiring an explicit repin, not a silent fixture refresh.

## Caller integration (the OTA path, ICE-Fabric side)

```
oras pull <registry>/<channel_ref>:<hardware-target>-<device-channel> # signed v2 channel record + .sig
oras pull <registry>/<bundle_ref>@<record.bundle_digest>  # signed BOM + .sig; never :<train>
ni-ota-verify verify --bom … --bom-sig … --record … --record-sig … \
    --bundle-digest <digest reported for the pulled OCI manifest>     # THE GATE
    → apply strictly by the digests in the verified BOM (never by tag)
    → health gate (NRestarts / is-active)
ni-ota-verify commit --bom …                              # only after health passes
```

`oras` (fetch) and `cosign` (verify) are both version-pinned in the OS image
(`image/Containerfile.bootc` §2b).

The v2 channel record has exactly these keys: `assigned_at`, `bundle_digest`,
`bundle_seq`, `channel`, `hardware_target`, `key_version`, `schema_version`,
and `train`. `schema_version` must be `2`; `channel` is `beta` or `stable`; and
`bundle_digest` must be exactly `sha256:` followed by 64 lowercase hexadecimal
characters. Missing fields, extra fields, legacy v1 records, non-canonical
digests, and a pulled-manifest mismatch all refuse. A release-train tag is a
publication/diagnostic convenience only and is never reconstructed or pulled
by the device.

## P3 roadmap — the state-backend seam

The applied state is read/written behind the `AppliedStateStore` trait
(`src/state.rs`). P2 backend: the `applied.json` file. P3 replaces it with the
TPM2 NV index (tpm2-tools, already in the image; `nv_index` already in
ota.conf), seeded from the P2 record — a new store impl, not a logic change.
`commit` gains the NV write at the same seam.

## Development

```
umask 077                                   # REQUIRED — see below
export NI_TRUSTED_TIME_ISSUER=trusted-time.example.test   # REQUIRED — see below

cargo test --locked --all-targets           # default-feature unit tests
cargo test --locked --features test-path-overrides  # unit + CLI tests; cosign is stubbed
```

`NI_OTA_COSIGN` (the cosign stub the CLI tests inject) exists only in the
`test-path-overrides` build, and even there only for an unprivileged process
outside a release image (`/usr/lib/neural-ice/release-image` absent). The
default build the OS image ships never reads it and does not contain its name:
`cargo test --locked` proves the environment is ignored through the real
`verify_seed` entry, and CI greps the release binary for the string.

```
cargo fmt --check && cargo clippy --all-targets --locked -- -D warnings
```

Both environment settings are load-bearing, not decoration:

- **`umask 077`** — the CLI tests build their fixtures under `TMPDIR`. Under a
  **group-writable** umask (`0002`, the default on Debian/Ubuntu user accounts)
  the verifier correctly fail-closes on a state directory reachable through a
  group/world-writable parent, and **37 of the 66 CLI tests fail** for that
  reason alone. That is the control working, not a regression. Measured on this
  tree: `umask 0002` → 37 failed; `umask 022` → 0 failed; `umask 077` → 0
  failed. Any non-group-writable umask suffices; CI gets one from running
  containerized as root.
- **`NI_TRUSTED_TIME_ISSUER`** — deliberately a wrong, neutral value. The suite
  must prove the contract, not the identity of a deployment; the real authority
  comes from the repository configuration at image build time.

Dependencies are deliberately minimal. The direct ones are exactly four —
`p256` (P-256 public-key handling for the delegation snapshot), `serde`,
`serde_json` and `sha2` — plus std. No async runtime and no network crates:
fetching is the OTA caller's job. `Cargo.lock` is committed so the in-image
build (`--locked`, static crt-static) stays reproducible.

`sha2` (MIT OR Apache-2.0) exists for exactly one caller: the release-manifest
canonical digest, which is hashed in-process. Every other artifact hash still
shells out to coreutils. The asymmetry is deliberate — that one digest decides
anti-rollback, so resolving `sha256sum` through `PATH` would let a planted
binary return a constant, collapse two different manifests onto one digest and
classify a divergence as `no-op`. Signature crypto remains the pinned cosign.
