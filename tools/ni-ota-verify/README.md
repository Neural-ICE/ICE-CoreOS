# ni-ota-verify

On-device OTA bundle verifier for Neural ICE appliances (ICE-Fabric,
decision D3: the verifier lives in this open-core OS repo — generic
"verify signed bundle manifest + anti-rollback" logic, zero product IP; only
the keys are secret).

The appliance is treated like a game console: it must verify every update
**by itself** — signature, provenance, anti-rollback — before applying it, with
no reach-back and no operator. This binary is that gate. It verifies **local
files only**; fetching them is the OTA caller's job (see *Caller integration*).

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

The immediate prior bootc deployment predates this command. A one-version OS
rollback therefore keeps the appliance running but intentionally disables new
registry-backed OTA checks: a non-zero capability probe remains fail-closed.
Recovery is to boot the retained newer deployment or use the separately signed
offline recovery path; a controller must not infer support by scraping usage
text or retry without the digest gate.

### ADR-0039 delegation-snapshot trust gate

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
`verify-delegated-usb` path. It is explicitly floor-bound to the immutable
`/usr/lib/neural-ice/ota-min-delegation-seq` and additionally requires the
signed debug target/release/media bindings. Omitting accepted state from the
generic or network verifier is always an authority refusal.

Owner authorization for this gate is recorded in the 2026-07-20/21 task by
the explicit decisions `GO signed-boot LAB debug ... gate LAB/PROD #37`,
`GO ADR délégation OTA v2 — racine offline uniquement pour
délégation/révocation/secours`, and `GO parcours opérateur simplifié —
cérémonie root-only, bootstrap KMS automatisé`. These approvals cover the
delegated trust model and its local verifier only; they authorize no channel
movement.

The closed snapshot contract also reserves a distinct `trusted-time` role for
canonical assertions issued by `licensing.neural-ice.ch`. It cannot sign images,
releases, receipts or channels. On first bootstrap, the immutable root may
authenticate the physically delivered candidate snapshot before trusted time is
available; the snapshot is accepted only in the later atomic transaction after
an assertion under that candidate's scoped time key proves the snapshot current.
Subsequent rotations must chain from the persisted snapshot and floors. An N-1
rollback keeps the installed deployment bootable but cannot authorize a new
trusted-time update until the newer state-capable verifier is restored. Loss,
expiry or reset therefore denies only new updates and never lowers accepted
authority, applied-bundle or time floors. The atomic persistence and one-time
freshness mechanism are implemented in the stacked state-v1 change, not by this
contract-only slice.

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
validated `debug|prod` build argument. This prevents a signed debug release
from entering a sealed production host. A missing or malformed immutable marker
is broken image tooling (exit `2`), never a shadow-mode bypass.

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

The command is verification-only. A pass prints the complete facts needed by
the future bootstrap transaction, but does not write `applied.json`, accept a
delegation snapshot or establish trusted time. Initial bootstrap remains
blocked until the separately reviewed atomic-state implementation persists
three records together: accepted authority (complete canonical snapshot +
sequence + hash), applied bundle (sequence + exact BOM hash), and trusted-time
continuity for new updates. A crash may never expose applied state without its
authority and time anchors; a one-version rollback must read the prior applied
record without discarding either new anchor. Until that implementation and its
media gates land, callers must treat this verdict as diagnostics, not
installation authorization.

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
  --current-os-ref registry.neural-ice.ch/neural-ice/neural-ice-appliance@sha256:<64hex> \
  --current-seed-ref <40hex> \
  --device-compat 5,5
```

`commit` records `{bundle_seq, bom_sha256}` in `state_dir/applied.json`
**after** the caller's health gate passes. It refuses (exit 1) any BOM that
would lower the recorded seq, and an equal seq with a different hash; an equal
seq with the identical hash re-commits idempotently (repair). Bootstrap and
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
cargo test --locked --all-targets           # default-feature unit tests
cargo test --locked --features test-path-overrides  # unit + CLI tests; cosign is stubbed
cargo fmt --check && cargo clippy --all-targets --locked -- -D warnings
```

Dependencies are deliberately minimal (`serde`, `serde_json`, std — no async
runtime, no network crates); `Cargo.lock` is committed so the in-image build
(`--locked`, static crt-static) stays reproducible.
