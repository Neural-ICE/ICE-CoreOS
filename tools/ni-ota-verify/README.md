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
contract in `/etc/neural-ice/keys/README`) — it is a verification failure,
not an internal error.

Signature verification is delegated to the image's version-pinned
`/usr/bin/cosign` (P0) — one verification stack, no crypto re-implemented:

```
cosign verify-blob --key <root_pubkey> --insecure-ignore-tlog=true \
    --signature <sig> <file>
```

(`--insecure-ignore-tlog=true` is private-infrastructure mode:
there is deliberately no public Rekor entry to check.)

## Output and exit codes

`verify` prints exactly one JSON verdict line on stdout —

```json
{"verdict":"pass|refuse","checks":[{"name":"…","ok":true,"detail":"…"}],"enforce":false}
```

— plus a human summary on stderr, and mirrors the verdict to
`state_dir/last-verdict.json` (best effort) for the posture surface.

| exit | meaning |
|------|---------|
| `0`  | verdict `pass` — **or** verdict `refuse` in **shadow** mode (`enforce=0`): shadow is log-only, the caller decides nothing on the exit code |
| `1`  | verdict `refuse` in **enforce** mode (`enforce=1`) — do not apply. `bootstrap` and `commit` refusals also exit 1 (state mutation is always enforced) |
| `2`  | internal error (missing cosign, unreadable config, …) — **always**, in every mode: broken tooling never passes, and never masquerades as a clean refusal |

The shadow/enforce distinction affects **only** the exit code of a clean
`refuse` verdict — never internal errors, never the verdict content.

## Usage

```
ni-ota-verify verify --bom <path> --bom-sig <path> --record <path> --record-sig <path>
                     [--config /etc/neural-ice/ota.conf] [--device-channel <ch>]
                     [--device-compat <min,max>] [--applied-state <path>]
ni-ota-verify bootstrap --bom <path> --bom-sig <path> --expected-train <train>
                        --current-os-ref <image@sha256:digest>
                        --current-seed-ref <40-hex-commit>
                        [--config …] [--device-compat <min,max>]
                        [--applied-state <path>]
ni-ota-verify commit --bom <path> [--config …] [--applied-state <path>]
```

Config (`/etc/neural-ice/ota.conf`) supplies `enforce`, `root_pubkey`,
`state_dir` and optionally `device_channel` / `device_compat_min` /
`device_compat_max`; flags override. A missing `enforce` key defaults to
**enforce** (an incomplete config leans strict, never silently log-only). The
hardware target comes from the immutable image marker, not a CLI override.

An absent configured `state_dir` is created component by component as mode
`0700`, with every new directory and parent entry synced before use. An
existing directory must already be a real mode-`0700` directory; `verify`
warns and skips its best-effort verdict mirror rather than chmod-repairing an
insecure directory or following a directory symlink. For an explicit relative
`--applied-state applied.json`, `commit` may use an existing current directory
that is not group/world-writable and never changes its mode. `bootstrap`
always requires its state parent to be exactly mode `0700`.

### Signed LAB USB baseline bootstrap

`bootstrap` is the one-time bridge from a physically delivered, signed LAB USB
image to the normal anti-rollback state. It consumes only the signed BOM and
its detached signature: it neither accepts nor creates a channel record and
cannot move a `beta`, `stable`, or product alias.

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
- corrupt, insecure, or different existing state is never deleted or silently
  reseeded. Boot recovery media, preserve evidence, diagnose the state, then
  repair with a newly signed train whose sequence is strictly higher.

For one-version rollback, the health gate remains before `commit`. If install
or health fails, the caller rolls the bootc deployment back one version while
the prior applied-state sequence remains unchanged. Once `commit` succeeds,
booting an older payload does not lower that sequence and verification refuses
the older BOM; recovery is a forward repair with a higher signed sequence (or
the existing equal-sequence, byte-identical BOM repair carve-out). Thus neither
bootstrap nor concurrent commits can regress the anti-rollback state.

## Caller integration (the OTA path, ICE-Fabric side)

```
oras pull <registry>/<channel_ref>:<hardware-target>-<device-channel> # signed channel record + .sig
oras pull <registry>/<bundle_ref>:<record.train>          # signed BOM + .sig
ni-ota-verify verify --bom … --bom-sig … --record … --record-sig …   # THE GATE
    → apply strictly by the digests in the verified BOM (never by tag)
    → health gate (NRestarts / is-active)
ni-ota-verify commit --bom …                              # only after health passes
```

`oras` (fetch) and `cosign` (verify) are both version-pinned in the OS image
(`image/Containerfile.bootc` §2b).

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
