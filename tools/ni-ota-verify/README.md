# ni-ota-verify

On-device OTA bundle verifier for Neural ICE appliances (ICE-Fabric ADR-0026,
decision D3: the verifier lives in this open-core OS repo — generic
"verify signed bundle manifest + anti-rollback" logic, zero product IP; only
the keys are secret).

The appliance is treated like a game console: it must verify every update
**by itself** — signature, provenance, anti-rollback — before applying it, with
no reach-back and no operator. This binary is that gate. It verifies **local
files only**; fetching them is the OTA caller's job (see *Caller integration*).

## The verification contract

Checks run in the order of the ICE-Fabric plan (`PLAN-ADR-0026-SIGNING` §0,
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
| 5 | `channel_match` | `record.channel !=` this device's channel                                |
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

(`--insecure-ignore-tlog=true` is private-infrastructure mode, ADR-0026 D1:
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
| `1`  | verdict `refuse` in **enforce** mode (`enforce=1`) — do not apply. `commit` refusals also exit 1 (commit mutates state, so it is always enforced) |
| `2`  | internal error (missing cosign, unreadable config, …) — **always**, in every mode: broken tooling never passes, and never masquerades as a clean refusal |

The shadow/enforce distinction affects **only** the exit code of a clean
`refuse` verdict — never internal errors, never the verdict content.

## Usage

```
ni-ota-verify verify --bom <path> --bom-sig <path> --record <path> --record-sig <path>
                     [--config /etc/neural-ice/ota.conf] [--device-channel <ch>]
                     [--device-compat <min,max>] [--applied-state <path>]
ni-ota-verify commit --bom <path> [--config …] [--applied-state <path>]
```

Config (`/etc/neural-ice/ota.conf`) supplies `enforce`, `root_pubkey`,
`state_dir` and optionally `device_channel` / `device_compat_min` /
`device_compat_max`; flags override. A missing `enforce` key defaults to
**enforce** (an incomplete config leans strict, never silently log-only).

`commit` records `{bundle_seq, bom_sha256}` in `state_dir/applied.json`
**after** the caller's health gate passes. It refuses (exit 1) any BOM that
would lower the recorded seq, and an equal seq with a different hash; an equal
seq with the identical hash re-commits idempotently (repair).

## Caller integration (the OTA path, ICE-Fabric side)

```
oras pull <registry>/<channel_ref>:<device-channel>       # signed channel record + .sig
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
cargo test                                  # unit + CLI tests; cosign is stubbed via NI_OTA_COSIGN
cargo fmt --check && cargo clippy --all-targets --locked -- -D warnings
```

Dependencies are deliberately minimal (`serde`, `serde_json`, std — no async
runtime, no network crates); `Cargo.lock` is committed so the in-image build
(`--locked`, static crt-static) stays reproducible.
