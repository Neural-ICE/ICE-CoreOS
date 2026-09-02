# Installer editions — LIGHT vs PRELOADED

Two installer editions from the **same** codebase and the **same** OS image:

| Edition | Size | Contents | For |
|---|---|---|---|
| **light** (`./image/build-installer-usb.sh`) | ~1.4 GB | OS only → workload images + models pulled post-install (registry / HF) | good bandwidth |
| **preloaded** (`./image/build-preloaded.sh`) | release-dependent | light installer **+ a `ni-seed` GPT partition** carrying one signed Fabric release pack and its digest-addressed closure | poor bandwidth / air-gap |

## Seed v2 lifecycle

The OS image stays light in both editions. The preload is a transport, never an authority and never
an already-trusted containers-storage graphroot:

1. Fabric produces a canonical release manifest, recursive OCI release closure, root-signed
   delegation snapshot, delegated release authorization and detached signatures. The authorization
   binds the exact manifest and closure plus the signed PCR-policy generation. The sealed device
   channel defaults to `lab` for the initial `.67` installer and must equal the authorization's
   signed `ring`; only the Fabric-defined `lab|beta|stable` values are accepted.
2. `image/build-seed-v2.sh` copies the exact closed object set to
   `seed/<release-closure-sha256>/objects/sha256/<digest>`, calls `ni-ota-verify` before publication,
   and writes the non-authoritative `READY` crash marker last. No registry `index.json`, tag or loose
   model path is an authority input.
3. `image/build-preloaded.sh` adds that tree as the sole contents of the **`ni-seed`** partition.
   Its deterministic tree manifest records every object size/hash. The final-media receipt binds
   that manifest, the seed partition identity, both release hashes, and the raw/archive identities.
4. After the writable build loop is detached, the Linux-only final-media gate locks and retains a
   descriptor for the exact raw, creates its own private mount namespace, then reopens that inode
   with a read-only loop. It selects the `ni-seed` child partition from that loop (never from a
   global label link), mounts XFS `ro,nosuid,nodev,noexec`, enforces the seed-v2 root shape and
   recreates the complete tree manifest.
   The build refuses unless every file digest, directory, symlink, hard-link relation, OCI overlay
   whiteout (`c 0:0` only), owner, mode and xattr matches the approved source manifest and the raw
   SHA-256 is unchanged before/after. Other device nodes, FIFOs and sockets are rejected.
   The gate compresses directly from the retained descriptor, expands and hashes the result again,
   and only then publishes it without overwriting an existing path. A
   `*.img.final-media.json` receipt binds both the accepted raw and the final archive digest, size,
   compression, seed manifest and `PARTUUID`; there is no pathname-only gate-to-artifact interval.
   🔴 **The sealed core is re-inspected here, on the finished raw** (review 2026-09-01, P1 #4).
   Steps 2–4 above grow this file, relocate the GPT backup header, rewrite the partition table and
   copy ~20 GB of seed into a new `ni-seed` partition — all after the base media build inspected
   the LIGHT raw. So the gate runs the full `image/inspect-installer-media.py` through its own
   locked descriptor before it publishes anything: `EFI/BOOT/BOOTAA64.EFI` and its sealed
   `.cmdline`, the ESP allowlist, every payload region hash, both recomputed dm-verity root hashes
   and "every other partition is entirely zero". Its expectations come from
   `<name>.img.sealed-core.json`, written by the build that sealed them, and they are REQUIRED
   arguments: a final gate that can be invoked without inspecting what the medium boots is not a
   gate. The receipt (now `neural-ice-preloaded-final-media-receipt-v2`) records the result under
   `sealed_core`.
5. Before destructive installation, the autoinstaller verifies the complete pack from the mounted
   seed. It copies the still-non-authoritative bytes to encrypted persistent storage and re-verifies
   them there. The previous installed generation is not touched.
6. On first boot, `neural-ice-seed-import.service` re-verifies again with networking denied, builds
   a candidate containers-storage generation with `skopeo --preserve-digests`, reads every imported
   root digest back, constructs content/model CAS generations from signed manifest references,
   relabels the store, fsyncs receipts and directories, then atomically switches all `current`
   pointers. `OFFLINE-READY` is written last. A crash or refusal before that point leaves the prior
   generation selected; an exact retry reuses a complete generation.

**Invariant (learned in the field):** the `additionalimagestores` path MUST exist on every edition —
containers-storage hard-fails on a missing path. It is guaranteed three ways: baked into the image,
tmpfiles.d recreation, and an unconditional `mkdir` in the autoinstall (LIGHT gets an empty store).

Result: no network is permitted during admission or import. Workloads become offline-ready only
after complete verification, import, relabel, readback and atomic publication.
The P0 seed is self-sufficient: its signed closure supplies the OS pack, every P0 image, payload,
required content and vLLM model objects. SGLang is outside P0. A Zot mirror such as `.63` can be an
optional digest-pinned cache, but is never a first-boot dependency or alternate authority.

Each validated model card uses the closed JSON schema
`neural-ice-hf-cache-model-card-v1`, with exactly `cache_directory`, `card_id`, `files`, `model`,
`revision`, and `schema`. Every sorted `files` entry has exactly `path`, `sha256`, and `size`.
It is carried without extending Fabric's closure schema: a standard `oci-artifact` root manifest
has artifact type `application/vnd.neural-ice.hf-cache-model-card.v1`, the card JSON is its typed
config, and the model bytes are typed layers. Thus the existing signed root and recursive OCI
edges authenticate every byte and the importer never trusts an unbound loose file path.

## Compression — `COMPRESS` (speed vs size lever)
The raw→archive compression is the build bottleneck (a ~110 GiB raw).

| Use | `COMPRESS` | Why |
|---|---|---|
| **dev** (local reflash loop) | **`zstd-fast`** (zstd -3 -T0, default) | file stays local → size irrelevant, speed is everything; multithreaded, collapses the raw's zeros in seconds |
| **published release** (downloaded once) | `zstd-max` (zstd -19 --long -T0) or `xz` | optimize the download (max ratio) |

## Build (on a self-hosted ARM64 runner with the seed staged locally)

```sh
SEED_RELEASE_MANIFEST=/release/release-manifest.json \
SEED_RELEASE_CLOSURE=/release/release-closure.json \
SEED_RELEASE_AUTHORIZATION=/release/release-authorization.json \
SEED_RELEASE_AUTHORIZATION_SIGNATURE=/release/release-authorization.json.sig \
SEED_DELEGATION_SNAPSHOT=/release/delegation-snapshot.json \
SEED_DELEGATION_SIGNATURE=/release/delegation-snapshot.json.sig \
SEED_OBJECTS=/release/objects/sha256 \
SEED_HF_CACHE=/cache/huggingface/hub \
SEED_MODEL_PROFILES=/fabric/config/inference/model-profiles.json \
SEED_MODEL_CATALOGUE=/fabric/config/inference/model-catalogue.json \
DEVICE_CHANNEL=lab \
BASE_IMAGE=registry.example.test/neural-ice/neural-ice-appliance@sha256:<train-digest> \
SSH_AUTHORIZED_KEYS_FILE=$HOME/.ssh/id_ed25519.pub \
SSH_AUTHORIZED_KEYS_SHA256=<approved-public-key-file-sha256> \
LAB_BASELINE_BOM_FILE=/release/train.bom.json \
LAB_BASELINE_BOM_SHA256=<approved-bom-sha256> \
LAB_BASELINE_SIGNATURE_FILE=/release/train.bom.sig \
LAB_BASELINE_SIGNATURE_SHA256=<approved-signature-sha256> \
COMPRESS=zstd-fast ./image/build-preloaded.sh
```

Produces `ice-coreos-installer-preloaded-<version>.img.zst` (+ `.sha256`). Flash:
`zstd -dc <img.zst> | sudo dd of=/dev/sdX bs=64M oflag=direct status=progress`.

The build also emits `<name>.img.sealed-core.json` — what the signed UKI on this raw seals, handed
from the base media build to the final gate — plus `<name>.img.final-media.json` and its `.sha256`.
Release automation must
verify both checksums, retain the receipt, expand exactly the archive digest recorded in it, and
flash/read back exactly the raw digest and size recorded in the same receipt. Existing artifact,
checksum or receipt paths are never overwritten; retry with a fresh output name after diagnosing a
failed build.

The `ni-seed` partition is sized from the extracted image store, models and the complete optional
product payload. The sum receives 10% proportional headroom plus 4 GiB fixed headroom and is rounded
up to 1 MiB. This keeps large (~70 GiB) payloads from exhausting the partition. First-boot payload
application is bounded to two hours instead of systemd's default 90 seconds.

For LAB-MANAGED media, the optional SSH public-key file is validated, hash-bound and written to
`EFI:/ice-coreos/authorized_keys` before final-media acceptance. Staging is refused unless the base
image is lab-anchored, its immutable `/usr/lib/neural-ice/access-policy` permits installer SSH
provisioning, and the installed target is that same digest-pinned reference. The input must be one
plain OpenSSH public-key record (never a private key or an `authorized_keys` record with options)
and at most 512 bytes so its base64 form fits the supported ARM64 kernel command line with
headroom.

The final-media gate then closes the loop: pass `--esp-authorized-keys-sha256 <approved>` to
`image/verify-preloaded-media.py` and it refuses a medium whose ESP key is absent, drifted,
oversized or — with the flag omitted — present at all. The delivered USB therefore remains
byte-for-byte covered by the raw and artifact digests in the final receipt (which now carries an
`esp_authorized_keys` entry, `null` when no key was approved); do not modify its ESP after
acceptance.

🔴 **The medium is a convenience, not the authority.** Whether a provisioned key is ever honoured
is decided twice on the appliance itself, against the immutable access policy in the signed image:
once by the autoinstaller before any disk write, once by the first-boot service. A `customer-locked`
image refuses a crafted ESP entry or a forged `neuralice.sshkey=` karg outright — see
[ADR-0014](ADR-0014-access-policy-lab-vs-customer.md).

Notes:
- `OUT` names the output archive here but is the bib output DIR in
  `build-installer-usb.sh` — the child is invoked with `env -u OUT` (do not export `OUT` around it).
- Disk: seed (extracted store + models + optional payload) + raw + archive needs roughly **2.5× the seed size**
  free on the build host (~250 GB for a ~63 GB seed).
- Build time ≈ 11 min on a GB10-class build host (store load + bib + copy + zstd-fast).
- Publish: dev keeps the `.img.zst` local; releases go to a GitHub Release / object storage.

## Optional LAB baseline receipt on the installer ESP

A LAB installer may carry this exact pair on its EFI System Partition:

```text
/ice-coreos/ota-lab-baseline.json
/ice-coreos/ota-lab-baseline.sig
```

The pair is optional. To include it, the preloaded builder requires the two source files and their
two exact lowercase SHA-256 values as one complete input set. It snapshots those bytes into a
private mode-0700 staging directory before the expensive image build, refuses symlinks,
non-regular/empty/oversized inputs and hash drift, and never overwrites an existing fixed ESP path.
LAB injection is restricted to a debug image where `BASE_IMAGE` and the installed target are the
same digest-pinned reference.

The signed BOM deliberately contains **no final installer raw/archive hash and no installer
chunk-index identity**. It authorizes the installed result: the exact booted OS manifest digest,
the exact Fabric seed commit, the digest-addressed bundle and its image-attestation set. Putting
the raw-media hash in a BOM embedded on that media would be circular because adding the BOM and
signature changes the raw image. `ni-ota-verify` therefore refuses legacy delegated/bootstrap BOMs
that contain `appliance.raw_sha256` or `appliance.caibx`.

Media integrity remains independently complete: the final-media gate emits the raw/archive hashes,
partition identities and embedded baseline-file hashes only after assembly. That receipt and its
checksum are operator/build evidence kept next to the artifact and verified before flashing; they
are not release authority and are never copied into the signed BOM.

After `ni-seed` has been added, the final-media gate independently opens the finalized raw,
selects exactly one `EFI-SYSTEM` vfat child of its retained read-only loop, mounts it
`ro,nosuid,nodev,noexec`, and re-hashes both fixed paths. The receipt binds the approved file paths,
sizes and SHA-256 values plus the ESP `PARTUUID`. A missing, partial, unexpected or changed pair
refuses the complete output set before an archive, checksum or receipt is published. The accepted
raw must not be modified afterward: every delivered USB is produced only from the archive digest
and raw digest already bound by that receipt.

If all four builder inputs are absent, installation behaves exactly as before and the receipt
records `lab_baseline: null`. If only one file or hash is supplied, the build refuses before doing
expensive work. Independently, if only one fixed ESP path exists, either path is a
symlink/non-regular file, either file is empty, the JSON exceeds 16 KiB, or the signature exceeds
4 KiB, autoinstall fails closed **before wiping the target**.

CoreOS does not parse the record and does not verify or interpret its signature. It snapshots
the two byte streams before touching the target, then atomically installs them on the encrypted
system volume as root-owned state:

```text
/var/lib/neural-ice/ota/lab-baseline/ota-lab-baseline.json  root:root 0600
/var/lib/neural-ice/ota/lab-baseline/ota-lab-baseline.sig   root:root 0600
```

The `lab-baseline` directory is `root:root 0700`; writes are compared byte-for-byte and flushed
before install completion. The target SELinux policy labels the directory in the same pass as
the rest of runtime `/var`. The Fabric baseline service is the sole consumer responsible for
signature verification and the trust decision after boot.

This handoff is independent of `/ice-coreos/authorized_keys`; the installer SSH key behavior
described above is unchanged by it.

### Failure recovery and one-version rollback

The handoff directory lives in persistent `/var`, not inside a bootc deployment. It therefore
survives a one-version `bootc rollback`. That persistence is intentional: changing the deployed
`/usr` must not silently replace the physically delivered trust input or erase evidence of a
failed bootstrap.

The supported one-version behavior is:

- an older deployment with no baseline consumer ignores the unknown root-only directory;
- a baseline-aware Fabric service must re-verify the detached signature and all device/train
  bindings before state mutation, and an exact retry must be idempotent;
- neither rollback nor a retry may lower, replace, or delete verifier-owned `applied.json`;
- a different receipt at the same sequence, a bad signature, an incompatible device binding, or
  insecure metadata is a fail-closed refusal, not a reason to repair or remove state automatically.

Failure before the atomic directory rename leaves no final `lab-baseline` directory and aborts the
install. Diagnose or replace the USB media and rerun the complete installer; do not boot or repair
the partially installed target in place. Failure after publication leaves the complete, flushed
pair, so the same signed bootstrap can be retried safely.

A LAB-baseline refusal occurs before any final artifact, checksum or receipt is published. Keep the
failed raw as evidence, correct the approved input, and rebuild under a fresh `OUT`; never patch the
ESP after acceptance or reuse an old final-media receipt.

If post-boot verification refuses, preserve the receipt and diagnostic output. Roll back to the
previous healthy bootc deployment when one exists; that deployment either ignores the pair or
re-verifies the exact same bytes under the rules above. Recovery then uses a corrected, newly
signed installation/release input with a strictly valid sequence and bindings. Operators must not
hand-edit or delete the receipt to force acceptance. The handoff itself never moves a channel or
authorizes an update.

## Security note — recovery escrow on the USB

The autoinstall writes `NEURAL-ICE-RECOVERY-<serial>.txt` (data-volume key + system-volume key)
to the installer USB ESP, in clear: **physical possession of that USB is the trust boundary**.
After an install, the USB must be treated as a key backup — store it safely or wipe it
(`shred`/reflash) once the keys are transcribed. See
[INSTALLER-UX-HARDENING.md](INSTALLER-UX-HARDENING.md).
