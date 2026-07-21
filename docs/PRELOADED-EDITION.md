# Installer editions — LIGHT vs PRELOADED

Two installer editions from the **same** codebase and the **same** OS image:

| Edition | Size | Contents | For |
|---|---|---|---|
| **light** (`./image/build-installer-usb.sh`) | ~1.4 GB | OS only → workload images + models pulled post-install (registry / HF) | good bandwidth |
| **preloaded** (`./image/build-preloaded.sh`) | ~48 GB (zstd) | light installer **+ a `ni-seed` GPT partition**: a READY podman overlay image store + base models | poor bandwidth / air-gap / fast dev iteration |

## Key design decision — seed partition on the INSTALLER, zero first-boot import

The OS image stays **LIGHT in both editions**, so **OTA updates stay small** (bootc never ships the
seed). The preload is a one-shot install-time seed carried by the *installer media only*, and the
expensive work happens **once on the build host, never on the target device**:

1. **Container images** — `image/build-preloaded.sh` runs `podman --root <tmp> load` on the build
   host for each workload image archive (`SEED_IMAGES=…/*.tar`), producing a **ready overlay
   store** (untar + sha256 done here). Refs are preserved so Quadlets resolve them offline.
2. **Base models** — copied from `SEED_MODELS` (a local Hugging Face hub staging directory) into
   the seed. Only openly redistributable model files belong in the seed; anything gated or
   restricted must be pulled post-install through its own channel. `SEED_MODELS` may be a stable
   symlink; the builder resolves it once before sizing and copying so partition capacity is based
   on the real model tree, not on the symlink inode.
3. The script grows the light raw, appends a **`ni-seed` GPT partition** (xfs, sized from the
   EXTRACTED store + models + headroom) and copies both payloads in.
4. After the writable build loop is detached, a Linux-only final-media gate reopens the exact raw
   with a read-only loop, selects the `ni-seed` child partition from that loop (never from a global
   label link), mounts XFS `ro,nosuid,nodev,noexec`, and recreates the complete namespace manifest.
   The build refuses unless every file digest, directory, symlink, hard-link relation, OCI overlay
   whiteout (`c 0:0` only), owner, mode and xattr matches the approved source manifest and the raw
   SHA-256 is unchanged before/after. Other device nodes, FIFOs and sockets are rejected.
   A `*.img.final-media.json` receipt binds the accepted raw digest, size, seed manifest and
   `PARTUUID`; the raw is hashed again after compression to close the gate-to-artifact interval.
5. **`ota/neural-ice-autoinstall.sh`** (seed step, only when `/dev/disk/by-partlabel/ni-seed`
   exists): after `bootc install`, it copies the ready store onto the encrypted data volume as
   `/var/lib/neural-ice/data/seed-store` (SELinux-labelled `container_ro_file_t`) and the models
   into `data/huggingface`. The image's `storage.conf.d` drop-in registers `seed-store` as a
   **READ-ONLY `additionalimagestores`** — the device sees the images INSTANTLY at first boot:
   no `podman load`, no import, no pull.

**Invariant (learned in the field):** the `additionalimagestores` path MUST exist on every edition —
containers-storage hard-fails on a missing path. It is guaranteed three ways: baked into the image,
tmpfiles.d recreation, and an unconditional `mkdir` in the autoinstall (LIGHT gets an empty store).

Result: first boot starts with **no downloads**. Later updates flow normally (bootc OTA + regular
registry/model pulls). Contrast with bootc *Logically Bound Images*, which bind images to the OS
image and would bloat every OTA — rejected for that reason.

## Compression — `COMPRESS` (speed vs size lever)
The raw→archive compression is the build bottleneck (a ~110 GiB raw).

| Use | `COMPRESS` | Why |
|---|---|---|
| **dev** (local reflash loop) | **`zstd-fast`** (zstd -3 -T0, default) | file stays local → size irrelevant, speed is everything; multithreaded, collapses the raw's zeros in seconds |
| **published release** (downloaded once) | `zstd-max` (zstd -19 --long -T0) or `xz` | optimize the download (max ratio) |

## Build (on a self-hosted ARM64 runner with the seed staged locally)

```sh
SEED_IMAGES=$HOME/ice-seed/images \
SEED_MODELS=$HOME/ice-seed/models \
BASE_IMAGE=registry.neural-ice.ch/neural-ice/neural-ice-appliance@sha256:<train-digest> \
VARIANT=debug COMPRESS=zstd-fast ./image/build-preloaded.sh
```

Produces `ice-coreos-installer-preloaded-<version>.img.zst` (+ `.sha256`). Flash:
`zstd -dc <img.zst> | sudo dd of=/dev/sdX bs=64M oflag=direct status=progress`.

The build also emits `<name>.img.final-media.json` and its `.sha256`. Release automation must
retain that receipt and flash/read back exactly the raw digest recorded in it.

Notes:
- `OUT` names the output archive here but is the bib output DIR in
  `build-installer-usb.sh` — the child is invoked with `env -u OUT` (do not export `OUT` around it).
- Disk: seed (extracted store + models) + raw + archive needs roughly **2.5× the seed size**
  free on the build host (~250 GB for a ~63 GB seed).
- Build time ≈ 11 min on a GB10-class build host (store load + bib + copy + zstd-fast).
- Publish: dev keeps the `.img.zst` local; releases go to a GitHub Release / object storage.

## Optional LAB baseline receipt on the installer ESP

A LAB installer may carry this exact pair on its EFI System Partition:

```text
/ice-coreos/ota-lab-baseline.json
/ice-coreos/ota-lab-baseline.sig
```

The pair is optional. If both files are absent, installation behaves exactly as before. If only
one exists, either path is a symlink/non-regular file, either file is empty, the JSON exceeds
16 KiB, or the signature exceeds 4 KiB, autoinstall fails closed **before wiping the target**.

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

This handoff is independent of `/ice-coreos/authorized_keys`; its existing debug-key behavior is
unchanged.

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
