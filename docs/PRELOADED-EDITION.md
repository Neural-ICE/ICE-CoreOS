# Installer editions — LIGHT vs PRELOADED

Two installer editions from the **same** codebase and the **same** OS image:

| Edition | Size | Contents | For |
|---|---|---|---|
| **light** (`./image/build-installer-usb.sh`) | ~1.4 GB | OS only → app images + models pulled post-install (gated R2 / HF) | good bandwidth |
| **preloaded** (`./image/build-preloaded.sh`) | ~48 GB (zstd) | light installer **+ a `ni-seed` GPT partition**: a READY podman overlay image store + the public NVFP4 **base** models | poor bandwidth / air-gap / fast dev iteration |

## Key design decision — seed partition on the INSTALLER, zero first-boot import

The OS image stays **LIGHT in both editions**, so **OTA updates stay small** (bootc never ships the
seed). The preload is a one-shot install-time seed carried by the *installer media only*, and the
expensive work happens **once on the build host, never on the client**:

1. **Container images** — `image/build-preloaded.sh` runs `podman --root <tmp> load` on the build
   host for each appliance image archive (`SEED_IMAGES=…/*.tar`: vllm-node, icecore, qdrant, vector,
   caddy), producing a **ready overlay store** (untar + sha256 done here). Refs are preserved so the
   Quadlets resolve them offline.
2. **Base models (public NVFP4)** — copied from `SEED_MODELS` (the `.63` HF hub archive) into the
   seed. **NOT the private LoRA adapters** (those stay gated-R2 + decrypt-to-RAM, ADR-0001; they are
   tiny → a fast gated pull post-activation).
3. The script grows the light raw, appends a **`ni-seed` GPT partition** (xfs, sized from the
   EXTRACTED store + models + headroom) and copies both payloads in.
4. **`ota/neural-ice-autoinstall.sh`** (seed step, only when `/dev/disk/by-partlabel/ni-seed`
   exists): after `bootc install`, it copies the ready store onto the encrypted data volume as
   `/var/lib/neural-ice/data/seed-store` (SELinux-labelled `container_ro_file_t`) and the models
   into `data/huggingface`. The image's `storage.conf.d` drop-in registers `seed-store` as a
   **READ-ONLY `additionalimagestores`** — the appliance sees the images INSTANTLY at first boot:
   no `podman load`, no import, no pull.

**Invariant (learned in the field):** the `additionalimagestores` path MUST exist on every edition —
containers-storage hard-fails on a missing path. It is guaranteed three ways: baked into the image,
tmpfiles.d recreation, and an unconditional `mkdir` in the autoinstall (LIGHT gets an empty store).

Result: install → onboarding → **everything starts, no downloads**. Later updates flow normally
(bootc OTA + gated R2 pulls). Contrast with bootc *Logically Bound Images*, which bind images to the
OS image and would bloat every OTA — rejected for that reason.

## Compression — `COMPRESS` (speed vs size lever)
The raw→archive compression is the build bottleneck (a ~110 GiB raw).

| Use | `COMPRESS` | Why |
|---|---|---|
| **dev** (`.63`→USB over LAN, frequent reflash) | **`zstd-fast`** (zstd -3 -T0, default) | file stays local → size irrelevant, speed is everything; multithreaded, collapses the raw's zeros in seconds |
| **customer release** (download once) | `zstd-max` (zstd -19 --long -T0) or `xz` | optimize *their* download (max ratio) |

## Build (on the `.63` self-hosted ARM64 runner — has the models + archives)

```sh
SEED_IMAGES=/home/user/ice-seed/images \
SEED_MODELS=/data/models/Neural-ICE_cache_models/local/model-assets/huggingface/hub \
BASE_IMAGE=ghcr.io/neural-ice/neural-ice-coreos:alpha-debug \
VARIANT=debug COMPRESS=zstd-fast ./image/build-preloaded.sh
```

Produces `ice-coreos-installer-preloaded-<version>.img.zst` (+ `.sha256`). Flash:
`zstd -dc <img.zst> | sudo dd of=/dev/sdX bs=64M oflag=direct status=progress`.

Notes:
- `OUT` names the output archive here but is the bib output DIR in
  `build-installer-usb.sh` — the child is invoked with `env -u OUT` (do not export `OUT` around it).
- Disk: seed (~19 GB store + ~44 GB models) + raw + archive needs ~250 GB free on `.63`.
- Build time ≈ 11 min on `.63` (store load + bib + copy + zstd-fast).
- Publish: dev keeps the `.img.zst` local on `.63`/USB; release goes to GitHub Release / R2.

## Security note — recovery escrow on the USB

The autoinstall writes `NEURAL-ICE-RECOVERY-<serial>.txt` (CLIENT data key + INTERNAL system key)
to the installer USB ESP, in clear: **physical possession of that USB is the trust boundary**.
After a customer install, the USB must be treated as a key backup — store it safely or wipe it
(`shred`/reflash) once the keys are transcribed. See docs/INSTALLER-UX-HARDENING.md.
