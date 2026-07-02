# Installer editions — LIGHT vs PRELOADED

Two installer editions from the **same** codebase, selected by `EDITION`:

| Edition | Size | Contents | For |
|---|---|---|---|
| **light** (default) | ~1.4 GB | OS only → app images + models pulled post-install (gated R2 / HF) | good bandwidth |
| **preloaded** | ~65 GB | OS **+ a one-shot seed payload**: app container images (OCI archives) + the public NVFP4 **base** models | poor bandwidth / air-gap / fast dev iteration |

## Key design decision — seed payload in the INSTALLER, not baked into the OS image

The OS image stays **LIGHT in both editions**, so **OTA updates stay small** (bootc never ships the
65 GB). The preload is a **one-shot install-time seed** carried by the *installer only*:

1. **Container images** — `skopeo copy docker://<img> oci-archive:seed/images/<name>.tar` for each
   appliance Quadlet image (digest-pinned). The installer image carries `seed/images/`.
2. **Base models (public NVFP4)** — copied from `/data/models/Neural-ICE_cache_models/local/model-assets/huggingface/hub`
   into `seed/models/`. **NOT the private LoRA adapters** (those stay gated-R2 + decrypt-to-RAM,
   [ADR-0001]; they are tiny → a fast gated pull post-activation).
3. **`neural-ice-autoinstall.sh`** gains a *seed* step (only when `seed/` is present): after
   `bootc install`, it loads the OCI archives into the target `/var/lib/containers` (skopeo copy to
   `containers-storage:`) and copies the models onto the encrypted `/var/lib/neural-ice/data`.

Result: install → onboarding → **everything starts, no downloads**. Later updates flow normally
(bootc OTA + gated R2 pulls). Contrast with bootc *Logically Bound Images*, which bind images to the
OS image and would bloat every OTA — rejected for that reason.

## Compression — `COMPRESS` (speed vs size lever)
The raw→archive compression is the build bottleneck (a 40 GiB+ raw). `xz -9` is the slowest choice.

| Use | `COMPRESS` | Why |
|---|---|---|
| **dev** (`.63`→USB over LAN, frequent reflash) | **`zstd -3 -T0`** (default) | file stays local → size irrelevant, speed is everything; multithreaded, collapses the raw's zeros in seconds |
| **customer release** (download once) | `zstd -19 --long -T0` (or `xz -9 -T0`) | optimize *their* download (max ratio) |

## Build (on the `.63` self-hosted ARM64 runner — has the models + artifacts)
1. Pull the app images onto `.63` (digest-pinned): vllm-node (serves inference/embed/rerank/ocr),
   qdrant, vector, caddy, ghostunnel, icecore.
2. `EDITION=preloaded ./image/build-installer-usb.sh` → base installer image + `Containerfile.installer.preloaded`
   COPYs the seed payload → bib → raw → `COMPRESS`.
3. Publish (dev: keep the `.img` local on `.63`/USB; release: GitHub Release / R2).

Disk: the seed (~20 GB images + ~44 GB models) + the raw needs ~150–200 GB free on `.63` (742 GB
available — OK).
