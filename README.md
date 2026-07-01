# ICE-CoreOS

Immutable, container-native, **sovereign** operating system for **NVIDIA DGX Spark**
(GB10 Grace-Blackwell, ARM64) edge-AI appliances.

ICE-CoreOS is the open-core base layer of the [Neural ICE](https://github.com/Neural-ICE)
stack. It is a [bootc](https://bootc.dev) image built on **CentOS Stream 10**, with the
GB10 kernel (**4 KiB pages**), the NVIDIA open driver (r595), Secure Boot signing, and optional
**two-domain TPM2/LUKS full-disk encryption**. The OS updates over-the-air from a public
container registry (`bootc upgrade`), atomically, with rollback.

> The public base image is a **vanilla, reusable distro** — no baked credentials. Anyone
> can install it on a DGX Spark and inject their own SSH key. The Neural ICE commercial
> appliance is built from this same base by baking an operator key and adding a private
> application layer on top.

---

## Highlights

- **Immutable / image-based** — `/usr` read-only (ostree/composefs), `/var` persistent,
  atomic updates and rollback (`bootc`).
- **GB10-native** — GB10 kernel from the Red Hat `nvidia-gb10` tree, built with
  **4 KiB pages** for broad software compatibility (qdrant/vLLM/wheels break under
  64k; NVIDIA recommends the regular kernel — see
  [ADR-0006](docs/ADR-0006-kernel-4k-page-size.md)). NVIDIA open driver baked &
  signed, GPU works out of the box (`nvidia-smi`).
- **Encrypted, zero-touch** — system + client-data LUKS2 volumes, both auto-unlocked by
  the **TPM2** at boot (PCR 7); recovery keys escrowed at install. See
  [ADR-0004](docs/ADR-0004-disk-encryption-tpm-luks.md).
- **OTA from GHCR** — `ghcr.io/neural-ice/neural-ice-coreos`, free pull egress, atomic,
  rollback. See [ADR-0003](docs/ADR-0003-base-and-update-model.md).
- **Release channels** — `alpha` / `beta` / `prod`, with promotion-by-digest (no rebuild).
- **Flashable USB installer** — dual-mode (Live / Install), published per channel.

---

## Release channels & promotion (staging)

Three moving channel tags on the package, plus immutable `:<version>-<channel>.<n>` tags:

| Channel | Tag | Cadence | Use |
| --- | --- | --- | --- |
| **alpha** | `…:alpha` | every push to `main` (CI) | active development |
| **beta** | `…:beta` | promoted, occasional | wider validation |
| **prod** | `…:prod` | promoted, when validated | production / community |

The flow is a **staging pipeline** — the exact bits validated in `alpha` are what reach
`beta` and then `prod`, because promotion only **re-tags the digest** (no rebuild, no drift):

```
push → CI builds  → :alpha            (.github/workflows/build-image.yml)
promote alpha→beta → :beta            (.github/workflows/promote.yml, manual)
promote beta→prod  → :prod            (.github/workflows/promote.yml, manual)
```

An appliance or installer subscribes to a channel via its OTA origin
(`--target-imgref …:prod`), so `bootc upgrade` follows that channel.

---

## Install on a DGX Spark

The OS image itself is **public** on GHCR (`ghcr.io/neural-ice/neural-ice-coreos:<channel>`),
so it can be pulled and updated by anyone even while this code repo is private.

The flashable USB **installer** is produced by the `release-installer` workflow. Pre-built
installer images are attached to [Releases](https://github.com/Neural-ICE/ICE-CoreOS/releases)
**once this repository is public**; until then, build one locally for any channel:

```sh
BASE_IMAGE=ghcr.io/neural-ice/neural-ice-coreos:prod ./image/build-installer-usb.sh
```

Then:

1. Take the installer `.img` (from a Release, or the local build above).
2. Flash it to a USB stick:
   ```sh
   xz -dc ice-coreos-installer-*.img.xz | sudo dd of=/dev/sdX bs=64M oflag=direct status=progress
   ```
3. **Inject your SSH key** (the vanilla image has none) — either:
   - drop your public key onto the USB's EFI partition at `ice-coreos/authorized_keys`
     (the EFI partition is FAT and mounts on any OS), **or**
   - pass `neuralice.sshkey=<base64-of-your-pubkey>` as a kernel argument.
4. Boot the USB on the DGX Spark (GPT raw disk; the firmware only boots GPT, not El-Torito
   ISO), choose **“Neural ICE — Install”**. It wipes the internal disk, sets up the
   encrypted volumes (TPM2), shows the **data recovery key** (also saved on the USB), then
   prompts to remove the USB and reboot.

> Secure Boot: production images ship a Microsoft-signed shim (see
> [ADR-0002](docs/ADR-0002-secure-boot-zero-touch.md)); lab builds use an enrolled lab key.

---

## AI workloads

AI runtimes are **not baked into the OS** — they run as **containers** with GPU
access via the NVIDIA CDI spec generated at boot. See
[docs/ai-quickstart.md](docs/ai-quickstart.md) for Ollama, vLLM and Hugging Face
examples, plus ready-made [Quadlets](examples/quadlets/). Store model caches on
the encrypted `/var/lib/neural-ice/data` volume.

## Build

The OS image needs **staged GB10 artifacts** that are produced rarely and live outside git
(GB10 kernel (4k) RPMs, signed NVIDIA modules, NVIDIA userspace, signed boot binaries):

```
image/rpms/  image/driver-modules/  image/nvidia-userspace/  image/signed-boot/
```

Produce/stage them with `build/build-kernel.sh` + `ci/stage-artifacts.sh` (run rarely),
then build:

```sh
# Vanilla public image (no SSH key):
CHANNEL=alpha ./ci/build-image.sh

# Appliance / dev image with a baked operator key:
SSH_AUTHORIZED_KEY="ssh-ed25519 AAAA... me@host" CHANNEL=alpha PUSH=1 ./ci/build-image.sh
```

Build a flashable USB installer for a channel:

```sh
BASE_IMAGE=ghcr.io/neural-ice/neural-ice-coreos:prod ./image/build-installer-usb.sh
```

### CI runner

The build/installer workflows run on a **self-hosted ARM64 runner** (a DGX Spark or an
ARM64 build host) because they need native aarch64, `podman` + `bootc-image-builder`, and
the staged GB10 artifacts. Register one with the
[GitHub Actions runner](https://docs.github.com/actions/hosting-your-own-runners) and the
labels `self-hosted, linux, ARM64`. Promotion runs on hosted runners (skopeo only).

GHCR auth: workflows use `GITHUB_TOKEN` (`packages: write`); set a `GHCR_PAT` repo secret
to override. Keep the `neural-ice-coreos` package **public** for free community pulls.

---

## Repository layout

```
image/          bootc OS image + installer (Containerfiles, overlay, branding, bib config)
ota/            auto-install service + script (dual-mode installer logic)
ignition/       Butane/Ignition for first-boot provisioning (SSH key, etc.)
build/          GB10 kernel (4k) + driver build (heavy, rare)
ci/             build/stage/version helper scripts used by CI and locally
docs/           Architecture Decision Records (ADR-0002..0006)
.github/        CI workflows (build-image, promote, release-installer, build-kernel)
VERSION         semantic version base for channel tags
```

## Architecture decisions

- [ADR-0002 — Secure Boot, zero-touch](docs/ADR-0002-secure-boot-zero-touch.md)
- [ADR-0003 — Base OS, update model & open-core](docs/ADR-0003-base-and-update-model.md)
- [ADR-0004 — TPM2/LUKS two-domain encryption](docs/ADR-0004-disk-encryption-tpm-luks.md)
- [ADR-0005 — Release channels & promotion](docs/ADR-0005-release-channels.md)
- [ADR-0006 — Kernel page size: 4k instead of kernel-64k](docs/ADR-0006-kernel-4k-page-size.md)

## License

Apache-2.0 (open-core base). The private Neural ICE application layer is licensed separately.
