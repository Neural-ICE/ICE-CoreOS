# ICE-CoreOS

Immutable, container-native, **sovereign** operating system for **NVIDIA DGX Spark**
(GB10 Grace-Blackwell, ARM64) edge-AI appliances.

ICE-CoreOS is a [bootc](https://bootc.dev) image built on **CentOS Stream 10**, with the
GB10 kernel (**4 KiB pages**), the NVIDIA open driver (r595), a signed Secure Boot chain,
and optional **two-domain TPM2/LUKS full-disk encryption**. The OS updates over-the-air
from a public container registry (`bootc upgrade`), atomically, with rollback.
It is developed by [Neural ICE](https://github.com/Neural-ICE) and published as a
**vanilla, reusable distro** — no baked credentials, nothing phoning home. Anyone can
install it on a DGX Spark and inject their own SSH key.

---

## Highlights

- **Immutable / image-based** — `/usr` read-only (ostree/composefs), `/var` persistent,
  atomic updates and rollback (`bootc`).
- **GB10-native** — GB10 kernel from the Red Hat `nvidia-gb10` tree, built with
  **4 KiB pages** for broad software compatibility (qdrant/vLLM/wheels break under
  64k; NVIDIA recommends the regular kernel — see
  [ADR-0006](docs/ADR-0006-kernel-4k-page-size.md)). NVIDIA open driver baked &
  signed, GPU works out of the box (`nvidia-smi`).
- **Encrypted, zero-touch** — system + data LUKS2 volumes, both auto-unlocked by
  the **TPM2** at boot (PCR 7); recovery keys escrowed at install. See
  [ADR-0004](docs/ADR-0004-disk-encryption-tpm-luks.md).
- **Secure Boot** — shim → GRUB2 → signed kernel → signed modules. Current builds
  boot with an enrolled lab key; a **Microsoft-signed shim** (boot on factory
  Secure Boot, no enrollment) is in preparation — see
  [ADR-0002](docs/ADR-0002-secure-boot-zero-touch.md) and [secureboot/](secureboot/).
- **OTA from GHCR** — `ghcr.io/neural-ice/neural-ice-coreos`, free pull egress, atomic,
  rollback. See [ADR-0003](docs/ADR-0003-base-and-update-model.md).
- **Release channels** — two rings, `beta` / `stable`, with promotion-by-digest (no rebuild).
- **Flashable USB installer** — dual-mode (Live / Install), light or preloaded
  edition (see [docs/PRELOADED-EDITION.md](docs/PRELOADED-EDITION.md)).

---

## Release channels & promotion (staging)

Two moving channel tags on the package, plus immutable `:<version>-<channel>.<n>` tags
(ring set unified with the appliance-bundle channels — see ICE-Fabric ADR-0028):

| Channel | Tag | Cadence | Use |
| --- | --- | --- | --- |
| **beta** | `…:beta` | every push to `main` (CI) | validation ring |
| **stable** | `…:stable` | promoted, when validated | production / community |

The flow is a **staging pipeline** — the exact bits validated in `beta` are what reach
`stable`, because promotion only **re-tags the digest** (no rebuild, no drift):

```
push → CI builds    → :beta           (.github/workflows/build-image.yml)
promote beta→stable → :stable         (.github/workflows/promote.yml, manual)
```

A device or installer subscribes to a channel via its OTA origin
(`--target-imgref …:stable`), so `bootc upgrade` follows that channel.

---

## Install on a DGX Spark

The OS image is **public** on GHCR (`ghcr.io/neural-ice/neural-ice-coreos:<channel>`).

The flashable USB **installer** is produced by the `release-installer` workflow and
attached to [Releases](https://github.com/Neural-ICE/ICE-CoreOS/releases) when
published; you can always build one locally for any channel:

```sh
BASE_IMAGE=ghcr.io/neural-ice/neural-ice-coreos:stable ./image/build-installer-usb.sh
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
   ISO), choose **“Neural ICE - Install”**. It wipes the internal disk, sets up the
   encrypted volumes (TPM2), shows the **data recovery key** (also saved on the USB), then
   prompts to remove the USB and reboot.

> Secure Boot: until the Microsoft-signed shim lands (see
> [ADR-0002](docs/ADR-0002-secure-boot-zero-touch.md) and [secureboot/](secureboot/)),
> booting with Secure Boot ON requires enrolling the signing certificate in the
> firmware `db` once (Security → Secure Boot → Expert Key Management).

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
CHANNEL=beta ./ci/build-image.sh

# Dev image with a baked SSH key (lab only — keys in the image do not survive
# a `bootc switch` to a keyless image; prefer the persistent authorized_keys):
SSH_AUTHORIZED_KEY="ssh-ed25519 AAAA... me@host" CHANNEL=beta PUSH=1 ./ci/build-image.sh
```

Build a flashable USB installer for a channel:

```sh
BASE_IMAGE=ghcr.io/neural-ice/neural-ice-coreos:stable ./image/build-installer-usb.sh
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
secureboot/     Microsoft-signed shim preparation (runbook, key ceremony, shim build)
docs/           Architecture Decision Records + guides
.github/        CI workflows (build-image, promote, release-installer, build-kernel)
VERSION         semantic version base for channel tags
```

## Architecture decisions

- [ADR-0002 — Secure Boot, zero-touch](docs/ADR-0002-secure-boot-zero-touch.md)
- [ADR-0003 — Base OS, update model & open-core](docs/ADR-0003-base-and-update-model.md)
- [ADR-0004 — TPM2/LUKS two-domain encryption](docs/ADR-0004-disk-encryption-tpm-luks.md)
- [ADR-0005 — Release channels & promotion](docs/ADR-0005-release-channels.md)
- [ADR-0006 — Kernel page size: 4k instead of kernel-64k](docs/ADR-0006-kernel-4k-page-size.md)
- [ADR-0007 — Repository license: FSL-1.1-ALv2](docs/ADR-0007-license-fsl.md)

## License

**[FSL-1.1-ALv2](LICENSE.md)** (Functional Source License, source-available): use,
audit, modify and redistribute freely for any purpose **except offering a competing
commercial product or service** — internal use, professional evaluation, security
auditing, education and research are all permitted. **Each release automatically
becomes Apache-2.0 two years after publication.** Rationale:
[ADR-0007](docs/ADR-0007-license-fsl.md). Contributions: DCO — see
[CONTRIBUTING.md](CONTRIBUTING.md).

Third-party components built or installed by these recipes (Linux kernel, GRUB2,
CentOS Stream packages, NVIDIA driver, shim, …) remain under their respective
upstream licenses.
