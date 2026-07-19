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
- **Immutable OCI source** — CI publishes digest-addressable GB10 artifacts to
  `ghcr.io/neural-ice/neural-ice-coreos`; Fabric mirrors approved digests and
  signed product trains drive atomic OTA + rollback. See
  [ADR-0003](docs/ADR-0003-base-and-update-model.md).
- **Flashable USB installer** — dual-mode (Live / Install), light or preloaded
  edition (see [docs/PRELOADED-EDITION.md](docs/PRELOADED-EDITION.md)).

---

## Artifact publication and product release trains

This repository is a producer, not a release-channel authority. A trusted `main`
build publishes one run-unique immutable GHCR tag and reports its digest. It never
logs in to the sovereign registry and never moves `beta`, `stable`, `latest`, or
any other alias.

ICE-Fabric centrally mirrors an approved digest to `registry.neural-ice.ch`, binds
it into a signed BOM, and moves only the signed product-train `beta`/`stable`
pointers. Appliances install the BOM's digest with `bootc switch --retain`; the
current `.72` validation uses `beta`, while `stable` remains untouched.

---

## Install on a DGX Spark

The vanilla OS source image is public on GHCR. Resolve an immutable tag to a digest
and pass that exact reference when building a local installer:

```sh
BASE_IMAGE='ghcr.io/neural-ice/neural-ice-coreos@sha256:<digest>' ./image/build-installer-usb.sh
```

The local build writes `${OUT:-/var/tmp/ice-coreos-bib}/image/disk.raw`. Then:

1. Take that exact `disk.raw` (or set `OUT` explicitly before building).
2. Flash it to a USB stick:
   ```sh
   sudo dd if=/var/tmp/ice-coreos-bib/image/disk.raw of=/dev/sdX bs=64M oflag=direct conv=fsync status=progress
   ```
3. **Inject your SSH key** (the vanilla image has none) — either:
   - drop your public key onto the USB's EFI partition at `ice-coreos/authorized_keys`
     after flashing and byte-verifying the raw image; debug CI images keep sshd
     enabled but are keyless by default, so this per-USB injection is the normal path
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
(GB10 kernel (4k) RPMs with signed NVIDIA modules, NVIDIA userspace, signed boot payload):

```
$HOME/neural-ice/artifacts/generations/<run-id>/
  rpms/  nvidia-userspace/  signed-boot/  generation.env  manifest.sha256
$HOME/neural-ice/artifacts/current -> generations/<run-id>
```

`ci/stage-artifacts.sh` verifies the five exact, coherent aarch64 RPMs (including
`kernel-modules-nvidia-open`) and snapshots them as an immutable **candidate**. It deliberately
does not move `current`. The signing pipeline must sign that candidate's exact vmlinuz and emit its
candidate ID, uname and unsigned-vmlinuz hash in `signed-boot-provenance.env`; finalization matches
that provenance before checking the signed shim, GRUB, MokManager and vmlinuz. Only that complete, checksummed generation
can atomically move `current`. An incomplete, mismatched, stale or interrupted candidate leaves the
previous buildable generation untouched.

The heavy kernel workflow is requested from the default branch only. Both values are immutable
inputs; update them deliberately when the upstream kernel or driver is approved:

```sh
gh api repos/Neural-ICE/ICE-CoreOS/dispatches \
  -f event_type=build-coreos-kernel \
  -F 'client_payload[kernel_ref]=fa4faa0227e00c2291e47b120e71c7aed0fe27b7' \
  -F 'client_payload[nvidia_driver_version]=595.58.03'
```

For operator recovery on the Spark, reactivation of a retained generation is explicit,
checksummed and atomic:

```sh
ARTIFACTS_ROOT="$HOME/neural-ice/artifacts" \
  ./ci/artifact-generation.sh activate <previous-generation-id>
```

Finalization is an Owner-controlled signing gate, not part of `build-kernel`:

```sh
ARTIFACTS_ROOT="$HOME/neural-ice/artifacts" \
SIGNEDBOOT_SRC=/path/to/signed-boot-for-this-candidate \
SIGNED_BOOT_TRUST_POLICY_BIN="$PWD/secureboot/trust-policies/neural-ice-secureboot-lab-v1" \
SIGNED_BOOT_TRUST_POLICY_ID=neural-ice-secureboot-lab-v1 \
  ./ci/artifact-generation.sh finalize <candidate-generation-id>
```

The trust-policy command is mandatory and fail-closed. It must verify the approved signer mapping
(Microsoft UEFI signer for shim/boot fallback, Neural ICE signer for GRUB, MokManager and vmlinuz).
Its trust anchors and mapping remain an Owner/Secure-Boot decision; the staging code never invents
or accepts an implicit certificate.
Successful finalization records the policy ID and executable SHA-256 inside the generation's
checksummed `trust-policy.env`; later materialization and rollback revalidate that durable
attestation without depending on an external process environment. Any public trust-anchor files
used by a policy must have their exact hashes enforced by that executable, so its recorded hash
binds the complete signer mapping.

The image consumer then applies a second, source-controlled gate and re-runs the exact policy:

- `debug` accepts only `secureboot/trust-policies/neural-ice-secureboot-lab-v1`, its exact
  executable SHA-256 and the matching attestation;
- `prod` accepts only a future `neural-ice-secureboot-prod-v1` executable and matching
  attestation. Until that reviewed policy exists, production builds fail closed.

Repository variables and secrets cannot override this mapping. A policy edit changes its hash and
therefore requires a new Owner-controlled finalization before another image can be built.

For local builds, first materialize the verified finalized generation, then build:

```sh
ARTIFACTS_ROOT="$HOME/neural-ice/artifacts" STAGING_DEST=image \
  ./ci/artifact-generation.sh materialize

# Dev image with a baked SSH key (LAB only — keys in the image do not survive
# a `bootc switch` to a keyless image; prefer the persistent authorized_keys):
SSH_AUTHORIZED_KEY="ssh-ed25519 AAAA... me@host" VARIANT=debug ./ci/build-image.sh

# VARIANT=prod remains unavailable until the reviewed production policy and a
# generation finalized by that exact policy exist.
```

CI publishes only through an explicit repository dispatch, which always executes the workflow
from the default branch. There is no push/merge default and the variant has no implicit value. A
keyless LAB debug build is requested with:

```sh
gh api repos/Neural-ICE/ICE-CoreOS/dispatches \
  -f event_type=build-coreos -F 'client_payload[variant]=debug'
```

Run-unique CoreOS source artifacts keep the native `bootc-fetch-apply-updates.timer`
masked: an immutable tag cannot be an update channel. Fabric composes the branded
appliance from this digest and its signed OTA controller performs
`bootc switch --retain` to later train digests.

### CI runner

The build/installer workflows run on a **self-hosted ARM64 runner** (a DGX Spark or an
ARM64 build host) because they need native aarch64, `podman` + `bootc-image-builder`, and
the staged GB10 artifacts. Register one with the
[GitHub Actions runner](https://docs.github.com/actions/hosting-your-own-runners) and the
labels `self-hosted, Linux, ARM64, spark`. Mirroring and signed train promotion run
only in ICE-Fabric on the designated self-hosted infrastructure.

GHCR auth: workflows use only the job-scoped `GITHUB_TOKEN` (`packages: write`); no PAT fallback
is supported. Keep the `neural-ice-coreos` package **public** for free community pulls.

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
.github/        CI workflows (immutable build, installer tooling, kernel build)
VERSION         semantic version base for immutable source tags
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
