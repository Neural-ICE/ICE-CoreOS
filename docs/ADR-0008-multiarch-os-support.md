# ADR-0008 — Multi-architecture OS support (aarch64 + x86_64, aarch64 first)

- **Status**: Proposed
- **Date**: 2026-07-09
- **Decider**: Business/Security Owner (human)
- **Links**: [[ADR-0002-secure-boot-zero-touch]] (per-arch shim chain),
  [[ADR-0003-base-and-update-model]] (bootc/OTA — unchanged, extended per arch),
  [[ADR-0005-release-channels]] (channels become arch-aware),
  [[ADR-0006-kernel-4k-page-size]] (aarch64-specific; does not apply to x86_64).
- **Guiding principle**: *one OS, one update model, both platforms — aarch64 ships
  first and stays the priority.*

## Context

ICE-CoreOS today positions itself as an OS **for NVIDIA DGX Spark (GB10, ARM64)**.
The appliance product line, however, supports **two hardware platforms**:

1. **aarch64 — DGX Spark (GB10 Grace-Blackwell)**: the shipping platform, priority.
2. **x86_64 — workstation hardware with NVIDIA RTX PRO (Blackwell) GPUs**: the
   sanctioned second platform (owner decision 2026-07-09; no other x86 GPU targets).

Parts of the tooling already anticipate this: `build/build-kernel.sh` accepts
`<aarch64|x86_64>`, `ci/build-image.sh` takes an OCI `PLATFORM` (defaulting to
`linux/arm64`). What is missing is the doctrine, the per-arch chain end-to-end
(kernel → image → installer → Secure Boot → OTA), and CI that keeps x86_64 from
bit-rotting while aarch64 leads.

The two architectures are NOT symmetric at the kernel layer, and the asymmetry is
an advantage:

- **aarch64/GB10** needs the custom `nvidia-gb10` kernel tree (4 KiB flavor,
  ADR-0006) because GB10 is absent from stock el10.
- **x86_64/RTX PRO** boots on the **stock CentOS Stream 10 kernel** — no custom
  tree, no fork maintenance. Only the NVIDIA open driver (r595 line, which
  supports Blackwell workstation GPUs) is built and signed as an out-of-tree
  module, exactly as on aarch64.

## Decision

1. **The bootc OS image is published per-arch and referenced by ONE manifest list**
   (`linux/arm64` + `linux/amd64`, arm64 first). `bootc upgrade` on an appliance
   resolves its own architecture from the list — one OTA ref, both platforms,
   release channels (ADR-0005) stay arch-agnostic at the ref level.
2. **Kernel strategy per arch**:
   - aarch64: unchanged — `nvidia-gb10` 4 KiB kernel + signed NVIDIA open driver.
   - x86_64: **stock el10 kernel** + the same signed NVIDIA open driver kmod
     (RTX PRO Blackwell). No custom kernel tree is created or maintained for x86.
3. **Secure Boot covers both arches**: the shim-signing track (Microsoft submission,
   `secureboot/runbook-shim-signing.md`) MUST submit **`shimaa64` and `shimx64`**
   together — one review cycle, two binaries. The rest of the chain (GRUB2, kernel,
   kmod signing with our key) is arch-parallel by construction.
4. **Installer images (USB) are built per arch** from the same tooling
   (`image/build-installer-usb.sh`, `image/build-preloaded.sh` gain an explicit
   `ARCH` parameter instead of an implicit arm64 default).
5. **CI builds both arches on every release**; an x86_64 build failure blocks a
   release exactly like an aarch64 one. aarch64 remains first in every list,
   first in smoke-test order, and the reference platform in docs.
6. **Positioning**: README/docs move from "an OS for DGX Spark" to "an OS for
   NVIDIA edge-AI appliances — DGX Spark (aarch64, reference) and RTX PRO
   Blackwell workstations (x86_64)".

## Consequences

- (+) One OTA ref and one release process for the whole fleet; porting the
  appliance product to x86 requires no OS-side special-casing.
- (+) The x86 kernel is stock: LESS maintenance than the aarch64 path, and it
  benefits from upstream el10 security updates without a rebase workflow.
- (−) Every release now builds two image sets (bootc image, installer, preloaded);
  CI wall-clock and artifact storage roughly double.
- (−) x86_64 needs its own build/test host with an RTX PRO Blackwell GPU for the
  driver smoke test (`nvidia-smi` gate) — hardware to provision before the first
  x86 release can be called supported.
- (−) TPM2/LUKS (ADR-0004) and zero-touch enrollment must be re-validated on the
  x86 reference machine (PCR 7 measurements differ per firmware).
- (◦) Until the first x86_64 release ships, the manifest list may legitimately
  contain only arm64 — consumers must treat a missing arch as "not yet supported",
  not as an error in the doctrine.

## Non-goals

- No x86 datacenter GPUs (H100/A100), no pre-Blackwell consumer GPUs.
- No 32-bit, no riscv64, no Windows/WSL.
- No cross-building of the GB10 kernel from x86 (native builds per arch).
