# ADR-0041 — GB10 GSP firmware must live in the initramfs

Status: Accepted (2026-07-23)
Relates to: ADR-0006 (GB10 kernel), the `kernel-modules-nvidia-open` install in `image/Containerfile.bootc`

## Context

The GB10 (`nvidia-gb10`) kernel ships the nvidia open modules inside the kernel
RPM's canonical initramfs, and udev coldplug loads them **early, in the
initramfs**. The GPU's GSP firmware (`nvidia/<ver>/gsp_ga10x.bin`, ~72 MB) is
**not** in that initramfs — it lives only in `/usr/lib/firmware` on the deployed
root.

When nvidia loads before the real root is available, `Direct firmware load for
nvidia/<ver>/gsp_ga10x.bin` fails with `-2` (ENOENT) → `RmInitAdapter failed` →
the GPU is dead for the entire session. Because `nvidia-drm` then never obtains a
KMS device, `fbcon` stays on `simpledrm` at the firmware GOP mode (800x600), so
the appliance console (and its TUI) is stuck at ~37x100 instead of the panel's
native ~67x240 (1920x1080). The failure is **intermittent** — a load-order race
the early path sometimes wins — which reads as a flaky GPU/TUI regression.

Diagnosed live on the .72, 2026-07-23.

## Decision

The image **regenerates the initramfs at build time** with a dracut drop-in
(`91-neural-ice-nvidia-gsp.conf`) that:

- `install_items` the GSP firmware (`gsp_ga10x.bin`, `gsp_tu10x.bin`), and
- `force_drivers` the nvidia stack,

so the GPU initializes deterministically and `nvidia-drm` owns the console from
boot. The firmware version is **derived from what the kernel generation staged**
(`ls /usr/lib/firmware/nvidia/*/gsp_ga10x.bin`), never pinned, so any
`nvidia_driver_version` supported by `build-kernel.yml` works. The build asserts
`gsp_ga10x.bin` is present in the produced initramfs.

This intentionally **re-enables** the initramfs regeneration that the branding
step had skipped for build speed / smaller OTA deltas (§3b comment) — a GPU that
actually initializes is worth the rewrite.

## Invariant (for future kernel/driver updates)

**Omitting this regeneration reintroduces the GPU-init failure (and the 800x600
console).** Any change to the GB10 kernel, the nvidia driver version, or the
initramfs pipeline MUST keep the GSP firmware in the initramfs and keep the
build-time assertion. Do not "optimize" it away.

## Validation

Applied at runtime on the .72 (same dracut conf + `rpm-ostree initramfs
--enable` + reboot): `nvidia-smi` → NVIDIA GB10, console → 240x67, single DRM
driver = nvidia. Durable across reboots.
