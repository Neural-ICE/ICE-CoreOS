# ADR-0010 — Hardware-targeted bootc identity

- **Status:** Accepted
- **Date:** 2026-07-16
- **Decider:** Business/Security Owner
- **Extends:** ADR-0005, ADR-0008 and ADR-0009; companion to ICE-Fabric

## Context

DGX Spark/GB10 ARM64 is the only qualified appliance today. NVIDIA CUDA x86_64
support is planned next and AMD ROCm x86_64 later. Architecture alone cannot
distinguish the two x86 accelerator stacks, and a shared mutable channel could
therefore select a validly signed but unbootable OS.

## Decision

Every bootc SKU has one stable hardware target identity:

- `nvidia-gb10-arm64`;
- `nvidia-cuda-x86_64`;
- `amd-rocm-x86_64`.

The current GB10 image bakes `nvidia-gb10-arm64` into
`/usr/lib/neural-ice/hardware-target`. This immutable image-owned marker is the
device-side authority; `/etc/neural-ice/ota.conf` is only the fetch configuration.

The signed channel record and signed BOM both carry `hardware_target`.
`ni-ota-verify` refuses unless they agree with each other and with the immutable
host marker. `commit` repeats the host/BOM comparison before advancing the
anti-rollback state, so invoking it directly cannot commit another SKU's bundle.
The production binary always reads that marker from
`/usr/lib/neural-ice/hardware-target`; its environment-selectable path exists
only behind the non-default `test-path-overrides` Cargo feature used by
integration tests. The bootc build uses default features and therefore cannot
inherit a path override from a service environment.

Channels are target-scoped OCI records such as
`channels:nvidia-gb10-arm64-beta`; `latest` aliases are forbidden. A future x86
SKU receives a separate native bootc artifact and qualification path. We do not
combine hardware-bound bootc images into a synthetic cross-SKU manifest list.
Architecture-neutral application containers remain true ARM64+AMD64 manifests.

## Qualification gates for a new target

A target is not release-enabled until native CI proves its kernel/driver stack,
Secure Boot chain, installer, TPM/LUKS enrollment, GPU smoke test, OTA reboot,
health and rollback. Merely adding an OCI descriptor or running an emulated build
does not qualify a target.

## Rollback

Bootc keeps the previous deployment with `--retain`. Fleet recovery remains a new
higher-sequence signed bundle for the same hardware target. Neither path permits
cross-target rollback or promotion.
