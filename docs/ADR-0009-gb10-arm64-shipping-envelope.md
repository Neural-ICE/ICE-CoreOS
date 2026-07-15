# ADR-0009 — Current shipping envelope: GB10 ARM64 bootc only

- **Status**: Accepted
- **Date**: 2026-07-15
- **Decider**: Business/Security Owner (explicit industrial-package GO)
- **Supersedes for current trains**: ADR-0008's requirement to publish one
  ARM64+AMD64 bootc manifest before an x86 SKU is hardware-qualified
- **Related**: ADR-0002 (Secure Boot), ADR-0004 (TPM/LUKS), ADR-0005 (release
  channels), ADR-0006 (GB10 kernel), ICE-Fabric ADR-0018 (multi-arch payloads),
  ADR-0026/ADR-0034 (signed, entitlement-scoped release trains)

## Context

The only shipping and validation appliance is the NVIDIA DGX Spark/GB10. Its bootc
image is not architecture-neutral: it contains the GB10-specific 4 KiB kernel,
signed NVIDIA modules and userspace, an ARM64 Secure Boot chain, and an installer
validated against DGX Spark firmware. The ARM64 self-hosted build runner is also
the only runner holding those staged hardware artefacts.

ADR-0008 describes a valid future RTX PRO Blackwell x86_64 SKU. That SKU does not
yet have its required reference hardware, signed shimx64 chain, driver smoke test,
installer validation, TPM/PCR validation, or rollback evidence. Creating an AMD64
manifest entry from the ARM64 image, or from an unqualified generic CentOS image,
would claim support that does not exist and could deliver an unbootable OS.

Architecture-neutral product containers are a separate concern. They remain
subject to the ARM64+AMD64 publication requirement in ICE-Fabric ADR-0018.

## Decision

1. The current ICE-CoreOS product image, installer, and release-train
   `appliance.os_base` are explicitly **hardware-bound to linux/arm64 GB10**.
2. The immutable version tag and the `beta` channel may therefore resolve to a
   single ARM64 image. This is an intentional support envelope, not a partially
   successful multi-arch build.
3. CI must assert that the published OS image reports `linux/arm64`. It must not
   create a `linux/amd64` descriptor by copying, relabelling, emulation, or manifest
   surgery.
4. Signed BOMs identify the GB10 hardware target in their compatibility data. The
   OTA controller must continue to reject an incompatible train before pulling or
   staging the OS.
5. `beta` remains the only validation ring for the current appliance. `stable` is
   promoted only from the exact, previously validated digest; this ADR does not
   authorize a promotion.
6. The exception stops at the bootc OS and hardware-specific installer payloads.
   ICE-AC1, gateways, connectors, CPU/glue images, the thin client, and other
   architecture-neutral deliverables still build and test natively for ARM64 and
   AMD64 and publish real manifest lists where OCI applies.

## Re-opening the x86_64 SKU

ADR-0008 becomes actionable only after all of the following exist:

- designated RTX PRO Blackwell reference hardware and self-hosted X64 runner;
- stock-el10 kernel plus signed NVIDIA driver build and `nvidia-smi` smoke test;
- shimx64, GRUB, kernel and module Secure Boot chain;
- x86_64 installer, TPM2/LUKS PCR7 enrollment and recovery validation;
- signed beta train with install, reboot, health and rollback evidence;
- an Owner decision to add that SKU to the supported release envelope.

Only then may CI assemble one ARM64+AMD64 bootc index and move a shared channel.

## Consequences

- The two-week client demonstration uses the image that is actually qualified on
  the only appliance, without fabricating platform coverage.
- OS channel and rollback semantics remain unchanged: immutable digest, signed
  train, `bootc switch --retain`, explicit `pending_reboot`, and retained rollback.
- A future x86 appliance is visible as a hardware-enablement project instead of a
  misleading CI checkbox.
- Multi-arch enforcement remains strict for every architecture-neutral payload.
