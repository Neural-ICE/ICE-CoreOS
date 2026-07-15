# AGENTS.md — ICE-CoreOS

This file supplements the Neural ICE global AGENTS.md and governs this public
base-OS repository.

## Open-core boundary

ICE-CoreOS is the vanilla CentOS Stream 10 + bootc host image. It owns the
GB10 kernel/driver integration, installer, first boot, Secure Boot preparation,
TPM/LUKS integration, and host OTA verifier. It must contain no Neural ICE
product IP, gated configuration, branding beyond the public distro, customer
credentials, product TUI, models, or appliance workloads. Product composition
and Quadlets belong in ICE-Fabric.

Read the applicable ADR before editing. In particular:

- ADR-0003 and ADR-0005 govern base image and channels.
- ADR-0004 governs TPM/LUKS.
- ADR-0006 fixes the GB10 kernel to 4 KiB pages.
- ADR-0008 governs multi-architecture support.
- secureboot/ documents the signing boundary and ceremonies.

## Host invariants

- The deployed host is immutable. Host changes are image changes; never add a
  post-install mutation or require an operator to repair /usr.
- SELinux remains enforcing. Add correct labels/policy, never privileged or
  label-disabled workarounds.
- Preserve bootability, atomic update, rollback, and recovery on both supported
  architectures. Architecture-specific artifacts and logic must fail clearly.
- Keep the vanilla image keyless. Development SSH injection is explicit and
  must never become a production default.
- AI services are containers and examples use Quadlets, not compose or ad hoc
  production podman commands.
- The bootc and installer release set must support linux/arm64 and linux/amd64.
  ARM64/sm_121 is the priority platform, not an ARM64-only release exception.
  OCI publication must expose one verified multi-arch manifest list.
- Builds consume staged, verified artifacts. Never commit RPMs, driver blobs,
  signing keys, recovery keys, or generated work/ output.

Any change to Secure Boot, TPM enrollment, encryption, installer disk writes,
OTA verification/origins, rollback, release channels, signing, or persistent
layout requires Owner approval before implementation. These changes also need
an explicit recovery and one-version rollback analysis.

## Repository map

- image/ is the bootc image, installer, overlays, first boot, and payload apply.
- ota/ is installer/autoinstall systemd behavior.
- ignition/ is first-boot provisioning.
- build/ and ci/ create/stage the heavy GB10 inputs and OS image.
- secureboot/ contains the controlled signing preparation and runbooks.
- tools/ni-ota-verify/ is the on-device signed/anti-rollback verifier.
- examples/quadlets/ are examples only, not product deployment.

Keep docs and ADRs synchronized with changed boot, config, file, unit, image,
and channel contracts.

## Verification

Run cheap deterministic checks locally:

    shellcheck build/*.sh ci/*.sh image/*.sh image/firstboot/*.sh image/mdns/*.sh image/payload/*.sh ota/*.sh secureboot/shim/*.sh
    cargo fmt --manifest-path tools/ni-ota-verify/Cargo.toml --check
    cargo clippy --manifest-path tools/ni-ota-verify/Cargo.toml --all-targets --all-features -- -D warnings
    cargo test --manifest-path tools/ni-ota-verify/Cargo.toml --locked --all-targets

Image, kernel, installer, Secure Boot, destructive disk, GPU, and boot/rollback
tests run only in the designated self-hosted or disposable hardware path.
Never publish, promote, enroll keys, flash disks, or alter signing material as
part of ordinary validation.
