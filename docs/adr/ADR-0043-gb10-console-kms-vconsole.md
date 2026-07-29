# ADR-0043 — GB10 console KMS and vconsole configuration belongs in the initramfs

- **Status**: Accepted
- **Date**: 2026-07-29
- **Decider**: Business/Security Owner (human)
- **Relates to**: ADR-0006 (GB10 kernel), ADR-0041 (GSP firmware), ADR-0042 (R580 qualification)

## Context

During live R580 validation on the `.72`, tty1 sometimes restarted at 100x37
instead of 240x67. The GSP firmware was present and the NVIDIA stack could
initialize, but `nvidia_drm` reported `modeset=N`. A late recovery unit was not
a durable solution: it attempted `/usr/bin/modprobe` while CentOS Stream 10
provides `/usr/sbin/modprobe`, and unloading/reloading the display module after
boot races fbcon and GPU consumers.

The live hotfix loaded `nvidia_drm` with `modeset=1 fbdev=1` and selected
`default8x16`; tty1 returned to 240x67. The image must establish that state
before the module's first load, without retaining mutable `/etc` repair steps.

## Decision

The vanilla ICE-CoreOS image:

1. ships `options nvidia_drm modeset=1 fbdev=1` as a vendor configuration in
   `/usr/lib/modprobe.d`;
2. ships `/etc/vconsole.conf` with `FONT=default8x16` as an image default;
3. orders `nvidia_drm` before `nvidia_uvm` in `modules-load.d`;
4. adds the modprobe configuration, vconsole configuration and resolved font
   file to dracut `install_items`;
5. keeps `nvidia_drm` in `force_drivers`, so modprobe applies the options during
   the initial initramfs load; and
6. fails the image build unless the generated initramfs lists the GSP firmware,
   modprobe configuration, vconsole configuration and font.

No late unload/reload unit is introduced. No product TUI, application
configuration or workload enters the open-core image.

## Rollback analysis

The change adds no persistent state, schema, kernel argument or boot-time
mutation. A one-version `bootc rollback` selects the previous deployment and
its previous initramfs; the vendor modprobe file under `/usr/lib` therefore
rolls back with the deployment.

`/etc/vconsole.conf` is an image-owned default subject to bootc/ostree `/etc`
merge semantics. If the default remains after rollback, `default8x16` is
supported by both R580 and the retained R595 deployment and is safe. If the
previous default is restored, the prior deployment keeps its former console
behavior. In either case rollback remains bootable and does not alter OTA
anti-rollback authority. The retained deployment and artifact generation must
not be deleted during hardware qualification.

## Consequences

- (+) NVIDIA KMS/fbdev is deterministic from the first module load.
- (+) tty1 geometry no longer depends on a mutable hotfix or a late module reload.
- (+) Missing console artifacts fail the image build instead of surfacing after flash.
- (-) Regenerating the initramfs continues to carry the build-time and OTA-delta
  cost already accepted by ADR-0041.
- (-) Hardware geometry still requires validation on GB10; static tests can
  prove artifact composition, not the physical framebuffer result.

## Validation

The deterministic artifact test is `./ci/test-gb10-console-boot.sh`. The
hardware procedure and rollback proof are documented in
`docs/RUNBOOK-GB10-CONSOLE-BOOT.md`.
