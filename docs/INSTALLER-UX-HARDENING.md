# Installer UX hardening — the USB install is the PRIMARY client path

**Owner decision (2026-07-03):** appliances will mostly be sold online — the customer
flashes and installs the appliance **themselves**. The USB installer is therefore the
main product experience, not a recovery path. The boot flakiness observed during the
2026-07-02/03 install session on the GB10 must be engineered away, not documented around.

## What we lived through (field notes, GB10 / DGX Spark firmware, AMI Aptio 2.22)

| Symptom | Root cause (established) |
|---|---|
| Firmware boots the internal NVMe even with the USB plugged | No NVRAM boot entry existed for the USB; this firmware does not reliably try the removable-media fallback on its own |
| Scary "system restore, auto-starts, 5 s to cancel" screen | `\EFI\BOOT\BOOTAA64.EFI` (shim) chain-loads **`fbaa64.efi` (fallback.efi)**, which re-creates NVRAM entries from `BOOTAA64.CSV` and **resets the machine**. Standard shim behaviour — terrifying UX for a client |
| Boot entry appears as "Red Hat Enterprise Linux" | Label comes from the shim's `BOOTAA64.CSV` (our signed shim is built from RHEL sources) |
| "Neural ICE - Install" menu entry sometimes not rendered | The install entry is a **cloned BLS file** (`ostree-0-install.conf`); blscfg rendering of the clone is not deterministic (the live's `bootloader-update.service` regenerates entries between boots) |
| USB menu and NVMe menu are indistinguishable | Both show `Neural ICE CoreOS (debug) (ostree:N)` titles; both put grub on gpt2 (`$prefix` does not disambiguate either) |

## Fixes (build-installer-usb.sh / autoinstall) — REQUIRED before client shipping

1. **Kill the fallback dance on the installer USB**: remove `\EFI\BOOT\fbaa64.efi`
   (and/or `BOOTAA64.CSV`) from the installer ESP. Booting the USB from the firmware
   boot menu then goes STRAIGHT to our GRUB — no NVRAM rewrite, no auto-reset, no
   "restore" screen. (The fallback mechanism is for OS media that want persistent
   entries; a one-shot installer must not touch the customer's NVRAM.)
2. **Static install menuentry** in the USB `grub.cfg` (not a BLS clone): always rendered,
   deterministic order, explicit title. Distinct live title too:
   `Neural ICE Installer (Live)` + `Neural ICE - Install (wipes the internal disk)`.
3. **Branded, clean NVRAM on the installed system**: autoinstall already creates the boot
   entry; also (a) label it `Neural ICE` (not "CentOS Stream"), (b) delete stale entries
   pointing at wiped partition GUIDs (old "CentOS"/"Ubuntu" leftovers make the firmware
   menu a minefield), (c) put it first in BootOrder.
4. **Ship a branded `BOOTAA64.CSV`** on the *installed* ESP (`Neural ICE`) so any future
   fallback run shows our name, never "Red Hat Enterprise Linux".
5. **First-boot friendliness is already good** (TUI dashboard, no login prompt) — keep it.

## Client install journey (online sale, self-service)

```
buy on portal → download installer (R2-gated) → flash USB
  → (v0.45 cockpit: the Tauri app downloads + flashes + guides)
→ plug into DGX Spark → firmware boot menu (one keypress, documented per device)
→ USB GRUB: "Neural ICE - Install" → unattended install (LUKS2+TPM2, seed staging)
→ RECOVERY KEY shown + saved on the USB ESP (customer writes it down)
→ remove USB, reboot → TUI dashboard → onboard with serial + purchase email
```

- The Tauri **v0.45 "single cockpit"** (download + flash + guided boot) is promoted to a
  core deliverable of the online-sales funnel, not a nice-to-have.
- The docs page must include per-firmware boot-menu instructions (DGX Spark first),
  with photos, and explain the recovery key.

## Validation checklist (each installer release)

- [ ] Fresh USB on a machine with a populated NVMe: firmware boot menu → USB → our GRUB
      appears with BOTH entries, correctly titled — first try, no reset loop.
- [ ] Install completes unattended; recovery key printed + on USB ESP.
- [ ] Installed system: single branded `Neural ICE` NVRAM entry, no stale entries.
- [ ] First boot: TUI on HDMI; `podman images` shows the seed images R/O instantly
      (zero-import); no failed units.
