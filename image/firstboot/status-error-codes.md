# Boot status screen — error codes

`neural-ice-status-screen.service` draws a non-interactive status screen on
tty1 on every boot (`image/firstboot/neural-ice-status-screen.sh`). When a
watched unit fails, or the TPM owner ceremony has not completed within
`NI_STATUS_CEREMONY_TIMEOUT` seconds (default 1800, set in the unit), the
screen switches to a FAILURE block:

```
 ##############################################################################
 #  FAILURE  NI-E02  (TPM ceremony)
 #  unit:    neural-ice-firstboot-tpm-ceremony.service
 #  serial:  <DMI product serial, as printed on the chassis label>
 #  Contact Neural ICE support with this code and serial.
 ##############################################################################
```

The code is **stable**: it names the phase, never the cause. Support maps the
code plus the serial to the journal of that appliance. The screen prints
nothing else about the failure by design — no recovery key, no LUKS/TPM
material, no licence, no token, no fingerprint (`image/test-status-screen.sh`
asserts the script cannot read those paths).

| Code   | Phase          | Trigger (unit in `failed`, unless stated)                                          |
|--------|----------------|------------------------------------------------------------------------------------|
| NI-E01 | storage unlock | `systemd-cryptsetup@data.service` or `var-lib-neural\x2dice-data.mount`            |
| NI-E02 | TPM ceremony   | `neural-ice-firstboot-tpm-ceremony.service` failed, **or** still `activating` after `NI_STATUS_CEREMONY_TIMEOUT` s |
| NI-E03 | network        | `NetworkManager.service`                                                            |
| NI-E04 | image pull     | v1: `neural-ice-seed-import.service` or `neural-ice-payload-apply.service`; v2: `ni-v2-seed-import.service` or `ni-v2-first-pull.service` |
| NI-E05 | core service   | any unit of the core-services list (below); the failed unit names are shown         |

When several phases fail at once, the **earliest phase wins** (E01 before E02
before …): the first thing that broke is the one to report.

## Phases shown (every boot)

| Line          | Source                                                                                  |
|---------------|-----------------------------------------------------------------------------------------|
| Storage       | `systemd-cryptsetup@data.service` + data mount state                                    |
| Device trust  | ceremony `activating` → "TPM owner ceremony running (elapsed)"; `active` → "device trust: sealed" |
| Network       | management NIC as published by `neural-ice-hostname-init` in `/run/neural-ice/mgmt-interface` (one rule, `neural-ice-mgmt-port`: first built-in wired port, never USB, never ConnectX; absent = "waiting for the management port"), `operstate`, first IPv4, receive rate and total from `/sys/class/net/*/statistics/rx_bytes` deltas (physical interfaces only) |
| Images (v1)   | N/M: `Image=` references declared in `/usr/lib/bootc/bound-images.d`, `/usr/share/containers/systemd`, `/etc/containers/systemd`, counted present when their digest (or name) appears in `overlay-images/images.json` of the graphroot, of the bootc bound-image store (`/usr/lib/bootc/storage`, the store `bootc install` fills from the medium) or of the seed store |
| Core services | fixed list below; `active`, or `inactive` with a failed `Condition*=`, counts as done   |
| READY         | ceremony active, network up with address, N = M, every core service done               |

On a **v2 host** the Images line and READY differ, see "v2 hosts" below.

## Core-services list

The OS ships `neural-ice-hostname-init.service`, `neural-ice-device-root.service`,
`neural-ice-payload-apply.service`, `avahi-daemon.service`. The branded
derivation (ICE-Fabric) appends its product units by shipping
`/usr/lib/neural-ice/status-screen/core-services` — one unit name per line, `#`
comments allowed. The OS itself carries no product knowledge (ADR-0032).

## v2 hosts

A host whose image carries `/usr/lib/neural-ice/ota-state-profile` =
`owner-sealed-ota-state-v2` is a v2 appliance (matched exactly; any other value
or no file keeps the v1 screen, byte for byte). Its components are not the
`Image=` references of the OS image but the components of the signed release
manifest the first boot imported, so:

| Line / state  | v2 source                                                                               |
|---------------|-----------------------------------------------------------------------------------------|
| Header        | `release <release_id>` from `/var/lib/neural-ice-v2/current-release/release-manifest.json` (`[A-Za-z0-9._-]`, else `unset`). The v2 manifest carries **no ring**, and no ring is stored on a v2 host, so the screen does not invent a `channel`. |
| Images        | N/M: M = components of that manifest, N = those whose alias `localhost/neural-ice-applied/<id>:v1` **and** manifest digest are both in `overlay-images/images.json` (graphroot, bootc store or seed store; the alias is what the first pull and the preload import both tag). `[ .. ]` until `ni-v2-seed-import.service` **and** `ni-v2-first-pull.service` are themselves done: `active`, skipped by their `Condition*=` (a full preload never starts the first pull) or not shipped. Having pulled the last image is not done: the unit still commits the aliases and its DONE marker. |
| Images, no manifest | `[    ] waiting for the attested release manifest` (import not finished) or `release manifest names no readable component`; never the v1 "no product image inventory" skip, and never READY. |
| NI-E04        | `ni-v2-seed-import.service` or `ni-v2-first-pull.service` in `failed` (a permanent refusal: signature, access profile, signed mirror endpoint/CA, digest, disk). A mirror outage keeps the first pull `activating` (it retries inside the unit), so the screen stays on `N/M present`. The v1 units are not watched. |
| Core services | `neural-ice-hostname-init`, `neural-ice-device-root`, `avahi-daemon`, `neural-ice-product-payload-apply` (ordered after the first pull, starts the product), `icecore-api` (the product core API, a Quadlet unit), plus the optional extension file. Units the image does not ship are skipped. |
| READY         | the v1 conditions, with Images and Core services as above: so not before the first pull is done, the product payload applied and the core API active. |

The screen only **displays** the manifest. Its signature is verified by the
first pull before it pulls anything, and the release receipt by the owner
ceremony; this screen reads no key and does not re-verify.

## Header

Product name (`/usr/lib/os-release`), OS version (`/usr/lib/neural-ice/version`),
booted image short digest (12 hex, `bootc status`; fallback: the `ostree=`
deployment checksum from the kernel command line, prefixed `deploy`), device
channel (v1: `/var/lib/neural-ice/data/release/CHANNEL`, fallback `device_channel=`
in `/etc/neural-ice/ota.conf`; v2: the release id instead, see above), DMI vendor + model + serial
(`/sys/class/dmi/id`), hostname.

**Identity policy.** The only device-identifying data on screen is what the
chassis label already prints (DMI model + serial) plus the hostname the
appliance broadcasts over mDNS. The short image digest identifies the
appliance's **software version** (which build is running, for support), not
the device: it is the same for every appliance on that release and is therefore
not a fingerprint. Nothing else — no key, no LUKS/TPM material, no licence, no
token, no hardware fingerprint — is read or printed; `image/test-status-screen.sh`
holds the script to an explicit allow-list of readable paths.

## Unknown state

`systemctl show` failing is **not** a state. A unit the manager cannot answer
for is shown as `probing...`, READY is withheld while any watched probe is
unanswered, and no NI-Exx code is raised for it (an absent unit —
`LoadState=not-found` — is different: it is skipped).

## Serial mirror (headless qualification)

Every stable line is also written, **once per change**, to the kernel's own
serial console as plain `neural-ice-status: <text>` lines — never the
per-second redraw, never the volatile rate/elapsed part. The UART is taken from
`/sys/class/tty/console/active` (virtual terminals excluded), then from
`console=` on the kernel command line; only `ttyS<n>` and `ttyAMA<n>` qualify,
because those are the two nodes the unit's `DeviceAllow=` opens (GB10 image:
`ttyS0`; QEMU aarch64 `virt`: `ttyAMA0`). No serial console configured means no
mirror, and the tty1 screen is unaffected. `image/qualify-installer-qemu.sh` captures that
console, so a first-boot qualification can require:

```
--expect 'neural-ice-status: \[ OK \] Device trust: device trust: sealed'
--expect 'neural-ice-status: READY -- login available'
--reject 'neural-ice-status: FAILURE NI-E'
```

A serial write is bounded by `timeout 2`; the first failed write disables the
mirror for the rest of the boot (a port with no carrier must never hang the
screen). On the debug variant the mirror lines land in the serial autologin
session; on sealed variants nothing else writes there.

## Exit

The script exits on its own once READY has been shown for
`NI_STATUS_READY_LINGER` seconds (default 10), or as soon as a tty1 owner —
`getty@tty1.service` (debug variant) or `neural-ice-tui.service` (branded
appliance) — is active. Ownership is re-asked from the manager immediately
before every write to tty1 (and in the exit handler): a frame prepared while
the owner was starting is dropped, never drawn. The unit is never restarted
within a boot and is stopped on shutdown (`Conflicts=`/`Before=shutdown.target`,
`TimeoutStopSec=5`).
