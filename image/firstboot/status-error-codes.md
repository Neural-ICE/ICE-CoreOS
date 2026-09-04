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
| NI-E04 | image pull     | `neural-ice-seed-import.service` or `neural-ice-payload-apply.service`              |
| NI-E05 | core service   | any unit of the core-services list (below); the failed unit names are shown         |

When several phases fail at once, the **earliest phase wins** (E01 before E02
before …): the first thing that broke is the one to report.

## Phases shown (every boot)

| Line          | Source                                                                                  |
|---------------|-----------------------------------------------------------------------------------------|
| Storage       | `systemd-cryptsetup@data.service` + data mount state                                    |
| Device trust  | ceremony `activating` → "TPM owner ceremony running (elapsed)"; `active` → "device trust: sealed" |
| Network       | management NIC (`interface-name=` of `mgmt-*.nmconnection`, else on-board `enP<d>s<d>`), `operstate`, first IPv4, receive rate and total from `/sys/class/net/*/statistics/rx_bytes` deltas (physical interfaces only) |
| Images        | N/M: `Image=` references declared in `/usr/lib/bootc/bound-images.d`, `/usr/share/containers/systemd`, `/etc/containers/systemd`, counted present when their digest (or name) appears in `overlay-images/images.json` of the graphroot or of the seed store |
| Core services | fixed list below; `active`, or `inactive` with a failed `Condition*=`, counts as done   |
| READY         | ceremony active, network up with address, N = M, every core service done               |

## Core-services list

The OS ships `neural-ice-hostname-init.service`, `neural-ice-device-root.service`,
`neural-ice-payload-apply.service`, `avahi-daemon.service`. The branded
derivation (ICE-Fabric) appends its product units by shipping
`/usr/lib/neural-ice/status-screen/core-services` — one unit name per line, `#`
comments allowed. The OS itself carries no product knowledge (ADR-0032).

## Header

Product name (`/usr/lib/os-release`), OS version (`/usr/lib/neural-ice/version`),
booted image short digest (12 hex, `bootc status`; fallback: the `ostree=`
deployment checksum from the kernel command line, prefixed `deploy`), device
channel (`/var/lib/neural-ice/data/release/CHANNEL`, fallback `device_channel=`
in `/etc/neural-ice/ota.conf`), DMI vendor + model + serial
(`/sys/class/dmi/id`), hostname.

## Serial mirror (headless qualification)

Every stable line is also written, **once per change**, to the first serial
port present (`/dev/ttyAMA0`, then `/dev/ttyS0`) as plain
`neural-ice-status: <text>` lines — never the per-second redraw, never the
volatile rate/elapsed part. `image/qualify-installer-qemu.sh` captures that
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
appliance) — is active. It is never restarted within a boot.
