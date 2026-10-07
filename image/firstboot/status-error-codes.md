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
| NI-E04 | image pull     | v1: `neural-ice-seed-import.service` or `neural-ice-payload-apply.service`; with a product declaration: a unit of its `images_units=` |
| NI-E05 | core service   | any unit of the core-services list (below); the failed unit names are shown         |
| NI-E06 | status declaration | a product declaration under `status-screen.d` was refused (grammar below); the reason and the file name are shown. Not a boot phase: it ranks after E01–E05 and withholds READY |

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

On a host whose image ships a **product declaration** the Images line and READY differ, see "Product declarations" below.

## Core-services list

The OS ships `neural-ice-hostname-init.service`, `neural-ice-device-root.service`,
`neural-ice-payload-apply.service`, `avahi-daemon.service`. The branded
derivation (ICE-Fabric) adds its product units with a declaration (`core_units=`,
below) or, older, by shipping `/usr/lib/neural-ice/status-screen/core-services` —
one unit name per line, `#` comments allowed. A unit the image does not ship
(`LoadState=not-found`) is skipped. The OS itself carries no product knowledge
(ADR-0032): every product unit name, path and manifest key comes from the image's
declarations, and `image/test-status-screen.sh` fails if the script names one.

## Product declarations

A branded derivation tells the screen what its product needs with files
`/usr/lib/neural-ice/status-screen.d/*.conf`. **No directory = the v1 screen,
byte for byte.** An empty directory, or files whose name does not end in `.conf`,
change nothing.

Grammar (closed; the parser is `decl_parse` in the script):

- The directory and every `*.conf` file: owned by root, regular file (a symlink is
  refused), not group- or world-writable; at most 16 `*.conf` files, each at most
  4096 bytes of printable ASCII (no tab, CR, NUL or non-ASCII); the file name
  matches `[a-z0-9][a-z0-9._-]{0,63}\.conf`.
- Lines: empty, `# comment` (whole line only), or `key=value`: lower-case key, no
  space around `=`, no space starting the value, no key twice in a file, a
  non-empty value. A list is single-space separated.
- `version=1` is required. The `images_*` keys come **together** in one file
  (`images_release_key` optional) and only one file may declare them;
  `core_units` and `tty1_owners` may be given by several files. A file declaring
  none of them is refused.

| Key                      | Value                                                                                       |
|--------------------------|---------------------------------------------------------------------------------------------|
| `version=`               | `1`                                                                                          |
| `images_units=`          | 1–8 `*.service` names, in the order they run: the image phase. `failed` = NI-E04; READY waits until each is `active`, skipped by its `Condition*=`, or not shipped. Replaces the OS's own v1 image units and its v1 payload apply (they are no longer watched) |
| `images_manifest=`       | absolute path of the manifest listing the components, under `/var/lib/`, `/usr/lib/` or `/usr/share/` (plain components: no `.`, `..`, empty, space; at most 200 characters). Read as a regular file, never through a symlink, at most 1 MiB, as text only |
| `images_component_key=`  | JSON key (`[a-z][a-z0-9_]{0,31}`) whose string value is a component id (`[a-z0-9][a-z0-9._-]{0,127}`); each flat `{...}` object carrying it is one component |
| `images_digest_key=`     | JSON key whose string value is the component's `sha256:<64 hex>` digest                       |
| `images_alias=`          | alias of a component in containers-storage, `[a-z0-9._/:-]` with exactly one `{id}` replaced by the component id |
| `images_release_key=`    | optional JSON key whose string value (`[A-Za-z0-9._-]`, else `unset`) is shown as `release <value>` in the header instead of the v1 channel |
| `core_units=`            | 1–16 `*.service`/`*.target`/`*.mount`/`*.socket` names appended to the core services         |
| `tty1_owners=`           | 1–4 `*.service` names that take tty1 over from this screen (a kiosk compositor, for example). Added to the OS's own owners (`getty@tty1.service`, `neural-ice-tui.service`); an owner that is `active` ends the screen, one that is only `activating`, `failed` or absent owns nothing. Without this key the screen is the v1 screen, byte for byte |

With `images_*` declared:

| Line / state  | Behaviour                                                                                |
|---------------|------------------------------------------------------------------------------------------|
| Images        | N/M: M = components of the manifest, N = those whose alias **and** manifest digest are both in `overlay-images/images.json` (graphroot, bootc store or seed store). `[ .. ]` until every `images_units` unit is itself done: having fetched the last image is not done, the unit still commits. |
| Images, no manifest | `[    ] waiting for the release manifest` or `release manifest names no readable component`; never the v1 "no product image inventory" skip, and never READY. |
| Header        | `release <value>` when `images_release_key` is declared, else the v1 channel. A header never invents a value. |
| READY         | the v1 conditions, with Images and Core services as declared.                            |

The screen only **displays** the manifest: it never verifies a signature and
reads no key; verifying is the job of the product's own import/pull units.

**NI-E06.** A file that breaks any rule above contributes **nothing** (never
half-applied, never guessed) and is reported: `FAILURE NI-E06 (status declaration:
<reason>)` with `unit: <file name>` (the directory name for a directory-level
refusal) and on the serial mirror. Valid files keep applying. Reasons:
`unknown key <k>`, `key <k> given twice`, `line <n> is not key=value`,
`version=1 missing or unsupported`, `declares nothing`, `bad <key>`,
`missing key <key>`, `images declared by another file`,
`not printable ASCII`, `larger than 4096 bytes`, `unsafe owner or mode`,
`not a regular file`, `bad file name`, `more than 16 declarations`,
`not a plain directory`. The declaration is image content, trusted like the
image; what it can make the screen print is bounded (a release id of 40 safe
characters, counters, unit names that passed the unit grammar).

## Header

Product name (`/usr/lib/os-release`), OS version (`/usr/lib/neural-ice/version`),
booted image short digest (12 hex, `bootc status`; fallback: the `ostree=`
deployment checksum from the kernel command line, prefixed `deploy`), device
channel (v1: `/var/lib/neural-ice/data/release/CHANNEL`, fallback `device_channel=`
in `/etc/neural-ice/ota.conf`; with `images_release_key=`: the release id instead, see above), DMI vendor + model + serial
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
`getty@tty1.service` (debug variant), `neural-ice-tui.service` (branded
appliance) or a unit the image declares with `tty1_owners=` — is active. Ownership is re-asked from the manager immediately
before every write to tty1 (and in the exit handler): a frame prepared while
the owner was starting is dropped, never drawn. The unit is never restarted
within a boot and is stopped on shutdown (`Conflicts=`/`Before=shutdown.target`,
`TimeoutStopSec=5`).
