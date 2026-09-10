# Runbook — rehearsing a full medium installation on the bench (`image/bench-rehearse-medium.sh`)

> **Status**: the driver, its parsers and their suite are proven offline. The
> rehearsal itself has **not** been run yet: it needs an ARM64 host with
> `/dev/kvm`, which is the bench (`.63`), and the first run is a MEASUREMENT run
> (§6). Nothing below is a prediction of what the VM will do — it is the exact
> sequence, and the exact place each answer will appear. Line references
> below are at `bc6ea18`, this branch's base; `#164` has since been fixed on
> `main` by `fdcfd89`, which shifts the lines after `:3555`.

## 1 · What this replaces

Four hardware attempts on `.67` on 2026-09-09, roughly an hour each — build
25–35 min, flash, carry the stick, boot — and each one surfaced exactly **one**
defect before powering off:

| attempt | defect | installer phase | closed-vocabulary code |
| --- | --- | --- | --- |
| 1 | operator key on two transports (#162) | 1/8 | `install-failed-preflight-and-trust-gate` |
| 2 | PCR policy counter floor after the wipe (P1.5a) | 2/8 | `install-failed-partition-and-encrypt` |
| 3 | `fuse-overlayfs` absent from the bootc container (#163) | 1/8 | `install-failed-preflight-and-trust-gate` |
| 4 | `--log-driver=passthrough` probe on a TTY (#164, fixed on `main` by `fdcfd89`) | 1/8 | `install-failed-preflight-and-trust-gate` |

Three of the four refused **before** the wipe. A VM reaches those same three
refusals with no stick, no walk and no risk to a machine — and the fourth is
exactly the one worth reaching on something disposable.

The medium is **never modified**. There is no `if vm` in the installer and none
is wanted: everything that differs is an input (§6, §7, §8).

## 2 · Prerequisites on the bench

```sh
# ARM64 with hardware virtualisation, and KVM reachable WITHOUT root.
uname -m                      # aarch64
ls -l /dev/kvm                # crw-rw---- root kvm
id -nG | tr ' ' '\n' | grep -x kvm   # this user is in the kvm group

# The emulator, the disk tool, the software TPM, and awk/python3.
qemu-system-aarch64 --version | head -1
qemu-img --version | head -1
swtpm --version
command -v python3 awk timeout setsid

# ARM64 UEFI with Secure Boot. Ubuntu package: qemu-efi-aarch64.
ls -l /usr/share/AAVMF/AAVMF_CODE.secboot.fd /usr/share/AAVMF/AAVMF_VARS.fd

# The EFI variable-store editor. Ubuntu package: python3-virt-firmware.
#   dpkg -s python3-virt-firmware >/dev/null && command -v virt-fw-vars
# It is REQUIRED for --enrol-cert and for reading the installer's persisted
# failure evidence back out of the varstore (§6). Without it the rehearsal still
# runs, and the receipt says `efi_evidence=virt-fw-vars-absent`.
virt-fw-vars --help | head -1

# Room for a sparse 1 TiB qcow2 plus the medium.
df -h /var/tmp
```

🔴 **Do not run the rehearsal as root.** It refuses, on purpose: KVM access is a
group, not a privilege, and a root-owned target image plus a root-owned software
TPM state directory on a shared bench is a mess nobody asked for. `--allow-root`
exists so that, if a bench ever genuinely needs it, that is a recorded decision.

🔴 **The host TPM (`/dev/tpm0`) is never touched.** The driver never names it;
`image/test-bench-rehearse-medium.sh` fails if it ever does. Each rehearsal gets
its own `swtpm` with its own state directory inside the work directory.

## 3 · The Secure Boot variable store

PCR 7 is *"the digest of the UEFI Secure Boot state (PK, KEK, `db`, `dbx`, and
the certificates that validated what was loaded)"* (`docs/TPM-SIGNED-POLICY-RUNBOOK.md`).
So the varstore is not a detail — it **is** the input that decides PCR 7.

`virt-fw-vars` option semantics, from its own `--help` (virt-firmware, read
2026-09-09):

* `--set-pk GUID FILE` — set PK to an x509 cert *"loaded in pem or der format
  from FILE and with owner GUID"*; `--add-kek GUID FILE` and `--add-db GUID FILE`
  append to KEK and `db` the same way.
* `--secure-boot` — *"enable secure boot mode"*. It also creates `dbx` with a
  dummy entry and sets `CustomMode` off; both are part of what PCR 7 measures.
* `--enroll-cert CERT` is **not** a file path. It names a certificate bundled
  with virt-firmware as `domain/name` and fails on a path
  (`virt/firmware/efi/certs.py`, `load_cert` splits on `/`). Do not use it here.

The driver builds the store for you:

```sh
image/bench-rehearse-medium.sh ... \
  --firmware-vars /usr/share/AAVMF/AAVMF_VARS.fd \
  --enrol-cert "$UKI_SIGNING_CERT"
```

which runs, verbatim:

```sh
virt-fw-vars -i /usr/share/AAVMF/AAVMF_VARS.fd \
  --set-pk  1e5f0057-0000-4000-b000-6e6575726963 "$UKI_SIGNING_CERT" \
  --add-kek 1e5f0057-0000-4000-b000-6e6575726963 "$UKI_SIGNING_CERT" \
  --add-db  1e5f0057-0000-4000-b000-6e6575726963 "$UKI_SIGNING_CERT" \
  --secure-boot -o <work-dir>/AAVMF_VARS.fd
```

🔴 **The owner GUID is a constant, not a fresh UUID.** The SignatureOwner goes
into the measured `EFI_SIGNATURE_LIST` bytes of PK, KEK and `db`, so a different
owner is a different PCR 7. Measured 2026-09-09: building the store twice with
the same owner gives byte-identical files (same SHA-256); building it with
another owner gives a different one. Change `--enrol-owner-guid` only if you
intend to invalidate every signed policy that covers this VM.

If you already have an enrolled store, pass it as `--firmware-vars` and omit
`--enrol-cert`. Either way the driver re-reads the store and refuses unless
`SecureBootEnable : bool: ON`.

## 4 · The command

```sh
cd /path/to/ICE-CoreOS
WORK=/var/tmp/ni-bench-$(date -u +%Y%m%dT%H%M%SZ)

image/bench-rehearse-medium.sh \
  --raw     /var/tmp/media/neural-ice-installer-<version>.raw \
  --work-dir "$WORK" \
  --firmware-vars /usr/share/AAVMF/AAVMF_VARS.fd \
  --enrol-cert    "$UKI_SIGNING_CERT" \
  --mirror-ip     192.168.178.63 \
  --mirror-port   5055 \
  --install-timeout 5400 \
  --firstboot-timeout 1800 \
  --ssh-wait 900
```

What it does, in order, all inside `$WORK` and nowhere else:

1. refuses root, checks `aarch64`, `/dev/kvm`, the tools, and that **the bench
   host itself** can open `192.168.178.63:5055` — before a 1 TiB image exists;
2. builds the Secure Boot varstore (§3) and a sparse `target.qcow2`;
3. starts a dedicated `swtpm` (`--tpmstate dir=$WORK/tpmstate`, control socket
   only — QEMU supplies the data channel);
4. boots QEMU/KVM `virt` with AAVMF Secure Boot, the medium **read-only**, the
   target disk, user-mode NAT, and the serial console captured to
   `$WORK/install.console.log`, bounded by `--install-timeout` and by
   `--serial-max-bytes`;
5. watches the console for the installer's own two terminal markers, presses
   Enter over QMP on completion (the completed screen waits for it), and gives
   the failure surface `--failure-grace` seconds to power the machine off;
6. parses the serial log, reads the persisted EFI failure evidence back out of
   the varstore, and — only after a completed install — reboots the VM on the
   target disk and waits for TCP/22 to open through a loopback forward;
7. writes `$WORK/bench-rehearsal-receipt.json` and **exits non-zero** if the
   medium did not install or the appliance never served SSH.

Every exit path — refusal, timeout, Ctrl-C — goes through one cleanup that kills
the QEMU process **group** and then `swtpm`.

## 5 · Reading the receipt

`bench-rehearsal-receipt.json` (schema `neural-ice-bench-rehearsal-receipt-v1`):

| key | meaning |
| --- | --- |
| `install.outcome` | `complete`, `failed` or `incomplete` |
| `install.failure_code` | the installer's closed-vocabulary code, e.g. `install-failed-partition-and-encrypt` |
| `install.failure_phase` / `failure_phase_total` | which of the eight phases refused — **1 is before the wipe, 2 is after it** |
| `install.failure_source` | `serial-refusal-line` (the UART) or `tty1-failure-block` (a mirrored console) |
| `install.pcr7_live` / `pcr7_policy` / `pcr7_available` | printed by the installer once the coverage gate has PASSED (`ota/neural-ice-autoinstall.sh:1718-1720`) |
| `efi_failure_evidence.*` | the same evidence read back out of the varstore — **the only place the live PCR 7 appears when the coverage gate is what refused** |
| `firstboot.ssh` | `open` = the operator key answered on TCP/22 |
| `vm.medium_mode` | `read-only` (default: the raw medium is never written, so phase 8 cannot escrow the SYSTEM recovery key and skips it) or `overlay` (`--medium-overlay`: a qcow2 copy-on-write overlay in the work directory receives the escrow; the raw stays unwritten). With `overlay`, the SYSTEM recovery key of the rehearsed install is readable afterwards from `medium.qcow2`'s ESP, e.g. `qemu-nbd` + `NEURAL-ICE-RECOVERY-<serial>.txt`, which is what `image/bench-read-rehearsed-firstboot-journal.sh --work-dir DIR` does (root on the bench host, everything read-only) to print the ceremony unit's journal off the target disk after a failed first boot |
| `firstboot.firstboot_ready`, `firstboot_device_trust`, `firstboot_core_services`, `firstboot_status_failure` | the status screen's serial mirror (`image/firstboot/neural-ice-status-screen.sh:343`) |
| `install.serial_truncated` | the console hit `--serial-max-bytes` and the VM was stopped |

🔴 **What is NOT on the serial log, and why.** `ota/neural-ice-autoinstall.service:50-52`
and `image/installer/neural-ice-installer-failure.service` are both
`StandardOutput=tty`, `TTYPath=/dev/tty1`. The only thing that reaches the UART
is `log()` (`ota/neural-ice-autoinstall.sh:76`), which writes to `/dev/console`
explicitly. So the phase banners, the completion line, the PCR 7 values and the
`FAILED in phase N/8 … [code]: message` line are on the serial log; the boxed
`failure code` / `stage` block is not. The EFI variable is what closes that gap.

## 6 · PCR 7 — what this VM produces, and how to cover it

**What it is.** PCR 7 in this VM is a deterministic function of the varstore of
§3 (SecureBoot on, PK/KEK/`db` = the lab certificate under a fixed owner GUID,
the `dbx` `--secure-boot` created) and of the certificate that authenticated the
UKI that was loaded. It is **stable across rehearsals** as long as the
certificate file, the owner GUID and the AAVMF build do not change, and it is
**necessarily different from the GB10's**, whose PK/KEK/`dbx` are the platform
vendor's rather than these three lines.

**It must be measured, not predicted.** `ota/neural-ice-tpm-policy.py predict`
replays the firmware's own TCG event log and refuses unless the replay
reproduces the live PCR first — and that log lives in guest memory, reachable
only from inside a booted guest. The medium has no shell (every login surface is
masked on an Install boot). So the value comes from the run itself:

* **first run, coverage refuses** — expected, and it is a phase 1 refusal, so
  *nothing has been written to any disk*: `verify_live_pcr7_coverage`
  (`ota/neural-ice-autoinstall.sh:1697-1716`) is called long before `phase 2`
  (`:3577`). Read the value from the receipt:

  ```sh
  python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["efi_failure_evidence"])' \
    "$WORK/bench-rehearsal-receipt.json"
  # efi_code=install-failed-preflight-and-trust-gate  efi_phase=1  efi_pcr7=<64 hex>
  ```

* **later runs, coverage passes** — the value is on the serial line as
  `Live SHA-256 PCR7 = <64 hex>` and in `install.pcr7_live`.

**How the lead covers it** (the private key never moves —
`docs/TPM-SIGNED-POLICY-RUNBOOK.md` §3, and the ordering rule of §4):

```sh
VM_PCR7=<the 64 hex from the receipt>
POL=$(ota/neural-ice-tpm-policy.py --pcr 7 --alg sha256 policy-digest --value "$VM_PCR7")
ota/neural-ice-tpm-policy.py --pcr 7 --alg sha256 sign-request --pol "$POL" --out vm.bin
# Owner-only step, on the signing host:
openssl dgst -sha256 -sign <owner.key> -out vm.sig vm.bin
ota/neural-ice-tpm-policy.py --pcr 7 --alg sha256 emit \
  --pubkey <owner.pub> --pol "$POL" --sig vm.sig \
  --merge policy-vm+67.json --out policy-vm+67.json
```

🔴 **One medium can serve both the VM and `.67`.** `ota/test-installer-pcr7-coverage.sh:74-78`
proves the supported bridge: *"the live machine may be a different authorised
entry from the one naming the signed generation"*. The medium seals ONE
generation digest (`neuralice.pcr_policy`) plus the key digest and the JSON
digest; the JSON may carry several entries under `pcrs=[7]`, and the live
machine only has to be one of them.

🔴 **But merging an entry means cutting a new medium.** `neuralice.pcr_policy_signature`
seals the SHA-256 of `tpm2-pcr-signature.json`, and the installer re-checks the
staged ESP file against it (`ota/neural-ice-autoinstall.sh:1695`). A merged JSON
is a different file, so the UKI command line changes and the medium is re-cut.
Plan the first bench run as the measurement run, and the second as the real one.

## 7 · Hardware identity

`image/lib/hardware-identity.sh` measures, in this order:

1. `/sys/firmware/devicetree/base/compatible`, rendered `devicetree:<a,b,…>`;
2. otherwise `/sys/class/dmi/id` as `dmi:<sys_vendor>|<product_name>|<board_name>`;
3. otherwise it **refuses** — *"I do not know what this is"* is not a licence to
   repartition a disk.

The SHA-256 of that line must appear in
`/usr/lib/neural-ice/hardware-identity/<target>.fingerprints`, staged into the
image from the reference appliance. The rehearsal presents the GB10's SMBIOS
identity (`-smbios type=1,manufacturer=NVIDIA,product=NVIDIA_DGX_Spark` and
`type=2,manufacturer=NVIDIA,product=P4242`, the same values
`image/qualify-installer-qemu.sh` uses), so the DMI branch measures
`dmi:NVIDIA|NVIDIA_DGX_Spark|P4242`.

**Which branch a QEMU `virt` guest actually takes has not been measured.** If the
guest exposes a device-tree `compatible`, that branch wins and the measurement is
the VM's, not the GB10's. Measure it once, without the medium and without a
shell on it, by booting any ARM64 Linux image in the same machine with the same
SMBIOS flags and running:

```sh
image/lib/hardware-identity.sh measure       # the canonical line
image/lib/hardware-identity.sh fingerprint   # its SHA-256
```

The smallest legitimate input is then **one line added to the LAB medium's
`<target>.fingerprints`** — a build input of the LAB medium, exactly like the
signed PCR policy. It is not an `if vm`, and it must never be added to a customer
medium. If the identity does not match, the installer refuses in phase 1 with
`this medium carries no verified sealed trust anchor …`; the precise
`this machine measures as '<line>' (<sha256>)` diagnostic goes to tty1, not to
the serial log (`image/lib/hardware-identity.sh:206`, `image/lib/installer-trust.sh:866`).

## 8 · Networking — the mirror, and what mDNS costs

`--network lan` uses QEMU user-mode networking with **no `restrict`**. QEMU
documents `restrict=on` as *"the guest will be isolated, i.e. it will not be able
to contact the host and no guest IP packets will be routed over the host to the
outside"* (`qemu-system.1`, `-netdev user`) — which is precisely the bench mirror
becoming unreachable, and it is why this driver does not reuse
`image/qualify-installer-qemu.sh --network restricted-user`.

* **A mirror sealed by IP works as-is.** The guest's traffic to
  `192.168.178.63:5055` is NAT-ed out through the bench's own stack.
* **A mirror sealed as `registry.neural-ice.local` does not.** mDNS is multicast
  on `224.0.0.251:5353`, and the user-mode stack routes no multicast: its
  built-in resolver (`x.x.x.3`) forwards ordinary DNS only. The installer's
  resolve-only mDNS path (#161) has nothing to answer it.

  To rehearse the mDNS path the guest needs a real L2 presence on the bench LAN —
  a bridge over the management NIC (`-netdev bridge,br=<br>` plus
  `/etc/qemu/bridge.conf`, which needs `qemu-bridge-helper` and is setuid) or
  macvtap (`-netdev tap,fd=…` on a `macvtap` link). Both are host network changes
  and neither is done by this driver.

`--network isolated` gives `-nic none`, for rehearsing a medium that must install
with no network at all.

## 9 · What this rehearsal does NOT cover

* **The NVIDIA GPU stack.** QEMU `virt` has no GB10 GPU; anything the appliance
  does with the driver is out of scope here and stays a `.67` question.
* **USB as the medium transport.** `--source-transport usb` exists, but the
  medium's kernel ships the Tegra xHCI driver and QEMU `virt` cannot emulate it —
  the same limitation `image/qualify-installer-qemu.sh` records. Use `virtio`.
* **A login on the installed appliance.** The rehearsal proves TCP/22 opens; it
  does not authenticate. Unit-level state comes from the status screen's serial
  mirror, which is the surface designed for headless reading.
* **Real disk timing.** A sparse qcow2 on `/var/tmp` is not an NVMe.

## 10 · Afterwards

The work directory holds a sparse 1 TiB qcow2 and a software-TPM state
directory. Keep it while the run is being read; then:

```sh
rm -rf -- "$WORK"
```

Nothing outside it was created: the receipt, both serial logs, QEMU's stderr, the
varstore and the target disk are all inside, and the driver refuses to start if
the directory already exists — a rehearsal never reuses one.

## Related

* `image/bench-rehearse-medium.sh`, `image/test-bench-rehearse-medium.sh`
* `image/qualify-installer-qemu.sh` — the CI-shaped synthetic matrix
* `docs/TPM-SIGNED-POLICY-RUNBOOK.md` — the signed PCR policy
* `image/firstboot/status-error-codes.md` — the NI-Exx vocabulary and the mirror
* `docs/RUNBOOK-GB10-CONSOLE-BOOT.md` — the hardware counterpart
