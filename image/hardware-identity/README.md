# Measured hardware identity — staged, never guessed

`image/lib/hardware-identity.sh` binds the sealed `neuralice.hardware_target=` to
what the **machine itself reports**: its device-tree `compatible` property, or,
on machines that have SMBIOS instead, the `sys_vendor|product_name|board_name`
triple. Before this existed, the hardware target was a build-time word compared
only with another copy of itself, so a medium built for a GB10 booted on any
other arm64 box satisfied every check the installer made and then wiped it.

The accepted identities travel as **SHA-256 digests of the canonical
measurement**, one per line, in `<hardware-target>.fingerprints`.

## Why digests and not a vendor string in this repository

This tree is open core and holds no ground truth about what a GB10 reports. A
vendor string invented here would be a check that passes on the wrong hardware
or fails on the right one — worse than no check, because it would look like one.
So the list is produced by MEASURING the reference appliance:

```sh
# on the reference appliance, as any user:
bash image/lib/hardware-identity.sh measure       # shows what will be hashed
bash image/lib/hardware-identity.sh fingerprint   # the line to add to the list
```

Append the printed digest to `image/hardware-identity/<hardware-target>.fingerprints`,
with a comment naming the machine and the date it was measured. One line per
accepted hardware revision; a revision that changes its `compatible` string is a
different machine until somebody measures it and says otherwise.

## Fail-closed

* No list for the sealed target → `image/build-installer-uki.sh` refuses to build
  and `image/build-installer-usb.sh` refuses to produce a medium.
* An empty list → the same refusal. Absence is never a pass.
* A machine that exposes neither device-tree nor SMBIOS → the install-time gate
  refuses. "I cannot tell what this is" is not a licence to repartition it.

## What is committed, and what is staged

`*.fingerprints` is **git-ignored by default**, because a fingerprint committed
without a measurement behind it is exactly the invented vendor string this design
avoids. The list for a target this tree actually ships is un-ignored **by exact
name** in `.gitignore` once its machines have been measured:

* `nvidia-gb10-arm64.fingerprints` — committed. Its two entries were measured on
  the reference build appliance (NVIDIA DGX Spark) and on the qualification
  appliance (ASUS GX10) on 2026-09-02, and each carries the machine and the date
  above it. `image/test-hardware-identity.sh` reproduces both measurements from
  their canonical SMBIOS triples and fails if the committed digests drift.
* Every other target — staged, like `image/signed-boot/` and `image/rpms/`.

A staged-only list made every media build depend on somebody remembering to copy
a file that `build-installer-uki.sh` and `build-installer-usb.sh` refuse to
proceed without; committing the measured list for the shipped target removes that
step without weakening anything. Adding a machine is still a measurement, a
comment naming it, and a reviewed commit.
