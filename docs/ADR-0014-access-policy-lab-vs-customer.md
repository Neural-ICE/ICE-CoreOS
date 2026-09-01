# ADR-0014 — Immutable access policy: lab-managed vs customer-locked

- **Status**: Accepted (pre-production breaking correction)
- **Date**: 2026-08-31
- **Decider**: Business/Security Owner (human)
- **Related**: [ADR-0003](ADR-0003-base-and-update-model.md) (sealed appliance, no SSH in prod),
  [ADR-0005](ADR-0005-release-channels.md) (signed trains, variant gate),
  [ADR-0002](ADR-0002-secure-boot-zero-touch.md) (Secure Boot anchors)

## Context — the hole

The appliance had exactly one mechanism for granting remote access, and it was
anchored to nothing that reached the machine:

1. `image/build-installer-usb.sh` validated an operator public key against an
   approved SHA-256 and refused to stage it unless the base image carried the
   label `ch.neural-ice.signed-boot-trust-policy-id=neural-ice-secureboot-lab-v1`.
   That check runs **on a build host**, and a label is metadata anyone building
   an image can set.
2. `ota/neural-ice-autoinstall.sh` then read the key back from
   `ice-coreos/authorized_keys` on the installer **ESP** — a mutable vfat
   partition — or from a kernel argument, and turned it into
   `neuralice.sshkey=<base64>` on the installed system. It re-checked nothing.
3. `image/firstboot/neural-ice-firstboot-sshkey.sh` honoured that kernel
   argument on **every non-`debug` image**, wrote `~core/.ssh/authorized_keys`,
   unmasked sshd and started it.

So the whole chain's only guard was a build-time label. Writing one file onto an
otherwise correctly signed installer USB — or typing one word at the GRUB prompt
— provisioned working SSH on a `prod` appliance. Reproduced before the fix:

```
--- firstboot exit code: 0
--- authorized_keys WRITTEN on a customer-locked image:
      ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA… attacker
--- sshd unit state: active
RESULT: VULNERABLE — a forged karg opened SSH on a customer-locked image
```

Meanwhile the requirement had split in two, and one mechanism could not express
both halves. Neural ICE must be able to debug its own lab appliances over SSH.
A customer appliance must have no SSH at all: after installation, software
changes arrive as signed OTA, and recovery is physical signed media — never a
hidden shell.

## Decision

**The trust anchor moves inside the signed image.** The image build derives an
access policy from `${VARIANT}` and writes it to
`/usr/lib/neural-ice/access-policy`, in the read-only ostree `/usr` that the
image signature covers. Every gate asks that file — never a label, never `/etc`,
never a kernel argument, never a file on the ESP.

| `VARIANT` | access policy | installer may provision SSH |
|---|---|---|
| `prod` | `customer-locked` | **never**, under any input |
| `sealed-lab` | `lab-managed` | yes — exactly one validated key |
| `debug` | `developer-diagnostic` | yes (it already ships sshd enabled) |

`debug` remains an explicitly **non-release** direct-digest developer
diagnostic. It must never enter a channel; ICE-Fabric maps it to no product ring.

The mapping is a **total function** and lives in exactly one place,
`image/lib/access-policy.sh`, which the image build, the autoinstaller and the
first-boot service all use. An unknown variant yields no policy at all, so a new
build flavour cannot inherit permissiveness by omission.

### Two independent gates, neither trusting the other

- **Install time** (`ota/neural-ice-autoinstall.sh`). Reads the policy from the
  source image and refuses **before the target disk is selected or touched**. On
  the default `medium` path the live installer root *is* the image being
  installed (`bootc install to-filesystem --source-imgref
  containers-storage:localhost/bootc`), so the policy read is the policy of the
  deployment being written. A key offered to a `customer-locked` image aborts the
  install; it is never silently dropped, because silently dropping it hands the
  operator an appliance they believe is reachable and hands an attacker a free
  retry. The `registry` install source refuses a medium-supplied key outright:
  the deployment comes from an image pulled later, so there is nothing honest to
  gate against at preflight.
- **First boot** (`image/firstboot/neural-ice-firstboot-sshkey.sh`). Re-states
  the whole decision against the *installed* image's own `/usr`. On
  `customer-locked` a kernel argument is refused with no `authorized_keys` write
  and no `systemctl` call at all. An unreadable or unrecognised policy fails
  closed on both gates.

### First boot is two units, because one unit cannot be ordered both ways

The key must be on disk **before** anything could serve it, and the appliance
must not report success until something **actually** serves it. A single oneshot
cannot satisfy both: ordered `Before=sshd.service`, systemd holds the sshd start
job until it exits, so the unit queued sshd, waited for a job the manager was
holding open on its own exit, timed out, and recorded failure on a healthy lab
boot while sshd came up a moment later.

| unit | ordering | does | must never |
|---|---|---|---|
| `neural-ice-firstboot-sshkey.service` | `Before=sshd.service` | decides, validates, writes `authorized_keys`, unmasks + enables sshd, stages a handoff | start or poll sshd; write the success marker |
| `neural-ice-firstboot-sshkey-activate.service` | `After=` the above **and** `After=sshd.service`, `ConditionPathExists=` the handoff | starts sshd, **verifies** it is active, writes the success marker | write the marker before that proof |

Activation is where the honesty lives. If sshd never comes up it **rolls the
provisioning back** — removes exactly the record it appended to
`authorized_keys` (an Ignition-placed community key that was there first is left
alone) and restores exactly the sshd enablement state provisioning changed — and
leaves the marker unwritten so the next boot retries from the karg. An unmasked
sshd guarding an unusable key is strictly more attack surface than the sealed
posture it replaced, for zero access; the appliance is returned to the sealed
posture instead of left half-open. The receipt records
`provisioned-pending-activation`, then either `provisioned` or
`activation-failed-rolled-back` — the appliance's actual posture at each instant,
never the one it was expected to reach.

### What is still hash-pinned, and what is not

The public key input remains explicitly supplied and pinned to an exact SHA-256
at **build** time (`SSH_AUTHORIZED_KEYS_FILE` + `SSH_AUTHORIZED_KEYS_SHA256`).
The two runtime gates have no approved digest to compare against — that is
precisely why they need the image policy as their anchor. What they do enforce is
structure, identically to the build path: a regular non-symlink file of 1..512
bytes holding **exactly one** plain OpenSSH public-key record, no options, no
private key, no second record.

### Provisioning receipt

`/var/lib/neural-ice/access-provisioning-receipt.json`, root-owned `0600`,
bounded, schema `neural-ice-access-provisioning-receipt-v1`. It records the
policy, the decision, whether SSH was provisioned, and the accepted key's SHA-256
and OpenSSH fingerprint — **never the key itself**.

Two fields are deliberately `null` rather than guessed:

- `recorded_at`: first boot has no trusted time source. The RTC is whatever the
  firmware said, NTP has not run, and the OTA verifier's trusted-time challenge
  is not available synchronously here. A field that would only ever hold an
  attacker-influenced number is worse than an absent one.
- `source_installer_identity`: nothing the installer hands the installed system
  today identifies the medium in a way that survives an attacker who controls
  that medium. `image_ota_imgref` **is** recorded, because it comes from the same
  signed `/usr` as the policy.

### Sealed posture, asserted rather than assumed

The non-`debug` branch of `image/Containerfile.bootc` now reads its own work
back and fails the **build** if any of it did not take: sshd masked, `getty@` and
`autovt@` masked, no serial root autologin drop-in, no `enforcing=0` and no
`console=ttyS0` karg, and `/usr/ssh/core.keys` free of any baked key. A sealed
image ships **keyless**; the privilege travels on the physical installation
medium *and* must be authorised by the image's own policy.

"Keyless" is **two independent requirements**, because either alone is
bypassable:

1. `SSH_AUTHORIZED_KEY` must be **exactly empty**. It is the only input that can
   put anything in that file, and checking it directly needs no opinion about
   what a key looks like.
2. `/usr/ssh/core.keys` must contain **no non-whitespace byte**
   (`installer_ssh_key_assert_keyless`). `printf '%s\n' ""` leaves exactly one
   newline, so whitespace — and only whitespace — passes.

The check these replace rejected only lines *beginning* with a key algorithm.
`restrict ssh-ed25519 AAAA… lab@host` is a perfectly valid `authorized_keys`
record that sshd honours exactly like a bare one, and it walked through a build
that claimed to ship keyless. Asserting the **absence of content** rather than
the absence of a recognised key shape also covers every future options prefix,
every algorithm this repository has not heard of, and comment-line smuggling.
The predicate lives in `image/lib/installer-ssh-key.sh` so the suite exercises
the same code the build runs, including the options-prefixed regression.

This is a breaking correction: a non-`debug` build that passes
`--build-arg SSH_AUTHORIZED_KEY=…` now fails. No production or customer device
exists yet, and the Owner authorised the break.

## OTA continuity — no new ICE-Fabric field

`sealed-lab` and `prod` carry different access policies, so an OTA that moved a
host between them would change the answer without anyone deciding to. Nothing new
is needed to prevent it:

- `/usr/lib/neural-ice/appliance-variant` is immutable and image-signed;
- every delegated path already requires the signed release's `variant` to
  **equal** the host's (`tools/ni-ota-verify/src/delegated/beta.rs`);
- the variant → policy mapping is a total function, so **equal variants imply an
  equal access policy**.

The existing `appliance-variant` binding therefore *is* the access-policy
binding. `tools/ni-ota-verify/tests/cli.rs` now proves it in both directions
(`sealed-lab` host + `prod` release, and the reverse) instead of assuming it.
**ICE-Fabric requires no schema change for this ADR.**

⚠️ **That third premise did not hold, and this section's conclusion was wrong.**
*The variant → policy mapping is a total function, so equal variants imply an
equal access policy* is true of **today's tree** and is enforced by nothing
signed. A later same-variant OTA that edits `image/lib/access-policy.sh` changes
the answer with no signature stating the old one. The binding was *variant*; the
thing that must be immutable is *profile*.

[ADR-0015](ADR-0015-installer-trust-anchor-uki-verity.md) closes it, and it did
take the ICE-Fabric schema change this ADR said was unnecessary: `access_profile`
is now a **required** field on the release authorization, compared against a value
enrolled at install time into the stateroot and signed by the TPM device root. A
mismatch is refused with **"reinstall required"**.

The sentence above — *"ICE-Fabric requires no schema change for this ADR"* — was
accurate about the scope of *this* ADR and misleading about the property. It is
left in place rather than edited away, because the reasoning that produced it is
the thing worth not repeating: three sound premises and one that was a property
of the source tree wearing the costume of a control.

## Consequences

- One sealed posture ships to customers and to the lab. The difference is a file
  inside the signed image plus a key on a physical medium — not a second build
  flavour to keep honest.
- A modified ESP or a forged kernel argument is now a *refusal* on a customer
  appliance, loud at both gates, with nothing written.
- Lab debugging is unchanged in practice: `sealed-lab` media staged with an
  approved key keep working, on a SELinux-enforcing, shell-less, autologin-free
  image.
- The first-boot gate is a script plus **two** units. Anything that enables only
  `neural-ice-firstboot-sshkey.service` writes a key nothing ever starts a daemon
  for; anything that enables only the activation unit never writes one at all.
  `image/test-access-policy.sh` asserts the image build enables both.
- `image/lib/debug-ssh-key.sh` is renamed to `image/lib/installer-ssh-key.sh`
  and its functions with it. The old name described a `debug` facility that had
  not been one since the first-boot service learned to serve a key on a sealed
  image. No compatibility shim: nothing is in production.
