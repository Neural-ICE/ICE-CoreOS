# NI-P7-RULES end-to-end, QEMU + swtpm

`run-e2e.sh` boots an aarch64 KVM guest (AAVMF with Secure Boot enforcing, a swtpm
TPM 2.0) and runs the installer's own gate on it. Run on an aarch64 KVM host:

```sh
QEMU_PREFIX="sudo -n" bash image/e2e-pcr-rules-qemu/run-e2e.sh --work /var/tmp/ni-pcr-rules-e2e-1
```

(`QEMU_PREFIX` only if the account cannot open `/dev/kvm`.) Everything is created
under `--work`, apart from the swtpm state and sockets, which live under `/tmp`
because Ubuntu's AppArmor profile for swtpm refuses sockets under `/var/tmp`. Both
are removed on exit unless `--keep`.

## What it runs, and from where

* The guest boots a kernel signed by a test `db` key, so the firmware logs a real
  authority event. The Owner key, PK, KEK and `db` are generated per run.
* `/gate.sh`, `/gate-block.sh`, `/enroll.sh`, `/evidence.sh` are cut out of
  `ota/neural-ice-autoinstall.sh` by `awk`, not rewritten: `karg_once`,
  `esp_staged_file`, `verify_pcr_rules` and its call block, `enroll_luks`, and the
  block that records the decision on the installed ESP. The engine sits at the path
  `image/Containerfile.installer` gives it.
* The rules and the Owner key are read from a FAT "medium" through the installer's
  own `esp_staged_file`, against hashes given on the kernel command line.
* Scenarios: A conforming (gate accepts, the real `systemd-cryptenroll` enrols a
  scratch disk, a `PolicyAuthorize` token whose public key is the Owner key staged by
  the gate exists, the installed ESP record is written); B a second, unapproved certificate in `db`; C rules that
  approve no `db` certificate; D no PK (setup mode, Secure Boot off); E rules on the
  medium that are not the sealed ones. B-E must refuse with a closed-vocabulary class and leave the
  scratch disk **byte-identical**.

## What it does not prove

* Not the whole installer: no bootc deployment, seed or mirror.
* Not the signed command line: the sealed arguments travel on the QEMU `-append`.
* Not a GB10: this firmware measures the **contents** of the Secure Boot variables
  (`binding=contents`), a GB10 only their names (`names-only`). That path is exercised by
  the unit test `ota/test-installer-pcr-rules.sh` on the real `.67` event log and variables,
  **except `SetupMode`/`AuditMode`, which the `.67` capture lacks and the test supplies
  synthetically**. The engine refuses a machine without `SetupMode`: until a physical GB10
  capture shows the firmware exposes it, a rules-carrying install on a GB10 may be refused
  as `secure-boot-state`. That is unproven, not known to work.
* Not run by CI: it needs an aarch64 KVM host. `ota/test-installer-pcr-rules.sh` (CI) checks
  the gate's order against the destructive steps textually, not dynamically; this bench is
  the dynamic proof.
* Not the NV shard: enrolment here is the `PolicyAuthorize` shard only.
* The host's systemd is 255; the appliance ships 257.
