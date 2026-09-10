# Bench rehearsals before any hardware attempt

Rule (Owner, 2026-09-09, after fourteen one-hour hardware attempts): **no
medium is flashed for a real appliance until the rehearsals below have passed
on the installation bench**. Each one runs on the bench host alone, in minutes,
and each one found or confirmed a defect that day.

| Rehearsal | Exercises | Time | Command |
|---|---|---|---|
| Whole medium under KVM | firmware, signed UKI, initramfs (verity, TPM gate), systemd, installer preflight | ~2 min to the preflight | `image/bench-rehearse-medium.sh --raw <medium.img> --work-dir /tmp/<run> --firmware-vars /usr/share/AAVMF/AAVMF_VARS.fd --enrol-cert <lab.crt> --mirror-ip <bench> --skip-firstboot` (root needs `--allow-root`; work dir under `/tmp`: Ubuntu's AppArmor profile for swtpm refuses `/var/tmp`). Beyond the preflight the VM's PCR7 must be covered by the signed policy: `docs/RUNBOOK-BENCH-MEDIUM-REHEARSAL.md`. |
| Whole medium under KVM, install and first boot | everything above, then phases 2–8 against the LAN mirror, then the first boot of the installed target (TPM ceremony, status screen) with its journal readable afterwards | ~35 min | On the bench host, as the unprivileged user: `image/bench-rehearse-medium.sh --raw <medium.img> --work-dir /tmp/<run> --firmware-vars /root/ni-bench-0601-20260909/AAVMF_VARS.lab-db-20260904.fd --mirror-ip <bench> --medium-overlay --skip-firstboot` — **that varstore, not a fresh `--enrol-cert` enrolment**: it is the AAVMF Secure Boot state whose PCR7 (`bb661dcb…`, PolicyPCR `ea9b7ee9…`) the sealed policy of 2026-09-04 covers; a fresh enrolment yields another PCR7 and the coverage gate refuses before any write (measured 2026-09-09 and 2026-09-10). A medium that seals `console=tty0` (`MEDIA_VERBOSE_CONSOLE=1`) before PR #175 writes no installer line on the serial, so the driver cannot see completion: judge the install by the target's growth and the mirror's blob requests, then `image/bench-rehearse-medium.sh --raw <medium.img> --work-dir /tmp/<run> --resume-firstboot`. Afterwards, as root: `image/bench-read-rehearsed-firstboot-journal.sh --work-dir /tmp/<run>` prints the ceremony unit's journal off the target disk through the overlay's escrow. |
| Phase 4 alone | `bootc install to-filesystem` from the appliance container, exactly as the installer runs it, onto a loop device laid out like the appliance disk | ~45 s | `image/bench-rehearse-phase4.sh --image <appliance ref@digest> --pcr-policy-signature <json> --pcr-policy-key <pem>` (root; the appliance image must be in the host's container storage) |
| Phase 5 alone | the seed pack and the whole release closure fetched from the real LAN mirror by the installer's own helper, then `verify-seed-closure` from the appliance image | ~7 min for 130 GiB | extract `seed_mirror_helper` from `ota/neural-ice-autoinstall.sh` (as `image/test-seed-from-mirror.sh` does), run `documents`, `plan`, `objects` against `<mirror>:5055` with the bench CA into `<work>/release/<closure>`, then `podman run --rm --entrypoint '' -v <work>/release:/run/seed-dst/release:ro <appliance> ni-ota-verify verify-seed-closure --seed-root /run/seed-dst/release/<closure> ...` with the medium's exact values (the seed root directory **must be named by the closure hash**) |

Not rehearsable on the bench yet: phase 2 (LUKS + real TPM enrolment, the PCR
policy counter) and phase 6 (device-root TPM provisioning), and the first boot
ceremony. Those still cost one hardware attempt each — with the console readable
(`MEDIA_VERBOSE_CONSOLE=1`) and the failure screen carrying the installer journal
on a LAB medium, one attempt now yields its cause.

What the rehearsals found on 2026-09-09: the KVM boot proved a medium sound
while the appliance's screen stayed black (the GB10 console handover, #170);
the phase-4 rehearsal reproduced in 30 s the `rejected by policy` refusal of
hardware attempt 14 and proved its fix in 44 s (#172); the phase-5 rehearsal
proved the mirror path before any hardware touched it.
