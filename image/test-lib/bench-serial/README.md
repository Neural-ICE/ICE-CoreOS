# Serial-console fixtures for the bench rehearsal parsers

These are the inputs `image/test-bench-rehearse-medium.sh` runs
`ni_bench_parse_install_log` and `ni_bench_parse_firstboot_log` over. They are
**reconstructions**, not captures: the four failures they model happened on `.67`
on 2026-09-09 on a console nobody was recording, so each line here is built from
the producer that emits it, cited below. A fixture that guessed a format would
prove nothing, so every line has a source.

🔴 **Every line number below is at `bc6ea18`, this branch's base.** `#164` has
since been fixed on `main` (`fdcfd89`, *"make the pre-wipe bootc container probe
independent of the console"*), which rewrites `assert_bootc_container_reads_source`
and shifts everything after it by about twelve lines. The fixture keeps modelling
the failure as it was OBSERVED on 2026-09-09 — that is what a fixture is for —
and the `FAILED in phase N/8 (…) [code]: message` shape the parser reads is
unchanged by that fix.

The only thing that reaches the serial console is
`ota/neural-ice-autoinstall.sh:76` `log()`, which writes
`[neural-ice-autoinstall] <text>` to `/dev/console` explicitly — the installer's
stdout goes to tty1 (`ota/neural-ice-autoinstall.service:50-52`).

| fixture | models | producer |
| --- | --- | --- |
| `install-162-operator-key-two-transports.log` | 2026-09-09 attempt 1, #162: the operator key on both the sealed command line and the ESP | `ota/neural-ice-autoinstall.sh:1152` via `die` (`:169`), phase 1 opens at `:740` |
| `install-p15a-pcr-policy-floor.log` | 2026-09-09 attempt 2, P1.5a: the signed PCR policy sequence at or below the TPM high-water, **after** the wipe | `ota/neural-ice-autoinstall.sh:3666`, phase 2 opens at `:3577`; the underlying reason (`ota/neural-ice-tpm-state.sh:626`) prints on tty1, not here |
| `install-163-fuse-overlayfs-missing.log` | 2026-09-09 attempt 3, #163: `fuse-overlayfs` absent from the bootc container | `ota/neural-ice-autoinstall.sh:3567`, reached from `assert_bootc_container_reads_source` (`:3559-3571`), which runs **before** the wipe and is therefore still phase 1 |
| `install-164-log-driver-passthrough-tty.log` | 2026-09-09 attempt 4, #164 (fixed on `main` by `fdcfd89`): the same pre-wipe probe refused by podman because `--log-driver=passthrough` (`:3560`) cannot be used while stdout is a terminal. **LF-only**, on purpose: not every console capture is CRLF | same as above |
| `install-success.log` | the outcome this rehearsal exists to reach | phase banners `:215`, phase durations `:210`, PCR 7 values `:1718-1720`, completion `:4445` |
| `install-tty1-failure-block.log` | the boxed failure block, as a mirrored console would show it — the only surface carrying the live PCR 7 when the coverage gate refuses | `image/installer/neural-ice-installer-failure.sh`, `printf '  %-18s %s\n'`, schema `neural-ice-installer-failure-evidence-v1` |
| `firstboot-ready.log` | an installed appliance that sealed its device trust and reached READY | `image/firstboot/neural-ice-status-screen.sh:341-352`, marks from `mark()` `:300-308` |
| `firstboot-ceremony-failure.log` | a first boot whose TPM owner ceremony never completed | same, plus the NI-E02 row of `image/firstboot/status-error-codes.md` |

The SHA-256-shaped values are fabricated digests, not measurements: the parsers
check shape, and a real PCR 7 in a fixture would be a value somebody would later
mistake for the bench's.
