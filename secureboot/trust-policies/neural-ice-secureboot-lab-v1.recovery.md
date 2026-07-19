# neural-ice-secureboot-lab-v1 — recovery & rollback (LAB / debug)

Operational recovery for the **LAB** signed-boot trust policy. Companion to
[../disaster-recovery.md](../disaster-recovery.md) and
[../signing-pipeline.md](../signing-pipeline.md); this file is specific to the
`neural-ice-secureboot-lab-v1` chain and to bringing a candidate up on the `.72`
test appliance.

## Scope (hard boundary)

- **`.72` LAB / debug only.** This policy approves the LAB chain (grub/vmlinuz by
  the Neural ICE leaf → CA; shim/MokManager/fallback by *Neural ICE Lab Secure
  Boot*). It **never** approves a Microsoft/PROD chain and is never used on a
  client appliance. PROD activation stays fail-closed until a separate,
  Owner-approved `neural-ice-secureboot-prod-v1` exists.
- No unsigned fallback, no implicit PROD policy, no channel/alias movement at any
  step below.

## Preflight (mandatory before activation)

1. `neural-ice-secureboot-lab-v1 <signed-boot> <uname_r>` returns 0 (closed-world,
   signers, no writable root/files).
2. The policy's pinned anchors match the certificates **enrolled in the `.72`
   firmware `db`**: the Lab cert (`580360d8…`) must be in `db` (so shim boots) and
   the boot chain must validate under it. If the firmware `db` and the policy
   anchors disagree → **stop, do not activate**.
3. `current` and the previous finalized generation are untouched (a candidate is
   immutable; finalize is a separate, later step).

## Failure modes

### Before finalization
Finalize refused / policy rejected / hash mismatch → **nothing changed**:
`current`, the previous generation, and every channel stay intact. Fix the tree
or the policy and re-run; no rollback needed.

### USB install fails before writing the target
Remove the USB and reboot into the **existing** installation; the on-disk system
is unchanged. Re-attempt only with a corrected candidate.

### New deployment installed but does not boot (OTA / bootc)
- Deploy with the previous root **retained** (`bootc … --retain`), and **prove the
  N-1 deployment still boots under the LAB chain before switching the default**.
- If the new deployment does not boot: at the boot menu, **select the previous
  deployment locally** (bootc keeps it), then investigate. No channel moves.

### Firmware `db` ↔ chain disagreement (Secure Boot refuses the chain)
Fail-closed: the unit stops rather than booting an unverified image. Recovery is
by **Owner physical presence at the UEFI console** — re-align `db`/re-enroll the
approved Lab anchor, or select a known-good previous deployment. **Never disable
Secure Boot** to work around it.

### PCR 7 / TPM auto-unlock broken by the `db` change
Changing the firmware `db` (or the shim/CA) changes **PCR 7**, so the TPM-sealed
LUKS auto-unlock stops (see [../disaster-recovery.md](../disaster-recovery.md) and
ADR-0011). Use the **already-escrowed recovery key** to unlock, and **re-enroll
the TPM only after** an approved Secure Boot state has been restored — never
re-seal against an unverified state.

## Exit criteria (a LAB run is "good")

1. The new generation boots healthy on `.72` under the LAB chain; and
2. a **forced rollback** to N-1 boots healthy as well.

Only when both hold is the candidate considered validated for LAB/debug. Nothing
here authorizes a PROD build, a client deployment, or a channel move.
