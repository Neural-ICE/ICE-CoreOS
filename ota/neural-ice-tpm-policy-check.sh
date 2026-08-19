#!/usr/bin/env bash
# FAB-0046 verification clause: prove the policy IN FORCE is the expected one.
#
# The failure this exists to catch is an appliance that carries the new image but
# was never re-enrolled. It boots, it serves, it looks correct — and it is still
# sealed to the literal PCR value. Nothing surfaces until the anchor moves, at
# which point that unit is the one that does not come back.
#
# So this asserts on the LUKS header of the running machine, never on the image,
# the documentation, or the presence of tooling. `can` is not `is`.
#
#   neural-ice-tpm-policy-check.sh /dev/nvme0n1p3 [/dev/nvme0n1p4 …]
#
# Exit 0 = every named volume is on the signed policy.
# Exit 1 = at least one is not, and it says which and why.
set -uo pipefail

SIG_PATH=/run/systemd/tpm2-pcr-signature.json
rc=0

say()  { printf '\n\033[1m%s\033[0m\n' "$*"; }
ok()   { printf '  \033[32m✅ %s\033[0m\n' "$*"; }
bad()  { printf '  \033[31m🔴 %s\033[0m\n' "$*" >&2; rc=1; }
warn() { printf '  \033[33m⚠️  %s\033[0m\n' "$*"; }

[[ $EUID -eq 0 ]] || { echo "run as root: reading a LUKS header needs it" >&2; exit 2; }
[[ $# -ge 1 ]] || { echo "usage: $0 <luks-device> [<luks-device> …]" >&2; exit 2; }

command -v cryptsetup >/dev/null || { echo "cryptsetup missing" >&2; exit 2; }

say "signature file"
if [[ -f "$SIG_PATH" && ! -L "$SIG_PATH" ]]; then
  # The count matters operationally: one authorised state means no rollback path
  # and no pre-authorised future. Two or more is the healthy steady state during
  # a transition.
  n="$(python3 -c "
import json,sys
try:
    d=json.load(open('$SIG_PATH'))
    print(sum(len(v) for v in d.values()))
except Exception:
    print(-1)" 2>/dev/null)"
  case "$n" in
    -1) bad "$SIG_PATH is present but not parseable — unlock will fall back to recovery" ;;
    0)  bad "$SIG_PATH authorises no state at all" ;;
    1)  warn "$SIG_PATH authorises 1 state: no rollback path and no pre-authorised future" ;;
    *)  ok "$SIG_PATH authorises $n states" ;;
  esac
else
  bad "$SIG_PATH is absent — a signed-policy volume cannot unlock without it"
fi

for dev in "$@"; do
  say "$dev"
  if ! cryptsetup isLuks "$dev" 2>/dev/null; then
    bad "not a LUKS device"
    continue
  fi
  dump="$(cryptsetup luksDump "$dev" 2>/dev/null)"

  # The discriminator. A token carrying tpm2-pubkey is bound to a KEY and accepts
  # any state that key authorises. A token carrying only tpm2-pcrs is the old
  # literal seal: it accepts exactly one state, forever.
  has_pubkey=0; has_literal=0
  grep -q 'tpm2-pubkey:' <<<"$dump" && has_pubkey=1
  grep -qE 'tpm2-pcrs: *[0-9]' <<<"$dump" && has_literal=1

  if (( has_pubkey && ! has_literal )); then
    ok "signed policy, and no literal PCR seal beside it"
    printf '     %s\n' "$(grep -E 'tpm2-pubkey-pcrs:' <<<"$dump" | tr -s ' ')"
  elif (( has_pubkey && has_literal )); then
    bad "BOTH a signed policy and a literal PCR seal: the literal half will refuse
       the day the state changes, whatever the signature authorises. Re-enrol with
       --tpm2-pcrs= empty (see docs/TPM-SIGNED-POLICY-RUNBOOK.md §5ter)."
    printf '     %s\n' "$(grep -E 'tpm2-pcrs:' <<<"$dump" | tr -s ' ')"
  elif (( has_literal )); then
    bad "LITERAL PCR seal only — this volume was never re-enrolled onto the signed
       policy. It works today and will not survive the anchor switch."
  else
    bad "no TPM2 token at all: this volume unlocks by passphrase only"
  fi

  # A volume with no recovery keyslot is one policy mistake away from being lost.
  slots="$(grep -cE '^  [0-9]+: luks2' <<<"$dump")"
  if (( slots >= 2 )); then
    ok "$slots keyslots — a recovery path exists beside the policy"
  else
    bad "$slots keyslot: no recovery path. A policy that fails loses the volume."
  fi
done

say "verdict"
if (( rc == 0 )); then
  ok "every volume named is on the signed policy, with recovery beside it"
else
  bad "at least one volume is NOT in the expected state — see above"
fi
exit "$rc"
