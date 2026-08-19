#!/usr/bin/env bash
# Prove the signed TPM policy on a real TPM, without an appliance.
#
# mission-0024 asks for three things a test volume CAN establish:
#
#   - a signed policy authorising a FUTURE state opens the volume once the
#     machine reaches that state, with no re-enrolment and nobody on site
#   - a state that was NOT authorised is refused
#   - the recovery path restores access to a volume whose policy fails
#
# and one it cannot: that `systemd-cryptsetup` opens the ROOT filesystem this
# way at boot, before any system exists. That needs an installed machine and is
# explicitly out of scope here — see docs/TPM-SIGNED-POLICY-RUNBOOK.md §7.
#
# ⚠️ THIS EXTENDS PCR 7 ON THE HOST. PCR 7 cannot be reset without a reboot, so
# after this run the host's PCR 7 no longer matches its boot-time Secure Boot
# state. Harmless where nothing seals against it; a reboot restores it. The
# script refuses to run on a host whose PCR 7 is already sealing something.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOL="$ROOT/ota/neural-ice-tpm-policy.py"
W="$(mktemp -d /var/tmp/ni-tpm-proof.XXXXXX)"
LOOP=""
PCR=7

cleanup() {
  [[ -e /dev/mapper/nitest ]] && cryptsetup close nitest 2>/dev/null || true
  [[ -n "$LOOP" ]] && losetup -d "$LOOP" 2>/dev/null || true
  rm -rf "$W"
}
trap cleanup EXIT

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
ok()   { printf '  \033[32m✅ %s\033[0m\n' "$*"; }
bad()  { printf '  \033[31m🔴 %s\033[0m\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || bad "run as root: LUKS and the TPM both need it"
for t in cryptsetup systemd-cryptenroll tpm2_pcrread tpm2_pcrextend openssl python3; do
  command -v "$t" >/dev/null || bad "missing $t"
done

# --- refuse to disturb a host that seals against PCR 7 ----------------------- #
# Extending PCR 7 on a machine whose own root is sealed to it would lock that
# machine out at the next boot. The check is cheap and the failure is not.
if command -v lsblk >/dev/null; then
  while read -r dev; do
    [[ -b "$dev" ]] || continue
    if cryptsetup isLuks "$dev" 2>/dev/null &&
       cryptsetup luksDump "$dev" 2>/dev/null | grep -q 'systemd-tpm2'; then
      bad "$dev on this host is sealed to the TPM. Extending PCR 7 here would
       lock it out at the next boot. Run this on a host that seals nothing."
    fi
  done < <(lsblk -pnro NAME 2>/dev/null)
fi
ok "no volume on this host seals against the TPM — safe to extend PCR 7"

pcr_now() { tpm2_pcrread "sha256:$PCR" | sed -n 's/.*0x\([0-9A-Fa-f]*\).*/\1/p' | head -1 | tr 'A-F' 'a-f'; }

say "1. a throwaway Owner key (the real one never leaves the Owner's token)"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$W/priv.pem" 2>/dev/null
openssl rsa -in "$W/priv.pem" -pubout -out "$W/pub.pem" 2>/dev/null
ok "keypair generated"

say "2. predict the state PCR 7 will reach, BEFORE reaching it"
A="$(pcr_now)"
EXT=$(printf 'neural-ice-signed-policy-proof' | sha256sum | cut -d' ' -f1)
# tpm2_pcrextend performs PCR := H(PCR ‖ digest). Predicting B is therefore
# arithmetic, which is the point: the authorisation is computed and signed while
# the machine is still in A.
B="$(python3 -c "
import hashlib,sys
print(hashlib.sha256(bytes.fromhex(sys.argv[1])+bytes.fromhex(sys.argv[2])).hexdigest())" "$A" "$EXT")"
printf '  current  A = %s\n  predicted B = %s\n' "$A" "$B"

POL_A="$(python3 "$TOOL" --pcr "$PCR" policy-digest --value "$A")"
POL_B="$(python3 "$TOOL" --pcr "$PCR" policy-digest --value "$B")"
printf '  policy(A) = %s\n  policy(B) = %s\n' "$POL_A" "$POL_B"

say "3. the Owner signs BOTH states — the current one and the one to come"
for p in "$POL_A" "$POL_B"; do
  python3 "$TOOL" sign-request --pol "$p" --out "$W/$p.bin" >/dev/null
  openssl dgst -sha256 -sign "$W/priv.pem" -out "$W/$p.bin.sig" "$W/$p.bin"
done
python3 "$TOOL" --pcr "$PCR" emit --pubkey "$W/pub.pem" --pol "$POL_A" \
  --sig "$W/$POL_A.bin.sig" --out "$W/sig.json" >/dev/null
python3 "$TOOL" --pcr "$PCR" emit --pubkey "$W/pub.pem" --pol "$POL_B" \
  --sig "$W/$POL_B.bin.sig" --merge "$W/sig.json" --out "$W/sig.json" >/dev/null
ok "$(python3 -c "import json;print(len(json.load(open('$W/sig.json'))['sha256']))") states authorised by one signature file"

say "4. a LUKS volume enrolled against the signed policy"
truncate -s 64M "$W/vol.img"
LOOP="$(losetup --find --show "$W/vol.img")"
PASS=recovery-passphrase-for-this-proof
# A deliberately weak KDF: this volume exists for seconds and holds nothing. The
# default argon2id is memory-hard by design and would dominate the run time of a
# proof that is about the POLICY, not about passphrase strength.
printf '%s' "$PASS" | cryptsetup luksFormat --type luks2 --batch-mode \
  --pbkdf pbkdf2 --pbkdf-force-iterations 1000 "$LOOP" - 2>/dev/null
ok "volume created, slot 0 = recovery passphrase"

PASSWORD="$PASS" systemd-cryptenroll "$LOOP" \
  --tpm2-device=auto --tpm2-public-key="$W/pub.pem" --tpm2-public-key-pcrs="$PCR" \
  --tpm2-signature="$W/sig.json" >/dev/null 2>&1 \
  || bad "enrolment against the signed policy failed"
ok "slot 1 = signed policy, bound to the public key (not to a PCR value)"

# Assert on what the header actually says, and PRINT it: the token type string
# is a cryptsetup/systemd implementation detail that has changed across releases,
# so a hard-coded name is a check that breaks on upgrade rather than on a defect.
TOKENS="$(cryptsetup luksDump "$LOOP" | sed -n '/^Tokens:/,/^Digests:/p')"
printf '%s\n' "$TOKENS" | sed 's/^/    /'
printf '%s' "$TOKENS" | grep -qi 'tpm2' \
  || bad "the header carries no TPM2 token — the enrolment did not take"
ok "the header carries a TPM2 token"

say "5. state A — it opens"
systemd-cryptsetup attach nitest "$LOOP" - \
  "tpm2-device=auto,tpm2-signature=$W/sig.json,headless=1" >/dev/null 2>&1 \
  || bad "the volume does not open in the state it was enrolled in"
ok "opened with no passphrase, in state A"
cryptsetup close nitest

say "6. move the machine to state B — the pre-authorised one"
tpm2_pcrextend "$PCR:sha256=$EXT" >/dev/null
NOW="$(pcr_now)"
[[ "$NOW" == "$B" ]] || bad "PCR 7 is $NOW, the prediction said $B — the arithmetic is wrong"
ok "PCR 7 moved to exactly the predicted value"

say "7. 🎯 THE POINT — it still opens, with no re-enrolment"
if systemd-cryptsetup attach nitest "$LOOP" - \
     "tpm2-device=auto,tpm2-signature=$W/sig.json,headless=1" >/dev/null 2>&1; then
  ok "opened in a state it was NEVER sealed to, because the Owner authorised it in advance"
  cryptsetup close nitest
else
  bad "the pre-authorised state did not open — the mechanism does not hold"
fi

say "8. an UNauthorised state — it must refuse"
tpm2_pcrextend "$PCR:sha256=$(printf 'unauthorised' | sha256sum | cut -d' ' -f1)" >/dev/null
if systemd-cryptsetup attach nitest "$LOOP" - \
     "tpm2-device=auto,tpm2-signature=$W/sig.json,headless=1" >/dev/null 2>&1; then
  cryptsetup close nitest
  bad "a state nobody authorised opened the volume — the policy is not binding"
fi
ok "refused — a signature covering other states does not open this one"

say "9. recovery — the volume is not lost"
printf '%s' "$PASS" | cryptsetup open "$LOOP" nitest - 2>/dev/null \
  || bad "the recovery passphrase does not open a volume whose policy fails"
ok "recovery passphrase opens it: a wrong policy costs an unlock, never the data"
cryptsetup close nitest

printf '\n\033[1m== proven on this host\033[0m\n'
printf '  a future state, signed in advance, opens without re-enrolment\n'
printf '  an unauthorised state is refused\n'
printf '  recovery restores access when the policy fails\n'
printf '\n  \033[33mNOT proven here: systemd-cryptsetup opening the ROOT at boot from\n'
printf '  the initramfs. That needs an installed machine.\033[0m\n'
printf '\n  PCR 7 on this host is now extended; a reboot restores it.\n'
