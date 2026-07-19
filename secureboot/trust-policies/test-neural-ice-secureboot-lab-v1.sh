#!/usr/bin/bash -p
# Negative tests for neural-ice-secureboot-lab-v1 (fail-closed / closed-world /
# environment-hardened). Builds throwaway trees and asserts the policy REJECTS
# every deviation and cannot be bypassed by a hostile environment. Every case
# must be refused before or at the signer step; no real leaf/lab signature needed.
# Run where /usr/bin/{bash,sbverify,sha256sum,find,stat} are the root-owned system
# binaries. Exits 0 iff all cases reject as expected.
PATH='/usr/sbin:/usr/bin:/sbin:/bin'; export PATH
set -euo pipefail

HERE="$(cd "$(/usr/bin/dirname "$(/usr/bin/readlink -f "$0")")" && pwd)"
POL="$HERE/neural-ice-secureboot-lab-v1"
U="6.12.0-249.gb10.0.test.el10.aarch64"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
fails=0

# A directory of hostile tools that all "succeed" (would bypass an unqualified policy).
EVIL="$TMP/evil"; mkdir -p "$EVIL"
for name in bash sh sbverify sha256sum find stat readlink dirname grep; do
  printf '#!/bin/sh\nexit 0\n' > "$EVIL/$name"; chmod 0755 "$EVIL/$name"
done
BE="$TMP/bash_env.sh"; printf 'exit 0\n' > "$BE"

mktree() {  # complete closed-world tree of dummy (unsigned) files, 0755 dirs, 0644 files
  local d="$1" f
  rm -rf "$d"
  install -d -m0755 "$d/usr/lib/modules/$U" \
    "$d/usr/lib/bootupd/updates/EFI/BOOT" "$d/usr/lib/bootupd/updates/EFI/centos"
  for f in "usr/lib/modules/$U/vmlinuz" \
    usr/lib/bootupd/updates/EFI/BOOT/BOOTAA64.EFI usr/lib/bootupd/updates/EFI/BOOT/fbaa64.efi \
    usr/lib/bootupd/updates/EFI/BOOT/grubaa64.efi usr/lib/bootupd/updates/EFI/BOOT/mmaa64.efi \
    usr/lib/bootupd/updates/EFI/centos/grubaa64.efi usr/lib/bootupd/updates/EFI/centos/mmaa64.efi \
    usr/lib/bootupd/updates/EFI/centos/shimaa64.efi; do
    install -m0644 /dev/null "$d/$f"; printf 'dummy' > "$d/$f"
  done
  install -m0644 /dev/null "$d/signed-boot-provenance.env"
  printf 'generation_id=29669232382.1\n' > "$d/signed-boot-provenance.env"
}

expect_reject() {  # $1=label  $2=exact substring in reason  $3...=env prefix (e.g. env VAR=val)
  local label="$1" want="$2"; shift 2
  local out rc
  if out="$("$@" "$POL" "$TMP/t" "$U" 2>&1)"; then rc=0; else rc=$?; fi
  if [[ $rc -ne 0 ]] && grep -qF -- "$want" <<<"$out"; then
    echo "PASS  $label"
  else
    echo "FAIL  $label (rc=$rc) :: $(tail -1 <<<"$out")"
    fails=$((fails + 1))
  fi
}

# Signer (baseline): a complete but unsigned tree must reject at the signer step.
mktree "$TMP/t"; expect_reject "unsigned components rejected" "unapproved/absent signer" env
# P1: hostile interpreter / env cannot bypass (must still reject, not rc=0).
mktree "$TMP/t"; expect_reject "fake bash in PATH ignored" "unapproved/absent signer" env "PATH=$EVIL:$PATH"
mktree "$TMP/t"; expect_reject "BASH_ENV=exit0 ignored" "unapproved/absent signer" env "BASH_ENV=$BE"
mktree "$TMP/t"; expect_reject "fake sha256sum/find/stat in PATH ignored" "unapproved/absent signer" env "PATH=$EVIL:$PATH" "BASH_ENV=$BE"
# G1: writable root / writable component.
mktree "$TMP/t"; chmod 0777 "$TMP/t"; expect_reject "writable root (0777) rejected" "signed-boot root is group/other-writable" env
mktree "$TMP/t"; chmod 0666 "$TMP/t/usr/lib/modules/$U/vmlinuz"; expect_reject "writable component (0666) rejected" "group/other-writable file" env
# F2: closed-world deviations.
mktree "$TMP/t"; install -d -m0755 "$TMP/t/usr/lib/systemd/system"; printf 'x\n' > "$TMP/t/usr/lib/systemd/system/unexpected.service"
expect_reject "extra systemd unit rejected" "unexpected file in tree" env
mktree "$TMP/t"; printf 'x' > "$TMP/t/usr/lib/bootupd/updates/EFI/BOOT/extra.efi"
expect_reject "extra EFI rejected" "unexpected file in tree" env
mktree "$TMP/t"; install -d -m0755 "$TMP/t/usr/lib/modules/other"; printf 'x' > "$TMP/t/usr/lib/modules/other/vmlinuz"
expect_reject "second vmlinuz rejected" "unexpected file in tree" env
mktree "$TMP/t"; ln -s /etc/passwd "$TMP/t/usr/lib/bootupd/updates/EFI/BOOT/link"
expect_reject "symlink rejected" "symlink present" env
mktree "$TMP/t"; install -d -m0755 "$TMP/t/usr/lib/bootupd/updates/EFI/BOOT/emptydir"
expect_reject "unexpected empty dir rejected" "unexpected directory in tree" env
mktree "$TMP/t"; mkfifo "$TMP/t/usr/lib/bootupd/updates/EFI/BOOT/fifo"
expect_reject "unexpected FIFO rejected" "special node in tree" env
mktree "$TMP/t"; mv "$TMP/t/usr/lib/bootupd/updates/EFI/centos/grubaa64.efi" "$TMP/t/usr/lib/bootupd/updates/EFI/centos/grub.moved.efi"
expect_reject "moved component rejected" "unexpected file in tree" env
mktree "$TMP/t"; chmod 0775 "$TMP/t/usr/lib/bootupd"
expect_reject "writable dir rejected" "group/other-writable directory" env
mktree "$TMP/t"; rm -f "$TMP/t/signed-boot-provenance.env"
expect_reject "missing provenance rejected" "missing signed-boot-provenance.env" env

echo "---"
if [[ $fails -eq 0 ]]; then
  echo "ALL NEGATIVE TESTS PASSED"
  exit 0
else
  echo "$fails FAILURE(S)"
  exit 1
fi
