#!/usr/bin/env bash
# Negative tests for neural-ice-secureboot-lab-v1 (fail-closed / closed-world).
# Builds throwaway trees and asserts the policy REJECTS every deviation. Does not
# require the real leaf/lab signatures: every case here must be refused before or
# at the signer step. Run on a host whose /usr/bin/sbverify is the root-owned
# system binary. Exits 0 iff all negative cases reject with their expected reason.
set -euo pipefail

HERE="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
POL="$HERE/neural-ice-secureboot-lab-v1"
U="6.12.0-249.gb10.0.test.el10.aarch64"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
fails=0

mktree() {  # build a closed-world-complete tree of dummy (unsigned) files, 0755 dirs
  local d="$1" f
  rm -rf "$d"
  install -d -m0755 "$d/usr/lib/modules/$U" \
    "$d/usr/lib/bootupd/updates/EFI/BOOT" "$d/usr/lib/bootupd/updates/EFI/centos"
  for f in "usr/lib/modules/$U/vmlinuz" \
    usr/lib/bootupd/updates/EFI/BOOT/BOOTAA64.EFI usr/lib/bootupd/updates/EFI/BOOT/fbaa64.efi \
    usr/lib/bootupd/updates/EFI/BOOT/grubaa64.efi usr/lib/bootupd/updates/EFI/BOOT/mmaa64.efi \
    usr/lib/bootupd/updates/EFI/centos/grubaa64.efi usr/lib/bootupd/updates/EFI/centos/mmaa64.efi \
    usr/lib/bootupd/updates/EFI/centos/shimaa64.efi; do
    printf 'dummy' > "$d/$f"
  done
  printf 'generation_id=29669232382.1\n' > "$d/signed-boot-provenance.env"
}

expect_reject() {  # $1=label  $2=exact substring expected in the reason  $3...=env prefix
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

# Baseline: complete-but-unsigned tree must reject at the signer step.
mktree "$TMP/t"; expect_reject "unsigned components rejected" "unapproved/absent signer" env
# F1: environment cannot swap the verifier.
mktree "$TMP/t"; expect_reject "SBVERIFY_BIN override ignored" "unapproved/absent signer" env SBVERIFY_BIN=/bin/true
# F2: extra regular file (systemd unit) anywhere.
mktree "$TMP/t"; install -d -m0755 "$TMP/t/usr/lib/systemd/system"; printf 'x\n' > "$TMP/t/usr/lib/systemd/system/unexpected.service"
expect_reject "extra systemd unit rejected" "unexpected file in tree" env
# F2: extra EFI binary.
mktree "$TMP/t"; printf 'x' > "$TMP/t/usr/lib/bootupd/updates/EFI/BOOT/extra.efi"
expect_reject "extra EFI rejected" "unexpected file in tree" env
# F2: second vmlinuz.
mktree "$TMP/t"; install -d -m0755 "$TMP/t/usr/lib/modules/other"; printf 'x' > "$TMP/t/usr/lib/modules/other/vmlinuz"
expect_reject "second vmlinuz rejected" "unexpected file in tree" env
# F2: symlink.
mktree "$TMP/t"; ln -s /etc/passwd "$TMP/t/usr/lib/bootupd/updates/EFI/BOOT/link"
expect_reject "symlink rejected" "symlink present" env
# F2: unexpected empty directory.
mktree "$TMP/t"; install -d -m0755 "$TMP/t/usr/lib/bootupd/updates/EFI/BOOT/emptydir"
expect_reject "unexpected empty dir rejected" "unexpected directory in tree" env
# F2: unexpected FIFO special node.
mktree "$TMP/t"; mkfifo "$TMP/t/usr/lib/bootupd/updates/EFI/BOOT/fifo"
expect_reject "unexpected FIFO rejected" "special node in tree" env
# F2: moved component (grub outside its path).
mktree "$TMP/t"; mv "$TMP/t/usr/lib/bootupd/updates/EFI/centos/grubaa64.efi" "$TMP/t/usr/lib/bootupd/updates/EFI/centos/grub.moved.efi"
expect_reject "moved component rejected" "unexpected file in tree" env
# F2: group/other-writable directory.
mktree "$TMP/t"; chmod 0775 "$TMP/t/usr/lib/bootupd"
expect_reject "writable dir rejected" "group/other-writable directory" env
# Missing provenance (exact message).
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
