#!/usr/bin/env bash
# QEMU + swtpm end-to-end of the installer's NI-P7-RULES gate (ADR-0045, T5).
#
# WHAT RUNS. An aarch64 KVM guest with AAVMF (Secure Boot enforcing, keys enrolled
# with virt-fw-vars) and a swtpm TPM 2.0. The guest boots a kernel signed by the
# test `db` key, so the firmware logs a real authority event, then runs the
# installer's OWN gate code (extracted verbatim from ota/neural-ice-autoinstall.sh) on
# its live TPM, TCG event log and efivarfs, with the rules and the Owner key read
# from a FAT "medium" through the installer's own esp_staged_file. Only when the gate
# accepts does it run the installer's own enroll_luks on a scratch disk.
#
# WHAT IT DOES NOT RUN. The rest of the installer (bootc deployment, seed, mirror),
# the sealed UKI command line (the sealed kargs travel on the QEMU -append here, so the
# signed-cmdline chain is not exercised), a GB10 (the guest's firmware measures the
# CONTENTS of the Secure Boot variables, a GB10 measures only their names).
#
# usage: run-e2e.sh [--repo DIR] [--work DIR] [--keep]
#   needs: aarch64 host, /dev/kvm, qemu-system-aarch64, swtpm, AAVMF, tpm2-tools,
#          systemd-cryptenroll, cryptsetup, sbsign, sbattach, mtools, python3 (venv + pip
#          for virt-firmware), openssl, ldd. Everything is created under --work.
set -euo pipefail
umask 077
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK=""
KEEP=0
while (( $# )); do
  case "$1" in
    --repo) REPO="$2"; shift 2 ;;
    --work) WORK="$2"; shift 2 ;;
    --keep) KEEP=1; shift ;;
    *) echo "unknown argument $1" >&2; exit 64 ;;
  esac
done
[[ -n "$WORK" ]] || WORK="/var/tmp/ni-pcr-rules-e2e-$$"
[[ ! -e "$WORK" ]] || { echo "refused: $WORK already exists" >&2; exit 1; }
# QEMU_PREFIX: how to run qemu when the account is not in the kvm group (e.g. "sudo -n").
# Only qemu itself runs under it; every file it touches stays owned by this account.
QEMU_PREFIX="${QEMU_PREFIX:-}"
[[ "$(uname -m)" == aarch64 ]] && { [[ -n "$QEMU_PREFIX" ]] || [[ -w /dev/kvm ]]; } \
  || { echo "refused: needs an aarch64 KVM host (set QEMU_PREFIX='sudo -n' if /dev/kvm is not writable)" >&2; exit 1; }
AUTOINSTALL="$REPO/ota/neural-ice-autoinstall.sh"
ENGINE="$REPO/tools/ni-pcr-rules/ni-pcr-rules.py"
CODE=/usr/share/AAVMF/AAVMF_CODE.secboot.fd
VARS_TEMPLATE=/usr/share/AAVMF/AAVMF_VARS.fd
mkdir -m 0700 "$WORK"
# Ubuntu's AppArmor profile for swtpm refuses to create sockets under /var/tmp; /tmp is
# allowed, so the TPM state and sockets (only those) live in a private directory there.
TPMROOT="$(mktemp -d /tmp/ni-pcr-rules-e2e-tpm.XXXXXX)"
SWTPM_PID=""
cleanup() {
  [[ -z "$SWTPM_PID" ]] || kill "$SWTPM_PID" 2>/dev/null || true
  rm -rf "$TPMROOT"
  if (( KEEP == 0 )); then rm -rf "$WORK"; else echo "kept: $WORK"; fi
}
trap cleanup EXIT
say() { printf '== %s\n' "$*"; }
fail() { printf 'E2E-FAIL: %s\n' "$*" >&2; exit 1; }

# --- 1. keys, Secure Boot varstores -----------------------------------------------------------
say "keys and Secure Boot varstores"
K="$WORK/keys"; mkdir "$K"
selfsign() { # name cn
  openssl req -new -x509 -newkey rsa:2048 -nodes -keyout "$K/$1.key" -out "$K/$1.crt" \
    -subj "/CN=$2/" -days 3650 -sha256 >/dev/null 2>&1
}
selfsign pk "ni-e2e platform key"; selfsign kek "ni-e2e kek"; selfsign db "ni-e2e db"
selfsign db-extra "ni-e2e db extra (not approved)"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$K/owner.key" >/dev/null 2>&1
openssl pkey -in "$K/owner.key" -pubout -out "$K/owner.pub" >/dev/null 2>&1
python3 -m venv "$WORK/venv" >/dev/null
"$WORK/venv/bin/pip" install -q virt-firmware >/dev/null 2>&1 || fail "pip could not install virt-firmware"
VFV="$WORK/venv/bin/virt-fw-vars"
OWNER_GUID="$(python3 -c 'import uuid; print(uuid.uuid4())')"
DBX_HASH="$(printf 'ni-e2e dbx floor entry' | sha256sum | awk '{print $1}')"
common=(--set-pk "$OWNER_GUID" "$K/pk.crt" --add-kek "$OWNER_GUID" "$K/kek.crt"
        --add-dbx-hash "$OWNER_GUID" "$DBX_HASH" --secure-boot)
"$VFV" -i "$VARS_TEMPLATE" -o "$WORK/vars.conform.fd" "${common[@]}" --add-db "$OWNER_GUID" "$K/db.crt" >/dev/null
# non-conforming 1: a second, unapproved certificate in db (a variable the rules bound)
"$VFV" -i "$VARS_TEMPLATE" -o "$WORK/vars.extradb.fd" "${common[@]}" \
  --add-db "$OWNER_GUID" "$K/db.crt" --add-db "$OWNER_GUID" "$K/db-extra.crt" >/dev/null
# non-conforming 2: no PK at all = setup mode, Secure Boot not enforcing
cp "$VARS_TEMPLATE" "$WORK/vars.setup.fd"

# --- 2. the guest kernel (signed by the db key) and initramfs -------------------------------------
say "kernel and initramfs"
KVER="$(uname -r)"
# /boot is root-only on Ubuntu: read it through the same prefix as qemu; the copy is ours.
# shellcheck disable=SC2086
$QEMU_PREFIX cat "/boot/vmlinuz-$KVER" > "$WORK/vmlinuz.orig"
# Ubuntu's arm64 vmlinuz is a gzip of the EFI-stub Image: the firmware needs the PE itself.
if [[ "$(head -c2 "$WORK/vmlinuz.orig" | od -An -tx1 | tr -d ' ')" == 1f8b ]]; then
  gzip -dc "$WORK/vmlinuz.orig" > "$WORK/vmlinuz.pe" && mv "$WORK/vmlinuz.pe" "$WORK/vmlinuz.orig"
fi
sbattach --remove "$WORK/vmlinuz.orig" >/dev/null 2>&1 || true
sbsign --key "$K/db.key" --cert "$K/db.crt" --output "$WORK/vmlinuz.signed" "$WORK/vmlinuz.orig" >/dev/null 2>&1 \
  || fail "sbsign could not sign the kernel"
I="$WORK/initramfs"; mkdir -p "$I"/{usr/bin,usr/sbin,usr/lib,proc,sys,dev,run,tmp,etc,usr/lib/neural-ice/pcr-rules/ota,usr/lib/neural-ice/pcr-rules/tools/ni-pcr-rules}
ln -s usr/bin "$I/bin"; ln -s usr/sbin "$I/sbin"; ln -s usr/lib "$I/lib"
copy_lib() { # path as printed by ldd
  local lib=$1 real
  [[ -e "$I$lib" ]] && return 0
  real="$(readlink -f "$lib")"
  install -D "$real" "$I$lib" 2>/dev/null || { mkdir -p "$(dirname "$I$lib")"; cp -L "$real" "$I$lib"; }
}
copy_deps() { # a binary or shared object
  local dep
  while read -r dep; do [[ -n "$dep" ]] && copy_lib "$dep"; done < <(
    ldd "$1" 2>/dev/null | awk '/=> \//{print $3} /^[[:space:]]*\/[^ ]*ld-linux/{print $1}')
}
copy_bin() { # name (looked up in PATH)
  local src; src="$(command -v "$1")" || fail "missing tool $1"
  install -D "$(readlink -f "$src")" "$I/usr/bin/$1"
  copy_deps "$src"
}
for tool in bash busybox sha256sum awk sed tr head tail cut install mktemp stat cat mount umount \
            findmnt lsblk chattr sfdisk partx wipefs cryptsetup systemd-cryptenroll openssl \
            tpm2_pcrread tpm2_createprimary tpm2_evictcontrol modprobe kmod od wc sync sleep \
            grep readlink ls rm mkdir ln cp mv dd date python3.12 env uname dmesg shred; do copy_bin "$tool"; done
ln -sf python3.12 "$I/usr/bin/python3"
ln -sf busybox "$I/usr/bin/poweroff"; ln -sf busybox "$I/usr/bin/mdev"
# libraries the tools dlopen
for pattern in 'libtss2-*' 'libcryptsetup*' 'libcrypto*' 'libssl*' 'libargon2*' 'libjson-c*' \
               'libgcc_s*' 'libdevmapper*' 'libudev*' 'libkmod*' 'libzstd*' 'liblzma*' 'libp11-kit*' 'libblkid*' 'libmount*'; do
  for lib in /usr/lib/aarch64-linux-gnu/$pattern /lib/aarch64-linux-gnu/$pattern; do
    [[ -e "$lib" ]] && { copy_lib "${lib/#\/lib\//\/usr\/lib\/}"; copy_deps "$lib"; }
  done
done
# python: stdlib without tests, plus the compiled modules' libraries
tar -C /usr/lib -cf - --exclude='python3.12/test' --exclude='python3.12/idlelib' \
  --exclude='python3.12/tkinter' --exclude='python3.12/turtledemo' --exclude='python3.12/ensurepip' \
  --exclude='python3.12/lib2to3' --exclude='*/__pycache__' python3.12 | tar -C "$I/usr/lib" -xf -
for so in /usr/lib/python3.12/lib-dynload/*.so; do copy_deps "$so"; done
# the TPM library loader finds its TCTI by name at run time
mkdir -p "$I/etc"; cp /etc/ld.so.cache "$I/etc/" 2>/dev/null || true
# device-mapper crypt and what it needs
MODDIR="/usr/lib/modules/$KVER"
mkdir -p "$I/usr/lib/modules/$KVER"
# vfat needs its default charset (iso8859-1, a module on this kernel) to mount the medium
for mod in $(for name in dm-crypt nls_iso8859-1 nls_utf8; do modprobe -S "$KVER" --show-depends "$name"; done | awk '/^insmod/{print $2}' | sort -u); do
  install -D "$mod" "$I$mod"
done
cp "$MODDIR"/modules.{order,builtin,builtin.modinfo} "$I/usr/lib/modules/$KVER/" 2>/dev/null || true
depmod -b "$I" "$KVER" 2>/dev/null || true
# the installer's own code, extracted verbatim (see ota/test-installer-pcr-rules.sh)
ex() { awk "/^$1\\(\\) \\{/,/^}\$/" "$AUTOINSTALL"; }
{
  echo 'NI_INSTALLER_TEST_SEAM=""'
  ex ni_path; ex write_failure_evidence; ex karg_count; ex karg_once
  ex esp_snapshot_file; ex esp_staged_file; ex esp_staged_file_unsealed
  awk '/^die\(\)  \{/,/^}$/' "$AUTOINSTALL"
} > "$I/gate.sh"
awk '/^PCR_RULES_DIGEST=/,/^readonly PCR_RULES_STATE$/' "$AUTOINSTALL" > "$I/gate-block.sh"
ex enroll_luks > "$I/enroll.sh"
# E2E_VERBOSE_ENROLL=1 lets the tools' own diagnostics through (debugging only).
[[ "${E2E_VERBOSE_ENROLL:-0}" != 1 ]] || sed -i 's#>/dev/null 2>&1##; s#>/dev/null##' "$I/enroll.sh"
# the installer's own "what the gate decided" record for the installed ESP
awk '/^install -m 0644 \/dev\/null .*pcr-rules-at-install\.txt"$/{on=1} on{print} on&&/^fi$/{exit}' "$AUTOINSTALL" > "$I/evidence.sh"
for f in gate.sh gate-block.sh enroll.sh evidence.sh; do [[ -s "$I/$f" ]] || fail "could not extract $f from the installer"; done
grep -q '^verify_pcr_rules() {' "$I/gate-block.sh" || fail "the gate block does not hold verify_pcr_rules"
# The image layout of image/Containerfile.installer, byte for byte.
cp "$ENGINE" "$I/usr/lib/neural-ice/pcr-rules/tools/ni-pcr-rules/ni-pcr-rules.py"
cp "$REPO/ota/neural-ice-tpm-policy.py" "$I/usr/lib/neural-ice/tpm-policy.py"
ln -s ../../tpm-policy.py "$I/usr/lib/neural-ice/pcr-rules/ota/neural-ice-tpm-policy.py"
install -m 0755 "$(dirname "${BASH_SOURCE[0]}")/guest-init.sh" "$I/init"
( cd "$I" && find . | cpio -o -H newc --quiet | gzip -1 ) > "$WORK/initrd.img"
echo "initramfs $(du -h "$WORK/initrd.img" | cut -f1)"

# --- 3. rules, medium ---------------------------------------------------------------------------------
say "rules and medium"
der_id() { openssl x509 -in "$1" -outform DER | sha256sum | awk '{print "x509:"$1}'; }
write_rules() { # $1=out  $2=approved db id list (json)  $3=unbound policy
  python3 - "$1" "$2" "$3" "$(der_id "$K/pk.crt")" "$(der_id "$K/kek.crt")" "$(der_id "$K/db.crt")" "$DBX_HASH" <<'PY'
import json, sys
out, certs, unbound, pk, kek, db, dbx = sys.argv[1:]
json.dump({"schema": "ni-pcr-rules/1", "sequence": 7, "unbound_variables": unbound,
           "approved_certs": json.loads(certs), "approved_pk": [pk], "approved_kek": [kek],
           "dbx_floor": [f"sha256:{dbx}"], "authorities": [{"name": "db", "ids": [db]}]},
          open(out, "w"), indent=2)
PY
}
DBID="$(der_id "$K/db.crt")"
write_rules "$WORK/rules.json" "[\"$DBID\"]" refuse
python3 -I "$ENGINE" sign --rules "$WORK/rules.json" --key "$K/owner.key" --out "$WORK/rules.json.sig" >/dev/null
RULES_SHA="$(sha256sum "$WORK/rules.json" | awk '{print $1}')"
PUBKEY_SHA="$(sha256sum "$K/owner.pub" | awk '{print $1}')"
# rules whose db set does not approve the booted certificate
write_rules "$WORK/rules.nodb.json" '["x509:'"$(printf 'nobody' | sha256sum | awk '{print $1}')"'"]' refuse
python3 -I "$ENGINE" sign --rules "$WORK/rules.nodb.json" --key "$K/owner.key" --out "$WORK/rules.nodb.json.sig" >/dev/null
make_medium() { # $1=out $2=rules $3=sig
  truncate -s 16M "$1"; mkfs.vfat -n NIMEDIUM "$1" >/dev/null
  mmd -i "$1" ::ice-coreos ::ice-coreos/pcr-rules
  mcopy -i "$1" "$K/owner.pub" ::ice-coreos/tpm2-pcr-public-key.pem
  mcopy -i "$1" "$2" ::ice-coreos/pcr-rules/rules.json
  mcopy -i "$1" "$3" ::ice-coreos/pcr-rules/rules.json.sig
}
make_medium "$WORK/medium.good.img" "$WORK/rules.json" "$WORK/rules.json.sig"
make_medium "$WORK/medium.nodb.img" "$WORK/rules.nodb.json" "$WORK/rules.nodb.json.sig"
RULES_NODB_SHA="$(sha256sum "$WORK/rules.nodb.json" | awk '{print $1}')"

# The scratch target: 96 MiB of a fixed non-zero pattern, so "byte-identical" is a real statement.
python3 -c 'import hashlib,sys
block=b"".join(hashlib.sha256(b"ni-e2e-target"+i.to_bytes(4,"big")).digest() for i in range(32768))
open(sys.argv[1],"wb").write(block*96)' "$WORK/target.pristine.img"
TARGET_ORIG="$(sha256sum "$WORK/target.pristine.img" | awk '{print $1}')"

# --- 4. one VM run ---------------------------------------------------------------------------------------
run_vm() { # $1=scenario $2=varstore $3=medium $4=cmdline extras ; leaves $WORK/$1.{log,target.img}
  local name=$1 vars="$WORK/vars.$1.run.fd" tpm="$TPMROOT/$1"
  cp "$2" "$vars"; mkdir -m 0700 "$tpm"
  # the scratch target: a fixed non-zero pattern, so "unchanged" is a real statement
  cp "$WORK/target.pristine.img" "$WORK/$name.target.img"
  swtpm socket --tpm2 --tpmstate "dir=$tpm" --ctrl "type=unixio,path=$tpm/ctrl.sock,mode=0600" \
    --pid "file=$tpm/pid" --flags not-need-init,startup-clear --daemon
  for _ in {1..50}; do [[ -S "$tpm/ctrl.sock" ]] && break; sleep 0.1; done
  SWTPM_PID="$(cat "$tpm/pid")"
  # shellcheck disable=SC2086
  timeout 600 $QEMU_PREFIX qemu-system-aarch64 -name "ni-e2e-$name" -machine virt,accel=kvm,gic-version=3 \
    -cpu host -smp 2 -m 3072 -nographic -no-reboot \
    -drive "if=pflash,format=raw,unit=0,readonly=on,file=$CODE" \
    -drive "if=pflash,format=raw,unit=1,file=$vars" \
    -chardev "socket,id=chrtpm,path=$tpm/ctrl.sock" -tpmdev emulator,id=tpm0,chardev=chrtpm \
    -device tpm-tis-device,tpmdev=tpm0 \
    -drive "if=none,id=media,format=raw,readonly=on,file=$3" -device virtio-blk-pci,drive=media \
    -drive "if=none,id=target,format=raw,file=$WORK/$name.target.img" -device virtio-blk-pci,drive=target \
    -kernel "$WORK/vmlinuz.signed" -initrd "$WORK/initrd.img" \
    -append "console=ttyAMA0 rdinit=/init loglevel=3 e2e.scenario=$name $4" \
    > "$WORK/$name.log" 2>&1 < /dev/null || true
  kill "$SWTPM_PID" 2>/dev/null || true; SWTPM_PID=""
  tr -d '\r' < "$WORK/$name.log" | grep -E '^(E2E|\[neural-ice-autoinstall\]|\{|  "|\]|\})' | sed 's/^/    | /' || true
}
target_sha() { sha256sum "$WORK/$1.target.img" | awk '{print $1}'; }
common_cmdline() { echo "neuralice.pcr_policy_key=$PUBKEY_SHA neuralice.pcr_rules=$1 neuralice.pcr_rules_seq=7"; }
log_has() { tr -d '\r' < "$WORK/$1.log" | grep -Fq -- "$2"; }

PASS=0
check() { # description, command...
  local what=$1; shift
  if "$@"; then echo "PASS: $what"; PASS=$((PASS+1)); else echo "FAIL: $what"; FAILED=1; fi
}
FAILED=0

say "calibration: what the guest firmware logged, read by the engine's own 'ids'"
run_vm calibrate "$WORK/vars.conform.fd" "$WORK/medium.good.img" "e2e.mode=ids"
log_has calibrate "E2E: SecureBoot=1 SetupMode=0" || fail "the conforming varstore does not boot with Secure Boot enforcing (see $WORK/calibrate.log)"

say "scenario A: conforming state -> the gate accepts and the installer enrols"
run_vm conforming "$WORK/vars.conform.fd" "$WORK/medium.good.img" "$(common_cmdline "$RULES_SHA")"
check "A: gate accepted" log_has conforming "E2E: gate state=accepted"
check "A: binding is contents (the guest firmware measures contents)" log_has conforming "binding=contents"
check "A: the installer enrolled the scratch disk" log_has conforming "E2E: ENROLLED"
check "A: a PolicyAuthorize (pubkey-bound) TPM2 token exists" log_has conforming "pubkey-bound 1"
check "A: the target changed (the install really wrote)" test "$(target_sha conforming)" != "$TARGET_ORIG"
check "A: the installed ESP record says state=accepted, sequence 7, binding=contents" \
  bash -c 'tr -d "\r" < "'"$WORK/conforming.log"'" | grep -F "E2E: record " | grep -F "state=accepted" | grep -F "sequence=7" | grep -F "binding=contents"'
check "A: the installed rules are the sealed bytes" log_has conforming "E2E: installed rules sha256 $RULES_SHA"

refused() { # scenario slug
  check "$1: refused with NI-P7-RULES: $2" log_has "$1" "NI-P7-RULES: $2"
  check "$1: never reached the install" bash -c '! tr -d "\r" < "'"$WORK/$1.log"'" | grep -Fq "E2E: INSTALLING"'
  check "$1: the target disk is byte-identical (no write before the refusal)" test "$(target_sha "$1")" = "$TARGET_ORIG"
  check "$1: no LUKS header was written" bash -c '! tr -d "\r" < "'"$WORK/$1.log"'" | grep -Fq "E2E: ENROLLED"'
}
say "scenario B: a certificate in db that the rules do not approve -> refused before any write"
run_vm extradb "$WORK/vars.extradb.fd" "$WORK/medium.good.img" "$(common_cmdline "$RULES_SHA")"
refused extradb variable-rule
say "scenario C: rules that approve no db certificate -> refused before any write"
run_vm nodb "$WORK/vars.conform.fd" "$WORK/medium.nodb.img" "$(common_cmdline "$RULES_NODB_SHA")"
refused nodb variable-rule
say "scenario D: setup mode, no PK, Secure Boot off -> refused before any write"
run_vm setup "$WORK/vars.setup.fd" "$WORK/medium.good.img" "$(common_cmdline "$RULES_SHA")"
refused setup secure-boot-state
say "scenario E: the medium's rules are not the sealed ones -> refused before any write"
run_vm swapped "$WORK/vars.conform.fd" "$WORK/medium.nodb.img" "$(common_cmdline "$RULES_SHA")"
check "E: refused (the ESP's rules hash is not the sealed hash)" log_has swapped "NI-P7-RULES: payload-unavailable"
check "E: the target disk is byte-identical" test "$(target_sha swapped)" = "$TARGET_ORIG"

echo "e2e checks passed: $PASS; failures: $FAILED"
(( FAILED == 0 )) || { echo "logs: $WORK (kept)"; KEEP=1; exit 1; }
echo "PCR_RULES_E2E_OK"
