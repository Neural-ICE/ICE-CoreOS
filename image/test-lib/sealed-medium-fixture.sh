#!/usr/bin/env bash
# shellcheck shell=bash
# A REAL SEALED MEDIUM, BUILT WITH THE REAL TOOLCHAIN — the one fixture two
# suites share.
#
# WHY THIS IS A LIBRARY AND NOT TWO COPIES. image/test-installer-media.sh proves
# what a produced medium CONTAINS. image/test-verify-preloaded-media.sh proves
# what the PRELOADED finalization gate does to a medium that has since been
# GROWN, re-partitioned and seeded (review 2026-09-01, P1 #4). Both need the same
# object: a signed UKI whose .cmdline seals a real dm-verity root hash and a real
# payload digest, a real sealed payload extent, a real FAT ESP and a real GPT.
# Two fixtures would be two definitions of "a sealed medium", and only one of
# them could be the one the producer actually makes.
#
# NOTHING HERE SIGNS WITH A PRODUCTION KEY: the signing key and the trust policy
# that pins it are generated into the caller's throwaway directory and live for
# the duration of one test run.
#
# CONTRACT. The caller sets $ROOT (repo root), $TMP (a throwaway directory) and a
# `fail` function, calls sealed_medium_require_tools -- which SKIPs the suite
# when the toolchain is absent, because a suite that reports green without
# veritysetup is reporting on nothing -- and then sources the rest of this file.
# Afterwards it has:
#
#   $IN $SEALED $POLICY_ROOT $POLICY_ID $ROOT_HASH $PAYLOAD_DIGEST $ESP $RAW
#   build_uki NAME KARGS [ENV=…]      one UKI, signed by the throwaway key
#   make_esp UKI MANIFEST NAME        a FAT ESP carrying exactly one EFI binary
#   assemble ESP PAYLOAD [VOIDBYTES]  a GPT medium, written into $RAW
#
# ...and $RAW already holds one correctly assembled Install medium.

sealed_medium_require_tools() {
  local required
  for required in objdump objcopy sbsign sbverify openssl sha256sum python3 \
    mkfs.vfat mcopy mmd sgdisk veritysetup truncate; do
    command -v "$required" >/dev/null 2>&1 || { echo "SKIP: $required unavailable" >&2; exit 0; }
  done
}
sealed_medium_require_tools

TOOLS="$TMP/tools"; mkdir -p "$TOOLS"
for real in objdump objcopy sbsign sbverify sha256sum awk veritysetup dd truncate; do
  ln -sf "$(command -v "$real")" "$TOOLS/$real"
done
echo "  (using the host's real veritysetup)"

# --------------------------------------------------------------------------- #
# A minimal but REAL PE32+ to stand in for systemd-stub. binutils must be able to
# parse it, objcopy must be able to append sections to it, and sbsign must be
# able to sign the result — all three are exercised below.
# --------------------------------------------------------------------------- #
IN="$TMP/in"; mkdir -p "$IN"
python3 - "$IN/stub.efi" <<'PYEOF'
import struct, sys

SECTION_ALIGNMENT, FILE_ALIGNMENT = 4096, 512
text = b"\x90" * 64
optional_size = 112 + 16 * 8
headers = 0x80 + 4 + 20 + optional_size + 40
header_raw = (headers + FILE_ALIGNMENT - 1) // FILE_ALIGNMENT * FILE_ALIGNMENT
text_rva = SECTION_ALIGNMENT
dos = bytearray(0x80)
dos[0:2] = b"MZ"
struct.pack_into("<I", dos, 0x3C, 0x80)
# 0x8664 rather than 0xAA64: the GB10 medium is aarch64, but binutils on a CI
# runner only speaks pei-x86-64, and every property this suite asserts is about
# PE structure rather than instruction set.
coff = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, optional_size, 0x0022 | 0x2000)
optional = struct.pack(
    "<HBBIIIIIQ", 0x20B, 14, 0, len(text), 0, 0, text_rva, text_rva, 0x140000000
)
optional += struct.pack(
    "<IIHHHHHHIIIIHH", SECTION_ALIGNMENT, FILE_ALIGNMENT, 0, 0, 0, 0, 0, 0, 0,
    text_rva + SECTION_ALIGNMENT, header_raw, 0, 10, 0,
)
optional += struct.pack("<QQQQ", 0x100000, 0x1000, 0x100000, 0x1000)
optional += struct.pack("<II", 0, 16) + b"\x00" * (16 * 8)
assert len(optional) == optional_size
section = struct.pack(
    "<8sIIIIIIHHI", b".text", len(text), text_rva, FILE_ALIGNMENT, header_raw,
    0, 0, 0, 0, 0x60000020,
)
blob = bytes(dos) + b"PE\x00\x00" + coff + optional + section
blob = blob.ljust(header_raw, b"\x00") + text.ljust(FILE_ALIGNMENT, b"\x00")
open(sys.argv[1], "wb").write(blob)
PYEOF
[ -s "$IN/stub.efi" ] || fail "the synthetic PE stub was not produced"
objdump -h "$IN/stub.efi" >/dev/null || fail "binutils cannot parse the synthetic PE stub"

printf 'vmlinuz-bytes\n'                > "$IN/vmlinuz"
printf 'initramfs-with-verity-hook\n'   > "$IN/initrd"
printf 'NAME="Neural ICE"\n'            > "$IN/os-release"
# Multi-block images, so the dm-verity trees the inspector recomputes have more
# than one level to get wrong.
head -c 600000 /dev/urandom > "$IN/root.img"
head -c 200000 /dev/urandom > "$IN/store.img"
printf -- '-----BEGIN PUBLIC KEY-----\nrelauth\n-----END PUBLIC KEY-----\n' > "$IN/relauth.pub"
printf '%s\n' "$(printf 'devicetree:nvidia,gb10' | sha256sum | awk '{print $1}')" \
  > "$IN/gb10.fingerprints"

# --------------------------------------------------------------------------- #
# A throwaway signing key and a throwaway trust policy that pins its certificate.
# This is what binds TRUST_POLICY_ID to the key that actually signs.
# --------------------------------------------------------------------------- #
POLICY_ROOT="$TMP/trust-policies"
POLICY_ID=neural-ice-secureboot-test-v1
mkdir -p "$POLICY_ROOT/$POLICY_ID.d"
openssl req -x509 -newkey rsa:2048 -keyout "$TMP/uki.key" -out "$TMP/uki.crt" \
  -days 1 -nodes -subj "/CN=Neural ICE test UKI" >/dev/null 2>&1
cp "$TMP/uki.crt" "$POLICY_ROOT/$POLICY_ID.d/anchor.crt"
printf '#!/usr/bin/bash -p\nANCHOR_SHA256="%s"\n' \
  "$(sha256sum "$POLICY_ROOT/$POLICY_ID.d/anchor.crt" | awk '{print $1}')" \
  > "$POLICY_ROOT/$POLICY_ID"
chmod 0755 "$POLICY_ROOT/$POLICY_ID"

export NI_UKI_TESTING=1 NI_UKI_TEST_TOOLS="$TOOLS"
SEALED="$TMP/sealed"; mkdir -p "$SEALED"

# --------------------------------------------------------------------------- #
# 1) THE SEALED PAYLOAD, ASSEMBLED FOR REAL. Both protected extents, both hash
#    trees and the header whose digest the UKI seals.
# --------------------------------------------------------------------------- #
env ROOT_IMAGE="$IN/root.img" STORE_IMAGE="$IN/store.img" \
  PAYLOAD_OUT="$SEALED/payload.img" bash "$ROOT/image/build-installer-payload.sh" >/dev/null \
  || fail "the sealed payload assembly failed"
PAYLOAD_MANIFEST="$SEALED/payload.img.manifest"
ROOT_HASH="$(sed -n 's/^root_verity_hash=//p' "$PAYLOAD_MANIFEST")"
PAYLOAD_DIGEST="$(sed -n 's/^payload_header_sha256=//p' "$PAYLOAD_MANIFEST")"
for value in "$ROOT_HASH" "$PAYLOAD_DIGEST"; do
  [[ "$value" =~ ^[0-9a-f]{64}$ ]] || fail "the payload manifest carries a malformed digest"
done

build_uki() { # $1=name  $2=extra kargs  $3...=env overrides
  local name=$1 kargs=$2; shift 2
  env KERNEL="$IN/vmlinuz" INITRD="$IN/initrd" STUB="$IN/stub.efi" OSREL="$IN/os-release" \
    ROOT_VERITY_HASH="$ROOT_HASH" PAYLOAD_DIGEST="$PAYLOAD_DIGEST" \
    VARIANT=sealed-lab HARDWARE_TARGET=nvidia-gb10-arm64 \
    HARDWARE_IDENTITY_FILE="$IN/gb10.fingerprints" \
    TRUST_POLICY_ID="$POLICY_ID" TRUST_POLICY_ROOT="$POLICY_ROOT" \
    RELEASE_AUTH_PUBKEY="$IN/relauth.pub" \
    UKI_OUT="$SEALED/$name.efi" \
    EXTRA_KARGS="$kargs" \
    UKI_SIGNING_KEY="$TMP/uki.key" UKI_SIGNING_CERT="$TMP/uki.crt" \
    "$@" bash "$ROOT/image/build-installer-uki.sh"
}
# --------------------------------------------------------------------------- #
# 3) BUILD THE REAL, SIGNED UKIs — one per MODE. A produced medium carries
#    exactly one of them.
# --------------------------------------------------------------------------- #
build_uki installer-live "quiet" >/dev/null || fail "the Live UKI build failed"
build_uki installer-install "quiet systemd.unit=neural-ice-installer.target neuralice.autoinstall=1 enforcing=0" >/dev/null \
  || fail "the Install UKI build failed"
grep -qx 'signed=yes' "$SEALED/installer-install.efi.manifest" || fail "the Install UKI is not signed"
grep -qx 'release_authorization_schema=neural-ice-installer-release-authorization-v2' \
  "$SEALED/installer-install.efi.manifest" \
  || fail "the Install UKI manifest does not pin the exact v2 authorization contract"
grep -q "^signing_cert_sha256=[0-9a-f]\{64\}$" "$SEALED/installer-install.efi.manifest" \
  || fail "the manifest does not record the signing certificate fingerprint"
grep -qx "signing_cert_anchor=anchor.crt" "$SEALED/installer-install.efi.manifest" \
  || fail "the manifest does not record which trust anchor approved the certificate"
sbverify --cert "$TMP/uki.crt" "$SEALED/installer-install.efi" >/dev/null \
  || fail "the produced UKI does not verify with real sbverify"

# --------------------------------------------------------------------------- #
# 4) ASSEMBLE A REAL MEDIUM. Three partitions and nothing else: the ESP with ONE
#    EFI binary, the sealed payload, and the emptied remains of what bib wrote.
# --------------------------------------------------------------------------- #
RAW="$TMP/disk.raw"
ESP="$TMP/esp.img"
export MTOOLS_SKIP_CHECK=1
make_esp() { # $1=uki path  $2=manifest path  $3=manifest name
  rm -f "$ESP"; truncate -s 64M "$ESP"
  mkfs.vfat -F 32 -n EFI-SYSTEM "$ESP" >/dev/null
  mmd -i "$ESP" ::/EFI ::/EFI/BOOT ::/EFI/neural-ice
  mcopy -i "$ESP" "$1" '::/EFI/BOOT/BOOTAA64.EFI'
  mcopy -i "$ESP" "$2" "::/EFI/neural-ice/$3"
}
make_esp "$SEALED/installer-install.efi" "$SEALED/installer-install.efi.manifest" \
  installer-install.efi.manifest

PAYLOAD_BYTES="$(wc -c < "$SEALED/payload.img" | tr -d '[:space:]')"
PAYLOAD_MIB=$(( (PAYLOAD_BYTES + 1048575) / 1048576 + 1 ))
assemble() { # $1=esp image  $2=payload image  [$3=bytes to write into the void partition]
  rm -f "$RAW"
  truncate -s $(( 96 + PAYLOAD_MIB ))M "$RAW"
  sgdisk --clear \
    --new=1:2048:+64M          --typecode=1:EF00 --change-name=1:EFI-SYSTEM \
    --new=2:0:+16M             --typecode=2:8300 --change-name=2:ni-installer-void \
    --new=3:0:0                --typecode=3:8300 --change-name=3:ni-installer-payload \
    "$RAW" >/dev/null
  dd if="$1" of="$RAW" bs=512 seek=2048 conv=notrunc status=none
  local payload_start
  payload_start="$(sgdisk -i 3 "$RAW" | sed -n 's/^First sector: \([0-9]*\).*/\1/p')"
  [ -n "$payload_start" ] || fail "cannot locate the payload partition"
  dd if="$2" of="$RAW" bs=512 seek="$payload_start" conv=notrunc status=none
  if [ -n "${3:-}" ]; then
    local void_start
    void_start="$(sgdisk -i 2 "$RAW" | sed -n 's/^First sector: \([0-9]*\).*/\1/p')"
    printf '%s' "$3" | dd of="$RAW" bs=512 seek="$void_start" conv=notrunc status=none
  fi
}
assemble "$ESP" "$SEALED/payload.img"
