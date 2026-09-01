#!/usr/bin/env bash
# shellcheck disable=SC2016 # literal source-contract assertions below
# THE MEDIUM CONTAINS WHAT THE BUILD CLAIMS IT STAGED — proven on real bytes.
#
# WHY THIS SUITE EXISTS. image/test-installer-uki.sh mocks objcopy, sbsign and
# sbverify, so it proves the BUILDER's arithmetic and nothing about the artefact.
# Nothing at all asserted that a produced medium carried the signed UKIs, that
# their .cmdline really held the sealed anchor, or that the destructive entry was
# a signature rather than a keystroke — so the whole UKI/verity path could be
# dead code with every test green.
#
# THIS suite uses the REAL toolchain: real objdump/objcopy assemble a real PE,
# real sbsign signs it, real sbverify verifies it, real veritysetup formats both
# protected extents, real mkfs.vfat/mcopy/sgdisk build a real GPT medium with a
# real FAT ESP, and image/inspect-installer-media.py reads it back WITHOUT root
# and WITHOUT a loop device -- hashing every sealed region and RECOMPUTING both
# dm-verity root hashes from the bytes on the medium.
#
# 🔴 WHAT IT NOW ALSO PROVES (review 2026-09-01, P0 #2). The medium is
# single-purpose: one signed UKI at \EFI\BOOT\BOOTAA64.EFI and NOTHING ELSE
# bootable. A second EFI binary, a boot manager, a leftover kernel or a
# non-empty partition are each a refusal, because "GRUB cannot name a kernel" was
# a claim about a generated config file and not about the medium.
#
# NOTHING HERE SIGNS WITH A PRODUCTION KEY: the signing key and its trust policy
# are generated into a throwaway directory for the duration of the test.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/ni-media.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

# shellcheck source=image/test-lib/sealed-medium-fixture.sh
source "$ROOT/image/test-lib/sealed-medium-fixture.sh"

# --------------------------------------------------------------------------- #
# 2) THE CERTIFICATE IS BOUND TO THE POLICY. A key the named policy does not
#    approve must not be able to produce a medium that claims that policy.
# --------------------------------------------------------------------------- #
openssl req -x509 -newkey rsa:2048 -keyout "$TMP/rogue.key" -out "$TMP/rogue.crt" \
  -days 1 -nodes -subj "/CN=Rogue" >/dev/null 2>&1
build_uki rogue "quiet" UKI_SIGNING_KEY="$TMP/rogue.key" UKI_SIGNING_CERT="$TMP/rogue.crt" \
  >/dev/null 2>&1 \
  && fail "a certificate the trust policy does not approve produced a UKI"
[ ! -f "$SEALED/rogue.efi" ] || fail "the refused build left an artefact behind"
build_uki noidentity "quiet" HARDWARE_IDENTITY_FILE= >/dev/null 2>&1 \
  && fail "a build with no measured-identity list produced a UKI"


inspect() {
  python3 "$ROOT/image/inspect-installer-media.py" --raw "$RAW" \
    --expect-verity-root-hash "$ROOT_HASH" \
    --expect-payload-digest "$PAYLOAD_DIGEST" \
    --expect-mode install \
    --expect-access-profile lab-managed \
    --expect-hardware-target nvidia-gb10-arm64 \
    --expect-trust-policy-id "$POLICY_ID" "$@"
}
inspect >"$TMP/inspect.out" || { cat "$TMP/inspect.out" >&2; fail "a correct medium was refused"; }
grep -q 'inspect-installer-media: OK' "$TMP/inspect.out" || fail "the inspector did not report OK"
grep -q 'neuralice.autoinstall=1' "$TMP/inspect.out" \
  || fail "the inspector did not surface the sealed install cmdline"
grep -q 'systemd.unit=neural-ice-installer.target' "$TMP/inspect.out" \
  || fail "the inspector did not surface the signed fail-closed installer target"
grep -q 'neuralice.relauth_schema=neural-ice-installer-release-authorization-v2' "$TMP/inspect.out" \
  || fail "the inspector did not surface the exact v2 authorization contract sealed by the UKI"
grep -q 'recomputed from the medium' "$TMP/inspect.out" \
  || fail "the inspector did not recompute the verity root hashes off the medium"

# --------------------------------------------------------------------------- #
# 5) THE REFUSALS. Each mutation is one way a medium can be wrong.
# --------------------------------------------------------------------------- #
# (a) a medium whose UKI seals a DIFFERENT root than the payload it carries
python3 "$ROOT/image/inspect-installer-media.py" --raw "$RAW" \
  --expect-verity-root-hash "$(printf 'other' | sha256sum | awk '{print $1}')" \
  >/dev/null 2>&1 && fail "a medium sealing another root hash was accepted"

# (b) and (c): a medium sealed to another access profile or another machine
inspect --expect-access-profile customer-locked >/dev/null 2>&1 \
  && fail "a medium sealed to another access profile was accepted"
inspect --expect-hardware-target some-other-box >/dev/null 2>&1 \
  && fail "a medium sealed to another hardware target was accepted"

# (d) no partition the initramfs can find the sealed payload by
rm -f "$RAW"; truncate -s $(( 96 + PAYLOAD_MIB ))M "$RAW"
sgdisk --clear --new=1:2048:+64M --typecode=1:EF00 --change-name=1:EFI-SYSTEM \
  --new=2:0:0 --typecode=2:8300 --change-name=2:somethingelse "$RAW" >/dev/null
dd if="$ESP" of="$RAW" bs=512 seek=2048 conv=notrunc status=none
inspect >/dev/null 2>&1 && fail "a medium with no ni-installer-payload partition was accepted"
assemble "$ESP" "$SEALED/payload.img"

# (e) A LIVE UKI ON AN INSTALL MEDIUM. The mode is a property of the signature;
#     swapping the binary under an Install manifest must not produce an Install
#     medium.
make_esp "$SEALED/installer-live.efi" "$SEALED/installer-install.efi.manifest" \
  installer-install.efi.manifest
assemble "$ESP" "$SEALED/payload.img"
inspect >/dev/null 2>&1 \
  && fail "a medium whose BOOTAA64.EFI seals no autoinstall karg was accepted as an Install medium"
# ...and the same binary under its OWN manifest is a perfectly good LIVE medium.
make_esp "$SEALED/installer-live.efi" "$SEALED/installer-live.efi.manifest" \
  installer-live.efi.manifest
assemble "$ESP" "$SEALED/payload.img"
inspect --expect-mode live >/dev/null || fail "a correct Live medium was refused"
inspect >/dev/null 2>&1 && fail "a Live medium was accepted where an Install medium was expected"
make_esp "$SEALED/installer-install.efi" "$SEALED/installer-install.efi.manifest" \
  installer-install.efi.manifest
assemble "$ESP" "$SEALED/payload.img"

# (e2) Install mode must select exactly the dedicated fail-closed target.  An
# appliance target or duplicated selector must not be accepted merely because
# neuralice.autoinstall=1 is also signed.
build_uki installer-wrong-target \
  "quiet systemd.unit=multi-user.target neuralice.autoinstall=1" >/dev/null \
  || fail "the wrong-target mutation UKI failed to build"
make_esp "$SEALED/installer-wrong-target.efi" \
  "$SEALED/installer-wrong-target.efi.manifest" installer-install.efi.manifest
assemble "$ESP" "$SEALED/payload.img"
inspect >/dev/null 2>&1 \
  && fail "an Install medium selecting multi-user.target was accepted"
build_uki installer-duplicate-target \
  "quiet systemd.unit=neural-ice-installer.target systemd.unit=multi-user.target neuralice.autoinstall=1" \
  >/dev/null || fail "the duplicate-target mutation UKI failed to build"
make_esp "$SEALED/installer-duplicate-target.efi" \
  "$SEALED/installer-duplicate-target.efi.manifest" installer-install.efi.manifest
assemble "$ESP" "$SEALED/payload.img"
inspect >/dev/null 2>&1 \
  && fail "an Install medium with duplicate systemd.unit selectors was accepted"
make_esp "$SEALED/installer-install.efi" "$SEALED/installer-install.efi.manifest" \
  installer-install.efi.manifest
assemble "$ESP" "$SEALED/payload.img"

# (f) an UNSIGNED UKI on the medium
env NI_UKI_TESTING=1 NI_UKI_TEST_TOOLS="$TOOLS" \
  KERNEL="$IN/vmlinuz" INITRD="$IN/initrd" STUB="$IN/stub.efi" OSREL="$IN/os-release" \
  ROOT_VERITY_HASH="$ROOT_HASH" PAYLOAD_DIGEST="$PAYLOAD_DIGEST" \
  VARIANT=sealed-lab HARDWARE_TARGET=nvidia-gb10-arm64 \
  HARDWARE_IDENTITY_FILE="$IN/gb10.fingerprints" \
  TRUST_POLICY_ID="$POLICY_ID" TRUST_POLICY_ROOT="$POLICY_ROOT" \
  RELEASE_AUTH_PUBKEY="$IN/relauth.pub" \
  UKI_OUT="$SEALED/unsigned.efi" \
  EXTRA_KARGS="quiet systemd.unit=neural-ice-installer.target neuralice.autoinstall=1" \
  bash "$ROOT/image/build-installer-uki.sh" >/dev/null || fail "the unsigned build failed"
make_esp "$SEALED/unsigned.efi" "$SEALED/installer-install.efi.manifest" \
  installer-install.efi.manifest
assemble "$ESP" "$SEALED/payload.img"
inspect >/dev/null 2>&1 && fail "a medium carrying an unsigned UKI was accepted"
make_esp "$SEALED/installer-install.efi" "$SEALED/installer-install.efi.manifest" \
  installer-install.efi.manifest
assemble "$ESP" "$SEALED/payload.img"

# --------------------------------------------------------------------------- #
# (g) 🔴 A SECOND EFI AUTHORITY. This is P0 #2 in one assertion: the previous
#     medium kept GRUB, a shim, a fallback binary and a standalone kernel, and
#     the argument for that was a claim about a generated grub.cfg rather than
#     about the medium. Anything on the ESP that is not the one signed UKI and
#     its manifest is now a refusal, whatever it is called.
# --------------------------------------------------------------------------- #
for intruder in 'EFI/BOOT/grubaa64.efi' 'EFI/redhat/shimaa64.efi' 'EFI/BOOT/BOOTAA64.CSV'; do
  make_esp "$SEALED/installer-install.efi" "$SEALED/installer-install.efi.manifest" \
    installer-install.efi.manifest
  dir="${intruder%/*}"
  [ "$dir" = "EFI/BOOT" ] || mmd -i "$ESP" "::/$dir"
  mcopy -i "$ESP" "$SEALED/installer-live.efi" "::/$intruder"
  assemble "$ESP" "$SEALED/payload.img"
  inspect >/dev/null 2>&1 \
    && fail "a medium carrying a second EFI file ($intruder) was accepted"
done
# A grub.cfg is not an EFI binary and is just as dangerous: it is a boot
# manager's instructions.
make_esp "$SEALED/installer-install.efi" "$SEALED/installer-install.efi.manifest" \
  installer-install.efi.manifest
printf 'linux /vmlinuz neuralice.autoinstall=1\n' > "$TMP/grub.cfg"
mmd -i "$ESP" '::/EFI/redhat'
mcopy -i "$ESP" "$TMP/grub.cfg" '::/EFI/redhat/grub.cfg'
assemble "$ESP" "$SEALED/payload.img"
inspect >/dev/null 2>&1 && fail "a medium carrying a boot-manager configuration was accepted"
make_esp "$SEALED/installer-install.efi" "$SEALED/installer-install.efi.manifest" \
  installer-install.efi.manifest

# --------------------------------------------------------------------------- #
# (h) A SURVIVING BOOT PARTITION. bib writes a kernel, an initramfs and BLS
#     entries; the producer OVERWRITES that partition rather than deleting files,
#     because deleted files leave their bytes. Prove the inspector notices.
# --------------------------------------------------------------------------- #
assemble "$ESP" "$SEALED/payload.img" \
  "$(printf 'linux /ostree/vmlinuz-6.12 root=UUID=x neuralice.autoinstall=1\n')"
inspect >/dev/null 2>&1 \
  && fail "a medium whose emptied boot partition still carries a boot entry was accepted"
assemble "$ESP" "$SEALED/payload.img"

# --------------------------------------------------------------------------- #
# (i) A MUTATED PAYLOAD. One flipped byte in the container store — the bytes an
#     attacker actually wants to change, because they are what is written onto
#     the customer's disk.
# --------------------------------------------------------------------------- #
cp "$SEALED/payload.img" "$TMP/payload-mutated.img"
STORE_OFF="$(sed -n 's/^region\.store-image=offset:\([0-9]*\),.*/\1/p' "$PAYLOAD_MANIFEST")"
[ -n "$STORE_OFF" ] || fail "the payload manifest names no store-image offset"
printf '\xff' | dd of="$TMP/payload-mutated.img" bs=1 seek="$STORE_OFF" conv=notrunc status=none
assemble "$ESP" "$TMP/payload-mutated.img"
inspect >/dev/null 2>&1 && fail "a medium whose sealed container store was modified was accepted"

# ...and one flipped byte in a HASH TREE. dm-verity reads the tree at runtime, so
# a corrupted tree is a medium that panics mid-install; and because the tree is
# not data the Merkle recomputation ever reads, only the header's own region
# digest can see it. That is why the inspector hashes every region AND recomputes
# the roots, rather than treating either as sufficient.
cp "$SEALED/payload.img" "$TMP/payload-tree-mutated.img"
TREE_OFF="$(sed -n 's/^region\.store-hash=offset:\([0-9]*\),.*/\1/p' "$PAYLOAD_MANIFEST")"
[ -n "$TREE_OFF" ] || fail "the payload manifest names no store-hash offset"
printf '\xff' | dd of="$TMP/payload-tree-mutated.img" bs=1 seek="$TREE_OFF" conv=notrunc status=none
assemble "$ESP" "$TMP/payload-tree-mutated.img"
inspect >/dev/null 2>&1 \
  && fail "a medium whose sealed dm-verity hash tree was modified was accepted"
assemble "$ESP" "$SEALED/payload.img"

# (j) A PAYLOAD THE SIGNATURE DOES NOT NAME. The header is authentic and
#     self-consistent; it is simply not the one the UKI seals.
env ROOT_IMAGE="$IN/root.img" STORE_IMAGE="$IN/root.img" \
  PAYLOAD_OUT="$TMP/other-payload.img" bash "$ROOT/image/build-installer-payload.sh" >/dev/null \
  || fail "the second payload assembly failed"
assemble "$ESP" "$TMP/other-payload.img"
inspect >/dev/null 2>&1 \
  && fail "a self-consistent payload the signed UKI does not name was accepted"
# ...and WITHOUT the build-side `--expect-payload-digest`, because a medium in the
# field is inspected against its own signature and nothing else. This is the
# assertion that makes the header<->UKI binding load-bearing rather than a second
# copy of a command-line argument.
python3 "$ROOT/image/inspect-installer-media.py" --raw "$RAW" \
  --expect-verity-root-hash "$ROOT_HASH" --expect-mode install >/dev/null 2>&1 \
  && fail "a payload the signed UKI does not name was accepted on the signature alone"
assemble "$ESP" "$SEALED/payload.img"
inspect >/dev/null || fail "the restored correct medium was refused"
python3 "$ROOT/image/inspect-installer-media.py" --raw "$RAW" \
  --expect-verity-root-hash "$ROOT_HASH" --expect-mode install >/dev/null \
  || fail "the correct medium was refused when judged against its signature alone"

# (k) A HEADER THAT LIES ABOUT ITS OWN VERITY ROOT. Every region hashes to what
#     the header records, the header hashes to what the UKI seals — and the
#     dm-verity root hash it carries is not the one those bytes produce. Only a
#     from-scratch recomputation off the medium can see it, which is why the
#     inspector does one instead of trusting the hash tree that ships beside the
#     data.
python3 - "$SEALED/payload.img" "$TMP/lying-payload.img" <<'PYEOF'
import sys
data = bytearray(open(sys.argv[1], "rb").read())
header = bytes(data[:4096]).rstrip(b"\x00").decode("ascii")
lines = []
for line in header.splitlines():
    if line.startswith("store_verity_hash="):
        line = "store_verity_hash=" + "b" * 64
    lines.append(line)
new = "\n".join(lines).encode("ascii")
assert len(new) < 4096
data[:4096] = new.ljust(4096, b"\x00")
open(sys.argv[2], "wb").write(bytes(data))
PYEOF
LYING_DIGEST="$(python3 -c '
import hashlib, sys
print(hashlib.sha256(open(sys.argv[1], "rb").read(4096).rstrip(b"\x00")).hexdigest())
' "$TMP/lying-payload.img")"
build_uki installer-lying \
  "quiet systemd.unit=neural-ice-installer.target neuralice.autoinstall=1" \
  PAYLOAD_DIGEST="$LYING_DIGEST" \
  >/dev/null || fail "the UKI sealing the forged header failed to build"
make_esp "$SEALED/installer-lying.efi" "$SEALED/installer-lying.efi.manifest" \
  installer-install.efi.manifest
assemble "$ESP" "$TMP/lying-payload.img"
python3 "$ROOT/image/inspect-installer-media.py" --raw "$RAW" \
  --expect-verity-root-hash "$ROOT_HASH" --expect-mode install >/dev/null 2>&1 \
  && fail "a header claiming a dm-verity root hash its data does not produce was accepted"
make_esp "$SEALED/installer-install.efi" "$SEALED/installer-install.efi.manifest" \
  installer-install.efi.manifest
assemble "$ESP" "$SEALED/payload.img"
inspect >/dev/null || fail "the restored correct medium was refused"

# --------------------------------------------------------------------------- #
# 6) THE PRODUCER MUST ACTUALLY DO ALL OF THIS. A perfect implementation that
#    nothing invokes is what the review found the first time.
# --------------------------------------------------------------------------- #
USB="$ROOT/image/build-installer-usb.sh"
grep -Fq 'image/build-installer-uki.sh' "$USB" || fail "the media producer does not build a UKI"
grep -Fq 'image/build-installer-root.sh' "$USB" \
  || fail "the media producer does not build the sealed installer root"
grep -Fq 'image/build-installer-payload.sh' "$USB" \
  || fail "the media producer does not assemble the sealed payload"
grep -Fq 'image/inspect-installer-media.py' "$USB" \
  || fail "the media producer does not inspect the medium it produced"
grep -Fq 'EFI/BOOT/BOOTAA64.EFI' "$USB" \
  || fail "the media producer does not install the signed UKI as the removable-media default path"
grep -Fq 'ni-installer-payload' "$USB" \
  || fail "the media producer does not name the partition the initramfs looks the payload up by"

# 🔴 THE BOOT AUTHORITY IS GONE, not merely reconfigured (review 2026-09-01,
# P0 #2). No grub.cfg is written, nothing is chainloaded, and the partitions bib
# wrote a bootloader and a kernel onto are OVERWRITTEN.
if grep -vE '^[[:space:]]*#' "$USB" | grep -Eq 'chainloader|menuentry|grub\.cfg|loader/entries'; then
  fail "the media producer still writes or configures a boot manager"
fi
grep -Fq 'zero_partition "$BOOTPART"' "$USB" \
  || fail "the media producer does not overwrite the boot partition bib wrote a kernel onto"
grep -Fq 'mkfs.fat -F32 -n EFI-SYSTEM "$ESPPART"' "$USB" \
  || fail "the media producer does not remake the ESP from scratch"
grep -Fq 'zero_partition "$ESPPART"' "$USB" \
  || fail "the media producer does not overwrite the ESP before remaking it; deleted files leave their bytes"
grep -Fq 'MEDIA_MODE' "$USB" \
  || fail "the media producer does not build a single-purpose medium"
grep -Fq 'systemd.unit=neural-ice-installer.target' "$USB" \
  || fail "the media producer does not seal the dedicated fail-closed installer target"

HOOK="$ROOT/image/initramfs/90neural-ice-installer-verity/neural-ice-installer-verity.sh"
[ -f "$HOOK" ] || fail "there is no initramfs hook to open the sealed payload"
grep -Fq 'veritysetup open' "$HOOK" || fail "the initramfs hook does not open the verity targets"
grep -Fq 'neuralice-installer-root' "$HOOK" || fail "the initramfs hook opens the wrong root mapper"
grep -Fq 'neuralice-installer-store' "$HOOK" \
  || fail "the initramfs hook does not open the sealed image store"
grep -Fq -- '--panic-on-corruption' "$HOOK" \
  || fail "the initramfs hook activates verity without panicking on corruption"
grep -Fq 'the sealed anchor may be shadowed' "$HOOK" \
  || fail "the initramfs hook does not refuse a duplicated sealed karg"
grep -Fq 'mount -t overlay' "$HOOK" \
  || fail "the initramfs hook does not build a writable runtime over the verified root"
grep -Fq 'mount -t tmpfs' "$HOOK" \
  || fail "the writable runtime is not a tmpfs, so it is not empty at every boot"
grep -Fq 'NI_RW_OPTIONS="size=' "$HOOK" \
  || fail "the writable runtime tmpfs is unbounded"
# --------------------------------------------------------------------------- #
# 6b) THE PRELOADED FINALIZATION (review 2026-09-01, P1 #4).
#
# 🔴 THE FINDING. This suite's inspection -- and the one build-installer-usb.sh
# runs -- happens on the LIGHT raw. `image/build-preloaded.sh` then keeps WRITING
# to that same file: it grows it, relocates the GPT backup header, rewrites the
# partition table, attaches it WRITABLE and copies ~20 GB of seed into a new
# `ni-seed` partition. The final acceptance gate re-checked the seed tree and the
# ESP handoffs and NOTHING ELSE -- not BOOTAA64.EFI, not the payload region
# hashes, not the ESP allowlist, not the zeroed partitions. So the receipt and
# the checksum could bless a raw whose sealed core changed after its only
# inspection.
#
# The gate therefore runs the FULL inspector on the FINISHED raw, through the
# very descriptor it holds its exclusive lock on. What follows drives that exact
# function -- imported from image/verify-preloaded-media.py, not reimplemented --
# over a medium finished the way build-preloaded.sh finishes one.
# --------------------------------------------------------------------------- #
SEALED_CMDLINE="$(sed -n 's/^cmdline=//p' "$SEALED/installer-install.efi.manifest")"
[ -n "$SEALED_CMDLINE" ] || fail "the Install UKI manifest records no cmdline"
PRELOADED="$TMP/preloaded.img"
finish_preloaded() { # turn the freshly assembled $RAW into a PRELOADED-shaped raw
  cp "$RAW" "$PRELOADED"
  truncate -s "+32M" "$PRELOADED"
  sgdisk -e "$PRELOADED" >/dev/null
  sgdisk -n 0:0:0 -c 0:ni-seed -t 0:8300 "$PRELOADED" >/dev/null
  sgdisk -p "$PRELOADED" | grep -q 'ni-seed' || fail "the ni-seed partition was not appended"
}
# The gate's OWN function, over the gate's OWN lock. Importing it is the point: a
# paraphrase here would pass while the shipped gate did something else.
finalize() { # -> 0 when the finished raw's sealed core is accepted
  python3 - "$ROOT/image/verify-preloaded-media.py" "$PRELOADED" \
    "$ROOT_HASH" "$PAYLOAD_DIGEST" "$POLICY_ID" <<'PYFINAL'
import fcntl
import importlib.util
import os
import sys
import types

gate_path, raw, root_hash, payload_digest, policy_id = sys.argv[1:]
spec = importlib.util.spec_from_file_location("ni_final_media_gate", gate_path)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

descriptor = os.open(raw, os.O_RDONLY)
try:
    # The same exclusive lock the gate takes on the raw before it inspects or
    # publishes anything: the inspection below reads through THIS descriptor.
    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    arguments = types.SimpleNamespace(
        expect_verity_root_hash=root_hash,
        expect_payload_digest=payload_digest,
        expect_mode="install",
        expect_access_profile="lab-managed",
        expect_hardware_target="nvidia-gb10-arm64",
        expect_trust_policy_id=policy_id,
        allow_unsigned=False,
    )
    gate.inspect_sealed_core(descriptor, arguments)
except gate.GateError as error:
    print(f"REFUSED: {error}", file=sys.stderr)
    raise SystemExit(1)
finally:
    os.close(descriptor)
PYFINAL
}

assemble "$ESP" "$SEALED/payload.img"
finish_preloaded
finalize >/dev/null 2>"$TMP/finalize.err" \
  || { cat "$TMP/finalize.err" >&2; fail "a correctly finished PRELOADED raw was refused"; }

# (a) THE SIGNED UKI, MUTATED AFTER THE SEED PHASE. One byte of the sealed
#     .cmdline on the finished raw -- the exact window the finding is about,
#     because build-preloaded.sh has the file open for writing after the only
#     inspection that used to happen.
python3 - "$PRELOADED" "$SEALED_CMDLINE" <<'PYMUT'
import sys

raw, cmdline = sys.argv[1], sys.argv[2].encode("ascii")
with open(raw, "r+b") as handle:
    blob = handle.read()
    offset = blob.find(cmdline)
    if offset < 0:
        raise SystemExit("the sealed cmdline is not on the medium; this mutation proves nothing")
    handle.seek(offset + len(cmdline) - 1)
    handle.write(bytes([blob[offset + len(cmdline) - 1] ^ 0x01]))
PYMUT
finalize >/dev/null 2>&1 \
  && fail "a finished raw whose signed UKI cmdline was modified after the seed phase was accepted"

# (b) THE SEALED PAYLOAD, MUTATED AFTER THE SEED PHASE. dm-verity protects the
#     regions at RUN time; nothing protected them between the light inspection
#     and publication.
assemble "$ESP" "$SEALED/payload.img"
finish_preloaded
python3 - "$PRELOADED" <<'PYMUT'
import struct
import sys

raw = sys.argv[1]
with open(raw, "rb") as handle:
    handle.seek(512)
    header = handle.read(512)
signature, = struct.unpack_from("<8s", header, 0)
if signature != b"EFI PART":
    raise SystemExit("the fixture has no GPT at LBA 1")
entries_lba, = struct.unpack_from("<Q", header, 72)
count, size = struct.unpack_from("<II", header, 80)
start = None
with open(raw, "rb") as handle:
    handle.seek(entries_lba * 512)
    for _ in range(count):
        entry = handle.read(size)
        name = entry[56:128].decode("utf-16-le").rstrip("\x00")
        if name == "ni-installer-payload":
            start, = struct.unpack_from("<Q", entry, 32)
            break
if start is None:
    raise SystemExit("the fixture carries no ni-installer-payload partition")
# The first byte of the first REGION, i.e. past the 4096-byte header: a region
# whose bytes changed must fail its recorded sha256 and its recomputed verity
# root hash, which is the statement a manifest can never make.
offset = start * 512 + 4096
with open(raw, "r+b") as handle:
    handle.seek(offset)
    original = handle.read(1)
    handle.seek(offset)
    handle.write(bytes([original[0] ^ 0xFF]))
PYMUT
finalize >/dev/null 2>&1 \
  && fail "a finished raw whose sealed payload was modified after the seed phase was accepted"

# (c) A PARTITION THAT IS NO LONGER ZERO. The medium's old boot partition is
#     OVERWRITTEN, not deleted; anything written back into it after the seed
#     phase is a boot authority nothing signed.
assemble "$ESP" "$SEALED/payload.img" "vmlinuz-leftover"
finish_preloaded
finalize >/dev/null 2>&1 \
  && fail "a finished raw carrying a non-empty void partition was accepted"

# ...and the honest medium is still accepted, so (a)-(c) are about the mutations
# and not about the finishing step itself.
assemble "$ESP" "$SEALED/payload.img"
finish_preloaded
finalize >/dev/null 2>&1 || fail "the restored PRELOADED fixture was refused"

# --------------------------------------------------------------------------- #
# 6c) AND THE GATE MUST ACTUALLY RUN IT, IN THE RIGHT PLACE. A function nothing
#     calls, or one called after the receipt is written, closes nothing.
# --------------------------------------------------------------------------- #
GATE="$ROOT/image/verify-preloaded-media.py"
gate_line() { grep -nF -- "$1" "$GATE" | head -1 | cut -d: -f1; }
inspect_line="$(gate_line 'sealed_core = inspect_sealed_core(descriptor, arguments)')"
[ -n "$inspect_line" ] || fail "the final-media gate never inspects the sealed core"
# The four things this gate PUBLISHES, each matched by a line that appears
# exactly once: the release artifact, its checksum, the receipt and the receipt's
# checksum. Every one of them must come after the sealed core has been inspected.
for published in 'artifact = build_artifact(' 'str(artifact["sha256"]),' \
  'publish_bytes_noreplace(arguments.receipt, receipt_bytes)' \
  'hashlib.sha256(receipt_bytes).hexdigest(),'; do
  publish_line="$(gate_line "$published")"
  [ -n "$publish_line" ] || fail "cannot locate the gate's publication step: $published"
  [ "$inspect_line" -lt "$publish_line" ] \
    || fail "the sealed core is inspected at line $inspect_line, AFTER '$published' at line $publish_line"
done
# The inspection reads through the LOCKED DESCRIPTOR, not through a path that
# could be replaced between the lock and the read.
grep -Fq 'f"/proc/self/fd/{descriptor}"' "$GATE" \
  || fail "the sealed-core inspection does not read through the gate's own locked descriptor"
grep -Fq 'pass_fds=(descriptor,)' "$GATE" \
  || fail "the sealed-core inspection does not pass its locked descriptor to the inspector"

# The sealed-core expectations are REQUIRED. A final gate that can be invoked
# without them is a gate that can be invoked without inspecting anything.
python3 "$GATE" --raw "$PRELOADED" --expected-manifest "$TMP/none.json" \
  --artifact "$TMP/none.art" --artifact-checksum "$TMP/none.sha256" --compression none \
  --receipt "$TMP/none.receipt" --receipt-checksum "$TMP/none.receipt.sha256" \
  >/dev/null 2>&1 \
  && fail "the final-media gate ran with no sealed-core expectations at all"

# ...and the PRELOADED build must hand them over rather than invent them: they
# are produced by the build that SEALED them, carried in a file beside the raw.
PRELOADED_BUILD="$ROOT/image/build-preloaded.sh"
grep -Fq 'SEALED_CORE_FACTS="${RAW}.sealed-core.json"' "$PRELOADED_BUILD" \
  || fail "the PRELOADED build reads no sealed-core facts from the base media build"
grep -Fq '"${SEALED_CORE_ARGS[@]}"' "$PRELOADED_BUILD" \
  || fail "the PRELOADED build does not forward the sealed-core expectations to the final gate"
grep -Fq 'neural-ice-sealed-core-facts-v1' "$ROOT/image/build-installer-usb.sh" \
  || fail "the media build declares no sealed-core facts for the PRELOADED build to check against"

# --------------------------------------------------------------------------- #
# 7) THE INITRAMFS HOOKS, EXECUTED. Everything above about them is a source-text
#    assertion, which cannot tell a removed control from a surviving message.
#    These two hooks are pure shell up to the point where they touch a device, so
#    the refusals that decide what `/` IS are driven against a fixture command
#    line instead of being greped for.
# --------------------------------------------------------------------------- #
CMDLINE_HOOK="$ROOT/image/initramfs/90neural-ice-installer-verity/neural-ice-installer-verity-cmdline.sh"
VERITY_HOOK="$HOOK"

hook_cmdline() { # $1=hook  $2=command line text  -> runs it against a fixture
  printf '%s\n' "$2" > "$TMP/fixture-cmdline"
  env NEURAL_ICE_INITRAMFS_TESTING=1 \
    NEURAL_ICE_INITRAMFS_TEST_CMDLINE="$TMP/fixture-cmdline" \
    sh -c ". '$1'; printf 'root=%s rootok=%s\n' \"\${root:-}\" \"\${rootok:-}\""
}

# The sealed command line, as the medium actually carries it: the hook takes the
# root away from dracut and hands it to the module that verifies it.
out="$(hook_cmdline "$CMDLINE_HOOK" "$SEALED_CMDLINE" 2>&1)" \
  || fail "the cmdline hook refused the medium's own sealed command line: $out"
grep -Fq 'root=neuralice:sealed-installer-root rootok=1' <<<"$out" \
  || fail "the cmdline hook does not point dracut at this module's root: $out"

# 🔴 AN EXTERNALLY SUPPLIED root=. With Secure Boot off, systemd-stub concatenates
# an attacker's command line onto the sealed one; appending this made dracut mount
# an attacker's root and never touch dm-verity. It must be a refusal, not a
# default that yields.
hook_cmdline "$CMDLINE_HOOK" "$SEALED_CMDLINE root=/dev/sda2" >/dev/null 2>&1 \
  && fail "an externally supplied root= can still steer this initramfs"
hook_cmdline "$CMDLINE_HOOK" "root=LABEL=anything $SEALED_CMDLINE" >/dev/null 2>&1 \
  && fail "a root= placed BEFORE the sealed anchor can still steer this initramfs"

# The override that makes this testable must never be a runtime bypass: an
# initramfs runs as root, and there the fixture is refused outright. Assert the
# REFUSAL by its words -- "it exited non-zero" would also be satisfied by the
# hook reading this host's real /proc/cmdline and finding a root= there.
printf '%s\n' "$SEALED_CMDLINE" > "$TMP/fixture-cmdline"
out="$(env NEURAL_ICE_INITRAMFS_TEST_CMDLINE="$TMP/fixture-cmdline" sh "$CMDLINE_HOOK" 2>&1)" \
  && fail "the cmdline override worked without the test-harness flag"
grep -Fq 'a command-line override is forbidden in a privileged process' <<<"$out" \
  || fail "the cmdline override was not refused as an override: $out"

# The PRE-MOUNT hook refuses a shadowed sealed key before it looks at any device.
verity_hook() { # $1=command line text
  printf '%s\n' "$1" > "$TMP/fixture-cmdline"
  env NEURAL_ICE_INITRAMFS_TESTING=1 \
    NEURAL_ICE_INITRAMFS_TEST_CMDLINE="$TMP/fixture-cmdline" \
    NI_TEST_LIB="$ROOT/image/lib/installer-payload.sh" \
    sh -c 'sed "s#^\. /lib/neural-ice-installer-payload.sh#. $NI_TEST_LIB#" "$1" > "$2"; sh "$2"' \
    _ "$VERITY_HOOK" "$TMP/verity-hook-under-test.sh"
}
out="$(verity_hook "$SEALED_CMDLINE $SEALED_CMDLINE" 2>&1)" \
  && fail "a command line carrying every sealed key twice was accepted"
grep -Fq 'the sealed anchor may be shadowed' <<<"$out" \
  || fail "a shadowed sealed anchor was refused for the wrong reason: $out"
out="$(verity_hook "quiet" 2>&1)" \
  && fail "a command line carrying no sealed anchor was accepted"
grep -Fq 'occurrences of neuralice.trust' <<<"$out" \
  || fail "an absent sealed anchor was refused for the wrong reason: $out"
out="$(verity_hook "neuralice.trust=neural-ice-installer-trust-v1 neuralice.rootverity=deadbeef neuralice.payload=$PAYLOAD_DIGEST" 2>&1)" \
  && fail "a malformed sealed verity root hash was accepted"
grep -Fq 'malformed' <<<"$out" \
  || fail "a malformed root hash was refused for the wrong reason: $out"

# 🔴 THE BREADCRUMB THE INSTALLER LIVES ON (review 2026-09-01, P0 #1). After
# switch-root the installer cannot ask `findmnt /` which disk it booted from --
# `/` is the overlay this hook mounts. It reads what the hook recorded instead,
# so the hook must record a RESOLVED device node and the device number sysfs
# reports for it, not the udev by-partlabel symlink it looked the partition up
# by. A symlink can be repointed at a second medium between here and there.
hook_code() { grep -vE '^[[:space:]]*#' "$VERITY_HOOK"; }
hook_code | grep -Fq 'NI_PAYLOAD_NODE="$(readlink -f "$NI_PAYLOAD_DEV"' \
  || fail "the initramfs hook records the by-partlabel symlink instead of the resolved payload node"
hook_code | grep -Fq 'printf '"'"'%s\n'"'"' "$NI_PAYLOAD_NODE" > "$NI_STATE/payload-device"' \
  || fail "the initramfs hook does not record the resolved payload device"
hook_code | grep -Fq '> "$NI_STATE/payload-device-devno"' \
  || fail "the initramfs hook does not record the payload device number"
hook_code | grep -Fq '/sys/class/block/$NI_PAYLOAD_KNAME/partition' \
  || fail "the initramfs hook does not require the payload device to be a partition"

echo "INSTALLER_MEDIA_TEST_OK"
