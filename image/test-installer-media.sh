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

# FAT is case-insensitive and may enumerate an 8.3 directory in uppercase.
# Canonicalise only known allowlisted paths, and never let a second spelling
# choose which entry the inspector reads. This pure check runs even when the
# host lacks the real media toolchain used below.
python3 - "$ROOT/image/inspect-installer-media.py" <<'PYEOF'
import importlib.util, os, pathlib, stat, sys, tempfile
spec = importlib.util.spec_from_file_location("media_inspector", pathlib.Path(sys.argv[1]))
module = importlib.util.module_from_spec(spec)
assert spec.loader
spec.loader.exec_module(module)
expected_bounds = {
    "ice-coreos/preseal/preseal-set.json": 16 * 1024,
    "ice-coreos/preseal/delegation-snapshot.json": 16 * 1024,
    "ice-coreos/preseal/delegation-snapshot.sig": 1024,
    "ice-coreos/preseal/ota-release-authorization.json": 64 * 1024,
    "ice-coreos/preseal/ota-release-authorization.sig": 1024,
    "ice-coreos/preseal/bom.json": 128 * 1024,
}
assert module.PRESEAL_FILES == expected_bounds
paths = module.canonical_esp_paths([
    "EFI/BOOT/BOOTAA64.EFI", "ice-coreos/PRESEAL/bom.json", "FOREIGN/PATH",
    "EFI/NEURAL-ICE/INSTALLER-INSTALL.EFI.MANIFEST",
])
assert "ice-coreos/preseal/bom.json" in paths
assert "EFI/neural-ice/installer-install.efi.manifest" in paths
assert "FOREIGN/PATH" in paths
try:
    module.canonical_esp_paths([
        "ice-coreos/preseal/bom.json", "ICE-COREOS/PRESEAL/BOM.JSON",
    ])
except module.InspectionError:
    pass
else:
    raise SystemExit("case-insensitive FAT aliases were accepted")

# The create-new publisher's retry proves the retained inode and fsyncs that
# file before its directory. This pure transaction check stays active on hosts
# that lack the real media toolchain used by the rest of the suite.
with tempfile.TemporaryDirectory(prefix="ni-measurements-") as scratch_name:
    scratch = pathlib.Path(scratch_name)
    os.chmod(scratch, 0o700)
    raw_path = scratch / "raw"
    raw_path.write_bytes(b"raw")
    output = scratch / "measurements.json"
    document = module.measurements_document(
        "1" * 64,
        "2" * 64,
        "3" * 64,
        "neuralice.source=registry",
        {"neuralice.rootverity": "4" * 64, "neuralice.relauth_keyid": "5" * 64},
    )
    medium_document = module.measurements_document(
        "1" * 64,
        "2" * 64,
        "3" * 64,
        "neuralice.source=medium",
        {"neuralice.rootverity": "4" * 64, "neuralice.relauth_keyid": "5" * 64},
    )
    assert medium_document == document
    try:
        module.measurements_document(
            "1" * 64,
            "2" * 64,
            "3" * 64,
            "neuralice.autoinstall=1",
            {"neuralice.rootverity": "4" * 64, "neuralice.relauth_keyid": "5" * 64},
        )
    except module.InspectionError:
        pass
    else:
        raise SystemExit("a source-less Install medium emitted measurements")
    with module.PinnedRaw(raw_path) as pinned:
        module.publish_measurements(output, document, pinned)
    fsynced_types = []
    real_fsync = module.os.fsync
    def recording_fsync(descriptor):
        fsynced_types.append(stat.S_IFMT(os.fstat(descriptor).st_mode))
        return real_fsync(descriptor)
    module.os.fsync = recording_fsync
    with module.PinnedRaw(raw_path) as pinned:
        module.publish_measurements(output, document, pinned)
    module.os.fsync = real_fsync
    assert fsynced_types == [stat.S_IFREG, stat.S_IFDIR, stat.S_IFREG]

    inherited = os.open(raw_path, os.O_RDONLY)
    try:
        with module.PinnedRaw(pathlib.Path(f"/proc/self/fd/{inherited}")) as pinned:
            assert pinned.sha256() == module.hashlib.sha256(b"raw").hexdigest()
    finally:
        os.close(inherited)
    try:
        module.PinnedRaw(pathlib.Path("/proc/self/fd/999999"))
    except OSError:
        pass
    else:
        raise SystemExit("an absent inherited raw descriptor was accepted")
    raw_link = scratch / "raw-link"
    raw_link.symlink_to(raw_path.name)
    try:
        module.PinnedRaw(raw_link)
    except OSError:
        pass
    else:
        raise SystemExit("an arbitrary raw symlink was accepted")
    raw_fifo = scratch / "raw-fifo"
    os.mkfifo(raw_fifo)
    fifo_fd = os.open(raw_fifo, os.O_RDWR | os.O_NONBLOCK)
    try:
        try:
            module.PinnedRaw(pathlib.Path(f"/proc/self/fd/{fifo_fd}"))
        except module.InspectionError:
            pass
        else:
            raise SystemExit("a non-regular inherited raw descriptor was accepted")
    finally:
        os.close(fifo_fd)
PYEOF

# --------------------------------------------------------------------------- #
# 🔴 THE COMPOSED MEDIUM: A REGISTRY OS ROOT BESIDE THE SIGNED OFFLINE SEED.
#
# A LIGHT medium leaves the product images absent, and the private registry
# needs a licence to serve the very images onboarding needs -- so a fresh USB
# install could not reach first activation without a WAN. The seed already
# carries and verifies those images; what was missing was proof that the seed
# and the pulled appliance are ONE release. The sealed grammar now admits the
# pair only beside `neuralice.preseal`, and the two gates below are what make
# that admission safe:
#
#   producer   image/build-installer-usb.sh:seal_offline_seed_kargs -- refuses
#              to CUT a medium whose seed and preseal set disagree;
#   installer  ota/neural-ice-autoinstall.sh:assert_seed_is_the_preseal_release
#              -- refuses to INSTALL one, before the target disk is touched.
#
# Both are lifted verbatim, the way image/test-installer-selector-grammar.sh
# lifts the installer's own selector revalidation: the suite runs the SAME code
# the build host and the appliance run, not a paraphrase of it.
#
# This section needs bash, python3 and sha256sum only, so it lives ABOVE the
# sealed-medium fixture -- which `exit 0`s on a host without veritysetup. A
# reconciliation control that disappears with a fixture is a control nobody
# notices the loss of.
# --------------------------------------------------------------------------- #
COMPOSE="$TMP/compose"; mkdir -p "$COMPOSE"
AUTOINSTALL="$ROOT/ota/neural-ice-autoinstall.sh"
BUILDER="$ROOT/image/build-installer-usb.sh"
awk '/^assert_sealed_document_digest\(\) \{/,/^}$/' "$AUTOINSTALL"  > "$COMPOSE/reconcile.sh"
awk '/^seed_manifest_hash_from_closure\(\) \{/,/^}$/' "$AUTOINSTALL" >> "$COMPOSE/reconcile.sh"
awk '/^assert_seed_is_the_preseal_release\(\) \{/,/^}$/' "$AUTOINSTALL" >> "$COMPOSE/reconcile.sh"
grep -q '^seed_manifest_hash_from_closure()' "$COMPOSE/reconcile.sh" \
  || fail "the installer no longer derives the release manifest hash from the verified closure (FAB-0057 P1.1b, rule C)"
grep -q '^assert_seed_is_the_preseal_release()' "$COMPOSE/reconcile.sh" \
  || fail "the installer no longer reconciles the offline seed with the preseal release"
grep -q 'SEED_PRESEAL_RECONCILE_PY' "$COMPOSE/reconcile.sh" \
  || fail "the installer's seed reconciliation lost its bounded document reader"
awk '/^seal_offline_seed_kargs\(\) \{/,/^}$/' "$BUILDER" > "$COMPOSE/seal.sh"
grep -q '^seal_offline_seed_kargs()' "$COMPOSE/seal.sh" \
  || fail "the producer no longer has one seed-sealing path for both install sources"

# 🔴 AND IT IS ON THE PATH, BEFORE THE WIPE. A reconciliation that runs after
# `wipefs` cannot mean "leave the machine as it was" -- which is the whole point
# of doing it at all. Asserted by line number against the installer's own first
# destructive command, exactly as the selector suite asserts its gate.
compose_call_line="$(grep -n '^    assert_seed_is_the_preseal_release$' "$AUTOINSTALL" | head -1 | cut -d: -f1)"
compose_verify_line="$(grep -nF '  "$NEURALICE_SEED_VERIFIER" verify-seed-closure' "$AUTOINSTALL" | head -1 | cut -d: -f1)"
compose_write_line="$(grep -nE '^[[:space:]]*(wipefs|sfdisk|mkfs\.|cryptsetup luksFormat) ' "$AUTOINSTALL" | head -1 | cut -d: -f1)"
{ [ -n "$compose_call_line" ] && [ -n "$compose_verify_line" ] && [ -n "$compose_write_line" ]; } \
  || fail "cannot locate the seed verification, its reconciliation or the first mutation; the ordering assertion would be vacuous"
[ "$compose_verify_line" -lt "$compose_call_line" ] \
  || fail "the installer reconciles the seed (line $compose_call_line) before verifying its signed closure (line $compose_verify_line)"
[ "$compose_call_line" -lt "$compose_write_line" ] \
  || fail "the installer mutates the target disk (line $compose_write_line) before reconciling the offline seed (line $compose_call_line)"

COMPOSE_OS_REPOSITORY="release.example.test/neural-ice/neural-ice-appliance"
COMPOSE_OS_DIGEST="sha256:$(printf '%064d' 42)"
COMPOSE_OS_IMAGE="$COMPOSE_OS_REPOSITORY@$COMPOSE_OS_DIGEST"

# One release, written three times the way Fabric writes it: the closure, the
# release manifest whose `host.digest` the closure's `host_digest` is derived
# from, and the UKI-bound preseal set. `overrides` is a JSON object applied to
# exactly one of them, which is how each negative case below states its one
# difference and nothing else.
compose_fixture() { # $1=destination $2=document $3=overrides-json
  python3 - "$1" "$2" "$3" "$COMPOSE_OS_REPOSITORY" "$COMPOSE_OS_DIGEST" <<'PYEOF'
import hashlib
import json
import pathlib
import sys

destination, document, overrides, repository, digest = sys.argv[1:]
root = pathlib.Path(destination)
seed = root / "seed"
preseal = root / "preseal"
seed.mkdir(parents=True, exist_ok=True)
preseal.mkdir(parents=True, exist_ok=True)

closure = {
    "boot_trust_profile": "neural-ice-secureboot-lab-v1",
    "bundle_seq": 13,
    "hardware_target": "nvidia-gb10-arm64",
    "host_digest": digest,
    "release_id": "release-1-0-0",
    "schema": "neural-ice-oci-release-closure-v1",
    "train": "1.0.0",
}
manifest = {
    "bundle_seq": 13,
    "hardware_target": "nvidia-gb10-arm64",
    "host": {"digest": digest, "repository": repository},
    "release_id": "release-1-0-0",
    "schema": "neural-ice-release-manifest-v1",
}
preseal_set = {
    "bundle_seq": 13,
    "hardware_target": "nvidia-gb10-arm64",
    "ring": "lab",
    "schema": "neural-ice-installer-preseal-set-v1",
    "signed_boot_trust_policy_id": "neural-ice-secureboot-lab-v1",
    "target_os_ref": f"{repository}@{digest}",
    "train": "1.0.0",
}
documents = {"closure": closure, "manifest": manifest, "preseal": preseal_set}
if document != "none":
    documents[document].update(json.loads(overrides))
manifest_raw = json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n"
# The closure names its release manifest by hash, as Fabric's does; the
# installer derives the expected manifest hash from it (rule C). An override
# that sets the field explicitly is a mismatch case and is kept as stated.
closure.setdefault("release_manifest_sha256", hashlib.sha256(manifest_raw.encode("utf-8")).hexdigest())
(seed / "release-closure.json").write_text(
    json.dumps(closure, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
(seed / "release-manifest.json").write_text(manifest_raw, encoding="utf-8")
(preseal / "preseal-set.json").write_text(
    json.dumps(preseal_set, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
PYEOF
}

# The sealed hashes are the REAL hashes of the produced documents, so a negative
# case fails on the field it changed rather than on a digest nobody updated.
# Variables are consumed by the exact production functions sourced below.
# shellcheck disable=SC2034
compose_reconcile() { # $1=root [ENV=VALUE …] -> 0 when the installer would proceed
  local root=$1; shift
  local closure manifest preseal
  # An absent or unreadable document is one of the cases under test, so the
  # hashes are read tolerantly here and the ASSERTION is left to the lifted
  # installer code rather than to this harness.
  closure="$(sha256sum -- "$root/seed/release-closure.json" 2>/dev/null | awk '{print tolower($1)}')"
  preseal="$(sha256sum -- "$root/preseal/preseal-set.json" 2>/dev/null | awk '{print tolower($1)}')"
  (
    set -uo pipefail
    # shellcheck disable=SC2329,SC2317
    die() { echo "die: $*" >&2; exit 1; }
    SEED_VERIFIED_ROOT="$root/seed"
    PRESEAL_SNAPSHOT="$root/preseal"
    SEED_CLOSURE="$closure"
    PRESEAL_SET_SHA256="$preseal"
    OS_IMAGE="$COMPOSE_OS_IMAGE"
    AUTH_TARGET_REF="$COMPOSE_OS_IMAGE"
    SEALED_HARDWARE_TARGET=nvidia-gb10-arm64
    SEALED_TRUST_POLICY_ID=neural-ice-secureboot-lab-v1
    DEVICE_CHANNEL=lab
    INSTALL_MIRROR=""
    MIRROR_READY_SHA256=""
    MIRROR_READY_MANIFEST_SHA256=""
    for assignment in "$@"; do export "${assignment?}"; eval "$assignment"; done
    # shellcheck source=/dev/null
    . "$COMPOSE/reconcile.sh"
    # The ni-seed path, in the installer's own order (rule C): the closure is
    # hashed against the sealed value, the manifest hash is derived from it,
    # and only then is the seed reconciled -- the manifest document must hash
    # to what the closure says.
    assert_sealed_document_digest "$SEED_VERIFIED_ROOT/release-closure.json" "$SEED_CLOSURE" "offline seed's release closure"
    SEED_MANIFEST_SHA256="$(seed_manifest_hash_from_closure "$SEED_VERIFIED_ROOT/release-closure.json")" \
      || die "the sealed release closure names no well-formed release manifest hash"
    assert_seed_is_the_preseal_release
  ) >/dev/null 2>&1
}

compose_case() { # $1=expect accept|refuse $2=label $3=document $4=overrides [ENV…]
  local expect=$1 label=$2 document=$3 overrides=$4; shift 4
  local root="$COMPOSE/case"
  rm -rf -- "$root"
  compose_fixture "$root" "$document" "$overrides" \
    || fail "cannot build the composed-medium fixture for: $label"
  if compose_reconcile "$root" "$@"; then
    [ "$expect" = accept ] \
      || fail "the installer accepted a seed it must refuse: $label"
  else
    [ "$expect" = refuse ] \
      || fail "the installer refused the supported composed medium: $label"
  fi
}

compose_case accept "one release carried by two transports" none '{}'
# 🔴 SABOTAGE (FAB-0057 P1.1b, rule C): a closure that hashes to the sealed value
# but names ANOTHER release manifest. The installer derives the manifest hash
# from the closure, so the manifest on the medium no longer hashes to what the
# closure says, and the seed is refused before the disk is touched.
compose_case refuse "a closure naming a release manifest that is not the one beside it" \
  closure "{\"release_manifest_sha256\":\"$(printf 'f%.0s' {1..64})\"}"
compose_case refuse "a closure naming no release manifest at all" closure '{"release_manifest_sha256":null}'
compose_case refuse "a seed from another train" closure '{"train":"1.1.0"}'
compose_case refuse "a seed from another bundle sequence" closure '{"bundle_seq":14}'
compose_case refuse "a seed cut around another appliance root" \
  closure "{\"host_digest\":\"sha256:$(printf '%064d' 43)\"}"
compose_case refuse "a seed for another hardware target" \
  closure '{"hardware_target":"nvidia-other-arm64"}'
compose_case refuse "a seed for another boot-trust policy" \
  closure '{"boot_trust_profile":"neural-ice-secureboot-prod-v1"}'
compose_case refuse "a release manifest naming a different appliance root" \
  manifest "{\"host\":{\"digest\":\"sha256:$(printf '%064d' 43)\",\"repository\":\"$COMPOSE_OS_REPOSITORY\"}}"
compose_case refuse "a release manifest from another release" manifest '{"release_id":"release-1-0-1"}'
compose_case refuse "a preseal set for another train" preseal '{"train":"1.1.0"}'
compose_case refuse "a preseal set for another ring than the sealed channel" preseal '{"ring":"beta"}'
compose_case refuse "a preseal set naming another appliance" \
  preseal "{\"target_os_ref\":\"$COMPOSE_OS_REPOSITORY@sha256:$(printf '%064d' 43)\"}"
compose_case refuse "an appliance root that is not the one being installed" none '{}' \
  "AUTH_TARGET_REF=$COMPOSE_OS_REPOSITORY@sha256:$(printf '%064d' 43)"
compose_case refuse "a mirror declaring a different release than the seed" none '{}' \
  "INSTALL_MIRROR=bench.example.test:5000" \
  "MIRROR_READY_SHA256=$(printf '%064d' 9)"

# The documents are re-hashed against their sealed values before a byte is
# parsed, so a tree swapped between verification and reconciliation selects
# nothing -- and a hostile or corrupt document is refused by the reader itself.
compose_tampered() { # $1=how
  local root="$COMPOSE/case"
  rm -rf -- "$root"
  compose_fixture "$root" none '{}' || fail "cannot build the tamper fixture"
  case "$1" in
    bytes)   printf '{"train":"1.0.0"}\n' > "$root/seed/release-closure.json" ;;
    duplicate)
      printf '{"train":"1.0.0","train":"1.1.0"}\n' > "$root/seed/release-closure.json" ;;
    oversize)
      python3 -c 'import sys; sys.stdout.write("{\"pad\":\"" + "x" * (17 * 1024 * 1024) + "\"}\n")' \
        > "$root/seed/release-closure.json" ;;
    symlink)
      rm -f -- "$root/seed/release-closure.json"
      ln -s /dev/null "$root/seed/release-closure.json" ;;
    absent) rm -f -- "$root/seed/release-closure.json" ;;
  esac
  ! compose_reconcile "$root" \
    || fail "the installer accepted a seed whose release closure was $1"
}
# `bytes` and `duplicate` are caught by the sealed-hash comparison; the others
# prove the reader itself is bounded and refuses a non-regular input.
for how in bytes duplicate oversize symlink absent; do compose_tampered "$how"; done

# A duplicate key that survives the hash comparison -- i.e. the sealed hash is
# the hash OF the duplicate document -- must still be refused by the reader.
compose_duplicate_root="$COMPOSE/duplicate"
rm -rf -- "$compose_duplicate_root"
compose_fixture "$compose_duplicate_root" none '{}' || fail "cannot build the duplicate-key fixture"
printf '{"bundle_seq":13,"bundle_seq":13,"host_digest":"%s","train":"1.0.0"}\n' \
  "$COMPOSE_OS_DIGEST" > "$compose_duplicate_root/seed/release-closure.json"
! compose_reconcile "$compose_duplicate_root" \
  || fail "the installer's document reader accepted a duplicate JSON field"

# --------------------------------------------------------------------------- #
# The PRODUCER side of the same rule.
# --------------------------------------------------------------------------- #
# Variables are consumed by the exact production functions sourced below.
# shellcheck disable=SC2034
compose_seal() { # $1=source $2=root [ENV=VALUE …] -> 0 when the medium would be cut
  local source=$1 root=$2; shift 2
  (
    set -uo pipefail
    sha256_of() { sha256sum -- "$1" | awk '{print tolower($1)}'; }
    SEED_CLOSURE="$(sha256_of "$root/seed/release-closure.json")"
    SEED_TRUSTED_NOW=2026-09-02T07:00:00Z
    RELEASE_MANIFEST_FILE="$root/seed/release-manifest.json"
    RELEASE_CLOSURE_FILE="$root/seed/release-closure.json"
    PRESEAL_STAGE_ROOT="$root"
    OS_IMAGE="$COMPOSE_OS_IMAGE"
    TARGET_IMGREF="$COMPOSE_OS_IMAGE"
    HARDWARE_TARGET=nvidia-gb10-arm64
    INSTALL_MIRROR=""
    MIRROR_READY_SHA256=""
    MIRROR_READY_MANIFEST_SHA256=""
    UKI_KARGS=()
    for assignment in "$@"; do eval "$assignment"; done
    # shellcheck source=/dev/null
    . "$COMPOSE/seal.sh"
    seal_offline_seed_kargs "$source"
    # A medium that seals nothing when a seed was asked for is not a medium that
    # passed: the tuple is the point.
    if [ -n "$SEED_CLOSURE" ]; then
      printf '%s\n' "${UKI_KARGS[@]}" | grep -qx "neuralice.seed_closure=$SEED_CLOSURE"
      printf '%s\n' "${UKI_KARGS[@]}" | grep -qx "neuralice.seed_trusted_now=$SEED_TRUSTED_NOW"
      # Rule C: the manifest hash is the closure's to state; the producer seals
      # no `neuralice.seed_manifest` (the sealed grammar would refuse the line).
      if printf '%s\n' "${UKI_KARGS[@]}" | grep -q '^neuralice.seed_manifest='; then exit 1; fi
    fi
  ) >/dev/null 2>&1
}

compose_seal_root="$COMPOSE/seal-fixture"
rm -rf -- "$compose_seal_root"
compose_fixture "$compose_seal_root" none '{}' || fail "cannot build the producer fixture"
compose_seal medium "$compose_seal_root" \
  || fail "the producer no longer seals the offline seed tuple for a medium install"
compose_seal registry "$compose_seal_root" \
  || fail "the producer refuses the supported registry medium carrying a reconciled seed"
compose_seal registry "$compose_seal_root" 'PRESEAL_STAGE_ROOT=""' \
  && fail "the producer cut a registry medium with a seed and no preseal set to reconcile it against"
compose_seal registry "$compose_seal_root" 'SEED_TRUSTED_NOW=""' \
  && fail "the producer cut a medium sealing a closure with no verification time"
compose_seal medium "$compose_seal_root" 'SEED_CLOSURE=""' \
  && fail "the producer cut a medium carrying a release manifest that nothing seals"
compose_seal medium "$compose_seal_root" 'RELEASE_CLOSURE_FILE=""' \
  && fail "the producer cut a medium without reading the closure the sealed hash names (rule C)"
compose_seal medium "$compose_seal_root" "SEED_CLOSURE=$(printf '%064d' 7)" \
  && fail "the producer cut a medium whose sealed closure hash is not the hash of the closure it was given"
compose_closure_mismatch_root="$COMPOSE/seal-closure-mismatch"
rm -rf -- "$compose_closure_mismatch_root"
compose_fixture "$compose_closure_mismatch_root" closure "{\"release_manifest_sha256\":\"$(printf 'f%.0s' {1..64})\"}" \
  || fail "cannot build the closure/manifest mismatch producer fixture"
compose_seal medium "$compose_closure_mismatch_root" \
  && fail "the producer cut a medium whose closure names another release manifest than the one beside it (rule C)"
compose_seal registry "$compose_closure_mismatch_root" \
  && fail "the producer cut a registry medium whose closure names another release manifest than the one beside it (rule C)"
compose_seal registry "$compose_seal_root" \
  "OS_IMAGE=$COMPOSE_OS_REPOSITORY@sha256:$(printf '%064d' 43)" \
  && fail "the producer cut a registry medium whose seed is not the appliance it installs"
compose_seal registry "$compose_seal_root" 'HARDWARE_TARGET=nvidia-other-arm64' \
  && fail "the producer cut a medium whose seed is for another hardware target"
compose_seal registry "$compose_seal_root" \
  'INSTALL_MIRROR=bench.example.test:5000' "MIRROR_READY_SHA256=$(printf '%064d' 9)" \
  && fail "the producer cut a medium whose mirror declares a different release than its seed"

compose_mismatch_root="$COMPOSE/seal-mismatch"
rm -rf -- "$compose_mismatch_root"
compose_fixture "$compose_mismatch_root" manifest '{"bundle_seq":14}' \
  || fail "cannot build the mismatched producer fixture"
compose_seal registry "$compose_mismatch_root" \
  && fail "the producer cut a registry medium whose seed and preseal set are different releases"
compose_seal medium "$compose_mismatch_root" \
  && fail "the producer cut an offline medium whose seed and preseal set are different releases"
compose_seal medium "$compose_mismatch_root" 'PRESEAL_STAGE_ROOT=""' \
  || fail "a legacy medium install must keep sealing its own seed without a preseal set"

echo "  composed medium: producer and installer both reconcile the seed with the preseal release"

# --------------------------------------------------------------------------- #
# 🔴 THE OPT-IN CONTENT CACHE (FAB-0057 P1.7), DRIVEN AGAINST THE PRODUCER'S OWN
# FUNCTIONS.
#
# Four media were cut on the bench on 2026-09-09, each for one edit of
# ota/neural-ice-autoinstall.sh, and each rebuilt the sealed store: a `skopeo
# copy` of ~8 GiB plus a `mksquashfs` over the result (the copy dominates),
# for a change the store cannot depend on. The producer may now hand that extent
# back -- and the whole question is whether it can do so without weakening a
# proof.
#
# The functions are LIFTED from image/build-installer-usb.sh, the way the
# composed-medium section above lifts `seal_offline_seed_kargs`: this suite runs
# the code the build host runs, not a paraphrase of it. It needs bash, python3
# and sha256sum only, so it lives ABOVE the sealed-medium fixture, which `exit
# 0`s on a host without veritysetup -- a cache control that disappeared with a
# fixture would be a control nobody notices the loss of.
#
# WHERE THE BYTE-LEVEL SABOTAGE IS PROVED: image/test-build-installer-root.sh
# section 8. The re-hash of a reused extent happens inside
# image/build-installer-root.sh, on the COPY it makes, and that suite drives the
# real script. What is proved HERE is everything the producer decides on its own
# side: which entries it will read at all, and the one comparison a cache can
# never satisfy by itself.
# --------------------------------------------------------------------------- #
CACHE="$TMP/cache-lift"; mkdir -p "$CACHE"
# The lift cannot be the `awk '/^name() {/,/^}$/'` this file uses elsewhere:
# these functions embed python heredocs whose dict literals close with a `}` in
# the first column, and that range would cut each function in half and produce a
# file that only LOOKS like the producer. The extractor below tracks the
# heredocs, so what is sourced is the whole function or nothing.
CACHE_FUNCTIONS=(sha256_of medium_cache_die medium_cache_require_dir
  medium_cache_store_key_document medium_cache_assert_reused_verity
  medium_cache_entry_dir medium_cache_read_entry medium_cache_stage_store
  medium_cache_finalize_store medium_cache_prune)
python3 - "$BUILDER" "$CACHE/cache.sh" "${CACHE_FUNCTIONS[@]}" <<'PYEOF' \
  || fail "cannot lift the media producer's content-cache functions"
import re
import sys

source = open(sys.argv[1], encoding="utf-8").read().splitlines()
extracted = []
for name in sys.argv[3:]:
    opening = f"{name}() {{"
    starts = [index for index, line in enumerate(source) if line.startswith(opening)]
    if len(starts) != 1:
        raise SystemExit(f"the media producer defines {name} {len(starts)} times")
    start = starts[0]
    heredoc = None
    for index in range(start, len(source)):
        line = source[index]
        extracted.append(line)
        if heredoc is not None:
            if line.strip() == heredoc:
                heredoc = None
            continue
        opened = re.search(r"<<-?'([A-Za-z_][A-Za-z0-9_]*)'", line)
        if opened:
            heredoc = opened.group(1)
            continue
        if index > start and line == "}":
            break
    else:
        raise SystemExit(f"{name} has no closing brace in the media producer")
    extracted.append("")
open(sys.argv[2], "w", encoding="utf-8").write("\n".join(extracted) + "\n")
PYEOF
for cache_function in "${CACHE_FUNCTIONS[@]}"; do
  grep -q "^${cache_function}()" "$CACHE/cache.sh" \
    || fail "the media producer no longer defines ${cache_function}; the cache would be untested"
done
bash -n "$CACHE/cache.sh" \
  || fail "the lifted content-cache functions do not parse; the cases below would prove nothing"

# Variables are consumed by the exact production functions sourced below.
# shellcheck disable=SC2034
cache_run() { # [ENV=VALUE …] -- function args…   -> runs one lifted function
  local -a assignments=()
  while [ "$#" -gt 0 ] && [ "$1" != -- ]; do assignments+=("$1"); shift; done
  shift
  (
    set -uo pipefail
    REPO_ROOT="$ROOT"
    MEDIUM_BUILD_CACHE_DIR="$CACHE/store"
    MEDIUM_BUILD_CACHE_MAX_ENTRIES=4
    MEDIUM_BUILD_CACHE_SCHEMA="neural-ice-medium-build-cache-entry-v1"
    MEDIUM_BUILD_CACHE_KEY_SCHEMA="neural-ice-medium-build-cache-key-v1"
    BASE_IMAGE="registry.example.test/neural-ice/appliance@sha256:$(printf '%064d' 1)"
    BASE_IMAGE_ID="$(printf '%064d' 2)"
    BASE_MANIFEST_DIGEST="sha256:$(printf '%064d' 3)"
    STORE_IMAGE_NAME=localhost/bootc
    STORE_SOURCE_REF=""
    for assignment in "${assignments[@]+"${assignments[@]}"}"; do eval "$assignment"; done
    # shellcheck source=/dev/null
    . "$CACHE/cache.sh"
    "$@"
  )
}

mkdir -p "$CACHE/store"; chmod 0700 "$CACHE/store"

# 1) THE KEY IS A DOCUMENT, AND EVERY INPUT THAT CAN CHANGE THE BYTES IS IN IT.
cache_key() { cache_run "$@" -- medium_cache_store_key_document mksquashfs-4.6 skopeo-1.13.3; }
cache_key_baseline="$(cache_key)" || fail "the cache key document could not be rendered"
python3 -c 'import json,sys; d=json.load(sys.stdin); sys.exit(0 if d["schema"]=="neural-ice-medium-build-cache-key-v1" and d["kind"]=="sealed-store" else 1)' \
  <<<"$cache_key_baseline" || fail "the cache key document is not the declared schema"
[ "$cache_key_baseline" = "$(cache_key)" ] \
  || fail "two renderings of the same inputs produced different cache keys"
for cache_changed_input in \
  "BASE_IMAGE=registry.example.test/neural-ice/appliance@sha256:$(printf '%064d' 9)" \
  "BASE_IMAGE_ID=$(printf '%064d' 9)" \
  "BASE_MANIFEST_DIGEST=sha256:$(printf '%064d' 9)" \
  "STORE_IMAGE_NAME=localhost/something-else" \
  "STORE_SOURCE_REF=docker://mirror.test:5055/x@sha256:$(printf '%064d' 9)"; do
  [ "$(cache_key "$cache_changed_input")" != "$cache_key_baseline" ] \
    || fail "changing '$cache_changed_input' did not change the cache key"
done
# ...including the tool versions and the producer scripts themselves. The three
# scripts are HASHED rather than their mksquashfs/veritysetup options copied
# here: an option list copied into a key would be a second answer, and only one
# of them would be the one that ran.
[ "$(cache_run -- medium_cache_store_key_document mksquashfs-4.7 skopeo-1.13.3)" \
  != "$cache_key_baseline" ] \
  || fail "a different mksquashfs version did not change the cache key"
[ "$(cache_run -- medium_cache_store_key_document mksquashfs-4.6 skopeo-1.21.0)" \
  != "$cache_key_baseline" ] \
  || fail "a different skopeo version did not change the cache key"
for cache_producer in image/build-installer-root.sh image/build-installer-payload.sh \
  image/lib/installer-payload.sh; do
  grep -Fq "\"$cache_producer\":" <<<"$cache_key_baseline" \
    || fail "the cache key does not pin $cache_producer, whose code decides the cached bytes"
  cache_recorded="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["producer_sha256"][sys.argv[1]])' \
    "$cache_producer" <<<"$cache_key_baseline")"
  [ "$cache_recorded" = "$(sha256sum "$ROOT/$cache_producer" | awk '{print tolower($1)}')" ] \
    || fail "the cache key records a stale hash for $cache_producer"
done

# 2) THE DIRECTORY. A cache that can be repointed, that somebody else owns, that
#    anybody can write, or that lives in the checkout is not a cache.
cache_dir_case() { # $1=label $2=directory [MAX=…]
  cache_run "MEDIUM_BUILD_CACHE_DIR=$2" "${3:-MEDIUM_BUILD_CACHE_MAX_ENTRIES=4}" \
    -- medium_cache_require_dir
}
cache_dir_case ok "$CACHE/store" >/dev/null 2>&1 \
  || fail "a private, build-user-owned cache directory was refused"
mkdir -p "$CACHE/group-writable"; chmod 0770 "$CACHE/group-writable"
out="$(cache_dir_case group "$CACHE/group-writable" 2>&1)" \
  && fail "a group-writable cache directory was accepted"
grep -Fq 'group- or world-accessible' <<<"$out" || fail "the permissive-mode refusal is not named: $out"
ln -sfn "$CACHE/store" "$CACHE/link"
out="$(cache_dir_case symlink "$CACHE/link" 2>&1)" \
  && fail "a symlinked cache directory was accepted"
grep -Fq 'is a symlink' <<<"$out" || fail "the symlink refusal is not named: $out"
out="$(cache_dir_case relative "relative/path" 2>&1)" \
  && fail "a relative cache directory was accepted"
grep -Fq 'must be an absolute path' <<<"$out" || fail "the relative-path refusal is not named: $out"
out="$(cache_dir_case absent "$CACHE/does-not-exist" 2>&1)" \
  && fail "a cache directory that does not exist was accepted"
grep -Fq 'not an existing directory' <<<"$out" || fail "the absent-directory refusal is not named: $out"
out="$(cache_dir_case inrepo "$ROOT/image" 2>&1)" \
  && fail "a cache directory inside the checkout was accepted"
grep -Fq 'inside the checkout' <<<"$out" || fail "the in-checkout refusal is not named: $out"
out="$(cache_dir_case bound "$CACHE/store" 'MEDIUM_BUILD_CACHE_MAX_ENTRIES=0' 2>&1)" \
  && fail "an unbounded cache was accepted"
grep -Fq 'between 1 and 999' <<<"$out" || fail "the bound refusal is not named: $out"

# 3) AN ENTRY IS NOT REUSABLE UNTIL EVERY VALUE A REUSE RE-CHECKS IS RECORDED.
cache_key_value="$(printf '%s' "$cache_key_baseline" | sha256sum | awk '{print tolower($1)}')"
CACHE_STORE_IMG="$TMP/cache-store.img"
printf 'a sealed store, for the purposes of this suite\n' > "$CACHE_STORE_IMG"
CACHE_STORE_SHA="$(sha256sum "$CACHE_STORE_IMG" | awk '{print tolower($1)}')"
CACHE_STORE_BYTES="$(wc -c < "$CACHE_STORE_IMG" | tr -d '[:space:]')"
CACHE_STORE_VERITY="$(printf '%064d' 4)"
# The digest of the bound image list the store was cut around (2026-09-17):
# recorded so a reuse can refuse a store cut around another list.
CACHE_STORE_BOUND_LIST="$(printf '%064d' 7)"
cache_stage() { cache_run -- medium_cache_stage_store "$cache_key_value" "$CACHE_STORE_IMG"; }
cache_finalize() { # $1=the store SHA-256 to record (the real one, or a sabotaged fact)
  cache_run -- medium_cache_finalize_store "$cache_key_value" "$cache_key_baseline" \
    "$1" "$CACHE_STORE_BYTES" "$BASE_ID_FIXTURE" \
    "sha256:$(printf '%064d' 3)" localhost/bootc "$CACHE_STORE_VERITY" \
    "$(printf 'f%.0s' {1..64})" 6e657572-616c-4963-9e69-6e7374616c6c \
    "$CACHE_STORE_BOUND_LIST"
}
BASE_ID_FIXTURE="$(printf '%064d' 2)"
cache_stage || fail "staging a cache entry failed"
cache_entry="$CACHE/store/sealed-store/$cache_key_value"
[ -f "$cache_entry/installer-store.img" ] || fail "staging did not copy the store extent"
[ ! -e "$cache_entry/entry.json" ] \
  || fail "a staged entry is already reusable before its verity root hash is known"
out="$(cache_run -- medium_cache_read_entry "$cache_key_value" 2>&1 >/dev/null)" \
  && fail "an unfinished cache entry was reused"
grep -Fq 'no provenance document' <<<"$out" \
  || fail "the unfinished-entry refusal is not named: $out"
cache_finalize "$CACHE_STORE_SHA" || fail "finalizing a cache entry failed"
cache_facts="$(cache_run -- medium_cache_read_entry "$cache_key_value" 2>/dev/null)" \
  || fail "a finalized cache entry was refused"
[ "$(sed -n 's/^store_image_sha256=//p' <<<"$cache_facts")" = "$CACHE_STORE_SHA" ] \
  || fail "the entry does not hand back the digest a reuse is checked against"
[ "$(sed -n 's/^store_verity_hash=//p' <<<"$cache_facts")" = "$CACHE_STORE_VERITY" ] \
  || fail "the entry does not hand back the verity root hash a reuse is checked against"
[ "$(sed -n 's/^store_image_id=//p' <<<"$cache_facts")" = "$BASE_ID_FIXTURE" ] \
  || fail "the entry does not hand back the store image identity"
[ "$(sed -n 's/^store_bound_images_sha256=//p' <<<"$cache_facts")" = "$CACHE_STORE_BOUND_LIST" ] \
  || fail "the entry does not hand back the bound image list a reuse is checked against"

# 🔴 SABOTAGE A -- THE RECORD. An entry whose provenance document is altered is
# refused, and it is refused BY NAME. This is the half of the cache the producer
# itself decides; the byte-level half is proved in
# image/test-build-installer-root.sh section 8, which drives the real re-hash.
cache_sabotage() { # $1=python expression mutating `document`
  python3 - "$cache_entry/entry.json" "$1" <<'PYEOF'
import json, sys
path, mutation = sys.argv[1:]
document = json.load(open(path, encoding="utf-8"))
exec(mutation)  # noqa: S102 - a test fixture, mutating its own fixture document
open(path, "w", encoding="utf-8").write(json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n")
PYEOF
}
cache_restore() { cache_finalize "$CACHE_STORE_SHA" || fail "cannot restore the cache entry"; }
cache_refuses() { # $1=expected words in the refusal
  local refusal
  refusal="$(cache_run -- medium_cache_read_entry "$cache_key_value" 2>&1 >/dev/null)" \
    && fail "a sabotaged cache entry was reused (expected: $1)"
  grep -Fq "$1" <<<"$refusal" || fail "the refusal is not named '$1': $refusal"
}
cache_sabotage 'document["store_image_sha256"] = "0" * 64'
cache_facts_altered="$(cache_run -- medium_cache_read_entry "$cache_key_value" 2>/dev/null)" \
  || fail "an entry whose recorded digest was changed could not be read at all"
[ "$(sed -n 's/^store_image_sha256=//p' <<<"$cache_facts_altered")" != "$CACHE_STORE_SHA" ] \
  || fail "the altered record did not reach the value a reuse is checked against"
# ...and that altered value is exactly what image/build-installer-root.sh
# re-hashes the copied extent against, which is why THAT comparison is the
# refusal and this one is only the transport. Asserted on the source, executed
# in image/test-build-installer-root.sh.
grep -Fq 'die "the reused store image hashes to $STORE_IMAGE_SHA256, not the recorded $STORE_IMAGE_REUSE_SHA256' \
  "$ROOT/image/build-installer-root.sh" \
  || fail "the sealed root builder no longer re-hashes a reused extent against the recorded digest"
cache_restore
cache_sabotage 'document["schema"] = "neural-ice-medium-build-cache-entry-v0"'
cache_refuses 'provenance schema is'
cache_restore
cache_sabotage 'document["key"] = "f" * 64'
cache_refuses 'records a different key than the directory it sits in'
cache_restore
cache_sabotage 'del document["store_verity_hash"]'
cache_refuses "field 'store_verity_hash' is missing or malformed"
cache_restore
cache_sabotage 'document["store_image_manifest_digest"] = "not-a-digest"'
cache_refuses "field 'store_image_manifest_digest' is missing or malformed"
cache_restore
cache_sabotage 'document["store_image_bytes"] = 12'
cache_refuses "field 'store_image_bytes' is missing or malformed"
# An entry from before the store carried the bound images records no list; it
# is refused here by the reader, and again by the builder if it ever got there.
cache_restore
cache_sabotage 'del document["store_bound_images_sha256"]'
cache_refuses "field 'store_bound_images_sha256' is missing or malformed"
cache_restore
printf 'not json at all\n' > "$cache_entry/entry.json"
cache_refuses 'unreadable provenance document'
cache_restore
mv "$cache_entry/installer-store.img" "$cache_entry/installer-store.img.moved"
ln -s /etc/hostname "$cache_entry/installer-store.img"
cache_refuses 'holds no plain, non-empty store image'
rm -f "$cache_entry/installer-store.img"
mv "$cache_entry/installer-store.img.moved" "$cache_entry/installer-store.img"
cache_run -- medium_cache_read_entry "$cache_key_value" >/dev/null 2>&1 \
  || fail "the restored entry is no longer readable; the sabotage cases would prove nothing"
out="$(cache_run -- medium_cache_read_entry "$(printf 'e%.0s' {1..64})" 2>&1 >/dev/null)" \
  && fail "an absent cache entry was reported as a hit"
grep -Fq 'cache miss' <<<"$out" || fail "a cold cache is not reported as a miss: $out"

# 🔴 SABOTAGE B -- THE BYTES, AT THE ONE GATE A CACHE CANNOT SATISFY. The store's
# dm-verity root hash is recomputed by the UNCHANGED payload assembler over the
# extent that is going onto the medium; a cached entry that does not reproduce it
# is refused before the UKI seals the header digest that covers it.
cache_run -- medium_cache_assert_reused_verity "$CACHE_STORE_VERITY" "$CACHE_STORE_VERITY" \
  || fail "a reused store whose verity root hash reproduces was refused"
out="$(cache_run -- medium_cache_assert_reused_verity "$(printf '%064d' 5)" "$CACHE_STORE_VERITY" 2>&1)" \
  && fail "a reused store whose verity root hash did not reproduce was accepted"
grep -Fq 'refusing a medium built on bytes the cache cannot account for' <<<"$out" \
  || fail "the verity mismatch refusal is not named: $out"

# 4) THE CACHE IS BOUNDED. Entries are ~8 GiB; an unbounded cache fills the build
#    host and the next build dies on ENOSPC inside a `veritysetup format`.
for cache_extra in 1 2 3 4 5; do
  cache_extra_key="$(printf '%s%063d' c "$cache_extra")"
  cache_run -- medium_cache_stage_store "$cache_extra_key" "$CACHE_STORE_IMG" \
    || fail "staging filler entry $cache_extra failed"
  cache_run -- medium_cache_finalize_store "$cache_extra_key" "$cache_key_baseline" \
    "$CACHE_STORE_SHA" "$CACHE_STORE_BYTES" "$BASE_ID_FIXTURE" \
    "sha256:$(printf '%064d' 3)" localhost/bootc "$CACHE_STORE_VERITY" \
    "$(printf 'f%.0s' {1..64})" 6e657572-616c-4963-9e69-6e7374616c6c \
    "$CACHE_STORE_BOUND_LIST" \
    || fail "finalizing filler entry $cache_extra failed"
  # `entry.json` mtime orders the eviction, so the fillers must not share one.
  touch -d "2026-09-0${cache_extra}T00:00:00Z" "$CACHE/store/sealed-store/$cache_extra_key/entry.json"
done
cache_run -- medium_cache_prune "$cache_key_value" >/dev/null \
  || fail "pruning the cache failed"
cache_kept="$(find "$CACHE/store/sealed-store" -mindepth 1 -maxdepth 1 -type d | wc -l)"
[ "$cache_kept" = 5 ] \
  || fail "the cache kept $cache_kept entries; the bound is 4 plus the build's own key"
[ -d "$cache_entry" ] || fail "pruning evicted the entry of the build that was running"
[ ! -d "$CACHE/store/sealed-store/$(printf '%s%063d' c 1)" ] \
  || fail "the oldest entry survived the bound"
[ -d "$CACHE/store/sealed-store/$(printf '%s%063d' c 5)" ] \
  || fail "the newest entry was evicted"

echo "  incremental build: the sealed store cache is opt-in, keyed by document, bounded, and re-proved on every reuse"

# --------------------------------------------------------------------------- #
# ADR-0058 Volet C: the sealed store identity is sourced from the SIGNED
# reference, not from podman's local .Digest.
#
# resolve_sealed_store_identity is LIFTED from the producer (as the cache
# functions above are) and driven directly: it needs bash and nothing else, so
# it too lives ABOVE the veritysetup fixture that `exit 0`s on this host. It owns
# the manifest-digest PROVENANCE -- the value the whole store-equality chain is
# compared against -- so a regression here is exactly the "phantom digest" class
# ADR-0058 closes.
# --------------------------------------------------------------------------- #
IDENTITY="$TMP/identity-lift"; mkdir -p "$IDENTITY"
python3 - "$BUILDER" "$IDENTITY/identity.sh" resolve_sealed_store_identity <<'PYEOF' \
  || fail "cannot lift the store-identity resolver"
import re, sys
source = open(sys.argv[1], encoding="utf-8").read().splitlines()
extracted = []
for name in sys.argv[3:]:
    opening = f"{name}() {{"
    starts = [i for i, line in enumerate(source) if line.startswith(opening)]
    if len(starts) != 1:
        raise SystemExit(f"the producer defines {name} {len(starts)} times")
    for index in range(starts[0], len(source)):
        extracted.append(source[index])
        if index > starts[0] and source[index] == "}":
            break
    else:
        raise SystemExit(f"{name} has no closing brace")
    extracted.append("")
open(sys.argv[2], "w", encoding="utf-8").write("\n".join(extracted) + "\n")
PYEOF
grep -q '^resolve_sealed_store_identity()' "$IDENTITY/identity.sh" \
  || fail "the producer no longer defines resolve_sealed_store_identity; the store identity would be untested"
bash -n "$IDENTITY/identity.sh" || fail "the lifted store-identity resolver does not parse"
# shellcheck source=/dev/null
. "$IDENTITY/identity.sh"

SIGNED_INDEX="sha256:$(printf 'a%.0s' {1..64})"
OTHER_DIGEST="sha256:$(printf 'b%.0s' {1..64})"
SIGNED_REF="registry.example.test/neural-ice/appliance@${SIGNED_INDEX}"
# (i) A signed reference whose locally observed manifest matches yields exactly
# the SIGNED digest -- the value the readback of the staged store is compared
# against, so an accepted build reads the same digest back.
resolved="$(resolve_sealed_store_identity "$SIGNED_REF" "$SIGNED_INDEX")" \
  || fail "the store identity was refused for a base whose observed manifest matches its signed reference"
[ "$resolved" = "$SIGNED_INDEX" ] \
  || fail "the store identity resolved to '$resolved', not the signed reference digest $SIGNED_INDEX"
# (iv) A locally observed manifest that DIFFERS from the signed reference (a
# re-encoded or substituted manifest -- different content behind the same ref) is
# refused; the digest is never taken from podman's local view alone.
if resolve_sealed_store_identity "$SIGNED_REF" "$OTHER_DIGEST" >/dev/null 2>&1; then
  fail "a manifest digest differing from the signed reference was accepted"
fi
# A reference that is not digest-pinned carries no signed identity at all.
if resolve_sealed_store_identity "registry.example.test/neural-ice/appliance:latest" "$SIGNED_INDEX" >/dev/null 2>&1; then
  fail "a tag-only (unpinned) reference was accepted as a signed store identity"
fi
# A malformed observed digest is refused rather than trusted.
if resolve_sealed_store_identity "$SIGNED_REF" "not-a-digest" >/dev/null 2>&1; then
  fail "a malformed observed manifest digest was accepted"
fi
echo "  store identity: sourced from the signed reference digest, podman's .Digest demoted to a fail-closed cross-check (ADR-0058 Volet C)"


# --------------------------------------------------------------------------- #
# 🔴 THE v2 RELEASE PAIR, PRODUCER SIDE (mission B, T3a;
# docs/ota/V2-RELEASE-ATTESTATION.md). An owner-sealed v2 medium has no preseal
# set: the producer takes the release manifest and its detached signature
# (V2_RELEASE_MANIFEST / V2_RELEASE_MANIFEST_SIG), seals their SHA-256 in the
# signed UKI line (neuralice.v2rel_sha256 / neuralice.v2rel_sig_sha256, after the
# medium source) and stages the two files on the ESP. It refuses to CUT a medium
# whose installer would refuse it: unsigned, signed by another key, not the
# release the sealed image belongs to, the wrong hardware, or in company the
# grammar forbids.
#
# Lifted verbatim, like the seed sealing above, and ABOVE the sealed-medium
# fixture so it runs on a host without veritysetup. The first vector is the T0
# golden manifest: the producer and the verifier read the same contract bytes.
# --------------------------------------------------------------------------- #
V2P="$TMP/v2-producer"; mkdir -p "$V2P"
awk '/^sha256_of\(\) \{/,/^}$/' "$BUILDER" > "$V2P/lifted.sh"
for v2_function in v2_release_acquire assert_v2_release_inputs v2_release_check_signature \
  verify_v2_release_against_base_image seal_v2_release_kargs; do
  awk "/^${v2_function}\\(\\) \\{/,/^}\$/" "$BUILDER" >> "$V2P/lifted.sh"
done
for v2_function in sha256_of v2_release_acquire assert_v2_release_inputs v2_release_check_signature \
  verify_v2_release_against_base_image seal_v2_release_kargs; do
  grep -q "^${v2_function}()" "$V2P/lifted.sh" \
    || fail "the producer no longer defines ${v2_function}; the v2 release pair would be unsealed"
done
bash -n "$V2P/lifted.sh" || fail "the lifted v2 release functions do not parse"
V2_GOLDEN="$ROOT/tools/ni-ota-verify/tests/fixtures/v2-release"
[ -f "$V2_GOLDEN/golden.json" ] || fail "the T0 golden vectors are missing: $V2_GOLDEN"

v2_golden_value() { python3 -I -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d["inputs"][sys.argv[2]])' "$V2_GOLDEN/golden.json" "$1"; }
V2_GOLDEN_REPOSITORY="$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["expected"]["host_repository"])' "$V2_GOLDEN/golden.json")"
V2_GOLDEN_DIGEST="$(v2_golden_value host_index_digest)"
V2_GOLDEN_TARGET="$(v2_golden_value hardware_target)"
V2_GOLDEN_AUTHORITY="$(v2_golden_value release_authority)"

# A throwaway key and a manifest this suite signs itself, so each negative states
# its one difference and nothing else. `v2_make_release DIR [key=value…]` writes
# DIR/{manifest,sig,release-authorization.pub}; overrides are JSON paths
# (host.digest=…, bundle_seq=…, drop:schema).
openssl ecparam -name prime256v1 -genkey -noout -out "$V2P/test.key" 2>/dev/null \
  || fail "cannot generate the v2 release test key"
openssl ec -in "$V2P/test.key" -pubout -out "$V2P/test.pub" 2>/dev/null \
  || fail "cannot derive the v2 release test public key"
openssl ecparam -name prime256v1 -genkey -noout -out "$V2P/other.key" 2>/dev/null \
  || fail "cannot generate the second v2 release test key"
v2_make_release() { # $1=dir $2=signing key, rest: JSON overrides (a.b=value | a.b:=<json> | drop:a.b)
  local dir=$1 key=$2; shift 2
  mkdir -p "$dir"
  python3 -I - "$dir/manifest" "$V2_GOLDEN_REPOSITORY" "$V2_GOLDEN_DIGEST" "$V2_GOLDEN_TARGET" "$@" <<'PYEOF'
import json
import sys

path, repository, digest, target, *overrides = sys.argv[1:]
manifest = json.loads(
    '{"bundle_seq":3,"hardware_target":"%s","host":{"digest":"%s","repository":"%s"},'
    '"release_id":"v2-test-train-3","schema":"neural-ice-release-manifest-v1"}'
    % (target, digest, repository)
)
for item in overrides:
    if item.startswith("drop:"):
        node = manifest
        parts = item[5:].split(".")
        for part in parts[:-1]:
            node = node[part]
        del node[parts[-1]]
        continue
    raw, _, value = item.partition(":=") if ":=" in item else item.partition("=")
    parsed = json.loads(value) if ":=" in item else value
    node = manifest
    parts = raw.split(".")
    for part in parts[:-1]:
        node = node[part]
    node[parts[-1]] = parsed
with open(path, "w", encoding="utf-8") as handle:
    handle.write(json.dumps(manifest, sort_keys=True, separators=(",", ":")))
PYEOF
  openssl dgst -sha256 -sign "$key" -out "$dir/sig.der" "$dir/manifest" 2>/dev/null \
    || fail "cannot sign the v2 release test manifest"
  base64 -w0 < "$dir/sig.der" > "$dir/sig"
  rm -f "$dir/sig.der"
}
# `sudo` and `podman` as the lifted producer functions call them: a sudo that runs
# its command, and a podman that answers the one question the producer asks of the
# base image (`run ... BASE_IMAGE cat <release key path>`) with a key file.
mkdir -p "$V2P/bin"
printf '#!/bin/sh\nexec "$@"\n' > "$V2P/bin/sudo"
cat > "$V2P/bin/podman" <<'FAKEPODMAN'
#!/bin/bash
# run --rm --entrypoint '' <image> cat <path>
if [ "${1:-}" = run ] && [ "${*: -2:1}" = cat ] \
   && [ "${*: -1}" = /usr/lib/neural-ice/keys/release-authorization.pub ] \
   && [ "${*: -3:1}" = "$BASE_IMAGE" ]; then
  [ -f "$V2_BASE_KEY" ] || exit 1
  exec cat -- "$V2_BASE_KEY"
fi
echo "unexpected podman call: $*" >&2
exit 125
FAKEPODMAN
chmod +x "$V2P/bin/sudo" "$V2P/bin/podman"
# Variables are consumed by the exact production functions sourced below.
# shellcheck disable=SC2034
v2_seal() { # [VAR=value …] -> runs the LIFTED producer function; prints the kargs it sealed
  (
    set -uo pipefail
    MEDIA_MODE=install VARIANT=sealed-lab INSTALL_SOURCE=medium
    HARDWARE_TARGET="$V2_GOLDEN_TARGET" RELEASE_AUTHORITY="$V2_GOLDEN_AUTHORITY"
    TARGET_IMGREF="$V2_GOLDEN_REPOSITORY@$V2_GOLDEN_DIGEST"
    PRESEAL_SET_DIR="" PRESEAL_SET_SHA256="" RELEASE_AUTHORIZATION_FILE="" RELEASE_AUTHORIZATION_SIGNATURE_FILE=""
    SEALED_DIR="$V2P/sealed" V2_BASE_KEY="$V2P/test.pub" V2_RELEASE_PRIVATE_DIR=""
    V2_RELEASE_MANIFEST="$V2P/good/manifest" V2_RELEASE_MANIFEST_SIG="$V2P/good/sig"
    local_assignment=""
    for local_assignment in "$@"; do printf -v "${local_assignment%%=*}" '%s' "${local_assignment#*=}"; done
    UKI_KARGS=(sentinel)
    # shellcheck disable=SC1091
    source "$V2P/lifted.sh"
    # The producer runs three steps, two of them BEFORE the image build: the
    # inputs (one read, the contract's content rules), the signature under the
    # key BASE_IMAGE carries, and only then the seal under the key the medium
    # carries. The base image is stood in for by a podman that prints a key file;
    # EARLY=0 skips the two early steps to exercise the seal on its own.
    TMPDIR="$V2P/tmp"; mkdir -p "$TMPDIR"
    trap 'rm -rf -- "$V2_RELEASE_PRIVATE_DIR"' EXIT
    # shellcheck disable=SC2030 # subshell-local on purpose: the fake podman is for this case only
    PATH="$V2P/bin:$PATH"
    BASE_IMAGE="registry.example.test/neural-ice-test/base@sha256:$(printf 'e%.0s' {1..64})"
    export BASE_IMAGE V2_BASE_KEY
    if [ "${EARLY:-1}" = 1 ]; then
      assert_v2_release_inputs || exit $?
      # A hook run once the files have been read: the source is rewritten HERE.
      eval "${AFTER_READ:-true}"
      verify_v2_release_against_base_image || exit $?
    fi
    seal_v2_release_kargs || exit $?
    printf '%s\n' "${UKI_KARGS[*]}"
    printf 'STAGE=%s MANIFEST_SHA=%s SIG_SHA=%s\n' "${V2_RELEASE_STAGE_ROOT:-unset}" \
      "${V2_RELEASE_MANIFEST_SHA256:-unset}" "${V2_RELEASE_MANIFEST_SIG_SHA256:-unset}"
  )
}
v2_refused() { # $1=label $2=text the refusal must carry, rest as v2_seal -> the producer must REFUSE for THAT reason
  local label=$1 reason=$2 rc=0; shift 2
  v2_seal "$@" >"$V2P/out" 2>"$V2P/err" || rc=$?
  [ "$rc" -ne 0 ] || fail "[v2 producer] $label: the producer accepted it ($(cat "$V2P/out"))"
  grep -q "^ERROR:.*${reason}" "$V2P/err" \
    || fail "[v2 producer] $label: refused, but not for '${reason}': $(cat "$V2P/err")"
}

mkdir -p "$V2P/sealed" "$V2P/good"
cp "$V2P/test.pub" "$V2P/sealed/release-authorization.pub"
v2_make_release "$V2P/good" "$V2P/test.key"
v2_good_manifest_sha="$(sha256sum "$V2P/good/manifest" | awk '{print $1}')"
v2_good_sig_sha="$(sha256sum "$V2P/good/sig" | awk '{print $1}')"

v2_out="$(v2_seal)" || fail "[v2 producer] a correctly signed manifest bound to the target was refused: $(v2_seal 2>&1 | head -3)"
[ "$(sed -n 1p <<<"$v2_out")" = "sentinel neuralice.v2rel_sha256=${v2_good_manifest_sha} neuralice.v2rel_sig_sha256=${v2_good_sig_sha}" ] \
  || fail "[v2 producer] the sealed kargs are not the manifest then the signature hash, appended after the existing ones: $v2_out"
grep -q "^STAGE=staged MANIFEST_SHA=${v2_good_manifest_sha} SIG_SHA=${v2_good_sig_sha}\$" <<<"$v2_out" \
  || fail "[v2 producer] the producer does not hand the staged hashes to the ESP step: $v2_out"

# The T0 golden pair, replayed under the golden key: the producer and the
# verifier read the same contract bytes.
cp "$V2_GOLDEN/release-authorization.pub" "$V2P/sealed-golden.pub"
mkdir -p "$V2P/sealed-golden"; cp "$V2P/sealed-golden.pub" "$V2P/sealed-golden/release-authorization.pub"
v2_seal SEALED_DIR="$V2P/sealed-golden" V2_BASE_KEY="$V2P/sealed-golden.pub" V2_RELEASE_MANIFEST="$V2_GOLDEN/release-manifest.json" \
  V2_RELEASE_MANIFEST_SIG="$V2_GOLDEN/release-manifest.json.sig" >"$V2P/out" 2>"$V2P/err" \
  || { cat "$V2P/err" >&2; fail "[v2 producer] the T0 golden release manifest was refused"; }
grep -q "neuralice.v2rel_sha256=$(v2_golden_value sealed_manifest_sha256) neuralice.v2rel_sig_sha256=$(v2_golden_value sealed_manifest_sig_sha256)" "$V2P/out" \
  || fail "[v2 producer] the producer seals other hashes than the golden vectors state: $(cat "$V2P/out")"

# Joint, or nothing.
v2_refused "manifest without signature" "supplied together" V2_RELEASE_MANIFEST_SIG=""
v2_refused "signature without manifest" "supplied together" V2_RELEASE_MANIFEST=""
# Exclusive with the other two authentication routes.
v2_refused "beside a preseal set" "excludes PRESEAL_SET" PRESEAL_SET_DIR="$V2P/good" PRESEAL_SET_SHA256="$(printf '%064d' 9)"
v2_refused "beside the authorization pair" "excludes PRESEAL_SET" RELEASE_AUTHORIZATION_FILE="$V2P/good/manifest" RELEASE_AUTHORIZATION_SIGNATURE_FILE="$V2P/good/sig"
# Medium source, Install, sealed-lab only.
v2_refused "registry source" "only permitted on sealed-lab Install media" INSTALL_SOURCE=registry
v2_refused "Live medium" "only permitted on sealed-lab Install media" MEDIA_MODE=live
v2_refused "prod variant" "only permitted on sealed-lab Install media" VARIANT=prod
# Files.
printf '' > "$V2P/empty"
ln -sf "$V2P/good/manifest" "$V2P/link"
head -c $(( 1048576 + 1 )) /dev/zero | tr '\0' 'x' > "$V2P/huge"
head -c 1025 /dev/zero | tr '\0' 'A' > "$V2P/bigsig"
v2_refused "empty manifest" "non-empty regular files" V2_RELEASE_MANIFEST="$V2P/empty"
v2_refused "empty signature" "non-empty regular files" V2_RELEASE_MANIFEST_SIG="$V2P/empty"
v2_refused "missing manifest" "non-empty regular files" V2_RELEASE_MANIFEST="$V2P/none"
v2_refused "symlinked manifest" "non-empty regular files" V2_RELEASE_MANIFEST="$V2P/link"
v2_refused "manifest over 1 MiB" "larger than the 1048576-byte bound" V2_RELEASE_MANIFEST="$V2P/huge"
v2_refused "signature over 1 KiB" "larger than the 1024-byte bound" V2_RELEASE_MANIFEST_SIG="$V2P/bigsig"
v2_refused "the same bytes for both objects" "same bytes" V2_RELEASE_MANIFEST_SIG="$V2P/good/manifest"
# The manifest must be the release the sealed image belongs to.
for v2_case in \
  "host digest of another image|TARGET_IMGREF|host.digest=sha256:$(printf 'c%.0s' {1..64})" \
  "host repository of another image|TARGET_IMGREF|host.repository=registry.example.test/neural-ice-test/other-appliance" \
  "host repository at another authority|release authority|host.repository=other.example.test/neural-ice-test/host-appliance" \
  "another hardware target|hardware_target|hardware_target=some-other-box" \
  "another schema|schema|schema=neural-ice-release-manifest-v9" \
  "no schema|schema|drop:schema" \
  "bundle_seq 0|bundle_seq|bundle_seq:=0" \
  "bundle_seq 2^53|bundle_seq|bundle_seq:=9007199254740992" \
  "bundle_seq as a string|bundle_seq|bundle_seq=3" \
  "bundle_seq as a float|bundle_seq|bundle_seq:=3.0" \
  "bad release_id|release_id|release_id=has space"; do
  v2_label="${v2_case%%|*}"; v2_rest="${v2_case#*|}"
  v2_reason="${v2_rest%%|*}"; v2_override="${v2_rest#*|}"
  v2_make_release "$V2P/case" "$V2P/test.key" "$v2_override"
  v2_refused "manifest with $v2_label" "$v2_reason" V2_RELEASE_MANIFEST="$V2P/case/manifest" V2_RELEASE_MANIFEST_SIG="$V2P/case/sig"
done
# Duplicate keys at any depth: the JSON the signature covers must be unambiguous.
printf '{"bundle_seq":3,"bundle_seq":4,"hardware_target":"%s","host":{"digest":"%s","repository":"%s"},"release_id":"v2-test-train-3","schema":"neural-ice-release-manifest-v1"}' \
  "$V2_GOLDEN_TARGET" "$V2_GOLDEN_DIGEST" "$V2_GOLDEN_REPOSITORY" > "$V2P/dup-manifest"
openssl dgst -sha256 -sign "$V2P/test.key" "$V2P/dup-manifest" | base64 -w0 > "$V2P/dup-sig"
v2_refused "duplicate key" "duplicated JSON key" V2_RELEASE_MANIFEST="$V2P/dup-manifest" V2_RELEASE_MANIFEST_SIG="$V2P/dup-sig"
printf 'not json' > "$V2P/notjson"
openssl dgst -sha256 -sign "$V2P/test.key" "$V2P/notjson" | base64 -w0 > "$V2P/notjson-sig"
v2_refused "manifest that is not JSON" "not valid JSON" V2_RELEASE_MANIFEST="$V2P/notjson" V2_RELEASE_MANIFEST_SIG="$V2P/notjson-sig"
# The signature is verified under THE KEY THE MEDIUM SEALS, over the exact bytes.
v2_make_release "$V2P/otherkey" "$V2P/other.key"
v2_refused "signed by another key" "does not verify" V2_RELEASE_MANIFEST="$V2P/otherkey/manifest" V2_RELEASE_MANIFEST_SIG="$V2P/otherkey/sig"
cp "$V2P/good/manifest" "$V2P/flipped"; printf ' ' >> "$V2P/flipped"
v2_refused "manifest changed after signing (one trailing byte)" "does not verify" V2_RELEASE_MANIFEST="$V2P/flipped"
printf 'not*base64*at*all' > "$V2P/badb64"
v2_refused "signature that is not base64" "strict base64" V2_RELEASE_MANIFEST_SIG="$V2P/badb64"
printf 'AAAA' > "$V2P/shortsig"
v2_refused "signature that is not a DER ECDSA signature" "does not verify" V2_RELEASE_MANIFEST_SIG="$V2P/shortsig"
# THE JSON THE VERIFIER (serde_json) READS, READ THE SAME WAY (review 240, P3-2).
# Python's json accepts what serde_json refuses; a manifest signed that way would
# cut a medium the installer refuses at its pre-wipe check. Each one is signed, so
# the ONLY reason to refuse it is its content.
v2_raw_manifest() { # $1=dir $2=extra members (JSON text, may be empty) $3=release_id
  local dir=$1 extra=$2 release_id=${3-v2-test-train-3}
  mkdir -p "$dir"
  printf '{"bundle_seq":3,%s"hardware_target":"%s","host":{"digest":"%s","repository":"%s"},"release_id":"%s","schema":"neural-ice-release-manifest-v1"}' \
    "$extra" "$V2_GOLDEN_TARGET" "$V2_GOLDEN_DIGEST" "$V2_GOLDEN_REPOSITORY" "$release_id" > "$dir/manifest"
  openssl dgst -sha256 -sign "$V2P/test.key" "$dir/manifest" 2>/dev/null | base64 -w0 > "$dir/sig"
}
v2_big_integer="1$(printf '0%.0s' {1..400})"
for v2_case in \
  'NaN|"extra":NaN,' \
  'Infinity|"extra":Infinity,' \
  'minus Infinity|"extra":-Infinity,' \
  'a float out of range (1e999)|"extra":1e999,' \
  'a negative float out of range|"extra":-1e999,' \
  'an integer out of range|"extra":'"$v2_big_integer"',' \
  'an isolated surrogate in a value|"extra":"\ud800",' \
  'an isolated trailing surrogate in a value|"extra":"\udc00x",' \
  'an isolated surrogate in a member name|"\ud800":1,'; do
  v2_label="${v2_case%%|*}"; v2_extra="${v2_case#*|}"
  v2_raw_manifest "$V2P/raw" "$v2_extra"
  v2_refused "manifest carrying $v2_label" "not valid JSON" \
    V2_RELEASE_MANIFEST="$V2P/raw/manifest" V2_RELEASE_MANIFEST_SIG="$V2P/raw/sig"
done
# ...while a PAIRED surrogate (a real astral character) and a finite float are JSON
# serde_json reads, and must not be refused by the same rules.
v2_raw_manifest "$V2P/raw" '"extra":"\ud83d\ude00","ratio":1.5e3,'
v2_seal V2_RELEASE_MANIFEST="$V2P/raw/manifest" V2_RELEASE_MANIFEST_SIG="$V2P/raw/sig" >/dev/null 2>"$V2P/err" \
  || { cat "$V2P/err" >&2; fail "[v2 producer] a manifest with a paired surrogate and a finite float was refused"; }
# release_id is 1..128 characters of [A-Za-z0-9._-] (contract rule 7), not 1..infinity.
v2_raw_manifest "$V2P/raw" '' "$(printf 'a%.0s' {1..128})"
v2_seal V2_RELEASE_MANIFEST="$V2P/raw/manifest" V2_RELEASE_MANIFEST_SIG="$V2P/raw/sig" >/dev/null 2>"$V2P/err" \
  || { cat "$V2P/err" >&2; fail "[v2 producer] a 128-character release_id was refused"; }
v2_raw_manifest "$V2P/raw" '' "$(printf 'a%.0s' {1..129})"
v2_refused "a 129-character release_id" "release_id" V2_RELEASE_MANIFEST="$V2P/raw/manifest" V2_RELEASE_MANIFEST_SIG="$V2P/raw/sig"
v2_raw_manifest "$V2P/raw" '' ""
v2_refused "an empty release_id" "release_id" V2_RELEASE_MANIFEST="$V2P/raw/manifest" V2_RELEASE_MANIFEST_SIG="$V2P/raw/sig"
v2_make_release "$V2P/case" "$V2P/test.key" 'host.digest=sha256:'"$(printf 'C%.0s' {1..64})"
v2_refused "an uppercase host digest" "host.digest" V2_RELEASE_MANIFEST="$V2P/case/manifest" V2_RELEASE_MANIFEST_SIG="$V2P/case/sig" \
  TARGET_IMGREF="$V2_GOLDEN_REPOSITORY@sha256:$(printf 'C%.0s' {1..64})"

# EVERYTHING BUT THE SEALED KEY IS JUDGED BEFORE THE IMAGE BUILD (review 240, P3-3).
# The seal runs after the 40-minute build, when the sealed key exists; the content
# rules and the signature must not wait for it. SEALED_DIR is absent here, so any
# refusal below can only have come from the early steps.
v2_refused "[early] manifest of another hardware, no sealed dir yet" "hardware_target" \
  SEALED_DIR="$V2P/none" HARDWARE_TARGET=some-other-box
v2_refused "[early] manifest of another image, no sealed dir yet" "TARGET_IMGREF" \
  SEALED_DIR="$V2P/none" TARGET_IMGREF="$V2_GOLDEN_REPOSITORY@sha256:$(printf 'c%.0s' {1..64})"
v2_refused "[early] signed by another key than BASE_IMAGE carries, no sealed dir yet" "under the key BASE_IMAGE carries" \
  SEALED_DIR="$V2P/none" V2_RELEASE_MANIFEST="$V2P/otherkey/manifest" V2_RELEASE_MANIFEST_SIG="$V2P/otherkey/sig"
v2_refused "[early] a BASE_IMAGE from which the release key cannot be read" "cannot read the release key out of BASE_IMAGE" \
  SEALED_DIR="$V2P/none" V2_BASE_KEY="$V2P/no-such-key"
: > "$V2P/empty-key"
v2_refused "[early] a BASE_IMAGE whose release key is empty" "no usable release key" \
  SEALED_DIR="$V2P/none" V2_BASE_KEY="$V2P/empty-key"
# The seal, alone, still judges the signature under the key the medium really seals...
v2_refused "[seal] signed by another key than the sealed one" "under the key this medium seals" EARLY=0 \
  V2_RELEASE_MANIFEST="$V2P/otherkey/manifest" V2_RELEASE_MANIFEST_SIG="$V2P/otherkey/sig"
# ...and refuses a sealed key that is not the one the early check used.
v2_refused "[seal] a sealed key other than BASE_IMAGE's" "not the one BASE_IMAGE carries" \
  SEALED_DIR="$V2P/sealed-golden" V2_BASE_KEY="$V2P/test.pub"

# ONE READ OF EACH FILE (contract: "Single read of every input"; review 240, P4-1).
# The source is rewritten right after the producer has read it: what is hashed,
# validated, verified, sealed and staged must still be the bytes that were read.
mkdir -p "$V2P/swap"
cp "$V2P/good/manifest" "$V2P/swap/manifest"; cp "$V2P/good/sig" "$V2P/swap/sig"
v2_swapped_out="$(v2_seal V2_RELEASE_MANIFEST="$V2P/swap/manifest" V2_RELEASE_MANIFEST_SIG="$V2P/swap/sig" \
  AFTER_READ="cp $V2P/dup-manifest $V2P/swap/manifest; cp $V2P/dup-sig $V2P/swap/sig")" \
  || fail "[v2 producer] a source rewritten after the read made the producer refuse the bytes it had validated"
[ "$(sed -n 1p <<<"$v2_swapped_out")" = "sentinel neuralice.v2rel_sha256=${v2_good_manifest_sha} neuralice.v2rel_sig_sha256=${v2_good_sig_sha}" ] \
  || fail "[v2 producer] a source rewritten after the read changed what was sealed: $v2_swapped_out"
[ "$(sha256sum "$V2P/swap/manifest" | awk '{print $1}')" != "$v2_good_manifest_sha" ] \
  || fail "[v2 producer] the single-read probe did not rewrite its source"
# No private copy survives a producer that exits (the trap of the producer removes it).
[ -z "$(find "$V2P/tmp" -mindepth 1 -print -quit)" ] \
  || fail "[v2 producer] a refused or sealed v2 release left its private copy behind: $(ls "$V2P/tmp")"
rm -f "$V2P/sealed/release-authorization.pub"
v2_refused "no sealed release key to verify under" "carries no release key"
cp "$V2P/test.pub" "$V2P/sealed/release-authorization.pub"
echo "  v2 release pair (producer): sealed after the source, joint, exclusive, signature verified under the sealed key, bound to the target and hardware"

# --------------------------------------------------------------------------- #
# 🔴 THE SIGNED PCR7 RULES PAIR, PRODUCER SIDE (mission "TPM policy at scale",
# ADR-0045, T5). The producer takes the Owner-signed rules document and its
# detached signature (`--pcr-rules FILE` / `--pcr-rules-signature FILE`, or
# PCR_RULES_FILE / PCR_RULES_SIGNATURE_FILE), reads each ONCE without following
# a link into a private copy, seals the SHA-256 of rules.json and the rules'
# own `sequence` (never asked for as an argument) in the signed UKI line
# (neuralice.pcr_rules / neuralice.pcr_rules_seq, beside the pcr_policy terms)
# and stages both files on the ESP under ice-coreos/pcr-rules/. Both or
# neither; Install only; absent / empty / link / over 1 MiB are refusals.
#
# Lifted verbatim, like the v2 pair above, so it runs on a host without
# veritysetup.
# --------------------------------------------------------------------------- #
PRP="$TMP/pcr-rules-producer"; mkdir -p "$PRP/tmp"
awk '/^sha256_of\(\) \{/,/^}$/' "$BUILDER" > "$PRP/lifted.sh"
for pr_function in pcr_rules_acquire assert_pcr_rules_inputs seal_pcr_rules_kargs; do
  awk "/^${pr_function}\\(\\) \\{/,/^}\$/" "$BUILDER" >> "$PRP/lifted.sh"
done
for pr_function in sha256_of pcr_rules_acquire assert_pcr_rules_inputs seal_pcr_rules_kargs; do
  grep -q "^${pr_function}()" "$PRP/lifted.sh" \
    || fail "the producer no longer defines ${pr_function}; the PCR rules pair would be unsealed"
done
bash -n "$PRP/lifted.sh" || fail "the lifted PCR rules functions do not parse"

pr_write_rules() { # $1=dir $2=rules.json body -> dir/rules.json and a distinct dir/rules.json.sig
  mkdir -p "$1"
  printf '%s' "$2" > "$1/rules.json"
  printf 'b3duZXItc2lnbmF0dXJlLW92ZXItdGhlLWRvbWFpbi1zZXBhcmF0ZWQtcnVsZXM=' > "$1/rules.json.sig"
}
PR_RULES_BODY='{"approved_certs":[],"approved_pk":[],"schema":"ni-pcr-rules/1","sequence":12,"unbound_variables":"allow"}'
pr_write_rules "$PRP/good" "$PR_RULES_BODY"
pr_good_sha="$(sha256sum "$PRP/good/rules.json" | awk '{print $1}')"

# shellcheck disable=SC2034
pr_seal() { # [VAR=value ...] -> runs the LIFTED producer functions; prints the kargs it sealed
  (
    set -uo pipefail
    MEDIA_MODE=install
    PCR_RULES_FILE="$PRP/good/rules.json" PCR_RULES_SIGNATURE_FILE="$PRP/good/rules.json.sig"
    PCR_RULES_PRIVATE_DIR="" PCR_RULES_STAGE_ROOT=""
    local_assignment=""
    for local_assignment in "$@"; do printf -v "${local_assignment%%=*}" '%s' "${local_assignment#*=}"; done
    UKI_KARGS=(sentinel)
    # shellcheck disable=SC1091
    source "$PRP/lifted.sh"
    TMPDIR="$PRP/tmp"
    trap 'rm -rf -- "$PCR_RULES_PRIVATE_DIR"' EXIT
    assert_pcr_rules_inputs || exit $?
    seal_pcr_rules_kargs || exit $?
    printf '%s\n' "${UKI_KARGS[*]}"
    printf 'STAGE=%s SHA=%s SEQ=%s\n' "${PCR_RULES_STAGE_ROOT:-unset}" "${PCR_RULES_SHA256:-unset}" "${PCR_RULES_SEQ:-unset}"
  )
}
pr_refused() { # $1=label $2=text the refusal must carry, rest as pr_seal
  local label=$1 reason=$2 rc=0; shift 2
  pr_seal "$@" >"$PRP/out" 2>"$PRP/err" || rc=$?
  [ "$rc" -ne 0 ] || fail "[pcr rules producer] $label: the producer accepted it ($(cat "$PRP/out"))"
  grep -q "^ERROR:.*${reason}" "$PRP/err" \
    || fail "[pcr rules producer] $label: refused, but not for '${reason}': $(cat "$PRP/err")"
}

pr_out="$(pr_seal)" || fail "[pcr rules producer] a well-formed signed rules pair was refused: $(pr_seal 2>&1 | head -3)"
[ "$(sed -n 1p <<<"$pr_out")" = "sentinel neuralice.pcr_rules=${pr_good_sha} neuralice.pcr_rules_seq=12" ] \
  || fail "[pcr rules producer] the sealed kargs are not the rules digest then the sequence READ FROM THE RULES: $pr_out"
grep -q "^STAGE=staged SHA=${pr_good_sha} SEQ=12\$" <<<"$pr_out" \
  || fail "[pcr rules producer] the producer does not hand the staged hash and sequence to the ESP step: $pr_out"
# The produced pair, on a produced Install line, is one the closed grammar accepts.
# shellcheck source=/dev/null
. "$ROOT/image/installer/neural-ice-sealed-cmdline-grammar.sh"
pr_pair="$(sed -n 1p <<<"$pr_out")"; pr_pair="${pr_pair#sentinel }"
ni_sealed_cmdline_classify "quiet systemd.unit=neural-ice-installer.target neuralice.autoinstall=1 neuralice.trust=neural-ice-installer-trust-v1 neuralice.access_profile=lab-managed neuralice.hardware_target=nvidia-gb10-arm64 neuralice.payload=$(printf '1%.0s' {1..64}) neuralice.relauth_keyid=$(printf '2%.0s' {1..64}) neuralice.relauth_schema=neural-ice-installer-release-authorization-v2 neuralice.rootverity=$(printf '3%.0s' {1..64}) neuralice.trust_policy_id=neural-ice-secureboot-lab-v1 neuralice.pcr_policy=$(printf '4%.0s' {1..64}) neuralice.pcr_policy_key=$(printf '5%.0s' {1..64}) neuralice.pcr_policy_signature=$(printf '6%.0s' {1..64}) neuralice.pcr_policy_seq=7 $pr_pair" >/dev/null 2>&1 \
  || fail "[pcr rules producer] the closed grammar refused the pair the producer seals: $pr_pair"

# Neither input: not a trace of it, and nothing staged.
pr_none="$(pr_seal PCR_RULES_FILE= PCR_RULES_SIGNATURE_FILE=)" || fail "[pcr rules producer] a medium with no rules was refused"
[ "$(sed -n 1p <<<"$pr_none")" = sentinel ] \
  || fail "[pcr rules producer] a medium with no rules sealed something: $pr_none"
grep -q '^STAGE=unset ' <<<"$pr_none" || fail "[pcr rules producer] a medium with no rules staged something: $pr_none"
# A sequence read from the rules, whatever it is: 1 and the largest safe integer.
pr_write_rules "$PRP/seq1" '{"schema":"ni-pcr-rules/1","sequence":1}'
pr_seq1="$(pr_seal PCR_RULES_FILE="$PRP/seq1/rules.json" PCR_RULES_SIGNATURE_FILE="$PRP/seq1/rules.json.sig" 2>/dev/null)" \
  || fail "[pcr rules producer] sequence 1 was refused"
[[ "$(sed -n 1p <<<"$pr_seq1")" == *' neuralice.pcr_rules_seq=1' ]] \
  || fail "[pcr rules producer] sequence 1 was not sealed as read: $pr_seq1"
pr_write_rules "$PRP/seqmax" '{"schema":"ni-pcr-rules/1","sequence":9007199254740991}'
pr_seqmax="$(pr_seal PCR_RULES_FILE="$PRP/seqmax/rules.json" PCR_RULES_SIGNATURE_FILE="$PRP/seqmax/rules.json.sig" 2>/dev/null)" \
  || fail "[pcr rules producer] the largest safe sequence was refused"
[[ "$(sed -n 1p <<<"$pr_seqmax")" == *' neuralice.pcr_rules_seq=9007199254740991' ]] \
  || fail "[pcr rules producer] the largest safe sequence was not sealed as read: $pr_seqmax"

# Joint, or nothing: one file pins nothing.
pr_refused "rules without signature" "supplied together" PCR_RULES_SIGNATURE_FILE=
pr_refused "signature without rules" "supplied together" PCR_RULES_FILE=
# Install only: a Live medium enrols and unlocks nothing.
pr_refused "Live medium" "Install media" MEDIA_MODE=live
# Absent / empty / link / too large, on each of the two files.
: > "$PRP/empty"
ln -sf "$PRP/good/rules.json" "$PRP/link"
truncate -s 1048577 "$PRP/huge"
pr_refused "missing rules" "non-empty regular files" PCR_RULES_FILE="$PRP/none"
pr_refused "missing signature" "non-empty regular files" PCR_RULES_SIGNATURE_FILE="$PRP/none"
pr_refused "empty rules" "non-empty regular files" PCR_RULES_FILE="$PRP/empty"
pr_refused "empty signature" "non-empty regular files" PCR_RULES_SIGNATURE_FILE="$PRP/empty"
pr_refused "symlinked rules" "non-empty regular files" PCR_RULES_FILE="$PRP/link"
pr_refused "symlinked signature" "non-empty regular files" PCR_RULES_SIGNATURE_FILE="$PRP/link"
pr_refused "a directory as rules" "non-empty regular files" PCR_RULES_FILE="$PRP"
pr_refused "rules over 1 MiB" "larger than the 1048576-byte bound" PCR_RULES_FILE="$PRP/huge"
pr_refused "signature over 4096 bytes (the installer's bound)" "larger than the 4096-byte bound" PCR_RULES_SIGNATURE_FILE="$PRP/huge"
# The rules the engine will read: a JSON object whose `sequence` is an integer in 1..2^53-1.
pr_bad_rules() { # $1=label $2=body $3=text the refusal must carry
  pr_write_rules "$PRP/bad" "$2"
  pr_refused "$1" "$3" PCR_RULES_FILE="$PRP/bad/rules.json" PCR_RULES_SIGNATURE_FILE="$PRP/bad/rules.json.sig"
}
pr_bad_rules "rules that are not JSON" 'not json at all' "not valid JSON"
pr_bad_rules "rules that are an array" '[1,2]' "JSON object"
pr_bad_rules "rules with no sequence" '{"schema":"ni-pcr-rules/1"}' "sequence"
pr_bad_rules "a string sequence" '{"sequence":"12"}' "sequence"
pr_bad_rules "a boolean sequence" '{"sequence":true}' "sequence"
pr_bad_rules "a fractional sequence" '{"sequence":12.5}' "sequence"
pr_bad_rules "a float spelling of an integer" '{"sequence":12.0}' "sequence"
pr_bad_rules "sequence zero" '{"sequence":0}' "sequence"
pr_bad_rules "a negative sequence" '{"sequence":-3}' "sequence"
pr_bad_rules "a sequence beyond 2^53-1" '{"sequence":9007199254740992}' "sequence"
pr_bad_rules "a duplicated sequence key (the engine's parser and ours would disagree)" '{"sequence":1,"sequence":99}' "duplicated JSON key"
# A signature that is the rules' own bytes pins neither.
cp "$PRP/good/rules.json" "$PRP/same-sig"
pr_refused "signature identical to the rules" "same bytes" PCR_RULES_SIGNATURE_FILE="$PRP/same-sig"
# No private copy survives a producer that exits.
[ -z "$(find "$PRP/tmp" -mindepth 1 -print -quit)" ] \
  || fail "[pcr rules producer] a refused or sealed rules pair left its private copy behind: $(ls "$PRP/tmp")"

# The producer's own wiring, asserted on the real file: the two options, the
# environment inputs they feed, the ordering beside the pcr_policy terms, the ESP
# staging, and the early (pre-build) call of the cheap half of the refusals.
for wiring in 'PCR_RULES_FILE="${PCR_RULES_FILE:-}"' 'PCR_RULES_SIGNATURE_FILE="${PCR_RULES_SIGNATURE_FILE:-}"' \
  '--pcr-rules)' '--pcr-rules-signature)' \
  'ice-coreos/pcr-rules/rules.json' 'ice-coreos/pcr-rules/rules.json.sig'; do
  grep -Fq -- "$wiring" "$BUILDER" || fail "[pcr rules producer] the producer lost its wiring: $wiring"
done
pr_policy_line="$(grep -nF '"neuralice.pcr_policy_seq=${PCR_POLICY_SEQ}")' "$BUILDER" | head -1 | cut -d: -f1)"
pr_seal_line="$(grep -n '^    seal_pcr_rules_kargs$' "$BUILDER" | head -1 | cut -d: -f1)"
pr_source_line="$(grep -nF 'UKI_KARGS+=("neuralice.source=medium")' "$BUILDER" | head -1 | cut -d: -f1)"
{ [ -n "$pr_policy_line" ] && [ -n "$pr_seal_line" ] && [ -n "$pr_source_line" ]; } \
  || fail "[pcr rules producer] cannot locate the sealing call, the pcr_policy terms or the medium source"
{ [ "$pr_policy_line" -lt "$pr_seal_line" ] && [ "$pr_seal_line" -lt "$pr_source_line" ]; } \
  || fail "[pcr rules producer] the rules pair is not sealed right after the pcr_policy terms and before neuralice.source"
grep -q '^assert_pcr_rules_inputs$' "$BUILDER" \
  || fail "[pcr rules producer] the cheap half of the rules refusals does not run before the image build"

# The two options, on the REAL producer (no toolchain is needed: the options are
# judged before anything else is).
# The PATH read here is the script's own: the earlier PATH prepend lives in a
# subshell on purpose (it stands in a fake podman for one case only), so it must
# NOT reach this runner.
# shellcheck disable=SC2031
pr_run() { env -i PATH="$PATH" HOME="$HOME" TMPDIR="$PRP/tmp" bash "$BUILDER" "$@" </dev/null 2>"$PRP/run.err" >"$PRP/run.out"; }
pr_run --pcr-rules "$PRP/good/rules.json" \
  && fail "[pcr rules producer] --pcr-rules alone was accepted"
grep -q '^ERROR:.*supplied together' "$PRP/run.err" \
  || fail "[pcr rules producer] --pcr-rules alone was refused, but not for being unpaired: $(cat "$PRP/run.err")"
pr_run --pcr-rules-signature "$PRP/good/rules.json.sig" \
  && fail "[pcr rules producer] --pcr-rules-signature alone was accepted"
grep -q '^ERROR:.*supplied together' "$PRP/run.err" \
  || fail "[pcr rules producer] --pcr-rules-signature alone was refused, but not for being unpaired: $(cat "$PRP/run.err")"
pr_run --pcr-rules \
  && fail "[pcr rules producer] --pcr-rules with no value was accepted"
grep -q '^ERROR:.*requires a file' "$PRP/run.err" \
  || fail "[pcr rules producer] --pcr-rules with no value was refused, but not for that: $(cat "$PRP/run.err")"
pr_run --pcr-rules "$PRP/good/rules.json" --pcr-rules "$PRP/good/rules.json" --pcr-rules-signature "$PRP/good/rules.json.sig" \
  && fail "[pcr rules producer] a repeated --pcr-rules was accepted"
grep -q '^ERROR:.*more than once' "$PRP/run.err" \
  || fail "[pcr rules producer] a repeated --pcr-rules was refused, but not for that: $(cat "$PRP/run.err")"
pr_run --pcr-rule "$PRP/good/rules.json" \
  && fail "[pcr rules producer] an unknown option was accepted"
grep -q '^ERROR:.*unknown option' "$PRP/run.err" \
  || fail "[pcr rules producer] an unknown option was refused, but not as one: $(cat "$PRP/run.err")"
echo "  PCR rules pair (producer): read once, sequence taken from the rules, sealed beside the policy terms, joint, Install only, bounded"

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
NONREGISTRY_MEASUREMENTS="$TMP/nonregistry-measurements.json"
inspect --measurements-output "$NONREGISTRY_MEASUREMENTS" >/dev/null 2>&1 \
  && fail "an Install medium without an explicit source emitted final measurements"
[[ ! -e "$NONREGISTRY_MEASUREMENTS" ]] \
  || fail "a refused source-less measurement left an output behind"

# Public TPM policy material may travel on the mutable ESP only when the signed
# UKI command line pins each file's digest, and the policy JSON must contain the
# exact sealed generation. Put the sealed digest second to prove a multi-entry
# document is accepted rather than accidentally checking only its first entry.
cp "$FIXTURE_PCR_POLICY_KEY_FILE" "$TMP/tpm2-pcr-public-key.pem"
tpm_policy_sha="$PCR_POLICY_DIGEST"
other_tpm_policy_sha="$(printf 'other fixture TPM PCR policy' | sha256sum | awk '{print $1}')"
python3 - "$other_tpm_policy_sha" "$TMP/other-policy.bin" <<'PYEOF'
import sys
open(sys.argv[2], "wb").write(bytes.fromhex(sys.argv[1]))
PYEOF
openssl dgst -sha256 -sign "$TMP/pcr-policy.key" \
  -out "$TMP/other-policy.sig" "$TMP/other-policy.bin"
other_policy_signature_b64="$(base64 -w0 < "$TMP/other-policy.sig")"
python3 - "$FIXTURE_PCR_POLICY_SIGNATURE_FILE" "$TMP/tpm2-pcr-signature.json" \
  "$PCR_POLICY_FINGERPRINT" "$other_tpm_policy_sha" \
  "$other_policy_signature_b64" <<'PYEOF'
import json, sys
document = json.load(open(sys.argv[1], encoding="ascii"))
document["sha256"].insert(
    0,
    {"pcrs": [7], "pkfp": sys.argv[3], "pol": sys.argv[4], "sig": sys.argv[5]},
)
json.dump(document, open(sys.argv[2], "w", encoding="ascii"), separators=(",", ":"))
PYEOF
tpm_key_sha="$(sha256sum "$TMP/tpm2-pcr-public-key.pem" | awk '{print $1}')"
tpm_signature_sha="$(sha256sum "$TMP/tpm2-pcr-signature.json" | awk '{print $1}')"
build_uki installer-tpm-policy \
  "quiet systemd.unit=neural-ice-installer.target neuralice.autoinstall=1 enforcing=0 neuralice.pcr_policy=${tpm_policy_sha} neuralice.pcr_policy_key=${tpm_key_sha} neuralice.pcr_policy_signature=${tpm_signature_sha} neuralice.pcr_policy_seq=7" \
  >/dev/null || fail "the TPM-policy Install UKI failed to build"
tpm_esp_files=(
  "::/ice-coreos/tpm2-pcr-public-key.pem=$TMP/tpm2-pcr-public-key.pem"
  "::/ice-coreos/tpm2-pcr-signature.json=$TMP/tpm2-pcr-signature.json"
)
make_esp "$SEALED/installer-tpm-policy.efi" \
  "$SEALED/installer-tpm-policy.efi.manifest" installer-install.efi.manifest \
  "${tpm_esp_files[@]}"
assemble "$ESP" "$SEALED/payload.img"
inspect >/dev/null || fail "correctly hash-bound TPM public policy files were refused"

assert_policy_medium_refused() { # $1=name $2=public key $3=signature JSON $4=message
  local name=$1 key=$2 document=$3 message=$4 key_sha document_sha
  key_sha="$(sha256sum "$key" | awk '{print $1}')"
  document_sha="$(sha256sum "$document" | awk '{print $1}')"
  build_uki "$name" \
    "quiet systemd.unit=neural-ice-installer.target neuralice.autoinstall=1 enforcing=0 neuralice.pcr_policy=${tpm_policy_sha} neuralice.pcr_policy_key=${key_sha} neuralice.pcr_policy_signature=${document_sha} neuralice.pcr_policy_seq=7" \
    >/dev/null || fail "the $name mutation UKI failed to build"
  make_esp "$SEALED/$name.efi" "$SEALED/$name.efi.manifest" \
    installer-install.efi.manifest \
    "::/ice-coreos/tpm2-pcr-public-key.pem=$key" \
    "::/ice-coreos/tpm2-pcr-signature.json=$document"
  assemble "$ESP" "$SEALED/payload.img"
  if inspect >/dev/null 2>&1; then
    fail "$message"
  fi
}

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
  -out "$TMP/inspector-wrong.key" >/dev/null 2>&1
openssl pkey -in "$TMP/inspector-wrong.key" -pubout \
  -out "$TMP/inspector-wrong.pub" >/dev/null 2>&1
assert_policy_medium_refused inspector-wrong-policy-key \
  "$TMP/inspector-wrong.pub" "$TMP/tpm2-pcr-signature.json" \
  "a hash-bound policy signed by another key was accepted"

python3 - "$TMP/tpm2-pcr-signature.json" \
  "$TMP/tpm2-pcr-signature-unsigned.json" "$tpm_policy_sha" \
  "$TMP/tpm2-pcr-signature-malformed-entry.json" \
  "$TMP/tpm2-pcr-signature-malformed-sig.json" <<'PYEOF'
import json, sys
document = json.load(open(sys.argv[1], encoding="ascii"))
unsigned = json.loads(json.dumps(document))
next(entry for entry in unsigned["sha256"] if entry["pol"] == sys.argv[3]).pop("sig")
json.dump(unsigned, open(sys.argv[2], "w", encoding="ascii"), separators=(",", ":"))
malformed = json.loads(json.dumps(document))
malformed["sha256"].insert(0, "not-an-entry")
json.dump(malformed, open(sys.argv[4], "w", encoding="ascii"), separators=(",", ":"))
malformed_sig = json.loads(json.dumps(document))
next(
    entry for entry in malformed_sig["sha256"] if entry["pol"] == sys.argv[3]
)["sig"] = "***"
json.dump(
    malformed_sig, open(sys.argv[5], "w", encoding="ascii"), separators=(",", ":")
)
PYEOF
assert_policy_medium_refused inspector-unsigned-policy \
  "$TMP/tpm2-pcr-public-key.pem" "$TMP/tpm2-pcr-signature-unsigned.json" \
  "an unsigned sealed-generation policy entry was accepted"
assert_policy_medium_refused inspector-malformed-policy \
  "$TMP/tpm2-pcr-public-key.pem" \
  "$TMP/tpm2-pcr-signature-malformed-entry.json" \
  "a malformed policy entry before a valid signed entry was accepted"
assert_policy_medium_refused inspector-malformed-policy-signature \
  "$TMP/tpm2-pcr-public-key.pem" "$TMP/tpm2-pcr-signature-malformed-sig.json" \
  "a malformed sealed-generation policy signature was accepted"

# Hash binding alone is insufficient: a signer can accidentally cut a medium
# whose staged JSON is valid but covers only another machine. Seal the hash of
# that internally consistent wrong document and require the inspector to catch
# the missing PolicyPCR digest before the medium leaves the build plane.
python3 - "$TMP/tpm2-pcr-signature.json" \
  "$TMP/tpm2-pcr-signature-uncovered.json" "$other_tpm_policy_sha" <<'PYEOF'
import json, sys
document = json.load(open(sys.argv[1], encoding="ascii"))
document["sha256"] = [
    entry for entry in document["sha256"] if entry["pol"] == sys.argv[3]
]
json.dump(document, open(sys.argv[2], "w", encoding="ascii"), separators=(",", ":"))
PYEOF
uncovered_signature_sha="$(sha256sum "$TMP/tpm2-pcr-signature-uncovered.json" | awk '{print $1}')"
build_uki installer-tpm-policy-uncovered \
  "quiet systemd.unit=neural-ice-installer.target neuralice.autoinstall=1 enforcing=0 neuralice.pcr_policy=${tpm_policy_sha} neuralice.pcr_policy_key=${tpm_key_sha} neuralice.pcr_policy_signature=${uncovered_signature_sha} neuralice.pcr_policy_seq=7" \
  >/dev/null || fail "the uncovered-policy mutation UKI failed to build"
make_esp "$SEALED/installer-tpm-policy-uncovered.efi" \
  "$SEALED/installer-tpm-policy-uncovered.efi.manifest" installer-install.efi.manifest \
  "::/ice-coreos/tpm2-pcr-public-key.pem=$TMP/tpm2-pcr-public-key.pem" \
  "::/ice-coreos/tpm2-pcr-signature.json=$TMP/tpm2-pcr-signature-uncovered.json"
assemble "$ESP" "$SEALED/payload.img"
inspect >/dev/null 2>&1 \
  && fail "a medium whose hash-bound TPM policy JSON omits its sealed PolicyPCR digest was accepted"

printf '%s\n' 'substituted TPM PCR public key' > "$TMP/tpm2-pcr-public-key-swapped.pem"
make_esp "$SEALED/installer-tpm-policy.efi" \
  "$SEALED/installer-tpm-policy.efi.manifest" installer-install.efi.manifest \
  "::/ice-coreos/tpm2-pcr-public-key.pem=$TMP/tpm2-pcr-public-key-swapped.pem" \
  "::/ice-coreos/tpm2-pcr-signature.json=$TMP/tpm2-pcr-signature.json"
assemble "$ESP" "$SEALED/payload.img"
inspect >/dev/null 2>&1 \
  && fail "a TPM public key that no longer matches the signed digest was accepted"

make_esp "$SEALED/installer-tpm-policy.efi" \
  "$SEALED/installer-tpm-policy.efi.manifest" installer-install.efi.manifest \
  "::/ice-coreos/tpm2-pcr-public-key.pem=$TMP/tpm2-pcr-public-key.pem"
assemble "$ESP" "$SEALED/payload.img"
inspect >/dev/null 2>&1 \
  && fail "a medium missing the TPM signature file its UKI pins was accepted"

make_esp "$SEALED/installer-install.efi" "$SEALED/installer-install.efi.manifest" \
  installer-install.efi.manifest "${tpm_esp_files[@]}"
assemble "$ESP" "$SEALED/payload.img"
inspect >/dev/null 2>&1 \
  && fail "TPM public policy files not pinned by the signed UKI were accepted"

OMIT_DEFAULT_PCR_POLICY=1 make_esp \
  "$SEALED/installer-install.efi" "$SEALED/installer-install.efi.manifest" \
  installer-install.efi.manifest
assemble "$ESP" "$SEALED/payload.img"
inspect >/dev/null 2>&1 \
  && fail "an Install medium without mandatory TPM policy files was accepted"
make_esp "$SEALED/installer-install.efi" "$SEALED/installer-install.efi.manifest" \
  installer-install.efi.manifest
assemble "$ESP" "$SEALED/payload.img"
inspect >/dev/null || fail "the restored Install medium with mandatory TPM policy files was refused"

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
inspect --expect-mode live >"$TMP/inspect-live.out" || fail "a correct Live medium was refused"
grep -q 'neuralice.live=1' "$TMP/inspect-live.out" \
  || fail "the inspector did not surface the sealed Live selector"
grep -q 'systemd.unit=neural-ice-live.target' "$TMP/inspect-live.out" \
  || fail "the inspector did not surface the signed Live target"
inspect >/dev/null 2>&1 && fail "a Live medium was accepted where an Install medium was expected"

# Live is an affirmative signed mode, never whatever remains after removing the
# autoinstall word. Missing, duplicated and mixed selectors all produce validly
# signed UKIs here; the medium inspector must still refuse their grammar.
build_uki live-missing-selector "quiet systemd.unit=neural-ice-live.target" >/dev/null \
  || fail "the missing-Live-selector mutation UKI failed to build"
build_uki live-duplicate-selector \
  "quiet systemd.unit=neural-ice-live.target neuralice.live=1 neuralice.live=1" >/dev/null \
  || fail "the duplicate-Live-selector mutation UKI failed to build"
build_uki live-mixed-selector \
  "quiet systemd.unit=neural-ice-live.target neuralice.live=1 neuralice.autoinstall=1" >/dev/null \
  || fail "the mixed-selector mutation UKI failed to build"
# ...and the mixture in the other direction: one well-formed Install target
# selection that ALSO claims Live. Nothing about its shape is malformed, so only
# the mutual exclusion refuses it -- and it is the mixture that would actually
# run the destructive autoinstall.
build_uki live-installer-target-mixed \
  "quiet systemd.unit=neural-ice-installer.target neuralice.autoinstall=1 neuralice.live=1" \
  >/dev/null || fail "the Install-target-mixed mutation UKI failed to build"
# 🔴 AND THE ESCAPE FAMILY, ON REAL SIGNED BINARIES. Each of these is a validly
# signed UKI whose .cmdline is a well-formed Live selection plus ONE extra word.
# `systemd.debug_shell` is the one the independent review demonstrated end to end:
# systemd-debug-generator starts an unauthenticated root shell on tty9, and the
# destructive installer is one command away from it. The grammar these are
# refused by is exercised exhaustively and without a medium in
# image/test-installer-selector-grammar.sh; what is proved HERE is that the
# refusal survives the whole path -- a real signed PE, a real FAT ESP, a real GPT
# and the off-device inspector reading it back.
build_uki live-debug-shell \
  "quiet systemd.unit=neural-ice-live.target neuralice.live=1 systemd.debug_shell" \
  >/dev/null || fail "the debug-shell mutation UKI failed to build"
build_uki live-init-override \
  "quiet systemd.unit=neural-ice-live.target neuralice.live=1 init=/bin/sh" \
  >/dev/null || fail "the init-override mutation UKI failed to build"
build_uki live-emergency \
  "quiet systemd.unit=neural-ice-live.target neuralice.live=1 emergency" \
  >/dev/null || fail "the emergency mutation UKI failed to build"
build_uki live-permissive \
  "quiet systemd.unit=neural-ice-live.target neuralice.live=1 enforcing=0" \
  >/dev/null || fail "the permissive-SELinux mutation UKI failed to build"
build_uki live-mask-diagnostics \
  "quiet systemd.unit=neural-ice-live.target neuralice.live=1 systemd.mask=neural-ice-live-diagnostics.service" \
  >/dev/null || fail "the unit-mask mutation UKI failed to build"
for mutation in missing-selector duplicate-selector mixed-selector \
  installer-target-mixed debug-shell init-override emergency permissive \
  mask-diagnostics; do
  make_esp "$SEALED/live-$mutation.efi" "$SEALED/live-$mutation.efi.manifest" \
    installer-live.efi.manifest
  assemble "$ESP" "$SEALED/payload.img"
  inspect --expect-mode live >/dev/null 2>&1 \
    && fail "a Live medium with the $mutation mutation was accepted"
done
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
# The same mixture judged as an INSTALL medium: exactly one systemd.unit=, the
# correct target, the correct autoinstall word -- and a Live claim beside it.
make_esp "$SEALED/live-installer-target-mixed.efi" \
  "$SEALED/live-installer-target-mixed.efi.manifest" installer-install.efi.manifest
assemble "$ESP" "$SEALED/payload.img"
inspect >/dev/null 2>&1 \
  && fail "an Install medium that also seals a Live selector was accepted"

# THE REGISTRY-BACKED INSTALL, on a real signed medium. It is a supported
# shipping contract, so a correctly sealed one must be ACCEPTED -- and every
# malformed variant refused. A mutable tag is the interesting refusal: the digest
# is what makes a LAN mirror safe to consult, so a tag would undo the property
# the mirror rests on.
registry_digest="sha256:$(printf '%064d' 7)"
# 🔴 ONE CANONICAL ORIGIN, AND A MIRROR THAT IS ONLY TRANSPORT (independent
# review 2026-09-02, P0 #3). This vector used to seal `ghcr.io/...` and a bare
# mirror. Both are refusals now: the OS/source reference is exactly
# `release.example.test/<repo>@sha256:<digest>`, a registry medium seals the
# hashes of the release authorization its ESP must carry, and a mirror seals the
# CA it is trusted with and the exact release closure it declares READY.
registry_relauth="neuralice.relauth_sha256=$(printf 'a%.0s' {1..64}) neuralice.relauth_sig_sha256=$(printf 'b%.0s' {1..64})"
registry_mirror_pin="neuralice.mirror_ca_sha256=$(printf 'c%.0s' {1..64}) neuralice.mirror_ready=$(printf 'd%.0s' {1..64}) neuralice.mirror_manifest=$(printf 'e%.0s' {1..64}) neuralice.mirror_generation=7"
# The three ESP artefacts a registry medium's signature pins. The producer
# computes each karg from the bytes it stages, so the fixture does the same:
# write the bytes, then read their digests back. Naming a digest first and hoping
# some content matches it is not a thing a producer can do either.
python3 - "$TMP/relauth.json" "$TMP/relauth.sig" "$TMP/mirror-ca.crt" <<'PYEOF'
import sys

for index, path in enumerate(sys.argv[1:]):
    with open(path, "wb") as handle:
        handle.write(f"neural-ice media fixture artefact {index}\n".encode())
PYEOF
registry_relauth_sha="$(sha256sum "$TMP/relauth.json" | awk '{print $1}')"
registry_relauth_sig_sha="$(sha256sum "$TMP/relauth.sig" | awk '{print $1}')"
registry_mirror_ca_sha="$(sha256sum "$TMP/mirror-ca.crt" | awk '{print $1}')"
registry_relauth="neuralice.relauth_sha256=${registry_relauth_sha} neuralice.relauth_sig_sha256=${registry_relauth_sig_sha}"
registry_mirror_pin="neuralice.mirror_ca_sha256=${registry_mirror_ca_sha} neuralice.mirror_ready=$(printf 'd%.0s' {1..64}) neuralice.mirror_manifest=$(printf 'e%.0s' {1..64}) neuralice.mirror_generation=7"
build_uki installer-registry \
  "quiet systemd.unit=neural-ice-installer.target neuralice.autoinstall=1 enforcing=0 $PCR_POLICY_FIELDS neuralice.release_authority=release.example.test neuralice.source=registry neuralice.osimage=release.example.test/neural-ice/neural-ice-coreos@${registry_digest} ${registry_relauth} neuralice.mirror=bench.example.test:5000 ${registry_mirror_pin}" \
  >/dev/null || fail "the registry-install UKI failed to build"
registry_esp_files=(
  "::/ice-coreos/release-authorization.json=$TMP/relauth.json"
  "::/ice-coreos/release-authorization.sig=$TMP/relauth.sig"
  "::/ice-coreos/mirror-ca.crt=$TMP/mirror-ca.crt"
)
preseal_auth_files=(
  "::/ice-coreos/release-authorization.json=$TMP/relauth.json"
  "::/ice-coreos/release-authorization.sig=$TMP/relauth.sig"
)
make_esp "$SEALED/installer-registry.efi" "$SEALED/installer-registry.efi.manifest" \
  installer-install.efi.manifest "${registry_esp_files[@]}"
assemble "$ESP" "$SEALED/payload.img"
inspect >"$TMP/inspect-registry.out" \
  || { cat "$TMP/inspect-registry.out"; fail "a correctly sealed registry-install medium was refused"; }

# 🔴 THE PIN IS A REAL COMPARISON. Replace one staged artefact with different
# bytes -- the UKI is untouched, the signature is untouched -- and the medium
# must be refused. Without this the assertion above would pass just as happily
# against an inspector that never hashed anything.
printf 'a substituted release authorization\n' > "$TMP/relauth-swapped.json"
make_esp "$SEALED/installer-registry.efi" "$SEALED/installer-registry.efi.manifest" \
  installer-install.efi.manifest \
  "::/ice-coreos/release-authorization.json=$TMP/relauth-swapped.json" \
  "::/ice-coreos/release-authorization.sig=$TMP/relauth.sig" \
  "::/ice-coreos/mirror-ca.crt=$TMP/mirror-ca.crt"
assemble "$ESP" "$SEALED/payload.img"
TAMPERED_MEASUREMENTS="$TMP/tampered-measurements.json"
inspect --measurements-output "$TAMPERED_MEASUREMENTS" >/dev/null 2>&1 \
  && fail "a medium whose ESP release authorization was swapped after the cut was accepted"
[[ ! -e "$TAMPERED_MEASUREMENTS" ]] \
  || fail "a tampered medium left a measurement output behind"

# ...and an artefact the signature pins but the ESP does not carry is a medium
# that would refuse itself at install time. It is refused here instead.
make_esp "$SEALED/installer-registry.efi" "$SEALED/installer-registry.efi.manifest" \
  installer-install.efi.manifest \
  "::/ice-coreos/release-authorization.sig=$TMP/relauth.sig" \
  "::/ice-coreos/mirror-ca.crt=$TMP/mirror-ca.crt"
assemble "$ESP" "$SEALED/payload.img"
inspect >/dev/null 2>&1 \
  && fail "a registry medium missing the release authorization its signature pins was accepted"

# Restore the good registry medium for the assertions that follow.
make_esp "$SEALED/installer-registry.efi" "$SEALED/installer-registry.efi.manifest" \
  installer-install.efi.manifest "${registry_esp_files[@]}"
assemble "$ESP" "$SEALED/payload.img"
inspect >"$TMP/inspect-registry.out" \
  || fail "the restored registry medium was refused"
grep -q 'neuralice.source=registry' "$TMP/inspect-registry.out" \
  || fail "the inspector did not surface the sealed registry install source"
grep -q "neuralice.osimage=release.example.test/neural-ice/neural-ice-coreos@${registry_digest}" \
  "$TMP/inspect-registry.out" \
  || fail "the inspector did not surface the sealed digest-pinned appliance image"
grep -q 'neuralice.mirror=bench.example.test:5000' "$TMP/inspect-registry.out" \
  || fail "the inspector did not surface the sealed mirror transport"

# 🔴 THE v2 RELEASE PAIR ON A REAL SIGNED MEDIUM (mission B, T3a). An
# owner-sealed v2 medium seals the SHA-256 of the release manifest and of its
# detached signature on a medium source, and carries both on the ESP at
# ice-coreos/v2-release-manifest.json(.sig). It must be ACCEPTED, and each way
# the mutable ESP can disagree with the signed line must be refused: a swapped
# manifest (another correctly signed release), a swapped signature, a pin with no
# file, a file with no pin -- and the pair beside the v1 authorization pair.
python3 - "$TMP/v2-manifest.json" "$TMP/v2-manifest.json.sig" <<'PYEOF'
import sys

for index, path in enumerate(sys.argv[1:]):
    with open(path, "wb") as handle:
        handle.write(f"neural-ice v2 release fixture artefact {index}\n".encode())
PYEOF
v2_manifest_sha="$(sha256sum "$TMP/v2-manifest.json" | awk '{print $1}')"
v2_manifest_sig_sha="$(sha256sum "$TMP/v2-manifest.json.sig" | awk '{print $1}')"
v2_pair="neuralice.v2rel_sha256=${v2_manifest_sha} neuralice.v2rel_sig_sha256=${v2_manifest_sig_sha}"
# The produced order (build-installer-usb.sh: ... imgref, pcr_policy*, source, pair):
# the renderer refuses a pair anywhere but right after the medium source, so the
# fixture states the pair where the producer puts it.
v2_install_head="quiet systemd.unit=neural-ice-installer.target neuralice.autoinstall=1 enforcing=0 $PCR_POLICY_FIELDS neuralice.release_authority=release.example.test neuralice.imgref=release.example.test/neural-ice/neural-ice-coreos@${registry_digest}"
v2_install_line="$v2_install_head neuralice.source=medium"
v2_esp_files=(
  "::/ice-coreos/v2-release-manifest.json=$TMP/v2-manifest.json"
  "::/ice-coreos/v2-release-manifest.json.sig=$TMP/v2-manifest.json.sig"
)
build_uki installer-v2rel "$v2_install_line $v2_pair" >/dev/null \
  || fail "the v2 release medium UKI failed to build"
make_esp "$SEALED/installer-v2rel.efi" "$SEALED/installer-v2rel.efi.manifest" \
  installer-install.efi.manifest "${v2_esp_files[@]}"
assemble "$ESP" "$SEALED/payload.img"
inspect --expect-v2-release-manifest-sha256 "$v2_manifest_sha" \
  --expect-v2-release-manifest-sig-sha256 "$v2_manifest_sig_sha" >"$TMP/inspect-v2rel.out" \
  || { cat "$TMP/inspect-v2rel.out"; fail "a correctly sealed v2 release medium was refused"; }
grep -q "neuralice.v2rel_sha256=${v2_manifest_sha}" "$TMP/inspect-v2rel.out" \
  || fail "the inspector did not surface the sealed v2 manifest pin"
inspect >/dev/null 2>&1 \
  || fail "a v2 release medium was refused when the producer stated no v2 expectation"
# An approved pair the line does not seal, and a sealed pair nobody approved.
inspect --expect-v2-release-manifest-sha256 "$(printf 'x' | sha256sum | awk '{print $1}')" \
  --expect-v2-release-manifest-sig-sha256 "$v2_manifest_sig_sha" >/dev/null 2>&1 \
  && fail "a v2 medium sealing another manifest than the approved one was accepted"
inspect --expect-no-v2-release >/dev/null 2>&1 \
  && fail "a v2 medium nobody approved was accepted"
# The pin is a real comparison: swap the manifest on the ESP, the UKI untouched.
printf 'a substituted but correctly signed v2 release manifest\n' > "$TMP/v2-manifest-swapped.json"
make_esp "$SEALED/installer-v2rel.efi" "$SEALED/installer-v2rel.efi.manifest" \
  installer-install.efi.manifest \
  "::/ice-coreos/v2-release-manifest.json=$TMP/v2-manifest-swapped.json" \
  "::/ice-coreos/v2-release-manifest.json.sig=$TMP/v2-manifest.json.sig"
assemble "$ESP" "$SEALED/payload.img"
inspect >/dev/null 2>&1 \
  && fail "a v2 medium whose ESP manifest was swapped after the cut was accepted"
make_esp "$SEALED/installer-v2rel.efi" "$SEALED/installer-v2rel.efi.manifest" \
  installer-install.efi.manifest \
  "::/ice-coreos/v2-release-manifest.json=$TMP/v2-manifest.json" \
  "::/ice-coreos/v2-release-manifest.json.sig=$TMP/relauth.sig"
assemble "$ESP" "$SEALED/payload.img"
inspect >/dev/null 2>&1 \
  && fail "a v2 medium whose ESP signature was swapped after the cut was accepted"
# A pin with no file would refuse itself at install time; a file with no pin is
# an artefact anybody can replace.
make_esp "$SEALED/installer-v2rel.efi" "$SEALED/installer-v2rel.efi.manifest" \
  installer-install.efi.manifest "::/ice-coreos/v2-release-manifest.json=$TMP/v2-manifest.json"
assemble "$ESP" "$SEALED/payload.img"
inspect >/dev/null 2>&1 \
  && fail "a v2 medium missing the signature its UKI pins was accepted"
make_esp "$SEALED/installer-install.efi" "$SEALED/installer-install.efi.manifest" \
  installer-install.efi.manifest "${v2_esp_files[@]}"
assemble "$ESP" "$SEALED/payload.img"
inspect >/dev/null 2>&1 \
  && fail "an unpinned v2 release pair on the ESP was accepted"
# The pair beside the v1 authorization pair is two routes for one floor. The
# renderer refuses to cut such a line at all...
build_uki installer-v2rel-with-relauth "$v2_install_line $v2_pair ${registry_relauth}" >/dev/null 2>&1 \
  && fail "the UKI renderer sealed the v2 pair beside the authorization pair"
# ...and so does a pair on a registry source, and a pair that is not right after
# the medium source (its position is a contract the grammar readers cannot see).
build_uki installer-v2rel-registry \
  "${v2_install_head} neuralice.source=registry neuralice.osimage=release.example.test/neural-ice/neural-ice-coreos@${registry_digest} $v2_pair" >/dev/null 2>&1 \
  && fail "the UKI renderer sealed the v2 pair on a registry source"
build_uki installer-v2rel-before-source "$v2_install_head $v2_pair neuralice.source=medium" >/dev/null 2>&1 \
  && fail "the UKI renderer sealed the v2 pair BEFORE neuralice.source=medium"
build_uki installer-v2rel-after-seed \
  "$v2_install_line neuralice.seed_closure=$(printf 'd%.0s' {1..64}) $v2_pair" >/dev/null 2>&1 \
  && fail "the UKI renderer sealed the v2 pair after an offline seed token"
# A medium whose line was rendered in the produced order, seed tokens after the
# pair, is the one the inspector accepts (the grammar admits the seed beside it).
build_uki installer-v2rel-seed \
  "$v2_install_line $v2_pair neuralice.seed_closure=$(printf 'd%.0s' {1..64}) neuralice.seed_trusted_now=2026-10-06T10:00:00Z" >/dev/null \
  || fail "the produced order (source, pair, seed tokens) was refused by the UKI renderer"
# Restore the good registry medium for the assertions that follow.
make_esp "$SEALED/installer-registry.efi" "$SEALED/installer-registry.efi.manifest" \
  installer-install.efi.manifest "${registry_esp_files[@]}"
assemble "$ESP" "$SEALED/payload.img"
echo "  v2 release pair: accepted sealed, refused swapped / unpinned / unsealed / misplaced / beside the authorization pair"

# --------------------------------------------------------------------------- #
# THE SIGNED PCR7 RULES PAIR ON A REAL MEDIUM (ADR-0045, T5). `rules.json` is
# hash-bound by the signed UKI (`neuralice.pcr_rules`, with the sequence floor
# `neuralice.pcr_rules_seq`); `rules.json.sig` is not pinned by hash -- it is
# verified under the Owner key `neuralice.pcr_policy_key` pins -- but it exists
# on the ESP if and only if the pair is sealed. Every one of the refusals below
# is a medium the installer would refuse after the wipe was authorised, or an
# artefact on the mutable ESP that nothing the signature covers accounts for.
# --------------------------------------------------------------------------- #
pcr_rules_doc="$TMP/pcr-rules.json"
printf '%s' '{"schema":"ni-pcr-rules/1","sequence":12,"unbound_variables":"allow"}' > "$pcr_rules_doc"
printf 'b3duZXItc2ln' > "$TMP/pcr-rules.json.sig"
pcr_rules_sha="$(sha256sum "$pcr_rules_doc" | awk '{print $1}')"
pcr_rules_head="quiet systemd.unit=neural-ice-installer.target neuralice.autoinstall=1 enforcing=0 $PCR_POLICY_FIELDS"
pcr_rules_pair="neuralice.pcr_rules=${pcr_rules_sha} neuralice.pcr_rules_seq=12"
pcr_rules_esp_files=(
  "::/ice-coreos/pcr-rules/rules.json=$pcr_rules_doc"
  "::/ice-coreos/pcr-rules/rules.json.sig=$TMP/pcr-rules.json.sig"
)
build_uki installer-rules "$pcr_rules_head $pcr_rules_pair" >/dev/null \
  || fail "the PCR rules medium UKI failed to build"
make_esp "$SEALED/installer-rules.efi" "$SEALED/installer-rules.efi.manifest" \
  installer-install.efi.manifest "${pcr_rules_esp_files[@]}"
assemble "$ESP" "$SEALED/payload.img"
inspect >"$TMP/inspect-rules.out" \
  || { cat "$TMP/inspect-rules.out"; fail "a correctly sealed PCR rules medium was refused"; }
grep -q "neuralice.pcr_rules=${pcr_rules_sha}" "$TMP/inspect-rules.out" \
  || fail "the inspector did not surface the sealed rules pin"
# The pin is a real comparison: swap rules.json on the ESP, the UKI untouched.
printf '%s' '{"schema":"ni-pcr-rules/1","sequence":99,"unbound_variables":"allow"}' > "$TMP/pcr-rules-swapped.json"
make_esp "$SEALED/installer-rules.efi" "$SEALED/installer-rules.efi.manifest" \
  installer-install.efi.manifest \
  "::/ice-coreos/pcr-rules/rules.json=$TMP/pcr-rules-swapped.json" \
  "::/ice-coreos/pcr-rules/rules.json.sig=$TMP/pcr-rules.json.sig"
assemble "$ESP" "$SEALED/payload.img"
inspect >/dev/null 2>&1 \
  && fail "a medium whose rules.json was swapped after the cut was accepted"
# A pin with no file, in each direction.
make_esp "$SEALED/installer-rules.efi" "$SEALED/installer-rules.efi.manifest" \
  installer-install.efi.manifest "::/ice-coreos/pcr-rules/rules.json=$pcr_rules_doc"
assemble "$ESP" "$SEALED/payload.img"
inspect >/dev/null 2>&1 \
  && fail "a medium sealing a rules pair but carrying no rules signature was accepted"
make_esp "$SEALED/installer-rules.efi" "$SEALED/installer-rules.efi.manifest" \
  installer-install.efi.manifest "::/ice-coreos/pcr-rules/rules.json.sig=$TMP/pcr-rules.json.sig"
assemble "$ESP" "$SEALED/payload.img"
inspect >/dev/null 2>&1 \
  && fail "a medium sealing a rules pair but carrying no rules.json was accepted"
make_esp "$SEALED/installer-rules.efi" "$SEALED/installer-rules.efi.manifest" \
  installer-install.efi.manifest
assemble "$ESP" "$SEALED/payload.img"
inspect >/dev/null 2>&1 \
  && fail "a medium sealing a rules pair but carrying no rules file at all was accepted"
# A file with no pin is an artefact anybody can replace.
make_esp "$SEALED/installer-install.efi" "$SEALED/installer-install.efi.manifest" \
  installer-install.efi.manifest "${pcr_rules_esp_files[@]}"
assemble "$ESP" "$SEALED/payload.img"
inspect >/dev/null 2>&1 \
  && fail "unpinned rules files on the ESP were accepted"
# The kargs are a pair, at the reader of the finished medium too.
build_uki installer-rules-digest-only "$pcr_rules_head neuralice.pcr_rules=${pcr_rules_sha}" >/dev/null \
  || fail "the PCR rules digest-only UKI failed to build"
make_esp "$SEALED/installer-rules-digest-only.efi" "$SEALED/installer-rules-digest-only.efi.manifest" \
  installer-install.efi.manifest "${pcr_rules_esp_files[@]}"
assemble "$ESP" "$SEALED/payload.img"
inspect >/dev/null 2>&1 \
  && fail "a medium sealing the rules digest without its sequence floor was accepted"
build_uki installer-rules-seq-only "$pcr_rules_head neuralice.pcr_rules_seq=12" >/dev/null \
  || fail "the PCR rules sequence-only UKI failed to build"
make_esp "$SEALED/installer-rules-seq-only.efi" "$SEALED/installer-rules-seq-only.efi.manifest" \
  installer-install.efi.manifest "${pcr_rules_esp_files[@]}"
assemble "$ESP" "$SEALED/payload.img"
inspect >/dev/null 2>&1 \
  && fail "a medium sealing a sequence floor without its rules digest was accepted"
# Rules older than the sealed floor would refuse themselves after the wipe.
build_uki installer-rules-floor-above "$pcr_rules_head neuralice.pcr_rules=${pcr_rules_sha} neuralice.pcr_rules_seq=13" >/dev/null \
  || fail "the PCR rules above-the-rules floor UKI failed to build"
make_esp "$SEALED/installer-rules-floor-above.efi" "$SEALED/installer-rules-floor-above.efi.manifest" \
  installer-install.efi.manifest "${pcr_rules_esp_files[@]}"
assemble "$ESP" "$SEALED/payload.img"
inspect >/dev/null 2>&1 \
  && fail "a medium whose sealed sequence floor exceeds the rules' own sequence was accepted"
# One bound on the signature for every reader (4096 bytes: the installer's), and one
# strict reading of the rules for every reader (the builder's): a medium the installer
# or the engine would refuse after the wipe is refused here, at the cut.
rules_case() { # $1=name $2=rules doc $3=signature file -> builds and inspects the medium
  local name=$1 doc=$2 sig=$3 sha
  sha="$(sha256sum "$doc" | awk '{print $1}')"
  build_uki "installer-rules-$name" "$pcr_rules_head neuralice.pcr_rules=${sha} neuralice.pcr_rules_seq=7" >/dev/null \
    || fail "the PCR rules '$name' UKI failed to build"
  make_esp "$SEALED/installer-rules-$name.efi" "$SEALED/installer-rules-$name.efi.manifest" \
    installer-install.efi.manifest "::/ice-coreos/pcr-rules/rules.json=$doc" "::/ice-coreos/pcr-rules/rules.json.sig=$sig"
  assemble "$ESP" "$SEALED/payload.img"
  inspect
}
rules_ok="$TMP/pcr-rules-ok.json"
printf '%s' '{"schema":"ni-pcr-rules/1","sequence":7,"unbound_variables":"allow"}' > "$rules_ok"
rules_case strict-ok "$rules_ok" "$TMP/pcr-rules.json.sig" >/dev/null 2>&1 \
  || fail "the strict-reading control medium was refused"
head -c 5000 /dev/zero | tr '\0' 'A' > "$TMP/pcr-rules-bigsig.sig"
rules_case bigsig "$rules_ok" "$TMP/pcr-rules-bigsig.sig" >/dev/null 2>&1 \
  && fail "a 5000-byte rules signature (the installer refuses above 4096) was accepted"
printf '%s' '{"schema":"ni-pcr-rules/1","sequence":7,"sequence":8,"unbound_variables":"allow"}' > "$TMP/pcr-rules-dupkey.json"
rules_case dupkey "$TMP/pcr-rules-dupkey.json" "$TMP/pcr-rules.json.sig" >/dev/null 2>&1 \
  && fail "rules carrying a duplicated JSON key were accepted"
printf '%s' '{"schema":"ni-pcr-rules/1","sequence":1152921504606846976,"unbound_variables":"allow"}' > "$TMP/pcr-rules-hugeseq.json"
rules_case hugeseq "$TMP/pcr-rules-hugeseq.json" "$TMP/pcr-rules.json.sig" >/dev/null 2>&1 \
  && fail "rules whose sequence is above 2^53-1 were accepted"
printf '%s' '{"schema":"ni-pcr-rules/1","sequence":NaN,"unbound_variables":"allow"}' > "$TMP/pcr-rules-nan.json"
rules_case nan "$TMP/pcr-rules-nan.json" "$TMP/pcr-rules.json.sig" >/dev/null 2>&1 \
  && fail "rules carrying a non-finite number were accepted"
# Restore the good registry medium for the assertions that follow.
make_esp "$SEALED/installer-registry.efi" "$SEALED/installer-registry.efi.manifest" \
  installer-install.efi.manifest "${registry_esp_files[@]}"
assemble "$ESP" "$SEALED/payload.img"
echo "  PCR rules pair: accepted sealed, refused swapped / unpinned / unsealed / half-sealed / below the floor"

# FINAL MEASUREMENTS ARE FROM THE ACCEPTED BYTES, NOT THE BUILD INPUTS. Ask the
# real inspector to publish them, then independently parse the PE section table
# and stream the complete raw to derive every expected value.
MEASUREMENTS_DIR="$TMP/measurements"
mkdir -m 0700 "$MEASUREMENTS_DIR"
MEASUREMENTS="$MEASUREMENTS_DIR/medium.json"
inspect --measurements-output "$MEASUREMENTS" >/dev/null \
  || fail "the accepted registry medium did not produce final measurements"
python3 - "$RAW" "$SEALED/installer-registry.efi" \
  "$SEALED/installer-registry.efi.manifest" "$ROOT_HASH" "$MEASUREMENTS" <<'PYEOF'
import hashlib, json, pathlib, stat, struct, sys

raw, uki, manifest, root_hash, output = map(pathlib.Path, sys.argv[1:])
expected_root = str(root_hash)

def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(8 << 20), b""):
            digest.update(block)
    return digest.hexdigest()

pe = uki.read_bytes()
pe_offset = struct.unpack_from("<I", pe, 0x3C)[0]
coff = pe_offset + 4
count = struct.unpack_from("<H", pe, coff + 2)[0]
optional_size = struct.unpack_from("<H", pe, coff + 16)[0]
table = coff + 20 + optional_size
cmdline = None
for index in range(count):
    entry = table + index * 40
    name = pe[entry:entry + 8].rstrip(b"\0")
    if name == b".cmdline":
        raw_size = struct.unpack_from("<I", pe, entry + 16)[0]
        raw_pointer = struct.unpack_from("<I", pe, entry + 20)[0]
        cmdline = pe[raw_pointer:raw_pointer + raw_size]
        break
assert cmdline is not None
manifest_values = dict(
    line.split("=", 1)
    for line in manifest.read_text(encoding="ascii").splitlines()
    if "=" in line
)
expected = {
    "medium_raw_sha256": sha256_file(raw),
    "relauth_key_sha256": manifest_values["relauth_keyid"],
    "rootfs_verity_hash_algorithm": "sha256",
    "rootfs_verity_root_hash": expected_root,
    "schema": "neural-ice-installer-medium-measurements-v1",
    "uki_cmdline_sha256": hashlib.sha256(cmdline).hexdigest(),
    "uki_pe_sha256": hashlib.sha256(pe).hexdigest(),
}
encoded = output.read_bytes()
assert encoded == (json.dumps(expected, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
assert stat.S_IMODE(output.stat().st_mode) == 0o644
assert set(json.loads(encoded)) == set(expected)
PYEOF

# A byte-identical retry is the only accepted reuse of an output name.
before_measurements="$(sha256sum "$MEASUREMENTS")"
inspect --measurements-output "$MEASUREMENTS" >/dev/null \
  || fail "a byte-identical measurement retry was refused"
[[ "$(sha256sum "$MEASUREMENTS")" == "$before_measurements" ]] \
  || fail "a byte-identical retry rewrote the measurement document"

printf '{}\n' > "$MEASUREMENTS_DIR/conflict.json"
chmod 0644 "$MEASUREMENTS_DIR/conflict.json"
inspect --measurements-output "$MEASUREMENTS_DIR/conflict.json" >/dev/null 2>&1 \
  && fail "an existing different measurement document was replaced"
ln -s medium.json "$MEASUREMENTS_DIR/symlink.json"
inspect --measurements-output "$MEASUREMENTS_DIR/symlink.json" >/dev/null 2>&1 \
  && fail "a symlink measurement output was followed"
mkfifo "$MEASUREMENTS_DIR/fifo.json"
inspect --measurements-output "$MEASUREMENTS_DIR/fifo.json" >/dev/null 2>&1 \
  && fail "a FIFO measurement output was accepted"
python3 - "$MEASUREMENTS_DIR/oversize.json" <<'PYEOF'
import os, sys
with open(sys.argv[1], "wb") as handle:
    handle.truncate(2049)
os.chmod(sys.argv[1], 0o644)
PYEOF
inspect --measurements-output "$MEASUREMENTS_DIR/oversize.json" >/dev/null 2>&1 \
  && fail "an oversized existing measurement output was read or accepted"

# The pinned descriptor cannot be switched underneath the parser or hasher.
# Drive main() over this same real medium while injecting each race at a stable
# seam; neither attempt may publish a result.
python3 - "$ROOT/image/inspect-installer-media.py" "$RAW" "$MEASUREMENTS_DIR" \
  "$ROOT_HASH" "$PAYLOAD_DIGEST" "$POLICY_ID" <<'PYEOF'
import importlib.util, os, pathlib, shutil, sys

module_path, source_name, output_name = map(pathlib.Path, sys.argv[1:4])
root_hash, payload_digest, policy_id = sys.argv[4:]
spec = importlib.util.spec_from_file_location("media_inspector_race", module_path)
module = importlib.util.module_from_spec(spec)
assert spec.loader
spec.loader.exec_module(module)

def arguments(raw, output):
    return [
        str(module_path), "--raw", str(raw),
        "--expect-verity-root-hash", root_hash,
        "--expect-payload-digest", payload_digest,
        "--expect-mode", "install",
        "--expect-access-profile", "lab-managed",
        "--expect-hardware-target", "nvidia-gb10-arm64",
        "--expect-trust-policy-id", policy_id,
        "--measurements-output", str(output),
    ]

mutated = output_name / "mutated.raw"
shutil.copyfile(source_name, mutated)
mutation_output = output_name / "mutation.json"
original_sha256 = module.PinnedRaw.sha256
def mutate_then_hash(pinned):
    os.utime(pinned.path, None)
    return original_sha256(pinned)
module.PinnedRaw.sha256 = mutate_then_hash
sys.argv = arguments(mutated, mutation_output)
assert module.main() == 1
assert not mutation_output.exists()

module.PinnedRaw.sha256 = original_sha256
replaced = output_name / "replaced.raw"
replacement = output_name / "replacement.raw"
shutil.copyfile(source_name, replaced)
shutil.copyfile(source_name, replacement)
replacement_output = output_name / "replacement.json"
original_check_payload = module.check_payload
def replace_after_inspection(*args, **kwargs):
    result = original_check_payload(*args, **kwargs)
    os.replace(replacement, replaced)
    return result
module.check_payload = replace_after_inspection
sys.argv = arguments(replaced, replacement_output)
assert module.main() == 1
assert not replacement_output.exists()
PYEOF

# A LAB LIGHT medium binds one closed six-file pre-seal set to the signed UKI.
PRESEAL_DIR="$TMP/preseal"
mkdir "$PRESEAL_DIR"
printf '{"snapshot":"synthetic"}\n' > "$PRESEAL_DIR/delegation-snapshot.json"
printf 'synthetic snapshot signature\n' > "$PRESEAL_DIR/delegation-snapshot.sig"
printf '{"authorization":"synthetic"}\n' > "$PRESEAL_DIR/ota-release-authorization.json"
printf 'synthetic authorization signature\n' > "$PRESEAL_DIR/ota-release-authorization.sig"
printf '{"bom":"synthetic"}\n' > "$PRESEAL_DIR/bom.json"
python3 - "$PRESEAL_DIR" "$TMP/relauth.json" "$TMP/relauth.sig" \
  "release.example.test/neural-ice/neural-ice-appliance@${registry_digest}" \
  "$POLICY_ID" <<'PYEOF'
import hashlib, json, pathlib, sys
root, auth, sig = map(pathlib.Path, sys.argv[1:4])
target = sys.argv[4]
policy_id = sys.argv[5]
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
doc = {
    "access_policy_sha256":"1"*64,"access_profile":"lab-managed",
    "attestation_set_sha256":"2"*64,"bom_file_sha256":sha(root/"bom.json"),
    "bom_sha256":"3"*64,"bundle_seq":7,"channel_record_sha256":"4"*64,
    "compat_max":9,"compat_min":3,"delegation_seq":2,
    "delegation_snapshot_file_sha256":sha(root/"delegation-snapshot.json"),
    "delegation_snapshot_sha256":"3378808da1841f89db7dcc125fa1c7025662e9b3c099cf8f67a69c5f7341dad0",
    "delegation_snapshot_signature_sha256":sha(root/"delegation-snapshot.sig"),
    "hardware_target":"nvidia-gb10-arm64","installer_authorization_sha256":sha(auth),
    "installer_authorization_signature_sha256":sha(sig),
    "ota_release_authorization_file_sha256":sha(root/"ota-release-authorization.json"),
    "ota_release_authorization_sha256":"5"*64,
    "ota_release_authorization_signature_sha256":sha(root/"ota-release-authorization.sig"),
    "ota_state_profile":"owner-sealed-ota-state-v1","release_key_id":"release-lab-v1",
    "release_signing_role":"release-lab","ring":"lab",
    "schema":"neural-ice-installer-preseal-set-v1","seed_ref":"6"*40,
    "signed_boot_trust_policy_id":policy_id,
    "target_os_ref":target,"train":"lab-20260905","variant":"sealed-lab",
}
(root/"preseal-set.json").write_text(json.dumps(doc,sort_keys=True,separators=(",",":"))+"\n")
PYEOF
preseal_sha="$(sha256sum "$PRESEAL_DIR/preseal-set.json" | awk '{print $1}')"
# 🔴 A PRESEAL MEDIUM SEALS NO neuralice.relauth_* (FAB-0057 P1.1b, rule B):
# the set binds the pair by hash and neuralice.preseal binds the set. The ESP
# still carries the pair, and the inspector's preseal check is what pins it.
preseal_kargs="quiet systemd.unit=neural-ice-installer.target neuralice.autoinstall=1 enforcing=0 $PCR_POLICY_FIELDS neuralice.release_authority=release.example.test neuralice.source=registry neuralice.osimage=release.example.test/neural-ice/neural-ice-appliance@${registry_digest} neuralice.preseal=${preseal_sha}"
build_uki installer-preseal "$preseal_kargs" >/dev/null \
  || fail "the LAB LIGHT preseal UKI failed to build"
preseal_names=(preseal-set.json delegation-snapshot.json delegation-snapshot.sig \
  ota-release-authorization.json ota-release-authorization.sig bom.json)
make_preseal_esp() { # $1=uki name [$2=omitted name] [$3=replacement name=path]
  local uki_name=$1 omitted=${2:-} replacement=${3:-} name source
  make_esp "$SEALED/$uki_name.efi" "$SEALED/$uki_name.efi.manifest" \
    installer-install.efi.manifest "${preseal_auth_files[@]}"
  mmd -i "$ESP" ::/ice-coreos/preseal
  for name in "${preseal_names[@]}"; do
    [[ "$name" != "$omitted" ]] || continue
    source="$PRESEAL_DIR/$name"
    [[ "${replacement%%=*}" != "$name" ]] || source="${replacement#*=}"
    mcopy -i "$ESP" "$source" "::/ice-coreos/preseal/$name"
  done
}
make_preseal_esp installer-preseal
assemble "$ESP" "$SEALED/payload.img"
inspect >"$TMP/inspect-preseal.out" \
  || { cat "$TMP/inspect-preseal.out"; fail "the complete UKI-bound preseal set was refused"; }
grep -q "neuralice.preseal=${preseal_sha}" "$TMP/inspect-preseal.out" \
  || fail "the inspector did not surface the UKI-bound preseal set"

# The disconnected Install medium carries the same authenticated original host
# under its canonical digest in neuralice.imgref.  It has no registry source,
# OS image transport or mirror; the mutable ESP authorization remains pinned by
# this distinct signed UKI and binds the store's host index/child pair.
offline_preseal_kargs="quiet systemd.unit=neural-ice-installer.target neuralice.autoinstall=1 enforcing=0 $PCR_POLICY_FIELDS neuralice.release_authority=release.example.test neuralice.source=medium neuralice.imgref=release.example.test/neural-ice/neural-ice-appliance@${registry_digest} neuralice.preseal=${preseal_sha}"
build_uki installer-preseal-offline "$offline_preseal_kargs" >/dev/null \
  || fail "the fully offline preseal UKI failed to build"
make_preseal_esp installer-preseal-offline
assemble "$ESP" "$SEALED/payload.img"
OFFLINE_MEASUREMENTS="$TMP/offline-medium-measurements.json"
inspect --measurements-output "$OFFLINE_MEASUREMENTS" >"$TMP/inspect-preseal-offline.out" \
  || { cat "$TMP/inspect-preseal-offline.out"; fail "the complete offline original-host preseal medium was refused"; }
grep -q "neuralice.imgref=release.example.test/neural-ice/neural-ice-appliance@${registry_digest}" \
  "$TMP/inspect-preseal-offline.out" \
  || fail "the offline inspector did not retain the canonical original-host reference"
grep -q 'neuralice.source=medium' "$TMP/inspect-preseal-offline.out" \
  || fail "the offline UKI does not explicitly seal its medium transport"
if grep -qE 'neuralice\.(osimage|mirror)=' "$TMP/inspect-preseal-offline.out"; then
  fail "the offline medium inspection invented a network transport"
fi
python3 - "$RAW" "$SEALED/installer-preseal-offline.efi" \
  "$SEALED/installer-preseal-offline.efi.manifest" "$ROOT_HASH" \
  "$OFFLINE_MEASUREMENTS" <<'PYEOF'
import hashlib, json, pathlib, struct, sys

raw, uki, manifest, root_hash, output = map(pathlib.Path, sys.argv[1:])

def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(8 << 20), b""):
            digest.update(block)
    return digest.hexdigest()

pe = uki.read_bytes()
pe_offset = struct.unpack_from("<I", pe, 0x3C)[0]
coff = pe_offset + 4
count = struct.unpack_from("<H", pe, coff + 2)[0]
optional_size = struct.unpack_from("<H", pe, coff + 16)[0]
table = coff + 20 + optional_size
cmdline = None
for index in range(count):
    entry = table + index * 40
    if pe[entry:entry + 8].rstrip(b"\0") == b".cmdline":
        raw_size = struct.unpack_from("<I", pe, entry + 16)[0]
        raw_pointer = struct.unpack_from("<I", pe, entry + 20)[0]
        cmdline = pe[raw_pointer:raw_pointer + raw_size]
        break
assert cmdline is not None
manifest_values = dict(
    line.split("=", 1)
    for line in manifest.read_text(encoding="ascii").splitlines()
    if "=" in line
)
expected = {
    "medium_raw_sha256": sha256_file(raw),
    "relauth_key_sha256": manifest_values["relauth_keyid"],
    "rootfs_verity_hash_algorithm": "sha256",
    "rootfs_verity_root_hash": str(root_hash),
    "schema": "neural-ice-installer-medium-measurements-v1",
    "uki_cmdline_sha256": hashlib.sha256(cmdline).hexdigest(),
    "uki_pe_sha256": hashlib.sha256(pe).hexdigest(),
}
assert output.read_bytes() == (
    json.dumps(expected, sort_keys=True, separators=(",", ":")) + "\n"
).encode("ascii")
PYEOF

for name in "${preseal_names[@]}"; do
  make_preseal_esp installer-preseal "$name"
  assemble "$ESP" "$SEALED/payload.img"
  inspect >/dev/null 2>&1 && fail "a preseal medium missing $name was accepted"
  printf 'substituted %s\n' "$name" > "$TMP/preseal-swapped"
  make_preseal_esp installer-preseal '' "$name=$TMP/preseal-swapped"
  assemble "$ESP" "$SEALED/payload.img"
  inspect >/dev/null 2>&1 && fail "a preseal medium with drifted $name was accepted"
done

make_preseal_esp installer-preseal
printf 'foreign\n' > "$TMP/preseal-foreign"
mcopy -i "$ESP" "$TMP/preseal-foreign" ::/ice-coreos/preseal/foreign.json
assemble "$ESP" "$SEALED/payload.img"
inspect >/dev/null 2>&1 && fail "a preseal namespace with an unknown file was accepted"
# The line without neuralice.preseal must still be a valid registry line (so it
# seals the pair itself, as a registry medium without a set does); the refusal
# under test is the ESP carrying a set nothing binds.
build_uki installer-preseal-unbound "${preseal_kargs% neuralice.preseal=*} ${registry_relauth}" >/dev/null \
  || fail "the unbound preseal mutation UKI failed to build"
make_preseal_esp installer-preseal-unbound
assemble "$ESP" "$SEALED/payload.img"
inspect >/dev/null 2>&1 && fail "an ESP preseal set unbound by its UKI was accepted"

python3 - "$PRESEAL_DIR/preseal-set.json" "$TMP/preseal-duplicate.json" <<'PYEOF'
import pathlib, sys
raw = pathlib.Path(sys.argv[1]).read_text()
pathlib.Path(sys.argv[2]).write_text(raw.replace('{"access_policy_sha256":', '{"access_profile":"lab-managed","access_policy_sha256":'))
PYEOF
duplicate_sha="$(sha256sum "$TMP/preseal-duplicate.json" | awk '{print $1}')"
build_uki installer-preseal-duplicate "${preseal_kargs%neuralice.preseal=*}neuralice.preseal=${duplicate_sha}" >/dev/null \
  || fail "the duplicate-field preseal UKI failed to build"
make_preseal_esp installer-preseal-duplicate '' "preseal-set.json=$TMP/preseal-duplicate.json"
assemble "$ESP" "$SEALED/payload.img"
inspect >/dev/null 2>&1 && fail "a preseal set with a duplicate JSON field was accepted"

python3 - "$PRESEAL_DIR/preseal-set.json" "$TMP/preseal-unknown-field.json" <<'PYEOF'
import json, pathlib, sys
doc = json.loads(pathlib.Path(sys.argv[1]).read_text())
doc["unexpected"] = "field"
pathlib.Path(sys.argv[2]).write_text(json.dumps(doc,sort_keys=True,separators=(",",":"))+"\n")
PYEOF
unknown_field_sha="$(sha256sum "$TMP/preseal-unknown-field.json" | awk '{print $1}')"
build_uki installer-preseal-unknown "${preseal_kargs%neuralice.preseal=*}neuralice.preseal=${unknown_field_sha}" >/dev/null \
  || fail "the unknown-field preseal UKI failed to build"
make_preseal_esp installer-preseal-unknown '' "preseal-set.json=$TMP/preseal-unknown-field.json"
assemble "$ESP" "$SEALED/payload.img"
inspect >/dev/null 2>&1 && fail "a preseal set with an unknown JSON field was accepted"

python3 - "$PRESEAL_DIR/preseal-set.json" "$TMP/preseal-wrong-installer-auth.json" <<'PYEOF'
import json, pathlib, sys
doc = json.loads(pathlib.Path(sys.argv[1]).read_text())
doc["installer_authorization_sha256"] = "f" * 64
pathlib.Path(sys.argv[2]).write_text(json.dumps(doc,sort_keys=True,separators=(",",":"))+"\n")
PYEOF
wrong_auth_sha="$(sha256sum "$TMP/preseal-wrong-installer-auth.json" | awk '{print $1}')"
build_uki installer-preseal-wrong-auth "${preseal_kargs%neuralice.preseal=*}neuralice.preseal=${wrong_auth_sha}" >/dev/null \
  || fail "the wrong-authorization-binding preseal UKI failed to build"
make_preseal_esp installer-preseal-wrong-auth '' "preseal-set.json=$TMP/preseal-wrong-installer-auth.json"
assemble "$ESP" "$SEALED/payload.img"
inspect >/dev/null 2>&1 && fail "a preseal set that does not bind installer authorization bytes was accepted"

build_uki installer-preseal-restated "${preseal_kargs% neuralice.preseal=*} ${registry_relauth} neuralice.preseal=${preseal_sha}" >/dev/null \
  || fail "the restated-pair preseal mutation UKI failed to build"
make_preseal_esp installer-preseal-restated
assemble "$ESP" "$SEALED/payload.img"
inspect >/dev/null 2>&1 && fail "a preseal medium restating the authorization pair its set already binds was accepted (rule B)"

build_uki installer-preseal-customer "$preseal_kargs" VARIANT=prod >/dev/null \
  || fail "the customer-profile preseal mutation UKI failed to build"
make_preseal_esp installer-preseal-customer
assemble "$ESP" "$SEALED/payload.img"
inspect >/dev/null 2>&1 && fail "a customer-profile medium carrying a preseal set was accepted"

# Restore the ordinary registry fixture for the existing mutation cases below.
make_esp "$SEALED/installer-registry.efi" "$SEALED/installer-registry.efi.manifest" \
  installer-install.efi.manifest "${registry_esp_files[@]}"
assemble "$ESP" "$SEALED/payload.img"
build_uki installer-registry-tag \
  "quiet systemd.unit=neural-ice-installer.target neuralice.autoinstall=1 $PCR_POLICY_FIELDS neuralice.release_authority=release.example.test neuralice.source=registry neuralice.osimage=release.example.test/neural-ice/neural-ice-coreos:stable" \
  >/dev/null || fail "the mutable-tag registry mutation UKI failed to build"
build_uki installer-registry-orphan-mirror \
  "quiet systemd.unit=neural-ice-installer.target neuralice.autoinstall=1 $PCR_POLICY_FIELDS neuralice.mirror=bench.example.test" \
  >/dev/null || fail "the orphan-mirror mutation UKI failed to build"
build_uki installer-registry-no-image \
  "quiet systemd.unit=neural-ice-installer.target neuralice.autoinstall=1 $PCR_POLICY_FIELDS neuralice.source=registry" \
  >/dev/null || fail "the imageless-registry mutation UKI failed to build"
for mutation in registry-tag registry-orphan-mirror registry-no-image; do
  make_esp "$SEALED/installer-$mutation.efi" "$SEALED/installer-$mutation.efi.manifest" \
    installer-install.efi.manifest
  assemble "$ESP" "$SEALED/payload.img"
  inspect >/dev/null 2>&1 \
    && fail "an Install medium with the $mutation mutation was accepted"
done
make_esp "$SEALED/installer-install.efi" "$SEALED/installer-install.efi.manifest" \
  installer-install.efi.manifest
assemble "$ESP" "$SEALED/payload.img"
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
  EXTRA_KARGS="quiet systemd.unit=neural-ice-installer.target neuralice.autoinstall=1 $PCR_POLICY_FIELDS" \
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
python3 - "$TMP/payload-mutated.img" "$STORE_OFF" <<'PYEOF'
import sys

with open(sys.argv[1], "r+b") as image:
    image.seek(int(sys.argv[2]))
    original = image.read(1)
    if len(original) != 1:
        raise SystemExit("store mutation offset is outside the payload")
    image.seek(-1, 1)
    image.write(bytes([original[0] ^ 0xFF]))
PYEOF
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
python3 - "$TMP/payload-tree-mutated.img" "$TREE_OFF" <<'PYEOF'
import sys

with open(sys.argv[1], "r+b") as image:
    image.seek(int(sys.argv[2]))
    original = image.read(1)
    if len(original) != 1:
        raise SystemExit("hash-tree mutation offset is outside the payload")
    image.seek(-1, 1)
    image.write(bytes([original[0] ^ 0xFF]))
PYEOF
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
  "quiet systemd.unit=neural-ice-installer.target neuralice.autoinstall=1 $PCR_POLICY_FIELDS" \
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
# 5b) THE OPERATOR KEY HAS ONE TRANSPORT: THE SIGNED UKI. The producer used to
#     seal `neuralice.sshkey` AND stage the same key at ice-coreos/authorized_keys;
#     the installer refuses both together at preflight, and the bench medium of
#     2026-09-09 was refused on hardware exactly so. The inspector now refuses
#     that medium at the cut, reads the sealed key back against the approved
#     hash, and refuses a key on a medium that approved none.
# --------------------------------------------------------------------------- #
printf 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMediaFixtureOperatorKeyAAAAAAAAAAAAAAAAAAAAAAAAAAAAA fixture\n' \
  > "$TMP/operator.pub"
operator_b64="$(base64 -w0 < "$TMP/operator.pub")"
operator_sha="$(sha256sum "$TMP/operator.pub" | awk '{print $1}')"
build_uki installer-keyed \
  "quiet systemd.unit=neural-ice-installer.target neuralice.autoinstall=1 enforcing=0 $PCR_POLICY_FIELDS neuralice.sshkey=$operator_b64" \
  >/dev/null || fail "the keyed Install UKI failed to build"
make_esp "$SEALED/installer-keyed.efi" "$SEALED/installer-keyed.efi.manifest" \
  installer-install.efi.manifest
assemble "$ESP" "$SEALED/payload.img"
inspect --expect-sshkey-sha256 "$operator_sha" >/dev/null \
  || fail "a medium sealing the approved operator key in its UKI alone was refused"
inspect --expect-no-sshkey >/dev/null 2>&1 \
  && fail "a medium sealing an operator key was accepted as keyless"
inspect --expect-sshkey-sha256 "$(printf 'other-key' | sha256sum | awk '{print $1}')" >/dev/null 2>&1 \
  && fail "a sealed operator key differing from the approved hash was accepted"
make_esp "$SEALED/installer-keyed.efi" "$SEALED/installer-keyed.efi.manifest" \
  installer-install.efi.manifest "::/ice-coreos/authorized_keys=$TMP/operator.pub"
assemble "$ESP" "$SEALED/payload.img"
inspect --expect-sshkey-sha256 "$operator_sha" >/dev/null 2>&1 \
  && fail "the bench medium of 2026-09-09 (operator key sealed in the UKI AND staged on the ESP) was accepted"
inspect >/dev/null 2>&1 \
  && fail "an operator key on both transports was accepted when no expectation was given"
make_esp "$SEALED/installer-install.efi" "$SEALED/installer-install.efi.manifest" \
  installer-install.efi.manifest "::/ice-coreos/authorized_keys=$TMP/operator.pub"
assemble "$ESP" "$SEALED/payload.img"
inspect --expect-no-sshkey >/dev/null 2>&1 \
  && fail "an ESP operator key on a medium that approved none was accepted"
inspect --expect-sshkey-sha256 "$operator_sha" >/dev/null 2>&1 \
  && fail "an approved key absent from the sealed line was accepted on the strength of an ESP copy"
make_esp "$SEALED/installer-install.efi" "$SEALED/installer-install.efi.manifest" \
  installer-install.efi.manifest
assemble "$ESP" "$SEALED/payload.img"
inspect --expect-no-sshkey >/dev/null || fail "the restored keyless medium was refused"

# --------------------------------------------------------------------------- #
# 6) THE PRODUCER MUST ACTUALLY DO ALL OF THIS. A perfect implementation that
#    nothing invokes is what the review found the first time.
# --------------------------------------------------------------------------- #
USB="$ROOT/image/build-installer-usb.sh"
# The bench sequence counter: read, +1, written back under a lock, one source only.
grep -Fq 'PCR_POLICY_SEQ="$(pcr_policy_seq_from_counter "$PCR_POLICY_SEQ_COUNTER_FILE")" || exit 1' "$USB" \
  || fail "the media producer does not take the PCR policy sequence from the bench counter"
grep -Fq 'two sources for one sealed value' "$USB" \
  || fail "the media producer accepts both a fixed PCR_POLICY_SEQ and a counter file"
counter_fn="$TMP/counter-fn.sh"
awk '/^pcr_policy_seq_from_counter\(\) \{/,/^}$/' "$USB" > "$counter_fn"
grep -q '^pcr_policy_seq_from_counter()' "$counter_fn" || fail "cannot extract the sequence counter reader"
printf '41\n' > "$TMP/seq.counter"
got="$(bash -c 'source "$1"; pcr_policy_seq_from_counter "$2"' _ "$counter_fn" "$TMP/seq.counter")" \
  || fail "the sequence counter reader refused a valid counter"
{ [ "$got" = 42 ] && [ "$(cat "$TMP/seq.counter")" = 42 ]; } \
  || fail "the sequence counter did not advance 41 -> 42 (got '$got', file '$(cat "$TMP/seq.counter")')"
got="$(bash -c 'source "$1"; pcr_policy_seq_from_counter "$2"' _ "$counter_fn" "$TMP/seq.counter")"
[ "$got" = 43 ] || fail "a second cut did not take the next sequence (got '$got')"
printf 'not-a-number\n' > "$TMP/seq.counter"
bash -c 'source "$1"; pcr_policy_seq_from_counter "$2"' _ "$counter_fn" "$TMP/seq.counter" >/dev/null 2>&1 \
  && fail "a malformed sequence counter was accepted"
ln -sf /dev/null "$TMP/seq.symlink"
bash -c 'source "$1"; pcr_policy_seq_from_counter "$2"' _ "$counter_fn" "$TMP/seq.symlink" >/dev/null 2>&1 \
  && fail "a symlinked sequence counter was accepted"
# The installer's console stays on the firmware framebuffer: the installer image
# must pin nvidia_drm to modeset=0 fbdev=0 (bench, 2026-09-09: every boot went
# dark at the nvidia-drm handover and nothing after it could be read).
grep -Fq "'options nvidia_drm modeset=0 fbdev=0'" "$ROOT/image/Containerfile.installer" \
  || fail "the installer image lets nvidia-drm take over the console"
grep -Fq 'image/build-installer-uki.sh' "$USB" || fail "the media producer does not build a UKI"
grep -Fq 'image/build-installer-root.sh' "$USB" \
  || fail "the media producer does not build the sealed installer root"
grep -Fq 'image/build-installer-payload.sh' "$USB" \
  || fail "the media producer does not assemble the sealed payload"
grep -Fq 'image/inspect-installer-media.py' "$USB" \
  || fail "the media producer does not inspect the medium it produced"
grep -Fq 'INSPECT_ARGS+=(--measurements-output "$SEALED_DIR/final-medium-measurements.json")' "$USB" \
  || fail "the registry Install producer does not request measurements in its caller-owned directory"
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
grep -Fq 'mkfs.fat -F32 -n NI-INSTALL "$ESPPART"' "$USB" \
  || fail "the media producer does not remake the ESP with its unambiguous installer label"
grep -Fq 'zero_partition "$ESPPART"' "$USB" \
  || fail "the media producer does not overwrite the ESP before remaking it; deleted files leave their bytes"
grep -Fq 'MEDIA_MODE' "$USB" \
  || fail "the media producer does not build a single-purpose medium"
grep -Fq 'UKI_KARGS+=("neuralice.source=medium")' "$USB" \
  || fail "the offline producer relies on an implicit source default instead of sealing its transport"
grep -Fq 'systemd.unit=neural-ice-installer.target' "$USB" \
  || fail "the media producer does not seal the dedicated fail-closed installer target"
grep -Fq 'systemd.unit=neural-ice-live.target' "$USB" \
  || fail "the media producer does not seal the dedicated Live target"
grep -Fq 'rd.systemd.gpt_auto=0' "$USB" \
  || fail "the media producer lets systemd-gpt-auto compete with its verified overlay root"
grep -Fq '"luks=0"' "$USB" \
  || fail "the media producer lets the inherited appliance crypttab race target encryption"
grep -Fq 'UKI_KARGS=("${CONSOLE_KARGS[@]}" "rd.systemd.gpt_auto=0"' "$USB" \
  || fail "the media producer hardcodes quiet instead of taking the console words from MEDIA_VERBOSE_CONSOLE"
grep -Fq 'MEDIA_VERBOSE_CONSOLE=1 is a LAB medium input' "$USB" \
  || fail "the media producer lets a non-lab medium seal a verbose console"
grep -Fq -- '--build-arg "INSTALLER_VERBOSE_CONSOLE=${MEDIA_VERBOSE_CONSOLE}"' "$USB" \
  || fail "the media producer does not carry the verbose console into the installer image and its initramfs"
grep -Fq 'CONSOLE_KARGS=("console=tty0")' "$USB" \
  || fail "a verbose lab medium does not make the screen the kernel console"
grep -Fq "kernel.printk = 7 4 1 7" "$ROOT/image/Containerfile.installer" \
  || fail "the installer image does not raise the console printk level on a verbose lab medium"
grep -Fq 'UKI_KARGS+=("neuralice.sshkey=${_sshkey_b64}")' "$USB" \
  || fail "the installer SSH key remains replaceable on mutable vfat instead of sealed in the UKI"
# ...and sealed ONLY there. The runtime refuses a key carried on both the sealed
# command line and the ESP (ota/neural-ice-autoinstall.sh step 1b); a producer
# that stages the ESP copy next to the sealed karg cuts a medium that refuses
# itself on hardware (bench medium, 2026-09-09).
grep -Fq 'installer-ssh-key.sh" install' "$USB" \
  && fail "the media producer stages the operator key on the ESP as well as in the sealed UKI"
grep -Fq -- '--expect-sshkey-sha256 "$SSH_AUTHORIZED_KEYS_SHA256"' "$USB" \
  || fail "the media producer does not have the inspector read the sealed operator key back against the approved hash"
grep -Fq -- 'INSPECT_ARGS+=(--expect-no-sshkey)' "$USB" \
  || fail "the media producer does not have the inspector refuse a key on a medium that approved none"
grep -Fq 'SSH_AUTHORIZED_KEYS_FILE is an Install medium input' "$USB" \
  || fail "the media producer silently drops an operator key given to a Live cut"
grep -Fq 'neuralice.live=1' "$USB" \
  || fail "the media producer does not seal an affirmative Live selector"
grep -Fq 'PRESEAL_SET_DIR and PRESEAL_SET_SHA256 must be supplied together' "$USB" \
  || fail "the media producer accepts a partial preseal build input"
grep -Fq 'UKI_KARGS+=("neuralice.preseal=${PRESEAL_SET_SHA256}")' "$USB" \
  || fail "the media producer does not bind the protected preseal snapshot into the UKI"
preseal_snapshot_line="$(grep -n 'python3 "$PRESEAL_HELPER" snapshot' "$USB" | head -1 | cut -d: -f1)"
uki_build_line="$(grep -n 'bash "$REPO_ROOT/image/build-installer-uki.sh"' "$USB" | head -1 | cut -d: -f1)"
preseal_install_line="$(grep -n 'sudo python3 "$PRESEAL_HELPER" install' "$USB" | head -1 | cut -d: -f1)"
media_inspect_line="$(grep -n 'python3 "$REPO_ROOT/image/inspect-installer-media.py"' "$USB" | head -1 | cut -d: -f1)"
[[ -n "$preseal_snapshot_line" && -n "$uki_build_line" && -n "$preseal_install_line" \
   && -n "$media_inspect_line" && "$preseal_snapshot_line" -lt "$uki_build_line" \
   && "$uki_build_line" -lt "$preseal_install_line" \
   && "$preseal_install_line" -lt "$media_inspect_line" ]] \
  || fail "the producer does not snapshot, UKI-bind, stage and independently inspect preseal evidence in order"

# 🔴 THE v2 RELEASE PAIR IS ON THE PATH, IN ORDER (mission B, T3a). A sealing
# function nothing calls is a medium that silently carries no v2 pin: the early
# shape check must precede the long image build, the seal must follow the medium
# source in the kargs, the ESP staging must precede the inspection that reads the
# pair back, and the inspector must be asked for exactly the staged hashes.
grep -Fq 'V2_RELEASE_MANIFEST="${V2_RELEASE_MANIFEST:-}"' "$USB" \
  || fail "the media producer takes no V2_RELEASE_MANIFEST input"
grep -Fq 'V2_RELEASE_MANIFEST_SIG="${V2_RELEASE_MANIFEST_SIG:-}"' "$USB" \
  || fail "the media producer takes no V2_RELEASE_MANIFEST_SIG input"
v2_early_line="$(grep -nx 'assert_v2_release_inputs' "$USB" | head -1 | cut -d: -f1)"
v2_image_build_line="$(grep -n 'ni_step "build installer image' "$USB" | head -1 | cut -d: -f1)"
v2_source_line="$(grep -n 'UKI_KARGS+=("neuralice.source=medium")' "$USB" | head -1 | cut -d: -f1)"
v2_seal_line="$(grep -nx '          seal_v2_release_kargs' "$USB" | head -1 | cut -d: -f1)"
v2_uki_line="$(grep -n 'bash "$REPO_ROOT/image/build-installer-uki.sh"' "$USB" | head -1 | cut -d: -f1)"
v2_stage_line="$(grep -n 'ice-coreos/v2-release-manifest.json"$' "$USB" | head -1 | cut -d: -f1)"
v2_inspect_line="$(grep -n 'python3 "$REPO_ROOT/image/inspect-installer-media.py"' "$USB" | head -1 | cut -d: -f1)"
[[ -n "$v2_early_line" && -n "$v2_image_build_line" && -n "$v2_source_line" && -n "$v2_seal_line" \
   && -n "$v2_uki_line" && -n "$v2_stage_line" && -n "$v2_inspect_line" \
   && "$v2_early_line" -lt "$v2_image_build_line" && "$v2_source_line" -lt "$v2_seal_line" \
   && "$v2_seal_line" -lt "$v2_uki_line" && "$v2_uki_line" -lt "$v2_stage_line" \
   && "$v2_stage_line" -lt "$v2_inspect_line" ]] \
  || fail "the producer does not check, seal (after the medium source), UKI-bind, stage and inspect the v2 release pair in order"
# The content rules and the signature are judged BEFORE the image build (review 240,
# P3-3): the base image is local after the pull, the key is read out of it, and the
# build of the installer image comes after.
v2_base_verify_line="$(grep -nx 'verify_v2_release_against_base_image' "$USB" | head -1 | cut -d: -f1)"
v2_installer_build_line="$(grep -n 'sudo podman build --pull=never --platform linux/arm64' "$USB" | head -1 | cut -d: -f1)"
[[ -n "$v2_base_verify_line" && -n "$v2_installer_build_line" \
   && "$v2_early_line" -lt "$v2_base_verify_line" && "$v2_base_verify_line" -lt "$v2_installer_build_line" ]] \
  || fail "the producer does not verify the v2 release signature before building the installer image"
# The position of the pair on the produced line (contract section 11): nothing
# else is appended between the medium source and the pair, and the offline seed
# tokens come after it. The renderer refuses any other order at build time
# (test-installer-trust.sh); this is the producer's side of the same statement.
v2_seed_line="$(grep -n '^        seal_offline_seed_kargs medium$' "$USB" | head -1 | cut -d: -f1)"
[[ -n "$v2_seed_line" && "$v2_seal_line" -lt "$v2_seed_line" ]] \
  || fail "the producer seals the offline seed tokens before the v2 release pair"
! sed -n "$(( v2_source_line + 1 )),$(( v2_seal_line - 1 ))p" "$USB" | grep -Fq 'UKI_KARGS+=' \
  || fail "the producer appends a karg between neuralice.source=medium and the v2 release pair"
grep -Fq 'ice-coreos/v2-release-manifest.json.sig"' "$USB" \
  || fail "the producer stages no v2 release signature on the ESP"
grep -Fq '"$V2_RELEASE_PRIVATE_DIR/release-manifest.json" "$MNT/ice-coreos/v2-release-manifest.json"' "$USB" \
  || fail "the producer stages the v2 manifest from its source path, not from the private copy it validated"
grep -Fq -- '--expect-v2-release-manifest-sha256 "$V2_RELEASE_MANIFEST_SHA256"' "$USB" \
  || fail "the media producer does not have the inspector read the sealed v2 manifest hash back"
grep -Fq -- '--expect-v2-release-manifest-sig-sha256 "$V2_RELEASE_MANIFEST_SIG_SHA256"' "$USB" \
  || fail "the media producer does not have the inspector read the sealed v2 signature hash back"
grep -Fq -- 'INSPECT_ARGS+=(--expect-no-v2-release)' "$USB" \
  || fail "the media producer does not have the inspector refuse a v2 pin on a medium that approved none"
grep -Fq 'a v2 release manifest requires INSTALL_SOURCE=medium' "$USB" \
  || fail "the producer lets a registry medium take a v2 release manifest"

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
        installer_ssh_key_sha256=None,
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
