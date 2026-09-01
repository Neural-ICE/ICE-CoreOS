#!/usr/bin/env bash
#
# Neural ICE CoreOS — build a SINGLE-PURPOSE sealed installer medium.
#
#   1) build the SEALED INSTALLER ROOT and the container store, as squashfs
#   2) assemble the SEALED PAYLOAD: both images, a dm-verity hash tree for each,
#      and a header that names and hashes all four (image/build-installer-payload.sh)
#   3) build ONE signed UKI sealing the root's verity hash AND the header's digest
#   4) bootc-image-builder --type raw, then REPLACE what it produced: the ESP is
#      remade from scratch with the UKI as \EFI\BOOT\BOOTAA64.EFI, the boot
#      partition is zeroed, and the payload takes over the data partition
#
# 🔴 WHY THE MEDIUM IS SINGLE-PURPOSE (review 2026-09-01, P0 #2).
# The previous revision kept GRUB as "a two-entry menu that cannot name a
# kernel". That claim was about the grub.cfg this script WROTE; it was not a
# claim about the medium. GRUB itself retained its `linux`/`initrd` commands and
# its editable command line, and the raw still carried the signed standalone
# vmlinuz, the original initramfs and a whole ostree deployment. An operator at
# the GRUB console could therefore boot that kernel with kargs of their choosing
# and the sealed .cmdline, the dm-verity root, the access profile and the
# duplicate-karg controls were all simply not in the picture.
#
# The honest fix is not a better grub.cfg. It is to remove the boot manager: the
# firmware loads \EFI\BOOT\BOOTAA64.EFI, that file IS the signed UKI, and there
# is no second binary, no kernel, no initramfs and no configuration file anywhere
# on the medium for anything to choose between. A medium is therefore Live OR
# Install (MEDIA_MODE), decided when it is cut and stated by a signature -- which
# is exactly the trade the review authorised rather than weakening UKI sealing.
#
# 🔴 AND WHY THE PAYLOAD IS ITS OWN PARTITION (review 2026-09-01, P0 #1).
# The medium used to stage the root image, its hash tree and a `store/` directory
# on an ordinary filesystem. The store was authenticated by nothing, the medium
# could not actually boot (a dm-verity squashfs with no writable overlay cannot
# run an installer), and no off-device reader could hash any of it. All three are
# now one raw, self-describing extent whose header digest the UKI seals.
#
# Produces a flashable raw at $OUT/image/disk.raw. Flash with:
#   sudo dd if=<raw> of=/dev/sdX bs=64M oflag=direct conv=fsync status=progress
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# Exact base the installer is built on. No mutable or legacy default is allowed.
BASE_IMAGE="${BASE_IMAGE:-}"
# Exact imgref installed by the autoinstaller. The source artifact's native timer is
# masked; later movement is owned by the signed Fabric train controller via bootc switch.
# Defaulting to the exact BASE_IMAGE preserves byte identity through installation.
TARGET_IMGREF="${TARGET_IMGREF:-$BASE_IMAGE}"
INSTALLER_IMG="${INSTALLER_IMG:-localhost/ice-coreos-installer:local}"
# bib output (root-owned, ~40 GiB) lives OUTSIDE the checkout so it never
# pollutes the workspace (a root-owned file there breaks the next CI checkout).
OUT="${OUT:-${RUNNER_TEMP:-/var/tmp}/ice-coreos-bib}"
OUT_NAME="${OUT_NAME:-}"            # if set, copy the final raw to <REPO>/<OUT_NAME>.img
BG_SRC="${BG_SRC:-${REPO_ROOT}/image/branding/grub-bg.png}"
CONFIG="${CONFIG:-${REPO_ROOT}/image/config-installer.toml}"
BIB="${BIB:-quay.io/centos-bootc/bootc-image-builder:latest@sha256:2b52843ea2bfda73b0a08d97e76b734393b1d3a804681b9fabb26723bd3a2f0b}"
# LAB-MANAGED media may carry ONE operator public key on the ESP. The expected
# hash is mandatory so a mutable build-host pathname cannot silently change the
# key. Whether the installed image will honour it at all is decided by the
# image's own immutable access policy, checked below and re-checked at install
# time and at first boot — this staging step is a convenience, not the gate.
SSH_AUTHORIZED_KEYS_FILE="${SSH_AUTHORIZED_KEYS_FILE:-}"
SSH_AUTHORIZED_KEYS_SHA256="${SSH_AUTHORIZED_KEYS_SHA256:-}"
LAB_BASELINE_BOM_FILE="${LAB_BASELINE_BOM_FILE:-}"
LAB_BASELINE_BOM_SHA256="${LAB_BASELINE_BOM_SHA256:-}"
LAB_BASELINE_SIGNATURE_FILE="${LAB_BASELINE_SIGNATURE_FILE:-}"
LAB_BASELINE_SIGNATURE_SHA256="${LAB_BASELINE_SIGNATURE_SHA256:-}"
LAB_BASELINE_STAGE_ROOT=""
LAB_BASELINE_HELPER="$REPO_ROOT/ota/neural-ice-lab-baseline-handoff.sh"
# --------------------------------------------------------------------------- #
# THE SEALED BOOT PATH. All of these are explicit: a default here would be a
# silent decision about what a medium is allowed to install.
# --------------------------------------------------------------------------- #
# install | live. A medium is ONE of them: the mode decides which single signed
# UKI becomes \EFI\BOOT\BOOTAA64.EFI, and nothing else bootable is left on the
# medium for a console to choose instead.
MEDIA_MODE="${MEDIA_MODE:-install}"
# The local name the staged container store gives the image the installer writes.
STORE_IMAGE_NAME="${STORE_IMAGE_NAME:-localhost/bootc}"
# prod | sealed-lab | debug. Derives the access profile sealed into the UKI.
# It is READ BACK off the base image below and must agree -- a medium that seals
# a profile the image it carries does not state is a medium whose two halves
# disagree about what it is.
VARIANT="${VARIANT:-}"
HARDWARE_TARGET="${HARDWARE_TARGET:-}"
# The measured-identity fingerprint list for HARDWARE_TARGET, produced by running
# `image/lib/hardware-identity.sh measure` ON the reference appliance. Absent, the
# build refuses: a hardware target nothing can be measured against is a word.
HARDWARE_IDENTITY_FILE="${HARDWARE_IDENTITY_FILE:-}"
TRUST_POLICY_ROOT="${TRUST_POLICY_ROOT:-$REPO_ROOT/secureboot/trust-policies}"
# systemd-stub, taken from the base image unless overridden.
UKI_STUB="${UKI_STUB:-}"
# Signing is opt-in and never happens by accident: BOTH must be supplied, and the
# certificate must be one the image's own trust policy approves.
UKI_SIGNING_KEY="${UKI_SIGNING_KEY:-}"
UKI_SIGNING_CERT="${UKI_SIGNING_CERT:-}"
# Refuse to produce an UNSIGNED medium unless the caller says so in as many
# words. An unsigned UKI boots nowhere with Secure Boot on, but it also produces
# a medium that LOOKS finished, and a medium that looks finished gets flashed.
ALLOW_UNSIGNED_MEDIA="${ALLOW_UNSIGNED_MEDIA:-0}"
SEALED_DIR=""
# shellcheck source=image/lib/installer-trust.sh
source "$REPO_ROOT/image/lib/installer-trust.sh"
# shellcheck source=image/lib/hardware-identity.sh
source "$REPO_ROOT/image/lib/hardware-identity.sh"
# shellcheck source=image/lib/installer-ssh-key.sh
source "$REPO_ROOT/image/lib/installer-ssh-key.sh"
# shellcheck source=image/lib/access-policy.sh
source "$REPO_ROOT/image/lib/access-policy.sh"

cleanup_lab_baseline_stage() {
  if [[ -n "$LAB_BASELINE_STAGE_ROOT" ]]; then
    chmod -R u+w -- "$LAB_BASELINE_STAGE_ROOT" 2>/dev/null || true
    rm -rf -- "$LAB_BASELINE_STAGE_ROOT"
    LAB_BASELINE_STAGE_ROOT=""
  fi
}

[[ -f "$CONFIG" ]] || { echo "ERROR: missing bib config $CONFIG" >&2; exit 1; }
[[ "$BASE_IMAGE" =~ @sha256:[0-9a-f]{64}$ ]] \
  || { echo "ERROR: BASE_IMAGE is required as a digest-pinned OCI reference" >&2; exit 1; }
[[ "$TARGET_IMGREF" =~ @sha256:[0-9a-f]{64}$ ]] \
  || { echo "ERROR: TARGET_IMGREF must be a digest-pinned OCI reference" >&2; exit 1; }
# The installer records TARGET_IMGREF as the OTA origin WITHOUT fetching it
# (bootc --skip-fetch-check: the install env is air-gapped by design). The
# publication proof therefore lives HERE, at media staging, where the network
# exists: a target that differs from the staged base must resolve in its
# registry, or a mistyped/unpublished digest would be silently recorded as
# the installed system's origin. Equality with BASE_IMAGE needs no fetch —
# the staged base is already content-addressed locally.
# WHERE the proof resolves. This repository is OPEN CORE and must not know where
# any private registry lives -- a boundary test enforces it. The caller, which
# does know, may therefore supply TARGET_PROOF_REF: the same digest reachable
# from the build plane. Unset, the proof resolves TARGET_IMGREF itself, which is
# the behaviour a public consumer gets.
#
# What the proof still catches either way is what it was written for: an
# unpublished or mistyped digest resolves nowhere. What a build-plane probe does
# not catch is a private mirror misconfigured for that repository -- which
# belongs in an explicit warm-up before a demo or an update, not here.
TARGET_PROOF_REF="${TARGET_PROOF_REF:-$TARGET_IMGREF}"
[[ "$TARGET_PROOF_REF" =~ @sha256:[0-9a-f]{64}$ ]] \
  || { echo "ERROR: TARGET_PROOF_REF must be a digest-pinned OCI reference" >&2; exit 1; }

if [[ "$TARGET_IMGREF" != "$BASE_IMAGE" ]]; then
  if command -v skopeo >/dev/null 2>&1; then
    # No sudo: this is a registry READ, and root holds none of the caller's
    # credentials. `sudo` resets the environment, so $REGISTRY_AUTH_FILE and
    # $DOCKER_CONFIG never reach it and the probe fails "unauthorized" on an
    # image the caller can read perfectly well. MEASURED 2026-08-22, at the last
    # step of a media build.
    skopeo inspect --raw "docker://${TARGET_PROOF_REF}" >/dev/null \
      || { echo "ERROR: TARGET_IMGREF does not resolve (unpublished or mistyped digest?): ${TARGET_IMGREF} — probed as ${TARGET_PROOF_REF}" >&2; exit 1; }
  else
    podman manifest inspect "docker://${TARGET_PROOF_REF}" >/dev/null 2>&1 \
      || sudo podman image exists "$TARGET_IMGREF" \
      || { echo "ERROR: TARGET_IMGREF does not resolve (no skopeo; podman could not find it): ${TARGET_IMGREF}" >&2; exit 1; }
  fi
fi
# The sealed boot path is not optional and has no defaults. Validate before the
# 40-minute bib run rather than after it.
[[ -n "$VARIANT" ]] || { echo "ERROR: VARIANT is required (prod|sealed-lab|debug)" >&2; exit 1; }
case "$MEDIA_MODE" in
  install|live) ;;
  *) echo "ERROR: MEDIA_MODE must be install or live, got: $MEDIA_MODE" >&2; exit 1 ;;
esac
SEALED_ACCESS_PROFILE="$(access_policy_for_variant "$VARIANT")" \
  || { echo "ERROR: no access policy is defined for VARIANT '$VARIANT'" >&2; exit 1; }
installer_trust_value_is_valid neuralice.hardware_target "$HARDWARE_TARGET" \
  || { echo "ERROR: HARDWARE_TARGET is required and must be a valid hardware target" >&2; exit 1; }
[[ -f "$HARDWARE_IDENTITY_FILE" && ! -L "$HARDWARE_IDENTITY_FILE" ]] \
  || { echo "ERROR: HARDWARE_IDENTITY_FILE is required — a hardware target no machine can be measured against is a word, not a binding. Produce it with 'image/lib/hardware-identity.sh measure' on the reference appliance." >&2; exit 1; }
[[ -d "$TRUST_POLICY_ROOT" ]] \
  || { echo "ERROR: TRUST_POLICY_ROOT does not exist: $TRUST_POLICY_ROOT" >&2; exit 1; }
if [[ -n "$UKI_SIGNING_KEY$UKI_SIGNING_CERT" ]]; then
  [[ -n "$UKI_SIGNING_KEY" && -n "$UKI_SIGNING_CERT" ]] \
    || { echo "ERROR: signing requires BOTH UKI_SIGNING_KEY and UKI_SIGNING_CERT" >&2; exit 1; }
elif [[ "$ALLOW_UNSIGNED_MEDIA" != 1 ]]; then
  echo "ERROR: no UKI signing key supplied. An unsigned medium boots nowhere with Secure Boot on, but it looks finished — and a medium that looks finished gets flashed. Set ALLOW_UNSIGNED_MEDIA=1 to build one deliberately." >&2
  exit 1
fi
installer_ssh_key_validate "$SSH_AUTHORIZED_KEYS_FILE" "$SSH_AUTHORIZED_KEYS_SHA256" \
  || { echo "ERROR: invalid installer SSH key input" >&2; exit 1; }
installer_ssh_key_require_matching_target "$SSH_AUTHORIZED_KEYS_FILE" "$BASE_IMAGE" "$TARGET_IMGREF" \
  || { echo "ERROR: installer SSH key cannot be bound to this install target" >&2; exit 1; }
lab_baseline_input_count=0
for lab_baseline_input in "$LAB_BASELINE_BOM_FILE" "$LAB_BASELINE_BOM_SHA256" \
  "$LAB_BASELINE_SIGNATURE_FILE" "$LAB_BASELINE_SIGNATURE_SHA256"; do
  [[ -z "$lab_baseline_input" ]] || lab_baseline_input_count=$((lab_baseline_input_count + 1))
done
case "$lab_baseline_input_count" in
  0) ;;
  4)
    [[ "$BASE_IMAGE" == "$TARGET_IMGREF" ]] \
      || { echo "ERROR: LAB baseline must be bound to the exact installed image digest" >&2; exit 1; }
    LAB_BASELINE_STAGE_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/ni-lab-baseline-media.XXXXXX")"
    chmod 0700 "$LAB_BASELINE_STAGE_ROOT"
    trap cleanup_lab_baseline_stage EXIT
    bash "$LAB_BASELINE_HELPER" stage-media \
      "$LAB_BASELINE_BOM_FILE" "$LAB_BASELINE_BOM_SHA256" \
      "$LAB_BASELINE_SIGNATURE_FILE" "$LAB_BASELINE_SIGNATURE_SHA256" \
      "$LAB_BASELINE_STAGE_ROOT"
    ;;
  *)
    echo "ERROR: LAB baseline requires BOM, signature and both exact SHA-256 values" >&2
    exit 1
    ;;
esac

# Build the dual-mode installer image FROM the chosen immutable base. Reusing a
# locally present digest is safe because the content address cannot drift.
echo "==> build installer image  FROM ${BASE_IMAGE}"
if sudo podman image exists "$BASE_IMAGE"; then
  echo "    (using local content-addressed ${BASE_IMAGE})"
else
  # `sudo` resets the environment, so root sees neither $REGISTRY_AUTH_FILE nor
  # $DOCKER_CONFIG and pulls anonymously -- which fails "unauthorized" on a
  # private base the caller can read perfectly well. The path is expanded by the
  # caller's shell BEFORE sudo, and root can read the file, so passing it
  # explicitly is what carries the credential across the privilege boundary.
  # MEASURED 2026-08-22, at the last step of a media build.
  pull_auth=()
  [[ -n "${REGISTRY_AUTH_FILE:-}" ]] && pull_auth=(--authfile "$REGISTRY_AUTH_FILE")
  sudo podman pull "${pull_auth[@]}" "$BASE_IMAGE"
fi
if [[ -n "$SSH_AUTHORIZED_KEYS_FILE" || -n "$LAB_BASELINE_STAGE_ROOT" ]]; then
  # The discriminator is the Secure Boot ANCHOR, not the debug posture.
  #
  # It used to be the "(debug)" PRETTY_NAME, which conflated two things: a debug
  # image (sshd unmasked, SELinux permissive, serial root autologin) and a build
  # we are allowed to hand an ESP key to. Since the first-boot service serves a
  # provisioned key on a SEALED image, `sealed-lab` is now the build we actually
  # install -- and the old check refused exactly that, which is what made the
  # medium's key unusable for anything but a debug box.
  #
  # What must stay closed is the CUSTOMER surface: a prod-anchored image must
  # never be openable by a crafted medium. Gating on the lab anchor keeps that
  # shut while letting the sealed lab build take the key, and it needs no update
  # when prod-v1 finally exists -- prod simply never matches.
  anchor="$(sudo podman image inspect "$BASE_IMAGE" \
    --format '{{index .Labels "ch.neural-ice.signed-boot-trust-policy-id"}}' 2>/dev/null || true)"
  [[ "$anchor" == neural-ice-secureboot-lab-v1 ]] \
    || { echo "ERROR: LAB-only ESP inputs require a lab-anchored base image (got '${anchor:-no anchor label}')" >&2; exit 1; }
fi
if [[ -n "$SSH_AUTHORIZED_KEYS_FILE" ]]; then
  # The anchor label above is a LABEL: metadata, trivially settable by whoever
  # builds an image, and read here on a build host. The access policy is a FILE
  # inside the image's read-only /usr, and it is the same file the autoinstaller
  # and the first-boot service will interrogate on the appliance. Reading it here
  # means a medium that could never be honoured is refused at staging time
  # instead of producing a key the installed system will (correctly) reject.
  #
  # `podman run` rather than `image inspect`: only the former can read a file out
  # of the image, and reading the file is the entire point.
  base_policy="$(sudo podman run --rm --entrypoint '' "$BASE_IMAGE" \
    cat /usr/lib/neural-ice/access-policy 2>/dev/null | tr -d '[:space:]' || true)"
  access_policy_permits_installer_ssh "$base_policy" \
    || { echo "ERROR: an operator SSH key requires a lab-managed base image (immutable access policy is '${base_policy:-unreadable}')" >&2; exit 1; }
  echo "    (base image access policy: ${base_policy} — an installer SSH key is permitted)"
fi
sudo podman build --pull=never --platform linux/arm64 \
  --build-arg "BASE_IMAGE=${BASE_IMAGE}" \
  -f image/Containerfile.installer -t "${INSTALLER_IMG}" "${REPO_ROOT}"

# --------------------------------------------------------------------------- #
# 🔴 ONE IMMUTABLE IDENTITY, RESOLVED HERE AND NOWHERE ELSE (review 2026-09-01,
# P1 #1).
#
# `$INSTALLER_IMG` is a local TAG, i.e. a mutable pointer. Everything after this
# line used to name it: the marker reads, the measured-identity list, the sealed
# root build, the sealed store staging, the dracut run and bootc-image-builder.
# Each of those is a separate resolution, and a concurrent build or a `podman
# tag` between any two of them produced a medium whose halves are different
# images -- both correctly hashed, both correctly signed, and installing bytes
# the medium's own checks assume are something else.
#
# The tag is resolved ONCE, immediately after the build that produced it, and
# every step below is handed $INSTALLER_IMAGE_REF instead. The tag is re-resolved
# at the end and must not have moved: a build that raced with another one is a
# refusal, not a medium.
# --------------------------------------------------------------------------- #
INSTALLER_IMAGE_ID="$(sudo podman image inspect --format '{{.Id}}' "$INSTALLER_IMG" 2>/dev/null \
  | tr -d '[:space:]' | sed 's/^sha256://')"
[[ "$INSTALLER_IMAGE_ID" =~ ^[0-9a-f]{64}$ ]] \
  || { echo "ERROR: the installer image build produced no resolvable immutable image ID" >&2; exit 1; }
readonly INSTALLER_IMAGE_ID
readonly INSTALLER_IMAGE_REF="sha256:${INSTALLER_IMAGE_ID}"
echo "    installer image id: ${INSTALLER_IMAGE_REF} (every step below names this, never the tag)"

# Assert the tag still points at the image this build produced. Called after each
# step that could span a concurrent build.
assert_installer_tag_unmoved() { # $1=what has just been done
  local now
  now="$(sudo podman image inspect --format '{{.Id}}' "$INSTALLER_IMG" 2>/dev/null \
    | tr -d '[:space:]' | sed 's/^sha256://')"
  [[ "$now" == "$INSTALLER_IMAGE_ID" ]] \
    || { echo "ERROR: ${INSTALLER_IMG} moved from ${INSTALLER_IMAGE_ID} to '${now:-nothing}' during $1; refusing to produce a medium assembled from two different images" >&2; exit 1; }
}

# --------------------------------------------------------------------------- #
# The medium's THREE identities must agree BEFORE anything is sealed: the
# variant this build was asked for, the profile the image's own immutable marker
# states, and the hardware target the image was built for. Sealing a word the
# image does not state would produce a medium whose runtime gate refuses it —
# on the appliance, after the operator has committed.
# --------------------------------------------------------------------------- #
img_read() { # $1=absolute path inside the immutable installer image
  sudo podman run --rm --entrypoint '' --net=none "$INSTALLER_IMAGE_REF" cat "$1" 2>/dev/null \
    | tr -d '[:space:]'
}
img_variant="$(img_read /usr/lib/neural-ice/appliance-variant)"
img_profile="$(img_read /usr/lib/neural-ice/access-policy)"
img_target="$(img_read /usr/lib/neural-ice/hardware-target)"
img_policy_id="$(img_read /usr/lib/neural-ice/signed-boot-trust-policy-id)"
[[ "$img_variant" == "$VARIANT" ]] \
  || { echo "ERROR: the installer image states variant '$img_variant' but this build was asked for '$VARIANT'" >&2; exit 1; }
[[ "$img_profile" == "$SEALED_ACCESS_PROFILE" ]] \
  || { echo "ERROR: the installer image states access profile '$img_profile' but variant '$VARIANT' derives '$SEALED_ACCESS_PROFILE'" >&2; exit 1; }
[[ "$img_target" == "$HARDWARE_TARGET" ]] \
  || { echo "ERROR: the installer image is built for hardware target '$img_target' but this build seals '$HARDWARE_TARGET'" >&2; exit 1; }
installer_trust_value_is_valid neuralice.trust_policy_id "$img_policy_id" \
  || { echo "ERROR: the installer image states no usable signed-boot trust policy id ('$img_policy_id')" >&2; exit 1; }
# The TRUST POLICY IS THE IMAGE'S, never a build argument. A caller-supplied one
# could name a policy the image was not built against, and every downstream
# comparison would then agree about a word nothing established.
TRUST_POLICY_ID="$img_policy_id"
echo "    installer image: variant=$img_variant profile=$img_profile target=$img_target trust=$TRUST_POLICY_ID"

# The measured-identity list must be the one the image ships, or the medium would
# seal a target the installed root cannot check itself against.
SEALED_DIR="$OUT/sealed"
sudo rm -rf "$OUT"; mkdir -p "$OUT" "$SEALED_DIR"
# `sudo` deliberately does NOT own this redirect (shellcheck SC2024): the file
# must be written by the CALLER, into a caller-created directory, so the rest of
# the build can read and diff it without another privilege hop.
# shellcheck disable=SC2024
if ! sudo podman run --rm --entrypoint '' --net=none "$INSTALLER_IMAGE_REF" \
  cat "/usr/lib/neural-ice/hardware-identity/${HARDWARE_TARGET}.fingerprints" \
  2>/dev/null > "$SEALED_DIR/image-identity.fingerprints"; then
  echo "ERROR: the installer image ships no measured-identity list for '$HARDWARE_TARGET'" >&2
  exit 1
fi
cmp -s "$SEALED_DIR/image-identity.fingerprints" "$HARDWARE_IDENTITY_FILE" \
  || { echo "ERROR: HARDWARE_IDENTITY_FILE differs from the list the installer image ships for '$HARDWARE_TARGET'" >&2; exit 1; }


# --------------------------------------------------------------------------- #
# THE SEALED IMAGES. One immutable squashfs for the installer root, one for the
# containers-storage the install reads FROM.
# --------------------------------------------------------------------------- #
echo "==> build the sealed installer root and image store"
sudo env \
  INSTALLER_IMG="$INSTALLER_IMAGE_REF" \
  ROOT_IMAGE_OUT="$SEALED_DIR/installer-root.img" \
  STORE_IMAGE_OUT="$SEALED_DIR/installer-store.img" \
  STORE_IMAGE_NAME="$STORE_IMAGE_NAME" \
  bash "$REPO_ROOT/image/build-installer-root.sh" \
  || { echo "ERROR: cannot build the sealed installer root and store" >&2; exit 1; }
sudo chown -R "$(id -u):$(id -g)" "$SEALED_DIR" 2>/dev/null || true
# The sealed-root builder resolves the same identity independently and records
# what it actually sealed. Reading it back closes the loop between the two
# scripts: a manifest naming another image is a build failure here, not a
# discrepancy a reviewer would have to notice.
SEALED_ROOT_MANIFEST="$SEALED_DIR/installer-root.img.manifest"
sealed_image_id="$(sed -n 's/^installer_image_id=//p' "$SEALED_ROOT_MANIFEST")"
sealed_store_image_id="$(sed -n 's/^store_image_id=//p' "$SEALED_ROOT_MANIFEST")"
[[ "$sealed_image_id" == "$INSTALLER_IMAGE_ID" ]] \
  || { echo "ERROR: the sealed installer root was built from image '${sealed_image_id:-nothing}', not ${INSTALLER_IMAGE_ID}" >&2; exit 1; }
[[ "$sealed_store_image_id" == "$INSTALLER_IMAGE_ID" ]] \
  || { echo "ERROR: the sealed image store holds image '${sealed_store_image_id:-nothing}', not ${INSTALLER_IMAGE_ID}; the medium would install a different image than it boots" >&2; exit 1; }
assert_installer_tag_unmoved "the sealed root and store build"

# --------------------------------------------------------------------------- #
# THE INITRAMFS THAT OPENS THEM. Built inside the installer image so it carries
# that image's kernel modules, with the verity module added — and it travels
# INSIDE the signed PE, which is the whole point: the code that verifies the
# payload, sets dm-verity up and builds the writable runtime is covered by the
# same signature as the kernel and the command line it reads.
#
# image/lib/installer-payload.sh is staged INTO the dracut module so the hook,
# the build and the installer all parse the sealed header with the same POSIX sh
# code. A second parser would be a second answer, and only one of them would be
# the one that was signed.
# --------------------------------------------------------------------------- #
echo "==> build the installer initramfs (dracut + neural-ice-installer-verity)"
DRACUT_MODULE="$SEALED_DIR/dracut-module"
rm -rf -- "$DRACUT_MODULE"; mkdir -p "$DRACUT_MODULE"
cp -- "$REPO_ROOT/image/initramfs/90neural-ice-installer-verity"/*.sh "$DRACUT_MODULE/"
cp -- "$REPO_ROOT/image/lib/installer-payload.sh" "$DRACUT_MODULE/installer-payload.sh"
sudo podman run --rm --entrypoint '' \
  -v "$DRACUT_MODULE":/ni-dracut:ro \
  -v "$SEALED_DIR":/ni-out \
  "$INSTALLER_IMAGE_REF" bash -euxo pipefail -c '
    kver="$(ls -1 /usr/lib/modules | head -1)"
    [ -n "$kver" ]
    install -d -m 0755 /usr/lib/dracut/modules.d/90neural-ice-installer-verity
    cp /ni-dracut/*.sh /usr/lib/dracut/modules.d/90neural-ice-installer-verity/
    chmod 0755 /usr/lib/dracut/modules.d/90neural-ice-installer-verity/*.sh
    dracut --force --no-hostonly --reproducible --add neural-ice-installer-verity \
      --kver "$kver" /ni-out/installer-initramfs.img
    cp "/usr/lib/modules/$kver/vmlinuz" /ni-out/vmlinuz
    cp /usr/lib/os-release /ni-out/os-release
    # systemd-stub, from the image rather than the build host: the stub that
    # wraps the kernel must come from the same tree as the kernel.
    for stub in /usr/lib/systemd/boot/efi/linuxaa64.efi.stub \
                /usr/lib/systemd/boot/efi/linuxx64.efi.stub; do
      [ -f "$stub" ] && cp "$stub" /ni-out/stub.efi && break
    done
    test -f /ni-out/stub.efi
    cp /usr/lib/neural-ice/keys/release-authorization.pub /ni-out/release-authorization.pub
  ' || { echo "ERROR: cannot build the installer initramfs" >&2; exit 1; }
sudo chown -R "$(id -u):$(id -g)" "$SEALED_DIR" 2>/dev/null || true
# An `if`, not `[[ … ]] && cp`: under `set -e` a false test as the LAST command
# of an `&&` list at top level exits the script, and this line sits between two
# steps that must both run. (Same lesson as the mirror note in the autoinstaller.)
if [[ -n "$UKI_STUB" ]]; then
  cp -- "$UKI_STUB" "$SEALED_DIR/stub.efi"
fi

# --------------------------------------------------------------------------- #
# THE SEALED PAYLOAD. Both images, both hash trees, one header — and the header's
# SHA-256 is the single value the signature has to carry for every byte on the
# medium to be authenticated.
# --------------------------------------------------------------------------- #
echo "==> assemble the sealed payload"
env \
  ROOT_IMAGE="$SEALED_DIR/installer-root.img" \
  STORE_IMAGE="$SEALED_DIR/installer-store.img" \
  STORE_IMAGE_NAME="$STORE_IMAGE_NAME" \
  PAYLOAD_OUT="$SEALED_DIR/payload.img" \
  bash "$REPO_ROOT/image/build-installer-payload.sh" \
  || { echo "ERROR: cannot assemble the sealed installer payload" >&2; exit 1; }
PAYLOAD_MANIFEST="$SEALED_DIR/payload.img.manifest"
ROOT_VERITY_HASH="$(sed -n 's/^root_verity_hash=//p' "$PAYLOAD_MANIFEST")"
PAYLOAD_DIGEST="$(sed -n 's/^payload_header_sha256=//p' "$PAYLOAD_MANIFEST")"
PAYLOAD_BYTES="$(sed -n 's/^payload_bytes=//p' "$PAYLOAD_MANIFEST")"
[[ "$ROOT_VERITY_HASH" =~ ^[0-9a-f]{64}$ && "$PAYLOAD_DIGEST" =~ ^[0-9a-f]{64}$ && "$PAYLOAD_BYTES" =~ ^[0-9]+$ ]] \
  || { echo "ERROR: the payload build produced no usable manifest" >&2; exit 1; }
echo "    sealed verity root hash : $ROOT_VERITY_HASH"
echo "    sealed payload digest   : $PAYLOAD_DIGEST"

# --------------------------------------------------------------------------- #
# ONE SIGNED UKI. `neuralice.autoinstall=1` is a property of a signature, not of
# a keystroke — and with no second bootable object on the medium it is also not
# a property of a menu.
# --------------------------------------------------------------------------- #
case "$MEDIA_MODE" in
  install)
    UKI_NAME="installer-install"
    # SELinux permissive: bootc install relabels the target and the enforcing
    # live policy denies it. The explicit OTA origin is sealed here too, so the
    # recorded origin is no longer an attacker's choice.
    UKI_KARGS=("quiet" "systemd.unit=neural-ice-installer.target" \
      "neuralice.autoinstall=1" "enforcing=0" "neuralice.imgref=${TARGET_IMGREF}")
    ;;
  live)
    UKI_NAME="installer-live"
    UKI_KARGS=("quiet")
    ;;
esac
echo "==> build the ${MEDIA_MODE} UKI"
env \
  KERNEL="$SEALED_DIR/vmlinuz" \
  INITRD="$SEALED_DIR/installer-initramfs.img" \
  STUB="$SEALED_DIR/stub.efi" \
  OSREL="$SEALED_DIR/os-release" \
  ROOT_VERITY_HASH="$ROOT_VERITY_HASH" \
  PAYLOAD_DIGEST="$PAYLOAD_DIGEST" \
  VARIANT="$VARIANT" \
  HARDWARE_TARGET="$HARDWARE_TARGET" \
  HARDWARE_IDENTITY_FILE="$HARDWARE_IDENTITY_FILE" \
  TRUST_POLICY_ID="$TRUST_POLICY_ID" \
  TRUST_POLICY_ROOT="$TRUST_POLICY_ROOT" \
  RELEASE_AUTH_PUBKEY="$SEALED_DIR/release-authorization.pub" \
  UKI_OUT="$SEALED_DIR/$UKI_NAME.efi" \
  EXTRA_KARGS="${UKI_KARGS[*]}" \
  UKI_SIGNING_KEY="$UKI_SIGNING_KEY" \
  UKI_SIGNING_CERT="$UKI_SIGNING_CERT" \
  bash "$REPO_ROOT/image/build-installer-uki.sh" \
  || { echo "ERROR: cannot build the ${MEDIA_MODE} installer UKI" >&2; exit 1; }

assert_installer_tag_unmoved "the initramfs and UKI build"
echo "==> bootc-image-builder --type raw  (${INSTALLER_IMAGE_REF})  config=${CONFIG}"
sudo podman run --rm --privileged --security-opt label=type:unconfined_t \
  -v /var/lib/containers/storage:/var/lib/containers/storage \
  -v "$OUT":/output \
  -v "$CONFIG":/config.toml:ro \
  "$BIB" build --type raw --local --config /config.toml "$INSTALLER_IMAGE_REF"
assert_installer_tag_unmoved "the bootc-image-builder run"

RAW="$OUT/image/disk.raw"
[[ -f "$RAW" ]] || { echo "ERROR: raw not produced ($RAW)" >&2; exit 1; }

# --------------------------------------------------------------------------- #
# REPLACE WHAT bib PRODUCED.
#
# bib gives us a valid GPT, an ESP and a sized data partition; every byte of
# BOOTABLE content it wrote is then removed. This is deliberate and it is the
# whole of P0 #2: an ostree deployment, a GRUB, a shim and a standalone
# kernel/initramfs are exactly the alternative boot authorities a sealed medium
# must not carry, and deleting FILES would leave their bytes on the medium.
# Every one of the three partitions is therefore OVERWRITTEN, not edited.
# --------------------------------------------------------------------------- #
echo "==> replace the produced raw's boot content with the sealed medium"
LOOP="$(sudo losetup --find --show -P "$RAW")"; sudo udevadm settle
MNT=/mnt/ni-postproc
cleanup(){
  sudo umount -R "$MNT" 2>/dev/null || true
  sudo losetup -d "$LOOP" 2>/dev/null || true
  cleanup_lab_baseline_stage
}
trap cleanup EXIT

part_label() { sudo blkid -s LABEL -o value "$1" 2>/dev/null || true; }
part_bytes() { sudo blockdev --getsize64 "$1"; }
# Overwrite a whole partition with zeros. dd stops at ENOSPC on the last block,
# which is a successful full overwrite reported as a failure; the property is
# asserted by reading the medium back (image/inspect-installer-media.py), never
# by dd's exit status.
zero_partition() { sudo dd if=/dev/zero of="$1" bs=4M conv=fsync status=none 2>/dev/null || true; }

# The PAYLOAD partition = the big one bib wrote the ostree onto. It is the only
# one with room for the sealed payload, and after this step it holds nothing else.
PAYLOADPART=""; PAYLOADPART_NUM=""
for p in "${LOOP}"p*; do
  case "$(part_label "$p")" in
    EFI-SYSTEM | boot | ni-seed) continue ;;
  esac
  sudo mkdir -p "$MNT"
  if sudo mount -o ro "$p" "$MNT" 2>/dev/null; then
    if [[ -d "$MNT/ostree" ]]; then
      PAYLOADPART="$p"; PAYLOADPART_NUM="${p##*p}"
    fi
    sudo umount "$MNT"
  fi
  [[ -n "$PAYLOADPART" ]] && break
done
[[ -n "$PAYLOADPART" && "$PAYLOADPART_NUM" =~ ^[0-9]+$ ]] \
  || { echo "ERROR: cannot identify the data partition on the raw" >&2; exit 1; }

PAYLOADPART_BYTES="$(part_bytes "$PAYLOADPART")"
(( PAYLOADPART_BYTES >= PAYLOAD_BYTES )) \
  || { echo "ERROR: the sealed payload is ${PAYLOAD_BYTES} bytes and the data partition holds only ${PAYLOADPART_BYTES}; raise customizations.filesystem minsize in ${CONFIG}" >&2; exit 1; }
# Grow the payload image to the FULL partition, sparsely. Writing it then
# overwrites every ostree byte in one pass -- the holes read back as the zeros
# the header implies -- instead of leaving a tail of the old deployment behind
# the last region.
truncate -s "$PAYLOADPART_BYTES" "$SEALED_DIR/payload.img"
echo "    writing ${PAYLOADPART_BYTES} bytes of sealed payload to ${PAYLOADPART}"
sudo dd if="$SEALED_DIR/payload.img" of="$PAYLOADPART" bs=4M conv=fsync status=none \
  || { echo "ERROR: cannot write the sealed payload onto the medium" >&2; exit 1; }

# The GPT partition NAME the initramfs looks the payload up by. Not a trust
# input: a wrong candidate simply fails the sealed header digest.
sudo sfdisk --part-label "$LOOP" "$PAYLOADPART_NUM" ni-installer-payload \
  || { echo "ERROR: cannot name the installer payload partition" >&2; exit 1; }

# The BOOT partition loses everything. Nothing on this medium reads it: the root
# is the verified squashfs inside the payload, and there is no boot manager left
# to look for a kernel here.
BOOTPART=""; BOOTPART_NUM=""
for p in "${LOOP}"p*; do
  if [[ "$(part_label "$p")" == "boot" ]]; then BOOTPART="$p"; BOOTPART_NUM="${p##*p}"; break; fi
done
[[ -n "$BOOTPART" ]] || { echo "ERROR: boot partition not found" >&2; exit 1; }
echo "    zeroing the boot partition (${BOOTPART}) — no kernel, no initramfs, no BLS entry"
zero_partition "$BOOTPART"
sudo sfdisk --part-label "$LOOP" "$BOOTPART_NUM" ni-installer-void \
  || { echo "ERROR: cannot rename the emptied boot partition" >&2; exit 1; }

# The ESP is REMADE. Zeroing first and then mkfs is what makes "there is no shim,
# no GRUB and no fallback binary on this medium" a statement about bytes rather
# than about directory entries.
ESPPART=""
for p in "${LOOP}"p*; do
  [[ "$(part_label "$p")" == "EFI-SYSTEM" ]] && { ESPPART="$p"; break; }
done
[[ -n "$ESPPART" ]] || { echo "ERROR: installer ESP not found" >&2; exit 1; }
echo "    remaking the ESP (${ESPPART}) with a single signed EFI authority"
zero_partition "$ESPPART"
sudo mkfs.fat -F32 -n EFI-SYSTEM "$ESPPART" >/dev/null \
  || { echo "ERROR: cannot remake the installer ESP" >&2; exit 1; }
sudo partx -u "$LOOP" 2>/dev/null || true
sudo udevadm settle
sudo mkdir -p "$MNT"
sudo mount "$ESPPART" "$MNT"
sudo install -d -m 0755 "$MNT/EFI" "$MNT/EFI/BOOT" "$MNT/EFI/neural-ice"
# \EFI\BOOT\BOOTAA64.EFI is the removable-media default path: the firmware loads
# it with no NVRAM entry, no boot manager and no configuration file. It IS the
# signed UKI.
sudo install -m 0444 "$SEALED_DIR/$UKI_NAME.efi" "$MNT/EFI/BOOT/BOOTAA64.EFI"
sudo install -m 0444 "$SEALED_DIR/$UKI_NAME.efi.manifest" \
  "$MNT/EFI/neural-ice/$UKI_NAME.efi.manifest"
sudo cmp -s "$SEALED_DIR/$UKI_NAME.efi" "$MNT/EFI/BOOT/BOOTAA64.EFI" \
  || { echo "ERROR: the staged UKI differs from the one that was built" >&2; exit 1; }
if [[ -n "$SSH_AUTHORIZED_KEYS_FILE" ]]; then
  sudo bash "$REPO_ROOT/image/lib/installer-ssh-key.sh" install \
    "$SSH_AUTHORIZED_KEYS_FILE" "$SSH_AUTHORIZED_KEYS_SHA256" "$MNT"
fi
if [[ -n "$LAB_BASELINE_STAGE_ROOT" ]]; then
  sudo bash "$LAB_BASELINE_HELPER" stage-media \
    "$LAB_BASELINE_STAGE_ROOT/ice-coreos/ota-lab-baseline.json" \
    "$LAB_BASELINE_BOM_SHA256" \
    "$LAB_BASELINE_STAGE_ROOT/ice-coreos/ota-lab-baseline.sig" \
    "$LAB_BASELINE_SIGNATURE_SHA256" "$MNT"
fi
sync
sudo umount "$MNT"; sudo losetup -d "$LOOP"
cleanup_lab_baseline_stage
trap - EXIT

echo "==> Sealed single-purpose medium (${MEDIA_MODE}):"
echo "    EFI/BOOT/BOOTAA64.EFI  = ${UKI_NAME}.efi (signed UKI, the ONLY EFI authority)"
echo "    verity root hash       : ${ROOT_VERITY_HASH}"
echo "    sealed payload digest  : ${PAYLOAD_DIGEST}"
if [[ "$MEDIA_MODE" == install ]]; then
  echo "    OTA target sealed in the signature: neuralice.imgref=${TARGET_IMGREF}"
fi

# The medium is inspectable WITHOUT root and WITHOUT a loop device: the reader
# below parses the GPT, the FAT ESP and the raw payload extent straight out of
# the file, hashes every sealed region and proves the ESP carries nothing but the
# one signed binary. Running it here means a medium that does not carry what this
# script claims it staged never reaches a USB stick.
INSPECT_ARGS=(
  --raw "$RAW"
  --expect-verity-root-hash "$ROOT_VERITY_HASH"
  --expect-payload-digest "$PAYLOAD_DIGEST"
  --expect-mode "$MEDIA_MODE"
  --expect-trust-policy-id "$TRUST_POLICY_ID"
  --expect-access-profile "$SEALED_ACCESS_PROFILE"
  --expect-hardware-target "$HARDWARE_TARGET"
)
if [[ -z "$UKI_SIGNING_KEY" ]]; then INSPECT_ARGS+=(--allow-unsigned); fi
python3 "$REPO_ROOT/image/inspect-installer-media.py" "${INSPECT_ARGS[@]}" \
  || { echo "ERROR: the produced medium does not contain the artefacts this build staged" >&2; exit 1; }

if [[ -n "$OUT_NAME" ]]; then
  cp "$RAW" "${REPO_ROOT}/${OUT_NAME}.img"
  sudo chown "$(id -u):$(id -g)" "${REPO_ROOT}/${OUT_NAME}.img" 2>/dev/null || true
  # THE SEALED CORE, DECLARED FOR WHOEVER FINISHES THIS RAW (review 2026-09-01,
  # P1 #4). The PRELOADED build takes this image and keeps writing to it: it
  # grows the file, rewrites the GPT and appends a ~20 GB `ni-seed` partition. Its
  # final acceptance gate therefore has to re-run the inspector above on the
  # FINISHED raw -- and to do that it needs the values this build sealed, which
  # only this script knows. Handing them over in a file next to the image is what
  # makes that gate a check rather than a restatement of its own inputs.
  SEALED_CORE_FACTS="${REPO_ROOT}/${OUT_NAME}.img.sealed-core.json"
  python3 - "$SEALED_CORE_FACTS" \
    "$ROOT_VERITY_HASH" "$PAYLOAD_DIGEST" "$MEDIA_MODE" \
    "$SEALED_ACCESS_PROFILE" "$HARDWARE_TARGET" "$TRUST_POLICY_ID" \
    "$( [[ -z "$UKI_SIGNING_KEY" ]] && echo true || echo false )" <<'PY'
import json
import sys

path, root_hash, payload, mode, profile, target, policy_id, unsigned = sys.argv[1:]
document = {
    "access_profile": profile,
    "allow_unsigned": unsigned == "true",
    "hardware_target": target,
    "media_mode": mode,
    "payload_digest": payload,
    "schema": "neural-ice-sealed-core-facts-v1",
    "trust_policy_id": policy_id,
    "verity_root_hash": root_hash,
}
with open(path, "w", encoding="ascii") as handle:
    handle.write(json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n")
PY
  echo "==> Flashable image: ${REPO_ROOT}/${OUT_NAME}.img"
  echo "    sealed-core facts: ${SEALED_CORE_FACTS}"
else
  echo "==> Done. Flashable raw: $RAW"
fi
