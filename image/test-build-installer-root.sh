#!/usr/bin/env bash
# shellcheck disable=SC2016 # literal source-contract assertions below
# THE SEALED INSTALLER ROOT. podman, mksquashfs and skopeo are mocked -- a CI
# runner has no 10 GiB installer image and no root storage -- but everything the
# builder DECIDES is asserted on the arguments it computes and on the artefacts
# it produces, which is where the defects live.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="$ROOT/image/build-installer-root.sh"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/ni-installer-root.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

TOOLS="$TMP/tools"; ROOTFS="$TMP/rootfs"; mkdir -p "$TOOLS" "$ROOTFS"
ln -sf "$(command -v sha256sum)" "$TOOLS/sha256sum"
ln -sf "$(command -v xargs)" "$TOOLS/xargs" 2>/dev/null || true
cat > "$TOOLS/mountpoint" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$MOCK_STATE/mountpoint.args"
[ -e "$MOCK_STATE/overlay-mounted" ]
EOF
cat > "$TOOLS/umount" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$MOCK_STATE/umount.args"
[ "${MOCK_UMOUNT_FAIL:-0}" != 1 ] || exit 32
rm -f "$MOCK_STATE/overlay-mounted"
EOF

# A minimal but COMPLETE installer image root: the four files the whole trust
# construction reads out of it, plus the measured-identity list.
make_rootfs() {
  rm -rf "$ROOTFS"; mkdir -p "$ROOTFS/usr/lib/neural-ice/keys" \
    "$ROOTFS/usr/lib/neural-ice/hardware-identity"
  printf 'customer-locked\n' > "$ROOTFS/usr/lib/neural-ice/access-policy"
  printf 'nvidia-gb10-arm64\n' > "$ROOTFS/usr/lib/neural-ice/hardware-target"
  printf 'neural-ice-secureboot-lab-v1\n' \
    > "$ROOTFS/usr/lib/neural-ice/signed-boot-trust-policy-id"
  printf -- '-----BEGIN PUBLIC KEY-----\nk\n-----END PUBLIC KEY-----\n' \
    > "$ROOTFS/usr/lib/neural-ice/keys/release-authorization.pub"
  printf '%s\n' "$(printf 'devicetree:nvidia,gb10' | sha256sum | awk '{print $1}')" \
    > "$ROOTFS/usr/lib/neural-ice/hardware-identity/nvidia-gb10-arm64.fingerprints"
}
make_rootfs

# The installer image's IMMUTABLE ID. `podman image inspect --format {{.Id}}`
# is what the builder resolves once and uses everywhere; the mock answers with
# whatever $MOCK_IMAGE_ID says, so a test can make the tag "move".
IMAGE_ID="$(printf 'installer-image' | sha256sum | awk '{print $1}')"
OTHER_IMAGE_ID="$(printf 'someone-elses-image' | sha256sum | awk '{print $1}')"
cat > "$TOOLS/podman" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >> "\${MOCK_STATE:-$TMP}/podman.args"
case "\$1 \$2 \$3" in
  "image inspect --format")
    ref="\${*: -1}"
    case "\$ref" in
      localhost/*) printf 'sha256:%s\n' "\${MOCK_NAMED_IMAGE_ID:-$IMAGE_ID}" ;;
      *) printf 'sha256:%s\n' "\${MOCK_IMAGE_ID:-$IMAGE_ID}" ;;
    esac ;;
  *)
    case "\$1 \$2" in
      "image mount") printf '%s\n' "$ROOTFS" ;;
      "image umount") : ;;
      *) exit 2 ;;
    esac ;;
esac
EOF
# A deterministic "squashfs": a function of the tree's contents, so a changed
# root image changes the artefact exactly as mksquashfs would.
cat > "$TOOLS/mksquashfs" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$MOCK_STATE/mksquashfs.args"
src="$1"; out="$2"
find "$src" -type f -print0 | sort -z | xargs -0 sha256sum > "$out"
EOF
# The skopeo mock stages a store recording the image it was asked to copy, by
# ID -- which is what containers-storage actually records and what the builder
# now compares against the root it sealed.
cat > "$TOOLS/skopeo" <<'EOF'
#!/usr/bin/env bash
printf '%s
' "$*" >> "$MOCK_STATE/skopeo.args"
src=""
for arg in "$@"; do
  case "$arg" in containers-storage:localhost/*) src="${MOCK_NAMED_IMAGE_ID:-$EXPECTED_IMAGE_ID}" ;; esac
done
dest="${*: -1}"
name="${dest##*]}"
store="${dest#*overlay@}"; store="${store%%+*}"
mkdir -p "$store/overlay-images" "$store/overlay-layers" "$store/overlay"
printf '[{"id":"%s","names":["%s:latest"]}]
' "${MOCK_STORE_IMAGE_ID:-$src}" "$name"   > "$store/overlay-images/images.json"
printf 'staged
' > "$store/overlay-layers/layers.json"
EOF
ln -sf "$(command -v python3)" "$TOOLS/python3"
chmod +x "$TOOLS"/podman "$TOOLS"/mksquashfs "$TOOLS"/skopeo \
  "$TOOLS"/mountpoint "$TOOLS"/umount

export NI_INSTALLER_ROOT_TESTING=1 NI_INSTALLER_ROOT_TEST_TOOLS="$TOOLS"
build() { # $1=output dir, rest=env overrides
  local out=$1; shift
  mkdir -p "$out"
  env MOCK_STATE="$out" EXPECTED_IMAGE_ID="$IMAGE_ID" \
    INSTALLER_IMG="sha256:$IMAGE_ID" \
    INSTALLER_STORAGE_NAME="localhost/ice-coreos-installer:local" \
    ROOT_IMAGE_OUT="$out/installer-root.img" \
    STORE_IMAGE_OUT="$out/installer-store.img" \
    "$@" bash "$BUILD"
}

# --------------------------------------------------------------------------- #
# 1) DETERMINISM. Two builds of one image must produce the same bytes, or nobody
#    can tell a rebuild from a substitution -- and the verity root hash sealed
#    into the signed UKI is a function of exactly these bytes.
# --------------------------------------------------------------------------- #
build "$TMP/a" >/dev/null || fail "the first build failed"
build "$TMP/b" >/dev/null || fail "the second build failed"
[ "$(sed -n 's/^root_image_sha256=//p' "$TMP/a/installer-root.img.manifest")" \
  = "$(sed -n 's/^root_image_sha256=//p' "$TMP/b/installer-root.img.manifest")" ] \
  || fail "the sealed installer root is not reproducible"

# The mksquashfs invocation must pin every source of build-host state.
args="$(cat "$TMP/a/mksquashfs.args")"
for pinned in -all-root '-mkfs-time 0' '-all-time 0' -noappend -xattrs; do
  grep -Fq -- "$pinned" <<<"$args" || fail "mksquashfs is not invoked with $pinned"
done

# --------------------------------------------------------------------------- #
# 2) THE HASH FOLLOWS THE TREE. A build that produced a stale image would seal a
#    root hash describing bytes the medium is not standing on.
# --------------------------------------------------------------------------- #
printf 'sealed-lab\n' > "$ROOTFS/usr/lib/neural-ice/appliance-variant"
build "$TMP/c" >/dev/null || fail "the third build failed"
[ "$(sed -n 's/^root_image_sha256=//p' "$TMP/c/installer-root.img.manifest")" \
  != "$(sed -n 's/^root_image_sha256=//p' "$TMP/a/installer-root.img.manifest")" ] \
  || fail "changing the image did not change the sealed root"

# --------------------------------------------------------------------------- #
# 3) FAIL-CLOSED ON WHAT THE TRUST CONSTRUCTION READS. A root image missing one
#    of these verifies perfectly and then refuses at install time, on the
#    appliance, after the operator has committed.
# --------------------------------------------------------------------------- #
for required in usr/lib/neural-ice/access-policy usr/lib/neural-ice/hardware-target \
  usr/lib/neural-ice/signed-boot-trust-policy-id \
  usr/lib/neural-ice/keys/release-authorization.pub; do
  make_rootfs
  rm -f "$ROOTFS/$required"
  build "$TMP/missing" >/dev/null 2>&1 \
    && fail "a root image with no $required was sealed"
  rm -rf "$TMP/missing"
done
make_rootfs

# --------------------------------------------------------------------------- #
# 4) THE MEDIUM'S IMAGE STORE, AS ITS OWN IMMUTABLE IMAGE. With the root a verity
#    image the booted system is no longer an ostree deployment, so `bootc image
#    copy-to-storage` has nothing to copy: the bytes are staged here, at build
#    time. They are then frozen into a SECOND squashfs, because a directory
#    cannot be dm-verity protected and cannot be hashed off-device -- which is
#    what left the install payload attacker-replaceable (review 2026-09-01, P0 #1).
# --------------------------------------------------------------------------- #
build "$TMP/store-test" >/dev/null || fail "the store build failed"
[ -s "$TMP/store-test/installer-store.img" ] || fail "the medium image store image was not produced"
grep -Fq 'containers-storage:localhost/ice-coreos-installer:local' \
  "$TMP/store-test/skopeo.args" \
  || fail "the store is not staged from the skopeo-compatible stable local name"
grep -Fq "image inspect --format {{.Id}} localhost/ice-coreos-installer:local" \
  "$TMP/store-test/podman.args" \
  || fail "the stable transport name is not resolved immediately before staging"
grep -Fq 'overlay@' "$TMP/store-test/skopeo.args" \
  || fail "the store is not staged as an overlay containers-storage"
grep -q '^store_image_sha256=[0-9a-f]\{64\}$' "$TMP/store-test/installer-root.img.manifest" \
  || fail "the manifest does not pin the staged store image"
grep -qx 'store_image_name=localhost/bootc' "$TMP/store-test/installer-root.img.manifest" \
  || fail "the manifest does not record the name the store offers"
# The store image is built with the SAME pinned mksquashfs invocation as the root:
# a store whose bytes differ run to run would change the sealed payload digest on
# every rebuild and nobody could tell a rebuild from a substitution.
[ "$(grep -c -- '-mkfs-time 0' "$TMP/store-test/mksquashfs.args")" = 2 ] \
  || fail "the store image is not built with the same deterministic mksquashfs invocation as the root"

# A store that did not land, or one podman could not read as an additional image
# store, is a refusal rather than a warning.
cat > "$TOOLS/skopeo" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x "$TOOLS/skopeo"
build "$TMP/no-store" >/dev/null 2>&1 && fail "a build whose image store never landed succeeded"
cat > "$TOOLS/skopeo" <<'EOF'
#!/usr/bin/env bash
dest="${*: -1}"
store="${dest#*overlay@}"; store="${store%%+*}"
mkdir -p "$store/overlay-images"
printf '[]\n' > "$store/overlay-images/images.json"
EOF
chmod +x "$TOOLS/skopeo"
build "$TMP/partial-store" >/dev/null 2>&1 \
  && fail "a store with no overlay-layers directory was accepted; podman could not read it"
cat > "$TOOLS/skopeo" <<'EOF'
#!/usr/bin/env bash
dest="${*: -1}"
store="${dest#*overlay@}"; store="${store%%+*}"
mkdir -p "$store/overlay-images" "$store/overlay-layers" "$store/overlay"
printf '[{"names":["localhost/something-else:latest"]}]\n' > "$store/overlay-images/images.json"
EOF
chmod +x "$TOOLS/skopeo"
build "$TMP/misnamed-store" >/dev/null 2>&1 \
  && fail "a store that does not name the image the installer asks for was accepted"

# --------------------------------------------------------------------------- #
# 4b) ONE IMMUTABLE IDENTITY (review 2026-09-01, P1 #1).
#
# 🔴 THE FINDING. This script resolved the caller's reference once for the root
# filesystem and again, later, for the sealed store. The caller handed it a local
# TAG. A concurrent build or a `podman tag` between the two resolutions therefore
# produced root A plus store B: both extents validly hashed, both covered by the
# signature, and bootc installing B while every medium-path check assumes A.
# --------------------------------------------------------------------------- #
make_rootfs
# Section 4 left a deliberately broken skopeo behind; restore the honest one so
# the mutations below are the only thing wrong with each build.
cat > "$TOOLS/skopeo" <<'EOF'
#!/usr/bin/env bash
src=""
for arg in "$@"; do
  case "$arg" in containers-storage:localhost/*) src="${MOCK_NAMED_IMAGE_ID:-$EXPECTED_IMAGE_ID}" ;; esac
done
dest="${*: -1}"
name="${dest##*]}"
store="${dest#*overlay@}"; store="${store%%+*}"
mkdir -p "$store/overlay-images" "$store/overlay-layers" "$store/overlay"
printf '[{"id":"%s","names":["%s:latest"]}]\n' "${MOCK_STORE_IMAGE_ID:-$src}" "$name" \
  > "$store/overlay-images/images.json"
printf 'staged\n' > "$store/overlay-layers/layers.json"
EOF
chmod +x "$TOOLS/skopeo"
# A mutable reference is refused OUTRIGHT. Resolving it here would leave the
# caller free to move it between its reads and this script's.
for mutable in localhost/ice-coreos-installer:local localhost/bootc \
  'registry.example.test/x@sha256:not-a-digest' sha256:deadbeef; do
  out="$(env MOCK_STATE="$TMP/mutable" INSTALLER_IMG="$mutable" \
    ROOT_IMAGE_OUT="$TMP/mutable/root.img" STORE_IMAGE_OUT="$TMP/mutable/store.img" \
    bash "$BUILD" 2>&1)" && fail "the mutable reference '$mutable' was sealed"
  grep -Fq 'must be an immutable local image ID' <<<"$out" \
    || fail "'$mutable' was refused for the wrong reason: $out"
  rm -rf "$TMP/mutable"
done

# The ID must RESOLVE, and resolve to itself. Local storage answering with a
# different image is a build that was handed one thing and would seal another.
out="$(build "$TMP/moved" MOCK_IMAGE_ID="$OTHER_IMAGE_ID" 2>&1)" \
  && fail "an image ID that local storage resolves to another image was sealed"
grep -Fq 'refusing to seal an image that is not the one this build was given' <<<"$out" \
  || fail "a moved image ID was refused for the wrong reason: $out"
rm -rf "$TMP/moved"

# The stable name is a compatibility transport handle, not a relaxation of the
# immutable identity contract. A moved name must be refused before skopeo runs.
out="$(build "$TMP/named-moved" MOCK_NAMED_IMAGE_ID="$OTHER_IMAGE_ID" 2>&1)" \
  && fail "a stable transport name resolving to another image was accepted"
grep -Fq "resolves to '$OTHER_IMAGE_ID', not immutable image $IMAGE_ID" <<<"$out" \
  || fail "a moved transport name was refused for the wrong reason: $out"
[ ! -s "$TMP/named-moved/skopeo.args" ] \
  || fail "skopeo ran before the transport name's immutable identity was proved"
rm -rf "$TMP/named-moved"

# THE SEALED ROOT AND THE STAGED STORE MUST BE THE SAME IMAGE. This is the defect
# itself: a store holding a different image is what a raced build produces, and
# nothing downstream can see it because both halves hash and sign correctly.
out="$(build "$TMP/split" MOCK_STORE_IMAGE_ID="$OTHER_IMAGE_ID" 2>&1)" \
  && fail "a medium whose sealed root and staged store are different images was produced"
grep -Fq 'the medium would install a different image than the one it boots' <<<"$out" \
  || fail "a split root/store build was refused for the wrong reason: $out"
rm -rf "$TMP/split"

# A store holding TWO images is equally ambiguous: `localhost/bootc` could
# resolve to either, and the medium would carry no single answer.
cat > "$TOOLS/skopeo" <<EOF
#!/usr/bin/env bash
dest="\${*: -1}"
name="\${dest##*]}"
store="\${dest#*overlay@}"; store="\${store%%+*}"
mkdir -p "\$store/overlay-images" "\$store/overlay-layers" "\$store/overlay"
printf '[{"id":"%s","names":["%s:latest"]},{"id":"%s","names":["%s:other"]}]\n' \
  "$IMAGE_ID" "\$name" "$OTHER_IMAGE_ID" "\$name" > "\$store/overlay-images/images.json"
printf 'staged\n' > "\$store/overlay-layers/layers.json"
EOF
chmod +x "$TOOLS/skopeo"
out="$(build "$TMP/two-images" 2>&1)" \
  && fail "a store holding two images was sealed onto a medium"
grep -Fq 'a sealed medium carries exactly one' <<<"$out" \
  || fail "an ambiguous store was refused for the wrong reason: $out"
rm -rf "$TMP/two-images"

# A failed skopeo copy can leave this invocation's private overlay graphroot
# mounted. Cleanup must unmount exactly that graphroot before removing WORK.
cat > "$TOOLS/skopeo" <<'EOF'
#!/usr/bin/env bash
dest="${*: -1}"
store="${dest#*overlay@}"; store="${store%%+*}"
mkdir -p "$store/overlay"
touch "$MOCK_STATE/overlay-mounted"
exit 23
EOF
chmod +x "$TOOLS/skopeo"
build "$TMP/mounted-failure" >/dev/null 2>&1 \
  && fail "a failed skopeo copy unexpectedly succeeded"
[ ! -e "$TMP/mounted-failure/overlay-mounted" ] \
  || fail "cleanup did not unmount the task-owned overlay graphroot"
umount_arg="$(cat "$TMP/mounted-failure/umount.args")"
[[ "$umount_arg" == "-- ${TMPDIR:-/tmp}/ni-installer-root."*"/store/overlay" ]] \
  || fail "cleanup targeted something other than the task-owned overlay graphroot: $umount_arg"

# If the unmount itself fails, cleanup must preserve the invocation-owned work
# tree rather than recurse through a still-live mount.
out="$(build "$TMP/unmount-failure" MOCK_UMOUNT_FAIL=1 2>&1)" \
  && fail "a failed overlay unmount unexpectedly reported success"
grep -Fq 'preserving work directory' <<<"$out" \
  || fail "failed unmount did not explain that the work tree was preserved: $out"
preserved="$(sed -n 's/.*preserving work directory //p' <<<"$out" | tail -n1)"
[[ "$preserved" == "${TMPDIR:-/tmp}/ni-installer-root."* && -d "$preserved" ]] \
  || fail "failed unmount did not preserve its exact task-owned work tree: $preserved"
rm -f "$TMP/unmount-failure/overlay-mounted"
rm -rf -- "$preserved"

# Restore the honest mock and assert what the manifest now records: the immutable
# identity, on both halves, plus a digest of the four markers the runtime gate
# reads back off the medium.
cat > "$TOOLS/skopeo" <<'EOF'
#!/usr/bin/env bash
src=""
for arg in "$@"; do
  case "$arg" in containers-storage:localhost/*) src="${MOCK_NAMED_IMAGE_ID:-$EXPECTED_IMAGE_ID}" ;; esac
done
dest="${*: -1}"
name="${dest##*]}"
store="${dest#*overlay@}"; store="${store%%+*}"
mkdir -p "$store/overlay-images" "$store/overlay-layers" "$store/overlay"
printf '[{"id":"%s","names":["%s:latest"]}]\n' "${MOCK_STORE_IMAGE_ID:-$src}" "$name" \
  > "$store/overlay-images/images.json"
printf 'staged\n' > "$store/overlay-layers/layers.json"
EOF
chmod +x "$TOOLS/skopeo"
build "$TMP/identity" >/dev/null || fail "the honest build failed after the identity mutations"
manifest="$TMP/identity/installer-root.img.manifest"
grep -qx "schema=neural-ice-installer-root-manifest-v3" "$manifest" \
  || fail "the manifest schema did not move with the identity contract"
grep -qx "installer_image_id=$IMAGE_ID" "$manifest" \
  || fail "the manifest does not record the immutable image the root was sealed from"
grep -qx "store_image_id=$IMAGE_ID" "$manifest" \
  || fail "the manifest does not record the immutable image the store holds"
grep -q '^installer_root_marker_sha256=[0-9a-f]\{64\}$' "$manifest" \
  || fail "the manifest does not record the sealed root's immutable markers"
grep -Fq 'installer_image=' "$manifest" \
  && fail "the manifest still records a mutable image reference"

# The MARKER DIGEST FOLLOWS THE MARKERS. A build whose access policy changed must
# not produce the same statement about what the medium is.
before="$(sed -n 's/^installer_root_marker_sha256=//p' "$manifest")"
printf 'lab-managed\n' > "$ROOTFS/usr/lib/neural-ice/access-policy"
build "$TMP/marker-moved" >/dev/null || fail "the marker-mutation build failed"
[ "$(sed -n 's/^installer_root_marker_sha256=//p' "$TMP/marker-moved/installer-root.img.manifest")" \
  != "$before" ] \
  || fail "changing the sealed root's access policy did not change its recorded marker digest"
make_rootfs

# --------------------------------------------------------------------------- #
# 4c) AND THE MEDIA PRODUCER MUST CAPTURE THAT IDENTITY ATOMICALLY, then never
#     derive it from the mutable tag. A post-build tag inspect has a race window.
# --------------------------------------------------------------------------- #
USB="$ROOT/image/build-installer-usb.sh"
grep -Fq -- '--iidfile "$INSTALLER_IID_FILE"' "$USB" \
  || fail "the media producer does not atomically capture the exact podman build result"
grep -Fq 'INSTALLER_IID_DIR="$(mktemp -d ' "$USB" \
  || fail "the media producer does not isolate its atomic iidfile in a private directory"
grep -Fq 'INSTALLER_IID_FILE="$INSTALLER_IID_DIR/iid"' "$USB" \
  || fail "the media producer does not give Podman an absent iidfile path"
grep -Fq '[[ ! -e "$INSTALLER_IID_FILE" ]]' "$USB" \
  || fail "the media producer can hand Podman a pre-existing, permission-incompatible iidfile"
if grep -F 'INSTALLER_IID_FILE="$(mktemp ' "$USB" >/dev/null; then
  fail "the media producer pre-creates Podman's iidfile"
fi
grep -Fq 'INSTALLER_IMAGE_REF="$(sudo cat -- "$INSTALLER_IID_FILE" | tr -d '"'"'[:space:]'"'"')"' "$USB" \
  || fail "the media producer does not consume the atomic iidfile"
grep -Fq 'readonly INSTALLER_IMAGE_REF' "$USB" \
  || fail "the media producer keeps no single immutable reference"
grep -Fq 'INSTALLER_STORAGE_NAME="localhost/ice-coreos-installer:build-${INSTALLER_IMAGE_ID:0:16}"' "$USB" \
  || fail "the legacy skopeo/BIB transport tag is not task-unique by default"
grep -Fq 'INSTALLER_IMG="$INSTALLER_IMAGE_REF"' "$USB" \
  || fail "the sealed root builder is not handed the immutable image identity"
grep -Fq 'INSTALLER_STORAGE_NAME="$INSTALLER_STORAGE_NAME"' "$USB" \
  || fail "the skopeo-compatible name is not passed through the privileged root-builder environment"
grep -Fq 'assert_installer_tag_unmoved' "$USB" \
  || fail "the media producer does not refuse a tag that moved mid-build"
grep -Fq '[[ "$storage_now" == "$INSTALLER_IMAGE_ID" ]]' "$USB" \
  || fail "the media producer does not bind the stable transport name to the immutable image ID"
grep -Fq 'assert_installer_tag_unmoved "the immediate pre-bootc-image-builder binding"' "$USB" \
  || fail "the stable transport name is not re-bound immediately before BIB consumes it"
# Every step AFTER the resolution must name the immutable reference. The tag may
# only appear in the build that creates it and in the movement check itself.
usb_after_resolve() {
  awk '/^INSTALLER_IMAGE_REF=/{seen=1} seen' "$USB" | grep -vE '^[[:space:]]*#'
}
usb_after_resolve | grep -n '"\$INSTALLER_IMG"' | grep -v 'podman image inspect' \
  && fail "a build step after the identity resolution still names the mutable installer tag"
for immutable_step in \
  '--net=none "$INSTALLER_IMAGE_REF" cat "$1"' \
  '"$INSTALLER_IMAGE_REF" bash -euxo pipefail -c' \
  'build --type raw --local --config /config.toml "$INSTALLER_STORAGE_NAME"'; do
  grep -Fq -e "$immutable_step" "$USB" \
    || fail "a build step does not use its identity-checked image handle: $immutable_step"
done
# ...and the two halves the sealed-root builder produced must be read back and
# required to be the same image, rather than assumed to be.
grep -Fq '[[ "$sealed_store_image_id" == "$INSTALLER_IMAGE_ID" ]]' "$USB" \
  || fail "the media producer does not compare the staged store's image with the sealed root's"

# Pinned BIB rejects filesystem customization for raw builds. The selected
# config therefore makes no sizing claim; the producer's measured fit refusal
# remains the sole decision about whether the sealed payload fits.
DEFAULT_CONFIG="$ROOT/image/config-installer-default-size.toml"
[ -f "$DEFAULT_CONFIG" ] || fail "the BIB-compatible default-size config is missing"
grep -Ev '^[[:space:]]*(#|$)' "$DEFAULT_CONFIG" | grep -q . \
  && fail "the default-size raw config unexpectedly customizes the BIB layout"
grep -Fq 'CONFIG="${CONFIG:-${REPO_ROOT}/image/config-installer-default-size.toml}"' "$USB" \
  || fail "the media producer does not select the BIB-compatible raw config"
grep -Fq "BIB's raw data partition holds only" "$USB" \
  || fail "the producer no longer refuses a sealed payload that does not fit"

# The immutable installer image must contain both producer-side UKI tools that
# the EL10 base omitted: the real veritysetup applet and the ARM64 systemd stub.
INSTALLER_CONTAINERFILE="$ROOT/image/Containerfile.installer"
grep -Fq -- 'systemd-boot-unsigned-257-31.el10.aarch64.rpm' \
  "$INSTALLER_CONTAINERFILE" \
  || fail "the exact ARM64 systemd-boot-unsigned RPM is not pinned"
grep -Fq -- 'd4370eabdbd2085b5e1679cf68f577bf9288ad22f8077f8f274c56857d342300' \
  "$INSTALLER_CONTAINERFILE" \
  || fail "the pinned systemd-boot-unsigned RPM has no immutable checksum"
grep -Fq -- "dnf --disablerepo='*' -y install \"\$stub_rpm\"" "$INSTALLER_CONTAINERFILE" \
  || fail "the verified local RPM install can still resolve mutable repository packages"
grep -Fq 'verity_evr="$(rpm -q --qf' "$INSTALLER_CONTAINERFILE" \
  || fail "the veritysetup package is not pinned to the base cryptsetup release"
grep -Fq '"veritysetup-${verity_evr}"' \
  "$INSTALLER_CONTAINERFILE" \
  || fail "the real EL10 veritysetup package is not installed"
grep -Fq 'fuse-overlayfs-1.17-1.el10.aarch64' "$INSTALLER_CONTAINERFILE" \
  || fail "the installer does not pin the overlay helper required by its sealed store"
grep -Fq "test -x /usr/bin/fuse-overlayfs" "$INSTALLER_CONTAINERFILE" \
  || fail "the installer image build does not prove the pinned overlay helper is executable"
grep -Fq 'test ! -L /usr/sbin/veritysetup' "$INSTALLER_CONTAINERFILE" \
  || fail "the installer image build does not reject the broken cryptsetup symlink"
grep -Fq 'COPY ota/neural-ice-luks-token-evidence.py /usr/libexec/neural-ice-luks-token-evidence' \
  "$INSTALLER_CONTAINERFILE" \
  || fail "the installer silently inherits a stale destructive token validator from its base image"
# The pre-re-pin bridge (drop-in + unit copy + generator staged from the medium
# onto the deployment /etc) is retired. The medium must not carry it, and the
# installer must instead refuse an appliance whose own unit still cycles.
! grep -Eq 'COPY image/firstboot/(10-neural-ice-firstboot-ceremony-sysinit\.conf|neural-ice-firstboot-ceremony-generator|neural-ice-firstboot-tpm-ceremony\.service)' \
  "$INSTALLER_CONTAINERFILE" \
  || fail "the installer image still carries the retired first-boot ceremony bridge"
! grep -Fq '/usr/lib/neural-ice/firstboot-ceremony-generator' "$ROOT/ota/neural-ice-autoinstall.sh" \
  || fail "the installer still stages the retired first-boot ceremony generator"
! grep -Fq 'chcon -t systemd_generic_generator_exec_t' "$ROOT/ota/neural-ice-autoinstall.sh" \
  || fail "the installer still relabels a first-boot ceremony generator overlay"
grep -Fq 'ceremony_unit="$dep/usr/lib/systemd/system/neural-ice-firstboot-tpm-ceremony.service"' \
  "$ROOT/ota/neural-ice-autoinstall.sh" \
  || fail "the installer does not verify the pinned appliance's own first-boot ceremony unit"
grep -Fq 'retired first-boot ceremony bridge' "$ROOT/ota/neural-ice-autoinstall.sh" \
  || fail "the installer does not refuse a deployment that still carries the retired ceremony bridge"
# The ceremony/tmpfiles cycle is broken at its source (PrivateTmp=disconnected
# in the ceremony unit). A systemd.mask= karg on sysext/confext would persist
# across every bootc upgrade and disable the root-capable-extension gate.
! grep -Eq -- '--karg "systemd\.mask=systemd-(sysext|confext)\.service"' \
  "$ROOT/ota/neural-ice-autoinstall.sh" \
  || fail "the installer masks systemd-sysext/confext by karg instead of fixing the ceremony ordering"
grep -Fq 'COPY image/initramfs/91neural-ice-tpm-policy/neural-ice-tpm-policy.sh' \
  "$INSTALLER_CONTAINERFILE" \
  || fail "the installed deployment silently inherits a stale TPM initramfs hook from its base image"
grep -Fq 'COPY image/initramfs/91neural-ice-tpm-policy/neural-ice-tpm-policy.service' \
  "$INSTALLER_CONTAINERFILE" \
  || fail "the installed deployment has no ordered TPM policy staging service before cryptsetup"
grep -Fq 'COPY image/initramfs/91neural-ice-tpm-policy/systemd-cryptsetup-policy.conf' \
  "$INSTALLER_CONTAINERFILE" \
  || fail "a direct dracut cryptsetup start does not require TPM policy staging"
grep -Fq 'dracut --force --no-hostonly --reproducible --kver "$kver" "$initramfs"' \
  "$INSTALLER_CONTAINERFILE" \
  || fail "the installed deployment does not regenerate its initramfs after staging the local TPM hook"
grep -Fq 'installed initramfs unexpectedly carries the installer-media marker' \
  "$INSTALLER_CONTAINERFILE" \
  || fail "the installed initramfs is not proved distinct from the virgin-only installer initramfs"
grep -Fq 'lsinitrd -f /usr/lib/systemd/system/neural-ice-tpm-policy.service' \
  "$INSTALLER_CONTAINERFILE" \
  || fail "the installed initramfs is not proved to contain the cryptsetup ordering service"
grep -Fq 'lsinitrd -f /etc/systemd/system/systemd-cryptsetup@.service.d/10-neural-ice-policy.conf' \
  "$INSTALLER_CONTAINERFILE" \
  || fail "the installed initramfs is not proved to order direct cryptsetup starts after policy staging"
grep -Fq "grep -Fq -- '--panic-on-corruption'" "$INSTALLER_CONTAINERFILE" \
  || fail "the installer image build does not prove the required verity option exists"
grep -Fq 'test -s /usr/lib/systemd/boot/efi/linuxaa64.efi.stub' "$INSTALLER_CONTAINERFILE" \
  || fail "the installer image build does not prove the ARM64 UKI stub is present"

# --------------------------------------------------------------------------- #
# 5) THE OVERRIDE MUST NOT BE A PRODUCTION BYPASS, and the producer must call it.
# --------------------------------------------------------------------------- #
grep -Fq 'a tool override is forbidden in a privileged process' "$BUILD" \
  || fail "the builder's tool override is not refused under a privileged process"
grep -Fq 'image/build-installer-root.sh' "$ROOT/image/build-installer-usb.sh" \
  || fail "the media producer never builds the sealed installer root"
grep -Fq 'ROOT_IMAGE="$SEALED_DIR/installer-root.img"' "$ROOT/image/build-installer-usb.sh" \
  || fail "the sealed payload is not assembled from the root image that was just built"
grep -Fq 'STORE_IMAGE="$SEALED_DIR/installer-store.img"' "$ROOT/image/build-installer-usb.sh" \
  || fail "the sealed payload is not assembled from the store image that was just built"
# 🔴 AND THE 10 GiB RUNTIME COPY IS GONE. `bootc image copy-to-storage` cannot
# work on a verity-rooted medium -- there is no ostree deployment to copy -- so a
# medium that still called it could not install at all.
AUTOINSTALL="$ROOT/ota/neural-ice-autoinstall.sh"
if grep -vE '^[[:space:]]*#' "$AUTOINSTALL" | grep -q 'copy-to-storage'; then
  fail "the installer still copies the booted image into podman storage"
fi

# --------------------------------------------------------------------------- #
# 6) WHAT THE INSTALLER DOES WITH THE STORE. A verified extent nothing registers
#    is a medium that cannot install; a registration nothing asserts is a
#    `bootc install` failure after the target disk has been destroyed.
# --------------------------------------------------------------------------- #
line_of() { grep -n -- "$1" "$AUTOINSTALL" | head -1 | cut -d: -f1; }
grep -Fq 'additionalimagestores = ["$STORE_MOUNT"]' "$AUTOINSTALL" \
  || fail "the installer does not register the verified store as a read-only additional image store"
grep -Fq 'export CONTAINERS_STORAGE_CONF="$INSTALLER_STORAGE_CONF"' "$AUTOINSTALL" \
  || fail "the installer's own podman calls do not use the storage configuration it wrote"
grep -Fq 'graphroot = "$INSTALLER_STORAGE_GRAPHROOT"' "$AUTOINSTALL" \
  || fail "the installer does not keep its writable image graph off the verified root overlay"
grep -Fq 'runroot = "$INSTALLER_STORAGE_RUNROOT"' "$AUTOINSTALL" \
  || fail "the installer does not keep its containers runroot in the runtime tmpfs"
grep -Fq 'mount_program = "/usr/bin/fuse-overlayfs"' "$AUTOINSTALL" \
  || fail "the installer does not select the mount program used to produce its sealed overlay store"
grep -Fq 'readonly INSTALLER_STORAGE_ROOT=/run/neural-ice-container-runtime' "$AUTOINSTALL" \
  || fail "the writable container runtime can share the verified installer's mount hierarchy"
grep -Fq 'mount -t tmpfs -o nodev,nosuid,mode=0755' "$AUTOINSTALL" \
  || fail "the installer assumes /run is tmpfs instead of mounting a proved writable storage backing"
grep -Fq 'findmnt -n -o FSTYPE --target "$INSTALLER_STORAGE_GRAPHROOT"' "$AUTOINSTALL" \
  || fail "the installer does not prove that its writable container graph is backed by tmpfs"
grep -Fq '|| die "the installer'\''s writable container storage is not backed by tmpfs"' "$AUTOINSTALL" \
  || fail "the installer does not refuse an overlay-on-overlay writable container graph"
grep -Fq '"installer image store after writable-runtime mount"' "$AUTOINSTALL" \
  || fail "the installer does not re-prove its sealed store after mounting the writable runtime"
grep -Fq 'media_vfat_partition()' "$AUTOINSTALL" \
  || fail "the installer has no pipefail-safe ESP selector"
if grep -E 'lsblk .*awk .*exit' "$AUTOINSTALL" >/dev/null; then
  fail "the installer can SIGPIPE lsblk while selecting the ESP"
fi
# The WHOLE command, not a substring of it: an assertion that matched
# `true image exists …` would survive the control being removed.
exists_line="$(line_of 'podman --cgroup-manager=cgroupfs --events-backend=file image exists "$STORE_IMAGE_NAME"')"
[ -n "$exists_line" ] \
  || fail "the installer never asks podman to resolve the image in the verified store"
create_line="$(line_of 'create --network=none --name "$_medium_probe" --entrypoint /usr/bin/true')"
[ -n "$create_line" ] \
  || fail "the installer never creates its sealed-store no-exec preflight container"
mount_line="$(line_of 'mount "$_medium_probe"')"
[ -n "$mount_line" ] \
  || fail "the installer never proves a sealed-store container can be mounted without execution before wiping the target"
grep -Fq '|| die "the verified image store does not offer ${STORE_IMAGE_NAME}' "$AUTOINSTALL" \
  || fail "the installer does not REFUSE when the verified store offers no installable image"
destructive_line="$(grep -nE '^[[:space:]]*(wipefs|sfdisk|mkfs\.|cryptsetup luksFormat)' \
  "$AUTOINSTALL" | head -1 | cut -d: -f1)"
[ -n "$destructive_line" ] || fail "cannot locate the first destructive write in the autoinstaller"
[ "$exists_line" -lt "$destructive_line" ] \
  || fail "the store is proved resolvable at line $exists_line, AFTER the first disk write at line $destructive_line"
[ "$create_line" -lt "$destructive_line" ] \
  || fail "the store is proved container-creatable at line $create_line, AFTER the first disk write at line $destructive_line"
[ "$mount_line" -lt "$destructive_line" ] \
  || fail "the store is proved mountable at line $mount_line, AFTER the first disk write at line $destructive_line"
grep -Fq -- '-v "$STORE_MOUNT:$STORE_MOUNT:ro"' "$AUTOINSTALL" \
  || fail "the bootc container cannot see the verified store"
grep -Fq -- '-v "$INSTALLER_STORAGE_ROOT:$INSTALLER_STORAGE_ROOT"' "$AUTOINSTALL" \
  || fail "the bootc container cannot see the proved tmpfs-backed writable storage runtime"
grep -Fq -- '-v "$INSTALLER_STORAGE_CONF:/etc/containers/storage.conf:ro"' "$AUTOINSTALL" \
  || fail "the bootc container resolves containers-storage against its own configuration, not the medium's"
grep -Fq -- '-e CONTAINERS_STORAGE_CONF=/etc/containers/storage.conf' "$AUTOINSTALL" \
  || fail "bootc can ignore the bound complete storage config and load appliance defaults"
grep -Fq -- '-v "$INSTALLER_STORAGE_DROPINS:/etc/containers/storage.conf.d:ro"' "$AUTOINSTALL" \
  || fail "the appliance seed-store drop-in can override the installer's sealed additional image store"
# The object must not change between the proof and the install: a second,
# writable store shadowing `localhost/bootc` is exactly what the digest re-check
# exists to see.
grep -Fq '[[ "$_medium_now" == "$MEDIUM_IMAGE_DIGEST" ]]' "$AUTOINSTALL" \
  || fail "the installer does not re-check the medium image digest before installing it"

echo "INSTALLER_ROOT_TEST_OK"
