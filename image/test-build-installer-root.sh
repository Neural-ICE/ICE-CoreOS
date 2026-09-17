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

TOOLS="$TMP/tools"; ROOTFS="$TMP/rootfs"; HOST_ROOTFS="$TMP/host-rootfs"
mkdir -p "$TOOLS" "$ROOTFS" "$HOST_ROOTFS"
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
  # The HOST image the store holds, mounted separately by the builder to read
  # what it binds to itself. A vanilla host binds nothing: an empty
  # bound-images.d, which is what a base bootc image ships.
  rm -rf "$HOST_ROOTFS"; mkdir -p "$HOST_ROOTFS/usr/lib/bootc/bound-images.d"
}
make_rootfs

# The installer image's IMMUTABLE ID. `podman image inspect --format {{.Id}}`
# is what the builder resolves once and uses everywhere; the mock answers with
# whatever $MOCK_IMAGE_ID says, so a test can make the tag "move".
IMAGE_ID="$(printf 'installer-image' | sha256sum | awk '{print $1}')"
HOST_IMAGE_ID="$(printf 'original-host-image' | sha256sum | awk '{print $1}')"
HOST_MANIFEST="sha256:$(printf 'original-host-manifest' | sha256sum | awk '{print $1}')"
OTHER_IMAGE_ID="$(printf 'someone-elses-image' | sha256sum | awk '{print $1}')"
cat > "$TOOLS/podman" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >> "\${MOCK_STATE:-$TMP}/podman.args"
case "\$1 \$2 \$3" in
  "image inspect --format")
    ref="\${*: -1}"
    format="\$4"
    if [[ "\$format" == *Digest* ]]; then
      printf '%s\n' "\${MOCK_NAMED_MANIFEST:-$HOST_MANIFEST}"
    else
      case "\$ref" in
        localhost/ice-coreos-host:*) printf 'sha256:%s\n' "\${MOCK_NAMED_IMAGE_ID:-$HOST_IMAGE_ID}" ;;
        sha256:$HOST_IMAGE_ID) printf 'sha256:%s\n' "\${MOCK_STORE_RESOLVED_ID:-$HOST_IMAGE_ID}" ;;
        *) printf 'sha256:%s\n' "\${MOCK_IMAGE_ID:-$IMAGE_ID}" ;;
      esac
    fi ;;
  "--root "*)
    case "\$*" in
      *"image inspect --format {{.Digest}}"*) printf '%s\n' "\${MOCK_STORE_MANIFEST:-$HOST_MANIFEST}" ;;
      *) exit 2 ;;
    esac ;;
  *)
    case "\$1 \$2" in
      "image mount")
        if [[ "\$3" == "sha256:$HOST_IMAGE_ID" ]]; then printf '%s\n' "$HOST_ROOTFS"; else printf '%s\n' "$ROOTFS"; fi ;;
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
  case "$arg" in containers-storage:localhost/*) src="${MOCK_NAMED_IMAGE_ID:-$EXPECTED_STORE_IMAGE_ID}" ;; esac
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
  env MOCK_STATE="$out" EXPECTED_IMAGE_ID="$IMAGE_ID" EXPECTED_STORE_IMAGE_ID="$HOST_IMAGE_ID" \
    INSTALLER_IMG="sha256:$IMAGE_ID" \
    STORE_IMG="sha256:$HOST_IMAGE_ID" \
    INSTALLER_STORAGE_NAME="localhost/ice-coreos-installer:local" \
    STORE_STORAGE_NAME="localhost/ice-coreos-host:local" \
    STORE_MANIFEST_DIGEST="$HOST_MANIFEST" \
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
grep -Fq -- '--preserve-digests containers-storage:localhost/ice-coreos-host:local' \
  "$TMP/store-test/skopeo.args" \
  || fail "the store is not staged from the original host's stable local name with digest preservation"
grep -Fq "image inspect --format {{.Id}} localhost/ice-coreos-host:local" \
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
  case "$arg" in containers-storage:localhost/*) src="${MOCK_NAMED_IMAGE_ID:-$EXPECTED_STORE_IMAGE_ID}" ;; esac
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
    STORE_IMG="sha256:$HOST_IMAGE_ID" STORE_MANIFEST_DIGEST="$HOST_MANIFEST" \
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
grep -Fq "resolves to '$OTHER_IMAGE_ID', not immutable image $HOST_IMAGE_ID" <<<"$out" \
  || fail "a moved transport name was refused for the wrong reason: $out"
[ ! -s "$TMP/named-moved/skopeo.args" ] \
  || fail "skopeo ran before the transport name's immutable identity was proved"
rm -rf "$TMP/named-moved"

# The config ID does not authenticate an OCI manifest: the same config can be
# wrapped by another platform manifest. Refuse a moved source child before copy,
# then independently refuse a destination store whose readback child changed.
OTHER_MANIFEST="sha256:$(printf 'someone-elses-manifest' | sha256sum | awk '{print $1}')"
out="$(build "$TMP/named-manifest-moved" MOCK_NAMED_MANIFEST="$OTHER_MANIFEST" 2>&1)" \
  && fail "a host transport name resolving to another platform manifest was accepted"
grep -Fq "not $HOST_MANIFEST" <<<"$out" \
  || fail "a moved source manifest was refused for the wrong reason: $out"
[ ! -s "$TMP/named-manifest-moved/skopeo.args" ] \
  || fail "skopeo ran before the source platform manifest was proved"
rm -rf "$TMP/named-manifest-moved"

out="$(build "$TMP/store-manifest-moved" MOCK_STORE_MANIFEST="$OTHER_MANIFEST" 2>&1)" \
  && fail "a destination store that rewrote the platform manifest was accepted"
grep -Fq "staged store manifest $OTHER_MANIFEST differs" <<<"$out" \
  || fail "a rewritten destination manifest was refused for the wrong reason: $out"
rm -rf "$TMP/store-manifest-moved"

# The store must contain exactly the selected original host image. A different
# ID is a different install target even when the live installer root is valid.
out="$(build "$TMP/split" MOCK_STORE_IMAGE_ID="$OTHER_IMAGE_ID" 2>&1)" \
  && fail "a medium whose sealed root and staged store are different images was produced"
grep -Fq 'the staged image store holds image' <<<"$out" \
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
  "$HOST_IMAGE_ID" "\$name" "$OTHER_IMAGE_ID" "\$name" > "\$store/overlay-images/images.json"
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
  case "$arg" in containers-storage:localhost/*) src="${MOCK_NAMED_IMAGE_ID:-$EXPECTED_STORE_IMAGE_ID}" ;; esac
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
grep -qx "schema=neural-ice-installer-root-manifest-v5" "$manifest" \
  || fail "the manifest schema did not move with the identity contract"
# A vanilla host binds nothing, and the manifest says so rather than omitting it.
grep -qx 'store_bound_image_count=0' "$manifest" \
  || fail "the manifest does not record that the host binds no images"
grep -qx "store_bound_images_sha256=$(printf '' | sha256sum | awk '{print $1}')" "$manifest" \
  || fail "the manifest does not record the digest of the (empty) bound image list"
grep -qx "installer_image_id=$IMAGE_ID" "$manifest" \
  || fail "the manifest does not record the immutable image the root was sealed from"
grep -qx "store_image_id=$HOST_IMAGE_ID" "$manifest" \
  || fail "the manifest does not record the immutable image the store holds"
grep -qx "store_image_manifest_digest=$HOST_MANIFEST" "$manifest" \
  || fail "the manifest does not record the original host platform manifest"
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
grep -Fq 'STORE_IMG="$BASE_IMAGE_REF"' "$USB" \
  || fail "the sealed store builder is not handed the immutable original host identity"
grep -Fq 'BASE_IMAGE_ID="${_base_image_id_raw#sha256:}"' "$USB" \
  || fail "the media producer does not normalize Podman's prefixed or bare config identity"
grep -Fq 'BASE_IMAGE_REF="sha256:${BASE_IMAGE_ID}"' "$USB" \
  || fail "the media producer does not reconstruct one unambiguous immutable host reference"
grep -Fq 'STORE_MANIFEST_DIGEST="$BASE_MANIFEST_DIGEST"' "$USB" \
  || fail "the sealed store builder is not handed the observed original host child digest"
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
# ...and the two deliberately different halves must each be checked against the
# immutable identity selected for it.
grep -Fq '[[ "$sealed_store_image_id" == "$BASE_IMAGE_ID" ]]' "$USB" \
  || fail "the media producer does not compare the staged store with the original host"
grep -Fq '[[ "$sealed_store_manifest_digest" == "$BASE_MANIFEST_DIGEST" ]]' "$USB" \
  || fail "the media producer does not compare the staged store child digest with the original host"

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
grep -Fq 'ceremony_unit="$dep/usr/lib/systemd/system/$ceremony_unit_name"' \
  "$ROOT/ota/neural-ice-autoinstall.sh" \
  || fail "the installer does not verify the pinned appliance's own first-boot ceremony unit"
grep -Fq 'retired medium bridge' "$ROOT/ota/neural-ice-autoinstall.sh" \
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
# 4d) THE BOUND IMAGES THE HOST DECLARES ARE ON THE MEDIUM, AS OCI LAYOUTS THE
#     INSTALL CAN COPY. bootc's own install-time copy (`podman image push`
#     from a containers-storage) cannot land a digest-pinned image -- proved on
#     the bench 2026-09-17 (image/lib/bound-images.sh) -- so the store carries
#     each image as a layout: the index under `list` (its bytes hash to the
#     pinned digest) and the appliance's platform instance under `system`,
#     staged by digest from a registry and verified before the extent freezes,
#     and recorded so a cached store cut without them is refused. Until
#     2026-09-17 the installer hid the directory from bootc and every reinstall
#     paid 14 minutes of first-boot `skopeo copy` (lab GX10).
#
#     REAL skopeo does the layout work here: the mock only translates the
#     registry reference into the fixture layout that stands for the registry
#     (a multi-arch index with a linux/arm64 and a linux/amd64 instance), and
#     keeps mocking the host image's own store copy as before.
# --------------------------------------------------------------------------- #
make_rootfs
ln -sf "$(command -v cp)" "$TOOLS/cp" # the reuse path places the extent with the builder's cp
REAL_SKOPEO="$(command -v skopeo || true)"
[ -n "$REAL_SKOPEO" ] || fail "skopeo is required for the bound-image layout cases (CI installs it)"
REGISTRY="$TMP/registry"; rm -rf "$REGISTRY"; mkdir -p "$REGISTRY"
# A registry object: an OCI layout carrying a multi-arch index under the tag
# `list`, two tiny gzip layers per instance. Prints the index digest.
bound_fixture() { # $1=repository $2=output layout dir
  python3 - "$2" "$1" <<'PY'
import gzip, hashlib, io, json, os, sys, tarfile
out, repo = sys.argv[1], sys.argv[2]
os.makedirs(os.path.join(out, "blobs", "sha256"), exist_ok=True)
def put(data, media):
    digest = "sha256:" + hashlib.sha256(data).hexdigest()
    with open(os.path.join(out, "blobs", "sha256", digest[7:]), "wb") as handle:
        handle.write(data)
    return {"mediaType": media, "digest": digest, "size": len(data)}
def layer(name, arch):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        payload = f"{repo} {name} {arch}\n".encode()
        info = tarfile.TarInfo(name=f"{name}-{arch}.txt"); info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))
    raw = buffer.getvalue()
    return put(gzip.compress(raw, mtime=0), "application/vnd.oci.image.layer.v1.tar+gzip"), "sha256:" + hashlib.sha256(raw).hexdigest()
instances = []
for arch in ("arm64", "amd64"):
    layers, diff_ids = zip(*(layer(name, arch) for name in ("base", "app")))
    config = put(json.dumps({"architecture": arch, "os": "linux", "rootfs": {"type": "layers", "diff_ids": list(diff_ids)}, "config": {}}, sort_keys=True).encode(), "application/vnd.oci.image.config.v1+json")
    manifest = put(json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json", "config": config, "layers": list(layers)}, sort_keys=True).encode(), "application/vnd.oci.image.manifest.v1+json")
    manifest["platform"] = {"os": "linux", "architecture": arch}
    instances.append(manifest)
index = put(json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": instances}, sort_keys=True).encode(), "application/vnd.oci.image.index.v1+json")
index["annotations"] = {"org.opencontainers.image.ref.name": "list"}
with open(os.path.join(out, "index.json"), "w") as handle:
    json.dump({"schemaVersion": 2, "manifests": [index]}, handle)
with open(os.path.join(out, "oci-layout"), "w") as handle:
    json.dump({"imageLayoutVersion": "1.0.0"}, handle)
print(index["digest"][7:])
PY
}
bound_registry_object() { # $1=repository -> stages the object under its own digest, prints the digest
  local digest
  digest="$(bound_fixture "$1" "$TMP/fixture-$1")" || fail "cannot build the $1 fixture"
  rm -rf "${REGISTRY:?}/$digest"; mv "$TMP/fixture-$1" "$REGISTRY/$digest"
  printf '%s' "$digest"
}
BOUND_A_DIGEST="$(bound_registry_object working-memory)"
BOUND_B_DIGEST="$(bound_registry_object model-runtime-gb10)"
BOUND_A="registry.example.test/neural-ice/working-memory@sha256:$BOUND_A_DIGEST"
BOUND_B="registry.example.test/neural-ice/model-runtime-gb10@sha256:$BOUND_B_DIGEST"
declare_bound_images() { # $1=host root, rest: <unit>=<Image= reference>
  local root=$1 pair name ref
  shift
  rm -rf "$root/usr/lib/bootc/bound-images.d" "$root/usr/share/containers/systemd/neural-ice-bound-images"
  mkdir -p "$root/usr/lib/bootc/bound-images.d" "$root/usr/share/containers/systemd/neural-ice-bound-images"
  for pair in "$@"; do
    name="${pair%%=*}"; ref="${pair#*=}"
    printf '[Image]\nImage=%s\n' "$ref" \
      > "$root/usr/share/containers/systemd/neural-ice-bound-images/$name.image"
    # The appliance links with ABSOLUTE targets, which only resolve inside the mount.
    ln -s "/usr/share/containers/systemd/neural-ice-bound-images/$name.image" \
      "$root/usr/lib/bootc/bound-images.d/$name.image"
  done
}
declare_bound_images "$HOST_ROOTFS" "working-memory=$BOUND_A" "model-runtime=$BOUND_B"
# The skopeo mock: anything involving an `oci:` reference is the real skopeo,
# with docker://mirror.test:5055/<path>@sha256:<d> translated into the fixture
# layout registered under <d> (and the registry-only --src-* options dropped);
# a missing fixture is a registry that lacks the object. The host image's
# store copy stays mocked as before.
cat > "$TOOLS/skopeo" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$MOCK_STATE/skopeo.args"
case "$*" in
  *oci:*)
    args=(); skip=0
    for arg in "$@"; do
      if [ "$skip" = 1 ]; then skip=0; continue; fi
      case "$arg" in
        --src-cert-dir) skip=1 ;;
        --src-no-creds) ;;
        docker://mirror.test:5055/*)
          digest="${arg##*@sha256:}"
          [ -d "${MOCK_REGISTRY:?}/$digest" ] || { echo "mock registry: no object $arg" >&2; exit 1; }
          args+=("oci:${MOCK_REGISTRY}/${digest}:list") ;;
        *) args+=("$arg") ;;
      esac
    done
    exec "${REAL_SKOPEO:?}" "${args[@]}" ;;
esac
last="${*: -1}"
store="${last#*overlay@}"; store="${store%%+*}"
if [ "$1" = inspect ]; then cat "${MOCK_SOURCE_MANIFEST_FILE:?}"; exit 0; fi
name="${last##*]}"
mkdir -p "$store/overlay-images" "$store/overlay-layers" "$store/overlay"
src="${MOCK_NAMED_IMAGE_ID:-$EXPECTED_STORE_IMAGE_ID}"
printf '[{"id":"%s","names":["%s:latest"]}]\n' "${MOCK_STORE_IMAGE_ID:-$src}" "$name" \
  > "$store/overlay-images/images.json"
printf 'staged\n' > "$store/overlay-layers/layers.json"
EOF
chmod +x "$TOOLS/skopeo"
MIRROR="docker://mirror.test:5055"
bound_build() { # $1=output dir, rest=env overrides
  local out=$1; shift
  build "$out" MOCK_REGISTRY="$REGISTRY" REAL_SKOPEO="$REAL_SKOPEO" \
    BOUND_IMAGE_SOURCE_REGISTRY="mirror.test:5055" "$@"
}
bound_build "$TMP/bound" >/dev/null || fail "a host image binding two staged images was refused"
# The host image is what the list is read from: mounted by its immutable ID.
grep -Fq "image mount sha256:$HOST_IMAGE_ID" "$TMP/bound/podman.args" \
  || fail "the bound image list is not read from a mount of the host image itself"
# Two copies per image, from the registry, digests preserved: the index alone
# under `list`, then the arm64 instance -- the hardware target's architecture,
# not the build host's -- under `system`.
grep -Fq "copy --preserve-digests --multi-arch index-only --src-no-creds $MIRROR/neural-ice/working-memory@sha256:$BOUND_A_DIGEST oci:" \
  "$TMP/bound/skopeo.args" \
  || fail "the index of the first bound image was not staged alone from the registry with digests preserved"
grep -Fq -- "--override-os linux --override-arch arm64 copy --preserve-digests --multi-arch system --src-no-creds $MIRROR/neural-ice/model-runtime-gb10@sha256:$BOUND_B_DIGEST oci:" \
  "$TMP/bound/skopeo.args" \
  || fail "the instance of the second bound image was not staged for the hardware target's architecture"
! grep -Fq -- '--multi-arch all' "$TMP/bound/skopeo.args" \
  || fail "a bound image was staged with every platform's blobs"
# The layouts are inside the store tree the squashfs freezes, keyed by digest,
# and the store's own image index holds the host and nothing else.
grep -q "neural-ice-bound-images/$BOUND_A_DIGEST/index.json$" "$TMP/bound/installer-store.img" \
  || fail "the first bound image's layout is not inside the sealed store tree"
grep -q "neural-ice-bound-images/$BOUND_B_DIGEST/blobs/sha256/" "$TMP/bound/installer-store.img" \
  || fail "the second bound image's blobs are not inside the sealed store tree"
manifest="$TMP/bound/installer-root.img.manifest"
grep -qx 'store_bound_image_count=2' "$manifest" \
  || fail "the manifest does not record how many bound images the store carries"
BOUND_LIST_SHA="$(printf '%s\n%s\n' "$BOUND_B" "$BOUND_A" | LC_ALL=C sort | sha256sum | awk '{print $1}')"
grep -qx "store_bound_images_sha256=$BOUND_LIST_SHA" "$manifest" \
  || fail "the manifest does not record the digest of the sorted bound image list"
# Determinism holds with bound images: two builds, one store. The mock
# mksquashfs records the source PATH of every file, which carries the random
# work directory; the real one records none, so the paths are normalised.
bound_build "$TMP/bound-again" >/dev/null || fail "the second bound build failed"
store_content() { sed -E 's#  .*/store/#  store/#' "$1"; }
[ "$(store_content "$TMP/bound/installer-store.img")" = "$(store_content "$TMP/bound-again/installer-store.img")" ] \
  || fail "two builds of one host image with bound images produced different stores"
# A tag-pinned bound image cannot be proved present: refused before any copy.
declare_bound_images "$HOST_ROOTFS" "working-memory=$BOUND_A" \
  "model-runtime=registry.example.test/neural-ice/model-runtime-gb10:latest"
out="$(bound_build "$TMP/bound-tag" 2>&1)" && fail "a tag-pinned bound image was staged"
grep -Fq 'not a digest-pinned registry reference' <<<"$out" \
  || fail "the tag refusal is not named: $out"
[ ! -s "$TMP/bound-tag/skopeo.args" ] \
  || fail "skopeo ran for a host whose bound images could not be read"
# A dangling link is a bootc failure after the wipe; here it is a build refusal.
declare_bound_images "$HOST_ROOTFS" "working-memory=$BOUND_A" "model-runtime=$BOUND_B"
rm -f "$HOST_ROOTFS/usr/share/containers/systemd/neural-ice-bound-images/model-runtime.image"
out="$(bound_build "$TMP/bound-dangling" 2>&1)" && fail "a dangling bound image link was accepted"
grep -Fq 'which the host image does not carry' <<<"$out" \
  || fail "the dangling-link refusal is not named: $out"
declare_bound_images "$HOST_ROOTFS" "working-memory=$BOUND_A" "model-runtime=$BOUND_B"
# A registry that lacks one of them is a build refusal, not a medium.
mv "$REGISTRY/$BOUND_B_DIGEST" "$TMP/parked-b"
out="$(bound_build "$TMP/bound-missing" 2>&1)" && fail "a store missing a bound image was sealed"
grep -Fq "cannot stage bound image $BOUND_B" <<<"$out" \
  || fail "the missing-image refusal does not name the image: $out"
[ ! -s "$TMP/bound-missing/installer-store.img" ] \
  || fail "a store image was produced despite the missing bound image"
# A registry serving OTHER bytes under the pinned digest -- another image's
# index -- is caught by the layout verification: the `list` tag is not the pin.
OTHER_DIGEST="$(bound_fixture something-else "$REGISTRY/$BOUND_B_DIGEST")" || fail "cannot build the impostor fixture"
[ "$OTHER_DIGEST" != "$BOUND_B_DIGEST" ] || fail "the impostor fixture collides with the real one"
out="$(bound_build "$TMP/bound-tampered" 2>&1)" \
  && fail "a bound image whose index does not hash to the pinned digest was sealed"
grep -Fq "not the pinned sha256:$BOUND_B_DIGEST" <<<"$out" \
  || fail "the digest-mismatch refusal is not named: $out"
rm -rf "${REGISTRY:?}/$BOUND_B_DIGEST"; mv "$TMP/parked-b" "$REGISTRY/$BOUND_B_DIGEST"
# An image published for ONE platform only pins its manifest, not an index
# (the GB10 runtimes, bench 2026-09-17): accepted when its config says
# linux/arm64, refused when it says another platform.
bound_single_fixture() { # $1=repository $2=arch $3=output layout dir -> prints the manifest digest
  python3 - "$3" "$1" "$2" <<'PY'
import gzip, hashlib, io, json, os, sys, tarfile
out, repo, arch = sys.argv[1:]
os.makedirs(os.path.join(out, "blobs", "sha256"), exist_ok=True)
def put(data, media):
    digest = "sha256:" + hashlib.sha256(data).hexdigest()
    with open(os.path.join(out, "blobs", "sha256", digest[7:]), "wb") as handle:
        handle.write(data)
    return {"mediaType": media, "digest": digest, "size": len(data)}
buffer = io.BytesIO()
with tarfile.open(fileobj=buffer, mode="w") as tar:
    payload = f"{repo} {arch}\n".encode()
    info = tarfile.TarInfo(name="only.txt"); info.size = len(payload)
    tar.addfile(info, io.BytesIO(payload))
raw = buffer.getvalue()
layer = put(gzip.compress(raw, mtime=0), "application/vnd.oci.image.layer.v1.tar+gzip")
config = put(json.dumps({"architecture": arch, "os": "linux", "rootfs": {"type": "layers", "diff_ids": ["sha256:" + hashlib.sha256(raw).hexdigest()]}, "config": {}}, sort_keys=True).encode(), "application/vnd.oci.image.config.v1+json")
manifest = put(json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json", "config": config, "layers": [layer]}, sort_keys=True).encode(), "application/vnd.oci.image.manifest.v1+json")
manifest["annotations"] = {"org.opencontainers.image.ref.name": "list"}
with open(os.path.join(out, "index.json"), "w") as handle:
    json.dump({"schemaVersion": 2, "manifests": [manifest]}, handle)
with open(os.path.join(out, "oci-layout"), "w") as handle:
    json.dump({"imageLayoutVersion": "1.0.0"}, handle)
print(manifest["digest"][7:])
PY
}
BOUND_C_DIGEST="$(bound_single_fixture model-runtime-gb10 arm64 "$TMP/fixture-single")" || fail "cannot build the single-platform fixture"
rm -rf "${REGISTRY:?}/$BOUND_C_DIGEST"; mv "$TMP/fixture-single" "$REGISTRY/$BOUND_C_DIGEST"
BOUND_C="registry.example.test/neural-ice/model-runtime-gb10@sha256:$BOUND_C_DIGEST"
declare_bound_images "$HOST_ROOTFS" "model-runtime=$BOUND_C"
bound_build "$TMP/bound-single" >/dev/null || fail "a bound image published for arm64 only was refused"
grep -qx 'store_bound_image_count=1' "$TMP/bound-single/installer-root.img.manifest" \
  || fail "the single-platform bound image was not counted"
BOUND_D_DIGEST="$(bound_single_fixture model-runtime-x86 amd64 "$TMP/fixture-single-amd64")" || fail "cannot build the amd64-only fixture"
rm -rf "${REGISTRY:?}/$BOUND_D_DIGEST"; mv "$TMP/fixture-single-amd64" "$REGISTRY/$BOUND_D_DIGEST"
declare_bound_images "$HOST_ROOTFS" "model-runtime=registry.example.test/neural-ice/model-runtime-x86@sha256:$BOUND_D_DIGEST"
out="$(bound_build "$TMP/bound-single-amd64" 2>&1)" \
  && fail "a bound image published for amd64 only was sealed onto an arm64 medium"
grep -Fq 'is linux/amd64, not linux/arm64' <<<"$out" \
  || fail "the wrong-platform refusal is not named: $out"
declare_bound_images "$HOST_ROOTFS" "working-memory=$BOUND_A" "model-runtime=$BOUND_B"
# The layout the medium carries copies into a containers-storage under the
# pinned reference -- the step the installer performs after bootc -- with the
# real skopeo. A store write needs a user namespace; where the sandbox has
# none, the bench proof (2026-09-17, appliance skopeo 1.23) stands alone.
# shellcheck source=image/lib/bound-images.sh
. "$ROOT/image/lib/bound-images.sh"
IMPORT_STORE="$TMP/import-store"; mkdir -p "$IMPORT_STORE" "$IMPORT_STORE.run"
# The copy is a real skopeo write into a containers-storage. Rootless, that
# needs a user namespace, which this sandbox and the ubuntu-24.04 runner both
# refuse; and the runner is x86_64, so the copy names the arm64 platform as
# the installer does, or skopeo would look for an instance the layout does
# not carry (CI 2026-09-17: "the layout could not be copied")
# -- it also refuses ("Error during unshare(...): Operation not permitted", 2026-09-17);
# root needs none. So the case runs rootless where it can, under `sudo -n`
# where the runner grants it (as the ssh-key suite's root seam already does),
# and is skipped OUT LOUD only where neither exists -- never in CI, which sets
# NI_INSTALLER_ROOT_REQUIRE_IMPORT=1. The suite's mocks are not involved: the
# real skopeo stages the layout as the builder does and copies it as the
# installer does.
IMPORT_CASE="$TMP/import-case.sh"
cat > "$IMPORT_CASE" <<EOF
#!/usr/bin/env bash
set -euo pipefail
. "$ROOT/image/lib/bound-images.sh"
NI_BOUND_IMAGES_SKOPEO="$REAL_SKOPEO"
ERR="$TMP/import-case.err"; : > "\$ERR"; "$REAL_SKOPEO" --version >> "\$ERR" 2>&1
rm -rf "$TMP/import-store" "$TMP/import-store.run" "$TMP/bound-work-layout"
mkdir -p "$TMP/import-store" "$TMP/import-store.run"
ni_bound_image_stage_layout "oci:$REGISTRY/$BOUND_A_DIGEST:list" "$TMP/bound-work-layout" arm64 >>"\$ERR" 2>&1 \
  || { echo "cannot stage the layout for the import case" >&2; exit 1; }
ni_bound_image_import "$TMP/bound-work-layout" "containers-storage:[vfs@$TMP/import-store+$TMP/import-store.run]$BOUND_A" arm64 >>"\$ERR" 2>&1 \
  || { echo "the layout could not be copied into a containers-storage under the pinned reference" >&2; exit 1; }
[ "\$("$REAL_SKOPEO" inspect --raw "containers-storage:[vfs@$TMP/import-store+$TMP/import-store.run]$BOUND_A" | sha256sum | cut -c1-64)" = "$BOUND_A_DIGEST" ] \
  || { echo "the imported image does not answer to the pinned index digest" >&2; exit 1; }
grep -Fq "\"$BOUND_A\"" "$TMP/import-store/vfs-images/images.json" \
  || { echo "the target store does not name the imported image by its pinned reference" >&2; exit 1; }
echo IMPORT_CASE_OK
EOF
chmod 0755 "$IMPORT_CASE"
import_probe_ok=0
if "$REAL_SKOPEO" copy "oci:$REGISTRY/$BOUND_A_DIGEST:list" "containers-storage:[vfs@$TMP/import-probe+$TMP/import-probe.run]localhost/import-probe:1" \
    >/dev/null 2>"$TMP/import-probe.err"; then
  import_probe_ok=1
fi
if [ "$import_probe_ok" = 1 ]; then
  out="$(bash "$IMPORT_CASE" 2>&1)" || fail "the layout-to-store import failed rootless: $out"
elif sudo -n true 2>/dev/null; then
  import_rc=0
  out="$(sudo -n bash "$IMPORT_CASE" 2>&1)" || import_rc=$?
  # Root wrote these; hand them back so the suite's own trap can remove them.
  sudo -n chown -R "$(id -u):$(id -g)" "$TMP/import-store" "$TMP/import-store.run" "$TMP/bound-work-layout" "$TMP/import-case.err" 2>/dev/null || true
  [ "$import_rc" = 0 ] \
    || fail "the layout-to-store import failed under sudo: $out; skopeo said: $(grep -v '^$' "$TMP/import-case.err" 2>/dev/null | tail -n 4 | tr '\n' ' ' | cut -c1-600)"
  echo "    (rootless containers-storage unavailable here -- $(tail -n 1 "$TMP/import-probe.err" | cut -c1-80); the import case ran under sudo)"
elif [ "${NI_INSTALLER_ROOT_REQUIRE_IMPORT:-0}" = 1 ]; then
  fail "this environment can write a containers-storage neither rootless ($(tail -n 1 "$TMP/import-probe.err" | cut -c1-80)) nor under sudo, and the import case may not be skipped here"
else
  echo "    (this environment cannot write a containers-storage -- $(tail -n 1 "$TMP/import-probe.err" | cut -c1-120); the layout-to-store import is proved on the bench and in CI)"
fi
[ "$import_probe_ok" = 0 ] || grep -Fq IMPORT_CASE_OK <<<"$out" || fail "the rootless import case did not report success"

make_rootfs

# --------------------------------------------------------------------------- #
# 4e) THE RAW GROWS TO THE PAYLOAD. bib sizes its raw at twice the container
#     (a 10 GiB raw for the 0.60.1 medium) and the pinned bib rejects filesystem
#     sizing for raw builds; a store carrying ~22 GiB of bound images does not
#     fit that. The producer grows bib's LAST partition -- the one the sealed
#     payload overwrites -- to the measured payload BEFORE its fit refusal,
#     with sfdisk on the raw file: every other partition, every PARTUUID and
#     every name stay as bib wrote them, and the backup GPT follows the new
#     end. The function is lifted verbatim and driven on a real GPT.
# --------------------------------------------------------------------------- #
USB="$ROOT/image/build-installer-usb.sh"
grep -Fq 'grow_raw_payload_partition "$RAW" "$PAYLOAD_BYTES"' "$USB" \
  || fail "the media producer does not grow bib's payload partition to the measured payload"
grow_line="$(grep -n 'grow_raw_payload_partition "$RAW" "$PAYLOAD_BYTES"' "$USB" | head -1 | cut -d: -f1)"
fit_line="$(grep -n 'PAYLOADPART_BYTES >= PAYLOAD_BYTES' "$USB" | head -1 | cut -d: -f1)"
[[ -n "$grow_line" && -n "$fit_line" && "$grow_line" -lt "$fit_line" ]] \
  || fail "the raw is grown at line ${grow_line:-none}, not before the fit refusal at line ${fit_line:-none}"
if command -v sfdisk >/dev/null 2>&1; then
  GROW_FN="$(awk '/^grow_raw_payload_partition\(\) \{/,/^}$/' "$USB")"
  [ -n "$GROW_FN" ] || fail "the media producer has no grow_raw_payload_partition function to lift"
  # The producer drives it under sudo, on bib's root-owned raw; the lifted
  # function is what invokes this shim, which shellcheck cannot see (SC2329
  # on 0.11, SC2317 on the CI runner's 0.10).
  # shellcheck disable=SC2329,SC2317
  sudo() { "$@"; }
  eval "$GROW_FN"
  table_of() { # node, start, PARTUUID and name of every partition: what must NOT change
    sfdisk --json "$1" | python3 -c '
import json, sys
table = json.load(sys.stdin)["partitiontable"]
for part in table["partitions"]:
    print(part["node"], part["start"], part["uuid"], part.get("name", ""))'
  }
  last_bytes_of() {
    sfdisk --json "$1" | python3 -c '
import json, sys
table = json.load(sys.stdin)["partitiontable"]
last = sorted(table["partitions"], key=lambda part: part["start"])[-1]
print(last["size"] * table.get("sectorsize", 512))'
  }
  RAWFX="$TMP/grow.raw"; truncate -s 64M "$RAWFX"
  printf 'label: gpt\n,8M,U\n,8M,L\n,,L\n' | sfdisk --quiet "$RAWFX" >/dev/null 2>&1 \
    || fail "cannot lay out the raw fixture"
  sfdisk --part-label "$RAWFX" 3 ni-fixture-data >/dev/null 2>&1 || fail "cannot name the fixture partition"
  table_before="$(table_of "$RAWFX")"; size_before="$(stat -c %s "$RAWFX")"
  grow_raw_payload_partition "$RAWFX" $((30 * 1024 * 1024)) >/dev/null 2>&1 \
    || fail "a payload that already fits was refused"
  [ "$(stat -c %s "$RAWFX")" = "$size_before" ] || fail "a payload that already fits grew the raw"
  grow_raw_payload_partition "$RAWFX" $((100 * 1024 * 1024)) >/dev/null 2>&1 \
    || fail "the raw could not be grown for a larger payload"
  last_bytes="$(last_bytes_of "$RAWFX")"
  [ "$last_bytes" -ge $((100 * 1024 * 1024)) ] \
    || fail "the grown payload partition holds $last_bytes bytes, less than the payload"
  [ "$table_before" = "$(table_of "$RAWFX")" ] \
    || fail "growing the payload partition moved a partition, changed a PARTUUID or renamed one"
  sfdisk --verify "$RAWFX" >/dev/null 2>&1 \
    || fail "the grown raw does not verify: the backup GPT did not follow the new end"
  unset -f sudo
else
  echo "    (sfdisk unavailable here: the raw grow is asserted on the producer's source only)"
fi

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
create_line="$(line_of 'create --pull=never --network=none --name "$_medium_probe" --entrypoint /usr/bin/true')"
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

# --------------------------------------------------------------------------- #
# 7) THE STORE MAY BE STAGED FROM A REGISTRY SOURCE, BOUND TO THE SAME TWO
#    IDENTITIES. A containers-storage source cannot always reproduce the
#    compressed layer streams a manifest names; a registry serves the exact
#    blobs. The source is admitted only when its reference names the store
#    manifest digest, its served manifest hashes to that digest and names the
#    immutable store image as config. Anything else is a refusal, and the copy
#    still preserves digests.
# --------------------------------------------------------------------------- #
SRC_MANIFEST="$TMP/store-source-manifest.json"
printf '{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:%s","size":7},"layers":[]}' \
  "$HOST_IMAGE_ID" > "$SRC_MANIFEST"
SRC_DIGEST="sha256:$(sha256sum "$SRC_MANIFEST" | awk '{print $1}')"
OTHER_SRC_MANIFEST="$TMP/store-source-other.json"
printf '{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:%s","size":7},"layers":[]}' \
  "$OTHER_IMAGE_ID" > "$OTHER_SRC_MANIFEST"
OTHER_SRC_DIGEST="sha256:$(sha256sum "$OTHER_SRC_MANIFEST" | awk '{print $1}')"
cat > "$TOOLS/skopeo" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$MOCK_STATE/skopeo.args"
if [ "$1" = inspect ]; then cat "${MOCK_SOURCE_MANIFEST_FILE:?}"; exit 0; fi
dest="${*: -1}"
name="${dest##*]}"
store="${dest#*overlay@}"; store="${store%%+*}"
mkdir -p "$store/overlay-images" "$store/overlay-layers" "$store/overlay"
printf '[{"id":"%s","names":["%s:latest"]}]\n' "$EXPECTED_STORE_IMAGE_ID" "$name" > "$store/overlay-images/images.json"
printf 'staged\n' > "$store/overlay-layers/layers.json"
EOF
chmod +x "$TOOLS/skopeo"
mkdir -p "$TMP/certs"
SRC_REF="docker://mirror.test:5055/neural-ice/appliance@$SRC_DIGEST"
build "$TMP/registry-source" STORE_MANIFEST_DIGEST="$SRC_DIGEST" MOCK_NAMED_MANIFEST="$SRC_DIGEST" MOCK_STORE_MANIFEST="$SRC_DIGEST" \
  STORE_SOURCE_REF="$SRC_REF" STORE_SOURCE_CERT_DIR="$TMP/certs" MOCK_SOURCE_MANIFEST_FILE="$SRC_MANIFEST" >/dev/null 2>&1 \
  || fail "a registry source bound to the store manifest and image was refused"
grep -Fq "inspect --raw --no-creds --cert-dir $TMP/certs $SRC_REF" "$TMP/registry-source/skopeo.args" \
  || fail "the registry source manifest was not read back with the pinned certificate directory and no credential"
grep -Fq "copy --preserve-digests --src-cert-dir $TMP/certs --src-no-creds $SRC_REF containers-storage:[overlay@" "$TMP/registry-source/skopeo.args" \
  || fail "the store was not copied from the registry source with digests preserved"
out="$(build "$TMP/registry-source-other-ref" STORE_MANIFEST_DIGEST="$SRC_DIGEST" MOCK_NAMED_MANIFEST="$SRC_DIGEST" MOCK_STORE_MANIFEST="$SRC_DIGEST" \
  STORE_SOURCE_REF="docker://mirror.test:5055/neural-ice/appliance@$HOST_MANIFEST" MOCK_SOURCE_MANIFEST_FILE="$SRC_MANIFEST" 2>&1)" \
  && fail "a registry source naming another manifest digest was accepted"
grep -Fq "not the store manifest" <<<"$out" || fail "the other-manifest refusal is not named: $out"
grep -Fq "copy --preserve-digests" "$TMP/registry-source-other-ref/skopeo.args" 2>/dev/null \
  && fail "the store was copied despite the other-manifest refusal"
out="$(build "$TMP/registry-source-other-bytes" STORE_MANIFEST_DIGEST="$SRC_DIGEST" MOCK_NAMED_MANIFEST="$SRC_DIGEST" MOCK_STORE_MANIFEST="$SRC_DIGEST" \
  STORE_SOURCE_REF="$SRC_REF" MOCK_SOURCE_MANIFEST_FILE="$OTHER_SRC_MANIFEST" 2>&1)" \
  && fail "a registry serving other manifest bytes than the reference names was accepted"
grep -Fq "does not hash to" <<<"$out" || fail "the other-bytes refusal is not named: $out"
out="$(build "$TMP/registry-source-other-config" STORE_MANIFEST_DIGEST="$OTHER_SRC_DIGEST" MOCK_NAMED_MANIFEST="$OTHER_SRC_DIGEST" MOCK_STORE_MANIFEST="$OTHER_SRC_DIGEST" \
  STORE_SOURCE_REF="docker://mirror.test:5055/neural-ice/appliance@$OTHER_SRC_DIGEST" MOCK_SOURCE_MANIFEST_FILE="$OTHER_SRC_MANIFEST" 2>&1)" \
  && fail "a registry source whose manifest names another image config was accepted"
grep -Fq "not the immutable store image" <<<"$out" || fail "the other-config refusal is not named: $out"
out="$(build "$TMP/registry-source-clear-text" STORE_MANIFEST_DIGEST="$SRC_DIGEST" MOCK_NAMED_MANIFEST="$SRC_DIGEST" MOCK_STORE_MANIFEST="$SRC_DIGEST" \
  STORE_SOURCE_REF="oci:/tmp/layout:tag" MOCK_SOURCE_MANIFEST_FILE="$SRC_MANIFEST" 2>&1)" \
  && fail "a non-registry store source was accepted"
grep -Fq "digest-pinned registry reference" <<<"$out" || fail "the non-registry refusal is not named: $out"


# --------------------------------------------------------------------------- #
# 8) THE ALREADY-BUILT STORE (FAB-0057 P1.7). Two media cut for two edits of the
#    installer root carry byte-identical stores, because the store is a
#    containers-storage holding exactly one digest-named image. The caller may
#    therefore hand the extent back instead of paying `skopeo copy` plus a
#    single-threaded zstd-19 mksquashfs over ~8 GiB again.
#
#    Every assertion below is about the REFUSALS, because a reuse path that
#    accepts is a reuse path that has replaced a proof with a filename.
# --------------------------------------------------------------------------- #
make_rootfs
ln -sf "$(command -v cp)" "$TOOLS/cp"
cat > "$TOOLS/skopeo" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$MOCK_STATE/skopeo.args"
src=""
for arg in "$@"; do
  case "$arg" in containers-storage:localhost/*) src="${MOCK_NAMED_IMAGE_ID:-$EXPECTED_STORE_IMAGE_ID}" ;; esac
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

# The extent a first, full build produced -- and the facts recorded about it.
build "$TMP/reuse-source" >/dev/null || fail "the reuse source build failed"
REUSE_IMG="$TMP/reuse-store.img"
cp "$TMP/reuse-source/installer-store.img" "$REUSE_IMG"
REUSE_SHA="$(sed -n 's/^store_image_sha256=//p' "$TMP/reuse-source/installer-root.img.manifest")"
REUSE_BYTES="$(sed -n 's/^store_image_bytes=//p' "$TMP/reuse-source/installer-root.img.manifest")"
if [ -z "$REUSE_SHA" ] || [ -z "$REUSE_BYTES" ]; then
  fail "the full build recorded no store size and digest to reuse"
fi

EMPTY_LIST_SHA="$(printf '' | sha256sum | awk '{print $1}')"
reuse_build() { # $1=output dir, rest=env overrides
  local out=$1; shift
  build "$out" \
    STORE_IMAGE_REUSE="$REUSE_IMG" \
    STORE_IMAGE_REUSE_SHA256="$REUSE_SHA" \
    STORE_IMAGE_REUSE_BYTES="$REUSE_BYTES" \
    STORE_IMAGE_REUSE_IMAGE_ID="$HOST_IMAGE_ID" \
    STORE_IMAGE_REUSE_MANIFEST_DIGEST="$HOST_MANIFEST" \
    STORE_IMAGE_REUSE_NAME="localhost/bootc" \
    STORE_IMAGE_REUSE_BOUND_IMAGES_SHA256="$EMPTY_LIST_SHA" \
    "$@"
}

# 🔴 THE SECOND BUILD PRODUCES THE SAME STORE BYTES AND THE SAME MANIFEST LINES.
# A reuse that changed either would change the sealed payload header digest, and
# nobody could tell a rebuild from a substitution.
reuse_build "$TMP/reuse-hit" >/dev/null || fail "a correctly described reusable store was refused"
cmp -s "$TMP/reuse-source/installer-store.img" "$TMP/reuse-hit/installer-store.img" \
  || fail "the reused store is not byte-identical to the one the full build produced"
for line in store_image_sha256 store_image_bytes store_image_id \
  store_image_manifest_digest store_image_name; do
  [ "$(sed -n "s/^$line=//p" "$TMP/reuse-hit/installer-root.img.manifest")" \
    = "$(sed -n "s/^$line=//p" "$TMP/reuse-source/installer-root.img.manifest")" ] \
    || fail "the reused build's manifest line '$line' differs from the full build's"
done
# ...and the expensive half really was skipped: no copy was staged at all.
[ ! -s "$TMP/reuse-hit/skopeo.args" ] \
  || fail "the reuse path still ran skopeo; nothing was saved"
[ "$(grep -c -- '-mkfs-time 0' "$TMP/reuse-hit/mksquashfs.args")" = 1 ] \
  || fail "the reuse path still ran mksquashfs over the store tree"
# The installer ROOT is never reused: it is what a change to this tree changes.
[ "$(sed -n 's/^root_image_sha256=//p' "$TMP/reuse-hit/installer-root.img.manifest")" \
  = "$(sed -n 's/^root_image_sha256=//p' "$TMP/reuse-source/installer-root.img.manifest")" ] \
  || fail "the reuse fixture changed the root image; this case would prove nothing"
printf 'sealed-lab\n' > "$ROOTFS/usr/lib/neural-ice/appliance-variant"
reuse_build "$TMP/reuse-new-root" >/dev/null || fail "the changed-root reuse build failed"
[ "$(sed -n 's/^root_image_sha256=//p' "$TMP/reuse-new-root/installer-root.img.manifest")" \
  != "$(sed -n 's/^root_image_sha256=//p' "$TMP/reuse-hit/installer-root.img.manifest")" ] \
  || fail "a reused store made the sealed installer root stale"
cmp -s "$TMP/reuse-new-root/installer-store.img" "$TMP/reuse-source/installer-store.img" \
  || fail "the changed-root build did not carry the same reused store"
rm -f "$ROOTFS/usr/lib/neural-ice/appliance-variant"

# 🔴 SABOTAGE 1: ONE BYTE. The recorded digest is the only thing standing
# between a cached extent and the signature that will cover it.
TAMPERED="$TMP/reuse-tampered.img"
python3 - "$REUSE_IMG" "$TAMPERED" <<'PYEOF'
import sys
data = bytearray(open(sys.argv[1], "rb").read())
data[0] ^= 0x01
open(sys.argv[2], "wb").write(data)
PYEOF
cmp -s "$REUSE_IMG" "$TAMPERED" && fail "the sabotage fixture did not change a byte"
out="$(reuse_build "$TMP/reuse-tamper" STORE_IMAGE_REUSE="$TAMPERED" 2>&1)" \
  && fail "a reusable store whose bytes were altered was sealed"
grep -Fq 'refusing to seal an extent nothing accounts for' <<<"$out" \
  || fail "the altered-bytes refusal is not named: $out"
grep -Fq "not the recorded $REUSE_SHA" <<<"$out" \
  || fail "the altered-bytes refusal does not name the digest it expected: $out"

# 🔴 SABOTAGE 2: THE RECORD. Correct bytes, an altered claim about them, and the
# comparison must still fail -- in the other direction.
out="$(reuse_build "$TMP/reuse-wrong-sha" \
  STORE_IMAGE_REUSE_SHA256="$(printf '%064d' 7)" 2>&1)" \
  && fail "a reusable store described by another digest was sealed"
grep -Fq 'refusing to seal an extent nothing accounts for' <<<"$out" \
  || fail "the altered-record refusal is not named: $out"
out="$(reuse_build "$TMP/reuse-wrong-bytes" STORE_IMAGE_REUSE_BYTES=17 2>&1)" \
  && fail "a reusable store described by another size was sealed"
grep -Fq 'not the 17 it is recorded as' <<<"$out" \
  || fail "the size refusal does not name the size it expected: $out"

# 🔴 THE IDENTITY IS RE-READ, NOT INHERITED. Each of the three identity values
# is compared against what THIS build resolved live from the digest-pinned base
# image; a stale entry must not be able to substitute the installed appliance.
out="$(reuse_build "$TMP/reuse-other-image" \
  STORE_IMAGE_REUSE_IMAGE_ID="$OTHER_IMAGE_ID" 2>&1)" \
  && fail "a reusable store recorded around another image was sealed"
grep -Fq 'but this build selected' <<<"$out" \
  || fail "the other-image refusal is not named: $out"
out="$(reuse_build "$TMP/reuse-other-manifest" \
  STORE_IMAGE_REUSE_MANIFEST_DIGEST="sha256:$(printf '%064d' 8)" 2>&1)" \
  && fail "a reusable store recorded around another platform manifest was sealed"
grep -Fq 'records manifest' <<<"$out" \
  || fail "the other-manifest refusal is not named: $out"
out="$(reuse_build "$TMP/reuse-other-name" \
  STORE_IMAGE_REUSE_NAME=localhost/something-else 2>&1)" \
  && fail "a reusable store offering the image under another name was sealed"
grep -Fq 'but this build installs from' <<<"$out" \
  || fail "the other-name refusal is not named: $out"
out="$(reuse_build "$TMP/reuse-other-bound" \
  STORE_IMAGE_REUSE_BOUND_IMAGES_SHA256="$(printf '%064d' 9)" 2>&1)" \
  && fail "a reusable store recorded around another bound image list was sealed"
grep -Fq 'records bound images' <<<"$out" \
  || fail "the other-bound-list refusal is not named: $out"

# A HALF-DESCRIBED EXTENT IS REFUSED IN BOTH DIRECTIONS: a path with no facts is
# bytes nothing accounts for, and facts with no path describe nothing.
out="$(reuse_build "$TMP/reuse-half" STORE_IMAGE_REUSE_SHA256= 2>&1)" \
  && fail "a store reuse with no recorded digest was accepted"
grep -Fq 'requires all seven of' <<<"$out" \
  || fail "the half-tuple refusal is not named: $out"
out="$(reuse_build "$TMP/reuse-six" STORE_IMAGE_REUSE_BOUND_IMAGES_SHA256= 2>&1)" \
  && fail "the six-value tuple of a store cut before the bound images were carried was accepted"
grep -Fq 'requires all seven of' <<<"$out" \
  || fail "the six-value-tuple refusal is not named: $out"
out="$(build "$TMP/reuse-facts-only" \
  STORE_IMAGE_REUSE_SHA256="$REUSE_SHA" \
  STORE_IMAGE_REUSE_BYTES="$REUSE_BYTES" 2>&1)" \
  && fail "recorded facts with no extent were accepted"
grep -Fq 'requires all seven of' <<<"$out" \
  || fail "the facts-without-extent refusal is not named: $out"

# A SYMLINK IS NOT AN EXTENT. The reuse input is read by a privileged process;
# a repointable path is exactly what must never be followed.
ln -sf "$REUSE_IMG" "$TMP/reuse-link.img"
out="$(reuse_build "$TMP/reuse-symlink" STORE_IMAGE_REUSE="$TMP/reuse-link.img" 2>&1)" \
  && fail "a symlinked reusable store was accepted"
grep -Fq 'not a plain file' <<<"$out" \
  || fail "the symlink refusal is not named: $out"
out="$(reuse_build "$TMP/reuse-relative" STORE_IMAGE_REUSE=store.img 2>&1)" \
  && fail "a relative reusable store path was accepted"
grep -Fq 'must be an absolute path' <<<"$out" \
  || fail "the relative-path refusal is not named: $out"

# --------------------------------------------------------------------------- #
# 8b) THE PRODUCER SIDE. The reuse tuple is only ever built from a cache entry
#     whose recorded key equals the key this build recomputes, and the store's
#     dm-verity root hash is recomputed by the UNCHANGED payload assembler and
#     compared against the entry. Asserted on the producer's source, the way
#     every other producer contract in this suite is.
# --------------------------------------------------------------------------- #
grep -Fq 'MEDIUM_BUILD_CACHE_DIR="${MEDIUM_BUILD_CACHE_DIR:-}"' "$USB" \
  || fail "the media producer's content cache is not opt-in by an explicit directory"
grep -Fq 'medium_cache_require_dir' "$USB" \
  || fail "the media producer never validates the cache directory"
grep -Fq 'STORE_IMAGE_REUSE="$(medium_cache_entry_dir "$MEDIUM_CACHE_STORE_KEY")/installer-store.img"' "$USB" \
  || fail "the media producer does not hand the sealed root builder the cached extent"
grep -Fq 'STORE_IMAGE_REUSE_BOUND_IMAGES_SHA256="$(sed -n '"'"'s/^store_bound_images_sha256=//p'"'"' <<<"$medium_cache_entry_facts")"' "$USB" \
  || fail "the media producer does not hand the builder the bound image list a cache entry records"
grep -Fq '"store_bound_images_sha256": HEX64,' "$USB" \
  || fail "the media producer's cache reader does not require the recorded bound image list"
grep -Fq 'BOUND_IMAGE_SOURCE_REGISTRY="$BOUND_IMAGE_SOURCE_REGISTRY"' "$USB" \
  || fail "the media producer does not pass the bound image registry to the store builder"
grep -Fq 'medium_cache_assert_reused_verity "$STORE_VERITY_HASH" "$MEDIUM_CACHE_STORE_VERITY_HASH"' "$USB" \
  || fail "the media producer does not compare the recomputed store verity root hash with the cache entry"
grep -Fq 'medium_cache_finalize_store' "$USB" \
  || fail "the media producer never records what a reuse would be checked against"
grep -Fq 'medium_cache_prune' "$USB" \
  || fail "the media producer's cache is unbounded"
# The cached artefacts are the store and nothing else: the installer root, the
# initramfs, the UKI and the raw are what a change to this tree changes.
for never_cached in installer-root.img installer-initramfs.img disk.raw; do
  if grep -F "medium_cache_stage_store" "$USB" | grep -Fq "$never_cached"; then
    fail "the media producer caches $never_cached"
  fi
done

echo "INSTALLER_ROOT_TEST_OK"
