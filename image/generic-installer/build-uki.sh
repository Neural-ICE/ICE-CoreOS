#!/bin/bash
# Build the generic installer UKI once per installer version (ADR-0044). The kernel RPMs, the GSP firmware and
# the console files are the HOST's: they come from the staged GB10 artifact generation that image/Containerfile.bootc
# consumes, verified by the same ci/verify-build-context.sh. Seals in the cmdline only what does not change
# per release.
# Usage: build-uki.sh OUTDIR CONTEXT_DIR PCR_POLICY_KEY [MIN_BUNDLE_SEQ] [HARDWARE_TARGET] [INSTALLER_VERSION]
#   CONTEXT_DIR      staged generation (rpms/ nvidia-userspace/ signed-boot/ generation.env)
#   PCR_POLICY_KEY   the PCR-policy public key; embedded in the initrd, its sha256 sealed (ADR-0044 D3)
# Environment: VARIANT (default sealed-lab), CONSOLE_KARG (default none), INSTALL_STAGE (default prototype-ungated),
#   TARGET_DEBUG (0|1, default 0: asks the installed host for a verbose first boot; prototype only),
#   MKOSI_CACHE (optional package cache directory), CONTEXT_RESULT (output of a prior ci/verify-build-context.sh run).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; REPO="$(cd "$HERE/../.." && pwd)"
OUT="${1:?outdir}"; CTX="${2:?staged generation}"; PCRKEY="${3:?pcr policy public key}"
MINSEQ="${4:-1}"; TARGET="${5:-nvidia-gb10-arm64}"; VERSION="${6:-0.1.0}"
VARIANT="${VARIANT:-sealed-lab}"; CONSOLE_KARG="${CONSOLE_KARG:-}"; STAGE="${INSTALL_STAGE:-prototype-ungated}"
TARGET_DEBUG="${TARGET_DEBUG:-0}"
[[ "$MINSEQ" =~ ^[1-9][0-9]{0,15}$ ]] && [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "bad floor or version" >&2; exit 2; }
[[ "$CONSOLE_KARG" =~ ^(console=[A-Za-z0-9,]+)?$ ]] && [[ "$TARGET_DEBUG" =~ ^[01]$ ]] || { echo "bad console or debug flag" >&2; exit 2; }
[[ "$TARGET" =~ ^[a-z0-9]+(-[a-z0-9]+)*$ && "$STAGE" =~ ^[a-z]+(-[a-z]+)*$ && "$VARIANT" =~ ^[a-z]+(-[a-z]+)*$ ]] || { echo "bad target, stage or variant" >&2; exit 2; }
for v in "$OUT" "$CTX" "$PCRKEY" "${MKOSI_CACHE:-}"; do [[ "$v" =~ ^[A-Za-z0-9._/@+-]*$ ]] || { echo "unsupported character in a path" >&2; exit 2; }; done
[ -s "$PCRKEY" ] && [ ! -L "$PCRKEY" ] || { echo "PCR policy key missing" >&2; exit 2; }
# The same gate the host build passes: re-hashes every staged byte and re-checks the signed boot binding. Its
# tools (sbverify, sbattach) behave differently in the build container, so build-in-container.sh runs it on the
# build host and hands the result in CONTEXT_RESULT. The result is then bound to the directory: the manifest hash
# it reports must be the hash of manifest.sha256, and every file consumed below must match that manifest.
if [ -n "${CONTEXT_RESULT:-}" ]; then
  cp -- "$CONTEXT_RESULT" "$OUT.context.txt"
  want="$(sed -n 's/^ARTIFACT_MANIFEST_SHA256=//p' "$OUT.context.txt")"
  [ "$(sha256sum "$CTX/manifest.sha256" | cut -d' ' -f1)" = "$want" ] || { echo "the verification result is not for this staged generation" >&2; exit 3; }
  ( cd "$CTX" && find generation.env rpms nvidia-userspace/usr/lib/firmware -type f -print0 | xargs -0 sha256sum ) | LC_ALL=C sort > "$OUT.consumed.sha256"
  awk -F'\t' '$1 == "F" { print $2 "  " $3 }' "$CTX/manifest.sha256" | LC_ALL=C sort > "$OUT.manifest.sha256"
  [ -s "$OUT.consumed.sha256" ] && [ -z "$(LC_ALL=C comm -23 "$OUT.consumed.sha256" "$OUT.manifest.sha256")" ] \
    || { echo "a consumed file does not match the staged generation manifest" >&2; exit 3; }
else
  "$REPO/ci/verify-build-context.sh" "$CTX" "$VARIANT" > "$OUT.context.txt" || { echo "staged generation not approved for $VARIANT" >&2; exit 3; }
fi
POLICY_RE='^[a-z0-9]+(-[a-z0-9]+)*$'
gen() { awk -F= -v k="$1" '$1 == k { sub(/^[^=]*=/, ""); print; n++ } END { exit n == 1 ? 0 : 1 }' "$CTX/generation.env"; }
NEVRA="$(gen kernel_nevra)"; UNAME="$(gen kernel_uname_r)"; NV="${NEVRA#*:}"   # 0:6.12.0-249... -> 6.12.0-249...
[[ "$NV" =~ ^[0-9][0-9A-Za-z._+-]*$ ]] || { echo "bad kernel nevra $NEVRA" >&2; exit 3; }
KEYID="$(sha256sum "$HERE/mkosi.extra/usr/lib/neural-ice-generic/release-authorization.pub" | cut -d' ' -f1)"
PCRID="$(sha256sum "$PCRKEY" | cut -d' ' -f1)"
ID="$(gen generation_id)"; POLICY="$(sed -n 's/^SIGNED_BOOT_TRUST_POLICY_ID=//p' "$OUT.context.txt")"
[[ "$POLICY" =~ $POLICY_RE ]] || { echo "context verification named no trust policy" >&2; exit 3; }
mkdir -p "$OUT"; OUT="$(cd "$OUT" && pwd)"; rm -rf "$OUT/stage" "$OUT/workspace"; mkdir -p "$OUT/workspace"
# Firmware and console files go in as an extra tree: the GSP blobs are the host's, byte for byte.
S="$OUT/stage"; install -d -m 0755 "$S/usr/lib/firmware" "$S/usr/lib/neural-ice-generic" "$S/usr/lib/modprobe.d" "$S/etc"
cp -a "$CTX/nvidia-userspace/usr/lib/firmware/nvidia" "$S/usr/lib/firmware/"
cp "$REPO/image/bootc-overlay/usr/lib/modprobe.d/90-neural-ice-nvidia-drm.conf" "$S/usr/lib/modprobe.d/"
cp "$REPO/image/bootc-overlay/etc/vconsole.conf" "$S/etc/vconsole.conf"
install -m 0644 "$PCRKEY" "$S/usr/lib/neural-ice-generic/pcr-policy.pub"
printf '%s\n' "kernel_nevra=$NEVRA" "generation_id=$ID" "trust_policy_id=$POLICY" > "$S/usr/lib/neural-ice-generic/host-kernel.env"
KARGS="neuralice.relauth_keyid=$KEYID neuralice.pcr_policy_key=$PCRID neuralice.min_bundle_seq=$MINSEQ neuralice.hardware_target=$TARGET"
KARGS="$KARGS neuralice.installer_version=$VERSION neuralice.access_profile=lab-managed neuralice.trust_policy_id=$POLICY"
KARGS="$KARGS neuralice.install_stage=$STAGE neuralice.target_debug=$TARGET_DEBUG ${CONSOLE_KARG} systemd.unit=ni-generic-installer.target systemd.firstboot=off"
cat > "$OUT/local.conf" <<CONF
[Build]
WorkspaceDirectory=$OUT/workspace
${MKOSI_CACHE:+PackageCacheDirectory=$MKOSI_CACHE}

[Content]
PackageDirectories=$CTX/rpms
ExtraTrees=$S:/
Packages=
        kernel-core-$NV
        kernel-modules-core-$NV
        kernel-modules-$NV
        kernel-modules-nvidia-open-$NV
KernelCommandLine=$KARGS
CONF
start=$(date +%s)
( cd "$HERE" && mkosi --force --output-directory "$OUT" --include "$OUT/local.conf" build )
echo "kernel $UNAME  generation $ID  build seconds: $(( $(date +%s) - start ))"
ls -la "$OUT"
