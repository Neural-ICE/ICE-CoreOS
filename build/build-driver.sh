#!/usr/bin/env bash
# Build the NVIDIA open GPU kernel modules against the freshly-built GB10 kernel
# and sign them with that kernel build's EPHEMERAL module-signing key — the key
# whose public half the kernel build embedded in .builtin_trusted_keys, and whose
# private half is discarded with the build. This binds the modules to exactly one
# kernel build (see secureboot/signing-pipeline.md) and leaves no persistent
# module-signing key to protect.
#
# MUST run in the SAME build context as the kernel build (same container, same
# rpmbuild tree), right after it, BEFORE the tree is cleaned — that is the only
# window where certs/signing_key.pem still exists.
#
# Inputs (env):
#   KTREE   kernel source/build tree that contains certs/signing_key.pem
#           (default: the nvidia-gb10 checkout under the workspace)
#   KVER    kernel version-release.arch (default: derived from kernel-devel)
#   NVSRC   NVIDIA open module source (…/kernel-open)
#   OUT     directory to stage the signed *.ko into
set -euo pipefail

KTREE="${KTREE:?set KTREE to the kernel build tree holding certs/signing_key.pem}"
NVSRC="${NVSRC:?set NVSRC to the NVIDIA .../kernel-open source}"
OUT="${OUT:-./driver-out}"

# 1) Locate the kernel build's ephemeral signing key + its certificate.
SIGN_KEY="$(find "$KTREE" -path '*/certs/signing_key.pem' 2>/dev/null | head -1)"
SIGN_X509="$(find "$KTREE" -path '*/certs/signing_key.x509' 2>/dev/null | head -1)"
if [[ -z "$SIGN_KEY" || -z "$SIGN_X509" ]]; then
  echo "ERROR: ephemeral kernel signing key not found under $KTREE." >&2
  echo "       This script must run right after the kernel build, in the same" >&2
  echo "       tree, before certs/signing_key.pem is cleaned up." >&2
  exit 2
fi

# 2) Confirm this key is the one the kernel actually trusts (fail closed).
KVER="${KVER:-$(rpm -q --qf '%{VERSION}-%{RELEASE}.%{ARCH}\n' kernel-devel 2>/dev/null | head -1)}"
SF="/usr/src/kernels/${KVER}/scripts/sign-file"
[[ -x "$SF" ]] || SF="$(find "/usr/src/kernels/${KVER}" -name sign-file 2>/dev/null | head -1)"
[[ -x "$SF" ]] || { echo "ERROR: sign-file not found for KVER=$KVER" >&2; exit 3; }

echo "==> ephemeral key : $SIGN_KEY"
echo "==> kernel        : $KVER"
echo "==> sign-file     : $SF"

# 3) Build the NVIDIA open modules against this kernel.
rm -rf /tmp/kernel-open && cp -a "$NVSRC" /tmp/kernel-open && cd /tmp/kernel-open
make -j"$(nproc)" modules SYSSRC="/usr/src/kernels/${KVER}"

# 4) Sign every .ko with the EPHEMERAL key, stage it, and verify the signer.
mkdir -p "$OUT"; n=0
while IFS= read -r ko; do
  "$SF" sha512 "$SIGN_KEY" "$SIGN_X509" "$ko"
  cp "$ko" "$OUT/"
  echo "--- $(basename "$ko") ---"; modinfo "$ko" | grep -E '^(vermagic|signer|sig_hashalgo):'
  n=$((n+1))
done < <(find . -name '*.ko')
echo "==> signed $n module(s) with the per-build ephemeral key into $OUT"

# 5) The private key is discarded when the kernel build tree is cleaned; do not
#    copy it anywhere. (The kernel build owns its lifecycle.)
echo "==> reminder: certs/signing_key.pem must NOT be persisted — it dies with the build."
