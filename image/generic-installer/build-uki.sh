#!/bin/bash
# Build the generic installer UKI once per installer version (ADR-0044). Seals in the cmdline only what does
# not change per release: release key id, anti-rollback floor, hardware target, installer version.
# Usage: build-uki.sh OUTDIR [MIN_BUNDLE_SEQ] [HARDWARE_TARGET] [INSTALLER_VERSION]
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; OUT="${1:?outdir}"; MINSEQ="${2:-1}"; TARGET="${3:-nvidia-gb10-arm64}"; VERSION="${4:-0.1.0}"
KEYID="$(sha256sum "$HERE/mkosi.extra/usr/lib/neural-ice-generic/release-authorization.pub" | cut -d' ' -f1)"
printf '[Content]\nKernelCommandLine=neuralice.relauth_keyid=%s neuralice.min_bundle_seq=%s neuralice.hardware_target=%s neuralice.installer_version=%s\n' "$KEYID" "$MINSEQ" "$TARGET" "$VERSION" > "$HERE/mkosi.local.conf"
mkdir -p "$OUT"
start=$(date +%s)
( cd "$HERE" && mkosi --force --output-directory "$OUT" build )
echo "build seconds: $(( $(date +%s) - start ))"
ls -la "$OUT"
