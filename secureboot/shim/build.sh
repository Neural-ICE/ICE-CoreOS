#!/usr/bin/env bash
# Build the Neural ICE shim reproducibly and extract the artifacts.
# Prereq: neural-ice-uefi-ca.der present in this directory (key ceremony output).
set -euo pipefail
cd "$(dirname "$0")"

[[ -f neural-ice-uefi-ca.der ]] || {
    echo "ERROR: neural-ice-uefi-ca.der missing — run the key ceremony first" >&2
    exit 1
}

TAG="neural-ice-shim:$(date +%Y%m%d)"
ENGINE="${ENGINE:-podman}"

# --format docker: required for the SHELL/pipefail directive to apply under podman
BUILD_ARGS=()
[[ "$ENGINE" == podman ]] && BUILD_ARGS+=(--format docker)
"$ENGINE" build "${BUILD_ARGS[@]}" --no-cache -t "$TAG" .
cid=$("$ENGINE" create "$TAG")
trap '"$ENGINE" rm -f "$cid" >/dev/null' EXIT

rm -rf out && mkdir out
"$ENGINE" cp "$cid":/out/. out/

echo "== artifacts =="
cat out/SHA256SUMS
echo
echo "Next: commit Dockerfile, sbat.neuralice.csv, neural-ice-uefi-ca.der,"
echo "out/shimaa64.efi and out/build.log to the Neural-ICE/shim-review fork,"
echo "then run this script a second time and diff the SHA256s to prove"
echo "reproducibility before tagging."
