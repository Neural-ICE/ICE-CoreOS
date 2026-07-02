#!/usr/bin/env bash
# Neural ICE — first-boot seed import (PRELOADED edition).
#
# The preloaded installer stages OCI image archives onto the encrypted data volume at
# /var/lib/neural-ice/data/seed/images/*.tar. On first boot (before the app Quadlets), import
# them into the root podman storage so the Quadlets start offline — no registry pull. The
# archives are removed after a successful import (they were a one-shot install seed). A stamp
# file makes this idempotent. No-op (and instant) when there is no seed (the LIGHT edition).
set -euo pipefail

SEED_DIR="/var/lib/neural-ice/data/seed/images"
STAMP="/var/lib/neural-ice/.seed-imported"

[ -f "$STAMP" ] && exit 0
[ -d "$SEED_DIR" ] || { echo "seed-import: no seed present (light edition) — nothing to do"; exit 0; }

shopt -s nullglob
archives=("$SEED_DIR"/*.tar)
[ ${#archives[@]} -gt 0 ] || { echo "seed-import: seed dir empty"; touch "$STAMP"; exit 0; }

echo "seed-import: importing ${#archives[@]} image archive(s) into podman storage…"
for a in "${archives[@]}"; do
  echo "seed-import: + $(basename "$a")"
  # `podman load` restores each image under its ORIGINAL ref embedded in the archive
  # (e.g. ghcr.io/neural-ice/vllm-node:latest), so the Quadlets find it with no pull.
  podman load -i "$a" || { echo "seed-import: FAILED on $a" >&2; exit 1; }
done

echo "seed-import: done — reclaiming seed space"
rm -f "${archives[@]}"
rmdir "$SEED_DIR" 2>/dev/null || true
mkdir -p "$(dirname "$STAMP")"
touch "$STAMP"
echo "seed-import: complete"
