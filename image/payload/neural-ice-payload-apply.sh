#!/usr/bin/env bash
# Neural ICE — apply an installer-staged payload from the data volume (one-shot).
#
# GENERIC mechanism (the OS stays vanilla): the PRELOADED installer may stage a
# `payload/` dir onto the encrypted data volume (next to seed-store/ and
# huggingface/). If it carries an apply.sh, run it ONCE as root on first boot,
# then stamp /var/lib/neural-ice/.payload-applied (machine-local /var survives
# bootc upgrades; a re-install recreates the data volume and re-applies).
# The payload CONTENT (e.g. the ICE-AC1 appliance layer) is built and owned by
# the product side — this script knows nothing about it.
set -euo pipefail

FLAG=/var/lib/neural-ice/.payload-applied
PAYLOAD=/var/lib/neural-ice/data/payload

if [ ! -x "$PAYLOAD/apply.sh" ]; then
  echo "neural-ice-payload-apply: no payload staged ($PAYLOAD/apply.sh) — nothing to do"
  exit 0
fi

echo "neural-ice-payload-apply: applying staged payload…"
bash "$PAYLOAD/apply.sh"
mkdir -p "$(dirname "$FLAG")"
touch "$FLAG"
echo "neural-ice-payload-apply: done (stamped $FLAG)"
