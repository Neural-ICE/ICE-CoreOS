#!/bin/bash
# Prototype of the generic installer's first gate (ADR-0044): nothing on the payload partition is used before
# the release manifest it carries verifies under the release key whose file sha256 the UKI cmdline seals.
set -euo pipefail
say() { echo "ni-generic: $*" > /dev/console; echo "ni-generic: $*"; }
die() { say "REFUSED: $*"; exit 1; }
KEY=/usr/lib/neural-ice-generic/release-authorization.pub
karg() { tr ' ' '\n' < /proc/cmdline | sed -n "s/^$1=//p" | tail -1; }
keyid="$(karg neuralice.relauth_keyid)"
[[ "$keyid" =~ ^[0-9a-f]{64}$ ]] || die "no sealed neuralice.relauth_keyid"
[ "$(sha256sum "$KEY" | cut -d' ' -f1)" = "$keyid" ] || die "the embedded release key is not the sealed one"
minseq="$(karg neuralice.min_bundle_seq)"; [[ "$minseq" =~ ^[0-9]+$ ]] || minseq=1
dev=""; for _ in $(seq 1 30); do [ -e /dev/disk/by-partlabel/ni-payload ] && { dev=/dev/disk/by-partlabel/ni-payload; break; }; sleep 1; done
[ -n "$dev" ] || die "no partition labelled ni-payload"
mkdir -p /run/ni-payload; mount -o ro "$dev" /run/ni-payload || die "cannot mount the payload"
P=/run/ni-payload
for f in release-manifest.json release-manifest.json.sig; do [ -s "$P/$f" ] || die "payload lacks $f"; done
base64 -d "$P/release-manifest.json.sig" > /run/manifest.sig.der 2>/dev/null || die "signature is not base64"
openssl dgst -sha256 -verify "$KEY" -signature /run/manifest.sig.der "$P/release-manifest.json" >/dev/null 2>&1 \
  || die "the release manifest does not verify under the sealed release key"
rid="$(jq -r .release_id "$P/release-manifest.json")"; seq="$(jq -r .bundle_seq "$P/release-manifest.json")"
host="$(jq -r '.host.repository + "@" + .host.digest' "$P/release-manifest.json")"
[[ "$seq" =~ ^[0-9]+$ ]] && [ "$seq" -ge "$minseq" ] || die "bundle_seq $seq below the sealed floor $minseq"
[[ "$host" =~ ^rg\.fr-par\.scw\.cloud/neural-ice-v2-lab/host-appliance@sha256:[0-9a-f]{64}$ ]] || die "host reference outside the v2 namespace: $host"
say "NI-GENERIC-PAYLOAD-OK release=$rid seq=$seq host=$host"
