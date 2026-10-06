#!/bin/bash
# The generic installer's first gate (ADR-0044). Nothing on the payload partition is used before
# the release manifest it carries verifies under the release key whose file sha256 the UKI cmdline seals.
# On success it writes /run/ni-verified/release.env, the only input the install step trusts.
# Closed-world: sealed kargs exactly once and well-formed (an external cmdline appended by systemd-stub when
# Secure Boot is off must not shadow them); exactly one payload partition; one bounded copy of each object,
# verified and parsed from that copy; the manifest must be canonical JSON (no duplicate keys).
set -euo pipefail
say() { echo "ni-generic: $*" > /dev/console; echo "ni-generic: $*"; }
die() { say "REFUSED: $*"; exit 1; }
KEY=/usr/lib/neural-ice-generic/release-authorization.pub
read -r -a ARGS < /proc/cmdline
sealed() { # $1 name $2 regex -> the single value, or refuse
  local n=0 v="" a
  for a in "${ARGS[@]}"; do case "$a" in "$1="*) n=$((n + 1)); v="${a#*=}";; "$1") n=$((n + 1));; esac; done
  [ "$n" = 1 ] || die "sealed $1 appears $n times"
  [[ "$v" =~ $2 ]] || die "sealed $1 is malformed"
  printf '%s' "$v"
}
keyid="$(sealed neuralice.relauth_keyid '^[0-9a-f]{64}$')"
minseq="$(sealed neuralice.min_bundle_seq '^[1-9][0-9]{0,15}$')"
target="$(sealed neuralice.hardware_target '^[a-z0-9]+(-[a-z0-9]+)*$')"
sealed neuralice.installer_version '^[0-9]+\.[0-9]+\.[0-9]+$' >/dev/null
pcrid="$(sealed neuralice.pcr_policy_key '^[0-9a-f]{64}$')"
sealed neuralice.access_profile '^[a-z]+(-[a-z]+)*$' >/dev/null
sealed neuralice.trust_policy_id '^[a-z0-9]+(-[a-z0-9]+)*$' >/dev/null
[ "$(sha256sum "$KEY" | cut -d' ' -f1)" = "$keyid" ] || die "the embedded release key is not the sealed one"
[ "$(sha256sum /usr/lib/neural-ice-generic/pcr-policy.pub | cut -d' ' -f1)" = "$pcrid" ] || die "the embedded PCR policy key is not the sealed one"
devs=""
for _ in $(seq 1 30); do   # every block device probed first, so a slower second disk cannot be missed
  udevadm settle --timeout=30 || true
  devs="$(lsblk -rno PATH,PARTLABEL 2>/dev/null | awk '$2 == "ni-payload" { print $1 }')"
  [ -n "$devs" ] && break; sleep 1
done
[ "$(printf '%s\n' "$devs" | grep -c .)" = 1 ] || die "need exactly one ni-payload partition, found: $(printf '%s ' $devs)"
[ "$(lsblk -rno FSTYPE "$devs")" = vfat ] || die "the payload partition is not vfat"
mkdir -p /run/ni-payload /run/ni-verified; mount -t vfat -o ro,nosuid,nodev,noexec "$devs" /run/ni-payload || die "cannot mount the payload"
copy() { # one bounded copy into tmpfs; everything after reads only the copy
  local s="/run/ni-payload/$1"
  [ -f "$s" ] && [ ! -L "$s" ] || die "payload lacks $1"
  [ "$(stat -c %s "$s")" -le "$2" ] || die "$1 exceeds $2 bytes"
  cp -- "$s" "/run/ni-verified/$1"
}
copy release-manifest.json 1048576; copy release-manifest.json.sig 4096
M=/run/ni-verified/release-manifest.json
base64 -d < /run/ni-verified/release-manifest.json.sig > /run/ni-verified/sig.der 2>/dev/null || die "signature is not base64"
openssl dgst -sha256 -verify "$KEY" -signature /run/ni-verified/sig.der "$M" >/dev/null 2>&1 \
  || die "the release manifest does not verify under the sealed release key"
# duplicate keys: a leaf path seen twice in the stream (jq keeps the last one, a signer may have meant the first)
dups="$(jq -n --stream '[inputs | select(length == 2) | .[0] | tojson] | group_by(.) | map(select(length > 1)) | length' "$M")" \
  || die "the manifest is not JSON"
[ "$dups" = 0 ] || die "the manifest repeats a key"
rid="$(jq -r .release_id "$M")"; seq="$(jq -r .bundle_seq "$M")"; mt="$(jq -r .hardware_target "$M")"
host="$(jq -r '.host.repository + "@" + .host.digest' "$M")"
[[ "$seq" =~ ^[1-9][0-9]{0,15}$ ]] && [ "$seq" -ge "$minseq" ] || die "bundle_seq $seq below the sealed floor $minseq"
[ "$mt" = "$target" ] || die "manifest hardware_target $mt is not the sealed $target"
[[ "$host" =~ ^rg\.fr-par\.scw\.cloud/neural-ice-v2-lab/host-appliance@sha256:[0-9a-f]{64}$ ]] || die "host reference outside the v2 namespace: $host"
hostdigest="${host#*@}"
printf 'RELEASE_ID=%s\nBUNDLE_SEQ=%s\nHARDWARE_TARGET=%s\nHOST_REF=%s\nHOST_DIGEST=%s\n' "$rid" "$seq" "$mt" "$host" "$hostdigest" > /run/ni-verified/release.env
[[ "$rid" =~ ^[A-Za-z0-9._-]+$ ]] || die "release_id has unsafe characters"
say "NI-GENERIC-PAYLOAD-OK release=$rid seq=$seq target=$mt host=$host"
