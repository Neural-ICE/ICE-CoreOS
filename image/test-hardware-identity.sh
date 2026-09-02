#!/usr/bin/env bash
# shellcheck disable=SC2016 # literal source-contract assertions below
# THE MEASURED HARDWARE IDENTITY. `neuralice.hardware_target=` used to be a word
# sealed at build time and compared only with another copy of itself, so a medium
# built for a GB10 satisfied every check on any arm64 box and then wiped it.
#
# Every case below is a machine this code could actually be booted on.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIB="$ROOT/image/lib/hardware-identity.sh"
work="$(mktemp -d "${TMPDIR:-/tmp}/ni-hardware-identity.XXXXXX")"
trap 'rm -rf "$work"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

machine_dt() { # $1=dir  $2..=compatible entries
  local dir=$1; shift
  mkdir -p "$dir/sys/firmware/devicetree/base"
  : > "$dir/sys/firmware/devicetree/base/compatible"
  local entry
  for entry in "$@"; do printf '%s\0' "$entry" >> "$dir/sys/firmware/devicetree/base/compatible"; done
}
machine_dmi() { # $1=dir  $2=vendor  $3=product  $4=board
  local dir=$1
  mkdir -p "$dir/sys/class/dmi/id"
  printf '%s\n' "$2" > "$dir/sys/class/dmi/id/sys_vendor"
  printf '%s\n' "$3" > "$dir/sys/class/dmi/id/product_name"
  printf '%s\n' "$4" > "$dir/sys/class/dmi/id/board_name"
}

# --------------------------------------------------------------------------- #
# 1) MEASUREMENT. Device-tree wins where it exists — it is the property the
#    kernel itself matches drivers on — and SMBIOS is the fallback.
# --------------------------------------------------------------------------- #
GB10="$work/gb10"; machine_dt "$GB10" nvidia,gb10 nvidia,tegra264
[ "$(bash "$LIB" measure "$GB10")" = 'devicetree:nvidia,gb10,nvidia,tegra264' ] \
  || fail "the device-tree measurement is not the canonical joined form"

X86="$work/x86"; machine_dmi "$X86" 'ACME Corp' 'Model 5' 'B550'
[ "$(bash "$LIB" measure "$X86")" = 'dmi:ACME Corp|Model 5|B550' ] \
  || fail "the SMBIOS measurement is not the canonical triple"

# Device-tree takes precedence when both are present: two answers for one
# machine would mean two fingerprints for one machine.
BOTH="$work/both"; machine_dt "$BOTH" nvidia,gb10; machine_dmi "$BOTH" A B C
[ "$(bash "$LIB" measure "$BOTH")" = 'devicetree:nvidia,gb10' ] \
  || fail "SMBIOS overrode device-tree"

# 🔴 A MACHINE THAT CANNOT BE IDENTIFIED. There is deliberately no third branch:
# "I do not know what this is" is not a licence to repartition it.
BLIND="$work/blind"; mkdir -p "$BLIND"
bash "$LIB" measure "$BLIND" >/dev/null 2>&1 \
  && fail "a machine exposing neither device-tree nor SMBIOS was measured anyway"

# A partial SMBIOS is not an identity: a vendor string alone is not a model.
PARTIAL="$work/partial"; mkdir -p "$PARTIAL/sys/class/dmi/id"
printf 'ACME\n' > "$PARTIAL/sys/class/dmi/id/sys_vendor"
bash "$LIB" measure "$PARTIAL" >/dev/null 2>&1 \
  && fail "a partial SMBIOS was measured as an identity"

# The '|' separator is refused inside a field, so a crafted product name cannot
# forge a second one and collide with a different machine's fingerprint.
FORGE="$work/forge"; machine_dmi "$FORGE" 'ACME|NVIDIA' 'DGX' 'X'
bash "$LIB" measure "$FORGE" >/dev/null 2>&1 \
  && fail "a product string containing the field separator was measured"

# An implausibly large sysfs value is a corrupt or hostile machine, not a name.
HUGE="$work/huge"; mkdir -p "$HUGE/sys/firmware/devicetree/base"
head -c 4096 /dev/zero | tr '\0' 'a' > "$HUGE/sys/firmware/devicetree/base/compatible"
bash "$LIB" measure "$HUGE" >/dev/null 2>&1 && fail "an oversized compatible property was measured"

# A symlinked compatible property could point anywhere; it is not this machine.
LINKED="$work/linked"; mkdir -p "$LINKED/sys/firmware/devicetree/base"
printf 'nvidia,gb10\0' > "$work/elsewhere"
ln -s "$work/elsewhere" "$LINKED/sys/firmware/devicetree/base/compatible"
bash "$LIB" measure "$LINKED" >/dev/null 2>&1 \
  && fail "a symlinked device-tree property was measured"

# The fingerprint is a pure function of the measurement.
FP="$(bash "$LIB" fingerprint "$GB10")"
[ "$FP" = "$(printf 'devicetree:nvidia,gb10,nvidia,tegra264' | sha256sum | awk '{print $1}')" ] \
  || fail "the fingerprint is not the SHA-256 of the canonical measurement"
[ "$FP" = "$(bash "$LIB" fingerprint "$GB10")" ] || fail "the fingerprint is not deterministic"

# --------------------------------------------------------------------------- #
# 2) THE LIST. Absence fails closed at every step: an empty or missing list is a
#    refusal, never "any machine will do".
# --------------------------------------------------------------------------- #
IMG="$work/image"
mkdir -p "$IMG/usr/lib/neural-ice/hardware-identity"
LIST="$IMG/usr/lib/neural-ice/hardware-identity/nvidia-gb10-arm64.fingerprints"
printf '# measured 2026-08-31 on the reference appliance\n%s\n' "$FP" > "$LIST"
[ "$(bash "$LIB" read-fingerprints "$IMG" nvidia-gb10-arm64)" = "$FP" ] \
  || fail "a well-formed fingerprint list was not read"
bash "$LIB" assert-target "$IMG" nvidia-gb10-arm64 "$GB10" >/dev/null \
  || fail "the reference machine was refused by its own list"

# 🔴 THE FINDING. A medium sealed for one target, booted on another machine.
bash "$LIB" assert-target "$IMG" nvidia-gb10-arm64 "$X86" >/dev/null 2>&1 \
  && fail "a machine the target does not admit was accepted"
bash "$LIB" assert-target "$IMG" nvidia-gb10-arm64 "$BLIND" >/dev/null 2>&1 \
  && fail "an unidentifiable machine was accepted"

: > "$LIST"
bash "$LIB" assert-target "$IMG" nvidia-gb10-arm64 "$GB10" >/dev/null 2>&1 \
  && fail "an EMPTY fingerprint list admitted the machine"
printf '# only comments\n\n' > "$LIST"
bash "$LIB" assert-target "$IMG" nvidia-gb10-arm64 "$GB10" >/dev/null 2>&1 \
  && fail "a comment-only fingerprint list admitted the machine"
printf 'not-a-fingerprint\n' > "$LIST"
bash "$LIB" assert-target "$IMG" nvidia-gb10-arm64 "$GB10" >/dev/null 2>&1 \
  && fail "a malformed fingerprint list was parsed"
rm -f "$LIST"
bash "$LIB" assert-target "$IMG" nvidia-gb10-arm64 "$GB10" >/dev/null 2>&1 \
  && fail "a MISSING fingerprint list admitted the machine"
printf '%s\n' "$FP" > "$LIST"

# A list for one target says nothing about another.
bash "$LIB" assert-target "$IMG" some-other-box "$GB10" >/dev/null 2>&1 \
  && fail "a target with no list of its own was accepted"
# ...and a target name that is not a target name is refused before any file read.
bash "$LIB" read-fingerprints "$IMG" '../../etc/passwd' >/dev/null 2>&1 \
  && fail "a traversal-shaped hardware target reached the filesystem"

# Several accepted revisions is legitimate; the list is a set, not a single value.
printf '%s\n%s\n' "$(bash "$LIB" fingerprint "$X86")" "$FP" > "$LIST"
bash "$LIB" assert-target "$IMG" nvidia-gb10-arm64 "$GB10" >/dev/null \
  || fail "a machine listed second was refused"
bash "$LIB" assert-target "$IMG" nvidia-gb10-arm64 "$X86" >/dev/null \
  || fail "a second accepted revision was refused"

# --------------------------------------------------------------------------- #
# 3) THE WIRING. A perfect implementation nothing calls is what the review found
#    the first time.
# --------------------------------------------------------------------------- #
grep -Fq 'hardware_identity_assert_target "$root" "$sealed_target"' \
  "$ROOT/image/lib/installer-trust.sh" \
  || fail "the sealed trust gate never measures the machine it is standing on"
grep -Fq 'COPY image/lib/hardware-identity.sh /usr/lib/neural-ice/lib/hardware-identity.sh' \
  "$ROOT/image/Containerfile.bootc" \
  || fail "the image does not ship the measured-identity reader"
grep -Fq 'COPY image/hardware-identity/ /usr/lib/neural-ice/hardware-identity/' \
  "$ROOT/image/Containerfile.bootc" \
  || fail "the image does not ship the accepted-fingerprint lists"
grep -Fq 'HARDWARE_IDENTITY_FILE' "$ROOT/image/build-installer-uki.sh" \
  || fail "the UKI build does not require a measured-identity list"
grep -Fq 'HARDWARE_IDENTITY_FILE' "$ROOT/image/build-installer-usb.sh" \
  || fail "the media build does not require a measured-identity list"
# A list must be measured, not invented in this open-core tree: every list stays
# ignored by default, and exactly one — the target this tree ships — is
# un-ignored by exact name. A second negation would put a target back in the
# tree without this test noticing.
grep -Fq 'image/hardware-identity/*.fingerprints' "$ROOT/.gitignore" \
  || fail "a fingerprint list could be committed without anyone having measured it"
[ "$(grep -c '^!image/hardware-identity/.*\.fingerprints$' "$ROOT/.gitignore")" = 1 ] \
  || fail "the set of committed fingerprint lists changed without this test"
grep -Fqx '!image/hardware-identity/nvidia-gb10-arm64.fingerprints' "$ROOT/.gitignore" \
  || fail "the shipped target's measured list is not the one that is committed"

# --------------------------------------------------------------------------- #
# 4) THE COMMITTED LIST. The digests in the tree must be the digests of the
#    machines the comments name. A datasheet cannot produce them: each one is
#    reproduced here from the canonical SMBIOS triple of a real appliance, so an
#    edited, truncated or invented entry fails this suite rather than a boot.
# --------------------------------------------------------------------------- #
SHIPPED="$ROOT/image/hardware-identity/nvidia-gb10-arm64.fingerprints"
[ -f "$SHIPPED" ] || fail "the shipped target has no committed fingerprint list"
SHIPPED_IMG="$work/shipped"
mkdir -p "$SHIPPED_IMG/usr/lib/neural-ice/hardware-identity"
cp "$SHIPPED" "$SHIPPED_IMG/usr/lib/neural-ice/hardware-identity/nvidia-gb10-arm64.fingerprints"

# POSITIVE: both measured appliances are admitted by the committed list.
SPARK="$work/spark"; machine_dmi "$SPARK" 'NVIDIA' 'NVIDIA_DGX_Spark' 'P4242'
[ "$(bash "$LIB" measure "$SPARK")" = 'dmi:NVIDIA|NVIDIA_DGX_Spark|P4242' ] \
  || fail "the DGX Spark triple is not the identity the committed comment names"
bash "$LIB" assert-target "$SHIPPED_IMG" nvidia-gb10-arm64 "$SPARK" >/dev/null \
  || fail "the committed list refuses the reference build appliance"

GX10="$work/gx10"; machine_dmi "$GX10" 'ASUSTeK COMPUTER INC.' 'GX10' 'GX10'
[ "$(bash "$LIB" measure "$GX10")" = 'dmi:ASUSTeK COMPUTER INC.|GX10|GX10' ] \
  || fail "the ASUS GX10 triple is not the identity the committed comment names"
bash "$LIB" assert-target "$SHIPPED_IMG" nvidia-gb10-arm64 "$GX10" >/dev/null \
  || fail "the committed list refuses the qualification appliance"

# ...and the file says exactly those two machines, in the reader's own grammar.
[ "$(bash "$LIB" read-fingerprints "$SHIPPED_IMG" nvidia-gb10-arm64 | wc -l)" = 2 ] \
  || fail "the committed list does not carry exactly the two measured machines"

# The bootc fail-closed RUN used `grep -Eq` under `set -o pipefail`.
# read-fingerprints prints two lines for this target; grep -q exits after the
# first; the writer dies SIGPIPE; the pipeline is 141. Run 33692480833 died
# there after the key and the list were already present.
if grep -n 'read-fingerprints' "$ROOT/image/Containerfile.bootc" | grep -F 'grep -Eq' >/dev/null; then
  fail "Containerfile.bootc still pipes read-fingerprints into grep -Eq; that is exit 141 on a two-entry list"
fi
(
  set -o pipefail
  fps="$(bash "$LIB" read-fingerprints "$SHIPPED_IMG" nvidia-gb10-arm64)"
  printf '%s\n' "$fps" | grep -E '^[0-9a-f]{64}$' >/dev/null
) || fail "the bootc fingerprint presence check fails under pipefail on the shipped two-entry list"

# NEGATIVE: a GB10-adjacent machine nobody measured is still refused, and so is
# the same vendor with a different board — the list is a set of measurements,
# not a family.
OTHER="$work/other-gb10"; machine_dmi "$OTHER" 'NVIDIA' 'NVIDIA_DGX_Spark' 'P9999'
bash "$LIB" assert-target "$SHIPPED_IMG" nvidia-gb10-arm64 "$OTHER" >/dev/null 2>&1 \
  && fail "an unmeasured board revision was admitted by the committed list"
LOOKALIKE="$work/lookalike"; machine_dmi "$LOOKALIKE" 'ASUSTeK COMPUTER INC.' 'GX11' 'GX10'
bash "$LIB" assert-target "$SHIPPED_IMG" nvidia-gb10-arm64 "$LOOKALIKE" >/dev/null 2>&1 \
  && fail "an unmeasured product was admitted by the committed list"

# NEGATIVE: one flipped hex character is a different machine, so a tampered or
# mistyped entry admits nobody rather than admitting somebody else.
TAMPERED="$work/tampered"
mkdir -p "$TAMPERED/usr/lib/neural-ice/hardware-identity"
sed 's/^290dbcf4/290dbcf5/' "$SHIPPED" \
  > "$TAMPERED/usr/lib/neural-ice/hardware-identity/nvidia-gb10-arm64.fingerprints"
bash "$LIB" assert-target "$TAMPERED" nvidia-gb10-arm64 "$SPARK" >/dev/null 2>&1 \
  && fail "a tampered fingerprint still admitted the machine it was derived from"

echo "HARDWARE_IDENTITY_TEST_OK"
