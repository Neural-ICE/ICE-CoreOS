#!/usr/bin/env bash
# Constrains the install-time LAN registry mirror (FAB-0040 deployment bench).
#
# The mirror exists so one medium serves both a bench and a customer. Three
# properties carry that, and each one below fails loudly if it is ever dropped:
#   1. the image reference is never rewritten -- only a mirror is added;
#   2. the mirror is digest-only, so a hostile mirror cannot substitute content;
#   3. the mirror does not survive onto the installed appliance.
#
# Property 3 is the one that needs a TEST rather than a comment: it is asserted
# by a block that runs once, at install time, on hardware nobody watches.
set -euo pipefail
cd "$(dirname "$0")/.."
S=ota/neural-ice-autoinstall.sh
fail=0
check() { # $1=description  $2..=grep args
  local d="$1"; shift
  if grep -q "$@" "$S"; then printf '  ok    %s\n' "$d"
  else printf '  FAIL  %s\n' "$d"; fail=1; fi
}

check "the mirror is read from an explicit kernel argument" -F 'neuralice.mirror='
check "the mirror value is validated as a bare host[:port]" -F '^[A-Za-z0-9._-]+(:[0-9]{1,5})?$'
check "the mirror is digest-only"                           -F 'pull-from-mirror = "digest-only"'
check "the drop-in lands in the LIVE environment only"      -F '/etc/containers/registries.conf.d/99-neural-ice-install-mirror.conf'
check "the target is checked for a leaked mirror drop-in"   -F '"$dep"/etc/containers/registries.conf.d/*neural-ice-install-mirror*'
check "a leaked drop-in is removed, not merely reported"    -E 'rm -f -- "\$\{_leaked\[@\]\}"'

# The property that makes the whole design work: the image reference is NOT
# rewritten. A `location =` that points anywhere other than the real registry
# would mean the medium installs something whose identity differs from what the
# signed lock names -- exactly what digest-pinning is supposed to prevent.
if grep -E '^\s*location = "registry\.neural-ice\.ch/' "$S" >/dev/null; then
  printf '  ok    the registry scope keeps its real name (no reference rewriting)\n'
else
  printf '  FAIL  the registry scope must stay registry.neural-ice.ch\n'; fail=1
fi

# A trailing `[[ ]] && cmd` as the LAST statement of the script would make the
# unit fail on the common path. Cheap to check, impossible to spot in review.
if [ "$(tail -n 1 "$S" | grep -cE '^\[\[.*\]\] &&')" != 0 ]; then
  printf '  FAIL  the script ends on a conditional && list; it would exit non-zero when the condition is false\n'; fail=1
else
  printf '  ok    the script does not end on a conditional && list\n'
fi

# --------------------------------------------------------------------------- #
# The registry install source (FAB-0040 light medium).
#
# This path installs bytes that arrived over the network, so every guard below
# is the difference between "digest-pinned and signature-verified" and "whatever
# the LAN served".
check "the install source is an explicit kernel argument"    -F 'neuralice.source='
check "the appliance image is an explicit kernel argument"   -F 'neuralice.osimage='
check "the appliance image must be digest-pinned"            -F '@sha256:[0-9a-f]{64}$'
check "a registry install requires a signed docker scope"    -F 'refusing a registry install that nothing would verify'
check "the pulled digest is re-checked after the pull"       -F 'is not the requested one'
check "bootc consumes the resolved source, not a literal"    -F -e '--source-imgref "$source_imgref"'

# The default MUST remain the medium. This is the single property that keeps the
# USB path -- the one that installs appliances today -- untouched by all of the
# above.
if grep -qE '^INSTALL_SOURCE=medium$' "$S"; then
  printf '  ok    the default install source is the medium (USB path unchanged)\n'
else
  printf '  FAIL  the default install source must be `medium`; a registry default would break every offline install\n'; fail=1
fi

[ "$fail" = 0 ] || { echo "install registry mirror: FAILED"; exit 1; }
echo "install registry mirror: OK"
