#!/usr/bin/env bash
# The phase-5 NIC helpers must survive a mirror name the routing lookup cannot
# take: `ip route get <name>` exits non-zero, and under the installer's
# `set -euo pipefail` a failing `iface="$(...)"` assignment ended the whole
# install silently (GX10, 2026-09-19, first name-sealed medium). The helpers are
# extracted from the installer (it wipes disks; it cannot be sourced) and run in
# a shell with the installer's options against an unresolvable name and an
# address; both must return 0 and log the unpinned/no-readout path.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AUTOINSTALL="$HERE/neural-ice-autoinstall.sh"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
{
  echo 'set -euo pipefail'
  printf '%s\n' 'log() { printf "%s\n" "$*"; }'
  echo 'bg_stop() { :; }'
  echo 'declare -A _net_health_before=()'
  awk '/^mirror_route_iface\(\) \{/,/^}$/' "$AUTOINSTALL"
  awk '/^isolate_mirror_nic_irq\(\) \{/,/^}$/' "$AUTOINSTALL"
  awk '/^network_health_snapshot\(\) \{/,/^}$/' "$AUTOINSTALL"
} >"$TMP/helpers.sh"
for fn in mirror_route_iface isolate_mirror_nic_irq network_health_snapshot; do
  grep -q "^${fn}()" "$TMP/helpers.sh" || fail "cannot extract ${fn} from the installer"
done
# shellcheck disable=SC2016 # literal source-shape assertion
grep -q 'ip -o -4 route get "\$host"' "$AUTOINSTALL" \
  && fail "the installer still hands the raw mirror host to ip route get; route through mirror_route_iface"

# 1. an mDNS name NSS cannot answer: no exit, the unpinned path is logged
out="$(bash -c 'source "$1"; INSTALL_MIRROR="mirror.does-not-resolve.local:5055"; isolate_mirror_nic_irq; network_health_snapshot before; echo SURVIVED' _ "$TMP/helpers.sh")" \
  || fail "the helpers exited on an unresolvable mirror name (rc=$?)"
grep -q 'SURVIVED' <<<"$out" || fail "the helpers did not run to completion: $out"
grep -q 'IRQ: no resolvable route to the mirror host mirror.does-not-resolve.local' <<<"$out" \
  || fail "isolate_mirror_nic_irq did not log the unpinned path: $out"
grep -q 'NET before: no resolvable route to the mirror host mirror.does-not-resolve.local' <<<"$out" \
  || fail "network_health_snapshot did not log the no-readout path: $out"

# 2. an address: the lookup goes through ip route get and still cannot end the shell
out="$(bash -c 'source "$1"; INSTALL_MIRROR="127.0.0.1:5055"; isolate_mirror_nic_irq; network_health_snapshot before; echo SURVIVED' _ "$TMP/helpers.sh")" \
  || fail "the helpers exited on an address mirror (rc=$?)"
grep -q 'SURVIVED' <<<"$out" || fail "the helpers did not complete for an address: $out"

# 3. the resolver itself: a name -> "" ; an address -> the route interface (or "" where there is none)
out="$(bash -c 'source "$1"; r="$(mirror_route_iface mirror.does-not-resolve.local)"; [ -z "$r" ] && echo EMPTY_OK; mirror_route_iface 127.0.0.1 >/dev/null && echo ADDR_OK' _ "$TMP/helpers.sh")" \
  || fail "mirror_route_iface returned non-zero"
grep -q EMPTY_OK <<<"$out" || fail "mirror_route_iface did not yield an empty interface for an unresolvable name"
grep -q ADDR_OK <<<"$out" || fail "mirror_route_iface failed for an address"
echo "PASS: phase-5 NIC helpers survive an unresolvable mirror name and route addresses through ip"
