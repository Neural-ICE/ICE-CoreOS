#!/usr/bin/env bash
# No IPv6 on the appliance's NetworkManager profiles (Owner decision, 2026-09-11).
#
# MEASURED on the lab GX10 (first boot C27, 2026-09-10): with ipv6.method=auto on
# the management profile and no IPv6 router on the LAN, NetworkManager held
# enP7s7 in ip-check for 51 s (router solicitation, then a 45 s DHCPv6
# transaction) and declared "startup complete" 0.1 s after nm-online's 60 s
# timeout: NetworkManager-wait-online failed, the system reported "degraded",
# and every unit After=network-online.target waited a minute for nothing.
#
# Every profile the image ships and every profile it renders at boot must carry
# [ipv6] method=disabled. Non-vacuous: the shipped set and the rendered set are
# both counted, and the check fails if either is empty.
set -euo pipefail
cd "$(dirname "$0")/.."
fails=0
ok()   { printf '  ok    %s\n' "$*"; }
fail() { printf '  FAIL  %s\n' "$*" >&2; fails=$((fails + 1)); }
ipv6_method() { # <file> -> the method= value inside [ipv6]
  awk '/^\[/ { in6 = ($0 == "[ipv6]") } in6 && /^method=/ { sub(/^method=/, ""); print }' "$1"
}
shipped=0
for f in image/bootc-overlay/etc/NetworkManager/system-connections/*.nmconnection; do
  shipped=$((shipped + 1))
  m="$(ipv6_method "$f")"
  if [ "$m" = disabled ]; then ok "$(basename "$f"): ipv6 disabled"; else fail "$(basename "$f"): [ipv6] method is '${m:-absent}', not disabled"; fi
done
(( shipped >= 3 )) || fail "only $shipped shipped profile(s) found: the layout moved, or profiles were dropped"
# The fallback profile is rendered by hostname-init; read its [ipv6] block from the heredoc.
rendered="$(awk '/^\[ipv6\]$/ { in6 = 1; next } in6 && /^method=/ { sub(/^method=/, ""); print; exit }' image/mdns/neural-ice-hostname-init.sh)"
if [ "$rendered" = disabled ]; then ok "rendered fallback profile: ipv6 disabled"; else fail "the rendered fallback profile's [ipv6] method is '${rendered:-absent}', not disabled"; fi
# Nothing in the image may re-enable it through NetworkManager.conf defaults.
if grep -rqs 'ipv6.method=\(auto\|dhcp\|link-local\|shared\)' image/bootc-overlay/etc/NetworkManager/ 2>/dev/null; then
  fail "a NetworkManager.conf default re-enables IPv6"
else ok "no NetworkManager.conf default re-enables IPv6"; fi
if (( fails > 0 )); then echo "test-no-ipv6-on-profiles: $fails FAILURE(S)" >&2; exit 1; fi
echo "test-no-ipv6-on-profiles: OK ($shipped shipped profiles + the rendered fallback)"
