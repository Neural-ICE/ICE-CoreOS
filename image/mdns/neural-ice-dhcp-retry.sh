#!/usr/bin/env bash
#
# Neural ICE CoreOS — return to DHCP when the link-local fallback is holding the
# management NIC.
#
# NetworkManager does NOT preempt an active connection: `autoconnect` only picks
# a profile when the device is free, and `autoconnect-priority` merely orders the
# candidates at that moment. So an appliance that booted onto a link with no DHCP
# server activates `fallback-<iface>` and KEEPS it — even once a DHCP server
# appears — until a carrier bounce, a reboot, or an explicit reconnection. This
# unit is that explicit reconnection.
#
# The attempt is not free: NetworkManager drops the fallback, waits out
# `ipv4.dhcp-timeout` (45 s by default) and, on failure, autoconnects the
# fallback again — roughly a minute during which the appliance answers on
# neither address. Hence the deliberately long timer period: this trades a
# short, periodic outage on a machine that is ALREADY off its normal address for
# an automatic return to the LAN, and does nothing at all the rest of the time.
set -uo pipefail

# The management NIC is resolved by exactly the same rule as the hostname, so
# reuse that code rather than restate it. Sourcing is safe: the file only runs
# main() when executed as a program.
readonly INIT_SCRIPT="${NEURAL_ICE_HOSTNAME_INIT:-/usr/local/bin/neural-ice-hostname-init.sh}"
if [ ! -r "$INIT_SCRIPT" ]; then
    echo "neural-ice-dhcp-retry: cannot read $INIT_SCRIPT" >&2
    exit 0
fi
# shellcheck source=/dev/null
. "$INIT_SCRIPT"
set +e   # the sourced file turns errexit on; this one decides for itself

log() { echo "neural-ice-dhcp-retry: $*"; }

# The management profile's id as NetworkManager knows it, read from the profile
# itself rather than assumed to be "mgmt-<iface>".
mgmt_profile() {
    local conn id
    for conn in "${NM_CONN_DIR}"/mgmt-*.nmconnection; do
        [ -e "$conn" ] || continue
        id="$(sed -n 's/^id=//p' "$conn" | head -1)"
        if [ -n "$id" ]; then
            echo "$id"
            return 0
        fi
    done
    return 1
}

active_profile_on() {
    nmcli -t -f NAME,DEVICE connection show --active 2>/dev/null \
        | awk -F: -v i="$1" '$2 == i { print $1; exit }'
}

main() {
    local iface profile active
    command -v nmcli >/dev/null 2>&1 || { log "nmcli absent, nothing to do"; exit 0; }
    systemctl is-active --quiet NetworkManager 2>/dev/null \
        || { log "NetworkManager is not running, nothing to do"; exit 0; }

    iface="$(mgmt_interface)"  || { log "no management interface, nothing to do"; exit 0; }
    profile="$(mgmt_profile)"  || { log "no management profile in ${NM_CONN_DIR}"; exit 0; }
    active="$(active_profile_on "$iface")"

    if [ "$active" != "fallback-${iface}" ]; then
        log "active profile on ${iface} is '${active:-none}' — nothing to retry"
        exit 0
    fi

    log "link-local fallback holds ${iface}; trying '${profile}' (expect ~1 min without any address if DHCP is still absent)"
    if nmcli connection up "$profile" >/dev/null 2>&1; then
        log "DHCP answered: '${profile}' is active on ${iface}"
    else
        log "still no DHCP; NetworkManager re-activates the fallback on its own"
    fi
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    main "$@"
fi
