#!/usr/bin/env bash
#
# Neural ICE CoreOS — deterministic hostname + mDNS name from the management NIC.
#
# Sets the persistent system hostname to `ni-coreos-<XXXX>`, where <XXXX> is the
# last two octets (4 lowercase hex chars) of the RJ45 management NIC's MAC. The
# management NIC is chosen DETERMINISTICALLY from its NetworkManager connection
# profile (interface-name in mgmt-*.nmconnection), never from kernel enumeration
# order, so a box with several NICs always names itself from the same physical
# port across reboots and reinstalls.
#
# It also (re)publishes the short hostname to /run/neural-ice/mdns-hostname — the
# runtime contract the console TUI reads to derive the access URL
# (https://<hostname>.local). /run is tmpfs, so this runs on EVERY boot (ordered
# before avahi-daemon) to repopulate the file; the hostnamectl call is a no-op
# once the static hostname already matches.
#
# mDNS `.local` publication is performed by avahi-daemon, which follows the
# system hostname set here. Any SERVICE advertisement is an application
# concern, deliberately NOT handled in this OS image.

set -euo pipefail

readonly PREFIX="ni-coreos"
readonly NM_CONN_DIR="/etc/NetworkManager/system-connections"
readonly RUN_DIR="/run/neural-ice"
readonly MDNS_FILE="${RUN_DIR}/mdns-hostname"
readonly AVAHI_CONF="/etc/avahi/avahi-daemon.conf"

log() { echo "neural-ice-hostname-init: $*"; }

# Pin avahi to the management NIC so mDNS advertises ONLY that port's routable
# LAN address. Without this, avahi publishes every interface — the podman
# bridges (podman1 -> 10.89.0.1), the per-container veth link-locals, and
# loopback — so `<hostname>.local` resolves to a SET of addresses and a client
# routinely picks an unreachable one (the .72 bring-up hit exactly this: the mac
# could not reach the appliance until avahi was pinned). We run before
# avahi-daemon, so setting the config here needs no restart. Idempotent.
configure_avahi_interface() {
    local iface="$1"
    [ -f "$AVAHI_CONF" ] || { log "WARN: $AVAHI_CONF missing, skipping mDNS interface pin"; return 0; }
    sed -i -E '/^\[server\]/,/^\[/ { /^allow-interfaces=/d }' "$AVAHI_CONF"
    sed -i -E "/^\[server\]/a allow-interfaces=${iface}" "$AVAHI_CONF"
    log "pinned avahi mDNS to management interface: $iface"
}

# Deterministically resolve the RJ45 management interface name.
#   1. The interface-name pinned in the management NM profile (mgmt-*.nmconnection)
#      — the canonical source of truth for "which physical port is management".
#   2. Fallback for a vanilla install without that profile: the on-board 1GbE
#      port matches enP<d>s<d> and, unlike the ConnectX QSFP ports (enp1s0f0np0,
#      ...), carries no PCIe function suffix (fN).
mgmt_interface() {
    local conn iface name cand
    for conn in "${NM_CONN_DIR}"/mgmt-*.nmconnection; do
        [ -e "$conn" ] || continue
        iface="$(sed -n 's/^interface-name=//p' "$conn" | head -1)"
        if [ -n "$iface" ]; then
            echo "$iface"
            return 0
        fi
    done
    for cand in /sys/class/net/enP*s*; do
        [ -e "$cand" ] || continue
        name="$(basename "$cand")"
        [[ "$name" =~ f[0-9] ]] && continue
        echo "$name"
        return 0
    done
    return 1
}

# Last two octets (4 lowercase hex chars) of the interface MAC.
mac_suffix() {
    local addr="/sys/class/net/$1/address" mac
    [ -r "$addr" ] || return 1
    mac="$(tr -d ':' < "$addr" | tr '[:upper:]' '[:lower:]')"
    [ "${#mac}" -ge 4 ] || return 1
    printf '%s' "${mac: -4}"
}

main() {
    local iface suffix desired current

    iface="$(mgmt_interface)" || { log "ERROR: no management interface found"; exit 1; }
    suffix="$(mac_suffix "$iface")" || { log "ERROR: cannot read MAC for $iface"; exit 1; }
    desired="${PREFIX}-${suffix}"
    log "management interface=$iface mac-suffix=$suffix hostname=$desired"

    # 1) Runtime contract for the console TUI + the avahi NIC pin FIRST. These
    #    must land on EVERY boot even if hostname persistence below hiccups —
    #    on the first enforcing boot of the .72 GB10 (2026-07-13) a failed
    #    hostnamectl aborted the script mid-way and the TUI showed a bare IP
    #    while the avahi pin was skipped. Publish, then persist.
    install -d -m 0755 "$RUN_DIR"
    printf '%s\n' "$desired" > "$MDNS_FILE"
    chmod 0644 "$MDNS_FILE"
    log "published short hostname to $MDNS_FILE"
    configure_avahi_interface "$iface"

    # 2) Kernel (runtime) hostname — what avahi/NM/the journal actually use.
    #    Direct /proc write: NO dbus, NO systemd-hostnamed. Both have failed
    #    us here (dbus not yet up on a degraded boot; hostnamed's sandbox
    #    refused the static write under enforcing). Deterministic instead.
    current="$(cat /proc/sys/kernel/hostname 2>/dev/null || true)"
    if [ "$current" != "$desired" ]; then
        if printf '%s' "$desired" > /proc/sys/kernel/hostname 2>/dev/null; then
            log "runtime hostname: '${current:-<unset>}' -> '$desired'"
        else
            log "WARN: cannot write /proc/sys/kernel/hostname (unit sandbox?)"
        fi
    fi

    # 3) Persist for the next boots (PID1 applies /etc/hostname at early boot).
    current="$(cat /etc/hostname 2>/dev/null || true)"
    if [ "$current" != "$desired" ]; then
        log "persisting static hostname: '${current:-<unset>}' -> '$desired'"
        printf '%s\n' "$desired" > /etc/hostname \
            || log "WARN: could not write /etc/hostname (will retry next boot)"
        # Map the FQDN in /etc/hosts so `hostname -f` and local lookups resolve.
        if grep -qE '^127\.0\.1\.1' /etc/hosts; then
            sed -i -E "s/^127\.0\.1\.1.*/127.0.1.1\t${desired}.local ${desired}/" /etc/hosts
        else
            printf '127.0.1.1\t%s.local %s\n' "$desired" "$desired" >> /etc/hosts
        fi
    fi
}

main "$@"
