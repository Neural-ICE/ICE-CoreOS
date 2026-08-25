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
# Racines paramétrables pour que la CI puisse EXÉCUTER ce script sur un faux
# système de fichiers. Les valeurs par défaut sont celles de production : rien
# ne change sur l'appliance, et aucun branchement de test ne vit dans le corps
# des fonctions — seules les racines, qui sont des entrées, sont substituables.
readonly NM_CONN_DIR="${NEURAL_ICE_NM_CONN_DIR:-/etc/NetworkManager/system-connections}"
readonly SYS_NET="${NEURAL_ICE_SYS_NET:-/sys/class/net}"
readonly RUN_DIR="${NEURAL_ICE_RUN_DIR:-/run/neural-ice}"
readonly MDNS_FILE="${RUN_DIR}/mdns-hostname"
readonly AVAHI_CONF="${NEURAL_ICE_AVAHI_CONF:-/etc/avahi/avahi-daemon.conf}"
readonly ETC_HOSTNAME="${NEURAL_ICE_ETC_HOSTNAME:-/etc/hostname}"
readonly ETC_HOSTS="${NEURAL_ICE_ETC_HOSTS:-/etc/hosts}"
readonly PROC_HOSTNAME="${NEURAL_ICE_PROC_HOSTNAME:-/proc/sys/kernel/hostname}"
readonly LL_NET="169.254"

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

# IPv4 link-local address DERIVED from the same two MAC octets as the hostname:
# `ni-coreos-93b9` -> 169.254.147.185. Unique per appliance, and computable from
# the name alone — an operator who knows the name knows the fallback address
# without having to discover it.
# RFC 3927 §2.1 reserves 169.254.0.0/24 and 169.254.255.0/24, so the third octet
# is clamped into 1..254.
linklocal_address() {
    local suffix="$1" a b
    [ "${#suffix}" -eq 4 ] || return 1
    a=$((16#${suffix:0:2}))
    b=$((16#${suffix:2:2}))
    [ "$a" -eq 0 ] && a=1
    [ "$a" -eq 255 ] && a=254
    printf '%s.%d.%d' "$LL_NET" "$a" "$b"
}

# Render a SECOND, lower-priority profile on the management NIC so the appliance
# keeps an address when the link has no DHCP server — a direct cable to a laptop,
# or a truly air-gapped install. Without it the box is reachable by NO path at
# all (ICE-Fabric #447).
#
# Measured on ni-coreos-93b9 the 2026-08-25, and this is why it is a SEPARATE
# profile rather than a setting on the management one:
#   * `ipv4.link-local=fallback` on mgmt-*: the address appears at t=5 s and is
#     GONE at t=45 s — with `ipv6.method=auto` and no RA on the link both address
#     families fail and NetworkManager tears the connection down
#     (`ip-config -> failed (reason 'ip-config-unavailable')`).
#   * a separate profile with `ipv4.method=manual` + `ipv6.method=link-local`
#     stays `activated` (checked at t=5, 20, 45 and 70 s), and NM switches to it
#     on its own ~150 s after the DHCP attempts start failing.
# The management profile is left EXACTLY as shipped: it keeps priority 100 and
# always wins whenever a DHCP server answers.
configure_linklocal_fallback() {
    local iface="$1" suffix="$2" addr file tmp
    addr="$(linklocal_address "$suffix")" || { log "WARN: cannot derive link-local address from '$suffix'"; return 1; }
    file="${NM_CONN_DIR}/fallback-${iface}.nmconnection"
    # Written to a temporary name that does NOT end in .nmconnection (NetworkManager
    # ignores it) then moved into place, so NM never observes a half-written profile.
    tmp="$(mktemp "${file}.tmp.XXXXXX")" || return 1
    cat > "$tmp" <<EOF
[connection]
# Neural ICE — link-local fallback on the management NIC. RENDERED at boot by
# neural-ice-hostname-init.sh; do not edit, the next boot overwrites it.
# Only ever activates when the higher-priority DHCP profile cannot: see
# ICE-Fabric #447 for the measurements behind this shape.
id=fallback-${iface}
type=ethernet
interface-name=${iface}
autoconnect=true
autoconnect-priority=10

[ethernet]

[ipv4]
method=manual
address1=${addr}/16

[ipv6]
method=link-local
EOF
    chmod 0600 "$tmp"
    if [ -e "$file" ] && cmp -s "$tmp" "$file"; then
        rm -f "$tmp"
        log "link-local fallback already current: $file ($addr/16)"
        return 0
    fi
    mv -f "$tmp" "$file"
    log "rendered link-local fallback: $file ($addr/16, priority 10)"
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
    for cand in "${SYS_NET}"/enP*s*; do
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
    local addr="${SYS_NET}/$1/address" mac
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

    # Joignabilité sans DHCP. Volontairement non fatal : sur le premier démarrage
    # enforçant de la .72 (2026-07-13) une étape en échec avait interrompu le
    # script et fait sauter les suivantes. Le nom d'hôte prime sur le secours.
    configure_linklocal_fallback "$iface" "$suffix" \
        || log "WARN: link-local fallback profile not rendered (continuing)"

    # 2) Kernel (runtime) hostname — what avahi/NM/the journal actually use.
    #    Direct /proc write: NO dbus, NO systemd-hostnamed. Both have failed
    #    us here (dbus not yet up on a degraded boot; hostnamed's sandbox
    #    refused the static write under enforcing). Deterministic instead.
    current="$(cat "$PROC_HOSTNAME" 2>/dev/null || true)"
    if [ "$current" != "$desired" ]; then
        if printf '%s' "$desired" > "$PROC_HOSTNAME" 2>/dev/null; then
            log "runtime hostname: '${current:-<unset>}' -> '$desired'"
        else
            log "WARN: cannot write $PROC_HOSTNAME (unit sandbox?)"
        fi
    fi

    # 3) Persist for the next boots (PID1 applies /etc/hostname at early boot).
    current="$(cat "$ETC_HOSTNAME" 2>/dev/null || true)"
    if [ "$current" != "$desired" ]; then
        log "persisting static hostname: '${current:-<unset>}' -> '$desired'"
        printf '%s\n' "$desired" > "$ETC_HOSTNAME" \
            || log "WARN: could not write $ETC_HOSTNAME (will retry next boot)"
        # Map the FQDN in /etc/hosts so `hostname -f` and local lookups resolve.
        if grep -qE '^127\.0\.1\.1' "$ETC_HOSTS" 2>/dev/null; then
            sed -i -E "s/^127\.0\.1\.1.*/127.0.1.1\t${desired}.local ${desired}/" "$ETC_HOSTS"
        else
            printf '127.0.1.1\t%s.local %s\n' "$desired" "$desired" >> "$ETC_HOSTS"
        fi
    fi
}

# Exécuté seulement en tant que programme : `source` ce fichier expose les
# fonctions à la CI sans toucher au nom d'hôte de la machine qui teste.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    main "$@"
fi
