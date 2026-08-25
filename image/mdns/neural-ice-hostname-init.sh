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
# Filesystem roots, overridable so CI can EXECUTE this script against a fake
# tree. The defaults are the production paths: nothing changes on an appliance,
# and no test branch lives inside any function — only the roots, which are
# inputs, are substitutable.
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
# `ni-coreos-93b9` -> 0x93 = 147, 0xb9 = 185 -> 169.254.147.185. The rule is
# deliberately one an operator can do in their head, because the whole point is
# to know the address WITHOUT reaching the machine.
#
# RFC 3927 §2.1 reserves 169.254.0.0/24 and 169.254.255.0/24, so a third octet of
# 0 becomes 1 and 255 becomes 254.
#
# That folding is NOT avoidable: 65536 possible suffixes, 254*256 = 65024 usable
# addresses — by the pigeonhole principle no mapping can be injective, and every
# alternative (modular reduction, octet swapping) folds the same 512 suffixes
# while destroying the mental rule above. So the folding is stated instead of
# claimed away: `00xx` shares its address with `01xx`, and `ffxx` with `fexx`.
# 512 suffixes out of 65536 — 0.8% — and only ever a problem if two appliances
# whose management MACs differ in exactly that way sit on the same DHCP-less
# segment. Pinned by ci/test-linklocal-fallback.sh so it cannot drift silently.
linklocal_address() {
    local suffix="$1" a b
    [ "${#suffix}" -eq 4 ] || return 1
    # Refuse a malformed suffix EXPLICITLY. `set -u` would also block the printf
    # below on the unset locals, so no test can tell the two apart — but relying
    # on that is relying on a side effect: a later edit giving `a` a default
    # would remove the refusal without touching anything that looks like a check.
    a=$((16#${suffix:0:2})) 2>/dev/null || return 1
    b=$((16#${suffix:2:2})) 2>/dev/null || return 1
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
    local iface="$1" suffix="$2" addr file tmp mode
    addr="$(linklocal_address "$suffix")" || { log "WARN: cannot derive link-local address from '$suffix'"; return 1; }
    file="${NM_CONN_DIR}/fallback-${iface}.nmconnection"
    # Written to a temporary name that does NOT end in .nmconnection (NetworkManager
    # ignores it) then moved into place, so NM never observes a half-written profile.
    tmp="$(mktemp "${file}.tmp.XXXXXX")" || { log "WARN: cannot create a temporary file in ${NM_CONN_DIR}"; return 1; }
    # Every step below checks explicitly. This function is called as the left
    # side of `||`, which DISABLES errexit inside it: without these checks a
    # `cat` that fails on a full disk would fall through to chmod and mv, install
    # a truncated profile, log it as rendered and return success.
    if ! cat > "$tmp" <<EOF
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
    then
        rm -f "$tmp"
        log "WARN: could not write the link-local profile body (disk full?)"
        return 1
    fi
    if ! chmod 0600 "$tmp"; then
        rm -f "$tmp"
        log "WARN: could not restrict the link-local profile to 0600"
        return 1
    fi
    if [ -e "$file" ] && cmp -s "$tmp" "$file"; then
        rm -f "$tmp"
        # Same bytes is not the same file. NetworkManager's keyfile plugin
        # IGNORES a profile that non-root can read, so a mode drifted to 0644
        # would make this branch log "already current" on every boot while the
        # fallback does not exist at all. Repair metadata before declaring it.
        mode="$(stat -c %a "$file" 2>/dev/null || echo unknown)"
        if [ "$mode" != "600" ]; then
            if chmod 0600 "$file"; then
                log "repaired link-local profile mode: $file ($mode -> 600)"
                reload_networkmanager
            else
                log "WARN: could not repair the mode of $file (currently $mode)"
                return 1
            fi
        fi
        if command -v restorecon >/dev/null 2>&1; then
            restorecon -F "$file" >/dev/null 2>&1 || true
        fi
        log "link-local fallback already current: $file ($addr/16)"
        return 0
    fi
    if ! mv -f "$tmp" "$file"; then
        rm -f "$tmp"
        log "WARN: could not install the link-local profile at $file"
        return 1
    fi
    # The file inherits the directory's SELinux type, which is what the policy
    # enforces, but normalise the whole label anyway so a future policy keyed on
    # the user part cannot start rejecting a profile we rendered ourselves.
    if command -v restorecon >/dev/null 2>&1; then
        restorecon -F "$file" >/dev/null 2>&1 || true
    fi
    log "rendered link-local fallback: $file ($addr/16, priority 10)"
    reload_networkmanager
}

# NetworkManager reads keyfiles when it starts. This script normally runs
# Before=NetworkManager.service, so nothing more is needed on a boot. It also
# runs on a LIVE system though — a re-render after an update — and there a
# freshly written keyfile is INVISIBLE to NM: measured on ni-coreos-93b9 the
# 2026-08-25, `nmcli con show fallback-<iface>` answered "no such connection
# profile" until a reload. The reload is not disruptive: across it the active
# DHCP connection kept its state and its address.
reload_networkmanager() {
    command -v nmcli >/dev/null 2>&1 || return 0
    systemctl is-active --quiet NetworkManager 2>/dev/null || return 0
    if nmcli connection reload >/dev/null 2>&1; then
        log "asked NetworkManager to re-read its profiles"
    else
        log "WARN: nmcli connection reload failed (profile lands at next boot)"
    fi
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

    # Reachability on a DHCP-less link. Deliberately non-fatal: on the first
    # enforcing boot of the .72 (2026-07-13) a failing step aborted this script
    # and dropped everything after it. The hostname outranks the fallback.
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

# Only when run as a program: sourcing this file exposes the functions to CI
# without touching the hostname of the machine running the tests.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    main "$@"
fi
