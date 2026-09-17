#!/usr/bin/env bash
#
# Neural ICE CoreOS — which wired port is the management port. ONE rule, ONE file.
#
# The rule, in words: the management port is the first (C-locale name order)
# wired Ethernet port that is BUILT IN — a physical device on the PCI/platform
# tree, not on a USB bus — and is not a ConnectX fabric port. It is the same
# rule the shipped NetworkManager profile expresses in its own vocabulary:
#
#   this file (sysfs)                          mgmt-onboard.nmconnection ([match])
#   name en* or eth*                           interface-name=en*;eth*
#   /sys/class/net/<if>/device exists          (NM only matches real devices)
#   device path has no /usb<N>/ element        path=!*-usb-*   (udev ID_PATH)
#   device/driver is not mlx5_core             driver=!mlx5_core
#
# Why by device and not by name (ICE-CoreOS issue 215): the profile used to pin
# `interface-name=enP7s7`, the GX10's port. A QEMU virt guest exposes `enp0s1`,
# so on the KVM bench neural-ice-hostname-init failed (NI-E05), no profile
# activated, and the first boot never reached the seed nor sshd. Both ports
# satisfy the rule above; a USB dongle never does — the hostname is a property
# of the box, not of whatever is plugged into it — and the ConnectX ports keep
# their own pinned profiles (cx7-port0/1).
#
# Why C-locale name order as the tie-break, and not carrier: the hostname is
# derived from this port's MAC and must not change with cabling. On the shipped
# hardware (GX10: enP7s7 + two mlx5 ports; bench VM: enp0s1) the rule leaves
# exactly ONE candidate, which the tests pin; NetworkManager decides on its own
# which matching device gets the profile, so two built-in candidates would be a
# hardware target this rule does not yet cover — it must be declared here, not
# guessed at boot.
#
# Consumers: neural-ice-hostname-init.sh (sources this file: hostname, avahi pin,
# link-local fallback), the installer's resolve-only avahi (`--pin-avahi`, as
# ExecStartPre= from the runtime generator), and through hostname-init's
# /run/neural-ice/mgmt-interface contract the tty1 status screen.
#
# Usage as a program:
#   neural-ice-mgmt-port                 print the management port name, or fail
#   neural-ice-mgmt-port --pin-avahi F   set allow-interfaces=<port> under [server] in F
#
# NEURAL_ICE_SYS_NET overrides /sys/class/net so CI can EXECUTE this against a
# fake tree; it is the only substitutable input.

mgmt_port_sys_net() { printf '%s' "${NEURAL_ICE_SYS_NET:-/sys/class/net}"; }

# Every candidate, one per line, in C-locale name order.
mgmt_port_candidates() {
    local sys dev name driver
    sys="$(mgmt_port_sys_net)"
    for dev in "$sys"/en* "$sys"/eth*; do
        [ -e "$dev" ] || continue                       # unmatched glob
        name="${dev##*/}"
        [ -e "$dev/device" ] || continue                # virtual: veth, bridge, lo
        case "$(readlink -f "$dev/device")" in
            */usb[0-9]*/*) continue ;;                  # on a USB bus: never
        esac
        driver="$(readlink -f "$dev/device/driver" 2>/dev/null || true)"
        [ "${driver##*/}" = mlx5_core ] && continue     # ConnectX fabric port
        printf '%s\n' "$name"
    done | LC_ALL=C sort
}

# The management port name on stdout, or 1 when the rule selects nothing.
mgmt_interface() {
    local first
    # sed reads to the end: no early close, so no SIGPIPE for a pipefail caller.
    first="$(mgmt_port_candidates | sed -n '1p')"
    [ -n "$first" ] || return 1
    printf '%s' "$first"
}

# Pin avahi to the management port so mDNS uses ONLY that port: on the appliance
# it advertises only that port's routable LAN address (without this avahi
# publishes every interface — podman bridges, per-container veth link-locals,
# loopback — and `<hostname>.local` resolves to a set a client cannot use; the
# .72 bring-up hit exactly this), on the installer medium it resolves the sealed
# mirror name on the LAN port only. Idempotent: the previous pin is replaced.
pin_avahi_interface() { # $1=avahi-daemon.conf $2=port
    local conf="$1" iface="$2"
    [ -f "$conf" ] || return 1
    sed -i -E '/^\[server\]/,/^\[/ { /^allow-interfaces=/d }' "$conf" || return 1
    sed -i -E "/^\[server\]/a allow-interfaces=${iface}" "$conf" || return 1
    grep -qx "allow-interfaces=${iface}" "$conf"
}

mgmt_port_main() {
    local iface
    set -euo pipefail
    case "${1:-}" in
        "")
            iface="$(mgmt_interface)" || { echo "neural-ice-mgmt-port: no built-in wired port matches the management rule" >&2; exit 1; }
            printf '%s\n' "$iface"
            ;;
        --pin-avahi)
            [ -n "${2:-}" ] || { echo "neural-ice-mgmt-port: --pin-avahi needs the avahi-daemon.conf path" >&2; exit 2; }
            iface="$(mgmt_interface)" || { echo "neural-ice-mgmt-port: no built-in wired port matches the management rule; $2 not pinned" >&2; exit 1; }
            pin_avahi_interface "$2" "$iface" || { echo "neural-ice-mgmt-port: could not pin allow-interfaces=${iface} in $2" >&2; exit 1; }
            echo "neural-ice-mgmt-port: pinned avahi to management interface: ${iface} ($2)"
            ;;
        *)
            echo "usage: neural-ice-mgmt-port [--pin-avahi <avahi-daemon.conf>]" >&2
            exit 2
            ;;
    esac
}

# Only when run as a program: sourcing exposes the functions and changes no
# shell option of the caller.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    mgmt_port_main "$@"
fi
