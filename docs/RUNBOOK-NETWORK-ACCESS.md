# Runbook — reaching an appliance, with or without DHCP

An appliance is addressed **by name**, never by IP. This is not a preference:
the edge runs Caddy with `strict_sni_host`, and a bare IP carries no SNI, so an
IP request is answered with **421 Misdirected Request** even though the
certificate lists the address. The thin client only ever uses the name.

    https://ni-coreos-<mac4>.local/

`<mac4>` is the last two octets of the management NIC's MAC, in lowercase hex —
the same four characters the hostname is built from.

## Two profiles, one physical port

The management port is the on-board copper NIC (`Supported ports: [ TP MII ]`).
The ConnectX-7 ports are QSFP and are not usable with an ordinary Ethernet cable.
NetworkManager carries two profiles on that one port:

| profile | priority | IPv4 | when it activates |
|---|---|---|---|
| `mgmt-<iface>` | 100 | `auto` (DHCP) | whenever a DHCP server answers |
| `fallback-<iface>` | 10 | `manual`, `169.254.x.y/16` | only when the DHCP profile cannot |

The fallback profile is **rendered at every boot** by
`neural-ice-hostname-init.sh`, before NetworkManager starts. The management
profile is never modified.

### Why a separate profile and not a setting

Measured on `ni-coreos-93b9`, 2026-08-25, on an isolated veth with no DHCP server:

* `ipv4.link-local=fallback` on the management profile **does not hold**. The
  address appears at t=5 s and is gone at t=45 s. NetworkManager says why:
  `ip-config -> failed (reason 'ip-config-unavailable')`. With `ipv6.method=auto`
  and no router advertisement on the link, both address families fail and the
  connection is torn down, taking the link-local address with it.
* A separate profile with `ipv4.method=manual` and `ipv6.method=link-local`
  stays `activated` — checked at t=5, 20, 45 and 70 s.
* With two profiles at priorities 100 and 10 and no DHCP, NetworkManager gives
  up on the higher one and activates the fallback **on its own at t≈150 s**.

## Working out the fallback address without reaching the appliance

The address is derived from the same two MAC octets as the hostname, so the name
alone is enough:

    ni-coreos-93b9   ->  0x93 = 147, 0xb9 = 185  ->  169.254.147.185

RFC 3927 §2.1 reserves `169.254.0.0/24` and `169.254.255.0/24`, so a third octet
of 0 becomes 1 and 255 becomes 254.

That folding cannot be avoided. There are 65536 possible suffixes and
254 × 256 = 65024 usable addresses, so by the pigeonhole principle **no** mapping
is injective; alternatives such as a modular reduction fold exactly as many
suffixes while destroying the mental rule above. So the folding is stated rather
than claimed away:

* `00xx` shares its address with `01xx`;
* `ffxx` shares its address with `fexx`;
* every other suffix — 65024 of 65536, **99.2 %** — is unique.

It matters only if two appliances whose management MACs differ in exactly that
way sit on the same DHCP-less segment. `ci/test-linklocal-fallback.sh` pins both
collision pairs so the behaviour cannot drift into an accident.

## Direct cable to a laptop

1. Plug an ordinary Ethernet cable into the copper port. No crossover cable is
   needed — every NIC involved is auto-MDI-X.
2. The laptop self-assigns a `169.254.x.y/16` address on its own; macOS, Windows
   and NetworkManager all do this without configuration.
3. Wait **~150 s** for the appliance to give up on DHCP and switch profiles.
4. Because the name still has to resolve — mDNS may not be reachable in this
   state — pin it once on the laptop, **before travelling**:

        sudo sh -c 'echo "169.254.147.185  ni-coreos-93b9.local ni-coreos-93b9" >> /etc/hosts'

5. Check the edge answers:

        curl -sk -o /dev/null -w '%{http_code}\n' https://ni-coreos-93b9.local/api/v1/health   # 200

`200` means the name resolved and the edge routed. The certificate is valid for
the **name**, not for whatever address the link happens to give out, so it keeps
working on the fallback address — verified: `200` by name forced onto a
`169.254` address, `421` on the bare address.

## Coming back to DHCP

NetworkManager does **not** preempt an active connection: `autoconnect` only
picks a profile when the device is free, and `autoconnect-priority` merely orders
the candidates at that moment. An appliance that came up on a DHCP-less link
therefore **keeps** its link-local address even once a DHCP server appears —
until a carrier bounce, a reboot, or an explicit reconnection.

`neural-ice-dhcp-retry.timer` is that explicit reconnection. Every 15 minutes it
checks the management NIC and, **only** if the fallback is the active profile,
asks NetworkManager to bring the DHCP profile up.

The attempt is not free: NM drops the fallback, waits out `ipv4.dhcp-timeout`
(45 s by default) and, on failure, re-activates the fallback — roughly a minute
answering on neither address. That is the trade: a short periodic outage on a
machine already off its normal address, in exchange for an automatic return to
the LAN. When the fallback is not active the unit exits immediately and costs
nothing.

To force it rather than wait:

    sudo systemctl start neural-ice-dhcp-retry.service
    journalctl -u neural-ice-dhcp-retry.service -n 5

## What is deliberately not solved here

`avahi-resolve` publishes only the **routable** address when a routable and a
link-local address coexist. Whether it publishes the link-local one when it is
the only address has not been established, which is exactly why the fallback
address is fixed and derivable rather than randomly chosen: the `/etc/hosts`
line above removes the dependency on mDNS entirely.

Covered by `ci/test-linklocal-fallback.sh`, which executes the rendering script
against a fake filesystem and asserts the produced profile.
