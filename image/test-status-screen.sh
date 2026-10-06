#!/usr/bin/env bash
# Offline proof of the tty1 boot status screen (image/firstboot/neural-ice-status-screen.*).
#
# Three families of assertions:
#   1. the unit cannot cycle, is not ceremony-gated, is sandboxed, owns tty1 only;
#   2. the script reads NOTHING outside its declared allow-list -- no recovery
#      key, no LUKS/TPM material, no licence, no token, no fingerprint path;
#   3. the script, run through its unprivileged test seam against crafted
#      fixtures, shows the phases, the counters, the receive rate, the failure
#      block with the stable NI-Exx code, READY, and the serial mirror lines;
#   4. the same script on a host whose image ships a product declaration
#      (/usr/lib/neural-ice/status-screen.d/*.conf, the exact file the v2 host
#      image ships): Images from the manifest the declaration names, the declared
#      image units, READY only once those are done and the declared core units
#      are active; and every malformed declaration is refused and reported
#      (NI-E06), never half-applied.
set -euo pipefail

if (( EUID == 0 )); then
  command -v runuser >/dev/null 2>&1 \
    || { echo "FAIL: runuser is required to exercise the unprivileged status-screen test seam" >&2; exit 1; }
  exec runuser -u nobody -- "$0" "$@"
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CF="$ROOT/image/Containerfile.bootc"
UNIT="$ROOT/image/firstboot/neural-ice-status-screen.service"
SCRIPT="$ROOT/image/firstboot/neural-ice-status-screen.sh"
CODES="$ROOT/image/firstboot/status-error-codes.md"
CEREMONY_TEST="$ROOT/image/test-tpm-ceremony-systemd.sh"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/ni-status-screen.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

[[ -f $UNIT && -f $SCRIPT && -f $CODES ]] || fail "status screen unit, script or error-code table is missing"

# --- 1. unit contract --------------------------------------------------------
grep -qx 'DefaultDependencies=no' "$UNIT" || fail "status screen keeps default dependencies (would start after basic.target, i.e. after the ceremony gate)"
! grep -E '^(After|Before|Requires|Wants|Requisite|BindsTo)=.*systemd-tmpfiles-setup\.service' "$UNIT" \
  || fail "status screen orders against tmpfiles-setup (cycles with sysext)"
! grep -E '^(After|Before|Requires|Wants|Requisite|BindsTo)=.*(sysinit|sockets|basic)\.target' "$UNIT" \
  || fail "status screen orders against sysinit/sockets/basic (the ceremony cycle set)"
! grep -E '^(After|Before|Requires|Wants|Requisite|BindsTo|PartOf|Conflicts)=.*neural-ice-firstboot-tpm-ceremony\.service' "$UNIT" \
  || fail "status screen has an edge to the ceremony; it must run WHILE the ceremony runs"
! grep -E '^Conflicts=.*(getty|neural-ice-tui|neural-ice-firstboot-tpm-ceremony)' "$UNIT" \
  || fail "Conflicts= against a tty1 owner or the ceremony: two conflicting jobs in one boot transaction make systemd drop one of them; the script polls the owners instead"
{ grep -qx 'Conflicts=shutdown.target' "$UNIT" && grep -qx 'Before=shutdown.target' "$UNIT"; } \
  || fail "DefaultDependencies=no drops the shutdown edge; without Conflicts=+Before=shutdown.target TimeoutStopSec never applies"
grep -qx 'IgnoreOnIsolate=yes' "$UNIT" || fail "OnFailure=emergency.target isolate would tear the failure block down"
grep -qx 'PrivateTmp=disconnected' "$UNIT" || fail "PrivateTmp must be disconnected: yes re-adds After=tmpfiles-setup"
grep -qx 'Type=simple' "$UNIT" || fail "a oneshot here would hold getty/TUI until the screen exits"
grep -qx 'Restart=no' "$UNIT" || fail "a restarting observer would loop on top of the TUI"
grep -qx 'TTYPath=/dev/tty1' "$UNIT" || fail "status screen does not target tty1"
grep -qx 'StandardOutput=tty' "$UNIT" || fail "status screen stdout is not the tty"
grep -qx 'StandardInput=null' "$UNIT" || fail "status screen must not read the console"
grep -qx 'ExecStart=/usr/local/bin/neural-ice-status-screen.sh' "$UNIT" || fail "unexpected ExecStart"
! grep -E '^Exec(Start|StartPre|StartPost|Stop|StopPost)=.*(agetty|login|sulogin|/bin/sh|/bin/bash)' "$UNIT" \
  || fail "status screen must never spawn a shell or a login"
for hard in 'ProtectSystem=strict' 'NoNewPrivileges=yes' 'CapabilityBoundingSet=' 'ProtectHome=yes' \
  'RestrictAddressFamilies=AF_UNIX AF_NETLINK' 'IPAddressDeny=any' 'MemoryDenyWriteExecute=yes' \
  'SystemCallFilter=@system-service' 'SystemCallArchitectures=native' 'UMask=0077'; do
  grep -qx -- "$hard" "$UNIT" || fail "status screen sandbox lacks $hard"
done
! grep -E '^(ReadWritePaths|StateDirectory|RuntimeDirectory|CacheDirectory|LogsDirectory)=' "$UNIT" \
  || fail "a read-only observer needs no writable path"
grep -qx 'DevicePolicy=closed' "$UNIT" || fail "device cgroup is not closed"
for dev in /dev/tty1 /dev/ttyS0 /dev/ttyAMA0; do
  grep -qx "DeviceAllow=$dev rw" "$UNIT" || fail "DeviceAllow= lacks $dev"
done
[[ "$(grep -c '^DeviceAllow=' "$UNIT")" -eq 3 ]] || fail "DeviceAllow= opens more than tty1 and the two UARTs"
! grep -E '^PrivateDevices=yes' "$UNIT" || fail "PrivateDevices=yes would hide tty1 and the UARTs"
grep -qx 'WantedBy=multi-user.target' "$UNIT" || fail "status screen is not pulled in by multi-user"
grep -qx 'Environment=NI_STATUS_CEREMONY_TIMEOUT=[0-9]*' "$UNIT" || fail "ceremony timeout is not configurable from the unit"

# The full effective unit must load and verify under a real systemd when one is
# available (no unknown keys, no syntax error, no cycle it can see).
# `PrivateTmp=disconnected` exists since systemd 257; the appliance runs 257
# (CentOS Stream 10), a CI host may run 255 and would reject the directive as a
# parse error. The static assertion above holds the real unit to `disconnected`;
# an older host verifies a copy with that ONE line removed and says so.
if command -v systemd-analyze >/dev/null 2>&1; then
  VROOT="$TMP/verify-root"
  mkdir -p "$VROOT/usr/lib/systemd/system" "$VROOT/usr/local/bin"
  host_systemd="$(systemd-analyze --version 2>/dev/null | sed -nE '1s/^systemd ([0-9]+).*/\1/p')"
  if [[ -n $host_systemd && $host_systemd -ge 257 ]]; then
    cp -- "$UNIT" "$VROOT/usr/lib/systemd/system/"
    verified="the shipped unit, byte for byte"
  else
    grep -vx 'PrivateTmp=disconnected' "$UNIT" > "$VROOT/usr/lib/systemd/system/neural-ice-status-screen.service"
    verified="the shipped unit minus PrivateTmp=disconnected (host systemd ${host_systemd:-?} < 257 cannot parse it)"
  fi
  cp -- "$SCRIPT" "$VROOT/usr/local/bin/neural-ice-status-screen.sh"
  chmod 0755 "$VROOT/usr/local/bin/neural-ice-status-screen.sh"
  out="$(systemd-analyze --root="$VROOT" verify neural-ice-status-screen.service 2>&1)" \
    || fail "systemd-analyze verify rejects the status screen unit ($verified): $out"
  ! grep -Eiq 'cycle|Unknown key|Failed to parse' <<<"$out" || fail "systemd-analyze verify flagged the unit ($verified): $out"
  echo "systemd-analyze verify: $verified"
fi

# --- 1b. image wiring ----------------------------------------------------------
grep -Fq 'COPY image/firstboot/neural-ice-status-screen.sh      /usr/local/bin/neural-ice-status-screen.sh' "$CF" \
  || fail "the image does not install the status screen script"
grep -Fq 'COPY image/firstboot/neural-ice-status-screen.service /usr/lib/systemd/system/neural-ice-status-screen.service' "$CF" \
  || fail "the image does not install the status screen unit"
grep -Eq '^ +/usr/local/bin/neural-ice-status-screen\.sh \\$' "$CF" || fail "the image does not chmod the status screen script"
enable_block="$(sed -n '/systemctl enable nvidia-device-nodes.service/,/avahi-daemon.service;/p' "$CF")"
grep -Fq 'neural-ice-status-screen.service' <<<"$enable_block" || fail "the status screen is not enabled by the image"
! grep -Fq 'neural-ice-status-screen.service.d/50-neural-ice-tpm-ceremony.conf' <<<"$(grep '^COPY' "$CF")" \
  || fail "the ceremony hard-gate drop-in targets the status screen; it must run while the ceremony runs"
grep -Fq 'test ! -e /usr/lib/systemd/system/neural-ice-status-screen.service.d/50-neural-ice-tpm-ceremony.conf' "$CF" \
  || fail "the image build does not assert the status screen stays ungated"
# The ceremony suite audits the enabled set; it must know this unit is the one
# deliberate exception, by name, so a second ungated unit still fails review.
grep -Fq 'neural-ice-status-screen.service' "$CEREMONY_TEST" || fail "the ceremony suite does not name the status screen as the audited ungated exception"
# On a medium boot (installer / Live) tty1 belongs to the installer; the
# runtime generator must transiently mask the screen like the other appliance
# lifecycle units (image/test-installer-systemd-lifecycle.sh exercises the mask).
GENERATOR="$ROOT/image/installer/neural-ice-installer-runtime-generator.sh"
sed -n '/^readonly -a MASKED_UNITS=(/,/^)/p' "$GENERATOR" | grep -qx '  neural-ice-status-screen.service' \
  || fail "the installer runtime generator does not mask the status screen on media boots"

# --- 2. static secret-freedom ------------------------------------------------
bash -n "$SCRIPT" || fail "script does not parse"
if command -v shellcheck >/dev/null 2>&1; then
  shellcheck "$SCRIPT" || fail "shellcheck rejects the status screen script"
fi
# Comments may explain what is forbidden; code may not touch it.
CODE="$TMP/code.sh"
grep -Ev '^[[:space:]]*#' "$SCRIPT" > "$CODE"
forbidden=(
  'recovery' 'luks' 'licen[cs]e' 'token' 'fingerprint' 'crypttab' 'tpm2' '/dev/tpm'
  '/var/lib/neural-ice/ota' '/etc/neural-ice/keys' 'authorized_keys' '\.ssh' '/etc/shadow' '/etc/passwd'
  'PCR-POLICY' 'owner-ceremony' 'device-root-v1' 'srk' 'release-authorization' 'AUTHORITY'
  '/proc/[0-9]' '/proc/self/environ' 'journalctl' 'systemd-creds' 'ssh-keygen' 'bootc install'
)
for pattern in "${forbidden[@]}"; do
  ! grep -Eiq -- "$pattern" "$CODE" || fail "status screen code mentions a forbidden path/word: $pattern"
done
# Every absolute path the code names must sit under the declared allow-list.
# Nothing on it identifies the DEVICE beyond what the chassis label already
# prints (DMI model + serial): the short bootc image digest in the header is
# the appliance's software VERSION, not a device fingerprint, and is kept.
allowed=(
  /usr/lib/os-release /usr/lib/neural-ice/version /usr/lib/neural-ice/status-screen
  /usr/lib/neural-ice/release-image /usr/lib/bootc/bound-images.d /usr/share/containers/systemd
  /etc/containers/systemd /etc/neural-ice/ota.conf /run/neural-ice/mgmt-interface
  /var/lib/neural-ice/data/release/CHANNEL /var/lib/neural-ice/data/seed-store/current/overlay-images/images.json
  /var/lib/containers/storage/overlay-images/images.json /usr/lib/bootc/storage/overlay-images/images.json
  /sys/class/net /sys/class/dmi/id
  /proc/cmdline /proc/sys/kernel/hostname /sys/class/tty/console/active /dev /dev/null
  /usr/lib/neural-ice/status-screen.d
)
while IFS= read -r found; do
  ok=0
  for prefix in "${allowed[@]}"; do
    [[ $found == "$prefix" || $found == "$prefix"/* ]] && { ok=1; break; }
  done
  (( ok )) || fail "status screen code names a path outside its allow-list: $found"
done < <(grep -oE '(^|[^A-Za-z0-9_])/(usr|etc|var|sys|proc|dev|run|root|home|tmp|boot|opt|srv|sysroot|ostree|mnt|media)(/[A-Za-z0-9_.@-]+)*' "$CODE" \
           | sed -E 's/^[^\/]//' | sort -u)
# Open-core boundary (ADR-0032): the OS names no product unit, no product file
# layout and no product manifest key. All of it comes from a declaration.
for product in 'ni-v2' 'icecore' 'product-payload' 'neural-ice-applied' 'neural-ice-v2' 'release-manifest' \
  'component_id' 'release_id' 'ota-state-profile' 'owner-sealed' 'first-pull'; do
  ! grep -Fq -- "$product" "$CODE" || fail "status screen code names product knowledge ($product); it belongs in a declaration"
done
# A declaration is only honoured from an image-owned, plain, bounded file.
grep -Fq 'DECL_UID=0' "$CODE" || fail "declarations are not held to root ownership"
grep -Fq 'decl_owner_ok' "$CODE" || fail "declaration owner/mode check is missing"
# The management NIC is the one hostname-init selected and published (one rule,
# neural-ice-mgmt-port); a NetworkManager profile can carry credentials and this
# code must not read any profile at all.
! grep -q 'nmconnection\|NetworkManager/system-connections' "$CODE" \
  || fail "status screen reads a NetworkManager profile; the management port comes from /run/neural-ice/mgmt-interface"
grep -Fq '/run/neural-ice/mgmt-interface' "$CODE" || fail "status screen does not read hostname-init's management-port contract"
# The UART is the kernel's active console (then console=), never a guess, and
# only the two nodes DeviceAllow= opens qualify.
grep -Fq '/sys/class/tty/console/active' "$CODE" || fail "serial mirror does not read the kernel's active console list"
grep -Fq 'console=tty' "$CODE" || fail "serial mirror does not fall back to console= on the kernel command line"
grep -Fq '^tty(S|AMA)[0-9]+$' "$CODE" || fail "serial mirror may select a UART the unit's DeviceAllow= does not open"
# Receive counters come from /sys/class/net statistics and nothing else.
grep -Fq 'statistics/rx_bytes' "$CODE" || fail "receive rate is not derived from /sys/class/net statistics"
! grep -Eq '(^|[^A-Za-z])(ifconfig|ethtool|nmcli|ss|netstat|sar|iftop|vnstat|bmon)([^A-Za-z]|$)' "$CODE" \
  || fail "receive rate must not use an external network tool"
# The seam is closed to root and to release images (same rule as seed-import).
# shellcheck disable=SC2016 # literal source assertion
grep -Fq '[[ $EUID -ne 0 ]] || die "the test seam is forbidden to root"' "$SCRIPT" || fail "test seam is open to root"
grep -Fq '[[ ! -e /usr/lib/neural-ice/release-image ]] || die' "$SCRIPT" || fail "test seam is open in a release image"
# Every code the script can print is documented, and vice versa.
while IFS= read -r code; do
  grep -Fq "| $code |" "$CODES" || fail "$code is printed by the script but not documented in status-error-codes.md"
done < <(grep -oE 'NI-E[0-9]{2}' "$CODE" | sort -u)
while IFS= read -r code; do
  grep -Fq "$code" "$CODE" || fail "$code is documented but the script never prints it"
done < <(grep -oE '^\| (NI-E[0-9]{2}) ' "$CODES" | grep -oE 'NI-E[0-9]{2}')

# --- 3. behaviour through the unprivileged seam -------------------------------
FX="$TMP/fx"
TOOLS="$TMP/tools"
mkdir -p "$TOOLS"
cat > "$TOOLS/systemctl" <<'EOF'
#!/usr/bin/env bash
# `systemctl show -p A,B,... -- <unit>`: answer from the scene file
# "<unit> <LoadState> <ActiveState> <SubState> <ConditionTimestampMonotonic> <ConditionResult>"
unit=${*: -1}
# Optional ownership flip: the Nth query of NI_TEST_FLIP_UNIT (and every later
# one) answers `active`, modelling getty/the TUI taking tty1 between the loop's
# snapshot and the write.
if [[ -n ${NI_TEST_FLIP_UNIT:-} && $unit == "$NI_TEST_FLIP_UNIT" ]]; then
  n=0; [[ -f $NI_TEST_FLIP_COUNTER ]] && n=$(<"$NI_TEST_FLIP_COUNTER")
  n=$((n + 1)); printf '%s' "$n" > "$NI_TEST_FLIP_COUNTER"
  if (( n >= NI_TEST_FLIP_AFTER )); then
    printf 'LoadState=loaded\nActiveState=active\nSubState=running\nConditionTimestampMonotonic=0\nConditionResult=yes\n'; exit 0
  fi
fi
state=$(awk -v u="$unit" '$1 == u { $1 = ""; print; exit }' "$NI_TEST_SCENE")
if [[ -z $state ]]; then
  printf 'LoadState=not-found\nActiveState=inactive\nSubState=dead\nConditionTimestampMonotonic=0\nConditionResult=no\n'; exit 0
fi
read -r load active sub condts condres <<<"$state"
printf 'LoadState=%s\nActiveState=%s\nSubState=%s\nConditionTimestampMonotonic=%s\nConditionResult=%s\n' "$load" "$active" "$sub" "$condts" "$condres"
EOF
cat > "$TOOLS/ip" <<'EOF'
#!/usr/bin/env bash
[[ -f $NI_TEST_IPV4 ]] || exit 1
printf '2: %s    inet %s brd 192.168.1.255 scope global dynamic %s\n' "${*: -1}" "$(<"$NI_TEST_IPV4")" "${*: -1}"
EOF
chmod 0755 "$TOOLS"/*

make_fixture() { # fresh fixture root with a first-boot scene
  rm -rf "$FX"
  mkdir -p "$FX/root/usr/lib/neural-ice/status-screen" "$FX/root/usr/lib/bootc/bound-images.d" \
    "$FX/root/usr/share/containers/systemd/neural-ice-bound-images" "$FX/root/etc/containers/systemd" \
    "$FX/root/run/neural-ice" "$FX/root/etc/neural-ice" \
    "$FX/root/var/lib/neural-ice/data/release" "$FX/root/var/lib/containers/storage/overlay-images" \
    "$FX/root/sys/class/net/enP7s7/statistics" "$FX/root/sys/class/net/enP7s7/device" \
    "$FX/root/sys/class/net/lo/statistics" "$FX/root/sys/class/net/veth0/statistics" \
    "$FX/root/sys/class/dmi/id" "$FX/root/proc/sys/kernel" "$FX/root/sys/class/tty/console" "$FX/root/dev"
  # The kernel console list names the UART the mirror must use (GB10 image: ttyS0).
  printf 'tty0 ttyS0\n' > "$FX/root/sys/class/tty/console/active"
  : > "$FX/root/dev/ttyS0"; : > "$FX/root/dev/ttyAMA0"; : > "$FX/root/dev/ttyTHS0"
  printf 'NAME="Neural ICE"\nPRETTY_NAME="Neural ICE CoreOS"\n' > "$FX/root/usr/lib/os-release"
  printf '0.51.11\n' > "$FX/root/usr/lib/neural-ice/version"
  printf '# product units appended by the branded derivation\nneural-ice-agentic-core.service\nnot a unit\n../../etc/shadow\n' \
    > "$FX/root/usr/lib/neural-ice/status-screen/core-services"
  printf 'BOOT_IMAGE=(hd0)/vmlinuz ostree=/ostree/boot.1/default/%s/0 quiet\n' "$(printf 'ab%062d' 7)" > "$FX/root/proc/cmdline"
  printf 'ni-coreos-ab12\n' > "$FX/root/proc/sys/kernel/hostname"
  printf 'NVIDIA\n' > "$FX/root/sys/class/dmi/id/sys_vendor"
  printf 'DGX Spark\n' > "$FX/root/sys/class/dmi/id/product_name"
  printf 'SN-1234-5678\n' > "$FX/root/sys/class/dmi/id/product_serial"
  printf 'beta-debug\n' > "$FX/root/var/lib/neural-ice/data/release/CHANNEL"
  printf 'enP7s7\n' > "$FX/root/run/neural-ice/mgmt-interface"   # published by hostname-init
  printf 'up\n' > "$FX/root/sys/class/net/enP7s7/operstate"
  printf '1000000\n' > "$FX/root/sys/class/net/enP7s7/statistics/rx_bytes"
  printf 'unknown\n' > "$FX/root/sys/class/net/lo/operstate"
  printf '500000000\n' > "$FX/root/sys/class/net/lo/statistics/rx_bytes"
  printf 'up\n' > "$FX/root/sys/class/net/veth0/operstate"          # virtual: no ./device
  printf '900000000\n' > "$FX/root/sys/class/net/veth0/statistics/rx_bytes"
  printf '[Image]\nImage=ghcr.io/neural-ice/a@sha256:%064d\n' 1 > "$FX/root/usr/share/containers/systemd/neural-ice-bound-images/a.image"
  ln -s /usr/share/containers/systemd/neural-ice-bound-images/a.image "$FX/root/usr/lib/bootc/bound-images.d/a.image"
  printf '[Container]\nImage=ghcr.io/neural-ice/b@sha256:%064d\n' 2 > "$FX/root/etc/containers/systemd/b.container"
  printf '[Container]\nImage=a.image\n' > "$FX/root/etc/containers/systemd/uses-a.container"   # indirection, not a ref
  printf '[{"id":"x","digest":"sha256:%064d","names":["ghcr.io/neural-ice/a"]}]\n' 1 \
    > "$FX/root/var/lib/containers/storage/overlay-images/images.json"
  printf '192.168.1.20/24\n' > "$FX/ipv4"
  cat > "$FX/scene" <<'EOF'
systemd-cryptsetup@data.service loaded active exited 0 yes
var-lib-neural\x2dice-data.mount loaded active mounted 0 yes
neural-ice-firstboot-tpm-ceremony.service loaded activating start 0 yes
NetworkManager.service loaded inactive dead 0 no
neural-ice-hostname-init.service loaded active exited 0 yes
neural-ice-device-root.service loaded inactive dead 4242 no
neural-ice-payload-apply.service loaded inactive dead 0 no
avahi-daemon.service loaded inactive dead 0 no
neural-ice-agentic-core.service loaded inactive dead 0 no
EOF
}
set_state() { # <unit> <load> <active> <sub> [condts] [condres]
  local unit=$1
  sed -i "\|^${unit//\\/\\\\} |d" "$FX/scene"
  printf '%s %s %s %s %s %s\n' "$unit" "$2" "$3" "$4" "${5:-0}" "${6:-no}" >> "$FX/scene"
}
run_screen() { # [iterations] [interval] [extra env...] -> stdout stripped of ANSI; serial lines land in $FX/root/dev/<uart>
  local iterations=${1:-1} interval=${2:-0}; shift 2 || true
  : > "$FX/root/dev/ttyS0"; : > "$FX/root/dev/ttyAMA0"; : > "$FX/root/dev/ttyTHS0"; rm -f "$FX/flip-counter"
  env NI_STATUS_SCREEN_TESTING=1 NI_STATUS_TEST_ROOT="$FX/root" NI_STATUS_TEST_SYSTEMCTL="$TOOLS/systemctl" \
    NI_STATUS_TEST_IP="$TOOLS/ip" NI_STATUS_TEST_ITERATIONS="$iterations" NI_STATUS_TEST_INTERVAL="$interval" \
    NI_TEST_SCENE="$FX/scene" NI_TEST_IPV4="$FX/ipv4" NI_TEST_FLIP_COUNTER="$FX/flip-counter" "$@" \
    bash "$SCRIPT" | sed 's/\x1b\[[0-9;?]*[A-Za-z]//g'
}
serial_out() { cat "$FX/root/dev/ttyS0"; }
expect() { grep -Fq -- "$2" <<<"$1" || fail "$3: expected '$2' in: $1"; }
reject() { ! grep -Fq -- "$2" <<<"$1" || fail "$3: must not show '$2' in: $1"; }

# 3a. first boot: header, phases, counters.
make_fixture
out="$(run_screen)"
expect "$out" 'NEURAL ICE   Neural ICE CoreOS' "header product"
expect "$out" 'OS 0.51.11' "header OS version"
expect "$out" "image deploy ab0000000000" "header image short digest falls back to the ostree deployment (12 hex)"
expect "$out" 'channel beta-debug' "header channel"
expect "$out" 'Model NVIDIA DGX Spark   Serial SN-1234-5678   Host ni-coreos-ab12' "header identity"
expect "$out" '[ OK ]  Storage         system and data volumes unlocked' "storage phase"
expect "$out" '[ .. ]  Device trust    TPM owner ceremony running' "ceremony running"
expect "$out" '[ OK ]  Network         enP7s7 up 192.168.1.20  RX 0 B/s  0 B total' "network phase with rate and total"
expect "$out" '[ .. ]  Images          1/2 present  RX ' "image counter with rate on the same line"
expect "$out" '[ .. ]  Core services   2/5 active' "core services: 4 shipped + 1 appended, active + condition-skipped count as done"
expect "$out" 'no input is read' "informational footer"
reject "$out" 'READY' "not ready while the ceremony runs"
reject "$out" 'FAILURE' "no failure on a healthy first boot"
reject "$out" '/24' "prefix length is not shown"
# The ostree fallback must not leak the full 64-hex checksum.
! grep -Eq '[0-9a-f]{20}' <<<"$out" || fail "a long hex string reached the screen"
serial="$(serial_out)"
expect "$serial" 'neural-ice-status: Neural ICE CoreOS | OS 0.51.11 | image deploy ab0000000000 | channel beta-debug' "serial header"
expect "$serial" 'neural-ice-status: model NVIDIA DGX Spark | serial SN-1234-5678' "serial identity"
expect "$serial" 'neural-ice-status: [ .. ] Device trust: TPM owner ceremony running' "serial phase line"
expect "$serial" 'neural-ice-status: [ .. ] Images: 1/2 present' "serial image counter"
reject "$serial" 'RX ' "serial mirror never carries the volatile rate"
[[ "$(grep -c 'neural-ice-status: ' "$FX/root/dev/ttyS0")" -eq 7 ]] || fail "serial mirror should print header(2) + five phases once: $serial"

# 3b. serial lines are emitted on CHANGE only; the redraw never repeats them.
out="$(run_screen 3 0)"
[[ "$(grep -c 'neural-ice-status: ' "$FX/root/dev/ttyS0")" -eq 7 ]] || fail "unchanged phases were re-mirrored to serial"

# 3b-bis. the management port is hostname-init's published contract, nothing
# else: absent (hostname-init not yet run, or NI-E05) the phase waits and names
# it; a published name with no such interface is treated the same, never trusted.
make_fixture
rm -f "$FX/root/run/neural-ice/mgmt-interface"
out="$(run_screen 1 0)"
expect "$out" '[    ]  Network         waiting for the management port (hostname-init)' "no contract: the network phase waits on hostname-init"
reject "$out" 'enP7s7' "without the contract the screen must not guess a port"
make_fixture
printf 'enp0s9\n' > "$FX/root/run/neural-ice/mgmt-interface"
out="$(run_screen 1 0)"
expect "$out" 'waiting for the management port (hostname-init)' "a published port absent from /sys/class/net is not trusted"
make_fixture
mkdir -p "$FX/root/sys/class/net/enp0s1/statistics" "$FX/root/sys/class/net/enp0s1/device"
printf 'up\n' > "$FX/root/sys/class/net/enp0s1/operstate"; printf '10\n' > "$FX/root/sys/class/net/enp0s1/statistics/rx_bytes"
printf 'enp0s1\n' > "$FX/root/run/neural-ice/mgmt-interface"
out="$(run_screen 1 0)"
expect "$out" '[ OK ]  Network         enp0s1 up 192.168.1.20' "the KVM bench port (enp0s1) is shown when hostname-init published it"

# 3c. receive rate from rx_bytes deltas, physical interfaces only.
make_fixture
( sleep 0.35; printf '8000000\n' > "$FX/root/sys/class/net/enP7s7/statistics/rx_bytes"
  printf '999999999\n' > "$FX/root/sys/class/net/lo/statistics/rx_bytes"
  printf '999999999\n' > "$FX/root/sys/class/net/veth0/statistics/rx_bytes" ) &
out="$(run_screen 2 0.7)"
wait
grep -Eq 'RX [0-9]+\.[0-9] MB/s  7\.0 MB total' <<<"$out" \
  || fail "receive rate/total not derived from the physical NIC rx_bytes delta (7 MB over ~0.7 s): $out"
reject "$out" 'GB total' "loopback / virtual interface counters must be excluded"

# 3d. ready: everything active and every image present -> READY, then exit on its own.
make_fixture
set_state neural-ice-firstboot-tpm-ceremony.service loaded active exited
set_state NetworkManager.service loaded active running
set_state neural-ice-payload-apply.service loaded active exited
set_state avahi-daemon.service loaded active running
set_state neural-ice-agentic-core.service loaded active running
printf '[{"digest":"sha256:%064d"},{"digest":"sha256:%064d"}]\n' 1 2 > "$FX/root/var/lib/containers/storage/overlay-images/images.json"
out="$(run_screen 50 0 NI_STATUS_READY_LINGER=0)"
expect "$out" '[ OK ]  Device trust    device trust: sealed' "later boot shows sealed trust"
expect "$out" '[ OK ]  Images          2/2 present' "all images present"
expect "$out" '[ OK ]  Core services   5/5 active' "all core services active"
expect "$out" 'READY -- login available.' "READY line"
[[ "$(grep -c 'READY -- login available' <<<"$out")" -eq 1 ]] || fail "READY with linger 0 must exit after one frame, got: $out"
expect "$(serial_out)" 'neural-ice-status: READY -- login available' "serial READY marker for the QEMU harness"

# 3d-bis. an image the bootc bound-image store carries counts as present. The
# store is a symlink (bootc points /usr/lib/bootc/storage under /sysroot) and
# is read through it; a store holding another digest counts for nothing.
make_fixture
set_state neural-ice-firstboot-tpm-ceremony.service loaded active exited
set_state NetworkManager.service loaded active running
set_state neural-ice-payload-apply.service loaded active exited
set_state avahi-daemon.service loaded active running
set_state neural-ice-agentic-core.service loaded active running
mkdir -p "$FX/root/sysroot/ostree/bootc/storage/overlay-images"
ln -s ../../../sysroot/ostree/bootc/storage "$FX/root/usr/lib/bootc/storage"
printf '[{"digest":"sha256:%064d"}]\n' 3 > "$FX/root/sysroot/ostree/bootc/storage/overlay-images/images.json"
out="$(run_screen 1 0)"
expect "$out" 'Images          1/2 present' "a bootc store holding another digest counts for nothing"
printf '[{"digest":"sha256:%064d"}]\n' 2 > "$FX/root/sysroot/ostree/bootc/storage/overlay-images/images.json"
out="$(run_screen 50 0 NI_STATUS_READY_LINGER=0)"
expect "$out" '[ OK ]  Images          2/2 present' "an image carried by the bootc store, read through the symlink, is present"
expect "$out" 'READY -- login available.' "READY with the second image only in the bootc store"

# 3e. a tty1 owner is active -> exit immediately, draw nothing.
set_state 'getty@tty1.service' loaded active running
out="$(run_screen 5 0)"
[[ -z $out ]] || fail "status screen must leave tty1 alone once getty owns it: $out"
set_state 'getty@tty1.service' loaded inactive dead
set_state neural-ice-tui.service loaded active running
out="$(run_screen 5 0)"
[[ -z $out ]] || fail "status screen must leave tty1 alone once the product TUI owns it: $out"

# 3e-2. ownership changes BETWEEN the loop's snapshot and the write: the pre-write
# re-check must drop the frame. getty@tty1 is queried once per iteration at the
# top of the loop and once again just before the write; flipping on its 2nd
# query means "inactive when scanned, active when about to draw".
make_fixture
out="$(run_screen 3 0 NI_TEST_FLIP_UNIT=getty@tty1.service NI_TEST_FLIP_AFTER=2)"
[[ -z $out ]] || fail "a tty1 owner that appeared between snapshot and write must suppress the frame: $out"
# ...and the same flip on the TUI, one iteration later: exactly one frame, then silence.
out="$(run_screen 3 0 NI_TEST_FLIP_UNIT=neural-ice-tui.service NI_TEST_FLIP_AFTER=3)"
[[ "$(grep -c 'NEURAL ICE   Neural ICE CoreOS' <<<"$out")" -eq 1 ]] \
  || fail "after the TUI took tty1 mid-run no further frame may be drawn: $out"

# 3e-3. systemctl failing is UNKNOWN, not "absent": no READY, no FAILURE, "probing".
make_fixture
out="$(run_screen 1 0 NI_STATUS_TEST_SYSTEMCTL=/bin/false NI_STATUS_READY_LINGER=0)"
expect "$out" 'Storage         probing...' "unknown storage state shows probing"
expect "$out" 'Device trust    probing...' "unknown ceremony state shows probing"
expect "$out" 'Network         probing...' "unknown network state shows probing"
expect "$out" 'Images          1/2 present -- probing...' "unknown import state still counts images but probes"
expect "$out" 'Core services   0/5 active -- probing...' "unknown core services are counted, not skipped"
expect "$out" 'Probing system state...' "footer says probing"
reject "$out" 'READY' "a failing systemctl must never yield READY"
reject "$out" 'FAILURE' "a failing systemctl is not an appliance failure"
reject "$out" 'no separate data volume' "unknown must not be read as not-found"
# A ready scene with ONE unknown probe is not ready either.
make_fixture
set_state neural-ice-firstboot-tpm-ceremony.service loaded active exited
set_state NetworkManager.service loaded active running
set_state neural-ice-payload-apply.service loaded active exited
set_state avahi-daemon.service loaded active running
set_state neural-ice-agentic-core.service loaded active running
printf '[{"digest":"sha256:%064d"},{"digest":"sha256:%064d"}]\n' 1 2 > "$FX/root/var/lib/containers/storage/overlay-images/images.json"
cat > "$TOOLS/systemctl-flaky" <<'EOS'
#!/usr/bin/env bash
[[ ${*: -1} == neural-ice-seed-import.service ]] && exit 1
exec "$(dirname "$0")/systemctl" "$@"
EOS
chmod 0755 "$TOOLS/systemctl-flaky"
out="$(run_screen 1 0 NI_STATUS_TEST_SYSTEMCTL="$TOOLS/systemctl-flaky" NI_STATUS_READY_LINGER=0)"
reject "$out" 'READY' "one unanswered probe must block READY"
expect "$out" 'probing...' "the unanswered probe is shown as probing"

# 3e-4. serial UART = the kernel's active console, then console=; VTs and
# other UARTs never qualify.
make_fixture
printf 'tty0 ttyAMA0\n' > "$FX/root/sys/class/tty/console/active"
run_screen >/dev/null
[[ -s $FX/root/dev/ttyAMA0 && ! -s $FX/root/dev/ttyS0 ]] || fail "QEMU aarch64 console ttyAMA0 was not selected from the active console list"
make_fixture
printf 'tty0\n' > "$FX/root/sys/class/tty/console/active"
printf 'BOOT_IMAGE=(hd0)/vmlinuz console=tty1 console=ttyS0,115200 quiet\n' > "$FX/root/proc/cmdline"
run_screen >/dev/null
[[ -s $FX/root/dev/ttyS0 && ! -s $FX/root/dev/ttyAMA0 ]] || fail "console= on the kernel command line was not honoured when the active list has only a VT"
make_fixture
printf 'tty0\n' > "$FX/root/sys/class/tty/console/active"
printf 'BOOT_IMAGE=(hd0)/vmlinuz quiet\n' > "$FX/root/proc/cmdline"
out="$(run_screen)"
[[ ! -s $FX/root/dev/ttyS0 && ! -s $FX/root/dev/ttyAMA0 ]] || fail "with no serial console configured nothing may be written to a UART"
expect "$out" 'Core services' "no serial console must not affect the tty1 screen"
make_fixture
printf 'tty0 ttyTHS0\n' > "$FX/root/sys/class/tty/console/active"
run_screen >/dev/null
[[ ! -s $FX/root/dev/ttyTHS0 ]] || fail "a UART outside the unit's DeviceAllow= set was selected"

# 3f. failure block: stable code, unit, serial, instruction; earliest phase wins.
make_fixture
set_state neural-ice-firstboot-tpm-ceremony.service loaded failed failed
out="$(run_screen)"
expect "$out" 'FAILURE  NI-E02  (TPM ceremony)' "ceremony failure code"
expect "$out" 'unit:    neural-ice-firstboot-tpm-ceremony.service' "failing unit named"
expect "$out" 'serial:  SN-1234-5678' "serial in the failure block"
expect "$out" 'Contact Neural ICE support with this code and serial.' "support instruction"
reject "$out" 'READY' "no READY on failure"
expect "$(serial_out)" 'neural-ice-status: FAILURE NI-E02 (TPM ceremony) unit=neural-ice-firstboot-tpm-ceremony.service serial=SN-1234-5678' "serial failure marker"
set_state systemd-cryptsetup@data.service loaded failed failed
out="$(run_screen)"
expect "$out" 'FAILURE  NI-E01  (storage unlock)' "storage failure wins over a later phase"
expect "$out" 'unit:    systemd-cryptsetup@data.service' "storage unit named"

make_fixture
set_state NetworkManager.service loaded failed failed
out="$(run_screen)"; expect "$out" 'FAILURE  NI-E03  (network)' "network failure code"
make_fixture
set_state neural-ice-seed-import.service loaded failed failed
out="$(run_screen)"; expect "$out" 'FAILURE  NI-E04  (image pull)' "image import failure code"
make_fixture
set_state neural-ice-agentic-core.service loaded failed failed
out="$(run_screen)"
expect "$out" 'FAILURE  NI-E05  (core service)' "core service failure code"
expect "$out" 'unit:    neural-ice-agentic-core.service' "the appended product unit is named"

# 3g. ceremony timeout is a failure with the same stable code.
make_fixture
out="$(run_screen 2 0 NI_STATUS_CEREMONY_TIMEOUT=0)"
expect "$out" 'FAILURE  NI-E02  (TPM ceremony timeout)' "ceremony timeout reported as NI-E02"
expect "$out" 'TPM owner ceremony still running after timeout' "timeout phase text"

# 3h. no product inventory (vanilla OS), no data volume, no channel: degrade, never fail.
make_fixture
rm -rf "$FX/root/usr/lib/bootc/bound-images.d" "$FX/root/usr/share/containers/systemd" "$FX/root/etc/containers/systemd" \
  "$FX/root/var/lib/neural-ice/data/release/CHANNEL" "$FX/root/usr/lib/neural-ice/status-screen"
printf 'device_channel=stable\n' > "$FX/root/etc/neural-ice/ota.conf"
sed -i '/^systemd-cryptsetup@data.service /d; /^var-lib-neural/d' "$FX/scene"
out="$(run_screen)"
expect "$out" '[ -- ]  Images          no product image inventory on this image' "vanilla image has no inventory"
expect "$out" '[ OK ]  Storage         system volume unlocked (no separate data volume)' "no data volume is not a failure"
expect "$out" 'channel stable' "channel falls back to ota.conf"
expect "$out" 'Core services   2/4 active' "without the extension file only the shipped list is watched"
reject "$out" 'FAILURE' "degraded inventory is not a failure"

# 3i. the seam refuses a relative root and a missing systemctl.
! env NI_STATUS_SCREEN_TESTING=1 NI_STATUS_TEST_ROOT=relative NI_STATUS_TEST_SYSTEMCTL="$TOOLS/systemctl" bash "$SCRIPT" >/dev/null 2>&1 \
  || fail "test seam accepted a relative root"
! env NI_STATUS_SCREEN_TESTING=1 NI_STATUS_TEST_ROOT="$FX/root" bash "$SCRIPT" >/dev/null 2>&1 \
  || fail "test seam ran without an explicit systemctl"

# --- 4. a host whose image ships a product declaration --------------------------
# Field bug, first production-grade v2 appliance (ASUS GX10, lane-2 preload=none
# medium): the v1 screen showed "Images [--] no product image inventory on this
# image", "channel unset", and READY while the first pull was still pulling. The
# OS knows nothing of that product: its image ships /usr/lib/neural-ice/status-screen.d/
# appliance-v2.conf, and the fixture below is byte for byte that file. A host
# without the directory keeps the v1 screen (sections 3a-3i run without it).
DECL_NAME=appliance-v2.conf
read -r -d '' DECL_V2 <<'EOF' || true
# Boot status screen declaration of the Neural ICE v2 appliance (grammar:
# ICE-CoreOS image/firstboot/status-error-codes.md, "Product declarations").
version=1
images_units=ni-v2-seed-import.service ni-v2-first-pull.service
images_manifest=/var/lib/neural-ice-v2/current-release/release-manifest.json
images_component_key=component_id
images_digest_key=digest
images_alias=localhost/neural-ice-applied/{id}:v1
images_release_key=release_id
core_units=neural-ice-product-payload-apply.service icecore-api.service
EOF
V2_REL=v2-lab-train-3-20261006-b
v2_digest() { printf 'sha256:%064d' "$1"; }
write_decl() { # <name> <content>: a declaration as the image ships it (0644)
  mkdir -p "$FX/root/usr/lib/neural-ice/status-screen.d"
  chmod 0755 "$FX/root/usr/lib/neural-ice/status-screen.d"
  printf '%s\n' "$2" > "$FX/root/usr/lib/neural-ice/status-screen.d/$1"
  chmod 0644 "$FX/root/usr/lib/neural-ice/status-screen.d/$1"
}
make_v2_fixture() { # tonight's screen: first pull activating, 1 of 3 components pulled, nothing else started
  make_fixture
  rm -rf "$FX/root/usr/lib/bootc/bound-images.d" "$FX/root/usr/share/containers/systemd" "$FX/root/etc/containers/systemd" \
    "$FX/root/usr/lib/neural-ice/status-screen" "$FX/root/var/lib/neural-ice/data/release"
  write_decl "$DECL_NAME" "$DECL_V2"
  mkdir -p "$FX/root/var/lib/neural-ice-v2/current-release"
  # compact canonical JSON, as signed: 3 components, the host entry and an evidence entry are NOT components
  printf '{"bundle_seq":3,"compatibility":{"minimum_reader":1},"components":[%s,%s,%s],"content":[],"evidence":[{"digest":"%s","kind":"attestation"}],"hardware_target":"nvidia-gb10-arm64","host":{"contract":"host-bootc-v1","digest":"%s","reboot_required":true,"repository":"rg.fr-par.scw.cloud/neural-ice-v2-lab/host-appliance","restart_scope":["bootc-fetch-apply-updates.service"]},"release_id":"%s","schema":"neural-ice-release-manifest-v1"}\n' \
    "{\"component_id\":\"agentic-core\",\"contract\":\"oci-component-v1\",\"digest\":\"$(v2_digest 11)\",\"reboot_required\":false,\"repository\":\"rg.fr-par.scw.cloud/neural-ice-v2-lab/agentic-core\",\"restart_scope\":[\"agentic-core.service\"]}" \
    "{\"component_id\":\"caddy\",\"contract\":\"oci-component-v1\",\"digest\":\"$(v2_digest 12)\",\"reboot_required\":false,\"repository\":\"rg.fr-par.scw.cloud/neural-ice-v2-lab/caddy\",\"restart_scope\":[\"caddy.service\"]}" \
    "{\"component_id\":\"icecore-api\",\"contract\":\"oci-component-v1\",\"digest\":\"$(v2_digest 13)\",\"reboot_required\":false,\"repository\":\"rg.fr-par.scw.cloud/neural-ice-v2-lab/icecore-api\",\"restart_scope\":[\"icecore-api.service\"]}" \
    "$(v2_digest 99)" "$(v2_digest 98)" "$V2_REL" > "$FX/root/var/lib/neural-ice-v2/current-release/release-manifest.json"
  v2_store 1
  cat > "$FX/scene" <<'EOF'
systemd-cryptsetup@data.service loaded active exited 0 yes
var-lib-neural\x2dice-data.mount loaded active mounted 0 yes
neural-ice-firstboot-tpm-ceremony.service loaded active exited 0 yes
NetworkManager.service loaded active running 0 yes
neural-ice-hostname-init.service loaded active exited 0 yes
neural-ice-device-root.service loaded inactive dead 4242 no
neural-ice-payload-apply.service loaded inactive dead 4242 no
avahi-daemon.service loaded active running 0 yes
ni-v2-seed-import.service loaded active exited 0 yes
ni-v2-first-pull.service loaded activating start 0 yes
neural-ice-product-payload-apply.service loaded inactive dead 0 no
icecore-api.service loaded inactive dead 0 no
EOF
}
v2_store() { # <n>: containers-storage holds the aliases of the first n components, digest-for-digest
  local n=$1 i out="" ids=(agentic-core caddy icecore-api)
  for ((i = 0; i < n; i++)); do
    out+="${out:+,}{\"id\":\"x$i\",\"digest\":\"$(v2_digest $((11 + i)))\",\"names\":[\"localhost/neural-ice-applied/${ids[i]}:v1\",\"rg.fr-par.scw.cloud/neural-ice-v2-lab/${ids[i]}@$(v2_digest $((11 + i)))\"]}"
  done
  printf '[%s]\n' "$out" > "$FX/root/var/lib/containers/storage/overlay-images/images.json"
}
v2_ready_scene() { # first pull done, every component present, product core units up
  v2_store 3
  set_state ni-v2-first-pull.service loaded active exited 0 yes
  set_state neural-ice-product-payload-apply.service loaded active exited 0 yes
  set_state icecore-api.service loaded active running 0 yes
}

# 4a. tonight's screen, reproduced: first pull at 1/3, product units not started.
make_v2_fixture
out="$(run_screen)"
expect "$out" "release $V2_REL" "header carries the declared release id"
reject "$out" 'channel unset' "a declared host has no v1 CHANNEL file; the header must not claim an unset channel"
reject "$out" 'channel ' "the header names the release, not a v1 channel"
expect "$out" '[ .. ]  Images          1/3 present  RX ' "Images row: components present / components of the declared manifest, first pull running"
reject "$out" 'no product image inventory' "a declared host has an inventory: the components of its manifest"
reject "$out" 'READY' "no READY while the declared first pull is still activating"
reject "$out" 'FAILURE' "a first pull in progress is not a failure"
expect "$out" '[ .. ]  Core services   3/5 active' "core list: hostname-init, device-root, avahi + the two declared units"
expect "$out" 'no input is read' "footer still says starting"
serial="$(serial_out)"
expect "$serial" "neural-ice-status: Neural ICE CoreOS | OS 0.51.11 | image deploy ab0000000000 | release $V2_REL" "serial header names the release"
expect "$serial" 'neural-ice-status: [ .. ] Images: 1/3 present' "serial image counter"
reject "$serial" 'READY' "serial never announces READY during the first pull"

# 4b. READY only after the declared image units are done AND the declared core units are active.
make_v2_fixture
v2_ready_scene
out="$(run_screen 50 0 NI_STATUS_READY_LINGER=0)"
expect "$out" '[ OK ]  Images          3/3 present' "all components present, image units done"
expect "$out" '[ OK ]  Core services   5/5 active' "declared core units all active"
expect "$out" 'READY -- login available.' "READY once everything is done"
expect "$(serial_out)" 'neural-ice-status: READY -- login available' "serial READY marker"
# every component present but the unit has not committed yet (aliases, DONE marker): not ready
set_state ni-v2-first-pull.service loaded activating start 0 yes
out="$(run_screen 1 0)"
expect "$out" '[ .. ]  Images          3/3 present' "all components present but the last image unit still running"
reject "$out" 'READY' "READY waits for the image unit itself, not for the last alias"
# queued behind the seed import: not started yet, not done
set_state ni-v2-first-pull.service loaded inactive dead 0 no
out="$(run_screen 1 0)"
reject "$out" 'READY' "an image unit that has not started is not done"
# a full-preload host: the first pull is skipped by its Condition and counts as done
set_state ni-v2-first-pull.service loaded inactive dead 4242 no
out="$(run_screen 50 0 NI_STATUS_READY_LINGER=0)"
expect "$out" 'READY -- login available.' "a condition-skipped image unit is done"
# the declared core units are part of READY
set_state icecore-api.service loaded inactive dead 0 no
out="$(run_screen 1 0)"
expect "$out" '[ .. ]  Core services   4/5 active' "declared core unit not started yet"
reject "$out" 'READY' "READY waits for the declared core units"
set_state icecore-api.service loaded failed failed 0 no
out="$(run_screen 1 0)"
expect "$out" 'FAILURE  NI-E05  (core service)' "a failed declared core unit is a core-service failure"
expect "$out" 'unit:    icecore-api.service' "the declared core unit is named"
# a declared core unit the image does not ship is skipped, not waited for
make_v2_fixture
v2_ready_scene
sed -i '/^icecore-api.service /d' "$FX/scene"
out="$(run_screen 50 0 NI_STATUS_READY_LINGER=0)"
expect "$out" '[ OK ]  Core services   4/4 active' "an unshipped declared unit is skipped"
expect "$out" 'READY -- login available.' "an unshipped declared unit does not hold READY"

# 4c. a digest that is not the manifest's is not "present"; an alias without its image neither.
make_v2_fixture
printf '[{"digest":"%s","names":["localhost/neural-ice-applied/agentic-core:v1"]},{"digest":"%s","names":["localhost/neural-ice-applied/caddy:v1"]}]\n' \
  "$(v2_digest 77)" "$(v2_digest 12)" > "$FX/root/var/lib/containers/storage/overlay-images/images.json"
out="$(run_screen 1 0)"
expect "$out" 'Images          1/3 present' "a stale alias (other digest) does not count; the matching one does"

# 4d. failures: NI-E04 names the declared unit; earliest phase wins.
make_v2_fixture
set_state ni-v2-first-pull.service loaded failed failed 0 yes
out="$(run_screen)"
expect "$out" 'FAILURE  NI-E04  (image pull)' "image unit failure code"
expect "$out" 'unit:    ni-v2-first-pull.service' "failed image unit named"
expect "$out" '[FAIL]  Images          1/3 present -- image import failed' "images row fails"
reject "$out" 'READY' "no READY on a failed image unit"
expect "$(serial_out)" 'neural-ice-status: FAILURE NI-E04 (image pull) unit=ni-v2-first-pull.service serial=SN-1234-5678' "serial failure marker"
set_state ni-v2-seed-import.service loaded failed failed 0 yes
out="$(run_screen)"
expect "$out" 'unit:    ni-v2-seed-import.service' "the first declared unit is the one named"
# the OS's own v1 image units are not watched once a declaration replaces them
make_v2_fixture
set_state neural-ice-seed-import.service loaded failed failed 0 yes
set_state neural-ice-payload-apply.service loaded failed failed 0 yes
out="$(run_screen)"
reject "$out" 'NI-E04' "v1 import units are not watched under a declared image phase"
reject "$out" 'NI-E05' "the v1 payload apply is not a core service under a declared image phase"

# 4e. no manifest yet: nothing to count, never READY, never a v1 "no inventory" skip.
make_v2_fixture
rm -f "$FX/root/var/lib/neural-ice-v2/current-release/release-manifest.json"
out="$(run_screen)"
expect "$out" 'release unset' "no manifest: the header says so"
expect "$out" '[    ]  Images          waiting for the release manifest' "no manifest: waiting, not skipped"
reject "$out" 'no product image inventory' "an absent manifest is not an empty inventory"
reject "$out" 'READY' "no READY without a manifest"
# a manifest that names no component cannot be READY either
printf '{"release_id":"%s","components":[]}\n' "$V2_REL" > "$FX/root/var/lib/neural-ice-v2/current-release/release-manifest.json"
out="$(run_screen 50 0 NI_STATUS_READY_LINGER=0)"
reject "$out" 'READY' "a manifest with zero components must not be READY"
# the manifest is read as a regular file, never through a symlink, and its release id is character-checked
rm -f "$FX/root/var/lib/neural-ice-v2/current-release/release-manifest.json"
printf '{"release_id":"x","components":[]}\n' > "$FX/elsewhere.json"
ln -s "$FX/elsewhere.json" "$FX/root/var/lib/neural-ice-v2/current-release/release-manifest.json"
out="$(run_screen)"
reject "$out" 'release x' "a symlinked manifest is not read"
make_v2_fixture
sed -i "s/$V2_REL/bad id;\$(touch pwned)/" "$FX/root/var/lib/neural-ice-v2/current-release/release-manifest.json"
out="$(run_screen)"
expect "$out" 'release unset' "a release id outside [A-Za-z0-9._-] is not shown"
[[ ! -e pwned && ! -e $FX/pwned ]] || fail "manifest content reached a shell"

# 4f. unknown is not a state on a declared host either.
make_v2_fixture
out="$(run_screen 1 0 NI_STATUS_TEST_SYSTEMCTL=/bin/false NI_STATUS_READY_LINGER=0)"
expect "$out" 'Images          1/3 present -- probing...' "unknown image unit state probes"
reject "$out" 'READY' "a failing systemctl never yields READY"
reject "$out" 'FAILURE' "a failing systemctl is not a failure"

# 4g. no declaration, no change: no directory (even with the old v2 marker), or an
# empty directory, is the v1 screen.
make_v2_fixture
mkdir -p "$FX/root/var/lib/neural-ice/data/release"; printf 'beta-debug\n' > "$FX/root/var/lib/neural-ice/data/release/CHANNEL"   # a v1 host has one
rm -rf "$FX/root/usr/lib/neural-ice/status-screen.d"
printf 'owner-sealed-ota-state-v2\n' > "$FX/root/usr/lib/neural-ice/ota-state-profile"
out="$(run_screen)"
expect "$out" 'channel beta-debug' "no declaration directory: v1 header, whatever the image markers say"
expect "$out" 'no product image inventory on this image' "no declaration directory: v1 images row"
reject "$out" 'release ' "no declaration directory: no release in the header"
reject "$out" 'NI-E06' "an absent directory is not a fault"
mkdir -p "$FX/root/usr/lib/neural-ice/status-screen.d"; chmod 0755 "$FX/root/usr/lib/neural-ice/status-screen.d"
printf 'notes\n' > "$FX/root/usr/lib/neural-ice/status-screen.d/README"          # not *.conf: ignored
out="$(run_screen)"
expect "$out" 'channel beta-debug' "empty directory: v1 header"
reject "$out" 'NI-E06' "files that are not *.conf are ignored, as systemd drop-ins are"

# 4h. core_units alone (no image phase): v1 images row, the declared units are core services.
make_fixture
write_decl extra.conf $'version=1\ncore_units=product-a.service product-b.socket'
printf 'product-a.service loaded active running 0 yes\nproduct-b.socket loaded active running 0 yes\n' >> "$FX/scene"
out="$(run_screen)"
expect "$out" 'channel beta-debug' "core_units alone keeps the v1 header"
expect "$out" 'Images          1/2 present' "core_units alone keeps the v1 inventory"
expect "$out" 'Core services   4/7 active' "declared core units join the OS and extension lists"
# the same unit named twice (declaration + the older extension file) is counted once
write_decl extra.conf $'version=1\ncore_units=neural-ice-agentic-core.service avahi-daemon.service'
out="$(run_screen)"
expect "$out" 'Core services   2/5 active' "a unit already in the list is not counted twice"
# two declarations may both add core units; both are applied
write_decl extra.conf $'version=1\ncore_units=product-a.service'
write_decl more.conf $'version=1\ncore_units=product-b.socket'
out="$(run_screen)"
expect "$out" 'Core services   4/7 active' "core_units add up across files"

# 4i. every malformed declaration is refused AND reported (NI-E06 + the file); its
# facts are never applied, and READY is withheld.
refuse() { # <scenario> <file name> <content> <expected reason>
  make_v2_fixture
  v2_ready_scene
  write_decl "$2" "$3"
  local out serial
  out="$(run_screen 1 0)"
  expect "$out" "FAILURE  NI-E06  (status declaration: $4" "$1: reported as a status fault"
  expect "$out" "unit:    $2" "$1: the offending file is named"
  reject "$out" 'READY' "$1: no READY while a declaration is refused"
  serial="$(serial_out)"
  expect "$serial" "neural-ice-status: FAILURE NI-E06 (status declaration: $4" "$1: serial failure marker"
  expect "$serial" "unit=$2 serial=SN-1234-5678" "$1: serial names the file"
  # the good declaration still applies (a refused file contributes nothing, others stand)
  expect "$out" "release $V2_REL" "$1: the valid declaration is still applied"
}
BAD_NAME=zz-bad.conf
refuse "unknown key" "$BAD_NAME" $'version=1\ncore_units=x.service\nimages_unit=y.service' "unknown key images_unit"
refuse "unknown key (typo of a valid one)" "$BAD_NAME" $'version=1\ncore_unit=x.service' "unknown key core_unit"
refuse "duplicate key" "$BAD_NAME" $'version=1\ncore_units=x.service\ncore_units=y.service' "key core_units given twice"
refuse "missing version" "$BAD_NAME" 'core_units=x.service' "version=1 missing or unsupported"
refuse "unsupported version" "$BAD_NAME" $'version=2\ncore_units=x.service' "version=1 missing or unsupported"
refuse "declares nothing" "$BAD_NAME" 'version=1' "declares nothing"
refuse "not key=value" "$BAD_NAME" $'version=1\nthis is not a declaration' "line 2 is not key=value"
refuse "space around =" "$BAD_NAME" $'version=1\ncore_units = x.service' "line 2 is not key=value"
refuse "empty value" "$BAD_NAME" $'version=1\ncore_units=' "line 2 is not key=value"
refuse "leading space in value" "$BAD_NAME" $'version=1\ncore_units= x.service' "line 2 is not key=value"
refuse "indented line" "$BAD_NAME" $'version=1\n core_units=x.service' "line 2 is not key=value"
refuse "uppercase key" "$BAD_NAME" $'version=1\nCore_Units=x.service' "line 2 is not key=value"
refuse "unit name with a path" "$BAD_NAME" $'version=1\ncore_units=../../etc/shadow' "bad core_units"
refuse "unit name without a type" "$BAD_NAME" $'version=1\ncore_units=sshd' "bad core_units"
refuse "unit name with shell metacharacters" "$BAD_NAME" $'version=1\ncore_units=x$(touch pwned).service' "bad core_units"
refuse "double space in a list" "$BAD_NAME" $'version=1\ncore_units=a.service  b.service' "bad core_units"
refuse "trailing space in a list" "$BAD_NAME" $'version=1\ncore_units=a.service ' "bad core_units"
refuse "repeated unit in a list" "$BAD_NAME" $'version=1\ncore_units=a.service a.service' "bad core_units"
refuse "too many core units" "$BAD_NAME" "$(printf 'version=1\ncore_units='; for i in $(seq 1 17); do printf 'u%d.service ' "$i"; done | sed 's/ $//')" "bad core_units"
refuse "image unit that is not a service" "$BAD_NAME" "$(printf '%s\n' "$DECL_V2" | sed 's/^images_units=.*/images_units=x.socket/')" "bad images_units"
refuse "second image declaration" "$BAD_NAME" "$DECL_V2" "images declared by another file"
refuse "incomplete images_*" "$BAD_NAME" $'version=1\nimages_units=a.service\nimages_manifest=/var/lib/x/m.json' "missing key images_component_key"
refuse "images_release_key alone" "$BAD_NAME" $'version=1\nimages_release_key=release_id' "missing key images_units"
bad_images() { printf '%s\n' "$DECL_V2" | sed -E "s|^$1=.*|$1=$2|; /^# /d; /^core_units=/d" | sed "s/^images_units=.*/images_units=a.service/"; }
refuse "manifest path outside the allowed roots" "$BAD_NAME" "$(bad_images images_manifest /etc/shadow)" "bad images_manifest"
refuse "manifest path into /sys" "$BAD_NAME" "$(bad_images images_manifest /sys/class/net/x)" "bad images_manifest"
refuse "manifest path with .." "$BAD_NAME" "$(bad_images images_manifest /var/lib/x/../../etc/shadow)" "bad images_manifest"
refuse "manifest path with //" "$BAD_NAME" "$(bad_images images_manifest /var/lib//x)" "bad images_manifest"
refuse "manifest path relative" "$BAD_NAME" "$(bad_images images_manifest var/lib/x/m.json)" "bad images_manifest"
refuse "manifest path with a space" "$BAD_NAME" "$(bad_images images_manifest '/var/lib/x y')" "bad images_manifest"
refuse "manifest path ending in a slash" "$BAD_NAME" "$(bad_images images_manifest /var/lib/x/)" "bad images_manifest"
refuse "manifest key with a quote" "$BAD_NAME" "$(bad_images images_component_key 'a"b')" "bad images_component_key"
refuse "manifest key in upper case" "$BAD_NAME" "$(bad_images images_digest_key Digest)" "bad images_digest_key"
refuse "release key with a regex metacharacter" "$BAD_NAME" "$(bad_images images_release_key 'a.*')" "bad images_release_key"
refuse "alias without {id}" "$BAD_NAME" "$(bad_images images_alias localhost/x:v1)" "bad images_alias"
refuse "alias with two {id}" "$BAD_NAME" "$(bad_images images_alias 'localhost/{id}/{id}:v1')" "bad images_alias"
refuse "alias with a glob character" "$BAD_NAME" "$(bad_images images_alias 'localhost/*/{id}:v1')" "bad images_alias"
refuse "alias in upper case" "$BAD_NAME" "$(bad_images images_alias 'Localhost/{id}:v1')" "bad images_alias"
refuse "carriage return" "$BAD_NAME" $'version=1\r\ncore_units=x.service' "not printable ASCII"
refuse "tab" "$BAD_NAME" $'version=1\ncore_units=x.service\t' "not printable ASCII"
refuse "non-ASCII" "$BAD_NAME" $'version=1\n# caf\xc3\xa9\ncore_units=x.service' "not printable ASCII"
refuse "comment in the middle of a line" "$BAD_NAME" $'version=1\ncore_units=x.service # comment' "bad core_units"
refuse "file name outside the grammar" "Bad_Name.conf" $'version=1\ncore_units=x.service' "bad file name"

# file-level refusals: NUL, size, mode, symlink, non-regular, count, directory.
refuse_file() { # <scenario> <expected reason> <name>: the caller prepared the file in $FX/root/.../status-screen.d
  local out
  out="$(run_screen 1 0)"
  expect "$out" "FAILURE  NI-E06  (status declaration: $2" "$1: reported as a status fault"
  expect "$out" "unit:    $3" "$1: the offending entry is named"
  reject "$out" 'READY' "$1: no READY"
}
DD="$FX/root/usr/lib/neural-ice/status-screen.d"
make_v2_fixture; v2_ready_scene
printf 'version=1\ncore_units=x.service\n\0' > "$DD/$BAD_NAME"; chmod 0644 "$DD/$BAD_NAME"
refuse_file "NUL byte" "not printable ASCII" "$BAD_NAME"
make_v2_fixture; v2_ready_scene
{ printf 'version=1\ncore_units=x.service\n'; head -c 5000 /dev/zero | tr '\0' '#'; printf '\n'; } > "$DD/$BAD_NAME"; chmod 0644 "$DD/$BAD_NAME"
refuse_file "oversize" "larger than 4096 bytes" "$BAD_NAME"
make_v2_fixture; v2_ready_scene
printf 'version=1\ncore_units=x.service\n' > "$DD/$BAD_NAME"; chmod 0666 "$DD/$BAD_NAME"
refuse_file "world-writable" "unsafe owner or mode" "$BAD_NAME"
printf 'version=1\ncore_units=x.service\n' > "$DD/$BAD_NAME"; chmod 0664 "$DD/$BAD_NAME"
refuse_file "group-writable" "unsafe owner or mode" "$BAD_NAME"
make_v2_fixture; v2_ready_scene
printf 'version=1\ncore_units=x.service\n' > "$FX/elsewhere.conf"; chmod 0644 "$FX/elsewhere.conf"
ln -s "$FX/elsewhere.conf" "$DD/$BAD_NAME"
refuse_file "symlink" "not a regular file" "$BAD_NAME"
make_v2_fixture; v2_ready_scene
mkdir "$DD/$BAD_NAME"
refuse_file "directory named *.conf" "not a regular file" "$BAD_NAME"
make_v2_fixture; v2_ready_scene
for i in $(seq 1 16); do printf 'version=1\ncore_units=p%d.service\n' "$i" > "$DD/extra-$(printf '%02d' "$i").conf"; chmod 0644 "$DD/extra-$(printf '%02d' "$i").conf"; done
refuse_file "more than 16 declarations" "more than 16 declarations" "status-screen.d"
make_v2_fixture; v2_ready_scene
mv "$DD" "$FX/real-status-screen.d"; ln -s "$FX/real-status-screen.d" "$DD"
refuse_file "directory symlink" "not a plain directory" "status-screen.d"
make_v2_fixture; v2_ready_scene
chmod 0777 "$DD"
refuse_file "world-writable directory" "unsafe owner or mode" "status-screen.d"
chmod 0755 "$DD"
make_v2_fixture; v2_ready_scene
rm -rf "$DD"; : > "$FX/root/usr/lib/neural-ice/status-screen.d"
refuse_file "directory replaced by a file" "not a plain directory" "status-screen.d"
# a refused file never leaks its facts: a lone refused images declaration leaves the v1 screen
make_fixture
write_decl "$BAD_NAME" "$(printf '%s\n' "$DECL_V2" | sed 's/^images_alias=.*/images_alias=oops/')"
out="$(run_screen)"
expect "$out" 'channel beta-debug' "a refused images declaration is not half-applied (header)"
expect "$out" 'Images          1/2 present' "a refused images declaration is not half-applied (v1 inventory)"
expect "$out" 'NI-E06' "and it is reported"
[[ ! -e pwned && ! -e $FX/pwned ]] || fail "declaration content reached a shell"
# the grammar paragraph of the doc names every key the parser accepts, and only those
for k in version images_units images_manifest images_component_key images_digest_key images_release_key images_alias core_units; do
  grep -qE "^\| \`$k=\` " "$CODES" || fail "declaration key $k is not documented in status-error-codes.md"
  grep -qE "^      $k\)" "$SCRIPT" || fail "declaration key $k is not parsed"
done

echo "STATUS_SCREEN_OFFLINE_TEST_OK (unit contract, secret allow-list, open-core boundary, 13 v1 behaviour scenes, declared-product scenes, malformed-declaration refusals)"
