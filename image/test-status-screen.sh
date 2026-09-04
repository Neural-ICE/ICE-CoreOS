#!/usr/bin/env bash
# Offline proof of the tty1 boot status screen (image/firstboot/neural-ice-status-screen.*).
#
# Three families of assertions:
#   1. the unit cannot cycle, is not ceremony-gated, is sandboxed, owns tty1 only;
#   2. the script reads NOTHING outside its declared allow-list -- no recovery
#      key, no LUKS/TPM material, no licence, no token, no fingerprint path;
#   3. the script, run through its unprivileged test seam against crafted
#      fixtures, shows the phases, the counters, the receive rate, the failure
#      block with the stable NI-Exx code, READY, and the serial mirror lines.
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
! grep -E '^Conflicts=' "$UNIT" \
  || fail "Conflicts= between two jobs of the boot transaction makes systemd drop one of them; the script polls the tty1 owners instead"
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
grep -qx 'WantedBy=multi-user.target' "$UNIT" || fail "status screen is not pulled in by multi-user"
grep -qx 'Environment=NI_STATUS_CEREMONY_TIMEOUT=[0-9]*' "$UNIT" || fail "ceremony timeout is not configurable from the unit"

# The full effective unit must load and verify under a real systemd when one is
# available (no unknown keys, no syntax error, no cycle it can see).
if command -v systemd-analyze >/dev/null 2>&1; then
  VROOT="$TMP/verify-root"
  mkdir -p "$VROOT/usr/lib/systemd/system" "$VROOT/usr/local/bin"
  cp -- "$UNIT" "$VROOT/usr/lib/systemd/system/"
  cp -- "$SCRIPT" "$VROOT/usr/local/bin/neural-ice-status-screen.sh"
  chmod 0755 "$VROOT/usr/local/bin/neural-ice-status-screen.sh"
  out="$(systemd-analyze --root="$VROOT" verify neural-ice-status-screen.service 2>&1)" \
    || fail "systemd-analyze verify rejects the status screen unit: $out"
  ! grep -Eiq 'cycle|Unknown key|Failed to parse' <<<"$out" || fail "systemd-analyze verify flagged the unit: $out"
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
allowed=(
  /usr/lib/os-release /usr/lib/neural-ice/version /usr/lib/neural-ice/status-screen
  /usr/lib/neural-ice/release-image /usr/lib/bootc/bound-images.d /usr/share/containers/systemd
  /etc/containers/systemd /etc/NetworkManager/system-connections /etc/neural-ice/ota.conf
  /var/lib/neural-ice/data/release/CHANNEL /var/lib/neural-ice/data/seed-store/current/overlay-images/images.json
  /var/lib/containers/storage/overlay-images/images.json /sys/class/net /sys/class/dmi/id
  /proc/cmdline /proc/sys/kernel/hostname /dev/ttyAMA0 /dev/ttyS0 /dev/null
)
while IFS= read -r found; do
  ok=0
  for prefix in "${allowed[@]}"; do
    [[ $found == "$prefix" || $found == "$prefix"/* ]] && { ok=1; break; }
  done
  (( ok )) || fail "status screen code names a path outside its allow-list: $found"
done < <(grep -oE '(^|[^A-Za-z0-9_])/(usr|etc|var|sys|proc|dev|run|root|home|tmp|boot|opt|srv|sysroot|ostree|mnt|media)(/[A-Za-z0-9_.@-]+)*' "$CODE" \
           | sed -E 's/^[^\/]//' | sort -u)
# The only NetworkManager profile read is the interface name of mgmt-*; a
# profile can carry credentials and this code must never read anything else.
nm_reads="$(grep -n 'nmconnection' "$CODE" || true)"
[[ -n $nm_reads ]] || fail "management NIC resolution disappeared"
while IFS= read -r l; do
  [[ $l == *'mgmt-*.nmconnection'* ]] || fail "status screen reads a NetworkManager profile other than mgmt-*: $l"
done <<<"$nm_reads"
grep -Fq "sed -n 's/^interface-name=//p' \"\$conn\"" "$CODE" || fail "status screen must extract only interface-name= from the mgmt profile"
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
    "$FX/root/etc/NetworkManager/system-connections" "$FX/root/etc/neural-ice" \
    "$FX/root/var/lib/neural-ice/data/release" "$FX/root/var/lib/containers/storage/overlay-images" \
    "$FX/root/sys/class/net/enP7s7/statistics" "$FX/root/sys/class/net/enP7s7/device" \
    "$FX/root/sys/class/net/lo/statistics" "$FX/root/sys/class/net/veth0/statistics" \
    "$FX/root/sys/class/dmi/id" "$FX/root/proc/sys/kernel"
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
  printf '[connection]\nid=mgmt-enP7s7\ninterface-name=enP7s7\n[802-3-ethernet]\n' \
    > "$FX/root/etc/NetworkManager/system-connections/mgmt-enP7s7.nmconnection"
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
run_screen() { # [iterations] [interval] [extra env...] -> stdout stripped of ANSI, serial in $FX/serial
  local iterations=${1:-1} interval=${2:-0}; shift 2 || true
  : > "$FX/serial"
  env NI_STATUS_SCREEN_TESTING=1 NI_STATUS_TEST_ROOT="$FX/root" NI_STATUS_TEST_SYSTEMCTL="$TOOLS/systemctl" \
    NI_STATUS_TEST_IP="$TOOLS/ip" NI_STATUS_TEST_ITERATIONS="$iterations" NI_STATUS_TEST_INTERVAL="$interval" \
    NI_STATUS_TEST_SERIAL="$FX/serial" NI_TEST_SCENE="$FX/scene" NI_TEST_IPV4="$FX/ipv4" "$@" \
    bash "$SCRIPT" | sed 's/\x1b\[[0-9;?]*[A-Za-z]//g'
}
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
serial="$(<"$FX/serial")"
expect "$serial" 'neural-ice-status: Neural ICE CoreOS | OS 0.51.11 | image deploy ab0000000000 | channel beta-debug' "serial header"
expect "$serial" 'neural-ice-status: model NVIDIA DGX Spark | serial SN-1234-5678' "serial identity"
expect "$serial" 'neural-ice-status: [ .. ] Device trust: TPM owner ceremony running' "serial phase line"
expect "$serial" 'neural-ice-status: [ .. ] Images: 1/2 present' "serial image counter"
reject "$serial" 'RX ' "serial mirror never carries the volatile rate"
[[ "$(grep -c 'neural-ice-status: ' "$FX/serial")" -eq 7 ]] || fail "serial mirror should print header(2) + five phases once: $serial"

# 3b. serial lines are emitted on CHANGE only; the redraw never repeats them.
out="$(run_screen 3 0)"
[[ "$(grep -c 'neural-ice-status: ' "$FX/serial")" -eq 7 ]] || fail "unchanged phases were re-mirrored to serial"

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
expect "$(<"$FX/serial")" 'neural-ice-status: READY -- login available' "serial READY marker for the QEMU harness"

# 3e. a tty1 owner is active -> exit immediately, draw nothing.
set_state 'getty@tty1.service' loaded active running
out="$(run_screen 5 0)"
[[ -z $out ]] || fail "status screen must leave tty1 alone once getty owns it: $out"
set_state 'getty@tty1.service' loaded inactive dead
set_state neural-ice-tui.service loaded active running
out="$(run_screen 5 0)"
[[ -z $out ]] || fail "status screen must leave tty1 alone once the product TUI owns it: $out"

# 3f. failure block: stable code, unit, serial, instruction; earliest phase wins.
make_fixture
set_state neural-ice-firstboot-tpm-ceremony.service loaded failed failed
out="$(run_screen)"
expect "$out" 'FAILURE  NI-E02  (TPM ceremony)' "ceremony failure code"
expect "$out" 'unit:    neural-ice-firstboot-tpm-ceremony.service' "failing unit named"
expect "$out" 'serial:  SN-1234-5678' "serial in the failure block"
expect "$out" 'Contact Neural ICE support with this code and serial.' "support instruction"
reject "$out" 'READY' "no READY on failure"
expect "$(<"$FX/serial")" 'neural-ice-status: FAILURE NI-E02 (TPM ceremony) unit=neural-ice-firstboot-tpm-ceremony.service serial=SN-1234-5678' "serial failure marker"
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

echo "STATUS_SCREEN_OFFLINE_TEST_OK (unit contract, secret allow-list, 9 behaviour scenes)"
