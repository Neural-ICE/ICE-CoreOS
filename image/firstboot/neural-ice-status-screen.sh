#!/usr/bin/env bash
# Neural ICE CoreOS -- non-interactive boot status screen on tty1.
#
# WHY. A sealed appliance boots with `quiet`, masks every getty/serial-getty/sshd
# and holds the network until the TPM owner ceremony has completed. Until then
# the operator sees a black screen with a blinking cursor for minutes, and after
# installation the customer (or the partner doing the RMA) has no way to tell a
# slow first boot from a dead box. This screen answers "what is happening" and,
# on failure, prints ONE stable code plus the chassis serial so support can be
# called without SSH (product decision, Thomas, 2026-09-04).
#
# WHAT IT IS NOT. It is not a shell, it reads no input, and it prints no secret:
# no recovery key, no LUKS/TPM material, no licence, no token, no fingerprint.
# The only identity shown is what is already printed on the chassis label (DMI
# model + serial), the hostname, the OS version and the booted image's short
# digest. image/test-status-screen.sh asserts, statically, that this file reads
# nothing outside the allow-list at the bottom of this header.
#
# HOW. A plain bash loop. Every second it asks systemd (`systemctl show`) for
# the state of a FIXED list of units, counts the product images present in
# containers-storage against the images the image declares, derives the
# management NIC's receive rate from /sys/class/net/*/statistics/rx_bytes deltas
# and redraws the whole screen. It exits by itself when the box is READY or as
# soon as the unit that owns tty1 (getty@tty1 on the debug variant, the product
# TUI on the branded appliance) is active. Error codes: status-error-codes.md.
#
# Paths this script reads (the static test enforces this list):
#   /usr/lib/os-release                       product name
#   /usr/lib/neural-ice/version               OS version (CI, run-unique)
#   /usr/lib/neural-ice/status-screen/        core-services list extension
#   /usr/lib/bootc/bound-images.d/            image inventory (bound images)
#   /usr/share/containers/systemd/            image inventory (Quadlets)
#   /etc/containers/systemd/                  image inventory (Quadlets)
#   /etc/NetworkManager/system-connections/   mgmt-*.nmconnection, interface-name= ONLY
#   /etc/neural-ice/ota.conf                  device_channel= fallback
#   /var/lib/neural-ice/data/release/CHANNEL  device channel
#   /var/lib/neural-ice/data/seed-store/current/overlay-images/images.json
#   /var/lib/containers/storage/overlay-images/images.json
#   /sys/class/net/                           operstate, device, statistics/rx_bytes
#   /sys/class/dmi/id/                        sys_vendor, product_name, product_serial
#   /proc/cmdline                             ostree= deployment (version fallback)
#   /proc/sys/kernel/hostname
set -euo pipefail

die() { printf 'neural-ice-status-screen: %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Test seam. Only an unprivileged process, only outside a release image, may
# redirect the filesystem or substitute the tools. Root always uses production
# paths and tools (same rule as neural-ice-seed-import.sh).
# ---------------------------------------------------------------------------
ROOT_PREFIX=""
SYSTEMCTL=systemctl
IP_TOOL=ip
BOOTC_TOOL=bootc
INTERVAL=1
MAX_ITERATIONS=0        # 0 = until READY / tty1 owner / signal
if [[ ${NI_STATUS_SCREEN_TESTING:-0} != 0 ]]; then
  [[ $EUID -ne 0 ]] || die "the test seam is forbidden to root"
  [[ ! -e /usr/lib/neural-ice/release-image ]] || die "the test seam is forbidden in a release image"
  [[ -n ${NI_STATUS_TEST_ROOT:-} && ${NI_STATUS_TEST_ROOT:0:1} == / ]] || die "test root must be absolute"
  ROOT_PREFIX=${NI_STATUS_TEST_ROOT%/}
  SYSTEMCTL=${NI_STATUS_TEST_SYSTEMCTL:?}
  IP_TOOL=${NI_STATUS_TEST_IP:-false}
  BOOTC_TOOL=${NI_STATUS_TEST_BOOTC:-false}
  INTERVAL=${NI_STATUS_TEST_INTERVAL:-0}
  MAX_ITERATIONS=${NI_STATUS_TEST_ITERATIONS:-1}
fi
path() { printf '%s%s' "$ROOT_PREFIX" "$1"; }

# Seconds the TPM owner ceremony may stay `activating` before the screen shows
# NI-E02. The first boot legitimately takes minutes (TPM provisioning, seed
# import); the unit sets the default, a drop-in may override it.
CEREMONY_TIMEOUT=${NI_STATUS_CEREMONY_TIMEOUT:-1800}
[[ $CEREMONY_TIMEOUT =~ ^[0-9]+$ ]] || die "NI_STATUS_CEREMONY_TIMEOUT must be an integer number of seconds"
# Seconds READY stays on screen before the script exits on its own when no
# tty1 owner shows up (branded appliance: the TUI replaces us earlier).
READY_LINGER=${NI_STATUS_READY_LINGER:-10}
[[ $READY_LINGER =~ ^[0-9]+$ ]] || die "NI_STATUS_READY_LINGER must be an integer number of seconds"

# ---------------------------------------------------------------------------
# Watched units. FIXED: the screen never takes unit names from anything that
# is not part of the image.
# ---------------------------------------------------------------------------
UNIT_STORAGE='systemd-cryptsetup@data.service'      # the "data" volume of the disk encryption table (nofail)
UNIT_DATA_MOUNT='var-lib-neural\x2dice-data.mount'
UNIT_CEREMONY='neural-ice-firstboot-tpm-ceremony.service'
UNIT_NETWORK='NetworkManager.service'
UNIT_SEED_IMPORT='neural-ice-seed-import.service'
UNIT_PAYLOAD='neural-ice-payload-apply.service'
# tty1 owners: the login getty (debug variant) or the product console dashboard
# (branded appliance, ICE-Fabric neural-ice-tui.service). Either one active
# means the screen is no longer ours.
TTY1_OWNERS=('getty@tty1.service' 'neural-ice-tui.service')
# Core services shipped by this OS. The branded derivation appends its product
# units through /usr/lib/neural-ice/status-screen/core-services (one unit per
# line, `#` comments) -- the OS stays free of product knowledge (ADR-0032).
CORE_SERVICES=(
  neural-ice-hostname-init.service
  neural-ice-device-root.service
  neural-ice-payload-apply.service
  avahi-daemon.service
)
core_services_dir=$(path /usr/lib/neural-ice/status-screen)
if [[ -f $core_services_dir/core-services && ! -L $core_services_dir/core-services ]]; then
  while IFS= read -r line; do
    line=${line%%#*}; line=${line//[[:space:]]/}
    [[ -n $line ]] || continue
    [[ $line =~ ^[A-Za-z0-9@._:\\-]+\.(service|target|mount|socket)$ ]] || continue
    CORE_SERVICES+=("$line")
  done < "$core_services_dir/core-services"
fi

# ---------------------------------------------------------------------------
# systemd state, one query per unit per poll. `systemctl show` answers over the
# private manager socket, so it works before D-Bus and needs no dbus edge.
# ---------------------------------------------------------------------------
declare -A U_LOAD U_ACTIVE U_SUB U_CONDTS U_CONDRES
query_unit() { # <unit>
  local unit=$1 out key value
  U_LOAD[$unit]=unknown; U_ACTIVE[$unit]=unknown; U_SUB[$unit]=""
  U_CONDTS[$unit]=0; U_CONDRES[$unit]=no
  out=$("$SYSTEMCTL" show -p LoadState,ActiveState,SubState,ConditionTimestampMonotonic,ConditionResult -- "$unit" 2>/dev/null) || return 0
  while IFS='=' read -r key value; do
    case $key in
      LoadState) U_LOAD[$unit]=$value ;;
      ActiveState) U_ACTIVE[$unit]=$value ;;
      SubState) U_SUB[$unit]=$value ;;
      ConditionTimestampMonotonic) U_CONDTS[$unit]=${value:-0} ;;
      ConditionResult) U_CONDRES[$unit]=${value:-no} ;;
    esac
  done <<<"$out"
}
unit_absent() { [[ ${U_LOAD[$1]} == not-found || ${U_LOAD[$1]} == unknown ]]; }
unit_skipped() { # a unit whose Condition*= was evaluated and said no
  [[ ${U_ACTIVE[$1]} == inactive && ${U_CONDTS[$1]} != 0 && ${U_CONDRES[$1]} == no ]]
}
unit_failed() { [[ ${U_ACTIVE[$1]} == failed ]]; }
unit_active() { [[ ${U_ACTIVE[$1]} == active ]]; }

# ---------------------------------------------------------------------------
# Identity header. Nothing here is secret: the DMI model and serial are on the
# chassis label, the hostname is broadcast over mDNS, the version and short
# image digest identify the software for support.
# ---------------------------------------------------------------------------
read_first_line() { # <file> -> first line or ""
  local f=$1 line=""
  [[ -f $f && ! -L $f && -r $f ]] || { printf ''; return 0; }
  IFS= read -r line < "$f" || true
  printf '%s' "$line"
}
sanitize() { # printable ASCII only, one line, bounded length
  local s=$1
  s=${s//[^[:print:]]/}
  printf '%s' "${s:0:${2:-64}}"
}
product_name() {
  local name
  name=$(sed -n 's/^PRETTY_NAME="\{0,1\}\([^"]*\)"\{0,1\}$/\1/p' "$(path /usr/lib/os-release)" 2>/dev/null | head -1)
  sanitize "${name:-Neural ICE CoreOS}" 48
}
os_version() {
  local v
  v=$(read_first_line "$(path /usr/lib/neural-ice/version)")
  sanitize "${v:-unknown}" 32
}
booted_image_short() {
  # Preferred: the digest of the booted bootc image. Fallback: the ostree
  # deployment checksum from the kernel command line. Twelve hex either way.
  local json digest
  if json=$(timeout 15 "$BOOTC_TOOL" status --format=json 2>/dev/null); then
    digest=$(grep -oE '"imageDigest": *"sha256:[0-9a-f]{64}"' <<<"$json" | head -1 | grep -oE '[0-9a-f]{64}')
    if [[ -n $digest ]]; then printf '%s' "${digest:0:12}"; return 0; fi
  fi
  digest=$(grep -oE '(^| )ostree=[^ ]*/([0-9a-f]{64})/' "$(path /proc/cmdline)" 2>/dev/null | grep -oE '[0-9a-f]{64}' | head -1)
  if [[ -n $digest ]]; then printf 'deploy %s' "${digest:0:12}"; return 0; fi
  printf 'unknown'
}
device_channel() {
  local c
  c=$(read_first_line "$(path /var/lib/neural-ice/data/release/CHANNEL)")
  if [[ -z $c ]]; then
    c=$(sed -n 's/^device_channel=//p' "$(path /etc/neural-ice/ota.conf)" 2>/dev/null | head -1)
  fi
  sanitize "${c:-unset}" 24
}
dmi() { sanitize "$(read_first_line "$(path /sys/class/dmi/id/"$1")")" "${2:-40}"; }
hostname_now() { sanitize "$(read_first_line "$(path /proc/sys/kernel/hostname)")" 40; }

# ---------------------------------------------------------------------------
# Network: the management NIC, resolved exactly like neural-ice-hostname-init
# (the interface-name pinned in mgmt-*.nmconnection, else the on-board enP<d>s<d>
# port without a PCIe function suffix); receive rate from rx_bytes deltas.
# ---------------------------------------------------------------------------
SYS_NET=$(path /sys/class/net)
NM_CONN_DIR=$(path /etc/NetworkManager/system-connections)
mgmt_interface() {
  local conn iface cand name
  for conn in "$NM_CONN_DIR"/mgmt-*.nmconnection; do
    [[ -e $conn ]] || continue
    iface=$(sed -n 's/^interface-name=//p' "$conn" | head -1)
    if [[ -n $iface ]]; then printf '%s' "$iface"; return 0; fi
  done
  for cand in "$SYS_NET"/enP*s*; do
    [[ -e $cand ]] || continue
    name=${cand##*/}
    [[ $name =~ f[0-9] ]] && continue
    printf '%s' "$name"; return 0
  done
  return 1
}
# Sum of rx_bytes over every physical (non-loopback, non-virtual) interface;
# the management NIC first when it is known. Pull traffic may enter through a
# ConnectX port on a bench, so the total is not pinned to one port.
rx_bytes_total() {
  local dev total=0 n
  for dev in "$SYS_NET"/*; do
    [[ -e $dev/device ]] || continue                 # virtual interfaces have no device link
    [[ -r $dev/statistics/rx_bytes ]] || continue
    IFS= read -r n < "$dev/statistics/rx_bytes" || continue
    [[ $n =~ ^[0-9]+$ ]] || continue
    total=$((total + n))
  done
  printf '%s' "$total"
}
iface_operstate() { read_first_line "$SYS_NET/$1/operstate"; }
iface_ipv4() { # first IPv4 address of <iface>, "" if none / tool missing
  local out
  out=$("$IP_TOOL" -4 -o addr show dev "$1" 2>/dev/null) || { printf ''; return 0; }
  awk '$3 == "inet" { print $4; exit }' <<<"$out"
}
fmt_bytes() { # <integer bytes> -> "12.3 MB"
  local b=$1 unit=B div=1
  if   (( b >= 1000000000 )); then unit=GB; div=1000000000
  elif (( b >= 1000000 ));    then unit=MB; div=1000000
  elif (( b >= 1000 ));       then unit=KB; div=1000
  fi
  if [[ $unit == B ]]; then printf '%d B' "$b"; return 0; fi
  printf '%d.%d %s' $((b / div)) $(( (b % div) * 10 / div )) "$unit"
}
now_ms() { local t=${EPOCHREALTIME/./}; printf '%s' "${t:0:-3}"; }
fmt_duration() { # <seconds> -> "2m13s"
  local s=$1
  if (( s >= 3600 )); then printf '%dh%02dm' $((s / 3600)) $(((s % 3600) / 60))
  elif (( s >= 60 )); then printf '%dm%02ds' $((s / 60)) $((s % 60))
  else printf '%ds' "$s"; fi
}

# ---------------------------------------------------------------------------
# Images: M = distinct `Image=` references the image declares (bound images
# and Quadlets), N = how many of them are present in containers-storage
# (graphroot or the read-only seed store), judged on digest when pinned.
# ---------------------------------------------------------------------------
declare -A IMAGE_REFS=()
collect_image_refs() {
  local f ref
  IMAGE_REFS=()
  while IFS= read -r -d '' f; do
    while IFS= read -r ref; do
      ref=${ref#Image=}; ref=${ref//[[:space:]]/}
      [[ -n $ref && $ref != *.image ]] || continue      # `Image=foo.image` is an indirection, not a ref
      IMAGE_REFS[$ref]=1
    done < <(grep -h '^Image=' "$f" 2>/dev/null || true)
  done < <(find -L "$(path /usr/lib/bootc/bound-images.d)" \
                   "$(path /usr/share/containers/systemd)" "$(path /etc/containers/systemd)" \
                   -maxdepth 3 -type f \( -name '*.image' -o -name '*.container' \) -print0 2>/dev/null || true)
}
STORAGE_INDEXES=(
  "$(path /var/lib/containers/storage/overlay-images/images.json)"
  "$(path /var/lib/neural-ice/data/seed-store/current/overlay-images/images.json)"
)
image_present() { # <ref>
  local ref=$1 needle idx
  if [[ $ref =~ @(sha256:[0-9a-f]{64})$ ]]; then needle="\"${BASH_REMATCH[1]}\""; else needle="\"$ref\""; fi
  for idx in "${STORAGE_INDEXES[@]}"; do
    [[ -r $idx ]] || continue
    grep -Fq -- "$needle" "$idx" && return 0
  done
  return 1
}
count_images() { # -> "N M"
  local ref present=0
  for ref in "${!IMAGE_REFS[@]}"; do image_present "$ref" && present=$((present + 1)); done
  printf '%d %d' "$present" "${#IMAGE_REFS[@]}"
}

# ---------------------------------------------------------------------------
# Screen.
# ---------------------------------------------------------------------------
ESC=$'\033'
cursor_hide() { printf '%s[?25l' "$ESC"; }
cursor_show() { printf '%s[?25h' "$ESC"; }
clear_screen() { printf '%s[H%s[2J' "$ESC" "$ESC"; }
FRAME=""
line() { FRAME+="$*${ESC}[K"$'\n'; }
mark() { # <ok|run|wait|fail|skip> -> "[ok] "
  case $1 in
    ok)   printf '[ OK ]' ;;
    run)  printf '[ .. ]' ;;
    wait) printf '[    ]' ;;
    fail) printf '[FAIL]' ;;
    skip) printf '[ -- ]' ;;
  esac
}
flush_frame() { printf '%s[H%s%s[J' "$ESC" "$FRAME" "$ESC"; FRAME=""; }

# ---------------------------------------------------------------------------
# Serial mirror. The headless QEMU harness (image/qualify-installer-qemu.sh)
# captures the serial console, so every phase line is ALSO written there -- as
# plain `neural-ice-status: ...` lines, once per CHANGE (never the per-second
# redraw, never the volatile rate/elapsed part), so `--expect` can match them.
# Serial writes go through `timeout`: opening a serial port with no carrier or
# with hardware flow control and no peer can block, and this screen must never
# hang on a wire nobody is listening to. The first failed write disables the
# mirror for the rest of the boot.
# ---------------------------------------------------------------------------
SERIAL_DEV=""
if [[ ${NI_STATUS_SCREEN_TESTING:-0} != 0 ]]; then
  SERIAL_DEV=${NI_STATUS_TEST_SERIAL:-}
else
  for dev in /dev/ttyAMA0 /dev/ttyS0; do
    if [[ -c $dev ]]; then SERIAL_DEV=$dev; break; fi
  done
fi
declare -A MIRROR_LAST=()
mirror() { # <key> <text>: write "neural-ice-status: <text>" to serial when it changed
  local key=$1 text=$2
  [[ -n $SERIAL_DEV ]] || return 0
  [[ ${MIRROR_LAST[$key]:-} != "$text" ]] || return 0
  MIRROR_LAST[$key]=$text
  # shellcheck disable=SC2016 # $1/$2 are the child shell's positional parameters
  if ! timeout 2 bash -c 'printf "neural-ice-status: %s\r\n" "$1" >> "$2"' _ "$text" "$SERIAL_DEV" 2>/dev/null; then
    SERIAL_DEV=""
  fi
}

finish() { cursor_show; printf '\n'; }
trap 'finish; exit 0' TERM INT HUP
# First failure wins: the code shown is the earliest phase that broke.
set_failure() { [[ -n $fail_code ]] || { fail_code=$1; fail_what=$2; fail_unit=$3; }; }

# Static identity, read once.
PRODUCT=$(product_name)
VERSION=$(os_version)
IMAGE=$(booted_image_short)
CHANNEL=$(device_channel)
MODEL="$(dmi sys_vendor 24) $(dmi product_name 32)"
SERIAL=$(dmi product_serial 40)
[[ -n ${SERIAL// /} ]] || SERIAL="unknown"

START_MS=$(now_ms)
RX_BASE=$(rx_bytes_total)
RX_PREV=$RX_BASE
RX_PREV_MS=$START_MS
RATE_BPS=0
CEREMONY_SEEN_RUNNING=0     # $SECONDS when first seen activating (0 = not yet)
READY_SINCE=0
iteration=0

while :; do
  iteration=$((iteration + 1))
  for u in "$UNIT_STORAGE" "$UNIT_DATA_MOUNT" "$UNIT_CEREMONY" "$UNIT_NETWORK" \
           "$UNIT_SEED_IMPORT" "$UNIT_PAYLOAD" "${TTY1_OWNERS[@]}" "${CORE_SERVICES[@]}"; do
    query_unit "$u"
  done

  # Someone else owns tty1 now: leave quietly, whatever the state. Checked
  # BEFORE the first draw so a fast reboot never scribbles over a login prompt
  # or the product TUI that already took the screen.
  for u in "${TTY1_OWNERS[@]}"; do
    if unit_active "$u"; then (( iteration > 1 )) && finish; exit 0; fi
  done
  if (( iteration == 1 )); then cursor_hide; clear_screen; fi

  fail_code=""; fail_what=""; fail_unit=""

  # --- storage ------------------------------------------------------------
  if unit_failed "$UNIT_STORAGE" || unit_failed "$UNIT_DATA_MOUNT"; then
    storage_mark=fail; storage_text="data volume could not be unlocked"
    unit_failed "$UNIT_STORAGE" && set_failure NI-E01 "storage unlock" "$UNIT_STORAGE"
    unit_failed "$UNIT_DATA_MOUNT" && set_failure NI-E01 "storage unlock" "$UNIT_DATA_MOUNT"
  elif unit_absent "$UNIT_STORAGE"; then
    storage_mark=ok; storage_text="system volume unlocked (no separate data volume)"
  elif unit_active "$UNIT_STORAGE" && { unit_active "$UNIT_DATA_MOUNT" || unit_absent "$UNIT_DATA_MOUNT"; }; then
    storage_mark=ok; storage_text="system and data volumes unlocked"
  elif unit_active "$UNIT_STORAGE"; then
    storage_mark=run; storage_text="data volume unlocked, mounting"
  else
    storage_mark=run; storage_text="unlocking data volume (${U_SUB[$UNIT_STORAGE]:-waiting})"
  fi

  # --- device trust (TPM owner ceremony) ----------------------------------
  # *_text is the STABLE phase text (mirrored to serial on change); *_extra is
  # the volatile part (elapsed time, receive rate) shown on tty1 only.
  ceremony_done=0; trust_extra=""
  if unit_failed "$UNIT_CEREMONY"; then
    trust_mark=fail; trust_text="TPM owner ceremony failed"
    set_failure NI-E02 "TPM ceremony" "$UNIT_CEREMONY"
  elif unit_active "$UNIT_CEREMONY"; then
    trust_mark=ok; trust_text="device trust: sealed"; ceremony_done=1
  elif unit_absent "$UNIT_CEREMONY"; then
    trust_mark=skip; trust_text="no TPM ceremony on this image"; ceremony_done=1
  else
    (( CEREMONY_SEEN_RUNNING > 0 )) || CEREMONY_SEEN_RUNNING=$((SECONDS + 1))
    elapsed=$((SECONDS + 1 - CEREMONY_SEEN_RUNNING))
    trust_extra="($(fmt_duration "$elapsed"))"
    if (( elapsed >= CEREMONY_TIMEOUT )); then
      trust_mark=fail; trust_text="TPM owner ceremony still running after timeout"
      set_failure NI-E02 "TPM ceremony timeout" "$UNIT_CEREMONY"
    else
      trust_mark=run; trust_text="TPM owner ceremony running -- first boot takes several minutes"
    fi
  fi

  # --- network --------------------------------------------------------------
  now=$(now_ms)
  rx_now=$(rx_bytes_total)
  dt=$((now - RX_PREV_MS))
  if (( dt >= 500 )); then
    (( rx_now >= RX_PREV )) && RATE_BPS=$(( (rx_now - RX_PREV) * 1000 / dt )) || RATE_BPS=0
    RX_PREV=$rx_now; RX_PREV_MS=$now
  fi
  rx_total=$(( rx_now >= RX_BASE ? rx_now - RX_BASE : 0 ))
  rx_text="RX $(fmt_bytes "$RATE_BPS")/s  $(fmt_bytes "$rx_total") total"
  iface=$(mgmt_interface || true)
  net_extra=$rx_text
  if unit_failed "$UNIT_NETWORK"; then
    net_mark=fail; net_text="network manager failed"
    set_failure NI-E03 "network" "$UNIT_NETWORK"
  elif [[ -z $iface ]]; then
    net_mark="wait"; net_text="no management interface found"
  else
    oper=$(iface_operstate "$iface")
    addr=$(iface_ipv4 "$iface")
    if [[ $oper == up && -n $addr ]]; then
      net_mark=ok; net_text="$iface up ${addr%%/*}"
    elif [[ $oper == up ]]; then
      net_mark=run; net_text="$iface link up, waiting for address"
    elif unit_active "$UNIT_NETWORK" || [[ ${U_ACTIVE[$UNIT_NETWORK]} == activating ]]; then
      net_mark=run; net_text="$iface ${oper:-unknown}"
    else
      net_mark="wait"; net_text="$iface ${oper:-unknown} (network held until device trust)"
    fi
  fi

  # --- images ---------------------------------------------------------------
  collect_image_refs
  read -r img_present img_total <<<"$(count_images)"
  images_done=0; img_extra=""
  if unit_failed "$UNIT_SEED_IMPORT" || unit_failed "$UNIT_PAYLOAD"; then
    img_mark=fail; img_text="$img_present/$img_total present -- image import failed"
    unit_failed "$UNIT_SEED_IMPORT" && set_failure NI-E04 "image pull" "$UNIT_SEED_IMPORT"
    unit_failed "$UNIT_PAYLOAD" && set_failure NI-E04 "image pull" "$UNIT_PAYLOAD"
  elif (( img_total == 0 )); then
    img_mark=skip; img_text="no product image inventory on this image"; images_done=1
  elif (( img_present >= img_total )); then
    img_mark=ok; img_text="$img_present/$img_total present"; images_done=1
  else
    img_mark=run; img_text="$img_present/$img_total present"; img_extra=$rx_text
  fi

  # --- core services --------------------------------------------------------
  core_total=0; core_ok=0; core_failed=""
  for u in "${CORE_SERVICES[@]}"; do
    unit_absent "$u" && continue
    core_total=$((core_total + 1))
    if unit_failed "$u"; then core_failed+=" ${u}"
    elif unit_active "$u" || unit_skipped "$u"; then core_ok=$((core_ok + 1)); fi
  done
  if [[ -n $core_failed ]]; then
    core_mark=fail; core_text="$core_ok/$core_total active -- failed:${core_failed}"
    set_failure NI-E05 "core service" "${core_failed# }"
  elif (( core_total == 0 )); then
    core_mark=skip; core_text="no core services declared"
  elif (( core_ok >= core_total )); then
    core_mark=ok; core_text="$core_ok/$core_total active"
  else
    core_mark=run; core_text="$core_ok/$core_total active"
  fi
  core_done=$(( core_ok >= core_total ? 1 : 0 ))

  # --- ready ------------------------------------------------------------------
  network_done=0
  { [[ $net_mark == ok ]] || unit_absent "$UNIT_NETWORK"; } && network_done=1
  ready=0
  if [[ -z $fail_code ]] && (( ceremony_done && network_done && images_done && core_done )); then
    ready=1
    (( READY_SINCE > 0 )) || READY_SINCE=$((SECONDS + 1))
  else
    READY_SINCE=0
  fi

  # --- serial mirror (stable lines only, on change) ---------------------------
  if (( iteration == 1 )); then
    mirror header "$PRODUCT | OS $VERSION | image $IMAGE | channel $CHANNEL"
    mirror identity "model $MODEL | serial $SERIAL"
  fi
  mirror storage "$(mark "$storage_mark") Storage: $storage_text"
  mirror trust "$(mark "$trust_mark") Device trust: $trust_text"
  mirror network "$(mark "$net_mark") Network: $net_text"
  mirror images "$(mark "$img_mark") Images: $img_text"
  mirror core "$(mark "$core_mark") Core services: $core_text"
  if [[ -n $fail_code ]]; then
    mirror verdict "FAILURE $fail_code ($fail_what) unit=$fail_unit serial=$SERIAL -- contact Neural ICE support with this code and serial"
  elif (( ready )); then
    mirror verdict "READY -- login available"
  fi

  # --- draw -------------------------------------------------------------------
  uptime_s=$(( ($(now_ms) - START_MS) / 1000 ))
  line " NEURAL ICE   $PRODUCT"
  line " OS $VERSION   image $IMAGE   channel $CHANNEL"
  line " Model $MODEL   Serial $SERIAL   Host $(hostname_now)"
  line " ------------------------------------------------------------------------------"
  line " $(mark "$storage_mark")  Storage         $storage_text"
  line " $(mark "$trust_mark")  Device trust    $trust_text ${trust_extra}"
  line " $(mark "$net_mark")  Network         $net_text  ${net_extra}"
  line " $(mark "$img_mark")  Images          $img_text  ${img_extra}"
  line " $(mark "$core_mark")  Core services   $core_text"
  line " ------------------------------------------------------------------------------"
  if [[ -n $fail_code ]]; then
    line ""
    line " ##############################################################################"
    line " #  FAILURE  $fail_code  ($fail_what)"
    line " #  unit:    $fail_unit"
    line " #  serial:  $SERIAL"
    line " #  Contact Neural ICE support with this code and serial."
    line " ##############################################################################"
  elif (( ready )); then
    line ""
    line " READY -- login available.  ($(fmt_duration "$uptime_s"))"
  else
    line " Starting... $(fmt_duration "$uptime_s")   This screen is informational only; no input is read."
  fi
  flush_frame

  if (( ready )) && (( SECONDS + 1 - READY_SINCE >= READY_LINGER )); then break; fi
  if (( MAX_ITERATIONS > 0 && iteration >= MAX_ITERATIONS )); then break; fi
  sleep "$INTERVAL" &
  wait $! || true
done
finish
exit 0
