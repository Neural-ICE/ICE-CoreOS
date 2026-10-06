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
# PRODUCT DECLARATIONS. The OS carries no product knowledge (ADR-0032). A branded
# derivation tells this screen what its product needs through declaration files
# /usr/lib/neural-ice/status-screen.d/*.conf (closed key=value grammar, parsed
# and refused by decl_parse below, documented in status-error-codes.md): the
# units of its image phase, the signed manifest that lists its components (and
# how to read it), and extra core units. A declaration that names an image
# manifest switches the Images line from the v1 inventory (Quadlet/bound-image
# references of the OS image) to "components of that manifest present in
# containers-storage / components of the manifest", keeps the screen running
# until the declared image units are themselves done, shows the manifest's
# release id instead of the v1 channel (when the declaration names the key) and
# no longer watches the OS's own v1 image units. The screen only DISPLAYS the
# manifest: it never verifies it. A refused declaration is a status fault
# (NI-E06), never silently ignored. No directory = the v1 code paths, unchanged.
#
# Paths this script reads (the static test enforces this list):
#   /usr/lib/os-release                       product name
#   /usr/lib/neural-ice/version               OS version (CI, run-unique)
#   /usr/lib/neural-ice/status-screen/        core-services list extension
#   /usr/lib/neural-ice/status-screen.d/      product declarations (*.conf)
#   the one file a declaration names as its image manifest (images_manifest=,
#     regular file, under /var/lib, /usr/lib or /usr/share)
#   /usr/lib/bootc/bound-images.d/            image inventory (bound images)
#   /usr/share/containers/systemd/            image inventory (Quadlets)
#   /etc/containers/systemd/                  image inventory (Quadlets)
#   /run/neural-ice/mgmt-interface            management port, published by hostname-init
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
# Small readers, shared by the identity header and the declaration parser.
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

# ---------------------------------------------------------------------------
# Product declarations: /usr/lib/neural-ice/status-screen.d/*.conf. The grammar
# is closed (status-error-codes.md is its reference):
#   - the directory and every *.conf in it: root-owned, a regular file (never a
#     symlink), not group/world-writable; at most DECL_MAX_FILES files of at most
#     DECL_MAX_BYTES bytes, printable ASCII only. Other names are ignored (as
#     systemd drop-ins are);
#   - lines: blank, `# comment`, or `key=value` (no space around `=`, no key
#     twice, no key outside the list below);
#   - version=1 is required; images_* keys come all together (images_release_key
#     optional) in ONE file; core_units= may be spread over files.
# A file that breaks any rule contributes NOTHING and is reported (NI-E06): the
# screen never half-applies a declaration and never guesses what was meant.
# Values name units, a path and manifest keys; the screen reads the one manifest
# file as text (bash and grep only), never executes it, and prints only the
# release id, character-checked and bounded.
# ---------------------------------------------------------------------------
DECL_DIR=$(path /usr/lib/neural-ice/status-screen.d)
DECL_MAX_FILES=16
DECL_MAX_BYTES=4096
DECL_PATH_ROOTS=(var/lib usr/lib usr/share)     # a declared path sits under one of these (relative to /)
DECL_UID=0; [[ ${NI_STATUS_SCREEN_TESTING:-0} == 0 ]] || DECL_UID=$EUID
DECL_UNIT_RE='^[A-Za-z0-9@._:\\-]{1,200}\.(service|target|mount|socket)$'
DECL_IMG_UNIT_RE='^[A-Za-z0-9@._:-]{1,200}\.service$'
DECL_JSON_KEY_RE='^[a-z][a-z0-9_]{0,31}$'
DECL_ALIAS_RE='^[a-z0-9._/:-]*\{id\}[a-z0-9._/:-]*$'
declare -a DECL_FAULTS=() DECL_CORE=() DECL_IMG_UNITS=()
DECL_IMG_FILE=""; DECL_MANIFEST=""; DECL_COMP_KEY=""; DECL_DIGEST_KEY=""; DECL_ALIAS=""; DECL_RELEASE_KEY=""

decl_fault() { DECL_FAULTS+=("$(sanitize "$1" 40)|$(sanitize "$2" 40)"); }   # <file> <why>
decl_owner_ok() { # <path>: owned by the expected uid, not writable by group/others
  local uid mode
  read -r uid mode < <(stat -c '%u %a' -- "$1" 2>/dev/null) || return 1
  [[ $uid == "$DECL_UID" && $mode =~ ^[0-7]{3,4}$ ]] || return 1
  (( (8#$mode & 8#022) == 0 ))
}
decl_unit_list() { # <list> <max> <regex>: single-space separated, 1..max names, each matching the regex, no repeat
  local -a items; local u; local -A dup=()
  [[ -n $1 && $1 != ' '* && $1 != *' ' && $1 != *'  '* ]] || return 1
  IFS=' ' read -ra items <<<"$1"
  (( ${#items[@]} <= $2 )) || return 1
  for u in "${items[@]}"; do
    [[ $u =~ $3 && -z ${dup[$u]:-} ]] || return 1
    dup[$u]=1
  done
}
decl_path_ok() { # <path>: absolute, bounded, plain components, under an allowed root
  local p=$1 root
  [[ ${#p} -le 200 && $p =~ ^/[A-Za-z0-9._/-]*[A-Za-z0-9_-]$ ]] || return 1
  [[ $p != *//* && $p != */./* && $p != */../* && $p != */.. && $p != */. ]] || return 1
  for root in "${DECL_PATH_ROOTS[@]}"; do [[ $p == /"$root"/* ]] && return 0; done
  return 1
}
decl_parse() { # <file> <name>: parse one declaration; its facts are committed only when all of it is valid
  local f=$1 name=$2 line key value lineno=0 k u
  local -a core_items
  local -A seen=()
  local d_version="" d_units="" d_manifest="" d_comp="" d_digest="" d_alias="" d_release="" d_core=""
  while IFS= read -r line || [[ -n $line ]]; do
    lineno=$((lineno + 1))
    [[ -n $line && $line != '#'* ]] || continue
    if [[ ! $line =~ ^([a-z][a-z0-9_]{0,31})=([^[:space:]].*)$ ]]; then decl_fault "$name" "line $lineno is not key=value"; return 0; fi
    key=${BASH_REMATCH[1]}; value=${BASH_REMATCH[2]}
    if [[ -n ${seen[$key]:-} ]]; then decl_fault "$name" "key $key given twice"; return 0; fi
    seen[$key]=1
    case $key in
      version) d_version=$value ;;
      images_units)
        decl_unit_list "$value" 8 "$DECL_IMG_UNIT_RE" || { decl_fault "$name" "bad images_units"; return 0; }
        d_units=$value ;;
      images_manifest)
        decl_path_ok "$value" || { decl_fault "$name" "bad images_manifest"; return 0; }
        d_manifest=$value ;;
      images_component_key)
        [[ $value =~ $DECL_JSON_KEY_RE ]] || { decl_fault "$name" "bad images_component_key"; return 0; }
        d_comp=$value ;;
      images_digest_key)
        [[ $value =~ $DECL_JSON_KEY_RE ]] || { decl_fault "$name" "bad images_digest_key"; return 0; }
        d_digest=$value ;;
      images_release_key)
        [[ $value =~ $DECL_JSON_KEY_RE ]] || { decl_fault "$name" "bad images_release_key"; return 0; }
        d_release=$value ;;
      images_alias)
        [[ ${#value} -le 128 && $value =~ $DECL_ALIAS_RE ]] || { decl_fault "$name" "bad images_alias"; return 0; }
        d_alias=$value ;;
      core_units)
        decl_unit_list "$value" 16 "$DECL_UNIT_RE" || { decl_fault "$name" "bad core_units"; return 0; }
        d_core=$value ;;
      *) decl_fault "$name" "unknown key $key"; return 0 ;;
    esac
  done < "$f"
  [[ $d_version == 1 ]] || { decl_fault "$name" "version=1 missing or unsupported"; return 0; }
  for k in images_units images_manifest images_component_key images_digest_key images_alias images_release_key; do
    if [[ -n ${seen[$k]:-} ]]; then seen[images]=1; fi
  done
  if [[ -n ${seen[images]:-} ]]; then
    for k in images_units images_manifest images_component_key images_digest_key images_alias; do
      [[ -n ${seen[$k]:-} ]] || { decl_fault "$name" "missing key $k"; return 0; }
    done
    [[ -z $DECL_IMG_FILE ]] || { decl_fault "$name" "images declared by another file"; return 0; }
  elif [[ -z $d_core ]]; then
    decl_fault "$name" "declares nothing"; return 0
  fi
  if [[ -n ${seen[images]:-} ]]; then
    DECL_IMG_FILE=$name; DECL_MANIFEST=$d_manifest; DECL_COMP_KEY=$d_comp; DECL_DIGEST_KEY=$d_digest
    DECL_ALIAS=$d_alias; DECL_RELEASE_KEY=$d_release
    IFS=' ' read -ra DECL_IMG_UNITS <<<"$d_units"
  fi
  if [[ -n $d_core ]]; then
    IFS=' ' read -ra core_items <<<"$d_core"
    for u in "${core_items[@]}"; do DECL_CORE+=("$u"); done
  fi
}
decl_load() {
  local f name n=0
  [[ -e $DECL_DIR || -L $DECL_DIR ]] || return 0           # no directory: the v1 screen, nothing to report
  if [[ -L $DECL_DIR || ! -d $DECL_DIR ]]; then decl_fault status-screen.d "not a plain directory"; return 0; fi
  decl_owner_ok "$DECL_DIR" || { decl_fault status-screen.d "unsafe owner or mode"; return 0; }
  for f in "$DECL_DIR"/*.conf; do
    [[ -e $f || -L $f ]] || continue
    name=${f##*/}
    n=$((n + 1))
    if (( n > DECL_MAX_FILES )); then decl_fault status-screen.d "more than $DECL_MAX_FILES declarations"; return 0; fi
    if [[ ! $name =~ ^[a-z0-9][a-z0-9._-]{0,63}\.conf$ ]]; then decl_fault "$name" "bad file name"; continue; fi
    if [[ -L $f || ! -f $f ]]; then decl_fault "$name" "not a regular file"; continue; fi
    decl_owner_ok "$f" || { decl_fault "$name" "unsafe owner or mode"; continue; }
    if [[ $(stat -c %s -- "$f" 2>/dev/null) -gt $DECL_MAX_BYTES ]]; then decl_fault "$name" "larger than $DECL_MAX_BYTES bytes"; continue; fi
    if LC_ALL=C grep -aqv '^[[:print:]]*$' -- "$f" 2>/dev/null; then decl_fault "$name" "not printable ASCII"; continue; fi
    decl_parse "$f" "$name"
  done
}
decl_load

# ---------------------------------------------------------------------------
# Watched units. FIXED by the image: the screen never takes a unit name from
# anything that is not part of the image (the OS list below, plus what the
# image's own declarations name, validated above).
# ---------------------------------------------------------------------------
UNIT_STORAGE='systemd-cryptsetup@data.service'      # the "data" volume of the disk encryption table (nofail)
UNIT_DATA_MOUNT='var-lib-neural\x2dice-data.mount'
UNIT_CEREMONY='neural-ice-firstboot-tpm-ceremony.service'
UNIT_NETWORK='NetworkManager.service'
UNIT_SEED_IMPORT='neural-ice-seed-import.service'
UNIT_PAYLOAD='neural-ice-payload-apply.service'
# The units whose failure is the image phase (NI-E04), in the order they run:
# the OS's own v1 pair, or what the declaration names (it replaces them).
if [[ -n $DECL_IMG_FILE ]]; then IMG_UNITS=("${DECL_IMG_UNITS[@]}")
else IMG_UNITS=("$UNIT_SEED_IMPORT" "$UNIT_PAYLOAD"); fi
# tty1 owners: the login getty (debug variant) or the product console dashboard
# (branded appliance, ICE-Fabric neural-ice-tui.service). Either one active
# means the screen is no longer ours.
TTY1_OWNERS=('getty@tty1.service' 'neural-ice-tui.service')
# Core services shipped by this OS. The branded derivation adds its product
# units through its declaration (core_units=) or the older
# /usr/lib/neural-ice/status-screen/core-services (one unit per line, `#`
# comments) -- the OS stays free of product knowledge (ADR-0032). A declaration
# of the image phase replaces the OS's v1 payload apply, which is then not the
# one that starts the product.
CORE_SERVICES=(
  neural-ice-hostname-init.service
  neural-ice-device-root.service
  neural-ice-payload-apply.service
  avahi-daemon.service
)
if [[ -n $DECL_IMG_FILE ]]; then
  CORE_SERVICES=(
    neural-ice-hostname-init.service
    neural-ice-device-root.service
    avahi-daemon.service
  )
fi
core_services_dir=$(path /usr/lib/neural-ice/status-screen)
if [[ -f $core_services_dir/core-services && ! -L $core_services_dir/core-services ]]; then
  while IFS= read -r line; do
    line=${line%%#*}; line=${line//[[:space:]]/}
    [[ -n $line ]] || continue
    [[ $line =~ ^[A-Za-z0-9@._:\\-]+\.(service|target|mount|socket)$ ]] || continue
    CORE_SERVICES+=("$line")
  done < "$core_services_dir/core-services"
fi
for u in "${DECL_CORE[@]}"; do
  [[ " ${CORE_SERVICES[*]} " == *" $u "* ]] || CORE_SERVICES+=("$u")
done

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
# `not-found` is an answer (the image does not ship the unit); `unknown` is NO
# answer (systemctl failed). The two are never conflated: an absent unit is
# skipped, an unknown one keeps the screen in "probing" and blocks READY.
unit_absent() { [[ ${U_LOAD[$1]} == not-found ]]; }
unit_unknown() { [[ ${U_LOAD[$1]} == unknown ]]; }
unit_skipped() { # a unit whose Condition*= was evaluated and said no
  [[ ${U_ACTIVE[$1]} == inactive && ${U_CONDTS[$1]} != 0 && ${U_CONDRES[$1]} == no ]]
}
unit_failed() { [[ ${U_ACTIVE[$1]} == failed ]]; }
unit_active() { [[ ${U_ACTIVE[$1]} == active ]]; }
# A declared image step is behind us when it ran, was skipped by its Condition=
# (a step with nothing to do) or is not shipped.
step_done() { unit_active "$1" || unit_skipped "$1" || unit_absent "$1"; }

# ---------------------------------------------------------------------------
# Identity header. Nothing here is secret: the DMI model and serial are on the
# chassis label, the hostname is broadcast over mDNS, the version and short
# image digest identify the software for support.
# ---------------------------------------------------------------------------
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
# Network: the management NIC as neural-ice-hostname-init selected it (one rule,
# in /usr/local/bin/neural-ice-mgmt-port: first built-in wired port, never a USB
# dongle nor a ConnectX port), read from the runtime contract it publishes on
# every boot. This screen does not re-derive the port and reads no NetworkManager
# profile: an empty answer means hostname-init has not run yet, or failed —
# which the core-services line and NI-E05 already say. Receive rate from
# rx_bytes deltas.
# ---------------------------------------------------------------------------
SYS_NET=$(path /sys/class/net)
MGMT_IFACE_FILE=$(path /run/neural-ice/mgmt-interface)
mgmt_interface() {
  local iface
  iface=$(sanitize "$(read_first_line "$MGMT_IFACE_FILE")" 15)
  # A kernel interface name, nothing that could walk a path or reach `ip` as an
  # option; and it must exist, or the contract is stale.
  [[ $iface =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$ && -e $SYS_NET/$iface ]] || return 1
  printf '%s' "$iface"
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
# (graphroot, the bootc bound-image store or the read-only seed store), judged
# on digest when pinned.
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
# Three stores, the quadlets' own lookup order: the graphroot, the bootc
# bound-image store `bootc install` fills from the medium (a symlink under
# /sysroot; read through it, never resolved), and the seed store first boot
# publishes. Since the medium carries the images, a first boot counts them
# present from the bootc store before seed-import has run at all.
STORAGE_INDEXES=(
  "$(path /var/lib/containers/storage/overlay-images/images.json)"
  "$(path /usr/lib/bootc/storage/overlay-images/images.json)"
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
# Manifest components (only when a declaration names an image manifest). The
# manifest is compact JSON whose components are flat objects: each `{...}`
# carrying the declared component key is one component (other entries, such as
# the host or evidence ones, do not carry it). A component is present when its
# alias (images_alias with {id} replaced by the component id) AND its digest are
# in containers-storage. Parsed with bash and grep only, never executed, never
# trusted beyond the character classes below.
# ---------------------------------------------------------------------------
MANIFEST=""; [[ -z $DECL_IMG_FILE ]] || MANIFEST=$(path "$DECL_MANIFEST")
MANI_TOTAL=0; MANI_PRESENT=0; MANI_RELEASE='unset'; MANI_SEEN=0
manifest_read() {
  local id="" doc indexes="" idx obj cid cdigest alias
  MANI_TOTAL=0; MANI_PRESENT=0; MANI_RELEASE='unset'; MANI_SEEN=0
  [[ -f $MANIFEST && ! -L $MANIFEST && -r $MANIFEST ]] || return 0
  MANI_SEEN=1
  doc=$(head -c 1048576 "$MANIFEST" 2>/dev/null | tr -d '\n') || return 0
  if [[ -n $DECL_RELEASE_KEY && $doc =~ \"$DECL_RELEASE_KEY\"[[:space:]]*:[[:space:]]*\"([A-Za-z0-9._-]{1,128})\" ]]; then
    id=${BASH_REMATCH[1]}
  fi
  MANI_RELEASE=$(sanitize "${id:-unset}" 40)
  for idx in "${STORAGE_INDEXES[@]}"; do
    [[ -r $idx ]] && indexes+=$(<"$idx")
  done
  while IFS= read -r obj; do
    MANI_TOTAL=$((MANI_TOTAL + 1))
    cid=""; cdigest=""
    [[ $obj =~ \"$DECL_COMP_KEY\"[[:space:]]*:[[:space:]]*\"([a-z0-9][a-z0-9._-]{0,127})\" ]] && cid=${BASH_REMATCH[1]}
    [[ $obj =~ \"$DECL_DIGEST_KEY\"[[:space:]]*:[[:space:]]*\"(sha256:[0-9a-f]{64})\" ]] && cdigest=${BASH_REMATCH[1]}
    [[ -n $cid && -n $cdigest ]] || continue
    alias=${DECL_ALIAS/'{id}'/$cid}
    if [[ $indexes == *"\"$alias\""* && $indexes == *"\"$cdigest\""* ]]; then
      MANI_PRESENT=$((MANI_PRESENT + 1))
    fi
  done < <(grep -oE '\{[^{}]*\}' <<<"$doc" | grep -F "\"$DECL_COMP_KEY\"" || true)
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
# The UART is the kernel's own console choice, not a guess: the active console
# list (/sys/class/tty/console/active, VTs excluded), then `console=` on the
# kernel command line. Only ttyS<n>/ttyAMA<n> qualify -- those are the two the
# unit's DeviceAllow= opens (GB10 image: ttyS0; QEMU aarch64 virt: ttyAMA0).
serial_console_device() {
  local name candidates=""
  if [[ -r $(path /sys/class/tty/console/active) ]]; then
    IFS= read -r candidates < "$(path /sys/class/tty/console/active)" || true
  fi
  candidates+=" $(grep -oE '(^| )console=tty[A-Za-z]*[0-9]+' "$(path /proc/cmdline)" 2>/dev/null | sed 's/.*console=//' | tr '\n' ' ')"
  for name in $candidates; do
    [[ $name =~ ^tty(S|AMA)[0-9]+$ ]] || continue
    if [[ ${NI_STATUS_SCREEN_TESTING:-0} != 0 ]]; then
      [[ -e $(path /dev/"$name") ]] && { path /dev/"$name"; return 0; }
    else
      [[ -c /dev/$name ]] && { printf '/dev/%s' "$name"; return 0; }
    fi
  done
  return 1
}
SERIAL_DEV=$(serial_console_device || true)
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

# tty1 ownership, asked FRESH from the manager immediately before every write to
# the screen: the loop's snapshot can be a second old, and getty/the TUI may
# have taken tty1 in between. Once an owner is active nothing more is written.
tty1_owner_active() {
  local u
  for u in "${TTY1_OWNERS[@]}"; do
    query_unit "$u"
    unit_active "$u" && return 0
  done
  return 1
}
DREW=0
finish() { (( DREW )) || return 0; tty1_owner_active || { cursor_show; printf '\n'; }; }
trap 'finish; exit 0' TERM INT HUP
# First failure wins: the code shown is the earliest phase that broke.
set_failure() { [[ -n $fail_code ]] || { fail_code=$1; fail_what=$2; fail_unit=$3; }; }

# Static identity, read once.
PRODUCT=$(product_name)
VERSION=$(os_version)
IMAGE=$(booted_image_short)
CHANNEL=$(device_channel)
ID_LABEL=channel; ID_VALUE=$CHANNEL
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
           "${IMG_UNITS[@]}" "${TTY1_OWNERS[@]}" "${CORE_SERVICES[@]}"; do
    query_unit "$u"
  done

  # Someone else owns tty1 now: leave quietly, whatever the state. Checked
  # BEFORE the first draw so a fast reboot never scribbles over a login prompt
  # or the product TUI that already took the screen (re-checked before the
  # write itself, below).
  for u in "${TTY1_OWNERS[@]}"; do
    if unit_active "$u"; then finish; exit 0; fi
  done

  # Did every probe answer? A systemctl failure is not a state.
  probing=0
  for u in "$UNIT_STORAGE" "$UNIT_DATA_MOUNT" "$UNIT_CEREMONY" "$UNIT_NETWORK" \
           "${IMG_UNITS[@]}" "${CORE_SERVICES[@]}"; do
    unit_unknown "$u" && { probing=1; break; }
  done

  fail_code=""; fail_what=""; fail_unit=""

  # --- storage ------------------------------------------------------------
  if unit_failed "$UNIT_STORAGE" || unit_failed "$UNIT_DATA_MOUNT"; then
    storage_mark=fail; storage_text="data volume could not be unlocked"
    unit_failed "$UNIT_STORAGE" && set_failure NI-E01 "storage unlock" "$UNIT_STORAGE"
    unit_failed "$UNIT_DATA_MOUNT" && set_failure NI-E01 "storage unlock" "$UNIT_DATA_MOUNT"
  elif unit_unknown "$UNIT_STORAGE" || unit_unknown "$UNIT_DATA_MOUNT"; then
    storage_mark="wait"; storage_text="probing..."
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
  elif unit_unknown "$UNIT_CEREMONY"; then
    trust_mark="wait"; trust_text="probing..."
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
  elif unit_unknown "$UNIT_NETWORK"; then
    net_mark="wait"; net_text="probing..."
  elif [[ -z $iface ]]; then
    net_mark="wait"; net_text="waiting for the management port (hostname-init)"
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
  images_done=0; img_extra=""; img_failed=0; img_unknown=0; img_steps_done=1
  if [[ -n $DECL_IMG_FILE ]]; then
    # Declared: the components of the image manifest; done only when the declared
    # steps are done themselves (a pull that has fetched every image is still
    # committing its aliases until the unit ends).
    manifest_read
    img_present=$MANI_PRESENT; img_total=$MANI_TOTAL
    if [[ -n $DECL_RELEASE_KEY ]]; then ID_LABEL=release; ID_VALUE=$MANI_RELEASE; fi
  else
    collect_image_refs
    read -r img_present img_total <<<"$(count_images)"
  fi
  for u in "${IMG_UNITS[@]}"; do
    unit_failed "$u" && img_failed=1
    unit_unknown "$u" && img_unknown=1
    step_done "$u" || img_steps_done=0
  done
  if (( img_failed )); then
    img_mark=fail; img_text="$img_present/$img_total present -- image import failed"
    for u in "${IMG_UNITS[@]}"; do
      ! unit_failed "$u" || set_failure NI-E04 "image pull" "$u"
    done
  elif (( img_unknown )); then
    img_mark="wait"; img_text="$img_present/$img_total present -- probing..."
  elif [[ -n $DECL_IMG_FILE ]] && (( img_total == 0 )); then
    # No component to count: the release is not imported yet (or the manifest is
    # unreadable). Never the v1 "no inventory" skip: a declared image phase
    # always has one.
    img_mark="wait"
    if (( MANI_SEEN )); then img_text="release manifest names no readable component"
    else img_text="waiting for the release manifest"; fi
  elif [[ -n $DECL_IMG_FILE ]]; then
    if (( img_present >= img_total && img_steps_done )); then
      img_mark=ok; img_text="$img_present/$img_total present"; images_done=1
    else
      img_mark=run; img_text="$img_present/$img_total present"; img_extra=$rx_text
    fi
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
  elif (( probing )); then
    core_mark="wait"; core_text="$core_ok/$core_total active -- probing..."
  elif (( core_total == 0 )); then
    core_mark=skip; core_text="no core services declared"
  elif (( core_ok >= core_total )); then
    core_mark=ok; core_text="$core_ok/$core_total active"
  else
    core_mark=run; core_text="$core_ok/$core_total active"
  fi
  core_done=$(( core_ok >= core_total ? 1 : 0 ))

  # --- declarations ---------------------------------------------------------
  # A refused declaration is a fault of the image, not of a boot phase: it ranks
  # after every phase above, but it is never silent and it withholds READY.
  if (( ${#DECL_FAULTS[@]} > 0 )); then
    set_failure NI-E06 "status declaration: ${DECL_FAULTS[0]#*|}" "${DECL_FAULTS[0]%%|*}"
  fi

  # --- ready ------------------------------------------------------------------
  network_done=0
  { [[ $net_mark == ok ]] || unit_absent "$UNIT_NETWORK"; } && network_done=1
  ready=0
  if [[ -z $fail_code ]] && (( !probing && ceremony_done && network_done && images_done && core_done )); then
    ready=1
    (( READY_SINCE > 0 )) || READY_SINCE=$((SECONDS + 1))
  else
    READY_SINCE=0
  fi

  # --- serial mirror (stable lines only, on change) ---------------------------
  # v1: once. A declared release id appears when the import publishes the
  # manifest, so the (change-only) mirror is fed on every pass then.
  if (( iteration == 1 )) || [[ -n $DECL_RELEASE_KEY ]]; then
    mirror header "$PRODUCT | OS $VERSION | image $IMAGE | $ID_LABEL $ID_VALUE"
  fi
  if (( iteration == 1 )); then
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
  line " OS $VERSION   image $IMAGE   $ID_LABEL $ID_VALUE"
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
  elif (( probing )); then
    line " Probing system state... $(fmt_duration "$uptime_s")   This screen is informational only; no input is read."
  else
    line " Starting... $(fmt_duration "$uptime_s")   This screen is informational only; no input is read."
  fi
  # The write itself: ask the manager once more, right now, whether tty1 has an
  # owner. If it has, this frame is dropped and the screen is never touched again.
  if tty1_owner_active; then FRAME=""; finish; exit 0; fi
  if (( ! DREW )); then cursor_hide; clear_screen; DREW=1; fi
  flush_frame

  if (( ready )) && (( SECONDS + 1 - READY_SINCE >= READY_LINGER )); then break; fi
  if (( MAX_ITERATIONS > 0 && iteration >= MAX_ITERATIONS )); then break; fi
  sleep "$INTERVAL" &
  wait $! || true
done
finish
exit 0
