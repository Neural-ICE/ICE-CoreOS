#!/usr/bin/env bash
#
# ONE COMMAND THAT REHEARSES A WHOLE MEDIUM INSTALLATION ON THE BENCH — no USB
# stick, no physical gesture, no trip to the machine room.
#
# 🔴 WHY THIS EXISTS (measured 2026-09-09). Four hardware attempts on .67 in one
# day, ~1 h each (build 25–35 min, flash, walk the stick over, boot), each one
# surfacing exactly ONE defect before powering off: the operator key on two
# transports (#162), the PCR counter floor after a wipe (P1.5a), fuse-overlayfs
# missing from the bootc container (#163), a `--log-driver passthrough` probe on
# a TTY (#164). This generation of medium — registry source + LAN mirror + sealed
# store — had never been run end to end anywhere but .67.
#
# 🔴 WHAT THIS IS NOT. There is no `if vm` anywhere here and none is wanted in
# the installer. Everything that differs between the VM and the GB10 is an INPUT:
#
#   Secure Boot state   the AAVMF variable store this script builds or is given.
#                       PCR7 is a function of it, so the signed PCR policy must
#                       cover the VM's PCR7 — see docs/RUNBOOK-BENCH-MEDIUM-REHEARSAL.md.
#   hardware identity   SMBIOS type 1/2 are set to the values the GB10 medium
#                       expects (image/lib/hardware-identity.sh reads DMI).
#   the mirror          reachability is a network input, not a code path.
#
# If a phase is impossible in a VM, this script REPORTS it (the installer's own
# refusal line, with its phase and its closed-vocabulary code) instead of
# working around it.
#
# RELATION TO image/qualify-installer-qemu.sh. That harness is the CI-shaped
# gate: a fixed synthetic matrix (virgin/preceremony/equal/replay/partial/
# owner-auth), `--network none|restricted-user` (slirp `restrict=on`, which by
# QEMU's own definition means "the guest ... will not be able to contact the host
# and no guest IP packets will be routed over the host to the outside" — so it
# can never reach the bench mirror), an expect/reject contract, and no receipt.
# This script is the bench-shaped driver: it OBSERVES one real medium against the
# real LAN mirror and reports what happened. It deliberately reuses that
# harness's proven process-group, QMP and swtpm helpers rather than copying them.
set -euo pipefail
umask 077

readonly NI_BENCH_RECEIPT_SCHEMA=neural-ice-bench-rehearsal-receipt-v1
# The installer's own failure evidence, persisted in one non-volatile EFI
# variable by ota/neural-ice-autoinstall.sh:163 and re-persisted by
# image/installer/neural-ice-installer-failure.sh. The GUID is fixed by those
# two producers; it is repeated here as a reader, never invented.
readonly NI_BENCH_EFI_EVIDENCE_NAME=NeuralICEInstallerFailure
readonly NI_BENCH_EFI_EVIDENCE_GUID=870a0500-25d2-574e-a1cc-79a69630bf96
# The SignatureOwner GUID goes INTO the measured EFI_SIGNATURE_LIST bytes of PK,
# KEK and db, so it changes PCR7. It is therefore a CONSTANT, not a fresh UUID:
# proven 2026-09-09 by building the same varstore twice with the same owner
# (identical SHA-256) and once with another owner (different SHA-256).
readonly NI_BENCH_ENROL_OWNER_GUID=1e5f0057-0000-4000-b000-6e6575726963

# 🔴 NOT `usage`. image/qualify-installer-qemu.sh defines a function of that
# name and is sourced below for its process-group and QMP helpers, so a
# `usage` here would be silently REPLACED by the CI harness's help text and
# this script would document arguments it does not accept.
bench_usage() {
  cat <<'EOF'
Usage:
  bench-rehearse-medium.sh --raw FILE --work-dir DIR --firmware-vars FILE [options]

Required:
  --raw FILE               the installation medium image; opened READ-ONLY and
                           never written
  --work-dir DIR           absolute path that must NOT exist; everything this
                           run creates lives inside it and nowhere else
  --firmware-vars FILE     AAVMF variable store. With --enrol-cert this is the
                           TEMPLATE (e.g. /usr/share/AAVMF/AAVMF_VARS.fd);
                           without it, a store that ALREADY carries the lab
                           certificate and SecureBootEnable

Options:
  --enrol-cert FILE        enrol this X.509 certificate (PEM or DER) as PK, KEK
                           and db and turn Secure Boot on, with virt-fw-vars
  --enrol-owner-guid GUID  SignatureOwner for that enrolment (default is a fixed
                           constant; changing it CHANGES PCR7)
  --firmware-code FILE     AAVMF code image (default AAVMF_CODE.secboot.fd)
  --source-transport T     virtio, nvme or usb for the medium (default virtio)
  --target-transport T     nvme or virtio for the target disk (default nvme)
  --target-size SIZE       sparse qcow2 logical size (default 1T)
  --smp N                  guest vCPUs (default 8)
  --memory MiB             guest memory (default 8192)
  --network MODE           lan or isolated (default lan)
  --mirror-ip IP           bench mirror address; checked reachable FROM THE HOST
                           before anything is created, and recorded
  --mirror-port PORT       mirror port for that check (default 5055)
  --install-timeout SEC    hard bound on the install VM (default 5400)
  --failure-grace SEC      after the installer's refusal line, how long the
                           failure surface may take to power off (default 180)
  --firstboot-timeout SEC  hard bound on the first-boot VM (default 1800)
  --ssh-wait SEC           how long first boot may take to open TCP/22 (default 900)
  --ssh-port PORT          loopback forward to guest TCP/22 (default 22222)
  --serial-max-bytes N     per-phase serial log ceiling (default 8388608)
  --skip-firstboot         stop after the install phase
  --allow-root             run as root anyway, with a stated reason
  -h, --help               this text

Output, all inside --work-dir:
  bench-rehearsal-receipt.json   the receipt
  install.console.log            the install phase serial console
  firstboot.console.log          the first-boot serial console, when it ran
  *.qemu.stderr                  QEMU's own diagnostics
  AAVMF_VARS.fd                  the varstore the VM actually booted, AFTER the
                                 run — it carries the installer's persisted
                                 failure evidence, PCR7 included

`usb` is offered for completeness only: the medium's kernel ships the Tegra xHCI
driver, which QEMU `virt` cannot emulate, so `virtio` is what actually boots
(same limitation as image/qualify-installer-qemu.sh).
EOF
}

# --------------------------------------------------------------------------- #
# THE SERIAL-LOG PARSERS. Pure functions of one file: no globals, no side
# effects, no processes killed, nothing written. image/test-bench-rehearse-medium.sh
# runs them over fixtures of the four real 2026-09-09 failures and one synthetic
# success, which is why they live above the source-only seam.
#
# 🔴 WHAT IS ACTUALLY ON THE SERIAL LINE, AND WHAT IS NOT.
#   ota/neural-ice-autoinstall.service:50-52 sets StandardOutput=tty with
#   TTYPath=/dev/tty1, so the installer's stdout does NOT reach the UART. The
#   only thing that does is ota/neural-ice-autoinstall.sh:76 `log()`, which
#   writes `[neural-ice-autoinstall] <text>` to /dev/console explicitly. That
#   covers the phase banners (:215), the completion line (:4445), the PCR7
#   values (:1718-1720) and the refusal line (:169).
#   image/installer/neural-ice-installer-failure.service is StandardOutput=tty
#   TTYPath=/dev/tty1 as well, so its `failure code` / `stage` block is a tty1
#   surface and is NOT expected on a headless serial log. It is parsed anyway,
#   because a bench console may be mirrored and because the same block is what a
#   photograph of a hardware failure shows.
# --------------------------------------------------------------------------- #

# Emits `key=value` lines. Values are drawn from the installer's own closed
# vocabularies and anything that does not match its shape is dropped, so a
# defect upstream costs a missing field and never an unbounded receipt entry.
ni_bench_parse_install_log() { # $1=serial console log
  local log=$1
  [[ -f "$log" && ! -L "$log" && -r "$log" ]] || {
    printf 'ni_bench_parse_install_log: unreadable log: %s\n' "$log" >&2
    return 2
  }
  awk '
    function emit(key, value) { printf "%s=%s\n", key, value }
    # 🔴 NO ERE INTERVALS ({n,m}) AND NO \x ESCAPES ANYWHERE IN THIS PROGRAM.
    # mawk is the default awk on Ubuntu and older mawk does not implement
    # intervals; a shape check that silently stops checking is worse than none.
    # Lengths are asserted with length(), which every awk implements.
    function keep_token(v) { return (v ~ /^[A-Za-z0-9][A-Za-z0-9._:\/-]*$/ && length(v) <= 64) }
    function keep_sha(v)   { return (v ~ /^[0-9a-f]+$/ && length(v) == 64) }
    function keep_digits(v, maximum) { return (v ~ /^[0-9]+$/ && length(v) <= maximum) }
    function keep_sha_csv(v,   parts, i, n) {
      if (v == "") return 0
      n = split(v, parts, ",")
      for (i = 1; i <= n; i++) if (!keep_sha(parts[i])) return 0
      return 1
    }
    function trim(v) { sub(/^[ \t]+/, "", v); sub(/[ \t]+$/, "", v); return v }
    BEGIN {
      complete_line = 0; fail_line = 0
      phase_reached = 0; phase_total = ""
      fail_phase = ""; fail_total = ""; fail_code = ""
      tty_open = 0; tty_code = ""; tty_phase = ""; tty_total = ""
      tty_stage = ""; tty_detail = ""; tty_pcr7 = ""; tty_policy = ""; tty_count = ""
      pcr7 = ""; policy = ""; available = ""
    }
    {
      line = $0
      sub(/\r$/, "", line)

      # --- ota/neural-ice-autoinstall.sh:215 — "[N/8] <label> (t+…)"
      if (match(line, /\[[0-9]+\/[0-9]+\] /)) {
        span = substr(line, RSTART + 1, RLENGTH - 3)
        split(span, p, "/")
        if (p[1] + 0 > phase_reached) phase_reached = p[1] + 0
        if (phase_total == "") phase_total = p[2]
      }

      # --- ota/neural-ice-autoinstall.sh:4445 — the ONLY completion marker
      # The literal em dash from ota/neural-ice-autoinstall.sh:4445, not an
      # escape: awk escapes for non-ASCII bytes are not portable, literals are.
      if (complete_line == 0 && index(line, "done — install completed") > 0) {
        complete_line = NR
      }

      # --- ota/neural-ice-autoinstall.sh:169 — the refusal line, on the UART
      if (fail_line == 0 && index(line, "FAILED in phase ") > 0) {
        fail_line = NR
        if (match(line, /FAILED in phase [0-9]+\/[0-9]+/)) {
          span = substr(line, RSTART, RLENGTH)
          split(span, f, " ")
          split(f[4], g, "/")
          fail_phase = g[1]; fail_total = g[2]
        }
        if (match(line, /\[install-failed-[a-z0-9][a-z0-9-]*\]/)) {
          fail_code = substr(line, RSTART + 1, RLENGTH - 2)
        }
      }

      # --- ota/neural-ice-autoinstall.sh:1718-1720 — printed only once the
      # coverage check has PASSED, which is exactly why an uncovered PCR7 has to
      # be read back out of the EFI variable instead.
      if (pcr7 == "" && match(line, /Live SHA-256 PCR7 = [0-9a-f]+/)) {
        pcr7 = substr(line, RSTART + 20, RLENGTH - 20)
      }
      if (policy == "" && match(line, /Live PCR7 PolicyPCR digest = [0-9a-f]+/)) {
        policy = substr(line, RSTART + 29, RLENGTH - 29)
      }
      if (available == "" && match(line, /Available signed PolicyPCR digests = [0-9a-f,]+/)) {
        available = substr(line, RSTART + 37, RLENGTH - 37)
      }

      # --- image/installer/neural-ice-installer-failure.sh, printf "  %-18s %s"
      if (index(line, "INSTALL FAILED") > 0) { tty_open = 1; next }
      if (tty_open == 1) {
        if (match(line, /^[ \t]+stage name[ \t]+/)) {
          if (tty_stage == "") tty_stage = trim(substr(line, RSTART + RLENGTH))
        } else if (match(line, /^[ \t]+failure code[ \t]+/)) {
          if (tty_code == "") tty_code = trim(substr(line, RSTART + RLENGTH))
        } else if (match(line, /^[ \t]+stage[ \t]+/)) {
          span = trim(substr(line, RSTART + RLENGTH))
          if (tty_phase == "" && span ~ /^[0-9]+ \/ [0-9]+$/) {
            split(span, s, " / "); tty_phase = s[1]; tty_total = s[2]
          }
        } else if (match(line, /^[ \t]+evidence[ \t]+/)) {
          if (tty_detail == "") tty_detail = trim(substr(line, RSTART + RLENGTH))
        } else if (match(line, /^[ \t]+live PCR7[ \t]+/)) {
          if (tty_pcr7 == "") tty_pcr7 = trim(substr(line, RSTART + RLENGTH))
        } else if (match(line, /^[ \t]+computed policy[ \t]+/)) {
          if (tty_policy == "") tty_policy = trim(substr(line, RSTART + RLENGTH))
        } else if (match(line, /^[ \t]+verified count[ \t]+/)) {
          if (tty_count == "") tty_count = trim(substr(line, RSTART + RLENGTH))
        } else if (match(line, /^[ \t]+schema[ \t]+/)) {
          tty_open = 2
        }
      }
    }
    END {
      failed = (fail_line > 0 || tty_code != "")
      if (failed)                 emit("outcome", "failed")
      else if (complete_line > 0) emit("outcome", "complete")
      else                        emit("outcome", "incomplete")

      emit("lines", NR)
      emit("phase_reached", phase_reached)
      emit("phase_total", (phase_total == "" ? "unknown" : phase_total))
      emit("complete_line", complete_line)
      emit("failure_line", fail_line)

      code = (fail_code != "" ? fail_code : tty_code)
      source = (fail_code != "" ? "serial-refusal-line" : (tty_code != "" ? "tty1-failure-block" : "none"))
      emit("failure_code", (keep_token(code) ? code : "none"))
      emit("failure_source", source)

      fp = (fail_phase != "" ? fail_phase : tty_phase)
      ft = (fail_total != "" ? fail_total : tty_total)
      emit("failure_phase", (keep_digits(fp, 3) ? fp : "none"))
      emit("failure_phase_total", (keep_digits(ft, 3) ? ft : "none"))
      emit("failure_stage_name", (keep_token(tty_stage) ? tty_stage : "none"))
      emit("failure_detail", ((tty_detail ~ /^[0-9a-f]+$/ && length(tty_detail) == 12) ? tty_detail : "none"))

      live = (keep_sha(pcr7) ? pcr7 : (keep_sha(tty_pcr7) ? tty_pcr7 : ""))
      emit("pcr7_live", (live != "" ? live : "none"))
      emit("pcr7_live_source", (keep_sha(pcr7) ? "serial-log" : (keep_sha(tty_pcr7) ? "tty1-failure-block" : "none")))
      pol = (keep_sha(policy) ? policy : (keep_sha(tty_policy) ? tty_policy : ""))
      emit("pcr7_policy", (pol != "" ? pol : "none"))
      emit("pcr7_available", (keep_sha_csv(available) ? available : "none"))
      emit("pcr7_verified_count", (keep_digits(tty_count, 4) ? tty_count : "none"))
    }
  ' "$log"
}

# The installed appliance's headless surface: image/firstboot/neural-ice-status-screen.sh:343
# writes `neural-ice-status: <text>\r\n` to the UART once per CHANGE, so the LAST
# occurrence of each line is the final state. Values are bounded and stripped of
# control characters before they can reach the receipt.
ni_bench_parse_firstboot_log() { # $1=serial console log
  local log=$1
  [[ -f "$log" && ! -L "$log" && -r "$log" ]] || {
    printf 'ni_bench_parse_firstboot_log: unreadable log: %s\n' "$log" >&2
    return 2
  }
  awk '
    function emit(key, value) { printf "%s=%s\n", key, value }
    function clean(v) {
      # A portable "printable ASCII only" class: space through tilde. No octal
      # escapes, which mawk and gawk do not agree on inside a bracket expression.
      gsub(/[^ -~]/, "", v)
      sub(/^[ \t]+/, "", v); sub(/[ \t]+$/, "", v)
      return substr(v, 1, 200)
    }
    BEGIN { mirrored = 0; ready = 0; failcode = ""; failunit = "" }
    {
      line = $0
      sub(/\r$/, "", line)
      at = index(line, "neural-ice-status: ")
      if (at == 0) next
      mirrored++
      body = substr(line, at + 19)
      if (index(body, "READY -- login available") == 1) { ready = 1; next }
      if (substr(body, 1, 8) == "FAILURE ") {
        if (match(body, /NI-E[0-9][0-9]/)) failcode = substr(body, RSTART, RLENGTH)
        if (match(body, /unit=[^ ]+/)) failunit = substr(body, RSTART + 5, RLENGTH - 5)
        next
      }
      if (substr(body, 1, 1) != "[") next
      mark = substr(body, 1, 6)
      rest = substr(body, 8)
      colon = index(rest, ": ")
      if (colon == 0) next
      label = substr(rest, 1, colon - 1)
      text = substr(rest, colon + 2)
      key = ""
      if (label == "Storage")       key = "storage"
      else if (label == "Device trust")  key = "device_trust"
      else if (label == "Network")       key = "network"
      else if (label == "Images")        key = "images"
      else if (label == "Core services") key = "core_services"
      if (key == "") next
      marks[key] = mark
      texts[key] = text
    }
    END {
      emit("firstboot_mirror_lines", mirrored)
      emit("firstboot_ready", (ready ? "yes" : "no"))
      emit("firstboot_status_failure", (failcode != "" ? failcode : "none"))
      emit("firstboot_status_failure_unit", (failunit != "" ? clean(failunit) : "none"))
      split("storage device_trust network images core_services", order, " ")
      for (i = 1; i <= 5; i++) {
        k = order[i]
        emit("firstboot_" k "_mark", (k in marks ? clean(marks[k]) : "unknown"))
        emit("firstboot_" k, (k in texts ? clean(texts[k]) : "unknown"))
      }
    }
  ' "$log"
}

# The behavioural test sources these exact parsers. This cannot turn a bench
# invocation into a test: it is accepted only while the file is being sourced.
if [[ "${NI_BENCH_HARNESS_SOURCE_ONLY:-}" == 1 ]]; then
  [[ "${BASH_SOURCE[0]}" != "$0" ]] || {
    printf 'bench-rehearse-medium: source-only mode requires sourcing this file\n' >&2
    exit 2
  }
  return 0
fi

# --------------------------------------------------------------------------- #
# From here down: the bench driver.
# --------------------------------------------------------------------------- #
BENCH_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly BENCH_DIR
readonly QEMU_HARNESS="$BENCH_DIR/qualify-installer-qemu.sh"
[[ -f "$QEMU_HARNESS" && ! -L "$QEMU_HARNESS" ]] || {
  printf 'bench-rehearse-medium: REFUSED: the QEMU harness helpers are unavailable\n' >&2
  exit 1
}
# Reuses process_group_exists / terminate_qemu_session / stop_task_process /
# wait_for_exit / qmp_guest_request — the exact code #127 and #149 proved on this
# bench. Its own `die` is shadowed below so refusals still name THIS script.
# shellcheck source=image/qualify-installer-qemu.sh
NI_QEMU_HARNESS_SOURCE_ONLY=1 source "$QEMU_HARNESS"

die() { printf 'bench-rehearse-medium: REFUSED: %s\n' "$*" >&2; exit 1; }
say() { printf 'bench-rehearse-medium: %s\n' "$*"; }
need() { command -v "$1" >/dev/null 2>&1 || die "$1 is unavailable"; }

(( $# >= 1 )) || { bench_usage >&2; exit 2; }

raw=
work_dir=
firmware_code=/usr/share/AAVMF/AAVMF_CODE.secboot.fd
firmware_vars=
enrol_cert=
enrol_owner_guid=$NI_BENCH_ENROL_OWNER_GUID
source_transport=virtio
target_transport=nvme
target_size=1T
smp=8
memory=8192
network=lan
mirror_ip=
mirror_port=5055
install_timeout=5400
failure_grace=180
firstboot_timeout=1800
ssh_wait=900
ssh_port=22222
serial_max_bytes=8388608
skip_firstboot=0
allow_root=0

while (( $# )); do
  case "$1" in
    --raw|--work-dir|--firmware-code|--firmware-vars|--enrol-cert|--enrol-owner-guid \
    |--source-transport|--target-transport|--target-size|--smp|--memory|--network \
    |--mirror-ip|--mirror-port|--install-timeout|--failure-grace|--firstboot-timeout \
    |--ssh-wait|--ssh-port|--serial-max-bytes)
      (( $# >= 2 )) || die "$1 requires a value"
      key=$1 value=$2
      shift 2
      case "$key" in
        --raw) raw=$value ;;
        --work-dir) work_dir=$value ;;
        --firmware-code) firmware_code=$value ;;
        --firmware-vars) firmware_vars=$value ;;
        --enrol-cert) enrol_cert=$value ;;
        --enrol-owner-guid) enrol_owner_guid=$value ;;
        --source-transport) source_transport=$value ;;
        --target-transport) target_transport=$value ;;
        --target-size) target_size=$value ;;
        --smp) smp=$value ;;
        --memory) memory=$value ;;
        --network) network=$value ;;
        --mirror-ip) mirror_ip=$value ;;
        --mirror-port) mirror_port=$value ;;
        --install-timeout) install_timeout=$value ;;
        --failure-grace) failure_grace=$value ;;
        --firstboot-timeout) firstboot_timeout=$value ;;
        --ssh-wait) ssh_wait=$value ;;
        --ssh-port) ssh_port=$value ;;
        --serial-max-bytes) serial_max_bytes=$value ;;
      esac
      ;;
    --skip-firstboot) skip_firstboot=1; shift ;;
    --allow-root) allow_root=1; shift ;;
    -h|--help) bench_usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[[ -n "$work_dir" && "$work_dir" == /* && "$work_dir" != / ]] \
  || die "--work-dir must be an absolute non-root path"
[[ -n "$raw" && -f "$raw" && ! -L "$raw" && -r "$raw" ]] \
  || die "--raw must name one readable regular file"
[[ -n "$firmware_vars" && -f "$firmware_vars" && ! -L "$firmware_vars" && -r "$firmware_vars" ]] \
  || die "--firmware-vars must name one readable regular file"
[[ -f "$firmware_code" && -r "$firmware_code" ]] || die "AAVMF code is unreadable"
if [[ -n "$enrol_cert" ]]; then
  [[ -f "$enrol_cert" && ! -L "$enrol_cert" && -r "$enrol_cert" ]] \
    || die "--enrol-cert must name one readable regular file"
  [[ "$enrol_owner_guid" =~ ^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$ ]] \
    || die "--enrol-owner-guid is malformed"
fi
case "$source_transport" in virtio|nvme|usb) ;; *) die "unsupported source transport" ;; esac
case "$target_transport" in virtio|nvme) ;; *) die "unsupported target transport" ;; esac
case "$network" in lan|isolated) ;; *) die "unsupported network mode" ;; esac
[[ "$target_size" =~ ^[1-9][0-9]*[KMGT]$ ]] || die "--target-size is malformed"
[[ "$smp" =~ ^[1-9][0-9]{0,2}$ ]] || die "--smp is malformed"
[[ "$memory" =~ ^[1-9][0-9]{2,6}$ ]] || die "--memory is malformed"
for bound in install_timeout failure_grace firstboot_timeout ssh_wait; do
  [[ "${!bound}" =~ ^[1-9][0-9]{0,5}$ ]] || die "--${bound//_/-} is malformed"
done
[[ "$serial_max_bytes" =~ ^[1-9][0-9]{4,10}$ ]] || die "--serial-max-bytes is malformed"
[[ "$ssh_port" =~ ^[1-9][0-9]{3,4}$ && "$ssh_port" -le 65535 ]] || die "--ssh-port is malformed"
[[ "$mirror_port" =~ ^[1-9][0-9]{0,4}$ && "$mirror_port" -le 65535 ]] || die "--mirror-port is malformed"
if [[ -n "$mirror_ip" ]]; then
  [[ "$mirror_ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || die "--mirror-ip must be a plain IPv4 address"
  [[ "$network" == lan ]] || die "--mirror-ip is meaningless with --network isolated"
fi

# 🔴 ROOT IS NOT NEEDED AND IS NOT TAKEN. /dev/kvm is group-owned by `kvm`;
# swtpm, qemu-img and qemu-system-aarch64 all run unprivileged. Running this as
# root would put a root-owned 1 TiB image and a root-owned TPM state directory
# on the bench, and would give the guest's virtual disks a privileged opener for
# no gain. If a future bench genuinely requires it, --allow-root makes that an
# explicit, recorded decision rather than a silent escalation.
if (( EUID == 0 && allow_root == 0 )); then
  die "this rehearsal does not need root; add the bench user to the kvm group, or pass --allow-root on purpose"
fi

for tool in qemu-system-aarch64 qemu-img swtpm timeout setsid python3 awk stat; do need "$tool"; done
[[ "$(uname -m)" == aarch64 ]] || die "the rehearsal boots an ARM64 medium and requires an ARM64 host"
[[ -r /dev/kvm && -w /dev/kvm ]] || die "/dev/kvm is unreadable or unwritable by this user"
have_virt_fw_vars=no
if command -v virt-fw-vars >/dev/null 2>&1; then have_virt_fw_vars=yes; fi
if [[ -n "$enrol_cert" && "$have_virt_fw_vars" != yes ]]; then
  die "--enrol-cert needs virt-fw-vars (Ubuntu: python3-virt-firmware); see docs/RUNBOOK-BENCH-MEDIUM-REHEARSAL.md"
fi

# A necessary condition, checked BEFORE a 1 TiB image exists: if the bench host
# itself cannot open the mirror port, the guest behind slirp certainly cannot.
# It is NOT a sufficient condition — see the runbook on mDNS and bridging.
mirror_reachable=not-checked
if [[ -n "$mirror_ip" ]]; then
  # shellcheck disable=SC2016 # $1/$2 are the child shell's positional parameters
  if timeout 5 bash -c 'exec 3<>/dev/tcp/"$1"/"$2"' _ "$mirror_ip" "$mirror_port"; then
    mirror_reachable=yes
  else
    mirror_reachable=no
    die "the bench host cannot open ${mirror_ip}:${mirror_port}; the guest will not reach it either"
  fi
fi

[[ ! -e "$work_dir" ]] || die "the work directory already exists; a rehearsal never reuses one"
mkdir -m 0700 -- "$work_dir"
tpm_dir=$work_dir/tpmstate
mkdir -m 0700 -- "$tpm_dir"

target=$work_dir/target.qcow2
vars=$work_dir/AAVMF_VARS.fd
tpm_ctrl=$work_dir/swtpm.ctrl
tpm_pidfile=$work_dir/swtpm.pid
receipt=$work_dir/bench-rehearsal-receipt.json

# --------------------------------------------------------------------------- #
# THE SECURE BOOT STATE — the whole reason PCR7 in this VM is what it is.
#
# virt-fw-vars option semantics, from its own --help (virt-firmware, read
# 2026-09-09): `--set-pk GUID FILE` sets PK to an x509 cert "loaded in pem or der
# format from FILE and with owner GUID"; `--add-kek GUID FILE` and
# `--add-db GUID FILE` append to KEK and db the same way; `--secure-boot`
# "enable secure boot mode". `--enroll-cert CERT` is NOT a file path — it names a
# certificate bundled with virt-firmware as `domain/name` and fails on a path.
# --------------------------------------------------------------------------- #
firmware_vars_origin=copied-as-supplied
if [[ -n "$enrol_cert" ]]; then
  virt-fw-vars -i "$firmware_vars" \
    --set-pk "$enrol_owner_guid" "$enrol_cert" \
    --add-kek "$enrol_owner_guid" "$enrol_cert" \
    --add-db "$enrol_owner_guid" "$enrol_cert" \
    --secure-boot \
    -o "$vars" \
    || die "virt-fw-vars refused to build the Secure Boot variable store"
  firmware_vars_origin=enrolled-by-virt-fw-vars
else
  cp --reflink=auto -- "$firmware_vars" "$vars"
fi
chmod 0600 -- "$vars"
if [[ "$have_virt_fw_vars" == yes ]]; then
  virt-fw-vars -i "$vars" -p > "$work_dir/firmware-vars.before.txt" \
    || die "the Secure Boot variable store could not be read back"
  grep -Eq '^SecureBootEnable +: bool: ON' "$work_dir/firmware-vars.before.txt" \
    || die "the variable store does not have Secure Boot enabled; PCR7 would not be the appliance's"
fi

qemu-img create -q -f qcow2 "$target" "$target_size" \
  || die "the sparse target disk could not be created"

# --------------------------------------------------------------------------- #
# Phase runner. Every exit path — refusal, timeout, signal, success — goes
# through cleanup(): the QEMU process GROUP, then swtpm, then the sockets.
# --------------------------------------------------------------------------- #
timeout_pid=
swtpm_pidfile=
qmp_socket=
cleanup() {
  local original_rc=$? cleanup_rc=0 pid
  trap - EXIT
  if [[ -n "$timeout_pid" ]]; then
    terminate_qemu_session "$timeout_pid" || {
      printf 'bench-rehearse-medium: the QEMU session %s survived cleanup\n' "$timeout_pid" >&2
      cleanup_rc=1
    }
  fi
  if [[ -n "$swtpm_pidfile" && -f "$swtpm_pidfile" ]]; then
    pid=$(<"$swtpm_pidfile")
    stop_task_process "$pid" swtpm || cleanup_rc=1
  fi
  [[ -z "$qmp_socket" ]] || rm -f -- "$qmp_socket"
  (( original_rc != 0 )) && exit "$original_rc"
  exit "$cleanup_rc"
}
trap cleanup EXIT

start_swtpm() {
  rm -f -- "$tpm_ctrl" "$tpm_pidfile"
  # QEMU speaks the swtpm control protocol and supplies the data channel itself,
  # so only the control socket is published — the same shape #127 proved here.
  swtpm socket --tpm2 --tpmstate "dir=$tpm_dir" \
    --ctrl "type=unixio,path=$tpm_ctrl,mode=0600" \
    --pid "file=$tpm_pidfile" --flags startup-clear --daemon \
    || die "swtpm refused to start"
  swtpm_pidfile=$tpm_pidfile
  local _
  for _ in {1..50}; do [[ -S "$tpm_ctrl" ]] && break; sleep 0.1; done
  [[ -S "$tpm_ctrl" ]] || die "the swtpm control socket did not appear"
}

stop_swtpm() {
  local pid
  [[ -n "$swtpm_pidfile" && -f "$swtpm_pidfile" ]] || { swtpm_pidfile=; return 0; }
  pid=$(<"$swtpm_pidfile")
  swtpm_pidfile=
  stop_task_process "$pid" swtpm || die "swtpm survived a bounded shutdown"
  rm -f -- "$tpm_ctrl" "$tpm_pidfile"
}

# $1=phase name, $2=timeout, $3=success grep pattern (-F, empty when the
# watcher decides), $4=failure grep pattern (-F, may be empty), $5=guest request
# on success, $6=extra watcher ("ssh-port" or "").
# Sets: PHASE_RC, PHASE_STOP, PHASE_TRUNCATED, PHASE_SSH, PHASE_RESIDUAL.
run_phase() {
  local name=$1 bound=$2 success=$3 failure=$4 request=$5 watcher=$6
  local console=$work_dir/${name}.console.log
  local stderr_log=$work_dir/${name}.qemu.stderr
  local size grace_deadline=0 ssh_deadline=0 reached=0
  qmp_socket=$work_dir/${name}.qmp.sock
  [[ ! -e "$qmp_socket" ]] || die "the $name QMP socket path already exists"

  PHASE_STOP=none
  PHASE_TRUNCATED=no
  PHASE_SSH=not-watched

  set +e
  setsid --wait timeout --foreground "$bound" "${qemu[@]}" \
    >"$console" 2>"$stderr_log" &
  timeout_pid=$!
  [[ "$watcher" != ssh-port ]] || ssh_deadline=$(( SECONDS + ssh_wait ))
  while kill -0 "$timeout_pid" 2>/dev/null; do
    # The console file is this script's own creation inside its own work
    # directory; a stat failure here means it was removed under us, which is a
    # reason to stop, not a reason to keep waiting.
    size=$(stat -c %s -- "$console")
    if [[ ! "$size" =~ ^[0-9]+$ ]]; then
      PHASE_STOP=serial-log-vanished
      terminate_qemu_session "$timeout_pid"
      break
    fi
    if (( size > serial_max_bytes )); then
      PHASE_TRUNCATED=yes
      PHASE_STOP=serial-log-overflow
      terminate_qemu_session "$timeout_pid"
      break
    fi
    if [[ "$watcher" == ssh-port && "$PHASE_SSH" != open ]]; then
      # shellcheck disable=SC2016 # $1 is the child shell's positional parameter
      if timeout 2 bash -c 'exec 3<>/dev/tcp/127.0.0.1/"$1"' _ "$ssh_port"; then
        PHASE_SSH=open
      else
        PHASE_SSH=closed
        if (( SECONDS >= ssh_deadline )); then
          PHASE_STOP=ssh-wait-expired
          terminate_qemu_session "$timeout_pid"
          break
        fi
      fi
    fi
    if [[ -n "$failure" ]] && (( grace_deadline == 0 )) \
        && grep -Fq -- "$failure" "$console" 2>/dev/null; then
      PHASE_STOP=installer-refusal
      grace_deadline=$(( SECONDS + failure_grace ))
    fi
    if (( grace_deadline > 0 )); then
      if (( SECONDS >= grace_deadline )); then
        PHASE_STOP=refusal-without-poweroff
        terminate_qemu_session "$timeout_pid"
        break
      fi
      sleep 1
      continue
    fi
    # What "reached" means is decided ONCE, by the caller: a watched port when
    # there is one, otherwise the console marker. A phase whose verdict is the
    # port must not also require a serial line that may never be written.
    if [[ "$watcher" == ssh-port ]]; then
      [[ "$PHASE_SSH" == open ]] && reached=1
    elif grep -Fq -- "$success" "$console" 2>/dev/null; then
      reached=1
    fi
    if (( reached == 1 )); then
      sleep 2
      if ! qmp_guest_request "$qmp_socket" "$request"; then
        PHASE_STOP=qmp-request-refused
        terminate_qemu_session "$timeout_pid"
      elif ! wait_for_exit "$timeout_pid" 600; then
        PHASE_STOP=guest-did-not-exit
        terminate_qemu_session "$timeout_pid"
      else
        PHASE_STOP="$request"
      fi
      break
    fi
    sleep 1
  done
  local leader=$timeout_pid
  wait "$timeout_pid"
  PHASE_RC=$?
  if process_group_exists "$leader"; then
    terminate_qemu_session "$leader" || true
  fi
  PHASE_RESIDUAL=0
  process_group_exists "$leader" && PHASE_RESIDUAL=1
  timeout_pid=
  set -e
  rm -f -- "$qmp_socket"
  qmp_socket=
  (( PHASE_RESIDUAL == 0 )) || die "the $name QEMU process group survived bounded cleanup"
  if (( PHASE_RC == 124 )) && [[ "$PHASE_STOP" == none ]]; then PHASE_STOP='phase-timeout'; fi
}

declare -a qemu=()
build_qemu_base() {
  qemu=(
    qemu-system-aarch64
    -name "neural-ice-bench-rehearsal-$1"
    -machine "virt,accel=kvm,gic-version=3"
    -cpu host -smp "$smp" -m "$memory"
    # image/lib/hardware-identity.sh reads DMI. The medium is built for a GB10,
    # so the VM presents the GB10's DMI identity: an INPUT the medium already
    # accepts, not a branch inside the installer.
    -smbios "type=1,manufacturer=NVIDIA,product=NVIDIA_DGX_Spark"
    -smbios "type=2,manufacturer=NVIDIA,product=P4242"
    -drive "if=pflash,format=raw,unit=0,readonly=on,file=$firmware_code"
    -drive "if=pflash,format=raw,unit=1,file=$vars"
    -chardev "socket,id=chrtpm,path=$tpm_ctrl"
    -tpmdev "emulator,id=tpm0,chardev=chrtpm"
    -device "tpm-tis-device,tpmdev=tpm0"
    -device "virtio-keyboard-pci"
    -qmp "unix:$work_dir/$1.qmp.sock,server=on,wait=off"
  )
}

add_target_drive() {
  qemu+=(-drive "if=none,id=target,format=qcow2,file=$target,discard=unmap")
  case "$target_transport" in
    nvme)   qemu+=(-device "nvme,drive=target,serial=NIBENCHTARGET,bootindex=2") ;;
    virtio) qemu+=(-device "virtio-blk-pci,drive=target,bootindex=2") ;;
  esac
}

add_network() { # $1="" or a hostfwd fragment
  if [[ "$network" == isolated ]]; then
    qemu+=(-nic none)
    return 0
  fi
  # 🔴 NO `restrict=on` HERE, AND THAT IS THE POINT. QEMU documents restrict as
  # "the guest will be isolated, i.e. it will not be able to contact the host and
  # no guest IP packets will be routed over the host to the outside"
  # (qemu-system.1, -netdev user). The bench medium must reach the LAN mirror, so
  # the rehearsal uses plain user-mode NAT. What user mode does NOT carry is
  # multicast, so `registry.neural-ice.local` cannot be resolved by mDNS from
  # here — see the runbook.
  local nic="user,model=virtio-net-pci"
  [[ -z "$1" ]] || nic+=",$1"
  qemu+=(-nic "$nic")
}

# --------------------------------------------------------------------------- #
# Install phase.
# --------------------------------------------------------------------------- #
say "install phase: medium=$raw target=$target_size transport=$source_transport/$target_transport network=$network"
start_swtpm
build_qemu_base install
qemu+=(-drive "if=none,id=installer,format=raw,readonly=on,file=$raw")
case "$source_transport" in
  virtio) qemu+=(-device "virtio-blk-pci,drive=installer,bootindex=1") ;;
  nvme)   qemu+=(-device "nvme,drive=installer,serial=NIBENCHMEDIUM,bootindex=1") ;;
  usb)    qemu+=(-device "qemu-xhci,id=xhci" -device "usb-storage,drive=installer,bootindex=1,removable=on") ;;
esac
add_target_drive
add_network ""
qemu+=(-nographic -no-reboot)

run_phase install "$install_timeout" \
  'done — install completed' 'FAILED in phase ' send-key-ret ''
install_rc=$PHASE_RC
install_stop=$PHASE_STOP
install_truncated=$PHASE_TRUNCATED
stop_swtpm
say "install phase ended: qemu_rc=$install_rc stop=$install_stop"

install_facts=$work_dir/install.facts
ni_bench_parse_install_log "$work_dir/install.console.log" > "$install_facts"
install_outcome="$(awk -F= '$1=="outcome"{print $2; exit}' "$install_facts")"
say "install outcome: $install_outcome"

# The installer persists its bounded failure evidence — the closed-vocabulary
# code, the phase, and the live PCR7 — in one non-volatile EFI variable
# (ota/neural-ice-autoinstall.sh:151-166). That variable lives in the pflash
# varstore this run owns, so it is readable AFTER poweroff even though the tty1
# failure block never reaches the serial line. This is the only way to learn the
# VM's PCR7 when the coverage gate is what refused.
efi_facts=$work_dir/efi-evidence.facts
: > "$efi_facts"
if [[ "$have_virt_fw_vars" == yes ]]; then
  if virt-fw-vars -i "$vars" --output-json "$work_dir/firmware-vars.after.json"; then
    python3 - "$work_dir/firmware-vars.after.json" "$NI_BENCH_EFI_EVIDENCE_NAME" \
      "$NI_BENCH_EFI_EVIDENCE_GUID" > "$efi_facts" <<'PY'
import json
import re
import sys

path, name, guid = sys.argv[1:4]
with open(path, "r", encoding="utf-8") as handle:
    dump = json.load(handle)
found = None
for variable in dump.get("variables", []):
    if variable.get("name") == name and str(variable.get("guid", "")).lower() == guid.lower():
        found = variable
        break
if found is None:
    print("efi_evidence=absent")
    raise SystemExit(0)
try:
    raw = bytes.fromhex(found.get("data", ""))
except ValueError:
    print("efi_evidence=unreadable")
    raise SystemExit(0)
# efivarfs prepends four attribute bytes on WRITE; the firmware stores them in
# the variable header instead, so accept the payload with or without them.
if raw[:4] == b"\x07\x00\x00\x00":
    raw = raw[4:]
if len(raw) > 2048:
    print("efi_evidence=oversized")
    raise SystemExit(0)
try:
    text = raw.decode("ascii")
except UnicodeDecodeError:
    print("efi_evidence=not-ascii")
    raise SystemExit(0)
SHAPES = {
    "schema": r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,63}",
    "code": r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,63}",
    "phase": r"[0-9]{1,4}",
    "phase_total": r"[0-9]{1,4}",
    "stage": r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,63}",
    "detail": r"[0-9a-f]{12}|unavailable|unclassified",
    "pcr7": r"[0-9a-f]{64}|unavailable|unclassified",
    "pcr7_policy": r"[0-9a-f]{64}|unavailable|unclassified",
    "pcr7_verified": r"none|[0-9a-f]{64}(,[0-9a-f]{64}){0,3}|unclassified",
    "pcr7_verified_count": r"[0-9]{1,4}",
}
seen = {}
for line in text.splitlines():
    if "=" not in line:
        continue
    key, _, value = line.partition("=")
    if key not in SHAPES or key in seen:
        continue
    if re.fullmatch(SHAPES[key], value):
        seen[key] = value
print("efi_evidence=present")
for key in SHAPES:
    print(f"efi_{key}={seen.get(key, 'none')}")
PY
  else
    printf 'efi_evidence=varstore-unreadable\n' > "$efi_facts"
  fi
else
  printf 'efi_evidence=virt-fw-vars-absent\n' > "$efi_facts"
fi

# --------------------------------------------------------------------------- #
# First boot, only after a completed install.
# --------------------------------------------------------------------------- #
firstboot_facts=$work_dir/firstboot.facts
: > "$firstboot_facts"
firstboot_state=not-run
firstboot_rc=none
firstboot_stop=none
firstboot_truncated=no
firstboot_ssh=not-watched
if [[ "$install_outcome" == complete && "$skip_firstboot" == 0 ]]; then
  say "first boot: booting the installed target, waiting for TCP/22 on 127.0.0.1:$ssh_port"
  start_swtpm
  build_qemu_base firstboot
  add_target_drive
  add_network "hostfwd=tcp:127.0.0.1:${ssh_port}-:22"
  qemu+=(-nographic -no-reboot)
  # The success condition of a first boot is the operator key answering on TCP/22
  # (#162). The status mirror line is watched too, but the port is what decides,
  # because it is the thing an operator actually needs.
  run_phase firstboot "$firstboot_timeout" \
    '' '' system_powerdown ssh-port
  firstboot_rc=$PHASE_RC
  firstboot_stop=$PHASE_STOP
  firstboot_truncated=$PHASE_TRUNCATED
  firstboot_ssh=$PHASE_SSH
  stop_swtpm
  ni_bench_parse_firstboot_log "$work_dir/firstboot.console.log" > "$firstboot_facts"
  if [[ "$firstboot_ssh" == open ]]; then firstboot_state=ssh-open; else firstboot_state=ssh-never-opened; fi
  say "first boot ended: qemu_rc=$firstboot_rc stop=$firstboot_stop ssh=$firstboot_ssh"
elif [[ "$install_outcome" == complete ]]; then
  firstboot_state=skipped
fi

# --------------------------------------------------------------------------- #
# The receipt.
# --------------------------------------------------------------------------- #
# 🔴 EVERY VALUE CROSSES INTO THE RECEIPT THROUGH THE ENVIRONMENT, never through
# heredoc interpolation: a work directory or medium path containing a quote would
# otherwise write malformed JSON, and the receipt is the thing the lead reads.
NI_BENCH_SCHEMA="$NI_BENCH_RECEIPT_SCHEMA" \
NI_BENCH_RAW="$raw" NI_BENCH_WORK_DIR="$work_dir" \
NI_BENCH_ARCH="$(uname -m)" NI_BENCH_KERNEL="$(uname -r)" \
NI_BENCH_QEMU_VERSION="$(qemu-system-aarch64 --version | head -1)" \
NI_BENCH_SWTPM_VERSION="$(swtpm --version | head -1)" \
NI_BENCH_VIRT_FW_VARS="$have_virt_fw_vars" NI_BENCH_EUID="$EUID" \
NI_BENCH_SMP="$smp" NI_BENCH_MEMORY="$memory" \
NI_BENCH_SOURCE_TRANSPORT="$source_transport" NI_BENCH_TARGET_TRANSPORT="$target_transport" \
NI_BENCH_TARGET_SIZE="$target_size" NI_BENCH_NETWORK="$network" \
NI_BENCH_FIRMWARE_CODE="$firmware_code" NI_BENCH_FIRMWARE_VARS_ORIGIN="$firmware_vars_origin" \
NI_BENCH_ENROL_OWNER="$enrol_owner_guid" \
NI_BENCH_MIRROR_IP="$mirror_ip" NI_BENCH_MIRROR_PORT="$mirror_port" \
NI_BENCH_MIRROR_REACHABLE="$mirror_reachable" \
NI_BENCH_INSTALL_RC="$install_rc" NI_BENCH_INSTALL_STOP="$install_stop" \
NI_BENCH_INSTALL_TRUNCATED="$install_truncated" NI_BENCH_INSTALL_TIMEOUT="$install_timeout" \
NI_BENCH_FIRSTBOOT_STATE="$firstboot_state" NI_BENCH_FIRSTBOOT_RC="$firstboot_rc" \
NI_BENCH_FIRSTBOOT_STOP="$firstboot_stop" NI_BENCH_FIRSTBOOT_TRUNCATED="$firstboot_truncated" \
NI_BENCH_SSH_PORT="$ssh_port" NI_BENCH_SSH="$firstboot_ssh" \
NI_BENCH_SSH_WAIT="$ssh_wait" NI_BENCH_FIRSTBOOT_TIMEOUT="$firstboot_timeout" \
python3 - "$receipt" "$install_facts" "$efi_facts" "$firstboot_facts" <<'RECEIPT'
import json
import os
import sys

receipt_path, install_facts, efi_facts, firstboot_facts = sys.argv[1:5]


def facts(path):
    out = {}
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            key, sep, value = line.rstrip("\n").partition("=")
            if sep:
                out[key] = value
    return out


def number(name):
    raw = os.environ[name]
    return int(raw) if raw.lstrip("-").isdigit() else raw


work_dir = os.environ["NI_BENCH_WORK_DIR"]
receipt = {
    "schema": os.environ["NI_BENCH_SCHEMA"],
    "medium": os.environ["NI_BENCH_RAW"],
    "work_dir": work_dir,
    "host": {
        "arch": os.environ["NI_BENCH_ARCH"],
        "kernel": os.environ["NI_BENCH_KERNEL"],
        "qemu": os.environ["NI_BENCH_QEMU_VERSION"],
        "swtpm": os.environ["NI_BENCH_SWTPM_VERSION"],
        "virt_fw_vars": os.environ["NI_BENCH_VIRT_FW_VARS"],
        "euid": number("NI_BENCH_EUID"),
    },
    "vm": {
        "smp": number("NI_BENCH_SMP"),
        "memory_mib": number("NI_BENCH_MEMORY"),
        "source_transport": os.environ["NI_BENCH_SOURCE_TRANSPORT"],
        "target_transport": os.environ["NI_BENCH_TARGET_TRANSPORT"],
        "target_size": os.environ["NI_BENCH_TARGET_SIZE"],
        "network": os.environ["NI_BENCH_NETWORK"],
        "firmware_code": os.environ["NI_BENCH_FIRMWARE_CODE"],
        "firmware_vars_origin": os.environ["NI_BENCH_FIRMWARE_VARS_ORIGIN"],
        "enrol_owner_guid": os.environ["NI_BENCH_ENROL_OWNER"],
    },
    "mirror": {
        "ip": os.environ["NI_BENCH_MIRROR_IP"],
        "port": number("NI_BENCH_MIRROR_PORT"),
        "reachable_from_host": os.environ["NI_BENCH_MIRROR_REACHABLE"],
    },
    "install": {
        "qemu_exit": number("NI_BENCH_INSTALL_RC"),
        "stop_reason": os.environ["NI_BENCH_INSTALL_STOP"],
        "serial_log": os.path.join(work_dir, "install.console.log"),
        "serial_truncated": os.environ["NI_BENCH_INSTALL_TRUNCATED"],
        "timeout_seconds": number("NI_BENCH_INSTALL_TIMEOUT"),
    },
    "firstboot": {
        "state": os.environ["NI_BENCH_FIRSTBOOT_STATE"],
        "qemu_exit": number("NI_BENCH_FIRSTBOOT_RC"),
        "stop_reason": os.environ["NI_BENCH_FIRSTBOOT_STOP"],
        "serial_log": os.path.join(work_dir, "firstboot.console.log"),
        "serial_truncated": os.environ["NI_BENCH_FIRSTBOOT_TRUNCATED"],
        "ssh_port": number("NI_BENCH_SSH_PORT"),
        "ssh": os.environ["NI_BENCH_SSH"],
        "ssh_wait_seconds": number("NI_BENCH_SSH_WAIT"),
        "timeout_seconds": number("NI_BENCH_FIRSTBOOT_TIMEOUT"),
    },
}
receipt["install"].update(facts(install_facts))
receipt["efi_failure_evidence"] = facts(efi_facts)
receipt["firstboot"].update(facts(firstboot_facts))
with open(receipt_path, "w", encoding="utf-8") as handle:
    json.dump(receipt, handle, indent=2, sort_keys=True)
    handle.write("\n")
RECEIPT

say "receipt: $receipt"
cat -- "$receipt"

# 🔴 THE EXIT CODE IS THE VERDICT, and it is never softened. A rehearsal that did
# not install is a failed rehearsal even though every process was cleaned up.
case "$install_outcome" in
  complete) ;;
  *) die "the medium did not complete its installation (outcome=$install_outcome, stop=$install_stop)" ;;
esac
if [[ "$firstboot_state" == ssh-never-opened ]]; then
  die "the installed appliance never opened TCP/22 within ${ssh_wait}s of first boot"
fi
say "REHEARSAL COMPLETE (install=$install_outcome firstboot=$firstboot_state)"
