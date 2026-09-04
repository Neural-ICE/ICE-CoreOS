#!/usr/bin/env bash
# Offline proof that every image-enabled readiness/listener/root-extension path
# has a failure-propagating dependency on the TPM ceremony success gate.
set -euo pipefail

# The production wrapper deliberately forbids its path overrides at EUID 0.
# Keep this gate root-runnable for the lifecycle suite and container probes by
# dropping the entire read-only test process before any fixture is created.
if (( EUID == 0 )); then
  command -v runuser >/dev/null 2>&1 \
    || { echo "FAIL: runuser is required to exercise the unprivileged firstboot test seam" >&2; exit 1; }
  exec runuser -u nobody -- "$0" "$@"
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CF="$ROOT/image/Containerfile.bootc"
DROPIN="$ROOT/image/firstboot/50-neural-ice-tpm-ceremony-sshd.conf"
UNIT="$ROOT/image/firstboot/neural-ice-firstboot-tpm-ceremony.service"
CEREMONY="$ROOT/ota/neural-ice-firstboot-tpm-ceremony.sh"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/ni-tpm-ceremony-systemd.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

grep -qx 'Requires=neural-ice-firstboot-tpm-ceremony.service' "$DROPIN" || fail "gate drop-in has no hard Requires edge"
grep -qx 'After=neural-ice-firstboot-tpm-ceremony.service' "$DROPIN" || fail "gate drop-in has no ordering edge"
grep -qx 'OnFailure=emergency.target' "$UNIT" || fail "ceremony failure does not enter recovery"
grep -qx 'OnFailureJobMode=isolate' "$UNIT" || fail "ceremony failure does not isolate recovery"
grep -qx 'RequiredBy=multi-user.target' "$UNIT" || fail "multi-user readiness does not require ceremony success"
grep -qx 'DefaultDependencies=no' "$UNIT" \
  || fail "ceremony default dependencies would After=basic and cycle with sshd.socket"
grep -qx 'After=local-fs.target' "$UNIT" \
  || fail "ceremony is not ordered after local-fs"
grep -Fq '/run/neural-ice-device-root' "$UNIT" \
  || fail "ceremony sandbox cannot write the device-root runtime directory required by attest"
grep -Fq '/run/neural-ice-tpm-state' "$UNIT" \
  || fail "ceremony sandbox cannot write the TPM-state runtime directory"
grep -Fq '/run/neural-ice-access-profile-anchor' "$UNIT" \
  || fail "ceremony sandbox cannot write the access-profile-anchor runtime directory"
grep -Fq '/run/cryptsetup' "$UNIT" \
  || fail "ceremony sandbox cannot write /run/cryptsetup required to read LUKS2 metadata"
! grep -E '^(After|Before)=.*systemd-tmpfiles-setup\.service' "$UNIT" \
  || fail "ceremony must not After= or Before= tmpfiles-setup (cycles with sysext)"
! grep -E '^(After|Before)=.*sysinit\.target' "$UNIT" \
  || fail "ceremony Before=sysinit cycles with sshd.socket After=sysinit"
! grep -E '^(After|Before)=.*sockets\.target' "$UNIT" \
  || fail "ceremony Before=sockets is not required and widens the sysinit cycle"
# PrivateTmp=yes implicitly adds After=systemd-tmpfiles-setup.service (verified
# on systemd 255 and 257 with `systemctl show -p After`); sysext/confext are
# Requires=+After= this gate and Before= tmpfiles-setup, so `yes` is the cycle
# that made systemd 257 skip sysext/confext on QEMU first boot. `disconnected`
# keeps the private /tmp and adds no tmpfiles edge.
grep -qx 'PrivateTmp=disconnected' "$UNIT" \
  || fail "ceremony must use PrivateTmp=disconnected: PrivateTmp=yes re-adds After=tmpfiles-setup and cycles with sysext"
# The /etc overlay + generator that bridged pre-re-pin appliance digests from
# the medium is retired (2026-09-04 re-pin): the installer refuses an appliance
# whose own unit still cycles, instead of patching it.
for bridge in image/firstboot/10-neural-ice-firstboot-ceremony-sysinit.conf \
  image/firstboot/neural-ice-firstboot-ceremony-generator; do
  [[ ! -e "$ROOT/$bridge" ]] || fail "retired first-boot ceremony bridge is back in the tree: $bridge"
done
AUTOINSTALL="$ROOT/ota/neural-ice-autoinstall.sh"
! grep -Fq 'etc/systemd/system-generators/neural-ice-firstboot-ceremony"' "$AUTOINSTALL" \
  || { grep -Fq 'retired medium bridge' "$AUTOINSTALL" \
       || fail "the installer still stages the retired first-boot ceremony generator"; }

# Run the installer's verification block itself against crafted deployments.
# It must judge the EFFECTIVE unit (fragment + drop-ins, `Key = value`, line
# continuations, last assignment wins), not the raw fragment text: a drop-in
# that re-adds the cycle must be refused exactly like a cycling fragment.
verify_start="$(grep -n '^ceremony_unit_name=neural-ice-firstboot-tpm-ceremony\.service$' "$AUTOINSTALL" | cut -d: -f1)"
verify_end="$(grep -n '^log "first-boot ceremony unit verified on the pinned appliance' "$AUTOINSTALL" | cut -d: -f1)"
[[ -n "$verify_start" && -n "$verify_end" && "$verify_start" -lt "$verify_end" ]] \
  || fail "the installer's first-boot ceremony verification block is not where the test expects it"
verify_tmp="$TMP/verify"
mkdir -p "$verify_tmp"
{
  # shellcheck disable=SC2016 # shell source emitted verbatim into the harness
  printf 'die() { printf "REFUSED: %%s\\n" "$*"; exit 3; }\nlog() { printf "OK: %%s\\n" "$*"; }\ndep="$1"\n'
  sed -n "${verify_start},${verify_end}p" "$AUTOINSTALL"
} > "$verify_tmp/verify.sh"
verify_dep() { # <name> -> path of a deployment carrying the shipped unit
  local d="$verify_tmp/$1"
  mkdir -p "$d/usr/lib/systemd/system"
  cp -- "$UNIT" "$d/usr/lib/systemd/system/neural-ice-firstboot-tpm-ceremony.service"
  printf '%s\n' "$d"
}
verify_expect() { # <accept|refuse> <dep> <message fragment>
  local out
  out="$(bash "$verify_tmp/verify.sh" "$2" 2>&1)" || true
  case "$1" in
    accept) [[ "$out" == OK:* ]] || fail "installer refused the shipped ceremony unit ($3): $out" ;;
    refuse) [[ "$out" == REFUSED:*"$3"* ]] || fail "installer must refuse a deployment whose effective ceremony unit $3; got: $out" ;;
  esac
}
d="$(verify_dep shipped)"
verify_expect accept "$d" "as shipped"
d="$(verify_dep dropin-tmpfiles)"
mkdir -p "$d/usr/lib/systemd/system/neural-ice-firstboot-tpm-ceremony.service.d"
printf '[Unit]\nAfter = local-fs.target \\\n    systemd-tmpfiles-setup.service\n' \
  > "$d/usr/lib/systemd/system/neural-ice-firstboot-tpm-ceremony.service.d/90-test.conf"
verify_expect refuse "$d" "orders against tmpfiles-setup"
d="$(verify_dep dropin-privatetmp)"
mkdir -p "$d/usr/lib/systemd/system/service.d"
printf '[Service]\nPrivateTmp = yes\n' > "$d/usr/lib/systemd/system/service.d/90-test.conf"
verify_expect refuse "$d" "PrivateTmp=yes"
d="$(verify_dep dropin-defaultdeps)"
mkdir -p "$d/usr/lib/systemd/system/neural-ice-firstboot-tpm-ceremony.service.d"
printf '[Unit]\nDefaultDependencies=yes\n' \
  > "$d/usr/lib/systemd/system/neural-ice-firstboot-tpm-ceremony.service.d/90-test.conf"
verify_expect refuse "$d" "keeps default dependencies"
d="$(verify_dep etc-override)"
mkdir -p "$d/etc/systemd/system/neural-ice-firstboot-tpm-ceremony.service.d"
verify_expect refuse "$d" "overrides the pinned appliance's first-boot ceremony unit"
d="$(verify_dep etc-bridge)"
mkdir -p "$d/etc/systemd/system-generators"
: > "$d/etc/systemd/system-generators/neural-ice-firstboot-ceremony"
verify_expect refuse "$d" "retired first-boot ceremony medium bridge"
d="$(verify_dep continuation-comment)"
mkdir -p "$d/usr/lib/systemd/system/neural-ice-firstboot-tpm-ceremony.service.d"
printf '[Unit]\nAfter=local-fs.target \\\n# a comment inside the continuation is skipped by systemd\n  systemd-tmpfiles-setup.service\n' \
  > "$d/usr/lib/systemd/system/neural-ice-firstboot-tpm-ceremony.service.d/90-test.conf"
verify_expect refuse "$d" "orders against tmpfiles-setup"
d="$(verify_dep prefix-dropin-usr)"
mkdir -p "$d/usr/lib/systemd/system/neural-ice-firstboot-.service.d"
printf '[Unit]\nBefore=sysinit.target\n' > "$d/usr/lib/systemd/system/neural-ice-firstboot-.service.d/90-test.conf"
verify_expect refuse "$d" "orders against sysinit.target"
d="$(verify_dep prefix-dropin-etc)"
mkdir -p "$d/etc/systemd/system/neural-ice-.service.d"
printf '[Service]\nPrivateTmp=no\n' > "$d/etc/systemd/system/neural-ice-.service.d/90-test.conf"
verify_expect refuse "$d" "overrides the pinned appliance's first-boot ceremony unit"
d="$(verify_dep etc-service-d-privatetmp)"
mkdir -p "$d/etc/systemd/system/service.d"
printf '[Service]\nPrivateTmp=yes\n' > "$d/etc/systemd/system/service.d/90-test.conf"
verify_expect refuse "$d" "PrivateTmp=yes"
d="$(verify_dep benign-service-d)"
mkdir -p "$d/usr/lib/systemd/system/service.d"
printf '# Fedora ships this\n[Service]\nTimeoutStopFailureMode=abort\n' > "$d/usr/lib/systemd/system/service.d/10-timeout-abort.conf"
verify_expect accept "$d" "with the distribution's benign service.d drop-in"
d="$(verify_dep no-unit)"
rm -f -- "$d/usr/lib/systemd/system/neural-ice-firstboot-tpm-ceremony.service"
verify_expect refuse "$d" "ships no first-boot TPM ceremony unit"

dropin_units=(
  sshd.service sshd.socket getty@.service serial-getty@.service autovt@.service
  network-pre.target network.target network-online.target NetworkManager.service
  NetworkManager-wait-online.service avahi-daemon.service avahi-daemon.socket
  systemd-user-sessions.service user@.service neural-ice-payload-apply.service
  neural-ice-hostname-init.service neural-ice-dhcp-retry.service
  nvidia-device-nodes.service nvidia-cdi-generate.service
  neural-ice-device-root.service bootc-fetch-apply-updates.service
  bootc-fetch-apply-updates.timer systemd-sysext.service systemd-confext.service
)
for unit in "${dropin_units[@]}"; do
  destination="/usr/lib/systemd/system/$unit.d/50-neural-ice-tpm-ceremony.conf"
  grep -Fq "COPY image/firstboot/50-neural-ice-tpm-ceremony-sshd.conf $destination" "$CF" \
    || fail "$unit has no immutable hard-gate drop-in"
done

# These image-enabled firstboot units carry the dependency in their source so
# the proof covers the exact bytes systemd loads, not just the build recipe.
for source in \
  "$ROOT/image/firstboot/neural-ice-firstboot-sshkey.service" \
  "$ROOT/image/firstboot/neural-ice-firstboot-sshkey-activate.service" \
  "$ROOT/image/bootc-overlay/usr/lib/systemd/system/neural-ice-device-root.service"; do
  grep -Fq 'Requires=neural-ice-firstboot-tpm-ceremony.service' "$source" \
    || fail "$(basename "$source") lacks its hard ceremony edge"
done

# The composed image must carry one closed mode for all three public immutable
# inputs. The RUN assertion is the installed-artifact proof: a COPY-mode drift
# now breaks the image build instead of the first boot.
mode_block="$(sed -n '/chmod 0444 \/usr\/lib\/neural-ice\/access-policy/,/# Read the marker BACK/p' "$CF")"
for marker in access-policy hardware-target signed-boot-trust-policy-id; do
  grep -Fq "/usr/lib/neural-ice/$marker" <<<"$mode_block" \
    || fail "the image build does not normalize $marker to the immutable marker mode"
done
# shellcheck disable=SC2016 # exact Containerfile source assertion
grep -Fq 'test "$(stat -c '\''%u:%g:%a'\'' "$marker")" = 0:0:444' <<<"$mode_block" \
  || fail "the image build does not prove the installed immutable marker ownership and mode"

# Execute the real firstboot wrapper through its unprivileged test seam. The
# stubs model a complete legitimate boot but do not reimplement either file
# validator: the production script itself decides whether metadata is usable.
STATE="$TMP/state"
RUN="$TMP/run"
TOOLS="$TMP/tools"
MARKERS="$TMP/markers"
TPM_CALLED="$TMP/tpm-called"
mkdir -p "$TOOLS"

cat > "$TOOLS/tpm-state" <<'EOF'
#!/usr/bin/env bash
: > "$NI_TEST_TPM_CALLED"
case "$1" in
  completion-status) exit 1 ;;
  provisioning-status) exit 0 ;;
  ceremony-prepare) printf '1 1 %064d\n' 0 ;;
  state-snapshot) printf '{"freshness_counter":1,"install_counter":1,"schema":"neural-ice-tpm-state-snapshot-v1"}\n' ;;
  ceremony-finalize|runtime-status) exit 0 ;;
  *) exit 2 ;;
esac
EOF
cat > "$TOOLS/device-root" <<'EOF'
#!/usr/bin/env bash
[[ "$1" == attest && "$2" == --identity ]]
EOF
cat > "$TOOLS/profile-anchor" <<'EOF'
#!/usr/bin/env bash
case "$1" in
  enroll)
    printf '{"profile":"%s"}\n' "$4" > "$3/access-profile-v1.json"
    printf 'fixture-signature\n' > "$3/access-profile-v1.sig"
    printf 'fixture-spki\n' > "$3/access-profile-v1.spki" ;;
  verify) exit 0 ;;
  *) exit 2 ;;
esac
EOF
cat > "$TOOLS/systemd-analyze" <<'EOF'
#!/usr/bin/env bash
[[ "$1" == srk ]] || exit 2
printf 'fixture-srk\n'
EOF
cat > "$TOOLS/cryptsetup" <<'EOF'
#!/usr/bin/env bash
[[ "$1" == luksDump ]] || exit 2
printf '{}\n'
EOF
cat > "$TOOLS/luks-evidence" <<'EOF'
#!/usr/bin/env bash
printf '{"fixture":true}\n'
EOF
cat > "$TOOLS/tpm2-readpublic" <<'EOF'
#!/usr/bin/env bash
out=""
while (( $# )); do
  case "$1" in -n) out=$2; shift 2 ;; *) shift ;; esac
done
[[ -n "$out" ]] || exit 2
printf '\000\013fixture-name' > "$out"
EOF
chmod 0755 "$TOOLS"/*

prepare_fixture() {
  rm -rf "$STATE" "$RUN" "$MARKERS"
  mkdir -m 0700 "$STATE" "$RUN"
  mkdir -m 0755 "$MARKERS"
  printf 'access_profile=customer-locked\nhardware_target=nvidia-gb10-arm64\nsigned_boot_trust_policy_id=neural-ice-secureboot-lab-v1\ninitial_issuance_seq=1\n' \
    > "$STATE/owner-ceremony-intent-v1"
  printf '{"install_source":"medium","installed_at":"2026-09-01T00:00:00Z","installer_sealed_identity_sha256":"%064d","release_identity_sha256":"%064d","schema":"neural-ice-owner-ceremony-install-identity-v1"}\n' \
    0 0 > "$STATE/owner-ceremony-install-identity-v1.json"
  printf 'fixture-device-root\n' > "$STATE/device-root-v1.json"
  printf 'fixture-srk\n' > "$STATE/srk-v1.tpm2b_public"
  chmod 0600 "$STATE"/*
  printf 'customer-locked\n' > "$MARKERS/access-policy"
  printf 'nvidia-gb10-arm64\n' > "$MARKERS/hardware-target"
  printf 'neural-ice-secureboot-lab-v1\n' > "$MARKERS/signed-boot-trust-policy-id"
  chmod 0444 "$MARKERS"/*
  : > "$TMP/system-luks"; : > "$TMP/data-luks"
  rm -f "$TPM_CALLED"
}

run_ceremony() { # $1=script, optional $2=access-policy path
  local script=$1 access_policy=${2:-$MARKERS/access-policy}
  env NI_FIRSTBOOT_TPM_TESTING=1 \
    NI_FIRSTBOOT_TPM_TEST_VALIDATE_FILE_METADATA=1 \
    NI_FIRSTBOOT_TPM_TEST_STATE_DIR="$STATE" \
    NI_FIRSTBOOT_TPM_TEST_STATE="$TOOLS/tpm-state" \
    NI_FIRSTBOOT_TPM_TEST_DEVICE_ROOT="$TOOLS/device-root" \
    NI_FIRSTBOOT_TPM_TEST_PROFILE_ANCHOR="$TOOLS/profile-anchor" \
    NI_FIRSTBOOT_TPM_TEST_SYSTEM_LUKS="$TMP/system-luks" \
    NI_FIRSTBOOT_TPM_TEST_DATA_LUKS="$TMP/data-luks" \
    NI_FIRSTBOOT_TPM_TEST_ACCESS_POLICY="$access_policy" \
    NI_FIRSTBOOT_TPM_TEST_HARDWARE_TARGET="$MARKERS/hardware-target" \
    NI_FIRSTBOOT_TPM_TEST_TRUST_POLICY="$MARKERS/signed-boot-trust-policy-id" \
    NI_FIRSTBOOT_TPM_TEST_SYSTEMD_ANALYZE="$TOOLS/systemd-analyze" \
    NI_FIRSTBOOT_TPM_TEST_CRYPTSETUP="$TOOLS/cryptsetup" \
    NI_FIRSTBOOT_TPM_TEST_TPM2_READPUBLIC="$TOOLS/tpm2-readpublic" \
    NI_FIRSTBOOT_TPM_TEST_LUKS_EVIDENCE="$TOOLS/luks-evidence" \
    NI_FIRSTBOOT_TPM_TEST_RUN_ROOT="$RUN" \
    NI_TEST_TPM_CALLED="$TPM_CALLED" \
    bash "$script" boot
}

expect_pre_tpm_refusal() { # $1=label $2=diagnostic [$3=script] [$4=access-policy]
  local label=$1 diagnostic=$2 script=${3:-$CEREMONY} access_policy=${4:-$MARKERS/access-policy}
  local output
  if output="$(run_ceremony "$script" "$access_policy" 2>&1)"; then
    fail "$label was accepted"
  fi
  grep -Fq "$diagnostic" <<<"$output" || fail "$label refused for the wrong reason: $output"
  [[ ! -e "$TPM_CALLED" ]] || fail "$label reached TPM mutation after invalid file metadata"
}

prepare_fixture
[[ "$(run_ceremony "$CEREMONY")" == complete ]] \
  || fail "an exact 0600-evidence/0444-marker first boot did not complete"
[[ -e "$TPM_CALLED" ]] || fail "the exact-mode positive boot never reached the TPM lifecycle"

prepare_fixture
chmod 0644 "$MARKERS/access-policy"
expect_pre_tpm_refusal writable-marker 'required immutable marker is not mode 0444'

prepare_fixture
expect_pre_tpm_refusal wrong-owner-marker 'required immutable marker has the wrong owner' \
  "$CEREMONY" /proc/version

prepare_fixture
mv "$MARKERS/access-policy" "$MARKERS/access-policy.target"
ln -s access-policy.target "$MARKERS/access-policy"
expect_pre_tpm_refusal symlink-marker 'required immutable marker is not a regular file'

prepare_fixture
rm "$MARKERS/hardware-target"
expect_pre_tpm_refusal missing-marker 'required immutable marker is not a regular file'

prepare_fixture
chmod 0644 "$STATE/owner-ceremony-intent-v1"
expect_pre_tpm_refusal writable-evidence 'required mutable evidence is not mode 0600'

# Mutation oracle: restoring the old single all-0600 helper must make the exact
# legitimate image modes fail before TPM. This prevents a future refactor from
# silently recombining the two trust classes while keeping all negative cases.
MUTATED="$TMP/ceremony-all-0600.sh"
python3 - "$CEREMONY" "$MUTATED" <<'PY'
import sys
source = open(sys.argv[1], encoding="utf-8").read()
old = '  immutable_marker "$required"\n'
assert source.count(old) == 1
open(sys.argv[2], "w", encoding="utf-8").write(source.replace(old, '  secure_file "$required"\n'))
PY
prepare_fixture
expect_pre_tpm_refusal old-all-0600-helper 'required mutable evidence is not mode 0600' "$MUTATED"

# Guard the enabled set itself: adding a root-capable image unit without adding
# it to the gate list must make this suite fail during review.
enable_block="$(sed -n '/systemctl enable nvidia-device-nodes.service/,/avahi-daemon.service;/p' "$CF")"
for enabled in nvidia-device-nodes.service nvidia-cdi-generate.service \
  neural-ice-firstboot-sshkey.service neural-ice-firstboot-sshkey-activate.service \
  neural-ice-hostname-init.service neural-ice-payload-apply.service avahi-daemon.service; do
  grep -Fq "$enabled" <<<"$enable_block" || fail "$enabled disappeared from the audited enabled set"
  if [[ "$enabled" != neural-ice-firstboot-sshkey.service && "$enabled" != neural-ice-firstboot-sshkey-activate.service ]]; then
    printf '%s\n' "${dropin_units[@]}" | grep -qx "$enabled" || fail "$enabled is enabled but not hard-gated"
  fi
done

echo "TPM_CEREMONY_SYSTEMD_OFFLINE_TEST_OK (${#dropin_units[@]} direct consumers plus firstboot chain)"
