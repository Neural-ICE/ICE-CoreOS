#!/usr/bin/env bash
# shellcheck disable=SC2016 # literal source-contract assertions below
#
# Every `$` inside a single-quoted pattern here is DELIBERATELY literal: this
# file greps the first-boot script for its exact source text, so `"$pending"`
# must reach grep unexpanded. Expanding it would turn each check into a search
# for the empty string, which always matches.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HELPER="$ROOT/image/lib/installer-ssh-key.sh"
work="$(mktemp -d "${TMPDIR:-/tmp}/ni-installer-ssh-key.XXXXXX")"
trap 'rm -rf "$work"' EXIT

ssh-keygen -q -t ed25519 -N '' -f "$work/operator" </dev/null
key="$work/operator.pub"
digest="$(sha256sum "$key" | awk '{print $1}')"
if [[ "${digest:0:1}" == 0 ]]; then
  bad_digest="1${digest:1}"
else
  bad_digest="0${digest:1}"
fi

bash "$HELPER" validate '' ''
if bash "$HELPER" validate '' "$digest" >/dev/null 2>&1; then
  echo "hash-only installer SSH input was accepted" >&2
  exit 1
fi
if bash "$HELPER" validate "$key" '' >/dev/null 2>&1; then
  echo "key-only installer SSH input was accepted" >&2
  exit 1
fi
if bash "$HELPER" validate "$key" "$bad_digest" >/dev/null 2>&1; then
  echo "mismatched installer SSH key hash was accepted" >&2
  exit 1
fi
ln -s "$key" "$work/operator-link.pub"
if bash "$HELPER" validate "$work/operator-link.pub" "$digest" >/dev/null 2>&1; then
  echo "symlinked installer SSH key was accepted" >&2
  exit 1
fi
# The hash-free structural entrypoint is what the RUNTIME gates use, so it must
# refuse the same shapes on its own -- a symlink is the interesting one: on the
# installer ESP it is how an attacker points authorized_keys at another file.
if bash "$HELPER" validate-file "$work/operator-link.pub" >/dev/null 2>&1; then
  echo "structural validation accepted a symlinked key" >&2
  exit 1
fi
bash "$HELPER" validate-file "$key"

private_digest="$(sha256sum "$work/operator" | awk '{print $1}')"
if bash "$HELPER" validate "$work/operator" "$private_digest" >/dev/null 2>&1; then
  echo "private SSH key was accepted as an ESP public key" >&2
  exit 1
fi
if bash "$HELPER" validate-file "$work/operator" >/dev/null 2>&1; then
  echo "structural validation accepted a private key" >&2
  exit 1
fi

cp "$key" "$work/oversized.pub"
printf '%0512d' 0 >> "$work/oversized.pub"
oversized_digest="$(sha256sum "$work/oversized.pub" | awk '{print $1}')"
if bash "$HELPER" validate "$work/oversized.pub" "$oversized_digest" >/dev/null 2>&1; then
  echo "oversized kernel-command-line SSH key was accepted" >&2
  exit 1
fi

# Two records in one payload: the operator approves one key, and an appended
# second one would ride in on the same approval.
cat "$key" "$key" > "$work/multiple.pub"
if bash "$HELPER" validate-file "$work/multiple.pub" >/dev/null 2>&1; then
  echo "a payload holding two public keys was accepted" >&2
  exit 1
fi

base_image="registry.example/lab@sha256:$(printf '%064d' 1)"
bash "$HELPER" require-matching-target "$key" "$base_image" "$base_image"
if bash "$HELPER" require-matching-target "$key" "$base_image" \
  "registry.example/prod@sha256:$(printf '%064d' 2)" >/dev/null 2>&1; then
  echo "installer SSH key was accepted for a different install target" >&2
  exit 1
fi
bash "$HELPER" require-matching-target '' "$base_image" \
  "registry.example/prod@sha256:$(printf '%064d' 2)"

mkdir "$work/esp"
bash "$HELPER" install "$key" "$digest" "$work/esp"
cmp "$key" "$work/esp/ice-coreos/authorized_keys"
if bash "$HELPER" install "$key" "$digest" "$work/esp" >/dev/null 2>&1; then
  echo "existing ESP authorized_keys path was overwritten" >&2
  exit 1
fi


# --- the sealed keyless assertion -------------------------------------------
# The image build's promise that a non-debug variant ships NO baked key. The
# check this replaces grepped for lines STARTING with a key algorithm, so an
# options-prefixed authorized_keys record walked through it and stayed fully
# usable by sshd. The predicate is now "no non-whitespace bytes", exercised here
# as the same code the Containerfile runs.
keyless="$work/keyless"
: > "$keyless"
bash "$HELPER" assert-keyless "$keyless"
# What `printf '%s\n' "${SSH_AUTHORIZED_KEY}"` leaves behind for an empty build
# arg, and the only content that may pass.
printf '\n' > "$keyless"
bash "$HELPER" assert-keyless "$keyless"
printf ' \t\n\n' > "$keyless"
bash "$HELPER" assert-keyless "$keyless"

for smuggled_label in bare-key options-prefixed command-forced cert-authority \
  unknown-algorithm comment-line; do
  case "$smuggled_label" in
    bare-key)          printf '%s\n' "$(cat "$key")" > "$keyless" ;;
    # THE REGRESSION: `restrict ssh-ed25519 ...` is a valid authorized_keys
    # record and sshd honours it exactly like a bare one. The old
    # `^(ssh-|ecdsa-|sk-)` grep did not see it at all.
    options-prefixed)  printf 'restrict %s\n' "$(cat "$key")" > "$keyless" ;;
    command-forced)    printf 'command="/bin/bash",no-pty %s\n' "$(cat "$key")" > "$keyless" ;;
    cert-authority)    printf 'cert-authority %s\n' "$(cat "$key")" > "$keyless" ;;
    # An algorithm this repository has never heard of is still a key to sshd.
    unknown-algorithm) printf 'ssh-future-alg AAAAB3NzaC1 lab@host\n' > "$keyless" ;;
    comment-line)      printf '# %s\n' "$(cat "$key")" > "$keyless" ;;
  esac
  if bash "$HELPER" assert-keyless "$keyless" >/dev/null 2>&1; then
    echo "the keyless assertion accepted a $smuggled_label authorized_keys record" >&2
    exit 1
  fi
done

# A file that is not a real file is not evidence of anything.
rm -f "$keyless"
if bash "$HELPER" assert-keyless "$keyless" >/dev/null 2>&1; then
  echo "the keyless assertion accepted a missing file" >&2
  exit 1
fi
: > "$work/keyless-target"
ln -s "$work/keyless-target" "$keyless"
if bash "$HELPER" assert-keyless "$keyless" >/dev/null 2>&1; then
  echo "the keyless assertion accepted a symlink" >&2
  exit 1
fi
rm -f "$keyless"

# --- first-boot provisioning and activation ---------------------------------
# Every sealed variant ships sshd masked, so writing the key is only half the
# job: without the unmask the operator's key lands on a sealed image and nothing
# listens. And an image the medium is not ALLOWED to open must refuse the key
# outright. These run the REAL script through its test seams rather than a copy
# of its logic -- a test that reimplements the script proves nothing about it.
FIRSTBOOT="$ROOT/image/firstboot/neural-ice-firstboot-sshkey.sh"
PROVISION_UNIT="$ROOT/image/firstboot/neural-ice-firstboot-sshkey.service"
ACTIVATE_UNIT="$ROOT/image/firstboot/neural-ice-firstboot-sshkey-activate.service"

if [[ "${1:-}" == --root-seam-negative-only ]]; then
  (( EUID == 0 )) || { echo "root seam test must run as root" >&2; exit 1; }
  root_fixture="$work/root-seam"
  mkdir -p "$root_fixture"
  : >"$root_fixture/cmdline"
  if env NEURALICE_FIRSTBOOT_TESTING=1 \
      NEURALICE_FIRSTBOOT_ROOT="$root_fixture" \
      NEURALICE_FIRSTBOOT_CMDLINE="$root_fixture/cmdline" \
      bash "$FIRSTBOOT" provision >/dev/null 2>&1; then
    echo "root process accepted firstboot SSH environment seams" >&2
    exit 1
  fi
  echo "INSTALLER_SSH_ROOT_SEAM_REFUSAL_OK"
  exit 0
fi

stub_dir="$work/stub"
mkdir -p "$stub_dir"
# A STATEFUL stub that models systemd's JOB QUEUE, not just unit states. The
# previous one answered `exit 0` to everything, so `is-active` returned nothing
# and no test could tell a started sshd from an unstarted one -- which is
# exactly how the real defect shipped: on GB10, 2026-08-20, `enable --now`
# returned success one second into the first boot and sshd did not come up until
# the NEXT reboot. A stub that cannot express "succeeded but had no effect"
# cannot catch a bug whose whole shape is that.
#
# `start` therefore QUEUES the unit; the queued job only runs when nothing
# ordered Before=sshd.service is still executing. NI_TEST_UNIT_PHASE=provision
# models precisely that unit -- and is why the second defect shipped: a single
# oneshot ordered before sshd both queued the job and waited for it, so the wait
# could never succeed and a healthy lab boot recorded failure.
#
# NI_TEST_SSHD_STUBBORN=1 models a start that is accepted and has no effect.
cat > "$stub_dir/systemctl" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$NI_TEST_SYSTEMCTL_LOG"
state_file="${NI_TEST_SYSTEMCTL_LOG%.log}.sshd-state"
[ -f "$state_file" ] || printf 'masked\n' > "$state_file"
state() { cat "$state_file"; }
set_state() { printf '%s\n' "$1" > "$state_file"; }

# The manager runs a queued sshd job only once every unit ordered before it has
# exited. A caller running AS such a unit therefore never observes the effect.
release_queued() {
  [ "$(state)" = queued ] || return 0
  [ "${NI_TEST_UNIT_PHASE:-activate}" != provision ] || return 0
  if [ "${NI_TEST_SSHD_STUBBORN:-0}" = 1 ]; then set_state inactive; return 0; fi
  set_state active
}

case "${1:-}" in
  is-enabled) state; exit 0 ;;
  is-active)
    release_queued
    if [ "$(state)" = active ]; then printf 'active\n'; exit 0; fi
    printf 'inactive\n'; exit 3 ;;
  unmask)  set_state disabled; exit 0 ;;
  mask)    set_state masked; exit 0 ;;
  disable) [ "$(state)" = masked ] || set_state disabled; exit 0 ;;
  enable)  [ "$(state)" = masked ] || set_state enabled; exit 0 ;;
  start|restart)
    # The manager refuses to start a unit it still believes is masked, and says
    # nothing about it.
    [ "$(state)" = masked ] && exit 0
    # A SYNCHRONOUS start of a unit ordered after this one deadlocks: systemd
    # holds the job until this service exits. Model it as a hang, which is what
    # it was on hardware -- a stub that always returns cannot express the
    # failure the fix exists to prevent.
    if [ "${2:-}" != --no-block ] && [ "${3:-}" != --no-block ] \
       && [ "${NI_TEST_SSHD_DEADLOCK:-0}" = 1 ]; then
      printf 'DEADLOCK\n' >> "$NI_TEST_SYSTEMCTL_LOG"; sleep 30; exit 0
    fi
    set_state queued; exit 0 ;;
esac
exit 0
STUB
printf '#!/usr/bin/env bash\nexit 0\n' > "$stub_dir/logger"
chmod 0755 "$stub_dir/systemctl" "$stub_dir/logger"

# --- the unit contract ------------------------------------------------------
# The split only means anything if the UNITS say what the script assumes. These
# read the shipped unit files rather than restating them, and the boot driver
# below then obeys what it reads -- so a unit edited out of agreement with the
# script fails here instead of on an appliance.
unit_values() { # <unit-file> <key>  -> one value per line
  awk -v k="$2" 'index($0, k "=") == 1 { print substr($0, length(k) + 2) }' "$1"
}
unit_has() { # <unit-file> <key> <value>
  unit_values "$1" "$2" | tr ' ' '\n' | grep -qx -- "$3"
}

unit_has "$PROVISION_UNIT" Before sshd.service \
  || { echo "provisioning is not ordered before sshd: the key could be served before it is written" >&2; exit 1; }
unit_has "$PROVISION_UNIT" ConditionPathExists '!/var/lib/neural-ice/.sshkey-provisioned' \
  || { echo "provisioning is no longer gated on the once-only marker" >&2; exit 1; }
unit_values "$PROVISION_UNIT" ExecStart | grep -qx -- \
  '/usr/local/bin/neural-ice-firstboot-sshkey.sh provision' \
  || { echo "the provisioning unit does not run the provision phase" >&2; exit 1; }
unit_values "$ACTIVATE_UNIT" ExecStart | grep -qx -- \
  '/usr/local/bin/neural-ice-firstboot-sshkey.sh activate' \
  || { echo "the activation unit does not run the activate phase" >&2; exit 1; }
# THE ORDERING THE P1 WAS ABOUT. Activation must come after BOTH the provisioning
# oneshot and sshd itself; only then can it start sshd and observe the result.
unit_has "$ACTIVATE_UNIT" After neural-ice-firstboot-sshkey.service \
  || { echo "activation is not ordered after provisioning" >&2; exit 1; }
unit_has "$ACTIVATE_UNIT" After sshd.service \
  || { echo "activation is not ordered after sshd: its verification cannot succeed" >&2; exit 1; }
unit_has "$ACTIVATE_UNIT" Requires neural-ice-firstboot-sshkey.service \
  || { echo "activation does not require provisioning" >&2; exit 1; }
if unit_values "$ACTIVATE_UNIT" Before | grep -qx -- sshd.service; then
  echo "activation is ordered BEFORE sshd — this is the deadlock the split removes" >&2
  exit 1
fi
act_condition="$(unit_values "$ACTIVATE_UNIT" ConditionPathExists)"
[ "$act_condition" = /var/lib/neural-ice/sshkey-activation-pending ] \
  || { echo "the activation unit is not conditioned on the provisioning handoff" >&2; exit 1; }

# Build a fake installed root carrying the SAME immutable /usr layout the real
# image has: the policy marker plus the two libraries the script sources. The
# tests therefore exercise the real lookup path, not a special-cased one.
make_root() { # <root> <policy|"">  — "" means the marker is absent entirely
  local root="$1" policy="$2"
  mkdir -p "$root/usr/lib/neural-ice/lib" "$root/run"
  install -m 0644 "$ROOT/image/lib/access-policy.sh" \
    "$ROOT/image/lib/installer-ssh-key.sh" "$root/usr/lib/neural-ice/lib/"
  printf '%s\n' 'ghcr.io/neural-ice/neural-ice-coreos:test' \
    > "$root/usr/lib/neural-ice/ota-imgref"
  [ -z "$policy" ] || printf '%s\n' "$policy" > "$root/usr/lib/neural-ice/access-policy"
}

run_unit() { # <root> <subcommand> [ordering-phase]
  local root="$1" subcommand="$2" phase="${3:-$2}"
  NI_TEST_SYSTEMCTL_LOG="$root/systemctl.log" \
  NI_TEST_UNIT_PHASE="$phase" \
  NEURALICE_FIRSTBOOT_TESTING=1 \
  NEURALICE_FIRSTBOOT_ROOT="$root" \
  NEURALICE_FIRSTBOOT_CMDLINE="$root/cmdline" \
  NEURALICE_FIRSTBOOT_SSHD_TIMEOUT="${NI_TEST_SSHD_TIMEOUT:-2}" \
  NEURALICE_FIRSTBOOT_CRASH_AT="${NEURALICE_FIRSTBOOT_CRASH_AT:-}" \
  PATH="$stub_dir:$PATH" bash "$FIRSTBOOT" "$subcommand"
}

# One boot, driven the way systemd would drive it FROM THE UNIT FILES: run the
# provisioning oneshot; honour Requires= by not activating after a failure; and
# honour the activation unit's ConditionPathExists before running it.
run_boot() { # <root> <cmdline-content>
  local root="$1" cmdline="$2" rc=0
  mkdir -p "$root"
  printf '%s\n' "$cmdline" > "$root/cmdline"
  run_unit "$root" provision || rc=$?
  [ "$rc" -eq 0 ] || return "$rc"
  [ -e "$root$act_condition" ] || return 0
  run_unit "$root" activate
}

encoded_key="$(base64 -w0 < "$key")"
receipt_field() { # <root> <field>
  python3 -c 'import json,sys; print(json.dumps(json.load(open(sys.argv[1]))[sys.argv[2]]))' \
    "$1/var/lib/neural-ice/access-provisioning-receipt.json" "$2"
}
assert_untouched() { # <root> <label>
  [ ! -e "$1/var/home/core/.ssh/authorized_keys" ] \
    || { echo "$2: authorized_keys was written" >&2; exit 1; }
  [ ! -s "$1/systemctl.log" ] \
    || { echo "$2: sshd was touched" >&2; exit 1; }
  [ ! -e "$1$act_condition" ] \
    || { echo "$2: an activation handoff was staged for a refused key" >&2; exit 1; }
}

# An alternate root alone is never enough authority to redirect this root-run
# service, and an immutable release marker disables the seam even for a proper
# unprivileged test process.
unguarded="$work/root-unguarded"
make_root "$unguarded" lab-managed
printf 'quiet\n' >"$unguarded/cmdline"
if env NEURALICE_FIRSTBOOT_ROOT="$unguarded" \
    NEURALICE_FIRSTBOOT_CMDLINE="$unguarded/cmdline" \
    bash "$FIRSTBOOT" provision >/dev/null 2>&1; then
  echo "firstboot SSH seams worked without the explicit test guard" >&2
  exit 1
fi
assert_untouched "$unguarded" unguarded-seam

release_root="$work/root-release-marker"
make_root "$release_root" lab-managed
: >"$release_root/usr/lib/neural-ice/release-image"
printf 'quiet\n' >"$release_root/cmdline"
if run_unit "$release_root" provision >/dev/null 2>&1; then
  echo "firstboot SSH seams worked inside a marked release root" >&2
  exit 1
fi
assert_untouched "$release_root" release-root-seam

# --- lab-managed: the sealed lab image, key on the medium: written AND served.
provisioned="$work/root-lab"
make_root "$provisioned" lab-managed
run_boot "$provisioned" "root=/dev/sda neuralice.sshkey=${encoded_key} quiet"
cmp -s "$key" "$provisioned/var/home/core/.ssh/authorized_keys" \
  || { echo "first boot did not write the operator key it was given" >&2; exit 1; }
[ "$(stat -c %a "$provisioned/var/home/core/.ssh/authorized_keys")" = 600 ] \
  || { echo "provisioned authorized_keys is not 0600" >&2; exit 1; }
grep -qx 'unmask sshd.service' "$provisioned/systemctl.log" \
  || { echo "sshd was left MASKED: the provisioned key is unusable on a sealed image" >&2; exit 1; }
grep -q '^enable .*sshd.service' "$provisioned/systemctl.log" \
  || { echo "sshd was unmasked but never enabled" >&2; exit 1; }
[ "$(cat "$provisioned/systemctl.sshd-state" 2>/dev/null)" = active ] \
  || { echo "sshd is not active after a complete first boot" >&2; exit 1; }
[ -e "$provisioned/var/lib/neural-ice/.sshkey-provisioned" ] \
  || { echo "a proven-active sshd did not record the provisioning as complete" >&2; exit 1; }
[ ! -e "$provisioned$act_condition" ] \
  || { echo "the activation handoff outlived a successful activation" >&2; exit 1; }

# The receipt: bounded, root-only, and carrying no key material.
receipt="$provisioned/var/lib/neural-ice/access-provisioning-receipt.json"
[ "$(stat -c %a "$receipt")" = 600 ] \
  || { echo "the provisioning receipt is not 0600" >&2; exit 1; }
test "$(receipt_field "$provisioned" access_policy)" = '"lab-managed"'
test "$(receipt_field "$provisioned" ssh_provisioned)" = true
test "$(receipt_field "$provisioned" decision)" = '"provisioned"'
test "$(receipt_field "$provisioned" public_key_sha256)" = "\"$digest\""
test "$(receipt_field "$provisioned" recorded_at)" = null
test "$(receipt_field "$provisioned" source_installer_identity)" = null
test "$(receipt_field "$provisioned" image_ota_imgref)" = '"ghcr.io/neural-ice/neural-ice-coreos:test"'
grep -q "$(awk '{print $2}' < "$key")" "$receipt" \
  && { echo "the receipt contains the public key material itself" >&2; exit 1; }
[ "$(wc -c < "$receipt")" -le 1024 ] \
  || { echo "the receipt is not bounded" >&2; exit 1; }

# --- THE P1, AS A PROPERTY OF THE PROVISIONING PHASE ALONE.
# Ordered Before=sshd.service, this phase must never start sshd and never wait
# for it: systemd holds the sshd job until the oneshot exits, so both are
# guaranteed-useless work whose only observable effect was a false failure.
phase1="$work/root-phase1"
make_root "$phase1" lab-managed
printf '%s\n' "root=/dev/sda neuralice.sshkey=${encoded_key} quiet" > "$phase1/cmdline"
run_unit "$phase1" provision
if grep -qE '^(start|restart|is-active)' "$phase1/systemctl.log"; then
  echo "the provisioning phase started or polled sshd from a unit ordered before it" >&2
  exit 1
fi
[ ! -e "$phase1/var/lib/neural-ice/.sshkey-provisioned" ] \
  || { echo "provisioning recorded success before anything proved sshd serves the key" >&2; exit 1; }
[ -d "$phase1$act_condition" ] \
  || { echo "provisioning staged no handoff for the activation unit" >&2; exit 1; }
test "$(receipt_field "$phase1" decision)" = '"provisioned-pending-activation"'
test "$(receipt_field "$phase1" ssh_provisioned)" = false
# The handoff must carry no more than the activation phase needs, and it must
# not be world-readable: it names the key and the state to restore.
[ "$(stat -c %a "$phase1$act_condition")" = 700 ] \
  || { echo "the activation handoff is not 0700" >&2; exit 1; }

# ...and the activation phase, run afterwards, is what turns it into success.
run_unit "$phase1" activate
grep -qx 'start --no-block sshd.service' "$phase1/systemctl.log" \
  || { echo "activation did not queue sshd" >&2; exit 1; }
grep -qx 'is-active sshd.service' "$phase1/systemctl.log" \
  || { echo "activation never verified that sshd came up" >&2; exit 1; }
[ -e "$phase1/var/lib/neural-ice/.sshkey-provisioned" ] \
  || { echo "a verified-active sshd did not complete the provisioning" >&2; exit 1; }
test "$(receipt_field "$phase1" decision)" = '"provisioned"'

# THE ORDERING CONTRADICTION ITSELF, pinned behaviourally. Run the activation
# logic with the ordering the OLD single unit had -- Before=sshd.service, so the
# queued sshd job cannot run while it waits -- and it must fail and roll back.
# That is precisely the false failure the split removes: same code, same key,
# wrong unit.
contradiction="$work/root-ordering"
make_root "$contradiction" lab-managed
printf '%s\n' "root=/dev/sda neuralice.sshkey=${encoded_key} quiet" > "$contradiction/cmdline"
run_unit "$contradiction" provision
if run_unit "$contradiction" activate provision; then
  echo "activation reported success from a unit ordered before sshd — the poll cannot succeed there" >&2
  exit 1
fi
[ ! -e "$contradiction/var/home/core/.ssh/authorized_keys" ] \
  || { echo "a failed activation left the operator key on disk" >&2; exit 1; }
grep -qx 'mask sshd.service' "$contradiction/systemctl.log" \
  || { echo "a failed activation left sshd unmasked" >&2; exit 1; }
[ "$(cat "$contradiction/systemctl.sshd-state" 2>/dev/null)" = masked ] \
  || { echo "a failed activation did not restore the sealed sshd state" >&2; exit 1; }
[ ! -e "$contradiction/var/lib/neural-ice/.sshkey-provisioned" ] \
  || { echo "a rolled-back activation was recorded as a completed provisioning" >&2; exit 1; }
[ ! -e "$contradiction$act_condition" ] \
  || { echo "a rolled-back activation left its handoff behind" >&2; exit 1; }
test "$(receipt_field "$contradiction" decision)" = '"activation-failed-rolled-back"'
test "$(receipt_field "$contradiction" ssh_provisioned)" = false

# --- customer-locked: THE REGRESSION. A forged karg on a sealed CUSTOMER image
# must be refused outright: no authorized_keys, no systemctl, no silent drop.
# Before the immutable access policy existed, this script honoured the karg on
# EVERY non-debug image, so a crafted installer ESP opened SSH on `prod`.
locked="$work/root-customer"
make_root "$locked" customer-locked
if run_boot "$locked" "root=/dev/sda neuralice.sshkey=${encoded_key} quiet"; then
  echo "a customer-locked image accepted a forged SSH karg" >&2
  exit 1
fi
assert_untouched "$locked" "customer-locked + forged karg"
test "$(receipt_field "$locked" access_policy)" = '"customer-locked"'
test "$(receipt_field "$locked" ssh_provisioned)" = false
test "$(receipt_field "$locked" decision)" = '"policy-forbids-ssh"'
test "$(receipt_field "$locked" public_key_sha256)" = null

# A customer appliance with no key on its medium: normal, silent, successful.
sealed="$work/root-sealed"
make_root "$sealed" customer-locked
run_boot "$sealed" "root=/dev/sda quiet"
assert_untouched "$sealed" "customer-locked, no key"
test "$(receipt_field "$sealed" decision)" = '"no-key-offered"'
[ -e "$sealed/var/lib/neural-ice/.sshkey-provisioned" ] \
  || { echo "a keyless appliance did not complete its first boot" >&2; exit 1; }

# Repeated boot on a customer appliance that was attacked once: still refused,
# still nothing written. The marker must not turn a refusal into a silent pass.
: > "$locked/systemctl.log"
if run_boot "$locked" "root=/dev/sda neuralice.sshkey=${encoded_key} quiet"; then
  echo "a repeated boot let the forged karg through" >&2
  exit 1
fi
assert_untouched "$locked" "customer-locked + forged karg, second boot"

# --- unknown and missing policy both fail closed.
unknown="$work/root-unknown"
make_root "$unknown" wide-open
if run_boot "$unknown" "root=/dev/sda neuralice.sshkey=${encoded_key} quiet"; then
  echo "an unrecognised access policy was treated as permissive" >&2
  exit 1
fi
assert_untouched "$unknown" "unknown policy"
test "$(receipt_field "$unknown" decision)" = '"policy-unreadable"'
test "$(receipt_field "$unknown" access_policy)" = '"unknown"'

missing="$work/root-missing"
make_root "$missing" ""
if run_boot "$missing" "root=/dev/sda neuralice.sshkey=${encoded_key} quiet"; then
  echo "a missing access policy was treated as permissive" >&2
  exit 1
fi
assert_untouched "$missing" "missing policy"

# A missing policy is refused even with NO key offered: an image whose access
# posture cannot be read is not an image this service can reason about.
missing_nokey="$work/root-missing-nokey"
make_root "$missing_nokey" ""
if run_boot "$missing_nokey" "root=/dev/sda quiet"; then
  echo "a missing access policy passed when no key was offered" >&2
  exit 1
fi
assert_untouched "$missing_nokey" "missing policy, no key"

# --- malformed, multiple and oversized keys on a LAB-MANAGED image.
for case_name in not-base64 not-a-key two-keys private-key oversized; do
  bad_root="$work/root-bad-$case_name"
  make_root "$bad_root" lab-managed
  case "$case_name" in
    not-base64)  payload='!!!!not base64!!!!' ;;
    not-a-key)   payload="$(printf 'hello world\n' | base64 -w0)" ;;
    two-keys)    payload="$(base64 -w0 < "$work/multiple.pub")" ;;
    private-key) payload="$(base64 -w0 < "$work/operator")" ;;
    oversized)   payload="$(base64 -w0 < "$work/oversized.pub")" ;;
  esac
  if run_boot "$bad_root" "root=/dev/sda neuralice.sshkey=${payload} quiet"; then
    echo "a lab-managed image accepted a $case_name payload" >&2
    exit 1
  fi
  assert_untouched "$bad_root" "lab-managed + $case_name"
done

# An options-prefixed record must be refused on the KARG path too, for the same
# reason the sealed build refuses one: it is a usable authorized_keys line.
optioned="$work/root-optioned"
make_root "$optioned" lab-managed
printf 'restrict %s\n' "$(cat "$key")" > "$work/optioned.pub"
if run_boot "$optioned" \
  "root=/dev/sda neuralice.sshkey=$(base64 -w0 < "$work/optioned.pub") quiet"; then
  echo "a lab-managed image accepted an options-prefixed karg key" >&2
  exit 1
fi
assert_untouched "$optioned" "lab-managed + options-prefixed key"

# Two neuralice.sshkey arguments: ambiguous, and the old `sed .*` silently kept
# the last one -- which is how an appended karg replaces the operator's key.
ambiguous="$work/root-ambiguous"
make_root "$ambiguous" lab-managed
if run_boot "$ambiguous" \
  "root=/dev/sda neuralice.sshkey=${encoded_key} neuralice.sshkey=${encoded_key} quiet"; then
  echo "two SSH kargs were accepted" >&2
  exit 1
fi
assert_untouched "$ambiguous" "two SSH kargs"
test "$(receipt_field "$ambiguous" decision)" = '"ambiguous-karg"'

# --- the developer diagnostic image still provisions (it ships sshd enabled).
diag="$work/root-diagnostic"
make_root "$diag" developer-diagnostic
run_boot "$diag" "root=/dev/sda neuralice.sshkey=${encoded_key} quiet"
cmp -s "$key" "$diag/var/home/core/.ssh/authorized_keys" \
  || { echo "the developer diagnostic image did not provision its key" >&2; exit 1; }

# The marker is what makes this once-only: a later boot must not re-open sshd
# after an operator has deliberately masked it again.
: > "$provisioned/systemctl.log"
run_boot "$provisioned" "root=/dev/sda neuralice.sshkey=${encoded_key} quiet"
[ ! -s "$provisioned/systemctl.log" ] \
  || { echo "first-boot provisioning ran a second time" >&2; exit 1; }

# THE DEFECT THIS FILE DID NOT CATCH, now pinned.
#
# On GB10 (2026-08-20) sshd was unmasked one second into the first boot and never
# started: `enable --now` returned success while the manager still held its
# in-memory MASKED view, so the `|| logger` branch never fired and remote debug
# was unavailable for the whole first boot. The script must ASSERT that sshd is
# active, not that a command exited 0.
started="$work/root-started"
make_root "$started" lab-managed
run_boot "$started" "root=/dev/sda neuralice.sshkey=${encoded_key} quiet"
grep -qx 'daemon-reload' "$started/systemctl.log" \
  || { echo "sshd was unmasked without making the unmask visible to the manager" >&2; exit 1; }
[ "$(cat "$started/systemctl.sshd-state" 2>/dev/null)" = active ] \
  || { echo "sshd is not active after first-boot provisioning" >&2; exit 1; }

# And when starting genuinely has no effect, the script must SAY so rather than
# reporting a usable key -- and must not leave a key on disk that nothing serves
# behind an sshd it unmasked for it. This is the case the old one-liner reported
# as success. The marker stays unwritten, so the next boot retries from the karg.
stubborn="$work/root-stubborn"
make_root "$stubborn" lab-managed
if NI_TEST_SSHD_STUBBORN=1 run_boot "$stubborn" \
  "root=/dev/sda neuralice.sshkey=${encoded_key} quiet"; then
  echo "the script reported success while sshd never came up" >&2
  exit 1
fi
[ "$(cat "$stubborn/systemctl.sshd-state" 2>/dev/null)" = masked ] \
  || { echo "a stubborn sshd was left unmasked after the key was withdrawn" >&2; exit 1; }
grep -qx 'is-active sshd.service' "$stubborn/systemctl.log" \
  || { echo "the script never checked whether sshd actually came up" >&2; exit 1; }
[ ! -e "$stubborn/var/home/core/.ssh/authorized_keys" ] \
  || { echo "an unusable operator key was left in authorized_keys" >&2; exit 1; }
test "$(receipt_field "$stubborn" decision)" = '"activation-failed-rolled-back"'
test "$(receipt_field "$stubborn" ssh_provisioned)" = false
test "$(receipt_field "$stubborn" public_key_sha256)" = "\"$digest\""
[ ! -e "$stubborn/var/lib/neural-ice/.sshkey-provisioned" ] \
  || { echo "a failed sshd start was recorded as a completed provisioning" >&2; exit 1; }
# ...and the next boot retries from the karg rather than inheriting the failure.
: > "$stubborn/systemctl.log"
run_boot "$stubborn" "root=/dev/sda neuralice.sshkey=${encoded_key} quiet"
cmp -s "$key" "$stubborn/var/home/core/.ssh/authorized_keys" \
  || { echo "the boot after a rolled-back activation did not retry" >&2; exit 1; }
test "$(receipt_field "$stubborn" decision)" = '"provisioned"'

# The rollback removes EXACTLY the record it added. A community key placed by
# Ignition was here first and has nothing to do with this decision; destroying
# it would be a regression of its own.
coexist="$work/root-coexist"
make_root "$coexist" lab-managed
ssh-keygen -q -t ed25519 -N '' -f "$work/community" </dev/null
mkdir -p "$coexist/var/home/core/.ssh"
printf '%s' "$(cat "$work/community.pub")" > "$coexist/var/home/core/.ssh/authorized_keys"
chmod 0640 "$coexist/var/home/core/.ssh/authorized_keys"
cp -p "$coexist/var/home/core/.ssh/authorized_keys" "$work/community.before"
coexist_metadata="$(stat -c '%a:%u:%g' "$coexist/var/home/core/.ssh/authorized_keys")"
if NI_TEST_SSHD_STUBBORN=1 run_boot "$coexist" \
  "root=/dev/sda neuralice.sshkey=${encoded_key} quiet"; then
  echo "the coexistence case did not model an activation failure" >&2
  exit 1
fi
cmp -s "$work/community.before" "$coexist/var/home/core/.ssh/authorized_keys" \
  || { echo "the rollback destroyed a pre-existing community key" >&2; exit 1; }
[ "$(stat -c '%a:%u:%g' "$coexist/var/home/core/.ssh/authorized_keys")" = "$coexist_metadata" ] \
  || { echo "the rollback did not restore pre-existing authorized_keys metadata" >&2; exit 1; }

# The exact approved record may already belong to Ignition or an administrator.
# Provisioning must detect that fact under its lifecycle lock and leave every
# byte, duplicate, ordering choice and file attribute alone; a timeout rollback
# then has no authorized_keys mutation to undo.
assert_preexisting_exact_survives_timeout() { # $1=label $2=fixture $3=mode
  local label=$1 fixture=$2 mode=$3 root="$work/root-preexisting-$1"
  make_root "$root" lab-managed
  mkdir -p "$root/var/home/core/.ssh"
  cp "$fixture" "$root/var/home/core/.ssh/authorized_keys"
  chmod "$mode" "$root/var/home/core/.ssh/authorized_keys"
  cp -p "$root/var/home/core/.ssh/authorized_keys" "$work/$label.before"
  local metadata
  metadata="$(stat -c '%a:%u:%g' "$root/var/home/core/.ssh/authorized_keys")"
  if NI_TEST_SSHD_STUBBORN=1 run_boot "$root" \
    "root=/dev/sda neuralice.sshkey=${encoded_key} quiet"; then
    echo "$label: activation timeout was reported as success" >&2
    exit 1
  fi
  cmp -s "$work/$label.before" "$root/var/home/core/.ssh/authorized_keys" \
    || { echo "$label: timeout rollback changed pre-existing authorized_keys bytes" >&2; exit 1; }
  [ "$(stat -c '%a:%u:%g' "$root/var/home/core/.ssh/authorized_keys")" = "$metadata" ] \
    || { echo "$label: timeout rollback changed pre-existing authorized_keys metadata" >&2; exit 1; }
}

# Single exact record with no final newline: command substitution used by the
# old rollback necessarily changed these bytes even before deleting the match.
printf '%s' "$(cat "$key")" > "$work/preexisting-single"
assert_preexisting_exact_survives_timeout single "$work/preexisting-single" 0640

# Duplicate exact records are intentionally preserved. De-duplication is a
# mutation of authority owned by another path, not provisioning hygiene.
cat "$key" "$key" > "$work/preexisting-duplicate"
assert_preexisting_exact_survives_timeout duplicate "$work/preexisting-duplicate" 0600

# Comments, blank lines and record order are all meaningful existing content;
# neither provisioning nor rollback may canonicalize them.
{
  printf '# operator-managed ordering\n\n'
  cat "$work/community.pub"
  cat "$key"
  printf '# trailing content stays trailing\n'
} > "$work/preexisting-ordered"
assert_preexisting_exact_survives_timeout ordered "$work/preexisting-ordered" 0644

# Power interruption oracle. The journal is staged before the newly approved
# record is written. A second provision invocation models the next boot: it
# must first undo the interrupted transaction, then retry. A subsequent timeout
# restores the original absence rather than leaving the twice-staged key.
interrupted_new="$work/root-interrupted-new"
make_root "$interrupted_new" lab-managed
printf '%s\n' "root=/dev/sda neuralice.sshkey=${encoded_key} quiet" > "$interrupted_new/cmdline"
run_unit "$interrupted_new" provision
[ -f "$interrupted_new/var/home/core/.ssh/authorized_keys" ] \
  || { echo "the power-interruption fixture never reached the key mutation" >&2; exit 1; }
[ -d "$interrupted_new$act_condition" ] \
  || { echo "the power-interruption fixture staged no rollback journal" >&2; exit 1; }
# ...and a temporary image stranded in ~core/.ssh by the same interruption is
# cleaned up rather than left holding the operator key under another name.
: > "$interrupted_new/var/home/core/.ssh/.neural-ice-authorized_keys.new"
run_unit "$interrupted_new" provision
[ ! -e "$interrupted_new/var/home/core/.ssh/.neural-ice-authorized_keys.new" ] \
  || { echo "an interrupted mutation left its temporary key image behind" >&2; exit 1; }
if NI_TEST_SSHD_STUBBORN=1 run_unit "$interrupted_new" activate; then
  echo "the interrupted retry's activation timeout was reported as success" >&2
  exit 1
fi
[ ! -e "$interrupted_new/var/home/core/.ssh/authorized_keys" ] \
  || { echo "power-interruption recovery did not restore authorized_keys absence" >&2; exit 1; }

# The same interruption when the approved record pre-existed must keep its
# exact bytes and metadata across stale-journal recovery and timeout rollback.
interrupted_existing="$work/root-interrupted-existing"
make_root "$interrupted_existing" lab-managed
mkdir -p "$interrupted_existing/var/home/core/.ssh"
cp "$work/preexisting-ordered" "$interrupted_existing/var/home/core/.ssh/authorized_keys"
chmod 0640 "$interrupted_existing/var/home/core/.ssh/authorized_keys"
cp -p "$interrupted_existing/var/home/core/.ssh/authorized_keys" "$work/interrupted-existing.before"
interrupted_metadata="$(stat -c '%a:%u:%g' "$interrupted_existing/var/home/core/.ssh/authorized_keys")"
printf '%s\n' "root=/dev/sda neuralice.sshkey=${encoded_key} quiet" > "$interrupted_existing/cmdline"
run_unit "$interrupted_existing" provision
run_unit "$interrupted_existing" provision
if NI_TEST_SSHD_STUBBORN=1 run_unit "$interrupted_existing" activate; then
  echo "the pre-existing interruption timeout was reported as success" >&2
  exit 1
fi
cmp -s "$work/interrupted-existing.before" \
  "$interrupted_existing/var/home/core/.ssh/authorized_keys" \
  || { echo "power interruption changed pre-existing authorized_keys bytes" >&2; exit 1; }
[ "$(stat -c '%a:%u:%g' "$interrupted_existing/var/home/core/.ssh/authorized_keys")" = "$interrupted_metadata" ] \
  || { echo "power interruption changed pre-existing authorized_keys metadata" >&2; exit 1; }

# A THIRD WRITER between provision and activate. The file now matches neither
# journalled image, so rollback cannot know which bytes are authority. It must
# refuse rather than overwrite -- and it must not REPORT a rollback it did not
# perform: the handoff survives for the next boot, the marker stays unwritten,
# and sshd -- the half whose prior state is unambiguous -- is closed anyway.
contended="$work/root-contended"
make_root "$contended" lab-managed
printf '%s\n' "root=/dev/sda neuralice.sshkey=${encoded_key} quiet" > "$contended/cmdline"
run_unit "$contended" provision
cp "$contended/var/home/core/.ssh/authorized_keys" "$work/contended.provisioned"
{ cat "$work/contended.provisioned"; cat "$work/community.pub"; } \
  > "$contended/var/home/core/.ssh/authorized_keys"
cp "$contended/var/home/core/.ssh/authorized_keys" "$work/contended.third-writer"
if NI_TEST_SSHD_STUBBORN=1 run_unit "$contended" activate; then
  echo "a refused rollback was reported as a successful activation" >&2
  exit 1
fi
cmp -s "$work/contended.third-writer" \
  "$contended/var/home/core/.ssh/authorized_keys" \
  || { echo "the refused rollback overwrote a third writer's authorized_keys" >&2; exit 1; }
[ -d "$contended$act_condition" ] \
  || { echo "a refused rollback discarded the only journal of what it changed" >&2; exit 1; }
[ ! -e "$contended/var/lib/neural-ice/.sshkey-provisioned" ] \
  || { echo "a refused rollback still marked the appliance provisioned" >&2; exit 1; }
[ "$(receipt_field "$contended" decision)" = '"activation-failed-rollback-refused"' ] \
  || { echo "the receipt claims a rollback that was refused" >&2; exit 1; }
[ "$(receipt_field "$contended" ssh_provisioned)" = false ] \
  || { echo "a refused rollback reported the appliance as SSH-provisioned" >&2; exit 1; }
[ "$(cat "$contended/systemctl.sshd-state")" = masked ] \
  || { echo "a refused rollback left sshd unmasked and unserved" >&2; exit 1; }
# ...and the next boot refuses too, fail-closed and loudly, instead of
# re-provisioning on top of a file it cannot account for.
if run_unit "$contended" provision; then
  echo "the next boot re-provisioned over an unaccountable authorized_keys" >&2
  exit 1
fi
[ "$(receipt_field "$contended" decision)" = '"stale-handoff-unrecoverable"' ] \
  || { echo "the next boot did not record why it refused the stale handoff" >&2; exit 1; }
cmp -s "$work/contended.third-writer" \
  "$contended/var/home/core/.ssh/authorized_keys" \
  || { echo "the stale-handoff refusal still rewrote authorized_keys" >&2; exit 1; }

# A handoff path that is not a directory is refused before anything is decided.
badhandoff="$work/root-badhandoff"
make_root "$badhandoff" lab-managed
mkdir -p "$badhandoff/var/lib/neural-ice"
: > "$badhandoff$act_condition"
printf '%s\n' "root=/dev/sda neuralice.sshkey=${encoded_key} quiet" > "$badhandoff/cmdline"
if run_unit "$badhandoff" provision; then
  echo "a non-directory activation handoff was accepted" >&2
  exit 1
fi
[ ! -e "$badhandoff/var/home/core/.ssh/authorized_keys" ] \
  || { echo "a non-directory handoff still reached the key mutation" >&2; exit 1; }
[ ! -s "$badhandoff/systemctl.log" ] \
  || { echo "a non-directory handoff still touched sshd" >&2; exit 1; }
[ -f "$badhandoff$act_condition" ] && [ ! -d "$badhandoff$act_condition" ] \
  || { echo "the refusal replaced the handoff path it could not interpret" >&2; exit 1; }
[ "$(receipt_field "$badhandoff" decision)" = '"invalid-handoff-path"' ] \
  || { echo "the refusal did not record an invalid handoff path" >&2; exit 1; }

# =========================================================================== #
# 🔴 POWER-LOSS INJECTION AT EVERY PHASE OF THE ROLLBACK TRANSACTION.
#
# WHAT THIS COVERS (independent review 2026-09-02, P1 #2 and P2). The previous
# suite could reach exactly one interruption -- "provisioning ran, activation did
# not" -- because that is the only state a script that runs to completion can be
# left in. Every OTHER crash state was unasserted:
#
#   journal-staged     the journal was built but never published
#   journal-published  it was published and nothing has been mutated yet
#   backup-linked      the prior file's inode is held under a second name
#   new-written        the composed image exists but has not been renamed
#   mutated            the rename happened; nothing is fsynced
#   mutated-synced     the file and its directory are durable; the receipt is not
#   rolled-back        the undo is durable and the journal has not been removed
#
# The script carries a seam that stops it at each of those, inert unless an
# ALTERNATE ROOT is in force. Each state is then followed by a NEXT BOOT, and the
# whole point is that the next boot converges: the same bytes, the same mode,
# owner, group, mtime, ACL, xattrs and the SAME INODE, or -- where there was
# nothing before -- the same absence, including the absence of ~core/.ssh itself.
# =========================================================================== #
crash_phases=(journal-staged journal-published backup-linked new-written
  mutated mutated-synced rolled-back)

fingerprint_state() { # $1=root -> "<sha>|<mode>:<uid>:<gid>|<inode>|<nlink>|<mtime>"
  local target="$1/var/home/core/.ssh/authorized_keys"
  if [ ! -e "$target" ]; then printf 'ABSENT'; return 0; fi
  printf '%s|%s|%s' \
    "$(sha256sum "$target" | awk '{print $1}')" \
    "$(stat -c '%a:%u:%g' "$target")" \
    "$(stat -c '%i|%h|%.9Y' "$target")"
}
dir_state() { # $1=root
  local target="$1/var/home/core/.ssh"
  if [ ! -d "$target" ]; then printf 'ABSENT'; return 0; fi
  stat -c '%a:%u:%g:%.9Y' "$target"
}
ssh_dir_entries() { # $1=root
  local target="$1/var/home/core/.ssh"
  [ -d "$target" ] || { printf 'ABSENT'; return 0; }
  find "$target" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort | tr '\n' ' '
}

# --- case A: an operator's file was already there --------------------------- #
# Its inode is what carries the ACL, the SELinux context and every xattr, so
# "restored" has to mean the same inode, not the same bytes.
for phase in "${crash_phases[@]}"; do
  root="$work/crash-existing-$phase"
  make_root "$root" lab-managed
  mkdir -p "$root/var/home/core/.ssh"
  printf '%s' "$(cat "$work/community.pub")" > "$root/var/home/core/.ssh/authorized_keys"
  chmod 0640 "$root/var/home/core/.ssh/authorized_keys"
  touch -d '@1600000000.123456789' "$root/var/home/core/.ssh/authorized_keys"
  touch -d '@1600000001.987654321' "$root/var/home/core/.ssh"
  before_file="$(fingerprint_state "$root")"
  before_dir="$(dir_state "$root")"
  printf '%s\n' "root=/dev/sda neuralice.sshkey=${encoded_key} quiet" > "$root/cmdline"

  NEURALICE_FIRSTBOOT_CRASH_AT="$phase" run_unit "$root" provision >/dev/null 2>&1 && rc=0 || rc=$?
  case "$phase" in
    rolled-back)
      # This phase is only reachable through a rollback, so drive one: provision
      # completes, activation times out, and the crash lands after the undo is
      # durable but before the journal stops existing.
      [ "$rc" -eq 0 ] || { echo "$phase: provisioning did not complete" >&2; exit 1; }
      NEURALICE_FIRSTBOOT_CRASH_AT="$phase" NI_TEST_SSHD_STUBBORN=1 \
        run_unit "$root" activate >/dev/null 2>&1 && rc=0 || rc=$?
      [ "$rc" -eq 99 ] \
        || { echo "$phase: the rollback crash seam never fired (rc=$rc)" >&2; exit 1; }
      [ -d "$root$act_condition" ] \
        || { echo "$phase: the journal was removed before the undo was durable" >&2; exit 1; }
      ;;
    journal-staged|journal-published|new-written|mutated|mutated-synced|backup-linked)
      # backup-linked is the one seam that legitimately may not fire when there
      # is no prior file; with one there is, so every phase here must stop.
      [ "$rc" -eq 99 ] \
        || { echo "$phase: the crash seam never fired (rc=$rc)" >&2; exit 1; }
      ;;
  esac

  # THE NEXT BOOT. It replays whatever it finds, then re-decides; a second
  # activation timeout must land the appliance exactly where it started.
  run_unit "$root" provision >/dev/null 2>&1 \
    || { echo "$phase: the next boot could not reconcile the interrupted transaction" >&2; exit 1; }
  if NI_TEST_SSHD_STUBBORN=1 run_unit "$root" activate >/dev/null 2>&1; then
    echo "$phase: the retry's activation timeout was reported as success" >&2
    exit 1
  fi
  after_file="$(fingerprint_state "$root")"
  after_dir="$(dir_state "$root")"
  [ "$before_file" = "$after_file" ] \
    || { echo "$phase: authorized_keys did not converge (bytes|mode:uid:gid|inode|nlink|mtime): $before_file -> $after_file" >&2; exit 1; }
  [ "$before_dir" = "$after_dir" ] \
    || { echo "$phase: ~core/.ssh metadata did not converge: $before_dir -> $after_dir" >&2; exit 1; }
  [ "$(ssh_dir_entries "$root")" = "authorized_keys " ] \
    || { echo "$phase: ~core/.ssh holds leftovers: $(ssh_dir_entries "$root")" >&2; exit 1; }
  [ ! -e "$root$act_condition" ] \
    || { echo "$phase: a reconciled transaction left its journal behind" >&2; exit 1; }
  [ ! -e "$root/var/lib/neural-ice/.sshkey-activation-pending.staging" ] \
    || { echo "$phase: an unpublished staging journal was left behind" >&2; exit 1; }
  [ ! -e "$root/var/lib/neural-ice/.sshkey-provisioned" ] \
    || { echo "$phase: a rolled-back appliance was marked provisioned" >&2; exit 1; }
done

# --- case B: there was nothing there, and nothing must remain --------------- #
# Including ~core/.ssh itself: a directory this gate created is a directory this
# gate removes, and the journal is what records that it did not exist before.
for phase in "${crash_phases[@]}"; do
  root="$work/crash-absent-$phase"
  make_root "$root" lab-managed
  printf '%s\n' "root=/dev/sda neuralice.sshkey=${encoded_key} quiet" > "$root/cmdline"
  NEURALICE_FIRSTBOOT_CRASH_AT="$phase" run_unit "$root" provision >/dev/null 2>&1 && rc=0 || rc=$?
  if [ "$phase" = rolled-back ]; then
    NEURALICE_FIRSTBOOT_CRASH_AT="$phase" NI_TEST_SSHD_STUBBORN=1 \
      run_unit "$root" activate >/dev/null 2>&1 || true
  fi
  run_unit "$root" provision >/dev/null 2>&1 \
    || { echo "absent/$phase: the next boot could not reconcile" >&2; exit 1; }
  if NI_TEST_SSHD_STUBBORN=1 run_unit "$root" activate >/dev/null 2>&1; then
    echo "absent/$phase: the retry's activation timeout was reported as success" >&2
    exit 1
  fi
  [ "$(fingerprint_state "$root")" = ABSENT ] \
    || { echo "absent/$phase: an operator key survived a rollback of a file that never existed" >&2; exit 1; }
  [ "$(dir_state "$root")" = ABSENT ] \
    || { echo "absent/$phase: rollback kept a ~core/.ssh it had created itself" >&2; exit 1; }
  [ ! -e "$root$act_condition" ] \
    || { echo "absent/$phase: a reconciled transaction left its journal behind" >&2; exit 1; }
done

# =========================================================================== #
# 🔴 THE CROSS-FILESYSTEM ORDERING, MODELLED AND ASSERTED STRUCTURALLY.
#
# /var/lib holds the journal and /var/home holds authorized_keys, and they can be
# different filesystems. The defect was that rollback removed the journal without
# fsyncing either the restored file or its parent directory: journal removal
# reaching stable storage while the ~core/.ssh unlink did not is a boot that comes
# up with the injected key present and NO record that this gate put it there --
# and the boot after that classifies the identical key as pre-existing
# (key_added=0), so rollback would deliberately never remove it again.
#
# A test cannot cut power to a real disk here. What it CAN do is pin the ordering
# that makes the loss impossible, in the one function that owns it, and prove the
# crash BETWEEN the two halves is survivable -- which the `rolled-back` phase
# above already did. Both halves are asserted, because either alone is weak.
# =========================================================================== #
commit_body="$(awk '/^commit_rollback\(\) \{/,/^}$/' "$FIRSTBOOT")"
[ -n "$commit_body" ] \
  || { echo "the durable-undo commit is no longer a single named function; its ordering cannot be pinned" >&2; exit 1; }
target_sync_line="$(grep -n 'fsync_path "\$authorized_dir"' <<<"$commit_body" | head -1 | cut -d: -f1)"
journal_removal_line="$(grep -n 'rm -rf -- "\$pending"' <<<"$commit_body" | head -1 | cut -d: -f1)"
state_sync_line="$(grep -n 'fsync_path "\$STATE_DIR"' <<<"$commit_body" | head -1 | cut -d: -f1)"
[ -n "$target_sync_line" ] && [ -n "$journal_removal_line" ] && [ -n "$state_sync_line" ] \
  || { echo "commit_rollback no longer fsyncs the target, removes the journal and fsyncs the state directory" >&2; exit 1; }
[ "$target_sync_line" -lt "$journal_removal_line" ] \
  || { echo "the journal is removed before the undo is durable on the TARGET filesystem (line $journal_removal_line <= $target_sync_line)" >&2; exit 1; }
[ "$journal_removal_line" -lt "$state_sync_line" ] \
  || { echo "the journal removal is not itself made durable after the fact" >&2; exit 1; }
# ...and no other path may delete the journal behind that function's back.
stray_removals="$(grep -c 'rm -rf "\$pending"' "$FIRSTBOOT" || true)"
[ "$stray_removals" = 0 ] \
  || { echo "$stray_removals journal removals bypass commit_rollback and its ordering" >&2; exit 1; }
grep -q 'sync -- "\$1"' "$FIRSTBOOT" \
  || { echo "the durability primitive no longer fsyncs a named path" >&2; exit 1; }

# =========================================================================== #
# 🔴 THE JOURNAL IS PUBLISHED ATOMICALLY, NEVER POPULATED IN PLACE.
#
# It used to be created under its FINAL public name and filled by six independent
# writes. A power loss inside those published a PARTIAL journal, and the next boot
# -- which demands every field before it will recognise even the clean "nothing
# was mutated" state -- refused forever, over a transaction that had not touched
# authorized_keys at all. That is fail-closed, and it is not a recoverable crash
# state machine.
# =========================================================================== #
grep -q 'mv -fT "\$staging" "\$pending"' "$FIRSTBOOT" \
  || { echo "the journal is no longer published by an atomic rename" >&2; exit 1; }
grep -Eq 'install -d -m 0700 "\$pending"' "$FIRSTBOOT" \
  && { echo "the journal is created under its public name again" >&2; exit 1; }

# A partial staging directory is a journal that was never published, so nothing
# it describes was ever done: the next boot must discard it and provision
# normally rather than treat it as evidence.
partial="$work/root-partial-staging"
make_root "$partial" lab-managed
mkdir -p "$partial/var/lib/neural-ice/.sshkey-activation-pending.staging"
printf 'neural-ice-sshkey-rollback-journal-v2\n' \
  > "$partial/var/lib/neural-ice/.sshkey-activation-pending.staging/schema"
printf '%s\n' "root=/dev/sda neuralice.sshkey=${encoded_key} quiet" > "$partial/cmdline"
run_unit "$partial" provision >/dev/null 2>&1 \
  || { echo "an unpublished staging journal blocked provisioning" >&2; exit 1; }
[ ! -e "$partial/var/lib/neural-ice/.sshkey-activation-pending.staging" ] \
  || { echo "the unpublished staging journal survived provisioning" >&2; exit 1; }
cmp -s "$key" "$partial/var/home/core/.ssh/authorized_keys" \
  || { echo "the boot after an unpublished staging journal did not provision" >&2; exit 1; }

# A PUBLISHED journal from a format this appliance does not understand is
# evidence, not scratch: it is kept, and provisioning refuses.
#
# 🔴 THE FIXTURE IS DELIBERATELY COMPLETE. A journal that is merely TRUNCATED is
# refused by the field reads alone, so a truncated one proves nothing about the
# schema gate. This one is well-formed in every respect a future reader would
# recognise -- every v2 field, valid values, a state that would otherwise replay
# cleanly -- and differs ONLY in the format word. An appliance that replays a
# format it does not understand is guessing at what was already done to
# authorized_keys, which is the one thing this journal exists to remove.
assert_unrecognised_journal_is_kept() { # $1=label $2=schema-word $3=populate-fn
  local label=$1 schema=$2 populate=$3 root="$work/root-journal-$1"
  make_root "$root" lab-managed
  # 0700, because that is what publish_journal actually leaves behind: the
  # staging directory is created `install -d -m 0700` and becomes the handoff by
  # one rename. A fixture at the shell's umask would be a journal this gate never
  # writes, and the custody check would then be refusing the FIXTURE rather than
  # the format word this case is about.
  install -d -m 0700 "$root$act_condition"
  printf '%s\n' "$schema" > "$root$act_condition/schema"
  "$populate" "$root$act_condition"
  printf '%s\n' "root=/dev/sda neuralice.sshkey=${encoded_key} quiet" > "$root/cmdline"
  if run_unit "$root" provision >/dev/null 2>&1; then
    echo "$label: a journal in an unrecognised format was provisioned over" >&2
    exit 1
  fi
  [ -d "$root$act_condition" ] \
    || { echo "$label: a journal in an unrecognised format was deleted instead of kept" >&2; exit 1; }
  [ ! -e "$root/var/home/core/.ssh/authorized_keys" ] \
    || { echo "$label: an unrecognised journal still reached the key mutation" >&2; exit 1; }
  [ "$(receipt_field "$root" decision)" = '"stale-handoff-unrecoverable"' ] \
    || { echo "$label: an unrecognised journal did not produce the stable refusal decision" >&2; exit 1; }
}

# Complete in every field a v2 reader wants, and in a state a v2 reader would
# happily call "already rolled back" -- so only the format word refuses it.
populate_complete_journal() { # $1=journal dir
  printf 'lab-managed\n'  > "$1/policy"
  printf '%s\n' "$digest" > "$1/key_sha256"
  printf 'SHA256:%s\n' "$(printf 'A%.0s' {1..43})" > "$1/fingerprint"
  printf '0\n' > "$1/sshd_was_masked"
  printf '1\n' > "$1/key_added"
  printf '0\n' > "$1/authorized_existed"
  printf '0\n' > "$1/dir_existed"
  printf '%s\n' "$(printf 'f%.0s' {1..64})" > "$1/after_sha256"
  install -m 0600 "$key" "$1/key.pub"
}
# A future format whose field names happen to overlap.
assert_unrecognised_journal_is_kept future   neural-ice-sshkey-rollback-journal-v3 populate_complete_journal
# ...and the previous one, whose semantics were images-on-disk rather than hashes.
populate_v1_journal() {
  populate_complete_journal "$1"
  rm -f "$1/after_sha256"
  cp "$key" "$1/authorized_keys.after"
}
assert_unrecognised_journal_is_kept legacy   neural-ice-sshkey-rollback-journal-v1 populate_v1_journal

# =========================================================================== #
# THE OPERATOR RECOVERY CONTRACT. A gate that can refuse indefinitely must say,
# ON THE MACHINE, what a human is expected to do about it -- otherwise
# "fail closed" is indistinguishable from "broken" (review 2026-09-02, product
# question 3).
# =========================================================================== #
contract="$work/root-contract"
make_root "$contract" lab-managed
printf '%s\n' "root=/dev/sda neuralice.sshkey=${encoded_key} quiet" > "$contract/cmdline"
run_unit "$contract" provision >/dev/null 2>&1
[ -f "$contract$act_condition/RECOVERY" ] \
  || { echo "the journal carries no operator recovery contract" >&2; exit 1; }
for phrase in 'before_sha256' 'after_sha256' 'stale-handoff-unrecoverable' \
  'access-provisioning-receipt.json' '.neural-ice-authorized_keys.backup' \
  'HARD LINK'; do
  grep -Fq "$phrase" "$contract$act_condition/RECOVERY" \
    || { echo "the recovery contract never mentions: $phrase" >&2; exit 1; }
done
# It must not carry key material: the fingerprint and the hashes are the record.
grep -Fq "$(awk '{print $2}' "$key")" "$contract$act_condition/RECOVERY" \
  && { echo "the recovery contract leaks the public key blob into prose" >&2; exit 1; }
[ "$(stat -c %a "$contract$act_condition")" = 700 ] \
  || { echo "the journal directory is not root-only" >&2; exit 1; }

# =========================================================================== #
# 🔴 EXACT METADATA: ACL, SELINUX CONTEXT, XATTRS AND INODE IDENTITY.
#
# This is what `cp -p` silently could not do, and what the tests could not see
# because they compared bytes plus mode:uid:gid only (review 2026-09-02, P2). The
# fix is not a better copy: it is NOT COPYING. A hard link inside the target
# directory holds the operator's original inode, and rollback renames that name
# back -- so mode, owner, group, mtime, ACL, SELinux context, every xattr and the
# inode number itself are restored because they never moved.
#
# ctime is the one exception, and it is not glossed: Linux offers no way to set
# it, so it is stated here as a known, irreducible difference.
#
# Each tool below is optional in a build environment. An ABSENT tool is REPORTED,
# never silently skipped: a run that could not check xattrs must not read as a run
# that checked them.
# =========================================================================== #
metadata_root="$work/root-metadata"
make_root "$metadata_root" lab-managed
mkdir -p "$metadata_root/var/home/core/.ssh"
cp "$work/community.pub" "$metadata_root/var/home/core/.ssh/authorized_keys"
chmod 0640 "$metadata_root/var/home/core/.ssh/authorized_keys"
metadata_target="$metadata_root/var/home/core/.ssh/authorized_keys"
# A second hard link OUTSIDE the directory: the operator's other provisioning
# path may own one, and restoring by copy would silently break it.
ln "$metadata_target" "$work/metadata-external-link"

checked_surfaces=()
skipped_surfaces=()
# EVERY mutation first, EVERY baseline afterwards. Setting an ACL adds a
# `system.posix_acl_access` xattr, so a baseline captured between the two would
# be comparing the file against a state it was never in -- a test failure that
# says nothing about the rollback.
if command -v setfattr >/dev/null 2>&1 && command -v getfattr >/dev/null 2>&1 \
  && setfattr -n user.neural-ice-test -v rollback-marker "$metadata_target" 2>/dev/null; then
  checked_surfaces+=(xattr)
else
  skipped_surfaces+=("xattr (setfattr/getfattr unavailable, or the filesystem refuses user.* xattrs)")
fi
if command -v setfacl >/dev/null 2>&1 && command -v getfacl >/dev/null 2>&1 \
  && setfacl -m u:"$(id -u)":r -- "$metadata_target" 2>/dev/null; then
  checked_surfaces+=(acl)
else
  skipped_surfaces+=("POSIX ACL (setfacl/getfacl unavailable, or the filesystem has no ACL support)")
fi
if command -v getfattr >/dev/null 2>&1 \
  && getfattr -n security.selinux --only-values -- "$metadata_target" >/dev/null 2>&1; then
  checked_surfaces+=(selinux)
else
  skipped_surfaces+=("SELinux context (no security.selinux xattr on this filesystem; a real enforcing appliance is the only place this can be proved)")
fi
before_xattr=""; before_acl=""; before_selinux=""
command -v getfattr >/dev/null 2>&1 \
  && before_xattr="$(getfattr -d -m . -- "$metadata_target" 2>/dev/null | tail -n +2)"
command -v getfacl >/dev/null 2>&1 \
  && before_acl="$(getfacl -pc -- "$metadata_target" 2>/dev/null)"
command -v getfattr >/dev/null 2>&1 \
  && before_selinux="$(getfattr -n security.selinux --only-values -- "$metadata_target" 2>/dev/null || true)"
before_inode="$(stat -c '%i|%h|%a:%u:%g|%.9Y' "$metadata_target")"

printf '%s\n' "root=/dev/sda neuralice.sshkey=${encoded_key} quiet" > "$metadata_root/cmdline"
run_unit "$metadata_root" provision >/dev/null 2>&1
grep -qxF "$(cat "$key")" "$metadata_target" \
  || { echo "provisioning did not append the approved record" >&2; exit 1; }
# While the transaction is open the held inode is a SECOND NAME for the original.
[ -f "$metadata_root/var/home/core/.ssh/.neural-ice-authorized_keys.backup" ] \
  || { echo "the prior file's inode is not held for rollback" >&2; exit 1; }
if NI_TEST_SSHD_STUBBORN=1 run_unit "$metadata_root" activate >/dev/null 2>&1; then
  echo "the metadata case's activation timeout was reported as success" >&2
  exit 1
fi

cmp -s "$work/community.pub" "$metadata_target" \
  || { echo "the rollback did not restore the prior bytes" >&2; exit 1; }
[ "$(stat -c '%i|%h|%a:%u:%g|%.9Y' "$metadata_target")" = "$before_inode" ] \
  || { echo "the rollback did not restore the original INODE, link count, mode/owner or mtime: $before_inode -> $(stat -c '%i|%h|%a:%u:%g|%.9Y' "$metadata_target")" >&2; exit 1; }
[ "$(stat -c %i "$work/metadata-external-link")" = "$(stat -c %i "$metadata_target")" ] \
  || { echo "the rollback broke a hard link the operator's other path owned" >&2; exit 1; }
for surface in "${checked_surfaces[@]}"; do
  case "$surface" in
    xattr)
      [ "$(getfattr -d -m . -- "$metadata_target" 2>/dev/null | tail -n +2)" = "$before_xattr" ] \
        || { echo "the rollback lost the file's extended attributes" >&2; exit 1; } ;;
    acl)
      [ "$(getfacl -pc -- "$metadata_target" 2>/dev/null)" = "$before_acl" ] \
        || { echo "the rollback lost the file's POSIX ACL" >&2; exit 1; } ;;
    selinux)
      [ "$(getfattr -n security.selinux --only-values -- "$metadata_target" 2>/dev/null)" = "$before_selinux" ] \
        || { echo "the rollback lost the file's SELinux context" >&2; exit 1; } ;;
  esac
done
[ "${#checked_surfaces[@]}" -ge 1 ] \
  || { echo "not one metadata surface could be checked in this environment; the exact-restore claim is unproven here" >&2; exit 1; }
echo "  [rollback metadata] proved: ${checked_surfaces[*]} + inode/link identity, mode, owner, mtime"
if [ "${#skipped_surfaces[@]}" -gt 0 ]; then
  printf '  [rollback metadata] NOT PROVED HERE: %s\n' "${skipped_surfaces[@]}"
fi
echo "  [rollback metadata] ctime is NOT restored and cannot be: Linux offers no interface to set it"

# ...and it restores only the enablement state it changed. A developer
# diagnostic image ships sshd unmasked; a failed activation there must not
# invent a sealed posture nobody asked for.
unmasked="$work/root-unmasked"
make_root "$unmasked" developer-diagnostic
mkdir -p "$unmasked"
printf 'enabled\n' > "$unmasked/systemctl.sshd-state"
if NI_TEST_SSHD_STUBBORN=1 run_boot "$unmasked" \
  "root=/dev/sda neuralice.sshkey=${encoded_key} quiet"; then
  echo "an already-unmasked sshd that never started was reported as success" >&2
  exit 1
fi
grep -qx 'mask sshd.service' "$unmasked/systemctl.log" \
  && { echo "the rollback masked an sshd that provisioning had not unmasked" >&2; exit 1; }
[ "$(cat "$unmasked/systemctl.sshd-state")" != masked ] \
  || { echo "the rollback sealed a developer diagnostic image" >&2; exit 1; }

# The deadlock, pinned. On GB10 (2026-08-20) the unit sat in `activating (start)`
# with `systemctl start sshd.service` as its only child: the service was ordered
# Before=sshd.service, so systemd held the sshd job until it exited, and it was
# waiting for that very job. Neither phase may issue a blocking start.
dl="$work/root-deadlock"
make_root "$dl" lab-managed
export NI_TEST_SSHD_DEADLOCK=1
_t0=$(date +%s)
run_boot "$dl" "root=/dev/sda neuralice.sshkey=${encoded_key} quiet"
_elapsed=$(( $(date +%s) - _t0 ))
unset NI_TEST_SSHD_DEADLOCK
[ "$_elapsed" -lt 20 ] \
  || { echo "firstboot blocked ${_elapsed}s under a modelled deadlock — the start is not queued" >&2; exit 1; }
! grep -q DEADLOCK "$dl/systemctl.log" 2>/dev/null \
  || { echo "the script issued a blocking start" >&2; exit 1; }

# =========================================================================== #
# 🔴 THE FOUR CASES THE PREVIOUS SUITE COULD NOT SEE (independent review
# 2026-09-02, P1 #4 and P1 #5).
#
# Every existing success case started from an appliance with NO prior
# authorized_keys, so the whole hard-link backup lifecycle was exercised only on
# the ROLLBACK path. On the SUCCESS path nothing released it -- the operator's
# prior key bytes stayed on disk under a second name, the old inode stayed
# reachable, and its link count never came back down. And every concurrency case
# ran one process, so a waiter that observed "no marker" before blocking was
# never asked what it does after another process publishes one.
# =========================================================================== #

# --------------------------------------------------------------------------- #
# 1) SUCCESS, STARTING FROM AN APPLIANCE THAT ALREADY HAD A KEY.
# --------------------------------------------------------------------------- #
oldfile="$work/root-success-oldfile"
make_root "$oldfile" lab-managed
mkdir -p "$oldfile/var/home/core/.ssh"
printf 'ssh-ed25519 %s existing@operator\n' "$(printf 'A%.0s' {1..68})" \
  > "$oldfile/var/home/core/.ssh/authorized_keys"
chmod 0640 "$oldfile/var/home/core/.ssh/authorized_keys"
oldfile_prior_inode="$(stat -c '%i' "$oldfile/var/home/core/.ssh/authorized_keys")"
printf '%s\n' "root=/dev/sda neuralice.sshkey=${encoded_key} quiet" > "$oldfile/cmdline"
run_unit "$oldfile" provision >/dev/null 2>&1 \
  || { echo "provisioning over a pre-existing authorized_keys failed" >&2; exit 1; }
[ -f "$oldfile/var/home/core/.ssh/.neural-ice-authorized_keys.backup" ] \
  || { echo "provisioning did not hold the prior authorized_keys for rollback" >&2; exit 1; }
run_unit "$oldfile" activate >/dev/null 2>&1 \
  || { echo "activation over a pre-existing authorized_keys failed" >&2; exit 1; }

# 🔴 THE LEAK. The backup is a second NAME for the operator's PRIOR key bytes.
# On success it must be gone; leaving it is stale key material plus a reachable
# old inode plus a link count that never returns.
[ ! -e "$oldfile/var/home/core/.ssh/.neural-ice-authorized_keys.backup" ] \
  || { echo "a successful provisioning leaked its hard-link backup of the prior key" >&2; exit 1; }
grep -q 'existing@operator' "$oldfile/var/home/core/.ssh/authorized_keys" \
  || { echo "the prior operator record was lost from the published authorized_keys" >&2; exit 1; }
grep -qxF -- "$(cat "$key")" "$oldfile/var/home/core/.ssh/authorized_keys" \
  || { echo "the approved key was not appended" >&2; exit 1; }
# The published file is a NEW inode with exactly one name...
[ "$(stat -c '%h' "$oldfile/var/home/core/.ssh/authorized_keys")" = 1 ] \
  || { echo "the published authorized_keys has more than one name" >&2; exit 1; }
[ "$(stat -c '%i' "$oldfile/var/home/core/.ssh/authorized_keys")" != "$oldfile_prior_inode" ] \
  || { echo "the published authorized_keys is the prior inode; the append rewrote the operator's file in place" >&2; exit 1; }
# ...and the journal is retired, because the transaction is complete.
[ ! -e "$oldfile$act_condition" ] \
  || { echo "a successful transaction left its journal behind" >&2; exit 1; }
[ -f "$oldfile/var/lib/neural-ice/.sshkey-provisioned" ] \
  || { echo "a successful transaction did not write the marker" >&2; exit 1; }
[ "$(receipt_field "$oldfile" decision)" = '"provisioned"' ] \
  || { echo "a successful transaction over a prior key did not record it" >&2; exit 1; }

# --------------------------------------------------------------------------- #
# 2) EXTERNAL HARD LINKS SURVIVE A SUCCESS.
#
# The operator's prior file may have other names elsewhere on the same
# filesystem -- a backup tool, a second account, a bind-mounted path. Success
# replaces `authorized_keys`; it must take exactly that ONE name away from the
# prior inode and leave every other one intact, with its bytes.
# --------------------------------------------------------------------------- #
extlink="$work/root-success-external-link"
make_root "$extlink" lab-managed
mkdir -p "$extlink/var/home/core/.ssh" "$extlink/var/backup"
printf 'ssh-ed25519 %s external@operator\n' "$(printf 'B%.0s' {1..68})" \
  > "$extlink/var/home/core/.ssh/authorized_keys"
ln "$extlink/var/home/core/.ssh/authorized_keys" "$extlink/var/backup/authorized_keys.kept"
external_inode="$(stat -c '%i' "$extlink/var/backup/authorized_keys.kept")"
external_sha="$(sha256sum "$extlink/var/backup/authorized_keys.kept" | awk '{print $1}')"
[ "$(stat -c '%h' "$extlink/var/home/core/.ssh/authorized_keys")" = 2 ] \
  || { echo "the external hard-link fixture was not created" >&2; exit 1; }
printf '%s\n' "root=/dev/sda neuralice.sshkey=${encoded_key} quiet" > "$extlink/cmdline"
run_unit "$extlink" provision >/dev/null 2>&1 \
  || { echo "provisioning over an externally hard-linked authorized_keys failed" >&2; exit 1; }
# Under the transaction the prior inode carries TWO names: the operator's
# external one and this gate's backup. `~core/.ssh/authorized_keys` is no longer
# one of them -- the publish rename gave that name to the newly composed file,
# which is exactly why the backup has to exist at all.
[ "$(stat -c '%h' "$extlink/var/backup/authorized_keys.kept")" = 2 ] \
  || { echo "the transaction did not hold the prior inode by its backup name" >&2; exit 1; }
[ -f "$extlink/var/home/core/.ssh/.neural-ice-authorized_keys.backup" ] \
  || { echo "the transaction did not hold the prior authorized_keys for rollback" >&2; exit 1; }
run_unit "$extlink" activate >/dev/null 2>&1 \
  || { echo "activation over an externally hard-linked authorized_keys failed" >&2; exit 1; }
[ ! -e "$extlink/var/home/core/.ssh/.neural-ice-authorized_keys.backup" ] \
  || { echo "the backup name survived a success on an externally linked file" >&2; exit 1; }
# 🔴 THE OPERATOR'S OTHER NAME IS UNTOUCHED: same inode, same bytes, and the
# link count is back to exactly one -- the transaction took `authorized_keys`
# away from it and nothing else.
[ "$(stat -c '%i' "$extlink/var/backup/authorized_keys.kept")" = "$external_inode" ] \
  || { echo "the operator's external hard link no longer refers to the original inode" >&2; exit 1; }
[ "$(sha256sum "$extlink/var/backup/authorized_keys.kept" | awk '{print $1}')" = "$external_sha" ] \
  || { echo "the operator's external hard link lost its bytes" >&2; exit 1; }
[ "$(stat -c '%h' "$extlink/var/backup/authorized_keys.kept")" = 1 ] \
  || { echo "the prior inode's link count did not return to its pre-transaction value minus the one name this gate took" >&2; exit 1; }

# --------------------------------------------------------------------------- #
# 3) A CLEANUP THAT CANNOT COMPLETE KEEPS THE JOURNAL AND SAYS SO.
#
# The key is served, so the transaction is not rolled back -- but a success that
# cannot release its backup has left the appliance in a state the journal is the
# only record of. It must not write the marker and delete that record.
# --------------------------------------------------------------------------- #
cleanupfail="$work/root-cleanup-failure"
make_root "$cleanupfail" lab-managed
mkdir -p "$cleanupfail/var/home/core/.ssh"
printf 'ssh-ed25519 %s cleanup@operator\n' "$(printf 'C%.0s' {1..68})" \
  > "$cleanupfail/var/home/core/.ssh/authorized_keys"
printf '%s\n' "root=/dev/sda neuralice.sshkey=${encoded_key} quiet" > "$cleanupfail/cmdline"
run_unit "$cleanupfail" provision >/dev/null 2>&1 \
  || { echo "provisioning for the cleanup-failure case failed" >&2; exit 1; }
# Break exactly the cleanup: give the prior inode an extra name so the link
# count the journal recorded is no longer the one the release will observe. The
# key is still served; only the cleanup's own proof fails.
ln "$cleanupfail/var/home/core/.ssh/.neural-ice-authorized_keys.backup" \
   "$cleanupfail/var/home/core/.ssh/.unexpected-extra-name"
if run_unit "$cleanupfail" activate >/dev/null 2>&1; then
  echo "activation reported success although its cleanup could not be proved" >&2
  exit 1
fi
[ -d "$cleanupfail$act_condition" ] \
  || { echo "a failed cleanup deleted the journal that was the only record of the transaction" >&2; exit 1; }
[ ! -e "$cleanupfail/var/lib/neural-ice/.sshkey-provisioned" ] \
  || { echo "a failed cleanup still wrote the completion marker" >&2; exit 1; }
[ "$(receipt_field "$cleanupfail" decision)" = '"provisioned-cleanup-failed"' ] \
  || { echo "a failed cleanup did not record its own decision" >&2; exit 1; }

# --------------------------------------------------------------------------- #
# 4) TWO WAITERS. A provisioner that observed "no marker" before blocking must
#    not act on that observation after the holder has published one.
#
#    The marker test happens before flock; the recheck happens after it. This is
#    driven for real: two provision processes are started at once against one
#    root, and the appliance must end with ONE transaction's worth of state.
# --------------------------------------------------------------------------- #
waiters="$work/root-two-waiters"
make_root "$waiters" lab-managed
printf '%s\n' "root=/dev/sda neuralice.sshkey=${encoded_key} quiet" > "$waiters/cmdline"
run_unit "$waiters" provision >/dev/null 2>&1 &
first=$!
run_unit "$waiters" provision >/dev/null 2>&1 &
second=$!
wait "$first" || true
wait "$second" || true
cmp -s "$key" "$waiters/var/home/core/.ssh/authorized_keys" \
  || { echo "two simultaneous provisioners did not leave exactly the approved key" >&2; exit 1; }
[ "$(grep -c . "$waiters/var/home/core/.ssh/authorized_keys")" = 1 ] \
  || { echo "two simultaneous provisioners appended the key twice" >&2; exit 1; }
[ ! -e "$waiters/var/home/core/.ssh/.neural-ice-authorized_keys.backup" ] \
  || { echo "a concurrent provisioner left a backup of a file that never existed" >&2; exit 1; }

# ...and the same for the ordering that actually caused the defect: a waiter that
# starts AFTER a complete transaction, with the marker already published, must
# exit without re-deciding. Driven directly, because a race cannot be relied on
# to reproduce the interesting interleaving.
run_unit "$waiters" activate >/dev/null 2>&1 || true
[ -f "$waiters/var/lib/neural-ice/.sshkey-provisioned" ] \
  || { echo "the concurrent fixture never reached a completed transaction" >&2; exit 1; }
waiters_sha_before="$(sha256sum "$waiters/var/home/core/.ssh/authorized_keys" | awk '{print $1}')"
run_unit "$waiters" provision >/dev/null 2>&1 \
  || { echo "a provisioner run after completion did not exit cleanly" >&2; exit 1; }
[ "$(sha256sum "$waiters/var/home/core/.ssh/authorized_keys" | awk '{print $1}')" = "$waiters_sha_before" ] \
  || { echo "a provisioner run after completion re-decided and rewrote authorized_keys" >&2; exit 1; }

# 🔴 THE JOURNAL DIRECTORY IS ROOT-CUSTODIED. A handoff any other user could
# have written decides what happens to authorized_keys, so one that is
# world-writable is refused and KEPT rather than replayed.
custody="$work/root-journal-custody"
make_root "$custody" lab-managed
install -d -m 0777 "$custody$act_condition"
printf 'neural-ice-sshkey-rollback-journal-v2\n' > "$custody$act_condition/schema"
printf '%s\n' "root=/dev/sda neuralice.sshkey=${encoded_key} quiet" > "$custody/cmdline"
if run_unit "$custody" provision >/dev/null 2>&1; then
  echo "a world-writable activation handoff was replayed" >&2
  exit 1
fi
[ -d "$custody$act_condition" ] \
  || { echo "a world-writable handoff was deleted instead of kept for inspection" >&2; exit 1; }
[ ! -e "$custody/var/home/core/.ssh/authorized_keys" ] \
  || { echo "a world-writable handoff still reached the key mutation" >&2; exit 1; }
[ "$(receipt_field "$custody" decision)" = '"invalid-handoff-path"' ] \
  || { echo "a world-writable handoff did not record a stable refusal decision" >&2; exit 1; }

echo "  [journal] success releases the hard-link backup; external links keep their inode, bytes and count"
echo "  [journal] a cleanup that cannot be proved keeps the journal and withholds the marker"
echo "  [journal] two simultaneous provisioners produce exactly one transaction"
echo "  [journal] a non-custodied handoff is refused and kept"

echo "INSTALLER_SSH_KEY_TEST_OK (${#crash_phases[@]} power-loss phases x 2 prior states reconciled; inode/ACL/xattr restore proved where the filesystem allows it; success cleanup, external hard links, cleanup failure, two waiters and journal custody all covered)"
