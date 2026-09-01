#!/usr/bin/env bash
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
  NEURALICE_FIRSTBOOT_ROOT="$root" \
  NEURALICE_FIRSTBOOT_CMDLINE="$root/cmdline" \
  NEURALICE_FIRSTBOOT_SSHD_TIMEOUT="${NI_TEST_SSHD_TIMEOUT:-2}" \
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
cp "$work/community.pub" "$coexist/var/home/core/.ssh/authorized_keys"
if NI_TEST_SSHD_STUBBORN=1 run_boot "$coexist" \
  "root=/dev/sda neuralice.sshkey=${encoded_key} quiet"; then
  echo "the coexistence case did not model an activation failure" >&2
  exit 1
fi
cmp -s "$work/community.pub" "$coexist/var/home/core/.ssh/authorized_keys" \
  || { echo "the rollback destroyed a pre-existing community key" >&2; exit 1; }

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

echo "INSTALLER_SSH_KEY_TEST_OK"
