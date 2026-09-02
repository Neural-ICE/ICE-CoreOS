#!/usr/bin/env bash
# shellcheck disable=SC2016 # literal source-contract assertions throughout
# The immutable access policy: the derivation, the reader, the installer gate,
# and the two places in the tree that must keep wiring them the right way round.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIB="$ROOT/image/lib/access-policy.sh"
work="$(mktemp -d "${TMPDIR:-/tmp}/ni-access-policy.XXXXXX")"
trap 'rm -rf "$work"' EXIT

fail() { echo "$*" >&2; exit 1; }

# --------------------------------------------------------------------------- #
# 1) The derivation. This is the whole security model in three lines, so it is
#    asserted literally rather than through the code that produces it.
# --------------------------------------------------------------------------- #
test "$(bash "$LIB" for-variant prod)" = customer-locked
test "$(bash "$LIB" for-variant sealed-lab)" = lab-managed
test "$(bash "$LIB" for-variant debug)" = developer-diagnostic
for bad in '' unknown PROD sealed_lab 'prod ' 'prod;rm -rf /'; do
  if bash "$LIB" for-variant "$bad" >/dev/null 2>&1; then
    fail "variant '$bad' was given an access policy"
  fi
done

# The three allowlisted values, and nothing else, permit or forbid provisioning.
bash "$LIB" permits-installer-ssh lab-managed
bash "$LIB" permits-installer-ssh developer-diagnostic
for forbidden in customer-locked '' unknown lab_managed 'lab-managed extra'; do
  if bash "$LIB" permits-installer-ssh "$forbidden" >/dev/null 2>&1; then
    fail "policy '$forbidden' was treated as permitting SSH provisioning"
  fi
done

# --------------------------------------------------------------------------- #
# 2) The reader. Anything that is not a small, regular, non-symlink file holding
#    exactly one allowlisted value is refused — a marker an attacker can redirect
#    or pad is not a marker.
# --------------------------------------------------------------------------- #
make_image_root() { # <dir> <content-or-"absent">
  local dir="$1" content="$2"
  mkdir -p "$dir/usr/lib/neural-ice"
  if [ "$content" != absent ]; then
    printf '%s' "$content" > "$dir/usr/lib/neural-ice/access-policy"
  fi
}

good="$work/good"; make_image_root "$good" 'lab-managed
'
test "$(bash "$LIB" read "$good")" = lab-managed
# A trailing-slash root prefix must resolve to the same file.
test "$(bash "$LIB" read "$good/")" = lab-managed

absent="$work/absent"; make_image_root "$absent" absent
bash "$LIB" read "$absent" >/dev/null 2>&1 && fail "a missing marker was accepted"

empty="$work/empty"; make_image_root "$empty" ''
bash "$LIB" read "$empty" >/dev/null 2>&1 && fail "an empty marker was accepted"

unknown="$work/unknown"; make_image_root "$unknown" 'wide-open
'
bash "$LIB" read "$unknown" >/dev/null 2>&1 && fail "an unrecognised marker was accepted"

# Two values in one file: a marker that can be appended to is a marker that can
# be widened after the fact.
two="$work/two"; make_image_root "$two" 'customer-locked
lab-managed
'
bash "$LIB" read "$two" >/dev/null 2>&1 && fail "a two-valued marker was accepted"

oversized="$work/oversized"; make_image_root "$oversized" "$(printf 'lab-managed%.0s' $(seq 1 20))"
bash "$LIB" read "$oversized" >/dev/null 2>&1 && fail "an oversized marker was accepted"

linked="$work/linked"
mkdir -p "$linked/usr/lib/neural-ice"
printf 'lab-managed\n' > "$work/elsewhere"
ln -s "$work/elsewhere" "$linked/usr/lib/neural-ice/access-policy"
bash "$LIB" read "$linked" >/dev/null 2>&1 && fail "a symlinked marker was accepted"

dir_marker="$work/dir"
mkdir -p "$dir_marker/usr/lib/neural-ice/access-policy"
bash "$LIB" read "$dir_marker" >/dev/null 2>&1 && fail "a directory marker was accepted"

# --------------------------------------------------------------------------- #
# 3) The installer gate. THE historical hole, expressed as a truth table: before
#    the immutable policy existed, every row below with key_present=1 installed a
#    working SSH key, including on a customer image, because the only input was
#    a file on a mutable ESP.
# --------------------------------------------------------------------------- #
gate() { bash "$LIB" gate-installer-ssh "$@" >/dev/null 2>&1; }

# Allowed: the lab path, installing the medium's own image.
gate lab-managed medium 1 || fail "a lab-managed medium install refused an operator key"
gate lab-managed medium 0 || fail "a lab-managed medium install refused a keyless install"
gate developer-diagnostic medium 1 || fail "the developer diagnostic image refused a key"

# Refused: the customer image, with or without a crafted ESP or karg.
gate customer-locked medium 1 && fail "a customer-locked image accepted an installer SSH key"
gate customer-locked medium 0 || fail "a customer-locked keyless install was refused"

# Refused: no readable policy at all, whether or not a key is offered.
for presence in 0 1; do
  gate '' medium "$presence" && fail "an empty policy passed the installer gate (key=$presence)"
  gate wide-open medium "$presence" && fail "an unknown policy passed the installer gate (key=$presence)"
done

# Refused: the registry path with a key. The deployment is written from an image
# pulled at install time, so the policy the installer can read describes the
# LIVE medium, not the system being installed — there is nothing honest to gate
# against, and fetching first would move the decision after the disk is gone.
gate lab-managed registry 1 && fail "a registry install accepted a medium-supplied SSH key"
gate lab-managed registry 0 || fail "a keyless registry install was refused"

# Malformed invocations refuse rather than default.
gate lab-managed elsewhere 1 && fail "an unknown install source was accepted"
gate lab-managed medium 2 && fail "a non-boolean key presence was accepted"

# --------------------------------------------------------------------------- #
# 4) The autoinstaller must consult the gate BEFORE it can touch a disk. A gate
#    that runs after the target is repartitioned is not a gate; it is a report.
# --------------------------------------------------------------------------- #
AUTOINSTALL="$ROOT/ota/neural-ice-autoinstall.sh"
gate_line="$(grep -n 'access_policy_gate_installer_ssh' "$AUTOINSTALL" | head -1 | cut -d: -f1)"
[ -n "$gate_line" ] || fail "the autoinstaller never calls the access-policy gate"
read_line="$(grep -n 'access_policy_read' "$AUTOINSTALL" | head -1 | cut -d: -f1)"
[ -n "$read_line" ] || fail "the autoinstaller never reads the immutable access policy"
# The first command that changes the target disk, whichever it happens to be.
destructive_line="$(grep -nE '^[[:space:]]*(wipefs|sfdisk|mkfs\.|cryptsetup luksFormat)' \
  "$AUTOINSTALL" | head -1 | cut -d: -f1)"
[ -n "$destructive_line" ] || fail "cannot locate the autoinstaller's first destructive command"
[ "$gate_line" -lt "$destructive_line" ] \
  || fail "the access-policy gate runs at line $gate_line, AFTER the first disk write at line $destructive_line"
[ "$read_line" -lt "$gate_line" ] || fail "the autoinstaller gates before it reads the policy"

# And it must validate the supplied key's structure before turning it into a
# karg: a payload that is not exactly one public key must never be installed.
grep -q 'installer_ssh_key_validate_file' "$AUTOINSTALL" \
  || fail "the autoinstaller installs an SSH karg without validating the key"

# --------------------------------------------------------------------------- #
# 5) The image build must WRITE the marker from this library, and must seal the
#    non-debug posture with fail-closed readbacks rather than trust.
# --------------------------------------------------------------------------- #
CONTAINERFILE="$ROOT/image/Containerfile.bootc"
# The strings below are asserted as SOURCE TEXT of the Containerfile, so they
# must stay unexpanded here.
# shellcheck disable=SC2016
for required in \
  'COPY image/lib/access-policy.sh     /usr/lib/neural-ice/lib/access-policy.sh' \
  'COPY image/lib/installer-ssh-key.sh /usr/lib/neural-ice/lib/installer-ssh-key.sh' \
  'bash /usr/lib/neural-ice/lib/access-policy.sh for-variant "${VARIANT}"' \
  'debug:developer-diagnostic|sealed-lab:lab-managed|prod:customer-locked' \
  'test "$(readlink -f /etc/systemd/system/sshd.service)" = /dev/null' \
  'test "$(readlink -f /etc/systemd/system/getty@.service)" = /dev/null' \
  'test "$(readlink -f /etc/systemd/system/autovt@.service)" = /dev/null' \
  'test ! -e /etc/systemd/system/serial-getty@ttyS0.service.d/autologin.conf' \
  "! grep -q 'enforcing=0' /usr/lib/bootc/kargs.d/10-neural-ice.toml" \
  'test -z "${SSH_AUTHORIZED_KEY}"' \
  'bash /usr/lib/neural-ice/lib/installer-ssh-key.sh assert-keyless /usr/ssh/core.keys' \
  'COPY image/firstboot/neural-ice-firstboot-sshkey.service          /usr/lib/systemd/system/neural-ice-firstboot-sshkey.service' \
  'COPY image/firstboot/neural-ice-firstboot-sshkey-activate.service /usr/lib/systemd/system/neural-ice-firstboot-sshkey-activate.service' \
  'neural-ice-firstboot-sshkey-activate.service' \
  ; do
  grep -Fq -- "$required" "$CONTAINERFILE" \
    || fail "the image build no longer asserts: $required"
done

# The sealed readbacks must live in the NON-debug branch. If they drifted into
# the debug branch they would assert nothing about a shipped appliance.
# Anchored on the sealed branch's own first statement rather than on `else`,
# which appears more than once in this file.
sealed_branch="$(awk '/kargs = \["quiet"\]/{inside=1} inside{print} /^    fi$/{if (inside) exit}' \
  "$CONTAINERFILE")"
[ -n "$sealed_branch" ] || fail "cannot locate the sealed variant branch in the image build"
# The keyless promise is TWO requirements, and the sealed branch must carry both.
# `SSH_AUTHORIZED_KEY` is the only input that can put a key in that file, so it
# is checked directly; the file itself is then checked for the absence of any
# content, because the previous `^(ssh-|ecdsa-|sk-)` grep let an options-prefixed
# record — `restrict ssh-ed25519 …`, which sshd honours normally — through a
# build that claims to ship keyless. These too are SOURCE TEXT of the
# Containerfile and must stay unexpanded here.
# shellcheck disable=SC2016
for required in 'systemctl mask sshd.service' 'readlink -f /etc/systemd/system/sshd.service' \
  'test -z "${SSH_AUTHORIZED_KEY}"' \
  'installer-ssh-key.sh assert-keyless /usr/ssh/core.keys' \
  '/usr/ssh/core.keys'; do
  grep -Fq -- "$required" <<<"$sealed_branch" \
    || fail "the sealed branch no longer contains: $required"
done
# ...and the serial root autologin must stay confined to the debug branch.
grep -Fq 'autologin root' <<<"$sealed_branch" \
  && fail "the sealed branch grants a serial root autologin"

# --------------------------------------------------------------------------- #
# 6) The first-boot gate ships as TWO units, and the image must install and
#    enable both. Provisioning is ordered before sshd and therefore cannot
#    observe it; activation is ordered after sshd and is the only phase allowed
#    to record success. An image that enables only the first half writes a key
#    nothing ever starts a daemon for -- and one that enables only the second
#    never writes one at all.
# --------------------------------------------------------------------------- #
PROVISION_UNIT="$ROOT/image/firstboot/neural-ice-firstboot-sshkey.service"
ACTIVATE_UNIT="$ROOT/image/firstboot/neural-ice-firstboot-sshkey-activate.service"
[ -f "$ACTIVATE_UNIT" ] || fail "the first-boot activation unit is missing"
grep -qx 'Before=sshd.service' "$PROVISION_UNIT" \
  || fail "the provisioning unit is no longer ordered before sshd"
grep -qx 'After=sshd.service' "$ACTIVATE_UNIT" \
  || fail "the activation unit is no longer ordered after sshd"
grep -qx 'Before=sshd.service' "$ACTIVATE_UNIT" \
  && fail "the activation unit is ordered before sshd — it could not verify it"
grep -qx 'ExecStart=/usr/local/bin/neural-ice-firstboot-sshkey.sh provision' "$PROVISION_UNIT" \
  || fail "the provisioning unit does not run the provision phase"
grep -qx 'ExecStart=/usr/local/bin/neural-ice-firstboot-sshkey.sh activate' "$ACTIVATE_UNIT" \
  || fail "the activation unit does not run the activate phase"
# Both must be enabled in the SAME systemctl enable invocation the image uses.
enable_block="$(awk '/systemctl enable nvidia-device-nodes.service/{inside=1} inside{print} /set-default multi-user.target/{if (inside) exit}' \
  "$CONTAINERFILE")"
for unit in neural-ice-firstboot-sshkey.service neural-ice-firstboot-sshkey-activate.service; do
  grep -Fq -- "$unit" <<<"$enable_block" || fail "the image build does not enable $unit"
done

# --------------------------------------------------------------------------- #
# 7) THE MARKER IS NOW A CROSS-CHECK, NOT THE AUTHORITY (DESIGN-NOTE-0001,
#    Finding 1). Sections 1-6 above still describe a real control, but on a
#    REMOVABLE MEDIUM they describe a control over an attacker-writable file:
#    Secure Boot authenticates EFI binaries and the kernel, not the root
#    filesystem they mount. The image must therefore ship the two libraries that
#    make the marker defensible — the sealed-anchor gate and the
#    release-authorization verifier — and must record its own Secure Boot trust
#    policy as a FILE in the read-only /usr, not only as an OCI label.
# --------------------------------------------------------------------------- #
for required in \
  'COPY image/lib/installer-trust.sh        /usr/lib/neural-ice/lib/installer-trust.sh' \
  'COPY image/lib/release-authorization.sh  /usr/lib/neural-ice/lib/release-authorization.sh' \
  'COPY ota/neural-ice-access-profile-anchor.sh /usr/libexec/neural-ice-access-profile-anchor' \
  'chmod 0755 /usr/libexec/neural-ice-access-profile-anchor' \
  'ARG SIGNED_BOOT_TRUST_POLICY_ID=neural-ice-secureboot-lab-v1' \
  '/usr/lib/neural-ice/signed-boot-trust-policy-id' \
  ; do
  grep -Fq -- "$required" "$CONTAINERFILE" \
    || fail "the image build no longer ships: $required"
done
# The libraries the installer's gates live in must be as immutable as the marker
# itself. A read-only policy read by a writable reader is not a control.
seal_block="$(awk '/chmod 0444 \/usr\/lib\/neural-ice\/access-policy/{inside=1} inside{print} /installer-ssh-key.sh; \\$/{if (inside) exit}' \
  "$CONTAINERFILE")"
[ -n "$seal_block" ] || fail "cannot locate the read-only sealing block in the image build"
for sealed in \
  '/usr/lib/neural-ice/signed-boot-trust-policy-id' \
  '/usr/lib/neural-ice/lib/hardware-identity.sh' \
  '/usr/lib/neural-ice/lib/installer-trust.sh' \
  '/usr/lib/neural-ice/lib/release-authorization.sh' \
  ; do
  grep -Fq -- "$sealed" <<<"$seal_block" || fail "the image build does not seal $sealed read-only"
done

# The autoinstaller must LOAD every library it reasons with. A missing one would
# surface as "command not found" mid-install rather than as a refusal before any
# disk write. `hardware-identity` joined the list when the hardware target
# stopped being a word compared with a copy of itself.
for _lib in access-policy hardware-identity installer-payload installer-ssh-key installer-trust release-authorization; do
  grep -Fq "source \"\$NEURALICE_INSTALLER_LIB_DIR/${_lib}.sh\"" "$AUTOINSTALL" \
    || fail "the autoinstaller does not load ${_lib}.sh"
done
grep -Fq 'for _ni_lib in access-policy hardware-identity installer-payload installer-ssh-key installer-trust release-authorization; do' \
  "$AUTOINSTALL" \
  || fail "the autoinstaller does not require every access library before it reasons about access"

# --------------------------------------------------------------------------- #
# 8) TPM provisioning and owner sealing are one mandatory first-boot lifecycle.
#    The installer persists the prerequisites and intent; runtime never creates
#    state and no root-accessible service precedes the ceremony.
# --------------------------------------------------------------------------- #
CEREMONY="$ROOT/ota/neural-ice-firstboot-tpm-ceremony.sh"
CEREMONY_UNIT="$ROOT/image/firstboot/neural-ice-firstboot-tpm-ceremony.service"
CEREMONY_DROPIN="$ROOT/image/firstboot/50-neural-ice-tpm-ceremony-sshd.conf"
for required in \
  '"$TPM_STATE" provisioning-status' \
  'systemd-analyze srk > "$INTENDED_SRK_PUBLIC"' \
  '--tpm2-seal-key-handle=0x81000001' \
  '/usr/libexec/neural-ice-luks-token-evidence' \
  'assert_luks_srk_token "$SYSP" /run/neural-ice-installer/system-luks-evidence.json' \
  'assert_luks_srk_token "$DATAP" /run/neural-ice-installer/data-luks-evidence.json' \
  'owner-ceremony-intent-v1' \
  'owner-ceremony-install-identity-v1.json' \
  'srk-v1.tpm2b_public'; do
  grep -Fq -- "$required" "$AUTOINSTALL" \
    || fail "the installer no longer persists the mandatory ceremony contract: $required"
done
grep -Fq '/usr/libexec/neural-ice-access-profile-anchor enroll' "$AUTOINSTALL" \
  && fail "the installer performs anchor enrollment outside the mandatory ceremony"

for required in \
  '"$DEVICE_ROOT_TOOL" attest --identity "$DEVICE_ROOT"' \
  'cmp -s "$WORK/live-srk.tpm2b_public" "$SRK_PUBLIC"' \
  '"$LUKS_EVIDENCE" "$WORK/$label-luks.json" "$SRK_PUBLIC"' \
  '"$TPM_STATE" ceremony-prepare' \
  '"$TPM_STATE" ceremony-finalize' \
  '"$TPM_STATE" completion-status' \
  '"$TPM_STATE" runtime-status' \
  '"$PROFILE_ANCHOR" enroll' \
  '"$PROFILE_ANCHOR" verify'; do
  grep -Fq -- "$required" "$CEREMONY" \
    || fail "the first-boot ceremony no longer enforces: $required"
done
grep -Fq 'tokens[0].get("tpm2-srk")' "$AUTOINSTALL" "$CEREMONY" \
  && fail "the SRK checks use a non-systemd LUKS2 token field name"
grep -Fq 'ownerAuthSet=1' "$CEREMONY" \
  || fail "the ceremony does not document refusal of pre-existing owner authorization"

grep -Fq 'Before=network-pre.target network.target network-online.target systemd-user-sessions.service sshd.service' "$CEREMONY_UNIT" \
  || fail "the ceremony no longer gates networking, sessions and SSH"
grep -Fq 'RequiredBy=multi-user.target' "$CEREMONY_UNIT" \
  || fail "the ceremony is not mandatory for multi-user readiness"
grep -Fq 'ConditionPathExists' "$CEREMONY_UNIT" \
  && fail "an absent TPM skips the ceremony instead of failing closed"
grep -qx 'Requires=neural-ice-firstboot-tpm-ceremony.service' "$CEREMONY_DROPIN" \
  || fail "root-accessible services do not require the ceremony"
for unit in sshd.service.d sshd.socket.d getty@.service.d serial-getty@.service.d \
  network-pre.target.d network.target.d network-online.target.d \
  neural-ice-payload-apply.service.d systemd-user-sessions.service.d; do
  grep -Fq "/usr/lib/systemd/system/$unit/50-neural-ice-tpm-ceremony.conf" "$CONTAINERFILE" \
    || fail "$unit is not gated by the mandatory ceremony"
done
for unit in "$PROVISION_UNIT" "$ACTIVATE_UNIT" \
  "$ROOT/image/bootc-overlay/usr/lib/systemd/system/neural-ice-device-root.service"; do
  grep -Fq 'Requires=neural-ice-firstboot-tpm-ceremony.service' "$unit" \
    || fail "$(basename "$unit") can run without the mandatory ceremony"
  if ! grep -Fq 'After=' "$unit" \
    || ! grep -Fq 'neural-ice-firstboot-tpm-ceremony.service' "$unit"; then
    fail "$(basename "$unit") is not ordered after the mandatory ceremony"
  fi
done
grep -Fq 'neural-ice-firstboot-tpm-ceremony.service' <<<"$enable_block" \
  || fail "the image does not enable the mandatory ceremony"

echo "ACCESS_POLICY_TEST_OK"
