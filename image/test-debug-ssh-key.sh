#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HELPER="$ROOT/image/lib/debug-ssh-key.sh"
work="$(mktemp -d "${TMPDIR:-/tmp}/ni-debug-ssh-key.XXXXXX")"
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
  echo "hash-only debug SSH input was accepted" >&2
  exit 1
fi
if bash "$HELPER" validate "$key" '' >/dev/null 2>&1; then
  echo "key-only debug SSH input was accepted" >&2
  exit 1
fi
if bash "$HELPER" validate "$key" "$bad_digest" >/dev/null 2>&1; then
  echo "mismatched debug SSH key hash was accepted" >&2
  exit 1
fi
ln -s "$key" "$work/operator-link.pub"
if bash "$HELPER" validate "$work/operator-link.pub" "$digest" >/dev/null 2>&1; then
  echo "symlinked debug SSH key was accepted" >&2
  exit 1
fi

private_digest="$(sha256sum "$work/operator" | awk '{print $1}')"
if bash "$HELPER" validate "$work/operator" "$private_digest" >/dev/null 2>&1; then
  echo "private SSH key was accepted as an ESP public key" >&2
  exit 1
fi

cp "$key" "$work/oversized.pub"
printf '%0512d' 0 >> "$work/oversized.pub"
oversized_digest="$(sha256sum "$work/oversized.pub" | awk '{print $1}')"
if bash "$HELPER" validate "$work/oversized.pub" "$oversized_digest" >/dev/null 2>&1; then
  echo "oversized kernel-command-line SSH key was accepted" >&2
  exit 1
fi

base_image="registry.example/debug@sha256:$(printf '%064d' 1)"
bash "$HELPER" require-debug-target "$key" "$base_image" "$base_image"
if bash "$HELPER" require-debug-target "$key" "$base_image" \
  "registry.example/prod@sha256:$(printf '%064d' 2)" >/dev/null 2>&1; then
  echo "debug SSH key was accepted for a different install target" >&2
  exit 1
fi
bash "$HELPER" require-debug-target '' "$base_image" \
  "registry.example/prod@sha256:$(printf '%064d' 2)"

mkdir "$work/esp"
bash "$HELPER" install "$key" "$digest" "$work/esp"
cmp "$key" "$work/esp/ice-coreos/authorized_keys"
if bash "$HELPER" install "$key" "$digest" "$work/esp" >/dev/null 2>&1; then
  echo "existing ESP authorized_keys path was overwritten" >&2
  exit 1
fi

# --- first-boot provisioning ------------------------------------------------
# Every non-debug variant ships sshd masked, so writing the key is only half the
# job: without the unmask the operator's key lands on a sealed image and nothing
# listens. These run the REAL script through its test seams rather than a copy of
# its logic -- a test that reimplements the script proves nothing about it.
FIRSTBOOT="$ROOT/image/firstboot/neural-ice-firstboot-sshkey.sh"

stub_dir="$work/stub"
mkdir -p "$stub_dir"
cat > "$stub_dir/systemctl" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$NI_TEST_SYSTEMCTL_LOG"
[ "${1:-}" = is-enabled ] && { printf 'masked\n'; exit 0; }
exit 0
STUB
printf '#!/usr/bin/env bash\nexit 0\n' > "$stub_dir/logger"
chmod 0755 "$stub_dir/systemctl" "$stub_dir/logger"

run_firstboot() { # <root> <cmdline-content>
  local root="$1" cmdline="$2"
  mkdir -p "$root"
  printf '%s\n' "$cmdline" > "$root/cmdline"
  NI_TEST_SYSTEMCTL_LOG="$root/systemctl.log" \
  NEURALICE_FIRSTBOOT_ROOT="$root" \
  NEURALICE_FIRSTBOOT_CMDLINE="$root/cmdline" \
  PATH="$stub_dir:$PATH" bash "$FIRSTBOOT"
}

# A key on the medium: written AND served.
provisioned="$work/root-key"
run_firstboot "$provisioned" "root=/dev/sda neuralice.sshkey=$(base64 -w0 < "$key") quiet"
cmp -s "$key" "$provisioned/var/home/core/.ssh/authorized_keys" \
  || { echo "first boot did not write the operator key it was given" >&2; exit 1; }
[ "$(stat -c %a "$provisioned/var/home/core/.ssh/authorized_keys")" = 600 ] \
  || { echo "provisioned authorized_keys is not 0600" >&2; exit 1; }
grep -qx 'unmask sshd.service' "$provisioned/systemctl.log" \
  || { echo "sshd was left MASKED: the provisioned key is unusable on a sealed image" >&2; exit 1; }
grep -q '^enable .*sshd.service' "$provisioned/systemctl.log" \
  || { echo "sshd was unmasked but never started" >&2; exit 1; }

# A customer appliance: same image, no key on the medium, nothing happens.
sealed="$work/root-sealed"
run_firstboot "$sealed" "root=/dev/sda quiet"
[ ! -e "$sealed/var/home/core/.ssh/authorized_keys" ] \
  || { echo "an appliance with no key on its medium was given one" >&2; exit 1; }
[ ! -s "$sealed/systemctl.log" ] \
  || { echo "sshd was touched on an appliance that carries no key" >&2; exit 1; }

# The marker is what makes this once-only: a later boot must not re-open sshd
# after an operator has deliberately masked it again.
: > "$provisioned/systemctl.log"
run_firstboot "$provisioned" "root=/dev/sda neuralice.sshkey=$(base64 -w0 < "$key") quiet"
[ ! -s "$provisioned/systemctl.log" ] \
  || { echo "first-boot provisioning ran a second time" >&2; exit 1; }

echo "DEBUG_SSH_KEY_TEST_OK"
