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

echo "DEBUG_SSH_KEY_TEST_OK"
