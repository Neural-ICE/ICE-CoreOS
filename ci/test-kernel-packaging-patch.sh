#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PATCH="$REPO_ROOT/build/patches/nvidia-open-inline-sign.patch"

fail() { echo "FAIL: $*" >&2; exit 1; }
require_once() {
  local line="$1" count
  count="$(grep -Fxc -- "$line" <<< "$stanza" || true)"
  [[ "$count" == 1 ]] || fail "expected exactly one '$line' in NVIDIA RPM stanza"
}

stanza="$(awk '
  $0 == "+%package modules-nvidia-open" {found++; capture=1}
  capture {print}
  capture && $0 == "+%description modules-nvidia-open" {exit}
  END {if (found != 1) exit 1}
' "$PATCH")" || fail "cannot isolate NVIDIA RPM package stanza"

require_once '+Requires: %{name}-modules-core-uname-r = %{KVERREL}'
require_once '+AutoReq: no'
require_once '+AutoProv: yes'
if grep -Eq '^\+AutoReqProv:' <<< "$stanza"; then
  fail "AutoReqProv would disable the ksym Provides required for diagnostics"
fi

echo "kernel packaging patch tests: PASS"
