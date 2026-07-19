#!/usr/bin/env bash
# Remove every Authenticode signature table to obtain stable underlying PE bytes.
set -euo pipefail

[[ $# -eq 2 ]] || { echo "usage: $0 INPUT OUTPUT" >&2; exit 2; }
SBVERIFY_BIN="${SBVERIFY_BIN:-sbverify}"
SBATTACH_BIN="${SBATTACH_BIN:-sbattach}"
command -v "$SBVERIFY_BIN" >/dev/null 2>&1 || { echo "sbverify is required" >&2; exit 1; }
command -v "$SBATTACH_BIN" >/dev/null 2>&1 || { echo "sbattach is required" >&2; exit 1; }
cp "$1" "$2"

for _ in 1 2 3 4 5 6 7 8; do
  output="$($SBVERIFY_BIN --list "$2" 2>&1)" || { echo "cannot inspect vmlinuz signatures" >&2; exit 1; }
  if ! grep -Eq '^signature [0-9]+$' <<< "$output"; then exit 0; fi
  "$SBATTACH_BIN" --remove "$2" >/dev/null 2>&1 || { echo "cannot remove vmlinuz signature" >&2; exit 1; }
done
echo "too many vmlinuz signatures" >&2
exit 1
