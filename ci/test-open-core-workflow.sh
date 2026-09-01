#!/usr/bin/env bash
# Mechanical trigger contract for the dedicated open-core boundary workflow.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKFLOW="${NI_OPEN_CORE_WORKFLOW:-$ROOT/.github/workflows/open-core-boundary.yml}"

validate() {
  python3 - "$1" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
try:
    lines = path.read_text(encoding="utf-8").splitlines()
except (OSError, UnicodeError) as error:
    print(f"FAIL: cannot read workflow: {error}", file=sys.stderr)
    raise SystemExit(1)

try:
    start = lines.index("on:")
except ValueError:
    print("FAIL: workflow has no exact top-level on: mapping", file=sys.stderr)
    raise SystemExit(1)
end = next((i for i in range(start + 1, len(lines)) if lines[i] and not lines[i].startswith((" ", "#"))), len(lines))
trigger = [line for line in lines[start:end] if line.strip() and not line.lstrip().startswith("#")]
if trigger != ["on:", "  pull_request:", "  push:"]:
    print(f"FAIL: triggers must be unconditional pull_request and push only: {trigger}", file=sys.stderr)
    raise SystemExit(1)

required = {
    "        run: bash ci/test-open-core-workflow.sh",
    "        run: bash ci/test-open-core-boundary.sh",
}
missing = required.difference(lines)
if missing:
    print(f"FAIL: workflow omits required gate steps: {sorted(missing)}", file=sys.stderr)
    raise SystemExit(1)
PY
}

validate "$WORKFLOW"

if [[ "${NI_OPEN_CORE_WORKFLOW_ORACLE:-0}" != 1 ]]; then
  tmp="$(mktemp -d)"
  trap 'rm -rf -- "$tmp"' EXIT

  sed '/^  pull_request:$/a\    paths:\n      - image/**' "$WORKFLOW" > "$tmp/path-filter.yml"
  if NI_OPEN_CORE_WORKFLOW_ORACLE=1 NI_OPEN_CORE_WORKFLOW="$tmp/path-filter.yml" bash "$0" >/dev/null 2>&1; then
    echo "FAIL: paths-filter workflow mutation was accepted" >&2
    exit 1
  fi
  echo "  ok: paths filter bypass rejected"

  sed '/^  push:$/d' "$WORKFLOW" > "$tmp/no-push.yml"
  if NI_OPEN_CORE_WORKFLOW_ORACLE=1 NI_OPEN_CORE_WORKFLOW="$tmp/no-push.yml" bash "$0" >/dev/null 2>&1; then
    echo "FAIL: missing push trigger mutation was accepted" >&2
    exit 1
  fi
  echo "  ok: missing push trigger rejected"

  sed '/run: bash ci\/test-open-core-boundary.sh/d' "$WORKFLOW" > "$tmp/no-gate.yml"
  if NI_OPEN_CORE_WORKFLOW_ORACLE=1 NI_OPEN_CORE_WORKFLOW="$tmp/no-gate.yml" bash "$0" >/dev/null 2>&1; then
    echo "FAIL: omitted boundary-step mutation was accepted" >&2
    exit 1
  fi
  echo "  ok: omitted boundary step rejected"
fi

echo "open-core workflow trigger: PASS"
