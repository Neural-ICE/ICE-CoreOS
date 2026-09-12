#!/usr/bin/env bash
# NetworkManager-wait-online was the one "failed" unit of every first boot on
# the GX10 (.67, 2026-09-12): the management link is held until device trust
# and the seed publication, then its first activation took 58 s against
# nm-online's default 60 s budget. The image ships a budget the activation
# fits, and gates wait-online exactly like NetworkManager itself.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CF="$ROOT/image/Containerfile.bootc"
D="$ROOT/image/firstboot"
fail() { echo "FAIL: $*" >&2; exit 1; }
budget="$D/60-neural-ice-wait-online-budget.conf"
[ -f "$budget" ] || fail "the wait-online budget drop-in is missing"
grep -qx 'ExecStart=' "$budget" || fail "the budget drop-in does not reset ExecStart"
timeout=$(sed -n 's/^ExecStart=\/usr\/bin\/nm-online -s -q --timeout=\([0-9]*\)$/\1/p' "$budget")
[ -n "$timeout" ] || fail "the budget drop-in does not run nm-online -s -q with a timeout"
[ "$timeout" -ge 180 ] || fail "wait-online budget $timeout s is below the measured 58 s activation with margin"
grep -qx 'COPY image/firstboot/60-neural-ice-wait-online-budget.conf /usr/lib/systemd/system/NetworkManager-wait-online.service.d/60-neural-ice-wait-online-budget.conf' "$CF" \
  || fail "the image does not ship the wait-online budget drop-in"
for gate in 50-neural-ice-tpm-ceremony-sshd.conf:50-neural-ice-tpm-ceremony.conf 50-neural-ice-seed-import.conf:40-neural-ice-seed-import.conf; do
  src=${gate%%:*}; dst=${gate##*:}
  grep -qx "COPY image/firstboot/$src /usr/lib/systemd/system/NetworkManager.service.d/$dst" "$CF" \
    || fail "NetworkManager is not gated by $src"
  grep -qx "COPY image/firstboot/$src /usr/lib/systemd/system/NetworkManager-wait-online.service.d/$dst" "$CF" \
    || fail "wait-online is not gated by $src like NetworkManager"
done
echo "WAIT_ONLINE_BUDGET_OK"
