#!/usr/bin/env bash
# The TPM unlock policy has ONE normative home: OS-0045. A document that still
# describes "a signed list of PCR7 values" as the target contradicts it, and
# AGENTS says a wrong decision is replaced, not stacked. Docs-only contract.
set -euo pipefail
cd "$(dirname "$0")/.."

fail=0
bad() { echo "FAIL: $*" >&2; fail=1; }

adr=$(ls docs/adr/ADR-0045-*.md 2>/dev/null | head -n1 || true)
[ -n "$adr" ] || { bad "docs/adr/ADR-0045-*.md is missing"; exit 1; }

grep -qE '^- \*\*Status\*\*: Proposed' "$adr" || bad "$adr must be Status: Proposed"
grep -q '^- \*\*Supersedes\*\*' "$adr" || bad "$adr must name what it supersedes"
for q in Q1 Q2 Q3 Q4 Q5; do
  grep -qE "^\| $q \|" "$adr" || bad "$adr must list Owner decision $q as open"
done

# ADR numbers are unique across docs/adr (a collision already happened: OS-0043).
dups=$(ls docs/adr/ADR-*.md | sed -E 's#.*/(ADR-[0-9]+)-.*#\1#' | sort | uniq -d)
[ -z "$dups" ] || bad "duplicate ADR number(s) in docs/adr: $dups"

# The superseded texts must point at the new decision.
for f in docs/TPM-SIGNED-POLICY-RUNBOOK.md docs/ADR-0004-disk-encryption-tpm-luks.md; do
  grep -q 'ADR-0045' "$f" || bad "$f does not point to ADR-0045"
done

# ADR-0004 must no longer carry the literal-seal decision.
! grep -q '^### TPM sealing = PCR 7 only' docs/ADR-0004-disk-encryption-tpm-luks.md \
  || bad "ADR-0004 still has the 'TPM sealing = PCR 7 only' decision"
! grep -q -- '--tpm2-pcrs=7' docs/ADR-0004-disk-encryption-tpm-luks.md \
  || bad "ADR-0004 still describes the literal --tpm2-pcrs=7 seal"

# No doc may present a list of PCR7 values as the target (ADR-0045 names it as superseded).
pat='(signed )?list of (signed )?PCR ?7 (values|states)|one (signature )?entr(y|ies) per (admitted )?PCR ?7'
hits=$(grep -rniE "$pat" docs --include='*.md' | grep -v "^$adr:" || true)
[ -z "$hits" ] || bad "docs still present a PCR7 value list as the target:
$hits"

# Relative links of the touched docs resolve.
for f in "$adr" docs/TPM-SIGNED-POLICY-RUNBOOK.md docs/ADR-0004-disk-encryption-tpm-luks.md; do
  dir=$(dirname "$f")
  while IFS= read -r l; do
    t=${l%%#*}
    [ -z "$t" ] || [ -e "$dir/$t" ] || bad "$f: broken link $l"
  done < <(grep -oE '\]\((\.\.?/[^)]+|[A-Za-z0-9_.-]+\.md[^)]*)\)' "$f" | sed -E 's/^\]\(//; s/\)$//')
done

[ "$fail" -eq 0 ] && echo "PASS: TPM policy ADR contract"
exit "$fail"
