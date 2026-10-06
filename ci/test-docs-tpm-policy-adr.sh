#!/usr/bin/env bash
# The TPM unlock policy has ONE normative home: OS-0045 (file docs/adr/ADR-0045-*.md; prose uses
# the OS-00XX prefix, docs/adr/README.md). A document that still describes "a signed list of PCR7
# values" as the target contradicts it, and AGENTS says a wrong decision is replaced, not stacked.
# Docs-only contract.
set -euo pipefail
cd "$(dirname "$0")/.."

fail=0
bad() { echo "FAIL: $*" >&2; fail=1; }

adr=$(ls docs/adr/ADR-0045-*.md 2>/dev/null | head -n1 || true)
[ -n "$adr" ] || { bad "docs/adr/ADR-0045-*.md is missing"; exit 1; }

grep -qE '^- \*\*Status\*\*: Accepted \(2026-10-06, Owner\)' "$adr" || bad "$adr must be Status: Accepted (2026-10-06, Owner)"
! grep -qiE 'Proposed|not decided|subject to Q[0-9]|Q1 open' "$adr" || bad "$adr still carries Proposed / conditional wording"
grep -q '^## Recorded Owner decisions' "$adr" || bad "$adr lacks the 'Recorded Owner decisions' section"
! grep -q '^## Open Owner decisions' "$adr" || bad "$adr still has an 'Open Owner decisions' section"
grep -q '^- \*\*Supersedes\*\*' "$adr" || bad "$adr must name what it supersedes"
for q in Q1 Q2 Q3 Q4 Q5; do
  grep -qE "^\| $q \|" "$adr" || bad "$adr must record Owner decision $q"
  grep -E "^\| $q \|" "$adr" | grep -q 'Accepted\|Yes\|pinned\|per-device\|Firmware pinned' || bad "$adr: decision $q has no recorded answer"
done

# ADR numbers are unique across BOTH directories that share the numbering (docs/ and docs/adr/;
# a collision already happened: OS-0043).
dups=$(ls docs/ADR-*.md docs/adr/ADR-*.md | sed -E 's#.*/(ADR-[0-9]+)-.*#\1#' | sort | uniq -d)
[ -z "$dups" ] || bad "duplicate ADR number(s) across docs/ and docs/adr/: $dups"

# The superseded texts must point at the new decision, with the OS-00XX prefix (docs/adr/README.md:
# "Écrivez OS-0004, jamais ADR-0004").
for f in docs/TPM-SIGNED-POLICY-RUNBOOK.md docs/ADR-0004-disk-encryption-tpm-luks.md; do
  grep -q 'OS-0045' "$f" || bad "$f does not point to OS-0045"
done
! grep -qE 'OS-0045[^.]*Proposed|Proposed[^.]*OS-0045' docs/TPM-SIGNED-POLICY-RUNBOOK.md docs/ADR-0004-disk-encryption-tpm-luks.md \
  || bad "runbook / ADR-0004 still call OS-0045 Proposed"
! grep -q 'ADR-0045.*Proposed' docs/adr/README.md || bad "docs/adr/README.md still calls ADR-0045 Proposed"
grep -q 'ADR-0045' docs/adr/README.md || bad "docs/adr/README.md does not index ADR-0045"
grep -qE '\*\*4 ADR\*\*' docs/adr/README.md || bad "docs/adr/README.md ADR count is stale"

# The new ADR may not claim the unmerged work as existing: it must keep the "Not proven" section.
grep -q '^## Not proven' "$adr" || bad "$adr lost its 'Not proven' section"

# The PR #245 finding (GB10 measures variable names only) and its consequence for the rules engine
# must stay stated, not silently removed.
grep -q '^### Finding of PR #245' "$adr" || bad "$adr lost its 'Finding of PR #245' section"
grep -q '^## Limitation for the rules engine' "$adr" || bad "$adr lost its 'Limitation for the rules engine' section"

# ADR-0004 must no longer carry the literal-seal decision.
! grep -q '^### TPM sealing = PCR 7 only' docs/ADR-0004-disk-encryption-tpm-luks.md \
  || bad "ADR-0004 still has the 'TPM sealing = PCR 7 only' decision"
! grep -q -- '--tpm2-pcrs=7' docs/ADR-0004-disk-encryption-tpm-luks.md \
  || bad "ADR-0004 still describes the literal --tpm2-pcrs=7 seal"

# No tracked markdown may present a list of PCR7 values as the target (the ADR names it as
# superseded). A line that legitimately describes the OLD model as history or as rejected carries
# the marker  <!-- pcr7-list:history -->  and is skipped; the ADR itself is exempt.
pat='(signed )?(list|set) of (signed |admitted )*(PCR ?7|values)|one (signed )?(signature )?entr(y|ies) per (admitted |signed )*(PCR ?7|value)|per (admitted |signed )?PCR ?7 value'
hits=$(git ls-files '*.md' | grep -v "^$adr\$" | xargs -r grep -niE "$pat" \
  | grep -v 'pcr7-list:history' || true)
[ -z "$hits" ] || bad "markdown still presents a PCR7 value list as the target:
$hits"

# Relative links of every doc that points at the ADR resolve.
while IFS= read -r f; do
  dir=$(dirname "$f")
  while IFS= read -r l; do
    t=${l%%#*}
    [ -z "$t" ] || [ -e "$dir/$t" ] || bad "$f: broken link $l"
  done < <(grep -oE '\]\((\.\.?/[^)]+|[A-Za-z0-9_.-]+\.md[^)]*|adr/[^)]+)\)' "$f" | sed -E 's/^\]\(//; s/\)$//')
done < <({ echo "$adr"; git ls-files '*.md' | xargs -r grep -lE 'OS-0045|ADR-0045'; } | sort -u)

[ "$fail" -eq 0 ] && echo "PASS: TPM policy ADR contract"
exit "$fail"
