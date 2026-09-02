#!/usr/bin/env bash
#
# The image must not ship a shim-chainable EFI updater, and the reason is not
# internal: `secureboot/shim-review-answers.draft.md` tells third-party reviewers
# that none is shipped. That sentence was NOT true of the published image — the
# base `centos-bootc:stream10` pulls in `fwupd-efi`, whose only payload is
# `fwupdaa64.efi`. Nobody caught it, which is precisely the problem: reviewers
# check what shim boots and whether the build reproduces, not the contents of an
# OS image, so nothing here would ever have contradicted us.
#
# Measured on the published image before the fix:
#
#   $ rpm -qf /usr/libexec/fwupd/efi/fwupdaa64.efi   -> fwupd-efi-1.8-1.el10.aarch64
#   $ rpm -q --whatrequires fwupd-efi                -> no package requires fwupd-efi
#
# Removing it costs nothing: fwupd reports "Updated via capsule-on-disk" for all
# four ESRT devices on this hardware, so firmware updates never traversed that
# binary.
#
# This test guards the SOURCE, because the image itself cannot be built in CI
# (the GB10 kernel RPMs are materialised on the Spark runner only). It therefore
# checks two things that must move together:
#
#   1. the Containerfile still removes the package AND still reads back that the
#      binaries are gone — a purge without a readback silently stops working the
#      day the base renames the package;
#   2. the claim in the review answers still exists — so that if someone deletes
#      the purge, this test names the external commitment they are falsifying,
#      instead of failing with an opaque "file missing".
#
# If the claim is ever withdrawn from the review answers, this test is what must
# be updated first, deliberately.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTAINERFILE="$REPO_ROOT/image/Containerfile.bootc"
REVIEW_ANSWERS="$REPO_ROOT/secureboot/shim-review-answers.draft.md"

fail() { echo "FAIL: $*" >&2; exit 1; }

[ -f "$CONTAINERFILE" ] || fail "$CONTAINERFILE is missing"

grep -Eq '^[[:space:]]*dnf -y remove --noautoremove fwupd-efi;' "$CONTAINERFILE" \
  || fail "the image no longer removes fwupd-efi.
       That reinstates a shim-chainable EFI updater in the published image, and
       falsifies this claim made to shim-review:
         \"$(grep -m1 'no fwupd EFI binary is shipped' "$REVIEW_ANSWERS" 2>/dev/null || echo '<claim not found>')\""

# A purge whose result is never verified is a purge that stops working in
# silence — for instance the day the base renames or splits the package.
for readback in \
  '! rpm -q fwupd-efi' \
  '! test -e /usr/libexec/fwupd/efi/fwupdaa64.efi' \
  '! test -e /usr/libexec/fwupd/efi/fwupdaa64.efi.signed'
do
  grep -Fq "$readback" "$CONTAINERFILE" \
    || fail "the fwupd-efi purge lost its fail-closed readback: '$readback'"
done

# Removing the payload must not remove the capability: capsule-on-disk needs the
# fwupd daemon, which is a different package. Losing it would be a silent
# regression of firmware updatability, traded for nothing.
grep -Fq 'test -x /usr/bin/fwupdmgr' "$CONTAINERFILE" \
  || fail "nothing asserts that fwupd itself survived the purge of fwupd-efi"

# LVFS metadata refresh is egress, not the firmware-update contract. The
# daemon stays; the refresh timer/service must still be masked. Presence is
# the unit FILE — `list-unit-files | grep -q` under pipefail is exit 141
# (run 33692883287) and reports a missing unit that is on disk.
for refresh_unit in fwupd-refresh.timer fwupd-refresh.service; do
  grep -Fq "test -f \"/usr/lib/systemd/system/\$u\"" "$CONTAINERFILE" \
    || fail "the egress mask no longer asserts the unit file on disk before masking"
  grep -Fq "$refresh_unit" "$CONTAINERFILE" \
    || fail "the egress mask dropped $refresh_unit; LVFS refresh would go unmasked"
done
if grep -n 'fwupd-refresh' "$CONTAINERFILE" | grep -F 'list-unit-files' >/dev/null; then
  fail "the fwupd-refresh mask still uses list-unit-files; that pipeline is exit 141 under pipefail"
fi
grep -E 'systemctl (enable|start) fwupd-refresh' "$CONTAINERFILE" >/dev/null \
  && fail "fwupd-refresh must stay masked; enabling it is LVFS egress, not capsule-on-disk"

[ -f "$REVIEW_ANSWERS" ] || fail "$REVIEW_ANSWERS is missing"
grep -Fq 'no fwupd EFI binary is shipped' "$REVIEW_ANSWERS" \
  || fail "the shim-review claim about fwupd is gone.
       If it was withdrawn deliberately, update this test in the same change —
       the purge above exists to make that sentence true."

echo "PASS: no shim-chainable EFI updater is shipped, and the review claim it backs is intact"
