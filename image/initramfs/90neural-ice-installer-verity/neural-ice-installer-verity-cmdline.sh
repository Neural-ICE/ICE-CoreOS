#!/bin/sh
# Take the root away from dracut and give it to this module.
#
# WHY `root=` IS REFUSED RATHER THAN DEFAULTED (review 2026-09-01, P0 #2).
# This hook used to read `[ -z "$root" ] && root=block:/dev/mapper/…`, i.e. it
# yielded to a `root=` that was already set. With Secure Boot enforcing, nothing
# can set one: systemd-stub honours only the sealed .cmdline. With Secure Boot
# OFF -- a state an attacker with physical access can reach -- the stub
# CONCATENATES an externally supplied command line onto the sealed one, so
# appending `root=/dev/sda2` was enough to make dracut mount an attacker's root
# and never touch dm-verity at all. The sealed anchor was intact; it was simply
# not the thing that decided.
#
# So a `root=` on the command line is now a REFUSAL, exactly as a duplicated
# sealed key is: an input that can be shadowed by appending to it is not an input
# this initramfs can reason about, and this one decides what `/` is.
#
# The value set below is deliberately NOT a `block:` spec. dracut's own
# 95rootfs-block/mount-root.sh acts only on `root=block:*`, so naming our own
# scheme keeps every generic mount path out of the picture; this module's
# pre-mount hook has already mounted $NEWROOT by the time any mount hook runs.
# `root` and `rootok` are dracut's own variables, read by its main loop after
# every cmdline hook has run; nothing in this file consumes them.

# THE COMMAND LINE THIS HOOK READS. `/proc/cmdline` in production, always; the
# override exists so image/test-installer-media.sh can drive every refusal below
# against a fixture instead of asserting that a string appears in this file. It
# is refused in a privileged process, which is every process in an initramfs --
# the same guard shape image/lib/installer-trust.sh uses for its tool overrides.
NI_CMDLINE_FILE=/proc/cmdline
if [ -n "${NEURAL_ICE_INITRAMFS_TEST_CMDLINE:-}" ]; then
    if [ "${NEURAL_ICE_INITRAMFS_TESTING:-}" = 1 ] && [ "$(id -u)" -ne 0 ]; then
        NI_CMDLINE_FILE="$NEURAL_ICE_INITRAMFS_TEST_CMDLINE"
    else
        printf 'neural-ice-installer-verity: REFUSED: a command-line override is forbidden in a privileged process\n' >&2
        exit 1
    fi
fi

if [ "$(awk 'BEGIN{n=0}{for (i=1;i<=NF;i++) if (index($i,"root=")==1) n++} END{print n+0}' "$NI_CMDLINE_FILE")" -ne 0 ]; then
    printf 'neural-ice-installer-verity: REFUSED: the command line carries a root= this sealed medium did not seal\n' >&2
    if type die >/dev/null 2>&1; then
        die "neural-ice-installer-verity: an externally supplied root= may not select this installer's root"
    fi
    exit 1
fi
# shellcheck disable=SC2034
root="neuralice:sealed-installer-root"
# shellcheck disable=SC2034
rootok=1
