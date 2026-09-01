#!/bin/bash
# shellcheck disable=SC2154 # $moddir is dracut's, set before this file is sourced
# dracut module: open the SEALED PAYLOAD and build the installer's root BEFORE
# switch-root.
#
# WHY THIS MODULE EXISTS. The UKI seals a dm-verity root hash and the digest of
# the payload header in its .cmdline, and the whole construction is worth nothing
# unless something INSIDE the signed binary acts on them. This module is that
# something: it ships in the initramfs that is embedded in the signed PE, so the
# code that verifies the payload, sets dm-verity up and builds the writable
# runtime is covered by the same signature as the kernel and the command line it
# reads.
#
# It deliberately does NOT fall back. A medium whose payload header, root image,
# hash tree or store fails to verify does not boot into "the installer,
# degraded"; it does not boot at all. An installer that can start without its
# root being verified is the exact state DESIGN-NOTE-0001 Finding 1 describes.
#
# THE PAYLOAD PARSER IS SHARED, NOT RE-IMPLEMENTED (review 2026-09-01, P0 #1).
# image/lib/installer-payload.sh is POSIX sh precisely so that the build, the
# installer and this hook all read the header with the same code. A second parser
# would be a second answer, and only one of them would be the one that was
# signed. The media build stages it beside this file before running dracut.

check() {
    return 0
}

depends() {
    echo dm rootfs-block
    return 0
}

install() {
    inst_multiple veritysetup losetup blkid findmnt awk mount umount mkdir sed \
        dmsetup readlink cat sort dd tr head grep sha256sum rm
    inst_simple "$moddir/installer-payload.sh" /lib/neural-ice-installer-payload.sh
    inst_hook cmdline 29 "$moddir/neural-ice-installer-verity-cmdline.sh"
    inst_hook pre-mount 29 "$moddir/neural-ice-installer-verity.sh"
    return 0
}

installkernel() {
    # `overlay` is as load-bearing as `dm-verity` here: without a writable upper
    # layer the verified squashfs root cannot hold /etc, /var or the installer's
    # own scratch state, and the install cannot run at all.
    instmods dm-verity loop squashfs overlay
    return 0
}
