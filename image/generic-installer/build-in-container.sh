#!/bin/bash
# Run build-uki.sh inside a Fedora container pinned by digest, which carries mkosi, so the build host installs
# nothing. Rootful podman, because mkosi mounts and creates device nodes. All the paths it is given must live under
# WORKDIR, which is the only directory shared with the container besides the repository.
# Usage: build-in-container.sh WORKDIR build-uki.sh-arguments...
set -euo pipefail
W="$(cd "${1:?workdir}" && pwd)"; shift
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
# The staged generation is verified here, on the build host, by the project's own gate.
OUT="${1:?outdir}"; CTX="${2:?staged generation}"; mkdir -p "$OUT"
"$REPO/ci/verify-build-context.sh" "$CTX" "${VARIANT:-sealed-lab}" > "$W/context-result.txt"
export CONTEXT_RESULT="$W/context-result.txt"
FEDORA="registry.fedoraproject.org/fedora@sha256:e78cd1a688cd079c23864f289a89a49a3f4ad66d817864e325e1d058310ee95c"
exec sudo --preserve-env=CONTEXT_RESULT,MKOSI_CACHE,VARIANT,CONSOLE_KARG,INSTALL_STAGE,TARGET_DEBUG podman run --rm --privileged --net=host --security-opt label=disable \
  -v "$REPO:$REPO" -v "$W:$W" -w "$REPO/image/generic-installer" -e CONTEXT_RESULT -e MKOSI_CACHE -e VARIANT -e CONSOLE_KARG -e INSTALL_STAGE -e TARGET_DEBUG \
  "$FEDORA" bash -euc 'dnf -y -q install mkosi dnf5 rpm cpio zstd xz createrepo_c systemd-ukify python3-pefile sbsigntools util-linux >/dev/null
    exec "$@"' _ "$REPO/image/generic-installer/build-uki.sh" "$@"
