# Neural ICE CoreOS — Deliverable 1
# Isolated compilation environment (GB10 kernel + NVIDIA r595 driver).
#
# Base: CentOS Stream 10 (ABI aligned with RHEL 10, like the nvidia-gb10 source).
# Multi-arch: the SAME image builds natively on aarch64 (DGX Spark, <arm64-build-host>)
# and on x86_64 (<x86_64-build-host>) — `podman build` selects the host's arch.
#
# Build:
#   podman build -t neural-ice/kernel-builder:stream10 -f build/Containerfile.builder build/
FROM quay.io/centos/centos:stream10

# CRB (codeready-builder) repo required by the kernel BuildRequires.
RUN dnf -y install 'dnf-command(config-manager)' \
 && dnf config-manager --set-enabled crb \
 && dnf -y install epel-release || true

# Kernel + RPM build tooling. The kernel's precise BuildRequires are
# resolved dynamically by `make dist-get-buildreqs` in build-kernel.sh
# (we don't pin them here to avoid drifting from the upstream source).
RUN dnf -y groupinstall "Development Tools" || dnf -y install gcc make ; \
    dnf -y install \
        git rpm-build rpmdevtools dwarves \
        bison flex openssl-devel elfutils-libelf-devel \
        bc kmod ncurses-devel \
        perl python3 hostname diffutils which findutils \
        gcc-c++ zstd xz tar sudo \
 && dnf clean all

# Full BuildRequires of the nvidia-gb10 kernel, resolved via `make dist-get-buildreqs`
# (source of truth = the kernel spec). Avoids the BuildRequires-check failure
# in rpmbuild during `make dist-rpms`. Repos: baseos/appstream + CRB + EPEL.
RUN dnf -y install \
        audit-libs-devel binutils-devel bpftool centos-sb-certs clang \
        dosfstools dracut e2fsprogs fuse-devel glibc-static hmaccalc \
        java-devel kernel-rpm-macros libbabeltrace-devel libbpf-devel \
        libcap-devel libcap-ng-devel libmnl-devel libtraceevent-devel \
        libtracefs-devel libxml2-devel llvm-devel lvm2 net-tools newt-devel \
        numactl-devel opencsd-devel openssl pciutils-devel python3-devel \
        python3-docutils python3-jsonschema python3-pip python3-pyyaml \
        python3-setuptools python3-wheel rsync swig system-sb-certs \
        systemd-boot-unsigned systemd-udev systemd-ukify tpm2-tools \
        xfsprogs xmlto xxd \
 && dnf clean all

# Non-root user for compilation (isolation; no builds as root).
ARG BUILDER_UID=1000
RUN useradd --create-home --uid ${BUILDER_UID} builder \
 && mkdir -p /workspace /output \
 && chown -R builder:builder /workspace /output
RUN su - builder -c 'rpmdev-setuptree'

USER builder
WORKDIR /workspace

# The clone + compilation are driven by build-kernel.sh (mounted at runtime),
# not frozen into the image: the branch/source stay configurable and auditable.
ENTRYPOINT ["/bin/bash"]
