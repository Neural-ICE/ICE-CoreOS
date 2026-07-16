# Reproducible build of shim 16.1 (aarch64) with the Neural ICE vendor CA.
# Reviewers must be able to run `docker build .` and obtain a byte-identical
# shimaa64.efi — hence the pinned base image and the cross toolchain (same
# compiler package whether the host is x86_64 or aarch64).
#
# Build context must contain:
#   - neural-ice-uefi-ca.der   (vendor CA certificate, DER — from the key ceremony)
#   - sbat.neuralice.csv       (vendor SBAT entry)

FROM debian:12.11
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN apt-get update && apt-get install -y --no-install-recommends \
        make gcc libc6-dev \
        gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu \
        curl ca-certificates bzip2 xxd openssl file dos2unix \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Source of truth: the official 16.1 release tarball, checksum-pinned
# (matches the values published in the shim-review template).
ARG SHIM_VERSION=16.1
ARG SHIM_SHA256=46319cd228d8f2c06c744241c0f342412329a7c630436fce7f82cf6936b1d603
RUN curl -L -o shim-${SHIM_VERSION}.tar.bz2 \
        https://github.com/rhboot/shim/releases/download/${SHIM_VERSION}/shim-${SHIM_VERSION}.tar.bz2 \
    && echo "${SHIM_SHA256}  shim-${SHIM_VERSION}.tar.bz2" | sha256sum -c - \
    && tar xjf shim-${SHIM_VERSION}.tar.bz2

COPY neural-ice-uefi-ca.der /build/
COPY sbat.neuralice.csv /build/shim-${SHIM_VERSION}/data/

# No patches: vanilla 16.1 + vendor cert + vendor SBAT (data/sbat.*.csv files
# are picked up automatically by the shim build system). The default target
# builds shimaa64.efi, mmaa64.efi (MokManager) and fbaa64.efi (fallback).
RUN cd shim-${SHIM_VERSION} && \
    make ARCH=aarch64 CROSS_COMPILE=aarch64-linux-gnu- \
         VENDOR_CERT_FILE=/build/neural-ice-uefi-ca.der \
         2>&1 | tee /build/build.log

RUN mkdir /out && cd shim-${SHIM_VERSION} && \
    cp shimaa64.efi mmaa64.efi fbaa64.efi /build/build.log /out/ && \
    file /out/*.efi && \
    aarch64-linux-gnu-objcopy --only-section .sbat -O binary /out/shimaa64.efi /dev/stdout && \
    sha256sum /out/*.efi | tee /out/SHA256SUMS
