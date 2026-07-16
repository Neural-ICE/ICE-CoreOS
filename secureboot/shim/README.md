# Reproducible shim 16.1 build (aarch64)

Builds the Neural ICE shim exactly as it will be submitted to
[rhboot/shim-review](https://github.com/rhboot/shim-review): official 16.1
release tarball (checksum-verified), **zero patches**, Neural ICE CA embedded
as `vendor_cert`, vendor SBAT entry appended.

## Usage

```sh
cp /path/to/neural-ice-uefi-ca.der .   # key-ceremony output (DER!)
./build.sh                              # or ENGINE=docker ./build.sh
```

Artifacts land in `out/`: `shimaa64.efi`, `mmaa64.efi`, `fbaa64.efi`,
`build.log`, `SHA256SUMS`.

## Reproducibility check (do this before tagging the submission)

Run `./build.sh` twice (it always builds `--no-cache`) and compare
`SHA256SUMS`. Reviewers will run `docker build .` themselves; if the hash
drifts, the submission is dead on arrival. The base image is tag-pinned
(`debian:12.11`); if Debian ships a point release between our build and the
review, rebuild + update the recorded hashes rather than arguing about it.

## Verification of the tarball's PGP signature (optional but recommended)

The release is signed by Peter Jones (key
`B00B48BC731AA8840FED9FB0EED266B70F4FEF10`, signing subkey
`02093E0D19DDE0F7DFFBB53C1FD3F540256A1372` — a copy lives in
`rhboot/shim-review` as `pjones.asc`):

```sh
curl -LO https://github.com/rhboot/shim/releases/download/16.1/shim-16.1.tar.bz2.asc
gpg --verify shim-16.1.tar.bz2.asc shim-16.1.tar.bz2
```

## What must NOT be in this directory

Private keys, in any form. The only key-material input is the **public** CA
certificate in DER. (`.key`/`.pem` are already git-ignored repo-wide.)
