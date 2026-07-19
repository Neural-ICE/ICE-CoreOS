# GB10 artifact staging runbook

This runbook covers runner-local artifacts only. It never publishes an image or moves an OTA
channel. Private signing keys must not enter the store, repository or image context.

## 1. Produce a candidate

Dispatch the default-branch kernel workflow with immutable inputs:

```sh
gh api repos/Neural-ICE/ICE-CoreOS/dispatches \
  -f event_type=build-coreos-kernel \
  -F 'client_payload[kernel_ref]=<full-40-character-commit>' \
  -F 'client_payload[nvidia_driver_version]=<approved-version>'
```

The workflow writes `candidates/<run-id>/` under the configured `ARTIFACTS_DIR`. It verifies the
five required RPMs, their EVRA/aarch64 coherence and hashes, NVIDIA userspace version, and kernel
source revision. It also extracts and canonicalizes:

```text
candidates/<run-id>/unsigned-boot/vmlinuz
```

This is the exact PE input for the signing pipeline. Candidate creation never creates or changes
`current`.

## 2. Sign outside the store

The Owner-approved Secure Boot pipeline consumes the candidate vmlinuz and produces a clean
`SIGNEDBOOT_SRC` tree. It must contain exactly the matching vmlinuz plus these bootupd paths:

```text
usr/lib/modules/<uname-r>/vmlinuz
usr/lib/bootupd/updates/EFI/BOOT/BOOTAA64.EFI
usr/lib/bootupd/updates/EFI/BOOT/fbaa64.efi
usr/lib/bootupd/updates/EFI/BOOT/grubaa64.efi
usr/lib/bootupd/updates/EFI/BOOT/mmaa64.efi
usr/lib/bootupd/updates/EFI/centos/grubaa64.efi
usr/lib/bootupd/updates/EFI/centos/mmaa64.efi
usr/lib/bootupd/updates/EFI/centos/shimaa64.efi
```

It also emits `signed-boot-provenance.env`:

```text
generation_id=<run-id>
kernel_uname_r=<candidate-uname-r>
vmlinuz_unsigned_sha256=<candidate-canonical-vmlinuz-sha256>
```

Do not point `SIGNEDBOOT_SRC` at a key-ceremony workspace. Finalization rejects private-key PEM,
`.key`, `.p12`, `.pfx`, `.age`, multiple vmlinuz trees, missing paths and unsigned EFI files.

## 3. Finalize and activate

The trust policy is an Owner-approved executable with this contract:

```text
trust-policy SIGNEDBOOT_DIR KERNEL_UNAME_R
```

It returns zero only when every component maps to its approved signer/trust anchor. Finalize with:

```sh
ARTIFACTS_ROOT=<configured-artifact-root> \
SIGNEDBOOT_SRC=<clean-signed-boot-tree> \
SIGNED_BOOT_TRUST_POLICY_BIN="$PWD/secureboot/trust-policies/neural-ice-secureboot-lab-v1" \
SIGNED_BOOT_TRUST_POLICY_ID=neural-ice-secureboot-lab-v1 \
  ./ci/artifact-generation.sh finalize <run-id>
```

Finalization re-canonicalizes the signed vmlinuz and compares it with the candidate hash, runs the
trust policy, records the policy ID and executable SHA-256, re-hashes the complete generation, then
atomically moves `current`. Any failure leaves the previous `current` untouched.

The policy executable must hash-bind any external public trust anchors that it reads. The consumer
does not accept a hash from a GitHub variable: it hashes the reviewed executable in the default-
branch checkout, matches that exact ID/hash against `trust-policy.env`, and re-runs the policy.

## 4. Consume and recover

Materialize only a finalized `current`:

```sh
ARTIFACTS_ROOT=<configured-artifact-root> STAGING_DEST=image \
  ./ci/artifact-generation.sh materialize
VARIANT=debug ./ci/build-image.sh
```

Materialization independently revalidates the generation metadata and every hash immediately before
the image build. The consumer then binds the generation to its requested variant:

| Variant | Exact approved policy | Current availability |
| --- | --- | --- |
| `debug` | `neural-ice-secureboot-lab-v1` | LAB validation only |
| `prod` | `neural-ice-secureboot-prod-v1` | fail-closed until the reviewed PROD policy exists |

The build records the generation ID, artifact-manifest SHA-256 and exact trust-policy ID/SHA-256 as
OCI labels. After LAB finalization, request the default-branch CI producer rather than pushing an
image manually:

```sh
gh api repos/Neural-ICE/ICE-CoreOS/dispatches \
  -f event_type=build-coreos \
  -F 'client_payload[variant]=debug'
```

There is no push/merge trigger and no implicit variant. A production dispatch remains unavailable
until both the reviewed production policy executable and a generation finalized by that exact policy
exist. A successful dispatch publishes one immutable GHCR source artifact only. Central mirroring
and signed release-train promotion remain ICE-Fabric responsibilities; this dispatch never moves a
product channel.

To roll the CI staging pointer back, reactivate a retained generation; it is fully revalidated before
the atomic switch:

```sh
ARTIFACTS_ROOT=<configured-artifact-root> \
  ./ci/artifact-generation.sh activate <previous-generation-id>
```

Never delete a generation used by a published image. A `.preparing.*` directory is incomplete and
is never eligible for activation or consumption.
