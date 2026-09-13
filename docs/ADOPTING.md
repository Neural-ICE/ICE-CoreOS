# Adopting ICE-CoreOS

This OS is published as a reusable distribution. Nothing in it phones home and
no credential is baked into it. What it *does* carry is an **identity**: the
trust anchors it verifies against, and the namespace it seals into your TPM.

Those are the things you must decide before your first build. This page is the
list, and it is short on purpose.

See [ADR-0016](ADR-0016-open-core-namespace.md) for why these are build inputs
rather than configuration files. The short version: a trust anchor that can be
redirected by whoever writes a config file is not a trust anchor.

## What you must supply

### `NI_TRUSTED_TIME_ISSUER` — who may tell your appliance what time it is

A build-time environment variable, read by `ni-ota-verify` and baked into the
binary. It names the authority whose signed time assertions the appliance will
accept.

**If you do not set it, the verifier accepts no trusted-time assertion at all.**
That is deliberate: a build that was never told whom to trust must not trust
anyone. It is not a warning you can ignore — the anti-rollback and freshness
checks depend on it.

```sh
NI_TRUSTED_TIME_ISSUER=time.example.org ./ci/build-image.sh
```

The test suite supplies a deliberately wrong value of its own
(`trusted-time.example.test`), so a green suite proves the *contract*, never the
identity of any deployment.

### Secure Boot keys

`secureboot/` documents the chain and the ceremony
([`key-ceremony.md`](../secureboot/key-ceremony.md),
[`signing-pipeline.md`](../secureboot/signing-pipeline.md)). The published
trust policies under `secureboot/trust-policies/` are **ours**. An appliance
you ship must be anchored to keys you control, and the shim you distribute must
be one you are entitled to distribute.

### The sealed-record namespace

The magic bytes and domain-separation strings this OS writes into your TPM
identify the *operator*, not the mechanism. They default to the values this
repository has always used, so an unconfigured build keeps reading records
sealed by earlier builds.

Change them and you start a **new lineage**: appliances sealed under your
namespace cannot be verified by a build using another, and the reverse. That is
the intended property of a domain separator, and it is why the default exists —
records already sealed in deployed hardware cannot be re-sealed.

## What you inherit and should not change

The **layout** of every sealed record, the NV index assignments, the ordering
guarantees of the OTA state machine, and the fail-closed behaviour of every
check. These are the mechanism. They are documented in ADR-0012 through
ADR-0015 and exercised by `tools/ni-ota-verify/tests/`.

If you find yourself editing one of those to make your deployment work, that is
a defect in this repository, not a customisation. Please open an issue.

## What is deliberately absent

This repository is the operating system. It is not the appliance product built
on top of it: the licensed runtime, the inference stack, the registry gateway
and the control plane live elsewhere and are not published here. Where a
document needed to explain *why* a mechanism exists, it describes the mechanism
and not that product.

## Variants

`VARIANT=debug` builds a development image. `VARIANT=sealed-lab` builds the
sealed lab posture. `VARIANT=prod` is reserved for a reviewed production policy
and a generation finalized by that exact policy. Read
[ADR-0014](ADR-0014-access-policy-lab-vs-customer.md) before choosing: the
variant decides whether an operator can ever reach a shell on the appliance.
