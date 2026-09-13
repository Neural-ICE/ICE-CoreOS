# ADR-0016 — One declared namespace, so the open core is actually adoptable

- **Status**: Accepted
- **Date**: 2026-09-13
- **Decider**: Business/Security Owner (human)
- **Related**: [ADR-0013](ADR-0013-device-root-tpm-v1.md) (device root),
  [ADR-0014](ADR-0014-access-policy-lab-vs-customer.md) (access profiles),
  [ADR-0015](ADR-0015-installer-trust-anchor-uki-verity.md) (sealed records)

## Context — the promise and what contradicts it

The README says this OS is published as a *"vanilla, reusable distro — no baked
credentials, nothing phoning home. Anyone can install it on a DGX Spark."* The
CI boundary (`ci/test-open-core-boundary.sh`) enforces the credential half of
that: two sovereign endpoint hostnames may not appear anywhere Git can see.
That part holds, and nothing in this ADR weakens it.

The reusable half does not hold, for three reasons found on 2026-09-13.

**A third party cannot build the verifier.** `NI_TRUSTED_TIME_ISSUER` is
mandatory — absent, `ni-ota-verify` accepts no trusted-time assertion at all,
which is the correct fail-closed behaviour — and it appears in no README and no
document. It is discoverable only by reading a CI workflow. Someone cloning the
repository hits this at their first `cargo build` and has nothing to read.

**A third party cannot avoid sealing our brand into their hardware.** The OTA
verifier alone carries about thirty literals that name this product: the magic
bytes of every sealed TPM record (`NI-TPM02`, `NI-PCRG1`, `NI-DONE1`,
`NI-DONE2`), the domain-separation strings (`neural-ice:tpm:…`,
`neural-ice:ota:…`), and the schema identifiers of every evidence file. None is
configurable. An adopter therefore writes *our* namespace into *their* TPM,
permanently, on first boot.

**The public repository documents a private product.** Dozens of files refer to
`icecore`, to ICE-Fabric, to the licence gate and to the AI stack — components
that exist only in private repositories. A reader follows those references to
nothing.

The pattern that fixes this is already in the tree and already argued, in
`trusted_time.rs`: the issuer *"used to be a string literal in this file, which
put a specific deployment's identity into an open-core OS — a third party could
not build this verifier against their own authority without editing the
source."* It was made a build-time input for exactly that reason. The decision
below finishes what that one change started.

## Decision

**One namespace, declared once at build time, with this deployment's values as
the default.**

1. Every string that identifies the OPERATOR rather than the MECHANISM is
   derived from a single declared namespace, supplied at image-build time.
2. The namespace has a default equal to the values in use today, so an
   unconfigured build of this repository produces byte-identical records. This
   is not a convenience: records already sealed in deployed TPMs carry those
   bytes, and a change would make installed appliances unverifiable.
3. Values that are WRITTEN into persistent state — TPM record magics, sealed
   evidence schemas — are part of the namespace but are **versioned**: an
   adopter who changes them starts a new lineage and cannot read records sealed
   under another. The code states that rather than implying it.
4. Values only COMPARED at runtime carry no such constraint and follow the
   namespace freely.
5. Build inputs are documented where an adopter looks — the README and one
   adoption page — not only where CI reads them.
6. The boundary test grows a second rule: a Git-visible file may not reference a
   component that does not exist in this repository. Prose that explains the
   mechanism stays; prose that documents a private product goes.

## Consequences

Someone can build this OS under their own namespace, seal their own records and
run their own trust anchors, without editing a source file. That is what
"reusable distro" has to mean for an OS whose whole subject is sealed identity.

For Neural ICE the same mechanism separates its own deployments: the OEM bench,
the laboratory and a customer appliance share one domain-separation string
today, so a record sealed on the bench and a record sealed for a customer live
in the same cryptographic domain. A declared namespace separates them without a
fork.

It also makes the sealed-record contract testable against the *layout* instead
of the brand. The defect of 2026-09-13 — a reserve read at byte 40 where the
ceremony writes a freshness base — was a layout defect that no test could reach
while the layout and the brand were the same literals.

The cost is that an adopter who changes the namespace cannot read our records,
and we cannot read theirs. That is the correct outcome and it is now explicit.
