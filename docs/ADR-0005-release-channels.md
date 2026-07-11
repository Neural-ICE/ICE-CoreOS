# ADR-0005 — Release channels & promotion

- **Status**: Accepted
- **Date**: 2026-06-30
- **Decider**: Business/Security Owner (human)
- **Related**: [ADR-0003](ADR-0003-base-and-update-model.md) (bootc OS, native OTA, open-core); ICE-Fabric **ADR-0023** (uniform packaging & OTA)

> **Ring set superseded (2026-07-11)**: the three-ring `alpha|beta|prod` set decided below
> is reduced to **two rings: `beta|stable`**, unified with the appliance-bundle channels —
> see ICE-Fabric **ADR-0028**. `beta` = validation ring (every push to `main`, runs on the
> lab validation appliance); `stable` = customers/community (promoted). The promotion
> mechanics (re-tag by digest, never rebuild) are unchanged; the flow is now simply
> `beta → stable`. The old `:alpha`/`:prod` tags remain on the registries for rollback and
> forensics but **no longer move**; devices still following them re-bake onto the new rings
> at their next re-seed or `bootc switch` (no tag aliases are maintained — accepted, no
> customer fleet at switch time). The rest of this ADR is kept as decided for the record.

> **Amendment (2026-07-10, ICE-Fabric ADR-0023)**: the alpha/beta/prod channel *model*
> below is unchanged, but for the **appliance fleet** the channel tags now also live on
> **`registry.neural-ice.ch/neural-ice/neural-ice-coreos:<channel>`** (the sovereign OTA
> target), and `promote.yml` moves the channel pointer on **both** GHCR and the sovereign
> registry by the same digest. The GHCR channel tags remain for community/open-core pulls.

## Context

ICE-CoreOS ships as a single OCI image on GHCR (`ghcr.io/neural-ice/neural-ice-coreos`)
and updates via `bootc upgrade`. We need a release process that lets us:

- push frequently during development,
- expose a small ring of testers before going wide,
- publish a stable build for production appliances and the community,
- guarantee that what was tested is exactly what ships (no rebuild drift),
- be trivial to operate (no bespoke tooling).

## Decision

### Three channels as moving tags + immutable version tags

| Channel | Moving tag | Immutable tag | Cadence |
| --- | --- | --- | --- |
| alpha | `:alpha` | `:<version>-alpha.<run>` | every push to `main` (CI) |
| beta | `:beta` | (promoted digest) | manual, occasional |
| prod | `:prod` | (promoted digest) | manual, when validated |

`VERSION` holds the semantic base (e.g. `0.1.0`); CI appends `-<channel>.<run>` for the
immutable tag and also moves the channel tag.

### Promotion = re-tag by digest, never rebuild

Promotion (`alpha → beta → prod`) copies the **manifest by digest** to the target channel
tag (`skopeo copy docker://…@sha256:… docker://…:beta`). The bytes validated in alpha are
bit-for-bit what land in beta and prod. No rebuild, no drift, instant, reversible.

```
push → CI → :alpha           (build-image.yml, automatic)
promote alpha→beta → :beta   (promote.yml, manual workflow_dispatch)
promote beta→prod  → :prod   (promote.yml, manual workflow_dispatch)
```

### Consumers subscribe to a channel

An installed appliance records its OTA origin as `…:<channel>` (via the installer's
`--target-imgref`), so `bootc upgrade` follows that channel. Dev appliances track `:alpha`
or `:beta`; production and the community track `:prod`. Switching channel = `bootc switch`.

### Implementation

- `.github/workflows/build-image.yml` — builds + pushes `:alpha` (+ version tag) on push;
  `workflow_dispatch` can target any channel. Self-hosted ARM64 runner (artifacts).
- `.github/workflows/promote.yml` — `workflow_dispatch(from_channel, to_channel,
  source_ref?)`; re-tags the digest. Hosted runner (skopeo only).
- `.github/workflows/release-installer.yml` — builds the flashable `.img` installer for a
  channel and attaches it to a GitHub Release.
- `ci/build-image.sh` / `ci/stage-artifacts.sh` — shared build/stage logic.

## Consequences

- The package must stay **public** for free community pulls and OTA egress.
- GHCR retention should keep recent immutable `-alpha.<run>` tags for rollback/forensics.
- Heavy GB10 artifacts (kernel/driver) are built rarely (`build-kernel.yml`) and staged on
  the runner; the per-push image build is fast (no kernel rebuild).
- The same mechanism scales to future variants (x86, Strix Halo) by adding image
  names/tags, not new processes.
