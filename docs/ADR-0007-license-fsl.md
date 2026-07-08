# ADR-0007 — Repository license: FSL-1.1-ALv2 (Functional Source License)

- **Status**: Accepted
- **Date**: 2026-07-08
- **Decider**: Business Owner (human)
- **Related to**: [ADR-0003](ADR-0003-base-and-update-model.md) (open-core model)

## Context

ICE-CoreOS is the public, auditable OS layer of a commercial appliance. The
goals for its license, as formulated by the decider:

1. **Transparency and auditability** — anyone (including enterprise security
   teams evaluating the product at work) must be able to read, build, audit
   and test the OS without legal ambiguity.
2. **Free personal / non-commercial use.**
3. **No commercial re-use by third parties** — a competitor or integrator must
   not be able to take the OS and sell it (or a service based on it) during
   its commercial life.

The README previously said "Apache-2.0" while the repository carried **no
LICENSE file** — legally ambiguous and inconsistent. A decision was needed
before the first tagged release and before any external contribution.

## Decision

**FSL-1.1-ALv2** (Functional Source License 1.1, with Apache-2.0 future
license) — [LICENSE.md](../LICENSE.md), SPDX: `FSL-1.1-ALv2`.

What it does, per version of the software:

- **Everything is permitted except a "Competing Use"** (offering the Software,
  or substantially the same functionality, to others in a commercial product
  or service). Internal use — including commercial internal use — professional
  evaluation, security auditing, education and research are all permitted.
  This delivers goal 1 *better than a non-commercial license would*: the
  enterprise evaluator auditing this OS in a work context is squarely licensed.
- **Each release automatically converts to Apache-2.0 two years after it is
  made available** (irrevocable future grant). The sovereignty promise
  ("this code will be genuinely open") has a legal mechanism behind it, and
  the earlier Apache-2.0 statement becomes true — on a two-year delay.

## Alternatives rejected

- **PolyForm Noncommercial 1.0.0** — matches goal 3 literally but breaks
  goal 1: our own prospects (enterprises) are "commercial" users, so the very
  people we want auditing and piloting the OS would violate the license.
  Would have required a custom evaluation/audit grant and dual licensing for
  every pilot. Never converts to open source.
- **BUSL-1.1** — same family, but parameterized: the *Additional Use Grant*
  must be drafted (custom legal text = ambiguity risk), the change date is
  chosen (up to 4 years), and the change license is chosen. FSL is the fixed,
  lawyer-reviewed, community-known instance of the same idea (2 years,
  Apache-2.0, competing-use-only restriction).
- **Apache-2.0 today** — maximal adoption but zero protection of the
  commercial window; a competitor could ship the appliance OS immediately.

## Scope and boundaries

- The license covers the **content of this repository authored by TKRI**
  (build recipes, scripts, overlays, docs). **Terminology**: this makes the
  repo *source-available*, not OSI open source, until each version's Apache
  conversion — public communication must not claim "open source" before that.
- **Upstream components remain under their own licenses** (Linux kernel and
  GRUB2 = GPL, CentOS Stream packages, NVIDIA driver EULA/open-modules dual
  license, shim = BSD). The built OS image is an *aggregate*; nothing in FSL
  applies to those components, and their notices are preserved.
- **No impact on Secure Boot signing** (ADR-0002): shim-review and Microsoft
  do not require the OS to be open source; the audit exemption depends on shim
  chain-loading an open-source bootloader (GRUB2, GPL — unchanged).
- **Contributions**: external contributions are accepted under the
  **Developer Certificate of Origin** (DCO, `Signed-off-by`) with an inbound
  license grant to TKRI broad enough to sustain the FSL + future-Apache
  scheme (see [CONTRIBUTING.md](../CONTRIBUTING.md)).
- **Trademarks**: FSL explicitly grants no trademark rights; the "Neural ICE"
  name and branding are protected independently of the code license.

## Consequences

- (+) Goals 1–3 all satisfied with a standard, unmodified, SPDX-listed text.
- (+) Time-bomb to Apache-2.0 strengthens the sovereignty/trust narrative.
- (+) GitHub/SPDX tooling recognizes `FSL-1.1-ALv2`.
- (−) Not OSI open source during the first two years of each release —
  some distros/communities will not package or contribute during that window.
- (−) The two-year clock runs **per release**: old releases open up over time
  regardless of the product roadmap (accepted — that is the point).
