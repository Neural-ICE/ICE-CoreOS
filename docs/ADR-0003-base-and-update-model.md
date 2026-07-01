# ADR-0003 — Base OS, update model and open-core

- **Status**: Accepted (locks in the foundation)
- **Date**: 2026-06-28
- **Decider**: Business/Security Owner (human)
- **Supersedes**: the parts of [ADR-0001](ADR-0001-ota-licence-gate.md) that
  gated the **OS** by license and masked Zincati on Fedora CoreOS.

> **Amendment (2026-07-01, [[ADR-0006-kernel-4k-page-size]])**: the base and the
> update model are unchanged, but the kernel flavor is now the **standard 4k**
> `kernel` (not `kernel-64k`) — for compatibility with the container AI stack.
> The "64k tested/QA" rationale below is superseded on the page-size point only.

## Context (the path taken)

The real need, as formulated by the decider: *"an immutable read-only OS with
rpm-ostree and OTA for an autonomous edge AI device, without SSH in prod and without
telemetry."*

Framing decisions taken along the way:
- **No Fedora CoreOS.** The GB10 `kernel-64k` kernel is **el10** (Red Hat
  `nvidia-gb10`), GB10 is **not** in mainline, and **Fedora does not provide
  a `kernel-64k` variant**. Grafting el10 onto Fedora 44 = userspace mismatch +
  64k untested on the Fedora side.
- **No Zincati.** Zincati only serves **centralized fleet
  coordination** (Cincinnati graph, FleetLock, rollout). But "no telemetry"
  forbids any centralized orchestration/monitoring. The need reduces to
  "each appliance updates itself" → a **timer + native update** is enough.
- **No COSA / in-house distro.** Building one's own "SCOS" via
  coreos-assembler = becoming a distro maintainer (permanent cost), and Zincati
  would not even be free there (el-CoreOS = Machine Config Operator, not Zincati).
  Over-engineering, rejected.

## Decision

### Foundation
- **Base = CentOS Stream 10 in bootc mode** (`quay.io/centos-bootc/centos-bootc:stream10`).
  el10 everywhere (kernel **and** userspace) → **zero mismatch, 64k tested/QA RHEL/CentOS**.
  **Validated on the GB10 test hardware**: boot, 64 KiB pages, r595 driver, GPU
  (`nvidia-smi`), Secure Boot, nvme install.
- **Immutable / read-only**: `/usr` mounted read-only (OS); `/var` read-write
  persistent (state/data); `/etc` versioned per deployment. ostree model:
  content-addressed store, multiple deployments, **atomic local rollback**.

### OS update model = **public, free, native**
- **PUBLIC OS image on GHCR** (`ghcr.io/neural-ice/neural-ice-coreos`).
  **Free and unlimited** egress on public GHCR → no cost even at 1M pulls.
  Transparency + community reuse (**open-core**).
- **Update = native `bootc upgrade`** from the GHCR image (re-enable the native timer
  `bootc-fetch-apply-updates.timer`, which we had masked). **No license gate
  on the OS** (it is public/free), **no custom wrapper**, **no Zincati**.
- Atomic (new ostree deployment), local rollback always available.

### Appliance posture (prod)
- **No SSH in prod**: `sshd` masked. No remote shell. Sealed appliance.
  (The `core` user + SSH key was only for **lab validation**.)
- **No telemetry**: no usage/state data sent to Neural ICE. The device
  only contacts, functionally: Keygen (license) + the registry
  (image). To be stated as such on the contract side.
- **Management plane = Tauri thin client over mTLS** (onboarding, license, triggering
  local rollback). Break-glass = local physical console.
- **First-boot provisioning = Ignition**.

### Open-core: where the gating lives
Two layers, separated:
- **OS layer** = **public** bootc image (GHCR), free update. Auditable, reusable.
- **Application layer + gating** = **private Podman containers** (including the
  Keygen gating container + the proprietary AI stack). The appliance, for **pull/run**:
  validates license + entitlements (Keygen) → **temporary deployment token** →
  Neural ICE **private registry**. That is where the commercial value + control reside.
- → The egress cost only applies to the private side = proportional to the **number of
  paying customers** (controlled). The public OS costs nothing.

## Consequences

- (+) Clean, immutable el10 combo, **already proven** on GB10 — no distro to maintain.
- (+) Trivial OS OTA: **native bootc** mechanism, zero custom code, free egress.
- (+) Sovereignty + transparency: auditable public base; secret/value in the
  gated private layer.
- (+) Appliance security: immutable + Secure Boot + read-only `/usr` + no SSH.
- (−) Zero-touch Secure Boot in prod still depends on the Microsoft-signed shim
  (see [ADR-0002](ADR-0002-secure-boot-zero-touch.md)) — unchanged.
- (−) Low residual risk: public GHCR is *"currently free"* (1-month notice
  before any billing). Possible mitigation: mirror/CDN.

## Implementation (delta vs what runs on the GB10 test hardware)
1. OS image rebuilt **without a license gate** on the OS: remove the Keygen wrapper from
   the OS path, **re-enable `bootc-fetch-apply-updates.timer`** (free native update).
2. **Mask `sshd`** for prod (keep a lab variant with SSH).
3. Add **Ignition** for provisioning.
4. Publish the **public** image on `ghcr.io/neural-ice/neural-ice-coreos`.
5. The Keygen gating layer + private registry = **containers**, outside the public image
   (later phase, appliance repo).
