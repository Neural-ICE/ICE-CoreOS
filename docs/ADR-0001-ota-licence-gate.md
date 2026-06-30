# ADR-0001 — License gate on the OTA pipeline (Standalone)

- **Status**: Accepted
- **Date**: 2026-06-27
- **Deciders**: Business/Security Owner (human) — proposed by the architect
- **Product context**: Neural ICE CoreOS, sovereign inference appliances
  (CH/EU), private distribution via GHCR, without Kubernetes.

## Context

The host OS is packaged as a bootable OCI image (CoreOS Layering) and distributed
privately on GHCR. Access to updates must be **conditioned on a valid
subscription**. The system is *Standalone*: no orchestrator, no central control
plane pushing updates. Validation relies on the existing architecture:

- a local Neural ICE appliance,
- a **Tauri** thin client communicating over **mTLS** with the appliance to validate
  the subscription and push the license,
- the **Keygen.sh** SaaS API as the source of truth for entitlements.

## Decision

Replace Fedora CoreOS's native auto-update (**Zincati**) with a **gated wrapper**
triggered by a `systemd.timer` (8 h cycle). The wrapper:

1. validates the license **locally** then via **Keygen.sh** (fingerprint = `machine-id`);
2. obtains a **minimally-scoped, ephemeral GHCR token** (`repository:<repo>:pull`)
   from the Neural ICE appliance over mTLS;
3. materializes this token in **`/run/ostree/auth.json`** (tmpfs, `0600`);
4. runs `rpm-ostree upgrade` (atomic A/B deployment);
5. **destroys** the auth file via `trap` (on success **or** failure).

### Major technical fix vs. the initial specification

The spec called for `rpm-ostree upgrade --auth-file=/run/ostree-auth.json`.
**This option does not exist.** Verified against the upstream documentation:

- ostree (ostree-rs-ext, via skopeo) automatically reads, in this order,
  `/etc/ostree/auth.json` then `/run/ostree/auth.json`, in
  `containers-auth.json(5)` format.
- We therefore use `/run/ostree/auth.json` (the `ostree/` directory, not
  `ostree-auth.json`), read **natively** by `rpm-ostree upgrade`.

Positive consequence: no flag to wire up, credential in **memory only**
(tmpfs `/run`), standard auto-discovery. The "ephemeral" design is preserved and
reinforced.

Refs:
- <https://coreos.github.io/rpm-ostree/container/>
- <https://github.com/coreos/rpm-ostree/issues/4180>

### Security Owner trade-offs (2026-06-27)

Decisions ratified by the Decision Maker / Security Architect:

1. **GHCR token via mTLS — APPROVED.** The appliance holds **no** GitHub secret
   and does **not** query a global GitHub App (an on-premise anti-pattern: the
   compromise of one appliance would exfiltrate the registry secrets).
   **Zero Trust** model: the appliance proves its identity (mTLS + Keygen), the
   Neural ICE backend issues an **ephemeral token, scoped `pull` to a single package**.
2. **Offline grace — ADJUSTED to 168 h (7 days)** (was 72 h). An HPC/AI appliance
   (DGX Spark) may be isolated for maintenance, audit, or a link outage.
   72 h would cut off the AI stack on a mere DNS incident over a long weekend. 7 days
   provides the required resilience with no material financial risk to the subscription.
   → `OFFLINE_GRACE_HOURS="168"` (default in the wrapper, the Ignition, the example).
3. **`AUTO_REBOOT=false` — APPROVED.** An automatic post-OTA reboot is unacceptable on
   long-running AI workloads (training/inference lasting hours/days). The
   **staged** deployment (downloaded in the background, applied at the next reboot
   planned by the admin / thin client) is the only production-grade approach.

### Zincati disabled

`zincati.service` is **masked** in the image (`image/Containerfile`) to avoid
two competing update mechanisms. The only update path is the wrapper.

## Threat model (STRIDE) — summary

| Threat | Vector | Control |
|--------|---------|----------|
| **S**poofing | Fake GHCR server / appliance | mTLS (client cert + CA pin) to the appliance; TLS + (recommended) **cosign/sigstore** on the OCI image |
| **T**ampering | OS image altered in transit/at rest | **atomic** rpm-ostree update + ostree checksum; cosign image signature (`containers/policy.json` policy) |
| **R**epudiation | Untraceable update action | Timestamped `journald` logging (no secrets); `rpm-ostree status` keeps deployment history |
| **I**nfo disclosure | GHCR token leak | **Ephemeral** token, `pull` scope to a single repo, tmpfs `0600`, destruction `trap`, never logged |
| **D**oS | Update loop / GHCR rate-limit | 8 h timer + `RandomizedDelaySec`; backoff; no aggressive retry |
| **E**levation | Privileged injector container | `nvidia-driver-injector`: image **pinned by digest**, targeted `--pid=host`, minimal scope, not network-exposed |

### Accepted residual risks (validated by the Security Owner — 2026-06-27)

- **Simulated token minting**: minting the restricted-scope GHCR token is
  materialized by an mTLS call to the appliance (`get_ghcr_token`). In production,
  the appliance must implement it via a **GitHub App** (installation token scoping
  `read:packages` to the single package) — the code clearly marks the integration
  point (`# >>> SIMULATION`).
- **Image signature verification**: by default `ostree-unverified-registry:`
  (TLS only). For production, switch to `ostree-image-signed:` +
  cosign policy. Snippet provided below.

## Signature verification (recommended for production)

`/etc/containers/policy.json`:

```json
{
  "default": [{ "type": "reject" }],
  "transports": {
    "docker": {
      "ghcr.io/neural-ice/neural-ice-coreos": [
        {
          "type": "sigstoreSigned",
          "keyPath": "/etc/neural-ice/pki/cosign.pub",
          "signedIdentity": { "type": "matchRepository" }
        }
      ]
    }
  }
}
```

Then, in the wrapper, replace the rebase target with
`ostree-image-signed:registry:ghcr.io/neural-ice/neural-ice-coreos:latest`.

## Rejected alternatives

- **Zincati + external barrier**: Zincati cannot condition a pull on a
  license; token scoping would be outside its model. Rejected.
- **Long-lived token in the image**: violates minimization and non-exfiltration.
  Rejected.
- **Direct pull by the Tauri thin client**: would couple the UI to
  registry/root privileges. Rejected (see desktop guardrails: no privileged credential on the frontend).

## Consequences

- (+) Sovereign, gated, atomic update, with no external control plane.
- (+) Minimal and ephemeral credential surface.
- (−) The appliance must expose a token-minting endpoint (dependency).
- (−) Responsibility for rotating the mTLS certs and the cosign key on the ops side.
