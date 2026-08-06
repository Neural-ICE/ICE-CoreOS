# Container-image signature policy

This OS refuses to transfer a container image it cannot verify. The refusal is
the default: `/etc/containers/policy.json`, shipped in the overlay, is

```json
{ "default": [ { "type": "reject" } ], "transports": { "docker": {} } }
```

and it names nothing. A build of this repository produces an OS that trusts
**nobody** — which is the only honest vanilla state for a signature policy, and
the only one that is safe to hand to a third party. An OS that accepts anything
is not "unconfigured"; it is configured to trust everybody, and it looks
identical to a configured one until an unsigned image is pulled and nothing
happens.

## Who consumes this file

`containers/image` — the library behind `podman`, `skopeo`, and `bootc`
(through `ostree-ext`). It is the same code path in all three; this is not a
podman-specific setting.

## The injection point

Which repository is trusted, and under which public key, is **deployment
identity**. It never lives in this tree (FAB-0032). The composer supplies it, at
composition, from its own derivation of this image:

```dockerfile
COPY my-image-signing.pub /etc/containers/keys/image-signing.pub
RUN /usr/libexec/neural-ice-render-container-policy \
      --signed-scope registry.example.org/org=/etc/containers/keys/image-signing.pub
```

`/etc/containers/keys` is created 0755 by the image build; it is empty in the
vanilla OS.

The renderer — not the composer's care — is what holds the posture:

* the default is `reject` and is **not a parameter**;
* `insecureAcceptAnything` cannot be produced by any input;
* an absent, empty, unreadable or relative key path is refused **and nothing is
  written**, so a composition that got it wrong fails at build instead of
  shipping an appliance that refuses its own images in the field;
* it writes the matching `registries.d` entry, because the policy alone is not
  enough (see below).

The image build itself re-checks that the shipped policy is fail-closed and is
byte-identical to the renderer's zero-scope output; a divergence fails the
build.

## Two measured facts that are easy to get wrong

Both were measured on 2026-08-06 with `skopeo` 1.21.0-dev / 1.13.3 and `cosign`
2.6.3 against a local registry. They are quoted here because each one silently
turns "verified" into "rejected".

**1. `use-sigstore-attachments` is required, or a correctly signed image is
refused as unsigned.** Without it, `containers/image` never looks at the cosign
`sha256-<digest>.sig` attachment:

```
Source image rejected: A signature was required, but no signature exists
```

This is why the renderer writes `registries.d` as well as the policy.

**2. cosign signs with a BARE-REPOSITORY identity, so the strict
`signedIdentity` modes accept nothing.** `matchRepoDigestOrExact` (the
`containers/image` default) and `matchExact` both reject a correctly signed
image, whether it is pulled by tag or by digest:

```
Source image rejected: Signature for identity "127.0.0.1:15000/ni/app" is not accepted
```

The renderer therefore defaults to `matchRepository`. That is not a relaxation
chosen to make a gate pass — the stricter values do not accept cosign signatures
at all. What is given up is that a signature made for one tag of a repository
also validates another tag of the *same* repository; which exact digest may be
deployed is decided upstream, by the signed BOM (`ni-ota-verify`). A composer
whose signer writes full references can pass
`--signed-identity matchRepoDigestOrExact`.

## What this policy does NOT gate — read before assuming coverage

**Images already in local container storage.** The policy is a *transfer* gate.
Measured: with `default: reject` and no `containers-storage` entry,
`podman create` from an image already in the store still succeeds. The preloaded
seed store is provisioned by the installer from verified media, not through this
gate.

**`bootc install`, and therefore the offline installer.** Read in the bootc
source (`crates/lib/src/install.rs`, `main` on 2026-08-06): the install *source*
is always fetched with `SignatureSource::ContainerPolicyAllowInsecure` —
verbatim comment: *"There are no signatures to verify since we're fetching the
already pulled container."* Shipping `default: reject` therefore **cannot** break
`bootc install to-filesystem --source-imgref containers-storage:…`.

**`bootc upgrade`, unless the install asked for it.** Same source,
`utils.rs::sigpolicy_from_opt`: without `--enforce-container-sigpolicy` the
installed origin records `ContainerPolicyAllowInsecure`, so the OS update path
does not consult this policy at all. Turning it on requires (a) an OS image that
is actually signed — no workflow in this repository signs one today — and (b)
the installer passing the flag. Both are outside this mechanism and are named,
not assumed.

## Proof

`ci/test-oci-signature-policy.sh` — runs the four decisions against the real
policy engine, plus every doubt case, plus a non-vacuity check that fails the
suite if the harness has gone inert.
