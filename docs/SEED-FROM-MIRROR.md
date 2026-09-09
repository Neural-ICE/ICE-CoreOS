# Seed from the LAN mirror (`neuralice.seed_source=mirror`)

FAB-0057 P1.1. A registry-install medium (`neuralice.source=registry`) with a
LAN mirror and a preseal set can seal a release seed **without an `ni-seed`
partition**: the installer materialises `release/<closure_hex>/` on the
encrypted data volume by fetching every object of the sealed release closure
from the mirror, then runs exactly the `ni-ota-verify verify-seed-closure`
the `ni-seed` path runs before the install is reported successful. First boot
(`image/firstboot/neural-ice-seed-import.sh`) is unchanged.

Nothing the mirror says is trusted. The authority is, in order:

1. the sealed `neuralice.seed_closure` and `neuralice.seed_manifest` (the UKI
   signature covers them) -- they decide which bytes are the closure and the
   release manifest;
2. the closure, once its bytes hash to the sealed value -- it names every other
   object (digest, repository, media type, size);
3. `ni-ota-verify verify-seed-closure`, after the objects land -- it verifies the
   release authorization and delegation snapshot against the root key in the
   dm-verity root, and proves the whole tree (every object present, reachable,
   hashing to its name, nothing extra, READY consistent).

The mirror's TLS is pinned to the CA the medium seals (`neuralice.mirror_ca_
sha256`); no credential is presented (a controlled `lab-managed` install LAN).
No byte is ever used before it has been hashed against a sealed value or
against a closure whose hash is sealed.

## Sealed command line

| Term | Requirement |
|---|---|
| `neuralice.seed_source=mirror` | the only value; absent means "seed on the `ni-seed` partition" |
| `neuralice.source=registry` | refused otherwise: `seed-source-mirror-without-registry-source` |
| `neuralice.mirror` (+ `mirror_ca_sha256`, `mirror_ready`, `mirror_manifest`, `mirror_generation`) | refused otherwise: `seed-source-mirror-without-mirror` |
| `neuralice.preseal` | refused otherwise: `seed-source-mirror-without-preseal` |
| `neuralice.seed_closure` (+ `seed_manifest`, `seed_trusted_now`) | refused otherwise: `seed-source-mirror-without-seed-closure` |
| `mirror_ready == seed_closure`, `mirror_manifest == seed_manifest` | already forced by the existing rules (`mirror-ready-not-the-sealed-seed-closure`, `mirror-manifest-not-the-sealed-seed-manifest`) |

Every existing refusal keeps its precedence; the four new refusals are checked
last. Producer: `SEED_SOURCE=mirror` on `image/build-installer-usb.sh`
(requires `INSTALL_SOURCE=registry`, `INSTALL_MIRROR`, the preseal set, the six
seed documents as today, and `MIRROR_READY_SHA256`/`MIRROR_READY_MANIFEST_
SHA256` equal to the sealed seed hashes). `image/build-preloaded.sh` refuses
it, and the base producer refuses a raw that carries an `ni-seed` partition.
Nothing is copied to the medium.

Byte budget: the full composed line with short fixture names measures 1942 of
the 1957 bytes the kernel delivers; a long release authority or mirror name
can exceed it, and the producer's read-back refuses such a medium before it is
signed.

## Seed-pack contract (published by ICE-Fabric, consumed before the wipe)

The six seed documents are one OCI artifact on the mirror.

| Item | Value |
|---|---|
| Repository | `neural-ice/seed-packs` |
| Tag | `<closure_hex>` -- 64 lowercase hex, `sha256(release-closure.json)`. **Untrusted routing only.** |
| Fetch | `GET https://<mirror>/v2/neural-ice/seed-packs/manifests/<closure_hex>`, `Accept: application/vnd.oci.image.manifest.v1+json`, TLS pinned to the sealed CA, no credential, bounded to 64 KiB |
| `schemaVersion` | `2` |
| `mediaType` | `application/vnd.oci.image.manifest.v1+json` (refused otherwise) |
| `artifactType` | `application/vnd.neural-ice.seed-pack.v1+json` (refused otherwise) |
| `config` | exactly `{mediaType, digest, size}` = `application/vnd.neural-ice.seed-pack.config.v1+json`, `sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a` (the bytes `{}`), `2`. Not fetched. |
| Top-level keys | only `schemaVersion`, `mediaType`, `artifactType`, `config`, `layers`, `annotations` |
| `layers` | exactly six descriptors, each with exactly `mediaType`, `digest`, `size`, `annotations`; identified by `org.opencontainers.image.title` |

| `org.opencontainers.image.title` | `mediaType` | size bound |
|---|---|---|
| `release-manifest.json` | `application/json` | 16 MiB |
| `release-closure.json` | `application/json` | 16 MiB |
| `release-authorization.json` | `application/json` | 64 KiB |
| `release-authorization.json.sig` | `application/octet-stream` | 4 KiB |
| `delegation-snapshot.json` | `application/json` | 64 KiB |
| `delegation-snapshot.json.sig` | `application/octet-stream` | 4 KiB |

Refused: a duplicate title, a missing title, an unknown title, a seventh layer,
a size of 0 or above the bound, a wrong media type, a descriptor with other
keys. Before any layer is fetched, the `release-closure.json` layer digest must
equal `sha256:<neuralice.seed_closure>` and the `release-manifest.json` layer
digest must equal `sha256:<neuralice.seed_manifest>`.

Each layer is fetched as `GET /v2/neural-ice/seed-packs/blobs/<digest>` with
`--max-filesize` equal to the declared size, hashed in flight, and refused
unless `sha256 == digest` and `bytes == size`. The installer then re-hashes
`release-closure.json` and `release-manifest.json` against the sealed values and
runs the existing preseal reconciliation
(`assert_seed_is_the_preseal_release`) on the fetched documents. The target
disk is untouched until all of this has passed.

## Closure objects (fetched after LUKS/mkfs, phase 5)

The object set is the one `verify-seed-closure` derives
(`tools/ni-ota-verify/src/seed_closure.rs`, `validate_closure`):

- every `artifacts[].nodes[]` digest (`kind` `index`, `manifest`, `config`,
  `layer`);
- every `artifacts[].attachments[].manifest_digest`;
- the `config.digest` of each attachment manifest (read from the fetched
  attachment manifest);
- every attachment layer digest (the closure's `layer_digests`, which must equal
  the attachment manifest's `layers[].digest` in order).

Mirror path: a node's `repository` is `<release_authority>/<ns>/<name>` where
`<release_authority>` is the value `neuralice.release_authority` seals (the
verifier is handed the same value as `--registry-host`); the object is at
`https://<mirror>/v2/<ns>/<name>/...`:

| Object | URL | `Accept` | size |
|---|---|---|---|
| node `manifest` / `index` | `/manifests/<digest>` | the node's `media_type` | the node's `size` |
| node `config` / `layer` | `/blobs/<digest>` | `*/*` | the node's `size` |
| attachment manifest | `/v2/<subject ns/name>/manifests/<manifest_digest>` | the attachment's `media_type` | bounded to 4 MiB (the verifier's OCI document bound) |
| attachment config, attachment layers | `/blobs/<digest>` | `*/*` | from the attachment manifest's descriptors |

Order: attachment manifests first (small, digest-named by the closure), so the
config and layer digests and every exact size are known before the bulk.

Rules for every object:

- downloaded to a temporary file in `objects/sha256/`, SHA-256 computed in
  flight, renamed atomically to `objects/sha256/<hex>` only when the hash
  equals the name and the byte count equals the declared size; fsync of file
  and directory;
- an object already present that hashes to its name (and has the declared size)
  is not fetched again; a present object that does not is replaced; any other
  entry in the store is a refusal;
- 3 attempts for transport failures only, waits of 2 s and 6 s; a hash or size
  mismatch or an oversize response is a verdict and ends the install at once;
- per object: `--connect-timeout 15`, `--speed-limit 65536 --speed-time 60`
  (stall floor), `--max-time 120 + size / 512 KiB/s`, `--max-filesize` = the
  declared size, and the helper's own byte count as the real ceiling (curl
  before 8.4.0 does not apply `--max-filesize` to a transfer in progress);
- disk space: sum of declared node sizes plus 12 MiB per attachment, +5 % and
  +256 MiB, checked against the data volume before the first byte; re-checked
  with exact sizes after the attachment manifests are parsed, before the bulk;
- one object in flight at a time; at most 100 000 objects (the verifier's
  bound).

`READY` is written last (`neural-ice-seed-closure-ready-v1`, the same document
`image/build-seed-v2.sh` writes), then the common phase-5 re-verification runs
`verify-seed-closure` on the staged tree, and the `release/*` pointers and the
SELinux labels are written exactly as for an `ni-seed` seed.

## Failure model

| Event | Behaviour |
|---|---|
| network cut during the document fetch | `die` before the wipe; the machine is exactly as it was |
| network cut during the object fetch | `die`; the target disk is already wiped and holds no customer data; reinstall from the bench |
| corrupt or substituted object | hash differs from name: temp file discarded, `die`, no retry |
| mirror changes generation between READY and the fetch | an object no longer served is missing: `die`; one still served under the same name still hashes to it |
| disk full | precheck `die` before the first byte; a write that still fails is `die`, never a truncated object |
| power loss | nothing is committed: no READY, no `release/CLOSURE`, no ceremony; the next boot is the installer again |

## Where it lives

- grammar: `image/installer/neural-ice-sealed-cmdline-grammar.sh`,
  `image/inspect-installer-media.py`, corpus `image/test-lib/sealed-cmdline-corpus.tsv`;
- producer: `image/build-installer-usb.sh` (`seal_offline_seed_kargs`), `image/build-preloaded.sh`;
- runtime: `ota/neural-ice-autoinstall.sh` §2d (`seed_mirror_helper`,
  `seed_from_mirror_preflight`, `seed_from_mirror_materialize`);
- tests: `image/test-seed-from-mirror.sh` (real local HTTPS mirror, success,
  missing, corrupt, wrong size, resume, insufficient space, stray `ni-seed`),
  `image/test-installer-selector-grammar.sh` (corpus),
  `ci/test-install-registry-mirror.sh` (guards and ordering).
