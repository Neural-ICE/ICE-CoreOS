# Seed from the LAN mirror (`neuralice.seed_source=mirror`)

FAB-0057 P1.1. A registry-install medium (`neuralice.source=registry`) with a
LAN mirror and a preseal set can seal a release seed **without an `ni-seed`
partition**: the installer materialises `release/<closure_hex>/` on the
encrypted data volume by fetching every object of the sealed release closure
from the mirror, then runs exactly the `ni-ota-verify verify-seed-closure`
the `ni-seed` path runs before the install is reported successful. First boot
(`image/firstboot/neural-ice-seed-import.sh`) is unchanged.

Nothing the mirror says is trusted. The authority is, in order:

1. the sealed `neuralice.seed_closure` (the UKI signature covers it) -- it
   decides which bytes are the closure;
2. the closure, once its bytes hash to the sealed value -- it names the release
   manifest (`release_manifest_sha256`) and every other object (digest,
   repository, media type, size);
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
| `neuralice.mirror` (+ `mirror_ca_sha256`, `mirror_generation`) | refused otherwise: `seed-source-mirror-without-mirror` |
| `neuralice.preseal` | refused otherwise: `seed-source-mirror-without-preseal` |
| `neuralice.seed_closure` (+ `seed_trusted_now`) | refused otherwise: `seed-source-mirror-without-seed-closure` |
| `neuralice.mirror_ready`, `neuralice.mirror_manifest` | **implicit, refused if restated**: `seed-source-mirror-restates-mirror-ready` (rule A) |
| `neuralice.relauth_sha256`, `neuralice.relauth_sig_sha256` | **implicit beside `neuralice.preseal`, refused if restated**: `preseal-restates-relauth` (rule B; any medium with a preseal set) |
| `neuralice.seed_manifest` | **implicit beside `neuralice.seed_closure`, refused if restated**: `seed-closure-restates-manifest` (rule C; any medium with a seed) |

Every existing refusal keeps its precedence; the four `seed-source-mirror-
without-*` refusals are checked last. Producer: `SEED_SOURCE=mirror` on
`image/build-installer-usb.sh` (requires `INSTALL_SOURCE=registry`,
`INSTALL_MIRROR`, the preseal set, `RELEASE_MANIFEST_FILE` and
`RELEASE_CLOSURE_FILE`, and `MIRROR_READY_SHA256`/`MIRROR_READY_MANIFEST_
SHA256` equal to the sealed seed closure and the manifest hash it carries).
`image/build-preloaded.sh` refuses it, and the base producer refuses a raw
that carries an `ni-seed` partition. Nothing is copied to the medium.

### The three implicit terms (FAB-0057 P1.1b)

The kernel's EFI stub delivers at most 1957 bytes of the sealed line
(`NI_SEALED_CMDLINE_MAX_BYTES`) and silently truncates the rest. The full
composed line with production-length names measured **2332 bytes**; three
terms restated a value another sealed term or a hash-sealed document already
fixed. Each is now implicit under its condition, **refused by name if
restated**, derived by the installer from the value it already verified, and
consumed by exactly the same checks as before. No authority moves.

| Rule | Implicit term(s) | Condition | Derived from | Runtime check kept |
|---|---|---|---|---|
| A | `mirror_ready`, `mirror_manifest` | `seed_source=mirror` | `seed_closure` and the `release_manifest_sha256` of the closure that hashes to it | the READY receipt is compared on all three fields (closure, manifest, generation) before the transport is written; closure and generation are judged before the seed pack is asked for |
| B | `relauth_sha256`, `relauth_sig_sha256` | `preseal` sealed | `installer_authorization_sha256` / `installer_authorization_signature_sha256` of the `preseal-set.json` staged from the ESP and hashed against `neuralice.preseal` first (`esp_staged_file preseal/preseal-set.json`) | the pair is staged by the same `esp_staged_file`, the signature is verified with the sealed key, the snapshot re-binds the pair to the set |
| C | `seed_manifest` | `seed_closure` sealed | `release_manifest_sha256` of the closure after it hashes to `neuralice.seed_closure` (ni-seed: on the mounted partition before `verify-seed-closure`; mirror: on the fetched pack before the READY receipt is judged) | `--expect-manifest` to the verifier, the manifest document re-hashed against it, `release/MANIFEST` written; first boot unchanged |

Producer: it still hashes `RELEASE_MANIFEST_FILE` and now also reads
`RELEASE_CLOSURE_FILE`, requires it to hash to `SEED_CLOSURE` and requires its
`release_manifest_sha256` to equal the manifest hash; it still requires
`MIRROR_READY_*` to equal the seed's values and the preseal set to bind the
authorization pair (`neural-ice-preseal-handoff.py verify`). Every equality
that used to be sealed twice is a producer refusal. The mirror-side derivation
proves the closure first: the fetcher fetches `release-closure.json` alone,
verifies it by the sealed hash, reads the manifest hash, and only then judges
and fetches the manifest layer.

Byte budget: the full production line (authority 22 bytes, mirror 30 bytes,
128-byte operator key, digest-pinned appliance repository, all eight anchor
terms, `stable` channel) measures **1884 bytes**; the grammar suite carries it
as the `budget:` corpus vector and fails above 1900.

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
equal `sha256:<neuralice.seed_closure>`. The closure layer is fetched first and
proved by that hash; its `release_manifest_sha256` is read from the proved
bytes, and the `release-manifest.json` layer digest must equal `sha256:<that
value>` before any other layer is fetched.

Each layer is fetched as `GET /v2/neural-ice/seed-packs/blobs/<digest>` with
`--max-filesize` equal to the declared size, hashed in flight, and refused
unless `sha256 == digest` and `bytes == size`. The installer then re-hashes
`release-closure.json` against the sealed value, derives the manifest hash from
it, re-hashes `release-manifest.json` against that, judges the mirror's READY
receipt on all three fields, and -- once the preseal set is authenticated --
runs the existing preseal reconciliation (`assert_seed_is_the_preseal_release`)
on the fetched documents. The target disk is untouched until all of this has
passed.

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

## Mirror name resolution (`.local`, FAB-0057 P1.1c)

Owner decision 2026-09-09: media seal the mirror by **name**
(`neuralice.mirror=registry.neural-ice.local:5055`), never by address; the
bench announces that name in mDNS (ICE-Fabric
`quadlets/registry/lan-mirror-mdns.service`). Measured the same day: the bench
LAN's unicast DNS answers NXDOMAIN for it, the installer's runtime generator
masked `avahi-daemon.service/.socket` on every medium boot, and the installer
image had no NSS module for mDNS (the appliance's own journal on `.67`:
`avahi-daemon: No NSS support for mDNS detected`), so the READY fetch and the
seed-pack fetch died on resolution.

Facts that fixed the variant: `systemd-resolved` is **not** in the image (the
local systemd rebuild in `image/systemd-srk/build-rpms.sh` ships only
`systemd`, `systemd-libs`, `systemd-pam`, `systemd-udev`; neither Containerfile
installs it); `avahi` + `avahi-tools` are (`image/Containerfile.bootc`,
inherited by the installer image). So the resolver is avahi, **resolution
only**, and the NSS module is `nss-mdns` -- a **new package, installer image
only** (`image/Containerfile.installer`): the appliance is the installer's
*base*, never its derivative, so nothing here reaches an installed system (the
site mirror for OTA is P3.3).

| Where | What |
|---|---|
| `image/Containerfile.installer` | installs `nss-mdns`; `hosts: files myhostname mdns4_minimal [NOTFOUND=return] dns` (one line, asserted). Only `.local` names are asked of avahi; a `.local` name avahi does not know is not leaked to unicast DNS; other names are untouched. When avahi is masked the module answers UNAVAIL on its absent socket and the line is inert. |
| `image/installer/neural-ice-installer-runtime-generator.sh` | on the exact Install grammar with `neuralice.source=registry` and exactly one `neuralice.mirror=` whose host ends in `.local` (`mirror_host_is_mdns_name`, read off the sealed line): writes `/run/neural-ice-installer-mdns/avahi-daemon.conf` -- `disable-publishing=yes`, `publish-addresses=no`, `publish-hinfo=no`, `publish-workstation=no`, `use-ipv6=no`, `enable-dbus=no`, `enable-reflector=no`, `allow-interfaces=<management port>` (the `interface-name` of `mgmt-*.nmconnection`, the same rule `neural-ice-hostname-init.sh` pins the appliance's avahi with; no profile = no unmask, and a named refusal later) -- shadows the appliance's ceremony drop-in on both avahi units, points `ExecStart=` at that file (`Type=simple`, no D-Bus), adds `Wants=/After=avahi-daemon.socket avahi-daemon.service` to `neural-ice-autoinstall.service`, and only then takes the two avahi masks back off. Everything is under `/run`. An IP or a non-`.local` name: nothing is written, avahi stays masked. |
| `ota/neural-ice-autoinstall.sh` | restates the condition against the same `karg_once neuralice.mirror`; before the READY fetch -- the first use of the mirror, before the first disk write -- `assert_mirror_name_resolves` requires the avahi socket and proves `getent ahostsv4 <host>` (the NSS path curl/podman/skopeo take) under `timeout`, at most 6 attempts of 5 s with 2 s pauses (40 s bound), then logs the address. Failure is the named refusal **`mirror-name-unresolvable`**, naming the name and the mechanism, with the target disk untouched. |

The mDNS answer is unauthenticated and decides only *where* the medium asks:
every byte that follows is still TLS-pinned to the sealed CA, digest-pinned and
signature-verified, so a spoofed answer can only produce one of the refusals
below. The medium never announces a record of any kind (`disable-publishing=yes`
is asserted by `image/test-installer-systemd-lifecycle.sh`, which also runs a
sabotaged generator that would enable publishing and requires the suite to
catch it). `ci/test-install-registry-mirror.sh` extracts the two installer
functions and drives them with a mocked `getent` (answer, not found, hang,
garbage) and asserts the proof precedes the READY fetch and the first write.

## Failure model

| Event | Behaviour |
|---|---|
| `.local` mirror name does not resolve (no announcement on the LAN, wrong port pinned, resolver not started) | `mirror-name-unresolvable` before the READY fetch and before the wipe; the machine is exactly as it was |
| `.local` name resolved by a host that is not the mirror | the READY fetch fails the sealed-CA pin: `die` before the wipe |
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
  `seed_from_mirror_fetch_documents` -- called from the mirror block,
  `seed_from_mirror_preflight`, `seed_from_mirror_materialize`), the
  derivations `seed_manifest_hash_from_closure`,
  `preseal_installer_authorization_pins`,
  `release_authorization_pins_from_preseal`, and the name proof
  `mirror_host_is_mdns_name` / `assert_mirror_name_resolves`;
- installer runtime: `image/installer/neural-ice-installer-runtime-generator.sh`
  (`request_mirror_mdns_resolution`), `image/Containerfile.installer`
  (`nss-mdns`, `hosts:` line);
- tests: `image/test-seed-from-mirror.sh` (real local HTTPS mirror, success,
  missing, corrupt, wrong size, resume, insufficient space, stray `ni-seed`,
  a closure naming another manifest, a preseal set binding another
  authorization), `image/test-installer-selector-grammar.sh` (corpus and the
  byte budget), `image/test-installer-media.sh` (composed medium, producer),
  `ci/test-install-registry-mirror.sh` (guards and ordering, the name proof
  with a mocked `getent`), `image/test-installer-systemd-lifecycle.sh` (the
  generator driven for real on a `.local`, an IP and a unicast-DNS mirror; no
  announcement; the sabotaged generator).
