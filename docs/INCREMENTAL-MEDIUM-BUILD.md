# Incremental installation-media build (FAB-0057 P1.7)

`image/build-installer-usb.sh` can reuse the sealed **container store** it built
for an earlier medium instead of producing it again. It is **off by default**:
with `MEDIUM_BUILD_CACHE_DIR` unset the producer behaves exactly as before,
byte for byte, and that is the supported way to prove a medium from nothing.

## The problem it addresses

Four media were cut on the bench (`.63`, GB10, 20 cores) on 2026-09-09, each for
one edit of `ota/neural-ice-autoinstall.sh`. Each build took 22–35 minutes, and
each rebuilt the sealed store from scratch: a `skopeo copy` of ~8 GiB followed by
`mksquashfs -comp zstd -Xcompression-level 19 -processors 1` over the result.
Nothing about the store can depend on an edit to the installer root: the store is
a `containers-storage` holding exactly `$BASE_IMAGE`, and `$BASE_IMAGE` is a
digest.

## Measure first

Every `==>` line the producer prints now carries the wall clock and the elapsed
build time, and the run ends with a per-step duration table:

```
==> [09:14:02Z +  318s] build the sealed installer root and image store
…
==> step durations (seconds), total 1946s
       291  build installer image  FROM …
       842  build the sealed installer root and image store
       …
```

The durations are a **log**: no branch in the producer reads one. Take a baseline
with the cache disabled before drawing any conclusion about what the cache saved
(`docs/` cannot state numbers it did not measure — see “Not yet measured” below).

## How to use it

```bash
mkdir -p "$HOME/.cache/neural-ice/medium-build"
chmod 0700 "$HOME/.cache/neural-ice/medium-build"

MEDIUM_BUILD_CACHE_DIR="$HOME/.cache/neural-ice/medium-build" \
MEDIUM_BUILD_CACHE_MAX_ENTRIES=4 \
  ./image/build-installer-usb.sh   # plus the usual inputs
```

The directory is refused unless it is an absolute path, a real directory (not a
symlink), owned by the build user, not group- or world-accessible, and **outside
the checkout**. `MEDIUM_BUILD_CACHE_MAX_ENTRIES` (default `4`) bounds it: entries
are ~8 GiB each, and an unbounded cache fills the build host so the next build
dies on `ENOSPC` in the middle of a `veritysetup format`.

## What is reused, and what is never reused

| Artefact | Cached? | Why |
|---|---|---|
| sealed store squashfs (`installer-store.img`) | **yes** | a `containers-storage` holding one digest-named image; identical between two media cut for two edits of the installer root |
| installer root squashfs | no | it is exactly what a change to this tree changes |
| installer initramfs | no | `dracut --no-hostonly` copies binaries out of the installer image, which is rebuilt on every edit |
| UKI, ESP, `bootc-image-builder` raw | no | they carry the sealed statement about this medium |
| final measurements | no | a measurement that is not taken is not a measurement |

## What every reuse re-proves, before a cached byte reaches the payload

1. **The directory** passes the hygiene checks above
   (`medium_cache_require_dir`, `image/build-installer-usb.sh`).
2. **The key matches.** The key is the SHA-256 of a canonical JSON document that
   names every input which can change the produced bytes: the digest-pinned
   `BASE_IMAGE`, its config ID and platform manifest digest as resolved live from
   podman on *this* run, `STORE_IMAGE_NAME`, `STORE_SOURCE_REF`, the SHA-256 of
   `image/build-installer-root.sh`, `image/build-installer-payload.sh` and
   `image/lib/installer-payload.sh`, and the `mksquashfs`/`skopeo` versions as
   the privileged store build sees them. The three scripts are **hashed** rather
   than their `mksquashfs`/`veritysetup` options copied into the key: an option
   list copied there would be a second answer, and only one of them would be the
   one that ran.
3. **The provenance document is well formed** — declared schema, the key it sits
   under, and every field a reuse is checked against present and shaped
   (`medium_cache_read_entry`). An entry with no `entry.json` is the residue of an
   interrupted build and is never reused.
4. **The bytes are re-hashed.** `image/build-installer-root.sh` copies the entry
   to `$STORE_IMAGE_OUT` and hashes **the copy** — never the source, which could
   be swapped between a hash and a copy — and refuses unless its size and SHA-256
   equal the recorded ones.
5. **The identity is re-read.** The config ID, platform manifest digest and store
   image name the entry records must equal the ones this build resolved live from
   the digest-pinned base image moments earlier. A stale entry therefore cannot
   substitute the appliance a medium installs.
6. **The dm-verity root hash is recomputed.** `image/build-installer-payload.sh`
   runs unchanged over the reused extent, so `veritysetup format` — with the fixed
   salt and UUID that make it a pure function of the bytes — produces the store's
   root hash from those bytes. It must equal the one the entry records, and the
   refusal lands **before** the UKI seals the payload header digest that covers
   it.

## What a reuse does **not** prove

It does not re-derive “these bytes contain that image” from the bytes. That
derivation was made by the build that populated the entry, which read
`overlay-images/images.json` out of the staged store and asked podman for its
platform manifest digest; a reuse re-establishes that these are *those* bytes and
that their identity is the one this build selected.

Anyone who can write into the cache directory can therefore choose the store —
which is why the directory must be the build user's own and unshared. That user
already runs `sudo podman build` inside this producer, so the cache grants no
capability that was not already held; what it adds is a place where a mistake
**persists between builds**. `MEDIUM_BUILD_CACHE_DIR` unset is the way to prove a
medium from nothing, and it is what a release build should do.

## How to invalidate

- **Change any keyed input** — a different base image, store name, store source
  reference, a change to one of the three producer scripts, a toolchain upgrade —
  and the key changes, so the old entry is simply never selected again and ages
  out under `MEDIUM_BUILD_CACHE_MAX_ENTRIES`.
- **Drop one entry**: `rm -rf "$MEDIUM_BUILD_CACHE_DIR/sealed-store/<key>"`. The
  key is printed by the build (`sealed store cache key : …`).
- **Drop everything**: `rm -rf "$MEDIUM_BUILD_CACHE_DIR/sealed-store"`.
- **Prove a medium from nothing**: unset `MEDIUM_BUILD_CACHE_DIR`.

An entry is *never* half-consumed: `image/build-installer-root.sh` takes the six
reuse values as one tuple and refuses a half-supplied one in both directions —
a path with no recorded facts is bytes nothing accounts for, and facts with no
path describe nothing.

## Where this is tested

- `image/test-build-installer-root.sh` §8 — the reuse path in the real script,
  with mocked podman/skopeo/mksquashfs: byte-identical store and manifest lines,
  the expensive half actually skipped, one flipped byte refused by name, an
  altered record refused by name, each of the three identity values refused by
  name, a half tuple, a symlink and a relative path refused.
- `image/test-installer-media.sh` — the producer's own cache functions, lifted
  and executed: key determinism and sensitivity, directory hygiene, the entry
  lifecycle, seven provenance sabotages, the recomputed-verity refusal, and the
  eviction bound.

## Not yet measured

The `≤ 10 min` second-build target of FAB-0057 P1.7 is **not** claimed here. The
instrumentation exists so that it can be measured on the bench; no timing in this
repository is a measurement of the GB10 build host.
