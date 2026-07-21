# Offline seed tree manifest v1

`image/seed-tree-manifest.py` emits the persisted
`neural-ice-offline-seed-tree-v1` contract used to compare staged preload
trees with finalized installer media. The manifest describes namespace and
content equality; it deliberately excludes filesystem timestamps and inode
numbers, which can change during an exact copy to XFS.

## Authoritative execution

An authoritative Linux manifest MUST be produced by the CLI as host root in
the initial user namespace with effective `CAP_SYS_ADMIN`. This is required to
enumerate protected attributes such as `trusted.overlay.opaque`; root in a
nested user namespace is refused. The caller MUST also provide:

- stable input snapshots for the complete invocation;
- a caller-owned output directory with no concurrent writers;
- input filesystems whose `(st_dev, st_ino)` values form one unambiguous inode
  namespace. Btrfs inputs are refused because different subvolumes or
  snapshots can reuse those values.

The final-media gate owns the stronger production boundary: a private mount
namespace, private propagation, exclusive read-only XFS media, descendant
mount refusal, capacity enforcement and pre/post topology validation.

## Canonical document

The file is UTF-8 JSON followed by one newline. Object keys are sorted,
separators contain no optional whitespace, and `entries` are ordered by the
raw UTF-8/surrogate-preserving bytes of `path`. The top-level object contains:

- `schema`: exactly `neural-ice-offline-seed-tree-v1`;
- `trees`: sorted unique tree names accepted by the CLI (`[A-Za-z0-9_-]`-like
  alphanumeric names with `_` and `-` separators);
- `entries`: every root and descendant namespace entry.

Every entry contains `path`, `type`, `mode`, `uid`, `gid` and `xattrs`.
`xattrs` maps each visible attribute name to its base64-encoded raw value.
Type-specific fields are:

- `directory`: no additional fields;
- `file`: `size` and lowercase hexadecimal SHA-256 `sha256`;
- `symlink`: exact uninterpreted `target`;
- `overlay-whiteout`: `device` fixed to `0:0`, accepted only below
  `store/overlay/`;
- any entry participating in a multi-name inode group: `hardlink_to`, whose
  value is the lexicographically first manifest path in that group (including
  on the representative entry itself).

FIFOs, sockets, block devices and non-whiteout character devices are refused.
Paths are rooted in their tree name and never follow a namespace symlink.

## Compatibility and reconstruction

Consumers MUST fail closed on an unknown `schema`, unknown entry type,
missing required field, duplicate/unsorted path, invalid digest/base64, or a
`hardlink_to` target outside the same document. Version 1 is immutable: a
semantic field or reconstruction-rule change requires a new schema value and
a coordinated producer/consumer migration.

Reconstruction creates directories first, materializes each hard-link
representative once, links the other group members, creates symlinks and exact
0:0 overlay whiteouts without following targets, then applies owner, mode and
xattrs. A verifier compares canonical document bytes or their SHA-256; it does
not infer equality from timestamps or source inode numbers.

Publication is atomic and no-replace: the producer writes a private mode-0600
sibling, fsyncs it, links it to the requested final name only if absent, fsyncs
the parent, removes the private name and fsyncs the parent again.
