# ni-support-verify — Owner-side reader of a support bundle

What the Owner runs on the file a user hands over from « Exporter un diagnostic »: it
**verifies** the bundle against the device key pinned at that device's ceremony, **decrypts**
it with the support key file, **lists** it and **scans** it for content that must never be
there. Python 3 standard library, the `openssl` binary and, for encrypted input, `age`
(`apt install age`, `brew install age`). Nothing here talks to a network or to the device.

Phase 1 of the support-bundle design (`DESIGN-support-bundle-20261006`, PR-3, sections 2 and
4). The collector (host), the AC1 routes and the client export are other PRs; this tool is the
reader they are tested against (`fixtures/golden-v1/`).

```sh
T=tools/ni-support-verify/ni-support-verify.py
python3 -I $T verify  ni-support-1a2b3c4d.zip --key support.age.key --pins-file pins.txt [--canaries canaries.txt] [--format json]
python3 -I $T show    ni-support-1a2b3c4d.zip units.json --key support.age.key --pins-file pins.txt
python3 -I $T extract ni-support-1a2b3c4d.zip --out /run/user/$UID/case-4711 --key support.age.key --pins-file pins.txt
```

`pins.txt`: one pin per line, `<sha256 of the device root SPKI DER, 64 lowercase hex> [label]`,
`#` comments. **The pin is mandatory and is never taken from the bundle**: a forged bundle
carries its own key. A pin is `spki_sha256` of `neural-ice-device-root`
(`0x81010005`), recorded in the device's ceremony evidence before it ships.

## Verdict and exit codes

| Exit | Verdict | Meaning |
|---|---|---|
| 0 | `verified` | integrity and signature hold, the content scan found nothing |
| 1 | `refused` | one check failed (the JSON names it in `checks`); the bundle is not trustworthy |
| 2 | — | usage error or missing tool (no pin, no `--key` for an age file, no `openssl`/`age`) |
| 3 | `findings` | integrity and signature hold, but the content scan found something |

`show` and `extract` exit 0 for a verified bundle even with findings (they print them on
stderr): the Owner who holds the key may need to read a leaking file to fix its producer.

## What is checked, in order, stopping at the first refusal

`input` · `decrypt` · `archive_size` (compressed ≤ 8 MiB) · `decompress` (one gzip stream,
nothing after it, ≤ 24 MiB + framing) · `tar` · `envelope` · `spki` · `pin` · `signature` ·
`manifest` · `spki_binding` · `files`.

* **`tar`**: strict POSIX ustar (GNU and pax extensions refused), regular files only (no link,
  directory, device), flat `^[a-z0-9][a-z0-9._-]{0,63}$` names (no `/`, `..`, upper case),
  no duplicate, ≤ 64 entries, ≤ 2 MiB each. **Every header must be the canonical ustar header
  of its own fields and every byte of padding zero** (so no text rides in unused header fields
  or padding, where neither a hash nor a scan would look), and nothing but zeros follows the
  end-of-archive marker. The gzip header carries no name, comment, extra or CRC field. Members are
  read in memory; nothing is extracted by `tarfile`.
* **`input`**: the client's zip holds exactly `LISEZ-MOI.txt` and `diagnostic.tar.gz.age` (either order),
  once each, no path, no comment, no byte outside the two members and the directory (a stored member holds exactly its
  content, a deflated one ends with its stream: nothing rides in the slack), each within its bound
  (README 64 KiB; the decrypted archive is capped at 8 MiB). `LISEZ-MOI.txt` is read by a person: it is never
  parsed, scanned or trusted, and it changes no verdict. `--require-encrypted` refuses a plain `.tar.gz`.
* **`signature`**: ECDSA P-256 / SHA-256, DER, over `"neural-ice-support-bundle-v1" ‖ 0x00 ‖
  manifest.json` (the stored bytes). A signature made for another domain, for example the
  access-profile anchor's (`neural-ice:ota:access-profile-anchor:v1`), does not verify.
* **`manifest`**: parsed only after the signature verified. Strict JSON (no duplicate key, no
  `NaN`), closed schema (`x-…` fields ignored, any other unknown field refused), key and value
  syntax as the collector's `support-bundle-manifest.schema.json`. A schema other than
  `neural-ice-support-bundle-v1` is refused.
* **`files`**: every entry of the archive except the three envelope members and the client's
  unsigned `client.json` (reported under `unsigned`, scanned like the rest) is listed with its exact
  size and sha256. `sections` says what the user declined or what was unavailable; those files are
  simply absent. **One exception, `journal-app-excerpts.jsonl`** (the opt-in text excerpts the user may thin
  out after the preview): its manifest entry carries `lines`, the sha256 of each line in file order (at most
  1000, closed schema; `lines` on any other file is a `manifest` refusal). The file must be present (empty when
  every line was removed) and end with LF when not empty; every line must hash to an entry of `lines`, in
  strictly increasing order. A modified, added, duplicated or reordered line is refused. A signed line
  that is absent is **accepted** and reported, in `removed_by_user` and in the text output, as
  « retirée par l'utilisateur » with its position in `lines` (a hash does not give the id back). Nothing is
  signed again: manifest and signature stay as the host produced them. In the verdict's `files`, such a file is reported as
  extracted (its real `size` and `sha256`, what `show` and `extract` give) with `removed_lines`, `signed_lines`, `signed_size`
  and `signed_sha256`; a repeated digest in `lines` is a `manifest` refusal. When no line is removed the file must
  equal the signed size and sha256. Without `lines` in the entry, the whole-file rule applies as to any file.

Deviations that carry no trust decision (tar uid/gid/mode/mtime, a gzip timestamp, a manifest not in
canonical form or `files` not sorted, a signature that is not low-S, a key file readable by others) are `warnings`, not refusals.

## The content scan (exit 3)

A built-in deny-list from design section 2.3 — e-mail, IPv4/IPv6 (loopback excluded), MAC,
PEM blocks, `Bearer`/JWT/`nicap1_` tokens, systemd-style recovery keys, `password=…`-style pairs,
non-empty values under forbidden JSON keys (`license_key`, `email`, `token`, `filename`, …),
control characters, non-UTF-8 bytes — plus the strings of `--canaries FILE` (one literal per
line, ≥ 6 characters; matched case-insensitively, as UTF-8 and as a JSON escape, in every
section, in `manifest.json` and in `client.json`; also in the raw tar and gzip bytes). The
Owner can feed it the names, e-mails and licence keys he knows must never leave a customer.

Every rule is bounded (lookbehinds, capped repeats, lines scanned in 16 KiB windows, a 150 s budget
that ends in a `scan_incomplete` finding): one hostile line cannot stall the reader. The key-name
rules (`secret_pair`, `forbidden_field`, `deny_key`) do not apply to `manifest.json`, whose keys the
schema closes and whose `redaction`/`dropped` tables are named after rules (`email`, `token`); only its
free `x-` fields are scanned. A bare word after `password:` is prose, not a secret.

A finding is `{file, line, rule}`: **the matched text is never printed**, so a leak is not
re-leaked into a terminal, a ticket or a log. `systemd` unit names such as `user@1000.service`
are not e-mails; a four-number version after `version`, `build`, `commit`… or glued to a package name is
not an IP. Known limits: a 64-hex digest is not flagged (digests are everywhere in a
bundle, so the hardware fingerprint cannot be told apart by shape: put it in `--canaries`);
free text cannot be proven free of a name nobody listed; a four-number version such as
`1.2.3.4` with no such word before it reads as an IPv4; `dead::beef` reads as an IPv6; a password made
only of letters and shorter than 12 characters after `password=` is not seen. **`journal-app-excerpts.jsonl`
is free text by design (D2-A: opt-in, read by the user line by line): with the Owner's canaries it is the one
file where a hit is expected to be possible; the collector's README pins that limit.**

## The bundle as this tool reads it (the contract the producers meet)

The inner archive is the collector's (ICE-Fabric-v2 PR #125, `config/support-bundle/README.md` and its
closed `support-bundle-manifest.schema.json`, which supersede the design where they differ). The outer
layers are the client's (ICE-Client PR-4): the `.zip` holds `LISEZ-MOI.txt` and `diagnostic.tar.gz.age`.

```
ni-support-<id8>.zip            LISEZ-MOI.txt (for a person) + diagnostic.tar.gz.age   (age X25519, support key)
  └─ tar.gz  (gzip -n, ustar, sorted, uid=gid=0, mode 0644, mtime = generated_at, flat names)
       manifest.json            canonical JSON: sorted keys, no whitespace, ASCII-escaped, no trailing LF
       manifest.sig             DER ECDSA P-256 (low-S), over "neural-ice-support-bundle-v1" ‖ 0x00 ‖ manifest.json
       device-root.spki.der     the signing key, 91-byte P-256 SubjectPublicKeyInfo
       <section files>          each listed in manifest.files with its exact size and sha256
       client.json              optional, produced by the client, NOT signed
```

`manifest.json` fields: `schema`, `bundle_id` (32 hex), `case_id` (`[A-Za-z0-9-]{0,32}`),
`generated_at` (`YYYY-MM-DDTHH:MM:SS[.ffffff]Z`), `time_source` (`attested`|`host_clock`), `boot_id`
(UUID), `collector_version`, `device_root_spki_sha256`, `files[{path,size,sha256}]`,
`sections{name: {included, status}}`, `dropped`, `truncated`, `redaction`; each `files` entry is
`{path, size, sha256}` plus `lines` for the excerpts file. The outer zip holds exactly the two members above;
a bare `.tar.gz.age` and an already decrypted `.tar.gz` are also accepted.

## Handling the decrypted bundle

The decrypted bytes stay in memory (`verify`, `show`); core dumps are disabled; a key file
readable by group or others is a warning. `extract` is the only command that writes: into a new
or empty `0700` directory, files `0600`, `O_EXCL | O_NOFOLLOW`. **Delete the directory once the
case is read** (put it on a `tmpfs`, such as `/run/user/$UID`). For a stricter sandbox:

```sh
systemd-run --user --pipe --wait --quiet -p PrivateNetwork=yes -p NoNewPrivileges=yes \
  -p ProtectSystem=strict -p PrivateTmp=yes -p MemoryMax=1G -p MemorySwapMax=0 -p LimitCORE=0 -- \
  /usr/bin/python3 -I $T verify BUNDLE --pins-file pins.txt --key support.age.key
```

(`age` runs inside the same sandbox, so `--key` must be readable by it.)

## Tests

```sh
python3 -I tools/ni-support-verify/test-ni-support-verify.py   # needs openssl, age, age-keygen
# release differential, against the real collector (needs an ICE-Fabric-v2 checkout; not in CI):
NEURAL_ICE_FABRIC_V2_ROOT=/path/to/ICE-Fabric-v2 python3 -I tools/ni-support-verify/test-collector-interop.py
```

Bundles are built per run by a producer independent of the tool; the signing and age keys are
generated per run, nothing secret is committed, every planted « customer » string is synthetic.
`fixtures/golden-v1/` is one bundle signed once by a throwaway key whose private half was destroyed.

## Not covered here

* A signature made by the real TPM (`tpm2_sign` on `0x81010005`) has not been fed to this tool: the
  sandbox has no `tpm2-tools`. The interop test reads bundles from the real collector, whose
  `tpm2_sign` is a stub speaking the real `-f tss` format over a software key and whose
  TPMT_SIGNATURE → DER conversion runs for real. The first bundle from a real appliance is the last
  integration test.
* The length of a line the user removed stays visible (signed `size` minus the bytes kept), and so does how
  many lines went and where: that is the collector's contract, not something the reader can hide.
