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
  no duplicate, ≤ 64 entries, ≤ 2 MiB each, nothing but zeros after the end-of-archive
  marker. Members are read in memory; nothing is extracted by `tarfile`.
* **`signature`**: ECDSA P-256 / SHA-256, DER, over `"neural-ice-support-bundle-v1" ‖ 0x00 ‖
  manifest.json` (the stored bytes). A signature made for another domain, for example the
  access-profile anchor's (`neural-ice:ota:access-profile-anchor:v1`), does not verify.
* **`manifest`**: parsed only after the signature verified. Strict JSON (no duplicate key, no
  `NaN`), closed schema (`x-…` fields ignored, any other unknown field refused), sorted `files`,
  the fields of design section 4.2. A schema other than `neural-ice-support-bundle-v1` is refused.
* **`files`**: every `included` section is in the archive with the listed size and sha256; an
  `included: false` one is absent; nothing else is in the archive except the three envelope
  members and the client's unsigned `client.json` (reported under `unsigned`, scanned like the rest).

Deviations that carry no trust decision (tar uid/gid/mode/mtime, gzip header fields, manifest
not in canonical form, a zip member name with another bundle id) are `warnings`, not refusals.

## The content scan (exit 3)

A built-in deny-list from design section 2.3 — e-mail, IPv4/IPv6 (loopback excluded), MAC,
PEM blocks, `Bearer`/JWT/`nicap1_` tokens, systemd-style recovery keys, `password=…`-style pairs,
non-empty values under forbidden JSON keys (`license_key`, `email`, `token`, `filename`, …),
control characters, non-UTF-8 bytes — plus the strings of `--canaries FILE` (one literal per
line, ≥ 6 characters; matched case-insensitively, as UTF-8 and as a JSON escape, in every
section, in `manifest.json` and in `client.json`; also in the raw tar and gzip bytes). The
Owner can feed it the names, e-mails and licence keys he knows must never leave a customer.

A finding is `{file, line, rule}`: **the matched text is never printed**, so a leak is not
re-leaked into a terminal, a ticket or a log. `systemd` unit names such as `user@1000.service`
are not e-mails. Known limits: a 64-hex digest is not flagged (digests are everywhere in a
bundle, so the hardware fingerprint cannot be told apart by shape: put it in `--canaries`);
free text cannot be proven free of a name nobody listed; a four-number version such as
`1.2.3.4` reads as an IPv4.

## The bundle as this tool reads it (the contract the producers meet)

```
ni-support-<id8>.zip            ONE member: ni-support-<id8>.tar.gz.age     (age X25519, support key)
  └─ tar.gz  (gzip -n, ustar, sorted, uid=gid=0, mode 0644, mtime = generated_at, flat names)
       manifest.json            canonical JSON: sorted keys, no spaces, UTF-8
       manifest.sig             DER ECDSA, tpm2_sign -g sha256 -s ecdsa over DOMAIN ‖ manifest.json
       device-root.spki.der     the signing key, 91-byte P-256 SubjectPublicKeyInfo
       <section files>          exactly the manifest's included files
       client.json              optional, produced by the client, NOT signed
```

`manifest.json` fields: `schema`, `bundle_id` (32 hex), `case_id` (`^[A-Za-z0-9-]{0,32}$`),
`generated_at` (`YYYY-MM-DDTHH:MM:SSZ`), `time_source` (`attested`|`host_clock`), `boot_id`,
`files[{path,size,sha256,included?}]`, `dropped`, `truncated`, `redaction`,
`device_root_spki_sha256`, `collector_version`. The outer zip must hold exactly one `*.age`
member; a bare `.tar.gz.age` and an already decrypted `.tar.gz` are also accepted.

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
```

Bundles are built per run by a producer independent of the tool; the signing and age keys are
generated per run, nothing secret is committed, every planted « customer » string is synthetic.
`fixtures/golden-v1/` is one bundle signed once by a throwaway key whose private half was destroyed.

## Not covered here

* A signature made by the real TPM (`tpm2_sign` on `0x81010005`) has not been fed to this tool:
  the sandbox that built it has no `tpm2-tools`. The format is the plain DER ECDSA the
  access-profile anchor already produces and `openssl` already verifies; the first bundle from a
  real collector is the integration test.
* Whether a user-removed preview line can reach the signed bundle is a design point for the
  client PR: a signed section cannot be edited without breaking its sha256 (see the PR report).
