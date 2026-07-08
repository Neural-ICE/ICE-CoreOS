# Key ceremony — Neural ICE Secure Boot PKI on YubiKey 5 FIPS

Produces the key material for the MS-signed shim chain. Run once, on an
**air-gapped machine** (live Linux from USB, no disk, no network), with at
least two people (dual control) and a safe available.

## Design

Two-tier PKI, so that day-to-day signing never touches the root:

| Key | Where it lives | Signs |
|---|---|---|
| **Neural ICE UEFI Secure Boot CA 2026** (root) | Offline: encrypted backups in safe (optionally also imported into a dedicated "CA" YubiKey kept in the safe) | Leaf certificates only |
| **Neural ICE Secure Boot Signer 2026** (leaf) | YubiKey 5 FIPS PIV slot **9c**, generated **on-device** (non-exportable) | `grubaa64.efi`, `vmlinuz` (and any future EFI binary loaded by shim) |
| **EV code-signing key** (public CA-issued) | YubiKey PIV slot **9a** (or the CA's own token) | Partner Center `.cab` submissions only |

Rationale:

- The **CA cert** (not the leaf) is embedded in shim (`VENDOR_CERT_FILE`,
  `CA:TRUE`): leaf rotation/re-issue then requires **no new shim-review**.
- Leaf on-device generation means a stolen YubiKey (still PIN + touch
  protected) is the worst case, and it is recoverable: issue a new leaf from
  the CA. A compromised leaf is revoked by shipping a new shim with the old
  binaries' hashes in `vendor_dbx`.
- The CA key is generated off-device so it can be **backed up** (Microsoft
  requirement: keys backed up/recoverable by trusted-role personnel, dual
  control). Losing an unbackable CA key would force a full shim-review round.
- **RSA 2048**: Microsoft minimum, shim-standard, and the ceiling of YubiKey 5
  FIPS firmware < 5.7 for PIV. (If `ykman piv info` reports firmware ≥ 5.7,
  RSA 3072/4096 are possible for the *leaf*; keep the CA at 2048 for shim
  compatibility conservatism.)

## Preparation

- [ ] Air-gapped laptop booted from a live Linux USB (e.g. Fedora Live),
  packages available offline: `openssl`, `ykman` (yubikey-manager), `age` or
  `gpg` for backup encryption.
- [ ] 1× YubiKey 5C NFC FIPS (signer) — plus, strongly recommended, a 2nd
  YubiKey FIPS as CA token / spare.
- [ ] 2× new USB sticks for encrypted CA backups; envelopes; safe.
- [ ] Print this document; log every step (who/when/serials).

## 1. Initialize the YubiKey PIV applet

```sh
ykman piv info                          # note serial + firmware version
ykman piv reset                         # ONLY if factory-fresh / repurposed
ykman piv access change-pin             # new PIN  (FIPS: min 6 digits, not default)
ykman piv access change-puk             # new PUK
ykman piv access change-management-key --generate --protect
```

Record PIN/PUK in the safe (sealed envelope). The FIPS applet refuses
operation with default credentials — this step is mandatory.

## 2. Generate the CA (offline, openssl)

```sh
umask 077
cat > ca.cnf <<'EOF'
[req]
distinguished_name = dn
x509_extensions = ca_ext
prompt = no
[dn]
C  = FR
O  = TKRI                  # dénomination sociale as on the Kbis/RCS entry (SIREN 789990298)
CN = Neural ICE UEFI Secure Boot CA 2026
[ca_ext]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign, digitalSignature
subjectKeyIdentifier = hash
EOF

openssl req -new -x509 -newkey rsa:2048 -sha256 -days 7300 \
    -config ca.cnf -keyout ca.key -out ca.crt          # 20-year validity
openssl x509 -in ca.crt -outform DER -out neural-ice-uefi-ca.der
openssl x509 -in ca.crt -noout -text                   # verify CA:TRUE critical
```

`neural-ice-uefi-ca.der` is the `VENDOR_CERT_FILE` for the shim build
(shim-review requires **DER**, not PEM).

## 3. Generate the leaf on the YubiKey and certify it

```sh
# key is generated inside the YubiKey — never exists outside it
ykman piv keys generate --algorithm RSA2048 --pin-policy ONCE --touch-policy CACHED \
    9c leaf-pub.pem

# CSR built by the YubiKey (proves possession)
ykman piv certificates request --subject "C=FR,O=TKRI,CN=Neural ICE Secure Boot Signer 2026" \
    9c leaf-pub.pem leaf.csr

cat > leaf.cnf <<'EOF'
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = codeSigning
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
EOF
openssl x509 -req -in leaf.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -sha256 -days 1825 -extfile leaf.cnf -out neural-ice-signer-2026.crt

ykman piv certificates import 9c neural-ice-signer-2026.crt
openssl verify -CAfile ca.crt neural-ice-signer-2026.crt
```

Touch policy `CACHED` keeps CI signing usable (one touch validates a burst);
switch to `ALWAYS` if the pipeline design allows a human touch per release.

## 4. Back up and destroy the CA private key

```sh
age -p -o ca.key.age ca.key            # or: gpg --symmetric --cipher-algo AES256
sha256sum ca.key.age neural-ice-uefi-ca.der ca.crt > MANIFEST
# copy ca.key.age + certs + MANIFEST to BOTH USB sticks; verify hashes on each
# optional: import the CA into the spare YubiKey (slot 9c) as an online-usable copy:
#   ykman piv keys import 9c ca.key && ykman piv certificates import 9c ca.crt
shred -u ca.key ca.key.age leaf.csr    # nothing key-shaped leaves the room in clear
```

Passphrase and USB sticks go in **separate** sealed envelopes in the safe
(dual control: no single person holds both). Power off the live machine
(RAM-resident OS → no residue).

## 5. What leaves the ceremony

| Artifact | Destination |
|---|---|
| `neural-ice-uefi-ca.der`, `ca.crt` | Repo / shim-review fork (public by design) |
| `neural-ice-signer-2026.crt` | Repo + build host (public) |
| YubiKey (leaf in 9c) | Build/signing station |
| `ca.key.age` ×2 + passphrase envelope | Safe (dual control) |
| Ceremony log | Safe |

## 6. Day-to-day signing (pipeline, later work)

The leaf key is used via PKCS#11 (`libykcs11` / `pkcs11-provider`), e.g.:

```sh
# OpenSSL 3 + pkcs11-provider; exact URI: `p11tool --list-token-urls`
sbsign --engine pkcs11 \
    --key 'pkcs11:manufacturer=piv_II;id=%02;type=private' \
    --cert neural-ice-signer-2026.crt \
    --output vmlinuz.signed vmlinuz
```

To be finalized in the signing-pipeline work (sbsign vs pesign, PIN handling
on the runner, touch policy vs unattended CI trade-off).
