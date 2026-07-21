# ADR-0013 — Dedicated TPM device root v1

- Status: Accepted
- Date: 2026-07-21
- Owners: Neural ICE
- Related: ADR-0004, ADR-0012; ICE-Fabric ADR-0039

## Context

Licensing bootstrap and OTA state recovery need one hardware-bound appliance
identity that is independent from disk state. Reusing the endorsement key or
the appliance PKI root would couple unrelated lifecycles and make rotation or
recovery unsafe. The appliance PKI already owns persistent handle
`0x81010004`; it and every EK object must remain untouched.

The Owner approved a separate ECC P-256 key at `0x81010005`. This change does
not activate a release channel, mutate a live appliance or build USB media.

## Decision

The installer creates a TPM primary under the endorsement hierarchy and makes
it persistent at exactly `0x81010005`. Creating a primary uses the endorsement
hierarchy seed but does not read, evict, replace or otherwise mutate an EK
object. The key has this closed public template:

- type ECC, NIST P-256, Name algorithm SHA-256;
- scheme ECDSA with SHA-256 and no symmetric algorithm;
- attributes `fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign|noda`
  (raw `0x00040472`).

`fixedtpm`, `fixedparent` and `sensitivedataorigin` make the private key
TPM-generated and non-exportable. No private or sealed key blob is written to
disk. The only persisted file is root-owned public identity
`/var/lib/neural-ice/ota/device-root-v1.json`.

Attestation reads the TPMT_PUBLIC, DER SPKI, Name and qualified Name twice
under a process lock. It checks every algorithm and attribute by its numeric
TPM identifier, proves `Name = TPM_ALG_SHA256 || SHA256(TPMT_PUBLIC)`, then
binds the exact public-area and SPKI hashes in canonical JSON. Installer and
the enabled `neural-ice-device-root.service` run the same idempotent gate. An
existing exact key is reused. An occupied but non-conforming handle, a changed
identity or a missing handle for an established disk identity fails closed.

The service emits no key identity to journald. It is an OTA/licensing
prerequisite, not a boot dependency: failure blocks new trust bootstrap and
updates but does not stop the retained workload.

## Recovery

There is no force, local-reset or delete-and-recreate flag. Recovery requires:

1. the established canonical public identity on disk;
2. a new 32-byte nonce obtained from `TPM2_GetRandom` and stored as the sole
   root-owned pending challenge;
3. the byte-identical canonical recovery authorization signed by the offline
   OTA root over
   `neural-ice:ota:device-root-recovery:v1\0 || authorization`;
4. successful verification against the immutable image-staged OTA root public
   key.

Only then may the helper evict `0x81010005`, create the exact replacement,
attest it, atomically replace the public identity and consume the pending
challenge. The binary ECDSA DER signature is transported to the image-pinned
Cosign verifier as base64; no second production crypto stack is introduced. The authorization
binds the prior TPM Name and SPKI hash, exact handle and fresh nonce. It never
authorizes `0x81010004`, any EK handle or a caller-selected root key.

A simultaneous disk and TPM loss has no local continuity evidence. A fresh
install may create a new device root, but the OTA/licensing state remains
untrusted until the separately signed licensing-bootstrap recovery proof binds
the licence, old and new device identities, fresh nonce and exact immutable
baseline. Reinstalling therefore cannot recover update authority by itself.

## Rollback and failure analysis

- A crash before persistence leaves no established identity; an exact retry
  creates the same endorsement-seed primary.
- A crash after persistence but before the public receipt is written is
  recovered by attesting and adopting only the exact closed template.
- A crash after an authorized eviction leaves the pending challenge intact;
  the same exact root authorization can complete once. Success removes it.
- A one-version bootc rollback sees the same persistent handle and public
  receipt. It can keep the workload running but cannot claim a newer OTA
  capability or lower any state floor.
- TPM clear, handle replacement, public-area ambiguity, missing immutable root
  key or signature failure blocks only new licensing/OTA trust operations.

Physical TPM ownership can always clear the hardware. This design does not
pretend to prevent destructive denial of service; it prevents that destruction
from restoring licensing or OTA authority without the signed bootstrap path.
