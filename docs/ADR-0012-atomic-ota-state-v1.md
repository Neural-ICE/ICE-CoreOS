# ADR-0012 — Atomic TPM-anchored OTA state

- Status: Accepted
- Date: 2026-07-21
- Owners: Neural ICE
- Related: ADR-0003, ADR-0005, ADR-0010; ICE-Fabric ADR-0039

## Context

An appliance must not persist a new applied bundle while retaining older
authority or trusted-time state. A crash between independent writes would
create an ambiguous update baseline. Wall-clock time is not a trust source on
an offline or power-cycled appliance.

The deployed TPM NV index `0x01500001` remains the monotonic legacy bundle
floor. It cannot be repurposed without breaking rollback compatibility.

## Decision

The verifier uses a separate SHA-256, 32-byte TPM NV EXTEND index at
`0x01500002`. Its exact base attributes are
`authread|authwrite|no_da|nt=extend|ownerread|platformcreate|policydelete`;
`written` is the only permitted dynamic attribute. `platformcreate` is
required by TPM 2.0 for `TPM2_NV_UndefineSpaceSpecial`; an owner-created index
with `policydelete` is invalid and must never be provisioned. Runtime extension
authenticates to this index, not to the owner hierarchy.

Deletion is an exceptional root-recovery operation. The NV authorization
policy is the SHA-256 policy digest
`921f9fa2ce8c30bbf29b84500a8456188f1febc04f154e9eccca4d5b1bc8a25d`,
constructed as:

1. `TPM2_PolicyAuthorize` by the `ota-root-v1` public key whose TPM Name is
   `000beb256627a4315f1a3d2a2a0c9931760ad30e8822b35c5ebed854f1829b07b7b1`,
   with the exact binary policy reference
   `neural-ice:ota:state-nv-delete:v1\0`;
2. `TPM2_PolicyCommandCode(TPM_CC_NV_UndefineSpaceSpecial)`.

Per TCG TPM 2.0 Library Part 3 section 23.2.3, `PolicyUpdate` hashes its
variable-sized arguments in two distinct steps; it does not concatenate the
key Name and `policyRef` into one hash. For SHA-256 the reproducible chain is:

- `H(0^32 || 0000016a || ota-root-v1.Name)` =
  `8599598585b872929367c006ff1e53da890a41a20a590f436b160ebb141d7e85`;
- `H(previous || policyRef.buffer)` =
  `acd9fab3a701a6738e092425f342abd45962ffc2808f399d59aa615f892df063`;
- `H(previous || 0000016c || 0000011f)` = the pinned authorization policy
  `921f9fa2ce8c30bbf29b84500a8456188f1febc04f154e9eccca4d5b1bc8a25d`.

The same values are emitted by a trial policy session on `swtpm` through
`tpm2_policyauthorize` and `tpm2_policycommandcode`.

The root signature authorizes the approved recovery policy; it does not expose
or import the root private key on the appliance. The platform hierarchy must
also authorize the special undefine command. Owner/password undefine and an
empty-policy fallback are forbidden.

Capability discovery attests the complete public area, including the exact
authorization-policy digest and the TPM-computed public Name. The only accepted
Names are
`000b8ae052b814918370b191fe38782bb500041130d0665b1e7b2a368edcaf81eb62`
before the first extend and
`000b571132a9688f4088f3696fa9bf5d5793be7483202cee08ceb2261f2bbe89b440`
after `written` is set. It accepts both zero-padded and canonical unpadded
hexadecimal handles emitted by supported `tpm2-tools`, then compares the parsed
numeric handle. It must additionally prove that the complete pre-apply guard
and post-health commit command set is present. Consequently this first policy
slice does **not** advertise `atomic-state-v1`, even when a correct index
already exists.

Each committed generation binds the complete root-signed delegation snapshot,
the exact signed release authorization and BOM, the applied bundle floor, and
a canonical trusted-time v2 assertion. The manifest also binds all artifact
hashes, every monotonic floor, the previous manifest hash and the previous TPM
anchor. The verifier stages and fsyncs all files, extends the TPM with the
manifest hash, reads the expected anchor back, then publishes and rereads the
current pointer and enforcement marker. No success receipt is emitted earlier.

### Persistent disk contract

The canonical root is `${state_dir}/state-v1` (normally
`/var/lib/neural-ice/ota/state-v1`), owned by root with mode `0700`. Recovery
and commit serialize through the persistent inode
`.transaction.json.lock`; the inode contains no authority and a process crash
releases its kernel lock.

`current` is a root-owned `0600` regular file containing exactly
`generation-NNNNNNNNNNNNNNNN\n`. `enforce-ready.json` is canonical JSON with
one final LF and the closed fields `schema`, `manifest_sha256`, and
`nv_anchor`. It is authoritative only when its two hashes reproduce the
current complete generation and the TPM value under the same transaction
lock.

Every committed directory is named
`generations/generation-NNNNNNNNNNNNNNNN`, is root-owned mode `0700`, and has
this exact closed inventory of root-owned `0600` regular files:

- `manifest.json`, `applied.json`, `authority.json`, `trusted-time.json`;
- `delegation-snapshot.json` and `delegation-snapshot.sig`;
- `release-authorization.json` and `release-authorization.sig`;
- `trusted-time-assertion.json` and `trusted-time-assertion.sig`.

JSON artifacts are canonical UTF-8 JSON with one final LF. Signature files are
the exact signed bytes. The manifest binds the raw SHA-256 of every file; its
separate canonical JSON hashes follow the delegation contract and exclude the
single framing LF. Missing, additional, non-regular, symlinked, insecurely
owned, or mode-incompatible entries refuse the complete generation.

`current` and `enforce-ready.json` are derived repairable pointers, not
independent authority. Recovery holds the transaction lock while observing
the TPM, validating the complete chain, publishing and rereading both files,
then rereads the TPM before success. N-1 may ignore this new directory and run
the retained workload, but it must not mutate, delete, or lower the state-v1
chain; only the state-v1-capable retained deployment or root-signed recovery
may repair it.

Trusted time is a short-lived signed artifact obtained by the controller from
the allowlisted licensing service; the verifier itself remains networkless.
The v2 assertion is valid for at most ten minutes and binds:

- the exact release-authorization and root-signed snapshot hashes;
- hardware target and release ring;
- the appliance TPM-rooted device identity;
- the current TPM NV anchor, clock, reset count, restart count and safe bit;
- a fresh 32-byte appliance challenge consumed by the same atomic transaction.

Both the pre-apply guard and post-health commit re-read that TPM tuple locally.
The safe bit must remain true, reset/restart counts must be unchanged, and the
clock must not decrease or advance by more than the ten-minute assertion
freshness window. The asserted `trusted_time` plus conservatively rounded TPM
elapsed time must remain strictly below signed `valid_until`. The canonical
hash is computed from the supplied snapshot bytes, not accepted from a
separate caller claim. A scoped
`retiring` time key remains valid only during its bounded snapshot overlap.

For a fresh appliance, the trusted-time key is provisionally authorized only
by the candidate root-signed initial snapshot. Snapshot, assertion, release
and first state generation are accepted atomically; none becomes independent
authority on failure. A TPM-state recovery is a distinct root-signed artifact
bound to a new one-use appliance challenge and the complete replacement state.
Ordinary trusted-time assertions can never reset or lower a floor.

`ni-ota-verify prepare-trusted-time-v2` is the controller's local,
networkless preparation gate. It first freezes the four caller-supplied
authority artifacts, then verifies the complete root-signed snapshot and the
beta release signature. Both `active` and `retiring` release keys are accepted
during their bounded overlap; revoked, expired, wrong-role, wrong-target,
wrong-ring and wrong immutable appliance-variant releases refuse. A nonzero
TPM state anchor must resolve to exactly one complete durable generation before
the command can issue anything.

On success the command atomically replaces
`state-v1/pending-time-challenge.json` with a canonical mode-`0600` challenge
and prints that same object for the controller to submit to the allowlisted
trusted-time service. Replacement deliberately invalidates an earlier pending
attempt; no release has been applied at this point. The later atomic commit
must bind and consume the exact pending challenge. A malformed candidate exits
as a refusal, while local I/O, TPM or verifier failures remain internal errors.
The challenge fingerprints only the separate, installer-provisioned,
non-exportable device root at persistent handle `0x81010005` (ADR-0013); the
appliance PKI handle `0x81010004` is never read or reused. Thus a clean install
must complete the ADR-0013 device-root gate before trusted-time preparation;
failure denies only the candidate update and cannot create substitute identity.

## Crash recovery and rollback

- A crash before NV EXTEND leaves a non-authoritative staged generation which
  an exact retry may replace.
- A crash after challenge publication but before commit leaves only a pending
  request. The controller may retry the exact request or replace it by running
  preparation again; neither path advances a floor or authorizes payload
  application by itself.
- A crash after NV EXTEND recovers only the unique complete generation chain
  whose derived anchor equals the observed TPM value.
- An equal sequence is accepted only for byte-identical retry; a split view
  refuses.
- Existing state with a missing/recreated index, an unreadable legacy floor,
  ambiguous history, unsafe TPM clock or invalid issuance window fails closed
  for new updates while the installed workload keeps running.
- The legacy floor is read and cross-checked but never redefined or lowered.
- The previous immutable bootc deployment and OCI digests remain available for
  local rollback. Rollback never lowers authority, bundle or trusted-time
  floors; forward repair requires a newer signed release or root recovery.

An N-1 verifier without `atomic-state-v1` may boot the retained deployment but
cannot authorize a new atomic-state update. Operators must boot the retained
newer deployment or signed recovery media before changing update state.
The pending challenge is therefore forward-compatible state, not rollback
authority: an N-1 deployment ignores it, cannot consume it, and cannot lower
any state already anchored by the newer verifier.

## Delivery

Implementation lands as a reviewable stack. This first layer only parses and
attests the reserved index policy and cannot provision, extend, commit,
recover or move any channel. Later layers add installer/first-boot
provisioning, storage, transactional mutation, trusted-time v2 challenge
handling and caller integration. The public capability remains absent until
the exact index exists, passes attestation, and the same verifier binary
contains the pre-apply and post-health state-v1 commands.

No release channel, live appliance or USB medium is changed by this ADR.

The attribute and command constraints follow the published TCG TPM 2.0 Library
Part 2 (TPMA_NV) and Part 3 (`TPM2_NV_UndefineSpaceSpecial`) specifications.
