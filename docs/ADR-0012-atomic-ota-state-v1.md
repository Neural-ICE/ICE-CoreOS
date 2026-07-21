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
`authread|authwrite|no_da|nt=extend|ownerread|policydelete`; `written` is the
only permitted dynamic attribute. Runtime extension authenticates to this
index, not to the owner hierarchy. The index attestation accepts both the
zero-padded and canonical unpadded hexadecimal handle emitted by supported
`tpm2-tools`, then compares the parsed numeric handle. Capability discovery
must additionally prove that the complete pre-apply guard and post-health
commit command set is present. Consequently this first policy slice does
**not** advertise `atomic-state-v1`, even when a correct index already exists.

Each committed generation binds the complete root-signed delegation snapshot,
the exact signed release authorization and BOM, the applied bundle floor, and
a canonical trusted-time v2 assertion. The manifest also binds all artifact
hashes, every monotonic floor, the previous manifest hash and the previous TPM
anchor. The verifier stages and fsyncs all files, extends the TPM with the
manifest hash, reads the expected anchor back, then publishes and rereads the
current pointer and enforcement marker. No success receipt is emitted earlier.

Trusted time is a short-lived signed artifact obtained by the controller from
the allowlisted licensing service; the verifier itself remains networkless.
The v2 assertion is valid for at most ten minutes and binds:

- the exact release-authorization and root-signed snapshot hashes;
- hardware target and release ring;
- the appliance TPM-rooted device identity;
- the current TPM NV anchor, clock, reset count, restart count and safe bit;
- a fresh 32-byte appliance challenge consumed by the same atomic transaction.

For a fresh appliance, the trusted-time key is provisionally authorized only
by the candidate root-signed initial snapshot. Snapshot, assertion, release
and first state generation are accepted atomically; none becomes independent
authority on failure. A TPM-state recovery is a distinct root-signed artifact
bound to a new one-use appliance challenge and the complete replacement state.
Ordinary trusted-time assertions can never reset or lower a floor.

## Crash recovery and rollback

- A crash before NV EXTEND leaves a non-authoritative staged generation which
  an exact retry may replace.
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

## Delivery

Implementation lands as a reviewable stack. This first layer only parses and
attests the reserved index policy and cannot provision, extend, commit,
recover or move any channel. Later layers add installer/first-boot
provisioning, storage, transactional mutation, trusted-time v2 challenge
handling and caller integration. The public capability remains absent until
the exact index exists, passes attestation, and the same verifier binary
contains the pre-apply and post-health state-v1 commands.

No release channel, live appliance or USB medium is changed by this ADR.
