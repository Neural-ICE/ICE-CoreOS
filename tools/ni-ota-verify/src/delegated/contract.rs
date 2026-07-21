//! ADR-0039 closed delegation-snapshot contract primitives.
//! Fetching and trusted-time acquisition stay outside this local-only verifier.

use std::collections::HashSet;

use p256::{elliptic_curve::sec1::FromEncodedPoint, AffinePoint, EncodedPoint};
use serde::{Deserialize, Serialize};

use crate::{runner, InternalError};

#[derive(Debug)]
pub(crate) enum ContractError {
    Refusal(String),
    Internal(InternalError),
}

impl From<String> for ContractError {
    fn from(reason: String) -> Self {
        Self::Refusal(reason)
    }
}

impl From<&str> for ContractError {
    fn from(reason: &str) -> Self {
        Self::Refusal(reason.to_owned())
    }
}

fn hash_bytes(bytes: &[u8]) -> Result<String, ContractError> {
    classify_hash(runner::sha256_bytes(bytes))
}

fn classify_hash(result: Result<String, InternalError>) -> Result<String, ContractError> {
    result.map_err(ContractError::Internal)
}

const P256_SPKI_PREFIX: &[u8] = &[
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
];

#[derive(Deserialize, Serialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct PublicKey {
    algorithm: String,
    encoding: String,
    pub(crate) spki_der_base64: String,
    spki_sha256: String,
}

#[derive(Deserialize, Serialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct RootKey {
    key_id: String,
    public_key: PublicKey,
    root_version: u64,
}

#[derive(Deserialize, Serialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct RotationOverlap {
    mode: String,
    with_key_id: Option<String>,
    valid_from: Option<String>,
    valid_until: Option<String>,
}

#[derive(Deserialize, Serialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct DelegatedKey {
    pub(crate) artifact_types: Vec<String>,
    pub(crate) hardware_targets: Vec<String>,
    pub(crate) key_id: String,
    predecessor_key_id: Option<String>,
    pub(crate) public_key: PublicKey,
    pub(crate) rings: Vec<String>,
    pub(crate) role: String,
    rotation_overlap: RotationOverlap,
    signature_algorithm: String,
    signature_encoding: String,
    pub(crate) status: String,
    successor_key_id: Option<String>,
    pub(crate) valid_from: String,
    pub(crate) valid_until: String,
}

#[derive(Deserialize, Serialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Tombstone {
    key_id: String,
    predecessor_key_id: Option<String>,
    reason: String,
    revocation_seq: u64,
    revoked_at: String,
    role: String,
    spki_sha256: String,
    successor_key_id: Option<String>,
    terminal_status: String,
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub(crate) struct Snapshot {
    pub(crate) delegation_seq: u64,
    issued_at: String,
    pub(crate) keys: Vec<DelegatedKey>,
    previous_snapshot_sha256: Option<String>,
    root_key: RootKey,
    schema: String,
    signature_algorithm: String,
    signature_encoding: String,
    signing_role: String,
    tombstones: Vec<Tombstone>,
    pub(crate) valid_from: String,
    pub(crate) valid_until: String,
}

pub(crate) fn parse_canonical<T>(bytes: &[u8], what: &str) -> Result<T, String>
where
    T: serde::de::DeserializeOwned,
{
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| format!("invalid {what}: {e}"))?;
    let parsed: T = serde_json::from_slice(bytes).map_err(|e| format!("invalid {what}: {e}"))?;
    let mut canonical = serde_json::to_vec(&value).map_err(|e| e.to_string())?;
    canonical.push(b'\n');
    if canonical != bytes {
        return Err(format!(
            "{what} is not canonical compact sorted JSON plus LF"
        ));
    }
    Ok(parsed)
}

pub(crate) fn validate_snapshot(snapshot: &Snapshot) -> Result<(), ContractError> {
    if snapshot.schema != "neural-ice-ota-delegation-snapshot-v1"
        || snapshot.signing_role != "ota-root"
        || !signature_profile(&snapshot.signature_algorithm, &snapshot.signature_encoding)
        || !safe_uint(snapshot.delegation_seq)
        || !timestamp(&snapshot.issued_at)
        || !timestamp(&snapshot.valid_from)
        || !timestamp(&snapshot.valid_until)
        || snapshot.issued_at > snapshot.valid_from
        || snapshot.valid_from >= snapshot.valid_until
    {
        return Err("snapshot schema/profile/sequence/time is invalid".into());
    }
    if snapshot.delegation_seq == 1 {
        if snapshot.previous_snapshot_sha256.is_some() {
            return Err("initial snapshot has a predecessor hash".into());
        }
    } else if !snapshot
        .previous_snapshot_sha256
        .as_deref()
        .is_some_and(sha256)
    {
        return Err("snapshot predecessor hash is invalid".into());
    }
    if !safe_uint(snapshot.root_key.root_version)
        || snapshot.root_key.key_id != format!("ota-root-v{}", snapshot.root_key.root_version)
    {
        return Err("root identity is invalid".into());
    }
    validate_public_key(&snapshot.root_key.public_key)?;
    let mut ids = HashSet::from([snapshot.root_key.key_id.as_str()]);
    let mut pins = HashSet::from([snapshot.root_key.public_key.spki_sha256.as_str()]);
    let mut prior = "";
    for key in &snapshot.keys {
        if key.key_id.as_str() <= prior
            || !ids.insert(&key.key_id)
            || !pins.insert(&key.public_key.spki_sha256)
        {
            return Err("duplicate or unsorted key inventory".into());
        }
        prior = &key.key_id;
        validate_key(key)?;
    }
    prior = "";
    for tombstone in &snapshot.tombstones {
        if tombstone.key_id.as_str() <= prior
            || !ids.insert(&tombstone.key_id)
            || !pins.insert(&tombstone.spki_sha256)
            || !ident(&tombstone.key_id)
            || !matches!(
                tombstone.role.as_str(),
                "image-ci" | "release-beta" | "release-stable"
            )
            || !sha256(&tombstone.spki_sha256)
            || tombstone.terminal_status != "revoked"
            || !safe_uint(tombstone.revocation_seq)
            || tombstone.revocation_seq > snapshot.delegation_seq
            || !timestamp(&tombstone.revoked_at)
            || tombstone.revoked_at > snapshot.issued_at
            || !ident(&tombstone.reason)
            || !distinct_lineage(&tombstone.predecessor_key_id, &tombstone.successor_key_id)
        {
            return Err("invalid, duplicate or unsorted tombstone inventory".into());
        }
        prior = &tombstone.key_id;
    }
    validate_references(snapshot)?;
    Ok(())
}

pub(crate) fn validate_snapshot_time(snapshot: &Snapshot, now: &str) -> Result<(), String> {
    if !timestamp(now) || now < snapshot.valid_from.as_str() || now >= snapshot.valid_until.as_str()
    {
        return Err("snapshot is not current at trusted time".into());
    }
    Ok(())
}

fn validate_key(key: &DelegatedKey) -> Result<(), ContractError> {
    validate_public_key(&key.public_key)?;
    if !ident(&key.key_id)
        || !signature_profile(&key.signature_algorithm, &key.signature_encoding)
        || !timestamp(&key.valid_from)
        || !timestamp(&key.valid_until)
        || key.valid_from >= key.valid_until
        || !matches!(key.status.as_str(), "active" | "retiring")
        || !sorted_unique(&key.hardware_targets)
        || key.hardware_targets.is_empty()
        || !key.hardware_targets.iter().all(|v| target(v))
        || !optional_ident(&key.predecessor_key_id)
        || !optional_ident(&key.successor_key_id)
        || !distinct_lineage(&key.predecessor_key_id, &key.successor_key_id)
    {
        return Err("invalid delegated key".into());
    }
    let policy = match key.role.as_str() {
        "image-ci" => (
            &[
                "oci-image-signature",
                "slsa-provenance-attestation",
                "spdx-sbom-attestation",
            ][..],
            &["beta", "stable"][..],
        ),
        "release-beta" => (
            &["beta-publication-receipt", "beta-release-authorization"][..],
            &["beta"][..],
        ),
        "release-stable" => (&["stable-release-authorization"][..], &["stable"][..]),
        _ => return Err("unknown delegated role".into()),
    };
    if key
        .artifact_types
        .iter()
        .map(String::as_str)
        .ne(policy.0.iter().copied())
        || key
            .rings
            .iter()
            .map(String::as_str)
            .ne(policy.1.iter().copied())
    {
        return Err("delegated role scope differs from closed policy".into());
    }
    match key.rotation_overlap.mode.as_str() {
        "none"
            if key.rotation_overlap.with_key_id.is_none()
                && key.rotation_overlap.valid_from.is_none()
                && key.rotation_overlap.valid_until.is_none() => {}
        "bounded"
            if key
                .rotation_overlap
                .with_key_id
                .as_deref()
                .is_some_and(ident)
                && key
                    .rotation_overlap
                    .valid_from
                    .as_deref()
                    .is_some_and(timestamp)
                && key
                    .rotation_overlap
                    .valid_until
                    .as_deref()
                    .is_some_and(timestamp)
                && key.rotation_overlap.valid_from < key.rotation_overlap.valid_until => {}
        _ => return Err("delegated rotation overlap is invalid".into()),
    }
    Ok(())
}

fn validate_references(snapshot: &Snapshot) -> Result<(), String> {
    let live = |candidate: &str| snapshot.keys.iter().find(|key| key.key_id == candidate);
    let dead = |candidate: &str| {
        snapshot
            .tombstones
            .iter()
            .find(|tombstone| tombstone.key_id == candidate)
    };
    for tombstone in &snapshot.tombstones {
        for (predecessor, reference) in [
            (true, tombstone.predecessor_key_id.as_deref()),
            (false, tombstone.successor_key_id.as_deref()),
        ] {
            let Some(reference) = reference else {
                continue;
            };
            let valid = live(reference).is_some_and(|peer| {
                peer.role == tombstone.role
                    && if predecessor {
                        peer.successor_key_id.as_deref() == Some(tombstone.key_id.as_str())
                            && peer.valid_from <= tombstone.revoked_at
                    } else {
                        peer.predecessor_key_id.as_deref() == Some(tombstone.key_id.as_str())
                            && tombstone.revoked_at < peer.valid_until
                    }
            }) || dead(reference).is_some_and(|peer| {
                peer.role == tombstone.role
                    && if predecessor {
                        peer.successor_key_id.as_deref() == Some(tombstone.key_id.as_str())
                            && peer.revoked_at <= tombstone.revoked_at
                    } else {
                        peer.predecessor_key_id.as_deref() == Some(tombstone.key_id.as_str())
                            && tombstone.revoked_at <= peer.revoked_at
                    }
            });
            if reference == tombstone.key_id || !valid {
                return Err("tombstone lineage role or temporal order is invalid".into());
            }
        }
    }
    for key in &snapshot.keys {
        for reference in [
            key.predecessor_key_id.as_deref(),
            key.successor_key_id.as_deref(),
            key.rotation_overlap.with_key_id.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            if reference == key.key_id || (live(reference).is_none() && dead(reference).is_none()) {
                return Err(
                    "delegated rotation reference is unresolved or self-referential".into(),
                );
            }
        }
        for (predecessor, reference) in [
            (true, key.predecessor_key_id.as_deref()),
            (false, key.successor_key_id.as_deref()),
        ] {
            if let Some(peer) = reference.and_then(dead) {
                let valid = peer.role == key.role
                    && if predecessor {
                        peer.revoked_at < key.valid_until
                    } else {
                        key.valid_from <= peer.revoked_at
                    };
                if !valid {
                    return Err("live/tombstone lineage role or temporal order is invalid".into());
                }
            }
        }
        let live_peers: Vec<_> = [
            key.predecessor_key_id.as_deref(),
            key.successor_key_id.as_deref(),
        ]
        .into_iter()
        .flatten()
        .filter_map(live)
        .collect();
        let dead_peers: Vec<_> = [
            key.predecessor_key_id.as_deref(),
            key.successor_key_id.as_deref(),
        ]
        .into_iter()
        .flatten()
        .filter_map(dead)
        .collect();
        match live_peers.as_slice() {
            [] if key.rotation_overlap.mode == "none" => {}
            [] if matches!(dead_peers.as_slice(), [peer]
                if key.rotation_overlap.mode == "bounded"
                    && key.rotation_overlap.with_key_id.as_deref()
                        == Some(peer.key_id.as_str())
                    && peer.role == key.role
                    && ((key.predecessor_key_id.as_deref() == Some(peer.key_id.as_str())
                        && peer.successor_key_id.as_deref() == Some(key.key_id.as_str()))
                        || (key.successor_key_id.as_deref() == Some(peer.key_id.as_str())
                            && peer.predecessor_key_id.as_deref()
                                == Some(key.key_id.as_str())))
                    && key.rotation_overlap.valid_from.as_deref()
                        .is_some_and(|from| from <= peer.revoked_at.as_str())
                    && key.rotation_overlap.valid_until.as_deref()
                        .is_some_and(|until| peer.revoked_at.as_str() < until)) => {}
            [peer]
                if key.rotation_overlap.mode == "bounded"
                    && key.rotation_overlap.with_key_id.as_deref()
                        == Some(peer.key_id.as_str())
                    && peer.role == key.role
                    && ((key.predecessor_key_id.as_deref() == Some(peer.key_id.as_str())
                        && peer.successor_key_id.as_deref() == Some(key.key_id.as_str()))
                        || (key.successor_key_id.as_deref() == Some(peer.key_id.as_str())
                            && peer.predecessor_key_id.as_deref()
                                == Some(key.key_id.as_str())))
                    && peer.rotation_overlap.mode == "bounded"
                    && peer.rotation_overlap.with_key_id.as_deref()
                        == Some(key.key_id.as_str())
                    && peer.rotation_overlap.valid_from == key.rotation_overlap.valid_from
                    && peer.rotation_overlap.valid_until == key.rotation_overlap.valid_until
                    && key.rotation_overlap.valid_from.as_deref()
                        == Some(key.valid_from.as_str().max(peer.valid_from.as_str()))
                    && key.rotation_overlap.valid_until.as_deref()
                        == Some(key.valid_until.as_str().min(peer.valid_until.as_str())) => {}
            _ => return Err("live rotation lineage or exact mutual overlap is invalid".into()),
        }
    }
    for (index, left) in snapshot.keys.iter().enumerate() {
        for right in &snapshot.keys[index + 1..] {
            let shared_target = left
                .hardware_targets
                .iter()
                .any(|target| right.hardware_targets.contains(target));
            let time_overlap =
                left.valid_from < right.valid_until && right.valid_from < left.valid_until;
            if left.role == right.role
                && shared_target
                && time_overlap
                && !(left.rotation_overlap.with_key_id.as_deref() == Some(right.key_id.as_str())
                    && right.rotation_overlap.with_key_id.as_deref() == Some(left.key_id.as_str()))
            {
                return Err("overlapping authority lacks an exact mutual rotation peer".into());
            }
        }
    }
    Ok(())
}

pub(crate) fn validate_chain(
    old: &Snapshot,
    new: &Snapshot,
    old_hash: &str,
) -> Result<(), ContractError> {
    if new.delegation_seq != old.delegation_seq + 1
        || new.previous_snapshot_sha256.as_deref() != Some(old_hash)
        || new.root_key != old.root_key
    {
        return Err("delegation sequence, root or previous-hash link is invalid".into());
    }
    for dead in &old.tombstones {
        if !new.tombstones.contains(dead) {
            return Err("delegation tombstone was omitted or changed".into());
        }
    }
    for dead in &new.tombstones {
        if old.tombstones.iter().any(|old| old.key_id == dead.key_id) {
            continue;
        }
        if !old.keys.iter().any(|key| key.key_id == dead.key_id)
            || dead.revocation_seq != new.delegation_seq
        {
            return Err("new delegation tombstone is backdated or lacks a live predecessor".into());
        }
    }
    for key in &old.keys {
        if let Some(next) = new.keys.iter().find(|next| next.key_id == key.key_id) {
            if next.role != key.role
                || next.public_key != key.public_key
                || next.signature_algorithm != key.signature_algorithm
                || next.signature_encoding != key.signature_encoding
                || !subset(&next.artifact_types, &key.artifact_types)
                || !subset(&next.rings, &key.rings)
                || !subset(&next.hardware_targets, &key.hardware_targets)
                || next.valid_from < key.valid_from
                || next.valid_until > key.valid_until
                || (key.status == "retiring" && next.status != "retiring")
                || key
                    .predecessor_key_id
                    .as_ref()
                    .is_some_and(|old| next.predecessor_key_id.as_ref() != Some(old))
                || key
                    .successor_key_id
                    .as_ref()
                    .is_some_and(|old| next.successor_key_id.as_ref() != Some(old))
                || (key.rotation_overlap.mode == "bounded"
                    && next.rotation_overlap != key.rotation_overlap
                    && !advances_overlap_after_peer_revocation(key, next, new))
            {
                return Err("retained delegation widened or changed identity".into());
            }
        } else {
            let dead = new
                .tombstones
                .iter()
                .find(|dead| dead.key_id == key.key_id)
                .ok_or_else(|| "delegated key omitted without tombstone".to_string())?;
            if dead.role != key.role
                || dead.spki_sha256 != key.public_key.spki_sha256
                || dead.revocation_seq != new.delegation_seq
                || dead.predecessor_key_id != key.predecessor_key_id
                || dead.successor_key_id != key.successor_key_id
            {
                return Err("revocation tombstone does not bind removed key".into());
            }
        }
    }
    Ok(())
}

fn advances_overlap_after_peer_revocation(
    old: &DelegatedKey,
    next: &DelegatedKey,
    snapshot: &Snapshot,
) -> bool {
    let (Some(old_peer), Some(next_peer)) = (
        old.rotation_overlap.with_key_id.as_deref(),
        next.rotation_overlap.with_key_id.as_deref(),
    ) else {
        return false;
    };
    old_peer != next_peer
        && next.rotation_overlap.mode == "bounded"
        && old.predecessor_key_id.as_deref() == Some(old_peer)
        && old.successor_key_id.is_none()
        && next.successor_key_id.as_deref() == Some(next_peer)
        && snapshot.keys.iter().any(|peer| peer.key_id == next_peer)
        && snapshot.tombstones.iter().any(|peer| {
            peer.key_id == old_peer
                && peer.role == old.role
                && peer.successor_key_id.as_deref() == Some(old.key_id.as_str())
        })
}

pub(crate) fn canonical_hash(canonical: &[u8]) -> Result<String, ContractError> {
    let compact = canonical
        .strip_suffix(b"\n")
        .ok_or_else(|| ContractError::Refusal("canonical artifact lacks its single LF".into()))?;
    hash_bytes(compact)
}

pub(crate) fn verify_root_binding(snapshot: &Snapshot, root_pem: &[u8]) -> Result<(), String> {
    let independent = decode_pem(root_pem)?;
    let embedded = decode_base64(&snapshot.root_key.public_key.spki_der_base64)?;
    if independent != embedded {
        return Err("snapshot root SPKI differs from immutable trust anchor".into());
    }
    Ok(())
}

fn validate_public_key(key: &PublicKey) -> Result<(), ContractError> {
    if key.algorithm != "ecdsa-p256-sha256"
        || key.encoding != "spki-der-base64"
        || !sha256(&key.spki_sha256)
    {
        return Err("public-key profile is invalid".into());
    }
    let der = decode_base64(&key.spki_der_base64).map_err(ContractError::Refusal)?;
    if der.len() != 91 || !der.starts_with(P256_SPKI_PREFIX) {
        return Err("public key is not canonical uncompressed P-256 SPKI DER".into());
    }
    let encoded = EncodedPoint::from_bytes(&der[P256_SPKI_PREFIX.len() - 1..])
        .map_err(|_| ContractError::Refusal("public key has invalid SEC1 encoding".into()))?;
    let point = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&encoded))
        .ok_or_else(|| ContractError::Refusal("public key point is not on P-256".into()))?;
    if bool::from(point.is_identity()) {
        return Err("public key is the P-256 identity".into());
    }
    if hash_bytes(&der)? != key.spki_sha256 {
        return Err("public-key SPKI pin mismatch".into());
    }
    if encode_base64(&der) != key.spki_der_base64 {
        return Err("public-key base64 is non-canonical".into());
    }
    Ok(())
}

fn decode_pem(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "root public key is not UTF-8 PEM")?;
    let body = text
        .strip_prefix("-----BEGIN PUBLIC KEY-----\n")
        .and_then(|v| v.strip_suffix("-----END PUBLIC KEY-----\n"))
        .ok_or("root public key is not exact PUBLIC KEY PEM")?;
    decode_base64(&body.replace('\n', ""))
}

fn decode_base64(value: &str) -> Result<Vec<u8>, String> {
    if value.is_empty()
        || value
            .bytes()
            .any(|b| !(b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'='))
    {
        return Err("invalid base64".into());
    }
    let mut out = Vec::new();
    for chunk in value.as_bytes().chunks(4) {
        if chunk.len() != 4 {
            return Err("invalid base64 length".into());
        }
        let mut n = 0u32;
        let mut padding = 0;
        for &byte in chunk {
            n = (n << 6)
                | match byte {
                    b'A'..=b'Z' => u32::from(byte - b'A'),
                    b'a'..=b'z' => u32::from(byte - b'a' + 26),
                    b'0'..=b'9' => u32::from(byte - b'0' + 52),
                    b'+' => 62,
                    b'/' => 63,
                    b'=' => {
                        padding += 1;
                        0
                    }
                    _ => return Err("invalid base64".into()),
                };
        }
        out.push((n >> 16) as u8);
        if padding < 2 {
            out.push((n >> 8) as u8);
        }
        if padding == 0 {
            out.push(n as u8);
        }
    }
    if encode_base64(&out) != value {
        return Err("non-canonical base64".into());
    }
    Ok(out)
}

pub(crate) fn encode_base64(bytes: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            TABLE[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

pub(crate) fn validate_der_signature(bytes: &[u8]) -> Result<(), String> {
    if !(8..=72).contains(&bytes.len())
        || bytes[0] != 0x30
        || usize::from(bytes[1]) != bytes.len() - 2
    {
        return Err("signature is not minimal ASN.1 DER".into());
    }
    let mut offset = 2;
    let mut integers = [&[][..]; 2];
    for integer in &mut integers {
        if offset + 2 > bytes.len() || bytes[offset] != 0x02 {
            return Err("signature is not ASN.1 DER integers".into());
        }
        let len = usize::from(bytes[offset + 1]);
        offset += 2;
        if len == 0 || len > 33 || offset + len > bytes.len() {
            return Err("signature integer length is invalid".into());
        }
        let raw = &bytes[offset..offset + len];
        offset += len;
        if raw.iter().all(|byte| *byte == 0)
            || raw[0] & 0x80 != 0
            || (len > 1 && raw[0] == 0 && raw[1] & 0x80 == 0)
        {
            return Err("signature integer is non-minimal".into());
        }
        *integer = raw;
    }
    if offset != bytes.len() {
        return Err("signature has trailing bytes".into());
    }
    const ORDER: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63,
        0x25, 0x51,
    ];
    const HALF: [u8; 32] = [
        0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31,
        0x92, 0xa8,
    ];
    if integers.iter().any(|value| !scalar_below(value, &ORDER)) {
        return Err("signature integer is outside the P-256 scalar range".into());
    }
    if !scalar_below_or_equal(integers[1], &HALF) {
        return Err("signature is not low-S".into());
    }
    Ok(())
}

fn scalar_below(value: &[u8], upper: &[u8; 32]) -> bool {
    let significant = value.strip_prefix(&[0]).unwrap_or(value);
    significant.len() < 32 || (significant.len() == 32 && significant < upper)
}

fn scalar_below_or_equal(value: &[u8], upper: &[u8; 32]) -> bool {
    let significant = value.strip_prefix(&[0]).unwrap_or(value);
    significant.len() < 32 || (significant.len() == 32 && significant <= upper)
}

fn signature_profile(algorithm: &str, encoding: &str) -> bool {
    algorithm == "ecdsa-p256-sha256" && encoding == "asn1-der"
}
pub(crate) fn sha256(v: &str) -> bool {
    v.len() == 64
        && v.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn ident(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 127
        && v.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
        && v.as_bytes()[0].is_ascii_alphanumeric()
}
fn target(v: &str) -> bool {
    matches!(
        v,
        "amd-rocm-x86_64" | "nvidia-cuda-x86_64" | "nvidia-gb10-arm64"
    )
}
fn sorted_unique(v: &[String]) -> bool {
    v.windows(2).all(|w| w[0] < w[1])
}
fn subset(a: &[String], b: &[String]) -> bool {
    a.iter().all(|v| b.contains(v))
}
fn optional_ident(value: &Option<String>) -> bool {
    value.as_deref().is_none_or(ident)
}
fn distinct_lineage(predecessor: &Option<String>, successor: &Option<String>) -> bool {
    predecessor.is_none() || successor.is_none() || predecessor != successor
}
pub(crate) fn safe_uint(value: u64) -> bool {
    (1..=9_007_199_254_740_991).contains(&value)
}
fn timestamp(v: &str) -> bool {
    let b = v.as_bytes();
    if b.len() != 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b[19] != b'Z'
    {
        return false;
    }
    let n = |r: std::ops::Range<usize>| std::str::from_utf8(&b[r]).ok()?.parse::<u32>().ok();
    let (Some(y), Some(m), Some(d), Some(h), Some(mi), Some(s)) =
        (n(0..4), n(5..7), n(8..10), n(11..13), n(14..16), n(17..19))
    else {
        return false;
    };
    let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let days = [
        0,
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    y > 0 && m > 0 && m <= 12 && d > 0 && d <= days[m as usize] && h < 24 && mi < 60 && s < 60
}

#[cfg(test)]
mod tests {
    use super::*;

    const SNAPSHOT: &[u8] =
        include_bytes!("../../tests/fixtures/delegated-v1/delegation-snapshot.json");

    fn canonical(value: &serde_json::Value) -> Vec<u8> {
        let mut bytes = serde_json::to_vec(value).unwrap();
        bytes.push(b'\n');
        bytes
    }

    fn revoked_snapshot() -> (Snapshot, String) {
        let old_hash = canonical_hash(SNAPSHOT).unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(SNAPSHOT).unwrap();
        value["delegation_seq"] = serde_json::json!(2);
        value["previous_snapshot_sha256"] = serde_json::json!(old_hash);
        value["issued_at"] = serde_json::json!("2026-08-01T00:45:00Z");
        value["valid_from"] = serde_json::json!("2026-08-01T01:00:00Z");
        value["keys"].as_array_mut().unwrap().remove(1);
        value["tombstones"] = serde_json::json!([{
            "key_id": "release-beta-v1",
            "predecessor_key_id": null,
            "reason": "key-compromise",
            "revocation_seq": 2,
            "revoked_at": "2026-08-01T00:30:00Z",
            "role": "release-beta",
            "spki_sha256": "162e3c389da5d687742928c8ee4719279706d18b15db81031702bb9d077349e8",
            "successor_key_id": null,
            "terminal_status": "revoked"
        }]);
        let snapshot = parse_canonical(&canonical(&value), "snapshot").unwrap();
        (snapshot, old_hash)
    }

    #[test]
    fn fabric_snapshot_vector_validates_and_binds_exact_hash() {
        let snapshot: Snapshot = parse_canonical(SNAPSHOT, "snapshot").unwrap();
        validate_snapshot(&snapshot).unwrap();
        validate_snapshot_time(&snapshot, "2026-07-22T00:00:00Z").unwrap();
        let hash = canonical_hash(SNAPSHOT).unwrap();
        assert_eq!(
            hash,
            "959c879bc0583bdf98ac029503d37e814c5f51120a5aef6ddf5ed0896b859a3b"
        );
    }

    #[test]
    fn closed_contract_rejects_unknown_duplicate_and_scope_widening() {
        let mut unknown: serde_json::Value = serde_json::from_slice(SNAPSHOT).unwrap();
        unknown["unknown"] = serde_json::json!(true);
        assert!(parse_canonical::<Snapshot>(&canonical(&unknown), "snapshot").is_err());

        let duplicate = std::str::from_utf8(SNAPSHOT).unwrap().replacen(
            "{\"delegation_seq\":1,",
            "{\"delegation_seq\":1,\"delegation_seq\":1,",
            1,
        );
        assert!(parse_canonical::<Snapshot>(duplicate.as_bytes(), "snapshot").is_err());

        let mut widened: serde_json::Value = serde_json::from_slice(SNAPSHOT).unwrap();
        widened["keys"][1]["rings"] = serde_json::json!(["beta", "stable"]);
        let widened: Snapshot = parse_canonical(&canonical(&widened), "snapshot").unwrap();
        assert!(validate_snapshot(&widened).is_err());
    }

    #[test]
    fn chain_refuses_omission_without_exact_tombstone() {
        let old: Snapshot = parse_canonical(SNAPSHOT, "snapshot").unwrap();
        let old_hash = canonical_hash(SNAPSHOT).unwrap();
        let mut new: Snapshot = parse_canonical(SNAPSHOT, "snapshot").unwrap();
        new.delegation_seq = 2;
        new.previous_snapshot_sha256 = Some(old_hash.clone());
        new.keys.retain(|key| key.key_id != "release-beta-v1");
        assert!(validate_chain(&old, &new, &old_hash).is_err());
    }

    #[test]
    fn snapshot_refuses_reused_lineage_identifier() {
        let snapshot: Snapshot = parse_canonical(SNAPSHOT, "snapshot").unwrap();
        let mut key = snapshot.keys[1].clone();
        key.predecessor_key_id = Some("release-beta-v0".into());
        key.successor_key_id = Some("release-beta-v0".into());
        assert!(validate_key(&key).is_err());
    }

    #[test]
    fn chain_refuses_backdated_or_invented_tombstone() {
        let old: Snapshot = parse_canonical(SNAPSHOT, "snapshot").unwrap();
        let old_hash = canonical_hash(SNAPSHOT).unwrap();
        let mut new = old.clone();
        new.delegation_seq = 2;
        new.previous_snapshot_sha256 = Some(old_hash.clone());
        new.tombstones.push(Tombstone {
            key_id: "release-beta-retired".into(),
            predecessor_key_id: None,
            reason: "key-compromise".into(),
            revocation_seq: 1,
            revoked_at: "2026-07-21T00:00:00Z".into(),
            role: "release-beta".into(),
            spki_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            successor_key_id: None,
            terminal_status: "revoked".into(),
        });
        assert!(validate_snapshot(&new).is_ok());
        assert!(validate_chain(&old, &new, &old_hash).is_err());
    }

    #[test]
    fn snapshot_refuses_cross_role_rotation_overlap() {
        let mut value: serde_json::Value = serde_json::from_slice(SNAPSHOT).unwrap();
        value["keys"][1]["predecessor_key_id"] = serde_json::json!("image-ci-v1");
        value["keys"][0]["successor_key_id"] = serde_json::json!("release-beta-v1");
        value["keys"][1]["rotation_overlap"] = serde_json::json!({
            "mode": "bounded",
            "with_key_id": "image-ci-v1",
            "valid_from": "2026-07-21T01:00:00Z",
            "valid_until": "2027-07-21T01:00:00Z"
        });
        let snapshot: Snapshot = parse_canonical(&canonical(&value), "snapshot").unwrap();
        assert!(validate_snapshot(&snapshot).is_err());
    }

    #[test]
    fn snapshot_refuses_unilateral_rotation_overlap() {
        let mut value: serde_json::Value = serde_json::from_slice(SNAPSHOT).unwrap();
        value["keys"][1]["successor_key_id"] = serde_json::json!("release-beta-v2");
        value["keys"][1]["rotation_overlap"] = serde_json::json!({
            "mode": "bounded",
            "with_key_id": "release-beta-v2",
            "valid_from": "2026-07-21T01:00:00Z",
            "valid_until": "2027-07-21T01:00:00Z"
        });
        value["keys"][2]["key_id"] = serde_json::json!("release-beta-v2");
        value["keys"][2]["role"] = serde_json::json!("release-beta");
        value["keys"][2]["artifact_types"] =
            serde_json::json!(["beta-publication-receipt", "beta-release-authorization"]);
        value["keys"][2]["rings"] = serde_json::json!(["beta"]);
        value["keys"][2]["predecessor_key_id"] = serde_json::json!("release-beta-v1");
        let snapshot: Snapshot = parse_canonical(&canonical(&value), "snapshot").unwrap();
        assert!(validate_snapshot(&snapshot).is_err());
    }

    #[test]
    fn snapshot_refuses_live_rotation_pair_without_overlap() {
        let mut value: serde_json::Value = serde_json::from_slice(SNAPSHOT).unwrap();
        value["keys"][2]["role"] = serde_json::json!("release-beta");
        value["keys"][2]["artifact_types"] =
            serde_json::json!(["beta-publication-receipt", "beta-release-authorization"]);
        value["keys"][2]["rings"] = serde_json::json!(["beta"]);
        value["keys"][2]["predecessor_key_id"] = serde_json::json!("release-beta-v1");
        value["keys"][1]["successor_key_id"] = value["keys"][2]["key_id"].clone();
        let snapshot: Snapshot = parse_canonical(&canonical(&value), "snapshot").unwrap();
        assert!(validate_snapshot(&snapshot).is_err());
    }

    #[test]
    fn snapshot_requires_exact_mutual_overlap_for_duplicate_authority() {
        let mut value: serde_json::Value = serde_json::from_slice(SNAPSHOT).unwrap();
        value["keys"][2]["role"] = serde_json::json!("release-beta");
        value["keys"][2]["artifact_types"] =
            serde_json::json!(["beta-publication-receipt", "beta-release-authorization"]);
        value["keys"][2]["rings"] = serde_json::json!(["beta"]);
        let duplicate: Snapshot = parse_canonical(&canonical(&value), "snapshot").unwrap();
        assert!(validate_snapshot(&duplicate).is_err());

        value["keys"][1]["successor_key_id"] = serde_json::json!("release-stable-v1");
        value["keys"][2]["predecessor_key_id"] = serde_json::json!("release-beta-v1");
        for index in [1, 2] {
            let peer = if index == 1 {
                "release-stable-v1"
            } else {
                "release-beta-v1"
            };
            value["keys"][index]["rotation_overlap"] = serde_json::json!({
                "mode": "bounded",
                "with_key_id": peer,
                "valid_from": "2026-07-21T01:00:00Z",
                "valid_until": "2027-07-21T01:00:00Z"
            });
        }
        let exact: Snapshot = parse_canonical(&canonical(&value), "snapshot").unwrap();
        validate_snapshot(&exact).unwrap();
        value["keys"][1]["rotation_overlap"]["valid_until"] =
            serde_json::json!("2027-01-01T00:00:00Z");
        value["keys"][2]["rotation_overlap"]["valid_until"] =
            serde_json::json!("2027-01-01T00:00:00Z");
        let shortened: Snapshot = parse_canonical(&canonical(&value), "snapshot").unwrap();
        assert!(validate_snapshot(&shortened).is_err());
    }

    #[test]
    fn tombstone_lineage_preserves_role_time_and_live_conversion() {
        let old: Snapshot = parse_canonical(SNAPSHOT, "snapshot").unwrap();
        let (new, old_hash) = revoked_snapshot();
        validate_snapshot(&new).unwrap();
        validate_chain(&old, &new, &old_hash).unwrap();

        let mut invalid = new.clone();
        invalid.tombstones[0].successor_key_id = Some("image-ci-v1".into());
        assert!(validate_snapshot(&invalid).is_err());
        assert!(validate_chain(&old, &invalid, &old_hash).is_err());

        let mut unilateral: serde_json::Value = serde_json::from_slice(SNAPSHOT).unwrap();
        unilateral["tombstones"] = serde_json::json!([{
            "key_id": "release-beta-v0",
            "predecessor_key_id": null,
            "reason": "key-compromise",
            "revocation_seq": 1,
            "revoked_at": "2026-07-21T00:30:00Z",
            "role": "release-beta",
            "spki_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "successor_key_id": "release-beta-v1",
            "terminal_status": "revoked"
        }]);
        let unilateral: Snapshot = parse_canonical(&canonical(&unilateral), "snapshot").unwrap();
        assert!(validate_snapshot(&unilateral).is_err());
    }
    #[test]
    fn chain_preserves_reciprocal_lineage_and_overlap_after_peer_revocation() {
        let mut value: serde_json::Value = serde_json::from_slice(SNAPSHOT).unwrap();
        value["keys"][2]["key_id"] = serde_json::json!("release-beta-v2");
        value["keys"][2]["role"] = serde_json::json!("release-beta");
        value["keys"][2]["artifact_types"] =
            serde_json::json!(["beta-publication-receipt", "beta-release-authorization"]);
        value["keys"][2]["rings"] = serde_json::json!(["beta"]);
        value["keys"][1]["successor_key_id"] = serde_json::json!("release-beta-v2");
        value["keys"][2]["predecessor_key_id"] = serde_json::json!("release-beta-v1");
        for (index, peer) in [(1, "release-beta-v2"), (2, "release-beta-v1")] {
            value["keys"][index]["rotation_overlap"] = serde_json::json!({
                "mode": "bounded",
                "with_key_id": peer,
                "valid_from": "2026-07-21T01:00:00Z",
                "valid_until": "2027-07-21T01:00:00Z"
            });
        }
        let old: Snapshot = parse_canonical(&canonical(&value), "snapshot").unwrap();
        validate_snapshot(&old).unwrap();
        let old_bytes = canonical(&serde_json::to_value(&old).unwrap());
        let old_hash = canonical_hash(&old_bytes).unwrap();

        let mut new = old.clone();
        new.delegation_seq = 2;
        new.previous_snapshot_sha256 = Some(old_hash.clone());
        new.issued_at = "2026-08-01T00:45:00Z".into();
        new.valid_from = "2026-08-01T01:00:00Z".into();
        let removed = new.keys.remove(1);
        new.tombstones.push(Tombstone {
            key_id: removed.key_id,
            predecessor_key_id: removed.predecessor_key_id,
            reason: "key-compromise".into(),
            revocation_seq: 2,
            revoked_at: "2026-08-01T00:30:00Z".into(),
            role: removed.role,
            spki_sha256: removed.public_key.spki_sha256,
            successor_key_id: removed.successor_key_id,
            terminal_status: "revoked".into(),
        });
        validate_snapshot(&new).unwrap();
        validate_chain(&old, &new, &old_hash).unwrap();

        let mut cleared = new.clone();
        cleared.keys[1].predecessor_key_id = None;
        cleared.keys[1].rotation_overlap = RotationOverlap {
            mode: "none".into(),
            with_key_id: None,
            valid_from: None,
            valid_until: None,
        };
        assert!(validate_snapshot(&cleared).is_err());

        let generation_two_bytes = canonical(&serde_json::to_value(&new).unwrap());
        let generation_two_hash = canonical_hash(&generation_two_bytes).unwrap();
        let mut generation_three = new.clone();
        generation_three.delegation_seq = 3;
        generation_three.previous_snapshot_sha256 = Some(generation_two_hash.clone());
        generation_three.issued_at = "2026-09-01T00:45:00Z".into();
        generation_three.valid_from = "2026-09-01T01:00:00Z".into();
        let mut successor = generation_three.keys[1].clone();
        successor.key_id = "release-beta-v3".into();
        successor.predecessor_key_id = Some("release-beta-v2".into());
        successor.successor_key_id = None;
        let mut der = P256_SPKI_PREFIX.to_vec();
        der.extend_from_slice(&hex_bytes(
            "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
        ));
        successor.public_key.spki_der_base64 = encode_base64(&der);
        successor.public_key.spki_sha256 = hash_bytes(&der).unwrap();
        successor.rotation_overlap.with_key_id = Some("release-beta-v2".into());
        generation_three.keys[1].successor_key_id = Some(successor.key_id.clone());
        generation_three.keys[1].rotation_overlap.with_key_id = Some(successor.key_id.clone());
        generation_three.keys.push(successor);
        generation_three
            .keys
            .sort_by(|left, right| left.key_id.cmp(&right.key_id));
        validate_snapshot(&generation_three).unwrap();
        validate_chain(&new, &generation_three, &generation_two_hash).unwrap();

        let mut reversed_snapshot = old.clone();
        let reversed_old = reversed_snapshot
            .keys
            .iter()
            .find(|key| key.key_id == "release-beta-v1")
            .unwrap()
            .clone();
        let removed = reversed_snapshot
            .keys
            .iter()
            .find(|key| key.key_id == "release-beta-v2")
            .unwrap()
            .clone();
        reversed_snapshot
            .keys
            .retain(|key| key.key_id != removed.key_id);
        reversed_snapshot.tombstones.push(Tombstone {
            key_id: removed.key_id,
            predecessor_key_id: removed.predecessor_key_id,
            reason: "key-compromise".into(),
            revocation_seq: 2,
            revoked_at: "2026-08-01T00:30:00Z".into(),
            role: removed.role,
            spki_sha256: removed.public_key.spki_sha256,
            successor_key_id: removed.successor_key_id,
            terminal_status: "revoked".into(),
        });
        let mut reversed_next = reversed_old.clone();
        reversed_next.predecessor_key_id = Some("release-beta-v3".into());
        reversed_next.rotation_overlap.with_key_id = Some("release-beta-v3".into());
        let mut reversed_peer = reversed_old.clone();
        reversed_peer.key_id = "release-beta-v3".into();
        reversed_peer.predecessor_key_id = None;
        reversed_peer.successor_key_id = Some(reversed_old.key_id.clone());
        reversed_snapshot.keys.push(reversed_peer);
        assert!(!advances_overlap_after_peer_revocation(
            &reversed_old,
            &reversed_next,
            &reversed_snapshot
        ));
    }

    fn hex_bytes(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }
    #[test]
    fn timestamp_rejects_impossible_dates() {
        assert!(timestamp("2026-07-21T01:02:03Z"));
        assert!(!timestamp("0000-01-01T00:00:00Z"));
        assert!(!timestamp("2026-02-30T01:02:03Z"));
    }
    #[test]
    fn base64_is_canonical() {
        for bytes in [b"a".as_slice(), b"ab", b"abc", P256_SPKI_PREFIX] {
            let value = encode_base64(bytes);
            assert_eq!(decode_base64(&value).unwrap(), bytes);
        }
        assert!(decode_base64("YR==").is_err());
    }

    #[test]
    fn public_key_rejects_off_curve_and_identity_sec1_points() {
        let mut off_curve = P256_SPKI_PREFIX.to_vec();
        off_curve.extend_from_slice(&[0; 64]);
        let key = PublicKey {
            algorithm: "ecdsa-p256-sha256".into(),
            encoding: "spki-der-base64".into(),
            spki_der_base64: encode_base64(&off_curve),
            spki_sha256: hash_bytes(&off_curve).unwrap(),
        };
        assert!(matches!(
            validate_public_key(&key),
            Err(ContractError::Refusal(reason)) if reason.contains("not on P-256")
        ));

        let mut identity = off_curve;
        identity[P256_SPKI_PREFIX.len() - 1] = 0;
        let key = PublicKey {
            algorithm: "ecdsa-p256-sha256".into(),
            encoding: "spki-der-base64".into(),
            spki_der_base64: encode_base64(&identity),
            spki_sha256: hash_bytes(&identity).unwrap(),
        };
        assert!(validate_public_key(&key).is_err());
    }

    #[test]
    fn hashing_failures_remain_typed_internal_errors() {
        let error = classify_hash(Err(InternalError("sha256sum unavailable".into()))).unwrap_err();
        assert!(matches!(error, ContractError::Internal(_)));
        assert!(matches!(
            canonical_hash(b"{}"),
            Err(ContractError::Refusal(_))
        ));
    }

    #[test]
    fn der_rejects_trailing_and_high_s() {
        let ok = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];
        assert!(validate_der_signature(&ok).is_ok());
        let mut trailing = ok.to_vec();
        trailing.push(0);
        assert!(validate_der_signature(&trailing).is_err());
        let mut high_s = vec![0x30, 0x26, 0x02, 0x01, 0x01, 0x02, 0x21, 0x00];
        high_s.extend_from_slice(&[
            0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61,
            0x7e, 0x31, 0x92, 0xa9,
        ]);
        assert!(validate_der_signature(&high_s).is_err());

        let order = [
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2,
            0xfc, 0x63, 0x25, 0x51,
        ];
        let mut bad_r = vec![0x30, 0x26, 0x02, 0x21, 0x00];
        bad_r.extend_from_slice(&order);
        bad_r.extend_from_slice(&[0x02, 0x01, 0x01]);
        assert!(validate_der_signature(&bad_r).is_err());

        let mut bad_s = vec![0x30, 0x26, 0x02, 0x01, 0x01, 0x02, 0x21, 0x00];
        bad_s.extend_from_slice(&order);
        assert!(validate_der_signature(&bad_s).is_err());
    }
}
