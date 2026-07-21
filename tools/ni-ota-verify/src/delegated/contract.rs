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
    let known = |candidate: &str| {
        snapshot.keys.iter().any(|key| key.key_id == candidate)
            || snapshot
                .tombstones
                .iter()
                .any(|tombstone| tombstone.key_id == candidate)
    };
    for key in &snapshot.keys {
        for reference in [
            key.predecessor_key_id.as_deref(),
            key.successor_key_id.as_deref(),
            key.rotation_overlap.with_key_id.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            if reference == key.key_id || !known(reference) {
                return Err(
                    "delegated rotation reference is unresolved or self-referential".into(),
                );
            }
        }
        if key.rotation_overlap.mode == "bounded" {
            let from = key
                .rotation_overlap
                .valid_from
                .as_deref()
                .unwrap_or_default();
            let until = key
                .rotation_overlap
                .valid_until
                .as_deref()
                .unwrap_or_default();
            let peer = key
                .rotation_overlap
                .with_key_id
                .as_deref()
                .unwrap_or_default();
            if from < key.valid_from.as_str()
                || until > key.valid_until.as_str()
                || !snapshot.keys.iter().any(|candidate| {
                    candidate.key_id == peer
                        && candidate.role == key.role
                        && ((key.predecessor_key_id.as_deref() == Some(peer)
                            && candidate.successor_key_id.as_deref() == Some(key.key_id.as_str()))
                            || (key.successor_key_id.as_deref() == Some(peer)
                                && candidate.predecessor_key_id.as_deref()
                                    == Some(key.key_id.as_str())))
                        && candidate.rotation_overlap.mode == "bounded"
                        && candidate.rotation_overlap.with_key_id.as_deref()
                            == Some(key.key_id.as_str())
                        && candidate.rotation_overlap.valid_from.as_deref() == Some(from)
                        && candidate.rotation_overlap.valid_until.as_deref() == Some(until)
                        && candidate.valid_from.as_str() <= from
                        && until <= candidate.valid_until.as_str()
                })
            {
                return Err("bounded overlap is not contained by both live key windows".into());
            }
        } else if [
            key.predecessor_key_id.as_deref(),
            key.successor_key_id.as_deref(),
        ]
        .into_iter()
        .flatten()
        .any(|reference| {
            snapshot
                .keys
                .iter()
                .any(|candidate| candidate.key_id == reference)
        }) {
            return Err("live rotation pair lacks mutual bounded overlap".into());
        }
    }
    for tombstone in &snapshot.tombstones {
        for reference in [
            tombstone.predecessor_key_id.as_deref(),
            tombstone.successor_key_id.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            if !ident(reference) || reference == tombstone.key_id || !known(reference) {
                return Err("tombstone reference is unresolved or self-referential".into());
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
            {
                return Err("revocation tombstone does not bind removed key".into());
            }
        }
    }
    Ok(())
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
    m > 0 && m <= 12 && d > 0 && d <= days[m as usize] && h < 24 && mi < 60 && s < 60
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
    fn timestamp_rejects_impossible_dates() {
        assert!(timestamp("2026-07-21T01:02:03Z"));
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
