//! Closed trusted-time v2 assertion contract.
//!
//! Transport stays outside this verifier. The assertion is accepted only
//! under the distinct root-delegated `trusted-time` role and must echo one
//! exact appliance-generated challenge plus the release and TPM state it
//! authorizes.

use serde::{Deserialize, Serialize};

use crate::delegated::contract::{
    canonical_hash, ident, parse_canonical, public_key_pem, safe_uint, sha256, signature_profile,
    timestamp, ContractError, Snapshot,
};
use crate::delegated::{verify_signature, AuthenticatedSnapshot};
use crate::runner;
use crate::state::FileStateStore;

const TIME_DOMAIN: &[u8] = b"neural-ice:ota:trusted-time:v2\0";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TrustedTimeAssertion {
    pub(crate) assertion_seq: u64,
    pub(crate) delegation_seq: u64,
    pub(crate) delegation_snapshot_sha256: String,
    pub(crate) device_fingerprint: String,
    pub(crate) hardware_target: String,
    pub(crate) issuance_id: String,
    pub(crate) issued_at: String,
    pub(crate) issuer: String,
    pub(crate) key_id: String,
    pub(crate) nonce: String,
    pub(crate) release_authorization_sha256: String,
    pub(crate) ring: String,
    pub(crate) schema: String,
    pub(crate) signature_algorithm: String,
    pub(crate) signature_encoding: String,
    pub(crate) signing_role: String,
    pub(crate) state_nv_anchor: String,
    pub(crate) tpm_clock: u64,
    pub(crate) tpm_reset_count: u32,
    pub(crate) tpm_restart_count: u32,
    pub(crate) tpm_safe: bool,
    pub(crate) trusted_time: String,
    pub(crate) valid_until: String,
}

pub(crate) struct ExpectedTrustedTime<'a> {
    pub(crate) delegation_snapshot_sha256: &'a str,
    pub(crate) device_fingerprint: &'a str,
    pub(crate) hardware_target: &'a str,
    pub(crate) nonce: &'a str,
    pub(crate) release_authorization_sha256: &'a str,
    pub(crate) ring: &'a str,
    pub(crate) state_nv_anchor: &'a str,
    pub(crate) tpm_clock: u64,
    pub(crate) tpm_reset_count: u32,
    pub(crate) tpm_restart_count: u32,
    pub(crate) tpm_safe: bool,
    pub(crate) consumption_tpm_clock: u64,
    pub(crate) consumption_tpm_reset_count: u32,
    pub(crate) consumption_tpm_restart_count: u32,
    pub(crate) consumption_tpm_safe: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VerifiedTrustedTime {
    pub(crate) assertion_seq: u64,
    pub(crate) assertion_sha256: String,
    pub(crate) delegation_seq: u64,
    pub(crate) device_fingerprint: String,
    pub(crate) key_id: String,
    pub(crate) nonce_sha256: String,
    pub(crate) signature_sha256: String,
    pub(crate) trusted_time: String,
}

pub(crate) fn verify(
    authenticated_snapshot: &AuthenticatedSnapshot,
    assertion_bytes: &[u8],
    signature_bytes: &[u8],
    expected: &ExpectedTrustedTime<'_>,
    scratch: &FileStateStore,
) -> Result<VerifiedTrustedTime, ContractError> {
    let snapshot = authenticated_snapshot.snapshot();
    let snapshot_sha256 = authenticated_snapshot.canonical_sha256();
    let assertion: TrustedTimeAssertion =
        parse_canonical(assertion_bytes, "trusted-time assertion")?;
    validate(&assertion, snapshot, snapshot_sha256, expected)?;
    let key = authority(snapshot, &assertion, expected)?;
    let key = public_key_pem(&key.public_key)?;
    match verify_signature(&key, TIME_DOMAIN, assertion_bytes, signature_bytes, scratch)
        .map_err(ContractError::Internal)?
    {
        Ok(()) => {}
        Err(reason) => return Err(reason.into()),
    }
    Ok(VerifiedTrustedTime {
        assertion_seq: assertion.assertion_seq,
        assertion_sha256: canonical_hash(assertion_bytes)?,
        delegation_seq: assertion.delegation_seq,
        device_fingerprint: assertion.device_fingerprint,
        key_id: assertion.key_id,
        nonce_sha256: hash(assertion.nonce.as_bytes())?,
        signature_sha256: hash(signature_bytes)?,
        trusted_time: assertion.trusted_time,
    })
}

fn authority<'a>(
    snapshot: &'a Snapshot,
    assertion: &TrustedTimeAssertion,
    expected: &ExpectedTrustedTime<'_>,
) -> Result<&'a crate::delegated::contract::DelegatedKey, ContractError> {
    let keys: Vec<_> = snapshot
        .keys
        .iter()
        .filter(|key| {
            key.key_id == assertion.key_id
                && key.role == "trusted-time"
                && key.artifact_types == ["trusted-time-assertion"]
                && key
                    .hardware_targets
                    .iter()
                    .any(|value| value == expected.hardware_target)
                && key.rings.iter().any(|value| value == expected.ring)
                && key.authorizes_at(&assertion.issued_at)
                && key.authorizes_at(&assertion.trusted_time)
        })
        .collect();
    if keys.len() != 1 {
        return Err("trusted-time assertion has no unique live scoped authority".into());
    }
    Ok(keys[0])
}

fn validate(
    value: &TrustedTimeAssertion,
    snapshot: &Snapshot,
    snapshot_sha256: &str,
    expected: &ExpectedTrustedTime<'_>,
) -> Result<(), ContractError> {
    if value.schema != "neural-ice-ota-trusted-time-v2"
        || value.issuer != "licensing.neural-ice.ch"
        || value.signing_role != "trusted-time"
        || !signature_profile(&value.signature_algorithm, &value.signature_encoding)
        || !safe_uint(value.assertion_seq)
        || !safe_uint(value.tpm_clock)
        || !safe_uint(expected.consumption_tpm_clock)
        || !ident(&value.issuance_id)
        || !ident(&value.key_id)
        || !is_lower_hex_32(&value.nonce)
        || !sha256(&value.device_fingerprint)
        || !sha256(&value.state_nv_anchor)
        || !value.tpm_safe
        || !expected.tpm_safe
        || value.tpm_safe != expected.tpm_safe
        || !expected.consumption_tpm_safe
        || value.nonce != expected.nonce
        || value.device_fingerprint != expected.device_fingerprint
        || value.state_nv_anchor != expected.state_nv_anchor
        || value.tpm_clock != expected.tpm_clock
        || value.tpm_reset_count != expected.tpm_reset_count
        || value.tpm_restart_count != expected.tpm_restart_count
        || expected.consumption_tpm_reset_count != expected.tpm_reset_count
        || expected.consumption_tpm_restart_count != expected.tpm_restart_count
        || value.hardware_target != expected.hardware_target
        || value.ring != expected.ring
        || !matches!(expected.ring, "beta" | "stable")
        || value.release_authorization_sha256 != expected.release_authorization_sha256
        || !sha256(&value.release_authorization_sha256)
        || value.delegation_snapshot_sha256 != expected.delegation_snapshot_sha256
        || value.delegation_snapshot_sha256 != snapshot_sha256
        || !sha256(&value.delegation_snapshot_sha256)
        || value.delegation_seq != snapshot.delegation_seq
        || !timestamp(&value.issued_at)
        || !timestamp(&value.trusted_time)
        || !timestamp(&value.valid_until)
        || value.issued_at > value.trusted_time
        || value.trusted_time >= value.valid_until
        || !consumption_precedes_expiry(value, expected)
        || !assertion_lifetime_seconds(&value.issued_at, &value.valid_until)
            .is_some_and(|seconds| seconds <= 600)
        || value.issued_at < snapshot.valid_from
        || value.issued_at >= snapshot.valid_until
        || value.trusted_time < snapshot.valid_from
        || value.trusted_time >= snapshot.valid_until
    {
        return Err("trusted-time v2 assertion scope, challenge or time is invalid".into());
    }
    Ok(())
}

fn consumption_precedes_expiry(
    value: &TrustedTimeAssertion,
    expected: &ExpectedTrustedTime<'_>,
) -> bool {
    let Some(elapsed_ms) = expected
        .consumption_tpm_clock
        .checked_sub(expected.tpm_clock)
    else {
        return false;
    };
    let Some(elapsed_seconds) = elapsed_ms.checked_add(999).map(|value| value / 1_000) else {
        return false;
    };
    let Some(consumption_time) =
        utc_seconds(&value.trusted_time).and_then(|value| value.checked_add(elapsed_seconds))
    else {
        return false;
    };
    utc_seconds(&value.valid_until).is_some_and(|valid_until| consumption_time < valid_until)
}

fn is_lower_hex_32(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn assertion_lifetime_seconds(issued_at: &str, valid_until: &str) -> Option<u64> {
    utc_seconds(valid_until)?.checked_sub(utc_seconds(issued_at)?)
}

pub(crate) fn utc_seconds(value: &str) -> Option<u64> {
    if value.len() != 20 || !timestamp(value) {
        return None;
    }
    let number = |range: std::ops::Range<usize>| value.get(range)?.parse::<u64>().ok();
    let year = number(0..4)?;
    let month = number(5..7)?;
    let day = number(8..10)?;
    let hour = number(11..13)?;
    let minute = number(14..16)?;
    let second = number(17..19)?;
    if year < 1970 || !(1..=12).contains(&month) || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let leap = |year: u64| {
        year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
    };
    let month_days = [31_u64, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let max_day = month_days[(month - 1) as usize] + u64::from(month == 2 && leap(year));
    if day == 0 || day > max_day {
        return None;
    }
    let years = (1970..year)
        .map(|value| 365 + u64::from(leap(value)))
        .sum::<u64>();
    let months =
        month_days[..(month - 1) as usize].iter().sum::<u64>() + u64::from(month > 2 && leap(year));
    Some((((years + months + day - 1) * 24 + hour) * 60 + minute) * 60 + second)
}

fn hash(bytes: &[u8]) -> Result<String, ContractError> {
    runner::sha256_bytes(bytes).map_err(ContractError::Internal)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delegated::contract::{canonical_hash, parse_canonical};
    use std::path::PathBuf;

    const SNAPSHOT: &[u8] =
        include_bytes!("../tests/fixtures/delegated-v1/delegation-snapshot.json");

    fn assertion() -> TrustedTimeAssertion {
        TrustedTimeAssertion {
            assertion_seq: 1,
            delegation_seq: 1,
            delegation_snapshot_sha256: canonical_hash(SNAPSHOT).unwrap(),
            device_fingerprint: "d".repeat(64),
            hardware_target: "nvidia-gb10-arm64".into(),
            issuance_id: "time-0001".into(),
            issued_at: "2026-07-22T00:00:00Z".into(),
            issuer: "licensing.neural-ice.ch".into(),
            key_id: "trusted-time-v1".into(),
            nonce: "a".repeat(64),
            release_authorization_sha256: "b".repeat(64),
            ring: "beta".into(),
            schema: "neural-ice-ota-trusted-time-v2".into(),
            signature_algorithm: "ecdsa-p256-sha256".into(),
            signature_encoding: "asn1-der".into(),
            signing_role: "trusted-time".into(),
            state_nv_anchor: "c".repeat(64),
            tpm_clock: 42,
            tpm_reset_count: 3,
            tpm_restart_count: 4,
            tpm_safe: true,
            trusted_time: "2026-07-22T00:00:01Z".into(),
            valid_until: "2026-07-22T00:05:00Z".into(),
        }
    }

    fn expected(value: &TrustedTimeAssertion) -> ExpectedTrustedTime<'_> {
        ExpectedTrustedTime {
            delegation_snapshot_sha256: &value.delegation_snapshot_sha256,
            device_fingerprint: &value.device_fingerprint,
            hardware_target: &value.hardware_target,
            nonce: &value.nonce,
            release_authorization_sha256: &value.release_authorization_sha256,
            ring: &value.ring,
            state_nv_anchor: &value.state_nv_anchor,
            tpm_clock: value.tpm_clock,
            tpm_reset_count: value.tpm_reset_count,
            tpm_restart_count: value.tpm_restart_count,
            tpm_safe: value.tpm_safe,
            consumption_tpm_clock: value.tpm_clock,
            consumption_tpm_reset_count: value.tpm_reset_count,
            consumption_tpm_restart_count: value.tpm_restart_count,
            consumption_tpm_safe: value.tpm_safe,
        }
    }

    #[test]
    fn v2_binds_nonce_device_release_ring_snapshot_and_complete_tpm_state() {
        let snapshot: Snapshot = parse_canonical(SNAPSHOT, "snapshot").unwrap();
        let mut value = assertion();
        let snapshot_sha256 = canonical_hash(SNAPSHOT).unwrap();
        assert!(validate(&value, &snapshot, &snapshot_sha256, &expected(&value)).is_ok());

        for field in [
            "nonce", "device", "release", "ring", "snapshot", "anchor", "clock",
        ] {
            let baseline = assertion();
            value = baseline.clone();
            match field {
                "nonce" => value.nonce = "f".repeat(64),
                "device" => value.device_fingerprint = "f".repeat(64),
                "release" => value.release_authorization_sha256 = "f".repeat(64),
                "ring" => value.ring = "stable".into(),
                "snapshot" => value.delegation_snapshot_sha256 = "f".repeat(64),
                "anchor" => value.state_nv_anchor = "f".repeat(64),
                "clock" => value.tpm_clock += 1,
                _ => unreachable!(),
            }
            assert!(
                validate(&value, &snapshot, &snapshot_sha256, &expected(&baseline)).is_err(),
                "{field}"
            );
        }
    }

    #[test]
    fn v2_refuses_long_lived_or_unsafe_assertions() {
        let snapshot: Snapshot = parse_canonical(SNAPSHOT, "snapshot").unwrap();
        let baseline = assertion();
        let mut value = baseline.clone();
        value.valid_until = "2026-07-22T00:10:01Z".into();
        let snapshot_sha256 = canonical_hash(SNAPSHOT).unwrap();
        assert!(validate(&value, &snapshot, &snapshot_sha256, &expected(&baseline)).is_err());
        value = baseline.clone();
        value.tpm_safe = false;
        assert!(validate(&value, &snapshot, &snapshot_sha256, &expected(&baseline)).is_err());
        value = baseline.clone();
        value.nonce = "A".repeat(64);
        assert!(validate(&value, &snapshot, &snapshot_sha256, &expected(&baseline)).is_err());
    }

    #[test]
    fn v2_consumption_uses_the_live_safe_monotonic_tpm_tuple() {
        let snapshot: Snapshot = parse_canonical(SNAPSHOT, "snapshot").unwrap();
        let snapshot_sha256 = canonical_hash(SNAPSHOT).unwrap();
        let value = assertion();

        let mut observed = expected(&value);
        observed.tpm_safe = false;
        assert!(validate(&value, &snapshot, &snapshot_sha256, &observed).is_err());

        let mut observed = expected(&value);
        observed.consumption_tpm_safe = false;
        assert!(validate(&value, &snapshot, &snapshot_sha256, &observed).is_err());

        let mut observed = expected(&value);
        observed.consumption_tpm_reset_count += 1;
        assert!(validate(&value, &snapshot, &snapshot_sha256, &observed).is_err());

        let mut observed = expected(&value);
        observed.consumption_tpm_restart_count += 1;
        assert!(validate(&value, &snapshot, &snapshot_sha256, &observed).is_err());

        let mut observed = expected(&value);
        observed.consumption_tpm_clock -= 1;
        assert!(validate(&value, &snapshot, &snapshot_sha256, &observed).is_err());

        let mut observed = expected(&value);
        observed.consumption_tpm_clock += 298_000;
        assert!(validate(&value, &snapshot, &snapshot_sha256, &observed).is_ok());
        observed.consumption_tpm_clock += 1;
        assert!(validate(&value, &snapshot, &snapshot_sha256, &observed).is_err());
    }

    #[test]
    fn v2_binds_the_actual_snapshot_and_bounds_a_retiring_authority() {
        let mut snapshot: Snapshot = parse_canonical(SNAPSHOT, "snapshot").unwrap();
        let value = assertion();
        let baseline = expected(&value);
        assert!(validate(&value, &snapshot, &"f".repeat(64), &baseline).is_err());

        let mut encoded = serde_json::to_value(&snapshot).unwrap();
        {
            let key = encoded["keys"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|key| key["key_id"] == value.key_id)
                .unwrap();
            key["status"] = "retiring".into();
        }
        snapshot = serde_json::from_value(encoded.clone()).unwrap();
        assert!(authority(&snapshot, &value, &baseline).is_err());

        {
            let key = encoded["keys"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|key| key["key_id"] == value.key_id)
                .unwrap();
            key["rotation_overlap"] = serde_json::json!({
                "mode": "bounded",
                "valid_from": "2026-07-22T00:00:00Z",
                "valid_until": "2026-07-22T00:02:00Z",
                "with_key_id": "trusted-time-v2"
            });
        }
        snapshot = serde_json::from_value(encoded.clone()).unwrap();
        assert!(authority(&snapshot, &value, &baseline).is_ok());

        let mut outside = value.clone();
        outside.trusted_time = "2026-07-22T00:02:00Z".into();
        assert!(authority(&snapshot, &outside, &expected(&outside)).is_err());

        let key = encoded["keys"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|key| key["key_id"] == value.key_id)
            .unwrap();
        key["status"] = "revoked".into();
        snapshot = serde_json::from_value(encoded).unwrap();
        assert!(authority(&snapshot, &value, &baseline).is_err());
    }

    #[test]
    fn contract_is_canonical_and_calendar_exact() {
        let mut bytes = serde_json::to_vec(&assertion()).unwrap();
        bytes.push(b'\n');
        assert!(parse_canonical::<TrustedTimeAssertion>(&bytes, "assertion").is_ok());
        bytes.extend_from_slice(b" \n");
        assert!(parse_canonical::<TrustedTimeAssertion>(&bytes, "assertion").is_err());
        assert_eq!(utc_seconds("2024-02-29T00:00:00Z"), Some(1_709_164_800));
        assert_eq!(utc_seconds("2023-02-29T00:00:00Z"), None);
    }

    #[test]
    fn scratch_type_remains_local_file_backed() {
        let scratch = FileStateStore {
            path: PathBuf::from("/tmp/state.json"),
        };
        assert_eq!(scratch.path, PathBuf::from("/tmp/state.json"));
    }
}
