//! Closed, local-only licensing bootstrap and recovery-ack contracts.
//!
//! The caller supplies already-local bytes plus the exact pending TPM-backed
//! challenge and immutable baseline. Verification never performs network I/O,
//! persists authority or exposes a public capability. The later atomic state
//! transaction is solely responsible for consuming the nonce and committing
//! the verified proof with the snapshot, release and trusted time.

use serde::{Deserialize, Serialize};

use crate::delegated::contract::{
    canonical_hash, ident, parse_canonical, public_key_pem, safe_uint, sha256, signature_profile,
    target, timestamp, validate_der_signature, validate_snapshot, ContractError, PublicKey,
    Snapshot,
};
use crate::delegated::verify_signature;
use crate::state::FileStateStore;
use crate::trusted_time::utc_seconds;

const BOOTSTRAP_DOMAIN: &[u8] = b"neural-ice:ota:licensing-bootstrap:v1\0";
const RECOVERY_ACK_DOMAIN: &[u8] = b"neural-ice:ota:licensing-recovery-ack:v1\0";
const MAX_TPM_ELAPSED_MS: u64 = 600_000;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BaselineIdentity {
    pub(crate) baseline_manifest_sha256: String,
    pub(crate) bootstrap_delegation_seq: u64,
    pub(crate) bootstrap_snapshot_sha256: String,
    pub(crate) compatibility_version: u64,
    pub(crate) hardware_target: String,
    pub(crate) os_image_manifest_digest: String,
    pub(crate) ota_root_spki_sha256: String,
    pub(crate) ota_root_version: u64,
    pub(crate) release_variant: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeviceRootIdentity {
    pub(crate) spki_sha256: String,
    pub(crate) tpm_name: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AuthoritativeState {
    pub(crate) baseline: BaselineIdentity,
    pub(crate) bundle_seq: u64,
    pub(crate) delegation_seq: u64,
    pub(crate) delegation_snapshot_sha256: String,
    pub(crate) last_trusted_time_assertion_sha256: String,
    pub(crate) recovery_seq: u64,
    pub(crate) recovery_sha256: Option<String>,
    pub(crate) root_spki_sha256: String,
    pub(crate) root_transition_sha256: Option<String>,
    pub(crate) root_version: u64,
    pub(crate) trusted_time: String,
    pub(crate) trusted_time_recovery_floor: String,
    pub(crate) trusted_time_seq: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LicensingBootstrapAuthorization {
    active_product: String,
    authoritative_state: Option<AuthoritativeState>,
    baseline: BaselineIdentity,
    bootstrap_seq: u64,
    device_root: DeviceRootIdentity,
    device_serial: String,
    entitlement_policy_revision: String,
    issuance_id: String,
    issued_at: String,
    key_id: String,
    licence_record_id: String,
    licensing_bootstrap_nonce: String,
    previous_authorization_sha256: Option<String>,
    previous_device_root: Option<DeviceRootIdentity>,
    reason: String,
    schema: String,
    signature_algorithm: String,
    signature_encoding: String,
    signing_role: String,
    tpm_clock: u64,
    tpm_reset_count: u32,
    tpm_restart_count: u32,
    tpm_safe: bool,
    valid_until: String,
}

#[derive(Clone, Debug)]
pub(crate) struct PendingChallenge<'a> {
    pub(crate) nonce: &'a str,
    pub(crate) tpm_clock: u64,
    pub(crate) tpm_reset_count: u32,
    pub(crate) tpm_restart_count: u32,
}

#[derive(Clone, Debug)]
pub(crate) struct CurrentTpmState {
    pub(crate) tpm_clock: u64,
    pub(crate) tpm_reset_count: u32,
    pub(crate) tpm_restart_count: u32,
    pub(crate) tpm_safe: bool,
}

pub(crate) struct ExpectedBootstrap<'a> {
    pub(crate) active_product: &'a str,
    pub(crate) authoritative_state: Option<&'a AuthoritativeState>,
    pub(crate) baseline: &'a BaselineIdentity,
    pub(crate) bootstrap_seq: u64,
    pub(crate) current_tpm: CurrentTpmState,
    pub(crate) device_root: &'a DeviceRootIdentity,
    pub(crate) device_serial: &'a str,
    pub(crate) entitlement_policy_revision: &'a str,
    pub(crate) licence_record_id: &'a str,
    pub(crate) pending: PendingChallenge<'a>,
    pub(crate) previous_authorization_sha256: Option<&'a str>,
    pub(crate) previous_device_root: Option<&'a DeviceRootIdentity>,
    pub(crate) reason: &'a str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VerifiedBootstrap {
    pub(crate) authorization_sha256: String,
    pub(crate) bootstrap_seq: u64,
    pub(crate) key_id: String,
    pub(crate) licence_record_id: String,
    pub(crate) reason: String,
}

pub(crate) fn verify_bootstrap(
    snapshot: &Snapshot,
    snapshot_bytes: &[u8],
    authorization_bytes: &[u8],
    signature_bytes: &[u8],
    expected: &ExpectedBootstrap<'_>,
    scratch: &FileStateStore,
) -> Result<VerifiedBootstrap, ContractError> {
    verify_bootstrap_with(
        snapshot,
        snapshot_bytes,
        authorization_bytes,
        signature_bytes,
        expected,
        |key, domain, payload, signature| match verify_signature(
            key, domain, payload, signature, scratch,
        )
        .map_err(ContractError::Internal)?
        {
            Ok(()) => Ok(()),
            Err(reason) => Err(reason.into()),
        },
    )
}

fn verify_bootstrap_with<F>(
    snapshot: &Snapshot,
    snapshot_bytes: &[u8],
    authorization_bytes: &[u8],
    signature_bytes: &[u8],
    expected: &ExpectedBootstrap<'_>,
    signature_verifier: F,
) -> Result<VerifiedBootstrap, ContractError>
where
    F: FnOnce(&[u8], &[u8], &[u8], &[u8]) -> Result<(), ContractError>,
{
    let parsed_snapshot: Snapshot = parse_canonical(snapshot_bytes, "delegation snapshot")?;
    if parsed_snapshot != *snapshot {
        return Err("delegation snapshot bytes differ from parsed authority".into());
    }
    validate_snapshot(snapshot)?;
    let authorization: LicensingBootstrapAuthorization =
        parse_canonical(authorization_bytes, "licensing-bootstrap authorization")?;
    validate_bootstrap(
        &authorization,
        snapshot,
        &canonical_hash(snapshot_bytes)?,
        expected,
    )?;
    validate_der_signature(signature_bytes)?;
    let key = unique_snapshot_key(
        snapshot,
        &authorization.key_id,
        &authorization.issued_at,
        &authorization.baseline.hardware_target,
    )?;
    let public_key = public_key_pem(&key.public_key)?;
    signature_verifier(
        &public_key,
        BOOTSTRAP_DOMAIN,
        authorization_bytes,
        signature_bytes,
    )?;
    Ok(VerifiedBootstrap {
        authorization_sha256: canonical_hash(authorization_bytes)?,
        bootstrap_seq: authorization.bootstrap_seq,
        key_id: authorization.key_id,
        licence_record_id: authorization.licence_record_id,
        reason: authorization.reason,
    })
}

fn validate_bootstrap(
    value: &LicensingBootstrapAuthorization,
    snapshot: &Snapshot,
    snapshot_sha256: &str,
    expected: &ExpectedBootstrap<'_>,
) -> Result<(), ContractError> {
    if value.schema != "ota-licensing-bootstrap-v1"
        || value.signing_role != "licensing-bootstrap"
        || !signature_profile(&value.signature_algorithm, &value.signature_encoding)
        || !ident(&value.key_id)
        || !ident(&value.issuance_id)
        || !sha256(&value.licence_record_id)
        || !ident(&value.active_product)
        || !ident(&value.entitlement_policy_revision)
        || value.device_serial.is_empty()
        || value.device_serial.len() > 127
        || !is_nonce(&value.licensing_bootstrap_nonce)
        || !valid_device_root(&value.device_root)
        || !valid_baseline(&value.baseline)
        || !safe_uint(value.bootstrap_seq)
        || !timestamp(&value.issued_at)
        || !timestamp(&value.valid_until)
        || value.issued_at >= value.valid_until
        || lifetime_seconds(&value.issued_at, &value.valid_until).is_none_or(|value| value > 600)
        || !value.tpm_safe
        || value.baseline.bootstrap_delegation_seq != snapshot.delegation_seq
        || value.baseline.bootstrap_snapshot_sha256 != snapshot_sha256
        || value.baseline.ota_root_version != snapshot.root_version()
        || value.baseline.ota_root_spki_sha256 != snapshot.root_spki_sha256()
        || value.licence_record_id != expected.licence_record_id
        || value.active_product != expected.active_product
        || value.entitlement_policy_revision != expected.entitlement_policy_revision
        || value.device_serial != expected.device_serial
        || value.device_root != *expected.device_root
        || value.baseline != *expected.baseline
        || value.bootstrap_seq != expected.bootstrap_seq
        || value.previous_authorization_sha256.as_deref() != expected.previous_authorization_sha256
        || value.licensing_bootstrap_nonce != expected.pending.nonce
        || value.tpm_clock != expected.pending.tpm_clock
        || value.tpm_reset_count != expected.pending.tpm_reset_count
        || value.tpm_restart_count != expected.pending.tpm_restart_count
        || value.tpm_reset_count != expected.current_tpm.tpm_reset_count
        || value.tpm_restart_count != expected.current_tpm.tpm_restart_count
        || !expected.current_tpm.tpm_safe
        || expected.current_tpm.tpm_clock < value.tpm_clock
        || expected.current_tpm.tpm_clock - value.tpm_clock > MAX_TPM_ELAPSED_MS
    {
        return Err("licensing-bootstrap scope, challenge, chain or time is invalid".into());
    }
    match value.reason.as_str() {
        "initial_activation"
            if value.bootstrap_seq == 1
                && value.previous_authorization_sha256.is_none()
                && value.previous_device_root.is_none()
                && value.authoritative_state.is_none()
                && expected.reason == "initial_activation"
                && expected.previous_device_root.is_none()
                && expected.authoritative_state.is_none() => {}
        "state_loss_recovery"
            if value.bootstrap_seq > 1
                && value
                    .previous_authorization_sha256
                    .as_deref()
                    .is_some_and(sha256)
                && value
                    .previous_device_root
                    .as_ref()
                    .is_some_and(valid_device_root)
                && value.previous_device_root.as_ref() != Some(&value.device_root)
                && value
                    .authoritative_state
                    .as_ref()
                    .is_some_and(valid_authoritative_state)
                && expected.reason == "state_loss_recovery"
                && value.previous_device_root.as_ref() == expected.previous_device_root
                && value.authoritative_state.as_ref() == expected.authoritative_state => {}
        _ => return Err("licensing-bootstrap reason or recovery state is invalid".into()),
    }
    Ok(())
}

fn unique_snapshot_key<'a>(
    snapshot: &'a Snapshot,
    key_id: &str,
    issued_at: &str,
    hardware_target: &str,
) -> Result<&'a crate::delegated::contract::DelegatedKey, ContractError> {
    let keys: Vec<_> = snapshot
        .keys
        .iter()
        .filter(|key| {
            key.key_id == key_id
                && key.role == "licensing-bootstrap"
                && key.status == "active"
                && key.artifact_types
                    == [
                        "ota-licensing-bootstrap-v1",
                        "ota-licensing-recovery-ack-v1",
                    ]
                && key.rings == ["beta", "stable"]
                && key
                    .hardware_targets
                    .iter()
                    .any(|value| value == hardware_target)
                && key.valid_from.as_str() <= issued_at
                && issued_at < key.valid_until.as_str()
        })
        .collect();
    match keys.as_slice() {
        [key] => Ok(key),
        _ => Err("licensing-bootstrap proof has no unique active scoped authority".into()),
    }
}

fn valid_baseline(value: &BaselineIdentity) -> bool {
    value
        .os_image_manifest_digest
        .strip_prefix("sha256:")
        .is_some_and(sha256)
        && sha256(&value.baseline_manifest_sha256)
        && matches!(value.release_variant.as_str(), "debug" | "prod")
        && target(&value.hardware_target)
        && safe_uint(value.compatibility_version)
        && safe_uint(value.ota_root_version)
        && sha256(&value.ota_root_spki_sha256)
        && safe_uint(value.bootstrap_delegation_seq)
        && sha256(&value.bootstrap_snapshot_sha256)
}

fn valid_device_root(value: &DeviceRootIdentity) -> bool {
    value.tpm_name.len() == 68
        && value.tpm_name.starts_with("000b")
        && value
            .tpm_name
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        && sha256(&value.spki_sha256)
}

fn valid_authoritative_state(value: &AuthoritativeState) -> bool {
    valid_baseline(&value.baseline)
        && safe_uint(value.root_version)
        && sha256(&value.root_spki_sha256)
        && optional_hash_for_sequence(value.root_version - 1, &value.root_transition_sha256)
        && safe_uint(value.delegation_seq)
        && sha256(&value.delegation_snapshot_sha256)
        && safe_floor(value.bundle_seq)
        && safe_floor(value.trusted_time_seq)
        && timestamp(&value.trusted_time)
        && timestamp(&value.trusted_time_recovery_floor)
        && value.trusted_time < value.trusted_time_recovery_floor
        && sha256(&value.last_trusted_time_assertion_sha256)
        && safe_floor(value.recovery_seq)
        && optional_hash_for_sequence(value.recovery_seq, &value.recovery_sha256)
        && value.root_version >= value.baseline.ota_root_version
        && (value.root_version != value.baseline.ota_root_version
            || (value.root_spki_sha256 == value.baseline.ota_root_spki_sha256
                && value.root_transition_sha256.is_none()))
        && value.delegation_seq >= value.baseline.bootstrap_delegation_seq
        && (value.delegation_seq != value.baseline.bootstrap_delegation_seq
            || value.delegation_snapshot_sha256 == value.baseline.bootstrap_snapshot_sha256)
}

fn optional_hash_for_sequence(sequence: u64, value: &Option<String>) -> bool {
    if sequence == 0 {
        value.is_none()
    } else {
        value.as_deref().is_some_and(sha256)
    }
}

fn safe_floor(value: u64) -> bool {
    value <= MAX_SAFE_INTEGER
}

fn is_nonce(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn lifetime_seconds(issued_at: &str, valid_until: &str) -> Option<u64> {
    utc_seconds(valid_until)?.checked_sub(utc_seconds(issued_at)?)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct LicensingRecoveryAck {
    device_root: DeviceRootIdentity,
    device_serial: String,
    issuance_id: String,
    issued_at: String,
    key_id: String,
    licence_record_id: String,
    recovery_nonce: String,
    resulting_state: AuthoritativeState,
    root_recovery_sha256: String,
    schema: String,
    signature_algorithm: String,
    signature_encoding: String,
    signing_role: String,
    tpm_clock: u64,
    tpm_reset_count: u32,
    tpm_restart_count: u32,
    tpm_safe: bool,
    valid_until: String,
}

pub(crate) struct ExpectedRecoveryAck<'a> {
    pub(crate) authorized_key: &'a PublicKey,
    pub(crate) authorized_key_id: &'a str,
    pub(crate) current_tpm: CurrentTpmState,
    pub(crate) device_root: &'a DeviceRootIdentity,
    pub(crate) device_serial: &'a str,
    pub(crate) licence_record_id: &'a str,
    pub(crate) pending: PendingChallenge<'a>,
    pub(crate) recovery_nonce: &'a str,
    pub(crate) resulting_state: &'a AuthoritativeState,
    pub(crate) root_recovery_sha256: &'a str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VerifiedRecoveryAck {
    pub(crate) acknowledgement_sha256: String,
    pub(crate) key_id: String,
    pub(crate) root_recovery_sha256: String,
}

pub(crate) fn verify_recovery_ack(
    acknowledgement_bytes: &[u8],
    signature_bytes: &[u8],
    expected: &ExpectedRecoveryAck<'_>,
    scratch: &FileStateStore,
) -> Result<VerifiedRecoveryAck, ContractError> {
    verify_recovery_ack_with(
        acknowledgement_bytes,
        signature_bytes,
        expected,
        |key, domain, payload, signature| match verify_signature(
            key, domain, payload, signature, scratch,
        )
        .map_err(ContractError::Internal)?
        {
            Ok(()) => Ok(()),
            Err(reason) => Err(reason.into()),
        },
    )
}

fn verify_recovery_ack_with<F>(
    acknowledgement_bytes: &[u8],
    signature_bytes: &[u8],
    expected: &ExpectedRecoveryAck<'_>,
    signature_verifier: F,
) -> Result<VerifiedRecoveryAck, ContractError>
where
    F: FnOnce(&[u8], &[u8], &[u8], &[u8]) -> Result<(), ContractError>,
{
    let value: LicensingRecoveryAck =
        parse_canonical(acknowledgement_bytes, "licensing recovery acknowledgement")?;
    if value.schema != "ota-licensing-recovery-ack-v1"
        || value.signing_role != "licensing-bootstrap"
        || !signature_profile(&value.signature_algorithm, &value.signature_encoding)
        || !ident(&value.issuance_id)
        || !ident(&value.key_id)
        || value.device_serial.is_empty()
        || value.device_serial.len() > 127
        || !timestamp(&value.issued_at)
        || !timestamp(&value.valid_until)
        || value.issued_at >= value.valid_until
        || lifetime_seconds(&value.issued_at, &value.valid_until).is_none_or(|value| value > 600)
        || value.key_id != expected.authorized_key_id
        || value.licence_record_id != expected.licence_record_id
        || value.device_serial != expected.device_serial
        || value.device_root != *expected.device_root
        || value.recovery_nonce != expected.recovery_nonce
        || value.recovery_nonce != expected.pending.nonce
        || value.root_recovery_sha256 != expected.root_recovery_sha256
        || value.resulting_state != *expected.resulting_state
        || value.tpm_clock != expected.pending.tpm_clock
        || value.tpm_reset_count != expected.pending.tpm_reset_count
        || value.tpm_restart_count != expected.pending.tpm_restart_count
        || !value.tpm_safe
        || value.tpm_reset_count != expected.current_tpm.tpm_reset_count
        || value.tpm_restart_count != expected.current_tpm.tpm_restart_count
        || !expected.current_tpm.tpm_safe
        || expected.current_tpm.tpm_clock < value.tpm_clock
        || expected.current_tpm.tpm_clock - value.tpm_clock > MAX_TPM_ELAPSED_MS
        || !sha256(&value.licence_record_id)
        || !is_nonce(&value.recovery_nonce)
        || !sha256(&value.root_recovery_sha256)
        || !valid_device_root(&value.device_root)
        || !valid_authoritative_state(&value.resulting_state)
    {
        return Err("licensing recovery acknowledgement scope or state is invalid".into());
    }
    validate_der_signature(signature_bytes)?;
    let public_key = public_key_pem(expected.authorized_key)?;
    signature_verifier(
        &public_key,
        RECOVERY_ACK_DOMAIN,
        acknowledgement_bytes,
        signature_bytes,
    )?;
    Ok(VerifiedRecoveryAck {
        acknowledgement_sha256: canonical_hash(acknowledgement_bytes)?,
        key_id: value.key_id,
        root_recovery_sha256: value.root_recovery_sha256,
    })
}

#[cfg(test)]
mod tests;
