//! Closed device-side verifier for the ADR-0039 licensing bootstrap proof.
//!
//! Transport and licence authentication stay outside this local-only layer.
//! This verifier accepts only the initial-activation subset needed by a fresh
//! appliance. State-loss recovery remains refused until its complete chain
//! reconstruction and atomic state transaction land together.

use serde::{Deserialize, Serialize};

use crate::delegated::contract::{
    canonical_hash, ident, parse_canonical, public_key_pem, safe_uint, sha256, signature_profile,
    target, timestamp, ContractError, Snapshot,
};
use crate::delegated::{verify_signature, AuthenticatedSnapshot};
use crate::state::FileStateStore;
use crate::trusted_time::utc_seconds;

const DOMAIN: &[u8] = b"neural-ice:ota:licensing-bootstrap:v1\0";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BaselineIdentity {
    pub(crate) baseline_manifest_sha256: String,
    pub(crate) bootstrap_delegation_seq: u64,
    pub(crate) bootstrap_snapshot_sha256: String,
    pub(crate) compatibility_version: u64,
    pub(crate) hardware_target: String,
    pub(crate) minimum_bundle_seq: u64,
    pub(crate) minimum_delegation_seq: u64,
    pub(crate) minimum_recovery_seq: u64,
    pub(crate) minimum_trusted_time_seq: u64,
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

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Authorization {
    active_product: String,
    authoritative_state: Option<serde_json::Value>,
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

pub(crate) struct Expected<'a> {
    pub(crate) baseline: &'a BaselineIdentity,
    pub(crate) device_root: &'a DeviceRootIdentity,
    pub(crate) device_serial: &'a str,
    pub(crate) licensing_bootstrap_nonce: &'a str,
    pub(crate) ring: &'a str,
    pub(crate) tpm_clock: u64,
    pub(crate) tpm_reset_count: u32,
    pub(crate) tpm_restart_count: u32,
    pub(crate) tpm_safe: bool,
}

pub(crate) struct Verified {
    pub(crate) authorization_sha256: String,
    pub(crate) bootstrap_seq: u64,
    pub(crate) issued_at: String,
    pub(crate) key_id: String,
    pub(crate) licence_record_id: String,
    pub(crate) licensing_bootstrap_nonce: String,
    pub(crate) valid_until: String,
}

pub(crate) fn verify(
    authenticated_snapshot: &AuthenticatedSnapshot,
    authorization_bytes: &[u8],
    signature_bytes: &[u8],
    expected: &Expected<'_>,
    scratch: &FileStateStore,
) -> Result<Verified, ContractError> {
    let authorization: Authorization =
        parse_canonical(authorization_bytes, "licensing-bootstrap authorization")?;
    validate(
        &authorization,
        authenticated_snapshot.snapshot(),
        authenticated_snapshot.canonical_sha256(),
        expected,
    )?;
    let key = authority(authenticated_snapshot.snapshot(), &authorization, expected)?;
    let public_key = public_key_pem(&key.public_key)?;
    match verify_signature(
        &public_key,
        DOMAIN,
        authorization_bytes,
        signature_bytes,
        scratch,
    )
    .map_err(ContractError::Internal)?
    {
        Ok(()) => {}
        Err(reason) => return Err(reason.into()),
    }
    Ok(Verified {
        authorization_sha256: canonical_hash(authorization_bytes)?,
        bootstrap_seq: authorization.bootstrap_seq,
        issued_at: authorization.issued_at,
        key_id: authorization.key_id,
        licence_record_id: authorization.licence_record_id,
        licensing_bootstrap_nonce: authorization.licensing_bootstrap_nonce,
        valid_until: authorization.valid_until,
    })
}

fn validate(
    value: &Authorization,
    snapshot: &Snapshot,
    snapshot_sha256: &str,
    expected: &Expected<'_>,
) -> Result<(), ContractError> {
    let lifetime = utc_seconds(&value.valid_until)
        .zip(utc_seconds(&value.issued_at))
        .and_then(|(until, issued)| until.checked_sub(issued));
    if value.schema != "ota-licensing-bootstrap-v1"
        || value.signing_role != "licensing-bootstrap"
        || !signature_profile(&value.signature_algorithm, &value.signature_encoding)
        || !ident(&value.active_product)
        || !ident(&value.entitlement_policy_revision)
        || !ident(&value.issuance_id)
        || !ident(&value.key_id)
        || !sha256(&value.licence_record_id)
        || !device_serial(&value.device_serial)
        || !nonce(&value.licensing_bootstrap_nonce)
        || !baseline(&value.baseline)
        || !device_root(&value.device_root)
        || !safe_uint(value.bootstrap_seq)
        || !safe_uint(value.tpm_clock)
        || !value.tpm_safe
        || !timestamp(&value.issued_at)
        || !timestamp(&value.valid_until)
        || lifetime.is_none_or(|seconds| seconds == 0 || seconds > 600)
        || value.reason != "initial_activation"
        || value.bootstrap_seq != 1
        || value.previous_authorization_sha256.is_some()
        || value.previous_device_root.is_some()
        || value.authoritative_state.is_some()
        || value.baseline != *expected.baseline
        || value.device_root != *expected.device_root
        || value.device_serial != expected.device_serial
        || value.licensing_bootstrap_nonce != expected.licensing_bootstrap_nonce
        || value.tpm_clock != expected.tpm_clock
        || value.tpm_reset_count != expected.tpm_reset_count
        || value.tpm_restart_count != expected.tpm_restart_count
        || value.tpm_safe != expected.tpm_safe
        || !matches!(expected.ring, "beta" | "stable")
        || (expected.ring == "stable" && value.baseline.release_variant != "prod")
        || value.baseline.bootstrap_delegation_seq != snapshot.delegation_seq
        || value.baseline.bootstrap_snapshot_sha256 != snapshot_sha256
        || value.issued_at < snapshot.valid_from
        || value.valid_until > snapshot.valid_until
    {
        return Err("licensing-bootstrap authorization scope or challenge is invalid".into());
    }
    Ok(())
}

fn authority<'a>(
    snapshot: &'a Snapshot,
    value: &Authorization,
    expected: &Expected<'_>,
) -> Result<&'a crate::delegated::contract::DelegatedKey, ContractError> {
    let matches: Vec<_> = snapshot
        .keys
        .iter()
        .filter(|key| {
            key.key_id == value.key_id
                && key.role == "licensing-bootstrap"
                && key.artifact_types
                    == [
                        "ota-licensing-bootstrap-v1",
                        "ota-licensing-recovery-ack-v1",
                    ]
                && key.rings.iter().any(|ring| ring == expected.ring)
                && key
                    .hardware_targets
                    .iter()
                    .any(|target| target == &value.baseline.hardware_target)
                && key.authorizes_at(&value.issued_at)
                && key
                    .authorization_deadline()
                    .is_some_and(|deadline| value.valid_until.as_str() <= deadline)
        })
        .collect();
    if matches.len() != 1 {
        return Err("licensing-bootstrap key is not uniquely authorized for scope/time".into());
    }
    Ok(matches[0])
}

fn baseline(value: &BaselineIdentity) -> bool {
    sha256(&value.baseline_manifest_sha256)
        && safe_uint(value.bootstrap_delegation_seq)
        && sha256(&value.bootstrap_snapshot_sha256)
        && safe_uint(value.compatibility_version)
        && target(&value.hardware_target)
        && safe_uint(value.minimum_bundle_seq)
        && safe_uint(value.minimum_delegation_seq)
        && value.minimum_recovery_seq <= 9_007_199_254_740_991
        && safe_uint(value.minimum_trusted_time_seq)
        && value
            .os_image_manifest_digest
            .strip_prefix("sha256:")
            .is_some_and(sha256)
        && sha256(&value.ota_root_spki_sha256)
        && safe_uint(value.ota_root_version)
        && matches!(value.release_variant.as_str(), "debug" | "prod")
}

fn device_root(value: &DeviceRootIdentity) -> bool {
    sha256(&value.spki_sha256)
        && value.tpm_name.len() == 68
        && value.tpm_name.starts_with("000b")
        && lower_hex(&value.tpm_name)
}

fn nonce(value: &str) -> bool {
    value.len() == 64 && lower_hex(value)
}

fn lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn device_serial(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 127
        && value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delegated::contract::{parse_canonical, validate_snapshot};

    const SNAPSHOT: &[u8] =
        include_bytes!("../tests/fixtures/delegated-v1/delegation-snapshot.json");

    fn snapshot() -> (Snapshot, String) {
        let mut value: serde_json::Value = serde_json::from_slice(SNAPSHOT).unwrap();
        value["keys"].as_array_mut().unwrap().push(serde_json::json!({
            "artifact_types":["ota-licensing-bootstrap-v1","ota-licensing-recovery-ack-v1"],
            "hardware_targets":["amd-rocm-x86_64","nvidia-cuda-x86_64","nvidia-gb10-arm64"],
            "key_id":"licensing-bootstrap-v1","predecessor_key_id":null,
            "public_key":{"algorithm":"ecdsa-p256-sha256","encoding":"spki-der-base64","spki_der_base64":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEVCDRKQw/OTGAxwBSs7zXuxRzqqUPvgH4FEO7BI00qdkgg+MRoS6PsMJa9cwfEUZzrRyiQuOMAVrBBpJ5V+CL2Q==","spki_sha256":"4d25cb738d78b6b83be69d96ecb9b3e1d5f07e86f23c8dd76c14bf07387d2874"},
            "rings":["beta","stable"],"role":"licensing-bootstrap",
            "rotation_overlap":{"mode":"none","valid_from":null,"valid_until":null,"with_key_id":null},
            "signature_algorithm":"ecdsa-p256-sha256","signature_encoding":"asn1-der","status":"active",
            "successor_key_id":null,"valid_from":"2026-07-21T19:35:00Z","valid_until":"2027-07-21T19:35:00Z"
        }));
        value["keys"]
            .as_array_mut()
            .unwrap()
            .sort_by(|left, right| left["key_id"].as_str().cmp(&right["key_id"].as_str()));
        let mut bytes = serde_json::to_vec(&value).unwrap();
        bytes.push(b'\n');
        let snapshot: Snapshot = parse_canonical(&bytes, "snapshot").unwrap();
        validate_snapshot(&snapshot).unwrap();
        let hash = canonical_hash(&bytes).unwrap();
        (snapshot, hash)
    }

    fn baseline(snapshot_hash: String) -> BaselineIdentity {
        BaselineIdentity {
            baseline_manifest_sha256: "a".repeat(64),
            bootstrap_delegation_seq: 1,
            bootstrap_snapshot_sha256: snapshot_hash,
            compatibility_version: 5,
            hardware_target: "nvidia-gb10-arm64".into(),
            minimum_bundle_seq: 1,
            minimum_delegation_seq: 1,
            minimum_recovery_seq: 0,
            minimum_trusted_time_seq: 1,
            os_image_manifest_digest: format!("sha256:{}", "b".repeat(64)),
            ota_root_spki_sha256: "c".repeat(64),
            ota_root_version: 1,
            release_variant: "debug".into(),
        }
    }

    fn authorization(baseline: BaselineIdentity) -> Authorization {
        Authorization {
            active_product: "icecore".into(),
            authoritative_state: None,
            baseline,
            bootstrap_seq: 1,
            device_root: DeviceRootIdentity {
                spki_sha256: "d".repeat(64),
                tpm_name: format!("000b{}", "e".repeat(64)),
            },
            device_serial: "dgx-spark-test".into(),
            entitlement_policy_revision: "policy-v1".into(),
            issuance_id: "issuance-v1".into(),
            issued_at: "2026-07-21T20:00:00Z".into(),
            key_id: "licensing-bootstrap-v1".into(),
            licence_record_id: "f".repeat(64),
            licensing_bootstrap_nonce: "1".repeat(64),
            previous_authorization_sha256: None,
            previous_device_root: None,
            reason: "initial_activation".into(),
            schema: "ota-licensing-bootstrap-v1".into(),
            signature_algorithm: "ecdsa-p256-sha256".into(),
            signature_encoding: "asn1-der".into(),
            signing_role: "licensing-bootstrap".into(),
            tpm_clock: 42,
            tpm_reset_count: 3,
            tpm_restart_count: 4,
            tpm_safe: true,
            valid_until: "2026-07-21T20:10:00Z".into(),
        }
    }

    fn expected<'a>(value: &'a Authorization) -> Expected<'a> {
        Expected {
            baseline: &value.baseline,
            device_root: &value.device_root,
            device_serial: &value.device_serial,
            licensing_bootstrap_nonce: &value.licensing_bootstrap_nonce,
            ring: "beta",
            tpm_clock: value.tpm_clock,
            tpm_reset_count: value.tpm_reset_count,
            tpm_restart_count: value.tpm_restart_count,
            tpm_safe: value.tpm_safe,
        }
    }

    #[test]
    fn initial_activation_binds_exact_baseline_device_nonce_and_tpm() {
        let (snapshot, hash) = snapshot();
        let value = authorization(baseline(hash.clone()));
        assert!(validate(&value, &snapshot, &hash, &expected(&value)).is_ok());
        assert!(authority(&snapshot, &value, &expected(&value)).is_ok());

        let mut drift = value.clone();
        drift.licensing_bootstrap_nonce = "2".repeat(64);
        assert!(validate(&drift, &snapshot, &hash, &expected(&value)).is_err());
        let mut recovery = value.clone();
        recovery.reason = "state_loss_recovery".into();
        recovery.bootstrap_seq = 2;
        assert!(validate(&recovery, &snapshot, &hash, &expected(&recovery)).is_err());
    }

    #[test]
    fn authorization_window_and_role_scope_fail_closed() {
        let (mut snapshot, hash) = snapshot();
        let mut value = authorization(baseline(hash.clone()));
        value.valid_until = "2026-07-21T20:10:01Z".into();
        assert!(validate(&value, &snapshot, &hash, &expected(&value)).is_err());

        value.valid_until = "2026-07-21T20:10:00Z".into();
        let key = snapshot
            .keys
            .iter_mut()
            .find(|key| key.role == "licensing-bootstrap")
            .unwrap();
        key.rings = vec!["stable".into()];
        assert!(authority(&snapshot, &value, &expected(&value)).is_err());
    }
}
