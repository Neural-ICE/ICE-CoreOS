//! Closed beta authorization plus publication-receipt gate.

use std::path::Path;

use serde::{Deserialize, Serialize};

use super::contract::{
    canonical_hash, ident, parse_canonical, public_key_pem, safe_uint, sha256, signature_profile,
    target, timestamp, ContractError, DelegatedKey, Snapshot,
};
use super::{
    freeze_authority, freeze_root, refusal, validate_candidate, verify_root_binding,
    verify_signature,
};
use crate::config::{
    immutable_appliance_variant, immutable_hardware_target, immutable_minimum_delegation_seq,
    Config,
};
use crate::state::{ensure_secure_state_directory, FileStateStore};
use crate::{parse_flags, InternalError, DEFAULT_CONFIG, EXIT_PASS};

mod usb;

pub(crate) use usb::run as run_usb;

const RELEASE_DOMAIN: &[u8] = b"neural-ice:ota:release-authorization:v1\0";
const RECEIPT_DOMAIN: &[u8] = b"neural-ice:ota:beta-publication-receipt:v1\0";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ReleaseAuthorization {
    attestation_set_sha256: String,
    beta_publication_receipt_sha256: Option<String>,
    bom_sha256: String,
    bundle_seq: u64,
    channel_record_sha256: String,
    compat_max: u64,
    compat_min: u64,
    delegation_seq: u64,
    delegation_snapshot_sha256: String,
    hardware_target: String,
    issuance_id: String,
    issued_at: String,
    key_id: String,
    ring: String,
    schema: String,
    signature_algorithm: String,
    signature_encoding: String,
    signing_role: String,
    train: String,
    valid_from: String,
    valid_until: String,
    variant: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BetaReceipt {
    attestation_set_sha256: String,
    beta_envelope_sha256: String,
    beta_variant: String,
    bom_sha256: String,
    bundle_seq: u64,
    channel_record_sha256: String,
    compat_max: u64,
    compat_min: u64,
    delegation_seq: u64,
    delegation_snapshot_sha256: String,
    hardware_target: String,
    issuance_id: String,
    issued_at: String,
    key_id: String,
    observed_at: String,
    pointer_identity: String,
    registry_repository: String,
    resolved_pointer_manifest_digest: String,
    ring: String,
    schema: String,
    signature_algorithm: String,
    signature_encoding: String,
    signing_role: String,
    train: String,
    valid_until: String,
}

pub(crate) fn run(args: &[String]) -> Result<u8, InternalError> {
    let flags = parse_flags(
        args,
        &[
            "snapshot",
            "snapshot-sig",
            "release",
            "release-sig",
            "receipt",
            "receipt-sig",
            "trusted-now",
            "accepted-snapshot",
            "accepted-delegation-seq",
            "accepted-delegation-sha256",
            "config",
        ],
    )?;
    let required = |name: &str| {
        flags
            .get(name)
            .ok_or_else(|| InternalError(format!("verify-delegated-beta: --{name} is required")))
    };
    let config = Config::load(Path::new(
        flags.get("config").map_or(DEFAULT_CONFIG, String::as_str),
    ))?;
    let state_dir = config
        .state_dir
        .ok_or_else(|| InternalError("state_dir is required".into()))?;
    ensure_secure_state_directory(&state_dir)?;
    let scratch = FileStateStore {
        path: state_dir.join("applied.json"),
    };
    macro_rules! artifact {
        ($flag:literal, $label:literal) => {
            match freeze_authority(&scratch, Path::new(required($flag)?), $label)? {
                Ok(file) => file,
                Err(reason) => return refusal(reason),
            }
        };
    }
    let snapshot_file = artifact!("snapshot", "delegation-snapshot");
    let snapshot_sig = artifact!("snapshot-sig", "delegation-signature");
    let release_file = artifact!("release", "beta-release");
    let release_sig = artifact!("release-sig", "beta-release-signature");
    let receipt_file = artifact!("receipt", "beta-receipt");
    let receipt_sig = artifact!("receipt-sig", "beta-receipt-signature");
    let Some(root) = config.root_pubkey.as_deref() else {
        return refusal("no root_pubkey configured in ota.conf".into());
    };
    let root = match freeze_root(&scratch, root, "root-public-key")? {
        Ok(root) => root,
        Err(reason) => return refusal(reason),
    };
    let snapshot_bytes = snapshot_file.read()?;
    let release_bytes = release_file.read()?;
    let receipt_bytes = receipt_file.read()?;
    let snapshot: Snapshot = match parse_canonical(&snapshot_bytes, "delegation snapshot") {
        Ok(value) => value,
        Err(reason) => return refusal(reason),
    };
    let release: ReleaseAuthorization = match parse_canonical(&release_bytes, "beta release") {
        Ok(value) => value,
        Err(reason) => return refusal(reason),
    };
    let receipt: BetaReceipt = match parse_canonical(&receipt_bytes, "beta receipt") {
        Ok(value) => value,
        Err(reason) => return refusal(reason),
    };
    let now = required("trusted-now")?;
    let context = super::CandidateContext {
        now,
        minimum: immutable_minimum_delegation_seq()?,
        flags: &flags,
        snapshot_file: &snapshot_file,
        scratch: &scratch,
        allow_unseeded_bootstrap: false,
    };
    let target = immutable_hardware_target()?;
    let variant = immutable_appliance_variant()?;
    let snapshot_hash = match validate_candidate(&snapshot, &context) {
        Ok(hash) => hash,
        Err(ContractError::Refusal(reason)) => return refusal(reason),
        Err(ContractError::Internal(error)) => return Err(error),
    };
    let root_bytes = root.read()?;
    if let Err(reason) = verify_root_binding(&snapshot, &root_bytes) {
        return refusal(reason);
    }
    if let Err(reason) = verify_signature(
        &root_bytes,
        super::SNAPSHOT_DOMAIN,
        &snapshot_bytes,
        &snapshot_sig.read()?,
        &scratch,
    )? {
        return refusal(reason);
    }
    if let Err(reason) = validate_release(&release, &snapshot, &snapshot_hash, now, &target) {
        return refusal(reason);
    }
    if config.device_channel.as_deref() != Some("beta") {
        return refusal("delegated beta release requires device_channel=beta".into());
    }
    if release.variant != variant {
        return refusal(format!(
            "release variant '{}' does not match immutable host variant '{variant}'",
            release.variant
        ));
    }
    if let Err(reason) = device_compatibility(&release, config.device_compat) {
        if config.enforce {
            return refusal(reason);
        }
        eprintln!("ni-ota-verify: beta compatibility WARNING: {reason}");
    }
    if let Err(error) = validate_receipt(
        &receipt,
        &release,
        &release_bytes,
        &snapshot,
        &snapshot_hash,
        now,
        &target,
    ) {
        match error {
            ContractError::Refusal(reason) => return refusal(reason),
            ContractError::Internal(error) => return Err(error),
        }
    }
    let release_key = match authorized_key(
        &snapshot,
        &release.key_id,
        "beta-release-authorization",
        &target,
        &release.issued_at,
        now,
    ) {
        Ok(key) => key,
        Err(reason) => return refusal(reason),
    };
    let release_pem = match public_key_pem(&release_key.public_key) {
        Ok(pem) => pem,
        Err(ContractError::Refusal(reason)) => return refusal(reason),
        Err(ContractError::Internal(error)) => return Err(error),
    };
    if let Err(reason) = verify_signature(
        &release_pem,
        RELEASE_DOMAIN,
        &release_bytes,
        &release_sig.read()?,
        &scratch,
    )? {
        return refusal(reason);
    }
    let receipt_key = match authorized_key(
        &snapshot,
        &receipt.key_id,
        "beta-publication-receipt",
        &target,
        &receipt.issued_at,
        now,
    ) {
        Ok(key) => key,
        Err(reason) => return refusal(reason),
    };
    let receipt_pem = match public_key_pem(&receipt_key.public_key) {
        Ok(pem) => pem,
        Err(ContractError::Refusal(reason)) => return refusal(reason),
        Err(ContractError::Internal(error)) => return Err(error),
    };
    if let Err(reason) = verify_signature(
        &receipt_pem,
        RECEIPT_DOMAIN,
        &receipt_bytes,
        &receipt_sig.read()?,
        &scratch,
    )? {
        return refusal(reason);
    }
    let receipt_hash = match canonical_hash(&receipt_bytes) {
        Ok(hash) => hash,
        Err(ContractError::Refusal(reason)) => return refusal(reason),
        Err(ContractError::Internal(error)) => return Err(error),
    };
    println!(
        "{{\"verdict\":\"pass\",\"ring\":\"beta\",\"bundle_seq\":{},\"receipt_sha256\":\"{}\",\"manifest_digest\":\"{}\"}}",
        release.bundle_seq, receipt_hash, receipt.resolved_pointer_manifest_digest
    );
    Ok(EXIT_PASS)
}

fn device_compatibility(
    release: &ReleaseAuthorization,
    device: Option<(i64, i64)>,
) -> Result<(), String> {
    let Some((device_min, device_max)) = device else {
        return Err("device compatibility range is unknown".into());
    };
    let release_min = release.compat_min as i64;
    let release_max = release.compat_max as i64;
    if release_min > device_max || device_min > release_max {
        return Err(format!(
            "release range [{release_min},{release_max}] does not overlap device [{device_min},{device_max}]"
        ));
    }
    Ok(())
}

fn validate_release(
    value: &ReleaseAuthorization,
    snapshot: &Snapshot,
    snapshot_hash: &str,
    now: &str,
    immutable_target: &str,
) -> Result<(), String> {
    if value.schema != "neural-ice-ota-release-authorization-v1"
        || value.signing_role != "release-beta"
        || value.ring != "beta"
        || value.beta_publication_receipt_sha256.is_some()
        || !signature_profile(&value.signature_algorithm, &value.signature_encoding)
        || !safe_uint(value.delegation_seq)
        || value.delegation_seq != snapshot.delegation_seq
        || value.delegation_snapshot_sha256 != snapshot_hash
        || !safe_uint(value.bundle_seq)
        || !safe_uint(value.compat_min)
        || !safe_uint(value.compat_max)
        || value.compat_min > value.compat_max
        || !matches!(value.variant.as_str(), "debug" | "prod")
        || !target(&value.hardware_target)
        || value.hardware_target != immutable_target
        || !ident(&value.issuance_id)
        || !ident(&value.key_id)
        || !ident(&value.train)
        || ![
            &value.bom_sha256,
            &value.channel_record_sha256,
            &value.attestation_set_sha256,
        ]
        .into_iter()
        .all(|hash| sha256(hash))
        || !timestamp(&value.issued_at)
        || !timestamp(&value.valid_from)
        || !timestamp(&value.valid_until)
        || value.issued_at > value.valid_from
        || value.valid_from >= value.valid_until
        || value.issued_at < snapshot.valid_from
        || value.issued_at >= snapshot.valid_until
        || now < value.valid_from.as_str()
        || now >= value.valid_until.as_str()
    {
        return Err("beta release authorization contract or binding is invalid".into());
    }
    authorized_key(
        snapshot,
        &value.key_id,
        "beta-release-authorization",
        immutable_target,
        &value.issued_at,
        now,
    )?;
    Ok(())
}

fn validate_receipt(
    value: &BetaReceipt,
    release: &ReleaseAuthorization,
    release_bytes: &[u8],
    snapshot: &Snapshot,
    snapshot_hash: &str,
    now: &str,
    immutable_target: &str,
) -> Result<(), ContractError> {
    if value.schema != "neural-ice-ota-beta-publication-receipt-v1"
        || value.signing_role != "release-beta"
        || value.ring != "beta"
        || !signature_profile(&value.signature_algorithm, &value.signature_encoding)
        || !safe_uint(value.delegation_seq)
        || value.delegation_seq != snapshot.delegation_seq
        || value.delegation_snapshot_sha256 != snapshot_hash
        || !safe_uint(value.bundle_seq)
        || !safe_uint(value.compat_min)
        || !safe_uint(value.compat_max)
        || value.compat_min > value.compat_max
        || !matches!(value.beta_variant.as_str(), "debug" | "prod")
        || !target(&value.hardware_target)
        || value.hardware_target != immutable_target
        || !ident(&value.issuance_id)
        || !ident(&value.key_id)
        || !ident(&value.train)
        || value.registry_repository != "neural-ice/channels"
        || value.pointer_identity != format!("{}-beta", value.hardware_target)
        || !oci_digest(&value.resolved_pointer_manifest_digest)
        || ![
            &value.bom_sha256,
            &value.channel_record_sha256,
            &value.attestation_set_sha256,
            &value.beta_envelope_sha256,
        ]
        .into_iter()
        .all(|hash| sha256(hash))
        || !timestamp(&value.observed_at)
        || !timestamp(&value.issued_at)
        || !timestamp(&value.valid_until)
        || value.observed_at > value.issued_at
        || value.issued_at >= value.valid_until
        || value.issued_at < snapshot.valid_from
        || value.issued_at >= snapshot.valid_until
        || now < value.issued_at.as_str()
        || now >= value.valid_until.as_str()
    {
        return Err(ContractError::Refusal(
            "beta publication receipt contract or binding is invalid".into(),
        ));
    }
    authorized_key(
        snapshot,
        &value.key_id,
        "beta-publication-receipt",
        immutable_target,
        &value.issued_at,
        now,
    )
    .map_err(ContractError::Refusal)?;
    let release_hash = canonical_hash(release_bytes)?;
    if value.beta_envelope_sha256 != release_hash
        || value.beta_variant != release.variant
        || value.bom_sha256 != release.bom_sha256
        || value.attestation_set_sha256 != release.attestation_set_sha256
        || value.channel_record_sha256 != release.channel_record_sha256
        || value.compat_min != release.compat_min
        || value.compat_max != release.compat_max
        || value.bundle_seq != release.bundle_seq
        || value.delegation_seq != release.delegation_seq
        || value.delegation_snapshot_sha256 != release.delegation_snapshot_sha256
        || value.hardware_target != release.hardware_target
        || value.train != release.train
        || value.observed_at < release.valid_from
        || value.observed_at >= release.valid_until
    {
        return Err(ContractError::Refusal(
            "beta receipt does not bind the exact beta release".into(),
        ));
    }
    Ok(())
}

fn authorized_key<'a>(
    snapshot: &'a Snapshot,
    key_id: &str,
    artifact: &str,
    target: &str,
    issued_at: &str,
    now: &str,
) -> Result<&'a DelegatedKey, String> {
    let matches: Vec<_> = snapshot
        .keys
        .iter()
        .filter(|key| {
            key.key_id == key_id
                && key.role == "release-beta"
                && key.artifact_types.iter().any(|value| value == artifact)
                && key.rings.iter().any(|value| value == "beta")
                && key.hardware_targets.iter().any(|value| value == target)
                && matches!(key.status.as_str(), "active" | "retiring")
                && key.valid_from.as_str() <= issued_at
                && issued_at < key.valid_until.as_str()
                && key.valid_from.as_str() <= now
                && now < key.valid_until.as_str()
        })
        .collect();
    if matches.len() != 1 {
        return Err("release-beta key is not uniquely authorized for role/scope/time".into());
    }
    Ok(matches[0])
}

fn oci_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(sha256)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SNAPSHOT: &[u8] =
        include_bytes!("../../tests/fixtures/delegated-v1/delegation-snapshot.json");
    const RELEASE: &[u8] =
        include_bytes!("../../tests/fixtures/delegated-v1/release-authorization.json");
    const RECEIPT: &[u8] =
        include_bytes!("../../tests/fixtures/delegated-v1/beta-publication-receipt.json");

    #[test]
    fn fabric_beta_vectors_bind_and_authority_drift_refuses() {
        let snapshot: Snapshot = parse_canonical(SNAPSHOT, "snapshot").unwrap();
        let mut release: ReleaseAuthorization = parse_canonical(RELEASE, "release").unwrap();
        let mut receipt: BetaReceipt = parse_canonical(RECEIPT, "receipt").unwrap();
        let snapshot_hash = canonical_hash(SNAPSHOT).unwrap();
        assert_eq!(
            canonical_hash(RECEIPT).unwrap(),
            "4fff4b85728ffe3b12ecdaf98a0f6a332c93da0dca6855336638d3b1dfc91850"
        );
        validate_release(
            &release,
            &snapshot,
            &snapshot_hash,
            "2026-07-22T01:00:00Z",
            "nvidia-gb10-arm64",
        )
        .unwrap();
        validate_receipt(
            &receipt,
            &release,
            RELEASE,
            &snapshot,
            &snapshot_hash,
            "2026-07-22T01:00:00Z",
            "nvidia-gb10-arm64",
        )
        .unwrap();
        receipt.beta_variant = "debug".into();
        assert!(validate_receipt(
            &receipt,
            &release,
            RELEASE,
            &snapshot,
            &snapshot_hash,
            "2026-07-22T01:00:00Z",
            "nvidia-gb10-arm64",
        )
        .is_err());
        receipt.beta_variant = "prod".into();
        receipt.compat_max += 1;
        assert!(validate_receipt(
            &receipt,
            &release,
            RELEASE,
            &snapshot,
            &snapshot_hash,
            "2026-07-22T01:00:00Z",
            "nvidia-gb10-arm64",
        )
        .is_err());
        release.issued_at = "2026-07-20T00:00:00Z".into();
        assert!(validate_release(
            &release,
            &snapshot,
            &snapshot_hash,
            "2026-07-22T01:00:00Z",
            "nvidia-gb10-arm64",
        )
        .is_err());
    }
}
