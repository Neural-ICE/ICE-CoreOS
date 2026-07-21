//! Generate one TPM-bound trusted-time v2 challenge after root verification.

use std::path::{Path, PathBuf};

use crate::config::{
    immutable_appliance_variant, immutable_hardware_target, immutable_minimum_delegation_seq,
    Config,
};
use crate::delegated::beta::{ReleaseAuthorization, RELEASE_DOMAIN};
use crate::delegated::contract::{
    canonical_hash, parse_canonical, public_key_pem, safe_uint, sha256, signature_profile, target,
    timestamp, validate_snapshot, verify_root_binding, ContractError, Snapshot,
};
use crate::delegated::{freeze_authority, freeze_root, verify_signature, SNAPSHOT_DOMAIN};
use crate::state_v1::{CommandTpm, Store, STATE_NV_INDEX};
use crate::{parse_flags, InternalError, DEFAULT_CONFIG, EXIT_PASS, EXIT_REFUSE};

pub(crate) fn run(args: &[String]) -> Result<u8, InternalError> {
    let flags = parse_flags(
        args,
        &[
            "config",
            "release",
            "release-sig",
            "snapshot",
            "snapshot-sig",
        ],
    )?;
    let required = |name: &str| -> Result<PathBuf, InternalError> {
        flags
            .get(name)
            .map(PathBuf::from)
            .ok_or_else(|| InternalError(format!("prepare-trusted-time-v2: --{name} is required")))
    };
    let config = Config::load(Path::new(
        flags.get("config").map_or(DEFAULT_CONFIG, String::as_str),
    ))?;
    if config.state_nv_index != Some(STATE_NV_INDEX) {
        return refusal("state-v1 anchor must be TPM NV EXTEND 0x01500002".into());
    }
    let ring = match config.device_channel.as_deref() {
        Some("beta") => "beta",
        _ => return refusal("trusted-time v2 preparation currently requires ring beta".into()),
    };
    let target = immutable_hardware_target()?;
    let root_path = config
        .root_pubkey
        .as_deref()
        .ok_or_else(|| InternalError("root_pubkey is required".into()))?;
    let state_dir = config
        .state_dir
        .as_deref()
        .ok_or_else(|| InternalError("state_dir is required".into()))?;
    let store = Store {
        root: state_dir.join("state-v1"),
    };
    let scratch = store.lock_store();
    let _lock = scratch.lock_commit()?;

    macro_rules! artifact {
        ($flag:literal, $label:literal) => {
            match freeze_authority(&scratch, &required($flag)?, $label)? {
                Ok(file) => file,
                Err(reason) => return refusal(reason),
            }
        };
    }
    let snapshot_file = artifact!("snapshot", "time-v2-snapshot");
    let snapshot_sig = artifact!("snapshot-sig", "time-v2-snapshot-signature");
    let release_file = artifact!("release", "time-v2-release");
    let release_sig = artifact!("release-sig", "time-v2-release-signature");
    let root = match freeze_root(&scratch, root_path, "time-v2-root")? {
        Ok(value) => value,
        Err(reason) => return refusal(reason),
    };

    let snapshot_bytes = snapshot_file.read()?;
    let snapshot: Snapshot = match parse_canonical(&snapshot_bytes, "delegation snapshot") {
        Ok(value) => value,
        Err(reason) => return refusal(reason),
    };
    if let Err(error) = validate_snapshot(&snapshot) {
        return contract_refusal(error);
    }
    if snapshot.delegation_seq < immutable_minimum_delegation_seq()? {
        return refusal("snapshot is below immutable delegation sequence floor".into());
    }
    let root_bytes = root.read()?;
    if let Err(reason) = verify_root_binding(&snapshot, &root_bytes) {
        return refusal(reason);
    }
    if let Err(reason) = verify_signature(
        &root_bytes,
        SNAPSHOT_DOMAIN,
        &snapshot_bytes,
        &snapshot_sig.read()?,
        &scratch,
    )? {
        return refusal(reason);
    }
    let snapshot_hash = match canonical_hash(&snapshot_bytes) {
        Ok(value) => value,
        Err(error) => return contract_refusal(error),
    };

    let release_bytes = release_file.read()?;
    let release: ReleaseAuthorization =
        match parse_canonical(&release_bytes, "release authorization") {
            Ok(value) => value,
            Err(reason) => return refusal(reason),
        };
    let variant = immutable_appliance_variant()?;
    if let Err(reason) =
        validate_release_shape(&release, &snapshot, &snapshot_hash, &target, &variant)
    {
        return refusal(reason);
    }
    let keys: Vec<_> = snapshot
        .keys
        .iter()
        .filter(|key| {
            key.key_id == release.key_id
                && key.role == "release-beta"
                && release_key_status(&key.status)
                && key
                    .artifact_types
                    .iter()
                    .any(|value| value == "beta-release-authorization")
                && key.hardware_targets.iter().any(|value| value == &target)
                && key.rings.iter().any(|value| value == ring)
                && key.valid_from <= release.issued_at
                && release.valid_from < key.valid_until
        })
        .collect();
    if keys.len() != 1 {
        return refusal("release has no unique active or retiring beta authority".into());
    }
    let release_key = match public_key_pem(&keys[0].public_key) {
        Ok(value) => value,
        Err(error) => return contract_refusal(error),
    };
    if let Err(reason) = verify_signature(
        &release_key,
        RELEASE_DOMAIN,
        &release_bytes,
        &release_sig.read()?,
        &scratch,
    )? {
        return refusal(reason);
    }
    let release_hash = match canonical_hash(&release_bytes) {
        Ok(value) => value,
        Err(error) => return contract_refusal(error),
    };
    let tpm = CommandTpm {
        index: STATE_NV_INDEX,
        scratch,
    };
    let challenge =
        store.issue_time_challenge(&tpm, &snapshot_hash, &release_hash, &target, ring)?;
    println!(
        "{}",
        serde_json::to_string(&challenge)
            .map_err(|error| InternalError(format!("cannot encode challenge: {error}")))?
    );
    Ok(EXIT_PASS)
}

fn validate_release_shape(
    value: &ReleaseAuthorization,
    snapshot: &Snapshot,
    snapshot_hash: &str,
    target_name: &str,
    variant: &str,
) -> Result<(), String> {
    if value.schema != "neural-ice-ota-release-authorization-v1"
        || value.signing_role != "release-beta"
        || value.ring != "beta"
        || !signature_profile(&value.signature_algorithm, &value.signature_encoding)
        || !safe_uint(value.delegation_seq)
        || value.delegation_seq != snapshot.delegation_seq
        || value.delegation_snapshot_sha256 != snapshot_hash
        || !safe_uint(value.bundle_seq)
        || !target(&value.hardware_target)
        || value.hardware_target != target_name
        || !release_variant(&value.variant, variant)
        || ![&value.bom_sha256, &value.channel_record_sha256]
            .into_iter()
            .all(|hash| sha256(hash))
        || !timestamp(&value.issued_at)
        || !timestamp(&value.valid_from)
        || !timestamp(&value.valid_until)
        || value.issued_at > value.valid_from
        || value.valid_from >= value.valid_until
    {
        return Err("release authorization shape is invalid for a time challenge".into());
    }
    Ok(())
}

fn release_key_status(value: &str) -> bool {
    matches!(value, "active" | "retiring")
}

fn release_variant(value: &str, immutable: &str) -> bool {
    matches!(immutable, "debug" | "prod") && value == immutable
}

fn contract_refusal(error: ContractError) -> Result<u8, InternalError> {
    match error {
        ContractError::Refusal(reason) => refusal(reason),
        ContractError::Internal(error) => Err(error),
    }
}

fn refusal(reason: String) -> Result<u8, InternalError> {
    eprintln!("ni-ota-verify: trusted-time-v2 REFUSED: {reason}");
    Ok(EXIT_REFUSE)
}

#[cfg(test)]
mod tests {
    use super::{release_key_status, release_variant};

    #[test]
    fn release_rotation_accepts_only_active_or_retiring() {
        assert!(release_key_status("active"));
        assert!(release_key_status("retiring"));
        for status in ["revoked", "retired", "pending", "ACTIVE", ""] {
            assert!(!release_key_status(status));
        }
    }

    #[test]
    fn release_variant_must_equal_the_immutable_host_marker() {
        assert!(release_variant("debug", "debug"));
        assert!(release_variant("prod", "prod"));
        assert!(!release_variant("debug", "prod"));
        assert!(!release_variant("prod", "debug"));
        assert!(!release_variant("debug", "unknown"));
    }
}
