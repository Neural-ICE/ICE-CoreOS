//! Generate one TPM-bound trusted-time v2 challenge after root verification.

use std::path::{Path, PathBuf};

use crate::config::{
    immutable_appliance_variant, immutable_hardware_target, immutable_minimum_delegation_seq,
    Config,
};
use crate::delegated::beta::{
    validate_release_for_time_challenge, ReleaseAuthorization, RELEASE_DOMAIN,
};
use crate::delegated::contract::{
    canonical_hash, parse_canonical, public_key_pem, validate_snapshot, verify_root_binding,
    ContractError, Snapshot,
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
    let key = match validate_release_for_time_challenge(
        &release,
        &snapshot,
        &snapshot_hash,
        &target,
        &variant,
    ) {
        Ok(value) => value,
        Err(reason) => return refusal(reason),
    };
    let release_key = match public_key_pem(&key.public_key) {
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
