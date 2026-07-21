//! ADR-0039 delegation-snapshot command and secure Cosign transport.

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use crate::config::{immutable_minimum_delegation_seq, Config};
use crate::state::{ensure_secure_state_directory, FileStateStore, SecureTempFile};
use crate::{parse_flags, runner, InternalError, DEFAULT_CONFIG, EXIT_PASS, EXIT_REFUSE};

mod beta;
pub(crate) mod contract;

pub(crate) use beta::run as run_beta;

use contract::{
    canonical_hash, encode_base64, parse_canonical, safe_uint, sha256, validate_chain,
    validate_der_signature, validate_snapshot, validate_snapshot_time, verify_root_binding,
    ContractError, Snapshot,
};

const SNAPSHOT_DOMAIN: &[u8] = b"neural-ice:ota:delegation-snapshot:v1\0";
const MAX_ARTIFACT: usize = 128 * 1024;
#[cfg(target_os = "linux")]
const O_NONBLOCK: i32 = 0x800;
#[cfg(target_os = "macos")]
const O_NONBLOCK: i32 = 0x4;

pub(crate) fn run(args: &[String]) -> Result<u8, InternalError> {
    let flags = parse_flags(
        args,
        &[
            "snapshot",
            "snapshot-sig",
            "trusted-now",
            "accepted-snapshot",
            "accepted-delegation-seq",
            "accepted-delegation-sha256",
            "config",
        ],
    )?;
    let required = |name: &str| {
        flags.get(name).ok_or_else(|| {
            InternalError(format!("verify-delegation-snapshot: --{name} is required"))
        })
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
    let snapshot = match freeze_authority(
        &scratch,
        Path::new(required("snapshot")?),
        "delegation-snapshot",
    )? {
        Ok(file) => file,
        Err(reason) => return refusal(reason),
    };
    let signature = match freeze_authority(
        &scratch,
        Path::new(required("snapshot-sig")?),
        "delegation-signature",
    )? {
        Ok(file) => file,
        Err(reason) => return refusal(reason),
    };
    let Some(root) = config.root_pubkey.as_deref() else {
        return refusal("no root_pubkey configured in ota.conf".into());
    };
    let root = match freeze_root(&scratch, root, "root-public-key")? {
        Ok(root) => root,
        Err(reason) => return refusal(reason),
    };
    let snapshot_bytes = snapshot.read()?;
    let candidate = match parse_canonical(&snapshot_bytes, "delegation snapshot") {
        Ok(candidate) => candidate,
        Err(reason) => return refusal(reason),
    };
    let context = CandidateContext {
        now: required("trusted-now")?,
        minimum: immutable_minimum_delegation_seq()?,
        flags: &flags,
        snapshot_file: &snapshot,
        scratch: &scratch,
        allow_unseeded_bootstrap: false,
    };
    let hash = match validate_candidate(&candidate, &context) {
        Ok(hash) => hash,
        Err(ContractError::Refusal(reason)) => return refusal(reason),
        Err(ContractError::Internal(error)) => return Err(error),
    };
    let root_bytes = root.read()?;
    if let Err(reason) = verify_root_binding(&candidate, &root_bytes) {
        return refusal(reason);
    }
    let signature_bytes = signature.read()?;
    if let Err(reason) = verify_signature(
        &root_bytes,
        SNAPSHOT_DOMAIN,
        &snapshot_bytes,
        &signature_bytes,
        &scratch,
    )? {
        return refusal(reason);
    }
    println!(
        "{{\"verdict\":\"pass\",\"delegation_seq\":{},\"snapshot_sha256\":\"{}\"}}",
        candidate.delegation_seq, hash
    );
    Ok(EXIT_PASS)
}

struct CandidateContext<'a> {
    now: &'a str,
    minimum: u64,
    flags: &'a HashMap<String, String>,
    snapshot_file: &'a SecureTempFile,
    scratch: &'a FileStateStore,
    allow_unseeded_bootstrap: bool,
}

fn validate_candidate(
    candidate: &Snapshot,
    context: &CandidateContext<'_>,
) -> Result<String, ContractError> {
    validate_snapshot(candidate)?;
    validate_snapshot_time(candidate, context.now).map_err(ContractError::Refusal)?;
    if candidate.delegation_seq < context.minimum {
        return Err("snapshot is below immutable delegation sequence floor".into());
    }
    let hash = canonical_hash(
        &context
            .snapshot_file
            .read()
            .map_err(ContractError::Internal)?,
    )?;
    match (
        context.flags.get("accepted-delegation-seq"),
        context.flags.get("accepted-delegation-sha256"),
        context.flags.get("accepted-snapshot"),
    ) {
        (None, None, None)
            if context.allow_unseeded_bootstrap && candidate.delegation_seq == context.minimum => {}
        (None, None, None) => {
            return Err(
                "accepted delegation state is required outside explicit floor-bound bootstrap"
                    .into(),
            )
        }
        (Some(sequence), Some(state_hash), Some(previous)) => {
            let sequence = sequence.parse::<u64>().map_err(|_| {
                ContractError::Refusal("accepted delegation sequence is invalid".into())
            })?;
            if !safe_uint(sequence) || !sha256(state_hash) {
                return Err("accepted delegation authority is invalid".into());
            }
            let previous =
                freeze_authority(context.scratch, Path::new(previous), "accepted-snapshot")
                    .map_err(ContractError::Internal)?
                    .map_err(ContractError::Refusal)?;
            let previous_bytes = previous.read().map_err(ContractError::Internal)?;
            let old: Snapshot = parse_canonical(&previous_bytes, "accepted snapshot")
                .map_err(ContractError::Refusal)?;
            validate_snapshot(&old)?;
            let old_hash = canonical_hash(&previous_bytes)?;
            if sequence != old.delegation_seq || state_hash != &old_hash {
                return Err("accepted snapshot does not match trusted delegation state".into());
            }
            if candidate.delegation_seq != old.delegation_seq || hash != old_hash {
                validate_chain(&old, candidate, &old_hash)?;
            }
        }
        _ => {
            return Err(
                "accepted sequence, hash and complete snapshot must be supplied together".into(),
            )
        }
    }
    Ok(hash)
}

fn freeze(
    store: &FileStateStore,
    source: &Path,
    label: &str,
) -> Result<SecureTempFile, InternalError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NONBLOCK)
        .open(source)
        .map_err(|e| InternalError(format!("cannot open {}: {e}", source.display())))?;
    let opened = file
        .metadata()
        .map_err(|e| InternalError(format!("cannot inspect {}: {e}", source.display())))?;
    let named = std::fs::symlink_metadata(source)
        .map_err(|e| InternalError(format!("cannot re-inspect {}: {e}", source.display())))?;
    if !opened.file_type().is_file()
        || !named.file_type().is_file()
        || opened.dev() != named.dev()
        || opened.ino() != named.ino()
    {
        return Err(InternalError(format!(
            "{label} source must be a stable regular non-symlink file"
        )));
    }
    let mut bytes = Vec::new();
    file.take((MAX_ARTIFACT + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|e| InternalError(format!("cannot read {}: {e}", source.display())))?;
    if bytes.is_empty() || bytes.len() > MAX_ARTIFACT {
        return Err(InternalError(format!("{label} size is invalid")));
    }
    store.secure_temp_bytes(label, &bytes)
}

pub(super) fn freeze_authority(
    store: &FileStateStore,
    source: &Path,
    label: &str,
) -> Result<Result<SecureTempFile, String>, InternalError> {
    match std::fs::symlink_metadata(source) {
        Ok(metadata)
            if metadata.file_type().is_file()
                && metadata.len() > 0
                && metadata.len() <= MAX_ARTIFACT as u64 => {}
        Ok(_) => {
            return Ok(Err(format!(
                "{label} must be a non-empty regular non-symlink file no larger than {MAX_ARTIFACT} bytes"
            )))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Err(format!("{label} is missing")))
        }
        Err(error) => {
            return Err(InternalError(format!(
                "cannot inspect authority artifact {}: {error}",
                source.display()
            )))
        }
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NONBLOCK)
        .open(source)
        .map_err(|error| {
            InternalError(format!(
                "cannot open authority artifact {}: {error}",
                source.display()
            ))
        })?;
    let opened = file.metadata().map_err(|error| {
        InternalError(format!(
            "cannot inspect opened authority artifact {}: {error}",
            source.display()
        ))
    })?;
    let named = std::fs::symlink_metadata(source).map_err(|error| {
        InternalError(format!(
            "cannot re-inspect authority artifact {}: {error}",
            source.display()
        ))
    })?;
    if !opened.file_type().is_file()
        || !named.file_type().is_file()
        || opened.dev() != named.dev()
        || opened.ino() != named.ino()
    {
        return Ok(Err(format!(
            "{label} source must remain a stable regular non-symlink file"
        )));
    }
    let mut bytes = Vec::new();
    file.take((MAX_ARTIFACT + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            InternalError(format!(
                "cannot read authority artifact {}: {error}",
                source.display()
            ))
        })?;
    if bytes.is_empty() || bytes.len() > MAX_ARTIFACT {
        return Ok(Err(format!("{label} size is invalid")));
    }
    store.secure_temp_bytes(label, &bytes).map(Ok)
}

fn freeze_root(
    store: &FileStateStore,
    source: &Path,
    label: &str,
) -> Result<Result<SecureTempFile, String>, InternalError> {
    match std::fs::symlink_metadata(source) {
        Ok(metadata)
            if metadata.file_type().is_file()
                && metadata.len() > 0
                && metadata.len() <= MAX_ARTIFACT as u64 => {}
        Ok(_) => {
            return Ok(Err(format!(
                "OTA root pubkey must be a non-empty regular non-symlink file no larger than {MAX_ARTIFACT} bytes: {}",
                source.display()
            )))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Err(format!(
                "OTA root pubkey missing or empty: {}",
                source.display()
            )))
        }
        Err(error) => {
            return Err(InternalError(format!(
                "cannot inspect OTA root pubkey {}: {error}",
                source.display()
            )))
        }
    }
    freeze(store, source, label).map(Ok)
}

fn verify_signature(
    public_key: &[u8],
    domain: &[u8],
    payload: &[u8],
    der: &[u8],
    store: &FileStateStore,
) -> Result<Result<(), String>, InternalError> {
    if let Err(reason) = validate_der_signature(der) {
        return Ok(Err(reason));
    }
    let mut message = domain.to_vec();
    let Some(payload) = payload.strip_suffix(b"\n") else {
        return Ok(Err("canonical payload lacks LF".into()));
    };
    message.extend_from_slice(payload);
    let key = store.secure_temp_bytes("delegated-key", public_key)?;
    let message = store.secure_temp_bytes("delegated-message", &message)?;
    let encoded = encode_base64(der);
    let signature = store.secure_temp_bytes("delegated-signature-b64", encoded.as_bytes())?;
    let cosign = runner::cosign_path()?;
    runner::verify_blob(&cosign, key.path(), signature.path(), message.path())
}

fn refusal(reason: String) -> Result<u8, InternalError> {
    eprintln!("ni-ota-verify: delegation snapshot REFUSED: {reason}");
    Ok(EXIT_REFUSE)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;

    use super::*;

    #[test]
    fn authority_freeze_refuses_fifo_and_oversize_before_opening() {
        let root =
            std::env::temp_dir().join(format!("ni-ota-authority-freeze-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let store = FileStateStore {
            path: root.join("applied.json"),
        };

        let fifo = root.join("authority.fifo");
        assert!(Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success());
        assert!(freeze_authority(&store, &fifo, "authority")
            .unwrap()
            .is_err());

        let oversize = root.join("authority.oversize");
        fs::write(&oversize, vec![0_u8; MAX_ARTIFACT + 1]).unwrap();
        assert!(freeze_authority(&store, &oversize, "authority")
            .unwrap()
            .is_err());

        fs::remove_dir_all(root).unwrap();
    }
}
