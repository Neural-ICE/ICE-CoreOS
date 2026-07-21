//! ADR-0039 delegation-snapshot command and secure Cosign transport.

use std::collections::HashMap;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use crate::config::{immutable_minimum_delegation_seq, Config};
use crate::state::{ensure_secure_state_directory, FileStateStore, SecureTempFile};
use crate::{parse_flags, runner, InternalError, DEFAULT_CONFIG, EXIT_PASS, EXIT_REFUSE};

pub(crate) mod contract;

use contract::{
    canonical_hash, encode_base64, parse_canonical, safe_uint, sha256, validate_chain,
    validate_der_signature, validate_snapshot, validate_snapshot_time, verify_root_binding,
    Snapshot,
};

const SNAPSHOT_DOMAIN: &[u8] = b"neural-ice:ota:delegation-snapshot:v1\0";
const MAX_ARTIFACT: usize = 128 * 1024;

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
    let snapshot = freeze(
        &scratch,
        Path::new(required("snapshot")?),
        "delegation-snapshot",
    )?;
    let signature = freeze(
        &scratch,
        Path::new(required("snapshot-sig")?),
        "delegation-signature",
    )?;
    let root = config
        .root_pubkey
        .as_deref()
        .ok_or_else(|| InternalError("root_pubkey is required".into()))?;
    let root = freeze(&scratch, root, "root-public-key")?;
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
    };
    let result = validate_candidate(&candidate, &context).and_then(|hash| {
        let root_bytes = root.read().map_err(|e| e.0)?;
        verify_root_binding(&candidate, &root_bytes)?;
        verify_signature(
            &root_bytes,
            &snapshot_bytes,
            &signature.read().map_err(|e| e.0)?,
            &scratch,
        )?;
        Ok(hash)
    });
    match result {
        Ok(hash) => {
            println!(
                "{{\"verdict\":\"pass\",\"delegation_seq\":{},\"snapshot_sha256\":\"{}\"}}",
                candidate.delegation_seq, hash
            );
            Ok(EXIT_PASS)
        }
        Err(reason) => refusal(reason),
    }
}

struct CandidateContext<'a> {
    now: &'a str,
    minimum: u64,
    flags: &'a HashMap<String, String>,
    snapshot_file: &'a SecureTempFile,
    scratch: &'a FileStateStore,
}

fn validate_candidate(
    candidate: &Snapshot,
    context: &CandidateContext<'_>,
) -> Result<String, String> {
    validate_snapshot(candidate)?;
    validate_snapshot_time(candidate, context.now)?;
    if candidate.delegation_seq < context.minimum {
        return Err("snapshot is below immutable delegation sequence floor".into());
    }
    let hash = canonical_hash(&context.snapshot_file.read().map_err(|e| e.0)?)?;
    match (
        context.flags.get("accepted-delegation-seq"),
        context.flags.get("accepted-delegation-sha256"),
        context.flags.get("accepted-snapshot"),
    ) {
        (None, None, None) => {}
        (Some(sequence), Some(state_hash), Some(previous)) => {
            let sequence = sequence
                .parse::<u64>()
                .map_err(|_| "accepted delegation sequence is invalid")?;
            if !safe_uint(sequence) || !sha256(state_hash) {
                return Err("accepted delegation authority is invalid".into());
            }
            let previous = freeze(context.scratch, Path::new(previous), "accepted-snapshot")
                .map_err(|e| e.0)?;
            let previous_bytes = previous.read().map_err(|e| e.0)?;
            let old: Snapshot = parse_canonical(&previous_bytes, "accepted snapshot")?;
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
    let file = std::fs::File::open(source)
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

fn verify_signature(
    root: &[u8],
    payload: &[u8],
    der: &[u8],
    store: &FileStateStore,
) -> Result<(), String> {
    validate_der_signature(der)?;
    let mut message = SNAPSHOT_DOMAIN.to_vec();
    message.extend_from_slice(
        payload
            .strip_suffix(b"\n")
            .ok_or("canonical payload lacks LF")?,
    );
    let key = store
        .secure_temp_bytes("delegated-key", root)
        .map_err(|e| e.0)?;
    let message = store
        .secure_temp_bytes("delegated-message", &message)
        .map_err(|e| e.0)?;
    let encoded = encode_base64(der);
    let signature = store
        .secure_temp_bytes("delegated-signature-b64", encoded.as_bytes())
        .map_err(|e| e.0)?;
    let cosign = runner::cosign_path().map_err(|e| e.0)?;
    runner::verify_blob(&cosign, key.path(), signature.path(), message.path()).map_err(|e| e.0)?
}

fn refusal(reason: String) -> Result<u8, InternalError> {
    eprintln!("ni-ota-verify: delegation snapshot REFUSED: {reason}");
    Ok(EXIT_REFUSE)
}
