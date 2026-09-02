//! `commit` — advance the applied-bundle record AFTER the caller's health gate
//! passes (plan §0 last step). P3 adds the TPM NV write here, behind the same
//! `AppliedStateStore` seam.
//!
//! No shadow semantics: commit mutates the anti-rollback baseline, so a
//! refusal always exits nonzero regardless of the enforce flag.

use std::path::{Path, PathBuf};

use crate::config::{immutable_hardware_target, Config};
use crate::state::{AppliedState, AppliedStateStore, FileStateStore, StateRead};
use crate::verify::{applied_state_path, BomCore};
use crate::{parse_flags, runner, InternalError, DEFAULT_CONFIG, EXIT_PASS, EXIT_REFUSE};

pub(crate) fn run(args: &[String]) -> Result<u8, InternalError> {
    let flags = parse_flags(
        args,
        &[
            "bom",
            "config",
            "applied-state",
            "active-ring",
            "previous-ring",
        ],
    )?;
    let (active_ring, previous_ring) = match (flags.get("active-ring"), flags.get("previous-ring"))
    {
        (Some(active), Some(previous)) => (Some(active), Some(previous)),
        (None, None) => (None, None), // backward-compatible non-ring callers
        _ => {
            return Err(InternalError(
                "commit: --active-ring and --previous-ring must be supplied together".into(),
            ))
        }
    };
    let ring_rank = |ring: &str| match ring {
        "lab" => Some(0_u8),
        "beta" => Some(1),
        "stable" => Some(2),
        _ => None,
    };
    if let (Some(active), Some(previous)) = (active_ring, previous_ring) {
        let Some(active_rank) = ring_rank(active) else {
            return Err(InternalError("commit: invalid --active-ring".into()));
        };
        let Some(previous_rank) = ring_rank(previous) else {
            return Err(InternalError("commit: invalid --previous-ring".into()));
        };
        if active_rank < previous_rank {
            eprintln!("ni-ota-verify: commit REFUSED: ring downgrade is forbidden");
            return Ok(EXIT_REFUSE);
        }
    }
    let bom_path = flags
        .get("bom")
        .map(PathBuf::from)
        .ok_or_else(|| InternalError("commit: --bom is required".to_string()))?;
    let config_path = flags.get("config").map_or(DEFAULT_CONFIG, String::as_str);
    let cfg = Config::load(Path::new(config_path))?;
    let store = FileStateStore {
        path: applied_state_path(&flags, &cfg)?,
    };
    let _state_lock = store.lock_commit()?;
    let bom_snapshot = store.snapshot_commit(&bom_path)?;

    // A BOM that cannot be parsed cannot be committed — internal error, not a
    // policy refusal: the caller must only ever commit a BOM that already
    // passed `verify`.
    let bytes = bom_snapshot.read()?;
    let bom: BomCore = serde_json::from_slice(&bytes)
        .map_err(|e| InternalError(format!("malformed BOM {}: {e}", bom_path.display())))?;
    let refuse = |why: String| -> Result<u8, InternalError> {
        eprintln!("ni-ota-verify: commit REFUSED: {why}");
        Ok(EXIT_REFUSE)
    };
    if let Err(reason) = bom.require_media_independent() {
        return refuse(reason);
    }
    let hardware_target = immutable_hardware_target()?;
    let bom_sha = runner::sha256_file(bom_snapshot.path())?;
    if bom_snapshot.read()? != bytes {
        return Err(InternalError(
            "protected BOM snapshot changed during commit".to_string(),
        ));
    }

    if bom.hardware_target != hardware_target {
        return refuse(format!(
            "BOM hardware_target '{}' does not match immutable host target '{hardware_target}'",
            bom.hardware_target
        ));
    }
    let mut ring_to_commit = active_ring.cloned();
    match store.read() {
        // First commit seeds the record (P2 shadow burn-in; P3's NV seeding
        // reads exactly this record — plan P3). On a TPM-anchored appliance
        // (NV indices configured) seeding authority belongs exclusively to the
        // media-verified bootstrap path: a lost state file with persisting TPM
        // floors must not let commit mint a fresh media-independent marker.
        Ok(StateRead::Unseeded) => {
            if cfg.nv_index.is_some() {
                return refuse(format!(
                    "state at {} is unseeded while TPM anchoring is configured — baseline seeding belongs to the verified bootstrap path; reinstall from verified final media (ADR-0012)",
                    store.describe()
                ));
            }
            if active_ring.is_some() && active_ring != previous_ring {
                return refuse("an unseeded state cannot claim a ring promotion".into());
            }
        }
        Ok(StateRead::Applied(applied)) => {
            if ring_to_commit.is_none() {
                ring_to_commit = applied.active_ring.clone();
            }
            if !applied.is_media_independent() {
                return refuse(format!(
                    "applied baseline at {} was recorded by a media-era verifier (no media-independent format marker) — implicit migration is unsupported; reinstall from verified final media (ADR-0012)",
                    store.describe()
                ));
            }
            if bom.bundle_seq < applied.bundle_seq {
                return refuse(format!(
                    "bundle_seq {} would LOWER the applied seq {} (anti-rollback is forward-only)",
                    bom.bundle_seq, applied.bundle_seq
                ));
            }
            if bom.bundle_seq == applied.bundle_seq && bom_sha != applied.bom_sha256 {
                return refuse(format!(
                    "bundle_seq {} equals the applied seq but the BOM hash differs — forgery signal, not a repair",
                    bom.bundle_seq
                ));
            }
            match (active_ring, previous_ring, applied.active_ring.as_deref()) {
                (Some(_), Some(previous), Some(ring)) if ring != previous => {
                    return refuse("--previous-ring does not equal durable active_ring".into())
                }
                (Some(_), Some(previous), None)
                    if !matches!(previous.as_str(), "beta" | "stable") =>
                {
                    return refuse("legacy ring migration is limited to beta or stable".into())
                }
                _ => {}
            }
            if active_ring.is_some()
                && active_ring != previous_ring
                && (bom.bundle_seq != applied.bundle_seq || bom_sha != applied.bom_sha256)
            {
                return refuse(
                    "ring promotion requires identical bundle sequence and BOM bytes".into(),
                );
            }
            // equal seq + equal hash = idempotent repair re-commit: allowed.
        }
        // Never overwrite state we cannot read — a corrupt record needs an
        // operator (P2) / the P3 drill runbook, not a silent reset.
        Err(why) => {
            return refuse(format!(
                "applied state unusable ({why}) — refusing to overwrite it"
            ))
        }
    }

    // Integration-test-only race seam. The production image builds without
    // `test-path-overrides`, so no delay or environment-controlled behavior is
    // present in the shipped verifier.
    #[cfg(feature = "test-path-overrides")]
    test_delay_after_read()?;

    let state = AppliedState {
        bundle_seq: bom.bundle_seq,
        bom_sha256: bom_sha,
        bom_format: Some(crate::state::BOM_FORMAT_MEDIA_INDEPENDENT_V1.to_string()),
        active_ring: ring_to_commit,
    };
    store.write(&state)?;
    let receipt = serde_json::json!({
        "committed": true,
        "bundle_seq": state.bundle_seq,
        "hardware_target": hardware_target,
        "bom_sha256": state.bom_sha256,
        "active_ring": state.active_ring,
    });
    println!("{receipt}");
    eprintln!(
        "ni-ota-verify: committed applied state (bundle_seq {}, {})",
        state.bundle_seq,
        store.describe()
    );
    Ok(EXIT_PASS)
}

#[cfg(feature = "test-path-overrides")]
fn test_delay_after_read() -> Result<(), InternalError> {
    if let Some(path) = std::env::var_os("NI_OTA_TEST_COMMIT_READY") {
        std::fs::write(PathBuf::from(path), b"ready\n")
            .map_err(|e| InternalError(format!("cannot publish commit test barrier: {e}")))?;
    }
    let Some(raw) = std::env::var_os("NI_OTA_TEST_COMMIT_DELAY_MS") else {
        return Ok(());
    };
    let millis = raw.to_string_lossy().parse::<u64>().map_err(|e| {
        InternalError(format!(
            "invalid NI_OTA_TEST_COMMIT_DELAY_MS '{}': {e}",
            raw.to_string_lossy()
        ))
    })?;
    std::thread::sleep(std::time::Duration::from_millis(millis));
    Ok(())
}
