//! Verify and atomically commit one complete OTA state generation.

use std::path::{Path, PathBuf};

use crate::config::{
    immutable_appliance_variant, immutable_hardware_target, immutable_minimum_delegation_seq,
    Config,
};
use crate::delegated::beta::{
    authorized_key, device_compatibility, validate_release, ReleaseAuthorization, RELEASE_DOMAIN,
};
use crate::delegated::contract::{canonical_hash, parse_canonical, public_key_pem, ContractError};
use crate::delegated::{authenticate_snapshot, freeze, freeze_root, verify_signature};
use crate::state_v1::{
    AppliedStateV1, AuthorityState, Candidate, CommandTpm, NvAnchor, PreapplyCandidate, Store,
    TimeChallenge, TrustedTimeState, STATE_NV_INDEX,
};
use crate::trusted_time::{self, ExpectedTrustedTime, TrustedTimeAssertion};
use crate::verify::BomCore;
use crate::{parse_flags, runner, InternalError, DEFAULT_CONFIG, EXIT_PASS, EXIT_REFUSE};

pub(crate) fn run(args: &[String]) -> Result<u8, InternalError> {
    execute(args, true)
}

pub(crate) fn guard(args: &[String]) -> Result<u8, InternalError> {
    execute(args, false)
}

fn execute(args: &[String], commit: bool) -> Result<u8, InternalError> {
    let flags = parse_flags(
        args,
        &[
            "bom",
            "config",
            "release",
            "release-sig",
            "snapshot",
            "snapshot-sig",
            "trusted-time",
            "trusted-time-sig",
        ],
    )?;
    let required = |name: &str| -> Result<PathBuf, InternalError> {
        flags
            .get(name)
            .map(PathBuf::from)
            .ok_or_else(|| InternalError(format!("commit-state-v2: --{name} is required")))
    };
    let config = Config::load(Path::new(
        flags.get("config").map_or(DEFAULT_CONFIG, String::as_str),
    ))?;
    if config.nv_index != Some(0x0150_0001) || config.state_nv_index != Some(STATE_NV_INDEX) {
        return refusal("atomic state requires fixed TPM indices 0x01500001/0x01500002".into());
    }
    let ring = config
        .device_channel
        .as_deref()
        .ok_or_else(|| InternalError("device_channel is required".into()))?;
    let state_dir = config
        .state_dir
        .as_deref()
        .ok_or_else(|| InternalError("state_dir is required".into()))?;
    let root_path = config
        .root_pubkey
        .as_deref()
        .ok_or_else(|| InternalError("root_pubkey is required".into()))?;
    let target = immutable_hardware_target()?;
    let store = Store {
        root: state_dir.join("state-v1"),
    };
    let scratch = store.lock_store();
    let _lock = scratch.lock_commit()?;
    macro_rules! artifact {
        ($flag:literal, $label:literal) => {
            freeze(&scratch, &required($flag)?, $label)?
        };
    }
    let snapshot_file = artifact!("snapshot", "state-v2-snapshot");
    let snapshot_sig = artifact!("snapshot-sig", "state-v2-snapshot-signature");
    let release_file = artifact!("release", "state-v2-release");
    let release_sig = artifact!("release-sig", "state-v2-release-signature");
    let assertion_file = artifact!("trusted-time", "state-v2-trusted-time");
    let assertion_sig = artifact!("trusted-time-sig", "state-v2-trusted-time-signature");
    let bom_file = artifact!("bom", "state-v2-bom");
    let root = match freeze_root(&scratch, root_path, "state-v2-root")? {
        Ok(value) => value,
        Err(reason) => return refusal(reason),
    };

    let snapshot_bytes = snapshot_file.read()?;
    let snapshot_signature = snapshot_sig.read()?;
    let root_bytes = root.read()?;
    let authenticated_snapshot =
        match authenticate_snapshot(&snapshot_bytes, &snapshot_signature, &root_bytes, &scratch) {
            Ok(value) => value,
            Err(error) => return contract_refusal(error),
        };
    let snapshot = authenticated_snapshot.snapshot();
    if snapshot.delegation_seq < immutable_minimum_delegation_seq()? {
        return refusal("snapshot is below immutable delegation sequence floor".into());
    }
    let snapshot_hash = authenticated_snapshot.canonical_sha256();

    let release_bytes = release_file.read()?;
    let release_signature = release_sig.read()?;
    let release: ReleaseAuthorization =
        match parse_canonical(&release_bytes, "release authorization") {
            Ok(value) => value,
            Err(reason) => return refusal(reason),
        };
    let release_hash = match canonical_hash(&release_bytes) {
        Ok(value) => value,
        Err(error) => return contract_refusal(error),
    };
    let assertion_bytes = assertion_file.read()?;
    let (challenge, pending_challenge) =
        match std::fs::symlink_metadata(store.root.join("pending-time-challenge.json")) {
            Ok(_) => (store.pending_time_challenge()?, true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && commit => {
                let assertion: TrustedTimeAssertion =
                    match parse_canonical(&assertion_bytes, "trusted-time assertion") {
                        Ok(value) => value,
                        Err(reason) => return refusal(reason),
                    };
                (
                    TimeChallenge {
                        delegation_snapshot_sha256: assertion.delegation_snapshot_sha256,
                        device_fingerprint: assertion.device_fingerprint,
                        hardware_target: assertion.hardware_target,
                        nonce: assertion.nonce,
                        release_authorization_sha256: assertion.release_authorization_sha256,
                        ring: assertion.ring,
                        schema: "neural-ice-ota-time-challenge-v2".into(),
                        state_nv_anchor: assertion.state_nv_anchor,
                        tpm_clock: assertion.tpm_clock,
                        tpm_reset_count: assertion.tpm_reset_count,
                        tpm_restart_count: assertion.tpm_restart_count,
                        tpm_safe: assertion.tpm_safe,
                    },
                    false,
                )
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return refusal("trusted-time challenge is absent".into())
            }
            Err(error) => {
                return Err(InternalError(format!(
                    "cannot inspect pending trusted-time challenge: {error}"
                )))
            }
        };
    let tpm = CommandTpm {
        index: STATE_NV_INDEX,
        scratch: crate::state::FileStateStore {
            path: scratch.path.clone(),
        },
    };
    let assertion_signature = assertion_sig.read()?;
    let trusted = if pending_challenge {
        let now_clock = tpm.clock()?;
        if !now_clock.safe
            || now_clock.reset_count != challenge.tpm_reset_count
            || now_clock.restart_count != challenge.tpm_restart_count
            || now_clock.clock < challenge.tpm_clock
        {
            return refusal("TPM continuity changed after challenge issuance".into());
        }
        let expected = ExpectedTrustedTime {
            delegation_snapshot_sha256: snapshot_hash,
            device_fingerprint: &challenge.device_fingerprint,
            hardware_target: &target,
            nonce: &challenge.nonce,
            release_authorization_sha256: &release_hash,
            ring,
            state_nv_anchor: &challenge.state_nv_anchor,
            tpm_clock: challenge.tpm_clock,
            tpm_reset_count: challenge.tpm_reset_count,
            tpm_restart_count: challenge.tpm_restart_count,
            tpm_safe: challenge.tpm_safe,
            consumption_tpm_clock: now_clock.clock,
            consumption_tpm_reset_count: now_clock.reset_count,
            consumption_tpm_restart_count: now_clock.restart_count,
            consumption_tpm_safe: now_clock.safe,
        };
        let trusted = match trusted_time::verify(
            &authenticated_snapshot,
            &assertion_bytes,
            &assertion_signature,
            &expected,
            &scratch,
        ) {
            Ok(value) => value,
            Err(error) => return contract_refusal(error),
        };
        if let Err(reason) = validate_release(
            &release,
            snapshot,
            snapshot_hash,
            &trusted.effective_time,
            &target,
        ) {
            return refusal(reason);
        }
        if let Err(reason) = device_compatibility(&release, config.device_compat) {
            return refusal(reason);
        }
        let release_key = match authorized_key(
            snapshot,
            &release.key_id,
            "beta-release-authorization",
            &target,
            &release.issued_at,
            &trusted.effective_time,
        ) {
            Ok(value) => value,
            Err(reason) => return refusal(reason),
        };
        let release_key = match public_key_pem(&release_key.public_key) {
            Ok(value) => value,
            Err(error) => return contract_refusal(error),
        };
        if let Err(reason) = verify_signature(
            &release_key,
            RELEASE_DOMAIN,
            &release_bytes,
            &release_signature,
            &scratch,
        )? {
            return refusal(reason);
        }
        trusted
    } else {
        // A commit that already consumed its challenge can only recover an
        // exact durable receipt.  TPM restart counters may legitimately have
        // advanced before stdout was observed, so do not re-run live evidence
        // checks here; `exact_receipt_locked` compares every artifact byte.
        match trusted_time::receipt_evidence(&assertion_bytes, &assertion_signature) {
            Ok(value) => value,
            Err(error) => return contract_refusal(error),
        }
    };

    let bom_bytes = bom_file.read()?;
    let bom: BomCore = serde_json::from_slice(&bom_bytes)
        .map_err(|error| InternalError(format!("malformed state-v2 BOM: {error}")))?;
    if let Err(reason) = bom.require_media_independent() {
        return refusal(reason);
    }
    let bom_hash = runner::sha256_bytes(&bom_bytes)?;
    if let Err(reason) = validate_bom_binding(
        &bom,
        &release,
        &bom_hash,
        &target,
        &immutable_appliance_variant()?,
        ring,
    ) {
        return refusal(reason);
    }
    let trusted_state = TrustedTimeState {
        assertion_seq: trusted.assertion_seq,
        assertion_sha256: trusted.assertion_sha256.clone(),
        challenge_sha256: trusted.nonce_sha256.clone(),
        delegation_seq: trusted.delegation_seq,
        device_fingerprint: trusted.device_fingerprint.clone(),
        key_id: trusted.key_id.clone(),
        schema: "neural-ice-ota-trusted-time-state-v2".into(),
        signature_sha256: trusted.signature_sha256.clone(),
        tpm_clock: challenge.tpm_clock,
        tpm_reset_count: challenge.tpm_reset_count,
        tpm_restart_count: challenge.tpm_restart_count,
        tpm_safe: true,
        trusted_time: trusted.trusted_time.clone(),
    };
    let preapply = PreapplyCandidate {
        bom_sha256: &bom_hash,
        bundle_seq: bom.bundle_seq,
        challenge: &challenge,
        snapshot,
        snapshot_sha256: snapshot_hash,
        snapshot_signature: &snapshot_signature,
        trusted: &trusted_state,
        trusted_assertion: &assertion_bytes,
    };
    // Rerun the complete preapply gate immediately before every mutation,
    // including initial state-v1 seeding.  The guard owns the explicit
    // zero-anchor/legacy-floor rules; no controller ordering is trusted.
    if pending_challenge {
        match store.guard_preapply_locked(&tpm, &preapply)? {
            Ok(()) => {}
            Err(reason) => return refusal(reason),
        }
    }
    if !commit {
        println!(
            "{{\"bundle_seq\":{},\"release_authorization_sha256\":\"{}\",\"schema\":\"neural-ice-ota-state-preapply-receipt-v2\",\"verdict\":\"pass\"}}",
            bom.bundle_seq, release_hash
        );
        return Ok(EXIT_PASS);
    }
    let candidate = Candidate {
        applied: AppliedStateV1 {
            bom_sha256: bom_hash,
            bundle_seq: bom.bundle_seq,
            schema: "neural-ice-ota-applied-state-v1".into(),
        },
        authority: AuthorityState {
            delegation_seq: snapshot.delegation_seq,
            schema: "neural-ice-ota-authority-state-v1".into(),
            snapshot_sha256: snapshot_hash.to_owned(),
            snapshot_signature_sha256: runner::sha256_bytes(&snapshot_signature)?,
        },
        challenge: challenge.clone(),
        release: &release_bytes,
        release_signature: &release_signature,
        snapshot: &snapshot_bytes,
        snapshot_signature: &snapshot_signature,
        trusted: trusted_state,
        trusted_assertion: &assertion_bytes,
        trusted_signature: &assertion_signature,
    };
    let receipt = if pending_challenge {
        store.commit_locked(&candidate, &tpm)?
    } else {
        store.exact_receipt_locked(&candidate, &tpm)?
    };
    match receipt {
        Ok(receipt) => {
            println!(
                "{{\"enforce_ready\":true,\"generation\":{},\"manifest_sha256\":\"{}\",\"nv_anchor\":\"{}\",\"schema\":\"neural-ice-ota-state-commit-receipt-v2\"}}",
                receipt.generation, receipt.manifest_sha256, receipt.nv_anchor
            );
            Ok(EXIT_PASS)
        }
        Err(reason) => refusal(reason),
    }
}

fn contract_refusal(error: ContractError) -> Result<u8, InternalError> {
    match error {
        ContractError::Refusal(reason) => refusal(reason),
        ContractError::Internal(error) => Err(error),
    }
}

fn refusal(reason: String) -> Result<u8, InternalError> {
    eprintln!("ni-ota-verify: state-v2 REFUSED: {reason}");
    Ok(EXIT_REFUSE)
}

fn validate_bom_binding(
    bom: &BomCore,
    release: &ReleaseAuthorization,
    bom_hash: &str,
    target: &str,
    variant: &str,
    ring: &str,
) -> Result<(), String> {
    if bom.bundle_seq == 0
        || bom.train != release.train
        || bom.hardware_target != target
        || release.hardware_target != target
        || release.bundle_seq != bom.bundle_seq
        || release.bom_sha256 != bom_hash
        || bom.compat_min != i64::try_from(release.compat_min).ok()
        || bom.compat_version != i64::try_from(release.compat_max).ok()
        || release.variant != variant
        || release.ring != ring
    {
        return Err("release does not bind the exact applied BOM and host scope".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bom() -> BomCore {
        BomCore {
            appliance: None,
            bundle_seq: 19,
            compat_min: Some(5),
            compat_version: Some(5),
            hardware_target: "nvidia-gb10-arm64".into(),
            sources: None,
            train: "0.44.19".into(),
        }
    }

    fn release() -> ReleaseAuthorization {
        serde_json::from_slice(include_bytes!(
            "../tests/fixtures/delegated-v1/release-authorization.json"
        ))
        .unwrap()
    }

    #[test]
    fn exact_bom_release_scope_is_required() {
        let mut release = release();
        release.bom_sha256 = "a".repeat(64);
        assert!(validate_bom_binding(
            &bom(),
            &release,
            &"a".repeat(64),
            "nvidia-gb10-arm64",
            "prod",
            "beta"
        )
        .is_ok());

        let mut wrong_train = bom();
        wrong_train.train = "0.44.20".into();
        assert!(validate_bom_binding(
            &wrong_train,
            &release,
            &"a".repeat(64),
            "nvidia-gb10-arm64",
            "prod",
            "beta"
        )
        .is_err());

        let mut wrong_compat = bom();
        wrong_compat.compat_version = Some(6);
        assert!(validate_bom_binding(
            &wrong_compat,
            &release,
            &"a".repeat(64),
            "nvidia-gb10-arm64",
            "prod",
            "beta"
        )
        .is_err());
    }
}
