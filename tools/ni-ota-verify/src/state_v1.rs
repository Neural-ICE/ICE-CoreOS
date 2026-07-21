//! TPM capability gate for the atomic OTA state chain.
//!
//! This non-mutating layer recovers only complete generations whose manifest
//! chain reproduces the observed TPM anchor. The public capability remains
//! gated until the complete guard/commit command set lands.

use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};

use crate::delegated::contract::{
    canonical_hash, parse_canonical, safe_uint, sha256, timestamp, validate_chain, ContractError,
    Snapshot,
};
use crate::runner;
use crate::state::{
    ensure_secure_state_directory, validate_secure_state_directory, FileStateStore, O_NOFOLLOW,
};
use crate::InternalError;

pub(crate) const STATE_NV_INDEX: u32 = 0x0150_0002;
pub(crate) const LEGACY_NV_INDEX: u32 = 0x0150_0001;
const TRUSTED_TIME_MAX_ELAPSED_MS: u64 = 600_000;
// ADR-0013 reserves 0x81010004 for the appliance PKI. The installer-owned,
// non-exportable OTA/licensing device root is provisioned at this separate
// handle before trusted-time preparation is available on a clean install.
const DEVICE_ROOT_HANDLE: u32 = 0x8101_0005;
const DEVICE_ROOT_HELPER: &str = "/usr/libexec/neural-ice-device-root";
const DEVICE_ROOT_IDENTITY: &str = "/var/lib/neural-ice/ota/device-root-v1.json";
const DEVICE_ROOT_SCHEMA: &str = "neural-ice-device-root-tpm-v1";
const DEVICE_ROOT_ATTRIBUTES: &str =
    "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign|noda";
const STATE_NV_ATTRIBUTES: &str =
    "authread|authwrite|no_da|nt=0x1|ownerread|platformcreate|policydelete";
const STATE_NV_DELETE_AUTH_POLICY: &str =
    "921f9fa2ce8c30bbf29b84500a8456188f1febc04f154e9eccca4d5b1bc8a25d";
const STATE_NV_NAME_UNWRITTEN: &str =
    "000b8ae052b814918370b191fe38782bb500041130d0665b1e7b2a368edcaf81eb62";
const STATE_NV_NAME_WRITTEN: &str =
    "000b571132a9688f4088f3696fa9bf5d5793be7483202cee08ceb2261f2bbe89b440";
const ZERO_ANCHOR: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const GENERATION_ARTIFACTS: &[&str] = &[
    "applied.json",
    "authority.json",
    "delegation-snapshot.json",
    "delegation-snapshot.sig",
    "manifest.json",
    "release-authorization.json",
    "release-authorization.sig",
    "trusted-time-assertion.json",
    "trusted-time-assertion.sig",
    "trusted-time.json",
];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AuthorityState {
    pub(crate) delegation_seq: u64,
    pub(crate) schema: String,
    pub(crate) snapshot_sha256: String,
    pub(crate) snapshot_signature_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AppliedStateV1 {
    pub(crate) bom_sha256: String,
    pub(crate) bundle_seq: u64,
    pub(crate) schema: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TrustedTimeState {
    pub(crate) assertion_seq: u64,
    pub(crate) assertion_sha256: String,
    pub(crate) challenge_sha256: String,
    pub(crate) delegation_seq: u64,
    pub(crate) device_fingerprint: String,
    pub(crate) key_id: String,
    pub(crate) schema: String,
    pub(crate) signature_sha256: String,
    pub(crate) tpm_clock: u64,
    pub(crate) tpm_reset_count: u32,
    pub(crate) tpm_restart_count: u32,
    pub(crate) tpm_safe: bool,
    pub(crate) trusted_time: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StateManifest {
    applied_sha256: String,
    applied_bom_sha256: String,
    authority_sha256: String,
    bundle_seq_floor: u64,
    delegation_seq_floor: u64,
    delegation_snapshot_canonical_sha256: String,
    delegation_snapshot_sha256: String,
    delegation_snapshot_signature_sha256: String,
    generation: u64,
    legacy_bundle_floor: Option<u64>,
    previous_manifest_sha256: Option<String>,
    previous_nv_anchor: String,
    release_authorization_sha256: String,
    release_authorization_signature_sha256: String,
    schema: String,
    trusted_time_assertion_canonical_sha256: String,
    trusted_time_assertion_sha256: String,
    trusted_time_assertion_signature_sha256: String,
    trusted_time_floor: String,
    trusted_time_seq_floor: u64,
    trusted_time_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LoadedGeneration {
    manifest: StateManifest,
    manifest_sha256: String,
    nv_anchor: String,
    trusted: TrustedTimeState,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TimeChallenge {
    pub(crate) delegation_snapshot_sha256: String,
    pub(crate) device_fingerprint: String,
    pub(crate) hardware_target: String,
    pub(crate) nonce: String,
    pub(crate) release_authorization_sha256: String,
    pub(crate) ring: String,
    pub(crate) schema: String,
    pub(crate) state_nv_anchor: String,
    pub(crate) tpm_clock: u64,
    pub(crate) tpm_reset_count: u32,
    pub(crate) tpm_restart_count: u32,
    pub(crate) tpm_safe: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceRootReceipt {
    attributes: String,
    curve: String,
    handle: String,
    hierarchy: String,
    name: String,
    name_algorithm: String,
    public_area_sha256: String,
    qualified_name: String,
    schema: String,
    scheme: String,
    spki_sha256: String,
}

#[derive(Default)]
struct GenerationScan {
    has_evidence: bool,
    numbers: Vec<u64>,
}

#[allow(dead_code, reason = "constructed by the next stacked command layer")]
pub(crate) struct Candidate<'a> {
    pub(crate) applied: AppliedStateV1,
    pub(crate) authority: AuthorityState,
    pub(crate) challenge: TimeChallenge,
    pub(crate) release: &'a [u8],
    pub(crate) release_signature: &'a [u8],
    pub(crate) snapshot: &'a [u8],
    pub(crate) snapshot_signature: &'a [u8],
    pub(crate) trusted: TrustedTimeState,
    pub(crate) trusted_assertion: &'a [u8],
    pub(crate) trusted_signature: &'a [u8],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CommitReceipt {
    pub(crate) generation: u64,
    pub(crate) manifest_sha256: String,
    pub(crate) nv_anchor: String,
}

pub(crate) struct PreapplyCandidate<'a> {
    pub(crate) bom_sha256: &'a str,
    pub(crate) bundle_seq: u64,
    pub(crate) challenge: &'a TimeChallenge,
    pub(crate) snapshot: &'a Snapshot,
    pub(crate) snapshot_sha256: &'a str,
    pub(crate) snapshot_signature: &'a [u8],
    pub(crate) trusted: &'a TrustedTimeState,
    pub(crate) trusted_assertion: &'a [u8],
}

pub(crate) struct Store {
    pub(crate) root: PathBuf,
}

// A readable store and TPM index are not by themselves an update protocol.
// This changes only with the complete guard/commit command set and controller.
const STATE_V1_COMMAND_SET_READY: bool = false;

pub(crate) fn capability_ready(config_path: &Path) -> Result<bool, InternalError> {
    capability_ready_for(config_path, STATE_V1_COMMAND_SET_READY)
}

fn capability_ready_for(
    config_path: &Path,
    command_set_ready: bool,
) -> Result<bool, InternalError> {
    if !command_set_ready {
        return Ok(false);
    }
    let config = crate::config::Config::load(config_path)?;
    if config.nv_index != Some(LEGACY_NV_INDEX) || config.state_nv_index != Some(STATE_NV_INDEX) {
        return Err(InternalError(
            "atomic-state command set is compiled but TPM indices are not exactly configured"
                .into(),
        ));
    }
    let state_dir = config.state_dir.ok_or_else(|| {
        InternalError("atomic-state command set is compiled but state_dir is not configured".into())
    })?;
    let tpm = CommandTpm {
        index: STATE_NV_INDEX,
        scratch: FileStateStore {
            path: state_dir.join("state-v1-capability.json"),
        },
    };
    let store = Store {
        root: state_dir.join("state-v1"),
    };
    continuity_ready(&tpm)?;
    store.verify_enforce_ready(&tpm)?;
    Ok(true)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TpmClockState {
    pub(crate) clock: u64,
    pub(crate) reset_count: u32,
    pub(crate) restart_count: u32,
    pub(crate) safe: bool,
}

pub(crate) trait NvAnchor {
    fn attest(&self) -> Result<(), InternalError>;
    fn read(&self) -> Result<[u8; 32], InternalError>;
    fn legacy_bundle_floor(&self) -> Result<Option<u64>, InternalError>;
    fn clock(&self) -> Result<TpmClockState, InternalError>;
    fn read_initial(&self) -> Result<[u8; 32], InternalError>;
    fn provision_initial(&self) -> Result<(), InternalError>;
    fn extend(&self, digest: [u8; 32]) -> Result<(), InternalError>;
}

pub(crate) struct CommandTpm {
    pub(crate) index: u32,
    pub(crate) scratch: FileStateStore,
}

impl NvAnchor for CommandTpm {
    fn attest(&self) -> Result<(), InternalError> {
        if self.inspect()? {
            Ok(())
        } else {
            Err(InternalError(format!(
                "TPM NV 0x{:08x} is defined but has no committed state anchor",
                self.index
            )))
        }
    }

    fn read(&self) -> Result<[u8; 32], InternalError> {
        let output = self.scratch.secure_temp_bytes("nv-read", &[])?;
        let status = Command::new(tool("tpm2_nvread"))
            .args([
                format!("0x{:08x}", self.index),
                "-C".into(),
                format!("0x{:08x}", self.index),
                "-s".into(),
                "32".into(),
                "-o".into(),
            ])
            .arg(output.path())
            .status()
            .map_err(|error| InternalError(format!("cannot execute tpm2_nvread: {error}")))?;
        if !status.success() {
            return Err(InternalError(format!(
                "tpm2_nvread failed for initialized 0x{:08x}",
                self.index
            )));
        }
        output.read()?.try_into().map_err(|_| {
            InternalError(format!(
                "TPM NV 0x{:08x} did not return exactly 32 bytes",
                self.index
            ))
        })
    }

    fn legacy_bundle_floor(&self) -> Result<Option<u64>, InternalError> {
        let output = self.scratch.secure_temp_bytes("legacy-nv-read", &[])?;
        let status = Command::new(tool("tpm2_nvread"))
            .args([
                format!("0x{LEGACY_NV_INDEX:08x}"),
                "-C".into(),
                format!("0x{LEGACY_NV_INDEX:08x}"),
                "-s".into(),
                "8".into(),
                "-o".into(),
            ])
            .arg(output.path())
            .status()
            .map_err(|error| InternalError(format!("cannot read legacy TPM floor: {error}")))?;
        if !status.success() {
            let handles = Command::new(tool("tpm2_getcap"))
                .arg("handles-nv-index")
                .output()
                .map_err(|error| {
                    InternalError(format!("cannot enumerate TPM NV handles: {error}"))
                })?;
            if !handles.status.success() {
                return Err(InternalError("cannot enumerate TPM NV handles".into()));
            }
            let handles = String::from_utf8(handles.stdout)
                .map_err(|_| InternalError("TPM NV handle list is not UTF-8".into()))?;
            if contains_nv_handle(&handles, LEGACY_NV_INDEX) {
                return Err(InternalError(
                    "legacy TPM floor exists but cannot be read exactly".into(),
                ));
            }
            return Ok(None);
        }
        let bytes: [u8; 8] = output
            .read()?
            .try_into()
            .map_err(|_| InternalError("legacy TPM floor is not exactly 8 bytes".into()))?;
        Ok(Some(u64::from_be_bytes(bytes)))
    }

    fn clock(&self) -> Result<TpmClockState, InternalError> {
        let output = Command::new(tool("tpm2_readclock"))
            .output()
            .map_err(|error| InternalError(format!("cannot execute tpm2_readclock: {error}")))?;
        if !output.status.success() {
            return Err(InternalError("tpm2_readclock failed".into()));
        }
        parse_clock(
            &String::from_utf8(output.stdout)
                .map_err(|_| InternalError("tpm2_readclock returned non-UTF-8 output".into()))?,
        )
    }

    fn read_initial(&self) -> Result<[u8; 32], InternalError> {
        self.initial_or_existing_anchor()
            .and_then(|value| decode_hash(&value))
    }

    fn provision_initial(&self) -> Result<(), InternalError> {
        if self.index_present()? {
            if !self.inspect()? {
                // A prior first commit can crash after NV_Define but before
                // its first extend. The exact, policy-attested unwritten
                // index is the same zero anchor and may resume; any written
                // or malformed occupied index remains non-reseedable.
                return Ok(());
            }
            return Err(InternalError(
                "state-v1 index already exists; automatic reseeding is forbidden".into(),
            ));
        }
        let policy = self.scratch.secure_temp_bytes(
            "state-nv-delete-policy",
            &decode_hash(STATE_NV_DELETE_AUTH_POLICY)?,
        )?;
        let status = Command::new(tool("tpm2_nvdefine"))
            .args(nvdefine_args(self.index, policy.path()))
            .status()
            .map_err(|error| InternalError(format!("cannot execute tpm2_nvdefine: {error}")))?;
        if !status.success() {
            return Err(InternalError(format!(
                "cannot provision TPM NV 0x{:08x}",
                self.index
            )));
        }
        if self.inspect()? {
            return Err(InternalError(
                "new state-v1 index is unexpectedly written before its first extend".into(),
            ));
        }
        Ok(())
    }

    fn extend(&self, digest: [u8; 32]) -> Result<(), InternalError> {
        let input = self.scratch.secure_temp_bytes("nv-extend", &digest)?;
        let status = Command::new(tool("tpm2_nvextend"))
            .args([
                format!("0x{:08x}", self.index),
                "-C".into(),
                format!("0x{:08x}", self.index),
                "-i".into(),
            ])
            .arg(input.path())
            .status()
            .map_err(|error| InternalError(format!("cannot execute tpm2_nvextend: {error}")))?;
        if status.success() {
            Ok(())
        } else {
            Err(InternalError(format!(
                "tpm2_nvextend failed for 0x{:08x}",
                self.index
            )))
        }
    }
}

fn nvdefine_args(index: u32, policy: &Path) -> Vec<OsString> {
    vec![
        format!("0x{index:08x}").into(),
        "-C".into(),
        "p".into(),
        "-s".into(),
        "32".into(),
        "-a".into(),
        STATE_NV_ATTRIBUTES.into(),
        "-L".into(),
        policy.as_os_str().to_owned(),
    ]
}

fn continuity_ready(tpm: &impl NvAnchor) -> Result<bool, InternalError> {
    tpm.attest()?;
    tpm.read()?;
    if tpm.legacy_bundle_floor()?.is_none() {
        return Err(InternalError(
            "legacy TPM bundle floor is absent while atomic-state is compiled".into(),
        ));
    }
    if !tpm.clock()?.safe {
        return Err(InternalError("TPM clock is not safe".into()));
    }
    Ok(true)
}

impl CommandTpm {
    fn index_present(&self) -> Result<bool, InternalError> {
        let handles = Command::new(tool("tpm2_getcap"))
            .arg("handles-nv-index")
            .output()
            .map_err(|error| InternalError(format!("cannot enumerate TPM NV handles: {error}")))?;
        if !handles.status.success() {
            return Err(InternalError("cannot enumerate TPM NV handles".into()));
        }
        let handles = String::from_utf8(handles.stdout)
            .map_err(|_| InternalError("TPM NV handle list is not UTF-8".into()))?;
        Ok(contains_nv_handle(&handles, self.index))
    }

    fn inspect(&self) -> Result<bool, InternalError> {
        let output = Command::new(tool("tpm2_nvreadpublic"))
            .arg(format!("0x{:08x}", self.index))
            .output()
            .map_err(|error| InternalError(format!("cannot execute tpm2_nvreadpublic: {error}")))?;
        if !output.status.success() {
            return Err(InternalError(format!(
                "tpm2_nvreadpublic failed for 0x{:08x}",
                self.index
            )));
        }
        inspect_state_index(
            &String::from_utf8(output.stdout)
                .map_err(|_| InternalError("tpm2_nvreadpublic returned non-UTF-8 output".into()))?,
            self.index,
        )
    }

    fn initial_or_existing_anchor(&self) -> Result<String, InternalError> {
        if !self.index_present()? {
            return Ok(ZERO_ANCHOR.to_owned());
        }
        if !self.inspect()? {
            // An exact EXTEND index is unreadable until its first extend.
            // Treat its attested unwritten state as the logical zero anchor.
            return Ok(ZERO_ANCHOR.to_owned());
        }
        self.read().map(hex)
    }

    fn device_fingerprint(&self) -> Result<String, InternalError> {
        let receipt = self.attested_device_root_receipt()?;
        let output = self
            .scratch
            .secure_temp_bytes("device-root-public", b"pending")?;
        let status = Command::new(tool("tpm2_readpublic"))
            .args([
                "-Q",
                "-c",
                &format!("0x{DEVICE_ROOT_HANDLE:08x}"),
                "-f",
                "der",
                "-o",
            ])
            .arg(output.path())
            .status()
            .map_err(|error| InternalError(format!("cannot read TPM device root: {error}")))?;
        if !status.success() {
            return Err(InternalError(format!(
                "cannot read TPM device root handle 0x{DEVICE_ROOT_HANDLE:08x}"
            )));
        }
        let observed_spki_sha256 = runner::sha256_file(output.path())?;
        if observed_spki_sha256 != receipt.spki_sha256 {
            return Err(InternalError(
                "TPM device root changed after ADR-0013 attestation".into(),
            ));
        }
        runner::sha256_bytes(format!("tpm-pub-v1:{}", receipt.spki_sha256).as_bytes())
    }

    fn attested_device_root_receipt(&self) -> Result<DeviceRootReceipt, InternalError> {
        let output = Command::new(DEVICE_ROOT_HELPER)
            .args(["attest", "--identity", DEVICE_ROOT_IDENTITY])
            .output()
            .map_err(|error| {
                InternalError(format!("cannot execute ADR-0013 device-root gate: {error}"))
            })?;
        if !output.status.success() {
            return Err(InternalError(
                "ADR-0013 device-root attestation/receipt gate refused trusted-time preparation"
                    .into(),
            ));
        }
        let receipt: DeviceRootReceipt = parse_canonical(&output.stdout, "device-root receipt")
            .map_err(|reason| {
                InternalError(format!("invalid attested device-root receipt: {reason}"))
            })?;
        validate_device_root_receipt(&receipt)?;
        Ok(receipt)
    }
}

fn validate_device_root_receipt(receipt: &DeviceRootReceipt) -> Result<(), InternalError> {
    let closed_name =
        |value: &str| value.len() == 68 && value.starts_with("000b") && sha256(&value[4..]);
    if receipt.attributes != DEVICE_ROOT_ATTRIBUTES
        || receipt.curve != "nist-p256"
        || receipt.handle != format!("0x{DEVICE_ROOT_HANDLE:08x}")
        || receipt.hierarchy != "endorsement"
        || receipt.name_algorithm != "sha256"
        || receipt.schema != DEVICE_ROOT_SCHEMA
        || receipt.scheme != "ecdsa-sha256"
        || !sha256(&receipt.public_area_sha256)
        || !sha256(&receipt.spki_sha256)
        || receipt.name != format!("000b{}", receipt.public_area_sha256)
        || !closed_name(&receipt.name)
        || !closed_name(&receipt.qualified_name)
    {
        return Err(InternalError(
            "attested device-root receipt is outside the ADR-0013 closed contract".into(),
        ));
    }
    Ok(())
}

impl Store {
    pub(crate) fn lock_store(&self) -> FileStateStore {
        FileStateStore {
            path: self.root.join("transaction.json"),
        }
    }

    pub(crate) fn issue_time_challenge(
        &self,
        tpm: &CommandTpm,
        delegation_snapshot_sha256: &str,
        release_authorization_sha256: &str,
        hardware_target: &str,
        ring: &str,
    ) -> Result<TimeChallenge, InternalError> {
        ensure_secure_state_directory(&self.root)?;
        let anchor = tpm.initial_or_existing_anchor()?;
        self.validate_challenge_continuity(tpm, &anchor)?;
        let clock = tpm.clock()?;
        if !clock.safe {
            return Err(InternalError("TPM clock is not safe".into()));
        }
        let challenge = TimeChallenge {
            delegation_snapshot_sha256: delegation_snapshot_sha256.to_owned(),
            device_fingerprint: tpm.device_fingerprint()?,
            hardware_target: hardware_target.to_owned(),
            nonce: fresh_nonce()?,
            release_authorization_sha256: release_authorization_sha256.to_owned(),
            ring: ring.to_owned(),
            schema: "neural-ice-ota-time-challenge-v2".into(),
            state_nv_anchor: anchor,
            tpm_clock: clock.clock,
            tpm_reset_count: clock.reset_count,
            tpm_restart_count: clock.restart_count,
            tpm_safe: clock.safe,
        };
        validate_time_challenge(&challenge)?;
        atomic_replace(
            &self.root,
            "pending-time-challenge.json",
            &canonical(&challenge)?,
        )?;
        let readback = self.pending_time_challenge()?;
        if readback != challenge {
            return Err(InternalError(
                "trusted-time challenge readback differs after publication".into(),
            ));
        }
        Ok(challenge)
    }

    fn validate_challenge_continuity(
        &self,
        nv: &dyn NvAnchor,
        anchor: &str,
    ) -> Result<(), InternalError> {
        let legacy_floor = nv
            .legacy_bundle_floor()?
            .ok_or_else(|| InternalError("legacy TPM bundle floor is absent".into()))?;
        if anchor == ZERO_ANCHOR {
            if self.has_prior_state_evidence()? {
                return Err(InternalError(
                    "zero TPM anchor with existing state history requires signed recovery".into(),
                ));
            }
        } else {
            let current = self.read_current_locked(nv)?.ok_or_else(|| {
                InternalError("nonzero TPM anchor has no complete state-v1 generation".into())
            })?;
            if current.manifest.legacy_bundle_floor != Some(legacy_floor) {
                return Err(InternalError(
                    "legacy floor differs from TPM-anchored state-v1 manifest".into(),
                ));
            }
        }
        Ok(())
    }

    fn has_prior_state_evidence(&self) -> Result<bool, InternalError> {
        if self.scan_generations()?.has_evidence {
            return Ok(true);
        }
        for entry in std::fs::read_dir(&self.root).map_err(|error| {
            InternalError(format!("cannot enumerate {}: {error}", self.root.display()))
        })? {
            let entry = entry
                .map_err(|error| InternalError(format!("cannot enumerate state-v1: {error}")))?;
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                return Ok(true);
            };
            if name == "generations"
                || name == "pending-time-challenge.json"
                || name == ".transaction.json.lock"
                || (name.starts_with(".transaction.json.") && name.ends_with(".tmp"))
            {
                continue;
            }
            return Ok(true);
        }
        Ok(false)
    }

    pub(crate) fn pending_time_challenge(&self) -> Result<TimeChallenge, InternalError> {
        let bytes = read_regular(&self.root.join("pending-time-challenge.json"), 0o600)?;
        let challenge: TimeChallenge =
            parse_canonical(&bytes, "trusted-time v2 challenge").map_err(InternalError)?;
        validate_time_challenge(&challenge)?;
        Ok(challenge)
    }

    pub(crate) fn guard_preapply(
        &self,
        nv: &dyn NvAnchor,
        candidate: &PreapplyCandidate<'_>,
    ) -> Result<Result<(), String>, InternalError> {
        let _lock = self.lock_store().lock_commit()?;
        self.guard_preapply_locked(nv, candidate)
    }

    fn guard_preapply_locked(
        &self,
        nv: &dyn NvAnchor,
        candidate: &PreapplyCandidate<'_>,
    ) -> Result<Result<(), String>, InternalError> {
        validate_preapply_candidate(candidate)?;
        if self.pending_time_challenge()? != *candidate.challenge {
            return Ok(Err("pending trusted-time challenge differs".into()));
        }
        if let Err(reason) = self.challenge_is_live(
            nv,
            candidate.challenge,
            candidate.trusted,
            candidate.trusted_assertion,
        )? {
            return Ok(Err(reason));
        }
        let anchor = hex(nv.read_initial()?);
        if candidate.challenge.state_nv_anchor != anchor {
            return Ok(Err("trusted-time challenge anchor is stale".into()));
        }
        if anchor == ZERO_ANCHOR {
            return if self.has_prior_state_evidence()? {
                Ok(Err("zero TPM anchor has existing state history".into()))
            } else {
                let Some(legacy_floor) = nv.legacy_bundle_floor()? else {
                    return Ok(Err(
                        "legacy TPM floor is absent before state-v1 seeding".into()
                    ));
                };
                if candidate.bundle_seq < legacy_floor {
                    return Ok(Err("candidate bundle is below legacy TPM floor".into()));
                }
                Ok(Ok(()))
            };
        }
        let current = self
            .read_current_locked(nv)?
            .ok_or_else(|| InternalError("TPM-anchored state is unavailable".into()))?;
        let legacy_floor = nv.legacy_bundle_floor()?;
        if current.manifest.legacy_bundle_floor.is_some() && legacy_floor.is_none() {
            return Ok(Err(
                "legacy TPM floor disappeared after state-v1 seeding".into()
            ));
        }
        let observed_floor = legacy_floor.unwrap_or(0);
        let persisted_floor = current.manifest.legacy_bundle_floor.unwrap_or(0);
        if observed_floor < persisted_floor {
            return Ok(Err(
                "legacy TPM floor regressed after state-v1 seeding".into()
            ));
        }
        self.verify_enforce_ready_locked(nv)?;
        if candidate.bundle_seq < observed_floor.max(persisted_floor)
            || candidate.bundle_seq < current.manifest.bundle_seq_floor
            || (candidate.bundle_seq == current.manifest.bundle_seq_floor
                && candidate.bom_sha256 != current.manifest.applied_bom_sha256)
            || candidate.snapshot.delegation_seq < current.manifest.delegation_seq_floor
        {
            return Ok(Err(
                "candidate is below a TPM-anchored pre-apply floor".into()
            ));
        }
        if let Err(reason) =
            monotonic_trusted(&current.manifest, &current.trusted, candidate.trusted)
        {
            return Ok(Err(reason));
        }
        if candidate.snapshot.delegation_seq == current.manifest.delegation_seq_floor {
            if !same_preapply_snapshot(
                candidate.snapshot_sha256,
                candidate.snapshot_signature,
                &current.manifest.delegation_snapshot_canonical_sha256,
                &current.manifest.delegation_snapshot_signature_sha256,
            )? {
                return Ok(Err(
                    "equal delegation sequence has a different snapshot".into()
                ));
            }
        } else {
            let dir = self
                .root
                .join("generations")
                .join(format!("generation-{:016}", current.manifest.generation));
            let previous: Snapshot = parse_canonical(
                &read_regular(&dir.join("delegation-snapshot.json"), 0o600)?,
                "accepted snapshot",
            )
            .map_err(InternalError)?;
            if let Err(error) = validate_chain(
                &previous,
                candidate.snapshot,
                &current.manifest.delegation_snapshot_canonical_sha256,
            ) {
                return match error {
                    ContractError::Refusal(reason) => Ok(Err(reason)),
                    ContractError::Internal(error) => Err(error),
                };
            }
        }
        Ok(Ok(()))
    }

    pub(crate) fn commit(
        &self,
        candidate: &Candidate<'_>,
        nv: &dyn NvAnchor,
    ) -> Result<Result<CommitReceipt, String>, InternalError> {
        let _lock = self.lock_store().lock_commit()?;
        self.commit_locked(candidate, nv)
    }

    fn commit_locked(
        &self,
        candidate: &Candidate<'_>,
        nv: &dyn NvAnchor,
    ) -> Result<Result<CommitReceipt, String>, InternalError> {
        let prior_history = self.has_durable_state_history()?;
        ensure_secure_state_directory(&self.root)?;
        ensure_secure_state_directory(&self.root.join("generations"))?;
        validate_candidate(candidate)?;
        let initial_anchor = hex(nv.read_initial()?);
        if initial_anchor == ZERO_ANCHOR && !prior_history {
            self.remove_temporary_generation("generation-0000000000000001")?;
        }
        let state_index_ready = nv.attest().is_ok();
        let Some(legacy_floor) = nv.legacy_bundle_floor()? else {
            return Ok(Err(
                "legacy TPM floor is absent before state-v1 seeding".into()
            ));
        };
        let scan = self.scan_generations()?;
        let current = if initial_anchor == ZERO_ANCHOR {
            if prior_history {
                return Ok(Err(
                    "zero TPM anchor with existing durable state history requires signed recovery"
                        .into(),
                ));
            }
            if scan.has_evidence
                && !self.exact_unanchored_generation(candidate, Some(legacy_floor))?
            {
                return Ok(Err(
                    "zero TPM anchor with existing state history requires signed recovery".into(),
                ));
            }
            None
        } else {
            nv.attest()?;
            self.read_current_locked(nv)?
        };
        let observed_floor = legacy_floor;
        let persisted_floor = current
            .as_ref()
            .and_then(|value| value.manifest.legacy_bundle_floor)
            .unwrap_or(0);
        if observed_floor < persisted_floor {
            return Ok(Err(
                "legacy TPM floor regressed after state-v1 seeding".into()
            ));
        }
        if candidate.applied.bundle_seq < observed_floor.max(persisted_floor) {
            return Ok(Err("bundle sequence is below legacy TPM floor".into()));
        }
        if let Some(loaded) = &current {
            if let Err(reason) = monotonic(&loaded.manifest, &loaded.trusted, candidate) {
                return Ok(Err(reason));
            }
            if same_candidate(&loaded.manifest, candidate)? {
                self.publish_current(loaded.manifest.generation)?;
                self.publish_enforce_ready(&loaded.manifest_sha256, &loaded.nv_anchor)?;
                self.consume_challenge_if_present(&candidate.challenge)?;
                self.verify_enforce_ready_locked(nv)?;
                return Ok(Ok(CommitReceipt {
                    generation: loaded.manifest.generation,
                    manifest_sha256: loaded.manifest_sha256.clone(),
                    nv_anchor: loaded.nv_anchor.clone(),
                }));
            }
        }
        if let Err(reason) = self.challenge_is_live(
            nv,
            &candidate.challenge,
            &candidate.trusted,
            candidate.trusted_assertion,
        )? {
            return Ok(Err(reason));
        }
        if self.pending_time_challenge()? != candidate.challenge {
            return Ok(Err(
                "trusted-time assertion does not consume the pending challenge".into(),
            ));
        }
        if candidate.challenge.state_nv_anchor != initial_anchor {
            return Ok(Err(
                "trusted-time challenge does not bind the current TPM anchor".into(),
            ));
        }
        let generation = current
            .as_ref()
            .map_or(1, |value| value.manifest.generation + 1);
        if !safe_uint(generation) {
            return Ok(Err("state generation overflow".into()));
        }
        if current.is_none() && !state_index_ready {
            // Provision before staging any generation. A crash after define
            // therefore leaves a zero index and no disk authority; retry can
            // continue. Staging first would strand evidence beside a zero
            // anchor and correctly trigger the no-auto-reseed refusal.
            nv.provision_initial()?;
            if hex(nv.read_initial()?) != ZERO_ANCHOR {
                return Ok(Err("new state-v1 index did not read back zero".into()));
            }
        }
        let manifest = self.stage_generation(
            generation,
            candidate,
            current.as_ref().map(|value| value.manifest_sha256.clone()),
            initial_anchor.clone(),
            Some(legacy_floor),
        )?;
        let manifest_sha256 = hash(&canonical(&manifest)?)?;
        let expected = extend_value(&initial_anchor, &manifest_sha256)?;
        nv.extend(decode_hash(&manifest_sha256)?)?;
        if hex(nv.read()?) != expected {
            return Ok(Err("TPM NV readback differs after extend".into()));
        }
        self.publish_current(generation)?;
        let readback = self.read_current_locked(nv)?;
        if !readback.as_ref().is_some_and(|value| {
            value.manifest == manifest
                && value.manifest_sha256 == manifest_sha256
                && value.nv_anchor == expected
        }) {
            return Ok(Err(
                "complete state readback differs after publication".into()
            ));
        }
        self.publish_enforce_ready(&manifest_sha256, &expected)?;
        self.consume_challenge_if_present(&candidate.challenge)?;
        self.verify_enforce_ready_locked(nv)?;
        Ok(Ok(CommitReceipt {
            generation,
            manifest_sha256,
            nv_anchor: expected,
        }))
    }

    pub(crate) fn exact_receipt(
        &self,
        candidate: &Candidate<'_>,
        nv: &dyn NvAnchor,
    ) -> Result<Result<CommitReceipt, String>, InternalError> {
        validate_candidate(candidate)?;
        let current = self
            .read_current(nv)?
            .ok_or_else(|| InternalError("state-v1 is unseeded".into()))?;
        self.verify_enforce_ready(nv)?;
        if !same_candidate(&current.manifest, candidate)? {
            return Ok(Err(
                "consumed trusted-time challenge is not an exact committed retry".into(),
            ));
        }
        Ok(Ok(CommitReceipt {
            generation: current.manifest.generation,
            manifest_sha256: current.manifest_sha256,
            nv_anchor: current.nv_anchor,
        }))
    }

    fn stage_generation(
        &self,
        generation: u64,
        value: &Candidate<'_>,
        previous_manifest_sha256: Option<String>,
        previous_nv_anchor: String,
        legacy_bundle_floor: Option<u64>,
    ) -> Result<StateManifest, InternalError> {
        let generations = self.root.join("generations");
        let final_name = format!("generation-{generation:016}");
        let final_dir = generations.join(&final_name);
        if final_dir.exists() {
            secure_existing_dir(&final_dir)?;
            std::fs::remove_dir_all(&final_dir).map_err(|error| {
                InternalError(format!("cannot replace unanchored {final_name}: {error}"))
            })?;
            sync_dir(&generations)?;
        }
        self.remove_temporary_generation(&final_name)?;
        let temp = generations.join(format!(".{final_name}.{}.tmp", std::process::id()));
        let mut builder = std::fs::DirBuilder::new();
        builder
            .mode(0o700)
            .create(&temp)
            .map_err(|error| InternalError(format!("cannot create state generation: {error}")))?;
        let authority = canonical(&value.authority)?;
        let applied = canonical(&value.applied)?;
        let trusted = canonical(&value.trusted)?;
        for (name, bytes) in [
            ("applied.json", applied.as_slice()),
            ("authority.json", authority.as_slice()),
            ("delegation-snapshot.json", value.snapshot),
            ("delegation-snapshot.sig", value.snapshot_signature),
            ("release-authorization.json", value.release),
            ("release-authorization.sig", value.release_signature),
            ("trusted-time-assertion.json", value.trusted_assertion),
            ("trusted-time-assertion.sig", value.trusted_signature),
            ("trusted-time.json", trusted.as_slice()),
        ] {
            write_new(&temp.join(name), bytes)?;
        }
        let manifest = self.manifest_for(
            generation,
            value,
            previous_manifest_sha256,
            previous_nv_anchor,
            legacy_bundle_floor,
        )?;
        write_new(&temp.join("manifest.json"), &canonical(&manifest)?)?;
        sync_dir(&temp)?;
        std::fs::rename(&temp, &final_dir)
            .map_err(|error| InternalError(format!("cannot publish {final_name}: {error}")))?;
        sync_dir(&generations)?;
        Ok(manifest)
    }

    fn manifest_for(
        &self,
        generation: u64,
        value: &Candidate<'_>,
        previous_manifest_sha256: Option<String>,
        previous_nv_anchor: String,
        legacy_bundle_floor: Option<u64>,
    ) -> Result<StateManifest, InternalError> {
        let applied = canonical(&value.applied)?;
        let authority = canonical(&value.authority)?;
        let trusted = canonical(&value.trusted)?;
        Ok(StateManifest {
            applied_sha256: hash(&applied)?,
            applied_bom_sha256: value.applied.bom_sha256.clone(),
            authority_sha256: hash(&authority)?,
            bundle_seq_floor: value.applied.bundle_seq,
            delegation_seq_floor: value.authority.delegation_seq,
            delegation_snapshot_canonical_sha256: value.authority.snapshot_sha256.clone(),
            delegation_snapshot_sha256: hash(value.snapshot)?,
            delegation_snapshot_signature_sha256: hash(value.snapshot_signature)?,
            generation,
            legacy_bundle_floor,
            previous_manifest_sha256,
            previous_nv_anchor,
            release_authorization_sha256: hash(value.release)?,
            release_authorization_signature_sha256: hash(value.release_signature)?,
            schema: "neural-ice-ota-state-manifest-v1".into(),
            trusted_time_assertion_canonical_sha256: value.trusted.assertion_sha256.clone(),
            trusted_time_assertion_sha256: hash(value.trusted_assertion)?,
            trusted_time_assertion_signature_sha256: hash(value.trusted_signature)?,
            trusted_time_floor: value.trusted.trusted_time.clone(),
            trusted_time_seq_floor: value.trusted.assertion_seq,
            trusted_time_sha256: hash(&trusted)?,
        })
    }

    fn remove_temporary_generation(&self, final_name: &str) -> Result<(), InternalError> {
        let generations = self.root.join("generations");
        let prefix = format!(".{final_name}.");
        for entry in std::fs::read_dir(&generations)
            .map_err(|error| InternalError(format!("cannot enumerate generations: {error}")))?
        {
            let entry = entry
                .map_err(|error| InternalError(format!("cannot enumerate generation: {error}")))?;
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if name.starts_with(&prefix) && name.ends_with(".tmp") {
                secure_existing_dir(&entry.path())?;
                std::fs::remove_dir_all(entry.path()).map_err(|error| {
                    InternalError(format!("cannot remove abandoned generation: {error}"))
                })?;
            }
        }
        sync_dir(&generations)
    }

    fn publish_enforce_ready(&self, manifest: &str, anchor: &str) -> Result<(), InternalError> {
        atomic_replace(
            &self.root,
            "enforce-ready.json",
            &canonical(&serde_json::json!({
                "manifest_sha256": manifest,
                "nv_anchor": anchor,
                "schema": "neural-ice-ota-enforce-ready-v1"
            }))?,
        )
    }

    fn consume_challenge_if_present(&self, expected: &TimeChallenge) -> Result<(), InternalError> {
        let path = self.root.join("pending-time-challenge.json");
        match self.pending_time_challenge() {
            Ok(value) if &value == expected => {
                std::fs::remove_file(&path).map_err(|error| {
                    InternalError(format!("cannot consume trusted-time challenge: {error}"))
                })?;
                sync_dir(&self.root)
            }
            Ok(_) => Err(InternalError(
                "pending trusted-time challenge differs during consumption".into(),
            )),
            Err(_) if !path.exists() => Ok(()),
            Err(error) => Err(error),
        }
    }

    fn challenge_is_live(
        &self,
        nv: &dyn NvAnchor,
        challenge: &TimeChallenge,
        trusted: &TrustedTimeState,
        trusted_assertion: &[u8],
    ) -> Result<Result<(), String>, InternalError> {
        let live = nv.clock()?;
        if !live.safe {
            return Ok(Err(
                "TPM clock is not safe while consuming trusted-time challenge".into(),
            ));
        }
        if live.reset_count != challenge.tpm_reset_count
            || live.restart_count != challenge.tpm_restart_count
        {
            return Ok(Err(
                "TPM reset or restart count changed since trusted-time challenge".into(),
            ));
        }
        let Some(elapsed) = live.clock.checked_sub(challenge.tpm_clock) else {
            return Ok(Err(
                "TPM clock regressed since trusted-time challenge".into()
            ));
        };
        if elapsed > TRUSTED_TIME_MAX_ELAPSED_MS {
            return Ok(Err(
                "trusted-time challenge exceeded its freshness window".into()
            ));
        }
        let valid_until = signed_assertion_valid_until(trusted, trusted_assertion)?;
        let trusted_time =
            crate::trusted_time::utc_seconds(&trusted.trusted_time).ok_or_else(|| {
                InternalError("trusted-time assertion has invalid trusted time".into())
            })?;
        let valid_until = crate::trusted_time::utc_seconds(&valid_until)
            .ok_or_else(|| InternalError("trusted-time assertion has invalid expiry".into()))?;
        let elapsed_seconds = elapsed
            .checked_add(999)
            .ok_or_else(|| InternalError("TPM elapsed-time overflow".into()))?
            / 1_000;
        if trusted_time
            .checked_add(elapsed_seconds)
            .is_none_or(|now| now >= valid_until)
        {
            return Ok(Err(
                "trusted-time assertion expired at the current TPM clock".into(),
            ));
        }
        Ok(Ok(()))
    }

    fn has_durable_state_history(&self) -> Result<bool, InternalError> {
        let root = match std::fs::read_dir(&self.root) {
            Ok(root) => root,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => {
                return Err(InternalError(format!(
                    "cannot enumerate {}: {error}",
                    self.root.display()
                )))
            }
        };
        secure_existing_dir(&self.root)?;
        for entry in root {
            let entry = entry.map_err(|error| {
                InternalError(format!("cannot enumerate state-v1 entry: {error}"))
            })?;
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                return Ok(true);
            };
            if matches!(name.as_str(), "current" | "enforce-ready.json") {
                return Ok(true);
            }
            if matches!(name.as_str(), "generations" | "pending-time-challenge.json")
                || name == ".transaction.json.lock"
                || (name.starts_with(".transaction.json.") && name.ends_with(".tmp"))
            {
                continue;
            }
            return Ok(true);
        }
        Ok(false)
    }

    fn exact_unanchored_generation(
        &self,
        candidate: &Candidate<'_>,
        legacy_bundle_floor: Option<u64>,
    ) -> Result<bool, InternalError> {
        let scan = self.scan_generations()?;
        if scan.numbers != [1] || scan.numbers.len() != 1 {
            return Ok(false);
        }
        let dir = self.root.join("generations/generation-0000000000000001");
        let entries = std::fs::read_dir(self.root.join("generations"))
            .map_err(|error| InternalError(format!("cannot enumerate staged generation: {error}")))?
            .map(|entry| {
                entry
                    .map_err(|error| {
                        InternalError(format!("cannot enumerate staged entry: {error}"))
                    })?
                    .file_name()
                    .into_string()
                    .map_err(|_| InternalError("staged generation name is not UTF-8".into()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if entries.as_slice() != ["generation-0000000000000001"] {
            return Ok(false);
        }
        let observed: StateManifest = parse_canonical(
            &read_regular(&dir.join("manifest.json"), 0o600)?,
            "unanchored state-v1 manifest",
        )
        .map_err(InternalError)?;
        let expected =
            self.manifest_for(1, candidate, None, ZERO_ANCHOR.into(), legacy_bundle_floor)?;
        if observed != expected {
            return Ok(false);
        }
        Ok(verify_generation(&dir, &observed).is_ok())
    }

    #[allow(dead_code, reason = "used by state-v1 adversarial tests")]
    fn read_current(&self, nv: &dyn NvAnchor) -> Result<Option<LoadedGeneration>, InternalError> {
        let _lock = self.lock_store().lock_commit()?;
        self.read_current_locked(nv)
    }

    fn read_current_locked(
        &self,
        nv: &dyn NvAnchor,
    ) -> Result<Option<LoadedGeneration>, InternalError> {
        let observed = hex(nv.read()?);
        if !secure_optional_dir(&self.root)? {
            return if observed == ZERO_ANCHOR {
                Ok(None)
            } else {
                Err(InternalError(
                    "TPM NV anchor exists while state-v1 root is absent".into(),
                ))
            };
        }
        let pointer = self.root.join("current");
        let pointer_generation = if let Some(bytes) = read_optional_regular(&pointer, 0o600)? {
            Some(parse_pointer(&bytes)?)
        } else {
            None
        };
        let scan = self.scan_generations()?;
        let loaded = self.load_generations(&scan.numbers)?;
        let matches: Vec<_> = loaded
            .iter()
            .filter(|value| value.nv_anchor == observed)
            .cloned()
            .collect();
        if let Some(generation) = pointer_generation {
            let pointed = loaded
                .iter()
                .find(|value| value.manifest.generation == generation)
                .ok_or_else(|| {
                    InternalError("state-v1 CURRENT names an absent generation".into())
                })?;
            if pointed.nv_anchor == observed {
                return match matches.as_slice() {
                    [anchored] if anchored.manifest.generation == pointed.manifest.generation => {
                        self.accept_current(nv, &observed, pointed, false)
                    }
                    _ => Err(InternalError(
                        "state-v1 CURRENT does not identify one unique anchored generation".into(),
                    )),
                };
            }
        }
        match matches.as_slice() {
            [] if observed == ZERO_ANCHOR && !scan.has_evidence => Ok(None),
            [] if observed == ZERO_ANCHOR => Err(InternalError(
                "zero TPM anchor with existing state history requires signed recovery".into(),
            )),
            [] => Err(InternalError(
                "TPM NV anchor has no complete state-v1 generation".into(),
            )),
            [value] => self.accept_current(nv, &observed, value, true),
            _ => Err(InternalError(
                "TPM NV anchor matches multiple state-v1 generations".into(),
            )),
        }
    }

    fn accept_current(
        &self,
        nv: &dyn NvAnchor,
        observed: &str,
        value: &LoadedGeneration,
        publish: bool,
    ) -> Result<Option<LoadedGeneration>, InternalError> {
        if hex(nv.read()?) != observed {
            return Err(InternalError(
                "TPM NV anchor changed before state-v1 recovery publication".into(),
            ));
        }
        if publish {
            self.publish_current(value.manifest.generation)?;
        }
        let pointer = read_regular(&self.root.join("current"), 0o600)?;
        if parse_pointer(&pointer)? != value.manifest.generation {
            return Err(InternalError(
                "state-v1 CURRENT readback differs after recovery".into(),
            ));
        }
        if hex(nv.read()?) != observed {
            return Err(InternalError(
                "TPM NV anchor changed during state-v1 recovery".into(),
            ));
        }
        Ok(Some(value.clone()))
    }

    fn load_generations(&self, numbers: &[u64]) -> Result<Vec<LoadedGeneration>, InternalError> {
        if numbers.is_empty() {
            return Ok(Vec::new());
        }
        for (offset, number) in numbers.iter().enumerate() {
            let expected = offset as u64 + 1;
            if *number != expected || !safe_uint(*number) {
                return Err(InternalError(
                    "state-v1 generations are not one contiguous canonical sequence".into(),
                ));
            }
        }
        let mut previous_hash: Option<String> = None;
        let mut anchor = ZERO_ANCHOR.to_owned();
        let mut previous_manifest: Option<StateManifest> = None;
        let mut previous_trusted: Option<TrustedTimeState> = None;
        let mut result = Vec::with_capacity(numbers.len());
        for &generation in numbers {
            let dir = self
                .root
                .join("generations")
                .join(format!("generation-{generation:016}"));
            secure_existing_dir(&dir)?;
            let manifest_bytes = read_regular(&dir.join("manifest.json"), 0o600)?;
            let manifest: StateManifest =
                parse_canonical(&manifest_bytes, "state-v1 manifest").map_err(InternalError)?;
            if manifest.generation != generation
                || manifest.previous_manifest_sha256 != previous_hash
                || manifest.previous_nv_anchor != anchor
            {
                return Err(InternalError("state-v1 generation chain is broken".into()));
            }
            let trusted = verify_generation(&dir, &manifest)?;
            if let Some(previous) = &previous_manifest {
                verify_floor_continuity(previous, &manifest)?;
            }
            if let Some(previous) = &previous_trusted {
                verify_clock_continuity(previous, &trusted)?;
            }
            let manifest_sha256 = hash(&manifest_bytes)?;
            anchor = extend_value(&anchor, &manifest_sha256)?;
            previous_hash = Some(manifest_sha256.clone());
            result.push(LoadedGeneration {
                manifest: manifest.clone(),
                manifest_sha256,
                nv_anchor: anchor.clone(),
                trusted: trusted.clone(),
            });
            previous_manifest = Some(manifest);
            previous_trusted = Some(trusted);
        }
        Ok(result)
    }

    fn scan_generations(&self) -> Result<GenerationScan, InternalError> {
        let generations = self.root.join("generations");
        match std::fs::symlink_metadata(&generations) {
            Ok(_) => secure_existing_dir(&generations)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(GenerationScan::default())
            }
            Err(error) => {
                return Err(InternalError(format!(
                    "cannot inspect {}: {error}",
                    generations.display()
                )))
            }
        }
        let mut scan = GenerationScan::default();
        for entry in std::fs::read_dir(&generations).map_err(|error| {
            InternalError(format!(
                "cannot enumerate {}: {error}",
                generations.display()
            ))
        })? {
            let entry = entry
                .map_err(|error| InternalError(format!("cannot enumerate generation: {error}")))?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                return Err(InternalError(
                    "state-v1 generation name is not UTF-8".into(),
                ));
            };
            if let Some(number) = generation_number(name) {
                secure_existing_dir(&entry.path())?;
                scan.numbers.push(number);
                scan.has_evidence = true;
            } else if temporary_generation(name) {
                secure_existing_dir(&entry.path())?;
                scan.has_evidence = true;
            } else {
                return Err(InternalError(format!(
                    "unexpected entry in state-v1 generations: {name}"
                )));
            }
        }
        scan.numbers.sort_unstable();
        Ok(scan)
    }

    fn publish_current(&self, generation: u64) -> Result<(), InternalError> {
        atomic_replace(
            &self.root,
            "current",
            format!("generation-{generation:016}\n").as_bytes(),
        )
    }

    pub(crate) fn verify_enforce_ready(&self, nv: &dyn NvAnchor) -> Result<(), InternalError> {
        let _lock = self.lock_store().lock_commit()?;
        self.verify_enforce_ready_locked(nv)
    }

    fn verify_enforce_ready_locked(&self, nv: &dyn NvAnchor) -> Result<(), InternalError> {
        secure_existing_dir(&self.root)?;
        let current = self
            .read_current_locked(nv)?
            .ok_or_else(|| InternalError("state-v1 is unseeded".into()))?;
        let legacy_floor = nv
            .legacy_bundle_floor()?
            .ok_or_else(|| InternalError("legacy TPM floor is absent".into()))?;
        if current.manifest.legacy_bundle_floor != Some(legacy_floor) {
            return Err(InternalError(
                "legacy floor differs from TPM-anchored state-v1 manifest".into(),
            ));
        }
        let expected = EnforceReady {
            manifest_sha256: current.manifest_sha256,
            nv_anchor: current.nv_anchor,
            schema: "neural-ice-ota-enforce-ready-v1".into(),
        };
        let marker = self.root.join("enforce-ready.json");
        let publish = match read_optional_regular(&marker, 0o600)? {
            None => true,
            Some(bytes) => {
                let value: EnforceReady =
                    parse_canonical(&bytes, "state-v1 enforce-ready").map_err(InternalError)?;
                if value.schema != "neural-ice-ota-enforce-ready-v1"
                    || !sha256(&value.manifest_sha256)
                    || !sha256(&value.nv_anchor)
                {
                    return Err(InternalError(
                        "invalid state-v1 enforce marker contract".into(),
                    ));
                }
                value != expected
            }
        };
        if publish {
            atomic_replace(&self.root, "enforce-ready.json", &canonical(&expected)?)?;
        }
        let readback: EnforceReady = parse_canonical(
            &read_regular(&marker, 0o600)?,
            "state-v1 enforce-ready readback",
        )
        .map_err(InternalError)?;
        if readback != expected {
            return Err(InternalError(
                "state-v1 enforce marker readback differs after publication".into(),
            ));
        }
        if hex(nv.read()?) != expected.nv_anchor {
            return Err(InternalError(
                "TPM NV anchor changed during enforce-ready publication".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct EnforceReady {
    manifest_sha256: String,
    nv_anchor: String,
    schema: String,
}

fn verify_generation(dir: &Path, value: &StateManifest) -> Result<TrustedTimeState, InternalError> {
    verify_generation_inventory(dir)?;
    if value.schema != "neural-ice-ota-state-manifest-v1"
        || !safe_uint(value.generation)
        || !safe_uint(value.bundle_seq_floor)
        || !safe_uint(value.delegation_seq_floor)
        || !safe_uint(value.trusted_time_seq_floor)
        || !sha256(&value.applied_bom_sha256)
        || !sha256(&value.delegation_snapshot_canonical_sha256)
        || !sha256(&value.trusted_time_assertion_canonical_sha256)
        || !timestamp(&value.trusted_time_floor)
        || !sha256(&value.previous_nv_anchor)
        || value
            .previous_manifest_sha256
            .as_deref()
            .is_some_and(|hash| !sha256(hash))
        || value
            .legacy_bundle_floor
            .is_some_and(|floor| !safe_uint(floor))
    {
        return Err(InternalError("invalid state-v1 manifest contract".into()));
    }
    let applied: AppliedStateV1 = parse_canonical(
        &read_manifest_artifact(dir, "applied.json", &value.applied_sha256)?,
        "state-v1 applied state",
    )
    .map_err(InternalError)?;
    let authority: AuthorityState = parse_canonical(
        &read_manifest_artifact(dir, "authority.json", &value.authority_sha256)?,
        "state-v1 authority state",
    )
    .map_err(InternalError)?;
    let snapshot = read_manifest_artifact(
        dir,
        "delegation-snapshot.json",
        &value.delegation_snapshot_sha256,
    )?;
    let _: serde_json::Value =
        parse_canonical(&snapshot, "state-v1 delegation snapshot").map_err(InternalError)?;
    if state_canonical_hash(&snapshot, "delegation snapshot")?
        != value.delegation_snapshot_canonical_sha256
    {
        return Err(InternalError(
            "state-v1 delegation snapshot bytes differ from their canonical hash".into(),
        ));
    }
    let assertion = read_manifest_artifact(
        dir,
        "trusted-time-assertion.json",
        &value.trusted_time_assertion_sha256,
    )?;
    let _: serde_json::Value =
        parse_canonical(&assertion, "state-v1 trusted-time assertion").map_err(InternalError)?;
    if state_canonical_hash(&assertion, "trusted-time assertion")?
        != value.trusted_time_assertion_canonical_sha256
    {
        return Err(InternalError(
            "state-v1 trusted-time assertion bytes differ from their canonical hash".into(),
        ));
    }
    for (name, expected) in [
        (
            "delegation-snapshot.sig",
            &value.delegation_snapshot_signature_sha256,
        ),
        (
            "release-authorization.sig",
            &value.release_authorization_signature_sha256,
        ),
        (
            "trusted-time-assertion.sig",
            &value.trusted_time_assertion_signature_sha256,
        ),
    ] {
        read_manifest_artifact(dir, name, expected)?;
    }
    let release = read_manifest_artifact(
        dir,
        "release-authorization.json",
        &value.release_authorization_sha256,
    )?;
    let _: serde_json::Value =
        parse_canonical(&release, "state-v1 release authorization").map_err(InternalError)?;
    let trusted: TrustedTimeState = parse_canonical(
        &read_manifest_artifact(dir, "trusted-time.json", &value.trusted_time_sha256)?,
        "trusted-time state",
    )
    .map_err(InternalError)?;
    if applied.schema != "neural-ice-ota-applied-state-v1"
        || applied.bundle_seq != value.bundle_seq_floor
        || applied.bom_sha256 != value.applied_bom_sha256
        || authority.schema != "neural-ice-ota-authority-state-v1"
        || authority.delegation_seq != value.delegation_seq_floor
        || authority.snapshot_sha256 != value.delegation_snapshot_canonical_sha256
        || authority.snapshot_signature_sha256 != value.delegation_snapshot_signature_sha256
        || trusted.schema != "neural-ice-ota-trusted-time-state-v2"
        || trusted.assertion_seq != value.trusted_time_seq_floor
        || trusted.assertion_sha256 != value.trusted_time_assertion_canonical_sha256
        || trusted.signature_sha256 != value.trusted_time_assertion_signature_sha256
        || trusted.delegation_seq != value.delegation_seq_floor
        || trusted.trusted_time != value.trusted_time_floor
        || !safe_uint(trusted.assertion_seq)
        || !safe_uint(trusted.delegation_seq)
        || !safe_uint(trusted.tpm_clock)
        || !sha256(&trusted.assertion_sha256)
        || !sha256(&trusted.signature_sha256)
        || !sha256(&trusted.challenge_sha256)
        || !sha256(&trusted.device_fingerprint)
        || !safe_key_id(&trusted.key_id)
        || !trusted.tpm_safe
        || !timestamp(&trusted.trusted_time)
    {
        return Err(InternalError(
            "state-v1 semantic state differs from its manifest floors".into(),
        ));
    }
    verify_generation_inventory(dir)?;
    Ok(trusted)
}

fn verify_generation_inventory(dir: &Path) -> Result<(), InternalError> {
    let mut observed = Vec::new();
    for entry in std::fs::read_dir(dir).map_err(|error| {
        InternalError(format!(
            "cannot enumerate state-v1 generation {}: {error}",
            dir.display()
        ))
    })? {
        let entry = entry.map_err(|error| {
            InternalError(format!(
                "cannot enumerate state-v1 generation {}: {error}",
                dir.display()
            ))
        })?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| InternalError("state-v1 generation contains a non-UTF-8 entry".into()))?;
        observed.push(name);
    }
    observed.sort_unstable();
    if observed != GENERATION_ARTIFACTS {
        return Err(InternalError(
            "state-v1 generation artifact inventory is not exact".into(),
        ));
    }
    Ok(())
}

fn read_manifest_artifact(
    dir: &Path,
    name: &str,
    expected: &str,
) -> Result<Vec<u8>, InternalError> {
    if !sha256(expected) {
        return Err(InternalError(format!(
            "state-v1 manifest has invalid hash for {name}"
        )));
    }
    let bytes = read_regular(&dir.join(name), 0o600)?;
    if hash(&bytes)? != expected {
        return Err(InternalError(format!(
            "state-v1 artifact {name} hash differs from manifest"
        )));
    }
    Ok(bytes)
}

fn state_canonical_hash(bytes: &[u8], what: &str) -> Result<String, InternalError> {
    match canonical_hash(bytes) {
        Ok(value) => Ok(value),
        Err(ContractError::Refusal(reason)) => Err(InternalError(format!(
            "invalid state-v1 canonical {what}: {reason}"
        ))),
        Err(ContractError::Internal(error)) => Err(error),
    }
}

fn verify_floor_continuity(
    previous: &StateManifest,
    current: &StateManifest,
) -> Result<(), InternalError> {
    let legacy_regressed = match (previous.legacy_bundle_floor, current.legacy_bundle_floor) {
        (Some(_), None) => true,
        (Some(old), Some(new)) => new < old,
        _ => false,
    };
    if current.bundle_seq_floor < previous.bundle_seq_floor
        || current.delegation_seq_floor < previous.delegation_seq_floor
        || current.trusted_time_seq_floor < previous.trusted_time_seq_floor
        || current.trusted_time_floor < previous.trusted_time_floor
        || legacy_regressed
        || (current.bundle_seq_floor == previous.bundle_seq_floor
            && (current.applied_sha256 != previous.applied_sha256
                || current.applied_bom_sha256 != previous.applied_bom_sha256
                || current.release_authorization_sha256 != previous.release_authorization_sha256
                || current.release_authorization_signature_sha256
                    != previous.release_authorization_signature_sha256))
        || (current.delegation_seq_floor == previous.delegation_seq_floor
            && (current.authority_sha256 != previous.authority_sha256
                || current.delegation_snapshot_canonical_sha256
                    != previous.delegation_snapshot_canonical_sha256
                || current.delegation_snapshot_sha256 != previous.delegation_snapshot_sha256
                || current.delegation_snapshot_signature_sha256
                    != previous.delegation_snapshot_signature_sha256))
        || (current.trusted_time_seq_floor == previous.trusted_time_seq_floor
            && (current.trusted_time_sha256 != previous.trusted_time_sha256
                || current.trusted_time_assertion_canonical_sha256
                    != previous.trusted_time_assertion_canonical_sha256
                || current.trusted_time_assertion_sha256 != previous.trusted_time_assertion_sha256
                || current.trusted_time_assertion_signature_sha256
                    != previous.trusted_time_assertion_signature_sha256
                || current.trusted_time_floor != previous.trusted_time_floor))
    {
        return Err(InternalError(
            "state-v1 persisted monotonic floor regressed or split".into(),
        ));
    }
    Ok(())
}

fn verify_clock_continuity(
    previous: &TrustedTimeState,
    current: &TrustedTimeState,
) -> Result<(), InternalError> {
    let regressed = current.device_fingerprint != previous.device_fingerprint
        || current.tpm_reset_count < previous.tpm_reset_count
        || current.trusted_time < previous.trusted_time
        || (current.tpm_reset_count == previous.tpm_reset_count
            && (current.tpm_clock < previous.tpm_clock
                || current.tpm_restart_count < previous.tpm_restart_count))
        || (current.tpm_reset_count > previous.tpm_reset_count
            && (current.assertion_seq <= previous.assertion_seq
                || current.trusted_time <= previous.trusted_time));
    if regressed {
        return Err(InternalError(
            "state-v1 persisted TPM clock continuity regressed".into(),
        ));
    }
    Ok(())
}

fn safe_key_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn validate_time_challenge(value: &TimeChallenge) -> Result<(), InternalError> {
    if value.schema != "neural-ice-ota-time-challenge-v2"
        || !sha256(&value.delegation_snapshot_sha256)
        || !sha256(&value.device_fingerprint)
        || !sha256(&value.release_authorization_sha256)
        || !sha256(&value.state_nv_anchor)
        || value.nonce.len() != 64
        || !value
            .nonce
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        || !matches!(value.ring.as_str(), "beta" | "stable")
        || !value.tpm_safe
        || !safe_uint(value.tpm_clock)
    {
        return Err(InternalError(
            "trusted-time v2 challenge contract is invalid".into(),
        ));
    }
    Ok(())
}

fn validate_candidate(value: &Candidate<'_>) -> Result<(), InternalError> {
    validate_time_challenge(&value.challenge)?;
    if state_canonical_hash(value.release, "release authorization")?
        != value.challenge.release_authorization_sha256
        || state_canonical_hash(value.snapshot, "delegation snapshot")?
            != value.challenge.delegation_snapshot_sha256
        || value.authority.snapshot_sha256 != value.challenge.delegation_snapshot_sha256
    {
        return Err(InternalError(
            "trusted-time challenge does not bind the candidate release and snapshot".into(),
        ));
    }
    validate_trusted_challenge(&value.trusted, &value.challenge)?;
    if value.authority.schema != "neural-ice-ota-authority-state-v1"
        || value.applied.schema != "neural-ice-ota-applied-state-v1"
        || value.trusted.schema != "neural-ice-ota-trusted-time-state-v2"
        || !safe_uint(value.authority.delegation_seq)
        || !safe_uint(value.applied.bundle_seq)
        || !safe_uint(value.trusted.assertion_seq)
        || value.trusted.delegation_seq != value.authority.delegation_seq
        || !timestamp(&value.trusted.trusted_time)
        || !sha256(&value.authority.snapshot_sha256)
        || !sha256(&value.authority.snapshot_signature_sha256)
        || !sha256(&value.applied.bom_sha256)
        || !sha256(&value.trusted.assertion_sha256)
        || !sha256(&value.trusted.signature_sha256)
        || !sha256(&value.trusted.challenge_sha256)
        || !sha256(&value.trusted.device_fingerprint)
        || value.authority.snapshot_signature_sha256 != hash(value.snapshot_signature)?
        || value.trusted.assertion_sha256
            != state_canonical_hash(value.trusted_assertion, "trusted-time assertion")?
        || value.trusted.signature_sha256 != hash(value.trusted_signature)?
    {
        return Err(InternalError("invalid state-v1 candidate".into()));
    }
    signed_assertion_valid_until(&value.trusted, value.trusted_assertion)?;
    Ok(())
}

fn validate_preapply_candidate(value: &PreapplyCandidate<'_>) -> Result<(), InternalError> {
    validate_time_challenge(value.challenge)?;
    if !safe_uint(value.bundle_seq)
        || !safe_uint(value.snapshot.delegation_seq)
        || value.snapshot.delegation_seq != value.trusted.delegation_seq
        || value.snapshot_sha256 != value.challenge.delegation_snapshot_sha256
    {
        return Err(InternalError("invalid state-v1 pre-apply candidate".into()));
    }
    validate_trusted_challenge(value.trusted, value.challenge)?;
    signed_assertion_valid_until(value.trusted, value.trusted_assertion)?;
    Ok(())
}

fn validate_trusted_challenge(
    trusted: &TrustedTimeState,
    challenge: &TimeChallenge,
) -> Result<(), InternalError> {
    if trusted.schema != "neural-ice-ota-trusted-time-state-v2"
        || !safe_uint(trusted.assertion_seq)
        || !timestamp(&trusted.trusted_time)
        || !sha256(&trusted.assertion_sha256)
        || !sha256(&trusted.signature_sha256)
        || !sha256(&trusted.challenge_sha256)
        || !sha256(&trusted.device_fingerprint)
        || trusted.device_fingerprint != challenge.device_fingerprint
        || trusted.challenge_sha256 != hash(challenge.nonce.as_bytes())?
        || trusted.tpm_clock != challenge.tpm_clock
        || trusted.tpm_reset_count != challenge.tpm_reset_count
        || trusted.tpm_restart_count != challenge.tpm_restart_count
        || !trusted.tpm_safe
        || !challenge.tpm_safe
    {
        return Err(InternalError(
            "invalid trusted-time challenge binding".into(),
        ));
    }
    Ok(())
}

fn signed_assertion_valid_until(
    trusted: &TrustedTimeState,
    assertion_bytes: &[u8],
) -> Result<String, InternalError> {
    let assertion: crate::trusted_time::TrustedTimeAssertion =
        parse_canonical(assertion_bytes, "state-v1 trusted-time assertion")
            .map_err(InternalError)?;
    if state_canonical_hash(assertion_bytes, "state-v1 trusted-time assertion")?
        != trusted.assertion_sha256
        || assertion.assertion_seq != trusted.assertion_seq
        || assertion.delegation_seq != trusted.delegation_seq
        || assertion.device_fingerprint != trusted.device_fingerprint
        || assertion.key_id != trusted.key_id
        || assertion.trusted_time != trusted.trusted_time
        || assertion.tpm_clock != trusted.tpm_clock
        || assertion.tpm_reset_count != trusted.tpm_reset_count
        || assertion.tpm_restart_count != trusted.tpm_restart_count
        || assertion.tpm_safe != trusted.tpm_safe
        || hash(assertion.nonce.as_bytes())? != trusted.challenge_sha256
        || !timestamp(&assertion.valid_until)
        || assertion.trusted_time >= assertion.valid_until
    {
        return Err(InternalError(
            "trusted-time state is not bound to its signed assertion".into(),
        ));
    }
    Ok(assertion.valid_until)
}

fn monotonic(
    old: &StateManifest,
    old_time: &TrustedTimeState,
    new: &Candidate<'_>,
) -> Result<(), String> {
    if new.authority.delegation_seq < old.delegation_seq_floor
        || new.applied.bundle_seq < old.bundle_seq_floor
        || new.trusted.assertion_seq < old.trusted_time_seq_floor
        || new.trusted.trusted_time < old.trusted_time_floor
    {
        return Err("state-v1 monotonic floor would decrease".into());
    }
    if new.authority.delegation_seq == old.delegation_seq_floor
        && (new.authority.snapshot_sha256 != old.delegation_snapshot_canonical_sha256
            || new.authority.snapshot_signature_sha256 != old.delegation_snapshot_signature_sha256)
    {
        return Err("equal delegation sequence has a different snapshot".into());
    }
    if new.applied.bundle_seq == old.bundle_seq_floor
        && (new.applied.bom_sha256 != old.applied_bom_sha256
            || hash(new.release).map_err(|error| error.0)? != old.release_authorization_sha256
            || hash(new.release_signature).map_err(|error| error.0)?
                != old.release_authorization_signature_sha256)
    {
        return Err("equal bundle sequence has a different BOM".into());
    }
    monotonic_trusted(old, old_time, &new.trusted)
}

fn monotonic_trusted(
    old: &StateManifest,
    old_time: &TrustedTimeState,
    new: &TrustedTimeState,
) -> Result<(), String> {
    if new.assertion_seq < old.trusted_time_seq_floor || new.trusted_time < old.trusted_time_floor {
        return Err("state-v1 monotonic trusted-time floor would decrease".into());
    }
    if new.assertion_seq == old.trusted_time_seq_floor
        && (new.assertion_sha256 != old.trusted_time_assertion_canonical_sha256
            || new.signature_sha256 != old.trusted_time_assertion_signature_sha256
            || new.trusted_time != old.trusted_time_floor)
    {
        return Err("equal trusted-time sequence has different evidence".into());
    }
    if new.device_fingerprint != old_time.device_fingerprint {
        return Err("trusted-time device identity changed".into());
    }
    if new.tpm_reset_count < old_time.tpm_reset_count {
        return Err("TPM reset count decreased".into());
    }
    if new.tpm_reset_count == old_time.tpm_reset_count {
        if new.tpm_clock < old_time.tpm_clock || new.tpm_restart_count < old_time.tpm_restart_count
        {
            return Err("TPM clock continuity regressed".into());
        }
    } else if new.assertion_seq <= old.trusted_time_seq_floor
        || new.trusted_time <= old.trusted_time_floor
    {
        return Err("TPM reset requires strictly newer trusted-time evidence".into());
    }
    let old_seconds = crate::trusted_time::utc_seconds(&old_time.trusted_time)
        .ok_or_else(|| "persisted trusted time is invalid".to_string())?;
    let new_seconds = crate::trusted_time::utc_seconds(&new.trusted_time)
        .ok_or_else(|| "candidate trusted time is invalid".to_string())?;
    let elapsed = if new.tpm_reset_count == old_time.tpm_reset_count {
        new.tpm_clock.saturating_sub(old_time.tpm_clock) / 1000
    } else {
        0
    };
    if new_seconds > old_seconds.saturating_add(elapsed).saturating_add(600) {
        return Err("trusted-time advance exceeds TPM elapsed plus ten minutes".into());
    }
    Ok(())
}

fn same_preapply_snapshot(
    canonical_sha256: &str,
    signature: &[u8],
    accepted_canonical_sha256: &str,
    accepted_signature_sha256: &str,
) -> Result<bool, InternalError> {
    Ok(canonical_sha256 == accepted_canonical_sha256
        && hash(signature)? == accepted_signature_sha256)
}

fn same_candidate(old: &StateManifest, new: &Candidate<'_>) -> Result<bool, InternalError> {
    Ok(old.delegation_seq_floor == new.authority.delegation_seq
        && old.bundle_seq_floor == new.applied.bundle_seq
        && old.trusted_time_seq_floor == new.trusted.assertion_seq
        && old.applied_bom_sha256 == new.applied.bom_sha256
        && old.delegation_snapshot_canonical_sha256 == new.authority.snapshot_sha256
        && old.trusted_time_assertion_canonical_sha256 == new.trusted.assertion_sha256
        && old.release_authorization_sha256 == hash(new.release)?
        && old.release_authorization_signature_sha256 == hash(new.release_signature)?
        && old.delegation_snapshot_sha256 == hash(new.snapshot)?
        && old.delegation_snapshot_signature_sha256 == hash(new.snapshot_signature)?
        && old.trusted_time_assertion_sha256 == hash(new.trusted_assertion)?
        && old.trusted_time_assertion_signature_sha256 == hash(new.trusted_signature)?)
}
fn parse_pointer(bytes: &[u8]) -> Result<u64, InternalError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| InternalError("state-v1 CURRENT is not UTF-8".into()))?;
    let name = text
        .strip_suffix('\n')
        .ok_or_else(|| InternalError("state-v1 CURRENT lacks final LF".into()))?;
    generation_number(name).ok_or_else(|| InternalError("invalid state-v1 CURRENT".into()))
}

fn generation_number(name: &str) -> Option<u64> {
    let digits = name.strip_prefix("generation-")?;
    if digits.len() != 16 || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let value = digits.parse().ok()?;
    safe_uint(value).then_some(value)
}

fn temporary_generation(name: &str) -> bool {
    let Some(value) = name
        .strip_prefix(".generation-")
        .and_then(|value| value.strip_suffix(".tmp"))
    else {
        return false;
    };
    let Some((digits, writer)) = value.split_once('.') else {
        return false;
    };
    generation_number(&format!("generation-{digits}")).is_some()
        && !writer.is_empty()
        && writer.len() <= 32
        && writer.bytes().all(|byte| byte.is_ascii_digit())
}

fn hash(bytes: &[u8]) -> Result<String, InternalError> {
    runner::sha256_bytes(bytes)
}

fn extend_value(old: &str, manifest: &str) -> Result<String, InternalError> {
    let mut bytes = Vec::with_capacity(64);
    bytes.extend_from_slice(&decode_hash(old)?);
    bytes.extend_from_slice(&decode_hash(manifest)?);
    hash(&bytes)
}

fn decode_hash(value: &str) -> Result<[u8; 32], InternalError> {
    if !sha256(value) {
        return Err(InternalError("invalid SHA-256 hash".into()));
    }
    let mut out = [0_u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        out[index] = u8::from_str_radix(std::str::from_utf8(chunk).unwrap_or(""), 16)
            .map_err(|_| InternalError("invalid SHA-256 hash".into()))?;
    }
    Ok(out)
}

fn hex(value: [u8; 32]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn secure_existing_dir(path: &Path) -> Result<(), InternalError> {
    validate_secure_state_directory(path).map_err(InternalError)
}

fn secure_optional_dir(path: &Path) -> Result<bool, InternalError> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => {
            secure_existing_dir(path)?;
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(InternalError(format!(
            "cannot inspect {}: {error}",
            path.display()
        ))),
    }
}

fn atomic_replace(dir: &Path, name: &str, bytes: &[u8]) -> Result<(), InternalError> {
    ensure_secure_state_directory(dir)?;
    let destination = dir.join(name);
    let _ = read_optional_regular(&destination, 0o600)?;
    let (temp, mut file) = (0_u16..=u16::MAX)
        .find_map(|attempt| {
            let path = dir.join(format!(".{name}.{}.{attempt}.tmp", std::process::id()));
            match new_file(&path) {
                Ok(file) => Some(Ok((path, file))),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => None,
                Err(error) => Some(Err(InternalError(format!(
                    "cannot stage state-v1 {name}: {error}"
                )))),
            }
        })
        .transpose()?
        .ok_or_else(|| InternalError(format!("no free staging name for state-v1 {name}")))?;
    if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = std::fs::remove_file(&temp);
        return Err(InternalError(format!(
            "cannot sync {}: {error}",
            temp.display()
        )));
    }
    drop(file);
    if let Err(error) = std::fs::rename(&temp, &destination) {
        let _ = std::fs::remove_file(&temp);
        return Err(InternalError(format!(
            "cannot publish state-v1 {name}: {error}"
        )));
    }
    sync_dir(dir)
}

fn new_file(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), InternalError> {
    let mut file = new_file(path)
        .map_err(|error| InternalError(format!("cannot create {}: {error}", path.display())))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| InternalError(format!("cannot sync {}: {error}", path.display())))
}

fn read_optional_regular(path: &Path, mode: u32) -> Result<Option<Vec<u8>>, InternalError> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => read_regular(path, mode).map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(InternalError(format!(
            "cannot inspect {}: {error}",
            path.display()
        ))),
    }
}

fn read_regular(path: &Path, mode: u32) -> Result<Vec<u8>, InternalError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)
        .map_err(|error| InternalError(format!("cannot open {}: {error}", path.display())))?;
    let metadata = file
        .metadata()
        .map_err(|error| InternalError(format!("cannot inspect {}: {error}", path.display())))?;
    let named = std::fs::symlink_metadata(path)
        .map_err(|error| InternalError(format!("cannot inspect {}: {error}", path.display())))?;
    if !metadata.file_type().is_file()
        || !named.file_type().is_file()
        || metadata.dev() != named.dev()
        || metadata.ino() != named.ino()
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != mode
        || (unsafe { geteuid() } == 0 && metadata.uid() != 0)
    {
        return Err(InternalError(format!(
            "{} is not a stable regular mode-{mode:04o} file",
            path.display()
        )));
    }
    let mut bytes = Vec::new();
    file.take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| InternalError(format!("cannot read {}: {error}", path.display())))?;
    if bytes.len() > 1024 * 1024 {
        return Err(InternalError(format!(
            "state-v1 file {} exceeds 1 MiB",
            path.display()
        )));
    }
    Ok(bytes)
}

fn sync_dir(path: &Path) -> Result<(), InternalError> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|error| InternalError(format!("cannot sync {}: {error}", path.display())))
}

fn parse_clock(output: &str) -> Result<TpmClockState, InternalError> {
    let field = |name: &str| -> Result<&str, InternalError> {
        let mut values = output
            .lines()
            .filter_map(|line| line.trim().strip_prefix(name))
            .map(str::trim);
        let value = values
            .next()
            .ok_or_else(|| InternalError(format!("tpm2_readclock lacks {name}")))?;
        if values.next().is_some() {
            return Err(InternalError(format!(
                "tpm2_readclock contains duplicate {name}"
            )));
        }
        Ok(value)
    };
    let number = |name: &str| -> Result<u64, InternalError> {
        field(name)?
            .parse()
            .map_err(|_| InternalError(format!("tpm2_readclock has invalid {name}")))
    };
    let safe = match field("safe:")? {
        "yes" | "true" | "1" => true,
        "no" | "false" | "0" => false,
        _ => return Err(InternalError("tpm2_readclock has invalid safe:".into())),
    };
    Ok(TpmClockState {
        clock: number("clock:")?,
        reset_count: number("reset_count:")?
            .try_into()
            .map_err(|_| InternalError("TPM reset_count overflow".into()))?,
        restart_count: number("restart_count:")?
            .try_into()
            .map_err(|_| InternalError("TPM restart_count overflow".into()))?,
        safe,
    })
}

fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>, InternalError> {
    let value = serde_json::to_value(value)
        .map_err(|error| InternalError(format!("cannot encode state-v1 value: {error}")))?;
    let mut bytes = serde_json::to_vec(&value)
        .map_err(|error| InternalError(format!("cannot encode state-v1 value: {error}")))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn fresh_nonce() -> Result<String, InternalError> {
    #[cfg(feature = "test-path-overrides")]
    let source = std::env::var_os("NI_OTA_RANDOM_SOURCE")
        .map_or_else(|| PathBuf::from("/dev/urandom"), PathBuf::from);
    #[cfg(not(feature = "test-path-overrides"))]
    let source = PathBuf::from("/dev/urandom");
    nonce_from(&source)
}

fn nonce_from(source: &Path) -> Result<String, InternalError> {
    let mut bytes = [0_u8; 32];
    File::open(source)
        .and_then(|mut file| file.read_exact(&mut bytes))
        .map_err(|error| {
            InternalError(format!(
                "cannot read 32-byte trusted-time nonce from {}: {error}",
                source.display()
            ))
        })?;
    Ok(hex(bytes))
}

fn inspect_state_index(output: &str, index: u32) -> Result<bool, InternalError> {
    #[derive(Clone, Copy)]
    enum Section {
        HashAlgorithm,
        Attributes,
    }

    let mut in_index = false;
    let mut section = None;
    let mut name = None;
    let mut algorithm = None;
    let mut attributes = None;
    let mut size = None;
    let mut authorization_policy = None;
    for line in output.lines() {
        let trimmed = line.trim();
        if parse_index_header(trimmed) == Some(index) {
            in_index = true;
            section = None;
            continue;
        }
        if !in_index {
            continue;
        }
        if !line.chars().next().is_some_and(char::is_whitespace) && trimmed.ends_with(':') {
            break;
        }
        if let Some(value) = trimmed.strip_prefix("name:") {
            name = parse_unique_hex(name, value, 34, "name", index)?;
            section = None;
        } else if let Some(value) = trimmed.strip_prefix("hash algorithm:") {
            let value = value.trim();
            if value.is_empty() {
                section = Some(Section::HashAlgorithm);
            } else {
                algorithm = parse_unique_text(algorithm, value, "hash algorithm", index)?;
                section = None;
            }
        } else if trimmed == "attributes:" {
            section = Some(Section::Attributes);
        } else if let Some(value) = trimmed.strip_prefix("friendly:") {
            match section {
                Some(Section::HashAlgorithm) => {
                    algorithm =
                        parse_unique_text(algorithm, value.trim(), "hash algorithm", index)?;
                }
                Some(Section::Attributes) => {
                    if attributes.is_some() {
                        return Err(invalid_index(index, "duplicate attributes"));
                    }
                    let mut values: Vec<_> = value
                        .trim()
                        .split('|')
                        .map(|attribute| match attribute {
                            // tpm2-tools has emitted both spellings for the
                            // same TPM_NT_EXTEND bitfield across supported
                            // releases. Normalize the presentation, not the
                            // underlying policy.
                            "nt=extend" => "nt=0x1",
                            other => other,
                        })
                        .collect();
                    values.sort_unstable();
                    attributes = Some(values.join("|"));
                }
                None => return Err(invalid_index(index, "friendly value outside a section")),
            }
        } else if let Some(value) = trimmed.strip_prefix("size:") {
            if size.is_some() {
                return Err(invalid_index(index, "duplicate size"));
            }
            size = value.trim().parse::<u64>().ok();
            section = None;
        } else if let Some(value) = trimmed.strip_prefix("authorization policy:") {
            authorization_policy = parse_unique_hex(
                authorization_policy,
                value,
                32,
                "authorization policy",
                index,
            )?;
            section = None;
        }
    }
    let expected_written = format!("{STATE_NV_ATTRIBUTES}|written");
    let written = attributes.as_deref() == Some(expected_written.as_str());
    let expected_name = if written {
        STATE_NV_NAME_WRITTEN
    } else {
        STATE_NV_NAME_UNWRITTEN
    };
    if algorithm != Some("sha256")
        || (!written && attributes.as_deref() != Some(STATE_NV_ATTRIBUTES))
        || size != Some(32)
        || name.as_deref() != Some(expected_name)
        || authorization_policy.as_deref() != Some(STATE_NV_DELETE_AUTH_POLICY)
    {
        return Err(invalid_index(
            index,
            "public area, name, or root-authorized deletion policy mismatch",
        ));
    }
    Ok(written)
}

fn parse_unique_text<'a>(
    current: Option<&'a str>,
    value: &'a str,
    field: &str,
    index: u32,
) -> Result<Option<&'a str>, InternalError> {
    if current.is_some() || value.is_empty() {
        return Err(invalid_index(
            index,
            &format!("invalid or duplicate {field}"),
        ));
    }
    Ok(Some(value))
}

fn parse_unique_hex(
    current: Option<String>,
    value: &str,
    bytes: usize,
    field: &str,
    index: u32,
) -> Result<Option<String>, InternalError> {
    let normalized = value.trim().to_ascii_lowercase();
    if current.is_some()
        || normalized.len() != bytes * 2
        || !normalized.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(invalid_index(
            index,
            &format!("invalid or duplicate {field}"),
        ));
    }
    Ok(Some(normalized))
}

fn invalid_index(index: u32, reason: &str) -> InternalError {
    InternalError(format!(
        "TPM NV 0x{index:08x} is not the exact SHA-256 32-byte EXTEND index: {reason}"
    ))
}

fn parse_index_header(line: &str) -> Option<u32> {
    let hexadecimal = line.strip_prefix("0x")?.strip_suffix(':')?;
    if hexadecimal.is_empty() || !hexadecimal.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    u32::from_str_radix(hexadecimal, 16).ok()
}

fn contains_nv_handle(output: &str, expected: u32) -> bool {
    output
        .split_ascii_whitespace()
        .map(|value| value.trim_start_matches('-').trim())
        .filter_map(|value| {
            value
                .strip_prefix("0x")
                .or_else(|| value.strip_prefix("0X"))
        })
        .filter_map(|value| u32::from_str_radix(value, 16).ok())
        .any(|value| value == expected)
}

fn tool(name: &str) -> PathBuf {
    #[cfg(feature = "test-path-overrides")]
    if let Some(path) = std::env::var_os(format!("NI_OTA_{}", name.to_ascii_uppercase())) {
        return PathBuf::from(path);
    }
    PathBuf::from(format!("/usr/bin/{name}"))
}

unsafe extern "C" {
    fn geteuid() -> u32;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn hex_bytes(value: &str) -> Vec<u8> {
        assert_eq!(value.len() % 2, 0);
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    #[test]
    fn deletion_policy_uses_the_normative_two_step_policy_update() {
        let mut authorize_name = vec![0_u8; 32];
        authorize_name.extend_from_slice(&0x0000_016a_u32.to_be_bytes());
        authorize_name.extend_from_slice(&hex_bytes(
            "000beb256627a4315f1a3d2a2a0c9931760ad30e8822b35c5ebed854f1829b07b7b1",
        ));
        let authorize_name = runner::sha256_bytes(&authorize_name).unwrap();
        assert_eq!(
            authorize_name,
            "8599598585b872929367c006ff1e53da890a41a20a590f436b160ebb141d7e85"
        );

        let mut authorize_ref = hex_bytes(&authorize_name);
        authorize_ref.extend_from_slice(b"neural-ice:ota:state-nv-delete:v1\0");
        let authorize_ref = runner::sha256_bytes(&authorize_ref).unwrap();
        assert_eq!(
            authorize_ref,
            "acd9fab3a701a6738e092425f342abd45962ffc2808f399d59aa615f892df063"
        );

        let mut command_code = hex_bytes(&authorize_ref);
        command_code.extend_from_slice(&0x0000_016c_u32.to_be_bytes());
        command_code.extend_from_slice(&0x0000_011f_u32.to_be_bytes());
        assert_eq!(
            runner::sha256_bytes(&command_code).unwrap(),
            STATE_NV_DELETE_AUTH_POLICY
        );
    }

    #[test]
    fn provisioning_uses_the_platform_hierarchy_and_pinned_policy() {
        let args = nvdefine_args(STATE_NV_INDEX, Path::new("/run/private/policy.bin"));
        let args: Vec<_> = args
            .iter()
            .map(|value| value.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            args,
            [
                "0x01500002",
                "-C",
                "p",
                "-s",
                "32",
                "-a",
                STATE_NV_ATTRIBUTES,
                "-L",
                "/run/private/policy.bin",
            ]
        );
        assert!(!args.iter().any(|value| value == "o"));
    }

    #[derive(Clone, Copy)]
    struct TestAnchor {
        anchor: [u8; 32],
        initialized: bool,
        readable: bool,
        legacy_floor: Option<u64>,
        safe_clock: bool,
    }

    impl NvAnchor for TestAnchor {
        fn attest(&self) -> Result<(), InternalError> {
            self.initialized
                .then_some(())
                .ok_or_else(|| InternalError("uninitialized state anchor".into()))
        }

        fn read(&self) -> Result<[u8; 32], InternalError> {
            self.readable
                .then_some(self.anchor)
                .ok_or_else(|| InternalError("unreadable state anchor".into()))
        }

        fn legacy_bundle_floor(&self) -> Result<Option<u64>, InternalError> {
            Ok(self.legacy_floor)
        }

        fn clock(&self) -> Result<TpmClockState, InternalError> {
            Ok(TpmClockState {
                clock: 42,
                reset_count: 3,
                restart_count: 4,
                safe: self.safe_clock,
            })
        }

        fn read_initial(&self) -> Result<[u8; 32], InternalError> {
            self.read()
        }

        fn provision_initial(&self) -> Result<(), InternalError> {
            Err(InternalError("test anchor cannot be provisioned".into()))
        }

        fn extend(&self, _digest: [u8; 32]) -> Result<(), InternalError> {
            Err(InternalError("test anchor cannot be extended".into()))
        }
    }

    struct ChangingAnchor {
        first: [u8; 32],
        later: [u8; 32],
        reads: Cell<u8>,
    }

    impl NvAnchor for ChangingAnchor {
        fn attest(&self) -> Result<(), InternalError> {
            Ok(())
        }

        fn read(&self) -> Result<[u8; 32], InternalError> {
            let reads = self.reads.get();
            self.reads.set(reads.saturating_add(1));
            Ok(if reads == 0 { self.first } else { self.later })
        }

        fn legacy_bundle_floor(&self) -> Result<Option<u64>, InternalError> {
            Ok(Some(1))
        }

        fn clock(&self) -> Result<TpmClockState, InternalError> {
            Ok(TpmClockState {
                clock: 42,
                reset_count: 1,
                restart_count: 1,
                safe: true,
            })
        }

        fn read_initial(&self) -> Result<[u8; 32], InternalError> {
            self.read()
        }

        fn provision_initial(&self) -> Result<(), InternalError> {
            Err(InternalError("test anchor cannot be provisioned".into()))
        }

        fn extend(&self, _digest: [u8; 32]) -> Result<(), InternalError> {
            Err(InternalError("test anchor cannot be extended".into()))
        }
    }

    struct GenerationSpec<'a> {
        generation: u64,
        bundle: u64,
        delegation: u64,
        time_seq: u64,
        trusted_time: &'a str,
        legacy: Option<u64>,
        previous_manifest: Option<String>,
        previous_anchor: String,
    }

    #[derive(Clone, Copy)]
    struct GenerationArtifacts {
        bind_assertion: bool,
        bind_snapshot: bool,
        release_json: u8,
        variant: u8,
    }

    impl Default for GenerationArtifacts {
        fn default() -> Self {
            Self {
                bind_assertion: true,
                bind_snapshot: true,
                release_json: 0,
                variant: 0,
            }
        }
    }

    struct MemoryNv {
        anchor: Cell<[u8; 32]>,
        clock: Cell<TpmClockState>,
        exists: Cell<bool>,
    }

    impl NvAnchor for MemoryNv {
        fn attest(&self) -> Result<(), InternalError> {
            self.exists
                .get()
                .then_some(())
                .ok_or_else(|| InternalError("absent".into()))
        }

        fn read(&self) -> Result<[u8; 32], InternalError> {
            self.attest().map(|()| self.anchor.get())
        }

        fn legacy_bundle_floor(&self) -> Result<Option<u64>, InternalError> {
            Ok(Some(1))
        }

        fn clock(&self) -> Result<TpmClockState, InternalError> {
            Ok(self.clock.get())
        }

        fn read_initial(&self) -> Result<[u8; 32], InternalError> {
            Ok(self.anchor.get())
        }

        fn provision_initial(&self) -> Result<(), InternalError> {
            if self.exists.replace(true) {
                return Err(InternalError("reseed".into()));
            }
            Ok(())
        }

        fn extend(&self, digest: [u8; 32]) -> Result<(), InternalError> {
            self.attest()?;
            let next = extend_value(&hex(self.anchor.get()), &hex(digest))?;
            self.anchor.set(decode_hash(&next)?);
            Ok(())
        }
    }

    fn test_signed_assertion(
        challenge: &TimeChallenge,
        trusted: &TrustedTimeState,
        valid_until: &str,
    ) -> &'static [u8] {
        Box::leak(
            canonical(&crate::trusted_time::TrustedTimeAssertion {
                assertion_seq: trusted.assertion_seq,
                delegation_seq: trusted.delegation_seq,
                delegation_snapshot_sha256: challenge.delegation_snapshot_sha256.clone(),
                device_fingerprint: trusted.device_fingerprint.clone(),
                hardware_target: challenge.hardware_target.clone(),
                issuance_id: "assertion-1".into(),
                issued_at: "2026-07-22T00:00:00Z".into(),
                issuer: "licensing.neural-ice.ch".into(),
                key_id: trusted.key_id.clone(),
                nonce: challenge.nonce.clone(),
                release_authorization_sha256: challenge.release_authorization_sha256.clone(),
                ring: challenge.ring.clone(),
                schema: "neural-ice-ota-trusted-time-v2".into(),
                signature_algorithm: "ECDSA".into(),
                signature_encoding: "der".into(),
                signing_role: "trusted-time".into(),
                state_nv_anchor: challenge.state_nv_anchor.clone(),
                tpm_clock: trusted.tpm_clock,
                tpm_reset_count: trusted.tpm_reset_count,
                tpm_restart_count: trusted.tpm_restart_count,
                tpm_safe: trusted.tpm_safe,
                trusted_time: trusted.trusted_time.clone(),
                valid_until: valid_until.into(),
            })
            .unwrap()
            .into_boxed_slice(),
        )
    }

    fn candidate() -> Candidate<'static> {
        let challenge = TimeChallenge {
            delegation_snapshot_sha256: state_canonical_hash(b"{}\n", "test snapshot").unwrap(),
            device_fingerprint: "b".repeat(64),
            hardware_target: "nvidia-gb10-arm64".into(),
            nonce: "c".repeat(64),
            release_authorization_sha256: state_canonical_hash(b"{}\n", "test release").unwrap(),
            ring: "beta".into(),
            schema: "neural-ice-ota-time-challenge-v2".into(),
            state_nv_anchor: ZERO_ANCHOR.into(),
            tpm_clock: 1_000,
            tpm_reset_count: 1,
            tpm_restart_count: 1,
            tpm_safe: true,
        };
        let mut trusted = TrustedTimeState {
            assertion_seq: 1,
            assertion_sha256: String::new(),
            challenge_sha256: hash(challenge.nonce.as_bytes()).unwrap(),
            delegation_seq: 1,
            device_fingerprint: challenge.device_fingerprint.clone(),
            key_id: "trusted-time-v1".into(),
            schema: "neural-ice-ota-trusted-time-state-v2".into(),
            signature_sha256: hash(b"sig").unwrap(),
            tpm_clock: challenge.tpm_clock,
            tpm_reset_count: challenge.tpm_reset_count,
            tpm_restart_count: challenge.tpm_restart_count,
            tpm_safe: true,
            trusted_time: "2026-07-22T00:00:01Z".into(),
        };
        let assertion = test_signed_assertion(&challenge, &trusted, "2026-07-22T00:05:00Z");
        trusted.assertion_sha256 =
            state_canonical_hash(assertion, "test trusted-time assertion").unwrap();
        Candidate {
            applied: AppliedStateV1 {
                bom_sha256: "e".repeat(64),
                bundle_seq: 1,
                schema: "neural-ice-ota-applied-state-v1".into(),
            },
            authority: AuthorityState {
                delegation_seq: 1,
                schema: "neural-ice-ota-authority-state-v1".into(),
                snapshot_sha256: challenge.delegation_snapshot_sha256.clone(),
                snapshot_signature_sha256: hash(b"sig").unwrap(),
            },
            challenge: challenge.clone(),
            release: b"{}\n",
            release_signature: b"sig",
            snapshot: b"{}\n",
            snapshot_signature: b"sig",
            trusted,
            trusted_assertion: assertion,
            trusted_signature: b"sig",
        }
    }

    fn test_store() -> (Store, PathBuf) {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let temp = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        let root = temp.join(format!(
            "ni-ota-state-read-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        ensure_secure_state_directory(&root).unwrap();
        ensure_secure_state_directory(&root.join("generations")).unwrap();
        (Store { root: root.clone() }, root)
    }

    fn write_file(path: &Path, bytes: &[u8]) {
        let mut file = new_file(path).unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
    }

    fn write_generation(store: &Store, spec: GenerationSpec<'_>) -> (String, String) {
        write_generation_with_artifacts(store, spec, GenerationArtifacts::default())
    }

    fn write_generation_with_artifacts(
        store: &Store,
        spec: GenerationSpec<'_>,
        artifacts: GenerationArtifacts,
    ) -> (String, String) {
        let dir = store
            .root
            .join("generations")
            .join(format!("generation-{:016}", spec.generation));
        ensure_secure_state_directory(&dir).unwrap();

        let snapshot = b"{}\n";
        let assertion = b"{}\n";
        let snapshot_signature = artifact_variant(b"snapshot-signature", artifacts.variant);
        let release = artifact_variant(
            match artifacts.release_json {
                0 => b"{}\n".as_slice(),
                1 => b"{ }\n".as_slice(),
                _ => b"{\n".as_slice(),
            },
            artifacts.variant,
        );
        let release_signature = artifact_variant(b"release-signature", artifacts.variant);
        let assertion_signature = artifact_variant(b"trusted-time-signature", artifacts.variant);
        let snapshot_canonical_hash = if artifacts.bind_snapshot {
            canonical_hash(snapshot).unwrap()
        } else {
            canonical_hash(b"{\"different\":true}\n").unwrap()
        };
        let assertion_canonical_hash = if artifacts.bind_assertion {
            canonical_hash(assertion).unwrap()
        } else {
            canonical_hash(b"{\"different\":true}\n").unwrap()
        };
        let applied = AppliedStateV1 {
            bom_sha256: format!("{:x}", spec.bundle)
                .repeat(64)
                .chars()
                .take(64)
                .collect(),
            bundle_seq: spec.bundle,
            schema: "neural-ice-ota-applied-state-v1".into(),
        };
        let authority = AuthorityState {
            delegation_seq: spec.delegation,
            schema: "neural-ice-ota-authority-state-v1".into(),
            snapshot_sha256: snapshot_canonical_hash,
            snapshot_signature_sha256: hash(&snapshot_signature).unwrap(),
        };
        let trusted = TrustedTimeState {
            assertion_seq: spec.time_seq,
            assertion_sha256: assertion_canonical_hash,
            challenge_sha256: hash(b"challenge").unwrap(),
            delegation_seq: spec.delegation,
            device_fingerprint: "d".repeat(64),
            key_id: "trusted-time-v1".into(),
            schema: "neural-ice-ota-trusted-time-state-v2".into(),
            signature_sha256: hash(&assertion_signature).unwrap(),
            tpm_clock: spec.generation * 1_000,
            tpm_reset_count: 1,
            tpm_restart_count: spec.generation as u32,
            tpm_safe: true,
            trusted_time: spec.trusted_time.into(),
        };
        let applied_bytes = canonical(&applied).unwrap();
        let authority_bytes = canonical(&authority).unwrap();
        let trusted_bytes = canonical(&trusted).unwrap();
        for (name, bytes) in [
            ("applied.json", applied_bytes.as_slice()),
            ("authority.json", authority_bytes.as_slice()),
            ("delegation-snapshot.json", snapshot),
            ("delegation-snapshot.sig", snapshot_signature.as_slice()),
            ("release-authorization.json", release.as_slice()),
            ("release-authorization.sig", release_signature.as_slice()),
            ("trusted-time-assertion.json", assertion),
            ("trusted-time-assertion.sig", assertion_signature.as_slice()),
            ("trusted-time.json", trusted_bytes.as_slice()),
        ] {
            write_file(&dir.join(name), bytes);
        }
        let manifest = StateManifest {
            applied_sha256: hash(&applied_bytes).unwrap(),
            applied_bom_sha256: applied.bom_sha256,
            authority_sha256: hash(&authority_bytes).unwrap(),
            bundle_seq_floor: spec.bundle,
            delegation_seq_floor: spec.delegation,
            delegation_snapshot_canonical_sha256: authority.snapshot_sha256,
            delegation_snapshot_sha256: hash(snapshot).unwrap(),
            delegation_snapshot_signature_sha256: hash(&snapshot_signature).unwrap(),
            generation: spec.generation,
            legacy_bundle_floor: spec.legacy,
            previous_manifest_sha256: spec.previous_manifest,
            previous_nv_anchor: spec.previous_anchor.clone(),
            release_authorization_sha256: hash(&release).unwrap(),
            release_authorization_signature_sha256: hash(&release_signature).unwrap(),
            schema: "neural-ice-ota-state-manifest-v1".into(),
            trusted_time_assertion_canonical_sha256: trusted.assertion_sha256,
            trusted_time_assertion_sha256: hash(assertion).unwrap(),
            trusted_time_assertion_signature_sha256: hash(&assertion_signature).unwrap(),
            trusted_time_floor: trusted.trusted_time,
            trusted_time_seq_floor: spec.time_seq,
            trusted_time_sha256: hash(&trusted_bytes).unwrap(),
        };
        let manifest_bytes = canonical(&manifest).unwrap();
        write_file(&dir.join("manifest.json"), &manifest_bytes);
        sync_dir(&dir).unwrap();
        sync_dir(&store.root.join("generations")).unwrap();
        let manifest_hash = hash(&manifest_bytes).unwrap();
        let anchor = extend_value(&spec.previous_anchor, &manifest_hash).unwrap();
        (manifest_hash, anchor)
    }

    fn artifact_variant(base: &[u8], variant: u8) -> Vec<u8> {
        if variant == 0 {
            base.to_vec()
        } else {
            [base, format!("-{variant}").as_bytes()].concat()
        }
    }

    #[test]
    fn state_nv_attestation_requires_exact_index_type_size_and_policy() {
        let base = "0x1500002:\n  name: 000b8ae052b814918370b191fe38782bb500041130d0665b1e7b2a368edcaf81eb62\n  hash algorithm:\n    friendly: sha256\n    value: 0xB\n  attributes:\n    friendly: authwrite|nt=0x1|policydelete|ownerread|authread|no_da|platformcreate\n    value: 0x42060444\n  size: 32\n  authorization policy: 921F9FA2CE8C30BBF29B84500A8456188F1FEBC04F154E9ECCCA4D5B1BC8A25D\n";
        assert!(!inspect_state_index(base, STATE_NV_INDEX).unwrap());
        assert!(
            !inspect_state_index(&base.replace("nt=0x1", "nt=extend"), STATE_NV_INDEX).unwrap()
        );
        assert!(!inspect_state_index(
            &base.replacen("0x1500002:", "0x01500002:", 1),
            STATE_NV_INDEX
        )
        .unwrap());
        let written = base
            .replace(
                "000b8ae052b814918370b191fe38782bb500041130d0665b1e7b2a368edcaf81eb62",
                "000b571132a9688f4088f3696fa9bf5d5793be7483202cee08ceb2261f2bbe89b440",
            )
            .replace("no_da|platformcreate", "no_da|written|platformcreate");
        assert!(inspect_state_index(&written, STATE_NV_INDEX).unwrap());
        assert!(inspect_state_index(
            &written.replacen("0x1500002:", "0x01500002:", 1),
            STATE_NV_INDEX
        )
        .unwrap());
        assert!(inspect_state_index(
            &written.replacen("0x1500002:", "0x1500003:", 1),
            STATE_NV_INDEX
        )
        .is_err());
        assert!(inspect_state_index(&base.replace("size: 32", "size: 8"), STATE_NV_INDEX).is_err());
        assert!(
            inspect_state_index(&base.replace("nt=0x1", "nt=counter"), STATE_NV_INDEX).is_err()
        );
        assert!(inspect_state_index(
            &base.replace("ownerread|", "ownerread|ownerwrite|"),
            STATE_NV_INDEX
        )
        .is_err());
        assert!(inspect_state_index(
            &base.replace("platformcreate", "platformcreate|policywrite"),
            STATE_NV_INDEX
        )
        .is_err());
        assert!(inspect_state_index(
            &base.replace(
                STATE_NV_DELETE_AUTH_POLICY.to_ascii_uppercase().as_str(),
                &"00".repeat(32)
            ),
            STATE_NV_INDEX
        )
        .is_err());
        assert!(inspect_state_index(
            &base.replace(STATE_NV_NAME_UNWRITTEN, &format!("000b{}", "00".repeat(32))),
            STATE_NV_INDEX
        )
        .is_err());
        assert!(inspect_state_index(
            &format!("{base}  authorization policy: {STATE_NV_DELETE_AUTH_POLICY}\n"),
            STATE_NV_INDEX
        )
        .is_err());
    }

    #[test]
    fn capability_stays_hidden_until_the_complete_command_set_lands() {
        assert!(!capability_ready(Path::new("missing.conf")).unwrap());
    }

    #[test]
    fn compiled_capability_fails_closed_when_runtime_attestation_cannot_start() {
        let error = capability_ready_for(Path::new("missing.conf"), true).unwrap_err();
        assert!(error.0.contains("unreadable config"));
    }

    #[test]
    fn parses_only_safe_tpm_clock() {
        let value =
            parse_clock("clock: 42\nreset_count: 3\nrestart_count: 4\nsafe: yes\n").unwrap();
        assert_eq!(
            value,
            TpmClockState {
                clock: 42,
                reset_count: 3,
                restart_count: 4,
                safe: true
            }
        );
        assert!(
            !parse_clock("clock: 42\nreset_count: 3\nrestart_count: 4\nsafe: no\n")
                .unwrap()
                .safe
        );
        assert!(parse_clock("clock: nope\nreset_count: 3\nrestart_count: 4\nsafe: yes\n").is_err());
        assert!(
            parse_clock("clock: 42\nclock: 43\nreset_count: 3\nrestart_count: 4\nsafe: yes\n")
                .is_err()
        );
        assert!(parse_clock("clock: 42\nreset_count: 3\nrestart_count: 4\nsafe: maybe\n").is_err());
    }

    #[test]
    fn legacy_handle_detection_accepts_tpm_tools_non_padded_hex_only() {
        assert!(contains_nv_handle("- 0x1500001\n", LEGACY_NV_INDEX));
        assert!(contains_nv_handle("0X01500001", LEGACY_NV_INDEX));
        assert!(!contains_nv_handle("0x015000010", LEGACY_NV_INDEX));
        assert!(!contains_nv_handle("noise1500001", LEGACY_NV_INDEX));
    }

    #[test]
    fn extend_chain_is_ordered_and_not_overwritable() {
        let first = extend_value(ZERO_ANCHOR, &"1".repeat(64)).unwrap();
        let second = extend_value(&first, &"2".repeat(64)).unwrap();
        assert_ne!(first, second);
        assert_ne!(second, extend_value(ZERO_ANCHOR, &"2".repeat(64)).unwrap());
    }

    #[test]
    fn pointers_are_exact_and_bounded() {
        assert_eq!(parse_pointer(b"generation-0000000000000001\n").unwrap(), 1);
        assert!(parse_pointer(b"generation-0000000000000001").is_err());
        assert!(parse_pointer(b"generation-0000000000000000\n").is_err());
        assert!(parse_pointer(b"generation-9007199254740992\n").is_err());
        assert!(parse_pointer(b"../generation-0000000000000001\n").is_err());
        assert!(temporary_generation(".generation-0000000000000001.123.tmp"));
        assert!(!temporary_generation(".anything.tmp"));
        assert!(!temporary_generation(
            ".generation-0000000000000001.writer.tmp"
        ));
    }

    #[test]
    fn continuity_requires_initialized_anchor_legacy_floor_and_safe_clock() {
        let ready = TestAnchor {
            anchor: [0x42; 32],
            initialized: true,
            readable: true,
            legacy_floor: Some(7),
            safe_clock: true,
        };
        assert!(continuity_ready(&ready).unwrap());
        assert!(continuity_ready(&TestAnchor {
            initialized: false,
            ..ready
        })
        .is_err());
        assert!(continuity_ready(&TestAnchor {
            readable: false,
            ..ready
        })
        .is_err());
        assert!(continuity_ready(&TestAnchor {
            legacy_floor: None,
            ..ready
        })
        .is_err());
        assert!(continuity_ready(&TestAnchor {
            safe_clock: false,
            ..ready
        })
        .is_err());
    }

    #[test]
    fn missing_current_recovers_only_the_complete_tpm_anchored_generation() {
        let (store, root) = test_store();
        let (_, anchor) = write_generation(
            &store,
            GenerationSpec {
                generation: 1,
                bundle: 1,
                delegation: 1,
                time_seq: 1,
                trusted_time: "2026-07-21T12:00:00Z",
                legacy: Some(1),
                previous_manifest: None,
                previous_anchor: ZERO_ANCHOR.into(),
            },
        );
        let nv = TestAnchor {
            anchor: decode_hash(&anchor).unwrap(),
            initialized: true,
            readable: true,
            legacy_floor: Some(1),
            safe_clock: true,
        };
        let loaded = store.read_current(&nv).unwrap().unwrap();
        assert_eq!(loaded.manifest.generation, 1);
        assert_eq!(
            std::fs::read(store.root.join("current")).unwrap(),
            b"generation-0000000000000001\n"
        );
        assert!(store.verify_enforce_ready(&nv).is_ok());
        assert!(store.root.join("enforce-ready.json").is_file());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn malformed_or_symlink_current_is_never_repaired() {
        use std::os::unix::fs::symlink;

        let (store, root) = test_store();
        let (_, anchor) = write_generation(
            &store,
            GenerationSpec {
                generation: 1,
                bundle: 1,
                delegation: 1,
                time_seq: 1,
                trusted_time: "2026-07-21T12:00:00Z",
                legacy: Some(1),
                previous_manifest: None,
                previous_anchor: ZERO_ANCHOR.into(),
            },
        );
        let nv = TestAnchor {
            anchor: decode_hash(&anchor).unwrap(),
            initialized: true,
            readable: true,
            legacy_floor: Some(1),
            safe_clock: true,
        };
        let current = store.root.join("current");
        write_file(&current, b"partial\n");
        assert!(store.read_current(&nv).is_err());
        assert_eq!(std::fs::read(&current).unwrap(), b"partial\n");
        std::fs::remove_file(&current).unwrap();
        symlink(
            store
                .root
                .join("generations/generation-0000000000000001/manifest.json"),
            &current,
        )
        .unwrap();
        assert!(store.read_current(&nv).is_err());
        assert!(std::fs::symlink_metadata(&current)
            .unwrap()
            .file_type()
            .is_symlink());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn partial_or_nonregular_generation_evidence_fails_closed() {
        let (store, root) = test_store();
        ensure_secure_state_directory(&store.root.join("generations/generation-0000000000000001"))
            .unwrap();
        let nv = TestAnchor {
            anchor: [0x55; 32],
            initialized: true,
            readable: true,
            legacy_floor: Some(1),
            safe_clock: true,
        };
        assert!(store.read_current(&nv).is_err());
        std::fs::remove_dir_all(root).unwrap();

        let (store, root) = test_store();
        write_file(
            &store
                .root
                .join("generations/.generation-0000000000000001.7.tmp"),
            b"partial",
        );
        assert!(store
            .read_current(&TestAnchor {
                anchor: [0; 32],
                initialized: false,
                readable: true,
                legacy_floor: None,
                safe_clock: true,
            })
            .is_err());
        assert!(!store.root.join("current").exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn generation_inventory_and_recovery_anchor_are_revalidated_before_publication() {
        let (store, root) = test_store();
        let (_, anchor) = write_generation(
            &store,
            GenerationSpec {
                generation: 1,
                bundle: 1,
                delegation: 1,
                time_seq: 1,
                trusted_time: "2026-07-21T12:00:00Z",
                legacy: Some(1),
                previous_manifest: None,
                previous_anchor: ZERO_ANCHOR.into(),
            },
        );
        let generation = store.root.join("generations/generation-0000000000000001");
        write_file(&generation.join("unexpected"), b"not-manifest-bound");
        let stable = TestAnchor {
            anchor: decode_hash(&anchor).unwrap(),
            initialized: true,
            readable: true,
            legacy_floor: Some(1),
            safe_clock: true,
        };
        assert!(store.read_current(&stable).is_err());
        std::fs::remove_file(generation.join("unexpected")).unwrap();

        let changing = ChangingAnchor {
            first: decode_hash(&anchor).unwrap(),
            later: [0x55; 32],
            reads: Cell::new(0),
        };
        assert!(store.read_current(&changing).is_err());
        assert!(!store.root.join("current").exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn artifact_tamper_and_persisted_floor_regression_fail_closed() {
        let (store, root) = test_store();
        let (first_manifest, first_anchor) = write_generation(
            &store,
            GenerationSpec {
                generation: 1,
                bundle: 2,
                delegation: 2,
                time_seq: 2,
                trusted_time: "2026-07-21T12:00:02Z",
                legacy: Some(2),
                previous_manifest: None,
                previous_anchor: ZERO_ANCHOR.into(),
            },
        );
        let (_, second_anchor) = write_generation(
            &store,
            GenerationSpec {
                generation: 2,
                bundle: 1,
                delegation: 1,
                time_seq: 1,
                trusted_time: "2026-07-21T12:00:01Z",
                legacy: Some(1),
                previous_manifest: Some(first_manifest),
                previous_anchor: first_anchor,
            },
        );
        write_file(
            &store.root.join("current"),
            b"generation-0000000000000002\n",
        );
        let nv = TestAnchor {
            anchor: decode_hash(&second_anchor).unwrap(),
            initialized: true,
            readable: true,
            legacy_floor: Some(1),
            safe_clock: true,
        };
        assert!(store.read_current(&nv).is_err());
        std::fs::remove_dir_all(root).unwrap();

        let (store, root) = test_store();
        let (_, anchor) = write_generation(
            &store,
            GenerationSpec {
                generation: 1,
                bundle: 1,
                delegation: 1,
                time_seq: 1,
                trusted_time: "2026-07-21T12:00:00Z",
                legacy: Some(1),
                previous_manifest: None,
                previous_anchor: ZERO_ANCHOR.into(),
            },
        );
        write_file(
            &store.root.join("current"),
            b"generation-0000000000000001\n",
        );
        std::fs::write(
            store
                .root
                .join("generations/generation-0000000000000001/applied.json"),
            b"{}\n",
        )
        .unwrap();
        assert!(store
            .read_current(&TestAnchor {
                anchor: decode_hash(&anchor).unwrap(),
                initialized: true,
                readable: true,
                legacy_floor: Some(1),
                safe_clock: true,
            })
            .is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn canonical_hashes_are_bound_to_the_recovered_artifact_bytes() {
        for artifacts in [
            GenerationArtifacts {
                bind_snapshot: false,
                ..GenerationArtifacts::default()
            },
            GenerationArtifacts {
                bind_assertion: false,
                ..GenerationArtifacts::default()
            },
        ] {
            let (store, root) = test_store();
            let (_, anchor) = write_generation_with_artifacts(
                &store,
                GenerationSpec {
                    generation: 1,
                    bundle: 1,
                    delegation: 1,
                    time_seq: 1,
                    trusted_time: "2026-07-21T12:00:00Z",
                    legacy: Some(1),
                    previous_manifest: None,
                    previous_anchor: ZERO_ANCHOR.into(),
                },
                artifacts,
            );
            assert!(store
                .read_current(&TestAnchor {
                    anchor: decode_hash(&anchor).unwrap(),
                    initialized: true,
                    readable: true,
                    legacy_floor: Some(1),
                    safe_clock: true,
                })
                .is_err());
            std::fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn release_authorization_must_be_canonical_json_before_recovery() {
        for release_json in [1, 2] {
            let (store, root) = test_store();
            let (_, anchor) = write_generation_with_artifacts(
                &store,
                GenerationSpec {
                    generation: 1,
                    bundle: 1,
                    delegation: 1,
                    time_seq: 1,
                    trusted_time: "2026-07-21T12:00:00Z",
                    legacy: Some(1),
                    previous_manifest: None,
                    previous_anchor: ZERO_ANCHOR.into(),
                },
                GenerationArtifacts {
                    release_json,
                    ..GenerationArtifacts::default()
                },
            );
            let error = store
                .read_current(&TestAnchor {
                    anchor: decode_hash(&anchor).unwrap(),
                    initialized: true,
                    readable: true,
                    legacy_floor: Some(1),
                    safe_clock: true,
                })
                .unwrap_err();
            assert!(error.0.contains("release authorization"));
            assert!(!store.root.join("current").exists());
            assert!(!store.root.join("enforce-ready.json").exists());
            std::fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn equal_sequences_require_every_scoped_artifact_to_be_byte_identical() {
        let (store, root) = test_store();
        let (first_manifest, first_anchor) = write_generation(
            &store,
            GenerationSpec {
                generation: 1,
                bundle: 1,
                delegation: 1,
                time_seq: 1,
                trusted_time: "2026-07-21T12:00:00Z",
                legacy: Some(1),
                previous_manifest: None,
                previous_anchor: ZERO_ANCHOR.into(),
            },
        );
        let (_, second_anchor) = write_generation_with_artifacts(
            &store,
            GenerationSpec {
                generation: 2,
                bundle: 1,
                delegation: 1,
                time_seq: 1,
                trusted_time: "2026-07-21T12:00:00Z",
                legacy: Some(1),
                previous_manifest: Some(first_manifest),
                previous_anchor: first_anchor,
            },
            GenerationArtifacts {
                variant: 1,
                ..GenerationArtifacts::default()
            },
        );
        assert!(store
            .read_current(&TestAnchor {
                anchor: decode_hash(&second_anchor).unwrap(),
                initialized: true,
                readable: true,
                legacy_floor: Some(1),
                safe_clock: true,
            })
            .is_err());
        std::fs::remove_dir_all(root).unwrap();

        let manifest = StateManifest {
            applied_sha256: "1".repeat(64),
            applied_bom_sha256: "2".repeat(64),
            authority_sha256: "3".repeat(64),
            bundle_seq_floor: 1,
            delegation_seq_floor: 1,
            delegation_snapshot_canonical_sha256: "4".repeat(64),
            delegation_snapshot_sha256: "5".repeat(64),
            delegation_snapshot_signature_sha256: "6".repeat(64),
            generation: 1,
            legacy_bundle_floor: Some(1),
            previous_manifest_sha256: None,
            previous_nv_anchor: ZERO_ANCHOR.into(),
            release_authorization_sha256: "7".repeat(64),
            release_authorization_signature_sha256: "8".repeat(64),
            schema: "neural-ice-ota-state-manifest-v1".into(),
            trusted_time_assertion_canonical_sha256: "9".repeat(64),
            trusted_time_assertion_sha256: "a".repeat(64),
            trusted_time_assertion_signature_sha256: "b".repeat(64),
            trusted_time_floor: "2026-07-21T12:00:00Z".into(),
            trusted_time_seq_floor: 1,
            trusted_time_sha256: "c".repeat(64),
        };
        for mutate in [
            |value: &mut StateManifest| {
                value.release_authorization_signature_sha256 = "d".repeat(64)
            },
            |value: &mut StateManifest| value.delegation_snapshot_signature_sha256 = "d".repeat(64),
            |value: &mut StateManifest| {
                value.trusted_time_assertion_signature_sha256 = "d".repeat(64)
            },
        ] {
            let mut split = manifest.clone();
            mutate(&mut split);
            assert!(verify_floor_continuity(&manifest, &split).is_err());
        }
    }

    #[test]
    fn enforce_ready_binds_the_exact_legacy_floor_without_mutating_it() {
        let (store, root) = test_store();
        let (manifest, anchor) = write_generation(
            &store,
            GenerationSpec {
                generation: 1,
                bundle: 7,
                delegation: 1,
                time_seq: 1,
                trusted_time: "2026-07-21T12:00:00Z",
                legacy: Some(7),
                previous_manifest: None,
                previous_anchor: ZERO_ANCHOR.into(),
            },
        );
        write_file(
            &store.root.join("current"),
            b"generation-0000000000000001\n",
        );
        write_file(
            &store.root.join("enforce-ready.json"),
            &canonical(&EnforceReady {
                manifest_sha256: "0".repeat(64),
                nv_anchor: "0".repeat(64),
                schema: "neural-ice-ota-enforce-ready-v1".into(),
            })
            .unwrap(),
        );
        let exact = TestAnchor {
            anchor: decode_hash(&anchor).unwrap(),
            initialized: true,
            readable: true,
            legacy_floor: Some(7),
            safe_clock: true,
        };
        assert!(store.verify_enforce_ready(&exact).is_ok());
        let marker: EnforceReady = parse_canonical(
            &std::fs::read(store.root.join("enforce-ready.json")).unwrap(),
            "test enforce-ready",
        )
        .unwrap();
        assert_eq!(marker.manifest_sha256, manifest);
        assert_eq!(marker.nv_anchor, anchor);
        assert!(store
            .verify_enforce_ready(&TestAnchor {
                legacy_floor: Some(6),
                ..exact
            })
            .is_err());
        assert!(store
            .verify_enforce_ready(&TestAnchor {
                legacy_floor: Some(8),
                ..exact
            })
            .is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn pointer_publication_skips_stale_temp_but_refuses_symlink_destination() {
        use std::os::unix::fs::symlink;

        let (store, root) = test_store();
        let stale = store
            .root
            .join(format!(".current.{}.0.tmp", std::process::id()));
        write_file(&stale, b"stale");
        store.publish_current(1).unwrap();
        assert_eq!(
            std::fs::read(store.root.join("current")).unwrap(),
            b"generation-0000000000000001\n"
        );
        std::fs::remove_file(store.root.join("current")).unwrap();
        symlink(&stale, store.root.join("current")).unwrap();
        assert!(store.publish_current(2).is_err());
        assert!(std::fs::symlink_metadata(store.root.join("current"))
            .unwrap()
            .file_type()
            .is_symlink());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn time_challenge_is_closed_and_nonce_is_exact() {
        let value = TimeChallenge {
            delegation_snapshot_sha256: "a".repeat(64),
            device_fingerprint: "b".repeat(64),
            hardware_target: "nvidia-gb10-arm64".into(),
            nonce: "c".repeat(64),
            release_authorization_sha256: "d".repeat(64),
            ring: "beta".into(),
            schema: "neural-ice-ota-time-challenge-v2".into(),
            state_nv_anchor: ZERO_ANCHOR.into(),
            tpm_clock: 42,
            tpm_reset_count: 3,
            tpm_restart_count: 4,
            tpm_safe: true,
        };
        assert!(validate_time_challenge(&value).is_ok());
        let mut unsafe_value = value.clone();
        unsafe_value.tpm_safe = false;
        assert!(validate_time_challenge(&unsafe_value).is_err());
        let mut noncanonical_nonce = value;
        noncanonical_nonce.nonce = "C".repeat(64);
        assert!(validate_time_challenge(&noncanonical_nonce).is_err());
        assert_eq!(nonce_from(Path::new("/dev/zero")).unwrap(), "0".repeat(64));
    }

    #[test]
    fn trusted_time_fingerprint_uses_the_dedicated_device_root() {
        // 0x81010004 is the appliance PKI root. A future handle regression
        // would silently couple OTA identity to that unrelated lifecycle.
        assert_eq!(DEVICE_ROOT_HANDLE, 0x8101_0005);
        assert_ne!(DEVICE_ROOT_HANDLE, 0x8101_0004);
    }

    #[test]
    fn device_root_receipt_is_closed_before_trusted_time_fingerprinting() {
        let public_area_sha256 = "a".repeat(64);
        let receipt = DeviceRootReceipt {
            attributes: DEVICE_ROOT_ATTRIBUTES.into(),
            curve: "nist-p256".into(),
            handle: "0x81010005".into(),
            hierarchy: "endorsement".into(),
            name: format!("000b{public_area_sha256}"),
            name_algorithm: "sha256".into(),
            public_area_sha256,
            qualified_name: format!("000b{}", "b".repeat(64)),
            schema: DEVICE_ROOT_SCHEMA.into(),
            scheme: "ecdsa-sha256".into(),
            spki_sha256: "c".repeat(64),
        };
        assert!(validate_device_root_receipt(&receipt).is_ok());

        let mut substituted = receipt;
        substituted.handle = "0x81010004".into();
        assert!(validate_device_root_receipt(&substituted).is_err());
    }

    #[test]
    fn challenge_continuity_ignores_lock_scratch_but_refuses_orphaned_anchor() {
        let (store, root) = test_store();
        write_file(
            &store
                .root
                .join(".transaction.json.time-v2-snapshot.1.1.tmp"),
            b"scratch",
        );
        let fresh = TestAnchor {
            anchor: [0; 32],
            initialized: false,
            readable: true,
            legacy_floor: Some(1),
            safe_clock: true,
        };
        assert!(store
            .validate_challenge_continuity(&fresh, ZERO_ANCHOR)
            .is_ok());

        for marker in ["current", "enforce-ready.json", "unexpected-state"] {
            write_file(&store.root.join(marker), b"retained");
            let error = store
                .validate_challenge_continuity(&fresh, ZERO_ANCHOR)
                .unwrap_err();
            assert!(error.0.contains("requires signed recovery"), "{marker}");
            std::fs::remove_file(store.root.join(marker)).unwrap();
        }
        write_file(
            &store.root.join("pending-time-challenge.json"),
            b"replaceable",
        );
        assert!(store
            .validate_challenge_continuity(&fresh, ZERO_ANCHOR)
            .is_ok());
        std::fs::remove_file(store.root.join("pending-time-challenge.json")).unwrap();

        let (_, anchored) = write_generation(
            &store,
            GenerationSpec {
                generation: 1,
                bundle: 1,
                delegation: 1,
                time_seq: 1,
                trusted_time: "2026-07-21T12:00:00Z",
                legacy: Some(1),
                previous_manifest: None,
                previous_anchor: ZERO_ANCHOR.into(),
            },
        );
        store.publish_current(1).unwrap();
        let mismatched_legacy = TestAnchor {
            anchor: decode_hash(&anchored).unwrap(),
            initialized: true,
            legacy_floor: Some(2),
            ..fresh
        };
        let error = store
            .validate_challenge_continuity(&mismatched_legacy, &anchored)
            .unwrap_err();
        assert!(error.0.contains("legacy floor differs"));
        std::fs::remove_dir_all(store.root.join("generations")).unwrap();
        ensure_secure_state_directory(&store.root.join("generations")).unwrap();
        std::fs::remove_file(store.root.join("current")).unwrap();

        let orphaned = TestAnchor {
            anchor: [7; 32],
            initialized: true,
            ..fresh
        };
        let error = store
            .validate_challenge_continuity(&orphaned, &hex(orphaned.anchor))
            .unwrap_err();
        assert!(error.0.contains("no complete state-v1 generation"));
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn complete_commit_is_anchored_consumes_nonce_and_retries_exactly() {
        let (store, root) = test_store();
        ensure_secure_state_directory(&store.root).unwrap();
        let candidate = candidate();
        atomic_replace(
            &store.root,
            "pending-time-challenge.json",
            &canonical(&candidate.challenge).unwrap(),
        )
        .unwrap();
        let nv = MemoryNv {
            anchor: Cell::new([0; 32]),
            clock: Cell::new(TpmClockState {
                clock: 1_000,
                reset_count: 1,
                restart_count: 1,
                safe: true,
            }),
            exists: Cell::new(false),
        };
        let first = store.commit(&candidate, &nv).unwrap().unwrap();
        assert_eq!(first.generation, 1);
        assert!(nv.exists.get());
        assert!(!store.root.join("pending-time-challenge.json").exists());
        nv.clock.set(TpmClockState {
            clock: 1_000 + TRUSTED_TIME_MAX_ELAPSED_MS + 1,
            reset_count: 2,
            restart_count: 1,
            safe: true,
        });
        assert_eq!(store.commit(&candidate, &nv).unwrap().unwrap(), first);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn exact_retry_recovers_a_generation_staged_before_the_first_extend() {
        let (store, root) = test_store();
        let candidate = candidate();
        atomic_replace(
            &store.root,
            "pending-time-challenge.json",
            &canonical(&candidate.challenge).unwrap(),
        )
        .unwrap();
        let nv = MemoryNv {
            anchor: Cell::new([0; 32]),
            clock: Cell::new(TpmClockState {
                clock: 1_000,
                reset_count: 1,
                restart_count: 1,
                safe: true,
            }),
            exists: Cell::new(true),
        };
        store
            .stage_generation(1, &candidate, None, ZERO_ANCHOR.into(), Some(1))
            .unwrap();
        let receipt = store.commit(&candidate, &nv).unwrap().unwrap();
        assert_eq!(receipt.generation, 1);
        assert!(!store.root.join("pending-time-challenge.json").exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn exact_retry_cleans_an_abandoned_first_generation_temp_directory() {
        let (store, root) = test_store();
        let candidate = candidate();
        atomic_replace(
            &store.root,
            "pending-time-challenge.json",
            &canonical(&candidate.challenge).unwrap(),
        )
        .unwrap();
        let abandoned = store
            .root
            .join("generations/.generation-0000000000000001.42.tmp");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&abandoned)
            .unwrap();
        let nv = MemoryNv {
            anchor: Cell::new([0; 32]),
            clock: Cell::new(TpmClockState {
                clock: 1_000,
                reset_count: 1,
                restart_count: 1,
                safe: true,
            }),
            exists: Cell::new(false),
        };
        assert_eq!(
            store.commit(&candidate, &nv).unwrap().unwrap().generation,
            1
        );
        assert!(!abandoned.exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn durable_markers_and_unknown_entries_block_zero_anchor_reseeding() {
        for name in ["current", "enforce-ready.json", "unexpected-state-v1-entry"] {
            let (store, root) = test_store();
            write_file(&store.root.join(name), b"durable");
            let candidate = candidate();
            let nv = MemoryNv {
                anchor: Cell::new([0; 32]),
                clock: Cell::new(TpmClockState {
                    clock: 1_000,
                    reset_count: 1,
                    restart_count: 1,
                    safe: true,
                }),
                exists: Cell::new(false),
            };
            let refusal = store.commit(&candidate, &nv).unwrap().unwrap_err();
            assert!(refusal.contains("durable state history"));
            assert!(!nv.exists.get());
            std::fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn candidate_challenge_binds_the_exact_release_and_snapshot_bytes() {
        let mut altered_release = candidate();
        altered_release.release = b"{ }\n";
        assert!(validate_candidate(&altered_release).is_err());

        let mut altered_snapshot = candidate();
        altered_snapshot.snapshot = b"{ }\n";
        assert!(validate_candidate(&altered_snapshot).is_err());

        let mut altered_snapshot_signature = candidate();
        altered_snapshot_signature
            .authority
            .snapshot_signature_sha256 = "f".repeat(64);
        assert!(validate_candidate(&altered_snapshot_signature).is_err());

        let mut altered_assertion = candidate();
        altered_assertion.trusted.assertion_sha256 = "f".repeat(64);
        assert!(validate_candidate(&altered_assertion).is_err());

        let mut altered_assertion_signature = candidate();
        altered_assertion_signature.trusted.signature_sha256 = "f".repeat(64);
        assert!(validate_candidate(&altered_assertion_signature).is_err());
    }

    #[test]
    fn preapply_and_commit_refuse_a_stale_live_tpm_challenge() {
        let (store, root) = test_store();
        let live_clock = TpmClockState {
            clock: TRUSTED_TIME_MAX_ELAPSED_MS + 1_000,
            reset_count: 1,
            restart_count: 1,
            safe: true,
        };
        let nv = MemoryNv {
            anchor: Cell::new([0; 32]),
            clock: Cell::new(live_clock),
            exists: Cell::new(false),
        };

        let mut commit_candidate = candidate();
        commit_candidate.challenge.tpm_clock = 999;
        commit_candidate.trusted.tpm_clock = 999;
        let assertion = test_signed_assertion(
            &commit_candidate.challenge,
            &commit_candidate.trusted,
            "2026-07-22T00:05:00Z",
        );
        commit_candidate.trusted.assertion_sha256 =
            state_canonical_hash(assertion, "test trusted-time assertion").unwrap();
        commit_candidate.trusted_assertion = assertion;
        let commit_refusal = store.commit(&commit_candidate, &nv).unwrap().unwrap_err();
        assert!(commit_refusal.contains("freshness window"));

        let snapshot_bytes =
            include_bytes!("../tests/fixtures/delegated-v1/delegation-snapshot.json");
        let snapshot: Snapshot = parse_canonical(snapshot_bytes, "test snapshot").unwrap();
        let mut challenge = candidate().challenge;
        challenge.delegation_snapshot_sha256 =
            state_canonical_hash(snapshot_bytes, "test snapshot").unwrap();
        challenge.tpm_clock = 999;
        let mut trusted = candidate().trusted;
        trusted.delegation_seq = snapshot.delegation_seq;
        trusted.tpm_clock = challenge.tpm_clock;
        let assertion = test_signed_assertion(&challenge, &trusted, "2026-07-22T00:05:00Z");
        trusted.assertion_sha256 =
            state_canonical_hash(assertion, "test trusted-time assertion").unwrap();
        atomic_replace(
            &store.root,
            "pending-time-challenge.json",
            &canonical(&challenge).unwrap(),
        )
        .unwrap();
        let preapply = PreapplyCandidate {
            bom_sha256: &candidate().applied.bom_sha256,
            bundle_seq: 1,
            challenge: &challenge,
            snapshot: &snapshot,
            snapshot_sha256: &challenge.delegation_snapshot_sha256,
            snapshot_signature: b"sig",
            trusted: &trusted,
            trusted_assertion: assertion,
        };
        let preapply_refusal = store.guard_preapply(&nv, &preapply).unwrap().unwrap_err();
        assert!(preapply_refusal.contains("freshness window"));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn commit_refuses_an_assertion_that_expires_before_the_freshness_cap() {
        let (store, root) = test_store();
        let value = candidate();
        let nv = MemoryNv {
            anchor: Cell::new([0; 32]),
            clock: Cell::new(TpmClockState {
                clock: value.challenge.tpm_clock + 300_000,
                reset_count: value.challenge.tpm_reset_count,
                restart_count: value.challenge.tpm_restart_count,
                safe: true,
            }),
            exists: Cell::new(false),
        };
        let refusal = store.commit(&value, &nv).unwrap().unwrap_err();
        assert!(refusal.contains("assertion expired"));
        assert!(!nv.exists.get());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn zero_anchor_preapply_requires_the_legacy_floor() {
        let (store, root) = test_store();
        let snapshot_bytes =
            include_bytes!("../tests/fixtures/delegated-v1/delegation-snapshot.json");
        let snapshot: Snapshot = parse_canonical(snapshot_bytes, "test snapshot").unwrap();
        let mut challenge = candidate().challenge;
        challenge.delegation_snapshot_sha256 =
            state_canonical_hash(snapshot_bytes, "test snapshot").unwrap();
        challenge.tpm_clock = 42;
        challenge.tpm_reset_count = 3;
        challenge.tpm_restart_count = 4;
        let mut trusted = candidate().trusted;
        trusted.delegation_seq = snapshot.delegation_seq;
        trusted.tpm_clock = challenge.tpm_clock;
        trusted.tpm_reset_count = challenge.tpm_reset_count;
        trusted.tpm_restart_count = challenge.tpm_restart_count;
        let assertion = test_signed_assertion(&challenge, &trusted, "2026-07-22T00:05:00Z");
        trusted.assertion_sha256 =
            state_canonical_hash(assertion, "test trusted-time assertion").unwrap();
        atomic_replace(
            &store.root,
            "pending-time-challenge.json",
            &canonical(&challenge).unwrap(),
        )
        .unwrap();
        let nv = TestAnchor {
            anchor: [0; 32],
            initialized: true,
            readable: true,
            legacy_floor: None,
            safe_clock: true,
        };
        let preapply = PreapplyCandidate {
            bom_sha256: &candidate().applied.bom_sha256,
            bundle_seq: 1,
            challenge: &challenge,
            snapshot: &snapshot,
            snapshot_sha256: &challenge.delegation_snapshot_sha256,
            snapshot_signature: b"sig",
            trusted: &trusted,
            trusted_assertion: assertion,
        };
        let refusal = store.guard_preapply(&nv, &preapply).unwrap().unwrap_err();
        assert!(refusal.contains("legacy TPM floor is absent"));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn zero_anchor_commit_requires_the_legacy_floor_before_staging() {
        let (store, root) = test_store();
        let nv = TestAnchor {
            anchor: [0; 32],
            initialized: true,
            readable: true,
            legacy_floor: None,
            safe_clock: true,
        };
        let refusal = store.commit(&candidate(), &nv).unwrap().unwrap_err();
        assert!(refusal.contains("legacy TPM floor is absent"));
        assert!(!store
            .root
            .join("generations")
            .join("generation-0000000000000001")
            .exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn preapply_equal_sequence_requires_the_accepted_snapshot_signature() {
        let canonical = "a".repeat(64);
        let signature = b"accepted-signature";
        assert!(same_preapply_snapshot(
            &canonical,
            signature,
            &canonical,
            &hash(signature).unwrap()
        )
        .unwrap());
        assert!(!same_preapply_snapshot(
            &canonical,
            b"re-signed",
            &canonical,
            &hash(signature).unwrap()
        )
        .unwrap());
    }

    #[test]
    fn preapply_refuses_a_missing_legacy_floor_before_payload_application() {
        let (store, root) = test_store();
        let (_, anchor) = write_generation(
            &store,
            GenerationSpec {
                generation: 1,
                bundle: 1,
                delegation: 1,
                time_seq: 1,
                trusted_time: "2026-07-22T00:00:01Z",
                legacy: Some(1),
                previous_manifest: None,
                previous_anchor: ZERO_ANCHOR.into(),
            },
        );
        let snapshot_bytes =
            include_bytes!("../tests/fixtures/delegated-v1/delegation-snapshot.json");
        let snapshot: Snapshot = parse_canonical(snapshot_bytes, "test snapshot").unwrap();
        let mut challenge = candidate().challenge;
        challenge.delegation_snapshot_sha256 =
            state_canonical_hash(snapshot_bytes, "test snapshot").unwrap();
        challenge.state_nv_anchor = anchor.clone();
        challenge.tpm_clock = 42;
        challenge.tpm_reset_count = 3;
        challenge.tpm_restart_count = 4;
        let mut trusted = candidate().trusted;
        trusted.delegation_seq = snapshot.delegation_seq;
        trusted.tpm_clock = challenge.tpm_clock;
        trusted.tpm_reset_count = challenge.tpm_reset_count;
        trusted.tpm_restart_count = challenge.tpm_restart_count;
        let assertion = test_signed_assertion(&challenge, &trusted, "2026-07-22T00:05:00Z");
        trusted.assertion_sha256 =
            state_canonical_hash(assertion, "test trusted-time assertion").unwrap();
        atomic_replace(
            &store.root,
            "pending-time-challenge.json",
            &canonical(&challenge).unwrap(),
        )
        .unwrap();
        let nv = TestAnchor {
            anchor: decode_hash(&anchor).unwrap(),
            initialized: true,
            readable: true,
            legacy_floor: None,
            safe_clock: true,
        };
        let preapply = PreapplyCandidate {
            bom_sha256: &candidate().applied.bom_sha256,
            bundle_seq: 1,
            challenge: &challenge,
            snapshot: &snapshot,
            snapshot_sha256: &challenge.delegation_snapshot_sha256,
            snapshot_signature: b"sig",
            trusted: &trusted,
            trusted_assertion: assertion,
        };
        let refusal = store.guard_preapply(&nv, &preapply).unwrap().unwrap_err();
        assert!(refusal.contains("legacy TPM floor disappeared"));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn split_views_and_unbounded_time_advance_refuse() {
        let baseline = candidate();
        let manifest = StateManifest {
            applied_sha256: "0".repeat(64),
            applied_bom_sha256: baseline.applied.bom_sha256.clone(),
            authority_sha256: "0".repeat(64),
            bundle_seq_floor: 1,
            delegation_seq_floor: 1,
            delegation_snapshot_canonical_sha256: baseline.authority.snapshot_sha256.clone(),
            delegation_snapshot_sha256: hash(baseline.snapshot).unwrap(),
            delegation_snapshot_signature_sha256: hash(baseline.snapshot_signature).unwrap(),
            generation: 1,
            legacy_bundle_floor: None,
            previous_manifest_sha256: None,
            previous_nv_anchor: ZERO_ANCHOR.into(),
            release_authorization_sha256: hash(baseline.release).unwrap(),
            release_authorization_signature_sha256: hash(baseline.release_signature).unwrap(),
            schema: "neural-ice-ota-state-manifest-v1".into(),
            trusted_time_assertion_canonical_sha256: baseline.trusted.assertion_sha256.clone(),
            trusted_time_assertion_sha256: hash(baseline.trusted_assertion).unwrap(),
            trusted_time_assertion_signature_sha256: hash(baseline.trusted_signature).unwrap(),
            trusted_time_floor: baseline.trusted.trusted_time.clone(),
            trusted_time_seq_floor: 1,
            trusted_time_sha256: "0".repeat(64),
        };
        let mut split = candidate();
        split.applied.bom_sha256 = "9".repeat(64);
        assert!(monotonic(&manifest, &baseline.trusted, &split).is_err());
        let mut re_signed_snapshot = candidate();
        re_signed_snapshot.snapshot_signature = b"different-signature";
        re_signed_snapshot.authority.snapshot_signature_sha256 =
            hash(re_signed_snapshot.snapshot_signature).unwrap();
        assert!(monotonic(&manifest, &baseline.trusted, &re_signed_snapshot).is_err());
        let mut re_signed_assertion = candidate();
        re_signed_assertion.trusted_signature = b"different-signature";
        re_signed_assertion.trusted.signature_sha256 =
            hash(re_signed_assertion.trusted_signature).unwrap();
        assert!(monotonic(&manifest, &baseline.trusted, &re_signed_assertion).is_err());
        let mut prior_time = baseline.trusted.clone();
        prior_time.tpm_reset_count = 2;
        prior_time.tpm_clock = 2_000;
        let reset_regressed = candidate();
        assert_eq!(
            monotonic_trusted(&manifest, &prior_time, &reset_regressed.trusted),
            Err("TPM reset count decreased".into())
        );
        let mut jump = candidate();
        jump.applied.bundle_seq = 2;
        jump.trusted.assertion_seq = 2;
        jump.trusted.tpm_clock = 2_000;
        jump.trusted.trusted_time = "2026-07-22T00:10:03Z".into();
        assert!(monotonic(&manifest, &baseline.trusted, &jump).is_err());
        jump.trusted.trusted_time = "2026-07-22T00:10:02Z".into();
        assert!(monotonic(&manifest, &baseline.trusted, &jump).is_ok());
    }
}
