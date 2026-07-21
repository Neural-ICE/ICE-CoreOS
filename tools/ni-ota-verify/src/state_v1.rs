//! TPM capability gate for the atomic OTA state chain.
//!
//! This non-mutating layer recovers only complete generations whose manifest
//! chain reproduces the observed TPM anchor. The public capability remains
//! gated until the complete guard/commit command set lands.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};

use crate::delegated::contract::{
    canonical_hash, parse_canonical, safe_uint, sha256, timestamp, ContractError,
};
use crate::runner;
use crate::state::{
    ensure_secure_state_directory, validate_secure_state_directory, FileStateStore, O_NOFOLLOW,
};
use crate::InternalError;

pub(crate) const STATE_NV_INDEX: u32 = 0x0150_0002;
pub(crate) const LEGACY_NV_INDEX: u32 = 0x0150_0001;
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
struct AuthorityState {
    delegation_seq: u64,
    schema: String,
    snapshot_sha256: String,
    snapshot_signature_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct AppliedStateV1 {
    bom_sha256: String,
    bundle_seq: u64,
    schema: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct TrustedTimeState {
    assertion_seq: u64,
    assertion_sha256: String,
    challenge_sha256: String,
    delegation_seq: u64,
    device_fingerprint: String,
    key_id: String,
    schema: String,
    signature_sha256: String,
    tpm_clock: u64,
    tpm_reset_count: u32,
    tpm_restart_count: u32,
    tpm_safe: bool,
    trusted_time: String,
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

#[derive(Default)]
struct GenerationScan {
    has_evidence: bool,
    numbers: Vec<u64>,
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

#[derive(Clone, Debug, Eq, PartialEq)]
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
}

impl Store {
    pub(crate) fn lock_store(&self) -> FileStateStore {
        FileStateStore {
            path: self.root.join("transaction.json"),
        }
    }

    #[cfg(test)]
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
            "release-authorization.json",
            &value.release_authorization_sha256,
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
        variant: u8,
    }

    impl Default for GenerationArtifacts {
        fn default() -> Self {
            Self {
                bind_assertion: true,
                bind_snapshot: true,
                variant: 0,
            }
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
        let release = artifact_variant(b"{}\n", artifacts.variant);
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
}
