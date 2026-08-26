//! Strict, local-only release-manifest parser and pure delta planner.
//!
//! Signature verification deliberately remains outside this module. The OTA
//! transaction hands this command two already verified canonical manifests;
//! this module decides which activation engine is allowed to run.

use std::{
    fs::OpenOptions,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

use serde::{Deserialize, Serialize};

use crate::{
    delegated::contract::{ident, parse_canonical, safe_uint, sha256, target},
    parse_flags, runner,
    state::O_NOFOLLOW,
    InternalError, EXIT_PASS, EXIT_REFUSE,
};

const SCHEMA: &str = "neural-ice-release-manifest-v1";
const PLAN_SCHEMA: &str = "neural-ice-release-plan-v1";
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_COMPONENTS: usize = 256;
const MAX_CONTENT: usize = 1024;
const MAX_RESTART_UNITS: usize = 32;
#[cfg(target_os = "linux")]
const O_NONBLOCK: i32 = 0x800;
#[cfg(target_os = "macos")]
const O_NONBLOCK: i32 = 0x4;

#[derive(Debug)]
enum PlanError {
    Refusal(String),
    Internal(InternalError),
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ReleaseManifest {
    schema: String,
    release_id: String,
    release_seq: u64,
    hardware_target: String,
    host: HostArtifact,
    components: Vec<ComponentArtifact>,
    content: Vec<ContentArtifact>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct HostArtifact {
    repository: String,
    digest: String,
    compatibility_contract: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ComponentArtifact {
    id: String,
    repository: String,
    digest: String,
    configuration_contract: String,
    restart_units: Vec<String>,
    reboot_required: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ContentArtifact {
    id: String,
    media_type: String,
    digest: String,
    activation_contract: String,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum Transaction {
    Noop,
    Content,
    Component,
    Host,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct ReleasePlan {
    schema: &'static str,
    current_manifest_sha256: String,
    candidate_manifest_sha256: String,
    release_id: String,
    release_seq: u64,
    hardware_target: String,
    transaction: Transaction,
    changed_components: Vec<String>,
    changed_content: Vec<String>,
    reboot_required: bool,
}

pub(crate) fn run(args: &[String]) -> Result<u8, InternalError> {
    match plan_files(args) {
        Ok(plan) => {
            let value = serde_json::to_value(plan)
                .map_err(|error| InternalError(format!("cannot encode release plan: {error}")))?;
            println!(
                "{}",
                serde_json::to_string(&value).map_err(|error| InternalError(format!(
                    "cannot encode release plan: {error}"
                )))?
            );
            Ok(EXIT_PASS)
        }
        Err(PlanError::Refusal(reason)) => {
            let refusal = serde_json::json!({
                "schema": "neural-ice-release-plan-refusal-v1",
                "verdict": "refuse",
                "reason": reason,
            });
            println!("{refusal}");
            Ok(EXIT_REFUSE)
        }
        Err(PlanError::Internal(error)) => Err(error),
    }
}

fn plan_files(args: &[String]) -> Result<ReleasePlan, PlanError> {
    let flags = parse_flags(args, &["current", "candidate"]).map_err(PlanError::Internal)?;
    let current_path = required(&flags, "current")?;
    let candidate_path = required(&flags, "candidate")?;
    let current = read_bounded(Path::new(current_path))?;
    let candidate = read_bounded(Path::new(candidate_path))?;
    plan_bytes(&current, &candidate)
}

fn required<'a>(
    flags: &'a std::collections::HashMap<String, String>,
    name: &str,
) -> Result<&'a str, PlanError> {
    flags
        .get(name)
        .map(String::as_str)
        .ok_or_else(|| PlanError::Internal(InternalError(format!("missing --{name}"))))
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, PlanError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW | O_NONBLOCK)
        .open(path)
        .map_err(|error| {
            PlanError::Internal(InternalError(format!(
                "cannot open {}: {error}",
                path.display()
            )))
        })?;
    let metadata = file.metadata().map_err(|error| {
        PlanError::Internal(InternalError(format!(
            "cannot inspect {}: {error}",
            path.display()
        )))
    })?;
    let named = std::fs::symlink_metadata(path).map_err(|error| {
        PlanError::Internal(InternalError(format!(
            "cannot re-inspect {}: {error}",
            path.display()
        )))
    })?;
    if !metadata.is_file()
        || !named.file_type().is_file()
        || metadata.dev() != named.dev()
        || metadata.ino() != named.ino()
    {
        return Err(PlanError::Internal(InternalError(format!(
            "{} is not a stable regular non-symlink file",
            path.display()
        ))));
    }
    if metadata.len() > MAX_MANIFEST_BYTES {
        return Err(PlanError::Refusal(format!(
            "{} exceeds the release-manifest size limit",
            path.display()
        )));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_MANIFEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            PlanError::Internal(InternalError(format!(
                "cannot read {}: {error}",
                path.display()
            )))
        })?;
    if bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(PlanError::Refusal(format!(
            "{} grew beyond the release-manifest size limit",
            path.display()
        )));
    }
    Ok(bytes)
}

fn plan_bytes(current_bytes: &[u8], candidate_bytes: &[u8]) -> Result<ReleasePlan, PlanError> {
    let current = parse(current_bytes, "current release manifest")?;
    let candidate = parse(candidate_bytes, "candidate release manifest")?;

    if current.hardware_target != candidate.hardware_target {
        return refuse("candidate hardware target differs from current authority");
    }
    if candidate.release_seq < current.release_seq {
        return refuse("candidate release sequence is a rollback");
    }
    if candidate.release_seq == current.release_seq && candidate != current {
        return refuse("same release sequence identifies different manifests");
    }

    let changed_components = changed_component_ids(&current, &candidate);
    let changed_content = changed_content_ids(&current, &candidate);
    let host_changed = current.host != candidate.host;

    if !host_changed {
        validate_component_only_delta(&current.components, &candidate.components)?;
        validate_content_only_delta(&current.content, &candidate.content)?;
    }

    let transaction = if host_changed {
        Transaction::Host
    } else if !changed_components.is_empty() {
        Transaction::Component
    } else if !changed_content.is_empty() {
        Transaction::Content
    } else {
        Transaction::Noop
    };
    let reboot_required = host_changed
        || changed_components.iter().any(|id| {
            candidate
                .components
                .iter()
                .any(|component| component.id == *id && component.reboot_required)
        });

    Ok(ReleasePlan {
        schema: PLAN_SCHEMA,
        current_manifest_sha256: hash(current_bytes)?,
        candidate_manifest_sha256: hash(candidate_bytes)?,
        release_id: candidate.release_id,
        release_seq: candidate.release_seq,
        hardware_target: candidate.hardware_target,
        transaction,
        changed_components,
        changed_content,
        reboot_required,
    })
}

fn parse(bytes: &[u8], what: &str) -> Result<ReleaseManifest, PlanError> {
    if bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return refuse("release manifest exceeds the size limit");
    }
    let manifest: ReleaseManifest = parse_canonical(bytes, what).map_err(PlanError::Refusal)?;
    validate(&manifest)?;
    Ok(manifest)
}

fn validate(manifest: &ReleaseManifest) -> Result<(), PlanError> {
    if manifest.schema != SCHEMA
        || !ident(&manifest.release_id)
        || !safe_uint(manifest.release_seq)
        || !target(&manifest.hardware_target)
        || !repository(&manifest.host.repository)
        || !digest(&manifest.host.digest)
        || !ident(&manifest.host.compatibility_contract)
    {
        return refuse("release manifest identity or host contract is invalid");
    }
    if manifest.components.len() > MAX_COMPONENTS || manifest.content.len() > MAX_CONTENT {
        return refuse("release manifest inventory exceeds its cardinality limit");
    }
    let mut prior = "";
    for component in &manifest.components {
        if component.id.as_str() <= prior
            || !ident(&component.id)
            || !repository(&component.repository)
            || !digest(&component.digest)
            || !ident(&component.configuration_contract)
            || component.restart_units.len() > MAX_RESTART_UNITS
            || !sorted_unique(&component.restart_units)
            || !component
                .restart_units
                .iter()
                .all(|unit| systemd_unit(unit))
        {
            return refuse("component inventory or contract is invalid or unsorted");
        }
        prior = &component.id;
    }
    prior = "";
    for content in &manifest.content {
        if content.id.as_str() <= prior
            || !ident(&content.id)
            || !media_type(&content.media_type)
            || !digest(&content.digest)
            || !ident(&content.activation_contract)
        {
            return refuse("content inventory or contract is invalid or unsorted");
        }
        prior = &content.id;
    }
    Ok(())
}

fn validate_component_only_delta(
    current: &[ComponentArtifact],
    candidate: &[ComponentArtifact],
) -> Result<(), PlanError> {
    if current.len() != candidate.len() {
        return refuse("component add/remove requires a host transaction");
    }
    for (old, new) in current.iter().zip(candidate) {
        if old.id != new.id
            || old.repository != new.repository
            || old.configuration_contract != new.configuration_contract
            || old.restart_units != new.restart_units
            || old.reboot_required != new.reboot_required
        {
            return refuse("component contract change requires a host transaction");
        }
    }
    Ok(())
}

fn validate_content_only_delta(
    current: &[ContentArtifact],
    candidate: &[ContentArtifact],
) -> Result<(), PlanError> {
    if current.len() != candidate.len() {
        return refuse("content add/remove requires a host transaction");
    }
    for (old, new) in current.iter().zip(candidate) {
        if old.id != new.id
            || old.media_type != new.media_type
            || old.activation_contract != new.activation_contract
        {
            return refuse("content contract change requires a host transaction");
        }
    }
    Ok(())
}

fn changed_component_ids(current: &ReleaseManifest, candidate: &ReleaseManifest) -> Vec<String> {
    let mut ids: Vec<String> = candidate
        .components
        .iter()
        .filter(|new| current.components.iter().find(|old| old.id == new.id) != Some(*new))
        .map(|component| component.id.clone())
        .chain(
            current
                .components
                .iter()
                .filter(|old| !candidate.components.iter().any(|new| new.id == old.id))
                .map(|component| component.id.clone()),
        )
        .collect();
    ids.sort_unstable();
    ids.dedup();
    ids
}

fn changed_content_ids(current: &ReleaseManifest, candidate: &ReleaseManifest) -> Vec<String> {
    let mut ids: Vec<String> = candidate
        .content
        .iter()
        .filter(|new| current.content.iter().find(|old| old.id == new.id) != Some(*new))
        .map(|content| content.id.clone())
        .chain(
            current
                .content
                .iter()
                .filter(|old| !candidate.content.iter().any(|new| new.id == old.id))
                .map(|content| content.id.clone()),
        )
        .collect();
    ids.sort_unstable();
    ids.dedup();
    ids
}

fn hash(bytes: &[u8]) -> Result<String, PlanError> {
    runner::sha256_bytes(bytes).map_err(PlanError::Internal)
}

fn digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(sha256)
}

fn repository(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && !value.starts_with('/')
        && !value.ends_with('/')
        && !value.contains("//")
        && !value
            .split('/')
            .any(|segment| segment.is_empty() || segment == "..")
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-/".contains(&byte)
        })
}

fn systemd_unit(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 160
        && value.ends_with(".service")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"@_.-".contains(&byte))
}

fn media_type(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 127
        && value.contains('/')
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b".+-/".contains(&byte)
        })
}

fn sorted_unique(values: &[String]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn refuse<T>(reason: impl Into<String>) -> Result<T, PlanError> {
    Err(PlanError::Refusal(reason.into()))
}

#[cfg(test)]
#[path = "release_manifest_tests.rs"]
mod tests;
