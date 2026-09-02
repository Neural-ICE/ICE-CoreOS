//! Strict, local-only verifier for the Fabric release-pack carried by SEED v2.
//!
//! Authority is one closed chain: the immutable offline root signs the
//! delegation snapshot; the snapshot's release role signs an authorization;
//! that authorization hashes the canonical release manifest and the canonical,
//! recursively complete OCI closure.  READY is required only as a crash marker.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::delegated::contract::{
    canonical_hash, encode_base64, parse_canonical, public_key_pem, validate_snapshot,
    validate_snapshot_time, verify_root_binding, Snapshot,
};
use crate::delegated::{signing_bytes, RELEASE_AUTHORIZATION_V2_DOMAIN, SNAPSHOT_DOMAIN};
use crate::{runner, InternalError, EXIT_PASS, EXIT_REFUSE};

pub(crate) const READY_SCHEMA: &str = "neural-ice-seed-closure-ready-v1";
pub(crate) const AUTHORIZATION_SCHEMA: &str = "neural-ice-ota-release-authorization-v2";
pub(crate) const CLOSURE_SCHEMA: &str = "neural-ice-oci-release-closure-v1";

const MAX_DOCUMENT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_OCI_DOCUMENT_BYTES: u64 = 4 * 1024 * 1024;
const MAX_OBJECTS: usize = 100_000;
const MAX_DEPTH: u64 = 8;
const SAFE_INTEGER_MAX: u64 = 9_007_199_254_740_991;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Refusal(pub(crate) String);

fn refuse<T>(reason: impl Into<String>) -> Result<T, Refusal> {
    Err(Refusal(reason.into()))
}

fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>, Refusal> {
    let file = std::fs::File::open(path)
        .map_err(|e| Refusal(format!("cannot read {}: {e}", path.display())))?;
    let metadata = file
        .metadata()
        .map_err(|e| Refusal(format!("cannot stat {}: {e}", path.display())))?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.len() > limit {
        return refuse(format!(
            "{} must be one bounded regular, single-link file",
            path.display()
        ));
    }
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| Refusal(format!("cannot read {}: {e}", path.display())))?;
    if bytes.len() as u64 > limit {
        return refuse(format!("{} exceeds its byte limit", path.display()));
    }
    Ok(bytes)
}

fn hex_digest(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn hash_file(path: &Path) -> Result<(String, u64), Refusal> {
    let mut file = std::fs::File::open(path)
        .map_err(|e| Refusal(format!("cannot read {}: {e}", path.display())))?;
    let metadata = file
        .metadata()
        .map_err(|e| Refusal(format!("cannot stat {}: {e}", path.display())))?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return refuse(format!(
            "{} is not a single-link regular file",
            path.display()
        ));
    }
    let mut hasher = Sha256::new();
    let mut count = 0_u64;
    let mut block = [0_u8; 1024 * 1024];
    loop {
        let read = file
            .read(&mut block)
            .map_err(|e| Refusal(format!("cannot hash {}: {e}", path.display())))?;
        if read == 0 {
            break;
        }
        count = count
            .checked_add(read as u64)
            .ok_or_else(|| Refusal("object size overflow".into()))?;
        hasher.update(&block[..read]);
    }
    let mut digest = String::with_capacity(64);
    for byte in hasher.finalize() {
        let _ = write!(digest, "{byte:02x}");
    }
    Ok((digest, count))
}

fn is_hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn is_nonzero_hex64(value: &str) -> bool {
    is_hex64(value) && value.bytes().any(|byte| byte != b'0')
}

fn digest_hex(value: &str) -> Result<&str, Refusal> {
    value
        .strip_prefix("sha256:")
        .filter(|v| is_hex64(v))
        .ok_or_else(|| Refusal(format!("{value} is not sha256:<64 lowercase hex>")))
}

fn ascii_json(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Null | serde_json::Value::Bool(_) => true,
        serde_json::Value::Number(n) => n.as_u64().is_some_and(|v| v <= SAFE_INTEGER_MAX),
        serde_json::Value::String(s) => s.is_ascii(),
        serde_json::Value::Array(v) => v.iter().all(ascii_json),
        serde_json::Value::Object(v) => v
            .iter()
            .all(|(key, value)| key.is_ascii() && ascii_json(value)),
    }
}

/// Fabric canonical domain: strict UTF-8 ASCII JSON, no floats, integers in the
/// interoperable range, compact sorted encoding and exactly one terminal LF.
/// Re-encoding also makes duplicate members fail byte equality.
fn canonical_value(bytes: &[u8], label: &str) -> Result<serde_json::Value, Refusal> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| Refusal(format!("{label} is not JSON: {e}")))?;
    if !ascii_json(&value) {
        return refuse(format!("{label} leaves the ASCII/integer canonical domain"));
    }
    let mut encoded = serde_json::to_vec(&value)
        .map_err(|e| Refusal(format!("cannot canonicalise {label}: {e}")))?;
    encoded.push(b'\n');
    if encoded != bytes {
        return refuse(format!(
            "{label} is not canonical compact sorted JSON plus LF"
        ));
    }
    Ok(value)
}

fn canonical<T: serde::de::DeserializeOwned>(bytes: &[u8], label: &str) -> Result<T, Refusal> {
    canonical_value(bytes, label)?;
    serde_json::from_slice(bytes).map_err(|e| Refusal(format!("invalid {label}: {e}")))
}

fn exact_keys(
    object: &serde_json::Map<String, serde_json::Value>,
    required: &[&str],
    optional: &[&str],
    label: &str,
) -> Result<(), Refusal> {
    for key in required {
        if !object.contains_key(*key) {
            return refuse(format!("{label} lacks required field {key}"));
        }
    }
    for key in object.keys() {
        if !required.contains(&key.as_str()) && !optional.contains(&key.as_str()) {
            return refuse(format!("{label} carries unknown field {key}"));
        }
    }
    Ok(())
}

fn as_object<'a>(
    value: &'a serde_json::Value,
    label: &str,
) -> Result<&'a serde_json::Map<String, serde_json::Value>, Refusal> {
    value
        .as_object()
        .ok_or_else(|| Refusal(format!("{label} is not an object")))
}

fn string<'a>(
    object: &'a serde_json::Map<String, serde_json::Value>,
    key: &str,
    label: &str,
) -> Result<&'a str, Refusal> {
    object
        .get(key)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| Refusal(format!("{label}.{key} is not a string")))
}

fn uint(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
    label: &str,
) -> Result<u64, Refusal> {
    object
        .get(key)
        .and_then(serde_json::Value::as_u64)
        .filter(|v| *v <= SAFE_INTEGER_MAX)
        .ok_or_else(|| Refusal(format!("{label}.{key} is not a safe unsigned integer")))
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Closure {
    schema: String,
    closure_format_version: u64,
    release_id: String,
    bundle_seq: u64,
    hardware_target: String,
    security_posture: String,
    boot_trust_profile: String,
    access_policy_sha256: String,
    boot_trust_policy_sha256: String,
    delegation_seq: u64,
    delegation_snapshot_sha256: String,
    host_digest: String,
    release_manifest_sha256: String,
    train: String,
    traversal_bound: u64,
    artifacts: Vec<Artifact>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Artifact {
    artifact_key: String,
    artifact_class: String,
    repository: String,
    root: ArtifactRoot,
    nodes: Vec<Node>,
    edges: Vec<Edge>,
    attachments: Vec<Attachment>,
    vendor: Option<Vendor>,
    assembly: Option<Assembly>,
    candidate_repository: String,
    chunked: Option<serde_json::Value>,
    node_counts: NodeCounts,
    required_entitlement: String,
    target: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactRoot {
    digest: String,
    repository: String,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Assembly {
    builder_id: String,
    operation: String,
    provenance: String,
    rejected_children: Vec<RejectedChild>,
    selected_children: Vec<SelectedChild>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SelectedChild {
    digest: String,
    repository: String,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RejectedChild {
    digest: String,
    reason: String,
    repository: String,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NodeCounts {
    config: u64,
    index: u64,
    layer: u64,
    manifest: u64,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Node {
    repository: String,
    digest: String,
    media_type: String,
    size: u64,
    kind: String,
    signatures: Vec<NodeSignature>,
    artifact_type: Option<String>,
    provenance: Option<String>,
    sbom: Option<String>,
    subject: Option<ArtifactRoot>,
}

#[derive(Debug, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
struct Edge {
    parent_repository: String,
    parent_digest: String,
    edge_kind: String,
    position: u64,
    child_repository: String,
    child_digest: String,
    media_type: String,
    size: u64,
    annotations: BTreeMap<String, String>,
    artifact_type: Option<String>,
    data: Option<String>,
    platform: Option<Platform>,
    urls: Vec<String>,
}

#[derive(Debug, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
struct Platform {
    architecture: String,
    os: String,
    #[serde(default, rename = "os.version")]
    os_version: OptionalField<String>,
    #[serde(default, rename = "os.features")]
    os_features: OptionalField<Vec<String>>,
    #[serde(default)]
    variant: OptionalField<String>,
    #[serde(default)]
    features: OptionalField<Vec<String>>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
enum OptionalField<T> {
    #[default]
    Missing,
    Present(T),
}

impl<'de, T> Deserialize<'de> for OptionalField<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        T::deserialize(deserializer).map(Self::Present)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NodeSignature {
    scheme: String,
    attachment_tag: String,
    attachment_digest: String,
    layer_digests: Vec<String>,
    payload_sha256: String,
    identity: String,
    key_id: String,
    role: String,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Attachment {
    subject_repository: String,
    subject_digest: String,
    kind: String,
    manifest_digest: String,
    media_type: String,
    layer_digests: Vec<String>,
    artifact_type: String,
    discovery: Discovery,
    predicate_type: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Discovery {
    cosign_tag: String,
    fallback_tag: String,
    referrers_api: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Vendor {
    source_repository: String,
    source_digest: String,
    ingested_digest: String,
}

#[derive(Debug, Clone)]
pub(crate) struct SeedExpectation {
    pub(crate) registry_host: String,
    pub(crate) hardware_target: String,
    pub(crate) access_profile: String,
    pub(crate) device_channel: String,
    pub(crate) trust_policy_id: String,
    pub(crate) expect_closure: String,
    pub(crate) expect_manifest: String,
    pub(crate) trusted_now: String,
    pub(crate) pcr_policy_digest: String,
    pub(crate) pcr_policy_public_key_sha256: String,
    pub(crate) pcr_policy_signature_sha256: String,
    pub(crate) pcr_policy_seq: u64,
}

#[derive(Debug)]
pub(crate) struct SeedVerdict {
    pub(crate) closure: String,
    pub(crate) manifest: String,
    pub(crate) objects: usize,
    pub(crate) artifacts: usize,
}

pub(crate) type VerifyBlob<'a> =
    &'a mut dyn FnMut(&[u8], &[u8], &[u8]) -> Result<Result<(), String>, InternalError>;

fn decode_base64(value: &str) -> Result<Vec<u8>, Refusal> {
    // Reuse the audited codec/profile from the delegation verifier.
    crate::delegated::contract::decode_base64(value).map_err(Refusal)
}

fn signature_bytes(path: &Path) -> Result<Vec<u8>, Refusal> {
    let der = read_bounded(path, 4096)?;
    crate::delegated::contract::validate_der_signature(&der).map_err(Refusal)?;
    Ok(der)
}

fn verify_or_refuse(
    verify: VerifyBlob<'_>,
    key: &[u8],
    signature: &[u8],
    payload: &[u8],
    label: &str,
) -> Result<(), Refusal> {
    match verify(key, signature, payload) {
        Ok(Ok(())) => Ok(()),
        Ok(Err(reason)) => refuse(format!("{label} signature denied: {reason}")),
        Err(InternalError(reason)) => refuse(format!("cannot verify {label}: {reason}")),
    }
}

fn validate_timestamp(value: &str, label: &str) -> Result<(), Refusal> {
    let bytes = value.as_bytes();
    if bytes.len() != 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'Z'
        || bytes
            .iter()
            .enumerate()
            .any(|(i, b)| !matches!(i, 4 | 7 | 10 | 13 | 16 | 19) && !b.is_ascii_digit())
    {
        return refuse(format!("{label} is not UTC RFC3339 second precision"));
    }
    let number = |start: usize, end: usize| -> u32 { value[start..end].parse().unwrap_or(0) };
    let year = number(0, 4);
    let month = number(5, 7);
    let day = number(8, 10);
    let hour = number(11, 13);
    let minute = number(14, 16);
    let second = number(17, 19);
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let month_days = [
        0,
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if year == 0
        || !(1..=12).contains(&month)
        || day == 0
        || day > month_days[month as usize]
        || hour > 23
        || minute > 59
        || second > 59
    {
        return refuse(format!("{label} is not a real UTC calendar timestamp"));
    }
    Ok(())
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
}

fn normalize_platform(mut platform: Platform) -> Result<Platform, Refusal> {
    if !valid_identifier(&platform.architecture)
        || !valid_identifier(&platform.os)
        || platform.architecture == "unknown"
        || platform.os == "unknown"
        || matches!(&platform.os_version, OptionalField::Present(value) if !valid_identifier(value))
        || matches!(&platform.variant, OptionalField::Present(value) if !valid_identifier(value))
    {
        return refuse("OCI platform identity is invalid or ambiguous");
    }
    for features in [&mut platform.os_features, &mut platform.features] {
        if let OptionalField::Present(features) = features {
            if features.len() > 16 || features.iter().any(|value| !valid_identifier(value)) {
                return refuse("OCI platform feature set is invalid");
            }
            features.sort();
            if features.windows(2).any(|pair| pair[0] == pair[1]) {
                return refuse("OCI platform feature set contains duplicates");
            }
        }
    }
    Ok(platform)
}

fn validate_declared_platform(platform: &Platform) -> Result<(), Refusal> {
    if &normalize_platform(platform.clone())? != platform {
        return refuse("OCI platform feature set is not canonical");
    }
    Ok(())
}

fn valid_repository(value: &str, registry: &str) -> bool {
    if !crate::release_manifest::is_registry_authority(registry) {
        return false;
    }
    let Some(path) = value
        .strip_prefix(registry)
        .and_then(|value| value.strip_prefix('/'))
    else {
        return false;
    };
    let mut segments = path.split('/');
    if !matches!(segments.next(), Some("neural-ice" | "vendor")) {
        return false;
    }
    let remainder: Vec<&str> = segments.collect();
    !remainder.is_empty()
        && remainder.iter().all(|segment| {
            !segment.is_empty()
                && segment.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'.' | b'_' | b'-')
                })
                && segment
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && segment
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        })
}

fn valid_candidate_repository(value: &str) -> bool {
    let Some(path) = value.strip_prefix("ghcr.io/") else {
        return false;
    };
    let segments: Vec<&str> = path.split('/').collect();
    segments.len() >= 2
        && segments.iter().all(|segment| {
            !segment.is_empty()
                && segment.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'.' | b'_' | b'-')
                })
                && segment
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && segment
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        })
}

fn valid_entitlement(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.as_bytes()[0].is_ascii_uppercase()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-')
}

fn device_channel_allowed(access_profile: &str, channel: &str) -> bool {
    match access_profile {
        "lab-managed" => matches!(channel, "lab" | "beta" | "stable"),
        "customer-locked" => matches!(channel, "beta" | "stable"),
        _ => false,
    }
}

#[derive(Debug)]
struct ManifestRoot {
    artifact_key: String,
    repository: String,
    digest: String,
    allowed_classes: &'static [&'static str],
}

#[derive(Debug)]
struct ParsedManifest {
    release_id: String,
    bundle_seq: u64,
    hardware_target: String,
    roots: Vec<ManifestRoot>,
}

const MANIFEST_READER_VERSION: u64 = 1;
const SUPPORTED_PAYLOAD_CONTRACTS: &[&str] =
    &["content-model-v1", "host-bootc-v1", "oci-component-v1"];

fn parse_manifest_roots(
    value: &serde_json::Value,
    registry: &str,
) -> Result<ParsedManifest, Refusal> {
    let root = as_object(value, "release manifest")?;
    exact_keys(
        root,
        &[
            "schema",
            "release_id",
            "bundle_seq",
            "hardware_target",
            "compatibility",
            "host",
            "components",
            "content",
            "evidence",
        ],
        &[],
        "release manifest",
    )?;
    if string(root, "schema", "release manifest")? != "neural-ice-release-manifest-v1" {
        return refuse("release manifest schema is invalid");
    }
    let release_id = string(root, "release_id", "release manifest")?;
    let hardware_target = string(root, "hardware_target", "release manifest")?;
    let bundle_seq = uint(root, "bundle_seq", "release manifest")?;
    if !valid_identifier(release_id) || !valid_identifier(hardware_target) || bundle_seq == 0 {
        return refuse("release manifest identity is invalid");
    }
    let compatibility = as_object(&root["compatibility"], "release manifest.compatibility")?;
    exact_keys(
        compatibility,
        &["minimum_reader", "required_contracts"],
        &[],
        "release manifest.compatibility",
    )?;
    if uint(
        compatibility,
        "minimum_reader",
        "release manifest.compatibility",
    )? > MANIFEST_READER_VERSION
    {
        return refuse("release manifest requires a newer reader");
    }
    let contracts = compatibility["required_contracts"]
        .as_array()
        .ok_or_else(|| Refusal("required_contracts is not an array".into()))?;
    if contracts.is_empty()
        || contracts.iter().any(|contract| {
            contract
                .as_str()
                .is_none_or(|value| !SUPPORTED_PAYLOAD_CONTRACTS.contains(&value))
        })
        || contracts
            .windows(2)
            .any(|pair| pair[0].as_str() >= pair[1].as_str())
    {
        return refuse("release manifest requires an unsupported or non-canonical contract set");
    }
    let declared_contracts: BTreeSet<&str> = contracts
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();
    let mut roots = Vec::new();
    let mut add = |entry: &serde_json::Value,
                   key: String,
                   allowed_classes: &'static [&'static str],
                   label: &str|
     -> Result<(), Refusal> {
        let entry = as_object(entry, label)?;
        let repository = string(entry, "repository", label)?;
        let digest = string(entry, "digest", label)?;
        let contract = string(entry, "contract", label)?;
        let restart_scope = entry["restart_scope"]
            .as_array()
            .ok_or_else(|| Refusal(format!("{label}.restart_scope is not an array")))?;
        if !valid_repository(repository, registry)
            || digest_hex(digest).is_err()
            || !declared_contracts.contains(contract)
            || !SUPPORTED_PAYLOAD_CONTRACTS.contains(&contract)
            || !entry["reboot_required"].is_boolean()
            || !valid_entitlement(string(entry, "required_entitlement", label)?)
            || restart_scope.len() > 32
            || restart_scope
                .iter()
                .any(|scope| scope.as_str().is_none_or(|scope| !valid_identifier(scope)))
            || restart_scope
                .windows(2)
                .any(|pair| pair[0].as_str() >= pair[1].as_str())
        {
            return refuse(format!("{label} has a non-canonical repository or digest"));
        }
        roots.push(ManifestRoot {
            artifact_key: key,
            repository: repository.to_owned(),
            digest: digest.to_owned(),
            allowed_classes,
        });
        Ok(())
    };
    let host = root
        .get("host")
        .ok_or_else(|| Refusal("release manifest lacks host".into()))?;
    let host_object = as_object(host, "release manifest.host")?;
    exact_keys(
        host_object,
        &[
            "repository",
            "digest",
            "contract",
            "restart_scope",
            "reboot_required",
            "required_entitlement",
        ],
        &[],
        "release manifest.host",
    )?;
    let host_repository = string(host_object, "repository", "release manifest.host")?;
    if string(host_object, "contract", "release manifest.host")? != "host-bootc-v1" {
        return refuse("release manifest host contract is unsupported");
    }
    let host_name = host_repository
        .rsplit('/')
        .next()
        .filter(|value| valid_identifier(value))
        .ok_or_else(|| Refusal("release manifest host repository has no canonical name".into()))?;
    add(
        host,
        format!("os:{host_name}"),
        &["portable-multiarch-image", "hardware-targeted-manifest"],
        "release manifest.host",
    )?;
    for (field, id_field, prefix, classes) in [
        (
            "components",
            "component_id",
            "image:",
            &["portable-multiarch-image", "hardware-targeted-manifest"][..].as_ref(),
        ),
        (
            "content",
            "content_id",
            "content:",
            &["oci-artifact", "chunked-content-artifact"][..].as_ref(),
        ),
    ] {
        let Some(entries_value) = root.get(field) else {
            continue;
        };
        let entries = entries_value
            .as_array()
            .ok_or_else(|| Refusal(format!("release manifest.{field} is not an array")))?;
        for (index, entry) in entries.iter().enumerate() {
            let label = format!("release manifest.{field}[{index}]");
            let object = as_object(entry, &label)?;
            let mut keys = vec![
                "repository",
                "digest",
                "contract",
                "restart_scope",
                "reboot_required",
                "required_entitlement",
                id_field,
            ];
            if field == "content" {
                keys.push("media_type");
            }
            exact_keys(object, &keys, &[], &label)?;
            let identifier = string(object, id_field, &label)?;
            let expected_contract = if field == "components" {
                "oci-component-v1"
            } else {
                "content-model-v1"
            };
            if string(object, "contract", &label)? != expected_contract {
                return refuse(format!("{label} carries an unsupported payload contract"));
            }
            if !valid_identifier(identifier) {
                return refuse(format!("{label}.{id_field} is invalid"));
            }
            add(entry, format!("{prefix}{identifier}"), classes, &label)?;
        }
    }
    let evidence = root["evidence"]
        .as_array()
        .ok_or_else(|| Refusal("release manifest.evidence is not an array".into()))?;
    let mut prior_evidence: Option<(String, String)> = None;
    for (index, item) in evidence.iter().enumerate() {
        let label = format!("release manifest.evidence[{index}]");
        let item = as_object(item, &label)?;
        exact_keys(item, &["kind", "digest"], &[], &label)?;
        let kind = string(item, "kind", &label)?;
        let digest = string(item, "digest", &label)?;
        if !matches!(
            kind,
            "attestation" | "bom" | "channel-snapshot" | "lockfile" | "receipt"
        ) || digest_hex(digest).is_err()
        {
            return refuse(format!("{label} is invalid"));
        }
        let current = (kind.to_owned(), digest.to_owned());
        if prior_evidence
            .as_ref()
            .is_some_and(|prior| prior >= &current)
        {
            return refuse("release manifest evidence is not a sorted set");
        }
        prior_evidence = Some(current);
    }
    roots.sort_by(|a, b| (&a.repository, &a.digest).cmp(&(&b.repository, &b.digest)));
    if roots
        .windows(2)
        .any(|pair| pair[0].repository == pair[1].repository && pair[0].digest == pair[1].digest)
    {
        return refuse("release manifest repeats an artifact root");
    }
    Ok(ParsedManifest {
        release_id: release_id.to_owned(),
        bundle_seq,
        hardware_target: hardware_target.to_owned(),
        roots,
    })
}

fn reconcile_manifest_closure(manifest: &[ManifestRoot], closure: &Closure) -> Result<(), Refusal> {
    if manifest.len() != closure.artifacts.len() || manifest.is_empty() {
        return refuse("release manifest and closure do not carry the same number of roots");
    }
    for reference in manifest {
        let artifact = closure
            .artifacts
            .iter()
            .find(|artifact| {
                artifact.root.repository == reference.repository
                    && artifact.root.digest == reference.digest
            })
            .ok_or_else(|| {
                Refusal(format!(
                    "manifest root {}@{} is absent from closure",
                    reference.repository, reference.digest
                ))
            })?;
        if artifact.artifact_key != reference.artifact_key
            || !reference
                .allowed_classes
                .contains(&artifact.artifact_class.as_str())
        {
            return refuse(format!(
                "manifest root {} is reclassified by closure",
                reference.artifact_key
            ));
        }
    }
    Ok(())
}

fn object_path(root: &Path, digest: &str) -> Result<PathBuf, Refusal> {
    Ok(root.join("objects/sha256").join(digest_hex(digest)?))
}

fn descriptor_edges(
    repository: &str,
    parent: &str,
    bytes: &[u8],
    kind: &str,
) -> Result<Vec<Edge>, Refusal> {
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|e| Refusal(format!("structural OCI object {parent} is not JSON: {e}")))?;
    let object = as_object(&value, "OCI structural object")?;
    if uint(object, "schemaVersion", "OCI structural object")? != 2 {
        return refuse("OCI structural object schemaVersion is not 2");
    }
    let mut edges = Vec::new();
    let mut push =
        |edge_kind: &str, position: u64, descriptor: &serde_json::Value| -> Result<(), Refusal> {
            let descriptor = as_object(descriptor, "OCI descriptor")?;
            edges.push(Edge {
                parent_repository: repository.to_owned(),
                parent_digest: parent.to_owned(),
                edge_kind: edge_kind.to_owned(),
                position,
                child_repository: repository.to_owned(),
                child_digest: string(descriptor, "digest", "OCI descriptor")?.to_owned(),
                media_type: string(descriptor, "mediaType", "OCI descriptor")?.to_owned(),
                size: uint(descriptor, "size", "OCI descriptor")?,
                annotations: descriptor
                    .get("annotations")
                    .map(|value| {
                        as_object(value, "OCI descriptor annotations")?
                            .iter()
                            .map(|(key, value)| {
                                value
                                    .as_str()
                                    .map(|value| (key.clone(), value.to_owned()))
                                    .ok_or_else(|| {
                                        Refusal("OCI descriptor annotation is not a string".into())
                                    })
                            })
                            .collect()
                    })
                    .transpose()?
                    .unwrap_or_default(),
                artifact_type: descriptor
                    .get("artifactType")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned),
                data: descriptor
                    .get("data")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned),
                platform: descriptor
                    .get("platform")
                    .map(|value| {
                        serde_json::from_value::<Platform>(value.clone())
                            .map_err(|error| Refusal(format!("OCI platform is invalid: {error}")))
                            .and_then(normalize_platform)
                    })
                    .transpose()?,
                urls: descriptor
                    .get("urls")
                    .map(|value| {
                        value
                            .as_array()
                            .ok_or_else(|| Refusal("OCI descriptor urls is not an array".into()))?
                            .iter()
                            .map(|url| {
                                url.as_str().map(str::to_owned).ok_or_else(|| {
                                    Refusal("OCI descriptor URL is not a string".into())
                                })
                            })
                            .collect()
                    })
                    .transpose()?
                    .unwrap_or_default(),
            });
            Ok(())
        };
    match kind {
        "index" => {
            let manifests = object
                .get("manifests")
                .and_then(serde_json::Value::as_array)
                .ok_or_else(|| Refusal("OCI index has no manifests array".into()))?;
            for (position, item) in manifests.iter().enumerate() {
                push("manifests", position as u64, item)?;
            }
        }
        "manifest" => {
            push(
                "config",
                0,
                object
                    .get("config")
                    .ok_or_else(|| Refusal("OCI manifest has no config".into()))?,
            )?;
            let layers = object
                .get("layers")
                .and_then(serde_json::Value::as_array)
                .ok_or_else(|| Refusal("OCI manifest has no layers array".into()))?;
            if layers.is_empty() {
                return refuse("OCI manifest has no layer");
            }
            for (position, item) in layers.iter().enumerate() {
                push("layers", position as u64, item)?;
            }
        }
        _ => return refuse(format!("{kind} is not a structural OCI node kind")),
    }
    edges.sort();
    Ok(edges)
}

fn validate_simple_signing_payload(
    bytes: &[u8],
    payload_type: &str,
    identity: &str,
    subject: &str,
    optional: Option<&BTreeMap<&str, &str>>,
) -> Result<(), Refusal> {
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|e| Refusal(format!("attestation payload is not JSON: {e}")))?;
    let root = as_object(&value, "attestation payload")?;
    exact_keys(root, &["critical", "optional"], &[], "attestation payload")?;
    let critical = as_object(&root["critical"], "attestation critical")?;
    exact_keys(
        critical,
        &["identity", "image", "type"],
        &[],
        "attestation critical",
    )?;
    let signed_identity = as_object(&critical["identity"], "attestation identity")?;
    exact_keys(
        signed_identity,
        &["docker-reference"],
        &[],
        "attestation identity",
    )?;
    let image = as_object(&critical["image"], "attestation image")?;
    exact_keys(image, &["docker-manifest-digest"], &[], "attestation image")?;
    if string(critical, "type", "attestation critical")? != payload_type
        || string(signed_identity, "docker-reference", "attestation identity")? != identity
        || string(image, "docker-manifest-digest", "attestation image")? != subject
    {
        return refuse("attestation payload type/identity/subject is not its closure claim");
    }
    let facts = as_object(&root["optional"], "attestation optional")?;
    if let Some(expected) = optional {
        if facts.len() != expected.len()
            || expected.iter().any(|(key, value)| {
                facts.get(*key).and_then(serde_json::Value::as_str) != Some(*value)
            })
        {
            return refuse("attestation optional facts are not the exact vendor ingest facts");
        }
    }
    Ok(())
}

fn attachment_payload(
    root: &Path,
    attachment: &Attachment,
) -> Result<(PathBuf, Vec<u8>, Vec<u8>), Refusal> {
    if attachment.layer_digests.len() != 1 {
        return refuse("signed attestation attachment must carry exactly one layer");
    }
    let payload = object_path(root, &attachment.layer_digests[0])?;
    let bytes = read_bounded(&payload, 64 * 1024)?;
    let manifest_bytes = read_bounded(
        &object_path(root, &attachment.manifest_digest)?,
        MAX_OCI_DOCUMENT_BYTES,
    )?;
    let manifest: serde_json::Value =
        serde_json::from_slice(&manifest_bytes).map_err(|e| Refusal(e.to_string()))?;
    let annotation = manifest
        .pointer("/layers/0/annotations/dev.cosignproject.cosign~1signature")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| Refusal("attestation lacks cosign signature annotation".into()))?;
    let der = decode_base64(annotation)?;
    crate::delegated::contract::validate_der_signature(&der).map_err(Refusal)?;
    Ok((payload, bytes, der))
}

fn list_object_store(root: &Path) -> Result<BTreeSet<String>, Refusal> {
    let store = root.join("objects/sha256");
    let mut found = BTreeSet::new();
    for entry in std::fs::read_dir(&store)
        .map_err(|e| Refusal(format!("cannot list {}: {e}", store.display())))?
    {
        let entry = entry.map_err(|e| Refusal(format!("cannot list object store: {e}")))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let metadata = entry
            .path()
            .symlink_metadata()
            .map_err(|e| Refusal(format!("cannot stat object {name}: {e}")))?;
        if !is_hex64(&name) || !metadata.is_file() || metadata.nlink() != 1 {
            return refuse(format!(
                "objects/sha256/{name} is not a canonical single-link object"
            ));
        }
        if found.len() >= MAX_OBJECTS {
            return refuse("seed object count exceeds its bound");
        }
        found.insert(name);
    }
    Ok(found)
}

fn validate_closure(
    root: &Path,
    closure: &Closure,
    registry: &str,
) -> Result<BTreeSet<String>, Refusal> {
    if closure.schema != CLOSURE_SCHEMA
        || closure.closure_format_version != 1
        || closure.bundle_seq == 0
        || closure.bundle_seq > SAFE_INTEGER_MAX
        || closure.traversal_bound == 0
        || closure.traversal_bound > MAX_DEPTH
        || closure.hardware_target.is_empty()
        || !matches!(closure.security_posture.as_str(), "debug" | "sealed")
        || !matches!(
            closure.boot_trust_profile.as_str(),
            "neural-ice-secureboot-lab-v1" | "neural-ice-secureboot-prod-v1"
        )
    {
        return refuse("closure header/schema/profile is invalid");
    }
    if closure.artifacts.is_empty() {
        return refuse("closure has no artifacts");
    }
    let mut expected = BTreeSet::new();
    let mut prior_key: Option<&str> = None;
    for artifact in &closure.artifacts {
        if prior_key.is_some_and(|p| p >= artifact.artifact_key.as_str()) {
            return refuse("closure artifacts are not a sorted set");
        }
        prior_key = Some(&artifact.artifact_key);
        if !valid_repository(&artifact.repository, registry)
            || !valid_candidate_repository(&artifact.candidate_repository)
            || !valid_entitlement(&artifact.required_entitlement)
            || artifact
                .artifact_key
                .split_once(':')
                .is_none_or(|(prefix, name)| {
                    !matches!(prefix, "image" | "os" | "artifact" | "content")
                        || !valid_identifier(name)
                })
            || !matches!(
                artifact.artifact_class.as_str(),
                "portable-multiarch-image"
                    | "hardware-targeted-manifest"
                    | "oci-artifact"
                    | "chunked-content-artifact"
            )
            || artifact.artifact_class == "chunked-content-artifact"
            || artifact.root.repository != artifact.repository
            || if artifact.artifact_class == "hardware-targeted-manifest" {
                artifact.target.as_deref() != Some(closure.hardware_target.as_str())
            } else {
                artifact.target.is_some()
            }
            || artifact.chunked.is_some()
        {
            return refuse(format!(
                "artifact {} has unsupported class/origin",
                artifact.artifact_key
            ));
        }
        let mut nodes = BTreeMap::new();
        let mut prior_digest: Option<&str> = None;
        for node in &artifact.nodes {
            let hex = digest_hex(&node.digest)?;
            if node.repository != artifact.repository
                || node.size == 0
                || node.size > SAFE_INTEGER_MAX
                || !matches!(
                    node.kind.as_str(),
                    "index" | "manifest" | "config" | "layer"
                )
                || prior_digest.is_some_and(|p| p >= node.digest.as_str())
            {
                return refuse(format!(
                    "artifact {} carries an invalid/unsorted node",
                    artifact.artifact_key
                ));
            }
            prior_digest = Some(&node.digest);
            if matches!(node.kind.as_str(), "index" | "manifest") && node.signatures.is_empty() {
                return refuse(format!(
                    "{} has an unsigned structural node",
                    artifact.artifact_key
                ));
            }
            if matches!(node.kind.as_str(), "config" | "layer")
                && (!node.signatures.is_empty()
                    || node.artifact_type.is_some()
                    || node.subject.is_some()
                    || node.sbom.is_some()
                    || node.provenance.is_some())
            {
                return refuse("blob nodes must be evidence-free leaves");
            }
            expected.insert(hex.to_owned());
            if nodes.insert(node.digest.clone(), node).is_some() {
                return refuse("closure has a duplicate node");
            }
        }
        if !nodes.contains_key(&artifact.root.digest) {
            return refuse(format!("artifact {} root is absent", artifact.artifact_key));
        }
        let mut declared = artifact.edges.clone();
        declared.sort();
        if declared != artifact.edges {
            return refuse(format!(
                "artifact {} edges are not sorted",
                artifact.artifact_key
            ));
        }
        let mut adjacency: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut edge_slots = BTreeSet::new();
        for edge in &artifact.edges {
            if let Some(platform) = &edge.platform {
                validate_declared_platform(platform)?;
            }
            if matches!(edge.edge_kind.as_str(), "config" | "layers") && edge.platform.is_some() {
                return refuse("OCI config/layer descriptors must not carry a platform");
            }
            let parent_kind = nodes
                .get(&edge.parent_digest)
                .map(|node| node.kind.as_str())
                .unwrap_or("");
            let child_kind = nodes
                .get(&edge.child_digest)
                .map(|node| node.kind.as_str())
                .unwrap_or("");
            if edge.parent_repository != artifact.repository
                || edge.child_repository != artifact.repository
                || !nodes.contains_key(&edge.parent_digest)
                || !nodes.contains_key(&edge.child_digest)
                || nodes[&edge.child_digest].media_type != edge.media_type
                || nodes[&edge.child_digest].size != edge.size
                || !matches!(edge.edge_kind.as_str(), "manifests" | "config" | "layers")
                || !matches!(
                    (parent_kind, edge.edge_kind.as_str(), child_kind),
                    ("index", "manifests", "manifest")
                        | ("manifest", "config", "config")
                        | ("manifest", "layers", "layer")
                )
                || !edge_slots.insert((
                    edge.parent_digest.as_str(),
                    edge.edge_kind.as_str(),
                    edge.position,
                ))
            {
                return refuse(format!(
                    "artifact {} carries an invalid edge",
                    artifact.artifact_key
                ));
            }
            adjacency
                .entry(edge.parent_digest.clone())
                .or_default()
                .push(edge.child_digest.clone());
        }
        for node in &artifact.nodes {
            let edges = artifact
                .edges
                .iter()
                .filter(|edge| edge.parent_digest == node.digest)
                .collect::<Vec<_>>();
            match node.kind.as_str() {
                "index" => {
                    if edges.is_empty()
                        || edges.iter().any(|edge| edge.edge_kind != "manifests")
                        || {
                            let positions: Vec<u64> =
                                edges.iter().map(|edge| edge.position).collect();
                            positions != (0..positions.len() as u64).collect::<Vec<_>>()
                        }
                    {
                        return refuse("OCI index child slots are incomplete or non-contiguous");
                    }
                    if matches!(
                        artifact.artifact_class.as_str(),
                        "portable-multiarch-image" | "hardware-targeted-manifest"
                    ) {
                        let platforms = edges
                            .iter()
                            .filter_map(|edge| edge.platform.as_ref())
                            .collect::<BTreeSet<_>>();
                        if platforms.len() != edges.len() {
                            return refuse(
                                "bootable OCI index children require unique concrete platforms",
                            );
                        }
                    }
                }
                "manifest" => {
                    let configs = edges
                        .iter()
                        .filter(|edge| edge.edge_kind == "config")
                        .count();
                    let positions: Vec<u64> = edges
                        .iter()
                        .filter(|edge| edge.edge_kind == "layers")
                        .map(|edge| edge.position)
                        .collect();
                    if configs != 1
                        || positions.is_empty()
                        || positions != (0..positions.len() as u64).collect::<Vec<_>>()
                    {
                        return refuse("OCI manifest config/layer slots are incomplete");
                    }
                }
                "config" | "layer" if !edges.is_empty() => {
                    return refuse("OCI blob node has outgoing edges");
                }
                _ => {}
            }
        }
        // Kahn's algorithm proves the graph is acyclic independently of reachability.
        let mut indegree: BTreeMap<String, usize> =
            nodes.keys().map(|digest| (digest.clone(), 0)).collect();
        for children in adjacency.values() {
            for child in children {
                *indegree.get_mut(child).expect("validated child") += 1;
            }
        }
        let mut zero: Vec<String> = indegree
            .iter()
            .filter(|(_, count)| **count == 0)
            .map(|(digest, _)| digest.clone())
            .collect();
        let mut processed = 0_usize;
        while let Some(parent) = zero.pop() {
            processed += 1;
            for child in adjacency.get(&parent).into_iter().flatten() {
                let count = indegree.get_mut(child).expect("validated child");
                *count -= 1;
                if *count == 0 {
                    zero.push(child.clone());
                }
            }
        }
        if processed != nodes.len() {
            return refuse("closure graph contains a cycle");
        }
        let mut reachable = BTreeSet::new();
        let mut frontier = vec![(artifact.root.digest.clone(), 1_u64)];
        while let Some((digest, depth)) = frontier.pop() {
            if depth > closure.traversal_bound {
                return refuse("closure graph exceeds traversal_bound");
            }
            if reachable.insert(digest.clone()) {
                frontier.extend(adjacency.get(&digest).into_iter().flatten().map(|child| {
                    let child_depth = if matches!(nodes[child].kind.as_str(), "config" | "layer") {
                        depth
                    } else {
                        depth + 1
                    };
                    (child.clone(), child_depth)
                }));
            }
        }
        if reachable.len() != nodes.len() {
            return refuse(format!(
                "artifact {} has unreachable nodes",
                artifact.artifact_key
            ));
        }
        let observed_counts = NodeCounts {
            config: artifact
                .nodes
                .iter()
                .filter(|node| node.kind == "config")
                .count() as u64,
            index: artifact
                .nodes
                .iter()
                .filter(|node| node.kind == "index")
                .count() as u64,
            layer: artifact
                .nodes
                .iter()
                .filter(|node| node.kind == "layer")
                .count() as u64,
            manifest: artifact
                .nodes
                .iter()
                .filter(|node| node.kind == "manifest")
                .count() as u64,
        };
        if observed_counts.config != artifact.node_counts.config
            || observed_counts.index != artifact.node_counts.index
            || observed_counts.layer != artifact.node_counts.layer
            || observed_counts.manifest != artifact.node_counts.manifest
        {
            return refuse("closure node_counts do not match the graph");
        }
        if matches!(
            artifact.artifact_class.as_str(),
            "portable-multiarch-image" | "hardware-targeted-manifest"
        ) && artifact.nodes.iter().any(|node| {
            node.kind == "manifest" && (node.sbom.is_none() || node.provenance.is_none())
        }) {
            return refuse("image manifest lacks mandatory SBOM/provenance evidence");
        }
        let root_node = nodes[&artifact.root.digest];
        if root_node.kind == "index" && artifact.assembly.is_none() {
            return refuse("locally produced index lacks assembly provenance");
        }
        if let Some(assembly) = &artifact.assembly {
            let selected: BTreeSet<(&str, &str)> = assembly
                .selected_children
                .iter()
                .map(|child| (child.repository.as_str(), child.digest.as_str()))
                .collect();
            let enumerated: BTreeSet<(&str, &str)> = artifact
                .edges
                .iter()
                .filter(|edge| {
                    edge.parent_digest == artifact.root.digest && edge.edge_kind == "manifests"
                })
                .map(|edge| (edge.child_repository.as_str(), edge.child_digest.as_str()))
                .collect();
            let rejected: BTreeSet<(&str, &str)> = assembly
                .rejected_children
                .iter()
                .map(|child| (child.repository.as_str(), child.digest.as_str()))
                .collect();
            if selected != enumerated
                || !rejected.is_disjoint(&enumerated)
                || !matches!(
                    assembly.operation.as_str(),
                    "first-party-index-assembly" | "vendor-index-normalization"
                )
                || digest_hex(&assembly.provenance).is_err()
                || !assembly.builder_id.starts_with("https://")
            {
                return refuse("closure assembly evidence disagrees with the root index");
            }
        }
        for node in artifact
            .nodes
            .iter()
            .filter(|n| matches!(n.kind.as_str(), "index" | "manifest"))
        {
            let bytes = read_bounded(&object_path(root, &node.digest)?, MAX_OCI_DOCUMENT_BYTES)?;
            let observed =
                descriptor_edges(&artifact.repository, &node.digest, &bytes, &node.kind)?;
            let declared: Vec<Edge> = artifact
                .edges
                .iter()
                .filter(|e| e.parent_digest == node.digest)
                .cloned()
                .collect();
            if observed != declared {
                return refuse(format!(
                    "closure edges do not equal descriptors in {}",
                    node.digest
                ));
            }
        }
        let mut prior_attachment: Option<(&str, &str, &str, &str)> = None;
        for attachment in &artifact.attachments {
            let current = (
                attachment.subject_repository.as_str(),
                attachment.subject_digest.as_str(),
                attachment.kind.as_str(),
                attachment.manifest_digest.as_str(),
            );
            if attachment.subject_repository != artifact.repository
                || !nodes.contains_key(&attachment.subject_digest)
                || !matches!(
                    nodes[&attachment.subject_digest].kind.as_str(),
                    "index" | "manifest"
                )
                || attachment.media_type != "application/vnd.oci.image.manifest.v1+json"
                || !matches!(
                    attachment.kind.as_str(),
                    "signature" | "sbom" | "provenance"
                )
                || prior_attachment.is_some_and(|previous| previous >= current)
            {
                return refuse(format!(
                    "artifact {} carries an invalid attachment",
                    artifact.artifact_key
                ));
            }
            prior_attachment = Some(current);
            let expected_tag = format!(
                "sha256-{}.{}",
                digest_hex(&attachment.subject_digest)?,
                match attachment.kind.as_str() {
                    "signature" => "sig",
                    "sbom" => "sbom",
                    "provenance" => "att",
                    _ => "att",
                }
            );
            if attachment.discovery.cosign_tag != expected_tag
                || attachment.discovery.fallback_tag
                    != format!("sha256-{}", digest_hex(&attachment.subject_digest)?)
                || !attachment.discovery.referrers_api
            {
                return refuse("attachment tag is not derived from its subject");
            }
            expected.insert(digest_hex(&attachment.manifest_digest)?.to_owned());
            for digest in &attachment.layer_digests {
                expected.insert(digest_hex(digest)?.to_owned());
            }
            let bytes = read_bounded(
                &object_path(root, &attachment.manifest_digest)?,
                MAX_OCI_DOCUMENT_BYTES,
            )?;
            let value: serde_json::Value = serde_json::from_slice(&bytes)
                .map_err(|e| Refusal(format!("attachment manifest is not JSON: {e}")))?;
            let document = as_object(&value, "attachment manifest")?;
            let config = as_object(
                document
                    .get("config")
                    .ok_or_else(|| Refusal("attachment lacks config".into()))?,
                "attachment config",
            )?;
            let config_digest = string(config, "digest", "attachment config")?;
            expected.insert(digest_hex(config_digest)?.to_owned());
            let mut total = uint(config, "size", "attachment config")?;
            let layers = document
                .get("layers")
                .and_then(serde_json::Value::as_array)
                .ok_or_else(|| Refusal("attachment lacks layers".into()))?;
            let actual: Vec<String> = layers
                .iter()
                .map(|layer| {
                    let layer = as_object(layer, "attachment layer")?;
                    total = total
                        .checked_add(uint(layer, "size", "attachment layer")?)
                        .ok_or_else(|| Refusal("attachment size overflow".into()))?;
                    Ok(string(layer, "digest", "attachment layer")?.to_owned())
                })
                .collect::<Result<_, Refusal>>()?;
            if actual != attachment.layer_digests || total == 0 {
                return refuse("attachment descriptors do not equal its closure declaration");
            }
        }
        match &artifact.vendor {
            None => {}
            Some(vendor) => {
                if vendor.ingested_digest != artifact.root.digest
                    || digest_hex(&vendor.source_digest).is_err()
                    || vendor.source_repository.is_empty()
                    || artifact
                        .assembly
                        .as_ref()
                        .is_none_or(|assembly| assembly.operation != "vendor-index-normalization")
                {
                    return refuse("vendor ingestion/assembly evidence is incomplete");
                }
            }
        }
        if artifact.vendor.is_none()
            && artifact
                .assembly
                .as_ref()
                .is_some_and(|assembly| assembly.operation == "vendor-index-normalization")
        {
            return refuse("vendor normalization assembly lacks vendor ingestion identity");
        }
    }
    Ok(expected)
}

fn closure_coverage_matches(value: &serde_json::Value, closure: &Closure) -> Result<bool, Refusal> {
    let coverage = as_object(value, "release authorization.closure_coverage")?;
    exact_keys(
        coverage,
        &[
            "artifacts",
            "config_nodes",
            "edges",
            "layer_nodes",
            "signed_structural_nodes",
            "structural_nodes",
            "traversal_bound",
        ],
        &[],
        "release authorization.closure_coverage",
    )?;
    let nodes = closure
        .artifacts
        .iter()
        .flat_map(|artifact| &artifact.nodes);
    let structural = nodes
        .clone()
        .filter(|node| matches!(node.kind.as_str(), "index" | "manifest"))
        .count() as u64;
    let signed = nodes
        .clone()
        .filter(|node| {
            matches!(node.kind.as_str(), "index" | "manifest") && !node.signatures.is_empty()
        })
        .count() as u64;
    let configs = nodes.clone().filter(|node| node.kind == "config").count() as u64;
    let layers = nodes.filter(|node| node.kind == "layer").count() as u64;
    Ok(
        uint(coverage, "artifacts", "closure coverage")? == closure.artifacts.len() as u64
            && uint(coverage, "config_nodes", "closure coverage")? == configs
            && uint(coverage, "edges", "closure coverage")?
                == closure
                    .artifacts
                    .iter()
                    .map(|artifact| artifact.edges.len() as u64)
                    .sum::<u64>()
            && uint(coverage, "layer_nodes", "closure coverage")? == layers
            && uint(coverage, "signed_structural_nodes", "closure coverage")? == signed
            && uint(coverage, "structural_nodes", "closure coverage")? == structural
            && uint(coverage, "traversal_bound", "closure coverage")? == closure.traversal_bound,
    )
}

fn validate_authorization_contract(
    auth: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), Refusal> {
    if uint(
        auth,
        "authorization_format_version",
        "release authorization",
    )? != 1
        || string(auth, "purpose", "release authorization")? != "install"
        || string(auth, "security_posture", "release authorization")? != "sealed"
    {
        return refuse("release authorization version/purpose/posture is not install-v1 sealed");
    }
    for field in [
        "access_policy_sha256",
        "boot_trust_policy_sha256",
        "delegation_snapshot_sha256",
        "release_closure_sha256",
        "release_manifest_sha256",
    ] {
        if !is_nonzero_hex64(string(auth, field, "release authorization")?) {
            return refuse(format!(
                "release authorization.{field} is not lowercase sha256"
            ));
        }
    }
    if digest_hex(string(auth, "host_digest", "release authorization")?).is_err()
        || !valid_identifier(string(auth, "release_id", "release authorization")?)
        || !valid_identifier(string(auth, "train", "release authorization")?)
        || !valid_identifier(string(auth, "hardware_target", "release authorization")?)
        || !valid_identifier(string(auth, "key_id", "release authorization")?)
    {
        return refuse("release authorization identity/digest fields are invalid");
    }
    let issuance = string(auth, "issuance_id", "release authorization")?;
    if issuance.len() < 2
        || issuance.len() > 64
        || !issuance
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        || !issuance
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        || !issuance
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
    {
        return refuse("release authorization issuance_id is invalid");
    }

    let medium = as_object(
        &auth["installer_medium"],
        "release authorization.installer_medium",
    )?;
    exact_keys(
        medium,
        &[
            "medium_raw_sha256",
            "relauth_key_sha256",
            "rootfs_verity_hash_algorithm",
            "rootfs_verity_root_hash",
            "uki_cmdline_sha256",
            "uki_pe_sha256",
        ],
        &[],
        "release authorization.installer_medium",
    )?;
    if string(
        medium,
        "rootfs_verity_hash_algorithm",
        "release authorization.installer_medium",
    )? != "sha256"
        || [
            "medium_raw_sha256",
            "relauth_key_sha256",
            "rootfs_verity_root_hash",
            "uki_cmdline_sha256",
            "uki_pe_sha256",
        ]
        .iter()
        .any(|field| {
            medium
                .get(*field)
                .and_then(serde_json::Value::as_str)
                .is_none_or(|value| !is_hex64(value) || value.bytes().all(|byte| byte == b'0'))
        })
    {
        return refuse("release authorization installer_medium is invalid");
    }

    let ring = string(auth, "ring", "release authorization")?;
    let receipts = auth["copy_completion_receipts"]
        .as_array()
        .ok_or_else(|| Refusal("copy_completion_receipts is not an array".into()))?;
    if receipts.is_empty() || receipts.len() > 3 {
        return refuse("copy_completion_receipts count is invalid");
    }
    let mut destinations = BTreeSet::new();
    let mut prior: Option<&str> = None;
    for (index, receipt) in receipts.iter().enumerate() {
        let label = format!("copy_completion_receipts[{index}]");
        let receipt = as_object(receipt, &label)?;
        exact_keys(receipt, &["destination", "sha256"], &[], &label)?;
        let destination = string(receipt, "destination", &label)?;
        if !matches!(destination, "lab-local" | "disaster-recovery" | "origin")
            || prior.is_some_and(|previous| previous >= destination)
            || !is_hex64(string(receipt, "sha256", &label)?)
            || string(receipt, "sha256", &label)?
                .bytes()
                .all(|byte| byte == b'0')
        {
            return refuse("copy completion receipts are invalid or unsorted");
        }
        prior = Some(destination);
        destinations.insert(destination);
    }
    let required: BTreeSet<&str> = match ring {
        "lab" => ["lab-local"].into_iter().collect(),
        "beta" | "stable" => ["lab-local", "disaster-recovery", "origin"]
            .into_iter()
            .collect(),
        _ => return refuse("release authorization ring is invalid"),
    };
    if !required.is_subset(&destinations) {
        return refuse("release authorization lacks a required copy completion receipt");
    }
    match (ring, &auth["qualification_receipt"]) {
        ("lab", serde_json::Value::Null) => {}
        ("beta" | "stable", value) => {
            let qualification = as_object(value, "qualification_receipt")?;
            exact_keys(
                qualification,
                &["schema", "sha256"],
                &[],
                "qualification_receipt",
            )?;
            let expected = if ring == "beta" {
                "neural-ice-ota-lab-qualification-receipt-v1"
            } else {
                "neural-ice-ota-beta-qualification-receipt-v1"
            };
            if string(qualification, "schema", "qualification_receipt")? != expected
                || !is_nonzero_hex64(string(qualification, "sha256", "qualification_receipt")?)
            {
                return refuse("release authorization qualification receipt is invalid");
            }
        }
        _ => return refuse("release authorization qualification receipt does not match its ring"),
    }
    Ok(())
}

pub(crate) fn verify_seed_with(
    seed_root: &Path,
    root_key: &[u8],
    expectation: &SeedExpectation,
    verify: VerifyBlob<'_>,
) -> Result<SeedVerdict, Refusal> {
    let expected_hex = expectation
        .expect_closure
        .strip_prefix("sha256:")
        .unwrap_or(&expectation.expect_closure);
    if !is_hex64(expected_hex)
        || seed_root.file_name().and_then(|v| v.to_str()) != Some(expected_hex)
        || !seed_root.is_dir()
    {
        return refuse("seed root is not a directory named by the expected closure hash");
    }
    let allowed_top: BTreeSet<&str> = [
        "release-manifest.json",
        "release-closure.json",
        "release-authorization.json",
        "release-authorization.json.sig",
        "delegation-snapshot.json",
        "delegation-snapshot.json.sig",
        "objects",
        "READY",
    ]
    .into_iter()
    .collect();
    for entry in
        std::fs::read_dir(seed_root).map_err(|e| Refusal(format!("cannot list seed root: {e}")))?
    {
        let name = entry
            .map_err(|e| Refusal(e.to_string()))?
            .file_name()
            .to_string_lossy()
            .into_owned();
        if !allowed_top.contains(name.as_str()) {
            return refuse(format!("seed root carries unknown entry {name}"));
        }
    }
    validate_timestamp(&expectation.trusted_now, "trusted_now")?;

    let delegation_bytes = read_bounded(
        &seed_root.join("delegation-snapshot.json"),
        MAX_DOCUMENT_BYTES,
    )?;
    let delegation_message = signing_bytes(SNAPSHOT_DOMAIN, &delegation_bytes).map_err(Refusal)?;
    let delegation_sig = signature_bytes(&seed_root.join("delegation-snapshot.json.sig"))?;
    verify_or_refuse(
        verify,
        root_key,
        &delegation_sig,
        &delegation_message,
        "root delegation",
    )?;
    let delegation: Snapshot =
        parse_canonical(&delegation_bytes, "delegation snapshot").map_err(Refusal)?;
    validate_snapshot(&delegation)
        .map_err(|_| Refusal("delegation snapshot violates the closed Fabric contract".into()))?;
    validate_snapshot_time(&delegation, &expectation.trusted_now).map_err(Refusal)?;
    verify_root_binding(&delegation, root_key).map_err(Refusal)?;

    // Never derive authority from names.  The root-signed snapshot supplies
    // the exact role, key id, ring, hardware and active-time scope.
    let mut delegated_keys: BTreeMap<(&str, &str), Vec<u8>> = BTreeMap::new();
    for key in &delegation.keys {
        if !key.authorizes_at(&expectation.trusted_now)
            || !key.hardware_targets.contains(&expectation.hardware_target)
        {
            continue;
        }
        delegated_keys.insert(
            (key.key_id.as_str(), key.role.as_str()),
            public_key_pem(&key.public_key).map_err(|_| {
                Refusal("delegated public key violates the Fabric key profile".into())
            })?,
        );
    }

    let auth_bytes = read_bounded(
        &seed_root.join("release-authorization.json"),
        MAX_DOCUMENT_BYTES,
    )?;
    let auth_value = canonical_value(&auth_bytes, "release authorization")?;
    let auth = as_object(&auth_value, "release authorization")?;
    exact_keys(
        auth,
        &[
            "schema",
            "authorization_format_version",
            "purpose",
            "subject",
            "train",
            "release_id",
            "bundle_seq",
            "ring",
            "signing_role",
            "key_id",
            "hardware_target",
            "security_posture",
            "boot_trust_profile",
            "boot_trust_policy_sha256",
            "access_profile",
            "access_policy_sha256",
            "host_digest",
            "delegation_seq",
            "delegation_snapshot_sha256",
            "release_closure_sha256",
            "release_manifest_sha256",
            "closure_coverage",
            "copy_completion_receipts",
            "qualification_receipt",
            "issuance_id",
            "issued_at",
            "valid_until",
            "installer_medium",
        ],
        &[],
        "release authorization",
    )?;
    if string(auth, "schema", "release authorization")? != AUTHORIZATION_SCHEMA {
        return refuse("release authorization schema is invalid");
    }
    validate_authorization_contract(auth)?;
    let signing_role = string(auth, "signing_role", "release authorization")?;
    let authorization_key_id = string(auth, "key_id", "release authorization")?;
    let release_key = delegated_keys
        .get(&(authorization_key_id, signing_role))
        .ok_or_else(|| Refusal("authorization signing role is not delegated".into()))?;
    let auth_sig = signature_bytes(&seed_root.join("release-authorization.json.sig"))?;
    let auth_message =
        signing_bytes(RELEASE_AUTHORIZATION_V2_DOMAIN, &auth_bytes).map_err(Refusal)?;
    verify_or_refuse(
        verify,
        release_key,
        &auth_sig,
        &auth_message,
        "delegated release authorization",
    )?;
    let ring = string(auth, "ring", "release authorization")?;
    let channel_allowed =
        device_channel_allowed(&expectation.access_profile, &expectation.device_channel);
    if signing_role != format!("release-{ring}")
        || ring != expectation.device_channel
        || !channel_allowed
        || !delegation.keys.iter().any(|key| {
            key.key_id == authorization_key_id
                && key.role == signing_role
                && key.rings == [ring]
                && key.authorizes_at(&expectation.trusted_now)
        })
        || uint(auth, "delegation_seq", "release authorization")? != delegation.delegation_seq
        || string(auth, "delegation_snapshot_sha256", "release authorization")?
            != canonical_hash(&delegation_bytes).map_err(|error| match error {
                crate::delegated::contract::ContractError::Refusal(reason) => Refusal(reason),
                crate::delegated::contract::ContractError::Internal(error) => Refusal(error.0),
            })?
        || string(auth, "hardware_target", "release authorization")? != expectation.hardware_target
        || auth
            .get("access_profile")
            .and_then(serde_json::Value::as_str)
            != Some(expectation.access_profile.as_str())
        || string(auth, "boot_trust_profile", "release authorization")?
            != expectation.trust_policy_id
    {
        return refuse("authorization delegation/scope/device binding is invalid");
    }
    // Fabric binds the immutable measured-boot baseline as the exact policy
    // hash. Key/signature/sequence remain sealed installer inputs and are
    // checked for strict shape here; they are not substituted for Fabric's
    // signed policy identity.
    if !is_hex64(&expectation.pcr_policy_digest)
        || !is_hex64(&expectation.pcr_policy_public_key_sha256)
        || !is_hex64(&expectation.pcr_policy_signature_sha256)
        || string(auth, "boot_trust_policy_sha256", "release authorization")?
            != expectation.pcr_policy_digest
        || expectation.pcr_policy_seq == 0
    {
        return refuse("release authorization does not bind the sealed PCR policy generation");
    }
    let issued_at = string(auth, "issued_at", "release authorization")?;
    let valid_until = string(auth, "valid_until", "release authorization")?;
    validate_timestamp(issued_at, "authorization.issued_at")?;
    validate_timestamp(valid_until, "authorization.valid_until")?;
    if issued_at >= valid_until
        || expectation.trusted_now.as_str() < issued_at
        || expectation.trusted_now.as_str() >= valid_until
    {
        return refuse("release authorization is outside its active validity window");
    }

    let closure_path = seed_root.join("release-closure.json");
    let closure_bytes = read_bounded(&closure_path, MAX_DOCUMENT_BYTES)?;
    let closure: Closure = canonical(&closure_bytes, "release closure")?;
    let observed_closure = hex_digest(&closure_bytes);
    if observed_closure != expected_hex
        || string(auth, "release_closure_sha256", "release authorization")? != observed_closure
    {
        return refuse("authorization, directory and canonical closure hashes disagree");
    }
    let subject = as_object(&auth["subject"], "release authorization.subject")?;
    exact_keys(
        subject,
        &["digest", "media_type", "repository"],
        &[],
        "release authorization.subject",
    )?;
    let subject_repository = string(subject, "repository", "release authorization.subject")?;
    let subject_digest = string(subject, "digest", "release authorization.subject")?;
    if !closure.artifacts.iter().any(|artifact| {
        artifact.root.repository == subject_repository
            && artifact.root.digest == subject_digest
            && artifact.nodes.iter().any(|node| {
                node.digest == subject_digest
                    && node.media_type
                        == string(subject, "media_type", "release authorization.subject")
                            .unwrap_or("")
            })
    }) {
        return refuse("authorization subject is not an enumerated closure root");
    }
    let manifest_path = seed_root.join("release-manifest.json");
    let manifest_bytes = read_bounded(&manifest_path, MAX_DOCUMENT_BYTES)?;
    let manifest_value = canonical_value(&manifest_bytes, "release manifest")?;
    let manifest_hash = hex_digest(&manifest_bytes);
    let expected_manifest = expectation
        .expect_manifest
        .strip_prefix("sha256:")
        .unwrap_or(&expectation.expect_manifest);
    if !is_hex64(expected_manifest)
        || manifest_hash != expected_manifest
        || string(auth, "release_manifest_sha256", "release authorization")? != manifest_hash
        || closure.release_id != string(auth, "release_id", "release authorization")?
        || closure.bundle_seq != uint(auth, "bundle_seq", "release authorization")?
        || closure.hardware_target != string(auth, "hardware_target", "release authorization")?
        || closure.security_posture != string(auth, "security_posture", "release authorization")?
        || closure.boot_trust_profile
            != string(auth, "boot_trust_profile", "release authorization")?
        || closure.train != string(auth, "train", "release authorization")?
        || closure.delegation_seq != uint(auth, "delegation_seq", "release authorization")?
        || closure.delegation_snapshot_sha256
            != string(auth, "delegation_snapshot_sha256", "release authorization")?
        || closure.release_manifest_sha256 != manifest_hash
        || closure.access_policy_sha256
            != string(auth, "access_policy_sha256", "release authorization")?
        || closure.boot_trust_policy_sha256
            != string(auth, "boot_trust_policy_sha256", "release authorization")?
        || closure.host_digest != string(auth, "host_digest", "release authorization")?
        || !closure_coverage_matches(&auth["closure_coverage"], &closure)?
    {
        return refuse("authorization does not bind the exact manifest/closure identity");
    }
    let manifest = parse_manifest_roots(&manifest_value, &expectation.registry_host)?;
    if manifest.release_id != closure.release_id
        || manifest.bundle_seq != closure.bundle_seq
        || manifest.hardware_target != closure.hardware_target
    {
        return refuse("release manifest identity disagrees with authorization/closure");
    }
    reconcile_manifest_closure(&manifest.roots, &closure)?;

    let expected_objects = validate_closure(seed_root, &closure, &expectation.registry_host)?;
    for hex in &expected_objects {
        let path = seed_root.join("objects/sha256").join(hex);
        let (observed, size) = hash_file(&path)?;
        if &observed != hex {
            return refuse(format!("object sha256:{hex} bytes do not match its name"));
        }
        for node in closure
            .artifacts
            .iter()
            .flat_map(|a| &a.nodes)
            .filter(|n| digest_hex(&n.digest).ok() == Some(hex))
        {
            if node.size != size {
                return refuse(format!("object {} size differs from closure", node.digest));
            }
        }
    }
    let present = list_object_store(seed_root)?;
    if present != expected_objects {
        return refuse("seed object store is not the exact closed object set");
    }

    // Every declared first-party signature resolves to an attachment and to a
    // root-delegated attestation key. Cryptographic payload verification is
    // performed over the attachment layer bytes, never over a tag.
    for artifact in &closure.artifacts {
        for node in &artifact.nodes {
            for signature in &node.signatures {
                if signature.scheme != "cosign-sigstore-v1"
                    || signature.identity != node.repository
                    || !matches!(signature.role.as_str(), "image-ci")
                    || !is_hex64(&signature.payload_sha256)
                    || !delegated_keys
                        .contains_key(&(signature.key_id.as_str(), signature.role.as_str()))
                {
                    return refuse("node signature profile/key/identity is invalid");
                }
                let attachment = artifact
                    .attachments
                    .iter()
                    .find(|a| {
                        a.kind == "signature"
                            && a.manifest_digest == signature.attachment_digest
                            && a.subject_digest == node.digest
                            && a.discovery.cosign_tag == signature.attachment_tag
                            && a.layer_digests == signature.layer_digests
                    })
                    .ok_or_else(|| {
                        Refusal("node signature has no exact carried attachment".into())
                    })?;
                let (_payload, payload_bytes, signature_bytes) =
                    attachment_payload(seed_root, attachment)?;
                if hex_digest(&payload_bytes) != signature.payload_sha256 {
                    return refuse("cosign payload hash does not match closure signature record");
                }
                validate_simple_signing_payload(
                    &payload_bytes,
                    "cosign container image signature",
                    &signature.identity,
                    &node.digest,
                    None,
                )?;
                let key = &delegated_keys[&(signature.key_id.as_str(), signature.role.as_str())];
                verify_or_refuse(
                    verify,
                    key,
                    &signature_bytes,
                    &payload_bytes,
                    "recursive OCI attestation",
                )?;
            }
        }
    }

    let ready_bytes = read_bounded(&seed_root.join("READY"), 4096)?;
    let ready = canonical_value(&ready_bytes, "seed READY")?;
    let ready = as_object(&ready, "seed READY")?;
    exact_keys(
        ready,
        &[
            "schema",
            "release_closure_sha256",
            "release_manifest_sha256",
            "object_count",
        ],
        &[],
        "seed READY",
    )?;
    if string(ready, "schema", "seed READY")? != READY_SCHEMA
        || string(ready, "release_closure_sha256", "seed READY")? != observed_closure
        || string(ready, "release_manifest_sha256", "seed READY")? != manifest_hash
        || uint(ready, "object_count", "seed READY")? as usize != expected_objects.len()
    {
        return refuse("READY does not describe the verified tree");
    }

    Ok(SeedVerdict {
        closure: observed_closure,
        manifest: manifest_hash,
        objects: expected_objects.len(),
        artifacts: closure.artifacts.len(),
    })
}

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

fn production_signature(
    key: &[u8],
    signature: &[u8],
    payload: &[u8],
) -> Result<Result<(), String>, InternalError> {
    let cosign = runner::cosign_path()?;
    production_signature_at(
        Path::new("/run/neural-ice/seed-verify"),
        &cosign,
        key,
        signature,
        payload,
    )
}

fn production_signature_at(
    directory: &Path,
    cosign: &Path,
    key: &[u8],
    signature: &[u8],
    payload: &[u8],
) -> Result<Result<(), String>, InternalError> {
    std::fs::create_dir_all(directory)
        .map_err(|e| InternalError(format!("cannot create {}: {e}", directory.display())))?;
    let suffix = format!(
        "{}-{}",
        std::process::id(),
        TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let key_path = directory.join(format!("key-{suffix}"));
    let sig_path = directory.join(format!("sig-{suffix}"));
    let payload_path = directory.join(format!("payload-{suffix}"));
    let write = |path: &Path, bytes: &[u8]| -> Result<(), InternalError> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| {
                InternalError(format!(
                    "cannot create verifier temporary {}: {e}",
                    path.display()
                ))
            })?;
        file.write_all(bytes)
            .and_then(|_| file.sync_all())
            .map_err(|e| {
                InternalError(format!(
                    "cannot write verifier temporary {}: {e}",
                    path.display()
                ))
            })
    };
    write(&key_path, key)?;
    let encoded_signature = encode_base64(signature);
    if let Err(error) = write(&sig_path, encoded_signature.as_bytes()) {
        let _ = std::fs::remove_file(&key_path);
        return Err(error);
    }
    if let Err(error) = write(&payload_path, payload) {
        let _ = std::fs::remove_file(&sig_path);
        let _ = std::fs::remove_file(&key_path);
        return Err(error);
    }
    let result = runner::verify_blob(cosign, &key_path, &sig_path, &payload_path);
    let _ = std::fs::remove_file(&sig_path);
    let _ = std::fs::remove_file(&key_path);
    let _ = std::fs::remove_file(&payload_path);
    result
}

pub(crate) fn verify_seed(
    seed_root: &Path,
    pubkey: &Path,
    expectation: &SeedExpectation,
) -> Result<Result<SeedVerdict, Refusal>, InternalError> {
    let key = std::fs::read(pubkey).map_err(|e| {
        InternalError(format!(
            "cannot read immutable root key {}: {e}",
            pubkey.display()
        ))
    })?;
    Ok(verify_seed_with(
        seed_root,
        &key,
        expectation,
        &mut production_signature,
    ))
}

pub(crate) fn run(args: &[String]) -> Result<u8, InternalError> {
    let flags = crate::parse_flags(
        args,
        &[
            "seed-root",
            "pubkey",
            "registry-host",
            "hardware-target",
            "access-profile",
            "device-channel",
            "trust-policy-id",
            "expect-closure",
            "expect-manifest",
            "trusted-now",
            "pcr-policy-digest",
            "pcr-policy-public-key-sha256",
            "pcr-policy-signature-sha256",
            "pcr-policy-seq",
        ],
    )?;
    let required = |name: &str| {
        flags
            .get(name)
            .cloned()
            .ok_or_else(|| InternalError(format!("verify-seed-closure needs --{name}")))
    };
    let expectation = SeedExpectation {
        registry_host: required("registry-host")?,
        hardware_target: required("hardware-target")?,
        access_profile: required("access-profile")?,
        device_channel: required("device-channel")?,
        trust_policy_id: required("trust-policy-id")?,
        expect_closure: required("expect-closure")?,
        expect_manifest: required("expect-manifest")?,
        trusted_now: required("trusted-now")?,
        pcr_policy_digest: required("pcr-policy-digest")?,
        pcr_policy_public_key_sha256: required("pcr-policy-public-key-sha256")?,
        pcr_policy_signature_sha256: required("pcr-policy-signature-sha256")?,
        pcr_policy_seq: required("pcr-policy-seq")?
            .parse()
            .map_err(|_| InternalError("--pcr-policy-seq must be a positive integer".into()))?,
    };
    match verify_seed(
        Path::new(&required("seed-root")?),
        Path::new(&required("pubkey")?),
        &expectation,
    )? {
        Ok(verdict) => {
            println!("{{\"schema\":\"neural-ice-seed-closure-verdict-v2\",\"verdict\":\"pass\",\"release_closure_sha256\":\"{}\",\"release_manifest_sha256\":\"{}\",\"objects\":{},\"artifacts\":{}}}", verdict.closure, verdict.manifest, verdict.objects, verdict.artifacts);
            Ok(EXIT_PASS)
        }
        Err(Refusal(reason)) => {
            println!(
                "{{\"schema\":\"neural-ice-seed-closure-verdict-v2\",\"verdict\":\"refuse\"}}"
            );
            eprintln!("ni-ota-verify: seed closure refused: {reason}");
            Ok(EXIT_REFUSE)
        }
    }
}

#[cfg(test)]
#[path = "seed_closure_tests.rs"]
mod tests;
