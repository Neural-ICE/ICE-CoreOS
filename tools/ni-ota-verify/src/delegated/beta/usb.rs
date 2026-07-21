//! Local-only delegated verification for a physically delivered debug image.
//!
//! This command deliberately does not persist authority, applied-bundle or
//! trusted-time state. Those three records need an Owner-approved atomic state
//! contract before this verification result may authorize bootstrap mutation.

use std::path::Path;

use serde::Deserialize;

use super::*;
use crate::record::{self, ChannelRecord};
use crate::runner;
use crate::state::{ensure_secure_state_directory, FileStateStore};
use crate::verify::BomCore;

const ATTESTATION_SET_DOMAIN: &[u8] = b"neural-ice:ota:image-attestation-set:v1\0";

macro_rules! refuse_try {
    ($expression:expr) => {
        match $expression {
            Ok(value) => value,
            Err(reason) => return refusal(reason),
        }
    };
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AttestationSet {
    bom_sha256: String,
    bundle_seq: u64,
    delegation_seq: u64,
    delegation_snapshot_sha256: String,
    generated_at: String,
    hardware_target: String,
    images: Vec<AttestedImage>,
    schema: String,
    train: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AttestedImage {
    authority: String,
    image_ci_key_id: Option<String>,
    image_name: String,
    image_signature_digest: Option<String>,
    manifest_digest: String,
    oci_repository: String,
    provenance_digest: Option<String>,
    sbom_digest: Option<String>,
}

pub(crate) fn run(args: &[String]) -> Result<u8, InternalError> {
    let flags = parse_flags(
        args,
        &[
            "snapshot",
            "snapshot-sig",
            "release",
            "release-sig",
            "bom",
            "record",
            "attestation",
            "attestation-sig",
            "bundle-digest",
            "current-os-ref",
            "current-seed-ref",
            "trusted-now",
            "accepted-snapshot",
            "accepted-delegation-seq",
            "accepted-delegation-sha256",
            "config",
        ],
    )?;
    let required = |name: &str| {
        flags
            .get(name)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| InternalError(format!("verify-delegated-usb: --{name} is required")))
    };
    let config = Config::load(Path::new(
        flags.get("config").map_or(DEFAULT_CONFIG, String::as_str),
    ))?;
    let state_dir = config
        .state_dir
        .as_ref()
        .ok_or_else(|| InternalError("state_dir is required".into()))?;
    ensure_secure_state_directory(state_dir)?;
    let scratch = FileStateStore {
        path: state_dir.join("applied.json"),
    };
    let artifact = |flag: &str, label: &str| freeze(&scratch, Path::new(required(flag)?), label);
    let snapshot_file = artifact("snapshot", "usb-delegation-snapshot")?;
    let snapshot_sig = artifact("snapshot-sig", "usb-delegation-signature")?;
    let release_file = artifact("release", "usb-beta-release")?;
    let release_sig = artifact("release-sig", "usb-beta-release-signature")?;
    let bom_file = artifact("bom", "usb-bom")?;
    let record_file = artifact("record", "usb-channel-record")?;
    let attestation_file = artifact("attestation", "usb-attestation-set")?;
    let attestation_sig = artifact("attestation-sig", "usb-attestation-signature")?;

    let snapshot_bytes = snapshot_file.read()?;
    let release_bytes = release_file.read()?;
    let bom_bytes = bom_file.read()?;
    let record_bytes = record_file.read()?;
    let attestation_bytes = attestation_file.read()?;
    let snapshot: Snapshot = refuse_try!(parse_canonical(&snapshot_bytes, "delegation snapshot"));
    let release: ReleaseAuthorization =
        refuse_try!(parse_canonical(&release_bytes, "beta release"));
    let attestation: AttestationSet =
        refuse_try!(parse_canonical(&attestation_bytes, "attestation set"));
    refuse_try!(validate_pretty_json(&bom_bytes, "BOM"));
    refuse_try!(validate_pretty_json(&record_bytes, "channel record"));
    let bom: BomCore = refuse_try!(
        serde_json::from_slice(&bom_bytes).map_err(|error| format!("invalid BOM: {error}"))
    );
    let record = refuse_try!(record::parse(&record_bytes));

    let Some(root_path) = config.root_pubkey.as_deref() else {
        return refusal("no root_pubkey configured in ota.conf".into());
    };
    let root = match super::super::freeze_root(&scratch, root_path, "usb-root-public-key")? {
        Ok(root) => root,
        Err(reason) => return refusal(reason),
    };
    let now = required("trusted-now")?;
    let context = super::super::CandidateContext {
        now,
        minimum: immutable_minimum_delegation_seq()?,
        flags: &flags,
        snapshot_file: &snapshot_file,
        scratch: &scratch,
        allow_unseeded_bootstrap: true,
    };
    let snapshot_hash = match super::super::validate_candidate(&snapshot, &context) {
        Ok(hash) => hash,
        Err(ContractError::Refusal(reason)) => return refusal(reason),
        Err(ContractError::Internal(error)) => return Err(error),
    };
    let root_bytes = root.read()?;
    refuse_try!(verify_root_binding(&snapshot, &root_bytes));
    refuse_try!(super::super::verify_signature(
        &root_bytes,
        super::super::SNAPSHOT_DOMAIN,
        &snapshot_bytes,
        &snapshot_sig.read()?,
        &scratch,
    )?);

    let target = immutable_hardware_target()?;
    let variant = immutable_appliance_variant()?;
    refuse_try!(validate_release(
        &release,
        &snapshot,
        &snapshot_hash,
        now,
        &target,
    ));
    if config.device_channel.as_deref() != Some("beta") {
        return refusal("delegated USB bootstrap requires device_channel=beta".into());
    }
    if variant != "debug" || release.variant != "debug" {
        return refusal(format!(
            "delegated USB bootstrap requires immutable and signed variant debug (host={variant}, release={})",
            release.variant
        ));
    }
    refuse_try!(device_compatibility(&release, config.device_compat));
    let release_key = refuse_try!(authorized_key(
        &snapshot,
        &release.key_id,
        "beta-release-authorization",
        &target,
        &release.issued_at,
        now,
    ));
    let release_pem = match public_key_pem(&release_key.public_key) {
        Ok(pem) => pem,
        Err(ContractError::Refusal(reason)) => return refusal(reason),
        Err(ContractError::Internal(error)) => return Err(error),
    };
    refuse_try!(super::super::verify_signature(
        &release_pem,
        RELEASE_DOMAIN,
        &release_bytes,
        &release_sig.read()?,
        &scratch,
    )?);

    let bom_hash = runner::sha256_bytes(&bom_bytes)?;
    let record_hash = runner::sha256_bytes(&record_bytes)?;
    let attestation_hash = match canonical_hash(&attestation_bytes) {
        Ok(hash) => hash,
        Err(ContractError::Refusal(reason)) => return refusal(reason),
        Err(ContractError::Internal(error)) => return Err(error),
    };
    let release_hash = match canonical_hash(&release_bytes) {
        Ok(hash) => hash,
        Err(ContractError::Refusal(reason)) => return refusal(reason),
        Err(ContractError::Internal(error)) => return Err(error),
    };
    let bundle_digest = required("bundle-digest")?;
    let current_os = required("current-os-ref")?;
    let current_seed = required("current-seed-ref")?;
    refuse_try!(validate_exact_bindings(
        &release,
        &snapshot,
        &bom,
        &record,
        &attestation,
        &bom_hash,
        &record_hash,
        &attestation_hash,
        bundle_digest,
        current_os,
        current_seed,
        now,
    ));
    let image_ci_key_id = refuse_try!(attestation_image_ci_key_id(&attestation));
    let image_ci_key = refuse_try!(authorized_image_ci_key(
        &snapshot,
        image_ci_key_id,
        &attestation,
        now,
    ));
    let image_ci_pem = match public_key_pem(&image_ci_key.public_key) {
        Ok(pem) => pem,
        Err(ContractError::Refusal(reason)) => return refusal(reason),
        Err(ContractError::Internal(error)) => return Err(error),
    };
    refuse_try!(super::super::verify_signature(
        &image_ci_pem,
        ATTESTATION_SET_DOMAIN,
        &attestation_bytes,
        &attestation_sig.read()?,
        &scratch,
    )?);

    println!(
        "{}",
        serde_json::json!({
            "verdict": "pass",
            "mode": "delegated-usb-beta",
            "delegation_seq": snapshot.delegation_seq,
            "snapshot_sha256": snapshot_hash,
            "release_sha256": release_hash,
            "bundle_seq": release.bundle_seq,
            "bom_sha256": bom_hash,
            "channel_record_sha256": record_hash,
            "attestation_set_sha256": attestation_hash,
            "bundle_digest": bundle_digest,
            "hardware_target": target,
            "train": release.train,
        })
    );
    Ok(EXIT_PASS)
}

#[allow(clippy::too_many_arguments)]
fn validate_exact_bindings(
    release: &ReleaseAuthorization,
    snapshot: &Snapshot,
    bom: &BomCore,
    record: &ChannelRecord,
    attestation: &AttestationSet,
    bom_hash: &str,
    record_hash: &str,
    attestation_hash: &str,
    bundle_digest: &str,
    current_os: &str,
    current_seed: &str,
    now: &str,
) -> Result<(), String> {
    if release.bom_sha256 != bom_hash
        || release.channel_record_sha256 != record_hash
        || release.attestation_set_sha256 != attestation_hash
        || record.channel != "beta"
        || record.key_version == 0
        || !timestamp(&record.assigned_at)
        || record.bundle_digest != bundle_digest
        || record.train != release.train
        || record.hardware_target != release.hardware_target
        || record.bundle_seq != release.bundle_seq
        || bom.train != release.train
        || bom.hardware_target != release.hardware_target
        || bom.bundle_seq != release.bundle_seq
        || bom.compat_min != i64::try_from(release.compat_min).ok()
        || bom.compat_version != i64::try_from(release.compat_max).ok()
    {
        return Err("release, BOM, channel record or bundle digest binding mismatch".into());
    }
    validate_attestation(attestation, release, snapshot, bom_hash, now)?;
    let os = bom
        .appliance
        .as_ref()
        .and_then(|appliance| appliance.os_base.as_ref())
        .ok_or("BOM lacks appliance.os_base image/digest")?;
    if format!("{}@{}", os.image, os.digest) != current_os || !valid_os_ref(current_os) {
        return Err("booted OS ref differs from the exact BOM appliance ref".into());
    }
    let seed = bom
        .sources
        .as_ref()
        .and_then(|sources| sources.seed.as_ref())
        .ok_or("BOM lacks sources.seed.ref")?;
    if seed.reference != current_seed || !valid_seed(current_seed) {
        return Err("installed PAYLOAD_ID differs from the exact BOM seed ref".into());
    }
    Ok(())
}

fn validate_attestation(
    value: &AttestationSet,
    release: &ReleaseAuthorization,
    snapshot: &Snapshot,
    bom_hash: &str,
    now: &str,
) -> Result<(), String> {
    if value.schema != "neural-ice-ota-image-attestation-set-v1"
        || value.bom_sha256 != bom_hash
        || value.bundle_seq != release.bundle_seq
        || value.delegation_seq != release.delegation_seq
        || value.delegation_snapshot_sha256 != release.delegation_snapshot_sha256
        || value.hardware_target != release.hardware_target
        || value.train != release.train
        || !timestamp(&value.generated_at)
        || value.generated_at < snapshot.valid_from
        || value.generated_at >= snapshot.valid_until
        || value.generated_at > release.issued_at
        || value.generated_at.as_str() > now
        || value.images.is_empty()
    {
        return Err("attestation-set top-level binding is invalid".into());
    }
    let mut previous = None;
    for image in &value.images {
        if !ident(&image.image_name)
            || previous.is_some_and(|name: &str| name >= image.image_name.as_str())
            || !repository(&image.oci_repository)
            || !oci_digest(&image.manifest_digest)
        {
            return Err("attestation image identity/order/digest is invalid".into());
        }
        previous = Some(image.image_name.as_str());
        match image.authority.as_str() {
            "image-ci" => {
                let Some(key_id) = image.image_ci_key_id.as_deref() else {
                    return Err("product image lacks image-ci key id".into());
                };
                if !image.oci_repository.starts_with("neural-ice/")
                    || ![
                        &image.image_signature_digest,
                        &image.provenance_digest,
                        &image.sbom_digest,
                    ]
                    .into_iter()
                    .all(|digest| digest.as_deref().is_some_and(oci_digest))
                    || !image_ci_authorized(snapshot, key_id, value, now)
                {
                    return Err("product image lacks exact image-ci authority/proofs".into());
                }
            }
            "bom-digest-only" => {
                if !image.oci_repository.starts_with("vendor/")
                    || image.image_ci_key_id.is_some()
                    || image.image_signature_digest.is_some()
                    || image.provenance_digest.is_some()
                    || image.sbom_digest.is_some()
                {
                    return Err("vendor digest-only image carries invalid authority fields".into());
                }
            }
            _ => return Err("unknown attestation image authority".into()),
        }
    }
    Ok(())
}

fn attestation_image_ci_key_id(value: &AttestationSet) -> Result<&str, String> {
    let mut key_id = None;
    for image in value
        .images
        .iter()
        .filter(|image| image.authority == "image-ci")
    {
        let current = image
            .image_ci_key_id
            .as_deref()
            .ok_or("product image lacks image-ci key id")?;
        if key_id.is_some_and(|accepted| accepted != current) {
            return Err("attestation set mixes image-ci signing authorities".into());
        }
        key_id = Some(current);
    }
    key_id.ok_or_else(|| "attestation set lacks image-ci signed product images".into())
}

fn authorized_image_ci_key<'a>(
    snapshot: &'a Snapshot,
    key_id: &str,
    set: &AttestationSet,
    now: &str,
) -> Result<&'a DelegatedKey, String> {
    let mut keys = snapshot.keys.iter().filter(|key| {
        key.key_id == key_id
            && key.role == "image-ci"
            && key.hardware_targets.contains(&set.hardware_target)
            && key.rings.iter().any(|ring| ring == "beta")
            && [
                "oci-image-signature",
                "slsa-provenance-attestation",
                "spdx-sbom-attestation",
            ]
            .iter()
            .all(|kind| key.artifact_types.iter().any(|value| value == kind))
            && matches!(key.status.as_str(), "active" | "retiring")
            && key.valid_from <= set.generated_at
            && set.generated_at < key.valid_until
            && key.valid_from.as_str() <= now
            && now < key.valid_until.as_str()
    });
    let key = keys
        .next()
        .ok_or("attestation set image-ci authority is unavailable")?;
    if keys.next().is_some() {
        return Err("attestation set image-ci authority is ambiguous".into());
    }
    Ok(key)
}

fn image_ci_authorized(snapshot: &Snapshot, key_id: &str, set: &AttestationSet, now: &str) -> bool {
    authorized_image_ci_key(snapshot, key_id, set, now).is_ok()
}

fn repository(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value.split('/').count() == 2
        && value.split('/').all(ident)
}

fn validate_pretty_json(bytes: &[u8], what: &str) -> Result<(), String> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|error| format!("invalid {what}: {error}"))?;
    let mut expected = serde_json::to_vec_pretty(&value).map_err(|error| error.to_string())?;
    expected.push(b'\n');
    if expected != bytes {
        return Err(format!(
            "{what} is not exact sorted pretty JSON plus one LF"
        ));
    }
    Ok(())
}

fn valid_seed(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_os_ref(value: &str) -> bool {
    let Some((image, digest)) = value.rsplit_once("@sha256:") else {
        return false;
    };
    !image.is_empty()
        && !image
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte == b'@')
        && sha256(digest)
}
