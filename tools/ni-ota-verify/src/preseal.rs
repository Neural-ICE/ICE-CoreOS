//! Offline, local-only verification of the delegated fresh-install baseline.
//!
//! This command authenticates immutable install inputs and writes one closed
//! receipt. It deliberately has no TPM, network, channel-activation, applied
//! state, or trusted-current-time behavior.

use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::{
    immutable_appliance_variant, immutable_bootstrap_delegation_sha256, immutable_hardware_target,
    immutable_minimum_delegation_seq, Config,
};
use crate::delegated::beta::{access_profile_for_variant, ReleaseAuthorization, RELEASE_DOMAIN};
use crate::delegated::contract::{
    canonical_hash, encode_base64, ident, parse_canonical, public_key_pem, safe_uint, sha256,
    signature_profile, timestamp, validate_der_signature, ContractError,
};
use crate::delegated::{authenticate_snapshot, verify_signature};
use crate::state::{FileStateStore, SecureTempFile, O_NOFOLLOW};
use crate::verify::BomCore;
use crate::{parse_flags, runner, InternalError, DEFAULT_CONFIG, EXIT_PASS, EXIT_REFUSE};

const SET_SCHEMA: &str = "neural-ice-installer-preseal-set-v1";
const RECEIPT_SCHEMA: &str = "neural-ice-ota-preseal-receipt-v1";
const STATE_PROFILE: &str = "owner-sealed-ota-state-v1";
const LAB_ROLE: &str = "release-lab";
const LAB_RING: &str = "lab";
const LAB_ARTIFACT: &str = "lab-release-authorization";
const LAB_KEY_ID: &str = "release-lab-v1";
const HARDWARE_TARGET: &str = "nvidia-gb10-arm64";
const APPLIANCE_VARIANT: &str = "sealed-lab";
const ACCESS_PROFILE: &str = "lab-managed";
const TRUST_POLICY: &str = "neural-ice-secureboot-lab-v1";
const INSTALLER_SCHEMA: &str = "neural-ice-installer-release-authorization-v2";
const INSTALLER_DOMAIN: &[u8] = b"neural-ice:installer:release-authorization:v2\0";
const MAX_SET: u64 = 16 * 1024;
const MAX_RELEASE: u64 = 64 * 1024;
const MAX_BOM: u64 = 128 * 1024;
const MAX_SIGNATURE: u64 = 1024;
const MAX_SMALL: u64 = 4 * 1024;
const MAX_RECEIPT: u64 = 16 * 1024;
#[cfg(target_os = "linux")]
const O_NONBLOCK: i32 = 0x800;
#[cfg(target_os = "macos")]
const O_NONBLOCK: i32 = 0x4;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PresealSet {
    access_policy_sha256: String,
    access_profile: String,
    attestation_set_sha256: String,
    bom_file_sha256: String,
    bom_sha256: String,
    bundle_seq: u64,
    channel_record_sha256: String,
    compat_max: u64,
    compat_min: u64,
    delegation_seq: u64,
    delegation_snapshot_file_sha256: String,
    delegation_snapshot_sha256: String,
    delegation_snapshot_signature_sha256: String,
    hardware_target: String,
    installer_authorization_sha256: String,
    installer_authorization_signature_sha256: String,
    ota_release_authorization_file_sha256: String,
    ota_release_authorization_sha256: String,
    ota_release_authorization_signature_sha256: String,
    ota_state_profile: String,
    release_key_id: String,
    release_signing_role: String,
    ring: String,
    schema: String,
    seed_ref: String,
    signed_boot_trust_policy_id: String,
    target_os_ref: String,
    train: String,
    variant: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InstallerAuthorization {
    access_profile: String,
    hardware_target: String,
    image_index_digest: String,
    image_manifest_digest: String,
    image_platform: String,
    image_publication_shape: String,
    image_repository: String,
    issuance_id: String,
    issuance_seq: String,
    issued_at: String,
    key_id: String,
    schema: String,
    signed_boot_trust_policy_id: String,
    variant: String,
}

#[derive(Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PresealReceipt {
    access_policy_sha256: String,
    access_profile: String,
    attestation_set_sha256: String,
    bom_sha256: String,
    bundle_seq: u64,
    channel_record_sha256: String,
    compat_max: u64,
    compat_min: u64,
    delegation_seq: u64,
    delegation_snapshot_sha256: String,
    delegation_snapshot_signature_sha256: String,
    hardware_target: String,
    installer_authorization_sha256: String,
    installer_issuance_id: String,
    installer_issuance_seq: u64,
    ota_release_authorization_sha256: String,
    ota_release_authorization_signature_sha256: String,
    ota_state_profile: String,
    preseal_set_sha256: String,
    release_issued_at: String,
    release_key_id: String,
    release_signing_role: String,
    release_valid_from: String,
    release_valid_until: String,
    ring: String,
    schema: String,
    seed_ref: String,
    signed_boot_trust_policy_id: String,
    target_os_ref: String,
    train: String,
    variant: String,
}

pub(crate) fn run(args: &[String]) -> Result<u8, InternalError> {
    let flags = parse_flags(
        args,
        &[
            "set",
            "snapshot",
            "snapshot-sig",
            "release",
            "release-sig",
            "bom",
            "installer-authorization",
            "installer-authorization-sig",
            "sealed-set-sha256",
            "sealed-installer-authorization-sha256",
            "sealed-installer-authorization-signature-sha256",
            "current-os-ref",
            "current-os-manifest-digest",
            "current-seed-ref",
            "candidate-root",
            "receipt-out",
            "config",
        ],
    )?;
    let required = |name: &str| {
        flags
            .get(name)
            .ok_or_else(|| InternalError(format!("verify-preseal-baseline: --{name} is required")))
    };
    let config = Config::load(Path::new(
        flags.get("config").map_or(DEFAULT_CONFIG, String::as_str),
    ))?;
    let state_dir = config
        .state_dir
        .ok_or_else(|| InternalError("verify-preseal-baseline requires state_dir".into()))?;
    let expected_receipt = state_dir.join("preseal/receipt.json");
    let receipt_path = PathBuf::from(required("receipt-out")?);
    if receipt_path != expected_receipt {
        return refusal(format!(
            "receipt path must be exactly {}",
            expected_receipt.display()
        ));
    }
    let receipt_store = FileStateStore {
        path: receipt_path.clone(),
    };
    if let Err(reason) = receipt_store.validate_bootstrap_parent() {
        return refusal(reason);
    }
    let _lock = match receipt_store.lock_bootstrap() {
        Ok(lock) => lock,
        Err(reason) => return refusal(reason),
    };

    macro_rules! snap {
        ($flag:literal, $label:literal, $max:expr) => {{
            match snapshot(&receipt_store, Path::new(required($flag)?), $label, $max)? {
                Ok(value) => value,
                Err(reason) => return refusal(reason),
            }
        }};
    }
    let set_file = snap!("set", "preseal set", MAX_SET);
    let snapshot_file = snap!("snapshot", "delegation snapshot", MAX_SET);
    let snapshot_sig = snap!(
        "snapshot-sig",
        "delegation snapshot signature",
        MAX_SIGNATURE
    );
    let release_file = snap!("release", "release authorization", MAX_RELEASE);
    let release_sig = snap!(
        "release-sig",
        "release authorization signature",
        MAX_SIGNATURE
    );
    let bom_file = snap!("bom", "BOM", MAX_BOM);
    let installer_file = snap!(
        "installer-authorization",
        "installer authorization",
        MAX_SIGNATURE
    );
    let installer_sig = snap!(
        "installer-authorization-sig",
        "installer authorization signature",
        MAX_SMALL
    );
    let root_path = match config.root_pubkey.as_deref() {
        Some(path) => path,
        None => return refusal("root_pubkey is required".into()),
    };
    let root_file = match snapshot(&receipt_store, root_path, "root public key", MAX_SMALL)? {
        Ok(value) => value,
        Err(reason) => return refusal(reason),
    };

    let set_bytes = set_file.read()?;
    let set: PresealSet = match parse_canonical(&set_bytes, "preseal set") {
        Ok(value) => value,
        Err(reason) => return refusal(reason),
    };
    let set_hash = runner::sha256_bytes(&set_bytes)?;
    let sealed_set_hash = required("sealed-set-sha256")?;
    if !sha256(sealed_set_hash) || sealed_set_hash != &set_hash {
        return refusal("preseal set differs from the signed UKI hash".into());
    }
    if let Err(reason) = validate_set_shape(&set) {
        return refusal(reason);
    }

    let snapshot_bytes = snapshot_file.read()?;
    let snapshot_sig_bytes = snapshot_sig.read()?;
    let root_bytes = root_file.read()?;
    let authenticated = match authenticate_snapshot(
        &snapshot_bytes,
        &snapshot_sig_bytes,
        &root_bytes,
        &receipt_store,
    ) {
        Ok(value) => value,
        Err(ContractError::Refusal(reason)) => return refusal(reason),
        Err(ContractError::Internal(error)) => return Err(error),
    };
    let authority = authenticated.snapshot();
    if set.delegation_seq != authority.delegation_seq
        || set.delegation_seq != immutable_minimum_delegation_seq()?
        || set.delegation_snapshot_sha256 != authenticated.canonical_sha256()
        || set.delegation_snapshot_sha256 != immutable_bootstrap_delegation_sha256()?
        || set.delegation_snapshot_file_sha256 != runner::sha256_bytes(&snapshot_bytes)?
        || set.delegation_snapshot_signature_sha256 != runner::sha256_bytes(&snapshot_sig_bytes)?
    {
        return refusal("preseal delegation epoch binding is invalid".into());
    }

    let release_bytes = release_file.read()?;
    let release: ReleaseAuthorization =
        match parse_canonical(&release_bytes, "release authorization") {
            Ok(value) => value,
            Err(reason) => return refusal(reason),
        };
    let key = match validate_release(&release, authority, authenticated.canonical_sha256(), &set) {
        Ok(value) => value,
        Err(reason) => return refusal(reason),
    };
    let release_pem = match public_key_pem(&key.public_key) {
        Ok(value) => value,
        Err(ContractError::Refusal(reason)) => return refusal(reason),
        Err(ContractError::Internal(error)) => return Err(error),
    };
    let release_sig_bytes = release_sig.read()?;
    if let Err(reason) = verify_signature(
        &release_pem,
        RELEASE_DOMAIN,
        &release_bytes,
        &release_sig_bytes,
        &receipt_store,
    )? {
        return refusal(reason);
    }
    if set.ota_release_authorization_file_sha256 != runner::sha256_bytes(&release_bytes)?
        || set.ota_release_authorization_sha256
            != match canonical_hash(&release_bytes) {
                Ok(value) => value,
                Err(ContractError::Refusal(reason)) => return refusal(reason),
                Err(ContractError::Internal(error)) => return Err(error),
            }
        || set.ota_release_authorization_signature_sha256
            != runner::sha256_bytes(&release_sig_bytes)?
    {
        return refusal("preseal release artifact hash binding is invalid".into());
    }

    let bom_bytes = bom_file.read()?;
    let bom: BomCore = match serde_json::from_slice(&bom_bytes) {
        Ok(value) => value,
        Err(error) => return refusal(format!("invalid BOM JSON: {error}")),
    };
    if let Err(reason) = bom.require_media_independent() {
        return refusal(reason);
    }
    if set.bom_file_sha256 != runner::sha256_bytes(&bom_bytes)?
        || set.bom_sha256 != set.bom_file_sha256
        || set.bom_sha256 != release.bom_sha256
    {
        return refusal("preseal BOM hash binding is invalid".into());
    }

    let installer_bytes = installer_file.read()?;
    let installer: InstallerAuthorization =
        match parse_canonical_no_lf(&installer_bytes, "installer authorization") {
            Ok(value) => value,
            Err(reason) => return refusal(reason),
        };
    let installer_sig_bytes = installer_sig.read()?;
    if set.installer_authorization_sha256 != runner::sha256_bytes(&installer_bytes)?
        || set.installer_authorization_signature_sha256
            != runner::sha256_bytes(&installer_sig_bytes)?
        || set.installer_authorization_sha256 != *required("sealed-installer-authorization-sha256")?
        || set.installer_authorization_signature_sha256
            != *required("sealed-installer-authorization-signature-sha256")?
    {
        return refusal("installer authorization differs from the signed UKI hashes".into());
    }
    if let Err(reason) = validate_installer(
        &installer,
        &set,
        required("current-os-ref")?,
        required("current-os-manifest-digest")?,
        &release_pem,
        authority,
        key,
    ) {
        return refusal(reason);
    }
    if let Err(reason) = verify_installer_signature(
        &release_pem,
        &installer_bytes,
        &installer_sig_bytes,
        &receipt_store,
    )? {
        return refusal(reason);
    }

    let hardware = immutable_hardware_target()?;
    let variant = immutable_appliance_variant()?;
    if set.hardware_target != hardware || set.variant != variant {
        return refusal("preseal selection differs from immutable host identity".into());
    }
    if config.device_compat != Some((set.compat_min as i64, set.compat_max as i64)) {
        return refusal(
            "preseal compatibility range differs from immutable device configuration".into(),
        );
    }
    let current_seed = required("current-seed-ref")?;
    if current_seed != &set.seed_ref {
        return refusal("current seed differs from the signed preseal selection".into());
    }
    if let Err(reason) = validate_bom(&bom, &set) {
        return refusal(reason);
    }
    if let Err(reason) =
        validate_candidate(Path::new(required("candidate-root")?), &set, current_seed)
    {
        return refusal(reason);
    }

    let receipt = PresealReceipt {
        access_policy_sha256: set.access_policy_sha256,
        access_profile: set.access_profile,
        attestation_set_sha256: set.attestation_set_sha256,
        bom_sha256: set.bom_sha256,
        bundle_seq: set.bundle_seq,
        channel_record_sha256: set.channel_record_sha256,
        compat_max: set.compat_max,
        compat_min: set.compat_min,
        delegation_seq: set.delegation_seq,
        delegation_snapshot_sha256: set.delegation_snapshot_sha256,
        delegation_snapshot_signature_sha256: set.delegation_snapshot_signature_sha256,
        hardware_target: set.hardware_target,
        installer_authorization_sha256: set.installer_authorization_sha256,
        installer_issuance_id: installer.issuance_id,
        installer_issuance_seq: installer
            .issuance_seq
            .parse()
            .expect("validated issuance sequence"),
        ota_release_authorization_sha256: set.ota_release_authorization_sha256,
        ota_release_authorization_signature_sha256: set.ota_release_authorization_signature_sha256,
        ota_state_profile: set.ota_state_profile,
        preseal_set_sha256: set_hash,
        release_issued_at: release.issued_at,
        release_key_id: set.release_key_id,
        release_signing_role: set.release_signing_role,
        release_valid_from: release.valid_from,
        release_valid_until: release.valid_until,
        ring: set.ring,
        schema: RECEIPT_SCHEMA.into(),
        seed_ref: set.seed_ref,
        signed_boot_trust_policy_id: set.signed_boot_trust_policy_id,
        target_os_ref: set.target_os_ref,
        train: set.train,
        variant: set.variant,
    };
    let mut receipt_bytes = serde_json::to_vec(&receipt)
        .map_err(|error| InternalError(format!("cannot serialize preseal receipt: {error}")))?;
    receipt_bytes.push(b'\n');
    let receipt_hash = runner::sha256_bytes(&receipt_bytes)?;
    let created = match publish_receipt(&receipt_store, &receipt_bytes)? {
        Ok(value) => value,
        Err(reason) => return refusal(reason),
    };
    println!(
        "{{\"bundle_seq\":{},\"idempotent\":{},\"preseal_receipt_sha256\":\"{}\",\"verdict\":\"pass\"}}",
        receipt.bundle_seq,
        if created { "false" } else { "true" },
        receipt_hash
    );
    Ok(EXIT_PASS)
}

fn validate_set_shape(value: &PresealSet) -> Result<(), String> {
    let hashes = [
        &value.access_policy_sha256,
        &value.attestation_set_sha256,
        &value.bom_file_sha256,
        &value.bom_sha256,
        &value.channel_record_sha256,
        &value.delegation_snapshot_file_sha256,
        &value.delegation_snapshot_sha256,
        &value.delegation_snapshot_signature_sha256,
        &value.installer_authorization_sha256,
        &value.installer_authorization_signature_sha256,
        &value.ota_release_authorization_file_sha256,
        &value.ota_release_authorization_sha256,
        &value.ota_release_authorization_signature_sha256,
    ];
    if value.schema != SET_SCHEMA
        || value.ota_state_profile != STATE_PROFILE
        || value.ring != LAB_RING
        || value.release_signing_role != LAB_ROLE
        || value.release_key_id != LAB_KEY_ID
        || value.access_profile != ACCESS_PROFILE
        || value.hardware_target != HARDWARE_TARGET
        || value.variant != APPLIANCE_VARIANT
        || value.signed_boot_trust_policy_id != TRUST_POLICY
        || access_profile_for_variant(&value.variant) != Some(value.access_profile.as_str())
        || !ident(&value.train)
        || !safe_uint(value.bundle_seq)
        || !safe_uint(value.delegation_seq)
        || !safe_uint(value.compat_min)
        || !safe_uint(value.compat_max)
        || value.compat_min > value.compat_max
        || !hashes.into_iter().all(|hash| nonzero_sha256(hash))
        || !seed_ref(&value.seed_ref)
        || !os_ref(&value.target_os_ref)
        || !trust_policy(&value.signed_boot_trust_policy_id)
    {
        return Err("preseal set contract is invalid".into());
    }
    Ok(())
}

fn validate_release<'a>(
    value: &ReleaseAuthorization,
    snapshot: &'a crate::delegated::contract::Snapshot,
    snapshot_hash: &str,
    set: &PresealSet,
) -> Result<&'a crate::delegated::contract::DelegatedKey, String> {
    if value.schema != "neural-ice-ota-release-authorization-v1"
        || value.signing_role != LAB_ROLE
        || value.ring != LAB_RING
        || value.beta_publication_receipt_sha256.is_some()
        || !signature_profile(&value.signature_algorithm, &value.signature_encoding)
        || value.access_profile != ACCESS_PROFILE
        || access_profile_for_variant(&value.variant) != Some(value.access_profile.as_str())
        || value.delegation_seq != snapshot.delegation_seq
        || value.delegation_snapshot_sha256 != snapshot_hash
        || !safe_uint(value.bundle_seq)
        || !safe_uint(value.compat_min)
        || !safe_uint(value.compat_max)
        || value.compat_min > value.compat_max
        || value.hardware_target != HARDWARE_TARGET
        || !ident(&value.issuance_id)
        || !ident(&value.key_id)
        || !ident(&value.train)
        || ![
            &value.access_policy_sha256,
            &value.bom_sha256,
            &value.channel_record_sha256,
            &value.attestation_set_sha256,
        ]
        .into_iter()
        .all(|hash| sha256(hash))
        || !timestamp(&value.issued_at)
        || !timestamp(&value.valid_from)
        || !timestamp(&value.valid_until)
        || value.issued_at > value.valid_from
        || value.valid_from >= value.valid_until
        || value.issued_at < snapshot.valid_from
        || value.issued_at >= snapshot.valid_until
    {
        return Err("LAB release authorization contract is invalid".into());
    }
    if value.access_policy_sha256 != set.access_policy_sha256
        || value.attestation_set_sha256 != set.attestation_set_sha256
        || value.bom_sha256 != set.bom_sha256
        || value.bundle_seq != set.bundle_seq
        || value.channel_record_sha256 != set.channel_record_sha256
        || value.compat_min != set.compat_min
        || value.compat_max != set.compat_max
        || value.delegation_seq != set.delegation_seq
        || value.hardware_target != set.hardware_target
        || value.key_id != set.release_key_id
        || value.signing_role != set.release_signing_role
        || value.ring != set.ring
        || value.train != set.train
        || value.variant != set.variant
    {
        return Err("release authorization differs from the preseal selection".into());
    }
    let mut matches = snapshot.keys.iter().filter(|key| {
        key.key_id == value.key_id
            && key.role == LAB_ROLE
            && key.status == "active"
            && key.rings == [LAB_RING]
            && key.hardware_targets == [value.hardware_target.as_str()]
            && key.artifact_types.iter().any(|kind| kind == LAB_ARTIFACT)
            && key.authorizes_at(&value.issued_at)
    });
    let key = matches
        .next()
        .ok_or("no delegated LAB key authorizes this release")?;
    if matches.next().is_some() {
        return Err("more than one delegated LAB key authorizes this release".into());
    }
    Ok(key)
}

fn validate_installer(
    value: &InstallerAuthorization,
    set: &PresealSet,
    current_os_ref: &str,
    current_manifest: &str,
    release_pem: &[u8],
    snapshot: &crate::delegated::contract::Snapshot,
    key: &crate::delegated::contract::DelegatedKey,
) -> Result<(), String> {
    let issuance_seq = value.issuance_seq.parse::<u64>().ok();
    let key_hash = runner::sha256_bytes(release_pem).map_err(|error| error.0)?;
    let (repository, digest) = set
        .target_os_ref
        .rsplit_once("@sha256:")
        .ok_or("target OS reference is malformed")?;
    if value.schema != INSTALLER_SCHEMA
        || value.access_profile != set.access_profile
        || value.hardware_target != set.hardware_target
        || value.image_platform != "linux/arm64"
        || !matches!(
            value.image_publication_shape.as_str(),
            "index" | "single-manifest"
        )
        || value.image_repository != repository
        || value.image_index_digest != format!("sha256:{digest}")
        || value.image_manifest_digest != current_manifest
        || current_os_ref != set.target_os_ref
        || !digest_value(current_manifest)
        || !installer_id(&value.issuance_id)
        || issuance_seq.is_none_or(|seq| !safe_uint(seq))
        || value.issuance_seq.len() > 16
        || value.issuance_seq.starts_with('0')
        || !timestamp(&value.issued_at)
        || value.issued_at < snapshot.valid_from
        || value.issued_at >= snapshot.valid_until
        || !key.authorizes_at(&value.issued_at)
        || value.key_id != key_hash
        || value.signed_boot_trust_policy_id != set.signed_boot_trust_policy_id
        || value.variant != set.variant
        || (value.image_publication_shape == "index"
            && value.image_index_digest == value.image_manifest_digest)
        || (value.image_publication_shape == "single-manifest"
            && value.image_index_digest != value.image_manifest_digest)
    {
        return Err("installer authorization contract or observed OS binding is invalid".into());
    }
    Ok(())
}

fn validate_bom(value: &BomCore, set: &PresealSet) -> Result<(), String> {
    let os = value
        .appliance
        .as_ref()
        .and_then(|value| value.os_base.as_ref())
        .ok_or("BOM has no OS base")?;
    let seed = value
        .sources
        .as_ref()
        .and_then(|value| value.seed.as_ref())
        .ok_or("BOM has no seed source")?;
    if value.train != set.train
        || value.hardware_target != set.hardware_target
        || value.bundle_seq != set.bundle_seq
        || value.compat_min != Some(set.compat_min as i64)
        || value.compat_version != Some(set.compat_max as i64)
        || format!("{}@{}", os.image, os.digest) != set.target_os_ref
        || seed.reference != set.seed_ref
    {
        return Err("BOM differs from the signed preseal selection".into());
    }
    Ok(())
}

fn validate_candidate(root: &Path, set: &PresealSet, current_seed: &str) -> Result<(), String> {
    crate::access_profile_anchor::assert_candidate_access_profile(
        root,
        &set.access_profile,
        &set.access_policy_sha256,
    )?;
    for (relative, expected) in [
        (
            "usr/lib/neural-ice/hardware-target",
            set.hardware_target.as_str(),
        ),
        ("usr/lib/neural-ice/appliance-variant", set.variant.as_str()),
        (
            "usr/lib/neural-ice/signed-boot-trust-policy-id",
            set.signed_boot_trust_policy_id.as_str(),
        ),
        ("usr/lib/neural-ice/ota-state-profile", STATE_PROFILE),
        (
            "usr/lib/neural-ice/product-payload/PAYLOAD_ID",
            set.seed_ref.as_str(),
        ),
    ] {
        let value = read_marker(root, relative)?;
        if value != expected {
            return Err(format!(
                "candidate marker {relative} differs from preseal selection"
            ));
        }
        if relative == "usr/lib/neural-ice/product-payload/PAYLOAD_ID" && value != current_seed {
            return Err("candidate PAYLOAD_ID differs from the observed current seed".into());
        }
    }
    Ok(())
}

fn read_marker(root: &Path, relative: &str) -> Result<String, String> {
    let path = root.join(relative);
    let named = std::fs::symlink_metadata(&path).map_err(|error| {
        format!(
            "cannot inspect candidate marker {}: {error}",
            path.display()
        )
    })?;
    if !named.file_type().is_file() || named.len() == 0 || named.len() > 256 {
        return Err(format!(
            "candidate marker {} is not a bounded regular file",
            path.display()
        ));
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NONBLOCK | O_NOFOLLOW)
        .open(&path)
        .map_err(|error| format!("cannot open candidate marker {}: {error}", path.display()))?;
    let opened = file.metadata().map_err(|error| {
        format!(
            "cannot inspect candidate marker {}: {error}",
            path.display()
        )
    })?;
    let named_again = std::fs::symlink_metadata(&path).map_err(|error| {
        format!(
            "cannot re-inspect candidate marker {}: {error}",
            path.display()
        )
    })?;
    if !opened.file_type().is_file()
        || !named_again.file_type().is_file()
        || opened.dev() != named_again.dev()
        || opened.ino() != named_again.ino()
    {
        return Err(format!(
            "candidate marker {} is not a stable regular non-symlink file",
            path.display()
        ));
    }
    let mut bytes = Vec::new();
    file.take(257)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read candidate marker {}: {error}", path.display()))?;
    if bytes.is_empty() || bytes.len() > 256 {
        return Err(format!(
            "candidate marker {} exceeds its read bound",
            path.display()
        ));
    }
    let value = String::from_utf8(bytes)
        .map_err(|_| format!("candidate marker {} is not UTF-8", path.display()))?;
    if !value.ends_with('\n') || value[..value.len() - 1].contains('\n') {
        return Err(format!(
            "candidate marker {} is not one line plus LF",
            path.display()
        ));
    }
    Ok(value[..value.len() - 1].to_owned())
}

fn snapshot(
    store: &FileStateStore,
    source: &Path,
    label: &str,
    maximum: u64,
) -> Result<Result<SecureTempFile, String>, InternalError> {
    let named = match std::fs::symlink_metadata(source) {
        Ok(metadata)
            if metadata.file_type().is_file()
                && metadata.len() > 0
                && metadata.len() <= maximum =>
        {
            metadata
        }
        Ok(_) => {
            return Ok(Err(format!(
            "{label} must be a non-empty regular non-symlink file no larger than {maximum} bytes"
        )))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Err(format!("{label} is missing")))
        }
        Err(error) => return Err(InternalError(format!("cannot inspect {label}: {error}"))),
    };
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NONBLOCK | O_NOFOLLOW)
        .open(source)
        .map_err(|error| InternalError(format!("cannot open {label}: {error}")))?;
    let opened = file
        .metadata()
        .map_err(|error| InternalError(format!("cannot inspect opened {label}: {error}")))?;
    let named_again = std::fs::symlink_metadata(source)
        .map_err(|error| InternalError(format!("cannot re-inspect {label}: {error}")))?;
    if !opened.file_type().is_file()
        || !named_again.file_type().is_file()
        || opened.dev() != named.dev()
        || opened.ino() != named.ino()
        || opened.dev() != named_again.dev()
        || opened.ino() != named_again.ino()
    {
        return Ok(Err(format!(
            "{label} source must remain a stable regular non-symlink file"
        )));
    }
    let mut bytes = Vec::new();
    file.take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| InternalError(format!("cannot read {label}: {error}")))?;
    if bytes.is_empty() || bytes.len() > maximum as usize {
        return Ok(Err(format!(
            "{label} exceeds its {maximum}-byte read bound"
        )));
    }
    store.secure_temp_bytes(label, &bytes).map(Ok)
}

fn parse_canonical_no_lf<T>(bytes: &[u8], what: &str) -> Result<T, String>
where
    T: serde::de::DeserializeOwned,
{
    if bytes.ends_with(b"\n") {
        return Err(format!("{what} must be canonical JSON without LF"));
    }
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|error| format!("invalid {what}: {error}"))?;
    let parsed =
        serde_json::from_slice(bytes).map_err(|error| format!("invalid {what}: {error}"))?;
    if serde_json::to_vec(&value).map_err(|error| error.to_string())? != bytes {
        return Err(format!(
            "{what} is not canonical compact sorted JSON without LF"
        ));
    }
    Ok(parsed)
}

fn verify_installer_signature(
    public_key: &[u8],
    payload: &[u8],
    der: &[u8],
    store: &FileStateStore,
) -> Result<Result<(), String>, InternalError> {
    if let Err(reason) = validate_der_signature(der) {
        return Ok(Err(reason));
    }
    let mut message = Vec::with_capacity(INSTALLER_DOMAIN.len() + payload.len());
    message.extend_from_slice(INSTALLER_DOMAIN);
    message.extend_from_slice(payload);
    let key = store.secure_temp_bytes("installer-key", public_key)?;
    let message = store.secure_temp_bytes("installer-message", &message)?;
    let encoded = encode_base64(der);
    let signature = store.secure_temp_bytes("installer-signature-b64", encoded.as_bytes())?;
    let cosign = runner::cosign_path()?;
    runner::verify_blob(&cosign, key.path(), signature.path(), message.path())
}

fn publish_receipt(
    store: &FileStateStore,
    expected: &[u8],
) -> Result<Result<bool, String>, InternalError> {
    if expected.len() > MAX_RECEIPT as usize {
        return Ok(Err("preseal receipt exceeds its bound".into()));
    }
    match store.validate_bootstrap_state() {
        Ok(true) => return compare_receipt(store, expected).map(|value| value.map(|()| false)),
        Ok(false) => {}
        Err(reason) => return Ok(Err(reason)),
    }
    let parent = store
        .path
        .parent()
        .ok_or_else(|| InternalError("receipt has no parent".into()))?;
    let staged = store.secure_temp_bytes("preseal-receipt", expected)?;
    let created = match std::fs::hard_link(staged.path(), &store.path) {
        Ok(()) => true,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(error) => {
            return Err(InternalError(format!(
                "cannot atomically publish preseal receipt: {error}"
            )))
        }
    };
    if created {
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| {
                InternalError(format!("cannot sync preseal receipt directory: {error}"))
            })?;
    }
    compare_receipt(store, expected).map(|value| value.map(|()| created))
}

fn compare_receipt(
    store: &FileStateStore,
    expected: &[u8],
) -> Result<Result<(), String>, InternalError> {
    if let Err(reason) = store.validate_bootstrap_state() {
        return Ok(Err(reason));
    }
    let file = File::open(&store.path)
        .map_err(|error| InternalError(format!("cannot read preseal receipt: {error}")))?;
    let mut actual = Vec::new();
    file.take(MAX_RECEIPT + 1)
        .read_to_end(&mut actual)
        .map_err(|error| InternalError(format!("cannot read preseal receipt: {error}")))?;
    if actual != expected {
        return Ok(Err(
            "existing preseal receipt differs from authenticated selection".into(),
        ));
    }
    match parse_canonical::<PresealReceipt>(&actual, "preseal receipt") {
        Ok(_) => Ok(Ok(())),
        Err(reason) => Ok(Err(reason)),
    }
}

fn digest_value(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(sha256)
}
fn nonzero_sha256(value: &str) -> bool {
    sha256(value) && value.bytes().any(|byte| byte != b'0')
}
fn installer_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}
fn seed_ref(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn trust_policy(value: &str) -> bool {
    value
        .strip_prefix("neural-ice-secureboot-")
        .is_some_and(|tail| {
            !tail.is_empty()
                && tail.len() <= 35
                && tail
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}
fn os_ref(value: &str) -> bool {
    let Some((repository, digest)) = value.rsplit_once("@sha256:") else {
        return false;
    };
    let Some(authority) = repository.strip_suffix("/neural-ice/neural-ice-appliance") else {
        return false;
    };
    let (host, port) = authority.split_once(':').unwrap_or((authority, ""));
    !host.is_empty()
        && host != "localhost"
        && host.contains('.')
        && !host
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.as_bytes()[0].is_ascii_alphanumeric()
                && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
        && (port.is_empty()
            || (port.bytes().all(|byte| byte.is_ascii_digit())
                && port.parse::<u16>().is_ok()
                && port != "0"))
        && sha256(digest)
}

fn refusal(reason: String) -> Result<u8, InternalError> {
    eprintln!("ni-ota-verify: preseal baseline REFUSED: {reason}");
    Ok(EXIT_REFUSE)
}
