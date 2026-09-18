//! Delegated lab authorization plus publication-receipt gate.
//!
//! This is the lab-ring twin of [`super::beta`]. The two rings share one
//! release-authorization schema (`neural-ice-ota-release-authorization-v1`,
//! the [`ReleaseAuthorization`] struct) and the whole authenticated-transport
//! and signature substrate in [`super`] and [`super::contract`]; only the
//! ring-specific words differ. A lab release is signed by `release-lab`, names
//! `ring == "lab"`, is `access_profile == "lab-managed"` and carries a null
//! `beta_publication_receipt_sha256` (a beta-only carve-out, refused when set
//! on a lab release). The publication receipt has its own schema
//! (`neural-ice-ota-lab-publication-receipt-v1`) and, unlike the beta receipt,
//! restates the release's `access_profile`/`access_policy_sha256` — so this
//! verifier binds those too.
//!
//! The trust posture is deliberate: ICE-Fabric fully delegates lab publication
//! to the `release-lab` KMS key (ADR-0057), so no IronKey gesture stands behind
//! a lab train. That is exactly why the lab receipt verify path must be as
//! strict as beta's — the only thing between a lab appliance and an arbitrary
//! image is this contract.

use std::path::Path;

use serde::{Deserialize, Serialize};

use super::beta::{
    access_profile_for_variant, device_compatibility, ReleaseAuthorization, RELEASE_DOMAIN_PURPOSE,
};
use super::contract::{
    canonical_hash, ident, parse_canonical, public_key_pem, safe_uint, sha256, signature_profile,
    target, timestamp, ContractError, DelegatedKey, Snapshot,
};
use super::{
    freeze_authority, freeze_root, refusal, validate_candidate, verify_root_binding,
    verify_signature,
};
use crate::access_profile_anchor;
use crate::config::{
    immutable_appliance_variant, immutable_hardware_target, immutable_minimum_delegation_seq,
    Config,
};
use crate::state::{ensure_secure_state_directory, FileStateStore};
use crate::{parse_flags, InternalError, DEFAULT_CONFIG, EXIT_PASS};

const RECEIPT_DOMAIN_PURPOSE_LAB: &str = "ota:lab-publication-receipt:v1";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LabReceipt {
    /// SHA-256 of the CANDIDATE deployment's own `access-policy` marker,
    /// restated by the receipt. The beta receipt does not carry this; the lab
    /// receipt does (ICE-Fabric `neural-ice-ota-lab-publication-receipt-v1`),
    /// and [`validate_receipt`] binds it to the release so the two signed
    /// documents cannot disagree about the posture the train ships with.
    access_policy_sha256: String,
    /// The access posture the train is FOR. Required, `lab-managed` on a lab
    /// receipt, and bound to the release's `access_profile` below — the same
    /// fail-closed shape the release-authorization carries it with.
    access_profile: String,
    attestation_set_sha256: String,
    bom_sha256: String,
    bundle_seq: u64,
    channel_record_sha256: String,
    compat_max: u64,
    compat_min: u64,
    delegation_seq: u64,
    delegation_snapshot_sha256: String,
    hardware_target: String,
    issuance_id: String,
    issued_at: String,
    key_id: String,
    lab_envelope_sha256: String,
    lab_variant: String,
    observed_at: String,
    pointer_identity: String,
    registry_repository: String,
    resolved_pointer_manifest_digest: String,
    ring: String,
    schema: String,
    signature_algorithm: String,
    signature_encoding: String,
    signing_role: String,
    train: String,
    valid_until: String,
}

pub(crate) fn run(args: &[String]) -> Result<u8, InternalError> {
    let flags = parse_flags(
        args,
        &[
            "snapshot",
            "snapshot-sig",
            "release",
            "release-sig",
            "receipt",
            "receipt-sig",
            "trusted-now",
            "accepted-snapshot",
            "accepted-delegation-seq",
            "accepted-delegation-sha256",
            "candidate-root",
            "config",
        ],
    )?;
    let required = |name: &str| {
        flags
            .get(name)
            .ok_or_else(|| InternalError(format!("verify-delegated-lab: --{name} is required")))
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
    macro_rules! artifact {
        ($flag:literal, $label:literal) => {
            match freeze_authority(&scratch, Path::new(required($flag)?), $label)? {
                Ok(file) => file,
                Err(reason) => return refusal(reason),
            }
        };
    }
    let snapshot_file = artifact!("snapshot", "delegation-snapshot");
    let snapshot_sig = artifact!("snapshot-sig", "delegation-signature");
    let release_file = artifact!("release", "lab-release");
    let release_sig = artifact!("release-sig", "lab-release-signature");
    let receipt_file = artifact!("receipt", "lab-receipt");
    let receipt_sig = artifact!("receipt-sig", "lab-receipt-signature");
    let Some(root) = config.root_pubkey.as_deref() else {
        return refusal("no root_pubkey configured in ota.conf".into());
    };
    let root = match freeze_root(&scratch, root, "root-public-key")? {
        Ok(root) => root,
        Err(reason) => return refusal(reason),
    };
    let snapshot_bytes = snapshot_file.read()?;
    let release_bytes = release_file.read()?;
    let receipt_bytes = receipt_file.read()?;
    let snapshot: Snapshot = match parse_canonical(&snapshot_bytes, "delegation snapshot") {
        Ok(value) => value,
        Err(reason) => return refusal(reason),
    };
    let release: ReleaseAuthorization = match parse_canonical(&release_bytes, "lab release") {
        Ok(value) => value,
        Err(reason) => return refusal(reason),
    };
    let receipt: LabReceipt = match parse_canonical(&receipt_bytes, "lab receipt") {
        Ok(value) => value,
        Err(reason) => return refusal(reason),
    };
    let now = required("trusted-now")?;
    let context = super::CandidateContext {
        now,
        minimum: immutable_minimum_delegation_seq()?,
        flags: &flags,
        snapshot_file: &snapshot_file,
        scratch: &scratch,
        allow_unseeded_bootstrap: false,
    };
    let target = immutable_hardware_target()?;
    let variant = immutable_appliance_variant()?;
    let snapshot_hash = match validate_candidate(&snapshot, &context) {
        Ok(hash) => hash,
        Err(ContractError::Refusal(reason)) => return refusal(reason),
        Err(ContractError::Internal(error)) => return Err(error),
    };
    let root_bytes = root.read()?;
    if let Err(reason) = verify_root_binding(&snapshot, &root_bytes) {
        return refusal(reason);
    }
    if let Err(reason) = verify_signature(
        &root_bytes,
        &crate::namespace::domain(crate::delegated::SNAPSHOT_DOMAIN_PURPOSE),
        &snapshot_bytes,
        &snapshot_sig.read()?,
        &scratch,
    )? {
        return refusal(reason);
    }
    if let Err(reason) = validate_release(&release, &snapshot, &snapshot_hash, now, &target) {
        return refusal(reason);
    }
    if config.device_channel.as_deref() != Some("lab") {
        return refusal("delegated lab release requires device_channel=lab".into());
    }
    if release.variant != variant {
        return refusal(format!(
            "release variant '{}' does not match immutable host variant '{variant}'",
            release.variant
        ));
    }
    // The variant check above binds what the appliance IS BUILT FROM. This one
    // binds what it WAS INSTALLED AS -- a value enrolled at install time,
    // outside the candidate deployment, and signed by the device root. Without
    // it, a correctly signed SAME-VARIANT release could rewrite the
    // variant->profile mapping and widen the appliance's access posture with no
    // signature ever having stated the old one (DESIGN-NOTE-0001, Finding 3).
    let enrolled = match access_profile_anchor::enrolled_access_profile(&state_dir, &scratch)? {
        Ok(profile) => profile,
        Err(reason) => return refusal(reason),
    };
    if let Err(reason) =
        access_profile_anchor::gate_release_profile(&enrolled, &release.access_profile)
    {
        return refusal(reason);
    }
    // …and the CANDIDATE's own marker, not only the release document's word for
    // it. `--candidate-root` is required rather than optional: an optional
    // security argument is one every caller forgets, and this one is what stops
    // a same-variant candidate shipping a widened access policy under an
    // unchanged signed profile.
    let candidate_root = Path::new(required("candidate-root")?);
    if let Err(reason) = access_profile_anchor::assert_candidate_access_profile(
        candidate_root,
        &enrolled,
        &release.access_policy_sha256,
    ) {
        return refusal(reason);
    }
    if let Err(reason) = device_compatibility(&release, config.device_compat) {
        if config.enforce {
            return refusal(reason);
        }
        eprintln!("ni-ota-verify: lab compatibility WARNING: {reason}");
    }
    if let Err(error) = validate_receipt(
        &receipt,
        &release,
        &release_bytes,
        &snapshot,
        &snapshot_hash,
        now,
        &target,
    ) {
        match error {
            ContractError::Refusal(reason) => return refusal(reason),
            ContractError::Internal(error) => return Err(error),
        }
    }
    let release_key = match authorized_key(
        &snapshot,
        &release.key_id,
        "lab-release-authorization",
        &target,
        &release.issued_at,
        now,
    ) {
        Ok(key) => key,
        Err(reason) => return refusal(reason),
    };
    let release_pem = match public_key_pem(&release_key.public_key) {
        Ok(pem) => pem,
        Err(ContractError::Refusal(reason)) => return refusal(reason),
        Err(ContractError::Internal(error)) => return Err(error),
    };
    if let Err(reason) = verify_signature(
        &release_pem,
        &crate::namespace::domain(RELEASE_DOMAIN_PURPOSE),
        &release_bytes,
        &release_sig.read()?,
        &scratch,
    )? {
        return refusal(reason);
    }
    let receipt_key = match authorized_key(
        &snapshot,
        &receipt.key_id,
        "lab-publication-receipt",
        &target,
        &receipt.issued_at,
        now,
    ) {
        Ok(key) => key,
        Err(reason) => return refusal(reason),
    };
    let receipt_pem = match public_key_pem(&receipt_key.public_key) {
        Ok(pem) => pem,
        Err(ContractError::Refusal(reason)) => return refusal(reason),
        Err(ContractError::Internal(error)) => return Err(error),
    };
    if let Err(reason) = verify_signature(
        &receipt_pem,
        &crate::namespace::domain(RECEIPT_DOMAIN_PURPOSE_LAB),
        &receipt_bytes,
        &receipt_sig.read()?,
        &scratch,
    )? {
        return refusal(reason);
    }
    let receipt_hash = match canonical_hash(&receipt_bytes) {
        Ok(hash) => hash,
        Err(ContractError::Refusal(reason)) => return refusal(reason),
        Err(ContractError::Internal(error)) => return Err(error),
    };
    println!(
        "{{\"verdict\":\"pass\",\"ring\":\"lab\",\"bundle_seq\":{},\"receipt_sha256\":\"{}\",\"manifest_digest\":\"{}\"}}",
        release.bundle_seq, receipt_hash, receipt.resolved_pointer_manifest_digest
    );
    Ok(EXIT_PASS)
}

fn validate_release(
    value: &ReleaseAuthorization,
    snapshot: &Snapshot,
    snapshot_hash: &str,
    now: &str,
    immutable_target: &str,
) -> Result<(), String> {
    validate_release_contract(value, snapshot, snapshot_hash, immutable_target)?;
    if now < value.valid_from.as_str() || now >= value.valid_until.as_str() {
        return Err("lab release authorization is not live at trusted time".into());
    }
    authorized_key(
        snapshot,
        &value.key_id,
        "lab-release-authorization",
        immutable_target,
        &value.issued_at,
        now,
    )?;
    Ok(())
}

fn validate_release_contract(
    value: &ReleaseAuthorization,
    snapshot: &Snapshot,
    snapshot_hash: &str,
    immutable_target: &str,
) -> Result<(), String> {
    if value.schema != "neural-ice-ota-release-authorization-v1"
        || value.signing_role != "release-lab"
        || value.ring != "lab"
        // A lab release is a first-class publication, not a promotion of a beta
        // one: the beta-only receipt carve-out must be absent, never merely
        // ignored. ICE-Fabric's contract forces this field null for `ring==lab`.
        || value.beta_publication_receipt_sha256.is_some()
        || !signature_profile(&value.signature_algorithm, &value.signature_encoding)
        || !safe_uint(value.delegation_seq)
        || value.delegation_seq != snapshot.delegation_seq
        || value.delegation_snapshot_sha256 != snapshot_hash
        || !safe_uint(value.bundle_seq)
        || !safe_uint(value.compat_min)
        || !safe_uint(value.compat_max)
        || value.compat_min > value.compat_max
        // The lab ring is `lab-managed`, and the one variant that maps to it is
        // `sealed-lab`. Both halves are asserted: the profile word directly,
        // and — via the same total mapping the image build derives its marker
        // from — the variant it must have come from. A release whose two fields
        // disagree is an internally inconsistent signed statement; refuse it
        // rather than prefer one half over the other.
        || value.access_profile != "lab-managed"
        || !matches!(value.variant.as_str(), "debug" | "prod" | "sealed-lab")
        || access_profile_for_variant(&value.variant) != Some(value.access_profile.as_str())
        || !target(&value.hardware_target)
        || value.hardware_target != immutable_target
        || !ident(&value.issuance_id)
        || !ident(&value.key_id)
        || !ident(&value.train)
        || ![
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
        return Err("lab release authorization contract or binding is invalid".into());
    }
    Ok(())
}

fn validate_receipt(
    value: &LabReceipt,
    release: &ReleaseAuthorization,
    release_bytes: &[u8],
    snapshot: &Snapshot,
    snapshot_hash: &str,
    now: &str,
    immutable_target: &str,
) -> Result<(), ContractError> {
    if value.schema != "neural-ice-ota-lab-publication-receipt-v1"
        || value.signing_role != "release-lab"
        || value.ring != "lab"
        || value.access_profile != "lab-managed"
        || !signature_profile(&value.signature_algorithm, &value.signature_encoding)
        || !safe_uint(value.delegation_seq)
        || value.delegation_seq != snapshot.delegation_seq
        || value.delegation_snapshot_sha256 != snapshot_hash
        || !safe_uint(value.bundle_seq)
        || !safe_uint(value.compat_min)
        || !safe_uint(value.compat_max)
        || value.compat_min > value.compat_max
        || !matches!(value.lab_variant.as_str(), "sealed-lab" | "prod")
        || !target(&value.hardware_target)
        || value.hardware_target != immutable_target
        || !ident(&value.issuance_id)
        || !ident(&value.key_id)
        || !ident(&value.train)
        || value.registry_repository != "neural-ice/channels"
        || value.pointer_identity != format!("{}-lab", value.hardware_target)
        || !oci_digest(&value.resolved_pointer_manifest_digest)
        || ![
            &value.bom_sha256,
            &value.channel_record_sha256,
            &value.attestation_set_sha256,
            &value.lab_envelope_sha256,
            &value.access_policy_sha256,
        ]
        .into_iter()
        .all(|hash| sha256(hash))
        || !timestamp(&value.observed_at)
        || !timestamp(&value.issued_at)
        || !timestamp(&value.valid_until)
        || value.observed_at > value.issued_at
        || value.issued_at >= value.valid_until
        || value.issued_at < snapshot.valid_from
        || value.issued_at >= snapshot.valid_until
        || now < value.issued_at.as_str()
        || now >= value.valid_until.as_str()
    {
        return Err(ContractError::Refusal(
            "lab publication receipt contract or binding is invalid".into(),
        ));
    }
    authorized_key(
        snapshot,
        &value.key_id,
        "lab-publication-receipt",
        immutable_target,
        &value.issued_at,
        now,
    )
    .map_err(ContractError::Refusal)?;
    let release_hash = canonical_hash(release_bytes)?;
    if value.lab_envelope_sha256 != release_hash
        || value.lab_variant != release.variant
        || value.bom_sha256 != release.bom_sha256
        || value.attestation_set_sha256 != release.attestation_set_sha256
        || value.channel_record_sha256 != release.channel_record_sha256
        // The lab receipt restates the release's posture; a mismatch here would
        // be two signed documents disagreeing about what the appliance boots.
        || value.access_profile != release.access_profile
        || value.access_policy_sha256 != release.access_policy_sha256
        || value.compat_min != release.compat_min
        || value.compat_max != release.compat_max
        || value.bundle_seq != release.bundle_seq
        || value.delegation_seq != release.delegation_seq
        || value.delegation_snapshot_sha256 != release.delegation_snapshot_sha256
        || value.hardware_target != release.hardware_target
        || value.train != release.train
        || value.observed_at < release.valid_from
        || value.observed_at >= release.valid_until
    {
        return Err(ContractError::Refusal(
            "lab receipt does not bind the exact lab release".into(),
        ));
    }
    Ok(())
}

fn authorized_key<'a>(
    snapshot: &'a Snapshot,
    key_id: &str,
    artifact: &str,
    target: &str,
    issued_at: &str,
    now: &str,
) -> Result<&'a DelegatedKey, String> {
    let matches: Vec<_> = snapshot
        .keys
        .iter()
        .filter(|key| {
            key.key_id == key_id
                && key.role == "release-lab"
                && key.artifact_types.iter().any(|value| value == artifact)
                && key.rings.iter().any(|value| value == "lab")
                && key.hardware_targets.iter().any(|value| value == target)
                && key.authorizes_at(issued_at)
                && key.authorizes_at(now)
        })
        .collect();
    if matches.len() != 1 {
        return Err("release-lab key is not uniquely authorized for role/scope/time".into());
    }
    Ok(matches[0])
}

fn oci_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(sha256)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delegated::signing_bytes;

    /// The normative ICE-Fabric delegated-lab trio (from ICE-Fabric PR #688):
    /// a delegation snapshot carrying the `release-lab` authority, the lab
    /// release-authorization that authority signs, and the publication receipt
    /// bound to the exact bytes of that release. These bytes are authoritative
    /// — the lab verify path must canonicalize and sign over them exactly as the
    /// Fabric SIGN half shipped them, so the whole `run_lab` chain has a real
    /// end-to-end vector rather than a self-constructed one.
    const SNAPSHOT: &[u8] =
        include_bytes!("../../tests/fixtures/delegated-v1/lab-delegation-snapshot.json");
    const RELEASE: &[u8] =
        include_bytes!("../../tests/fixtures/delegated-v1/lab-release-authorization.json");
    const RECEIPT: &[u8] =
        include_bytes!("../../tests/fixtures/delegated-v1/lab-publication-receipt.json");

    const NOW: &str = "2026-07-22T04:00:00Z";
    const TARGET: &str = "nvidia-gb10-arm64";

    #[test]
    fn fabric_lab_receipt_bytes_are_pinned() {
        // Byte-coherence with the normative ICE-Fabric contract fixture (PR
        // #688, which re-linked the lab receipt onto the exact release-auth
        // bytes). The canonical hash and the signing digest below are the two
        // numbers a producer or a refactor cannot move without saying so — the
        // first is the receipt's own canonical hash, the second is the exact
        // message the delegated signature is made over (`neural-ice:<purpose>`
        // + NUL + canonical bytes without their transport LF).
        let receipt: LabReceipt = parse_canonical(RECEIPT, "fabric lab receipt").unwrap();
        assert_eq!(receipt.schema, "neural-ice-ota-lab-publication-receipt-v1");
        assert_eq!(receipt.signing_role, "release-lab");
        assert_eq!(receipt.ring, "lab");
        assert_eq!(
            canonical_hash(RECEIPT).unwrap(),
            "b9c8c3056c1844abaa5dc5319dbc32cd4a9aa2d48a91a217bb6100ad17b5bea0"
        );
        let domain = crate::namespace::domain(RECEIPT_DOMAIN_PURPOSE_LAB);
        let message = signing_bytes(&domain, RECEIPT).unwrap();
        let digest = crate::runner::sha256_bytes(&message).unwrap();
        assert_eq!(
            digest,
            "93dfeeb5b54b75544f98047c8d8a3bed2f772bff81a9ecb2e4b1bba69d9670e1"
        );
    }

    #[test]
    fn fabric_lab_vectors_bind_and_drift_refuses() {
        let snapshot: Snapshot = parse_canonical(SNAPSHOT, "snapshot").unwrap();
        let mut release: ReleaseAuthorization = parse_canonical(RELEASE, "release").unwrap();
        let mut receipt: LabReceipt = parse_canonical(RECEIPT, "receipt").unwrap();
        let snapshot_hash = canonical_hash(SNAPSHOT).unwrap();

        validate_release(&release, &snapshot, &snapshot_hash, NOW, TARGET).unwrap();
        validate_receipt(
            &receipt,
            &release,
            RELEASE,
            &snapshot,
            &snapshot_hash,
            NOW,
            TARGET,
        )
        .unwrap();

        // Receipt drift: a lab_variant that no longer matches the release.
        receipt.lab_variant = "prod".into();
        assert!(validate_receipt(
            &receipt,
            &release,
            RELEASE,
            &snapshot,
            &snapshot_hash,
            NOW,
            TARGET,
        )
        .is_err());
        receipt.lab_variant = "sealed-lab".into();

        // Receipt drift: posture restatement disagreeing with the release.
        receipt.access_policy_sha256 = "b".repeat(64);
        assert!(validate_receipt(
            &receipt,
            &release,
            RELEASE,
            &snapshot,
            &snapshot_hash,
            NOW,
            TARGET,
        )
        .is_err());
        receipt.access_policy_sha256 =
            "fe924b4b7650765bdd1f0f7b4f67ac411e2c9a66005eb18c591ba3a9e6601991".into();

        // Receipt drift: compat window no longer equal to the release's.
        receipt.compat_max += 1;
        assert!(validate_receipt(
            &receipt,
            &release,
            RELEASE,
            &snapshot,
            &snapshot_hash,
            NOW,
            TARGET,
        )
        .is_err());

        // Release drift: issued before the snapshot became live.
        release.issued_at = "2026-07-20T00:00:00Z".into();
        assert!(validate_release(&release, &snapshot, &snapshot_hash, NOW, TARGET).is_err());
    }

    #[test]
    fn lab_release_refuses_wrong_ring_role_and_beta_carveover() {
        let snapshot: Snapshot = parse_canonical(SNAPSHOT, "snapshot").unwrap();
        let snapshot_hash = canonical_hash(SNAPSHOT).unwrap();
        for case in ["ring", "role", "profile", "receipt-carveover", "variant"] {
            let mut json: serde_json::Value = serde_json::from_slice(RELEASE).unwrap();
            match case {
                "ring" => json["ring"] = "beta".into(),
                "role" => json["signing_role"] = "release-beta".into(),
                "profile" => json["access_profile"] = "customer-locked".into(),
                "receipt-carveover" => {
                    json["beta_publication_receipt_sha256"] = Some("a".repeat(64)).into()
                }
                "variant" => json["variant"] = "prod".into(),
                _ => unreachable!(),
            }
            let bytes = format!("{}\n", serde_json::to_string(&json).unwrap()).into_bytes();
            let hostile: ReleaseAuthorization = parse_canonical(&bytes, "release").unwrap();
            assert!(
                validate_release(&hostile, &snapshot, &snapshot_hash, NOW, TARGET).is_err(),
                "{case}"
            );
        }
    }

    #[test]
    fn beta_role_key_cannot_authorize_a_lab_artifact() {
        // The lab snapshot's release key is `release-lab`. A snapshot whose only
        // release key is `release-beta` must not satisfy a lab receipt, even
        // with a matching key_id — the role and ring are part of the filter.
        let mut value: serde_json::Value = serde_json::from_slice(SNAPSHOT).unwrap();
        let key = value["keys"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|key| key["key_id"] == "release-lab-v1")
            .unwrap();
        key["role"] = "release-beta".into();
        key["artifact_types"] =
            serde_json::json!(["beta-publication-receipt", "beta-release-authorization"]);
        key["rings"] = serde_json::json!(["beta"]);
        let snapshot: Snapshot = serde_json::from_value(value).unwrap();
        assert!(authorized_key(
            &snapshot,
            "release-lab-v1",
            "lab-publication-receipt",
            TARGET,
            NOW,
            NOW,
        )
        .is_err());
    }

    #[test]
    fn retiring_lab_key_cannot_authorize_after_its_bounded_overlap() {
        let mut value: serde_json::Value = serde_json::from_slice(SNAPSHOT).unwrap();
        let key = value["keys"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|key| key["key_id"] == "release-lab-v1")
            .unwrap();
        key["status"] = "retiring".into();
        key["rotation_overlap"] = serde_json::json!({
            "mode": "bounded",
            "with_key_id": "release-lab-v2",
            "valid_from": "2026-07-21T01:00:00Z",
            "valid_until": "2026-07-22T01:00:00Z"
        });
        let snapshot: Snapshot = serde_json::from_value(value).unwrap();
        assert!(authorized_key(
            &snapshot,
            "release-lab-v1",
            "lab-release-authorization",
            TARGET,
            "2026-07-22T01:00:00Z",
            "2026-07-22T01:00:00Z",
        )
        .is_err());
    }
}
