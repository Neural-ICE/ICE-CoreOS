//! The v2 release attestation (`docs/ota/V2-RELEASE-ATTESTATION.md`, mission B).
//!
//! An owner-sealed v2 host cannot carry the v1 preseal set: that set needs the
//! v1 OTA authority, which a v2 host forbids by design. The TPM floor of the v2
//! lane is therefore authenticated by the **v2 release manifest and its detached
//! signature**, and this module is the one place that decides it:
//!
//! * `verify-v2-release` — the installer, before any destructive write;
//! * `verify-retained-v2-release` — the ceremony, every boot and the status
//!   reader, against the persisted pair and receipt and the LIVE root.
//!
//! The signature is the pinned `cosign verify-blob` through `runner::verify_blob`
//! (one signature stack, as `delegated` and `preseal`), over the exact manifest
//! bytes: no envelope, no domain prefix, no canonicalisation, and no low-S or
//! minimal-DER pre-filter, because a KMS signature is not required to be either
//! (the committed golden signature is high-S). Digests are in-process `sha2`.
//! No clock is read anywhere.
//!
//! Every refusal names a class of the contract's closed set; the order of the
//! checks is the order of the contract, so the first failure is the refusal.

use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use serde::de::{Deserializer, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::state::{FileStateStore, O_NOFOLLOW};
use crate::{parse_flags, runner, InternalError, EXIT_PASS, EXIT_REFUSE};

const RECEIPT_SCHEMA: &str = "neural-ice-v2-release-receipt-v1";
const MANIFEST_SCHEMA: &str = "neural-ice-release-manifest-v1";
/// The marker of the v2 attestation lane (contract §1). The TPM objects and the
/// status `profile` keep the v1 name; only this image marker differs.
pub(crate) const LANE_MARKER: &str = "owner-sealed-ota-state-v2";
/// The closed set of appliance variants of this contract version.
const VARIANTS: [&str; 1] = ["sealed-lab"];
const MAX_MANIFEST: u64 = 1024 * 1024;
const MAX_SIGNATURE: u64 = 1024;
const MAX_KEY: u64 = 4 * 1024;
const MAX_RECEIPT: u64 = 4 * 1024;
const MAX_MARKER: u64 = 64;
const MAX_TOKEN: usize = 63;
const MAX_RELEASE_ID: usize = 128;
const MAX_REPOSITORY: usize = 255;
/// `2^53 - 1`: the bound `ota-tpm-state.sh` enforces on a floor.
const MAX_SEQ: u64 = 9_007_199_254_740_991;
const O_NONBLOCK: i32 = 0x800;

const MARKER_DIR: &str = "usr/lib/neural-ice";
const KEY_RELATIVE: &str = "usr/lib/neural-ice/keys/release-authorization.pub";
const FORBIDDEN_ANCHORS: [&str; 2] = [
    "etc/neural-ice/keys/ota-root.pub",
    "usr/lib/neural-ice/ota-bootstrap",
];

const FIRST_FLAGS: [&str; 17] = [
    "manifest",
    "manifest-sig",
    "release-key",
    "sealed-key-sha256",
    "sealed-manifest-sha256",
    "sealed-manifest-sig-sha256",
    "sealed-min-bundle-seq",
    "freshness",
    "freshness-sig",
    "hardware-target",
    "access-profile",
    "trust-policy-id",
    "variant",
    "release-authority",
    "candidate-root",
    "host-index-digest",
    "host-manifest-digest",
];

// ---------------------------------------------------------------------------
// Refusals
// ---------------------------------------------------------------------------

/// A verdict: the closed class of the contract and a free-text detail.
#[derive(Debug)]
pub(crate) struct Refusal {
    class: &'static str,
    detail: String,
}

impl Refusal {
    fn render(&self) -> String {
        format!("{}: {}", self.class, self.detail)
    }
}

fn refuse<T>(class: &'static str, detail: impl Into<String>) -> Result<T, Failure> {
    Err(Failure::Refused(Refusal {
        class,
        detail: detail.into(),
    }))
}

/// Either a verdict (exit 1) or a tooling failure (exit 2).
enum Failure {
    Refused(Refusal),
    Internal(InternalError),
}

impl From<InternalError> for Failure {
    fn from(error: InternalError) -> Self {
        Failure::Internal(error)
    }
}

type Check<T> = Result<T, Failure>;

// ---------------------------------------------------------------------------
// Receipt
// ---------------------------------------------------------------------------

/// Fields are declared in alphabetical order: `serde_json` writes a struct in
/// declaration order, so the output is the canonical (sorted, compact) form.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    access_profile: String,
    bundle_seq: u64,
    hardware_target: String,
    host_index_digest: String,
    host_manifest_digest: String,
    host_repository: String,
    manifest_sha256: String,
    manifest_sig_sha256: String,
    release_id: String,
    release_key_sha256: String,
    schema: String,
    seal: Seal,
    signed_boot_trust_policy_id: String,
    variant: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Seal {
    min_bundle_seq: Option<u64>,
    mode: String,
    sealed_manifest_sha256: Option<String>,
}

/// What a reader needs from a receipt that has been checked against the pair.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VerifiedV2Release {
    pub(crate) bundle_seq: u64,
    pub(crate) receipt_sha256: String,
    pub(crate) release_id: String,
    pub(crate) manifest_sha256: String,
    pub(crate) manifest_sig_sha256: String,
    pub(crate) release_key_sha256: String,
    /// The booted deployment the reader binds to (design P4): the image
    /// repository, its index digest and the platform child's digest.
    pub(crate) host_repository: String,
    pub(crate) host_index_digest: String,
    pub(crate) host_manifest_digest: String,
}

impl Receipt {
    fn bytes(&self) -> Result<Vec<u8>, InternalError> {
        let mut bytes = serde_json::to_vec(self)
            .map_err(|error| InternalError(format!("cannot serialize the v2 receipt: {error}")))?;
        bytes.push(b'\n');
        if bytes.len() as u64 > MAX_RECEIPT {
            return Err(InternalError("the v2 receipt exceeds its bound".into()));
        }
        Ok(bytes)
    }

    /// The shape the contract gives a receipt, whatever wrote it.
    fn validate(&self) -> Result<(), String> {
        if self.schema != RECEIPT_SCHEMA {
            return Err("schema is not neural-ice-v2-release-receipt-v1".into());
        }
        if !safe_seq(self.bundle_seq) {
            return Err("bundle_seq is outside 1..=2^53-1".into());
        }
        if !release_id(&self.release_id) {
            return Err("release_id is malformed".into());
        }
        if !repository(&self.host_repository) {
            return Err("host_repository is malformed".into());
        }
        for (name, value) in [
            ("access_profile", &self.access_profile),
            ("hardware_target", &self.hardware_target),
            (
                "signed_boot_trust_policy_id",
                &self.signed_boot_trust_policy_id,
            ),
            ("variant", &self.variant),
        ] {
            if !token(value) {
                return Err(format!("{name} is malformed"));
            }
        }
        if !VARIANTS.contains(&self.variant.as_str()) {
            return Err("variant is not in the closed set".into());
        }
        for (name, value) in [
            ("host_index_digest", &self.host_index_digest),
            ("host_manifest_digest", &self.host_manifest_digest),
        ] {
            if !digest_ref(value) {
                return Err(format!("{name} is not sha256:<64 lowercase hex>"));
            }
        }
        for (name, value) in [
            ("manifest_sha256", &self.manifest_sha256),
            ("manifest_sig_sha256", &self.manifest_sig_sha256),
            ("release_key_sha256", &self.release_key_sha256),
        ] {
            if !hex64(value) {
                return Err(format!("{name} is not 64 lowercase hex"));
            }
        }
        match (
            self.seal.mode.as_str(),
            &self.seal.sealed_manifest_sha256,
            self.seal.min_bundle_seq,
        ) {
            ("manifest-digest", Some(sealed), None) if hex64(sealed) => {}
            ("floor", None, Some(minimum)) if safe_seq(minimum) => {}
            _ => return Err("seal is not exactly one well-formed mode".into()),
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Verbs
// ---------------------------------------------------------------------------

pub(crate) fn run(args: &[String]) -> Result<u8, InternalError> {
    let flags = parse_flags(
        args,
        &[FIRST_FLAGS.as_slice(), ["receipt"].as_slice()].concat(),
    )?;
    let required = |name: &str| {
        flags
            .get(name)
            .map(String::as_str)
            .ok_or_else(|| InternalError(format!("verify-v2-release: --{name} is required")))
    };
    // Usage first: a missing flag is a usage error whichever seal mode is meant.
    for name in [
        "manifest",
        "manifest-sig",
        "release-key",
        "sealed-key-sha256",
        "hardware-target",
        "access-profile",
        "trust-policy-id",
        "variant",
        "release-authority",
        "candidate-root",
        "host-index-digest",
        "host-manifest-digest",
        "receipt",
    ] {
        required(name)?;
    }
    let optional = |name: &str| flags.get(name).map(String::as_str);
    let inputs = InitialInputs {
        manifest: Path::new(required("manifest")?),
        manifest_sig: Path::new(required("manifest-sig")?),
        release_key: Path::new(required("release-key")?),
        sealed_key_sha256: required("sealed-key-sha256")?,
        sealed_manifest_sha256: optional("sealed-manifest-sha256"),
        sealed_manifest_sig_sha256: optional("sealed-manifest-sig-sha256"),
        sealed_min_bundle_seq: optional("sealed-min-bundle-seq"),
        freshness: optional("freshness").is_some() || optional("freshness-sig").is_some(),
        hardware_target: required("hardware-target")?,
        access_profile: required("access-profile")?,
        trust_policy_id: required("trust-policy-id")?,
        variant: required("variant")?,
        release_authority: required("release-authority")?,
        candidate_root: Path::new(required("candidate-root")?),
        host_index_digest: required("host-index-digest")?,
        host_manifest_digest: required("host-manifest-digest")?,
        receipt: Path::new(required("receipt")?),
    };
    match verify_initial(&inputs) {
        Ok((receipt_sha256, bundle_seq, created)) => {
            println!(
                "{{\"bundle_seq\":{bundle_seq},\"idempotent\":{},\"receipt_sha256\":\"{receipt_sha256}\",\"verdict\":\"pass\"}}",
                if created { "false" } else { "true" }
            );
            Ok(EXIT_PASS)
        }
        Err(Failure::Refused(refusal)) => Ok(report(&refusal)),
        Err(Failure::Internal(error)) => Err(error),
    }
}

pub(crate) fn run_retained(args: &[String]) -> Result<u8, InternalError> {
    #[cfg(feature = "test-path-overrides")]
    let allowed: &[&str] = &[
        "manifest",
        "manifest-sig",
        "release-key",
        "expected-receipt-sha256",
        "receipt",
        "scratch-dir",
        "root",
    ];
    #[cfg(not(feature = "test-path-overrides"))]
    let allowed: &[&str] = &[
        "manifest",
        "manifest-sig",
        "release-key",
        "expected-receipt-sha256",
        "receipt",
        "scratch-dir",
    ];
    let flags = parse_flags(args, allowed)?;
    let required = |name: &str| {
        flags.get(name).map(String::as_str).ok_or_else(|| {
            InternalError(format!("verify-retained-v2-release: --{name} is required"))
        })
    };
    #[cfg(feature = "test-path-overrides")]
    let root = PathBuf::from(flags.get("root").map_or("/", String::as_str));
    #[cfg(not(feature = "test-path-overrides"))]
    let root = PathBuf::from("/");
    let paths = RetainedPaths {
        manifest: Path::new(required("manifest")?),
        manifest_sig: Path::new(required("manifest-sig")?),
        release_key: Path::new(required("release-key")?),
        receipt: Path::new(required("receipt")?),
        scratch_dir: Path::new(required("scratch-dir")?),
        expected_receipt_sha256: required("expected-receipt-sha256")?,
        root: &root,
    };
    match verify_retained(&paths)? {
        Ok(verified) => {
            println!(
                "{{\"bundle_seq\":{},\"receipt_sha256\":\"{}\",\"verdict\":\"pass\"}}",
                verified.bundle_seq, verified.receipt_sha256
            );
            Ok(EXIT_PASS)
        }
        Err(refusal) => {
            eprintln!("ni-ota-verify: v2 release REFUSED: {refusal}");
            Ok(EXIT_REFUSE)
        }
    }
}

fn report(refusal: &Refusal) -> u8 {
    eprintln!("ni-ota-verify: v2 release REFUSED: {}", refusal.render());
    EXIT_REFUSE
}

// ---------------------------------------------------------------------------
// verify-v2-release
// ---------------------------------------------------------------------------

struct InitialInputs<'a> {
    manifest: &'a Path,
    manifest_sig: &'a Path,
    release_key: &'a Path,
    sealed_key_sha256: &'a str,
    sealed_manifest_sha256: Option<&'a str>,
    sealed_manifest_sig_sha256: Option<&'a str>,
    sealed_min_bundle_seq: Option<&'a str>,
    freshness: bool,
    hardware_target: &'a str,
    access_profile: &'a str,
    trust_policy_id: &'a str,
    variant: &'a str,
    release_authority: &'a str,
    candidate_root: &'a Path,
    host_index_digest: &'a str,
    host_manifest_digest: &'a str,
    receipt: &'a Path,
}

enum SealMode<'a> {
    ManifestDigest {
        manifest: &'a str,
        signature: &'a str,
    },
    Floor {
        minimum: &'a str,
    },
}

/// Returns `(receipt sha256, bundle_seq, created)`.
fn verify_initial(inputs: &InitialInputs<'_>) -> Check<(String, u64, bool)> {
    // 1. mode
    let mode = match (
        inputs.sealed_manifest_sha256,
        inputs.sealed_manifest_sig_sha256,
        inputs.sealed_min_bundle_seq,
    ) {
        (Some(manifest), Some(signature), None) => SealMode::ManifestDigest { manifest, signature },
        (None, None, Some(minimum)) => SealMode::Floor { minimum },
        _ => {
            return refuse(
                "mode",
                "exactly one seal mode is required: the sealed manifest and signature digests, or a minimum bundle_seq",
            )
        }
    };
    // 2. freshness is reserved: its schema is T7 / OS-0044 work.
    if inputs.freshness {
        return refuse(
            "freshness-unsupported",
            "--freshness and --freshness-sig are reserved in this contract version",
        );
    }

    let receipt_store = FileStateStore {
        path: inputs.receipt.to_path_buf(),
    };
    if let Err(reason) = receipt_store.validate_bootstrap_parent() {
        return refuse("receipt-conflict", reason);
    }

    // 3. key-digest
    let key = snapshot(
        &receipt_store,
        inputs.release_key,
        "release key",
        MAX_KEY,
        "key-digest",
    )?;
    let key_bytes = key.read()?;
    let key_sha256 = sha256_hex(&key_bytes);
    if !hex64(inputs.sealed_key_sha256) || key_sha256 != inputs.sealed_key_sha256 {
        return refuse("key-digest", "the release key is not the sealed one");
    }
    // 4. manifest-digest / sig-digest
    let manifest = snapshot(
        &receipt_store,
        inputs.manifest,
        "manifest",
        MAX_MANIFEST + 1,
        "manifest-digest",
    )?;
    let signature = snapshot(
        &receipt_store,
        inputs.manifest_sig,
        "manifest signature",
        MAX_SIGNATURE,
        "sig-digest",
    )?;
    let manifest_bytes = manifest.read()?;
    let signature_bytes = signature.read()?;
    let manifest_sha256 = sha256_hex(&manifest_bytes);
    let manifest_sig_sha256 = sha256_hex(&signature_bytes);
    if let SealMode::ManifestDigest {
        manifest: sealed_manifest,
        signature: sealed_signature,
    } = &mode
    {
        if !hex64(sealed_manifest) || manifest_sha256 != *sealed_manifest {
            return refuse(
                "manifest-digest",
                "the manifest differs from the sealed digest",
            );
        }
        if !hex64(sealed_signature) || manifest_sig_sha256 != *sealed_signature {
            return refuse(
                "sig-digest",
                "the manifest signature differs from the sealed digest",
            );
        }
    }
    // 5. signature, over the exact bytes of the manifest we hashed.
    verify_signature(&key, &signature, &manifest)?;
    // 6-8. strict JSON, schema, bundle_seq
    let parsed = parse_manifest(&manifest_bytes)?;
    // 9. min-bundle-seq
    let seal = match &mode {
        SealMode::ManifestDigest { manifest, .. } => Seal {
            min_bundle_seq: None,
            mode: "manifest-digest".into(),
            sealed_manifest_sha256: Some((*manifest).to_owned()),
        },
        SealMode::Floor { minimum } => {
            let Some(floor) = decimal(minimum).filter(|value| safe_seq(*value)) else {
                return refuse(
                    "min-bundle-seq",
                    "the sealed minimum is not an integer in 1..=2^53-1",
                );
            };
            if parsed.bundle_seq < floor {
                return refuse(
                    "min-bundle-seq",
                    format!(
                        "bundle_seq {} is below the sealed minimum {floor}",
                        parsed.bundle_seq
                    ),
                );
            }
            Seal {
                min_bundle_seq: Some(floor),
                mode: "floor".into(),
                sealed_manifest_sha256: None,
            }
        }
    };
    // 10. hardware-target
    if !token(inputs.hardware_target)
        || parsed.hardware_target.as_deref() != Some(inputs.hardware_target)
    {
        return refuse(
            "hardware-target",
            "the manifest names another hardware target",
        );
    }
    // 11. authority
    if !authority(inputs.release_authority)
        || authority_of(&parsed.host_repository) != inputs.release_authority
    {
        return refuse(
            "authority",
            "the host repository is not under the sealed release authority",
        );
    }
    // 12. host-digest
    if !digest_ref(inputs.host_index_digest) || parsed.host_digest != inputs.host_index_digest {
        return refuse(
            "host-digest",
            "the manifest host digest is not the observed host index digest",
        );
    }
    if !digest_ref(inputs.host_manifest_digest) {
        return refuse(
            "host-digest",
            "the platform manifest digest is not sha256:<64 lowercase hex>",
        );
    }
    // 13-15. the candidate root
    check_root(
        inputs.candidate_root,
        &Sealed {
            hardware_target: inputs.hardware_target,
            variant: inputs.variant,
            trust_policy_id: inputs.trust_policy_id,
            access_profile: inputs.access_profile,
        },
        &key_sha256,
    )?;

    let receipt = Receipt {
        access_profile: inputs.access_profile.to_owned(),
        bundle_seq: parsed.bundle_seq,
        hardware_target: inputs.hardware_target.to_owned(),
        host_index_digest: parsed.host_digest.clone(),
        host_manifest_digest: inputs.host_manifest_digest.to_owned(),
        host_repository: parsed.host_repository.clone(),
        manifest_sha256,
        manifest_sig_sha256,
        release_id: parsed.release_id.clone(),
        release_key_sha256: key_sha256,
        schema: RECEIPT_SCHEMA.into(),
        seal,
        signed_boot_trust_policy_id: inputs.trust_policy_id.to_owned(),
        variant: inputs.variant.to_owned(),
    };
    receipt
        .validate()
        .or_else(|reason| refuse("schema", reason))?;
    let bytes = receipt.bytes()?;
    // 16. receipt-conflict
    let created = publish_receipt(&receipt_store, &bytes)?;
    Ok((sha256_hex(&bytes), receipt.bundle_seq, created))
}

// ---------------------------------------------------------------------------
// verify-retained-v2-release
// ---------------------------------------------------------------------------

pub(crate) struct RetainedPaths<'a> {
    pub(crate) manifest: &'a Path,
    pub(crate) manifest_sig: &'a Path,
    pub(crate) release_key: &'a Path,
    pub(crate) receipt: &'a Path,
    pub(crate) scratch_dir: &'a Path,
    pub(crate) expected_receipt_sha256: &'a str,
    /// The live root `/`; a directory only under `test-path-overrides`.
    pub(crate) root: &'a Path,
}

/// Re-verify the persisted pair and receipt against the live root. `Ok(Err(_))`
/// is a verdict (`class: detail`), `Err` a tooling failure.
pub(crate) fn verify_retained(
    paths: &RetainedPaths<'_>,
) -> Result<Result<VerifiedV2Release, String>, InternalError> {
    match retained(paths) {
        Ok(verified) => Ok(Ok(verified)),
        Err(Failure::Refused(refusal)) => Ok(Err(refusal.render())),
        Err(Failure::Internal(error)) => Err(error),
    }
}

fn retained(paths: &RetainedPaths<'_>) -> Check<VerifiedV2Release> {
    let scratch = paths.scratch_dir;
    if !scratch.is_absolute()
        || scratch.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    {
        return Err(Failure::Internal(InternalError(
            "the retained v2 scratch directory is not a canonical absolute path".into(),
        )));
    }
    #[cfg(not(feature = "test-path-overrides"))]
    if !scratch.starts_with("/run") {
        return Err(Failure::Internal(InternalError(
            "the retained v2 scratch directory must be beneath /run".into(),
        )));
    }
    let store = FileStateStore {
        path: scratch.join("v2-release-retained-operation"),
    };
    if let Err(reason) = store.validate_bootstrap_parent() {
        return Err(Failure::Internal(InternalError(format!(
            "the retained v2 scratch directory is not private: {reason}"
        ))));
    }

    let receipt_file = snapshot(
        &store,
        paths.receipt,
        "receipt",
        MAX_RECEIPT,
        "receipt-digest",
    )?;
    let receipt_bytes = receipt_file.read()?;
    let receipt_sha256 = sha256_hex(&receipt_bytes);
    if !hex64(paths.expected_receipt_sha256) || receipt_sha256 != paths.expected_receipt_sha256 {
        return refuse(
            "receipt-digest",
            "the receipt is not the one the completion evidence binds",
        );
    }
    let receipt = parse_receipt(&receipt_bytes)?;
    let key = snapshot(
        &store,
        paths.release_key,
        "release key",
        MAX_KEY,
        "key-digest",
    )?;
    let manifest = snapshot(
        &store,
        paths.manifest,
        "manifest",
        MAX_MANIFEST + 1,
        "manifest-digest",
    )?;
    let signature = snapshot(
        &store,
        paths.manifest_sig,
        "manifest signature",
        MAX_SIGNATURE,
        "sig-digest",
    )?;
    let key_bytes = key.read()?;
    let manifest_bytes = manifest.read()?;
    let signature_bytes = signature.read()?;

    if sha256_hex(&key_bytes) != receipt.release_key_sha256 {
        return refuse(
            "key-digest",
            "the release key is not the one the receipt records",
        );
    }
    if sha256_hex(&manifest_bytes) != receipt.manifest_sha256 {
        return refuse(
            "manifest-digest",
            "the persisted manifest is not the one the receipt records",
        );
    }
    if sha256_hex(&signature_bytes) != receipt.manifest_sig_sha256 {
        return refuse(
            "sig-digest",
            "the persisted signature is not the one the receipt records",
        );
    }
    if receipt.seal.mode == "manifest-digest"
        && receipt.seal.sealed_manifest_sha256.as_deref() != Some(receipt.manifest_sha256.as_str())
    {
        return refuse(
            "receipt-malformed",
            "the sealed manifest digest is not the manifest digest",
        );
    }
    verify_signature(&key, &signature, &manifest)?;
    let parsed = parse_manifest(&manifest_bytes)?;
    if parsed.bundle_seq != receipt.bundle_seq {
        return refuse("bundle-seq", "the manifest bundle_seq is not the receipt's");
    }
    if let Some(minimum) = receipt.seal.min_bundle_seq {
        if receipt.bundle_seq < minimum {
            return refuse(
                "min-bundle-seq",
                "the receipt bundle_seq is below its sealed minimum",
            );
        }
    }
    if parsed.release_id != receipt.release_id {
        return refuse("schema", "the manifest release_id is not the receipt's");
    }
    if parsed.hardware_target.as_deref() != Some(receipt.hardware_target.as_str()) {
        return refuse(
            "hardware-target",
            "the manifest hardware target is not the receipt's",
        );
    }
    if parsed.host_repository != receipt.host_repository
        || authority_of(&parsed.host_repository) != authority_of(&receipt.host_repository)
    {
        return refuse(
            "authority",
            "the manifest host repository is not the receipt's",
        );
    }
    if parsed.host_digest != receipt.host_index_digest {
        return refuse(
            "host-digest",
            "the manifest host digest is not the receipt's",
        );
    }
    check_root(
        paths.root,
        &Sealed {
            hardware_target: &receipt.hardware_target,
            variant: &receipt.variant,
            trust_policy_id: &receipt.signed_boot_trust_policy_id,
            access_profile: &receipt.access_profile,
        },
        &receipt.release_key_sha256,
    )?;
    Ok(VerifiedV2Release {
        bundle_seq: receipt.bundle_seq,
        receipt_sha256,
        release_id: receipt.release_id,
        manifest_sha256: receipt.manifest_sha256,
        manifest_sig_sha256: receipt.manifest_sig_sha256,
        release_key_sha256: receipt.release_key_sha256,
        host_repository: receipt.host_repository,
        host_index_digest: receipt.host_index_digest,
        host_manifest_digest: receipt.host_manifest_digest,
    })
}

/// A receipt is canonical bytes: it must re-serialize to exactly itself, which
/// also rejects an unknown key, a reordering, a float and a missing LF.
fn parse_receipt(bytes: &[u8]) -> Check<Receipt> {
    let malformed = |detail: String| -> Check<Receipt> { refuse("receipt-malformed", detail) };
    if bytes.last() != Some(&b'\n') || bytes[..bytes.len() - 1].contains(&b'\n') {
        return malformed("the receipt is not one line plus a final LF".into());
    }
    let receipt: Receipt = match serde_json::from_slice(&bytes[..bytes.len() - 1]) {
        Ok(value) => value,
        Err(error) => return malformed(format!("the receipt does not parse: {error}")),
    };
    if let Err(reason) = receipt.validate() {
        return malformed(reason);
    }
    if receipt.bytes()? != bytes {
        return malformed("the receipt is not canonical compact sorted JSON".into());
    }
    Ok(receipt)
}

// ---------------------------------------------------------------------------
// Shared checks
// ---------------------------------------------------------------------------

fn verify_signature(
    key: &crate::state::SecureTempFile,
    signature: &crate::state::SecureTempFile,
    manifest: &crate::state::SecureTempFile,
) -> Check<()> {
    let cosign = runner::cosign_path()?;
    match runner::verify_blob(&cosign, key.path(), signature.path(), manifest.path())? {
        Ok(()) => Ok(()),
        Err(detail) => refuse("signature", detail),
    }
}

struct ParsedManifest {
    bundle_seq: u64,
    release_id: String,
    hardware_target: Option<String>,
    host_repository: String,
    host_digest: String,
}

/// Rules 6-8 of the contract. The fields compared with the sealed values (rules
/// 10-12) are extracted here but judged by their own rule, in their own order.
fn parse_manifest(bytes: &[u8]) -> Check<ParsedManifest> {
    if bytes.len() as u64 > MAX_MANIFEST {
        return refuse("duplicate-key", "the manifest exceeds 1 MiB");
    }
    let value = match serde_json::from_slice::<Strict>(bytes) {
        Ok(Strict(value)) => value,
        Err(error) => {
            return refuse(
                "duplicate-key",
                format!("the manifest is not strict JSON: {error}"),
            )
        }
    };
    let Some(object) = value.as_object() else {
        return refuse("schema", "the manifest is not a JSON object");
    };
    if object.get("schema").and_then(Value::as_str) != Some(MANIFEST_SCHEMA) {
        return refuse(
            "schema",
            "the manifest schema is not neural-ice-release-manifest-v1",
        );
    }
    let Some(release) = object
        .get("release_id")
        .and_then(Value::as_str)
        .filter(|id| release_id(id))
    else {
        return refuse("schema", "release_id is missing or malformed");
    };
    let Some(bundle_seq) = object
        .get("bundle_seq")
        .and_then(Value::as_u64)
        .filter(|seq| safe_seq(*seq))
    else {
        return refuse("bundle-seq", "bundle_seq is not an integer in 1..=2^53-1");
    };
    let host = object.get("host").and_then(Value::as_object);
    Ok(ParsedManifest {
        bundle_seq,
        release_id: release.to_owned(),
        hardware_target: object
            .get("hardware_target")
            .and_then(Value::as_str)
            .map(str::to_owned),
        host_repository: host
            .and_then(|host| host.get("repository"))
            .and_then(Value::as_str)
            .filter(|repository| repository_ok(repository))
            .unwrap_or_default()
            .to_owned(),
        host_digest: host
            .and_then(|host| host.get("digest"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
    })
}

/// A JSON value that refuses a duplicated object key at any depth. `serde_json`
/// keeps the last of two equal keys, which would let a producer show one manifest
/// to a reviewer and another to the device under one signature.
struct Strict(Value);

impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Walk;
        impl<'de> Visitor<'de> for Walk {
            type Value = Strict;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a JSON value")
            }
            fn visit_bool<E>(self, value: bool) -> Result<Strict, E> {
                Ok(Strict(Value::Bool(value)))
            }
            fn visit_i64<E>(self, value: i64) -> Result<Strict, E> {
                Ok(Strict(Value::from(value)))
            }
            fn visit_u64<E>(self, value: u64) -> Result<Strict, E> {
                Ok(Strict(Value::from(value)))
            }
            fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Strict, E> {
                serde_json::Number::from_f64(value)
                    .map(|number| Strict(Value::Number(number)))
                    .ok_or_else(|| E::custom("non-finite number"))
            }
            fn visit_str<E>(self, value: &str) -> Result<Strict, E> {
                Ok(Strict(Value::String(value.to_owned())))
            }
            fn visit_unit<E>(self) -> Result<Strict, E> {
                Ok(Strict(Value::Null))
            }
            fn visit_none<E>(self) -> Result<Strict, E> {
                Ok(Strict(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Strict, A::Error> {
                let mut items = Vec::new();
                while let Some(Strict(item)) = seq.next_element()? {
                    items.push(item);
                }
                Ok(Strict(Value::Array(items)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Strict, A::Error> {
                let mut object = serde_json::Map::new();
                while let Some((key, Strict(value))) = map.next_entry::<String, Strict>()? {
                    if object.contains_key(&key) {
                        return Err(serde::de::Error::custom(format!(
                            "duplicate JSON object key: {key}"
                        )));
                    }
                    object.insert(key, value);
                }
                Ok(Strict(Value::Object(object)))
            }
        }
        deserializer.deserialize_any(Walk)
    }
}

struct Sealed<'a> {
    hardware_target: &'a str,
    variant: &'a str,
    trust_policy_id: &'a str,
    access_profile: &'a str,
}

/// Rules 13-15 against a root, read without executing anything in it.
fn check_root(root: &Path, sealed: &Sealed<'_>, sealed_key_sha256: &str) -> Check<()> {
    if !VARIANTS.contains(&sealed.variant) {
        return refuse("candidate-marker", "the variant is not in the closed set");
    }
    for (name, expected) in [
        ("hardware-target", sealed.hardware_target),
        ("appliance-variant", sealed.variant),
        ("signed-boot-trust-policy-id", sealed.trust_policy_id),
        ("access-policy", sealed.access_profile),
        ("ota-state-profile", LANE_MARKER),
    ] {
        if !token(expected) {
            return refuse(
                "candidate-marker",
                format!("the sealed value for {name} is malformed"),
            );
        }
        let relative = format!("{MARKER_DIR}/{name}");
        let value = match read_marker(root, &relative) {
            Ok(value) => value,
            Err(reason) => return refuse("candidate-marker", reason),
        };
        if value != expected {
            return refuse(
                "candidate-marker",
                format!("{relative} differs from the sealed value"),
            );
        }
    }
    let key = match read_regular(&root.join(KEY_RELATIVE), MAX_KEY) {
        Ok(bytes) => bytes,
        Err(reason) => return refuse("candidate-key", reason),
    };
    if sha256_hex(&key) != sealed_key_sha256 {
        return refuse(
            "candidate-key",
            "the candidate release key is not the sealed key",
        );
    }
    for relative in FORBIDDEN_ANCHORS {
        match std::fs::symlink_metadata(root.join(relative)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) => {
                return refuse(
                    "candidate-anchor",
                    format!("{relative} exists: a v2 host forbids the v1 OTA anchors"),
                )
            }
            Err(error) => {
                return refuse(
                    "candidate-anchor",
                    format!("cannot prove {relative} absent: {error}"),
                )
            }
        }
    }
    Ok(())
}

/// One regular, non-symlink, stable file of at most `maximum` bytes. A FIFO or
/// device is refused on its metadata before it is ever opened.
fn read_regular(path: &Path, maximum: u64) -> Result<Vec<u8>, String> {
    let named = std::fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
    if !named.file_type().is_file() || named.len() == 0 || named.len() > maximum {
        return Err(format!(
            "{} is not a non-empty regular non-symlink file of at most {maximum} bytes",
            path.display()
        ));
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NONBLOCK | O_NOFOLLOW)
        .open(path)
        .map_err(|error| format!("cannot open {}: {error}", path.display()))?;
    let opened = file
        .metadata()
        .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
    let named_again = std::fs::symlink_metadata(path)
        .map_err(|error| format!("cannot re-inspect {}: {error}", path.display()))?;
    if !opened.file_type().is_file()
        || !named_again.file_type().is_file()
        || opened.dev() != named_again.dev()
        || opened.ino() != named_again.ino()
    {
        return Err(format!("{} is not a stable regular file", path.display()));
    }
    let mut bytes = Vec::new();
    file.take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    if bytes.is_empty() || bytes.len() as u64 > maximum {
        return Err(format!("{} exceeds its read bound", path.display()));
    }
    Ok(bytes)
}

/// A marker: at most 64 bytes, UTF-8, exactly one line plus its LF.
fn read_marker(root: &Path, relative: &str) -> Result<String, String> {
    let bytes = read_regular(&root.join(relative), MAX_MARKER)?;
    let value = String::from_utf8(bytes).map_err(|_| format!("{relative} is not UTF-8"))?;
    match value.strip_suffix('\n') {
        Some(line) if !line.is_empty() && !line.contains('\n') => Ok(line.to_owned()),
        _ => Err(format!("{relative} is not one line plus LF")),
    }
}

/// Freeze a caller-supplied file into a private temp inode and verify, parse and
/// hash THAT, never the source again. `class` names the refusal for a file that
/// is absent, not regular or out of bounds.
fn snapshot(
    store: &FileStateStore,
    source: &Path,
    label: &str,
    maximum: u64,
    class: &'static str,
) -> Check<crate::state::SecureTempFile> {
    match crate::preseal::snapshot(store, source, label, maximum)? {
        Ok(file) => Ok(file),
        Err(reason) => refuse(class, reason),
    }
}

/// Create-if-absent by hard link of a private staged file, then sync the
/// directory; an existing receipt must be byte-equal. Returns whether this call
/// created it.
fn publish_receipt(store: &FileStateStore, expected: &[u8]) -> Check<bool> {
    match store.validate_bootstrap_state() {
        Ok(true) => {
            compare_receipt(store, expected)?;
            return Ok(false);
        }
        Ok(false) => {}
        Err(reason) => return refuse("receipt-conflict", reason),
    }
    let parent = store
        .path
        .parent()
        .ok_or_else(|| InternalError("the receipt has no parent directory".into()))?;
    let staged = store.secure_temp_bytes("v2-release-receipt", expected)?;
    let created = match std::fs::hard_link(staged.path(), &store.path) {
        Ok(()) => true,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(error) => {
            return Err(Failure::Internal(InternalError(format!(
                "cannot atomically publish the v2 receipt: {error}"
            ))))
        }
    };
    if created {
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| {
                InternalError(format!("cannot sync the v2 receipt directory: {error}"))
            })?;
    }
    compare_receipt(store, expected)?;
    Ok(created)
}

fn compare_receipt(store: &FileStateStore, expected: &[u8]) -> Check<()> {
    if let Err(reason) = store.validate_bootstrap_state() {
        return refuse("receipt-conflict", reason);
    }
    let file = match File::open(&store.path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return refuse("receipt-conflict", "the receipt is missing");
        }
        Err(error) => {
            return Err(Failure::Internal(InternalError(format!(
                "cannot read the v2 receipt: {error}"
            ))))
        }
    };
    let mut actual = Vec::new();
    file.take(MAX_RECEIPT + 1)
        .read_to_end(&mut actual)
        .map_err(|error| InternalError(format!("cannot read the v2 receipt: {error}")))?;
    if actual != expected {
        return refuse(
            "receipt-conflict",
            "an existing receipt differs from the authenticated one",
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Shapes
// ---------------------------------------------------------------------------

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn digest_ref(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(hex64)
}

fn safe_seq(value: u64) -> bool {
    (1..=MAX_SEQ).contains(&value)
}

/// A canonical decimal: no sign, no leading zero, no whitespace.
fn decimal(value: &str) -> Option<u64> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    value.parse().ok()
}

fn token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_TOKEN
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn release_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_RELEASE_ID
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn authority(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_REPOSITORY
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':'))
}

fn authority_of(repository: &str) -> &str {
    repository.split('/').next().unwrap_or_default()
}

fn repository_ok(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_REPOSITORY
        && value.bytes().all(|b| b.is_ascii_graphic())
        && authority(authority_of(value))
}

fn repository(value: &str) -> bool {
    repository_ok(value)
}
