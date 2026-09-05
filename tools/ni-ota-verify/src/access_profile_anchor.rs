//! The install-time ACCESS-PROFILE ANCHOR, as the OTA path reads it.
//!
//! Why this exists (DESIGN-NOTE-0001, Finding 3). Every delegated path already
//! refuses a release whose `variant` differs from the host's immutable
//! `/usr/lib/neural-ice/appliance-variant`. ADR-0014's continuity argument then
//! leans on a third premise -- "the variant -> policy mapping is a total
//! function, so equal variants imply an equal access policy". That premise is a
//! property of the SOURCE TREE (`image/lib/access-policy.sh`), not of anything
//! signed. A later, correctly signed, SAME-VARIANT release can rewrite that
//! mapping, or the marker itself, and the appliance's access posture changes
//! with no signature ever having stated the old one. The binding is *variant*;
//! the thing that must be immutable is *profile*.
//!
//! So the profile is enrolled at install time into the STATEROOT -- outside the
//! candidate deployment, so a deployment cannot restate its own authority -- and
//! signed by the non-exportable device root at 0x81010005 (ADR-0013). This
//! module reads that bundle, proves it belongs to THIS machine's device root,
//! and hands the caller the one word every delegated path must compare against.
//!
//! Every failure here is a REFUSAL, never a repair, and the operator-facing
//! words are always "reinstall required". Deliberately not "re-enrol": a profile
//! change is a change of what the appliance IS, and the only honest path back is
//! signed physical media (ADR-0014).
//!
//! # The live TPM, and why a file comparison was not machine binding
//!
//! An earlier revision compared the anchor against an adjacent
//! `device-root-v1.json` and then verified it with an adjacent `.spki`. Every
//! one of those artefacts sits in `/var`, so a COHERENT BUNDLE COPIED FROM
//! ANOTHER APPLIANCE — identity, anchor, signature and key together — satisfied
//! all of them. The comment said the identity file "is re-attested against the
//! live TPM on every boot", but that service is only `WantedBy=`, is not
//! required by this verifier, and is skipped outright when the TPM is absent. A
//! premise nothing enforces is not a premise.
//!
//! So this module now talks to the TPM itself, and does it in the one way a copy
//! cannot survive: it makes the device root PROVE POSSESSION. A fresh 32-byte
//! nonce from `/dev/urandom` is signed by the key at 0x81010005 and the
//! signature is verified against the key the anchor names. A private key that
//! never leaves the TPM cannot produce that signature on a second machine, and a
//! recorded one is useless because the nonce is new every time.
//!
//! It also reads the machine's monotonic install counter out of TPM NV and
//! requires `anchor_seq` to BE that value. `anchor_seq` used to be validated and
//! then discarded here, while the installer wrote the literal `1`, so an
//! authentic anchor from a previous installation of this same machine replayed
//! perfectly.
//!
//! # Why the device-root signature is no longer the profile's authority
//!
//! (Review 2026-09-01, P1 #3.) The device root at 0x81010005 is a TPM key with
//! `userwithauth` and an EMPTY authorization policy, persisted under the owner
//! hierarchy with no authentication secret. Anything running as root on the
//! appliance can therefore make it sign -- including a REPLACEMENT anchor
//! carrying a different access profile, at the current install-counter value.
//! The liveness challenge below does not help with that: it proves the key is
//! present and usable on this machine, which is exactly what the attacker also
//! enjoys.
//!
//! So the profile is bound to a WRITE-ONCE, POLICY-PROTECTED TPM NV RECORD
//! (`ota/neural-ice-tpm-state.sh`, index 0x01500005): `policywrite` with no
//! `ownerwrite` and no `authwrite`, under a PolicyOR that permits exactly
//! NV_Write and NV_WriteLock, and `writedefine` so the lock the installer
//! applies is permanent for the life of the index. This module requires the
//! anchor's (profile, hardware target, trust policy) triple to hash to what that
//! record holds. A device-root-signed replacement anchor with a different
//! profile now fails here, because the attacker cannot rewrite the record.
//!
//! Division of labour, said plainly: the NV record is the AUTHORITY, the device
//! root proves DEVICE BINDING and LIVENESS, and the install counter proves this
//! is not a replay of an earlier installation. `docs/ADR-0015` records the one
//! residual -- owner-hierarchy `NV_UndefineSpace` -- and the physical recovery
//! (a TPM clear at the firmware setup screen, then a reinstall from signed
//! media) that a legitimate profile change requires.
//!
//! Absence fails closed at every step. No TPM, no tools, no counter, an
//! unreadable index — all refusals. This module exists to remove the branch
//! where "there is no evidence" meant "carry on".

use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use p256::elliptic_curve::ff::PrimeField;
use p256::Scalar;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::delegated::{contract::validate_der_signature, verify_signature};
use crate::state::FileStateStore;
use crate::{runner, InternalError};

/// Must equal `ANCHOR_DOMAIN` in `ota/neural-ice-access-profile-anchor.sh`
/// byte for byte, trailing NUL included. Two verifiers of one signature that
/// disagree about the domain do not both verify it -- they each verify a
/// different statement.
const ANCHOR_DOMAIN: &[u8] = b"neural-ice:ota:access-profile-anchor:v1\0";
const ANCHOR_SCHEMA: &str = "neural-ice-access-profile-anchor-v1";
const DEVICE_ROOT_SCHEMA: &str = "neural-ice-device-root-tpm-v1";
const DEVICE_ROOT_HANDLE: &str = "0x81010005";
#[cfg(not(feature = "test-path-overrides"))]
const TPM_LIFECYCLE_STATUS: &str = "/usr/libexec/neural-ice-firstboot-tpm-ceremony";
#[cfg(not(feature = "test-path-overrides"))]
const TPM_STATE_HELPER: &str = "/usr/libexec/neural-ice-tpm-state";

const ANCHOR_JSON: &str = "access-profile-v1.json";
const ANCHOR_SIG: &str = "access-profile-v1.sig";
const ANCHOR_SPKI: &str = "access-profile-v1.spki";
const DEVICE_ROOT_IDENTITY: &str = "device-root-v1.json";
const OWNER_CEREMONY_EVIDENCE_V1: &str = "owner-ceremony-evidence-v1.json";
const OWNER_CEREMONY_EVIDENCE_V2: &str = "owner-ceremony-evidence-v2.json";
const COMPLETION_V2_DOMAIN: &[u8] = b"neural-ice:tpm:owner-ceremony-completion:v2\0";
const OWNER_STATE_PROFILE: &str = "owner-sealed-ota-state-v1";
const OWNER_FLOOR_NAME: &str =
    "000be283f20a38b93f8cef085efb4aee9f5944cc3b3b28b850bf3c0eeb2054cd7fc4";
const OWNER_ANCHOR_PRISTINE_NAME: &str =
    "000b038de2091c1c8ef2e8fd8869f17bef3a576ae287530fa17f05ae3b9712014b5d";
const OWNER_ANCHOR_WRITTEN_NAME: &str =
    "000b11afd155aca82a503f2029cc11395389654c3a25fc54b9eca6d33abdff498d56";
const OWNER_FLOOR_POLICY: &str = "f83217e5a2a04342f7daa55ccfb3cd4b8a1f1e8ebb28c7719a9abbdbd638a230";
const OWNER_ANCHOR_POLICY: &str =
    "b6a2e7142ee56fd978047488483daa5b42b8dc4cc7ddcceddfb91793cf1ff1b7";

/// Bounds exist so a hostile or corrupted `/var` cannot make the verifier read
/// an unbounded file before it has decided anything.
const MAX_ANCHOR_BYTES: u64 = 1024;
const MAX_SIGNATURE_BYTES: u64 = 1024;
const MAX_SPKI_BYTES: u64 = 1024;
const MAX_IDENTITY_BYTES: u64 = 4096;
const MAX_OWNER_CEREMONY_EVIDENCE_BYTES: u64 = 16 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Anchor {
    access_profile: String,
    anchor_seq: u64,
    device_root_handle: String,
    device_root_name: String,
    device_root_spki_sha256: String,
    enrolled_at: String,
    hardware_target: String,
    schema: String,
    signed_boot_trust_policy_id: String,
}

#[derive(Deserialize)]
struct DeviceRootIdentity {
    handle: String,
    name: String,
    schema: String,
    spki_sha256: String,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct CeremonyAnchorEvidence {
    json_sha256: String,
    signature_sha256: String,
    spki_sha256: String,
}

#[derive(Deserialize)]
struct OwnerCeremonyEvidence {
    access_profile_anchor: CeremonyAnchorEvidence,
    schema: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CompletionInspection {
    completion_version: u64,
    evidence_digest_sha256: String,
    schema: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerPresealEvidence {
    receipt_schema: String,
    receipt_sha256: String,
    set_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerOtaStateEvidence {
    anchor_attributes: String,
    anchor_index: String,
    anchor_name_at_completion: String,
    anchor_policy_sha256: String,
    anchor_pristine_name: String,
    anchor_size: u64,
    anchor_state_at_completion: String,
    anchor_written_name: String,
    baseline_floor: u64,
    clear_protected_at_completion: bool,
    floor_attributes: String,
    floor_index: String,
    floor_name: String,
    floor_policy_sha256: String,
    floor_size: u64,
    profile: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerCeremonyEvidenceV2 {
    access_profile_anchor: CeremonyAnchorEvidence,
    data_luks: serde_json::Value,
    device_root_name: String,
    install_identity: serde_json::Value,
    ota_preseal: OwnerPresealEvidence,
    ota_state: OwnerOtaStateEvidence,
    schema: String,
    srk_name: String,
    system_luks: serde_json::Value,
    tpm_state: serde_json::Value,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct VerifiedOwnerCompletion {
    pub(crate) completion_version: u64,
    pub(crate) evidence_digest_sha256: String,
    pub(crate) preseal_receipt_sha256: Option<String>,
    pub(crate) preseal_set_sha256: Option<String>,
    pub(crate) baseline_floor: Option<u64>,
}

struct AuthenticatedCompletion {
    verified: VerifiedOwnerCompletion,
    anchor: CeremonyAnchorEvidence,
}

/// The one refusal string the OTA caller and the operator both key on.
pub(crate) fn reinstall_required(detail: &str) -> String {
    format!("reinstall required: {detail}")
}

fn read_bounded(path: &Path, maximum: u64, label: &str) -> Result<Vec<u8>, String> {
    let path_metadata = std::fs::symlink_metadata(path)
        .map_err(|_| reinstall_required(&format!("the {label} is absent ({})", path.display())))?;
    if !path_metadata.file_type().is_file() {
        return Err(reinstall_required(&format!(
            "the {label} is not a regular file ({})",
            path.display()
        )));
    }
    if path_metadata.len() == 0 || path_metadata.len() > maximum {
        return Err(reinstall_required(&format!(
            "the {label} has an implausible size ({} bytes)",
            path_metadata.len()
        )));
    }
    let mut file = std::fs::File::open(path).map_err(|_| {
        reinstall_required(&format!("the {label} is unreadable ({})", path.display()))
    })?;
    let opened_metadata = file.metadata().map_err(|_| {
        reinstall_required(&format!(
            "the {label} metadata is unreadable ({})",
            path.display()
        ))
    })?;
    if !opened_metadata.file_type().is_file()
        || opened_metadata.dev() != path_metadata.dev()
        || opened_metadata.ino() != path_metadata.ino()
    {
        return Err(reinstall_required(&format!(
            "the {label} changed while it was opened"
        )));
    }
    let mut bytes = Vec::with_capacity(std::cmp::min(maximum, 16 * 1024) as usize);
    file.by_ref()
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| {
            reinstall_required(&format!("the {label} is unreadable ({})", path.display()))
        })?;
    // Bound the descriptor-held bytes themselves. The path is mutable, but the
    // caller's snapshot cannot grow after this read or change under later use.
    if bytes.is_empty() || bytes.len() as u64 > maximum {
        return Err(reinstall_required(&format!(
            "the {label} changed to an implausible size while it was read"
        )));
    }
    Ok(bytes)
}

fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn closed_object(value: &serde_json::Value, fields: &[&str], schema: &str) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    object.len() == fields.len()
        && fields.iter().all(|field| object.contains_key(*field))
        && object.get("schema").and_then(serde_json::Value::as_str) == Some(schema)
}

fn known_profile(value: &str) -> bool {
    matches!(
        value,
        "lab-managed" | "customer-locked" | "developer-diagnostic"
    )
}

/// Re-serialise the parsed anchor in the ONE canonical form the enroller persists.
/// Shell command substitution strips the formatter LF before signing and storage.
/// Preserve those already-issued bytes; never normalise a signed file on disk.
///
/// The signature is verified over THIS, not over the file's bytes. Verifying the
/// file would accept whatever the file happened to contain -- including bytes no
/// field of `Anchor` ever looked at. Rebuilding from the parsed fields means an
/// unparsed byte cannot ride along, and it is also how the two implementations
/// are kept honest: if `anchor_json()` in the shell helper and this function ever
/// disagree by one character, nothing verifies and nothing silently passes.
fn canonical_bytes(anchor: &Anchor) -> Vec<u8> {
    format!(
        "{{\"access_profile\":\"{}\",\"anchor_seq\":{},\"device_root_handle\":\"{}\",\
\"device_root_name\":\"{}\",\"device_root_spki_sha256\":\"{}\",\"enrolled_at\":\"{}\",\
\"hardware_target\":\"{}\",\"schema\":\"{}\",\"signed_boot_trust_policy_id\":\"{}\"}}",
        anchor.access_profile,
        anchor.anchor_seq,
        anchor.device_root_handle,
        anchor.device_root_name,
        anchor.device_root_spki_sha256,
        anchor.enrolled_at,
        anchor.hardware_target,
        anchor.schema,
        anchor.signed_boot_trust_policy_id,
    )
    .into_bytes()
}

fn decode_base64_line(value: &[u8], label: &str) -> Result<Vec<u8>, String> {
    let text = std::str::from_utf8(value)
        .map_err(|_| reinstall_required(&format!("the {label} is not ASCII base64")))?;
    let text = text.trim();
    if text.is_empty() || text.len() % 4 != 0 {
        return Err(reinstall_required(&format!(
            "the {label} is not well-formed base64"
        )));
    }
    let mut out = Vec::new();
    for chunk in text.as_bytes().chunks(4) {
        let mut accumulator = 0u32;
        let mut padding = 0;
        for &byte in chunk {
            accumulator = (accumulator << 6)
                | match byte {
                    b'A'..=b'Z' => u32::from(byte - b'A'),
                    b'a'..=b'z' => u32::from(byte - b'a' + 26),
                    b'0'..=b'9' => u32::from(byte - b'0' + 52),
                    b'+' => 62,
                    b'/' => 63,
                    b'=' => {
                        padding += 1;
                        0
                    }
                    _ => {
                        return Err(reinstall_required(&format!(
                            "the {label} is not well-formed base64"
                        )))
                    }
                };
        }
        out.push((accumulator >> 16) as u8);
        if padding < 2 {
            out.push((accumulator >> 8) as u8);
        }
        if padding < 1 {
            out.push(accumulator as u8);
        }
    }
    Ok(out)
}

fn spki_pem(der: &[u8]) -> Vec<u8> {
    let encoded = crate::delegated::contract::encode_base64(der);
    let mut pem = b"-----BEGIN PUBLIC KEY-----\n".to_vec();
    for chunk in encoded.as_bytes().chunks(64) {
        pem.extend_from_slice(chunk);
        pem.push(b'\n');
    }
    pem.extend_from_slice(b"-----END PUBLIC KEY-----\n");
    pem
}

/// The dedicated device-root handle's TPM NV install counter (`nt=counter`),
/// the same index `ota/neural-ice-tpm-highwater.sh` provisions and advances.
/// Two readers of one counter that disagree about its address do not both read
/// it -- they each read a different number.
const INSTALL_COUNTER_NV_INDEX: u32 = 0x0150_0003;
/// The write-once, policy-protected NV record that BINDS this appliance's access
/// profile. See `ota/neural-ice-tpm-state.sh` for how it is provisioned; the
/// constants below are the same contract read from the other side.
const PROFILE_RECORD_NV_INDEX: u32 = 0x0150_0005;
const PROFILE_RECORD_BYTES: usize = 64;
const PROFILE_RECORD_MAGIC: &[u8] = b"NI-TPM02";
/// Domain separation: the same three words must never hash to a value some other
/// statement in this tree also produces. Byte-for-byte the shell helper's
/// `PROFILE_BINDING_DOMAIN`.
const PROFILE_BINDING_DOMAIN: &[u8] = b"neural-ice:tpm:access-profile-binding:v1";
/// `policywrite|writedefine|ownerread|authread` as the TPM reports it, with the
/// bits the TPM sets by itself masked out: WRITELOCKED (0x800), READLOCKED
/// (0x1000_0000) and WRITTEN (0x2000_0000) describe the index's HISTORY, not its
/// contract.
const PROFILE_RECORD_ATTRIBUTES: u32 = 0x0006_2008;
const NV_ATTRIBUTE_DYNAMIC_MASK: u32 = 0x3000_0800;
/// ...and then that history is REQUIRED BACK (review 2026-09-01, P1 #2).
///
/// Masking WRITELOCKED out of the contract comparison and never asking for it
/// again is how a record left writable by an interrupted provisioning -- a power
/// loss between `TPM2_NV_Write` and `TPM2_NV_WriteLock` -- was accepted here as a
/// finished binding. A finished record is WRITTEN **and** WRITELOCKED; anything
/// else is an ordinary rewritable index at a well-known address, and this
/// verifier must not read a profile out of one.
///
/// Byte-for-byte the same requirement `ota/neural-ice-tpm-state.sh` enforces:
/// two readers of one record that disagree about when it is finished do not both
/// read it.
const NV_WRITELOCKED: u32 = 0x0000_0800;
const NV_WRITTEN: u32 = 0x2000_0000;
const PROFILE_RECORD_SEALED_BITS: u32 = NV_WRITTEN | NV_WRITELOCKED;
/// `PolicyOR(PolicyCommandCode(NV_Write), PolicyCommandCode(NV_WriteLock))`.
const PROFILE_RECORD_POLICY: &str =
    "f83217e5a2a04342f7daa55ccfb3cd4b8a1f1e8ebb28c7719a9abbdbd638a230";

/// Resolve a TPM tool. The override exists ONLY under the integration-test
/// feature: a CI runner has no TPM, and a verifier that silently skipped this
/// evidence when a binary was missing would be the very hole this module closes.
/// The production build has no override at all.
fn tool(name: &str) -> PathBuf {
    #[cfg(feature = "test-path-overrides")]
    if let Some(path) = std::env::var_os(format!("NI_OTA_{}", name.to_ascii_uppercase())) {
        return PathBuf::from(path);
    }
    PathBuf::from(format!("/usr/bin/{name}"))
}

/// Require the exact same read-only lifecycle proof that gates boot readiness.
///
/// This is deliberately shared with the shell implementation instead of
/// duplicating a weaker subset in Rust: the status command authenticates the
/// write-locked completion record, both NV public contracts and counter values,
/// both persistent object Names, both canonical LUKS2 token contracts, the
/// access-profile anchor and the signed installer/release identity.  It never
/// enters the one-time provisioning path.
fn assert_full_tpm_lifecycle() -> Result<Result<(), String>, InternalError> {
    #[cfg(feature = "test-path-overrides")]
    let executable = std::env::var_os("NI_OTA_FIRSTBOOT_TPM_CEREMONY")
        .map(PathBuf::from)
        // Existing integration fixtures exercise each low-level TPM reader
        // independently. Only the test-only feature has this inert default;
        // production always uses the immutable absolute path below.
        .unwrap_or_else(|| PathBuf::from("/bin/true"));
    #[cfg(not(feature = "test-path-overrides"))]
    let executable = PathBuf::from(TPM_LIFECYCLE_STATUS);

    match Command::new(executable).arg("status").output() {
        Ok(output) if output.status.success() => Ok(Ok(())),
        Ok(output) => {
            let detail = String::from_utf8_lossy(&output.stderr);
            Ok(Err(reinstall_required(&format!(
                "the authenticated TPM owner lifecycle is incomplete ({})",
                detail.trim()
            ))))
        }
        Err(error) => Ok(Err(reinstall_required(&format!(
            "the authenticated TPM owner lifecycle cannot be checked ({error})"
        )))),
    }
}

/// Authenticate the versioned completion record, then bind its digest to the
/// exact canonical evidence file selected by the TPM magic. There is no
/// fallback between versions after the helper has selected one.
fn authenticated_completion(
    state_dir: &Path,
) -> Result<Result<AuthenticatedCompletion, String>, InternalError> {
    #[cfg(feature = "test-path-overrides")]
    let executable = match std::env::var_os("NI_OTA_TPM_STATE_HELPER") {
        Some(path) => PathBuf::from(path),
        None => {
            return Ok(Err(reinstall_required(
                "the test TPM-state helper was not explicitly configured",
            )))
        }
    };
    #[cfg(not(feature = "test-path-overrides"))]
    let executable = PathBuf::from(TPM_STATE_HELPER);

    let output = match Command::new(executable).arg("completion-inspect").output() {
        Ok(output) if output.status.success() => output,
        Ok(output) => {
            let detail = String::from_utf8_lossy(&output.stderr);
            return Ok(Err(reinstall_required(&format!(
                "the TPM ceremony-completion record cannot be authenticated ({})",
                detail.trim()
            ))));
        }
        Err(error) => {
            return Ok(Err(reinstall_required(&format!(
                "the TPM ceremony-completion record cannot be read ({error})"
            ))));
        }
    };
    let inspection: CompletionInspection = match serde_json::from_slice(&output.stdout) {
        Ok(value) => value,
        Err(error) => {
            return Ok(Err(reinstall_required(&format!(
                "the TPM ceremony-completion inspection is malformed ({error})"
            ))))
        }
    };
    let mut canonical = serde_json::to_vec(&inspection).map_err(|error| {
        InternalError(format!("cannot serialize completion inspection: {error}"))
    })?;
    canonical.push(b'\n');
    if output.stdout != canonical
        || inspection.schema != "neural-ice-owner-ceremony-completion-inspection-v1"
        || !matches!(inspection.completion_version, 1 | 2)
        || !is_lower_hex(&inspection.evidence_digest_sha256, 64)
    {
        return Ok(Err(reinstall_required(
            "the TPM ceremony-completion inspection violates its closed contract",
        )));
    }

    let evidence_path = state_dir.join(match inspection.completion_version {
        1 => OWNER_CEREMONY_EVIDENCE_V1,
        2 => OWNER_CEREMONY_EVIDENCE_V2,
        _ => unreachable!(),
    });
    let evidence_bytes = match read_bounded(
        &evidence_path,
        MAX_OWNER_CEREMONY_EVIDENCE_BYTES,
        "owner-ceremony evidence",
    ) {
        Ok(bytes) => bytes,
        Err(reason) => return Ok(Err(reason)),
    };
    let observed_digest = if inspection.completion_version == 1 {
        hex_sha256(&evidence_bytes)
    } else {
        let mut message = Vec::with_capacity(COMPLETION_V2_DOMAIN.len() + evidence_bytes.len());
        message.extend_from_slice(COMPLETION_V2_DOMAIN);
        message.extend_from_slice(&evidence_bytes);
        hex_sha256(&message)
    };
    if observed_digest != inspection.evidence_digest_sha256 {
        return Ok(Err(reinstall_required(
            "the owner-ceremony evidence bytes do not match the write-locked TPM completion record",
        )));
    }

    if inspection.completion_version == 1 {
        let evidence: OwnerCeremonyEvidence = match serde_json::from_slice(&evidence_bytes) {
            Ok(value) => value,
            Err(error) => {
                return Ok(Err(reinstall_required(&format!(
                    "the authenticated owner-ceremony evidence is malformed ({error})"
                ))))
            }
        };
        if evidence.schema != "neural-ice-owner-ceremony-evidence-v1" {
            return Ok(Err(reinstall_required(
                "the authenticated owner-ceremony evidence has the wrong schema",
            )));
        }
        return Ok(Ok(AuthenticatedCompletion {
            verified: VerifiedOwnerCompletion {
                completion_version: 1,
                evidence_digest_sha256: inspection.evidence_digest_sha256,
                preseal_receipt_sha256: None,
                preseal_set_sha256: None,
                baseline_floor: None,
            },
            anchor: evidence.access_profile_anchor,
        }));
    }

    let generic: serde_json::Value = match serde_json::from_slice(&evidence_bytes) {
        Ok(value) => value,
        Err(error) => {
            return Ok(Err(reinstall_required(&format!(
                "the authenticated owner-ceremony evidence is malformed ({error})"
            ))))
        }
    };
    let mut canonical_evidence = serde_json::to_vec(&generic).map_err(|error| {
        InternalError(format!("cannot serialize owner-ceremony evidence: {error}"))
    })?;
    canonical_evidence.push(b'\n');
    if canonical_evidence != evidence_bytes {
        return Ok(Err(reinstall_required(
            "the authenticated owner-ceremony evidence is not canonical JSON plus LF",
        )));
    }
    let evidence: OwnerCeremonyEvidenceV2 = match serde_json::from_slice(&evidence_bytes) {
        Ok(value) => value,
        Err(error) => {
            return Ok(Err(reinstall_required(&format!(
                "the authenticated owner-ceremony evidence is malformed ({error})"
            ))))
        }
    };
    let ota = &evidence.ota_state;
    if evidence.schema != "neural-ice-owner-ceremony-evidence-v2"
        || !closed_object(
            &evidence.install_identity,
            &[
                "install_source",
                "installed_at",
                "installer_sealed_identity_sha256",
                "release_identity_sha256",
                "schema",
            ],
            "neural-ice-owner-ceremony-install-identity-v1",
        )
        || !closed_object(
            &evidence.tpm_state,
            &[
                "freshness_counter",
                "freshness_public_sha256",
                "install_counter",
                "install_public_sha256",
                "profile_binding",
                "schema",
            ],
            "neural-ice-tpm-state-snapshot-v1",
        )
        || ![&evidence.system_luks, &evidence.data_luks]
            .into_iter()
            .all(|value| {
                closed_object(
                    value,
                    &[
                        "keyslot",
                        "pcr_bank",
                        "pcrs",
                        "policy_hash",
                        "policy_public_key_sha256",
                        "schema",
                        "sealed_object_sha256",
                        "srk_sha256",
                        "token_sha256",
                    ],
                    "neural-ice-luks-token-evidence-v1",
                )
            })
        || evidence.ota_preseal.receipt_schema != "neural-ice-ota-preseal-receipt-v1"
        || !is_lower_hex(&evidence.ota_preseal.receipt_sha256, 64)
        || !is_lower_hex(&evidence.ota_preseal.set_sha256, 64)
        || ota.profile != OWNER_STATE_PROFILE
        || ota.floor_index != "0x01500001"
        || ota.floor_attributes != "0x62008"
        || ota.floor_policy_sha256 != OWNER_FLOOR_POLICY
        || ota.floor_size != 8
        || ota.floor_name != OWNER_FLOOR_NAME
        || ota.anchor_index != "0x01500002"
        || ota.anchor_attributes != "0x2060048"
        || ota.anchor_policy_sha256 != OWNER_ANCHOR_POLICY
        || ota.anchor_size != 32
        || ota.anchor_pristine_name != OWNER_ANCHOR_PRISTINE_NAME
        || ota.anchor_written_name != OWNER_ANCHOR_WRITTEN_NAME
        || ota.anchor_state_at_completion != "pristine"
        || ota.anchor_name_at_completion != OWNER_ANCHOR_PRISTINE_NAME
        || !ota.clear_protected_at_completion
        || ota.baseline_floor == 0
        || ota.baseline_floor > 9_007_199_254_740_991
        || !is_lower_hex(&evidence.device_root_name, 68)
        || !is_lower_hex(&evidence.srk_name, 68)
    {
        return Ok(Err(reinstall_required(
            "the authenticated owner-profile completion evidence violates its closed contract",
        )));
    }
    Ok(Ok(AuthenticatedCompletion {
        verified: VerifiedOwnerCompletion {
            completion_version: 2,
            evidence_digest_sha256: inspection.evidence_digest_sha256,
            preseal_receipt_sha256: Some(evidence.ota_preseal.receipt_sha256),
            preseal_set_sha256: Some(evidence.ota_preseal.set_sha256),
            baseline_floor: Some(ota.baseline_floor),
        },
        anchor: evidence.access_profile_anchor,
    }))
}

#[allow(dead_code)] // Frozen Slice-C API consumed by the subsequent R1 reader.
pub(crate) fn verified_owner_completion(
    state_dir: &Path,
) -> Result<Result<VerifiedOwnerCompletion, String>, InternalError> {
    Ok(authenticated_completion(state_dir)?.map(|value| value.verified))
}

#[cfg(feature = "test-path-overrides")]
pub(crate) fn run_owner_completion_test(args: &[String]) -> Result<u8, InternalError> {
    let flags = crate::parse_flags(args, &["state-dir"])?;
    let state_dir = flags.get("state-dir").ok_or_else(|| {
        InternalError("test-inspect-owner-completion: --state-dir is required".into())
    })?;
    match verified_owner_completion(Path::new(state_dir))? {
        Ok(value) => {
            println!(
                "{{\"baseline_floor\":{},\"completion_version\":{},\"evidence_digest_sha256\":\"{}\",\"preseal_receipt_sha256\":{},\"preseal_set_sha256\":{}}}",
                value.baseline_floor.map_or("null".into(), |v| v.to_string()),
                value.completion_version,
                value.evidence_digest_sha256,
                value.preseal_receipt_sha256.map_or("null".into(), |v| format!("\"{v}\"")),
                value.preseal_set_sha256.map_or("null".into(), |v| format!("\"{v}\"")),
            );
            Ok(crate::EXIT_PASS)
        }
        Err(reason) => {
            eprintln!("ni-ota-verify: owner completion REFUSED: {reason}");
            Ok(crate::EXIT_REFUSE)
        }
    }
}

fn strict_der_integers(signature: &[u8]) -> (&[u8], &[u8]) {
    // Only called after validate_der_signature() established the complete DER
    // shape and both scalar ranges. Keep this extractor deliberately dumb so a
    // second parser cannot silently accept a wider language.
    let r_len = usize::from(signature[3]);
    let r = &signature[4..4 + r_len];
    let s_tag = 4 + r_len;
    let s_len = usize::from(signature[s_tag + 1]);
    let s = &signature[s_tag + 2..s_tag + 2 + s_len];
    (r, s)
}

fn der_integer_from_scalar(bytes: &[u8; 32]) -> Vec<u8> {
    let first = bytes.iter().position(|byte| *byte != 0).unwrap_or(31);
    let significant = &bytes[first..];
    let mut encoded = Vec::with_capacity(35);
    encoded.push(0x02);
    encoded.push((significant.len() + usize::from(significant[0] & 0x80 != 0)) as u8);
    if significant[0] & 0x80 != 0 {
        encoded.push(0);
    }
    encoded.extend_from_slice(significant);
    encoded
}

/// Preserve the persisted, NV-authenticated historical bytes. Only the
/// signature passed to the anchor verifier is canonicalized in memory. The
/// shared delegated verifier remains unmodified and still rejects every high-S
/// release signature.
fn canonicalize_ceremony_bound_signature(signature: &[u8]) -> Result<Vec<u8>, String> {
    match validate_der_signature(signature) {
        Ok(()) => return Ok(signature.to_vec()),
        Err(reason) if reason == "signature is not low-S" => {}
        Err(reason) => return Err(reason),
    }

    let (r, s) = strict_der_integers(signature);
    let significant_s = s.strip_prefix(&[0]).unwrap_or(s);
    let mut scalar_bytes = [0u8; 32];
    scalar_bytes[32 - significant_s.len()..].copy_from_slice(significant_s);
    let scalar = Option::<Scalar>::from(Scalar::from_repr(scalar_bytes.into()))
        .ok_or_else(|| "signature integer is outside the P-256 scalar range".to_string())?;
    let canonical_s: [u8; 32] = (-scalar).to_repr().into();

    let mut body = Vec::with_capacity(70);
    body.push(0x02);
    body.push(r.len() as u8);
    body.extend_from_slice(r);
    body.extend_from_slice(&der_integer_from_scalar(&canonical_s));
    let mut canonical = Vec::with_capacity(body.len() + 2);
    canonical.push(0x30);
    canonical.push(body.len() as u8);
    canonical.extend_from_slice(&body);
    validate_der_signature(&canonical)?;
    Ok(canonical)
}

/// Bind the exact in-memory anchor buffers to the write-locked completion NV
/// record before permitting the one historical high-S compatibility rule.
/// This closes the A/B path race left by merely running lifecycle status before
/// reading mutable `/var`: no different bytes can match the authenticated
/// evidence digest and its three embedded artifact hashes.
fn ceremony_bound_signature(
    state_dir: &Path,
    anchor_bytes: &[u8],
    signature_encoded: &[u8],
    spki_encoded: &[u8],
    signature: &[u8],
) -> Result<Result<Vec<u8>, String>, InternalError> {
    let completion = match authenticated_completion(state_dir)? {
        Ok(value) => value,
        Err(reason) => return Ok(Err(reason)),
    };
    let _authenticated_completion_version = completion.verified.completion_version;
    let hashes = completion.anchor;
    if !is_lower_hex(&hashes.json_sha256, 64)
        || !is_lower_hex(&hashes.signature_sha256, 64)
        || !is_lower_hex(&hashes.spki_sha256, 64)
    {
        return Ok(Err(reinstall_required(
            "the authenticated owner-ceremony anchor hashes are malformed",
        )));
    }
    if hashes.json_sha256 != hex_sha256(anchor_bytes)
        || hashes.signature_sha256 != hex_sha256(signature_encoded)
        || hashes.spki_sha256 != hex_sha256(spki_encoded)
    {
        return Ok(Err(reinstall_required(
            "the access-profile anchor bytes do not match the write-locked owner-ceremony evidence",
        )));
    }
    match canonicalize_ceremony_bound_signature(signature) {
        Ok(signature) => Ok(Ok(signature)),
        Err(reason) => Ok(Err(reinstall_required(&format!(
            "the access-profile anchor signature is invalid ({reason})"
        )))),
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Parse the TCG-marshalled `TPMT_SIGNATURE` requested from `tpm2_sign -f tss`.
///
/// `plain` is a tool-specific representation and is DER for the shipped
/// tpm2-tools. The TSS representation is the TPM wire contract: sigAlg,
/// hashAlg, then two
/// variable-length TPM2B parameters. Refuse every shape outside this appliance's
/// ECDSA-P256/SHA-256 profile before converting the integers to DER.
fn tss_signature_to_der(tss: &[u8]) -> Option<Vec<u8>> {
    const TPM_ALG_ECDSA: u16 = 0x0018;
    const TPM_ALG_SHA256: u16 = 0x000b;
    const CURVE_BYTES: usize = 32;
    const CURVE_ORDER: [u8; CURVE_BYTES] = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63,
        0x25, 0x51,
    ];

    if tss.len() < 4
        || u16::from_be_bytes(tss[0..2].try_into().ok()?) != TPM_ALG_ECDSA
        || u16::from_be_bytes(tss[2..4].try_into().ok()?) != TPM_ALG_SHA256
    {
        return None;
    }
    fn parameter(tss: &[u8], offset: &mut usize) -> Option<[u8; CURVE_BYTES]> {
        let size = usize::from(u16::from_be_bytes(
            tss.get(*offset..*offset + 2)?.try_into().ok()?,
        ));
        *offset += 2;
        if size == 0 || size > CURVE_BYTES {
            return None;
        }
        let value = tss.get(*offset..*offset + size)?;
        *offset += size;
        let mut scalar = [0u8; CURVE_BYTES];
        scalar[CURVE_BYTES - size..].copy_from_slice(value);
        (scalar.iter().any(|byte| *byte != 0) && scalar < CURVE_ORDER).then_some(scalar)
    }
    fn integer(value: &[u8]) -> Vec<u8> {
        let trimmed: &[u8] = {
            let start = value
                .iter()
                .position(|b| *b != 0)
                .unwrap_or(value.len() - 1);
            &value[start..]
        };
        let mut body = Vec::with_capacity(trimmed.len() + 1);
        if trimmed[0] & 0x80 != 0 {
            body.push(0x00);
        }
        body.extend_from_slice(trimmed);
        let mut out = vec![0x02, body.len() as u8];
        out.extend_from_slice(&body);
        out
    }
    let mut offset = 4;
    let r = parameter(tss, &mut offset)?;
    let s = parameter(tss, &mut offset)?;
    if offset != tss.len() {
        return None;
    }
    let body = [integer(&r), integer(&s)].concat();
    if body.len() > 0x7f {
        return None;
    }
    let mut der = vec![0x30, body.len() as u8];
    der.extend_from_slice(&body);
    Some(der)
}

/// Verify a DER ECDSA signature over exactly `message`, with no domain prefix
/// and no LF stripping: the challenge is raw bytes we chose, not a canonical
/// document. `crate::delegated::verify_signature` deliberately cannot express
/// that shape, so it would silently verify a different statement.
fn verify_der_over_bytes(
    pem: &[u8],
    message: &[u8],
    der: &[u8],
    store: &FileStateStore,
) -> Result<Result<(), String>, InternalError> {
    let key = store.secure_temp_bytes("device-root-challenge-key", pem)?;
    let challenge = store.secure_temp_bytes("device-root-challenge", message)?;
    let encoded = crate::delegated::contract::encode_base64(der);
    let signature = store.secure_temp_bytes("device-root-challenge-sig", encoded.as_bytes())?;
    let cosign = runner::cosign_path()?;
    runner::verify_blob(&cosign, key.path(), signature.path(), challenge.path())
}

/// Read the machine's monotonic install counter out of TPM NV.
///
/// Every failure is a refusal. An appliance that cannot say where it is in its
/// own install history must not apply an OTA: that state is the only thing that
/// distinguishes today's anchor from an authentic one lifted out of a previous
/// installation of the same machine.
fn tpm_install_counter(store: &FileStateStore) -> Result<Result<u64, String>, InternalError> {
    let output = store.secure_temp_bytes("install-counter", &[])?;
    let status = Command::new(tool("tpm2_nvread"))
        .arg(format!("0x{INSTALL_COUNTER_NV_INDEX:08x}"))
        .arg("-C")
        .arg(format!("0x{INSTALL_COUNTER_NV_INDEX:08x}"))
        .arg("-s")
        .arg("8")
        .arg("-o")
        .arg(output.path())
        .output();
    let status = match status {
        Ok(value) => value,
        Err(error) => {
            return Ok(Err(reinstall_required(&format!(
                "this appliance's TPM cannot be queried for its install counter ({error})"
            ))))
        }
    };
    if !status.status.success() {
        return Ok(Err(reinstall_required(&format!(
            "this appliance has no readable install counter at 0x{INSTALL_COUNTER_NV_INDEX:08x}"
        ))));
    }
    let bytes = output.read()?;
    let Ok(bytes) = <[u8; 8]>::try_from(bytes.as_slice()) else {
        return Ok(Err(reinstall_required(
            "the install counter is not exactly eight bytes",
        )));
    };
    let value = u64::from_be_bytes(bytes);
    if value == 0 || value > 9_007_199_254_740_991 {
        return Ok(Err(reinstall_required(
            "the install counter is outside the range an anchor sequence can take",
        )));
    }
    Ok(Ok(value))
}

/// The digest that binds an appliance's access profile, hardware target and
/// Secure Boot trust policy. Byte-for-byte the shell helper's `profile_digest`.
fn profile_binding_digest(profile: &str, target: &str, policy_id: &str) -> String {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(PROFILE_BINDING_DOMAIN);
    bytes.push(0);
    bytes.extend_from_slice(profile.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(target.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(policy_id.as_bytes());
    hex_sha256(&bytes)
}

/// Require the profile-record NV index to still have the attributes and policy
/// the installer defined it with.
///
/// An index redefined with `ownerwrite`, or without `writedefine`, is a
/// different index wearing the same address -- rewritable by anything with the
/// (empty) owner authorization. Reading its CONTENT without checking its SHAPE
/// would hand that attacker exactly the authority this record exists to remove.
fn assert_profile_record_shape() -> Result<Result<(), String>, InternalError> {
    let output = Command::new(tool("tpm2_nvreadpublic"))
        .arg(format!("0x{PROFILE_RECORD_NV_INDEX:08x}"))
        .output();
    let output = match output {
        Ok(value) if value.status.success() => value,
        _ => {
            return Ok(Err(reinstall_required(&format!(
                "this appliance's TPM will not describe its access-profile record at 0x{PROFILE_RECORD_NV_INDEX:08x}"
            ))))
        }
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let mut attributes: Option<u32> = None;
    let mut policy: Option<String> = None;
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("value: 0x") {
            attributes = u32::from_str_radix(rest.trim(), 16).ok();
        } else if let Some(rest) = trimmed.strip_prefix("authorization policy:") {
            policy = Some(rest.trim().to_ascii_lowercase());
        }
    }
    let Some(attributes) = attributes else {
        return Ok(Err(reinstall_required(
            "the access-profile record reports no usable NV attributes",
        )));
    };
    if attributes & !NV_ATTRIBUTE_DYNAMIC_MASK != PROFILE_RECORD_ATTRIBUTES {
        return Ok(Err(reinstall_required(&format!(
            "the access-profile record carries NV attributes 0x{attributes:08x}, not the write-once, policy-protected ones this appliance was installed with"
        ))));
    }
    if attributes & PROFILE_RECORD_SEALED_BITS != PROFILE_RECORD_SEALED_BITS {
        // WRITTEN without WRITELOCKED is an interrupted provisioning: the binding
        // is there and the index is still writable, so anything on this appliance
        // can restate what it is. Neither WRITTEN nor WRITELOCKED means the index
        // carries nothing at all. Both are refusals, and both name themselves so
        // an operator is not sent looking for a redefined index.
        let detail = if attributes & NV_WRITTEN == 0 {
            "exists but was never written"
        } else {
            "is written but was never write-locked, which is an interrupted provisioning and not a binding"
        };
        return Ok(Err(reinstall_required(&format!(
            "this appliance's access-profile record {detail} (NV attributes 0x{attributes:08x}); recovery is a TPM clear with physical presence followed by a reinstall from signed media"
        ))));
    }
    if policy.as_deref() != Some(PROFILE_RECORD_POLICY) {
        return Ok(Err(reinstall_required(
            "the access-profile record carries a different authorization policy than this appliance was installed with",
        )));
    }
    Ok(Ok(()))
}

/// Read the access-profile binding this machine's TPM holds.
fn tpm_profile_binding(store: &FileStateStore) -> Result<Result<String, String>, InternalError> {
    if let Err(reason) = assert_profile_record_shape()? {
        return Ok(Err(reason));
    }
    let output = store.secure_temp_bytes("access-profile-record", &[])?;
    let status = Command::new(tool("tpm2_nvread"))
        .arg(format!("0x{PROFILE_RECORD_NV_INDEX:08x}"))
        .arg("-C")
        .arg(format!("0x{PROFILE_RECORD_NV_INDEX:08x}"))
        .arg("-s")
        .arg(PROFILE_RECORD_BYTES.to_string())
        .arg("-o")
        .arg(output.path())
        .output();
    let status = match status {
        Ok(value) => value,
        Err(error) => {
            return Ok(Err(reinstall_required(&format!(
                "this appliance's TPM cannot be queried for its access-profile record ({error})"
            ))))
        }
    };
    if !status.status.success() {
        return Ok(Err(reinstall_required(&format!(
            "this appliance has no access-profile record at 0x{PROFILE_RECORD_NV_INDEX:08x}; it was not installed by a medium that binds one"
        ))));
    }
    let bytes = output.read()?;
    if bytes.len() != PROFILE_RECORD_BYTES {
        return Ok(Err(reinstall_required(&format!(
            "the access-profile record is {} bytes, not {PROFILE_RECORD_BYTES}",
            bytes.len()
        ))));
    }
    if &bytes[..PROFILE_RECORD_MAGIC.len()] != PROFILE_RECORD_MAGIC {
        return Ok(Err(reinstall_required(
            "the access-profile record is not this appliance's record",
        )));
    }
    if bytes[40..].iter().any(|byte| *byte != 0) {
        return Ok(Err(reinstall_required(
            "the access-profile record carries bytes outside its closed v2 contract",
        )));
    }
    Ok(Ok(hex_encode(&bytes[8..40])))
}

fn assert_owner_ceremony_complete() -> Result<Result<(), String>, InternalError> {
    let output = Command::new(tool("tpm2_getcap"))
        .arg("properties-variable")
        .output();
    let output = match output {
        Ok(value) if value.status.success() => value,
        _ => {
            return Ok(Err(reinstall_required(
                "the TPM will not report ownerAuthSet; runtime cannot prove the mandatory owner ceremony completed",
            )))
        }
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let owner_auth_set = text.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        (name.trim() == "ownerAuthSet").then(|| value.trim())
    });
    if owner_auth_set != Some("1") {
        return Ok(Err(reinstall_required(
            "ownerAuthSet is not 1; OTA readiness is forbidden before the mandatory owner ceremony",
        )));
    }
    Ok(Ok(()))
}

/// Make the LIVE device root prove it is the key this anchor names.
///
/// Three separate proofs, because the first two are copyable and the third is
/// not:
///   * the key at 0x81010005 hashes to the SPKI the anchor names;
///   * its TPM Name is the Name the anchor names (the Name binds the public
///     area AND the hierarchy, so a key with the same public bytes created under
///     a different hierarchy is a different Name);
///   * and it SIGNS A FRESH NONCE. A bundle copied from another appliance can
///     carry a correct hash and a correct Name; it cannot carry the private key,
///     which never leaves that other machine's TPM.
fn attest_live_device_root(
    anchor: &Anchor,
    store: &FileStateStore,
) -> Result<Result<(), String>, InternalError> {
    let spki = store.secure_temp_bytes("device-root-spki", &[])?;
    let readpublic = Command::new(tool("tpm2_readpublic"))
        .arg("-Q")
        .arg("-c")
        .arg(DEVICE_ROOT_HANDLE)
        .arg("-f")
        .arg("der")
        .arg("-o")
        .arg(spki.path())
        .output();
    let readpublic = match readpublic {
        Ok(value) => value,
        Err(error) => {
            return Ok(Err(reinstall_required(&format!(
                "this appliance's TPM cannot be queried for its device root ({error})"
            ))))
        }
    };
    if !readpublic.status.success() {
        return Ok(Err(reinstall_required(&format!(
            "this appliance has no device root at {DEVICE_ROOT_HANDLE}"
        ))));
    }
    let spki_der = spki.read()?;
    if hex_sha256(&spki_der) != anchor.device_root_spki_sha256 {
        return Ok(Err(reinstall_required(
            "the device root in this appliance's TPM is not the key the access-profile anchor names",
        )));
    }

    let name = store.secure_temp_bytes("device-root-name", &[])?;
    let name_output = Command::new(tool("tpm2_readpublic"))
        .arg("-Q")
        .arg("-c")
        .arg(DEVICE_ROOT_HANDLE)
        .arg("-n")
        .arg(name.path())
        .output();
    match name_output {
        Ok(value) if value.status.success() => {
            if hex_encode(&name.read()?) != anchor.device_root_name {
                return Ok(Err(reinstall_required(
                    "the device root in this appliance's TPM has a different Name than the anchor records",
                )));
            }
        }
        _ => {
            return Ok(Err(reinstall_required(
                "this appliance's TPM would not report its device root's Name",
            )))
        }
    }

    // The challenge is OURS, not the TPM's: a nonce the signer chooses proves
    // nothing about freshness.
    let mut challenge = [0u8; 32];
    {
        use std::io::Read;
        let mut source = std::fs::File::open("/dev/urandom")
            .map_err(|error| InternalError(format!("cannot open /dev/urandom: {error}")))?;
        source
            .read_exact(&mut challenge)
            .map_err(|error| InternalError(format!("cannot read a challenge nonce: {error}")))?;
    }
    let challenge_file = store.secure_temp_bytes("device-root-nonce", &challenge)?;
    let signature = store.secure_temp_bytes("device-root-nonce-sig", &[])?;
    let signed = Command::new(tool("tpm2_sign"))
        .arg("-Q")
        .arg("-c")
        .arg(DEVICE_ROOT_HANDLE)
        .arg("-g")
        .arg("sha256")
        .arg("-s")
        .arg("ecdsa")
        .arg("-f")
        .arg("tss")
        .arg("-o")
        .arg(signature.path())
        .arg(challenge_file.path())
        .output();
    match signed {
        Ok(value) if value.status.success() => {}
        _ => {
            return Ok(Err(reinstall_required(
                "this appliance's device root would not sign a liveness challenge",
            )))
        }
    }
    let Some(der) = tss_signature_to_der(&signature.read()?) else {
        return Ok(Err(reinstall_required(
            "the device root produced a liveness signature outside the ECDSA-P256/SHA-256 TPMT_SIGNATURE contract",
        )));
    };
    let pem = spki_pem(&spki_der);
    match verify_der_over_bytes(&pem, &challenge, &der, store)? {
        Ok(()) => Ok(Ok(())),
        Err(reason) => Ok(Err(reinstall_required(&format!(
            "this appliance's device root did not prove possession of the anchored key ({reason})"
        )))),
    }
}

/// Read and fully verify the anchor in `state_dir`.
///
/// `Ok(Ok(profile))` means the appliance provably was installed as `profile`.
/// `Ok(Err(reason))` is a refusal the caller must surface verbatim -- it always
/// starts with "reinstall required".
pub(crate) fn enrolled_access_profile(
    state_dir: &Path,
    store: &FileStateStore,
) -> Result<Result<String, String>, InternalError> {
    if let Err(reason) = assert_full_tpm_lifecycle()? {
        return Ok(Err(reason));
    }
    let anchor_bytes = match read_bounded(
        &state_dir.join(ANCHOR_JSON),
        MAX_ANCHOR_BYTES,
        "access-profile anchor",
    ) {
        Ok(bytes) => bytes,
        Err(reason) => return Ok(Err(reason)),
    };
    let anchor: Anchor = match serde_json::from_slice(&anchor_bytes) {
        Ok(value) => value,
        Err(error) => {
            return Ok(Err(reinstall_required(&format!(
                "the access-profile anchor is not the expected document ({error})"
            ))))
        }
    };

    if anchor.schema != ANCHOR_SCHEMA
        || anchor.device_root_handle != DEVICE_ROOT_HANDLE
        || !known_profile(&anchor.access_profile)
        || !is_lower_hex(&anchor.device_root_spki_sha256, 64)
        || anchor.device_root_name.len() != 68
        || !anchor.device_root_name.starts_with("000b")
        || !is_lower_hex(&anchor.device_root_name[4..], 64)
        || anchor.anchor_seq == 0
        || anchor.anchor_seq > 9_007_199_254_740_991
        || !anchor
            .signed_boot_trust_policy_id
            .starts_with("neural-ice-secureboot-")
        || anchor.hardware_target.is_empty()
        || anchor.hardware_target.len() > 64
    {
        return Ok(Err(reinstall_required(
            "the access-profile anchor does not satisfy its contract",
        )));
    }

    // Byte-for-byte canonicality. A second way to write the same document is a
    // second document, and only one of them was signed.
    if canonical_bytes(&anchor) != anchor_bytes {
        return Ok(Err(reinstall_required(
            "the access-profile anchor is not in its canonical form",
        )));
    }

    // The anchor must name THIS machine's device root. An anchor lifted from
    // another appliance is a perfectly valid signature over a statement about a
    // different machine. The identity file it is compared against is itself
    // re-attested against the live TPM on every boot by
    // /usr/libexec/neural-ice-device-root, so this inherits that check rather
    // than inventing a weaker one.
    let identity_bytes = match read_bounded(
        &state_dir.join(DEVICE_ROOT_IDENTITY),
        MAX_IDENTITY_BYTES,
        "device-root identity",
    ) {
        Ok(bytes) => bytes,
        Err(reason) => return Ok(Err(reason)),
    };
    let identity: DeviceRootIdentity = match serde_json::from_slice(&identity_bytes) {
        Ok(value) => value,
        Err(error) => {
            return Ok(Err(reinstall_required(&format!(
                "the device-root identity is not the expected document ({error})"
            ))))
        }
    };
    if identity.schema != DEVICE_ROOT_SCHEMA || identity.handle != DEVICE_ROOT_HANDLE {
        return Ok(Err(reinstall_required(
            "the device-root identity does not describe the dedicated OTA device root",
        )));
    }
    if identity.name != anchor.device_root_name
        || identity.spki_sha256 != anchor.device_root_spki_sha256
    {
        return Ok(Err(reinstall_required(
            "the access-profile anchor was signed by a different device root than this machine's",
        )));
    }

    let spki_encoded = match read_bounded(
        &state_dir.join(ANCHOR_SPKI),
        MAX_SPKI_BYTES,
        "access-profile anchor key",
    ) {
        Ok(bytes) => bytes,
        Err(reason) => return Ok(Err(reason)),
    };
    let spki_der = match decode_base64_line(&spki_encoded, "access-profile anchor key") {
        Ok(bytes) => bytes,
        Err(reason) => return Ok(Err(reason)),
    };
    // The stored key must be the key the anchor names, or the signature below
    // would prove only that SOME key signed the document.
    if hex_sha256(&spki_der) != anchor.device_root_spki_sha256 {
        return Ok(Err(reinstall_required(
            "the stored device-root key is not the one the access-profile anchor names",
        )));
    }

    let signature_encoded = match read_bounded(
        &state_dir.join(ANCHOR_SIG),
        MAX_SIGNATURE_BYTES,
        "access-profile anchor signature",
    ) {
        Ok(bytes) => bytes,
        Err(reason) => return Ok(Err(reason)),
    };
    let persisted_signature =
        match decode_base64_line(&signature_encoded, "access-profile anchor signature") {
            Ok(bytes) => bytes,
            Err(reason) => return Ok(Err(reason)),
        };
    let signature = match ceremony_bound_signature(
        state_dir,
        &anchor_bytes,
        &signature_encoded,
        &spki_encoded,
        &persisted_signature,
    )? {
        Ok(signature) => signature,
        Err(reason) => return Ok(Err(reason)),
    };

    let pem = spki_pem(&spki_der);
    // The delegated verifier removes one mandatory transport LF before adding
    // the signature domain. Anchor files have no transport LF, so adapt only
    // this in-memory input; the signed message stays DOMAIN || anchor_bytes.
    let mut delegated_payload = anchor_bytes.clone();
    delegated_payload.push(b'\n');
    if let Err(reason) =
        verify_signature(&pem, ANCHOR_DOMAIN, &delegated_payload, &signature, store)?
    {
        return Ok(Err(reinstall_required(&format!(
            "the access-profile anchor is not signed by this machine's device root ({reason})"
        ))));
    }

    if let Err(reason) = assert_owner_ceremony_complete()? {
        return Ok(Err(reason));
    }

    // Everything above compared FILES with FILES. All four of them live in /var,
    // so a coherent bundle copied from another appliance satisfies every one.
    // The two checks below are the ones a copy cannot pass: a live proof of
    // possession, and a counter only this machine's TPM can advance.
    if let Err(reason) = attest_live_device_root(&anchor, store)? {
        return Ok(Err(reason));
    }
    let counter = match tpm_install_counter(store)? {
        Ok(value) => value,
        Err(reason) => return Ok(Err(reason)),
    };
    if anchor.anchor_seq != counter {
        return Ok(Err(reinstall_required(&format!(
            "the access-profile anchor is sequence {} but this machine's TPM install counter stands at {counter}; an anchor from another installation cannot be applied",
            anchor.anchor_seq
        ))));
    }

    // THE AUTHORITY, LAST AND DECISIVE. Everything above establishes that this
    // anchor is an authentic, live, current statement by THIS machine's device
    // root. None of it establishes that the device root was ENTITLED to make the
    // statement -- an empty-policy TPM key signs whatever a root shell asks it
    // to. The write-once NV record is what the installer bound while it was
    // running from the signed medium, and it is the only thing here that a
    // privileged runtime attacker cannot rewrite.
    let binding = match tpm_profile_binding(store)? {
        Ok(value) => value,
        Err(reason) => return Ok(Err(reason)),
    };
    let expected = profile_binding_digest(
        &anchor.access_profile,
        &anchor.hardware_target,
        &anchor.signed_boot_trust_policy_id,
    );
    if binding != expected {
        return Ok(Err(reinstall_required(
            "the access-profile anchor does not match the write-once binding in this machine's TPM; a device-root signature alone cannot state what this appliance is",
        )));
    }

    Ok(Ok(anchor.access_profile))
}

/// The CANDIDATE's own immutable marker, not the release document's claim about
/// it.
///
/// Both gated paths used to compare the enrolled profile with
/// `release.access_profile` and stop there. That is a claim in a signed JSON,
/// and the deployment it describes is a separate object: a same-variant
/// candidate could carry a WIDENED `/usr/lib/neural-ice/access-policy` while its
/// signed release JSON kept the old word, pass the gate, and change the
/// appliance's posture on the next boot. So the marker is read out of the
/// candidate deployment itself and required to be the enrolled profile AND the
/// exact bytes the authorization binds.
///
/// `access_policy_sha256` is the field name ICE-Fabric's
/// `neural-ice-ota-release-authorization-v2` schema already uses for this hash;
/// keeping the spelling means the two sides cannot drift into two names for one
/// fact.
pub(crate) fn assert_candidate_access_profile(
    candidate_root: &Path,
    enrolled: &str,
    authorized_sha256: &str,
) -> Result<(), String> {
    const MARKER: &str = "usr/lib/neural-ice/access-policy";
    const MAX_MARKER_BYTES: u64 = 64;

    let path = candidate_root.join(MARKER);
    let metadata = std::fs::symlink_metadata(&path).map_err(|_| {
        format!(
            "the candidate deployment carries no immutable access policy at {}",
            path.display()
        )
    })?;
    if !metadata.file_type().is_file() {
        return Err(format!(
            "the candidate deployment's access policy is not a regular file ({})",
            path.display()
        ));
    }
    if metadata.len() == 0 || metadata.len() > MAX_MARKER_BYTES {
        return Err(format!(
            "the candidate deployment's access policy has an implausible size ({} bytes)",
            metadata.len()
        ));
    }
    let bytes = std::fs::read(&path).map_err(|_| {
        format!(
            "the candidate deployment's access policy is unreadable ({})",
            path.display()
        )
    })?;
    let digest = hex_sha256(&bytes);
    if digest != authorized_sha256 {
        return Err(format!(
            "the candidate deployment's access policy hashes to {digest}, not the authorised {authorized_sha256}"
        ));
    }
    let marker = String::from_utf8_lossy(&bytes).trim().to_string();
    if !known_profile(&marker) {
        return Err(format!(
            "the candidate deployment states an unrecognised access profile '{marker}'"
        ));
    }
    if marker != enrolled {
        return Err(reinstall_required(&format!(
            "this appliance was installed as '{enrolled}'; the candidate deployment's own immutable marker states '{marker}'"
        )));
    }
    Ok(())
}

/// The comparison every delegated path owes the appliance.
///
/// A release may only be applied if its signed `access_profile` equals the
/// enrolled one. A change is a refusal, never a silent widening -- which is
/// exactly what makes `customer-locked` un-walkable to `lab-managed` by any OTA,
/// however well signed.
pub(crate) fn gate_release_profile(enrolled: &str, release: &str) -> Result<(), String> {
    if enrolled == release {
        return Ok(());
    }
    Err(reinstall_required(&format!(
        "this appliance was installed as '{enrolled}'; a release carrying access profile '{release}' cannot be applied by OTA"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "test-path-overrides")]
    use std::sync::Mutex;

    #[cfg(feature = "test-path-overrides")]
    static LIFECYCLE_ENV: Mutex<()> = Mutex::new(());

    #[test]
    fn shell_tpm_signature_encoder_satisfies_the_rust_low_s_contract() {
        let source = include_str!("../../../ota/neural-ice-access-profile-anchor.sh");
        let body = source.split_once("tss_to_der() {").unwrap().1;
        let body = body.split_once("\n}").unwrap().0;
        let script = [
            "set -euo pipefail\ntool() { command -v \"$1\"; }\ntss_to_der() {",
            body,
            "\n}\n",
            r#"tmp="$(mktemp -d)"
trap 'rm -rf -- "$tmp"' EXIT
python3 - "$tmp/input" <<'PY'
import sys
order = int("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)
tss = bytes.fromhex("0018000b0020") + (1).to_bytes(32, "big")
tss += bytes.fromhex("0020") + (order - 1).to_bytes(32, "big")
open(sys.argv[1], "wb").write(tss)
PY
tss_to_der "$tmp/input" "$tmp/output"
cat "$tmp/output"
"#,
        ]
        .concat();
        let output = Command::new("bash").args(["-c", &script]).output().unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, [0x30, 6, 2, 1, 1, 2, 1, 1]);
        assert!(crate::delegated::contract::validate_der_signature(&output.stdout).is_ok());
    }

    #[test]
    fn only_strict_high_s_anchor_der_is_normalized_in_memory() {
        let low = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];
        assert_eq!(canonicalize_ceremony_bound_signature(&low).unwrap(), low);

        // (r=1, s=n-1) is strict, in-range DER and the high-S equivalent of
        // (r=1, s=1). The shared validator must keep refusing the persisted
        // bytes, while this anchor-local in-memory adapter produces its exact
        // canonical representative.
        let mut high = vec![0x30, 0x26, 0x02, 0x01, 0x01, 0x02, 0x21, 0x00];
        high.extend_from_slice(&[
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2,
            0xfc, 0x63, 0x25, 0x50,
        ]);
        assert_eq!(
            validate_der_signature(&high).unwrap_err(),
            "signature is not low-S"
        );
        assert_eq!(canonicalize_ceremony_bound_signature(&high).unwrap(), low);
        assert!(validate_der_signature(&low).is_ok());

        let mut out_of_range = high.clone();
        *out_of_range.last_mut().unwrap() = 0x51; // s=n
        for invalid in [
            [&low[..], &[0][..]].concat(),
            vec![0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01],
            out_of_range,
        ] {
            assert!(canonicalize_ceremony_bound_signature(&invalid).is_err());
        }
    }

    #[test]
    fn canonical_bytes_match_the_shell_enrollers_persisted_bytes() {
        // Run the actual shell formatter through the command substitution used
        // by enroll(), rather than duplicating its JSON spelling in a fixture.
        let source = include_str!("../../../ota/neural-ice-access-profile-anchor.sh");
        let body = source.split_once("anchor_json() {").unwrap().1;
        let body = body.split_once("\n}").unwrap().0;
        let script = format!(
            "readonly DEVICE_ROOT_HANDLE=0x81010005 ANCHOR_SCHEMA=neural-ice-access-profile-anchor-v1; \
             anchor_json() {{{body}\n}}; json=\"$(anchor_json \"$@\")\"; printf '%s' \"$json\""
        );
        let output = std::process::Command::new("bash")
            .args([
                "-c",
                &script,
                "anchor-test",
                "lab-managed",
                "nvidia-gb10-arm64",
                "neural-ice-secureboot-lab-v1",
                "3",
                &format!("000b{}", "12".repeat(32)),
                &"34".repeat(32),
                "2026-09-05T00:00:00Z",
            ])
            .output()
            .unwrap();
        assert!(output.status.success());
        let anchor: Anchor = serde_json::from_slice(&output.stdout).unwrap();
        let canonical = canonical_bytes(&anchor);
        assert_eq!(canonical, output.stdout);
        assert_eq!(canonical.last(), Some(&b'}'));
        let mut padded = canonical.clone();
        padded.push(b'\n');
        assert_ne!(
            canonical_bytes(&serde_json::from_slice(&padded).unwrap()),
            padded
        );
    }

    fn candidate(dir: &Path, marker: &str) {
        let target = dir.join("usr/lib/neural-ice");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("access-policy"), marker).unwrap();
    }

    fn scratch(label: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ni-access-profile-anchor-{label}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// `access_profile` is a word in a signed document; the appliance boots with
    /// a FILE. A same-variant candidate can ship a widened marker while the
    /// signed release keeps the old profile — which passed every check that
    /// existed before this function.
    #[test]
    fn the_candidate_marker_must_be_the_enrolled_profile_and_the_authorised_bytes() {
        let dir = scratch("candidate");
        candidate(&dir, "customer-locked\n");
        let authorised = hex_sha256(b"customer-locked\n");
        assert!(
            assert_candidate_access_profile(&dir, "customer-locked", &authorised).is_ok(),
            "a candidate that agrees with both was refused"
        );

        // Widened marker, unchanged authorisation: the HASH catches it.
        candidate(&dir, "lab-managed\n");
        let error =
            assert_candidate_access_profile(&dir, "customer-locked", &authorised).unwrap_err();
        assert!(error.contains("not the authorised"), "{error}");

        // Widened marker AND a matching hash: only the PROFILE comparison is
        // left, and it must say "reinstall required" rather than widen.
        let widened = hex_sha256(b"lab-managed\n");
        let error = assert_candidate_access_profile(&dir, "customer-locked", &widened).unwrap_err();
        assert!(error.starts_with("reinstall required"), "{error}");
        assert!(error.contains("states 'lab-managed'"), "{error}");

        // An unrecognised marker is not a profile this verifier can reason
        // about, and the honest response is to install nothing.
        candidate(&dir, "wide-open\n");
        let error =
            assert_candidate_access_profile(&dir, "customer-locked", &hex_sha256(b"wide-open\n"))
                .unwrap_err();
        assert!(error.contains("unrecognised access profile"), "{error}");

        // Absence, a directory in its place, and an implausible size are all
        // refusals: an appliance whose candidate cannot state what it is must
        // not be told it is fine.
        std::fs::remove_file(dir.join("usr/lib/neural-ice/access-policy")).unwrap();
        let error =
            assert_candidate_access_profile(&dir, "customer-locked", &authorised).unwrap_err();
        assert!(
            error.contains("carries no immutable access policy"),
            "{error}"
        );

        std::fs::create_dir_all(dir.join("usr/lib/neural-ice/access-policy")).unwrap();
        let error =
            assert_candidate_access_profile(&dir, "customer-locked", &authorised).unwrap_err();
        assert!(error.contains("not a regular file"), "{error}");
        std::fs::remove_dir(dir.join("usr/lib/neural-ice/access-policy")).unwrap();

        candidate(&dir, &"x".repeat(200));
        let error =
            assert_candidate_access_profile(&dir, "customer-locked", &authorised).unwrap_err();
        assert!(error.contains("implausible size"), "{error}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The TSS signature is a stable TPM wire structure. Parse its algorithms,
    /// bounded non-zero P-256 parameters and complete extent before DER encoding.
    #[test]
    fn tss_signatures_become_canonical_der() {
        let mut tss = vec![0x00, 0x18, 0x00, 0x0b, 0x00, 0x20];
        let mut r = [0x01u8; 32];
        r[0] = 0x80; // r's high bit set
        let mut s = [0x01u8; 32];
        s[0] = 0x00; // s has a leading zero
        tss.extend_from_slice(&r);
        tss.extend_from_slice(&[0x00, 0x20]);
        tss.extend_from_slice(&s);
        let der = tss_signature_to_der(&tss).expect("a valid TPMT_SIGNATURE must encode");
        assert_eq!(der[0], 0x30);
        assert_eq!(usize::from(der[1]), der.len() - 2);
        // r: 0x02 <len> 0x00 0x80 ...   (33 bytes of content)
        assert_eq!(der[2], 0x02);
        assert_eq!(der[3], 33);
        assert_eq!(der[4], 0x00);
        assert_eq!(der[5], 0x80);
        // s: the leading zero is stripped, so 31 bytes of content.
        let s_tag = 4 + usize::from(der[3]);
        assert_eq!(der[s_tag], 0x02);
        assert_eq!(der[s_tag + 1], 31);
        assert_ne!(der[s_tag + 2], 0x00);

        let short = [0x00, 0x18, 0x00, 0x0b, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01];
        assert_eq!(
            tss_signature_to_der(&short).unwrap(),
            [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]
        );

        let mut zero_scalar = short;
        zero_scalar[6] = 0;
        let mut order_scalar = vec![0x00, 0x18, 0x00, 0x0b, 0x00, 0x20];
        order_scalar.extend_from_slice(&[
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2,
            0xfc, 0x63, 0x25, 0x51,
        ]);
        order_scalar.extend_from_slice(&[0x00, 0x01, 0x01]);
        for invalid in [
            [&tss[..], &[0][..]].concat(),
            [&[0x00, 0x17][..], &tss[2..]].concat(),
            [&tss[..2], &[0x00, 0x0c][..], &tss[4..]].concat(),
            vec![0x00, 0x18, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x01, 0x01],
            vec![0x00, 0x18, 0x00, 0x0b, 0x00, 0x21],
            zero_scalar.to_vec(),
            order_scalar,
            tss[..tss.len() - 1].to_vec(),
        ] {
            assert!(tss_signature_to_der(&invalid).is_none());
        }
    }

    /// Differential shell/Rust vector: Rust must surface the exact read-only
    /// shell lifecycle gate's refusal and must invoke only its `status` branch.
    #[cfg(feature = "test-path-overrides")]
    #[test]
    fn rust_requires_the_shells_complete_lifecycle_status() {
        use std::os::unix::fs::PermissionsExt;

        let _guard = LIFECYCLE_ENV.lock().unwrap();
        let dir = scratch("lifecycle-status");
        let script = dir.join("gate");
        std::fs::write(
            &script,
            b"#!/bin/sh\n[ \"$1\" = status ] || exit 98\n[ \"${NI_TEST_LIFECYCLE_COMPLETE:-}\" = 1 ] || { echo missing-completion >&2; exit 7; }\n",
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::env::set_var("NI_OTA_FIRSTBOOT_TPM_CEREMONY", &script);
        std::env::remove_var("NI_TEST_LIFECYCLE_COMPLETE");
        let refused = assert_full_tpm_lifecycle().unwrap().unwrap_err();
        assert!(refused.starts_with("reinstall required"), "{refused}");
        assert!(refused.contains("missing-completion"), "{refused}");
        std::env::set_var("NI_TEST_LIFECYCLE_COMPLETE", "1");
        assert!(assert_full_tpm_lifecycle().unwrap().is_ok());
        std::env::remove_var("NI_TEST_LIFECYCLE_COMPLETE");
        std::env::remove_var("NI_OTA_FIRSTBOOT_TPM_CEREMONY");
        let _ = std::fs::remove_dir_all(dir);
    }
}
