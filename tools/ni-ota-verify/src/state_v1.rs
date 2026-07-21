//! TPM capability gate for the atomic OTA state chain.
//!
//! This first, non-mutating layer attests the configured NV index's exact fixed
//! SHA-256 EXTEND policy. The public capability remains gated until later,
//! independently reviewed layers add both provisioning and the complete
//! pre-apply/post-health command set.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::InternalError;

pub(crate) const STATE_NV_INDEX: u32 = 0x0150_0002;
const LEGACY_NV_INDEX: u32 = 0x0150_0001;
const STATE_NV_ATTRIBUTES: &str =
    "authread|authwrite|no_da|nt=0x1|ownerread|platformcreate|policydelete";
const STATE_NV_DELETE_AUTH_POLICY: &str =
    "921f9fa2ce8c30bbf29b84500a8456188f1febc04f154e9eccca4d5b1bc8a25d";
const STATE_NV_NAME_UNWRITTEN: &str =
    "000b8ae052b814918370b191fe38782bb500041130d0665b1e7b2a368edcaf81eb62";
const STATE_NV_NAME_WRITTEN: &str =
    "000b571132a9688f4088f3696fa9bf5d5793be7483202cee08ceb2261f2bbe89b440";

// Index attestation alone is not an update protocol. A later slice may change
// this only in the same commit that exposes and tests the complete guard and
// commit command set. This prevents a manually pre-created index from
// advertising a protocol this binary cannot enforce.
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
    inspect_index(STATE_NV_INDEX).map(|_| true)
}

fn inspect_index(index: u32) -> Result<bool, InternalError> {
    let output = Command::new(tool("tpm2_nvreadpublic"))
        .arg(format!("0x{index:08x}"))
        .output()
        .map_err(|error| InternalError(format!("cannot execute tpm2_nvreadpublic: {error}")))?;
    if !output.status.success() {
        return Err(InternalError(format!(
            "tpm2_nvreadpublic failed for 0x{index:08x}"
        )));
    }
    inspect_state_index(
        &String::from_utf8(output.stdout)
            .map_err(|_| InternalError("tpm2_nvreadpublic returned non-UTF-8 output".into()))?,
        index,
    )
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

fn tool(name: &str) -> PathBuf {
    #[cfg(feature = "test-path-overrides")]
    if let Some(path) = std::env::var_os(format!("NI_OTA_{}", name.to_ascii_uppercase())) {
        return PathBuf::from(path);
    }
    PathBuf::from(format!("/usr/bin/{name}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner;

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
}
