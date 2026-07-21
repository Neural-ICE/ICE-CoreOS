//! TPM capability gate for the atomic OTA state chain.
//!
//! This first, non-mutating layer advertises the capability only when the
//! configured NV index has the exact fixed SHA-256 EXTEND policy. Provisioning
//! and state mutation are introduced by later, independently reviewed layers.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::InternalError;

pub(crate) const STATE_NV_INDEX: u32 = 0x0150_0002;
const LEGACY_NV_INDEX: u32 = 0x0150_0001;
const STATE_NV_ATTRIBUTES: &str = "authread|authwrite|no_da|nt=extend|ownerread|policydelete";

pub(crate) fn capability_ready(config_path: &Path) -> bool {
    let Ok(config) = crate::config::Config::load(config_path) else {
        return false;
    };
    if config.nv_index != Some(LEGACY_NV_INDEX) || config.state_nv_index != Some(STATE_NV_INDEX) {
        return false;
    }
    inspect_index(STATE_NV_INDEX).is_ok()
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
    let expected_header = format!("0x{index:08x}:");
    let mut in_index = false;
    let mut algorithm = None;
    let mut attributes = None;
    let mut size = None;
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed == expected_header {
            in_index = true;
            continue;
        }
        if !in_index {
            continue;
        }
        if !line.chars().next().is_some_and(char::is_whitespace) && trimmed.ends_with(':') {
            break;
        }
        if let Some(value) = trimmed.strip_prefix("hash algorithm:") {
            algorithm = Some(value.trim());
        } else if let Some(value) = trimmed.strip_prefix("friendly:") {
            let mut values: Vec<_> = value.trim().split('|').collect();
            values.sort_unstable();
            attributes = Some(values.join("|"));
        } else if let Some(value) = trimmed.strip_prefix("size:") {
            size = value.trim().parse::<u64>().ok();
        }
    }
    let expected_written = format!("{STATE_NV_ATTRIBUTES}|written");
    let written = attributes.as_deref() == Some(expected_written.as_str());
    if algorithm != Some("sha256")
        || (!written && attributes.as_deref() != Some(STATE_NV_ATTRIBUTES))
        || size != Some(32)
    {
        return Err(InternalError(format!(
            "TPM NV 0x{index:08x} is not the exact SHA-256 32-byte EXTEND index policy"
        )));
    }
    Ok(written)
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

    #[test]
    fn state_nv_attestation_requires_exact_index_type_size_and_policy() {
        let base = "0x01500002:\n  name: 000b00\n  hash algorithm: sha256\n  attributes:\n    friendly: authread|authwrite|no_da|nt=extend|ownerread|policydelete\n  size: 32\n";
        assert!(!inspect_state_index(base, STATE_NV_INDEX).unwrap());
        let written = base.replace("policydelete", "policydelete|written");
        assert!(inspect_state_index(&written, STATE_NV_INDEX).unwrap());
        assert!(inspect_state_index(&base.replace("size: 32", "size: 8"), STATE_NV_INDEX).is_err());
        assert!(
            inspect_state_index(&base.replace("nt=extend", "nt=counter"), STATE_NV_INDEX).is_err()
        );
        assert!(inspect_state_index(
            &base.replace("ownerread|", "ownerread|ownerwrite|"),
            STATE_NV_INDEX
        )
        .is_err());
    }
}
