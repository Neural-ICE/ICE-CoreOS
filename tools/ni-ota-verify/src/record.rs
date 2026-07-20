//! Strict parser for the signed OTA channel record v2.
//!
//! The record is the device-side authority that binds a release train to the
//! exact OCI bundle manifest fetched by the caller.  Keeping the parser here
//! prevents the online update path and the registry-backed bootstrap path from
//! drifting onto different acceptance rules.

use std::path::Path;

use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ChannelRecord {
    pub schema_version: u64,
    pub assigned_at: String,
    pub bundle_digest: String,
    pub bundle_seq: u64,
    pub channel: String,
    pub hardware_target: String,
    pub key_version: u64,
    pub train: String,
}

pub(crate) fn read(path: &Path) -> Result<ChannelRecord, String> {
    let bytes =
        std::fs::read(path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    parse(&bytes).map_err(|error| format!("{}: {error}", path.display()))
}

pub(crate) fn parse(bytes: &[u8]) -> Result<ChannelRecord, String> {
    let record: ChannelRecord = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    if record.schema_version != 2 {
        return Err(format!(
            "unsupported channel record schema_version {} (expected 2)",
            record.schema_version
        ));
    }
    if !is_canonical_sha256(&record.bundle_digest) {
        return Err(format!(
            "bundle_digest is not canonical sha256:<64 lowercase hex>: '{}'",
            record.bundle_digest
        ));
    }
    if !matches!(record.channel.as_str(), "beta" | "stable") {
        return Err(format!(
            "channel must be exactly 'beta' or 'stable': '{}'",
            record.channel
        ));
    }
    Ok(record)
}

pub(crate) fn is_canonical_sha256(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST: &str = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

    fn record(extra: &str, digest: &str, schema: u64) -> Vec<u8> {
        format!(
            r#"{{"assigned_at":"2026-07-21T00:00:00Z","bundle_digest":"{digest}","bundle_seq":7,"channel":"beta","hardware_target":"nvidia-gb10-arm64","key_version":1,"schema_version":{schema},"train":"0.44.18"{extra}}}"#
        )
        .into_bytes()
    }

    #[test]
    fn accepts_only_exact_v2_with_canonical_digest() {
        assert!(parse(&record("", DIGEST, 2)).is_ok());
        assert!(parse(&record("", DIGEST, 1)).is_err());
        assert!(parse(&record("", &DIGEST.to_uppercase(), 2)).is_err());
        assert!(parse(&record(",\"unexpected\":true", DIGEST, 2)).is_err());
    }

    #[test]
    fn digest_validator_is_exact() {
        assert!(is_canonical_sha256(DIGEST));
        assert!(!is_canonical_sha256(&format!("{DIGEST}0")));
        assert!(!is_canonical_sha256("sha256:abc"));
        assert!(!is_canonical_sha256(
            "SHA256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
        ));
    }
}
