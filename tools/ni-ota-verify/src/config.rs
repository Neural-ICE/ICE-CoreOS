//! /etc/neural-ice/ota.conf parsing (key=value, '#' comments — the staged file
//! lives in image/bootc-overlay/etc/neural-ice/ota.conf).
//!
//! Unknown keys are ignored: the file also carries fetch-side settings
//! (registry, channel_ref, bundle_ref, nv_index, …) that belong to the OTA
//! caller / later phases, not to this verifier.

use std::path::{Path, PathBuf};

use crate::InternalError;

const DEFAULT_HARDWARE_TARGET_FILE: &str = "/usr/lib/neural-ice/hardware-target";
const DEFAULT_APPLIANCE_VARIANT_FILE: &str = "/usr/lib/neural-ice/appliance-variant";
const DEFAULT_MIN_DELEGATION_SEQ_FILE: &str = "/usr/lib/neural-ice/ota-min-delegation-seq";
const DEFAULT_BOOTSTRAP_DELEGATION_SHA256_FILE: &str =
    "/usr/lib/neural-ice/ota-bootstrap-delegation-sha256";

pub(crate) fn immutable_hardware_target() -> Result<String, InternalError> {
    #[cfg(feature = "test-path-overrides")]
    let path = std::env::var_os("NI_OTA_HARDWARE_TARGET_FILE").map_or_else(
        || PathBuf::from(DEFAULT_HARDWARE_TARGET_FILE),
        PathBuf::from,
    );
    #[cfg(not(feature = "test-path-overrides"))]
    let path = PathBuf::from(DEFAULT_HARDWARE_TARGET_FILE);
    let target = std::fs::read_to_string(&path).map_err(|e| {
        InternalError(format!(
            "unreadable immutable hardware target {}: {e}",
            path.display()
        ))
    })?;
    let target = target.trim();
    let valid = !target.is_empty()
        && target.len() <= 64
        && target
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_'))
        && target
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && target
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric);
    if !valid {
        return Err(InternalError(format!(
            "invalid immutable hardware target in {}",
            path.display()
        )));
    }
    Ok(target.to_string())
}

pub(crate) fn immutable_appliance_variant() -> Result<String, InternalError> {
    #[cfg(feature = "test-path-overrides")]
    let path = std::env::var_os("NI_OTA_APPLIANCE_VARIANT_FILE").map_or_else(
        || PathBuf::from(DEFAULT_APPLIANCE_VARIANT_FILE),
        PathBuf::from,
    );
    #[cfg(not(feature = "test-path-overrides"))]
    let path = PathBuf::from(DEFAULT_APPLIANCE_VARIANT_FILE);
    let variant = std::fs::read_to_string(&path).map_err(|error| {
        InternalError(format!(
            "unreadable immutable appliance variant {}: {error}",
            path.display()
        ))
    })?;
    match variant.trim() {
        "debug" | "prod" => Ok(variant.trim().to_owned()),
        _ => Err(InternalError(format!(
            "invalid immutable appliance variant in {}",
            path.display()
        ))),
    }
}

pub(crate) fn immutable_minimum_delegation_seq() -> Result<u64, InternalError> {
    #[cfg(feature = "test-path-overrides")]
    let path = std::env::var_os("NI_OTA_MIN_DELEGATION_SEQ_FILE").map_or_else(
        || PathBuf::from(DEFAULT_MIN_DELEGATION_SEQ_FILE),
        PathBuf::from,
    );
    #[cfg(not(feature = "test-path-overrides"))]
    let path = PathBuf::from(DEFAULT_MIN_DELEGATION_SEQ_FILE);
    let value = std::fs::read_to_string(&path).map_err(|error| {
        InternalError(format!(
            "unreadable immutable minimum delegation sequence {}: {error}",
            path.display()
        ))
    })?;
    let sequence = value.trim().parse::<u64>().map_err(|_| {
        InternalError(format!(
            "invalid immutable minimum delegation sequence in {}",
            path.display()
        ))
    })?;
    if !(1..=9_007_199_254_740_991).contains(&sequence) {
        return Err(InternalError(format!(
            "invalid immutable minimum delegation sequence in {}",
            path.display()
        )));
    }
    Ok(sequence)
}

pub(crate) fn immutable_bootstrap_delegation_sha256() -> Result<String, InternalError> {
    #[cfg(feature = "test-path-overrides")]
    let path = std::env::var_os("NI_OTA_BOOTSTRAP_DELEGATION_SHA256_FILE").map_or_else(
        || PathBuf::from(DEFAULT_BOOTSTRAP_DELEGATION_SHA256_FILE),
        PathBuf::from,
    );
    #[cfg(not(feature = "test-path-overrides"))]
    let path = PathBuf::from(DEFAULT_BOOTSTRAP_DELEGATION_SHA256_FILE);
    let value = std::fs::read_to_string(&path).map_err(|error| {
        InternalError(format!(
            "unreadable immutable bootstrap delegation SHA-256 {}: {error}",
            path.display()
        ))
    })?;
    let digest = value.trim();
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(InternalError(format!(
            "invalid immutable bootstrap delegation SHA-256 in {}",
            path.display()
        )));
    }
    Ok(digest.to_owned())
}

pub(crate) struct Config {
    /// false = shadow for non-authority rollout checks; authenticity, signed
    /// bindings, target/ring, anti-rollback and bundle identity still exit 1;
    /// true = enforce (refuse exits nonzero). A missing/stripped `enforce`
    /// key defaults to TRUE: an incomplete config must lean strict, never
    /// silently downgrade to log-only (fail-closed bias).
    pub enforce: bool,
    pub root_pubkey: Option<PathBuf>,
    pub state_dir: Option<PathBuf>,
    /// Legacy monotonic bundle floor. It remains reserved while state-v1 adds
    /// a separate hash-chain anchor; an upgrade must never repurpose it.
    pub nv_index: Option<u32>,
    /// TPM NV EXTEND index for the complete state-v1 manifest chain.
    pub state_nv_index: Option<u32>,
    /// Optional `device_channel=` key — the channel THIS device follows.
    /// Instance identity, so the vanilla image ships it unset; the
    /// `--device-channel` flag overrides.
    pub device_channel: Option<String>,
    /// Optional `device_compat_min=`/`device_compat_max=` pair — the
    /// appliance⇄thin-client compat range this device supports.
    /// Both or neither: a half-configured range aborts (fail-closed).
    pub device_compat: Option<(i64, i64)>,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, InternalError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| InternalError(format!("unreadable config {}: {e}", path.display())))?;
        Self::parse(&text, path)
    }

    fn parse(text: &str, path: &Path) -> Result<Self, InternalError> {
        let mut enforce: Option<bool> = None;
        let mut root_pubkey = None;
        let mut state_dir = None;
        let mut device_channel = None;
        let mut nv_index = None;
        let mut state_nv_index = None;
        let mut compat_min: Option<i64> = None;
        let mut compat_max: Option<i64> = None;

        for (lineno, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (key, value) = line.split_once('=').ok_or_else(|| {
                InternalError(format!(
                    "malformed config {} line {}: expected key=value",
                    path.display(),
                    lineno + 1
                ))
            })?;
            let (key, value) = (key.trim(), value.trim());
            let int = |what: &str| -> Result<i64, InternalError> {
                value.parse().map_err(|_| {
                    InternalError(format!(
                        "config {}: {what} is not an integer: '{value}'",
                        path.display()
                    ))
                })
            };
            match key {
                // exactly "0"/"1": an unparseable enforce flag must never be
                // guessed into shadow mode.
                "enforce" => match value {
                    "0" => enforce = Some(false),
                    "1" => enforce = Some(true),
                    other => {
                        return Err(InternalError(format!(
                            "config {}: enforce must be 0 or 1, got '{other}'",
                            path.display()
                        )))
                    }
                },
                "root_pubkey" => root_pubkey = Some(PathBuf::from(value)),
                "state_dir" => state_dir = Some(PathBuf::from(value)),
                "nv_index" => nv_index = Some(parse_nv_index(value, path, "nv_index")?),
                "state_nv_index" => {
                    state_nv_index = Some(parse_nv_index(value, path, "state_nv_index")?)
                }
                "device_channel" => device_channel = Some(value.to_string()),
                "device_compat_min" => compat_min = Some(int("device_compat_min")?),
                "device_compat_max" => compat_max = Some(int("device_compat_max")?),
                _ => {} // fetch-side / future keys — not ours
            }
        }

        let device_compat = match (compat_min, compat_max) {
            (Some(lo), Some(hi)) if lo <= hi => Some((lo, hi)),
            (Some(lo), Some(hi)) => {
                return Err(InternalError(format!(
                    "config {}: device compat range inverted ({lo} > {hi})",
                    path.display()
                )))
            }
            (None, None) => None,
            _ => {
                return Err(InternalError(format!(
                    "config {}: device_compat_min/device_compat_max must be set together",
                    path.display()
                )))
            }
        };

        Ok(Config {
            enforce: enforce.unwrap_or(true),
            root_pubkey,
            state_dir,
            nv_index,
            state_nv_index,
            device_channel,
            device_compat,
        })
    }
}

fn parse_nv_index(value: &str, path: &Path, key: &str) -> Result<u32, InternalError> {
    let hex = value.strip_prefix("0x").ok_or_else(|| {
        InternalError(format!(
            "config {}: {key} must be an exact hexadecimal TPM NV index",
            path.display()
        ))
    })?;
    if hex.len() != 8 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(InternalError(format!(
            "config {}: {key} must be 0x followed by eight hexadecimal digits",
            path.display()
        )));
    }
    u32::from_str_radix(hex, 16)
        .map_err(|_| InternalError(format!("config {}: invalid {key}", path.display())))
}

/// `--device-compat <min,max>` flag value.
pub(crate) fn parse_compat_flag(value: &str) -> Result<(i64, i64), InternalError> {
    let (lo, hi) = value.split_once(',').ok_or_else(|| {
        InternalError(format!("--device-compat expects <min,max>, got '{value}'"))
    })?;
    let parse = |s: &str| -> Result<i64, InternalError> {
        s.trim()
            .parse()
            .map_err(|_| InternalError(format!("--device-compat: '{s}' is not an integer")))
    };
    let (lo, hi) = (parse(lo)?, parse(hi)?);
    if lo > hi {
        return Err(InternalError(format!(
            "--device-compat range inverted ({lo} > {hi})"
        )));
    }
    Ok((lo, hi))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Result<Config, InternalError> {
        Config::parse(text, Path::new("test.conf"))
    }

    #[test]
    fn parses_the_staged_ota_conf_shape() {
        let cfg = parse(
            "# comment\nenforce=0\nnv_index=0x01500001\nstate_nv_index=0x01500002\nregistry=registry.neural-ice.ch\n\
             root_pubkey=/etc/neural-ice/keys/ota-root.pub\nstate_dir=/var/lib/neural-ice/ota\n",
        )
        .unwrap();
        assert!(!cfg.enforce);
        assert_eq!(
            cfg.root_pubkey.unwrap(),
            PathBuf::from("/etc/neural-ice/keys/ota-root.pub")
        );
        assert_eq!(
            cfg.state_dir.unwrap(),
            PathBuf::from("/var/lib/neural-ice/ota")
        );
        assert!(cfg.device_channel.is_none());
        assert!(cfg.device_compat.is_none());
        assert_eq!(cfg.nv_index, Some(0x0150_0001));
        assert_eq!(cfg.state_nv_index, Some(0x0150_0002));
    }

    #[test]
    fn missing_enforce_defaults_to_enforce() {
        assert!(parse("root_pubkey=/k\n").unwrap().enforce);
    }

    #[test]
    fn bad_enforce_and_malformed_lines_abort() {
        assert!(parse("enforce=yes\n").is_err());
        assert!(parse("enforce\n").is_err());
        assert!(parse("nv_index=0x1\n").is_err());
        assert!(parse("state_nv_index=01500002\n").is_err());
    }

    #[test]
    fn compat_pair_is_all_or_nothing_and_ordered() {
        let cfg = parse("enforce=0\ndevice_compat_min=1\ndevice_compat_max=3\n").unwrap();
        assert_eq!(cfg.device_compat, Some((1, 3)));
        assert!(parse("enforce=0\ndevice_compat_min=1\n").is_err());
        assert!(parse("enforce=0\ndevice_compat_min=4\ndevice_compat_max=3\n").is_err());
    }

    #[test]
    fn compat_flag_parses_and_rejects_garbage() {
        assert_eq!(parse_compat_flag("1,3").unwrap(), (1, 3));
        assert!(parse_compat_flag("3").is_err());
        assert!(parse_compat_flag("a,b").is_err());
        assert!(parse_compat_flag("4,1").is_err());
    }
}
