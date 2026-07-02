use std::fs;
use std::process::{Command, Stdio};

use serde::Deserialize;

use crate::paths;

/// Enrollment state for the device
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum EnrollmentState {
    #[default]
    NotActivated, // No license, needs activation
    Activated, // Valid license, ready to use
    Expired,   // License expired, needs renewal
}

/// License tier
#[derive(Debug, Clone, Default, PartialEq)]
pub struct LicenseInfo {
    pub state: EnrollmentState,
    pub valid: bool,
    pub expiry: String,
    pub tier: Option<String>, // "Core", "Plus", etc.
}

#[derive(Debug, Deserialize)]
struct CachedLicenseRecord {
    status: Option<String>,
    license_expiry: Option<String>,
}

fn load_cached_license() -> Option<CachedLicenseRecord> {
    // ICE-CoreOS layout: license cache lives on the LUKS-encrypted /var/lib
    // volume, persisting across reboots and OTA updates. Missing file
    // (licensing agent not provisioned yet) is not an error here — the
    // dashboard just reports "not activated".
    let content = fs::read_to_string(paths::LICENSE_CACHE).ok()?;
    serde_json::from_str(&content).ok()
}

/// Get full license information including enrollment state
pub fn get_license_info() -> LicenseInfo {
    let (valid, expiry) = get_license_status();

    // Determine enrollment state
    let state = if valid {
        EnrollmentState::Activated
    } else if license_cache_exists() {
        // Cache exists but invalid = expired
        EnrollmentState::Expired
    } else {
        EnrollmentState::NotActivated
    };

    let tier = get_license_tier();

    LicenseInfo {
        state,
        valid,
        expiry,
        tier,
    }
}

/// Check if license cache file exists (indicates previous activation).
fn license_cache_exists() -> bool {
    fs::metadata(paths::LICENSE_CACHE).is_ok()
}

/// Get the license tier from cache or command
fn get_license_tier() -> Option<String> {
    None
}

/// Get device fingerprint for activation URL
#[allow(dead_code)]
pub fn get_device_fingerprint() -> Option<String> {
    // Try command first
    Command::new("/usr/local/bin/neuralice-license")
        .args(["fingerprint"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()
        .and_then(|output| {
            if output.status.success() {
                let fp = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !fp.is_empty() && fp.len() > 8 {
                    // Return shortened fingerprint for URL (first 12 chars)
                    return Some(fp[..12.min(fp.len())].to_string());
                }
            }
            None
        })
}

/// Get license status: (valid, expiry_string)
pub fn get_license_status() -> (bool, String) {
    if let Some(cache) = load_cached_license() {
        let valid = matches!(cache.status.as_deref(), Some("valid"));
        let expiry = cache
            .license_expiry
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| {
                if valid {
                    "Active".to_string()
                } else {
                    "Not validated".to_string()
                }
            });
        return (valid, expiry);
    }

    (false, "Not validated".to_string())
}
