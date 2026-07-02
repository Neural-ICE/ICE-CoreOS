//! Appliance identity: hostname, mDNS name, access URL, version.

use std::fs;

use crate::paths;

/// Get the appliance hostname.
pub fn get_hostname() -> String {
    fs::read_to_string("/etc/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Get the mDNS hostname published by the avahi bring-up unit, if any.
pub fn get_mdns_hostname() -> Option<String> {
    fs::read_to_string(paths::MDNS_HOSTNAME)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Get the device access URL: explicit override, else mDNS hostname, else
/// IP address, else a generic fallback.
pub fn get_access_url(mdns_hostname: &Option<String>, ip_address: &str) -> String {
    if let Ok(url) = fs::read_to_string(paths::ACCESS_URL_OVERRIDE) {
        let url = url.trim();
        if !url.is_empty() {
            return url.to_string();
        }
    }

    if let Some(hostname) = mdns_hostname {
        return format!("https://{hostname}.local");
    }

    if !ip_address.is_empty() && ip_address != "unknown" {
        return format!("https://{ip_address}");
    }

    "https://neural-ice.local".to_string()
}

/// Get the appliance version: version file, then fallback version file,
/// then the version baked into this binary at build time.
pub fn get_version() -> String {
    fs::read_to_string(paths::VERSION_FILE)
        .or_else(|_| fs::read_to_string(paths::VERSION_FILE_FALLBACK))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string())
}
