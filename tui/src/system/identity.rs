//! Appliance identity: hostname, mDNS name, access URL, version.

use std::fs;

use crate::paths;

/// Get the appliance hostname: /etc/hostname, else the kernel hostname
/// (transient, e.g. DHCP-set), else the product default.
pub fn get_hostname() -> String {
    fs::read_to_string("/etc/hostname")
        .ok()
        .or_else(|| fs::read_to_string("/proc/sys/kernel/hostname").ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && s != "localhost")
        .unwrap_or_else(|| "neural-ice".to_string())
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

/// Get the appliance OS version: version file (baked by the image CI), then
/// fallback version file, then os-release VERSION_ID. This is the OS version,
/// never this crate's version — an old image without the baked file shows the
/// base OS release rather than a misleading TUI number.
pub fn get_version() -> String {
    fs::read_to_string(paths::VERSION_FILE)
        .or_else(|_| fs::read_to_string(paths::VERSION_FILE_FALLBACK))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(os_release_version)
        .unwrap_or_else(|| "unknown".to_string())
}

/// VERSION_ID from /etc/os-release (unquoted value), if present.
fn os_release_version() -> Option<String> {
    let content = fs::read_to_string("/etc/os-release").ok()?;
    content.lines().find_map(|l| {
        l.strip_prefix("VERSION_ID=")
            .map(|v| v.trim().trim_matches('"').to_string())
            .filter(|v| !v.is_empty())
    })
}
