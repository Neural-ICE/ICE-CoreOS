//! Centralized filesystem paths for the ICE-CoreOS appliance layout.
//!
//! These paths are contracts with other ICE-CoreOS components (licensing
//! agent, mDNS bring-up unit, OTA installer, ...). Some producers may not
//! exist yet on a given image, so every reader in `src/system/` that
//! consults one of these paths MUST fail gracefully (missing file ->
//! "unknown"/"-"/empty, never panic).

/// Cached licence status written by the licensing agent.
pub const LICENSE_CACHE: &str = "/var/lib/neural-ice/data/cache/license.cache";

/// Optional operator override for the dashboard's advertised access URL.
pub const ACCESS_URL_OVERRIDE: &str = "/var/lib/neural-ice/data/config/access_url";

/// mDNS hostname published by the avahi bring-up unit.
pub const MDNS_HOSTNAME: &str = "/run/neural-ice/mdns-hostname";

/// Appliance version file (primary location).
pub const VERSION_FILE: &str = "/usr/lib/neural-ice/version";

/// Appliance version file (fallback location).
pub const VERSION_FILE_FALLBACK: &str = "/etc/neural-ice/version";

/// Data volume used for the disk-usage gauge (`df -B1 <this>`).
pub const DATA_VOLUME: &str = "/var/lib/neural-ice/data";

/// AI stack services monitored on the dashboard, in display order.
// TODO(ICE-AC1): confirm real Quadlet unit names
pub const AI_STACK: &[&str] = &["vllm-node", "icecore", "qdrant", "vector", "caddy"];
