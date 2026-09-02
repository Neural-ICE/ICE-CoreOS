//! Authenticated immutable ring policy consumed by the Fabric OTA controller.

use std::path::Path;

use serde::Serialize;

use crate::access_profile_anchor;
use crate::config::Config;
use crate::state::{AppliedStateStore, FileStateStore, StateRead};
use crate::{parse_flags, InternalError, DEFAULT_CONFIG, EXIT_PASS, EXIT_REFUSE};

#[derive(Debug, PartialEq, Eq, Serialize)]
struct DevicePolicy {
    accepted_rings: Vec<&'static str>,
    access_profile: String,
    active_ring: Option<String>,
    boot_trust_profile: &'static str,
    schema: &'static str,
    security_posture: &'static str,
}

fn policy_for(profile: &str, active_ring: Option<String>) -> Result<DevicePolicy, String> {
    let (accepted_rings, boot_trust_profile, security_posture) = match profile {
        "lab-managed" => (
            vec!["lab", "beta", "stable"],
            "neural-ice-secureboot-lab-v1",
            "sealed",
        ),
        "customer-locked" => (
            vec!["beta", "stable"],
            "neural-ice-secureboot-prod-v1",
            "sealed",
        ),
        "developer-diagnostic" => (Vec::new(), "neural-ice-secureboot-lab-v1", "debug"),
        _ => return Err("unknown enrolled access profile".into()),
    };
    if profile == "developer-diagnostic" {
        if active_ring.is_some() {
            return Err("developer-diagnostic may not follow a release ring".into());
        }
    } else if !active_ring
        .as_deref()
        .is_some_and(|ring| accepted_rings.contains(&ring))
    {
        return Err("durable active ring is outside the enrolled access profile".into());
    }
    Ok(DevicePolicy {
        accepted_rings,
        access_profile: profile.to_owned(),
        active_ring,
        boot_trust_profile,
        schema: "neural-ice-ota-device-policy-v1",
        security_posture,
    })
}

pub(crate) fn run(args: &[String]) -> Result<u8, InternalError> {
    let flags = parse_flags(args, &["config"])?;
    let config_path = flags.get("config").map_or(DEFAULT_CONFIG, String::as_str);
    let config = Config::load(Path::new(config_path))?;
    let state_dir = config
        .state_dir
        .as_ref()
        .ok_or_else(|| InternalError("device-policy requires state_dir".into()))?;
    let store = FileStateStore {
        path: state_dir.join("applied.json"),
    };
    let profile = match access_profile_anchor::enrolled_access_profile(state_dir, &store)? {
        Ok(profile) => profile,
        Err(reason) => {
            eprintln!("ni-ota-verify: device-policy REFUSED: {reason}");
            return Ok(EXIT_REFUSE);
        }
    };
    let active_ring = match store.read() {
        Ok(StateRead::Applied(state)) => state.active_ring.or(config.device_channel),
        Ok(StateRead::Unseeded) => config.device_channel,
        Err(reason) => {
            eprintln!("ni-ota-verify: device-policy REFUSED: {reason}");
            return Ok(EXIT_REFUSE);
        }
    };
    let policy = match policy_for(&profile, active_ring) {
        Ok(policy) => policy,
        Err(reason) => {
            eprintln!("ni-ota-verify: device-policy REFUSED: {reason}");
            return Ok(EXIT_REFUSE);
        }
    };
    println!(
        "{}",
        serde_json::to_string(&policy)
            .map_err(|error| InternalError(format!("cannot serialize device policy: {error}")))?
    );
    Ok(EXIT_PASS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_profile_ring_matrix() {
        for ring in ["lab", "beta", "stable"] {
            assert!(policy_for("lab-managed", Some(ring.into())).is_ok());
        }
        assert!(policy_for("customer-locked", Some("lab".into())).is_err());
        for ring in ["beta", "stable"] {
            assert!(policy_for("customer-locked", Some(ring.into())).is_ok());
        }
        assert!(policy_for("developer-diagnostic", None).is_ok());
        assert!(policy_for("developer-diagnostic", Some("lab".into())).is_err());
    }
}
