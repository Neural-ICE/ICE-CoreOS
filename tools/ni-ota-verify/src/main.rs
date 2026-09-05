//! ni-ota-verify — on-device OTA bundle verifier (ICE-Fabric OTA verifier,
//! the ICE-Fabric OTA signing plan §0 / P2).
//!
//! Verifies LOCAL FILES only. `bootstrap` binds a physically delivered LAB
//! image to its signed BOM without trusting a channel record. The OTA caller
//! fetches the signed channel record, pulls the bundle exclusively by the OCI
//! manifest digest embedded in that record, and hands the local files plus the
//! observed digest to `verify`. It then applies strictly by the digests in the
//! verified BOM, runs its health gate, and calls `commit`
//! to advance the applied-state record. Signature verification is delegated to
//! the image's pinned /usr/bin/cosign — one verification stack, no crypto
//! re-implemented here.
//!
//! Exit codes (the caller's contract — see README.md):
//!   0  verdict "pass" — or a legacy/non-authority policy refusal in SHADOW
//!      mode (enforce=0). Authenticity, signed artifact bindings, target/ring
//!      authorization, anti-rollback, and bundle identity never exit 0.
//!   1  authority refusal in every mode, or any refusal in ENFORCE mode
//!      (enforce=1) — do not apply.
//!      `bootstrap` and `commit` refusals also exit 1 (state mutation has no
//!      shadow semantics and is always enforced).
//!   2  internal error (missing cosign, unreadable config, …) — ALWAYS,
//!      regardless of mode: broken tooling never passes (fail-closed).

mod access_profile_anchor;
mod atomic_state;
mod bootstrap;
mod commit;
mod config;
mod delegated;
mod device_policy;
mod preseal;
mod record;
mod release_manifest;
mod runner;
mod seed_closure;
mod state;
mod state_v1;
mod time_challenge;
mod trusted_time;
mod verify;

use std::collections::HashMap;
use std::io::Read;

pub(crate) const EXIT_PASS: u8 = 0;
pub(crate) const EXIT_REFUSE: u8 = 1;
pub(crate) const EXIT_INTERNAL: u8 = 2;

pub(crate) const DEFAULT_CONFIG: &str = "/etc/neural-ice/ota.conf";

const USAGE: &str = "usage:
  ni-ota-verify verify --bom <path> --bom-sig <path> --record <path> --record-sig <path>
                       --bundle-digest <sha256:64-lowercase-hex>
                       [--config /etc/neural-ice/ota.conf] [--device-channel <ch>]
                       [--device-compat <min,max>] [--applied-state <path>]
  ni-ota-verify bootstrap --bom <path> --bom-sig <path> --expected-train <train>
                          --current-os-ref <image@sha256:digest>
                          --current-seed-ref <40-hex-commit>
                          [--config /etc/neural-ice/ota.conf]
                          [--device-compat <min,max>] [--applied-state <path>]
  ni-ota-verify commit --bom <path> [--active-ring <lab|beta|stable>
                       --previous-ring <lab|beta|stable>]
                       [--config /etc/neural-ice/ota.conf] [--applied-state <path>]
  ni-ota-verify commit-state-v2 --bom <path> --release <path> --release-sig <path>
                       --snapshot <path> --snapshot-sig <path>
                       --trusted-time <path> --trusted-time-sig <path>
                       --candidate-root <path>
                       [--config /etc/neural-ice/ota.conf]
  ni-ota-verify guard-state-v2 --bom <path> --release <path> --release-sig <path>
                       --snapshot <path> --snapshot-sig <path>
                       --trusted-time <path> --trusted-time-sig <path>
                       --candidate-root <path>
                       [--config /etc/neural-ice/ota.conf]
  ni-ota-verify prepare-trusted-time-v2 --snapshot <path> --snapshot-sig <path>
                       --release <path> --release-sig <path>
                       [--config /etc/neural-ice/ota.conf]
  ni-ota-verify verify-delegation-snapshot --snapshot <path> --snapshot-sig <path>
                       --trusted-now <UTC-seconds>
                       --accepted-snapshot <path>
                       --accepted-delegation-seq <n> --accepted-delegation-sha256 <64hex>
                       [--config /etc/neural-ice/ota.conf]
  ni-ota-verify verify-delegated-beta --snapshot <path> --snapshot-sig <path>
                       --release <path> --release-sig <path>
                       --receipt <path> --receipt-sig <path> --trusted-now <UTC-seconds>
                       --accepted-snapshot <path>
                       --accepted-delegation-seq <n> --accepted-delegation-sha256 <64hex>
                       --candidate-root <path>
                       [--config /etc/neural-ice/ota.conf]
  ni-ota-verify verify-delegated-usb --snapshot <path> --snapshot-sig <path>
                       --release <path> --release-sig <path> --bom <path>
                       --record <path> --attestation <path> --attestation-sig <path>
                       --bundle-digest <sha256:...>
                       --current-os-ref <image@sha256:digest> --current-seed-ref <40hex>
                       --trusted-now <UTC-seconds> --candidate-root <path>
                       [--config /etc/neural-ice/ota.conf]
  ni-ota-verify verify-preseal-baseline --set <path>
                       --snapshot <path> --snapshot-sig <path>
                       --release <path> --release-sig <path> --bom <path>
                       --installer-authorization <path>
                       --installer-authorization-sig <path>
                       --sealed-set-sha256 <64hex>
                       --sealed-installer-authorization-sha256 <64hex>
                       --sealed-installer-authorization-signature-sha256 <64hex>
                       --current-os-ref <image@sha256:digest>
                       --current-os-manifest-digest <sha256:digest>
                       --current-seed-ref <40hex> --candidate-root <path>
                       --receipt-out <path> [--config /etc/neural-ice/ota.conf]
  ni-ota-verify release-plan --current <path> --candidate <path>
                       --registry-host <canonical OCI authority>
                       --hardware-target <id> --reader-version <n>
                       --supported-contracts <id[,id...]>
  ni-ota-verify verify-seed-closure --seed-root <dir named by the closure hex>
                       --pubkey <release public key PEM>
                       --registry-host <canonical OCI authority>
                       --hardware-target <id> --access-profile <p>
                       --device-channel <lab|beta|stable>
                       --trust-policy-id <id>
                       --expect-manifest <sha256:64-lowercase-hex>
                       --trusted-now <YYYY-MM-DDTHH:MM:SSZ>
                       --pcr-policy-digest <64hex> --pcr-policy-public-key-sha256 <64hex>
                       --pcr-policy-signature-sha256 <64hex> --pcr-policy-seq <n>
                       --expect-closure <sha256:64-lowercase-hex>
  ni-ota-verify capabilities
  ni-ota-verify device-policy [--config /etc/neural-ice/ota.conf]
  ni-ota-verify --version";

/// Environment/tooling failure — never a verification verdict. Always mapped
/// to EXIT_INTERNAL so a broken toolchain can never look like a pass (and,
/// in enforce mode, never like a clean refuse either).
#[derive(Debug)]
pub(crate) struct InternalError(pub String);

fn main() {
    std::process::exit(i32::from(run()));
}

fn run() -> u8 {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("verify") => verify::run(&args[1..]),
        Some("bootstrap") => bootstrap::run(&args[1..]),
        Some("commit") => commit::run(&args[1..]),
        Some("commit-state-v2") => atomic_state::run(&args[1..]),
        Some("guard-state-v2") => atomic_state::guard(&args[1..]),
        Some("prepare-trusted-time-v2") => time_challenge::run(&args[1..]),
        Some("verify-delegation-snapshot") => delegated::run(&args[1..]),
        Some("verify-delegated-beta") => delegated::run_beta(&args[1..]),
        Some("verify-delegated-usb") => delegated::run_usb(&args[1..]),
        Some("verify-preseal-baseline") => preseal::run(&args[1..]),
        Some("release-plan") => release_plan(&args[1..]),
        Some("verify-seed-closure") => seed_closure::run(&args[1..]),
        Some("device-policy") => device_policy::run(&args[1..]),
        Some("capabilities") if args.len() == 1 => {
            // Capability discovery is side-effect free and must work before
            // device configuration exists. Atomic state remains conditional;
            // the two ring contracts are implemented by this binary itself.
            let capability_ready =
                state_v1::capability_ready(std::path::Path::new(DEFAULT_CONFIG)).unwrap_or(false);
            if capability_ready {
                println!(
                    "{{\"features\":[\"atomic-state-v1\",\"bundle-digest-v1\",\"delegated-rings-v1\",\"transactional-ring-state-v1\"],\"schema\":1}}"
                );
            } else {
                println!("{{\"features\":[\"bundle-digest-v1\",\"delegated-rings-v1\",\"transactional-ring-state-v1\"],\"schema\":1}}");
            }
            return EXIT_PASS;
        }
        Some("--version" | "version") => {
            println!("ni-ota-verify {}", env!("CARGO_PKG_VERSION"));
            return EXIT_PASS;
        }
        _ => {
            eprintln!("{USAGE}");
            return EXIT_INTERNAL;
        }
    };
    match result {
        Ok(code) => code,
        Err(InternalError(msg)) => {
            eprintln!("ni-ota-verify: internal error: {msg}");
            EXIT_INTERNAL
        }
    }
}

/// `release-plan` — the only I/O the release-manifest reader gets: read two
/// local files, hand the bytes to the pure planner, print the canonical plan.
///
/// Registry authority and device capabilities are explicit arguments, never
/// sniffed from the environment, so an operator can reproduce a device's plan
/// off-device from the same two manifests.
///
/// No download, staging, activation, `bootc` or reboot happens here or
/// downstream of here: a plan is a statement about two documents.
///
/// Exit codes follow the binary's contract: 0 when a transition was
/// classified, 1 when the contract refused it, 2 for tooling failure.
fn release_plan(args: &[String]) -> Result<u8, InternalError> {
    let flags = parse_flags(
        args,
        &[
            "current",
            "candidate",
            "registry-host",
            "hardware-target",
            "reader-version",
            "supported-contracts",
        ],
    )?;
    let required = |name: &str| -> Result<&String, InternalError> {
        flags
            .get(name)
            .ok_or_else(|| InternalError(format!("release-plan needs --{name}\n{USAGE}")))
    };

    let current_path = required("current")?;
    let candidate_path = required("candidate")?;
    let registry_host = required("registry-host")?;
    let hardware_target = required("hardware-target")?.clone();
    let reader_version: u64 = required("reader-version")?.parse().map_err(|_| {
        InternalError("--reader-version must be a non-negative integer".to_string())
    })?;
    let supported_contracts: std::collections::BTreeSet<String> = required("supported-contracts")?
        .split(',')
        .filter(|entry| !entry.is_empty())
        .map(str::to_owned)
        .collect();
    if supported_contracts.is_empty() {
        return Err(InternalError(
            "--supported-contracts must list at least one contract".to_string(),
        ));
    }

    // Read at most ONE BYTE past the contract's limit. That is enough for the
    // parser to produce its own bounded refusal, and never enough for the size
    // of an attacker-supplied local file to decide this process's memory:
    // `std::fs::read` reserves capacity from the file's length, so a sparse or
    // hostile multi-gigabyte manifest would be allocated in full before the
    // limit was ever consulted. The bound is the canonical one, imported rather
    // than restated, so it cannot drift away from `parse`.
    let read = |path: &String| -> Result<Vec<u8>, InternalError> {
        let file = std::fs::File::open(path)
            .map_err(|e| InternalError(format!("cannot read {path}: {e}")))?;
        let mut buffer = Vec::new();
        file.take(release_manifest::MAX_MANIFEST_BYTES as u64 + 1)
            .read_to_end(&mut buffer)
            .map_err(|e| InternalError(format!("cannot read {path}: {e}")))?;
        Ok(buffer)
    };
    let current = read(current_path)?;
    let candidate = read(candidate_path)?;

    // Pure: no network, no staging, no activation, and the canonical digest is
    // hashed in-process so nothing on PATH can influence the verdict.
    let plan = release_manifest::classify(
        &current,
        &candidate,
        &release_manifest::DeviceCompatibility {
            hardware_target,
            reader_version,
            supported_contracts,
        },
        Some(registry_host),
    );
    // stdout carries the plan even on a refusal: the reason is the useful part.
    print!("{}", String::from_utf8_lossy(&plan.to_canonical_json()));
    Ok(
        if plan.classification == release_manifest::Classification::Refusal {
            EXIT_REFUSE
        } else {
            EXIT_PASS
        },
    )
}

/// Strict flag parser (std only): every flag takes exactly one value, unknown
/// or duplicated flags abort — an OTA path must never limp on a typo.
pub(crate) fn parse_flags(
    args: &[String],
    allowed: &[&str],
) -> Result<HashMap<String, String>, InternalError> {
    let mut out = HashMap::new();
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let name = flag
            .strip_prefix("--")
            .ok_or_else(|| InternalError(format!("unexpected argument '{flag}'\n{USAGE}")))?;
        if !allowed.contains(&name) {
            return Err(InternalError(format!("unknown flag --{name}\n{USAGE}")));
        }
        let value = it
            .next()
            .ok_or_else(|| InternalError(format!("flag --{name} needs a value")))?;
        if out.insert(name.to_string(), value.clone()).is_some() {
            return Err(InternalError(format!("flag --{name} given twice")));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::parse_flags;

    fn v(args: &[&str]) -> Vec<String> {
        args.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn parses_allowed_flags() {
        let flags = parse_flags(&v(&["--bom", "a", "--config", "b"]), &["bom", "config"]).unwrap();
        assert_eq!(flags["bom"], "a");
        assert_eq!(flags["config"], "b");
    }

    #[test]
    fn rejects_unknown_duplicate_and_valueless_flags() {
        assert!(parse_flags(&v(&["--nope", "x"]), &["bom"]).is_err());
        assert!(parse_flags(&v(&["--bom", "a", "--bom", "b"]), &["bom"]).is_err());
        assert!(parse_flags(&v(&["--bom"]), &["bom"]).is_err());
        assert!(parse_flags(&v(&["bare"]), &["bom"]).is_err());
    }
}
