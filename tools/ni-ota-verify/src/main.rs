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

mod bootstrap;
mod commit;
mod config;
mod delegated;
mod record;
mod runner;
mod state;
mod state_v1;
#[allow(
    dead_code,
    reason = "used by the next stacked atomic-state command layer"
)]
mod trusted_time;
mod verify;

use std::collections::HashMap;

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
  ni-ota-verify commit --bom <path> [--config /etc/neural-ice/ota.conf] [--applied-state <path>]
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
                       [--config /etc/neural-ice/ota.conf]
  ni-ota-verify verify-delegated-usb --snapshot <path> --snapshot-sig <path>
                       --release <path> --release-sig <path> --bom <path>
                       --record <path> --attestation <path> --attestation-sig <path>
                       --bundle-digest <sha256:...>
                       --current-os-ref <image@sha256:digest> --current-seed-ref <40hex>
                       --trusted-now <UTC-seconds>
                       [--accepted-snapshot <path>]
                       [--accepted-delegation-seq <n> --accepted-delegation-sha256 <64hex>]
                       [--config /etc/neural-ice/ota.conf]
  ni-ota-verify capabilities
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
        Some("verify-delegation-snapshot") => delegated::run(&args[1..]),
        Some("verify-delegated-beta") => delegated::run_beta(&args[1..]),
        Some("verify-delegated-usb") => delegated::run_usb(&args[1..]),
        Some("capabilities") if args.len() == 1 => {
            let capability_ready =
                match state_v1::capability_ready(std::path::Path::new(DEFAULT_CONFIG)) {
                    Ok(ready) => ready,
                    Err(InternalError(message)) => {
                        eprintln!("ni-ota-verify: internal error: {message}");
                        return EXIT_INTERNAL;
                    }
                };
            if capability_ready {
                println!(
                    "{{\"schema\":1,\"features\":[\"atomic-state-v1\",\"bundle-digest-v1\"]}}"
                );
            } else {
                println!("{{\"schema\":1,\"features\":[\"bundle-digest-v1\"]}}");
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
