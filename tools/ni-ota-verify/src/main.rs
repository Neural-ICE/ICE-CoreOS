//! ni-ota-verify — on-device OTA bundle verifier (ICE-Fabric ADR-0026 D3,
//! PLAN-ADR-0026-SIGNING §0 / P2).
//!
//! Verifies LOCAL FILES only. The OTA caller fetches the signed channel record
//! and BOM pair (oras, from the sovereign registry), hands the four files to
//! `verify`, applies the update strictly by the digests in the verified BOM,
//! runs its health gate, then calls `commit` to advance the applied-state
//! record. Signature verification is delegated to the image's pinned
//! /usr/bin/cosign — one verification stack, no crypto re-implemented here.
//!
//! Exit codes (the caller's contract — see README.md):
//!   0  verdict "pass" — or verdict "refuse" in SHADOW mode (enforce=0):
//!      shadow is log-only; the verdict is emitted, the caller decides nothing
//!      on the exit code.
//!   1  verdict "refuse" in ENFORCE mode (enforce=1) — do not apply.
//!      `commit` refusals also exit 1 (commit has no shadow semantics: it
//!      mutates state, so it is always enforced).
//!   2  internal error (missing cosign, unreadable config, …) — ALWAYS,
//!      regardless of mode: broken tooling never passes (fail-closed).

mod commit;
mod config;
mod runner;
mod state;
mod verify;

use std::collections::HashMap;

pub(crate) const EXIT_PASS: u8 = 0;
pub(crate) const EXIT_REFUSE: u8 = 1;
pub(crate) const EXIT_INTERNAL: u8 = 2;

pub(crate) const DEFAULT_CONFIG: &str = "/etc/neural-ice/ota.conf";

const USAGE: &str = "usage:
  ni-ota-verify verify --bom <path> --bom-sig <path> --record <path> --record-sig <path>
                       [--config /etc/neural-ice/ota.conf] [--device-channel <ch>]
                       [--device-compat <min,max>] [--applied-state <path>]
  ni-ota-verify commit --bom <path> [--config /etc/neural-ice/ota.conf] [--applied-state <path>]
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
        Some("commit") => commit::run(&args[1..]),
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
