//! The shipped build (default features) must not carry the v2 test seams.
//!
//! `verify-retained-v2-release --root` replaces the live `/` and the status
//! reader's `NI_OTA_AUTH_STATUS_V2_ROOT` moves the root it reads: both exist only
//! under `test-path-overrides`. This file compiles only without it, which is the
//! second `cargo test --locked` run of the CI workflow.
#![cfg(not(feature = "test-path-overrides"))]

use std::process::Command;

const BINARY: &str = env!("CARGO_BIN_EXE_ni-ota-verify");

#[test]
fn the_root_flag_does_not_exist_in_the_shipped_binary() {
    let output = Command::new(BINARY)
        .args([
            "verify-retained-v2-release",
            "--manifest",
            "/nonexistent",
            "--manifest-sig",
            "/nonexistent",
            "--release-key",
            "/nonexistent",
            "--expected-receipt-sha256",
            &"0".repeat(64),
            "--receipt",
            "/nonexistent",
            "--scratch-dir",
            "/run/nonexistent",
            "--root",
            "/tmp",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("unknown flag --root"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn the_shipped_binary_names_no_v2_test_seam() {
    let bytes = std::fs::read(BINARY).unwrap();
    for seam in ["NI_OTA_AUTH_STATUS_V2_ROOT", "NI_OTA_COSIGN"] {
        assert!(
            !bytes
                .windows(seam.len())
                .any(|window| window == seam.as_bytes()),
            "the shipped binary contains `{seam}`"
        );
    }
}

/// Mode floor needs the freshness object (T7 / OS-0044), which does not exist:
/// the shipped binary refuses it before it reads any input.
#[test]
fn the_shipped_binary_refuses_mode_floor_until_the_freshness_object_exists() {
    let output = Command::new(BINARY)
        .args(["verify-v2-release"])
        .args([
            "--manifest",
            "/nonexistent/m",
            "--manifest-sig",
            "/nonexistent/s",
            "--release-key",
            "/nonexistent/k",
            "--sealed-key-sha256",
            &"0".repeat(64),
            "--sealed-min-bundle-seq",
            "1",
            "--hardware-target",
            "t",
            "--access-profile",
            "p",
            "--trust-policy-id",
            "i",
            "--variant",
            "sealed-lab",
            "--release-authority",
            "a",
            "--candidate-root",
            "/nonexistent/r",
            "--host-index-digest",
            &format!("sha256:{}", "0".repeat(64)),
            "--host-manifest-digest",
            &format!("sha256:{}", "0".repeat(64)),
            "--receipt",
            "/nonexistent/receipt",
        ])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(output.stdout.is_empty());
    assert!(
        stderr.contains("v2 release REFUSED: freshness-unsupported:"),
        "{stderr}"
    );
}
