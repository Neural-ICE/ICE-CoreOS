//! Golden vectors of the v2 release attestation contract
//! (`docs/ota/V2-RELEASE-ATTESTATION.md`, mission B / T0).
//!
//! These tests pin the committed bytes under `tests/fixtures/v2-release/` to the
//! contract, independently of any verifier: the manifest is signed by the test
//! key, the receipts are the canonical bytes of schema §3.3, and the status is
//! the literal the licence gate and model-fetch compare. T1 (verifier), T2
//! (ceremony) and T3b (autoinstall) replay the SAME files; if one of them needs
//! a byte that is not here, the contract is what must change, not the consumer.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;
use sha2::{Digest, Sha256};

fn dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/v2-release")
}

fn read(name: &str) -> Vec<u8> {
    let path = dir().join(name);
    fs::read(&path).unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()))
}

fn hex_sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn json(name: &str) -> Value {
    serde_json::from_slice(&read(name)).unwrap_or_else(|error| panic!("{name}: {error}"))
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key]
        .as_str()
        .unwrap_or_else(|| panic!("missing string `{key}` in {value}"))
}

fn scratch(label: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "ni-v2-golden-{label}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir(&path).unwrap();
    path
}

/// `openssl dgst -sha256 -verify` over the exact bytes: the very check the host
/// importer performs (`ni-v2-seed-import.sh`) and the format `cosign verify-blob
/// --key` accepts. The signature file is base64 of an ASN.1 DER ECDSA signature.
fn signature_verifies(manifest: &[u8], sig_base64: &[u8]) -> bool {
    let work = scratch("verify");
    fs::write(work.join("manifest"), manifest).unwrap();
    fs::write(work.join("sig.b64"), sig_base64).unwrap();
    let decoded = Command::new("openssl")
        .args(["base64", "-d", "-A", "-in"])
        .arg(work.join("sig.b64"))
        .arg("-out")
        .arg(work.join("sig.der"))
        .output()
        .expect("the golden test needs the openssl CLI");
    if !decoded.status.success() {
        let _ = fs::remove_dir_all(&work);
        return false;
    }
    let verified = Command::new("openssl")
        .args(["dgst", "-sha256", "-verify"])
        .arg(dir().join("release-authorization.pub"))
        .arg("-signature")
        .arg(work.join("sig.der"))
        .arg(work.join("manifest"))
        .output()
        .expect("the golden test needs the openssl CLI")
        .status
        .success();
    let _ = fs::remove_dir_all(&work);
    verified
}

/// The authority of an image repository: everything before the first `/`.
fn authority(repository: &str) -> &str {
    repository.split('/').next().unwrap()
}

#[test]
fn manifest_is_signed_by_the_test_key_over_its_exact_bytes() {
    let manifest = read("release-manifest.json");
    let sig = read("release-manifest.json.sig");
    assert!(
        signature_verifies(&manifest, &sig),
        "the committed signature does not verify under the committed test key"
    );
    // Sensitivity: the check must fail on a manifest that differs by one byte,
    // and on the manifest with a trailing newline (no canonicalisation exists).
    let mut flipped = manifest.clone();
    flipped[0] ^= 0x01;
    assert!(
        !signature_verifies(&flipped, &sig),
        "a flipped byte verified"
    );
    let mut extended = manifest.clone();
    extended.push(b'\n');
    assert!(!signature_verifies(&extended, &sig), "an extra LF verified");
}

#[test]
fn manifest_carries_the_fields_the_contract_reads() {
    let golden = json("golden.json");
    let manifest = json("release-manifest.json");
    assert_eq!(text(&manifest, "schema"), "neural-ice-release-manifest-v1");
    assert_eq!(manifest["bundle_seq"], golden["expected"]["bundle_seq"]);
    assert_eq!(
        text(&manifest, "hardware_target"),
        text(&golden["inputs"], "hardware_target")
    );
    assert_eq!(
        text(&manifest, "release_id"),
        text(&golden["expected"], "release_id")
    );
    assert_eq!(
        text(&manifest["host"], "digest"),
        text(&golden["inputs"], "host_index_digest")
    );
    assert_eq!(
        authority(text(&manifest["host"], "repository")),
        text(&golden["inputs"], "release_authority")
    );
    assert_eq!(
        text(&manifest["host"], "repository"),
        text(&golden["expected"], "host_repository")
    );
}

#[test]
fn sealed_values_are_the_sha256_of_the_committed_bytes() {
    let golden = json("golden.json");
    let inputs = &golden["inputs"];
    assert_eq!(
        text(inputs, "sealed_manifest_sha256"),
        hex_sha256(&read("release-manifest.json"))
    );
    assert_eq!(
        text(inputs, "sealed_manifest_sig_sha256"),
        hex_sha256(&read("release-manifest.json.sig"))
    );
    assert_eq!(
        text(inputs, "sealed_key_sha256"),
        hex_sha256(&read("release-authorization.pub"))
    );
}

#[test]
fn candidate_root_carries_the_markers_the_verifier_reads() {
    let golden = json("golden.json");
    let inputs = &golden["inputs"];
    let marker = |relative: &str| read(&format!("candidate-root/usr/lib/neural-ice/{relative}"));
    for (relative, expected) in [
        ("hardware-target", text(inputs, "hardware_target")),
        ("appliance-variant", text(inputs, "variant")),
        (
            "signed-boot-trust-policy-id",
            text(inputs, "trust_policy_id"),
        ),
        ("access-policy", text(inputs, "access_profile")),
        // The lane marker: the image states the v2 attestation lane.
        ("ota-state-profile", "owner-sealed-ota-state-v2"),
    ] {
        assert_eq!(
            marker(relative),
            format!("{expected}\n").into_bytes(),
            "marker {relative}"
        );
    }
    // Key continuity installer -> host: the host carries the sealed key, bytes
    // for bytes, and none of the v1 OTA anchors.
    assert_eq!(
        marker("keys/release-authorization.pub"),
        read("release-authorization.pub")
    );
    assert!(!dir()
        .join("candidate-root/etc/neural-ice/keys/ota-root.pub")
        .exists());
    assert!(!dir()
        .join("candidate-root/usr/lib/neural-ice/ota-bootstrap")
        .exists());
}

fn expected_receipt(mode: &str, golden: &Value) -> Value {
    let inputs = &golden["inputs"];
    let expected = &golden["expected"];
    let seal = if mode == "manifest-digest" {
        serde_json::json!({
            "min_bundle_seq": null,
            "mode": "manifest-digest",
            "sealed_manifest_sha256": text(inputs, "sealed_manifest_sha256"),
        })
    } else {
        serde_json::json!({
            "min_bundle_seq": inputs["sealed_min_bundle_seq"],
            "mode": "floor",
            "sealed_manifest_sha256": null,
        })
    };
    serde_json::json!({
        "access_profile": text(inputs, "access_profile"),
        "bundle_seq": expected["bundle_seq"],
        "hardware_target": text(inputs, "hardware_target"),
        "host_index_digest": text(inputs, "host_index_digest"),
        "host_manifest_digest": text(inputs, "host_manifest_digest"),
        "host_repository": text(expected, "host_repository"),
        "manifest_sha256": text(inputs, "sealed_manifest_sha256"),
        "manifest_sig_sha256": text(inputs, "sealed_manifest_sig_sha256"),
        "release_id": text(expected, "release_id"),
        "release_key_sha256": text(inputs, "sealed_key_sha256"),
        "schema": "neural-ice-v2-release-receipt-v1",
        "seal": seal,
        "signed_boot_trust_policy_id": text(inputs, "trust_policy_id"),
        "variant": text(inputs, "variant"),
    })
}

#[test]
fn receipts_are_the_canonical_bytes_of_schema_3_3() {
    let golden = json("golden.json");
    for (mode, file) in [
        ("manifest-digest", "expected-receipt-manifest-digest.json"),
        ("floor", "expected-receipt-floor.json"),
    ] {
        let bytes = read(file);
        assert!(bytes.len() <= 4096, "{file} exceeds 4 KiB");
        assert_eq!(bytes.last(), Some(&b'\n'), "{file} lacks its final LF");
        assert!(
            !bytes[..bytes.len() - 1].contains(&b'\n'),
            "{file} has an inner LF"
        );
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value, expected_receipt(mode, &golden), "{file} content");
        // serde_json without `preserve_order` sorts keys and prints compactly:
        // the canonical form is whatever round-trips to the same bytes.
        let mut canonical = serde_json::to_vec(&value).unwrap();
        canonical.push(b'\n');
        assert_eq!(bytes, canonical, "{file} is not canonical");
        assert_eq!(
            hex_sha256(&bytes),
            text(&golden["expected"]["receipt_sha256"], mode),
            "{file} digest"
        );
    }
}

#[test]
fn status_is_the_literal_the_gate_and_model_fetch_compare() {
    let status = read("expected-authenticated-ota-status.json");
    assert_eq!(
        status,
        b"{\"committed_generation\":null,\"completion_version\":2,\"enforce_ready_verified\":false,\"profile\":\"owner-sealed-ota-state-v1\",\"schema\":\"neural-ice-authenticated-ota-status-v1\"}\n"
    );
    // The same literal is `HELD_STATUS` in the existing reader suite. Pin the two
    // together without editing that suite: its source must still contain the
    // fixture's bytes, Rust-escaped.
    let escaped = String::from_utf8(status)
        .unwrap()
        .replace('"', "\\\"")
        .replace('\n', "\\n");
    let reader = include_str!("owner_state_reader.rs");
    assert!(
        reader.contains(&format!("b\"{escaped}\"")),
        "owner_state_reader.rs no longer holds the status literal of the contract"
    );
}
