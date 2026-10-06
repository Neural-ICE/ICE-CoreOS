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

// ---------------------------------------------------------------------------
// The completed-appliance vector (contract §6, §6.5) and the sealed cmdline (§11).
// ---------------------------------------------------------------------------

const MODES: [&str; 2] = ["manifest-digest", "floor"];
const OTA_DIR: &str = "var/lib/neural-ice/ota";

fn completed(mode: &str, relative: &str) -> Vec<u8> {
    read(&format!("completed/{mode}/{relative}"))
}

/// The one canonical form of the contract (§6.2): sorted keys, compact, ASCII, one
/// final LF. `serde_json` without `preserve_order` is what T1's reader re-serialises
/// with, so a byte-equal round trip is exactly the reader's acceptance test.
fn is_canonical(bytes: &[u8]) -> bool {
    let Ok(value) = serde_json::from_slice::<Value>(bytes) else {
        return false;
    };
    let mut canonical = serde_json::to_vec(&value).unwrap();
    canonical.push(b'\n');
    canonical == bytes && bytes.is_ascii()
}

fn keys(value: &Value) -> Vec<&str> {
    value
        .as_object()
        .unwrap_or_else(|| panic!("not an object: {value}"))
        .keys()
        .map(String::as_str)
        .collect()
}

#[test]
fn completed_evidence_is_canonical_and_closed() {
    let golden = json("golden.json");
    for mode in MODES {
        let bytes = completed(mode, &format!("{OTA_DIR}/owner-ceremony-evidence-v2.json"));
        assert!(bytes.len() <= 16 * 1024, "{mode}: evidence over 16 KiB");
        assert!(is_canonical(&bytes), "{mode}: evidence is not canonical");
        assert!(
            !bytes[..bytes.len() - 1].contains(&b'\n'),
            "{mode}: inner LF"
        );
        let evidence: Value = serde_json::from_slice(&bytes).unwrap();
        // serde_json iterates a map in sorted order, so these are the sorted key sets.
        assert_eq!(
            keys(&evidence),
            [
                "access_profile_anchor",
                "data_luks",
                "device_root_name",
                "install_identity",
                "ota_state",
                "schema",
                "srk_name",
                "system_luks",
                "tpm_state",
                "v2_release"
            ],
            "{mode}: top-level key set (no `ota_preseal`)"
        );
        assert_eq!(
            text(&evidence, "schema"),
            "neural-ice-owner-ceremony-evidence-v2-lane2"
        );
        assert_eq!(
            keys(&evidence["access_profile_anchor"]),
            ["json_sha256", "signature_sha256", "spki_sha256"]
        );
        assert_eq!(
            keys(&evidence["install_identity"]),
            [
                "install_source",
                "installed_at",
                "installer_sealed_identity_sha256",
                "release_identity_sha256",
                "schema"
            ]
        );
        assert_eq!(
            keys(&evidence["ota_state"]).len(),
            16,
            "{mode}: ota_state has sixteen keys"
        );
        assert_eq!(
            keys(&evidence["tpm_state"]),
            [
                "freshness_counter",
                "freshness_public_sha256",
                "install_counter",
                "install_public_sha256",
                "profile_binding",
                "schema"
            ]
        );
        for luks in ["data_luks", "system_luks"] {
            assert_eq!(
                keys(&evidence[luks]),
                [
                    "keyslot",
                    "pcr_bank",
                    "pcrs",
                    "policy_hash",
                    "policy_public_key_sha256",
                    "schema",
                    "sealed_object_sha256",
                    "srk_sha256",
                    "token_sha256"
                ]
            );
        }
        let release = &evidence["v2_release"];
        assert_eq!(
            keys(release),
            [
                "bundle_seq",
                "manifest_sha256",
                "manifest_sig_sha256",
                "receipt_schema",
                "receipt_sha256",
                "release_id",
                "release_key_sha256"
            ]
        );
        let inputs = &golden["inputs"];
        assert_eq!(release["bundle_seq"], golden["expected"]["bundle_seq"]);
        assert_eq!(
            text(release, "manifest_sha256"),
            text(inputs, "sealed_manifest_sha256")
        );
        assert_eq!(
            text(release, "manifest_sig_sha256"),
            text(inputs, "sealed_manifest_sig_sha256")
        );
        assert_eq!(
            text(release, "release_key_sha256"),
            text(inputs, "sealed_key_sha256")
        );
        assert_eq!(
            text(release, "receipt_schema"),
            "neural-ice-v2-release-receipt-v1"
        );
        assert_eq!(
            text(release, "release_id"),
            text(&golden["expected"], "release_id")
        );
        // The invariants of §6.4 the parser enforces.
        assert_eq!(
            evidence["ota_state"]["baseline_floor"], release["bundle_seq"],
            "{mode}: floor == bundle_seq"
        );
        let identity = &evidence["install_identity"];
        assert_eq!(
            text(identity, "release_identity_sha256"),
            text(release, "manifest_sha256"),
            "{mode}: release identity is the manifest digest"
        );
        assert_eq!(text(identity, "install_source"), "medium");
        assert_eq!(text(identity, "installed_at"), "1970-01-01T00:00:00Z");
        // The TPM objects are those of the v1 lane, unchanged.
        let ota = &evidence["ota_state"];
        assert_eq!(text(ota, "profile"), "owner-sealed-ota-state-v1");
        assert_eq!(text(ota, "floor_index"), "0x01500001");
        assert_eq!(text(ota, "floor_attributes"), "0x62008");
        assert_eq!(text(ota, "anchor_index"), "0x01500002");
        assert_eq!(text(ota, "anchor_attributes"), "0x2060048");
        assert_eq!(text(ota, "anchor_state_at_completion"), "pristine");
        assert_eq!(
            text(ota, "anchor_name_at_completion"),
            text(ota, "anchor_pristine_name")
        );
        assert_eq!(ota["clear_protected_at_completion"], Value::Bool(true));
    }
}

#[test]
fn completed_digest_chain_and_completion_record_match() {
    let golden = json("golden.json");
    for mode in MODES {
        let evidence = completed(mode, &format!("{OTA_DIR}/owner-ceremony-evidence-v2.json"));
        let expected = &golden["expected"]["completed"][mode];
        assert_eq!(hex_sha256(&evidence), text(expected, "evidence_sha256"));
        let mut message = b"neural-ice:tpm:owner-ceremony-completion:v2\0".to_vec();
        message.extend_from_slice(&evidence);
        let digest = hex_sha256(&message);
        assert_eq!(digest, text(expected, "completion_digest_sha256"));
        // What `completion-inspect` prints, byte for byte (§6.1).
        assert_eq!(
            completed(mode, "completion-inspection.json"),
            format!(
                "{{\"completion_version\":2,\"evidence_digest_sha256\":\"{digest}\",\"schema\":\"neural-ice-owner-ceremony-completion-inspection-v1\"}}\n"
            )
            .into_bytes(),
            "{mode}: completion record"
        );
        // The receipt digest the evidence carries is the digest of receipt.json.
        let receipt = completed(mode, &format!("{OTA_DIR}/v2-release/receipt.json"));
        assert_eq!(hex_sha256(&receipt), text(expected, "receipt_sha256"));
        assert_eq!(
            text(&golden["expected"]["receipt_sha256"], mode),
            text(expected, "receipt_sha256")
        );
        let parsed: Value = serde_json::from_slice(&evidence).unwrap();
        assert_eq!(
            text(&parsed["v2_release"], "receipt_sha256"),
            hex_sha256(&receipt)
        );
    }
}

#[test]
fn completed_persisted_layout_is_the_contract_footprint() {
    for mode in MODES {
        // Copies of the top-level files: no drift between the two sets.
        let input = format!("{OTA_DIR}/v2-release-input-v1");
        assert_eq!(
            completed(mode, &format!("{input}/release-manifest.json")),
            read("release-manifest.json")
        );
        assert_eq!(
            completed(mode, &format!("{input}/release-manifest.json.sig")),
            read("release-manifest.json.sig")
        );
        assert_eq!(
            completed(mode, &format!("{OTA_DIR}/v2-release/receipt.json")),
            read(&format!("expected-receipt-{mode}.json"))
        );
        // The installer's canonical identity file is the object the evidence embeds.
        let identity = completed(
            mode,
            &format!("{OTA_DIR}/owner-ceremony-install-identity-v1.json"),
        );
        assert!(is_canonical(&identity), "{mode}: identity not canonical");
        let evidence: Value = serde_json::from_slice(&completed(
            mode,
            &format!("{OTA_DIR}/owner-ceremony-evidence-v2.json"),
        ))
        .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&identity).unwrap(),
            evidence["install_identity"]
        );
        // Exactly the v2-lane files, and none of the other lane's.
        let mut files = Vec::new();
        collect(&dir().join(format!("completed/{mode}")), "", &mut files);
        files.sort();
        let mut expected: Vec<String> = [
            "completion-inspection.json".to_string(),
            format!("{OTA_DIR}/owner-ceremony-evidence-v2.json"),
            format!("{OTA_DIR}/owner-ceremony-install-identity-v1.json"),
            format!("{OTA_DIR}/v2-release-input-v1/release-manifest.json"),
            format!("{OTA_DIR}/v2-release-input-v1/release-manifest.json.sig"),
            format!("{OTA_DIR}/v2-release/receipt.json"),
        ]
        .into();
        expected.sort();
        assert_eq!(files, expected, "{mode}: completed tree");
        assert!(!files.iter().any(|f| f.contains("preseal")));
    }
}

fn collect(root: &Path, prefix: &str, out: &mut Vec<String>) {
    for entry in fs::read_dir(root).unwrap() {
        let entry = entry.unwrap();
        let name = format!("{prefix}{}", entry.file_name().to_string_lossy());
        if entry.file_type().unwrap().is_dir() {
            collect(&entry.path(), &format!("{name}/"), out);
        } else {
            out.push(name);
        }
    }
}

/// The names the contract fixes for T3a/T3b/T5 (§11) must not drift from DESIGN-B:
/// a rename here is a contract change, so the test pins the document.
#[test]
fn contract_pins_the_sealed_cmdline_keys_and_esp_paths() {
    let doc = String::from_utf8(
        fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/ota/V2-RELEASE-ATTESTATION.md"),
        )
        .unwrap(),
    )
    .unwrap();
    for needle in [
        "`neuralice.v2rel_sha256`",
        "`neuralice.v2rel_sig_sha256`",
        "`ice-coreos/v2-release-manifest.json`",
        "`ice-coreos/v2-release-manifest.json.sig`",
        "`neuralice.preseal`",
        "`neuralice.relauth_sha256` / `neuralice.relauth_sig_sha256`",
        "`neuralice.source=medium`",
        "neuralice.source=medium neuralice.v2rel_sha256=@V2REL_SHA@ neuralice.v2rel_sig_sha256=@V2REL_SIG_SHA@",
        "owner-sealed-ota-state-v2",
        "**High-S is accepted.**",
    ] {
        assert!(doc.contains(needle), "the contract no longer says {needle}");
    }
}

/// The golden signature is HIGH-S on purpose (contract §2, "High-S is accepted"): a KMS
/// emits either form, and a verifier that pre-filtered to low-S would refuse genuine
/// output. If this fails after a regeneration, the generator did not keep the property.
#[test]
fn golden_signature_is_high_s() {
    let work = scratch("high-s");
    fs::write(work.join("sig.b64"), read("release-manifest.json.sig")).unwrap();
    let decoded = Command::new("openssl")
        .args(["base64", "-d", "-A", "-in"])
        .arg(work.join("sig.b64"))
        .arg("-out")
        .arg(work.join("sig.der"))
        .output()
        .expect("the golden test needs the openssl CLI");
    assert!(decoded.status.success());
    let der = fs::read(work.join("sig.der")).unwrap();
    let _ = fs::remove_dir_all(&work);
    // SEQUENCE { INTEGER r, INTEGER s }, short-form lengths for a P-256 signature.
    assert_eq!(der[0], 0x30);
    let mut at = if der[1] < 0x80 {
        2
    } else {
        2 + usize::from(der[1] & 0x7f)
    };
    assert_eq!(der[at], 0x02);
    at += 2 + usize::from(der[at + 1]);
    assert_eq!(der[at], 0x02);
    let s = &der[at + 2..at + 2 + usize::from(der[at + 1])];
    let s: Vec<u8> = s.iter().copied().skip_while(|byte| *byte == 0).collect();
    assert_eq!(s.len(), 32, "s is a full-width scalar");
    // Half the P-256 group order, big-endian.
    let half_order: [u8; 32] = [
        0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31,
        0x92, 0xa8,
    ];
    assert!(
        s.as_slice() > half_order.as_slice(),
        "the golden s is low-S"
    );
}
