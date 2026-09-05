#![cfg(feature = "test-path-overrides")]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::{json, Value};

const DOMAIN: &[u8] = b"neural-ice:tpm:owner-ceremony-completion:v2\0";
static SERIAL: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    root: PathBuf,
    helper: PathBuf,
}

impl Fixture {
    fn new(version: u64) -> Self {
        let root = std::env::temp_dir().join(format!(
            "ni-owner-completion-{}-{}",
            std::process::id(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let helper = root.join("tpm-state");
        fs::write(
            &helper,
            format!(
                "#!/bin/sh\n[ \"$#\" -eq 1 ] && [ \"$1\" = completion-inspect ] || exit 97\ncat '{}'\n",
                root.join("inspection.json").display()
            ),
        )
        .unwrap();
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o755)).unwrap();

        let evidence = if version == 1 {
            json!({
                "access_profile_anchor": anchor(),
                "schema":"neural-ice-owner-ceremony-evidence-v1"
            })
        } else {
            let luks = json!({
                "keyslot":"0","pcr_bank":"sha256","pcrs":[7],
                "policy_hash":"11".repeat(32),"policy_public_key_sha256":"22".repeat(32),
                "schema":"neural-ice-luks-token-evidence-v1",
                "sealed_object_sha256":"33".repeat(32),"srk_sha256":"44".repeat(32),
                "token_sha256":"55".repeat(32)
            });
            json!({
                "access_profile_anchor":anchor(),"data_luks":luks,
                "device_root_name":format!("000b{}", "11".repeat(32)),
                "install_identity":{"install_source":"medium","installed_at":"2026-09-05T00:00:00Z","installer_sealed_identity_sha256":"66".repeat(32),"release_identity_sha256":"77".repeat(32),"schema":"neural-ice-owner-ceremony-install-identity-v1"},
                "ota_preseal":{"receipt_schema":"neural-ice-ota-preseal-receipt-v1","receipt_sha256":"88".repeat(32),"set_sha256":"99".repeat(32)},
                "ota_state":{"anchor_attributes":"0x2060048","anchor_index":"0x01500002","anchor_name_at_completion":"000b038de2091c1c8ef2e8fd8869f17bef3a576ae287530fa17f05ae3b9712014b5d","anchor_policy_sha256":"b6a2e7142ee56fd978047488483daa5b42b8dc4cc7ddcceddfb91793cf1ff1b7","anchor_pristine_name":"000b038de2091c1c8ef2e8fd8869f17bef3a576ae287530fa17f05ae3b9712014b5d","anchor_size":32,"anchor_state_at_completion":"pristine","anchor_written_name":"000b11afd155aca82a503f2029cc11395389654c3a25fc54b9eca6d33abdff498d56","baseline_floor":5,"clear_protected_at_completion":true,"floor_attributes":"0x62008","floor_index":"0x01500001","floor_name":"000be283f20a38b93f8cef085efb4aee9f5944cc3b3b28b850bf3c0eeb2054cd7fc4","floor_policy_sha256":"f83217e5a2a04342f7daa55ccfb3cd4b8a1f1e8ebb28c7719a9abbdbd638a230","floor_size":8,"profile":"owner-sealed-ota-state-v1"},
                "schema":"neural-ice-owner-ceremony-evidence-v2",
                "srk_name":format!("000b{}", "aa".repeat(32)),
                "system_luks":luks,
                "tpm_state":{"freshness_counter":5,"freshness_public_sha256":"bb".repeat(32),"install_counter":1,"install_public_sha256":"cc".repeat(32),"profile_binding":"dd".repeat(32),"schema":"neural-ice-tpm-state-snapshot-v1"}
            })
        };
        let evidence_path = root.join(format!("owner-ceremony-evidence-v{version}.json"));
        let bytes = canonical(&evidence);
        fs::write(&evidence_path, &bytes).unwrap();
        let digest = if version == 1 {
            hash(&bytes)
        } else {
            let mut message = DOMAIN.to_vec();
            message.extend_from_slice(&bytes);
            hash(&message)
        };
        write_inspection(&root, version, &digest);
        Self { root, helper }
    }

    fn run(&self) -> Output {
        Command::new(env!("CARGO_BIN_EXE_ni-ota-verify"))
            .args(["test-inspect-owner-completion", "--state-dir"])
            .arg(&self.root)
            .env("NI_OTA_TPM_STATE_HELPER", &self.helper)
            .output()
            .unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn exact_v1_and_domain_bound_v2_are_accepted() {
    let v1 = Fixture::new(1);
    let output = v1.run();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["completion_version"], 1);
    assert!(value["baseline_floor"].is_null());

    let v2 = Fixture::new(2);
    let output = v2.run();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["completion_version"], 2);
    assert_eq!(value["baseline_floor"], 5);
    assert_eq!(value["preseal_receipt_sha256"], "88".repeat(32));
    assert_eq!(value["preseal_set_sha256"], "99".repeat(32));
}

#[test]
fn wrong_domain_noncanonical_or_foreign_owner_contract_is_refused() {
    let unknown_inspection = Fixture::new(2);
    let inspection_path = unknown_inspection.root.join("inspection.json");
    let mut inspection: Value =
        serde_json::from_slice(&fs::read(&inspection_path).unwrap()).unwrap();
    inspection["extra"] = json!(true);
    fs::write(&inspection_path, canonical(&inspection)).unwrap();
    assert_eq!(unknown_inspection.run().status.code(), Some(1));

    let missing_lf = Fixture::new(2);
    let inspection_path = missing_lf.root.join("inspection.json");
    let mut inspection = fs::read(&inspection_path).unwrap();
    assert_eq!(inspection.pop(), Some(b'\n'));
    fs::write(&inspection_path, inspection).unwrap();
    assert_eq!(missing_lf.run().status.code(), Some(1));

    let raw = Fixture::new(2);
    let bytes = fs::read(raw.root.join("owner-ceremony-evidence-v2.json")).unwrap();
    write_inspection(&raw.root, 2, &hash(&bytes));
    assert_eq!(raw.run().status.code(), Some(1));

    let noncanonical = Fixture::new(2);
    let path = noncanonical.root.join("owner-ceremony-evidence-v2.json");
    let value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let bytes = serde_json::to_vec_pretty(&value).unwrap();
    fs::write(&path, &bytes).unwrap();
    let mut message = DOMAIN.to_vec();
    message.extend_from_slice(&bytes);
    write_inspection(&noncanonical.root, 2, &hash(&message));
    assert_eq!(noncanonical.run().status.code(), Some(1));

    let extra_lf = Fixture::new(2);
    let path = extra_lf.root.join("owner-ceremony-evidence-v2.json");
    let mut bytes = fs::read(&path).unwrap();
    bytes.push(b'\n');
    fs::write(&path, &bytes).unwrap();
    let mut message = DOMAIN.to_vec();
    message.extend_from_slice(&bytes);
    write_inspection(&extra_lf.root, 2, &hash(&message));
    assert_eq!(extra_lf.run().status.code(), Some(1));

    let unknown_evidence = Fixture::new(2);
    let path = unknown_evidence
        .root
        .join("owner-ceremony-evidence-v2.json");
    let mut value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    value["unknown"] = json!(true);
    let bytes = canonical(&value);
    fs::write(&path, &bytes).unwrap();
    let mut message = DOMAIN.to_vec();
    message.extend_from_slice(&bytes);
    write_inspection(&unknown_evidence.root, 2, &hash(&message));
    assert_eq!(unknown_evidence.run().status.code(), Some(1));

    let foreign = Fixture::new(2);
    let path = foreign.root.join("owner-ceremony-evidence-v2.json");
    let mut value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    value["ota_state"]["anchor_name_at_completion"] = json!("000b".to_owned() + &"00".repeat(32));
    let bytes = canonical(&value);
    fs::write(&path, &bytes).unwrap();
    let mut message = DOMAIN.to_vec();
    message.extend_from_slice(&bytes);
    write_inspection(&foreign.root, 2, &hash(&message));
    assert_eq!(foreign.run().status.code(), Some(1));
}

fn anchor() -> Value {
    json!({"json_sha256":"11".repeat(32),"signature_sha256":"22".repeat(32),"spki_sha256":"33".repeat(32)})
}
fn canonical(value: &Value) -> Vec<u8> {
    let mut b = serde_json::to_vec(value).unwrap();
    b.push(b'\n');
    b
}
fn write_inspection(root: &Path, version: u64, digest: &str) {
    fs::write(root.join("inspection.json"), canonical(&json!({"completion_version":version,"evidence_digest_sha256":digest,"schema":"neural-ice-owner-ceremony-completion-inspection-v1"}))).unwrap();
}
fn hash(bytes: &[u8]) -> String {
    let path = std::env::temp_dir().join(format!(
        "ni-hash-{}-{}",
        std::process::id(),
        SERIAL.fetch_add(1, Ordering::Relaxed)
    ));
    fs::write(&path, bytes).unwrap();
    let output = Command::new("sha256sum").arg(&path).output().unwrap();
    let _ = fs::remove_file(path);
    String::from_utf8(output.stdout)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .into()
}
