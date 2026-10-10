//! ADR-0073 S1 acceptance gate. Expected to be red before planner implementation.
//! Same canonical input bytes as the Fabric test pack, with an independent pin.
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::process::Command;

const PACK: &[u8] = include_bytes!("fixtures/adr0073-planner-vectors.json");
const PACK_SHA256: &str = "81400b544c014b6a6f79a51ca074a785c3a709cf83f4c27cf9911c25a61c1198";

struct Work(PathBuf);

impl Drop for Work {
    fn drop(&mut self) {
        for name in ["current.json", "candidate.json"] {
            let _ = std::fs::remove_file(self.0.join(name));
        }
        let _ = std::fs::remove_dir(&self.0);
    }
}

#[test]
fn adr0073_s1_acceptance_vectors() {
    assert_eq!(format!("{:x}", Sha256::digest(PACK)), PACK_SHA256);
    let pack: Value = serde_json::from_slice(PACK).unwrap();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let work =
        Work(std::env::temp_dir().join(format!("adr0073-coreos-{}-{nonce}", std::process::id())));
    std::fs::create_dir(&work.0).unwrap();
    let current = work.0.join("current.json");
    let candidate = work.0.join("candidate.json");
    let mut failures = Vec::new();
    for case in pack["cases"].as_array().unwrap() {
        std::fs::write(&current, case["current_json"].as_str().unwrap()).unwrap();
        std::fs::write(&candidate, case["candidate_json"].as_str().unwrap()).unwrap();
        let contracts = case["device"]["supported_contracts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect::<Vec<_>>()
            .join(",");
        let output = Command::new(env!("CARGO_BIN_EXE_ni-ota-verify"))
            .arg("release-plan")
            .arg("--current")
            .arg(&current)
            .arg("--candidate")
            .arg(&candidate)
            .arg("--registry-host")
            .arg(pack["authority"].as_str().unwrap())
            .arg("--hardware-target")
            .arg(case["device"]["hardware_target"].as_str().unwrap())
            .arg("--reader-version")
            .arg(case["device"]["reader_version"].to_string())
            .arg("--supported-contracts")
            .arg(contracts)
            .output()
            .unwrap();
        // Exit 2 is tooling/setup failure, never a valid behavioral red.
        assert!(matches!(output.status.code(), Some(0 | 1)));
        let plan: Value = serde_json::from_slice(&output.stdout).unwrap();
        println!(
            "{}",
            serde_json::json!({"backend": "coreos", "id": case["id"], "observed": plan})
        );
        assert_eq!(
            output.status.code(),
            Some(if plan["classification"] == "refusal" {
                1
            } else {
                0
            })
        );
        for (field, expected) in case["expected"].as_object().unwrap() {
            if field == "refusal_reason_contains" {
                if !plan["refusal_reason"]
                    .as_str()
                    .unwrap_or_default()
                    .contains(expected.as_str().unwrap())
                {
                    failures.push(format!(
                        "{}: refusal reason {:?}",
                        case["id"], plan["refusal_reason"]
                    ));
                }
            } else if plan[field] != *expected {
                failures.push(format!(
                    "{}: {field}: observed {}, expected {expected}",
                    case["id"], plan[field]
                ));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
