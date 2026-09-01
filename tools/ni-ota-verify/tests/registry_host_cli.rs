//! Real-binary coverage for the required generic registry authority boundary.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_ni-ota-verify");
const PACK: &str =
    include_str!("fixtures/release-manifest-v1/producer/consumer-pack/release-manifest-v1.json");

fn producer_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/release-manifest-v1/producer")
}

fn command(current: &Path, candidate: &Path) -> Command {
    let mut command = Command::new(BIN);
    command
        .arg("release-plan")
        .arg("--current")
        .arg(current)
        .arg("--candidate")
        .arg(candidate)
        .arg("--hardware-target")
        .arg("nvidia-dgx-spark-gb10")
        .arg("--reader-version")
        .arg("1")
        .arg("--supported-contracts")
        .arg("content-model-v1,host-bootc-v1,oci-component-v1");
    command
}

fn run_case(case: &Value) -> Output {
    let root = producer_root();
    let mut command = command(
        &root.join(case["current"].as_str().unwrap()),
        &root.join(case["candidate"].as_str().unwrap()),
    );
    if let Some(authority) = case["configured_registry_authority"].as_str() {
        command.arg("--registry-host").arg(authority);
    }
    command.output().expect("ni-ota-verify runs")
}

#[test]
fn configured_host_cases_match_the_producer_through_the_real_binary() {
    let pack: Value = serde_json::from_str(PACK).unwrap();
    for case in pack["configured_host_cases"].as_array().unwrap() {
        if case["configured_registry_authority"].is_null() {
            continue;
        }
        let id = case["id"].as_str().unwrap();
        let output = run_case(case);
        let expected_plan = &case["expected_plan"];
        let expected_code = if expected_plan["classification"] == "refusal" {
            1
        } else {
            0
        };
        assert_eq!(
            output.status.code(),
            Some(expected_code),
            "{id}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            output.stdout,
            format!("{}\n", serde_json::to_string(expected_plan).unwrap()).as_bytes(),
            "{id}: plan"
        );
    }
}

#[test]
fn registry_host_is_required_and_has_no_environment_fallback() {
    let pack: Value = serde_json::from_str(PACK).unwrap();
    let case = pack["configured_host_cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["id"] == "missing-config")
        .unwrap();
    let root = producer_root();
    let output = command(
        &root.join(case["current"].as_str().unwrap()),
        &root.join(case["candidate"].as_str().unwrap()),
    )
    .env("NI_OTA_REGISTRY_HOST", "registry.example.test")
    .env("REGISTRY_HOST", "registry.example.test")
    .output()
    .expect("ni-ota-verify runs");

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("release-plan needs --registry-host"),
        "{stderr}"
    );
}

#[test]
fn registry_host_duplicate_and_missing_value_are_interface_errors() {
    let root = producer_root();
    let current = root.join("vectors/planner/current-example.json");
    let candidate = root.join("vectors/planner/candidate-no-op.json");

    let output = command(&current, &candidate)
        .arg("--registry-host")
        .arg("registry.example.test")
        .arg("--registry-host")
        .arg("foreign.example.test")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("flag --registry-host given twice"));

    let output = command(&current, &candidate)
        .arg("--registry-host")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("flag --registry-host needs a value"));
}

#[test]
fn short_registry_names_are_refused_before_container_tooling_can_expand_them() {
    let root = producer_root();
    let current = root.join("vectors/planner/current-example.json");
    let candidate = root.join("vectors/planner/candidate-no-op.json");

    for authority in ["foo", "foo:5443"] {
        let output = command(&current, &candidate)
            .arg("--registry-host")
            .arg(authority)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1), "{authority}");
        assert!(
            String::from_utf8_lossy(&output.stdout)
                .contains("configured registry authority is malformed"),
            "{authority}: {}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
}
