use serde_json::{json, Value};

use super::{plan_bytes, PlanError, Transaction, MAX_MANIFEST_BYTES};

fn manifest(seq: u64) -> Value {
    json!({
        "components": [{
            "configuration_contract": "icecore-v1",
            "digest": format!("sha256:{}", "1".repeat(64)),
            "id": "ice-ac1",
            "reboot_required": false,
            "repository": "registry.neural-ice.ch/neural-ice/ice-ac1",
            "restart_units": ["icecore-api.service"]
        }],
        "content": [{
            "activation_contract": "model-pointer-v1",
            "digest": format!("sha256:{}", "2".repeat(64)),
            "id": "gemma-4",
            "media_type": "application/vnd.neural-ice.model.v1",
            "repository": "registry.neural-ice.ch/neural-ice/models/gemma-4"
        }],
        "hardware_target": "nvidia-gb10-arm64",
        "host": {
            "compatibility_contract": "host-v1",
            "digest": format!("sha256:{}", "3".repeat(64)),
            "repository": "registry.neural-ice.ch/neural-ice/appliance"
        },
        "release_id": format!("release-{seq}"),
        "release_seq": seq,
        "schema": "neural-ice-release-manifest-v1"
    })
}

fn bytes(value: &Value) -> Vec<u8> {
    let mut encoded = serde_json::to_vec(value).unwrap();
    encoded.push(b'\n');
    encoded
}

fn refused(current: &Value, candidate: &Value) -> bool {
    matches!(
        plan_bytes(&bytes(current), &bytes(candidate)),
        Err(PlanError::Refusal(_))
    )
}

#[test]
fn classifies_noop_content_component_and_host() {
    let current = manifest(1);
    let mut candidate = manifest(2);
    let plan = plan_bytes(&bytes(&current), &bytes(&candidate)).unwrap();
    assert_eq!(plan.transaction, Transaction::Noop);
    assert!(!plan.reboot_required);

    candidate["content"][0]["digest"] = json!(format!("sha256:{}", "4".repeat(64)));
    let plan = plan_bytes(&bytes(&current), &bytes(&candidate)).unwrap();
    assert_eq!(plan.transaction, Transaction::Content);
    assert_eq!(plan.changed_content, ["gemma-4"]);

    candidate = manifest(2);
    candidate["components"][0]["digest"] = json!(format!("sha256:{}", "5".repeat(64)));
    let plan = plan_bytes(&bytes(&current), &bytes(&candidate)).unwrap();
    assert_eq!(plan.transaction, Transaction::Component);
    assert_eq!(plan.changed_components, ["ice-ac1"]);
    assert!(!plan.reboot_required);

    candidate["host"]["digest"] = json!(format!("sha256:{}", "6".repeat(64)));
    let plan = plan_bytes(&bytes(&current), &bytes(&candidate)).unwrap();
    assert_eq!(plan.transaction, Transaction::Host);
    assert!(plan.reboot_required);
}

#[test]
fn component_transaction_dominates_and_reports_every_changed_payload() {
    let mut current = manifest(1);
    let second = json!({
        "configuration_contract": "renderer-v1",
        "digest": format!("sha256:{}", "8".repeat(64)),
        "id": "pdf-rasterizer",
        "reboot_required": false,
        "repository": "registry.neural-ice.ch/neural-ice/pdf-rasterizer",
        "restart_units": ["pdf-rasterizer.service"]
    });
    current["components"].as_array_mut().unwrap().push(second);

    let mut candidate = current.clone();
    candidate["release_id"] = json!("release-2");
    candidate["release_seq"] = json!(2);
    candidate["components"][0]["digest"] = json!(format!("sha256:{}", "4".repeat(64)));
    candidate["components"][1]["digest"] = json!(format!("sha256:{}", "5".repeat(64)));
    candidate["content"][0]["digest"] = json!(format!("sha256:{}", "6".repeat(64)));

    let plan = plan_bytes(&bytes(&current), &bytes(&candidate)).unwrap();
    assert_eq!(plan.transaction, Transaction::Component);
    assert_eq!(plan.changed_components, ["ice-ac1", "pdf-rasterizer"]);
    assert_eq!(plan.changed_content, ["gemma-4"]);
}

#[test]
fn component_contract_can_explicitly_require_reboot() {
    let current = manifest(1);
    let mut candidate = manifest(2);
    candidate["components"][0]["digest"] = json!(format!("sha256:{}", "7".repeat(64)));
    candidate["components"][0]["reboot_required"] = json!(true);
    assert!(refused(&current, &candidate));

    let mut current_with_contract = current;
    current_with_contract["components"][0]["reboot_required"] = json!(true);
    let plan = plan_bytes(&bytes(&current_with_contract), &bytes(&candidate)).unwrap();
    assert_eq!(plan.transaction, Transaction::Component);
    assert!(plan.reboot_required);
}

#[test]
fn rejects_rollback_same_sequence_divergence_and_wrong_hardware() {
    assert!(refused(&manifest(2), &manifest(1)));
    let current = manifest(1);
    let mut same_sequence = manifest(1);
    same_sequence["content"][0]["digest"] = json!(format!("sha256:{}", "4".repeat(64)));
    assert!(refused(&current, &same_sequence));

    let mut wrong_hardware = manifest(2);
    wrong_hardware["hardware_target"] = json!("nvidia-cuda-x86_64");
    assert!(refused(&current, &wrong_hardware));
}

#[test]
fn refuses_inventory_or_contract_changes_without_host_change() {
    let current = manifest(1);
    let mut candidate = manifest(2);
    candidate["components"][0]["repository"] = json!("registry.neural-ice.ch/other/ice-ac1");
    assert!(refused(&current, &candidate));

    candidate = manifest(2);
    candidate["components"] = json!([]);
    assert!(refused(&current, &candidate));

    candidate = manifest(2);
    candidate["content"][0]["activation_contract"] = json!("model-pointer-v2");
    assert!(refused(&current, &candidate));

    candidate = manifest(2);
    candidate["content"][0]["repository"] = json!("registry.neural-ice.ch/other/models/gemma-4");
    assert!(refused(&current, &candidate));
}

#[test]
fn rejects_unknown_fields_invalid_digests_and_noncanonical_json() {
    let current = manifest(1);
    let mut unknown = manifest(2);
    unknown["surprise"] = json!(true);
    assert!(refused(&current, &unknown));

    let mut invalid = manifest(2);
    invalid["host"]["digest"] = json!("latest");
    assert!(refused(&current, &invalid));

    let pretty = serde_json::to_vec_pretty(&manifest(2)).unwrap();
    assert!(matches!(
        plan_bytes(&bytes(&current), &pretty),
        Err(PlanError::Refusal(_))
    ));

    let oversized = vec![b' '; MAX_MANIFEST_BYTES as usize + 1];
    assert!(matches!(
        plan_bytes(&bytes(&current), &oversized),
        Err(PlanError::Refusal(_))
    ));
}
