//! Differential consumer tests for Fabric's exact release-manifest v1 pack.

use std::collections::BTreeSet;

use serde_json::Value;
use sha2::{Digest, Sha256};

use super::*;

const CONSUMER_PACK: &[u8] = include_bytes!(
    "../tests/fixtures/release-manifest-v1/producer/consumer-pack/release-manifest-v1.json"
);
const PRODUCER_PIN: &[u8] =
    include_bytes!("../tests/fixtures/release-manifest-v1/producer/PIN.json");

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

macro_rules! producer_vectors {
    ($($path:literal),* $(,)?) => {
        fn producer_vector(path: &str) -> &'static [u8] {
            match path {
                $($path => include_bytes!(concat!(
                    "../tests/fixtures/release-manifest-v1/producer/", $path
                )),)*
                _ => panic!("consumer pack references an uncommitted producer vector: {path}"),
            }
        }
    };
}

producer_vectors![
    "vectors/canonical/valid-bracketed-ipv6.json",
    "vectors/canonical/valid-dns-host-253-port.json",
    "vectors/canonical/valid-dns-host-253.json",
    "vectors/canonical/valid-example-canonical.json",
    "vectors/canonical/valid-example-noncanonical.json",
    "vectors/canonical/valid-ipv4-mapped-ipv6-7f00.json",
    "vectors/canonical/valid-ipv4-mapped-ipv6-c000.json",
    "vectors/canonical/valid-production-host.json",
    "vectors/canonical/valid-registry-port.json",
    "vectors/parser/invalid-dns-host-254.json",
    "vectors/parser/invalid-dns-trailing-dot.json",
    "vectors/parser/invalid-duplicate-key.json",
    "vectors/parser/invalid-expanded-ipv6-zero-run.json",
    "vectors/parser/invalid-ipv4-mapped-ipv6-dotted.json",
    "vectors/parser/invalid-ipv6-unicode-zone-id.json",
    "vectors/parser/invalid-ipv6-zone-id.json",
    "vectors/parser/invalid-malformed-authority.json",
    "vectors/parser/invalid-nonascii-dns.json",
    "vectors/parser/invalid-noncanonical-ipv4.json",
    "vectors/parser/invalid-noncanonical-ipv6.json",
    "vectors/parser/invalid-overflow-port.json",
    "vectors/parser/invalid-repository-namespace.json",
    "vectors/parser/invalid-tagged-repository.json",
    "vectors/parser/invalid-uppercase-authority.json",
    "vectors/parser/invalid-uppercase-ipv6.json",
    "vectors/parser/invalid-zero-port.json",
    "vectors/parser/valid-bracketed-ipv6.json",
    "vectors/parser/valid-dns-host-253-port.json",
    "vectors/parser/valid-dns-host-253.json",
    "vectors/parser/valid-example-canonical.json",
    "vectors/parser/valid-example-noncanonical.json",
    "vectors/parser/valid-ipv4-mapped-ipv6-7f00.json",
    "vectors/parser/valid-ipv4-mapped-ipv6-c000.json",
    "vectors/parser/valid-production-host.json",
    "vectors/parser/valid-registry-port.json",
    "vectors/planner/candidate-component.json",
    "vectors/planner/candidate-host.json",
    "vectors/planner/candidate-mixed-host.json",
    "vectors/planner/candidate-no-op.json",
    "vectors/planner/current-example.json",
    "vectors/planner/current-mixed-host.json",
    "vectors/planner/production-host.json",
];

fn pack() -> Value {
    serde_json::from_slice(CONSUMER_PACK).expect("producer consumer pack is JSON")
}

fn device() -> DeviceCompatibility {
    DeviceCompatibility {
        hardware_target: "nvidia-dgx-spark-gb10".to_owned(),
        reader_version: 1,
        supported_contracts: ["content-model-v1", "host-bootc-v1", "oci-component-v1"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
    }
}

#[test]
fn producer_pack_schema_and_inputs_are_hash_pinned() {
    let pin: Value = serde_json::from_slice(PRODUCER_PIN).unwrap();
    assert_eq!(sha256(CONSUMER_PACK), pin["consumer_pack_sha256"]);

    let inputs: [(&str, &[u8]); 4] = [
        (
            "contract.py",
            include_bytes!("../tests/fixtures/release-manifest-v1/producer/contract.py"),
        ),
        (
            "classifier.py",
            include_bytes!("../tests/fixtures/release-manifest-v1/producer/classifier.py"),
        ),
        (
            "generate_vectors.py",
            include_bytes!("../tests/fixtures/release-manifest-v1/producer/generate_vectors.py"),
        ),
        (
            "release-manifest-v1.schema.json",
            include_bytes!(
                "../tests/fixtures/release-manifest-v1/producer/release-manifest-v1.schema.json"
            ),
        ),
    ];
    for (name, bytes) in inputs {
        assert_eq!(sha256(bytes), pin["producer_inputs"][name], "{name}");
    }
    assert_eq!(
        pin["producer_inputs"]["release-manifest-v1.schema.json"],
        pack()["schema_sha256"]
    );
    assert_eq!(
        pin["repository_pattern_sha256"],
        pack()["repository_grammar"]["pattern_sha256"]
    );
    assert_eq!(pack()["parser_vectors"].as_array().unwrap().len(), 26);
    assert_eq!(
        pack()["repository_grammar"]["equivalence_vectors"]
            .as_array()
            .unwrap()
            .len(),
        37
    );
    assert_eq!(pack()["configured_host_cases"].as_array().unwrap().len(), 9);
}

#[test]
fn repository_grammar_matches_schema_and_every_equivalence_vector() {
    let pack = pack();
    let grammar = &pack["repository_grammar"];
    let schema: Value = serde_json::from_slice(include_bytes!(
        "../tests/fixtures/release-manifest-v1/producer/release-manifest-v1.schema.json"
    ))
    .unwrap();
    let pattern = schema["$defs"]["repository"]["pattern"].as_str().unwrap();
    assert_eq!(sha256(pattern.as_bytes()), grammar["pattern_sha256"]);
    assert_eq!(grammar["dns_host_max_ascii_characters"], 253);
    assert_eq!(
        grammar["ipv4_mapped_ipv6_text"],
        "lowercase-compressed-hexadecimal-hextets"
    );

    for vector in grammar["equivalence_vectors"].as_array().unwrap() {
        let repository_text = vector["repository"].as_str().unwrap();
        let authority = repository_text.split_once('/').unwrap().0;
        let repository_value = Json::Str(repository_text.to_owned());
        let accepted = vector["accepted"].as_bool().unwrap();
        assert_eq!(
            repository(&repository_value, "equivalence.repository").is_ok(),
            accepted,
            "{}: repository grammar",
            vector["id"]
        );
        assert_eq!(
            registry_authority(Some(authority), "configured registry authority").is_ok(),
            accepted,
            "{}: authority grammar",
            vector["id"]
        );
    }
}

#[test]
fn parser_reproduces_every_exact_producer_vector() {
    for vector in pack()["parser_vectors"].as_array().unwrap() {
        let id = vector["id"].as_str().unwrap();
        let input = producer_vector(vector["input"].as_str().unwrap());
        assert_eq!(sha256(input), vector["input_sha256"], "{id}: input hash");
        let authority = vector["configured_registry_authority"].as_str();
        if vector["accepted"].as_bool().unwrap() {
            let parsed = parse(input, authority).unwrap_or_else(|reason| {
                panic!("{id}: producer accepted but CoreOS refused: {reason}")
            });
            let canonical = producer_vector(vector["canonical"].as_str().unwrap());
            assert_eq!(parsed.canonical_bytes, canonical, "{id}: canonical bytes");
            assert_eq!(sha256(canonical), vector["canonical_sha256"], "{id}: hash");
            assert_eq!(parsed.digest, vector["canonical_sha256"], "{id}: digest");
        } else {
            assert_eq!(
                parse(input, authority).unwrap_err().0,
                vector["refusal_reason"],
                "{id}: refusal"
            );
        }
    }
}

#[test]
fn planner_reproduces_every_exact_configured_host_case() {
    for case in pack()["configured_host_cases"].as_array().unwrap() {
        let id = case["id"].as_str().unwrap();
        let current = producer_vector(case["current"].as_str().unwrap());
        let candidate = producer_vector(case["candidate"].as_str().unwrap());
        assert_eq!(sha256(current), case["current_sha256"], "{id}: current");
        assert_eq!(
            sha256(candidate),
            case["candidate_sha256"],
            "{id}: candidate"
        );
        let plan = classify(
            current,
            candidate,
            &device(),
            case["configured_registry_authority"].as_str(),
        );
        let expected = format!(
            "{}\n",
            serde_json::to_string(&case["expected_plan"]).unwrap()
        );
        assert_eq!(plan.to_canonical_json(), expected.as_bytes(), "{id}: plan");
    }
}

#[test]
fn every_payload_authority_is_checked_before_sequence_or_transition() {
    let current = producer_vector("vectors/planner/current-example.json");
    let mut candidate: Value =
        serde_json::from_slice(producer_vector("vectors/planner/candidate-no-op.json")).unwrap();
    candidate["bundle_seq"] = 1_u64.into();

    for (collection, index) in [
        ("host", None),
        ("components", Some(0)),
        ("content", Some(0)),
    ] {
        let mut mutated = candidate.clone();
        let payload = match index {
            Some(index) => &mut mutated[collection][index],
            None => &mut mutated[collection],
        };
        let repository = payload["repository"].as_str().unwrap();
        payload["repository"] = repository
            .replacen("registry.example.test", "foreign.example.test", 1)
            .into();
        let bytes = serde_json::to_vec(&mutated).unwrap();
        let plan = classify(current, &bytes, &device(), Some("registry.example.test"));
        assert_eq!(plan.classification, Classification::Refusal);
        let reason = plan.refusal_reason.unwrap();
        assert!(
            reason.starts_with("candidate manifest refused:"),
            "{reason}"
        );
        assert!(
            reason.contains("does not match configured registry authority"),
            "{reason}"
        );
        assert!(!reason.contains("bundle_seq is below"), "{reason}");
    }
}

#[test]
fn required_authority_has_no_default_or_environment_fallback() {
    let current = producer_vector("vectors/planner/current-example.json");
    let candidate = producer_vector("vectors/planner/candidate-no-op.json");
    for authority in [
        None,
        Some(""),
        Some("https://registry.example.test"),
        Some("foo"),
        Some("foo:5443"),
    ] {
        let plan = classify(current, candidate, &device(), authority);
        assert_eq!(plan.classification, Classification::Refusal);
        assert!(plan
            .refusal_reason
            .as_deref()
            .unwrap()
            .starts_with("current manifest refused: configured registry authority"));
    }
}

#[test]
fn generic_authority_preserves_both_repository_namespaces() {
    let parsed = parse(
        producer_vector("vectors/parser/valid-example-canonical.json"),
        Some("registry.example.test"),
    )
    .unwrap();
    let namespaces: BTreeSet<&str> = parsed
        .value
        .components
        .iter()
        .map(|component| component.payload.repository.as_str())
        .collect();
    assert!(namespaces
        .iter()
        .any(|repository| repository.contains("/neural-ice/")));
    assert!(namespaces
        .iter()
        .any(|repository| repository.contains("/vendor/")));
}

#[test]
fn input_and_parser_depth_limits_remain_bounded() {
    assert_eq!(
        parse(
            &vec![b' '; MAX_MANIFEST_BYTES + 1],
            Some("registry.example.test")
        )
        .unwrap_err()
        .0,
        "release manifest exceeds the byte limit"
    );
    let nested = format!("{}0{}", "[".repeat(65), "]".repeat(65));
    assert!(parse(nested.as_bytes(), Some("registry.example.test"))
        .unwrap_err()
        .0
        .contains("depth limit"));
}
