//! Cross-contract tests for the release-manifest v1 reader and planner.
//!
//! The expected values are NOT written by hand and are not derived from this
//! implementation: `tests/fixtures/release-manifest-v1/golden.json` is the
//! output of ICE-Fabric's own `release-manifest/{contract,classifier}.py` at
//! `e08446d6fc899f670b962f1e013bbf46e7e91497`, produced by the committed
//! `generate-golden.py`. A test failure here means CoreOS and Fabric disagree
//! about what a signed manifest means — which is exactly the class of drift
//! that made the earlier planner unusable.
//!
//! The named regression tests at the bottom pin the specific mutations that
//! were actually present before this rewrite, so re-introducing any of them is
//! a red test rather than a field incident.

use std::collections::BTreeSet;

use serde_json::Value;

use super::*;

const GOLDEN: &str = include_str!("../tests/fixtures/release-manifest-v1/golden.json");

macro_rules! manifest_fixtures {
    ($($name:literal),* $(,)?) => {
        /// Every manifest vector, by the name `golden.json` uses.
        const MANIFESTS: &[(&str, &[u8])] = &[
            $((
                $name,
                include_bytes!(concat!(
                    "../tests/fixtures/release-manifest-v1/manifests/",
                    $name,
                    ".json"
                )),
            )),*
        ];
    };
}

manifest_fixtures![
    "base",
    "base-reordered",
    "compatibility-widened",
    "component-content",
    "component-contract-changed",
    "component-removed",
    "content-added",
    "content-restart-changed",
    "duplicate-component-id",
    "duplicate-json-key",
    "entitlement-changed",
    "entitlement-changed-with-host",
    "float-bundle-seq",
    "foreign-registry",
    "host",
    "identifier-max-length",
    "identifier-over-length",
    "missing-compatibility",
    "missing-entitlement",
    "missing-restart-scope",
    "non-finite",
    "oversized-integer",
    "release-seq",
    "restart-scope-overflow",
    "rollback",
    "same-seq-divergent",
    "undeclared-contract",
    "unit-max-length",
    "unit-over-length",
    "unit-trailing-punctuation",
];

fn golden() -> Value {
    serde_json::from_str(GOLDEN).expect("golden.json is valid JSON")
}

fn fixture(name: &str) -> &'static [u8] {
    MANIFESTS
        .iter()
        .find(|(fixture, _)| *fixture == name)
        .unwrap_or_else(|| panic!("golden.json references an uncommitted manifest: {name}"))
        .1
}

fn device(golden: &Value, name: &str) -> DeviceCompatibility {
    let entry = &golden["devices"][name];
    DeviceCompatibility {
        hardware_target: entry["hardware_target"].as_str().unwrap().to_owned(),
        reader_version: entry["reader_version"].as_u64().unwrap(),
        supported_contracts: entry["supported_contracts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap().to_owned())
            .collect(),
    }
}

fn gb10() -> DeviceCompatibility {
    device(&golden(), "gb10")
}

/// The base vector, mutated in place by the regression tests below.
fn base_value() -> Value {
    serde_json::from_slice(fixture("base")).unwrap()
}

fn refusal_for(bytes: &[u8]) -> String {
    match parse(bytes) {
        Ok(parsed) => panic!("expected a refusal, got digest {}", parsed.digest),
        Err(Refusal(reason)) => reason,
    }
}

fn digest_for(bytes: &[u8]) -> String {
    parse(bytes).expect("vector parses").digest
}

// ---------------------------------------------------------------------------
// Cross-contract: every committed vector, against Fabric's own output
// ---------------------------------------------------------------------------

/// The reader reproduces Fabric's canonical bytes, digest and refusal text for
/// every manifest vector — the whole contract in one assertion loop.
#[test]
fn manifest_vectors_match_the_fabric_contract() {
    let golden = golden();
    let expected = golden["manifests"].as_object().unwrap();
    assert_eq!(
        expected.len(),
        MANIFESTS.len(),
        "golden.json and the committed manifest fixtures disagree on the vector set"
    );

    for (name, bytes) in MANIFESTS {
        let entry = &expected[*name];
        match parse(bytes) {
            Ok(parsed) => {
                let canonical = entry["canonical"]
                    .as_str()
                    .unwrap_or_else(|| panic!("{name}: Fabric refused, this reader accepted"));
                assert_eq!(
                    String::from_utf8(parsed.canonical_bytes.clone()).unwrap(),
                    canonical,
                    "{name}: canonical bytes diverge from Fabric"
                );
                assert_eq!(
                    parsed.digest,
                    entry["digest"].as_str().unwrap(),
                    "{name}: canonical digest diverges from Fabric"
                );
            }
            Err(Refusal(reason)) => {
                let expected_reason = entry["refusal"].as_str().unwrap_or_else(|| {
                    panic!("{name}: Fabric accepted, this reader refused with: {reason}")
                });
                assert_eq!(reason, expected_reason, "{name}: refusal text diverges");
            }
        }
    }
}

/// Every plan vector: classification, digests, changed sets, restart scope,
/// reboot and refusal text, compared as the whole canonical plan document.
#[test]
fn plan_vectors_match_the_fabric_classifier() {
    let golden = golden();
    let plans = golden["plans"].as_object().unwrap();
    assert!(!plans.is_empty(), "golden.json carries no plan vectors");

    for (case, entry) in plans {
        let current = fixture(entry["current"].as_str().unwrap());
        let candidate = fixture(entry["candidate"].as_str().unwrap());
        let device = device(&golden, entry["device"].as_str().unwrap());
        let plan = classify(current, candidate, &device);
        assert_eq!(
            String::from_utf8(plan.to_canonical_json()).unwrap(),
            entry["plan"].as_str().unwrap(),
            "{case}: plan diverges from the Fabric classifier"
        );
    }
}

/// Coverage guard: the vector set must keep exercising every classification.
/// A silent drop to "only refusals still pass" would otherwise look green.
#[test]
fn plan_vectors_cover_every_classification() {
    let golden = golden();
    let seen: BTreeSet<String> = golden["plans"]
        .as_object()
        .unwrap()
        .values()
        .map(|entry| {
            let plan: Value = serde_json::from_str(entry["plan"].as_str().unwrap()).unwrap();
            plan["classification"].as_str().unwrap().to_owned()
        })
        .collect();
    for classification in ["no-op", "component-content", "host", "refusal"] {
        assert!(
            seen.contains(classification),
            "the golden vectors no longer exercise {classification}"
        );
    }
}

/// The vectors must stay pinned to the Fabric revision this reader was written
/// against; a bare regeneration against a moved contract is a decision, not a
/// refresh.
/// All three pinned sources are named, including the schema.
///
/// `release-manifest-v1.schema.json` is authority, not decoration: it is what a
/// producer validates against. Leaving it unasserted meant the schema could
/// move under a still-green suite, and the generator would silently omit it
/// from provenance if it were absent from the checkout.
const FABRIC_SOURCE_SHA256: &[(&str, &str)] = &[
    (
        "classifier.py",
        "f0cacd3c934e51f54e56d199835e8059b6dbfcc9c1fa2b0ba0324d684b3d5b05",
    ),
    (
        "contract.py",
        "426010e504af53352fcf51d4dc1cabfc7da575d7e608e971d7e4a5e9adfa47a5",
    ),
    (
        "release-manifest-v1.schema.json",
        "dd6f5e94855adcd0bb82a91588d44cf239ef408f1efbb004fdd0fa7f14450b66",
    ),
];

#[test]
fn golden_vectors_record_their_fabric_provenance() {
    let golden = golden();
    assert_eq!(
        golden["provenance"]["fabric_sha"].as_str().unwrap(),
        "e08446d6fc899f670b962f1e013bbf46e7e91497"
    );

    let recorded = golden["provenance"]["fabric_source_sha256"]
        .as_object()
        .expect("provenance records the Fabric source hashes");
    for (name, expected) in FABRIC_SOURCE_SHA256 {
        assert_eq!(
            recorded
                .get(*name)
                .unwrap_or_else(|| panic!("provenance omits the pinned source {name}"))
                .as_str()
                .unwrap(),
            *expected,
            "{name} moved under the pinned Fabric revision"
        );
    }
    // Exact, not merely sufficient: a source dropped from provenance is drift.
    assert_eq!(
        recorded.len(),
        FABRIC_SOURCE_SHA256.len(),
        "provenance must name exactly the pinned Fabric sources, found {:?}",
        recorded.keys().collect::<Vec<_>>()
    );
}

// ---------------------------------------------------------------------------
// Regressions: the exact mutations that made the previous planner unusable
// ---------------------------------------------------------------------------

/// `release_seq` was the previous planner's sequence field. Accepting it — or
/// aliasing it onto `bundle_seq` — would create a second manifest grammar under
/// one signature.
#[test]
fn release_seq_is_not_a_bundle_seq_alias() {
    let mut value = base_value();
    let object = value.as_object_mut().unwrap();
    let seq = object.remove("bundle_seq").unwrap();
    object.insert("release_seq".to_owned(), seq);
    let bytes = serde_json::to_vec(&value).unwrap();
    assert_eq!(
        refusal_for(&bytes),
        "release manifest is missing fields: bundle_seq"
    );
}

/// A component-only change and a content-only change are ONE class in v1.
/// The previous planner split them, so a mixed bundle had no engine at all.
#[test]
fn component_and_content_share_one_classification() {
    let golden = golden();
    let device = gb10();
    for candidate in ["component-content", "content-added"] {
        let plan = classify(fixture("base"), fixture(candidate), &device);
        assert_eq!(
            plan.classification,
            Classification::ComponentContent,
            "{candidate} must classify as component-content"
        );
    }
    // And a mixed bundle is still the same single class.
    let mut value: Value = serde_json::from_slice(fixture("content-added")).unwrap();
    value["components"][0]["digest"] = Value::String(format!("sha256:{}", "2b".repeat(32)));
    let bytes = serde_json::to_vec(&value).unwrap();
    let plan = classify(fixture("base"), &bytes, &device);
    assert_eq!(plan.classification, Classification::ComponentContent);
    assert_eq!(plan.changed_components, ["icecore-api"]);
    assert_eq!(plan.changed_content, ["kb-corpus"]);
    let _ = golden;
}

/// Identity is the digest of the CANONICAL bytes, never of the input bytes.
/// Hashing the input made re-serialization look like a new release and
/// re-indentation look like a rollback.
#[test]
fn identity_is_canonical_not_raw_input_bytes() {
    let golden = golden();
    let base = fixture("base");
    let reordered = fixture("base-reordered");
    assert_ne!(base, reordered, "the two vectors must differ as bytes");
    assert_eq!(
        digest_for(base),
        digest_for(reordered),
        "canonically equal manifests must share one digest"
    );

    // And that digest is not the hash of either input.
    let raw_base = golden["manifests"]["base"]["raw_sha256"].as_str().unwrap();
    let raw_reordered = golden["manifests"]["base-reordered"]["raw_sha256"]
        .as_str()
        .unwrap();
    assert_ne!(digest_for(base), raw_base);
    assert_ne!(digest_for(base), raw_reordered);

    // Same sequence, canonically identical: a re-apply, not a divergence.
    let plan = classify(base, reordered, &gb10());
    assert_eq!(plan.classification, Classification::NoOp);
    assert_eq!(plan.bundle_seq, Some(41));
}

/// `registry.neural-ice.ch/vendor/...` is a first-class namespace. Rejecting it
/// silently un-ships every third-party component and content payload.
#[test]
fn vendor_namespace_is_accepted_and_foreign_registries_are_not() {
    let parsed = parse(fixture("base")).expect("base parses");
    let vendor: Vec<&str> = parsed
        .value
        .components
        .iter()
        .map(|item| item.payload.repository.as_str())
        .chain(
            parsed
                .value
                .content
                .iter()
                .map(|item| item.payload.repository.as_str()),
        )
        .filter(|repository| repository.starts_with("registry.neural-ice.ch/vendor/"))
        .collect();
    assert!(
        vendor.len() >= 2,
        "the base vector must exercise vendor/ for both components and content"
    );

    assert_eq!(
        refusal_for(fixture("foreign-registry")),
        "host.repository has an invalid value"
    );
}

/// Each Fabric-only field is load-bearing: dropping any of them must refuse,
/// never default. The previous planner carried none of them.
#[test]
fn fabric_only_fields_are_required() {
    for (field, expected) in [
        (
            "compatibility",
            "release manifest is missing fields: compatibility",
        ),
        ("evidence", "release manifest is missing fields: evidence"),
    ] {
        let mut value = base_value();
        value.as_object_mut().unwrap().remove(field);
        let bytes = serde_json::to_vec(&value).unwrap();
        assert_eq!(refusal_for(&bytes), expected, "dropping {field}");
    }

    for field in ["restart_scope", "reboot_required", "required_entitlement"] {
        let mut value = base_value();
        value["host"].as_object_mut().unwrap().remove(field);
        let bytes = serde_json::to_vec(&value).unwrap();
        assert_eq!(
            refusal_for(&bytes),
            format!("host is missing fields: {field}"),
            "dropping host.{field}"
        );
    }
}

/// A restart on replacement must cover the units the INSTALLED payload needs
/// stopped as well as the ones the candidate needs started. Taking only the
/// candidate's side leaves an orphaned unit running against a new digest.
#[test]
fn restart_scope_unions_the_installed_and_candidate_payloads() {
    let plan = classify(fixture("base"), fixture("host"), &gb10());
    assert_eq!(plan.classification, Classification::Host);
    assert_eq!(
        plan.restart_scope,
        [
            "agentic-core.service",
            "ghostunnel-agentic-core.service",
            "ice-agent-runtime.service",
        ],
        "the union of the installed and candidate restart scopes"
    );
    assert!(plan.reboot_required, "a host payload delta reboots");
}

/// Compatibility is checked against the device, in both directions, and a
/// compatibility edit alone is still a host transition — it must not be able to
/// carry a structural change past the host requirement.
#[test]
fn compatibility_gates_the_plan_and_never_downgrades_it() {
    let golden = golden();
    for (device_name, expected) in [
        (
            "wrong-hardware",
            "current manifest incompatible: manifest hardware_target does not match the device",
        ),
        (
            "old-reader",
            "current manifest incompatible: manifest requires a newer release-manifest reader",
        ),
        (
            "missing-contract",
            "current manifest incompatible: device does not support required contracts: content-oci-v1",
        ),
    ] {
        let plan = classify(
            fixture("base"),
            fixture("component-content"),
            &device(&golden, device_name),
        );
        assert_eq!(plan.classification, Classification::Refusal);
        assert_eq!(plan.refusal_reason.as_deref(), Some(expected));
    }

    let plan = classify(fixture("base"), fixture("compatibility-widened"), &gb10());
    assert_eq!(
        plan.classification,
        Classification::Host,
        "a compatibility edit is a host transition even with no host payload delta"
    );
}

/// Anti-rollback: strictly lower refuses, equal is admitted only for the
/// byte-identical canonical manifest.
#[test]
fn bundle_seq_is_monotonic_and_equality_is_digest_bound() {
    let device = gb10();
    let plan = classify(fixture("base"), fixture("rollback"), &device);
    assert_eq!(
        plan.refusal_reason.as_deref(),
        Some("candidate bundle_seq is below the installed floor")
    );
    // A refusal still reports the candidate it refused, so the caller can log it.
    assert_eq!(plan.bundle_seq, Some(40));

    let plan = classify(fixture("base"), fixture("same-seq-divergent"), &device);
    assert_eq!(
        plan.refusal_reason.as_deref(),
        Some("the same bundle_seq identifies a different canonical manifest")
    );
}

/// Without an explicit host delta, only digests may move: membership and
/// contract changes need the host engine.
#[test]
fn structural_changes_require_an_explicit_host_delta() {
    let device = gb10();
    for (candidate, expected) in [
        (
            "component-removed",
            "component membership changed without an explicit host delta",
        ),
        (
            "component-contract-changed",
            "component contract changed without an explicit host delta",
        ),
        (
            "content-restart-changed",
            "content contract changed without an explicit host delta",
        ),
    ] {
        let plan = classify(fixture("base"), fixture(candidate), &device);
        assert_eq!(plan.classification, Classification::Refusal, "{candidate}");
        assert_eq!(
            plan.refusal_reason.as_deref(),
            Some(expected),
            "{candidate}"
        );
    }
}

// ---------------------------------------------------------------------------
// Strict parser bounds
// ---------------------------------------------------------------------------

/// Bounds that are impractical to ship as fixtures are built in memory. Each
/// one is a refusal, never a truncation.
#[test]
fn parser_bounds_are_enforced() {
    // Byte limit, checked before any parsing work.
    let oversized = vec![b' '; MAX_MANIFEST_BYTES + 1];
    assert_eq!(
        refusal_for(&oversized),
        "release manifest exceeds the byte limit"
    );

    // Component cardinality.
    let mut value = base_value();
    let template = value["components"][0].clone();
    let components: Vec<Value> = (0..257)
        .map(|index| {
            let mut item = template.clone();
            item["component_id"] = Value::String(format!("component-{index:03}"));
            item
        })
        .collect();
    value["components"] = Value::Array(components);
    let bytes = serde_json::to_vec(&value).unwrap();
    assert_eq!(
        refusal_for(&bytes),
        "components exceeds its cardinality limit of 256"
    );

    // Invalid UTF-8 anywhere in the document.
    let mut invalid = fixture("base").to_vec();
    invalid.extend_from_slice(&[0xff, 0xfe]);
    assert!(refusal_for(&invalid).starts_with("release manifest is not strict UTF-8 JSON:"));

    // Trailing data after a complete value.
    let mut trailing = fixture("base").to_vec();
    trailing.extend_from_slice(b"{}");
    assert!(refusal_for(&trailing).starts_with("release manifest is not strict UTF-8 JSON:"));
}

/// Number strictness: the digest must not depend on how a producer spells a
/// value, so integral floats are refused rather than coerced.
#[test]
fn numbers_are_strict_integers() {
    assert_eq!(
        refusal_for(fixture("float-bundle-seq")),
        "floating-point JSON number is forbidden: 41.0"
    );
    assert_eq!(
        refusal_for(fixture("non-finite")),
        "non-finite JSON number is forbidden: NaN"
    );
    assert_eq!(
        refusal_for(fixture("oversized-integer")),
        "JSON integer exceeds the safe integer range"
    );

    // An exponent form of a valid sequence is still a float.
    let bytes = String::from_utf8(fixture("base").to_vec())
        .unwrap()
        .replace("\"bundle_seq\": 41", "\"bundle_seq\": 4.1e1");
    assert_eq!(
        refusal_for(bytes.as_bytes()),
        "floating-point JSON number is forbidden: 4.1e1"
    );

    // Zero is not a valid sequence: bundle_seq is positive.
    let bytes = String::from_utf8(fixture("base").to_vec())
        .unwrap()
        .replace("\"bundle_seq\": 41", "\"bundle_seq\": 0");
    assert_eq!(
        refusal_for(bytes.as_bytes()),
        "bundle_seq is outside the safe integer range"
    );
}

/// Duplicate object keys refuse instead of last-wins: otherwise one signature
/// could cover two different manifests depending on the reader.
#[test]
fn duplicate_keys_refuse_instead_of_last_wins() {
    assert_eq!(
        refusal_for(fixture("duplicate-json-key")),
        "duplicate JSON object key: bundle_seq"
    );
    assert_eq!(
        refusal_for(fixture("duplicate-component-id")),
        "duplicate component_id: icecore-api"
    );
}

/// Nothing may declare a contract the compatibility block does not list, or a
/// device could clear the gate and then meet a payload it cannot activate.
#[test]
fn payload_contracts_must_be_declared() {
    assert_eq!(
        refusal_for(fixture("undeclared-contract")),
        "payload contracts are absent from compatibility.required_contracts: component-oci-v1"
    );
}

/// A refused manifest yields a refusal PLAN, never a panic or a permissive
/// default — and a refused current manifest reports no digests at all.
#[test]
fn refusal_is_a_first_class_plan_result() {
    let device = gb10();
    let plan = classify(fixture("release-seq"), fixture("base"), &device);
    assert_eq!(plan.classification, Classification::Refusal);
    assert_eq!(plan.current_manifest_digest, None);
    assert_eq!(plan.candidate_manifest_digest, None);
    assert_eq!(plan.bundle_seq, None);
    assert_eq!(
        plan.refusal_reason.as_deref(),
        Some("current manifest refused: release manifest is missing fields: bundle_seq")
    );

    // A refused candidate still reports the installed digest.
    let plan = classify(fixture("base"), fixture("release-seq"), &device);
    assert_eq!(
        plan.current_manifest_digest,
        Some(digest_for(fixture("base")))
    );
    assert_eq!(plan.candidate_manifest_digest, None);
}

/// Grammar boundaries, mirrored from Fabric's patterns rather than approximated.
///
/// Each of these was wrong before: the identifier bound was read as 127 instead
/// of 1 + 126 + 1, and the unit's length bound and "ends alphanumeric" rule were
/// applied to the whole name instead of the stem. The first two silently refuse
/// manifests Fabric signs; the third accepts a unit Fabric refuses, which is the
/// dangerous direction.
#[test]
fn grammar_bounds_match_fabric_exactly() {
    // Identifier: 128 bytes is admissible, 129 is not.
    assert!(parse(fixture("identifier-max-length")).is_ok());
    assert_eq!(
        refusal_for(fixture("identifier-over-length")),
        "release_id has an invalid value"
    );

    // Systemd unit: the STEM is bounded at 128, so 128 + ".service" = 136 bytes
    // is a legitimate unit name.
    let parsed = parse(fixture("unit-max-length")).expect("a 136-byte unit is valid");
    let unit = &parsed.value.host.restart_scope[0];
    assert_eq!(unit.len(), 136);
    assert_eq!(
        refusal_for(fixture("unit-over-length")),
        "host.restart_scope entry has an invalid value"
    );

    // The stem must END alphanumeric; the suffix's own letter does not count.
    assert_eq!(
        refusal_for(fixture("unit-trailing-punctuation")),
        "host.restart_scope entry has an invalid value"
    );

    // Directly, at the predicate level, so the intent survives a refactor.
    assert!(is_identifier(&"i".repeat(128)));
    assert!(!is_identifier(&"i".repeat(129)));
    assert!(is_systemd_unit(&format!("{}.service", "u".repeat(128))));
    assert!(!is_systemd_unit(&format!("{}.service", "u".repeat(129))));
    for rejected in [
        "foo-.service",
        "foo..service",
        "foo@.socket",
        "-foo.service",
    ] {
        assert!(!is_systemd_unit(rejected), "{rejected} must be refused");
    }
    for accepted in ["foo.service", "a.mount", "getty@tty1.service", "x.timer"] {
        assert!(is_systemd_unit(accepted), "{accepted} must be accepted");
    }
    // A bare suffix has no stem.
    assert!(!is_systemd_unit(".service"));
    assert!(!is_systemd_unit("service"));
}

/// An entitlement move is not a digest-only change: it re-gates who may run the
/// payload, so it needs the host engine. Letting it through as
/// `component-content` would activate a payload under an entitlement the device
/// was never checked against.
#[test]
fn entitlement_change_is_not_a_digest_only_transition() {
    let plan = classify(fixture("base"), fixture("entitlement-changed"), &gb10());
    assert_eq!(plan.classification, Classification::Refusal);
    assert_eq!(
        plan.refusal_reason.as_deref(),
        Some("component contract changed without an explicit host delta")
    );

    // Carried by an explicit host delta it is admissible, as a host transition.
    let plan = classify(
        fixture("base"),
        fixture("entitlement-changed-with-host"),
        &gb10(),
    );
    assert_eq!(plan.classification, Classification::Host);
    assert_eq!(plan.changed_components, ["icecore-api"]);
}

/// The canonical digest is computed in-process, so no external program can
/// influence it. Proven here at the API level and end-to-end through the real
/// binary with a hostile PATH in `tests/cli.rs`.
#[test]
fn canonical_digest_is_computed_in_process() {
    // A known-answer test pins the hash function itself.
    assert_eq!(
        canonical_digest(b"abc"),
        "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    // And the manifest digest is that function over the canonical bytes.
    let parsed = parse(fixture("base")).unwrap();
    assert_eq!(parsed.digest, canonical_digest(&parsed.canonical_bytes));
}
