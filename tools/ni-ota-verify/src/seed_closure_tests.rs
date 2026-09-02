use super::*;
use crate::delegated::{signing_bytes, RELEASE_AUTHORIZATION_V2_DOMAIN, SNAPSHOT_DOMAIN};

fn canonical_json(value: serde_json::Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(&value).unwrap();
    bytes.push(b'\n');
    bytes
}

fn openssl_ok(args: &[&str]) {
    let status = std::process::Command::new("openssl")
        .args(args)
        .status()
        .expect("openssl must be available for the cryptographic fixture");
    assert!(status.success(), "openssl failed: {args:?}");
}

fn generated_p256_key(base: &Path, label: &str) -> (PathBuf, Vec<u8>, serde_json::Value) {
    let private = base.join(format!("{label}.private.pem"));
    let public = base.join(format!("{label}.public.pem"));
    let der = base.join(format!("{label}.public.der"));
    openssl_ok(&[
        "genpkey",
        "-algorithm",
        "EC",
        "-pkeyopt",
        "ec_paramgen_curve:P-256",
        "-out",
        private.to_str().unwrap(),
    ]);
    openssl_ok(&[
        "pkey",
        "-in",
        private.to_str().unwrap(),
        "-pubout",
        "-out",
        public.to_str().unwrap(),
        "-outform",
        "PEM",
    ]);
    openssl_ok(&[
        "pkey",
        "-in",
        private.to_str().unwrap(),
        "-pubout",
        "-out",
        der.to_str().unwrap(),
        "-outform",
        "DER",
    ]);
    let der_bytes = std::fs::read(der).unwrap();
    let public_bytes = std::fs::read(public).unwrap();
    let descriptor = serde_json::json!({
        "algorithm": "ecdsa-p256-sha256",
        "encoding": "spki-der-base64",
        "spki_der_base64": encode_base64(&der_bytes),
        "spki_sha256": hex_digest(&der_bytes)
    });
    (private, public_bytes, descriptor)
}

fn sign_low_s(base: &Path, private: &Path, label: &str, payload: &[u8]) -> Vec<u8> {
    let payload_path = base.join(format!("{label}.payload"));
    let signature_path = base.join(format!("{label}.signature"));
    std::fs::write(&payload_path, payload).unwrap();
    for _ in 0..64 {
        openssl_ok(&[
            "dgst",
            "-sha256",
            "-sign",
            private.to_str().unwrap(),
            "-out",
            signature_path.to_str().unwrap(),
            payload_path.to_str().unwrap(),
        ]);
        let signature = std::fs::read(&signature_path).unwrap();
        if crate::delegated::contract::validate_der_signature(&signature).is_ok() {
            return signature;
        }
    }
    panic!("openssl did not produce a canonical low-S P-256 signature");
}

fn mutate_valid_der_signature(signature: &[u8]) -> Vec<u8> {
    for index in (2..signature.len()).rev() {
        for mask in [1u8, 2, 4, 8] {
            let mut candidate = signature.to_vec();
            candidate[index] ^= mask;
            if candidate != signature
                && crate::delegated::contract::validate_der_signature(&candidate).is_ok()
            {
                return candidate;
            }
        }
    }
    panic!("could not construct a distinct structurally valid DER signature mutation");
}

fn cosign_compatible_test_verifier(base: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let verifier = base.join("cosign-compatible-verify-blob");
    std::fs::write(
        &verifier,
        br#"#!/bin/sh
set -eu
key=
signature=
blob=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --key) key=$2; shift 2 ;;
    --signature) signature=$2; shift 2 ;;
    --insecure-ignore-tlog|--insecure-ignore-tlog=*|--offline) shift ;;
    verify-blob) shift ;;
    *) blob=$1; shift ;;
  esac
done
test -n "$key" && test -n "$signature" && test -n "$blob"
der="${signature}.der"
base64 -d <"$signature" >"$der"
openssl dgst -sha256 -verify "$key" -signature "$der" "$blob"
"#,
    )
    .unwrap();
    let mut permissions = std::fs::metadata(&verifier).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&verifier, permissions).unwrap();
    verifier
}

#[test]
fn canonical_domain_accepts_compact_sorted_ascii_with_one_lf() {
    let bytes = canonical_json(serde_json::json!({"a":1,"b":[true,null,"ascii"]}));
    canonical_value(&bytes, "fixture").unwrap();
}

#[test]
fn canonical_domain_refuses_whitespace_duplicate_unicode_float_and_missing_lf() {
    for bytes in [
        br#"{ "a":1}
"#
        .as_slice(),
        br#"{"a":1,"a":1}
"#,
        b"{\"a\":\"\xc3\xa9\"}\n",
        br#"{"a":1.0}
"#,
        br#"{"a":1}"#,
    ] {
        assert!(canonical_value(bytes, "mutation").is_err(), "{:?}", bytes);
    }
}

#[test]
fn canonical_domain_refuses_integers_outside_interoperable_range() {
    assert!(canonical_value(b"{\"n\":9007199254740992}\n", "large integer").is_err());
}

#[test]
fn digest_grammar_is_exact() {
    assert!(digest_hex(&format!("sha256:{}", "a".repeat(64))).is_ok());
    assert!(digest_hex(&format!("sha256:{}", "A".repeat(64))).is_err());
    assert!(digest_hex(&"a".repeat(64)).is_err());
}

#[test]
fn timestamp_grammar_is_exact_utc_seconds() {
    validate_timestamp("2026-09-02T07:00:00Z", "now").unwrap();
    validate_timestamp("2024-02-29T23:59:59Z", "leap").unwrap();
    for value in [
        "2026-09-02T07:00:00+00:00",
        "2026-09-02T07:00:00.0Z",
        "2026-02-29T00:00:00Z",
        "2026-13-01T00:00:00Z",
        "now",
    ] {
        assert!(validate_timestamp(value, "now").is_err());
    }
}

#[test]
fn repository_is_the_single_canonical_fabric_origin() {
    assert!(valid_repository(
        "registry.example.test/neural-ice/host",
        "registry.example.test"
    ));
    assert!(valid_repository(
        "registry.example.test/vendor/acme/model-v1",
        "registry.example.test"
    ));
    for repository in [
        "mirror.example.test/neural-ice/host",
        "registry.example.test/other/host",
        "registry.example.test/neural-ice/../host",
        "registry.example.test/neural-ice/Host",
    ] {
        assert!(!valid_repository(repository, "registry.example.test"));
    }
    assert!(!valid_repository(
        "registry.example.test/neural-ice/host",
        "mirror.example.test"
    ));
}

#[test]
fn authorization_envelope_is_closed_world() {
    let mut object = serde_json::Map::new();
    object.insert("required".into(), serde_json::json!(true));
    object.insert("surprise".into(), serde_json::json!(true));
    assert!(exact_keys(&object, &["required"], &[], "authorization").is_err());
    object.remove("surprise");
    exact_keys(&object, &["required"], &[], "authorization").unwrap();
}

#[test]
fn descriptor_walk_uses_declared_kind_not_heuristic_json_keys() {
    let bytes = br#"{"schemaVersion":2,"manifests":[{"digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","mediaType":"application/vnd.oci.image.manifest.v1+json","size":12}]}"#;
    assert_eq!(
        descriptor_edges(
            "registry.example.test/r",
            &format!("sha256:{}", "b".repeat(64)),
            bytes,
            "index"
        )
        .unwrap()
        .len(),
        1
    );
    assert!(descriptor_edges(
        "registry.example.test/r",
        &format!("sha256:{}", "b".repeat(64)),
        bytes,
        "layer"
    )
    .is_err());
}

#[test]
fn seed_expectation_has_no_implicit_time_or_authority() {
    let expectation = SeedExpectation {
        registry_host: "registry.example.test".into(),
        hardware_target: "nvidia-gb10-arm64".into(),
        access_profile: "customer-locked".into(),
        device_channel: "stable".into(),
        trust_policy_id: "lab-v1".into(),
        expect_closure: "a".repeat(64),
        expect_manifest: "b".repeat(64),
        trusted_now: "2026-09-02T07:00:00Z".into(),
        pcr_policy_digest: "c".repeat(64),
        pcr_policy_public_key_sha256: "d".repeat(64),
        pcr_policy_signature_sha256: "e".repeat(64),
        pcr_policy_seq: 1,
    };
    assert_eq!(expectation.registry_host, "registry.example.test");
}

#[test]
fn fabric_ring_vectors_bind_exact_domain_separated_bytes() {
    let Ok(root) = std::env::var("NEURAL_ICE_FABRIC_ROOT") else {
        return;
    };
    let fixtures = Path::new(&root).join("release-manifest/coreos-ring-fixtures");
    let index: serde_json::Value = serde_json::from_slice(
        &std::fs::read(fixtures.join("index.json")).expect("Fabric ring vector index"),
    )
    .expect("valid Fabric ring vector index");

    let snapshot = std::fs::read(
        fixtures.join(
            index["delegation_snapshot"]
                .as_str()
                .expect("delegation snapshot path"),
        ),
    )
    .expect("Fabric delegation snapshot");
    canonical_value(&snapshot, "Fabric delegation snapshot").unwrap();
    let message = signing_bytes(SNAPSHOT_DOMAIN, &snapshot).unwrap();
    assert_eq!(
        hex_digest(&message),
        index["delegation_snapshot_signing_digest_sha256"]
            .as_str()
            .unwrap()
    );
    assert_ne!(hex_digest(&snapshot), hex_digest(&message));
    assert_ne!(
        hex_digest(&[SNAPSHOT_DOMAIN, snapshot.as_slice()].concat()),
        hex_digest(&message),
        "the stored LF must not be signed"
    );

    for case in index["cases"].as_array().expect("ring cases") {
        let authorization = std::fs::read(
            fixtures.join(case["authorization"].as_str().expect("authorization path")),
        )
        .expect("Fabric authorization");
        canonical_value(&authorization, "Fabric authorization").unwrap();
        let message = signing_bytes(RELEASE_AUTHORIZATION_V2_DOMAIN, &authorization).unwrap();
        assert_eq!(
            hex_digest(&message),
            case["authorization_signing_digest_sha256"]
                .as_str()
                .unwrap(),
            "{}",
            case["vector_id"].as_str().unwrap()
        );
        assert_ne!(hex_digest(&authorization), hex_digest(&message));
        assert_ne!(
            hex_digest(&[RELEASE_AUTHORIZATION_V2_DOMAIN, authorization.as_slice()].concat()),
            hex_digest(&message),
            "{} signs the terminal LF",
            case["vector_id"].as_str().unwrap()
        );
    }
}

#[test]
fn fabric_generated_closure_is_consumed_when_available() {
    let Ok(root) = std::env::var("NEURAL_ICE_FABRIC_ROOT") else {
        return;
    };
    let root = Path::new(&root);
    let vector_index = root.join("release-manifest/vectors/index.json");
    if vector_index.is_file() {
        let index: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&vector_index).unwrap()).unwrap();
        let vectors = index["vectors"].as_array().unwrap();
        let mut accepted = 0;
        for vector in vectors
            .iter()
            .filter(|v| v["kind"] == "release" && v["expect"] == "accept")
        {
            let auth_path = root
                .join("release-manifest/vectors")
                .join(vector["authorization"].as_str().unwrap());
            let closure_path = root
                .join("release-manifest/vectors")
                .join(vector["closure"].as_str().unwrap());
            let auth = canonical_value(
                &std::fs::read(auth_path).unwrap(),
                "Fabric authorization vector",
            )
            .unwrap();
            let closure = canonical_value(
                &std::fs::read(closure_path).unwrap(),
                "Fabric closure vector",
            )
            .unwrap();
            let _: Closure = canonical(
                &std::fs::read(
                    root.join("release-manifest/vectors")
                        .join(vector["closure"].as_str().unwrap()),
                )
                .unwrap(),
                "Fabric closure-v2 object-root vector",
            )
            .unwrap();
            for signature in closure["artifacts"]
                .as_array()
                .unwrap()
                .iter()
                .flat_map(|artifact| artifact["nodes"].as_array().unwrap())
                .flat_map(|node| node["signatures"].as_array().unwrap())
            {
                assert_eq!(
                    signature["role"], "image-ci",
                    "Fabric must not emit a split image role the root snapshot does not delegate"
                );
            }
            let profile = auth["access_profile"].as_str().unwrap();
            let ring = auth["ring"].as_str().unwrap();
            assert_eq!(ring, vector["device"]["selected_ring"].as_str().unwrap());
            assert_eq!(
                profile,
                vector["device"]["access_profile"].as_str().unwrap()
            );
            assert!(device_channel_allowed(profile, ring));
            assert_eq!(closure["schema"], CLOSURE_SCHEMA);
            assert!(!closure["artifacts"].as_array().unwrap().is_empty());
            accepted += 1;
        }
        assert!(accepted >= 3);
        return;
    }
    let path = root.join("registry-prod/registry-copy/internal/registrycopy/testdata/release-pack/closure.canonical.json");
    if !path.is_file() {
        return;
    }
    let bytes = std::fs::read(path).unwrap();
    let closure: Closure = canonical(&bytes, "Fabric generated closure").unwrap();
    assert_eq!(closure.schema, CLOSURE_SCHEMA);
    assert!(!closure.artifacts.is_empty());
}

#[test]
fn fabric_platform_negative_vectors_reach_the_production_closure_validator() {
    let Ok(root) = std::env::var("NEURAL_ICE_FABRIC_ROOT") else {
        return;
    };
    let vectors = Path::new(&root).join("release-manifest/vectors");
    let index: serde_json::Value =
        serde_json::from_slice(&std::fs::read(vectors.join("index.json")).unwrap()).unwrap();

    for vector_id in [
        "wrong-child-duplicate-platform",
        "wrong-child-unknown-platform",
    ] {
        let vector = index["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|vector| vector["vector_id"] == vector_id)
            .unwrap_or_else(|| panic!("Fabric removed required vector {vector_id}"));
        assert_eq!(vector["expect"], "refuse");
        let bytes = std::fs::read(
            vectors.join(
                vector["closure"]
                    .as_str()
                    .expect("Fabric closure vector path"),
            ),
        )
        .unwrap();
        let mut closure: Closure = canonical(&bytes, "Fabric platform refusal vector").unwrap();
        closure
            .artifacts
            .retain(|artifact| artifact.artifact_key == "image:icecore-api");
        assert_eq!(closure.artifacts.len(), 1);
        // Fabric vectors are parser inputs. Fabric normalizes these set-valued
        // arrays before hashing/signing, so isolate the advertised platform
        // mutation after applying that same unrelated ordering rule.
        closure.artifacts[0].nodes.sort_by(|left, right| {
            (&left.repository, &left.digest).cmp(&(&right.repository, &right.digest))
        });
        closure.artifacts[0].edges.sort();
        let registry = closure.artifacts[0]
            .repository
            .split_once('/')
            .unwrap()
            .0
            .to_owned();
        let error = validate_closure(
            Path::new("/nonexistent-fabric-vector-objects"),
            &closure,
            &registry,
        )
        .expect_err("Fabric platform mutation must reach and fail the production validator");
        assert!(
            error.0.contains("platform"),
            "{vector_id} failed for the wrong reason: {}",
            error.0
        );
    }
}

/// The complete Fabric-derived seed: every document, object and attachment a
/// real seed carries, signed with ephemeral P-256 keys so the PRODUCTION
/// verifier can be driven end to end. READY is deliberately not written.
struct CompleteFixture {
    seed_root: PathBuf,
    root_key: Vec<u8>,
    root_private: PathBuf,
    release_private: PathBuf,
    verifier: PathBuf,
    expectation: SeedExpectation,
    authorization_bytes: Vec<u8>,
    authorization_message: Vec<u8>,
    authorization_signature: Vec<u8>,
    closure_hash: String,
    release_manifest_hash: String,
    object_count: usize,
}

fn complete_fabric_fixture(base: &Path) -> Option<CompleteFixture> {
    let Ok(fabric_root) = std::env::var("NEURAL_ICE_FABRIC_ROOT") else {
        return None;
    };
    let fabric = Path::new(&fabric_root).join("release-manifest");
    let ring_fixtures = fabric.join("coreos-ring-fixtures");
    std::fs::create_dir_all(base).unwrap();
    let (root_private, root_key, root_public) = generated_p256_key(base, "root");
    let (release_private, _, release_public) = generated_p256_key(base, "release-beta");
    let (image_private, _, image_public) = generated_p256_key(base, "image-ci");
    let verifier = cosign_compatible_test_verifier(base);

    // Fabric owns every field and vocabulary in the fixture.  Only ephemeral
    // public keys are substituted so this test can produce real signatures and
    // drive the production verifier rather than an always-success callback.
    let source_snapshot = std::fs::read(ring_fixtures.join("delegation-snapshot.json")).unwrap();
    let mut snapshot_value =
        canonical_value(&source_snapshot, "Fabric delegation snapshot").unwrap();
    snapshot_value["root_key"]["public_key"] = root_public;
    for key in snapshot_value["keys"].as_array_mut().unwrap() {
        match key["role"].as_str().unwrap() {
            "release-beta" => key["public_key"] = release_public.clone(),
            "image-ci" => key["public_key"] = image_public.clone(),
            _ => {}
        }
    }
    let snapshot_bytes = canonical_json(snapshot_value.clone());
    let snapshot: Snapshot =
        parse_canonical(&snapshot_bytes, "Fabric delegation snapshot").unwrap();
    validate_snapshot(&snapshot).unwrap();
    let embedded_root_public: crate::delegated::contract::PublicKey =
        serde_json::from_value(snapshot_value["root_key"]["public_key"].clone()).unwrap();
    assert_eq!(root_key, public_key_pem(&embedded_root_public).unwrap());

    let vectors = fabric.join("vectors");
    let vector_index: serde_json::Value =
        serde_json::from_slice(&std::fs::read(vectors.join("index.json")).unwrap()).unwrap();
    let install = vector_index["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|vector| {
            if vector["kind"] != "release" || vector["expect"] != "accept" {
                return false;
            }
            let authorization: serde_json::Value = serde_json::from_slice(
                &std::fs::read(vectors.join(vector["authorization"].as_str().unwrap())).unwrap(),
            )
            .unwrap();
            authorization["purpose"] == "install" && authorization["ring"] == "beta"
        })
        .expect("Fabric must carry an accepted beta install vector");
    let mut authorization: serde_json::Value = canonical_value(
        &std::fs::read(vectors.join(install["authorization"].as_str().unwrap())).unwrap(),
        "Fabric install authorization",
    )
    .unwrap();

    fn put_object(objects: &mut BTreeMap<String, Vec<u8>>, bytes: Vec<u8>) -> String {
        let digest = format!("sha256:{}", hex_digest(&bytes));
        objects.insert(digest.clone(), bytes);
        digest
    }

    fn attachment(
        objects: &mut BTreeMap<String, Vec<u8>>,
        repository: &str,
        subject: &str,
        config_digest: &str,
        kind: &str,
        payload: Vec<u8>,
        signature: &[u8],
    ) -> (String, String, serde_json::Value) {
        let config_size = objects[config_digest].len();
        let payload_digest = put_object(objects, payload);
        let payload_size = objects[&payload_digest].len();
        let manifest = canonical_json(serde_json::json!({
            "config": {
                "digest": config_digest,
                "mediaType": "application/vnd.oci.empty.v1+json",
                "size": config_size
            },
            "layers": [{
                "annotations": {
                    "dev.cosignproject.cosign/signature": encode_base64(signature)
                },
                "digest": payload_digest,
                "mediaType": "application/vnd.dev.cosign.simplesigning.v1+json",
                "size": payload_size
            }],
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "schemaVersion": 2
        }));
        let manifest_digest = put_object(objects, manifest);
        let suffix = match kind {
            "signature" => "sig",
            "sbom" => "sbom",
            "provenance" => "att",
            _ => unreachable!(),
        };
        let subject_hex = subject.strip_prefix("sha256:").unwrap();
        let record = serde_json::json!({
            "artifact_type": match kind {
                "signature" => "application/vnd.dev.cosign.simplesigning.v1+json",
                "sbom" => "application/spdx+json",
                "provenance" => "application/vnd.in-toto+json",
                _ => unreachable!(),
            },
            "discovery": {
                "cosign_tag": format!("sha256-{subject_hex}.{suffix}"),
                "fallback_tag": format!("sha256-{subject_hex}"),
                "referrers_api": true
            },
            "kind": kind,
            "layer_digests": [payload_digest],
            "manifest_digest": manifest_digest,
            "media_type": "application/vnd.oci.image.manifest.v1+json",
            "predicate_type": null,
            "subject_digest": subject,
            "subject_repository": repository
        });
        (manifest_digest, payload_digest, record)
    }

    let repository = "registry.example.test/neural-ice/neural-ice-appliance";
    let media_manifest = "application/vnd.oci.image.manifest.v1+json";
    let media_config = "application/vnd.oci.image.config.v1+json";
    let media_layer = "application/vnd.oci.image.layer.v1.tar";
    let mut objects = BTreeMap::new();
    let config_digest = put_object(&mut objects, b"{}\n".to_vec());
    let layer_digest = put_object(&mut objects, b"complete-seed-fixture-layer\n".to_vec());
    let manifest_bytes = canonical_json(serde_json::json!({
        "config": {
            "digest": config_digest,
            "mediaType": media_config,
            "size": objects[&config_digest].len()
        },
        "layers": [{
            "digest": layer_digest,
            "mediaType": media_layer,
            "size": objects[&layer_digest].len()
        }],
        "mediaType": media_manifest,
        "schemaVersion": 2
    }));
    let host_digest = put_object(&mut objects, manifest_bytes);
    let attachment_config = put_object(&mut objects, b"{}\n".to_vec());
    let signing_payload = canonical_json(serde_json::json!({
        "critical": {
            "identity": {"docker-reference": repository},
            "image": {"docker-manifest-digest": host_digest},
            "type": "cosign container image signature"
        },
        "optional": {}
    }));
    let image_signature = sign_low_s(base, &image_private, "image", &signing_payload);
    let (signature_manifest, signature_payload, signature_attachment) = attachment(
        &mut objects,
        repository,
        &host_digest,
        &attachment_config,
        "signature",
        signing_payload,
        &image_signature,
    );
    let (sbom_manifest, _, sbom_attachment) = attachment(
        &mut objects,
        repository,
        &host_digest,
        &attachment_config,
        "sbom",
        b"{\"spdxVersion\":\"SPDX-2.3\"}\n".to_vec(),
        &image_signature,
    );
    let (provenance_manifest, _, provenance_attachment) = attachment(
        &mut objects,
        repository,
        &host_digest,
        &attachment_config,
        "provenance",
        b"{\"predicateType\":\"https://slsa.dev/provenance/v1\"}\n".to_vec(),
        &image_signature,
    );

    let release_id = authorization["release_id"].as_str().unwrap().to_owned();
    let bundle_seq = authorization["bundle_seq"].as_u64().unwrap();
    let hardware_target = authorization["hardware_target"]
        .as_str()
        .unwrap()
        .to_owned();
    let boot_trust_policy = authorization["boot_trust_policy_sha256"]
        .as_str()
        .unwrap()
        .to_owned();
    let release_manifest = canonical_json(serde_json::json!({
        "bundle_seq": bundle_seq,
        "compatibility": {
            "minimum_reader": 1,
            "required_contracts": ["host-bootc-v1"]
        },
        "components": [],
        "content": [],
        "evidence": [],
        "hardware_target": hardware_target,
        "host": {
            "contract": "host-bootc-v1",
            "digest": host_digest,
            "reboot_required": true,
            "repository": repository,
            "required_entitlement": "BASE",
            "restart_scope": []
        },
        "release_id": release_id,
        "schema": "neural-ice-release-manifest-v1"
    }));
    let release_manifest_hash = hex_digest(&release_manifest);
    let delegation_hash = canonical_hash(&snapshot_bytes).unwrap();

    let mut nodes = vec![
        serde_json::json!({
            "artifact_type": null,
            "digest": host_digest,
            "kind": "manifest",
            "media_type": media_manifest,
            "provenance": provenance_manifest,
            "repository": repository,
            "sbom": sbom_manifest,
            "signatures": [{
                "attachment_digest": signature_manifest,
                "attachment_tag": format!("sha256-{}.sig", host_digest.strip_prefix("sha256:").unwrap()),
                "identity": repository,
                "key_id": "image-ci-v1",
                "layer_digests": [signature_payload],
                "payload_sha256": signature_payload.strip_prefix("sha256:").unwrap(),
                "role": "image-ci",
                "scheme": "cosign-sigstore-v1"
            }],
            "size": objects[&host_digest].len(),
            "subject": null
        }),
        serde_json::json!({
            "artifact_type": null,
            "digest": config_digest,
            "kind": "config",
            "media_type": media_config,
            "provenance": null,
            "repository": repository,
            "sbom": null,
            "signatures": [],
            "size": objects[&config_digest].len(),
            "subject": null
        }),
        serde_json::json!({
            "artifact_type": null,
            "digest": layer_digest,
            "kind": "layer",
            "media_type": media_layer,
            "provenance": null,
            "repository": repository,
            "sbom": null,
            "signatures": [],
            "size": objects[&layer_digest].len(),
            "subject": null
        }),
    ];
    nodes.sort_by(|left, right| {
        left["digest"]
            .as_str()
            .unwrap()
            .cmp(right["digest"].as_str().unwrap())
    });
    let mut attachments = vec![signature_attachment, sbom_attachment, provenance_attachment];
    attachments.sort_by(|left, right| {
        left["kind"]
            .as_str()
            .unwrap()
            .cmp(right["kind"].as_str().unwrap())
    });
    let closure_bytes = canonical_json(serde_json::json!({
        "access_policy_sha256": authorization["access_policy_sha256"],
        "artifacts": [{
            "artifact_class": "hardware-targeted-manifest",
            "artifact_key": "os:neural-ice-appliance",
            "assembly": null,
            "attachments": attachments,
            "candidate_repository": "ghcr.io/neural-ice/neural-ice-appliance",
            "chunked": null,
            "edges": [{
                "annotations": {},
                "artifact_type": null,
                "child_digest": config_digest,
                "child_repository": repository,
                "data": null,
                "edge_kind": "config",
                "media_type": media_config,
                "parent_digest": host_digest,
                "parent_repository": repository,
                "platform": null,
                "position": 0,
                "size": objects[&config_digest].len(),
                "urls": []
            }, {
                "annotations": {},
                "artifact_type": null,
                "child_digest": layer_digest,
                "child_repository": repository,
                "data": null,
                "edge_kind": "layers",
                "media_type": media_layer,
                "parent_digest": host_digest,
                "parent_repository": repository,
                "platform": null,
                "position": 0,
                "size": objects[&layer_digest].len(),
                "urls": []
            }],
            "node_counts": {"config": 1, "index": 0, "layer": 1, "manifest": 1},
            "nodes": nodes,
            "repository": repository,
            "required_entitlement": "BASE",
            "root": {"digest": host_digest, "repository": repository},
            "target": hardware_target,
            "vendor": null
        }],
        "boot_trust_policy_sha256": authorization["boot_trust_policy_sha256"],
        "boot_trust_profile": authorization["boot_trust_profile"],
        "bundle_seq": bundle_seq,
        "closure_format_version": 1,
        "delegation_seq": snapshot.delegation_seq,
        "delegation_snapshot_sha256": delegation_hash,
        "hardware_target": hardware_target,
        "host_digest": host_digest,
        "release_id": release_id,
        "release_manifest_sha256": release_manifest_hash,
        "schema": CLOSURE_SCHEMA,
        "security_posture": "sealed",
        "train": authorization["train"],
        "traversal_bound": 8
    }));
    let closure_hash = hex_digest(&closure_bytes);

    authorization["bundle_seq"] = serde_json::json!(bundle_seq);
    authorization["closure_coverage"] = serde_json::json!({
        "artifacts": 1,
        "config_nodes": 1,
        "edges": 2,
        "layer_nodes": 1,
        "signed_structural_nodes": 1,
        "structural_nodes": 1,
        "traversal_bound": 8
    });
    authorization["delegation_seq"] = serde_json::json!(snapshot.delegation_seq);
    authorization["delegation_snapshot_sha256"] = serde_json::json!(delegation_hash);
    authorization["host_digest"] = serde_json::json!(host_digest);
    authorization["release_closure_sha256"] = serde_json::json!(closure_hash);
    authorization["release_manifest_sha256"] = serde_json::json!(release_manifest_hash);
    authorization["subject"] = serde_json::json!({
        "digest": host_digest,
        "media_type": media_manifest,
        "repository": repository
    });
    let authorization_bytes = canonical_json(authorization);
    let delegation_message = signing_bytes(SNAPSHOT_DOMAIN, &snapshot_bytes).unwrap();
    let delegation_signature = sign_low_s(base, &root_private, "delegation", &delegation_message);
    let authorization_message =
        signing_bytes(RELEASE_AUTHORIZATION_V2_DOMAIN, &authorization_bytes).unwrap();
    let authorization_signature = sign_low_s(
        base,
        &release_private,
        "authorization",
        &authorization_message,
    );

    let seed_root = base.join(&closure_hash);
    let object_root = seed_root.join("objects/sha256");
    std::fs::create_dir_all(&object_root).unwrap();
    std::fs::write(seed_root.join("release-manifest.json"), &release_manifest).unwrap();
    std::fs::write(seed_root.join("release-closure.json"), &closure_bytes).unwrap();
    std::fs::write(
        seed_root.join("release-authorization.json"),
        &authorization_bytes,
    )
    .unwrap();
    std::fs::write(
        seed_root.join("release-authorization.json.sig"),
        &authorization_signature,
    )
    .unwrap();
    std::fs::write(seed_root.join("delegation-snapshot.json"), &snapshot_bytes).unwrap();
    std::fs::write(
        seed_root.join("delegation-snapshot.json.sig"),
        &delegation_signature,
    )
    .unwrap();
    for (digest, bytes) in &objects {
        std::fs::write(
            object_root.join(digest.strip_prefix("sha256:").unwrap()),
            bytes,
        )
        .unwrap();
    }

    let expectation = SeedExpectation {
        registry_host: "registry.example.test".into(),
        hardware_target,
        access_profile: "customer-locked".into(),
        device_channel: "beta".into(),
        trust_policy_id: "neural-ice-secureboot-prod-v1".into(),
        expect_closure: closure_hash.clone(),
        expect_manifest: release_manifest_hash.clone(),
        trusted_now: "2026-09-15T12:00:00Z".into(),
        pcr_policy_digest: boot_trust_policy,
        pcr_policy_public_key_sha256: "a".repeat(64),
        pcr_policy_signature_sha256: "b".repeat(64),
        pcr_policy_seq: 1,
    };
    Some(CompleteFixture {
        seed_root,
        root_key,
        root_private,
        release_private,
        verifier,
        expectation,
        authorization_bytes,
        authorization_message,
        authorization_signature,
        closure_hash,
        release_manifest_hash,
        object_count: objects.len(),
    })
}

#[test]
fn fabric_delegation_drives_a_complete_verify_seed_with_fixture() {
    let base = std::env::temp_dir().join(format!(
        "ni-seed-complete-{}-{}",
        std::process::id(),
        TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let Some(fixture) = complete_fabric_fixture(&base) else {
        return;
    };
    let CompleteFixture {
        seed_root,
        root_key,
        root_private,
        release_private,
        verifier,
        expectation,
        authorization_bytes,
        authorization_message,
        authorization_signature,
        closure_hash,
        release_manifest_hash,
        object_count,
    } = fixture;
    let scratch = base.join("production-signature-scratch");
    let mut verify = |key: &[u8], signature: &[u8], payload: &[u8]| {
        production_signature_at(&scratch, &verifier, key, signature, payload)
    };
    let missing_ready = verify_seed_with(&seed_root, &root_key, &expectation, &mut verify)
        .expect_err("a complete but unpublished seed must refuse");
    assert!(missing_ready.0.contains("READY"), "{}", missing_ready.0);

    let ready = canonical_json(serde_json::json!({
        "object_count": object_count,
        "release_closure_sha256": closure_hash,
        "release_manifest_sha256": release_manifest_hash,
        "schema": READY_SCHEMA
    }));
    std::fs::write(seed_root.join("READY"), ready).unwrap();
    let verdict = verify_seed_with(&seed_root, &root_key, &expectation, &mut verify).unwrap();
    assert_eq!(verdict.objects, object_count);
    assert_eq!(verdict.artifacts, 1);

    let raw_signature = sign_low_s(
        &base,
        &release_private,
        "authorization-raw-file",
        &authorization_bytes,
    );
    let mut wrong_domain_message = b"neural-ice:ota:wrong-domain:v1\0".to_vec();
    wrong_domain_message.extend_from_slice(authorization_bytes.strip_suffix(b"\n").unwrap());
    let wrong_domain_signature = sign_low_s(
        &base,
        &release_private,
        "authorization-wrong-domain",
        &wrong_domain_message,
    );
    let wrong_key_signature = sign_low_s(
        &base,
        &root_private,
        "authorization-wrong-key",
        &authorization_message,
    );
    let corrupt_signature = mutate_valid_der_signature(&authorization_signature);
    for (label, mutation) in [
        ("raw-file bytes", raw_signature),
        ("wrong domain", wrong_domain_signature),
        ("wrong key", wrong_key_signature),
        ("mutated signature", corrupt_signature),
    ] {
        std::fs::write(seed_root.join("release-authorization.json.sig"), mutation).unwrap();
        let error =
            verify_seed_with(&seed_root, &root_key, &expectation, &mut verify).expect_err(label);
        assert!(
            error.0.contains("signature"),
            "{label} failed for the wrong reason: {}",
            error.0
        );
    }
    std::fs::write(
        seed_root.join("release-authorization.json.sig"),
        authorization_signature,
    )
    .unwrap();
    std::fs::remove_dir_all(base).unwrap();
}

/// 🔴 THE PRODUCTION SIGNATURE PATH CANNOT BE REDIRECTED (review 2026-09-02,
/// P1). `NI_OTA_COSIGN=/usr/bin/true` used to turn every `verify_blob` into a
/// success in every build. This drives the real `verify_seed` entry -- the one
/// the installer and first boot call, whose only verifier is
/// `production_signature` -- with that environment set, in the default-feature
/// build the OS image ships. A corrupt root→snapshot signature, a corrupt
/// release authorization, and the intact seed (whose last check is the OCI
/// attestation) must all reach the pinned /usr/bin/cosign or refuse; none may
/// pass through `/usr/bin/true`.
#[cfg(not(feature = "test-path-overrides"))]
#[test]
fn production_verifier_ignores_the_cosign_environment_seam() {
    let base = std::env::temp_dir().join(format!(
        "ni-seed-production-seam-{}-{}",
        std::process::id(),
        TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let Some(fixture) = complete_fabric_fixture(&base) else {
        return;
    };
    let ready = canonical_json(serde_json::json!({
        "object_count": fixture.object_count,
        "release_closure_sha256": fixture.closure_hash,
        "release_manifest_sha256": fixture.release_manifest_hash,
        "schema": READY_SCHEMA
    }));
    std::fs::write(fixture.seed_root.join("READY"), ready).unwrap();
    let root_key_path = base.join("root.pub");
    std::fs::write(&root_key_path, &fixture.root_key).unwrap();
    std::env::set_var("NI_OTA_COSIGN", "/usr/bin/true");

    let pinned_cosign_present = Path::new("/usr/bin/cosign").is_file();
    let must_not_pass =
        |label: &str| match verify_seed(&fixture.seed_root, &root_key_path, &fixture.expectation) {
            Ok(Ok(_)) => panic!("{label}: the production verifier accepted the seed"),
            Ok(Err(Refusal(reason))) => {
                assert!(
                    !reason.contains("/usr/bin/true"),
                    "{label}: the seam executable was consulted: {reason}"
                );
                if !pinned_cosign_present {
                    assert!(
                        reason.contains("cosign not found at /usr/bin/cosign"),
                        "{label}: refused for a reason other than the pinned path: {reason}"
                    );
                }
            }
            Err(InternalError(reason)) => panic!("{label}: internal error: {reason}"),
        };

    let delegation_signature =
        std::fs::read(fixture.seed_root.join("delegation-snapshot.json.sig")).unwrap();
    std::fs::write(
        fixture.seed_root.join("delegation-snapshot.json.sig"),
        mutate_valid_der_signature(&delegation_signature),
    )
    .unwrap();
    must_not_pass("corrupt root→snapshot signature");
    std::fs::write(
        fixture.seed_root.join("delegation-snapshot.json.sig"),
        &delegation_signature,
    )
    .unwrap();

    std::fs::write(
        fixture.seed_root.join("release-authorization.json.sig"),
        mutate_valid_der_signature(&fixture.authorization_signature),
    )
    .unwrap();
    must_not_pass("corrupt release authorization signature");
    std::fs::write(
        fixture.seed_root.join("release-authorization.json.sig"),
        &fixture.authorization_signature,
    )
    .unwrap();

    // The intact seed: every signature is genuine, so only a real cosign may
    // accept it. Without the pinned binary the OCI attestation step -- the
    // last verification -- is where the pinned path is reported missing.
    if pinned_cosign_present {
        // A real /usr/bin/cosign legitimately verifies the ephemeral-key
        // fixture; what is proven here is that the seam had no say in it.
        let _ = verify_seed(&fixture.seed_root, &root_key_path, &fixture.expectation);
    } else {
        must_not_pass("intact seed without the pinned cosign");
    }
    std::env::remove_var("NI_OTA_COSIGN");
    std::fs::remove_dir_all(base).unwrap();
}

#[test]
fn fabric_install_authorization_profile_and_mutations_are_differential() {
    let Ok(root) = std::env::var("NEURAL_ICE_FABRIC_ROOT") else {
        return;
    };
    let vectors = Path::new(&root).join("release-manifest/vectors");
    let index: serde_json::Value =
        serde_json::from_slice(&std::fs::read(vectors.join("index.json")).unwrap()).unwrap();
    let vector = index["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|vector| {
            if vector["kind"] != "release" || vector["expect"] != "accept" {
                return false;
            }
            let bytes =
                std::fs::read(vectors.join(vector["authorization"].as_str().unwrap())).unwrap();
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["purpose"] == "install"
        })
        .expect("Fabric must carry an accepted install-purpose vector");
    let bytes = std::fs::read(vectors.join(vector["authorization"].as_str().unwrap())).unwrap();
    let value = canonical_value(&bytes, "Fabric install authorization").unwrap();
    validate_authorization_contract(value.as_object().unwrap()).unwrap();

    for mutate in [
        |value: &mut serde_json::Value| value["installer_medium"] = serde_json::Value::Null,
        |value: &mut serde_json::Value| value["security_posture"] = serde_json::json!("debug"),
        |value: &mut serde_json::Value| value["copy_completion_receipts"] = serde_json::json!([]),
        |value: &mut serde_json::Value| value["qualification_receipt"] = serde_json::Value::Null,
    ] {
        let mut changed = value.clone();
        mutate(&mut changed);
        assert!(validate_authorization_contract(changed.as_object().unwrap()).is_err());
    }
}
