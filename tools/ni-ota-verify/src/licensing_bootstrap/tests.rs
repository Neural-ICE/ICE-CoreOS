use super::*;
use crate::delegated::contract::{parse_canonical, public_key_pem, validate_snapshot, Snapshot};

const DER: &[u8] = &[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];
const SNAPSHOT: &[u8] =
    include_bytes!("../../tests/fixtures/delegated-v1/delegation-snapshot.json");
const CONTRACT: &[u8] = include_bytes!("../../contracts/licensing-bootstrap-v1.contract.json");

fn canonical<T: Serialize>(value: &T) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(value).unwrap();
    bytes.push(b'\n');
    bytes
}

fn contract_fields(schema: &str) -> Vec<String> {
    let contract: serde_json::Value = serde_json::from_slice(CONTRACT).unwrap();
    contract["artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|artifact| artifact["schema"] == schema)
        .unwrap()["fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|field| field.as_str().unwrap().to_owned())
        .collect()
}

fn structure_fields(name: &str) -> Vec<String> {
    let contract: serde_json::Value = serde_json::from_slice(CONTRACT).unwrap();
    contract["structures"][name]
        .as_array()
        .unwrap()
        .iter()
        .map(|field| field.as_str().unwrap().to_owned())
        .collect()
}

fn serialized_fields<T: Serialize>(value: &T) -> Vec<String> {
    serde_json::to_value(value)
        .unwrap()
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn snapshot() -> Snapshot {
    let mut value: serde_json::Value = serde_json::from_slice(SNAPSHOT).unwrap();
    let key = &mut value["keys"][0];
    key["key_id"] = "licensing-bootstrap-v1".into();
    key["role"] = "licensing-bootstrap".into();
    key["artifact_types"] = serde_json::json!([
        "ota-licensing-bootstrap-v1",
        "ota-licensing-recovery-ack-v1"
    ]);
    let bytes = canonical(&value);
    parse_canonical(&bytes, "snapshot").unwrap()
}

fn snapshot_bytes(snapshot: &Snapshot) -> Vec<u8> {
    canonical(&serde_json::to_value(snapshot).unwrap())
}

fn baseline(snapshot: &Snapshot) -> BaselineIdentity {
    BaselineIdentity {
        baseline_manifest_sha256: "a".repeat(64),
        bootstrap_delegation_seq: snapshot.delegation_seq,
        bootstrap_snapshot_sha256: canonical_hash(&snapshot_bytes(snapshot)).unwrap(),
        compatibility_version: 5,
        hardware_target: "nvidia-gb10-arm64".into(),
        minimum_bundle_seq: 1,
        minimum_delegation_seq: 1,
        minimum_recovery_seq: 0,
        minimum_trusted_time_seq: 1,
        os_image_manifest_digest: format!("sha256:{}", "c".repeat(64)),
        ota_root_spki_sha256: snapshot.root_spki_sha256().into(),
        ota_root_version: snapshot.root_version(),
        release_variant: "debug".into(),
    }
}

fn device(byte: char) -> DeviceRootIdentity {
    DeviceRootIdentity {
        spki_sha256: byte.to_string().repeat(64),
        tpm_name: format!("000b{}", byte.to_string().repeat(64)),
    }
}

fn state(snapshot: &Snapshot) -> AuthoritativeState {
    AuthoritativeState {
        baseline: baseline(snapshot),
        bundle_seq: 9,
        delegation_seq: 1,
        delegation_snapshot_sha256: baseline(snapshot).bootstrap_snapshot_sha256,
        last_trusted_time_assertion_sha256: "f".repeat(64),
        recovery_seq: 1,
        recovery_sha256: Some("1".repeat(64)),
        release_authorizations: vec![ReleaseAuthorizationHighWater {
            authorization_sha256: "2".repeat(64),
            bundle_seq: 9,
            ring: "beta".into(),
        }],
        root_spki_sha256: baseline(snapshot).ota_root_spki_sha256,
        root_transition_sha256: None,
        root_version: 1,
        trusted_time: "2026-07-21T12:00:00Z".into(),
        trusted_time_recovery_floor: "2026-07-21T12:05:00Z".into(),
        trusted_time_seq: 8,
    }
}

fn initial(snapshot: &Snapshot) -> LicensingBootstrapAuthorization {
    LicensingBootstrapAuthorization {
        active_product: "icecore".into(),
        authoritative_state: None,
        baseline: baseline(snapshot),
        bootstrap_seq: 1,
        device_root: device('3'),
        device_serial: "device-001".into(),
        entitlement_policy_revision: "policy-v7".into(),
        issuance_id: "bootstrap-0001".into(),
        issued_at: "2026-07-21T12:00:00Z".into(),
        key_id: "licensing-bootstrap-v1".into(),
        licence_record_id: "4".repeat(64),
        licensing_bootstrap_nonce: "5".repeat(64),
        previous_authorization_sha256: None,
        previous_device_root: None,
        reason: "initial_activation".into(),
        schema: "ota-licensing-bootstrap-v1".into(),
        signature_algorithm: "ecdsa-p256-sha256".into(),
        signature_encoding: "asn1-der".into(),
        signing_role: "licensing-bootstrap".into(),
        tpm_clock: 1_000,
        tpm_reset_count: 2,
        tpm_restart_count: 3,
        tpm_safe: true,
        valid_until: "2026-07-21T12:10:00Z".into(),
    }
}

fn expected<'a>(value: &'a LicensingBootstrapAuthorization) -> ExpectedBootstrap<'a> {
    ExpectedBootstrap {
        active_product: &value.active_product,
        authoritative_state: value.authoritative_state.as_ref(),
        baseline: &value.baseline,
        bootstrap_seq: value.bootstrap_seq,
        current_tpm: CurrentTpmState {
            tpm_clock: value.tpm_clock + 599_000,
            tpm_reset_count: value.tpm_reset_count,
            tpm_restart_count: value.tpm_restart_count,
            tpm_safe: true,
        },
        device_root: &value.device_root,
        device_serial: &value.device_serial,
        entitlement_policy_revision: &value.entitlement_policy_revision,
        licence_record_id: &value.licence_record_id,
        pending: PendingChallenge {
            nonce: &value.licensing_bootstrap_nonce,
            tpm_clock: value.tpm_clock,
            tpm_reset_count: value.tpm_reset_count,
            tpm_restart_count: value.tpm_restart_count,
        },
        previous_authorization_sha256: value.previous_authorization_sha256.as_deref(),
        previous_device_root: value.previous_device_root.as_ref(),
        reason: &value.reason,
    }
}

fn accept_expected_domain(
    _key: &[u8],
    domain: &[u8],
    _payload: &[u8],
    _signature: &[u8],
) -> Result<(), ContractError> {
    if domain == BOOTSTRAP_DOMAIN && domain.last() == Some(&0) {
        Ok(())
    } else {
        Err("wrong domain".into())
    }
}

#[test]
fn initial_authorization_binds_every_local_input_and_terminal_nul_domain() {
    let snapshot = snapshot();
    let value = initial(&snapshot);
    let verified = verify_bootstrap_with(
        &snapshot,
        &snapshot_bytes(&snapshot),
        &canonical(&value),
        DER,
        &expected(&value),
        accept_expected_domain,
    )
    .unwrap();
    assert_eq!(verified.bootstrap_seq, 1);
    assert_eq!(verified.reason, "initial_activation");
}

#[test]
fn delegation_scope_for_licensing_is_closed_and_hardware_complete() {
    let snapshot = snapshot();
    validate_snapshot(&snapshot).unwrap();
    for case in ["artifact", "ring", "target"] {
        let mut value = serde_json::to_value(&snapshot).unwrap();
        match case {
            "artifact" => {
                value["keys"][0]["artifact_types"] =
                    serde_json::json!(["ota-licensing-bootstrap-v1"])
            }
            "ring" => value["keys"][0]["rings"] = serde_json::json!(["beta"]),
            "target" => {
                value["keys"][0]["hardware_targets"] = serde_json::json!(["nvidia-gb10-arm64"])
            }
            _ => unreachable!(),
        }
        let hostile: Snapshot = parse_canonical(&canonical(&value), "snapshot").unwrap();
        assert!(validate_snapshot(&hostile).is_err(), "{case}");
    }
}

#[test]
fn bootstrap_refuses_wrong_device_nonce_baseline_licence_or_chain_replay() {
    let snapshot = snapshot();
    let signed = initial(&snapshot);
    let bytes = canonical(&signed);
    for case in [
        "device", "nonce", "baseline", "licence", "sequence", "previous",
    ] {
        let mut expected_value = signed.clone();
        match case {
            "device" => expected_value.device_root = device('6'),
            "nonce" => expected_value.licensing_bootstrap_nonce = "6".repeat(64),
            "baseline" => expected_value.baseline.baseline_manifest_sha256 = "6".repeat(64),
            "licence" => expected_value.licence_record_id = "6".repeat(64),
            "sequence" => expected_value.bootstrap_seq = 2,
            "previous" => expected_value.previous_authorization_sha256 = Some("6".repeat(64)),
            _ => unreachable!(),
        }
        assert!(
            verify_bootstrap_with(
                &snapshot,
                &snapshot_bytes(&snapshot),
                &bytes,
                DER,
                &expected(&expected_value),
                accept_expected_domain,
            )
            .is_err(),
            "{case}"
        );
    }
}

#[test]
fn recovery_requires_previous_device_full_floors_and_exact_reason() {
    let snapshot = snapshot();
    let mut value = initial(&snapshot);
    value.bootstrap_seq = 2;
    value.previous_authorization_sha256 = Some("6".repeat(64));
    value.previous_device_root = Some(device('7'));
    value.authoritative_state = Some(state(&snapshot));
    value.reason = "state_loss_recovery".into();
    assert!(verify_bootstrap_with(
        &snapshot,
        &snapshot_bytes(&snapshot),
        &canonical(&value),
        DER,
        &expected(&value),
        accept_expected_domain,
    )
    .is_ok());

    for case in [
        "reason",
        "previous-device",
        "same-device-root",
        "floor",
        "proof-hash",
    ] {
        let mut hostile = value.clone();
        match case {
            "reason" => hostile.reason = "initial_activation".into(),
            "previous-device" => hostile.previous_device_root = None,
            "same-device-root" => hostile.previous_device_root = Some(hostile.device_root.clone()),
            "floor" => {
                hostile.authoritative_state.as_mut().unwrap().bundle_seq = MAX_SAFE_INTEGER + 1
            }
            "proof-hash" => {
                hostile
                    .authoritative_state
                    .as_mut()
                    .unwrap()
                    .recovery_sha256 = None
            }
            _ => unreachable!(),
        }
        assert!(
            verify_bootstrap_with(
                &snapshot,
                &snapshot_bytes(&snapshot),
                &canonical(&hostile),
                DER,
                &expected(&value),
                accept_expected_domain,
            )
            .is_err(),
            "{case}"
        );
    }

    let mut no_recovery_history = value.clone();
    let state = no_recovery_history.authoritative_state.as_mut().unwrap();
    state.recovery_seq = 0;
    state.recovery_sha256 = None;
    assert!(verify_bootstrap_with(
        &snapshot,
        &snapshot_bytes(&snapshot),
        &canonical(&no_recovery_history),
        DER,
        &expected(&no_recovery_history),
        accept_expected_domain,
    )
    .is_ok());

    let mut ambiguous_zero = no_recovery_history.clone();
    ambiguous_zero
        .authoritative_state
        .as_mut()
        .unwrap()
        .recovery_sha256 = Some("9".repeat(64));
    assert!(verify_bootstrap_with(
        &snapshot,
        &snapshot_bytes(&snapshot),
        &canonical(&ambiguous_zero),
        DER,
        &expected(&ambiguous_zero),
        accept_expected_domain,
    )
    .is_err());
}

#[test]
fn recovery_floors_and_release_high_water_are_closed_and_baseline_bounded() {
    let snapshot = snapshot();
    let mut value = initial(&snapshot);
    value.bootstrap_seq = 2;
    value.previous_authorization_sha256 = Some("6".repeat(64));
    value.previous_device_root = Some(device('7'));
    value.authoritative_state = Some(state(&snapshot));
    value.reason = "state_loss_recovery".into();

    for case in [
        "zero-floor",
        "below-baseline",
        "release-gap",
        "release-order",
    ] {
        let mut hostile = value.clone();
        let state = hostile.authoritative_state.as_mut().unwrap();
        match case {
            "zero-floor" => state.trusted_time_seq = 0,
            "below-baseline" => {
                state.baseline.minimum_bundle_seq = 10;
                state.bundle_seq = 9;
            }
            "release-gap" => state.release_authorizations[0].bundle_seq = 8,
            "release-order" => {
                state.release_authorizations = vec![
                    ReleaseAuthorizationHighWater {
                        authorization_sha256: "3".repeat(64),
                        bundle_seq: 9,
                        ring: "stable".into(),
                    },
                    ReleaseAuthorizationHighWater {
                        authorization_sha256: "2".repeat(64),
                        bundle_seq: 9,
                        ring: "beta".into(),
                    },
                ]
            }
            _ => unreachable!(),
        }
        assert!(
            verify_bootstrap_with(
                &snapshot,
                &snapshot_bytes(&snapshot),
                &canonical(&hostile),
                DER,
                &expected(&hostile),
                accept_expected_domain,
            )
            .is_err(),
            "{case}"
        );
    }
}

#[test]
fn bootstrap_refuses_wrong_role_schema_key_signature_and_freshness() {
    let snapshot = snapshot();
    let baseline = initial(&snapshot);
    for case in [
        "role",
        "schema",
        "key",
        "long-window",
        "signed-expiry",
        "clock",
        "reset",
        "unsafe",
    ] {
        let mut hostile = baseline.clone();
        let mut expectation = expected(&baseline);
        match case {
            "role" => hostile.signing_role = "trusted-time".into(),
            "schema" => hostile.schema = "trusted-time-assertion".into(),
            "key" => hostile.key_id = "trusted-time-v1".into(),
            "long-window" => hostile.valid_until = "2026-07-21T12:10:01Z".into(),
            "signed-expiry" => hostile.valid_until = "2026-07-21T12:00:01Z".into(),
            "clock" => expectation.current_tpm.tpm_clock += 1,
            "reset" => expectation.current_tpm.tpm_reset_count += 1,
            "unsafe" => expectation.current_tpm.tpm_safe = false,
            _ => unreachable!(),
        }
        assert!(
            verify_bootstrap_with(
                &snapshot,
                &snapshot_bytes(&snapshot),
                &canonical(&hostile),
                DER,
                &expectation,
                accept_expected_domain,
            )
            .is_err(),
            "{case}"
        );
    }
    assert!(verify_bootstrap_with(
        &snapshot,
        &snapshot_bytes(&snapshot),
        &canonical(&baseline),
        &[0x30, 0x00],
        &expected(&baseline),
        accept_expected_domain,
    )
    .is_err());
    assert!(verify_bootstrap_with(
        &snapshot,
        &snapshot_bytes(&snapshot),
        &canonical(&baseline),
        DER,
        &expected(&baseline),
        |_key, _domain, _payload, _signature| Err("wrong cryptographic key".into()),
    )
    .is_err());
}

fn root_recovery(
    snapshot: &Snapshot,
    current: &AuthoritativeState,
    resulting: &AuthoritativeState,
) -> StateRecoveryAuthorization {
    StateRecoveryAuthorization {
        acknowledgement_authority: RecoveryAcknowledgementAuthority {
            artifact_types: vec!["ota-licensing-recovery-ack-v1".into()],
            key_id: "licensing-bootstrap-v1".into(),
            public_key: snapshot.keys[0].public_key.clone(),
            schema: "ota-recovery-ack-authority-v1".into(),
            signing_role: "licensing-bootstrap".into(),
        },
        baseline: current.baseline.clone(),
        current_state: current.clone(),
        device_root: device('3'),
        device_serial: "device-001".into(),
        incident_id: "incident-0001".into(),
        issuance_id: "root-recovery-0001".into(),
        issued_at: "2026-07-21T12:00:00Z".into(),
        key_id: format!("ota-root-v{}", current.root_version),
        previous_recovery_sha256: current.recovery_sha256.clone(),
        reason: "tpm-state-loss".into(),
        recovery_nonce: "5".repeat(64),
        recovery_seq: resulting.recovery_seq,
        release_authorization_sha256: Some("2".repeat(64)),
        resulting_state: RecoveryTargetState::from_authoritative(resulting),
        root_spki_sha256: current.root_spki_sha256.clone(),
        root_version: current.root_version,
        schema: "ota-state-recovery-v1".into(),
        signature_algorithm: "ecdsa-p256-sha256".into(),
        signature_encoding: "asn1-der".into(),
        signing_role: "ota-root".into(),
        tpm_clock: 1_000,
        tpm_reset_count: 2,
        tpm_restart_count: 3,
        tpm_safe: true,
        valid_until: "2026-07-21T12:10:00Z".into(),
    }
}

fn acknowledgement(
    resulting_state: AuthoritativeState,
    root_recovery_sha256: String,
) -> LicensingRecoveryAck {
    LicensingRecoveryAck {
        device_root: device('3'),
        device_serial: "device-001".into(),
        issuance_id: "recovery-ack-0001".into(),
        issued_at: "2026-07-21T12:00:00Z".into(),
        key_id: "licensing-bootstrap-v1".into(),
        licence_record_id: "4".repeat(64),
        recovery_nonce: "5".repeat(64),
        resulting_state,
        root_recovery_sha256,
        schema: "ota-licensing-recovery-ack-v1".into(),
        signature_algorithm: "ecdsa-p256-sha256".into(),
        signature_encoding: "asn1-der".into(),
        signing_role: "licensing-bootstrap".into(),
        tpm_clock: 1_000,
        tpm_reset_count: 2,
        tpm_restart_count: 3,
        tpm_safe: true,
        valid_until: "2026-07-21T12:10:00Z".into(),
    }
}

fn expected_ack<'a>(value: &'a LicensingRecoveryAck) -> ExpectedRecoveryAck<'a> {
    ExpectedRecoveryAck {
        current_tpm: CurrentTpmState {
            tpm_clock: value.tpm_clock + 599_000,
            tpm_reset_count: value.tpm_reset_count,
            tpm_restart_count: value.tpm_restart_count,
            tpm_safe: true,
        },
        device_root: &value.device_root,
        device_serial: &value.device_serial,
        licence_record_id: &value.licence_record_id,
        pending: PendingChallenge {
            nonce: &value.recovery_nonce,
            tpm_clock: value.tpm_clock,
            tpm_reset_count: value.tpm_reset_count,
            tpm_restart_count: value.tpm_restart_count,
        },
        resulting_state: &value.resulting_state,
    }
}

#[test]
fn recovery_ack_uses_only_exact_root_authorized_signer_and_state() {
    let snapshot = snapshot();
    let current = state(&snapshot);
    let mut resulting = current.clone();
    resulting.recovery_seq += 1;
    resulting.recovery_sha256 = Some("0".repeat(64));
    let root = root_recovery(&snapshot, &current, &resulting);
    let root_bytes = canonical(&root);
    let root_hash = canonical_hash(&root_bytes).unwrap();
    resulting.recovery_sha256 = Some(root_hash.clone());
    let expected_root = ExpectedRootRecovery {
        baseline: &current.baseline,
        current_state: &current,
        current_tpm: CurrentTpmState {
            tpm_clock: root.tpm_clock + 599_000,
            tpm_reset_count: root.tpm_reset_count,
            tpm_restart_count: root.tpm_restart_count,
            tpm_safe: true,
        },
        device_root: &root.device_root,
        device_serial: &root.device_serial,
        pending: PendingChallenge {
            nonce: &root.recovery_nonce,
            tpm_clock: root.tpm_clock,
            tpm_reset_count: root.tpm_reset_count,
            tpm_restart_count: root.tpm_restart_count,
        },
        release_authorization_sha256: root.release_authorization_sha256.as_deref(),
        resulting_state: &resulting,
        root_public_key: snapshot.root_public_key(),
    };
    let authority = verify_root_recovery_authority_with(
        &root_bytes,
        DER,
        &expected_root,
        |_key, domain, _payload, _signature| {
            assert_eq!(domain, STATE_RECOVERY_DOMAIN);
            assert_eq!(domain.last(), Some(&0));
            Ok(())
        },
    )
    .unwrap();

    let mut widened = root.clone();
    widened
        .acknowledgement_authority
        .artifact_types
        .push("ota-licensing-bootstrap-v1".into());
    assert!(verify_root_recovery_authority_with(
        &canonical(&widened),
        DER,
        &expected_root,
        |_key, _domain, _payload, _signature| Ok(()),
    )
    .is_err());
    let mut expired_root = root.clone();
    expired_root.valid_until = "2026-07-21T12:00:01Z".into();
    assert!(verify_root_recovery_authority_with(
        &canonical(&expired_root),
        DER,
        &expected_root,
        |_key, _domain, _payload, _signature| Ok(()),
    )
    .is_err());
    assert!(verify_root_recovery_authority_with(
        &root_bytes,
        DER,
        &expected_root,
        |_key, _domain, _payload, _signature| Err("wrong root signature".into()),
    )
    .is_err());

    let value = acknowledgement(resulting.clone(), root_hash);
    let bytes = canonical(&value);
    let expected = expected_ack(&value);
    let verified = verify_recovery_ack_with(
        &bytes,
        DER,
        &authority,
        &expected,
        |_key, domain, _payload, _signature| {
            assert_eq!(domain, RECOVERY_ACK_DOMAIN);
            assert_eq!(domain.last(), Some(&0));
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(verified.root_recovery_sha256, value.root_recovery_sha256);

    let correct_key = public_key_pem(&snapshot.keys[0].public_key).unwrap();
    assert!(verify_recovery_ack_with(
        &bytes,
        DER,
        &authority,
        &expected,
        |key, _domain, _payload, _signature| {
            assert_eq!(key, correct_key);
            Err("signature was made by a different key".into())
        },
    )
    .is_err());

    for case in [
        "key", "nonce", "recovery", "state", "role", "schema", "expired",
    ] {
        let mut hostile = value.clone();
        match case {
            "key" => hostile.key_id = "other-bootstrap-key".into(),
            "nonce" => hostile.recovery_nonce = "7".repeat(64),
            "recovery" => hostile.root_recovery_sha256 = "7".repeat(64),
            "state" => hostile.resulting_state.bundle_seq += 1,
            "role" => hostile.signing_role = "trusted-time".into(),
            "schema" => hostile.schema = "ota-licensing-bootstrap-v1".into(),
            "expired" => hostile.valid_until = "2026-07-21T12:00:01Z".into(),
            _ => unreachable!(),
        }
        assert!(
            verify_recovery_ack_with(
                &canonical(&hostile),
                DER,
                &authority,
                &expected,
                |_key, _domain, _payload, _signature| Ok(()),
            )
            .is_err(),
            "{case}"
        );
    }

    let wrong_root = ExpectedRootRecovery {
        root_public_key: &snapshot.keys[1].public_key,
        ..expected_root
    };
    assert!(verify_root_recovery_authority_with(
        &root_bytes,
        DER,
        &wrong_root,
        |_key, _domain, _payload, _signature| Ok(()),
    )
    .is_err());
}

#[test]
fn root_recovery_refuses_same_sequence_release_split_view() {
    let snapshot = snapshot();
    let current = state(&snapshot);
    let mut resulting = current.clone();
    resulting.recovery_seq += 1;
    resulting.recovery_sha256 = Some("0".repeat(64));
    resulting.release_authorizations[0].authorization_sha256 = "8".repeat(64);
    let root = root_recovery(&snapshot, &current, &resulting);
    let root_bytes = canonical(&root);
    resulting.recovery_sha256 = Some(canonical_hash(&root_bytes).unwrap());
    let expected_root = ExpectedRootRecovery {
        baseline: &current.baseline,
        current_state: &current,
        current_tpm: CurrentTpmState {
            tpm_clock: root.tpm_clock,
            tpm_reset_count: root.tpm_reset_count,
            tpm_restart_count: root.tpm_restart_count,
            tpm_safe: true,
        },
        device_root: &root.device_root,
        device_serial: &root.device_serial,
        pending: PendingChallenge {
            nonce: &root.recovery_nonce,
            tpm_clock: root.tpm_clock,
            tpm_reset_count: root.tpm_reset_count,
            tpm_restart_count: root.tpm_restart_count,
        },
        release_authorization_sha256: root.release_authorization_sha256.as_deref(),
        resulting_state: &resulting,
        root_public_key: snapshot.root_public_key(),
    };
    assert!(verify_root_recovery_authority_with(
        &root_bytes,
        DER,
        &expected_root,
        |_key, _domain, _payload, _signature| Ok(()),
    )
    .is_err());
}

#[test]
fn contracts_refuse_unknown_fields_noncanonical_json_and_cross_schema_replay() {
    let snapshot = snapshot();
    let value = initial(&snapshot);
    let expected = expected(&value);
    let mut json = serde_json::to_value(&value).unwrap();
    json["email"] = "forbidden@example.invalid".into();
    assert!(verify_bootstrap_with(
        &snapshot,
        &snapshot_bytes(&snapshot),
        &canonical(&json),
        DER,
        &expected,
        accept_expected_domain,
    )
    .is_err());

    let mut noncanonical = serde_json::to_vec_pretty(&value).unwrap();
    noncanonical.push(b'\n');
    assert!(verify_bootstrap_with(
        &snapshot,
        &snapshot_bytes(&snapshot),
        &noncanonical,
        DER,
        &expected,
        accept_expected_domain,
    )
    .is_err());

    let ack = acknowledgement(state(&snapshot), "6".repeat(64));
    assert!(verify_bootstrap_with(
        &snapshot,
        &snapshot_bytes(&snapshot),
        &canonical(&ack),
        DER,
        &expected,
        accept_expected_domain,
    )
    .is_err());
}

#[test]
fn exported_machine_contract_matches_every_closed_licensing_artifact() {
    let snapshot = snapshot();
    let bootstrap = initial(&snapshot);
    let current = state(&snapshot);
    let mut resulting = current.clone();
    resulting.recovery_seq += 1;
    resulting.recovery_sha256 = Some("6".repeat(64));
    let recovery = root_recovery(&snapshot, &current, &resulting);
    let acknowledgement = acknowledgement(resulting, "6".repeat(64));
    assert_eq!(
        serialized_fields(&bootstrap),
        contract_fields("ota-licensing-bootstrap-v1")
    );
    assert_eq!(
        serialized_fields(&recovery),
        contract_fields("ota-state-recovery-v1")
    );
    assert_eq!(
        serialized_fields(&acknowledgement),
        contract_fields("ota-licensing-recovery-ack-v1")
    );
    let contract: serde_json::Value = serde_json::from_slice(CONTRACT).unwrap();
    for (schema, domain) in [
        ("ota-licensing-bootstrap-v1", BOOTSTRAP_DOMAIN),
        ("ota-state-recovery-v1", STATE_RECOVERY_DOMAIN),
        ("ota-licensing-recovery-ack-v1", RECOVERY_ACK_DOMAIN),
    ] {
        let artifact = contract["artifacts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|artifact| artifact["schema"] == schema)
            .unwrap();
        assert_eq!(artifact["domain_hex"], hex(domain));
        assert_eq!(artifact["terminal_nul"], true);
    }
    for (name, fields) in [
        (
            "acknowledgement_authority",
            serialized_fields(&recovery.acknowledgement_authority),
        ),
        ("authoritative_state", serialized_fields(&current)),
        ("baseline_identity", serialized_fields(&current.baseline)),
        (
            "device_root_identity",
            serialized_fields(&bootstrap.device_root),
        ),
        (
            "public_key",
            serialized_fields(&recovery.acknowledgement_authority.public_key),
        ),
        (
            "recovery_target_state",
            serialized_fields(&recovery.resulting_state),
        ),
    ] {
        assert_eq!(fields, structure_fields(name), "{name}");
    }
}
