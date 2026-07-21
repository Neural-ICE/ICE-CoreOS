use super::*;
use crate::delegated::contract::{parse_canonical, public_key_pem, validate_snapshot, Snapshot};

const DER: &[u8] = &[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];
const SNAPSHOT: &[u8] =
    include_bytes!("../../tests/fixtures/delegated-v1/delegation-snapshot.json");

fn canonical<T: Serialize>(value: &T) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(value).unwrap();
    bytes.push(b'\n');
    bytes
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
            tpm_clock: value.tpm_clock + 600_000,
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

fn acknowledgement(snapshot: &Snapshot) -> LicensingRecoveryAck {
    LicensingRecoveryAck {
        device_root: device('3'),
        device_serial: "device-001".into(),
        issuance_id: "recovery-ack-0001".into(),
        issued_at: "2026-07-21T12:00:00Z".into(),
        key_id: "licensing-bootstrap-v1".into(),
        licence_record_id: "4".repeat(64),
        recovery_nonce: "5".repeat(64),
        resulting_state: state(snapshot),
        root_recovery_sha256: "6".repeat(64),
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

fn expected_ack<'a>(
    snapshot: &'a Snapshot,
    value: &'a LicensingRecoveryAck,
) -> ExpectedRecoveryAck<'a> {
    ExpectedRecoveryAck {
        authorized_key: &snapshot.keys[0].public_key,
        authorized_key_id: &value.key_id,
        current_tpm: CurrentTpmState {
            tpm_clock: value.tpm_clock + 600_000,
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
        recovery_nonce: &value.recovery_nonce,
        resulting_state: &value.resulting_state,
        root_recovery_sha256: &value.root_recovery_sha256,
    }
}

#[test]
fn recovery_ack_uses_only_exact_root_authorized_signer_and_state() {
    let snapshot = snapshot();
    let value = acknowledgement(&snapshot);
    let bytes = canonical(&value);
    let expected = expected_ack(&snapshot, &value);
    let verified = verify_recovery_ack_with(
        &bytes,
        DER,
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
    let mut wrong_authority = expected_ack(&snapshot, &value);
    wrong_authority.authorized_key = &snapshot.keys[1].public_key;
    assert!(verify_recovery_ack_with(
        &bytes,
        DER,
        &wrong_authority,
        |key, _domain, _payload, _signature| {
            if key == correct_key {
                Ok(())
            } else {
                Err("recovery acknowledgement used a generic snapshot key".into())
            }
        },
    )
    .is_err());

    for case in ["key", "nonce", "recovery", "state", "role", "schema"] {
        let mut hostile = value.clone();
        match case {
            "key" => hostile.key_id = "other-bootstrap-key".into(),
            "nonce" => hostile.recovery_nonce = "7".repeat(64),
            "recovery" => hostile.root_recovery_sha256 = "7".repeat(64),
            "state" => hostile.resulting_state.bundle_seq += 1,
            "role" => hostile.signing_role = "trusted-time".into(),
            "schema" => hostile.schema = "ota-licensing-bootstrap-v1".into(),
            _ => unreachable!(),
        }
        assert!(
            verify_recovery_ack_with(
                &canonical(&hostile),
                DER,
                &expected,
                |_key, _domain, _payload, _signature| Ok(()),
            )
            .is_err(),
            "{case}"
        );
    }
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

    let ack = acknowledgement(&snapshot);
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
