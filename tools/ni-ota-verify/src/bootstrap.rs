//! `bootstrap` — initialize the anti-rollback baseline from a signed BOM that
//! is physically delivered with a LAB USB image.
//!
//! This is deliberately BOM-only: a fresh device has no trusted channel
//! pointer yet, and bootstrapping one here would turn installation media into a
//! release-channel authority. The command always fails closed, independently
//! of `enforce`, binds the signed train to the booted OS and installed seed,
//! and only creates a genuinely absent state. An exact retry is accepted after
//! readback so interruption after the atomic create is safe.

use std::path::{Path, PathBuf};

use crate::config::{immutable_hardware_target, parse_compat_flag, Config};
use crate::state::{AppliedState, AppliedStateStore, FileStateStore, StateRead};
use crate::verify::{applied_state_path, BomCore};
use crate::{parse_flags, runner, InternalError, DEFAULT_CONFIG, EXIT_PASS, EXIT_REFUSE};

pub(crate) fn run(args: &[String]) -> Result<u8, InternalError> {
    let flags = parse_flags(
        args,
        &[
            "bom",
            "bom-sig",
            "expected-train",
            "current-os-ref",
            "current-seed-ref",
            "config",
            "device-compat",
            "applied-state",
        ],
    )?;
    let path_of = |key: &str| -> Result<PathBuf, InternalError> {
        flags
            .get(key)
            .map(PathBuf::from)
            .ok_or_else(|| InternalError(format!("bootstrap: --{key} is required")))
    };
    let bom_path = path_of("bom")?;
    let bom_sig_path = path_of("bom-sig")?;
    let value_of = |key: &str| -> Result<&str, InternalError> {
        flags
            .get(key)
            .map(String::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| InternalError(format!("bootstrap: --{key} is required")))
    };
    let expected_train = value_of("expected-train")?;
    let current_os_ref = value_of("current-os-ref")?;
    let current_seed_ref = value_of("current-seed-ref")?;
    let config_path = flags.get("config").map_or(DEFAULT_CONFIG, String::as_str);
    let cfg = Config::load(Path::new(config_path))?;
    let store = FileStateStore {
        path: applied_state_path(&flags, &cfg)?,
    };
    let hardware_target = immutable_hardware_target()?;
    let device_compat = match flags.get("device-compat") {
        Some(raw) => Some(parse_compat_flag(raw)?),
        None => cfg.device_compat,
    };

    let refuse = |why: String| -> Result<u8, InternalError> {
        eprintln!("ni-ota-verify: bootstrap REFUSED: {why}");
        Ok(EXIT_REFUSE)
    };

    let _state_lock = match store.lock_bootstrap() {
        Ok(lock) => lock,
        Err(why) => return refuse(why),
    };
    if let Err(why) = store.validate_bootstrap_state() {
        return refuse(why);
    }
    let bom_snapshot = store.snapshot(&bom_path)?;

    // Resolve and run the pinned verifier before parsing or trusting any BOM
    // field. Bootstrap has no shadow semantics: a missing trust anchor or bad
    // signature is always a refusal and never creates state.
    let cosign = runner::cosign_path()?;
    let Some(pubkey) = cfg.root_pubkey.as_deref() else {
        return refuse("no root_pubkey configured in ota.conf".to_string());
    };
    if !non_empty_file(pubkey) {
        return refuse(format!(
            "OTA root pubkey missing or empty: {}",
            pubkey.display()
        ));
    }
    if let Err(why) = runner::verify_blob(&cosign, pubkey, &bom_sig_path, bom_snapshot.path())? {
        return refuse(format!(
            "BOM signature rejected for {}: {why}",
            bom_path.display()
        ));
    }

    let bytes = bom_snapshot.read()?;
    let bom: BomCore = match serde_json::from_slice(&bytes) {
        Ok(bom) => bom,
        Err(e) => return refuse(format!("malformed BOM {}: {e}", bom_path.display())),
    };
    if bom.bundle_seq == 0 {
        return refuse("BOM bundle_seq must be greater than zero".to_string());
    }
    if !valid_train(expected_train) {
        return refuse(format!("expected train is malformed: '{expected_train}'"));
    }
    if bom.train != expected_train {
        return refuse(format!(
            "BOM train '{}' does not match expected train '{expected_train}'",
            bom.train
        ));
    }
    if bom.hardware_target != hardware_target {
        return refuse(format!(
            "BOM hardware_target '{}' does not match immutable host target '{hardware_target}'",
            bom.hardware_target
        ));
    }
    let Some((device_min, device_max)) = device_compat else {
        return refuse(
            "device compat range is required (--device-compat or ota.conf pair)".to_string(),
        );
    };
    let (Some(bom_min), Some(bom_max)) = (bom.compat_min, bom.compat_version) else {
        return refuse("BOM lacks compat_min/compat_version".to_string());
    };
    if bom_min > bom_max {
        return refuse(format!("BOM compat range inverted ({bom_min} > {bom_max})"));
    }
    if bom_min > device_max || device_min > bom_max {
        return refuse(format!(
            "BOM compat [{bom_min},{bom_max}] does not overlap device [{device_min},{device_max}]"
        ));
    }

    if !valid_digest_ref(current_os_ref) {
        return refuse(format!(
            "current OS ref is not digest-pinned: '{current_os_ref}'"
        ));
    }
    let Some(os_base) = bom
        .appliance
        .as_ref()
        .and_then(|appliance| appliance.os_base.as_ref())
    else {
        return refuse("BOM lacks appliance.os_base image/digest".to_string());
    };
    let bom_os_ref = format!("{}@{}", os_base.image, os_base.digest);
    if !valid_digest_ref(&bom_os_ref) {
        return refuse(format!(
            "BOM appliance OS ref is not digest-pinned: '{bom_os_ref}'"
        ));
    }
    if bom_os_ref != current_os_ref {
        return refuse(format!(
            "BOM appliance OS ref '{bom_os_ref}' does not match booted OS ref '{current_os_ref}'"
        ));
    }

    if !valid_seed_ref(current_seed_ref) {
        return refuse(format!(
            "current seed ref is not a full lowercase commit id: '{current_seed_ref}'"
        ));
    }
    let Some(bom_seed_ref) = bom
        .sources
        .as_ref()
        .and_then(|sources| sources.seed.as_ref())
        .map(|seed| seed.reference.as_str())
    else {
        return refuse("BOM lacks sources.seed.ref".to_string());
    };
    if !valid_seed_ref(bom_seed_ref) {
        return refuse(format!(
            "BOM sources.seed.ref is not a full lowercase commit id: '{bom_seed_ref}'"
        ));
    }
    if bom_seed_ref != current_seed_ref {
        return refuse(format!(
            "BOM seed ref '{bom_seed_ref}' does not match installed payload '{current_seed_ref}'"
        ));
    }

    let bom_sha256 = runner::sha256_file(bom_snapshot.path())?;
    if bom_snapshot.read()? != bytes {
        return refuse("protected BOM snapshot changed during verification".to_string());
    }
    let expected = AppliedState {
        bundle_seq: bom.bundle_seq,
        bom_sha256,
    };
    match store.read() {
        Ok(StateRead::Applied(applied)) => {
            return finish_existing(
                &store,
                &expected,
                expected_train,
                &hardware_target,
                current_os_ref,
                current_seed_ref,
                applied,
            )
        }
        Err(why) => {
            return refuse(format!(
                "applied state unusable ({why}) — refusing to overwrite it"
            ))
        }
        Ok(StateRead::Unseeded) => {}
    }

    // hard-link publication inside `write_if_absent` is the atomic
    // create-if-absent boundary. If another bootstrap wins the race, only an
    // exact match is accepted below.
    let created = store.write_if_absent(&expected)?;
    match store.validate_bootstrap_state() {
        Ok(true) => {}
        Ok(false) => return refuse("baseline remained absent after atomic bootstrap".to_string()),
        Err(why) => return refuse(format!("baseline metadata readback failed ({why})")),
    }
    let readback = match store.read() {
        Ok(StateRead::Applied(applied)) => applied,
        Ok(StateRead::Unseeded) => {
            return refuse("baseline disappeared after readback".to_string())
        }
        Err(why) => return refuse(format!("baseline readback failed ({why})")),
    };
    if readback != expected {
        return refuse(format!(
            "baseline readback differs from signed BOM (state at {})",
            store.describe()
        ));
    }
    emit_receipt(
        &expected,
        expected_train,
        &hardware_target,
        current_os_ref,
        current_seed_ref,
        !created,
    );
    Ok(EXIT_PASS)
}

fn finish_existing(
    store: &FileStateStore,
    expected: &AppliedState,
    train: &str,
    hardware_target: &str,
    os_ref: &str,
    seed_ref: &str,
    applied: AppliedState,
) -> Result<u8, InternalError> {
    if applied != *expected {
        eprintln!(
            "ni-ota-verify: bootstrap REFUSED: applied state already exists with a different baseline ({})",
            store.describe()
        );
        return Ok(EXIT_REFUSE);
    }
    // Read twice: an idempotent success is reported only for stable state, not
    // for a transient or concurrently replaced observation.
    match store.read() {
        Ok(StateRead::Applied(readback)) if readback == *expected => {
            emit_receipt(expected, train, hardware_target, os_ref, seed_ref, true);
            Ok(EXIT_PASS)
        }
        Ok(StateRead::Applied(_)) => {
            eprintln!(
                "ni-ota-verify: bootstrap REFUSED: baseline changed during idempotence readback"
            );
            Ok(EXIT_REFUSE)
        }
        Ok(StateRead::Unseeded) => {
            eprintln!(
                "ni-ota-verify: bootstrap REFUSED: baseline disappeared during idempotence readback"
            );
            Ok(EXIT_REFUSE)
        }
        Err(why) => {
            eprintln!("ni-ota-verify: bootstrap REFUSED: baseline readback failed ({why})");
            Ok(EXIT_REFUSE)
        }
    }
}

fn emit_receipt(
    state: &AppliedState,
    train: &str,
    hardware_target: &str,
    os_ref: &str,
    seed_ref: &str,
    idempotent: bool,
) {
    let receipt = serde_json::json!({
        "bootstrapped": true,
        "idempotent": idempotent,
        "train": train,
        "bundle_seq": state.bundle_seq,
        "hardware_target": hardware_target,
        "os_ref": os_ref,
        "seed_ref": seed_ref,
        "bom_sha256": state.bom_sha256,
    });
    println!("{receipt}");
    eprintln!(
        "ni-ota-verify: signed baseline {} (bundle_seq {})",
        if idempotent {
            "already present exactly"
        } else {
            "bootstrapped"
        },
        state.bundle_seq
    );
}

fn non_empty_file(path: &Path) -> bool {
    std::fs::metadata(path)
        .map(|metadata| metadata.is_file() && metadata.len() > 0)
        .unwrap_or(false)
}

fn valid_train(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
}

fn valid_digest_ref(value: &str) -> bool {
    let Some((image, digest)) = value.rsplit_once("@sha256:") else {
        return false;
    };
    !image.is_empty()
        && !image
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte == b'@')
        && digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_seed_ref(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
