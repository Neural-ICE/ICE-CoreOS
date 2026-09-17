//! `bootstrap-from-preseal` — seed the v1 applied baseline (`applied.json`,
//! its format sidecar and `applied.bom.json`) from the preseal receipt a
//! medium install leaves behind, on the first boot, before the TPM
//! ceremony's one-time mutation.
//!
//! WHY THIS VERB EXISTS. Measured on .67, 2026-09-17, after the C37 medium
//! reinstall (0.61.0, image 8e5edd9; ICE-CoreOS issue 206): the first-boot
//! ceremony authenticated the preseal baseline (`verify-preseal-baseline`,
//! receipt `preseal/receipt.json`, v2 evidence with a pristine anchor) and
//! stopped there. Nothing wrote `applied.json`. The OTA controller then
//! refused every train — `FAIL unseeded — no applied state … and enforce=1`;
//! `commit` refused to seed ("baseline seeding belongs to the verified
//! bootstrap path"); `bootstrap` accepted but demanded a cosign `--bom-sig`
//! that the sealed medium BOM never has, because in the v2 model the BOM is
//! covered by `ota-release-authorization.json/.sig`. It took a manual
//! root-key signature of that BOM at 00:45 to seed bundle_seq 22, after which
//! the gate passed (anti_rollback 26 > 22). An appliance out of the installer
//! could not update without a human holding the root key.
//!
//! WHAT IT TRUSTS. Exactly what `verify-retained-preseal-baseline` trusts,
//! through the same function with the same inputs and the same refusals: the
//! delegation snapshot signed by the OTA root, the release authorization
//! signed by the delegated key, the installer authorization, the BOM hash
//! bound into the release authorization, the immutable host identity and
//! compat range, and the receipt reproduced byte for byte from those signed
//! inputs. The train, bundle_seq, BOM hash, ring, OS reference and seed
//! reference it seeds are the receipt's — none is read from an unsigned file.
//!
//! WHAT IT WRITES, AND HOW `bootstrap` WRITES IT. The applied state
//! `bootstrap` would have written (`AppliedState`, media-independent format,
//! `active_ring` = the sealed device channel) through the same
//! create-if-absent store, plus `applied.bom.json` — the verified BOM bytes,
//! mode 0600 — which the transaction engine requires beside the state
//! ("applied BOM must be a regular mode-0600 file", measured the same night)
//! and which `bootstrap` never wrote because no engine consumed it then.
//! Nothing here touches the TPM: `bootstrap` defines no NV index and neither
//! does this. The owner anchor is only READ and must be pristine, so the
//! seeding runs before the ceremony's one-time mutation and a failure here
//! leaves the TPM exactly as the installer left it.
//!
//! IDEMPOTENT. An applied state equal to the receipt (seq, BOM hash, format,
//! ring) beside an equal `applied.bom.json` is a no-op success; any other
//! applied state is refused and never overwritten.

use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::config::Config;
use crate::preseal::{verify_retained, RetainedPresealPaths, VerifiedPreseal};
use crate::state::{
    effective_uid, sync_directory, AppliedState, AppliedStateStore, FileStateStore, StateRead,
    BOM_FORMAT_MEDIA_INDEPENDENT_V1,
};
use crate::{parse_flags, runner, InternalError, DEFAULT_CONFIG, EXIT_PASS, EXIT_REFUSE};

const COMMAND: &str = "bootstrap-from-preseal";
const APPLIED_BOM_NAME: &str = "applied.bom.json";
/// The BOM the engine copies beside the state is the release BOM (≈10 KiB
/// for train 0.61.0); the bound only has to stay inside the reader's
/// per-file snapshot bound.
const MAX_APPLIED_BOM: u64 = 1024 * 1024;

pub(crate) fn run(args: &[String]) -> Result<u8, InternalError> {
    let flags = parse_flags(
        args,
        &[
            "set",
            "snapshot",
            "snapshot-sig",
            "release",
            "release-sig",
            "bom",
            "installer-authorization",
            "installer-authorization-sig",
            "receipt",
            "expected-set-sha256",
            "expected-receipt-sha256",
            "scratch-dir",
            "config",
        ],
    )?;
    let required = |name: &str| -> Result<&str, InternalError> {
        flags
            .get(name)
            .map(String::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| InternalError(format!("{COMMAND}: --{name} is required")))
    };
    let config_path = PathBuf::from(flags.get("config").map_or(DEFAULT_CONFIG, String::as_str));
    let cfg = Config::load(&config_path)?;
    let state_dir = cfg
        .state_dir
        .clone()
        .ok_or_else(|| InternalError(format!("{COMMAND} requires state_dir")))?;
    let bom_path = PathBuf::from(required("bom")?);
    let refuse = |why: String| -> Result<u8, InternalError> {
        eprintln!("ni-ota-verify: {COMMAND} REFUSED: {why}");
        Ok(EXIT_REFUSE)
    };

    // 1. The signed baseline, re-derived from every signed input exactly as
    //    the retained verification does at every later boot.
    let paths = RetainedPresealPaths {
        set: Path::new(required("set")?),
        snapshot: Path::new(required("snapshot")?),
        snapshot_signature: Path::new(required("snapshot-sig")?),
        release: Path::new(required("release")?),
        release_signature: Path::new(required("release-sig")?),
        bom: &bom_path,
        installer_authorization: Path::new(required("installer-authorization")?),
        installer_authorization_signature: Path::new(required("installer-authorization-sig")?),
        receipt: Path::new(required("receipt")?),
        expected_set_sha256: required("expected-set-sha256")?,
        expected_receipt_sha256: required("expected-receipt-sha256")?,
        scratch_dir: Path::new(required("scratch-dir")?),
        config: &config_path,
    };
    let verified = match verify_retained(&paths)? {
        Ok(value) => value,
        Err(reason) => return refuse(format!("preseal baseline: {reason}")),
    };

    // 2. The ring the applied state names is the sealed device channel, and
    //    the receipt must agree: the engine commits only a BOM whose applied
    //    `active_ring` equals the transaction channel (issue 201/202 class).
    match cfg.device_channel.as_deref() {
        Some(channel) if channel == verified.ring => {}
        Some(channel) => {
            return refuse(format!(
                "sealed device channel '{channel}' differs from the receipt ring '{}'",
                verified.ring
            ))
        }
        None => {
            return refuse(
                "ota.conf names no device_channel; the applied ring cannot be seeded".into(),
            )
        }
    }

    // 3. The anchor exactly as the installer left it: owner-sealed profile,
    //    defined, never written; and no generation state beside it.
    if let Err(reason) = crate::state_v1::owner_anchor_pristine()? {
        return refuse(format!("owner OTA anchor: {reason}"));
    }
    if state_dir.join("state-v1").exists() {
        return refuse("generation state exists beside a pristine owner anchor".into());
    }

    // 4. The running system IS the receipt's target: booted origin, imported
    //    manifest digest and payload marker, read by the same inspector the
    //    authenticated status uses, re-read after the comparison.
    if let Err(reason) = crate::state_v1::verify_running_is_preseal_target(&verified) {
        return refuse(format!("running system: {reason}"));
    }

    let expected = AppliedState {
        bundle_seq: verified.bundle_seq,
        bom_sha256: verified.bom_sha256.clone(),
        bom_format: Some(BOM_FORMAT_MEDIA_INDEPENDENT_V1.to_string()),
        active_ring: Some(verified.ring.clone()),
    };
    let store = FileStateStore {
        path: state_dir.join("applied.json"),
    };
    let _state_lock = match store.lock_bootstrap() {
        Ok(lock) => lock,
        Err(why) => return refuse(why),
    };
    if let Err(why) = store.validate_bootstrap_state() {
        return refuse(why);
    }
    // The BOM bytes to persist are frozen and re-hashed against the receipt:
    // the verification above hashed its own protected snapshot, this one is
    // what gets written, and they must be the same document.
    let bom_snapshot = store.snapshot_bootstrap(&bom_path)?;
    let bom_bytes = bom_snapshot.read()?;
    if runner::sha256_bytes(&bom_bytes)? != verified.bom_sha256 {
        return refuse("BOM bytes differ from the authenticated preseal receipt".into());
    }

    let existing = match store.read() {
        Ok(StateRead::Applied(applied)) => Some(applied),
        Ok(StateRead::Unseeded) => None,
        Err(why) => {
            return refuse(format!(
                "applied state unusable ({why}) — refusing to overwrite it"
            ))
        }
    };
    if let Some(applied) = &existing {
        if !applied.is_media_independent() {
            return refuse(format!(
                "applied baseline at {} was recorded by a media-era verifier (no media-independent format marker) — implicit migration is unsupported; reinstall from verified final media (ADR-0012)",
                store.describe()
            ));
        }
        if *applied != expected {
            return refuse(format!(
                "applied state already exists with a different baseline ({})",
                store.describe()
            ));
        }
    }

    // 5. The BOM copy first, the state second: the engine reads the state as
    //    "seeded" and then requires the BOM beside it, so a crash between the
    //    two leaves an unseeded state with a BOM copy that the retry compares
    //    and keeps — never a seeded state with no BOM.
    let applied_bom = state_dir.join(APPLIED_BOM_NAME);
    if let Err(why) = publish_applied_bom(&store, &applied_bom, &bom_bytes)? {
        return refuse(why);
    }
    let created = match existing {
        Some(_) => false,
        None => store.write_if_absent(&expected)?,
    };
    match store.validate_bootstrap_state() {
        Ok(true) => {}
        Ok(false) => return refuse("baseline remained absent after atomic bootstrap".into()),
        Err(why) => return refuse(format!("baseline metadata readback failed ({why})")),
    }
    let readback = match store.read() {
        Ok(StateRead::Applied(applied)) => applied,
        Ok(StateRead::Unseeded) => return refuse("baseline disappeared after readback".into()),
        Err(why) => return refuse(format!("baseline readback failed ({why})")),
    };
    if readback != expected {
        return refuse(format!(
            "baseline readback differs from the preseal receipt (state at {})",
            store.describe()
        ));
    }
    if let Err(why) = compare_applied_bom(&applied_bom, &bom_bytes)? {
        return refuse(format!("applied BOM readback: {why}"));
    }
    emit_receipt(&verified, &expected, !created);
    Ok(EXIT_PASS)
}

/// Publish the verified BOM bytes beside the state, create-if-absent like
/// the state itself: a fully written and fsynced 0600 temp inode is linked
/// into place; an existing file is accepted only when it is that exact
/// document in that exact mode.
fn publish_applied_bom(
    store: &FileStateStore,
    target: &Path,
    bytes: &[u8],
) -> Result<Result<bool, String>, InternalError> {
    match std::fs::symlink_metadata(target) {
        Ok(_) => return compare_applied_bom(target, bytes).map(|value| value.map(|()| false)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Ok(Err(format!(
                "cannot inspect applied BOM {}: {error}",
                target.display()
            )))
        }
    }
    let parent = target
        .parent()
        .ok_or_else(|| InternalError("applied BOM has no parent".into()))?;
    let staged = store.secure_temp_bytes("applied-bom", bytes)?;
    let created = match std::fs::hard_link(staged.path(), target) {
        Ok(()) => true,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(error) => {
            return Err(InternalError(format!(
                "cannot atomically publish applied BOM {}: {error}",
                target.display()
            )))
        }
    };
    drop(staged);
    if created {
        sync_directory(parent)?;
    }
    compare_applied_bom(target, bytes).map(|value| value.map(|()| created))
}

fn compare_applied_bom(
    target: &Path,
    expected: &[u8],
) -> Result<Result<(), String>, InternalError> {
    let metadata = match std::fs::symlink_metadata(target) {
        Ok(metadata) => metadata,
        Err(error) => {
            return Ok(Err(format!(
                "cannot inspect applied BOM {}: {error}",
                target.display()
            )))
        }
    };
    if !metadata.file_type().is_file()
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
        || (effective_uid() == 0 && metadata.uid() != 0)
    {
        return Ok(Err(format!(
            "applied BOM {} is not a root-owned regular mode-0600 file",
            target.display()
        )));
    }
    let file = match std::fs::File::open(target) {
        Ok(file) => file,
        Err(error) => {
            return Ok(Err(format!(
                "cannot read applied BOM {}: {error}",
                target.display()
            )))
        }
    };
    let mut actual = Vec::new();
    file.take(MAX_APPLIED_BOM + 1)
        .read_to_end(&mut actual)
        .map_err(|error| InternalError(format!("cannot read applied BOM: {error}")))?;
    if actual != expected {
        return Ok(Err(format!(
            "existing applied BOM {} differs from the authenticated preseal BOM",
            target.display()
        )));
    }
    Ok(Ok(()))
}

fn emit_receipt(verified: &VerifiedPreseal, state: &AppliedState, idempotent: bool) {
    let receipt = serde_json::json!({
        "bootstrapped": true,
        "source": "preseal-receipt",
        "idempotent": idempotent,
        "train": verified.train,
        "bundle_seq": state.bundle_seq,
        "ring": verified.ring,
        "os_ref": verified.target_os_ref,
        "seed_ref": verified.seed_ref,
        "bom_sha256": state.bom_sha256,
    });
    println!("{receipt}");
    eprintln!(
        "ni-ota-verify: preseal baseline {} (train {}, bundle_seq {})",
        if idempotent {
            "already applied exactly"
        } else {
            "seeded as the applied state"
        },
        verified.train,
        state.bundle_seq
    );
}
