//! Applied-bundle state — the anti-rollback record.
//!
//! P2 backend: a JSON file `state_dir/applied.json` = `{bundle_seq, bom_sha256}`.
//! P3 replaces the backend with the TPM2 NV index (tpm2-tools, plan P3) behind
//! the SAME trait: the verify/commit logic never learns which backend it talks
//! to, so the swap is a new `AppliedStateStore` impl, not a logic change.

use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::InternalError;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub(crate) struct AppliedState {
    /// bundle_seq of the last successfully applied bundle (post health gate).
    pub bundle_seq: u64,
    /// sha256 of the exact BOM file that was applied — the repair carve-out
    /// anchor (equal seq is only acceptable for the byte-identical BOM).
    pub bom_sha256: String,
}

pub(crate) enum StateRead {
    /// No state recorded yet (fresh install, pre-P3-seeding). Shadow warns,
    /// enforce refuses (plan P3 seeding rule).
    Unseeded,
    Applied(AppliedState),
}

pub(crate) trait AppliedStateStore {
    /// Err = unreadable or corrupt state — surfaced as a FAILED anti-rollback
    /// check (fail-closed verdict), not an internal error: in shadow mode a
    /// broken state file must log-and-continue like any other failed check.
    fn read(&self) -> Result<StateRead, String>;
    /// Err = InternalError: a commit that cannot persist is broken tooling.
    fn write(&self, state: &AppliedState) -> Result<(), InternalError>;
    /// Human-readable location for verdict details ("/var/lib/…/applied.json",
    /// later "TPM NV 0x01500001").
    fn describe(&self) -> String;
}

pub(crate) struct FileStateStore {
    pub path: PathBuf,
}

impl FileStateStore {
    /// Bootstrap runs as root on the appliance. Its state parent is a trust
    /// boundary, not scratch space: require an existing real directory and,
    /// for a privileged caller, exact root ownership and mode 0700.
    pub(crate) fn validate_bootstrap_parent(&self) -> Result<(), String> {
        let dir = self
            .path
            .parent()
            .ok_or_else(|| format!("applied-state path has no parent: {}", self.path.display()))?;
        let metadata = std::fs::symlink_metadata(dir)
            .map_err(|e| format!("cannot inspect state dir {}: {e}", dir.display()))?;
        if !metadata.file_type().is_dir() {
            return Err(format!(
                "state parent is not a real directory: {}",
                dir.display()
            ));
        }
        if effective_uid() == 0 {
            let mode = metadata.mode() & 0o7777;
            if metadata.uid() != 0 || mode != 0o700 {
                return Err(format!(
                    "state dir {} must be root-owned mode 0700 (uid={}, mode={mode:04o})",
                    dir.display(),
                    metadata.uid()
                ));
            }
        }
        Ok(())
    }

    /// Validate the published bootstrap inode without following symlinks.
    /// `Ok(false)` is the only representation of a genuinely absent state.
    pub(crate) fn validate_bootstrap_state(&self) -> Result<bool, String> {
        let metadata = match std::fs::symlink_metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(e) => {
                return Err(format!(
                    "cannot inspect applied state {}: {e}",
                    self.path.display()
                ))
            }
        };
        if !metadata.file_type().is_file() {
            return Err(format!(
                "applied state is a symlink or non-regular file: {}",
                self.path.display()
            ));
        }
        let mode = metadata.mode() & 0o7777;
        if mode != 0o600 {
            return Err(format!(
                "applied state {} must be mode 0600 (mode={mode:04o})",
                self.path.display()
            ));
        }
        if effective_uid() == 0 && metadata.uid() != 0 {
            return Err(format!(
                "applied state {} must be root-owned (uid={})",
                self.path.display(),
                metadata.uid()
            ));
        }
        Ok(true)
    }

    /// Atomically publish a new baseline without ever replacing an existing
    /// state path. The fully-written and fsynced temporary inode is linked into
    /// place; `AlreadyExists` means a concurrent or prior bootstrap won and the
    /// caller must compare it before accepting idempotence.
    pub(crate) fn write_if_absent(&self, state: &AppliedState) -> Result<bool, InternalError> {
        let dir = self.path.parent().ok_or_else(|| {
            InternalError(format!(
                "applied-state path has no parent: {}",
                self.path.display()
            ))
        })?;
        self.validate_bootstrap_parent().map_err(InternalError)?;
        let file_name = self.path.file_name().ok_or_else(|| {
            InternalError(format!(
                "applied-state path has no file name: {}",
                self.path.display()
            ))
        })?;
        let json = serde_json::to_string(state)
            .map_err(|e| InternalError(format!("cannot serialize applied state: {e}")))?;

        let (tmp, mut file) = (0_u16..128)
            .find_map(|attempt| {
                let tmp = self.path.with_file_name(format!(
                    ".{}.bootstrap.{}.{}.tmp",
                    file_name.to_string_lossy(),
                    std::process::id(),
                    attempt
                ));
                let mut options = std::fs::OpenOptions::new();
                options.write(true).create_new(true).mode(0o600);
                match options.open(&tmp) {
                    Ok(file) => Some(Ok((tmp, file))),
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => None,
                    Err(e) => Some(Err(InternalError(format!(
                        "cannot create bootstrap temp file {}: {e}",
                        tmp.display()
                    )))),
                }
            })
            .transpose()?
            .ok_or_else(|| {
                InternalError(format!(
                    "cannot allocate bootstrap temp file beside {}",
                    self.path.display()
                ))
            })?;

        let stage = (|| -> Result<(), InternalError> {
            file.set_permissions(std::fs::Permissions::from_mode(0o600))
                .map_err(|e| {
                    InternalError(format!(
                        "cannot secure permissions on {}: {e}",
                        tmp.display()
                    ))
                })?;
            file.write_all(format!("{json}\n").as_bytes())
                .map_err(|e| InternalError(format!("cannot write {}: {e}", tmp.display())))?;
            file.sync_all()
                .map_err(|e| InternalError(format!("cannot sync {}: {e}", tmp.display())))?;
            Ok(())
        })();
        drop(file);
        if let Err(error) = stage {
            let _ = std::fs::remove_file(&tmp);
            return Err(error);
        }

        let created = match std::fs::hard_link(&tmp, &self.path) {
            Ok(()) => true,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => false,
            Err(e) => {
                let _ = std::fs::remove_file(&tmp);
                return Err(InternalError(format!(
                    "cannot atomically create {}: {e}",
                    self.path.display()
                )));
            }
        };
        let _ = std::fs::remove_file(&tmp);
        if created {
            std::fs::File::open(dir)
                .and_then(|directory| directory.sync_all())
                .map_err(|e| {
                    InternalError(format!("cannot sync state dir {}: {e}", dir.display()))
                })?;
        }
        Ok(created)
    }
}

impl AppliedStateStore for FileStateStore {
    fn read(&self) -> Result<StateRead, String> {
        let metadata = match std::fs::symlink_metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(StateRead::Unseeded),
            Err(e) => return Err(format!("cannot inspect {}: {e}", self.path.display())),
        };
        if !metadata.file_type().is_file() {
            return Err(format!(
                "applied state is a symlink or non-regular file: {}",
                self.path.display()
            ));
        }
        let bytes = match std::fs::read(&self.path) {
            Ok(b) => b,
            Err(e) => return Err(format!("cannot read {}: {e}", self.path.display())),
        };
        let state: AppliedState = serde_json::from_slice(&bytes)
            .map_err(|e| format!("corrupt applied state {}: {e}", self.path.display()))?;
        Ok(StateRead::Applied(state))
    }

    fn write(&self, state: &AppliedState) -> Result<(), InternalError> {
        let dir = self.path.parent().ok_or_else(|| {
            InternalError(format!(
                "applied-state path has no parent: {}",
                self.path.display()
            ))
        })?;
        std::fs::create_dir_all(dir).map_err(|e| {
            InternalError(format!("cannot create state dir {}: {e}", dir.display()))
        })?;
        // atomic write: temp sibling + rename, so a crash mid-write can never
        // leave a half-written (= corrupt = fail-closed-refusing) record.
        let file_name = self.path.file_name().ok_or_else(|| {
            InternalError(format!(
                "applied-state path has no file name: {}",
                self.path.display()
            ))
        })?;
        let tmp = self
            .path
            .with_file_name(format!("{}.tmp", file_name.to_string_lossy()));
        let json = serde_json::to_string(state)
            .map_err(|e| InternalError(format!("cannot serialize applied state: {e}")))?;
        std::fs::write(&tmp, format!("{json}\n"))
            .map_err(|e| InternalError(format!("cannot write {}: {e}", tmp.display())))?;
        std::fs::rename(&tmp, &self.path)
            .map_err(|e| InternalError(format!("cannot move {} into place: {e}", tmp.display())))?;
        Ok(())
    }

    fn describe(&self) -> String {
        self.path.display().to_string()
    }
}

#[cfg(unix)]
fn effective_uid() -> u32 {
    unsafe extern "C" {
        fn geteuid() -> u32;
    }
    // SAFETY: POSIX `geteuid` takes no arguments and has no memory-safety
    // preconditions. uid_t is u32 on the supported Linux/macOS targets.
    unsafe { geteuid() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(name: &str) -> FileStateStore {
        let dir =
            std::env::temp_dir().join(format!("ni-ota-verify-state-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        FileStateStore {
            path: dir.join("applied.json"),
        }
    }

    #[test]
    fn missing_file_reads_unseeded() {
        assert!(matches!(store("unseeded").read(), Ok(StateRead::Unseeded)));
    }

    #[test]
    fn roundtrips_and_detects_corruption() {
        let s = store("roundtrip");
        let state = AppliedState {
            bundle_seq: 7,
            bom_sha256: "ab".repeat(32),
        };
        s.write(&state).unwrap();
        match s.read().unwrap() {
            StateRead::Applied(got) => assert_eq!(got, state),
            StateRead::Unseeded => panic!("expected applied state"),
        }
        std::fs::write(&s.path, "{not json").unwrap();
        assert!(s.read().is_err());
    }

    #[test]
    fn read_refuses_symlink_state() {
        let s = store("symlink");
        let dir = s.path.parent().unwrap();
        std::fs::create_dir_all(dir).unwrap();
        let target = dir.join("outside.json");
        std::fs::write(
            &target,
            r#"{"bundle_seq":7,"bom_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#,
        )
        .unwrap();
        std::os::unix::fs::symlink(target, &s.path).unwrap();
        let Err(error) = s.read() else {
            panic!("symlink state must be refused");
        };
        assert!(error.contains("symlink or non-regular"));
    }
}
