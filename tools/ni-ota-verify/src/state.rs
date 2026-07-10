//! Applied-bundle state — the anti-rollback record.
//!
//! P2 backend: a JSON file `state_dir/applied.json` = `{bundle_seq, bom_sha256}`.
//! P3 replaces the backend with the TPM2 NV index (tpm2-tools, plan P3) behind
//! the SAME trait: the verify/commit logic never learns which backend it talks
//! to, so the swap is a new `AppliedStateStore` impl, not a logic change.

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

impl AppliedStateStore for FileStateStore {
    fn read(&self) -> Result<StateRead, String> {
        let bytes = match std::fs::read(&self.path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(StateRead::Unseeded),
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
}
