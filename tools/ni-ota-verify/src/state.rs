//! Applied-bundle state — the anti-rollback record.
//!
//! P2 backend: a JSON file `state_dir/applied.json` = `{bundle_seq, bom_sha256}`.
//! P3 replaces the backend with the TPM2 NV index (tpm2-tools, plan P3) behind
//! the SAME trait: the verify/commit logic never learns which backend it talks
//! to, so the swap is a new `AppliedStateStore` impl, not a logic change.

use std::fs::File;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

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

/// Process-scoped exclusive lock for one applied-state path. The lock inode is
/// persistent, but ownership lives in the kernel and is released when this
/// descriptor closes (including process crash), so no stale owner file can
/// block recovery.
pub(crate) struct StateLock {
    file: File,
}

impl Drop for StateLock {
    fn drop(&mut self) {
        let _ = flock(&self.file, LOCK_UN);
    }
}

/// Root-only temporary inode removed on every return path. It is created in
/// the state directory, so publication and directory fsync stay on one
/// filesystem and no untrusted temporary namespace is involved.
pub(crate) struct SecureTempFile {
    path: PathBuf,
}

impl SecureTempFile {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn read(&self) -> Result<Vec<u8>, InternalError> {
        std::fs::read(&self.path)
            .map_err(|e| InternalError(format!("cannot read {}: {e}", self.path.display())))
    }
}

impl Drop for SecureTempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

impl FileStateStore {
    /// Lock the complete bootstrap read/check/write transaction. Bootstrap is
    /// deliberately unable to create its trust-boundary directory.
    pub(crate) fn lock_bootstrap(&self) -> Result<StateLock, String> {
        self.validate_bootstrap_parent()?;
        self.acquire_lock()
    }

    /// Lock the complete post-health commit transaction. Unlike bootstrap,
    /// commit historically supports a custom state path whose parent is not
    /// present yet; create that parent mode 0700, then attest it before use.
    pub(crate) fn lock_commit(&self) -> Result<StateLock, InternalError> {
        self.ensure_commit_parent()?;
        self.acquire_lock().map_err(InternalError)
    }

    /// Bootstrap runs as root on the appliance. Its state parent is a trust
    /// boundary, not scratch space: require an existing real directory and,
    /// for a privileged caller, exact root ownership and mode 0700.
    pub(crate) fn validate_bootstrap_parent(&self) -> Result<(), String> {
        let dir = self.parent().map_err(|error| error.0)?;
        let metadata = std::fs::symlink_metadata(dir)
            .map_err(|e| format!("cannot inspect state dir {}: {e}", dir.display()))?;
        if !metadata.file_type().is_dir() {
            return Err(format!(
                "state parent is not a real directory: {}",
                dir.display()
            ));
        }
        validate_owner_mode(
            &format!("state dir {}", dir.display()),
            metadata.uid(),
            metadata.mode(),
            effective_uid() == 0,
            (effective_uid() == 0).then_some(0o700),
        )
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
        validate_owner_mode(
            &format!("applied state {}", self.path.display()),
            metadata.uid(),
            metadata.mode(),
            effective_uid() == 0,
            Some(0o600),
        )?;
        Ok(true)
    }

    /// Freeze a caller-supplied artifact into a protected inode. Callers must
    /// verify, parse, and hash this snapshot rather than reopening the source.
    pub(crate) fn snapshot(&self, source: &Path) -> Result<SecureTempFile, InternalError> {
        self.validate_bootstrap_parent().map_err(InternalError)?;
        let bytes = std::fs::read(source)
            .map_err(|e| InternalError(format!("cannot read {}: {e}", source.display())))?;
        self.create_secure_temp("bom-snapshot", &bytes)
    }

    /// Atomically publish a new baseline without ever replacing an existing
    /// state path. The fully-written and fsynced temporary inode is linked into
    /// place; `AlreadyExists` means a concurrent or prior bootstrap won and the
    /// caller must compare it before accepting idempotence.
    pub(crate) fn write_if_absent(&self, state: &AppliedState) -> Result<bool, InternalError> {
        let dir = self.parent()?;
        self.validate_bootstrap_parent().map_err(InternalError)?;
        let staged = self.stage_state(state)?;
        let created = match std::fs::hard_link(staged.path(), &self.path) {
            Ok(()) => true,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => false,
            Err(e) => {
                return Err(InternalError(format!(
                    "cannot atomically create {}: {e}",
                    self.path.display()
                )));
            }
        };
        if created {
            drop(staged);
            sync_directory(dir)?;
            self.readback(state)?;
        }
        Ok(created)
    }

    fn parent(&self) -> Result<&Path, InternalError> {
        self.path.parent().ok_or_else(|| {
            InternalError(format!(
                "applied-state path has no parent: {}",
                self.path.display()
            ))
        })
    }

    fn ensure_commit_parent(&self) -> Result<(), InternalError> {
        let dir = self.parent()?;
        let created = match std::fs::symlink_metadata(dir) {
            Ok(_) => false,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir_all(dir).map_err(|e| {
                    InternalError(format!(
                        "cannot create state dir {} mode 0700: {e}",
                        dir.display()
                    ))
                })?;
                std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).map_err(
                    |e| {
                        InternalError(format!(
                            "cannot secure state dir {} mode 0700: {e}",
                            dir.display()
                        ))
                    },
                )?;
                true
            }
            Err(e) => {
                return Err(InternalError(format!(
                    "cannot inspect state dir {}: {e}",
                    dir.display()
                )))
            }
        };
        self.validate_commit_parent().map_err(InternalError)?;
        if created {
            sync_directory(dir)?;
            if let Some(parent) = dir.parent() {
                sync_directory(parent)?;
            }
        }
        Ok(())
    }

    fn validate_commit_parent(&self) -> Result<(), String> {
        let dir = self.parent().map_err(|error| error.0)?;
        let metadata = std::fs::symlink_metadata(dir)
            .map_err(|e| format!("cannot inspect state dir {}: {e}", dir.display()))?;
        if !metadata.file_type().is_dir() {
            return Err(format!(
                "state parent is not a real directory: {}",
                dir.display()
            ));
        }
        validate_owner_mode(
            &format!("state dir {}", dir.display()),
            metadata.uid(),
            metadata.mode(),
            effective_uid() == 0,
            Some(0o700),
        )
    }

    fn acquire_lock(&self) -> Result<StateLock, String> {
        let path = self.lock_path()?;
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) if !metadata.file_type().is_file() => {
                return Err(format!(
                    "state lock is a symlink or non-regular file: {}",
                    path.display()
                ))
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("cannot inspect state lock {}: {e}", path.display())),
        }

        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create(true).mode(0o600);
        let file = options
            .open(&path)
            .map_err(|e| format!("cannot open state lock {}: {e}", path.display()))?;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("cannot secure state lock {}: {e}", path.display()))?;
        validate_open_regular(&path, &file, "state lock")?;
        flock(&file, LOCK_EX)
            .map_err(|e| format!("cannot lock applied state {}: {e}", self.path.display()))?;

        // Re-attest after acquisition. A root-owned 0700 parent prevents an
        // unprivileged replacement; the identity comparison also detects an
        // inode swap between pathname inspection and open.
        if let Err(error) = self.validate_bootstrap_parent() {
            let _ = flock(&file, LOCK_UN);
            return Err(error);
        }
        if let Err(error) = validate_open_regular(&path, &file, "state lock") {
            let _ = flock(&file, LOCK_UN);
            return Err(error);
        }
        Ok(StateLock { file })
    }

    fn lock_path(&self) -> Result<PathBuf, String> {
        let file_name = self.path.file_name().ok_or_else(|| {
            format!(
                "applied-state path has no file name: {}",
                self.path.display()
            )
        })?;
        Ok(self
            .path
            .with_file_name(format!(".{}.lock", file_name.to_string_lossy())))
    }

    fn stage_state(&self, state: &AppliedState) -> Result<SecureTempFile, InternalError> {
        let json = serde_json::to_string(state)
            .map_err(|e| InternalError(format!("cannot serialize applied state: {e}")))?;
        self.create_secure_temp("state", format!("{json}\n").as_bytes())
    }

    fn create_secure_temp(
        &self,
        label: &str,
        contents: &[u8],
    ) -> Result<SecureTempFile, InternalError> {
        let file_name = self.path.file_name().ok_or_else(|| {
            InternalError(format!(
                "applied-state path has no file name: {}",
                self.path.display()
            ))
        })?;
        let (path, mut file) = (0_u16..128)
            .find_map(|attempt| {
                let path = self.path.with_file_name(format!(
                    ".{}.{}.{}.{}.tmp",
                    file_name.to_string_lossy(),
                    label,
                    std::process::id(),
                    attempt
                ));
                let mut options = std::fs::OpenOptions::new();
                options.write(true).create_new(true).mode(0o600);
                match options.open(&path) {
                    Ok(file) => Some(Ok((path, file))),
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => None,
                    Err(e) => Some(Err(InternalError(format!(
                        "cannot create secure temp file {}: {e}",
                        path.display()
                    )))),
                }
            })
            .transpose()?
            .ok_or_else(|| {
                InternalError(format!(
                    "cannot allocate secure temp file beside {}",
                    self.path.display()
                ))
            })?;
        let result = (|| -> Result<(), InternalError> {
            file.set_permissions(std::fs::Permissions::from_mode(0o600))
                .map_err(|e| {
                    InternalError(format!(
                        "cannot secure permissions on {}: {e}",
                        path.display()
                    ))
                })?;
            file.write_all(contents)
                .map_err(|e| InternalError(format!("cannot write {}: {e}", path.display())))?;
            file.sync_all()
                .map_err(|e| InternalError(format!("cannot sync {}: {e}", path.display())))?;
            Ok(())
        })();
        drop(file);
        if let Err(error) = result {
            let _ = std::fs::remove_file(&path);
            return Err(error);
        }
        let temp = SecureTempFile { path };
        validate_secure_regular(temp.path()).map_err(InternalError)?;
        if temp.read()? != contents {
            return Err(InternalError(format!(
                "secure temp readback differs: {}",
                temp.path().display()
            )));
        }
        Ok(temp)
    }

    fn readback(&self, expected: &AppliedState) -> Result<(), InternalError> {
        match self.validate_bootstrap_state() {
            Ok(true) => {}
            Ok(false) => {
                return Err(InternalError(format!(
                    "applied state disappeared after publication: {}",
                    self.path.display()
                )))
            }
            Err(why) => return Err(InternalError(why)),
        }
        match self.read() {
            Ok(StateRead::Applied(actual)) if actual == *expected => Ok(()),
            Ok(StateRead::Applied(_)) => Err(InternalError(format!(
                "applied state readback differs after publication: {}",
                self.path.display()
            ))),
            Ok(StateRead::Unseeded) => Err(InternalError(format!(
                "applied state absent after publication: {}",
                self.path.display()
            ))),
            Err(why) => Err(InternalError(format!(
                "applied state readback failed: {why}"
            ))),
        }
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
        let dir = self.parent()?;
        self.validate_bootstrap_parent().map_err(InternalError)?;
        let staged = self.stage_state(state)?;
        std::fs::rename(staged.path(), &self.path).map_err(|e| {
            InternalError(format!(
                "cannot move {} into place: {e}",
                staged.path().display()
            ))
        })?;
        drop(staged);
        sync_directory(dir)?;
        self.readback(state)
    }

    fn describe(&self) -> String {
        self.path.display().to_string()
    }
}

fn validate_secure_regular(path: &Path) -> Result<(), String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|e| format!("cannot inspect secure file {}: {e}", path.display()))?;
    if !metadata.file_type().is_file() {
        return Err(format!(
            "secure file is a symlink or non-regular file: {}",
            path.display()
        ));
    }
    validate_owner_mode(
        &format!("secure file {}", path.display()),
        metadata.uid(),
        metadata.mode(),
        effective_uid() == 0,
        Some(0o600),
    )
}

fn validate_open_regular(path: &Path, file: &File, label: &str) -> Result<(), String> {
    let path_metadata = std::fs::symlink_metadata(path)
        .map_err(|e| format!("cannot inspect {label} {}: {e}", path.display()))?;
    let file_metadata = file
        .metadata()
        .map_err(|e| format!("cannot inspect open {label} {}: {e}", path.display()))?;
    if !path_metadata.file_type().is_file()
        || !file_metadata.file_type().is_file()
        || path_metadata.dev() != file_metadata.dev()
        || path_metadata.ino() != file_metadata.ino()
    {
        return Err(format!(
            "{label} pathname is a symlink, non-regular file, or replaced inode: {}",
            path.display()
        ));
    }
    validate_owner_mode(
        &format!("{label} {}", path.display()),
        file_metadata.uid(),
        file_metadata.mode(),
        effective_uid() == 0,
        Some(0o600),
    )
}

fn validate_owner_mode(
    label: &str,
    uid: u32,
    mode: u32,
    require_root: bool,
    required_mode: Option<u32>,
) -> Result<(), String> {
    let mode = mode & 0o7777;
    if let Some(required) = required_mode {
        if mode != required {
            return Err(format!(
                "{label} must be mode {required:04o} (mode={mode:04o})"
            ));
        }
    }
    if require_root && uid != 0 {
        return Err(format!("{label} must be root-owned (uid={uid})"));
    }
    Ok(())
}

fn sync_directory(dir: &Path) -> Result<(), InternalError> {
    std::fs::File::open(dir)
        .and_then(|directory| directory.sync_all())
        .map_err(|e| InternalError(format!("cannot sync state dir {}: {e}", dir.display())))
}

const LOCK_EX: i32 = 2;
const LOCK_UN: i32 = 8;

fn flock(file: &File, operation: i32) -> std::io::Result<()> {
    unsafe extern "C" {
        fn flock(fd: i32, operation: i32) -> i32;
    }
    loop {
        // SAFETY: `file` owns a live descriptor for the duration of the call;
        // flock neither retains the pointer nor accesses Rust memory.
        if unsafe { flock(file.as_raw_fd(), operation) } == 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error);
        }
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
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
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
        assert_eq!(std::fs::metadata(&s.path).unwrap().mode() & 0o7777, 0o600);
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

    #[test]
    fn owner_mode_predicate_is_hermetic() {
        assert!(validate_owner_mode("parent", 0, 0o40700, true, Some(0o700)).is_ok());
        assert!(validate_owner_mode("state", 0, 0o100600, true, Some(0o600)).is_ok());
        assert!(validate_owner_mode("parent", 1000, 0o40700, true, Some(0o700)).is_err());
        assert!(validate_owner_mode("parent", 0, 0o40750, true, Some(0o700)).is_err());
        assert!(validate_owner_mode("state", 0, 0o100640, true, Some(0o600)).is_err());
        assert!(validate_owner_mode("dev", 1000, 0o40777, false, None).is_ok());
    }
}
