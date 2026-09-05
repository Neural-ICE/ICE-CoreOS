//! External tool runners: cosign (signature verification) and sha256sum
//! (BOM content hash for the repair carve-out). Both are hard dependencies of
//! the image (cosign is version-pinned in Containerfile.bootc §2b, sha256sum
//! is coreutils) — a missing binary is an internal error, never a verdict.

use std::cell::Cell;
use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use crate::InternalError;

/// Production always runs the P0-pinned /usr/bin/cosign. The test suite's
/// `NI_OTA_COSIGN` stub seam (tests/cli.rs) exists ONLY in the
/// `test-path-overrides` build: a default-feature binary neither reads the
/// variable nor contains its name (the workflow greps the release binary), so
/// an environment an attacker controls cannot swap the signature stack for
/// `/usr/bin/true` (review 2026-09-02, P1). Even the test build honours the
/// seam only for an unprivileged process outside a release image — the same
/// gate every shell seam in this tree applies.
const COSIGN_DEFAULT: &str = "/usr/bin/cosign";
const MAX_HELPER_OUTPUT: usize = 64 * 1024;
#[cfg(not(feature = "test-path-overrides"))]
const HELPER_TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(feature = "test-path-overrides")]
const HELPER_TIMEOUT: Duration = Duration::from_millis(500);

thread_local! {
    /// Optional deadline for one top-level verification operation. Helpers use
    /// the earlier of this deadline and their own bound. This is thread-local
    /// because all verifier command chains are synchronous and it prevents an
    /// unrelated concurrent verification from shortening another operation.
    static OPERATION_DEADLINE: Cell<Option<Instant>> = const { Cell::new(None) };
}

struct DeadlineGuard(Option<Instant>);

impl Drop for DeadlineGuard {
    fn drop(&mut self) {
        OPERATION_DEADLINE.set(self.0);
    }
}

/// Bound a complete synchronous verification chain, including every nested
/// helper. The caller reserves enough time after this deadline for ordinary
/// error propagation and volatile-state cleanup before its outer supervisor
/// kills the verifier process group.
pub(crate) fn with_operation_deadline<T>(duration: Duration, operation: impl FnOnce() -> T) -> T {
    let requested = Instant::now() + duration;
    let previous = OPERATION_DEADLINE.replace(Some(
        OPERATION_DEADLINE
            .get()
            .map_or(requested, |current| current.min(requested)),
    ));
    let _guard = DeadlineGuard(previous);
    operation()
}

/// Refuse cooperatively once the current top-level verification budget has
/// elapsed. This prevents new helpers and bounded local traversal work from
/// starting after the caller's fail-closed deadline. It cannot interrupt a
/// kernel syscall which is already blocked in uninterruptible sleep.
pub(crate) fn check_operation_deadline(label: &str) -> Result<(), InternalError> {
    if OPERATION_DEADLINE
        .get()
        .is_some_and(|deadline| Instant::now() >= deadline)
    {
        return Err(InternalError(format!(
            "authenticated OTA status deadline exceeded before {label}"
        )));
    }
    Ok(())
}

#[derive(Debug)]
pub(crate) struct BoundedOutput {
    pub(crate) status: ExitStatus,
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
    pub(crate) timed_out: bool,
    pub(crate) overflowed: bool,
}

pub(crate) fn bounded_output(
    command: &mut Command,
    stdin: Option<Vec<u8>>,
    label: &str,
) -> Result<BoundedOutput, InternalError> {
    check_operation_deadline(label)?;
    let started = Instant::now();
    let helper_deadline = started + HELPER_TIMEOUT;
    let deadline = OPERATION_DEADLINE
        .get()
        .map_or(helper_deadline, |operation| operation.min(helper_deadline));
    command
        .process_group(0)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|error| InternalError(format!("failed to run {label}: {error}")))?;
    let pid = child.id();
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| InternalError(format!("{label} stdout pipe is unavailable")))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| InternalError(format!("{label} stderr pipe is unavailable")))?;
    let reader = |pipe: Box<dyn Read + Send>| {
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            pipe.take(MAX_HELPER_OUTPUT as u64 + 1)
                .read_to_end(&mut bytes)
                .map(|_| bytes)
        })
    };
    let stdout_thread = reader(Box::new(stdout));
    let stderr_thread = reader(Box::new(stderr));
    let stdin_thread = stdin.map(|bytes| {
        let mut pipe = child.stdin.take().expect("configured piped stdin");
        std::thread::spawn(move || pipe.write_all(&bytes))
    });
    let (status, timed_out) = loop {
        if Instant::now() >= deadline {
            terminate_process_group(pid);
            let _ = child.kill();
            let status = child.wait().map_err(|error| {
                InternalError(format!("cannot reap timed-out {label}: {error}"))
            })?;
            break (status, true);
        }
        match child.try_wait() {
            Ok(Some(status)) => break (status, false),
            Ok(None) => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => {
                terminate_process_group(pid);
                let _ = child.kill();
                let _ = child.wait();
                return Err(InternalError(format!("cannot wait for {label}: {error}")));
            }
        }
    };
    // The direct process may exit while a descendant keeps one of its pipes
    // open. It belongs to the dedicated process group and has no role after
    // the helper exits, so terminate it before joining reader/writer threads.
    terminate_process_group(pid);
    let join_reader = |thread: std::thread::JoinHandle<std::io::Result<Vec<u8>>>, stream: &str| {
        thread
            .join()
            .map_err(|_| InternalError(format!("{label} {stream} reader panicked")))?
            .map_err(|error| InternalError(format!("cannot read {label} {stream}: {error}")))
    };
    let stdout = join_reader(stdout_thread, "stdout")?;
    let stderr = join_reader(stderr_thread, "stderr")?;
    if let Some(thread) = stdin_thread {
        match thread.join() {
            Ok(Ok(())) => {}
            // A helper that closes stdin early reports its real exit status;
            // EPIPE is not promoted over that result.
            Ok(Err(error)) if error.kind() == std::io::ErrorKind::BrokenPipe => {}
            Ok(Err(error)) => {
                return Err(InternalError(format!(
                    "cannot provide {label} input: {error}"
                )))
            }
            Err(_) => return Err(InternalError(format!("{label} stdin writer panicked"))),
        }
    }
    Ok(BoundedOutput {
        status,
        overflowed: stdout.len() > MAX_HELPER_OUTPUT || stderr.len() > MAX_HELPER_OUTPUT,
        stdout,
        stderr,
        timed_out,
    })
}

fn terminate_process_group(pid: u32) {
    if let Ok(pid) = i32::try_from(pid) {
        // SAFETY: the spawned child is explicitly made leader of a fresh
        // process group whose numeric ID is its PID. A negative PID targets
        // only that group. Failure is followed by Child::kill/wait above.
        unsafe {
            kill(-pid, 9);
        }
    }
}

unsafe extern "C" {
    fn kill(pid: i32, signal: i32) -> i32;
}

#[cfg(not(feature = "test-path-overrides"))]
fn resolved_cosign() -> Result<PathBuf, InternalError> {
    Ok(PathBuf::from(COSIGN_DEFAULT))
}

#[cfg(feature = "test-path-overrides")]
fn resolved_cosign() -> Result<PathBuf, InternalError> {
    seam::select_cosign(
        std::env::var_os(seam::COSIGN_ENV).map(PathBuf::from),
        crate::state::effective_uid(),
        Path::new(seam::RELEASE_MARKER).exists(),
    )
}

#[cfg(feature = "test-path-overrides")]
mod seam {
    use super::COSIGN_DEFAULT;
    use crate::InternalError;
    use std::path::PathBuf;

    pub(super) const COSIGN_ENV: &str = "NI_OTA_COSIGN";
    /// The immutable release marker every test seam in this tree refuses to
    /// run beside (image/firstboot/neural-ice-firstboot-sshkey.sh,
    /// image/initramfs/91neural-ice-tpm-policy/neural-ice-tpm-policy.sh).
    pub(super) const RELEASE_MARKER: &str = "/usr/lib/neural-ice/release-image";

    /// Pure selection so the gate itself is under test: an override is
    /// honoured only when the process is unprivileged and no release marker
    /// exists. Root or a release image is an internal error, never a silent
    /// fallback to the real binary (a caller that meant to inject a stub must
    /// not read the real cosign's "valid" as proof of its stub).
    pub(super) fn select_cosign(
        requested: Option<PathBuf>,
        euid: u32,
        release_marker_present: bool,
    ) -> Result<PathBuf, InternalError> {
        match requested {
            None => Ok(PathBuf::from(COSIGN_DEFAULT)),
            Some(_) if euid == 0 => Err(InternalError(format!(
                "{COSIGN_ENV} is a test seam and is refused in a privileged process"
            ))),
            Some(_) if release_marker_present => Err(InternalError(format!(
                "{COSIGN_ENV} is a test seam and is refused in a release image ({RELEASE_MARKER} exists)"
            ))),
            Some(path) => Ok(path),
        }
    }
}

pub(crate) fn cosign_path() -> Result<PathBuf, InternalError> {
    let path = resolved_cosign()?;
    if !path.is_file() {
        return Err(InternalError(format!(
            "cosign not found at {} — the OS image bakes it (Containerfile.bootc §2b); refusing to verify without it",
            path.display()
        )));
    }
    Ok(path)
}

/// `cosign verify-blob --key <pub> --insecure-ignore-tlog=true --signature <sig> <file>`.
/// --insecure-ignore-tlog=true is private-infrastructure mode:
/// there is deliberately no public Rekor entry to check.
/// Ok(Ok(())) = signature valid; Ok(Err(detail)) = cosign rejected it (a
/// verification failure, i.e. a check result); Err = could not run cosign.
pub(crate) fn verify_blob(
    cosign: &Path,
    pubkey: &Path,
    sig: &Path,
    file: &Path,
) -> Result<Result<(), String>, InternalError> {
    let mut command = Command::new(cosign);
    command
        .arg("verify-blob")
        .arg("--key")
        .arg(pubkey)
        .arg("--insecure-ignore-tlog=true")
        .arg("--signature")
        .arg(sig)
        .arg(file);
    let output = bounded_output(
        &mut command,
        None,
        &format!("cosign ({})", cosign.display()),
    )?;
    if output.timed_out || output.overflowed {
        return Err(InternalError("cosign exceeded its process bound".into()));
    }
    if output.status.success() {
        return Ok(Ok(()));
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let reason = stderr
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("no error output")
        .trim();
    // char-boundary-safe cap (String::truncate panics mid-codepoint)
    let reason: String = reason.chars().take(200).collect();
    // ExitStatus's Display already reads "exit status: N"
    Ok(Err(format!("cosign {}: {reason}", output.status)))
}

/// sha256 of a file via coreutils — the BOM content hash recorded in the
/// applied state (repair carve-out: equal seq is only re-applicable for the
/// byte-identical BOM). Not signature crypto — cosign stays the only
/// signature stack.
pub(crate) fn sha256_file(path: &Path) -> Result<String, InternalError> {
    let mut command = Command::new("sha256sum");
    command.arg(path);
    let output = bounded_output(&mut command, None, "sha256sum")?;
    if output.timed_out || output.overflowed {
        return Err(InternalError("sha256sum exceeded its process bound".into()));
    }
    if !output.status.success() {
        return Err(InternalError(format!(
            "sha256sum failed for {}: {}",
            path.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let digest = stdout.split_whitespace().next().unwrap_or_default();
    if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(InternalError(format!(
            "sha256sum produced no digest for {}",
            path.display()
        )));
    }
    Ok(digest.to_ascii_lowercase())
}

/// Hash verifier-generated bytes without publishing them in an untrusted
/// filesystem namespace.
pub(crate) fn sha256_bytes(bytes: &[u8]) -> Result<String, InternalError> {
    let mut command = Command::new("sha256sum");
    let output = bounded_output(&mut command, Some(bytes.to_vec()), "sha256sum")?;
    if output.timed_out || output.overflowed {
        return Err(InternalError("sha256sum exceeded its process bound".into()));
    }
    if !output.status.success() {
        return Err(InternalError(format!(
            "sha256sum failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let digest = stdout.split_whitespace().next().unwrap_or_default();
    if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(InternalError("sha256sum produced no digest".to_string()));
    }
    Ok(digest.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    #[cfg(not(feature = "test-path-overrides"))]
    use super::cosign_path;
    #[cfg(feature = "test-path-overrides")]
    use super::seam::select_cosign;
    #[cfg(feature = "test-path-overrides")]
    use super::{bounded_output, with_operation_deadline};
    use super::{sha256_file, COSIGN_DEFAULT};
    use std::io::Write;
    use std::path::PathBuf;
    #[cfg(feature = "test-path-overrides")]
    use std::process::Command;
    #[cfg(feature = "test-path-overrides")]
    use std::time::{Duration, Instant};

    #[test]
    fn sha256_matches_known_vector() {
        let dir = std::env::temp_dir().join(format!("ni-ota-verify-sha-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("vector");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(b"abc").unwrap();
        drop(f);
        assert_eq!(
            sha256_file(&path).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(feature = "test-path-overrides")]
    #[test]
    fn bounded_runner_reaps_a_timed_out_helper_process_group() {
        let started = Instant::now();
        let mut command = Command::new("bash");
        command.args(["-c", "sleep 30 & wait"]);
        let output = bounded_output(&mut command, None, "timeout fixture").unwrap();
        assert!(output.timed_out);
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[cfg(feature = "test-path-overrides")]
    #[test]
    fn operation_deadline_shortens_the_current_helper_bound() {
        let started = Instant::now();
        let output = with_operation_deadline(Duration::from_millis(40), || {
            let mut command = Command::new("bash");
            command.args(["-c", "sleep 30 & wait"]);
            bounded_output(&mut command, None, "operation deadline fixture").unwrap()
        });
        assert!(output.timed_out);
        assert!(started.elapsed() < Duration::from_millis(400));
    }

    #[cfg(feature = "test-path-overrides")]
    #[test]
    fn expired_operation_deadline_refuses_before_spawning_a_helper() {
        let dir =
            std::env::temp_dir().join(format!("ni-ota-runner-expired-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let marker = dir.join("spawned");
        let error = with_operation_deadline(Duration::ZERO, || {
            let mut command = Command::new("touch");
            command.arg(&marker);
            bounded_output(&mut command, None, "expired operation fixture")
        })
        .unwrap_err();
        assert!(error.0.contains("deadline exceeded"), "{}", error.0);
        assert!(!marker.exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(feature = "test-path-overrides")]
    #[test]
    fn bounded_runner_marks_oversized_output() {
        let mut command = Command::new("python3");
        command.args(["-c", "import sys; sys.stderr.write('x' * 65537)"]);
        let output = bounded_output(&mut command, None, "overflow fixture").unwrap();
        assert!(output.overflowed);
    }

    #[cfg(feature = "test-path-overrides")]
    #[test]
    fn no_override_selects_the_pinned_cosign_regardless_of_privilege() {
        for (euid, marker) in [(0, false), (0, true), (1000, false), (1000, true)] {
            assert_eq!(
                select_cosign(None, euid, marker).unwrap(),
                PathBuf::from(COSIGN_DEFAULT)
            );
        }
    }

    #[cfg(feature = "test-path-overrides")]
    #[test]
    fn override_is_refused_for_root_and_inside_a_release_image() {
        let stub = Some(PathBuf::from("/usr/bin/true"));
        let root = select_cosign(stub.clone(), 0, false).unwrap_err();
        assert!(root.0.contains("privileged"), "{}", root.0);
        let release = select_cosign(stub.clone(), 1000, true).unwrap_err();
        assert!(release.0.contains("release image"), "{}", release.0);
        let both = select_cosign(stub, 0, true).unwrap_err();
        assert!(both.0.contains("privileged"), "{}", both.0);
    }

    #[cfg(feature = "test-path-overrides")]
    #[test]
    fn override_is_honoured_only_for_an_unprivileged_process_outside_a_release_image() {
        assert_eq!(
            select_cosign(Some(PathBuf::from("/usr/bin/true")), 1000, false).unwrap(),
            PathBuf::from("/usr/bin/true")
        );
    }

    /// The production build must not even read the seam: with the variable
    /// set to an always-successful executable, the resolved path is still the
    /// pinned binary (or the pinned binary's absence is the reported error).
    #[cfg(not(feature = "test-path-overrides"))]
    #[test]
    fn production_build_ignores_the_cosign_environment_seam() {
        std::env::set_var("NI_OTA_COSIGN", "/usr/bin/true");
        let resolved = cosign_path();
        std::env::remove_var("NI_OTA_COSIGN");
        match resolved {
            Ok(path) => assert_eq!(path, PathBuf::from(COSIGN_DEFAULT)),
            Err(error) => {
                assert!(error.0.contains(COSIGN_DEFAULT), "{}", error.0);
                assert!(!error.0.contains("/usr/bin/true"), "{}", error.0);
            }
        }
    }
}
