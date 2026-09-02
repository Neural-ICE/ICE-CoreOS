//! External tool runners: cosign (signature verification) and sha256sum
//! (BOM content hash for the repair carve-out). Both are hard dependencies of
//! the image (cosign is version-pinned in Containerfile.bootc §2b, sha256sum
//! is coreutils) — a missing binary is an internal error, never a verdict.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

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
    let output = Command::new(cosign)
        .arg("verify-blob")
        .arg("--key")
        .arg(pubkey)
        .arg("--insecure-ignore-tlog=true")
        .arg("--signature")
        .arg(sig)
        .arg(file)
        .output()
        .map_err(|e| InternalError(format!("failed to run cosign ({}): {e}", cosign.display())))?;
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
    let output = Command::new("sha256sum")
        .arg(path)
        .output()
        .map_err(|e| InternalError(format!("failed to run sha256sum: {e}")))?;
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
    let mut child = Command::new("sha256sum")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| InternalError(format!("failed to run sha256sum: {e}")))?;
    child
        .stdin
        .take()
        .ok_or_else(|| InternalError("sha256sum stdin unavailable".to_string()))?
        .write_all(bytes)
        .map_err(|e| InternalError(format!("cannot feed sha256sum: {e}")))?;
    let output = child
        .wait_with_output()
        .map_err(|e| InternalError(format!("cannot wait for sha256sum: {e}")))?;
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
    use super::{sha256_file, COSIGN_DEFAULT};
    use std::io::Write;
    use std::path::PathBuf;

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
