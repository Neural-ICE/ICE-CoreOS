//! External tool runners: cosign (signature verification) and sha256sum
//! (BOM content hash for the repair carve-out). Both are hard dependencies of
//! the image (cosign is version-pinned in Containerfile.bootc §2b, sha256sum
//! is coreutils) — a missing binary is an internal error, never a verdict.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::InternalError;

/// Test seam: `NI_OTA_COSIGN` overrides the baked binary so the test suite can
/// inject a stub (tests/cli.rs) — production always uses the P0-pinned
/// /usr/bin/cosign.
const COSIGN_ENV: &str = "NI_OTA_COSIGN";
const COSIGN_DEFAULT: &str = "/usr/bin/cosign";

pub(crate) fn cosign_path() -> Result<PathBuf, InternalError> {
    let path = std::env::var_os(COSIGN_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(COSIGN_DEFAULT));
    if !path.is_file() {
        return Err(InternalError(format!(
            "cosign not found at {} — the OS image bakes it (Containerfile.bootc §2b); refusing to verify without it",
            path.display()
        )));
    }
    Ok(path)
}

/// `cosign verify-blob --key <pub> --insecure-ignore-tlog=true --signature <sig> <file>`.
/// --insecure-ignore-tlog=true is private-infrastructure mode (ADR-0026 D1):
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

#[cfg(test)]
mod tests {
    use super::sha256_file;
    use std::io::Write;

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
}
