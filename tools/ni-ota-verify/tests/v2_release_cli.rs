//! `verify-v2-release` / `verify-retained-v2-release` against the golden vectors
//! of `docs/ota/V2-RELEASE-ATTESTATION.md` (mission B, T1).
//!
//! The positive tests replay `tests/fixtures/v2-release/golden.json` byte for
//! byte. The negatives are derived from the same files by mutation: a mutated
//! manifest is re-signed with a throw-away key generated at run time (the golden
//! private key was deleted), so each refusal is reached through the rule it
//! names and not through an earlier signature failure.
#![cfg(all(target_os = "linux", feature = "test-path-overrides"))]

use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::Value;
use sha2::{Digest, Sha256};

static NEXT: AtomicU64 = AtomicU64::new(0);

/// `cosign verify-blob --key K --insecure-ignore-tlog=true --signature S FILE`
/// with the signature check done by openssl: the very ECDSA-P256-SHA256 check of
/// the golden test, behind the verifier's real cosign argument vector.
const COSIGN_STUB: &str = r#"#!/bin/sh
[ "$#" -eq 7 ] && [ "$1" = verify-blob ] && [ "$2" = --key ] \
  && [ "$4" = --insecure-ignore-tlog=true ] && [ "$5" = --signature ] || exit 97
tmp=$(mktemp -d) || exit 98
trap 'rm -rf "$tmp"' EXIT
openssl base64 -d -A -in "$6" -out "$tmp/sig.der" 2>/dev/null || { echo "bad base64" >&2; exit 1; }
openssl dgst -sha256 -verify "$3" -signature "$tmp/sig.der" "$7" >/dev/null 2>&1 \
  || { echo "invalid signature" >&2; exit 1; }
"#;

fn golden_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/v2-release")
}

fn hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn run_tool(args: &[&str]) {
    let output = Command::new(args[0]).args(&args[1..]).output().unwrap();
    assert!(
        output.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}

fn private_dir(path: &Path) {
    fs::create_dir_all(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

/// One working copy of the golden inputs, plus the argument vector derived from
/// them. Every field a test mutates is a file under `dir` or an entry of `args`.
struct Case {
    dir: PathBuf,
    golden: Value,
    args: Vec<(String, String)>,
}

impl Case {
    fn golden(mode: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "ni-v2-release-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        private_dir(&dir);
        let source = golden_dir();
        let golden: Value = serde_json::from_slice(&fs::read(source.join("golden.json")).unwrap())
            .expect("golden.json");
        for name in [
            "release-manifest.json",
            "release-manifest.json.sig",
            "release-authorization.pub",
        ] {
            fs::copy(source.join(name), dir.join(name)).unwrap();
        }
        copy_tree(&source.join("candidate-root"), &dir.join("root"));
        private_dir(&dir.join("out"));
        let cosign = dir.join("cosign");
        fs::write(&cosign, COSIGN_STUB).unwrap();
        fs::set_permissions(&cosign, fs::Permissions::from_mode(0o755)).unwrap();
        let mut case = Case {
            dir,
            golden,
            args: Vec::new(),
        };
        case.rebuild_args(mode);
        case
    }

    fn input(&self, name: &str) -> String {
        match &self.golden["inputs"][name] {
            Value::String(text) => text.clone(),
            Value::Number(number) => number.to_string(),
            other => panic!("golden input {name}: {other}"),
        }
    }

    fn rebuild_args(&mut self, mode: &str) {
        let path = |name: &str| self.dir.join(name).to_string_lossy().into_owned();
        let mut args: Vec<(String, String)> = vec![
            ("manifest".into(), path("release-manifest.json")),
            ("manifest-sig".into(), path("release-manifest.json.sig")),
            ("release-key".into(), path("release-authorization.pub")),
            ("sealed-key-sha256".into(), self.input("sealed_key_sha256")),
        ];
        match mode {
            "manifest-digest" => {
                args.push((
                    "sealed-manifest-sha256".into(),
                    self.input("sealed_manifest_sha256"),
                ));
                args.push((
                    "sealed-manifest-sig-sha256".into(),
                    self.input("sealed_manifest_sig_sha256"),
                ));
            }
            "floor" => args.push((
                "sealed-min-bundle-seq".into(),
                self.input("sealed_min_bundle_seq"),
            )),
            other => panic!("unknown mode {other}"),
        }
        for (flag, key) in [
            ("hardware-target", "hardware_target"),
            ("access-profile", "access_profile"),
            ("trust-policy-id", "trust_policy_id"),
            ("variant", "variant"),
            ("release-authority", "release_authority"),
            ("host-index-digest", "host_index_digest"),
            ("host-manifest-digest", "host_manifest_digest"),
        ] {
            args.push((flag.into(), self.input(key)));
        }
        args.push(("candidate-root".into(), path("root")));
        args.push(("receipt".into(), path("out/receipt.json")));
        self.args = args;
    }

    fn set(&mut self, flag: &str, value: &str) {
        let slot = self
            .args
            .iter_mut()
            .find(|(name, _)| name == flag)
            .unwrap_or_else(|| panic!("no flag {flag}"));
        slot.1 = value.to_string();
    }

    fn remove(&mut self, flag: &str) {
        let before = self.args.len();
        self.args.retain(|(name, _)| name != flag);
        assert_eq!(before - 1, self.args.len(), "no flag {flag}");
    }

    fn add(&mut self, flag: &str, value: &str) {
        self.args.push((flag.to_string(), value.to_string()));
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.dir.join(relative)
    }

    fn receipt(&self) -> PathBuf {
        self.path("out/receipt.json")
    }

    fn command(&self, verb: &str, args: &[(String, String)]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_ni-ota-verify"));
        command.arg(verb).env("NI_OTA_COSIGN", self.path("cosign"));
        for (flag, value) in args {
            command.arg(format!("--{flag}")).arg(value);
        }
        command
    }

    fn verify(&self) -> Output {
        self.command("verify-v2-release", &self.args)
            .output()
            .unwrap()
    }

    /// Sign `manifest` with a fresh throw-away key and make every input that
    /// names the manifest, its signature or the key agree with it, so that only
    /// the property under test is wrong.
    fn resign(&mut self, mode: &str, manifest: &[u8]) {
        let key = self.path("signing.key");
        run_tool(&[
            "openssl",
            "ecparam",
            "-name",
            "prime256v1",
            "-genkey",
            "-noout",
            "-out",
            key.to_str().unwrap(),
        ]);
        run_tool(&[
            "openssl",
            "pkey",
            "-in",
            key.to_str().unwrap(),
            "-pubout",
            "-out",
            self.path("release-authorization.pub").to_str().unwrap(),
        ]);
        fs::write(self.path("release-manifest.json"), manifest).unwrap();
        run_tool(&[
            "openssl",
            "dgst",
            "-sha256",
            "-sign",
            key.to_str().unwrap(),
            "-out",
            self.path("sig.der").to_str().unwrap(),
            self.path("release-manifest.json").to_str().unwrap(),
        ]);
        let encoded = Command::new("openssl")
            .args(["base64", "-A", "-in"])
            .arg(self.path("sig.der"))
            .output()
            .unwrap()
            .stdout;
        fs::write(self.path("release-manifest.json.sig"), &encoded).unwrap();
        let public = fs::read(self.path("release-authorization.pub")).unwrap();
        fs::write(
            self.path("root/usr/lib/neural-ice/keys/release-authorization.pub"),
            &public,
        )
        .unwrap();
        self.rebuild_args(mode);
        self.set("sealed-key-sha256", &hex(&public));
        if mode == "manifest-digest" {
            self.set("sealed-manifest-sha256", &hex(manifest));
            self.set("sealed-manifest-sig-sha256", &hex(&encoded));
        }
    }

    fn manifest_text(&self) -> String {
        String::from_utf8(fs::read(self.path("release-manifest.json")).unwrap()).unwrap()
    }

    fn marker(&self, name: &str) -> PathBuf {
        self.path(&format!("root/usr/lib/neural-ice/{name}"))
    }
}

impl Drop for Case {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn assert_refused(case: &Case, output: &Output, class: &str) {
    assert_eq!(output.status.code(), Some(1), "{}", stderr(output));
    assert!(output.stdout.is_empty(), "stdout on a refusal");
    let message = stderr(output);
    assert!(
        message.contains(&format!("ni-ota-verify: v2 release REFUSED: {class}:")),
        "expected class `{class}`, got: {message}"
    );
    assert!(
        !case.receipt().exists(),
        "a refusal must not publish a receipt ({class})"
    );
    assert_eq!(
        fs::read_dir(case.path("out")).unwrap().count(),
        0,
        "a refusal must leave no residue beside the receipt ({class})"
    );
}

fn replace_once(text: &str, from: &str, to: &str) -> String {
    assert_eq!(text.matches(from).count(), 1, "`{from}` must occur once");
    text.replacen(from, to, 1)
}

// ---------------------------------------------------------------------------
// Golden replay
// ---------------------------------------------------------------------------

fn replay_golden(mode: &str) {
    let case = Case::golden(mode);
    let output = case.verify();
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let expected = &case.golden["expected"];
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    let line: Value = serde_json::from_str(stdout.trim_end()).unwrap();
    assert_eq!(line, expected["verify_stdout"][mode]);
    // One line, keys in the contract order, one LF.
    assert_eq!(
        stdout,
        format!(
            "{{\"bundle_seq\":3,\"idempotent\":false,\"receipt_sha256\":\"{}\",\"verdict\":\"pass\"}}\n",
            expected["receipt_sha256"][mode].as_str().unwrap()
        )
    );
    assert!(output.stderr.is_empty(), "{}", stderr(&output));
    let receipt = fs::read(case.receipt()).unwrap();
    assert_eq!(
        receipt,
        fs::read(golden_dir().join(format!("expected-receipt-{mode}.json"))).unwrap()
    );
    assert_eq!(hex(&receipt), expected["receipt_sha256"][mode]);
    let metadata = fs::metadata(case.receipt()).unwrap();
    assert_eq!(metadata.permissions().mode() & 0o7777, 0o600);
    assert_eq!(fs::read_dir(case.path("out")).unwrap().count(), 1);

    // Replay: a second call finds the byte-equal receipt and says so.
    let again = case.verify();
    assert_eq!(again.status.code(), Some(0), "{}", stderr(&again));
    let second = String::from_utf8(again.stdout).unwrap();
    assert!(second.contains("\"idempotent\":true"), "{second}");
    assert_eq!(fs::read(case.receipt()).unwrap(), receipt);
    assert_eq!(fs::read_dir(case.path("out")).unwrap().count(), 1);
}

#[test]
fn golden_manifest_digest_mode_prints_the_golden_line_and_writes_the_golden_receipt() {
    replay_golden("manifest-digest");
}

#[test]
fn golden_floor_mode_prints_the_golden_line_and_writes_the_golden_receipt() {
    replay_golden("floor");
}

/// The signature check is the pinned cosign, not a stub of ours: when a real
/// cosign is installed it must accept the golden pair (a high-S signature, as a
/// KMS may produce) through the same argument vector.
#[test]
fn golden_pair_verifies_with_a_real_cosign_when_one_is_installed() {
    let Some(cosign) = ["/usr/local/bin/cosign", "/usr/bin/cosign"]
        .into_iter()
        .map(Path::new)
        .find(|path| path.is_file())
    else {
        eprintln!("SKIP: no cosign binary on this host; the stub test covers the vector");
        return;
    };
    let case = Case::golden("manifest-digest");
    let output = case
        .command("verify-v2-release", &case.args)
        .env("NI_OTA_COSIGN", cosign)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
}

// ---------------------------------------------------------------------------
// Usage errors: exit 2, never a verdict
// ---------------------------------------------------------------------------

#[test]
fn unknown_missing_repeated_and_valueless_flags_are_usage_errors() {
    let mut unknown = Case::golden("manifest-digest");
    unknown.add("surprise", "x");
    let output = unknown.verify();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        stderr(&output).contains("unknown flag --surprise"),
        "{}",
        stderr(&output)
    );

    let mut missing = Case::golden("manifest-digest");
    missing.remove("candidate-root");
    let output = missing.verify();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        stderr(&output).contains("--candidate-root"),
        "{}",
        stderr(&output)
    );

    let mut repeated = Case::golden("manifest-digest");
    repeated.add("variant", "sealed-lab");
    let output = repeated.verify();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        stderr(&output).contains("--variant given twice"),
        "{}",
        stderr(&output)
    );

    let valueless = Case::golden("manifest-digest");
    let output = Command::new(env!("CARGO_BIN_EXE_ni-ota-verify"))
        .args(["verify-v2-release", "--manifest"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        stderr(&output).contains("--manifest needs a value"),
        "{}",
        stderr(&output)
    );
    for case in [&unknown, &missing, &repeated, &valueless] {
        assert!(!case.receipt().exists());
    }
}

// ---------------------------------------------------------------------------
// Refusals, in the order of the contract (§2)
// ---------------------------------------------------------------------------

#[test]
fn rule_1_mode_needs_exactly_one_seal_mode() {
    let mut both = Case::golden("manifest-digest");
    both.add("sealed-min-bundle-seq", "2");
    assert_refused(&both, &both.verify(), "mode");

    let mut neither = Case::golden("manifest-digest");
    neither.remove("sealed-manifest-sha256");
    neither.remove("sealed-manifest-sig-sha256");
    assert_refused(&neither, &neither.verify(), "mode");

    let mut half = Case::golden("manifest-digest");
    half.remove("sealed-manifest-sig-sha256");
    assert_refused(&half, &half.verify(), "mode");
}

#[test]
fn rule_2_freshness_is_reserved_and_refused() {
    let mut case = Case::golden("floor");
    case.add("freshness", "/nonexistent/freshness.json");
    case.add("freshness-sig", "/nonexistent/freshness.sig");
    assert_refused(&case, &case.verify(), "freshness-unsupported");
    let mut lone = Case::golden("floor");
    lone.add("freshness", "/nonexistent/freshness.json");
    assert_refused(&lone, &lone.verify(), "freshness-unsupported");
}

#[test]
fn rule_3_key_digest_refuses_a_key_other_than_the_sealed_one() {
    let mut case = Case::golden("manifest-digest");
    case.set("sealed-key-sha256", &"0".repeat(64));
    assert_refused(&case, &case.verify(), "key-digest");
    let mut malformed = Case::golden("manifest-digest");
    malformed.set("sealed-key-sha256", "ZZ");
    assert_refused(&malformed, &malformed.verify(), "key-digest");
}

#[test]
fn rule_4_sealed_manifest_and_signature_digests_must_match() {
    let mut manifest = Case::golden("manifest-digest");
    manifest.set("sealed-manifest-sha256", &"1".repeat(64));
    assert_refused(&manifest, &manifest.verify(), "manifest-digest");

    let mut sig = Case::golden("manifest-digest");
    sig.set("sealed-manifest-sig-sha256", &"2".repeat(64));
    assert_refused(&sig, &sig.verify(), "sig-digest");

    // One byte of the manifest changes under the sealed digest.
    let case = Case::golden("manifest-digest");
    let mut bytes = fs::read(case.path("release-manifest.json")).unwrap();
    bytes[10] ^= 0x01;
    fs::write(case.path("release-manifest.json"), bytes).unwrap();
    assert_refused(&case, &case.verify(), "manifest-digest");
}

#[test]
fn rule_5_signature_is_checked_over_the_exact_bytes() {
    // floor mode has no sealed digest in front of the signature check.
    let flipped = Case::golden("floor");
    let mut bytes = fs::read(flipped.path("release-manifest.json")).unwrap();
    bytes[10] ^= 0x01;
    fs::write(flipped.path("release-manifest.json"), bytes).unwrap();
    assert_refused(&flipped, &flipped.verify(), "signature");

    // A trailing LF is part of the bytes: there is no canonicalisation.
    let lf = Case::golden("floor");
    let mut bytes = fs::read(lf.path("release-manifest.json")).unwrap();
    bytes.push(b'\n');
    fs::write(lf.path("release-manifest.json"), bytes).unwrap();
    assert_refused(&lf, &lf.verify(), "signature");

    // A signature by another key under the sealed key.
    let other = Case::golden("floor");
    let mut forged = Case::golden("floor");
    forged.resign(
        "floor",
        fs::read(other.path("release-manifest.json"))
            .unwrap()
            .as_slice(),
    );
    let foreign_sig = fs::read(forged.path("release-manifest.json.sig")).unwrap();
    fs::write(other.path("release-manifest.json.sig"), foreign_sig).unwrap();
    assert_refused(&other, &other.verify(), "signature");

    // Not base64 at all.
    let junk = Case::golden("floor");
    fs::write(junk.path("release-manifest.json.sig"), b"not a signature").unwrap();
    assert_refused(&junk, &junk.verify(), "signature");
}

#[test]
fn rule_6_a_duplicated_json_key_is_refused_even_when_signed() {
    for mode in ["manifest-digest", "floor"] {
        let mut case = Case::golden(mode);
        let text = case.manifest_text();
        let duplicated = replace_once(
            &text,
            "\"bundle_seq\":3,",
            "\"bundle_seq\":3,\"bundle_seq\":9,",
        );
        case.resign(mode, duplicated.as_bytes());
        assert_refused(&case, &case.verify(), "duplicate-key");
    }
    // At depth: a duplicate inside the host object.
    let mut nested = Case::golden("floor");
    let text = nested.manifest_text();
    let duplicated = replace_once(&text, "\"host\":{", "\"host\":{\"reboot_required\":false,");
    nested.resign("floor", duplicated.as_bytes());
    assert_refused(&nested, &nested.verify(), "duplicate-key");
    // Not JSON at all, and over the 1 MiB bound.
    let mut garbage = Case::golden("floor");
    garbage.resign("floor", b"{\"schema\":");
    assert_refused(&garbage, &garbage.verify(), "duplicate-key");
    let mut large = Case::golden("floor");
    let mut big = large.manifest_text().into_bytes();
    big.resize(1024 * 1024 + 1, b' ');
    large.resign("floor", &big);
    assert_refused(&large, &large.verify(), "duplicate-key");
}

#[test]
fn rule_7_schema_and_release_id_are_closed() {
    let mut schema = Case::golden("floor");
    let text = schema.manifest_text();
    schema.resign(
        "floor",
        replace_once(
            &text,
            "neural-ice-release-manifest-v1",
            "neural-ice-release-manifest-v2",
        )
        .as_bytes(),
    );
    assert_refused(&schema, &schema.verify(), "schema");

    for bad in ["has space", "semi;colon", "", "a/b"] {
        let mut id = Case::golden("floor");
        let text = id.manifest_text();
        id.resign(
            "floor",
            replace_once(
                &text,
                "\"release_id\":\"v2-test-train-3\"",
                &format!("\"release_id\":\"{bad}\""),
            )
            .as_bytes(),
        );
        assert_refused(&id, &id.verify(), "schema");
    }
}

#[test]
fn rule_8_bundle_seq_is_an_integer_in_range() {
    for (label, replacement) in [
        ("zero", "\"bundle_seq\":0"),
        ("above 2^53-1", "\"bundle_seq\":9007199254740992"),
        ("float", "\"bundle_seq\":3.0"),
        ("string", "\"bundle_seq\":\"3\""),
        ("negative", "\"bundle_seq\":-1"),
    ] {
        let mut case = Case::golden("floor");
        let text = case.manifest_text();
        case.resign(
            "floor",
            replace_once(&text, "\"bundle_seq\":3", replacement).as_bytes(),
        );
        let output = case.verify();
        assert_refused(&case, &output, "bundle-seq");
        let _ = label;
    }
    // The bound itself is accepted: 2^53-1 is the largest floor ota-tpm-state writes.
    let mut edge = Case::golden("floor");
    let text = edge.manifest_text();
    edge.resign(
        "floor",
        replace_once(&text, "\"bundle_seq\":3", "\"bundle_seq\":9007199254740991").as_bytes(),
    );
    let output = edge.verify();
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(String::from_utf8_lossy(&output.stdout).contains("\"bundle_seq\":9007199254740991"));
}

#[test]
fn rule_9_floor_mode_refuses_a_manifest_below_the_sealed_minimum() {
    let mut case = Case::golden("floor");
    case.set("sealed-min-bundle-seq", "4");
    assert_refused(&case, &case.verify(), "min-bundle-seq");
    // Equality is not below.
    let mut equal = Case::golden("floor");
    equal.set("sealed-min-bundle-seq", "3");
    assert_eq!(equal.verify().status.code(), Some(0));
    // A malformed minimum never defaults.
    for bad in ["0", "x", "-1", "9007199254740992"] {
        let mut malformed = Case::golden("floor");
        malformed.set("sealed-min-bundle-seq", bad);
        assert_refused(&malformed, &malformed.verify(), "min-bundle-seq");
    }
}

#[test]
fn rule_10_hardware_target_must_match_the_manifest() {
    let mut case = Case::golden("manifest-digest");
    case.set("hardware-target", "other-arm64");
    assert_refused(&case, &case.verify(), "hardware-target");
}

#[test]
fn rule_11_release_authority_must_match_the_host_repository() {
    let mut case = Case::golden("manifest-digest");
    case.set("release-authority", "registry.example.invalid");
    assert_refused(&case, &case.verify(), "authority");
    // A prefix of the authority is not the authority.
    let mut prefix = Case::golden("manifest-digest");
    prefix.set("release-authority", "registry.example");
    assert_refused(&prefix, &prefix.verify(), "authority");
}

#[test]
fn rule_12_host_index_digest_must_match_the_manifest_and_be_well_formed() {
    let mut other = Case::golden("manifest-digest");
    other.set("host-index-digest", &format!("sha256:{}", "c".repeat(64)));
    assert_refused(&other, &other.verify(), "host-digest");
    let mut malformed = Case::golden("manifest-digest");
    malformed.set("host-manifest-digest", "sha256:XYZ");
    assert_refused(&malformed, &malformed.verify(), "host-digest");
}

#[test]
fn rule_13_candidate_markers_must_equal_the_sealed_values() {
    // Each marker, once wrong; the matching flag, once wrong.
    for marker in [
        "hardware-target",
        "appliance-variant",
        "signed-boot-trust-policy-id",
        "access-policy",
    ] {
        let case = Case::golden("manifest-digest");
        fs::write(case.marker(marker), b"something-else\n").unwrap();
        assert_refused(&case, &case.verify(), "candidate-marker");
    }
    // The v1 lane marker on a candidate is the exact pre-T0 failure: refused.
    let v1 = Case::golden("manifest-digest");
    fs::write(
        v1.marker("ota-state-profile"),
        b"owner-sealed-ota-state-v1\n",
    )
    .unwrap();
    assert_refused(&v1, &v1.verify(), "candidate-marker");
    let unmarked = Case::golden("manifest-digest");
    fs::remove_file(unmarked.marker("ota-state-profile")).unwrap();
    assert_refused(&unmarked, &unmarked.verify(), "candidate-marker");

    let mut profile = Case::golden("manifest-digest");
    profile.set("access-profile", "managed-other");
    assert_refused(&profile, &profile.verify(), "candidate-marker");
    let mut policy = Case::golden("manifest-digest");
    policy.set("trust-policy-id", "neural-ice-secureboot-other-v1");
    assert_refused(&policy, &policy.verify(), "candidate-marker");
    let mut variant = Case::golden("manifest-digest");
    variant.set("variant", "sealed-prod");
    assert_refused(&variant, &variant.verify(), "candidate-marker");
}

#[test]
fn rule_13_markers_are_regular_bounded_files_read_without_following_links() {
    let link = Case::golden("manifest-digest");
    let real = link.path("elsewhere");
    fs::write(&real, b"nvidia-gb10-arm64\n").unwrap();
    fs::remove_file(link.marker("hardware-target")).unwrap();
    symlink(&real, link.marker("hardware-target")).unwrap();
    assert_refused(&link, &link.verify(), "candidate-marker");

    let big = Case::golden("manifest-digest");
    let mut oversized = b"nvidia-gb10-arm64".to_vec();
    oversized.extend(std::iter::repeat_n(b'x', 64));
    oversized.push(b'\n');
    fs::write(big.marker("hardware-target"), oversized).unwrap();
    assert_refused(&big, &big.verify(), "candidate-marker");

    // No final LF: not one line plus LF.
    let bare = Case::golden("manifest-digest");
    fs::write(bare.marker("hardware-target"), b"nvidia-gb10-arm64").unwrap();
    assert_refused(&bare, &bare.verify(), "candidate-marker");

    // A FIFO must not hang the verifier.
    let fifo = Case::golden("manifest-digest");
    fs::remove_file(fifo.marker("access-policy")).unwrap();
    run_tool(&["mkfifo", fifo.marker("access-policy").to_str().unwrap()]);
    assert_refused(&fifo, &fifo.verify(), "candidate-marker");
}

#[test]
fn rule_14_candidate_key_must_be_the_sealed_key() {
    let case = Case::golden("manifest-digest");
    fs::write(
        case.marker("keys/release-authorization.pub"),
        b"-----BEGIN PUBLIC KEY-----\nother\n-----END PUBLIC KEY-----\n",
    )
    .unwrap();
    assert_refused(&case, &case.verify(), "candidate-key");
    let missing = Case::golden("manifest-digest");
    fs::remove_file(missing.marker("keys/release-authorization.pub")).unwrap();
    assert_refused(&missing, &missing.verify(), "candidate-key");
}

#[test]
fn rule_15_candidate_must_not_carry_the_v1_anchors() {
    let root_pub = Case::golden("manifest-digest");
    fs::create_dir_all(root_pub.path("root/etc/neural-ice/keys")).unwrap();
    fs::write(root_pub.path("root/etc/neural-ice/keys/ota-root.pub"), b"x").unwrap();
    assert_refused(&root_pub, &root_pub.verify(), "candidate-anchor");

    let bootstrap = Case::golden("manifest-digest");
    fs::create_dir_all(bootstrap.marker("ota-bootstrap")).unwrap();
    assert_refused(&bootstrap, &bootstrap.verify(), "candidate-anchor");

    // A dangling symlink is still an anchor entry.
    let dangling = Case::golden("manifest-digest");
    fs::create_dir_all(dangling.path("root/etc/neural-ice/keys")).unwrap();
    symlink(
        "/nonexistent",
        dangling.path("root/etc/neural-ice/keys/ota-root.pub"),
    )
    .unwrap();
    assert_refused(&dangling, &dangling.verify(), "candidate-anchor");
}

#[test]
fn rule_16_an_existing_receipt_must_be_byte_equal() {
    let case = Case::golden("manifest-digest");
    fs::write(case.receipt(), b"{}\n").unwrap();
    fs::set_permissions(case.receipt(), fs::Permissions::from_mode(0o600)).unwrap();
    let output = case.verify();
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("v2 release REFUSED: receipt-conflict:"),
        "{}",
        stderr(&output)
    );
    assert_eq!(fs::read(case.receipt()).unwrap(), b"{}\n");
    assert_eq!(fs::read_dir(case.path("out")).unwrap().count(), 1);

    // The other mode's receipt is a different receipt, even for the same pair.
    let floor = Case::golden("floor");
    assert_eq!(floor.verify().status.code(), Some(0));
    let mut digest = Case::golden("manifest-digest");
    digest.set("receipt", floor.receipt().to_str().unwrap());
    let output = digest.verify();
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(stderr(&output).contains("receipt-conflict"));
}

#[test]
fn the_receipt_directory_must_be_private() {
    let case = Case::golden("manifest-digest");
    fs::set_permissions(case.path("out"), fs::Permissions::from_mode(0o755)).unwrap();
    let output = case.verify();
    assert_ne!(output.status.code(), Some(0));
    assert!(output.stdout.is_empty());
    assert!(!case.receipt().exists());
}

/// Contract §2 orders the digest rules before `receipt-conflict`: a sealed key
/// or manifest that does not match is the refusal even when the receipt
/// directory is also unusable.
#[test]
fn the_digest_rules_precede_receipt_conflict() {
    let mut key = Case::golden("manifest-digest");
    fs::set_permissions(key.path("out"), fs::Permissions::from_mode(0o755)).unwrap();
    key.set("sealed-key-sha256", &"0".repeat(64));
    let output = key.verify();
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("v2 release REFUSED: key-digest:"),
        "{}",
        stderr(&output)
    );

    let mut manifest = Case::golden("manifest-digest");
    fs::set_permissions(manifest.path("out"), fs::Permissions::from_mode(0o755)).unwrap();
    manifest.set("sealed-manifest-sha256", &"1".repeat(64));
    let output = manifest.verify();
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("v2 release REFUSED: manifest-digest:"),
        "{}",
        stderr(&output)
    );

    // With every digest right, the unusable directory is the refusal.
    let good = Case::golden("manifest-digest");
    fs::set_permissions(good.path("out"), fs::Permissions::from_mode(0o755)).unwrap();
    let output = good.verify();
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("v2 release REFUSED: receipt-conflict:"),
        "{}",
        stderr(&output)
    );
    assert!(!good.receipt().exists());
}

// ---------------------------------------------------------------------------
// verify-retained-v2-release
// ---------------------------------------------------------------------------

struct Retained {
    case: Case,
    receipt_sha256: String,
}

impl Retained {
    /// Install: publish the golden receipt, then lay the persisted pair beside it.
    fn new(mode: &str) -> Self {
        let case = Case::golden(mode);
        let installed = case.verify();
        assert_eq!(installed.status.code(), Some(0), "{}", stderr(&installed));
        let receipt_sha256 = hex(&fs::read(case.receipt()).unwrap());
        private_dir(&case.path("scratch"));
        Retained {
            case,
            receipt_sha256,
        }
    }

    fn args(&self) -> Vec<(String, String)> {
        let path = |name: &str| self.case.path(name).to_string_lossy().into_owned();
        vec![
            ("manifest".into(), path("release-manifest.json")),
            ("manifest-sig".into(), path("release-manifest.json.sig")),
            (
                "release-key".into(),
                path("root/usr/lib/neural-ice/keys/release-authorization.pub"),
            ),
            (
                "expected-receipt-sha256".into(),
                self.receipt_sha256.clone(),
            ),
            ("receipt".into(), path("out/receipt.json")),
            ("scratch-dir".into(), path("scratch")),
            ("root".into(), path("root")),
        ]
    }

    fn run_with(&self, args: &[(String, String)]) -> Output {
        self.case
            .command("verify-retained-v2-release", args)
            .output()
            .unwrap()
    }

    fn run(&self) -> Output {
        self.run_with(&self.args())
    }

    fn assert_refused(&self, output: &Output, class: &str) {
        assert_eq!(output.status.code(), Some(1), "{}", stderr(output));
        assert!(output.stdout.is_empty());
        assert!(
            stderr(output).contains(&format!("ni-ota-verify: v2 release REFUSED: {class}:")),
            "expected `{class}`, got {}",
            stderr(output)
        );
        assert_eq!(
            fs::read_dir(self.case.path("scratch")).unwrap().count(),
            0,
            "scratch residue after a refusal"
        );
    }
}

#[test]
fn retained_passes_for_both_modes_and_leaves_no_residue() {
    for mode in ["manifest-digest", "floor"] {
        let retained = Retained::new(mode);
        let receipt_before = fs::read(retained.case.receipt()).unwrap();
        let output = retained.run();
        assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
        assert_eq!(
            String::from_utf8(output.stdout.clone()).unwrap(),
            format!(
                "{{\"bundle_seq\":3,\"receipt_sha256\":\"{}\",\"verdict\":\"pass\"}}\n",
                retained.receipt_sha256
            )
        );
        assert!(output.stderr.is_empty(), "{}", stderr(&output));
        assert_eq!(fs::read(retained.case.receipt()).unwrap(), receipt_before);
        assert_eq!(
            fs::read_dir(retained.case.path("scratch")).unwrap().count(),
            0
        );
        assert_eq!(fs::read_dir(retained.case.path("out")).unwrap().count(), 1);
    }
}

#[test]
fn retained_refuses_a_receipt_that_is_not_the_one_the_evidence_binds() {
    let retained = Retained::new("manifest-digest");
    let mut args = retained.args();
    args.iter_mut()
        .find(|(n, _)| n == "expected-receipt-sha256")
        .unwrap()
        .1 = "0".repeat(64);
    retained.assert_refused(&retained.run_with(&args), "receipt-digest");

    // The other mode's golden receipt is not the one the evidence binds.
    fs::copy(
        golden_dir().join("expected-receipt-floor.json"),
        retained.case.receipt(),
    )
    .unwrap();
    retained.assert_refused(&retained.run(), "receipt-digest");
}

#[test]
fn retained_refuses_a_malformed_receipt_even_when_its_digest_is_expected() {
    let tamper = |label: &str, rewrite: &dyn Fn(&str) -> String| {
        let retained = Retained::new("manifest-digest");
        let text = fs::read_to_string(retained.case.receipt()).unwrap();
        let bytes = rewrite(&text).into_bytes();
        fs::write(retained.case.receipt(), &bytes).unwrap();
        let mut args = retained.args();
        args.iter_mut()
            .find(|(n, _)| n == "expected-receipt-sha256")
            .unwrap()
            .1 = hex(&bytes);
        let output = retained.run_with(&args);
        assert_eq!(
            output.status.code(),
            Some(1),
            "{label}: {}",
            stderr(&output)
        );
        assert!(
            stderr(&output).contains("v2 release REFUSED: receipt-malformed:"),
            "{label}: {}",
            stderr(&output)
        );
    };
    tamper("unknown key", &|t| {
        t.replacen(
            "{\"access_profile\"",
            "{\"freshness_sha256\":\"00\",\"access_profile\"",
            1,
        )
    });
    tamper("reordered", &|t| {
        t.replacen(
            "\"access_profile\":\"lab-managed\",\"bundle_seq\":3",
            "\"bundle_seq\":3,\"access_profile\":\"lab-managed\"",
            1,
        )
    });
    tamper("no final LF", &|t| t.trim_end().to_string());
    tamper("pretty", &|t| {
        t.replace(",\"bundle_seq\"", ", \"bundle_seq\"")
    });
    tamper("float seq", &|t| {
        t.replace("\"bundle_seq\":3", "\"bundle_seq\":3.0")
    });
    tamper("seal mode swapped", &|t| {
        t.replace("\"mode\":\"manifest-digest\"", "\"mode\":\"floor\"")
    });
    tamper("not json", &|_| "garbage\n".to_string());
}

#[test]
fn retained_refuses_a_persisted_pair_that_differs_from_the_receipt() {
    let manifest = Retained::new("manifest-digest");
    let mut bytes = fs::read(manifest.case.path("release-manifest.json")).unwrap();
    bytes[10] ^= 0x01;
    fs::write(manifest.case.path("release-manifest.json"), bytes).unwrap();
    manifest.assert_refused(&manifest.run(), "manifest-digest");

    let sig = Retained::new("manifest-digest");
    let mut bytes = fs::read(sig.case.path("release-manifest.json.sig")).unwrap();
    bytes.push(b'\n');
    fs::write(sig.case.path("release-manifest.json.sig"), bytes).unwrap();
    sig.assert_refused(&sig.run(), "sig-digest");

    let key = Retained::new("manifest-digest");
    fs::write(
        key.case
            .path("root/usr/lib/neural-ice/keys/release-authorization.pub"),
        b"another key\n",
    )
    .unwrap();
    key.assert_refused(&key.run(), "key-digest");
}

#[test]
fn retained_rechecks_the_signature_not_only_the_digests() {
    // A persisted signature that is not the manifest's, with a receipt (and an
    // expected digest) that agree with it: only the signature check can refuse.
    let retained = Retained::new("floor");
    let junk = b"bm90IGEgc2lnbmF0dXJl";
    fs::write(retained.case.path("release-manifest.json.sig"), junk).unwrap();
    let genuine = retained.case.input("sealed_manifest_sig_sha256");
    let receipt = fs::read_to_string(retained.case.receipt()).unwrap();
    let forged = receipt.replace(&genuine, &hex(junk));
    assert_ne!(forged, receipt);
    fs::write(retained.case.receipt(), forged.as_bytes()).unwrap();
    let mut args = retained.args();
    args.iter_mut()
        .find(|(n, _)| n == "expected-receipt-sha256")
        .unwrap()
        .1 = hex(forged.as_bytes());
    retained.assert_refused(&retained.run_with(&args), "signature");
}

#[test]
fn retained_refuses_a_live_root_that_no_longer_matches_the_receipt() {
    for (label, class) in [
        ("hardware-target", "candidate-marker"),
        ("appliance-variant", "candidate-marker"),
        ("signed-boot-trust-policy-id", "candidate-marker"),
        ("access-policy", "candidate-marker"),
        ("ota-state-profile", "candidate-marker"),
    ] {
        let retained = Retained::new("manifest-digest");
        fs::write(retained.case.marker(label), b"drifted\n").unwrap();
        retained.assert_refused(&retained.run(), class);
    }
    let anchor = Retained::new("manifest-digest");
    fs::create_dir_all(anchor.case.path("root/etc/neural-ice/keys")).unwrap();
    fs::write(
        anchor.case.path("root/etc/neural-ice/keys/ota-root.pub"),
        b"x",
    )
    .unwrap();
    anchor.assert_refused(&anchor.run(), "candidate-anchor");
    let bootstrap = Retained::new("manifest-digest");
    fs::create_dir_all(bootstrap.case.marker("ota-bootstrap")).unwrap();
    bootstrap.assert_refused(&bootstrap.run(), "candidate-anchor");
}

#[test]
fn retained_usage_errors_are_exit_2() {
    let retained = Retained::new("manifest-digest");
    let mut missing = retained.args();
    missing.retain(|(name, _)| name != "scratch-dir");
    assert_eq!(retained.run_with(&missing).status.code(), Some(2));
    let mut unknown = retained.args();
    unknown.push(("sealed-key-sha256".into(), "00".into()));
    assert_eq!(retained.run_with(&unknown).status.code(), Some(2));
}

/// The shipped binary has no `--root`: the live root is `/`.
#[test]
fn the_root_flag_is_a_test_seam_only() {
    let source =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/v2_release.rs"))
            .expect("src/v2_release.rs");
    let root_uses: Vec<&str> = source
        .lines()
        .filter(|line| line.contains("\"root\""))
        .collect();
    assert!(!root_uses.is_empty());
    assert!(
        source.contains("#[cfg(feature = \"test-path-overrides\")]"),
        "the --root seam must be feature-gated"
    );
}
