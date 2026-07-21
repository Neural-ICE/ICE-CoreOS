//! End-to-end CLI tests against the built binary. No real cosign and no
//! signing infrastructure needed: `NI_OTA_COSIGN` injects a stub script whose
//! verdict is driven by the CONTENT of the signature file (`GOOD` accepts a
//! fixture; `SHA256:<digest>` binds it to the exact blob), so every §0 check is
//! exercised through the real subprocess plumbing.
#![cfg(all(unix, feature = "test-path-overrides"))]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_ni-ota-verify");
const TEST_OS_DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const TEST_OS_REF: &str = "registry.neural-ice.ch/neural-ice/neural-ice-appliance@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const TEST_SEED_REF: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const TEST_BUNDLE_DIGEST: &str =
    "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

const COSIGN_STUB: &str = r#"#!/bin/sh
# Test stub for `cosign verify-blob` (see tests/cli.rs): a signature file
# starting with GOOD verifies. SHA256:<digest> verifies only if the blob hash
# matches, allowing the bootstrap tests to exercise post-signature tampering.
sig=""
blob=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --signature) sig="$2"; shift 2 ;;
    --key) shift 2 ;;
    --*) shift 1 ;;
    verify-blob) shift 1 ;;
    *) blob="$1"; shift 1 ;;
  esac
done
[ -n "$sig" ] || { echo "stub: no --signature flag" >&2; exit 2; }
if grep -qx 'MAYCAQECAQE=' "$sig" 2>/dev/null; then
  message_hex="$(od -An -tx1 -v "$blob" | tr -d ' \n')" || exit 2
  case "$message_hex" in
    6e657572616c2d6963653a6f74613a64656c65676174696f6e2d736e617073686f743a763100*|\
    6e657572616c2d6963653a6f74613a72656c656173652d617574686f72697a6174696f6e3a763100*|\
    6e657572616c2d6963653a6f74613a626574612d7075626c69636174696f6e2d726563656970743a763100*) ;;
    *) echo "stub: missing delegated signature domain" >&2; exit 1 ;;
  esac
elif ! grep -q '^GOOD' "$sig" 2>/dev/null; then
  expected="$(sed -n 's/^SHA256://p' "$sig")"
  [ -n "$expected" ] && [ -n "$blob" ] || { echo "stub: signature rejected" >&2; exit 1; }
  actual="$(sha256sum "$blob" | awk '{print $1}')" || exit 2
  [ "$actual" = "$expected" ] || { echo "stub: signature rejected" >&2; exit 1; }
fi
if [ -n "${NI_OTA_TEST_MUTATE_SOURCE:-}" ]; then
  cp "$NI_OTA_TEST_MUTATION" "$NI_OTA_TEST_MUTATE_SOURCE" || exit 2
fi
[ -z "${NI_OTA_TEST_COSIGN_READY:-}" ] || printf 'ready\n' > "$NI_OTA_TEST_COSIGN_READY"
[ -z "${NI_OTA_TEST_COSIGN_DELAY:-}" ] || sleep "$NI_OTA_TEST_COSIGN_DELAY"
exit 0
"#;

struct Fixture {
    dir: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Self {
        let dir = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!("ni-ota-verify-cli-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("state")).unwrap();
        fs::set_permissions(dir.join("state"), fs::Permissions::from_mode(0o700)).unwrap();
        let stub = dir.join("cosign-stub.sh");
        fs::write(&stub, COSIGN_STUB).unwrap();
        fs::set_permissions(&stub, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(
            dir.join("ota-root.pub"),
            "-----BEGIN TEST PUBLIC KEY-----\n",
        )
        .unwrap();
        fs::write(dir.join("hardware-target"), "nvidia-gb10-arm64\n").unwrap();
        fs::write(dir.join("appliance-variant"), "prod\n").unwrap();
        fs::write(dir.join("min-delegation-seq"), "1\n").unwrap();
        Fixture { dir }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    fn write_config(&self, enforce: u8, extra: &str) -> PathBuf {
        self.write_config_with_state(enforce, &self.path("state"), extra)
    }

    fn write_config_with_state(&self, enforce: u8, state_dir: &Path, extra: &str) -> PathBuf {
        let path = self.path("ota.conf");
        fs::write(
            &path,
            format!(
                "# test ota.conf\nenforce={enforce}\nregistry=registry.neural-ice.ch\n\
                 root_pubkey={}\nstate_dir={}\n{extra}",
                self.path("ota-root.pub").display(),
                state_dir.display()
            ),
        )
        .unwrap();
        path
    }

    fn write_bom(&self, train: &str, seq: u64) -> PathBuf {
        // Shape of a real BOM-core: the lockfile minus `status` — extra fields
        // must ride along ignored.
        let path = self.path("bom.json");
        fs::write(
            &path,
            format!(
                r#"{{"appliance":{{"images":{{"icecore":{{"digest":"reg/x@sha256:aa"}}}},"os_base":{{"digest":"sha256:{TEST_OS_DIGEST}","image":"registry.neural-ice.ch/neural-ice/neural-ice-appliance"}},"raw_sha256":"bb","version":"{train}"}},"bundle_seq":{seq},"compat_min":1,"compat_version":3,"created":"2026-07-11T00:00:00Z","hardware_target":"nvidia-gb10-arm64","key_version":1,"sources":{{"seed":{{"ref":"{TEST_SEED_REF}","repo":"ICE-Fabric"}}}},"train":"{train}"}}"#
            ),
        )
        .unwrap();
        path
    }

    fn write_record(&self, train: &str, channel: &str, seq: u64) -> PathBuf {
        let path = self.path("record.json");
        fs::write(
            &path,
            format!(
                r#"{{"assigned_at":"2026-07-11T00:00:00Z","bundle_digest":"{TEST_BUNDLE_DIGEST}","bundle_seq":{seq},"channel":"{channel}","hardware_target":"nvidia-gb10-arm64","key_version":1,"schema_version":2,"train":"{train}"}}"#
            ),
        )
        .unwrap();
        path
    }

    fn write_sig(&self, name: &str, good: bool) -> PathBuf {
        let path = self.path(name);
        fs::write(
            &path,
            if good {
                "GOOD-detached-signature\n"
            } else {
                "BAD-detached-signature\n"
            },
        )
        .unwrap();
        path
    }

    fn write_bound_sig(&self, name: &str, blob: &Path) -> PathBuf {
        let path = self.path(name);
        fs::write(&path, format!("SHA256:{}\n", sha256_of(blob))).unwrap();
        path
    }

    fn seed_applied(&self, seq: u64, sha: &str) {
        let path = self.path("state/applied.json");
        fs::write(
            &path,
            format!(r#"{{"bundle_seq":{seq},"bom_sha256":"{sha}"}}"#),
        )
        .unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    /// 4-file verify invocation WITHOUT device identity flags.
    fn verify_cmd_bare(&self, config: &Path) -> Command {
        self.verify_cmd_bare_with_digest(config, TEST_BUNDLE_DIGEST)
    }

    fn verify_cmd_bare_with_digest(&self, config: &Path, bundle_digest: &str) -> Command {
        let mut cmd = Command::new(BIN);
        cmd.env("NI_OTA_COSIGN", self.path("cosign-stub.sh"))
            .env("NI_OTA_HARDWARE_TARGET_FILE", self.path("hardware-target"))
            .arg("verify")
            .args(["--bom".as_ref(), self.path("bom.json").as_os_str()])
            .args(["--bom-sig".as_ref(), self.path("bom.sig").as_os_str()])
            .args(["--record".as_ref(), self.path("record.json").as_os_str()])
            .args(["--record-sig".as_ref(), self.path("record.sig").as_os_str()])
            .args(["--bundle-digest", bundle_digest])
            .args(["--config".as_ref(), config.as_os_str()]);
        cmd
    }

    /// Standard verify invocation with concrete device identity.
    fn verify_cmd(&self, config: &Path) -> Command {
        let mut cmd = self.verify_cmd_bare(config);
        cmd.args(["--device-channel", "stable"])
            .args(["--device-compat", "1,3"]);
        cmd
    }

    fn bootstrap_cmd(&self, config: &Path, bom: &Path, signature: &Path) -> Command {
        let mut cmd = Command::new(BIN);
        cmd.env("NI_OTA_COSIGN", self.path("cosign-stub.sh"))
            .env("NI_OTA_HARDWARE_TARGET_FILE", self.path("hardware-target"))
            .arg("bootstrap")
            .args(["--bom".as_ref(), bom.as_os_str()])
            .args(["--bom-sig".as_ref(), signature.as_os_str()])
            .args(["--expected-train", "0.44.18"])
            .args(["--current-os-ref", TEST_OS_REF])
            .args(["--current-seed-ref", TEST_SEED_REF])
            .args(["--config".as_ref(), config.as_os_str()])
            .args(["--device-compat", "1,3"]);
        cmd
    }

    /// Happy-path fixture set: signed record+BOM for train 0.44.7 / seq 7 on
    /// channel stable, device already at seq 3.
    fn arrange_happy(&self) {
        self.write_bom("0.44.7", 7);
        self.write_record("0.44.7", "stable", 7);
        self.write_sig("bom.sig", true);
        self.write_sig("record.sig", true);
        self.seed_applied(3, &"c".repeat(64));
    }
}

fn intermediate_symlink_state_parent(fx: &Fixture) -> (PathBuf, PathBuf) {
    let outside = fx.path("outside-tree");
    let target = outside.join("state");
    fs::create_dir(&outside).unwrap();
    fs::create_dir(&target).unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
    let link = fx.path("state-prefix-link");
    std::os::unix::fs::symlink(&outside, &link).unwrap();
    (link.join("state"), target)
}

fn run(cmd: &mut Command) -> (i32, Value, String) {
    let out = cmd.output().expect("binary runs");
    let code = out.status.code().expect("exit code");
    let stdout = String::from_utf8(out.stdout).unwrap();
    let verdict = stdout.lines().next().map_or(Value::Null, |line| {
        serde_json::from_str(line).expect("stdout line 1 is the JSON verdict")
    });
    (
        code,
        verdict,
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn check<'v>(verdict: &'v Value, name: &str) -> &'v Value {
    verdict["checks"]
        .as_array()
        .expect("checks array")
        .iter()
        .find(|c| c["name"] == name)
        .unwrap_or_else(|| panic!("check '{name}' missing from {verdict}"))
}

fn sha256_of(path: &Path) -> String {
    let out = Command::new("sha256sum").arg(path).output().unwrap();
    String::from_utf8(out.stdout)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .to_string()
}

fn wait_for_path(path: &Path) {
    // The full CLI suite runs many subprocess-heavy tests in parallel on
    // self-hosted runners. Keep this bounded while allowing scheduling jitter.
    for _ in 0..1000 {
        if path.exists() {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("timed out waiting for test barrier {}", path.display());
}

// --- verify: happy paths -----------------------------------------------------

#[test]
fn happy_path_passes_in_both_modes() {
    for (mode, enforce) in [("shadow", 0), ("enforce", 1)] {
        let fx = Fixture::new(&format!("happy-{mode}"));
        fx.arrange_happy();
        let cfg = fx.write_config(enforce, "");
        let (code, verdict, _) = run(&mut fx.verify_cmd(&cfg));
        assert_eq!(code, 0, "{mode}: {verdict}");
        assert_eq!(verdict["verdict"], "pass");
        assert_eq!(verdict["enforce"], enforce == 1);
        for name in [
            "record_sig",
            "bom_sig",
            "record_parse",
            "bom_parse",
            "bundle_digest",
            "train_match",
            "seq_match",
            "target_binding",
            "channel_match",
            "hardware_target",
            "anti_rollback",
            "compat_overlap",
        ] {
            assert_eq!(check(&verdict, name)["ok"], true, "{mode}: check {name}");
        }
    }
}

#[test]
fn signed_bundle_digest_blocks_registry_retag() {
    for enforce in [0, 1] {
        let fx = Fixture::new(&format!("bundle-retag-{enforce}"));
        fx.arrange_happy();
        let cfg = fx.write_config(enforce, "");
        let observed = "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
        let mut command = fx.verify_cmd_bare_with_digest(&cfg, observed);
        command
            .args(["--device-channel", "stable"])
            .args(["--device-compat", "1,3"]);

        let (code, verdict, _) = run(&mut command);
        assert_eq!(code, 1, "enforce={enforce}: {verdict}");
        assert_eq!(verdict["verdict"], "refuse");
        assert_eq!(check(&verdict, "record_sig")["ok"], true);
        assert_eq!(check(&verdict, "bundle_digest")["ok"], false);
        assert!(check(&verdict, "bundle_digest")["detail"]
            .as_str()
            .unwrap()
            .contains("possible tag retarget"));
    }
}

#[test]
fn channel_record_v1_missing_or_noncanonical_bundle_digest_refuses() {
    for enforce in [0, 1] {
        for name in [
            "schema-v1",
            "uppercase-digest",
            "missing-digest",
            "extra-key",
        ] {
            let fx = Fixture::new(&format!("{name}-{enforce}"));
            fx.arrange_happy();
            let mut record: Value =
                serde_json::from_str(&fs::read_to_string(fx.path("record.json")).unwrap()).unwrap();
            match name {
                "schema-v1" => record["schema_version"] = Value::from(1_u64),
                "uppercase-digest" => {
                    record["bundle_digest"] = Value::String(TEST_BUNDLE_DIGEST.to_uppercase())
                }
                "missing-digest" => {
                    record.as_object_mut().unwrap().remove("bundle_digest");
                }
                "extra-key" => record["unexpected"] = Value::Bool(true),
                _ => unreachable!(),
            }
            fs::write(fx.path("record.json"), serde_json::to_vec(&record).unwrap()).unwrap();
            let cfg = fx.write_config(enforce, "");
            let (code, verdict, _) = run(&mut fx.verify_cmd(&cfg));
            assert_eq!(code, 1, "{name} enforce={enforce}: {verdict}");
            assert_eq!(check(&verdict, "record_parse")["ok"], false);
        }
    }
}

// --- verify: each §0 check fails with its own code -----------------------------

#[test]
fn bad_record_signature_refuses_in_every_mode() {
    for enforce in [0, 1] {
        let fx = Fixture::new(&format!("recsig-{enforce}"));
        fx.arrange_happy();
        fx.write_sig("record.sig", false);
        let cfg = fx.write_config(enforce, "");
        let (code, verdict, _) = run(&mut fx.verify_cmd(&cfg));
        assert_eq!(code, 1);
        assert_eq!(verdict["verdict"], "refuse");
        assert_eq!(check(&verdict, "record_sig")["ok"], false);
        assert_eq!(
            check(&verdict, "bom_sig")["ok"],
            true,
            "later checks still run"
        );
    }
}

#[test]
fn bad_bom_signature_refuses() {
    for enforce in [0, 1] {
        let fx = Fixture::new(&format!("bomsig-{enforce}"));
        fx.arrange_happy();
        fx.write_sig("bom.sig", false);
        let cfg = fx.write_config(enforce, "");
        let (code, verdict, _) = run(&mut fx.verify_cmd(&cfg));
        assert_eq!(code, 1);
        assert_eq!(check(&verdict, "record_sig")["ok"], true);
        assert_eq!(check(&verdict, "bom_sig")["ok"], false);
    }
}

#[test]
fn malformed_bom_and_signed_bindings_never_shadow_pass() {
    let malformed = Fixture::new("shadow-malformed-bom");
    malformed.arrange_happy();
    fs::write(malformed.path("bom.json"), "{\"train\":").unwrap();
    let cfg = malformed.write_config(0, "");
    let (code, verdict, _) = run(&mut malformed.verify_cmd(&cfg));
    assert_eq!(code, 1, "{verdict}");
    assert_eq!(check(&verdict, "bom_parse")["ok"], false);

    for (name, train, seq, channel) in [
        ("train", "0.44.6", 7, "stable"),
        ("seq", "0.44.7", 8, "stable"),
        ("channel", "0.44.7", 7, "beta"),
    ] {
        let fx = Fixture::new(&format!("shadow-binding-{name}"));
        fx.arrange_happy();
        fx.write_record(train, channel, seq);
        let cfg = fx.write_config(0, "");
        let (code, verdict, _) = run(&mut fx.verify_cmd(&cfg));
        assert_eq!(code, 1, "{name}: {verdict}");
    }

    let target = Fixture::new("shadow-target-binding");
    target.arrange_happy();
    let mut record: Value =
        serde_json::from_str(&fs::read_to_string(target.path("record.json")).unwrap()).unwrap();
    record["hardware_target"] = Value::String("nvidia-cuda-x86_64".to_string());
    fs::write(
        target.path("record.json"),
        serde_json::to_vec(&record).unwrap(),
    )
    .unwrap();
    let cfg = target.write_config(0, "");
    let (code, verdict, _) = run(&mut target.verify_cmd(&cfg));
    assert_eq!(code, 1, "{verdict}");
    assert_eq!(check(&verdict, "target_binding")["ok"], false);
    assert_eq!(check(&verdict, "hardware_target")["ok"], false);

    let rollback = Fixture::new("shadow-rollback");
    rollback.arrange_happy();
    rollback.seed_applied(9, &"c".repeat(64));
    let cfg = rollback.write_config(0, "");
    let (code, verdict, _) = run(&mut rollback.verify_cmd(&cfg));
    assert_eq!(code, 1, "{verdict}");
    assert_eq!(check(&verdict, "anti_rollback")["ok"], false);
}

#[test]
fn compatibility_remains_a_shadow_only_rollout_check() {
    let fx = Fixture::new("shadow-compat");
    fx.arrange_happy();
    let cfg = fx.write_config(0, "");
    let mut command = fx.verify_cmd_bare(&cfg);
    command
        .args(["--device-channel", "stable"])
        .args(["--device-compat", "4,5"]);
    let (code, verdict, _) = run(&mut command);
    assert_eq!(code, 0, "{verdict}");
    assert_eq!(verdict["verdict"], "refuse");
    assert_eq!(check(&verdict, "compat_overlap")["ok"], false);
}

#[test]
fn train_mismatch_refuses() {
    let fx = Fixture::new("train");
    fx.arrange_happy();
    fx.write_record("0.44.6", "stable", 7);
    let cfg = fx.write_config(1, "");
    let (code, verdict, _) = run(&mut fx.verify_cmd(&cfg));
    assert_eq!(code, 1);
    assert_eq!(check(&verdict, "train_match")["ok"], false);
    assert_eq!(check(&verdict, "seq_match")["ok"], true);
}

#[test]
fn seq_mismatch_refuses() {
    let fx = Fixture::new("seq");
    fx.arrange_happy();
    fx.write_record("0.44.7", "stable", 8);
    let cfg = fx.write_config(1, "");
    let (code, verdict, _) = run(&mut fx.verify_cmd(&cfg));
    assert_eq!(code, 1);
    assert_eq!(check(&verdict, "seq_match")["ok"], false);
}

#[test]
fn channel_mismatch_refuses() {
    let fx = Fixture::new("channel");
    fx.arrange_happy();
    fx.write_record("0.44.7", "beta", 7);
    let cfg = fx.write_config(1, "");
    let (code, verdict, _) = run(&mut fx.verify_cmd(&cfg));
    assert_eq!(code, 1);
    let c = check(&verdict, "channel_match");
    assert_eq!(c["ok"], false);
    assert!(c["detail"].as_str().unwrap().contains("beta"));
}

#[test]
fn hardware_target_mismatch_refuses() {
    let fx = Fixture::new("hardware-target");
    fx.arrange_happy();
    fs::write(
        fx.path("record.json"),
        format!(r#"{{"assigned_at":"2026-07-11T00:00:00Z","bundle_digest":"{TEST_BUNDLE_DIGEST}","bundle_seq":7,"channel":"stable","hardware_target":"nvidia-cuda-x86_64","key_version":1,"schema_version":2,"train":"0.44.7"}}"#),
    )
    .unwrap();
    let cfg = fx.write_config(1, "");
    let (code, verdict, _) = run(&mut fx.verify_cmd(&cfg));
    assert_eq!(code, 1);
    assert_eq!(check(&verdict, "target_binding")["ok"], false);
    assert_eq!(check(&verdict, "hardware_target")["ok"], false);
}

#[test]
fn rollback_refused() {
    let fx = Fixture::new("rollback");
    fx.arrange_happy();
    fx.seed_applied(9, &"c".repeat(64)); // device already past seq 7
    let cfg = fx.write_config(1, "");
    let (code, verdict, _) = run(&mut fx.verify_cmd(&cfg));
    assert_eq!(code, 1);
    let c = check(&verdict, "anti_rollback");
    assert_eq!(c["ok"], false);
    assert!(c["detail"].as_str().unwrap().contains("ROLLBACK"));
}

#[test]
fn repair_carveout_equal_seq_same_hash_passes() {
    let fx = Fixture::new("repair");
    fx.arrange_happy();
    fx.seed_applied(7, &sha256_of(&fx.path("bom.json")));
    let cfg = fx.write_config(1, "");
    let (code, verdict, _) = run(&mut fx.verify_cmd(&cfg));
    assert_eq!(code, 0, "{verdict}");
    assert_eq!(verdict["verdict"], "pass");
    assert!(check(&verdict, "anti_rollback")["detail"]
        .as_str()
        .unwrap()
        .contains("repair"));
}

#[test]
fn equal_seq_different_hash_refused_as_forgery_signal() {
    let fx = Fixture::new("forgery");
    fx.arrange_happy();
    fx.seed_applied(7, &"d".repeat(64));
    let cfg = fx.write_config(1, "");
    let (code, verdict, _) = run(&mut fx.verify_cmd(&cfg));
    assert_eq!(code, 1);
    assert!(check(&verdict, "anti_rollback")["detail"]
        .as_str()
        .unwrap()
        .contains("forgery"));
}

#[test]
fn compat_no_overlap_refused() {
    // device only supports 4..5, BOM covers 1..3 → no overlap
    let fx = Fixture::new("compat");
    fx.arrange_happy();
    let cfg = fx.write_config(1, "");
    let mut cmd = fx.verify_cmd_bare(&cfg);
    cmd.args(["--device-channel", "stable"])
        .args(["--device-compat", "4,5"]);
    let (code, verdict, _) = run(&mut cmd);
    assert_eq!(code, 1);
    assert_eq!(check(&verdict, "compat_overlap")["ok"], false);
}

#[test]
fn compat_range_from_config_is_honored() {
    let fx = Fixture::new("compat-cfg");
    fx.arrange_happy();
    let cfg = fx.write_config(1, "device_compat_min=4\ndevice_compat_max=5\n");
    let mut cmd = fx.verify_cmd_bare(&cfg);
    cmd.args(["--device-channel", "stable"]);
    let (code, verdict, _) = run(&mut cmd);
    assert_eq!(code, 1);
    assert_eq!(check(&verdict, "compat_overlap")["ok"], false);
}

#[test]
fn duplicate_flags_abort_as_internal_error() {
    let fx = Fixture::new("dupflag");
    fx.arrange_happy();
    let cfg = fx.write_config(0, "");
    let mut cmd = fx.verify_cmd(&cfg);
    cmd.args(["--device-compat", "4,5"]); // second --device-compat
    let (code, verdict, stderr) = run(&mut cmd);
    assert_eq!(code, 2, "{verdict}");
    assert!(stderr.contains("given twice"));
}

#[test]
fn unknown_device_inputs_warn_in_shadow_refuse_in_enforce() {
    for (enforce, want_code, want_verdict) in [(0, 0, "pass"), (1, 1, "refuse")] {
        let fx = Fixture::new(&format!("unknown-device-{enforce}"));
        fx.arrange_happy();
        let cfg = fx.write_config(enforce, "");
        // no --device-channel, no --device-compat, none in config either
        let (code, verdict, _) = run(&mut fx.verify_cmd_bare(&cfg));
        assert_eq!(code, want_code, "{verdict}");
        assert_eq!(verdict["verdict"], want_verdict);
        let ch = check(&verdict, "channel_match");
        let co = check(&verdict, "compat_overlap");
        if enforce == 0 {
            assert!(ch["detail"].as_str().unwrap().contains("WARNING"));
            assert!(co["detail"].as_str().unwrap().contains("WARNING"));
        } else {
            assert_eq!(ch["ok"], false);
            assert_eq!(co["ok"], false);
        }
    }
}

// --- verify: state edge cases --------------------------------------------------

#[test]
fn unseeded_state_shadow_passes_with_warning_enforce_refuses() {
    for (enforce, want_code, want_verdict, want_ok) in
        [(0, 0, "pass", true), (1, 1, "refuse", false)]
    {
        let fx = Fixture::new(&format!("unseeded-{enforce}"));
        fx.arrange_happy();
        fs::remove_file(fx.path("state/applied.json")).unwrap();
        let cfg = fx.write_config(enforce, "");
        let (code, verdict, _) = run(&mut fx.verify_cmd(&cfg));
        assert_eq!(code, want_code, "{verdict}");
        assert_eq!(verdict["verdict"], want_verdict);
        let c = check(&verdict, "unseeded");
        assert_eq!(c["ok"], want_ok);
    }
}

#[test]
fn corrupt_applied_state_fails_closed() {
    let fx = Fixture::new("corrupt-state");
    fx.arrange_happy();
    fs::write(fx.path("state/applied.json"), "{not json").unwrap();
    let cfg = fx.write_config(1, "");
    let (code, verdict, _) = run(&mut fx.verify_cmd(&cfg));
    assert_eq!(code, 1);
    assert_eq!(check(&verdict, "anti_rollback")["ok"], false);
}

// --- verify: malformed artifacts ------------------------------------------------

#[test]
fn malformed_bom_and_record_json_refuse() {
    let fx = Fixture::new("malformed");
    fx.arrange_happy();
    fs::write(fx.path("bom.json"), "{\"train\": ").unwrap();
    fs::write(fx.path("record.json"), "not json at all").unwrap();
    let cfg = fx.write_config(1, "");
    let (code, verdict, _) = run(&mut fx.verify_cmd(&cfg));
    assert_eq!(code, 1);
    assert_eq!(verdict["verdict"], "refuse");
    assert_eq!(check(&verdict, "bom_parse")["ok"], false);
    assert_eq!(check(&verdict, "record_parse")["ok"], false);
}

#[test]
fn missing_pubkey_fails_signature_checks_not_internally() {
    let fx = Fixture::new("nopubkey");
    fx.arrange_happy();
    fs::remove_file(fx.path("ota-root.pub")).unwrap();
    let cfg = fx.write_config(0, "");
    let (code, verdict, _) = run(&mut fx.verify_cmd(&cfg));
    assert_eq!(code, 1, "signature authority refuses in shadow: {verdict}");
    assert_eq!(verdict["verdict"], "refuse");
    assert_eq!(check(&verdict, "record_sig")["ok"], false);
    assert_eq!(check(&verdict, "bom_sig")["ok"], false);
}

// --- internal errors: ALWAYS nonzero, in every mode ------------------------------

#[test]
fn missing_cosign_is_an_internal_error_even_in_shadow() {
    let fx = Fixture::new("nocosign");
    fx.arrange_happy();
    let cfg = fx.write_config(0, "");
    let mut cmd = fx.verify_cmd(&cfg);
    cmd.env("NI_OTA_COSIGN", "/nonexistent/cosign");
    let (code, verdict, stderr) = run(&mut cmd);
    assert_eq!(code, 2);
    assert_eq!(verdict, Value::Null, "no verdict on internal error");
    assert!(stderr.contains("cosign not found"));
}

#[test]
fn unreadable_config_is_an_internal_error() {
    let fx = Fixture::new("noconfig");
    fx.arrange_happy();
    let mut cmd = fx.verify_cmd(&fx.path("does-not-exist.conf"));
    let (code, verdict, stderr) = run(&mut cmd);
    assert_eq!(code, 2);
    assert_eq!(verdict, Value::Null);
    assert!(stderr.contains("unreadable config"));
}

#[test]
fn missing_immutable_hardware_target_is_an_internal_error() {
    let fx = Fixture::new("no-hardware-target");
    fx.arrange_happy();
    fs::remove_file(fx.path("hardware-target")).unwrap();
    let cfg = fx.write_config(1, "");
    let (code, verdict, stderr) = run(&mut fx.verify_cmd(&cfg));
    assert_eq!(code, 2);
    assert_eq!(verdict, Value::Null);
    assert!(stderr.contains("unreadable immutable hardware target"));
}

// --- bootstrap ---------------------------------------------------------------

#[test]
fn bootstrap_creates_absent_baseline_and_exact_retry_is_idempotent() {
    let fx = Fixture::new("bootstrap-idempotent");
    let bom = fx.write_bom("0.44.18", 4);
    let sig = fx.write_bound_sig("bom.sig", &bom);
    let cfg = fx.write_config(0, "");

    let (code, receipt, stderr) = run(&mut fx.bootstrap_cmd(&cfg, &bom, &sig));
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(receipt["bootstrapped"], true);
    assert_eq!(receipt["idempotent"], false);
    assert_eq!(receipt["train"], "0.44.18");
    assert_eq!(receipt["bundle_seq"], 4);
    assert_eq!(receipt["hardware_target"], "nvidia-gb10-arm64");
    assert_eq!(receipt["os_ref"], TEST_OS_REF);
    assert_eq!(receipt["seed_ref"], TEST_SEED_REF);
    assert_eq!(receipt["bom_sha256"], sha256_of(&bom));

    let applied: Value =
        serde_json::from_str(&fs::read_to_string(fx.path("state/applied.json")).unwrap()).unwrap();
    assert_eq!(applied["bundle_seq"], 4);
    assert_eq!(applied["bom_sha256"], sha256_of(&bom));
    assert_eq!(
        fs::metadata(fx.path("state/applied.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o600
    );

    // Models a retry after the atomic state create succeeded but the original
    // caller crashed before observing the receipt.
    let (code, receipt, stderr) = run(&mut fx.bootstrap_cmd(&cfg, &bom, &sig));
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(receipt["idempotent"], true);
}

#[test]
fn bootstrap_rejects_bad_or_post_signature_tampered_bom_even_in_shadow_config() {
    let bad_sig = Fixture::new("bootstrap-bad-signature");
    let bom = bad_sig.write_bom("0.44.18", 4);
    let sig = bad_sig.write_sig("bom.sig", false);
    let cfg = bad_sig.write_config(0, "");
    let (code, _, stderr) = run(&mut bad_sig.bootstrap_cmd(&cfg, &bom, &sig));
    assert_eq!(code, 1, "{stderr}");
    assert!(stderr.contains("BOM signature rejected"));
    assert!(!bad_sig.path("state/applied.json").exists());

    let tampered = Fixture::new("bootstrap-tampered-bom");
    let bom = tampered.write_bom("0.44.18", 4);
    let sig = tampered.write_bound_sig("bom.sig", &bom);
    fs::write(&bom, fs::read_to_string(&bom).unwrap() + "\n").unwrap();
    let cfg = tampered.write_config(0, "");
    let (code, _, stderr) = run(&mut tampered.bootstrap_cmd(&cfg, &bom, &sig));
    assert_eq!(code, 1, "{stderr}");
    assert!(stderr.contains("BOM signature rejected"));
    assert!(!tampered.path("state/applied.json").exists());
}

#[test]
fn bootstrap_uses_one_protected_snapshot_when_source_mutates_during_cosign() {
    let fx = Fixture::new("bootstrap-source-race");
    let bom = fx.write_bom("0.44.18", 4);
    let signed_hash = sha256_of(&bom);
    let sig = fx.write_bound_sig("bom.sig", &bom);
    let mutation = fx.path("unsigned-mutation.json");
    let mut value: Value = serde_json::from_str(&fs::read_to_string(&bom).unwrap()).unwrap();
    value["bundle_seq"] = Value::from(999_u64);
    fs::write(&mutation, serde_json::to_vec(&value).unwrap()).unwrap();
    let cfg = fx.write_config(0, "");
    let mut cmd = fx.bootstrap_cmd(&cfg, &bom, &sig);
    cmd.env("NI_OTA_TEST_MUTATE_SOURCE", &bom)
        .env("NI_OTA_TEST_MUTATION", &mutation);

    let (code, receipt, stderr) = run(&mut cmd);
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(receipt["bundle_seq"], 4);
    assert_eq!(receipt["bom_sha256"], signed_hash);
    let applied: Value =
        serde_json::from_str(&fs::read_to_string(fx.path("state/applied.json")).unwrap()).unwrap();
    assert_eq!(applied["bundle_seq"], 4);
    assert_eq!(applied["bom_sha256"], signed_hash);
    let source: Value = serde_json::from_str(&fs::read_to_string(&bom).unwrap()).unwrap();
    assert_eq!(source["bundle_seq"], 999, "source mutation did run");
    let mut entries: Vec<_> = fs::read_dir(fx.path("state"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    entries.sort();
    assert_eq!(
        entries,
        [".applied.json.lock", "applied.json"],
        "snapshot cleanup leaves only durable state and its kernel-lock inode"
    );
}

#[test]
fn bootstrap_rejects_wrong_hardware_target_and_incompatible_bom() {
    let target = Fixture::new("bootstrap-target");
    let bom = target.write_bom("0.44.18", 4);
    let mut value: Value = serde_json::from_str(&fs::read_to_string(&bom).unwrap()).unwrap();
    value["hardware_target"] = Value::String("nvidia-cuda-x86_64".to_string());
    fs::write(&bom, serde_json::to_vec(&value).unwrap()).unwrap();
    let sig = target.write_sig("bom.sig", true);
    let cfg = target.write_config(1, "");
    let (code, _, stderr) = run(&mut target.bootstrap_cmd(&cfg, &bom, &sig));
    assert_eq!(code, 1, "{stderr}");
    assert!(stderr.contains("does not match immutable host target"));
    assert!(!target.path("state/applied.json").exists());

    let compat = Fixture::new("bootstrap-compat");
    let bom = compat.write_bom("0.44.18", 4);
    let sig = compat.write_sig("bom.sig", true);
    let cfg = compat.write_config(1, "");
    let mut cmd = Command::new(BIN);
    cmd.env("NI_OTA_COSIGN", compat.path("cosign-stub.sh"))
        .env(
            "NI_OTA_HARDWARE_TARGET_FILE",
            compat.path("hardware-target"),
        )
        .arg("bootstrap")
        .args(["--bom".as_ref(), bom.as_os_str()])
        .args(["--bom-sig".as_ref(), sig.as_os_str()])
        .args(["--expected-train", "0.44.18"])
        .args(["--current-os-ref", TEST_OS_REF])
        .args(["--current-seed-ref", TEST_SEED_REF])
        .args(["--config".as_ref(), cfg.as_os_str()])
        .args(["--device-compat", "4,5"]);
    let (code, _, stderr) = run(&mut cmd);
    assert_eq!(code, 1, "{stderr}");
    assert!(stderr.contains("does not overlap device"));
    assert!(!compat.path("state/applied.json").exists());
}

#[test]
fn bootstrap_binds_expected_train_booted_os_and_installed_seed() {
    let train = Fixture::new("bootstrap-train-binding");
    let bom = train.write_bom("0.44.19", 4);
    let sig = train.write_sig("bom.sig", true);
    let cfg = train.write_config(1, "");
    let (code, _, stderr) = run(&mut train.bootstrap_cmd(&cfg, &bom, &sig));
    assert_eq!(code, 1, "{stderr}");
    assert!(stderr.contains("does not match expected train"));
    assert!(!train.path("state/applied.json").exists());

    let os = Fixture::new("bootstrap-os-binding");
    let bom = os.write_bom("0.44.18", 4);
    let mut value: Value = serde_json::from_str(&fs::read_to_string(&bom).unwrap()).unwrap();
    value["appliance"]["os_base"]["digest"] = Value::String(format!("sha256:{}", "c".repeat(64)));
    fs::write(&bom, serde_json::to_vec(&value).unwrap()).unwrap();
    let sig = os.write_sig("bom.sig", true);
    let cfg = os.write_config(1, "");
    let (code, _, stderr) = run(&mut os.bootstrap_cmd(&cfg, &bom, &sig));
    assert_eq!(code, 1, "{stderr}");
    assert!(stderr.contains("does not match booted OS ref"));
    assert!(!os.path("state/applied.json").exists());

    let seed = Fixture::new("bootstrap-seed-binding");
    let bom = seed.write_bom("0.44.18", 4);
    let mut value: Value = serde_json::from_str(&fs::read_to_string(&bom).unwrap()).unwrap();
    value["sources"]["seed"]["ref"] = Value::String("c".repeat(40));
    fs::write(&bom, serde_json::to_vec(&value).unwrap()).unwrap();
    let sig = seed.write_sig("bom.sig", true);
    let cfg = seed.write_config(1, "");
    let (code, _, stderr) = run(&mut seed.bootstrap_cmd(&cfg, &bom, &sig));
    assert_eq!(code, 1, "{stderr}");
    assert!(stderr.contains("does not match installed payload"));
    assert!(!seed.path("state/applied.json").exists());
}

#[test]
fn bootstrap_refuses_different_or_corrupt_existing_state_without_overwrite() {
    let different = Fixture::new("bootstrap-state-different");
    let bom = different.write_bom("0.44.18", 4);
    let sig = different.write_sig("bom.sig", true);
    let cfg = different.write_config(1, "");
    different.seed_applied(3, &"c".repeat(64));
    let before = fs::read(different.path("state/applied.json")).unwrap();
    let (code, _, stderr) = run(&mut different.bootstrap_cmd(&cfg, &bom, &sig));
    assert_eq!(code, 1, "{stderr}");
    assert!(stderr.contains("different baseline"));
    assert_eq!(
        fs::read(different.path("state/applied.json")).unwrap(),
        before
    );

    let corrupt = Fixture::new("bootstrap-state-corrupt");
    let bom = corrupt.write_bom("0.44.18", 4);
    let sig = corrupt.write_sig("bom.sig", true);
    let cfg = corrupt.write_config(1, "");
    fs::write(corrupt.path("state/applied.json"), "{not json").unwrap();
    fs::set_permissions(
        corrupt.path("state/applied.json"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let before = fs::read(corrupt.path("state/applied.json")).unwrap();
    let (code, _, stderr) = run(&mut corrupt.bootstrap_cmd(&cfg, &bom, &sig));
    assert_eq!(code, 1, "{stderr}");
    assert!(stderr.contains("refusing to overwrite"));
    assert_eq!(
        fs::read(corrupt.path("state/applied.json")).unwrap(),
        before
    );
}

#[test]
fn bootstrap_refuses_symlink_and_insecure_mode_state() {
    let symlinked = Fixture::new("bootstrap-state-symlink");
    let bom = symlinked.write_bom("0.44.18", 4);
    let sig = symlinked.write_sig("bom.sig", true);
    let cfg = symlinked.write_config(1, "");
    let target = symlinked.path("outside-state.json");
    fs::write(
        &target,
        format!(r#"{{"bundle_seq":4,"bom_sha256":"{}"}}"#, sha256_of(&bom)),
    )
    .unwrap();
    std::os::unix::fs::symlink(&target, symlinked.path("state/applied.json")).unwrap();
    let before = fs::read(&target).unwrap();
    let (code, _, stderr) = run(&mut symlinked.bootstrap_cmd(&cfg, &bom, &sig));
    assert_eq!(code, 1, "{stderr}");
    assert!(stderr.contains("symlink or non-regular"));
    assert_eq!(fs::read(&target).unwrap(), before);

    let permissive = Fixture::new("bootstrap-state-mode");
    let bom = permissive.write_bom("0.44.18", 4);
    let sig = permissive.write_sig("bom.sig", true);
    let cfg = permissive.write_config(1, "");
    permissive.seed_applied(4, &sha256_of(&bom));
    fs::set_permissions(
        permissive.path("state/applied.json"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    let (code, _, stderr) = run(&mut permissive.bootstrap_cmd(&cfg, &bom, &sig));
    assert_eq!(code, 1, "{stderr}");
    assert!(stderr.contains("must be mode 0600"));
}

#[test]
fn bootstrap_refuses_symlink_and_non_directory_state_parent() {
    let symlinked = Fixture::new("bootstrap-parent-symlink");
    let bom = symlinked.write_bom("0.44.18", 4);
    let sig = symlinked.write_sig("bom.sig", true);
    let cfg = symlinked.write_config(1, "");
    fs::remove_dir(symlinked.path("state")).unwrap();
    let real = symlinked.path("real-state");
    fs::create_dir(&real).unwrap();
    fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).unwrap();
    std::os::unix::fs::symlink(&real, symlinked.path("state")).unwrap();
    let (code, _, stderr) = run(&mut symlinked.bootstrap_cmd(&cfg, &bom, &sig));
    assert_eq!(code, 1, "{stderr}");
    assert!(stderr.contains("without following symlinks"), "{stderr}");
    assert!(!real.join("applied.json").exists());

    let regular = Fixture::new("bootstrap-parent-file");
    let bom = regular.write_bom("0.44.18", 4);
    let sig = regular.write_sig("bom.sig", true);
    let cfg = regular.write_config(1, "");
    fs::remove_dir(regular.path("state")).unwrap();
    fs::write(regular.path("state"), "not a directory").unwrap();
    let (code, _, stderr) = run(&mut regular.bootstrap_cmd(&cfg, &bom, &sig));
    assert_eq!(code, 1, "{stderr}");
    assert!(stderr.contains("without following symlinks"), "{stderr}");

    let missing = Fixture::new("bootstrap-parent-missing");
    let bom = missing.write_bom("0.44.18", 4);
    let sig = missing.write_sig("bom.sig", true);
    let cfg = missing.write_config(1, "");
    let custom_state = missing.path("missing/custom/applied.json");
    let mut command = missing.bootstrap_cmd(&cfg, &bom, &sig);
    command.args(["--applied-state".as_ref(), custom_state.as_os_str()]);
    let (code, _, stderr) = run(&mut command);
    assert_eq!(code, 1, "{stderr}");
    assert!(stderr.contains("not found"), "{stderr}");
    assert!(
        !custom_state.parent().unwrap().exists(),
        "bootstrap must not create its trust-boundary parent"
    );
}

#[test]
fn bootstrap_refuses_an_intermediate_state_parent_symlink_without_target_writes() {
    let fx = Fixture::new("bootstrap-intermediate-parent-symlink");
    let bom = fx.write_bom("0.44.18", 4);
    let sig = fx.write_sig("bom.sig", true);
    let (state_dir, target) = intermediate_symlink_state_parent(&fx);
    let cfg = fx.write_config_with_state(1, &state_dir, "");

    let (code, _, stderr) = run(&mut fx.bootstrap_cmd(&cfg, &bom, &sig));
    assert_eq!(code, 1, "{stderr}");
    assert!(stderr.contains("without following symlinks"), "{stderr}");
    assert!(fs::read_dir(&target).unwrap().next().is_none());
}

#[test]
fn bootstrap_ignores_harmless_crash_debris_before_atomic_publication() {
    let fx = Fixture::new("bootstrap-crash-debris");
    let bom = fx.write_bom("0.44.18", 4);
    let sig = fx.write_sig("bom.sig", true);
    let cfg = fx.write_config(1, "");
    let debris = fx.path("state/.applied.json.bootstrap.999999.0.tmp");
    fs::write(&debris, "partial").unwrap();

    let (code, receipt, stderr) = run(&mut fx.bootstrap_cmd(&cfg, &bom, &sig));
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(receipt["idempotent"], false);
    assert!(fx.path("state/applied.json").exists());
    assert!(debris.exists(), "unowned crash debris is never overwritten");
}

#[test]
fn concurrent_bootstraps_are_idempotent_or_refuse_a_different_baseline() {
    let same = Fixture::new("bootstrap-concurrent-same");
    let bom = same.write_bom("0.44.18", 4);
    let sig = same.write_sig("bom.sig", true);
    let cfg = same.write_config(1, "");
    let mut first = same.bootstrap_cmd(&cfg, &bom, &sig);
    let mut second = same.bootstrap_cmd(&cfg, &bom, &sig);
    for command in [&mut first, &mut second] {
        command
            .env("NI_OTA_TEST_COSIGN_DELAY", "0.1")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
    }
    let first = first.spawn().unwrap();
    let second = second.spawn().unwrap();
    let first = first.wait_with_output().unwrap();
    let second = second.wait_with_output().unwrap();
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(
        second.status.success(),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );

    let different = Fixture::new("bootstrap-concurrent-different");
    let base = different.write_bom("0.44.18", 4);
    let bom_a = different.path("bom-a.json");
    fs::copy(&base, &bom_a).unwrap();
    let mut value: Value = serde_json::from_str(&fs::read_to_string(&base).unwrap()).unwrap();
    value["bundle_seq"] = Value::from(5_u64);
    let bom_b = different.path("bom-b.json");
    fs::write(&bom_b, serde_json::to_vec(&value).unwrap()).unwrap();
    let sig = different.write_sig("bom.sig", true);
    let cfg = different.write_config(1, "");
    let mut first = different.bootstrap_cmd(&cfg, &bom_a, &sig);
    let mut second = different.bootstrap_cmd(&cfg, &bom_b, &sig);
    for command in [&mut first, &mut second] {
        command
            .env("NI_OTA_TEST_COSIGN_DELAY", "0.1")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
    }
    let first = first.spawn().unwrap();
    let second = second.spawn().unwrap();
    let outputs = [
        first.wait_with_output().unwrap(),
        second.wait_with_output().unwrap(),
    ];
    assert_eq!(
        outputs
            .iter()
            .filter(|output| output.status.success())
            .count(),
        1,
        "one different baseline must win exactly"
    );
    let applied: Value =
        serde_json::from_str(&fs::read_to_string(different.path("state/applied.json")).unwrap())
            .unwrap();
    let seq = applied["bundle_seq"].as_u64().unwrap();
    assert!(matches!(seq, 4 | 5));
    let expected_hash = if seq == 4 {
        sha256_of(&bom_a)
    } else {
        sha256_of(&bom_b)
    };
    assert_eq!(applied["bom_sha256"], expected_hash);
}

#[test]
fn concurrent_bootstrap_and_commit_never_regress_the_baseline() {
    let fx = Fixture::new("bootstrap-vs-commit");
    let bootstrap_source = fx.write_bom("0.44.18", 5);
    let bootstrap_bom = fx.path("bootstrap-bom.json");
    fs::copy(&bootstrap_source, &bootstrap_bom).unwrap();
    let bootstrap_sig = fx.write_bound_sig("bootstrap-bom.sig", &bootstrap_bom);
    let commit_source = fx.write_bom("0.44.17", 4);
    let commit_bom = fx.path("commit-bom.json");
    fs::copy(&commit_source, &commit_bom).unwrap();
    let cfg = fx.write_config(1, "");
    let ready = fx.path("bootstrap-cosign-ready");

    let mut bootstrap = fx.bootstrap_cmd(&cfg, &bootstrap_bom, &bootstrap_sig);
    bootstrap
        .env("NI_OTA_TEST_COSIGN_READY", &ready)
        .env("NI_OTA_TEST_COSIGN_DELAY", "0.3")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let bootstrap = bootstrap.spawn().unwrap();
    wait_for_path(&ready);

    // Bootstrap owns the common state lock while its signature is checked.
    // Commit must not observe Unseeded and later overwrite seq 5 with seq 4.
    let mut commit = Command::new(BIN);
    commit
        .env("NI_OTA_HARDWARE_TARGET_FILE", fx.path("hardware-target"))
        .arg("commit")
        .args(["--bom".as_ref(), commit_bom.as_os_str()])
        .args(["--config".as_ref(), cfg.as_os_str()])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let commit = commit.spawn().unwrap();

    let bootstrap = bootstrap.wait_with_output().unwrap();
    let commit = commit.wait_with_output().unwrap();
    assert!(
        bootstrap.status.success(),
        "{}",
        String::from_utf8_lossy(&bootstrap.stderr)
    );
    assert_eq!(commit.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&commit.stderr).contains("LOWER"));
    let applied: Value =
        serde_json::from_str(&fs::read_to_string(fx.path("state/applied.json")).unwrap()).unwrap();
    assert_eq!(applied["bundle_seq"], 5, "state must never regress");
}

// --- commit ---------------------------------------------------------------------

#[test]
fn commit_seeds_advances_and_guards() {
    let fx = Fixture::new("commit");
    let bom = fx.write_bom("0.44.7", 7);
    let cfg = fx.write_config(0, "");
    let commit = |bom: &Path| -> (i32, Value, String) {
        run(Command::new(BIN)
            .env("NI_OTA_HARDWARE_TARGET_FILE", fx.path("hardware-target"))
            .arg("commit")
            .args(["--bom".as_ref(), bom.as_os_str()])
            .args(["--config".as_ref(), cfg.as_os_str()]))
    };

    // 1) fresh state: the first commit seeds applied.json
    let (code, receipt, _) = commit(&bom);
    assert_eq!(code, 0);
    assert_eq!(receipt["committed"], true);
    assert_eq!(receipt["bundle_seq"], 7);
    let applied: Value =
        serde_json::from_str(&fs::read_to_string(fx.path("state/applied.json")).unwrap()).unwrap();
    assert_eq!(applied["bundle_seq"], 7);
    assert_eq!(applied["bom_sha256"], sha256_of(&bom).as_str());
    assert_eq!(
        fs::metadata(fx.path("state/applied.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o600
    );

    // 2) idempotent repair re-commit (same seq, same bytes) is allowed
    let (code, _, _) = commit(&bom);
    assert_eq!(code, 0);

    // 3) same seq, different bytes = forgery signal → refused
    let forged = fx.path("bom-forged.json");
    fs::write(
        &forged,
        r#"{"train":"0.44.7-evil","hardware_target":"nvidia-gb10-arm64","bundle_seq":7,"compat_min":1,"compat_version":3}"#,
    )
    .unwrap();
    let (code, _, stderr) = commit(&forged);
    assert_eq!(code, 1);
    assert!(stderr.contains("forgery"));

    // 4) lower seq → refused, state untouched
    let older = fx.path("bom-old.json");
    fs::write(
        &older,
        r#"{"train":"0.44.5","hardware_target":"nvidia-gb10-arm64","bundle_seq":5,"compat_min":1,"compat_version":3}"#,
    )
    .unwrap();
    let (code, _, stderr) = commit(&older);
    assert_eq!(code, 1);
    assert!(stderr.contains("LOWER"));
    let applied: Value =
        serde_json::from_str(&fs::read_to_string(fx.path("state/applied.json")).unwrap()).unwrap();
    assert_eq!(
        applied["bundle_seq"], 7,
        "refused commit must not move the record"
    );

    // 5) higher seq advances
    let newer = fx.path("bom-new.json");
    fs::write(
        &newer,
        r#"{"train":"0.44.8","hardware_target":"nvidia-gb10-arm64","bundle_seq":8,"compat_min":1,"compat_version":3}"#,
    )
    .unwrap();
    let (code, receipt, _) = commit(&newer);
    assert_eq!(code, 0);
    assert_eq!(receipt["bundle_seq"], 8);
    let applied: Value =
        serde_json::from_str(&fs::read_to_string(fx.path("state/applied.json")).unwrap()).unwrap();
    assert_eq!(applied["bundle_seq"], 8, "durable writer readback");
    assert_eq!(
        fs::metadata(fx.path("state/applied.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o600
    );
}

#[test]
fn commit_creates_and_attests_an_absent_custom_parent() {
    let fx = Fixture::new("commit-custom-parent");
    let bom = fx.write_bom("0.44.7", 7);
    let cfg = fx.write_config(1, "");
    let state = fx.path("custom/nested/applied.json");
    assert!(!state.parent().unwrap().exists());

    let (code, receipt, stderr) = run(Command::new(BIN)
        .env("NI_OTA_HARDWARE_TARGET_FILE", fx.path("hardware-target"))
        .arg("commit")
        .args(["--bom".as_ref(), bom.as_os_str()])
        .args(["--config".as_ref(), cfg.as_os_str()])
        .args(["--applied-state".as_ref(), state.as_os_str()]));
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(receipt["bundle_seq"], 7);
    assert_eq!(
        fs::metadata(fx.path("custom"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o700
    );
    assert_eq!(
        fs::metadata(state.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o700
    );
    assert_eq!(
        fs::metadata(&state).unwrap().permissions().mode() & 0o7777,
        0o600
    );
    assert_eq!(
        fs::metadata(state.parent().unwrap().join(".applied.json.lock"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o600
    );
}

#[test]
fn relative_applied_state_uses_current_directory_without_chmod() {
    let fx = Fixture::new("commit-relative-parent");
    fs::set_permissions(&fx.dir, fs::Permissions::from_mode(0o755)).unwrap();
    let bom = fx.write_bom("0.44.7", 7);
    let sig = fx.write_bound_sig("bom.sig", &bom);
    let cfg = fx.write_config(0, "");

    let commit = || {
        run(Command::new(BIN)
            .current_dir(&fx.dir)
            .env("NI_OTA_HARDWARE_TARGET_FILE", fx.path("hardware-target"))
            .arg("commit")
            .args(["--bom".as_ref(), bom.as_os_str()])
            .args(["--config".as_ref(), cfg.as_os_str()])
            .args(["--applied-state", "applied.json"]))
    };
    let (code, receipt, stderr) = commit();
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(receipt["bundle_seq"], 7);
    let (code, _, stderr) = commit();
    assert_eq!(code, 0, "idempotent retry: {stderr}");
    assert_eq!(
        fs::metadata(&fx.dir).unwrap().permissions().mode() & 0o7777,
        0o755
    );
    assert_eq!(
        fs::metadata(fx.path("applied.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o600
    );
    assert_eq!(
        fs::metadata(fx.path(".applied.json.lock"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o600
    );

    let mut bootstrap = fx.bootstrap_cmd(&cfg, &bom, &sig);
    bootstrap
        .current_dir(&fx.dir)
        .args(["--applied-state", "bootstrap-applied.json"]);
    let (code, _, stderr) = run(&mut bootstrap);
    assert_eq!(code, 1, "bootstrap must keep its strict 0700 parent policy");
    assert!(stderr.contains("must be mode 0700"), "{stderr}");
    assert_eq!(
        fs::metadata(&fx.dir).unwrap().permissions().mode() & 0o7777,
        0o755
    );
    assert!(!fx.path("bootstrap-applied.json").exists());
}

#[test]
fn verify_creates_commit_compatible_secure_state_dir() {
    let fx = Fixture::new("verify-creates-state-dir");
    let bom = fx.write_bom("0.44.7", 7);
    fx.write_record("0.44.7", "stable", 7);
    fx.write_sig("bom.sig", true);
    fx.write_sig("record.sig", true);
    let cfg = fx.write_config(0, "");
    fs::remove_dir_all(fx.path("state")).unwrap();

    let (code, _, stderr) = run(&mut fx.verify_cmd(&cfg));
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(
        fs::metadata(fx.path("state")).unwrap().permissions().mode() & 0o7777,
        0o700
    );
    assert!(fx.path("state/last-verdict.json").is_file());

    let (code, receipt, stderr) = run(Command::new(BIN)
        .env("NI_OTA_HARDWARE_TARGET_FILE", fx.path("hardware-target"))
        .arg("commit")
        .args(["--bom".as_ref(), bom.as_os_str()])
        .args(["--config".as_ref(), cfg.as_os_str()]));
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(receipt["bundle_seq"], 7);
    assert_eq!(
        fs::metadata(fx.path("state/applied.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o600
    );
}

#[test]
fn verify_never_repairs_or_writes_through_an_insecure_state_dir() {
    let permissive = Fixture::new("verify-permissive-state-dir");
    permissive.write_bom("0.44.7", 7);
    permissive.write_record("0.44.7", "stable", 7);
    permissive.write_sig("bom.sig", true);
    permissive.write_sig("record.sig", true);
    let cfg = permissive.write_config(0, "");
    fs::set_permissions(permissive.path("state"), fs::Permissions::from_mode(0o755)).unwrap();

    let (code, _, stderr) = run(&mut permissive.verify_cmd(&cfg));
    assert_eq!(code, 0, "unseeded shadow posture remains non-blocking");
    assert!(stderr.contains("could not record last verdict"), "{stderr}");
    assert_eq!(
        fs::metadata(permissive.path("state"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o755
    );
    assert!(!permissive.path("state/last-verdict.json").exists());

    let symlinked = Fixture::new("verify-symlink-state-dir");
    symlinked.write_bom("0.44.7", 7);
    symlinked.write_record("0.44.7", "stable", 7);
    symlinked.write_sig("bom.sig", true);
    symlinked.write_sig("record.sig", true);
    let cfg = symlinked.write_config(0, "");
    fs::remove_dir_all(symlinked.path("state")).unwrap();
    fs::create_dir(symlinked.path("outside-state")).unwrap();
    fs::set_permissions(
        symlinked.path("outside-state"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    std::os::unix::fs::symlink(symlinked.path("outside-state"), symlinked.path("state")).unwrap();

    let (code, _, stderr) = run(&mut symlinked.verify_cmd(&cfg));
    assert_eq!(code, 1, "untrusted anti-rollback state never shadow-passes");
    assert!(stderr.contains("could not record last verdict"), "{stderr}");
    assert!(fs::symlink_metadata(symlinked.path("state"))
        .unwrap()
        .file_type()
        .is_symlink());
    assert!(!symlinked.path("outside-state/last-verdict.json").exists());
}

#[test]
fn verify_refuses_an_intermediate_state_parent_symlink_without_target_writes() {
    let fx = Fixture::new("verify-intermediate-parent-symlink");
    fx.write_bom("0.44.7", 7);
    fx.write_record("0.44.7", "stable", 7);
    fx.write_sig("bom.sig", true);
    fx.write_sig("record.sig", true);
    let (state_dir, target) = intermediate_symlink_state_parent(&fx);
    let cfg = fx.write_config_with_state(0, &state_dir, "");

    let (code, verdict, stderr) = run(&mut fx.verify_cmd(&cfg));
    assert_eq!(code, 1, "anti-rollback authority never shadow-passes");
    assert_eq!(verdict["verdict"], "refuse");
    assert_eq!(check(&verdict, "anti_rollback")["ok"], false);
    assert!(check(&verdict, "anti_rollback")["detail"]
        .as_str()
        .unwrap()
        .contains("without following symlinks"));
    assert!(stderr.contains("could not record last verdict"), "{stderr}");
    assert!(fs::read_dir(&target).unwrap().next().is_none());
}

#[test]
fn commit_refuses_an_intermediate_state_parent_symlink_without_target_writes() {
    let fx = Fixture::new("commit-intermediate-parent-symlink");
    let bom = fx.write_bom("0.44.7", 7);
    let cfg = fx.write_config(1, "");
    let (state_dir, target) = intermediate_symlink_state_parent(&fx);
    fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).unwrap();
    let applied = state_dir.join("applied.json");

    let (code, _, stderr) = run(Command::new(BIN)
        .env("NI_OTA_HARDWARE_TARGET_FILE", fx.path("hardware-target"))
        .env("NI_OTA_TEST_LEGACY_STATE_DIR", &state_dir)
        .arg("commit")
        .args(["--bom".as_ref(), bom.as_os_str()])
        .args(["--config".as_ref(), cfg.as_os_str()])
        .args(["--applied-state".as_ref(), applied.as_os_str()]));
    assert_eq!(code, 2, "{stderr}");
    assert!(stderr.contains("without following symlinks"), "{stderr}");
    assert!(fs::read_dir(&target).unwrap().next().is_none());
    assert_eq!(
        fs::metadata(&target).unwrap().permissions().mode() & 0o7777,
        0o755,
        "migration must not chmod through an intermediate symlink"
    );
}

#[test]
fn commit_refuses_a_replaceable_intermediate_parent_without_target_writes() {
    let fx = Fixture::new("commit-replaceable-intermediate-parent");
    let bom = fx.write_bom("0.44.7", 7);
    let cfg = fx.write_config(1, "");
    let replaceable = fx.path("replaceable");
    let target = replaceable.join("state");
    fs::create_dir(&replaceable).unwrap();
    fs::set_permissions(&replaceable, fs::Permissions::from_mode(0o777)).unwrap();
    let applied = target.join("applied.json");

    let (code, _, stderr) = run(Command::new(BIN)
        .env("NI_OTA_HARDWARE_TARGET_FILE", fx.path("hardware-target"))
        .env("NI_OTA_TEST_LEGACY_STATE_DIR", &target)
        .arg("commit")
        .args(["--bom".as_ref(), bom.as_os_str()])
        .args(["--config".as_ref(), cfg.as_os_str()])
        .args(["--applied-state".as_ref(), applied.as_os_str()]));
    assert_eq!(code, 2, "{stderr}");
    assert!(stderr.contains("replaceable"), "{stderr}");
    assert!(!target.exists(), "commit must reject before mkdirat");
}

#[test]
fn commit_migrates_only_the_bounded_legacy_0755_state_dir() {
    let fx = Fixture::new("commit-legacy-state-dir-migration");
    let bom = fx.write_bom("0.44.7", 7);
    let cfg = fx.write_config(1, "");
    let state_dir = fx.path("state");
    let legacy_marker = state_dir.join("legacy-marker");
    fs::write(&legacy_marker, b"preserve-me\n").unwrap();
    fs::set_permissions(&state_dir, fs::Permissions::from_mode(0o755)).unwrap();

    let commit = || {
        run(Command::new(BIN)
            .env("NI_OTA_HARDWARE_TARGET_FILE", fx.path("hardware-target"))
            .env("NI_OTA_TEST_LEGACY_STATE_DIR", &state_dir)
            .arg("commit")
            .args(["--bom".as_ref(), bom.as_os_str()])
            .args(["--config".as_ref(), cfg.as_os_str()]))
    };
    let (code, receipt, stderr) = commit();
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(receipt["bundle_seq"], 7);
    assert!(
        stderr.contains("migrated legacy state directory"),
        "{stderr}"
    );
    assert_eq!(
        fs::metadata(&state_dir).unwrap().permissions().mode() & 0o7777,
        0o700
    );
    assert_eq!(
        fs::metadata(state_dir.join("applied.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o600
    );
    assert_eq!(fs::read(&legacy_marker).unwrap(), b"preserve-me\n");

    let (code, _, stderr) = commit();
    assert_eq!(code, 0, "idempotent post-migration retry: {stderr}");
    assert!(!stderr.contains("migrated legacy state directory"));
}

#[test]
fn commit_never_migrates_an_unbounded_0755_state_dir() {
    let fx = Fixture::new("commit-unbounded-legacy-state-dir");
    let bom = fx.write_bom("0.44.7", 7);
    let cfg = fx.write_config(1, "");
    let state_dir = fx.path("state");
    fs::set_permissions(&state_dir, fs::Permissions::from_mode(0o755)).unwrap();

    let (code, _, stderr) = run(Command::new(BIN)
        .env("NI_OTA_HARDWARE_TARGET_FILE", fx.path("hardware-target"))
        .arg("commit")
        .args(["--bom".as_ref(), bom.as_os_str()])
        .args(["--config".as_ref(), cfg.as_os_str()]));
    assert_eq!(code, 2, "{stderr}");
    assert!(stderr.contains("must be mode 0700"), "{stderr}");
    assert_eq!(
        fs::metadata(&state_dir).unwrap().permissions().mode() & 0o7777,
        0o755
    );
    assert!(!state_dir.join("applied.json").exists());
}

#[test]
fn concurrent_commits_can_never_publish_a_lower_sequence_last() {
    let fx = Fixture::new("commit-concurrent-forward-only");
    fx.seed_applied(3, &"c".repeat(64));
    let low_source = fx.write_bom("0.44.4", 4);
    let low = fx.path("low.json");
    fs::copy(&low_source, &low).unwrap();
    let high_source = fx.write_bom("0.44.5", 5);
    let high = fx.path("high.json");
    fs::copy(&high_source, &high).unwrap();
    let cfg = fx.write_config(1, "");
    let ready = fx.path("low-commit-read-ready");

    let mut low_command = Command::new(BIN);
    low_command
        .env("NI_OTA_HARDWARE_TARGET_FILE", fx.path("hardware-target"))
        .env("NI_OTA_TEST_COMMIT_READY", &ready)
        .env("NI_OTA_TEST_COMMIT_DELAY_MS", "300")
        .arg("commit")
        .args(["--bom".as_ref(), low.as_os_str()])
        .args(["--config".as_ref(), cfg.as_os_str()])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let low_command = low_command.spawn().unwrap();
    wait_for_path(&ready);

    let mut high_command = Command::new(BIN);
    high_command
        .env("NI_OTA_HARDWARE_TARGET_FILE", fx.path("hardware-target"))
        .arg("commit")
        .args(["--bom".as_ref(), high.as_os_str()])
        .args(["--config".as_ref(), cfg.as_os_str()])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let high_command = high_command.spawn().unwrap();

    let low_output = low_command.wait_with_output().unwrap();
    let high_output = high_command.wait_with_output().unwrap();
    assert!(
        low_output.status.success(),
        "{}",
        String::from_utf8_lossy(&low_output.stderr)
    );
    assert!(
        high_output.status.success(),
        "{}",
        String::from_utf8_lossy(&high_output.stderr)
    );
    let applied: Value =
        serde_json::from_str(&fs::read_to_string(fx.path("state/applied.json")).unwrap()).unwrap();
    assert_eq!(
        applied["bundle_seq"], 5,
        "a delayed lower commit must never overwrite a completed higher commit"
    );
}

#[test]
fn commit_refuses_a_different_hardware_target() {
    let fx = Fixture::new("commit-hardware-target");
    let bom = fx.write_bom("0.44.7", 7);
    let value: Value = serde_json::from_str(&fs::read_to_string(&bom).unwrap()).unwrap();
    let mut value = value;
    value["hardware_target"] = Value::String("nvidia-cuda-x86_64".to_string());
    fs::write(&bom, serde_json::to_vec(&value).unwrap()).unwrap();
    let cfg = fx.write_config(1, "");
    let (code, _, stderr) = run(Command::new(BIN)
        .env("NI_OTA_HARDWARE_TARGET_FILE", fx.path("hardware-target"))
        .arg("commit")
        .args(["--bom".as_ref(), bom.as_os_str()])
        .args(["--config".as_ref(), cfg.as_os_str()]));
    assert_eq!(code, 1);
    assert!(stderr.contains("does not match immutable host target"));
}

#[test]
fn commit_refuses_malformed_bom_as_internal_error() {
    let fx = Fixture::new("commit-malformed");
    let cfg = fx.write_config(0, "");
    let bad = fx.path("bad.json");
    fs::write(&bad, "{").unwrap();
    let (code, _, stderr) = run(Command::new(BIN)
        .arg("commit")
        .args(["--bom".as_ref(), bad.as_os_str()])
        .args(["--config".as_ref(), cfg.as_os_str()]));
    assert_eq!(code, 2);
    assert!(stderr.contains("malformed BOM"));
}

#[test]
fn delegation_snapshot_accepts_exact_vector_and_enforces_immutable_floor() {
    let fx = Fixture::new("delegation-snapshot");
    let snapshot = fx.path("delegation-snapshot.json");
    fs::write(
        &snapshot,
        include_bytes!("fixtures/delegated-v1/delegation-snapshot.json"),
    )
    .unwrap();
    let value: Value = serde_json::from_slice(&fs::read(&snapshot).unwrap()).unwrap();
    let encoded = value["root_key"]["public_key"]["spki_der_base64"]
        .as_str()
        .unwrap();
    fs::write(
        fx.path("ota-root.pub"),
        format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n{}\n-----END PUBLIC KEY-----\n",
            &encoded[..64],
            &encoded[64..]
        ),
    )
    .unwrap();
    fs::write(
        fx.path("snapshot.sig"),
        [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01],
    )
    .unwrap();
    let cfg = fx.write_config(1, "");
    let command = |minimum: &str| {
        fs::write(fx.path("min-delegation-seq"), format!("{minimum}\n")).unwrap();
        let mut command = Command::new(BIN);
        command
            .env("NI_OTA_COSIGN", fx.path("cosign-stub.sh"))
            .env(
                "NI_OTA_MIN_DELEGATION_SEQ_FILE",
                fx.path("min-delegation-seq"),
            )
            .arg("verify-delegation-snapshot")
            .args(["--snapshot".as_ref(), snapshot.as_os_str()])
            .args([
                "--snapshot-sig".as_ref(),
                fx.path("snapshot.sig").as_os_str(),
            ])
            .args(["--accepted-snapshot".as_ref(), snapshot.as_os_str()])
            .args(["--accepted-delegation-seq", "1"])
            .args([
                "--accepted-delegation-sha256",
                "959c879bc0583bdf98ac029503d37e814c5f51120a5aef6ddf5ed0896b859a3b",
            ])
            .args(["--trusted-now", "2026-07-22T00:00:00Z"])
            .args(["--config".as_ref(), cfg.as_os_str()]);
        run(&mut command)
    };
    let (code, verdict, stderr) = command("1");
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(verdict["verdict"], "pass");
    assert!(verdict.get("ring").is_none());

    let mut omitted_state = Command::new(BIN);
    omitted_state
        .env("NI_OTA_COSIGN", fx.path("cosign-stub.sh"))
        .env(
            "NI_OTA_MIN_DELEGATION_SEQ_FILE",
            fx.path("min-delegation-seq"),
        )
        .arg("verify-delegation-snapshot")
        .args(["--snapshot".as_ref(), snapshot.as_os_str()])
        .args([
            "--snapshot-sig".as_ref(),
            fx.path("snapshot.sig").as_os_str(),
        ])
        .args(["--trusted-now", "2026-07-22T00:00:00Z"])
        .args(["--config".as_ref(), cfg.as_os_str()]);
    let (code, _, stderr) = run(&mut omitted_state);
    assert_eq!(code, 1, "{stderr}");
    assert!(stderr.contains("accepted delegation state is required"));

    let mut missing_cosign = Command::new(BIN);
    missing_cosign
        .env("NI_OTA_COSIGN", fx.path("missing-cosign"))
        .env(
            "NI_OTA_MIN_DELEGATION_SEQ_FILE",
            fx.path("min-delegation-seq"),
        )
        .arg("verify-delegation-snapshot")
        .args(["--snapshot".as_ref(), snapshot.as_os_str()])
        .args([
            "--snapshot-sig".as_ref(),
            fx.path("snapshot.sig").as_os_str(),
        ])
        .args(["--accepted-snapshot".as_ref(), snapshot.as_os_str()])
        .args(["--accepted-delegation-seq", "1"])
        .args([
            "--accepted-delegation-sha256",
            "959c879bc0583bdf98ac029503d37e814c5f51120a5aef6ddf5ed0896b859a3b",
        ])
        .args(["--trusted-now", "2026-07-22T00:00:00Z"])
        .args(["--config".as_ref(), cfg.as_os_str()]);
    let (code, _, stderr) = run(&mut missing_cosign);
    assert_eq!(code, 2, "broken verifier tooling is an internal error");
    assert!(stderr.contains("cosign not found"), "{stderr}");

    let (code, _, stderr) = command("2");
    assert_eq!(code, 1);
    assert!(stderr.contains("delegation snapshot REFUSED"));
}

#[test]
fn delegated_snapshot_keeps_anchor_refusals_distinct_from_broken_hashing() {
    let fx = Fixture::new("delegation-failure-classification");
    let snapshot = fx.path("delegation-snapshot.json");
    fs::write(
        &snapshot,
        include_bytes!("fixtures/delegated-v1/delegation-snapshot.json"),
    )
    .unwrap();
    let value: Value = serde_json::from_slice(&fs::read(&snapshot).unwrap()).unwrap();
    let encoded = value["root_key"]["public_key"]["spki_der_base64"]
        .as_str()
        .unwrap();
    let root = format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n{}\n-----END PUBLIC KEY-----\n",
        &encoded[..64],
        &encoded[64..]
    );
    fs::write(fx.path("ota-root.pub"), &root).unwrap();
    fs::write(
        fx.path("snapshot.sig"),
        [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01],
    )
    .unwrap();
    let command = |config: &Path| {
        let mut command = Command::new(BIN);
        command
            .env("NI_OTA_COSIGN", fx.path("cosign-stub.sh"))
            .env(
                "NI_OTA_MIN_DELEGATION_SEQ_FILE",
                fx.path("min-delegation-seq"),
            )
            .arg("verify-delegation-snapshot")
            .args(["--snapshot".as_ref(), snapshot.as_os_str()])
            .args([
                "--snapshot-sig".as_ref(),
                fx.path("snapshot.sig").as_os_str(),
            ])
            .args(["--accepted-snapshot".as_ref(), snapshot.as_os_str()])
            .args(["--accepted-delegation-seq", "1"])
            .args([
                "--accepted-delegation-sha256",
                "959c879bc0583bdf98ac029503d37e814c5f51120a5aef6ddf5ed0896b859a3b",
            ])
            .args(["--trusted-now", "2026-07-22T00:00:00Z"])
            .args(["--config".as_ref(), config.as_os_str()]);
        command
    };

    let no_anchor = fx.path("no-anchor.conf");
    fs::write(
        &no_anchor,
        format!("enforce=1\nstate_dir={}\n", fx.path("state").display()),
    )
    .unwrap();
    let (code, _, stderr) = run(&mut command(&no_anchor));
    assert_eq!(code, 1, "{stderr}");

    let config = fx.write_config(1, "");
    fs::write(fx.path("ota-root.pub"), "").unwrap();
    let (code, _, stderr) = run(&mut command(&config));
    assert_eq!(code, 1, "{stderr}");

    fs::write(fx.path("ota-root-target.pub"), &root).unwrap();
    fs::remove_file(fx.path("ota-root.pub")).unwrap();
    std::os::unix::fs::symlink(fx.path("ota-root-target.pub"), fx.path("ota-root.pub")).unwrap();
    let (code, _, stderr) = run(&mut command(&config));
    assert_eq!(code, 1, "{stderr}");
    fs::remove_file(fx.path("ota-root.pub")).unwrap();
    fs::write(fx.path("ota-root.pub"), vec![b'x'; 128 * 1024 + 1]).unwrap();
    let (code, _, stderr) = run(&mut command(&config));
    assert_eq!(code, 1, "{stderr}");

    fs::write(fx.path("ota-root.pub"), root).unwrap();
    let empty_path = fx.path("empty-path");
    fs::create_dir(&empty_path).unwrap();
    let mut broken_hash = command(&config);
    broken_hash.env("PATH", empty_path);
    let (code, _, stderr) = run(&mut broken_hash);
    assert_eq!(code, 2, "{stderr}");
    assert!(stderr.contains("sha256sum"), "{stderr}");
}

#[test]
fn capabilities_are_canonical_bounded_and_argument_free() {
    let output = Command::new(BIN).arg("capabilities").output().unwrap();
    assert!(output.status.success());
    assert_eq!(
        output.stdout,
        b"{\"schema\":1,\"features\":[\"bundle-digest-v1\"]}\n"
    );
    assert!(output.stdout.len() < 4096);

    let output = Command::new(BIN)
        .args(["capabilities", "unexpected"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
}

#[test]
fn delegated_beta_binds_signed_release_receipt_and_immutable_target() {
    let fx = Fixture::new("delegated-beta-receipt");
    let snapshot = fx.path("delegation-snapshot.json");
    let release = fx.path("release-authorization.json");
    let receipt = fx.path("beta-publication-receipt.json");
    fs::write(
        &snapshot,
        include_bytes!("fixtures/delegated-v1/delegation-snapshot.json"),
    )
    .unwrap();
    fs::write(
        &release,
        include_bytes!("fixtures/delegated-v1/release-authorization.json"),
    )
    .unwrap();
    fs::write(
        &receipt,
        include_bytes!("fixtures/delegated-v1/beta-publication-receipt.json"),
    )
    .unwrap();
    let value: Value = serde_json::from_slice(&fs::read(&snapshot).unwrap()).unwrap();
    let encoded = value["root_key"]["public_key"]["spki_der_base64"]
        .as_str()
        .unwrap();
    fs::write(
        fx.path("ota-root.pub"),
        format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n{}\n-----END PUBLIC KEY-----\n",
            &encoded[..64],
            &encoded[64..]
        ),
    )
    .unwrap();
    let signature = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];
    for name in ["snapshot.sig", "release.sig", "receipt.sig"] {
        fs::write(fx.path(name), signature).unwrap();
    }
    let command = |cfg: &Path| {
        let mut command = Command::new(BIN);
        command
            .env("NI_OTA_COSIGN", fx.path("cosign-stub.sh"))
            .env("NI_OTA_HARDWARE_TARGET_FILE", fx.path("hardware-target"))
            .env(
                "NI_OTA_APPLIANCE_VARIANT_FILE",
                fx.path("appliance-variant"),
            )
            .env(
                "NI_OTA_MIN_DELEGATION_SEQ_FILE",
                fx.path("min-delegation-seq"),
            )
            .arg("verify-delegated-beta")
            .args(["--snapshot".as_ref(), snapshot.as_os_str()])
            .args([
                "--snapshot-sig".as_ref(),
                fx.path("snapshot.sig").as_os_str(),
            ])
            .args(["--release".as_ref(), release.as_os_str()])
            .args(["--release-sig".as_ref(), fx.path("release.sig").as_os_str()])
            .args(["--receipt".as_ref(), receipt.as_os_str()])
            .args(["--receipt-sig".as_ref(), fx.path("receipt.sig").as_os_str()])
            .args(["--trusted-now", "2026-07-22T01:00:00Z"])
            .args(["--config".as_ref(), cfg.as_os_str()]);
        run(&mut command)
    };
    let cfg = fx.write_config(
        1,
        "device_channel=beta\ndevice_compat_min=5\ndevice_compat_max=5\n",
    );
    let (code, verdict, stderr) = command(&cfg);
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(verdict["ring"], "beta");
    assert_eq!(verdict["bundle_seq"], 19);
    assert_eq!(
        verdict["receipt_sha256"],
        "4fff4b85728ffe3b12ecdaf98a0f6a332c93da0dca6855336638d3b1dfc91850"
    );
    assert_eq!(
        verdict["manifest_digest"],
        "sha256:9999999999999999999999999999999999999999999999999999999999999999"
    );

    let incompatible = fx.write_config(
        1,
        "device_channel=beta\ndevice_compat_min=6\ndevice_compat_max=6\n",
    );
    let (code, _, stderr) = command(&incompatible);
    assert_eq!(code, 1);
    assert!(stderr.contains("does not overlap device"), "{stderr}");

    let shadow = fx.write_config(
        0,
        "device_channel=beta\ndevice_compat_min=6\ndevice_compat_max=6\n",
    );
    let (code, verdict, stderr) = command(&shadow);
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(verdict["verdict"], "pass");
    assert!(stderr.contains("compatibility WARNING"), "{stderr}");

    let stable = fx.write_config(
        1,
        "device_channel=stable\ndevice_compat_min=5\ndevice_compat_max=5\n",
    );
    let (code, _, stderr) = command(&stable);
    assert_eq!(code, 1, "{stderr}");
    assert!(stderr.contains("device_channel=beta"), "{stderr}");

    let cfg = fx.write_config(
        1,
        "device_channel=beta\ndevice_compat_min=5\ndevice_compat_max=5\n",
    );
    fs::write(fx.path("appliance-variant"), "debug\n").unwrap();
    let (code, _, stderr) = command(&cfg);
    assert_eq!(code, 1, "{stderr}");
    assert!(stderr.contains("immutable host variant"), "{stderr}");
}
