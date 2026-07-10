//! End-to-end CLI tests against the built binary. No real cosign and no
//! signing infrastructure needed: `NI_OTA_COSIGN` injects a stub script whose
//! verdict is driven by the CONTENT of the signature file (contains "GOOD" →
//! valid, anything else → rejected), so every §0 check is exercised through
//! the real subprocess plumbing.
#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_ni-ota-verify");

const COSIGN_STUB: &str = r#"#!/bin/sh
# Test stub for `cosign verify-blob` (see tests/cli.rs): a signature file
# containing the string GOOD verifies; anything else is rejected like a bad
# signature (exit 1), which is exactly how the real cosign reports one.
sig=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--signature" ]; then sig="$2"; shift 2; else shift 1; fi
done
[ -n "$sig" ] || { echo "stub: no --signature flag" >&2; exit 2; }
grep -q GOOD "$sig" 2>/dev/null || { echo "stub: signature rejected" >&2; exit 1; }
exit 0
"#;

struct Fixture {
    dir: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("ni-ota-verify-cli-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("state")).unwrap();
        let stub = dir.join("cosign-stub.sh");
        fs::write(&stub, COSIGN_STUB).unwrap();
        fs::set_permissions(&stub, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(
            dir.join("ota-root.pub"),
            "-----BEGIN TEST PUBLIC KEY-----\n",
        )
        .unwrap();
        Fixture { dir }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    fn write_config(&self, enforce: u8, extra: &str) -> PathBuf {
        let path = self.path("ota.conf");
        fs::write(
            &path,
            format!(
                "# test ota.conf\nenforce={enforce}\nregistry=registry.neural-ice.ch\n\
                 root_pubkey={}\nstate_dir={}\n{extra}",
                self.path("ota-root.pub").display(),
                self.path("state").display()
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
                r#"{{"appliance":{{"images":{{"icecore":{{"digest":"reg/x@sha256:aa"}}}},"raw_sha256":"bb","version":"{train}"}},"bundle_seq":{seq},"compat_min":1,"compat_version":3,"created":"2026-07-11T00:00:00Z","key_version":1,"train":"{train}"}}"#
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
                r#"{{"assigned_at":"2026-07-11T00:00:00Z","bundle_seq":{seq},"channel":"{channel}","key_version":1,"train":"{train}"}}"#
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

    fn seed_applied(&self, seq: u64, sha: &str) {
        fs::write(
            self.path("state/applied.json"),
            format!(r#"{{"bundle_seq":{seq},"bom_sha256":"{sha}"}}"#),
        )
        .unwrap();
    }

    /// 4-file verify invocation WITHOUT device identity flags.
    fn verify_cmd_bare(&self, config: &Path) -> Command {
        let mut cmd = Command::new(BIN);
        cmd.env("NI_OTA_COSIGN", self.path("cosign-stub.sh"))
            .arg("verify")
            .args(["--bom".as_ref(), self.path("bom.json").as_os_str()])
            .args(["--bom-sig".as_ref(), self.path("bom.sig").as_os_str()])
            .args(["--record".as_ref(), self.path("record.json").as_os_str()])
            .args(["--record-sig".as_ref(), self.path("record.sig").as_os_str()])
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
            "train_match",
            "seq_match",
            "channel_match",
            "anti_rollback",
            "compat_overlap",
        ] {
            assert_eq!(check(&verdict, name)["ok"], true, "{mode}: check {name}");
        }
    }
}

// --- verify: each §0 check fails with its own code -----------------------------

#[test]
fn bad_record_signature_refuses_shadow_exit0_enforce_exit1() {
    for (enforce, want_code) in [(0, 0), (1, 1)] {
        let fx = Fixture::new(&format!("recsig-{enforce}"));
        fx.arrange_happy();
        fx.write_sig("record.sig", false);
        let cfg = fx.write_config(enforce, "");
        let (code, verdict, _) = run(&mut fx.verify_cmd(&cfg));
        assert_eq!(code, want_code);
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
    let fx = Fixture::new("bomsig");
    fx.arrange_happy();
    fx.write_sig("bom.sig", false);
    let cfg = fx.write_config(1, "");
    let (code, verdict, _) = run(&mut fx.verify_cmd(&cfg));
    assert_eq!(code, 1);
    assert_eq!(check(&verdict, "record_sig")["ok"], true);
    assert_eq!(check(&verdict, "bom_sig")["ok"], false);
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
    fx.write_record("0.44.7", "edge", 7);
    let cfg = fx.write_config(1, "");
    let (code, verdict, _) = run(&mut fx.verify_cmd(&cfg));
    assert_eq!(code, 1);
    let c = check(&verdict, "channel_match");
    assert_eq!(c["ok"], false);
    assert!(c["detail"].as_str().unwrap().contains("edge"));
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
    assert_eq!(code, 0, "shadow logs, does not block: {verdict}");
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

// --- commit ---------------------------------------------------------------------

#[test]
fn commit_seeds_advances_and_guards() {
    let fx = Fixture::new("commit");
    let bom = fx.write_bom("0.44.7", 7);
    let cfg = fx.write_config(0, "");
    let commit = |bom: &Path| -> (i32, Value, String) {
        run(Command::new(BIN)
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

    // 2) idempotent repair re-commit (same seq, same bytes) is allowed
    let (code, _, _) = commit(&bom);
    assert_eq!(code, 0);

    // 3) same seq, different bytes = forgery signal → refused
    let forged = fx.path("bom-forged.json");
    fs::write(
        &forged,
        r#"{"train":"0.44.7-evil","bundle_seq":7,"compat_min":1,"compat_version":3}"#,
    )
    .unwrap();
    let (code, _, stderr) = commit(&forged);
    assert_eq!(code, 1);
    assert!(stderr.contains("forgery"));

    // 4) lower seq → refused, state untouched
    let older = fx.path("bom-old.json");
    fs::write(
        &older,
        r#"{"train":"0.44.5","bundle_seq":5,"compat_min":1,"compat_version":3}"#,
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
        r#"{"train":"0.44.8","bundle_seq":8,"compat_min":1,"compat_version":3}"#,
    )
    .unwrap();
    let (code, receipt, _) = commit(&newer);
    assert_eq!(code, 0);
    assert_eq!(receipt["bundle_seq"], 8);
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
