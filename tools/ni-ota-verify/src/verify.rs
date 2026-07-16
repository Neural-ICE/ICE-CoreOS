//! The §0 verification contract (ICE-Fabric OTA signing plan), evaluated
//! over local files in plan order. Every §0 check emits a distinct
//! machine-readable entry; checks keep running after a failure wherever their
//! inputs allow it (shadow-mode burn-in wants the FULL diagnostic picture,
//! not the first refusal).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::{immutable_hardware_target, parse_compat_flag, Config};
use crate::state::{AppliedStateStore, FileStateStore, StateRead};
use crate::{parse_flags, runner, InternalError, DEFAULT_CONFIG, EXIT_PASS, EXIT_REFUSE};

/// The signed IMMUTABLE core of the release-train lockfile (ICE-Fabric
/// `release-train.sh bom` — canonical `jq -S del(.status)` serialization).
/// Only the fields the §0 checks consume are modeled; the rest of the BOM
/// (digests, sources, …) is the apply-side caller's business.
#[derive(Deserialize)]
pub(crate) struct BomCore {
    pub train: String,
    pub hardware_target: String,
    pub bundle_seq: u64,
    // Optional so that an incomplete BOM fails the compat CHECK (a verdict)
    // instead of the parse step — the failure code must say "compat", not
    // "malformed JSON", when only the range is missing.
    pub compat_min: Option<i64>,
    pub compat_version: Option<i64>,
}

/// The signed channel record (`releases/channels/<ch>.json` — plan §2).
#[derive(Deserialize)]
struct ChannelRecord {
    train: String,
    hardware_target: String,
    channel: String,
    bundle_seq: u64,
}

#[derive(Serialize)]
struct Verdict {
    verdict: &'static str,
    checks: Vec<Check>,
    enforce: bool,
}

#[derive(Serialize)]
struct Check {
    name: &'static str,
    ok: bool,
    detail: String,
}

impl Check {
    fn pass(name: &'static str, detail: String) -> Self {
        Check {
            name,
            ok: true,
            detail,
        }
    }
    fn fail(name: &'static str, detail: String) -> Self {
        Check {
            name,
            ok: false,
            detail,
        }
    }
    /// A device-side input (channel / compat range) is unconfigured: shadow
    /// mode skips WITH a warning (the check cannot run, burn-in continues),
    /// enforce mode refuses (fail-closed — an enforcing device must know its
    /// own identity).
    fn unknown_device_input(name: &'static str, what: &str, enforce: bool) -> Self {
        if enforce {
            Check::fail(
                name,
                format!("{what} unknown — refusing (fail-closed in enforce mode)"),
            )
        } else {
            Check::pass(
                name,
                format!("WARNING: {what} unknown — check skipped (shadow mode)"),
            )
        }
    }
}

pub(crate) fn run(args: &[String]) -> Result<u8, InternalError> {
    let flags = parse_flags(
        args,
        &[
            "bom",
            "bom-sig",
            "record",
            "record-sig",
            "config",
            "device-channel",
            "device-compat",
            "applied-state",
        ],
    )?;
    let path_of = |key: &str| -> Result<PathBuf, InternalError> {
        flags
            .get(key)
            .map(PathBuf::from)
            .ok_or_else(|| InternalError(format!("verify: --{key} is required")))
    };
    let bom_path = path_of("bom")?;
    let bom_sig_path = path_of("bom-sig")?;
    let record_path = path_of("record")?;
    let record_sig_path = path_of("record-sig")?;

    let config_path = flags.get("config").map_or(DEFAULT_CONFIG, String::as_str);
    let cfg = Config::load(Path::new(config_path))?;
    let hardware_target = immutable_hardware_target()?;
    // Resolve the whole toolchain BEFORE any check runs: a missing cosign is
    // an internal error in every mode, never a "refuse" a caller could route.
    let cosign = runner::cosign_path()?;

    let device_channel = flags
        .get("device-channel")
        .cloned()
        .or_else(|| cfg.device_channel.clone());
    let device_compat = match flags.get("device-compat") {
        Some(raw) => Some(parse_compat_flag(raw)?),
        None => cfg.device_compat,
    };
    let store = FileStateStore {
        path: applied_state_path(&flags, &cfg)?,
    };

    let mut checks: Vec<Check> = Vec::new();

    // --- §0 steps 1+2: record signature, then BOM signature ------------------
    match cfg.root_pubkey.as_deref().filter(|p| non_empty_file(p)) {
        Some(pubkey) => {
            for (name, file, sig) in [
                ("record_sig", &record_path, &record_sig_path),
                ("bom_sig", &bom_path, &bom_sig_path),
            ] {
                checks.push(match runner::verify_blob(&cosign, pubkey, sig, file)? {
                    Ok(()) => Check::pass(
                        name,
                        format!("cosign verify-blob OK for {}", file.display()),
                    ),
                    Err(why) => Check::fail(
                        name,
                        format!("signature REJECTED for {}: {why}", file.display()),
                    ),
                });
            }
        }
        None => {
            // Missing/empty trust anchor = a verification failure (the staged
            // contract in /etc/neural-ice/keys/README: shadow logs, enforce
            // refuses) — not an internal error, the tooling itself is fine.
            let detail = match &cfg.root_pubkey {
                Some(p) => format!(
                    "OTA root pubkey missing or empty: {} (staged at the P0 key ceremony — see /etc/neural-ice/keys/README)",
                    p.display()
                ),
                None => "no root_pubkey configured in ota.conf".to_string(),
            };
            checks.push(Check::fail("record_sig", detail.clone()));
            checks.push(Check::fail("bom_sig", detail));
        }
    }

    // --- parse the (signed) artifacts; malformed content = refusal -----------
    let record: Result<ChannelRecord, String> = read_json(&record_path);
    checks.push(match &record {
        Ok(r) => Check::pass(
            "record_parse",
            format!(
                "channel record well-formed (train '{}', channel '{}')",
                r.train, r.channel
            ),
        ),
        Err(e) => Check::fail("record_parse", format!("channel record unusable: {e}")),
    });
    let bom: Result<BomCore, String> = read_json(&bom_path);
    checks.push(match &bom {
        Ok(b) => Check::pass(
            "bom_parse",
            format!(
                "BOM well-formed (train '{}', bundle_seq {})",
                b.train, b.bundle_seq
            ),
        ),
        Err(e) => Check::fail("bom_parse", format!("BOM unusable: {e}")),
    });

    // --- §0 steps 3+4: the signed channel↔bundle binding ---------------------
    if let (Ok(rec), Ok(bom)) = (&record, &bom) {
        checks.push(if rec.train == bom.train {
            Check::pass(
                "train_match",
                format!("record and BOM both name train '{}'", bom.train),
            )
        } else {
            Check::fail(
                "train_match",
                format!(
                    "record names train '{}' but BOM is train '{}'",
                    rec.train, bom.train
                ),
            )
        });
        checks.push(if rec.bundle_seq == bom.bundle_seq {
            Check::pass(
                "seq_match",
                format!("record and BOM agree on bundle_seq {}", bom.bundle_seq),
            )
        } else {
            Check::fail(
                "seq_match",
                format!(
                    "record says bundle_seq {} but BOM says {}",
                    rec.bundle_seq, bom.bundle_seq
                ),
            )
        });
        checks.push(if rec.hardware_target == bom.hardware_target {
            Check::pass(
                "target_binding",
                format!(
                    "record and BOM both bind hardware_target '{}'",
                    bom.hardware_target
                ),
            )
        } else {
            Check::fail(
                "target_binding",
                format!(
                    "record targets '{}' but BOM targets '{}'",
                    rec.hardware_target, bom.hardware_target
                ),
            )
        });
    }

    // --- §0 step 5: the record must be for THIS device's channel -------------
    if let Ok(rec) = &record {
        checks.push(match &device_channel {
            Some(ch) if *ch == rec.channel => Check::pass(
                "channel_match",
                format!("record is for this device's channel '{ch}'"),
            ),
            Some(ch) => Check::fail(
                "channel_match",
                format!(
                    "record is for channel '{}' but this device follows '{ch}'",
                    rec.channel
                ),
            ),
            None => Check::unknown_device_input(
                "channel_match",
                "device channel (--device-channel / device_channel=)",
                cfg.enforce,
            ),
        });
        checks.push(if rec.hardware_target == hardware_target {
            Check::pass(
                "hardware_target",
                format!("record targets this host '{hardware_target}'"),
            )
        } else {
            Check::fail(
                "hardware_target",
                format!(
                    "record targets '{}' but immutable host target is '{hardware_target}'",
                    rec.hardware_target
                ),
            )
        });
    }

    // --- §0 step 6: anti-rollback against the applied state ------------------
    if let Ok(bom) = &bom {
        let bom_sha = runner::sha256_file(&bom_path)?;
        checks.push(anti_rollback_check(
            bom.bundle_seq,
            &bom_sha,
            &store,
            cfg.enforce,
        ));
    }

    // --- §0 step 7: compat ranges must OVERLAP (the full compat-range test) ------
    if let Ok(bom) = &bom {
        checks.push(compat_check(bom, device_compat, cfg.enforce));
    }

    // --- verdict --------------------------------------------------------------
    let ok = checks.iter().all(|c| c.ok);
    let verdict = Verdict {
        verdict: if ok { "pass" } else { "refuse" },
        checks,
        enforce: cfg.enforce,
    };
    let json = serde_json::to_string(&verdict)
        .map_err(|e| InternalError(format!("cannot serialize verdict: {e}")))?;
    println!("{json}");
    human_summary(&verdict);
    record_last_verdict(&cfg, &json);

    // Shadow mode is LOG-ONLY: a clean "refuse" verdict still exits 0 — the
    // caller decides nothing on the exit code in shadow. Internal errors never
    // reach this point (they exit 2 in every mode).
    Ok(if ok || !cfg.enforce {
        EXIT_PASS
    } else {
        EXIT_REFUSE
    })
}

pub(crate) fn applied_state_path(
    flags: &std::collections::HashMap<String, String>,
    cfg: &Config,
) -> Result<PathBuf, InternalError> {
    match flags.get("applied-state") {
        Some(p) => Ok(PathBuf::from(p)),
        None => cfg
            .state_dir
            .as_ref()
            .map(|d| d.join("applied.json"))
            .ok_or_else(|| {
                InternalError("no state_dir in config and no --applied-state".to_string())
            }),
    }
}

fn anti_rollback_check(
    bom_seq: u64,
    bom_sha: &str,
    store: &dyn AppliedStateStore,
    enforce: bool,
) -> Check {
    match store.read() {
        // Unseeded (plan P3 seeding rule): shadow passes WITH a warning — the
        // first `commit` seeds the record; enforce refuses — an enforcing
        // device with no baseline would accept any replayed signed bundle.
        Ok(StateRead::Unseeded) => {
            if enforce {
                Check::fail(
                    "unseeded",
                    format!("no applied state at {} and enforce=1 — refusing (enforcement is invalid on an unseeded device)", store.describe()),
                )
            } else {
                Check::pass(
                    "unseeded",
                    format!("WARNING: no applied state at {} — anti-rollback not evaluated (shadow mode; the first commit seeds it)", store.describe()),
                )
            }
        }
        Ok(StateRead::Applied(applied)) => {
            if bom_seq > applied.bundle_seq {
                Check::pass(
                    "anti_rollback",
                    format!("bundle_seq {bom_seq} > applied {}", applied.bundle_seq),
                )
            } else if bom_seq == applied.bundle_seq && bom_sha == applied.bom_sha256 {
                Check::pass(
                    "anti_rollback",
                    format!("bundle_seq {bom_seq} == applied and BOM hash matches — re-apply of the exact current bundle (repair)"),
                )
            } else if bom_seq == applied.bundle_seq {
                Check::fail(
                    "anti_rollback",
                    format!("bundle_seq {bom_seq} == applied but the BOM hash DIFFERS — two bundles claiming one seq is a forgery signal"),
                )
            } else {
                Check::fail(
                    "anti_rollback",
                    format!(
                        "ROLLBACK: bundle_seq {bom_seq} < applied {} — recovery is forward-only",
                        applied.bundle_seq
                    ),
                )
            }
        }
        // Corrupt/unreadable state: fail-closed CHECK failure (not internal),
        // so shadow burn-in logs it instead of blocking the whole update path.
        Err(why) => Check::fail(
            "anti_rollback",
            format!("applied state unusable ({why}) — fail-closed"),
        ),
    }
}

fn compat_check(bom: &BomCore, device: Option<(i64, i64)>, enforce: bool) -> Check {
    let (Some(lo), Some(hi)) = (bom.compat_min, bom.compat_version) else {
        return Check::fail(
            "compat_overlap",
            "BOM lacks compat_min/compat_version — malformed BOM".to_string(),
        );
    };
    if lo > hi {
        return Check::fail(
            "compat_overlap",
            format!("BOM compat range inverted ({lo} > {hi}) — malformed BOM"),
        );
    }
    match device {
        Some((dev_lo, dev_hi)) => {
            if lo <= dev_hi && dev_lo <= hi {
                Check::pass(
                    "compat_overlap",
                    format!("BOM [{lo},{hi}] overlaps device [{dev_lo},{dev_hi}]"),
                )
            } else {
                Check::fail(
                    "compat_overlap",
                    format!("BOM [{lo},{hi}] does not overlap device [{dev_lo},{dev_hi}]"),
                )
            }
        }
        None => Check::unknown_device_input(
            "compat_overlap",
            "device compat range (--device-compat / device_compat_min+max=)",
            enforce,
        ),
    }
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("{}: {e}", path.display()))
}

fn non_empty_file(path: &Path) -> bool {
    std::fs::metadata(path)
        .map(|m| m.is_file() && m.len() > 0)
        .unwrap_or(false)
}

fn human_summary(verdict: &Verdict) {
    let mode = if verdict.enforce {
        "enforce"
    } else {
        "shadow (log-only)"
    };
    eprintln!(
        "ni-ota-verify: verdict={} mode={mode}",
        verdict.verdict.to_uppercase()
    );
    for check in &verdict.checks {
        let mark = if check.ok { "ok  " } else { "FAIL" };
        eprintln!("  {mark} {:<14} {}", check.name, check.detail);
    }
}

/// Best-effort posture surface: the last verdict lands in state_dir so the
/// sovereignty check 14 (Fabric P2) can report it without re-running a verify.
/// Never fatal — observability must not block (or fake) a verdict.
fn record_last_verdict(cfg: &Config, json: &str) {
    let Some(dir) = &cfg.state_dir else { return };
    let write = || -> std::io::Result<()> {
        std::fs::create_dir_all(dir)?;
        std::fs::write(dir.join("last-verdict.json"), format!("{json}\n"))
    };
    if let Err(e) = write() {
        eprintln!(
            "ni-ota-verify: WARN: could not record last verdict in {}: {e}",
            dir.display()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MemStore(Result<Option<AppliedStateForTest>, String>);
    type AppliedStateForTest = crate::state::AppliedState;

    impl AppliedStateStore for MemStore {
        fn read(&self) -> Result<StateRead, String> {
            match &self.0 {
                Ok(Some(s)) => Ok(StateRead::Applied(s.clone())),
                Ok(None) => Ok(StateRead::Unseeded),
                Err(e) => Err(e.clone()),
            }
        }
        fn write(&self, _: &AppliedStateForTest) -> Result<(), InternalError> {
            unreachable!("verify never writes state")
        }
        fn describe(&self) -> String {
            "mem".to_string()
        }
    }

    fn applied(seq: u64, sha: &str) -> MemStore {
        MemStore(Ok(Some(AppliedStateForTest {
            bundle_seq: seq,
            bom_sha256: sha.to_string(),
        })))
    }

    #[test]
    fn anti_rollback_three_way() {
        let ok = anti_rollback_check(8, "aa", &applied(7, "xx"), true);
        assert!(ok.ok);
        let repair = anti_rollback_check(7, "xx", &applied(7, "xx"), true);
        assert!(repair.ok && repair.detail.contains("repair"));
        let forged = anti_rollback_check(7, "aa", &applied(7, "xx"), true);
        assert!(!forged.ok && forged.detail.contains("forgery"));
        let rollback = anti_rollback_check(6, "aa", &applied(7, "xx"), true);
        assert!(!rollback.ok && rollback.detail.contains("ROLLBACK"));
    }

    #[test]
    fn unseeded_depends_on_mode_and_corrupt_state_fails_closed() {
        let unseeded = MemStore(Ok(None));
        assert!(anti_rollback_check(8, "aa", &unseeded, false).ok);
        assert_eq!(
            anti_rollback_check(8, "aa", &unseeded, false).name,
            "unseeded"
        );
        assert!(!anti_rollback_check(8, "aa", &unseeded, true).ok);
        let corrupt = MemStore(Err("corrupt".to_string()));
        assert!(!anti_rollback_check(8, "aa", &corrupt, false).ok);
        assert!(!anti_rollback_check(8, "aa", &corrupt, true).ok);
    }

    #[test]
    fn compat_overlap_matrix() {
        let bom = |lo, hi| BomCore {
            train: "t".into(),
            hardware_target: "nvidia-gb10-arm64".into(),
            bundle_seq: 1,
            compat_min: lo,
            compat_version: hi,
        };
        assert!(compat_check(&bom(Some(1), Some(3)), Some((2, 4)), true).ok);
        assert!(compat_check(&bom(Some(1), Some(3)), Some((3, 3)), true).ok);
        assert!(!compat_check(&bom(Some(1), Some(3)), Some((4, 5)), true).ok);
        // missing/inverted BOM range = malformed → fails in BOTH modes
        assert!(!compat_check(&bom(None, Some(3)), Some((1, 3)), false).ok);
        assert!(!compat_check(&bom(Some(4), Some(3)), Some((1, 9)), false).ok);
        // unknown device range: shadow warns-and-skips, enforce refuses
        assert!(compat_check(&bom(Some(1), Some(3)), None, false).ok);
        assert!(!compat_check(&bom(Some(1), Some(3)), None, true).ok);
    }
}
