#![cfg(feature = "test-path-overrides")]

use std::fs;
use std::io::Write;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::{json, Value};

const SNAPSHOT_DOMAIN: &[u8] = b"neural-ice:ota:delegation-snapshot:v1\0";
const RELEASE_DOMAIN: &[u8] = b"neural-ice:ota:release-authorization:v1\0";
const INSTALLER_DOMAIN: &[u8] = b"neural-ice:installer:release-authorization:v2\0";
const REPOSITORY: &str = "release.example.test/neural-ice/neural-ice-appliance";
const INDEX: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const CHILD: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const SEED: &str = "cccccccccccccccccccccccccccccccccccccccc";
static SERIAL: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    root: PathBuf,
    config: PathBuf,
    set: PathBuf,
    snapshot: PathBuf,
    snapshot_sig: PathBuf,
    release: PathBuf,
    release_sig: PathBuf,
    bom: PathBuf,
    installer: PathBuf,
    installer_sig: PathBuf,
    candidate: PathBuf,
    receipt: PathBuf,
    sealed_set: String,
    sealed_installer: String,
    sealed_installer_sig: String,
}

impl Fixture {
    fn new(name: &str, mutate: impl FnOnce(&mut Documents)) -> Self {
        let root = std::env::temp_dir().join(format!(
            "ni-preseal-{name}-{}-{}",
            std::process::id(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        for directory in [
            "state",
            "state/preseal",
            "candidate/usr/lib/neural-ice/product-payload",
        ] {
            fs::create_dir_all(root.join(directory)).unwrap();
        }
        fs::set_permissions(root.join("state"), fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(
            root.join("state/preseal"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();

        let root_key = root.join("root.key");
        let root_pub = root.join("root.pub");
        let release_key = root.join("release.key");
        let release_pub = root.join("release.pub");
        keypair(&root_key, &root_pub);
        keypair(&release_key, &release_pub);
        let (root_b64, root_sha) = spki(&root_pub);
        let (release_b64, release_sha) = spki(&release_pub);
        let release_pem_sha = hash(&fs::read(&release_pub).unwrap());

        let policy = b"lab-managed\n";
        let policy_sha = hash(policy);
        let mut documents = Documents {
            snapshot: json!({
                "delegation_seq": 2,
                "issued_at": "2026-09-02T15:40:33Z",
                "keys": [{
                    "artifact_types": ["lab-publication-receipt", "lab-release-authorization"],
                    "hardware_targets": ["nvidia-gb10-arm64"],
                    "key_id": "release-lab-v1",
                    "predecessor_key_id": null,
                    "public_key": {"algorithm":"ecdsa-p256-sha256", "encoding":"spki-der-base64", "spki_der_base64":release_b64, "spki_sha256":release_sha},
                    "rings": ["lab"], "role": "release-lab",
                    "rotation_overlap": {"mode":"none", "valid_from":null, "valid_until":null, "with_key_id":null},
                    "signature_algorithm":"ecdsa-p256-sha256", "signature_encoding":"asn1-der",
                    "status":"active", "successor_key_id":null,
                    "valid_from":"2026-09-02T15:40:33Z", "valid_until":"2027-07-21T19:35:00Z"
                }],
                "previous_snapshot_sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                "root_key":{"key_id":"ota-root-v1", "public_key":{"algorithm":"ecdsa-p256-sha256", "encoding":"spki-der-base64", "spki_der_base64":root_b64, "spki_sha256":root_sha}, "root_version":1},
                "schema":"neural-ice-ota-delegation-snapshot-v1",
                "signature_algorithm":"ecdsa-p256-sha256", "signature_encoding":"asn1-der",
                "signing_role":"ota-root", "tombstones":[],
                "valid_from":"2026-09-02T15:40:33Z", "valid_until":"2027-07-21T19:35:00Z"
            }),
            release: json!({
                "access_policy_sha256": policy_sha,
                "access_profile":"lab-managed",
                "attestation_set_sha256":"1111111111111111111111111111111111111111111111111111111111111111",
                "beta_publication_receipt_sha256":null,
                "bom_sha256":"",
                "bundle_seq":5,
                "channel_record_sha256":"2222222222222222222222222222222222222222222222222222222222222222",
                "compat_max":5, "compat_min":5, "delegation_seq":2,
                "delegation_snapshot_sha256":"",
                "hardware_target":"nvidia-gb10-arm64",
                "issuance_id":"release-lab-0.50.9-5",
                "issued_at":"2026-09-05T00:00:00Z", "key_id":"release-lab-v1",
                "ring":"lab", "schema":"neural-ice-ota-release-authorization-v1",
                "signature_algorithm":"ecdsa-p256-sha256", "signature_encoding":"asn1-der",
                "signing_role":"release-lab", "train":"0.50.9-lab.20260905",
                "valid_from":"2026-09-05T00:00:00Z", "valid_until":"2026-10-05T00:00:00Z",
                "variant":"sealed-lab"
            }),
            installer: json!({
                "access_profile":"lab-managed", "hardware_target":"nvidia-gb10-arm64",
                "image_index_digest":INDEX, "image_manifest_digest":CHILD,
                "image_platform":"linux/arm64", "image_publication_shape":"index",
                "image_repository":REPOSITORY, "issuance_id":"install-lab-5",
                "issuance_seq":"5", "issued_at":"2026-09-05T00:00:00Z",
                "key_id":release_pem_sha, "schema":"neural-ice-installer-release-authorization-v2",
                "signed_boot_trust_policy_id":"neural-ice-secureboot-lab-v1", "variant":"sealed-lab"
            }),
            bom: json!({
                "appliance":{"os_base":{"digest":INDEX,"image":REPOSITORY},"version":"0.50.9-lab.20260905"},
                "bundle_seq":5,"compat_min":5,"compat_version":5,
                "hardware_target":"nvidia-gb10-arm64",
                "sources":{"seed":{"ref":SEED,"repo":"ICE-Fabric"}},
                "train":"0.50.9-lab.20260905"
            }),
            set_extra: None,
        };
        mutate(&mut documents);

        let snapshot_bytes = canonical(&documents.snapshot);
        let snapshot_sig_bytes = sign(&root, &root_key, SNAPSHOT_DOMAIN, &snapshot_bytes);
        let snapshot_canonical_sha = hash(&snapshot_bytes[..snapshot_bytes.len() - 1]);
        documents.release["delegation_snapshot_sha256"] = json!(snapshot_canonical_sha);
        let bom_bytes = serde_json::to_vec_pretty(&documents.bom).unwrap();
        documents.release["bom_sha256"] = json!(hash(&bom_bytes));
        let release_bytes = canonical(&documents.release);
        let release_sig_bytes = sign(&root, &release_key, RELEASE_DOMAIN, &release_bytes);
        let installer_bytes = canonical_no_lf(&documents.installer);
        let installer_sig_bytes =
            sign_exact(&root, &release_key, INSTALLER_DOMAIN, &installer_bytes);

        let mut set = json!({
            "access_policy_sha256":documents.release["access_policy_sha256"],
            "access_profile":"lab-managed",
            "attestation_set_sha256":documents.release["attestation_set_sha256"],
            "bom_file_sha256":hash(&bom_bytes), "bom_sha256":hash(&bom_bytes),
            "bundle_seq":5,
            "channel_record_sha256":documents.release["channel_record_sha256"],
            "compat_max":5,"compat_min":5,"delegation_seq":2,
            "delegation_snapshot_file_sha256":hash(&snapshot_bytes),
            "delegation_snapshot_sha256":snapshot_canonical_sha,
            "delegation_snapshot_signature_sha256":hash(&snapshot_sig_bytes),
            "hardware_target":"nvidia-gb10-arm64",
            "installer_authorization_sha256":hash(&installer_bytes),
            "installer_authorization_signature_sha256":hash(&installer_sig_bytes),
            "ota_release_authorization_file_sha256":hash(&release_bytes),
            "ota_release_authorization_sha256":hash(&release_bytes[..release_bytes.len()-1]),
            "ota_release_authorization_signature_sha256":hash(&release_sig_bytes),
            "ota_state_profile":"owner-sealed-ota-state-v1",
            "release_key_id":"release-lab-v1","release_signing_role":"release-lab",
            "ring":"lab","schema":"neural-ice-installer-preseal-set-v1",
            "seed_ref":SEED,"signed_boot_trust_policy_id":"neural-ice-secureboot-lab-v1",
            "target_os_ref":format!("{REPOSITORY}@{INDEX}"),
            "train":"0.50.9-lab.20260905","variant":"sealed-lab"
        });
        if let Some((key, value)) = documents.set_extra {
            set[key] = value;
        }
        let set_bytes = canonical(&set);

        let paths = [
            ("snapshot.json", snapshot_bytes.as_slice()),
            ("snapshot.sig", snapshot_sig_bytes.as_slice()),
            ("release.json", release_bytes.as_slice()),
            ("release.sig", release_sig_bytes.as_slice()),
            ("bom.json", bom_bytes.as_slice()),
            ("installer.json", installer_bytes.as_slice()),
            ("installer.sig", installer_sig_bytes.as_slice()),
            ("set.json", set_bytes.as_slice()),
        ];
        for (name, bytes) in paths {
            fs::write(root.join(name), bytes).unwrap();
        }
        fs::write(root.join("hardware-target"), "nvidia-gb10-arm64\n").unwrap();
        fs::write(root.join("appliance-variant"), "sealed-lab\n").unwrap();
        fs::write(root.join("min-delegation-seq"), "2\n").unwrap();
        fs::write(
            root.join("bootstrap-delegation-sha256"),
            format!("{snapshot_canonical_sha}\n"),
        )
        .unwrap();
        fs::write(
            root.join("candidate/usr/lib/neural-ice/access-policy"),
            policy,
        )
        .unwrap();
        fs::write(
            root.join("candidate/usr/lib/neural-ice/hardware-target"),
            "nvidia-gb10-arm64\n",
        )
        .unwrap();
        fs::write(
            root.join("candidate/usr/lib/neural-ice/appliance-variant"),
            "sealed-lab\n",
        )
        .unwrap();
        fs::write(
            root.join("candidate/usr/lib/neural-ice/signed-boot-trust-policy-id"),
            "neural-ice-secureboot-lab-v1\n",
        )
        .unwrap();
        fs::write(
            root.join("candidate/usr/lib/neural-ice/ota-state-profile"),
            "owner-sealed-ota-state-v1\n",
        )
        .unwrap();
        fs::write(
            root.join("candidate/usr/lib/neural-ice/product-payload/PAYLOAD_ID"),
            format!("{SEED}\n"),
        )
        .unwrap();
        fs::write(root.join("ota.conf"), format!("enforce=1\nroot_pubkey={}\nstate_dir={}\ndevice_compat_min=5\ndevice_compat_max=5\n", root_pub.display(), root.join("state").display())).unwrap();
        let cosign = root.join("cosign");
        fs::write(&cosign, COSIGN).unwrap();
        fs::set_permissions(&cosign, fs::Permissions::from_mode(0o755)).unwrap();

        Self {
            config: root.join("ota.conf"),
            set: root.join("set.json"),
            snapshot: root.join("snapshot.json"),
            snapshot_sig: root.join("snapshot.sig"),
            release: root.join("release.json"),
            release_sig: root.join("release.sig"),
            bom: root.join("bom.json"),
            installer: root.join("installer.json"),
            installer_sig: root.join("installer.sig"),
            candidate: root.join("candidate"),
            receipt: root.join("state/preseal/receipt.json"),
            sealed_set: hash(&set_bytes),
            sealed_installer: hash(&installer_bytes),
            sealed_installer_sig: hash(&installer_sig_bytes),
            root,
        }
    }

    fn command(&self) -> Command {
        self.command_with(&format!("{REPOSITORY}@{INDEX}"), CHILD, SEED)
    }

    fn command_with(&self, os_ref: &str, child: &str, seed: &str) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_ni-ota-verify"));
        command
            .args(["verify-preseal-baseline", "--set"])
            .arg(&self.set)
            .arg("--snapshot")
            .arg(&self.snapshot)
            .arg("--snapshot-sig")
            .arg(&self.snapshot_sig)
            .arg("--release")
            .arg(&self.release)
            .arg("--release-sig")
            .arg(&self.release_sig)
            .arg("--bom")
            .arg(&self.bom)
            .arg("--installer-authorization")
            .arg(&self.installer)
            .arg("--installer-authorization-sig")
            .arg(&self.installer_sig)
            .arg("--sealed-set-sha256")
            .arg(&self.sealed_set)
            .arg("--sealed-installer-authorization-sha256")
            .arg(&self.sealed_installer)
            .arg("--sealed-installer-authorization-signature-sha256")
            .arg(&self.sealed_installer_sig)
            .args(["--current-os-ref", os_ref])
            .args([
                "--current-os-manifest-digest",
                child,
                "--current-seed-ref",
                seed,
            ])
            .arg("--candidate-root")
            .arg(&self.candidate)
            .arg("--receipt-out")
            .arg(&self.receipt)
            .arg("--config")
            .arg(&self.config)
            .env("NI_OTA_COSIGN", self.root.join("cosign"))
            .env(
                "NI_OTA_HARDWARE_TARGET_FILE",
                self.root.join("hardware-target"),
            )
            .env(
                "NI_OTA_APPLIANCE_VARIANT_FILE",
                self.root.join("appliance-variant"),
            )
            .env(
                "NI_OTA_MIN_DELEGATION_SEQ_FILE",
                self.root.join("min-delegation-seq"),
            )
            .env(
                "NI_OTA_BOOTSTRAP_DELEGATION_SHA256_FILE",
                self.root.join("bootstrap-delegation-sha256"),
            );
        command
    }

    fn run(&self) -> Output {
        self.command().output().unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

struct Documents {
    snapshot: Value,
    release: Value,
    installer: Value,
    bom: Value,
    set_extra: Option<(&'static str, Value)>,
}

type DocumentMutation = fn(&mut Documents);

#[test]
fn authentic_preseal_is_exactly_idempotent_and_writes_no_runtime_state() {
    let fixture = Fixture::new("success", |_| {});
    let first = fixture.run();
    assert_eq!(
        first.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(String::from_utf8_lossy(&first.stdout).contains("\"idempotent\":false"));
    let receipt = fs::read(&fixture.receipt).unwrap();
    assert!(receipt.ends_with(b"\n"));
    let parsed: Value = serde_json::from_slice(&receipt).unwrap();
    assert_eq!(parsed["schema"], "neural-ice-ota-preseal-receipt-v1");
    assert_eq!(parsed["ota_state_profile"], "owner-sealed-ota-state-v1");
    assert_eq!(parsed["preseal_set_sha256"], fixture.sealed_set);
    assert_eq!(parsed["release_issued_at"], "2026-09-05T00:00:00Z");
    assert_eq!(
        canonical(&parsed),
        receipt,
        "receipt is not canonical JSON+LF"
    );
    assert_eq!(
        fs::metadata(&fixture.receipt).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(!fixture.root.join("state/applied.json").exists());
    assert!(!fixture.root.join("state/state-v1").exists());

    let second = fixture.run();
    assert_eq!(
        second.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );
    assert!(String::from_utf8_lossy(&second.stdout).contains("\"idempotent\":true"));
    assert_eq!(fs::read(&fixture.receipt).unwrap(), receipt);
}

#[test]
fn cryptographic_scope_and_cross_document_mismatches_fail_closed() {
    let cases: &[(&str, DocumentMutation)] = &[
        ("unknown-set", |d| {
            d.set_extra = Some(("unknown", json!(true)))
        }),
        ("wrong-role", |d| {
            d.release["signing_role"] = json!("release-beta")
        }),
        ("wrong-key", |d| {
            d.release["key_id"] = json!("release-lab-v2")
        }),
        ("inactive-key", |d| {
            d.snapshot["keys"][0]["status"] = json!("retired")
        }),
        ("wrong-target", |d| {
            d.release["hardware_target"] = json!("generic-arm64")
        }),
        ("wrong-variant", |d| {
            d.release["variant"] = json!("sealed-enterprise")
        }),
        ("wrong-bundle", |d| d.bom["bundle_seq"] = json!(6)),
        ("wrong-seed", |d| {
            d.bom["sources"]["seed"]["ref"] = json!("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
        }),
        ("bad-time", |d| {
            d.release["issued_at"] = json!("2026-09-06T00:00:00Z")
        }),
        ("bad-profile", |d| {
            d.release["access_profile"] = json!("customer-locked")
        }),
        ("bad-installer-sequence", |d| {
            d.installer["issuance_seq"] = json!("05")
        }),
        ("backdated-installer", |d| {
            d.installer["issued_at"] = json!("2026-09-01T00:00:00Z")
        }),
    ];
    for (name, mutate) in cases {
        let fixture = Fixture::new(name, *mutate);
        let output = fixture.run();
        assert_eq!(
            output.status.code(),
            Some(1),
            "{name}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!fixture.receipt.exists(), "{name} published a receipt");
    }

    let mut signature = Fixture::new("signature", |_| {});
    fs::write(
        &signature.release_sig,
        fs::read(&signature.installer_sig).unwrap(),
    )
    .unwrap();
    rewrite_set_hash(
        &signature.set,
        "ota_release_authorization_signature_sha256",
        &hash(&fs::read(&signature.release_sig).unwrap()),
    );
    signature.sealed_set = hash(&fs::read(&signature.set).unwrap());
    assert_eq!(signature.run().status.code(), Some(1));

    let mut installer_signature = Fixture::new("installer-signature", |_| {});
    fs::write(
        &installer_signature.installer_sig,
        fs::read(&installer_signature.release_sig).unwrap(),
    )
    .unwrap();
    let installer_sig_hash = hash(&fs::read(&installer_signature.installer_sig).unwrap());
    rewrite_set_hash(
        &installer_signature.set,
        "installer_authorization_signature_sha256",
        &installer_sig_hash,
    );
    installer_signature.sealed_installer_sig = installer_sig_hash;
    installer_signature.sealed_set = hash(&fs::read(&installer_signature.set).unwrap());
    assert_eq!(installer_signature.run().status.code(), Some(1));

    let child = Fixture::new("child", |_| {});
    let output = child
        .command_with(
            &format!("{REPOSITORY}@{INDEX}"),
            "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            SEED,
        )
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));

    let index = Fixture::new("index", |_| {});
    let output = index
        .command_with(
            &format!("{REPOSITORY}@sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"),
            CHILD,
            SEED,
        )
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));

    let seed = Fixture::new("seed-arg", |_| {});
    let output = seed
        .command_with(
            &format!("{REPOSITORY}@{INDEX}"),
            CHILD,
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        )
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));

    let mut duplicate = Fixture::new("duplicate", |_| {});
    let original = fs::read_to_string(&duplicate.set).unwrap();
    fs::write(
        &duplicate.set,
        original.replacen(
            '{',
            "{\"schema\":\"neural-ice-installer-preseal-set-v1\",",
            1,
        ),
    )
    .unwrap();
    duplicate.sealed_set = hash(&fs::read(&duplicate.set).unwrap());
    assert_eq!(duplicate.run().status.code(), Some(1));
}

#[test]
fn immutable_epoch_compat_candidate_and_raw_byte_changes_are_refused() {
    let epoch = Fixture::new("epoch", |_| {});
    fs::write(epoch.root.join("min-delegation-seq"), "3\n").unwrap();
    assert_eq!(epoch.run().status.code(), Some(1));

    let compat = Fixture::new("compat", |_| {});
    fs::write(
        &compat.config,
        format!(
            "enforce=1\nroot_pubkey={}\nstate_dir={}\ndevice_compat_min=4\ndevice_compat_max=5\n",
            compat.root.join("root.pub").display(),
            compat.root.join("state").display()
        ),
    )
    .unwrap();
    assert_eq!(compat.run().status.code(), Some(1));

    let marker = Fixture::new("marker", |_| {});
    fs::write(
        marker
            .candidate
            .join("usr/lib/neural-ice/ota-state-profile"),
        "some-other-profile\n",
    )
    .unwrap();
    assert_eq!(marker.run().status.code(), Some(1));

    let missing_payload = Fixture::new("missing-payload", |_| {});
    fs::remove_file(
        missing_payload
            .candidate
            .join("usr/lib/neural-ice/product-payload/PAYLOAD_ID"),
    )
    .unwrap();
    assert_eq!(missing_payload.run().status.code(), Some(1));

    let wrong_payload = Fixture::new("wrong-payload", |_| {});
    fs::write(
        wrong_payload
            .candidate
            .join("usr/lib/neural-ice/product-payload/PAYLOAD_ID"),
        "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\n",
    )
    .unwrap();
    assert_eq!(wrong_payload.run().status.code(), Some(1));

    let raw = Fixture::new("raw", |_| {});
    fs::OpenOptions::new()
        .append(true)
        .open(&raw.release)
        .unwrap()
        .write_all(b" ")
        .unwrap();
    assert_eq!(raw.run().status.code(), Some(1));
}

#[test]
fn hostile_files_and_drifting_receipts_never_admit() {
    let drift = Fixture::new("drift", |_| {});
    assert_eq!(drift.run().status.code(), Some(0));
    fs::write(&drift.receipt, b"{}\n").unwrap();
    fs::set_permissions(&drift.receipt, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(drift.run().status.code(), Some(1));

    let metadata = Fixture::new("metadata", |_| {});
    assert_eq!(metadata.run().status.code(), Some(0));
    fs::set_permissions(&metadata.receipt, fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(metadata.run().status.code(), Some(1));

    let insecure_parent = Fixture::new("insecure-parent", |_| {});
    fs::set_permissions(
        insecure_parent.root.join("state/preseal"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    assert_eq!(insecure_parent.run().status.code(), Some(1));

    let linked = Fixture::new("symlink", |_| {});
    fs::rename(&linked.set, linked.root.join("set.real")).unwrap();
    symlink(linked.root.join("set.real"), &linked.set).unwrap();
    assert_eq!(linked.run().status.code(), Some(1));

    let oversized = Fixture::new("oversized", |_| {});
    fs::write(&oversized.set, vec![b'x'; 16 * 1024 + 1]).unwrap();
    assert_eq!(oversized.run().status.code(), Some(1));

    let fifo = Fixture::new("fifo", |_| {});
    fs::remove_file(&fifo.set).unwrap();
    assert!(Command::new("mkfifo")
        .arg(&fifo.set)
        .status()
        .unwrap()
        .success());
    assert_eq!(fifo.run().status.code(), Some(1));

    let payload_link = Fixture::new("payload-link", |_| {});
    let payload = payload_link
        .candidate
        .join("usr/lib/neural-ice/product-payload/PAYLOAD_ID");
    fs::remove_file(&payload).unwrap();
    symlink(payload_link.root.join("set.json"), &payload).unwrap();
    assert_eq!(payload_link.run().status.code(), Some(1));

    let payload_oversized = Fixture::new("payload-oversized", |_| {});
    fs::write(
        payload_oversized
            .candidate
            .join("usr/lib/neural-ice/product-payload/PAYLOAD_ID"),
        vec![b'x'; 257],
    )
    .unwrap();
    assert_eq!(payload_oversized.run().status.code(), Some(1));

    let payload_directory = Fixture::new("payload-directory", |_| {});
    let payload = payload_directory
        .candidate
        .join("usr/lib/neural-ice/product-payload/PAYLOAD_ID");
    fs::remove_file(&payload).unwrap();
    fs::create_dir(&payload).unwrap();
    assert_eq!(payload_directory.run().status.code(), Some(1));

    let receipt_link = Fixture::new("receipt-link", |_| {});
    fs::write(receipt_link.root.join("elsewhere"), b"{}\n").unwrap();
    symlink(receipt_link.root.join("elsewhere"), &receipt_link.receipt).unwrap();
    assert_eq!(receipt_link.run().status.code(), Some(1));

    let receipt_fifo = Fixture::new("receipt-fifo", |_| {});
    assert!(Command::new("mkfifo")
        .arg(&receipt_fifo.receipt)
        .status()
        .unwrap()
        .success());
    assert_eq!(receipt_fifo.run().status.code(), Some(1));

    let no_tpm = Fixture::new("no-tpm", |_| {});
    let bin = no_tpm.root.join("bin");
    fs::create_dir(&bin).unwrap();
    let called = no_tpm.root.join("tpm-called");
    for tool in ["tpm2_nvread", "tpm2_nvwrite", "tpm2_nvdefine", "tpm2_clear"] {
        let path = bin.join(tool);
        fs::write(
            &path,
            format!(
                "#!/bin/sh\nprintf called > '{}'\nexit 99\n",
                called.display()
            ),
        )
        .unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let output = no_tpm
        .command()
        .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!called.exists(), "preseal invoked a TPM utility");
}

fn rewrite_set_hash(path: &Path, field: &str, digest: &str) {
    let mut value: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    value[field] = json!(digest);
    fs::write(path, canonical(&value)).unwrap();
}

fn keypair(private: &Path, public: &Path) {
    assert!(Command::new("openssl")
        .args([
            "ecparam",
            "-name",
            "prime256v1",
            "-genkey",
            "-noout",
            "-out"
        ])
        .arg(private)
        .status()
        .unwrap()
        .success());
    assert!(Command::new("openssl")
        .args(["pkey", "-in"])
        .arg(private)
        .args(["-pubout", "-out"])
        .arg(public)
        .status()
        .unwrap()
        .success());
}

fn spki(public: &Path) -> (String, String) {
    let output = Command::new("openssl")
        .args(["pkey", "-pubin", "-in"])
        .arg(public)
        .args(["-outform", "DER"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let encoded = Command::new("openssl")
        .args(["base64", "-A"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            child.stdin.take().unwrap().write_all(&output.stdout)?;
            child.wait_with_output()
        })
        .unwrap();
    (
        String::from_utf8(encoded.stdout).unwrap(),
        hash(&output.stdout),
    )
}

fn canonical(value: &Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(value).unwrap();
    bytes.push(b'\n');
    bytes
}

fn canonical_no_lf(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}

fn sign(root: &Path, key: &Path, domain: &[u8], payload: &[u8]) -> Vec<u8> {
    sign_message(root, key, domain, &payload[..payload.len() - 1])
}

fn sign_exact(root: &Path, key: &Path, domain: &[u8], payload: &[u8]) -> Vec<u8> {
    sign_message(root, key, domain, payload)
}

fn sign_message(root: &Path, key: &Path, domain: &[u8], payload: &[u8]) -> Vec<u8> {
    let message = root.join(format!(
        "message-{}",
        SERIAL.fetch_add(1, Ordering::Relaxed)
    ));
    let signature = root.join(format!(
        "signature-{}",
        SERIAL.fetch_add(1, Ordering::Relaxed)
    ));
    let mut bytes = domain.to_vec();
    bytes.extend_from_slice(payload);
    fs::write(&message, bytes).unwrap();
    for _ in 0..128 {
        let status = Command::new("openssl")
            .args(["dgst", "-sha256", "-sign"])
            .arg(key)
            .arg("-out")
            .arg(&signature)
            .arg(&message)
            .status()
            .unwrap();
        assert!(status.success());
        let bytes = fs::read(&signature).unwrap();
        if low_s(&bytes) {
            let _ = fs::remove_file(&message);
            let _ = fs::remove_file(&signature);
            return bytes;
        }
    }
    panic!("OpenSSL did not generate a low-S signature");
}

fn low_s(der: &[u8]) -> bool {
    const HALF: [u8; 32] = [
        0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b,
        0x20, 0xa0,
    ];
    if der.len() < 8 || der[0] != 0x30 || der[2] != 0x02 {
        return false;
    }
    let rlen = der[3] as usize;
    let spos = 4 + rlen;
    if spos + 2 > der.len() || der[spos] != 0x02 {
        return false;
    }
    let slen = der[spos + 1] as usize;
    if spos + 2 + slen != der.len() {
        return false;
    }
    let mut s = &der[spos + 2..];
    if s.first() == Some(&0) {
        s = &s[1..];
    }
    s.len() < 32 || (s.len() == 32 && s <= HALF.as_slice())
}

fn hash(bytes: &[u8]) -> String {
    let mut child = Command::new("sha256sum")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(bytes).unwrap();
    String::from_utf8(child.wait_with_output().unwrap().stdout)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .to_owned()
}

const COSIGN: &str = r#"#!/bin/sh
set -eu
[ "$1" = verify-blob ]
shift
key= signature=
while [ "$#" -gt 1 ]; do
  case "$1" in
    --key) key=$2; shift 2 ;;
    --signature) signature=$2; shift 2 ;;
    --insecure-ignore-tlog|--insecure-ignore-tlog=true|--offline) shift ;;
    *) break ;;
  esac
done
[ "$#" -eq 1 ] && [ -n "$key" ] && [ -n "$signature" ]
der="${signature}.der"
trap 'rm -f "$der"' EXIT HUP INT TERM
base64 -d "$signature" > "$der"
openssl dgst -sha256 -verify "$key" -signature "$der" "$1" >/dev/null
"#;
