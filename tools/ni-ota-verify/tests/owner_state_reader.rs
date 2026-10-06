#![cfg(all(target_os = "linux", feature = "test-path-overrides"))]

use std::fs;
use std::io::Write;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

static NEXT: AtomicU64 = AtomicU64::new(0);
const OWNER_REPOSITORY: &str = "release.example.test/neural-ice/neural-ice-appliance";
const OWNER_INDEX: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const OWNER_CHILD: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const OWNER_CHECKSUM: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

struct Fixture {
    root: PathBuf,
    state: PathBuf,
    scratch: PathBuf,
    config: PathBuf,
    nvreadpublic: PathBuf,
    forbidden: PathBuf,
    calls: PathBuf,
}

impl Fixture {
    fn new(name: &str, public: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "ni-owner-reader-{name}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let state = root.join("state");
        let scratch = root.join("run");
        fs::create_dir(&state).unwrap();
        fs::create_dir(&scratch).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&scratch, fs::Permissions::from_mode(0o700)).unwrap();
        let root_key = root.join("root.pub");
        fs::write(&root_key, b"public fixture only\n").unwrap();
        let config = root.join("ota.conf");
        fs::write(
            &config,
            format!(
                "enforce=1\nroot_pubkey={}\nstate_dir={}\ndevice_compat_min=5\ndevice_compat_max=5\n",
                root_key.display(),
                state.display()
            ),
        )
        .unwrap();
        let calls = root.join("calls");
        let nvreadpublic = root.join("tpm2_nvreadpublic");
        fs::write(
            &nvreadpublic,
            format!(
                "#!/bin/sh\nprintf 'nvreadpublic %s\\n' \"$*\" >> '{}'\ncat <<'EOF'\n{}EOF\n",
                calls.display(),
                public
            ),
        )
        .unwrap();
        fs::set_permissions(&nvreadpublic, fs::Permissions::from_mode(0o755)).unwrap();
        let forbidden = root.join("forbidden-tpm-mutation");
        fs::write(
            &forbidden,
            format!(
                "#!/bin/sh\nprintf 'FORBIDDEN %s\\n' \"$*\" >> '{}'\nexit 99\n",
                calls.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&forbidden, fs::Permissions::from_mode(0o755)).unwrap();
        Self {
            root,
            state,
            scratch,
            config,
            nvreadpublic,
            forbidden,
            calls,
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_ni-ota-verify"));
        command
            .arg("authenticated-ota-status")
            .env("NI_OTA_AUTH_STATUS_CONFIG", &self.config)
            .env("NI_OTA_AUTH_STATUS_SCRATCH_ROOT", &self.scratch)
            .env("NI_OTA_TPM2_NVREADPUBLIC", &self.nvreadpublic)
            .env("NI_OTA_TPM2_NVDEFINE", &self.forbidden)
            .env("NI_OTA_TPM2_NVEXTEND", &self.forbidden)
            .env("NI_OTA_TPM2_NVWRITE", &self.forbidden)
            .env("NI_OTA_TPM2_NVWRITELOCK", &self.forbidden)
            .env("NI_OTA_TPM2_NVUNDEFINE", &self.forbidden)
            .env("NI_OTA_TPM2_CLEAR", &self.forbidden)
            .env("NI_OTA_TPM2_CHANGEAUTH", &self.forbidden);
        command
    }

    fn run(&self) -> Output {
        self.command().output().unwrap()
    }

    fn replace_nvreadpublic(&self, script: &str) {
        fs::write(&self.nvreadpublic, script).unwrap();
        fs::set_permissions(&self.nvreadpublic, fs::Permissions::from_mode(0o755)).unwrap();
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn owner_public(name: &str, attributes: &str) -> String {
    format!(
        "0x01500002:\n  name: {name}\n  hash algorithm:\n    friendly: sha256\n    value: 0xB\n  attributes:\n    friendly: {attributes}\n    value: 0x0\n  size: 32\n  authorization policy: b6a2e7142ee56fd978047488483daa5b42b8dc4cc7ddcceddfb91793cf1ff1b7\n"
    )
}

fn metadata(path: &Path) -> (u64, u64, u32, u32, u32, u64, i64, i64, i64, i64) {
    let value = fs::symlink_metadata(path).unwrap();
    (
        value.dev(),
        value.ino(),
        value.mode(),
        value.uid(),
        value.gid(),
        value.size(),
        value.atime(),
        value.atime_nsec(),
        value.mtime(),
        value.mtime_nsec(),
    )
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
        .into()
}

fn canonical(value: &Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(value).unwrap();
    bytes.push(b'\n');
    bytes
}

fn base64(bytes: &[u8]) -> String {
    let mut child = Command::new("base64")
        .arg("-w0")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(bytes).unwrap();
    let mut encoded = String::from_utf8(child.wait_with_output().unwrap().stdout).unwrap();
    encoded.push('\n');
    encoded
}

fn openssl(args: &[&str]) {
    let output = Command::new("openssl").args(args).output().unwrap();
    assert!(
        output.status.success(),
        "openssl {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn write_mode(path: &Path, bytes: &[u8], mode: u32) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

fn sign(key: &Path, domain: &[u8], document: &[u8], root: &Path, name: &str) -> Vec<u8> {
    let payload = root.join(format!("{name}.payload"));
    let signature = root.join(format!("{name}.der"));
    let mut bytes = domain.to_vec();
    bytes.extend_from_slice(document);
    fs::write(&payload, bytes).unwrap();
    for _ in 0..128 {
        openssl(&[
            "dgst",
            "-sha256",
            "-sign",
            key.to_str().unwrap(),
            "-out",
            signature.to_str().unwrap(),
            payload.to_str().unwrap(),
        ]);
        let bytes = fs::read(&signature).unwrap();
        if low_s(&bytes) {
            return bytes;
        }
    }
    panic!("OpenSSL did not generate a low-S fixture signature")
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
    let rlen = usize::from(der[3]);
    let spos = 4 + rlen;
    if spos + 2 > der.len() || der[spos] != 0x02 {
        return false;
    }
    let slen = usize::from(der[spos + 1]);
    if spos + 2 + slen != der.len() {
        return false;
    }
    let mut s = &der[spos + 2..];
    if s.first() == Some(&0) {
        s = &s[1..];
    }
    s.len() < 32 || (s.len() == 32 && s <= HALF.as_slice())
}

fn hex_bytes(value: &str) -> String {
    (0..value.len())
        .step_by(2)
        .map(|index| {
            format!(
                "\\0{:03o}",
                u8::from_str_radix(&value[index..index + 2], 16).unwrap()
            )
        })
        .collect()
}

struct AccessFiles {
    key: PathBuf,
    spki: PathBuf,
    name: String,
    binding: String,
    evidence_anchor: Value,
}

fn install_access_profile(fixture: &Fixture, profile: &str) -> AccessFiles {
    write_mode(
        &fixture.root.join("cosign"),
        br#"#!/bin/sh
set -eu
[ "$1" = verify-blob ]; shift
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
"#,
        0o755,
    );
    let key = fixture.root.join("device-root.key");
    let spki = fixture.root.join("device-root.der");
    openssl(&[
        "ecparam",
        "-name",
        "prime256v1",
        "-genkey",
        "-noout",
        "-out",
        key.to_str().unwrap(),
    ]);
    openssl(&[
        "ec",
        "-in",
        key.to_str().unwrap(),
        "-pubout",
        "-outform",
        "DER",
        "-out",
        spki.to_str().unwrap(),
    ]);
    let spki_bytes = fs::read(&spki).unwrap();
    let spki_hash = hash(&spki_bytes);
    let public_hash = hash(b"owner-reader-device-root-public-area");
    let name = format!("000b{public_hash}");
    let anchor = format!(
        "{{\"access_profile\":\"{profile}\",\"anchor_seq\":1,\"device_root_handle\":\"0x81010005\",\"device_root_name\":\"{name}\",\"device_root_spki_sha256\":\"{spki_hash}\",\"enrolled_at\":\"2026-09-05T00:00:00Z\",\"hardware_target\":\"nvidia-gb10-arm64\",\"schema\":\"neural-ice-access-profile-anchor-v1\",\"signed_boot_trust_policy_id\":\"neural-ice-secureboot-lab-v1\"}}"
    );
    let signature = sign(
        &key,
        b"neural-ice:ota:access-profile-anchor:v1\0",
        anchor.as_bytes(),
        &fixture.root,
        "anchor",
    );
    write_mode(
        &fixture.state.join("access-profile-v1.json"),
        anchor.as_bytes(),
        0o600,
    );
    write_mode(
        &fixture.state.join("access-profile-v1.sig"),
        base64(&signature).as_bytes(),
        0o600,
    );
    write_mode(
        &fixture.state.join("access-profile-v1.spki"),
        base64(&spki_bytes).as_bytes(),
        0o600,
    );
    write_mode(
        &fixture.state.join("device-root-v1.json"),
        format!("{{\"attributes\":\"sign\",\"handle\":\"0x81010005\",\"name\":\"{name}\",\"schema\":\"neural-ice-device-root-tpm-v1\",\"spki_sha256\":\"{spki_hash}\"}}\n").as_bytes(),
        0o600,
    );
    let mut binding_input = b"neural-ice:tpm:access-profile-binding:v1\0".to_vec();
    binding_input.extend_from_slice(profile.as_bytes());
    binding_input.extend_from_slice(b"\0nvidia-gb10-arm64\0neural-ice-secureboot-lab-v1");
    let binding = hash(&binding_input);
    AccessFiles {
        key,
        spki,
        name,
        binding,
        evidence_anchor: json!({
            "json_sha256": hash(anchor.as_bytes()),
            "signature_sha256": hash(base64(&signature).as_bytes()),
            "spki_sha256": hash(base64(&spki_bytes).as_bytes())
        }),
    }
}

fn install_completion_v1(fixture: &Fixture, access: &AccessFiles) {
    let evidence = canonical(&json!({
        "access_profile_anchor": access.evidence_anchor,
        "schema": "neural-ice-owner-ceremony-evidence-v1"
    }));
    write_mode(
        &fixture.state.join("owner-ceremony-evidence-v1.json"),
        &evidence,
        0o600,
    );
    let inspection = canonical(&json!({
        "completion_version": 1,
        "evidence_digest_sha256": hash(&evidence),
        "schema": "neural-ice-owner-ceremony-completion-inspection-v1"
    }));
    fs::write(fixture.root.join("completion-inspection.json"), inspection).unwrap();
    write_mode(
        &fixture.root.join("tpm-state"),
        format!(
            "#!/bin/sh\n[ \"$#\" -eq 1 ] && [ \"$1\" = completion-inspect ] || exit 97\nprintf 'completion %s\\n' \"$*\" >> '{}'\ncat '{}'\n",
            fixture.calls.display(),
            fixture.root.join("completion-inspection.json").display()
        )
        .as_bytes(),
        0o755,
    );
}

fn install_read_only_tpm(
    fixture: &Fixture,
    access: &AccessFiles,
    state_public: &str,
    state_anchor: Option<&str>,
    legacy_floor: u64,
) {
    let public = fixture.root.join("tpm2_nvreadpublic-success");
    write_mode(
        &public,
        format!(
            "#!/bin/sh\nprintf 'nvreadpublic %s\\n' \"$*\" >> '{}'\ncase \"$1\" in\n  0x01500005) cat <<'EOF'\n0x1500005:\n  name: 000b0000\n  hash algorithm:\n    friendly: sha256\n    value: 0xB\n  attributes:\n    friendly: policywrite|writedefine|ownerread|authread\n    value: 0x20062808\n  size: 64\n  authorization policy: F83217E5A2A04342F7DAA55CCFB3CD4B8A1F1E8EBB28C7719A9ABBDBD638A230\nEOF\n  ;;\n  0x01500002) cat <<'EOF'\n{state_public}EOF\n  ;;\n  *) exit 97 ;;\nesac\n",
            fixture.calls.display()
        )
        .as_bytes(),
        0o755,
    );
    let state_anchor = state_anchor.map_or_else(|| "00".repeat(32), str::to_owned);
    let nvread = fixture.root.join("tpm2_nvread");
    write_mode(
        &nvread,
        format!(
            r#"#!/bin/sh
printf 'nvread %s\n' "$*" >> '{}'
out=""
index=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    -C|-s) shift 2 ;;
    0x*) index="$1"; shift ;;
    *) shift ;;
  esac
done
case "$index" in
  0x01500001) python3 -c 'import struct,sys; open(sys.argv[1],"wb").write(struct.pack(">Q", int(sys.argv[2])))' "$out" '{legacy_floor}' ;;
  0x01500002) python3 -c 'import sys; open(sys.argv[1],"wb").write(bytes.fromhex(sys.argv[2]))' "$out" '{state_anchor}' ;;
  0x01500003) python3 -c 'import struct,sys; open(sys.argv[1],"wb").write(struct.pack(">Q", 1))' "$out" ;;
  0x01500005) python3 -c 'import sys; open(sys.argv[1],"wb").write((b"NI-TPM02"+bytes.fromhex(sys.argv[2])+(2408).to_bytes(8,"big")+(1750).to_bytes(8,"big")).ljust(64,b"\0"))' "$out" '{}' ;;
  *) exit 97 ;;
esac
"#,
            fixture.calls.display(),
            access.binding
        )
        .as_bytes(),
        0o755,
    );
    let readpublic = fixture.root.join("tpm2_readpublic");
    write_mode(
        &readpublic,
        format!(
            r#"#!/bin/sh
printf 'readpublic %s\n' "$*" >> '{}'
out=""
mode=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) out="$2"; mode=spki; shift 2 ;;
    -n) out="$2"; mode=name; shift 2 ;;
    -c|-f) shift 2 ;;
    *) shift ;;
  esac
done
if [ "$mode" = name ]; then printf '\000\013%b' '{}' > "$out"; else cp '{}' "$out"; fi
"#,
            fixture.calls.display(),
            hex_bytes(access.name.strip_prefix("000b").unwrap()),
            access.spki.display()
        )
        .as_bytes(),
        0o755,
    );
    let sign_tool = fixture.root.join("tpm2_sign");
    write_mode(
        &sign_tool,
        format!(
            r#"#!/bin/sh
printf 'sign %s\n' "$*" >> '{}'
out=""; message=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    -c|-g|-s|-f) shift 2 ;;
    -Q) shift ;;
    *) message="$1"; shift ;;
  esac
done
der="$out.der"
openssl dgst -sha256 -sign '{}' -out "$der" "$message" || exit 2
python3 - "$der" "$out" <<'PY'
import sys
raw=open(sys.argv[1],'rb').read(); body=raw[2:2+raw[1]]
def take(value):
    n=value[1]; return int.from_bytes(value[2:2+n],'big'), value[2+n:]
r,rest=take(body); s,rest=take(rest); assert not rest
open(sys.argv[2],'wb').write(bytes.fromhex('0018000b0020')+r.to_bytes(32,'big')+bytes.fromhex('0020')+s.to_bytes(32,'big'))
PY
rm -f "$der"
"#,
            fixture.calls.display(),
            access.key.display()
        )
        .as_bytes(),
        0o755,
    );
    let getcap = fixture.root.join("tpm2_getcap");
    write_mode(
        &getcap,
        format!(
            "#!/bin/sh\nprintf 'getcap %s\\n' \"$*\" >> '{}'\nprintf 'TPM2_PT_PERMANENT:\\n  ownerAuthSet: 1\\n'\n",
            fixture.calls.display()
        )
        .as_bytes(),
        0o755,
    );
}

fn success_command(fixture: &Fixture) -> Command {
    let mut command = fixture.command();
    command
        .env("NI_OTA_COSIGN", fixture.root.join("cosign"))
        .env(
            "NI_OTA_TPM2_NVREADPUBLIC",
            fixture.root.join("tpm2_nvreadpublic-success"),
        )
        .env("NI_OTA_TPM2_NVREAD", fixture.root.join("tpm2_nvread"))
        .env(
            "NI_OTA_TPM2_READPUBLIC",
            fixture.root.join("tpm2_readpublic"),
        )
        .env("NI_OTA_TPM2_SIGN", fixture.root.join("tpm2_sign"))
        .env("NI_OTA_TPM2_GETCAP", fixture.root.join("tpm2_getcap"))
        .env("NI_OTA_TPM_STATE_HELPER", fixture.root.join("tpm-state"))
        .env(
            "NI_OTA_HARDWARE_TARGET_FILE",
            fixture.root.join("hardware-target"),
        )
        .env(
            "NI_OTA_APPLIANCE_VARIANT_FILE",
            fixture.root.join("appliance-variant"),
        )
        .env(
            "NI_OTA_MIN_DELEGATION_SEQ_FILE",
            fixture.root.join("min-delegation-seq"),
        )
        .env(
            "NI_OTA_BOOTSTRAP_DELEGATION_SHA256_FILE",
            fixture.root.join("bootstrap-delegation-sha256"),
        );
    command
}

struct OstreeFixture {
    bootc_denied: PathBuf,
    command: PathBuf,
    deployment_root: PathBuf,
    metadata: PathBuf,
    origin: PathBuf,
    status: PathBuf,
}

fn owner_status_command(
    fixture: &Fixture,
    profile: &Path,
    payload: &Path,
    ostree: &OstreeFixture,
) -> Command {
    let mut command = success_command(fixture);
    command
        // The old implementation consumes this seam and reproduces the
        // capability-bound bootc failure. The capability-free implementation
        // does not read it.
        .env("NI_OTA_AUTH_STATUS_BOOTC", &ostree.bootc_denied)
        .env("NI_OTA_AUTH_STATUS_PROFILE_MARKER", profile)
        .env("NI_OTA_AUTH_STATUS_OSTREE", &ostree.command)
        .env("NI_OTA_AUTH_STATUS_DEPLOY_ROOT", &ostree.deployment_root)
        .env("NI_OTA_AUTH_STATUS_PAYLOAD_ID", payload);
    command
}

fn run_owner_status(
    fixture: &Fixture,
    profile: &Path,
    payload: &Path,
    ostree: &OstreeFixture,
) -> Output {
    owner_status_command(fixture, profile, payload, ostree)
        .env(
            "NI_OTA_OWNER_STATE_HELPER",
            fixture.root.join("owner-state"),
        )
        .output()
        .unwrap()
}

fn assert_owner_status_refused(fixture: &Fixture, output: &Output, before: &[ObservedTreeEntry]) {
    assert_eq!(
        output.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());
    assert_eq!(observe_tree(&fixture.state), before);
    assert_eq!(fs::read_dir(&fixture.scratch).unwrap().count(), 0);
}

fn write_default_ostree_command(command: &Path, status: &Path, metadata: &Path) {
    write_mode(
        command,
        format!(
            "#!/bin/sh\nif [ \"$#\" -eq 3 ] && [ \"$1 $2 $3\" = 'admin status --json' ]; then\n  cat '{}'\nelif [ \"$#\" -eq 4 ] && [ \"$1\" = show ] && [ \"$2\" = --repo=/sysroot/ostree/repo ] && [ \"$3\" = --print-metadata-key=ostree.manifest-digest ] && [ \"$4\" = {OWNER_CHECKSUM} ]; then\n  cat '{}'\nelse\n  exit 97\nfi\n",
            status.display(),
            metadata.display()
        )
        .as_bytes(),
        0o755,
    );
}

fn install_ostree_fixture(fixture: &Fixture) -> OstreeFixture {
    assert_ne!(OWNER_INDEX, OWNER_CHILD);
    let status = fixture.root.join("ostree-status.json");
    fs::write(
        &status,
        serde_json::to_vec(&json!({"deployments":[{
            "booted":true,"checksum":OWNER_CHECKSUM,"serial":0,"stateroot":"default"
        }]}))
        .unwrap(),
    )
    .unwrap();
    let metadata = fixture.root.join("ostree-manifest-digest");
    fs::write(&metadata, format!("'{OWNER_CHILD}'\n")).unwrap();
    let command = fixture.root.join("ostree");
    write_default_ostree_command(&command, &status, &metadata);
    let bootc_denied = fixture.root.join("bootc-denied");
    write_mode(
        &bootc_denied,
        b"#!/bin/sh\necho 'requires full root privileges (CAP_SYS_ADMIN)' >&2\nexit 1\n",
        0o755,
    );
    let deployment_root = fixture.root.join("ostree-deploy");
    let stateroot = deployment_root.join("default");
    let deployment = stateroot.join("deploy");
    fs::create_dir_all(&deployment).unwrap();
    for directory in [&deployment_root, &stateroot, &deployment] {
        fs::set_permissions(directory, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let origin = deployment.join(format!("{OWNER_CHECKSUM}.0.origin"));
    write_mode(
        &origin,
        format!(
            "[origin]\ncontainer-image-reference=ostree-unverified-registry:{OWNER_REPOSITORY}@{OWNER_INDEX}\n"
        )
        .as_bytes(),
        0o644,
    );
    OstreeFixture {
        bootc_denied,
        command,
        deployment_root,
        metadata,
        origin,
        status,
    }
}

fn install_historical_state(fixture: &Fixture) -> (String, String) {
    let root = fixture.state.join("state-v1");
    let generations = root.join("generations");
    let generation = generations.join("generation-0000000000000001");
    for directory in [&root, &generations, &generation] {
        fs::create_dir(directory).unwrap();
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let snapshot = b"{}\n";
    let assertion = b"{}\n";
    let snapshot_sig = b"snapshot-signature";
    let release = b"{}\n";
    let release_sig = b"release-signature";
    let assertion_sig = b"trusted-time-signature";
    let snapshot_canonical = hash(b"{}");
    let assertion_canonical = hash(b"{}");
    let applied = canonical(&json!({
        "bom_sha256": "1".repeat(64), "bundle_seq": 1,
        "schema": "neural-ice-ota-applied-state-v1"
    }));
    let authority = canonical(&json!({
        "delegation_seq": 1, "schema": "neural-ice-ota-authority-state-v1",
        "snapshot_sha256": snapshot_canonical,
        "snapshot_signature_sha256": hash(snapshot_sig)
    }));
    let trusted = canonical(&json!({
        "assertion_seq":1,"assertion_sha256":assertion_canonical,
        "challenge_sha256":hash(b"challenge"),"delegation_seq":1,
        "device_fingerprint":"d".repeat(64),"key_id":"trusted-time-v1",
        "schema":"neural-ice-ota-trusted-time-state-v2",
        "signature_sha256":hash(assertion_sig),"tpm_clock":1000,
        "tpm_reset_count":1,"tpm_restart_count":1,"tpm_safe":true,
        "trusted_time":"2026-07-21T12:00:00Z"
    }));
    for (name, bytes) in [
        ("applied.json", applied.as_slice()),
        ("authority.json", authority.as_slice()),
        ("delegation-snapshot.json", snapshot),
        ("delegation-snapshot.sig", snapshot_sig),
        ("release-authorization.json", release),
        ("release-authorization.sig", release_sig),
        ("trusted-time-assertion.json", assertion),
        ("trusted-time-assertion.sig", assertion_sig),
        ("trusted-time.json", trusted.as_slice()),
    ] {
        write_mode(&generation.join(name), bytes, 0o600);
    }
    let manifest = canonical(&json!({
        "applied_sha256":hash(&applied),"applied_bom_sha256":"1".repeat(64),
        "authority_sha256":hash(&authority),"bundle_seq_floor":1,
        "delegation_seq_floor":1,"delegation_snapshot_canonical_sha256":snapshot_canonical,
        "delegation_snapshot_sha256":hash(snapshot),
        "delegation_snapshot_signature_sha256":hash(snapshot_sig),"generation":1,
        "legacy_bundle_floor":1,"previous_manifest_sha256":null,
        "previous_nv_anchor":"0".repeat(64),"release_authorization_sha256":hash(release),
        "release_authorization_signature_sha256":hash(release_sig),
        "schema":"neural-ice-ota-state-manifest-v1",
        "trusted_time_assertion_canonical_sha256":assertion_canonical,
        "trusted_time_assertion_sha256":hash(assertion),
        "trusted_time_assertion_signature_sha256":hash(assertion_sig),
        "trusted_time_floor":"2026-07-21T12:00:00Z","trusted_time_seq_floor":1,
        "trusted_time_sha256":hash(&trusted)
    }));
    write_mode(&generation.join("manifest.json"), &manifest, 0o600);
    let manifest_hash = hash(&manifest);
    let mut extend = vec![0_u8; 32];
    for index in (0..manifest_hash.len()).step_by(2) {
        extend.push(u8::from_str_radix(&manifest_hash[index..index + 2], 16).unwrap());
    }
    let anchor = hash(&extend);
    write_mode(
        &root.join("current"),
        b"generation-0000000000000001\n",
        0o600,
    );
    let ready = canonical(&json!({
        "manifest_sha256":manifest_hash,"nv_anchor":anchor,
        "schema":"neural-ice-ota-enforce-ready-v1"
    }));
    write_mode(&root.join("enforce-ready.json"), &ready, 0o600);
    (manifest_hash, anchor)
}

#[derive(Debug, Eq, PartialEq)]
struct ObservedTreeEntry {
    relative: PathBuf,
    bytes: Option<Vec<u8>>,
    metadata: (u64, u64, u32, u32, u32, u64, i64, i64, i64, i64),
}

fn observe_tree(root: &Path) -> Vec<ObservedTreeEntry> {
    fn visit(root: &Path, current: &Path, out: &mut Vec<ObservedTreeEntry>) {
        let mut entries: Vec<_> = fs::read_dir(current)
            .unwrap()
            .map(|entry| entry.unwrap())
            .collect();
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let path = entry.path();
            let initial = fs::symlink_metadata(&path).unwrap();
            let bytes = initial
                .file_type()
                .is_file()
                .then(|| fs::read(&path).unwrap());
            let value = fs::symlink_metadata(&path).unwrap();
            out.push(ObservedTreeEntry {
                relative: path.strip_prefix(root).unwrap().to_owned(),
                bytes,
                metadata: (
                    value.dev(),
                    value.ino(),
                    value.mode(),
                    value.uid(),
                    value.gid(),
                    value.size(),
                    value.mtime(),
                    value.mtime_nsec(),
                    value.ctime(),
                    value.ctime_nsec(),
                ),
            });
            if value.file_type().is_dir() {
                visit(root, &path, out);
            }
        }
    }
    let mut out = Vec::new();
    visit(root, root, &mut out);
    out
}

#[test]
fn public_historical_ready_status_is_exact_and_read_only() {
    let fixture = Fixture::new("historical-success", "");
    let access = install_access_profile(&fixture, "lab-managed");
    install_completion_v1(&fixture, &access);
    let (_, anchor) = install_historical_state(&fixture);
    let public = "0x01500002:\n  name: 000b571132a9688f4088f3696fa9bf5d5793be7483202cee08ceb2261f2bbe89b440\n  hash algorithm:\n    friendly: sha256\n    value: 0xB\n  attributes:\n    friendly: authwrite|nt=0x1|policydelete|ownerread|authread|no_da|written|platformcreate\n    value: 0x62060444\n  size: 32\n  authorization policy: 921F9FA2CE8C30BBF29B84500A8456188F1FEBC04F154E9ECCCA4D5B1BC8A25D\n".to_owned();
    install_read_only_tpm(&fixture, &access, &public, Some(&anchor), 1);
    let before = observe_tree(&fixture.state);
    let output = success_command(&fixture).output().unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        output.stdout,
        b"{\"committed_generation\":1,\"completion_version\":1,\"enforce_ready_verified\":true,\"profile\":\"retained-platform-state-v1\",\"schema\":\"neural-ice-authenticated-ota-status-v1\"}\n"
    );
    assert!(output.stderr.is_empty());
    assert_eq!(observe_tree(&fixture.state), before);
    assert_eq!(fs::read_dir(&fixture.scratch).unwrap().count(), 0);
    let calls = fs::read_to_string(&fixture.calls).unwrap();
    assert!(!calls.contains("FORBIDDEN"), "{calls}");
    assert!(calls.matches("0x01500002").count() >= 4, "{calls}");
    assert!(calls.matches("0x01500001").count() >= 2, "{calls}");
}

fn public_spki(public: &Path) -> (String, String) {
    let output = Command::new("openssl")
        .args(["pkey", "-pubin", "-in"])
        .arg(public)
        .args(["-outform", "DER"])
        .output()
        .unwrap();
    assert!(output.status.success());
    (
        base64(&output.stdout).trim().to_owned(),
        hash(&output.stdout),
    )
}

fn install_owner_preseal(fixture: &Fixture) -> (String, String) {
    const SEED: &str = "cccccccccccccccccccccccccccccccccccccccc";
    let input = fixture.state.join("preseal-input-v1");
    let preseal = fixture.state.join("preseal");
    let candidate = fixture
        .root
        .join("candidate/usr/lib/neural-ice/product-payload");
    for directory in [&input, &preseal, &candidate] {
        fs::create_dir_all(directory).unwrap();
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let root_key = fixture.root.join("ota-root.key");
    let release_key = fixture.root.join("release.key");
    let release_pub = fixture.root.join("release.pub");
    openssl(&[
        "ecparam",
        "-name",
        "prime256v1",
        "-genkey",
        "-noout",
        "-out",
        root_key.to_str().unwrap(),
    ]);
    openssl(&[
        "pkey",
        "-in",
        root_key.to_str().unwrap(),
        "-pubout",
        "-out",
        fixture.root.join("root.pub").to_str().unwrap(),
    ]);
    openssl(&[
        "ecparam",
        "-name",
        "prime256v1",
        "-genkey",
        "-noout",
        "-out",
        release_key.to_str().unwrap(),
    ]);
    openssl(&[
        "pkey",
        "-in",
        release_key.to_str().unwrap(),
        "-pubout",
        "-out",
        release_pub.to_str().unwrap(),
    ]);
    let (root_b64, root_sha) = public_spki(&fixture.root.join("root.pub"));
    let (release_b64, release_sha) = public_spki(&release_pub);
    let release_pem_sha = hash(&fs::read(&release_pub).unwrap());
    let policy_sha = hash(b"lab-managed\n");
    let snapshot = canonical(&json!({
        "delegation_seq":2,"issued_at":"2026-09-02T15:40:33Z",
        "keys":[{"artifact_types":["lab-publication-receipt","lab-release-authorization"],
            "hardware_targets":["nvidia-gb10-arm64"],"key_id":"release-lab-v1",
            "predecessor_key_id":null,
            "public_key":{"algorithm":"ecdsa-p256-sha256","encoding":"spki-der-base64","spki_der_base64":release_b64,"spki_sha256":release_sha},
            "rings":["lab"],"role":"release-lab","rotation_overlap":{"mode":"none","valid_from":null,"valid_until":null,"with_key_id":null},
            "signature_algorithm":"ecdsa-p256-sha256","signature_encoding":"asn1-der","status":"active","successor_key_id":null,
            "valid_from":"2026-09-02T15:40:33Z","valid_until":"2027-07-21T19:35:00Z"}],
        "previous_snapshot_sha256":"d".repeat(64),
        "root_key":{"key_id":"ota-root-v1","public_key":{"algorithm":"ecdsa-p256-sha256","encoding":"spki-der-base64","spki_der_base64":root_b64,"spki_sha256":root_sha},"root_version":1},
        "schema":"neural-ice-ota-delegation-snapshot-v1","signature_algorithm":"ecdsa-p256-sha256",
        "signature_encoding":"asn1-der","signing_role":"ota-root","tombstones":[],
        "valid_from":"2026-09-02T15:40:33Z","valid_until":"2027-07-21T19:35:00Z"
    }));
    let snapshot_sig = sign(
        &root_key,
        b"neural-ice:ota:delegation-snapshot:v1\0",
        &snapshot[..snapshot.len() - 1],
        &fixture.root,
        "snapshot",
    );
    let snapshot_canonical = hash(&snapshot[..snapshot.len() - 1]);
    let bom = serde_json::to_vec_pretty(&json!({
        "appliance":{"os_base":{"digest":OWNER_INDEX,"image":OWNER_REPOSITORY},"version":"0.50.9-lab.20260905"},
        "bundle_seq":5,"compat_min":5,"compat_version":5,"hardware_target":"nvidia-gb10-arm64",
        "sources":{"seed":{"ref":SEED,"repo":"ICE-Fabric"}},"train":"0.50.9-lab.20260905"
    }))
    .unwrap();
    let release = canonical(&json!({
        "access_policy_sha256":policy_sha,"access_profile":"lab-managed","attestation_set_sha256":"1".repeat(64),
        "beta_publication_receipt_sha256":null,"bom_sha256":hash(&bom),"bundle_seq":5,
        "channel_record_sha256":"2".repeat(64),"compat_max":5,"compat_min":5,"delegation_seq":2,
        "delegation_snapshot_sha256":snapshot_canonical,"hardware_target":"nvidia-gb10-arm64",
        "issuance_id":"release-lab-0.50.9-5","issued_at":"2026-09-05T00:00:00Z","key_id":"release-lab-v1",
        "ring":"lab","schema":"neural-ice-ota-release-authorization-v1","signature_algorithm":"ecdsa-p256-sha256",
        "signature_encoding":"asn1-der","signing_role":"release-lab","train":"0.50.9-lab.20260905",
        "valid_from":"2026-09-05T00:00:00Z","valid_until":"2026-10-05T00:00:00Z","variant":"sealed-lab"
    }));
    let release_sig = sign(
        &release_key,
        b"neural-ice:ota:release-authorization:v1\0",
        &release[..release.len() - 1],
        &fixture.root,
        "release",
    );
    let installer = serde_json::to_vec(&json!({
        "access_profile":"lab-managed","hardware_target":"nvidia-gb10-arm64","image_index_digest":OWNER_INDEX,
        "image_manifest_digest":OWNER_CHILD,"image_platform":"linux/arm64","image_publication_shape":"index",
        "image_repository":OWNER_REPOSITORY,"issuance_id":"install-lab-5","issuance_seq":"5",
        "issued_at":"2026-09-05T00:00:00Z","key_id":release_pem_sha,
        "schema":"neural-ice-installer-release-authorization-v2","signed_boot_trust_policy_id":"neural-ice-secureboot-lab-v1","variant":"sealed-lab"
    })).unwrap();
    let installer_sig = sign(
        &release_key,
        b"neural-ice:installer:release-authorization:v2\0",
        &installer,
        &fixture.root,
        "installer",
    );
    let set = canonical(&json!({
        "access_policy_sha256":policy_sha,"access_profile":"lab-managed","attestation_set_sha256":"1".repeat(64),
        "bom_file_sha256":hash(&bom),"bom_sha256":hash(&bom),"bundle_seq":5,
        "channel_record_sha256":"2".repeat(64),"compat_max":5,"compat_min":5,"delegation_seq":2,
        "delegation_snapshot_file_sha256":hash(&snapshot),"delegation_snapshot_sha256":snapshot_canonical,
        "delegation_snapshot_signature_sha256":hash(&snapshot_sig),"hardware_target":"nvidia-gb10-arm64",
        "installer_authorization_sha256":hash(&installer),"installer_authorization_signature_sha256":hash(&installer_sig),
        "ota_release_authorization_file_sha256":hash(&release),"ota_release_authorization_sha256":hash(&release[..release.len()-1]),
        "ota_release_authorization_signature_sha256":hash(&release_sig),"ota_state_profile":"owner-sealed-ota-state-v1",
        "release_key_id":"release-lab-v1","release_signing_role":"release-lab","ring":"lab",
        "schema":"neural-ice-installer-preseal-set-v1","seed_ref":SEED,
        "signed_boot_trust_policy_id":"neural-ice-secureboot-lab-v1","target_os_ref":format!("{OWNER_REPOSITORY}@{OWNER_INDEX}"),
        "train":"0.50.9-lab.20260905","variant":"sealed-lab"
    }));
    for (name, bytes) in [
        ("preseal-set.json", set.as_slice()),
        ("delegation-snapshot.json", snapshot.as_slice()),
        ("delegation-snapshot.sig", snapshot_sig.as_slice()),
        ("ota-release-authorization.json", release.as_slice()),
        ("ota-release-authorization.sig", release_sig.as_slice()),
        ("bom.json", bom.as_slice()),
        (
            "installer-release-authorization-v2.json",
            installer.as_slice(),
        ),
        (
            "installer-release-authorization-v2.sig",
            installer_sig.as_slice(),
        ),
    ] {
        write_mode(&input.join(name), bytes, 0o600);
    }
    let marker = fixture.root.join("candidate/usr/lib/neural-ice");
    fs::create_dir_all(&marker).unwrap();
    for (name, value) in [
        ("access-policy", "lab-managed\n"),
        ("hardware-target", "nvidia-gb10-arm64\n"),
        ("appliance-variant", "sealed-lab\n"),
        (
            "signed-boot-trust-policy-id",
            "neural-ice-secureboot-lab-v1\n",
        ),
        ("ota-state-profile", "owner-sealed-ota-state-v1\n"),
    ] {
        fs::write(marker.join(name), value).unwrap();
    }
    fs::write(candidate.join("PAYLOAD_ID"), format!("{SEED}\n")).unwrap();
    for (name, value) in [
        ("hardware-target", "nvidia-gb10-arm64\n"),
        ("appliance-variant", "sealed-lab\n"),
        ("min-delegation-seq", "2\n"),
        (
            "bootstrap-delegation-sha256",
            &format!("{snapshot_canonical}\n"),
        ),
    ] {
        fs::write(fixture.root.join(name), value).unwrap();
    }
    let receipt = preseal.join("receipt.json");
    let output = Command::new(env!("CARGO_BIN_EXE_ni-ota-verify"))
        .args(["verify-preseal-baseline", "--set"])
        .arg(input.join("preseal-set.json"))
        .arg("--snapshot")
        .arg(input.join("delegation-snapshot.json"))
        .arg("--snapshot-sig")
        .arg(input.join("delegation-snapshot.sig"))
        .arg("--release")
        .arg(input.join("ota-release-authorization.json"))
        .arg("--release-sig")
        .arg(input.join("ota-release-authorization.sig"))
        .arg("--bom")
        .arg(input.join("bom.json"))
        .arg("--installer-authorization")
        .arg(input.join("installer-release-authorization-v2.json"))
        .arg("--installer-authorization-sig")
        .arg(input.join("installer-release-authorization-v2.sig"))
        .arg("--sealed-set-sha256")
        .arg(hash(&set))
        .arg("--sealed-installer-authorization-sha256")
        .arg(hash(&installer))
        .arg("--sealed-installer-authorization-signature-sha256")
        .arg(hash(&installer_sig))
        .args([
            "--current-os-ref",
            &format!("{OWNER_REPOSITORY}@{OWNER_INDEX}"),
            "--current-os-manifest-digest",
            OWNER_CHILD,
            "--current-seed-ref",
            SEED,
        ])
        .arg("--candidate-root")
        .arg(fixture.root.join("candidate"))
        .arg("--receipt-out")
        .arg(&receipt)
        .arg("--config")
        .arg(&fixture.config)
        .env("NI_OTA_COSIGN", fixture.root.join("cosign"))
        .env(
            "NI_OTA_HARDWARE_TARGET_FILE",
            fixture.root.join("hardware-target"),
        )
        .env(
            "NI_OTA_APPLIANCE_VARIANT_FILE",
            fixture.root.join("appliance-variant"),
        )
        .env(
            "NI_OTA_MIN_DELEGATION_SEQ_FILE",
            fixture.root.join("min-delegation-seq"),
        )
        .env(
            "NI_OTA_BOOTSTRAP_DELEGATION_SHA256_FILE",
            fixture.root.join("bootstrap-delegation-sha256"),
        )
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    (hash(&fs::read(&receipt).unwrap()), hash(&set))
}

fn install_completion_v2(
    fixture: &Fixture,
    access: &AccessFiles,
    receipt_sha256: &str,
    set_sha256: &str,
) {
    let luks = json!({
        "keyslot":"0","pcr_bank":"sha256","pcrs":[7],"policy_hash":"11".repeat(32),
        "policy_public_key_sha256":"22".repeat(32),"schema":"neural-ice-luks-token-evidence-v1",
        "sealed_object_sha256":"33".repeat(32),"srk_sha256":"44".repeat(32),"token_sha256":"55".repeat(32)
    });
    let evidence = canonical(&json!({
        "access_profile_anchor":access.evidence_anchor,"data_luks":luks,
        "device_root_name":format!("000b{}", "11".repeat(32)),
        "install_identity":{"install_source":"medium","installed_at":"2026-09-05T00:00:00Z",
            "installer_sealed_identity_sha256":"66".repeat(32),"release_identity_sha256":"77".repeat(32),
            "schema":"neural-ice-owner-ceremony-install-identity-v1"},
        "ota_preseal":{"receipt_schema":"neural-ice-ota-preseal-receipt-v1","receipt_sha256":receipt_sha256,"set_sha256":set_sha256},
        "ota_state":{"anchor_attributes":"0x2060048","anchor_index":"0x01500002",
            "anchor_name_at_completion":"000b038de2091c1c8ef2e8fd8869f17bef3a576ae287530fa17f05ae3b9712014b5d",
            "anchor_policy_sha256":"b6a2e7142ee56fd978047488483daa5b42b8dc4cc7ddcceddfb91793cf1ff1b7",
            "anchor_pristine_name":"000b038de2091c1c8ef2e8fd8869f17bef3a576ae287530fa17f05ae3b9712014b5d",
            "anchor_size":32,"anchor_state_at_completion":"pristine",
            "anchor_written_name":"000b11afd155aca82a503f2029cc11395389654c3a25fc54b9eca6d33abdff498d56",
            "baseline_floor":5,"clear_protected_at_completion":true,"floor_attributes":"0x62008",
            "floor_index":"0x01500001","floor_name":"000be283f20a38b93f8cef085efb4aee9f5944cc3b3b28b850bf3c0eeb2054cd7fc4",
            "floor_policy_sha256":"f83217e5a2a04342f7daa55ccfb3cd4b8a1f1e8ebb28c7719a9abbdbd638a230",
            "floor_size":8,"profile":"owner-sealed-ota-state-v1"},
        "schema":"neural-ice-owner-ceremony-evidence-v2","srk_name":format!("000b{}", "aa".repeat(32)),
        "system_luks":luks,"tpm_state":{"freshness_counter":5,"freshness_public_sha256":"bb".repeat(32),
            "install_counter":1,"install_public_sha256":"cc".repeat(32),"profile_binding":"dd".repeat(32),
            "schema":"neural-ice-tpm-state-snapshot-v1"}
    }));
    write_mode(
        &fixture.state.join("owner-ceremony-evidence-v2.json"),
        &evidence,
        0o600,
    );
    let mut completion_message = b"neural-ice:tpm:owner-ceremony-completion:v2\0".to_vec();
    completion_message.extend_from_slice(&evidence);
    fs::write(
        fixture.root.join("completion-inspection.json"),
        canonical(
            &json!({"completion_version":2,"evidence_digest_sha256":hash(&completion_message),
            "schema":"neural-ice-owner-ceremony-completion-inspection-v1"}),
        ),
    )
    .unwrap();
    write_mode(&fixture.root.join("tpm-state"), format!(
        "#!/bin/sh\n[ \"$#\" -eq 1 ] && [ \"$1\" = completion-inspect ] || exit 97\nprintf 'completion %s\\n' \"$*\" >> '{}'\ncat '{}'\n",
        fixture.calls.display(), fixture.root.join("completion-inspection.json").display()).as_bytes(), 0o755);
    fs::write(fixture.root.join("owner-inspection.json"), canonical(&json!({
        "anchor_attributes":"0x2060048","anchor_index":"0x01500002",
        "anchor_name":"000b038de2091c1c8ef2e8fd8869f17bef3a576ae287530fa17f05ae3b9712014b5d",
        "anchor_policy_sha256":"b6a2e7142ee56fd978047488483daa5b42b8dc4cc7ddcceddfb91793cf1ff1b7",
        "anchor_sha256":null,"anchor_size":32,"anchor_state":"pristine","baseline_floor":5,
        "clear_protected":true,"floor_attributes":"0x62008","floor_index":"0x01500001",
        "floor_name":"000be283f20a38b93f8cef085efb4aee9f5944cc3b3b28b850bf3c0eeb2054cd7fc4",
        "floor_policy_sha256":"f83217e5a2a04342f7daa55ccfb3cd4b8a1f1e8ebb28c7719a9abbdbd638a230",
        "floor_size":8,"owner_sealed":true,"profile":"owner-sealed-ota-state-v1",
        "schema":"neural-ice-owner-ota-state-inspection-v2"
    }))).unwrap();
    write_mode(&fixture.root.join("owner-state"), format!(
        "#!/bin/sh\n[ \"$#\" -eq 1 ] && [ \"$1\" = inspect-v2 ] || exit 97\nprintf 'owner-inspect %s\\n' \"$*\" >> '{}'\ncat '{}'\n",
        fixture.calls.display(), fixture.root.join("owner-inspection.json").display()).as_bytes(), 0o755);
}

#[test]
fn public_owner_pristine_status_is_exact_and_read_only() {
    let fixture = Fixture::new("owner-success", "");
    let access = install_access_profile(&fixture, "lab-managed");
    let (receipt_sha, set_sha) = install_owner_preseal(&fixture);
    install_completion_v2(&fixture, &access, &receipt_sha, &set_sha);
    let public = owner_public(
        "000b038de2091c1c8ef2e8fd8869f17bef3a576ae287530fa17f05ae3b9712014b5d",
        "policywrite|authread|ownerread|no_da|nt=extend",
    );
    install_read_only_tpm(&fixture, &access, &public, None, 5);
    let profile = fixture.root.join("ota-state-profile");
    write_mode(&profile, b"owner-sealed-ota-state-v1\n", 0o444);
    let payload = fixture.root.join("PAYLOAD_ID");
    write_mode(
        &payload,
        b"cccccccccccccccccccccccccccccccccccccccc\n",
        0o644,
    );
    let ostree = install_ostree_fixture(&fixture);
    let before = observe_tree(&fixture.state);
    let output = owner_status_command(&fixture, &profile, &payload, &ostree)
        .env(
            "NI_OTA_OWNER_STATE_HELPER",
            fixture.root.join("owner-state"),
        )
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"{\"committed_generation\":null,\"completion_version\":2,\"enforce_ready_verified\":false,\"profile\":\"owner-sealed-ota-state-v1\",\"schema\":\"neural-ice-authenticated-ota-status-v1\"}\n");
    assert!(output.stderr.is_empty());
    assert_eq!(observe_tree(&fixture.state), before);
    assert_eq!(fs::read_dir(&fixture.scratch).unwrap().count(), 0);
    let calls = fs::read_to_string(&fixture.calls).unwrap();
    assert!(!calls.contains("FORBIDDEN"), "{calls}");
    assert_eq!(
        calls.matches("owner-inspect inspect-v2").count(),
        2,
        "{calls}"
    );

    // The image producer seals this marker as 0444. A writable marker is not
    // the shipped contract, even when its contents name the expected profile.
    fs::set_permissions(&profile, fs::Permissions::from_mode(0o644)).unwrap();
    let rejected = owner_status_command(&fixture, &profile, &payload, &ostree)
        .env(
            "NI_OTA_OWNER_STATE_HELPER",
            fixture.root.join("owner-state"),
        )
        .output()
        .unwrap();
    assert_eq!(rejected.status.code(), Some(1));
    assert!(rejected.stdout.is_empty());
    assert!(String::from_utf8_lossy(&rejected.stderr)
        .contains("cannot authenticate immutable OTA profile marker"));
    assert_eq!(observe_tree(&fixture.state), before);
    assert_eq!(fs::read_dir(&fixture.scratch).unwrap().count(), 0);
}

#[test]
fn owner_pristine_baseline_refuses_hostile_or_changing_ostree_identity() {
    let fixture = Fixture::new("owner-hostile-ostree", "");
    let access = install_access_profile(&fixture, "lab-managed");
    let (receipt_sha, set_sha) = install_owner_preseal(&fixture);
    install_completion_v2(&fixture, &access, &receipt_sha, &set_sha);
    let public = owner_public(
        "000b038de2091c1c8ef2e8fd8869f17bef3a576ae287530fa17f05ae3b9712014b5d",
        "policywrite|authread|ownerread|no_da|nt=extend",
    );
    install_read_only_tpm(&fixture, &access, &public, None, 5);
    let profile = fixture.root.join("ota-state-profile");
    write_mode(&profile, b"owner-sealed-ota-state-v1\n", 0o444);
    let payload = fixture.root.join("PAYLOAD_ID");
    write_mode(
        &payload,
        b"cccccccccccccccccccccccccccccccccccccccc\n",
        0o644,
    );
    let ostree = install_ostree_fixture(&fixture);
    let before = observe_tree(&fixture.state);

    fs::write(&ostree.metadata, format!("'sha256:{}'\n", "e".repeat(64))).unwrap();
    assert_owner_status_refused(
        &fixture,
        &run_owner_status(&fixture, &profile, &payload, &ostree),
        &before,
    );
    fs::write(&ostree.metadata, format!("'{OWNER_CHILD}'\n")).unwrap();

    write_mode(
        &ostree.origin,
        format!(
            "[origin]\ncontainer-image-reference=ostree-unverified-registry:{OWNER_REPOSITORY}@sha256:{}\n",
            "e".repeat(64)
        )
        .as_bytes(),
        0o644,
    );
    assert_owner_status_refused(
        &fixture,
        &run_owner_status(&fixture, &profile, &payload, &ostree),
        &before,
    );
    write_mode(
        &ostree.origin,
        format!(
            "[origin]\ncontainer-image-reference=ostree-unverified-registry:{OWNER_REPOSITORY}@{OWNER_INDEX}\ncontainer-image-reference=ostree-unverified-registry:{OWNER_REPOSITORY}@{OWNER_INDEX}\n"
        )
        .as_bytes(),
        0o644,
    );
    assert_owner_status_refused(
        &fixture,
        &run_owner_status(&fixture, &profile, &payload, &ostree),
        &before,
    );
    write_mode(
        &ostree.origin,
        format!(
            "[origin]\ncontainer-image-reference=ostree-unverified-registry:{OWNER_REPOSITORY}@{OWNER_INDEX}\n"
        )
        .as_bytes(),
        0o644,
    );

    write_mode(&ostree.origin, &vec![b'x'; 4097], 0o644);
    assert_owner_status_refused(
        &fixture,
        &run_owner_status(&fixture, &profile, &payload, &ostree),
        &before,
    );
    write_mode(
        &ostree.origin,
        format!(
            "[origin]\ncontainer-image-reference=ostree-unverified-registry:{OWNER_REPOSITORY}@{OWNER_INDEX}\n"
        )
        .as_bytes(),
        0o644,
    );

    fs::set_permissions(&ostree.origin, fs::Permissions::from_mode(0o664)).unwrap();
    assert_owner_status_refused(
        &fixture,
        &run_owner_status(&fixture, &profile, &payload, &ostree),
        &before,
    );
    fs::set_permissions(&ostree.origin, fs::Permissions::from_mode(0o644)).unwrap();
    let saved_origin = ostree.origin.with_extension("origin.saved");
    fs::rename(&ostree.origin, &saved_origin).unwrap();
    symlink(&saved_origin, &ostree.origin).unwrap();
    assert_owner_status_refused(
        &fixture,
        &run_owner_status(&fixture, &profile, &payload, &ostree),
        &before,
    );
    fs::remove_file(&ostree.origin).unwrap();
    fs::rename(&saved_origin, &ostree.origin).unwrap();

    let deployment_directory = ostree.origin.parent().unwrap();
    let saved_directory = deployment_directory.with_extension("saved");
    fs::rename(deployment_directory, &saved_directory).unwrap();
    symlink(&saved_directory, deployment_directory).unwrap();
    assert_owner_status_refused(
        &fixture,
        &run_owner_status(&fixture, &profile, &payload, &ostree),
        &before,
    );
    fs::remove_file(deployment_directory).unwrap();
    fs::rename(&saved_directory, deployment_directory).unwrap();

    fs::write(&payload, b"different-seed\n").unwrap();
    assert_owner_status_refused(
        &fixture,
        &run_owner_status(&fixture, &profile, &payload, &ostree),
        &before,
    );
    fs::write(&payload, b"cccccccccccccccccccccccccccccccccccccccc\n").unwrap();

    for hostile in [
        json!({"deployments":[
            {"booted":true,"checksum":OWNER_CHECKSUM,"serial":0,"stateroot":"default"},
            {"booted":true,"checksum":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","serial":1,"stateroot":"default"}
        ]}),
        json!({"deployments":[{"booted":true,"checksum":"not-a-checksum","serial":0,"stateroot":"default"}]}),
        json!({"deployments":[{"booted":true,"checksum":OWNER_CHECKSUM,"serial":0,"stateroot":"../default"}]}),
        json!({"deployments":[{"booted":true,"checksum":OWNER_CHECKSUM,"serial":9_007_199_254_740_992_u64,"stateroot":"default"}]}),
    ] {
        fs::write(&ostree.status, serde_json::to_vec(&hostile).unwrap()).unwrap();
        assert_owner_status_refused(
            &fixture,
            &run_owner_status(&fixture, &profile, &payload, &ostree),
            &before,
        );
    }
    fs::write(
        &ostree.status,
        serde_json::to_vec(&json!({"deployments":[{
            "booted":true,"checksum":OWNER_CHECKSUM,"serial":0,"stateroot":"default"
        }]}))
        .unwrap(),
    )
    .unwrap();
    fs::write(
        &ostree.status,
        format!(
            "{{\"deployments\":[{{\"booted\":true,\"checksum\":\"{OWNER_CHECKSUM}\",\"serial\":0,\"stateroot\":\"default\"}}],\"deployments\":[]}}"
        ),
    )
    .unwrap();
    assert_owner_status_refused(
        &fixture,
        &run_owner_status(&fixture, &profile, &payload, &ostree),
        &before,
    );
    fs::write(
        &ostree.status,
        serde_json::to_vec(&json!({"deployments":[{
            "booted":true,"checksum":OWNER_CHECKSUM,"serial":0,"stateroot":"default"
        }]}))
        .unwrap(),
    )
    .unwrap();

    let metadata_marker = fixture.root.join("metadata-mutation-fired");
    write_mode(
        &ostree.command,
        format!(
            "#!/bin/sh\nif [ \"$1 $2 $3\" = 'admin status --json' ]; then\n  cat '{}'\nelif [ \"$1\" = show ]; then\n  if [ ! -e '{}' ]; then\n    cat '{}'\n    : > '{}'\n    printf \"'sha256:%s'\\n\" '{}' > '{}'\n  else\n    cat '{}'\n  fi\nelse\n  exit 97\nfi\n",
            ostree.status.display(),
            metadata_marker.display(),
            ostree.metadata.display(),
            metadata_marker.display(),
            "e".repeat(64),
            ostree.metadata.display(),
            ostree.metadata.display()
        )
        .as_bytes(),
        0o755,
    );
    let changed_metadata = run_owner_status(&fixture, &profile, &payload, &ostree);
    assert_owner_status_refused(&fixture, &changed_metadata, &before);
    assert!(String::from_utf8_lossy(&changed_metadata.stderr)
        .contains("booted deployment changed during authenticated inspection"));
    fs::write(&ostree.metadata, format!("'{OWNER_CHILD}'\n")).unwrap();

    let final_status = fixture.root.join("ostree-final-status.json");
    fs::write(
        &final_status,
        serde_json::to_vec(&json!({"deployments":[{
            "booted":true,"checksum":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "serial":1,"stateroot":"default"
        }]}))
        .unwrap(),
    )
    .unwrap();
    let status_marker = fixture.root.join("status-mutation-fired");
    write_mode(
        &ostree.command,
        format!(
            "#!/bin/sh\nif [ \"$1 $2 $3\" = 'admin status --json' ]; then\n  if [ -e '{}' ]; then cat '{}'; else cat '{}'; : > '{}'; fi\nelif [ \"$1\" = show ]; then\n  cat '{}'\nelse\n  exit 97\nfi\n",
            status_marker.display(),
            final_status.display(),
            ostree.status.display(),
            status_marker.display(),
            ostree.metadata.display()
        )
        .as_bytes(),
        0o755,
    );
    let changed_status = run_owner_status(&fixture, &profile, &payload, &ostree);
    assert_owner_status_refused(&fixture, &changed_status, &before);
    assert!(String::from_utf8_lossy(&changed_status.stderr)
        .contains("booted deployment changed during authenticated inspection"));
    write_default_ostree_command(&ostree.command, &ostree.status, &ostree.metadata);

    let mutation_marker = fixture.root.join("origin-mutation-fired");
    write_mode(
        &ostree.command,
        format!(
            "#!/bin/sh\nif [ \"$1 $2 $3\" = 'admin status --json' ]; then\n  cat '{}'\nelif [ \"$1\" = show ]; then\n  if [ ! -e '{}' ]; then\n    : > '{}'\n    printf '%s\\n' '[origin]' 'container-image-reference=ostree-unverified-registry:{OWNER_REPOSITORY}@sha256:{}' > '{}'\n    chmod 0644 '{}'\n  fi\n  cat '{}'\nelse\n  exit 97\nfi\n",
            ostree.status.display(),
            mutation_marker.display(),
            mutation_marker.display(),
            "e".repeat(64),
            ostree.origin.display(),
            ostree.origin.display(),
            ostree.metadata.display()
        )
        .as_bytes(),
        0o755,
    );
    let changed = run_owner_status(&fixture, &profile, &payload, &ostree);
    assert_owner_status_refused(&fixture, &changed, &before);
    assert!(String::from_utf8_lossy(&changed.stderr)
        .contains("booted deployment changed during authenticated inspection"));
}

#[test]
fn foreign_nv02_refuses_without_persistent_or_volatile_residue() {
    let fixture = Fixture::new(
        "foreign",
        &owner_public(
            "000b038de2091c1c8ef2e8fd8869f17bef3a576ae287530fa17f05ae3b9712014b5d",
            "authread|ownerwrite|nt=extend",
        ),
    );
    let before = metadata(&fixture.state);
    let output = fixture.run();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("either exact supported backend"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(metadata(&fixture.state), before);
    assert_eq!(fs::read_dir(&fixture.state).unwrap().count(), 0);
    assert_eq!(fs::read_dir(&fixture.scratch).unwrap().count(), 0);
    assert_eq!(
        fs::read_to_string(&fixture.calls).unwrap().lines().count(),
        1
    );
}

#[test]
fn duplicate_nv02_section_refuses_before_any_profile_helper() {
    let exact = owner_public(
        "000b038de2091c1c8ef2e8fd8869f17bef3a576ae287530fa17f05ae3b9712014b5d",
        "policywrite|authread|ownerread|no_da|nt=extend",
    );
    let fixture = Fixture::new("duplicate", &format!("{exact}{exact}"));
    let output = fixture.run();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("duplicate public-area section"));
    assert_eq!(fs::read_dir(&fixture.scratch).unwrap().count(), 0);
}

#[test]
fn symlink_fifo_and_oversize_persistent_inputs_refuse_before_tpm() {
    for kind in ["symlink", "fifo", "oversize"] {
        let fixture = Fixture::new(
            kind,
            &owner_public(
                "000b038de2091c1c8ef2e8fd8869f17bef3a576ae287530fa17f05ae3b9712014b5d",
                "policywrite|authread|ownerread|no_da|nt=extend",
            ),
        );
        let hostile = fixture.state.join("hostile");
        match kind {
            "symlink" => symlink("/etc/passwd", &hostile).unwrap(),
            "fifo" => {
                assert!(Command::new("mkfifo")
                    .arg(&hostile)
                    .status()
                    .unwrap()
                    .success());
                fs::set_permissions(&hostile, fs::Permissions::from_mode(0o600)).unwrap();
            }
            "oversize" => {
                fs::write(&hostile, vec![0_u8; 1024 * 1024 + 1]).unwrap();
                fs::set_permissions(&hostile, fs::Permissions::from_mode(0o600)).unwrap();
            }
            _ => unreachable!(),
        }
        let output = fixture.run();
        assert_eq!(output.status.code(), Some(1), "{kind}");
        assert!(output.stdout.is_empty(), "{kind}");
        assert!(
            !fixture.calls.exists(),
            "TPM must not be reached for {kind}"
        );
        assert_eq!(fs::read_dir(&fixture.scratch).unwrap().count(), 0, "{kind}");
    }
}

#[test]
fn public_command_is_argument_free_and_does_not_create_scratch_on_misuse() {
    let output = Command::new(env!("CARGO_BIN_EXE_ni-ota-verify"))
        .args(["authenticated-ota-status", "--config", "/tmp/forbidden"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("takes no arguments"));
}

#[test]
fn helper_timeout_and_oversized_output_refuse_without_success_or_residue() {
    for (name, script, expected_code, expected) in [
        (
            "timeout",
            "#!/bin/sh\nsleep 30 & echo $! > \"$0.child\"\nwait\n",
            2,
            "deadline exceeded",
        ),
        (
            "overflow",
            "#!/bin/sh\npython3 - <<'PY'\nimport sys\nsys.stdout.write('x' * 65537)\nPY\n",
            1,
            "output bound",
        ),
    ] {
        let fixture = Fixture::new(name, "");
        fixture.replace_nvreadpublic(script);
        let before = metadata(&fixture.state);
        let started = Instant::now();
        let output = fixture.run();
        let elapsed = started.elapsed();
        assert_eq!(output.status.code(), Some(expected_code), "{name}");
        assert!(output.stdout.is_empty(), "{name}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(expected),
            "{name}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(metadata(&fixture.state), before, "{name}");
        assert_eq!(fs::read_dir(&fixture.scratch).unwrap().count(), 0, "{name}");
        if name == "timeout" {
            assert!(
                elapsed < Duration::from_secs(5),
                "the test-only three-second deadline was widened with production: {elapsed:?}"
            );
            let child: u32 = fs::read_to_string(fixture.nvreadpublic.with_extension("child"))
                .unwrap()
                .trim()
                .parse()
                .unwrap();
            let proc_path = PathBuf::from(format!("/proc/{child}"));
            for _ in 0..100 {
                if !proc_path.exists() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            assert!(
                !proc_path.exists(),
                "timed-out helper descendant {child} survived the operation deadline"
            );
        }
    }
}

#[test]
fn deterministic_source_swap_during_authentication_is_detected_on_refusal() {
    let public = owner_public(
        "000b038de2091c1c8ef2e8fd8869f17bef3a576ae287530fa17f05ae3b9712014b5d",
        "policywrite|authread|ownerread|no_da|nt=extend",
    );
    let fixture = Fixture::new("source-swap", &public);
    let watched = fixture.state.join("watched");
    fs::write(&watched, b"before\n").unwrap();
    fs::set_permissions(&watched, fs::Permissions::from_mode(0o600)).unwrap();
    fixture.replace_nvreadpublic(&format!(
        "#!/bin/sh\ncat <<'EOF'\n{public}EOF\nprintf 'after\\n' > '{}.replacement'\nchmod 0600 '{}.replacement'\nmv '{}.replacement' '{}'\n",
        watched.display(),
        watched.display(),
        watched.display(),
        watched.display(),
    ));
    let output = fixture.run();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("persistent OTA state changed during authenticated read-only status"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read(&watched).unwrap(), b"after\n");
    assert_eq!(fs::read_dir(&fixture.scratch).unwrap().count(), 0);
}

// ---------------------------------------------------------------------------
// The OTA transaction window (ICE-Fabric issue 665).
//
// Measured on .67, 2026-09-17 02:07–02:13 CEST, OTA 0.61.0 → 0.61.2: booted
// onto the staged target, phase `finalizing`, the licence gate ran this verb,
// the verb refused (booted ≠ applied), the gate stayed closed, the required
// `licensed-plane` probe timed out after 180 s and the engine rolled back.
// These tests hold the window open for exactly that shape and closed for
// every other.
// ---------------------------------------------------------------------------

const TARGET_INDEX: &str =
    "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
const TARGET_CHILD: &str =
    "sha256:9999999999999999999999999999999999999999999999999999999999999999";
const TARGET_SEED: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
const PREVIOUS_SEED: &str = "cccccccccccccccccccccccccccccccccccccccc";
const ACTIVATED_BOOT: &str = "66666666-7777-8888-9999-aaaaaaaaaaaa";
const PREPARED_BOOT: &str = "11111111-2222-3333-4444-555555555555";
const HELD_STATUS: &[u8] = b"{\"committed_generation\":null,\"completion_version\":2,\"enforce_ready_verified\":false,\"profile\":\"owner-sealed-ota-state-v1\",\"schema\":\"neural-ice-authenticated-ota-status-v1\"}\n";

struct PristineOwner {
    fixture: Fixture,
    profile: PathBuf,
    payload: PathBuf,
    ostree: OstreeFixture,
    boot_id: PathBuf,
}

/// The pristine owner appliance of `public_owner_pristine_status_is_exact_and_read_only`,
/// booted on its applied baseline, with a boot identity file beside it.
fn install_pristine_owner(name: &str) -> PristineOwner {
    let fixture = Fixture::new(name, "");
    let access = install_access_profile(&fixture, "lab-managed");
    let (receipt_sha, set_sha) = install_owner_preseal(&fixture);
    install_completion_v2(&fixture, &access, &receipt_sha, &set_sha);
    let public = owner_public(
        "000b038de2091c1c8ef2e8fd8869f17bef3a576ae287530fa17f05ae3b9712014b5d",
        "policywrite|authread|ownerread|no_da|nt=extend",
    );
    install_read_only_tpm(&fixture, &access, &public, None, 5);
    let profile = fixture.root.join("ota-state-profile");
    write_mode(&profile, b"owner-sealed-ota-state-v1\n", 0o444);
    let payload = fixture.root.join("PAYLOAD_ID");
    write_mode(&payload, format!("{PREVIOUS_SEED}\n").as_bytes(), 0o644);
    let ostree = install_ostree_fixture(&fixture);
    let boot_id = fixture.root.join("boot_id");
    fs::write(&boot_id, format!("{ACTIVATED_BOOT}\n")).unwrap();
    PristineOwner {
        fixture,
        profile,
        payload,
        ostree,
        boot_id,
    }
}

impl PristineOwner {
    fn command(&self) -> Command {
        let mut command =
            owner_status_command(&self.fixture, &self.profile, &self.payload, &self.ostree);
        command
            .env(
                "NI_OTA_OWNER_STATE_HELPER",
                self.fixture.root.join("owner-state"),
            )
            .env("NI_OTA_AUTH_STATUS_BOOT_ID", &self.boot_id);
        command
    }

    fn run(&self) -> Output {
        self.command().output().unwrap()
    }

    /// Reboot the fixture onto the transaction's target: the origin names the
    /// target image, the commit imported another manifest, the booted image
    /// carries the target seed.
    fn boot_target(&self) {
        self.boot_image(&format!("{OWNER_REPOSITORY}@{TARGET_INDEX}"));
        fs::write(&self.ostree.metadata, format!("'{TARGET_CHILD}'\n")).unwrap();
        write_mode(&self.payload, format!("{TARGET_SEED}\n").as_bytes(), 0o644);
    }

    fn boot_image(&self, image: &str) {
        write_mode(
            &self.ostree.origin,
            format!("[origin]\ncontainer-image-reference=ostree-unverified-registry:{image}\n")
                .as_bytes(),
            0o644,
        );
    }

    fn transaction_dir(&self) -> PathBuf {
        self.fixture.state.join("transaction")
    }

    fn state_json(&self) -> PathBuf {
        self.transaction_dir().join("state.json")
    }

    /// The transaction directory as the engine's `prepare` leaves it: mode
    /// 0700, five mode-0600 regular files, `state.json` last.
    fn install_transaction(&self, state: &Value) {
        let directory = self.transaction_dir();
        if directory.exists() {
            fs::remove_dir_all(&directory).unwrap();
        }
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        write_mode(
            &directory.join("aliases.tsv"),
            b"chat\tprevious\tnext\n",
            0o600,
        );
        write_mode(&directory.join("entitlements.txt"), b"ICE-CORE\n", 0o600);
        write_mode(
            &directory.join("bom.json"),
            b"{\"train\":\"0.61.2\"}\n",
            0o600,
        );
        write_mode(
            &directory.join("previous-bom.json"),
            b"{\"train\":\"0.61.0\"}\n",
            0o600,
        );
        self.write_state(state);
    }

    fn write_state(&self, state: &Value) {
        let mut bytes = serde_json::to_vec(state).unwrap();
        bytes.push(b'\n');
        write_mode(&self.state_json(), &bytes, 0o600);
    }
}

/// `neural-ice-ota-transaction.sh cmd_prepare` … `cmd_finalize`: the state
/// of train 0.61.2 departing from the fixture's applied 0.61.0 baseline.
fn engine_state(phase: &str) -> Value {
    json!({
        "schema_version": 3,
        "phase": phase,
        "train": "0.61.2",
        "channel": "lab",
        "previous_ring": "lab",
        "ring_state_migration": false,
        "hardware_target": "nvidia-gb10-arm64",
        "target_seed_ref": TARGET_SEED,
        "target_os_ref": format!("{OWNER_REPOSITORY}@{TARGET_INDEX}"),
        "previous_seed_ref": PREVIOUS_SEED,
        "previous_os_ref": format!("{OWNER_REPOSITORY}@{OWNER_INDEX}"),
        "prepared_boot_id": PREPARED_BOOT,
        "activated_boot_id": ACTIVATED_BOOT,
        "rollback_boot_id": null,
        "activation_attempts": 1,
        "finalize_attempts": 1,
        "commit_attempts": 0,
        "rollback_attempts": 0
    })
}

fn assert_held(owner: &PristineOwner, output: &Output, before: &[ObservedTreeEntry], phase: &str) {
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, HELD_STATUS);
    assert_eq!(
        output.stderr,
        format!("ni-ota-verify: authenticated OTA status HELD inside OTA transaction window: phase {phase} of train 0.61.2\n").as_bytes()
    );
    assert_eq!(observe_tree(&owner.fixture.state), before);
    assert_eq!(fs::read_dir(&owner.fixture.scratch).unwrap().count(), 0);
}

fn assert_window_refused(
    owner: &PristineOwner,
    output: &Output,
    before: &[ObservedTreeEntry],
    reason: &str,
) {
    assert_owner_status_refused(&owner.fixture, output, before);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(reason), "expected {reason:?} in: {stderr}");
}

#[test]
fn held_status_is_answered_inside_the_ota_transaction_window() {
    let owner = install_pristine_owner("tx-window");
    // Booted on the target with no transaction at all: the divergence has
    // nothing to explain it. This is the pre-fix refusal, kept verbatim.
    owner.boot_target();
    let before = observe_tree(&owner.fixture.state);
    assert_window_refused(
        &owner,
        &owner.run(),
        &before,
        "booted deployment differs from authenticated preseal baseline; not a held OTA transaction window: no durable OTA transaction",
    );

    for phase in ["activated", "finalizing", "committing"] {
        owner.install_transaction(&engine_state(phase));
        let before = observe_tree(&owner.fixture.state);
        let output = owner.run();
        assert_held(&owner, &output, &before, phase);
        let calls = fs::read_to_string(&owner.fixture.calls).unwrap();
        assert!(!calls.contains("FORBIDDEN"), "{calls}");
    }

    // The framing the licence gate re-canonicalises and compares byte for
    // byte: one object, sorted keys, no spaces, exactly one LF.
    let output = owner.run();
    let parsed: Value = serde_json::from_slice(&output.stdout[..output.stdout.len() - 1]).unwrap();
    assert_eq!(canonical(&parsed), output.stdout);
    assert!(!output.stdout.ends_with(b"\n\n"));
    assert_eq!(parsed["enforce_ready_verified"], json!(false));
    assert_eq!(parsed["committed_generation"], Value::Null);

    // Keys the engine appends in flight are not a schema change.
    let mut in_flight = engine_state("finalizing");
    in_flight["data_snapshot"] = "taken".into();
    owner.install_transaction(&in_flight);
    let before = observe_tree(&owner.fixture.state);
    assert_held(&owner, &owner.run(), &before, "finalizing");

    // Back on the applied baseline with the transaction still on disk
    // (the engine has not archived it yet): the baseline answers on its own,
    // the transaction is not consulted and nothing is said on stderr.
    owner.boot_image(&format!("{OWNER_REPOSITORY}@{OWNER_INDEX}"));
    fs::write(&owner.ostree.metadata, format!("'{OWNER_CHILD}'\n")).unwrap();
    write_mode(
        &owner.payload,
        format!("{PREVIOUS_SEED}\n").as_bytes(),
        0o644,
    );
    let before = observe_tree(&owner.fixture.state);
    let output = owner.run();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, HELD_STATUS);
    assert!(output.stderr.is_empty());
    assert_eq!(observe_tree(&owner.fixture.state), before);
}

#[test]
fn ota_transaction_window_refuses_a_booted_system_that_is_not_its_target() {
    let owner = install_pristine_owner("tx-not-target");
    owner.install_transaction(&engine_state("finalizing"));

    // A third image: neither the applied baseline nor the target.
    owner.boot_target();
    owner.boot_image(&format!("{OWNER_REPOSITORY}@sha256:{}", "3".repeat(64)));
    let before = observe_tree(&owner.fixture.state);
    assert_window_refused(
        &owner,
        &owner.run(),
        &before,
        "not a held OTA transaction window: booted deployment is not the OTA transaction target",
    );

    // The target image by tag, not by the digest the engine staged.
    owner.boot_image(&format!("{OWNER_REPOSITORY}:0.61.2"));
    assert_window_refused(
        &owner,
        &owner.run(),
        &before,
        "not a held OTA transaction window: booted deployment is not the OTA transaction target",
    );

    // The applied image with the target's payload: the baseline refuses on
    // the payload, and the window refuses on the image.
    owner.boot_image(&format!("{OWNER_REPOSITORY}@{OWNER_INDEX}"));
    fs::write(&owner.ostree.metadata, format!("'{OWNER_CHILD}'\n")).unwrap();
    assert_window_refused(
        &owner,
        &owner.run(),
        &before,
        "running PAYLOAD_ID differs from authenticated preseal baseline; not a held OTA transaction window: booted deployment is not the OTA transaction target",
    );

    // The target image with the applied payload.
    owner.boot_target();
    write_mode(
        &owner.payload,
        format!("{PREVIOUS_SEED}\n").as_bytes(),
        0o644,
    );
    assert_window_refused(
        &owner,
        &owner.run(),
        &before,
        "not a held OTA transaction window: running PAYLOAD_ID is not the OTA transaction target seed",
    );

    // The target, but in another boot than the one that activated it.
    owner.boot_target();
    fs::write(&owner.boot_id, format!("{PREPARED_BOOT}\n")).unwrap();
    assert_window_refused(
        &owner,
        &owner.run(),
        &before,
        "not a held OTA transaction window: OTA transaction was not activated in this boot",
    );
    fs::write(&owner.boot_id, b"not-a-boot-id\n").unwrap();
    assert_window_refused(
        &owner,
        &owner.run(),
        &before,
        "not a held OTA transaction window: boot identity is malformed",
    );
    fs::write(&owner.boot_id, format!("{ACTIVATED_BOOT}\n")).unwrap();

    // A transaction that departs from some other applied baseline.
    let mut foreign_previous = engine_state("finalizing");
    foreign_previous["previous_os_ref"] =
        format!("{OWNER_REPOSITORY}@sha256:{}", "1".repeat(64)).into();
    owner.write_state(&foreign_previous);
    let before = observe_tree(&owner.fixture.state);
    assert_window_refused(
        &owner,
        &owner.run(),
        &before,
        "not a held OTA transaction window: OTA transaction does not depart from the authenticated applied baseline",
    );
    let mut foreign_seed = engine_state("finalizing");
    foreign_seed["previous_seed_ref"] = "2".repeat(40).into();
    owner.write_state(&foreign_seed);
    let before = observe_tree(&owner.fixture.state);
    assert_window_refused(
        &owner,
        &owner.run(),
        &before,
        "not a held OTA transaction window: OTA transaction does not depart from the authenticated applied baseline",
    );

    // Another hardware target than the immutable one.
    let mut other_hardware = engine_state("finalizing");
    other_hardware["hardware_target"] = "nvidia-gb10-x86_64".into();
    owner.write_state(&other_hardware);
    let before = observe_tree(&owner.fixture.state);
    assert_window_refused(
        &owner,
        &owner.run(),
        &before,
        "not a held OTA transaction window: OTA transaction names another hardware target",
    );

    // Back to the exact window: still answered, so the refusals above were
    // each earned by the one thing they changed.
    owner.write_state(&engine_state("finalizing"));
    let before = observe_tree(&owner.fixture.state);
    assert_held(&owner, &owner.run(), &before, "finalizing");
}

#[test]
fn ota_transaction_outside_its_health_window_refuses_as_before() {
    let owner = install_pristine_owner("tx-phase");
    owner.boot_target();
    for phase in [
        "prepared",
        "pending_reboot",
        "activating",
        "rollback_armed",
        "completed",
        "rolled_back",
        "recovery_required",
        "aborted",
    ] {
        let mut state = engine_state(phase);
        if matches!(phase, "rollback_armed" | "recovery_required") {
            state["failure_reason"] = "health_timeout".into();
        }
        owner.install_transaction(&state);
        let before = observe_tree(&owner.fixture.state);
        assert_window_refused(
            &owner,
            &owner.run(),
            &before,
            &format!("not a held OTA transaction window: OTA transaction phase {phase} is not a health window"),
        );
    }
    let mut unknown = engine_state("finalizing");
    unknown["phase"] = "health_window".into();
    owner.install_transaction(&unknown);
    let before = observe_tree(&owner.fixture.state);
    assert_window_refused(
        &owner,
        &owner.run(),
        &before,
        "not a held OTA transaction window: OTA transaction state is outside the engine's schema",
    );
}

#[test]
fn tampered_ota_transaction_refuses_the_whole_status() {
    let owner = install_pristine_owner("tx-tampered");
    owner.boot_target();
    owner.install_transaction(&engine_state("finalizing"));
    let state_json = owner.state_json();
    let directory = owner.transaction_dir();

    // A world-readable state file is refused by the persistent snapshot
    // itself, before any profile is selected: the status is not answered at
    // all, held or otherwise.
    fs::set_permissions(&state_json, fs::Permissions::from_mode(0o644)).unwrap();
    let before = observe_tree(&owner.fixture.state);
    assert_window_refused(
        &owner,
        &owner.run(),
        &before,
        "persistent OTA state has unsafe mode/owner/type metadata; expected 0600",
    );
    fs::set_permissions(&state_json, fs::Permissions::from_mode(0o600)).unwrap();

    // A group-accessible directory, likewise.
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o750)).unwrap();
    let before = observe_tree(&owner.fixture.state);
    assert_window_refused(
        &owner,
        &owner.run(),
        &before,
        "persistent OTA state has unsafe mode/owner/type metadata; expected 0700",
    );
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();

    // A symlinked state file: never followed (the snapshot opens it with
    // O_NOFOLLOW and the kernel answers ELOOP).
    let saved = owner.fixture.root.join("state.json.saved");
    fs::rename(&state_json, &saved).unwrap();
    symlink(&saved, &state_json).unwrap();
    let before = observe_tree(&owner.fixture.state);
    assert_window_refused(
        &owner,
        &owner.run(),
        &before,
        "Too many levels of symbolic links",
    );
    fs::remove_file(&state_json).unwrap();
    fs::rename(&saved, &state_json).unwrap();

    // A symlinked transaction directory: never followed either.
    let saved_directory = owner.fixture.root.join("transaction.saved");
    fs::rename(&directory, &saved_directory).unwrap();
    symlink(&saved_directory, &directory).unwrap();
    let before = observe_tree(&owner.fixture.state);
    assert_window_refused(
        &owner,
        &owner.run(),
        &before,
        "Too many levels of symbolic links",
    );
    fs::remove_file(&directory).unwrap();
    fs::rename(&saved_directory, &directory).unwrap();

    // A directory named `transaction` that the engine did not assemble.
    fs::remove_file(directory.join("bom.json")).unwrap();
    let before = observe_tree(&owner.fixture.state);
    assert_window_refused(
        &owner,
        &owner.run(),
        &before,
        "not a held OTA transaction window: OTA transaction lacks its bom.json",
    );
    write_mode(
        &directory.join("bom.json"),
        b"{\"train\":\"0.61.2\"}\n",
        0o600,
    );

    // Another schema, a truncated document, a document that is not the
    // engine's object.
    let mut schema = engine_state("finalizing");
    schema["schema_version"] = 2.into();
    owner.write_state(&schema);
    let before = observe_tree(&owner.fixture.state);
    assert_window_refused(
        &owner,
        &owner.run(),
        &before,
        "not a held OTA transaction window: OTA transaction state is outside the engine's schema",
    );
    write_mode(
        &state_json,
        b"{\"schema_version\":3,\"phase\":\"finali",
        0o600,
    );
    let before = observe_tree(&owner.fixture.state);
    assert_window_refused(
        &owner,
        &owner.run(),
        &before,
        "not a held OTA transaction window: OTA transaction state is malformed",
    );
    write_mode(&state_json, b"[]\n", 0o600);
    let before = observe_tree(&owner.fixture.state);
    assert_window_refused(
        &owner,
        &owner.run(),
        &before,
        "not a held OTA transaction window: OTA transaction state is malformed",
    );

    // The exact window again: every refusal above was the tampering's own.
    owner.write_state(&engine_state("finalizing"));
    let before = observe_tree(&owner.fixture.state);
    assert_held(&owner, &owner.run(), &before, "finalizing");
}

// ---------------------------------------------------------------------------
// The committed applied state as the running baseline (ICE-Fabric PR 667
// report, gap E1).
//
// Before this, the running system was compared to the PRESEAL baseline only.
// An OTA that reached `completed` committed applied.json + applied.bom.json
// and archived its transaction; the next reboot had no window, a booted
// deployment that was the committed train and a preseal naming the installed
// one — refused, licence gate closed, on every OTA'd appliance at its second
// boot. These tests hold the baseline as the latest of the two.
// ---------------------------------------------------------------------------

const THIRD_INDEX: &str = "sha256:7777777777777777777777777777777777777777777777777777777777777777";
const THIRD_SEED: &str = "5555555555555555555555555555555555555555";

/// The release BOM the engine copies beside the applied state at commit.
fn committed_bom(train: &str, seq: u64, index: &str, seed: &str) -> Vec<u8> {
    serde_json::to_vec_pretty(&json!({
        "appliance":{"os_base":{"digest":index,"image":OWNER_REPOSITORY},"version":train},
        "bundle_seq":seq,"compat_min":5,"compat_version":5,"hardware_target":"nvidia-gb10-arm64",
        "sources":{"seed":{"ref":seed,"repo":"ICE-Fabric"}},"train":train
    }))
    .unwrap()
}

impl PristineOwner {
    /// What `commit` and the engine's `persist_applied_bom` leave behind.
    fn commit_applied(&self, bom: &[u8], seq: u64) {
        write_mode(
            &self.fixture.state.join("applied.json"),
            &canonical(&json!({
                "bundle_seq": seq, "bom_sha256": hash(bom),
                "bom_format": "media-independent-v1", "active_ring": "lab"
            })),
            0o600,
        );
        write_mode(&self.fixture.state.join("applied.bom.json"), bom, 0o600);
    }

    fn boot_third(&self) {
        self.boot_image(&format!("{OWNER_REPOSITORY}@{THIRD_INDEX}"));
        fs::write(
            &self.ostree.metadata,
            format!("'sha256:{}'\n", "8".repeat(64)),
        )
        .unwrap();
        write_mode(&self.payload, format!("{THIRD_SEED}\n").as_bytes(), 0o644);
    }

    fn boot_preseal(&self) {
        self.boot_image(&format!("{OWNER_REPOSITORY}@{OWNER_INDEX}"));
        fs::write(&self.ostree.metadata, format!("'{OWNER_CHILD}'\n")).unwrap();
        write_mode(
            &self.payload,
            format!("{PREVIOUS_SEED}\n").as_bytes(),
            0o644,
        );
    }
}

fn assert_answered_silently(owner: &PristineOwner, before: &[ObservedTreeEntry]) {
    let output = owner.run();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, HELD_STATUS);
    assert!(
        output.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(observe_tree(&owner.fixture.state), before);
    assert_eq!(fs::read_dir(&owner.fixture.scratch).unwrap().count(), 0);
}

#[test]
fn committed_applied_state_is_the_running_baseline_after_the_transaction_is_archived() {
    let owner = install_pristine_owner("applied-baseline");
    let bom = committed_bom("0.61.2", 6, TARGET_INDEX, TARGET_SEED);
    owner.commit_applied(&bom, 6);
    // The engine archives the completed transaction beside the state.
    owner.install_transaction(&engine_state("completed"));
    fs::rename(
        owner.transaction_dir(),
        owner.fixture.state.join("transaction.previous"),
    )
    .unwrap();

    // Second boot after the OTA: booted on the committed train, no window.
    owner.boot_target();
    let before = observe_tree(&owner.fixture.state);
    assert_answered_silently(&owner, &before);

    // The committed BOM names its image by the index digest alone: another
    // well-formed manifest digest is not a divergence, a malformed one is.
    fs::write(
        &owner.ostree.metadata,
        format!("'sha256:{}'\n", "4".repeat(64)),
    )
    .unwrap();
    let before = observe_tree(&owner.fixture.state);
    assert_answered_silently(&owner, &before);
    fs::write(&owner.ostree.metadata, "'not-a-digest'\n").unwrap();
    assert_window_refused(
        &owner,
        &owner.run(),
        &before,
        "booted manifest metadata is malformed",
    );
    fs::write(&owner.ostree.metadata, format!("'{TARGET_CHILD}'\n")).unwrap();

    // The NEXT OTA departs from the committed baseline, not from the
    // preseal: its window is held on top of the applied state.
    let mut next = engine_state("finalizing");
    next["train"] = "0.61.3".into();
    next["previous_os_ref"] = format!("{OWNER_REPOSITORY}@{TARGET_INDEX}").into();
    next["previous_seed_ref"] = TARGET_SEED.into();
    next["target_os_ref"] = format!("{OWNER_REPOSITORY}@{THIRD_INDEX}").into();
    next["target_seed_ref"] = THIRD_SEED.into();
    owner.install_transaction(&next);
    owner.boot_third();
    let before = observe_tree(&owner.fixture.state);
    let output = owner.run();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, HELD_STATUS);
    assert_eq!(
        output.stderr,
        b"ni-ota-verify: authenticated OTA status HELD inside OTA transaction window: phase finalizing of train 0.61.3\n"
    );
    assert_eq!(observe_tree(&owner.fixture.state), before);

    // A transaction that still departs from the preseal is stale here.
    let mut stale = next.clone();
    stale["previous_os_ref"] = format!("{OWNER_REPOSITORY}@{OWNER_INDEX}").into();
    stale["previous_seed_ref"] = PREVIOUS_SEED.into();
    owner.write_state(&stale);
    let before = observe_tree(&owner.fixture.state);
    assert_window_refused(
        &owner,
        &owner.run(),
        &before,
        "booted deployment differs from authenticated applied baseline; not a held OTA transaction window: OTA transaction does not depart from the authenticated applied baseline",
    );
}

#[test]
fn a_boot_beneath_the_committed_baseline_is_refused() {
    let owner = install_pristine_owner("applied-beneath");
    let bom = committed_bom("0.61.2", 6, TARGET_INDEX, TARGET_SEED);
    owner.commit_applied(&bom, 6);

    // An operator's `bootc rollback` after `completed`: the engine never
    // rewrites the applied state (its rollback exists only before the
    // commit), so the preseal deployment now sits beneath the committed
    // baseline — the anti-rollback floor's own refusal.
    owner.boot_preseal();
    let before = observe_tree(&owner.fixture.state);
    assert_window_refused(
        &owner,
        &owner.run(),
        &before,
        "booted deployment differs from authenticated applied baseline; not a held OTA transaction window: no durable OTA transaction",
    );

    // The rollback the engine DOES perform happens before the commit: the
    // applied state is still the preseal's, the booted deployment is the
    // preseal's, and the archived transaction says so.
    fs::remove_file(owner.fixture.state.join("applied.json")).unwrap();
    fs::remove_file(owner.fixture.state.join("applied.bom.json")).unwrap();
    let mut rolled_back = engine_state("rolled_back");
    rolled_back["failure_reason"] = "health_timeout".into();
    owner.install_transaction(&rolled_back);
    let before = observe_tree(&owner.fixture.state);
    assert_answered_silently(&owner, &before);
}

#[test]
fn a_tampered_or_incomplete_applied_state_refuses_the_status() {
    let owner = install_pristine_owner("applied-tampered");
    let bom = committed_bom("0.61.2", 6, TARGET_INDEX, TARGET_SEED);
    owner.commit_applied(&bom, 6);
    owner.boot_target();
    let applied = owner.fixture.state.join("applied.json");
    let applied_bom = owner.fixture.state.join("applied.bom.json");
    let refused = |reason: &str| {
        let before = observe_tree(&owner.fixture.state);
        assert_window_refused(&owner, &owner.run(), &before, reason);
    };

    // The BOM copy no longer hashes to the applied state.
    let mut altered = bom.clone();
    altered.push(b'\n');
    write_mode(&applied_bom, &altered, 0o600);
    refused("applied BOM differs from the committed applied state");
    // No BOM copy at all beside a committed state.
    fs::remove_file(&applied_bom).unwrap();
    refused("committed applied state has no readable BOM beside it");
    // A BOM that hashes right but names another hardware target.
    let foreign = serde_json::to_vec_pretty(&json!({
        "appliance":{"os_base":{"digest":TARGET_INDEX,"image":OWNER_REPOSITORY},"version":"0.61.2"},
        "bundle_seq":6,"compat_min":5,"compat_version":5,"hardware_target":"nvidia-gb10-x86_64",
        "sources":{"seed":{"ref":TARGET_SEED,"repo":"ICE-Fabric"}},"train":"0.61.2"
    }))
    .unwrap();
    owner.commit_applied(&foreign, 6);
    refused("applied BOM names another hardware target");
    // A BOM that hashes right but names another image than the booted one.
    let other_image = committed_bom("0.61.2", 6, THIRD_INDEX, TARGET_SEED);
    owner.commit_applied(&other_image, 6);
    refused("booted deployment differs from authenticated applied baseline");
    // A BOM copy wider than 0600 refuses the whole directory, as any entry.
    owner.commit_applied(&bom, 6);
    fs::set_permissions(&applied_bom, fs::Permissions::from_mode(0o644)).unwrap();
    refused("persistent OTA state has unsafe mode/owner/type metadata; expected 0600");
    fs::set_permissions(&applied_bom, fs::Permissions::from_mode(0o600)).unwrap();

    // Applied states the engine never writes: beneath the sealed floor, at
    // the sealed sequence with another BOM, without the format marker.
    owner.commit_applied(&committed_bom("0.60.9", 4, TARGET_INDEX, TARGET_SEED), 4);
    refused("applied state sequence 4 is below the sealed baseline floor 5");
    owner.commit_applied(&committed_bom("0.61.0", 5, TARGET_INDEX, TARGET_SEED), 5);
    refused("applied state at the sealed sequence names another BOM");
    write_mode(
        &applied,
        &canonical(&json!({"bundle_seq": 6, "bom_sha256": hash(&bom), "active_ring": "lab"})),
        0o600,
    );
    write_mode(&applied_bom, &bom, 0o600);
    refused("applied baseline was recorded by a media-era verifier");

    // The sealed BOM bootstrapped by hand at the sealed sequence (the .67
    // shape after the night of 2026-09-17): the preseal stays the baseline,
    // manifest digest included, and no BOM copy is consulted.
    let sealed = fs::read(owner.fixture.state.join("preseal-input-v1/bom.json")).unwrap();
    write_mode(
        &applied,
        &canonical(&json!({
            "bundle_seq": 5, "bom_sha256": hash(&sealed),
            "bom_format": "media-independent-v1", "active_ring": "lab"
        })),
        0o600,
    );
    fs::remove_file(&applied_bom).unwrap();
    owner.boot_preseal();
    let before = observe_tree(&owner.fixture.state);
    assert_answered_silently(&owner, &before);
    // …and the exact committed shape answers again on the target.
    owner.commit_applied(&bom, 6);
    owner.boot_target();
    let before = observe_tree(&owner.fixture.state);
    assert_answered_silently(&owner, &before);
}

// ---------------------------------------------------------------------------
// `bootstrap-from-preseal` (ICE-CoreOS issue 206).
//
// Measured on .67, 2026-09-17, after the C37 medium reinstall: the first-boot
// ceremony authenticated the preseal baseline and wrote no applied state;
// `verify` answered `FAIL unseeded`, `commit` refused to seed, `bootstrap`
// demanded a cosign BOM signature the sealed medium never carries. A manual
// root-key signature at 00:45 seeded bundle_seq 22 and the gate passed
// (anti_rollback 26 > 22). These tests hold the verb that makes that hand
// ceremony unnecessary — and hold it closed for every other shape.
// ---------------------------------------------------------------------------

struct FirstBoot {
    fixture: Fixture,
    profile: PathBuf,
    payload: PathBuf,
    ostree: OstreeFixture,
    receipt_sha: String,
    set_sha: String,
}

/// The appliance as the installer leaves it for its first boot: preseal
/// inputs and receipt under state_dir, owner anchor defined and pristine,
/// booted on the sealed target, no applied state, no completion evidence.
fn install_first_boot(name: &str) -> FirstBoot {
    let fixture = Fixture::new(name, "");
    let access = install_access_profile(&fixture, "lab-managed");
    let (receipt_sha, set_sha) = install_owner_preseal(&fixture);
    let public = owner_public(
        "000b038de2091c1c8ef2e8fd8869f17bef3a576ae287530fa17f05ae3b9712014b5d",
        "policywrite|authread|ownerread|no_da|nt=extend",
    );
    install_read_only_tpm(&fixture, &access, &public, None, 5);
    // The sealed device channel the installer writes into ota.conf.
    let mut config = fs::read_to_string(&fixture.config).unwrap();
    config.push_str("device_channel=lab\n");
    fs::write(&fixture.config, config).unwrap();
    let profile = fixture.root.join("ota-state-profile");
    write_mode(&profile, b"owner-sealed-ota-state-v1\n", 0o444);
    let payload = fixture.root.join("PAYLOAD_ID");
    write_mode(
        &payload,
        b"cccccccccccccccccccccccccccccccccccccccc\n",
        0o644,
    );
    let ostree = install_ostree_fixture(&fixture);
    FirstBoot {
        fixture,
        profile,
        payload,
        ostree,
        receipt_sha,
        set_sha,
    }
}

impl FirstBoot {
    fn input(&self, name: &str) -> PathBuf {
        self.fixture.state.join("preseal-input-v1").join(name)
    }

    fn seed_command(&self) -> Command {
        self.seed_command_expecting_set(&self.set_sha)
    }

    fn seed_command_expecting_set(&self, set_sha: &str) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_ni-ota-verify"));
        command
            .arg("bootstrap-from-preseal")
            .arg("--set")
            .arg(self.input("preseal-set.json"))
            .arg("--snapshot")
            .arg(self.input("delegation-snapshot.json"))
            .arg("--snapshot-sig")
            .arg(self.input("delegation-snapshot.sig"))
            .arg("--release")
            .arg(self.input("ota-release-authorization.json"))
            .arg("--release-sig")
            .arg(self.input("ota-release-authorization.sig"))
            .arg("--bom")
            .arg(self.input("bom.json"))
            .arg("--installer-authorization")
            .arg(self.input("installer-release-authorization-v2.json"))
            .arg("--installer-authorization-sig")
            .arg(self.input("installer-release-authorization-v2.sig"))
            .args(["--expected-set-sha256", set_sha])
            .args(["--expected-receipt-sha256", &self.receipt_sha])
            .arg("--receipt")
            .arg(self.fixture.state.join("preseal/receipt.json"))
            .arg("--scratch-dir")
            .arg(&self.fixture.scratch)
            .arg("--config")
            .arg(&self.fixture.config)
            .env("NI_OTA_COSIGN", self.fixture.root.join("cosign"))
            .env(
                "NI_OTA_HARDWARE_TARGET_FILE",
                self.fixture.root.join("hardware-target"),
            )
            .env(
                "NI_OTA_APPLIANCE_VARIANT_FILE",
                self.fixture.root.join("appliance-variant"),
            )
            .env(
                "NI_OTA_MIN_DELEGATION_SEQ_FILE",
                self.fixture.root.join("min-delegation-seq"),
            )
            .env(
                "NI_OTA_BOOTSTRAP_DELEGATION_SHA256_FILE",
                self.fixture.root.join("bootstrap-delegation-sha256"),
            )
            .env(
                "NI_OTA_TPM2_NVREADPUBLIC",
                self.fixture.root.join("tpm2_nvreadpublic-success"),
            )
            .env("NI_OTA_TPM2_NVDEFINE", &self.fixture.forbidden)
            .env("NI_OTA_TPM2_NVEXTEND", &self.fixture.forbidden)
            .env("NI_OTA_TPM2_NVWRITE", &self.fixture.forbidden)
            .env("NI_OTA_TPM2_NVWRITELOCK", &self.fixture.forbidden)
            .env("NI_OTA_TPM2_NVUNDEFINE", &self.fixture.forbidden)
            .env("NI_OTA_TPM2_CLEAR", &self.fixture.forbidden)
            .env("NI_OTA_TPM2_CHANGEAUTH", &self.fixture.forbidden)
            .env("NI_OTA_AUTH_STATUS_PROFILE_MARKER", &self.profile)
            .env("NI_OTA_AUTH_STATUS_OSTREE", &self.ostree.command)
            .env(
                "NI_OTA_AUTH_STATUS_DEPLOY_ROOT",
                &self.ostree.deployment_root,
            )
            .env("NI_OTA_AUTH_STATUS_PAYLOAD_ID", &self.payload);
        command
    }

    fn seed(&self) -> Output {
        self.seed_command().output().unwrap()
    }

    fn applied(&self) -> PathBuf {
        self.fixture.state.join("applied.json")
    }

    fn applied_bom(&self) -> PathBuf {
        self.fixture.state.join("applied.bom.json")
    }

    /// The persistent tree minus the state lock, whose ctime moves on every
    /// locking (chmod restates 0600) without any content or mode change.
    fn tree(&self) -> Vec<ObservedTreeEntry> {
        observe_tree(&self.fixture.state)
            .into_iter()
            .filter(|entry| entry.relative != Path::new(".applied.json.lock"))
            .collect()
    }
}

fn assert_seed_refused(boot: &FirstBoot, output: &Output, reason: &str) {
    assert_eq!(
        output.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(&format!("bootstrap-from-preseal REFUSED: {reason}")),
        "expected {reason:?} in: {stderr}"
    );
    let calls = fs::read_to_string(&boot.fixture.calls).unwrap_or_default();
    assert!(!calls.contains("FORBIDDEN"), "{calls}");
}

#[test]
fn first_boot_seeds_the_applied_baseline_from_the_preseal_receipt() {
    let boot = install_first_boot("seed-nominal");
    assert!(!boot.applied().exists());
    let bom = fs::read(boot.input("bom.json")).unwrap();

    let output = boot.seed();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let receipt: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        receipt,
        json!({
            "bootstrapped": true, "source": "preseal-receipt", "idempotent": false,
            "train": "0.50.9-lab.20260905", "bundle_seq": 5, "ring": "lab",
            "os_ref": format!("{OWNER_REPOSITORY}@{OWNER_INDEX}"),
            "seed_ref": "cccccccccccccccccccccccccccccccccccccccc",
            "bom_sha256": hash(&bom)
        })
    );
    let calls = fs::read_to_string(&boot.fixture.calls).unwrap();
    assert!(!calls.contains("FORBIDDEN"), "{calls}");
    assert!(
        !calls.contains("nvdefine") && !calls.contains("nvwrite"),
        "the seeding must not touch the TPM: {calls}"
    );

    // The applied state `bootstrap` would have written, plus the BOM copy
    // the engine requires beside it, every one a root-owned 0600 regular
    // file — the mode the authenticated snapshot accepts.
    for (name, expected_mode) in [
        ("applied.json", 0o600),
        ("applied.format.v1.json", 0o600),
        ("applied.bom.json", 0o600),
    ] {
        let metadata = fs::symlink_metadata(boot.fixture.state.join(name)).unwrap();
        assert!(metadata.file_type().is_file(), "{name}");
        assert_eq!(metadata.mode() & 0o7777, expected_mode, "{name}");
        assert_eq!(metadata.nlink(), 1, "{name}");
    }
    let applied: Value = serde_json::from_slice(&fs::read(boot.applied()).unwrap()).unwrap();
    assert_eq!(
        applied,
        json!({"bundle_seq": 5, "bom_sha256": hash(&bom), "bom_format": "media-independent-v1", "active_ring": "lab"})
    );
    assert_eq!(fs::read(boot.applied_bom()).unwrap(), bom);
    let debris: Vec<_> = fs::read_dir(&boot.fixture.state)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".tmp"))
        .collect();
    assert!(debris.is_empty(), "{debris:?}");

    // Exactly idempotent: the same verb again changes nothing on disk.
    let before = boot.tree();
    let again = boot.seed();
    assert_eq!(
        again.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&again.stderr)
    );
    let receipt: Value = serde_json::from_slice(&again.stdout).unwrap();
    assert_eq!(receipt["idempotent"], json!(true));
    assert_eq!(receipt["bundle_seq"], json!(5));
    assert_eq!(boot.tree(), before);

    // The ceremony completes; the authenticated reader still answers the
    // pristine status with the applied state beside the receipt.
    let access = install_access_profile(&boot.fixture, "lab-managed");
    install_completion_v2(&boot.fixture, &access, &boot.receipt_sha, &boot.set_sha);
    let status = run_owner_status(&boot.fixture, &boot.profile, &boot.payload, &boot.ostree);
    assert_eq!(
        status.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&status.stderr)
    );
    assert_eq!(status.stdout, b"{\"committed_generation\":null,\"completion_version\":2,\"enforce_ready_verified\":false,\"profile\":\"owner-sealed-ota-state-v1\",\"schema\":\"neural-ice-authenticated-ota-status-v1\"}\n");

    // THE MEASURED GAP, CLOSED: the v1 OTA gate `verify`, in enforce mode,
    // now finds a seeded baseline and passes the sealed train itself
    // (equal seq, equal BOM bytes) — with no cosign signature of the BOM
    // by anybody's hand; the channel record and the BOM are signed by the
    // fixture's real root key, as a release would be. The v1 record grammar
    // knows beta and stable only (lab rides the delegated verbs), so the
    // gate is exercised with a stable record; the applied ring is the
    // engine's business, not this verdict's.
    let root_key = boot.fixture.root.join("ota-root.key");
    let record = canonical(&json!({
        "assigned_at":"2026-09-05T00:00:00Z","bundle_digest":format!("sha256:{}", "d".repeat(64)),
        "bundle_seq":5,"channel":"stable","hardware_target":"nvidia-gb10-arm64","key_version":1,
        "schema_version":2,"train":"0.50.9-lab.20260905"
    }));
    let record_path = boot.fixture.root.join("record.json");
    fs::write(&record_path, &record).unwrap();
    let bom_sig = boot.fixture.root.join("bom.sig");
    let record_sig = boot.fixture.root.join("record.sig");
    fs::write(
        &bom_sig,
        base64(&sign(&root_key, b"", &bom, &boot.fixture.root, "gate-bom")),
    )
    .unwrap();
    fs::write(
        &record_sig,
        base64(&sign(
            &root_key,
            b"",
            &record,
            &boot.fixture.root,
            "gate-record",
        )),
    )
    .unwrap();
    let verify = Command::new(env!("CARGO_BIN_EXE_ni-ota-verify"))
        .arg("verify")
        .arg("--bom")
        .arg(boot.input("bom.json"))
        .arg("--bom-sig")
        .arg(&bom_sig)
        .arg("--record")
        .arg(&record_path)
        .arg("--record-sig")
        .arg(&record_sig)
        .args(["--bundle-digest", &format!("sha256:{}", "d".repeat(64))])
        .args(["--device-channel", "stable", "--device-compat", "5,5"])
        .arg("--config")
        .arg(&boot.fixture.config)
        .env("NI_OTA_COSIGN", boot.fixture.root.join("cosign"))
        .env(
            "NI_OTA_HARDWARE_TARGET_FILE",
            boot.fixture.root.join("hardware-target"),
        )
        .output()
        .unwrap();
    assert_eq!(
        verify.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&verify.stderr)
    );
    let verdict: Value =
        serde_json::from_slice(verify.stdout.split(|byte| *byte == b'\n').next().unwrap()).unwrap();
    assert_eq!(verdict["verdict"], json!("pass"), "{verdict}");
    let checks = verdict["checks"].as_array().unwrap();
    let check = |name: &str| {
        checks
            .iter()
            .find(|check| check["name"] == json!(name))
            .unwrap_or_else(|| panic!("no {name} check in {verdict}"))
    };
    assert_eq!(check("anti_rollback")["ok"], json!(true), "{verdict}");
    assert!(
        checks
            .iter()
            .all(|check| check["name"] != json!("unseeded")),
        "the gate still reports an unseeded baseline: {verdict}"
    );
}

#[test]
fn bootstrap_from_preseal_refuses_a_booted_system_that_is_not_the_receipt_target() {
    let boot = install_first_boot("seed-not-target");
    let before = boot.tree();
    write_mode(
        &boot.ostree.origin,
        format!(
            "[origin]\ncontainer-image-reference=ostree-unverified-registry:{OWNER_REPOSITORY}@sha256:{}\n",
            "e".repeat(64)
        )
        .as_bytes(),
        0o644,
    );
    assert_seed_refused(
        &boot,
        &boot.seed(),
        "running system: booted deployment differs from authenticated preseal baseline",
    );
    assert_eq!(boot.tree(), before);
    assert!(!boot.applied().exists() && !boot.applied_bom().exists());

    // The right image with another payload: the seed marker is part of the
    // identity, exactly as the ceremony binds it.
    write_mode(
        &boot.ostree.origin,
        format!(
            "[origin]\ncontainer-image-reference=ostree-unverified-registry:{OWNER_REPOSITORY}@{OWNER_INDEX}\n"
        )
        .as_bytes(),
        0o644,
    );
    write_mode(
        &boot.payload,
        format!("{}\n", "e".repeat(40)).as_bytes(),
        0o644,
    );
    assert_seed_refused(
        &boot,
        &boot.seed(),
        "running system: running PAYLOAD_ID differs from authenticated preseal baseline",
    );
    assert!(!boot.applied().exists() && !boot.applied_bom().exists());
}

#[test]
fn bootstrap_from_preseal_refuses_a_tampered_set_and_a_foreign_bom() {
    let boot = install_first_boot("seed-tampered");
    let set_path = boot.input("preseal-set.json");
    let authentic = fs::read(&set_path).unwrap();

    // One field of the set changed: the set no longer hashes to the sealed
    // value the ceremony passes — the retained verification's own refusal.
    let mut set: Value = serde_json::from_slice(&authentic).unwrap();
    set["train"] = "0.50.10-lab.20260917".into();
    write_mode(&set_path, &canonical(&set), 0o600);
    assert_seed_refused(
        &boot,
        &boot.seed(),
        "preseal baseline: preseal set differs from the signed UKI hash",
    );
    // …and with the tampered hash offered as the expected one, the signed
    // release authorization no longer binds the set.
    let tampered_hash = hash(&canonical(&set));
    let output = boot
        .seed_command_expecting_set(&tampered_hash)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("preseal baseline:"));
    write_mode(&set_path, &authentic, 0o600);
    assert!(!boot.applied().exists() && !boot.applied_bom().exists());

    // A BOM whose bytes are not the ones the receipt hashes.
    let bom_path = boot.input("bom.json");
    let authentic_bom = fs::read(&bom_path).unwrap();
    let mut foreign = authentic_bom.clone();
    foreign.push(b'\n');
    write_mode(&bom_path, &foreign, 0o600);
    assert_seed_refused(
        &boot,
        &boot.seed(),
        "preseal baseline: preseal BOM hash binding is invalid",
    );
    write_mode(&bom_path, &authentic_bom, 0o600);
    assert!(!boot.applied().exists() && !boot.applied_bom().exists());
}

#[test]
fn bootstrap_from_preseal_never_overwrites_a_different_applied_state() {
    let boot = install_first_boot("seed-existing");
    let bom = fs::read(boot.input("bom.json")).unwrap();
    // A baseline already seeded at another sequence (the .67 shape after the
    // hand ceremony would be seq 22 against a receipt at 22 — equal, a no-op;
    // this is the unequal one).
    write_mode(
        &boot.applied(),
        &canonical(
            &json!({"bundle_seq": 4, "bom_sha256": "1".repeat(64), "bom_format": "media-independent-v1", "active_ring": "lab"}),
        ),
        0o600,
    );
    let before = boot.tree();
    assert_seed_refused(
        &boot,
        &boot.seed(),
        "applied state already exists with a different baseline",
    );
    assert_eq!(boot.tree(), before);
    assert!(!boot.applied_bom().exists());

    // Same sequence and hash, other ring: still a different baseline.
    write_mode(
        &boot.applied(),
        &canonical(
            &json!({"bundle_seq": 5, "bom_sha256": hash(&bom), "bom_format": "media-independent-v1", "active_ring": "beta"}),
        ),
        0o600,
    );
    assert_seed_refused(
        &boot,
        &boot.seed(),
        "applied state already exists with a different baseline",
    );
    assert!(!boot.applied_bom().exists());

    // The exact baseline without its BOM copy (a crash between the two
    // writes, or a hand-seeded state): the copy is published, the state kept.
    write_mode(
        &boot.applied(),
        &canonical(
            &json!({"bundle_seq": 5, "bom_sha256": hash(&bom), "bom_format": "media-independent-v1", "active_ring": "lab"}),
        ),
        0o600,
    );
    let output = boot.seed();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let receipt: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(receipt["idempotent"], json!(true));
    assert_eq!(fs::read(boot.applied_bom()).unwrap(), bom);

    // An applied BOM copy that is not the receipt's BOM is never replaced.
    write_mode(&boot.applied_bom(), b"{\"train\":\"other\"}\n", 0o600);
    assert_seed_refused(&boot, &boot.seed(), "existing applied BOM");
    assert_eq!(
        fs::read(boot.applied_bom()).unwrap(),
        b"{\"train\":\"other\"}\n"
    );
}

#[test]
fn bootstrap_from_preseal_requires_a_pristine_anchor_and_the_sealed_channel() {
    let boot = install_first_boot("seed-anchor");
    let before = boot.tree();

    // The owner anchor already written: this is no longer a first boot.
    let written = owner_public(
        "000b11afd155aca82a503f2029cc11395389654c3a25fc54b9eca6d33abdff498d56",
        "policywrite|authread|ownerread|no_da|nt=extend|written",
    );
    let public = boot.fixture.root.join("tpm2_nvreadpublic-success");
    let pristine_script = fs::read_to_string(&public).unwrap();
    let written_script = pristine_script.replace(
        "000b038de2091c1c8ef2e8fd8869f17bef3a576ae287530fa17f05ae3b9712014b5d",
        "000b11afd155aca82a503f2029cc11395389654c3a25fc54b9eca6d33abdff498d56",
    );
    assert_ne!(pristine_script, written_script);
    let _ = written;
    write_mode(
        &public,
        written_script
            .replace(
                "policywrite|authread|ownerread|no_da|nt=extend",
                "policywrite|authread|ownerread|no_da|nt=extend|written",
            )
            .as_bytes(),
        0o755,
    );
    assert_seed_refused(
        &boot,
        &boot.seed(),
        "owner OTA anchor: owner OTA anchor is already written",
    );
    write_mode(&public, pristine_script.as_bytes(), 0o755);

    // The anchor absent altogether (an installer that never presealed).
    write_mode(&public, b"#!/bin/sh\nexit 1\n", 0o755);
    assert_seed_refused(
        &boot,
        &boot.seed(),
        "owner OTA anchor: TPM NV02 public state is absent or unreadable",
    );
    write_mode(&public, pristine_script.as_bytes(), 0o755);

    // No sealed device channel in ota.conf: the applied ring cannot be
    // guessed (issue 201/202 class), so nothing is seeded.
    let config = fs::read_to_string(&boot.fixture.config).unwrap();
    fs::write(
        &boot.fixture.config,
        config.replace("device_channel=lab\n", ""),
    )
    .unwrap();
    assert_seed_refused(&boot, &boot.seed(), "ota.conf names no device_channel");
    fs::write(
        &boot.fixture.config,
        config.replace("device_channel=lab\n", "device_channel=beta\n"),
    )
    .unwrap();
    assert_seed_refused(
        &boot,
        &boot.seed(),
        "sealed device channel 'beta' differs from the receipt ring 'lab'",
    );
    fs::write(&boot.fixture.config, config).unwrap();
    assert_eq!(boot.tree(), before);
    assert!(!boot.applied().exists() && !boot.applied_bom().exists());

    // Everything restored: the seeding proceeds, so each refusal above was
    // earned by the one thing it changed.
    let output = boot.seed();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// ICE-CoreOS issue 208, measured on .67 2026-09-17 00:35: after one OTA
/// check the state directory read `600 …` for every entry except
/// `644 root 1290 last-verdict.json`, the authenticated reader refused the
/// directory as a unit and the licence gate stayed closed; `chmod 0600`
/// reopened it. The verdict `verify` records must never close the reader
/// that shares its directory — and a foreign 0644 entry must still.
#[test]
fn verify_verdict_keeps_the_authenticated_status_answerable() {
    let fixture = Fixture::new("verdict-beside-status", "");
    let access = install_access_profile(&fixture, "lab-managed");
    let (receipt_sha, set_sha) = install_owner_preseal(&fixture);
    install_completion_v2(&fixture, &access, &receipt_sha, &set_sha);
    let public = owner_public(
        "000b038de2091c1c8ef2e8fd8869f17bef3a576ae287530fa17f05ae3b9712014b5d",
        "policywrite|authread|ownerread|no_da|nt=extend",
    );
    install_read_only_tpm(&fixture, &access, &public, None, 5);
    let profile = fixture.root.join("ota-state-profile");
    write_mode(&profile, b"owner-sealed-ota-state-v1\n", 0o444);
    let payload = fixture.root.join("PAYLOAD_ID");
    write_mode(
        &payload,
        b"cccccccccccccccccccccccccccccccccccccccc\n",
        0o644,
    );
    let ostree = install_ostree_fixture(&fixture);
    let held = b"{\"committed_generation\":null,\"completion_version\":2,\"enforce_ready_verified\":false,\"profile\":\"owner-sealed-ota-state-v1\",\"schema\":\"neural-ice-authenticated-ota-status-v1\"}\n";
    let output = run_owner_status(&fixture, &profile, &payload, &ostree);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, held);

    // The OTA controller's `verify`, against the SAME state directory. The
    // fixture's root key is real (install_owner_preseal generated it), so
    // the BOM and the channel record carry real signatures the fixture's
    // cosign checks with OpenSSL; the verdict itself is whatever an unseeded
    // enforcing appliance earns — what matters here is the file it leaves.
    let root_key = fixture.root.join("ota-root.key");
    let bom = serde_json::to_vec_pretty(&json!({
        "appliance":{"os_base":{"digest":OWNER_INDEX,"image":OWNER_REPOSITORY},"version":"0.50.9-lab.20260905"},
        "bundle_seq":5,"compat_min":5,"compat_version":5,"hardware_target":"nvidia-gb10-arm64",
        "sources":{"seed":{"ref":"cccccccccccccccccccccccccccccccccccccccc","repo":"ICE-Fabric"}},"train":"0.50.9-lab.20260905"
    }))
    .unwrap();
    let record = canonical(&json!({
        "assigned_at":"2026-09-05T00:00:00Z","bundle_digest":format!("sha256:{}", "d".repeat(64)),
        "bundle_seq":5,"channel":"lab","hardware_target":"nvidia-gb10-arm64","key_version":1,
        "schema_version":2,"train":"0.50.9-lab.20260905"
    }));
    let bom_path = fixture.root.join("verify-bom.json");
    let record_path = fixture.root.join("verify-record.json");
    fs::write(&bom_path, &bom).unwrap();
    fs::write(&record_path, &record).unwrap();
    let bom_sig = fixture.root.join("verify-bom.sig");
    let record_sig = fixture.root.join("verify-record.sig");
    fs::write(
        &bom_sig,
        base64(&sign(&root_key, b"", &bom, &fixture.root, "verify-bom")),
    )
    .unwrap();
    fs::write(
        &record_sig,
        base64(&sign(
            &root_key,
            b"",
            &record,
            &fixture.root,
            "verify-record",
        )),
    )
    .unwrap();
    let verify = Command::new(env!("CARGO_BIN_EXE_ni-ota-verify"))
        .arg("verify")
        .arg("--bom")
        .arg(&bom_path)
        .arg("--bom-sig")
        .arg(&bom_sig)
        .arg("--record")
        .arg(&record_path)
        .arg("--record-sig")
        .arg(&record_sig)
        .args(["--bundle-digest", &format!("sha256:{}", "d".repeat(64))])
        .args(["--device-channel", "lab", "--device-compat", "5,5"])
        .arg("--config")
        .arg(&fixture.config)
        .env("NI_OTA_COSIGN", fixture.root.join("cosign"))
        .env(
            "NI_OTA_HARDWARE_TARGET_FILE",
            fixture.root.join("hardware-target"),
        )
        .output()
        .unwrap();
    assert_ne!(
        verify.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&verify.stderr)
    );
    let verdict = fixture.state.join("last-verdict.json");
    let metadata = fs::symlink_metadata(&verdict).unwrap();
    assert!(metadata.file_type().is_file());
    assert_eq!(metadata.mode() & 0o7777, 0o600);
    let recorded: Value = serde_json::from_slice(&fs::read(&verdict).unwrap()).unwrap();
    assert!(recorded["checks"].is_array(), "{recorded}");

    // The reader answers with the verdict beside it, and touches nothing.
    let before = observe_tree(&fixture.state);
    let output = run_owner_status(&fixture, &profile, &payload, &ostree);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, held);
    assert_eq!(observe_tree(&fixture.state), before);

    // The .67 shape, reproduced: the same verdict widened to 0644 closes it.
    fs::set_permissions(&verdict, fs::Permissions::from_mode(0o644)).unwrap();
    let before = observe_tree(&fixture.state);
    let output = run_owner_status(&fixture, &profile, &payload, &ostree);
    assert_owner_status_refused(&fixture, &output, &before);
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("persistent OTA state has unsafe mode/owner/type metadata; expected 0600"));
    fs::set_permissions(&verdict, fs::Permissions::from_mode(0o600)).unwrap();

    // A foreign 0644 entry is refused exactly the same way: the mode contract
    // of the directory did not move, only the verifier's own writer did.
    write_mode(&fixture.state.join("posture.json"), b"{}\n", 0o644);
    let before = observe_tree(&fixture.state);
    let output = run_owner_status(&fixture, &profile, &payload, &ostree);
    assert_owner_status_refused(&fixture, &output, &before);
    fs::remove_file(fixture.state.join("posture.json")).unwrap();
    let output = run_owner_status(&fixture, &profile, &payload, &ostree);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, held);
}

// ---------------------------------------------------------------------------
// The v2 attestation lane (mission B, T1): marker `owner-sealed-ota-state-v2`,
// evidence `neural-ice-owner-ceremony-evidence-v2-lane2`, the golden pair and
// receipt of `tests/fixtures/v2-release/`. The status bytes are the SAME as the
// v1 lane's: the licence gate and model-fetch compare them and change nothing.
// ---------------------------------------------------------------------------

const V2_FLOOR: u64 = 3;

fn v2_golden() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/v2-release")
}

struct V2Owner {
    fixture: Fixture,
    profile: PathBuf,
    payload: PathBuf,
    ostree: OstreeFixture,
    live_root: PathBuf,
    access: AccessFiles,
    golden: Value,
    mode: &'static str,
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

fn v2_evidence(owner: &V2Owner, floor: u64) -> Value {
    let golden = &owner.golden;
    let luks = json!({
        "keyslot":"0","pcr_bank":"sha256","pcrs":[7],"policy_hash":"11".repeat(32),
        "policy_public_key_sha256":"22".repeat(32),"schema":"neural-ice-luks-token-evidence-v1",
        "sealed_object_sha256":"33".repeat(32),"srk_sha256":"44".repeat(32),"token_sha256":"55".repeat(32)
    });
    let manifest_sha = golden["inputs"]["sealed_manifest_sha256"].as_str().unwrap();
    json!({
        "access_profile_anchor":owner.access.evidence_anchor,"data_luks":luks,
        "device_root_name":format!("000b{}", "11".repeat(32)),
        "install_identity":{"install_source":"medium","installed_at":"1970-01-01T00:00:00Z",
            "installer_sealed_identity_sha256":"66".repeat(32),"release_identity_sha256":manifest_sha,
            "schema":"neural-ice-owner-ceremony-install-identity-v1"},
        "ota_state":{"anchor_attributes":"0x2060048","anchor_index":"0x01500002",
            "anchor_name_at_completion":"000b038de2091c1c8ef2e8fd8869f17bef3a576ae287530fa17f05ae3b9712014b5d",
            "anchor_policy_sha256":"b6a2e7142ee56fd978047488483daa5b42b8dc4cc7ddcceddfb91793cf1ff1b7",
            "anchor_pristine_name":"000b038de2091c1c8ef2e8fd8869f17bef3a576ae287530fa17f05ae3b9712014b5d",
            "anchor_size":32,"anchor_state_at_completion":"pristine",
            "anchor_written_name":"000b11afd155aca82a503f2029cc11395389654c3a25fc54b9eca6d33abdff498d56",
            "baseline_floor":floor,"clear_protected_at_completion":true,"floor_attributes":"0x62008",
            "floor_index":"0x01500001","floor_name":"000be283f20a38b93f8cef085efb4aee9f5944cc3b3b28b850bf3c0eeb2054cd7fc4",
            "floor_policy_sha256":"f83217e5a2a04342f7daa55ccfb3cd4b8a1f1e8ebb28c7719a9abbdbd638a230",
            "floor_size":8,"profile":"owner-sealed-ota-state-v1"},
        "schema":"neural-ice-owner-ceremony-evidence-v2-lane2","srk_name":format!("000b{}", "aa".repeat(32)),
        "system_luks":luks,"tpm_state":{"freshness_counter":floor,"freshness_public_sha256":"bb".repeat(32),
            "install_counter":1,"install_public_sha256":"cc".repeat(32),"profile_binding":"dd".repeat(32),
            "schema":"neural-ice-tpm-state-snapshot-v1"},
        "v2_release":{"bundle_seq":V2_FLOOR,"manifest_sha256":manifest_sha,
            "manifest_sig_sha256":golden["inputs"]["sealed_manifest_sig_sha256"],
            "receipt_schema":"neural-ice-v2-release-receipt-v1",
            "receipt_sha256":golden["expected"]["receipt_sha256"][owner.mode],
            "release_id":golden["expected"]["release_id"],
            "release_key_sha256":golden["inputs"]["sealed_key_sha256"]}
    })
}

/// Write the completion evidence, its inspection and the two helper stubs.
fn install_v2_completion(owner: &V2Owner, evidence: &Value, inspected_floor: u64) {
    let fixture = &owner.fixture;
    let bytes = canonical(evidence);
    write_mode(
        &fixture.state.join("owner-ceremony-evidence-v2.json"),
        &bytes,
        0o600,
    );
    let mut message = b"neural-ice:tpm:owner-ceremony-completion:v2\0".to_vec();
    message.extend_from_slice(&bytes);
    fs::write(
        fixture.root.join("completion-inspection.json"),
        canonical(
            &json!({"completion_version":2,"evidence_digest_sha256":hash(&message),
            "schema":"neural-ice-owner-ceremony-completion-inspection-v1"}),
        ),
    )
    .unwrap();
    write_mode(&fixture.root.join("tpm-state"), format!(
        "#!/bin/sh\n[ \"$#\" -eq 1 ] && [ \"$1\" = completion-inspect ] || exit 97\nprintf 'completion %s\\n' \"$*\" >> '{}'\ncat '{}'\n",
        fixture.calls.display(), fixture.root.join("completion-inspection.json").display()).as_bytes(), 0o755);
    fs::write(fixture.root.join("owner-inspection.json"), canonical(&json!({
        "anchor_attributes":"0x2060048","anchor_index":"0x01500002",
        "anchor_name":"000b038de2091c1c8ef2e8fd8869f17bef3a576ae287530fa17f05ae3b9712014b5d",
        "anchor_policy_sha256":"b6a2e7142ee56fd978047488483daa5b42b8dc4cc7ddcceddfb91793cf1ff1b7",
        "anchor_sha256":null,"anchor_size":32,"anchor_state":"pristine","baseline_floor":inspected_floor,
        "clear_protected":true,"floor_attributes":"0x62008","floor_index":"0x01500001",
        "floor_name":"000be283f20a38b93f8cef085efb4aee9f5944cc3b3b28b850bf3c0eeb2054cd7fc4",
        "floor_policy_sha256":"f83217e5a2a04342f7daa55ccfb3cd4b8a1f1e8ebb28c7719a9abbdbd638a230",
        "floor_size":8,"owner_sealed":true,"profile":"owner-sealed-ota-state-v1",
        "schema":"neural-ice-owner-ota-state-inspection-v2"
    }))).unwrap();
    write_mode(&fixture.root.join("owner-state"), format!(
        "#!/bin/sh\n[ \"$#\" -eq 1 ] && [ \"$1\" = inspect-v2 ] || exit 97\nprintf 'owner-inspect %s\\n' \"$*\" >> '{}'\ncat '{}'\n",
        fixture.calls.display(), fixture.root.join("owner-inspection.json").display()).as_bytes(), 0o755);
}

/// A completed v2-lane appliance: the persisted pair and receipt, the lane-2
/// evidence, the pristine owner anchor, the lane marker, and a booted deployment
/// that is exactly the host the receipt names.
fn install_v2_owner(name: &str, mode: &'static str) -> V2Owner {
    let fixture = Fixture::new(name, "");
    let access = install_access_profile(&fixture, "lab-managed");
    let golden: Value =
        serde_json::from_slice(&fs::read(v2_golden().join("golden.json")).unwrap()).unwrap();
    let input = fixture.state.join("v2-release-input-v1");
    let receipt_dir = fixture.state.join("v2-release");
    for directory in [&input, &receipt_dir] {
        fs::create_dir(directory).unwrap();
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
    }
    for (name, target) in [
        ("release-manifest.json", input.join("release-manifest.json")),
        (
            "release-manifest.json.sig",
            input.join("release-manifest.json.sig"),
        ),
    ] {
        write_mode(&target, &fs::read(v2_golden().join(name)).unwrap(), 0o600);
    }
    write_mode(
        &receipt_dir.join("receipt.json"),
        &fs::read(v2_golden().join(format!("expected-receipt-{mode}.json"))).unwrap(),
        0o600,
    );
    let live_root = fixture.root.join("live");
    copy_tree(&v2_golden().join("candidate-root"), &live_root);
    let public = owner_public(
        "000b038de2091c1c8ef2e8fd8869f17bef3a576ae287530fa17f05ae3b9712014b5d",
        "policywrite|authread|ownerread|no_da|nt=extend",
    );
    install_read_only_tpm(&fixture, &access, &public, None, V2_FLOOR);
    let profile = fixture.root.join("ota-state-profile");
    write_mode(&profile, b"owner-sealed-ota-state-v2\n", 0o444);
    // The v2 lane reads no PAYLOAD_ID: the path names nothing on purpose.
    let payload = fixture.root.join("no-such-PAYLOAD_ID");
    let ostree = install_ostree_fixture(&fixture);
    let host = format!(
        "{}@{}",
        golden["expected"]["host_repository"].as_str().unwrap(),
        golden["inputs"]["host_index_digest"].as_str().unwrap()
    );
    write_mode(
        &ostree.origin,
        format!("[origin]\ncontainer-image-reference=ostree-unverified-registry:{host}\n")
            .as_bytes(),
        0o644,
    );
    fs::write(
        &ostree.metadata,
        format!(
            "'{}'\n",
            golden["inputs"]["host_manifest_digest"].as_str().unwrap()
        ),
    )
    .unwrap();
    let owner = V2Owner {
        fixture,
        profile,
        payload,
        ostree,
        live_root,
        access,
        golden,
        mode,
    };
    let evidence = v2_evidence(&owner, V2_FLOOR);
    install_v2_completion(&owner, &evidence, V2_FLOOR);
    owner
}

impl V2Owner {
    fn command(&self) -> Command {
        let mut command =
            owner_status_command(&self.fixture, &self.profile, &self.payload, &self.ostree);
        command
            .env(
                "NI_OTA_OWNER_STATE_HELPER",
                self.fixture.root.join("owner-state"),
            )
            .env("NI_OTA_AUTH_STATUS_V2_ROOT", &self.live_root);
        command
    }

    fn run(&self) -> Output {
        self.command().output().unwrap()
    }

    fn state(&self, relative: &str) -> PathBuf {
        self.fixture.state.join(relative)
    }

    fn assert_refused(&self, label: &str, reason: &str) {
        let before = observe_tree(&self.fixture.state);
        let output = self.run();
        assert_eq!(
            output.status.code(),
            Some(1),
            "{label}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stdout.is_empty(), "{label}");
        let message = String::from_utf8_lossy(&output.stderr);
        assert!(message.contains(reason), "{label}: {message}");
        assert_eq!(observe_tree(&self.fixture.state), before, "{label}");
        assert_eq!(
            fs::read_dir(&self.fixture.scratch).unwrap().count(),
            0,
            "{label}"
        );
    }
}

const V2_HELD_STATUS: &[u8] = HELD_STATUS;

#[test]
fn v2_lane_status_is_the_exact_held_bytes_for_both_seal_modes() {
    for mode in ["manifest-digest", "floor"] {
        let owner = install_v2_owner(&format!("v2-lane-{mode}"), mode);
        let before = observe_tree(&owner.fixture.state);
        let output = owner.run();
        assert_eq!(
            output.status.code(),
            Some(0),
            "{mode}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        // The bytes the licence gate and model-fetch compare: unchanged.
        assert_eq!(output.stdout, V2_HELD_STATUS, "{mode}");
        assert_eq!(
            output.stdout,
            fs::read(v2_golden().join("expected-authenticated-ota-status.json")).unwrap()
        );
        assert!(output.stderr.is_empty());
        assert_eq!(observe_tree(&owner.fixture.state), before);
        assert_eq!(fs::read_dir(&owner.fixture.scratch).unwrap().count(), 0);
        let calls = fs::read_to_string(&owner.fixture.calls).unwrap();
        assert!(!calls.contains("FORBIDDEN"), "{calls}");
        assert_eq!(
            calls.matches("owner-inspect inspect-v2").count(),
            2,
            "{calls}"
        );
    }
}

/// Rewrite the evidence with `edit` applied and re-bind the completion record.
fn rebind_v2_evidence(owner: &V2Owner, floor: u64, edit: impl FnOnce(&mut Value)) {
    let mut evidence = v2_evidence(owner, floor);
    edit(&mut evidence);
    install_v2_completion(owner, &evidence, floor);
}

#[test]
fn v2_lane_refuses_a_marker_and_evidence_that_name_different_lanes() {
    // The v1 marker on a v2-lane appliance: the pre-T0 shape of the failure.
    let owner = install_v2_owner("v2-marker-v1", "manifest-digest");
    fs::remove_file(&owner.profile).unwrap();
    write_mode(&owner.profile, b"owner-sealed-ota-state-v1\n", 0o444);
    owner.assert_refused(
        "v1 marker, lane2 evidence",
        "lacks one exact version-2 completion binding",
    );

    // An unknown marker is no lane at all.
    let unknown = install_v2_owner("v2-marker-unknown", "manifest-digest");
    fs::remove_file(&unknown.profile).unwrap();
    write_mode(&unknown.profile, b"owner-sealed-ota-state-v3\n", 0o444);
    unknown.assert_refused("unknown marker", "not the owner-sealed contract");

    // The marker must be the sealed 0444 file, exactly 26 bytes.
    let writable = install_v2_owner("v2-marker-mode", "manifest-digest");
    fs::set_permissions(&writable.profile, fs::Permissions::from_mode(0o644)).unwrap();
    writable.assert_refused(
        "writable marker",
        "cannot authenticate immutable OTA profile marker",
    );
}

#[test]
fn v2_lane_refuses_preseal_evidence_beside_the_v2_marker_and_the_reverse() {
    // v2 marker + a preseal directory: mixed lanes.
    let mixed = install_v2_owner("v2-with-preseal", "manifest-digest");
    fs::create_dir(mixed.state("preseal")).unwrap();
    fs::set_permissions(mixed.state("preseal"), fs::Permissions::from_mode(0o700)).unwrap();
    mixed.assert_refused("preseal directory", "mixed with preseal evidence");

    // Lane-2 evidence that also carries ota_preseal is not the lane-2 schema.
    let both = install_v2_owner("v2-evidence-both", "manifest-digest");
    rebind_v2_evidence(&both, V2_FLOOR, |evidence| {
        evidence["ota_preseal"] = json!({"receipt_schema":"neural-ice-ota-preseal-receipt-v1",
            "receipt_sha256":"88".repeat(32),"set_sha256":"99".repeat(32)});
    });
    both.assert_refused("ota_preseal and v2_release", "evidence is malformed");

    // The v1 evidence under the v2 marker has no v2 attestation.
    let v1 = install_v2_owner("v2-marker-v1-evidence", "manifest-digest");
    let access = &v1.access;
    let (receipt_sha, set_sha) = (hash(b"receipt"), hash(b"set"));
    let luks = json!({"keyslot":"0","pcr_bank":"sha256","pcrs":[7],"policy_hash":"11".repeat(32),
        "policy_public_key_sha256":"22".repeat(32),"schema":"neural-ice-luks-token-evidence-v1",
        "sealed_object_sha256":"33".repeat(32),"srk_sha256":"44".repeat(32),"token_sha256":"55".repeat(32)});
    let mut evidence = v2_evidence(&v1, V2_FLOOR);
    evidence["schema"] = json!("neural-ice-owner-ceremony-evidence-v2");
    evidence.as_object_mut().unwrap().remove("v2_release");
    evidence["ota_preseal"] = json!({"receipt_schema":"neural-ice-ota-preseal-receipt-v1",
        "receipt_sha256":receipt_sha,"set_sha256":set_sha});
    evidence["access_profile_anchor"] = access.evidence_anchor.clone();
    evidence["data_luks"] = luks.clone();
    evidence["system_luks"] = luks;
    install_v2_completion(&v1, &evidence, V2_FLOOR);
    v1.assert_refused(
        "preseal evidence, v2 marker",
        "lacks one exact version-2 completion binding",
    );
}

#[test]
fn v2_lane_refuses_a_receipt_or_pair_that_is_not_the_one_the_evidence_binds() {
    let receipt = install_v2_owner("v2-receipt-tampered", "manifest-digest");
    let path = receipt.state("v2-release/receipt.json");
    let mut bytes = fs::read(&path).unwrap();
    bytes[10] ^= 0x01;
    write_mode(&path, &bytes, 0o600);
    receipt.assert_refused("receipt byte flipped", "receipt-digest");

    let other_mode = install_v2_owner("v2-receipt-other-mode", "manifest-digest");
    write_mode(
        &other_mode.state("v2-release/receipt.json"),
        &fs::read(v2_golden().join("expected-receipt-floor.json")).unwrap(),
        0o600,
    );
    other_mode.assert_refused(
        "floor receipt under manifest-digest evidence",
        "receipt-digest",
    );

    let manifest = install_v2_owner("v2-manifest-tampered", "floor");
    let path = manifest.state("v2-release-input-v1/release-manifest.json");
    let mut bytes = fs::read(&path).unwrap();
    bytes[10] ^= 0x01;
    write_mode(&path, &bytes, 0o600);
    manifest.assert_refused("manifest byte flipped", "manifest-digest");

    let signature = install_v2_owner("v2-signature-tampered", "floor");
    write_mode(
        &signature.state("v2-release-input-v1/release-manifest.json.sig"),
        b"bm90IGEgc2lnbmF0dXJl",
        0o600,
    );
    signature.assert_refused("signature replaced", "sig-digest");

    let missing = install_v2_owner("v2-receipt-missing", "manifest-digest");
    fs::remove_file(missing.state("v2-release/receipt.json")).unwrap();
    missing.assert_refused("receipt absent", "receipt");
}

#[test]
fn v2_lane_refuses_a_floor_that_is_not_the_manifest_bundle_seq() {
    // Evidence, inspection and TPM agree with each other but not with the receipt.
    let evidence_floor = install_v2_owner("v2-floor-evidence", "manifest-digest");
    rebind_v2_evidence(&evidence_floor, V2_FLOOR + 1, |evidence| {
        evidence["v2_release"]["bundle_seq"] = json!(V2_FLOOR + 1);
    });
    evidence_floor.assert_refused("floor 4 vs manifest 3", "owner baseline floor differs");

    // The evidence says the manifest's seq, the TPM floor says another.
    let tpm_floor = install_v2_owner("v2-floor-tpm", "manifest-digest");
    let evidence = v2_evidence(&tpm_floor, V2_FLOOR);
    install_v2_completion(&tpm_floor, &evidence, V2_FLOOR + 1);
    tpm_floor.assert_refused("inspected floor 4", "owner-state inspection does not match");

    // v2_release.bundle_seq not the floor: the evidence contradicts itself.
    let contradiction = install_v2_owner("v2-floor-contradiction", "manifest-digest");
    rebind_v2_evidence(&contradiction, V2_FLOOR, |evidence| {
        evidence["v2_release"]["bundle_seq"] = json!(V2_FLOOR + 1);
    });
    contradiction.assert_refused("bundle_seq 4 vs floor 3", "violates its closed contract");
}

#[test]
fn v2_lane_refuses_evidence_that_names_another_release() {
    for (label, edit) in [
        ("manifest digest", "manifest_sha256"),
        ("signature digest", "manifest_sig_sha256"),
        ("key digest", "release_key_sha256"),
        ("receipt digest", "receipt_sha256"),
    ] {
        let owner = install_v2_owner(&format!("v2-evidence-{edit}"), "manifest-digest");
        rebind_v2_evidence(&owner, V2_FLOOR, |evidence| {
            evidence["v2_release"][edit] = json!("e".repeat(64));
            if edit == "manifest_sha256" {
                evidence["install_identity"]["release_identity_sha256"] = json!("e".repeat(64));
            }
        });
        let before = observe_tree(&owner.fixture.state);
        let output = owner.run();
        assert_eq!(output.status.code(), Some(1), "{label}");
        assert!(output.stdout.is_empty(), "{label}");
        assert_eq!(observe_tree(&owner.fixture.state), before, "{label}");
    }
    // The install identity must be the manifest digest (contract §6).
    let identity = install_v2_owner("v2-evidence-identity", "manifest-digest");
    rebind_v2_evidence(&identity, V2_FLOOR, |evidence| {
        evidence["install_identity"]["release_identity_sha256"] = json!("77".repeat(32));
    });
    identity.assert_refused("release identity", "violates its closed contract");
}

#[test]
fn v2_lane_binds_the_booted_deployment_to_the_receipt_host() {
    let origin = install_v2_owner("v2-booted-origin", "manifest-digest");
    let other = format!(
        "{}@sha256:{}",
        origin.golden["expected"]["host_repository"]
            .as_str()
            .unwrap(),
        "9".repeat(64)
    );
    write_mode(
        &origin.ostree.origin,
        format!("[origin]\ncontainer-image-reference=ostree-unverified-registry:{other}\n")
            .as_bytes(),
        0o644,
    );
    origin.assert_refused(
        "another index digest",
        "booted deployment differs from authenticated v2 release baseline",
    );

    let repository = install_v2_owner("v2-booted-repository", "manifest-digest");
    let foreign = format!(
        "registry.example.invalid/neural-ice-test/host-appliance@{}",
        repository.golden["inputs"]["host_index_digest"]
            .as_str()
            .unwrap()
    );
    write_mode(
        &repository.ostree.origin,
        format!("[origin]\ncontainer-image-reference=ostree-unverified-registry:{foreign}\n")
            .as_bytes(),
        0o644,
    );
    repository.assert_refused("another repository", "booted deployment differs");

    let child = install_v2_owner("v2-booted-child", "manifest-digest");
    fs::write(
        &child.ostree.metadata,
        format!("'sha256:{}'\n", "8".repeat(64)),
    )
    .unwrap();
    child.assert_refused("another platform manifest", "booted deployment differs");
}

#[test]
fn v2_lane_refuses_a_live_root_that_drifted_from_the_receipt() {
    for marker in [
        "hardware-target",
        "appliance-variant",
        "signed-boot-trust-policy-id",
        "access-policy",
        "ota-state-profile",
    ] {
        let owner = install_v2_owner(&format!("v2-live-{marker}"), "manifest-digest");
        fs::write(
            owner.live_root.join(format!("usr/lib/neural-ice/{marker}")),
            b"drifted\n",
        )
        .unwrap();
        owner.assert_refused(marker, "candidate-marker");
    }
    let key = install_v2_owner("v2-live-key", "manifest-digest");
    fs::write(
        key.live_root
            .join("usr/lib/neural-ice/keys/release-authorization.pub"),
        b"another\n",
    )
    .unwrap();
    key.assert_refused("live key", "key-digest");

    // The v2 host forbids the v1 anchors: one planted after install refuses.
    let anchor = install_v2_owner("v2-live-anchor", "manifest-digest");
    fs::create_dir_all(anchor.live_root.join("etc/neural-ice/keys")).unwrap();
    fs::write(
        anchor.live_root.join("etc/neural-ice/keys/ota-root.pub"),
        b"x",
    )
    .unwrap();
    anchor.assert_refused("ota-root.pub", "candidate-anchor");
}

#[test]
fn v2_lane_refuses_a_written_owner_anchor_and_generation_state() {
    let written = install_v2_owner("v2-anchor-written", "manifest-digest");
    let public = owner_public(
        "000b11afd155aca82a503f2029cc11395389654c3a25fc54b9eca6d33abdff498d56",
        "policywrite|authread|ownerread|no_da|nt=extend|written",
    );
    install_read_only_tpm(
        &written.fixture,
        &written.access,
        &public,
        Some(&"ab".repeat(32)),
        V2_FLOOR,
    );
    written.assert_refused("written anchor", "owner-state inspection does not match");

    let state = install_v2_owner("v2-generation-state", "manifest-digest");
    fs::create_dir(state.state("state-v1")).unwrap();
    fs::set_permissions(state.state("state-v1"), fs::Permissions::from_mode(0o700)).unwrap();
    state.assert_refused("generation state", "mixed with generation state");
}

#[test]
fn v2_lane_has_no_relaxed_branch() {
    // NEURALICE_SEALED_OTA_STATE defaults to `relaxed` elsewhere and turns an
    // unreadable attestation into a fail-open there. Here it changes nothing.
    for posture in ["relaxed", "strict", ""] {
        let owner = install_v2_owner("v2-posture", "manifest-digest");
        let path = owner.state("v2-release/receipt.json");
        let mut bytes = fs::read(&path).unwrap();
        bytes[10] ^= 0x01;
        write_mode(&path, &bytes, 0o600);
        let output = owner
            .command()
            .env("NEURALICE_SEALED_OTA_STATE", posture)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1), "posture `{posture}`");
        assert!(output.stdout.is_empty(), "posture `{posture}`");
    }
}

#[test]
fn v2_lane_does_not_read_the_payload_marker() {
    // `no-such-PAYLOAD_ID` is not a file: the v1 reader would refuse on it.
    let owner = install_v2_owner("v2-no-payload", "manifest-digest");
    assert!(!owner.payload.exists());
    assert_eq!(owner.run().status.code(), Some(0));
}

#[test]
fn preseal_lane_refuses_v2_release_state_beside_it() {
    // The lanes are disjoint in both directions: a v1-marker appliance that
    // carries the v2 attestation directories is mixed, not answered.
    let owner = install_pristine_owner("v1-with-v2-state");
    assert_eq!(owner.run().status.code(), Some(0));
    let directory = owner.fixture.state.join("v2-release");
    fs::create_dir(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    let before = observe_tree(&owner.fixture.state);
    let output = owner.run();
    assert_owner_status_refused(&owner.fixture, &output, &before);
    assert!(String::from_utf8_lossy(&output.stderr).contains("mixed with v2-release evidence"));
}

// ---------------------------------------------------------------------------
// T9, the succession rule: a booted host that is not the one the install
// receipt names is accepted when it is the host of the CURRENT RELEASE — the
// manifest `/var/lib/neural-ice-v2/current-release/` that the engine hands over
// — signed under the receipt's own release key, at a `bundle_seq` no lower than
// the TPM floor, for the receipt's hardware target and release authority.
// The golden key is not kept, so these appliances are re-keyed with a key the
// test holds: the receipt, its digest and the completion evidence follow it.
// ---------------------------------------------------------------------------

const SUCCESSOR_INDEX: &str =
    "sha256:c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3";
const SUCCESSOR_CHILD: &str =
    "sha256:d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4";

struct V2Keyed {
    owner: V2Owner,
    private_key: PathBuf,
}

fn sign_v2_manifest(private_key: &Path, work: &Path, name: &str, manifest: &[u8]) -> Vec<u8> {
    let payload = work.join(format!("{name}.manifest"));
    let der = work.join(format!("{name}.der"));
    fs::write(&payload, manifest).unwrap();
    openssl(&[
        "dgst",
        "-sha256",
        "-sign",
        private_key.to_str().unwrap(),
        "-out",
        der.to_str().unwrap(),
        payload.to_str().unwrap(),
    ]);
    base64(&fs::read(&der).unwrap()).into_bytes()
}

/// A completed v2 appliance whose receipt key is `private_key`: the golden
/// manifest is re-signed, the receipt and the evidence re-bound to it.
fn install_v2_keyed_owner(name: &str) -> V2Keyed {
    let mut owner = install_v2_owner(name, "manifest-digest");
    let work = owner.fixture.root.join("keyed");
    fs::create_dir(&work).unwrap();
    let private_key = work.join("release.key");
    let public_key = work.join("release.pub");
    openssl(&[
        "ecparam",
        "-name",
        "prime256v1",
        "-genkey",
        "-noout",
        "-out",
        private_key.to_str().unwrap(),
    ]);
    openssl(&[
        "ec",
        "-in",
        private_key.to_str().unwrap(),
        "-pubout",
        "-out",
        public_key.to_str().unwrap(),
    ]);
    let public = fs::read(&public_key).unwrap();
    let key_sha = hash(&public);
    fs::write(
        owner
            .live_root
            .join("usr/lib/neural-ice/keys/release-authorization.pub"),
        &public,
    )
    .unwrap();
    let manifest = fs::read(owner.state("v2-release-input-v1/release-manifest.json")).unwrap();
    let signature = sign_v2_manifest(&private_key, &work, "install", &manifest);
    write_mode(
        &owner.state("v2-release-input-v1/release-manifest.json.sig"),
        &signature,
        0o600,
    );
    let mut receipt: Value =
        serde_json::from_slice(&fs::read(owner.state("v2-release/receipt.json")).unwrap()).unwrap();
    receipt["release_key_sha256"] = json!(key_sha);
    receipt["manifest_sig_sha256"] = json!(hash(&signature));
    let receipt_bytes = canonical(&receipt);
    write_mode(&owner.state("v2-release/receipt.json"), &receipt_bytes, 0o600);
    owner.golden["inputs"]["sealed_key_sha256"] = json!(key_sha);
    owner.golden["inputs"]["sealed_manifest_sig_sha256"] = json!(hash(&signature));
    owner.golden["expected"]["receipt_sha256"]["manifest-digest"] = json!(hash(&receipt_bytes));
    let evidence = v2_evidence(&owner, V2_FLOOR);
    install_v2_completion(&owner, &evidence, V2_FLOOR);
    V2Keyed { owner, private_key }
}

impl V2Keyed {
    fn current_release(&self, relative: &str) -> PathBuf {
        self.owner
            .live_root
            .join("var/lib/neural-ice-v2/current-release")
            .join(relative)
    }

    /// The golden manifest with `edit` applied, signed by `key`, handed over
    /// as the current release.
    fn hand_over(&self, key: &Path, edit: impl FnOnce(&mut Value)) -> Vec<u8> {
        let mut manifest: Value = serde_json::from_slice(
            &fs::read(self.owner.state("v2-release-input-v1/release-manifest.json")).unwrap(),
        )
        .unwrap();
        edit(&mut manifest);
        let bytes = serde_json::to_vec(&manifest).unwrap();
        let signature = sign_v2_manifest(key, &self.owner.fixture.root.join("keyed"), "current", &bytes);
        fs::create_dir_all(self.current_release("")).unwrap();
        write_mode(&self.current_release("release-manifest.json"), &bytes, 0o644);
        write_mode(
            &self.current_release("release-manifest.json.sig"),
            &signature,
            0o644,
        );
        bytes
    }

    /// The signed successor host: bundle 4, a new index digest.
    fn hand_over_successor(&self) {
        self.hand_over(&self.private_key, |manifest| {
            manifest["bundle_seq"] = json!(V2_FLOOR + 1);
            manifest["release_id"] = json!("v2-test-train-4");
            manifest["host"]["digest"] = json!(SUCCESSOR_INDEX);
        });
    }

    fn repository(&self) -> String {
        self.owner.golden["expected"]["host_repository"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    fn boot(&self, index_digest: &str, child: &str) {
        self.boot_ref(&format!("{}@{index_digest}", self.repository()), child);
    }

    fn boot_ref(&self, host: &str, child: &str) {
        fs::remove_file(&self.owner.ostree.origin).unwrap();
        write_mode(
            &self.owner.ostree.origin,
            format!("[origin]\ncontainer-image-reference=ostree-unverified-registry:{host}\n")
                .as_bytes(),
            0o644,
        );
        fs::write(&self.owner.ostree.metadata, format!("'{child}'\n")).unwrap();
    }

    fn boot_successor(&self) {
        self.boot(SUCCESSOR_INDEX, SUCCESSOR_CHILD);
    }
}

const NOT_THE_CURRENT_HOST: &str = "booted deployment differs from authenticated v2 release baseline";

#[test]
fn v2_keyed_owner_is_still_accepted_on_the_install_host() {
    // The re-keying itself changes nothing the reader judges.
    let keyed = install_v2_keyed_owner("v2-t9-install-host");
    let output = keyed.owner.run();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, V2_HELD_STATUS);
}

#[test]
fn v2_lane_accepts_the_host_of_the_signed_current_release() {
    let keyed = install_v2_keyed_owner("v2-t9-successor");
    keyed.hand_over_successor();
    keyed.boot_successor();
    let before = observe_tree(&keyed.owner.fixture.state);
    let output = keyed.owner.run();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    // The licence gate compares these bytes: the same as for the install host.
    assert_eq!(output.stdout, V2_HELD_STATUS);
    assert_eq!(
        output.stdout,
        fs::read(v2_golden().join("expected-authenticated-ota-status.json")).unwrap()
    );
    assert!(output.stderr.is_empty());
    assert_eq!(observe_tree(&keyed.owner.fixture.state), before);
    assert_eq!(fs::read_dir(&keyed.owner.fixture.scratch).unwrap().count(), 0);
    let calls = fs::read_to_string(&keyed.owner.fixture.calls).unwrap();
    assert!(!calls.contains("FORBIDDEN"), "{calls}");
}

#[test]
fn v2_lane_accepts_a_current_release_at_the_floor_itself() {
    // `bundle_seq >= floor`: a host re-issued at the floor is not below it.
    let keyed = install_v2_keyed_owner("v2-t9-at-floor");
    keyed.hand_over(&keyed.private_key, |manifest| {
        manifest["host"]["digest"] = json!(SUCCESSOR_INDEX);
    });
    keyed.boot_successor();
    assert_eq!(keyed.owner.run().status.code(), Some(0));
}

#[test]
fn v2_lane_keeps_the_install_host_accepted_after_a_rollback() {
    // The engine rolled back: the booted host is the receipt's again while the
    // current release still names the successor, or names nothing readable.
    let keyed = install_v2_keyed_owner("v2-t9-rollback");
    keyed.hand_over_successor();
    assert_eq!(keyed.owner.run().status.code(), Some(0));
    fs::write(keyed.current_release("release-manifest.json"), b"{not json").unwrap();
    let output = keyed.owner.run();
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, V2_HELD_STATUS);
}

#[test]
fn v2_lane_refuses_a_booted_host_the_current_release_does_not_name() {
    let unknown = install_v2_keyed_owner("v2-t9-unknown-digest");
    unknown.hand_over_successor();
    unknown.boot(&format!("sha256:{}", "9".repeat(64)), SUCCESSOR_CHILD);
    unknown.owner.assert_refused("unknown index digest", NOT_THE_CURRENT_HOST);

    // The right index digest, pulled from another repository.
    let foreign = install_v2_keyed_owner("v2-t9-other-repository");
    foreign.hand_over_successor();
    foreign.boot_ref(
        &format!("registry.example.invalid/neural-ice-test/host-appliance@{SUCCESSOR_INDEX}"),
        SUCCESSOR_CHILD,
    );
    foreign.owner.assert_refused("another repository", NOT_THE_CURRENT_HOST);

    // No current release at all: only the receipt's host is the host.
    let none = install_v2_keyed_owner("v2-t9-no-current-release");
    none.boot_successor();
    none.owner.assert_refused("no current release", NOT_THE_CURRENT_HOST);

    // A malformed platform manifest digest is no host.
    let child = install_v2_keyed_owner("v2-t9-malformed-child");
    child.hand_over_successor();
    child.boot(SUCCESSOR_INDEX, "not-a-digest");
    child.owner.assert_refused("malformed child", "booted manifest metadata is malformed");
}

#[test]
fn v2_lane_refuses_a_current_release_below_the_floor() {
    let keyed = install_v2_keyed_owner("v2-t9-below-floor");
    keyed.hand_over(&keyed.private_key, |manifest| {
        manifest["bundle_seq"] = json!(V2_FLOOR - 1);
        manifest["host"]["digest"] = json!(SUCCESSOR_INDEX);
    });
    keyed.boot_successor();
    keyed.owner.assert_refused("bundle_seq 2 under floor 3", "bundle-seq");
}

#[test]
fn v2_lane_refuses_a_current_release_signed_by_another_key() {
    let keyed = install_v2_keyed_owner("v2-t9-other-key");
    let other = keyed.owner.fixture.root.join("keyed/other.key");
    openssl(&[
        "ecparam",
        "-name",
        "prime256v1",
        "-genkey",
        "-noout",
        "-out",
        other.to_str().unwrap(),
    ]);
    keyed.hand_over(&other, |manifest| {
        manifest["bundle_seq"] = json!(V2_FLOOR + 1);
        manifest["host"]["digest"] = json!(SUCCESSOR_INDEX);
    });
    keyed.boot_successor();
    keyed.owner.assert_refused("another key", "signature");

    // A manifest altered after it was signed.
    let tampered = install_v2_keyed_owner("v2-t9-tampered");
    tampered.hand_over_successor();
    let path = tampered.current_release("release-manifest.json");
    let mut bytes = fs::read(&path).unwrap();
    let at = bytes.windows(7).position(|window| window == b"train-4").unwrap();
    bytes[at + 6] = b'5';
    write_mode(&path, &bytes, 0o644);
    tampered.boot_successor();
    tampered.owner.assert_refused("manifest altered", "signature");
}

#[test]
fn v2_lane_refuses_a_current_release_for_another_target_or_authority() {
    let target = install_v2_keyed_owner("v2-t9-other-target");
    target.hand_over(&target.private_key, |manifest| {
        manifest["bundle_seq"] = json!(V2_FLOOR + 1);
        manifest["hardware_target"] = json!("nvidia-gb200-arm64");
        manifest["host"]["digest"] = json!(SUCCESSOR_INDEX);
    });
    target.boot_successor();
    target.owner.assert_refused("another hardware target", "hardware-target");

    let authority = install_v2_keyed_owner("v2-t9-other-authority");
    let foreign = "registry.example.invalid/neural-ice-test/host-appliance";
    authority.hand_over(&authority.private_key, |manifest| {
        manifest["bundle_seq"] = json!(V2_FLOOR + 1);
        manifest["host"]["repository"] = json!(foreign);
        manifest["host"]["digest"] = json!(SUCCESSOR_INDEX);
    });
    authority.boot_ref(&format!("{foreign}@{SUCCESSOR_INDEX}"), SUCCESSOR_CHILD);
    authority.owner.assert_refused("another authority", "authority");
}

#[test]
fn v2_lane_refuses_a_current_release_that_is_not_a_plain_file_pair() {
    let missing = install_v2_keyed_owner("v2-t9-no-signature");
    missing.hand_over_successor();
    fs::remove_file(missing.current_release("release-manifest.json.sig")).unwrap();
    missing.boot_successor();
    missing.owner.assert_refused("signature absent", NOT_THE_CURRENT_HOST);

    let link = install_v2_keyed_owner("v2-t9-symlinked");
    link.hand_over_successor();
    let real = link.owner.fixture.root.join("keyed/real-manifest.json");
    fs::rename(link.current_release("release-manifest.json"), &real).unwrap();
    std::os::unix::fs::symlink(&real, link.current_release("release-manifest.json")).unwrap();
    link.boot_successor();
    link.owner.assert_refused("manifest is a symlink", NOT_THE_CURRENT_HOST);

    let big = install_v2_keyed_owner("v2-t9-oversized");
    big.hand_over_successor();
    write_mode(
        &big.current_release("release-manifest.json"),
        &vec![b' '; 1024 * 1024 + 2],
        0o644,
    );
    big.boot_successor();
    big.owner.assert_refused("manifest oversized", NOT_THE_CURRENT_HOST);
}

#[test]
fn v2_lane_still_refuses_a_successor_under_a_written_anchor_or_drifted_root() {
    // The succession rule relaxes ONLY the host comparison.
    let written = install_v2_keyed_owner("v2-t9-written");
    written.hand_over_successor();
    written.boot_successor();
    let public = owner_public(
        "000b11afd155aca82a503f2029cc11395389654c3a25fc54b9eca6d33abdff498d56",
        "policywrite|authread|ownerread|no_da|nt=extend|written",
    );
    install_read_only_tpm(
        &written.owner.fixture,
        &written.owner.access,
        &public,
        Some(&"ab".repeat(32)),
        V2_FLOOR,
    );
    written
        .owner
        .assert_refused("written anchor", "owner-state inspection does not match");

    // A live root carrying another release key is not the receipt's key, even
    // when the current release is signed by that very key.
    let rekeyed = install_v2_keyed_owner("v2-t9-live-key");
    let other = rekeyed.owner.fixture.root.join("keyed/other.key");
    let other_pub = rekeyed.owner.fixture.root.join("keyed/other.pub");
    openssl(&["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", other.to_str().unwrap()]);
    openssl(&["ec", "-in", other.to_str().unwrap(), "-pubout", "-out", other_pub.to_str().unwrap()]);
    fs::copy(
        &other_pub,
        rekeyed
            .owner
            .live_root
            .join("usr/lib/neural-ice/keys/release-authorization.pub"),
    )
    .unwrap();
    rekeyed.hand_over(&other, |manifest| {
        manifest["bundle_seq"] = json!(V2_FLOOR + 1);
        manifest["host"]["digest"] = json!(SUCCESSOR_INDEX);
    });
    rekeyed.boot_successor();
    rekeyed.owner.assert_refused("live key is not the receipt's", "key-digest");
}
