#![cfg(all(target_os = "linux", feature = "test-path-overrides"))]

use std::fs;
use std::io::Write;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::{json, Value};

static NEXT: AtomicU64 = AtomicU64::new(0);

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
  0x01500005) python3 -c 'import sys; open(sys.argv[1],"wb").write((b"NI-TPM02"+bytes.fromhex(sys.argv[2])).ljust(64,b"\0"))' "$out" '{}' ;;
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
    const REPOSITORY: &str = "release.example.test/neural-ice/neural-ice-appliance";
    const INDEX: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const CHILD: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
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
        "appliance":{"os_base":{"digest":INDEX,"image":REPOSITORY},"version":"0.50.9-lab.20260905"},
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
        "access_profile":"lab-managed","hardware_target":"nvidia-gb10-arm64","image_index_digest":INDEX,
        "image_manifest_digest":CHILD,"image_platform":"linux/arm64","image_publication_shape":"index",
        "image_repository":REPOSITORY,"issuance_id":"install-lab-5","issuance_seq":"5",
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
        "signed_boot_trust_policy_id":"neural-ice-secureboot-lab-v1","target_os_ref":format!("{REPOSITORY}@{INDEX}"),
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
            &format!("{REPOSITORY}@{INDEX}"),
            "--current-os-manifest-digest",
            CHILD,
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
    write_mode(&profile, b"owner-sealed-ota-state-v1\n", 0o644);
    let payload = fixture.root.join("PAYLOAD_ID");
    write_mode(
        &payload,
        b"cccccccccccccccccccccccccccccccccccccccc\n",
        0o644,
    );
    let bootc = fixture.root.join("bootc");
    let bootc_status = serde_json::to_string(&json!({
        "spec":{"image":{"image":"release.example.test/neural-ice/neural-ice-appliance@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},
        "status":{"booted":{"image":{"image":{"image":"release.example.test/neural-ice/neural-ice-appliance@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
            "imageDigest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}}
    })).unwrap();
    write_mode(
        &bootc,
        format!("#!/bin/sh\nprintf '%s\\n' '{bootc_status}'\n").as_bytes(),
        0o755,
    );
    let before = observe_tree(&fixture.state);
    let output = success_command(&fixture)
        .env(
            "NI_OTA_OWNER_STATE_HELPER",
            fixture.root.join("owner-state"),
        )
        .env("NI_OTA_AUTH_STATUS_PROFILE_MARKER", &profile)
        .env("NI_OTA_AUTH_STATUS_BOOTC", &bootc)
        .env("NI_OTA_AUTH_STATUS_PAYLOAD_ID", &payload)
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
        let output = fixture.run();
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
