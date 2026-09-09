#!/usr/bin/env bash
# shellcheck disable=SC2016 # literal source-contract assertions below
# THE SEED THAT ARRIVES OVER THE LAN, PROVED AGAINST A REAL HTTPS MIRROR.
#
# `neuralice.seed_source=mirror` (FAB-0057 P1.1, docs/SEED-FROM-MIRROR.md) lets
# a registry medium seal a release seed with no ni-seed partition: the installer
# fetches the six seed-pack documents before the wipe and every closure object
# after LUKS/mkfs, each hashed against the name the sealed closure gives it.
# Since FAB-0057 P1.1b the manifest hash, the mirror READY pins and the
# authorization pair are DERIVED from documents the sealed line already fixes
# (rules C, A, B); this suite drives those derivations and their sabotages.
#
# WHAT THIS SUITE RUNS. The installer's OWN functions, lifted verbatim the way
# image/test-installer-media.sh lifts its seed reconciliation: the bounded
# fetcher, the pre-wipe preflight and the phase-5 materialisation. They are
# driven against a real local HTTPS server (python3 + ssl, a throwaway CA
# generated here) serving a fixture closure and its seed pack in exactly the
# layout the contract states, so `curl --proto =https --tlsv1.2 --cacert` is
# exercised for real, and the sabotage cases are real: an object altered on the
# mirror must refuse the install.
#
# The grammar side lives in image/test-lib/sealed-cmdline-corpus.tsv; the
# ordering properties (documents before the wipe, objects after LUKS, verifier
# after landing) in ci/test-install-registry-mirror.sh.
#
# 🔴 NO SKIP PATH. bash, python3, curl, openssl and sha256sum are the whole
# toolchain, and if any is absent the answer is a failure, not a green run.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AUTOINSTALL="$ROOT/ota/neural-ice-autoinstall.sh"
BUILDER="$ROOT/image/build-installer-usb.sh"
PRELOADED="$ROOT/image/build-preloaded.sh"
DOC="$ROOT/docs/SEED-FROM-MIRROR.md"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/ni-seed-from-mirror.XXXXXX")"
SERVER_PID=""
cleanup() {
  [[ -z "$SERVER_PID" ]] || { kill "$SERVER_PID" 2>/dev/null || true; wait "$SERVER_PID" 2>/dev/null || true; }
  rm -rf "$TMP"
}
trap cleanup EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
for tool in python3 curl openssl sha256sum; do
  command -v "$tool" >/dev/null 2>&1 || fail "$tool is required; this suite does not SKIP"
done
for required in "$AUTOINSTALL" "$BUILDER" "$PRELOADED" "$DOC"; do
  [ -f "$required" ] || fail "missing input: $required"
done

# --------------------------------------------------------------------------- #
# 1) THE CODE UNDER TEST, LIFTED OUT OF THE INSTALLER AND THE PRODUCER.
# --------------------------------------------------------------------------- #
LIFTED="$TMP/lifted.sh"
{
  awk '/^karg_count\(\) \{/,/^}$/' "$AUTOINSTALL"
  awk '/^esp_staged_file\(\) \{/,/^}$/' "$AUTOINSTALL"
  awk '/^seed_mirror_helper\(\) \{/,/^}$/' "$AUTOINSTALL"
  awk '/^seed_from_mirror_fetch_documents\(\) \{/,/^}$/' "$AUTOINSTALL"
  awk '/^seed_from_mirror_preflight\(\) \{/,/^}$/' "$AUTOINSTALL"
  awk '/^seed_from_mirror_materialize\(\) \{/,/^}$/' "$AUTOINSTALL"
  awk '/^assert_sealed_document_digest\(\) \{/,/^}$/' "$AUTOINSTALL"
  awk '/^seed_manifest_hash_from_closure\(\) \{/,/^}$/' "$AUTOINSTALL"
  awk '/^preseal_installer_authorization_pins\(\) \{/,/^}$/' "$AUTOINSTALL"
  awk '/^release_authorization_pins_from_preseal\(\) \{/,/^}$/' "$AUTOINSTALL"
  awk '/^assert_seed_is_the_preseal_release\(\) \{/,/^}$/' "$AUTOINSTALL"
} > "$LIFTED"
for function in karg_count esp_staged_file seed_mirror_helper seed_from_mirror_fetch_documents \
  seed_from_mirror_preflight seed_from_mirror_materialize assert_sealed_document_digest \
  seed_manifest_hash_from_closure preseal_installer_authorization_pins \
  release_authorization_pins_from_preseal assert_seed_is_the_preseal_release; do
  grep -q "^${function}()" "$LIFTED" || fail "the installer no longer defines ${function} as an extractable function"
done
grep -q "SEED_MIRROR_PY" "$LIFTED" || fail "the installer's mirror fetcher lost its bounded Python helper"
awk '/^seal_offline_seed_kargs\(\) \{/,/^}$/' "$BUILDER" > "$TMP/seal.sh"
grep -q '^seal_offline_seed_kargs()' "$TMP/seal.sh" || fail "the producer no longer seals the seed tuple in one function"
grep -q 'neuralice.seed_source=mirror' "$TMP/seal.sh" || fail "the producer no longer seals neuralice.seed_source"

# The contract the document states and the code the installer runs must name
# the same constants: a drift here is a bench that publishes one thing and an
# installer that refuses it.
for literal in 'neural-ice/seed-packs' 'application/vnd.neural-ice.seed-pack.v1+json' \
  'application/vnd.neural-ice.seed-pack.config.v1+json' \
  '44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a' \
  'release-manifest.json' 'release-closure.json' 'release-authorization.json' \
  'release-authorization.json.sig' 'delegation-snapshot.json' 'delegation-snapshot.json.sig' \
  'org.opencontainers.image.title'; do
  grep -qF -- "$literal" "$DOC" || fail "docs/SEED-FROM-MIRROR.md no longer states: $literal"
  grep -qF -- "$literal" "$LIFTED" || fail "the installer's fetcher no longer names: $literal"
done

# --------------------------------------------------------------------------- #
# 2) A THROWAWAY CA, A SERVER CERTIFICATE FOR localhost, AND A ROGUE CA.
# --------------------------------------------------------------------------- #
PKI="$TMP/pki"; mkdir -p "$PKI"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout "$PKI/ca.key" -out "$PKI/ca.crt" -days 2 -subj "/CN=seed-from-mirror test CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" >/dev/null 2>&1 \
  || fail "cannot generate the test CA"
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout "$PKI/server.key" -out "$PKI/server.csr" -subj "/CN=localhost" >/dev/null 2>&1 \
  || fail "cannot generate the server key"
printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=CA:FALSE\n' > "$PKI/server.ext"
openssl x509 -req -in "$PKI/server.csr" -CA "$PKI/ca.crt" -CAkey "$PKI/ca.key" -CAcreateserial \
  -days 2 -out "$PKI/server.crt" -extfile "$PKI/server.ext" >/dev/null 2>&1 \
  || fail "cannot sign the server certificate"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout "$PKI/rogue.key" -out "$PKI/rogue.crt" -days 2 -subj "/CN=rogue CA" \
  -addext "basicConstraints=critical,CA:TRUE" >/dev/null 2>&1 || fail "cannot generate the rogue CA"

# --------------------------------------------------------------------------- #
# 3) THE MIRROR: a real TLS server on 127.0.0.1 serving a directory tree in the
#    registry layout, logging every request so the suite can prove what was and
#    was not fetched.
# --------------------------------------------------------------------------- #
MIRROR_ROOT="$TMP/mirror"; mkdir -p "$MIRROR_ROOT"
REQUEST_LOG="$TMP/requests.log"; : > "$REQUEST_LOG"
cat > "$TMP/server.py" <<'PYEOF'
import http.server
import ssl
import sys

root, cert, key, portfile, logfile = sys.argv[1:]


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=root, **kwargs)

    def log_message(self, fmt, *args):
        with open(logfile, "a", encoding="utf-8") as handle:
            handle.write((fmt % args) + "\n")


server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.minimum_version = ssl.TLSVersion.TLSv1_2
context.load_cert_chain(cert, key)
server.socket = context.wrap_socket(server.socket, server_side=True)
with open(portfile, "w", encoding="ascii") as handle:
    handle.write(str(server.server_address[1]))
server.serve_forever()
PYEOF
python3 "$TMP/server.py" "$MIRROR_ROOT" "$PKI/server.crt" "$PKI/server.key" "$TMP/port" "$REQUEST_LOG" \
  >"$TMP/server.out" 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 100); do
  [[ -s "$TMP/port" ]] && break
  sleep 0.1
done
[[ -s "$TMP/port" ]] || fail "the test mirror did not start: $(cat "$TMP/server.out")"
MIRROR="localhost:$(cat "$TMP/port")"
for _ in $(seq 1 100); do
  curl --silent --output /dev/null --proto '=https' --tlsv1.2 --cacert "$PKI/ca.crt" "https://$MIRROR/" && break
  sleep 0.1
done
curl --silent --output /dev/null --proto '=https' --tlsv1.2 --cacert "$PKI/ca.crt" "https://$MIRROR/" \
  || fail "the test mirror does not answer over TLS pinned to the test CA"
: > "$REQUEST_LOG"
requests_since() { # $1=line count marker -> the request lines logged since
  tail -n +"$(( $1 + 1 ))" "$REQUEST_LOG"
}
log_mark() { wc -l < "$REQUEST_LOG"; }

# --------------------------------------------------------------------------- #
# 4) THE FIXTURE: one release, written the way Fabric writes it -- a closure
#    naming one artifact (index, manifest, config, two layers) with one cosign
#    signature attachment (attachment manifest, its config, its payload layer),
#    the release manifest, the preseal set, the four authority documents, and the
#    seed pack as the contract publishes it. The mirror tree is the contract's
#    layout. Variants state one difference each.
# --------------------------------------------------------------------------- #
cat > "$TMP/fixture.py" <<'PYEOF'
import hashlib
import json
import os
import pathlib
import sys

out, variant = pathlib.Path(sys.argv[1]), sys.argv[2]
AUTHORITY = "release.example.test"
REPOSITORY = f"{AUTHORITY}/neural-ice/runtime"
MIRROR_PATH = "neural-ice/runtime"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_INDEX = "application/vnd.oci.image.index.v1+json"
OCI_CONFIG = "application/vnd.oci.image.config.v1+json"
OCI_LAYER = "application/vnd.oci.image.layer.v1.tar+gzip"
PACK_ARTIFACT_TYPE = "application/vnd.neural-ice.seed-pack.v1+json"
PACK_CONFIG_TYPE = "application/vnd.neural-ice.seed-pack.config.v1+json"
TITLE = "org.opencontainers.image.title"
MIB = 1024 * 1024


def canonical(document):
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


mirror = out / "mirror"
blobs = mirror / "v2" / MIRROR_PATH / "blobs"
manifests = mirror / "v2" / MIRROR_PATH / "manifests"
for directory in (blobs, manifests):
    directory.mkdir(parents=True, exist_ok=True)
objects = {}   # hex -> bytes


def blob(raw):
    objects[digest(raw)[7:]] = raw
    (blobs / digest(raw)).write_bytes(raw)
    return digest(raw), len(raw)


def manifest(raw):
    objects[digest(raw)[7:]] = raw
    (manifests / digest(raw)).write_bytes(raw)
    return digest(raw), len(raw)


config_raw = canonical({"architecture": "arm64", "os": "linux"})
layer_one_raw = os.urandom(3 * MIB + 7)
layer_two_raw = os.urandom(4096)
config_digest, config_size = blob(config_raw)
layer_one_digest, layer_one_size = blob(layer_one_raw)
layer_two_digest, layer_two_size = blob(layer_two_raw)
image_manifest_raw = canonical({
    "schemaVersion": 2, "mediaType": OCI_MANIFEST,
    "config": {"mediaType": OCI_CONFIG, "digest": config_digest, "size": config_size},
    "layers": [
        {"mediaType": OCI_LAYER, "digest": layer_one_digest, "size": layer_one_size},
        {"mediaType": OCI_LAYER, "digest": layer_two_digest, "size": layer_two_size},
    ],
})
image_manifest_digest, image_manifest_size = manifest(image_manifest_raw)
index_raw = canonical({
    "schemaVersion": 2, "mediaType": OCI_INDEX,
    "manifests": [{"mediaType": OCI_MANIFEST, "digest": image_manifest_digest,
                   "size": image_manifest_size,
                   "platform": {"architecture": "arm64", "os": "linux"}}],
})
index_digest, index_size = manifest(index_raw)

attachment_config_raw = b"{}"
payload_raw = canonical({"critical": {"identity": {"docker-reference": REPOSITORY},
                                      "image": {"docker-manifest-digest": image_manifest_digest},
                                      "type": "cosign container image signature"}})
attachment_config_digest, attachment_config_size = blob(attachment_config_raw)
payload_digest, payload_size = blob(payload_raw)
attachment_raw = canonical({
    "schemaVersion": 2, "mediaType": OCI_MANIFEST,
    "config": {"mediaType": OCI_CONFIG, "digest": attachment_config_digest, "size": attachment_config_size},
    "layers": [{"mediaType": "application/vnd.dev.cosign.simplesigning.v1+json",
                "digest": payload_digest, "size": payload_size}],
})
attachment_digest, attachment_size = manifest(attachment_raw)

layer_two_declared = layer_two_size
if variant == "wrong-size":
    layer_two_declared = layer_two_size + 1
if variant == "huge":
    layer_two_declared = 2 ** 50
nodes = [
    {"repository": REPOSITORY, "digest": config_digest, "media_type": OCI_CONFIG, "size": config_size,
     "kind": "config", "signatures": []},
    {"repository": REPOSITORY, "digest": layer_one_digest, "media_type": OCI_LAYER, "size": layer_one_size,
     "kind": "layer", "signatures": []},
    {"repository": REPOSITORY, "digest": layer_two_digest, "media_type": OCI_LAYER, "size": layer_two_declared,
     "kind": "layer", "signatures": []},
    {"repository": REPOSITORY, "digest": image_manifest_digest, "media_type": OCI_MANIFEST,
     "size": image_manifest_size, "kind": "manifest", "signatures": [{"scheme": "cosign-sigstore-v1"}]},
    {"repository": REPOSITORY, "digest": index_digest, "media_type": OCI_INDEX, "size": index_size,
     "kind": "index", "signatures": [{"scheme": "cosign-sigstore-v1"}]},
]
nodes.sort(key=lambda node: node["digest"])
closure = {
    "schema": "neural-ice-oci-release-closure-v1", "closure_format_version": 1,
    "release_id": "release-1-0-0", "bundle_seq": 13, "hardware_target": "nvidia-gb10-arm64",
    "security_posture": "sealed", "boot_trust_profile": "neural-ice-secureboot-lab-v1",
    "host_digest": index_digest, "train": "1.0.0", "traversal_bound": 4,
    "artifacts": [{
        "artifact_key": "image:runtime", "artifact_class": "portable-multiarch-image",
        "repository": REPOSITORY, "candidate_repository": REPOSITORY,
        "root": {"repository": REPOSITORY, "digest": index_digest},
        "nodes": nodes, "edges": [],
        "attachments": [{
            "subject_repository": REPOSITORY, "subject_digest": image_manifest_digest,
            "kind": "signature", "manifest_digest": attachment_digest, "media_type": OCI_MANIFEST,
            "layer_digests": [payload_digest], "artifact_type": None,
            "discovery": {"cosign_tag": f"sha256-{image_manifest_digest[7:]}.sig",
                          "fallback_tag": f"sha256-{image_manifest_digest[7:]}", "referrers_api": False},
            "predicate_type": None,
        }],
        "required_entitlement": "ICECORE",
    }],
}
release_manifest_raw = canonical({
    "schema": "neural-ice-release-manifest-v1", "release_id": "release-1-0-0", "bundle_seq": 13,
    "hardware_target": "nvidia-gb10-arm64",
    "host": {"repository": REPOSITORY, "digest": index_digest},
})
# The closure names its release manifest by hash, as Fabric's does; the
# installer derives the expected manifest hash from the proved closure (rule C).
closure["release_manifest_sha256"] = digest(release_manifest_raw)[7:]
if variant == "manifest-mismatch":
    closure["release_manifest_sha256"] = "0" * 63 + "1"
if variant == "manifest-unnamed":
    del closure["release_manifest_sha256"]
closure_raw = canonical(closure)
preseal_raw = canonical({
    "schema": "neural-ice-installer-preseal-set-v1", "train": "1.0.0", "bundle_seq": 13,
    "hardware_target": "nvidia-gb10-arm64", "ring": "lab",
    "signed_boot_trust_policy_id": "neural-ice-secureboot-lab-v1",
    "target_os_ref": f"{REPOSITORY}@{index_digest}",
})
documents = {
    "release-manifest.json": ("application/json", release_manifest_raw),
    "release-closure.json": ("application/json", closure_raw),
    "release-authorization.json": ("application/json", canonical({"schema": "fixture-authorization"})),
    "release-authorization.json.sig": ("application/octet-stream", os.urandom(64)),
    "delegation-snapshot.json": ("application/json", canonical({"schema": "fixture-delegation"})),
    "delegation-snapshot.json.sig": ("application/octet-stream", os.urandom(64)),
}
docs = out / "docs"; docs.mkdir(exist_ok=True)
preseal = out / "preseal"; preseal.mkdir(exist_ok=True)
(preseal / "preseal-set.json").write_bytes(preseal_raw)
pack_blobs = mirror / "v2" / "neural-ice" / "seed-packs" / "blobs"
pack_manifests = mirror / "v2" / "neural-ice" / "seed-packs" / "manifests"
pack_blobs.mkdir(parents=True, exist_ok=True); pack_manifests.mkdir(parents=True, exist_ok=True)
layers = []
for title, (media_type, raw) in documents.items():
    (docs / title).write_bytes(raw)
    (pack_blobs / digest(raw)).write_bytes(raw)
    layers.append({"mediaType": media_type, "digest": digest(raw), "size": len(raw),
                   "annotations": {TITLE: title}})
closure_hex = digest(closure_raw)[7:]
manifest_hex = digest(release_manifest_raw)[7:]
pack = {
    "schemaVersion": 2, "mediaType": OCI_MANIFEST, "artifactType": PACK_ARTIFACT_TYPE,
    "config": {"mediaType": PACK_CONFIG_TYPE, "digest": digest(b"{}"), "size": 2},
    "layers": layers,
}
(pack_manifests / closure_hex).write_bytes(json.dumps(pack, indent=1).encode("utf-8"))
(out / "closure_hex").write_text(closure_hex + "\n")
(out / "manifest_hex").write_text(manifest_hex + "\n")
(out / "expected").write_text("".join(f"{hex_value}\n" for hex_value in sorted(objects)))
(out / "layer_one_hex").write_text(layer_one_digest[7:] + "\n")
(out / "layer_two_hex").write_text(layer_two_digest[7:] + "\n")
(out / "attachment_hex").write_text(attachment_digest[7:] + "\n")
(out / "os_image").write_text(f"{REPOSITORY}@{index_digest}\n")
objects_dir = out / "objects"; objects_dir.mkdir(exist_ok=True)
for hex_value, raw in objects.items():
    (objects_dir / hex_value).write_bytes(raw)
PYEOF
make_fixture() { # $1=name $2=variant
  local root="$TMP/fixture-$1"
  rm -rf -- "$root"; mkdir -p "$root"
  python3 "$TMP/fixture.py" "$root" "$2" || fail "cannot build the $1 fixture"
  printf '%s' "$root"
}
publish() { # $1=fixture root -> the mirror serves exactly this fixture
  rm -rf -- "${MIRROR_ROOT:?}/v2"
  cp -a "$1/mirror/v2" "$MIRROR_ROOT/v2"
}
OK="$(make_fixture ok ok)"
CLOSURE_HEX="$(cat "$OK/closure_hex")"
MANIFEST_HEX="$(cat "$OK/manifest_hex")"
OS_IMAGE_REF="$(cat "$OK/os_image")"
PRESEAL_SHA256="$(sha256sum -- "$OK/preseal/preseal-set.json" | awk '{print tolower($1)}')"
EXPECTED_COUNT="$(grep -c . "$OK/expected")"
[[ "$EXPECTED_COUNT" == 8 ]] || fail "the fixture closure should derive 8 objects, derived $EXPECTED_COUNT"

# --------------------------------------------------------------------------- #
# 5) DRIVERS. Each runs the lifted production code in a subshell with the
#    installer's own names bound, `die` stubbed to a visible exit, and every
#    console helper a no-op. `$1` is the case label; the rest are ENV=VALUE
#    overrides; stderr lands in $TMP/last.err for the message assertions.
# --------------------------------------------------------------------------- #
# Variables and stubs are consumed by the exact production functions sourced
# below, indirectly.
# shellcheck disable=SC2034,SC2329,SC2317
bind_installer() { # sourced inside the driver subshells
  die() { echo "die: $*" >&2; exit 1; }
  log() { echo "log: $*" >&2; }
  heartbeat_start() { :; }
  copy_progress_start() { :; }
  bg_stop() { :; }
  INSTALL_SOURCE=registry
  INSTALL_MIRROR="$MIRROR"
  MIRROR_CA_FILE="$PKI/ca.crt"
  SEED_CLOSURE="$CLOSURE_HEX"
  SEED_MANIFEST_SHA256="$MANIFEST_HEX"
  SEED_TRUSTED_NOW=2026-09-09T12:00:00Z
  SEED_VERIFIED_ROOT=""
  PRESEAL_ACTIVE=1
  MIRROR_READY_SHA256="$CLOSURE_HEX"
  MIRROR_READY_MANIFEST_SHA256="$MANIFEST_HEX"
  NEURALICE_SEED_VERIFIER=/bin/true
  NEURALICE_RELEASE_AUTHORITY=release.example.test
  SEED_PACK_DIR="$TMP/seed-pack"
  NEURALICE_CMDLINE_FILE="$TMP/cmdline"
  PRESEAL_SNAPSHOT="$OK/preseal"
  PRESEAL_SET_SHA256="$PRESEAL_SHA256"
  OS_IMAGE="$OS_IMAGE_REF"
  AUTH_TARGET_REF="$OS_IMAGE_REF"
  SEALED_HARDWARE_TARGET=nvidia-gb10-arm64
  SEALED_TRUST_POLICY_ID=neural-ice-secureboot-lab-v1
  DEVICE_CHANNEL=lab
}
declare -f bind_installer > "$TMP/bind.sh"
# The sealed line the lifted karg_count reads: the composed medium as the
# producer now cuts it -- no relauth pair, no READY pins, no manifest hash.
printf 'quiet systemd.unit=neural-ice-installer.target neuralice.autoinstall=1 neuralice.source=registry neuralice.preseal=%s neuralice.mirror=%s neuralice.seed_closure=%s neuralice.seed_source=mirror\n' \
  "$PRESEAL_SHA256" "$MIRROR" "$CLOSURE_HEX" > "$TMP/cmdline"

run_fetch() { # $1=label $2=partuuid [ENV=VALUE …] -> 0 when the six documents landed; prints derived=<manifest hex>
  local label=$1 partuuid=$2; shift 2
  printf '%s\n' "$label" > "$TMP/last.case"
  (
    set -uo pipefail
    # shellcheck source=/dev/null
    . "$TMP/bind.sh"; bind_installer
    SEED_MANIFEST_SHA256=""
    for assignment in "$@"; do eval "$assignment"; done
    # shellcheck source=/dev/null
    . "$LIFTED"
    seed_from_mirror_fetch_documents "$partuuid"
    printf 'derived=%s\n' "$SEED_MANIFEST_SHA256"
  ) >"$TMP/last.out" 2>"$TMP/last.err"
}

run_preflight() { # $1=label $2=partuuid [ENV=VALUE …] -> 0 when the installer would proceed
  local label=$1 partuuid=$2; shift 2
  printf '%s\n' "$label" > "$TMP/last.case"
  (
    set -uo pipefail
    # shellcheck source=/dev/null
    . "$TMP/bind.sh"; bind_installer
    for assignment in "$@"; do eval "$assignment"; done
    # shellcheck source=/dev/null
    . "$LIFTED"
    seed_from_mirror_preflight "$partuuid"
  ) >"$TMP/last.out" 2>"$TMP/last.err"
}

run_materialize() { # $1=label $2=destination [ENV=VALUE …] -> 0 when the objects landed and READY exists
  local label=$1 destination=$2; shift 2
  printf '%s\n' "$label" > "$TMP/last.case"
  (
    set -uo pipefail
    # shellcheck source=/dev/null
    . "$TMP/bind.sh"; bind_installer
    for assignment in "$@"; do eval "$assignment"; done
    # shellcheck source=/dev/null
    . "$LIFTED"
    seed_from_mirror_materialize "$destination"
  ) >"$TMP/last.out" 2>"$TMP/last.err"
}

expect_refusal() { # $1=label $2=needle in stderr
  grep -qF -- "$2" "$TMP/last.err" \
    || fail "$1: refused for another reason than expected ('$2'); stderr: $(tail -n 3 "$TMP/last.err")"
}

stage_documents() { # $1=fixture root -> SEED_PACK_DIR holds its six documents (bypassing the preflight)
  rm -rf -- "$TMP/seed-pack"; mkdir -p "$TMP/seed-pack"
  cp -- "$1"/docs/* "$TMP/seed-pack/"
}

# --------------------------------------------------------------------------- #
# 6) THE PRE-WIPE PREFLIGHT: the six documents, over pinned TLS.
# --------------------------------------------------------------------------- #
publish "$OK"
mark="$(log_mark)"
run_fetch "supported fetch" "" \
  || fail "the installer refused the supported mirror-sourced seed pack: $(tail -n 3 "$TMP/last.err")"
for document in release-manifest.json release-closure.json release-authorization.json \
  release-authorization.json.sig delegation-snapshot.json delegation-snapshot.json.sig; do
  cmp -s -- "$OK/docs/$document" "$TMP/seed-pack/$document" \
    || fail "the fetched $document is not the published one"
done
[[ ! -e "$TMP/seed-pack/.seed-pack-manifest.json" ]] || fail "the untrusted pack manifest was left beside the documents"
requests_since "$mark" | grep -q "GET /v2/neural-ice/seed-packs/manifests/$CLOSURE_HEX " \
  || fail "the pack manifest was not fetched by the closure-hex tag"
[[ "$(requests_since "$mark" | grep -c 'GET /v2/neural-ice/seed-packs/blobs/sha256:')" == 6 ]] \
  || fail "the six documents were not fetched as six blobs"
# 🔴 RULE C, MEASURED. The manifest hash the installer will use is the one the
# proved closure carries, equal to the hash of the served manifest -- and the
# closure blob was fetched BEFORE the manifest blob, because the manifest layer
# can only be judged once the closure has said what the manifest is.
grep -qx "derived=$MANIFEST_HEX" "$TMP/last.out" \
  || fail "the fetch did not derive the manifest hash the closure carries: $(grep '^derived=' "$TMP/last.out")"
closure_request="$(requests_since "$mark" | grep -n "seed-packs/blobs/sha256:$CLOSURE_HEX " | head -1 | cut -d: -f1)"
manifest_request="$(requests_since "$mark" | grep -n "seed-packs/blobs/sha256:$MANIFEST_HEX " | head -1 | cut -d: -f1)"
[[ -n "$closure_request" && -n "$manifest_request" && "$closure_request" -lt "$manifest_request" ]] \
  || fail "the closure blob must be fetched and proved before the manifest blob is asked for (closure=$closure_request, manifest=$manifest_request)"
echo "  fetch: six documents fetched over TLS pinned to the sealed CA; the closure first, and the manifest hash derived from it (rule C)"

run_preflight "supported preflight" "" \
  || fail "the installer refused the fetched, supported seed pack at the preflight: $(tail -n 3 "$TMP/last.err")"
echo "  preflight: the fetched pack reconciled with the preseal set"

mark="$(log_mark)"
run_fetch "stray ni-seed partition" "0f0f0f0f-0000-4000-8000-000000000001" \
  && fail "a medium sealing seed_source=mirror AND carrying an ni-seed partition was accepted"
expect_refusal "stray ni-seed partition" "carries an ni-seed partition"
[[ -z "$(requests_since "$mark")" ]] || fail "the stray-partition refusal still spoke to the mirror"
run_preflight "stray ni-seed partition (preflight)" "0f0f0f0f-0000-4000-8000-000000000001" \
  && fail "the preflight accepted a medium carrying an ni-seed partition beside seed_source=mirror"
expect_refusal "stray ni-seed partition (preflight)" "carries an ni-seed partition"

run_preflight "no preseal" "" 'PRESEAL_ACTIVE=0' \
  && fail "a mirror-sourced seed with no preseal set was accepted"
expect_refusal "no preseal" "requires the signed preseal set"
run_fetch "no sealed preseal set" "" 'PRESEAL_SET_SHA256=""' \
  && fail "a mirror-sourced seed on a medium sealing no preseal set was fetched"
expect_refusal "no sealed preseal set" "requires the signed preseal set"
run_fetch "medium source" "" 'INSTALL_SOURCE=medium' \
  && fail "a mirror-sourced seed on a medium install was accepted"
expect_refusal "medium source" "requires neuralice.source=registry"
run_fetch "no mirror" "" 'INSTALL_MIRROR=""' \
  && fail "a mirror-sourced seed with no mirror was accepted"
expect_refusal "no mirror" "requires a LAN mirror whose CA this medium pins"
run_preflight "mirror declares another release" "" "MIRROR_READY_SHA256=$(printf '%064d' 9)" \
  && fail "a mirror declaring another release closure was accepted"
expect_refusal "mirror declares another release" "a mirror that declares another release cannot serve this one"
run_preflight "mirror declares another manifest" "" "MIRROR_READY_MANIFEST_SHA256=$(printf '%064d' 9)" \
  && fail "a mirror declaring another release manifest than the closure names was accepted"
expect_refusal "mirror declares another manifest" "a mirror that declares another release cannot serve this one"
run_preflight "manifest hash never derived" "" 'SEED_MANIFEST_SHA256=""' 'MIRROR_READY_MANIFEST_SHA256=""' \
  && fail "a preflight with no derived manifest hash proceeded"
expect_refusal "manifest hash never derived" "incomplete tuple"
run_fetch "no verifier" "" 'NEURALICE_SEED_VERIFIER=/nonexistent' \
  && fail "a medium with no seed verifier was accepted"
expect_refusal "no verifier" "carries no seed-closure verifier"

# The pin is the pin: a mirror whose certificate the sealed CA did not issue
# cannot answer at all, and the refusal names the transport.
mark="$(log_mark)"
run_fetch "rogue CA" "" "MIRROR_CA_FILE=$PKI/rogue.crt" \
  && fail "a mirror not issued by the pinned CA served the seed pack"
expect_refusal "rogue CA" "did not serve the seed pack"
[[ -z "$(requests_since "$mark")" ]] || fail "a TLS handshake the pin must refuse reached the request handler"

# A sealed closure the mirror has no pack for.
run_fetch "unknown closure" "" "SEED_CLOSURE=$(printf '%064d' 5)" \
  && fail "a closure the mirror does not carry was accepted"
expect_refusal "unknown closure" "did not serve the seed pack"

# 🔴 SABOTAGE, RULE C (FAB-0057 P1.1b brief, sabotage 2): a closure that hashes
# to the sealed value but names ANOTHER release manifest than the one the pack
# serves. The closure is proved first, the manifest layer is judged against
# what the closure says, and the refusal comes before the manifest blob is
# asked for. A closure naming no manifest at all is refused the same way.
MISMATCH="$(make_fixture manifest-mismatch manifest-mismatch)"
publish "$MISMATCH"
mark="$(log_mark)"
run_fetch "closure names another manifest" "" "SEED_CLOSURE=$(cat "$MISMATCH/closure_hex")" \
  && fail "a closure naming a release manifest the pack does not serve was accepted"
expect_refusal "closure names another manifest" "did not serve the seed pack"
grep -q "is not the release manifest the sealed closure names" "$TMP/last.err" \
  || fail "the closure/manifest mismatch was not the stated refusal: $(grep 'seed-mirror:' "$TMP/last.err" | tail -n 2)"
[[ "$(requests_since "$mark" | grep -c 'seed-packs/blobs/')" == 1 ]] \
  || fail "only the closure blob may be fetched before the manifest layer is judged: $(requests_since "$mark" | tr '\n' ' ')"
[[ ! -e "$TMP/seed-pack/release-manifest.json" ]] || fail "a manifest the closure does not name was published into the seed pack"
UNNAMED="$(make_fixture manifest-unnamed manifest-unnamed)"
publish "$UNNAMED"
run_fetch "closure names no manifest" "" "SEED_CLOSURE=$(cat "$UNNAMED/closure_hex")" \
  && fail "a closure naming no release manifest was accepted"
grep -q "carries no well-formed release_manifest_sha256" "$TMP/last.err" \
  || fail "the unnamed-manifest closure was not the stated refusal: $(grep 'seed-mirror:' "$TMP/last.err" | tail -n 2)"
echo "  fetch: a closure naming another manifest than the pack serves refuses before the manifest is fetched; a closure naming none refuses (rule C sabotage)"

# The pack manifest is untrusted routing, and every shape rule refuses.
mutate_pack() { # $1=how -> the mirror's pack manifest for the OK closure is altered
  python3 - "$MIRROR_ROOT/v2/neural-ice/seed-packs/manifests/$CLOSURE_HEX" "$1" <<'PYEOF'
import json
import pathlib
import sys

path, how = pathlib.Path(sys.argv[1]), sys.argv[2]
document = json.loads(path.read_text(encoding="utf-8"))
title = "org.opencontainers.image.title"
if how == "artifact-type":
    document["artifactType"] = "application/vnd.oci.empty.v1+json"
elif how == "media-type":
    document["mediaType"] = "application/vnd.docker.distribution.manifest.v2+json"
elif how == "seventh-layer":
    document["layers"].append(dict(document["layers"][2]))
    document["layers"][-1]["annotations"] = {title: "extra.json"}
elif how == "duplicate-title":
    document["layers"][3]["annotations"][title] = document["layers"][2]["annotations"][title]
elif how == "missing-title":
    document["layers"][4]["annotations"] = {}
elif how == "oversize":
    for layer in document["layers"]:
        if layer["annotations"][title] == "release-authorization.json":
            layer["size"] = 64 * 1024 + 1
elif how == "wrong-media-type":
    document["layers"][0]["mediaType"] = "text/plain"
elif how == "closure-not-sealed":
    for layer in document["layers"]:
        if layer["annotations"][title] == "release-closure.json":
            layer["digest"] = "sha256:" + "d" * 64
elif how == "config":
    document["config"]["size"] = 3
elif how == "extra-field":
    document["subject"] = {"digest": "sha256:" + "a" * 64}
else:
    raise SystemExit(f"unknown mutation {how}")
path.write_text(json.dumps(document, indent=1), encoding="utf-8")
PYEOF
}
for how in artifact-type media-type seventh-layer duplicate-title missing-title oversize \
  wrong-media-type closure-not-sealed config extra-field; do
  publish "$OK"
  mutate_pack "$how"
  mark="$(log_mark)"
  run_fetch "pack $how" "" \
    && fail "a seed-pack manifest with $how was accepted"
  expect_refusal "pack $how" "did not serve the seed pack"
  [[ "$(requests_since "$mark" | grep -c 'seed-packs/blobs/')" == 0 ]] \
    || fail "pack $how: a document was fetched from a pack manifest that must refuse before any blob"
done
echo "  preflight: ten pack-manifest shape violations refused before any document byte"

# 🔴 SABOTAGE, DOCUMENT SIDE. The descriptor is right, the bytes behind it are
# not: the document is refused by its own hash, and nothing is kept.
publish "$OK"
sabotage_hex="$(sha256sum -- "$OK/docs/release-authorization.json" | awk '{print tolower($1)}')"
printf '{"schema":"fixture-authorization","tampered":true}\n' \
  > "$MIRROR_ROOT/v2/neural-ice/seed-packs/blobs/sha256:$sabotage_hex"
run_fetch "tampered authorization" "" \
  && fail "a seed-pack document whose bytes do not hash to its descriptor was accepted"
expect_refusal "tampered authorization" "did not serve the seed pack"
[[ ! -e "$TMP/seed-pack/release-authorization.json" ]] || fail "a tampered document was published into the seed pack"
[[ -z "$(find "$TMP/seed-pack" -name '.fetch*' -print -quit)" ]] || fail "a temporary file survived the tampered-document refusal"
echo "  preflight: a document altered on the mirror behind an unchanged descriptor refuses, and nothing of it is kept"

# --------------------------------------------------------------------------- #
# 6b) RULE B (FAB-0057 P1.1b): the authorization pair is read from the preseal
#     set the ESP carries, AFTER that set is hashed against neuralice.preseal,
#     and the pair is then staged by the very same esp_staged_file. The ESP is a
#     directory here: the lifted esp_staged_file mounts nothing when
#     `mounted_at` already names a mountpoint, which is how the installer itself
#     finds an ESP the live root already mounted.
# --------------------------------------------------------------------------- #
FAKE_ESP="$TMP/esp"
make_esp_dir() { # $1=preseal-set.json to stage [$2=authorization bytes file]
  rm -rf -- "$FAKE_ESP"; mkdir -p "$FAKE_ESP/ice-coreos/preseal"
  cp -- "$1" "$FAKE_ESP/ice-coreos/preseal/preseal-set.json"
  cp -- "${2:-$OK/docs/release-authorization.json}" "$FAKE_ESP/ice-coreos/release-authorization.json"
  cp -- "$OK/docs/release-authorization.json.sig" "$FAKE_ESP/ice-coreos/release-authorization.sig"
}
# A preseal set that binds the fixture pair, in the installer's exact shape for
# the two fields (the other fields are the fixture's; only the pins are read).
python3 - "$OK/preseal/preseal-set.json" "$OK/docs/release-authorization.json" "$OK/docs/release-authorization.json.sig" "$TMP/preseal-bound.json" "$TMP/preseal-sabotaged.json" <<'PYEOF'
import hashlib
import json
import pathlib
import sys

set_path, auth, sig, bound, sabotaged = map(pathlib.Path, sys.argv[1:])
document = json.loads(set_path.read_text(encoding="utf-8"))
document["installer_authorization_sha256"] = hashlib.sha256(auth.read_bytes()).hexdigest()
document["installer_authorization_signature_sha256"] = hashlib.sha256(sig.read_bytes()).hexdigest()
bound.write_bytes(json.dumps(document, sort_keys=True, separators=(",", ":")).encode() + b"\n")
document["installer_authorization_sha256"] = "f" * 64
sabotaged.write_bytes(json.dumps(document, sort_keys=True, separators=(",", ":")).encode() + b"\n")
PYEOF
# Variables and stubs are consumed by the lifted production functions.
# shellcheck disable=SC2034,SC2329,SC2317
run_pins() { # $1=label $2=preseal set on the ESP $3=neuralice.preseal value [ENV=VALUE …] -> 0 when the pair was staged; prints the pins
  local label=$1 set=$2 sealed=$3; shift 3
  printf '%s\n' "$label" > "$TMP/last.case"
  make_esp_dir "$set"
  (
    set -uo pipefail
    # shellcheck source=/dev/null
    . "$TMP/bind.sh"; bind_installer
    media_vfat_partition() { echo esp; }
    mounted_at() { echo "$FAKE_ESP"; }
    PRESEAL_SET_SHA256="$sealed"
    for assignment in "$@"; do eval "$assignment"; done
    # shellcheck source=/dev/null
    . "$LIFTED"
    scratch="$TMP/auth-scratch"; rm -rf -- "$scratch"; install -d -m 0700 "$scratch"
    # The installer's own sequence, verbatim: derive, then stage the pair by the
    # same call the karg path uses.
    release_authorization_pins_from_preseal "$scratch"
    esp_staged_file release-authorization.json "$RELEASE_AUTH_DOC_SHA256" "$scratch/release-authorization.json"
    esp_staged_file release-authorization.sig "$RELEASE_AUTH_SIG_SHA256" "$scratch/release-authorization.sig"
    printf 'doc=%s\nsig=%s\n' "$RELEASE_AUTH_DOC_SHA256" "$RELEASE_AUTH_SIG_SHA256"
  ) >"$TMP/last.out" 2>"$TMP/last.err"
}
bound_sha="$(sha256sum -- "$TMP/preseal-bound.json" | awk '{print tolower($1)}')"
sabotaged_sha="$(sha256sum -- "$TMP/preseal-sabotaged.json" | awk '{print tolower($1)}')"
auth_sha="$(sha256sum -- "$OK/docs/release-authorization.json" | awk '{print tolower($1)}')"
sig_sha="$(sha256sum -- "$OK/docs/release-authorization.json.sig" | awk '{print tolower($1)}')"
run_pins "pins from the bound set" "$TMP/preseal-bound.json" "$bound_sha" \
  || fail "the installer refused a preseal set that binds the pair on the ESP: $(tail -n 3 "$TMP/last.err")"
{ grep -qx "doc=$auth_sha" "$TMP/last.out" && grep -qx "sig=$sig_sha" "$TMP/last.out"; } \
  || fail "the pins read from the set are not the ESP pair's hashes: $(cat "$TMP/last.out")"
cmp -s -- "$OK/docs/release-authorization.json" "$TMP/auth-scratch/release-authorization.json" \
  || fail "the staged authorization is not the ESP's"
# 🔴 SABOTAGE, RULE B (brief, sabotage 1): the set on the ESP binds ANOTHER
# authorization hash, and the sealed neuralice.preseal is that set's hash (the
# attacker who rewrites the ESP cannot rewrite the UKI, but this is the
# stronger case). The derived pin does not match the ESP's authorization, and
# the very esp_staged_file that stages the pair refuses it.
run_pins "sabotaged set" "$TMP/preseal-sabotaged.json" "$sabotaged_sha" \
  && fail "a preseal set binding another installer authorization staged the ESP's pair"
expect_refusal "sabotaged set" "release-authorization.json hashes to $auth_sha, not the $(printf 'f%.0s' {1..64}) this medium's signature seals"
# esp_staged_file copies first and hashes the copied bytes (its "compare AFTER
# the copy" rule), so the refused document is in scratch; what proves the
# install stopped at that refusal is that the NEXT staging never ran.
[[ ! -e "$TMP/auth-scratch/release-authorization.sig" ]] || fail "the install went on past the refused authorization and staged its signature"
# ...and the weaker case: the set is the sealed one, the ESP's authorization is not.
printf '{"schema":"fixture-authorization","swapped":true}\n' > "$TMP/auth-swapped.json"
rm -rf -- "$FAKE_ESP"
# Variables and stubs are consumed by the lifted production functions.
# shellcheck disable=SC2034,SC2329,SC2317
run_pins_swapped() {
  make_esp_dir "$TMP/preseal-bound.json" "$TMP/auth-swapped.json"
  (
    set -uo pipefail
    # shellcheck source=/dev/null
    . "$TMP/bind.sh"; bind_installer
    media_vfat_partition() { echo esp; }
    mounted_at() { echo "$FAKE_ESP"; }
    PRESEAL_SET_SHA256="$bound_sha"
    # shellcheck source=/dev/null
    . "$LIFTED"
    scratch="$TMP/auth-scratch"; rm -rf -- "$scratch"; install -d -m 0700 "$scratch"
    release_authorization_pins_from_preseal "$scratch"
    esp_staged_file release-authorization.json "$RELEASE_AUTH_DOC_SHA256" "$scratch/release-authorization.json"
  ) >"$TMP/last.out" 2>"$TMP/last.err"
}
run_pins_swapped && fail "an ESP authorization the sealed set does not bind was staged"
grep -q "release-authorization.json hashes to" "$TMP/last.err" || fail "the swapped authorization was not refused by its hash"
# The set itself must hash to the sealed value before a byte of it is read.
run_pins "set not the sealed one" "$TMP/preseal-bound.json" "$sabotaged_sha" \
  && fail "a preseal set that does not hash to neuralice.preseal was read for pins"
expect_refusal "set not the sealed one" "preseal/preseal-set.json hashes to"
# A line that restates the pair beside the set is refused before the ESP is read.
printf 'quiet neuralice.preseal=%s neuralice.relauth_sha256=%s neuralice.relauth_sig_sha256=%s\n' "$bound_sha" "$auth_sha" "$sig_sha" > "$TMP/cmdline-restated"
run_pins "restated pair" "$TMP/preseal-bound.json" "$bound_sha" "NEURALICE_CMDLINE_FILE=$TMP/cmdline-restated" \
  && fail "a line restating the authorization pair beside its preseal set was accepted"
expect_refusal "restated pair" "restates neuralice.relauth_sha256/relauth_sig_sha256"
echo "  rule B: the pair is read from the set only after the set hashes to neuralice.preseal; a set binding another authorization, a swapped ESP authorization, a wrong set and a restated pair all refuse"

# --------------------------------------------------------------------------- #
# 7) PHASE 5: THE CLOSURE'S OBJECTS, ONTO THE (HERE: A) DATA VOLUME.
# --------------------------------------------------------------------------- #
verify_store() { # $1=destination $2=fixture root -> the exact expected set, every object hashing to its name
  local destination=$1 fixture=$2 store="$1/objects/sha256" hex
  [[ "$(find "$store" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort)" == "$(sort "$fixture/expected")" ]] \
    || fail "the object store is not the exact set the closure derives: $(find "$store" -mindepth 1 -maxdepth 1 -printf '%f ')"
  while read -r hex; do
    [[ "$(sha256sum -- "$store/$hex" | awk '{print tolower($1)}')" == "$hex" ]] \
      || fail "object $hex does not hash to its name after landing"
    cmp -s -- "$store/$hex" "$fixture/objects/$hex" || fail "object $hex is not the published object"
    [[ "$(stat -c %a -- "$store/$hex")" == 444 ]] || fail "object $hex is not read-only"
  done < "$fixture/expected"
  [[ -z "$(find "$store" -name '.fetch*' -print -quit)" ]] || fail "a temporary file survived in the object store"
  python3 - "$destination/READY" "$(cat "$fixture/closure_hex")" "$(cat "$fixture/manifest_hex")" "$EXPECTED_COUNT" <<'PYEOF'
import json
import sys

path, closure, manifest, count = sys.argv[1:]
with open(path, "rb") as handle:
    raw = handle.read(4096)
document = json.loads(raw)
assert raw.endswith(b"\n") and set(document) == {"schema", "release_closure_sha256", "release_manifest_sha256", "object_count"}, document
assert document["schema"] == "neural-ice-seed-closure-ready-v1", document
assert document["release_closure_sha256"] == closure, (document, closure)
assert document["release_manifest_sha256"] == manifest, (document, manifest)
assert document["object_count"] == int(count), (document, count)
PYEOF
}

DST="$TMP/data/release/$CLOSURE_HEX"
publish "$OK"; stage_documents "$OK"
rm -rf -- "$TMP/data"; mkdir -p "$TMP/data/release"
mark="$(log_mark)"
run_materialize "complete materialisation" "$DST" \
  || fail "the installer could not materialise the fixture closure: $(tail -n 5 "$TMP/last.err")"
verify_store "$DST" "$OK"
for document in release-manifest.json release-closure.json release-authorization.json \
  release-authorization.json.sig delegation-snapshot.json delegation-snapshot.json.sig; do
  cmp -s -- "$OK/docs/$document" "$DST/$document" || fail "$document was not staged beside the objects"
done
[[ "$(requests_since "$mark" | grep -c "GET /v2/neural-ice/runtime/")" == "$EXPECTED_COUNT" ]] \
  || fail "the mirror was asked for something other than each object exactly once: $(requests_since "$mark" | tr '\n' ' ')"
requests_since "$mark" | grep -q "GET /v2/neural-ice/runtime/manifests/sha256:$(cat "$OK/attachment_hex") " \
  || fail "the attachment manifest was not fetched from the manifests endpoint"
requests_since "$mark" | grep -q "GET /v2/neural-ice/runtime/blobs/sha256:$(cat "$OK/layer_one_hex") " \
  || fail "the layer was not fetched from the blobs endpoint"
# The attachment manifest comes first: its config and layer are only knowable
# from it, and the exact-size space check needs them before the bulk.
first_bulk="$(requests_since "$mark" | grep -n "blobs/sha256:$(cat "$OK/layer_one_hex")" | head -1 | cut -d: -f1)"
attachment_request="$(requests_since "$mark" | grep -n "manifests/sha256:$(cat "$OK/attachment_hex")" | head -1 | cut -d: -f1)"
[[ "$attachment_request" -lt "$first_bulk" ]] || fail "the attachment manifest was fetched after the bulk objects"
grep -q "closure ${CLOSURE_HEX}: ${EXPECTED_COUNT} objects proved by name (${EXPECTED_COUNT} fetched, 0 already present" "$TMP/last.err" \
  || fail "the fetcher did not report the materialised set: $(grep 'seed-mirror:' "$TMP/last.err" | tail -n 1)"
echo "  phase 5: ${EXPECTED_COUNT} objects (nodes, attachment manifest, its config and layer) fetched once each, hashed, renamed, READY written"

# Resume: an object already present and hashing to its name is not fetched
# again -- proved by removing it from the mirror before the run.
publish "$OK"; stage_documents "$OK"
layer_one="$(cat "$OK/layer_one_hex")"
rm -rf -- "$TMP/data"; mkdir -p "$DST/objects/sha256"
cp -- "$OK/objects/$layer_one" "$DST/objects/sha256/$layer_one"
rm -- "$MIRROR_ROOT/v2/neural-ice/runtime/blobs/sha256:$layer_one"
mark="$(log_mark)"
run_materialize "resume" "$DST" \
  || fail "a present, correct object was not accepted as already landed: $(tail -n 3 "$TMP/last.err")"
verify_store "$DST" "$OK"
requests_since "$mark" | grep -q "sha256:$layer_one" && fail "a present, correct object was fetched again"
grep -q "1 already present" "$TMP/last.err" || fail "the fetcher did not account the present object"
echo "  phase 5: an object already present with the right hash is not fetched again"

# A present object with the WRONG bytes is replaced, never trusted.
publish "$OK"; stage_documents "$OK"
rm -rf -- "$TMP/data"; mkdir -p "$DST/objects/sha256"
head -c 1000 /dev/urandom > "$DST/objects/sha256/$layer_one"
run_materialize "stale present object" "$DST" || fail "a stale present object was not replaced: $(tail -n 3 "$TMP/last.err")"
verify_store "$DST" "$OK"
echo "  phase 5: a present object that does not hash to its name is replaced"

# A missing object is a missing object: die, no READY, nothing partial reported.
publish "$OK"; stage_documents "$OK"
rm -rf -- "$TMP/data"; mkdir -p "$TMP/data/release"
rm -- "$MIRROR_ROOT/v2/neural-ice/runtime/blobs/sha256:$layer_one"
run_materialize "missing object" "$DST" && fail "a closure whose object the mirror does not serve was materialised"
expect_refusal "missing object" "could not be materialised from the LAN mirror"
grep -q "transport failed 3 times" "$TMP/last.err" || fail "a missing object was not retried the bounded 3 times: $(grep 'seed-mirror:' "$TMP/last.err" | tail -n 2)"
[[ ! -e "$DST/READY" ]] || fail "READY was written for an incomplete object set"
[[ ! -e "$DST/objects/sha256/$layer_one" ]] || fail "a missing object appeared in the store"
echo "  phase 5: a missing object refuses after 3 bounded attempts; no READY"

# 🔴 SABOTAGE, OBJECT SIDE. Same length, different bytes, served under the same
# name: refused by its hash, no retry, no temp file, no READY.
publish "$OK"; stage_documents "$OK"
rm -rf -- "$TMP/data"; mkdir -p "$TMP/data/release"
python3 - "$MIRROR_ROOT/v2/neural-ice/runtime/blobs/sha256:$layer_one" <<'PYEOF'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
raw = bytearray(path.read_bytes())
raw[len(raw) // 2] ^= 0xFF
path.write_bytes(bytes(raw))
PYEOF
mark="$(log_mark)"
run_materialize "sabotaged object" "$DST" && fail "an object altered on the mirror was materialised"
expect_refusal "sabotaged object" "could not be materialised from the LAN mirror"
grep -q "not the sha256:$layer_one it is named by" "$TMP/last.err" \
  || fail "the sabotaged object was not refused by its hash: $(grep 'seed-mirror:' "$TMP/last.err" | tail -n 2)"
[[ "$(requests_since "$mark" | grep -c "sha256:$layer_one")" == 1 ]] || fail "a hash mismatch was retried; it is a verdict"
[[ ! -e "$DST/READY" ]] || fail "READY was written after a sabotaged object"
[[ ! -e "$DST/objects/sha256/$layer_one" ]] || fail "the sabotaged object was published into the store"
[[ -z "$(find "$DST" -name '.fetch*' -print -quit)" ]] || fail "the sabotaged object's temporary file survived"
echo "  phase 5: an object altered on the mirror refuses by its hash, once, and nothing of it is kept"

# The attachment manifest is digest-named by the closure: altering it refuses
# before its config and layer are even planned.
publish "$OK"; stage_documents "$OK"
rm -rf -- "$TMP/data"; mkdir -p "$TMP/data/release"
attachment="$(cat "$OK/attachment_hex")"
printf '{"schemaVersion":2,"config":{"digest":"sha256:%s","size":2},"layers":[]}\n' "$(printf 'e%.0s' {1..64})" \
  > "$MIRROR_ROOT/v2/neural-ice/runtime/manifests/sha256:$attachment"
mark="$(log_mark)"
run_materialize "sabotaged attachment manifest" "$DST" && fail "an altered attachment manifest was accepted"
grep -q "not the sha256:$attachment it is named by" "$TMP/last.err" || fail "the altered attachment manifest was not refused by its hash"
[[ "$(requests_since "$mark" | grep -c 'blobs/')" == 0 ]] || fail "bulk objects were fetched after the attachment manifest refused"
echo "  phase 5: an altered attachment manifest refuses before any bulk byte"

# A closure that declares a size the mirror does not serve.
WRONG="$(make_fixture wrong-size wrong-size)"
publish "$WRONG"; stage_documents "$WRONG"
rm -rf -- "$TMP/data"; mkdir -p "$TMP/data/release"
run_materialize "wrong size" "$TMP/data/release/$(cat "$WRONG/closure_hex")" \
  "SEED_CLOSURE=$(cat "$WRONG/closure_hex")" "SEED_MANIFEST_SHA256=$(cat "$WRONG/manifest_hex")" \
  && fail "an object whose size differs from the closure's declaration was accepted"
grep -q "declared bytes arrived" "$TMP/last.err" || grep -q "not the .* the closure declares" "$TMP/last.err" \
  || fail "the size mismatch was not the stated refusal: $(grep 'seed-mirror:' "$TMP/last.err" | tail -n 2)"
[[ ! -e "$TMP/data/release/$(cat "$WRONG/closure_hex")/READY" ]] || fail "READY was written despite a size mismatch"
echo "  phase 5: a size that differs from the closure's declaration refuses"

# Insufficient space: refused from the declared sizes before the first object
# byte is asked for.
HUGE="$(make_fixture huge huge)"
publish "$HUGE"; stage_documents "$HUGE"
rm -rf -- "$TMP/data"; mkdir -p "$TMP/data/release"
mark="$(log_mark)"
run_materialize "insufficient space" "$TMP/data/release/$(cat "$HUGE/closure_hex")" \
  "SEED_CLOSURE=$(cat "$HUGE/closure_hex")" "SEED_MANIFEST_SHA256=$(cat "$HUGE/manifest_hex")" \
  && fail "a closure larger than the data volume was materialised"
grep -q "bytes free and the closure needs" "$TMP/last.err" || fail "the space precheck did not refuse: $(grep 'seed-mirror:' "$TMP/last.err" | tail -n 2)"
[[ "$(requests_since "$mark" | grep -c 'GET /v2/neural-ice/runtime/')" == 0 ]] \
  || fail "objects were requested before the space precheck refused"
echo "  phase 5: a closure the data volume cannot hold refuses before the first byte"

# Something the closure does not name may not sit in the store.
publish "$OK"; stage_documents "$OK"
rm -rf -- "$TMP/data"; mkdir -p "$DST/objects/sha256"
printf 'stray' > "$DST/objects/sha256/$(printf '1%.0s' {1..64})"
run_materialize "stray object" "$DST" && fail "an object the closure does not name was tolerated in the store"
grep -q "objects the closure does not name" "$TMP/last.err" || fail "the stray object was not the stated refusal"
[[ ! -e "$DST/READY" ]] || fail "READY was written over a store with a stray object"
echo "  phase 5: a stray object in the store refuses"

# A staged closure whose bytes are not the sealed closure is refused before any plan.
publish "$OK"; stage_documents "$OK"
rm -rf -- "$TMP/data"; mkdir -p "$TMP/data/release"
mark="$(log_mark)"
run_materialize "closure not the sealed one" "$DST" "SEED_CLOSURE=$(printf '%064d' 3)" \
  && fail "a staged closure that does not hash to the sealed value was planned"
expect_refusal "closure not the sealed one" "this medium's signature seals"
[[ -z "$(requests_since "$mark")" ]] || fail "the mirror was consulted for a closure that is not the sealed one"
echo "  phase 5: a staged closure that is not the sealed one is refused before the mirror is consulted"

# --------------------------------------------------------------------------- #
# 8) THE PRODUCER: SEED_SOURCE=mirror is sealed only in the right company, and
#    the PRELOADED producer refuses it outright.
# --------------------------------------------------------------------------- #
# Variables and sha256_of are consumed by the exact production function sourced
# below, indirectly.
# shellcheck disable=SC2034,SC2329,SC2317
compose_seal() { # $1=source [ENV=VALUE …] -> 0 when the medium would be cut, and prints UKI_KARGS
  local source=$1; shift
  (
    set -uo pipefail
    sha256_of() { sha256sum -- "$1" | awk '{print tolower($1)}'; }
    SEED_SOURCE=mirror
    SEED_CLOSURE="$CLOSURE_HEX"
    SEED_TRUSTED_NOW=2026-09-09T12:00:00Z
    RELEASE_MANIFEST_FILE="$OK/docs/release-manifest.json"
    RELEASE_CLOSURE_FILE="$OK/docs/release-closure.json"
    PRESEAL_STAGE_ROOT="$OK"
    OS_IMAGE="$OS_IMAGE_REF"
    TARGET_IMGREF="$OS_IMAGE_REF"
    HARDWARE_TARGET=nvidia-gb10-arm64
    INSTALL_MIRROR="$MIRROR"
    MIRROR_READY_SHA256="$CLOSURE_HEX"
    MIRROR_READY_MANIFEST_SHA256="$MANIFEST_HEX"
    UKI_KARGS=()
    for assignment in "$@"; do eval "$assignment"; done
    # shellcheck source=/dev/null
    . "$TMP/seal.sh"
    seal_offline_seed_kargs "$source"
    printf '%s\n' "${UKI_KARGS[@]}"
  ) >"$TMP/last.out" 2>"$TMP/last.err"
}
compose_seal registry || fail "the producer refused the supported mirror-sourced seed: $(cat "$TMP/last.err")"
grep -qx 'neuralice.seed_source=mirror' "$TMP/last.out" || fail "the producer did not seal neuralice.seed_source=mirror"
grep -qx "neuralice.seed_closure=$CLOSURE_HEX" "$TMP/last.out" || fail "the producer no longer seals the closure beside the source"
grep -q '^neuralice.seed_manifest=' "$TMP/last.out" && fail "the producer still seals neuralice.seed_manifest; the closure carries it (rule C)"
grep -q 'neuralice.mirror_ready=\|neuralice.mirror_manifest=' "$TMP/last.out" && fail "the seed function sealed a READY pin"
# The READY pins are sealed by the mirror arm only when the seed is not the
# mirror's to serve (rule A): asserted on the producer's source, since the arm
# is not a function this suite can lift.
grep -q 'if \[\[ "${SEED_SOURCE:-}" != mirror \]\]; then' "$BUILDER" \
  || fail "the producer no longer conditions the READY pins on SEED_SOURCE (rule A)"
awk '/if \[\[ "\$\{SEED_SOURCE:-\}" != mirror \]\]; then/,/fi/' "$BUILDER" | grep -q 'neuralice.mirror_ready=' \
  || fail "the producer's READY pins are not inside the SEED_SOURCE condition (rule A)"
# Rule C on the producer: the closure is read, hashed against SEED_CLOSURE, and
# must name the manifest this medium is cut with.
compose_seal registry 'RELEASE_CLOSURE_FILE=""' && fail "the producer cut a seed without reading the closure the sealed hash names"
grep -q 'requires RELEASE_CLOSURE_FILE' "$TMP/last.err" || fail "the missing-closure refusal is not the stated one: $(cat "$TMP/last.err")"
compose_seal registry "SEED_CLOSURE=$(printf '%064d' 5)" && fail "the producer cut a seed whose sealed closure hash is not the closure's"
grep -q 'does not hash to SEED_CLOSURE' "$TMP/last.err" || fail "the closure-hash refusal is not the stated one: $(cat "$TMP/last.err")"
compose_seal registry "RELEASE_CLOSURE_FILE=$MISMATCH/docs/release-closure.json" "SEED_CLOSURE=$(cat "$MISMATCH/closure_hex")" \
  "MIRROR_READY_SHA256=$(cat "$MISMATCH/closure_hex")" \
  && fail "the producer cut a seed whose closure names another release manifest than the one beside it (rule C sabotage)"
grep -q 'refusing to cut a medium whose closure and manifest are two releases' "$TMP/last.err" \
  || fail "the closure/manifest mismatch is not the stated producer refusal: $(cat "$TMP/last.err")"
compose_seal registry 'SEED_SOURCE=""' || fail "the producer refused the unchanged ni-seed composition"
grep -q 'seed_source' "$TMP/last.out" && fail "the producer sealed a seed source nobody asked for"
compose_seal medium && fail "the producer cut a medium install with a mirror-sourced seed"
grep -q 'requires INSTALL_SOURCE=registry' "$TMP/last.err" || fail "the medium-source refusal is not the stated one"
compose_seal registry 'INSTALL_MIRROR=""' 'MIRROR_READY_SHA256=""' 'MIRROR_READY_MANIFEST_SHA256=""' \
  && fail "the producer cut a mirror-sourced seed with no mirror"
grep -q 'requires INSTALL_MIRROR' "$TMP/last.err" || fail "the no-mirror refusal is not the stated one"
compose_seal registry 'PRESEAL_STAGE_ROOT=""' && fail "the producer cut a mirror-sourced seed with no preseal set"
compose_seal registry "MIRROR_READY_SHA256=$(printf '%064d' 9)" \
  && fail "the producer cut a mirror-sourced seed whose mirror declares another closure"
grep -q 'MIRROR_READY_SHA256/MIRROR_READY_MANIFEST_SHA256 to equal' "$TMP/last.err" \
  || grep -q 'declares release closure' "$TMP/last.err" \
  || fail "the mirror-mismatch refusal is not a stated one: $(cat "$TMP/last.err")"
compose_seal registry 'SEED_SOURCE=partition' && fail "the producer accepted a seed source spelling that does not exist"
grep -q "SEED_SOURCE must be unset" "$TMP/last.err" || fail "the spelling refusal is not the stated one"
compose_seal registry 'SEED_CLOSURE=""' 'SEED_TRUSTED_NOW=""' 'RELEASE_MANIFEST_FILE=""' \
  && fail "the producer accepted SEED_SOURCE=mirror with no closure to fetch"
grep -q "SEED_CLOSURE names none" "$TMP/last.err" || fail "the no-closure refusal is not the stated one"
echo "  producer: SEED_SOURCE=mirror sealed only beside registry + mirror + preseal + a READY mirror; no seed_manifest, no READY pin; nine refusals named"

# build-preloaded.sh refuses before reading any input. The same invocation
# WITHOUT the variable must get past that check and fail on something else,
# or the refusal would be proving nothing.
if ( cd "$ROOT" && SEED_SOURCE=mirror SEED_HF_CACHE=/nonexistent SEED_MODEL_PROFILES=/nonexistent \
     SEED_MODEL_CATALOGUE=/nonexistent bash "$PRELOADED" ) >"$TMP/last.out" 2>"$TMP/last.err"; then
  fail "build-preloaded.sh accepted SEED_SOURCE=mirror"
fi
grep -q "is not a PRELOADED medium" "$TMP/last.err" \
  || fail "build-preloaded.sh refused SEED_SOURCE=mirror for another reason: $(tail -n 2 "$TMP/last.err")"
if ( cd "$ROOT" && SEED_HF_CACHE=/nonexistent SEED_MODEL_PROFILES=/nonexistent \
     SEED_MODEL_CATALOGUE=/nonexistent OUT="ni-seed-from-mirror-probe-$$" bash "$PRELOADED" ) >"$TMP/last.out" 2>"$TMP/last.err"; then
  fail "build-preloaded.sh ran to completion with no inputs at all"
fi
grep -q "is not a PRELOADED medium" "$TMP/last.err" \
  && fail "build-preloaded.sh refuses even without SEED_SOURCE; the refusal is not specific"
echo "  producer: build-preloaded.sh refuses SEED_SOURCE=mirror, and only that"

echo "SEED_FROM_MIRROR_TEST_OK (real TLS mirror on $MIRROR; ${EXPECTED_COUNT}-object closure materialised; sabotaged document, sabotaged object and altered attachment manifest all refused; missing object, wrong size, insufficient space, stray object, resume and stray ni-seed partition proved; rule C derived and its mismatch refused; rule B pins derived and a sabotaged set refused)"
