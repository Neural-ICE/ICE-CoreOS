#!/usr/bin/env bash
# Refuse sovereign endpoints in every Git-visible tracked or non-ignored
# untracked file. Exact hash-pinned producer fixture files are the sole skips.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

failures=0
fail() { echo "FAIL: $*" >&2; failures=$((failures + 1)); }
PRODUCER_FIXTURE_ROOT="tools/ni-ota-verify/tests/fixtures/release-manifest-v1/producer"
FIXTURE_HASHES="tools/ni-ota-verify/tests/fixtures/release-manifest-v1/OPEN_CORE_FIXTURE_SHA256"
FIXTURE_MANIFEST_SHA256="00e7427ae9ebd69169c74f46e376f42881df395ba9efd69df7c81172d7e1150c"
# Split source tokens keep the gate itself inside the boundary it enforces.
FORBIDDEN=("registry.neural""-ice.ch" "licensing.neural""-ice.ch")

SCAN_TMP="$(mktemp -d)"
ORACLE_TMP=""
cleanup() {
  rm -rf -- "$SCAN_TMP"
  [ -z "$ORACLE_TMP" ] || rm -rf -- "$ORACLE_TMP"
}
trap cleanup EXIT
if ! git ls-files --cached --others --exclude-standard -z > "$SCAN_TMP/git-visible"; then
  echo "FAIL: cannot enumerate all Git-visible inputs" >&2
  exit 1
fi
mapfile -d '' GIT_VISIBLE < "$SCAN_TMP/git-visible"

is_git_visible() {
  local wanted="$1" path
  for path in "${GIT_VISIBLE[@]}"; do [ "$path" = "$wanted" ] && return 0; done
  return 1
}

# Exit 0 = endpoint bytes found, 1 = clean, 2 = stat/read/type failure. No text
# decoding occurs: invalid UTF-8 cannot disappear through replacement/ignore.
scan_raw_path() {
  local expected_hash="${2:-}"
  python3 - "$1" "$expected_hash" "${FORBIDDEN[@]}" <<'PY'
import hashlib
import os
import re
import stat
import sys

path = os.fsencode(sys.argv[1])
try:
    before = os.lstat(path)
    if stat.S_ISLNK(before.st_mode):
        raw = os.readlink(path)
        after = os.lstat(path)
        if (after.st_dev, after.st_ino, after.st_mode, after.st_mtime_ns) != (
            before.st_dev, before.st_ino, before.st_mode, before.st_mtime_ns
        ):
            raise OSError("symlink changed while reading")
    elif stat.S_ISREG(before.st_mode):
        if before.st_mode & 0o444 == 0:
            raise PermissionError("no read bit is set")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
        try:
            opened = os.fstat(fd)
            if (opened.st_dev, opened.st_ino, opened.st_mode) != (before.st_dev, before.st_ino, before.st_mode):
                raise OSError("path changed while opening")
            chunks = []
            while True:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            raw = b"".join(chunks)
        finally:
            os.close(fd)
        after = os.lstat(path)
        if (after.st_dev, after.st_ino, after.st_mode, after.st_size, after.st_mtime_ns) != (
            before.st_dev, before.st_ino, before.st_mode, before.st_size, before.st_mtime_ns
        ):
            raise OSError("path changed while reading")
    else:
        raise OSError("Git-visible path is neither regular file nor symlink")
except (OSError, ValueError) as error:
    print(f"cannot inspect raw bytes: {os.fsdecode(path)}: {error}", file=sys.stderr)
    raise SystemExit(2)

def byte_escape(match):
    return bytes([int(match.group(1), 16)])

def unicode_escape(match):
    value = int(match.group(1), 16)
    return bytes([value]) if value <= 255 else match.group(0)

def decimal_entity(match):
    value = int(match.group(1), 10)
    return bytes([value]) if value <= 255 else match.group(0)

normal = raw.lower()
for _ in range(4):
    normal = re.sub(br"%([0-9a-f]{2})", byte_escape, normal)
    normal = re.sub(br"\\x([0-9a-f]{2})", byte_escape, normal)
    normal = re.sub(br"\\u00([0-9a-f]{2})", byte_escape, normal)
    normal = re.sub(br"&#x([0-9a-f]{1,2});", byte_escape, normal)
    normal = re.sub(br"&#([0-9]{1,3});", decimal_entity, normal)
    normal = normal.replace(b"&period;", b".").replace(b"&hyphen;", b"-")
    normal = re.sub(br"(?:\\\.|\[\.\]|\(dot\))", b".", normal)
needles = [os.fsencode(value).lower() for value in sys.argv[3:]]
found = any(needle in normal for needle in needles)
expected = sys.argv[2]
if expected:
    if hashlib.sha256(raw).hexdigest() != expected:
        print(f"allowlisted fixture changed before exemption: {os.fsdecode(path)}", file=sys.stderr)
        raise SystemExit(2)
    if not found:
        print(f"allowlisted fixture lost its endpoint oracle: {os.fsdecode(path)}", file=sys.stderr)
        raise SystemExit(2)
    raise SystemExit(1)
raise SystemExit(0 if found else 1)
PY
}

validate_fixture_allowlist() {
  local hash path
  declare -gA ALLOWED_FIXTURES=()
  if ! python3 - "$FIXTURE_HASHES" "$SCAN_TMP/git-visible" "$FIXTURE_MANIFEST_SHA256" "${FORBIDDEN[@]}" \
      > "$SCAN_TMP/validated-fixtures" <<'PY'
import hashlib
import os
import re
import stat
import sys

manifest = os.fsencode(sys.argv[1])
visible = set(open(sys.argv[2], "rb").read().split(b"\0"))
expected_paths = (
    "tools/ni-ota-verify/tests/fixtures/release-manifest-v1/producer/consumer-pack/release-manifest-v1.json",
    "tools/ni-ota-verify/tests/fixtures/release-manifest-v1/producer/generate_vectors.py",
    "tools/ni-ota-verify/tests/fixtures/release-manifest-v1/producer/vectors/canonical/valid-production-host.json",
    "tools/ni-ota-verify/tests/fixtures/release-manifest-v1/producer/vectors/parser/valid-production-host.json",
    "tools/ni-ota-verify/tests/fixtures/release-manifest-v1/producer/vectors/planner/production-host.json",
)
race_target = os.environ.get("NI_OPEN_CORE_BOUNDARY_RACE_TARGET") if os.environ.get("NI_OPEN_CORE_BOUNDARY_ORACLE") == "1" else None
race_with = os.environ.get("NI_OPEN_CORE_BOUNDARY_RACE_WITH")
race_fired = False

def secure_read(path):
    global race_fired
    encoded = os.fsencode(path)
    before = os.lstat(encoded)
    if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode):
        raise OSError(f"not an exact regular non-symlink file: {path}")
    if before.st_mode & 0o444 == 0:
        raise PermissionError(f"no read bit is set: {path}")
    if not race_fired and race_target == path:
        os.replace(os.fsencode(race_with), encoded)
        race_fired = True
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(encoded, flags)
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino, opened.st_mode) != (before.st_dev, before.st_ino, before.st_mode):
            raise OSError(f"file changed between lstat and O_NOFOLLOW open: {path}")
        chunks = []
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        raw = b"".join(chunks)
    finally:
        os.close(fd)
    after = os.lstat(encoded)
    if (after.st_dev, after.st_ino, after.st_mode, after.st_size, after.st_mtime_ns) != (
        before.st_dev, before.st_ino, before.st_mode, before.st_size, before.st_mtime_ns
    ):
        raise OSError(f"file changed while reading: {path}")
    return raw

try:
    manifest_raw = secure_read(os.fsdecode(manifest))
    manifest_text = manifest_raw.decode("ascii")
    if manifest not in visible:
        raise OSError("fixture manifest is not Git-visible")
    entries = []
    for number, line in enumerate(manifest_text.splitlines(), 1):
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"([0-9a-f]{64})  (\S+)", line)
        if not match:
            raise ValueError(f"malformed fixture manifest line {number}")
        entries.append((match.group(2), match.group(1)))
    paths = [path for path, _ in entries]
    duplicates = sorted({path for path in paths if paths.count(path) != 1})
    if duplicates:
        raise ValueError(f"duplicate reviewed fixture path: {', '.join(duplicates)}")
    if len(entries) != len(expected_paths):
        raise ValueError(f"fixture manifest must contain exactly five entries, got {len(entries)}")
    if set(paths) != set(expected_paths):
        missing = sorted(set(expected_paths) - set(paths))
        extra = sorted(set(paths) - set(expected_paths))
        raise ValueError(f"fixture manifest differs from hardcoded reviewed set (missing={missing}, extra={extra})")
    if hashlib.sha256(manifest_raw).hexdigest() != sys.argv[3]:
        raise ValueError("fixture manifest hash does not match the reviewed manifest")
    needles = [os.fsencode(value).lower() for value in sys.argv[4:]]
    for path, expected_hash in entries:
        encoded = os.fsencode(path)
        if encoded not in visible:
            raise OSError(f"reviewed fixture is not Git-visible: {path}")
        raw = secure_read(path)
        if hashlib.sha256(raw).hexdigest() != expected_hash:
            raise ValueError(f"fixture hash mismatch: {path}")
        if not any(needle in raw.lower() for needle in needles):
            raise ValueError(f"fixture lost its endpoint oracle: {path}")
        print(expected_hash, path)
except (OSError, UnicodeError, ValueError) as error:
    print(f"fixture exemption validation failed: {error}", file=sys.stderr)
    raise SystemExit(1)
PY
  then
    fail "fixed-five fixture exemption validation failed"
    return
  fi
  while read -r hash path; do
    ALLOWED_FIXTURES[$path]="$hash"
  done < "$SCAN_TMP/validated-fixtures"
  [ "${#ALLOWED_FIXTURES[@]}" -eq 5 ] || fail "validated fixture exemption set is not exactly five"
}

validate_fixture_allowlist
if [ "$failures" -ne 0 ]; then echo "open-core boundary tests: $failures FAILURE(S) before repository scan" >&2; exit 1; fi

echo "open-core boundary: raw-byte scanning every Git-visible input"
for path in "${GIT_VISIBLE[@]}"; do
  # A tracked deletion is no longer a worktree input. Distinguish it from an
  # unexpected stat race/error; dirty worktrees must remain supported.
  if [ ! -e "$path" ] && [ ! -L "$path" ]; then
    if git ls-files --deleted --error-unmatch -- "$path" >/dev/null 2>&1; then
      continue
    fi
    fail "Git-visible path disappeared before inspection: $path"
    continue
  fi
  if scan_raw_path "$path" "${ALLOWED_FIXTURES[$path]:-}"; then
    fail "sovereign endpoint bytes are hardcoded in Git-visible path: $path"
  else
    rc=$?
    [ "$rc" -eq 1 ] || fail "Git-visible path could not be inspected fail-closed: $path"
  fi
done

OVERLAY="image/bootc-overlay"
if [ -d "$OVERLAY" ]; then
  while IFS= read -r hit; do [ -n "$hit" ] && fail "a certificate ships in the open-core overlay: $hit"; done <<< "$(grep -rlF -- "BEGIN CERTIFICATE" "$OVERLAY" 2>/dev/null || true)"
fi
OTA_CONF="image/bootc-overlay/etc/neural-ice/ota.conf"
if [ -f "$OTA_CONF" ]; then
  for key in registry channel_ref bundle_ref; do grep -qE "^[[:space:]]*${key}=" "$OTA_CONF" && fail "$OTA_CONF assigns ${key}= — it is composer-supplied product config"; done
fi

run_mutation_oracles() {
  local case_dir fixture hash output label variant endpoint rc race_target race_with old_path new_path duplicate_line
  endpoint="registry.neural""-ice.ch"
  ORACLE_TMP="$(mktemp -d)"
  new_case() {
    case_dir="$ORACLE_TMP/$1"
    race_target=""; race_with=""
    mkdir -p "$case_dir/ci" "$case_dir/${FIXTURE_HASHES%/*}"
    cp -- "$REPO_ROOT/ci/test-open-core-boundary.sh" "$case_dir/ci/"
    cp -- "$REPO_ROOT/$FIXTURE_HASHES" "$case_dir/$FIXTURE_HASHES"
    while IFS= read -r fixture; do
      mkdir -p "$case_dir/${fixture%/*}"
      cp -- "$REPO_ROOT/$fixture" "$case_dir/$fixture"
    done <<EOF
$PRODUCER_FIXTURE_ROOT/consumer-pack/release-manifest-v1.json
$PRODUCER_FIXTURE_ROOT/generate_vectors.py
$PRODUCER_FIXTURE_ROOT/vectors/canonical/valid-production-host.json
$PRODUCER_FIXTURE_ROOT/vectors/parser/valid-production-host.json
$PRODUCER_FIXTURE_ROOT/vectors/planner/production-host.json
EOF
    fixture="$case_dir/$PRODUCER_FIXTURE_ROOT/consumer-pack/release-manifest-v1.json"
    git -C "$case_dir" init -q
    git -C "$case_dir" add ci "$PRODUCER_FIXTURE_ROOT"
  }
  expect_path_refusal() {
    local expected=$1
    if output="$(cd "$case_dir" && \
        NI_OPEN_CORE_BOUNDARY_ORACLE=1 \
        NI_OPEN_CORE_BOUNDARY_RACE_TARGET="$race_target" \
        NI_OPEN_CORE_BOUNDARY_RACE_WITH="$race_with" \
        bash ci/test-open-core-boundary.sh 2>&1)"; then return 1; fi
    grep -qF "$expected" <<< "$output"
  }

  new_case positive
  if (cd "$case_dir" && NI_OPEN_CORE_BOUNDARY_ORACLE=1 bash ci/test-open-core-boundary.sh >/dev/null); then echo "  ok: positive exact pinned producer fixture"; else fail "positive fixture oracle failed"; fi

  new_case symlink-manifest
  mv "$case_dir/$FIXTURE_HASHES" "$case_dir/$FIXTURE_HASHES.real"
  ln -s "${FIXTURE_HASHES##*/}.real" "$case_dir/$FIXTURE_HASHES"
  if expect_path_refusal 'not an exact regular non-symlink file'; then echo "  ok: symlinked manifest rejected"; else fail "symlinked manifest mutation escaped"; fi

  new_case changed-manifest
  printf '# unreviewed comment\n' >> "$case_dir/$FIXTURE_HASHES"
  if expect_path_refusal 'manifest hash does not match the reviewed manifest'; then echo "  ok: manifest byte mutation rejected"; else fail "manifest hash mutation escaped"; fi

  new_case sixth-entry
  fixture="$PRODUCER_FIXTURE_ROOT/vectors/sixth.json"; mkdir -p "$case_dir/${fixture%/*}"; printf '%s\n' "$endpoint" > "$case_dir/$fixture"
  hash="$(sha256sum -- "$case_dir/$fixture" | awk '{print $1}')"; printf '%s  %s\n' "$hash" "$fixture" >> "$case_dir/$FIXTURE_HASHES"; git -C "$case_dir" add "$fixture" "$FIXTURE_HASHES"
  if expect_path_refusal 'exactly five entries'; then echo "  ok: sixth in-subtree exemption rejected"; else fail "sixth exemption mutation escaped"; fi

  new_case duplicate-entry
  duplicate_line="$(grep -E '^[0-9a-f]{64}  ' "$case_dir/$FIXTURE_HASHES" | head -1)"
  printf '%s\n' "$duplicate_line" >> "$case_dir/$FIXTURE_HASHES"
  if expect_path_refusal 'duplicate reviewed fixture path'; then echo "  ok: duplicate exemption rejected"; else fail "duplicate exemption mutation escaped"; fi

  new_case renamed-entry
  old_path="$PRODUCER_FIXTURE_ROOT/vectors/parser/valid-production-host.json"
  new_path="$PRODUCER_FIXTURE_ROOT/vectors/parser/renamed-production-host.json"
  mv "$case_dir/$old_path" "$case_dir/$new_path"; sed -i "s|$old_path|$new_path|" "$case_dir/$FIXTURE_HASHES"; git -C "$case_dir" add -A
  if expect_path_refusal 'differs from hardcoded reviewed set'; then echo "  ok: renamed exemption rejected"; else fail "renamed exemption mutation escaped"; fi

  new_case missing-entry
  old_path="$PRODUCER_FIXTURE_ROOT/vectors/planner/production-host.json"; rm "$case_dir/$old_path"
  if expect_path_refusal 'No such file or directory'; then echo "  ok: missing reviewed fixture rejected"; else fail "missing fixture mutation escaped"; fi

  new_case nonvisible-entry
  old_path="$PRODUCER_FIXTURE_ROOT/vectors/planner/production-host.json"
  git -C "$case_dir" rm --cached -f "$old_path" >/dev/null
  printf '%s\n' "$old_path" > "$case_dir/.gitignore"; git -C "$case_dir" add .gitignore
  if expect_path_refusal 'reviewed fixture is not Git-visible'; then echo "  ok: non-visible reviewed fixture rejected"; else fail "non-visible fixture mutation escaped"; fi

  new_case fixture-swap-race
  race_target="$PRODUCER_FIXTURE_ROOT/vectors/canonical/valid-production-host.json"
  race_with="$case_dir/replacement-fixture"; printf '%s\n' "$endpoint changed" > "$race_with"
  if expect_path_refusal 'changed between lstat and O_NOFOLLOW open'; then echo "  ok: fixture swap race rejected"; else fail "fixture swap race mutation escaped"; fi

  new_case manifest-swap-race
  race_target="$FIXTURE_HASHES"; race_with="$case_dir/replacement-manifest"; cp "$case_dir/$FIXTURE_HASHES" "$race_with"; printf '# changed\n' >> "$race_with"
  if expect_path_refusal 'changed between lstat and O_NOFOLLOW open'; then echo "  ok: manifest swap race rejected"; else fail "manifest swap race mutation escaped"; fi

  new_case production-allowlist; mkdir -p "$case_dir/image"
  printf 'FROM %s/base\n' "$endpoint" > "$case_dir/image/Containerfile.installer"
  hash="$(sha256sum -- "$case_dir/image/Containerfile.installer" | awk '{print $1}')"
  printf '%s  image/Containerfile.installer\n' "$hash" >> "$case_dir/$FIXTURE_HASHES"; git -C "$case_dir" add image "$FIXTURE_HASHES"
  if expect_path_refusal 'exactly five entries' && grep -qF 'before repository scan' <<< "$output"; then echo "  ok: production allowlist injection rejected before scan"; else fail "production allowlist injection mutation escaped"; fi

  new_case named-test-fixture; mkdir -p "$case_dir/image/fixtures"
  printf '%s\n' "$endpoint" > "$case_dir/image/test-registry.sh"
  printf '%s\n' "$endpoint" > "$case_dir/image/fixtures/runtime.bin"
  git -C "$case_dir" add image
  if expect_path_refusal 'image/test-registry.sh' && grep -qF 'image/fixtures/runtime.bin' <<< "$output"; then echo "  ok: production test/fixture names are scanned"; else fail "production test/fixture name mutation escaped"; fi

  new_case untracked-production; mkdir -p "$case_dir/ota"; printf '%s\n' "$endpoint" > "$case_dir/ota/runtime-source"
  if expect_path_refusal 'ota/runtime-source'; then echo "  ok: non-ignored untracked source scanned"; else fail "untracked source mutation escaped"; fi

  new_case unreadable; mkdir -p "$case_dir/image"; printf 'neutral\n' > "$case_dir/image/unreadable"; git -C "$case_dir" add image; chmod 000 "$case_dir/image/unreadable"
  if expect_path_refusal 'could not be inspected fail-closed: image/unreadable'; then echo "  ok: unreadable input fails closed"; else fail "unreadable input mutation escaped"; fi

  new_case invalid-utf8; mkdir -p "$case_dir/image"; printf '\377%s\n' "$endpoint" > "$case_dir/image/invalid.bin"; git -C "$case_dir" add image
  if expect_path_refusal 'image/invalid.bin'; then echo "  ok: invalid UTF-8 cannot hide endpoint bytes"; else fail "invalid UTF-8 mutation escaped"; fi

  while IFS='|' read -r label variant; do
    new_case "variant-$label"; mkdir -p "$case_dir/ota"; printf '%s\n' "$variant" > "$case_dir/ota/encoded-source"
    if expect_path_refusal 'ota/encoded-source'; then echo "  ok: encoded endpoint rejected ($label)"; else fail "encoded endpoint mutation escaped ($label)"; fi
  done < <(
    printf '%s|%s%s\n' case 'REGISTRY.NEURAL' '-ICE.CH'
    printf '%s|%s%s\n' percent 'registry%2Eneural' '-ice%2Ech'
    printf '%s|%s%s\n' double-percent 'registry%252Eneural' '-ice%252Ech'
    printf '%s|%s%s\n' hex 'registry\x2eneural' '-ice\x2ech'
    printf '%s|%s%s\n' unicode 'registry\u002eneural' '-ice\u002ech'
    printf '%s|%s%s\n' entity 'registry&#46;neural' '-ice&#x2e;ch'
    printf '%s|%s%s\n' bracket-dot 'registry[.]neural' '-ice[.]ch'
  )
}

[ "${NI_OPEN_CORE_BOUNDARY_ORACLE:-0}" = 1 ] || run_mutation_oracles
if [ "$failures" -ne 0 ]; then echo "open-core boundary tests: $failures FAILURE(S)" >&2; exit 1; fi
echo "open-core boundary tests: PASS"
