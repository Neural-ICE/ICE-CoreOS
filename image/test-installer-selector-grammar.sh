#!/usr/bin/env bash
# shellcheck disable=SC2016 # literal source-contract assertions below
# THE SEALED SELECTOR / COMMAND-LINE GRAMMAR, PROVED WITHOUT A MEDIUM.
#
# 🔴 WHY THIS SUITE EXISTS SEPARATELY (independent review 2026-09-02, P3).
#
# Every signed-selector case used to live in image/test-installer-media.sh, after
# a fixture that SKIPs -- reporting success -- the moment any of objdump, objcopy,
# sbsign, sbverify, mkfs.vfat, mcopy, sgdisk or veritysetup is missing. In the
# review environment that fixture printed `SKIP: veritysetup unavailable` and
# exited 0, so NONE of the selector tests ran and the suite was green. A control
# that disappears with its fixture is a control nobody notices the loss of.
#
# The grammar is a pure function of a string. It needs no PE, no FAT, no GPT, no
# dm-verity and no root, so it is tested here -- on ordinary CI, on a developer's
# laptop, in a container with nothing installed -- and the full-media suite keeps
# the cases that genuinely need a medium.
#
# 🔴 AND IT PROVES THE IMPLEMENTATIONS AGREE.
#
# The grammar ships THREE times, deliberately: a shell library the producer, the
# early runtime generator and the installer all source; a Python re-implementation
# that audits a finished medium off-device; and the installer's own revalidation.
# Three readers are only defence in depth if they answer the same. Every vector in
# image/test-lib/sealed-cmdline-corpus.tsv is put to all of them, and a
# disagreement fails this suite in either direction.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$ROOT/.." && pwd)"
GRAMMAR="$ROOT/image/installer/neural-ice-sealed-cmdline-grammar.sh"
INSPECTOR="$ROOT/image/inspect-installer-media.py"
GENERATOR="$ROOT/image/installer/neural-ice-installer-runtime-generator.sh"
AUTOINSTALL="$ROOT/ota/neural-ice-autoinstall.sh"
CORPUS="$ROOT/image/test-lib/sealed-cmdline-corpus.tsv"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/ni-selector-grammar.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
chmod 0755 "$TMP"
fail() { echo "FAIL: $*" >&2; exit 1; }

for required in "$GRAMMAR" "$INSPECTOR" "$GENERATOR" "$AUTOINSTALL" "$CORPUS"; do
  [ -f "$required" ] || fail "missing input: $required"
done
# 🔴 NO SKIP PATH. bash and python3 are the whole toolchain, and if either is
# absent the answer is a failure, not a green run.
command -v python3 >/dev/null 2>&1 || fail "python3 is required; this suite does not SKIP"

# The eight sealed trust fields, spelled the way installer_trust_render_cmdline
# renders them. Values are shape-valid but arbitrary: this suite is about the
# grammar of the LINE, and image/test-installer-trust.sh owns the field values.
anchor_for() { # $1=access profile -> the eight sealed trust fields
  local profile=$1 anchor
  anchor="neuralice.trust=neural-ice-installer-trust-v1"
  anchor="$anchor neuralice.access_profile=$profile"
  anchor="$anchor neuralice.hardware_target=nvidia-gb10-arm64"
  anchor="$anchor neuralice.payload=$(printf '%064d' 1)"
  anchor="$anchor neuralice.relauth_keyid=$(printf '%064d' 2)"
  anchor="$anchor neuralice.relauth_schema=neural-ice-installer-release-authorization-v2"
  anchor="$anchor neuralice.rootverity=$(printf '%064d' 3)"
  anchor="$anchor neuralice.trust_policy_id=neural-ice-secureboot-lab-v1"
  printf '%s' "$anchor"
}
ANCHOR="$(anchor_for lab-managed)"
PCR_POLICY_FIELDS="neuralice.pcr_policy=$(printf '%064d' 4)"
PCR_POLICY_FIELDS="$PCR_POLICY_FIELDS neuralice.pcr_policy_key=$(printf '%064d' 5)"
PCR_POLICY_FIELDS="$PCR_POLICY_FIELDS neuralice.pcr_policy_signature=$(printf '%064d' 6)"
PCR_POLICY_FIELDS="$PCR_POLICY_FIELDS neuralice.pcr_policy_seq=7"
ANCHOR_INSTALL="$ANCHOR $PCR_POLICY_FIELDS"
# 🔴 THE SECOND ANCHOR (independent review 2026-09-02, P0 #3). A `customer-locked`
# medium may not name a LAN mirror at all: a mirror puts a lab host in the boot
# path of a machine that must never depend on one, and no digest argument makes
# that acceptable. That rule is a property of the ACCESS PROFILE, so it cannot be
# stated with a corpus that only ever carries one -- the corpus `anchor` column
# selects which.
ANCHOR_CUSTOMER="$(anchor_for customer-locked)"

# --------------------------------------------------------------------------- #
# READER 1 -- the shell library the producer, the generator and the installer
# all source. Driven in a subshell so a `set -e` inside it cannot end this suite.
# --------------------------------------------------------------------------- #
classify_bash() { # $1=cmdline -> "install"|"live"|"refuse:<reason>"
  local out err rc=0
  err="$TMP/bash.err"
  # The redirection lives INSIDE the substitution: bash expands a simple
  # command's words before applying its redirections, so `out="$(...)" 2>err`
  # would let the refusal reason escape to the terminal and arrive nowhere.
  out="$(
    {
      set +e
      # shellcheck source=image/installer/neural-ice-sealed-cmdline-grammar.sh
      . "$GRAMMAR"
      ni_sealed_cmdline_classify "$1"
    } 2>"$err"
  )" || rc=$?
  if [ "$rc" -eq 0 ]; then
    printf '%s' "$out"
    return 0
  fi
  printf 'refuse:%s' "$(sed -n 's/^neural-ice-sealed-cmdline: refused: //p' "$err" | tail -1)"
}

# --------------------------------------------------------------------------- #
# READER 2 -- the off-device inspector's independent Python implementation.
# --------------------------------------------------------------------------- #
classify_python() { # $1=cmdline
  local out err rc=0
  err="$TMP/python.err"
  out="$(python3 "$INSPECTOR" --classify-cmdline "$1" 2>"$err")" || rc=$?
  if [ "$rc" -eq 0 ]; then
    printf '%s' "$out"
    return 0
  fi
  printf 'refuse:%s' "$(sed -n 's/^REFUSED //p' "$err" | tail -1)"
}

# --------------------------------------------------------------------------- #
# READER 3 -- the installer's OWN revalidation, extracted verbatim from
# ota/neural-ice-autoinstall.sh. The installer is a top-to-bottom script that
# wipes disks and cannot be sourced, so the function under test is lifted out of
# it the same way ota/test-autoinstall-kargs.sh lifts the argument reader: the
# suite runs the SAME code the appliance runs, not a paraphrase of it.
# --------------------------------------------------------------------------- #
awk '/^karg_count\(\) \{/,/^}$/' "$AUTOINSTALL" > "$TMP/installer-gate.sh"
awk '/^karg_once\(\) \{/,/^}$/'  "$AUTOINSTALL" >> "$TMP/installer-gate.sh"
awk '/^require_signed_install_cmdline\(\) \{/,/^}$/' "$AUTOINSTALL" >> "$TMP/installer-gate.sh"
grep -q '^require_signed_install_cmdline()' "$TMP/installer-gate.sh" \
  || fail "the installer no longer revalidates the signed selector itself; a shell could invoke it directly"
grep -q 'ni_sealed_cmdline_classify_file' "$TMP/installer-gate.sh" \
  || fail "the installer's revalidation no longer goes through the sealed grammar"

# 🔴 AND IT IS ON THE PATH, BEFORE ANYTHING IT COULD DESTROY.
#
# A gate that exists but is never called is exactly the defect the review found
# one level up: the check lived in the service's ExecStartPre, so a direct
# invocation walked past it. Asserting the FUNCTION would repeat that mistake, so
# the CALL SITE and its position are asserted too -- by line number, against the
# first argument read and the first destructive command.
gate_call_line="$(grep -nx 'require_signed_install_cmdline' "$AUTOINSTALL" | head -1 | cut -d: -f1)"
[ -n "$gate_call_line" ] \
  || fail "the installer defines its revalidation but never calls it; a direct invocation walks straight past"
first_karg_line="$(grep -n '^_[a-z_]*_karg="\$(karg_once' "$AUTOINSTALL" | head -1 | cut -d: -f1)"
first_write_line="$(grep -nE '^[[:space:]]*(wipefs|sfdisk|mkfs\.|cryptsetup luksFormat|install -d|cat >|bootc install)' "$AUTOINSTALL" | head -1 | cut -d: -f1)"
{ [ -n "$first_karg_line" ] && [ -n "$first_write_line" ]; } \
  || fail "cannot locate the installer's first argument read or first mutation; the ordering assertion below would be vacuous"
[ "$gate_call_line" -lt "$first_karg_line" ] \
  || fail "the installer reads a security-relevant argument (line $first_karg_line) before revalidating its own authorisation (line $gate_call_line)"
[ "$gate_call_line" -lt "$first_write_line" ] \
  || fail "the installer mutates the system (line $first_write_line) before revalidating its own authorisation (line $gate_call_line)"

# The SERVICE keeps its independent preflight: two readers of one grammar is the
# point, and removing either is a regression rather than a tidy-up.
AUTOINSTALL_UNIT="$ROOT/ota/neural-ice-autoinstall.service"
grep -Fq 'ExecStartPre=/bin/bash -c '\''/usr/lib/systemd/system-generators/neural-ice-installer-runtime-generator --check || { rc=$?;' \
  "$AUTOINSTALL_UNIT" \
  || fail "the autoinstall unit lost its independent executable preflight"

installer_gate() { # $1=cmdline -> 0 when the installer would proceed
  printf '%s\n' "$1" > "$TMP/installer-cmdline"
  (
    set -uo pipefail
    # The installer's own `die`/`log`, and the two inputs its gate reads. All
    # four are consumed by the extracted function below, not by this file.
    # shellcheck disable=SC2329,SC2317,SC2034
    die() { echo "die: $*" >&2; exit 1; }
    # shellcheck disable=SC2329,SC2317
    log() { :; }
    # shellcheck disable=SC2034
    NEURALICE_CMDLINE_FILE="$TMP/installer-cmdline"
    # shellcheck disable=SC2034
    NEURALICE_SEALED_GRAMMAR="$GRAMMAR"
    # shellcheck source=/dev/null
    . "$TMP/installer-gate.sh"
    require_signed_install_cmdline
  ) >/dev/null 2>&1
}

# --------------------------------------------------------------------------- #
# READER 4 -- the runtime generator, driven for real. Not a classifier: what is
# asserted is the MASK SET it emits, because that is what a boot actually obeys.
# --------------------------------------------------------------------------- #
run_generator() { # $1=cmdline $2=output-root [--check]
  local cmdline=$1 output=$2 mode=${3:-generate}
  install -d -m 0755 "$output/normal" "$output/early" "$output/late"
  printf '%s\n' "$cmdline" > "$output/cmdline"
  chmod -R a+rX "$output"
  local -a command=(env NI_INSTALLER_GENERATOR_TESTING=1
    NI_INSTALLER_GENERATOR_TEST_CMDLINE="$output/cmdline"
    NI_INSTALLER_GENERATOR_TEST_GRAMMAR="$GRAMMAR" "$GENERATOR")
  if [[ "$mode" == --check ]]; then
    command+=(--check)
  else
    command+=("$output/normal" "$output/early" "$output/late")
  fi
  if (( EUID == 0 )); then
    chown -R nobody:nogroup "$output" 2>/dev/null || chown -R nobody:nobody "$output"
    runuser -u nobody -- "${command[@]}"
  else
    "${command[@]}"
  fi
}

masked() { # $1=output-root $2=unit
  [[ -L "$1/early/$2" && "$(readlink "$1/early/$2")" == /dev/null ]]
}

# --------------------------------------------------------------------------- #
# THE MEDIA MARKER, EXTRACTED FROM THE GENERATOR RATHER THAN RESTATED.
#
# 🔴 WHAT THIS CLOSES (independent review 2026-09-02, P1 #6). This suite used to
# carry its OWN copy of the generator's media hint -- the two selector keys and
# the two exact target words -- and so it agreed with the generator about a case
# they were BOTH wrong about: a signed medium whose command line carries the
# sealed trust anchor but a missing or misspelled selector was classified as an
# installed appliance boot, and the generator emitted no masks at all. A test
# that reimplements the thing it tests can only ever confirm it.
#
# The function and its two literal lists are now lifted verbatim out of the
# generator, exactly as the installer's own gate is lifted out of the installer.
# --------------------------------------------------------------------------- #
{
  awk '/^readonly -a NI_MEDIA_MARKER_KEYS=\(/,/^\)$/' "$GENERATOR"
  awk '/^readonly -a NI_MEDIA_MARKER_WORDS=\(/,/^\)$/' "$GENERATOR"
  awk '/^count_key\(\) \{/,/^}$/' "$GENERATOR"
  awk '/^count_word\(\) \{/,/^}$/' "$GENERATOR"
  awk '/^installer_media_hint_present\(\) \{/,/^}$/' "$GENERATOR"
} > "$TMP/media-marker.sh"
grep -q '^installer_media_hint_present()' "$TMP/media-marker.sh" \
  || fail "the generator no longer defines its media marker as an extractable function"
grep -q 'NI_MEDIA_MARKER_KEYS' "$TMP/media-marker.sh" \
  || fail "the generator's media marker is no longer driven by an extractable key list"

# 🔴 AND THE MARKER MUST COVER EVERY SEALED TRUST FIELD. The eight fields are the
# only words an installed appliance can never carry, so they are the fail-closed
# marker. If the grammar grows a ninth and the generator does not learn about it,
# a medium sealing that field alone would fall through to the appliance default.
(
  set -euo pipefail
  # shellcheck source=image/installer/neural-ice-sealed-cmdline-grammar.sh
  . "$GRAMMAR"
  # shellcheck source=/dev/null
  . "$TMP/media-marker.sh"
  for trust_key in "${NI_SEALED_TRUST_KEYS[@]}"; do
    found=0
    for marker_key in "${NI_MEDIA_MARKER_KEYS[@]}"; do
      [[ "$marker_key" == "$trust_key" ]] && found=1
    done
    [[ "$found" == 1 ]] || {
      echo "FAIL: the runtime generator's media marker does not cover the sealed trust field $trust_key" >&2
      exit 1
    }
  done
) || fail "the runtime generator's media marker and the sealed grammar's trust fields have drifted apart"

# The generator's FIRST question is deliberately cruder than the grammar: does
# this boot look like a medium boot at all? A line carrying NONE of the sealed
# trust fields, neither selector and neither target word is an INSTALLED
# appliance boot, and the generator must emit nothing on it -- that is what keeps
# the mandatory first-boot ceremony in force.
has_media_hint() { # $1=cmdline
  printf '%s\n' "$1" > "$TMP/hint-cmdline"
  (
    set -uo pipefail
    # Read by count_key/count_word, lifted verbatim out of the generator below.
    # shellcheck disable=SC2034
    CMDLINE_FILE="$TMP/hint-cmdline"
    # shellcheck source=/dev/null
    . "$TMP/media-marker.sh"
    installer_media_hint_present
  )
}

# --------------------------------------------------------------------------- #
# THE CORPUS. Every vector, every reader, one expected answer.
# --------------------------------------------------------------------------- #
vectors=0 accepted=0 refused=0
while IFS=$'\t' read -r expected anchor label words; do
  case "$expected" in ''|'#'*) continue ;; esac
  vectors=$(( vectors + 1 ))
  case "$anchor" in
    yes)
      cmdline="$ANCHOR ${words:-}"
      [[ "${words:-}" != *"systemd.unit=neural-ice-installer.target"* ]] \
        || cmdline="$cmdline $PCR_POLICY_FIELDS"
      ;;
    customer)
      cmdline="$ANCHOR_CUSTOMER ${words:-}"
      [[ "${words:-}" != *"systemd.unit=neural-ice-installer.target"* ]] \
        || cmdline="$cmdline $PCR_POLICY_FIELDS"
      ;;
    no-policy) cmdline="$ANCHOR ${words:-}" ;;
    no)       cmdline="${words:-}" ;;
    *)        fail "[$label] unknown anchor column '$anchor'" ;;
  esac

  got_bash="$(classify_bash "$cmdline")"
  got_python="$(classify_python "$cmdline")"
  [[ "$got_bash" == "$expected" ]] \
    || fail "[$label] the shell grammar answered '$got_bash', expected '$expected'"
  [[ "$got_python" == "$expected" ]] \
    || fail "[$label] the inspector's Python grammar answered '$got_python', expected '$expected' — the two implementations disagree"

  if [[ "$expected" == install ]]; then
    accepted=$(( accepted + 1 ))
    installer_gate "$cmdline" \
      || fail "[$label] the installer's own revalidation refused a line the grammar accepts as Install"
    run_generator "$cmdline" "$TMP/v$vectors" --check >/dev/null 2>&1 \
      || fail "[$label] the executable preflight refused a valid Install line"
    run_generator "$cmdline" "$TMP/v$vectors" >/dev/null 2>&1 \
      || fail "[$label] the runtime generator refused a valid Install line"
    for unit in neural-ice-installer.target neural-ice-autoinstall.service; do
      masked "$TMP/v$vectors" "$unit" && fail "[$label] Install mode masked its own $unit"
    done
    for unit in neural-ice-sovereignty-egress.service neural-ice-sovereignty-egress.timer; do
      masked "$TMP/v$vectors" "$unit" \
        || fail "[$label] Install mode left inherited appliance lifecycle unit $unit reachable"
    done
    masked "$TMP/v$vectors" neural-ice-live.target \
      || fail "[$label] Install mode left the Live target reachable"
  elif [[ "$expected" == live ]]; then
    accepted=$(( accepted + 1 ))
    installer_gate "$cmdline" \
      && fail "[$label] the installer would have run on a LIVE medium"
    run_generator "$cmdline" "$TMP/v$vectors" --check >/dev/null 2>&1 \
      && fail "[$label] the executable Install preflight accepted a Live line"
    run_generator "$cmdline" "$TMP/v$vectors" >/dev/null 2>&1 \
      || fail "[$label] the runtime generator refused a valid Live line"
    for unit in neural-ice-installer.target neural-ice-autoinstall.service \
      debug-shell.service emergency.service emergency.target rescue.service \
      rescue.target getty@.service serial-getty@.service autovt@.service \
      console-getty.service container-getty@.service getty.target \
      systemd-user-sessions.service user@.service sshd.service sshd.socket \
      sshd@.service default.target multi-user.target graphical.target; do
      masked "$TMP/v$vectors" "$unit" \
        || fail "[$label] a Live boot left $unit reachable"
    done
    masked "$TMP/v$vectors" neural-ice-live.target \
      && fail "[$label] Live mode masked its own target"
    masked "$TMP/v$vectors" neural-ice-live-diagnostics.service \
      && fail "[$label] Live mode masked its only product surface"
  else
    refused=$(( refused + 1 ))
    installer_gate "$cmdline" \
      && fail "[$label] the installer's own revalidation ACCEPTED a refused line"
    run_generator "$cmdline" "$TMP/v$vectors" --check >/dev/null 2>&1 \
      && fail "[$label] the executable preflight accepted a refused line"
    if has_media_hint "$cmdline"; then
      run_generator "$cmdline" "$TMP/v$vectors" >/dev/null 2>&1 \
        && fail "[$label] the runtime generator accepted a refused line"
      # 🔴 A REFUSED LINE MUST REACH NOTHING. The generator masks everything
      # BEFORE it classifies, so a refusal keeps every mask -- the general boot
      # targets, the destructive installer, and every root shell. This is exactly
      # the property the previous revision did not have: it decided first and
      # masked afterwards, so anything failing before the decision fell through
      # to the inherited installed-appliance default.
      for unit in default.target multi-user.target graphical.target \
        neural-ice-live.target neural-ice-installer.target \
        neural-ice-autoinstall.service neural-ice-live-diagnostics.service \
        debug-shell.service emergency.target emergency.service \
        rescue.target rescue.service getty@.service sshd.service; do
        masked "$TMP/v$vectors" "$unit" \
          || fail "[$label] a refused selector can still fall through to $unit"
      done
    else
      # No selector word at all: this is an installed appliance boot, and the
      # generator must emit NOTHING rather than mask an appliance's own lifecycle.
      run_generator "$cmdline" "$TMP/v$vectors" >/dev/null 2>&1 \
        || fail "[$label] the generator refused a boot that claims no medium at all"
      [[ -z "$(find "$TMP/v$vectors/early" -mindepth 1 -print -quit)" ]] \
        || fail "[$label] installer-only masks leaked into a boot with no media selector"
    fi
  fi
done < "$CORPUS"

(( vectors >= 60 )) || fail "the shared corpus shrank to $vectors vectors"
(( accepted >= 8 )) || fail "the corpus no longer proves what a VALID medium looks like"
(( refused >= 45 )) || fail "the corpus no longer covers the hostile mutations"

# --------------------------------------------------------------------------- #
# 🔴 THE GENERATOR FAILS CLOSED WHEN ITS GRAMMAR IS GONE.
# An unreadable library is the case that used to leave a media boot with no masks
# at all. Everything must still be masked, and the generator must still refuse.
# --------------------------------------------------------------------------- #
missing="$TMP/missing-grammar"
install -d -m 0755 "$missing/normal" "$missing/early" "$missing/late"
printf '%s\n' "$ANCHOR quiet systemd.unit=neural-ice-live.target neuralice.live=1" > "$missing/cmdline"
chmod -R a+rX "$missing"
if env NI_INSTALLER_GENERATOR_TESTING=1 \
  NI_INSTALLER_GENERATOR_TEST_CMDLINE="$missing/cmdline" \
  NI_INSTALLER_GENERATOR_TEST_GRAMMAR="$TMP/there-is-no-such-file" \
  "$GENERATOR" "$missing/normal" "$missing/early" "$missing/late" >/dev/null 2>&1; then
  fail "the generator accepted a boot whose sealed grammar it could not read"
fi
for unit in default.target multi-user.target graphical.target neural-ice-live.target \
  neural-ice-installer.target neural-ice-autoinstall.service debug-shell.service \
  emergency.target getty@.service sshd.service; do
  masked "$missing" "$unit" \
    || fail "an unreadable grammar left $unit reachable; the generator must mask before it classifies"
done

# --------------------------------------------------------------------------- #
# 🔴 THE INSTALLER REFUSES A DIRECT INVOCATION IT WAS NOT AUTHORISED FOR.
# This is the escape the review demonstrated end to end: a root shell on a signed
# Live medium running /usr/local/bin/neural-ice-autoinstall.sh by hand. The
# service's ExecStartPre is not in the picture there, so the script's own gate is.
# --------------------------------------------------------------------------- #
installer_gate "$ANCHOR quiet systemd.unit=neural-ice-live.target neuralice.live=1" \
  && fail "the installer would run when invoked by hand on a Live medium"
installer_gate "quiet neuralice.autoinstall=1" \
  && fail "the installer would run on a bare neuralice.autoinstall=1 with no anchor and no target"
installer_gate "$ANCHOR quiet systemd.unit=neural-ice-installer.target neuralice.autoinstall=1 systemd.debug_shell" \
  && fail "the installer would run on a line carrying a root debug shell"
installer_gate "$ANCHOR_INSTALL quiet systemd.unit=neural-ice-installer.target neuralice.autoinstall=1 enforcing=0" \
  || fail "the installer refuses the exact signed Install grammar it exists to serve"

# ...and it refuses when the grammar itself is unavailable, rather than assuming.
printf '%s\n' "$ANCHOR quiet systemd.unit=neural-ice-installer.target neuralice.autoinstall=1" \
  > "$TMP/installer-cmdline"
if (
  set -uo pipefail
  # shellcheck disable=SC2329,SC2317
  die() { echo "die: $*" >&2; exit 1; }
  # shellcheck disable=SC2329,SC2317
  log() { :; }
  # shellcheck disable=SC2034
  NEURALICE_CMDLINE_FILE="$TMP/installer-cmdline"
  # shellcheck disable=SC2034
  NEURALICE_SEALED_GRAMMAR="$TMP/there-is-no-such-file"
  # shellcheck source=/dev/null
  . "$TMP/installer-gate.sh"
  require_signed_install_cmdline
) >/dev/null 2>&1; then
  fail "the installer proceeded with no readable sealed grammar"
fi

# --------------------------------------------------------------------------- #
# 🔴 THE ESP ARTEFACTS THE SIGNATURE PINS (independent review 2026-09-02, P0 #3).
#
# A registry medium carries `ice-coreos/release-authorization.json` and its
# detached signature; a lab-managed bench medium also carries the mirror CA. All
# three live on a MUTABLE vfat partition, and the UKI that seals their SHA-256
# is signed. Until now nothing compared the two: the installer verified the
# authorization's SIGNATURE, so the VERIFIER was non-editable and the DOCUMENT
# was selectable -- any other correctly signed authorization would have done.
#
# image/inspect-installer-media.py::check_esp_hash_bound is that comparison, and
# it is driven HERE rather than only from the media suite, which needs
# veritysetup, a loop device and a real medium and SKIPs without them.
# --------------------------------------------------------------------------- #
esp_bound() { # $1=cmdline, rest: "<path>=<content>" pairs -> 0 when accepted
  local cmdline=$1; shift
  python3 - "$INSPECTOR" "$cmdline" "$@" <<'PYEOF'
import importlib.util
import sys

spec = importlib.util.spec_from_file_location("inspector", sys.argv[1])
inspector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inspector)

cmdline = sys.argv[2]
files = {}
for pair in sys.argv[3:]:
    path, _, content = pair.partition("=")
    files[path] = content.encode()

try:
    inspector.check_esp_hash_bound(set(files), lambda path: files[path], cmdline)
except inspector.InspectionError as error:
    print(f"REFUSED {error}", file=sys.stderr)
    raise SystemExit(1)
PYEOF
}

esp_digest() { printf '%s' "$1" | sha256sum | awk '{print $1}'; }
pcr_material() { # $1=mode, rest=paths -> inspector's mandatory carrier check
  python3 - "$INSPECTOR" "$@" <<'PYEOF'
import importlib.util
import sys

spec = importlib.util.spec_from_file_location("inspector", sys.argv[1])
inspector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inspector)
try:
    inspector.check_required_pcr_policy_material(set(sys.argv[3:]), sys.argv[2])
except inspector.InspectionError:
    raise SystemExit(1)
PYEOF
}

pcr_material live \
  || fail "a Live medium was incorrectly required to carry Install PCR policy material"
pcr_material install \
  && fail "an Install medium with neither mandatory PCR policy carrier was accepted"
pcr_material install ice-coreos/tpm2-pcr-public-key.pem \
  && fail "an Install medium with only the PCR public key was accepted"
pcr_material install ice-coreos/tpm2-pcr-signature.json \
  && fail "an Install medium with only the PCR signature JSON was accepted"
pcr_material install ice-coreos/tpm2-pcr-public-key.pem \
  ice-coreos/tpm2-pcr-signature.json \
  || fail "an Install medium carrying both mandatory PCR policy files was refused"

relauth_content='an authorization'
relauth_sig_content='a detached signature'
mirror_ca_content='a PEM certificate'
pinned_line="$ANCHOR quiet systemd.unit=neural-ice-installer.target neuralice.autoinstall=1"
pinned_line="$pinned_line neuralice.relauth_sha256=$(esp_digest "$relauth_content")"
pinned_line="$pinned_line neuralice.relauth_sig_sha256=$(esp_digest "$relauth_sig_content")"

esp_bound "$pinned_line" \
  "ice-coreos/release-authorization.json=$relauth_content" \
  "ice-coreos/release-authorization.sig=$relauth_sig_content" \
  || fail "an ESP whose artefacts hash to the sealed values was refused"

# A SWAPPED document: the UKI is untouched, the signature is untouched, the bytes
# are not. This is the exact substitution the pin exists to stop.
esp_bound "$pinned_line" \
  "ice-coreos/release-authorization.json=a DIFFERENT authorization" \
  "ice-coreos/release-authorization.sig=$relauth_sig_content" \
  && fail "a swapped release authorization on the ESP was accepted"

# A pin with no artefact is a medium that would refuse itself at install time.
esp_bound "$pinned_line" "ice-coreos/release-authorization.sig=$relauth_sig_content" \
  && fail "a medium pinning an artefact its ESP does not carry was accepted"

# An artefact nothing pins is one anybody can replace.
esp_bound "$ANCHOR quiet systemd.unit=neural-ice-installer.target neuralice.autoinstall=1" \
  "ice-coreos/release-authorization.json=$relauth_content" \
  && fail "an unpinned release authorization on the ESP was accepted"

# The mirror CA is bound the same way, and independently.
mirror_line="$pinned_line neuralice.mirror_ca_sha256=$(esp_digest "$mirror_ca_content")"
esp_bound "$mirror_line" \
  "ice-coreos/release-authorization.json=$relauth_content" \
  "ice-coreos/release-authorization.sig=$relauth_sig_content" \
  "ice-coreos/mirror-ca.crt=$mirror_ca_content" \
  || fail "an ESP whose mirror CA hashes to the sealed value was refused"
esp_bound "$mirror_line" \
  "ice-coreos/release-authorization.json=$relauth_content" \
  "ice-coreos/release-authorization.sig=$relauth_sig_content" \
  "ice-coreos/mirror-ca.crt=a CA for somebody else entirely" \
  && fail "a swapped mirror CA on the ESP was accepted"

# A medium that pins nothing and carries nothing is the ordinary medium install.
esp_bound "$ANCHOR quiet systemd.unit=neural-ice-installer.target neuralice.autoinstall=1" \
  || fail "an ordinary medium install with no pinned ESP artefacts was refused"

# --------------------------------------------------------------------------- #
# THE INSTALLED APPLIANCE IS UNTOUCHED. No media selector means no masks at all,
# which is what keeps the mandatory first-boot ceremony in force on first
# installed boot -- the installer image IS the source deployment.
# --------------------------------------------------------------------------- #
run_generator 'quiet rd.luks=1 root=/dev/mapper/system' "$TMP/installed"
[[ -z "$(find "$TMP/installed/early" -mindepth 1 -print -quit)" ]] \
  || fail "installer-only masks leaked into an installed boot"

echo "SELECTOR_GRAMMAR_TEST_OK (${vectors} corpus vectors: ${accepted} accepted, ${refused} refused; 3 grammar implementations agree; generator, preflight, installer gate and the ESP artefact pins all exercised)"
