#!/usr/bin/env bash
# TPM-BACKED APPLIANCE STATE — the only thing on this machine a wipe does not
# reset, and the only place the access profile is anchored to hardware.
#
# WHY THIS FILE EXISTS. Three claims in this tree had no state behind them:
#
#   * the access-profile anchor carried `anchor_seq`, described as "monotonic per
#     machine", and every reinstall wrote the literal `1`;
#   * the installer's release authorization was replayable for ever, because
#     nothing recorded that one had already been consumed;
#   * and the ACCESS PROFILE itself was authorised by a device-root signature.
#     The device root is a TPM key with `userwithauth` and an EMPTY policy, so
#     anything running as root on the appliance can make it sign -- which means
#     "the appliance was installed customer-locked" was a statement a privileged
#     runtime attacker could simply re-issue (review 2026-09-01, P1 #3).
#
# WHAT THIS HOLDS
#
#   0x01500003  INSTALL COUNTER (`nt=counter`). Each installation takes the next
#               value as its `anchor_seq`.
#   0x01500004  FRESHNESS COUNTER (`nt=counter`). Its ABSOLUTE TPM value is the
#               high-water of consumed release authorizations.
#   0x01500005  THE SEALED RECORD (64 bytes, WRITE-ONCE). Magic and the digest
#               that binds this machine's access profile, hardware target and
#               Secure Boot trust policy. The remaining bytes are fixed zeroes.
#
# Neither index overlaps the OTA state indices (0x01500001 legacy floor,
# 0x01500002 atomic state-v1) or the device-root/PKI persistent handles.
#
# NO EMPTY OWNER/AUTH WRITES. Every index is defined `policywrite` with NO
# `ownerwrite` and NO `authwrite`, under a NON-EMPTY authorization policy that
# permits exactly the one command the index exists for:
#
#   counters   PolicyCommandCode(TPM2_CC_NV_Increment)
#              -> the index's own authorization cannot write it, cannot change
#                 its auth value, and cannot undefine it specially. `nt=counter`
#                 does the rest: the TPM refuses an ordinary write outright.
#   record     PolicyOR( PolicyCommandCode(TPM2_CC_NV_Write),
#                        PolicyCommandCode(TPM2_CC_NV_WriteLock) )
#              -> exactly two operations: write it once, then lock it for the
#                 life of the index. `writedefine` makes that lock PERMANENT --
#                 it survives a TPM restart, which is MEASURED against a real
#                 TPM 2.0 in ci/test-swtpm-monotonic-state.sh.
#
# WRITTEN **AND** WRITELOCKED (review 2026-09-01, P1 #2). WRITELOCKED used to be
# masked out as a "dynamic" bit and never required back, so a power loss between
# `TPM2_NV_Write` and `TPM2_NV_WriteLock` left a record that is written and still
# REWRITABLE -- which every reader, here and in `src/access_profile_anchor.rs`,
# then treated as finished. Both bits are now REQUIRED by every reader, and
# `profile-bind` does not repair incomplete state either: it is read-only, so a
# defined-but-unwritten or written-but-unlocked record is treated exactly like a
# removed one -- a refusal, and physical recovery.
# `ci/test-swtpm-monotonic-state.sh` interrupts a real provisioning between the
# two commands and measures every one of those refusals.
#
# 🔴 THE OWNER HIERARCHY, AND WHAT IS DONE ABOUT IT.
# `TPMA_NV_POLICY_DELETE` -- the attribute that would make an index undeletable --
# may only be set when the index is defined under the PLATFORM hierarchy
# (TPM_RC_ATTRIBUTES otherwise; measured). Platform authorization is not
# available to an operating system: TCG PC Client firmware disables the platform
# hierarchy before handing off. So owner authorization, which is EMPTY on an
# appliance nobody has taken ownership of, can `TPM2_NV_UndefineSpace` these
# indices -- and a redefined index has, by construction, the same public area, so
# no attribute or policy check can tell it from the original.
#
# THREE INDEPENDENT BARRIERS stand in the way of what that would buy:
#
#   1. NOT A ROLLBACK. A redefined `nt=counter` index does NOT restart at zero;
#      the TPM initialises it above the highest count any counter on that TPM has
#      ever reached. Measured in ci/test-swtpm-monotonic-state.sh: undefine +
#      redefine + increment read back above the original's last value.
#   2. THE FRESHNESS VALUE IS ABSOLUTE. The counter value itself is the signed
#      issuance high-water. No per-install offset exists to reset or reinterpret.
#   3. THE OWNER HIERARCHY IS TAKEN AWAY. `ceremony-finalize` sets owner authorization
#      to 32 bytes from the kernel CSPRNG and keeps no copy, after which no
#      software on this appliance can undefine or redefine anything. It is an
#      explicit, preconditioned step rather than a side effect of `profile-bind`,
#      because owner authorization is also what persists the device root and --
#      absent a persistent SRK -- what systemd uses to unlock the disk. Both are
#      checked before the hierarchy is sealed. See the ceremony commands below.
#
#   RECOVERY, when the record is legitimately gone (a TPM clear, a replaced
#   board): the appliance's OTA path refuses with "reinstall required" and the
#   only path back is a TPM clear at the firmware setup screen -- physical
#   presence -- followed by a reinstall from signed physical media, which
#   re-provisions all of it. docs/ADR-0015 documents the operator procedure.
#
# NO CLOCKS. The freshness high-water used to be UTC seconds taken from
# `date -u +%s`, i.e. from an unauthenticated RTC, and rolling the clock back
# kept a captured authorization inside its age window for ever (review
# 2026-09-01, P1 #4). It is now a SIGNED, MONOTONIC ISSUANCE SEQUENCE enforced
# against this counter. Timestamps survive in the documents as information; no
# decision is made from one.
#
# FAIL-CLOSED EVERYWHERE. An unreadable, malformed, unexpectedly-sized index, or
# one whose attributes and policy are not the ones this file defines, is a
# refusal -- never a zero. A TPM that is absent is a refusal too: this helper
# exists precisely to remove the "no state, therefore anything goes" branch.
set -euo pipefail
umask 077

readonly COUNTER_INDEX="0x01500003"
readonly FRESHNESS_INDEX="0x01500004"
readonly RECORD_INDEX="0x01500005"
readonly COMPLETION_INDEX="0x01500006"
readonly RECORD_BYTES=64
readonly RECORD_MAGIC="NI-TPM02"
readonly COMPLETION_MAGIC="NI-DONE1"
# Domain separation: the same three words must never hash to a value some other
# statement in this tree also produces.
readonly PROFILE_BINDING_DOMAIN="neural-ice:tpm:access-profile-binding:v1"
# Same IEEE-754 safe-integer ceiling the OTA contract uses everywhere else, so a
# sequence cannot be a value one reader rounds and another does not.
readonly MAX_SAFE_INTEGER=9007199254740991
# How far ahead of this machine a signed issuance sequence may be. A TPM counter
# only moves by one, so consuming sequence N costs N-high_water increments; an
# unbounded gap is a hostile authorization asking the TPM to work for an hour.
# A machine further behind than this needs signed physical media, which is the
# same answer as every other "this appliance cannot prove where it is" case.
readonly MAX_FRESHNESS_GAP=4096

# The DEFINE-TIME attributes, as the TPM reports them. Asserted on every read: an
# index redefined with `ownerwrite`, without `nt=counter`, or without
# `writedefine` is a different index wearing the same address, and this helper
# must not use it as if it were the one it provisioned.
readonly COUNTER_ATTRIBUTES="0x60018"   # policywrite|nt=counter|ownerread|authread
readonly RECORD_ATTRIBUTES="0x62008"    # policywrite|writedefine|ownerread|authread
# The dynamic bits the TPM sets by itself: WRITELOCKED (0x800), READLOCKED
# (0x10000000) and WRITTEN (0x20000000). They are masked out of the CONTRACT
# comparison because they describe the index's HISTORY, not its shape -- and then
# they are asserted SEPARATELY, because that history is itself a requirement.
readonly ATTRIBUTE_DYNAMIC_MASK=$(( 0x30000800 ))
readonly NV_WRITELOCKED=$(( 0x800 ))
readonly NV_WRITTEN=$(( 0x20000000 ))
# 🔴 THE STATE A COMPLETE RECORD IS IN (review 2026-09-01, P1 #2). WRITELOCKED was
# only ever masked OUT, and nothing required it back. A power loss between
# `TPM2_NV_Write` and `TPM2_NV_WriteLock` therefore left a record that is written
# but still WRITABLE, and every reader -- this file and
# `src/access_profile_anchor.rs` alike -- accepted it as finished. `profile-bind`
# saw a binding it agreed with and returned early, so the lock was never taken
# and the record stayed rewritable for the life of the appliance.
#
# A complete record is WRITTEN **and** WRITELOCKED. Anything else is incomplete
# provisioning: `record_state` names which half is missing, every reader refuses
# it, and no code path completes it.
readonly RECORD_SEALED_BITS=$(( NV_WRITTEN | NV_WRITELOCKED ))

# The authorization policies, as TPM2_PolicyCommandCode / TPM2_PolicyOR compute
# them over a zero starting digest. They are deterministic properties of the TPM
# specification, so they are written here AND recomputed against the live TPM:
# the constant makes the intent reviewable, the recomputation makes it true.
readonly POLICY_INCREMENT="e8c02d3c5e701670cbaa327db1a2e9f3f41b2c22793e5c669a6e7f44b912f6c0"
readonly POLICY_WRITE_BRANCH="1c4f7107dcaf23ce00756448508558683104bd9e203e93749c227b451270438f"
readonly POLICY_WRITELOCK_BRANCH="c8905eb3b7302fc69bb1a52843b142f3e2faf66386f04f89b86cf6399b30e301"
readonly POLICY_RECORD="f83217e5a2a04342f7daa55ccfb3cd4b8a1f1e8ebb28c7719a9abbdbd638a230"

die() { printf 'neural-ice-tpm-state: refused: %s\n' "$*" >&2; exit 1; }

if [[ -n "${NI_TPM_STATE_TEST_TOOLS:-}" ]]; then
  [[ "${NI_TPM_STATE_TESTING:-}" == 1 && "$EUID" -ne 0 ]] \
    || die "test tool override is forbidden in a privileged process"
  readonly TOOL_DIR="$NI_TPM_STATE_TEST_TOOLS"
  readonly RUN_DIR="${NI_TPM_STATE_TEST_RUN_DIR:?test run directory is required}"
else
  [[ "$EUID" -eq 0 ]] || die "must run as root"
  readonly TOOL_DIR="/usr/bin"
  readonly RUN_DIR="/run/neural-ice-tpm-state"
fi

tool() {
  local path="$TOOL_DIR/$1"
  [[ -x "$path" ]] || die "required tool is unavailable: $path"
  printf '%s' "$path"
}

with_workspace() {
  install -d -m 0700 "$RUN_DIR"
  exec 9>"$RUN_DIR/operation.lock"
  "$(tool flock)" -x 9
  WORK="$(mktemp -d "$RUN_DIR/work.XXXXXX")"
  trap 'session_close; rm -rf -- "$WORK"' EXIT
}

# --------------------------------------------------------------------------- #
# Policy digests, recomputed on the live TPM and cross-checked against the
# constants above.
# --------------------------------------------------------------------------- #
SESSION=""
session_close() {
  if [[ -n "$SESSION" ]]; then
    "$(tool tpm2_flushcontext)" "$SESSION" >/dev/null 2>&1 || true
    SESSION=""
  fi
}

hex_of() { od -An -tx1 -v "$1" | tr -d '[:space:]' | tr 'A-F' 'a-f'; }

trial_command_code() { # $1=command code  $2=output digest path
  local trial="$WORK/trial.ctx"
  "$(tool tpm2_startauthsession)" -S "$trial" >/dev/null 2>&1 \
    || die "the TPM refused a trial policy session"
  "$(tool tpm2_policycommandcode)" -S "$trial" -L "$2" "$1" >/dev/null 2>&1 || {
    "$(tool tpm2_flushcontext)" "$trial" >/dev/null 2>&1 || true
    die "the TPM refused to compute a PolicyCommandCode($1) digest"
  }
  "$(tool tpm2_flushcontext)" "$trial" >/dev/null 2>&1 || true
}

compute_policies() {
  trial_command_code TPM2_CC_NV_Increment "$WORK/policy-increment"
  trial_command_code TPM2_CC_NV_Write "$WORK/branch-write"
  trial_command_code TPM2_CC_NV_WriteLock "$WORK/branch-writelock"
  local trial="$WORK/trial-or.ctx"
  "$(tool tpm2_startauthsession)" -S "$trial" >/dev/null 2>&1 \
    || die "the TPM refused a trial policy session"
  "$(tool tpm2_policyor)" -S "$trial" -L "$WORK/policy-record" \
    "sha256:$WORK/branch-write,$WORK/branch-writelock" >/dev/null 2>&1 || {
    "$(tool tpm2_flushcontext)" "$trial" >/dev/null 2>&1 || true
    die "the TPM refused to compute the record's PolicyOR digest"
  }
  "$(tool tpm2_flushcontext)" "$trial" >/dev/null 2>&1 || true

  # THE CONSTANTS ARE THE CONTRACT. A TPM (or a tpm2-tools release) that computes
  # a different digest for the same policy would silently provision indices this
  # file cannot describe, and a reviewer reading the constants above would be
  # reading fiction.
  [[ "$(hex_of "$WORK/policy-increment")" == "$POLICY_INCREMENT" ]] \
    || die "PolicyCommandCode(NV_Increment) is not the documented digest"
  [[ "$(hex_of "$WORK/branch-write")" == "$POLICY_WRITE_BRANCH" ]] \
    || die "PolicyCommandCode(NV_Write) is not the documented digest"
  [[ "$(hex_of "$WORK/branch-writelock")" == "$POLICY_WRITELOCK_BRANCH" ]] \
    || die "PolicyCommandCode(NV_WriteLock) is not the documented digest"
  [[ "$(hex_of "$WORK/policy-record")" == "$POLICY_RECORD" ]] \
    || die "the record's PolicyOR is not the documented digest"
}

# A real policy session that satisfies one branch, left in $SESSION for the
# command that follows.
session_for() { # $1=command code  $2=or|plain
  session_close
  SESSION="$WORK/session.ctx"
  "$(tool tpm2_startauthsession)" --policy-session -S "$SESSION" >/dev/null 2>&1 \
    || { SESSION=""; die "the TPM refused a policy session"; }
  "$(tool tpm2_policycommandcode)" -S "$SESSION" "$1" >/dev/null 2>&1 \
    || die "the TPM refused PolicyCommandCode($1)"
  if [[ "$2" == or ]]; then
    "$(tool tpm2_policyor)" -S "$SESSION" \
      "sha256:$WORK/branch-write,$WORK/branch-writelock" >/dev/null 2>&1 \
      || die "the TPM refused the record's PolicyOR"
  fi
}

# --------------------------------------------------------------------------- #
# Index shape. Absence is answered by the caller; PRESENCE is only ever accepted
# with the exact attributes and policy this file defines.
# --------------------------------------------------------------------------- #
index_present() { # $1=index
  local handles want line normalised
  handles="$("$(tool tpm2_getcap)" handles-nv-index 2>/dev/null)" \
    || die "cannot enumerate TPM NV indices"
  # tpm2_getcap prints `- 0x1500003`, WITHOUT the leading zero this script writes
  # and with a formatting that has changed between tpm2-tools releases. Compare
  # NUMBERS, not spellings: a padding difference silently answering "absent"
  # would make every index look virgin, and a virgin high-water is zero.
  want=$(( 16#${1#0x} ))
  while read -r line; do
    line="${line//[ -]/}"
    [[ "$line" =~ ^0[xX][0-9a-fA-F]+$ ]] || continue
    normalised=$(( 16#${line#0[xX]} ))
    (( normalised == want )) && return 0
  done <<<"$handles"
  return 1
}

# The raw attribute word the TPM reports for an index. Kept separate from the
# shape assertion because the DYNAMIC bits are read for two different questions:
# "is this the index this appliance defined" and "has it been finished".
index_raw_attributes() { # $1=index -> decimal
  local public attributes
  public="$("$(tool tpm2_nvreadpublic)" "$1" 2>/dev/null)" \
    || die "the TPM will not describe $1"
  attributes="$(awk '/value: 0x/{v=$2} END{print v}' <<<"$public")"
  [[ "$attributes" =~ ^0x[0-9a-fA-F]+$ ]] || die "$1 reports no usable attributes"
  printf '%s\n' "$(( 16#${attributes#0x} ))"
}

#   $1 index  $2 expected attributes  $3 expected policy hex  $4 expected size
#   $5 dynamic bits that MUST be set (decimal; default 0)
#
# The fifth argument is the whole of P1 #2 on this side: an index whose contract
# is right and whose HISTORY is wrong -- written but never locked -- is not a
# record this appliance may act on.
assert_index_shape() {
  local public attributes policy size raw required=${5:-0}
  public="$("$(tool tpm2_nvreadpublic)" "$1" 2>/dev/null)" \
    || die "the TPM will not describe $1"
  attributes="$(awk '/value: 0x/{v=$2} END{print v}' <<<"$public")"
  [[ "$attributes" =~ ^0x[0-9a-fA-F]+$ ]] || die "$1 reports no usable attributes"
  raw=$(( 16#${attributes#0x} ))
  (( ( raw & ~ATTRIBUTE_DYNAMIC_MASK ) == 16#${2#0x} )) \
    || die "$1 carries attributes $attributes, not the $2 this appliance defines; an index redefined with different authorization is not this machine's state"
  policy="$(awk '/authorization policy:/{print tolower($3)}' <<<"$public")"
  [[ "$policy" == "$3" ]] \
    || die "$1 carries authorization policy '${policy:-none}', not the one this appliance defines"
  size="$(awk '/^  size:/{print $2}' <<<"$public")"
  [[ "$size" == "$4" ]] || die "$1 is ${size:-unknown} bytes, not $4"
  if (( required != 0 )); then
    (( ( raw & required ) == required )) \
      || die "$1 is not in the state this appliance requires (attributes $attributes, wanted the dynamic bits $required set): an index that was never written carries nothing, and a record written but not write-locked is an interrupted provisioning no reader may treat as finished; recovery is a TPM clear with physical presence followed by a reinstall from signed media"
  fi
}

# --------------------------------------------------------------------------- #
# Encoding helpers. A big-endian u64 file <-> a decimal integer; anything that is
# not exactly eight bytes is a refusal, because a short read is a different
# number, silently.
# --------------------------------------------------------------------------- #
decode_u64() { # $1=path  [$2=byte offset]
  "$(tool python3)" -c '
import struct, sys
offset = int(sys.argv[2]) if len(sys.argv) > 2 else 0
blob = open(sys.argv[1], "rb").read()
if len(blob) < offset + 8:
    print("the TPM NV value is too short", file=sys.stderr)
    raise SystemExit(1)
value, = struct.unpack_from(">Q", blob, offset)
if value > 9007199254740991:
    print("the TPM NV value exceeds the safe integer range", file=sys.stderr)
    raise SystemExit(1)
print(value)
' "$1" "${2:-0}"
}

counter_value() { # $1=index -> decimal
  "$(tool tpm2_nvread)" "$1" -C "$1" -s 8 -o "$WORK/counter.bin" >/dev/null 2>&1 \
    || die "the counter at $1 exists but cannot be read"
  [[ "$(wc -c < "$WORK/counter.bin" | tr -d '[:space:]')" == 8 ]] \
    || die "the counter at $1 did not return eight bytes"
  decode_u64 "$WORK/counter.bin"
}

provision_counter() { # $1=index
  "$(tool tpm2_nvdefine)" "$1" -C o -s 8 \
    -a "policywrite|authread|ownerread|nt=counter" -L "$WORK/policy-increment" \
    >/dev/null 2>&1 \
    || die "cannot provision the monotonic counter at $1"
  assert_index_shape "$1" "$COUNTER_ATTRIBUTES" "$POLICY_INCREMENT" 8
}

increment_counter() { # $1=index
  session_for TPM2_CC_NV_Increment plain
  "$(tool tpm2_nvincrement)" "$1" -C "$1" -P "session:$SESSION" >/dev/null 2>&1 \
    || die "the TPM refused to advance the counter at $1"
  session_close
}

# --------------------------------------------------------------------------- #
# The sealed record.
# --------------------------------------------------------------------------- #
profile_digest() { # $1=profile $2=target $3=trust policy id
  printf '%s\0%s\0%s\0%s' "$PROFILE_BINDING_DOMAIN" "$1" "$2" "$3" \
    | "$(tool sha256sum)" | awk '{print tolower($1)}'
}

validate_profile() {
  case "$1" in
    lab-managed | customer-locked | developer-diagnostic) ;;
    *) die "'$1' is not a recognised access profile" ;;
  esac
}
validate_target() {
  [[ "$1" =~ ^[a-z0-9]([a-z0-9_-]{0,62}[a-z0-9])?$ ]] || die "'$1' is not a valid hardware target"
}
validate_policy_id() {
  [[ "$1" =~ ^neural-ice-secureboot-[a-z0-9-]{1,32}$ ]] \
    || die "'$1' is not a valid signed-boot trust policy id"
}

# WHAT STATE THE RECORD IS IN. `absent`, `unwritten`, `unlocked` or `sealed` --
# and anything whose static shape is wrong dies here rather than being classified.
#
# 🔴 `unlocked` IS THE INTERRUPTED PROVISIONING (review 2026-09-01, P1 #2), and it
# is a REFUSAL for every caller including `profile-bind`: a written-but-unlocked
# record is an ordinary rewritable index at a well-known address.
record_state() {
  index_present "$RECORD_INDEX" || { printf 'absent\n'; return 0; }
  assert_index_shape "$RECORD_INDEX" "$RECORD_ATTRIBUTES" "$POLICY_RECORD" "$RECORD_BYTES"
  local raw; raw="$(index_raw_attributes "$RECORD_INDEX")"
  if (( raw & NV_WRITTEN )); then
    if (( raw & NV_WRITELOCKED )); then printf 'sealed\n'; else printf 'unlocked\n'; fi
  elif (( raw & NV_WRITELOCKED )); then
    # Locked before anything was written: the index can never hold a binding, and
    # `writedefine` makes that permanent. Not a state provisioning can recover.
    die "the sealed record at $RECORD_INDEX is write-locked but was never written; this appliance's binding can never be completed — a TPM clear with physical presence and a reinstall from signed media are required"
  else
    printf 'unwritten\n'
  fi
}

# Prints the binding digest and returns 0; returns 2 when the index is ABSENT.
# Any other non-zero status is a REFUSAL that a caller must propagate.
#
# 🔴 THE TWO ARE NOT THE SAME ANSWER. An earlier revision returned 1 for both, and
# `profile-read` mapped that to "none" -- so a record redefined with `ownerwrite`,
# i.e. one an empty authorization can rewrite, was reported as "this machine has
# never been bound". That is fail-OPEN in the one place the whole binding lives.
record_read() {
  # WRITTEN **and** WRITELOCKED, required rather than masked away. This is the
  # reader half of P1 #2: without it, a record left writable by an interrupted
  # provisioning is indistinguishable from a finished one. record_state asserts
  # the static shape and names the state, so each refusal says which one it is.
  local state; state="$(record_state)"
  case "$state" in
    absent) return 2 ;;
    sealed) ;;
    unlocked)
      die "the sealed record at $RECORD_INDEX is written but not write-locked; that is an interrupted provisioning, not a binding, and no reader may treat it as one" ;;
    unwritten)
      die "the sealed record at $RECORD_INDEX exists but carries nothing; that is an interrupted provisioning, not a binding" ;;
    *) die "the sealed record at $RECORD_INDEX is in an unrecognised state '$state'" ;;
  esac
  assert_index_shape "$RECORD_INDEX" "$RECORD_ATTRIBUTES" "$POLICY_RECORD" "$RECORD_BYTES" \
    "$RECORD_SEALED_BITS"
  "$(tool tpm2_nvread)" "$RECORD_INDEX" -C "$RECORD_INDEX" -s "$RECORD_BYTES" \
    -o "$WORK/record.bin" >/dev/null 2>&1 \
    || die "the sealed record exists at $RECORD_INDEX but cannot be read"
  [[ "$(wc -c < "$WORK/record.bin" | tr -d '[:space:]')" == "$RECORD_BYTES" ]] \
    || die "the sealed record did not return $RECORD_BYTES bytes"
  local magic
  magic="$(head -c 8 "$WORK/record.bin")"
  [[ "$magic" == "$RECORD_MAGIC" ]] \
    || die "the sealed record at $RECORD_INDEX is not this appliance's record"
  local digest reserved
  digest="$("$(tool python3)" -c '
import sys
print(open(sys.argv[1], "rb").read()[8:40].hex())
' "$WORK/record.bin")"
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || die "the sealed record carries no usable profile binding"
  reserved="$("$(tool python3)" -c 'import sys; print(open(sys.argv[1], "rb").read()[40:].hex())' "$WORK/record.bin")"
  [[ "$reserved" == "$(printf '00%.0s' {1..24})" ]] \
    || die "the sealed record carries non-zero bytes outside its closed v2 contract"
  printf '%s\n' "$digest"
}

# --------------------------------------------------------------------------- #
# counter-read / counter-next -> the monotonic install counter.
# Runtime readers never treat absence as virgin. Only `ceremony-prepare` creates it.
# --------------------------------------------------------------------------- #
counter_read() {
  (( $# == 0 )) || die "counter-read takes no arguments"
  with_workspace; compute_policies
  index_present "$COUNTER_INDEX" \
    || die "the install counter is absent; TPM provisioning is incomplete and signed physical recovery is required"
  # A counter that exists and has never been incremented has no value the TPM
  # will read back; requiring WRITTEN turns that into a refusal rather than a
  # short read some caller would treat as zero.
  assert_index_shape "$COUNTER_INDEX" "$COUNTER_ATTRIBUTES" "$POLICY_INCREMENT" 8 "$NV_WRITTEN"
  counter_value "$COUNTER_INDEX"
}

counter_next() {
  (( $# == 0 )) || die "counter-next takes no arguments"
  with_workspace; compute_policies
  index_present "$COUNTER_INDEX" \
    || die "the install counter is absent; runtime may not create provisioning state"
  assert_index_shape "$COUNTER_INDEX" "$COUNTER_ATTRIBUTES" "$POLICY_INCREMENT" 8 "$NV_WRITTEN"
  increment_counter "$COUNTER_INDEX"
  local value
  value="$(counter_value "$COUNTER_INDEX")"
  (( value >= 1 )) || die "the install counter read back as $value after an increment"
  printf '%s\n' "$value"
}

# --------------------------------------------------------------------------- #
# freshness-read / freshness-consume -> the absolute TPM counter value. No
# subtraction, offset or install-specific arithmetic exists in this contract.
# --------------------------------------------------------------------------- #
freshness_read() {
  (( $# == 0 )) || die "freshness-read takes no arguments"
  with_workspace; compute_policies
  local record rc=0
  record="$(record_read)" || rc=$?
  case "$rc" in
    0) ;;
    2) die "this machine has no sealed record; runtime cannot call that virgin — signed physical recovery is required (docs/ADR-0015)" ;;
    *) die "this machine's sealed record cannot be read; refusing to report a high-water of zero" ;;
  esac
  if ! index_present "$FRESHNESS_INDEX"; then
    die "this machine has a sealed record but no freshness counter; its anti-replay state is incoherent"
  fi
  assert_index_shape "$FRESHNESS_INDEX" "$COUNTER_ATTRIBUTES" "$POLICY_INCREMENT" 8 "$NV_WRITTEN"
  counter_value "$FRESHNESS_INDEX"
}

freshness_consume() { # $1=the signed issuance sequence being consumed
  (( $# == 1 )) || die "freshness-consume requires exactly one issuance sequence"
  local requested="$1"
  if ! [[ "$requested" =~ ^[0-9]{1,16}$ ]] || (( requested < 1 || requested > MAX_SAFE_INTEGER )); then
    die "'$requested' is not a valid issuance sequence"
  fi
  with_workspace; compute_policies
  local record rc=0
  record="$(record_read)" || rc=$?
  case "$rc" in
    0) ;;
    2)
      if index_present "$FRESHNESS_INDEX"; then
        die "this machine's anti-replay counter exists but its sealed record does not; the record was removed and no software may recreate it — signed physical recovery is required (docs/ADR-0015)"
      fi
      die "this machine has no sealed record; a release authorization cannot be consumed before the appliance is bound" ;;
    *) die "this machine's sealed record cannot be read; refusing to consume an authorization against state nothing can vouch for" ;;
  esac
  index_present "$FRESHNESS_INDEX" \
    || die "this machine has a sealed record but no freshness counter; its anti-replay state is incoherent"
  assert_index_shape "$FRESHNESS_INDEX" "$COUNTER_ATTRIBUTES" "$POLICY_INCREMENT" 8 "$NV_WRITTEN"
  local current high_water
  current="$(counter_value "$FRESHNESS_INDEX")"
  high_water="$current"
  # STRICTLY greater. Equal is the same authorization being consumed twice, which
  # is the replay this counter exists for.
  (( requested > high_water )) \
    || die "refusing to consume issuance sequence $requested at or below the recorded high-water $high_water"
  (( requested - high_water <= MAX_FRESHNESS_GAP )) \
    || die "issuance sequence $requested is more than $MAX_FRESHNESS_GAP ahead of this machine's high-water $high_water; a TPM counter advances by one and this would not be a normal update"
  local step
  for (( step = high_water; step < requested; step++ )); do
    increment_counter "$FRESHNESS_INDEX"
  done
  # READ BACK what landed. A sequence of increments that silently stopped short
  # would leave the machine replayable while reporting success.
  current="$(counter_value "$FRESHNESS_INDEX")"
  (( current == requested )) \
    || die "the freshness high-water read back as $current, not $requested"
  printf '%s\n' "$requested"
}

# --------------------------------------------------------------------------- #
# profile-read / profile-bind / profile-digest — the access-profile authority.
# --------------------------------------------------------------------------- #
profile_read() {
  (( $# == 0 )) || die "profile-read takes no arguments"
  with_workspace; compute_policies
  local record rc=0
  record="$(record_read)" || rc=$?
  case "$rc" in
    0) printf '%s\n' "$record" ;;
    2) die "this machine has no sealed access-profile record; runtime cannot call that virgin — signed physical recovery is required (docs/ADR-0015)" ;;
    *) die "this machine's sealed record cannot be read; refusing to report it as absent" ;;
  esac
}

profile_bind() { # read-only compatibility gate; provisioning belongs to ceremony
  (( $# == 3 )) || die "profile-bind requires a profile, a hardware target and a trust policy id"
  validate_profile "$1"; validate_target "$2"; validate_policy_id "$3"
  local wanted; wanted="$(profile_digest "$1" "$2" "$3")"
  with_workspace; compute_policies

  local record rc=0
  record="$(record_read)" || rc=$?
  (( rc == 0 )) \
    || die "profile-bind is a read-only runtime gate; missing or partial state may only be recovered by TPM clear with physical presence and signed reinstall"
  [[ "$record" == "$wanted" ]] \
    || die "this appliance is bound to a different access profile, hardware target or trust policy; changing it requires a TPM clear with physical presence, then a reinstall from signed media"
  printf '%s\n' "$wanted"
}

write_record() { # $1=binding digest; workspace and policies already prepared
  "$(tool tpm2_nvdefine)" "$RECORD_INDEX" -C o -s "$RECORD_BYTES" \
    -a "policywrite|authread|ownerread|writedefine" -L "$WORK/policy-record" \
    >/dev/null 2>&1 || die "cannot provision the sealed record at $RECORD_INDEX"
  "$(tool python3)" -c '
import sys
magic, digest, size = sys.argv[1], sys.argv[2], int(sys.argv[3])
blob = magic.encode("ascii") + bytes.fromhex(digest)
open(sys.argv[4], "wb").write(blob.ljust(size, b"\x00"))
' "$RECORD_MAGIC" "$1" "$RECORD_BYTES" "$WORK/record-new.bin"
  session_for TPM2_CC_NV_Write or
  "$(tool tpm2_nvwrite)" "$RECORD_INDEX" -C "$RECORD_INDEX" -P "session:$SESSION" \
    -i "$WORK/record-new.bin" >/dev/null 2>&1 || die "the TPM refused to write the sealed record"
  session_close
  session_for TPM2_CC_NV_WriteLock or
  "$(tool tpm2_nvwritelock)" "$RECORD_INDEX" -C "$RECORD_INDEX" -P "session:$SESSION" \
    >/dev/null 2>&1 || die "the TPM refused to write-lock the sealed record"
  session_close
  [[ "$(record_read)" == "$1" ]] || die "the sealed record did not read back exactly"
}

completion_read() {
  index_present "$COMPLETION_INDEX" || return 2
  assert_index_shape "$COMPLETION_INDEX" "$RECORD_ATTRIBUTES" "$POLICY_RECORD" \
    "$RECORD_BYTES" "$RECORD_SEALED_BITS"
  "$(tool tpm2_nvread)" "$COMPLETION_INDEX" -C "$COMPLETION_INDEX" -s "$RECORD_BYTES" \
    -o "$WORK/completion.bin" >/dev/null 2>&1 \
    || die "the ceremony completion record exists but cannot be read"
  local magic digest reserved
  magic="$(head -c 8 "$WORK/completion.bin")"
  [[ "$magic" == "$COMPLETION_MAGIC" ]] \
    || die "the completion record is not this appliance's ceremony evidence"
  digest="$("$(tool python3)" -c 'import sys; print(open(sys.argv[1], "rb").read()[8:40].hex())' "$WORK/completion.bin")"
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || die "the completion record carries no evidence digest"
  reserved="$("$(tool python3)" -c 'import sys; print(open(sys.argv[1], "rb").read()[40:].hex())' "$WORK/completion.bin")"
  [[ "$reserved" == "$(printf '00%.0s' {1..24})" ]] \
    || die "the completion record carries bytes outside its closed contract"
  printf '%s\n' "$digest"
}

write_completion() { # $1=canonical evidence digest
  [[ "$1" =~ ^[0-9a-f]{64}$ ]] || die "completion evidence digest is malformed"
  "$(tool tpm2_nvdefine)" "$COMPLETION_INDEX" -C o -s "$RECORD_BYTES" \
    -a "policywrite|authread|ownerread|writedefine" -L "$WORK/policy-record" \
    >/dev/null 2>&1 || die "cannot provision the ceremony completion record"
  "$(tool python3)" -c '
import sys
blob = sys.argv[1].encode("ascii") + bytes.fromhex(sys.argv[2])
open(sys.argv[3], "wb").write(blob.ljust(64, b"\x00"))
' "$COMPLETION_MAGIC" "$1" "$WORK/completion-new.bin"
  session_for TPM2_CC_NV_Write or
  "$(tool tpm2_nvwrite)" "$COMPLETION_INDEX" -C "$COMPLETION_INDEX" \
    -P "session:$SESSION" -i "$WORK/completion-new.bin" >/dev/null 2>&1 \
    || die "the TPM refused to write ceremony completion evidence"
  session_close
  session_for TPM2_CC_NV_WriteLock or
  "$(tool tpm2_nvwritelock)" "$COMPLETION_INDEX" -C "$COMPLETION_INDEX" \
    -P "session:$SESSION" >/dev/null 2>&1 \
    || die "the TPM refused to write-lock ceremony completion evidence"
  session_close
  [[ "$(completion_read)" == "$1" ]] || die "completion evidence did not read back exactly"
}

# --------------------------------------------------------------------------- #
# THE OWNER HIERARCHY (review 2026-09-01, P1 #2).
#
# 🔴 THE RESIDUAL THIS ADDRESSES. `TPMA_NV_POLICY_DELETE` is refused outside the
# platform hierarchy (measured), so owner authorization -- EMPTY on an appliance
# nobody has taken ownership of -- can still `TPM2_NV_UndefineSpace` any of these
# indices. Attribute and policy checks cannot tell a redefined index from the
# original: the replacement has, by construction, the same public area.
#
# The doctrine is therefore to take the owner hierarchy away from the runtime:
# set its authorization to 32 bytes from the kernel CSPRNG and KEEP NO COPY. From
# that moment no software on this appliance can undefine or redefine anything --
# not this helper either. A TPM clear at the firmware setup screen (physical
# presence) resets it, and the way back is a reinstall from signed media, which
# is the same recovery every other "this appliance cannot prove where it is" case
# already has (docs/ADR-0015).
#
# 🔴 WHY THIS IS A ONE-TIME CEREMONY AND NOT A SIDE EFFECT OF `profile-bind`.
# Sealing the owner hierarchy takes away owner authorization from EVERYTHING,
# including two things this appliance needs it for:
#
#   * `tpm2_evictcontrol -C o`, which persists and rotates the device root
#     (ota/neural-ice-device-root-tpm.sh), which must run before the ceremony;
#   * systemd-cryptenroll / systemd-cryptsetup, which derive the storage primary
#     under the owner hierarchy unless a persistent SRK is already there.
#
# Doing it inside a runtime compatibility command would therefore make the
# appliance unable to provision its device root and unable to unlock its own
# disk. The mandatory first-boot ceremony checks both persisted prerequisites,
# creates the fixed state, then irreversibly removes owner authority before any
# runtime readiness is allowed.
# --------------------------------------------------------------------------- #
readonly PERSISTENT_SRK_HANDLE=0x81000001
readonly DEVICE_ROOT_HANDLE=0x81010005

handle_present() { # $1=persistent handle
  local handles want line normalised
  handles="$("$(tool tpm2_getcap)" handles-persistent 2>/dev/null)" \
    || die "cannot enumerate TPM persistent handles"
  want=$(( 16#${1#0x} ))
  while read -r line; do
    line="${line//[ -]/}"
    [[ "$line" =~ ^0[xX][0-9a-fA-F]+$ ]] || continue
    normalised=$(( 16#${line#0[xX]} ))
    (( normalised == want )) && return 0
  done <<<"$handles"
  return 1
}

# `1` when the TPM reports a non-empty owner authorization, `0` otherwise. Read
# from TPM2_PT_PERMANENT, which is the TPM's own answer rather than a marker this
# appliance could keep and be wrong about.
owner_auth_set() {
  local properties value
  properties="$("$(tool tpm2_getcap)" properties-variable 2>/dev/null)" \
    || die "the TPM will not report its permanent properties"
  value="$(awk -F: '/ownerAuthSet/{gsub(/[^0-9]/,"",$2); print $2; found=1} END{exit !found}' \
    <<<"$properties")" \
    || die "the TPM reports no ownerAuthSet property; refusing to reason about an owner hierarchy it will not describe"
  [[ "$value" =~ ^[01]$ ]] || die "the TPM reports an unusable ownerAuthSet value"
  printf '%s\n' "$value"
}

assert_fixed_state() { # $1=expected profile binding
  local index
  for index in "$COUNTER_INDEX" "$FRESHNESS_INDEX" "$RECORD_INDEX"; do
    index_present "$index" \
      || die "completed owner ceremony evidence is missing $index; signed physical recovery is required"
  done
  assert_index_shape "$COUNTER_INDEX" "$COUNTER_ATTRIBUTES" "$POLICY_INCREMENT" 8 "$NV_WRITTEN"
  assert_index_shape "$FRESHNESS_INDEX" "$COUNTER_ATTRIBUTES" "$POLICY_INCREMENT" 8 "$NV_WRITTEN"
  [[ "$(record_state)" == sealed ]] \
    || die "the access-profile record is not written and write-locked; signed physical recovery is required"
  [[ "$(record_read)" == "$1" ]] \
    || die "the access-profile record does not match the intended ceremony"
  handle_present "$DEVICE_ROOT_HANDLE" \
    || die "the persisted device root is absent after owner ceremony; signed physical recovery is required"
  handle_present "$PERSISTENT_SRK_HANDLE" \
    || die "the intended persistent SRK is absent after owner ceremony; signed physical recovery is required"
}

public_contract_digest() { # $1=index -> digest of its exact TPM-computed Name
  local name="$WORK/${1#0x}.name" public name_hex
  public="$("$(tool tpm2_nvreadpublic)" "$1" 2>"$WORK/nv-public.err")" \
    || die "the TPM will not emit the exact public Name for $1: $(tr '\n' ' ' < "$WORK/nv-public.err")"
  name_hex="$(awk '/^  name:/{print tolower($2)}' <<<"$public")"
  [[ "$name_hex" =~ ^000b[0-9a-f]{64}$ ]] \
    || die "the TPM emitted no canonical SHA-256 public Name for $1"
  "$(tool python3)" -c 'import sys; open(sys.argv[2],"wb").write(bytes.fromhex(sys.argv[1]))' \
    "$name_hex" "$name"
  "$(tool sha256sum)" "$name" | awk '{print tolower($1)}'
}

state_snapshot() { # $1=profile $2=target $3=policy
  (( $# == 3 )) || die "state-snapshot requires a profile, hardware target and trust policy id"
  validate_profile "$1"; validate_target "$2"; validate_policy_id "$3"
  local wanted; wanted="$(profile_digest "$1" "$2" "$3")"
  with_workspace; compute_policies
  assert_fixed_state "$wanted"
  local install_value freshness_value install_public freshness_public
  install_value="$(counter_value "$COUNTER_INDEX")"
  freshness_value="$(counter_value "$FRESHNESS_INDEX")"
  install_public="$(public_contract_digest "$COUNTER_INDEX")"
  freshness_public="$(public_contract_digest "$FRESHNESS_INDEX")"
  "$(tool python3)" - "$wanted" "$install_value" "$freshness_value" "$install_public" "$freshness_public" <<'PY'
import json, sys
binding, install, freshness, install_public, freshness_public = sys.argv[1:]
obj = {"freshness_counter":int(freshness),"freshness_public_sha256":freshness_public,"install_counter":int(install),"install_public_sha256":install_public,"profile_binding":binding,"schema":"neural-ice-tpm-state-snapshot-v1"}
print(json.dumps(obj, sort_keys=True, separators=(",", ":")))
PY
}

runtime_status() { # profile target policy evidence-digest install-at-ceremony freshness-at-ceremony
  (( $# == 6 )) || die "runtime-status requires profile, target, policy, evidence digest and ceremony counter values"
  validate_profile "$1"; validate_target "$2"; validate_policy_id "$3"
  [[ "$4" =~ ^[0-9a-f]{64}$ ]] || die "runtime completion evidence digest is malformed"
  [[ "$5" =~ ^[1-9][0-9]{0,15}$ && "$6" =~ ^[1-9][0-9]{0,15}$ ]] \
    || die "runtime ceremony counter evidence is malformed"
  local wanted expected_install="$5" expected_freshness="$6"
  wanted="$(profile_digest "$1" "$2" "$3")"
  with_workspace; compute_policies
  [[ "$(owner_auth_set)" == 1 ]] \
    || die "the mandatory owner ceremony is not complete; runtime readiness is forbidden"
  assert_fixed_state "$wanted"
  local completion install_value freshness_value
  completion="$(completion_read)" \
    || die "authenticated TPM completion evidence is absent or partial; signed physical recovery is required"
  [[ "$completion" == "$4" ]] \
    || die "authenticated TPM completion evidence does not match the canonical lifecycle evidence"
  install_value="$(counter_value "$COUNTER_INDEX")"
  freshness_value="$(counter_value "$FRESHNESS_INDEX")"
  (( install_value == 10#$expected_install )) \
    || die "the live install counter no longer equals its authenticated ceremony value"
  (( freshness_value >= 10#$expected_freshness )) \
    || die "the live freshness high-water regressed below its authenticated ceremony value"
  printf 'complete\n'
}

completion_status() {
  (( $# == 0 )) || die "completion-status takes no arguments"
  with_workspace; compute_policies
  [[ "$(owner_auth_set)" == 1 ]] \
    || die "ownerAuthSet is not set; there is no authenticated completed ceremony"
  completion_read \
    || die "the TPM has no authenticated write-locked ceremony completion record"
}

provisioning_status() {
  (( $# == 0 )) || die "provisioning-status takes no arguments"
  with_workspace
  [[ "$(owner_auth_set)" == 0 ]] \
    || die "ownerAuthSet=1 before provisioning; signed physical recovery is required"
  local index
  for index in "$COUNTER_INDEX" "$FRESHNESS_INDEX" "$RECORD_INDEX" "$COMPLETION_INDEX"; do
    ! index_present "$index" \
      || die "TPM state already exists at $index; encrypted-volume reset is not a fresh install — TPM clear with physical presence and signed reinstall are required"
  done
  printf 'virgin\n'
}

ceremony_prepare() { # profile target policy initial consumed absolute issuance seq
  (( $# == 4 )) || die "ceremony-prepare requires a profile, target, policy and initial issuance sequence"
  validate_profile "$1"; validate_target "$2"; validate_policy_id "$3"
  local requested="$4" wanted index current step
  if ! [[ "$requested" =~ ^[0-9]{1,16}$ ]] || (( requested > MAX_SAFE_INTEGER )); then
    die "'$requested' is not a valid initial issuance sequence"
  fi
  wanted="$(profile_digest "$1" "$2" "$3")"
  with_workspace; compute_policies

  # A pre-set owner authorization is not evidence of our ceremony. It is exactly
  # the attacker-known-auth case: no trusted invocation can prove who chose it.
  [[ "$(owner_auth_set)" == 0 ]] \
    || die "ownerAuthSet=1 before the trusted ceremony; refusing to accept arbitrary owner authorization — TPM clear with physical presence and signed reinstall are required"

  # Virgin means all four fixed indices are absent. Once provisioning begins,
  # deleting the record alone or record+freshness still leaves the install
  # counter, so this command can never reinterpret partial state as virgin.
  for index in "$COUNTER_INDEX" "$FRESHNESS_INDEX" "$RECORD_INDEX" "$COMPLETION_INDEX"; do
    ! index_present "$index" \
      || die "TPM provisioning already began ($index exists); ceremony is one-time and partial state requires signed physical recovery"
  done

  # EVERYTHING THE OWNER HIERARCHY IS STILL NEEDED FOR MUST ALREADY BE DONE.
  # These are refusals: sealing first and discovering the consequence at the next
  # boot is exactly the failure mode that makes an appliance unrecoverable.
  handle_present "$DEVICE_ROOT_HANDLE" \
    || die "refusing to seal the owner hierarchy before the device root is persisted at $DEVICE_ROOT_HANDLE; tpm2_evictcontrol needs owner authorization and would never get it again"
  handle_present "$PERSISTENT_SRK_HANDLE" \
    || die "refusing to seal the owner hierarchy while there is no persistent storage root key at $PERSISTENT_SRK_HANDLE; systemd would have to recreate it under the owner hierarchy at every boot, and this appliance would stop being able to unlock its own disk"

  # Fixed state is created in its irreversible order before owner authorization
  # changes: install counter, freshness counter, then written+write-locked record.
  provision_counter "$COUNTER_INDEX"; increment_counter "$COUNTER_INDEX"
  provision_counter "$FRESHNESS_INDEX"; increment_counter "$FRESHNESS_INDEX"
  current="$(counter_value "$FRESHNESS_INDEX")"
  if (( requested > 0 )); then
    (( requested >= current )) \
      || die "initial issuance sequence $requested is below the TPM's absolute freshness value $current"
    (( requested - current <= MAX_FRESHNESS_GAP )) \
      || die "initial issuance sequence $requested is more than $MAX_FRESHNESS_GAP ahead of the TPM's absolute value $current"
    for (( step = current; step < requested; step++ )); do increment_counter "$FRESHNESS_INDEX"; done
  fi
  write_record "$wanted"
  assert_fixed_state "$wanted"
  printf '%s %s %s\n' "$(counter_value "$COUNTER_INDEX")" \
    "$(counter_value "$FRESHNESS_INDEX")" "$wanted"
}

ceremony_finalize() { # profile target policy evidence-digest install-at-ceremony freshness-at-ceremony
  (( $# == 6 )) || die "ceremony-finalize requires profile, target, policy, evidence digest and ceremony counter values"
  validate_profile "$1"; validate_target "$2"; validate_policy_id "$3"
  [[ "$4" =~ ^[0-9a-f]{64}$ ]] || die "completion evidence digest is malformed"
  [[ "$5" =~ ^[1-9][0-9]{0,15}$ && "$6" =~ ^[1-9][0-9]{0,15}$ ]] \
    || die "ceremony counter evidence is malformed"
  local wanted install_value freshness_value expected_install="$5" expected_freshness="$6"
  wanted="$(profile_digest "$1" "$2" "$3")"
  with_workspace; compute_policies
  [[ "$(owner_auth_set)" == 0 ]] \
    || die "ownerAuthSet=1 before the trusted one-time finalize path; arbitrary owner authorization is never accepted"
  assert_fixed_state "$wanted"
  ! index_present "$COMPLETION_INDEX" \
    || die "ceremony completion evidence already exists before finalize; this is not a trusted one-time transition"
  install_value="$(counter_value "$COUNTER_INDEX")"
  freshness_value="$(counter_value "$FRESHNESS_INDEX")"
  (( install_value == 10#$expected_install && freshness_value == 10#$expected_freshness )) \
    || die "live TPM counters changed between ceremony preparation and authenticated finalization"
  write_completion "$4"

  # 32 BYTES FROM THE KERNEL CSPRNG, PASSED BY FILE AND NEVER BY ARGUMENT. An
  # authorization value on a command line is in /proc for every process on the
  # machine to read. $WORK is 0700 on a tmpfs and is removed when this command
  # returns; nothing writes the value anywhere else, prints it, or keeps it.
  "$(tool python3)" -c '
import os, sys
with open(sys.argv[1], "wb") as handle:
    handle.write(os.urandom(32))
' "$WORK/owner-auth.bin" \
    || die "cannot obtain owner authorization entropy"
  [[ "$(wc -c < "$WORK/owner-auth.bin" | tr -d '[:space:]')" == 32 ]] \
    || die "the owner authorization was not 32 bytes of entropy"
  "$(tool tpm2_changeauth)" -c o "file:$WORK/owner-auth.bin" >/dev/null 2>&1 \
    || die "the TPM refused to take a new owner authorization"
  # SHRED THE ONLY COPY BEFORE ASSERTING ANYTHING ELSE. From here nobody -- this
  # helper included -- holds the value.
  "$(tool python3)" -c '
import os, sys
path = sys.argv[1]
with open(path, "r+b") as handle:
    handle.write(b"\x00" * 32)
    handle.flush()
    os.fsync(handle.fileno())
os.unlink(path)
' "$WORK/owner-auth.bin" \
    || die "cannot discard the owner authorization; refusing to leave it on this appliance"
  [[ ! -e "$WORK/owner-auth.bin" ]] || die "the owner authorization was not discarded"

  if [[ -n "${NI_TPM_STATE_TEST_TOOLS:-}" && "${NI_TEST_INTERRUPT_AFTER_CHANGEAUTH:-}" == 1 ]]; then
    die "injected interruption after successful owner changeauth"
  fi

  # ASSERT THE OUTCOME, not the exit status of the command that produced it.
  [[ "$(owner_auth_set)" == 1 ]] \
    || die "the TPM still reports an empty owner authorization after it was changed"
  assert_fixed_state "$wanted"
  [[ "$(completion_read)" == "$4" ]] \
    || die "the authenticated completion record changed after owner authorization sealing"
  printf 'complete\n'
}

profile_digest_command() { # $1=profile $2=target $3=policy id — no TPM involved
  (( $# == 3 )) || die "profile-digest requires a profile, a hardware target and a trust policy id"
  validate_profile "$1"; validate_target "$2"; validate_policy_id "$3"
  profile_digest "$1" "$2" "$3"
}

usage() {
  cat >&2 <<'EOF'
usage:
  neural-ice-tpm-state counter-read
  neural-ice-tpm-state counter-next
  neural-ice-tpm-state freshness-read
  neural-ice-tpm-state freshness-consume ISSUANCE_SEQ
  neural-ice-tpm-state profile-read
  neural-ice-tpm-state profile-bind PROFILE HARDWARE_TARGET TRUST_POLICY_ID
  neural-ice-tpm-state profile-digest PROFILE HARDWARE_TARGET TRUST_POLICY_ID
  neural-ice-tpm-state ceremony-prepare PROFILE HARDWARE_TARGET TRUST_POLICY_ID INITIAL_ISSUANCE_SEQ
  neural-ice-tpm-state ceremony-finalize PROFILE HARDWARE_TARGET TRUST_POLICY_ID EVIDENCE_SHA256 INSTALL_COUNTER FRESHNESS_COUNTER
  neural-ice-tpm-state provisioning-status
  neural-ice-tpm-state completion-status
  neural-ice-tpm-state state-snapshot PROFILE HARDWARE_TARGET TRUST_POLICY_ID
  neural-ice-tpm-state runtime-status PROFILE HARDWARE_TARGET TRUST_POLICY_ID EVIDENCE_SHA256 INSTALL_COUNTER FRESHNESS_COUNTER
EOF
  exit 2
}

command_name="${1:-}"
shift || true
case "$command_name" in
  counter-read) counter_read "$@" ;;
  counter-next) counter_next "$@" ;;
  freshness-read) freshness_read "$@" ;;
  freshness-consume) freshness_consume "$@" ;;
  profile-read) profile_read "$@" ;;
  profile-bind) profile_bind "$@" ;;
  profile-digest) profile_digest_command "$@" ;;
  ceremony-prepare) ceremony_prepare "$@" ;;
  ceremony-finalize) ceremony_finalize "$@" ;;
  provisioning-status) provisioning_status "$@" ;;
  completion-status) completion_status "$@" ;;
  state-snapshot) state_snapshot "$@" ;;
  runtime-status) runtime_status "$@" ;;
  *) usage ;;
esac
