#!/usr/bin/env bash
# Deterministic contract/refusal tests. The real TPM semantics are exercised by
# ci/test-swtpm-owner-ota-state.sh; this mock makes pre-mutation refusals and
# malformed public/property responses directly observable.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HELPER="$ROOT/ota/neural-ice-ota-tpm-state.sh"
CEREMONY_UNIT="$ROOT/image/firstboot/neural-ice-firstboot-tpm-ceremony.service"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/ni-owner-ota-state.XXXXXX")"
trap 'rm -rf -- "$TMP"' EXIT
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
expect_refusal() {
  local why=$1
  shift
  if "$@" >"$TMP/out" 2>"$TMP/err"; then fail "$why"; fi
}

TOOLS="$TMP/tools"; STATE="$TMP/state"; RUN="$TMP/run"
mkdir -m 0700 "$TOOLS" "$STATE"
for tool in python3 flock; do ln -s "$(command -v "$tool")" "$TOOLS/$tool"; done

cat >"$TOOLS/tpm-mock" <<'PY'
#!/usr/bin/env python3
import hashlib, json, os, pathlib, struct, sys

state = pathlib.Path(os.environ["MOCK_TPM_STATE"])
command = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
FLOOR = "1500001"; ANCHOR = "1500002"
P_WRITE = "1c4f7107dcaf23ce00756448508558683104bd9e203e93749c227b451270438f"
P_LOCK = "c8905eb3b7302fc69bb1a52843b142f3e2faf66386f04f89b86cf6399b30e301"
P_FLOOR = "f83217e5a2a04342f7daa55ccfb3cd4b8a1f1e8ebb28c7719a9abbdbd638a230"
P_EXTEND = "b6a2e7142ee56fd978047488483daa5b42b8dc4cc7ddcceddfb91793cf1ff1b7"
FLOOR_NAME = "000be283f20a38b93f8cef085efb4aee9f5944cc3b3b28b850bf3c0eeb2054cd7fc4"
ANCHOR_NAMES = {False:"000b038de2091c1c8ef2e8fd8869f17bef3a576ae287530fa17f05ae3b9712014b5d",
                True:"000b11afd155aca82a503f2029cc11395389654c3a25fc54b9eca6d33abdff498d56"}

def opt(name):
    try: return args[args.index(name)+1]
    except (ValueError, IndexError): return None
def index_arg():
    for arg in args:
        if arg.startswith("0x"): return arg[2:].lower().lstrip("0") or "0"
    raise SystemExit(2)
def path_for(index): return state / (index.lstrip("0") or "0")
def load(index): return json.loads(path_for(index).read_text())
def save(index, value): path_for(index).write_text(json.dumps(value, sort_keys=True))
def mutate(label):
    with (state / "mutations").open("a") as stream: stream.write(label + "\n")
def prop(name): return (state / name).read_text().strip() if (state/name).exists() else "0"
def session():
    spec = opt("-P")
    if not spec or not spec.startswith("session:"): raise SystemExit(1)
    return json.loads(pathlib.Path(spec[8:]).read_text())

if command == "tpm2_getcap":
    if args == ["handles-nv-index"]:
        for path in sorted(state.glob("15*")): print(f"- 0x{path.name}")
    elif args == ["properties-variable"]:
        print("TPM2_PT_PERMANENT:")
        for key in ("ownerAuthSet", "lockoutAuthSet", "disableClear"):
            print(f"  {key}: {prop(key)}")
    else: raise SystemExit(2)
elif command == "tpm2_startauthsession":
    pathlib.Path(opt("-S")).write_text(json.dumps({"cc":""}))
elif command == "tpm2_policycommandcode":
    ctx=pathlib.Path(opt("-S")); value=json.loads(ctx.read_text()); cc=args[-1]
    digests={"TPM2_CC_NV_Write":P_WRITE,"TPM2_CC_NV_WriteLock":P_LOCK,"TPM2_CC_NV_Extend":P_EXTEND}
    if cc not in digests: raise SystemExit(2)
    value["cc"]=cc; value["digest"]=digests[cc]; ctx.write_text(json.dumps(value))
    if opt("-L"): pathlib.Path(opt("-L")).write_bytes(bytes.fromhex(digests[cc]))
elif command == "tpm2_policyor":
    ctx=pathlib.Path(opt("-S")); value=json.loads(ctx.read_text())
    if not opt("-L") and value.get("digest") not in (P_WRITE,P_LOCK): raise SystemExit(1)
    value["digest"]=P_FLOOR; ctx.write_text(json.dumps(value))
    if opt("-L"): pathlib.Path(opt("-L")).write_bytes(bytes.fromhex(P_FLOOR))
elif command == "tpm2_flushcontext":
    pathlib.Path(args[0]).unlink(missing_ok=True)
elif command == "tpm2_nvdefine":
    idx=index_arg()
    if prop("ownerAuthSet") != "0" or path_for(idx).exists(): raise SystemExit(1)
    attrs=opt("-a"); size=int(opt("-s")); policy=pathlib.Path(opt("-L")).read_bytes().hex()
    base = 0x62008 if idx == FLOOR else 0x2060048 if idx == ANCHOR else 0
    if not base: raise SystemExit(1)
    save(idx,{"attrs":base,"size":size,"policy":policy,"data":"00"*size,"written":False,"locked":False})
    mutate("define:"+idx)
elif command == "tpm2_nvwrite":
    idx=index_arg(); obj=load(idx); sess=session()
    if sess.get("cc")!="TPM2_CC_NV_Write" or sess.get("digest")!=obj["policy"] or obj["locked"]: raise SystemExit(1)
    obj["data"]=pathlib.Path(opt("-i")).read_bytes().hex(); obj["written"]=True; save(idx,obj); mutate("write:"+idx)
elif command == "tpm2_nvwritelock":
    idx=index_arg(); obj=load(idx); sess=session()
    if sess.get("cc")!="TPM2_CC_NV_WriteLock" or sess.get("digest")!=obj["policy"]: raise SystemExit(1)
    obj["locked"]=True; save(idx,obj); mutate("lock:"+idx)
elif command == "tpm2_nvread":
    idx=index_arg(); obj=load(idx); pathlib.Path(opt("-o")).write_bytes(bytes.fromhex(obj["data"]))
elif command == "tpm2_nvreadpublic":
    idx=index_arg(); obj=load(idx); raw=obj["attrs"]
    if obj["locked"]: raw |= 0x800
    if obj["written"]: raw |= 0x20000000
    name = FLOOR_NAME if idx==FLOOR else ANCHOR_NAMES[obj["written"]]
    if obj.get("foreign_name"): name="000b"+"ab"*32
    print(f"0x{idx}:\n  name: {name}\n  hash algorithm:\n    friendly: sha256\n    value: 0xB")
    print(f"  attributes:\n    friendly: fixture\n    value: 0x{raw:X}\n  size: {obj['size']}\n  authorization policy: {obj['policy'].upper()}")
elif command == "tpm2_nvextend":
    idx=index_arg(); obj=load(idx); sess=session()
    if sess.get("cc")!="TPM2_CC_NV_Extend" or sess.get("digest")!=obj["policy"]: raise SystemExit(1)
    inp=pathlib.Path(opt("-i")).read_bytes()
    obj["data"]=hashlib.sha256(bytes.fromhex(obj["data"])+inp).hexdigest(); obj["written"]=True
    save(idx,obj); mutate("extend:"+idx)
elif command == "tpm2_clearcontrol":
    if args != ["-C","l","s"] or prop("lockoutAuthSet") != "0" or prop("disableClear") != "0": raise SystemExit(1)
    (state/"disableClear").write_text("1"); mutate("clearcontrol:set")
else:
    raise SystemExit(127)
PY
chmod 0700 "$TOOLS/tpm-mock"
for command in tpm2_getcap tpm2_startauthsession tpm2_policycommandcode tpm2_policyor \
  tpm2_flushcontext tpm2_nvdefine tpm2_nvwrite tpm2_nvwritelock tpm2_nvread \
  tpm2_nvreadpublic tpm2_nvextend tpm2_clearcontrol; do
  ln -s tpm-mock "$TOOLS/$command"
done

export MOCK_TPM_STATE="$STATE"
export NI_OTA_TPM_STATE_TESTING=1
export NI_OTA_TPM_STATE_TEST_TOOLS="$TOOLS"
export NI_OTA_TPM_STATE_TEST_RUN_DIR="$RUN"
ota() { bash "$HELPER" "$@"; }
clear_mutations() { : >"$STATE/mutations"; }
assert_no_mutations() { [[ ! -s "$STATE/mutations" ]] || fail "$1"; }

# The helper creates this private workspace itself in every production mode.
# ProtectSystem=strict makes /run read-only unless the ceremony unit grants the
# exact RuntimeDirectory/ReadWritePaths exception.  Keep both declarations
# coupled to the helper rather than widening the unit to all of /run.
runtime_directories="$(sed -n 's/^RuntimeDirectory=//p' "$CEREMONY_UNIT")"
read_write_paths="$(sed -n 's/^ReadWritePaths=//p' "$CEREMONY_UNIT")"
[[ " $runtime_directories " == *" neural-ice-ota-tpm-state "* ]] \
  || fail "ceremony unit does not create the owner OTA TPM helper runtime directory"
[[ " $read_write_paths " == *" /run/neural-ice-ota-tpm-state "* ]] \
  || fail "ceremony unit does not grant the owner OTA TPM helper its exact writable runtime path"
[[ " $read_write_paths " != *" /run "* && " $read_write_paths " != *" /run/ "* ]] \
  || fail "ceremony unit grants an over-broad writable /run path"

clear_mutations
expect_refusal "zero floor accepted" ota prepare 0
expect_refusal "negative floor accepted" ota prepare -1
expect_refusal "unsafe integer accepted" ota prepare 9007199254740992
expect_refusal "extra argument accepted" ota prepare 42 extra
expect_refusal "uppercase anchor digest accepted" ota extend "$(printf 'AA%.0s' {1..32})"
assert_no_mutations "malformed arguments reached a persistent mutation"

expect_refusal "absent state inspected as valid" ota inspect
printf 1 >"$STATE/disableClear"
clear_mutations
expect_refusal "pre-protected TPM was provisioned" ota prepare 42
assert_no_mutations "pre-existing disableClear reached a persistent mutation"
printf 0 >"$STATE/disableClear"
printf 1 >"$STATE/lockoutAuthSet"
clear_mutations
expect_refusal "non-empty Lockout authorization was provisioned" ota prepare 42
assert_no_mutations "non-empty Lockout authorization reached a persistent mutation"
printf 0 >"$STATE/lockoutAuthSet"
ota prepare 42 | grep -Fxq prepared || fail "prepare did not report completion"
inspection="$(ota inspect)"
python3 - "$inspection" <<'PY'
import json,sys
assert json.loads(sys.argv[1]) == {
 "anchor_sha256":None,"anchor_state":"pristine","baseline_floor":42,
 "clear_protected":False,"owner_sealed":False,"profile":"owner-sealed-ota-state-v1",
 "schema":"neural-ice-owner-ota-state-inspection-v1"}
PY
inspection_v2="$(ota inspect-v2)"
python3 - "$inspection_v2" <<'PY'
import json,sys
assert json.loads(sys.argv[1]) == {
 "anchor_attributes":"0x2060048","anchor_index":"0x01500002",
 "anchor_name":"000b038de2091c1c8ef2e8fd8869f17bef3a576ae287530fa17f05ae3b9712014b5d",
 "anchor_policy_sha256":"b6a2e7142ee56fd978047488483daa5b42b8dc4cc7ddcceddfb91793cf1ff1b7",
 "anchor_sha256":None,"anchor_size":32,"anchor_state":"pristine",
 "baseline_floor":42,"clear_protected":False,"floor_attributes":"0x62008",
 "floor_index":"0x01500001",
 "floor_name":"000be283f20a38b93f8cef085efb4aee9f5944cc3b3b28b850bf3c0eeb2054cd7fc4",
 "floor_policy_sha256":"f83217e5a2a04342f7daa55ccfb3cd4b8a1f1e8ebb28c7719a9abbdbd638a230",
 "floor_size":8,"owner_sealed":False,"profile":"owner-sealed-ota-state-v1",
 "schema":"neural-ice-owner-ota-state-inspection-v2"}
PY

clear_mutations
expect_refusal "existing state was reprovisioned" ota prepare 42
assert_no_mutations "repeated prepare changed persistent state"

rm "$STATE/1500002"
clear_mutations
expect_refusal "partial state was repaired" ota prepare 43
assert_no_mutations "partial state triggered a persistent mutation"

rm -f "$STATE/1500001"; ota prepare 42 >/dev/null
python3 - "$STATE/1500002" <<'PY'
import json,sys
p=sys.argv[1]; value=json.load(open(p)); value["attrs"] |= 2
open(p,"w").write(json.dumps(value))
PY
clear_mutations
expect_refusal "foreign anchor attributes were accepted" ota inspect
expect_refusal "foreign anchor was clear-protected" ota clear-protection
assert_no_mutations "foreign state reached a persistent mutation"

rm -f "$STATE/1500001" "$STATE/1500002"; ota prepare 42 >/dev/null
clear_mutations
expect_refusal "runtime extended before owner sealing" ota extend "$(printf '11%.0s' {1..32})"
assert_no_mutations "unsealed runtime reached NV_Extend"
ota clear-protection | grep -Fxq protected || fail "clear protection did not report success"
printf 1 >"$STATE/ownerAuthSet"
first="$(ota extend "$(printf '11%.0s' {1..32})")"
[[ "$first" == 8878b15a7d6a3a4f464e8f9f42591dbc0cf4bedea0ec309003d2b2ee53655ef8 ]] \
  || fail "first anchor extension returned $first"
second="$(ota extend "$(printf '22%.0s' {1..32})")"
[[ "$second" == 78830000e1197790a7e1884139a65721210d642ad112e6c9899a05cb214027a5 ]] \
  || fail "second anchor extension returned $second"
inspection_v2="$(ota inspect-v2)"
python3 - "$inspection_v2" "$second" <<'PY'
import json,sys
d=json.loads(sys.argv[1])
assert d["anchor_name"] == "000b11afd155aca82a503f2029cc11395389654c3a25fc54b9eca6d33abdff498d56"
assert d["anchor_sha256"] == sys.argv[2] and d["anchor_state"] == "written"
assert d["clear_protected"] is True and d["owner_sealed"] is True
PY

printf 0 >"$STATE/disableClear"
clear_mutations
expect_refusal "runtime extended without clear protection" ota extend "$(printf '33%.0s' {1..32})"
assert_no_mutations "missing clear protection reached NV_Extend"

printf 1 >"$STATE/disableClear"
python3 - "$STATE/1500002" <<'PY'
import json,sys
p=sys.argv[1]; value=json.load(open(p)); value["foreign_name"]=True
open(p,"w").write(json.dumps(value))
PY
clear_mutations
expect_refusal "foreign TPM-computed Name was accepted" ota extend "$(printf '44%.0s' {1..32})"
assert_no_mutations "foreign Name reached NV_Extend"

printf 'OWNER_OTA_TPM_STATE_CONTRACT_TEST_OK\n'
