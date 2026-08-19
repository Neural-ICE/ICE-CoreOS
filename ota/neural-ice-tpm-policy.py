#!/usr/bin/env python3
"""Predict the PCR 7 value a future Secure Boot state will produce.

The signed-policy design (docs/TPM-SIGNED-POLICY-RUNBOOK.md) needs the Owner to
authorise a state the machine has not reached yet. That requires knowing the
value PCR 7 *will* take. `systemd-measure sign` cannot help: it computes PCR 11
for a UKI, and this chain is GRUB with a separate kernel and initramfs.

PCR 7 is not computed from first principles here. It is REPLAYED from the TCG
event log the firmware already produced, and the replay is proven against the
live PCR before any prediction is emitted.

    replay(current log)  ==  tpm2_pcrread sha256:7      <-- the whole point
    replay(log with the target state substituted)       --> the predicted value

🔴 If the first line does not hold, this tool REFUSES. A prediction from a parser
that cannot reproduce the present is a fleet-wide lockout waiting to happen, and
it would look exactly like a correct one.
"""

import argparse
import hashlib
import struct
import subprocess
import sys

# TPM_ALG_ID -> (name, digest length). Only what a PCR 7 replay needs.
ALGS = {0x0004: ("sha1", 20), 0x000B: ("sha256", 32),
        0x000C: ("sha384", 48), 0x000D: ("sha512", 64)}

# The event types PCR 7 carries. Names matter because the substitution addresses
# events by what they measure, never by position: an index shifts the day the
# firmware emits one more event, and silently predicts the wrong value.
EV_EFI_VARIABLE_DRIVER_CONFIG = 0x80000001   # SecureBoot, PK, KEK, db, dbx
EV_EFI_VARIABLE_AUTHORITY = 0x800000E0       # the cert that validated a binary
EV_SEPARATOR = 0x00000004

DEFAULT_EVENTLOG = "/sys/kernel/security/tpm0/binary_bios_measurements"


class EventLogError(RuntimeError):
    pass


def _u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def parse_eventlog(blob):
    """Yield the TCG2 events. The first record is the legacy-format spec-id
    header, which is NOT replayed: firmware emits it with a SHA-1 digest field
    that is not part of any bank."""
    events = []
    off = 0
    if len(blob) < 32:
        raise EventLogError("event log is too short to contain its header")

    # Record 0: TCG_PCR_EVENT (legacy layout) carrying EfiSpecIdEvent.
    ev_size = _u32(blob, 28)
    off = 32 + ev_size
    if off > len(blob):
        raise EventLogError("spec-id header claims a size past the end of the log")

    while off + 12 <= len(blob):
        pcr = _u32(blob, off)
        etype = _u32(blob, off + 4)
        count = _u32(blob, off + 8)
        off += 12
        digests = {}
        for _ in range(count):
            if off + 2 > len(blob):
                raise EventLogError("truncated digest header")
            alg_id = struct.unpack_from("<H", blob, off)[0]
            off += 2
            if alg_id not in ALGS:
                raise EventLogError(f"unknown digest algorithm 0x{alg_id:04x}; "
                                    "refusing to replay a log this parser does "
                                    "not fully understand")
            name, size = ALGS[alg_id]
            digests[name] = blob[off:off + size]
            off += size
        if off + 4 > len(blob):
            raise EventLogError("truncated event size")
        size = _u32(blob, off)
        off += 4
        data = blob[off:off + size]
        if len(data) != size:
            raise EventLogError("event data runs past the end of the log")
        off += size
        events.append({"pcr": pcr, "type": etype, "digests": digests, "data": data})

    if off != len(blob):
        raise EventLogError(f"{len(blob) - off} trailing bytes the parser did "
                            "not consume; the log is not fully understood")
    return events


def variable_name(ev):
    """UEFI variable name from an EV_EFI_VARIABLE_* event.

    UEFI_VARIABLE_DATA: VendorGuid[16] UnicodeNameLength[8] VariableDataLength[8]
    UnicodeName[NameLength*2] ...
    """
    if len(ev["data"]) < 32:
        return None
    name_len = struct.unpack_from("<Q", ev["data"], 16)[0]
    end = 32 + name_len * 2
    if end > len(ev["data"]):
        return None
    try:
        return ev["data"][32:end].decode("utf-16-le")
    except UnicodeDecodeError:
        return None


def replay(events, pcr_index, alg="sha256"):
    """Extend a zeroed PCR with every event addressed to it, in log order."""
    h = hashlib.new(alg)
    size = h.digest_size
    acc = b"\x00" * size
    seen = 0
    for ev in events:
        if ev["pcr"] != pcr_index:
            continue
        d = ev["digests"].get(alg)
        if d is None:
            raise EventLogError(f"an event for PCR {pcr_index} carries no {alg} "
                                "digest; this bank cannot be replayed")
        acc = hashlib.new(alg, acc + d).digest()
        seen += 1
    if seen == 0:
        raise EventLogError(f"no event addresses PCR {pcr_index}")
    return acc, seen


def live_pcr(pcr_index, alg="sha256"):
    out = subprocess.run(["tpm2_pcrread", f"{alg}:{pcr_index}"],
                         capture_output=True, text=True, check=True).stdout
    # tpm2_pcrread prints "    7 : 0x<HEX>" under a "  sha256:" heading. Match on
    # the index as a token rather than a prefix: "7:" also prefixes "70:", and
    # spacing varies between tpm2-tools releases.
    for line in out.splitlines():
        parts = line.strip().split(":", 1)
        if len(parts) != 2 or parts[0].strip() != str(pcr_index):
            continue
        value = parts[1].strip()
        if not value.lower().startswith("0x"):
            continue
        return bytes.fromhex(value[2:])
    raise EventLogError(f"tpm2_pcrread returned no value for {alg}:{pcr_index}; "
                        f"output was:\n{out}")


def cmd_selfcheck(args):
    """Prove the replay reproduces the CURRENT value. Everything else depends on
    this, so it is a command in its own right: it is the one thing an operator
    can run to decide whether a prediction from this host is worth anything."""
    blob = open(args.eventlog, "rb").read()
    events = parse_eventlog(blob)
    computed, n = replay(events, args.pcr, args.alg)
    measured = live_pcr(args.pcr, args.alg)
    print(f"  events replayed for PCR {args.pcr} : {n}")
    print(f"  replayed  : {computed.hex()}")
    print(f"  measured  : {measured.hex()}")
    if computed != measured:
        print("\n🔴 REPLAY DOES NOT REPRODUCE THE LIVE PCR.\n"
              "   No prediction may be emitted from this host: the parser does "
              "not model what this firmware measures.", file=sys.stderr)
        return 1
    print("\n✅ the replay reproduces the live PCR — predictions from this host "
          "rest on a method proven here")
    return 0


def cmd_show(args):
    """List what PCR 7 actually measures on this machine, by variable name.

    Substitutions are written against these names, so an operator must be able
    to see them before authoring one."""
    blob = open(args.eventlog, "rb").read()
    events = parse_eventlog(blob)
    idx = 0
    for ev in events:
        if ev["pcr"] != args.pcr:
            continue
        idx += 1
        d = ev["digests"].get(args.alg, b"").hex()
        if ev["type"] in (EV_EFI_VARIABLE_DRIVER_CONFIG, EV_EFI_VARIABLE_AUTHORITY):
            label = variable_name(ev) or "<unnamed variable>"
            kind = ("config" if ev["type"] == EV_EFI_VARIABLE_DRIVER_CONFIG
                    else "authority")
            print(f"  {idx:3d}  {kind:9s}  {label:<24s}  {d}")
        elif ev["type"] == EV_SEPARATOR:
            print(f"  {idx:3d}  separator  {'':<24s}  {d}")
        else:
            print(f"  {idx:3d}  0x{ev['type']:08x} {'':<23s}  {d}")
    return 0


def selector(ev):
    """`kind:name` for an addressable event, else None.

    `db` is measured TWICE and differently: once as driver config (what is
    enrolled) and once as authority (which certificate actually validated the
    loaded binary). Both move at an anchor switch and they are not the same
    value, so a selector that only carried the name would be ambiguous exactly
    where it matters most."""
    if ev["type"] == EV_EFI_VARIABLE_DRIVER_CONFIG:
        kind = "config"
    elif ev["type"] == EV_EFI_VARIABLE_AUTHORITY:
        kind = "authority"
    else:
        return None
    name = variable_name(ev)
    return f"{kind}:{name}" if name else None


def substitute(events, pcr_index, alg, overrides):
    """Replace the digest of the named events. Refuses anything ambiguous."""
    remaining = dict(overrides)
    applied = []
    for ev in events:
        if ev["pcr"] != pcr_index:
            continue
        sel = selector(ev)
        if sel is None or sel not in remaining:
            continue
        new = remaining.pop(sel)
        if len(new) != len(ev["digests"][alg]):
            raise EventLogError(f"{sel}: replacement digest is {len(new)} bytes, "
                                f"the log carries {len(ev['digests'][alg])}")
        applied.append((sel, ev["digests"][alg], new))
        ev["digests"][alg] = new
    if remaining:
        raise EventLogError("these selectors match no event in this log: "
                            + ", ".join(sorted(remaining))
                            + " — run `show` to see what this machine measures. "
                              "Predicting from a substitution that silently did "
                              "nothing returns the CURRENT value dressed as a "
                              "future one.")
    return applied


def pcr_policy_digest(pcr_index, value, alg="sha256"):
    """The TPM policyDigest a PolicyPCR session reaches for this PCR value.

        policyDigest = H( 0…0 || TPM_CC_PolicyPCR || TPML_PCR_SELECTION || H(value) )

    This is what the Owner signs: the authorisation names a policy digest, never
    a PCR value directly."""
    if pcr_index > 23:
        raise EventLogError("PCR index outside the 0..23 the selection encodes")
    alg_id = next(k for k, v in ALGS.items() if v[0] == alg)
    select = bytearray(3)
    select[pcr_index // 8] |= 1 << (pcr_index % 8)
    # TPML_PCR_SELECTION: count, then {hashAlg, sizeofSelect, pcrSelect}
    selection = struct.pack(">I", 1) + struct.pack(">H", alg_id) + bytes([3]) + bytes(select)
    digest_tpm = hashlib.new(alg, value).digest()
    zero = b"\x00" * hashlib.new(alg).digest_size
    TPM_CC_PolicyPCR = 0x0000017F
    return hashlib.new(alg, zero + struct.pack(">I", TPM_CC_PolicyPCR)
                       + selection + digest_tpm).digest()


def cmd_predict(args):
    blob = open(args.eventlog, "rb").read()
    events = parse_eventlog(blob)

    # The self-check is not optional here. A prediction is only as trustworthy as
    # the parser's ability to reproduce the present, so it is re-proven on the
    # untouched log before anything is substituted.
    computed, _ = replay(events, args.pcr, args.alg)
    measured = live_pcr(args.pcr, args.alg)
    if computed != measured:
        print("🔴 the replay does not reproduce the live PCR; refusing to predict",
              file=sys.stderr)
        return 1
    print(f"  current   : {measured.hex()}")

    overrides = {}
    for item in args.set or []:
        if "=" not in item:
            raise EventLogError(f"--set expects kind:name=<hex>, got {item!r}")
        sel, hexval = item.split("=", 1)
        try:
            overrides[sel.strip()] = bytes.fromhex(hexval.strip())
        except ValueError:
            raise EventLogError(f"{sel}: replacement is not hex")
    if not overrides:
        raise EventLogError("no --set given: predicting an unchanged state would "
                            "return the current value, which authorises nothing new")

    applied = substitute(events, args.pcr, args.alg, overrides)
    for sel, old, new in applied:
        print(f"  replaced  : {sel}\n              {old.hex()}\n           -> {new.hex()}")
    predicted, _ = replay(events, args.pcr, args.alg)
    if predicted == measured:
        print("\n🔴 the prediction equals the current value — the substitution "
              "changed nothing measurable. Refusing: this would authorise the "
              "present while claiming to authorise a future state.", file=sys.stderr)
        return 1
    print(f"\n  predicted : {predicted.hex()}")
    print(f"  policy    : {pcr_policy_digest(args.pcr, predicted, args.alg).hex()}"
          "   <- what the Owner signs")
    return 0


def cmd_policy_digest(args):
    """Exposed on its own so it can be checked against tpm2_createpolicy."""
    value = bytes.fromhex(args.value)
    print(pcr_policy_digest(args.pcr, value, args.alg).hex())
    return 0


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--eventlog", default=DEFAULT_EVENTLOG)
    p.add_argument("--pcr", type=int, default=7)
    p.add_argument("--alg", default="sha256", choices=sorted({v[0] for v in ALGS.values()}))
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("selfcheck", help="prove the replay reproduces the live PCR")
    sub.add_parser("show", help="list what this PCR measures, by variable name")
    sp = sub.add_parser("predict", help="value this PCR takes under a future state")
    sp.add_argument("--set", action="append", metavar="kind:name=HEX",
                    help="replace a measurement, e.g. authority:db=<sha256 hex>")
    pd = sub.add_parser("policy-digest",
                        help="policyDigest for a PCR value (check vs tpm2_createpolicy)")
    pd.add_argument("--value", required=True, metavar="HEX")
    args = p.parse_args()
    try:
        return {"selfcheck": cmd_selfcheck, "show": cmd_show,
                "predict": cmd_predict, "policy-digest": cmd_policy_digest}[args.cmd](args)
    except EventLogError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
