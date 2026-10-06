#!/usr/bin/env python3
"""ni-bench-snapshot — red-phase stub: every entry point is missing behaviour."""
import sys


class BenchError(RuntimeError):
    pass


def _todo(*_a, **_k):
    raise NotImplementedError("ni-bench-snapshot: not implemented yet")


capture = validate_snapshot = build_record = validate_record = record_digest = _todo
make_sheet = sheet_payload = verify_sheet = pubkey_fingerprint = load_json_strict = _todo
store = validate_store = _todo

if __name__ == "__main__":
    sys.exit(2)
