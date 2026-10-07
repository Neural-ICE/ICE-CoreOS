# collector-v2 — output of the REAL host collector, with the opt-in excerpts

`collector-excerpts.tar.gz` is what `neural-ice-support-bundle.py` (ICE-Fabric-v2 `5365944`, PR #125) wrote
in its own hermetic sandbox (`config/bin/test_support_bundle.py`, `Sandbox.make_bundle` with
`sections: {app_excerpts: true}`): five excerpt lines, `files[].lines` in the signed manifest. The signing
key was generated for that run and destroyed; `pin.txt` is the sha256 of its SPKI. Every « customer » string
in the excerpts is the sandbox's synthetic canary. The tests edit this file the way the client does (delete
whole lines) and never re-sign it.

## Neutral unit names

This repository is open core: it does not name product units. The collector's unit policy and its sandbox
use the product's real unit names, so the bundle was produced from a copy of three files of that checkout
(`config/bin/neural-ice-support-bundle.py`, `config/bin/test_support_bundle.py`,
`config/support-bundle/support-units.json`) after one mechanical rename, and nothing else changed:

| Product identifier in the producer | Neutral name in the fixture |
|---|---|
| the application unit (`*.service`) and its Rust crate prefix | `example-app.service`, `example_app::` |
| the licence-gate host unit | `example-gate.service` |
| the inference runtime unit named in the model-activation ledger | `example-engine.service` |
| the application's data directory and its licence right | `/example/`, `EXAMPLE-RIGHT` |

The new names have the same length as the application's (`example-app` / `example_app`), so the excerpts
file is still 773 bytes and the five lines keep their shape. The collector code path is the real one: run
unrenamed, the same sandbox reproduces every committed file of the previous fixture byte for byte except
`manifest.json` and `trust.json` (they carry the per-run key's SPKI hash). The schema keys of the units
section (`app_failure_classes`: `inference`, `paddle_stack`, `rag`, `tools`) are the collector's closed
contract and are left as they are.
