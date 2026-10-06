# collector-v2 — output of the REAL host collector, with the opt-in excerpts

`collector-excerpts.tar.gz` is what `neural-ice-support-bundle.py` (ICE-Fabric-v2 `5365944`, PR #125) wrote
in its own hermetic sandbox (`config/bin/test_support_bundle.py`, `Sandbox.make_bundle` with
`sections: {app_excerpts: true}`): five excerpt lines, `files[].lines` in the signed manifest. The signing
key was generated for that run and destroyed; `pin.txt` is the sha256 of its SPKI. Every « customer » string
in the excerpts is the sandbox's synthetic canary. The tests edit this file the way the client does (delete
whole lines) and never re-sign it.
