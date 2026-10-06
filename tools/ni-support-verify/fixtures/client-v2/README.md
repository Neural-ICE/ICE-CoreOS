# client-v2 — output of the REAL client export code on the REAL collector's bundle

Input: `../collector-v2/collector-excerpts.tar.gz` (five excerpt lines). Producer: the ICE-Client export
pipeline (`support_export::build_export` / `VerifiedBundle::export_archive` + `seal::seal_export`, ICE-Client
PR #288), run by its ignored test `export_for_the_cross_repository_proof`:

    NI_PROOF_OUT_DIR=… NI_PROOF_COLLECTOR_BUNDLE=…/collector-excerpts.tar.gz [NI_PROOF_REMOVE=1,3] [NI_PROOF_INCLUDE_EXCERPTS=0] \
      cargo test --lib -- --ignored export_for_the_cross_repository_proof

| File | What the user did in the preview |
|---|---|
| `client-unedited.tar.gz` | nothing |
| `client-removed-1-3.tar.gz` | removed excerpt lines with id 1 and 3 (positions 1 and 3 of the signed `lines`) |
| `client-all-removed.tar.gz` | unticked the excerpts section (the file stays, empty) |
| `client-removed-1-3-throwaway-key.zip` | same as the removed case, in the client's envelope (`LISEZ-MOI.txt` + `diagnostic.tar.gz.age`), sealed to an age key generated and dropped by the producer: it cannot be decrypted, by design; it proves the envelope layer |

The manifest and signature in every file are the collector's, untouched.
