# Contributing to ICE-CoreOS

Thanks for your interest! A few ground rules keep contributions compatible
with the project's license model ([FSL-1.1-ALv2](LICENSE.md), converting to
Apache-2.0 two years per release — see
[ADR-0007](docs/ADR-0007-license-fsl.md)).

## Developer Certificate of Origin (DCO)

All contributions must be signed off (`git commit -s`), certifying the
[Developer Certificate of Origin 1.1](https://developercertificate.org/):
you wrote the contribution (or have the right to submit it) and you submit it
under the project's license, including the future Apache-2.0 grant.

## Practical notes

- Match the existing style; shell scripts must pass `shellcheck`/`bash -n`.
- Keep the repo **vanilla**: no credentials, no private infrastructure
  details, no product/business material.
- Security issues: do not open a public issue — contact the security contacts
  listed in the shim-review submission (see `secureboot/`).
