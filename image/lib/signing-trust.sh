#!/usr/bin/env bash
#
# THE SIGNING CERTIFICATE IS THE TRUST POLICY — binding the two.
#
# WHY THIS FILE EXISTS. `TRUST_POLICY_ID` was a caller-supplied string sealed
# into the UKI cmdline, and the signing branch verified the produced binary
# against THE SAME certificate it had just signed it with. That is a tautology:
# any self-signed certificate satisfies it, so a medium could name
# `neural-ice-secureboot-lab-v1` while being signed by a key that policy has
# never heard of. Every downstream comparison — the image's marker, the release
# authorization, the enrolled anchor — then agreed about a word that meant
# nothing.
#
# WHAT REPLACES IT. The named trust policy is a REAL OBJECT in this tree
# (secureboot/trust-policies/<id>), a fail-closed executable that pins the
# SHA-256 of every anchor certificate it will approve. Before anything is signed,
# the signing certificate must resolve to one of THOSE anchors — either by being
# one, or by verifying against one. The anchor files themselves are pinned back
# to the policy executable, so pointing the build at a lookalike directory is a
# refusal rather than a substitution.
#
# WHAT THIS DOES NOT CLAIM. It does not prove the firmware carries that anchor in
# db; that is a property of a machine, established by the trust policy at
# artifact-finalisation time and by the measured boot on the appliance. It proves
# the narrower thing that was actually missing: the word sealed into the medium
# names the key that signed it.

# openssl is the only tool that can normalise a certificate to its DER encoding,
# and the DER bytes are what a fingerprint has to be over: the same certificate
# in PEM and in DER must produce the same identity, or "the cert is pinned" is a
# statement about a file format.
signing_trust_cert_fingerprint() { # $1=certificate path
  if (( $# != 1 )); then
    echo "signing_trust_cert_fingerprint requires a certificate path" >&2
    return 2
  fi
  local cert=$1 openssl_bin
  [[ -f "$cert" && ! -L "$cert" ]] || {
    echo "certificate is missing or not a regular file: $cert" >&2
    return 1
  }
  openssl_bin="${NEURAL_ICE_SIGNING_TRUST_OPENSSL:-$(command -v openssl 2>/dev/null || true)}"
  [[ -n "$openssl_bin" ]] || { echo "openssl is required to fingerprint a certificate" >&2; return 1; }
  local form scratch rc
  scratch="$(mktemp "${TMPDIR:-/tmp}/ni-signing-trust.XXXXXX")" || return 1
  for form in PEM DER; do
    rc=0
    # The EXIT STATUS decides, never the shape of the output. Piping openssl
    # straight into sha256sum would hash an EMPTY stream when the parse failed
    # and return a perfectly well-formed 64-hex digest -- the same digest for
    # every unparseable file, which is worse than no fingerprint at all.
    "$openssl_bin" x509 -inform "$form" -in "$cert" -outform DER -out "$scratch" \
      2>/dev/null || rc=$?
    if (( rc == 0 )) && [[ -s "$scratch" ]]; then
      sha256sum "$scratch" | awk '{print tolower($1)}'
      rm -f -- "$scratch"
      return 0
    fi
  done
  rm -f -- "$scratch"
  echo "not a parseable X.509 certificate: $cert" >&2
  return 1
}

# The anchors a trust policy approves, as `<fingerprint> <path>` lines. Each
# anchor FILE must be pinned by SHA-256 inside the policy executable: an anchor
# directory the policy does not vouch for is not this policy's anchor set.
signing_trust_policy_anchors() { # $1=policy id  $2=trust-policy root
  if (( $# != 2 )); then
    echo "signing_trust_policy_anchors requires a policy id and a trust-policy root" >&2
    return 2
  fi
  local policy_id=$1 root=${2%/} script anchors count=0 anchor file_hash fingerprint
  [[ "$policy_id" =~ ^neural-ice-secureboot-[a-z0-9-]{1,32}$ ]] || {
    echo "'$policy_id' is not a valid signed-boot trust policy id" >&2
    return 1
  }
  script="$root/$policy_id"
  anchors="$root/$policy_id.d"
  [[ -f "$script" && ! -L "$script" ]] || {
    echo "no trust policy executable at $script" >&2
    return 1
  }
  [[ -d "$anchors" && ! -L "$anchors" ]] || {
    echo "trust policy '$policy_id' ships no anchor directory at $anchors" >&2
    return 1
  }
  shopt -s nullglob
  local candidates=("$anchors"/*.crt)
  shopt -u nullglob
  (( ${#candidates[@]} > 0 )) || {
    echo "trust policy '$policy_id' pins no anchor certificate" >&2
    return 1
  }
  for anchor in "${candidates[@]}"; do
    [[ -f "$anchor" && ! -L "$anchor" ]] || {
      echo "anchor is not a regular file: $anchor" >&2
      return 1
    }
    file_hash="$(sha256sum "$anchor" | awk '{print tolower($1)}')"
    # The policy executable carries the anchor hash as a pinned literal. Reusing
    # that pin means the anchor set has exactly one definition, and swapping the
    # directory for a lookalike is caught here rather than at a shim review.
    grep -qF -- "$file_hash" "$script" || {
      echo "anchor ${anchor##*/} is not pinned by trust policy '$policy_id'" >&2
      return 1
    }
    fingerprint="$(signing_trust_cert_fingerprint "$anchor")" || return 1
    printf '%s %s\n' "$fingerprint" "$anchor"
    count=$((count + 1))
  done
  (( count > 0 )) || return 1
}

# THE GATE. The certificate a medium is about to be signed with must resolve to
# an anchor the named policy approves. Prints `<policy id> <cert fingerprint>
# <anchor basename>` on success.
signing_trust_assert_cert() { # $1=policy id  $2=trust-policy root  $3=signing certificate
  if (( $# != 3 )); then
    echo "signing_trust_assert_cert requires a policy id, a trust-policy root and a certificate" >&2
    return 2
  fi
  local policy_id=$1 root=$2 cert=$3 anchors fingerprint openssl_bin
  openssl_bin="${NEURAL_ICE_SIGNING_TRUST_OPENSSL:-$(command -v openssl 2>/dev/null || true)}"
  [[ -n "$openssl_bin" ]] || { echo "openssl is required to bind a certificate to a trust policy" >&2; return 1; }
  fingerprint="$(signing_trust_cert_fingerprint "$cert")" || return 1
  anchors="$(signing_trust_policy_anchors "$policy_id" "$root")" || return 1

  local anchor_fp anchor_path
  while read -r anchor_fp anchor_path; do
    [[ -n "$anchor_fp" ]] || continue
    if [[ "$anchor_fp" == "$fingerprint" ]]; then
      printf '%s %s %s\n' "$policy_id" "$fingerprint" "${anchor_path##*/}"
      return 0
    fi
    # A leaf signed by the policy's CA is the ordinary case: the lab CA is the
    # anchor in db and the medium is signed by a certificate it issued.
    if "$openssl_bin" verify -CAfile "$anchor_path" -partial_chain "$cert" >/dev/null 2>&1; then
      printf '%s %s %s\n' "$policy_id" "$fingerprint" "${anchor_path##*/}"
      return 0
    fi
  done <<<"$anchors"

  echo "the signing certificate ($fingerprint) is neither an anchor of trust policy '$policy_id' nor issued by one" >&2
  return 1
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  command_name=${1:-}
  shift || true
  case "$command_name" in
    fingerprint) signing_trust_cert_fingerprint "$@" ;;
    anchors) signing_trust_policy_anchors "$@" ;;
    assert-cert) signing_trust_assert_cert "$@" ;;
    *)
      echo "usage: $0 {fingerprint CERT|anchors POLICY_ID ROOT|assert-cert POLICY_ID ROOT CERT}" >&2
      exit 2
      ;;
  esac
fi
