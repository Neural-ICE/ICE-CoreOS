#!/usr/bin/env bash
# Render the container-image signature policy — the GENERIC mechanism.
#
# WHAT THIS IS
#
#   containers/image (podman, skopeo, and bootc through ostree-ext) decides
#   whether an image may be transferred by consulting containers-policy.json.
#   This OS ships that file with a default of `reject`: with no exception
#   configured, NO image can be pulled. That is the fail-closed state, and it is
#   also the honest one for a community build — an OS that accepts anything is
#   not "unconfigured", it is configured to trust everybody.
#
#   The exception — WHICH repository is trusted, and under WHICH public key — is
#   deployment identity. It never lives in this repository (FAB-0032: ICE-CoreOS
#   stays vanilla; a community build must produce a generic OS). It is supplied
#   by the composer, at composition, through this script.
#
# WHY A RENDERER AND NOT "the composer writes the file"
#
#   A composer that writes containers-policy.json itself can, by accident or by
#   convenience, write a permissive default. The guarantee would then live in the
#   composer's diligence. Here the OS owns the guarantee: this script cannot emit
#   a default other than `reject`, cannot emit `insecureAcceptAnything` anywhere,
#   and refuses to emit anything at all when the trusted key is missing, empty or
#   unparseable. The composer supplies values; it does not supply the posture.
#
#   Same shape as the two injection points that already exist in this tree:
#   /etc/neural-ice/ota.conf (fetch-side values commented out in the vanilla
#   image, written by the composer) and NI_TRUSTED_TIME_ISSUER (a build ARG the
#   Containerfile refuses to build without).
#
# USAGE (from a composer's Containerfile, deriving FROM this OS image)
#
#   RUN /usr/libexec/neural-ice-render-container-policy \
#         --signed-scope registry.example.org/org=/etc/containers/keys/img.pub
#
# WHY IT ALSO WRITES registries.d
#
#   MEASURED, 2026-08-06, skopeo 1.21.0-dev: a correctly signed image is
#   REJECTED — "A signature was required, but no signature exists" — unless the
#   scope carries `use-sigstore-attachments: true` in registries.d. Without it,
#   containers/image never looks at the cosign `sha256-<digest>.sig` attachment.
#   Emitting the policy without the lookaside setting would ship a policy that
#   refuses everything including the legitimate image; the two files are one
#   mechanism, so one command writes both.
#
# WHY signedIdentity DEFAULTS TO matchRepository
#
#   MEASURED, 2026-08-06, cosign 2.6.3 + skopeo 1.21.0-dev, against a local
#   registry: cosign sets the simple-signing identity to the BARE repository
#   ("127.0.0.1:15000/ni/app" — no tag, no digest). Consequently
#   `matchRepoDigestOrExact` (the containers/image default) and `matchExact`
#   reject a correctly signed image, by tag AND by digest:
#       Source image rejected: Signature for identity
#       "127.0.0.1:15000/ni/app" is not accepted
#   `matchRepository` is therefore not a relaxation chosen to make a gate pass —
#   the stricter values do not accept cosign signatures at all, they accept
#   nothing. The residual property given up is that a signature made for one tag
#   of a repository also validates another tag of the SAME repository; which
#   exact digest may be deployed is decided upstream by the signed BOM
#   (ni-ota-verify), not here. A composer whose signer writes full references can
#   pass --signed-identity matchRepoDigestOrExact and get the stricter check.
set -euo pipefail

PROG="$(basename "$0")"

POLICY_OUT=/etc/containers/policy.json
REGISTRIES_D_OUT=/etc/containers/registries.d/50-neural-ice-sigstore.yaml
SIGNED_IDENTITY=matchRepository
SCOPES=()
KEYS=()

die() { echo "$PROG: $*" >&2; exit 2; }

usage() {
  cat >&2 <<'EOF'
usage: neural-ice-render-container-policy [OPTIONS]

  --signed-scope SCOPE=KEYPATH  trust SCOPE when signed by the sigstore public
                                key at KEYPATH. Repeatable. Omit entirely to
                                render the vanilla policy, which trusts nothing.
  --signed-identity TYPE        matchRepository (default) | matchRepoDigestOrExact
                                | matchExact
  --policy-out PATH             default /etc/containers/policy.json; '-' = stdout
  --registries-d-out PATH       default
                                /etc/containers/registries.d/50-neural-ice-sigstore.yaml;
                                '-' = stdout; empty = do not write it

The default policy is always `reject` and is not parameterizable.
EOF
  exit 2
}

while [ $# -gt 0 ]; do
  case "$1" in
    --signed-scope)
      [ $# -ge 2 ] || die "--signed-scope needs an argument"
      case "$2" in *=*) ;; *) die "--signed-scope expects SCOPE=KEYPATH, got '$2'" ;; esac
      SCOPES+=("${2%%=*}")
      KEYS+=("${2#*=}")
      shift 2
      ;;
    --signed-identity)
      [ $# -ge 2 ] || die "--signed-identity needs an argument"
      SIGNED_IDENTITY="$2"; shift 2
      ;;
    --policy-out)
      [ $# -ge 2 ] || die "--policy-out needs an argument"
      POLICY_OUT="$2"; shift 2
      ;;
    --registries-d-out)
      [ $# -ge 2 ] || die "--registries-d-out needs an argument"
      REGISTRIES_D_OUT="$2"; shift 2
      ;;
    -h|--help) usage ;;
    # An unknown option is never ignored: silently dropping "--signed-scope=x"
    # (the = form, which this parser does not take) would render the vanilla
    # policy and the composer would ship an OS that trusts nobody without
    # noticing until the appliance refuses its own images.
    *) die "unknown option '$1'" ;;
  esac
done

case "$SIGNED_IDENTITY" in
  matchRepository|matchRepoDigestOrExact|matchExact) ;;
  *) die "unsupported --signed-identity '$SIGNED_IDENTITY'" ;;
esac

# Validation is deliberately strict, for two independent reasons.
#
#  1) FAIL-CLOSED AT COMPOSITION RATHER THAN AT RUNTIME. An absent, empty or
#     unparseable key does fail closed at runtime — measured: "open …: no such
#     file or directory", "parsing public key 1: PEM decoding failed" — but it
#     fails on the appliance, in the field, on the first pull. Refusing here
#     turns a field outage into a build failure.
#  2) The generated JSON/YAML is assembled by string concatenation. Restricting
#     scopes and paths to a character set that cannot carry a quote, a backslash
#     or a control character is what makes that assembly sound.
i=0
while [ "$i" -lt "${#SCOPES[@]}" ]; do
  scope="${SCOPES[$i]}"
  key="${KEYS[$i]}"

  [ -n "$scope" ] || die "empty scope"
  # A wildcard scope is refused: registries.d does not accept one, so the pair
  # would silently disagree — the policy would match and the attachment lookup
  # would not, and every signed image would be rejected as unsigned.
  case "$scope" in
    *'*'*) die "wildcard scope '$scope' is not supported" ;;
    /*|*/) die "scope '$scope' must not start or end with '/'" ;;
  esac
  printf '%s' "$scope" | grep -Eq '^[A-Za-z0-9._:/-]+$' \
    || die "scope '$scope' contains characters outside [A-Za-z0-9._:/-]"

  [ -n "$key" ] || die "empty key path for scope '$scope'"
  case "$key" in /*) ;; *) die "key path '$key' must be absolute" ;; esac
  printf '%s' "$key" | grep -Eq '^[A-Za-z0-9._/-]+$' \
    || die "key path '$key' contains characters outside [A-Za-z0-9._/-]"
  [ -f "$key" ] || die "key file '$key' does not exist"
  [ -s "$key" ] || die "key file '$key' is empty"
  grep -q -- '-----BEGIN PUBLIC KEY-----' "$key" \
    || die "key file '$key' is not a PEM public key"

  i=$((i + 1))
done

# ---------------------------------------------------------------------------- #
# Render. Everything is built in memory first: a partial write would leave the
# system with a truncated policy, and a truncated policy is an ERROR for
# containers/image ("invalid policy in …: unexpected end of JSON input"), not a
# permissive one — but it would still be an outage produced by this script.
# ---------------------------------------------------------------------------- #
policy="{
    \"default\": [
        {
            \"type\": \"reject\"
        }
    ],
    \"transports\": {
        \"docker\": {"

i=0
while [ "$i" -lt "${#SCOPES[@]}" ]; do
  [ "$i" -eq 0 ] || policy+=","
  policy+="
            \"${SCOPES[$i]}\": [
                {
                    \"type\": \"sigstoreSigned\",
                    \"keyPath\": \"${KEYS[$i]}\",
                    \"signedIdentity\": {
                        \"type\": \"$SIGNED_IDENTITY\"
                    }
                }
            ]"
  i=$((i + 1))
done

[ "${#SCOPES[@]}" -eq 0 ] || policy+="
        "
policy+="}
    }
}"

regd="docker:"
if [ "${#SCOPES[@]}" -eq 0 ]; then
  regd+=" {}"
else
  i=0
  while [ "$i" -lt "${#SCOPES[@]}" ]; do
    regd+="
  ${SCOPES[$i]}:
    use-sigstore-attachments: true"
    i=$((i + 1))
  done
fi

emit() { # emit <destination> <content>
  if [ "$1" = "-" ]; then
    printf '%s\n' "$2"
    return
  fi
  install -d -m 0755 "$(dirname "$1")"
  tmp="$1.tmp.$$"
  printf '%s\n' "$2" > "$tmp"
  chmod 0644 "$tmp"
  mv -f "$tmp" "$1"
}

emit "$POLICY_OUT" "$policy"
[ -z "$REGISTRIES_D_OUT" ] || emit "$REGISTRIES_D_OUT" "$regd"
