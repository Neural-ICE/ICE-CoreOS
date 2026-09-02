#!/usr/bin/env python3
"""Is a registry install of ``<repository>`` AUTHORISED by a container signature
policy read on stdin?

Usage:
    <policy.json on stdin>  neural-ice-registry-authorisation.py \\
        --repository <authority>/<path>  --authority <authority> \\
        [--index-digest sha256:<64hex>] [--manifest-digest sha256:<64hex>]

Exit 0 when the policy explicitly configures a signed ``docker`` scope that
covers ``--repository`` for ``--authority`` with a CLOSED, COMPLETE and
EXACT-BINDING signature requirement; exit 1 otherwise, saying which condition
failed; exit 2 on a usage error.

Why this exists
---------------
``neuralice.source=registry`` installs bytes that arrive over the network. The
digest pins WHICH bytes, and the mirror is only safe because of it -- but the
digest says nothing about who signed them. That is the signature policy's job,
and the medium runs a PERMISSIVE default so it can read its own local image
(image/Containerfile.installer). The signed ``docker`` scopes survive that
relaxation, and they are the whole of what verifies a registry pull.

ONE IMPLEMENTATION, TWO CALLERS
-------------------------------
🔴 WHAT THIS REPLACES (independent review 2026-09-02, P1 #2). There were TWO
readers with DIFFERENT semantics, and both were permissive:

* this file only rejected ``insecureAcceptAnything``, so an unknown or MISTYPED
  requirement type authorised the install -- ``{"type":"typoThatMustNotAuthorize"}``
  exited 0 under direct probe;
* ota/neural-ice-autoinstall.sh was weaker still: a nine-line inline reader that
  checked only that a matching scope EXISTED under the expected authority and
  never looked at the requirements at all.

So a medium the producer accepted could carry a scope that verified nothing, and
the installer would not notice. This file is now the single implementation and
the installer invokes it from the signed read-only /usr; there is no second
reader to disagree with.

THE CONDITIONS, ALL REQUIRED
----------------------------
1. SCOPE COVERAGE. Some configured ``docker`` scope covers the repository --
   exact, or a prefix on a path-segment boundary, so ``example.test/neural``
   never covers ``example.test/neural-ice/x``.
2. AUTHORITY. Every covering scope belongs to the authority the reference names,
   and that authority is CANONICAL: lowercase, no scheme, no userinfo, no path,
   no trailing dot, a bracketed IPv6 literal / dotted quad / ``localhost`` / a
   DNS name with at least two labels, optional port 1-65535. A scope written
   ``https://registry.example.test`` or ``Registry.Example.Test`` is refused
   rather than normalised: two readers of one medium must not disagree about its
   host.
3. NO WEAK SCOPE. A bare registry authority is not an authorisation -- it makes
   every repository that registry will ever serve equally installable. The
   docker-transport default scope ``""`` is not a cover at all. A covering scope
   must name at least ``<authority>/<one path segment>``.
4. CLOSED REQUIREMENT TYPES. Every requirement on every covering scope must be
   exactly one of ``signedBy`` or ``sigstoreSigned``, with every mandatory field
   present, no unknown field, and no unusable value. ``insecureAcceptAnything``
   is the absence of an authorisation spelled longer; ``reject`` cannot authorise
   anything; an unknown or mistyped type is refused BECAUSE it is unknown.
5. EXACT IDENTITY BINDING. ``signedIdentity`` must be present and of a type that
   binds the signature to this repository. ``remapIdentity`` is refused outright:
   it rewrites the name a signature is checked against, which is the one thing a
   signed identity may not do.
6. RECURSIVE OBJECT BINDING. containers/image's signed payload always binds
   ``critical.image.docker-manifest-digest``; ``signedIdentity`` binds the
   repository name. Under ``--require-object-binding``, ``matchRepository`` is
   accepted only when the caller also supplies the exact authenticated
   repository/index/manifest tuple from the verified authorization and closure.
   Repository policy alone is never promoted into an object authorization.

   BOTH CALLERS PASS IT, and that is the point. The producer passes it while
   cutting a registry medium, offline, with no child digest to hand; the
   installer passes it after the pull together with ``--index-digest`` and
   ``--manifest-digest``, the two digests it OBSERVED -- the index it asked for
   and the platform child the object resolved to. So a medium the producer
   accepts is one whose policy still authorises at install time, and a
   repository-bound policy is refused on the build host rather than on a bench
   with an already-wiped disk. The digests are required to be well-formed and
   distinct from each other's role; they are reported, so the install log carries
   the exact pair the policy was proved against.

What this file does NOT do
--------------------------
It verifies no signature and fetches nothing. containers/image performs the
cryptographic verification during the pull, under the very policy this file
proves is strong enough to be worth performing. Two different jobs, deliberately
not merged: this one has to be answerable on a build host, offline, before a
medium is cut.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys

# A policy is a small configuration file. Anything appreciably larger did not
# come from image/policy/render-container-policy.sh, and an unbounded read of an
# attacker-supplied file is a cost before it is a verdict.
MAX_POLICY_BYTES = 1024 * 1024

DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
PATH_SEGMENT = re.compile(r"[a-z0-9]+(?:[._-][a-z0-9]+)*")
DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
PORT = re.compile(r"[1-9][0-9]{0,4}")

# 🔴 THE CLOSED WORLD. containers-policy.json(5) defines exactly four requirement
# types; two of them authorise nothing and are named here so the refusal can say
# WHY rather than "unknown". Anything not in this table -- including a type
# invented after this file was written, and including a single mistyped
# character -- lands in the unknown branch.
AUTHORISING_TYPES = ("signedBy", "sigstoreSigned")
NON_AUTHORISING_TYPES = {
    "insecureAcceptAnything": (
        "it accepts any image at all; that is the absence of an authorisation, "
        "not one"
    ),
    "reject": "it refuses every image, so it can never authorise this install",
}

# Mandatory and optional fields per type, and the mutually exclusive key sources.
# An unknown field is refused: `keypath` for `keyPath`, or `signedidentity` for
# `signedIdentity`, would otherwise be silently ignored by this reader and leave
# the requirement looking complete.
REQUIREMENT_FIELDS = {
    "signedBy": {
        "required": {"type", "keyType"},
        "optional": {"keyPath", "keyPaths", "keyData", "signedIdentity"},
        "key_sources": ("keyPath", "keyPaths", "keyData"),
    },
    "sigstoreSigned": {
        "required": {"type"},
        "optional": {
            "keyPath",
            "keyPaths",
            "keyData",
            "fulcio",
            "rekorPublicKeyPath",
            "rekorPublicKeyPaths",
            "rekorPublicKeyData",
            "pkiRoots",
            "signedIdentity",
        },
        "key_sources": ("keyPath", "keyPaths", "keyData", "fulcio", "pkiRoots"),
    },
}

# GPGKeys is the only keyType containers/image defines for signedBy. Accepting
# anything else means accepting a requirement the runtime will not honour.
SIGNED_BY_KEY_TYPES = ("GPGKeys",)

# Identity types that bind the signature to this repository at all.
IDENTITY_TYPES_REPOSITORY = (
    "matchExact",
    "matchRepoDigestOrExact",
    "matchRepository",
    "exactReference",
    "exactRepository",
)
# ...and the subset that binds it to the exact OBJECT, which is what a
# digest-pinned recursive pull needs (condition 6).
IDENTITY_TYPES_EXACT_OBJECT = ("matchExact", "matchRepoDigestOrExact", "exactReference")
# Refused outright, in every mode: it rewrites the identity a signature is
# checked against.
IDENTITY_TYPE_REMAP = "remapIdentity"


class Refusal(Exception):
    """The policy cannot authorise this install. The message is the reason."""


def refuse(message: str) -> "Refusal":
    return Refusal(message)


def authority_is_canonical(authority: str) -> bool:
    """A full registry authority, spelled exactly one way.

    This is the Python counterpart of ni_sealed_authority_is_valid in
    image/installer/neural-ice-sealed-cmdline-grammar.sh and of the parser in
    ota/neural-ice-autoinstall.sh; image/test-installer-selector-grammar.sh
    proves the implementations agree on the shared corpus.
    """
    if not authority or authority != authority.strip() or authority != authority.lower():
        return False
    if "//" in authority or "@" in authority or "/" in authority:
        return False
    if authority.startswith("["):
        close = authority.find("]")
        if close < 0:
            return False
        literal, suffix = authority[1:close], authority[close + 1 :]
        try:
            address = ipaddress.IPv6Address(literal)
        except ValueError:
            return False
        if address.compressed != literal:
            return False
        if suffix and not suffix.startswith(":"):
            return False
        port = suffix[1:] if suffix else ""
    else:
        if authority.count(":") > 1:
            return False
        host, separator, port = authority.rpartition(":")
        if not separator:
            host, port = authority, ""
        if not host or host.endswith("."):
            return False
        if all(character in "0123456789." for character in host):
            try:
                if str(ipaddress.IPv4Address(host)) != host:
                    return False
            except ValueError:
                return False
        elif host != "localhost":
            labels = host.split(".")
            if len(labels) < 2 or len(host) > 253:
                return False
            if any(not DNS_LABEL.fullmatch(label) for label in labels):
                return False
        if separator and not port:
            return False
    if port and (not PORT.fullmatch(port) or int(port) > 65535):
        return False
    return True


def covering_scopes(docker: dict, repository: str) -> list[str]:
    """Every configured scope that covers the repository, on a path-segment
    boundary. The docker-transport default scope ``""`` is deliberately NOT a
    cover: an install that would only be authorised by the transport-wide
    fallback is an install nothing specific authorised."""
    return [
        scope
        for scope in docker
        if scope and (repository == scope or repository.startswith(scope + "/"))
    ]


def check_scope_shape(scope: str, authority: str) -> None:
    if scope != scope.strip() or not scope:
        raise refuse(f"the scope {scope!r} is empty or padded with whitespace")
    if "//" in scope or scope.endswith("/") or scope != scope.lower():
        raise refuse(
            f"the scope {scope!r} is not canonical (a scheme, a trailing slash or "
            "an uppercase byte); two readers of one medium must not disagree about "
            "its host"
        )
    scope_authority, separator, path = scope.partition("/")
    if not authority_is_canonical(scope_authority):
        raise refuse(
            f"the scope {scope!r} names a non-canonical registry authority "
            f"{scope_authority!r}"
        )
    if scope_authority != authority:
        raise refuse(
            f"the scope {scope!r} belongs to another registry authority "
            f"{scope_authority!r} (expected {authority!r})"
        )
    if not separator or not path:
        raise refuse(
            f"the scope {scope!r} is a bare registry authority; that authorises "
            "every repository that registry will ever serve, which is not an "
            "authorisation of this one"
        )
    if any(not PATH_SEGMENT.fullmatch(segment) for segment in path.split("/")):
        raise refuse(f"the scope {scope!r} carries a malformed repository path")


def check_identity(
    requirement: dict, scope: str, exact_object: bool, authenticated_binding: bool
) -> None:
    identity = requirement.get("signedIdentity")
    if identity is None:
        raise refuse(
            f"the scope {scope!r} states a requirement with no signedIdentity; the "
            "signature would not be bound to this repository"
        )
    if not isinstance(identity, dict):
        raise refuse(f"the scope {scope!r} carries a malformed signedIdentity")
    identity_type = identity.get("type")
    if not isinstance(identity_type, str) or not identity_type:
        raise refuse(f"the scope {scope!r} carries a signedIdentity with no type")
    if identity_type == IDENTITY_TYPE_REMAP:
        raise refuse(
            f"the scope {scope!r} uses signedIdentity {IDENTITY_TYPE_REMAP!r}, which "
            "rewrites the name a signature is checked against"
        )
    if identity_type not in IDENTITY_TYPES_REPOSITORY:
        raise refuse(
            f"the scope {scope!r} uses an unknown signedIdentity type "
            f"{identity_type!r}; the accepted set is {list(IDENTITY_TYPES_REPOSITORY)}"
        )
    if exact_object and identity_type not in IDENTITY_TYPES_EXACT_OBJECT and not (
        identity_type == "matchRepository" and authenticated_binding
    ):
        raise refuse(
            f"the scope {scope!r} uses signedIdentity {identity_type!r}, which is "
            "satisfied by any image in the repository. A digest-pinned recursive "
            "pull needs the signature bound to the OBJECT: one of "
            f"{list(IDENTITY_TYPES_EXACT_OBJECT)}"
        )


def check_requirement(
    requirement: object, scope: str, exact_object: bool, authenticated_binding: bool
) -> str:
    if not isinstance(requirement, dict):
        raise refuse(f"the scope {scope!r} carries a malformed requirement")
    if not requirement:
        raise refuse(f"the scope {scope!r} carries an empty requirement")
    requirement_type = requirement.get("type")
    if not isinstance(requirement_type, str) or not requirement_type:
        raise refuse(f"the scope {scope!r} carries a requirement with no type")
    if requirement_type in NON_AUTHORISING_TYPES:
        raise refuse(
            f"the scope {scope!r} is {requirement_type}: "
            f"{NON_AUTHORISING_TYPES[requirement_type]}"
        )
    if requirement_type not in REQUIREMENT_FIELDS:
        raise refuse(
            f"the scope {scope!r} states an unknown requirement type "
            f"{requirement_type!r}; the accepted set is {list(AUTHORISING_TYPES)}. An "
            "unknown type is refused because it is unknown: a mistyped one verifies "
            "nothing and must not read as an authorisation"
        )

    shape = REQUIREMENT_FIELDS[requirement_type]
    known = shape["required"] | shape["optional"]
    unknown = sorted(set(requirement) - known)
    if unknown:
        raise refuse(
            f"the scope {scope!r} states a {requirement_type} requirement with "
            f"unknown field(s) {unknown}; a mistyped field is silently ignored by "
            "the runtime and leaves the requirement looking complete"
        )
    missing = sorted(shape["required"] - set(requirement))
    if missing:
        raise refuse(
            f"the scope {scope!r} states a {requirement_type} requirement missing "
            f"{missing}"
        )
    sources = [name for name in shape["key_sources"] if name in requirement]
    if len(sources) != 1:
        raise refuse(
            f"the scope {scope!r} states a {requirement_type} requirement with "
            f"{len(sources)} key sources {sources}; exactly one of "
            f"{list(shape['key_sources'])} is required"
        )
    for name in sources:
        value = requirement[name]
        if isinstance(value, str) and not value.strip():
            raise refuse(f"the scope {scope!r} states an empty {name}")
        if isinstance(value, list) and not value:
            raise refuse(f"the scope {scope!r} states an empty {name}")
        if isinstance(value, dict) and not value:
            raise refuse(f"the scope {scope!r} states an empty {name}")
        if value is None:
            raise refuse(f"the scope {scope!r} states a null {name}")

    if requirement_type == "signedBy":
        key_type = requirement.get("keyType")
        if key_type not in SIGNED_BY_KEY_TYPES:
            raise refuse(
                f"the scope {scope!r} states signedBy keyType {key_type!r}; the only "
                f"type containers/image honours is {SIGNED_BY_KEY_TYPES[0]}"
            )
    if requirement_type == "sigstoreSigned" and "fulcio" in requirement:
        rekor = {"rekorPublicKeyPath", "rekorPublicKeyPaths", "rekorPublicKeyData"}
        if not rekor & set(requirement):
            raise refuse(
                f"the scope {scope!r} states keyless sigstoreSigned (fulcio) with no "
                "rekor public key; a keyless identity with no transparency log is "
                "not an authorisation"
            )

    check_identity(requirement, scope, exact_object, authenticated_binding)
    return requirement_type


def authorise(
    policy: object,
    repository: str,
    authority: str,
    exact_object: bool,
    authenticated_binding: bool,
) -> list[str]:
    """Returns the requirement types that authorise the install, or raises."""
    if not isinstance(policy, dict):
        raise refuse("the container signature policy is not a JSON object")
    transports = policy.get("transports")
    if not isinstance(transports, dict):
        raise refuse("the policy configures no transports at all")
    docker = transports.get("docker")
    if not isinstance(docker, dict) or not docker:
        raise refuse("the policy configures no docker transport scopes at all")
    if any(not isinstance(scope, str) for scope in docker):
        raise refuse("the policy carries a non-string docker scope")

    matches = covering_scopes(docker, repository)
    if not matches:
        raise refuse(
            f"no configured docker scope covers {repository}. The docker-transport "
            'default scope "" is not a cover: an install only the transport-wide '
            "fallback would authorise is an install nothing specific authorised"
        )

    # EVERY covering scope is checked, not only the most specific one. The most
    # specific wins at runtime, so a strict narrow scope beside a permissive
    # broad one is safe TODAY -- and one repository rename away from not being.
    # A medium is cut once and installs for years; refusing the pair is cheap.
    found: list[str] = []
    for scope in sorted(matches):
        check_scope_shape(scope, authority)
        requirements = docker[scope]
        if not isinstance(requirements, list) or not requirements:
            raise refuse(f"the scope {scope!r} states no signature requirement")
        for requirement in requirements:
            found.append(
                check_requirement(requirement, scope, exact_object, authenticated_binding)
            )
    return found


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Prove a container signature policy authorises a registry install.",
        allow_abbrev=False,
    )
    parser.add_argument("--repository", required=True)
    parser.add_argument("--authority", required=True)
    parser.add_argument("--require-object-binding", action="store_true")
    parser.add_argument("--index-digest")
    parser.add_argument("--manifest-digest")
    parser.add_argument("--authenticated-repository")
    parser.add_argument("--authenticated-index-digest")
    parser.add_argument("--authenticated-manifest-digest")
    arguments = parser.parse_args(argv[1:])

    repository, authority = arguments.repository, arguments.authority
    if "/" not in repository or repository.split("/", 1)[0] != authority:
        print(
            f"--repository {repository!r} is not rooted in --authority {authority!r}",
            file=sys.stderr,
        )
        return 2
    if not authority_is_canonical(authority):
        print(
            f"--authority {authority!r} is not a canonical full registry authority",
            file=sys.stderr,
        )
        return 2

    # 🔴 CONDITION 6 IS ALL-OR-NOTHING. Supplying one digest and not the other
    # would silently downgrade the recursive check to the repository-level one,
    # which is exactly the difference this argument exists to make. Supplying a
    # digest at all implies the object binding: a caller that observed a pair and
    # then asked the repository-level question would be asking the weaker one
    # while holding the evidence for the stronger.
    digests = [arguments.index_digest, arguments.manifest_digest]
    exact_object = arguments.require_object_binding or any(d is not None for d in digests)
    if any(digest is not None for digest in digests):
        if not all(digest is not None for digest in digests):
            print(
                "--index-digest and --manifest-digest are supplied together or not at "
                "all: a recursive proof needs both the index and its platform child",
                file=sys.stderr,
            )
            return 2
        for digest in digests:
            if not DIGEST.fullmatch(digest):
                print(f"{digest!r} is not a sha256:<64 lowercase hex> digest", file=sys.stderr)
                return 2

    authenticated = [
        arguments.authenticated_repository,
        arguments.authenticated_index_digest,
        arguments.authenticated_manifest_digest,
    ]
    if any(value is not None for value in authenticated) and not all(
        value is not None for value in authenticated
    ):
        print("the authenticated repository/index/manifest tuple is all-or-nothing", file=sys.stderr)
        return 2
    authenticated_binding = all(value is not None for value in authenticated)
    if authenticated_binding:
        if (
            arguments.authenticated_repository != repository
            or arguments.authenticated_index_digest != arguments.index_digest
            or arguments.authenticated_manifest_digest != arguments.manifest_digest
        ):
            print(
                "the observed repository/index/manifest tuple differs from the authenticated closure tuple",
                file=sys.stderr,
            )
            return 1
        if not all(
            DIGEST.fullmatch(value)
            for value in (
                arguments.authenticated_index_digest,
                arguments.authenticated_manifest_digest,
            )
        ):
            print("the authenticated closure tuple carries a malformed digest", file=sys.stderr)
            return 2

    raw = sys.stdin.buffer.read(MAX_POLICY_BYTES + 1)
    if len(raw) > MAX_POLICY_BYTES:
        print("the container signature policy exceeds the byte limit", file=sys.stderr)
        return 1
    try:
        policy = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        print(f"the container signature policy is not readable JSON: {error}", file=sys.stderr)
        return 1

    try:
        found = authorise(
            policy, repository, authority, exact_object, authenticated_binding
        )
    except Refusal as refusal:
        print(str(refusal), file=sys.stderr)
        return 1

    scope_word = "object-bound" if exact_object else "repository-bound"
    observed = ""
    if arguments.index_digest is not None:
        observed = f" index={arguments.index_digest} manifest={arguments.manifest_digest}"
    print(f"authorised: {repository} by {sorted(set(found))} ({scope_word}){observed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
