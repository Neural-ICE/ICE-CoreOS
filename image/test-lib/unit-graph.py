#!/usr/bin/env python3
"""Resolve a systemd unit dependency graph OFFLINE, honouring unit-directory
precedence, drop-in shadowing and masks.

Usage:
    unit-graph.py <unit> <dir>[:<dir>...]
    unit-graph.py --wants <unit> <dir>[:<dir>...]

``<dir>`` list is HIGHEST precedence first, exactly as systemd.unit(5) orders
them -- ``/run/systemd/generator.early`` before ``/etc/systemd/system`` before
``/usr/lib/systemd/system``.

Prints one line per unit reachable through the HARD edges (``Requires=``,
``Requisite=``, ``BindsTo=``) starting at ``<unit>``:

    <state> <unit>

where ``<state>`` is ``masked``, ``present`` or ``absent``. Exit 0 always; the
caller decides what an answer means.

``--wants`` prints the same ``<state> <unit>`` lines for the unit's own
EFFECTIVE ``Wants=`` set instead -- the merged value after drop-in collection and
shadowing. It exists because "would the transaction resolve" and "does anything
ask for the transaction" are two different questions, and asserting only the
first is how a registry-backed install shipped with a resolvable network path
that nothing ever requested (independent review 2026-09-02, P1 #1).

Why this exists
---------------
"NetworkManager is not masked" is not the question, and asserting it is how a
registry-backed install shipped with no reachable network path at all
(independent review 2026-09-02, P1 #3). The appliance image drops
``Requires=neural-ice-firstboot-tpm-ceremony.service`` into five network units,
and the installer's runtime generator masks that ceremony -- so a NetworkManager
START TRANSACTION failed on a masked required dependency while NetworkManager
itself was perfectly unmasked. Only a reader that follows the edges, through the
drop-ins, with the same precedence systemd uses, can see that.

What it models, and what it does not
------------------------------------
Modelled: unit-directory precedence; a unit masked by a symlink to /dev/null;
drop-in collection from every directory in the search path; drop-in SHADOWING by
filename (a ``50-x.conf`` in a higher-precedence ``<unit>.d`` replaces the lower
one entirely, which is exactly how the media generator neutralises the
appliance's ceremony drop-in); an empty assignment resetting a list.

Not modelled: templates and instance expansion, ``.wants``/``.requires``
directories, conditions, and ordering. The hard-requirement closure is the
property a failing start transaction is made of, and it is the one asserted.
"""

from __future__ import annotations

import sys
from pathlib import Path

HARD_EDGES = ("Requires", "Requisite", "BindsTo")
LIST_KEYS = HARD_EDGES + ("Wants", "After", "Before", "Conflicts")


def unit_file(name: str, search: list[Path]) -> tuple[str, Path | None]:
    for directory in search:
        candidate = directory / name
        if candidate.is_symlink():
            if candidate.readlink().as_posix() == "/dev/null":
                return "masked", candidate
            return "present", candidate
        if candidate.exists():
            return "present", candidate
    return "absent", None


def dropins(name: str, search: list[Path]) -> list[Path]:
    """Highest-precedence file wins per FILENAME, which is how a drop-in is
    shadowed. Returned in application order (lowest precedence first)."""
    chosen: dict[str, Path] = {}
    for directory in search:
        folder = directory / f"{name}.d"
        if not folder.is_dir():
            continue
        for conf in sorted(folder.glob("*.conf")):
            chosen.setdefault(conf.name, conf)
    return [chosen[key] for key in sorted(chosen)]


def parse(paths: list[Path]) -> dict[str, list[str]]:
    values: dict[str, list[str]] = {key: [] for key in LIST_KEYS}
    for path in paths:
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith(("#", ";", "[")):
                continue
            key, separator, value = line.partition("=")
            key = key.strip()
            if not separator or key not in LIST_KEYS:
                continue
            if not value.strip():
                values[key] = []  # an empty assignment resets the list
                continue
            values[key].extend(value.split())
    return values


def closure(root: str, search: list[Path]) -> dict[str, str]:
    seen: dict[str, str] = {}
    queue = [root]
    while queue:
        name = queue.pop()
        if name in seen:
            continue
        state, path = unit_file(name, search)
        seen[name] = state
        if state == "masked":
            # A masked unit contributes no edges of its own; it is the edge INTO
            # it that fails the transaction.
            continue
        sources = ([path] if path is not None else []) + dropins(name, search)
        values = parse(sources)
        for key in HARD_EDGES:
            queue.extend(values[key])
    return seen


def wants(root: str, search: list[Path]) -> dict[str, str]:
    """The unit's own effective ``Wants=`` set, each entry with its state."""
    state, path = unit_file(root, search)
    if state == "masked":
        return {}
    sources = ([path] if path is not None else []) + dropins(root, search)
    return {name: unit_file(name, search)[0] for name in parse(sources)["Wants"]}


def main(argv: list[str]) -> int:
    if len(argv) == 4 and argv[1] == "--wants":
        root = argv[2]
        search = [Path(part) for part in argv[3].split(":") if part]
        for name, state in sorted(wants(root, search).items()):
            print(f"{state} {name}")
        return 0
    if len(argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    root = argv[1]
    search = [Path(part) for part in argv[2].split(":") if part]
    for name, state in sorted(closure(root, search).items()):
        print(f"{state} {name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
