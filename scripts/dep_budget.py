#!/usr/bin/env python3
"""Misst die Abhängigkeitszahl im Signaturpfad und prüft sie gegen die Obergrenze.

Umsetzung von SPECIFICATION.md §1.7: "Jede Abhängigkeit im Signaturpfad ist ein
Angriffsvektor auf fremdes Geld." Die Grenze ist bewusst eng — sie soll bei jeder
Erweiterung eine bewusste Entscheidung erzwingen, nicht bequem sein.

Gezählt werden ausschließlich `-e normal` (keine Dev- und Build-Deps) und nur
externe Crates; die eigenen `trinity-*` zählen nicht mit.

    python3 scripts/dep_budget.py           # prüfen
    python3 scripts/dep_budget.py --list    # Liste ausgeben
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys

# Crates, die Schlüsselmaterial sehen oder die Signatur absichern.
SIGNATURE_PATH = [
    "trinity-types",
    "trinity-entropy",
    "trinity-keystore",
    "trinity-signer",
    "trinity-verify",
]

# Gemessen am 2026-08-08 mit dem Pinning aus SPECIFICATION.md §0.3: 41 externe Crates.
# Das Gate liegt knapp darüber, damit eine echte Erweiterung auffällt statt
# durchzurutschen. Anheben nur mit Begründung im PR.
BUDGET = 45


def deps_of(crate: str) -> set[str]:
    out = subprocess.run(
        ["cargo", "tree", "-p", crate, "--prefix", "none", "-e", "normal", "--no-dedupe"],
        capture_output=True, text=True, check=True,
    ).stdout
    names = set()
    for line in out.splitlines():
        m = re.match(r"^([a-zA-Z0-9_-]+) v", line.strip())
        if m:
            names.add(m.group(1))
    return names


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args()

    union: set[str] = set()
    per_crate: dict[str, int] = {}
    for crate in SIGNATURE_PATH:
        d = deps_of(crate)
        per_crate[crate] = len(d - set(SIGNATURE_PATH))
        union |= d
    external = sorted(union - set(SIGNATURE_PATH))

    if args.list:
        for crate in SIGNATURE_PATH:
            print(f"  {crate:22s} {per_crate[crate]:3d}")
        print(f"\nVereinigung, extern ({len(external)}):")
        for name in external:
            print(f"  {name}")
        return 0

    print(f"Signaturpfad: {len(external)} externe Crates (Grenze {BUDGET})")
    for crate in SIGNATURE_PATH:
        print(f"  {crate:22s} {per_crate[crate]:3d}")

    if len(external) > BUDGET:
        over = sorted(external)[BUDGET:]
        print(f"\n✗ Grenze überschritten um {len(external) - BUDGET}.")
        print("  Entweder Abhängigkeit entfernen oder BUDGET mit Begründung im PR anheben.")
        print(f"  Aktuelle Liste: {', '.join(over)}")
        return 1

    print(f"\n✓ {BUDGET - len(external)} Plätze Luft.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
