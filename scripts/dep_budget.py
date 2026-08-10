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

# Gemessen am 2026-08-09 mit dem Pinning aus SPECIFICATION.md §0.3 und
# `cargo tree -e normal` über den Signaturpfad: 40 externe Crates.
# Eine Abweichung von MEASURED ist eine bewusste Entscheidung, keine Nebenwirkung —
# MEASURED und die Dokumente sind dann gemeinsam nachzuziehen.
MEASURED = 40  # Stand 2026-08-09
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

    n = len(external)
    print(f"Signaturpfad: {n} externe Crates (MEASURED {MEASURED}, Grenze {BUDGET})")
    for crate in SIGNATURE_PATH:
        print(f"  {crate:22s} {per_crate[crate]:3d}")

    findings = []
    if n != MEASURED:
        findings.append(
            f"Messung {n} weicht von MEASURED={MEASURED} ab — "
            f"bewusste Änderung? MEASURED und Dokumente gemeinsam nachziehen."
        )
    if n > BUDGET:
        over = sorted(external)[BUDGET:]
        findings.append(
            f"Grenze überschritten um {n - BUDGET}. "
            f"Entweder Abhängigkeit entfernen oder BUDGET mit Begründung im PR anheben. "
            f"Aktuelle Liste ab Budget: {', '.join(over)}"
        )

    if findings:
        print(f"\ndep-budget: {len(findings)} Befund(e)\n")
        for f in findings:
            print(f"  ✗ {f}")
        return 1

    print(f"\n✓ Messung = MEASURED ({MEASURED}). {BUDGET - n} Plätze Luft bis Budget.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
