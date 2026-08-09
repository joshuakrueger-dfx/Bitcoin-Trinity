#!/usr/bin/env python3
"""Measures the dependency count on the signature path and checks the ceiling.

Implements SPECIFICATION.md §1.7: "Every dependency on the signature path is an
attack vector on other people's money." The ceiling is intentionally tight —
it should force a deliberate decision on every expansion, not be convenient.

Only `-e normal` is counted (no dev or build deps) and only external crates;
the project's own `trinity-*` crates do not count.

    python3 scripts/dep_budget.py           # check
    python3 scripts/dep_budget.py --list    # print list
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys

# Crates that see key material or secure the signature.
SIGNATURE_PATH = [
    "trinity-types",
    "trinity-entropy",
    "trinity-keystore",
    "trinity-signer",
    "trinity-verify",
]

# Measured on 2026-08-09 with the pinning from SPECIFICATION.md §0.3 and
# `cargo tree -e normal` over the signature path: 40 external crates.
# A deviation from MEASURED is a deliberate decision, not a side effect —
# MEASURED and the documents must then be updated together.
MEASURED = 40  # as of 2026-08-09
# The gate sits just above so a real expansion stands out instead of
# slipping through. Raise only with justification in the PR.
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
        print(f"\nUnion, external ({len(external)}):")
        for name in external:
            print(f"  {name}")
        return 0

    n = len(external)
    print(f"Signature path: {n} external crates (MEASURED {MEASURED}, budget {BUDGET})")
    for crate in SIGNATURE_PATH:
        print(f"  {crate:22s} {per_crate[crate]:3d}")

    findings = []
    if n != MEASURED:
        findings.append(
            f"Measurement {n} differs from MEASURED={MEASURED} — "
            f"deliberate change? Update MEASURED and documents together."
        )
    if n > BUDGET:
        over = sorted(external)[BUDGET:]
        findings.append(
            f"Budget exceeded by {n - BUDGET}. "
            f"Either remove a dependency or raise BUDGET with justification in the PR. "
            f"Current list past budget: {', '.join(over)}"
        )

    if findings:
        print(f"\ndep-budget: {len(findings)} finding(s)\n")
        for f in findings:
            print(f"  ✗ {f}")
        return 1

    print(f"\n✓ Measurement = MEASURED ({MEASURED}). {BUDGET - n} slots free until budget.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
