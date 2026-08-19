#!/usr/bin/env python3
"""Measures the dependency count on the signature path and checks the ceiling.

Implements SPECIFICATION.md §1.7: "Every dependency on the signature path is an
attack vector on other people's money." The ceiling is intentionally tight —
it should force a deliberate decision on every expansion, not be convenient.

Only `-e normal` is counted (no dev or build deps) and only external crates;
the project's own workspace packages (discovered from `crates/*/Cargo.toml`)
do not count — not merely the five signature-path names.

Measurement is **target-deterministic**: the union of external crates is taken
over the signature-path packages and the two declared shipped mobile targets
(`aarch64-apple-ios`, `aarch64-linux-android`). Host triple must not affect
the result (`cargo tree --target …` resolves target-specific deps without
installing those compilation targets).

    python3 scripts/dep_budget.py           # check
    python3 scripts/dep_budget.py --list    # print list
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
CRATES_DIR = ROOT / "crates"

# Crates that see key material or secure the signature.
SIGNATURE_PATH = [
    "trinity-types",
    "trinity-entropy",
    "trinity-keystore",
    "trinity-signer",
    "trinity-verify",
]

# Declared shipped mobile targets (SPECIFICATION.md / product platforms).
# The gate measures the union across both — never the developer host triple.
SHIPPED_TARGETS = (
    "aarch64-apple-ios",
    "aarch64-linux-android",
)

# Measured on 2026-08-09 with the pinning from SPECIFICATION.md §0.3 and
# `cargo tree -e normal --target <shipped>` over the signature path: 40
# external crates (union of both shipped targets). Host triples differ
# (e.g. x86_64-unknown-linux-gnu pulls cpufeatures and measures 41) and
# must not be used for this gate.
# A deviation from MEASURED is a deliberate decision, not a side effect —
# MEASURED and the documents must then be updated together.
MEASURED = 52  # as of 2026-08-18; +1 bitcoinconsensus on trinity-signer default (WP-36 / O7)
# The gate sits just above so a real expansion stands out instead of
# slipping through. Raise only with justification in the PR.
BUDGET = 55

TREE_LINE = re.compile(r"^([a-zA-Z0-9_-]+) v")
PKG_NAME_LINE = re.compile(r'^name\s*=\s*"([^"]+)"\s*$')

Runner = Callable[..., Any]


def package_name_from_manifest(text: str) -> str | None:
    """Read the `[package] name` from a Cargo.toml body (stdlib only)."""
    in_package = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped == "[package]":
            in_package = True
            continue
        if in_package:
            if stripped.startswith("["):
                break
            m = PKG_NAME_LINE.match(stripped)
            if m:
                return m.group(1)
    return None


def workspace_package_names(crates_dir: Path = CRATES_DIR) -> frozenset[str]:
    """Discover workspace package names from `crates/*/Cargo.toml` manifests.

    Fail-closed: a missing `crates/` directory, no manifests, unreadable
    manifests, or a Cargo.toml without a readable `[package] name` raise
    rather than silently returning an incomplete own-package set.
    """
    if not crates_dir.is_dir():
        raise FileNotFoundError(
            f"crates directory missing or not a directory: {crates_dir}"
        )
    manifests = sorted(crates_dir.glob("*/Cargo.toml"))
    if not manifests:
        raise FileNotFoundError(
            f"no crates/*/Cargo.toml manifests under {crates_dir}"
        )
    names: set[str] = set()
    for manifest in manifests:
        try:
            text = manifest.read_text(encoding="utf-8")
        except OSError as e:
            raise RuntimeError(f"unreadable manifest {manifest}: {e}") from e
        name = package_name_from_manifest(text)
        if not name:
            raise RuntimeError(
                f"{manifest}: missing readable [package] name"
            )
        names.add(name)
    return frozenset(names)


def cargo_tree_command(crate: str, target: str) -> list[str]:
    """Build the exact `cargo tree` argv for one crate on one target.

    `--target` is always present so the measurement cannot silently fall back
    to the host triple.
    """
    if not target:
        raise ValueError("target must be non-empty; host measurement is forbidden")
    return [
        "cargo",
        "tree",
        "-p",
        crate,
        "--prefix",
        "none",
        "-e",
        "normal",
        "--no-dedupe",
        "--target",
        target,
    ]


def parse_cargo_tree(stdout: str) -> set[str]:
    """Parse crate names from `cargo tree --prefix none` output."""
    names: set[str] = set()
    for line in stdout.splitlines():
        m = TREE_LINE.match(line.strip())
        if m:
            names.add(m.group(1))
    return names


def default_runner(cmd: Sequence[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, capture_output=True, text=True, check=True, **kwargs)


def deps_of(
    crate: str,
    target: str,
    runner: Runner = default_runner,
) -> set[str]:
    """External+workspace crate names for one package on one target."""
    cmd = cargo_tree_command(crate, target)
    out = runner(cmd)
    stdout = out.stdout if hasattr(out, "stdout") else out
    return parse_cargo_tree(stdout)


def measure_signature_path(
    targets: Sequence[str] = SHIPPED_TARGETS,
    crates: Sequence[str] = SIGNATURE_PATH,
    runner: Runner = default_runner,
    own_packages: frozenset[str] | set[str] | None = None,
) -> tuple[list[str], dict[str, dict[str, int]]]:
    """Union of external crates across packages and shipped targets.

    Project-owned packages (workspace members from `crates/*/Cargo.toml`, or
    an explicit `own_packages` override for tests) are excluded from the
    external count. Returns (sorted external names,
    per_crate[crate][target] = external count).
    """
    if not targets:
        raise ValueError("at least one target is required")
    if own_packages is None:
        own = set(workspace_package_names())
    else:
        own = set(own_packages)
    # Signature-path crates always count as own even if discovery is empty.
    own |= set(crates)
    union: set[str] = set()
    per_crate: dict[str, dict[str, int]] = {c: {} for c in crates}
    for target in targets:
        for crate in crates:
            names = deps_of(crate, target, runner=runner)
            external = names - own
            per_crate[crate][target] = len(external)
            union |= names
    external_sorted = sorted(union - own)
    return external_sorted, per_crate


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args()

    external, per_crate = measure_signature_path()

    if args.list:
        for crate in SIGNATURE_PATH:
            parts = "  ".join(
                f"{target.split('-')[-1]}={per_crate[crate][target]:3d}"
                for target in SHIPPED_TARGETS
            )
            print(f"  {crate:22s} {parts}")
        print(f"\nUnion, external ({len(external)}):")
        for name in external:
            print(f"  {name}")
        return 0

    n = len(external)
    print(
        f"Signature path: {n} external crates "
        f"(MEASURED {MEASURED}, budget {BUDGET}; "
        f"union of {', '.join(SHIPPED_TARGETS)})"
    )
    for crate in SIGNATURE_PATH:
        parts = "  ".join(
            f"{t}: {per_crate[crate][t]:3d}" for t in SHIPPED_TARGETS
        )
        print(f"  {crate:22s} {parts}")

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
