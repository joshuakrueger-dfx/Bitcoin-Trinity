#!/usr/bin/env python3
"""Checks per-crate coverage against the thresholds in docs/TESTING.md §3.2.

    cargo llvm-cov --workspace --lcov --output-path lcov.info
    python3 scripts/coverage_gate.py lcov.info

Exceptions live in coverage-exclusions.toml and each needs BOTH a reason and a
named substitute test — an entry without both fails the build.

Fail-closed rule: missing line or branch data for a crate that has source code
is a finding — never a silent 100 %.

Important framing also stated in TESTING.md §3.1: coverage measures execution,
not checking. A test that runs a line without asserting its result still counts
fully here. The real gate for the security cores is therefore `cargo mutants` —
100 % coverage with a surviving mutant is red.
"""

from __future__ import annotations

import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXCLUSIONS = ROOT / "coverage-exclusions.toml"
CRATES_DIR = ROOT / "crates"

# (lines, branches) in percent. Source: docs/TESTING.md §3.2
THRESHOLDS: dict[str, tuple[float, float]] = {
    "trinity-types":     (100.0, 100.0),
    "trinity-entropy":   (100.0, 100.0),
    "trinity-keystore":  (100.0, 100.0),
    "trinity-signer":    (100.0, 100.0),
    "trinity-verify":    (100.0, 100.0),   # no exception allowed here
    "trinity-watch":     (95.0,  90.0),
    "trinity-chain":     (90.0,  85.0),
    "trinity-transport": (90.0,  85.0),
    "trinity-export":    (100.0, 95.0),
    "trinity-ffi":       (95.0,  90.0),
}

# This crate must not appear in coverage-exclusions.toml.
NO_EXCLUSIONS = {"trinity-verify"}


def parse_lcov(path: Path) -> dict[str, dict[str, int]]:
    """Aggregate LCOV per crate: LF/LH (lines), BRF/BRH (branches)."""
    stats: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    crate = None
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("SF:"):
            m = re.search(r"crates/([a-z0-9-]+)/", line)
            crate = m.group(1) if m else None
        elif crate and re.fullmatch(r"(LF|LH|BRF|BRH):(\d+)", line):
            m = re.fullmatch(r"(LF|LH|BRF|BRH):(\d+)", line)
            assert m
            stats[crate][m.group(1)] += int(m.group(2))
    return stats


def parse_exclusions() -> tuple[dict[str, int], list[str]]:
    """Count exceptions and check completeness."""
    if not EXCLUSIONS.exists():
        return {}, []
    text = EXCLUSIONS.read_text(encoding="utf-8")
    per_crate: dict[str, int] = defaultdict(int)
    problems: list[str] = []
    blocks = re.split(r"^\[\[exclusion\]\]", text, flags=re.M)[1:]
    for i, block in enumerate(blocks, 1):
        path = re.search(r'path\s*=\s*"([^"]+)"', block)
        reason = re.search(r'reason\s*=\s*"([^"]*)"', block)
        test = re.search(r'test\s*=\s*"([^"]*)"', block)
        if not path:
            problems.append(f"exception #{i}: no 'path'")
            continue
        if not reason or not reason.group(1).strip():
            problems.append(f"exception for {path.group(1)}: no reason ('reason')")
        if not test or not test.group(1).strip():
            problems.append(f"exception for {path.group(1)}: no substitute test ('test')")
        m = re.search(r"crates/([a-z0-9-]+)/", path.group(1))
        if m:
            per_crate[m.group(1)] += 1
            if m.group(1) in NO_EXCLUSIONS:
                problems.append(
                    f"{m.group(1)} allows no exception — {path.group(1)} must be fully "
                    f"covered (TESTING.md §3.2)"
                )
    return dict(per_crate), problems


def crate_has_source(crate: str) -> bool:
    """True if the crate has more than a pure scaffold lib.rs.

    A single lib.rs that only holds module docs and attributes (no fn/struct/
    enum/impl/mod/use beyond allowed attributes) counts as a scaffold without
    domain code. As soon as additional .rs files exist or lib.rs carries real
    code, the crate is considered to "have source".
    """
    root = CRATES_DIR / crate / "src"
    if not root.exists():
        return False
    rs_files = list(root.rglob("*.rs"))
    if not rs_files:
        return False
    if len(rs_files) > 1:
        return True
    # One file: check whether it is more than a scaffold
    text = rs_files[0].read_text(encoding="utf-8")
    # Real code: fn, struct, enum, impl, trait, macro_rules, mod X;
    if re.search(r"^\s*(pub\s+)?(fn|struct|enum|impl|trait|macro_rules|mod)\b", text, re.M):
        return True
    if re.search(r"^\s*use\s+", text, re.M):
        return True
    return False


def pct(hit: int, total: int) -> float | None:
    """Percent or None when total == 0 (missing data)."""
    if total == 0:
        return None
    return 100.0 * hit / total


def main() -> int:
    if len(sys.argv) != 2:
        sys.exit("Usage: coverage_gate.py <lcov.info>")
    lcov = Path(sys.argv[1])
    if not lcov.exists():
        sys.exit(f"ERROR: {lcov} missing — run 'cargo llvm-cov' first")

    stats = parse_lcov(lcov)
    excl_counts, excl_problems = parse_exclusions()
    findings = list(excl_problems)

    print(f"{'Crate':22s} {'Lines':>16s} {'Branches':>16s}  Excl.")
    print("-" * 62)
    for crate, (min_lines, min_branches) in THRESHOLDS.items():
        has_src = crate_has_source(crate)
        s = stats.get(crate)

        if not s:
            if has_src:
                print(f"{crate:22s} {'— missing from lcov —':>16s}")
                findings.append(
                    f"{crate}: has source code but does not appear in lcov"
                )
            else:
                print(f"{crate:22s} {'— no code —':>16s}")
            continue

        lf, lh = s.get("LF", 0), s.get("LH", 0)
        brf, brh = s.get("BRF", 0), s.get("BRH", 0)
        lines = pct(lh, lf)
        branches = pct(brh, brf)

        # Missing data for a crate with source = finding
        if has_src and lines is None:
            findings.append(
                f"{crate}: line data missing (LF=0) — lcov incomplete?"
            )
        if has_src and branches is None:
            findings.append(
                f"{crate}: branch data missing — did `cargo llvm-cov` run without `--branch`?"
            )

        lines_s = f"{lines:9.2f}/{min_lines:<5.0f}" if lines is not None else f"{'n/a':>9s}/{min_lines:<5.0f}"
        branches_s = (
            f"{branches:9.2f}/{min_branches:<5.0f}"
            if branches is not None
            else f"{'n/a':>9s}/{min_branches:<5.0f}"
        )
        ok_l = lines is not None and lines >= min_lines
        ok_b = branches is not None and branches >= min_branches
        mark = "✓" if (ok_l and ok_b) else "✗"
        print(f"{crate:22s} {lines_s} {branches_s}  "
              f"{excl_counts.get(crate, 0):>3d} {mark}")
        if lines is not None and not ok_l:
            findings.append(f"{crate}: lines {lines:.2f} % < {min_lines:.0f} %")
        if branches is not None and not ok_b:
            findings.append(f"{crate}: branches {branches:.2f} % < {min_branches:.0f} %")

    if findings:
        print(f"\ncoverage-gate: {len(findings)} finding(s)\n")
        for f in findings:
            print(f"  ✗ {f}")
        return 1

    total = sum(excl_counts.values())
    print(f"\n✓ All thresholds held. {total} exception(s), all justified.")
    if total:
        print("  Note: The exceptions list is reviewed at every release. If it grows, "
              "that is a finding, not a detail.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
