#!/usr/bin/env python3
"""Checks per-crate coverage against the thresholds in docs/TESTING.md §3.2.

    cargo llvm-cov --workspace --lcov --output-path lcov.info
    python3 scripts/coverage_gate.py lcov.info

    # Preflight for pure scaffolds (CI coverage job / WP-03):
    python3 scripts/coverage_gate.py --source-state
    # prints exactly `true` or `false` on stdout; exit 0.
    # Operational errors (missing crates, unreadable inputs) exit nonzero
    # and must not be treated as scaffold `false`.

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

import argparse
import re
import sys
from collections import defaultdict
from collections.abc import Mapping
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


class SourceProbeError(Exception):
    """Operational failure of the source probe (not a scaffold result)."""


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


def _strip_block_comments(text: str) -> str:
    """Remove `/* … */` comments (non-nested; leftover text fails closed as real)."""
    return re.sub(r"/\*.*?\*/", "", text, flags=re.S)


def _strip_line_comments(text: str) -> str:
    """Remove `//…` line comments (including `//!` / `///` module and item docs)."""
    out: list[str] = []
    for line in text.splitlines():
        # No full string lexer: `//` after code still leaves the code tokens,
        # which correctly keeps the file non-scaffold. `//` only in a string
        # would also leave surrounding tokens (fail-closed toward "has source").
        cut = line.find("//")
        if cut >= 0:
            line = line[:cut]
        out.append(line)
    return "\n".join(out)


def _strip_crate_level_attributes(text: str) -> str:
    """Remove `#![…]` crate-level attributes with nested-bracket depth counting.

    Unclosed attributes are left in place so residual content marks the file
    as real source (fail-closed).
    """
    result: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        if text.startswith("#![", i):
            j = i + 3
            depth = 1
            while j < n and depth:
                ch = text[j]
                if ch == "[":
                    depth += 1
                elif ch == "]":
                    depth -= 1
                j += 1
            if depth != 0:
                # Unclosed — keep remainder as content (not a pure scaffold).
                result.append(text[i:])
                break
            i = j
            continue
        result.append(text[i])
        i += 1
    return "".join(result)


def is_pure_scaffold_lib(text: str) -> bool:
    """True only if a single lib.rs is nothing but allowed scaffold material.

    Allowed: blank lines, comments/module docs, and crate-level attributes
    (`#![…]`). After stripping those, **any** remaining token/content means
    real source. Uncertain or non-scaffold forms are never treated as scaffold.
    Not a Rust parser — deliberately conservative / fail-closed.
    """
    rest = _strip_block_comments(text)
    rest = _strip_line_comments(rest)
    rest = _strip_crate_level_attributes(rest)
    return rest.strip() == ""


def crate_has_source(crate: str, crates_dir: Path = CRATES_DIR) -> bool:
    """True if the crate has more than a pure scaffold lib.rs.

    Multiple `.rs` files always count as real source. A single `lib.rs` is a
    scaffold only when `is_pure_scaffold_lib` holds; anything else (const,
    type, static, include!, macros, items, …) activates coverage.

    Missing `src/` or no `.rs` files → False (scaffold/absent for the LCOV
    gate). The probe path (`any_threshold_crate_has_source`) fails closed if
    an expected threshold crate tree is missing entirely.
    """
    root = crates_dir / crate / "src"
    if not root.exists():
        return False
    rs_files = sorted(root.rglob("*.rs"))
    if not rs_files:
        return False
    if len(rs_files) > 1:
        return True
    text = rs_files[0].read_text(encoding="utf-8")
    return not is_pure_scaffold_lib(text)


def any_threshold_crate_has_source(
    crates_dir: Path = CRATES_DIR,
    thresholds: Mapping[str, tuple[float, float]] = THRESHOLDS,
) -> bool:
    """True if any threshold crate has non-scaffold source.

    Fail-closed: missing crates root, missing expected crate directories, or
    unreadable `.rs` inputs raise `SourceProbeError` rather than returning
    False (which would wrongly mean "successful scaffold no-op").
    """
    if not crates_dir.is_dir():
        raise SourceProbeError(
            f"crates directory missing or not a directory: {crates_dir}"
        )
    if not thresholds:
        raise SourceProbeError("threshold map is empty — cannot probe source state")

    any_real = False
    for crate in thresholds:
        crate_root = crates_dir / crate
        if not crate_root.is_dir():
            raise SourceProbeError(
                f"expected threshold crate missing: {crate} under {crates_dir}"
            )
        src = crate_root / "src"
        if not src.is_dir():
            raise SourceProbeError(
                f"expected src/ missing for threshold crate {crate}"
            )
        try:
            rs_files = list(src.rglob("*.rs"))
        except OSError as e:
            raise SourceProbeError(
                f"unreadable source tree for {crate}: {e}"
            ) from e
        for rs in rs_files:
            try:
                rs.read_text(encoding="utf-8")
            except OSError as e:
                raise SourceProbeError(
                    f"unreadable source file {rs}: {e}"
                ) from e
        if crate_has_source(crate, crates_dir=crates_dir):
            any_real = True
    return any_real


def pct(hit: int, total: int) -> float | None:
    """Percent or None when total == 0 (missing data)."""
    if total == 0:
        return None
    return 100.0 * hit / total


def run_source_state_probe(
    crates_dir: Path = CRATES_DIR,
    thresholds: Mapping[str, tuple[float, float]] = THRESHOLDS,
) -> int:
    """CLI mode: print exactly `true` or `false`; exit 0. Errors → exit 1."""
    try:
        has = any_threshold_crate_has_source(
            crates_dir=crates_dir, thresholds=thresholds
        )
    except SourceProbeError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    print("true" if has else "false")
    return 0


def run_lcov_gate(lcov: Path) -> int:
    if not lcov.exists():
        print(f"ERROR: {lcov} missing — run 'cargo llvm-cov' first", file=sys.stderr)
        return 1

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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source-state",
        action="store_true",
        help=(
            "print true/false whether any threshold crate has non-scaffold "
            "source (exit 0); operational errors exit nonzero"
        ),
    )
    parser.add_argument(
        "lcov",
        nargs="?",
        help="path to lcov.info from cargo llvm-cov",
    )
    args = parser.parse_args(argv)

    if args.source_state:
        if args.lcov is not None:
            print(
                "ERROR: --source-state does not take an lcov path",
                file=sys.stderr,
            )
            return 1
        return run_source_state_probe()

    if args.lcov is None:
        print(
            "Usage: coverage_gate.py <lcov.info> | coverage_gate.py --source-state",
            file=sys.stderr,
        )
        return 1
    return run_lcov_gate(Path(args.lcov))


if __name__ == "__main__":
    sys.exit(main())
