#!/usr/bin/env python3
"""Prüft die Coverage je Crate gegen die Schwellen aus docs/TESTING.md §3.2.

    cargo llvm-cov --workspace --lcov --output-path lcov.info
    python3 scripts/coverage_gate.py lcov.info

Ausnahmen stehen in coverage-exclusions.toml und brauchen JEDER eine Begründung
und einen benannten Ersatztest — ein Eintrag ohne beides bricht den Build.

Grundregel fail-closed: fehlende Zeilen- oder Zweigdaten für einen Crate, der
Quellcode hat, sind ein Befund — nie still 100 %.

Wichtige Einordnung, die auch in TESTING.md §3.1 steht: Coverage misst
Ausführung, nicht Prüfung. Ein Test, der eine Zeile durchläuft, ohne ihr Ergebnis
zu prüfen, zählt hier voll mit. Das eigentliche Gate für die Sicherheitskerne ist
deshalb `cargo mutants` — 100 % Coverage mit überlebendem Mutanten ist rot.
"""

from __future__ import annotations

import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXCLUSIONS = ROOT / "coverage-exclusions.toml"
CRATES_DIR = ROOT / "crates"

# (Zeilen, Zweige) in Prozent. Quelle: docs/TESTING.md §3.2
THRESHOLDS: dict[str, tuple[float, float]] = {
    "trinity-types":     (100.0, 100.0),
    "trinity-entropy":   (100.0, 100.0),
    "trinity-keystore":  (100.0, 100.0),
    "trinity-signer":    (100.0, 100.0),
    "trinity-verify":    (100.0, 100.0),   # hier ist keine Ausnahme zulässig
    "trinity-watch":     (95.0,  90.0),
    "trinity-chain":     (90.0,  85.0),
    "trinity-transport": (90.0,  85.0),
    "trinity-export":    (100.0, 95.0),
    "trinity-ffi":       (95.0,  90.0),
}

# Für diesen Crate darf coverage-exclusions.toml keinen Eintrag enthalten.
NO_EXCLUSIONS = {"trinity-verify"}


def parse_lcov(path: Path) -> dict[str, dict[str, int]]:
    """LCOV je Crate aggregieren: LF/LH (Zeilen), BRF/BRH (Zweige)."""
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
    """Ausnahmen zählen und auf Vollständigkeit prüfen."""
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
            problems.append(f"Ausnahme #{i}: kein 'path'")
            continue
        if not reason or not reason.group(1).strip():
            problems.append(f"Ausnahme für {path.group(1)}: keine Begründung ('reason')")
        if not test or not test.group(1).strip():
            problems.append(f"Ausnahme für {path.group(1)}: kein Ersatztest ('test')")
        m = re.search(r"crates/([a-z0-9-]+)/", path.group(1))
        if m:
            per_crate[m.group(1)] += 1
            if m.group(1) in NO_EXCLUSIONS:
                problems.append(
                    f"{m.group(1)} duldet keine Ausnahme — {path.group(1)} muss vollständig "
                    f"abgedeckt sein (TESTING.md §3.2)"
                )
    return dict(per_crate), problems


def crate_has_source(crate: str) -> bool:
    """True, wenn der Crate mehr als eine reine Gerüst-lib.rs hat.

    Eine einzelne lib.rs, die nur Modul-Doku und Attribute enthält (kein fn/struct/
    enum/impl/mod/use außer erlaubten Attributen), zählt als Gerüst ohne Fachcode.
    Sobald zusätzliche .rs-Dateien existieren oder lib.rs echten Code trägt,
    gilt der Crate als „hat Quellcode".
    """
    root = CRATES_DIR / crate / "src"
    if not root.exists():
        return False
    rs_files = list(root.rglob("*.rs"))
    if not rs_files:
        return False
    if len(rs_files) > 1:
        return True
    # Eine Datei: prüfen, ob sie mehr als ein Gerüst ist
    text = rs_files[0].read_text(encoding="utf-8")
    # Echter Code: fn, struct, enum, impl, trait, macro_rules, mod X;
    if re.search(r"^\s*(pub\s+)?(fn|struct|enum|impl|trait|macro_rules|mod)\b", text, re.M):
        return True
    if re.search(r"^\s*use\s+", text, re.M):
        return True
    return False


def pct(hit: int, total: int) -> float | None:
    """Prozent oder None, wenn total == 0 (fehlende Daten)."""
    if total == 0:
        return None
    return 100.0 * hit / total


def main() -> int:
    if len(sys.argv) != 2:
        sys.exit("Aufruf: coverage_gate.py <lcov.info>")
    lcov = Path(sys.argv[1])
    if not lcov.exists():
        sys.exit(f"FEHLER: {lcov} fehlt — erst 'cargo llvm-cov' laufen lassen")

    stats = parse_lcov(lcov)
    excl_counts, excl_problems = parse_exclusions()
    findings = list(excl_problems)

    print(f"{'Crate':22s} {'Zeilen':>16s} {'Zweige':>16s}  Ausn.")
    print("-" * 62)
    for crate, (min_lines, min_branches) in THRESHOLDS.items():
        has_src = crate_has_source(crate)
        s = stats.get(crate)

        if not s:
            if has_src:
                print(f"{crate:22s} {'— fehlt im lcov —':>16s}")
                findings.append(
                    f"{crate}: hat Quellcode, kommt im lcov aber nicht vor"
                )
            else:
                print(f"{crate:22s} {'— kein Code —':>16s}")
            continue

        lf, lh = s.get("LF", 0), s.get("LH", 0)
        brf, brh = s.get("BRF", 0), s.get("BRH", 0)
        lines = pct(lh, lf)
        branches = pct(brh, brf)

        # Fehlende Daten bei Crate mit Quellcode = Befund
        if has_src and lines is None:
            findings.append(
                f"{crate}: Zeilendaten fehlen (LF=0) — lcov unvollständig?"
            )
        if has_src and branches is None:
            findings.append(
                f"{crate}: Zweigdaten fehlen — lief `cargo llvm-cov` ohne `--branch`?"
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
            findings.append(f"{crate}: Zeilen {lines:.2f} % < {min_lines:.0f} %")
        if branches is not None and not ok_b:
            findings.append(f"{crate}: Zweige {branches:.2f} % < {min_branches:.0f} %")

    if findings:
        print(f"\ncoverage-gate: {len(findings)} Befund(e)\n")
        for f in findings:
            print(f"  ✗ {f}")
        return 1

    total = sum(excl_counts.values())
    print(f"\n✓ Alle Schwellen gehalten. {total} Ausnahme(n), alle begründet.")
    if total:
        print("  Hinweis: Die Ausnahmenliste wird bei jedem Release gereviewt. Wächst sie, "
              "ist das ein Befund, kein Detail.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
