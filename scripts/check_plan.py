#!/usr/bin/env python3
"""Prüft Spezifikation, Implementierungsplan und Testcode gegeneinander.

Umsetzung von TESTING.md §6. Läuft in CI als eigener Schritt und bricht den Build,
sobald die Dokumente auseinanderlaufen.

Aufruf:
    python3 scripts/check_plan.py            # alle Prüfungen
    python3 scripts/check_plan.py --list     # gefundene IDs auflisten, nichts prüfen

Exit 0 = alles konsistent, Exit 1 = mindestens ein Befund.
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
CRATES = ROOT / "crates"

SPEC = DOCS / "SPECIFICATION.md"
PLAN = DOCS / "IMPLEMENTATION_PLAN.md"
TESTING = DOCS / "TESTING.md"
RECOVERY = DOCS / "RECOVERY.md"

# Test-IDs stehen in der Spec als erste Tabellenspalte: | **D7** | ...
ID_DEF = re.compile(r"^\|\s*\*\*([DPSTEO]\d+[a-z]?)\*\*\s*\|", re.M)
# Durchgestrichene, also erledigte Einträge: | ~~**O15**~~ |
ID_DEF_RESOLVED = re.compile(r"^\|\s*~~\*\*([DPSTEO]\d+[a-z]?)\*\*~~\s*\|", re.M)
ID_USE = re.compile(r"\b([DPS]\d+[a-z]?)\b")
SECTION_DEF = re.compile(r"^#{2,4}\s+(\d+(?:\.\d+)*)\s", re.M)
SECTION_REF = re.compile(r"(?:Abschnitt|siehe|§)\s*(\d+\.\d+(?:\.\d+)?)\b")
WP_DEF = re.compile(r"^####\s+(WP-\d+)", re.M)
WP_USE = re.compile(r"\b(WP-\d+)\b")
# Testfunktionen heißen d01_…, p07_…, s29h_…
TEST_FN = re.compile(r"fn\s+([dps]\d+[a-z]?)_[a-z0-9_]+\s*\(", re.I)


@dataclass
class Report:
    findings: list[str] = field(default_factory=list)
    checks_run: int = 0

    def check(self, ok: bool, message: str) -> None:
        self.checks_run += 1
        if not ok:
            self.findings.append(message)

    def fail(self, message: str) -> None:
        self.findings.append(message)


def read(path: Path) -> str:
    if not path.exists():
        sys.exit(f"FEHLER: {path.relative_to(ROOT)} fehlt")
    return path.read_text(encoding="utf-8")


def ids_by_kind(text: str, kind: str) -> set[str]:
    """Alle in `text` definierten IDs einer Sorte, inklusive erledigter."""
    found = set(ID_DEF.findall(text)) | set(ID_DEF_RESOLVED.findall(text))
    return {i for i in found if i[0] == kind}


def sort_ids(ids: set[str]) -> list[str]:
    def key(i: str) -> tuple[str, int, str]:
        m = re.match(r"([A-Z])(\d+)([a-z]?)", i)
        assert m
        return (m.group(1), int(m.group(2)), m.group(3))

    return sorted(ids, key=key)


def check_unique_definitions(spec: str, rep: Report) -> None:
    """Keine ID darf zweimal definiert sein — sonst driften die Fassungen auseinander."""
    counts = Counter(ID_DEF.findall(spec) + ID_DEF_RESOLVED.findall(spec))
    for ident, n in sorted(counts.items()):
        rep.check(n == 1, f"ID {ident} ist {n}× in SPECIFICATION.md definiert (genau 1× erwartet)")


def check_tests_mapped(spec: str, plan: str, rep: Report) -> None:
    """Jede Test-ID der Spec muss im Plan vorkommen — und keine erfundene."""
    spec_ids = ids_by_kind(spec, "D") | ids_by_kind(spec, "P") | ids_by_kind(spec, "S")
    plan_ids = {i for i in ID_USE.findall(plan) if re.fullmatch(r"[DPS]\d+[a-z]?", i)}

    for ident in sort_ids(spec_ids - plan_ids):
        rep.fail(f"Test {ident} ist in SPECIFICATION.md definiert, aber keinem WP zugeordnet")
    for ident in sort_ids(plan_ids - spec_ids):
        rep.fail(f"Test {ident} wird im Plan genannt, existiert aber nicht in SPECIFICATION.md")
    rep.checks_run += 2


def check_decisions_mapped(spec: str, plan: str, rep: Report) -> None:
    """Jede Entscheidung E… braucht ein umsetzendes Arbeitspaket."""
    decisions = ids_by_kind(spec, "E")
    used = set(re.findall(r"\b(E\d[a-z]?)\b", plan))
    for ident in sort_ids(decisions - used):
        rep.fail(f"Entscheidung {ident} hat kein umsetzendes WP im Implementierungsplan")
    rep.checks_run += 1


def check_threats_handled(spec: str, rep: Report) -> None:
    """Jede Bedrohung wird entweder getestet oder steht ausdrücklich als nicht abgedeckt."""
    threats = ids_by_kind(spec, "T")
    uncovered_block = spec.split("### 4.2")[-1] if "### 4.2" in spec else ""
    for ident in sort_ids(threats):
        row = next((ln for ln in spec.splitlines() if re.match(rf"^\|\s*\*\*{ident}\*\*\s*\|", ln)), "")
        has_test = bool(ID_USE.search(row))
        named_uncovered = ident in uncovered_block
        rep.check(
            has_test or named_uncovered,
            f"Bedrohung {ident} nennt weder einen Test noch steht sie in §4.2 als nicht abgedeckt",
        )


def check_sections(rep: Report) -> None:
    """Kein Abschnittsverweis in irgendeinem Dokument darf ins Leere zeigen."""
    spec = read(SPEC)
    defined = set(SECTION_DEF.findall(spec))
    for path in (SPEC, PLAN, TESTING, RECOVERY):
        text = read(path)
        for ref in sorted(set(SECTION_REF.findall(text))):
            # Versionsnummern wie 30.2 oder 0.32 sind keine Abschnitte
            if ref in defined:
                continue
            rep.fail(f"{path.name}: Verweis auf Abschnitt {ref}, den es in SPECIFICATION.md nicht gibt")
        rep.checks_run += 1


def check_wp_defined(plan: str, rep: Report) -> None:
    """Jedes referenzierte Arbeitspaket muss auch beschrieben sein.

    Sammel-Überschriften wie `#### WP-50 · … · WP-51 · …` zählen für alle darin genannten.
    """
    described: set[str] = set()
    for line in plan.splitlines():
        # Eigene Überschrift, oder Tabellenzeile — leichtgewichtige Pakete
        # (M6, M7) sind bewusst als Tabelle beschrieben, nicht als Abschnitt.
        if line.startswith("#### ") or re.match(r"^\|\s*WP-\d+\s*\|", line):
            described |= set(WP_USE.findall(line))
    referenced = set(WP_USE.findall(plan))
    for wp in sorted(referenced - described):
        rep.fail(f"{wp} wird im Plan referenziert, aber nirgends beschrieben")
    rep.checks_run += 1


def wp_states(plan: str) -> dict[str, str]:
    """Zustand je Arbeitspaket aus dem Plan lesen."""
    states: dict[str, str] = {}
    for wp, state in re.findall(
        r"####\s+(WP-\d+)[^\n]*\n\*\*[^\n]*?\*\*Zustand:\*\*\s*([A-ZÄÖÜ ]+)", plan
    ):
        states[wp] = state.strip()
    for line in plan.splitlines():
        m = re.match(r"^\|\s*(WP-\d+)\s*\|", line)
        if m:
            states.setdefault(m.group(1), "OFFEN")
    return states


def expand(token: str) -> set[str]:
    """'S1–S8' zu {S1..S8} auflösen; Einzel-IDs unverändert."""
    token = token.strip().strip("*")
    m = re.fullmatch(r"([DPS])(\d+)\s*[–-]\s*(?:[DPS])?(\d+)", token)
    if m:
        kind, lo, hi = m.group(1), int(m.group(2)), int(m.group(3))
        return {f"{kind}{n}" for n in range(lo, hi + 1)}
    return {token} if re.fullmatch(r"[DPS]\d+[a-z]?", token) else set()


def test_owners(plan: str) -> dict[str, str]:
    """Test-ID -> zuständiges WP, aus der Zuordnungstabelle in §5."""
    owners: dict[str, str] = {}
    for wp, body in re.findall(r"(WP-\d+)\s*\(([^)]*)\)", plan):
        for token in re.split(r"[,/]", body):
            for ident in expand(token):
                owners.setdefault(ident, wp)
    return owners


def check_tests_exist(spec: str, plan: str, rep: Report) -> None:
    """Eine Test-ID braucht eine Testfunktion, sobald ihr WP auf FERTIG steht.

    Vorher wäre die Forderung sinnlos — der Test kann nicht existieren, bevor das
    Paket bearbeitet wurde. Ab FERTIG ist ein fehlender Test ein Befund, und das
    ist genau die Stelle, an der Testschulden sonst unbemerkt entstehen.
    """
    spec_ids = ids_by_kind(spec, "D") | ids_by_kind(spec, "P") | ids_by_kind(spec, "S")
    states, owners = wp_states(plan), test_owners(plan)

    sources = list(CRATES.rglob("*.rs")) if CRATES.exists() else []
    implemented: set[str] = set()
    for src in sources:
        implemented |= {m.lower() for m in TEST_FN.findall(src.read_text(encoding="utf-8"))}

    due = {i for i in spec_ids if states.get(owners.get(i, ""), "OFFEN") == "FERTIG"}
    for ident in sort_ids({i for i in due if i.lower() not in implemented}):
        rep.fail(
            f"Test {ident} fehlt als Testfunktion, obwohl {owners[ident]} auf FERTIG steht "
            f"(erwartet: fn {ident.lower()}_…)"
        )
    rep.checks_run += 1

    done = sum(1 for v in states.values() if v == "FERTIG")
    print(f"  {done}/{len(states)} WP fertig · {len(due)} Test-IDs fällig · "
          f"{len(spec_ids) - len(due)} stehen noch aus")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true", help="gefundene IDs auflisten")
    args = parser.parse_args()

    spec, plan = read(SPEC), read(PLAN)

    if args.list:
        for kind, label in (("D", "Differential"), ("P", "Property"), ("S", "Szenario"),
                            ("T", "Bedrohung"), ("E", "Entscheidung"), ("O", "Offen")):
            found = sort_ids(ids_by_kind(spec, kind))
            print(f"{label:14s} ({len(found):3d}): {', '.join(found)}")
        return 0

    rep = Report()
    check_unique_definitions(spec, rep)
    check_tests_mapped(spec, plan, rep)
    check_decisions_mapped(spec, plan, rep)
    check_threats_handled(spec, rep)
    check_sections(rep)
    check_wp_defined(plan, rep)
    check_tests_exist(spec, plan, rep)

    if rep.findings:
        print(f"check-plan: {len(rep.findings)} Befund(e)\n")
        for finding in rep.findings:
            print(f"  ✗ {finding}")
        print("\nDie Dokumente sind nicht konsistent. Siehe TESTING.md §6.")
        return 1

    print(f"check-plan: {rep.checks_run} Prüfungen, keine Befunde.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
