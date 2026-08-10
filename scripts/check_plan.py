#!/usr/bin/env python3
"""Prüft Spezifikation, Implementierungsplan und Testcode gegeneinander.

Umsetzung von TESTING.md §6. Läuft in CI als eigener Schritt und bricht den Build,
sobald die Dokumente auseinanderlaufen.

Grundregel: Eine Lage, die dieses Skript nicht eindeutig auflösen kann, ist ein
Befund mit Exit 1 — niemals ein stilles Weiterlaufen.

Aufruf:
    python3 scripts/check_plan.py            # alle Prüfungen
    python3 scripts/check_plan.py --list     # gefundene IDs auflisten, nichts prüfen

Exit 0 = alles konsistent, Exit 1 = mindestens ein Befund.
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
CRATES = ROOT / "crates"
README = ROOT / "README.md"

SPEC = DOCS / "SPECIFICATION.md"
PLAN = DOCS / "IMPLEMENTATION_PLAN.md"
TESTING = DOCS / "TESTING.md"
RECOVERY = DOCS / "RECOVERY.md"
DEP_BUDGET = ROOT / "scripts" / "dep_budget.py"

# Test-IDs stehen in der Spec als erste Tabellenspalte: | **D7** | ...
ID_DEF = re.compile(r"^\|\s*\*\*([DPSTEO]\d+[a-z]?)\*\*\s*\|", re.M)
# Durchgestrichene, also erledigte Einträge: | ~~**O15**~~ |
ID_DEF_RESOLVED = re.compile(r"^\|\s*~~\*\*([DPSTEO]\d+[a-z]?)\*\*~~\s*\|", re.M)
ID_USE = re.compile(r"\b([DPS]\d+[a-z]?)\b")
SECTION_DEF = re.compile(r"^#{2,4}\s+(\d+(?:\.\d+)*)\s", re.M)
SECTION_REF = re.compile(r"(?:Abschnitt|siehe|§)\s*(\d+\.\d+(?:\.\d+)?)\b")
# Eigener WP-Block: #### WP-nn · ...
WP_HEADING = re.compile(r"^####\s+(WP-\d+)\b", re.M)
WP_USE = re.compile(r"\b(WP-\d+)\b")
# Testfunktionen: d1_…, p5_…, s15b_…, s29h_… (kleingeschrieben, ohne führende Null)
TEST_FN = re.compile(r"fn\s+([dps]\d+[a-z]?)_[a-z0-9_]+\s*\(", re.I)

VALID_STATES = frozenset({"OFFEN", "BLOCKIERT", "IN ARBEIT", "REVIEW", "FERTIG"})

# Pflichtfelder im WP-Block (Reihenfolge egal, alle müssen vorkommen)
REQUIRED_FIELDS = (
    "**Spec:**",
    "**Braucht:**",
    "**Zustand:**",
    "**Dateien:**",
    "**Verbote:**",
    "**Abnahme**",
    "**Tests:**",
)

TESTS_LINE = re.compile(r"^\*\*Tests:\*\*\s*(.+?)\s*$", re.M)
STATE_LINE = re.compile(r"\*\*Zustand:\*\*\s*([^\n*]+)")
BRAUCHT_LINE = re.compile(r"\*\*Braucht:\*\*\s*([^\n*]+)")
TEST_ID_TOKEN = re.compile(r"^[DPS]\d+[a-z]?$")


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


def parse_wp_blocks(plan: str) -> dict[str, str]:
    """WP-ID → voller Blocktext (vom Heading bis vor den nächsten WP-Heading oder ##)."""
    blocks: dict[str, str] = {}
    matches = list(WP_HEADING.finditer(plan))
    for i, m in enumerate(matches):
        wp = m.group(1)
        start = m.start()
        if i + 1 < len(matches):
            end = matches[i + 1].start()
        else:
            # Ende am nächsten ##-Abschnitt der Stufe 1–2, sonst Dateiende
            rest = plan[m.end():]
            end_m = re.search(r"\n##\s", rest)
            end = m.end() + end_m.start() if end_m else len(plan)
        body = plan[start:end]
        if wp in blocks:
            # Doppelte Überschrift — wird in check_wp_structure als Befund gemeldet
            blocks[wp] = blocks[wp] + "\n" + body
        else:
            blocks[wp] = body
    return blocks


def parse_tests_line(line_body: str) -> list[str] | None:
    """Parst den Inhalt einer **Tests:**-Zeile. None = syntaktisch ungültig."""
    body = line_body.strip()
    if body in ("—", "-", "–"):
        return []
    # Keine Bereiche, keine Schrägstriche
    if "–" in body or re.search(r"\d\s*-\s*\d", body) or "/" in body:
        return None
    parts = [p.strip().strip("*") for p in body.split(",")]
    if not parts or any(not p for p in parts):
        return None
    for p in parts:
        if not TEST_ID_TOKEN.fullmatch(p):
            return None
    return parts


def test_owners_from_blocks(blocks: dict[str, str], rep: Report) -> dict[str, list[str]]:
    """Test-ID → Liste der WPs, die sie auf **Tests:** tragen."""
    owners: dict[str, list[str]] = defaultdict(list)
    for wp, body in blocks.items():
        m = TESTS_LINE.search(body)
        if not m:
            continue  # fehlende Zeile → check_wp_structure
        parsed = parse_tests_line(m.group(1))
        if parsed is None:
            rep.fail(
                f"{wp}: **Tests:**-Zeile ungültig "
                f"(nur kommaseparierte IDs wie D1, S15b oder —; keine Bereiche/Schrägstriche): "
                f"{m.group(1)!r}"
            )
            continue
        for ident in parsed:
            owners[ident].append(wp)
    return owners


def check_unique_definitions(spec: str, rep: Report) -> None:
    """Keine ID darf zweimal definiert sein — sonst driften die Fassungen auseinander."""
    counts = Counter(ID_DEF.findall(spec) + ID_DEF_RESOLVED.findall(spec))
    for ident, n in sorted(counts.items()):
        rep.check(n == 1, f"ID {ident} ist {n}× in SPECIFICATION.md definiert (genau 1× erwartet)")


def check_test_ownership(spec: str, blocks: dict[str, str], rep: Report) -> None:
    """Jede Spec-Test-ID auf genau einer **Tests:**-Zeile; keine erfundenen IDs."""
    spec_ids = ids_by_kind(spec, "D") | ids_by_kind(spec, "P") | ids_by_kind(spec, "S")
    owners = test_owners_from_blocks(blocks, rep)

    for ident in sort_ids(spec_ids):
        wps = owners.get(ident, [])
        if len(wps) == 0:
            rep.fail(f"Test {ident} ist in SPECIFICATION.md definiert, aber keinem WP auf **Tests:** zugeordnet")
        elif len(wps) > 1:
            rep.fail(
                f"Test {ident} ist {len(wps)}× zugeordnet: {', '.join(sorted(wps))} "
                f"(genau ein Eigentümer erwartet)"
            )
        else:
            rep.checks_run += 1

    for ident in sort_ids(set(owners) - spec_ids):
        wps = owners[ident]
        rep.fail(
            f"Test {ident} steht auf **Tests:** von {', '.join(sorted(wps))}, "
            f"existiert aber nicht in SPECIFICATION.md"
        )
    rep.checks_run += 1


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
    """Kein Abschnittsverweis darf ins Leere zeigen — inkl. README.md."""
    spec = read(SPEC)
    defined = set(SECTION_DEF.findall(spec))
    for path in (SPEC, PLAN, TESTING, RECOVERY, README):
        if not path.exists():
            continue
        text = read(path)
        for ref in sorted(set(SECTION_REF.findall(text))):
            if ref in defined:
                continue
            rep.fail(f"{path.name}: Verweis auf Abschnitt {ref}, den es in SPECIFICATION.md nicht gibt")
        rep.checks_run += 1


def check_wp_structure(plan: str, blocks: dict[str, str], rep: Report) -> None:
    """Jeder referenzierte WP hat einen eigenen Block; Pflichtfelder und gültiger Zustand."""
    referenced = set(WP_USE.findall(plan))
    for wp in sorted(referenced - set(blocks)):
        rep.fail(f"{wp} wird im Plan referenziert, hat aber keinen eigenen ####-Block")
    rep.checks_run += 1

    for wp, body in sorted(blocks.items()):
        for field in REQUIRED_FIELDS:
            rep.check(field in body, f"{wp}: Pflichtfeld {field} fehlt im WP-Block")

        sm = STATE_LINE.search(body)
        if sm:
            state = sm.group(1).strip()
            # Zustand kann "BLOCKIERT (Grund)" sein — Basiswort prüfen
            base = state.split("(")[0].strip()
            rep.check(
                base in VALID_STATES,
                f"{wp}: **Zustand:** {state!r} ist ungültig "
                f"(erlaubt: {', '.join(sorted(VALID_STATES))})",
            )
        # sonst: fehlendes **Zustand:** bereits oben


def check_dependencies(blocks: dict[str, str], rep: Report) -> None:
    """Jede WP-ID in **Braucht:** existiert; kein Zyklus im Abhängigkeitsgraphen."""
    graph: dict[str, list[str]] = {}
    for wp, body in blocks.items():
        bm = BRAUCHT_LINE.search(body)
        deps: list[str] = []
        if bm:
            raw = bm.group(1).strip()
            if raw not in ("—", "-", "–", ""):
                deps = WP_USE.findall(raw)
                for dep in deps:
                    if dep not in blocks:
                        rep.fail(f"{wp}: **Braucht:** nennt {dep}, das keinen eigenen Block hat")
        graph[wp] = deps
    rep.checks_run += 1

    # Zyklenerkennung (DFS)
    WHITE, GRAY, BLACK = 0, 1, 2
    color = {wp: WHITE for wp in graph}
    cycle_found: list[str] = []

    def dfs(node: str, path: list[str]) -> None:
        if cycle_found:
            return
        color[node] = GRAY
        path.append(node)
        for nxt in graph.get(node, []):
            if nxt not in color:
                continue
            if color[nxt] == GRAY:
                cycle_found.extend(path[path.index(nxt):] + [nxt])
                return
            if color[nxt] == WHITE:
                dfs(nxt, path)
        path.pop()
        color[node] = BLACK

    for wp in sorted(graph):
        if color[wp] == WHITE:
            dfs(wp, [])
    if cycle_found:
        rep.fail(f"Zyklus im Abhängigkeitsgraphen: {' → '.join(cycle_found)}")
    else:
        rep.checks_run += 1


def wp_states(blocks: dict[str, str]) -> dict[str, str]:
    """Zustand je Arbeitspaket aus den WP-Blöcken."""
    states: dict[str, str] = {}
    for wp, body in blocks.items():
        sm = STATE_LINE.search(body)
        if sm:
            states[wp] = sm.group(1).strip().split("(")[0].strip()
        else:
            states[wp] = "OFFEN"
    return states


def test_owners_unique(blocks: dict[str, str]) -> dict[str, str]:
    """Test-ID → Eigentümer-WP (nur eindeutige; doppelte werden woanders gemeldet)."""
    owners: dict[str, str] = {}
    for wp, body in blocks.items():
        m = TESTS_LINE.search(body)
        if not m:
            continue
        parsed = parse_tests_line(m.group(1))
        if parsed is None:
            continue
        for ident in parsed:
            if ident not in owners:
                owners[ident] = wp
    return owners


def check_tests_exist(spec: str, blocks: dict[str, str], rep: Report) -> None:
    """Eine Test-ID braucht eine Testfunktion, sobald ihr WP auf FERTIG steht."""
    spec_ids = ids_by_kind(spec, "D") | ids_by_kind(spec, "P") | ids_by_kind(spec, "S")
    states = wp_states(blocks)
    owners = test_owners_unique(blocks)

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
    print(
        f"  {done}/{len(states)} WP fertig · {len(due)} Test-IDs fällig · "
        f"{len(spec_ids) - len(due)} stehen noch aus"
    )


def count_release_criteria(spec: str) -> int:
    """Anzahl der Punkte in SPECIFICATION.md §5.5 (Tabellenzeilen mit Nummer)."""
    if "### 5.5" not in spec:
        return -1
    section = spec.split("### 5.5", 1)[1]
    # Nächster ##-Abschnitt beendet
    section = re.split(r"\n##\s", section, maxsplit=1)[0]
    rows = re.findall(r"^\|\s*\*?\*?(\d+[a-z]?)\*?\*?\s*\|", section, re.M)
    return len(rows)


def crates_on_disk() -> list[str]:
    if not CRATES.exists():
        return []
    return sorted(p.name for p in CRATES.iterdir() if p.is_dir() and (p / "Cargo.toml").exists())


def crates_in_spec_11(spec: str) -> list[str]:
    """Crate-Namen aus dem Workspace-Baum in §1.1 (nur unter crates/)."""
    # Abschnitt 1.1 bis 1.2
    m = re.search(r"### 1\.1\b", spec)
    if not m:
        return []
    rest = spec[m.end():]
    end = re.search(r"\n### 1\.2\b", rest)
    block = rest[: end.start()] if end else rest[:4000]
    # Nur Zeilen unter crates/…/trinity-* — nicht platform/android/trinity-platform
    crates_sec = block
    if "├── crates/" in block:
        crates_sec = block.split("├── crates/", 1)[1]
        # Plattform-Baum beginnt mit platform/
        if "├── platform/" in crates_sec:
            crates_sec = crates_sec.split("├── platform/", 1)[0]
        elif "└── platform/" in crates_sec:
            crates_sec = crates_sec.split("└── platform/", 1)[0]
    return sorted(set(re.findall(r"\b(trinity-[a-z0-9-]+)/", crates_sec)))


def measured_external_from_dep_budget() -> int | None:
    """Liest die Konstante MEASURED aus scripts/dep_budget.py."""
    if not DEP_BUDGET.exists():
        return None
    text = DEP_BUDGET.read_text(encoding="utf-8")
    m = re.search(r"^MEASURED\s*=\s*(\d+)\b", text, re.M)
    if not m:
        return None
    return int(m.group(1))


def check_numbers(spec: str, plan: str, rep: Report) -> None:
    """Zahlen in den Dokumenten gegen berechnete Werte halten."""
    # 1) Freigabepunkte §5.5
    n_criteria = count_release_criteria(spec)
    if n_criteria < 0:
        rep.fail("SPECIFICATION.md: Abschnitt §5.5 nicht gefunden")
    else:
        for path, text, label in (
            (PLAN, plan, "IMPLEMENTATION_PLAN.md"),
            (TESTING, read(TESTING), "TESTING.md"),
        ):
            for m in re.finditer(
                r"(\d+)\s+Punkte(?:\s+aus\s+(?:SPECIFICATION\.md\s+)?(?:§\s*)?5\.5|.*?5\.5)",
                text,
            ):
                claimed = int(m.group(1))
                rep.check(
                    claimed == n_criteria,
                    f"{label}: nennt {claimed} Punkte zu §5.5, gezählt sind {n_criteria}",
                )
            # auch „Alle N Punkte" / „die N Punkte in … 5.5"
            for m in re.finditer(r"(?:Alle|die)\s+(\d+)\s+Punkte", text):
                # nur wenn in der Nähe von 5.5
                start = max(0, m.start() - 80)
                end = min(len(text), m.end() + 80)
                window = text[start:end]
                if "5.5" in window or "Freigabe" in window:
                    claimed = int(m.group(1))
                    rep.check(
                        claimed == n_criteria,
                        f"{label}: nennt {claimed} Punkte (Kontext Freigabe/5.5), "
                        f"gezählt sind {n_criteria}",
                    )
        rep.checks_run += 1

    # 2) Anzahl WP-Blöcke vs. Stellen, die sie nennen
    blocks = parse_wp_blocks(plan)
    n_wp = len(blocks)
    if README.exists():
        readme = read(README)
        for m in re.finditer(r"(\d+)\s+Arbeitspakete", readme):
            claimed = int(m.group(1))
            rep.check(
                claimed == n_wp,
                f"README.md: nennt {claimed} Arbeitspakete, gezählt sind {n_wp} WP-Blöcke",
            )
    rep.checks_run += 1

    # 3) Crates auf Disk vs. §1.1 vs. Stellen mit Crate-Anzahl
    on_disk = crates_on_disk()
    in_spec = crates_in_spec_11(spec)
    n_disk = len(on_disk)
    if set(on_disk) != set(in_spec):
        only_disk = sorted(set(on_disk) - set(in_spec))
        only_spec = sorted(set(in_spec) - set(on_disk))
        parts = []
        if only_disk:
            parts.append(f"nur auf Disk: {', '.join(only_disk)}")
        if only_spec:
            parts.append(f"nur in §1.1: {', '.join(only_spec)}")
        rep.fail(f"Crate-Liste weicht ab ({'; '.join(parts)}; Disk={n_disk}, §1.1={len(in_spec)})")
    else:
        rep.checks_run += 1

    # „neun/zehn/N Crates" im Plan und Spec
    word_to_n = {
        "neun": 9, "zehn": 10, "elf": 11, "zwölf": 12,
        "acht": 8, "sieben": 7, "sechs": 6,
    }
    for path, text, label in (
        (PLAN, plan, "IMPLEMENTATION_PLAN.md"),
        (SPEC, spec, "SPECIFICATION.md"),
        (README, read(README) if README.exists() else "", "README.md"),
    ):
        if not text:
            continue
        for m in re.finditer(r"\b(\d+)\s+Crates?\b", text):
            claimed = int(m.group(1))
            # „22" in trinity-verify-Kontext etc. — nur Workspace-Anzahlen nahe crates/
            start = max(0, m.start() - 60)
            window = text[start:m.end() + 40]
            if re.search(r"workspace|Workspace|1\.1|Gerüst|crates/", window, re.I):
                rep.check(
                    claimed == n_disk,
                    f"{label}: nennt {claimed} Crates (Workspace-Kontext), auf Disk sind {n_disk}",
                )
        for word, n in word_to_n.items():
            for m in re.finditer(rf"\b{word}\s+Crates?\b", text, re.I):
                start = max(0, m.start() - 60)
                window = text[start:m.end() + 40]
                if re.search(r"workspace|Workspace|1\.1|Gerüst|crates/", window, re.I):
                    rep.check(
                        n == n_disk,
                        f"{label}: nennt '{word} Crates' (= {n}), auf Disk sind {n_disk}",
                    )
    rep.checks_run += 1

    # 4) „N externe Crates" == MEASURED aus dep_budget.py
    measured = measured_external_from_dep_budget()
    if measured is None:
        rep.fail("scripts/dep_budget.py: Konstante MEASURED fehlt oder ist nicht lesbar")
    else:
        for path, text, label in (
            (SPEC, spec, "SPECIFICATION.md"),
            (PLAN, plan, "IMPLEMENTATION_PLAN.md"),
            (TESTING, read(TESTING), "TESTING.md"),
            (README, read(README) if README.exists() else "", "README.md"),
        ):
            if not text:
                continue
            for m in re.finditer(r"(\d+)\s+externe Crates", text):
                claimed = int(m.group(1))
                rep.check(
                    claimed == measured,
                    f"{label}: nennt {claimed} externe Crates, MEASURED in dep_budget.py ist {measured}",
                )
        rep.checks_run += 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true", help="gefundene IDs auflisten")
    args = parser.parse_args()

    spec, plan = read(SPEC), read(PLAN)

    if args.list:
        for kind, label in (
            ("D", "Differential"),
            ("P", "Property"),
            ("S", "Szenario"),
            ("T", "Bedrohung"),
            ("E", "Entscheidung"),
            ("O", "Offen"),
        ):
            found = sort_ids(ids_by_kind(spec, kind))
            print(f"{label:14s} ({len(found):3d}): {', '.join(found)}")
        return 0

    rep = Report()
    blocks = parse_wp_blocks(plan)

    check_unique_definitions(spec, rep)
    check_test_ownership(spec, blocks, rep)
    check_decisions_mapped(spec, plan, rep)
    check_threats_handled(spec, rep)
    check_sections(rep)
    check_wp_structure(plan, blocks, rep)
    check_dependencies(blocks, rep)
    check_tests_exist(spec, blocks, rep)
    check_numbers(spec, plan, rep)

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
