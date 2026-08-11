#!/usr/bin/env python3
"""Checks specification, implementation plan, and test code against each other.

Implements TESTING.md §6. Runs in CI as its own step and fails the build when
the documents drift apart.

Rule: any situation this script cannot resolve unambiguously is a finding with
exit 1 — never silent continuation.

Usage:
    python3 scripts/check_plan.py            # all checks
    python3 scripts/check_plan.py --list     # list found IDs, do not check

Exit 0 = consistent, Exit 1 = at least one finding.
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

# Test IDs appear in the Spec as the first table column: | **D7** | ...
ID_DEF = re.compile(r"^\|\s*\*\*([DPSTEO]\d+[a-z]?)\*\*\s*\|", re.M)
# Struck-through, i.e. resolved entries: | ~~**O15**~~ |
ID_DEF_RESOLVED = re.compile(r"^\|\s*~~\*\*([DPSTEO]\d+[a-z]?)\*\*~~\s*\|", re.M)
ID_USE = re.compile(r"\b([DPS]\d+[a-z]?)\b")
SECTION_DEF = re.compile(r"^#{2,4}\s+(\d+(?:\.\d+)*)\s", re.M)
SECTION_REF = re.compile(r"(?:Section|see|§)\s*(\d+\.\d+(?:\.\d+)?)\b")
# Dedicated WP block: #### WP-nn · ...
WP_HEADING = re.compile(r"^####\s+(WP-\d+)\b", re.M)
WP_USE = re.compile(r"\b(WP-\d+)\b")
# Test functions: d1_…, p5_…, s15b_…, s29h_… (lowercase, no leading zero)
TEST_FN = re.compile(r"fn\s+([dps]\d+[a-z]?)_[a-z0-9_]+\s*\(", re.I)

VALID_STATES = frozenset({"OPEN", "BLOCKED", "IN PROGRESS", "REVIEW", "DONE"})

# Fail-closed inventory baseline (TESTING.md §6).
# Derived from the imported documents; every normative ID family and the WP
# inventory must match these counts. Deliberate inventory changes require an
# explicit update of this single map — silent empty/shrink passes are blocked.
INVENTORY_BASELINE: dict[str, int] = {
    "D": 19,
    "P": 16,
    "S": 47,
    "T": 23,
    "E": 8,
    "O": 18,
    "WP": 54,
}

# Required fields in a WP block (order irrelevant; all must appear)
REQUIRED_FIELDS = (
    "**Spec:**",
    "**Needs:**",
    "**State:**",
    "**Files:**",
    "**Prohibited:**",
    "**Acceptance**",
    "**Tests:**",
)

# Former German markers/state values must surface as findings, not be ignored.
LEFTOVER_GERMAN_MARKERS = (
    "**Zustand:**",
    "**Braucht:**",
    "**Dateien:**",
    "**Verbote:**",
    "**Abnahme**",
)
LEFTOVER_GERMAN_STATES = frozenset(
    {"OFFEN", "BLOCKIERT", "IN ARBEIT", "FERTIG"}
)

TESTS_LINE = re.compile(r"^\*\*Tests:\*\*\s*(.+?)\s*$", re.M)
STATE_LINE = re.compile(r"\*\*State:\*\*\s*([^\n*]+)")
NEEDS_LINE = re.compile(r"\*\*Needs:\*\*\s*([^\n*]+)")
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
        sys.exit(f"ERROR: {path.relative_to(ROOT)} is missing")
    return path.read_text(encoding="utf-8")


def ids_by_kind(text: str, kind: str) -> set[str]:
    """All IDs of one kind defined in `text`, including resolved ones."""
    found = set(ID_DEF.findall(text)) | set(ID_DEF_RESOLVED.findall(text))
    return {i for i in found if i[0] == kind}


def sort_ids(ids: set[str]) -> list[str]:
    def key(i: str) -> tuple[str, int, str]:
        m = re.match(r"([A-Z])(\d+)([a-z]?)", i)
        assert m
        return (m.group(1), int(m.group(2)), m.group(3))

    return sorted(ids, key=key)


def parse_wp_blocks(plan: str) -> dict[str, str]:
    """WP-ID → full block text (from heading until next WP heading or ##)."""
    blocks: dict[str, str] = {}
    matches = list(WP_HEADING.finditer(plan))
    for i, m in enumerate(matches):
        wp = m.group(1)
        start = m.start()
        if i + 1 < len(matches):
            end = matches[i + 1].start()
        else:
            # End at the next level-1/2 ## section, else end of file
            rest = plan[m.end():]
            end_m = re.search(r"\n##\s", rest)
            end = m.end() + end_m.start() if end_m else len(plan)
        body = plan[start:end]
        if wp in blocks:
            # Duplicate heading — reported in check_wp_structure
            blocks[wp] = blocks[wp] + "\n" + body
        else:
            blocks[wp] = body
    return blocks


def parse_tests_line(line_body: str) -> list[str] | None:
    """Parse the body of a **Tests:** line. None = syntactically invalid."""
    body = line_body.strip()
    if body in ("—", "-", "–"):
        return []
    # No ranges, no slashes
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
    """Test-ID → list of WPs that list it on **Tests:**."""
    owners: dict[str, list[str]] = defaultdict(list)
    for wp, body in blocks.items():
        m = TESTS_LINE.search(body)
        if not m:
            continue  # missing line → check_wp_structure
        parsed = parse_tests_line(m.group(1))
        if parsed is None:
            rep.fail(
                f"{wp}: **Tests:** line invalid "
                f"(only comma-separated IDs like D1, S15b, or —; no ranges/slashes): "
                f"{m.group(1)!r}"
            )
            continue
        for ident in parsed:
            owners[ident].append(wp)
    return owners


def inventory_counts(spec: str, blocks: dict[str, str]) -> dict[str, int]:
    """Current inventory sizes for each baseline key (D/P/S/T/E/O/WP)."""
    counts: dict[str, int] = {
        kind: len(ids_by_kind(spec, kind)) for kind in ("D", "P", "S", "T", "E", "O")
    }
    counts["WP"] = len(blocks)
    return counts


def check_inventory_baseline(
    spec: str,
    blocks: dict[str, str],
    rep: Report,
    baseline: dict[str, int] = INVENTORY_BASELINE,
) -> None:
    """Fail closed if a normative family or WP inventory empties or shrinks.

    Exact match against the baseline is required so growth also forces an
    explicit baseline update rather than drifting unnoticed.
    """
    actual = inventory_counts(spec, blocks)
    for key, expected in baseline.items():
        got = actual.get(key, 0)
        if got == 0 and expected > 0:
            rep.fail(
                f"Inventory baseline: family {key} is empty "
                f"(baseline requires {expected})"
            )
        elif got < expected:
            rep.fail(
                f"Inventory baseline: family {key} has {got}, "
                f"baseline requires {expected} — inventory shrank; "
                f"update INVENTORY_BASELINE only with a deliberate change"
            )
        elif got > expected:
            rep.fail(
                f"Inventory baseline: family {key} has {got}, "
                f"baseline requires {expected} — inventory grew; "
                f"update INVENTORY_BASELINE only with a deliberate change"
            )
        else:
            rep.checks_run += 1


def check_unique_definitions(spec: str, rep: Report) -> None:
    """No ID may be defined twice — otherwise the versions drift."""
    counts = Counter(ID_DEF.findall(spec) + ID_DEF_RESOLVED.findall(spec))
    for ident, n in sorted(counts.items()):
        rep.check(
            n == 1,
            f"ID {ident} is defined {n}× in SPECIFICATION.md (exactly 1× expected)",
        )


def check_test_ownership(spec: str, blocks: dict[str, str], rep: Report) -> None:
    """Every Spec test ID on exactly one **Tests:** line; no invented IDs."""
    spec_ids = ids_by_kind(spec, "D") | ids_by_kind(spec, "P") | ids_by_kind(spec, "S")
    owners = test_owners_from_blocks(blocks, rep)

    for ident in sort_ids(spec_ids):
        wps = owners.get(ident, [])
        if len(wps) == 0:
            rep.fail(
                f"Test {ident} is defined in SPECIFICATION.md but assigned to no WP on **Tests:**"
            )
        elif len(wps) > 1:
            rep.fail(
                f"Test {ident} is assigned {len(wps)}×: {', '.join(sorted(wps))} "
                f"(exactly one owner expected)"
            )
        else:
            rep.checks_run += 1

    for ident in sort_ids(set(owners) - spec_ids):
        wps = owners[ident]
        rep.fail(
            f"Test {ident} appears on **Tests:** of {', '.join(sorted(wps))}, "
            f"but does not exist in SPECIFICATION.md"
        )
    rep.checks_run += 1


def check_decisions_mapped(spec: str, plan: str, rep: Report) -> None:
    """Every decision E… needs an implementing work package."""
    decisions = ids_by_kind(spec, "E")
    used = set(re.findall(r"\b(E\d[a-z]?)\b", plan))
    for ident in sort_ids(decisions - used):
        rep.fail(f"Decision {ident} has no implementing WP in the implementation plan")
    rep.checks_run += 1


def check_threats_handled(spec: str, rep: Report) -> None:
    """Every threat is either tested or explicitly listed as not covered."""
    threats = ids_by_kind(spec, "T")
    uncovered_block = spec.split("### 4.2")[-1] if "### 4.2" in spec else ""
    for ident in sort_ids(threats):
        row = next(
            (ln for ln in spec.splitlines() if re.match(rf"^\|\s*\*\*{ident}\*\*\s*\|", ln)),
            "",
        )
        has_test = bool(ID_USE.search(row))
        named_uncovered = ident in uncovered_block
        rep.check(
            has_test or named_uncovered,
            f"Threat {ident} names neither a test nor appears in §4.2 as not covered",
        )


def check_sections(rep: Report) -> None:
    """No section reference may point into the void — including README.md."""
    spec = read(SPEC)
    defined = set(SECTION_DEF.findall(spec))
    for path in (SPEC, PLAN, TESTING, RECOVERY, README):
        if not path.exists():
            continue
        text = read(path)
        for ref in sorted(set(SECTION_REF.findall(text))):
            if ref in defined:
                continue
            rep.fail(
                f"{path.name}: reference to Section {ref}, "
                f"which does not exist in SPECIFICATION.md"
            )
        rep.checks_run += 1


def check_wp_structure(plan: str, blocks: dict[str, str], rep: Report) -> None:
    """Every referenced WP has its own block; required fields and valid state."""
    referenced = set(WP_USE.findall(plan))
    for wp in sorted(referenced - set(blocks)):
        rep.fail(f"{wp} is referenced in the plan but has no dedicated #### block")
    rep.checks_run += 1

    for wp, body in sorted(blocks.items()):
        for leftover in LEFTOVER_GERMAN_MARKERS:
            if leftover in body:
                rep.fail(
                    f"{wp}: leftover German marker {leftover} "
                    f"(expected English field names)"
                )

        for field in REQUIRED_FIELDS:
            rep.check(field in body, f"{wp}: required field {field} missing from WP block")

        sm = STATE_LINE.search(body)
        if sm:
            state = sm.group(1).strip()
            # State may be "BLOCKED (reason)" — check base word
            base = state.split("(")[0].strip()
            if base in LEFTOVER_GERMAN_STATES:
                rep.fail(
                    f"{wp}: leftover German state value {base!r} "
                    f"(expected English: {', '.join(sorted(VALID_STATES))})"
                )
            else:
                rep.check(
                    base in VALID_STATES,
                    f"{wp}: **State:** {state!r} is invalid "
                    f"(allowed: {', '.join(sorted(VALID_STATES))})",
                )
        # else: missing **State:** already reported above


def check_dependencies(blocks: dict[str, str], rep: Report) -> None:
    """Every WP-ID in **Needs:** exists; no cycle in the dependency graph."""
    graph: dict[str, list[str]] = {}
    for wp, body in blocks.items():
        bm = NEEDS_LINE.search(body)
        deps: list[str] = []
        if bm:
            raw = bm.group(1).strip()
            if raw not in ("—", "-", "–", ""):
                deps = WP_USE.findall(raw)
                for dep in deps:
                    if dep not in blocks:
                        rep.fail(
                            f"{wp}: **Needs:** names {dep}, which has no dedicated block"
                        )
        graph[wp] = deps
    rep.checks_run += 1

    # Cycle detection (DFS)
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
        rep.fail(f"Cycle in the dependency graph: {' → '.join(cycle_found)}")
    else:
        rep.checks_run += 1


def wp_states(blocks: dict[str, str]) -> dict[str, str]:
    """State per work package from the WP blocks.

    Missing **State:** is already a structure finding. Unknown values must not
    silently default to OPEN — callers that need a default for "not yet DONE"
    use the empty string so comparison with DONE fails closed.
    """
    states: dict[str, str] = {}
    for wp, body in blocks.items():
        sm = STATE_LINE.search(body)
        if sm:
            states[wp] = sm.group(1).strip().split("(")[0].strip()
        else:
            # No silent OPEN default: treat as non-DONE so test-due logic stays
            # fail-closed; missing field is already reported elsewhere.
            states[wp] = ""
    return states


def test_owners_unique(blocks: dict[str, str]) -> dict[str, str]:
    """Test-ID → owner WP (unique only; duplicates reported elsewhere)."""
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
    """A test ID needs a test function once its WP is DONE."""
    spec_ids = ids_by_kind(spec, "D") | ids_by_kind(spec, "P") | ids_by_kind(spec, "S")
    states = wp_states(blocks)
    owners = test_owners_unique(blocks)

    sources = list(CRATES.rglob("*.rs")) if CRATES.exists() else []
    implemented: set[str] = set()
    for src in sources:
        implemented |= {m.lower() for m in TEST_FN.findall(src.read_text(encoding="utf-8"))}

    due = {i for i in spec_ids if states.get(owners.get(i, ""), "") == "DONE"}
    for ident in sort_ids({i for i in due if i.lower() not in implemented}):
        rep.fail(
            f"Test {ident} is missing as a test function, although {owners[ident]} is DONE "
            f"(expected: fn {ident.lower()}_…)"
        )
    rep.checks_run += 1

    done = sum(1 for v in states.values() if v == "DONE")
    print(
        f"  {done}/{len(states)} WP done · {len(due)} test IDs due · "
        f"{len(spec_ids) - len(due)} still pending"
    )


def count_release_criteria(spec: str) -> int:
    """Number of criteria in SPECIFICATION.md §5.5 (numbered table rows)."""
    if "### 5.5" not in spec:
        return -1
    section = spec.split("### 5.5", 1)[1]
    # Next ## section ends it
    section = re.split(r"\n##\s", section, maxsplit=1)[0]
    rows = re.findall(r"^\|\s*\*?\*?(\d+[a-z]?)\*?\*?\s*\|", section, re.M)
    return len(rows)


def crates_on_disk() -> list[str]:
    if not CRATES.exists():
        return []
    return sorted(p.name for p in CRATES.iterdir() if p.is_dir() and (p / "Cargo.toml").exists())


def crates_in_spec_11(spec: str) -> list[str]:
    """Crate names from the workspace tree in §1.1 (only under crates/)."""
    m = re.search(r"### 1\.1\b", spec)
    if not m:
        return []
    rest = spec[m.end():]
    end = re.search(r"\n### 1\.2\b", rest)
    block = rest[: end.start()] if end else rest[:4000]
    # Only lines under crates/…/trinity-* — not platform/android/trinity-platform
    crates_sec = block
    if "├── crates/" in block:
        crates_sec = block.split("├── crates/", 1)[1]
        # Platform tree starts with platform/
        if "├── platform/" in crates_sec:
            crates_sec = crates_sec.split("├── platform/", 1)[0]
        elif "└── platform/" in crates_sec:
            crates_sec = crates_sec.split("└── platform/", 1)[0]
    return sorted(set(re.findall(r"\b(trinity-[a-z0-9-]+)/", crates_sec)))


def measured_external_from_dep_budget() -> int | None:
    """Read the MEASURED constant from scripts/dep_budget.py."""
    if not DEP_BUDGET.exists():
        return None
    text = DEP_BUDGET.read_text(encoding="utf-8")
    m = re.search(r"^MEASURED\s*=\s*(\d+)\b", text, re.M)
    if not m:
        return None
    return int(m.group(1))


def check_numbers(spec: str, plan: str, rep: Report) -> None:
    """Hold document numbers against computed values."""
    # 1) Release criteria §5.5
    n_criteria = count_release_criteria(spec)
    if n_criteria < 0:
        rep.fail("SPECIFICATION.md: Section §5.5 not found")
    else:
        for path, text, label in (
            (PLAN, plan, "IMPLEMENTATION_PLAN.md"),
            (TESTING, read(TESTING), "TESTING.md"),
        ):
            for m in re.finditer(
                r"(\d+)\s+criteria(?:\s+from\s+(?:SPECIFICATION\.md\s+)?(?:§\s*)?5\.5|.*?5\.5)",
                text,
            ):
                claimed = int(m.group(1))
                rep.check(
                    claimed == n_criteria,
                    f"{label}: claims {claimed} criteria for §5.5, counted {n_criteria}",
                )
            # also "All N criteria" / "the N criteria in … 5.5"
            for m in re.finditer(r"(?:All|all|the)\s+(\d+)\s+criteria", text):
                # only when near 5.5 / release
                start = max(0, m.start() - 80)
                end = min(len(text), m.end() + 80)
                window = text[start:end]
                if "5.5" in window or "release" in window.lower():
                    claimed = int(m.group(1))
                    rep.check(
                        claimed == n_criteria,
                        f"{label}: claims {claimed} criteria (release/5.5 context), "
                        f"counted {n_criteria}",
                    )
        rep.checks_run += 1

    # 2) Number of WP blocks vs. places that name them
    blocks = parse_wp_blocks(plan)
    n_wp = len(blocks)
    if README.exists():
        readme = read(README)
        for m in re.finditer(r"(\d+)\s+work packages", readme):
            claimed = int(m.group(1))
            rep.check(
                claimed == n_wp,
                f"README.md: claims {claimed} work packages, counted {n_wp} WP blocks",
            )
    rep.checks_run += 1

    # 3) Crates on disk vs. §1.1 vs. places with crate counts
    on_disk = crates_on_disk()
    in_spec = crates_in_spec_11(spec)
    n_disk = len(on_disk)
    if set(on_disk) != set(in_spec):
        only_disk = sorted(set(on_disk) - set(in_spec))
        only_spec = sorted(set(in_spec) - set(on_disk))
        parts = []
        if only_disk:
            parts.append(f"only on disk: {', '.join(only_disk)}")
        if only_spec:
            parts.append(f"only in §1.1: {', '.join(only_spec)}")
        rep.fail(
            f"Crate list diverges ({'; '.join(parts)}; disk={n_disk}, §1.1={len(in_spec)})"
        )
    else:
        rep.checks_run += 1

    # "nine/ten/N crates" in plan and spec
    word_to_n = {
        "nine": 9, "ten": 10, "eleven": 11, "twelve": 12,
        "eight": 8, "seven": 7, "six": 6,
    }
    for path, text, label in (
        (PLAN, plan, "IMPLEMENTATION_PLAN.md"),
        (SPEC, spec, "SPECIFICATION.md"),
        (README, read(README) if README.exists() else "", "README.md"),
    ):
        if not text:
            continue
        for m in re.finditer(r"\b(\d+)\s+[Cc]rates?\b", text):
            claimed = int(m.group(1))
            # "22" in trinity-verify context etc. — only workspace counts near crates/
            start = max(0, m.start() - 60)
            window = text[start:m.end() + 40]
            if re.search(r"workspace|Workspace|1\.1|scaffold|crates/", window, re.I):
                rep.check(
                    claimed == n_disk,
                    f"{label}: claims {claimed} crates (workspace context), "
                    f"on disk there are {n_disk}",
                )
        for word, n in word_to_n.items():
            for m in re.finditer(rf"\b{word}\s+[Cc]rates?\b", text, re.I):
                start = max(0, m.start() - 60)
                window = text[start:m.end() + 40]
                if re.search(r"workspace|Workspace|1\.1|scaffold|crates/", window, re.I):
                    rep.check(
                        n == n_disk,
                        f"{label}: claims '{word} crates' (= {n}), "
                        f"on disk there are {n_disk}",
                    )
    rep.checks_run += 1

    # 4) "N external crates" == MEASURED from dep_budget.py
    measured = measured_external_from_dep_budget()
    if measured is None:
        rep.fail("scripts/dep_budget.py: MEASURED constant missing or unreadable")
    else:
        for path, text, label in (
            (SPEC, spec, "SPECIFICATION.md"),
            (PLAN, plan, "IMPLEMENTATION_PLAN.md"),
            (TESTING, read(TESTING), "TESTING.md"),
            (README, read(README) if README.exists() else "", "README.md"),
        ):
            if not text:
                continue
            for m in re.finditer(r"(\d+)\s+external crates", text):
                claimed = int(m.group(1))
                rep.check(
                    claimed == measured,
                    f"{label}: claims {claimed} external crates, "
                    f"MEASURED in dep_budget.py is {measured}",
                )
        rep.checks_run += 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true", help="list found IDs")
    args = parser.parse_args()

    spec, plan = read(SPEC), read(PLAN)

    if args.list:
        for kind, label in (
            ("D", "Differential"),
            ("P", "Property"),
            ("S", "Scenario"),
            ("T", "Threat"),
            ("E", "Decision"),
            ("O", "Open"),
        ):
            found = sort_ids(ids_by_kind(spec, kind))
            print(f"{label:14s} ({len(found):3d}): {', '.join(found)}")
        return 0

    rep = Report()
    blocks = parse_wp_blocks(plan)

    check_inventory_baseline(spec, blocks, rep)
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
        print(f"check-plan: {len(rep.findings)} finding(s)\n")
        for finding in rep.findings:
            print(f"  ✗ {finding}")
        print("\nThe documents are not consistent. See TESTING.md §6.")
        return 1

    print(f"check-plan: {rep.checks_run} checks, no findings.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
