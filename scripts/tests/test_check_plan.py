#!/usr/bin/env python3
"""Unit tests for check_plan inventory baseline (fail-closed)."""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1]
ROOT = SCRIPTS.parent
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import check_plan  # noqa: E402

# Table rows that define normative Spec IDs (active or struck-through resolved).
SPEC_ID_ROW = re.compile(
    r"^\|\s*(?:~~)?\*\*[DPSTEO]\d+[a-z]?\*\*(?:~~)?\s*\|",
    re.M,
)
TESTS_LINE = re.compile(r"^(\*\*Tests:\*\*)\s*.+$", re.M)


def _spec_row(ident: str) -> str:
    return f"| **{ident}** | placeholder |\n"


def build_spec_with_counts(counts: dict[str, int]) -> str:
    """Minimal SPECIFICATION.md fragment with table-defined IDs."""
    parts = ["# Spec\n\n"]
    for kind, n in counts.items():
        if kind == "WP":
            continue
        parts.append(f"## {kind}\n\n")
        for i in range(1, n + 1):
            parts.append(_spec_row(f"{kind}{i}"))
        parts.append("\n")
    return "".join(parts)


def build_plan_with_wp_count(n: int) -> str:
    """Minimal plan with n dedicated WP blocks."""
    blocks = []
    for i in range(n):
        blocks.append(
            f"#### WP-{i:02d} · scaffold\n"
            f"**Spec:** 1.1 · **Needs:** — · **State:** OPEN\n"
            f"**Files:** x\n"
            f"**Prohibited:** none\n"
            f"**Acceptance**\n"
            f"- ok\n"
            f"**Tests:** —\n\n"
        )
    return "# Plan\n\n" + "".join(blocks)


class TestInventoryBaseline(unittest.TestCase):
    def test_baseline_constant_matches_task(self) -> None:
        self.assertEqual(
            check_plan.INVENTORY_BASELINE,
            {
                "D": 19,
                "P": 16,
                "S": 47,
                "T": 23,
                "E": 8,
                "O": 18,
                "WP": 54,
            },
        )

    def test_current_repository_inventory_passes(self) -> None:
        """Detector against the real imported documents — not a mock of itself."""
        spec = check_plan.read(check_plan.SPEC)
        plan = check_plan.read(check_plan.PLAN)
        blocks = check_plan.parse_wp_blocks(plan)
        rep = check_plan.Report()
        check_plan.check_inventory_baseline(spec, blocks, rep)
        self.assertEqual(
            rep.findings,
            [],
            "current inventory should match INVENTORY_BASELINE; findings:\n  "
            + "\n  ".join(rep.findings),
        )
        # One successful check per baseline key
        self.assertEqual(rep.checks_run, len(check_plan.INVENTORY_BASELINE))

    def test_wholesale_deletion_fails(self) -> None:
        """Removing all normative IDs and WP blocks must not vacuous-pass."""
        spec = "# Spec\n\nNo tables.\n"
        blocks: dict[str, str] = {}
        rep = check_plan.Report()
        check_plan.check_inventory_baseline(spec, blocks, rep)
        self.assertTrue(rep.findings, "empty inventory must produce findings")
        # Every family with baseline > 0 should be reported
        joined = "\n".join(rep.findings)
        for key, expected in check_plan.INVENTORY_BASELINE.items():
            if expected > 0:
                self.assertIn(
                    f"family {key}",
                    joined,
                    f"expected finding for emptied family {key}",
                )

    def test_one_family_shrinking_fails(self) -> None:
        """Dropping a single ID from one family fails the baseline check."""
        # Start from exact baseline counts, then remove one D.
        counts = {
            k: v for k, v in check_plan.INVENTORY_BASELINE.items() if k != "WP"
        }
        counts["D"] = check_plan.INVENTORY_BASELINE["D"] - 1
        spec = build_spec_with_counts(counts)
        plan = build_plan_with_wp_count(check_plan.INVENTORY_BASELINE["WP"])
        blocks = check_plan.parse_wp_blocks(plan)
        # Sanity: only D is short
        actual = check_plan.inventory_counts(spec, blocks)
        self.assertEqual(actual["D"], check_plan.INVENTORY_BASELINE["D"] - 1)
        self.assertEqual(actual["P"], check_plan.INVENTORY_BASELINE["P"])

        rep = check_plan.Report()
        check_plan.check_inventory_baseline(spec, blocks, rep)
        self.assertTrue(rep.findings)
        d_findings = [f for f in rep.findings if "family D" in f]
        self.assertEqual(len(d_findings), 1)
        self.assertIn("shrank", d_findings[0])
        # Other families should not be reported as failures
        for key in ("P", "S", "T", "E", "O", "WP"):
            self.assertFalse(
                any(f"family {key}" in f and "has" in f for f in rep.findings),
                f"unexpected finding for {key}: {rep.findings}",
            )

    def test_wp_inventory_shrinking_fails(self) -> None:
        counts = {
            k: v for k, v in check_plan.INVENTORY_BASELINE.items() if k != "WP"
        }
        spec = build_spec_with_counts(counts)
        plan = build_plan_with_wp_count(check_plan.INVENTORY_BASELINE["WP"] - 1)
        blocks = check_plan.parse_wp_blocks(plan)
        self.assertEqual(
            len(blocks), check_plan.INVENTORY_BASELINE["WP"] - 1
        )
        rep = check_plan.Report()
        check_plan.check_inventory_baseline(spec, blocks, rep)
        wp_findings = [f for f in rep.findings if "family WP" in f]
        self.assertEqual(len(wp_findings), 1)
        self.assertIn("shrank", wp_findings[0])

    def test_ids_by_kind_sees_real_spec_d_count(self) -> None:
        """Sanity: detector reads the real file the same way --list does."""
        spec = check_plan.read(check_plan.SPEC)
        n = len(check_plan.ids_by_kind(spec, "D"))
        self.assertEqual(n, check_plan.INVENTORY_BASELINE["D"])


class TestVacuousPassHoleClosed(unittest.TestCase):
    """The old script exited 0 after stripping Spec IDs and WP **Tests:** lines."""

    def test_stripped_normative_ids_fail_even_with_empty_tests_lines(self) -> None:
        # Plan with 54 WP blocks all saying **Tests:** — but empty Spec IDs.
        plan = build_plan_with_wp_count(check_plan.INVENTORY_BASELINE["WP"])
        # Ensure every block has the dash tests line (vacuous ownership pass shape)
        self.assertEqual(len(re.findall(r"\*\*Tests:\*\*\s*—", plan)), 54)
        blocks = check_plan.parse_wp_blocks(plan)
        empty_spec = "# Spec\n\nNo IDs left.\n"
        rep = check_plan.Report()
        check_plan.check_inventory_baseline(empty_spec, blocks, rep)
        # Ownership would see 0 due / 0 findings; baseline must still fail.
        owners = check_plan.test_owners_from_blocks(blocks, check_plan.Report())
        self.assertEqual(owners, {})
        self.assertTrue(
            any("family D" in f or "empty" in f for f in rep.findings),
            rep.findings,
        )


class TestMainInventoryWiring(unittest.TestCase):
    """Integration: exercise `main()` via subprocess — not the helper alone.

    The old bug: strip all normative Spec ID table rows and set every WP
    `**Tests:**` line to `—`; ownership then reported 0 due with no findings
    and exit 0. Deleting `check_inventory_baseline(...)` from `main()` must
    make this test fail; calling the helper in unit tests is not enough.
    """

    def test_main_rejects_stripped_spec_ids_and_empty_tests_lines(self) -> None:
        with tempfile.TemporaryDirectory(prefix="check-plan-fixture-") as tmp:
            fixture = Path(tmp)
            self._build_selective_fixture(fixture)
            self._strip_normative_ids_and_tests(fixture)

            script = fixture / "scripts" / "check_plan.py"
            proc = subprocess.run(
                [sys.executable, str(script)],
                cwd=str(fixture),
                capture_output=True,
                text=True,
                check=False,
            )
            combined = (proc.stdout or "") + (proc.stderr or "")
            self.assertEqual(
                proc.returncode,
                1,
                f"expected exit 1 for stripped inventory; got {proc.returncode}\n"
                f"--- stdout ---\n{proc.stdout}\n--- stderr ---\n{proc.stderr}",
            )
            self.assertRegex(
                combined,
                r"Inventory baseline",
                "main() must surface an inventory-baseline finding; "
                f"output was:\n{combined}",
            )

    def _build_selective_fixture(self, fixture: Path) -> None:
        """Copy only what check_plan.py needs — no target/, .git, or large trees."""
        (fixture / "scripts").mkdir(parents=True)
        (fixture / "docs").mkdir(parents=True)
        (fixture / "crates").mkdir(parents=True)

        shutil.copy2(ROOT / "scripts" / "check_plan.py", fixture / "scripts" / "check_plan.py")
        shutil.copy2(ROOT / "scripts" / "dep_budget.py", fixture / "scripts" / "dep_budget.py")
        for name in (
            "SPECIFICATION.md",
            "IMPLEMENTATION_PLAN.md",
            "TESTING.md",
            "RECOVERY.md",
        ):
            shutil.copy2(ROOT / "docs" / name, fixture / "docs" / name)
        shutil.copy2(ROOT / "README.md", fixture / "README.md")

        # Manifests only — enough for crates_on_disk() package discovery parity.
        for manifest in sorted((ROOT / "crates").glob("*/Cargo.toml")):
            dest_dir = fixture / "crates" / manifest.parent.name
            dest_dir.mkdir(parents=True)
            shutil.copy2(manifest, dest_dir / "Cargo.toml")

    def _strip_normative_ids_and_tests(self, fixture: Path) -> None:
        spec_path = fixture / "docs" / "SPECIFICATION.md"
        plan_path = fixture / "docs" / "IMPLEMENTATION_PLAN.md"
        spec = spec_path.read_text(encoding="utf-8")
        plan = plan_path.read_text(encoding="utf-8")

        stripped_spec_lines = [
            ln for ln in spec.splitlines(keepends=True) if not SPEC_ID_ROW.match(ln)
        ]
        stripped_spec = "".join(stripped_spec_lines)
        # Sanity: real IDs gone.
        self.assertEqual(
            len(check_plan.ids_by_kind(stripped_spec, "D")),
            0,
            "fixture Spec must have no D IDs after strip",
        )
        self.assertEqual(
            len(check_plan.ids_by_kind(stripped_spec, "S")),
            0,
        )

        stripped_plan, n_tests = TESTS_LINE.subn(r"\1 —", plan)
        self.assertGreaterEqual(
            n_tests,
            check_plan.INVENTORY_BASELINE["WP"],
            "expected to rewrite every WP **Tests:** line",
        )

        spec_path.write_text(stripped_spec, encoding="utf-8")
        plan_path.write_text(stripped_plan, encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
