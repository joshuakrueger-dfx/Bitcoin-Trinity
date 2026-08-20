#!/usr/bin/env python3
"""Reject former GitHub Actions workflow defects (stdlib only).

These tests encode the repository's intended invariants for
`.github/workflows/ci.yml`. They are not a general YAML parser and do not
claim that GitHub has accepted the workflow — only that the checked-in file
matches the audited pins and structure.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"

# Audited remote action → full 40-hex commit SHA (deliberate map update required).
AUDITED_ACTIONS: dict[str, str] = {
    "actions/checkout": "3d3c42e5aac5ba805825da76410c181273ba90b1",
    "dtolnay/rust-toolchain": "6c977a6ca4077a0ceb28ffbe03f59d46e9ac8772",
    "Swatinem/rust-cache": "6323deb102c322ba6fcbdcafc7e3dddab59af2b6",
    "taiki-e/install-action": "7f4eb899022d8fe70b20c4f3de697aa85c309026",
}

# Audited cargo tool pins for taiki-e/install-action tool@x.y.z.
AUDITED_TOOLS: dict[str, str] = {
    "cargo-deny": "0.20.2",
    "cargo-audit": "0.22.2",
    "cargo-llvm-cov": "0.8.7",
    "cargo-mutants": "27.1.0",
}

# Exact top-level permissions for this read-only CI.
EXPECTED_PERMISSIONS: dict[str, str] = {
    "contents": "read",
}

ALWAYS_ON_JOBS = frozenset({"check", "test", "supply-chain", "coverage"})
MAIN_ONLY_JOBS = frozenset({"signet", "mutants"})

SHA40 = re.compile(r"^[0-9a-f]{40}$")
JOB_HEADER = re.compile(r"^  ([A-Za-z0-9_-]+):\s*$")
JOB_LEVEL_IF = re.compile(r"^    if:\s*(.+)$")
TOOL_LINE = re.compile(r"^\s*tool:\s*(.+?)\s*$")
# Step list item: "- uses: ref" OR "uses: ref" indented under a named step.
USES_INLINE = re.compile(r"^(\s*)-\s*uses:\s*(\S+)\s*$")
USES_INDENTED = re.compile(r"^(\s+)uses:\s*(\S+)\s*$")
PERM_ENTRY = re.compile(r"^  ([A-Za-z0-9_-]+):\s*(\S+)\s*$")


def load_workflow() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def extract_uses_refs(text: str) -> list[tuple[int, str]]:
    """Return (1-based line, action@ref) for every step `uses:` in the workflow.

    Recognizes both:
      - uses: owner/action@sha
      - name: ...
        uses: owner/action@sha
    """
    found: list[tuple[int, str]] = []
    for i, line in enumerate(text.splitlines(), 1):
        m = USES_INLINE.match(line)
        if m:
            found.append((i, m.group(2)))
            continue
        m = USES_INDENTED.match(line)
        if m:
            # Ignore false positives at job/top level (uses is always under steps).
            if len(m.group(1)) >= 6:  # step body is typically 6+ spaces
                found.append((i, m.group(2)))
    return found


def job_ids(text: str) -> list[str]:
    """Parse job IDs from the top-level `jobs:` map (two-space keys)."""
    ids: list[str] = []
    in_jobs = False
    for line in text.splitlines():
        if line.startswith("jobs:"):
            in_jobs = True
            continue
        if not in_jobs:
            continue
        if line and not line.startswith(" ") and line.endswith(":"):
            break
        m = JOB_HEADER.match(line)
        if m:
            ids.append(m.group(1))
    return ids


def job_level_if_expressions(text: str) -> list[tuple[str, str]]:
    """Return (job_name, if_expression) for every job-level `if:`."""
    current_job: str | None = None
    found: list[tuple[str, str]] = []
    in_jobs = False
    for line in text.splitlines():
        if line.startswith("jobs:"):
            in_jobs = True
            continue
        if not in_jobs:
            continue
        if line and not line.startswith(" ") and line.endswith(":"):
            break
        m_job = JOB_HEADER.match(line)
        if m_job:
            current_job = m_job.group(1)
            continue
        m_if = JOB_LEVEL_IF.match(line)
        if m_if and current_job:
            found.append((current_job, m_if.group(1).strip()))
    return found


def parse_top_level_permissions(text: str) -> dict[str, str] | None:
    """Parse the top-level `permissions:` map (before `jobs:`). None if missing."""
    before_jobs = text.split("jobs:", 1)[0]
    lines = before_jobs.splitlines()
    start = None
    for i, line in enumerate(lines):
        if re.match(r"^permissions:\s*$", line):
            start = i + 1
            break
    if start is None:
        return None
    perms: dict[str, str] = {}
    for line in lines[start:]:
        if not line.strip():
            # blank line ends the block if we already saw entries; allow leading blanks
            if perms:
                break
            continue
        if not line.startswith("  "):
            break
        if line.startswith("   "):  # deeper than map entries — unexpected
            continue
        m = PERM_ENTRY.match(line)
        if m:
            perms[m.group(1)] = m.group(2)
        else:
            break
    return perms


def parse_install_tools(text: str) -> dict[str, str]:
    """Map tool name → version for every `tool: a@x,b@y` in the workflow."""
    versions: dict[str, str] = {}
    for line in text.splitlines():
        m = TOOL_LINE.match(line)
        if not m:
            continue
        raw = m.group(1).strip().strip("\"'")
        for part in re.split(r"[,\s]+", raw):
            part = part.strip()
            if not part:
                continue
            if "@" in part:
                name, ver = part.split("@", 1)
                versions[name] = ver
            else:
                versions[part] = ""
    return versions


def action_pin_findings(refs: list[tuple[int, str]]) -> list[str]:
    """Validate each uses ref against AUDITED_ACTIONS (or local ./ path)."""
    bad: list[str] = []
    for line_no, ref in refs:
        if ref.startswith("./") or ref.startswith(".\\"):
            continue  # local composite actions: allow explicitly
        if "@" not in ref:
            bad.append(f"L{line_no}: {ref} (no pin)")
            continue
        action, pin = ref.rsplit("@", 1)
        if action not in AUDITED_ACTIONS:
            bad.append(
                f"L{line_no}: unknown remote action {action!r} — "
                f"add it to AUDITED_ACTIONS with its audited SHA"
            )
            continue
        expected = AUDITED_ACTIONS[action]
        if pin != expected:
            bad.append(
                f"L{line_no}: {action} pinned to {pin!r}, "
                f"audited map requires {expected!r}"
            )
    return bad


class TestUsesExtraction(unittest.TestCase):
    def test_recognizes_multiline_named_step_uses(self) -> None:
        sample = """
jobs:
  check:
    steps:
      - name: Checkout
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
      - uses: dtolnay/rust-toolchain@6c977a6ca4077a0ceb28ffbe03f59d46e9ac8772
"""
        refs = extract_uses_refs(sample)
        actions = [r.split("@", 1)[0] for _, r in refs]
        self.assertEqual(
            actions,
            ["actions/checkout", "dtolnay/rust-toolchain"],
            "multiline `uses:` under `- name:` must be detected",
        )

    def test_counterexample_random_sha_fails_audit_map(self) -> None:
        refs = [
            (1, "actions/checkout@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        ]
        findings = action_pin_findings(refs)
        self.assertTrue(findings)
        self.assertIn("audited map requires", findings[0])

    def test_counterexample_unknown_action_requires_map_update(self) -> None:
        refs = [(1, "evil/pwn@3d3c42e5aac5ba805825da76410c181273ba90b1")]
        findings = action_pin_findings(refs)
        self.assertTrue(any("unknown remote action" in f for f in findings))


class TestPermissionsParser(unittest.TestCase):
    def test_write_scope_counterexample(self) -> None:
        sample = "permissions:\n  contents: read\n  issues: write\n\njobs:\n"
        perms = parse_top_level_permissions(sample)
        self.assertIsNotNone(perms)
        assert perms is not None
        self.assertNotEqual(perms, EXPECTED_PERMISSIONS)
        self.assertIn("issues", perms)

    def test_exact_read_only_scope(self) -> None:
        sample = "permissions:\n  contents: read\n\njobs:\n"
        self.assertEqual(parse_top_level_permissions(sample), EXPECTED_PERMISSIONS)


class TestToolPins(unittest.TestCase):
    def test_wrong_version_counterexample(self) -> None:
        sample = "        tool: cargo-deny@0.20.1,cargo-audit@0.22.2\n"
        versions = parse_install_tools(sample)
        self.assertEqual(versions.get("cargo-deny"), "0.20.1")
        self.assertNotEqual(versions.get("cargo-deny"), AUDITED_TOOLS["cargo-deny"])


class TestCiWorkflowInvariants(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = load_workflow()
        cls.lines = cls.text.splitlines()
        cls.refs = extract_uses_refs(cls.text)
        cls.jobs = job_ids(cls.text)

    def test_workflow_file_exists(self) -> None:
        self.assertTrue(WORKFLOW.is_file(), f"missing {WORKFLOW}")

    def test_every_uses_matches_audited_action_map(self) -> None:
        self.assertGreater(len(self.refs), 0, "no uses: references found")
        findings = action_pin_findings(self.refs)
        self.assertEqual(
            findings,
            [],
            "action pin findings:\n  " + "\n  ".join(findings),
        )

    def test_no_job_level_hashfiles(self) -> None:
        offenders = [
            f"{job}: {expr}"
            for job, expr in job_level_if_expressions(self.text)
            if "hashFiles" in expr
        ]
        self.assertEqual(
            offenders,
            [],
            "job-level if must not use hashFiles (unavailable there):\n  "
            + "\n  ".join(offenders),
        )

    def test_top_level_permissions_exactly_read_only(self) -> None:
        perms = parse_top_level_permissions(self.text)
        self.assertIsNotNone(perms, "top-level permissions: declaration missing")
        self.assertEqual(
            perms,
            EXPECTED_PERMISSIONS,
            f"permissions must be exactly {EXPECTED_PERMISSIONS}, got {perms}",
        )

    def test_checkout_does_not_persist_credentials(self) -> None:
        checkout_lines = [
            (i, ref)
            for i, ref in self.refs
            if ref.startswith("actions/checkout@")
        ]
        self.assertGreater(len(checkout_lines), 0, "no actions/checkout uses found")
        missing: list[str] = []
        for line_no, ref in checkout_lines:
            # Window: the uses line and the following step keys.
            idx = line_no - 1
            window = self.lines[idx : idx + 10]
            if not any(
                re.search(r"persist-credentials:\s*false\b", ln) for ln in window
            ):
                missing.append(f"L{line_no}: {ref}")
        self.assertEqual(
            missing,
            [],
            "checkout steps must set persist-credentials: false:\n  "
            + "\n  ".join(missing),
        )

    def test_selected_cargo_tools_match_audited_versions(self) -> None:
        versions = parse_install_tools(self.text)
        missing = [n for n in AUDITED_TOOLS if n not in versions]
        self.assertEqual(missing, [], f"selected tools not installed: {missing}")
        wrong: list[str] = []
        for name, expected in AUDITED_TOOLS.items():
            got = versions.get(name, "")
            if got != expected:
                wrong.append(f"{name}: got {got!r}, audited {expected!r}")
        self.assertEqual(
            wrong,
            [],
            "selected cargo tools must match audited versions:\n  "
            + "\n  ".join(wrong),
        )

    def test_install_action_fallback_disabled_when_tools_present(self) -> None:
        for line_no, ref in self.refs:
            if not ref.startswith("taiki-e/install-action@"):
                continue
            idx = line_no - 1
            window = "\n".join(self.lines[idx : idx + 12])
            if not any(t in window for t in AUDITED_TOOLS):
                continue
            self.assertRegex(
                window,
                r"fallback:\s*none\b",
                f"install-action at L{line_no} must set fallback: none "
                f"so the repository token is not passed to a fallback installer",
            )

    def test_always_on_jobs_exist_and_have_no_job_level_if(self) -> None:
        parsed = set(self.jobs)
        self.assertTrue(
            ALWAYS_ON_JOBS.issubset(parsed),
            f"missing always-on jobs: {ALWAYS_ON_JOBS - parsed}; parsed={parsed}",
        )
        job_ifs = {job: expr for job, expr in job_level_if_expressions(self.text)}
        for name in ALWAYS_ON_JOBS:
            self.assertNotIn(
                name,
                job_ifs,
                f"job {name!r} must not have a job-level if: (must always schedule)",
            )

    def test_signet_and_mutants_are_main_only(self) -> None:
        parsed = set(self.jobs)
        self.assertTrue(
            MAIN_ONLY_JOBS.issubset(parsed),
            f"missing main-only jobs: {MAIN_ONLY_JOBS - parsed}",
        )
        job_ifs = {job: expr for job, expr in job_level_if_expressions(self.text)}
        for name in MAIN_ONLY_JOBS:
            self.assertIn(name, job_ifs, f"{name} must have a job-level if for main-only")
            self.assertIn(
                "refs/heads/main",
                job_ifs[name],
                f"{name} must be restricted to main",
            )
            self.assertNotIn("hashFiles", job_ifs[name])

    def _job_body(self, job_id: str) -> str:
        lines = self.lines
        start = None
        for i, line in enumerate(lines):
            if line == f"  {job_id}:":
                start = i
                break
        self.assertIsNotNone(start, f"job `{job_id}` not found")
        assert start is not None
        end = len(lines)
        for j in range(start + 1, len(lines)):
            if JOB_HEADER.match(lines[j]):
                end = j
                break
        return "\n".join(lines[start:end])

    def test_check_job_fetches_locked_then_builds_offline(self) -> None:
        """Documented offline-build gate: fetch --locked, then build --locked --offline."""
        body = self._job_body("check")
        self.assertRegex(
            body,
            r"(?m)^\s+run:\s*cargo fetch --locked\s*$",
            "check job must run `cargo fetch --locked` before offline build",
        )
        self.assertRegex(
            body,
            r"(?m)^\s+run:\s*cargo build --workspace --locked --offline\s*$",
            "check job must build with --locked --offline after fetch",
        )
        # Order: fetch appears before offline build.
        fetch_i = body.find("cargo fetch --locked")
        build_i = body.find("cargo build --workspace --locked --offline")
        self.assertGreaterEqual(fetch_i, 0)
        self.assertGreaterEqual(build_i, 0)
        self.assertLess(fetch_i, build_i, "fetch must precede offline build")

    def test_coverage_job_probes_then_conditionally_reports(self) -> None:
        """Coverage always schedules; llvm-cov/gate only after source probe true."""
        body = self._job_body("coverage")
        # No job-level if on coverage (always-on set already checked).
        job_ifs = {job: expr for job, expr in job_level_if_expressions(self.text)}
        self.assertNotIn("coverage", job_ifs)
        self.assertNotIn("hashFiles", body)

        self.assertIn("coverage_gate.py --source-state", body)
        self.assertIn("id: source", body)
        self.assertIn("WP-03", body)

        # Toolchain / install / report / gate gated on probe output — not skipped on failure.
        self.assertRegex(
            body,
            r"if:\s*steps\.source\.outputs\.real\s*==\s*'true'",
        )
        # Branch coverage needs nightly (SPECIFICATION.md §0.3); pin job stays 1.94.1 too.
        self.assertIn(
            "cargo +nightly llvm-cov --workspace --locked --lcov --branch --output-path lcov.info",
            body,
        )
        self.assertIn("toolchain: nightly", body)
        self.assertIn('toolchain: "1.94.1"', body)
        self.assertIn("python3 scripts/coverage_gate.py lcov.info", body)

        # Probe step must not be conditioned on real==true (always runs after checkout).
        probe_idx = body.find("Probe for non-scaffold source")
        self.assertGreaterEqual(probe_idx, 0)
        # After probe heading, the run block should invoke --source-state without
        # an if: real==true on the same step (probe defines real).
        probe_chunk = body[probe_idx : probe_idx + 600]
        self.assertIn("--source-state", probe_chunk)
        self.assertNotIn(
            "if: steps.source.outputs.real == 'true'",
            probe_chunk.split("run:")[0],
        )

    def test_trinity_skip_live_only_on_jobs_without_test_env(self) -> None:
        """Live tests fail loud unless TRINITY_SKIP_LIVE is set.

        Unit · Property and Coverage run without ./scripts/test-env.sh, so
        they must set the variable. Differential starts the environment and
        must not, or a missing peer would skip instead of fail the job.
        """
        before_jobs = self.text.split("jobs:", 1)[0]
        self.assertNotIn(
            "TRINITY_SKIP_LIVE",
            before_jobs,
            "TRINITY_SKIP_LIVE must not be workflow-global (would skip Differential)",
        )
        test_body = self._job_body("test")
        self.assertRegex(
            test_body,
            r"(?m)^\s+TRINITY_SKIP_LIVE:\s*[\"']?1[\"']?\s*$",
            "Unit · Property must set TRINITY_SKIP_LIVE (no test-env in that job)",
        )
        cov_body = self._job_body("coverage")
        self.assertRegex(
            cov_body,
            r"(?m)^\s+TRINITY_SKIP_LIVE:\s*[\"']?1[\"']?\s*$",
            "Coverage gate must set TRINITY_SKIP_LIVE (llvm-cov runs tests, no test-env)",
        )
        diff_body = self._job_body("differential")
        self.assertNotRegex(
            diff_body,
            r"(?m)^\s+TRINITY_SKIP_LIVE:",
            "Differential must not set TRINITY_SKIP_LIVE so live tests run for real",
        )


if __name__ == "__main__":
    unittest.main()
