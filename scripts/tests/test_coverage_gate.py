#!/usr/bin/env python3
"""Tests for coverage source probe and crate_has_source (stdlib only)."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1]
ROOT = SCRIPTS.parent
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import coverage_gate  # noqa: E402

SCAFFOLD_LIB = """//! scaffold
//!
#![forbid(unsafe_code)]
"""

REAL_FN_LIB = """//! real code
#![forbid(unsafe_code)]

pub fn hello() -> u8 {
    1
}
"""


def _write_crate(crates_dir: Path, name: str, lib_rs: str) -> Path:
    src = crates_dir / name / "src"
    src.mkdir(parents=True)
    (src / "lib.rs").write_text(lib_rs, encoding="utf-8")
    return src


def _threshold_map(*names: str) -> dict[str, tuple[float, float]]:
    return {n: (100.0, 100.0) for n in names}


def _fixture_repo_with_threshold_crates(
    root: Path, *, real_crates: frozenset[str] | set[str] = frozenset()
) -> Path:
    """Minimal repo layout: scripts/coverage_gate.py + crates/ for each THRESHOLDS name."""
    (root / "scripts").mkdir(parents=True, exist_ok=True)
    script_src = (ROOT / "scripts" / "coverage_gate.py").read_text(encoding="utf-8")
    (root / "scripts" / "coverage_gate.py").write_text(script_src, encoding="utf-8")
    crates = root / "crates"
    for name in coverage_gate.THRESHOLDS:
        body = REAL_FN_LIB if name in real_crates else SCAFFOLD_LIB
        _write_crate(crates, name, body)
    return root / "scripts" / "coverage_gate.py"


class TestCrateHasSource(unittest.TestCase):
    def test_docs_attributes_only_is_scaffold(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            crates = Path(tmp) / "crates"
            _write_crate(crates, "trinity-types", SCAFFOLD_LIB)
            self.assertFalse(
                coverage_gate.crate_has_source("trinity-types", crates_dir=crates)
            )

    def test_real_fn_makes_coverage_required(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            crates = Path(tmp) / "crates"
            _write_crate(crates, "trinity-types", REAL_FN_LIB)
            self.assertTrue(
                coverage_gate.crate_has_source("trinity-types", crates_dir=crates)
            )

    def test_additional_rs_file_makes_coverage_required(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            crates = Path(tmp) / "crates"
            src = _write_crate(crates, "trinity-types", SCAFFOLD_LIB)
            (src / "extra.rs").write_text("// empty module file\n", encoding="utf-8")
            self.assertTrue(
                coverage_gate.crate_has_source("trinity-types", crates_dir=crates)
            )

    def test_pub_const_activates_coverage(self) -> None:
        lib = "//! scaffold\n#![forbid(unsafe_code)]\n\npub const VALUE: u8 = 1;\n"
        with tempfile.TemporaryDirectory() as tmp:
            crates = Path(tmp) / "crates"
            _write_crate(crates, "c", lib)
            self.assertTrue(coverage_gate.crate_has_source("c", crates_dir=crates))

    def test_pub_type_activates_coverage(self) -> None:
        lib = "#![forbid(unsafe_code)]\npub type Amount = u64;\n"
        with tempfile.TemporaryDirectory() as tmp:
            crates = Path(tmp) / "crates"
            _write_crate(crates, "c", lib)
            self.assertTrue(coverage_gate.crate_has_source("c", crates_dir=crates))

    def test_pub_static_activates_coverage(self) -> None:
        lib = "pub static VALUE: u8 = 1;\n"
        with tempfile.TemporaryDirectory() as tmp:
            crates = Path(tmp) / "crates"
            _write_crate(crates, "c", lib)
            self.assertTrue(coverage_gate.crate_has_source("c", crates_dir=crates))

    def test_extern_crate_activates_coverage(self) -> None:
        lib = "//! docs\nextern crate alloc;\n"
        with tempfile.TemporaryDirectory() as tmp:
            crates = Path(tmp) / "crates"
            _write_crate(crates, "c", lib)
            self.assertTrue(coverage_gate.crate_has_source("c", crates_dir=crates))

    def test_include_macro_activates_coverage(self) -> None:
        lib = '#![forbid(unsafe_code)]\ninclude!("generated.rs");\n'
        with tempfile.TemporaryDirectory() as tmp:
            crates = Path(tmp) / "crates"
            _write_crate(crates, "c", lib)
            self.assertTrue(coverage_gate.crate_has_source("c", crates_dir=crates))

    def test_macro_invocation_activates_coverage(self) -> None:
        lib = "//! scaffold\n\nmy_macro!(payload);\n"
        with tempfile.TemporaryDirectory() as tmp:
            crates = Path(tmp) / "crates"
            _write_crate(crates, "c", lib)
            self.assertTrue(coverage_gate.crate_has_source("c", crates_dir=crates))

    def test_is_pure_scaffold_lib_helper(self) -> None:
        self.assertTrue(coverage_gate.is_pure_scaffold_lib(SCAFFOLD_LIB))
        self.assertFalse(coverage_gate.is_pure_scaffold_lib("pub const X: u8 = 0;\n"))


class TestAnyThresholdSource(unittest.TestCase):
    def test_full_threshold_set_all_scaffolds_is_false(self) -> None:
        """Every name in THRESHOLDS is a scaffold → probe false (fixture, not live repo)."""
        with tempfile.TemporaryDirectory() as tmp:
            crates = Path(tmp) / "crates"
            for name in coverage_gate.THRESHOLDS:
                _write_crate(crates, name, SCAFFOLD_LIB)
            self.assertFalse(
                coverage_gate.any_threshold_crate_has_source(crates_dir=crates)
            )

    def test_all_scaffolds_is_false(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            crates = Path(tmp) / "crates"
            for name in ("a", "b"):
                _write_crate(crates, name, SCAFFOLD_LIB)
            self.assertFalse(
                coverage_gate.any_threshold_crate_has_source(
                    crates_dir=crates, thresholds=_threshold_map("a", "b")
                )
            )

    def test_real_fn_makes_probe_true(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            crates = Path(tmp) / "crates"
            _write_crate(crates, "a", SCAFFOLD_LIB)
            _write_crate(crates, "b", REAL_FN_LIB)
            self.assertTrue(
                coverage_gate.any_threshold_crate_has_source(
                    crates_dir=crates, thresholds=_threshold_map("a", "b")
                )
            )

    def test_missing_crates_root_fails_closed(self) -> None:
        missing = Path("/tmp/definitely-missing-trinity-crates-dir-xyz")
        with self.assertRaises(coverage_gate.SourceProbeError) as ctx:
            coverage_gate.any_threshold_crate_has_source(
                crates_dir=missing, thresholds=_threshold_map("trinity-types")
            )
        self.assertIn("missing", str(ctx.exception).lower())

    def test_missing_expected_crate_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            crates = Path(tmp) / "crates"
            crates.mkdir()
            _write_crate(crates, "a", SCAFFOLD_LIB)
            with self.assertRaises(coverage_gate.SourceProbeError) as ctx:
                coverage_gate.any_threshold_crate_has_source(
                    crates_dir=crates, thresholds=_threshold_map("a", "missing-crate")
                )
            self.assertIn("missing-crate", str(ctx.exception))

    def test_missing_src_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            crates = Path(tmp) / "crates"
            (crates / "a").mkdir(parents=True)
            with self.assertRaises(coverage_gate.SourceProbeError) as ctx:
                coverage_gate.any_threshold_crate_has_source(
                    crates_dir=crates, thresholds=_threshold_map("a")
                )
            self.assertIn("src/", str(ctx.exception))


class TestSourceStateCli(unittest.TestCase):
    def test_subprocess_source_state_false_on_scaffold_fixture(self) -> None:
        """CLI wiring: exact `false` + exit 0 when every threshold crate is a scaffold."""
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Path(tmp)
            script = _fixture_repo_with_threshold_crates(fixture)
            proc = subprocess.run(
                [sys.executable, str(script), "--source-state"],
                cwd=str(fixture),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(proc.stdout, "false\n", repr(proc.stdout))

    def test_subprocess_source_state_true_on_real_source_fixture(self) -> None:
        """CLI wiring: exact `true` + exit 0 when one threshold crate has real source."""
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Path(tmp)
            script = _fixture_repo_with_threshold_crates(
                fixture, real_crates={"trinity-types"}
            )
            proc = subprocess.run(
                [sys.executable, str(script), "--source-state"],
                cwd=str(fixture),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(proc.stdout, "true\n", repr(proc.stdout))

    def test_subprocess_source_state_fails_on_missing_crates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Path(tmp)
            (fixture / "scripts").mkdir()
            # Minimal copy: only coverage_gate.py; it resolves ROOT as parent.parent
            script_src = (ROOT / "scripts" / "coverage_gate.py").read_text(
                encoding="utf-8"
            )
            script = fixture / "scripts" / "coverage_gate.py"
            script.write_text(script_src, encoding="utf-8")
            # No crates/ directory → probe operational error
            proc = subprocess.run(
                [sys.executable, str(script), "--source-state"],
                cwd=str(fixture),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(proc.returncode, 0)
            self.assertNotEqual(proc.stdout.strip(), "false")
            self.assertIn("ERROR", proc.stderr)

    def test_run_source_state_probe_helper_true(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            crates = Path(tmp) / "crates"
            _write_crate(crates, "a", REAL_FN_LIB)
            # Capture stdout
            import io
            from contextlib import redirect_stdout

            buf = io.StringIO()
            with redirect_stdout(buf):
                code = coverage_gate.run_source_state_probe(
                    crates_dir=crates, thresholds=_threshold_map("a")
                )
            self.assertEqual(code, 0)
            self.assertEqual(buf.getvalue(), "true\n")


if __name__ == "__main__":
    unittest.main()
