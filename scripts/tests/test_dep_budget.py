#!/usr/bin/env python3
"""Unit tests for target-deterministic signature-path dependency budget."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

SCRIPTS = Path(__file__).resolve().parents[1]
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import dep_budget  # noqa: E402


class RecordingRunner:
    """Fake subprocess runner: records argv and returns canned tree output."""

    def __init__(self, trees: dict[tuple[str, str], str]) -> None:
        self.trees = trees
        self.calls: list[list[str]] = []

    def __call__(self, cmd, **_kwargs):  # type: ignore[no-untyped-def]
        self.calls.append(list(cmd))
        # cmd: cargo tree -p CRATE ... --target TARGET
        crate = cmd[cmd.index("-p") + 1]
        target = cmd[cmd.index("--target") + 1]
        key = (crate, target)
        if key not in self.trees:
            raise AssertionError(f"unexpected cargo tree call: {key}")
        return SimpleNamespace(stdout=self.trees[key], returncode=0)


def tree_stdout(*names: str) -> str:
    return "\n".join(f"{n} v1.0.0" for n in names) + "\n"


class TestCargoTreeCommand(unittest.TestCase):
    def test_target_always_present(self) -> None:
        cmd = dep_budget.cargo_tree_command("trinity-types", "aarch64-apple-ios")
        self.assertIn("--target", cmd)
        self.assertEqual(cmd[cmd.index("--target") + 1], "aarch64-apple-ios")
        self.assertNotIn("None", cmd)

    def test_empty_target_rejected(self) -> None:
        with self.assertRaises(ValueError):
            dep_budget.cargo_tree_command("trinity-types", "")


class TestParseCargoTree(unittest.TestCase):
    def test_parses_names(self) -> None:
        out = tree_stdout("bitcoin", "secp256k1", "trinity-types")
        self.assertEqual(
            dep_budget.parse_cargo_tree(out),
            {"bitcoin", "secp256k1", "trinity-types"},
        )


class TestWorkspacePackageDiscovery(unittest.TestCase):
    def test_discovers_from_local_manifests(self) -> None:
        names = dep_budget.workspace_package_names()
        self.assertIn("trinity-types", names)
        self.assertIn("trinity-watch", names)
        # Not a hardcoded ten-crate baseline — just that discovery sees real crates.
        self.assertGreaterEqual(len(names), len(dep_budget.SIGNATURE_PATH))

    def test_package_name_from_manifest(self) -> None:
        text = '[package]\nname = "trinity-watch"\nversion = "0.1.0"\n'
        self.assertEqual(dep_budget.package_name_from_manifest(text), "trinity-watch")

    def test_missing_crates_dir_raises(self) -> None:
        missing = Path("/tmp/definitely-missing-trinity-crates-for-dep-budget")
        with self.assertRaises(FileNotFoundError) as ctx:
            dep_budget.workspace_package_names(missing)
        self.assertIn("missing", str(ctx.exception).lower())

    def test_manifest_without_package_name_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            crates = Path(tmp) / "crates"
            pkg = crates / "broken"
            pkg.mkdir(parents=True)
            (pkg / "Cargo.toml").write_text(
                "[package]\nversion = \"0.1.0\"\n", encoding="utf-8"
            )
            with self.assertRaises(RuntimeError) as ctx:
                dep_budget.workspace_package_names(crates)
            self.assertIn("[package] name", str(ctx.exception))


class TestMeasureSignaturePath(unittest.TestCase):
    def setUp(self) -> None:
        # Minimal two-target world: android pulls an extra crate the iOS
        # tree does not — union must include it.
        self.crates = ["trinity-types", "trinity-verify"]
        self.targets = ("aarch64-apple-ios", "aarch64-linux-android")
        # own_packages includes a non-signature workspace crate so tests do
        # not depend on scanning the real tree when using injected runners.
        self.own = frozenset(
            {"trinity-types", "trinity-verify", "trinity-watch", "trinity-chain"}
        )
        self.trees: dict[tuple[str, str], str] = {}
        for crate in self.crates:
            self.trees[(crate, "aarch64-apple-ios")] = tree_stdout(
                crate, "shared-dep", "ios-only-dep"
            )
            self.trees[(crate, "aarch64-linux-android")] = tree_stdout(
                crate, "shared-dep", "android-only-dep"
            )

    def test_union_includes_target_specific_dependencies(self) -> None:
        runner = RecordingRunner(self.trees)
        external, per_crate = dep_budget.measure_signature_path(
            targets=self.targets,
            crates=self.crates,
            runner=runner,
            own_packages=self.own,
        )
        self.assertIn("shared-dep", external)
        self.assertIn("ios-only-dep", external)
        self.assertIn("android-only-dep", external)
        self.assertNotIn("trinity-types", external)
        self.assertNotIn("trinity-verify", external)
        # per-crate/target reporting preserved
        self.assertEqual(per_crate["trinity-types"]["aarch64-apple-ios"], 2)
        self.assertEqual(per_crate["trinity-types"]["aarch64-linux-android"], 2)

    def test_non_signature_workspace_crate_is_not_external(self) -> None:
        """A future edge into trinity-watch must not count as an external crate."""
        trees: dict[tuple[str, str], str] = {}
        for crate in self.crates:
            for target in self.targets:
                trees[(crate, target)] = tree_stdout(
                    crate, "shared-dep", "trinity-watch", "bitcoin"
                )
        runner = RecordingRunner(trees)
        external, per_crate = dep_budget.measure_signature_path(
            targets=self.targets,
            crates=self.crates,
            runner=runner,
            own_packages=self.own,
        )
        self.assertIn("bitcoin", external)
        self.assertIn("shared-dep", external)
        self.assertNotIn("trinity-watch", external)
        # per-crate counts exclude workspace packages too
        self.assertEqual(per_crate["trinity-types"]["aarch64-apple-ios"], 2)

    def test_every_invocation_passes_target(self) -> None:
        runner = RecordingRunner(self.trees)
        dep_budget.measure_signature_path(
            targets=self.targets,
            crates=self.crates,
            runner=runner,
            own_packages=self.own,
        )
        self.assertEqual(len(runner.calls), len(self.crates) * len(self.targets))
        for cmd in runner.calls:
            self.assertIn("--target", cmd)
            target = cmd[cmd.index("--target") + 1]
            self.assertIn(target, self.targets)

    def test_shipped_targets_are_both_declared(self) -> None:
        """Regression: measuring only one target must be detectable as incomplete."""
        self.assertEqual(
            set(dep_budget.SHIPPED_TARGETS),
            {"aarch64-apple-ios", "aarch64-linux-android"},
        )
        self.assertEqual(len(dep_budget.SHIPPED_TARGETS), 2)

    def test_measuring_only_one_target_misses_union_members(self) -> None:
        """A plausible regression (single-target measure) must fail this test.

        If someone later hard-codes a single target, the union loses
        target-specific crates — this assertion is the tripwire.
        """
        runner_both = RecordingRunner(self.trees)
        full, _ = dep_budget.measure_signature_path(
            targets=self.targets,
            crates=self.crates,
            runner=runner_both,
            own_packages=self.own,
        )
        runner_one = RecordingRunner(self.trees)
        partial, _ = dep_budget.measure_signature_path(
            targets=("aarch64-apple-ios",),
            crates=self.crates,
            runner=runner_one,
            own_packages=self.own,
        )
        self.assertIn("android-only-dep", full)
        self.assertNotIn("android-only-dep", partial)
        # Production defaults must use the full shipped set, not the partial.
        self.assertEqual(
            tuple(dep_budget.SHIPPED_TARGETS),
            ("aarch64-apple-ios", "aarch64-linux-android"),
        )
        self.assertGreater(len(full), len(partial))

    def test_default_measure_uses_all_shipped_targets(self) -> None:
        """Calls with default targets must hit every SHIPPED_TARGETS entry."""
        # Build trees for the real signature path names × shipped targets.
        trees: dict[tuple[str, str], str] = {}
        for crate in dep_budget.SIGNATURE_PATH:
            for target in dep_budget.SHIPPED_TARGETS:
                trees[(crate, target)] = tree_stdout(crate, "common-dep")
        runner = RecordingRunner(trees)
        own = frozenset(dep_budget.SIGNATURE_PATH)
        external, _ = dep_budget.measure_signature_path(
            runner=runner, own_packages=own
        )
        self.assertEqual(external, ["common-dep"])
        targets_seen = {
            cmd[cmd.index("--target") + 1] for cmd in runner.calls
        }
        self.assertEqual(targets_seen, set(dep_budget.SHIPPED_TARGETS))
        self.assertEqual(
            len(runner.calls),
            len(dep_budget.SIGNATURE_PATH) * len(dep_budget.SHIPPED_TARGETS),
        )


if __name__ == "__main__":
    unittest.main()
