from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "ralph_efficiency.py"
spec = importlib.util.spec_from_file_location("ralph_efficiency_test_module", MODULE_PATH)
eff = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(eff)


class EfficiencyPolicyTests(unittest.TestCase):
    def test_defaults_are_safe_and_normal(self):
        policy = eff.normalize_policy(None)
        self.assertEqual(policy["mode"], "NORMAL")
        self.assertEqual(policy["reserve_percent"], 5.0)
        self.assertEqual(policy["prompt_command_budget"], 6)
        self.assertEqual(eff.limits(policy, "NORMAL")["commands"], 8)
        self.assertEqual(eff.limits(policy, "RELAXED")["commands"], 32)
        self.assertEqual(eff.runaway_limits(policy)["commands"], 40)

    def test_policy_is_atomically_persisted_and_revisioned(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            first = eff.ensure_policy(root)
            updated = eff.save_policy(root, {"mode": "RELAXED", "reserve_percent": 7.5})
            loaded = eff.load_policy(root)
            self.assertEqual(first["mode"], "NORMAL")
            self.assertEqual(updated["mode"], "RELAXED")
            self.assertEqual(loaded["reserve_percent"], 7.5)
            self.assertGreater(updated["revision"], first["revision"])
            self.assertFalse((root / ".ralph" / "efficiency-policy.json.tmp").exists())

    def test_reset_restores_every_default(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            eff.ensure_policy(root)
            eff.save_policy(
                root,
                {
                    "mode": "RELAXED",
                    "reserve_percent": 11,
                    "prompt_command_budget": 9,
                    "normal_max_commands": 10,
                    "runaway_max_commands": 50,
                },
            )
            reset = eff.save_policy(root, {}, replace=True)
            self.assertEqual(reset["mode"], "NORMAL")
            self.assertEqual(reset["reserve_percent"], 5.0)
            self.assertEqual(reset["prompt_command_budget"], 6)
            self.assertEqual(reset["normal_max_commands"], 8)
            self.assertEqual(reset["runaway_max_commands"], 40)

    def test_runaway_ceiling_cannot_undercut_relaxed_policy(self):
        with self.assertRaisesRegex(ValueError, "runaway_max_commands"):
            eff.normalize_policy(
                {
                    "normal_max_commands": 20,
                    "relaxed_multiplier": 4,
                    "runaway_max_commands": 60,
                }
            )

    def test_strict_and_relaxed_multipliers_are_live_policy_values(self):
        policy = eff.normalize_policy(
            {
                "strict_multiplier": 0.5,
                "relaxed_multiplier": 2.0,
                "runaway_max_commands": 40,
                "runaway_max_reported_files": 64,
                "runaway_max_cumulative_input": 3_000_000,
                "runaway_max_noncached_input": 500_000,
            }
        )
        self.assertEqual(eff.limits(policy, "STRICT")["commands"], 4)
        self.assertEqual(eff.limits(policy, "RELAXED")["commands"], 16)


if __name__ == "__main__":
    unittest.main()
