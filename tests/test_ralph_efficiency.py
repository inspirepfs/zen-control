from __future__ import annotations

import importlib.util
import json
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
    def test_defaults_are_safe_explicit_and_normal(self):
        policy = eff.normalize_policy(None)
        self.assertEqual(policy["schema"], "zen_ralph_efficiency_policy_v2")
        self.assertEqual(policy["mode"], "NORMAL")
        self.assertEqual(policy["reserve_percent"], 5.0)
        self.assertEqual(policy["normal_prompt_command_budget"], 6)
        self.assertEqual(eff.limits(policy, "STRICT")["commands"], 6)
        self.assertEqual(eff.limits(policy, "NORMAL")["commands"], 8)
        self.assertEqual(eff.limits(policy, "RELAXED")["commands"], 32)
        self.assertEqual(eff.runaway_limits(policy)["commands"], 40)

    def test_each_mode_can_have_independent_limits(self):
        policy = eff.normalize_policy({
            "strict_max_commands": 5,
            "normal_max_commands": 11,
            "relaxed_max_commands": 27,
            "strict_prompt_command_budget": 3,
            "normal_prompt_command_budget": 7,
            "relaxed_prompt_command_budget": 15,
            "runaway_max_commands": 60,
        })
        self.assertEqual(eff.limits(policy, "STRICT")["commands"], 5)
        self.assertEqual(eff.limits(policy, "NORMAL")["commands"], 11)
        self.assertEqual(eff.limits(policy, "RELAXED")["commands"], 27)
        self.assertEqual(eff.limits(policy, "STRICT")["prompt_commands"], 3)
        self.assertEqual(eff.limits(policy, "NORMAL")["prompt_commands"], 7)
        self.assertEqual(eff.limits(policy, "RELAXED")["prompt_commands"], 15)

    def test_off_uses_normal_shape_only_for_non_enforced_prompt_reference(self):
        policy = eff.normalize_policy({"normal_max_commands": 9, "runaway_max_commands": 50})
        self.assertEqual(eff.limits(policy, "OFF")["commands"], 9)
        self.assertEqual(eff.runaway_limits(policy)["commands"], 50)

    def test_policy_is_atomically_persisted_and_revisioned(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            first = eff.ensure_policy(root)
            updated = eff.save_policy(
                root,
                {"mode": "RELAXED", "reserve_percent": 7.5, "relaxed_max_commands": 30},
            )
            loaded = eff.load_policy(root)
            self.assertEqual(first["mode"], "NORMAL")
            self.assertEqual(updated["mode"], "RELAXED")
            self.assertEqual(loaded["reserve_percent"], 7.5)
            self.assertEqual(loaded["relaxed_max_commands"], 30)
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
                    "normal_prompt_command_budget": 9,
                    "normal_max_commands": 10,
                    "relaxed_max_commands": 34,
                    "runaway_max_commands": 50,
                },
            )
            reset = eff.save_policy(root, {}, replace=True)
            self.assertEqual(reset["mode"], "NORMAL")
            self.assertEqual(reset["reserve_percent"], 5.0)
            self.assertEqual(reset["normal_prompt_command_budget"], 6)
            self.assertEqual(reset["normal_max_commands"], 8)
            self.assertEqual(reset["relaxed_max_commands"], 32)
            self.assertEqual(reset["runaway_max_commands"], 40)

    def test_runaway_ceiling_cannot_undercut_any_mode(self):
        with self.assertRaisesRegex(ValueError, "runaway_max_commands"):
            eff.normalize_policy({
                "relaxed_max_commands": 61,
                "runaway_max_commands": 60,
            })

    def test_v1_policy_is_migrated_to_explicit_mode_limits(self):
        legacy = {
            "schema": "zen_ralph_efficiency_policy_v1",
            "mode": "RELAXED",
            "prompt_command_budget": 10,
            "normal_max_commands": 10,
            "normal_max_reported_files": 12,
            "normal_max_cumulative_input": 700_000,
            "normal_max_noncached_input": 120_000,
            "strict_multiplier": 0.5,
            "relaxed_multiplier": 2.0,
            "runaway_max_commands": 40,
            "runaway_max_reported_files": 64,
            "runaway_max_cumulative_input": 3_000_000,
            "runaway_max_noncached_input": 500_000,
        }
        policy = eff.normalize_policy(legacy)
        self.assertEqual(policy["schema"], "zen_ralph_efficiency_policy_v2")
        self.assertEqual(policy["normal_prompt_command_budget"], 10)
        self.assertEqual(policy["strict_prompt_command_budget"], 5)
        self.assertEqual(policy["relaxed_prompt_command_budget"], 20)
        self.assertEqual(policy["strict_max_commands"], 5)
        self.assertEqual(policy["relaxed_max_commands"], 20)
        self.assertNotIn("strict_multiplier", policy)
        self.assertNotIn("relaxed_multiplier", policy)

    def test_v1_file_migrates_on_read_without_requiring_manual_rewrite(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            path = root / ".ralph" / "efficiency-policy.json"
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps({
                "schema": "zen_ralph_efficiency_policy_v1",
                "prompt_command_budget": 8,
                "normal_max_commands": 9,
                "strict_multiplier": 0.5,
                "relaxed_multiplier": 2,
                "runaway_max_commands": 40,
            }), encoding="utf-8")
            policy = eff.load_policy(root)
            self.assertEqual(policy["normal_prompt_command_budget"], 8)
            self.assertEqual(policy["strict_max_commands"], 4)
            self.assertEqual(policy["relaxed_max_commands"], 18)


if __name__ == "__main__":
    unittest.main()
