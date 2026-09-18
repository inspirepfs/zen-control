from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "ralph.py"
spec = importlib.util.spec_from_file_location("ralph_plan_bounds", MODULE_PATH)
ralph = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(ralph)


def plan(count: int, minimum: int = 1, maximum: int = 20) -> dict:
    return {
        "goal": "Exercise operator-selected plan bounds",
        "planning": {"min_steps": minimum, "max_steps": maximum},
        "steps": [
            {
                "id": i,
                "title": f"Step {i}",
                "objective": f"Objective {i}",
                "acceptance": [f"Acceptance {i}"],
                "test_change_policy": "none",
            }
            for i in range(1, count + 1)
        ],
    }


class PlanBoundsTests(unittest.TestCase):
    def test_defaults_preserve_existing_five_to_ten_contract(self):
        self.assertEqual(ralph.proposal_step_bounds(), (5, 10))

    def test_operator_bounds_are_validated(self):
        self.assertEqual(ralph.proposal_step_bounds(2, 7), (2, 7))
        with self.assertRaisesRegex(ValueError, "at least 1"):
            ralph.proposal_step_bounds(0, 7)
        with self.assertRaisesRegex(ValueError, "greater than or equal"):
            ralph.proposal_step_bounds(8, 7)
        with self.assertRaisesRegex(ValueError, "must not exceed 20"):
            ralph.proposal_step_bounds(1, 21)

    def test_plan_validation_uses_bound_plan_size(self):
        ralph.validate_plan(plan(3, 2, 4))
        with self.assertRaisesRegex(ValueError, "2-4 steps"):
            ralph.validate_plan(plan(5, 2, 4))

    def test_plan_hash_binds_planning_bounds(self):
        first = plan(3, 2, 4)
        second = plan(3, 3, 4)
        self.assertNotEqual(ralph.plan_hash(first), ralph.plan_hash(second))

    def test_prompt_and_rendering_expose_selected_bounds(self):
        prompt = ralph.plan_prompt("Bounded goal", min_steps=2, max_steps=6)
        self.assertIn("Return between 2 and 6 ordered", prompt)
        rendered = ralph.render_plan(plan(3, 2, 6))
        self.assertIn("Plan size:** `2-6` steps", rendered)

    def test_cli_exposes_bounds_for_new_and_replacement_proposals(self):
        parser = ralph.build_parser()
        args = parser.parse_args(["propose", "--goal", "A sufficiently long bounded engineering goal", "--min-steps", "2", "--max-steps", "6"])
        self.assertEqual((args.min_steps, args.max_steps), (2, 6))
        replacement = parser.parse_args(["propose", "--from-retirement", "RT-1", "--min-steps", "1", "--max-steps", "4"])
        self.assertEqual((replacement.min_steps, replacement.max_steps), (1, 4))


if __name__ == "__main__":
    unittest.main()
