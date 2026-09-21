from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "ralph_web.py"
spec = importlib.util.spec_from_file_location("ralph_web_plan_bounds", MODULE_PATH)
web = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = web
spec.loader.exec_module(web)


class WebPlanBoundsTests(unittest.TestCase):
    def test_new_plan_forwards_validated_bounds(self):
        state = {"status": "IDLE", "plan_hash": ""}
        req = web.command_for_action(
            {
                "action": "propose",
                "goal": "Implement bounded proposal sizing in the operator interface",
                "min_steps": 2,
                "max_steps": 7,
                "repository_authority": "write",
            },
            state,
        )
        self.assertEqual(
            req.argv,
            [
                "propose",
                "--goal",
                "Implement bounded proposal sizing in the operator interface",
                "--repository-authority",
                "write",
                "--min-steps",
                "2",
                "--max-steps",
                "7",
            ],
        )

    def test_web_rejects_invalid_bounds_before_command_launch(self):
        state = {"status": "IDLE", "plan_hash": ""}
        payload = {
            "action": "propose",
            "goal": "Implement bounded proposal sizing in the operator interface",
            "min_steps": 8,
            "max_steps": 3,
            "repository_authority": "write",
        }
        with self.assertRaisesRegex(web.WebConsoleError, "greater than or equal"):
            web.command_for_action(payload, state)

    def test_replacement_plan_forwards_latest_rt_bounds_and_optional_goal(self):
        state = {
            "status": "IDLE",
            "retired_plans": [
                {
                    "record_id": "RT-current",
                    "disposition": "RETIRED_WITH_CARRY_FORWARD",
                    "manifest_sha256": "a" * 64,
                }
            ],
        }
        req = web.command_for_action(
            {
                "action": "propose_replacement",
                "retirement_record_id": "RT-current",
                "goal": "Repair only the replacement lifecycle defect",
                "min_steps": 1,
                "max_steps": 5,
                "repository_authority": "write",
            },
            state,
        )
        self.assertEqual(
            req.argv,
            [
                "propose",
                "--from-retirement",
                "RT-current",
                "--repository-authority",
                "write",
                "--min-steps",
                "1",
                "--max-steps",
                "5",
                "--goal",
                "Repair only the replacement lifecycle defect",
            ],
        )

    def test_web_source_renders_one_shared_compact_plan_bounds_pair(self):
        source = MODULE_PATH.read_text(encoding="utf-8")

        # Human Control owns one shared plan-size pair. Normal proposals and
        # carry-forward replacements both read these same controls.
        self.assertEqual(source.count('id="planMinSteps"'), 1)
        self.assertEqual(source.count('id="planMaxSteps"'), 1)
        self.assertEqual(source.count("document.getElementById('planMinSteps')"), 2)
        self.assertEqual(source.count("document.getElementById('planMaxSteps')"), 2)

        # The old duplicated normal/replacement controls must not return.
        for marker in (
            'id="proposalMinSteps"',
            'id="proposalMaxSteps"',
            'id="replacementMinSteps"',
            'id="replacementMaxSteps"',
        ):
            self.assertNotIn(marker, source)

        # Keep the compact operator-control presentation aligned with the
        # Efficiency/Resource controls while preserving the existing payload.
        for marker in (
            'class="human-section-head"',
            'class="plan-bound-controls"',
            'class="plan-bound-field"',
            '<label for="planMinSteps">Min steps</label>',
            '<label for="planMaxSteps">Max steps</label>',
            "min_steps:minSteps",
            "max_steps:maxSteps",
        ):
            self.assertIn(marker, source)


        # Compact header controls are self-explanatory and deliberately render
        # without the blue info/help glyphs used by advanced efficiency fields.
        for marker in (
            "${info('Mode'",
            "${info('New-work reserve %'",
            'for="planMinSteps">Min steps <span class="field-help"',
            'for="planMaxSteps">Max steps <span class="field-help"',
        ):
            self.assertNotIn(marker, source)

        # Shared sizing controls are mounted in the Human Control header,
        # before retirement/reconciliation and action-specific content.
        self.assertLess(source.index('id="planBounds"'), source.index('id="retirementReconciliation"'))
        self.assertLess(source.index('id="planBounds"'), source.index('id="controls"'))


if __name__ == "__main__":
    unittest.main()
