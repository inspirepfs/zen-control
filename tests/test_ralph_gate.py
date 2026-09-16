import json
import tempfile
import unittest
from pathlib import Path

from scripts import ralph_gate


class RalphGateTests(unittest.TestCase):
    def state(self, reason="The Incident Monitor warning is runtime-owned evidence."):
        return {
            "status": "BLOCKED_HUMAN",
            "plan_hash": "f29a83bd8d1683f07ed192430f802c6c66cd2d83015582da97572552091f67c7",
            "loop_count": 14,
            "current_step": 4,
            "block_reason": reason,
            "last_result": {
                "summary": reason,
                "tests": ["21 focused incident/diagnostic tests passed"],
            },
            "plan": {
                "steps": [
                    {"title": "one"},
                    {"title": "two"},
                    {"title": "three"},
                    {
                        "title": "Classify the Incident Monitor warning without manufacturing health",
                        "acceptance": [
                            "If evidence is runtime-owned, stop with BLOCKED_HUMAN and state the exact safe operator action needed."
                        ],
                    },
                ]
            },
        }

    def test_incident_gate_is_operator_friendly(self):
        gate = ralph_gate.build_gate(self.state())
        self.assertTrue(gate["open"])
        self.assertEqual("HG-0014-04", gate["gate_id"])
        self.assertEqual("runtime_evidence", gate["class"])
        self.assertTrue(any("active ZEN incidents" in item for item in gate["human_actions"]))
        self.assertTrue(any("zero active incidents" in item.lower() for item in gate["human_actions"]))
        self.assertTrue(any("Do not disable Incident Monitor" in item for item in gate["forbidden_shortcuts"]))
        self.assertTrue(gate["resolution_allowed"])
        self.assertIn("resolve-gate", gate["resolve"])
        self.assertIn("HG-0014-04", gate["resolve"])
        self.assertIn("No verified source/configuration defect", gate["summary"])

    def test_performance_gate_uses_existing_acceptance_command(self):
        gate = ralph_gate.build_gate(
            self.state("Formal performance evidence remains incomplete for prepared views and mutation lane contention.")
        )
        self.assertEqual("validation_evidence", gate["class"])
        self.assertTrue(any("perf_acceptance.py ../zen-performance.json" in item for item in gate["human_actions"]))
        self.assertTrue(any("Do not lower" in item for item in gate["forbidden_shortcuts"]))
        self.assertFalse(gate["resolution_allowed"])
        self.assertEqual("", gate["resolve"])

    def test_gate_text_is_bounded(self):
        state = self.state("x" * 5000)
        gate = ralph_gate.build_gate(state)
        self.assertLessEqual(len(gate["summary"]), ralph_gate.MAX_TEXT)
        self.assertTrue(gate["summary"].endswith("…"))

    def test_nonblocked_state_is_not_presented_as_open_gate(self):
        state = self.state()
        state["status"] = "APPROVED"
        state["block_reason"] = None
        state["last_result"] = None
        gate = ralph_gate.build_gate(state)
        self.assertFalse(gate["open"])

    def test_history_tracks_repeated_human_blocks(self):
        with tempfile.TemporaryDirectory() as td:
            live = Path(td) / "live.log"
            live.write_text(
                "\n".join(
                    [
                        "[15:34:35] RALPH    loop=0013 step=4/9 phase=implement repair=0 title=Classify the Incident Monitor warning without manufacturing health",
                        "[15:35:56] SUMMARY  BLOCKED_HUMAN: first runtime evidence block",
                        "[15:42:29] RALPH    loop=0014 step=4/9 phase=implement repair=0 title=Classify the Incident Monitor warning without manufacturing health",
                        "[15:43:55] SUMMARY  BLOCKED_HUMAN: second runtime evidence block",
                        "[16:10:00] GATE     gate=HG-0014-04 resolved HUMAN_CONFIRMED; advanced to step=5 without Codex retry",
                    ]
                ),
                encoding="utf-8",
            )
            history = ralph_gate.gate_history(live)
        self.assertEqual(2, len(history))
        self.assertEqual("HG-0013-04", history[0]["gate_id"])
        self.assertEqual("HG-0014-04", history[1]["gate_id"])
        self.assertEqual("OPEN", history[0]["status"])
        self.assertEqual("RESOLVED", history[1]["status"])
        self.assertEqual("16:10:00", history[1]["resolved_at"])

    def test_rendered_runtime_gate_prefers_resolution_over_retry(self):
        gate = ralph_gate.build_gate(self.state())
        rendered = ralph_gate.render_gate(gate, details=True)
        self.assertIn("NEXT COMMANDS", rendered)
        self.assertIn("resolve-gate", rendered)
        self.assertIn("Use resume only when Ralph must re-evaluate genuinely new input.", rendered)
        self.assertIn("Raw blocker evidence", rendered)


    def test_review_view_contains_release_and_developer_sections(self):
        gate = ralph_gate.build_gate(self.state())
        rendered = ralph_gate.render_gate(gate, details=True, view="review", color=False)
        self.assertIn("HUMAN GATE REVIEW", rendered)
        self.assertIn("RELEASE MANAGER VIEW", rendered)
        self.assertIn("DEVELOPER VIEW", rendered)
        self.assertIn("OPERATOR ACTION", rendered)
        self.assertIn("NEXT COMMANDS", rendered)
        self.assertNotIn("\033[", rendered)

    def test_release_view_omits_developer_detail(self):
        gate = ralph_gate.build_gate(self.state())
        rendered = ralph_gate.render_gate(gate, view="release", color=False)
        self.assertIn("RELEASE MANAGER VIEW", rendered)
        self.assertNotIn("DEVELOPER VIEW", rendered)
        self.assertNotIn("OPERATOR ACTION", rendered)

    def test_developer_view_includes_technical_acceptance(self):
        gate = ralph_gate.build_gate(self.state())
        rendered = ralph_gate.render_gate(gate, details=True, view="developer", color=False)
        self.assertIn("DEVELOPER VIEW", rendered)
        self.assertIn("Approved acceptance", rendered)
        self.assertIn("RAW", rendered.upper())

    def test_color_mode_emits_ansi_only_when_enabled(self):
        gate = ralph_gate.build_gate(self.state())
        colored = ralph_gate.render_gate(gate, view="review", color=True)
        plain = ralph_gate.render_gate(gate, view="review", color=False)
        self.assertIn("\033[", colored)
        self.assertNotIn("\033[", plain)

    def test_no_color_environment_overrides_always(self):
        import os
        previous = os.environ.get("NO_COLOR")
        try:
            os.environ["NO_COLOR"] = "1"
            self.assertFalse(ralph_gate._color_enabled("always", is_tty=True))
        finally:
            if previous is None:
                os.environ.pop("NO_COLOR", None)
            else:
                os.environ["NO_COLOR"] = previous

    def test_markdown_is_shareable_for_release_review(self):
        gate = ralph_gate.build_gate(self.state())
        rendered = ralph_gate.render_markdown(gate, details=True, view="review")
        self.assertIn("# RALPH-Lite v0.2.1 — Human Gate Review", rendered)
        self.assertIn("## Release manager view", rendered)
        self.assertIn("## Developer view", rendered)
        self.assertIn("```bash", rendered)
        self.assertIn("resolve-gate", rendered)

    def test_policy_gate_exposes_bounded_steer_review(self):
        state = self.state()
        state["block_reason"] = "policy violation: test paths ['tests/test_new.py']"
        state["plan"]["steps"][state["current_step"] - 1]["test_change_policy"] = "add-only"
        gate = ralph_gate.build_gate(state)
        self.assertEqual(gate["class"], "policy_review")
        self.assertIn("steer", gate["steer"])
        rendered = ralph_gate.render_gate(gate, details=True, view="review", color=False)
        self.assertIn("Policy review", rendered)
        self.assertIn("add-only", rendered)
        self.assertIn("tests/test_new.py", rendered)

    def test_cli_json_is_machine_readable_and_read_only(self):
        with tempfile.TemporaryDirectory() as td:
            state_path = Path(td) / "state.json"
            original = self.state()
            state_path.write_text(json.dumps(original), encoding="utf-8")
            before = state_path.read_bytes()
            loaded = ralph_gate._load_json(state_path)
            gate = ralph_gate.build_gate(loaded)
            json.dumps(gate)
            self.assertEqual(before, state_path.read_bytes())


if __name__ == "__main__":
    unittest.main()
