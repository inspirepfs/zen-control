from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "ralph.py"
spec = importlib.util.spec_from_file_location("ralph_retry_hardening", MODULE_PATH)
ralph = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(ralph)


class ContinuationClassificationTests(unittest.TestCase):
    def test_result_schema_has_explicit_continuation_class(self):
        values = ralph.RESULT_SCHEMA["properties"]["blocker_class"]["enum"]
        self.assertIn("continuation", values)

    def test_explicit_continuation_never_requires_human(self):
        result = {
            "summary": "Need one more bounded implementation turn.",
            "blockers": ["Further shell execution is required to finish the approved API contract."],
            "needs_human": False,
            "blocker_class": "continuation",
        }
        requested, reason = ralph.codex_requests_continuation(result)
        self.assertTrue(requested)
        self.assertIn("Further shell execution", reason)
        blocked, _ = ralph.codex_requires_human_before_gates(result)
        self.assertFalse(blocked)

    def test_legacy_false_human_gate_is_reclassified_as_continuation(self):
        result = {
            "summary": "A further shell execution is required to apply the bounded API contract.",
            "blockers": ["Please authorize a new loop/retry."],
            "needs_human": True,
            "blocker_class": "human-decision",
        }
        requested, reason = ralph.codex_requests_continuation(result)
        self.assertTrue(requested)
        self.assertIn("authorize a new loop/retry", reason)

    def test_real_authority_boundaries_are_not_auto_continuation(self):
        for blocker in (
            "Further shell execution requires a policy violation.",
            "Another implementation turn requires a credential.",
            "Another shell execution would modify a protected path.",
        ):
            with self.subTest(blocker=blocker):
                result = {
                    "summary": blocker,
                    "blockers": [blocker],
                    "needs_human": True,
                    "blocker_class": "human-decision",
                }
                requested, _ = ralph.codex_requests_continuation(result)
                self.assertFalse(requested)


class RepairEpochTests(unittest.TestCase):
    def test_exhausted_human_steer_resets_attempt_budget_and_keeps_evidence(self):
        state = ralph.default_state()
        state.update(
            {
                "active_failure": "abc123",
                "failure_attempts": {"abc123": ralph.MAX_REPAIRS_PER_FAILURE},
                "block_reason": "failure abc123 persisted through 3 repair attempts",
                "last_failure": {
                    "fingerprint": "abc123",
                    "gates": ["unit-tests=FAIL"],
                    "output": "FAIL: test_contract\nAssertionError: boom",
                },
            }
        )
        reset = ralph.reset_failure_epoch_after_human_steer(state)
        self.assertEqual(reset["previous_attempts"], ralph.MAX_REPAIRS_PER_FAILURE)
        self.assertEqual(state["failure_attempts"]["abc123"], 0)
        self.assertEqual(state["active_failure"], "abc123")
        self.assertEqual(state["last_failure"]["fingerprint"], "abc123")

    def test_unrelated_human_gate_does_not_reset_failure_attempts(self):
        state = ralph.default_state()
        state.update(
            {
                "active_failure": "abc123",
                "failure_attempts": {"abc123": 3},
                "block_reason": "policy violation: test paths ['tests/test_existing.py']",
            }
        )
        self.assertIsNone(ralph.reset_failure_epoch_after_human_steer(state))
        self.assertEqual(state["failure_attempts"]["abc123"], 3)

    def test_next_turn_after_exhaustion_steer_is_repair_one(self):
        state = ralph.default_state()
        state.update(
            {
                "active_failure": "same-failure",
                "failure_attempts": {"same-failure": 3},
                "block_reason": "failure same-failure persisted through 3 repair attempts",
            }
        )
        ralph.reset_failure_epoch_after_human_steer(state)
        active = state["active_failure"]
        repair_no = int(state["failure_attempts"].get(active, 0)) + 1 if active else 0
        self.assertEqual(repair_no, 1)


class RepairEvidenceTests(unittest.TestCase):
    def test_repair_prompt_targets_authoritative_failure(self):
        state = ralph.default_state()
        state.update(
            {
                "plan_hash": "abc",
                "last_failure": {
                    "fingerprint": "feedface",
                    "gates": ["python-compile=PASS", "unit-tests=FAIL"],
                    "output": (
                        "FAIL: test_repository_contract_is_complete_and_static_validation_passes "
                        "(tests.test_environment.EnvironmentContractTests)\n"
                        "AssertionError: RALPH_WEB_PASSWORD missing"
                    ),
                },
            }
        )
        step = {
            "id": 1,
            "title": "Repair contract",
            "objective": "Fix the failing environment contract.",
            "acceptance": ["The environment contract passes."],
            "test_change_policy": "modify",
        }
        text = ralph.step_prompt(state, step, "feedface", 2)
        self.assertIn("unit-tests=FAIL", text)
        self.assertIn("test_repository_contract_is_complete", text)
        self.assertIn("RALPH_WEB_PASSWORD", text)
        self.assertIn("Do not churn already-green subsystems", text)

    def test_nonmatching_old_failure_is_not_injected(self):
        state = ralph.default_state()
        state["last_failure"] = {
            "fingerprint": "old",
            "gates": ["unit-tests=FAIL"],
            "output": "FAIL: stale",
        }
        self.assertEqual(ralph.repair_failure_evidence(state, "new"), "")


class SourceFlowContractTests(unittest.TestCase):
    def test_run_consumes_continuation_before_human_gate_and_gates(self):
        source = MODULE_PATH.read_text(encoding="utf-8")
        continuation = source.index(
            "continuation, continuation_reason = codex_requests_continuation(result, step)"
        )
        human = source.index(
            "requires_human, reason = codex_requires_human_before_gates(result, step)",
            continuation,
        )
        gates = source.index(
            "passed, gates, fp, gate_output, gate_durations = run_gates()",
            continuation,
        )
        self.assertLess(continuation, human)
        self.assertLess(continuation, gates)
        self.assertIn('"CONTINUE"', source[continuation:human])

    def test_prompt_no_longer_turns_command_budget_into_human_authority(self):
        state = {"plan_hash": "abc"}
        step = {
            "id": 1,
            "title": "Bounded work",
            "objective": "Complete bounded implementation.",
            "acceptance": ["Complete."],
            "test_change_policy": "add-only",
        }
        text = ralph.step_prompt(state, step, None, 0)
        self.assertIn('blocker_class="continuation"', text)
        self.assertIn("needs_human=false", text)
        self.assertNotIn(
            "If safe completion genuinely needs more, return needs_human=true",
            text,
        )


if __name__ == "__main__":
    unittest.main()
