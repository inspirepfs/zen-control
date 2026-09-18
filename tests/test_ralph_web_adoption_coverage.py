from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "ralph_web.py"
spec = importlib.util.spec_from_file_location("ralph_web_adoption_coverage", MODULE_PATH)
web = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = web
spec.loader.exec_module(web)


class WebAdoptionCoverageTests(unittest.TestCase):
    """Keep late-test adoption bounded to the controller's current context."""

    plan_hash = "a" * 64
    candidate_path = "tests/test_ralph_profile.py"

    def state(self, **overrides):
        value = {"status": "READY_TO_COMMIT", "plan_hash": self.plan_hash}
        value.update(overrides)
        return value

    def candidate(self):
        return {"path": self.candidate_path, "delta_kind": "untracked"}

    def action(self, **overrides):
        value = {
            "action": "reconcile_ready_test",
            "confirm": "ADOPT",
            "reason": "Restore the current controller candidate.",
        }
        value.update(overrides)
        return value

    def test_snapshot_exposes_only_the_current_ready_controller_candidate(self):
        with mock.patch.object(web, "_controller_test_reconciliation_candidate", return_value=self.candidate()) as candidate:
            self.assertEqual(
                web._test_reconciliation_snapshot(self.state()),
                {"eligible": True, "path": self.candidate_path, "delta_kind": "untracked"},
            )
            candidate.assert_called_once_with(self.state())

        for state in (self.state(status="APPROVED"), self.state(status="READY_TO_COMMIT")):
            with self.subTest(state=state):
                with mock.patch.object(
                    web,
                    "_controller_test_reconciliation_candidate",
                    return_value=None,
                ) as candidate:
                    self.assertEqual(web._test_reconciliation_snapshot(state), {"eligible": False})
                    if state["status"] == "READY_TO_COMMIT":
                        candidate.assert_called_once_with(state)
                    else:
                        candidate.assert_not_called()

    def test_action_uses_current_controller_context_not_client_candidate_context(self):
        payload = self.action(
            plan_hash="forged-plan-hash",
            candidatePath="tests/forged.py",
            paths=[self.candidate_path, "tests/broadened.py"],
        )
        with mock.patch.object(web, "_controller_test_reconciliation_candidate", return_value=self.candidate()) as candidate:
            request = web.command_for_action(payload, self.state())

        candidate.assert_called_once_with(self.state())
        self.assertEqual(
            request.argv,
            [
                "adopt-test-reconciliation", self.plan_hash, "--path", self.candidate_path,
                "--confirm", "ADOPT", "--reason", "Restore the current controller candidate.",
            ],
        )
        self.assertNotIn("forged-plan-hash", request.argv)
        self.assertNotIn("tests/forged.py", request.argv)
        self.assertNotIn("tests/broadened.py", request.argv)

    def test_action_rejects_forged_stale_missing_broadened_or_narrowed_context(self):
        cases = (
            ("forged", self.action(path="tests/forged.py"), self.state(), self.candidate(), "exactly match"),
            ("stale", self.action(), self.state(status="APPROVED"), self.candidate(), "READY_TO_COMMIT"),
            ("missing", self.action(), self.state(), None, "no eligible"),
            ("broadened", self.action(path="tests/broadened.py"), self.state(), self.candidate(), "exactly match"),
            ("narrowed", self.action(path="tests/narrowed.py"), self.state(), self.candidate(), "exactly match"),
        )
        for name, payload, state, candidate, message in cases:
            with self.subTest(context=name):
                with mock.patch.object(web, "_controller_test_reconciliation_candidate", return_value=candidate):
                    with self.assertRaisesRegex(web.WebConsoleError, message):
                        web.command_for_action(payload, state)

    def test_browser_submits_no_path_and_legacy_reconcile_commit_is_unsupported(self):
        submission_start = web.PAGE.index("async function submitReadyTestReconciliation()")
        submission_end = web.PAGE.index("async function logout", submission_start)
        submission = web.PAGE[submission_start:submission_end]
        self.assertIn("post({action:'reconcile_ready_test',confirm:'ADOPT',reason})", submission)
        self.assertNotIn("path,reason", submission)

        with self.assertRaisesRegex(web.WebConsoleError, "unsupported action"):
            web.command_for_action({"action": "reconcile_commit"}, self.state())


if __name__ == "__main__":
    unittest.main()
