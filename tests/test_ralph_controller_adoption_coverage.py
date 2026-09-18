import argparse
import unittest
from unittest import mock

from scripts import ralph


class ControllerAdoptionCoverageTests(unittest.TestCase):
    """Keep late-test adoption authority and its delta binding controller-owned."""

    plan_hash = "a" * 64
    path = ralph.READY_TO_COMMIT_TEST_RECONCILIATION_PATH
    recorded_path = "scripts/ralph.py"

    def state(self, **overrides):
        state = ralph.default_state()
        state.update({
            "status": "READY_TO_COMMIT",
            "plan_hash": self.plan_hash,
            "plan": {"approved": "controller-adoption-coverage"},
            "recovery_checkpoint": "RP-controller-adoption",
            "plan_changed_files": [self.recorded_path],
            "plan_owned_files": [],
            "test_reconciliation_adoptions": [],
            "final_qualification": {
                "state": "PASS",
                "completed_at": "2026-09-18T00:00:00+00:00",
                "delta_fingerprint": "f" * 64,
            },
        })
        state.update(overrides)
        return state

    def args(self, **overrides):
        values = {
            "plan_hash": self.plan_hash,
            "path": self.path,
            "confirm": "ADOPT",
            "reason": "Restore controller adoption coverage.",
        }
        values.update(overrides)
        return argparse.Namespace(**values)

    def validate(self, state, *, checkpoint=None, baseline="absent", current=None, **patches):
        checkpoint = checkpoint or {
            "plan_hash": self.plan_hash,
            "baseline_dirty_paths": [],
            "baseline_untracked_paths": [],
        }
        current = current or [self.recorded_path, self.path]
        with (
            mock.patch.object(ralph, "load_recovery_checkpoint", return_value=checkpoint),
            mock.patch.object(ralph, "plan_baseline_path_kind", return_value=baseline),
            mock.patch.object(ralph, "git_changed_paths", return_value=current),
            mock.patch.object(ralph, "validate_plan"),
            mock.patch.object(ralph, "plan_hash", return_value=patches.pop("derived_hash", self.plan_hash)),
            mock.patch.object(ralph, "is_protected_path", return_value=patches.pop("protected", False)),
            mock.patch.object(ralph, "is_tooling_path", return_value=patches.pop("tooling", False)),
        ):
            self.assertFalse(patches, f"unused patch values: {patches}")
            return ralph.validate_ready_to_commit_test_reconciliation(state)

    def invoke_adoption(self, state, args, *, candidate=None, baseline="absent", qualified=(True, "bound")):
        with (
            mock.patch.object(ralph, "init_files"),
            mock.patch.object(ralph, "load_state", return_value=state),
            mock.patch.object(ralph, "ready_to_commit_test_reconciliation_candidate", return_value=candidate),
            mock.patch.object(ralph, "plan_baseline_path_kind", return_value=baseline),
            mock.patch.object(ralph, "qualified_delta_matches", return_value=qualified),
            mock.patch.object(ralph, "save_state") as save,
            mock.patch.object(ralph, "append_journal"),
            mock.patch.object(ralph, "live_write"),
            mock.patch.object(ralph.tui, "write_event"),
        ):
            result = ralph.cmd_adopt_test_reconciliation(args)
        return result, save

    def test_candidate_requires_ready_active_authority_and_approval_time_absence(self):
        state = self.state()
        self.assertEqual((True, "eligible test reconciliation delta"), self.validate(state))

        cases = {
            "not-ready": (self.state(status="APPROVED"), {}),
            "stale-active-plan": (self.state(), {"derived_hash": "b" * 64}),
            "checkpoint-outside-plan": (self.state(), {"checkpoint": {"plan_hash": "b" * 64}}),
            "baseline-existing": (self.state(), {"baseline": "tracked"}),
            "already-recorded": (self.state(plan_changed_files=[self.recorded_path, self.path]), {}),
            "protected": (self.state(), {"protected": True}),
            "tooling": (self.state(), {"tooling": True}),
        }
        for name, (candidate_state, kwargs) in cases.items():
            with self.subTest(rejection=name):
                self.assertFalse(self.validate(candidate_state, **kwargs)[0])

    def test_adoption_requires_exact_candidate_confirmation_and_reason(self):
        exact_candidate = {"path": self.path, "delta_kind": "untracked"}
        state = self.state(recovery_checkpoint=None, plan_changed_files=[])
        result, save = self.invoke_adoption(state, self.args(), candidate=exact_candidate)
        self.assertEqual(0, result)
        self.assertEqual([self.path], state["plan_changed_files"])
        self.assertEqual("Restore controller adoption coverage.", state["test_reconciliation_adoptions"][-1]["operator_reason"])
        self.assertEqual("STALE", state["final_qualification"]["state"])
        save.assert_called_once_with(state)

        for args, candidate in (
            (self.args(path="tests/forged.py"), exact_candidate),
            (self.args(confirm="adopt"), exact_candidate),
            (self.args(reason=" \t "), exact_candidate),
            (self.args(), {"path": "tests/other.py", "delta_kind": "untracked"}),
            (self.args(), None),
        ):
            with self.subTest(args=vars(args), candidate=candidate):
                rejected = self.state(recovery_checkpoint=None, plan_changed_files=[])
                with self.assertRaises(RuntimeError):
                    self.invoke_adoption(rejected, args, candidate=candidate)
                self.assertEqual([], rejected["test_reconciliation_adoptions"])
                self.assertEqual([], rejected["plan_owned_files"])

    def test_adoption_rejects_forged_stale_baseline_and_duplicate_requests(self):
        exact_candidate = {"path": self.path, "delta_kind": "modified"}
        cases = (
            ("forged-hash", self.state(), self.args(plan_hash="b" * 64), exact_candidate, "absent", (True, "bound")),
            ("stale-qualification", self.state(), self.args(), exact_candidate, "absent", (False, "changed")),
            ("baseline-existing", self.state(), self.args(), exact_candidate, "tracked", (True, "bound")),
            ("duplicate-path", self.state(test_reconciliation_adoptions=[{"path": self.path}]), self.args(), exact_candidate, "absent", (True, "bound")),
        )
        for name, state, args, candidate, baseline, qualified in cases:
            with self.subTest(rejection=name):
                with self.assertRaises(RuntimeError):
                    self.invoke_adoption(state, args, candidate=candidate, baseline=baseline, qualified=qualified)
                self.assertEqual([self.recorded_path], state["plan_changed_files"])
                self.assertEqual([], state["plan_owned_files"])

    def test_requalification_binds_post_adoption_delta_and_rejects_unrelated_files(self):
        state = self.state(
            plan_changed_files=[self.recorded_path, self.path],
            test_reconciliation_adoptions=[{"path": self.path}],
            final_qualification={"state": "STALE"},
        )
        with (
            mock.patch.object(ralph, "init_files"),
            mock.patch.object(ralph, "load_state", return_value=state),
            mock.patch.object(ralph, "_requalification_delta_guard"),
            mock.patch.object(ralph, "run_final_qualification", return_value=(True, ["unit=PASS"], {"unit": 1.0}, "")),
            mock.patch.object(ralph, "plan_delta_fingerprint", return_value="post-adoption-delta") as fingerprint,
            mock.patch.object(ralph, "change_entries", return_value=[{"path": self.recorded_path}, {"path": self.path}]),
            mock.patch.object(ralph, "save_state"),
            mock.patch.object(ralph, "build_completion_report"),
            mock.patch.object(ralph, "live_write"),
        ):
            self.assertEqual(0, ralph.cmd_requalify(argparse.Namespace(plan_hash=self.plan_hash)))
        self.assertEqual("post-adoption-delta", state["final_qualification"]["completion_summary"]["delta_fingerprint"])
        fingerprint.assert_called_once_with(state)

        checkpoint = {"baseline_dirty_paths": [], "baseline_untracked_paths": []}
        unexpected = [self.recorded_path, self.path, "src/unrelated.py"]
        with (
            mock.patch.object(ralph, "load_recovery_checkpoint", return_value=checkpoint),
            mock.patch.object(ralph, "git_changed_paths", return_value=unexpected),
        ):
            with self.assertRaisesRegex(RuntimeError, r"^UNEXPECTED_DELTA: \['src/unrelated.py'\]$"):
                ralph._requalification_delta_guard(state)
            with self.assertRaisesRegex(RuntimeError, r"^UNEXPECTED_DELTA: \['src/unrelated.py'\]$"):
                ralph._finalization_guard(state)


if __name__ == "__main__":
    unittest.main()
