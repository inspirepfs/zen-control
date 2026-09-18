from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent))
from test_ralph_carry_forward_reconciliation import CarryForwardReconciliationTests, RepoHarness, ralph


class ReconciliationLifecycleTests(CarryForwardReconciliationTests):
    def test_qualification_refuses_pending_rejected_and_altered_adoption(self):
        state = {"recovery_checkpoint": "RP", "plan_changed_files": ["new.py"], "plan_carry_forward_files": ["kept.py"], "retirement_record_id": "RT-test"}
        candidate = {"path": "kept.py", "classification": "MANIFEST_BOUND_UNCHANGED", "disposition": "ADOPTED_PLAN_CARRY_FORWARD", "retirement_evidence": {"path": "kept.py"}}
        with mock.patch.object(ralph, "load_recovery_checkpoint", return_value={"baseline_dirty_paths": ["kept.py"], "baseline_untracked_paths": []}), mock.patch.object(ralph, "reconciliation_snapshot", return_value={"candidates": []}), mock.patch.object(ralph, "git_changed_paths", return_value=["new.py", "kept.py"]), mock.patch.object(ralph, "retirement_fingerprint_matches", return_value=False):
            state["carry_forward_candidates"] = [candidate]
            with self.assertRaisesRegex(RuntimeError, "ALTERED_ADOPTED_CARRY_FORWARD"):
                ralph._reconciled_provenance_guard(state, "requalification")
            candidate["disposition"] = "PENDING_RECONCILIATION"
            with self.assertRaisesRegex(RuntimeError, "PENDING_RECONCILIATION"):
                ralph._reconciled_provenance_guard(state, "requalification")
            candidate["disposition"] = "REJECTED_EXTERNAL_RECONCILIATION_REQUIRED"
            with self.assertRaisesRegex(RuntimeError, "REJECTED_EXTERNAL_RECONCILIATION_REQUIRED"):
                ralph._reconciled_provenance_guard(state, "requalification")

    def test_adopted_paths_are_qualified_but_never_staged_as_new_delta(self):
        state = {"recovery_checkpoint": "RP", "plan_changed_files": ["new.py"], "plan_carry_forward_files": ["kept.py"], "retirement_record_id": "RT-test", "carry_forward_candidates": [{"path": "kept.py", "classification": "MANIFEST_BOUND_UNCHANGED", "disposition": "ADOPTED_PLAN_CARRY_FORWARD", "retirement_evidence": {"path": "kept.py"}}]}
        with mock.patch.object(ralph, "load_recovery_checkpoint", return_value={"baseline_dirty_paths": ["kept.py"], "baseline_untracked_paths": [], "baseline_staged_paths": []}), mock.patch.object(ralph, "reconciliation_snapshot", return_value={"candidates": []}), mock.patch.object(ralph, "git_changed_paths", return_value=["new.py", "kept.py"]), mock.patch.object(ralph, "retirement_fingerprint_matches", return_value=True), mock.patch.object(ralph, "qualified_delta_matches", return_value=(True, "ok")), mock.patch.object(ralph, "_git", return_value=type("P", (), {"returncode": 0, "stdout": ""})()), mock.patch.object(ralph, "run_process", return_value=type("P", (), {"returncode": 0, "stdout": ""})()):
            planned, _ = ralph._finalization_guard(state)
        self.assertEqual(planned, ["new.py"])

    def test_provenance_refuses_untracked_residue_and_outside_boundary_absorption(self):
        state = {"recovery_checkpoint": "RP", "plan_changed_files": ["new.py"], "plan_carry_forward_files": [], "retirement_record_id": "RT-test"}
        candidate = {"path": "kept.py", "classification": "MANIFEST_BOUND_UNCHANGED", "disposition": ralph._CARRY_FORWARD_OUTSIDE, "retirement_evidence": {"path": "kept.py"}}
        state["carry_forward_candidates"] = [candidate]
        with mock.patch.object(ralph, "load_recovery_checkpoint", return_value={"baseline_dirty_paths": [], "baseline_untracked_paths": ["residue.py"]}), mock.patch.object(ralph, "reconciliation_snapshot", return_value={"candidates": []}), mock.patch.object(ralph, "git_changed_paths", return_value=["new.py", "residue.py"]):
            with self.assertRaisesRegex(RuntimeError, "OUTSIDE_BOUNDARY_RECONCILIATION: kept.py"):
                ralph._reconciled_provenance_guard(state, "requalification")
            candidate["disposition"] = "ADOPTED_PLAN_CARRY_FORWARD"
            state["plan_carry_forward_files"] = ["kept.py"]
            with mock.patch.object(ralph, "retirement_fingerprint_matches", return_value=True):
                with self.assertRaisesRegex(RuntimeError, r"UNTRACKED_APPROVAL_RESIDUE: \['residue.py'\]"):
                    ralph._reconciled_provenance_guard(state, "requalification")
    def test_replacement_snapshot_is_qualification_bound_and_reported(self):
        with RepoHarness(self) as repo:
            state = self.replacement_ready(repo, "app.py")
            self.assertEqual(ralph.cmd_adopt_carry_forward(self.adopt_args(state, "app.py")), 0)
            state = ralph.load_state()
            snapshot = ralph.reconciliation_snapshot(state)
            self.assertEqual(snapshot["candidates"][0]["classification"], "MANIFEST_BOUND_UNCHANGED")
            self.assertEqual(snapshot["candidates"][0]["claiming_step"], 1)
            state["final_qualification"] = {"state": "PASS", "delta_fingerprint": "prior-bound-delta"}
            state["carry_forward_candidates"][0]["adoption"]["test_change_policy"] = "none"
            qualified, reason = ralph.qualified_delta_matches(state)
            self.assertFalse(qualified)
            self.assertIn("policy context is stale", reason)
            state["carry_forward_candidates"][0]["adoption"]["test_change_policy"] = "modify"
            report = ralph.build_completion_report(state, [])
            self.assertEqual(report["reconciliation"]["replacement_snapshot"]["retirement_record_id"], state["retirement_record_id"])

    def test_resume_and_recovery_refuse_malformed_reconciliation_state(self):
        with RepoHarness(self) as repo:
            state = self.replacement_ready(repo, "app.py")
            state.update({"status": "BLOCKED_HUMAN", "block_reason": "operator evidence required"})
            state["carry_forward_candidates"].append(dict(state["carry_forward_candidates"][0]))
            ralph.save_state(state)
            args = type("Args", (), {"plan_hash": state["plan_hash"], "reason": "evidence"})()
            with self.assertRaisesRegex(RuntimeError, "duplicate candidate"):
                ralph.cmd_resume(args)
            with mock.patch.object(ralph, "is_recoverable_validation_block", return_value=True):
                with self.assertRaisesRegex(RuntimeError, "duplicate candidate"):
                    ralph.cmd_recover_validation_block(type("Args", (), {"plan_hash": state["plan_hash"]})())


    def test_completion_report_records_reconciliation_refusal_instead_of_raising(self):
        with RepoHarness(self):
            plan = {"goal": "Replacement repair", "steps": [
                {"id": i, "title": f"Step {i}", "objective": f"Objective {i}", "acceptance": ["ok"], "test_change_policy": "modify"}
                for i in range(1, 6)
            ]}
            state = ralph.default_state()
            state.update({
                "status": "BLOCKED_HUMAN",
                "plan": plan,
                "plan_hash": ralph.plan_hash(plan),
                "retirement_record_id": "RT-20260918T000000Z-abcdef123456",
                "final_qualification": {
                    "state": "BLOCKED",
                    "stage": "qualification-guard",
                    "error": "replacement reconciliation action hash is malformed or stale",
                },
            })
            with mock.patch.object(ralph, "reconciliation_snapshot", side_effect=RuntimeError("replacement reconciliation action hash is malformed or stale")):
                report = ralph.build_completion_report(state, [])
            snapshot = report["reconciliation"]["replacement_snapshot"]
            self.assertTrue(snapshot["replacement"])
            self.assertIn("malformed or stale", snapshot["error"])
            text = (ralph.ROOT / report["markdown_path"]).read_text(encoding="utf-8")
            self.assertIn("Controller refusal", text)
            self.assertIn("malformed or stale", text)

    def test_inspection_is_controller_snapshot_not_operator_path_selection(self):
        with RepoHarness(self) as repo:
            state = self.replacement_ready(repo, "app.py")
            with mock.patch("builtins.print") as printed:
                ralph.cmd_inspect_carry_forward(type("Args", (), {"plan_hash": state["plan_hash"]})())
            document = json.loads(printed.call_args.args[0])
            self.assertEqual(document["candidates"][0]["path"], "app.py")
            self.assertNotIn("path", ralph.build_parser().parse_args(["inspect-carry-forward", state["plan_hash"]]).__dict__)
