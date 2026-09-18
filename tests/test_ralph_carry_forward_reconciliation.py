from __future__ import annotations

import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "ralph.py"
spec = importlib.util.spec_from_file_location("ralph_carry_forward", MODULE_PATH)
ralph = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(ralph)


def valid_plan() -> dict:
    return {"goal": "Replacement plan", "steps": [
        {"id": i, "title": f"Step {i}", "objective": f"Objective {i}", "acceptance": [f"Acceptance {i}"], "test_change_policy": "modify"}
        for i in range(1, 6)
    ]}


class RepoHarness:
    PATH_NAMES = ("ROOT", "RALPH", "STATE", "PLAN", "IDEAS", "JOURNAL", "POLICY", "LIVE", "CONTEXT", "EVENTS", "RECOVERY", "REPORTS", "RETIREMENTS")

    def __init__(self, test: unittest.TestCase):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.saved = {name: getattr(ralph, name) for name in self.PATH_NAMES}

    def __enter__(self):
        def run(*args: str):
            return subprocess.run(args, cwd=self.root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=True)
        run("git", "init", "-q"); run("git", "config", "user.email", "ralph@example.invalid"); run("git", "config", "user.name", "RALPH Test")
        (self.root / "app.py").write_text("value = 1\n", encoding="utf-8")
        (self.root / ".ralph").mkdir(); (self.root / ".ralph" / "policy.md").write_text("# policy\n", encoding="utf-8")
        run("git", "add", "app.py", ".ralph/policy.md"); run("git", "commit", "-qm", "baseline")
        ralph.ROOT = self.root; ralph.RALPH = self.root / ".ralph"
        for name, leaf in (("STATE", "state.json"), ("PLAN", "plan.md"), ("IDEAS", "ideas.md"), ("JOURNAL", "journal.md"), ("POLICY", "policy.md"), ("LIVE", "live.log"), ("CONTEXT", "context.json"), ("EVENTS", "events.jsonl")):
            setattr(ralph, name, ralph.RALPH / leaf)
        ralph.RECOVERY = ralph.RALPH / "recovery"; ralph.REPORTS = ralph.RALPH / "reports"; ralph.RETIREMENTS = ralph.RALPH / "retirements"
        ralph.init_files(); return self

    def __exit__(self, *_args):
        for name, value in self.saved.items(): setattr(ralph, name, value)
        self.tmp.cleanup()


class CarryForwardReconciliationTests(unittest.TestCase):
    def blocked_state(self) -> dict:
        plan = valid_plan(); state = ralph.default_state()
        state.update({"status": "BLOCKED_HUMAN", "plan_hash": ralph.plan_hash(plan), "plan": plan, "current_step": 3, "loop_count": 9, "block_reason": "operator evidence required"})
        return state

    @staticmethod
    def args(state, *, rollback=False, carry_forward=False, confirm=None, reason="obsolete"):
        return type("Args", (), {"plan_hash": state["plan_hash"], "reason": reason, "rollback": rollback, "carry_forward": carry_forward, "confirm": confirm})()
    def replacement_ready(self, repo: RepoHarness, path: str, *, untracked: bool = False, test_policy: str = "modify") -> dict:
        state = self.blocked_state()
        checkpoint = ralph.create_recovery_checkpoint(state)
        if untracked:
            (ralph.ROOT / path).parent.mkdir(parents=True, exist_ok=True)
            (ralph.ROOT / path).write_text("carry forward\n", encoding="utf-8")
        state.update({"recovery_checkpoint": checkpoint["id"], "plan_changed_files": [path]})
        ralph.save_state(state)
        ralph.cmd_retire_plan(self.args(state, carry_forward=True))
        record_id = ralph.load_state()["retired_plans"][-1]["record_id"]
        replacement = valid_plan()
        replacement["goal"] = "Replacement plan with reconciled retained content"
        replacement["steps"][0]["test_change_policy"] = test_policy
        with mock.patch.object(ralph, "query_codex_rate_limits", return_value={}), mock.patch.object(ralph, "codex_usage_guard", return_value=("SAFE", [])), mock.patch.object(ralph, "run_codex", return_value=replacement):
            ralph.cmd_propose(type("Args", (), {"goal": None, "from_retirement": record_id})())
        proposed = ralph.load_state()
        ralph.cmd_approve(type("Args", (), {"plan_hash": proposed["plan_hash"]})())
        return ralph.load_state()

    @staticmethod
    def adopt_args(state: dict, path: str, *, step: int = 1):
        return type("Args", (), {"plan_hash": state["plan_hash"], "path": path, "step": step, "confirm": "ADOPT", "ownership_basis": "retired-unchanged-content"})()

    def test_adopts_tracked_and_untracked_as_carry_forward_not_new_files(self):
        with RepoHarness(self) as repo:
            tracked = self.replacement_ready(repo, "app.py")
            self.assertEqual(ralph.cmd_adopt_carry_forward(self.adopt_args(tracked, "app.py")), 0)
            adopted = ralph.load_state()
            self.assertIn("app.py", adopted["plan_carry_forward_files"])
            self.assertNotIn("app.py", adopted["plan_owned_files"])
            self.assertNotIn("app.py", adopted["plan_changed_files"])
            self.assertEqual(adopted["carry_forward_candidates"][0]["disposition"], "ADOPTED_PLAN_CARRY_FORWARD")

        with RepoHarness(self) as repo:
            untracked = self.replacement_ready(repo, "retained.py", untracked=True)
            self.assertEqual(ralph.cmd_adopt_carry_forward(self.adopt_args(untracked, "retained.py")), 0)
            self.assertEqual(ralph.load_state()["carry_forward_candidates"][0]["source_kind"], "untracked")

    def test_refuses_changed_since_retirement_and_test_policy_failure(self):
        with RepoHarness(self) as repo:
            state = self.replacement_ready(repo, "app.py")
            (ralph.ROOT / "app.py").write_text("changed\n", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "changed since retirement"):
                ralph.cmd_adopt_carry_forward(self.adopt_args(state, "app.py"))

        with RepoHarness(self) as repo:
            state = self.replacement_ready(repo, "tests/retained_test.py", untracked=True, test_policy="none")
            with self.assertRaisesRegex(RuntimeError, "violates test policy none"):
                ralph.cmd_adopt_carry_forward(self.adopt_args(state, "tests/retained_test.py"))

    def test_rejects_expired_self_hosting_and_records_nonabsorption_dispositions(self):
        with RepoHarness(self) as repo:
            state = self.replacement_ready(repo, "scripts/ralph.py", untracked=True)
            state["self_hosting_grant"] = {"plan_hash": state["plan_hash"], "step": 2, "paths": ["scripts/ralph.py"]}
            ralph.save_state(state)
            with self.assertRaisesRegex(RuntimeError, "lacks current self-hosting authority"):
                ralph.cmd_adopt_carry_forward(self.adopt_args(state, "scripts/ralph.py"))

        with RepoHarness(self) as repo:
            state = self.replacement_ready(repo, "app.py")
            args = type("Args", (), {"plan_hash": state["plan_hash"], "path": "app.py", "reason": "owned by external migration"})()
            self.assertEqual(ralph.cmd_leave_carry_forward_outside(args), 0)
            left = ralph.load_state()
            self.assertNotIn("app.py", left["plan_changed_files"])
            self.assertNotIn("app.py", left.get("plan_carry_forward_files", []))
            self.assertEqual(left["carry_forward_candidates"][0]["disposition"], "LEFT_OUTSIDE_PLAN_BOUNDARY")

        with RepoHarness(self) as repo:
            state = self.replacement_ready(repo, "app.py")
            args = type("Args", (), {"plan_hash": state["plan_hash"], "path": "app.py", "reason": "external owner must reconcile"})()
            self.assertEqual(ralph.cmd_reject_carry_forward(args), 0)
            rejected = ralph.load_state()["carry_forward_candidates"][0]
            self.assertEqual(rejected["disposition"], "REJECTED_EXTERNAL_RECONCILIATION_REQUIRED")
            self.assertFalse(rejected["owned"])

    def test_rejects_duplicate_forged_and_protected_candidates(self):
        with RepoHarness(self) as repo:
            state = self.replacement_ready(repo, "app.py")
            self.assertEqual(ralph.cmd_adopt_carry_forward(self.adopt_args(state, "app.py")), 0)
            with self.assertRaisesRegex(RuntimeError, "already has a durable disposition"):
                ralph.cmd_adopt_carry_forward(self.adopt_args(ralph.load_state(), "app.py"))

        with RepoHarness(self) as repo:
            state = self.replacement_ready(repo, "app.py")
            state["carry_forward_candidates"][0]["inherited_fingerprint"] = "forged"
            ralph.save_state(state)
            with self.assertRaisesRegex(RuntimeError, "forged or mismatched"):
                ralph.cmd_adopt_carry_forward(self.adopt_args(state, "app.py"))

        with RepoHarness(self) as repo:
            state = self.replacement_ready(repo, "app.py")
            state["carry_forward_candidates"][0]["path"] = ".ralph/state.json"
            ralph.save_state(state)
            with self.assertRaisesRegex(RuntimeError, "protected or ambiguous"):
                ralph.cmd_adopt_carry_forward(self.adopt_args(state, ".ralph/state.json"))


    def test_replacement_prompt_uses_current_rt_reason_and_clears_terminal_metadata(self):
        with RepoHarness(self) as repo:
            state = self.blocked_state()
            state["plan"]["goal"] = "Continue from RT-ancestor with superseded reconciliation work"
            state["plan_hash"] = ralph.plan_hash(state["plan"])
            state.update({
                "commit_sha": "deadbeef",
                "commit_message": "stale commit",
                "commit_reconciled": True,
                "commit_reconcile_note": "stale",
                "commit_reconciled_at": "2026-09-17T10:26:34+00:00",
                "push_upstream": "origin/main",
                "push_reconciled": True,
                "pushed_at": "2026-09-18T11:14:12+00:00",
                "human_gate_resolutions": [{"gate_id": "HG-old"}],
            })
            checkpoint = ralph.create_recovery_checkpoint(state)
            state.update({"recovery_checkpoint": checkpoint["id"], "plan_changed_files": ["app.py"]})
            ralph.save_state(state)
            reason = "All approved steps passed, but terminal qualification escaped at APPROVED N+1/N."
            ralph.cmd_retire_plan(self.args(state, carry_forward=True, reason=reason))
            record_id = ralph.load_state()["retired_plans"][-1]["record_id"]

            proposal = valid_plan()
            proposal["goal"] = "Repair only the newest retirement condition"
            with (
                mock.patch.object(ralph, "query_codex_rate_limits", return_value={}),
                mock.patch.object(ralph, "codex_usage_guard", return_value=("SAFE", [])),
                mock.patch.object(ralph, "run_codex", return_value=proposal) as run_codex,
            ):
                self.assertEqual(
                    0,
                    ralph.cmd_propose(type("Args", (), {"goal": None, "from_retirement": record_id})()),
                )

            prompt = run_codex.call_args.args[0]
            self.assertIn(f"Goal: Continue from {record_id} to resolve the retirement condition: {reason}", prompt)
            self.assertIn(f"- RT: {record_id}", prompt)
            self.assertIn(f"- Reason: {reason}", prompt)
            self.assertIn("Historical planning context follows for background only", prompt)
            self.assertIn("superseded reconciliation work", prompt)

            proposed = ralph.load_state()
            self.assertEqual(record_id, proposed["retirement_record_id"])
            self.assertIsNone(proposed["commit_sha"])
            self.assertIsNone(proposed["commit_message"])
            self.assertFalse(proposed["commit_reconciled"])
            self.assertIsNone(proposed["commit_reconcile_note"])
            self.assertIsNone(proposed["commit_reconciled_at"])
            self.assertIsNone(proposed["push_upstream"])
            self.assertFalse(proposed["push_reconciled"])
            self.assertIsNone(proposed["pushed_at"])
            self.assertEqual([], proposed["human_gate_resolutions"])

    def test_replacement_plan_does_not_absorb_approval_time_residue(self):
        with RepoHarness(self) as repo:
            state = self.replacement_ready(repo, "retained.py", untracked=True)
            (ralph.ROOT / "new.py").write_text("new plan work\n", encoding="utf-8")

            ralph.remember_plan_files(state, ["retained.py", "new.py"])

            self.assertNotIn("retained.py", state["plan_changed_files"])
            self.assertNotIn("retained.py", state["plan_owned_files"])
            self.assertIn("new.py", state["plan_changed_files"])
            self.assertIn("new.py", state["plan_owned_files"])

    def test_parser_exposes_only_explicit_reconciliation_commands(self):
        parser = ralph.build_parser()
        plan_hash = "a" * 64
        with self.assertRaises(SystemExit):
            parser.parse_args(["retire-plan", plan_hash, "--reason", "obsolete"])
        with self.assertRaises(SystemExit):
            parser.parse_args(["retire-plan", plan_hash, "--reason", "obsolete", "--rollback", "--carry-forward"])
        command = parser.parse_args(["adopt-carry-forward", plan_hash, "--path", "app.py", "--step", "1", "--ownership-basis", "retired-unchanged-content", "--confirm", "ADOPT"])
        self.assertEqual(command.path, "app.py")
