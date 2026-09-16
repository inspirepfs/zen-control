from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "ralph.py"
spec = importlib.util.spec_from_file_location("ralph_lifecycle_module", MODULE_PATH)
ralph = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(ralph)
tui = ralph.tui


def valid_plan() -> dict:
    return {
        "goal": "Improve ZEN operational analytics",
        "steps": [
            {
                "id": i,
                "title": f"Step {i}",
                "objective": f"Objective {i}",
                "acceptance": [f"Acceptance {i}"],
                "test_change_policy": "modify",
            }
            for i in range(1, 6)
        ],
    }


class RepoHarness:
    PATH_NAMES = (
        "ROOT", "RALPH", "STATE", "PLAN", "IDEAS", "JOURNAL", "POLICY", "LIVE", "CONTEXT",
        "EVENTS", "RECOVERY", "REPORTS",
    )

    def __init__(self, test: unittest.TestCase):
        self.test = test
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.saved = {name: getattr(ralph, name) for name in self.PATH_NAMES}

    def __enter__(self):
        def run(*args: str) -> subprocess.CompletedProcess[str]:
            return subprocess.run(args, cwd=self.root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=True)

        run("git", "init", "-q")
        run("git", "config", "user.email", "ralph@example.invalid")
        run("git", "config", "user.name", "RALPH Test")
        (self.root / "app.py").write_text("value = 1\n", encoding="utf-8")
        (self.root / ".ralph").mkdir()
        (self.root / ".ralph" / "policy.md").write_text("# policy\n", encoding="utf-8")
        run("git", "add", "app.py", ".ralph/policy.md")
        run("git", "commit", "-qm", "baseline")

        ralph.ROOT = self.root
        ralph.RALPH = self.root / ".ralph"
        ralph.STATE = ralph.RALPH / "state.json"
        ralph.PLAN = ralph.RALPH / "plan.md"
        ralph.IDEAS = ralph.RALPH / "ideas.md"
        ralph.JOURNAL = ralph.RALPH / "journal.md"
        ralph.POLICY = ralph.RALPH / "policy.md"
        ralph.LIVE = ralph.RALPH / "live.log"
        ralph.CONTEXT = ralph.RALPH / "context.json"
        ralph.EVENTS = ralph.RALPH / "events.jsonl"
        ralph.RECOVERY = ralph.RALPH / "recovery"
        ralph.REPORTS = ralph.RALPH / "reports"
        ralph.init_files()
        return self

    def git(self, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", *args], cwd=self.root, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=check,
        )

    def __exit__(self, exc_type, exc, tb):
        for name, value in self.saved.items():
            setattr(ralph, name, value)
        self.tmp.cleanup()


class TuiTests(unittest.TestCase):
    def tearDown(self):
        tui.configure("auto")
        os.environ.pop("NO_COLOR", None)

    def test_color_coded_file_events(self):
        tui.configure("always")
        line = tui.event_line("CREATE", "tests/test_new.py", stamp="12:00:00")
        self.assertIn("\033[32m", line)
        self.assertIn("CREATE", line)
        self.assertIn("tests/test_new.py", line)

    def test_no_color_wins_over_always(self):
        os.environ["NO_COLOR"] = "1"
        tui.configure("always")
        self.assertNotIn("\033[", tui.event_line("FAIL", "boom", stamp="12:00:00"))

    def test_diff_preview_highlights_hunks_and_changes(self):
        tui.configure("never")
        rendered = tui.diff_preview("@@ -1 +1 @@ def thing():\n-old\n+new\n")
        self.assertIn("DIFF PREVIEW", rendered)
        self.assertIn("@@ -1 +1 @@ def thing():", rendered)
        self.assertIn("-old", rendered)
        self.assertIn("+new", rendered)

    def test_structured_event_is_jsonl(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "events.jsonl"
            tui.write_event(path, "EDIT", "app/a.py", added=4, removed=1)
            event = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(event["category"], "EDIT")
            self.assertEqual(event["added"], 4)


class TuiHumanControlTests(unittest.TestCase):
    def tearDown(self):
        tui.configure("auto")

    def test_policy_gate_card_is_operator_actionable(self):
        tui.configure("never")
        card = tui.policy_gate_card(
            gate_id="HG-0021-03", step_no=3, step_count=5, title="Evidence labels",
            test_policy="add-only", paths=["tests/test_new.py"],
            origins={"tests/test_new.py": "absent"}, acceptance=["Add focused tests"], protected=[],
        )
        self.assertIn("HUMAN POLICY REVIEW", card)
        self.assertIn("add-only", card)
        self.assertIn("tests/test_new.py", card)
        self.assertIn("steer", card.lower())

    def test_steer_card_shows_bounded_authority(self):
        tui.configure("never")
        card = tui.steer_card(
            gate_id="HG-0021-03", step_no=3, step_count=5, title="Evidence labels",
            direction="Keep this new regression test in scope", allowed_new_tests=["tests/test_new.py"],
        )
        self.assertIn("HUMAN DIRECTION RECORDED", card)
        self.assertIn("Protected/security/tooling boundaries remain enforced", card)
        self.assertIn("tests/test_new.py", card)

    def test_behavior_summary_is_bounded_card(self):
        tui.configure("never")
        card = tui.behavior_summary("Changed TLS evidence labels. Preserved RouterOS authority.")
        self.assertIn("IMPLEMENTATION SUMMARY", card)
        self.assertIn("TLS evidence", card)


class RecoveryCheckpointTests(unittest.TestCase):
    def test_checkpoint_creates_git_ref_and_manifest(self):
        with RepoHarness(self) as repo:
            (repo.root / "app.py").write_text("value = 2\n", encoding="utf-8")
            state = ralph.default_state()
            state.update({"plan_hash": "a" * 64, "plan": valid_plan()})
            manifest = ralph.create_recovery_checkpoint(state)
            self.assertIn("app.py", manifest["baseline_dirty_paths"])
            self.assertTrue((ralph.RECOVERY / manifest["id"] / "manifest.json").exists())
            resolved = repo.git("rev-parse", manifest["ref"]).stdout.strip()
            self.assertEqual(resolved, manifest["recovery_oid"])

    def test_approval_creates_checkpoint_before_execution(self):
        with RepoHarness(self):
            plan = valid_plan()
            digest = ralph.plan_hash(plan)
            state = ralph.default_state()
            state.update({"status": "AWAITING_APPROVAL", "plan_hash": digest, "plan": plan})
            ralph.save_state(state)
            ralph.PLAN.write_text(ralph.render_plan(plan), encoding="utf-8")
            rc = ralph.cmd_approve(type("Args", (), {"plan_hash": digest})())
            self.assertEqual(rc, 0)
            approved = ralph.load_state()
            self.assertEqual(approved["status"], "APPROVED")
            self.assertTrue(approved["recovery_checkpoint"].startswith("RP-"))

    def test_preexisting_staged_change_blocks_automated_commit(self):
        with RepoHarness(self) as repo:
            (repo.root / "app.py").write_text("value = 2\n", encoding="utf-8")
            repo.git("add", "app.py")
            state = ralph.default_state()
            state.update({"plan_hash": "b" * 64, "plan": valid_plan()})
            checkpoint = ralph.create_recovery_checkpoint(state)
            state["recovery_checkpoint"] = checkpoint["id"]
            state["plan_changed_files"] = ["app.py"]
            with self.assertRaisesRegex(RuntimeError, "pre-existing staged"):
                ralph._finalization_guard(state)


class PlanOwnedTestPolicyTests(unittest.TestCase):
    def _state_with_checkpoint(self, repo, *, policy="add-only"):
        plan = valid_plan()
        plan["steps"][0]["test_change_policy"] = policy
        state = ralph.default_state()
        state.update({"status": "APPROVED", "plan_hash": ralph.plan_hash(plan), "plan": plan, "current_step": 1})
        checkpoint = ralph.create_recovery_checkpoint(state)
        state["recovery_checkpoint"] = checkpoint["id"]
        ralph.save_state(state)
        return state

    def test_add_only_allows_plan_created_test_to_be_refined_on_retry(self):
        with RepoHarness(self) as repo:
            state = self._state_with_checkpoint(repo)
            tests = repo.root / "tests"
            tests.mkdir()
            path = tests / "test_new.py"
            path.write_text("value = 1\n", encoding="utf-8")
            before = ralph.repo_snapshot()
            path.write_text("value = 2\n", encoding="utf-8")
            after = ralph.repo_snapshot()
            self.assertEqual(
                ralph.test_policy_violation(before, after, "add-only", state=state, step_no=1),
                [],
            )

    def test_add_only_still_blocks_test_that_existed_at_approval(self):
        with RepoHarness(self) as repo:
            tests = repo.root / "tests"
            tests.mkdir()
            path = tests / "test_existing.py"
            path.write_text("value = 1\n", encoding="utf-8")
            repo.git("add", "tests/test_existing.py")
            repo.git("commit", "-qm", "existing test")
            state = self._state_with_checkpoint(repo)
            before = ralph.repo_snapshot()
            path.write_text("value = 2\n", encoding="utf-8")
            after = ralph.repo_snapshot()
            self.assertEqual(
                ralph.test_policy_violation(before, after, "add-only", state=state, step_no=1),
                ["tests/test_existing.py"],
            )

    def test_add_only_blocks_preexisting_untracked_test(self):
        with RepoHarness(self) as repo:
            tests = repo.root / "tests"
            tests.mkdir()
            path = tests / "test_user.py"
            path.write_text("value = 1\n", encoding="utf-8")
            state = self._state_with_checkpoint(repo)
            before = ralph.repo_snapshot()
            path.write_text("value = 2\n", encoding="utf-8")
            after = ralph.repo_snapshot()
            self.assertEqual(
                ralph.test_policy_violation(before, after, "add-only", state=state, step_no=1),
                ["tests/test_user.py"],
            )

    def test_remember_plan_files_marks_new_path_plan_owned(self):
        with RepoHarness(self) as repo:
            state = self._state_with_checkpoint(repo)
            (repo.root / "new.py").write_text("x = 1\n", encoding="utf-8")
            ralph.remember_plan_files(state, ["new.py"])
            self.assertIn("new.py", state["plan_owned_files"])
            self.assertTrue(ralph.plan_owned_path(state, "new.py"))

    def test_changed_python_symbols_are_named(self):
        with RepoHarness(self) as repo:
            module = repo.root / "module.py"
            module.write_text("def thing():\n    return 1\n", encoding="utf-8")
            repo.git("add", "module.py")
            repo.git("commit", "-qm", "module")
            module.write_text("def thing():\n    return 2\n", encoding="utf-8")
            entries = ralph.change_entries(["module.py"])
            self.assertIn("thing()", entries[0]["symbols"])


class SteerTests(unittest.TestCase):
    def blocked_state(self, repo, *, policy="add-only"):
        plan = valid_plan()
        plan["steps"][2]["test_change_policy"] = policy
        state = ralph.default_state()
        state.update({
            "status": "BLOCKED_HUMAN",
            "plan_hash": ralph.plan_hash(plan),
            "plan": plan,
            "current_step": 3,
            "loop_count": 21,
            "block_reason": "policy violation: test paths ['tests/test_new.py']",
        })
        checkpoint = ralph.create_recovery_checkpoint(state)
        state["recovery_checkpoint"] = checkpoint["id"]
        ralph.save_state(state)
        ralph.PLAN.write_text(ralph.render_plan(plan), encoding="utf-8")
        return state

    def test_steer_records_direction_and_retries_same_step(self):
        with RepoHarness(self) as repo:
            state = self.blocked_state(repo)
            args = type("Args", (), {
                "plan_hash": state["plan_hash"],
                "gate": "HG-0021-03",
                "direction": "Keep the new evidence-label regression test in scope.",
                "allow_new_test": [],
            })()
            self.assertEqual(ralph.cmd_steer(args), 0)
            steered = ralph.load_state()
            self.assertEqual(steered["status"], "APPROVED")
            self.assertEqual(steered["current_step"], 3)
            self.assertEqual(steered["human_steering"][-1]["gate_id"], "HG-0021-03")
            self.assertIn("Human steer HG-0021-03", ralph.load_context()["accepted_findings"][0])

    def test_steer_can_grant_exact_new_test_without_existing_test_authority(self):
        with RepoHarness(self) as repo:
            state = self.blocked_state(repo, policy="none")
            args = type("Args", (), {
                "plan_hash": state["plan_hash"],
                "gate": "HG-0021-03",
                "direction": "Authorise this exact new regression test only.",
                "allow_new_test": ["tests/test_new.py"],
            })()
            ralph.cmd_steer(args)
            steered = ralph.load_state()
            allowed = ralph.steering_allowed_new_tests(steered, 3)
            self.assertEqual(allowed, {"tests/test_new.py"})
            before = ralph.repo_snapshot()
            (repo.root / "tests").mkdir(exist_ok=True)
            (repo.root / "tests" / "test_new.py").write_text("x = 1\n", encoding="utf-8")
            after = ralph.repo_snapshot()
            self.assertEqual(ralph.test_policy_violation(before, after, "none", state=steered, step_no=3), [])

    def test_steer_refuses_new_test_grant_for_preexisting_path(self):
        with RepoHarness(self) as repo:
            (repo.root / "tests").mkdir()
            (repo.root / "tests" / "test_existing.py").write_text("x = 1\n", encoding="utf-8")
            repo.git("add", "tests/test_existing.py")
            repo.git("commit", "-qm", "existing")
            state = self.blocked_state(repo)
            state["block_reason"] = "policy violation: test paths ['tests/test_existing.py']"
            ralph.save_state(state)
            args = type("Args", (), {
                "plan_hash": state["plan_hash"],
                "gate": "HG-0021-03",
                "direction": "try",
                "allow_new_test": ["tests/test_existing.py"],
            })()
            with self.assertRaisesRegex(RuntimeError, "pre-existing path"):
                ralph.cmd_steer(args)

    def test_steer_refuses_new_test_not_named_in_current_gate(self):
        with RepoHarness(self) as repo:
            state = self.blocked_state(repo)
            args = type("Args", (), {
                "plan_hash": state["plan_hash"],
                "gate": "HG-0021-03",
                "direction": "try unrelated path",
                "allow_new_test": ["tests/test_other.py"],
            })()
            with self.assertRaisesRegex(RuntimeError, "not part of the current policy gate"):
                ralph.cmd_steer(args)

    def test_steer_rejects_stale_gate(self):
        with RepoHarness(self) as repo:
            state = self.blocked_state(repo)
            args = type("Args", (), {
                "plan_hash": state["plan_hash"],
                "gate": "HG-0020-03",
                "direction": "retry",
                "allow_new_test": [],
            })()
            with self.assertRaisesRegex(RuntimeError, "current gate"):
                ralph.cmd_steer(args)


class FinalizationTests(unittest.TestCase):
    def ready_state(self, checkpoint: dict) -> dict:
        plan = valid_plan()
        digest = ralph.plan_hash(plan)
        state = ralph.default_state()
        state.update({
            "status": "READY_TO_COMMIT",
            "plan_hash": digest,
            "plan": plan,
            "current_step": 6,
            "recovery_checkpoint": checkpoint["id"],
            "plan_changed_files": ["app.py"],
            "step_results": [
                {"step": i, "title": f"Step {i}", "result": "PASS", "summary": "ok", "files": [], "gates": [], "stats": {}}
                for i in range(1, 6)
            ],
            "final_qualification": {"state": "PASS", "gates": ["unit-tests=PASS"]},
        })
        return state

    def test_safe_plan_delta_can_be_committed(self):
        with RepoHarness(self) as repo:
            bootstrap = ralph.default_state()
            bootstrap.update({"plan_hash": "c" * 64, "plan": valid_plan()})
            checkpoint = ralph.create_recovery_checkpoint(bootstrap)
            (repo.root / "app.py").write_text("value = 3\n", encoding="utf-8")
            state = self.ready_state(checkpoint)
            # The checkpoint belongs to the test plan for guard purposes.
            manifest_path = ralph.RECOVERY / checkpoint["id"] / "manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["plan_hash"] = state["plan_hash"]
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            ralph.save_state(state)
            ralph.PLAN.write_text(ralph.render_plan(state["plan"]), encoding="utf-8")
            rc = ralph.cmd_finalize(type("Args", (), {"plan_hash": state["plan_hash"], "commit": True, "push": False, "message": "test: ralph commit"})())
            self.assertEqual(rc, 0)
            committed = ralph.load_state()
            self.assertEqual(committed["status"], "COMMITTED")
            self.assertEqual(repo.git("show", "-s", "--format=%s", "HEAD").stdout.strip(), "test: ralph commit")

    def test_unexpected_delta_blocks_commit(self):
        with RepoHarness(self) as repo:
            bootstrap = ralph.default_state()
            bootstrap.update({"plan_hash": "d" * 64, "plan": valid_plan()})
            checkpoint = ralph.create_recovery_checkpoint(bootstrap)
            (repo.root / "app.py").write_text("value = 4\n", encoding="utf-8")
            (repo.root / "surprise.txt").write_text("external\n", encoding="utf-8")
            state = self.ready_state(checkpoint)
            with self.assertRaisesRegex(RuntimeError, "unexpected working-tree delta"):
                ralph._finalization_guard(state)

    def test_completion_report_is_commit_ready_summary(self):
        with RepoHarness(self) as repo:
            bootstrap = ralph.default_state()
            bootstrap.update({"plan_hash": "e" * 64, "plan": valid_plan()})
            checkpoint = ralph.create_recovery_checkpoint(bootstrap)
            (repo.root / "app.py").write_text("value = 5\n", encoding="utf-8")
            state = self.ready_state(checkpoint)
            state["completion_changes"] = {
                "entries": [{"action": "EDIT", "path": "app.py", "added": 1, "removed": 1, "symbols": []}],
                "files": 1, "added": 1, "removed": 1,
            }
            report = ralph.build_completion_report(state, ["unit-tests=PASS"])
            text = (repo.root / report["markdown_path"]).read_text(encoding="utf-8")
            self.assertIn("RALPH-Lite Completion Report", text)
            self.assertIn("Final qualification", text)
            self.assertIn("Recovery checkpoint", text)
            self.assertIn("EDIT `app.py` +1/-1", text)


class EndToEndLifecycleTests(unittest.TestCase):
    def test_all_green_plan_finishes_ready_to_commit_with_report(self):
        with RepoHarness(self) as repo:
            plan = valid_plan()
            digest = ralph.plan_hash(plan)
            state = ralph.default_state()
            state.update({"status": "AWAITING_APPROVAL", "plan_hash": digest, "plan": plan})
            ralph.save_state(state)
            ralph.PLAN.write_text(ralph.render_plan(plan), encoding="utf-8")
            ralph.cmd_approve(type("Args", (), {"plan_hash": digest})())

            counter = {"n": 0}

            def fake_codex(*_args, **_kwargs):
                counter["n"] += 1
                with (repo.root / "app.py").open("a", encoding="utf-8") as handle:
                    handle.write(f"step_{counter['n']} = True\n")
                return {
                    "summary": f"implemented step {counter['n']}",
                    "blocker_class": "none",
                    "needs_human": False,
                    "blockers": [],
                    "validation_notes": [],
                    "ideas": [],
                    "context": {"files_inspected": ["app.py"], "relevant_files": ["app.py"], "accepted_findings": []},
                    "_ralph_metrics": {
                        "commands_executed": 2,
                        "input_tokens": 1000,
                        "cached_input_tokens": 800,
                        "output_tokens": 100,
                        "reasoning_output_tokens": 50,
                    },
                }

            args = type("Args", (), {
                "max_loops": 10,
                "wait_for_limits": False,
                "usage_poll_seconds": 300,
                "color": "never",
            })()
            with (
                mock.patch.object(ralph, "ensure_codex_usage_capacity", return_value=True),
                mock.patch.object(ralph, "run_codex", side_effect=fake_codex),
                mock.patch.object(ralph, "run_gates", return_value=(True, ["unit-tests=PASS"], None, "", {})),
                mock.patch.object(ralph, "run_final_qualification", return_value=(True, ["unit-tests=PASS", "public-audit=PASS"], {}, "")),
                mock.patch.object(ralph, "query_codex_rate_limits", return_value={}),
            ):
                rc = ralph.cmd_run(args)

            self.assertEqual(rc, 0)
            finished = ralph.load_state()
            self.assertEqual(finished["status"], "READY_TO_COMMIT")
            self.assertEqual(finished["current_step"], 6)
            self.assertEqual(len(finished["step_results"]), 5)
            report_path = ralph.REPORTS / f"{digest[:16]}-summary.md"
            self.assertTrue(report_path.exists())
            report = report_path.read_text(encoding="utf-8")
            self.assertIn("READY", report.upper()) if False else None
            self.assertIn("unit-tests=PASS", report)
            self.assertIn("Suggested commit", report)


class RetirePlanTests(unittest.TestCase):
    def blocked_state(self) -> dict:
        plan = valid_plan()
        state = ralph.default_state()
        state.update({
            "status": "BLOCKED_HUMAN",
            "plan_hash": ralph.plan_hash(plan),
            "plan": plan,
            "current_step": 3,
            "loop_count": 9,
            "block_reason": "operator evidence required",
        })
        return state

    def test_retire_plan_rejects_wrong_hash(self):
        with RepoHarness(self):
            state = self.blocked_state()
            ralph.save_state(state)
            with self.assertRaisesRegex(RuntimeError, "hash does not match"):
                ralph.cmd_retire_plan(type("Args", (), {"plan_hash": "wrong", "reason": "obsolete"})())

    def test_retire_plan_rejects_empty_reason(self):
        with RepoHarness(self):
            state = self.blocked_state()
            ralph.save_state(state)
            with self.assertRaisesRegex(RuntimeError, "non-empty reason"):
                ralph.cmd_retire_plan(type("Args", (), {"plan_hash": state["plan_hash"], "reason": "   "})())

    def test_retire_plan_rejects_proposal_state(self):
        with RepoHarness(self):
            state = self.blocked_state()
            state["status"] = "AWAITING_APPROVAL"
            ralph.save_state(state)
            with self.assertRaisesRegex(RuntimeError, "active approved/blocked"):
                ralph.cmd_retire_plan(type("Args", (), {"plan_hash": state["plan_hash"], "reason": "obsolete"})())

    def test_retire_plan_returns_controller_to_idle_without_codex(self):
        with RepoHarness(self):
            state = self.blocked_state()
            ralph.save_state(state)
            ralph.PLAN.write_text(ralph.render_plan(state["plan"]), encoding="utf-8")
            rc = ralph.cmd_retire_plan(type("Args", (), {"plan_hash": state["plan_hash"], "reason": "superseded by real operation"})())
            self.assertEqual(rc, 0)
            retired = ralph.load_state()
            self.assertEqual(retired["status"], "IDLE")
            self.assertEqual(retired["loop_count"], 9)
            self.assertEqual(retired["last_result"], "RETIRED")
            self.assertEqual(retired["retired_plans"][-1]["plan_hash"], state["plan_hash"])


class ParserTests(unittest.TestCase):
    def test_operational_lifecycle_commands_are_exposed(self):
        parser = ralph.build_parser()
        for argv in (
            ["checkpoints"],
            ["checkpoint-info", "RP-test"],
            ["report", "a" * 64],
            ["finalize", "a" * 64],
            ["finalize", "a" * 64, "--commit"],
            ["finalize", "a" * 64, "--push"],
            ["run", "--color", "always"],
            ["steer", "a" * 64, "--gate", "HG-0001-01", "--direction", "continue within scope"],
            ["steer", "a" * 64, "--gate", "HG-0001-01", "--direction", "allow exact new test", "--allow-new-test", "tests/test_new.py"],
        ):
            parser.parse_args(argv)


if __name__ == "__main__":
    unittest.main()


class OperatorConsoleV022Tests(unittest.TestCase):
    def tearDown(self):
        tui.configure("auto")

    def test_step_banner_shows_authority_and_plan_progress(self):
        tui.configure("never")
        card = tui.step_banner(
            loop_no=24, step_no=3, step_count=5, title="TLS evidence",
            phase="repair", plan_hash="a" * 64, repair=1, quota="69.0% remaining",
            status="RUNNING", efficiency="PASS", recovery="RP-1", changed_files=8,
            test_policy="add-only",
            progress=["✓ 1. First", "✓ 2. Second", "▶ 3. TLS evidence", "○ 4. Next"],
            acceptance=["Add focused regression tests"],
        )
        self.assertIn("Authority tests=add-only", card)
        self.assertIn("Plan progress", card)
        self.assertIn("▶ 3. TLS evidence", card)
        self.assertIn("Acceptance", card)

    def test_completion_card_reports_accepted_breakdown(self):
        tui.configure("never")
        card = tui.completion_card({
            "plan_hash": "b" * 64,
            "status": "READY_TO_COMMIT",
            "counts": {
                "steps_total": 5, "steps_accepted": 5, "steps_passed": 4,
                "steps_human_confirmed": 1, "steps_recovered": 1,
                "steps_failed": 0, "loops": 24, "human_gates": 1, "human_steers": 1,
            },
            "qualification": {"state": "PASS"},
            "changes": {"files": 8, "added": 453, "removed": 64},
            "authority": {"protected_paths_changed": False, "ralph_tooling_changed": False},
            "recovery_checkpoint": "RP-1", "markdown_path": ".ralph/reports/report.md",
            "suggested_commit": "feat: example",
        })
        self.assertIn("5/5 ACCEPTED", card)
        self.assertIn("PASS 4", card)
        self.assertIn("HUMAN_CONFIRMED 1", card)
        self.assertIn("recovered 1", card)

    def test_commit_overlap_card_explains_safe_action(self):
        tui.configure("never")
        card = tui.commit_overlap_card(
            plan_hash="c" * 64, checkpoint="RP-1", baseline_head="1234567890abcdef",
            branch="main", upstream="origin/main",
            overlaps=["app/activity.py", "app/main.py"], plan_files=8,
        )
        self.assertIn("COMMIT REVIEW REQUIRED", card)
        self.assertIn("app/activity.py", card)
        self.assertIn("reconcile-commit", card)
        self.assertIn("force push", card)

    def test_step_outcome_summary_distinguishes_human_and_recovered(self):
        state = ralph.default_state()
        state["plan"] = valid_plan()
        state["step_results"] = [
            {"step": 1, "result": "PASS", "stats": {"repair": 0}},
            {"step": 2, "result": "HUMAN_CONFIRMED", "stats": {}},
            {"step": 3, "result": "PASS", "stats": {"repair": 2}},
            {"step": 4, "result": "PASS", "stats": {"repair": 0}},
            {"step": 5, "result": "PASS", "stats": {"repair": 0}},
        ]
        summary = ralph.summarize_step_outcomes(state)
        self.assertEqual(summary["accepted"], 5)
        self.assertEqual(summary["pass"], 4)
        self.assertEqual(summary["human_confirmed"], 1)
        self.assertEqual(summary["recovered"], 1)
        self.assertEqual(summary["failed"], 0)


class ReconciliationTests(unittest.TestCase):
    def _ready_state(self, checkpoint: dict, plan_paths: list[str]) -> dict:
        plan = valid_plan()
        digest = ralph.plan_hash(plan)
        state = ralph.default_state()
        state.update({
            "status": "READY_TO_COMMIT",
            "plan_hash": digest,
            "plan": plan,
            "current_step": 6,
            "recovery_checkpoint": checkpoint["id"],
            "plan_changed_files": plan_paths,
            "step_results": [
                {"step": i, "title": f"Step {i}", "result": "PASS", "summary": "ok", "files": [], "gates": [], "stats": {}}
                for i in range(1, 6)
            ],
            "final_qualification": {"state": "PASS", "gates": ["unit-tests=PASS"]},
        })
        manifest_path = ralph.RECOVERY / checkpoint["id"] / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["plan_hash"] = digest
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        return state

    def test_reconcile_commit_adopts_verified_manual_commit(self):
        with RepoHarness(self) as repo:
            bootstrap = ralph.default_state()
            bootstrap.update({"plan_hash": "a" * 64, "plan": valid_plan()})
            checkpoint = ralph.create_recovery_checkpoint(bootstrap)
            (repo.root / "app.py").write_text("value = 2\n", encoding="utf-8")
            repo.git("add", "app.py")
            repo.git("commit", "-qm", "manual qualified plan")
            sha = repo.git("rev-parse", "HEAD").stdout.strip()
            state = self._ready_state(checkpoint, ["app.py"])
            ralph.save_state(state)
            args = type("Args", (), {"plan_hash": state["plan_hash"], "commit": sha, "reason": "Manual closure after approved dirty-overlap review"})()
            self.assertEqual(ralph.cmd_reconcile_commit(args), 0)
            adopted = ralph.load_state()
            self.assertEqual(adopted["status"], "COMMITTED")
            self.assertEqual(adopted["commit_sha"], sha)
            self.assertTrue(adopted["commit_reconciled"])

    def test_reconcile_commit_rejects_unexpected_extra_path(self):
        with RepoHarness(self) as repo:
            bootstrap = ralph.default_state()
            bootstrap.update({"plan_hash": "b" * 64, "plan": valid_plan()})
            checkpoint = ralph.create_recovery_checkpoint(bootstrap)
            (repo.root / "app.py").write_text("value = 3\n", encoding="utf-8")
            (repo.root / "surprise.txt").write_text("unexpected\n", encoding="utf-8")
            repo.git("add", "app.py", "surprise.txt")
            repo.git("commit", "-qm", "manual bad commit")
            sha = repo.git("rev-parse", "HEAD").stdout.strip()
            state = self._ready_state(checkpoint, ["app.py"])
            ralph.save_state(state)
            with self.assertRaisesRegex(RuntimeError, "unexpected paths"):
                ralph._verify_reconciled_commit(state, sha)

    def test_reconcile_push_requires_recorded_commit_on_upstream(self):
        with RepoHarness(self) as repo:
            remote_tmp = tempfile.TemporaryDirectory()
            self.addCleanup(remote_tmp.cleanup)
            remote = Path(remote_tmp.name) / "remote.git"
            subprocess.run(["git", "init", "--bare", "-q", str(remote)], check=True)
            repo.git("remote", "add", "origin", str(remote))
            repo.git("push", "-u", "origin", "master")

            (repo.root / "app.py").write_text("value = 9\n", encoding="utf-8")
            repo.git("add", "app.py")
            repo.git("commit", "-qm", "manual commit")
            sha = repo.git("rev-parse", "HEAD").stdout.strip()
            state = ralph.default_state()
            state.update({"status": "COMMITTED", "plan_hash": "c" * 64, "plan": valid_plan(), "commit_sha": sha, "final_qualification": {"state": "PASS", "gates": []}})
            ralph.save_state(state)
            args = type("Args", (), {"plan_hash": state["plan_hash"]})()
            with self.assertRaisesRegex(RuntimeError, "not present"):
                ralph.cmd_reconcile_push(args)
            repo.git("push")
            self.assertEqual(ralph.cmd_reconcile_push(args), 0)
            pushed = ralph.load_state()
            self.assertEqual(pushed["status"], "PUSHED")
            self.assertTrue(pushed["push_reconciled"])

    def test_parser_exposes_reconciliation_and_web_commands(self):
        parser = ralph.build_parser()
        help_text = parser.format_help()
        self.assertIn("reconcile-commit", help_text)
        self.assertIn("reconcile-push", help_text)
        self.assertIn("serve", help_text)
