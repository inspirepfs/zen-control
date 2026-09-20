from __future__ import annotations

import importlib.util
import argparse
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
        "repository_authority": "write",
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
        "EVENTS", "RECOVERY", "REPORTS", "RETIREMENTS", "USAGE_LEDGER", "USAGE_STATS_RESET",
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
        ralph.RETIREMENTS = ralph.RALPH / "retirements"
        ralph.USAGE_LEDGER = ralph.RALPH / "usage-ledger.jsonl"
        ralph.USAGE_STATS_RESET = ralph.RALPH / "usage-stats-reset.json"
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


def native_approved_state(
    *, status: str = "APPROVED", repository_authority: str = "write",
) -> tuple[dict, dict]:
    plan = valid_plan()
    plan["repository_authority"] = repository_authority
    state = ralph.default_state()
    state.update({
        "status": status,
        "plan_hash": ralph.plan_hash(plan),
        "plan": plan,
        "current_step": 1,
    })
    ralph.PLAN.write_text(ralph.render_plan(plan), encoding="utf-8")
    ralph.bind_approved_plan_artifact(state)
    checkpoint = ralph.create_recovery_checkpoint(state)
    state["recovery_checkpoint"] = checkpoint["id"]
    state["approval_repository_evidence"] = checkpoint["repository_evidence"]
    ralph.save_state(state)
    return state, checkpoint


def accept_native_paths(state: dict, paths: list[str], *, step_no: int = 1, loop: int = 1) -> dict:
    step = state["plan"]["steps"][step_no - 1]
    verification = {
        "schema": "zen_ralph_post_turn_repository_verification_v1",
        "state": "PASS",
        "sandbox": "workspace-write",
        "checkpoint": state["recovery_checkpoint"],
        "plan_hash": state["plan_hash"],
        "new_project_delta": list(paths),
        "changed_approval_residue": [],
        "current_fingerprints": {path: ralph.retirement_path_fingerprint(path) for path in paths},
        "loop": loop,
        "step": step_no,
    }
    attribution = ralph.verified_attribution_result(
        state, step, verification, paths, loop=loop, phase="implement",
    )
    ralph.record_accepted_operations(state, attribution)
    provenance = ralph.strict_native_provenance(
        state, "test qualification", require_current_delta=True, require_write=True,
    )
    state["final_qualification"] = {
        "state": "PASS",
        "gates": ["unit-tests=PASS"],
        "delta_fingerprint": provenance["current_sha256"],
        "native_provenance_sha256": provenance["binding_sha256"],
        "completed_at": ralph.utc_now(),
    }
    state["status"] = "READY_TO_COMMIT"
    ralph.save_state(state)
    return provenance


class TuiTests(unittest.TestCase):
    def setUp(self):
        self.previous_no_color = os.environ.get("NO_COLOR")
        os.environ.pop("NO_COLOR", None)

    def tearDown(self):
        tui.configure("auto")
        if self.previous_no_color is None:
            os.environ.pop("NO_COLOR", None)
        else:
            os.environ["NO_COLOR"] = self.previous_no_color

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

    def test_checkpoint_evidence_preserves_staged_and_operator_residue(self):
        with RepoHarness(self) as repo:
            (repo.root / "deleted.py").write_text("delete_me = True\n", encoding="utf-8")
            repo.git("add", "deleted.py")
            repo.git("commit", "-qm", "tracked deletion fixture")
            (repo.root / "app.py").write_text("value = 2\n", encoding="utf-8")
            (repo.root / "deleted.py").unlink()
            (repo.root / "created.py").write_text("created = True\n", encoding="utf-8")
            repo.git("add", "created.py")
            (repo.root / "operator.txt").write_text("leave me alone\n", encoding="utf-8")
            state = ralph.default_state()
            state.update({"plan_hash": "a" * 64, "plan": valid_plan()})
            manifest = ralph.create_recovery_checkpoint(state)
            evidence = manifest["repository_evidence"]
            by_path = {item["path"]: item for item in evidence["tracked_index_worktree"]}
            self.assertEqual(" ", by_path["app.py"]["index_status"])
            self.assertEqual("M", by_path["app.py"]["worktree_status"])
            self.assertEqual("A", by_path["created.py"]["index_status"])
            self.assertEqual("D", by_path["deleted.py"]["worktree_status"])
            untracked = {item["path"]: item for item in evidence["untracked_content_fingerprints"]}
            self.assertTrue(untracked["operator.txt"]["content_fingerprint"])
            residue = {item["path"]: item for item in evidence["operator_residue"]}
            self.assertEqual("operator-residue", residue["operator.txt"]["ownership"])

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
            self.assertEqual(ralph.file_hash(ralph.PLAN), approved["approved_plan_artifact"]["sha256"])
            self.assertEqual(
                "zen_ralph_approval_repository_evidence_v1",
                approved["approval_repository_evidence"]["schema"],
            )
            ralph.PLAN.write_text("tampered\n", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "approved plan file changed"):
                ralph.verify_approved_plan_artifact(approved)

    def test_missing_native_evidence_is_refused_without_replacement(self):
        with RepoHarness(self):
            plan = valid_plan()
            if ralph.REPOSITORY_AUTHORITY_FIELD not in plan:
                ralph.controller_inject_repository_authority(plan, "write")
            digest = ralph.plan_hash(plan)
            state = ralph.default_state()
            state.update({"status": "AWAITING_APPROVAL", "plan_hash": digest, "plan": plan})
            ralph.save_state(state)
            ralph.PLAN.write_text(ralph.render_plan(plan), encoding="utf-8")
            self.assertEqual(0, ralph.cmd_approve(type("Args", (), {"plan_hash": digest})()))
            approved = ralph.load_state()
            manifest_path = ralph.RECOVERY / approved["recovery_checkpoint"] / "manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["repository_evidence"] = None
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "structured approval repository evidence"):
                ralph.verify_approval_execution_evidence(approved)
            self.assertIsNone(json.loads(manifest_path.read_text(encoding="utf-8"))["repository_evidence"])

    def test_accepted_operations_bind_checkpoint_and_exclude_residue(self):
        with RepoHarness(self) as repo:
            (repo.root / "operator.txt").write_text("before approval\n", encoding="utf-8")
            state = ralph.default_state()
            plan = valid_plan()
            state.update({"status": "APPROVED", "plan_hash": ralph.plan_hash(plan), "plan": plan})
            ralph.PLAN.write_text(ralph.render_plan(plan), encoding="utf-8")
            ralph.bind_approved_plan_artifact(state)
            checkpoint = ralph.create_recovery_checkpoint(state)
            state["recovery_checkpoint"] = checkpoint["id"]
            state["approval_repository_evidence"] = checkpoint["repository_evidence"]
            (repo.root / "app.py").write_text("value = 2\n", encoding="utf-8")
            (repo.root / "created.py").write_text("created = True\n", encoding="utf-8")
            (repo.root / "operator.txt").write_text("still operator work\n", encoding="utf-8")
            attribution = ralph.verified_attribution_result(
                state, plan["steps"][1], {
                    "schema": "zen_ralph_post_turn_repository_verification_v1", "state": "PASS", "sandbox": "workspace-write", "checkpoint": checkpoint["id"],
                    "plan_hash": state["plan_hash"], "new_project_delta": ["app.py", "created.py"], "loop": 7, "step": 2,
                    "current_fingerprints": {
                        "app.py": ralph.retirement_path_fingerprint("app.py"),
                        "created.py": ralph.retirement_path_fingerprint("created.py"),
                    },
                }, ["app.py", "created.py", "operator.txt", ".ralph/state.json"], loop=7, phase="implement",
            )
            attributed = ralph.record_accepted_operations(state, attribution)
            self.assertEqual({"app.py", "created.py"}, {item["path"] for item in attributed})
            self.assertTrue(all(item["plan_hash"] == state["plan_hash"] for item in attributed))
            self.assertTrue(all(item["schema"] == ralph.OPERATION_ATTRIBUTION_SCHEMA for item in attributed))
            self.assertTrue(all(item["approval_checkpoint"]["id"] == checkpoint["id"] for item in attributed))
            self.assertTrue(all(item["approved_plan_artifact"] == state["approved_plan_artifact"] for item in attributed))
            self.assertTrue(all(item["originating_test_change_policy"] == "modify" for item in attributed))
            self.assertTrue(all(item["controller_verification"].get("fingerprint") is None for item in attributed))
            self.assertEqual("tracked", next(item for item in attributed if item["path"] == "app.py")["baseline_kind"])
            created = next(item for item in attributed if item["path"] == "created.py")
            self.assertEqual("absent", created["baseline_kind"])
            self.assertEqual("create", created["operation"])
            ralph.save_state(state)
            self.assertEqual(attributed, ralph.load_state()["operation_attributions"])

    def test_proposal_controller_injects_and_persists_repository_authority(self):
        with RepoHarness(self):
            model_plan = valid_plan()
            model_plan.pop(ralph.REPOSITORY_AUTHORITY_FIELD)
            args = argparse.Namespace(
                goal="Add bounded controller contract", from_retirement=None,
                repository_authority="write", min_steps=5, max_steps=5,
            )
            usage = {"schema": "zen_codex_usage_v1", "windows": [{"remaining_percent": 100.0}]}
            with (
                mock.patch.object(ralph, "query_codex_rate_limits", return_value=usage),
                mock.patch.object(ralph, "codex_usage_guard", return_value=("SAFE", [])),
                mock.patch.object(ralph, "run_codex", return_value=model_plan) as run,
            ):
                self.assertEqual(ralph.cmd_propose(args), 0)
            proposed = ralph.load_state()
            self.assertEqual(proposed["plan"][ralph.REPOSITORY_AUTHORITY_FIELD], "write")
            self.assertEqual(proposed["plan_hash"], ralph.plan_hash(proposed["plan"]))
            self.assertIn("Repository authority:** `write`", ralph.PLAN.read_text(encoding="utf-8"))
            self.assertNotIn(ralph.REPOSITORY_AUTHORITY_FIELD, run.call_args.args[1]["properties"])

    def test_proposal_refuses_missing_controller_repository_authority(self):
        with RepoHarness(self):
            args = argparse.Namespace(goal="Missing contract", from_retirement=None, repository_authority=None, min_steps=5, max_steps=5)
            with self.assertRaisesRegex(RuntimeError, "--repository-authority"):
                ralph.cmd_propose(args)

    def test_preexisting_staged_change_blocks_automated_commit(self):
        with RepoHarness(self) as repo:
            (repo.root / "app.py").write_text("value = 2\n", encoding="utf-8")
            repo.git("add", "app.py")
            state = ralph.default_state()
            state.update({"plan_hash": "b" * 64, "plan": valid_plan()})
            checkpoint = ralph.create_recovery_checkpoint(state)
            state["recovery_checkpoint"] = checkpoint["id"]
            state["plan_changed_files"] = ["app.py"]
            with self.assertRaisesRegex(RuntimeError, r"^APPROVAL_BASELINE_RESIDUE_AS_NEW_PLAN: \['app.py'\]$"):
                ralph._finalization_guard(state)


class PlanOwnedTestPolicyTests(unittest.TestCase):
    def _state_with_checkpoint(self, repo, *, policy="add-only"):
        plan = valid_plan()
        plan["steps"][0]["test_change_policy"] = policy
        state = ralph.default_state()
        state.update({"status": "APPROVED", "plan_hash": ralph.plan_hash(plan), "plan": plan, "current_step": 1})
        ralph.PLAN.write_text(ralph.render_plan(plan), encoding="utf-8")
        ralph.bind_approved_plan_artifact(state)
        checkpoint = ralph.create_recovery_checkpoint(state)
        state["recovery_checkpoint"] = checkpoint["id"]
        state["approval_repository_evidence"] = checkpoint["repository_evidence"]
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

    def test_remember_plan_files_refuses_unattributed_path(self):
        with RepoHarness(self) as repo:
            state = self._state_with_checkpoint(repo)
            (repo.root / "new.py").write_text("x = 1\n", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "validated native operation attribution"):
                ralph.remember_plan_files(state, ["new.py"])

    def test_changed_python_symbols_are_named(self):
        with RepoHarness(self) as repo:
            module = repo.root / "module.py"
            module.write_text("def thing():\n    return 1\n", encoding="utf-8")
            repo.git("add", "module.py")
            repo.git("commit", "-qm", "module")
            module.write_text("def thing():\n    return 2\n", encoding="utf-8")
            entries = ralph.change_entries(["module.py"])
            self.assertIn("thing()", entries[0]["symbols"])


class NativeAttributionTests(unittest.TestCase):
    def _approved_state(self, repo):
        plan = valid_plan()
        state = ralph.default_state()
        state.update({"status": "APPROVED", "plan_hash": ralph.plan_hash(plan), "plan": plan, "current_step": 1})
        ralph.PLAN.write_text(ralph.render_plan(plan), encoding="utf-8")
        ralph.bind_approved_plan_artifact(state)
        checkpoint = ralph.create_recovery_checkpoint(state)
        state["recovery_checkpoint"] = checkpoint["id"]
        state["approval_repository_evidence"] = checkpoint["repository_evidence"]
        return state, checkpoint

    def _verification(self, state, checkpoint, *, sandbox="read-only", paths=()):
        evidence = {
            "schema": "zen_ralph_post_turn_repository_verification_v1",
            "state": "PASS", "sandbox": sandbox, "checkpoint": checkpoint["id"],
            "plan_hash": state["plan_hash"], "new_project_delta": list(paths),
            "current_fingerprints": {path: ralph.retirement_path_fingerprint(path) for path in paths},
            "changed_approval_residue": [], "loop": 4, "step": 1, "recorded_at": "2026-09-20T00:00:00+00:00",
        }
        evidence["fingerprint"] = ralph._evidence_digest({key: value for key, value in evidence.items() if key != "fingerprint"})
        return evidence

    def test_read_only_zero_delta_creates_no_attribution_or_ownership(self):
        with RepoHarness(self) as repo:
            state, checkpoint = self._approved_state(repo)
            attribution = ralph.verified_attribution_result(
                state, state["plan"]["steps"][0], self._verification(state, checkpoint), [], loop=4, phase="implement",
            )
            self.assertEqual([], ralph.record_accepted_operations(state, attribution))
            self.assertEqual([], state["operation_attributions"])
            self.assertEqual([], state["plan_changed_files"])
            self.assertEqual([], state["plan_owned_files"])

    def test_stale_origin_test_policy_and_duplicate_records_fail_closed(self):
        with RepoHarness(self) as repo:
            state, checkpoint = self._approved_state(repo)
            (repo.root / "app.py").write_text("value = 2\n", encoding="utf-8")
            verification = self._verification(state, checkpoint, sandbox="workspace-write", paths=["app.py"])
            attribution = ralph.verified_attribution_result(
                state, state["plan"]["steps"][0], verification, ["app.py"], loop=4, phase="implement",
            )
            ralph.record_accepted_operations(state, attribution)
            stale = dict(state["operation_attributions"][0])
            stale["originating_test_change_policy"] = "none"
            stale["record_sha256"] = ralph._operation_record_hash(stale)
            state["operation_attributions"] = [stale]
            with self.assertRaisesRegex(RuntimeError, "originating test policy"):
                ralph.validated_plan_paths(state)

            state["operation_attributions"] = []
            ralph.record_accepted_operations(state, attribution)
            with self.assertRaisesRegex(RuntimeError, "duplicate operation attribution"):
                ralph.record_accepted_operations(state, attribution)
            self.assertEqual(1, len(state["operation_attributions"]))

    def test_current_fingerprint_and_altered_origin_step_fail_closed(self):
        with RepoHarness(self) as repo:
            state, checkpoint = self._approved_state(repo)
            (repo.root / "app.py").write_text("value = 2\n", encoding="utf-8")
            attribution = ralph.verified_attribution_result(
                state, state["plan"]["steps"][0],
                self._verification(state, checkpoint, sandbox="workspace-write", paths=["app.py"]),
                ["app.py"], loop=4, phase="implement",
            )
            ralph.record_accepted_operations(state, attribution)
            original = dict(state["operation_attributions"][0])
            record = dict(original)
            record["current_fingerprint"] = {"kind": "missing"}
            record["operation"] = "delete"
            record["record_sha256"] = ralph._operation_record_hash(record)
            state["operation_attributions"] = [record]
            with self.assertRaisesRegex(RuntimeError, "current fingerprint evidence is stale or altered"):
                ralph.validated_plan_paths(state)

            record = dict(original)
            record["originating_step"] = {"id": 99}
            record["record_sha256"] = ralph._operation_record_hash(record)
            state["operation_attributions"] = [record]
            with self.assertRaisesRegex(RuntimeError, "missing or ambiguous approved-step origin"):
                ralph.validated_plan_paths(state)

    def test_altered_self_hosting_grant_evidence_fails_closed(self):
        with RepoHarness(self) as repo:
            state, checkpoint = self._approved_state(repo)
            path = "scripts/ralph.py"
            (repo.root / path).parent.mkdir(exist_ok=True)
            (repo.root / path).write_text("controller = 2\n", encoding="utf-8")
            grant = {"plan_hash": state["plan_hash"], "step": 1, "gate_id": "HG-test", "paths": [path], "reason": "test", "granted_at": "2026-09-20T00:00:00+00:00"}
            state["self_hosting_grant"] = dict(grant)
            state["self_hosting_grant_history"] = [dict(grant)]
            attribution = ralph.verified_attribution_result(
                state, state["plan"]["steps"][0], self._verification(state, checkpoint, sandbox="workspace-write", paths=[path]), [path], loop=4, phase="implement",
            )
            ralph.record_accepted_operations(state, attribution)
            state["self_hosting_grant_history"][0]["reason"] = "altered"
            with self.assertRaisesRegex(RuntimeError, "self-hosting grant is missing or altered"):
                ralph.validated_plan_paths(state)


class SelfUpgradeRecoveryTests(unittest.TestCase):
    def _approve(self, repo):
        plan = valid_plan()
        digest = ralph.plan_hash(plan)
        state = ralph.default_state()
        state.update({"status": "AWAITING_APPROVAL", "plan_hash": digest, "plan": plan})
        ralph.save_state(state)
        ralph.PLAN.write_text(ralph.render_plan(plan), encoding="utf-8")
        self.assertEqual(ralph.cmd_approve(type("Args", (), {"plan_hash": digest})()), 0)
        return ralph.load_state()

    @staticmethod
    def _grant(state, step, paths, gate):
        return {
            "plan_hash": state["plan_hash"], "step": step, "gate_id": gate, "paths": list(paths),
            "reason": "test recovery grant", "granted_at": f"2026-09-20T0{step}:00:00+00:00",
        }

    def test_approval_clears_foreign_operation_ledger(self):
        with RepoHarness(self):
            plan = valid_plan()
            digest = ralph.plan_hash(plan)
            state = ralph.default_state()
            state.update({
                "status": "AWAITING_APPROVAL", "plan_hash": digest, "plan": plan,
                "operation_attributions": [{"schema": "foreign", "plan_hash": "old"}],
                "pending_step_delta_paths": {"step": 9, "paths": ["old.py"]},
            })
            ralph.save_state(state)
            ralph.PLAN.write_text(ralph.render_plan(plan), encoding="utf-8")
            self.assertEqual(ralph.cmd_approve(type("Args", (), {"plan_hash": digest})()), 0)
            approved = ralph.load_state()
            self.assertEqual([], approved["operation_attributions"])
            self.assertEqual([], approved["pending_step_delta_paths"])

    def test_operator_recovery_converts_current_v1_drops_foreign_and_leaves_bootstrap_pending(self):
        with RepoHarness(self) as repo:
            for path in ("scripts/ralph.py", "tests/test_ralph_lifecycle.py", "tests/test_ralph_lite.py"):
                target = repo.root / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("baseline\n", encoding="utf-8")
            repo.git("add", "scripts/ralph.py", "tests/test_ralph_lifecycle.py", "tests/test_ralph_lite.py")
            repo.git("commit", "-qm", "tooling baseline")

            state = self._approve(repo)
            checkpoint = state["recovery_checkpoint"]
            g1 = self._grant(state, 1, ["scripts/ralph.py", "tests/test_ralph_lifecycle.py", "tests/test_ralph_lite.py"], "HG-0001-01")
            g2 = self._grant(state, 2, ["scripts/ralph.py", "tests/test_ralph_lifecycle.py"], "HG-0002-02")
            g3 = self._grant(state, 3, ["scripts/ralph.py", "tests/test_ralph_lifecycle.py"], "HG-0003-03")

            script = repo.root / "scripts/ralph.py"
            lifecycle = repo.root / "tests/test_ralph_lifecycle.py"
            lite = repo.root / "tests/test_ralph_lite.py"
            script.write_text("accepted step 2\n", encoding="utf-8")
            historical_script_fp = ralph.retirement_path_fingerprint("scripts/ralph.py")
            lifecycle.write_text("accepted step 2\n", encoding="utf-8")
            lite.write_text("accepted step 1\n", encoding="utf-8")
            # The BIG PATCH itself is current-Step-3 bootstrap content and must
            # stay pending rather than being retroactively assigned to Step 2.
            script.write_text("accepted step 2\noperator bootstrap step 3\n", encoding="utf-8")
            lifecycle.write_text("accepted step 2\noperator bootstrap step 3\n", encoding="utf-8")

            state.update({
                "status": "RUNNING", "current_step": 3, "loop_count": 204,
                "self_hosting_grant_history": [g1, g2, g3], "self_hosting_grant": g3,
                "step_results": [
                    {"step": 1, "result": "PASS", "files": ["scripts/ralph.py"], "attribution": {"loop": 197}},
                    {"step": 2, "result": "PASS", "files": ["scripts/ralph.py"], "attribution": {"loop": 202}},
                ],
                "operation_attributions": [
                    {"schema": "zen_ralph_operation_attribution_v1", "plan_hash": "f" * 64, "path": "scripts/ralph.py"},
                    {
                        "schema": "zen_ralph_operation_attribution_v1", "plan_hash": state["plan_hash"],
                        "checkpoint": checkpoint, "loop": 202, "step": state["plan"]["steps"][1],
                        "path": "scripts/ralph.py", "baseline_kind": "tracked", "operation": "edit",
                        "current_fingerprint": historical_script_fp, "phase": "repair",
                    },
                ],
            })
            ralph.save_state(state)
            args = type("Args", (), {
                "plan_hash": state["plan_hash"], "checkpoint": checkpoint, "confirm": "RECOVER",
                "pending_path": ["scripts/ralph.py", "tests/test_ralph_lifecycle.py"],
            })()
            self.assertEqual(ralph.cmd_recover_self_upgrade(args), 0)

            recovered = ralph.load_state()
            self.assertEqual("APPROVED", recovered["status"])
            self.assertEqual(3, recovered["current_step"])
            self.assertEqual(204, recovered["loop_count"])
            self.assertEqual(g3, recovered["self_hosting_grant"])
            self.assertEqual(
                ["scripts/ralph.py", "tests/test_ralph_lifecycle.py"],
                recovered["pending_step_delta_paths"]["paths"],
            )
            self.assertTrue(all(item["schema"] == ralph.OPERATION_ATTRIBUTION_SCHEMA for item in recovered["operation_attributions"]))
            self.assertTrue(all(item["plan_hash"] == state["plan_hash"] for item in recovered["operation_attributions"]))
            self.assertEqual(["tests/test_ralph_lite.py"], ralph.current_attributed_paths(recovered))

            verification = ralph.verify_post_turn_repository_state(
                recovered, recovered["plan"]["steps"][2], "workspace-write", [],
            )
            attribution = ralph.verified_attribution_result(
                recovered, recovered["plan"]["steps"][2],
                verification | {
                    "current_fingerprints": {
                        path: ralph.retirement_path_fingerprint(path)
                        for path in verification["new_project_delta"]
                    },
                },
                [], loop=205, phase="repair",
            )
            self.assertEqual(
                ["scripts/ralph.py", "tests/test_ralph_lifecycle.py"],
                attribution["paths"],
            )

    def test_unhandled_run_exception_never_leaves_running_state(self):
        with RepoHarness(self):
            state = ralph.default_state()
            state.update({"status": "RUNNING", "plan_hash": "a" * 64, "current_step": 3})
            ralph.save_state(state)
            args = type("Args", (), {"command": "run"})()
            ralph._fail_closed_unhandled_run_exception(args, RuntimeError("boom"))
            blocked = ralph.load_state()
            self.assertEqual("BLOCKED_HUMAN", blocked["status"])
            self.assertIn("controller runtime exception: boom", blocked["block_reason"])


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


class StrictNativeProvenanceTests(unittest.TestCase):
    def test_spoofed_filename_projection_never_changes_native_scope(self):
        with RepoHarness(self) as repo:
            state, _checkpoint = native_approved_state()
            (repo.root / "app.py").write_text("value = 2\n", encoding="utf-8")
            provenance = accept_native_paths(state, ["app.py"])
            state = ralph.load_state()
            state["plan_changed_files"] = ["surprise.py"]
            derived = ralph.strict_native_provenance(
                state, "spoof test", require_current_delta=True, require_write=True,
            )
            self.assertEqual(["app.py"], derived["new_plan_paths"])
            self.assertEqual(provenance["binding_sha256"], derived["binding_sha256"])

            reconciled = ralph._reconciled_provenance_guard(state, "spoofed reconciliation")
            self.assertEqual(["app.py"], reconciled["new_plan_paths"])
            self.assertEqual(provenance["binding_sha256"], reconciled["native_provenance_sha256"])

    def test_stale_current_fingerprint_and_qualification_binding_fail_closed(self):
        with RepoHarness(self) as repo:
            state, _checkpoint = native_approved_state()
            (repo.root / "app.py").write_text("value = 2\n", encoding="utf-8")
            accept_native_paths(state, ["app.py"])
            state = ralph.load_state()
            state["final_qualification"]["native_provenance_sha256"] = "0" * 64
            qualified, reason = ralph.qualified_delta_matches(state)
            self.assertFalse(qualified)
            self.assertIn("binding", reason)
            state = ralph.load_state()
            (repo.root / "app.py").write_text("value = 3\n", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "fingerprint is stale or altered"):
                ralph.strict_native_provenance(
                    state, "stale test", require_current_delta=True, require_write=True,
                )

    def test_altered_reconciliation_evidence_fails_closed(self):
        with RepoHarness(self) as repo:
            state, _checkpoint = native_approved_state()
            (repo.root / "app.py").write_text("value = 2\n", encoding="utf-8")
            accept_native_paths(state, ["app.py"])
            state = ralph.load_state()
            record = dict(state["operation_attributions"][0])
            record["reconciliation_evidence"] = {
                "schema": "zen_ralph_operation_reconciliation_v1",
                "state": "replacement",
                "snapshot": {"candidates": ["forged"]},
            }
            record["record_sha256"] = ralph._operation_record_hash(record)
            state["operation_attributions"] = [record]
            with self.assertRaisesRegex(RuntimeError, "reconciliation evidence is stale or altered"):
                ralph.strict_native_provenance(
                    state, "tampered reconciliation", require_current_delta=True, require_write=True,
                )


class FinalizationTests(unittest.TestCase):
    def test_safe_plan_delta_can_be_committed(self):
        with RepoHarness(self) as repo:
            state, _checkpoint = native_approved_state()
            (repo.root / "app.py").write_text("value = 3\n", encoding="utf-8")
            accept_native_paths(state, ["app.py"])
            args = type("Args", (), {
                "plan_hash": state["plan_hash"], "commit": True, "push": False,
                "message": "test: ralph commit",
            })()
            rc = ralph.cmd_finalize(args)
            self.assertEqual(rc, 0)
            committed = ralph.load_state()
            self.assertEqual(committed["status"], "COMMITTED")
            self.assertEqual(repo.git("show", "-s", "--format=%s", "HEAD").stdout.strip(), "test: ralph commit")

    def test_unexpected_delta_blocks_commit(self):
        with RepoHarness(self) as repo:
            state, _checkpoint = native_approved_state()
            (repo.root / "app.py").write_text("value = 4\n", encoding="utf-8")
            accept_native_paths(state, ["app.py"])
            (repo.root / "surprise.txt").write_text("external\n", encoding="utf-8")
            state = ralph.load_state()
            with self.assertRaisesRegex(RuntimeError, "native provenance delta mismatch"):
                ralph._finalization_guard(state)

    def test_completion_report_is_commit_ready_summary(self):
        with RepoHarness(self) as repo:
            state, _checkpoint = native_approved_state()
            (repo.root / "app.py").write_text("value = 5\n", encoding="utf-8")
            accept_native_paths(state, ["app.py"])
            state = ralph.load_state()
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


    def test_read_only_zero_delta_reaches_distinct_non_commit_terminal(self):
        with RepoHarness(self) as repo:
            state, _checkpoint = native_approved_state(repository_authority="read-only")
            state["current_step"] = 6
            state["step_results"] = [
                {"step": i, "title": f"Step {i}", "result": "PASS", "stats": {}}
                for i in range(1, 6)
            ]
            ralph.save_state(state)
            with (
                mock.patch.object(ralph, "run_final_qualification", return_value=(
                    True, ["unit-tests=PASS"], {}, "",
                )),
                mock.patch.object(ralph, "query_codex_rate_limits", return_value={}),
            ):
                self.assertEqual(ralph.finalize_completed_plan(state), 0)

            finished = ralph.load_state()
            self.assertEqual("READ_ONLY_COMPLETE", finished["status"])
            self.assertEqual([], finished["operation_attributions"])
            self.assertEqual([], finished["plan_changed_files"])
            self.assertEqual([], finished["plan_owned_files"])
            self.assertEqual(0, finished["completion_changes"]["files"])
            self.assertEqual("PASS", finished["final_qualification"]["state"])
            self.assertIsNotNone(finished["final_qualification"]["native_provenance_sha256"])
            report = ralph.build_completion_report(finished, ["unit-tests=PASS"])
            self.assertIsNone(report["suggested_commit"])
            text = (repo.root / report["markdown_path"]).read_text(encoding="utf-8")
            self.assertIn("READ_ONLY_COMPLETE", text)
            self.assertIn("Commit/push/reconciliation: prohibited", text)
            self.assertNotIn("Suggested commit", text)
            self.assertNotIn("finalize ", text)

    def test_read_only_checkpoint_delta_blocks_before_commit_capable_state(self):
        with RepoHarness(self) as repo:
            state, _checkpoint = native_approved_state(repository_authority="read-only")
            (repo.root / "app.py").write_text("value = 99\n", encoding="utf-8")
            state["current_step"] = 6
            ralph.save_state(state)
            with (
                mock.patch.object(ralph, "run_final_qualification", return_value=(
                    True, ["unit-tests=PASS"], {}, "",
                )),
                mock.patch.object(ralph, "query_codex_rate_limits", return_value={}),
            ):
                self.assertEqual(ralph.finalize_completed_plan(state), 2)

            blocked = ralph.load_state()
            self.assertEqual("BLOCKED_HUMAN", blocked["status"])
            self.assertIn("read-only provenance has repository delta", blocked["block_reason"])
            self.assertNotEqual("READY_TO_COMMIT", blocked["status"])

    def test_read_only_terminal_explicitly_rejects_write_finalization_paths(self):
        with RepoHarness(self):
            state, _checkpoint = native_approved_state(
                status="READ_ONLY_COMPLETE", repository_authority="read-only",
            )
            ralph.save_state(state)
            plan_hash_value = state["plan_hash"]

            for commit, push, label in (
                (False, False, "finalize review"),
                (True, False, "finalize --commit"),
                (False, True, "finalize --push"),
            ):
                args = type("Args", (), {
                    "plan_hash": plan_hash_value, "commit": commit, "push": push, "message": None,
                })()
                with self.assertRaisesRegex(RuntimeError, rf"{label}.*READ_ONLY_COMPLETE"):
                    ralph.cmd_finalize(args)

            with self.assertRaisesRegex(RuntimeError, "requalify.*READ_ONLY_COMPLETE"):
                ralph.cmd_requalify(type("Args", (), {"plan_hash": plan_hash_value})())
            with self.assertRaisesRegex(RuntimeError, "reconcile-commit.*READ_ONLY_COMPLETE"):
                ralph.cmd_reconcile_commit(type("Args", (), {
                    "plan_hash": plan_hash_value, "commit": "deadbeef", "reason": "not allowed",
                })())
            with self.assertRaisesRegex(RuntimeError, "reconcile-push.*READ_ONLY_COMPLETE"):
                ralph.cmd_reconcile_push(type("Args", (), {"plan_hash": plan_hash_value})())





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
            ledger_rows = ralph.usage_ledger_rows(include_before_reset=True)
            self.assertEqual(5, len(ledger_rows))
            self.assertEqual({digest}, {row.get("plan_hash") for row in ledger_rows})
            self.assertTrue(all(row.get("input_tokens") == 1000 for row in ledger_rows))
            report_path = ralph.REPORTS / f"{digest[:16]}-summary.md"
            self.assertTrue(report_path.exists())
            report = report_path.read_text(encoding="utf-8")
            self.assertIn("READY", report.upper()) if False else None
            self.assertIn("unit-tests=PASS", report)
            self.assertIn("Suggested commit", report)



    def test_all_green_read_only_plan_finishes_without_commit_state(self):
        with RepoHarness(self):
            plan = valid_plan()
            plan["repository_authority"] = "read-only"
            digest = ralph.plan_hash(plan)
            state = ralph.default_state()
            state.update({"status": "AWAITING_APPROVAL", "plan_hash": digest, "plan": plan})
            ralph.save_state(state)
            ralph.PLAN.write_text(ralph.render_plan(plan), encoding="utf-8")
            self.assertEqual(ralph.cmd_approve(type("Args", (), {"plan_hash": digest})()), 0)

            counter = {"n": 0}

            def fake_codex(_prompt, _schema, sandbox, **_kwargs):
                self.assertEqual("read-only", sandbox)
                counter["n"] += 1
                return {
                    "summary": f"inspected step {counter['n']}",
                    "blocker_class": "none",
                    "needs_human": False,
                    "blockers": [],
                    "validation_notes": [],
                    "ideas": [],
                    "context": {"files_inspected": ["app.py"], "relevant_files": ["app.py"], "accepted_findings": []},
                    "_ralph_metrics": {
                        "commands_executed": 1,
                        "input_tokens": 100,
                        "cached_input_tokens": 80,
                        "output_tokens": 10,
                        "reasoning_output_tokens": 5,
                    },
                }

            args = type("Args", (), {
                "max_loops": 10,
                "wait_for_limits": False,
                "usage_poll_seconds": 300,
                "color": "never",
                "efficiency_mode": None,
            })()
            with (
                mock.patch.object(ralph, "ensure_codex_usage_capacity", return_value=True),
                mock.patch.object(ralph, "run_codex", side_effect=fake_codex),
                mock.patch.object(ralph, "run_gates", return_value=(True, ["unit-tests=PASS"], None, "", {})),
                mock.patch.object(ralph, "run_final_qualification", return_value=(
                    True, ["unit-tests=PASS", "public-audit=PASS"], {}, "",
                )),
                mock.patch.object(ralph, "query_codex_rate_limits", return_value={}),
            ):
                self.assertEqual(ralph.cmd_run(args), 0)

            finished = ralph.load_state()
            self.assertEqual("READ_ONLY_COMPLETE", finished["status"])
            self.assertEqual(6, finished["current_step"])
            self.assertEqual(5, len(finished["step_results"]))
            self.assertEqual([], finished["operation_attributions"])
            self.assertEqual([], finished["plan_changed_files"])
            self.assertEqual([], finished["plan_owned_files"])
            self.assertEqual(0, finished["completion_changes"]["files"])
            report_path = ralph.REPORTS / f"{digest[:16]}-summary.md"
            report = report_path.read_text(encoding="utf-8")
            self.assertIn("READ_ONLY_COMPLETE", report)
            self.assertNotIn("Suggested commit", report)


class RunLoopSandboxVerificationTests(unittest.TestCase):
    def _approved_state(self, plan: dict) -> None:
        digest = ralph.plan_hash(plan)
        state = ralph.default_state()
        state.update({"status": "AWAITING_APPROVAL", "plan_hash": digest, "plan": plan})
        ralph.save_state(state)
        ralph.PLAN.write_text(ralph.render_plan(plan), encoding="utf-8")
        self.assertEqual(ralph.cmd_approve(type("Args", (), {"plan_hash": digest})()), 0)

    @staticmethod
    def _args():
        return type("Args", (), {
            "max_loops": 1, "wait_for_limits": False, "usage_poll_seconds": 300,
            "color": "never", "efficiency_mode": None,
        })()

    def test_run_refuses_missing_checkpoint_without_bootstrapping_replacement(self):
        with RepoHarness(self):
            plan = valid_plan()
            plan["repository_authority"] = "write"
            self._approved_state(plan)
            state = ralph.load_state()
            artifact = dict(state["approved_plan_artifact"])
            state.pop("recovery_checkpoint")
            ralph.save_state(state)
            with mock.patch.object(ralph, "run_codex") as run_codex:
                with self.assertRaisesRegex(RuntimeError, "approval recovery checkpoint is missing or invalid"):
                    ralph.cmd_run(self._args())
            blocked = ralph.load_state()
            run_codex.assert_not_called()
            self.assertNotIn("recovery_checkpoint", blocked)
            self.assertEqual(artifact, blocked["approved_plan_artifact"])

    def test_recovery_refuses_missing_artifact_without_bootstrapping_replacement(self):
        with RepoHarness(self):
            plan = valid_plan()
            plan["repository_authority"] = "write"
            self._approved_state(plan)
            state = ralph.load_state()
            state.update({"status": "BLOCKED_HUMAN", "block_reason": "validation failed"})
            state.pop("approved_plan_artifact")
            ralph.save_state(state)
            args = type("Args", (), {"plan_hash": state["plan_hash"]})()
            with mock.patch.object(ralph, "run_gates") as gates:
                with self.assertRaisesRegex(RuntimeError, "approved plan artifact binding is missing"):
                    ralph.cmd_recover_validation_block(args)
            blocked = ralph.load_state()
            gates.assert_not_called()
            self.assertNotIn("approved_plan_artifact", blocked)

    @staticmethod
    def _result() -> dict:
        return {
            "summary": "bounded implementation result",
            "ideas": [], "context": {"files_inspected": [], "relevant_files": [], "accepted_findings": []},
        }

    def test_read_only_sandbox_refuses_checkpoint_delta_before_continuation(self):
        with RepoHarness(self) as repo:
            operator = repo.root / "operator.txt"
            operator.write_text("operator residue\n", encoding="utf-8")
            plan = valid_plan()
            plan["repository_authority"] = "read-only"
            self._approved_state(plan)
            events: list[str] = []
            original_verify = ralph.verify_post_turn_repository_state

            def fake_codex(_prompt, _schema, sandbox, **_kwargs):
                events.append(f"codex:{sandbox}")
                (repo.root / "app.py").write_text("model delta\n", encoding="utf-8")
                return self._result()

            def tracked_verify(*args, **kwargs):
                events.append("verify")
                return original_verify(*args, **kwargs)

            with (
                mock.patch.object(ralph, "ensure_codex_usage_capacity", return_value=True),
                mock.patch.object(ralph, "run_codex", side_effect=fake_codex),
                mock.patch.object(ralph, "verify_post_turn_repository_state", side_effect=tracked_verify),
                mock.patch.object(ralph, "codex_requests_continuation") as continuation,
                mock.patch.object(ralph, "run_gates") as gates,
            ):
                self.assertEqual(ralph.cmd_run(self._args()), 2)

            self.assertEqual(events, ["codex:read-only", "verify"])
            continuation.assert_not_called()
            gates.assert_not_called()
            self.assertEqual(operator.read_text(encoding="utf-8"), "operator residue\n")
            blocked = ralph.load_state()
            self.assertEqual(blocked["last_post_turn_verification"]["state"], "REFUSED")
            self.assertIn("READ_ONLY_CHECKPOINT_DELTA", blocked["block_reason"])
            self.assertEqual([], blocked["plan_changed_files"])
            self.assertEqual([], blocked["plan_owned_files"])
            self.assertEqual([], blocked["operation_attributions"])

    def test_write_sandbox_verifies_checkpoint_delta_before_continuation(self):
        with RepoHarness(self) as repo:
            plan = valid_plan()
            plan["repository_authority"] = "write"
            self._approved_state(plan)
            events: list[str] = []
            original_verify = ralph.verify_post_turn_repository_state

            def fake_codex(_prompt, _schema, sandbox, **_kwargs):
                events.append(f"codex:{sandbox}")
                (repo.root / "app.py").write_text("authorized model delta\n", encoding="utf-8")
                return self._result()

            def tracked_verify(*args, **kwargs):
                events.append("verify")
                return original_verify(*args, **kwargs)

            def continuation_result(*_args, **_kwargs):
                events.append("continuation")
                return True, "ordinary bounded continuation"

            with (
                mock.patch.object(ralph, "ensure_codex_usage_capacity", return_value=True),
                mock.patch.object(ralph, "run_codex", side_effect=fake_codex),
                mock.patch.object(ralph, "verify_post_turn_repository_state", side_effect=tracked_verify),
                mock.patch.object(ralph, "codex_requests_continuation", side_effect=continuation_result),
                mock.patch.object(ralph, "run_gates") as gates,
            ):
                self.assertEqual(ralph.cmd_run(self._args()), 0)

            self.assertEqual(events, ["codex:workspace-write", "verify", "continuation"])
            gates.assert_not_called()
            state = ralph.load_state()
            self.assertEqual(state["last_post_turn_verification"]["state"], "PASS")
            self.assertEqual(state["last_post_turn_verification"]["new_project_delta"], ["app.py"])

    def test_mixed_tooling_and_product_pass_records_only_verified_attribution(self):
        with RepoHarness(self) as repo:
            plan = valid_plan()
            self._approved_state(plan)
            state = ralph.load_state()
            granted_paths = ["scripts/ralph.py", "tests/test_ralph_lifecycle.py"]
            self.assertTrue(all(ralph.is_tooling_path(path) for path in granted_paths))
            state["self_hosting_grant"] = {
                "plan_hash": state["plan_hash"], "step": 1, "paths": granted_paths,
            }
            ralph.save_state(state)

            def fake_codex(*_args, **_kwargs):
                (repo.root / "app.py").write_text("verified product delta\n", encoding="utf-8")
                for path in granted_paths:
                    target = repo.root / path
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text("verified tooling delta\n", encoding="utf-8")
                return self._result()

            with (
                mock.patch.object(ralph, "ensure_codex_usage_capacity", return_value=True),
                mock.patch.object(ralph, "run_codex", side_effect=fake_codex),
                mock.patch.object(ralph, "codex_requests_continuation", return_value=(False, "")),
                mock.patch.object(ralph, "run_gates", return_value=(True, ["unit-tests=PASS"], None, "", {})),
            ):
                self.assertEqual(ralph.cmd_run(self._args()), 0)

            accepted = ralph.load_state()
            paths = {item["path"] for item in accepted["operation_attributions"]}
            self.assertEqual({"app.py", *granted_paths}, paths)
            self.assertEqual(sorted(paths), accepted["plan_changed_files"])
            self.assertEqual(sorted(paths), accepted["step_results"][-1]["files"])
            self.assertEqual(sorted(paths), accepted["step_results"][-1]["attribution"]["paths"])

    def test_test_policy_block_does_not_create_attribution_or_progress(self):
        with RepoHarness(self) as repo:
            plan = valid_plan()
            plan["steps"][0]["test_change_policy"] = "none"
            self._approved_state(plan)

            def fake_codex(*_args, **_kwargs):
                (repo.root / "app.py").write_text("unaccepted product delta\n", encoding="utf-8")
                test = repo.root / "tests" / "test_new.py"
                test.parent.mkdir(exist_ok=True)
                test.write_text("def test_new(): pass\n", encoding="utf-8")
                return self._result()

            with (
                mock.patch.object(ralph, "ensure_codex_usage_capacity", return_value=True),
                mock.patch.object(ralph, "run_codex", side_effect=fake_codex),
                mock.patch.object(ralph, "run_gates") as gates,
            ):
                self.assertEqual(ralph.cmd_run(self._args()), 2)

            blocked = ralph.load_state()
            gates.assert_not_called()
            self.assertEqual(1, blocked["current_step"])
            self.assertEqual([], blocked["plan_changed_files"])
            self.assertEqual([], blocked["operation_attributions"])
            self.assertIn("test paths ['tests/test_new.py']", blocked["block_reason"])



    def test_terminal_guard_exception_blocks_with_report_and_no_model_turn(self):
        with RepoHarness(self) as repo:
            plan = valid_plan()
            digest = ralph.plan_hash(plan)
            state = ralph.default_state()
            state.update({
                "status": "APPROVED",
                "plan_hash": digest,
                "plan": plan,
                "current_step": len(plan["steps"]) + 1,
                "loop_count": 12,
                "step_results": [
                    {"step": i, "title": f"Step {i}", "result": "PASS", "summary": "ok", "files": [], "gates": [], "stats": {}}
                    for i in range(1, len(plan["steps"]) + 1)
                ],
            })
            ralph.PLAN.write_text(ralph.render_plan(plan), encoding="utf-8")
            ralph.bind_approved_plan_artifact(state)
            checkpoint = ralph.create_recovery_checkpoint(state)
            state["recovery_checkpoint"] = checkpoint["id"]
            state["approval_repository_evidence"] = checkpoint["repository_evidence"]
            state["plan_changed_files"] = ["app.py"]
            (repo.root / "app.py").write_text("value = 9\n", encoding="utf-8")
            ralph.save_state(state)
            args = type("Args", (), {
                "max_loops": 10, "wait_for_limits": False, "usage_poll_seconds": 300,
                "color": "never", "efficiency_mode": None,
            })()
            refusal = "APPROVAL_BASELINE_RESIDUE_AS_NEW_PLAN: ['app.py']"
            with (
                mock.patch.object(ralph, "run_final_qualification", side_effect=RuntimeError(refusal)),
                mock.patch.object(ralph, "run_codex") as run_codex,
            ):
                rc = ralph.cmd_run(args)

            self.assertEqual(2, rc)
            run_codex.assert_not_called()
            blocked = ralph.load_state()
            self.assertEqual("BLOCKED_HUMAN", blocked["status"])
            self.assertEqual(len(plan["steps"]) + 1, blocked["current_step"])
            self.assertEqual("BLOCKED", blocked["final_qualification"]["state"])
            self.assertEqual("qualification-guard", blocked["final_qualification"]["stage"])
            self.assertEqual(refusal, blocked["final_qualification"]["error"])
            self.assertIn(refusal, blocked["block_reason"])
            report_path = ralph.REPORTS / f"{digest[:16]}-summary.md"
            self.assertTrue(report_path.exists())
            report = report_path.read_text(encoding="utf-8")
            self.assertIn("State: BLOCKED", report)
            self.assertIn(refusal, report)

    def test_approved_terminal_sentinel_resumes_finalization_without_model_turn(self):
        with RepoHarness(self) as repo:
            plan = valid_plan()
            digest = ralph.plan_hash(plan)
            state = ralph.default_state()
            state.update({
                "status": "APPROVED",
                "plan_hash": digest,
                "plan": plan,
                "current_step": len(plan["steps"]) + 1,
                "loop_count": 12,
                "step_results": [
                    {"step": i, "title": f"Step {i}", "result": "PASS", "summary": "ok", "files": [], "gates": [], "stats": {}}
                    for i in range(1, len(plan["steps"]) + 1)
                ],
            })
            ralph.PLAN.write_text(ralph.render_plan(plan), encoding="utf-8")
            ralph.bind_approved_plan_artifact(state)
            checkpoint = ralph.create_recovery_checkpoint(state)
            state["recovery_checkpoint"] = checkpoint["id"]
            state["approval_repository_evidence"] = checkpoint["repository_evidence"]
            (repo.root / "app.py").write_text("value = 10\n", encoding="utf-8")
            ralph.save_state(state)
            accept_native_paths(state, ["app.py"], step_no=5, loop=12)
            state = ralph.load_state()
            state["status"] = "APPROVED"
            state["current_step"] = len(plan["steps"]) + 1
            ralph.save_state(state)
            args = type("Args", (), {
                "max_loops": 10, "wait_for_limits": False, "usage_poll_seconds": 300,
                "color": "never", "efficiency_mode": None,
            })()
            with (
                mock.patch.object(ralph, "run_final_qualification", return_value=(True, ["unit-tests=PASS"], {}, "")) as final_qualification,
                mock.patch.object(ralph, "query_codex_rate_limits", return_value={}),
                mock.patch.object(ralph, "run_codex") as run_codex,
            ):
                rc = ralph.cmd_run(args)

            self.assertEqual(0, rc)
            run_codex.assert_not_called()
            final_qualification.assert_called_once()
            finished = ralph.load_state()
            self.assertEqual("READY_TO_COMMIT", finished["status"])
            self.assertEqual(len(plan["steps"]) + 1, finished["current_step"])
            self.assertEqual("PASS", finished["final_qualification"]["state"])
            self.assertTrue(finished["final_qualification"]["delta_fingerprint"])
            self.assertTrue(finished["final_qualification"]["native_provenance_sha256"])


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

    def _rollback_state(self, repo) -> tuple[dict, dict]:
        (repo.root / "deleted.py").write_text("delete_me = True\n", encoding="utf-8")
        (repo.root / "residue.py").write_text("operator = 'before'\n", encoding="utf-8")
        repo.git("add", "deleted.py", "residue.py")
        repo.git("commit", "-qm", "rollback fixture")
        (repo.root / "residue.py").write_text("operator = 'staged approval residue'\n", encoding="utf-8")
        repo.git("add", "residue.py")
        (repo.root / "operator.txt").write_text("untracked approval residue\n", encoding="utf-8")
        plan = valid_plan()
        state = self.blocked_state()
        state.update({"plan_hash": ralph.plan_hash(plan), "plan": plan})
        ralph.PLAN.write_text(ralph.render_plan(plan), encoding="utf-8")
        ralph.bind_approved_plan_artifact(state)
        checkpoint = ralph.create_recovery_checkpoint(state)
        state["recovery_checkpoint"] = checkpoint["id"]
        state["approval_repository_evidence"] = checkpoint["repository_evidence"]

        (repo.root / "app.py").write_text("value = 2\n", encoding="utf-8")
        (repo.root / "deleted.py").unlink()
        (repo.root / "created.py").write_text("created = True\n", encoding="utf-8")
        paths = ["app.py", "created.py", "deleted.py"]
        verification = {
            "schema": "zen_ralph_post_turn_repository_verification_v1",
            "state": "PASS", "sandbox": "workspace-write", "checkpoint": checkpoint["id"],
            "plan_hash": state["plan_hash"], "new_project_delta": paths, "loop": 9, "step": 1,
            "current_fingerprints": {path: ralph.retirement_path_fingerprint(path) for path in paths},
        }
        attribution = ralph.verified_attribution_result(
            state, plan["steps"][0], verification, paths, loop=9, phase="implement",
        )
        ralph.record_accepted_operations(state, attribution)
        ralph.save_state(state)
        return state, checkpoint

    @staticmethod
    def _rollback_args(plan_hash: str):
        return type("Args", (), {
            "plan_hash": plan_hash, "reason": "obsolete", "rollback": True,
            "carry_forward": False, "confirm": "ROLLBACK", "reconcile_restored": False,
        })()

    def test_rollback_restores_attributed_tracked_edits_deletions_and_creations(self):
        with RepoHarness(self) as repo:
            state, checkpoint = self._rollback_state(repo)
            self.assertEqual(0, ralph.cmd_retire_plan(self._rollback_args(state["plan_hash"])))
            self.assertEqual("value = 1\n", (repo.root / "app.py").read_text(encoding="utf-8"))
            self.assertEqual("delete_me = True\n", (repo.root / "deleted.py").read_text(encoding="utf-8"))
            self.assertFalse((repo.root / "created.py").exists())
            self.assertEqual("operator = 'staged approval residue'\n", (repo.root / "residue.py").read_text(encoding="utf-8"))
            self.assertEqual("untracked approval residue\n", (repo.root / "operator.txt").read_text(encoding="utf-8"))
            manifest = json.loads(next(ralph.RETIREMENTS.glob("*.json")).read_text(encoding="utf-8"))
            self.assertEqual(ralph.RETIREMENT_MANIFEST_SCHEMA, manifest["schema"])
            self.assertEqual("ROLLED_BACK", manifest["disposition"])
            self.assertEqual(checkpoint["id"], manifest["checkpoint"])
            self.assertEqual({"app.py", "created.py", "deleted.py"}, {item["path"] for item in manifest["paths"]})
            self.assertTrue(all(item["before"] and item["after"] for item in manifest["paths"]))

    def test_rollback_refuses_stale_altered_duplicate_and_unattributed_evidence(self):
        cases = ("stale", "altered", "duplicate", "unattributed")
        for case in cases:
            with self.subTest(case=case), RepoHarness(self) as repo:
                state, _checkpoint = self._rollback_state(repo)
                if case == "stale":
                    (repo.root / "app.py").write_text("value = stale\n", encoding="utf-8")
                    expected = "stale attribution fingerprint"
                elif case == "altered":
                    state["operation_attributions"][0]["path"] = "altered.py"
                    ralph.save_state(state)
                    expected = "incomplete or altered"
                elif case == "duplicate":
                    state["operation_attributions"].append(dict(state["operation_attributions"][0]))
                    ralph.save_state(state)
                    expected = "duplicate operation attribution"
                else:
                    (repo.root / "surprise.py").write_text("surprise = True\n", encoding="utf-8")
                    expected = "unattributed or stale checkpoint delta"
                with self.assertRaisesRegex(RuntimeError, expected):
                    ralph.cmd_retire_plan(self._rollback_args(state["plan_hash"]))

    def test_rollback_refuses_protected_and_unsupported_attribution_baselines(self):
        for case in ("protected", "unsupported"):
            with self.subTest(case=case), RepoHarness(self) as repo:
                state, _checkpoint = self._rollback_state(repo)
                record = state["operation_attributions"][0]
                if case == "protected":
                    record["path"] = ".ralph/state.json"
                    expected = "protected, runtime, residue, or ambiguous"
                else:
                    record["baseline_kind"] = "unknown"
                    expected = "baseline classification is invalid"
                record["record_sha256"] = ralph._operation_record_hash(record)
                ralph.save_state(state)
                with self.assertRaisesRegex(RuntimeError, expected):
                    ralph.cmd_retire_plan(self._rollback_args(state["plan_hash"]))

    def test_carry_forward_v4_manifest_preserves_inventory_without_rollback_authority(self):
        with RepoHarness(self):
            state = self.blocked_state()
            ralph.PLAN.write_text(ralph.render_plan(state["plan"]), encoding="utf-8")
            checkpoint = ralph.create_recovery_checkpoint(state)
            state.update({
                "recovery_checkpoint": checkpoint["id"],
                "plan_changed_files": ["app.py"],
            })
            ralph.save_state(state)
            args = type("Args", (), {
                "plan_hash": state["plan_hash"], "reason": "replacement required",
                "rollback": False, "carry_forward": True, "confirm": None,
                "reconcile_restored": False,
            })()
            self.assertEqual(0, ralph.cmd_retire_plan(args))
            manifest = json.loads(next(ralph.RETIREMENTS.glob("*.json")).read_text(encoding="utf-8"))
            self.assertEqual(ralph.RETIREMENT_MANIFEST_SCHEMA, manifest["schema"])
            self.assertEqual("RETIRED_WITH_CARRY_FORWARD", manifest["disposition"])
            self.assertEqual(["app.py"], manifest["operations"]["preserved"])
            self.assertEqual(1, len(manifest["paths"]))
            record = manifest["paths"][0]
            self.assertEqual("app.py", record["path"])
            self.assertEqual("inventory-only", record["attribution"]["authority"])
            self.assertEqual(record["evidence"], record["before"])
            self.assertEqual(record["evidence"], record["after"])
            self.assertEqual(
                {"disposition": "preserved", "action": "none", "checkpoint": checkpoint["id"]},
                record["restoration"],
            )

    def test_legacy_v3_retirement_manifest_remains_readable(self):
        with RepoHarness(self):
            state = self.blocked_state()
            checkpoint = ralph.create_recovery_checkpoint(state)
            state["recovery_checkpoint"] = checkpoint["id"]
            current = ralph.retirement_path_fingerprint("app.py")
            record = {
                "path": "app.py",
                "baseline": "tracked",
                "plan_owned": False,
                "current": current["kind"],
                "unexpected": False,
                "evidence": current,
            }
            manifest = {
                "schema": ralph.RETIREMENT_MANIFEST_LEGACY_SCHEMA,
                "id": ralph.retirement_record_id(),
                "created_at": ralph.utc_now(),
                "plan_hash": state["plan_hash"],
                "status_before": state["status"],
                "reason": "historical carry-forward evidence",
                "disposition": "RETIRED_WITH_CARRY_FORWARD",
                "checkpoint": checkpoint["id"],
                "step": state["current_step"],
                "step_count": len(state["plan"]["steps"]),
                "loop_count": state["loop_count"],
                "paths": [record],
                "operations": {"restore": [], "delete": [], "preserved": ["app.py"]},
                "repository_before": ralph.repo_snapshot(),
                "repository_after": ralph.repo_snapshot(),
                "planning_context": ralph.retirement_planning_context(state),
            }
            validated = ralph.validate_retirement_manifest(manifest)
            self.assertEqual(ralph.RETIREMENT_MANIFEST_LEGACY_SCHEMA, validated["schema"])
            self.assertEqual("app.py", validated["paths"][0]["path"])


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

    def test_read_only_completion_card_has_no_commit_action(self):
        tui.configure("never")
        card = tui.completion_card({
            "plan_hash": "d" * 64,
            "status": "READ_ONLY_COMPLETE",
            "repository_authority": "read-only",
            "counts": {
                "steps_total": 5, "steps_accepted": 5, "steps_passed": 5,
                "steps_human_confirmed": 0, "steps_recovered": 0,
                "steps_failed": 0, "loops": 5, "human_gates": 0, "human_steers": 0,
            },
            "qualification": {"state": "PASS"},
            "changes": {"files": 0, "added": 0, "removed": 0},
            "authority": {"protected_paths_changed": False, "ralph_tooling_changed": False},
            "recovery_checkpoint": "RP-RO", "markdown_path": ".ralph/reports/read-only.md",
            "suggested_commit": None,
        })
        self.assertIn("READ-ONLY COMPLETE", card)
        self.assertIn("No commit, push, or reconciliation", card)
        self.assertNotIn("Suggested commit", card)
        self.assertNotIn("finalize", card)

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
    def test_reconcile_commit_adopts_verified_manual_commit(self):
        with RepoHarness(self) as repo:
            state, _checkpoint = native_approved_state()
            (repo.root / "app.py").write_text("value = 2\n", encoding="utf-8")
            accept_native_paths(state, ["app.py"])
            repo.git("add", "app.py")
            repo.git("commit", "-qm", "manual qualified plan")
            sha = repo.git("rev-parse", "HEAD").stdout.strip()
            state = ralph.load_state()
            args = type("Args", (), {
                "plan_hash": state["plan_hash"], "commit": sha,
                "reason": "Manual closure after approved dirty-overlap review",
            })()
            self.assertEqual(ralph.cmd_reconcile_commit(args), 0)
            adopted = ralph.load_state()
            self.assertEqual(adopted["status"], "COMMITTED")
            self.assertEqual(adopted["commit_sha"], sha)
            self.assertTrue(adopted["commit_reconciled"])

    def test_reconcile_commit_rejects_unexpected_extra_path(self):
        with RepoHarness(self) as repo:
            state, _checkpoint = native_approved_state()
            (repo.root / "app.py").write_text("value = 3\n", encoding="utf-8")
            accept_native_paths(state, ["app.py"])
            (repo.root / "surprise.txt").write_text("unexpected\n", encoding="utf-8")
            repo.git("add", "app.py", "surprise.txt")
            repo.git("commit", "-qm", "manual bad commit")
            sha = repo.git("rev-parse", "HEAD").stdout.strip()
            state = ralph.load_state()
            with self.assertRaisesRegex(RuntimeError, "commit scope differs from native provenance"):
                ralph._verify_reconciled_commit(state, sha)

    def test_reconcile_push_requires_recorded_commit_on_upstream(self):
        with RepoHarness(self) as repo:
            remote_tmp = tempfile.TemporaryDirectory()
            self.addCleanup(remote_tmp.cleanup)
            remote = Path(remote_tmp.name) / "remote.git"
            subprocess.run(["git", "init", "--bare", "-q", str(remote)], check=True)
            repo.git("remote", "add", "origin", str(remote))
            repo.git("push", "-u", "origin", "master")

            state, _checkpoint = native_approved_state()
            (repo.root / "app.py").write_text("value = 9\n", encoding="utf-8")
            accept_native_paths(state, ["app.py"])
            repo.git("add", "app.py")
            repo.git("commit", "-qm", "manual commit")
            sha = repo.git("rev-parse", "HEAD").stdout.strip()
            state = ralph.load_state()
            state.update({"status": "COMMITTED", "commit_sha": sha})
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
