from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "ralph.py"
spec = importlib.util.spec_from_file_location("ralph_lite", MODULE_PATH)
ralph = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(ralph)


def valid_plan(count: int = 5) -> dict:
    return {
        "goal": "Exercise deterministic controller invariants",
        "steps": [
            {
                "id": i,
                "title": f"Step {i}",
                "objective": f"Objective {i}",
                "acceptance": [f"Acceptance {i}"],
                "test_change_policy": "add-only",
            }
            for i in range(1, count + 1)
        ],
    }


class PlanTests(unittest.TestCase):
    def test_plan_hash_is_stable_for_key_order(self):
        first = valid_plan()
        second = {"steps": first["steps"], "goal": first["goal"]}
        self.assertEqual(ralph.plan_hash(first), ralph.plan_hash(second))

    def test_plan_requires_five_to_ten_steps(self):
        for count in (5, 10):
            ralph.validate_plan(valid_plan(count))
        for count in (4, 11):
            with self.assertRaises(ValueError):
                ralph.validate_plan(valid_plan(count))

    def test_step_ids_must_be_sequential(self):
        plan = valid_plan()
        plan["steps"][2]["id"] = 99
        with self.assertRaises(ValueError):
            ralph.validate_plan(plan)

    def test_rendered_plan_binds_human_gate_to_hash(self):
        plan = valid_plan()
        digest = ralph.plan_hash(plan)
        rendered = ralph.render_plan(plan)
        self.assertIn(digest, rendered)
        self.assertIn(f"approve {digest}", rendered)


class PolicyTests(unittest.TestCase):
    def test_test_policy_none_blocks_all_test_changes(self):
        before = {"tests/test_old.py": "a", "app/a.py": "a"}
        after = {"tests/test_old.py": "b", "tests/test_new.py": "n", "app/a.py": "b"}
        self.assertEqual(
            ralph.test_policy_violation(before, after, "none"),
            ["tests/test_new.py", "tests/test_old.py"],
        )

    def test_test_policy_add_only_allows_new_but_not_existing_changes(self):
        before = {"tests/test_old.py": "a"}
        after = {"tests/test_old.py": "b", "tests/test_new.py": "n"}
        self.assertEqual(ralph.test_policy_violation(before, after, "add-only"), ["tests/test_old.py"])

    def test_test_policy_modify_allows_test_changes(self):
        before = {"tests/test_old.py": "a"}
        after = {"tests/test_old.py": "b"}
        self.assertEqual(ralph.test_policy_violation(before, after, "modify"), [])

    def test_secret_and_certificate_paths_are_protected(self):
        for path in (
            ".env", ".env.local", "secrets/token", "certs/site.crt",
            ".npmrc", ".netrc", ".codex/auth.json", ".direnv/env",
            "scratch/session.token", "scratch/service.credentials",
        ):
            self.assertTrue(ralph.is_protected_path(path))
        self.assertFalse(ralph.is_protected_path("app/main.py"))

    def test_ralph_tooling_paths_are_classified_separately(self):
        self.assertTrue(ralph.is_tooling_path("scripts/ralph.py"))
        self.assertTrue(ralph.is_tooling_path("tests/test_ralph_lite.py"))
        self.assertFalse(ralph.is_tooling_path("app/main.py"))
        self.assertEqual(ralph.classify_changes(["app/main.py"]), "product-development")
        self.assertEqual(ralph.classify_changes(["scripts/ralph.py"]), "ralph-tooling")
        self.assertEqual(
            ralph.classify_changes(["scripts/ralph.py", "app/main.py"]),
            "mixed-tooling-product",
        )
        self.assertEqual(ralph.classify_changes([]), "no-code-change")


class FailureTests(unittest.TestCase):
    def test_failure_fingerprint_ignores_temp_path_address_and_runtime(self):
        a = "FAIL: test_x (tests.X)\nAssertionError: object 0x123abc failed in 1.23s /tmp/a/file"
        b = "FAIL: test_x (tests.X)\nAssertionError: object 0x9fffff failed in 9.99s /tmp/b/file"
        self.assertEqual(ralph.failure_fingerprint("unit-tests", a, 1), ralph.failure_fingerprint("unit-tests", b, 1))

    def test_different_gate_changes_fingerprint(self):
        text = "FAIL: test_x\nAssertionError: nope"
        self.assertNotEqual(ralph.failure_fingerprint("unit-tests", text, 1), ralph.failure_fingerprint("ux-validator", text, 1))


class CodexSandboxTests(unittest.TestCase):
    def test_bwrap_loopback_failure_is_recognised(self):
        output = "bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted"
        self.assertTrue(ralph.is_bwrap_bootstrap_failure(output))

    def test_bwrap_uid_map_failure_is_recognised(self):
        output = "bwrap: setting up uid map: Permission denied"
        self.assertTrue(ralph.is_bwrap_bootstrap_failure(output))

    def test_unrelated_codex_failure_does_not_trigger_fallback(self):
        output = "codex exec failed: invalid output schema"
        self.assertFalse(ralph.is_bwrap_bootstrap_failure(output))

    def test_preflight_keeps_default_backend_when_healthy(self):
        self.assertEqual(ralph.sandbox_prefix_from_preflights(0, ""), ["codex"])

    def test_preflight_blocks_instead_of_using_legacy_landlock(self):
        bwrap = "bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted"
        with self.assertRaises(ralph.EnvironmentBlocked):
            ralph.sandbox_prefix_from_preflights(1, bwrap)

    def test_outer_success_with_bwrap_text_is_still_detected(self):
        output = '{"type":"item.completed","item":{"aggregated_output":"bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted"}}'
        self.assertTrue(ralph.is_bwrap_bootstrap_failure(output))


class CodexObservabilityTests(unittest.TestCase):
    def test_reasoning_summary_is_operator_visible(self):
        messages = ralph.codex_event_messages({
            "type": "item.completed",
            "item": {"type": "reasoning", "text": "Inspecting classifier precedence"},
        })
        self.assertEqual(messages, [("THINK", "Inspecting classifier precedence")])

    def test_command_and_file_change_events_are_rendered(self):
        command = ralph.codex_event_messages({
            "type": "item.completed",
            "item": {
                "type": "command_execution",
                "command": "python3 -m unittest tests.test_classifier -v",
                "status": "completed",
                "exit_code": 0,
                "aggregated_output": "ok",
            },
        })
        self.assertIn("COMPLETED exit=0", command[0][1])
        files = ralph.codex_event_messages({
            "type": "item.completed",
            "item": {
                "type": "file_change",
                "status": "completed",
                "changes": [{"path": "app/classifier.py", "kind": "update"}],
            },
        })
        self.assertEqual(files, [("FILES", "update:app/classifier.py")])

    def test_turn_usage_includes_reasoning_tokens(self):
        messages = ralph.codex_event_messages({
            "type": "turn.completed",
            "usage": {
                "input_tokens": 100,
                "cached_input_tokens": 80,
                "output_tokens": 20,
                "reasoning_output_tokens": 7,
            },
        })
        self.assertEqual(messages, [("USAGE", "input=100 cached=80 output=20 reasoning=7")])

    def test_metrics_capture_commands_and_token_usage(self):
        metrics = ralph.empty_codex_metrics()
        ralph.update_codex_metrics(metrics, {
            "type": "item.completed",
            "item": {"type": "command_execution", "status": "completed"},
        })
        ralph.update_codex_metrics(metrics, {
            "type": "turn.completed",
            "usage": {
                "input_tokens": 120,
                "cached_input_tokens": 90,
                "output_tokens": 21,
                "reasoning_output_tokens": 8,
            },
        })
        self.assertEqual(metrics["commands_executed"], 1)
        self.assertEqual(metrics["input_tokens"], 120)
        self.assertEqual(metrics["cached_input_tokens"], 90)
        self.assertEqual(metrics["reasoning_output_tokens"], 8)


class ContextTests(unittest.TestCase):
    def test_step_prompt_injects_compact_context_and_efficiency_rules(self):
        with tempfile.TemporaryDirectory() as td:
            old_context = ralph.CONTEXT
            try:
                ralph.CONTEXT = Path(td) / "context.json"
                ralph.save_context({
                    "plan_hash": "abc",
                    "last_step": 1,
                    "last_result": "PASS",
                    "summary": "fixture corpus added",
                    "changed_files": ["tests/fixtures/service_classification.json"],
                    "relevant_files": ["app/classification_intelligence.py"],
                    "accepted_findings": ["address-list takes precedence over DNS"],
                })
                state = {"plan_hash": "abc"}
                step = {
                    "id": 2, "title": "Precedence", "objective": "Make precedence explicit",
                    "acceptance": ["deterministic"], "test_change_policy": "add-only",
                }
                prompt = ralph.step_prompt(state, step, None, 0)
                self.assertIn("address-list takes precedence over DNS", prompt)
                self.assertIn("Normally inspect no more than 6-8 relevant files", prompt)
                self.assertIn("Do not broadly scan docs/", prompt)
            finally:
                ralph.CONTEXT = old_context

    def test_context_update_merges_prior_findings_and_changed_files(self):
        with tempfile.TemporaryDirectory() as td:
            old_root, old_context = ralph.ROOT, ralph.CONTEXT
            try:
                ralph.ROOT = Path(td)
                ralph.CONTEXT = Path(td) / ".ralph" / "context.json"
                ralph.save_context({
                    "plan_hash": "abc", "last_step": 1, "last_result": "PASS",
                    "summary": "first", "changed_files": ["a.py"],
                    "relevant_files": ["a.py"], "accepted_findings": ["finding one"],
                })
                result = {
                    "summary": "second",
                    "context": {
                        "relevant_files": ["b.py"],
                        "accepted_findings": ["finding two"],
                        "files_inspected": ["a.py", "b.py"],
                    },
                }
                ralph.update_context_after_pass({"plan_hash": "abc"}, {"id": 2}, result, ["c.py"])
                saved = ralph.load_context()
                self.assertEqual(saved["relevant_files"][:3], ["c.py", "b.py", "a.py"])
                self.assertEqual(saved["accepted_findings"][:2], ["finding two", "finding one"])
            finally:
                ralph.ROOT, ralph.CONTEXT = old_root, old_context

    def test_bootstrap_context_from_existing_pass_journal(self):
        with tempfile.TemporaryDirectory() as td:
            old_context, old_journal = ralph.CONTEXT, ralph.JOURNAL
            try:
                ralph.CONTEXT = Path(td) / "context.json"
                ralph.JOURNAL = Path(td) / "journal.md"
                ralph.JOURNAL.write_text(
                    "# Journal\n\n## Loop 0003 — now\n\n"
                    "- Plan step: 1\n- Result: PASS\n"
                    "- Files changed: tests/fixtures/service_classification.json\n"
                    "- Summary: Added classifier fixtures.\n\n",
                    encoding="utf-8",
                )
                self.assertTrue(ralph.bootstrap_context_from_journal({"current_step": 2, "plan_hash": "abc"}))
                saved = ralph.load_context()
                self.assertEqual(saved["last_step"], 1)
                self.assertEqual(saved["relevant_files"], ["tests/fixtures/service_classification.json"])
                self.assertIn("Added classifier fixtures", saved["accepted_findings"][0])
            finally:
                ralph.CONTEXT, ralph.JOURNAL = old_context, old_journal


class SnapshotTests(unittest.TestCase):
    def test_changed_paths_reports_added_modified_deleted(self):
        before = {"a": "1", "b": "2"}
        after = {"a": "9", "c": "3"}
        self.assertEqual(ralph.changed_paths(before, after), ["a", "b", "c"])

    def test_restore_authority_restores_contents(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "state.json"
            path.write_text("before", encoding="utf-8")
            snapshot = {path: path.read_bytes()}
            path.write_text("after", encoding="utf-8")
            self.assertTrue(ralph.authority_changed(snapshot))
            ralph.restore_authority(snapshot)
            self.assertEqual(path.read_text(encoding="utf-8"), "before")

    def test_restore_protected_restores_contents(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / ".env"
            path.write_text("SECRET=before", encoding="utf-8")
            snapshot = {path: path.read_bytes()}
            path.write_text("SECRET=after", encoding="utf-8")
            ralph.restore_protected(snapshot)
            self.assertEqual(path.read_text(encoding="utf-8"), "SECRET=before")

    def test_protected_snapshot_preserves_existing_extended_secret_paths(self):
        with tempfile.TemporaryDirectory() as td:
            old_root = ralph.ROOT
            try:
                ralph.ROOT = Path(td)
                existing = ralph.ROOT / ".npmrc"
                existing.write_text("_authToken=before", encoding="utf-8")
                snapshot = ralph.protected_snapshot()
                self.assertEqual(snapshot[existing], b"_authToken=before")
                existing.write_text("_authToken=after", encoding="utf-8")
                ralph.restore_protected(snapshot, [".npmrc"])
                self.assertEqual(existing.read_text(encoding="utf-8"), "_authToken=before")
            finally:
                ralph.ROOT = old_root

    def test_restore_protected_removes_new_sensitive_file(self):
        with tempfile.TemporaryDirectory() as td:
            old_root = ralph.ROOT
            try:
                ralph.ROOT = Path(td)
                new_secret = ralph.ROOT / ".npmrc"
                new_secret.write_text("_authToken=secret", encoding="utf-8")
                ralph.restore_protected({}, [".npmrc"])
                self.assertFalse(new_secret.exists())
            finally:
                ralph.ROOT = old_root


if __name__ == "__main__":
    unittest.main()
