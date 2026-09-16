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
        self.assertTrue(ralph.is_tooling_path("scripts/ralph_gate.py"))
        self.assertTrue(ralph.is_tooling_path("tests/test_ralph_lite.py"))
        self.assertTrue(ralph.is_tooling_path("tests/test_ralph_gate.py"))
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
        self.assertEqual(command, [("PASS", "exit=0 · python3 -m unittest tests.test_classifier -v")])
        files = ralph.codex_event_messages({
            "type": "item.completed",
            "item": {
                "type": "file_change",
                "status": "completed",
                "changes": [{"path": "app/classifier.py", "kind": "update"}],
            },
        })
        self.assertEqual(files, [("EDIT", "app/classifier.py")])

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
        self.assertEqual(messages, [("USAGE", "cumulative_input=100 cached=80 cache_write=0 output=20 reasoning=7")])

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
                "cache_write_input_tokens": 5,
                "output_tokens": 21,
                "reasoning_output_tokens": 8,
            },
        })
        self.assertEqual(metrics["commands_executed"], 1)
        self.assertEqual(metrics["input_tokens"], 120)
        self.assertEqual(metrics["cached_input_tokens"], 90)
        self.assertEqual(metrics["cache_write_input_tokens"], 5)
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
                self.assertIn("HARD BUDGET: use at most 6 shell command executions", prompt)
                self.assertIn("Batch related reads into one discovery command", prompt)
                self.assertIn("Normally inspect no more than 6-8 relevant files", prompt)
                self.assertIn("Do not broadly scan docs/", prompt)
                self.assertIn("use `python3`", prompt)
                self.assertIn('blocker_class="validation-only"', prompt)
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


class EfficiencyBudgetTests(unittest.TestCase):
    def test_healthy_loop_is_within_efficiency_budget(self):
        stats = {
            "commands_executed": 5,
            "files_inspected": 6,
            "input_tokens": 300000,
            "cached_input_tokens": 250000,
        }
        self.assertEqual(ralph.efficiency_findings(stats), [])

    def test_expensive_loop_reports_each_exceeded_budget(self):
        stats = {
            "commands_executed": 12,
            "files_inspected": 10,
            "input_tokens": 931164,
            "cached_input_tokens": 798464,
        }
        findings = ralph.efficiency_findings(stats)
        self.assertIn("commands 12>8", findings)
        self.assertIn("reported-files 10>8", findings)
        self.assertIn("cumulative-input 931164>600000", findings)
        self.assertIn("non-cached-input 132700>100000", findings)

    def test_cached_input_does_not_hide_noncached_budget(self):
        stats = {
            "commands_executed": 4,
            "files_inspected": 4,
            "input_tokens": 700000,
            "cached_input_tokens": 590000,
        }
        findings = ralph.efficiency_findings(stats)
        self.assertIn("cumulative-input 700000>600000", findings)
        self.assertIn("non-cached-input 110000>100000", findings)


class ControllerQualificationAuthorityTests(unittest.TestCase):
    def test_validation_only_blocker_defers_to_controller_gates(self):
        result = {
            "needs_human": False,
            "blocker_class": "validation-only",
            "blockers": ["focused tests could not run"],
        }
        blocked, reason = ralph.codex_requires_human_before_gates(result)
        self.assertFalse(blocked)
        self.assertEqual(reason, "")

    def test_human_decision_blocker_still_blocks_before_gates(self):
        result = {
            "needs_human": True,
            "blocker_class": "human-decision",
            "blockers": ["operator must choose migration policy"],
        }
        blocked, reason = ralph.codex_requires_human_before_gates(result)
        self.assertTrue(blocked)
        self.assertIn("migration policy", reason)

    def test_explicit_blocked_human_summary_cannot_be_laundered_into_pass(self):
        step = {
            "objective": "Validate operator-owned evidence.",
            "acceptance": [
                "If operator evidence is unavailable, stop at BLOCKED_HUMAN with exact instructions."
            ],
        }
        result = {
            "summary": "BLOCKED_HUMAN: ../zen-performance.json is absent.",
            "needs_human": False,
            "blocker_class": "validation-only",
            "blockers": [],
        }
        blocked, reason = ralph.codex_requires_human_before_gates(result, step)
        self.assertTrue(blocked)
        self.assertIn("zen-performance.json", reason)

    def test_blocked_human_text_without_approved_delegation_does_not_create_authority(self):
        step = {"objective": "Run local checks.", "acceptance": ["Controller gates remain authoritative."]}
        result = {
            "summary": "BLOCKED_HUMAN: local focused test command missing.",
            "needs_human": False,
            "blocker_class": "validation-only",
            "blockers": [],
        }
        blocked, reason = ralph.codex_requires_human_before_gates(result, step)
        self.assertFalse(blocked)
        self.assertEqual("", reason)

    def test_current_python_command_budget_block_is_recoverable(self):
        reason = "Focused tests were not run: `python` is unavailable and the six-command shell budget was exhausted before retrying with `python3`."
        self.assertTrue(ralph.is_recoverable_validation_block(reason))
        self.assertFalse(ralph.is_recoverable_validation_block("policy violation: protected paths ['.env']"))

    def test_result_schema_requires_explicit_blocker_class(self):
        required = ralph.RESULT_SCHEMA["required"]
        self.assertIn("blocker_class", required)
        self.assertIn("validation_notes", required)


class CodexUsageGuardTests(unittest.TestCase):
    def sample_usage(self, *, used_primary=90, used_secondary=20, allowed=True):
        return {
            "ordinaryUsageAllowed": allowed,
            "rateLimits": {},
            "rateLimitsByLimitId": {
                "codex": {
                    "limitId": "codex",
                    "planType": "plus",
                    "primary": {"usedPercent": used_primary, "windowDurationMins": 300, "resetsAt": 2_000_000_000},
                    "secondary": {"usedPercent": used_secondary, "windowDurationMins": 10080, "resetsAt": 2_000_100_000},
                }
            },
            "rateLimitResetCredits": {"availableCount": 0},
        }

    def test_normalise_codex_usage_keeps_only_non_sensitive_limit_state(self):
        raw = self.sample_usage()
        raw["accountId"] = "must-not-be-retained"
        snapshot = ralph.normalise_codex_usage(raw, "gpt-5.6-terra")
        self.assertEqual(snapshot["plan_type"], "plus")
        self.assertTrue(snapshot["ordinary_usage_allowed"])
        self.assertEqual([w["name"] for w in snapshot["windows"]], ["5h", "weekly"])
        self.assertEqual(snapshot["windows"][0]["remaining_percent"], 10.0)
        self.assertNotIn("account_id", snapshot)
        self.assertNotIn("must-not-be-retained", str(snapshot))

    def test_guard_pauses_at_exactly_five_percent_remaining(self):
        snapshot = ralph.normalise_codex_usage(self.sample_usage(used_primary=95), "gpt-5.6-terra")
        status, findings = ralph.codex_usage_guard(snapshot)
        self.assertEqual(status, "PAUSE")
        self.assertIn("5h remaining 5.0% <= 5.0% reserve", findings)

    def test_guard_is_safe_above_reserve(self):
        snapshot = ralph.normalise_codex_usage(self.sample_usage(used_primary=94, used_secondary=40), "gpt-5.6-terra")
        self.assertEqual(ralph.codex_usage_guard(snapshot), ("SAFE", []))

    def test_guard_does_not_infer_recovery_without_backend_authority(self):
        snapshot = ralph.normalise_codex_usage(self.sample_usage(used_primary=10, allowed=None), "gpt-5.6-terra")
        status, findings = ralph.codex_usage_guard(snapshot)
        self.assertEqual(status, "UNKNOWN")
        self.assertIn("ordinaryUsageAllowed", findings[0])

    def test_backend_disallow_pauses_even_when_percentages_have_headroom(self):
        snapshot = ralph.normalise_codex_usage(self.sample_usage(used_primary=10, allowed=False), "gpt-5.6-terra")
        status, _ = ralph.codex_usage_guard(snapshot)
        self.assertEqual(status, "PAUSE")

    def test_live_usage_report_aggregates_old_and_new_usage_formats(self):
        with tempfile.TemporaryDirectory() as td:
            old_live = ralph.LIVE
            try:
                ralph.LIVE = Path(td) / "live.log"
                ralph.LIVE.write_text(
                    "[x] RALPH    loop=0001 step=1/7\n"
                    "[x] USAGE    input=100 cached=80 output=10 reasoning=3\n"
                    "[x] RALPH    loop=0002 step=2/7\n"
                    "[x] USAGE    cumulative_input=200 cached=150 cache_write=4 output=20 reasoning=5\n",
                    encoding="utf-8",
                )
                usage = ralph.live_usage_by_loop()
                self.assertEqual(usage[1]["noncached"], 20)
                self.assertEqual(usage[2]["input"], 200)
                self.assertEqual(sum(x["input"] for x in usage.values()), 300)
            finally:
                ralph.LIVE = old_live


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

class HumanGateResolutionTests(unittest.TestCase):
    def _with_paths(self, td: str):
        root = Path(td)
        saved = {
            "STATE": ralph.STATE,
            "PLAN": ralph.PLAN,
            "JOURNAL": ralph.JOURNAL,
            "CONTEXT": ralph.CONTEXT,
            "LIVE": ralph.LIVE,
            "init_files": ralph.init_files,
        }
        ralph.STATE = root / "state.json"
        ralph.PLAN = root / "plan.md"
        ralph.JOURNAL = root / "journal.md"
        ralph.CONTEXT = root / "context.json"
        ralph.LIVE = root / "live.log"
        ralph.JOURNAL.write_text("", encoding="utf-8")
        ralph.LIVE.write_text("", encoding="utf-8")
        ralph.init_files = lambda: None
        return saved

    def _restore_paths(self, saved):
        for name, value in saved.items():
            setattr(ralph, name, value)

    def _blocked_state(self, *, reason="Incident Monitor warning is runtime-owned evidence."):
        plan = valid_plan(9)
        plan["steps"][3].update({
            "title": "Classify Incident Monitor runtime evidence",
            "objective": "Classify the runtime-owned Incident Monitor warning without manufacturing health.",
            "acceptance": [
                "If evidence is runtime-owned, stop with BLOCKED_HUMAN and state the exact safe operator action needed."
            ],
            "test_change_policy": "none",
        })
        digest = ralph.plan_hash(plan)
        state = ralph.default_state()
        state.update({
            "status": "BLOCKED_HUMAN",
            "plan_hash": digest,
            "plan": plan,
            "current_step": 4,
            "loop_count": 15,
            "block_reason": reason,
            "last_result": None,
        })
        return state, digest

    def test_resolve_gate_records_human_confirmed_and_advances_without_loop(self):
        with tempfile.TemporaryDirectory() as td:
            saved = self._with_paths(td)
            try:
                state, digest = self._blocked_state()
                ralph.save_state(state)
                ralph.PLAN.write_text(ralph.render_plan(state["plan"]), encoding="utf-8")
                args = type("Args", (), {
                    "plan_hash": digest,
                    "gate": "HG-0015-04",
                    "reason": "Fresh scan completed; active durable incidents=0.",
                })()
                self.assertEqual(0, ralph.cmd_resolve_gate(args))
                resolved = ralph.load_state()
                self.assertEqual("APPROVED", resolved["status"])
                self.assertEqual(5, resolved["current_step"])
                self.assertEqual(15, resolved["loop_count"])
                self.assertEqual("HUMAN_CONFIRMED", resolved["last_result"])
                self.assertIsNone(resolved["block_reason"])
                self.assertEqual("HG-0015-04", resolved["human_gate_resolutions"][-1]["gate_id"])
                context = ralph.load_context()
                self.assertEqual(4, context["last_step"])
                self.assertEqual("HUMAN_CONFIRMED", context["last_result"])
                self.assertIn("active durable incidents=0", context["summary"])
                journal = ralph.JOURNAL.read_text(encoding="utf-8")
                self.assertIn("Result: HUMAN_CONFIRMED", journal)
                self.assertIn("Codex loop incremented: no", journal)
                self.assertIn("gate=HG-0015-04 resolved HUMAN_CONFIRMED", ralph.LIVE.read_text(encoding="utf-8"))
            finally:
                self._restore_paths(saved)

    def test_resolve_gate_rejects_stale_gate_id_without_mutation(self):
        with tempfile.TemporaryDirectory() as td:
            saved = self._with_paths(td)
            try:
                state, digest = self._blocked_state()
                ralph.save_state(state)
                before = ralph.STATE.read_bytes()
                args = type("Args", (), {
                    "plan_hash": digest,
                    "gate": "HG-0014-04",
                    "reason": "stale gate",
                })()
                with self.assertRaisesRegex(RuntimeError, "does not match current gate"):
                    ralph.cmd_resolve_gate(args)
                self.assertEqual(before, ralph.STATE.read_bytes())
            finally:
                self._restore_paths(saved)

    def test_resolve_gate_rejects_policy_or_authority_block(self):
        state, _ = self._blocked_state(reason="policy violation: protected paths ['.env']")
        allowed, reason = ralph.human_gate_resolution_allowed(state)
        self.assertFalse(allowed)
        self.assertIn("policy/authority", reason)

    def test_resolve_gate_requires_explicit_step_delegation(self):
        state, _ = self._blocked_state()
        state["plan"]["steps"][3]["acceptance"] = ["Operator review may be useful."]
        allowed, reason = ralph.human_gate_resolution_allowed(state)
        self.assertFalse(allowed)
        self.assertIn("does not explicitly delegate", reason)

    def test_resume_remains_retry_not_step_acceptance(self):
        with tempfile.TemporaryDirectory() as td:
            saved = self._with_paths(td)
            try:
                state, digest = self._blocked_state()
                ralph.save_state(state)
                args = type("Args", (), {"plan_hash": digest, "reason": "new runtime evidence supplied"})()
                self.assertEqual(0, ralph.cmd_resume(args))
                resumed = ralph.load_state()
                self.assertEqual("APPROVED", resumed["status"])
                self.assertEqual(4, resumed["current_step"])
                self.assertEqual(15, resumed["loop_count"])
                self.assertIsNone(resumed["block_reason"])
                self.assertIn("retry same approved step", ralph.JOURNAL.read_text(encoding="utf-8"))
            finally:
                self._restore_paths(saved)


class ProposalLifecycleTests(unittest.TestCase):
    def _with_paths(self, directory):
        return {
            "STATE": ralph.STATE,
            "PLAN": ralph.PLAN,
            "JOURNAL": ralph.JOURNAL,
            "init_files": ralph.init_files,
        }

    def test_reject_restores_previous_completed_state_when_snapshot_exists(self):
        with tempfile.TemporaryDirectory() as td:
            saved = self._with_paths(td)
            try:
                root = Path(td)
                ralph.STATE = root / "state.json"
                ralph.PLAN = root / "plan.md"
                ralph.JOURNAL = root / "journal.md"
                ralph.JOURNAL.write_text("", encoding="utf-8")
                ralph.init_files = lambda: None
                old_plan = valid_plan()
                old_hash = ralph.plan_hash(old_plan)
                previous = ralph.default_state()
                previous.update({
                    "status": "PLAN_COMPLETE",
                    "plan_hash": old_hash,
                    "plan": old_plan,
                    "current_step": 6,
                    "loop_count": 9,
                })
                proposal = valid_plan()
                proposal["goal"] = "Replacement proposal"
                proposal_hash = ralph.plan_hash(proposal)
                pending = dict(previous)
                pending.update({
                    "status": "AWAITING_APPROVAL",
                    "plan_hash": proposal_hash,
                    "plan": proposal,
                    "current_step": 1,
                    "proposal_previous_state": previous,
                    "codex_usage": {"schema": "zen_codex_usage_v1"},
                })
                ralph.save_state(pending)
                ralph.PLAN.write_text(ralph.render_plan(proposal), encoding="utf-8")

                rc = ralph.cmd_reject(type("Args", (), {"plan_hash": proposal_hash, "reason": "scope correction"})())
                self.assertEqual(rc, 0)
                restored = ralph.load_state()
                self.assertEqual(restored["status"], "PLAN_COMPLETE")
                self.assertEqual(restored["plan_hash"], old_hash)
                self.assertEqual(restored["loop_count"], 9)
                self.assertEqual(restored["codex_usage"]["schema"], "zen_codex_usage_v1")
                self.assertEqual(ralph.PLAN.read_text(encoding="utf-8"), ralph.render_plan(old_plan))
                self.assertIn("Execution authority granted: no", ralph.JOURNAL.read_text(encoding="utf-8"))
            finally:
                ralph.STATE = saved["STATE"]
                ralph.PLAN = saved["PLAN"]
                ralph.JOURNAL = saved["JOURNAL"]
                ralph.init_files = saved["init_files"]

    def test_reject_legacy_pending_proposal_returns_idle_without_losing_loop_count(self):
        with tempfile.TemporaryDirectory() as td:
            saved = self._with_paths(td)
            try:
                root = Path(td)
                ralph.STATE = root / "state.json"
                ralph.PLAN = root / "plan.md"
                ralph.JOURNAL = root / "journal.md"
                ralph.JOURNAL.write_text("", encoding="utf-8")
                ralph.init_files = lambda: None
                proposal = valid_plan()
                proposal_hash = ralph.plan_hash(proposal)
                pending = ralph.default_state()
                pending.update({
                    "status": "AWAITING_APPROVAL",
                    "plan_hash": proposal_hash,
                    "plan": proposal,
                    "loop_count": 9,
                    "codex_usage": {"schema": "zen_codex_usage_v1"},
                })
                ralph.save_state(pending)
                ralph.PLAN.write_text(ralph.render_plan(proposal), encoding="utf-8")

                ralph.cmd_reject(type("Args", (), {"plan_hash": proposal_hash, "reason": "superseded"})())
                restored = ralph.load_state()
                self.assertEqual(restored["status"], "IDLE")
                self.assertIsNone(restored["plan"])
                self.assertIsNone(restored["plan_hash"])
                self.assertEqual(restored["loop_count"], 9)
                self.assertEqual(restored["codex_usage"]["schema"], "zen_codex_usage_v1")
                self.assertFalse(ralph.PLAN.exists())
            finally:
                ralph.STATE = saved["STATE"]
                ralph.PLAN = saved["PLAN"]
                ralph.JOURNAL = saved["JOURNAL"]
                ralph.init_files = saved["init_files"]

    def test_proposal_usage_is_separate_from_last_implementation_loop(self):
        with tempfile.TemporaryDirectory() as td:
            old_live = ralph.LIVE
            try:
                ralph.LIVE = Path(td) / "live.log"
                ralph.LIVE.write_text(
                    "[x] RALPH    loop=0009 step=7/7\n"
                    "[x] USAGE    cumulative_input=389806 cached=339712 output=9792 reasoning=3672\n"
                    "[x] CODEX    PLAN PROPOSAL · sandbox=read-only backend=default\n"
                    "[x] USAGE    cumulative_input=829351 cached=690688 output=9042 reasoning=4354\n"
                    "[x] CODEX    PLAN PROPOSAL · sandbox=read-only backend=default\n"
                    "[x] USAGE    cumulative_input=126962 cached=88064 output=6938 reasoning=4503\n",
                    encoding="utf-8",
                )
                scopes = ralph.live_usage_scopes()
                self.assertEqual(scopes["implementation"][9]["input"], 389806)
                self.assertEqual([x["input"] for x in scopes["planning"]], [829351, 126962])
                self.assertEqual(ralph.live_usage_by_loop()[9]["input"], 389806)
            finally:
                ralph.LIVE = old_live
