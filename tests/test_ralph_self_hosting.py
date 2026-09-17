from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "ralph.py"
spec = importlib.util.spec_from_file_location("ralph_self_hosting", MODULE_PATH)
ralph = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(ralph)


class SelfHostingGrantContractTests(unittest.TestCase):
    def state(self):
        state = ralph.default_state()
        state.update(
            {
                "status": "BLOCKED_HUMAN",
                "plan_hash": "plan-123",
                "current_step": 2,
                "loop_count": 7,
                "block_reason": "Codex attempted to change RALPH controller/tooling authority",
                "plan": {
                    "goal": "repair self hosting",
                    "steps": [
                        {"id": 1, "title": "characterize"},
                        {"id": 2, "title": "repair authority"},
                    ],
                },
            }
        )
        return state

    def test_exact_plan_step_and_paths_are_allowed(self):
        state = self.state()
        state["self_hosting_grant"] = {
            "plan_hash": "plan-123",
            "step": 2,
            "gate_id": "HG-0007-02",
            "paths": ["scripts/ralph.py", "tests/test_ralph_lifecycle.py"],
        }
        allowed, reason = ralph.self_hosting_grant_allows(
            state, 2, ["scripts/ralph.py", "tests/test_ralph_lifecycle.py"]
        )
        self.assertTrue(allowed, reason)

    def test_grant_rejects_wrong_plan_or_step(self):
        state = self.state()
        state["self_hosting_grant"] = {
            "plan_hash": "other-plan",
            "step": 2,
            "paths": ["scripts/ralph.py"],
        }
        self.assertFalse(ralph.self_hosting_grant_allows(state, 2, ["scripts/ralph.py"])[0])
        state["self_hosting_grant"]["plan_hash"] = "plan-123"
        self.assertFalse(ralph.self_hosting_grant_allows(state, 3, ["scripts/ralph.py"])[0])

    def test_grant_rejects_runtime_protected_non_tooling_and_extra_tooling(self):
        state = self.state()
        state["self_hosting_grant"] = {
            "plan_hash": "plan-123",
            "step": 2,
            "paths": ["scripts/ralph.py"],
        }
        cases = [
            [".ralph/state.json"],
            ["secrets/token"],
            ["app/main.py"],
            ["scripts/ralph.py", "scripts/ralph_web.py"],
        ]
        for paths in cases:
            with self.subTest(paths=paths):
                allowed, _ = ralph.self_hosting_grant_allows(state, 2, paths)
                self.assertFalse(allowed)

    def test_authority_snapshot_covers_registered_tooling(self):
        snapshot = ralph.authority_snapshot()
        for rel in ralph.TOOLING_PATHS:
            if rel.startswith(".ralph/"):
                continue
            self.assertIn(ralph.ROOT / rel, snapshot, rel)


class AuthorizeSelfHostingCommandTests(unittest.TestCase):
    def base_state(self):
        state = ralph.default_state()
        state.update(
            {
                "status": "BLOCKED_HUMAN",
                "plan_hash": "plan-123",
                "current_step": 2,
                "loop_count": 7,
                "block_reason": "Codex attempted to change RALPH controller/tooling authority",
                "plan": {
                    "goal": "repair self hosting",
                    "steps": [
                        {"id": 1, "title": "characterize"},
                        {"id": 2, "title": "repair authority"},
                    ],
                },
            }
        )
        return state

    def call(self, state, paths):
        args = argparse.Namespace(
            plan_hash="plan-123",
            gate="HG-0007-02",
            path=paths,
            reason="Permit only these tooling paths for this approved repair step.",
        )
        saved = []
        with (
            mock.patch.object(ralph, "init_files"),
            mock.patch.object(ralph, "load_state", return_value=state),
            mock.patch.object(ralph, "save_state", side_effect=lambda value: saved.append(dict(value))),
            mock.patch.object(ralph, "gate_id_for_state", return_value="HG-0007-02"),
            mock.patch.object(ralph, "append_journal"),
            mock.patch.object(ralph, "live_write"),
        ):
            rc = ralph.cmd_authorize_self_hosting(args)
        return rc, saved

    def test_command_records_exact_scoped_grant_and_resumes_same_step(self):
        state = self.base_state()
        rc, saved = self.call(state, ["scripts/ralph.py", "tests/test_ralph_lifecycle.py"])
        self.assertEqual(rc, 0)
        self.assertTrue(saved)
        grant = state["self_hosting_grant"]
        self.assertEqual(grant["plan_hash"], "plan-123")
        self.assertEqual(grant["step"], 2)
        self.assertEqual(grant["gate_id"], "HG-0007-02")
        self.assertEqual(grant["paths"], ["scripts/ralph.py", "tests/test_ralph_lifecycle.py"])
        self.assertEqual(state["status"], "APPROVED")
        self.assertIsNone(state["block_reason"])
        self.assertEqual(state["human_steering"][-1]["self_hosting_paths"], grant["paths"])

    def test_command_refuses_runtime_state(self):
        state = self.base_state()
        with self.assertRaisesRegex(RuntimeError, "runtime state"):
            self.call(state, [".ralph/policy.md"])

    def test_command_refuses_non_tooling_path(self):
        state = self.base_state()
        with self.assertRaisesRegex(RuntimeError, "registered RALPH tooling"):
            self.call(state, ["app/main.py"])

    def test_command_only_works_for_exact_authority_block(self):
        state = self.base_state()
        state["block_reason"] = "policy violation: protected paths ['secrets/x']"
        with self.assertRaisesRegex(RuntimeError, "only for the current RALPH tooling authority block"):
            self.call(state, ["scripts/ralph.py"])


class BootstrapSourceFlowTests(unittest.TestCase):
    def test_parser_exposes_explicit_authorization_command(self):
        parser = ralph.build_parser()
        args = parser.parse_args(
            [
                "authorize-self-hosting",
                "plan-123",
                "--gate",
                "HG-0007-02",
                "--path",
                "scripts/ralph.py",
                "--reason",
                "bounded operator grant",
            ]
        )
        self.assertIs(args.func, ralph.cmd_authorize_self_hosting)

    def test_run_checks_exact_grant_before_restoring_authority(self):
        source = MODULE_PATH.read_text(encoding="utf-8")
        changed = source.index("changed_authority = authority_changed_paths(authority)")
        granted = source.index("self_hosting_grant_allows", changed)
        restore = source.index("restore_authority(authority)", granted)
        remember = source.index("remember_plan_files(state, files)", restore)
        self.assertLess(changed, granted)
        self.assertLess(granted, restore)
        self.assertLess(restore, remember)

    def test_successful_step_expires_active_grant(self):
        source = MODULE_PATH.read_text(encoding="utf-8")
        marker = 'state["self_hosting_grant"] = None\n            state["current_step"] += 1'
        self.assertIn(marker, source)


if __name__ == "__main__":
    unittest.main()
