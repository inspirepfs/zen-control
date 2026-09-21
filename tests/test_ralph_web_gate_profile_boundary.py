"""Boundary coverage for RALPH's web and human-gate host-project seam."""
from __future__ import annotations

import ast
import subprocess
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from scripts import ralph_gate, ralph_profile, ralph_web


class WebGateProfileBoundaryTests(unittest.TestCase):
    def test_web_snapshot_and_git_use_profile_metadata_and_context(self):
        profile = replace(
            ralph_profile.PROJECT_PROFILE,
            identity="Boundary Host",
            controller_cli_relative_path="tools/ralph-controller.py",
            git_executable="boundary-git",
        )
        completed = subprocess.CompletedProcess([], 0, stdout="main\n", stderr="")
        with mock.patch.object(ralph_web, "PROJECT_PROFILE", profile), mock.patch.object(
            ralph_web.subprocess, "run", return_value=completed
        ) as run:
            snapshot = ralph_web.snapshot()
            ralph_web.git_snapshot()
        self.assertEqual(profile.project_metadata(ralph_web.ROOT), snapshot["project"])
        self.assertEqual(["boundary-git", "branch", "--show-current"], run.call_args_list[-4].args[0])

    def test_web_controller_invocations_and_gate_commands_use_profile_cli(self):
        profile = replace(
            ralph_profile.PROJECT_PROFILE,
            controller_cli_relative_path="tools/ralph-controller.py",
        )
        state = {
            "status": "BLOCKED_HUMAN",
            "plan_hash": "a" * 64,
            "loop_count": 1,
            "current_step": 1,
            "block_reason": "policy violation: protected path",
            "plan": {"steps": [{"title": "boundary", "test_change_policy": "add-only"}]},
        }
        with mock.patch.object(ralph_web, "PROJECT_PROFILE", profile), mock.patch.object(
            ralph_web, "RALPH_CLI", profile.controller_cli(ralph_web.ROOT)
        ), mock.patch.object(ralph_gate, "PROJECT_PROFILE", profile):
            self.assertEqual(
                [ralph_web.sys.executable, str(profile.controller_cli(ralph_web.ROOT)), "run"],
                ralph_web._controller_command("run"),
            )
            gate = ralph_gate.build_gate(state)
        self.assertTrue(gate["steer"].startswith("python3 tools/ralph-controller.py steer"))
        self.assertEqual(".ralph/state.json", gate["sources"]["state"])

    def test_zen_incident_and_performance_guidance_remains_profile_owned(self):
        incident = ralph_gate._guidance("runtime_evidence", "incident evidence is required")
        performance = ralph_gate._guidance("validation_evidence", "performance evidence is required")
        self.assertEqual(incident, ralph_profile.PROJECT_PROFILE.guidance(ralph_profile.PROJECT_PROFILE.incident_gate_guidance))
        self.assertEqual(performance, ralph_profile.PROJECT_PROFILE.guidance(ralph_profile.PROJECT_PROFILE.performance_gate_guidance))
        self.assertTrue(any("python3 scripts/perf_acceptance.py ../zen-performance.json" in item for item in performance["actions"]))

    def test_gate_host_production_keywords_and_web_metadata_are_profile_owned(self):
        profile = replace(
            ralph_profile.PROJECT_PROFILE,
            identity="Portable Host",
            runtime_dir_name=".controller-state",
            production_action_keywords=("portable-live",),
            web_login_subtitle="Portable Host operator console",
            web_title="Portable Control",
            web_console_subtitle="Portable console",
        )
        with mock.patch.object(ralph_gate, "PROJECT_PROFILE", profile):
            self.assertEqual("production_action", ralph_gate._gate_class("portable-live change required"))
            self.assertNotEqual("production_action", ralph_gate._gate_class("routeros change required"))
        with mock.patch.object(ralph_web, "PROJECT_PROFILE", profile):
            snapshot = ralph_web.snapshot(usage_report={})
        self.assertEqual("Portable Host", snapshot["project"]["identity"])
        self.assertEqual(".controller-state", snapshot["project"]["runtime_directory"] )
        self.assertIn("Portable Control", ralph_web.PAGE.replace("__PROJECT_WEB_TITLE__", profile.web_title))

    def test_ralph_core_modules_do_not_import_zen_application_modules(self):
        modules = (ralph_gate, ralph_web)
        for module in modules:
            with self.subTest(module=module.__name__):
                tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
                imports = [
                    alias.name
                    for node in ast.walk(tree)
                    if isinstance(node, (ast.Import, ast.ImportFrom))
                    for alias in node.names
                ]
                self.assertFalse(any(name == "app" or name.startswith("app.") for name in imports))


if __name__ == "__main__":
    unittest.main()
