"""Boundary tests for the host-profile/controller seam.

Host-project metadata and commands may vary by profile.  RALPH lifecycle,
approval, usage, model, efficiency, and resource behavior remain controller
concerns and import no ZEN application modules.
"""
from __future__ import annotations

import ast
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from scripts import ralph, ralph_profile


class ProfileBoundaryTests(unittest.TestCase):
    def test_profile_controls_project_metadata_validation_and_discovery(self):
        profile = replace(
            ralph_profile.PROJECT_PROFILE,
            identity="Boundary Host",
            completion_commit_prefix="chore(boundary):",
            source_roots=("host_source",),
            test_root="host_tests",
            optional_final_validators=(("host-validator", "scripts/ux_validate.py"),),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "host_source").mkdir()
            (root / "host_source" / "module.py").write_text("value = 1\n", encoding="utf-8")
            (root / "scripts").mkdir()
            (root / "scripts" / "ux_validate.py").write_text("", encoding="utf-8")
            gates = profile.qualification_gates(root, "python3")
            self.assertEqual(["python3", "-m", "py_compile", "host_source/module.py"], gates[0][1])
            self.assertEqual(["python3", "-m", "unittest", "discover", "-s", "host_tests", "-v"], gates[1][1])
            self.assertEqual([("host-validator", ["python3", "scripts/ux_validate.py"])], profile.final_validator_gates(root, "python3"))

        with mock.patch.object(ralph, "PROJECT_PROFILE", profile):
            self.assertIn("Boundary Host", ralph.plan_prompt("test"))
            self.assertIn("Boundary Host", ralph.step_prompt(ralph.default_state(), {"id": 1, "title": "test", "objective": "test", "acceptance": [], "test_change_policy": "none"}, None, 0))
            self.assertEqual("chore(boundary): boundary work", ralph._default_commit_message({"plan": {"goal": "Boundary work"}}))
            self.assertEqual(profile.qualification_gates(ralph.ROOT, ralph.sys.executable), ralph.qualification_gates())
            self.assertEqual(
                profile.final_validator_gates(ralph.ROOT, ralph.sys.executable),
                ralph.final_qualification_gates()[-2:-1],
            )

    def test_profile_owns_runtime_boundary_and_host_prompt_guardrails(self):
        profile = replace(
            ralph_profile.PROJECT_PROFILE,
            identity="Portable Host",
            runtime_dir_name=".controller-state",
            execution_prompt_guardrails=("Do not access Portable Host production.",),
            nonrecoverable_validation_markers=("portable-policy",),
        )
        state = {"plan_hash": "a" * 64, "human_steering": []}
        step = {"id": 1, "title": "Boundary", "objective": "Prove boundary", "acceptance": ["done"], "test_change_policy": "none"}
        policy = ralph.efficiency_policy.normalize_policy({"normal_prompt_command_budget": 3})
        with (
            mock.patch.object(ralph, "PROJECT_PROFILE", profile),
            mock.patch.object(ralph.efficiency_policy, "load_policy", return_value=policy) as load_policy,
            mock.patch.object(ralph, "context_handoff", return_value={}),
        ):
            self.assertTrue(ralph._is_runtime_authority_path(".controller-state/state.json"))
            self.assertFalse(ralph._is_runtime_authority_path(".ralph/state.json"))
            self.assertIsNone(ralph._context_path(".controller-state/context.json"))
            prompt = ralph.step_prompt(state, step, None, 0)
            self.assertEqual(profile.policy_storage_directory(ralph.ROOT), load_policy.call_args.kwargs["runtime_directory"])
            self.assertIn(".controller-state/policy.md", prompt)
            self.assertIn("Do not edit any file under .controller-state", prompt)
            self.assertIn("Do not access Portable Host production.", prompt)
            self.assertNotIn("RouterOS", prompt)
            self.assertTrue(ralph.is_recoverable_validation_block("python test failed"))
            self.assertFalse(ralph.is_recoverable_validation_block("python test failed portable-policy"))

    def test_controller_source_has_no_zen_host_literals_outside_compatibility_schemas(self):
        source = Path(ralph.__file__).read_text(encoding="utf-8")
        self.assertNotIn("ZEN Control", source)
        self.assertNotIn("RouterOS", source)
        self.assertNotIn('startswith(".ralph/")', source)

    def test_controller_has_no_zen_application_module_dependency(self):
        tree = ast.parse(Path(ralph.__file__).read_text(encoding="utf-8"))
        imports = [
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        ]
        self.assertFalse(any(name == "app" or name.startswith("app.") for name in imports))
        self.assertEqual("zen_ralph_lite_state_v1", ralph.default_state()["schema"])


if __name__ == "__main__":
    unittest.main()
