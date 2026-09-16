import importlib.util
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"


def _load_module():
    if str(SCRIPTS) not in sys.path:
        sys.path.insert(0, str(SCRIPTS))
    path = SCRIPTS / "fresh_install_acceptance.py"
    spec = importlib.util.spec_from_file_location("zen_fresh_install_acceptance", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def fresh_payload(**updates):
    payload = {
        "schema": "zen_fresh_install_state_v1",
        "database_exists": True,
        "user_version": 1,
        "schema_migrations": [1],
        "config_revision": 1,
        "mutable_counts": {
            "profiles": 0,
            "device_policy": 0,
            "policy_templates": 0,
            "schedule_plans": 0,
            "schedule_templates": 0,
            "date_exceptions": 0,
            "service_groups": 0,
            "custom_services": 0,
            "custom_policy_groups": 0,
            "custom_bandwidth_presets": 0,
            "push_subscriptions": 0,
        },
        "builtin_services": 14,
        "builtin_policy_groups": 2,
        "builtin_bandwidth_presets": 5,
        "app_settings": 20,
        "marker_present": False,
    }
    payload.update(updates)
    return payload


def commissioning(**states):
    values = {
        "policy_database": "pass",
        "runtime_workers": "pass",
        "routeros_api": "unavailable",
        "security_authority": "blocked",
    }
    values.update(states)
    return {
        "schema": "zen_commissioning_report_v1",
        "overall": "blocked",
        "checks": [{"key": key, "state": state} for key, state in values.items()],
    }


class FreshInstallSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = _load_module()

    def test_destroy_scope_requires_exact_throwaway_confirmation(self):
        self.module._validate_destroy_scope("zen-fresh-install-ci", "zen-fresh-install-ci")
        for project, confirmation in (
            ("zen-control", "zen-control"),
            ("production", "production"),
            ("household", "household"),
            ("zen-fresh-install-ci", "wrong"),
        ):
            with self.assertRaises(self.module.FreshInstallError):
                self.module._validate_destroy_scope(project, confirmation)

    def test_fresh_state_accepts_seeded_defaults_but_no_operator_state(self):
        self.module._validate_fresh_state(fresh_payload())

    def test_fresh_state_rejects_retained_marker_or_operator_state(self):
        with self.assertRaises(self.module.FreshInstallError):
            self.module._validate_fresh_state(fresh_payload(marker_present=True))
        dirty = fresh_payload()
        dirty["mutable_counts"] = {**dirty["mutable_counts"], "profiles": 1}
        with self.assertRaises(self.module.FreshInstallError):
            self.module._validate_fresh_state(dirty)

    def test_fresh_state_requires_schema_and_exact_bootstrap_revision(self):
        with self.assertRaises(self.module.FreshInstallError):
            self.module._validate_fresh_state(fresh_payload(user_version=0, schema_migrations=[]))
        with self.assertRaises(self.module.FreshInstallError):
            self.module._validate_fresh_state(fresh_payload(config_revision=2))

    def test_fresh_commissioning_requires_safe_routeros_blockers(self):
        self.module._validate_fresh_commissioning(commissioning())
        with self.assertRaises(self.module.FreshInstallError):
            self.module._validate_fresh_commissioning(commissioning(routeros_api="pass"))
        bad = commissioning()
        bad["overall"] = "ready"
        with self.assertRaises(self.module.FreshInstallError):
            self.module._validate_fresh_commissioning(bad)


class FreshInstallOrchestrationTests(unittest.TestCase):
    def test_two_cycles_destroy_state_rebuild_once_and_repeat_acceptance(self):
        module = _load_module()
        commands = []

        def record_run(command, **_kwargs):
            commands.append(list(command))
            return mock.Mock(returncode=0, stdout="", stderr="")

        with (
            mock.patch.object(module, "_run", side_effect=record_run),
            mock.patch.object(module, "_destroy_project") as destroy,
            mock.patch.object(module, "_assert_project_clean") as clean,
            mock.patch.object(module, "_wait_healthy") as wait,
            mock.patch.object(module, "run_acceptance", return_value=["runtime ok"]) as runtime,
            mock.patch.object(module, "_fresh_state", side_effect=[fresh_payload(), fresh_payload()]),
            mock.patch.object(module, "_fresh_commissioning_report", side_effect=[commissioning(), commissioning()]),
            mock.patch.object(module, "_write_cycle_marker") as marker,
        ):
            results = module.run_fresh_install_acceptance(
                project_name="zen-fresh-install-ci",
                confirm_destroy_project="zen-fresh-install-ci",
                env_file=".env.example",
                compose_file="docker-compose.yml",
                base_url="http://127.0.0.1:8080",
                expected_version="0.59.0",
                admin_user="ci-parent",
                admin_password="ci-password",
                cycles=2,
                startup_timeout=1,
                request_timeout=1,
            )

        self.assertEqual(runtime.call_count, 2)
        self.assertEqual(wait.call_count, 2)
        self.assertEqual(marker.call_count, 2)
        self.assertGreaterEqual(destroy.call_count, 3)
        self.assertGreaterEqual(clean.call_count, 3)
        app_up = [cmd for cmd in commands if "up" in cmd and "mikrotik-control" in cmd]
        self.assertEqual(len(app_up), 2)
        self.assertIn("--build", app_up[0])
        self.assertNotIn("--build", app_up[1])
        self.assertTrue(any("previous-cycle marker" in item for item in results) is False)
        self.assertIn("cycle 2: fresh database/bootstrap PASS schema=1 revision=1", results)


class FreshInstallReleaseContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = (ROOT / ".github/workflows/quality.yml").read_text()
        cls.script = (ROOT / "scripts/fresh_install_acceptance.py").read_text()
        cls.readme = (ROOT / "README.md").read_text()
        cls.changelog = (ROOT / "CHANGELOG.md").read_text()
        cls.install = (ROOT / "docs/INSTALL.md").read_text()
        cls.public_release = (ROOT / "docs/PUBLIC_RELEASE.md").read_text()
        cls.contributing = (ROOT / "CONTRIBUTING.md").read_text()

    def test_quality_has_independent_destructive_fresh_install_job(self):
        self.assertIn("fresh-install-commissioning:", self.workflow)
        self.assertIn("needs: source-quality", self.workflow)
        self.assertIn("scripts/fresh_install_acceptance.py", self.workflow)
        self.assertIn("--cycles 2", self.workflow)
        self.assertIn("--confirm-destroy-project zen-fresh-install-ci", self.workflow)
        self.assertIn("MIKROTIK_HOST: 127.0.0.1", self.workflow)
        self.assertIn("down -v --remove-orphans", self.workflow)
        self.assertIn("if: always()", self.workflow)

    def test_harness_has_no_routeros_mutation_authority(self):
        for forbidden in (
            "set_global_mode(",
            "set_device_mode(",
            "set_device_services(",
            "mutation_session(",
            "coherent_router_mutation",
        ):
            self.assertNotIn(forbidden, self.script)
        self.assertIn("fresh synthetic install must remain BLOCKED", self.script)
        self.assertIn("config_revision", self.script)
        self.assertIn("marker_present", self.script)

    def test_release_and_docs_describe_fresh_install_gate(self):
        self.assertIn("Current maintenance release: **v0.59.0.", self.readme)
        self.assertIn("## v0.59.0.11 — Fresh-Install & First-Run Commissioning Acceptance", self.changelog)
        for text in (self.readme, self.install, self.public_release, self.contributing):
            self.assertIn("fresh-install", text.lower())
        self.assertIn("isolated", self.install.lower())
        self.assertIn("destructive", self.public_release.lower())


if __name__ == "__main__":
    unittest.main()
