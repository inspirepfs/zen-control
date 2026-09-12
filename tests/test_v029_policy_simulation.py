from pathlib import Path
import tempfile
import unittest

from app.policy_simulation import build_policy_simulation, build_profile_impact, policy_delta
from app.policy_store import PolicyStore

ROOT = Path(__file__).resolve().parents[1]


class PolicySimulationCompositionTests(unittest.TestCase):
    def baseline(self):
        return {
            "mode": "normal", "mode_source": "profile: Normal",
            "bandwidth_preset": "normal", "bandwidth_name": "Normal",
            "bandwidth_upload": "Unlimited", "bandwidth_download": "Unlimited",
            "blocked_services": ["youtube"], "blocked_policy_groups": [],
            "next_policy_action": None, "policy_timezone": "Europe/London",
            "policy_at": "2026-09-09T19:00+01:00", "quota_state": {},
        }

    def scenario(self):
        return {
            **self.baseline(),
            "mode": "blocked", "mode_source": "device override",
            "bandwidth_preset": "slow", "bandwidth_name": "Slow",
            "blocked_services": ["roblox", "youtube"],
            "blocked_policy_groups": ["gaming"],
        }

    def test_delta_reports_mode_bandwidth_service_and_group_changes(self):
        rows = policy_delta(self.baseline(), self.scenario())
        kinds = {row["kind"] for row in rows}
        self.assertIn("mode", kinds)
        self.assertIn("bandwidth", kinds)
        self.assertIn("service_block", kinds)
        self.assertIn("group_block", kinds)
        self.assertIn("source", kinds)

    def test_contract_is_read_only_and_has_no_apply_callback(self):
        result = build_policy_simulation(
            address="192.0.2.10", device_name="Tablet",
            baseline=self.baseline(), scenario=self.scenario(),
            scenario_label="test", simulation_at="2026-09-09T19:00+01:00",
        )
        self.assertEqual("zen_policy_simulation_v1", result["schema_version"])
        text = repr(result).lower()
        self.assertNotIn("apply_policy", text)
        self.assertNotIn("write_router", text)
        self.assertIn("does not write sqlite", result["evidence_note"].lower())

    def test_live_router_actions_are_current_state_comparison_not_prediction(self):
        result = build_policy_simulation(
            address="192.0.2.10", device_name="Tablet",
            baseline=self.baseline(), scenario=self.scenario(),
            scenario_label="test", simulation_at="2026-09-10T21:00+01:00",
            live_plan={"status": "drift", "planned_actions": [
                {"kind": "mode", "from": "normal", "to": "blocked", "supported": True}
            ]},
        )
        self.assertEqual(1, result["live_comparison"]["action_count"])
        self.assertIn("RouterOS as it is now", result["live_comparison"]["note"])
        self.assertIn("not a prediction", result["live_comparison"]["note"])

    def test_future_quota_prediction_is_explicitly_refused(self):
        result = build_policy_simulation(
            address="192.0.2.10", device_name="Tablet",
            baseline=self.baseline(), scenario=self.scenario(),
            scenario_label="test", simulation_at="2026-09-10T21:00+01:00",
        )
        self.assertFalse(result["quota_prediction"]["predicted"])
        self.assertIn("not predicted", result["quota_prediction"]["note"])

    def test_profile_impact_counts_changed_devices_without_score(self):
        changed = build_policy_simulation(
            address="192.0.2.10", device_name="A", baseline=self.baseline(),
            scenario=self.scenario(), scenario_label="profile", simulation_at="now",
        )
        same = build_policy_simulation(
            address="192.0.2.11", device_name="B", baseline=self.baseline(),
            scenario=self.baseline(), scenario_label="profile", simulation_at="now",
        )
        result = build_profile_impact(
            profile_id=1, profile_name="School", simulation_at="now", rows=[changed, same]
        )
        self.assertEqual(2, result["device_count"])
        self.assertEqual(1, result["changed_devices"])
        self.assertNotIn("risk", repr(result).lower())


class PolicyStoreSimulationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = PolicyStore(str(Path(self.tmp.name) / "policy.db"))
        self.profile_a = self.store.create_profile("Normal", "normal", "normal")
        self.profile_b = self.store.create_profile("Blocked", "blocked", "normal", blocked_services=["youtube"])
        self.ip = "192.0.2.10"
        self.store.update_device(self.ip, "Tablet", "", self.profile_a["id"], "inherit", "tablet", True)

    def tearDown(self):
        self.tmp.cleanup()

    def test_device_scenario_uses_same_resolver_without_persisting_assignment(self):
        before = self.store.list_device_policy()[self.ip].copy()
        result = self.store.simulate_effective_policy(
            self.ip, profile_id=self.profile_b["id"], mode_override="inherit",
            keep_profile=False, keep_mode=False,
        )
        after = self.store.list_device_policy()[self.ip]
        self.assertEqual("blocked", result["mode"])
        self.assertIn("youtube", result["blocked_services"])
        self.assertEqual(before["profile_id"], after["profile_id"])
        self.assertEqual(self.profile_a["id"], after["profile_id"])

    def test_unsaved_mode_override_does_not_persist(self):
        result = self.store.simulate_effective_policy(
            self.ip, mode_override="slow", keep_profile=True, keep_mode=False,
        )
        self.assertEqual("slow", result["mode"])
        self.assertEqual("inherit", self.store.list_device_policy()[self.ip]["mode_override"])

    def test_profile_candidate_is_validated_and_not_written(self):
        candidate = self.store.build_profile_candidate(
            self.profile_a["id"], "Normal changed", "blocked", "normal",
            blocked_services=["youtube"],
        )
        result = self.store.simulate_effective_policy(self.ip, profile_candidate=candidate)
        self.assertEqual("blocked", result["mode"])
        self.assertEqual("Normal", self.store.get_profile(self.profile_a["id"])["name"])
        self.assertEqual("normal", self.store.get_profile(self.profile_a["id"])["desired_mode"])

    def test_invalid_candidate_fails_before_simulation(self):
        with self.assertRaises(ValueError):
            self.store.build_profile_candidate(
                self.profile_a["id"], "", "normal", "normal"
            )

    def test_unassigned_scenario_resolves_default_normal(self):
        result = self.store.simulate_effective_policy(
            self.ip, profile_id=None, mode_override="inherit",
            keep_profile=False, keep_mode=False,
        )
        self.assertEqual("normal", result["mode"])
        self.assertEqual("default", result["mode_source"])


class PolicySimulationUxTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.main = (ROOT / "app/main.py").read_text()
        cls.index = (ROOT / "app/templates/index.html").read_text()
        cls.template = (ROOT / "app/templates/simulation.html").read_text()
        cls.css = (ROOT / "app/static/policy-simulation.css").read_text()
        cls.store = (ROOT / "app/policy_store.py").read_text()
        cls.readme = (ROOT / "README.md").read_text() + "\n" + (ROOT / "CHANGELOG.md").read_text()

    def test_release_version_and_simulation_asset(self):
        self.assertIn('version="0.54.0"', self.main)
        self.assertIn('/static/policy-simulation.css?v=0.54.0', self.template)

    def test_workbench_and_preview_routes_are_present(self):
        for route in (
            '@app.get("/policy/simulate"', '@app.post("/policy/simulate"',
            '@app.post("/local/devices/preview"', '@app.post("/local/profiles/preview"',
        ):
            self.assertIn(route, self.main)
        self.assertIn('formaction="/local/profiles/preview"', self.index)
        self.assertIn('formaction="/local/devices/preview"', self.index)

    def test_simulator_reuses_resolver_and_has_no_persistence_calls(self):
        self.assertIn('def _compute_effective_policy_from_context(', self.store)
        self.assertIn('def simulate_effective_policy(', self.store)
        simulation_method = self.store.split('def simulate_effective_policy(', 1)[1].split('\n    def ', 1)[0]
        self.assertNotIn('UPDATE ', simulation_method)
        self.assertNotIn('INSERT ', simulation_method)
        self.assertNotIn('DELETE ', simulation_method)

    def test_template_is_explicitly_read_only_and_future_honest(self):
        self.assertIn('READ ONLY', self.template)
        self.assertIn('Future quota consumption is not predicted', self.template)
        self.assertIn('not a forecast of future RouterOS state', self.template)
        self.assertNotIn('<form method="post" action="/devices/policy/apply"', self.template)

    def test_css_is_dense_and_responsive(self):
        self.assertIn('.simulation-state-grid', self.css)
        self.assertIn('.simulation-delta', self.css)
        self.assertIn('@media(max-width:850px)', self.css)
        self.assertIn('@media(max-width:520px)', self.css)

    def test_readme_documents_v029_contract(self):
        self.assertIn('## Policy Simulation / What-If Impact (v0.29)', self.readme)
        self.assertIn('/policy/simulate', self.readme)
        self.assertIn('never writes SQLite', self.readme)


if __name__ == "__main__":
    unittest.main()
