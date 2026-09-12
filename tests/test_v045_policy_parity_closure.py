from pathlib import Path
import sys
import types
import unittest

# Device 360 imports app.activity, whose production store uses psycopg. These
# parity tests exercise only pure composition, so keep the host test runner
# independent of the optional PostgreSQL client.
psycopg = types.ModuleType("psycopg")
psycopg.Error = Exception
psycopg.connect = None
rows = types.ModuleType("psycopg.rows")
rows.dict_row = object()
sys.modules.setdefault("psycopg", psycopg)
sys.modules.setdefault("psycopg.rows", rows)

from app.device360 import build_device_360_snapshot
from app.policy_explain import build_policy_explanation
from app.policy_parity import policy_parity_contract
from app.policy_simulation import build_policy_simulation

ROOT = Path(__file__).resolve().parents[1]


class PolicyParityClosureTests(unittest.TestCase):
    def desired(self):
        return {
            "mode": "blocked",
            "mode_source": "quota: daily",
            "base_mode": "normal",
            "base_mode_source": "profile: Child",
            "bandwidth_preset": "normal",
            "blocked_services": ["roblox", "youtube"],
            "requested_blocked_services": ["custom_games", "youtube", "legacy_service"],
            "blocked_policy_groups": ["custom_games"],
            "unsupported_policy_keys": ["legacy_service"],
            "unsupported_policy_group_members": ["old_game"],
            "schedule_active": True,
            "schedule_reason": "schedule: Bedtime",
            "active_date_exception": {"label": "School holiday"},
            "quota_active": True,
            "quota_state": {"configured": True, "available": True, "active": True},
            "policy_at": "2026-09-10T20:00+01:00",
            "policy_timezone": "Europe/London",
            "conflicts": [],
        }

    def explanation(self, desired=None, live_plan=None, groups=None):
        desired = desired or self.desired()
        services = [
            {"key": "youtube", "name": "YouTube", "classification": "TLS/SNI"},
            {"key": "roblox", "name": "Roblox", "classification": "TLS/SNI"},
            {"key": "legacy_service", "name": "Legacy Service", "classification": "reporting"},
        ]
        return build_policy_explanation(
            address="192.0.2.10",
            device_name="Tablet",
            device_config={"profile_id": 1, "mode_override": "inherit", "category": "tablet"},
            profile={"id": 1, "name": "Child", "desired_mode": "normal", "blocked_services": ["custom_games", "youtube"]},
            desired_policy=desired,
            live_plan=live_plan,
            temporary_access={"active": False},
            service_definitions=services,
            policy_groups=groups or {
                "custom_games": {"key": "custom_games", "name": "Custom Games", "members": ["roblox"], "builtin": False}
            },
        )

    def test_shared_contract_normalizes_resolver_state(self):
        contract = policy_parity_contract(self.desired())
        self.assertEqual("blocked", contract["mode"])
        self.assertEqual(["roblox", "youtube"], contract["blocked_services"])
        self.assertEqual(["custom_games"], contract["blocked_policy_groups"])
        self.assertEqual(["legacy_service"], contract["unsupported_policy_keys"])
        self.assertTrue(contract["quota_active"])

    def test_explanation_and_simulation_share_identical_desired_contract(self):
        desired = self.desired()
        explanation = self.explanation(desired=desired)
        simulation = build_policy_simulation(
            address="192.0.2.10", device_name="Tablet",
            baseline=desired, scenario=desired, scenario_label="same",
            simulation_at=desired["policy_at"],
        )
        self.assertEqual(explanation["desired_contract"], simulation["scenario_contract"])
        self.assertEqual(simulation["baseline_contract"], simulation["scenario_contract"])

    def test_device360_carries_explanation_contract_without_re_resolving(self):
        explanation = self.explanation()
        snapshot = build_device_360_snapshot(explanation=explanation)
        self.assertEqual(explanation["desired_contract"], snapshot["desired_contract"])
        self.assertEqual(explanation, snapshot["policy"])

    def test_custom_aggregate_group_provenance_is_not_lost(self):
        result = self.explanation()
        roblox = next(row for row in result["services"] if row["key"] == "roblox")
        self.assertEqual("policy_group", roblox["source_kind"])
        self.assertIn("Custom Games", roblox["source"])

    def test_device360_does_not_call_unavailable_contract_reporting_only(self):
        desired = self.desired()
        live = {
            "status": "partial",
            "live_mode": "blocked",
            "global_mode": "normal",
            "mode_drift": False,
            "bandwidth_drift": False,
            "service_states": [
                {"key": "youtube", "name": "YouTube", "available": False, "desired_blocked": True,
                 "live_blocked": False, "drift": False, "error": "contract malformed"},
                {"key": "roblox", "name": "Roblox", "available": True, "desired_blocked": True,
                 "live_blocked": True, "drift": False},
            ],
            "planned_actions": [],
        }
        snapshot = build_device_360_snapshot(explanation=self.explanation(desired=desired, live_plan=live))
        self.assertEqual(1, snapshot["service_counts"]["unavailable"])
        self.assertEqual(1, snapshot["service_counts"]["reporting_only"])
        self.assertEqual(1, snapshot["service_counts"]["unsupported"])

    def test_router_outage_preserves_desired_contract(self):
        explanation = self.explanation(live_plan=None)
        self.assertEqual("blocked", explanation["desired_contract"]["mode"])
        self.assertEqual("unknown", explanation["summary"]["live_mode"])


class PolicyParityRouteWiringTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.main = (ROOT / "app/main.py").read_text()
        cls.simulation = (ROOT / "app/policy_simulation.py").read_text()
        cls.device360 = (ROOT / "app/device360.py").read_text()

    def test_main_simulation_uses_retained_quota_evidence_for_selected_time(self):
        block = self.main.split('def policy_simulate_run(', 1)[1].split('\n@app.', 1)[0]
        self.assertIn('quota_usage = get_quota_usage(ip, at=at)', block)
        self.assertIn('compute_effective_policy(ip, at=at, quota_usage=quota_usage)', block)
        self.assertIn('quota_usage=quota_usage', block)

    def test_legacy_future_simulator_uses_same_quota_evidence_path(self):
        block = self.main.split('def local_simulate(', 1)[1].split('\n@app.', 1)[0]
        self.assertIn('quota_usage = get_quota_usage(ip, at=at)', block)
        self.assertIn('compute_effective_policy(ip, at=at, quota_usage=quota_usage)', block)

    def test_simulation_contract_exposes_machine_comparable_parity_projection(self):
        self.assertIn('"baseline_contract": policy_parity_contract(baseline)', self.simulation)
        self.assertIn('"scenario_contract": policy_parity_contract(scenario)', self.simulation)

    def test_device360_reporting_only_and_unavailable_are_separate(self):
        self.assertIn('row.get("enforcement_state") == "reporting_only"', self.device360)
        self.assertIn('row.get("enforcement_state") == "unavailable"', self.device360)


if __name__ == "__main__":
    unittest.main()
