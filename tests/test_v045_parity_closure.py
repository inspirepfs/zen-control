from pathlib import Path
import sys
import types
import unittest

# Device 360 imports app.activity; keep host-side tests independent of psycopg.
psycopg = types.ModuleType("psycopg")
psycopg.Error = Exception
psycopg.connect = None
rows = types.ModuleType("psycopg.rows")
rows.dict_row = object()
sys.modules.setdefault("psycopg", psycopg)
sys.modules.setdefault("psycopg.rows", rows)

from app.device360 import build_device_360_snapshot
from app.policy_explain import build_policy_explanation
from app.policy_simulation import build_policy_simulation, build_profile_impact, policy_delta

ROOT = Path(__file__).resolve().parents[1]


def base_policy(**overrides):
    value = {
        "mode": "normal",
        "mode_source": "profile: Default",
        "base_mode": "normal",
        "base_mode_source": "profile: Default",
        "bandwidth_preset": "normal",
        "bandwidth_name": "Normal",
        "bandwidth_upload": "Unlimited",
        "bandwidth_download": "Unlimited",
        "blocked_services": [],
        "requested_blocked_services": [],
        "blocked_policy_groups": [],
        "unsupported_policy_keys": [],
        "unsupported_policy_group_members": [],
        "scheduled_service_overrides": [],
        "active_date_exception": None,
        "schedule_reason": None,
        "next_policy_action": None,
        "policy_at": "2026-09-10T10:00+01:00",
        "policy_timezone": "Europe/London",
        "quota_state": {"configured": False, "enabled": True, "available": True, "daily": {"limit_mb": 0, "action": "blocked"}, "services": []},
        "conflicts": [],
    }
    value.update(overrides)
    return value


def live_plan(service_states=()):
    return {
        "status": "in_sync",
        "live_mode": "normal",
        "global_mode": "normal",
        "mode_drift": False,
        "bandwidth_drift": False,
        "bandwidth_suspended": False,
        "live_bandwidth_active": False,
        "service_states": list(service_states),
        "planned_actions": [],
        "reason": "RouterOS controls match.",
    }


class SimulationParityClosureTests(unittest.TestCase):
    def test_reporting_only_request_is_a_real_simulation_change(self):
        baseline = base_policy()
        scenario = base_policy(
            requested_blocked_services=["minecraft"],
            unsupported_policy_keys=["minecraft"],
        )
        result = build_policy_simulation(
            address="192.0.2.10", device_name="Tablet", baseline=baseline,
            scenario=scenario, scenario_label="reporting", simulation_at=scenario["policy_at"],
        )
        self.assertTrue(result["changed"])
        row = next(item for item in result["changes"] if item["kind"] == "service_request")
        self.assertEqual(["minecraft"], row["items"])
        self.assertFalse(row["enforceable"])

    def test_removing_reporting_only_request_is_visible(self):
        baseline = base_policy(
            requested_blocked_services=["minecraft"],
            unsupported_policy_keys=["minecraft"],
        )
        rows = policy_delta(baseline, base_policy())
        row = next(item for item in rows if item["kind"] == "service_request_removed")
        self.assertEqual(["minecraft"], row["items"])

    def test_quota_configuration_change_is_visible_without_current_enforcement_change(self):
        baseline = base_policy()
        scenario = base_policy(quota_state={
            "configured": True, "enabled": True, "available": True,
            "daily": {"limit_mb": 500, "action": "blocked"}, "services": [],
        })
        rows = policy_delta(baseline, scenario)
        quota = next(item for item in rows if item["kind"] == "quota_policy")
        self.assertIn("500 MiB/day", quota["to"])

    def test_profile_impact_counts_quota_only_change_as_changed(self):
        baseline = base_policy()
        scenario = base_policy(quota_state={
            "configured": True, "enabled": True, "available": True,
            "daily": {"limit_mb": 250, "action": "slow"}, "services": [],
        })
        row = build_policy_simulation(
            address="192.0.2.10", device_name="Tablet", baseline=baseline,
            scenario=scenario, scenario_label="quota", simulation_at=scenario["policy_at"], scope="profile",
        )
        impact = build_profile_impact(profile_id=1, profile_name="Default", simulation_at="now", rows=[row])
        self.assertEqual(1, impact["changed_devices"])


class ExplainabilityParityClosureTests(unittest.TestCase):
    def build(self, desired, services, groups=None, states=()):
        return build_policy_explanation(
            address="192.0.2.10", device_name="Tablet",
            device_config={"alias": "Tablet", "mode_override": "inherit", "category": "tablet"},
            profile={"name": "Default", "desired_mode": "normal", "blocked_services": desired.get("requested_blocked_services", [])},
            desired_policy=desired, live_plan=live_plan(states), temporary_access={"active": False},
            service_definitions=services, policy_groups=groups,
        )

    def test_custom_aggregate_group_provenance_uses_live_group_catalogue(self):
        groups = {"video": {"key": "video", "name": "Video", "members": ("youtube",), "builtin": False}}
        desired = base_policy(
            blocked_services=["youtube"], requested_blocked_services=["video"], blocked_policy_groups=["video"]
        )
        result = self.build(
            desired,
            [{"key": "youtube", "name": "YouTube", "classification": "TLS/SNI", "builtin": True}],
            groups,
            [{"key": "youtube", "name": "YouTube", "available": True, "desired_blocked": True, "live_blocked": True, "drift": False}],
        )
        row = next(item for item in result["services"] if item["key"] == "youtube")
        self.assertEqual("policy_group", row["source_kind"])
        self.assertIn("Video", row["source"])

    def test_unsupported_custom_group_member_is_block_requested_not_allow(self):
        groups = {"games": {"key": "games", "name": "Games", "members": ("minecraft",), "builtin": False}}
        desired = base_policy(
            requested_blocked_services=["games"], blocked_policy_groups=["games"],
            unsupported_policy_group_members=["minecraft"],
        )
        result = self.build(
            desired,
            [{"key": "minecraft", "name": "Minecraft", "classification": "reporting", "enforcement_approved": False}],
            groups,
        )
        row = next(item for item in result["services"] if item["key"] == "minecraft")
        self.assertEqual("BLOCK REQUESTED", row["desired"])
        self.assertEqual("NO CONTRACT", row["live"])
        self.assertEqual("reporting_only", row["enforcement_state"])
        self.assertEqual("policy_group", row["source_kind"])

    def test_approved_but_unbuildable_custom_contract_is_degraded_not_reporting_only(self):
        desired = base_policy(
            requested_blocked_services=["broken"], unsupported_policy_keys=["broken"]
        )
        result = self.build(
            desired,
            [{"key": "broken", "name": "Broken", "classification": "TLS/SNI", "enforcement_approved": True,
              "provisioning_error": "TLS patterns are required"}],
        )
        row = next(item for item in result["services"] if item["key"] == "broken")
        self.assertEqual("DEGRADED", row["live"])
        self.assertEqual("degraded", row["enforcement_state"])
        self.assertIn("TLS patterns", row["error"])

    def test_routeros_contract_read_failure_is_unavailable_not_reporting_only(self):
        desired = base_policy(blocked_services=["youtube"], requested_blocked_services=["youtube"])
        result = self.build(
            desired,
            [{"key": "youtube", "name": "YouTube", "classification": "TLS/SNI", "builtin": True}],
            states=[{"key": "youtube", "name": "YouTube", "available": False, "desired_blocked": True,
                     "live_blocked": False, "drift": False, "error": "RouterOS API unavailable"}],
        )
        row = result["services"][0]
        self.assertEqual("UNAVAILABLE", row["live"])
        self.assertEqual("unavailable", row["enforcement_state"])


class Device360ParityClosureTests(unittest.TestCase):
    def explanation(self):
        return {
            "device": {"ip": "192.0.2.10", "name": "Tablet", "profile": "Default", "category": "tablet"},
            "summary": {"headline": "Current", "desired_mode": "normal", "live_mode": "normal", "global_mode": "normal",
                        "effective_now": "normal", "sync_status": "in_sync", "mode_source": "default", "temporary": False},
            "services": [
                {"key": "report", "name": "Report", "desired": "BLOCK REQUESTED", "desired_blocked": False,
                 "live": "NO CONTRACT", "enforcement_state": "reporting_only", "drift": False},
                {"key": "down", "name": "Down", "desired": "BLOCK", "desired_blocked": True,
                 "live": "UNAVAILABLE", "enforcement_state": "unavailable", "drift": False},
                {"key": "bad", "name": "Bad", "desired": "BLOCK REQUESTED", "desired_blocked": False,
                 "live": "DEGRADED", "enforcement_state": "degraded", "drift": False},
                {"key": "unknown", "name": "Unknown", "desired": "ALLOW", "desired_blocked": False,
                 "live": "UNKNOWN", "enforcement_state": "unknown", "drift": False},
            ],
            "quota": {}, "next_changes": [], "limitations": [], "links": {}, "bandwidth": {}, "conflicts": [], "planned_actions": [],
        }

    def test_device360_does_not_conflate_reporting_only_unavailable_degraded_and_unknown(self):
        result = build_device_360_snapshot(explanation=self.explanation(), activity_error="telemetry unavailable")
        counts = result["service_counts"]
        self.assertEqual(1, counts["reporting_only"])
        self.assertEqual(1, counts["unavailable"])
        self.assertEqual(1, counts["degraded"])
        self.assertEqual(1, counts["unknown"])
        self.assertEqual(2, counts["requested_only"])

    def test_device360_policy_is_the_exact_explanation_contract_not_a_second_resolver(self):
        explanation = self.explanation()
        result = build_device_360_snapshot(explanation=explanation, activity_error="offline")
        self.assertEqual(result["policy"], explanation)
        self.assertEqual(explanation["summary"], result["summary"])


class ParityUxClosureTests(unittest.TestCase):
    def test_release_and_parity_wording(self):
        main = (ROOT / "app/main.py").read_text()
        simulation = (ROOT / "app/templates/simulation.html").read_text()
        device360 = (ROOT / "app/templates/device_360.html").read_text()
        self.assertIn('version="0.54.0"', main)
        self.assertIn("REPORTING ONLY", simulation)
        self.assertIn("unavailable", device360.lower())


if __name__ == "__main__":
    unittest.main()
