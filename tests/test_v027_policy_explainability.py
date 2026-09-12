from pathlib import Path
import unittest

from app.policy_explain import build_policy_explanation


ROOT = Path(__file__).resolve().parents[1]


class PolicyExplanationTests(unittest.TestCase):
    def setUp(self):
        self.services = [
            {"key": "youtube", "name": "YouTube", "classification": "TLS/SNI"},
            {"key": "roblox", "name": "Roblox", "classification": "TLS/SNI"},
            {"key": "steam", "name": "Steam", "classification": "TLS/SNI"},
            {"key": "xbox", "name": "Xbox", "classification": "TLS/SNI"},
            {"key": "playstation", "name": "PlayStation", "classification": "TLS/SNI"},
            {"key": "minecraft", "name": "Minecraft", "classification": "reporting"},
        ]
        self.profile = {
            "id": 7,
            "name": "School Night",
            "desired_mode": "normal",
            "blocked_services": ["youtube", "gaming"],
        }
        self.device = {
            "ip": "192.0.2.10",
            "alias": "Tablet",
            "profile_id": 7,
            "mode_override": "inherit",
            "category": "tablet",
        }
        self.desired = {
            "mode": "blocked",
            "mode_source": "schedule: Bedtime",
            "base_mode": "normal",
            "base_mode_source": "profile: School Night",
            "bandwidth_preset": "normal",
            "bandwidth_name": "Normal",
            "bandwidth_upload": "Unlimited",
            "bandwidth_download": "Unlimited",
            "blocked_services": ["playstation", "roblox", "steam", "xbox", "youtube"],
            "requested_blocked_services": ["gaming", "youtube"],
            "blocked_policy_groups": ["gaming"],
            "scheduled_service_overrides": [],
            "active_date_exception": None,
            "schedule_reason": "schedule: Bedtime",
            "next_policy_action": {
                "date": "2026-09-10",
                "time": "07:00",
                "label": "Morning",
                "value": "normal",
            },
            "policy_at": "2026-09-09T21:30+01:00",
            "policy_timezone": "Europe/London",
            "quota_state": {"configured": False, "active": False},
            "unsupported_policy_keys": [],
            "conflicts": [],
        }
        self.live = {
            "status": "in_sync",
            "live_mode": "blocked",
            "global_mode": "normal",
            "mode_drift": False,
            "bandwidth_drift": False,
            "bandwidth_suspended": False,
            "live_bandwidth_active": False,
            "service_states": [
                {"key": "youtube", "name": "YouTube", "available": True, "desired_blocked": True, "live_blocked": True, "drift": False, "classification": "TLS/SNI"},
                {"key": "roblox", "name": "Roblox", "available": True, "desired_blocked": True, "live_blocked": True, "drift": False, "classification": "TLS/SNI"},
                {"key": "steam", "name": "Steam", "available": True, "desired_blocked": True, "live_blocked": True, "drift": False, "classification": "TLS/SNI"},
                {"key": "xbox", "name": "Xbox", "available": True, "desired_blocked": True, "live_blocked": True, "drift": False, "classification": "TLS/SNI"},
                {"key": "playstation", "name": "PlayStation", "available": True, "desired_blocked": True, "live_blocked": True, "drift": False, "classification": "TLS/SNI"},
            ],
            "planned_actions": [],
            "reason": "RouterOS controls match.",
        }

    def build(self, **overrides):
        args = {
            "address": self.device["ip"],
            "device_name": "Tablet",
            "device_config": self.device,
            "profile": self.profile,
            "desired_policy": self.desired,
            "live_plan": self.live,
            "temporary_access": {"active": False},
            "service_definitions": self.services,
            "router_error": None,
            "focus_service": None,
        }
        args.update(overrides)
        return build_policy_explanation(**args)

    def test_mode_chain_explains_profile_schedule_desired_and_live_state(self):
        result = self.build()
        stages = [row["stage"] for row in result["mode_chain"]]
        self.assertIn("profile", stages)
        self.assertIn("schedule", stages)
        self.assertIn("desired", stages)
        self.assertIn("router_device", stages)
        self.assertIn("global", stages)
        self.assertEqual("blocked", result["summary"]["effective_now"])
        self.assertIn("Bedtime", result["summary"]["mode_source"])

    def test_direct_profile_service_block_has_profile_provenance(self):
        result = self.build(focus_service="youtube")
        row = result["focus_service"]
        self.assertEqual("BLOCK", row["desired"])
        self.assertEqual("profile", row["source_kind"])
        self.assertEqual("BLOCK", row["live"])
        self.assertIn("live RouterOS matches", result["summary"]["headline"])

    def test_logical_group_is_explained_without_inventing_group_firewall_authority(self):
        result = self.build(focus_service="roblox")
        row = result["focus_service"]
        self.assertEqual("policy_group", row["source_kind"])
        self.assertIn("Gaming", row["source"])
        self.assertIn("group itself has no RouterOS firewall authority", row["detail"])

    def test_concrete_allow_schedule_overrides_group_for_one_service(self):
        desired = dict(self.desired)
        desired["blocked_services"] = ["playstation", "steam", "xbox", "youtube"]
        desired["scheduled_service_overrides"] = [
            {"service": "roblox", "state": "allow", "label": "Roblox homework exception", "policy_group": False}
        ]
        live = dict(self.live)
        live["service_states"] = [dict(row) for row in self.live["service_states"]]
        roblox = next(row for row in live["service_states"] if row["key"] == "roblox")
        roblox["desired_blocked"] = False
        roblox["live_blocked"] = False
        result = self.build(desired_policy=desired, live_plan=live, focus_service="roblox")
        row = result["focus_service"]
        self.assertEqual("ALLOW", row["desired"])
        self.assertEqual("schedule", row["source_kind"])
        self.assertIn("ALLOW", row["detail"])

    def test_quota_is_explained_as_authoritative_after_schedule(self):
        desired = dict(self.desired)
        desired["quota_state"] = {
            "configured": True,
            "enabled": True,
            "available": True,
            "active": True,
            "active_service_blocks": ["gaming"],
            "daily": {"limit_mb": 0, "exhausted": False},
        }
        desired["scheduled_service_overrides"] = [
            {"service": "roblox", "state": "allow", "label": "Allow Roblox", "policy_group": False}
        ]
        result = self.build(desired_policy=desired, focus_service="roblox")
        row = result["focus_service"]
        self.assertEqual("quota", row["source_kind"])
        self.assertIn("Gaming quota", row["source"])
        self.assertIn("authoritative", row["detail"])

    def test_reporting_only_custom_block_is_never_presented_as_enforced(self):
        desired = dict(self.desired)
        desired["requested_blocked_services"] = ["minecraft"]
        desired["blocked_policy_groups"] = []
        desired["blocked_services"] = []
        desired["unsupported_policy_keys"] = ["minecraft"]
        live = dict(self.live)
        live["service_states"] = []
        result = self.build(desired_policy=desired, live_plan=live, focus_service="minecraft")
        row = result["focus_service"]
        self.assertEqual("BLOCK REQUESTED", row["desired"])
        self.assertEqual("NO CONTRACT", row["live"])
        self.assertFalse(row["available"])
        self.assertIn("no trusted RouterOS enforcement contract", result["summary"]["headline"])

    def test_router_outage_never_invents_normal_live_state(self):
        result = self.build(live_plan=None, router_error="Router API offline")
        self.assertEqual("unknown", result["summary"]["live_mode"])
        self.assertEqual("unknown", result["summary"]["effective_now"])
        self.assertIn("live RouterOS state is unavailable", result["summary"]["headline"])
        self.assertTrue(any("Router API offline" in item for item in result["limitations"]))

    def test_temporary_normal_does_not_hide_more_restrictive_global_mode(self):
        live = dict(self.live)
        live["live_mode"] = "normal"
        live["global_mode"] = "blocked"
        result = self.build(
            live_plan=live,
            temporary_access={
                "active": True,
                "restore_mode": "blocked",
                "restore_time": "22:15",
            },
        )
        self.assertEqual("blocked", result["summary"]["effective_now"])
        self.assertIn("household global mode", result["summary"]["headline"])
        temp = next(row for row in result["mode_chain"] if row["stage"] == "temporary")
        self.assertIn("Global mode and service blocks still apply", temp["detail"])

    def test_next_policy_transition_is_retained(self):
        result = self.build()
        self.assertEqual(1, len(result["next_changes"]))
        self.assertIn("2026-09-10 07:00", result["next_changes"][0]["when"])
        self.assertIn("Morning", result["next_changes"][0]["label"])

    def test_explanation_contract_is_read_only_and_contains_no_write_callback(self):
        result = self.build()
        self.assertEqual("zen_policy_explanation_v1", result["schema_version"])
        text = repr(result).lower()
        self.assertNotIn("set_device_mode", text)
        self.assertNotIn("provision", text)


class PolicyExplanationUxTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.main = (ROOT / "app/main.py").read_text()
        cls.index = (ROOT / "app/templates/index.html").read_text()
        cls.explain = (ROOT / "app/templates/policy_explain.html").read_text()
        cls.policy_summary = (ROOT / "app/templates/policy_summary.html").read_text()
        cls.activity_device = (ROOT / "app/templates/activity_device.html").read_text()
        cls.activity_service = (ROOT / "app/templates/activity_service.html").read_text()
        cls.readme = (ROOT / "README.md").read_text() + "\n" + (ROOT / "CHANGELOG.md").read_text()

    def test_release_is_v027_and_assets_are_cache_busted(self):
        self.assertIn('version="0.54.2"', self.main)
        self.assertIn('/static/app.css?v=0.54.2', self.index)
        self.assertIn('/static/app.css?v=0.54.2', self.explain)
        self.assertNotIn('v=0.26.0', self.explain)

    def test_page_and_json_routes_share_the_same_explanation_builder(self):
        self.assertIn('@app.get("/policy/explain/{address}"', self.main)
        self.assertIn('@app.get("/api/policy/explain/{address}")', self.main)
        self.assertGreaterEqual(self.main.count('get_policy_explanation(address'), 2)
        self.assertIn('build_policy_explanation(', self.main)

    def test_major_parent_surfaces_link_to_explanation(self):
        self.assertIn('/policy/explain/{{d.ip}}', self.index)
        self.assertIn('/policy/explain/{{row.ip}}', self.policy_summary)
        self.assertIn('/policy/explain/{{client_ip}}', self.activity_device)
        self.assertIn('/policy/explain/{{item.client_ip}}?service={{service.key}}', self.activity_service)

    def test_explanation_ui_names_all_decision_layers_and_evidence_boundary(self):
        for phrase in (
            'Device mode decision chain',
            'Service decisions',
            'Bandwidth decision',
            'Household mode',
            'Next automatic change',
            'Policy explainability is read-only',
            'not proof of foreground application use or browser history',
        ):
            self.assertIn(phrase, self.explain)

    def test_readme_documents_explainability_contract(self):
        self.assertIn('## Effective policy explainability', self.readme)
        self.assertIn('/api/policy/explain/<ip>', self.readme)
        self.assertIn('never creates, repairs or reorders RouterOS authority', self.readme)


if __name__ == "__main__":
    unittest.main()
