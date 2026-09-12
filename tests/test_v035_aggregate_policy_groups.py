import tempfile
import unittest
from pathlib import Path

from app.policy_quality import build_policy_quality_report
from app.policy_store import PolicyStore
from app.quota import bytes_for_mb


class AggregatePolicyGroupStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = PolicyStore(str(Path(self.tmp.name) / "policy.db"))
        self.ip = "192.168.2.55"

    def tearDown(self):
        self.tmp.cleanup()

    def _profile(self, blocked=(), quotas=None):
        profile = self.store.create_profile(
            "Child", "normal", "normal", "", blocked, 0, "blocked", quotas or {}
        )
        self.store.update_device(self.ip, alias="Tablet", profile_id=profile["id"])
        return profile

    @staticmethod
    def usage(**mb):
        return {
            "available": True,
            "day": "2026-09-09",
            "timezone": "Europe/London",
            "total_bytes": sum(bytes_for_mb(value) for value in mb.values()),
            "service_bytes": {key: bytes_for_mb(value) for key, value in mb.items()},
        }

    def test_default_groups_are_seeded_as_runtime_catalogue(self):
        groups = self.store.policy_group_catalog()
        self.assertIn("gaming", groups)
        self.assertIn("social_media", groups)
        self.assertTrue(groups["gaming"]["builtin"])
        self.assertIn("roblox", groups["gaming"]["members"])

    def test_custom_group_expands_to_concrete_services(self):
        group = self.store.create_policy_group("Streaming", "Video services", ["youtube", "netflix"])
        self.assertEqual("streaming", group["key"])
        self._profile([group["key"]])
        policy = self.store.compute_effective_policy(self.ip)
        self.assertEqual(["streaming"], policy["blocked_policy_groups"])
        self.assertEqual({"youtube", "netflix"}, set(policy["blocked_services"]))
        state = next(item for item in policy["policy_group_states"] if item["key"] == "streaming")
        self.assertTrue(state["requested"])
        self.assertTrue(state["fully_blocked"])

    def test_rename_keeps_stable_key_and_membership_update_changes_effective_policy(self):
        group = self.store.create_policy_group("Streaming", "", ["youtube", "netflix"])
        profile = self._profile([group["key"]])
        updated = self.store.update_policy_group(group["key"], "Video streaming", "Renamed", ["youtube", "bbc_iplayer"])
        self.assertEqual("streaming", updated["key"])
        self.assertEqual("Video streaming", updated["name"])
        self.assertEqual(["streaming"], self.store.get_profile(profile["id"])["blocked_services"])
        policy = self.store.compute_effective_policy(self.ip)
        self.assertEqual({"youtube", "bbc_iplayer"}, set(policy["blocked_services"]))

    def test_nested_aggregate_groups_are_rejected(self):
        group = self.store.create_policy_group("Streaming", "", ["youtube"])
        with self.assertRaisesRegex(ValueError, "cannot contain other aggregate groups"):
            self.store.create_policy_group("Everything", "", [group["key"], "netflix"])

    def test_safe_delete_refuses_live_references_and_builtin_delete(self):
        group = self.store.create_policy_group("Streaming", "", ["youtube", "netflix"])
        profile = self._profile([group["key"]])
        usage = self.store.policy_group_usage(group["key"])
        self.assertTrue(usage["in_use"])
        self.assertEqual(1, len(usage["profiles"]))
        with self.assertRaisesRegex(ValueError, "still referenced"):
            self.store.delete_policy_group(group["key"])
        self.store.update_profile(profile["id"], "Child", "normal", "normal", "", [])
        self.store.delete_policy_group(group["key"])
        self.assertNotIn(group["key"], self.store.policy_group_catalog())
        with self.assertRaisesRegex(ValueError, "Built-in"):
            self.store.delete_policy_group("gaming")

    def test_dynamic_group_service_schedule_is_live_policy_input(self):
        group = self.store.create_policy_group("Streaming", "", ["youtube", "netflix"])
        self._profile([])
        self.store.create_schedule_plan(
            "Streaming bedtime", "device", self.ip, "service", f"{group['key']}:block",
            "18:00", ["wed"],
        )
        policy = self.store.compute_effective_policy(self.ip, at="2026-09-09T19:00:00+01:00")
        self.assertEqual({"youtube", "netflix"}, set(policy["blocked_services"]))
        self.assertEqual("streaming", policy["scheduled_service_overrides"][0]["service"])
        self.assertTrue(policy["scheduled_service_overrides"][0]["policy_group"])

    def test_dynamic_group_quota_sums_member_telemetry(self):
        group = self.store.create_policy_group("Streaming", "", ["youtube", "netflix"])
        self._profile([], {group["key"]: 100})
        self.store.save_quota_settings("1", "80")
        policy = self.store.compute_effective_policy(
            self.ip, quota_usage=self.usage(youtube=60, netflix=40)
        )
        self.assertEqual({"youtube", "netflix"}, set(policy["blocked_services"]))
        entry = next(item for item in policy["quota_state"]["services"] if item["key"] == "streaming")
        self.assertEqual("group", entry["kind"])
        self.assertEqual("Streaming", entry["name"])
        self.assertTrue(entry["exhausted"])

    def test_backup_restore_preserves_custom_group_key_and_profile_reference(self):
        group = self.store.create_policy_group("Streaming", "", ["youtube", "netflix"])
        self._profile([group["key"]])
        payload = self.store.export_config()
        other = PolicyStore(str(Path(self.tmp.name) / "restored.db"))
        other.import_config(payload)
        self.assertIn("streaming", other.policy_group_catalog())
        profile = next(item for item in other.list_profiles() if item["name"] == "Child")
        self.assertEqual(["streaming"], profile["blocked_services"])

    def test_custom_service_cannot_be_deleted_while_aggregate_member(self):
        self.store.save_service("minecraft", "Minecraft", dns_suffixes=["minecraft.net"])
        self.store.create_policy_group("Games 2", "", ["minecraft"])
        with self.assertRaisesRegex(ValueError, "aggregate policy group"):
            self.store.delete_service("minecraft")


class AggregatePolicyGroupQualityTests(unittest.TestCase):
    def test_reporting_only_member_is_visible_as_warning(self):
        report = build_policy_quality_report(
            profiles=[], devices={}, schedules=[], date_exceptions=[], service_groups=[],
            services=[{"key": "minecraft", "name": "Minecraft", "builtin": 0, "enforcement_approved": False}],
            settings={"quota_engine_enabled": "1"},
            policy_groups={"games_2": {"name": "Games 2", "members": ["minecraft"], "builtin": False}},
        )
        finding = next(item for item in report["findings"] if "reporting-only services" in item["title"])
        self.assertEqual("warning", finding["category"])
        self.assertIn("policy-group:games_2", finding["link"])


class AggregatePolicyGroupUxAndDefectTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[1]
        cls.main = (cls.root / "app/main.py").read_text()
        cls.store = (cls.root / "app/policy_store.py").read_text()
        cls.index = (cls.root / "app/templates/index.html").read_text()
        cls.history = (cls.root / "app/templates/policy_history.html").read_text()
        cls.css = (cls.root / "app/static/app.css").read_text()

    def test_crud_routes_and_audit_events_are_wired(self):
        for route in (
            '@app.post("/local/policy-groups/add")',
            '@app.post("/local/policy-groups/update")',
            '@app.post("/local/policy-groups/delete")',
        ):
            self.assertIn(route, self.main)
        for event in (
            "AGGREGATE_POLICY_GROUP_CREATED",
            "AGGREGATE_POLICY_GROUP_UPDATED",
            "AGGREGATE_POLICY_GROUP_DELETED",
        ):
            self.assertIn(event, self.main)

    def test_ui_distinguishes_live_groups_from_authoring_collections(self):
        self.assertIn("Aggregate policy groups", self.index)
        self.assertIn("Reusable service collections", self.index)
        self.assertIn("stable machine key", self.index)
        self.assertIn("never receives its own RouterOS firewall authority", self.index)
        self.assertIn('action="/local/policy-groups/update"', self.index)
        self.assertIn('action="/local/policy-groups/add"', self.index)

    def test_delete_is_dependency_gated_and_builtin_keys_are_retained(self):
        self.assertIn("Remove references first", self.index)
        self.assertIn("Built-in stable key retained for compatibility", self.index)
        self.assertIn("policy_group_usage", self.main)
        self.assertIn("Built-in aggregate policy groups cannot be deleted", self.store)

    def test_policy_correlation_selector_uses_name_then_ip_and_never_ip_ip(self):
        self.assertIn("_policy_correlation_managed_names", self.main)
        self.assertIn("cfg.get(\"alias\") or activity_names.get(ip)", self.main)
        self.assertIn("{% if name %}{{name}} ({{ip}}){% else %}{{ip}}{% endif %}", self.history)
        self.assertNotIn("{{name}} ({{ip}})</option>", self.history)

    def test_group_ui_is_dense_and_tablet_responsive(self):
        self.assertIn(".aggregate-group-title-row", self.css)
        self.assertIn("@media(max-width:760px)", self.css)
        self.assertIn(".aggregate-group-usage", self.css)

    def test_no_aggregate_routeros_authority_is_introduced(self):
        aggregate_section = self.main[self.main.index('@app.post("/local/policy-groups/add")'):self.main.index('@app.post("/local/service-groups/add")')]
        self.assertNotIn("router.", aggregate_section)
        self.assertNotIn("MC_Block_", aggregate_section)
        self.assertNotIn("provision", aggregate_section.lower())


if __name__ == "__main__":
    unittest.main()
