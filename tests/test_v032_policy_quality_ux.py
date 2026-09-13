import unittest
from pathlib import Path

from app.policy_groups import POLICY_GROUPS
from app.policy_quality import build_policy_quality_report


class PolicyQualityTests(unittest.TestCase):
    def report(self, **overrides):
        base = {
            "profiles": [
                {
                    "id": 1,
                    "name": "Child",
                    "desired_mode": "normal",
                    "bandwidth_preset": "normal",
                    "blocked_services": [],
                    "daily_quota_mb": 0,
                    "service_quotas": {},
                }
            ],
            "devices": {
                "192.168.2.20": {
                    "ip": "192.168.2.20",
                    "alias": "Tablet",
                    "profile_id": 1,
                    "mode_override": "inherit",
                }
            },
            "schedules": [],
            "date_exceptions": [],
            "service_groups": [],
            "services": [
                {"key": "youtube", "name": "YouTube", "builtin": 1, "enforcement_approved": False},
                {"key": "roblox", "name": "Roblox", "builtin": 1, "enforcement_approved": False},
                {"key": "steam", "name": "Steam", "builtin": 1, "enforcement_approved": False},
                {"key": "xbox", "name": "Xbox", "builtin": 1, "enforcement_approved": False},
                {"key": "playstation", "name": "PlayStation", "builtin": 1, "enforcement_approved": False},
                {"key": "tiktok", "name": "TikTok", "builtin": 1, "enforcement_approved": False},
                {"key": "discord", "name": "Discord", "builtin": 1, "enforcement_approved": False},
                {"key": "gaming", "name": "Gaming", "builtin": 1, "enforcement_approved": False},
            ],
            "settings": {"quota_engine_enabled": "1"},
            "policy_groups": POLICY_GROUPS,
        }
        base.update(overrides)
        return build_policy_quality_report(**base)

    def test_clean_configuration_has_no_findings(self):
        result = self.report()
        self.assertEqual(result["schema_version"], "zen_policy_quality_v1")
        self.assertEqual(result["state"], "clean")
        self.assertEqual(result["counts"]["total"], 0)

    def test_device_override_is_visible_as_deterministic_shadow(self):
        devices = {
            "192.168.2.20": {
                "ip": "192.168.2.20", "alias": "Tablet", "profile_id": 1,
                "mode_override": "blocked",
            }
        }
        result = self.report(devices=devices)
        finding = next(item for item in result["findings"] if "Device mode override" in item["title"])
        self.assertEqual(finding["category"], "shadow")
        self.assertIn("assignments", finding["link"])

    def test_group_plus_explicit_member_is_redundant(self):
        profiles = [{
            "id": 1, "name": "Child", "desired_mode": "normal", "bandwidth_preset": "normal",
            "blocked_services": ["gaming", "roblox"], "daily_quota_mb": 0, "service_quotas": {},
        }]
        result = self.report(profiles=profiles)
        finding = next(item for item in result["findings"] if "aggregate group" in item["title"])
        self.assertEqual(finding["category"], "redundant")
        self.assertIn("roblox", finding["evidence"][0])

    def test_reporting_only_custom_service_is_warning(self):
        profiles = [{
            "id": 1, "name": "Child", "desired_mode": "normal", "bandwidth_preset": "normal",
            "blocked_services": ["minecraft"], "daily_quota_mb": 0, "service_quotas": {},
        }]
        services = [{"key": "minecraft", "name": "Minecraft", "builtin": 0, "enforcement_approved": False}]
        result = self.report(profiles=profiles, services=services)
        finding = next(item for item in result["findings"] if "reporting-only" in item["title"])
        self.assertEqual(finding["category"], "warning")
        self.assertIn("service:minecraft", finding["link"])

    def test_configured_quota_with_disabled_engine_is_warning(self):
        profiles = [{
            "id": 1, "name": "Child", "desired_mode": "normal", "bandwidth_preset": "normal",
            "blocked_services": [], "daily_quota_mb": 1000, "service_quotas": {},
        }]
        result = self.report(profiles=profiles, settings={"quota_engine_enabled": "0"})
        finding = next(item for item in result["findings"] if "quota engine is disabled" in item["title"])
        self.assertEqual(finding["category"], "warning")
        self.assertIn("settings&section=policy", finding["link"])

    def test_profile_bandwidth_suspended_by_non_normal_base_mode_is_shadow(self):
        profiles = [{
            "id": 1, "name": "Child", "desired_mode": "slow", "bandwidth_preset": "homework",
            "blocked_services": [], "daily_quota_mb": 0, "service_quotas": {},
        }]
        result = self.report(profiles=profiles)
        finding = next(item for item in result["findings"] if "bandwidth is suspended" in item["title"])
        self.assertEqual(finding["category"], "shadow")

    def test_equal_precedence_contradictory_schedules_are_conflict(self):
        schedules = [
            {"id": 1, "label": "Bedtime", "enabled": True, "target_type": "device", "target_value": "192.168.2.20", "action_type": "mode", "action_value": "blocked", "clock_time": "20:00", "days": ["mon", "tue"]},
            {"id": 2, "label": "Homework", "enabled": True, "target_type": "device", "target_value": "192.168.2.20", "action_type": "mode", "action_value": "slow", "clock_time": "20:00", "days": ["tue"]},
        ]
        result = self.report(schedules=schedules)
        self.assertEqual(result["state"], "conflict")
        finding = next(item for item in result["findings"] if "Ambiguous schedules" in item["title"])
        self.assertEqual(finding["severity"], "critical")
        self.assertIn("tue", finding["evidence"][2])

    def test_more_specific_schedule_is_shadow_not_conflict(self):
        schedules = [
            {"id": 1, "label": "House bedtime", "enabled": True, "target_type": "all", "target_value": "", "action_type": "mode", "action_value": "blocked", "clock_time": "20:00", "days": ["tue"]},
            {"id": 2, "label": "Tablet exception", "enabled": True, "target_type": "device", "target_value": "192.168.2.20", "action_type": "mode", "action_value": "normal", "clock_time": "20:00", "days": ["tue"]},
        ]
        result = self.report(schedules=schedules)
        finding = next(item for item in result["findings"] if "overrides a broader schedule" in item["title"])
        self.assertEqual(finding["category"], "shadow")
        self.assertEqual(result["counts"]["conflict"], 0)

    def test_orphaned_schedule_targets_are_visible(self):
        schedules = [
            {"id": 1, "label": "Old profile", "enabled": True, "target_type": "profile", "target_value": "99", "action_type": "mode", "action_value": "blocked", "clock_time": "20:00", "days": ["mon"]},
            {"id": 2, "label": "Old phone", "enabled": True, "target_type": "device", "target_value": "192.168.2.99", "action_type": "mode", "action_value": "blocked", "clock_time": "21:00", "days": ["mon"]},
        ]
        result = self.report(schedules=schedules)
        categories = {item["title"]: item["category"] for item in result["findings"]}
        self.assertEqual(categories["Schedule targets a missing profile"], "warning")
        self.assertEqual(categories["Schedule targets an unmanaged device"], "unused")

    def test_date_exception_conflicts_and_missing_template_fail_visibly(self):
        exceptions = [
            {"id": 1, "label": "Holiday A", "target_type": "device", "target_value": "192.168.2.20", "start_date": "2026-12-20", "end_date": "2026-12-25", "mode": "blocked", "template_id": None, "template_name": None},
            {"id": 2, "label": "Holiday B", "target_type": "device", "target_value": "192.168.2.20", "start_date": "2026-12-24", "end_date": "2026-12-26", "mode": "normal", "template_id": None, "template_name": None},
            {"id": 3, "label": "Broken template", "target_type": "all", "target_value": "", "start_date": "2027-01-01", "end_date": "2027-01-02", "mode": "template", "template_id": 999, "template_name": None},
        ]
        result = self.report(date_exceptions=exceptions)
        titles = [item["title"] for item in result["findings"]]
        self.assertIn("Overlapping date exceptions have equal precedence", titles)
        self.assertIn("Date exception references a missing template", titles)

    def test_service_collection_empty_and_stale_members_are_visible(self):
        groups = [
            {"id": 1, "name": "Empty", "services": []},
            {"id": 2, "name": "Old set", "services": ["youtube", "removed_service"]},
        ]
        result = self.report(service_groups=groups)
        titles = {item["title"] for item in result["findings"]}
        self.assertIn("Reusable service collection is empty", titles)
        self.assertIn("Reusable service collection contains missing services", titles)

    def test_report_has_no_behavioural_or_risk_score(self):
        result = self.report()
        text = repr(result).lower()
        self.assertNotIn("risk_score", text)
        self.assertNotIn("confidence_score", text)
        self.assertIn("does not", result["evidence_note"].lower())


class V032UXIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[1]
        cls.main = (cls.root / "app/main.py").read_text()
        cls.index = (cls.root / "app/templates/index.html").read_text()
        cls.quality = (cls.root / "app/templates/policy_quality.html").read_text()
        cls.performance = (cls.root / "app/templates/performance.html").read_text()
        cls.css = (cls.root / "app/static/policy-quality.css").read_text()
        cls.layout = (cls.root / "app/static/layout.css").read_text()
        cls.readme = (cls.root / "README.md").read_text() + "\n" + (cls.root / "CHANGELOG.md").read_text()

    def test_v032_routes_are_local_read_only_and_expose_stable_api(self):
        self.assertIn('version="0.55.3.1"', self.main)
        self.assertIn('@app.get("/policy/quality"', self.main)
        self.assertIn('@app.get("/api/policy/quality")', self.main)
        helper = self.main.split('def _policy_quality_snapshot():', 1)[1].split('@app.get("/policy/quality"', 1)[0]
        self.assertNotIn("router.", helper)
        self.assertNotIn("get_live", helper)
        self.assertNotIn("update_", helper)

    def test_policy_tools_link_to_quality_workbench(self):
        self.assertIn('href="/policy/quality">Policy quality</a>', self.index)
        self.assertIn('href="/policy/simulate">What-if workbench</a>', self.index)

    def test_quality_page_is_compact_filterable_and_has_owner_links(self):
        self.assertIn('data-quality-filter="conflict"', self.quality)
        self.assertIn('data-quality-category="{{item.category}}"', self.quality)
        self.assertIn('href="{{item.link}}">Open owner</a>', self.quality)
        self.assertIn('Back to Policy tools', self.quality)
        self.assertNotIn('<form', self.quality.lower())
        self.assertIn('@media(max-width:600px)', self.css)

    def test_ux_sweep_removes_obsolete_performance_back_link(self):
        self.assertNotIn('/?section=settings:operations', self.performance)
        self.assertIn('/?view=settings&amp;section=operations#settings/operations', self.performance)

    def test_ux_sweep_preserves_exact_subsections_after_actions(self):
        self.assertIn('"policies/tools",\n        f"Service collection', self.main)
        self.assertGreaterEqual(self.main.count('"devices/managed",'), 3)

    def test_deep_focus_is_available_for_quality_owner_links(self):
        for token in ('profile:{{p.id}}', 'collection:{{group.id}}', 'exception:{{e.id}}', 'schedule:{{p.id}}'):
            self.assertIn(f'data-ux-focus="{token}"', self.index)

    def test_standalone_actions_wrap_for_tablet_and_mobile(self):
        self.assertIn('.activity-page-actions,.header-actions', self.layout)
        self.assertIn('@media(max-width:720px)', self.layout)

    def test_release_documentation_states_static_analysis_and_recurring_ux_pass(self):
        self.assertIn('Policy Conflict & Shadow Analysis (v0.32)', self.readme)
        self.assertIn('does not connect to RouterOS', self.readme)
        self.assertIn('recurring UX validation pass', self.readme)

    def test_all_template_asset_versions_are_current(self):
        for path in (self.root / "app/templates").glob("*.html"):
            text = path.read_text()
            self.assertNotIn("?v=0.31.0", text, path.name)
        self.assertIn('/static/policy-quality.css?v=0.55.3.1', self.quality)


if __name__ == "__main__":
    unittest.main()
