import sys
import types
import unittest
from pathlib import Path

# Keep host-side validation independent of whether psycopg is installed.
psycopg = types.ModuleType("psycopg")
psycopg.Error = Exception
psycopg.connect = None
rows = types.ModuleType("psycopg.rows")
rows.dict_row = object()
sys.modules.setdefault("psycopg", psycopg)
sys.modules.setdefault("psycopg.rows", rows)

from app.activity import build_policy_service_activity

ROOT = Path(__file__).resolve().parents[1]


class PolicyServiceActivityTests(unittest.TestCase):
    def test_live_policy_catalog_is_dynamic(self):
        service_defs = [
            {"key": "youtube", "name": "YouTube", "builtin": 1},
            {"key": "minecraft", "name": "Minecraft", "builtin": 0},
        ]
        observed = [
            {"service_name": "YouTube", "total_bytes": 1000, "flows": 4},
        ]
        result = build_policy_service_activity(service_defs, observed)
        by_key = {row["key"]: row for row in result if row["key"]}
        self.assertTrue(by_key["youtube"]["observed"])
        self.assertEqual(by_key["youtube"]["total_bytes"], 1000)
        self.assertIn("minecraft", by_key)
        self.assertFalse(by_key["minecraft"]["observed"])
        self.assertEqual(by_key["minecraft"]["kind"], "custom")

    def test_matching_accepts_policy_key_or_display_name(self):
        service_defs = [{"key": "prime_video", "name": "Prime Video", "builtin": 1}]
        observed = [{"service_name": "prime-video", "total_bytes": 2048, "flows": 2}]
        row = build_policy_service_activity(service_defs, observed)[0]
        self.assertTrue(row["observed"])
        self.assertEqual(row["total_bytes"], 2048)

    def test_logical_group_aggregates_concrete_members(self):
        defs = [
            {"key": "gaming", "name": "Gaming", "builtin": 1},
            {"key": "roblox", "name": "Roblox", "builtin": 1},
            {"key": "steam", "name": "Steam", "builtin": 1},
        ]
        groups = {"gaming": {"members": ("roblox", "steam")}}
        observed = [
            {"service_name": "Roblox", "total_bytes": 100, "flows": 1},
            {"service_name": "Steam", "total_bytes": 300, "flows": 3},
        ]
        result = build_policy_service_activity(defs, observed, groups)
        gaming = next(row for row in result if row["key"] == "gaming")
        self.assertEqual(gaming["kind"], "group")
        self.assertEqual(gaming["total_bytes"], 400)
        self.assertEqual(gaming["flows"], 4)

    def test_profile_policy_is_shown_with_service_activity(self):
        defs = [{"key": "youtube", "name": "YouTube", "builtin": 1}]
        profiles = [
            {"name": "Kids", "blocked_services": ["youtube"]},
            {"name": "Parents", "blocked_services": []},
        ]
        row = build_policy_service_activity(defs, [], profiles=profiles)[0]
        self.assertEqual(row["blocked_by_profiles"], ["Kids"])

    def test_unmapped_telemetry_remains_visible_without_becoming_policy(self):
        result = build_policy_service_activity(
            [{"key": "youtube", "name": "YouTube", "builtin": 1}],
            [{"service_name": "Mystery App", "total_bytes": 500, "flows": 2}],
        )
        mystery = next(row for row in result if row["name"] == "Mystery App")
        self.assertFalse(mystery["policy_tracked"])
        self.assertEqual(mystery["kind"], "observed")


class ActivityUxTests(unittest.TestCase):
    def setUp(self):
        self.index = (ROOT / "app/templates/index.html").read_text()
        self.device = (ROOT / "app/templates/activity_device.html").read_text()
        self.css = (ROOT / "app/static/activity.css").read_text()
        self.main = (ROOT / "app/main.py").read_text()

    def test_version_and_activity_stylesheet(self):
        self.assertIn('version="0.54.5.1"', self.main)
        self.assertIn('/static/activity.css?v=0.54.5.1', self.index)

    def test_managed_activity_uses_name_and_ip(self):
        self.assertIn('{{d.display_name}}', self.index)
        self.assertIn('({{d.client_ip}})', self.index)
        self.assertIn('MANAGED', self.index)

    def test_device_rows_expand_for_parent_detail(self):
        self.assertIn('class="activity-device-card"', self.index)
        self.assertIn('Top services', self.index)
        self.assertIn('Top DNS names', self.index)
        self.assertIn('Current detail', self.index)
        self.assertIn('7-day history', self.index)

    def test_dns_view_is_larger_and_requests_more_rows(self):
        self.assertIn('dns_top_domains(24, 30)', self.main)
        self.assertIn('The 30 most requested DNS names', self.index)
        self.assertIn('.dns-table-large', self.css)
        self.assertIn('font-size:.81rem', self.css)

    def test_policy_services_drive_activity_view(self):
        self.assertIn('build_policy_service_activity', self.main)
        self.assertIn('Service intelligence', self.index)
        self.assertIn('Every current Policy', self.index)
        self.assertIn('Custom services are published dynamically', self.index)

    def test_telemetry_consumers_are_extended_to_insights(self):
        self.assertIn('Telemetry consumers &amp; insights', self.index)
        for phrase in (
            'Policy services', 'Managed devices seen', 'Attributed traffic',
            'DNS blocked', 'Historical correlation'
        ):
            self.assertIn(phrase, self.index)

    def test_incident_density_overlay_is_present(self):
        self.assertIn('.incident-hero-card{padding:6px 7px!important}', self.css)
        self.assertIn('.incident-card{padding:5px 6px!important', self.css)
        self.assertIn('.incident-monitor-strip', self.css)

    def test_full_device_page_carries_managed_identity_and_policy_services(self):
        self.assertIn('{{device_label or client_ip}}', self.device)
        self.assertIn('Policy service activity', self.device)
        self.assertIn('policy_services', self.main)


if __name__ == "__main__":
    unittest.main()
