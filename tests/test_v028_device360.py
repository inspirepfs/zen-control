from pathlib import Path
import sys
import types
import unittest

# Keep host-side validation independent of psycopg installation.
psycopg = types.ModuleType("psycopg")
psycopg.Error = Exception
psycopg.connect = None
rows = types.ModuleType("psycopg.rows")
rows.dict_row = object()
sys.modules.setdefault("psycopg", psycopg)
sys.modules.setdefault("psycopg.rows", rows)

from app.device360 import (
    build_device_360_snapshot,
    filter_related_records,
    record_mentions_device,
)


ROOT = Path(__file__).resolve().parents[1]


class Device360CompositionTests(unittest.TestCase):
    def setUp(self):
        self.explanation = {
            "schema_version": "zen_policy_explanation_v1",
            "device": {
                "ip": "192.0.2.10",
                "name": "Tablet",
                "profile": "School Night",
                "category": "tablet",
            },
            "summary": {
                "headline": "Device mode is BLOCKED now; RouterOS matches.",
                "desired_mode": "blocked",
                "live_mode": "blocked",
                "global_mode": "normal",
                "effective_now": "blocked",
                "sync_status": "in_sync",
                "mode_source": "schedule: Bedtime",
                "temporary": False,
            },
            "services": [
                {
                    "key": "youtube", "name": "YouTube", "desired": "BLOCK",
                    "desired_blocked": True, "live": "BLOCK", "live_known": True,
                    "available": True, "drift": False, "source": "profile: School Night",
                },
                {
                    "key": "roblox", "name": "Roblox", "desired": "ALLOW",
                    "desired_blocked": False, "live": "BLOCK", "live_known": True,
                    "available": True, "drift": True, "source": "no active service block",
                },
                {
                    "key": "minecraft", "name": "Minecraft", "desired": "BLOCK REQUESTED",
                    "desired_blocked": False, "live": "NO CONTRACT", "live_known": True,
                    "available": False, "drift": False, "source": "configured service block",
                },
            ],
            "bandwidth": {
                "name": "Normal", "upload": "Unlimited", "download": "Unlimited"
            },
            "quota": {
                "configured": True, "enabled": True, "available": True,
                "daily": {"limit_mb": 1000, "percent": 42, "used_human": "420 MB"},
            },
            "next_changes": [{"when": "2026-09-10 07:00", "label": "Morning → normal"}],
            "limitations": ["Service evidence is not browser history."],
            "conflicts": [],
            "planned_actions": [],
            "links": {
                "device": "/?focus=device:192.0.2.10#devices/managed",
                "assignment": "/?focus=assignment:192.0.2.10#policies/assignments",
                "activity": "/activity/device/192.0.2.10",
                "history": "/activity/analytics?period=7d&client_ip=192.0.2.10",
            },
        }
        self.activity = {
            "window": {"label": "Today", "timezone": "Europe/London"},
            "current": {
                "total_bytes": 1000, "download_bytes": 800, "upload_bytes": 200,
                "total_bytes_human": "1000 B", "download_bytes_human": "800 B",
                "upload_bytes_human": "200 B", "attributed_bytes": 900,
                "attributed_bytes_human": "900 B", "attributed_percent": 90.0,
                "flows": 10, "dns_queries": 20, "dns_blocked": 2, "unique_domains": 8,
            },
            "previous": {
                "total_bytes": 500, "download_bytes": 400, "upload_bytes": 100,
                "flows": 5, "dns_queries": 10, "dns_blocked": 1, "unique_domains": 5,
            },
            "services": [{"service_name": "YouTube", "total_bytes": 700, "total_bytes_human": "700 B", "flows": 4}],
            "new_domains": [{"domain": "new.example", "queries": 3, "blocked": 0, "service": ""}],
            "blocked_domains": [{"domain": "blocked.example", "queries": 2, "blocked": 2, "service": ""}],
            "timeline": [{"event_time": "2026-09-09T18:30:00+00:00", "kind": "traffic", "service": "YouTube", "total_bytes_human": "700 B", "flows": 4}],
        }

    def build(self, **overrides):
        args = {
            "explanation": self.explanation,
            "reward_account": {"enabled": True, "balance_minutes": 30, "ledger": []},
            "activity": self.activity,
            "activity_error": None,
            "incidents": [
                {"status": "open", "severity": "warning", "title": "Tablet policy drift"},
                {"status": "resolved", "severity": "critical", "title": "Old issue"},
            ],
            "audit_events": [{"event": "DEVICE_POLICY_UPDATED", "detail": "ip=192.0.2.10"}],
        }
        args.update(overrides)
        return build_device_360_snapshot(**args)

    def test_contract_composes_existing_policy_without_new_decision_engine(self):
        result = self.build()
        self.assertEqual("zen_device_360_v1", result["schema_version"])
        self.assertEqual("blocked", result["summary"]["effective_now"])
        self.assertEqual(result["policy"], self.explanation)
        self.assertEqual(30, result["access"]["reward"]["balance_minutes"])
        self.assertEqual(1, result["incident_counts"]["active"])

    def test_service_counts_and_attention_prioritise_drift(self):
        result = self.build()
        self.assertEqual(3, result["service_counts"]["defined"])
        self.assertEqual(1, result["service_counts"]["blocked"])
        self.assertEqual(1, result["service_counts"]["drift"])
        self.assertEqual(1, result["service_counts"]["reporting_only"])
        self.assertEqual("roblox", result["service_attention"][0]["key"])

    def test_activity_comparison_is_composed_when_evidence_is_available(self):
        result = self.build()
        self.assertTrue(result["activity"]["available"])
        self.assertEqual(100.0, result["activity"]["comparison"]["total_bytes"]["delta_percent"])
        self.assertEqual("new.example", result["activity"]["new_domains"][0]["domain"])

    def test_telemetry_failure_is_unknown_not_zero_activity(self):
        result = self.build(activity={}, activity_error="PostgreSQL offline")
        self.assertFalse(result["activity"]["available"])
        self.assertIsNone(result["activity"]["current"])
        self.assertIsNone(result["activity"]["comparison"])
        self.assertIn("PostgreSQL offline", result["activity"]["error"])

    def test_contract_contains_no_behavioural_risk_score_or_write_callback(self):
        result = self.build()
        text = repr(result).lower()
        self.assertNotIn("risk_score", text)
        self.assertNotIn("set_device_mode", text)
        self.assertIn("not browser history", result["evidence_note"].lower())
        self.assertIn("proof of who used the device", result["evidence_note"].lower())


class Device360EvidenceMatchTests(unittest.TestCase):
    def test_explicit_ip_or_device_name_matches_related_records(self):
        self.assertTrue(record_mentions_device(
            {"detail": "policy drift ip=192.0.2.10"}, "192.0.2.10", "Tablet"
        ))
        self.assertTrue(record_mentions_device(
            {"title": "Tablet policy drift"}, "192.0.2.10", "Tablet"
        ))
        self.assertFalse(record_mentions_device(
            {"detail": "phone policy changed"}, "192.0.2.10", "Tablet"
        ))

    def test_filter_preserves_order_and_limit_without_fuzzy_matching(self):
        rows = [
            {"id": 1, "detail": "Tablet first"},
            {"id": 2, "detail": "unrelated"},
            {"id": 3, "detail": "192.0.2.10 second"},
        ]
        result = filter_related_records(rows, "192.0.2.10", "Tablet", limit=1)
        self.assertEqual([1], [row["id"] for row in result])


class Device360UxTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.main = (ROOT / "app/main.py").read_text()
        cls.template = (ROOT / "app/templates/device_360.html").read_text()
        cls.css = (ROOT / "app/static/device360.css").read_text()
        cls.index = (ROOT / "app/templates/index.html").read_text()
        cls.activity_device = (ROOT / "app/templates/activity_device.html").read_text()
        cls.activity_service = (ROOT / "app/templates/activity_service.html").read_text()
        cls.activity_summary = (ROOT / "app/templates/activity_summary.html").read_text()
        cls.policy_summary = (ROOT / "app/templates/policy_summary.html").read_text()
        cls.explain = (ROOT / "app/templates/policy_explain.html").read_text()
        cls.readme = (ROOT / "README.md").read_text() + "\n" + (ROOT / "CHANGELOG.md").read_text()

    def test_page_and_api_share_one_device_360_builder(self):
        self.assertIn('def get_device_360(address: str)', self.main)
        self.assertIn('@app.get("/devices/{address}", response_class=HTMLResponse)', self.main)
        self.assertIn('@app.get("/api/devices/{address}/360")', self.main)
        self.assertGreaterEqual(self.main.count('get_device_360(address)'), 2)

    def test_device_360_is_dense_read_only_and_names_connected_features(self):
        for phrase in (
            "Device overview", "Policy &amp; enforcement", "Access, reward &amp; quota",
            "Service policy", "Today’s activity", "DNS attention",
            "Related incidents", "Recent audit evidence", "Evidence limits",
        ):
            self.assertIn(phrase, self.template)
        self.assertNotIn("<form", self.template)
        self.assertIn("Telemetry unavailable", self.template)
        self.assertIn("does not turn missing telemetry into zero activity", self.template)

    def test_major_device_surfaces_link_to_device_360(self):
        self.assertIn('/devices/{{d.ip}}', self.index)
        self.assertIn('/devices/{{row.ip}}', self.policy_summary)
        self.assertIn('/devices/{{client_ip}}', self.activity_device)
        self.assertIn('/devices/{{item.client_ip}}', self.activity_service)
        self.assertIn('/devices/{{device.ip}}', self.activity_summary)
        self.assertIn('/devices/{{explanation.device.ip}}', self.explain)

    def test_release_is_v028_and_new_asset_is_cache_busted(self):
        self.assertIn('version="0.54.0"', self.main)
        self.assertIn('/static/device360.css?v=0.54.0', self.template)
        self.assertIn('/static/app.css?v=0.54.0', self.index)
        self.assertNotIn('v=0.27.0', self.template)

    def test_device_360_css_has_compact_responsive_breakpoints(self):
        self.assertIn('.device360-kpis', self.css)
        self.assertIn('@media(max-width:760px)', self.css)
        self.assertIn('@media(max-width:460px)', self.css)

    def test_readme_documents_read_only_contract_and_api(self):
        self.assertIn('## Device 360', self.readme)
        self.assertIn('/api/devices/<ip>/360', self.readme)
        self.assertIn('zen_device_360_v1', self.readme)
        self.assertIn('Device 360 is read-only', self.readme)


if __name__ == "__main__":
    unittest.main()
