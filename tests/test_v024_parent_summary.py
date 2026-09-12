import sys
import types
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Keep host-side validation independent of psycopg installation.
psycopg = types.ModuleType("psycopg")
psycopg.Error = Exception
psycopg.connect = None
rows = types.ModuleType("psycopg.rows")
rows.dict_row = object()
sys.modules.setdefault("psycopg", psycopg)
sys.modules.setdefault("psycopg.rows", rows)

from app.activity import ActivityStore
from app.parent_summary import (
    build_parent_device_summary,
    merge_attention_domains,
    summarize_parent_household,
)

ROOT = Path(__file__).resolve().parents[1]


class ParentSummaryCompositionTests(unittest.TestCase):
    def test_attention_domains_merge_new_blocked_and_unclassified_evidence(self):
        rows = merge_attention_domains(
            [{"domain": "Example.TEST", "service": "", "queries": 4, "blocked": 1}],
            [{"domain": "example.test", "service": "", "queries": 3, "blocked": 3}],
        )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["domain"], "example.test")
        self.assertEqual(rows[0]["blocked"], 3)
        self.assertEqual(rows[0]["tags"], ["blocked", "new", "unclassified"])

    def test_device_summary_uses_evidence_categories_not_risk_score(self):
        result = build_parent_device_summary(
            ip="192.168.2.20", name="Tablet", profile_name="Kids",
            current={"total_bytes": 1000, "dns_queries": 20, "dns_blocked": 2},
            previous={"total_bytes": 500, "dns_queries": 10, "dns_blocked": 0},
            services=[],
            new_domains=[{"domain": "new.example", "service": "", "queries": 1, "blocked": 0}],
            blocked_domains=[], quota={}, quota_current=False,
        )
        self.assertEqual(result["comparison"]["total_bytes"]["delta_percent"], 100.0)
        self.assertIn("blocked_dns", result["signals"])
        self.assertIn("new_domains", result["signals"])
        self.assertIn("unclassified_new", result["signals"])
        self.assertNotIn("risk", result)
        self.assertNotIn("score", result)

    def test_historical_summary_does_not_backdate_current_quota_config(self):
        quota = {
            "configured": True,
            "daily": {"warning": True, "exhausted": True},
            "services": [],
        }
        result = build_parent_device_summary(
            ip="192.168.2.20", name="Tablet", profile_name="Kids",
            current={}, previous={}, services=[], new_domains=[], blocked_domains=[],
            quota=quota, quota_current=False,
        )
        self.assertFalse(result["quota_warning"])
        self.assertFalse(result["quota_exhausted"])
        self.assertNotIn("quota_warning", result["signals"])

    def test_current_quota_warning_and_exhaustion_are_explicit_signals(self):
        quota = {
            "configured": True,
            "daily": {"warning": True, "exhausted": False},
            "services": [{"warning": True, "exhausted": True}],
        }
        result = build_parent_device_summary(
            ip="192.168.2.20", name="Tablet", profile_name="Kids",
            current={}, previous={}, services=[], new_domains=[], blocked_domains=[],
            quota=quota, quota_current=True,
        )
        self.assertTrue(result["quota_warning"])
        self.assertTrue(result["quota_exhausted"])
        self.assertIn("quota_exhausted", result["signals"])

    def test_household_counts_unique_domain_names_across_devices(self):
        common = {"domain": "same.example", "service": "", "queries": 1, "blocked": 0}
        device_a = build_parent_device_summary(
            ip="192.168.2.20", name="A", profile_name="Kids",
            current={"total_bytes": 100}, previous={"total_bytes": 50}, services=[],
            new_domains=[common], blocked_domains=[], quota={}, quota_current=False,
        )
        device_b = build_parent_device_summary(
            ip="192.168.2.21", name="B", profile_name="Kids",
            current={"total_bytes": 200}, previous={"total_bytes": 100}, services=[],
            new_domains=[common], blocked_domains=[], quota={}, quota_current=False,
        )
        household = summarize_parent_household([device_a, device_b])
        self.assertEqual(household["current"]["total_bytes"], 300)
        self.assertEqual(household["new_domains"], 1)
        self.assertEqual(household["unclassified_new_domains"], 1)
        self.assertEqual(household["active_devices"], 2)


class FakeActivityStore(ActivityStore):
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def _query(self, sql, params=()):
        self.calls.append((sql, params))
        return self.responses.pop(0)


class ParentSummaryActivityStoreTests(unittest.TestCase):
    def test_blocked_domain_query_is_explicitly_blocked_only_and_bounded(self):
        now = datetime(2026, 9, 9, tzinfo=timezone.utc)
        store = FakeActivityStore([[
            {
                "domain": "blocked.example", "service": "Example", "queries": 7,
                "blocked": 7, "devices": 1, "first_seen": now, "last_seen": now,
            }
        ]])
        rows = store.blocked_domains_range(now, now + timedelta(hours=1), 999, "192.168.2.20")
        self.assertEqual(rows[0]["blocked"], 7)
        self.assertEqual(rows[0]["last_seen"], now.isoformat())
        sql, params = store.calls[0]
        self.assertIn("AND blocked", sql)
        self.assertIn("ORDER BY blocked DESC", sql)
        self.assertEqual(params[-1], 200)


class ParentSummaryUxTests(unittest.TestCase):
    def setUp(self):
        self.index = (ROOT / "app/templates/index.html").read_text()
        self.summary = (ROOT / "app/templates/activity_summary.html").read_text()
        self.main = (ROOT / "app/main.py").read_text()
        self.css = (ROOT / "app/static/parent-summary.css").read_text()
        self.readme = (ROOT / "README.md").read_text() + "\n" + (ROOT / "CHANGELOG.md").read_text()

    def test_release_version_and_summary_subtab_are_present(self):
        self.assertIn('version="0.53.1"', self.main)
        self.assertIn("key: 'summaries', label: 'Summaries'", self.index)
        self.assertIn('data-ux-group="summaries"', self.index)

    def test_summary_routes_and_daily_controls_exist(self):
        self.assertIn('@app.get("/api/activity/summary")', self.main)
        self.assertIn('@app.get("/activity/summary"', self.main)
        self.assertIn('Today summary', self.index)
        self.assertIn('Yesterday summary', self.index)
        self.assertIn('New / blocked DNS attention', self.summary)
        self.assertIn('Quota warnings', self.summary)

    def test_summary_states_evidence_boundary_and_no_risk_scoring(self):
        self.assertIn('not browser history, foreground-app time or proof of who used a device', self.main)
        self.assertIn('evidence categories, not risk', self.summary)
        self.assertIn('does not assign an opaque risk score', self.readme)

    def test_summary_ui_remains_dense_and_mobile_usable(self):
        self.assertIn('.parent-device-grid{display:grid', self.css)
        self.assertIn('grid-template-columns:repeat(2,minmax(0,1fr))', self.css)
        self.assertIn('@media(max-width:600px)', self.css)
        self.assertIn('padding:7px', self.css)


if __name__ == "__main__":
    unittest.main()
