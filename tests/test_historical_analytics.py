import sys
import types
import unittest
from datetime import datetime, timedelta, timezone, date
from pathlib import Path

# Keep host-side validation independent of psycopg installation.
psycopg = types.ModuleType("psycopg")
psycopg.Error = Exception
psycopg.connect = None
rows = types.ModuleType("psycopg.rows")
rows.dict_row = object()
sys.modules.setdefault("psycopg", psycopg)
sys.modules.setdefault("psycopg.rows", rows)

from app.activity import ActivityStore, compare_activity_totals, resolve_activity_window

ROOT = Path(__file__).resolve().parents[1]


class ActivityWindowTests(unittest.TestCase):
    def test_today_uses_policy_timezone_and_equal_previous_window(self):
        now = datetime(2026, 9, 9, 12, 0, tzinfo=timezone.utc)
        window = resolve_activity_window("today", "Europe/London", now=now)
        self.assertEqual(window["label"], "Today")
        # September is BST, so local midnight is 23:00 UTC the previous day.
        self.assertEqual(window["start"], datetime(2026, 9, 8, 23, 0, tzinfo=timezone.utc))
        self.assertEqual(window["end"], now)
        self.assertEqual(window["end"] - window["start"], window["previous_end"] - window["previous_start"])

    def test_yesterday_is_complete_local_day(self):
        now = datetime(2026, 9, 9, 12, 0, tzinfo=timezone.utc)
        window = resolve_activity_window("yesterday", "Europe/London", now=now)
        self.assertEqual(window["start"], datetime(2026, 9, 7, 23, 0, tzinfo=timezone.utc))
        self.assertEqual(window["end"], datetime(2026, 9, 8, 23, 0, tzinfo=timezone.utc))

    def test_custom_range_is_inclusive_by_local_date_and_bounded(self):
        window = resolve_activity_window("custom", "Europe/London", "2026-09-01", "2026-09-03")
        self.assertEqual(window["start_date"], "2026-09-01")
        self.assertEqual(window["end_date"], "2026-09-03")
        with self.assertRaises(ValueError):
            resolve_activity_window("custom", "Europe/London", "2026-01-01", "2026-03-01")

    def test_compare_totals_handles_zero_baseline_without_fake_infinity(self):
        comparison = compare_activity_totals(
            {"total_bytes": 100, "dns_queries": 10},
            {"total_bytes": 0, "dns_queries": 5},
        )
        self.assertIsNone(comparison["total_bytes"]["delta_percent"])
        self.assertEqual(comparison["dns_queries"]["delta_percent"], 100.0)


class FakeActivityStore(ActivityStore):
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def _query(self, sql, params=()):
        self.calls.append((sql, params))
        return self.responses.pop(0)


class HistoricalStoreTests(unittest.TestCase):
    def test_overview_range_returns_stats_and_classification(self):
        store = FakeActivityStore([
            [{
                "total_bytes": 1000,
                "download_bytes": 800,
                "upload_bytes": 200,
                "attributed_bytes": 750,
                "flows": 12,
                "active_devices": 2,
                "observed_services": 3,
                "first_flow": None,
                "last_flow": None,
            }],
            [{"queries": 20, "blocked": 5, "unique_domains": 7, "first_dns": None, "last_dns": None}],
        ])
        start = datetime(2026, 9, 1, tzinfo=timezone.utc)
        end = start + timedelta(days=1)
        result = store.overview_range(start, end)
        self.assertEqual(result["total_bytes"], 1000)
        self.assertEqual(result["attributed_percent"], 75.0)
        self.assertEqual(result["dns_block_percent"], 25.0)
        self.assertEqual(len(store.calls), 2)

    def test_daily_history_merges_flow_and_dns_days(self):
        store = FakeActivityStore([
            [{
                "day": date(2026, 9, 1), "total_bytes": 1000, "download_bytes": 900,
                "upload_bytes": 100, "classified_bytes": 800, "flows": 10, "devices": 2,
            }],
            [{
                "day": date(2026, 9, 1), "dns_queries": 100, "dns_blocked": 5,
                "classified_queries": 90, "unique_domains": 30,
            }],
        ])
        start = datetime(2026, 9, 1, tzinfo=timezone.utc)
        end = start + timedelta(days=1)
        row = store.daily_history(start, end)[0]
        self.assertEqual(row["traffic_percent"], 80.0)
        self.assertEqual(row["dns_percent"], 90.0)
        self.assertEqual(row["dns_blocked"], 5)

    def test_active_periods_split_on_thirty_minute_gap(self):
        start = datetime(2026, 9, 1, tzinfo=timezone.utc)
        store = FakeActivityStore([[
            {"bucket": start, "total_bytes": 100, "flows": 1},
            {"bucket": start + timedelta(minutes=5), "total_bytes": 200, "flows": 2},
            {"bucket": start + timedelta(minutes=45), "total_bytes": 300, "flows": 3},
        ]])
        periods = store.active_periods("192.168.2.22", start, start + timedelta(hours=2))
        self.assertEqual(len(periods), 2)
        # Returned newest first.
        self.assertEqual(periods[0]["total_bytes"], 300)
        self.assertEqual(periods[1]["total_bytes"], 300)


class HistoricalAnalyticsUxTests(unittest.TestCase):
    def setUp(self):
        self.index = (ROOT / "app/templates/index.html").read_text()
        self.analytics = (ROOT / "app/templates/activity_analytics.html").read_text()
        self.main = (ROOT / "app/main.py").read_text()
        self.css = (ROOT / "app/static/historical-analytics.css").read_text()

    def test_version_and_history_subtab_are_present(self):
        self.assertIn('version="0.55.4"', self.main)
        self.assertIn("key: 'history', label: 'History'", self.index)
        self.assertIn('Historical analytics', self.index)

    def test_parent_drilldown_controls_exist(self):
        for phrase in (
            'Today', 'Yesterday', '7 days', '30 days', 'Custom start',
            'Daily trend', 'New domains', 'Activity timeline', 'Active periods',
        ):
            self.assertIn(phrase, self.analytics)
        self.assertIn('/api/activity/analytics', self.main)
        self.assertIn('/activity/analytics', self.main)

    def test_analytics_explains_evidence_boundary(self):
        self.assertIn('network evidence, not browser-history reconstruction', self.analytics)
        self.assertIn('.analytics-timeline', self.css)


if __name__ == "__main__":
    unittest.main()
