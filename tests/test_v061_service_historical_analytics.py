import sys
import types
import unittest
from datetime import datetime, timedelta, timezone

psycopg = types.ModuleType("psycopg")
psycopg.Error = Exception
psycopg.connect = None
rows = types.ModuleType("psycopg.rows")
rows.dict_row = object()
sys.modules.setdefault("psycopg", psycopg)
sys.modules.setdefault("psycopg.rows", rows)

from app.activity import ActivityError, ActivityStore


class Store(ActivityStore):
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def _query(self, sql, params=()):
        self.calls.append((sql, params))
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


class HistoricalServiceAnalyticsTests(unittest.TestCase):
    def test_equivalent_windows_reconcile_and_movers_share_six_bounded_queries(self):
        start = datetime(2026, 9, 8, tzinfo=timezone.utc)
        end = start + timedelta(days=1)
        store = Store([
            [{"service_name": "Video", "current_records": 2, "current_total_bytes": 30, "current_flows": 3, "current_active_devices": 1, "previous_records": 1, "previous_total_bytes": 10, "previous_flows": 1, "previous_active_devices": 1},
             {"service_name": "Chat", "current_records": 1, "current_total_bytes": 5, "current_flows": 1, "current_active_devices": 1, "previous_records": 1, "previous_total_bytes": 20, "previous_flows": 2, "previous_active_devices": 1}],
            [{"service_name": "Video", "current_records": 2, "current_dns_queries": 4, "current_dns_blocked": 0, "current_active_devices": 1, "current_domains": 2, "previous_records": 0, "previous_dns_queries": 0, "previous_dns_blocked": 0, "previous_active_devices": 0, "previous_domains": 0}],
            [], [],
            [{"service_name": "Video", "bucket": start, "records": 2, "total_bytes": 30, "flows": 3}],
            [{"service_name": "Video", "bucket": start, "records": 2, "dns_blocked": 0, "domains": 2}],
        ])
        result = store.service_historical_analytics(start, end, "UTC")
        video = next(item for item in result["services"] if item["service_name"] == "Video")
        self.assertEqual(6, len(store.calls))
        self.assertEqual(6, result["query_count"])
        self.assertEqual(20, video["comparison"]["total_bytes"]["delta"])
        self.assertEqual(200.0, video["comparison"]["total_bytes"]["delta_percent"])
        self.assertIsNone(video["comparison"]["dns_queries"]["delta_percent"])
        self.assertEqual("zero_when_proven", video["dns_blocked_evidence"])
        self.assertEqual("Video", result["movers"][0]["service_name"])
        self.assertTrue(all("bucket >= %s AND bucket < %s" in sql or "event_time >= %s AND event_time < %s" in sql for sql, _ in store.calls))

    def test_no_evidence_and_unavailable_are_never_rendered_as_zero(self):
        start = datetime(2026, 9, 8, tzinfo=timezone.utc)
        end = start + timedelta(hours=2)
        store = Store([[{"service_name": "Video", "current_records": 0, "previous_records": 0}], ActivityError("dns offline"), [], [], [], []])
        item = store.service_historical_analytics(start, end, "UTC", service_name="Video")["services"][0]
        self.assertEqual("no_evidence", item["traffic_evidence"]["current"])
        self.assertIsNone(item["current"]["total_bytes"])
        self.assertEqual("unavailable", item["dns_evidence"]["current"])
        self.assertIsNone(item["current"]["dns_queries"])

    def test_range_limit_and_timezone_day_trends_are_preserved(self):
        start = datetime(2026, 9, 1, tzinfo=timezone.utc)
        with self.assertRaisesRegex(ValueError, "limited to 32 days"):
            Store([]).service_historical_analytics(start, start + timedelta(days=33), "Europe/London")


if __name__ == "__main__":
    unittest.main()
