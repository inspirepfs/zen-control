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

from app.activity import ActivityStore


class FakeActivityStore(ActivityStore):
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def _query(self, sql, params=()):
        self.calls.append((sql, params))
        return self.responses.pop(0)


class AnalyticsDrilldownTests(unittest.TestCase):
    def test_category_service_client_and_time_filters_reconcile(self):
        start = datetime(2026, 9, 1, tzinfo=timezone.utc)
        end = start + timedelta(hours=1)
        store = FakeActivityStore([
            [{"service": "YouTube", "total_bytes": 300, "download_bytes": 250, "upload_bytes": 50, "flows": 2, "active_clients": 1}],
            [{"client_ip": "192.0.2.10", "total_bytes": 300, "download_bytes": 250, "upload_bytes": 50, "flows": 2}],
            [{"bucket": start, "total_bytes": 300, "download_bytes": 250, "upload_bytes": 50, "flows": 2, "active_clients": 1}],
            [{"total_bytes": 300, "download_bytes": 250, "upload_bytes": 50, "flows": 2, "active_clients": 1}],
        ])

        result = store.analytics_drilldown(start, end, " Video ", "youtube", "192.0.2.10", 15)

        self.assertEqual(result["filters"], {"category": "video", "service": "youtube", "client_ip": "192.0.2.10"})
        self.assertEqual(result["totals"]["total_bytes"], 300)
        self.assertEqual(sum(row["total_bytes"] for row in result["services"]), result["totals"]["total_bytes"])
        self.assertEqual(sum(row["total_bytes"] for row in result["clients"]), result["totals"]["total_bytes"])
        self.assertEqual(sum(row["total_bytes"] for row in result["buckets"]), result["totals"]["total_bytes"])
        expected_params = (start, end, "video", "youtube", "192.0.2.10")
        self.assertTrue(all(params == expected_params for _, params in store.calls))
        self.assertTrue(all("flows_raw" in sql and "event_time >= %s" in sql for sql, _ in store.calls))

    def test_absent_or_unsupported_filter_returns_safe_empty_result(self):
        start = datetime(2026, 9, 1, tzinfo=timezone.utc)
        end = start + timedelta(hours=1)
        absent = FakeActivityStore([[], [], [], [{"total_bytes": 0, "download_bytes": 0, "upload_bytes": 0, "flows": 0, "active_clients": 0}]])

        result = absent.analytics_drilldown(start, end, "not-a-category")

        self.assertEqual(result["services"], [])
        self.assertEqual(result["clients"], [])
        self.assertEqual(result["buckets"], [])
        self.assertEqual(result["totals"]["total_bytes"], 0)

        unsupported = FakeActivityStore([]).analytics_drilldown(start, end, client_ip="not-an-ip")
        self.assertEqual(unsupported["totals"]["total_bytes"], 0)
        self.assertEqual(unsupported["services"], [])


if __name__ == "__main__":
    unittest.main()
