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


class ServiceStatisticsTests(unittest.TestCase):
    def test_statistics_bucket_by_service_category_reconciles_raw_samples(self):
        start = datetime(2026, 9, 1, tzinfo=timezone.utc)
        end = start + timedelta(hours=1)
        store = FakeActivityStore([
            [{
                "bucket": start, "category": "video", "service": "YouTube",
                "download_bytes": 800, "upload_bytes": 200, "flows": 3,
                "active_clients": 2,
            }],
            [{"download_bytes": 800, "upload_bytes": 200, "flows": 3, "active_clients": 2}],
        ])

        result = store.service_statistics(start, end, bucket_minutes=15)

        self.assertEqual(result["start"], start.isoformat())
        self.assertEqual(result["end"], end.isoformat())
        self.assertEqual(result["bucket_minutes"], 15)
        self.assertEqual(result["buckets"][0]["category"], "video")
        self.assertEqual(result["buckets"][0]["download_bytes"], 800)
        self.assertEqual(result["buckets"][0]["upload_bytes"], 200)
        self.assertEqual(result["totals"], {
            "download_bytes": 800, "upload_bytes": 200, "flows": 3, "active_clients": 2,
        })
        self.assertIn("flows_raw", store.calls[0][0])
        self.assertIn("date_bin", store.calls[0][0])
        self.assertEqual(store.calls[0][1], (start, end))

    def test_empty_range_returns_zero_totals_and_no_buckets(self):
        start = datetime(2026, 9, 1, tzinfo=timezone.utc)
        store = FakeActivityStore([
            [],
            [{"download_bytes": 0, "upload_bytes": 0, "flows": 0, "active_clients": 0}],
        ])

        result = store.service_statistics(start, start + timedelta(minutes=5))

        self.assertEqual(result["buckets"], [])
        self.assertEqual(result["totals"], {
            "download_bytes": 0, "upload_bytes": 0, "flows": 0, "active_clients": 0,
        })

    def test_statistics_requires_valid_time_range_and_bucket_size(self):
        start = datetime(2026, 9, 1, tzinfo=timezone.utc)
        store = FakeActivityStore([])
        with self.assertRaises(ValueError):
            store.service_statistics(start, start, 5)
        with self.assertRaises(ValueError):
            store.service_statistics(start, start + timedelta(minutes=5), 0)


if __name__ == "__main__":
    unittest.main()
