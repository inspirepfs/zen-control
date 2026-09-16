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


class AnalyticsSummaryTests(unittest.TestCase):
    def test_summary_has_ranked_categories_and_unclassified_share(self):
        start = datetime(2026, 9, 1, tzinfo=timezone.utc)
        end = start + timedelta(hours=1)
        store = FakeActivityStore([
            [
                {"category": "video", "total_bytes": 200, "download_bytes": 150, "upload_bytes": 50, "flows": 2, "active_clients": 1},
                {"category": "gaming", "total_bytes": 200, "download_bytes": 180, "upload_bytes": 20, "flows": 3, "active_clients": 2},
                {"category": "unknown", "total_bytes": 100, "download_bytes": 100, "upload_bytes": 0, "flows": 1, "active_clients": 1},
            ],
            [{"total_bytes": 500, "download_bytes": 430, "upload_bytes": 70, "flows": 6, "active_clients": 2}],
        ])

        result = store.analytics_summary(start, end, category_limit=2)

        self.assertEqual(result["totals"], {
            "total_bytes": 500, "download_bytes": 430, "upload_bytes": 70,
            "flows": 6, "active_clients": 2,
        })
        self.assertEqual([(row["rank"], row["category"], row["percent"]) for row in result["top_categories"]], [
            (1, "gaming", 40.0), (2, "video", 40.0),
        ])
        self.assertEqual(result["unclassified"], {
            "total_bytes": 100, "download_bytes": 100, "upload_bytes": 0,
            "flows": 1, "percent": 20.0,
        })
        self.assertIn("flows_raw", store.calls[0][0])
        self.assertEqual(store.calls[0][1], (start, end))

    def test_empty_summary_uses_zero_shares(self):
        start = datetime(2026, 9, 1, tzinfo=timezone.utc)
        store = FakeActivityStore([
            [],
            [{"total_bytes": 0, "download_bytes": 0, "upload_bytes": 0, "flows": 0, "active_clients": 0}],
        ])

        result = store.analytics_summary(start, start + timedelta(minutes=5))

        self.assertEqual(result["top_categories"], [])
        self.assertEqual(result["unclassified"]["percent"], 0.0)
        self.assertEqual(result["totals"]["total_bytes"], 0)


if __name__ == "__main__":
    unittest.main()
