import sys
import types
import unittest
from datetime import datetime

# Unit-test the quota-day window without requiring the PostgreSQL client package
# in the host-side patch validation environment. The production image installs
# psycopg from requirements.txt.
psycopg = types.ModuleType("psycopg")
psycopg.Error = Exception
psycopg.connect = None
rows = types.ModuleType("psycopg.rows")
rows.dict_row = object()
sys.modules.setdefault("psycopg", psycopg)
sys.modules.setdefault("psycopg.rows", rows)

from app.activity import ActivityStore


class FakeActivityStore(ActivityStore):
    def __init__(self):
        self.calls = []

    def _query(self, sql, params=()):
        self.calls.append((sql, params))
        if "GROUP BY service_name" in sql:
            return [
                {"service_name": "YouTube", "total_bytes": 1234, "flows": 3},
                {"service_name": "Other", "total_bytes": 50, "flows": 1},
            ]
        return [{
            "total_bytes": 1284,
            "download_bytes": 1200,
            "upload_bytes": 84,
            "flows": 4,
            "latest_bucket": datetime.fromisoformat("2026-10-25T11:55:00+00:00"),
        }]


class ActivityQuotaWindowTests(unittest.TestCase):
    def test_daily_usage_uses_policy_midnight_and_dst(self):
        store = FakeActivityStore()
        result = store.daily_usage(
            "192.168.2.22",
            "Europe/London",
            at="2026-10-25T12:00:00+00:00",
        )
        self.assertEqual(result["day"], "2026-10-25")
        self.assertEqual(result["total_bytes"], 1284)
        self.assertEqual(result["service_bytes"]["YouTube"], 1234)

        start_utc = store.calls[0][1][1]
        end_utc = store.calls[0][1][2]
        # DST ends on this date: one local quota day is 25 real hours.
        self.assertEqual((end_utc - start_utc).total_seconds(), 25 * 3600)
        self.assertEqual(start_utc.isoformat(), "2026-10-24T23:00:00+00:00")
        self.assertEqual(end_utc.isoformat(), "2026-10-26T00:00:00+00:00")


if __name__ == "__main__":
    unittest.main()
