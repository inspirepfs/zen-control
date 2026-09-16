import ast
import sys
import types
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
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


class ServiceHistoricalDrilldownRegressionTests(unittest.TestCase):
    def test_store_reconciles_explicit_range_and_client_to_retained_queries(self):
        start = datetime(2026, 9, 1, tzinfo=timezone.utc)
        end = start + timedelta(hours=6)
        store = FakeActivityStore([
            [{"total_bytes": 0, "flows": 0, "devices": 0, "first_seen": None, "last_seen": None}],
            [{"queries": 0, "blocked": 0, "dns_devices": 0, "domains": 0, "dns_first_seen": None, "dns_last_seen": None}],
            [], [], [],
        ])

        store.service_detail("YouTube", start=start, end=end, client_ip="192.0.2.10")

        expected = (start, end, "YouTube", "192.0.2.10")
        self.assertTrue(all(params == expected for _, params in store.calls))
        self.assertTrue(all("now()" not in sql for sql, _ in store.calls))
        self.assertTrue(all("client_ip=%s" in sql for sql, _ in store.calls))

    def test_store_rejects_oversized_explicit_range_without_clamping(self):
        start = datetime(2026, 8, 1, tzinfo=timezone.utc)
        with self.assertRaisesRegex(ValueError, "limited to 32 days"):
            FakeActivityStore([]).service_detail(
                "YouTube", start=start, end=start + timedelta(days=33)
            )

    def test_analytics_service_link_passes_exact_window_and_device_filter(self):
        template = (ROOT / "app/templates/activity_analytics.html").read_text()
        self.assertIn(
            "/activity/service/{{item.service_key}}?start={{window.start|urlencode}}&amp;end={{window.end|urlencode}}",
            template,
        )
        self.assertIn("&amp;client_ip={{selected_ip|urlencode}}", template)
        self.assertNotIn("/activity/service/{{item.service_key}}?hours=", template)

    def test_service_route_parses_explicit_boundaries_and_passes_them_to_store(self):
        source = (ROOT / "app/main.py").read_text()
        tree = ast.parse(source)
        route = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "activity_service_page")
        route_source = ast.get_source_segment(source, route)
        self.assertIn('start: str = ""', route_source)
        self.assertIn('end: str = ""', route_source)
        self.assertIn('client_ip: str = ""', route_source)
        self.assertIn("datetime.fromisoformat", route_source)
        self.assertIn("start=selected_start, end=selected_end", route_source)
        self.assertIn("client_ip=selected_client", route_source)


if __name__ == "__main__":
    unittest.main()
