import ast
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class HistoricalAnalyticsServiceKeyDecorationTests(unittest.TestCase):
    def test_prepared_and_fallback_decorate_historical_rows_and_movers_from_one_mapping(self):
        source = (ROOT / "app/main.py").read_text()
        tree = ast.parse(source)
        route = next(
            node for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "activity_analytics_page"
        )
        body = ast.get_source_segment(source, route)

        self.assertEqual(1, body.count("keys_by_name = _activity_service_keys_by_name()"))
        self.assertEqual(
            2,
            body.count('_decorate_activity_service_keys(service_analytics["services"], keys_by_name)'),
        )
        self.assertEqual(
            2,
            body.count('_decorate_activity_service_keys(service_analytics["movers"], keys_by_name)'),
        )
        self.assertIn('str(item.get("service_name") or "").strip().lower()', source)
        self.assertIn('str(item.get("name") or "").strip().lower()', source)


if __name__ == "__main__":
    unittest.main()
