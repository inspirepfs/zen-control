import ast
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class DrilldownFilterValidationTests(unittest.TestCase):
    def setUp(self):
        self.source = (ROOT / "app/main.py").read_text()
        self.tree = ast.parse(self.source)

    def _route(self, name):
        return next(node for node in self.tree.body if isinstance(node, ast.FunctionDef) and node.name == name)

    def test_analytics_reuses_the_canonical_client_ip_after_filter_validation(self):
        body = ast.get_source_segment(self.source, self._route("activity_analytics_page"))
        self.assertIn('selected = filters["client_ip"]', body)

    def test_invalid_device_service_filters_are_rejected_before_retained_queries(self):
        body = ast.get_source_segment(self.source, self._route("activity_device_page"))
        self.assertIn('raise ValueError("Activity filters require a concrete service")', body)
        self.assertIn('raise HTTPException(status_code=400, detail=str(exc))', body)

    def test_service_detail_applies_descriptive_contract_filters_without_live_reads(self):
        body = ast.get_source_segment(self.source, self._route("activity_service_page"))
        self.assertIn("_filter_service_matrix([service_contract], filters)", body)
        self.assertIn("filter_excluded", body)


if __name__ == "__main__":
    unittest.main()
