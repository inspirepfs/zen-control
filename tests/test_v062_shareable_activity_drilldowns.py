import ast
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ShareableActivityDrilldownRegressionTests(unittest.TestCase):
    def setUp(self):
        self.main = (ROOT / "app/main.py").read_text()
        self.analytics = (ROOT / "app/templates/activity_analytics.html").read_text()
        self.service = (ROOT / "app/templates/activity_service.html").read_text()
        self.device = (ROOT / "app/templates/activity_device.html").read_text()

    def test_analytics_accepts_and_preserves_descriptive_filters_for_service_drills(self):
        tree = ast.parse(self.main)
        route = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "activity_analytics_page")
        args = {arg.arg for arg in route.args.args}
        self.assertTrue({"capability", "routeros_state", "managed", "evidence_health"} <= args)
        self.assertIn("_filter_activity_service_rows", self.main)
        self.assertIn("&amp;evidence_health={{filters.evidence_health|urlencode}}", self.analytics)
        self.assertIn("/activity/service/{{item.service_key}}?start={{window.start|urlencode}}", self.analytics)

    def test_clear_filters_restores_only_the_bounded_window_and_announces_context(self):
        self.assertIn('role="status"', self.analytics)
        self.assertIn("Clear filters", self.service)
        self.assertIn('href="/activity/service/{{service.key}}{% if selected_start %}?start=', self.service)
        self.assertNotIn("client_ip={{selected_client|urlencode}}{% endif %}{% endif %}", self.service)
        self.assertIn("Clear filters", self.device)

    def test_concrete_service_guard_and_invalid_filter_validation_remain_present(self):
        self.assertIn("Open a concrete service rather than an aggregate policy group", self.main)
        self.assertIn("Activity filters require a concrete service", self.main)
        self.assertIn("Invalid {key.replace('_', ' ')} filter", self.main)


if __name__ == "__main__":
    unittest.main()
