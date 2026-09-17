import ast
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ShareableActivityDrilldownRegressionTests(unittest.TestCase):
    def test_service_domain_and_device_service_links_keep_exact_window_and_filters(self):
        service = (ROOT / "app/templates/activity_service.html").read_text()
        device = (ROOT / "app/templates/activity_device.html").read_text()

        self.assertIn("start={{selected_start|urlencode}}&amp;end={{selected_end|urlencode}}", service)
        self.assertIn("service={{service.key|urlencode}}", service)
        self.assertIn("client_ip={{selected_client|urlencode}}", service)
        self.assertIn("client_ip={{client_ip}}&amp;capability={{filters.capability}}", device)
        self.assertIn("routeros_state={{filters.routeros_state}}", device)
        self.assertIn("evidence_health={{filters.evidence_health}}", device)

    def test_exact_analytics_window_and_invalid_device_filters_are_validated(self):
        source = (ROOT / "app/main.py").read_text()
        tree = ast.parse(source)
        device = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                      and node.name == "activity_device_page")
        body = ast.get_source_segment(source, device)

        self.assertIn("def _activity_analytics_window", source)
        self.assertIn("_activity_drill_window(24, start, end)", source)
        self.assertIn("raise HTTPException(status_code=400, detail=str(exc))", body)
        self.assertIn("_activity_drill_filters", body)


if __name__ == "__main__":
    unittest.main()
