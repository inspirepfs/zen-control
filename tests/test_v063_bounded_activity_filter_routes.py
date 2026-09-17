import ast
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class BoundedActivityFilterRouteTests(unittest.TestCase):
    def test_device_route_accepts_bounded_service_drilldown_parameters(self):
        source = (ROOT / "app/main.py").read_text()
        tree = ast.parse(source)
        route = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "activity_device_page")
        names = {arg.arg for arg in route.args.args}
        self.assertTrue({"start", "end", "service", "capability", "routeros_state", "managed", "evidence_health"} <= names)
        body = ast.get_source_segment(source, route)
        self.assertIn("_activity_drill_window", body)
        self.assertIn("top_services_range", body)

    def test_service_and_device_pages_show_exact_window_and_clear_filters(self):
        service = (ROOT / "app/templates/activity_service.html").read_text()
        device = (ROOT / "app/templates/activity_device.html").read_text()
        self.assertIn("drill_window.label", service)
        self.assertIn("service={{service.key|urlencode}}", service)
        self.assertIn("Clear filters", device)
        self.assertIn("drill_window.label", device)


if __name__ == "__main__":
    unittest.main()
