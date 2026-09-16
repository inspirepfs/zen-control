import ast
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ServiceActivityRouterOutageRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.main = ROOT / "app/main.py"
        cls.tree = ast.parse(cls.main.read_text())
        cls.route = next(
            node for node in cls.tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "activity_service_page"
        )
        cls.template = (ROOT / "app/templates/activity_service.html").read_text()

    def test_service_activity_route_is_not_gated_by_router_session(self):
        decorators = [
            decorator.id
            for decorator in self.route.decorator_list
            if isinstance(decorator, ast.Name)
        ]
        self.assertNotIn("coherent_router_request", decorators)

    def test_router_health_remains_advisory_during_an_outage(self):
        source = ast.get_source_segment(self.main.read_text(), self.route)
        self.assertIn("router.get_service_contract_health()", source)
        self.assertIn("except RouterError:\n        router_health = {}", source)
        self.assertIn("router.get_restricted_devices()", source)
        self.assertIn("except RouterError:\n            live = []", source)
        self.assertIn("detail = activity_store.service_detail", source)
        self.assertIn("{% if router_health.healthy %}", self.template)

    def test_route_remains_read_only(self):
        methods = [
            decorator.func.attr
            for decorator in self.route.decorator_list
            if isinstance(decorator, ast.Call)
            and isinstance(decorator.func, ast.Attribute)
        ]
        self.assertEqual(["get"], methods)
        router_calls = {
            call.func.attr
            for call in ast.walk(self.route)
            if isinstance(call, ast.Call)
            and isinstance(call.func, ast.Attribute)
            and isinstance(call.func.value, ast.Name)
            and call.func.value.id == "router"
        }
        self.assertEqual(
            {"get_service_contract_health", "get_restricted_devices"}, router_calls
        )


if __name__ == "__main__":
    unittest.main()
