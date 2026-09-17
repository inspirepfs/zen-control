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
        cls.advisory_router_payload = next(
            node for node in cls.tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "_advisory_router_payload"
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

        # v0.60 deliberately consumes revision-bound advisory RouterOS
        # observations. Normal Activity navigation must not perform a live
        # RouterOS service-health or restricted-device read.
        self.assertIn("_advisory_router_payload(", source)
        self.assertIn('"router:service-contract-health"', source)
        self.assertNotIn("router.get_service_contract_health()", source)
        self.assertNotIn("router.get_restricted_devices()", source)

        # The advisory helper must reject an observation from another desired
        # configuration revision; an outage must never make old contract
        # semantics appear current.
        advisory_source = ast.get_source_segment(
            self.main.read_text(), self.advisory_router_payload
        )
        self.assertIn("current_config_revision()", advisory_source)
        self.assertIn("required_revision=revision", advisory_source)

        # Retained Activity evidence remains available independently of the
        # advisory RouterOS observation.
        self.assertIn("detail = activity_store.service_detail", source)
        self.assertIn("{% if router_health.healthy %}", self.template)


    def test_route_remains_read_only(self):
        source = ast.get_source_segment(self.main.read_text(), self.route)
        route_tree = ast.parse(source)

        router_calls = {
            call.func.attr
            for call in ast.walk(route_tree)
            if isinstance(call, ast.Call)
            and isinstance(call.func, ast.Attribute)
            and isinstance(call.func.value, ast.Name)
            and call.func.value.id == "router"
        }

        # Activity drilldowns consume advisory/prepared observations only.
        # There must be no direct RouterOS calls in this request path.
        self.assertEqual(set(), router_calls)
        self.assertIn("_advisory_router_payload(", source)



if __name__ == "__main__":
    unittest.main()
