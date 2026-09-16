import ast
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def service_intelligence_signal():
    """Load the isolated pure display classifier without application setup."""
    source = (ROOT / "app/main.py").read_text()
    tree = ast.parse(source)
    node = next(
        item for item in tree.body
        if isinstance(item, ast.FunctionDef) and item.name == "_service_intelligence_signal"
    )
    module = ast.Module(body=[node], type_ignores=[])
    ast.fix_missing_locations(module)
    namespace = {}
    exec(compile(module, str(ROOT / "app/main.py"), "exec"), namespace)
    return namespace["_service_intelligence_signal"]


class ServiceIntelligenceEvidenceLabelsTests(unittest.TestCase):
    @staticmethod
    def service(**overrides):
        value = {
            "routeros_managed": False,
            "tls_patterns": [],
            "dns_suffixes": [],
        }
        value.update(overrides)
        return value

    def signal(self, service, health=None, state="fresh", current=True):
        return service_intelligence_signal()(
            service, health or {}, {"state": state}, router_health_current=current
        )

    def test_approved_tls_contract_needs_current_routeros_evidence(self):
        service = self.service(
            routeros_managed=True,
            tls_patterns=["*example*"],
            dns_suffixes=["example.com"],
        )
        for state in ("missing", "stale"):
            with self.subTest(observation=state):
                signal = self.signal(service, {"healthy": True}, state, current=False)
                self.assertEqual("unverified", signal["state"])
                self.assertEqual("TLS CONTRACT UNVERIFIED", signal["label"])

    def test_signal_capabilities_follow_configured_signatures(self):
        cases = (
            (self.service(tls_patterns=["*tls*"]), "TLS/SNI CLASSIFIER"),
            (self.service(dns_suffixes=["example.com"]), "DNS REPORTING"),
            (
                self.service(tls_patterns=["*tls*"], dns_suffixes=["example.com"]),
                "TLS/SNI + DNS CLASSIFIERS",
            ),
        )
        for service, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(expected, self.signal(service)["label"])

    def test_healthy_tls_contract_never_claims_dns_capability(self):
        signal = self.signal(
            self.service(
                routeros_managed=True,
                tls_patterns=["*tls*"],
                dns_suffixes=["example.com"],
            ),
            {"healthy": True},
        )
        self.assertEqual("healthy", signal["state"])
        self.assertEqual("TLS CONTRACT HEALTHY", signal["label"])
        self.assertNotIn("DNS", signal["label"])

    def test_activity_route_only_uses_advisory_observation_for_display(self):
        source = (ROOT / "app/main.py").read_text()
        tree = ast.parse(source)
        route = next(
            node for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "activity_service_page"
        )
        route_source = ast.get_source_segment(source, route)
        self.assertIn("_advisory_router_payload", route_source)
        self.assertNotIn("_publish_router_observation", route_source)


if __name__ == "__main__":
    unittest.main()
