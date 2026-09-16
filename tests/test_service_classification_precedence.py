import importlib.util
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/service_classification.json"


def load_classifier():
    spec = importlib.util.spec_from_file_location(
        "service_map_precedence_test", ROOT / "telemetry/ingest/service_map.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ServiceClassificationPrecedenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.classifier = load_classifier()
        cls.fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def test_fixture_corpus_resolves_each_signal_to_its_declared_evidence(self):
        for case in self.fixture["cases"]:
            with self.subTest(case=case["id"]):
                self.assertEqual(
                    self.classifier.classify_record(case["signals"]), case["expected"]
                )

    def test_manual_override_precedes_every_observed_signal(self):
        result = self.classifier.classify_record({
            "manual_override": {"service": "Custom learning", "category": "education"},
            "address_list": ["Detected_ChatGPT"],
            "dns": {"domain": "api.netflix.com"},
            "flow": {"domain": "gateway.discord.gg", "protocol": "UDP", "destination_port": 3074},
            "port": {"protocol": "UDP", "number": 3074},
        })
        self.assertEqual(result, {
            "category": "education",
            "service": "Custom learning",
            "confidence": "high",
            "evidence": {
                "source": "manual_override",
                "matched_value": "Custom learning",
                "precedence": 0,
            },
        })

    def test_precedence_order_is_public_and_complete(self):
        self.assertEqual(self.classifier.CLASSIFICATION_PRECEDENCE, (
            "manual_override", "address_list", "dns", "flow", "port", "fallback",
        ))

