import importlib.util
import json
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
INGEST = ROOT / "telemetry/ingest/ingest.py"


def load_ingest():
    dns = types.ModuleType("dns")
    dns.resolver = types.ModuleType("dns.resolver")
    psycopg = types.ModuleType("psycopg")
    spec = importlib.util.spec_from_file_location("traffic_sample_ingest_test", INGEST)
    module = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, {"dns": dns, "dns.resolver": dns.resolver, "psycopg": psycopg}):
        with patch.object(sys, "path", [str(INGEST.parent), *sys.path]):
            spec.loader.exec_module(module)
    return module


class TrafficSampleClassificationStorageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ingest = load_ingest()

    def test_flow_sample_persists_complete_normalized_classification(self):
        with patch.object(self.ingest, "lookup_domain", return_value=("r1---sn.googlevideo.com", "YouTube")):
            sample = self.ingest.transform_flow({
                "src_addr": "192.168.1.20", "dst_addr": "198.51.100.10",
                "time_received_ns": 1, "time_flow_start_ns": 1, "time_flow_end_ns": 1,
                "proto": 6, "dst_port": 443,
            })
        stored = dict(zip(self.ingest.FLOW_RAW_FIELDS, self.ingest.flow_raw_values(sample)))
        self.assertEqual("video", stored["category"])
        self.assertEqual("YouTube", stored["service"])
        self.assertEqual("high", stored["confidence"])
        self.assertEqual({"source": "dns", "matched_value": "googlevideo.com", "precedence": 2}, json.loads(stored["classifier_evidence"]))
        self.assertEqual("zen_service_classifier_v1", stored["classifier_version"])

    def test_schema_migrates_historical_samples_to_explicit_unknown_metadata(self):
        schema = (ROOT / "telemetry/postgres/init.sql").read_text(encoding="utf-8")
        self.assertIn("ADD COLUMN IF NOT EXISTS category text NOT NULL DEFAULT 'unknown'", schema)
        self.assertIn("ADD COLUMN IF NOT EXISTS confidence text NOT NULL DEFAULT 'none'", schema)
        self.assertIn("ADD COLUMN IF NOT EXISTS classifier_evidence jsonb NOT NULL DEFAULT", schema)
        self.assertIn("ADD COLUMN IF NOT EXISTS classifier_version text NOT NULL DEFAULT 'unknown'", schema)

