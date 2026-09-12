import importlib.util
import json
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path

# Keep host-side tests independent of psycopg installation.
psycopg = types.ModuleType("psycopg")
psycopg.Error = Exception
psycopg.connect = None
rows = types.ModuleType("psycopg.rows")
rows.dict_row = object()
sys.modules.setdefault("psycopg", psycopg)
sys.modules.setdefault("psycopg.rows", rows)

from app.activity import build_service_intelligence
from app.policy_store import PolicyStore
from app.service_catalog import SERVICE_ENFORCEMENT, SERVICE_DNS_SUFFIXES

ROOT = Path(__file__).resolve().parents[1]


class ServiceCatalogTests(unittest.TestCase):
    def test_every_routeros_service_has_dns_and_tls_signatures(self):
        self.assertGreaterEqual(len(SERVICE_ENFORCEMENT), 12)
        for key, item in SERVICE_ENFORCEMENT.items():
            with self.subTest(service=key):
                self.assertTrue(item.get("tls_patterns"), key)
                self.assertTrue(item.get("dns_suffixes"), key)
                self.assertEqual(item.get("dns_suffixes"), list(SERVICE_DNS_SUFFIXES[key]))

    def test_custom_service_metadata_is_persisted_and_published(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = PolicyStore(str(Path(tmp) / "policy.db"))
            saved = store.save_service(
                "minecraft", "Minecraft", "Game service", "gaming",
                "minecraft.net\nmojang.com", "*minecraft* *mojang*", True,
            )
            self.assertEqual(saved["dns_suffixes"], ["minecraft.net", "mojang.com"])
            self.assertEqual(saved["tls_patterns"], ["*minecraft*", "*mojang*"])
            out = Path(tmp) / "service-catalog.json"
            payload = store.export_service_catalog(out)
            entry = next(item for item in payload["services"] if item["key"] == "minecraft")
            self.assertEqual(entry["name"], "Minecraft")
            self.assertEqual(entry["category"], "gaming")
            self.assertEqual(entry["dns_suffixes"], ["minecraft.net", "mojang.com"])
            self.assertFalse(entry["routeros_managed"])
            self.assertEqual(json.loads(out.read_text())["version"], 1)

    def test_invalid_classifier_signatures_fail_loud(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = PolicyStore(str(Path(tmp) / "policy.db"))
            with self.assertRaises(ValueError):
                store.save_service("bad", "Bad", dns_suffixes="bad_domain.com")
            with self.assertRaises(ValueError):
                store.save_service("bad", "Bad", tls_patterns="*bad/host*")


class DynamicTelemetryClassifierTests(unittest.TestCase):
    def load_module(self, catalog_file):
        old = os.environ.get("SERVICE_CATALOG_FILE")
        os.environ["SERVICE_CATALOG_FILE"] = str(catalog_file)
        try:
            spec = importlib.util.spec_from_file_location(
                "service_map_dynamic_test", ROOT / "telemetry/ingest/service_map.py"
            )
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module
        finally:
            if old is None:
                os.environ.pop("SERVICE_CATALOG_FILE", None)
            else:
                os.environ["SERVICE_CATALOG_FILE"] = old

    def test_live_catalog_classifies_new_service_without_code_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "catalog.json"
            path.write_text(json.dumps({
                "version": 1,
                "services": [
                    {"key": "minecraft", "name": "Minecraft", "dns_suffixes": ["minecraft.net", "mojang.com"]}
                ],
            }))
            module = self.load_module(path)
            self.assertEqual(module.classify_domain("session.minecraft.net"), "Minecraft")
            self.assertEqual(module.classify_domain("api.mojang.com"), "Minecraft")
            self.assertEqual(module.classifier_status()["source"], "live")

    def test_longest_suffix_wins_when_signatures_overlap(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "catalog.json"
            path.write_text(json.dumps({
                "services": [
                    {"key": "broad", "name": "Broad", "dns_suffixes": ["example.com"]},
                    {"key": "specific", "name": "Specific", "dns_suffixes": ["games.example.com"]},
                ]
            }))
            module = self.load_module(path)
            self.assertEqual(module.classify_domain("cdn.games.example.com"), "Specific")


class ServiceIntelligenceMergeTests(unittest.TestCase):
    def test_router_health_dns_and_traffic_are_merged(self):
        defs = [{
            "key": "youtube", "name": "YouTube", "builtin": 1,
            "category": "video", "dns_suffixes": ["youtube.com"],
            "tls_patterns": ["*youtube*"], "routeros_managed": True,
        }]
        traffic = [{"service_name": "YouTube", "total_bytes": 4096, "flows": 8}]
        dns = [{"service_name": "YouTube", "queries": 23, "blocked": 4}]
        health = {"services": [{"key": "youtube", "healthy": True, "detector_addresses": 17}]}
        row = build_service_intelligence(defs, traffic, dns, health)[0]
        self.assertEqual(row["classification_status"], "healthy")
        self.assertEqual(row["dns_queries"], 23)
        self.assertEqual(row["dns_blocked"], 4)
        self.assertEqual(row["detector_addresses"], 17)
        self.assertEqual(row["category"], "video")

    def test_custom_signed_service_is_reporting_classification(self):
        defs = [{
            "key": "minecraft", "name": "Minecraft", "builtin": 0,
            "category": "gaming", "dns_suffixes": ["minecraft.net"],
            "tls_patterns": ["*minecraft*"], "routeros_managed": False,
        }]
        row = build_service_intelligence(defs, [], [], {"services": []})[0]
        self.assertEqual(row["classification_status"], "reporting")


class ServiceIntelligenceUxTests(unittest.TestCase):
    def setUp(self):
        self.index = (ROOT / "app/templates/index.html").read_text()
        self.main = (ROOT / "app/main.py").read_text()
        self.compose = (ROOT / "docker-compose.yml").read_text()
        self.detail = (ROOT / "app/templates/activity_service.html").read_text()

    def test_service_intelligence_is_drillable_and_stats_heavy(self):
        for phrase in (
            "Service intelligence", "TLS contracts", "Detector addresses",
            "Classification candidates", "Traffic classified", "Drill in",
        ):
            self.assertIn(phrase, self.index)
        self.assertIn('/activity/service/{service_key}', self.main)
        self.assertIn('Devices using {{service.name}}', self.detail)
        self.assertIn('Hourly traffic', self.detail)

    def test_ingest_receives_shared_live_catalog(self):
        self.assertIn('SERVICE_CATALOG_FILE: /control-data/service-catalog.json', self.compose)
        self.assertIn('mikrotik-control-data:/control-data:ro', self.compose)
        self.assertIn('publish_service_catalog()', self.main)

    def test_product_version_is_023(self):
        self.assertIn('version="0.54.3"', self.main)

    def test_custom_service_provisioning_is_explicit_and_previewed(self):
        for phrase in (
            "Exact RouterOS contract preview",
            "No write occurs until Approve &amp; install",
            "Approve &amp; install",
            "REPORTING ONLY",
            "ORPHANED MC CONTRACT",
        ):
            self.assertIn(phrase, self.index)
        self.assertIn('/local/services/provision', self.main)
        self.assertIn('/local/services/unprovision', self.main)
        self.assertIn('CUSTOM_SERVICE_PROVISIONED', self.main)
        self.assertIn('CUSTOM_SERVICE_UNPROVISIONED', self.main)
        self.assertIn('group never receives its own MC_Block_* firewall rule', self.index)


if __name__ == "__main__":
    unittest.main()
