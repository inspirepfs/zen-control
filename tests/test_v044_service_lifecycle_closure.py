import importlib.util
import json
import os
import tempfile
import types
import unittest
from pathlib import Path

# Keep host-side tests independent of psycopg installation.
import sys
psycopg = types.ModuleType("psycopg")
psycopg.Error = Exception
psycopg.connect = None
rows = types.ModuleType("psycopg.rows")
rows.dict_row = object()
sys.modules.setdefault("psycopg", psycopg)
sys.modules.setdefault("psycopg.rows", rows)
sys.modules.setdefault("routeros_api", types.SimpleNamespace())

from app.activity import build_policy_service_activity
from app.policy_store import PolicyStore
from app.router import RouterOSAdapter
from tests.test_v023_custom_service_provisioning import _Api, _Pool

ROOT = Path(__file__).resolve().parents[1]


class DynamicClassifierLifecycleClosureTests(unittest.TestCase):
    def load_module(self, catalog_file):
        old = os.environ.get("SERVICE_CATALOG_FILE")
        os.environ["SERVICE_CATALOG_FILE"] = str(catalog_file)
        try:
            spec = importlib.util.spec_from_file_location(
                f"service_map_v044_{id(catalog_file)}",
                ROOT / "telemetry/ingest/service_map.py",
            )
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module
        finally:
            if old is None:
                os.environ.pop("SERVICE_CATALOG_FILE", None)
            else:
                os.environ["SERVICE_CATALOG_FILE"] = old

    @staticmethod
    def write(path, services, version=1):
        path.write_text(json.dumps({"version": version, "services": services}), encoding="utf-8")

    def test_valid_empty_live_catalogue_is_authoritative_not_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "catalog.json"
            self.write(path, [])
            module = self.load_module(path)
            self.assertEqual(module.classify_domain("www.youtube.com"), "")
            status = module.classifier_status()
            self.assertEqual(status["source"], "live")
            self.assertEqual(status["services"], 0)
            self.assertEqual(status["signatures"], 0)
            self.assertTrue(status["has_live"])

    def test_malformed_replacement_retains_last_known_good_live_catalogue(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "catalog.json"
            self.write(path, [{"key": "minecraft", "name": "Minecraft", "dns_suffixes": ["minecraft.net"]}])
            module = self.load_module(path)
            self.assertEqual(module.classify_domain("play.minecraft.net"), "Minecraft")
            path.write_text("{not-json", encoding="utf-8")
            self.assertEqual(module.classify_domain("play.minecraft.net"), "Minecraft")
            status = module.classifier_status()
            self.assertEqual(status["source"], "stale_live")
            self.assertIn("JSON", status["error"].upper())

    def test_missing_replacement_retains_last_known_good_live_catalogue(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "catalog.json"
            self.write(path, [{"name": "Minecraft", "dns_suffixes": ["minecraft.net"]}])
            module = self.load_module(path)
            self.assertEqual(module.classify_domain("minecraft.net"), "Minecraft")
            path.unlink()
            self.assertEqual(module.classify_domain("minecraft.net"), "Minecraft")
            self.assertEqual(module.classifier_status()["source"], "stale_live")

    def test_bootstrap_invalid_catalogue_uses_fallback_without_crashing(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "catalog.json"
            path.write_text(json.dumps({"version": 1, "services": ["bad-entry"]}), encoding="utf-8")
            module = self.load_module(path)
            self.assertEqual(module.classify_domain("www.youtube.com"), "YouTube")
            status = module.classifier_status()
            self.assertEqual(status["source"], "fallback")
            self.assertFalse(status["has_live"])
            self.assertTrue(status["error"])

    def test_atomic_replace_is_detected_even_if_size_and_mtime_match(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "catalog.json"
            first = {"version": 1, "services": [{"name": "Alpha", "dns_suffixes": ["a.example"]}]}
            second = {"version": 1, "services": [{"name": "Bravo", "dns_suffixes": ["b.example"]}]}
            first_text = json.dumps(first, separators=(",", ":"))
            second_text = json.dumps(second, separators=(",", ":"))
            self.assertEqual(len(first_text), len(second_text))
            path.write_text(first_text, encoding="utf-8")
            original = path.stat()
            module = self.load_module(path)
            self.assertEqual(module.classify_domain("a.example"), "Alpha")

            replacement = path.with_suffix(".tmp")
            replacement.write_text(second_text, encoding="utf-8")
            os.replace(replacement, path)
            os.utime(path, ns=(original.st_atime_ns, original.st_mtime_ns))
            self.assertEqual(path.stat().st_size, original.st_size)
            self.assertEqual(path.stat().st_mtime_ns, original.st_mtime_ns)
            self.assertEqual(module.classify_domain("b.example"), "Bravo")
            self.assertEqual(module.classifier_status()["source"], "live")

    def test_unsupported_live_catalogue_version_is_not_adopted(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "catalog.json"
            self.write(path, [{"name": "Minecraft", "dns_suffixes": ["minecraft.net"]}], version=2)
            module = self.load_module(path)
            self.assertEqual(module.classify_domain("minecraft.net"), "")
            self.assertEqual(module.classifier_status()["source"], "fallback")


class CustomServiceLifecycleClosureTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = PolicyStore(str(Path(self.tmp.name) / "policy.db"))

    def tearDown(self):
        self.tmp.cleanup()

    def add_minecraft(self):
        return self.store.save_service(
            "minecraft", "Minecraft", "Game service", "gaming",
            "minecraft.net mojang.com", "*minecraft*", True,
        )

    def test_publication_lifecycle_reporting_approved_reporting_deleted(self):
        self.add_minecraft()
        out = Path(self.tmp.name) / "service-catalog.json"

        reporting = self.store.export_service_catalog(out)
        item = next(row for row in reporting["services"] if row["key"] == "minecraft")
        self.assertFalse(item["routeros_managed"])
        self.assertFalse(item["enforcement_approved"])

        self.store.set_service_enforcement_approved("minecraft", True)
        approved = self.store.export_service_catalog(out)
        item = next(row for row in approved["services"] if row["key"] == "minecraft")
        self.assertTrue(item["routeros_managed"])
        self.assertTrue(item["enforcement_approved"])

        self.store.set_service_enforcement_approved("minecraft", False)
        back_to_reporting = self.store.export_service_catalog(out)
        item = next(row for row in back_to_reporting["services"] if row["key"] == "minecraft")
        self.assertFalse(item["routeros_managed"])
        self.store.delete_service("minecraft")
        final = self.store.export_service_catalog(out)
        self.assertNotIn("minecraft", {row["key"] for row in final["services"]})

    def test_delete_is_blocked_by_all_live_policy_reference_classes(self):
        self.add_minecraft()
        profile = self.store.create_profile(
            "Games", "normal", "normal", "", ["minecraft"]
        )
        self.store.save_template_from_profile("Games template", profile["id"])
        self.store.create_schedule_plan(
            "Minecraft bedtime", "all", "", "service", "minecraft:blocked", "20:00", ["mon"]
        )
        self.store.save_service_group("Game collection", "", ["minecraft"])
        self.store.create_policy_group("Block games", "", ["minecraft"])

        usage = self.store.service_usage("minecraft")
        self.assertEqual(usage["total"], 5)
        self.assertEqual(len(usage["profiles"]), 1)
        self.assertEqual(len(usage["templates"]), 1)
        self.assertEqual(len(usage["schedules"]), 1)
        self.assertEqual(len(usage["collections"]), 1)
        self.assertEqual(len(usage["aggregate_groups"]), 1)
        with self.assertRaisesRegex(ValueError, "still referenced by 5"):
            self.store.delete_service("minecraft")

    def test_deleted_service_telemetry_remains_visible_as_observed_history(self):
        rows = build_policy_service_activity(
            [],
            [{"service_name": "Minecraft", "total_bytes": 4096, "flows": 3}],
        )
        minecraft = next(row for row in rows if row["name"] == "Minecraft")
        self.assertEqual(minecraft["kind"], "observed")
        self.assertFalse(minecraft["policy_tracked"])
        self.assertEqual(minecraft["total_bytes"], 4096)


    def test_invalid_approved_metadata_is_reported_degraded_not_reporting_only(self):
        api = _Api(
            firewall=[{"id": "*99", "chain": "restricted-web", "action": "return", "comment": "RW99 - Return"}],
            address_lists=[],
        )
        adapter = RouterOSAdapter.__new__(RouterOSAdapter)
        adapter._connect = lambda: (_Pool(), api)
        result = adapter.get_service_contract_health([{
            "key": "minecraft", "name": "Minecraft", "builtin": False,
            "enforcement_approved": True, "routeros_contract": None,
            "provisioning_error": "Custom RouterOS enforcement requires at least one TLS/SNI pattern",
            "tls_patterns": [],
        }])
        row = next(item for item in result["services"] if item["key"] == "minecraft")
        self.assertEqual(row["status"], "degraded")
        self.assertFalse(row["healthy"])
        self.assertTrue(row["approved"])
        self.assertIn("requires at least one TLS/SNI pattern", row["error"])

    def test_invalid_approved_metadata_is_omitted_from_runtime_write_authority(self):
        self.add_minecraft()
        self.store.set_service_enforcement_approved("minecraft", True)
        with self.store._db() as db:
            db.execute("UPDATE services SET tls_patterns='[]' WHERE key='minecraft'")
        listed = self.store.get_service("minecraft")
        self.assertTrue(listed["enforcement_approved"])
        self.assertIn("requires at least one TLS/SNI pattern", listed["provisioning_error"])
        catalog = self.store.routeros_service_catalog()
        self.assertNotIn("minecraft", catalog)


class ServiceLifecycleUxClosureTests(unittest.TestCase):
    def test_services_ui_surfaces_dependency_guard_and_help_contract(self):
        index = (ROOT / "app/templates/index.html").read_text()
        help_text = (ROOT / "app/help_content.py").read_text()
        main = (ROOT / "app/main.py").read_text()
        self.assertIn("Delete unavailable", index)
        self.assertIn("live policy/configuration reference", index)
        self.assertIn('custom_service_usage', main)
        self.assertIn("last known-good live classifier catalogue", help_text)
        self.assertIn("valid empty catalogue deliberately classifies nothing", help_text)


if __name__ == "__main__":
    unittest.main()
