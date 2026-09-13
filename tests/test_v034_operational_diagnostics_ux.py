import contextlib
import json
from pathlib import Path
import unittest

from app.diagnostics import DIAGNOSTIC_SCHEMA, OperationalDiagnostics


ROOT = Path(__file__).resolve().parents[1]


class FakePolicyStore:
    def database_integrity_report(self):
        return {
            "ok": True,
            "size_bytes": 4096,
            "missing_tables": [],
            "table_counts": {"profiles": 2, "device_policy": 6, "audit_log": 25},
        }

    def list_config_snapshots(self, limit=20):
        return [{"id": 1}, {"id": 2}]

    def audit_count(self):
        return 25


class FakeRouter:
    def __init__(self):
        self.session_entries = 0
        self.calls = []

    @contextlib.contextmanager
    def coherent_session(self):
        self.session_entries += 1
        yield

    def health(self):
        self.calls.append("health")
        return {"connected": True, "router": "secret-router", "host": "192.168.88.1"}

    def get_security_posture(self):
        self.calls.append("security")
        return {"enforcement_ready": True, "score": 97, "critical_count": 0, "warning_count": 1}

    def get_managed_state_inventory(self):
        self.calls.append("inventory")
        return {
            "counts": {
                "restricted_devices": 6,
                "managed_address_entries": 14,
                "managed_queues": 3,
                "managed_schedulers": 2,
                "managed_scripts": 4,
                "required_firewall_rules_seen": 9,
                "required_firewall_rules_expected": 9,
            },
            "address_lists": [{"name": "MC_secret", "entries": 14}],
        }

    def get_service_contract_health(self, definitions):
        self.calls.append("services")
        return {
            "available": True,
            "healthy": 3,
            "total": 4,
            "degraded": 1,
            "reporting_only": 2,
            "detector_addresses": 31,
            "services": [{"key": "secret_service", "status": "healthy"}],
        }




class BrokenSessionRouter(FakeRouter):
    @contextlib.contextmanager
    def coherent_session(self):
        raise RuntimeError("connect failed to 10.0.0.1")
        yield

class FakeActivity:
    def __init__(self, ok=True):
        self.ok = ok

    def health(self):
        return self.ok


class FakeReconciler:
    def __init__(self, alive=True):
        self.alive = alive

    def snapshot(self):
        return {
            "worker_alive": self.alive,
            "busy": False,
            "mode": "report",
            "hold_active": False,
            "consecutive_failures": 0,
            "last": {"result": "ok"},
        }


class FakeIncidentMonitor:
    def snapshot(self):
        return {
            "enabled": True,
            "worker_alive": True,
            "counts": {"active": 1, "resolved": 7},
        }


class FakeSummaryDelivery:
    def snapshot(self):
        return {
            "enabled": False,
            "worker_running": True,
            "stats": {"pending": 0, "failed": 0},
        }


class FakePerformance:
    def snapshot(self):
        return {
            "enabled": True,
            "process": {
                "python": "3.12.0",
                "uptime_seconds": 123,
                "current_rss_mb": 55.2,
                "max_rss_mb": 61.0,
                "threads": 9,
            },
            "request_summary": {
                "retained": 20,
                "p50_ms": 100.0,
                "p95_ms": 800.0,
                "p99_ms": 900.0,
                "max_ms": 1100.0,
                "slow_count": 2,
            },
            "routes": [
                {"route": "GET /", "count": 10, "p50_ms": 100, "p95_ms": 500, "max_ms": 700, "errors": 0},
            ],
            "components": [
                {"name": "routeros.connect", "count": 5, "avg_ms": 50, "p95_ms": 90, "errors": 0},
            ],
            "slow_requests": [{"path": "/devices/192.168.88.50"}],
            "recent_requests": [{"path": "/activity/device/192.168.88.50"}],
        }


class OperationalDiagnosticsTests(unittest.TestCase):
    def build(self, *, activity_ok=True, reconciler_alive=True):
        router = FakeRouter()
        service = OperationalDiagnostics(
            app_version="0.34.0",
            policy_store=FakePolicyStore(),
            router=router,
            activity_store=FakeActivity(activity_ok),
            reconciler=FakeReconciler(reconciler_alive),
            incident_monitor=FakeIncidentMonitor(),
            summary_delivery=FakeSummaryDelivery(),
            performance_collector=FakePerformance(),
            service_contract_loader=lambda: [{"key": "custom", "dns_suffixes": ["private.example"]}],
        )
        return service, router

    def test_report_is_sanitized_and_uses_one_router_session(self):
        service, router = self.build()
        report = service.capture()
        self.assertEqual(report["schema"], DIAGNOSTIC_SCHEMA)
        self.assertEqual(report["version"], "0.34.0")
        self.assertEqual(router.session_entries, 1)
        self.assertEqual(router.calls, ["health", "security", "inventory", "services"])
        encoded = json.dumps(report)
        self.assertNotIn("192.168.88.1", encoded)
        self.assertNotIn("secret-router", encoded)
        self.assertNotIn("MC_secret", encoded)
        self.assertNotIn("secret_service", encoded)
        self.assertNotIn("private.example", encoded)
        self.assertNotIn("192.168.88.50", encoded)
        self.assertTrue(report["privacy"]["sanitized"])

    def test_telemetry_failure_degrades_only_that_check(self):
        service, _ = self.build(activity_ok=False)
        report = service.capture()
        telemetry = next(row for row in report["checks"] if row["key"] == "telemetry")
        database = next(row for row in report["checks"] if row["key"] == "policy_database")
        self.assertEqual(telemetry["state"], "offline")
        self.assertEqual(database["state"], "healthy")
        self.assertEqual(report["overall"], "offline")

    def test_reconciler_failure_is_critical(self):
        service, _ = self.build(reconciler_alive=False)
        report = service.capture()
        rec = next(row for row in report["checks"] if row["key"] == "reconciler")
        self.assertEqual(rec["state"], "critical")
        self.assertEqual(report["overall"], "critical")


    def test_router_session_failure_marks_all_router_checks_unavailable_without_raw_error(self):
        router = BrokenSessionRouter()
        service = OperationalDiagnostics(
            app_version="0.34.0", policy_store=FakePolicyStore(), router=router,
            activity_store=FakeActivity(True), reconciler=FakeReconciler(True),
            incident_monitor=FakeIncidentMonitor(), summary_delivery=FakeSummaryDelivery(),
            performance_collector=FakePerformance(), service_contract_loader=lambda: [],
        )
        report = service.capture()
        by_key = {row["key"]: row for row in report["checks"]}
        self.assertEqual(by_key["routeros_api"]["state"], "offline")
        self.assertEqual(by_key["security_authority"]["state"], "critical")
        self.assertEqual(by_key["managed_inventory"]["state"], "offline")
        self.assertEqual(by_key["service_contracts"]["state"], "offline")
        self.assertNotIn("10.0.0.1", json.dumps(report))

    def test_report_uses_aggregate_performance_not_request_paths(self):
        service, _ = self.build()
        report = service.capture()
        self.assertEqual(report["performance"]["slow_routes"][0]["route"], "GET /")
        self.assertNotIn("slow_requests", report["performance"])
        self.assertNotIn("recent_requests", report["performance"])


class DiagnosticsIntegrationAndUxTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.main = (ROOT / "app/main.py").read_text()
        cls.module = (ROOT / "app/diagnostics.py").read_text()
        cls.index = (ROOT / "app/templates/index.html").read_text()
        cls.template = (ROOT / "app/templates/diagnostics.html").read_text()
        cls.css = (ROOT / "app/static/diagnostics.css").read_text()
        cls.app_css = (ROOT / "app/static/app.css").read_text()
        cls.ux = (ROOT / "app/ux.py").read_text()

    def test_v034_routes_and_version_are_wired(self):
        self.assertIn('version="0.55.4.2"', self.main)
        self.assertIn('@app.get("/diagnostics", response_class=HTMLResponse)', self.main)
        self.assertIn('@app.get("/api/operations/diagnostics")', self.main)
        self.assertIn('@app.get("/local/operations/diagnostics/export")', self.main)
        self.assertIn('"diagnostics.html"', self.main)

    def test_diagnostics_is_read_only_with_respect_to_router_authority(self):
        forbidden = (
            "set_global_mode(", "set_device_mode(", "apply_device_policy(",
            "add_restricted_device(", "remove_restricted_device(",
            "provision_custom_service(", "remove_custom_service(",
        )
        for token in forbidden:
            self.assertNotIn(token, self.module)
        self.assertIn("Diagnostics are read-only", self.module)

    def test_operations_links_are_connected(self):
        self.assertIn('href="/diagnostics">Run diagnostics</a>', self.index)
        self.assertIn('<code>/api/operations/diagnostics</code>', self.index)
        self.assertIn('href="/diagnostics">Open diagnostics</a>', self.index)
        self.assertIn('"secondary": {"label": "Diagnostics", "href": "/diagnostics"}', self.ux)

    def test_standalone_navigation_is_compact_and_contextual(self):
        self.assertIn('Back to Operations', self.template)
        self.assertIn('href="/performance"', self.template)
        self.assertIn('Download sanitized bundle', self.template)
        self.assertIn('.diagnostics-actions', self.css)
        self.assertIn('@media(max-width:700px)', self.css)
        self.assertIn('.operations-tool-links', self.app_css)
        self.assertIn('@media(max-width:760px)', self.app_css)

    def test_diagnostics_assets_are_cache_busted(self):
        self.assertIn('/static/app.css?v=0.55.4.2', self.template)
        self.assertIn('/static/layout.css?v=0.55.4.2', self.template)
        self.assertIn('/static/diagnostics.css?v=0.55.4.2', self.template)

    def test_bundle_privacy_boundary_is_visible(self):
        self.assertIn('Sanitized support bundle', self.template)
        self.assertIn('credentials and tokens', self.module)
        self.assertIn('managed-device IP addresses', self.module)
        self.assertIn('DNS query/domain contents', self.module)
        self.assertIn('raw audit and incident details', self.module)


if __name__ == "__main__":
    unittest.main()
