import contextlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest

from app.diagnostics import OperationalDiagnostics, read_telemetry_ingest_status


ROOT = Path(__file__).resolve().parents[1]


class PolicyStore:
    def database_integrity_report(self):
        return {"ok": True, "size_bytes": 4096, "missing_tables": [], "table_counts": {"profiles": 2}}

    def list_config_snapshots(self, limit=20):
        return [{"id": 1}]

    def audit_count(self):
        return 7


class Router:
    def __init__(self, connected=True, session_error=None):
        self.connected = connected
        self.session_error = session_error

    @contextlib.contextmanager
    def coherent_session(self):
        if self.session_error:
            raise RuntimeError(self.session_error)
        yield

    def health(self):
        if not self.connected:
            raise RuntimeError("router secret host=192.0.2.99 password=do-not-export")
        return {"connected": True, "host": "192.0.2.99"}

    def get_security_posture(self):
        if not self.connected:
            raise RuntimeError("router security unavailable password=do-not-export")
        return {"enforcement_ready": True, "score": 100, "critical_count": 0, "warning_count": 0}

    def get_managed_state_inventory(self):
        if not self.connected:
            raise RuntimeError("router inventory unavailable 192.0.2.99")
        return {"counts": {"restricted_devices": 2, "required_firewall_rules_seen": 9, "required_firewall_rules_expected": 9}}

    def get_service_contract_health(self, definitions):
        if not self.connected:
            raise RuntimeError("router contracts unavailable token=do-not-export")
        return {"available": True, "healthy": 1, "total": 1, "degraded": 0, "reporting_only": 0, "detector_addresses": 2}


class ActivityStore:
    def __init__(self, healthy=True, error=None):
        self.healthy = healthy
        self.error = error

    def health(self):
        if self.error:
            raise RuntimeError(self.error)
        return self.healthy


class SnapshotProvider:
    def __init__(self, payload, error=None):
        self.payload = payload
        self.error = error

    def snapshot(self):
        if self.error:
            raise RuntimeError(self.error)
        return self.payload


class Performance:
    def __init__(self, error=None):
        self.error = error

    def snapshot(self):
        if self.error:
            raise RuntimeError(self.error)
        return {
            "enabled": True,
            "process": {"python": "3.13", "uptime_seconds": 60, "current_rss_mb": 50, "max_rss_mb": 55, "threads": 7},
            "request_summary": {"retained": 4, "p50_ms": 10, "p95_ms": 20, "p99_ms": 25, "max_ms": 30, "slow_count": 0},
            "routes": [],
            "components": [],
        }


def fresh_ingest(**overrides):
    payload = {
        "availability": "available",
        "age_seconds": 2.0,
        "dns_source": "available",
        "ipfix_source": "available",
        "flow_queue_depth": 0,
    }
    payload.update(overrides)
    return payload


def fresh_classifier(**overrides):
    payload = {
        "availability": "available",
        "source": "live",
        "services": 4,
        "signatures": 20,
        "has_live": True,
        "degraded": False,
        "age_seconds": 2.0,
        "error": "",
    }
    payload.update(overrides)
    return payload


def build_service(
    *,
    router=None,
    activity=None,
    ingest=None,
    classifier=None,
    reconciler=None,
    incident=None,
    delivery=None,
    performance=None,
    policy_store=None,
):
    return OperationalDiagnostics(
        app_version="0.54.2",
        policy_store=policy_store or PolicyStore(),
        router=router or Router(),
        activity_store=activity or ActivityStore(),
        reconciler=reconciler or SnapshotProvider({
            "worker_alive": True, "busy": False, "mode": "report", "hold_active": False,
            "consecutive_failures": 0, "last": {"result": "ok"},
        }),
        incident_monitor=incident or SnapshotProvider({
            "enabled": True, "worker_alive": True, "counts": {"active": 0, "resolved": 1},
        }),
        summary_delivery=delivery or SnapshotProvider({
            "enabled": False, "worker_running": False, "stats": {"pending": 0, "failed": 0},
        }),
        performance_collector=performance or Performance(),
        service_contract_loader=lambda: [],
        ingest_status_loader=(lambda: ingest if ingest is not None else fresh_ingest()),
        classifier_status_loader=(lambda: classifier if classifier is not None else fresh_classifier()),
    )


def by_key(report):
    return {row["key"]: row for row in report["checks"]}


class TelemetryIngestStatusReaderTests(unittest.TestCase):
    def test_fresh_status_preserves_independent_sources_without_raw_detail(self):
        now = datetime(2026, 9, 10, 12, 0, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ingest-status.json"
            path.write_text(json.dumps({
                "schema": "zen_telemetry_ingest_status_v1",
                "observed_at": (now - timedelta(seconds=4)).isoformat(),
                "dns_source": "unavailable",
                "ipfix_source": "available",
                "flow_queue_depth": 12,
                "error": "password=super-secret host=192.0.2.123",
            }))
            result = read_telemetry_ingest_status(path, now=now, stale_after_seconds=30)
        self.assertEqual(result["availability"], "available")
        self.assertEqual(result["dns_source"], "unavailable")
        self.assertEqual(result["ipfix_source"], "available")
        self.assertEqual(result["flow_queue_depth"], 12)
        self.assertEqual(result["age_seconds"], 4.0)
        self.assertNotIn("error", result)
        self.assertNotIn("super-secret", json.dumps(result))

    def test_stale_status_does_not_preserve_old_source_health(self):
        now = datetime(2026, 9, 10, 12, 0, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ingest-status.json"
            path.write_text(json.dumps({
                "schema": "zen_telemetry_ingest_status_v1",
                "observed_at": (now - timedelta(seconds=90)).isoformat(),
                "dns_source": "available", "ipfix_source": "available", "flow_queue_depth": 0,
            }))
            result = read_telemetry_ingest_status(path, now=now, stale_after_seconds=30)
        self.assertEqual(result["availability"], "stale")
        self.assertEqual(result["dns_source"], "unknown")
        self.assertEqual(result["ipfix_source"], "unknown")
        self.assertIsNone(result["flow_queue_depth"])

    def test_missing_and_malformed_status_are_unavailable_and_sanitized(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ingest-status.json"
            missing = read_telemetry_ingest_status(path)
            path.write_text('{"schema":"wrong","password":"do-not-export"}')
            malformed = read_telemetry_ingest_status(path)
        self.assertEqual(missing["availability"], "unavailable")
        self.assertEqual(malformed["availability"], "unavailable")
        self.assertIsNone(missing["flow_queue_depth"])
        self.assertIsNone(malformed["flow_queue_depth"])
        self.assertNotIn("do-not-export", json.dumps(malformed))


class IngestDependencyBoundaryTests(unittest.TestCase):
    def _load_ingest(self):
        import importlib.util
        import sys
        import types
        ingest_dir = ROOT / "telemetry" / "ingest"
        sys.path.insert(0, str(ingest_dir))
        saved = {name: sys.modules.get(name) for name in ("psycopg", "dns", "dns.resolver")}
        if saved["psycopg"] is None:
            sys.modules["psycopg"] = types.SimpleNamespace(connect=lambda **kwargs: None)
        if saved["dns"] is None or saved["dns.resolver"] is None:
            dns_module = types.ModuleType("dns")
            resolver_module = types.ModuleType("dns.resolver")
            resolver_module.Resolver = object
            dns_module.resolver = resolver_module
            sys.modules["dns"] = dns_module
            sys.modules["dns.resolver"] = resolver_module
        try:
            spec = importlib.util.spec_from_file_location("zen_v047_ingest_test", ingest_dir / "ingest.py")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module
        finally:
            sys.path.pop(0)
            for name, value in saved.items():
                if value is None:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = value

    def test_postgresql_write_failure_does_not_relabel_pihole_source_unavailable(self):
        import sqlite3
        ingest = self._load_ingest()
        class StopWorker(BaseException):
            pass
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "pihole-FTL.db"
            conn = sqlite3.connect(db_path)
            conn.execute("CREATE TABLE queries(id INTEGER, timestamp INTEGER, type INTEGER, status INTEGER, domain TEXT, client TEXT, reply_type INTEGER, reply_time REAL)")
            conn.execute("INSERT INTO queries VALUES(1, 1789041600, 1, 0, 'example.invalid', '192.168.2.10', 1, 0.1)")
            conn.commit(); conn.close()
            ingest.PIHOLE_DB = str(db_path)
            ingest.PIHOLE_DNS = "pihole"
            class OpenDns:
                def __enter__(self): return self
                def __exit__(self, *args): return False
            ingest.socket.create_connection = lambda *args, **kwargs: OpenDns()
            ingest.load_state = lambda: {"last_dns_id": 0}
            ingest.save_state = lambda state: None
            ingest.resolve_domain = lambda domain, service: None
            ingest.classify_domain = lambda domain: ""
            ingest.db_connect = lambda: (_ for _ in ()).throw(RuntimeError("postgres down"))
            ingest.time.sleep = lambda seconds: (_ for _ in ()).throw(StopWorker())
            with self.assertRaises(StopWorker):
                ingest.dns_worker()
        self.assertEqual(ingest.source_status_snapshot()["dns_source"], "available")

    def test_stale_pihole_volume_does_not_hide_dns_listener_outage(self):
        import sqlite3
        ingest = self._load_ingest()
        class StopWorker(BaseException):
            pass
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "pihole-FTL.db"
            conn = sqlite3.connect(db_path)
            conn.execute("CREATE TABLE queries(id INTEGER, timestamp INTEGER, type INTEGER, status INTEGER, domain TEXT, client TEXT, reply_type INTEGER, reply_time REAL)")
            conn.commit(); conn.close()
            ingest.PIHOLE_DB = str(db_path)
            ingest.PIHOLE_DNS = "pihole"
            ingest.socket.create_connection = lambda *args, **kwargs: (_ for _ in ()).throw(OSError("DNS listener down"))
            ingest.db_connect = lambda: (_ for _ in ()).throw(AssertionError("PostgreSQL must not be probed"))
            ingest.time.sleep = lambda seconds: (_ for _ in ()).throw(StopWorker())
            with self.assertRaises(StopWorker):
                ingest.dns_worker()
        self.assertEqual(ingest.source_status_snapshot()["dns_source"], "unavailable")

    def test_missing_pihole_source_is_unavailable_without_touching_postgresql(self):
        ingest = self._load_ingest()
        class StopWorker(BaseException):
            pass
        with tempfile.TemporaryDirectory() as tmp:
            ingest.PIHOLE_DB = str(Path(tmp) / "missing.db")
            ingest.db_connect = lambda: (_ for _ in ()).throw(AssertionError("PostgreSQL must not be probed"))
            ingest.time.sleep = lambda seconds: (_ for _ in ()).throw(StopWorker())
            with self.assertRaises(StopWorker):
                ingest.dns_worker()
        self.assertEqual(ingest.source_status_snapshot()["dns_source"], "unavailable")


class OperationalDependencyChaosTests(unittest.TestCase):
    def test_postgresql_failure_isolated_from_ingest_dns_and_router(self):
        report = build_service(activity=ActivityStore(error="postgres password=hunter2")).capture()
        checks = by_key(report)
        self.assertEqual(checks["telemetry"]["state"], "offline")
        self.assertEqual(checks["traffic_ingest"]["state"], "healthy")
        self.assertEqual(checks["dns_source"]["state"], "healthy")
        self.assertEqual(checks["ipfix_source"]["state"], "healthy")
        self.assertEqual(checks["routeros_api"]["state"], "healthy")
        self.assertNotIn("hunter2", json.dumps(report))

    def test_traffic_ingest_stale_is_offline_without_claiming_sources_healthy(self):
        report = build_service(ingest=fresh_ingest(
            availability="stale", age_seconds=95.0, dns_source="unknown", ipfix_source="unknown"
        )).capture()
        checks = by_key(report)
        self.assertEqual(checks["traffic_ingest"]["state"], "offline")
        self.assertEqual(checks["dns_source"]["state"], "offline")
        self.assertEqual(checks["ipfix_source"]["state"], "offline")
        self.assertIn("cannot be proven", checks["dns_source"]["summary"].lower())
        self.assertEqual(checks["telemetry"]["state"], "healthy")

    def test_pihole_dns_failure_isolated_from_ipfix_and_ingest_process(self):
        report = build_service(ingest=fresh_ingest(dns_source="unavailable", ipfix_source="available")).capture()
        checks = by_key(report)
        self.assertEqual(checks["traffic_ingest"]["state"], "healthy")
        self.assertEqual(checks["dns_source"]["state"], "offline")
        self.assertEqual(checks["ipfix_source"]["state"], "healthy")
        self.assertEqual(checks["telemetry"]["state"], "healthy")

    def test_ipfix_failure_isolated_from_dns_and_ingest_process(self):
        report = build_service(ingest=fresh_ingest(dns_source="available", ipfix_source="unavailable")).capture()
        checks = by_key(report)
        self.assertEqual(checks["traffic_ingest"]["state"], "healthy")
        self.assertEqual(checks["dns_source"]["state"], "healthy")
        self.assertEqual(checks["ipfix_source"]["state"], "offline")

    def test_classifier_stale_live_is_warning_not_healthy_or_offline(self):
        report = build_service(classifier=fresh_classifier(
            source="stale_live", degraded=True, has_live=True, error="secret=/run/hidden"
        )).capture()
        check = by_key(report)["classifier_consumer"]
        self.assertEqual(check["state"], "warning")
        self.assertIn("last-known-good", check["summary"].lower())
        self.assertNotIn("/run/hidden", json.dumps(report))

    def test_classifier_stale_heartbeat_is_offline(self):
        report = build_service(classifier=fresh_classifier(
            availability="stale", degraded=True, source="live", age_seconds=90.0
        )).capture()
        check = by_key(report)["classifier_consumer"]
        self.assertEqual(check["state"], "offline")
        self.assertNotIn("healthy", check["summary"].lower())

    def test_routeros_failure_does_not_erase_local_or_telemetry_dependency_checks(self):
        report = build_service(router=Router(connected=False)).capture()
        checks = by_key(report)
        self.assertEqual(checks["routeros_api"]["state"], "offline")
        self.assertEqual(checks["security_authority"]["state"], "critical")
        self.assertEqual(checks["telemetry"]["state"], "healthy")
        self.assertEqual(checks["traffic_ingest"]["state"], "healthy")
        self.assertEqual(checks["policy_database"]["state"], "healthy")
        dumped = json.dumps(report)
        self.assertNotIn("192.0.2.99", dumped)
        self.assertNotIn("do-not-export", dumped)

    def test_non_router_probe_exception_isolated_and_sanitized(self):
        report = build_service(
            reconciler=SnapshotProvider({}, error="reconciler token=secret-one"),
            incident=SnapshotProvider({}, error="incident password=secret-two"),
            delivery=SnapshotProvider({}, error="smtp_password=secret-three"),
            performance=Performance(error="request path /private?token=secret-four"),
        ).capture()
        checks = by_key(report)
        self.assertEqual(checks["application"]["state"], "warning")
        self.assertEqual(checks["reconciler"]["state"], "critical")
        self.assertEqual(checks["incidents"]["state"], "critical")
        self.assertEqual(checks["summary_delivery"]["state"], "critical")
        self.assertEqual(checks["telemetry"]["state"], "healthy")
        self.assertEqual(checks["application"]["facts"]["threads"], "unknown")
        self.assertEqual(checks["reconciler"]["facts"]["mode"], "unknown")
        self.assertEqual(checks["incidents"]["facts"]["active"], "unknown")
        self.assertEqual(checks["summary_delivery"]["facts"]["enabled"], "unknown")
        self.assertFalse(report["performance"]["available"])
        self.assertIsNone(report["performance"]["requests"]["p95_ms"])
        dumped = json.dumps(report)
        for secret in ("secret-one", "secret-two", "secret-three", "secret-four", "/private"):
            self.assertNotIn(secret, dumped)

    def test_loader_exception_does_not_crash_capture_or_leak_error(self):
        service = build_service()
        service.ingest_status_loader = lambda: (_ for _ in ()).throw(RuntimeError("password=ingest-secret"))
        service.classifier_status_loader = lambda: (_ for _ in ()).throw(RuntimeError("token=classifier-secret"))
        report = service.capture()
        checks = by_key(report)
        self.assertEqual(checks["traffic_ingest"]["state"], "offline")
        self.assertEqual(checks["classifier_consumer"]["state"], "offline")
        dumped = json.dumps(report)
        self.assertNotIn("ingest-secret", dumped)
        self.assertNotIn("classifier-secret", dumped)


class OperationalDiagnosticsV047IntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.main = (ROOT / "app/main.py").read_text()
        cls.diag = (ROOT / "app/diagnostics.py").read_text()
        cls.ingest = (ROOT / "telemetry/ingest/ingest.py").read_text()
        cls.compose = (ROOT / "docker-compose.yml").read_text()
        cls.template = (ROOT / "app/templates/diagnostics.html").read_text()
        cls.help = (ROOT / "app/help_content.py").read_text()

    def test_release_and_diagnostics_assets_are_v047(self):
        self.assertIn('version="0.54.2"', self.main)
        self.assertIn('/static/diagnostics.css?v=0.54.2', self.template)

    def test_ingest_publishes_sanitized_independent_dependency_status(self):
        self.assertIn("zen_telemetry_ingest_status_v1", self.ingest)
        self.assertIn("INGEST_STATUS_FILE", self.ingest)
        self.assertIn('"dns_source"', self.ingest)
        self.assertIn('"ipfix_source"', self.ingest)
        self.assertIn("flow_queue_depth", self.ingest)
        self.assertNotIn('"error":str(exc)', self.ingest.replace(" ", ""))

    def test_compose_shares_ingest_status_read_only_with_control_app(self):
        self.assertIn("INGEST_STATUS_FILE: /state/ingest-status.json", self.compose)
        self.assertIn("INGEST_STATUS_FILE: /telemetry-state/ingest-status.json", self.compose)
        self.assertIn("telemetry-state:/telemetry-state:ro", self.compose)

    def test_main_wires_both_status_readers_into_diagnostics(self):
        self.assertIn("read_telemetry_ingest_status", self.main)
        self.assertIn("read_classifier_consumer_status", self.main)
        segment = self.main[self.main.index("operational_diagnostics = OperationalDiagnostics("):]
        self.assertIn("ingest_status_loader=read_telemetry_ingest_status", segment)
        self.assertIn("classifier_status_loader=read_classifier_consumer_status", segment)

    def test_help_explains_dependency_isolation_and_no_health_inference(self):
        self.assertIn("traffic-ingest", self.help)
        self.assertIn("Pi-hole", self.help)
        self.assertIn("does not infer healthy", self.help)


if __name__ == "__main__":
    unittest.main()
