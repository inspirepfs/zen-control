import io
import json
import ast
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

from app.support_bundle import build_commissioning_report, build_support_bundle


ROOT = Path(__file__).resolve().parents[1]


def commissioning_functions(capture):
    """Load just the composition functions without importing the web app."""
    source = ast.parse((ROOT / "app/main.py").read_text())
    names = {"_captured_commissioning_evidence", "current_commissioning_report", "current_support_bundle"}
    nodes = [node for node in source.body if isinstance(node, ast.FunctionDef) and node.name in names]
    runtime_probe = Mock(side_effect=AssertionError("duplicate runtime probe"))
    readiness_probe = Mock(side_effect=AssertionError("duplicate readiness probe"))
    namespace = {
        "app": SimpleNamespace(version="0.59.0"),
        "operational_diagnostics": SimpleNamespace(capture=capture),
        "build_runtime_health": runtime_probe,
        "operations_monitor": SimpleNamespace(readiness=readiness_probe),
        "current_secure_transport_status": lambda: {"commissioning_ready": False, "local_https": {}, "pwa": {}},
        "push_delivery": SimpleNamespace(snapshot=lambda: {"worker_running": True, "subscriptions": {}}),
        "status_contract": lambda _version: {"mode": "online_first"},
        "build_commissioning_report": build_commissioning_report,
        "build_support_bundle": build_support_bundle,
        "policy_store": SimpleNamespace(list_audit=lambda _limit: []),
        "environment_presence": lambda: {},
        "audit_event_summary": lambda _rows: {},
    }
    exec(compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])), str(ROOT / "app/main.py"), "exec"), namespace)
    return namespace, runtime_probe, readiness_probe


def captured_diagnostics(**states):
    defaults = {
        "application": "healthy", "policy_database": "healthy",
        "routeros_api": "healthy", "security_authority": "healthy",
        "managed_inventory": "healthy", "service_contracts": "healthy",
        "telemetry": "healthy", "traffic_ingest": "healthy", "dns_source": "healthy",
        "ipfix_source": "healthy", "classifier_consumer": "healthy",
        "reconciler": "healthy", "incidents": "healthy",
        "summary_delivery": "healthy", "durable_evidence": "healthy",
    }
    defaults.update(states)
    return {
        "schema": "zen_operational_diagnostics_v1",
        "captured_at": "2026-09-16T12:00:00+00:00",
        "checks": [
            {"key": key, "state": state, "summary": f"{key} {state}"}
            for key, state in defaults.items()
        ],
    }


class CommissioningCaptureCoherenceTests(unittest.TestCase):
    def test_supplied_capture_is_the_only_operational_readiness_evidence(self):
        diagnostics = captured_diagnostics(routeros_api="offline", security_authority="critical", reconciler="offline")
        namespace, runtime_probe, readiness_probe = commissioning_functions(Mock(return_value=diagnostics))
        evidence = namespace["current_commissioning_report"](diagnostics, include_evidence=True)

        report = evidence["commissioning"]
        by_key = {row["key"]: row for row in report["checks"]}
        self.assertEqual(report["captured_at"], diagnostics["captured_at"])
        self.assertEqual(by_key["routeros_api"]["state"], "unavailable")
        self.assertEqual(by_key["security_authority"]["state"], "blocked")
        self.assertEqual(by_key["reconciler"]["state"], "unavailable")
        self.assertEqual(by_key["operations_readiness"]["state"], "blocked")
        self.assertEqual(report["overall"], "blocked")
        self.assertEqual(evidence["operations"]["evidence"], "operational_diagnostics_capture")
        runtime_probe.assert_not_called()
        readiness_probe.assert_not_called()

    def test_support_bundle_reuses_its_capture_without_duplicate_readiness_probes(self):
        diagnostics = captured_diagnostics(routeros_api="offline")
        capture = Mock(return_value=diagnostics)
        namespace, runtime_probe, readiness_probe = commissioning_functions(capture)
        bundle, _manifest, commissioning = namespace["current_support_bundle"]()

        self.assertEqual(capture.call_count, 1)
        self.assertEqual(commissioning["captured_at"], diagnostics["captured_at"])
        with zipfile.ZipFile(io.BytesIO(bundle)) as archive:
            bundled = json.loads(archive.read("commissioning.json"))
        self.assertEqual(bundled["captured_at"], diagnostics["captured_at"])
        self.assertEqual(bundled["overall"], "blocked")
        runtime_probe.assert_not_called()
        readiness_probe.assert_not_called()


if __name__ == "__main__":
    unittest.main()
