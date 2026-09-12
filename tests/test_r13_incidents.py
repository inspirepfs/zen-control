import tempfile
import unittest
from pathlib import Path

from app.incidents import IncidentMonitor
from app.policy_store import PolicyStore


class FakeRouter:
    def __init__(self):
        self.ready = True
        self.warning = False

    def get_security_posture(self):
        checks = []
        if not self.ready:
            checks.append({
                "name": "Global MASTER authority",
                "key": "master",
                "severity": "critical",
                "status": "fail",
            })
        if self.warning:
            checks.append({
                "name": "Optional hardening",
                "key": "optional",
                "severity": "warning",
                "status": "warn",
            })
        return {
            "enforcement_ready": self.ready,
            "checks": checks,
        }


class FakeReconciler:
    def __init__(self):
        self.hold = False
        self.last_result = "ok"

    def snapshot(self):
        return {
            "worker_alive": True,
            "hold_active": self.hold,
            "hold_until": "2030-01-01T00:00:00+00:00" if self.hold else None,
            "consecutive_failures": 3 if self.hold else 0,
            "last": {
                "result": self.last_result,
                "summary": "test reconciliation state",
                "failures": ["192.168.2.22: test"] if self.last_result == "failed" else [],
            },
        }


class FakeOperations:
    def __init__(self):
        self.ok = True

    def readiness(self):
        return {
            "ok": self.ok,
            "issues": [] if self.ok else ["RouterOS API"],
        }


class FakeActivity:
    def __init__(self):
        self.evidence = []
        self.error = None

    def bypass_evidence(self, managed_ips, hours, limit):
        if self.error:
            raise RuntimeError(self.error)
        return list(self.evidence)


class IncidentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = PolicyStore(str(Path(self.tmp.name) / "policy.db"))

    def tearDown(self):
        self.tmp.cleanup()

    def test_store_deduplicates_acknowledges_resolves_and_reopens_after_clear(self):
        first = self.store.upsert_incident(
            fingerprint="security:test",
            source="security",
            severity="critical",
            title="Broken authority",
            detail="first",
        )
        self.assertEqual(first["action"], "opened")
        second = self.store.upsert_incident(
            fingerprint="security:test",
            source="security",
            severity="critical",
            title="Broken authority",
            detail="first",
        )
        self.assertEqual(second["action"], "unchanged")
        self.assertEqual(second["id"], first["id"])
        self.assertEqual(second["occurrences"], 2)

        ack = self.store.acknowledge_incident(first["id"], "operator")
        self.assertEqual(ack["status"], "acknowledged")

        repeated = self.store.upsert_incident(
            fingerprint="security:test",
            source="security",
            severity="critical",
            title="Broken authority",
            detail="still broken",
        )
        self.assertEqual(repeated["status"], "acknowledged")

        resolved = self.store.resolve_incident(first["id"], "operator", "fixed")
        self.assertEqual(resolved["status"], "resolved")
        suppressed = self.store.upsert_incident(
            fingerprint="security:test",
            source="security",
            severity="critical",
            title="Broken authority",
            detail="still present",
        )
        self.assertEqual(suppressed["action"], "suppressed")
        self.assertEqual(suppressed["status"], "resolved")

        self.store.resolve_inactive_incidents("security", set())
        reopened = self.store.upsert_incident(
            fingerprint="security:test",
            source="security",
            severity="critical",
            title="Broken authority",
            detail="returned after clear",
        )
        self.assertEqual(reopened["action"], "reopened")
        self.assertEqual(reopened["status"], "open")
        self.assertEqual(reopened["acknowledged_by"], "")

    def test_auto_resolve_is_scoped_to_source(self):
        self.store.upsert_incident(
            fingerprint="security:a", source="security", severity="warning",
            title="A", detail="a"
        )
        self.store.upsert_incident(
            fingerprint="bypass:a", source="bypass", severity="warning",
            title="B", detail="b"
        )
        resolved = self.store.resolve_inactive_incidents("security", set())
        self.assertEqual(len(resolved), 1)
        active = self.store.list_incidents()
        self.assertEqual([item["fingerprint"] for item in active], ["bypass:a"])

    def test_incident_settings_validation(self):
        saved = self.store.save_incident_settings("1", "120", "high", "60")
        self.assertEqual(saved["incident_monitor_enabled"], "1")
        self.assertEqual(saved["incident_scan_interval_seconds"], "120")
        self.assertEqual(saved["incident_bypass_min_status"], "high")
        with self.assertRaises(ValueError):
            self.store.save_incident_settings("1", "10", "high", "60")
        with self.assertRaises(ValueError):
            self.store.save_incident_settings("1", "60", "anything", "60")

    def make_monitor(self, *, devices=None, policy_loader=None):
        router = FakeRouter()
        reconciler = FakeReconciler()
        operations = FakeOperations()
        activity = FakeActivity()
        audits = []
        monitor = IncidentMonitor(
            policy_store=self.store,
            router=router,
            reconciler=reconciler,
            operations=operations,
            activity_store=activity,
            device_loader=lambda: list(devices or []),
            policy_loader=policy_loader or (lambda ip: {"quota_state": {"configured": False}}),
            audit=lambda event, actor, detail="": audits.append((event, actor, detail)),
        )
        return monitor, router, reconciler, operations, activity, audits

    def test_security_incident_auto_resolves_after_successful_clear_scan(self):
        monitor, router, *_ = self.make_monitor()
        router.ready = False
        first = monitor.run_cycle("manual")
        self.assertEqual(first["opened"], 1)
        active = self.store.list_incidents()
        self.assertTrue(any(i["fingerprint"] == "security:enforcement-authority" for i in active))

        router.ready = True
        second = monitor.run_cycle("manual")
        self.assertGreaterEqual(second["resolved"], 1)
        self.assertFalse(any(i["fingerprint"] == "security:enforcement-authority" for i in self.store.list_incidents()))

    def test_security_only_readiness_failure_does_not_duplicate_incident(self):
        monitor, router, _, operations, _, _ = self.make_monitor()
        router.ready = False
        operations.ok = False
        # Mirror OperationsMonitor: the only readiness issue is the security posture.
        operations.readiness = lambda: {"ok": False, "issues": ["RouterOS enforcement posture"]}
        monitor.run_cycle("manual")
        active = self.store.list_incidents()
        fingerprints = {item["fingerprint"] for item in active}
        self.assertIn("security:enforcement-authority", fingerprints)
        self.assertNotIn("operations:not-ready", fingerprints)

    def test_reconciler_hold_becomes_critical_incident(self):
        monitor, _, reconciler, *_ = self.make_monitor()
        reconciler.hold = True
        monitor.run_cycle("manual")
        incident = next(i for i in self.store.list_incidents() if i["fingerprint"] == "reconciler:cooldown-hold")
        self.assertEqual(incident["severity"], "critical")

    def test_bypass_incident_threshold_and_telemetry_failure_does_not_false_clear(self):
        devices = [{"ip": "192.168.2.22"}]
        monitor, _, _, _, activity, _ = self.make_monitor(devices=devices)
        activity.evidence = [
            {
                "client_ip": "192.168.2.22",
                "key": "known_doh_flow",
                "weight": 18,
                "flows": 3,
                "category": "dns",
                "confidence": "high",
                "last_seen": "2026-09-08T20:00:00+00:00",
            },
            {
                "client_ip": "192.168.2.22",
                "key": "external_dns",
                "weight": 16,
                "flows": 2,
                "category": "dns",
                "confidence": "high",
                "last_seen": "2026-09-08T20:01:00+00:00",
            },
        ]
        monitor.run_cycle("manual")
        self.assertTrue(any(i["fingerprint"] == "bypass:192.168.2.22" for i in self.store.list_incidents()))

        activity.error = "postgres offline"
        monitor.run_cycle("manual")
        active = self.store.list_incidents()
        self.assertTrue(any(i["fingerprint"] == "bypass:192.168.2.22" for i in active))
        self.assertTrue(any(i["fingerprint"] == "telemetry:bypass-unavailable" for i in active))

    def test_quota_warning_and_exhaustion_are_deduplicated(self):
        devices = [{"ip": "192.168.2.22"}]
        state = {
            "configured": True,
            "enabled": True,
            "available": True,
            "daily": {
                "warning": True,
                "exhausted": False,
                "percent": 85.0,
                "used_human": "850 MiB",
                "limit_mb": 1000,
                "action": "blocked",
            },
            "services": [],
        }
        monitor, *_ = self.make_monitor(
            devices=devices,
            policy_loader=lambda ip: {"quota_state": state},
        )
        monitor.run_cycle("manual")
        incident = next(i for i in self.store.list_incidents() if i["fingerprint"] == "quota:192.168.2.22:daily")
        self.assertIn("nearing", incident["title"].lower())

        state["daily"]["exhausted"] = True
        state["daily"]["percent"] = 101.0
        monitor.run_cycle("manual")
        incidents = [i for i in self.store.list_incidents() if i["fingerprint"] == "quota:192.168.2.22:daily"]
        self.assertEqual(len(incidents), 1)
        self.assertIn("exhausted", incidents[0]["title"].lower())

    def test_disabled_background_scan_does_not_touch_incidents(self):
        self.store.save_incident_settings("0", "60", "elevated", "30")
        monitor, router, *_ = self.make_monitor()
        router.ready = False
        result = monitor.run_cycle("scheduled")
        self.assertEqual(result["result"], "disabled")
        self.assertEqual(self.store.incident_counts()["active"], 0)
        # Manual scan remains available while background monitoring is disabled.
        manual = monitor.run_cycle("manual")
        self.assertNotEqual(manual["result"], "disabled")
        self.assertGreater(self.store.incident_counts()["active"], 0)


if __name__ == "__main__":
    unittest.main()
