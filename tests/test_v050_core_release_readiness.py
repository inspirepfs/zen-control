import json
import tempfile
import unittest
from pathlib import Path

from app.operations import OperationsMonitor
from app.policy_store import PolicyStore


class _Router:
    def __init__(self, *, connected=True, ready=True):
        self.connected = connected
        self.ready = ready

    def health(self):
        return {"connected": self.connected, "router": "ZEN"}

    def get_security_posture(self):
        return {
            "enforcement_ready": self.ready,
            "status": "hardened" if self.ready else "critical",
            "score": 100 if self.ready else 50,
            "critical_count": 0 if self.ready else 1,
            "warning_count": 0,
        }

    def get_managed_state_inventory(self):
        return {"router": "ZEN", "counts": {}}


class _Reconciler:
    def __init__(self, *, alive=True, raises=False):
        self.alive = alive
        self.raises = raises

    def snapshot(self):
        if self.raises:
            raise RuntimeError("worker internals exploded")
        return {
            "worker_alive": self.alive,
            "mode": "observe",
            "hold_active": False,
            "last": {"result": "ok"},
        }


class _FailingIntegrityStore:
    def __init__(self, delegate):
        self.delegate = delegate

    def database_integrity_report(self):
        raise RuntimeError("sqlite path=/secret/data failed")

    def __getattr__(self, name):
        return getattr(self.delegate, name)


class OperationsReadinessClosureTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = PolicyStore(str(Path(self.tmp.name) / "policy.db"))

    def tearDown(self):
        self.tmp.cleanup()

    def make(self, *, router=None, reconciler=None):
        return OperationsMonitor(
            policy_store=self.store,
            router=router or _Router(),
            reconciler=reconciler or _Reconciler(),
            audit=lambda *_: None,
            app_version="0.50.0",
        )

    def test_readiness_does_not_treat_connected_false_as_ready(self):
        report = self.make(router=_Router(connected=False)).readiness()
        self.assertFalse(report["ok"])
        self.assertEqual("fail", report["components"]["router"])
        self.assertIn("RouterOS API", report["issues"])

    def test_startup_does_not_treat_connected_false_as_ready(self):
        report = self.make(router=_Router(connected=False)).startup_check()
        self.assertEqual("degraded", report["status"])
        self.assertFalse(report["router"]["ok"])

    def test_readiness_contains_reconciler_probe_failure(self):
        report = self.make(reconciler=_Reconciler(raises=True)).readiness()
        self.assertFalse(report["ok"])
        self.assertEqual("fail", report["components"]["reconciler"])
        self.assertIn("reconciliation worker", report["issues"])
        self.assertEqual("unknown", report["reconciler"]["mode"])

    def test_readiness_contains_database_probe_failure(self):
        monitor = OperationsMonitor(
            policy_store=_FailingIntegrityStore(self.store),
            router=_Router(),
            reconciler=_Reconciler(),
            audit=lambda *_: None,
            app_version="0.50.0",
        )
        report = monitor.readiness()
        self.assertFalse(report["ok"])
        self.assertEqual("fail", report["components"]["database"])
        self.assertNotIn("/secret/data", str(report))

    def test_startup_contains_database_probe_failure(self):
        monitor = OperationsMonitor(
            policy_store=_FailingIntegrityStore(self.store),
            router=_Router(),
            reconciler=_Reconciler(),
            audit=lambda *_: None,
            app_version="0.50.0",
        )
        report = monitor.startup_check()
        self.assertEqual("degraded", report["status"])
        self.assertFalse(report["database"]["ok"])
        self.assertNotIn("/secret/data", str(report))

    def test_startup_audit_records_release_identity(self):
        audit = []
        monitor = OperationsMonitor(
            policy_store=self.store,
            router=_Router(),
            reconciler=_Reconciler(),
            audit=lambda event, actor, detail: audit.append((event, actor, detail)),
            app_version="0.50.0",
        )
        monitor.startup_check()
        self.assertIn("version=0.50.0", audit[-1][2])


class ReleaseReadinessContractTests(unittest.TestCase):
    def setUp(self):
        from app.release_readiness import build_release_readiness
        self.build = build_release_readiness

    @staticmethod
    def inputs():
        return {
            "version": "0.50.0",
            "operations": {"ok": True, "issues": []},
            "startup": {"status": "ready", "issues": []},
            "diagnostics": {"overall": "healthy", "counts": {"healthy": 12, "warning": 0, "critical": 0, "offline": 0}},
            "performance": {"acceptance": {"state": "pass", "targets": []}},
            "config_smoke": {"state": "pass", "source_digest": "abc", "restored_digest": "abc"},
            "restart": {"state": "pass", "summary": "Controlled restart observed"},
            "auth": {"shared_display_mode": True, "totp_count": 1, "login_mode": "password_totp", "recovery_codes_remaining": 5},
            "pwa": {
                "mode": "online_first",
                "cached_private_data": False,
                "offline_mutations": False,
                "background_sync": False,
                "push_notifications": False,
                "server_auth_required": True,
                "shared_display_lock_server_enforced": True,
            },
        }

    def test_all_core_live_evidence_passes(self):
        result = self.build(**self.inputs())
        self.assertEqual("pass", result["state"])
        self.assertTrue(result["core_ready"])
        self.assertEqual("zen_release_readiness_v1", result["schema"])

    def test_performance_pending_keeps_release_pending(self):
        values = self.inputs()
        values["performance"]["acceptance"]["state"] = "pending"
        result = self.build(**values)
        self.assertEqual("pending", result["state"])
        self.assertFalse(result["core_ready"])

    def test_performance_failure_blocks_release(self):
        values = self.inputs()
        values["performance"]["acceptance"]["state"] = "fail"
        result = self.build(**values)
        self.assertEqual("fail", result["state"])

    def test_diagnostic_warning_is_pending_not_healthy(self):
        values = self.inputs()
        values["diagnostics"]["overall"] = "warning"
        values["diagnostics"]["counts"]["warning"] = 1
        result = self.build(**values)
        self.assertEqual("pending", result["state"])

    def test_diagnostic_offline_blocks_release(self):
        values = self.inputs()
        values["diagnostics"]["overall"] = "offline"
        result = self.build(**values)
        self.assertEqual("fail", result["state"])

    def test_uncommissioned_shared_display_is_explicit_pending(self):
        values = self.inputs()
        values["auth"]["shared_display_mode"] = False
        result = self.build(**values)
        row = next(item for item in result["checks"] if item["key"] == "shared_display")
        self.assertEqual("pending", row["state"])
        self.assertEqual("pending", result["state"])

    def test_invalid_shared_display_security_contract_blocks_release(self):
        values = self.inputs()
        values["pwa"]["shared_display_lock_server_enforced"] = False
        result = self.build(**values)
        row = next(item for item in result["checks"] if item["key"] == "pwa_security")
        self.assertEqual("fail", row["state"])
        self.assertEqual("fail", result["state"])

    def test_https_and_notifications_remain_deferred_and_do_not_block_core(self):
        result = self.build(**self.inputs())
        deferred = {item["key"]: item for item in result["deferred"]}
        self.assertEqual("deferred", deferred["https_remote_access"]["state"])
        self.assertEqual("deferred", deferred["notifications"]["state"])
        self.assertEqual("pass", result["state"])

    def test_push_enablement_before_human_gate_breaks_pwa_safety_contract(self):
        values = self.inputs()
        values["pwa"]["push_notifications"] = True
        result = self.build(**values)
        row = next(item for item in result["checks"] if item["key"] == "pwa_security")
        self.assertEqual("fail", row["state"])

    def test_release_report_does_not_echo_raw_startup_exception_text(self):
        values = self.inputs()
        values["startup"]["issues"] = ["connection failed password=hunter2 host=192.0.2.9"]
        result = self.build(**values)
        serialized = json.dumps(result)
        self.assertNotIn("hunter2", serialized)
        self.assertNotIn("192.0.2.9", serialized)

    def test_unavailable_parent_auth_is_fail_not_uncommissioned_pending(self):
        values = self.inputs()
        values["auth"]["available"] = False
        result = self.build(**values)
        row = next(item for item in result["checks"] if item["key"] == "shared_display")
        self.assertEqual("fail", row["state"])

    def test_totp_only_shared_display_requires_recovery_code(self):
        values = self.inputs()
        values["auth"]["login_mode"] = "totp_only"
        values["auth"]["recovery_codes_remaining"] = 0
        result = self.build(**values)
        row = next(item for item in result["checks"] if item["key"] == "shared_display")
        self.assertEqual("fail", row["state"])

    def test_parent_journey_matrix_is_source_qualified_not_live_evidence(self):
        result = self.build(**self.inputs())
        self.assertGreaterEqual(len(result["parent_journeys"]), 6)
        self.assertEqual({"source_qualified"}, {row["state"] for row in result["parent_journeys"]})

    def test_matrix_covers_every_closed_core_slice(self):
        result = self.build(**self.inputs())
        versions = {item["closed_in"] for item in result["closure_matrix"]}
        for version in {"0.40", "0.41", "0.42", "0.43", "0.44", "0.45", "0.46", "0.47", "0.48", "0.49"}:
            self.assertIn(version, versions)


class ReleaseReadinessEvidenceTests(unittest.TestCase):
    def setUp(self):
        from app.release_readiness import config_roundtrip_smoke, restart_evidence
        self.config_roundtrip_smoke = config_roundtrip_smoke
        self.restart_evidence = restart_evidence
        self.tmp = tempfile.TemporaryDirectory()
        self.store = PolicyStore(str(Path(self.tmp.name) / "policy.db"))

    def tearDown(self):
        self.tmp.cleanup()

    def test_config_roundtrip_smoke_is_non_destructive_and_digest_exact(self):
        profile = self.store.create_profile("Child", "blocked", "homework", "", ["youtube"])
        self.store.update_device("192.168.2.20", profile_id=profile["id"])
        before = self.store.config_digest()
        result = self.config_roundtrip_smoke(self.store)
        after = self.store.config_digest()
        self.assertEqual("pass", result["state"])
        self.assertEqual(before, result["source_digest"])
        self.assertEqual(before, result["restored_digest"])
        self.assertEqual(before, after)
        self.assertTrue(result["non_destructive"])

    def test_restart_evidence_is_pending_without_controlled_stop(self):
        self.store.append_audit(
            "STARTUP_INTEGRITY_OK",
            "system:startup",
            "version=0.50.0 status=ready",
        )
        result = self.restart_evidence(self.store, "0.50.0")
        self.assertEqual("pending", result["state"])

    def test_restart_evidence_passes_for_stop_then_current_release_start(self):
        self.store.append_audit("APPLICATION_STOP", "system:shutdown", "FastAPI shutdown completed")
        self.store.append_audit(
            "STARTUP_INTEGRITY_OK",
            "system:startup",
            "version=0.50.0 status=ready",
        )
        result = self.restart_evidence(self.store, "0.50.0")
        self.assertEqual("pass", result["state"])
        self.assertTrue(result["controlled_stop_seen"])

    def test_old_controlled_stop_cannot_cover_a_later_unclean_restart(self):
        self.store.append_audit("APPLICATION_STOP", "system:shutdown", "FastAPI shutdown completed")
        self.store.append_audit(
            "STARTUP_INTEGRITY_OK",
            "system:startup",
            "version=0.49.1 status=ready",
        )
        # No APPLICATION_STOP between the old process and the current release.
        self.store.append_audit(
            "STARTUP_INTEGRITY_OK",
            "system:startup",
            "version=0.50.0 status=ready",
        )
        result = self.restart_evidence(self.store, "0.50.0")
        self.assertEqual("pending", result["state"])
        self.assertFalse(result["controlled_stop_seen"])

    def test_old_release_startup_does_not_satisfy_current_restart_evidence(self):
        self.store.append_audit("APPLICATION_STOP", "system:shutdown", "FastAPI shutdown completed")
        self.store.append_audit(
            "STARTUP_INTEGRITY_OK",
            "system:startup",
            "version=0.49.1 status=ready",
        )
        result = self.restart_evidence(self.store, "0.50.0")
        self.assertEqual("pending", result["state"])
        self.assertFalse(result["current_release_start_seen"])


class ReleaseReadinessSurfaceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parents[1]
        cls.main = (root / "app" / "main.py").read_text(encoding="utf-8")
        cls.index = (root / "app" / "templates" / "index.html").read_text(encoding="utf-8")
        cls.template_path = root / "app" / "templates" / "release_readiness.html"
        cls.readme = (root / "README.md").read_text(encoding="utf-8") + "\n" + (root / "CHANGELOG.md").read_text(encoding="utf-8")

    def test_observability_workbenches_do_not_pollute_live_performance_acceptance(self):
        for path in (
            '/api/operations/diagnostics',
            '/diagnostics',
            '/local/operations/diagnostics',
            '/api/release-readiness',
            '/release-readiness',
            '/local/release-readiness',
        ):
            self.assertIn(path, self.main)
        middleware = self.main.split('async def performance_request_metrics', 1)[1].split('sample, token =', 1)[0]
        self.assertIn('path == "/diagnostics"', middleware)
        self.assertIn('path == "/release-readiness"', middleware)
        self.assertIn('path.startswith("/api/operations/diagnostics")', middleware)
        self.assertIn('path.startswith("/api/release-readiness")', middleware)

    def test_release_readiness_api_and_page_are_authenticated_surfaces(self):
        self.assertIn('@app.get("/api/release-readiness")', self.main)
        self.assertIn('@app.get("/release-readiness", response_class=HTMLResponse)', self.main)
        self.assertIn('require_role("admin", "operator", "viewer")', self.main)

    def test_operations_links_to_release_readiness(self):
        self.assertIn('href="/release-readiness"', self.index)
        self.assertIn("Core release readiness", self.index)

    def test_release_readiness_template_explains_pending_is_not_pass(self):
        text = self.template_path.read_text(encoding="utf-8")
        self.assertIn("PENDING is not PASS", text)
        self.assertIn("live performance", text.lower())
        self.assertIn("controlled restart", text.lower())

    def test_release_acceptance_cli_is_strict_by_default(self):
        root = Path(__file__).resolve().parents[1]
        script = (root / "scripts" / "release_acceptance.py").read_text(encoding="utf-8")
        self.assertIn('zen_release_readiness_v1', script)
        self.assertIn('if state == "pass"', script)
        self.assertIn('--allow-pending', script)

    def test_readme_declares_v050_as_core_closure_not_feature_expansion(self):
        self.assertIn("v0.50.0 — Core closure / release readiness", self.readme)
        self.assertIn("no feature expansion", self.readme.lower())


if __name__ == "__main__":
    unittest.main()
