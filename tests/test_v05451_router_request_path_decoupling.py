import contextlib
import sys
import tempfile
import types
import unittest
from pathlib import Path

sys.modules.setdefault("routeros_api", types.SimpleNamespace())

from app.policy_store import PolicyStore
from app.reconciler import AutoReconciler

ROOT = Path(__file__).resolve().parents[1]


class ReconciliationRequestStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = PolicyStore(str(Path(self.tmp.name) / "policy.db"))
        self.store.ensure_config_revision_baseline(actor="test")

    def tearDown(self):
        self.tmp.cleanup()

    def test_new_pending_request_supersedes_older_same_target(self):
        first = self.store.enqueue_reconciliation_request(target="192.168.2.10", actor="alice")
        second = self.store.enqueue_reconciliation_request(target="192.168.2.10", actor="alice")
        rows = self.store.list_reconciliation_requests(10)
        by_id = {row["id"]: row for row in rows}
        self.assertEqual("superseded", by_id[first["id"]]["status"])
        self.assertEqual("pending", by_id[second["id"]]["status"])
        self.assertEqual(1, self.store.reconciliation_request_stats()["pending"])

    def test_running_request_is_recovered_after_restart(self):
        queued = self.store.enqueue_reconciliation_request(target="*", actor="alice")
        claimed = self.store.claim_reconciliation_request()
        self.assertEqual(queued["id"], claimed["id"])
        self.assertEqual("running", claimed["status"])
        self.assertEqual(1, self.store.recover_reconciliation_requests())
        latest = self.store.list_reconciliation_requests(1)[0]
        self.assertEqual("pending", latest["status"])
        self.assertIn("Recovered interrupted reconciliation", latest["error"])


class _FakeRouter:
    def __init__(self):
        self.mutation_owners = []
        self.writes = []
        self.security_calls = 0

    @contextlib.contextmanager
    def mutation_session(self, owner):
        self.mutation_owners.append(owner)
        yield self

    def mutation_status(self):
        return {"schema": "zen_router_mutation_lane_v1", "busy": False, "available": True}

    def get_security_posture(self):
        self.security_calls += 1
        return {"enforcement_ready": True, "checks": []}

    def set_device_mode(self, address, mode, description=""):
        self.writes.append((address, mode, description))
        return {"mode": mode}


class RequestedReconcilerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = PolicyStore(str(Path(self.tmp.name) / "policy.db"))
        self.store.ensure_config_revision_baseline(actor="test")

    def tearDown(self):
        self.tmp.cleanup()

    def test_explicit_request_runs_even_when_automatic_mode_is_off(self):
        router = _FakeRouter()
        calls = {"plan": 0}

        def plan_loader(address):
            calls["plan"] += 1
            if calls["plan"] == 1:
                return {
                    "address": address, "temporary_override": False,
                    "policy_actionable": True, "mode_drift": True,
                    "bandwidth_drift": False, "service_drift": False,
                    "live_mode": "normal", "desired_mode": "blocked",
                }
            return {
                "address": address, "temporary_override": False,
                "policy_actionable": False, "mode_drift": False,
                "bandwidth_drift": False, "service_drift": False,
                "status": "in_sync",
            }

        worker = AutoReconciler(
            policy_store=self.store,
            router=router,
            device_loader=lambda: [{"ip": "192.168.2.10"}],
            plan_loader=plan_loader,
            audit=lambda *_: None,
        )
        queued = worker.request_reconciliation(target="192.168.2.10", actor="alice")
        result = worker.run_requested_reconciliation()
        self.assertEqual(queued["id"], result["id"])
        self.assertEqual("succeeded", result["status"])
        self.assertEqual(1, len(router.writes))
        self.assertGreaterEqual(router.security_calls, 1)
        self.assertTrue(router.mutation_owners)
        self.assertTrue(router.mutation_owners[0].startswith("requested-reconcile:"))


class RequestPathSourceContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.main = (ROOT / "app/main.py").read_text()
        cls.reconciler = (ROOT / "app/reconciler.py").read_text()
        cls.store = (ROOT / "app/policy_store.py").read_text()
        cls.template = (ROOT / "app/templates/index.html").read_text()
        cls.background = (ROOT / "app/background_work.py").read_text()

    def _function_block(self, name):
        return self.main.split(f"def {name}", 1)[1].split("\n@app.", 1)[0]

    def test_apply_routes_ack_without_routeros_calls(self):
        for name in ("apply_device_policy", "apply_all_device_policies"):
            block = self._function_block(name)
            self.assertIn("request_reconciliation", block)
            self.assertNotIn("router.", block)
            self.assertNotIn("get_live_policy_plan", block)
            self.assertNotIn("@coherent_router_mutation", self.main.split(f"def {name}", 1)[0].split("\n@app.")[-1])

    def test_durable_queue_is_consumed_only_by_auto_reconciler(self):
        self.assertIn("CREATE TABLE IF NOT EXISTS reconciliation_requests", self.store)
        self.assertIn("claim_reconciliation_request", self.reconciler)
        self.assertIn("with self._mutation_context(f\"requested-reconcile:{request['id']}\")", self.reconciler)
        self.assertIn("recover_reconciliation_requests", self.reconciler)
        self.assertNotIn("RouterOSAdapter", self.background)

    def test_revision_change_requeues_latest_desired_state(self):
        self.assertIn("finished_revision != started_revision", self.reconciler)
        self.assertIn('status = "superseded"', self.reconciler)
        self.assertIn("Desired state changed during reconciliation; latest revision re-queued", self.reconciler)
        self.assertIn("self.request_reconciliation(", self.reconciler)

    def test_dashboard_does_not_live_probe_expensive_security_or_service_health(self):
        dashboard = self.main.split('def dashboard(', 1)[1].split('@app.get("/api/services/health")', 1)[0]
        # Live probes still exist for explicit settings/security and service-intelligence paths,
        # but the dashboard condition itself must no longer include them.
        self.assertIn('_advisory_router_payload(\n            "router:security-posture"', dashboard)
        self.assertIn('_advisory_router_payload(\n            "router:service-contract-health"', dashboard)
        self.assertNotIn('if active_view == "dashboard" or (active_view == "settings" and active_section == "security")', dashboard)
        self.assertIn('if active_view == "settings" and active_section == "security":', dashboard)
        self.assertIn("RouterOS dashboard evidence is non-blocking", self.template)

    def test_queue_status_is_visible_and_machine_readable(self):
        self.assertIn('/api/reconciler/requests', self.main)
        self.assertIn("Queued applies", self.template)
        self.assertIn("Latest requested reconciliation", self.template)

    def test_background_performance_exposes_last_error_for_degraded_diagnosis(self):
        block = self.background.split("def performance_snapshot", 1)[1].split("@timed", 1)[0]
        self.assertIn('"last_error"', block)


if __name__ == "__main__":
    unittest.main()
