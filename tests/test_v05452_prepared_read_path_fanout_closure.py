import sys
import tempfile
import types
import unittest
from pathlib import Path

psycopg = types.ModuleType("psycopg")
psycopg.Error = Exception
psycopg.connect = None
rows = types.ModuleType("psycopg.rows")
rows.dict_row = object()
sys.modules.setdefault("psycopg", psycopg)
sys.modules.setdefault("psycopg.rows", rows)

from app.activity import ActivityStore
from app.policy_store import PolicyStore
from app.reconciler import AutoReconciler

ROOT = Path(__file__).resolve().parents[1]


class _FakeCursor:
    def __init__(self, rows):
        self.rows = rows
        self.executed = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def execute(self, sql, params=()):
        self.executed.append((sql, params))

    def fetchall(self):
        return list(self.rows)


class _FakeConnection:
    def __init__(self):
        self.cursors = []
        self.commits = 0
        self.rollbacks = 0
        self.closed = 0

    def cursor(self):
        cur = _FakeCursor([{"ok": 1}])
        self.cursors.append(cur)
        return cur

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1

    def close(self):
        self.closed += 1


class CoherentActivitySessionTests(unittest.TestCase):
    def test_multiple_queries_and_nested_session_reuse_one_postgres_connection(self):
        store = ActivityStore()
        conn = _FakeConnection()
        opens = []

        def connect():
            opens.append(1)
            return conn

        store._connect = connect
        with store.coherent_session():
            self.assertTrue(store.health())
            with store.coherent_session():
                self.assertTrue(store.health())
        self.assertEqual(1, len(opens))
        self.assertEqual(2, len(conn.cursors))
        self.assertEqual(1, conn.commits)
        self.assertEqual(1, conn.closed)


class PreparedJobCoalescingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = PolicyStore(str(Path(self.tmp.name) / "policy.db"))
        self.store.ensure_config_revision_baseline(actor="test")

    def tearDown(self):
        self.tmp.cleanup()

    def test_replace_pending_keeps_only_latest_pending_same_scope(self):
        first = self.store.enqueue_background_job(
            kind="analytics.prepared-view", scope="analytics:activity",
            idempotency_key="activity:old", payload={"bucket": "old"},
        )
        second = self.store.enqueue_background_job(
            kind="analytics.prepared-view", scope="analytics:activity",
            idempotency_key="activity:new", payload={"bucket": "new"},
            replace_pending=True,
        )
        jobs = self.store.list_background_jobs(20)
        keys = {row["idempotency_key"] for row in jobs}
        self.assertNotIn(first["idempotency_key"], keys)
        self.assertIn(second["idempotency_key"], keys)

    def test_replace_pending_never_deletes_running_work(self):
        old = self.store.enqueue_background_job(
            kind="analytics.prepared-view", scope="analytics:activity",
            idempotency_key="activity:running", payload={"bucket": "old"},
        )
        claimed = self.store.claim_background_job(
            worker_name="test-worker", lease_seconds=60,
            kinds=["analytics.prepared-view"],
        )
        self.assertEqual(old["id"], claimed["id"])
        self.store.enqueue_background_job(
            kind="analytics.prepared-view", scope="analytics:activity",
            idempotency_key="activity:new", payload={"bucket": "new"},
            replace_pending=True,
        )
        jobs = self.store.list_background_jobs(20)
        by_key = {row["idempotency_key"]: row for row in jobs}
        self.assertEqual("running", by_key["activity:running"]["status"])
        self.assertEqual("pending", by_key["activity:new"]["status"])


class _ObserveRouter:
    def mutation_status(self):
        return {"schema": "zen_router_mutation_lane_v1", "busy": False, "available": True}


class AdvisoryObservationPublicationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = PolicyStore(str(Path(self.tmp.name) / "policy.db"))
        self.revision = self.store.ensure_config_revision_baseline(actor="test")["revision"]

    def tearDown(self):
        self.tmp.cleanup()

    def test_observe_cycle_publishes_advisory_managed_and_service_views_without_mutation(self):
        writes = []

        def plan(address):
            return {
                "address": address,
                "global_mode": "normal",
                "temporary_override": False,
                "policy_actionable": False,
                "mode_drift": False,
                "bandwidth_drift": False,
                "service_drift": False,
                "status": "in_sync",
                "service_states": [
                    {"key": "youtube", "name": "YouTube", "available": True},
                ],
                "live_evidence": {
                    "enforcement": {"mode": "normal"},
                    "temporary_access": {"active": False},
                    "services": {"blocked_services": []},
                    "bandwidth": {"active": False},
                },
            }

        worker = AutoReconciler(
            policy_store=self.store,
            router=_ObserveRouter(),
            device_loader=lambda: [{"ip": "192.168.2.10", "name": "Tablet"}],
            plan_loader=plan,
            audit=lambda *args: writes.append(args),
        )
        result = worker.run_cycle(trigger="test", mode_override="observe")
        self.assertIn(result["result"], {"ok", "drift"})

        managed = self.store.get_prepared_view(
            "router:managed-device-observation", required_revision=self.revision,
            include_stale=True,
        )
        service = self.store.get_prepared_view(
            "router:service-contract-health", required_revision=self.revision,
            include_stale=True,
        )
        self.assertIsNotNone(managed)
        self.assertEqual("zen_managed_device_observation_v1", managed["payload"]["schema"])
        self.assertEqual("normal", managed["payload"]["plans"]["192.168.2.10"]["global_mode"])
        self.assertIsNotNone(service)
        self.assertEqual("zen_service_contract_observation_v1", service["payload"]["schema"])
        self.assertEqual(1, service["payload"]["healthy"])


class V05452SourceContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.main = (ROOT / "app/main.py").read_text()
        cls.activity = (ROOT / "app/activity.py").read_text()
        cls.store = (ROOT / "app/policy_store.py").read_text()
        cls.reconciler = (ROOT / "app/reconciler.py").read_text()
        cls.performance = (ROOT / "app/performance.py").read_text()

    def test_background_analytics_uses_one_coherent_postgres_session(self):
        start = self.main.index("def _background_prepared_view")
        end = self.main.index("def _background_retention", start)
        block = self.main[start:end]
        self.assertIn("activity_store.coherent_session()", block)
        self.assertIn("def coherent_session", self.activity)

    def test_normal_activity_navigation_does_not_live_fallback_to_postgres_or_routeros_health(self):
        start = self.main.index("def dashboard(")
        end = self.main.index('@app.get("/api/services/health")', start)
        block = self.main[start:end]
        self.assertIn('"activity:24h"', block)
        self.assertIn("allow_stale_same_revision=True", block)
        self.assertIn("Prepared telemetry evidence is not ready yet", block)
        self.assertNotIn("router.get_service_contract_health()", block)

    def test_dashboard_and_devices_use_advisory_reconciler_observation_not_snapshot_request(self):
        start = self.main.index("def dashboard(")
        end = self.main.index('@app.get("/api/services/health")', start)
        block = self.main[start:end]
        self.assertIn('"router:managed-device-observation"', block)
        self.assertNotIn("get_managed_device_observation_snapshot(", block)
        self.assertIn("_publish_managed_observation", self.reconciler)

    def test_prepared_miss_reasons_are_explicit_and_revision_stale_is_never_served(self):
        block = self.main[self.main.index("def _prepared_payload"):self.main.index("def _record_prepared_fallback")]
        for reason in ("not_found", "revision_mismatch", "status_not_ready", "expired", "too_old", "stale_grace_exceeded"):
            self.assertIn(reason, block)
        self.assertIn("allow_stale_same_revision", block)
        self.assertIn("same_revision", block)
        self.assertIn('str(prepared.get("status") or "") == "ready"', block)
        self.assertIn("stale_grace_seconds", block)

    def test_formal_gate_requires_warmed_ninety_percent_prepared_hit_rate(self):
        self.assertIn('minimum_hit_rate_percent": 90.0', self.performance)
        self.assertIn("prepared_lookups < 5", self.performance)
        self.assertIn("prepared_hit_rate < 90.0", self.performance)

    def test_prepared_observation_never_enters_mutation_authority_path(self):
        reconcile = self.reconciler[
            self.reconciler.index("def run_cycle("):
            self.reconciler.index("def _record_successful_cycle", self.reconciler.index("def run_cycle("))
        ]
        publish_pos = reconcile.index("self._publish_managed_observation")
        mutation_pos = reconcile.index("with self._mutation_context")
        self.assertLess(publish_pos, mutation_pos)
        mutation_block = reconcile[mutation_pos:]
        self.assertNotIn("get_prepared_view", mutation_block)
        self.assertNotIn("router:managed-device-observation", mutation_block)


if __name__ == "__main__":
    unittest.main()
