import tempfile
import unittest
from decimal import Decimal
from pathlib import Path

from app.policy_store import PolicyStore
from app.runtime_health import build_runtime_health

ROOT = Path(__file__).resolve().parents[1]


class _Snapshot:
    def __init__(self, payload):
        self.payload = dict(payload)

    def snapshot(self):
        return dict(self.payload)


class PreparedViewSerializationRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = PolicyStore(str(Path(self.tmp.name) / "policy.db"))
        self.revision = self.store.ensure_config_revision_baseline(actor="test")["revision"]

    def tearDown(self):
        self.tmp.cleanup()

    def test_decimal_analytics_payload_round_trips_as_json_numbers(self):
        row = self.store.save_prepared_view(
            view_key="activity:24h",
            kind="analytics.prepared-view",
            scope="analytics:activity",
            payload={
                "bytes": Decimal("9081"),
                "ratio": Decimal("12.50"),
                "nested": [{"value": Decimal("0.125")}],
            },
            source_revision=self.revision,
        )
        self.assertEqual(9081, row["payload"]["bytes"])
        self.assertEqual(12.5, row["payload"]["ratio"])
        self.assertEqual(0.125, row["payload"]["nested"][0]["value"])

    def test_latest_prepared_job_state_is_bounded_and_diagnostic(self):
        job = self.store.enqueue_background_job(
            kind="analytics.prepared-view",
            scope="analytics:activity",
            idempotency_key="prepared:activity:24h:r1:b1",
            payload={"view": "activity:24h"},
        )
        claimed = self.store.claim_background_job(
            worker_name="probe", kinds=("analytics.prepared-view",), lease_seconds=30
        )
        self.store.fail_background_job(
            claimed["id"], worker_name="probe", lease_token=claimed["lease_token"],
            error="Object of type Decimal is not JSON serializable",
        )
        state = self.store.prepared_view_job_state("activity:24h")
        self.assertEqual(job["id"], state["id"])
        self.assertEqual("pending", state["status"])
        self.assertEqual(1, state["attempts"])
        self.assertIn("Decimal", state["error"])
        self.assertNotIn("payload", state)

    def test_prepared_job_health_uses_latest_scope_attempt_not_historical_failure(self):
        with self.store._db() as db:
            now = self.store._operations_now_iso()
            db.execute(
                """INSERT INTO background_jobs
                   (kind,scope,idempotency_key,payload_json,status,attempts,max_attempts,
                    available_at,created_at,updated_at,error,finished_at)
                   VALUES ('analytics.prepared-view','analytics:activity','old','{}','failed',3,3,?,?,?,?,?)""",
                (now, now, now, "old failure", now),
            )
        stats = self.store.background_work_stats()
        self.assertEqual(1, stats["prepared_jobs"]["failed"])

        with self.store._db() as db:
            now = self.store._operations_now_iso()
            db.execute(
                """INSERT INTO background_jobs
                   (kind,scope,idempotency_key,payload_json,status,attempts,max_attempts,
                    available_at,created_at,updated_at,error,finished_at)
                   VALUES ('analytics.prepared-view','analytics:activity','new','{}','succeeded',1,3,?,?,?,?,?)""",
                (now, now, now, "", now),
            )
        stats = self.store.background_work_stats()
        self.assertEqual(0, stats["prepared_jobs"]["failed"])
        self.assertEqual(1, stats["prepared_jobs"]["succeeded"])


class RuntimePreparedWorkHealthTests(unittest.TestCase):
    def _runtime(self, prepared_jobs):
        return build_runtime_health(
            version="0.55.0.1",
            background_worker=_Snapshot({
                "worker_alive": True,
                "durable": {"available": True, "prepared_jobs": prepared_jobs},
            }),
            reconciler=_Snapshot({"worker_alive": True, "router_mutation": {"available": True}}),
            incident_monitor=_Snapshot({"worker_alive": True}),
            summary_delivery=_Snapshot({"worker_running": True}),
        )

    def test_retrying_or_failed_latest_prepared_work_degrades_runtime(self):
        report = self._runtime({"failed": 1, "retrying": 1, "warming": 0, "succeeded": 3})
        self.assertFalse(report["ok"])
        self.assertEqual("degraded", report["status"])
        self.assertFalse(report["background_read_models"]["healthy"])
        self.assertEqual(1, report["background_read_models"]["failed_latest"])
        self.assertEqual(1, report["background_read_models"]["retrying_latest"])

    def test_successful_latest_prepared_work_restores_runtime_health(self):
        report = self._runtime({"failed": 0, "retrying": 0, "warming": 2, "succeeded": 4})
        self.assertTrue(report["ok"])
        self.assertTrue(report["background_read_models"]["healthy"])

    def test_durable_worker_stats_failure_is_fail_closed(self):
        report = build_runtime_health(
            version="0.55.2",
            background_worker=_Snapshot({
                "worker_alive": True,
                "durable": {"available": False},
            }),
            reconciler=_Snapshot({"worker_alive": True, "router_mutation": {"available": True}}),
            incident_monitor=_Snapshot({"worker_alive": True}),
            summary_delivery=_Snapshot({"worker_running": True}),
        )
        self.assertFalse(report["ok"])
        self.assertFalse(report["background_read_models"]["durable_available"])


class V054521SourceContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.main = (ROOT / "app/main.py").read_text()
        cls.template = (ROOT / "app/templates/index.html").read_text()
        cls.store = (ROOT / "app/policy_store.py").read_text()

    def test_prepared_miss_reports_failed_or_preparing_job_state(self):
        block = self.main[self.main.index("def _prepared_payload"):self.main.index("def _record_prepared_fallback")]
        self.assertIn('state, reason = "failed", "generation_failed"', block)
        self.assertIn('state = "preparing"', block)
        self.assertIn("prepared_view_job_state", block)

    def test_activity_source_health_is_separate_from_prepared_data_availability(self):
        self.assertIn("telemetry_source_available = False", self.main)
        self.assertIn("telemetry_source_available = bool(activity_store.health())", self.main)
        self.assertIn("{% if telemetry_source_available %}", self.template)
        self.assertIn("Read model FAILED", self.template)
        self.assertIn("Read model PREPARING", self.template)

    def test_json_persistence_boundary_handles_postgres_decimal(self):
        self.assertIn("isinstance(value, Decimal)", self.store)
        self.assertIn("default=PolicyStore._json_storage_default", self.store)

    def test_prepared_job_identity_is_release_scoped_for_immediate_recovery(self):
        self.assertIn('key = f"prepared:{view}:v{app.version}:r{revision}:b{bucket}"', self.main)
        self.assertIn("replace_pending=True", self.main)


if __name__ == "__main__":
    unittest.main()
