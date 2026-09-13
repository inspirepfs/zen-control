import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.background_work import BackgroundWorker
from app.policy_store import PolicyStore

ROOT = Path(__file__).resolve().parents[1]


class PreparedViewStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = PolicyStore(str(Path(self.tmp.name) / "policy.db"))
        self.revision = self.store.ensure_config_revision_baseline()["revision"]

    def tearDown(self):
        self.tmp.cleanup()

    def test_prepared_view_is_bounded_single_row_with_generation(self):
        first = self.store.save_prepared_view(
            view_key="dashboard:24h",
            kind="analytics.prepared-view",
            scope="analytics:dashboard",
            payload={"value": 1},
            source_revision=self.revision,
            ttl_seconds=300,
        )
        second = self.store.save_prepared_view(
            view_key="dashboard:24h",
            kind="analytics.prepared-view",
            scope="analytics:dashboard",
            payload={"value": 2},
            source_revision=self.revision,
            ttl_seconds=300,
        )
        self.assertEqual(first["generation"], 1)
        self.assertEqual(second["generation"], 2)
        self.assertEqual(second["payload"]["value"], 2)
        self.assertEqual(len(self.store.list_prepared_views()), 1)

    def test_revision_mismatch_withholds_old_prepared_policy_semantics(self):
        self.store.save_prepared_view(
            view_key="services:24h",
            kind="analytics.prepared-view",
            payload={"rows": [1]},
            source_revision=self.revision,
            ttl_seconds=300,
        )
        with self.store.config_write(scope="test", reason="revision advance") as db:
            db.execute("INSERT INTO app_settings(key,value) VALUES('v0541_revision_probe','1')")
        current = self.store.current_config_revision()["revision"]
        self.assertEqual(current, self.revision + 1)
        self.assertIsNone(
            self.store.get_prepared_view(
                "services:24h", required_revision=current, max_age_seconds=300
            )
        )
        stale = self.store.get_prepared_view(
            "services:24h", required_revision=current, include_stale=True
        )
        self.assertTrue(stale["revision_stale"])
        self.assertFalse(stale["eligible"])

    def test_age_gate_and_expiry_are_explicit(self):
        self.store.save_prepared_view(
            view_key="history:7d",
            kind="analytics.prepared-view",
            payload={"ok": True},
            source_revision=self.revision,
            ttl_seconds=300,
        )
        old = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(timespec="seconds")
        with self.store._db() as db:
            db.execute(
                "UPDATE prepared_views SET captured_at=? WHERE view_key='history:7d'",
                (old,),
            )
        self.assertIsNone(
            self.store.get_prepared_view(
                "history:7d", required_revision=self.revision, max_age_seconds=60
            )
        )
        stale = self.store.get_prepared_view(
            "history:7d", required_revision=self.revision,
            max_age_seconds=60, include_stale=True,
        )
        self.assertTrue(stale["too_old"])
        self.assertFalse(stale["eligible"])

    def test_prepared_payload_has_two_megabyte_safety_bound(self):
        with self.assertRaises(ValueError):
            self.store.save_prepared_view(
                view_key="too-large",
                kind="analytics.prepared-view",
                payload={"blob": "x" * 2_100_000},
                source_revision=self.revision,
            )

    def test_prepared_views_are_derived_state_not_configuration_export(self):
        self.store.save_prepared_view(
            view_key="dashboard:24h",
            kind="analytics.prepared-view",
            payload={"private_runtime_evidence": True},
            source_revision=self.revision,
        )
        exported = self.store.export_config()
        self.assertNotIn("prepared_views", exported)
        self.assertNotIn("private_runtime_evidence", json.dumps(exported))

    def test_background_stats_include_prepared_view_size(self):
        saved = self.store.save_prepared_view(
            view_key="activity:24h",
            kind="analytics.prepared-view",
            payload={"schema": "probe", "rows": [1, 2, 3]},
            source_revision=self.revision,
        )
        stats = self.store.background_work_stats()
        self.assertEqual(stats["prepared_views"]["count"], 1)
        self.assertEqual(stats["prepared_views"]["payload_bytes"], saved["payload_bytes"])

    def test_retention_prunes_only_old_terminal_work_and_keeps_recent_floor(self):
        old = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat(timespec="seconds")
        with self.store._db() as db:
            for idx in range(30):
                db.execute(
                    """INSERT INTO background_jobs
                       (kind,scope,idempotency_key,payload_json,status,attempts,max_attempts,
                        available_at,created_at,updated_at,finished_at)
                       VALUES ('test','retention',?,'{}','succeeded',1,3,?,?,?,?)""",
                    (f"old-{idx}", old, old, old, old),
                )
            db.execute(
                """INSERT INTO background_jobs
                   (kind,scope,idempotency_key,payload_json,status,attempts,max_attempts,
                    available_at,created_at,updated_at)
                   VALUES ('test','retention','active-old','{}','pending',0,3,?,?,?)""",
                (old, old, old),
            )
        result = self.store.prune_background_history(
            retention_days=14, keep_jobs=20, keep_outbox=20
        )
        self.assertEqual(result["jobs_deleted"], 10)
        jobs = self.store.list_background_jobs(100)
        self.assertTrue(any(row["idempotency_key"] == "active-old" for row in jobs))
        self.assertEqual(sum(row["status"] == "succeeded" for row in jobs), 20)

    def test_integrity_report_includes_prepared_views(self):
        report = self.store.database_integrity_report()
        self.assertTrue(report["ok"], report)
        self.assertIn("prepared_views", report["table_counts"])


class PreparedViewWorkerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = PolicyStore(str(Path(self.tmp.name) / "policy.db"))
        self.store.ensure_config_revision_baseline()

    def tearDown(self):
        self.tmp.cleanup()

    def test_worker_runs_producer_before_claim_and_keeps_router_out(self):
        def producer():
            self.store.enqueue_background_job(
                kind="analytics.prepared-view",
                scope="analytics:test",
                idempotency_key="prepared:test",
                payload={"view": "probe"},
            )
            return 1

        def handler(payload):
            self.store.save_prepared_view(
                view_key="probe",
                kind="analytics.prepared-view",
                scope="analytics:test",
                payload={"input": payload["view"]},
                source_revision=self.store.current_config_revision()["revision"],
            )
            return {"ok": True}

        worker = BackgroundWorker(
            policy_store=self.store,
            handlers={"analytics.prepared-view": handler},
            producer=producer,
            audit=lambda *_: None,
            worker_name="prepared-worker",
        )
        result = worker.run_cycle(trigger="test")
        self.assertEqual(result["scheduled"], 1)
        self.assertEqual(result["succeeded"], 1)
        self.assertIsNotNone(self.store.get_prepared_view("probe"))
        self.assertNotIn("router", worker.__dict__)


class V0541SourceContractTests(unittest.TestCase):
    def test_release_version_and_changelog_are_v0541(self):
        main = (ROOT / "app/main.py").read_text()
        pwa = (ROOT / "app/pwa.py").read_text()
        changelog = (ROOT / "CHANGELOG.md").read_text()
        self.assertIn('version="0.55.3.1"', main)
        self.assertIn('PWA_RELEASE = "0.55.3.1"', pwa)
        self.assertIn("## v0.54.1 — Background analytics & prepared views", changelog)

    def test_background_prepared_handler_does_not_use_routeros(self):
        main = (ROOT / "app/main.py").read_text()
        start = main.index("def _background_prepared_view")
        end = main.index("def _background_retention", start)
        handler = main[start:end]
        self.assertNotIn("router.", handler)
        self.assertNotIn("RouterOSAdapter", handler)
        self.assertIn('"analytics.prepared-view"', main)
        self.assertIn('"maintenance.background-retention"', main)

    def test_device360_prepares_activity_but_keeps_router_authority_fresh(self):
        main = (ROOT / "app/main.py").read_text()
        self.assertIn('f"device360:{address}"', main)
        self.assertIn("get_policy_explanation(address)", main)
        self.assertIn("_build_device360_activity", main)
        template = (ROOT / "app/templates/device_360.html").read_text()
        self.assertIn("RouterOS authority evidence below is still read fresh", template)

    def test_common_read_surfaces_consume_prepared_views_with_live_fallback(self):
        main = (ROOT / "app/main.py").read_text()
        for key in (
            '"dashboard:24h"', '"activity:24h"', '"services:24h"',
            '"classification:24h"', '"history:7d"',
        ):
            with self.subTest(key=key):
                self.assertGreaterEqual(main.count(key), 2)
        self.assertIn('@app.get("/api/background/prepared-views")', main)

    def test_prepared_view_store_has_revision_age_size_and_retention_guards(self):
        store = (ROOT / "app/policy_store.py").read_text()
        self.assertIn("CREATE TABLE IF NOT EXISTS prepared_views", store)
        self.assertIn("source_revision", store)
        self.assertIn("payload_bytes", store)
        self.assertIn("Prepared view payload exceeds 2 MB safety limit", store)
        self.assertIn("revision_stale", store)
        self.assertIn("prune_background_history", store)


if __name__ == "__main__":
    unittest.main()
