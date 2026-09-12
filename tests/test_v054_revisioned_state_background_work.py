import tempfile
import unittest
from pathlib import Path

from app.background_work import BackgroundWorker
from app.policy_store import ConfigRevisionConflict, PolicyStore

ROOT = Path(__file__).resolve().parents[1]


class RevisionJournalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = PolicyStore(str(Path(self.tmp.name) / "policy.db"))

    def tearDown(self):
        self.tmp.cleanup()

    def test_upgrade_baseline_creates_revision_and_transactional_outbox(self):
        state = self.store.ensure_config_revision_baseline(actor="test")
        self.assertEqual(state["revision"], 1)
        revisions = self.store.list_config_revisions()
        self.assertEqual(revisions[0]["scope"], "bootstrap")
        outbox = self.store.list_outbox_events(status="pending")
        self.assertEqual(len(outbox), 1)
        self.assertEqual(outbox[0]["revision"], 1)
        self.assertEqual(outbox[0]["topic"], "config.changed")

    def test_optimistic_revision_rejects_stale_write_before_mutation(self):
        current = self.store.ensure_config_revision_baseline()["revision"]
        with self.store.config_write(
            expected_revision=current,
            actor="test",
            reason="first write",
            scope="test",
        ) as db:
            db.execute(
                "INSERT INTO app_settings(key, value) VALUES('v054_test', 'one')"
            )
        self.assertEqual(self.store.current_config_revision()["revision"], current + 1)

        with self.assertRaises(ConfigRevisionConflict):
            with self.store.config_write(
                expected_revision=current,
                actor="test",
                reason="stale write",
                scope="test",
            ) as db:
                db.execute(
                    "UPDATE app_settings SET value='two' WHERE key='v054_test'"
                )
        self.assertEqual(self.store.get_settings()["v054_test"], "one")

    def test_failed_revisioned_transaction_rolls_back_change_revision_and_outbox(self):
        current = self.store.ensure_config_revision_baseline()["revision"]
        pending_before = len(self.store.list_outbox_events(status="pending"))
        with self.assertRaises(RuntimeError):
            with self.store.config_write(
                expected_revision=current,
                actor="test",
                reason="must rollback",
                scope="test",
            ) as db:
                db.execute(
                    "INSERT INTO app_settings(key, value) VALUES('rollback_probe', 'bad')"
                )
                raise RuntimeError("boom")
        self.assertNotIn("rollback_probe", self.store.get_settings())
        self.assertEqual(self.store.current_config_revision()["revision"], current)
        self.assertEqual(
            len(self.store.list_outbox_events(status="pending")), pending_before
        )

    def test_global_settings_route_store_method_supports_expected_revision(self):
        revision = self.store.ensure_config_revision_baseline()["revision"]
        saved = self.store.save_settings(
            policy_timezone="Europe/London",
            expected_revision=revision,
            actor="test:settings",
        )
        self.assertEqual(saved["policy_timezone"], "Europe/London")
        self.assertEqual(self.store.current_config_revision()["revision"], revision + 1)
        latest = self.store.list_config_revisions(1)[0]
        self.assertEqual(latest["scope"], "settings")
        self.assertEqual(latest["actor"], "test:settings")

    def test_integrity_report_requires_v054_durable_tables(self):
        report = self.store.database_integrity_report()
        self.assertTrue(report["ok"], report)
        for table in (
            "config_revision_state",
            "config_revisions",
            "outbox_events",
            "background_jobs",
            "background_scope_locks",
            "background_worker_metrics",
        ):
            with self.subTest(table=table):
                self.assertIn(table, report["table_counts"])


class DurableBackgroundWorkTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = PolicyStore(str(Path(self.tmp.name) / "policy.db"))
        self.store.ensure_config_revision_baseline()

    def tearDown(self):
        self.tmp.cleanup()

    def test_outbox_dispatch_is_idempotent_per_config_revision(self):
        self.assertEqual(self.store.dispatch_outbox_to_background_jobs(), 1)
        self.assertEqual(self.store.dispatch_outbox_to_background_jobs(), 0)
        jobs = self.store.list_background_jobs()
        self.assertEqual(len(jobs), 1)
        self.assertEqual(jobs[0]["kind"], "analytics.config-summary")
        self.assertEqual(jobs[0]["idempotency_key"], "config-analytics:r1")

    def test_job_idempotency_key_deduplicates_repeated_enqueue(self):
        first = self.store.enqueue_background_job(
            kind="analytics.config-summary",
            scope="analytics:config",
            idempotency_key="same-job",
            payload={"revision": 1},
        )
        second = self.store.enqueue_background_job(
            kind="analytics.config-summary",
            scope="analytics:config",
            idempotency_key="same-job",
            payload={"revision": 999},
        )
        self.assertEqual(first["id"], second["id"])
        self.assertEqual(second["payload"]["revision"], 1)

    def test_scope_lock_serializes_same_scope(self):
        self.assertTrue(
            self.store.acquire_background_scope_lock(
                scope="analytics:config", owner="a", token="one", lease_seconds=30
            )
        )
        self.assertFalse(
            self.store.acquire_background_scope_lock(
                scope="analytics:config", owner="b", token="two", lease_seconds=30
            )
        )
        self.assertTrue(
            self.store.release_background_scope_lock(
                scope="analytics:config", owner="a", token="one"
            )
        )
        self.assertTrue(
            self.store.acquire_background_scope_lock(
                scope="analytics:config", owner="b", token="two", lease_seconds=30
            )
        )

    def test_expired_job_lease_is_recovered_without_new_identity(self):
        job = self.store.enqueue_background_job(
            kind="analytics.config-summary",
            scope="analytics:config",
            idempotency_key="recover-me",
            payload={},
        )
        claimed = self.store.claim_background_job(
            worker_name="worker-a", lease_seconds=30, kinds=("analytics.config-summary",)
        )
        self.assertEqual(claimed["id"], job["id"])
        with self.store._db() as db:
            db.execute(
                "UPDATE background_jobs SET lease_expires_at='2000-01-01T00:00:00+00:00' WHERE id=?",
                (job["id"],),
            )
        self.assertEqual(self.store.recover_expired_background_work(), 1)
        recovered = next(item for item in self.store.list_background_jobs() if item["id"] == job["id"])
        self.assertEqual(recovered["status"], "pending")
        self.assertEqual(recovered["idempotency_key"], "recover-me")

    def test_first_background_worker_is_read_only_local_analytics(self):
        audits = []
        worker = BackgroundWorker(
            policy_store=self.store,
            handlers={
                "analytics.config-summary": lambda payload: self.store.build_config_analytics_snapshot()
            },
            audit=lambda event, actor, detail: audits.append((event, actor, detail)),
            worker_name="test-read-worker",
        )
        result = worker.run_cycle(trigger="test")
        self.assertEqual(result["failed"], 0)
        self.assertEqual(result["succeeded"], 1)
        job = self.store.list_background_jobs(1)[0]
        self.assertEqual(job["status"], "succeeded")
        self.assertEqual(job["result"]["schema"], "zen_config_analytics_v1")
        self.assertEqual(job["result"]["authority"], "read-only-local")
        self.assertNotIn("router", worker.__dict__)

    def test_worker_metrics_are_durable_and_exposed(self):
        worker = BackgroundWorker(
            policy_store=self.store,
            handlers={
                "analytics.config-summary": lambda payload: self.store.build_config_analytics_snapshot()
            },
            audit=lambda *_: None,
            worker_name="metrics-worker",
        )
        worker.run_cycle(trigger="test")
        stats = self.store.background_work_stats()
        self.assertTrue(stats["available"])
        metric = next(item for item in stats["workers"] if item["worker_name"] == "metrics-worker")
        self.assertEqual(metric["cycles"], 1)
        self.assertEqual(metric["jobs_succeeded"], 1)


class V054SourceContractTests(unittest.TestCase):
    def test_release_version_and_changelog_are_v054(self):
        main = (ROOT / "app/main.py").read_text()
        pwa = (ROOT / "app/pwa.py").read_text()
        changelog = (ROOT / "CHANGELOG.md").read_text()
        self.assertIn('version="0.54.1"', main)
        self.assertIn('PWA_RELEASE = "0.54.1"', pwa)
        self.assertIn("## v0.54.1", changelog)

    def test_background_worker_has_no_routeros_dependency_and_is_started(self):
        background = (ROOT / "app/background_work.py").read_text()
        main = (ROOT / "app/main.py").read_text()
        self.assertNotIn("RouterOSAdapter", background)
        self.assertNotIn("app.router", background)
        self.assertIn("background_worker.start()", main)
        self.assertIn("background_worker.stop()", main)
        self.assertIn('"analytics.config-summary"', main)

    def test_revision_and_background_status_apis_are_read_only(self):
        main = (ROOT / "app/main.py").read_text()
        self.assertIn('@app.get("/api/config/revision")', main)
        self.assertIn('@app.get("/api/background/status")', main)
        self.assertNotIn('@app.post("/api/config/revision")', main)
        self.assertNotIn('@app.post("/api/background/status")', main)

    def test_settings_forms_carry_revision_and_routes_pass_expected_revision(self):
        template = (ROOT / "app/templates/index.html").read_text()
        main = (ROOT / "app/main.py").read_text()
        self.assertGreaterEqual(template.count('name="config_revision"'), 6)
        self.assertIn("expected_revision=config_revision", main)
        self.assertIn('"config_revision": int(policy_store.current_config_revision()', main)

    def test_release_resume_supports_clean_published_head_and_tag_mismatch_gate(self):
        script = (ROOT / "scripts/release_patch.py").read_text()
        self.assertIn("resume_state=", script)
        self.assertIn("committed-published", script)
        self.assertIn("committed-not-published", script)
        self.assertIn("TAG TARGET MISMATCH", script)
        self.assertIn("already at", script)


if __name__ == "__main__":
    unittest.main()
