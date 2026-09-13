import importlib.util
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.policy_store import PolicyStore
from app.runtime_health import build_runtime_health
from app.upgrade_safety import (
    SCHEMA_RELEASE,
    SCHEMA_VERSION,
    UpgradeSafetyError,
    backup_path_for,
    create_verified_backup,
    inspect_database,
    prepare_policy_database_upgrade,
)
from scripts.upgrade_acceptance import probe as upgrade_probe

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
SPEC = importlib.util.spec_from_file_location("zen_release_patch_v057", ROOT / "scripts" / "release_patch.py")
release_patch = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(release_patch)


class UpgradeFixtureMixin:
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def fixture(self, release: str) -> Path:
        path = Path(self.tmp.name) / f"policy-{release}.db"
        db = sqlite3.connect(path)
        try:
            db.executescript((FIXTURES / f"policy_{release}.sql").read_text())
            db.commit()
        finally:
            db.close()
        return path


class HistoricalUpgradeTests(UpgradeFixtureMixin, unittest.TestCase):
    def test_fresh_database_is_versioned_without_preupgrade_backup(self):
        path = Path(self.tmp.name) / "fresh.db"
        store = PolicyStore(str(path))
        self.assertEqual(SCHEMA_VERSION, store.schema_status()["version"])
        self.assertEqual("created", store.upgrade_report["state"])
        self.assertIsNone(store.upgrade_report["backup"])
        self.assertTrue(store.database_integrity_report()["ok"])
        self.assertFalse(backup_path_for(path).exists())

    def test_v054_fixture_upgrades_and_retains_policy_history(self):
        path = self.fixture("v054")
        store = PolicyStore(str(path))
        self.assertEqual("upgraded", store.upgrade_report["state"])
        self.assertTrue(Path(store.upgrade_report["backup"]["path"]).is_file())
        with store._db() as db:
            profile = db.execute("SELECT name, notes, daily_quota_mb FROM profiles WHERE name='v054 child'").fetchone()
            device = db.execute("SELECT alias, category, favourite FROM device_policy WHERE ip='192.0.2.54'").fetchone()
            history = db.execute("SELECT captured_at, identity_id FROM policy_state_history WHERE state_hash='v054-state'").fetchone()
        self.assertEqual("retain-v054", profile["notes"])
        self.assertEqual(0, profile["daily_quota_mb"])
        self.assertEqual("v054 tablet", device["alias"])
        self.assertEqual("other", device["category"])
        self.assertEqual(0, device["favourite"])
        self.assertEqual("2026-09-01T11:00:00+00:00", history["captured_at"])
        self.assertEqual("", history["identity_id"])

    def test_v055_fixture_upgrades_notification_intelligence_in_order(self):
        path = self.fixture("v055")
        store = PolicyStore(str(path))
        with store._db() as db:
            row = db.execute(
                "SELECT title, source_severity, correlation_key, escalation_level, reopen_count FROM notifications"
            ).fetchone()
            timeline = [r[0] for r in db.execute("SELECT event FROM notification_timeline ORDER BY id").fetchall()]
        self.assertEqual("v055 retained notification", row["title"])
        self.assertEqual("warning", row["source_severity"])
        self.assertEqual("subject:192.0.2.55", row["correlation_key"])
        self.assertEqual(0, row["escalation_level"])
        self.assertEqual(0, row["reopen_count"])
        self.assertEqual(["baseline"], timeline)
        self.assertEqual(SCHEMA_VERSION, store.schema_status()["version"])

    def test_exact_v056_fixture_upgrades_and_retains_representative_state(self):
        path = self.fixture("v056")
        before = inspect_database(path)
        self.assertEqual(0, before["version"])
        store = PolicyStore(str(path))
        with store._db() as db:
            profile = db.execute("SELECT notes FROM profiles WHERE name='Fixture Child'").fetchone()
            device = db.execute("SELECT alias, notes FROM device_policy WHERE ip='192.0.2.56'").fetchone()
            notification = db.execute("SELECT title FROM notifications WHERE dedupe_key='fixture:v056'").fetchone()
        self.assertEqual("v056 retained", profile["notes"])
        self.assertEqual(("Fixture Tablet", "retain-me"), tuple(device))
        self.assertEqual("v056 fixture", notification["title"])
        self.assertEqual(SCHEMA_VERSION, store.schema_status()["version"])
        self.assertTrue(store.database_integrity_report()["ok"])

    def test_repeated_startup_is_idempotent_and_does_not_replace_recovery_point(self):
        path = self.fixture("v056")
        first = PolicyStore(str(path))
        backup = Path(first.upgrade_report["backup"]["path"])
        original = backup.read_bytes()
        first_migrations = first.schema_status()["migrations"]
        second = PolicyStore(str(path))
        self.assertEqual("unchanged", second.upgrade_report["state"])
        self.assertIsNone(second.upgrade_report["backup"])
        self.assertEqual(original, backup.read_bytes())
        self.assertEqual(first_migrations, second.schema_status()["migrations"])
        self.assertEqual(1, len(second.schema_status()["migrations"]))

    def test_interrupted_application_migration_keeps_verified_preupgrade_copy(self):
        path = self.fixture("v056")
        before = path.read_bytes()
        with patch.object(PolicyStore, "_init_db", side_effect=RuntimeError("simulated migration interruption")):
            with self.assertRaisesRegex(RuntimeError, "simulated migration interruption"):
                PolicyStore(str(path))
        backup = backup_path_for(path)
        self.assertTrue(backup.is_file())
        self.assertTrue(inspect_database(backup)["ok"])
        # The backup is a coherent SQLite snapshot, not a byte copy requirement;
        # the source remains unversioned because the schema marker was never reached.
        self.assertEqual(0, inspect_database(path)["version"])
        self.assertGreater(len(before), 0)

    def test_future_schema_fails_closed_before_any_migration(self):
        path = self.fixture("v056")
        db = sqlite3.connect(path)
        db.execute(f"PRAGMA user_version={SCHEMA_VERSION + 1}")
        db.close()
        with self.assertRaisesRegex(UpgradeSafetyError, "newer than this application supports"):
            PolicyStore(str(path))
        self.assertEqual(SCHEMA_VERSION + 1, inspect_database(path)["version"])
        self.assertFalse(backup_path_for(path).exists())

    def test_corrupt_database_fails_preflight_without_manufacturing_healthy_state(self):
        path = Path(self.tmp.name) / "corrupt.db"
        path.write_bytes(b"not a sqlite database")
        with self.assertRaises(UpgradeSafetyError):
            prepare_policy_database_upgrade(path)
        self.assertFalse(backup_path_for(path).exists())


class BackupRestoreAcceptanceTests(UpgradeFixtureMixin, unittest.TestCase):
    def test_verified_backup_is_reopenable_and_does_not_modify_source(self):
        path = self.fixture("v056")
        destination = Path(self.tmp.name) / "external-backup.db"
        before = inspect_database(path)
        report = create_verified_backup(path, destination)
        self.assertEqual("created", report["state"])
        self.assertTrue(inspect_database(destination)["ok"])
        self.assertEqual(before["table_counts"], inspect_database(path)["table_counts"])
        reused = create_verified_backup(path, destination)
        self.assertEqual("reused", reused["state"])

    def test_offline_upgrade_acceptance_proves_restore_retention_and_idempotency(self):
        path = self.fixture("v056")
        result = upgrade_probe(path)
        self.assertEqual("pass", result["state"])
        self.assertTrue(result["upgrade"]["integrity"])
        self.assertTrue(result["upgrade"]["retained_counts"])
        self.assertTrue(result["upgrade"]["idempotent_reopen"])
        self.assertEqual(SCHEMA_VERSION, result["upgrade"]["first_open_schema"])
        self.assertEqual(SCHEMA_VERSION, result["upgrade"]["second_open_schema"])
        self.assertEqual(0, inspect_database(path)["version"], "acceptance must never modify the supplied backup")

    def test_upgrade_acceptance_cli_runs_directly_from_scripts_directory_entrypoint(self):
        path = self.fixture("v056")
        proc = subprocess.run(
            [sys.executable, "scripts/upgrade_acceptance.py", str(path), "--expect-schema", str(SCHEMA_VERSION)],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        self.assertEqual(0, proc.returncode, proc.stdout)
        payload = json.loads(proc.stdout)
        self.assertEqual("pass", payload["state"])
        self.assertEqual(0, inspect_database(path)["version"])


class RuntimeAndReleaseWorkflowTests(UpgradeFixtureMixin, unittest.TestCase):
    class Component:
        def __init__(self, payload):
            self.payload = payload

        def snapshot(self):
            return self.payload

    def test_runtime_health_exposes_only_sanitized_upgrade_state_and_schema(self):
        store = PolicyStore(str(Path(self.tmp.name) / "runtime.db"))
        report = build_runtime_health(
            version="0.57.0",
            background_worker=self.Component({"worker_alive": True}),
            reconciler=self.Component({"worker_alive": True, "router_mutation": {"available": True}}),
            incident_monitor=self.Component({"worker_alive": True}),
            summary_delivery=self.Component({"worker_running": True}),
            policy_store=store,
        )
        self.assertTrue(report["ok"])
        self.assertEqual(SCHEMA_VERSION, report["database"]["schema_version"])
        self.assertEqual(SCHEMA_VERSION, report["database"]["schema_target"])
        self.assertEqual("created", report["database"]["upgrade_state"])
        self.assertNotIn("path", report["database"])

    def test_release_helper_validates_real_sqlite_backup_and_exposes_backup_gate(self):
        path = self.fixture("v056")
        evidence = release_patch.validate_sqlite_backup(path)
        self.assertTrue(evidence["ok"])
        self.assertEqual(0, evidence["schema_version"])
        help_text = release_patch.build_parser().format_help()
        self.assertIn("--backup-dir", help_text)
        self.assertIn("--skip-policy-backup", help_text)
        self.assertIn("scripts/upgrade_acceptance.py", (ROOT / "scripts" / "release_patch.py").read_text())

    def test_release_helper_dry_run_plans_external_backup_for_policy_service(self):
        destination = Path(self.tmp.name) / "backups"
        result = release_patch.create_live_policy_backup(
            expected_version="0.57.0",
            head_sha="abcdef0123456789",
            backup_dir=destination,
            dry_run=True,
        )
        self.assertIsNotNone(result)
        self.assertEqual(destination.resolve(), result.parent)
        self.assertIn("policy-pre-v0.57.0", result.name)


class V057SourceContractTests(unittest.TestCase):
    def test_release_identity_schema_contract_and_authority_boundary(self):
        main = (ROOT / "app" / "main.py").read_text()
        upgrade = (ROOT / "app" / "upgrade_safety.py").read_text()
        release = (ROOT / "scripts" / "release_patch.py").read_text()
        self.assertIn('version="0.57.0"', main)
        self.assertIn('SCHEMA_VERSION = 570', upgrade)
        self.assertIn('SCHEMA_RELEASE = "0.57.0"', upgrade)
        self.assertIn("s.backup(d)", release)
        self.assertNotIn("RouterOSAdapter", upgrade)
        self.assertNotIn("router.", upgrade)


if __name__ == "__main__":
    unittest.main()
