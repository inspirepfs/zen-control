import tempfile
import unittest
from pathlib import Path

from app.operations import OperationsMonitor
from app.policy_store import PolicyStore


class DurableOperationsStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "policy.db"
        self.store = PolicyStore(str(self.path))

    def tearDown(self):
        self.tmp.cleanup()

    def test_audit_is_durable_across_store_reopen(self):
        event = self.store.append_audit("TEST_EVENT", "tester", "durable detail")
        self.assertGreater(event["id"], 0)
        reopened = PolicyStore(str(self.path))
        rows = reopened.list_audit(10)
        self.assertEqual(rows[0]["event"], "TEST_EVENT")
        self.assertEqual(rows[0]["user"], "tester")
        self.assertEqual(rows[0]["detail"], "durable detail")
        self.assertEqual(reopened.audit_count(), 1)

    def test_snapshot_dedup_and_semantic_restore_survive_new_sqlite_ids(self):
        profile = self.store.create_profile(
            "Child", "blocked", "homework", "baseline", ["youtube"]
        )
        self.store.update_device("192.168.2.22", profile_id=profile["id"])
        baseline = self.store.create_config_snapshot("tester", "baseline", force=True)
        duplicate = self.store.create_config_snapshot("tester", "startup", force=False)
        self.assertFalse(duplicate["created"])
        self.assertEqual(duplicate["id"], baseline["id"])

        other = self.store.create_profile("Other", "normal", "normal")
        self.store.update_device("192.168.2.22", profile_id=other["id"])
        result = self.store.restore_config_snapshot(baseline["id"], "tester")
        self.assertEqual(result["restored"], baseline["id"])
        self.assertNotEqual(result["safety_snapshot"], baseline["id"])
        self.assertEqual(result["sha256"], baseline["sha256"])

        policies = self.store.list_device_policy()
        restored_profile = self.store.get_profile(policies["192.168.2.22"]["profile_id"])
        self.assertEqual(restored_profile["name"], "Child")
        self.assertEqual(restored_profile["desired_mode"], "blocked")


    def test_snapshot_restore_digest_ignores_aggregate_group_storage_timestamps(self):
        # Reproduce the slower-host failure deterministically: aggregate-group
        # timestamps are storage metadata and must not participate in semantic
        # configuration identity.
        with self.store._db() as db:
            db.execute(
                "UPDATE aggregate_policy_groups SET created_at=?, updated_at=?",
                ("2000-01-01T00:00:00+00:00", "2000-01-01T00:00:00+00:00"),
            )
        baseline = self.store.create_config_snapshot("tester", "baseline", force=True)

        result = self.store.restore_config_snapshot(baseline["id"], "tester")

        self.assertEqual(result["sha256"], baseline["sha256"])
        self.assertEqual(self.store.config_digest(), baseline["sha256"])

    def test_snapshot_restore_digest_ignores_service_approval_timestamp(self):
        self.store.save_service(
            "minecraft_test",
            "Minecraft test",
            "",
            "gaming",
            ["minecraft.example"],
            ["*minecraft*"],
            True,
        )
        self.store.set_service_enforcement_approved("minecraft_test", True)
        with self.store._db() as db:
            db.execute(
                "UPDATE services SET enforcement_approved_at=? WHERE key=?",
                ("2000-01-01T00:00:00+00:00", "minecraft_test"),
            )
        baseline = self.store.create_config_snapshot("tester", "approved", force=True)

        self.store.set_service_enforcement_approved("minecraft_test", False)
        result = self.store.restore_config_snapshot(baseline["id"], "tester")

        self.assertEqual(result["sha256"], baseline["sha256"])
        restored = self.store.get_service("minecraft_test")
        self.assertTrue(restored["enforcement_approved"])
        self.assertNotEqual(restored["enforcement_approved_at"], "2000-01-01T00:00:00+00:00")

    def test_database_integrity_knows_r11_tables(self):
        report = self.store.database_integrity_report()
        self.assertTrue(report["ok"])
        self.assertEqual(report["quick_check"], ["ok"])
        self.assertIn("audit_log", report["table_counts"])
        self.assertIn("config_snapshots", report["table_counts"])


class _FakeRouter:
    def __init__(self, ready=True):
        self.ready = ready

    def health(self):
        return {"connected": True, "router": "ZEN", "host": "192.168.2.1"}

    def get_security_posture(self):
        return {
            "enforcement_ready": self.ready,
            "status": "hardened" if self.ready else "critical",
            "score": 100 if self.ready else 60,
            "critical_count": 0 if self.ready else 1,
            "warning_count": 0,
            "checks": [],
        }

    def get_managed_state_inventory(self):
        return {
            "router": "ZEN",
            "counts": {
                "restricted_devices": 4,
                "managed_address_entries": 8,
                "managed_queues": 1,
                "managed_schedulers": 0,
                "managed_scripts": 3,
            },
            "address_lists": [],
            "queues": [],
            "schedulers": [],
            "scripts": [],
            "firewall": [],
        }


class _FakeReconciler:
    def snapshot(self):
        return {
            "worker_alive": True,
            "mode": "observe",
            "hold_active": False,
            "last": {"result": "ok"},
        }


class OperationsMonitorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = PolicyStore(str(Path(self.tmp.name) / "policy.db"))
        self.audit = []

    def tearDown(self):
        self.tmp.cleanup()

    def make(self, ready=True):
        return OperationsMonitor(
            policy_store=self.store,
            router=_FakeRouter(ready=ready),
            reconciler=_FakeReconciler(),
            audit=lambda event, actor, detail: self.audit.append((event, actor, detail)),
        )

    def test_startup_check_records_checkpoint_and_inventory(self):
        monitor = self.make(True)
        result = monitor.startup_check()
        self.assertEqual(result["status"], "ready")
        self.assertTrue(result["database"]["ok"])
        self.assertEqual(result["inventory"]["restricted_devices"], 4)
        self.assertGreater(result["snapshot"]["id"], 0)
        self.assertEqual(self.audit[-1][0], "STARTUP_INTEGRITY_OK")

    def test_readiness_closes_when_enforcement_posture_is_not_ready(self):
        report = self.make(False).readiness()
        self.assertFalse(report["ok"])
        self.assertEqual(report["components"]["security"], "fail")
        self.assertIn("RouterOS enforcement posture", report["issues"])

    def test_readiness_is_open_when_core_components_are_ready(self):
        report = self.make(True).readiness()
        self.assertTrue(report["ok"])
        self.assertEqual(report["components"]["database"], "ok")
        self.assertEqual(report["components"]["router"], "ok")
        self.assertEqual(report["components"]["reconciler"], "ok")


if __name__ == "__main__":
    unittest.main()
