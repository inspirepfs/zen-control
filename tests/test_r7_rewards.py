import json
import tempfile
import unittest
from pathlib import Path

from app.policy_store import PolicyStore


class RewardBankTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.tmp.name) / "policy.db")
        self.store = PolicyStore(self.db_path)
        self.ip = "192.168.2.22"

    def tearDown(self):
        self.tmp.cleanup()

    def test_adjustments_are_ledgered_and_bounded(self):
        initial = self.store.get_reward_account(self.ip)
        self.assertEqual(initial["balance_minutes"], 0)
        self.assertTrue(initial["enabled"])

        grant = self.store.adjust_reward_minutes(
            self.ip,
            60,
            reason="chores",
            actor="parent",
            kind="grant",
        )
        self.assertEqual(grant["balance_minutes"], 60)

        correction = self.store.adjust_reward_minutes(
            self.ip,
            -15,
            reason="correction",
            actor="parent",
            kind="deduct",
        )
        self.assertEqual(correction["balance_minutes"], 45)

        account = self.store.get_reward_account(self.ip, ledger_limit=10)
        self.assertEqual(account["balance_minutes"], 45)
        self.assertEqual([row["delta_minutes"] for row in account["ledger"][:2]], [-15, 60])

        with self.assertRaisesRegex(ValueError, "Insufficient reward balance"):
            self.store.adjust_reward_minutes(self.ip, -60, actor="parent")

        self.store.save_reward_settings("1", "120", "30", "60")
        with self.assertRaisesRegex(ValueError, "maximum is 120"):
            self.store.adjust_reward_minutes(self.ip, 90, actor="parent")

    def test_redemption_reservation_refunds_cleanly(self):
        self.store.adjust_reward_minutes(self.ip, 60, actor="parent", kind="grant")
        reservation = self.store.reserve_reward_redemption(
            self.ip, 30, actor="parent"
        )
        self.assertEqual(reservation["status"], "reserved")
        self.assertEqual(self.store.get_reward_account(self.ip)["balance_minutes"], 30)

        refunded = self.store.refund_reward_redemption(
            reservation["id"], note="router failed"
        )
        self.assertEqual(refunded["status"], "refunded")
        self.assertEqual(self.store.get_reward_account(self.ip)["balance_minutes"], 60)

        ledger = self.store.get_reward_account(self.ip, ledger_limit=10)["ledger"]
        self.assertEqual(ledger[0]["kind"], "refund")
        self.assertEqual(ledger[0]["delta_minutes"], 30)
        self.assertEqual(ledger[1]["kind"], "redeem")
        self.assertEqual(ledger[1]["delta_minutes"], -30)

    def test_completed_redemption_cannot_be_refunded_as_reserved(self):
        self.store.adjust_reward_minutes(self.ip, 30, actor="parent", kind="grant")
        reservation = self.store.reserve_reward_redemption(
            self.ip, 15, actor="parent"
        )
        completed = self.store.complete_reward_redemption(
            reservation["id"], restore_at="2026-09-08T21:30:00+01:00"
        )
        self.assertEqual(completed["status"], "applied")
        self.assertEqual(self.store.get_reward_account(self.ip)["balance_minutes"], 15)
        with self.assertRaisesRegex(ValueError, "Only reserved"):
            self.store.refund_reward_redemption(reservation["id"])

    def test_stale_reserved_redemption_is_recovered(self):
        self.store.adjust_reward_minutes(self.ip, 30, actor="parent", kind="grant")
        reservation = self.store.reserve_reward_redemption(
            self.ip, 15, actor="parent"
        )
        self.assertEqual(self.store.get_reward_account(self.ip)["balance_minutes"], 15)
        with self.store._db() as db:
            db.execute(
                "UPDATE reward_redemptions SET created_at=? WHERE id=?",
                ("2020-01-01T00:00:00+00:00", reservation["id"]),
            )
        recovered = self.store.recover_stale_reward_redemptions(60)
        self.assertEqual(len(recovered), 1)
        self.assertEqual(recovered[0]["status"], "refunded")
        self.assertEqual(self.store.get_reward_account(self.ip)["balance_minutes"], 30)

    def test_config_round_trip_preserves_reward_settings_not_operational_balance(self):
        self.store.save_reward_settings("1", "480", "60", "30")
        self.store.adjust_reward_minutes(self.ip, 90, actor="parent", kind="grant")
        exported = self.store.export_config()

        other_path = str(Path(self.tmp.name) / "restored.db")
        restored = PolicyStore(other_path)
        restored.import_config(json.loads(json.dumps(exported)))
        settings = restored.get_settings()
        self.assertEqual(settings["reward_bank_enabled"], "1")
        self.assertEqual(settings["reward_bank_max_minutes"], "480")
        self.assertEqual(settings["reward_default_grant_minutes"], "60")
        self.assertEqual(settings["reward_max_redeem_minutes"], "30")
        self.assertEqual(restored.get_reward_account(self.ip)["balance_minutes"], 0)

    def test_delete_reward_account_prevents_ip_reuse_inheritance(self):
        self.store.adjust_reward_minutes(self.ip, 45, actor="parent", kind="grant")
        self.store.delete_reward_account(self.ip)
        account = self.store.get_reward_account(self.ip, ledger_limit=10)
        self.assertEqual(account["balance_minutes"], 0)
        self.assertEqual(account["ledger"], [])


if __name__ == "__main__":
    unittest.main()
