import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from app.policy_store import PolicyStore
from app.quota import bytes_for_mb
from app.reward_recovery import (
    recover_pending_reward_redemptions,
    reward_redemption_reference,
)

import sys
import types
sys.modules.setdefault("routeros_api", types.SimpleNamespace())
from app.router import RouterError, RouterOSAdapter


class FakeRouterFailure(RuntimeError):
    pass


class FakeRewardRouter:
    def __init__(self, states=None, error=None):
        self.states = states or {}
        self.error = error

    def get_device_temporary_access(self, ip):
        if self.error:
            raise self.error
        return dict(self.states.get(ip) or {"active": False, "address": ip})


class RewardRecoveryClosureTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = PolicyStore(str(Path(self.tmp.name) / "policy.db"))
        self.ip = "192.168.2.22"
        self.store.adjust_reward_minutes(self.ip, 60, actor="parent", kind="grant")
        self.audit_events = []

    def tearDown(self):
        self.tmp.cleanup()

    def reserve(self, minutes=30):
        return self.store.reserve_reward_redemption(self.ip, minutes, actor="parent")

    def status(self, redemption_id):
        with self.store._db() as db:
            return db.execute(
                "SELECT status FROM reward_redemptions WHERE id=?", (redemption_id,)
            ).fetchone()["status"]

    def audit(self, event, actor, detail):
        self.audit_events.append((event, actor, detail))

    def recover(self, router):
        return recover_pending_reward_redemptions(
            policy_store=self.store,
            router=router,
            audit=self.audit,
            router_error=FakeRouterFailure,
        )

    def test_matching_bound_routeros_grant_completes_not_refunds(self):
        reservation = self.reserve()
        reference = reward_redemption_reference(reservation["id"])
        result = self.recover(
            FakeRewardRouter(
                {self.ip: {"active": True, "reference": reference, "restore_at": "later"}}
            )
        )
        self.assertEqual(result[0]["recovery"], "applied")
        self.assertEqual(self.status(reservation["id"]), "applied")
        self.assertEqual(self.store.get_reward_account(self.ip)["balance_minutes"], 30)
        self.assertIn("REWARD_REDEMPTION_RECOVERED_APPLIED", [e[0] for e in self.audit_events])

    def test_expired_bound_routeros_grant_is_still_charged(self):
        reservation = self.reserve(15)
        reference = reward_redemption_reference(reservation["id"])
        result = self.recover(
            FakeRewardRouter(
                {self.ip: {"active": False, "expired": True, "reference": reference}}
            )
        )
        self.assertEqual(result[0]["recovery"], "applied")
        self.assertEqual(self.status(reservation["id"]), "applied")
        self.assertEqual(self.store.get_reward_account(self.ip)["balance_minutes"], 45)

    def test_proven_absence_refunds_immediately_after_restart(self):
        reservation = self.reserve()
        # No age manipulation: startup recovery must consider every RESERVED row.
        result = self.recover(FakeRewardRouter())
        self.assertEqual(result[0]["recovery"], "refunded")
        self.assertEqual(self.status(reservation["id"]), "refunded")
        self.assertEqual(self.store.get_reward_account(self.ip)["balance_minutes"], 60)

    def test_routeros_unavailable_defers_and_keeps_minutes_reserved(self):
        reservation = self.reserve()
        result = self.recover(FakeRewardRouter(error=FakeRouterFailure("api down")))
        self.assertEqual(result[0]["recovery"], "deferred")
        self.assertEqual(self.status(reservation["id"]), "reserved")
        self.assertEqual(self.store.get_reward_account(self.ip)["balance_minutes"], 30)


    def test_operator_recovery_can_scope_to_one_device(self):
        other = "192.168.2.24"
        self.store.adjust_reward_minutes(other, 30, actor="parent", kind="grant")
        first = self.reserve(15)
        second = self.store.reserve_reward_redemption(other, 15, actor="parent")
        result = recover_pending_reward_redemptions(
            policy_store=self.store,
            router=FakeRewardRouter(),
            audit=self.audit,
            router_error=FakeRouterFailure,
            ip=self.ip,
        )
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["id"], first["id"])
        self.assertEqual(self.status(first["id"]), "refunded")
        self.assertEqual(self.status(second["id"]), "reserved")

    def test_second_redemption_is_blocked_while_first_is_pending_recovery(self):
        first = self.reserve(15)
        with self.assertRaisesRegex(ValueError, "still pending recovery"):
            self.store.reserve_reward_redemption(self.ip, 15, actor="parent")
        self.assertEqual(self.status(first["id"]), "reserved")
        self.assertEqual(self.store.get_reward_account(self.ip)["balance_minutes"], 45)

    def test_unrelated_active_temporary_override_never_causes_refund(self):
        reservation = self.reserve()
        result = self.recover(
            FakeRewardRouter({self.ip: {"active": True, "reference": "manual-other"}})
        )
        self.assertEqual(result[0]["recovery"], "deferred")
        self.assertEqual(self.status(reservation["id"]), "reserved")
        self.assertEqual(self.store.get_reward_account(self.ip)["balance_minutes"], 30)


class _Pool:
    def disconnect(self):
        return None


class _Resource:
    def __init__(self, entries=None, fail_set=False, events=None, name="resource"):
        self.entries = list(entries or [])
        self.fail_set = fail_set
        self.events = events if events is not None else []
        self.name = name
        self.next_id = 10

    def get(self, **kwargs):
        if not kwargs:
            return list(self.entries)
        rows = self.entries
        for key, value in kwargs.items():
            rows = [row for row in rows if row.get(key) == value]
        return [dict(row) for row in rows]

    def add(self, **kwargs):
        row = {"id": f"*{self.next_id}", **kwargs}
        self.next_id += 1
        self.entries.append(row)
        self.events.append((self.name, "add", dict(kwargs)))
        return row["id"]

    def set(self, **kwargs):
        self.events.append((self.name, "set", dict(kwargs)))
        if self.fail_set:
            raise RuntimeError(f"{self.name} set failed")
        wanted = kwargs.pop("id")
        for row in self.entries:
            if row.get("id") == wanted:
                row.update(kwargs)
                return
        raise RuntimeError("id not found")


class _API:
    def __init__(self, script, scheduler):
        self.script = script
        self.scheduler = scheduler

    def get_resource(self, path):
        if path == "/system/script":
            return self.script
        if path == "/system/scheduler":
            return self.scheduler
        raise AssertionError(path)


class TemporaryAccessClosureTests(unittest.TestCase):
    def make_router(self, *, existing, scheduler_fail=False):
        router = RouterOSAdapter.__new__(RouterOSAdapter)
        router.timezone = "Europe/London"
        router.device_slow_limit = "128k/256k"
        router._require_policy_write_gate = Mock()
        router._validate_device_block_primitive = Mock()
        router._validate_restricted_device = Mock()
        router._cleanup_device_temp_resources = Mock(return_value={"schedulers": 1, "scripts": 1})
        router.get_device_enforcement = Mock(return_value={"mode": "normal" if existing else "blocked"})
        events = []
        address = "192.168.2.22"
        sched_name = router._device_temp_scheduler_name(address)
        script_name = router._device_temp_script_name(address)
        script = _Resource(
            [{"id": "*2", "name": script_name, "source": "old", "comment": "old"}] if existing else [],
            events=events,
            name="script",
        )
        scheduler = _Resource(
            [{"id": "*1", "name": sched_name, "comment": "old", "disabled": "false"}] if existing else [],
            fail_set=scheduler_fail,
            events=events,
            name="scheduler",
        )
        api = _API(script, scheduler)
        router._connect = Mock(return_value=(_Pool(), api))
        router.set_device_mode = Mock(return_value={"mode": "normal"})
        return router, events, scheduler, script

    def test_extension_failure_preserves_existing_fail_safe(self):
        router, events, scheduler, script = self.make_router(existing=True, scheduler_fail=True)
        router.get_device_temporary_access = Mock(
            return_value={
                "active": True,
                "restore_mode": "blocked",
                "reference": "redemption:7",
            }
        )
        with self.assertRaisesRegex(RouterError, "extend temporary access fail-safe"):
            router.set_device_temporary_normal("192.168.2.22", 30)
        router._cleanup_device_temp_resources.assert_not_called()
        router.set_device_mode.assert_not_called()
        self.assertEqual(len(scheduler.entries), 1)
        self.assertEqual(len(script.entries), 1)

    def test_extension_updates_in_place_and_preserves_original_reference(self):
        router, events, scheduler, _ = self.make_router(existing=True)
        states = [
            {"active": True, "restore_mode": "blocked", "reference": "redemption:7"},
            {"active": True, "restore_mode": "blocked", "reference": "redemption:7"},
        ]
        router.get_device_temporary_access = Mock(side_effect=states)
        result = router.set_device_temporary_normal(
            "192.168.2.22", 60, reference="redemption:99"
        )
        router._cleanup_device_temp_resources.assert_not_called()
        self.assertTrue(result["extended"])
        self.assertEqual(result["reference"], "redemption:7")
        self.assertEqual(len([e for e in events if e[1] == "add"]), 0)
        scheduler_set = next(e for e in events if e[0] == "scheduler" and e[1] == "set")
        self.assertIn("reference=redemption:7", scheduler_set[2]["comment"])

    def test_new_reward_reference_is_bound_only_after_validated_mode_write(self):
        router, events, scheduler, _ = self.make_router(existing=False)
        router.get_device_temporary_access = Mock(
            side_effect=[
                {"active": False},
                {"active": True, "restore_mode": "blocked", "reference": "redemption:12"},
            ]
        )
        def mode_write(*args, **kwargs):
            events.append(("mode", "write", {}))
            return {"mode": "normal"}
        router.set_device_mode = Mock(side_effect=mode_write)
        result = router.set_device_temporary_normal(
            "192.168.2.22", 30, restore_mode="blocked", reference="redemption:12"
        )
        add_event = next(e for e in events if e[0] == "scheduler" and e[1] == "add")
        bind_event = [e for e in events if e[0] == "scheduler" and e[1] == "set"][-1]
        mode_index = events.index(next(e for e in events if e[0] == "mode"))
        bind_index = events.index(bind_event)
        self.assertNotIn("reference=", add_event[2]["comment"])
        self.assertLess(mode_index, bind_index)
        self.assertIn("reference=redemption:12", bind_event[2]["comment"])
        self.assertEqual(result["reference"], "redemption:12")

    def test_reference_metadata_rejects_delimiters(self):
        router, _, _, _ = self.make_router(existing=False)
        router.get_device_temporary_access = Mock(return_value={"active": False})
        with self.assertRaisesRegex(RouterError, "reference contains invalid"):
            router.set_device_temporary_normal(
                "192.168.2.22", 30, restore_mode="blocked", reference="redemption:1|evil=x"
            )


class QuotaLifecycleClosureTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = PolicyStore(str(Path(self.tmp.name) / "policy.db"))
        self.ip = "192.168.2.23"
        profile = self.store.create_profile(
            "Quota lifecycle",
            "normal",
            "normal",
            "",
            [],
            100,
            "blocked",
            {"youtube": 25},
        )
        self.store.update_device(self.ip, profile_id=profile["id"])
        self.store.save_quota_settings("1", "80")

    def tearDown(self):
        self.tmp.cleanup()

    def usage(self, day, total, youtube=0):
        return {
            "available": True,
            "day": day,
            "timezone": "Europe/London",
            "total_bytes": bytes_for_mb(total),
            "service_bytes": {"youtube": bytes_for_mb(youtube)},
        }

    def test_late_usage_crossing_limit_is_enforced_on_next_resolution(self):
        before = self.store.compute_effective_policy(
            self.ip, quota_usage=self.usage("2026-09-10", 90, 20)
        )
        after = self.store.compute_effective_policy(
            self.ip, quota_usage=self.usage("2026-09-10", 110, 30)
        )
        self.assertEqual(before["mode"], "normal")
        self.assertEqual(after["mode"], "blocked")
        self.assertIn("youtube", after["blocked_services"])

    def test_new_calendar_day_releases_previous_quota_without_sticky_state(self):
        exhausted = self.store.compute_effective_policy(
            self.ip, quota_usage=self.usage("2026-09-10", 110, 30)
        )
        reset = self.store.compute_effective_policy(
            self.ip, quota_usage=self.usage("2026-09-11", 0, 0)
        )
        self.assertTrue(exhausted["quota_active"])
        self.assertFalse(reset["quota_active"])
        self.assertEqual(reset["mode"], "normal")
        self.assertNotIn("youtube", reset["blocked_services"])

    def test_telemetry_loss_never_reuses_previous_exhausted_state(self):
        exhausted = self.store.compute_effective_policy(
            self.ip, quota_usage=self.usage("2026-09-10", 110, 30)
        )
        unavailable = self.store.compute_effective_policy(
            self.ip, quota_usage={"available": False, "error": "telemetry down"}
        )
        self.assertTrue(exhausted["quota_active"])
        self.assertFalse(unavailable["quota_active"])
        self.assertFalse(unavailable["quota_state"]["available"])
        self.assertEqual(unavailable["mode"], "normal")


class RewardRouteContractTests(unittest.TestCase):
    def test_route_binds_redemption_and_never_blindly_refunds_uncertain_grant(self):
        source = Path("app/main.py").read_text()
        self.assertIn("reference=reward_redemption_reference(reservation[\"id\"])", source)
        self.assertIn("retained as reserved after uncertain ", source)
        self.assertIn("RouterOS result; verify_error=", source)
        self.assertIn("Reward time can only be redeemed when the effective device mode is SLOW or BLOCKED", source)
        self.assertIn('@app.post("/devices/rewards/recover")', source)
        index = Path("app/templates/index.html").read_text()
        self.assertIn("PENDING RECOVERY", index)
        self.assertIn("Recheck RouterOS evidence", index)
        self.assertNotIn("recover_stale_reward_redemptions()", source)


if __name__ == "__main__":
    unittest.main()
