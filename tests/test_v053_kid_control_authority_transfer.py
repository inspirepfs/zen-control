import copy
import os
import sys
import tempfile
import threading
import types
import unittest
from pathlib import Path

sys.modules.setdefault("routeros_api", types.SimpleNamespace())

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.kid_control_migration import translate_kid_control_snapshot
from app.kid_control_cutover import build_kid_control_cutover_readiness, failed_cutover_cleanup_complete
from app.policy_store import PolicyStore
from app.router import RouterOSAdapter, RouterError
from app.reconciler import AutoReconciler

DAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]


def household_snapshot(*, m8_online=True, static=True):
    profile = {
        "id": "*1", "name": "Kids", "disabled": False, "rate-limit": "",
        **{day: "7h-23h30m" for day in DAYS},
        **{f"tur-{day}": "" for day in DAYS},
    }
    devices = [
        {"id": "*2", "name": "Child Laptop", "mac-address": "02:00:00:00:10:01", "user": "Kids", "ip-address": "192.168.2.26"},
        {"id": "*3", "name": "Shared Display", "mac-address": "02:00:00:00:10:02", "user": "Kids", "ip-address": "192.168.2.17" if m8_online else "", "inactive": not m8_online},
        {"id": "*4", "name": "Child iPad", "mac-address": "02:00:00:00:10:03", "user": "Kids", "ip-address": "192.168.2.102"},
        {"id": "*5", "name": "Child Phone", "mac-address": "02:00:00:00:10:04", "user": "Kids", "ip-address": "192.168.2.121"},
        {"id": "*6", "dynamic": True, "name": "Access Point", "mac-address": "02:00:00:00:10:05", "user": "", "ip-address": "192.168.2.10"},
    ]
    leases = []
    for row in devices[:4]:
        if row.get("ip-address"):
            leases.append({
                "address": row["ip-address"], "mac": row["mac-address"],
                "dynamic": not static, "status": "bound",
            })
    return {
        "captured_at": "2026-09-11T22:00:00+00:00",
        "profiles": [profile], "devices": devices,
        "dhcp_leases": leases, "arp_entries": [],
    }


def staged_for(snapshot):
    payload = translate_kid_control_snapshot(snapshot)
    return {
        "source": "mikrotik_kid_control",
        "source_fingerprint": payload["source_fingerprint"],
        "payload": payload,
    }


class CutoverReadinessTests(unittest.TestCase):
    def ready(self, snapshot=None, **overrides):
        snapshot = snapshot or household_snapshot()
        preview = translate_kid_control_snapshot(snapshot)
        args = dict(
            staged=staged_for(snapshot), fresh_preview=preview, fresh_snapshot=snapshot,
            settings={"auto_reconcile_mode": "enforce"}, existing_profiles=[],
            existing_device_policy={}, current_cutover=None,
        )
        args.update(overrides)
        return build_kid_control_cutover_readiness(**args)

    def test_exact_household_is_ready_when_all_four_devices_have_static_leases(self):
        result = self.ready()
        self.assertTrue(result["ready"])
        self.assertEqual(len(result["devices"]), 4)
        self.assertTrue(all(d["ready"] and d["static_lease"] for d in result["devices"]))

    def test_offline_m8_blocks_cutover_instead_of_fabricating_identity(self):
        result = self.ready(household_snapshot(m8_online=False))
        self.assertFalse(result["ready"])
        m8 = next(d for d in result["devices"] if d["name"] == "Shared Display")
        self.assertFalse(m8["ready"])
        self.assertIn("unique live", m8["reason"])

    def test_dynamic_dhcp_lease_blocks_ip_authority_transfer(self):
        result = self.ready(household_snapshot(static=False))
        self.assertFalse(result["ready"])
        self.assertTrue(any(c["key"] == "device_identity" and not c["ok"] for c in result["checks"]))

    def test_auto_reconcile_must_be_enforce(self):
        result = self.ready(settings={"auto_reconcile_mode": "observe"})
        self.assertFalse(result["ready"])
        check = next(c for c in result["checks"] if c["key"] == "automatic_reconciliation")
        self.assertIn("OBSERVE", check["detail"])

    def test_stale_staged_fingerprint_blocks_cutover(self):
        snapshot = household_snapshot()
        preview = translate_kid_control_snapshot(snapshot)
        stale = staged_for(snapshot)
        stale["source_fingerprint"] = "0" * 64
        result = self.ready(snapshot, staged=stale, fresh_preview=preview)
        self.assertFalse(result["ready"])
        self.assertTrue(any(c["key"] == "source_unchanged" and not c["ok"] for c in result["checks"]))

    def test_semantically_conflicting_existing_profile_blocks(self):
        result = self.ready(existing_profiles=[{
            "id": 7, "name": "Kids", "desired_mode": "normal", "bandwidth_preset": "normal",
            "blocked_services": [], "daily_quota_mb": 0, "daily_quota_action": "blocked", "service_quotas": {},
        }])
        self.assertFalse(result["ready"])
        self.assertTrue(any(c["key"] == "local_profile_conflicts" and not c["ok"] for c in result["checks"]))

    def test_existing_equivalent_profile_is_reusable(self):
        result = self.ready(existing_profiles=[{
            "id": 7, "name": "Kids", "desired_mode": "blocked", "bandwidth_preset": "normal",
            "blocked_services": [], "daily_quota_mb": 0, "daily_quota_action": "blocked", "service_quotas": {},
        }])
        self.assertTrue(result["ready"])

    def test_prepared_or_failed_state_blocks_second_cutover(self):
        for state in ("prepared", "failed"):
            with self.subTest(state=state):
                result = self.ready(current_cutover={"state": state})
                self.assertFalse(result["ready"])
                self.assertFalse(result["checks"][0]["ok"])
                self.assertIn(state.upper(), result["checks"][0]["detail"])

    def test_authoritative_state_is_active_not_a_false_failed_gate(self):
        result = self.ready(current_cutover={"state": "authoritative"})
        self.assertFalse(result["ready"])
        self.assertEqual(result["authority_state"], "authoritative")
        self.assertTrue(result["checks"][0]["ok"])
        self.assertFalse(result["checks"][0]["blocking"])
        self.assertIn("ZEN authority is active", result["checks"][0]["detail"])

    def test_failed_cleanup_complete_requires_positive_proof_and_zero_errors(self):
        self.assertTrue(failed_cutover_cleanup_complete({
            "state": "failed",
            "evidence": {"cleanup_complete": True, "cleanup_errors": []},
        }))
        self.assertFalse(failed_cutover_cleanup_complete({
            "state": "failed",
            "evidence": {"cleanup_complete": True, "cleanup_errors": ["mode: failed"]},
        }))
        self.assertFalse(failed_cutover_cleanup_complete({
            "state": "failed",
            "evidence": {"cleanup_complete": False, "cleanup_errors": []},
        }))
        self.assertFalse(failed_cutover_cleanup_complete({
            "state": "authoritative",
            "evidence": {"cleanup_complete": True, "cleanup_errors": []},
        }))


class MaterialisationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = PolicyStore(os.path.join(self.tmp.name, "policy.db"))
        self.snapshot = household_snapshot()
        self.staged = self.store.stage_legacy_migration(
            "mikrotik_kid_control", translate_kid_control_snapshot(self.snapshot), actor="tester"
        )
    def tearDown(self):
        self.tmp.cleanup()

    def test_materialise_creates_one_profile_two_schedules_four_assignments(self):
        artifacts = self.store.materialize_kid_control_replacement(self.staged)
        self.assertEqual(len(self.store.list_profiles()), 1)
        self.assertEqual(len(self.store.list_schedule_plans()), 2)
        self.assertEqual(len(self.store.list_device_policy()), 4)
        self.assertEqual(sum(1 for p in artifacts["profiles"] if p["created"]), 1)
        self.assertEqual(sum(1 for p in artifacts["schedules"] if p["created"]), 2)

    def test_rollback_restores_empty_local_state(self):
        artifacts = self.store.materialize_kid_control_replacement(self.staged)
        self.store.rollback_kid_control_materialization(artifacts)
        self.assertEqual(self.store.list_profiles(), [])
        self.assertEqual(self.store.list_schedule_plans(), [])
        self.assertEqual(self.store.list_device_policy(), {})

    def test_equivalent_profile_and_schedule_are_reused_not_deleted_on_rollback(self):
        p = self.store.create_profile("Kids", "blocked", "normal")
        a = self.store.create_schedule_plan("existing-open", "profile", str(p["id"]), "mode", "normal", "07:00", DAYS)
        b = self.store.create_schedule_plan("existing-close", "profile", str(p["id"]), "mode", "blocked", "23:30", DAYS)
        artifacts = self.store.materialize_kid_control_replacement(self.staged)
        self.assertFalse(artifacts["profiles"][0]["created"])
        self.assertEqual({a, b}, {x["id"] for x in artifacts["schedules"]})
        self.assertTrue(all(not x["created"] for x in artifacts["schedules"]))
        self.store.rollback_kid_control_materialization(artifacts)
        self.assertEqual(len(self.store.list_profiles()), 1)
        self.assertEqual(len(self.store.list_schedule_plans()), 2)

    def test_existing_device_assignment_is_restored_exactly(self):
        old = self.store.create_profile("Old", "normal", "normal")
        self.store.update_device("192.168.2.26", alias="Existing Laptop", notes="keep", profile_id=old["id"], mode_override="inherit", category="laptop", favourite=True)
        with self.assertRaisesRegex(ValueError, "different profile"):
            self.store.materialize_kid_control_replacement(self.staged)
        row = self.store.list_device_policy()["192.168.2.26"]
        self.assertEqual(row["profile_id"], old["id"])
        self.assertEqual(row["alias"], "Existing Laptop")

    def test_cutover_event_history_is_durable_and_latest_state_wins(self):
        fp = self.staged["source_fingerprint"]
        prepared = self.store.record_legacy_migration_cutover("mikrotik_kid_control", "prepared", fp, actor="a", evidence={"x": 1})
        auth = self.store.record_legacy_migration_cutover("mikrotik_kid_control", "authoritative", fp, actor="a", evidence={"x": 2})
        latest = self.store.get_legacy_migration_cutover("mikrotik_kid_control")
        self.assertEqual(latest["id"], auth["id"])
        self.assertEqual(latest["state"], "authoritative")
        self.assertEqual(latest["evidence"], {"x": 2})
        self.assertEqual([x["state"] for x in self.store.list_legacy_migration_cutover_events()], ["authoritative", "prepared"])
        self.assertLess(prepared["id"], auth["id"])


class _Resource:
    def __init__(self, rows):
        self.rows = copy.deepcopy(rows)
        self.calls = []
    def get(self, **kwargs):
        rows = copy.deepcopy(self.rows)
        for key, value in kwargs.items():
            rows = [r for r in rows if str(r.get(key, r.get(key.replace('_','-'), ''))) == str(value)]
        return rows
    def add(self, **kwargs):
        row = {"id": f"*{len(self.rows)+10}", **kwargs}
        self.rows.append(row); self.calls.append(("add", copy.deepcopy(kwargs))); return {"id": row["id"]}
    def set(self, **kwargs):
        row_id = kwargs.pop("id")
        for row in self.rows:
            if row.get("id") == row_id or row.get(".id") == row_id:
                row.update(kwargs); self.calls.append(("set", {"id": row_id, **copy.deepcopy(kwargs)})); return
        raise KeyError(row_id)
    def remove(self, **kwargs):
        row_id = kwargs["id"]
        self.rows[:] = [r for r in self.rows if r.get("id") != row_id and r.get(".id") != row_id]
        self.calls.append(("remove", dict(kwargs)))


class _Api:
    def __init__(self):
        self.resources = {
            "/ip/dhcp-server/lease": _Resource([{"id": "*L", "address": "192.168.2.26", "mac-address": "02:00:00:00:10:01", "dynamic": "false"}]),
            "/ip/firewall/address-list": _Resource([]),
            "/ip/kid-control": _Resource([{"id": "*1", "name": "Kids", "disabled": "false"}]),
        }
    def get_resource(self, path): return self.resources[path]


class _Pool:
    def disconnect(self): pass


class RouterAuthorityBoundaryTests(unittest.TestCase):
    def adapter(self):
        api = _Api()
        adapter = RouterOSAdapter.__new__(RouterOSAdapter)
        adapter._session_local = threading.local()
        adapter._connect = lambda: (_Pool(), api)
        adapter._require_policy_write_gate = lambda: {"ok": True}
        return adapter, api

    def test_prepare_device_requires_existing_static_lease_and_only_adds_restricted_row(self):
        adapter, api = self.adapter()
        result = adapter.prepare_kid_control_migration_device("192.168.2.26", "02:00:00:00:10:01", "Child Laptop")
        self.assertTrue(result["created"])
        self.assertEqual(api.resources["/ip/dhcp-server/lease"].calls, [])
        self.assertEqual(api.resources["/ip/firewall/address-list"].calls[0][0], "add")

    def test_dynamic_lease_is_rejected_without_router_mutation(self):
        adapter, api = self.adapter()
        api.resources["/ip/dhcp-server/lease"].rows[0]["dynamic"] = "true"
        with self.assertRaisesRegex(RouterError, "dynamic"):
            adapter.prepare_kid_control_migration_device("192.168.2.26", "02:00:00:00:10:01", "Child Laptop")
        self.assertEqual(api.resources["/ip/firewall/address-list"].calls, [])

    def test_mac_mismatch_is_rejected(self):
        adapter, _ = self.adapter()
        with self.assertRaisesRegex(RouterError, "MAC mismatch"):
            adapter.prepare_kid_control_migration_device("192.168.2.26", "AA:BB:CC:DD:EE:FF", "Child Laptop")

    def test_legacy_profile_write_toggles_only_disabled_field(self):
        adapter, api = self.adapter()
        result = adapter.set_legacy_kid_control_profile_disabled("Kids", True, expected_id="*1")
        self.assertTrue(result["disabled"])
        call = api.resources["/ip/kid-control"].calls[-1]
        self.assertEqual(call[0], "set")
        self.assertEqual(set(call[1]), {"id", "disabled"})
        self.assertEqual(call[1]["disabled"], "true")

    def test_legacy_profile_identity_change_fails_closed(self):
        adapter, api = self.adapter()
        with self.assertRaisesRegex(RouterError, "identity changed"):
            adapter.set_legacy_kid_control_profile_disabled("Kids", True, expected_id="*other")
        self.assertEqual(api.resources["/ip/kid-control"].calls, [])

    def test_rollback_removes_only_migration_owned_restricted_row(self):
        adapter, api = self.adapter()
        r = api.resources["/ip/firewall/address-list"]
        r.rows.extend([
            {"id": "*A", "list": "Restricted_Devices", "address": "192.168.2.26", "comment": "Existing"},
            {"id": "*B", "list": "Restricted_Devices", "address": "192.168.2.26", "comment": "ZEN migration - Child Laptop"},
        ])
        result = adapter.rollback_kid_control_migration_device("192.168.2.26")
        self.assertTrue(result["removed"])
        self.assertEqual([x["id"] for x in r.rows], ["*A"])


class ReconcilerTransferGuardTests(unittest.TestCase):
    def test_authority_transfer_guard_owns_cycle_lock(self):
        obj = AutoReconciler.__new__(AutoReconciler)
        obj._cycle_lock = threading.Lock()
        obj._wake = threading.Event()
        with obj.authority_transfer_guard():
            self.assertFalse(obj._cycle_lock.acquire(blocking=False))
        self.assertTrue(obj._cycle_lock.acquire(blocking=False))
        obj._cycle_lock.release()


class SourceContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.main = (ROOT / "app/main.py").read_text()
        cls.router = (ROOT / "app/router.py").read_text()
        cls.template = (ROOT / "app/templates/kid_control_migration.html").read_text()
        cls.release = (ROOT / "app/release_readiness.py").read_text()

    def test_cutover_and_rollback_are_explicit_admin_routes(self):
        self.assertIn('@app.post("/local/migration/kid-control/cutover")', self.main)
        self.assertIn('@app.post("/local/migration/kid-control/rollback")', self.main)
        self.assertIn('user=Depends(require_role("admin"))', self.main)
        self.assertIn('_kid_control_authority_otp', self.main)

    def test_legacy_device_namespace_remains_write_forbidden(self):
        self.assertIn('READ_ONLY_LEGACY_ROUTER_PATHS = frozenset({\n    "/ip/kid-control/device",', self.main)
        self.assertIn('BOUNDED_LEGACY_AUTHORITY_WRITE_PATHS', self.main)
        self.assertNotIn('get_resource("/ip/kid-control/device").set', self.router)
        self.assertNotIn('get_resource("/ip/kid-control/device").remove', self.router)

    def test_failed_cleanup_is_finalized_without_replaying_completed_device_writes(self):
        self.assertIn('cleanup_already_completed = failed_cutover_cleanup_complete(cutover)', self.main)
        self.assertIn('_kid_control_verify_legacy_profiles_active(', self.main)
        self.assertIn('if str(previous.get("ip") or "") in created_addresses:', self.main)
        self.assertIn('"cleanup_complete": not cleanup_errors', self.main)
        self.assertIn('Kid Control rollback remains incomplete:', self.main)

    def test_stage_and_discard_are_blocked_while_failed_recovery_is_pending(self):
        self.assertGreaterEqual(self.main.count('in {"prepared", "authoritative", "failed"}'), 2)
        self.assertIn('awaiting recovery', self.main)

    def test_ui_exposes_readiness_and_rollback_not_delete(self):
        self.assertIn("READY FOR CUTOVER", self.template)
        self.assertIn("Roll back to legacy Kid Control", self.template)
        self.assertIn("The legacy configuration is not deleted", self.template)
        self.assertIn("FAILED · LEGACY RESTORED · FINALIZE", self.template)
        self.assertNotIn("Delete legacy Kid Control", self.template)


if __name__ == "__main__":
    unittest.main()
