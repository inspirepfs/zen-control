import copy
import json
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

from app.policy_store import PolicyStore
from app.router import RouterOSAdapter


DAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]


def legacy_snapshot():
    profile = {
        ".id": "*1",
        "name": "Kids",
        "mon": "7h-23h30m",
        "tue": "7h-23h30m",
        "wed": "7h-23h30m",
        "thu": "7h-23h30m",
        "fri": "7h-23h30m",
        "sat": "7h-23h30m",
        "sun": "7h-23h30m",
        "rate-limit": "",
        "tur-mon": "", "tur-tue": "", "tur-wed": "", "tur-thu": "",
        "tur-fri": "", "tur-sat": "", "tur-sun": "",
    }
    configured = [
        {".id": "*2", "name": "Child Laptop", "mac-address": "02:00:00:00:10:01", "user": "Kids", "ip-address": "192.168.2.26", "activity": "dns.google", "bytes-down": "7.4GiB"},
        {".id": "*3", "name": "Shared Display", "mac-address": "02:00:00:00:10:02", "user": "Kids", "ip-address": "", "inactive": "true", "bytes-down": "0"},
        {".id": "*4", "name": "Child iPad", "mac-address": "02:00:00:00:10:03", "user": "Kids", "ip-address": "fe80::1429:a762:315b:b5af,192.168.2.102", "activity": "mask.icloud.com", "bytes-down": "6.7GiB"},
        {".id": "*5", "name": "Child Phone", "mac-address": "02:00:00:00:10:04", "user": "Kids", "ip-address": "fe80::acfb:cbff:fe81:9fc6,192.168.2.121", "activity": "play.googleapis.com", "bytes-down": "1898.4MiB"},
    ]
    dynamic = [
        {".id": "*6", "dynamic": "true", "name": "Access Point", "mac-address": "02:00:00:00:10:05", "user": "", "ip-address": "192.168.2.10", "activity": "unifi"},
        {".id": "*7", "dynamic": "true", "name": "ZEN Host", "mac-address": "02:00:00:00:10:06", "user": "", "ip-address": "192.168.2.240", "activity": "region1.v2.argotunnel.com"},
    ]
    return {
        "captured_at": "2026-09-11T10:00:00+00:00",
        "profiles": [profile],
        "devices": configured + dynamic,
        "dhcp_leases": [],
        "arp_entries": [
            {"address": "192.168.2.26", "mac": "02:00:00:00:10:01", "complete": True},
            {"address": "192.168.2.102", "mac": "02:00:00:00:10:03", "complete": True},
            {"address": "192.168.2.121", "mac": "02:00:00:00:10:04", "complete": True},
        ],
    }


class KidControlTranslationTests(unittest.TestCase):
    def translate(self, snapshot=None):
        from app.kid_control_migration import translate_kid_control_snapshot
        return translate_kid_control_snapshot(snapshot or legacy_snapshot())

    def test_exact_household_fixture_translates_one_profile_four_devices(self):
        result = self.translate()
        self.assertEqual(result["schema"], "zen_kid_control_migration_v1")
        self.assertEqual(result["summary"]["legacy_profiles"], 1)
        self.assertEqual(result["summary"]["configured_devices"], 4)
        self.assertEqual(result["summary"]["ignored_dynamic_devices"], 2)
        self.assertEqual([p["legacy_name"] for p in result["profiles"]], ["Kids"])
        self.assertEqual([d["legacy_name"] for d in result["devices"]], ["Child Laptop", "Shared Display", "Child iPad", "Child Phone"])

    def test_all_seven_0700_2330_windows_collapse_to_two_zen_schedule_events(self):
        result = self.translate()
        profile = result["profiles"][0]
        proposed = profile["proposed"]
        self.assertEqual(proposed["desired_mode"], "blocked")
        self.assertEqual(proposed["bandwidth_preset"], "normal")
        self.assertEqual(proposed["schedule"], [
            {"days": DAYS, "time": "07:00", "mode": "normal"},
            {"days": DAYS, "time": "23:30", "mode": "blocked"},
        ])
        self.assertEqual(profile["warnings"], [])

    def test_empty_rate_limit_and_tur_fields_do_not_invent_bandwidth_policy(self):
        result = self.translate()
        profile = result["profiles"][0]
        self.assertEqual(profile["proposed"]["bandwidth_preset"], "normal")
        self.assertEqual(profile["legacy_rate_limit"], "")
        self.assertEqual(profile["legacy_unlimited_windows"], {})
        self.assertFalse(any("bandwidth" in item.lower() for item in profile["warnings"]))

    def test_dynamic_discovery_rows_are_never_migration_devices(self):
        result = self.translate()
        macs = {item["mac"] for item in result["devices"]}
        self.assertNotIn("02:00:00:00:10:05", macs)
        self.assertNotIn("02:00:00:00:10:06", macs)

    def test_activity_rates_and_counters_are_not_copied_into_staged_payload(self):
        rendered = json.dumps(self.translate(), sort_keys=True).lower()
        for forbidden in ("dns.google", "mask.icloud.com", "bytes-down", "bytes_up", "rate-down", "activity"):
            self.assertNotIn(forbidden, rendered)

    def test_mac_is_stable_identity_and_ipv4_is_evidence_only(self):
        result = self.translate()
        by_name = {item["legacy_name"]: item for item in result["devices"]}
        laptop = by_name["Child Laptop"]
        self.assertEqual(laptop["mac"], "02:00:00:00:10:01")
        self.assertEqual(laptop["identity"]["state"], "matched")
        self.assertEqual(laptop["identity"]["ipv4"], "192.168.2.26")
        self.assertEqual(laptop["proposed"]["identity_key"], "mac:02:00:00:00:10:01")

    def test_offline_device_is_retained_without_fabricated_ip(self):
        result = self.translate()
        m8 = next(item for item in result["devices"] if item["legacy_name"] == "Shared Display")
        self.assertEqual(m8["identity"]["state"], "unresolved")
        self.assertEqual(m8["identity"]["ipv4"], "")
        self.assertTrue(m8["legacy_inactive"])
        self.assertEqual(m8["proposed"]["profile_name"], "Kids")

    def test_dhcp_can_resolve_offline_configured_device_by_mac(self):
        snapshot = legacy_snapshot()
        snapshot["dhcp_leases"].append({"address": "192.168.2.17", "mac": "02:00:00:00:10:02", "status": "bound"})
        result = self.translate(snapshot)
        m8 = next(item for item in result["devices"] if item["legacy_name"] == "Shared Display")
        self.assertEqual(m8["identity"]["state"], "matched")
        self.assertEqual(m8["identity"]["ipv4"], "192.168.2.17")
        self.assertIn("dhcp", m8["identity"]["evidence"])

    def test_ambiguous_mac_to_multiple_ipv4s_fails_closed(self):
        snapshot = legacy_snapshot()
        device = snapshot["devices"][1]
        snapshot["dhcp_leases"] += [
            {"address": "192.168.2.17", "mac": device["mac-address"]},
            {"address": "192.168.2.18", "mac": device["mac-address"]},
        ]
        result = self.translate(snapshot)
        m8 = next(item for item in result["devices"] if item["legacy_name"] == "Shared Display")
        self.assertEqual(m8["identity"]["state"], "ambiguous")
        self.assertEqual(m8["identity"]["ipv4"], "")
        self.assertEqual(m8["identity"]["candidates"], ["192.168.2.17", "192.168.2.18"])

    def test_unknown_profile_assignment_is_warning_not_silent_remap(self):
        snapshot = legacy_snapshot()
        snapshot["devices"][0]["user"] = "Missing"
        result = self.translate(snapshot)
        laptop = next(item for item in result["devices"] if item["legacy_name"] == "Child Laptop")
        self.assertEqual(laptop["proposed"]["profile_name"], "")
        self.assertTrue(any("missing legacy profile" in item.lower() for item in laptop["warnings"]))
        self.assertGreater(result["summary"]["warnings"], 0)

    def test_overnight_window_is_not_silently_mistranslated(self):
        snapshot = legacy_snapshot()
        snapshot["profiles"][0]["mon"] = "23h-7h"
        result = self.translate(snapshot)
        profile = result["profiles"][0]
        self.assertTrue(any("overnight" in item.lower() for item in profile["warnings"]))
        self.assertFalse(any(event["days"] == ["mon"] for event in profile["proposed"]["schedule"]))

    def test_nonempty_rate_limit_is_preserved_as_review_required_not_guessed(self):
        snapshot = legacy_snapshot()
        snapshot["profiles"][0]["rate-limit"] = "5M"
        result = self.translate(snapshot)
        profile = result["profiles"][0]
        self.assertEqual(profile["legacy_rate_limit"], "5M")
        self.assertEqual(profile["proposed"]["bandwidth_preset"], "normal")
        self.assertTrue(any("manual bandwidth mapping" in item.lower() for item in profile["warnings"]))

    def test_tur_window_is_preserved_as_review_required_not_silently_dropped(self):
        snapshot = legacy_snapshot()
        snapshot["profiles"][0]["tur-mon"] = "12h-13h"
        result = self.translate(snapshot)
        profile = result["profiles"][0]
        self.assertEqual(profile["legacy_unlimited_windows"], {"mon": "12h-13h"})
        self.assertTrue(any("unlimited-rate" in item.lower() for item in profile["warnings"]))

    def test_policy_fingerprint_ignores_activity_counters_dynamic_rows_and_capture_time(self):
        from app.kid_control_migration import legacy_policy_fingerprint
        a = legacy_snapshot()
        b = copy.deepcopy(a)
        b["captured_at"] = "2030-01-01T00:00:00+00:00"
        b["devices"][0]["activity"] = "different.example"
        b["devices"][0]["bytes-down"] = "999TiB"
        b["devices"].append({"dynamic": "true", "mac-address": "AA:BB:CC:DD:EE:FF", "ip-address": "192.168.2.250"})
        self.assertEqual(legacy_policy_fingerprint(a), legacy_policy_fingerprint(b))

    def test_policy_fingerprint_changes_when_schedule_or_assignment_changes(self):
        from app.kid_control_migration import legacy_policy_fingerprint
        base = legacy_snapshot()
        schedule_change = copy.deepcopy(base)
        schedule_change["profiles"][0]["mon"] = "8h-23h30m"
        assignment_change = copy.deepcopy(base)
        assignment_change["devices"][0]["user"] = "Other"
        self.assertNotEqual(legacy_policy_fingerprint(base), legacy_policy_fingerprint(schedule_change))
        self.assertNotEqual(legacy_policy_fingerprint(base), legacy_policy_fingerprint(assignment_change))


class _ReadOnlyResource:
    def __init__(self, rows):
        self.rows = copy.deepcopy(rows)
        self.mutations = []
    def get(self, **kwargs):
        return copy.deepcopy(self.rows)
    def add(self, **kwargs):
        self.mutations.append(("add", kwargs)); raise AssertionError("migration discovery must be read-only")
    def set(self, **kwargs):
        self.mutations.append(("set", kwargs)); raise AssertionError("migration discovery must be read-only")
    def remove(self, **kwargs):
        self.mutations.append(("remove", kwargs)); raise AssertionError("migration discovery must be read-only")
    def call(self, *args, **kwargs):
        self.mutations.append(("call", args, kwargs)); raise AssertionError("migration discovery must be read-only")


class _Api:
    def __init__(self, snapshot):
        self.resources = {
            "/ip/kid-control": _ReadOnlyResource(snapshot["profiles"]),
            "/ip/kid-control/device": _ReadOnlyResource(snapshot["devices"]),
            "/ip/dhcp-server/lease": _ReadOnlyResource([
                {"address": row.get("address", ""), "mac-address": row.get("mac", ""), "status": row.get("status", ""), "dynamic": row.get("dynamic", False)}
                for row in snapshot["dhcp_leases"]
            ]),
            "/ip/arp": _ReadOnlyResource([
                {"address": row.get("address", ""), "mac-address": row.get("mac", ""), "complete": "true" if row.get("complete") else "false", "dynamic": "true"}
                for row in snapshot["arp_entries"]
            ]),
        }
    def get_resource(self, path):
        return self.resources[path]


class _Pool:
    def __init__(self): self.disconnects = 0
    def disconnect(self): self.disconnects += 1


class KidControlRouterReadOnlyTests(unittest.TestCase):
    def test_adapter_snapshot_reads_only_the_four_inventory_resources(self):
        snapshot = legacy_snapshot()
        api = _Api(snapshot)
        pool = _Pool()
        adapter = RouterOSAdapter.__new__(RouterOSAdapter)
        adapter._session_local = threading.local()
        adapter._connect = lambda: (pool, api)
        result = adapter.get_legacy_kid_control_snapshot()
        self.assertEqual(len(result["profiles"]), 1)
        self.assertEqual(len(result["devices"]), 6)
        for resource in api.resources.values():
            self.assertEqual(resource.mutations, [])
        self.assertEqual(pool.disconnects, 1)

    def test_snapshot_normalizes_only_bounded_fields_not_activity_or_counters(self):
        snapshot = legacy_snapshot()
        api = _Api(snapshot)
        pool = _Pool()
        adapter = RouterOSAdapter.__new__(RouterOSAdapter)
        adapter._session_local = threading.local()
        adapter._connect = lambda: (pool, api)
        result = adapter.get_legacy_kid_control_snapshot()
        rendered = json.dumps(result).lower()
        self.assertNotIn("dns.google", rendered)
        self.assertNotIn("bytes-down", rendered)
        self.assertNotIn("rate-down", rendered)


class KidControlStagingStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = PolicyStore(os.path.join(self.tmp.name, "policy.db"))
    def tearDown(self):
        self.tmp.cleanup()

    def translated(self):
        from app.kid_control_migration import translate_kid_control_snapshot
        return translate_kid_control_snapshot(legacy_snapshot())

    def test_stage_is_durable_local_only_and_idempotently_replaces_same_source(self):
        payload = self.translated()
        first = self.store.stage_legacy_migration("mikrotik_kid_control", payload, actor="tester")
        self.assertEqual(first["state"], "staged")
        self.assertEqual(first["source_fingerprint"], payload["source_fingerprint"])
        second_payload = copy.deepcopy(payload)
        second_payload["captured_at"] = "2026-09-11T11:00:00+00:00"
        second = self.store.stage_legacy_migration("mikrotik_kid_control", second_payload, actor="tester")
        self.assertEqual(first["source"], second["source"])
        rows = self.store.list_legacy_migration_stages()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["payload"]["captured_at"], "2026-09-11T11:00:00+00:00")

    def test_staging_does_not_create_active_profile_schedule_or_device_policy(self):
        self.store.stage_legacy_migration("mikrotik_kid_control", self.translated(), actor="tester")
        self.assertEqual(self.store.list_profiles(), [])
        self.assertEqual(self.store.list_schedule_plans(), [])
        self.assertEqual(self.store.list_device_policy(), {})

    def test_clear_stage_removes_only_staged_migration(self):
        self.store.stage_legacy_migration("mikrotik_kid_control", self.translated(), actor="tester")
        self.assertTrue(self.store.get_legacy_migration_stage("mikrotik_kid_control"))
        self.store.clear_legacy_migration_stage("mikrotik_kid_control")
        self.assertIsNone(self.store.get_legacy_migration_stage("mikrotik_kid_control"))


class KidControlMigrationSourceContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.main = (ROOT / "app/main.py").read_text()
        cls.router = (ROOT / "app/router.py").read_text()
        cls.template = (ROOT / "app/templates/kid_control_migration.html").read_text() if (ROOT / "app/templates/kid_control_migration.html").exists() else ""
        cls.readme = (ROOT / "README.md").read_text() + "\n" + (ROOT / "CHANGELOG.md").read_text()
        cls.release = (ROOT / "app/release_readiness.py").read_text()
        cls.env = (ROOT / ".env.example").read_text()

    def test_release_and_ui_contract_moves_forward_from_staging(self):
        self.assertIn('version="0.54.0"', self.main)
        self.assertIn("v0.54.0", self.readme)
        self.assertIn('("kid_control_migration", "MikroTik Kid Control staged migration", "0.52.0")', self.release)
        self.assertIn('("kid_control_authority", "MikroTik Kid Control controlled authority transfer", "0.53.0")', self.release)

    def test_staging_routes_remain_and_v053_adds_explicit_cutover_rollback(self):
        self.assertIn('@app.get("/migration/kid-control"', self.main)
        self.assertIn('@app.post("/local/migration/kid-control/stage")', self.main)
        self.assertIn('@app.post("/local/migration/kid-control/discard")', self.main)
        self.assertIn('@app.post("/local/migration/kid-control/cutover")', self.main)
        self.assertIn('@app.post("/local/migration/kid-control/rollback")', self.main)
        self.assertNotIn('/local/migration/kid-control/activate', self.main)

    def test_stage_requires_fresh_matching_preview_fingerprint(self):
        self.assertIn("preview_fingerprint", self.main)
        self.assertIn("Legacy Kid Control changed since preview", self.main)

    def test_ui_preserves_safe_staging_and_exposes_bounded_cutover(self):
        self.assertIn("Router writes", self.template)
        self.assertIn("CUTOVER ONLY", self.template)
        self.assertIn("DISABLED FLAG ONLY", self.template)
        self.assertIn("READY FOR CUTOVER", self.template)
        self.assertIn("Dynamic discovery rows are ignored", self.template)

    def test_kid_control_device_writes_remain_forbidden_and_profile_write_is_bounded(self):
        self.assertIn('"/ip/kid-control/device"', self.main)
        self.assertIn("READ_ONLY_LEGACY_ROUTER_PATHS", self.main)
        self.assertIn("BOUNDED_LEGACY_AUTHORITY_WRITE_PATHS", self.main)
        self.assertIn("FORBIDDEN_ROUTER_WRITE_PATHS", self.main)
        self.assertIn('frozenset({"disabled"})', self.main)

    def test_live_commissioning_token_permission_correction_is_baked_into_docs(self):
        self.assertIn("root:65532", self.readme)
        self.assertIn("0640", self.readme)
        self.assertIn("root:65532", self.env)
        self.assertIn("0640", self.env)
        self.assertNotIn("Keep this file mode 0600", self.env)


if __name__ == "__main__":
    unittest.main()
