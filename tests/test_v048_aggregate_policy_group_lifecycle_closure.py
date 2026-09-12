from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from app.policy_engine import build_device_policy_plan
from app.policy_explain import build_policy_explanation
from app.policy_groups import POLICY_GROUPS
from app.policy_parity import policy_parity_contract
from app.policy_simulation import build_policy_simulation
from app.policy_store import PolicyStore
from app.quota import bytes_for_mb


class AggregatePolicyGroupLifecycleClosureTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = PolicyStore(str(Path(self.tmp.name) / "policy.db"))
        self.ip = "192.168.2.55"

    def tearDown(self):
        self.tmp.cleanup()

    def _new_store(self, name="other.db"):
        return PolicyStore(str(Path(self.tmp.name) / name))

    def _profile(self, *, blocked=(), quotas=None, name="Child"):
        profile = self.store.create_profile(
            name, "normal", "normal", "", blocked, 0, "blocked", quotas or {}
        )
        self.store.update_device(self.ip, alias="Tablet", profile_id=profile["id"])
        return profile

    @staticmethod
    def _usage(**mb):
        return {
            "available": True,
            "day": "2026-09-10",
            "timezone": "Europe/London",
            "total_bytes": sum(bytes_for_mb(value) for value in mb.values()),
            "service_bytes": {key: bytes_for_mb(value) for key, value in mb.items()},
        }

    def _full_reference_graph(self):
        group = self.store.create_policy_group(
            "Streaming", "Video", ["youtube", "netflix"]
        )
        profile = self._profile(blocked=[group["key"]], quotas={group["key"]: 100})
        template_id = self.store.save_template_from_profile("Child template", profile["id"])
        collection_id = self.store.save_service_group(
            "Media collection", "", [group["key"]]
        )
        schedule_id = self.store.create_schedule_plan(
            "Streaming bedtime", "device", self.ip, "service",
            f"{group['key']}:block", "18:00", ["thu"],
        )
        return group, profile, template_id, collection_id, schedule_id

    def test_dependency_inventory_covers_every_supported_reference_surface(self):
        group, _, _, _, _ = self._full_reference_graph()
        usage = self.store.policy_group_usage(group["key"])
        self.assertEqual(5, usage["total"])
        self.assertEqual(1, len(usage["profiles"]))
        self.assertEqual(1, len(usage["quotas"]))
        self.assertEqual(1, len(usage["templates"]))
        self.assertEqual(1, len(usage["schedules"]))
        self.assertEqual(1, len(usage["collections"]))
        with self.assertRaisesRegex(ValueError, "still referenced by 5 policy reference"):
            self.store.delete_policy_group(group["key"])

    def test_dependency_removal_allows_custom_group_delete(self):
        group, profile, template_id, collection_id, schedule_id = self._full_reference_graph()
        self.store.delete_schedule_plan(schedule_id)
        self.store.delete_service_group(collection_id)
        self.store.delete_template(template_id)
        self.store.update_profile(
            profile["id"], profile["name"], profile["desired_mode"],
            profile["bandwidth_preset"], profile.get("notes", ""), [], 0,
            "blocked", {},
        )
        self.assertFalse(self.store.policy_group_usage(group["key"])["in_use"])
        self.store.delete_policy_group(group["key"])
        self.assertNotIn(group["key"], self.store.policy_group_catalog())

    def test_rename_preserves_stable_key_across_all_references(self):
        group, _, _, _, _ = self._full_reference_graph()
        before = self.store.policy_group_usage(group["key"])
        updated = self.store.update_policy_group(
            group["key"], "Video streaming", "Renamed", ["youtube", "netflix"]
        )
        after = self.store.policy_group_usage(group["key"])
        self.assertEqual("streaming", updated["key"])
        self.assertEqual("Video streaming", updated["name"])
        self.assertEqual(before["total"], after["total"])
        self.assertEqual(5, after["total"])

    def test_membership_change_updates_profile_schedule_and_quota_semantics(self):
        group = self.store.create_policy_group("Streaming", "", ["youtube", "netflix"])
        self._profile(blocked=[group["key"]], quotas={group["key"]: 100})
        self.store.save_quota_settings("1", "80")
        self.store.create_schedule_plan(
            "Streaming bedtime", "device", self.ip, "service",
            f"{group['key']}:block", "18:00", ["thu"],
        )
        self.store.update_policy_group(
            group["key"], "Streaming", "", ["youtube", "bbc_iplayer"]
        )
        policy = self.store.compute_effective_policy(
            self.ip,
            at="2026-09-10T19:00:00+01:00",
            quota_usage=self._usage(youtube=60, bbc_iplayer=40),
        )
        self.assertEqual({"youtube", "bbc_iplayer"}, set(policy["blocked_services"]))
        quota = next(row for row in policy["quota_state"]["services"] if row["key"] == group["key"])
        self.assertTrue(quota["exhausted"])
        self.assertEqual(group["key"], policy["scheduled_service_overrides"][0]["service"])

    def test_reusable_collection_keeps_group_intent_and_uses_current_membership(self):
        group = self.store.create_policy_group("Streaming", "", ["youtube"])
        profile = self._profile()
        collection = self.store.save_service_group("Media collection", "", [group["key"]])
        self.store.apply_service_group(collection, profile["id"], "block")
        self.assertEqual([group["key"]], self.store.get_profile(profile["id"])["blocked_services"])
        self.store.update_policy_group(group["key"], "Streaming", "", ["netflix"])
        policy = self.store.compute_effective_policy(self.ip)
        self.assertEqual(["netflix"], policy["blocked_services"])

    def test_policy_template_keeps_group_key_and_follows_current_membership(self):
        group = self.store.create_policy_group("Streaming", "", ["youtube"])
        profile = self._profile(blocked=[group["key"]])
        template_id = self.store.save_template_from_profile("Streaming profile", profile["id"])
        self.store.update_profile(profile["id"], "Child", "normal", "normal", "", [])
        self.store.update_policy_group(group["key"], "Streaming", "", ["netflix"])
        self.store.apply_template(template_id, profile["id"])
        self.assertEqual([group["key"]], self.store.get_profile(profile["id"])["blocked_services"])
        self.assertEqual(["netflix"], self.store.compute_effective_policy(self.ip)["blocked_services"])

    def test_explainability_and_simulation_use_live_renamed_group_catalogue(self):
        group = self.store.create_policy_group("Streaming", "", ["youtube"])
        profile = self._profile(blocked=[group["key"]])
        self.store.update_policy_group(group["key"], "Video streaming", "", ["youtube"])
        desired = self.store.compute_effective_policy(self.ip)
        services = self.store.list_services()
        explanation = build_policy_explanation(
            address=self.ip,
            device_name="Tablet",
            device_config=self.store.list_device_policy()[self.ip],
            profile=self.store.get_profile(profile["id"]),
            desired_policy=desired,
            live_plan=None,
            temporary_access={"active": False},
            service_definitions=services,
            policy_groups=self.store.policy_group_catalog(),
        )
        row = next(item for item in explanation["services"] if item["key"] == "youtube")
        self.assertEqual("policy_group", row["source_kind"])
        self.assertIn("Video streaming", row["source"])
        simulation = build_policy_simulation(
            address=self.ip,
            device_name="Tablet",
            baseline=desired,
            scenario=desired,
            scenario_label="same",
            simulation_at=desired["policy_at"],
        )
        self.assertEqual(explanation["desired_contract"], simulation["scenario_contract"])
        self.assertEqual(policy_parity_contract(desired), simulation["baseline_contract"])

    def test_router_policy_plan_contains_concrete_members_never_group_key(self):
        group = self.store.create_policy_group("Streaming", "", ["youtube", "netflix"])
        self._profile(blocked=[group["key"]])
        desired = self.store.compute_effective_policy(self.ip)
        service_catalog = self.store.routeros_service_catalog()
        live_services = {
            "blocked_services": [],
            "unavailable_services": [],
            "services": {
                key: {"available": True, "blocked": False}
                for key in service_catalog
            },
        }
        plan = build_device_policy_plan(
            self.ip,
            desired,
            {"mode": "normal"},
            live_services=live_services,
            service_catalog=service_catalog,
        )
        self.assertNotIn(group["key"], plan["desired_supported_blocked_services"])
        self.assertEqual({"youtube", "netflix"}, set(plan["desired_supported_blocked_services"]))

    def test_reporting_only_member_stays_requested_without_becoming_router_authority(self):
        self.store.save_service(
            "minecraft", "Minecraft", dns_suffixes=["minecraft.net"], classifier_enabled=True
        )
        group = self.store.create_policy_group("Games 2", "", ["minecraft"])
        self._profile(blocked=[group["key"]])
        desired = self.store.compute_effective_policy(self.ip)
        self.assertEqual([], desired["blocked_services"])
        self.assertEqual(["minecraft"], desired["unsupported_policy_group_members"])
        self.assertEqual([group["key"]], desired["blocked_policy_groups"])

    def test_backup_restore_preserves_full_reference_graph(self):
        group, _, _, _, _ = self._full_reference_graph()
        payload = json.loads(json.dumps(self.store.export_config()))
        restored = self._new_store("restored.db")
        restored.import_config(payload)
        self.assertEqual(5, restored.policy_group_usage(group["key"])["total"])
        self.assertEqual(("netflix", "youtube"), restored.policy_group_catalog()[group["key"]]["members"])
        profile = next(item for item in restored.list_profiles() if item["name"] == "Child")
        self.assertEqual([group["key"]], profile["blocked_services"])
        self.assertEqual({group["key"]: 100}, profile["service_quotas"])

    def test_backup_restore_preserves_modified_builtin_group_identity(self):
        original = self.store.policy_group_catalog()["gaming"]
        self.store.update_policy_group("gaming", "Games", "Custom household gaming", ["roblox", "steam"])
        payload = json.loads(json.dumps(self.store.export_config()))
        restored = self._new_store("builtin-restored.db")
        restored.import_config(payload)
        group = restored.policy_group_catalog()["gaming"]
        self.assertEqual("gaming", group["key"])
        self.assertTrue(group["builtin"])
        self.assertEqual("Games", group["name"])
        self.assertEqual(("roblox", "steam"), group["members"])
        self.assertNotEqual(original["name"], group["name"])

    def test_legacy_backup_without_group_section_resets_builtins_to_product_defaults(self):
        self.store.update_policy_group("gaming", "Games", "", ["youtube"])
        payload = self.store.export_config()
        payload.pop("aggregate_policy_groups", None)
        restored = self._new_store("legacy.db")
        restored.update_policy_group("gaming", "Locally changed", "", ["netflix"])
        restored.import_config(payload)
        group = restored.policy_group_catalog()["gaming"]
        self.assertEqual(POLICY_GROUPS["gaming"]["name"], group["name"])
        self.assertEqual(tuple(sorted(POLICY_GROUPS["gaming"]["members"])), group["members"])

    def test_missing_referenced_group_in_backup_fails_before_mutating_target(self):
        group = self.store.create_policy_group("Streaming", "", ["youtube"])
        self._profile(blocked=[group["key"]])
        payload = self.store.export_config()
        payload["aggregate_policy_groups"] = [
            item for item in payload["aggregate_policy_groups"] if item["key"] != group["key"]
        ]
        target = self._new_store("missing-group.db")
        target.create_profile("Keep me", "blocked", "normal")
        before = target.config_digest()
        with self.assertRaisesRegex(ValueError, "unknown service or aggregate policy group"):
            target.import_config(payload)
        self.assertEqual(before, target.config_digest())
        self.assertEqual(["Keep me"], [item["name"] for item in target.list_profiles()])

    def test_invalid_group_member_in_backup_fails_before_mutating_target(self):
        group = self.store.create_policy_group("Streaming", "", ["youtube"])
        payload = self.store.export_config()
        row = next(item for item in payload["aggregate_policy_groups"] if item["key"] == group["key"])
        row["members"] = ["missing_service"]
        target = self._new_store("bad-member.db")
        target.create_profile("Keep me", "blocked", "normal")
        before = target.config_digest()
        with self.assertRaisesRegex(ValueError, "unknown concrete service"):
            target.import_config(payload)
        self.assertEqual(before, target.config_digest())

    def test_overlong_group_key_is_rejected_not_truncated(self):
        group = self.store.create_policy_group("Streaming", "", ["youtube"])
        payload = self.store.export_config()
        row = next(item for item in payload["aggregate_policy_groups"] if item["key"] == group["key"])
        row["key"] = "a" * 41
        target = self._new_store("long-key.db")
        target.create_profile("Keep me", "blocked", "normal")
        before = target.config_digest()
        with self.assertRaisesRegex(ValueError, "stable key"):
            target.import_config(payload)
        self.assertEqual(before, target.config_digest())
        self.assertEqual([], [item for item in target.list_policy_groups() if not item["builtin"]])

    def test_incomplete_builtin_group_catalogue_is_rejected_not_merged(self):
        payload = self.store.export_config()
        payload["aggregate_policy_groups"] = [
            item for item in payload["aggregate_policy_groups"] if item["key"] != "social_media"
        ]
        target = self._new_store("missing-builtin.db")
        target.update_policy_group("social_media", "Local social", "", ["youtube"])
        before = target.config_digest()
        with self.assertRaisesRegex(ValueError, "built-in aggregate policy groups"):
            target.import_config(payload)
        self.assertEqual(before, target.config_digest())
        self.assertEqual("Local social", target.policy_group_catalog()["social_media"]["name"])

    def test_duplicate_group_names_are_rejected_case_insensitively_before_mutation(self):
        group = self.store.create_policy_group("Streaming", "", ["youtube"])
        payload = self.store.export_config()
        row = next(item for item in payload["aggregate_policy_groups"] if item["key"] == group["key"])
        row["name"] = "gaming"
        target = self._new_store("duplicate-name.db")
        target.create_profile("Keep me", "blocked", "normal")
        before = target.config_digest()
        with self.assertRaisesRegex(ValueError, "duplicate aggregate policy-group name"):
            target.import_config(payload)
        self.assertEqual(before, target.config_digest())

    def test_nested_imported_groups_are_rejected_before_mutation(self):
        first = self.store.create_policy_group("Streaming", "", ["youtube"])
        second = self.store.create_policy_group("Media", "", ["netflix"])
        payload = self.store.export_config()
        row = next(item for item in payload["aggregate_policy_groups"] if item["key"] == second["key"])
        row["members"] = [first["key"]]
        target = self._new_store("nested.db")
        target.create_profile("Keep me", "blocked", "normal")
        before = target.config_digest()
        with self.assertRaisesRegex(ValueError, "cannot contain other aggregate groups"):
            target.import_config(payload)
        self.assertEqual(before, target.config_digest())

    def test_service_collection_missing_group_reference_is_not_silently_dropped_on_restore(self):
        group = self.store.create_policy_group("Streaming", "", ["youtube"])
        self.store.save_service_group("Media collection", "", [group["key"]])
        payload = self.store.export_config()
        payload["aggregate_policy_groups"] = [
            item for item in payload["aggregate_policy_groups"] if item["key"] != group["key"]
        ]
        target = self._new_store("collection-missing.db")
        before = target.config_digest()
        with self.assertRaisesRegex(ValueError, "unknown service or aggregate policy group"):
            target.import_config(payload)
        self.assertEqual(before, target.config_digest())

    def test_policy_template_missing_group_reference_is_not_silently_dropped_on_restore(self):
        group = self.store.create_policy_group("Streaming", "", ["youtube"])
        profile = self._profile(blocked=[group["key"]])
        self.store.save_template_from_profile("Template", profile["id"])
        payload = self.store.export_config()
        payload["profiles"] = []
        payload["device_policy"] = []
        payload["aggregate_policy_groups"] = [
            item for item in payload["aggregate_policy_groups"] if item["key"] != group["key"]
        ]
        target = self._new_store("template-missing.db")
        before = target.config_digest()
        with self.assertRaisesRegex(ValueError, "unknown service or aggregate policy group"):
            target.import_config(payload)
        self.assertEqual(before, target.config_digest())


    def test_missing_group_service_schedule_reference_fails_before_mutating_target(self):
        group = self.store.create_policy_group("Streaming", "", ["youtube"])
        self.store.create_schedule_plan(
            "Streaming bedtime", "all", "", "service",
            f"{group['key']}:block", "18:00", ["thu"],
        )
        payload = self.store.export_config()
        payload["aggregate_policy_groups"] = [
            item for item in payload["aggregate_policy_groups"] if item["key"] != group["key"]
        ]
        target = self._new_store("schedule-missing.db")
        target.create_profile("Keep me", "blocked", "normal")
        before = target.config_digest()
        with self.assertRaisesRegex(ValueError, "unknown service or aggregate policy group"):
            target.import_config(payload)
        self.assertEqual(before, target.config_digest())

    def test_invalid_approved_custom_member_service_fails_before_mutating_target(self):
        self.store.save_service(
            "minecraft", "Minecraft", dns_suffixes=["minecraft.net"],
            tls_patterns=["*.minecraft.net"], classifier_enabled=True,
        )
        self.store.set_service_enforcement_approved("minecraft", True)
        self.store.create_policy_group("Games 2", "", ["minecraft"])
        payload = self.store.export_config()
        service = next(item for item in payload["services"] if item["key"] == "minecraft")
        service["tls_patterns"] = []
        target = self._new_store("bad-custom-service.db")
        target.create_profile("Keep me", "blocked", "normal")
        before = target.config_digest()
        with self.assertRaisesRegex(ValueError, "RouterOS contract is invalid"):
            target.import_config(payload)
        self.assertEqual(before, target.config_digest())



class AggregatePolicyGroupLifecycleSourceGuards(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parents[1]
        cls.store = (root / "app/policy_store.py").read_text()
        cls.router = (root / "app/router.py").read_text()
        cls.readme = (root / "README.md").read_text() + "\n" + (root / "CHANGELOG.md").read_text()

    def test_restore_preflight_runs_before_destructive_table_replacement(self):
        block = self.store.split("def import_config(self, payload):", 1)[1]
        self.assertLess(
            block.index("_preflight_import_policy_groups"),
            block.index('db.execute(f"DELETE FROM {table}")'),
        )

    def test_import_never_truncates_aggregate_stable_key(self):
        import_block = self.store.split("def import_config(self, payload):", 1)[1]
        self.assertNotIn("key[:40]", import_block)

    def test_router_write_boundary_rejects_unknown_group_level_authority(self):
        block = self.router.split("def set_device_services", 1)[1].split("def _terminate_service_connections", 1)[0]
        self.assertIn("unsupported = desired - supported_keys", block)
        self.assertIn("Unsupported live service key(s)", block)

    def test_release_notes_state_aggregate_groups_never_create_routeros_authority(self):
        self.assertIn("v0.54.4", self.readme)
        self.assertIn("never become RouterOS authority", self.readme)


if __name__ == "__main__":
    unittest.main()
