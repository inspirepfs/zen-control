import json
import sys
import tempfile
import types
import unittest
from pathlib import Path

sys.modules.setdefault("routeros_api", types.SimpleNamespace())

from app.policy_engine import build_device_policy_plan
from app.policy_store import PolicyStore
from app.router import RouterError, RouterOSAdapter
from app.service_provisioning import build_custom_service_contract


class _Resource:
    def __init__(self, rows=None):
        self.rows = [dict(row) for row in (rows or [])]
        self.next_id = 100

    @staticmethod
    def _id(row):
        return row.get("id") or row.get(".id")

    def get(self, **filters):
        if not filters:
            return [dict(row) for row in self.rows]
        return [
            dict(row) for row in self.rows
            if all(str(row.get(key, "")) == str(value) for key, value in filters.items())
        ]

    def add(self, **values):
        values = dict(values)
        place_before = values.pop("place-before", None)
        values["id"] = f"*{self.next_id}"
        self.next_id += 1
        if place_before:
            for index, row in enumerate(self.rows):
                if self._id(row) == place_before:
                    self.rows.insert(index, values)
                    break
            else:
                self.rows.append(values)
        else:
            self.rows.append(values)
        return {"ret": values["id"]}

    def remove(self, **values):
        target = values.get("id") or values.get("numbers")
        self.rows = [row for row in self.rows if self._id(row) != target]


class _Api:
    def __init__(self, firewall=None, address_lists=None):
        self.resources = {
            "/ip/firewall/filter": _Resource(firewall),
            "/ip/firewall/address-list": _Resource(address_lists),
            "/ip/firewall/connection": _Resource([]),
        }

    def get_resource(self, path):
        return self.resources[path]


class _Pool:
    def disconnect(self):
        pass


class CustomServiceContractTests(unittest.TestCase):
    def service(self, **overrides):
        item = {
            "key": "minecraft",
            "name": "Minecraft",
            "builtin": 0,
            "category": "gaming",
            "dns_suffixes": ["minecraft.net", "mojang.com"],
            "tls_patterns": ["*minecraft*", "*mojang*"],
        }
        item.update(overrides)
        return item

    def adapter(self, api):
        adapter = RouterOSAdapter.__new__(RouterOSAdapter)
        adapter._connect = lambda: (_Pool(), api)
        # These legacy tests isolate the custom-service contract mechanics.
        # v0.41 adds separate hostile coverage for the adapter-level write gate.
        adapter._require_policy_write_gate = lambda: None
        return adapter

    def test_contract_is_deterministic_and_app_owned(self):
        contract = build_custom_service_contract(self.service())
        self.assertEqual(contract["source_list"], "MC_Block_Minecraft")
        self.assertEqual(contract["detector_lists"], ["MC_Detected_Minecraft"])
        self.assertEqual(
            [row["comment"] for row in contract["learners"]],
            ["MC|SVC|minecraft|LEARN|01", "MC|SVC|minecraft|LEARN|02"],
        )
        self.assertEqual(contract["rules"][0]["comment"], "MC|SVC|minecraft|BLOCK|01")

    def test_dns_only_service_remains_reporting_only(self):
        with self.assertRaisesRegex(ValueError, "requires at least one TLS/SNI pattern"):
            build_custom_service_contract(self.service(tls_patterns=[]))

    def test_preview_is_exact_and_detects_reserved_namespace_conflict(self):
        contract = build_custom_service_contract(self.service())
        api = _Api(
            firewall=[{"id": "*99", "chain": "restricted-web", "action": "return", "comment": "RW99 - Return"}],
            address_lists=[],
        )
        adapter = self.adapter(api)
        preview = adapter.inspect_custom_service_contract(contract)
        self.assertEqual(preview["status"], "absent")
        self.assertEqual(len(preview["actions"]), 3)
        self.assertEqual(preview["actions"][0]["tls_host"], "*minecraft*")
        self.assertEqual(preview["actions"][-1]["source_list"], "MC_Block_Minecraft")

        api.resources["/ip/firewall/address-list"].rows.append({
            "id": "*a1", "list": "MC_Block_Minecraft", "address": "192.168.88.50",
            "comment": "manual collision", "dynamic": "false",
        })
        conflict = adapter.inspect_custom_service_contract(contract)
        self.assertEqual(conflict["status"], "conflict")
        self.assertIn("namespace already contains entries", conflict["error"])

    def test_partial_managed_contract_fails_closed(self):
        contract = build_custom_service_contract(self.service())
        api = _Api(
            firewall=[
                {
                    "id": "*1", "chain": "restricted-web", "action": "add-dst-to-address-list",
                    "protocol": "tcp", "dst-port": "443", "address-list": "MC_Detected_Minecraft",
                    "tls-host": "*minecraft*", "disabled": "false",
                    "comment": "MC|SVC|minecraft|LEARN|01",
                },
                {"id": "*99", "chain": "restricted-web", "action": "return", "comment": "RW99 - Return"},
            ],
            address_lists=[],
        )
        adapter = self.adapter(api)
        preview = adapter.inspect_custom_service_contract(contract)
        self.assertEqual(preview["status"], "conflict")
        self.assertIn("Partial managed custom contract", preview["error"])
        with self.assertRaisesRegex(RouterError, "Refusing custom service provisioning"):
            adapter.provision_custom_service_contract(contract)
        with self.assertRaisesRegex(RouterError, "malformed/conflicting"):
            adapter.remove_custom_service_contract(contract)

    def test_install_is_idempotent_and_rules_are_before_return(self):
        contract = build_custom_service_contract(self.service())
        api = _Api(
            firewall=[{"id": "*99", "chain": "restricted-web", "action": "return", "comment": "RW99 - Return"}],
            address_lists=[],
        )
        adapter = self.adapter(api)
        result = adapter.provision_custom_service_contract(contract)
        self.assertTrue(result["healthy"])
        self.assertEqual(result["created"], 3)
        comments = [row.get("comment") for row in api.resources["/ip/firewall/filter"].rows]
        self.assertEqual(comments[-1], "RW99 - Return")
        self.assertEqual(comments[:-1], [
            "MC|SVC|minecraft|LEARN|01",
            "MC|SVC|minecraft|LEARN|02",
            "MC|SVC|minecraft|BLOCK|01",
        ])
        second = adapter.provision_custom_service_contract(contract)
        self.assertTrue(second["idempotent"])
        self.assertEqual(len(api.resources["/ip/firewall/filter"].rows), 4)

    def test_failed_install_rolls_back_rules_and_learned_detector_entries(self):
        contract = build_custom_service_contract(self.service())
        api = _Api(
            firewall=[{"id": "*99", "chain": "restricted-web", "action": "return", "comment": "RW99 - Return"}],
            address_lists=[],
        )
        firewall = api.resources["/ip/firewall/filter"]
        address_lists = api.resources["/ip/firewall/address-list"]
        original_add = firewall.add
        calls = {"count": 0}

        def fail_after_first_rule(**values):
            calls["count"] += 1
            if calls["count"] == 2:
                address_lists.rows.append({
                    "id": "*learned",
                    "list": "MC_Detected_Minecraft",
                    "address": "203.0.113.10",
                    "dynamic": "true",
                })
                raise RuntimeError("simulated RouterOS write failure")
            return original_add(**values)

        firewall.add = fail_after_first_rule
        adapter = self.adapter(api)
        with self.assertRaisesRegex(RouterError, "Unable to provision custom service contract"):
            adapter.provision_custom_service_contract(contract)

        self.assertEqual(
            [row.get("comment") for row in firewall.rows],
            ["RW99 - Return"],
        )
        self.assertEqual(address_lists.get(list="MC_Detected_Minecraft"), [])

    def test_remove_cleans_owned_rules_and_list_entries(self):
        contract = build_custom_service_contract(self.service())
        api = _Api(
            firewall=[{"id": "*99", "chain": "restricted-web", "action": "return", "comment": "RW99 - Return"}],
            address_lists=[],
        )
        adapter = self.adapter(api)
        adapter.provision_custom_service_contract(contract)
        api.resources["/ip/firewall/address-list"].rows.extend([
            {"id": "*a1", "list": "MC_Block_Minecraft", "address": "192.168.88.20", "comment": "MC - Block Minecraft"},
            {"id": "*a2", "list": "MC_Detected_Minecraft", "address": "1.2.3.4", "dynamic": "true"},
        ])
        removed = adapter.remove_custom_service_contract(contract)
        self.assertEqual(removed["status"], "absent")
        self.assertEqual(removed["removed_rules"], 3)
        self.assertEqual(removed["removed_entries"], 2)
        self.assertEqual(
            [row.get("comment") for row in api.resources["/ip/firewall/filter"].rows],
            ["RW99 - Return"],
        )


class CustomServiceStoreTests(unittest.TestCase):
    def test_approval_controls_runtime_catalog_and_protects_tls_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = PolicyStore(str(Path(tmp) / "policy.db"))
            saved = store.save_service(
                "minecraft", "Minecraft", "Game", "gaming",
                "minecraft.net mojang.com", "*minecraft* *mojang*", True,
            )
            self.assertFalse(saved["enforcement_approved"])
            self.assertNotIn("minecraft", store.routeros_service_catalog())

            approved = store.set_service_enforcement_approved("minecraft", True)
            self.assertTrue(approved["enforcement_approved"])
            self.assertTrue(approved["routeros_managed"])
            self.assertIn("minecraft", store.routeros_service_catalog())
            with self.assertRaisesRegex(ValueError, "Remove the approved RouterOS contract"):
                store.save_service(
                    "minecraft", "Minecraft", "Game", "gaming",
                    "minecraft.net", "*different*", True,
                )
            with self.assertRaisesRegex(ValueError, "Remove the custom RouterOS enforcement contract"):
                store.delete_service("minecraft")

            store.set_service_enforcement_approved("minecraft", False)
            store.delete_service("minecraft")
            self.assertIsNone(store.get_service("minecraft"))

    def test_backup_restore_preserves_custom_policy_intent_without_router_writes(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = PolicyStore(str(Path(tmp) / "first.db"))
            first.save_service(
                "minecraft", "Minecraft", "Game", "gaming",
                "minecraft.net", "*minecraft*", True,
            )
            first.set_service_enforcement_approved("minecraft", True)
            profile = first.create_profile(
                "Games", "normal", "normal", "", ["minecraft"],
            )
            payload = first.export_config()

            second = PolicyStore(str(Path(tmp) / "second.db"))
            second.import_config(json.loads(json.dumps(payload)))
            restored = second.get_service("minecraft")
            self.assertTrue(restored["enforcement_approved"])
            restored_profile = next(p for p in second.list_profiles() if p["name"] == "Games")
            self.assertIn("minecraft", restored_profile["blocked_services"])
            self.assertIn("minecraft", second.routeros_service_catalog())


class CustomServicePolicyPlanTests(unittest.TestCase):
    def test_custom_service_becomes_actionable_only_in_runtime_catalog(self):
        contract = build_custom_service_contract({
            "key": "minecraft", "name": "Minecraft", "builtin": 0,
            "category": "gaming", "dns_suffixes": ["minecraft.net"],
            "tls_patterns": ["*minecraft*"],
        })
        desired = {
            "mode": "normal", "mode_source": "profile", "blocked_services": ["minecraft"],
            "unsupported_policy_keys": [],
        }
        live_mode = {"mode": "normal"}
        live_services = {
            "blocked_services": [], "unavailable_services": [],
            "services": {"minecraft": {"available": True, "blocked": False}},
        }
        live_bandwidth = {"active": False, "valid": True, "max_limit": None}

        staged = build_device_policy_plan(
            "192.168.88.20", desired, live_mode,
            live_services=live_services, live_bandwidth=live_bandwidth,
        )
        self.assertIn("minecraft", staged["unsupported_blocked_services"])
        self.assertFalse(staged["service_drift"])

        live = build_device_policy_plan(
            "192.168.88.20", desired, live_mode,
            live_services=live_services, live_bandwidth=live_bandwidth,
            service_catalog={"minecraft": contract},
        )
        self.assertEqual(live["desired_supported_blocked_services"], ["minecraft"])
        self.assertTrue(live["service_drift"])
        self.assertEqual(live["service_states"][0]["source_list"], "MC_Block_Minecraft")


if __name__ == "__main__":
    unittest.main()
