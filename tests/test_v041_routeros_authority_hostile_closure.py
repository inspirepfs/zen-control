import sys
import threading
import types
import unittest
from unittest.mock import patch

sys.modules.setdefault("routeros_api", types.SimpleNamespace())

from app.router import RouterError, RouterOSAdapter


class _Pool:
    def __init__(self):
        self.disconnects = 0
    def disconnect(self):
        self.disconnects += 1


class _ReadOnlyResource:
    def __init__(self, rows):
        self.rows = [dict(row) for row in rows]
        self.mutations = []
    def get(self, **kwargs):
        if not kwargs:
            return [dict(row) for row in self.rows]
        return [dict(row) for row in self.rows if all(str(row.get(k, "")) == str(v) for k, v in kwargs.items())]
    def add(self, **kwargs):
        self.mutations.append(("add", kwargs))
        raise AssertionError("security posture must be read-only")
    def set(self, **kwargs):
        self.mutations.append(("set", kwargs))
        raise AssertionError("security posture must be read-only")
    def remove(self, **kwargs):
        self.mutations.append(("remove", kwargs))
        raise AssertionError("security posture must be read-only")
    def call(self, *args, **kwargs):
        self.mutations.append(("call", args, kwargs))
        raise AssertionError("security posture must be read-only")


class _Api:
    def __init__(self, rules, queues=None, address_lists=None):
        self.resources = {
            "/ip/firewall/filter": _ReadOnlyResource(rules),
            "/ip/firewall/address-list": _ReadOnlyResource(address_lists or []),
            "/queue/simple": _ReadOnlyResource(queues or [{"name": "Restricted Slow Internet", "disabled": "true", "max-limit": "128k/256k"}]),
            "/system/scheduler": _ReadOnlyResource([]),
            "/system/script": _ReadOnlyResource([]),
        }
    def get_resource(self, path):
        return self.resources[path]


def _base_rules():
    return [
        {"id": "*1", "comment": "MASTER - Block Restricted Internet", "chain": "forward", "action": "drop", "src-address-list": "Restricted_Devices", "out-interface-list": "WAN", "disabled": "true"},
        {"id": "*2", "comment": "MC - Per Device Block", "chain": "forward", "action": "drop", "src-address-list": "MC_Mode_Blocked", "out-interface-list": "WAN", "disabled": "false"},
        {"id": "*3", "comment": "Restricted Devices - Web Policy", "chain": "forward", "action": "jump", "jump-target": "restricted-web", "src-address-list": "Restricted_Devices", "disabled": "false"},
        {"id": "*4", "comment": "defconf: accept established,related,untracked", "chain": "forward", "action": "accept", "connection-state": "established,related,untracked", "disabled": "false"},
        {"id": "*5", "comment": "RW01 - Block QUIC HTTP3", "chain": "restricted-web", "action": "drop", "protocol": "udp", "dst-port": "443", "disabled": "false"},
        {"id": "*6", "comment": "MC - Block Restricted DoT", "chain": "restricted-web", "action": "drop", "protocol": "tcp", "dst-port": "853", "src-address-list": "Restricted_Devices", "disabled": "false"},
        {"id": "*7", "comment": "MC - Block Restricted DoQ", "chain": "restricted-web", "action": "drop", "protocol": "udp", "dst-port": "853", "src-address-list": "Restricted_Devices", "disabled": "false"},
        {"id": "*8", "comment": "RW99 - Return", "chain": "restricted-web", "action": "return", "disabled": "false"},
    ]


class _PostureAdapter(RouterOSAdapter):
    def __init__(self, rules):
        self._api = _Api(rules)
        self._pool = _Pool()
        self._session_local = threading.local()
    def _connect(self):
        return self._pool, self._api


class AuthorityHostilePostureTests(unittest.TestCase):
    def posture(self, mutate=None):
        rules = _base_rules()
        if mutate:
            mutate(rules)
        adapter = _PostureAdapter(rules)
        with patch("app.router.DOH_ROUTER_RULES", []), patch("app.router.SERVICE_ENFORCEMENT", {}):
            return adapter.get_security_posture(), adapter

    def test_hostile_critical_rule_matrix_closes_write_gate(self):
        cases = {
            "missing device authority": lambda r: r.__setitem__(slice(None), [x for x in r if x.get("comment") != "MC - Per Device Block"]),
            "duplicate device authority": lambda r: r.append(dict(next(x for x in r if x.get("comment") == "MC - Per Device Block"), id="*22")),
            "disabled device authority": lambda r: next(x for x in r if x.get("comment") == "MC - Per Device Block").update(disabled="true"),
            "web jump after established": lambda r: r.append(r.pop(r.index(next(x for x in r if x.get("comment") == "Restricted Devices - Web Policy")))),
            "duplicate RW99": lambda r: r.append({"id": "*88", "comment": "RW99 - Return", "chain": "restricted-web", "action": "return", "disabled": "false"}),
            "managed custom rule after RW99": lambda r: r.append({"id": "*90", "comment": "MC|SVC|minecraft|BLOCK|01", "chain": "restricted-web", "action": "drop", "disabled": "false"}),
        }
        for label, mutate in cases.items():
            with self.subTest(label=label):
                posture, _ = self.posture(mutate)
                self.assertFalse(posture["enforcement_ready"], label)
                self.assertGreater(posture["critical_count"], 0, label)

    def test_security_posture_is_strictly_read_only(self):
        posture, adapter = self.posture()
        self.assertTrue(posture["enforcement_ready"])
        mutations = []
        for resource in adapter._api.resources.values():
            mutations.extend(resource.mutations)
        self.assertEqual(mutations, [])


class AdapterWriteGateTests(unittest.TestCase):
    def adapter(self):
        adapter = RouterOSAdapter.__new__(RouterOSAdapter)
        adapter._session_local = threading.local()
        adapter.timezone = "Europe/London"
        adapter.device_slow_limit = "128k/256k"
        return adapter

    def test_gate_proof_is_reused_only_inside_one_coherent_session(self):
        adapter = self.adapter()
        pool = _Pool()
        api = object()
        adapter._open_connection = lambda: (pool, api)
        calls = []
        adapter.get_security_posture = lambda: calls.append("posture") or {"enforcement_ready": True, "checks": []}
        with adapter.coherent_session():
            adapter._require_policy_write_gate()
            adapter._require_policy_write_gate()
            self.assertEqual(calls, ["posture"])
        self.assertEqual(pool.disconnects, 1)
        adapter.assert_policy_enforcement_ready()
        self.assertEqual(calls, ["posture", "posture"])

    def test_failed_gate_cannot_be_cached_as_success(self):
        adapter = self.adapter()
        adapter._session_local.state = (object(), object())
        adapter._session_local.authority_proven = True
        adapter.get_security_posture = lambda: {"enforcement_ready": False, "checks": [{"severity": "critical", "status": "fail", "name": "Broken authority"}]}
        with self.assertRaisesRegex(RouterError, "Broken authority"):
            adapter.assert_policy_enforcement_ready()
        self.assertFalse(adapter._session_local.authority_proven)

    def test_major_policy_writers_have_adapter_level_gate(self):
        adapter = self.adapter()
        def blocked():
            raise RouterError("HOSTILE WRITE GATE")
        adapter._require_policy_write_gate = blocked
        calls = [
            lambda: adapter.set_mode("normal"),
            lambda: adapter.set_device_mode("192.0.2.10", "normal"),
            lambda: adapter.set_device_services("192.0.2.10", [], service_catalog={}),
            lambda: adapter.set_device_bandwidth("192.0.2.10", "normal", "", ""),
            lambda: adapter.set_device_temporary_normal("192.0.2.10", 15),
            lambda: adapter.set_temporary_normal(15, "normal"),
            lambda: adapter.add_managed_schedule("test", "normal", "12:00", ["mon"]),
            lambda: adapter.add_restricted_device("192.0.2.10", "test"),
            lambda: adapter.remove_restricted_device("192.0.2.10"),
            lambda: adapter.provision_custom_service_contract({"key": "x"}),
            lambda: adapter.remove_custom_service_contract({"key": "x"}),
        ]
        for fn in calls:
            with self.subTest(fn=fn):
                with self.assertRaisesRegex(RouterError, "HOSTILE WRITE GATE"):
                    fn()

    def test_invalid_local_input_is_rejected_before_router_gate(self):
        adapter = self.adapter()
        adapter._require_policy_write_gate = lambda: (_ for _ in ()).throw(AssertionError("gate should not run"))
        with self.assertRaisesRegex(RouterError, "Invalid mode"):
            adapter.set_mode("banana")
        with self.assertRaisesRegex(RouterError, "Invalid device mode"):
            adapter.set_device_mode("192.0.2.10", "banana")
        with self.assertRaisesRegex(RouterError, "Unsupported live service"):
            adapter.set_device_services("192.0.2.10", ["missing"], service_catalog={})
        with self.assertRaisesRegex(RouterError, "Temporary access supports"):
            adapter.set_temporary_normal(5, "normal")


class _MutableAddressList:
    def __init__(self):
        self.rows = [
            {"id": "*old", "list": "SRC_OLD", "address": "192.0.2.10", "comment": "old"},
        ]
        self.events = []
    def get(self, **kwargs):
        return [dict(x) for x in self.rows if all(str(x.get(k, "")) == str(v) for k, v in kwargs.items())]
    def add(self, **kwargs):
        self.events.append(("add", kwargs.get("list")))
        self.rows.append({"id": "*new", **kwargs})
    def remove(self, **kwargs):
        row = next(x for x in self.rows if x.get("id") == kwargs.get("id"))
        self.events.append(("remove", row.get("list")))
        self.rows.remove(row)


class _ServiceApi:
    def __init__(self, address_list):
        self.address_list = address_list
    def get_resource(self, path):
        if path == "/ip/firewall/address-list":
            return self.address_list
        raise AssertionError(path)


class ServiceTransitionSafetyTests(unittest.TestCase):
    def test_new_service_blocks_are_established_before_old_blocks_are_released(self):
        address_list = _MutableAddressList()
        api = _ServiceApi(address_list)
        adapter = RouterOSAdapter.__new__(RouterOSAdapter)
        adapter._require_policy_write_gate = lambda: None
        adapter._connect = lambda: (_Pool(), api)
        adapter._validate_restricted_device = lambda api, address: None
        adapter._validate_service_primitive = lambda api, key, catalog: None
        adapter._terminate_service_connections = lambda *args, **kwargs: 0
        adapter.get_device_service_enforcement = lambda address, service_catalog=None: {
            "blocked_services": ["new"],
            "services": {"new": {"available": True}, "old": {"available": True}},
        }
        catalog = {
            "new": {"name": "New", "source_list": "SRC_NEW", "rules": []},
            "old": {"name": "Old", "source_list": "SRC_OLD", "rules": []},
        }
        adapter.set_device_services("192.0.2.10", ["new"], service_catalog=catalog)
        self.assertEqual(address_list.events[:2], [("add", "SRC_NEW"), ("remove", "SRC_OLD")])


class WriteFailureBoundaryTests(unittest.TestCase):
    def test_global_mode_rpc_failure_is_reported_and_not_claimed_converged(self):
        class Scripts:
            def get(self, **kwargs):
                return [{"id": "*1", "name": "restricted-internet-on"}]
            def call(self, *args, **kwargs):
                raise RuntimeError("router write lost")
        class Api:
            def get_resource(self, path):
                self.path = path
                return Scripts()
        adapter = RouterOSAdapter.__new__(RouterOSAdapter)
        adapter._require_policy_write_gate = lambda: None
        adapter._connect = lambda: (_Pool(), Api())
        with self.assertRaisesRegex(RouterError, "router write lost"):
            adapter.set_mode("normal")

    def test_global_mode_contradictory_post_write_read_fails_loudly(self):
        class Scripts:
            def get(self, **kwargs):
                return [{"id": "*1", "name": "restricted-internet-on"}]
            def call(self, *args, **kwargs):
                return None
        class Api:
            def get_resource(self, path):
                return Scripts()
        adapter = RouterOSAdapter.__new__(RouterOSAdapter)
        adapter._require_policy_write_gate = lambda: None
        adapter._connect = lambda: (_Pool(), Api())
        adapter.get_status = lambda: {"mode": "blocked"}
        with self.assertRaisesRegex(RouterError, "Requested mode 'normal' but router reports 'blocked'"):
            adapter.set_mode("normal")

    def test_failed_new_service_block_does_not_release_existing_block(self):
        class FailingAddressList(_MutableAddressList):
            def add(self, **kwargs):
                self.events.append(("add", kwargs.get("list")))
                raise RuntimeError("write interrupted")
        address_list = FailingAddressList()
        api = _ServiceApi(address_list)
        adapter = RouterOSAdapter.__new__(RouterOSAdapter)
        adapter._require_policy_write_gate = lambda: None
        adapter._connect = lambda: (_Pool(), api)
        adapter._validate_restricted_device = lambda api, address: None
        adapter._validate_service_primitive = lambda api, key, catalog: None
        adapter._terminate_service_connections = lambda *args, **kwargs: 0
        catalog = {
            "new": {"name": "New", "source_list": "SRC_NEW", "rules": []},
            "old": {"name": "Old", "source_list": "SRC_OLD", "rules": []},
        }
        with self.assertRaisesRegex(RouterError, "write interrupted"):
            adapter.set_device_services("192.0.2.10", ["new"], service_catalog=catalog)
        self.assertEqual(address_list.events, [("add", "SRC_NEW")])
        self.assertTrue(any(row.get("list") == "SRC_OLD" for row in address_list.rows))


if __name__ == "__main__":
    unittest.main()
