import sys
import threading
import types
import unittest
from pathlib import Path

sys.modules.setdefault("routeros_api", types.SimpleNamespace())

from app.performance import PerformanceCollector
from app.router import RouterOSAdapter

ROOT = Path(__file__).resolve().parents[1]


class _Pool:
    def __init__(self):
        self.disconnects = 0

    def disconnect(self):
        self.disconnects += 1


class _Resource:
    def __init__(self, rows):
        self.rows = list(rows)
        self.calls = []

    def get(self, **filters):
        self.calls.append(dict(filters))
        if not filters:
            return [dict(row) for row in self.rows]
        result = []
        for row in self.rows:
            if all(str(row.get(key, "")) == str(value) for key, value in filters.items()):
                result.append(dict(row))
        return result


class _Api:
    def __init__(self):
        self.resources = {
            "/ip/firewall/address-list": _Resource([
                {"id": "*1", "list": "Restricted_Devices", "address": "192.168.2.10", "comment": "Tablet", "dynamic": "false"},
                {"id": "*2", "list": "Restricted_Devices", "address": "192.168.2.11", "comment": "Laptop", "dynamic": "false"},
                {"id": "*3", "list": "MC_Mode_Blocked", "address": "192.168.2.10"},
                {"id": "*4", "list": "MC_Mode_Slow", "address": "192.168.2.11"},
                {"id": "*5", "list": "MC_Block_Test", "address": "192.168.2.10"},
            ]),
            "/queue/simple": _Resource([
                {"id": "*6", "name": "MC-SLOW-192-168-2-11", "target": "192.168.2.11/32", "max-limit": "128k/256k", "queue": "default-small/default-small", "disabled": "false"},
                {"id": "*7", "name": "MC-BW-192-168-2-10", "target": "192.168.2.10/32", "max-limit": "2M/10M", "queue": "default-small/default-small", "disabled": "false", "comment": "MC - Policy Bandwidth"},
            ]),
            "/ip/firewall/filter": _Resource([
                {"id": "*8", "comment": "MC - Per Device Block", "disabled": "false"},
            ]),
        }

    def get_resource(self, name):
        return self.resources[name]


class _SnapshotRouter(RouterOSAdapter):
    def __init__(self):
        self._session_local = threading.local()
        self.api = _Api()
        self.pool = _Pool()
        self.opens = 0

    def _open_connection(self):
        self.opens += 1
        return self.pool, self.api


class ManagedDeviceSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.router = _SnapshotRouter()
        self.catalog = {
            "test": {
                "name": "Test Service",
                "source_list": "MC_Block_Test",
                "rules": [{"detector_list": "Detected_Test"}],
                "classification": "TLS/SNI",
                "coverage_note": "test",
            }
        }
        self.health = {"test": {"healthy": True, "error": ""}}

    def test_snapshot_collapses_device_state_reads_and_preserves_semantics(self):
        result = self.router.get_managed_device_observation_snapshot(
            self.catalog, self.health
        )
        states = result["states"]
        self.assertEqual("blocked", states["192.168.2.10"]["live_enforcement"]["mode"])
        self.assertEqual("slow", states["192.168.2.11"]["live_enforcement"]["mode"])
        self.assertEqual(["test"], states["192.168.2.10"]["live_services"]["blocked_services"])
        self.assertEqual([], states["192.168.2.11"]["live_services"]["blocked_services"])
        self.assertTrue(states["192.168.2.10"]["live_bandwidth"]["active"])
        self.assertFalse(states["192.168.2.11"]["live_bandwidth"]["active"])

        address_calls = self.router.api.resources["/ip/firewall/address-list"].calls
        self.assertEqual(4, len(address_calls))  # 3 fixed lists + 1 service list, not per device
        self.assertEqual(1, len(self.router.api.resources["/queue/simple"].calls))
        self.assertEqual(1, len(self.router.api.resources["/ip/firewall/filter"].calls))
        self.assertFalse(result["query_plan"]["cross_request_cache"])
        self.assertFalse(result["query_plan"]["write_validation_source"])

    def test_snapshot_is_fresh_on_each_call_not_cross_request_cached(self):
        self.router.get_managed_device_observation_snapshot(self.catalog, self.health)
        first = len(self.router.api.resources["/ip/firewall/address-list"].calls)
        self.router.get_managed_device_observation_snapshot(self.catalog, self.health)
        second = len(self.router.api.resources["/ip/firewall/address-list"].calls)
        self.assertEqual(first * 2, second)
        self.assertEqual(2, self.router.opens)

    def test_malformed_device_authority_keeps_inventory_visible_but_marks_state_error(self):
        self.router.api.resources["/ip/firewall/filter"].rows.clear()
        result = self.router.get_managed_device_observation_snapshot(self.catalog, self.health)
        self.assertEqual(2, len(result["devices"]))
        self.assertIn("Expected exactly one", result["states"]["192.168.2.10"]["error"])


class PerformanceAcceptanceTests(unittest.TestCase):
    @staticmethod
    def _finish(perf, *, method, route, duration_ms, router=False):
        sample, token = perf.begin_request(method, route)
        sample.started_mono -= duration_ms / 1000.0
        if router:
            perf.record_component("routeros.connect", 2.0)
            perf.record_component("routeros.example", 10.0)
        perf.finish_request(sample, token, route=route, status=200)

    def test_acceptance_passes_only_after_representative_sample_floor(self):
        perf = PerformanceCollector()
        for _ in range(5):
            self._finish(perf, method="GET", route="/?view=devices&section=managed", duration_ms=200)
            self._finish(perf, method="POST", route="/local/profile", duration_ms=100)
            self._finish(perf, method="POST", route="/devices/enforcement", duration_ms=500, router=True)
            self._finish(perf, method="GET", route="/devices/{address}", duration_ms=400, router=True)
        acceptance = perf.snapshot()["acceptance"]
        self.assertEqual("pass", acceptance["state"])
        self.assertTrue(all(row["state"] == "pass" for row in acceptance["targets"]))

    def test_acceptance_remains_pending_with_too_few_samples(self):
        perf = PerformanceCollector()
        self._finish(perf, method="GET", route="/?view=dashboard&section=overview", duration_ms=100)
        self.assertEqual("pending", perf.snapshot()["acceptance"]["state"])

    def test_router_connection_budget_fails_when_request_opens_multiple_transports(self):
        perf = PerformanceCollector()
        for _ in range(5):
            sample, token = perf.begin_request("GET", "/devices/1")
            sample.started_mono -= 0.2
            perf.record_component("routeros.connect", 2.0)
            perf.record_component("routeros.connect", 2.0)
            perf.record_component("routeros.example", 10.0)
            perf.finish_request(sample, token, route="/devices/{address}", status=200)
        report = perf.snapshot()["acceptance"]
        row = next(item for item in report["targets"] if item["key"] == "router_connections")
        self.assertEqual("fail", row["state"])
        self.assertEqual(2.0, row["p95_calls"])


class PerformanceClosureContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.main = (ROOT / "app/main.py").read_text()
        cls.router = (ROOT / "app/router.py").read_text()
        cls.performance = (ROOT / "app/performance.py").read_text()
        cls.template = (ROOT / "app/templates/performance.html").read_text()
        cls.script = (ROOT / "scripts/perf_acceptance.py").read_text()
        cls.readme = (ROOT / "README.md").read_text() + "\n" + (ROOT / "CHANGELOG.md").read_text()

    def test_root_uses_bounded_snapshot_only_for_dashboard_and_managed_devices(self):
        self.assertIn("get_managed_device_observation_snapshot", self.main)
        self.assertIn('active_view in {"dashboard", "devices"}', self.main)
        self.assertEqual(1, self.main.count("get_managed_device_observation_snapshot("))
        self.assertIn("Write and validation routes do", self.main)

    def test_snapshot_contract_explicitly_excludes_cross_request_cache_and_write_validation(self):
        self.assertIn("does *not* cache values across requests", self.router)
        self.assertIn('"write_validation_source": False', self.router)
        self.assertIn("Temporary-access state intentionally remains outside", self.router)

    def test_root_route_metrics_are_split_by_view_and_section(self):
        self.assertIn('route_label = f"/?view={view}&section={section}"', self.main)
        self.assertIn("ROOT_VIEW_SECTIONS", self.main)

    def test_acceptance_contract_and_cli_exist(self):
        self.assertIn("zen_performance_acceptance_v1", self.performance)
        self.assertIn("Responsiveness acceptance", self.template)
        self.assertIn("ZEN Control v0.39 performance acceptance", self.script)
        self.assertIn("python3 scripts/perf_acceptance.py zen-performance.json", self.readme)

    def test_performance_closure_never_uses_budget_to_skip_routeros_safety(self):
        joined = "\n".join([self.router, self.performance, self.readme])
        self.assertIn("post-write validation", joined)
        self.assertIn("no values are cached across HTTP requests", self.readme)
        self.assertNotIn("skip_post_write_validation", joined)


if __name__ == "__main__":
    unittest.main()
