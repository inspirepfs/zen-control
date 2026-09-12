import sys
import tempfile
import types
import unittest
from pathlib import Path

sys.modules.setdefault("routeros_api", types.SimpleNamespace())

from app.performance import PerformanceCollector
from app.policy_store import PolicyStore
from app.reconciler import AutoReconciler

ROOT = Path(__file__).resolve().parents[1]


class _InventoryRouter:
    def __init__(self):
        self.inventory_calls = 0

    def mutation_status(self):
        return {"schema": "zen_router_mutation_lane_v1", "busy": False, "available": True}

    def get_managed_state_inventory(self):
        self.inventory_calls += 1
        return {
            "router": "ZEN",
            "counts": {
                "restricted_devices": 1,
                "managed_address_entries": 2,
                "managed_address_lists": 1,
                "managed_queues": 1,
                "managed_schedulers": 0,
                "managed_scripts": 1,
                "required_firewall_rules_seen": 4,
                "required_firewall_rules_expected": 4,
            },
            "restricted_devices": [{"address": "192.168.2.10"}],
            "address_lists": [{"name": "MC-Test", "entries": 2}],
            "queues": [{"name": "MC-BW-192.168.2.10"}],
            "schedulers": [],
            "scripts": [{"name": "MC-NORMAL"}],
            "firewall": [],
        }


class AdvisoryOperationsInventoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = PolicyStore(str(Path(self.tmp.name) / "policy.db"))
        self.revision = self.store.ensure_config_revision_baseline(actor="test")["revision"]
        self.router = _InventoryRouter()

    def tearDown(self):
        self.tmp.cleanup()

    def test_reconciler_publishes_and_throttles_managed_inventory_observation(self):
        worker = AutoReconciler(
            policy_store=self.store,
            router=self.router,
            device_loader=lambda: [{"ip": "192.168.2.10", "name": "Tablet"}],
            plan_loader=lambda address: {
                "address": address,
                "global_mode": "normal",
                "temporary_override": False,
                "policy_actionable": False,
                "mode_drift": False,
                "bandwidth_drift": False,
                "service_drift": False,
                "status": "in_sync",
                "service_states": [],
            },
            audit=lambda *args: None,
        )
        worker.run_cycle(trigger="test-1", mode_override="observe")
        worker.run_cycle(trigger="test-2", mode_override="observe")

        self.assertEqual(1, self.router.inventory_calls)
        row = self.store.get_prepared_view(
            "router:managed-state-inventory",
            required_revision=self.revision,
            include_stale=True,
        )
        self.assertIsNotNone(row)
        self.assertEqual("ZEN", row["payload"]["router"])
        self.assertEqual(2, row["payload"]["counts"]["managed_address_entries"])


class RouterConnectionEvidenceClassificationTests(unittest.TestCase):
    @staticmethod
    def _request(perf, *, local_only=False):
        sample, token = perf.begin_request("GET", "/probe")
        sample.started_mono -= 0.2
        perf.record_component("routeros.mutation_status", 0.02)
        if not local_only:
            perf.record_component("routeros.connect", 1.0)
            perf.record_component("routeros.get_status", 2.0)
        perf.finish_request(sample, token, route="/probe", status=200)

    def test_local_router_observability_does_not_create_false_connection_evidence_gap(self):
        perf = PerformanceCollector()
        for _ in range(10):
            self._request(perf, local_only=True)
        for _ in range(5):
            self._request(perf, local_only=False)

        row = next(
            item for item in perf.snapshot()["acceptance"]["targets"]
            if item["key"] == "router_connections"
        )
        self.assertEqual(5, row["samples"])
        self.assertEqual(0, row["missing_evidence"])
        self.assertEqual(1, row["max_calls"])
        self.assertEqual("pass", row["state"])


class V05453SourceContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.main = (ROOT / "app/main.py").read_text()
        cls.reconciler = (ROOT / "app/reconciler.py").read_text()
        cls.operations = (ROOT / "app/operations.py").read_text()
        cls.performance = (ROOT / "app/performance.py").read_text()
        cls.template = (ROOT / "app/templates/index.html").read_text()

    def test_dashboard_uses_advisory_plan_summary_not_per_device_effective_policy_recompute(self):
        start = self.main.index('if active_view == "dashboard":\n        policy_summary = _build_advisory_policy_summary')
        end = self.main.index('if active_view in {"activity", "dashboard"}', start)
        block = self.main[start:end]
        self.assertIn("_build_advisory_policy_summary", block)
        self.assertNotIn("build_policy_summary(devices)", block.split('elif active_view == "policies"')[0])
        helper = self.main[
            self.main.index("def _build_advisory_policy_summary"):
            self.main.index("def _prepare_dashboard_payload")
        ]
        self.assertNotIn("policy_store.", helper)
        self.assertIn('plan.get("desired_mode")', helper)

    def test_index_template_is_compiled_during_startup_before_first_navigation(self):
        startup = self.main[
            self.main.index("def start_auto_reconciler"):
            self.main.index('@app.on_event("shutdown")')
        ]
        self.assertIn('templates.env.get_template("index.html")', startup)
        self.assertIn('perf_span("worker.template_warmup")', startup)

    def test_operations_navigation_uses_advisory_inventory_not_live_router_scan(self):
        dashboard = self.main[
            self.main.index("def dashboard("):
            self.main.index('@app.get("/api/services/health")')
        ]
        self.assertIn('"router:managed-state-inventory"', dashboard)
        self.assertNotIn("router.get_managed_state_inventory()", dashboard)
        self.assertIn("managed_inventory_notice", self.template)
        self.assertIn('view_key="router:managed-state-inventory"', self.reconciler)
        self.assertIn('view_key="router:managed-state-inventory"', self.operations)

    def test_explicit_live_inventory_endpoint_refreshes_advisory_cache(self):
        start = self.main.index('@app.get("/api/operations/inventory")')
        end = self.main.index('@app.get("/api/audit")', start)
        block = self.main[start:end]
        self.assertIn("router.get_managed_state_inventory()", block)
        self.assertIn('"router:managed-state-inventory"', block)
        self.assertIn("_publish_router_observation", block)

    def test_connection_gate_excludes_local_router_observability_spans_only(self):
        self.assertIn('"routeros.mutation_status"', self.performance)
        self.assertIn('"routeros.coherent_session"', self.performance)
        self.assertIn("non_transport_router_components", self.performance)


if __name__ == "__main__":
    unittest.main()
