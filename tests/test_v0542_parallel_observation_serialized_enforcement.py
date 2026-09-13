import sys
import threading
import time
import types
import unittest
from contextlib import contextmanager
from pathlib import Path

sys.modules.setdefault("routeros_api", types.SimpleNamespace())

from app.parallel_observation import ParallelObserver
from app.reconciler import AutoReconciler
from app.router import RouterOSAdapter

ROOT = Path(__file__).resolve().parents[1]


class ParallelObserverTests(unittest.TestCase):
    def test_parallel_observation_overlaps_readers_and_preserves_input_order(self):
        observer = ParallelObserver(max_workers=4, name="test-observer")
        release = threading.Event()
        lock = threading.Lock()
        active = 0
        saw_parallel = threading.Event()

        def reader(item):
            nonlocal active
            with lock:
                active += 1
                if active >= 2:
                    saw_parallel.set()
            saw_parallel.wait(1.0)
            release.set()
            threading.Event().wait(0.01)
            with lock:
                active -= 1
            return item * 10

        batch = observer.observe(
            [3, 1, 4, 2],
            key=lambda item: str(item),
            reader=reader,
        )
        self.assertTrue(saw_parallel.is_set())
        self.assertGreaterEqual(batch["max_active"], 2)
        self.assertEqual(batch["order"], ["3", "1", "4", "2"])
        self.assertEqual(list(batch["results"]), ["3", "1", "4", "2"])
        self.assertEqual(batch["results"]["4"], 40)

    def test_parallel_observation_isolates_one_reader_failure(self):
        observer = ParallelObserver(max_workers=3)

        def reader(item):
            if item == "bad":
                raise RuntimeError("probe failed")
            return {"value": item}

        batch = observer.observe(
            ["a", "bad", "c"], key=str, reader=reader
        )
        self.assertEqual(set(batch["results"]), {"a", "c"})
        self.assertIn("bad", batch["errors"])
        self.assertIn("probe failed", batch["errors"]["bad"])

    def test_duplicate_observation_keys_fail_closed(self):
        observer = ParallelObserver(max_workers=2)
        with self.assertRaisesRegex(RuntimeError, "duplicated"):
            observer.observe(["x", "x"], key=str, reader=lambda item: item)


class RouterMutationLaneTests(unittest.TestCase):
    def adapter(self):
        adapter = RouterOSAdapter.__new__(RouterOSAdapter)
        adapter._ensure_mutation_state()
        return adapter

    def test_process_wide_mutation_lane_serializes_competing_threads(self):
        adapter = self.adapter()
        state_lock = threading.Lock()
        active = 0
        max_active = 0
        entered = []

        def writer(name):
            nonlocal active, max_active
            with adapter.mutation_session(owner=name, timeout=2):
                with state_lock:
                    active += 1
                    max_active = max(max_active, active)
                    entered.append(name)
                threading.Event().wait(0.04)
                with state_lock:
                    active -= 1

        threads = [
            threading.Thread(target=writer, args=("writer-a",)),
            threading.Thread(target=writer, args=("writer-b",)),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=2)
        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual(max_active, 1)
        self.assertCountEqual(entered, ["writer-a", "writer-b"])
        status = adapter.mutation_status()
        self.assertFalse(status["busy"])
        self.assertEqual(status["acquisitions"], 2)

    def test_nested_mutation_session_is_reentrant_one_logical_acquisition(self):
        adapter = self.adapter()
        with adapter.mutation_session(owner="outer"):
            self.assertEqual(adapter.mutation_status()["owner"], "outer")
            with adapter.mutation_session(owner="inner"):
                self.assertEqual(adapter.mutation_status()["owner"], "outer")
        self.assertEqual(adapter.mutation_status()["acquisitions"], 1)
        self.assertFalse(adapter.mutation_status()["busy"])


class _Settings:
    def get_settings(self):
        return {
            "auto_reconcile_mode": "enforce",
            "auto_reconcile_interval_seconds": "30",
            "auto_reconcile_failure_threshold": "3",
            "auto_reconcile_cooldown_seconds": "300",
        }


class _MutationAwareRouter:
    def __init__(self, *, degrade_second_security_check=False):
        self.lock = threading.RLock()
        self.local = threading.local()
        self.writes = []
        self.security_calls = 0
        self.degrade_second_security_check = degrade_second_security_check

    def get_security_posture(self):
        self.security_calls += 1
        if self.degrade_second_security_check and self.security_calls >= 2:
            return {
                "enforcement_ready": False,
                "checks": [{
                    "name": "authority changed",
                    "severity": "critical",
                    "status": "fail",
                }],
            }
        return {"enforcement_ready": True, "checks": []}

    @contextmanager
    def mutation_session(self, *, owner="test", timeout=30.0):
        del timeout
        with self.lock:
            self.local.owned = True
            self.local.owner = owner
            try:
                yield
            finally:
                self.local.owned = False
                self.local.owner = None

    def mutation_status(self):
        return {"schema": "zen_router_mutation_lane_v1", "busy": False}

    def set_device_mode(self, address, mode, description=""):
        del description
        if not getattr(self.local, "owned", False):
            raise AssertionError("write escaped serialized mutation lane")
        self.writes.append((address, mode))
        return {"mode": mode}


class ReconcilerParallelObservationTests(unittest.TestCase):
    @staticmethod
    def devices():
        return [{"ip": f"192.168.2.{idx}"} for idx in range(21, 25)]

    def test_observe_mode_parallelizes_planning_without_mutation(self):
        router = _MutationAwareRouter()

        def plan(address):
            threading.Event().wait(0.03)
            return {
                "address": address,
                "temporary_override": False,
                "policy_actionable": True,
                "status": "drift",
                "mode_drift": True,
                "live_mode": "normal",
                "desired_mode": "blocked",
                "bandwidth_drift": False,
                "service_drift": False,
            }

        worker = AutoReconciler(
            policy_store=_Settings(), router=router,
            device_loader=self.devices, plan_loader=plan,
            audit=lambda *_: None,
        )
        result = worker.run_cycle(mode_override="observe")
        self.assertEqual(result["result"], "drift")
        self.assertEqual(result["counts"]["observed"], 4)
        self.assertEqual(result["counts"]["drift"], 4)
        self.assertGreaterEqual(result["observation"]["max_active"], 2)
        self.assertEqual(router.writes, [])

    def test_parallel_plan_is_advisory_and_fresh_serial_read_controls_write(self):
        router = _MutationAwareRouter()
        calls = {}
        converged = set()
        call_lock = threading.Lock()

        def plan(address):
            with call_lock:
                calls[address] = calls.get(address, 0) + 1
                number = calls[address]
            # First call is the parallel observation: both look drifted.
            if number == 1:
                return {
                    "address": address, "temporary_override": False,
                    "policy_actionable": True, "status": "drift",
                    "mode_drift": True, "live_mode": "normal",
                    "desired_mode": "blocked", "bandwidth_drift": False,
                    "service_drift": False,
                }
            # Device .21 became synced before mutation ownership. It must not be
            # written merely because the parallel observation was stale.
            if address.endswith(".21") or address in converged:
                return {
                    "address": address, "temporary_override": False,
                    "policy_actionable": False, "status": "synced",
                    "mode_drift": False, "live_mode": "blocked",
                    "desired_mode": "blocked", "bandwidth_drift": False,
                    "service_drift": False,
                }
            return {
                "address": address, "temporary_override": False,
                "policy_actionable": True, "status": "drift",
                "mode_drift": True, "live_mode": "normal",
                "desired_mode": "blocked", "bandwidth_drift": False,
                "service_drift": False,
            }

        original = router.set_device_mode

        def set_mode(address, mode, description=""):
            result = original(address, mode, description)
            converged.add(address)
            return result

        router.set_device_mode = set_mode
        worker = AutoReconciler(
            policy_store=_Settings(), router=router,
            device_loader=lambda: [{"ip": "192.168.2.21"}, {"ip": "192.168.2.22"}],
            plan_loader=plan, audit=lambda *_: None,
        )
        result = worker.run_cycle(mode_override="enforce")
        self.assertEqual(result["result"], "applied")
        self.assertNotIn(("192.168.2.21", "blocked"), router.writes)
        self.assertIn(("192.168.2.22", "blocked"), router.writes)
        self.assertEqual(result["counts"]["applied"], 1)
        self.assertGreaterEqual(result["counts"]["synced"], 1)

    def test_authority_change_after_parallel_observation_blocks_all_writes(self):
        router = _MutationAwareRouter(degrade_second_security_check=True)

        def plan(address):
            return {
                "address": address, "temporary_override": False,
                "policy_actionable": True, "status": "drift",
                "mode_drift": True, "live_mode": "normal",
                "desired_mode": "blocked", "bandwidth_drift": False,
                "service_drift": False,
            }

        worker = AutoReconciler(
            policy_store=_Settings(), router=router,
            device_loader=lambda: [{"ip": "192.168.2.21"}],
            plan_loader=plan, audit=lambda *_: None,
        )
        result = worker.run_cycle(mode_override="enforce")
        self.assertEqual(result["result"], "security_hold")
        self.assertEqual(router.writes, [])
        self.assertGreaterEqual(router.security_calls, 2)


class V0542SourceContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.router = (ROOT / "app/router.py").read_text()
        cls.main = (ROOT / "app/main.py").read_text()
        cls.reconciler = (ROOT / "app/reconciler.py").read_text()
        cls.background = (ROOT / "app/background_work.py").read_text()

    def test_all_public_router_mutators_use_serialized_adapter_boundary(self):
        mutators = (
            "cleanup_stale_managed_resources", "set_mode", "set_web_policy",
            "provision_custom_service_contract", "remove_custom_service_contract",
            "set_device_services", "set_device_temporary_normal",
            "cancel_device_temporary_access", "set_device_bandwidth", "set_device_mode",
            "add_managed_schedule", "remove_managed_schedule", "set_temporary_normal",
            "cancel_temporary_access", "prepare_kid_control_migration_device",
            "rollback_kid_control_migration_device",
            "set_legacy_kid_control_profile_disabled", "add_restricted_device",
            "remove_restricted_device",
        )
        for name in mutators:
            with self.subTest(name=name):
                self.assertIn(f"@serialized_router_mutation\n    def {name}", self.router)

    def test_manual_multi_step_write_routes_own_logical_mutation_lane(self):
        for name in (
            "set_mode", "temporary", "add_schedule", "remove_schedule",
            "local_service_provision", "local_service_unprovision",
            "local_security_cleanup_stale", "redeem_device_rewards",
            "start_device_temporary_access", "cancel_device_temporary_access",
            "set_device_enforcement", "add_device", "remove_device", "set_web_policy",
        ):
            with self.subTest(name=name):
                self.assertIn(f"@coherent_router_mutation\ndef {name}", self.main)

        # v0.55.0.1 deliberately moves the declarative Apply buttons off the
        # synchronous RouterOS request path. The reconciler, not the HTTP route,
        # owns the mutation lane for those queued requests.
        for name in ("apply_device_policy", "apply_all_device_policies"):
            with self.subTest(name=f"queued:{name}"):
                self.assertNotIn(f"@coherent_router_mutation\ndef {name}", self.main)
                block = self.main.split(f"def {name}", 1)[1].split("\n@app.", 1)[0]
                self.assertIn("request_reconciliation", block)
                self.assertNotIn("router.", block)

    def test_authority_transfer_preserves_cycle_then_mutation_lock_order(self):
        self.assertIn('with self._mutation_context("authority-transfer"):', self.reconciler)
        self.assertIn('@coherent_router_request\ndef kid_control_migration_cutover', self.main)
        self.assertIn('@coherent_router_request\ndef kid_control_migration_rollback', self.main)

    def test_background_worker_still_has_no_routeros_dependency(self):
        self.assertNotIn("RouterOSAdapter", self.background)
        self.assertNotIn("router.", self.background)

    def test_observation_worker_setting_is_publicly_wired_and_bounded(self):
        env_example = (ROOT / ".env.example").read_text()
        compose = (ROOT / "docker-compose.yml").read_text()
        install = (ROOT / "docs" / "INSTALL.md").read_text()
        reconciler = (ROOT / "app" / "reconciler.py").read_text()

        self.assertIn("ZEN_ROUTER_OBSERVE_WORKERS=4", env_example)
        self.assertIn('ZEN_ROUTER_OBSERVE_WORKERS: "${ZEN_ROUTER_OBSERVE_WORKERS:-4}"', compose)
        self.assertIn("ZEN_ROUTER_OBSERVE_WORKERS", install)
        self.assertIn('os.getenv("ZEN_ROUTER_OBSERVE_WORKERS", "4")', reconciler)
        self.assertIn("max(1, min(8, observation_workers))", reconciler)

    def test_cycle_diagnostics_expose_observation_and_mutation_lane_evidence(self):
        template = (ROOT / "app" / "templates" / "index.html").read_text()
        for label in (
            "Observed",
            "Plan failures",
            "Read workers",
            "Max parallel reads",
            "Read-plan time",
            "Mutation lane",
        ):
            self.assertIn(label, template)
        self.assertIn("reconciler_status.last.observation", template)
        self.assertIn("reconciler_status.router_mutation", template)

    def test_release_identity_is_v0542(self):
        self.assertIn('version="0.55.3.1"', self.main)
        self.assertIn("v0.55.3.1", (ROOT / "README.md").read_text())
        self.assertIn("## v0.54.2 — Parallel observation / serialized enforcement", (ROOT / "CHANGELOG.md").read_text())


if __name__ == "__main__":
    unittest.main()
