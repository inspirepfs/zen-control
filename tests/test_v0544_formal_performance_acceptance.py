import sys
import types
import unittest
from pathlib import Path

sys.modules.setdefault("routeros_api", types.SimpleNamespace())

from app.performance import PerformanceCollector, build_formal_acceptance

ROOT = Path(__file__).resolve().parents[1]


class FormalPerformanceAcceptanceTests(unittest.TestCase):
    @staticmethod
    def _finish(perf, *, method, route, duration_ms, router=False, connects=1, status=200, error=""):
        sample, token = perf.begin_request(method, route)
        sample.started_mono -= duration_ms / 1000.0
        if router:
            for _ in range(connects):
                perf.record_component("routeros.connect", 1.0)
            perf.record_component("routeros.read", 2.0)
        perf.finish_request(sample, token, route=route, status=status, error=error)

    def _populate_request_classes(self, perf, *, count=5):
        for _ in range(count):
            self._finish(perf, method="GET", route="/?view=dashboard&section=overview", duration_ms=200)
            self._finish(perf, method="POST", route="/local/profile", duration_ms=120)
            self._finish(perf, method="POST", route="/devices/enforcement", duration_ms=600, router=True)
            self._finish(perf, method="GET", route="/devices/{address}", duration_ms=450, router=True)

    @staticmethod
    def _populate_prepared_hits(perf, *, count=5):
        for _ in range(count):
            perf.record_evidence("prepared_view.lookup")
            perf.record_evidence("prepared_view.hit")

    def test_stats_include_min_and_outliers_are_retained(self):
        perf = PerformanceCollector()
        for value in [100.0] * 19 + [2200.0]:
            self._finish(perf, method="GET", route="/?view=dashboard&section=overview", duration_ms=value)
        row = next(item for item in perf.snapshot()["acceptance"]["targets"] if item["key"] == "navigation")
        self.assertAlmostEqual(100.0, row["min_ms"], delta=5.0)
        self.assertGreater(row["max_ms"], 2100.0)
        self.assertGreater(row["p99_ms"], row["p95_ms"])
        self.assertEqual(20, row["valid_samples"])

    def test_missing_router_connection_evidence_can_never_pass(self):
        perf = PerformanceCollector()
        for _ in range(5):
            sample, token = perf.begin_request("GET", "/devices/1")
            sample.started_mono -= 0.2
            perf.record_component("routeros.read", 2.0)
            perf.finish_request(sample, token, route="/devices/{address}", status=200)
        row = next(item for item in perf.snapshot()["acceptance"]["targets"] if item["key"] == "router_connections")
        self.assertEqual("pending", row["state"])
        self.assertEqual("missing-connection-evidence", row["reason"])
        self.assertEqual(5, row["missing_evidence"])
        self.assertEqual(0, row["max_calls"])

    def test_one_multi_connection_request_fails_exact_per_request_budget(self):
        perf = PerformanceCollector()
        for index in range(20):
            self._finish(
                perf,
                method="GET",
                route="/devices/{address}",
                duration_ms=300,
                router=True,
                connects=2 if index == 19 else 1,
            )
        row = next(item for item in perf.snapshot()["acceptance"]["targets"] if item["key"] == "router_connections")
        self.assertEqual("fail", row["state"])
        self.assertEqual("connection-budget-exceeded", row["reason"])
        self.assertEqual(1, row["multiple_connections"])
        self.assertEqual(2, row["max_calls"])

    def test_failed_requests_do_not_manufacture_healthy_latency(self):
        perf = PerformanceCollector()
        for _ in range(5):
            self._finish(perf, method="GET", route="/?view=dashboard&section=overview", duration_ms=150)
        self._finish(
            perf,
            method="GET",
            route="/?view=dashboard&section=overview",
            duration_ms=5,
            status=500,
            error="RuntimeError: failed",
        )
        row = next(item for item in perf.snapshot()["acceptance"]["targets"] if item["key"] == "navigation")
        self.assertEqual(5, row["valid_samples"])
        self.assertEqual(1, row["invalid_samples"])
        self.assertEqual("fail", row["state"])
        self.assertEqual("request-errors-present", row["reason"])

    def test_formal_gate_requires_runtime_observability_evidence(self):
        perf = PerformanceCollector()
        self._populate_request_classes(perf)
        snapshot = perf.snapshot()
        formal = build_formal_acceptance(snapshot, {})
        self.assertEqual("pending", formal["state"])
        states = {row["key"]: row["state"] for row in formal["evidence_targets"]}
        self.assertEqual("pending", states["prepared_views"])
        self.assertEqual("pending", states["parallel_observation"])
        self.assertEqual("pending", states["mutation_lane"])

    def test_relaxed_threshold_profile_cannot_manufacture_formal_pass(self):
        perf = PerformanceCollector()
        self._populate_request_classes(perf)
        self._populate_prepared_hits(perf)
        snapshot = perf.snapshot()
        snapshot["configuration"]["budget_navigation_p95_ms"] = 5000.0
        operational = {
            "background_worker": {"worker_alive": True, "last_duration_ms": 12.5, "last_result": "ok", "last_failed": 0},
            "parallel_observation": {
                "items": 4, "workers": 4, "max_active": 4,
                "utilisation_percent": 100.0, "failed": 0,
            },
            "mutation_lane": {
                "acquisitions": 5, "contentions": 0,
                "last_wait_ms": 0.1, "max_wait_ms": 0.5,
            },
        }
        formal = build_formal_acceptance(snapshot, operational)
        row = next(item for item in formal["evidence_targets"] if item["key"] == "threshold_profile")
        self.assertEqual("fail", row["state"])
        self.assertIn("budget_navigation_p95_ms", row["relaxed"])
        self.assertEqual("fail", formal["state"])

    def test_degraded_background_worker_is_formal_fail(self):
        perf = PerformanceCollector()
        self._populate_request_classes(perf)
        self._populate_prepared_hits(perf)
        snapshot = perf.snapshot()
        operational = {
            "background_worker": {
                "worker_alive": True, "last_duration_ms": 66009.0,
                "last_result": "degraded", "last_failed": 6,
            },
            "parallel_observation": {
                "items": 4, "workers": 4, "max_active": 4,
                "utilisation_percent": 100.0, "failed": 0,
            },
            "mutation_lane": {
                "acquisitions": 1, "contentions": 0,
                "last_wait_ms": 0.0, "max_wait_ms": 0.0,
            },
        }
        formal = build_formal_acceptance(snapshot, operational)
        row = next(item for item in formal["evidence_targets"] if item["key"] == "background_worker")
        self.assertEqual("fail", row["state"])
        self.assertEqual(6, row["last_failed"])
        self.assertEqual("fail", formal["state"])

    def test_formal_gate_passes_with_complete_observational_evidence(self):
        perf = PerformanceCollector()
        self._populate_request_classes(perf)
        self._populate_prepared_hits(perf)
        snapshot = perf.snapshot()
        operational = {
            "background_worker": {"worker_alive": True, "last_duration_ms": 12.5, "last_result": "ok", "last_failed": 0},
            "parallel_observation": {
                "items": 4,
                "workers": 4,
                "max_active": 4,
                "utilisation_percent": 100.0,
                "failed": 0,
            },
            "mutation_lane": {
                "acquisitions": 5,
                "contentions": 1,
                "last_wait_ms": 0.2,
                "max_wait_ms": 4.8,
            },
        }
        formal = build_formal_acceptance(snapshot, operational)
        self.assertEqual("pass", formal["state"])
        self.assertTrue(all(row["state"] == "pass" for row in formal["evidence_targets"]))


class FormalPerformanceSourceContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.main = (ROOT / "app/main.py").read_text()
        cls.performance = (ROOT / "app/performance.py").read_text()
        cls.router = (ROOT / "app/router.py").read_text()
        cls.background = (ROOT / "app/background_work.py").read_text()
        cls.reconciler = (ROOT / "app/reconciler.py").read_text()
        cls.template = (ROOT / "app/templates/performance.html").read_text()
        cls.script = (ROOT / "scripts/perf_acceptance.py").read_text()
        cls.readme = (ROOT / "README.md").read_text()
        cls.changelog = (ROOT / "CHANGELOG.md").read_text()
        cls.compose = (ROOT / "docker-compose.yml").read_text()
        cls.env_example = (ROOT / ".env.example").read_text()

    def test_formal_sample_floor_is_not_configurable_below_five(self):
        self.assertIn('ZEN_PERF_ACCEPTANCE_MIN_SAMPLES", 5, 5, 100', self.performance)
        self.assertIn('or path.startswith("/local/performance/")', self.main)

    def test_release_and_formal_contract_are_v0544(self):
        self.assertIn('version="0.55.4.2"', self.main)
        self.assertIn("zen_performance_acceptance_v2", self.performance)
        self.assertIn("zen_formal_performance_acceptance_v1", self.performance)
        self.assertIn("ZEN Control v0.54.4 formal performance acceptance", self.script)
        self.assertIn("Current release: **v0.55.4.2**", self.readme)
        self.assertIn("## v0.54.4 — Formal performance acceptance", self.changelog)

    def test_prepared_view_hit_miss_fallback_evidence_is_explicit(self):
        self.assertIn('record_evidence("prepared_view.hit")', self.main)
        self.assertIn('record_evidence("prepared_view.miss")', self.main)
        self.assertIn('record_evidence("prepared_view.fallback")', self.main)
        self.assertIn("Prepared-view effectiveness", self.performance)

    def test_runtime_performance_snapshot_does_not_query_durable_background_stats(self):
        block = self.background.split("def performance_snapshot", 1)[1].split("@timed", 1)[0]
        self.assertNotIn("background_work_stats", block)
        self.assertIn("last_duration_ms", block)

    def test_formal_snapshot_surfaces_worker_observation_and_mutation_contention(self):
        self.assertIn("background_worker.performance_snapshot()", self.main)
        self.assertIn("auto_reconciler.performance_snapshot()", self.main)
        self.assertIn("raw_router.mutation_status()", self.main)
        self.assertIn("utilisation_percent", self.reconciler)
        self.assertIn('"contentions"', self.router)
        self.assertIn("Serialized mutation-lane contention", self.performance)

    def test_performance_evidence_never_creates_a_routeros_authority_path(self):
        formal = self.performance.split("def build_formal_acceptance", 1)[1].split("collector =", 1)[0]
        self.assertNotIn("mutation_session(", formal)
        self.assertNotIn("coherent_session(", formal)
        self.assertNotIn("set_device_", formal)
        self.assertIn("Operational evidence is read-only", formal)


    def test_compose_propagates_formal_acceptance_configuration(self):
        for name in (
            "ZEN_PERF_ACCEPTANCE_MIN_SAMPLES",
            "ZEN_PERF_ACCEPTANCE_RECOMMENDED_SAMPLES",
            "ZEN_PERF_BUDGET_NAVIGATION_MS",
            "ZEN_PERF_BUDGET_LOCAL_WRITE_MS",
            "ZEN_PERF_BUDGET_ROUTER_ACTION_MS",
            "ZEN_PERF_BUDGET_ROUTER_READ_MS",
        ):
            self.assertIn(name, self.compose)
            self.assertIn(name, self.env_example)

    def test_acceptance_cli_supports_live_fetch_and_sanitized_json_output(self):
        self.assertIn('parser.add_argument("--url"', self.script)
        self.assertIn('"--cookie-env"', self.script)
        self.assertIn('parser.add_argument("--json-out"', self.script)
        self.assertIn("zen_performance_acceptance_report_v1", self.script)
        self.assertNotIn('"slow_requests"', self.script)

    def test_performance_ui_defaults_to_twenty_measured_rounds(self):
        self.assertIn('id="perfRounds" type="number" min="1" max="50" value="20"', self.template)
        self.assertIn("recommended acceptance run", self.template)
        self.assertIn("invalid samples cannot manufacture PASS", self.template)


if __name__ == "__main__":
    unittest.main()
