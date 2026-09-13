from pathlib import Path
import time
import unittest

from app.performance import (
    InstrumentedProxy,
    PerformanceCollector,
    collector,
    perf_span,
    perf_sql,
)

ROOT = Path(__file__).resolve().parents[1]


class PerformanceCollectorTests(unittest.TestCase):
    def test_request_snapshot_has_route_distribution_and_component_counts(self):
        perf = PerformanceCollector()
        sample, token = perf.begin_request("GET", "/devices/192.0.2.10")
        perf.record_component("routeros.get_device_enforcement", 15.0)
        perf.record_component("routeros.get_device_enforcement", 10.0)
        perf.finish_request(
            sample, token, route="/devices/{address}", status=200
        )
        snapshot = perf.snapshot()
        self.assertEqual("zen_performance_snapshot_v1", snapshot["schema"])
        self.assertEqual(1, snapshot["request_summary"]["retained"])
        route = snapshot["routes"][0]
        self.assertEqual("GET /devices/{address}", route["route"])
        self.assertEqual(2.0, route["top_components"][0]["avg_calls_per_request"])
        self.assertEqual(25.0, route["top_components"][0]["avg_ms_per_request"])

    def test_percentiles_are_reported_not_only_average(self):
        perf = PerformanceCollector()
        for duration in (1, 2, 3, 100):
            sample, token = perf.begin_request("GET", "/x")
            sample.started_mono -= duration / 1000.0
            perf.finish_request(sample, token, route="/x", status=200)
        route = perf.snapshot()["routes"][0]
        self.assertGreater(route["p95_ms"], route["p50_ms"])
        self.assertGreaterEqual(route["max_ms"], route["p95_ms"])

    def test_reset_clears_request_and_component_evidence(self):
        perf = PerformanceCollector()
        sample, token = perf.begin_request("GET", "/x")
        perf.record_component("sqlite.list_profiles", 2.0)
        perf.finish_request(sample, token, route="/x", status=200)
        self.assertEqual(1, perf.snapshot()["request_summary"]["retained"])
        perf.reset()
        snapshot = perf.snapshot()
        self.assertEqual(0, snapshot["request_summary"]["retained"])
        self.assertEqual([], snapshot["components"])

    def test_slow_threshold_and_process_evidence_are_visible(self):
        perf = PerformanceCollector()
        snapshot = perf.snapshot()
        self.assertIn("slow_request_ms", snapshot["configuration"])
        self.assertEqual("memory-only", snapshot["configuration"]["storage"])
        self.assertIn("current_rss_mb", snapshot["process"])
        self.assertIn("threads", snapshot["process"])


class PerformanceInstrumentationTests(unittest.TestCase):
    def setUp(self):
        collector.reset()

    def tearDown(self):
        collector.reset()

    def test_proxy_measures_public_method_without_wrapping_attributes(self):
        class Target:
            value = 7
            def read(self):
                time.sleep(0.001)
                return "ok"

        proxy = InstrumentedProxy(Target(), "routeros")
        self.assertEqual(7, proxy.value)
        self.assertEqual("ok", proxy.read())
        names = {row["name"] for row in collector.snapshot()["components"]}
        self.assertIn("routeros.read", names)

    def test_perf_span_records_background_component(self):
        with perf_span("worker.test"):
            time.sleep(0.001)
        row = next(
            row for row in collector.snapshot()["components"]
            if row["name"] == "worker.test"
        )
        self.assertEqual(1, row["count"])
        self.assertEqual(1, row["scopes"].get("background"))

    def test_sql_fingerprint_contains_static_sql_not_parameter_values(self):
        with perf_sql("SELECT * FROM flow_5m WHERE client_ip = %s"):
            time.sleep(0.001)
        row = collector.snapshot()["sql"][0]
        self.assertIn("client_ip = %s", row["preview"])
        self.assertNotIn("192.0.2.10", row["preview"])
        self.assertEqual(10, len(row["fingerprint"]))

    def test_component_timings_are_labelled_inclusive_evidence(self):
        notes = " ".join(collector.snapshot()["notes"]).lower()
        self.assertIn("inclusive", notes)
        self.assertIn("overlap", notes)
        self.assertIn("multiple warm requests", notes)


class PerformanceGatheringUxTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.main = (ROOT / "app/main.py").read_text()
        cls.performance = (ROOT / "app/performance.py").read_text()
        cls.template = (ROOT / "app/templates/performance.html").read_text()
        cls.index = (ROOT / "app/templates/index.html").read_text()
        cls.css = (ROOT / "app/static/performance.css").read_text()
        cls.compose = (ROOT / "docker-compose.yml").read_text()
        cls.env = (ROOT / ".env.example").read_text()
        cls.readme = (ROOT / "README.md").read_text() + "\n" + (ROOT / "CHANGELOG.md").read_text()
        cls.unit_script = (ROOT / "scripts/perf_unit_baseline.py").read_text()
        cls.analysis_script = (ROOT / "scripts/perf_analyse.py").read_text()
        cls.runtime_script = (ROOT / "scripts/perf_runtime_snapshot.sh").read_text()

    def test_release_version_and_performance_routes(self):
        self.assertIn('version="0.55.1"', self.main)
        self.assertIn('@app.get("/api/performance")', self.main)
        self.assertIn('@app.get("/performance"', self.main)
        self.assertIn('@app.post("/local/performance/reset")', self.main)
        self.assertIn('/static/performance.css?v=0.55.1', self.template)

    def test_request_middleware_exports_server_timing_headers(self):
        self.assertIn('@app.middleware("http")', self.main)
        self.assertIn('X-ZEN-Request-Ms', self.main)
        self.assertIn('X-ZEN-Request-ID', self.main)
        self.assertIn('Server-Timing', self.main)
        self.assertIn('path.startswith("/api/performance")', self.main)
        self.assertIn('path.startswith("/health")', self.main)

    def test_core_sources_remain_instrumented_through_optimization(self):
        self.assertIn('instrument(RouterOSAdapter(), "routeros")', self.main)
        self.assertIn('"sqlite"', self.main)
        self.assertIn('instrument(ActivityStore(), "telemetry")', self.main)
        self.assertIn('"auth",', self.main)
        self.assertIn('routeros.connect', (ROOT / 'app/router.py').read_text())
        self.assertIn('postgres.connect', (ROOT / 'app/activity.py').read_text())
        self.assertIn('postgres.query', self.performance)

    def test_performance_page_has_authenticated_same_origin_probe(self):
        self.assertIn('Browser baseline probe', self.template)
        self.assertIn("credentials: 'same-origin'", self.template)
        self.assertIn("method: 'GET'", self.template)
        self.assertIn('X-ZEN-Request-Ms', self.template)
        self.assertIn('/activity/analytics', self.template)
        self.assertIn('/policy/simulate', self.template)
        self.assertNotIn("method: 'POST'", self.template)

    def test_performance_ui_is_linked_from_operations_and_is_dense(self):
        self.assertIn('Open performance metrics', self.index)
        self.assertIn('href="/performance"', self.index)
        self.assertIn('.perf-stat-grid', self.css)
        self.assertIn('.dense-table', self.css)
        self.assertIn('@media(max-width:720px)', self.css)

    def test_measurement_is_memory_only_and_configurable(self):
        self.assertIn('ZEN_PERF_ENABLED', self.compose)
        self.assertIn('ZEN_PERF_SAMPLE_LIMIT', self.compose)
        self.assertIn('ZEN_PERF_COMPONENT_LIMIT', self.compose)
        self.assertIn('ZEN_PERF_SLOW_MS', self.env)
        self.assertIn('memory-only', self.performance)
        self.assertNotIn('CREATE TABLE', self.performance)

    def test_scripts_cover_synthetic_baseline_and_snapshot_ranking(self):
        self.assertIn('unittest', self.unit_script)
        self.assertIn('--runs', self.unit_script)
        self.assertIn('zen_performance_snapshot_v1', self.analysis_script)
        self.assertIn('Slow routes', self.analysis_script)
        self.assertIn('Highest cumulative component cost', self.analysis_script)
        self.assertIn('docker stats --no-stream', self.runtime_script)
        self.assertIn('pg_stat_user_tables', self.runtime_script)
        self.assertIn('policy_db_bytes', self.runtime_script)

    def test_readme_marks_v030_as_measurement_not_optimization(self):
        self.assertIn('## Performance Gathering (v0.30)', self.readme)
        self.assertIn('measurement release', self.readme)
        self.assertIn('not an optimization release', self.readme)
        self.assertIn('v0.30.1', self.readme)
        self.assertIn('python3 scripts/perf_unit_baseline.py --runs 5', self.readme)
        self.assertIn('bash scripts/perf_runtime_snapshot.sh', self.readme)


if __name__ == "__main__":
    unittest.main()
