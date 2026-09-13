import unittest
from pathlib import Path

from app.runtime_health import build_runtime_health

ROOT = Path(__file__).resolve().parents[1]


class _Snapshot:
    def __init__(self, payload=None, error=False):
        self.payload = dict(payload or {})
        self.error = error

    def snapshot(self):
        if self.error:
            raise RuntimeError("hidden probe failure")
        return dict(self.payload)


class RuntimeHealthContractTests(unittest.TestCase):
    def _healthy(self):
        return build_runtime_health(
            version="0.55.4",
            background_worker=_Snapshot({"worker_alive": True}),
            reconciler=_Snapshot({
                "worker_alive": True,
                "observation_workers_configured": 4,
                "router_mutation": {"busy": False},
            }),
            incident_monitor=_Snapshot({"worker_alive": True}),
            summary_delivery=_Snapshot({"worker_running": True}),
        )

    def test_all_embedded_workers_must_be_alive(self):
        report = self._healthy()
        self.assertTrue(report["ok"])
        self.assertEqual(report["schema"], "zen_runtime_health_v1")
        self.assertEqual(report["parallel_observation"]["configured_workers"], 4)
        self.assertEqual(set(report["workers"]), {
            "background", "reconciler", "incidents", "summary_delivery"
        })

    def test_worker_failure_degrades_runtime_health(self):
        report = build_runtime_health(
            version="0.55.4",
            background_worker=_Snapshot({"worker_alive": False}),
            reconciler=_Snapshot({"worker_alive": True, "router_mutation": {}}),
            incident_monitor=_Snapshot({"worker_alive": True}),
            summary_delivery=_Snapshot({"worker_running": True}),
        )
        self.assertFalse(report["ok"])
        self.assertEqual(report["status"], "degraded")
        self.assertFalse(report["workers"]["background"]["alive"])

    def test_snapshot_exception_is_sanitized_and_fails_closed(self):
        report = build_runtime_health(
            version="0.55.4",
            background_worker=_Snapshot(error=True),
            reconciler=_Snapshot({"worker_alive": True, "router_mutation": {}}),
            incident_monitor=_Snapshot({"worker_alive": True}),
            summary_delivery=_Snapshot({"worker_running": True}),
        )
        self.assertFalse(report["ok"])
        self.assertEqual(report["workers"]["background"], {
            "required": True, "available": False, "alive": False
        })
        self.assertNotIn("hidden probe failure", repr(report))

    def test_mutation_lane_unavailable_degrades_runtime_health(self):
        report = build_runtime_health(
            version="0.55.4",
            background_worker=_Snapshot({"worker_alive": True}),
            reconciler=_Snapshot({
                "worker_alive": True,
                "observation_workers_configured": 99,
                "router_mutation": {"available": False, "busy": False},
            }),
            incident_monitor=_Snapshot({"worker_alive": True}),
            summary_delivery=_Snapshot({"worker_running": True}),
        )
        self.assertFalse(report["ok"])
        self.assertEqual(report["parallel_observation"]["configured_workers"], 8)
        self.assertFalse(report["router_mutation_lane"]["available"])


class V0543SourceContractTests(unittest.TestCase):
    def test_runtime_health_route_is_unauthenticated_minimal_release_probe(self):
        main = (ROOT / "app/main.py").read_text()
        block = main[main.index('@app.get("/health/runtime")'):main.index('@app.get("/health/ready")')]
        self.assertIn("build_runtime_health", block)
        self.assertIn("background_worker=background_worker", block)
        self.assertIn("reconciler=auto_reconciler", block)
        self.assertNotIn("Depends(", block)

    def test_release_workflow_gates_on_runtime_and_topology_health(self):
        source = (ROOT / "scripts/release_patch.py").read_text()
        self.assertIn("affected_services(release_paths", source)
        self.assertIn("wait_for_runtime_health(", source)
        self.assertIn("wait_for_topology(requirements", source)
        self.assertIn('"--force-recreate"', source)
        self.assertIn('["docker", "compose", "--profile", "*", "ps", "--all", "--format", "json"]', source)
        self.assertIn("telemetry/postgres changed", source)

    def test_release_and_docs_move_to_v0543(self):
        main = (ROOT / "app/main.py").read_text()
        readme = (ROOT / "README.md").read_text()
        changelog = (ROOT / "CHANGELOG.md").read_text()
        self.assertIn('version="0.55.4"', main)
        self.assertIn("Current release: **v0.55.4**", readme)
        self.assertIn("## v0.54.3 — Deployment topology & runtime-health closure", changelog)


if __name__ == "__main__":
    unittest.main()
