import sys
import threading
import types
import unittest
from pathlib import Path

sys.modules.setdefault("routeros_api", types.SimpleNamespace())

from app.router import RouterOSAdapter

ROOT = Path(__file__).resolve().parents[1]


class _FakePool:
    def __init__(self):
        self.disconnects = 0

    def disconnect(self):
        self.disconnects += 1


class _FakeApi:
    def __init__(self):
        self.reads = 0

    def read(self):
        self.reads += 1
        return self.reads


class _FakeRouter(RouterOSAdapter):
    """Small adapter that exercises the real coherent-session implementation."""

    def __init__(self):
        self._session_local = threading.local()
        self.opens = 0
        self.pools = []
        self.api = _FakeApi()

    def _open_connection(self):
        self.opens += 1
        pool = _FakePool()
        self.pools.append(pool)
        return pool, self.api

    def fresh_probe(self):
        pool, api = self._connect()
        try:
            return api.read()
        finally:
            pool.disconnect()


class CoherentRouterSessionTests(unittest.TestCase):
    def test_one_transport_reuses_connection_but_not_router_values(self):
        router = _FakeRouter()

        with router.coherent_session():
            self.assertEqual(1, router.fresh_probe())
            self.assertEqual(2, router.fresh_probe())
            with router.coherent_session():
                self.assertEqual(3, router.fresh_probe())

        self.assertEqual(1, router.opens)
        self.assertEqual(1, len(router.pools))
        self.assertEqual(1, router.pools[0].disconnects)
        self.assertEqual(3, router.api.reads)

    def test_calls_outside_coherent_session_still_open_independently(self):
        router = _FakeRouter()
        self.assertEqual(1, router.fresh_probe())
        self.assertEqual(2, router.fresh_probe())
        self.assertEqual(2, router.opens)
        self.assertEqual([1, 1], [pool.disconnects for pool in router.pools])


class PerformanceImplementationContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.main = (ROOT / "app/main.py").read_text()
        cls.router = (ROOT / "app/router.py").read_text()
        cls.index = (ROOT / "app/templates/index.html").read_text()
        cls.performance_template = (ROOT / "app/templates/performance.html").read_text()
        cls.css = (ROOT / "app/static/app.css").read_text()
        cls.readme = (ROOT / "README.md").read_text() + "\n" + (ROOT / "CHANGELOG.md").read_text()

    def test_write_routes_use_coherent_router_transport(self):
        self.assertIn("def coherent_router_request(func):", self.main)
        self.assertIn("def coherent_router_mutation(func):", self.main)
        mutation_routes = (
            "def set_device_enforcement(",
            "def start_device_temporary_access(",
            "def local_service_provision(",
        )
        for route in mutation_routes:
            offset = self.main.index(route)
            prefix = self.main[max(0, offset - 260):offset]
            self.assertIn("@coherent_router_mutation", prefix, route)
        # v0.54.5.1 deliberately decouples declarative Apply from synchronous
        # RouterOS mutation. The request durably queues desired-state intent;
        # AutoReconciler owns the later coherent mutation session.
        route = "def apply_device_policy("
        offset = self.main.index(route)
        block = self.main[offset:self.main.index("@app.", offset + len(route))]
        prefix = self.main[max(0, offset - 260):offset]
        self.assertNotIn("@coherent_router_mutation", prefix)
        self.assertIn("request_reconciliation", block)
        self.assertNotIn("router.", block)
        # The reconciler route may execute OBSERVE without mutation authority;
        # ENFORCE acquires the mutation lane inside AutoReconciler after planning.
        route = "def local_reconciler_run_now("
        offset = self.main.index(route)
        prefix = self.main[max(0, offset - 240):offset]
        self.assertIn("@coherent_router_request", prefix, route)

    def test_router_session_explicitly_preserves_fresh_reads(self):
        self.assertIn("It does not cache RouterOS values", self.router)
        self.assertIn("including post-write fresh validation", self.router)
        self.assertNotIn("routeros_cache_ttl", self.router.lower())

    def test_root_renders_only_requested_top_level_view(self):
        for view in ("dashboard", "devices", "policies", "schedules", "activity", "incidents", "audit", "settings"):
            self.assertIn("{% if active_view == '" + view + "' %}", self.index)
        self.assertIn('href="/?view=policies&amp;section=profiles#policies/profiles"', self.index)
        self.assertIn('href="/?view=audit&amp;section=recent#audit/recent"', self.index)
        self.assertIn("window.location.href = `/?view=${encodeURIComponent(view)}&section=${encodeURIComponent(group.key)}#${view}/${group.key}`", self.index)

    def test_local_settings_sections_do_not_force_router_connection(self):
        self.assertIn('active_view == "settings" and active_section in {"security", "operations"}', self.main)
        self.assertNotIn('active_view in {"dashboard", "settings", "activity"}', self.main)
        self.assertIn('active_view == "policies" and active_section == "services"', self.main)

    def test_write_feedback_is_immediate_and_non_authoritative(self):
        self.assertIn('id="zenWriteProgress"', self.index)
        self.assertIn("Applying ${label || 'change'}…", self.index)
        self.assertIn("zen-write-progress-spinner", self.css)
        self.assertIn("aria-busy", self.index)
        self.assertNotIn("optimistic", self.index.lower())

    def test_v0301_documentation_describes_optimization_and_safety_boundary(self):
        self.assertIn("## Performance Implementation (v0.30.1)", self.readme)
        self.assertIn("coherent RouterOS", self.readme)
        self.assertIn("no RouterOS value cache", self.readme)
        self.assertIn("post-write fresh validation", self.readme)
        self.assertIn("view/subsection", self.readme)
        self.assertIn("v0.30.1", self.performance_template)


if __name__ == "__main__":
    unittest.main()
