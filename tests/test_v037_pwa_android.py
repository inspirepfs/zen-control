import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class ProgressiveWebAppContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.main = (ROOT / "app" / "main.py").read_text()
        cls.index = (ROOT / "app" / "templates" / "index.html").read_text()
        cls.pwa_head = (ROOT / "app" / "templates" / "_pwa_head.jinja").read_text()
        cls.pwa_js = (ROOT / "app" / "static" / "pwa.js").read_text()
        cls.pwa_css = (ROOT / "app" / "static" / "pwa.css").read_text()
        cls.worker = (ROOT / "app" / "static" / "service-worker.js").read_text()
        cls.manifest = json.loads((ROOT / "app" / "static" / "manifest.webmanifest").read_text())
        cls.offline = (ROOT / "app" / "static" / "offline.html").read_text()
        cls.pwa_module = (ROOT / "app" / "pwa.py").read_text()
        cls.templates = list((ROOT / "app" / "templates").glob("*.html"))

    def test_release_and_shared_pwa_head_are_current(self):
        self.assertIn('version="0.55.0"', self.main)
        for template in self.templates:
            self.assertIn('{% include "_pwa_head.jinja" %}', template.read_text(), template.name)
        for token in (
            '/static/manifest.webmanifest?v=0.55.0',
            '/static/pwa.css?v=0.55.0',
            '/static/pwa.js?v=0.55.0',
            'apple-mobile-web-app-capable',
            'theme-color',
        ):
            self.assertIn(token, self.pwa_head)

    def test_manifest_is_installable_and_tablet_friendly(self):
        self.assertEqual(self.manifest["id"], "/")
        self.assertEqual(self.manifest["scope"], "/")
        self.assertEqual(self.manifest["display"], "standalone")
        self.assertEqual(self.manifest["orientation"], "any")
        self.assertIn("view=dashboard", self.manifest["start_url"])
        sizes = {icon["sizes"] for icon in self.manifest["icons"]}
        self.assertTrue({"192x192", "512x512"}.issubset(sizes))
        self.assertGreaterEqual(len(self.manifest.get("shortcuts", [])), 2)

    def test_root_scope_service_worker_has_explicit_server_headers(self):
        self.assertIn('@app.get("/service-worker.js", include_in_schema=False)', self.main)
        self.assertIn('"Service-Worker-Allowed": "/"', self.main)
        self.assertIn('"Cache-Control": "no-cache, no-store, must-revalidate"', self.main)
        self.assertIn("navigator.serviceWorker.register('/service-worker.js', {scope: '/'})", self.pwa_js)

    def test_service_worker_never_caches_dynamic_application_data(self):
        self.assertIn("if (request.method !== 'GET') return", self.worker)
        self.assertIn("request.mode === 'navigate'", self.worker)
        self.assertIn("fetch(request, {cache: 'no-store'})", self.worker)
        self.assertIn("safePresentationAsset", self.worker)
        self.assertIn("url.pathname.startsWith('/pwa/icon/')", self.worker)
        self.assertIn("offlineMutations: false", self.worker)
        self.assertIn("cachedPrivateData: false", self.worker)
        # No offline mutation machinery is registered.
        self.assertNotIn("sync'", self.worker)
        self.assertNotIn('addEventListener("sync"', self.worker)
        self.assertNotIn("push'", self.worker)
        self.assertNotIn('addEventListener("push"', self.worker)

    def test_dynamic_server_responses_are_private_no_store(self):
        self.assertIn("private_dynamic_cache_headers", self.main)
        self.assertIn('response.headers["Cache-Control"] = "private, no-store"', self.main)
        self.assertIn('response.headers["Pragma"] = "no-cache"', self.main)
        self.assertIn('not path.startswith("/static/")', self.main)
        self.assertIn('not path.startswith("/pwa/icon/")', self.main)

    def test_offline_fallback_is_sanitized_and_read_only(self):
        self.assertIn("ZEN Control is unavailable", self.offline)
        self.assertIn("Policy, device, activity and authentication data are intentionally not stored", self.offline)
        self.assertIn("No changes are queued while offline", self.offline)
        for forbidden in ("192.168.", "csrf", "password", "api/audit", "RouterOS username"):
            self.assertNotIn(forbidden, self.offline)

    def test_shared_display_install_card_explains_security_boundary(self):
        self.assertIn("Android / tablet installed app", self.index)
        self.assertIn("data-pwa-install", self.index)
        self.assertIn("data-pwa-state", self.index)
        self.assertIn("never stored for offline viewing or queued for later replay", self.index)
        self.assertIn("Shared display mode blocks every existing POST control server-side", self.index)

    def test_install_and_explicit_update_flow_are_present(self):
        self.assertIn("window.isSecureContext", self.pwa_js)
        self.assertIn("HTTPS REQUIRED", self.pwa_js)
        self.assertIn("Android/Chromium installation requires HTTPS", self.pwa_js)
        self.assertIn("beforeinstallprompt", self.pwa_js)
        self.assertIn("appinstalled", self.pwa_js)
        self.assertIn("registration.waiting", self.pwa_js)
        self.assertIn("SKIP_WAITING", self.pwa_js)
        self.assertIn("controllerchange", self.pwa_js)
        self.assertIn("ZEN Control update ready", self.pwa_js)

    def test_old_shell_caches_are_removed_by_release(self):
        self.assertIn("zen-control-shell-${RELEASE}", self.worker)
        self.assertIn("caches.keys()", self.worker)
        self.assertIn("caches.delete(name)", self.worker)
        self.assertIn("name !== CACHE_NAME", self.worker)

    def test_pwa_server_status_contract_is_security_explicit(self):
        self.assertIn('@app.get("/api/pwa/status")', self.main)
        self.assertIn("return status_contract(app.version)", self.main)
        for token in (
            '"schema": "zen_pwa_status_v1"',
            '"mode": "online_first"',
            '"cached_private_data": False',
            '"offline_mutations": False',
            '"background_sync": False',
            '"push_notifications": False',
            '"server_auth_required": True',
            '"shared_display_lock_server_enforced": True',
        ):
            self.assertIn(token, self.pwa_module)

    def test_standalone_css_uses_safe_area_and_touch_layout(self):
        for token in (
            "@media(display-mode:standalone)",
            "safe-area-inset-top",
            "safe-area-inset-bottom",
            ".pwa-install-card",
            ".pwa-update-banner",
        ):
            self.assertIn(token, self.pwa_css)

    def test_embedded_icons_are_valid_pngs_at_required_sizes(self):
        import importlib.util
        from io import BytesIO
        from PIL import Image
        spec = importlib.util.spec_from_file_location("zen_pwa_assets", ROOT / "app" / "pwa.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        for size in (180, 192, 512):
            with Image.open(BytesIO(module.icon_png(size))) as image:
                self.assertEqual(image.size, (size, size))
                self.assertEqual(image.mode, "RGB")
        self.assertIn('@app.get("/pwa/icon/{size}.png", include_in_schema=False)', self.main)
        self.assertIn('"Cache-Control": "public, max-age=31536000, immutable"', self.main)

    def test_pwa_does_not_add_routeros_or_policy_write_routes(self):
        pwa_route_block = self.main[self.main.index('@app.get("/service-worker.js"'):self.main.index('@app.get("/health/live")')]
        self.assertNotIn("router.", pwa_route_block)
        self.assertNotIn("policy_store.", pwa_route_block)
        self.assertNotRegex(pwa_route_block, r'@app\.post\(')


if __name__ == "__main__":
    unittest.main()
