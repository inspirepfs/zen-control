import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


class SecureTransportCommissioningConfigTests(unittest.TestCase):
    def config(self, **overrides):
        from app.secure_transport import SecureTransportConfig

        values = {
            "ZEN_REMOTE_ACCESS_ENABLED": "0",
            "ZEN_SECURE_COOKIES": "1",
            "ZEN_PUBLIC_HOST": "",
            "ZEN_LOCAL_HOST": "zen.home.example.net",
            "ZEN_LAN_BIND_IP": "192.0.2.10",
            "ZEN_ALLOWED_HOSTS": "zen.home.example.net,localhost,127.0.0.1",
            "ZEN_CLOUDFLARE_ACCESS_PROTECTED": "0",
            "ZEN_HSTS_MAX_AGE": "31536000",
        }
        values.update(overrides)
        return SecureTransportConfig.from_mapping(values)

    def test_local_https_can_be_commissioning_ready_without_remote_access(self):
        status = self.config().status("0.56.0")
        self.assertEqual("ready_for_live_validation", status["state"])
        self.assertTrue(status["commissioning_ready"])
        self.assertEqual("ready_for_live_validation", status["local_https"]["state"])
        self.assertEqual("disabled", status["remote_access"]["state"])
        self.assertEqual("ready_for_browser_validation", status["pwa"]["state"])

    def test_secure_cookie_and_local_host_allowlist_are_required_for_hardened_local_https(self):
        status = self.config(ZEN_SECURE_COOKIES="0", ZEN_ALLOWED_HOSTS="localhost,127.0.0.1").status("0.56.0")
        self.assertEqual("configuration_incomplete", status["state"])
        self.assertFalse(status["commissioning_ready"])
        failed = {row["key"] for row in status["local_https"]["checks"] if row["state"] == "fail"}
        self.assertEqual({"secure_cookie", "host_allowlist"}, failed)

    def test_remote_access_is_optional_but_when_enabled_must_be_ready(self):
        cfg = self.config(
            ZEN_REMOTE_ACCESS_ENABLED="1",
            ZEN_PUBLIC_HOST="zen.example.net",
            ZEN_ALLOWED_HOSTS="zen.home.example.net,zen.example.net,localhost,127.0.0.1",
            ZEN_CLOUDFLARE_ACCESS_PROTECTED="1",
        )
        status = cfg.status("0.56.0")
        self.assertTrue(status["remote_ready"])
        self.assertTrue(status["commissioning_ready"])
        self.assertEqual("ready_for_live_validation", status["remote_access"]["state"])

    def test_bad_local_host_and_bind_ip_fail_closed(self):
        from app.secure_transport import SecureTransportConfigError

        with self.assertRaises(SecureTransportConfigError):
            self.config(ZEN_LOCAL_HOST="https://zen.example.net")
        with self.assertRaises(SecureTransportConfigError):
            self.config(ZEN_LAN_BIND_IP="not-an-ip")

    def test_hsts_applies_to_hardened_local_https_even_when_remote_disabled(self):
        from app.secure_transport import security_headers

        headers = security_headers(self.config(ZEN_HSTS_MAX_AGE="86400"))
        self.assertEqual("max-age=86400", headers["Strict-Transport-Security"])


class TransportAcceptanceTests(unittest.TestCase):
    def test_local_probe_rejects_plain_http(self):
        from scripts.transport_acceptance import probe_local

        result = probe_local("http://zen.example.net/")
        self.assertEqual("fail", result["state"])
        self.assertEqual("local_url_must_be_https", result["checks"][0]["reason"])

    def test_local_probe_proves_health_headers_service_worker_and_manifest(self):
        from scripts import transport_acceptance as module

        responses = {
            "/health/live": {
                "status": 200,
                "headers": {
                    "x-content-type-options": "nosniff",
                    "x-frame-options": "DENY",
                    "referrer-policy": "same-origin",
                    "strict-transport-security": "max-age=31536000",
                },
                "body": json.dumps({"ok": True, "status": "alive", "version": "0.56.0"}).encode(),
                "error": None,
            },
            "/service-worker.js": {
                "status": 200,
                "headers": {"service-worker-allowed": "/", "cache-control": "no-cache, no-store, must-revalidate"},
                "body": b"self.addEventListener('message', e => { if (e.data.type === 'SKIP_WAITING') self.skipWaiting(); });",
                "error": None,
            },
            "/static/manifest.webmanifest": {
                "status": 200,
                "headers": {},
                "body": json.dumps({"display": "standalone", "start_url": "/", "icons": [{}, {}]}).encode(),
                "error": None,
            },
        }

        with patch.object(module, "_fetch", side_effect=lambda _base, path, _timeout: responses[path]):
            result = module.probe_local(
                "https://zen.example.net/", expect_version="0.56.0", require_hsts=True
            )
        self.assertEqual("pass", result["state"])
        self.assertTrue(result["server_pwa_ready"])
        self.assertEqual({"pass"}, {row["state"] for row in result["checks"]})

    def test_local_probe_does_not_convert_missing_hsts_to_pass_when_required(self):
        from scripts import transport_acceptance as module

        def fake(_base, path, _timeout):
            if path == "/health/live":
                return {
                    "status": 200,
                    "headers": {
                        "x-content-type-options": "nosniff",
                        "x-frame-options": "DENY",
                        "referrer-policy": "same-origin",
                    },
                    "body": json.dumps({"ok": True, "status": "alive", "version": "0.56.0"}).encode(),
                    "error": None,
                }
            if path == "/service-worker.js":
                return {"status": 200, "headers": {"service-worker-allowed": "/", "cache-control": "no-store"}, "body": b"SKIP_WAITING", "error": None}
            return {"status": 200, "headers": {}, "body": json.dumps({"display": "standalone", "start_url": "/", "icons": [{}, {}]}).encode(), "error": None}

        with patch.object(module, "_fetch", side_effect=fake):
            result = module.probe_local("https://zen.example.net/", require_hsts=True)
        self.assertEqual("fail", result["state"])
        hsts = next(row for row in result["checks"] if row["key"] == "hsts")
        self.assertEqual("fail", hsts["state"])


class SecureTransportCommissioningSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.main = (ROOT / "app/main.py").read_text()
        cls.secure = (ROOT / "app/secure_transport.py").read_text()
        cls.template = (ROOT / "app/templates/index.html").read_text()
        cls.compose = (ROOT / "docker-compose.yml").read_text()
        cls.env = (ROOT / ".env.example").read_text()
        cls.validator = (ROOT / "scripts/env_validate.py").read_text()
        cls.acceptance = (ROOT / "scripts/transport_acceptance.py").read_text()
        cls.release = (ROOT / "app/release_readiness.py").read_text()

    def test_release_identity_and_pwa_assets_are_v0560(self):
        self.assertIn('version="0.56.0"', self.main)
        self.assertIn('PWA_RELEASE = "0.56.0"', (ROOT / "app/pwa.py").read_text())
        self.assertIn("const RELEASE = '0.56.0'", (ROOT / "app/static/pwa.js").read_text())
        self.assertIn("const RELEASE = '0.56.0'", (ROOT / "app/static/service-worker.js").read_text())

    def test_app_receives_only_non_secret_local_https_identity(self):
        self.assertIn('ZEN_LOCAL_HOST: "${ZEN_LOCAL_HOST}"', self.compose)
        self.assertIn('ZEN_LAN_BIND_IP: "${ZEN_LAN_BIND_IP}"', self.compose)
        app_service = self.compose.split("  cloudflared:", 1)[0]
        self.assertNotIn("CADDY_CF_API_TOKEN:", app_service)

    def test_transport_api_and_pwa_api_expose_sanitized_commissioning_state(self):
        self.assertIn('"schema": "zen_secure_transport_v2"', self.secure)
        self.assertIn('"secure_transport": {', self.main)
        self.assertIn('"secure_origin_configured"', self.main)
        self.assertNotIn("CADDY_CF_API_TOKEN", self.secure)
        self.assertNotIn("CLOUDFLARE_TUNNEL_TOKEN", self.secure)

    def test_operations_and_pwa_ui_show_commissioning_state(self):
        self.assertIn("Secure transport &amp; PWA commissioning", self.template)
        self.assertIn("Local HTTPS:", self.template)
        self.assertIn("PWA server prerequisite", self.template)
        self.assertIn("Server secure-origin prerequisite", self.template)

    def test_environment_gate_prevents_secure_cookie_host_lockout(self):
        self.assertIn("ZEN_SECURE_COOKIES=1 requires ZEN_ALLOWED_HOSTS", self.validator)
        self.assertIn("ZEN_ALLOWED_HOSTS to cover ZEN_LOCAL_HOST", self.validator)
        self.assertIn("ZEN_ALLOWED_HOSTS to cover 127.0.0.1", self.validator)
        self.assertIn("secure-session commissioning remains incomplete", self.validator)

    def test_host_acceptance_has_no_credentials_and_reuses_public_access_probe(self):
        self.assertIn("zen_secure_transport_acceptance_v2", self.acceptance)
        self.assertIn("probe_public", self.acceptance)
        self.assertIn("service-worker.js", self.acceptance)
        self.assertIn("manifest.webmanifest", self.acceptance)
        for forbidden in ("password", "token=", "Authorization"):
            self.assertNotIn(forbidden, self.acceptance)

    def test_secure_transport_remains_post_core_and_non_authoritative(self):
        self.assertIn('"key": "https_remote_access"', self.release)
        self.assertIn("does not alter the core PASS/PENDING/FAIL count", self.release)
        self.assertNotIn("RouterOSAdapter", self.secure)
        self.assertIn("no RouterOS", self.acceptance)


if __name__ == "__main__":
    unittest.main()
