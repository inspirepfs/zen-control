import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


class SecureTransportConfigTests(unittest.TestCase):
    def config(self, **overrides):
        from app.secure_transport import SecureTransportConfig

        values = {
            "ZEN_REMOTE_ACCESS_ENABLED": "0",
            "ZEN_SECURE_COOKIES": "0",
            "ZEN_PUBLIC_HOST": "",
            "ZEN_ALLOWED_HOSTS": "",
            "ZEN_CLOUDFLARE_ACCESS_PROTECTED": "0",
            "ZEN_HSTS_MAX_AGE": "31536000",
        }
        values.update(overrides)
        return SecureTransportConfig.from_mapping(values)

    def test_local_default_is_non_disruptive_and_not_falsely_remote_ready(self):
        cfg = self.config()
        status = cfg.status("0.55.2")
        self.assertFalse(cfg.remote_access_enabled)
        self.assertFalse(cfg.secure_cookies)
        self.assertEqual(status["state"], "disabled")
        self.assertFalse(status["remote_ready"])
        self.assertEqual(status["live_external_validation"], "not_run")

    def test_remote_ready_requires_public_host_secure_cookie_access_and_host_allowlist(self):
        cfg = self.config(
            ZEN_REMOTE_ACCESS_ENABLED="1",
            ZEN_SECURE_COOKIES="1",
            ZEN_PUBLIC_HOST="zen.example.net",
            ZEN_ALLOWED_HOSTS="zen.example.net,localhost,127.0.0.1",
            ZEN_CLOUDFLARE_ACCESS_PROTECTED="1",
        )
        status = cfg.status("0.55.2")
        self.assertEqual(status["state"], "ready_for_live_validation")
        self.assertTrue(status["remote_ready"])
        self.assertEqual({item["state"] for item in status["checks"]}, {"pass"})
        self.assertEqual(status["live_external_validation"], "pending")

    def test_remote_mode_fails_closed_when_secure_cookie_is_not_enabled(self):
        cfg = self.config(
            ZEN_REMOTE_ACCESS_ENABLED="1",
            ZEN_PUBLIC_HOST="zen.example.net",
            ZEN_ALLOWED_HOSTS="zen.example.net",
            ZEN_CLOUDFLARE_ACCESS_PROTECTED="1",
        )
        status = cfg.status("0.55.2")
        self.assertEqual(status["state"], "blocked")
        self.assertFalse(status["remote_ready"])
        failed = {item["key"] for item in status["checks"] if item["state"] == "fail"}
        self.assertIn("secure_cookie", failed)

    def test_remote_mode_requires_operator_confirmation_of_access_protection(self):
        cfg = self.config(
            ZEN_REMOTE_ACCESS_ENABLED="1",
            ZEN_SECURE_COOKIES="1",
            ZEN_PUBLIC_HOST="zen.example.net",
            ZEN_ALLOWED_HOSTS="zen.example.net",
        )
        status = cfg.status("0.55.2")
        failed = {item["key"] for item in status["checks"] if item["state"] == "fail"}
        self.assertIn("cloudflare_access", failed)
        self.assertFalse(status["remote_ready"])

    def test_public_host_rejects_scheme_path_port_and_wildcard(self):
        from app.secure_transport import SecureTransportConfigError

        for value in ("https://zen.example.net", "zen.example.net/path", "zen.example.net:443", "*.example.net"):
            with self.subTest(value=value):
                with self.assertRaises(SecureTransportConfigError):
                    self.config(ZEN_PUBLIC_HOST=value)

    def test_allowed_hosts_normalize_and_public_host_must_be_covered(self):
        cfg = self.config(
            ZEN_REMOTE_ACCESS_ENABLED="1",
            ZEN_SECURE_COOKIES="1",
            ZEN_PUBLIC_HOST="zen.example.net",
            ZEN_ALLOWED_HOSTS=" LOCALHOST,*.internal.example.net ",
            ZEN_CLOUDFLARE_ACCESS_PROTECTED="1",
        )
        self.assertEqual(cfg.allowed_hosts, ("localhost", "*.internal.example.net"))
        self.assertFalse(cfg.status("0.55.2")["remote_ready"])

    def test_wildcard_all_hosts_is_not_accepted_for_remote_access(self):
        cfg = self.config(
            ZEN_REMOTE_ACCESS_ENABLED="1",
            ZEN_SECURE_COOKIES="1",
            ZEN_PUBLIC_HOST="zen.example.net",
            ZEN_ALLOWED_HOSTS="*",
            ZEN_CLOUDFLARE_ACCESS_PROTECTED="1",
        )
        status = cfg.status("0.55.2")
        failed = {item["key"] for item in status["checks"] if item["state"] == "fail"}
        self.assertIn("host_allowlist", failed)

    def test_security_headers_are_bounded_and_hsts_only_for_remote_secure_mode(self):
        from app.secure_transport import security_headers

        local = security_headers(self.config())
        self.assertNotIn("Strict-Transport-Security", local)
        self.assertEqual(local["X-Content-Type-Options"], "nosniff")
        self.assertEqual(local["X-Frame-Options"], "DENY")

        remote = self.config(
            ZEN_REMOTE_ACCESS_ENABLED="1",
            ZEN_SECURE_COOKIES="1",
            ZEN_PUBLIC_HOST="zen.example.net",
            ZEN_ALLOWED_HOSTS="zen.example.net",
            ZEN_CLOUDFLARE_ACCESS_PROTECTED="1",
            ZEN_HSTS_MAX_AGE="86400",
        )
        self.assertEqual(security_headers(remote)["Strict-Transport-Security"], "max-age=86400")

    def test_hsts_range_is_bounded(self):
        from app.secure_transport import SecureTransportConfigError

        with self.assertRaises(SecureTransportConfigError):
            self.config(ZEN_HSTS_MAX_AGE="999999999")
        with self.assertRaises(SecureTransportConfigError):
            self.config(ZEN_HSTS_MAX_AGE="-1")


class SecureTransportSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.main = (ROOT / "app/main.py").read_text()
        cls.compose = (ROOT / "docker-compose.yml").read_text()
        cls.readme = (ROOT / "README.md").read_text() + "\n" + (ROOT / "CHANGELOG.md").read_text()
        cls.release = (ROOT / "app/release_readiness.py").read_text()
        cls.index = (ROOT / "app/templates/index.html").read_text()
        cls.env_example = (ROOT / ".env.example").read_text()
        cls.script = (ROOT / "scripts/https_acceptance.py").read_text()

    def test_release_version_and_assets_are_current(self):
        self.assertIn('version="0.55.3.1"', self.main)
        self.assertIn('/static/app.css?v=0.55.3.1', self.index)
        self.assertIn("v0.55.2", self.readme)

    def test_session_secure_flag_is_configuration_driven(self):
        self.assertIn("https_only=SECURE_TRANSPORT.secure_cookies", self.main)
        self.assertNotIn("https_only=False", self.main)

    def test_trusted_host_middleware_is_enabled_only_for_explicit_allowlist(self):
        self.assertIn("TrustedHostMiddleware", self.main)
        self.assertIn("SECURE_TRANSPORT.enforce_host_allowlist", self.main)
        self.assertNotIn('allowed_hosts=["*"]', self.main)

    def test_transport_api_and_operations_ui_are_authenticated_and_visible(self):
        self.assertIn('@app.get("/api/security/transport")', self.main)
        self.assertIn('Depends(require_role("admin", "operator", "viewer"))', self.main)
        self.assertIn("Secure transport &amp; remote access", self.index)
        self.assertIn("/api/security/transport", self.index)

    def test_response_security_headers_are_applied_without_csp_feature_creep(self):
        self.assertIn("security_headers(SECURE_TRANSPORT)", self.main)
        self.assertNotIn("Content-Security-Policy", self.main)

    def test_cloudflared_is_profile_gated_pinned_and_has_no_published_ports(self):
        import yaml

        model = yaml.safe_load(self.compose)
        service = model["services"]["cloudflared"]
        self.assertEqual(service["image"], "cloudflare/cloudflared:2026.9.0")
        self.assertIn("remote-access", service["profiles"])
        self.assertNotIn("ports", service)
        self.assertTrue(service.get("read_only"))
        self.assertIn("ALL", service.get("cap_drop", []))
        self.assertIn("no-new-privileges:true", service.get("security_opt", []))

    def test_cloudflared_uses_token_file_secret_not_command_line_token(self):
        import yaml

        model = yaml.safe_load(self.compose)
        service = model["services"]["cloudflared"]
        command_text = " ".join(str(item) for item in service["command"])
        self.assertNotIn("--token", command_text)
        self.assertEqual(service["environment"]["TUNNEL_TOKEN_FILE"], "/run/secrets/cloudflare_tunnel_token")
        self.assertIn("cloudflare_tunnel_token", model.get("secrets", {}))
        self.assertNotIn("CLOUDFLARE_TUNNEL_TOKEN}", self.compose)

    def test_remote_access_settings_are_environment_only_and_default_off(self):
        self.assertIn('ZEN_REMOTE_ACCESS_ENABLED: "${ZEN_REMOTE_ACCESS_ENABLED:-0}"', self.compose)
        self.assertIn('ZEN_SECURE_COOKIES: "${ZEN_SECURE_COOKIES:-0}"', self.compose)
        self.assertIn("ZEN_CLOUDFLARE_ACCESS_PROTECTED", self.compose)
        self.assertIn("ZEN_REMOTE_ACCESS_ENABLED=0", self.env_example)
        self.assertIn("CLOUDFLARE_TUNNEL_TOKEN_FILE=", self.env_example)

    def test_remote_access_does_not_change_routeros_or_performance_authority(self):
        self.assertNotIn("cloudflared", (ROOT / "app/router.py").read_text().lower())
        self.assertNotIn("cloudflare", (ROOT / "app/reconciler.py").read_text().lower())
        self.assertNotIn("cloudflare", (ROOT / "app/performance.py").read_text().lower())

    def test_release_readiness_keeps_https_post_core_and_notification_centre_non_authoritative(self):
        self.assertIn('"https_remote_access"', self.release)
        self.assertNotIn('"key": "notifications"', self.release)
        self.assertIn("Notification Centre is an implemented read-side attention capability", self.release)
        self.assertIn("secure_transport", self.release)
        self.assertIn("does not alter the core PASS/PENDING/FAIL count", self.release)

    def test_https_acceptance_probe_never_accepts_public_200_without_access(self):
        self.assertIn("public_origin_bypassed_access", self.script)
        self.assertIn("cloudflareaccess.com", self.script)
        self.assertIn("zen_https_acceptance_v1", self.script)

    def test_documentation_requires_access_before_published_route_and_protect_with_access(self):
        self.assertIn("Create the Access application before the published Tunnel route", self.readme)
        self.assertIn("Protect with Access", self.readme)
        self.assertIn("http://mikrotik-control:8080", self.readme)
        self.assertIn("authenticated browser sessions must use the HTTPS hostname", self.readme)

    def test_no_tunnel_token_or_access_identity_is_exported_by_transport_status(self):
        from app.secure_transport import SecureTransportConfig

        cfg = SecureTransportConfig.from_mapping({
            "ZEN_REMOTE_ACCESS_ENABLED": "1",
            "ZEN_SECURE_COOKIES": "1",
            "ZEN_PUBLIC_HOST": "zen.example.net",
            "ZEN_ALLOWED_HOSTS": "zen.example.net",
            "ZEN_CLOUDFLARE_ACCESS_PROTECTED": "1",
            "CLOUDFLARE_TUNNEL_TOKEN": "must-not-leak",
            "CLOUDFLARE_TUNNEL_TOKEN_FILE": "/secret/location",
        })
        rendered = repr(cfg.status("0.55.2"))
        self.assertNotIn("must-not-leak", rendered)
        self.assertNotIn("/secret/location", rendered)


class HttpsAcceptanceProbeTests(unittest.TestCase):
    def classify(self, **kwargs):
        from scripts.https_acceptance import classify_public_response
        values = {
            "url": "https://zen.example.net/",
            "status": 302,
            "location": "https://team.cloudflareaccess.com/cdn-cgi/access/login/zen.example.net",
            "headers": {"cf-ray": "abc-LHR"},
        }
        values.update(kwargs)
        return classify_public_response(**values)

    def test_access_login_redirect_is_pass(self):
        result = self.classify()
        self.assertEqual(result, {"state": "pass", "reason": "cloudflare_access_challenge_seen"})

    def test_anonymous_public_200_is_hard_fail(self):
        result = self.classify(status=200, location="", headers={"cf-ray": "abc-LHR"})
        self.assertEqual(result["state"], "fail")
        self.assertEqual(result["reason"], "public_origin_bypassed_access")

    def test_generic_cloudflare_forbidden_is_pending_not_false_access_pass(self):
        result = self.classify(status=403, location="", headers={"cf-ray": "abc-LHR"})
        self.assertEqual(result["state"], "pending")

    def test_plain_http_url_is_never_accepted(self):
        result = self.classify(url="http://zen.example.net/", status=302)
        self.assertEqual(result["state"], "fail")
        self.assertEqual(result["reason"], "public_url_is_not_https")


class PostCoreReadinessSeparationTests(unittest.TestCase):
    def report(self, transport):
        from app.release_readiness import build_release_readiness
        return build_release_readiness(
            version="0.55.3.1",
            operations={"ok": True, "issues": []},
            startup={"status": "ready", "issues": []},
            diagnostics={"overall": "healthy", "counts": {"healthy": 15, "warning": 0, "critical": 0, "offline": 0}, "checks": []},
            performance={
                "acceptance": {"schema": "zen_performance_acceptance_v2", "state": "pass", "targets": [], "min_samples": 5},
                "formal_acceptance": {"schema": "zen_formal_performance_acceptance_v1", "state": "pass", "request_state": "pass", "evidence_targets": []},
            },
            config_smoke={"state": "pass", "non_destructive": True, "source_digest": "x", "restored_digest": "x", "summary": "ok"},
            restart={"state": "pass", "controlled_stop_seen": True, "current_release_start_seen": True, "summary": "ok"},
            auth={"available": True, "shared_display_mode": True, "totp_count": 1, "login_mode": "password_or_totp", "recovery_codes_remaining": 5},
            pwa={"mode": "online_first", "cached_private_data": False, "offline_mutations": False, "background_sync": False, "push_notifications": False, "server_auth_required": True, "shared_display_lock_server_enforced": True},
            runtime_health={"schema": "zen_runtime_health_v1", "ok": True, "status": "healthy"},
            secure_transport=transport,
        )

    def test_transport_ready_changes_post_core_status_not_core_counts(self):
        report = self.report({
            "state": "ready_for_live_validation",
            "public_host": "zen.example.net",
            "secure_cookies": True,
            "host_allowlist_enforced": True,
            "cloudflare_access_protected": True,
            "live_external_validation": "pending",
        })
        self.assertEqual(report["state"], "pass")
        self.assertEqual(report["counts"], {"pass": 8, "pending": 0, "fail": 0})
        https = next(item for item in report["deferred"] if item["key"] == "https_remote_access")
        self.assertEqual(https["state"], "ready_for_live_validation")

    def test_transport_blocked_does_not_rewrite_core_result(self):
        report = self.report({"state": "blocked", "secure_cookies": False})
        self.assertEqual(report["state"], "pass")
        self.assertEqual(report["counts"]["fail"], 0)
        https = next(item for item in report["deferred"] if item["key"] == "https_remote_access")
        self.assertEqual(https["state"], "blocked")


if __name__ == "__main__":
    unittest.main()
