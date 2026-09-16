import io
import json
import re
import unittest
import zipfile
from collections import Counter
from pathlib import Path

from app.support_bundle import (
    COMMISSIONING_SCHEMA,
    SUPPORT_BUNDLE_SCHEMA,
    SUPPORT_RELEASE,
    audit_event_summary,
    build_commissioning_report,
    build_support_bundle,
    commissioning_summary,
    environment_presence,
    sanitize_support_payload,
)


ROOT = Path(__file__).resolve().parents[1]


def diagnostics_with(**states):
    defaults = {
        "application": "healthy",
        "policy_database": "healthy",
        "routeros_api": "healthy",
        "security_authority": "healthy",
        "managed_inventory": "healthy",
        "service_contracts": "healthy",
        "telemetry": "healthy",
        "traffic_ingest": "healthy",
        "dns_source": "healthy",
        "ipfix_source": "healthy",
        "classifier_consumer": "healthy",
        "reconciler": "healthy",
        "incidents": "healthy",
        "summary_delivery": "healthy",
        "durable_evidence": "healthy",
    }
    defaults.update(states)
    return {
        "schema": "zen_operational_diagnostics_v1",
        "overall": "healthy",
        "checks": [
            {"key": key, "label": key.replace("_", " ").title(), "state": state, "summary": f"{key} {state}", "facts": {}}
            for key, state in defaults.items()
        ],
    }


def commissioning(**diag_states):
    return build_commissioning_report(
        version="0.59.0",
        diagnostics=diagnostics_with(**diag_states),
        runtime_health={"ok": True, "status": "healthy", "background_read_models": {"failed_latest": 0, "retrying_latest": 0}},
        operations={"ok": True, "issues": []},
        secure_transport={
            "commissioning_ready": True,
            "state": "ready_for_live_validation",
            "local_https": {"configured": True, "state": "ready_for_live_validation"},
            "pwa": {"secure_origin_configured": True},
        },
        pwa={"mode": "online_first"},
        push={"worker_running": True, "subscriptions": {"enabled": 1}},
    )


class CommissioningSemanticsTests(unittest.TestCase):
    def test_all_required_evidence_passes_and_optional_push_can_be_not_configured(self):
        report = build_commissioning_report(
            version="0.59.0",
            diagnostics=diagnostics_with(),
            runtime_health={"ok": True, "status": "healthy", "background_read_models": {}},
            operations={"ok": True, "issues": []},
            secure_transport={"commissioning_ready": False, "state": "blocked", "local_https": {"configured": False}, "pwa": {}},
            pwa={"mode": "online_first"},
            push={"worker_running": True, "subscriptions": {"enabled": 0}},
        )
        self.assertEqual(report["schema"], COMMISSIONING_SCHEMA)
        self.assertEqual(report["release"], SUPPORT_RELEASE)
        self.assertEqual(report["overall"], "ready")
        self.assertGreaterEqual(report["counts"]["not_configured"], 2)
        self.assertFalse(any(row["required"] and row["state"] != "pass" for row in report["checks"]))

    def test_required_security_failure_blocks_but_optional_telemetry_outage_is_warning(self):
        blocked = commissioning(security_authority="critical")
        self.assertEqual(blocked["overall"], "blocked")
        security = next(row for row in blocked["checks"] if row["key"] == "security_authority")
        self.assertEqual(security["state"], "blocked")

        optional = commissioning(telemetry="offline", traffic_ingest="offline", dns_source="offline", ipfix_source="offline")
        self.assertEqual(optional["overall"], "ready_with_warnings")
        telemetry = next(row for row in optional["checks"] if row["key"] == "telemetry")
        self.assertEqual(telemetry["state"], "unavailable")
        self.assertFalse(telemetry["required"])

    def test_missing_required_evidence_is_unavailable_not_pass(self):
        diag = diagnostics_with()
        diag["checks"] = [row for row in diag["checks"] if row["key"] != "routeros_api"]
        report = build_commissioning_report(
            version="0.59.0", diagnostics=diag,
            runtime_health={"ok": True, "status": "healthy", "background_read_models": {}},
            operations={"ok": True, "issues": []},
            secure_transport={"commissioning_ready": False, "local_https": {}, "pwa": {}},
            pwa={}, push={"worker_running": True, "subscriptions": {}},
        )
        row = next(item for item in report["checks"] if item["key"] == "routeros_api")
        self.assertEqual(row["state"], "unavailable")
        self.assertEqual(report["overall"], "blocked")


class SupportBundlePrivacyTests(unittest.TestCase):
    def test_defence_in_depth_sanitizer_removes_hostile_values(self):
        counters = Counter()
        hostile = {
            "password": "hunter2",
            "token": "tok_123",
            "endpoint": "https://push.example/sub/secret",
            "host": "router.home.example",
            "ip_address": "192.0.2.26",
            "detail": "password=hunter2 token=tok_123 user@example.com aa:bb:cc:dd:ee:ff 192.0.2.26 https://x.invalid/path?token=oops",
            "safe": "worker healthy",
        }
        cleaned = sanitize_support_payload(hostile, counters=counters)
        dumped = json.dumps(cleaned)
        for secret in ("hunter2", "tok_123", "push.example/sub/secret", "router.home.example", "192.0.2.26", "user@example.com", "aa:bb:cc:dd:ee:ff", "token=oops"):
            self.assertNotIn(secret, dumped)
        self.assertIn("worker healthy", dumped)
        self.assertGreater(counters["secret_fields"], 0)
        self.assertGreater(counters["identity_fields"], 0)
        self.assertGreater(counters["ip_addresses"], 0)

    def test_zip_bundle_contains_only_expected_sanitized_evidence(self):
        report = commissioning()
        hostile_diag = diagnostics_with()
        hostile_diag["checks"][0]["facts"] = {
            "ip": "192.0.2.90",
            "detail": "password=leak-me",
            "endpoint": "https://push.invalid/subscription/abc",
        }
        data, manifest = build_support_bundle(
            version="0.59.0",
            commissioning=report,
            diagnostics=hostile_diag,
            runtime_health={"ok": True, "status": "healthy", "router": {"host": "192.0.2.1"}},
            secure_transport={"local_host": "zen.private.example", "lan_bind_ip": "192.0.2.10", "url": "https://zen.private.example/?token=abc"},
            pwa={"mode": "online_first", "endpoint": "https://push.invalid/secret"},
            environment={"groups": {"routeros": {"configured_fields": 4, "expected_fields": 4}}},
            audit_summary={"events": {"LOGIN_SUCCESS": 2}},
        )
        self.assertEqual(manifest["schema"], SUPPORT_BUNDLE_SCHEMA)
        self.assertTrue(manifest["privacy"]["safe_for_public_issue_by_design"])
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            names = set(archive.namelist())
            self.assertEqual(names, set(manifest["files"]))
            combined = "\n".join(archive.read(name).decode("utf-8") for name in names)
        for secret in ("leak-me", "192.0.2.90", "192.0.2.1", "192.0.2.10", "zen.private.example", "push.invalid/subscription/abc", "push.invalid/secret", "token=abc"):
            self.assertNotIn(secret, combined)
        self.assertIn("raw Docker/application logs", combined)
        self.assertIn("ZEN Control Commissioning", combined)

    def test_environment_and_audit_summaries_never_emit_values_or_details(self):
        env = environment_presence({
            "ADMIN_USER": "private-admin",
            "ADMIN_PASSWORD": "super-secret",
            "SESSION_SECRET": "session-secret",
            "MIKROTIK_HOST": "192.0.2.1",
            "MIKROTIK_PORT": "8728",
            "MIKROTIK_USER": "router-admin",
            "MIKROTIK_PASSWORD": "router-secret",
        })
        audits = audit_event_summary([
            {"event": "LOGIN_SUCCESS", "actor": "private-admin", "detail": "192.0.2.26 password=oops", "severity": "info"},
            {"event": "LOGIN_SUCCESS", "actor": "someone", "detail": "secret", "severity": "info"},
        ])
        dumped = json.dumps({"env": env, "audits": audits})
        for value in ("private-admin", "super-secret", "session-secret", "192.0.2.1", "router-admin", "router-secret", "192.0.2.26", "password=oops"):
            self.assertNotIn(value, dumped)
        self.assertEqual(audits["events"]["LOGIN_SUCCESS"], 2)
        self.assertEqual(env["groups"]["routeros"]["configured_fields"], 4)

    def test_text_summary_is_human_readable_and_contains_remediation_not_secrets(self):
        report = commissioning(routeros_api="offline")
        text = commissioning_summary(report)
        self.assertIn("ZEN Control Commissioning", text)
        self.assertIn("Overall: BLOCKED", text)
        self.assertIn("Actions:", text)
        self.assertIn("RouterOS connectivity", text)
        self.assertNotRegex(text, r"password=|token=|192\.168\.")


class SupportBundleIntegrationContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.main = (ROOT / "app/main.py").read_text()
        cls.module = (ROOT / "app/support_bundle.py").read_text()
        cls.cli = (ROOT / "app/support_cli.py").read_text()
        cls.template = (ROOT / "app/templates/diagnostics.html").read_text()
        cls.index = (ROOT / "app/templates/index.html").read_text()
        cls.help = (ROOT / "app/help_content.py").read_text()
        cls.readme = (ROOT / "README.md").read_text()
        cls.changelog = (ROOT / "CHANGELOG.md").read_text()

    def test_routes_ui_cli_and_release_marker_are_wired(self):
        for token in (
            '@app.get("/api/operations/commissioning")',
            '@app.get("/local/operations/support-summary")',
            '@app.get("/local/operations/support-bundle")',
            'media_type="application/zip"',
            'SUPPORT_BUNDLE_EXPORTED',
        ):
            self.assertIn(token, self.main)
        self.assertIn("Download support bundle", self.template)
        self.assertIn("Copy support summary", self.template)
        self.assertIn("Support bundle", self.index)
        self.assertIn("python -m app.support_cli", self.readme)
        self.assertIn("127.0.0.1", self.cli)
        self.assertRegex(self.readme, r"Current maintenance release: \*\*v0\.59\.0\.\d+\*\*")
        self.assertIn("## v0.59.0.10 — Sanitized Support Bundle & Commissioning Diagnostics", self.changelog)
        self.assertIn("PASS / WARN / BLOCKED / UNAVAILABLE", self.help)

    def test_support_module_has_no_routeros_mutation_authority(self):
        forbidden = (
            "set_global_mode(", "set_device_mode(", "set_device_services(",
            "add_restricted_device(", "remove_restricted_device(",
            "mutation_session(", "coherent_router_mutation",
        )
        for token in forbidden:
            self.assertNotIn(token, self.module)
        self.assertIn("read_only_no_routeros_write_authority", self.module)
        self.assertIn("raw Docker/application logs", self.module)


if __name__ == "__main__":
    unittest.main()
