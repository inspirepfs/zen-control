from pathlib import Path
import unittest

from app.ux import build_connected_overview, audit_destination, incident_destination


ROOT = Path(__file__).resolve().parents[1]


class ConnectedOverviewTests(unittest.TestCase):
    def _overview(self, **overrides):
        args = {
            "live_status": {"mode": "NORMAL"},
            "devices": [{"ip": "192.0.2.10"}, {"ip": "192.0.2.11"}],
            "policy_plans": {
                "192.0.2.10": {"status": "in_sync", "quota_state": {"active": False}},
                "192.0.2.11": {"status": "in_sync", "quota_state": {"active": False}},
            },
            "security_posture": {
                "enforcement_ready": True,
                "score": 100,
                "critical_count": 0,
                "warning_count": 0,
            },
            "reconciler_status": {"mode": "enforce", "worker_alive": True, "hold_active": False},
            "service_contract_health": {
                "available": True,
                "healthy": 12,
                "total": 12,
                "degraded": 0,
                "reporting_only": 1,
                "detector_addresses": 25,
            },
            "telemetry_available": True,
            "activity_insights": {
                "managed_devices_seen": 2,
                "traffic_classified_percent": 92.4,
                "dns_classified_percent": 88.1,
                "unknown_domains": 7,
            },
            "database_integrity": {"ok": True},
            "operations_startup": {"status": "ready"},
            "incident_counts": {"active": 0, "resolved": 4},
            "audit_total": 321,
        }
        args.update(overrides)
        return build_connected_overview(**args)

    def test_healthy_state_connects_all_five_product_areas(self):
        result = self._overview()
        self.assertEqual("healthy", result["state"])
        self.assertEqual(5, len(result["areas"]))
        self.assertEqual(5, result["counts"]["healthy"])
        self.assertEqual(
            ["control", "security", "services", "activity", "operations"],
            [row["key"] for row in result["areas"]],
        )

    def test_policy_drift_is_warning_and_counts_actionable_devices(self):
        result = self._overview(
            policy_plans={
                "192.0.2.10": {"status": "drift", "policy_actionable": True, "quota_state": {"active": True}},
                "192.0.2.11": {"status": "temporary", "quota_state": {"active": False}},
            }
        )
        control = result["areas"][0]
        self.assertEqual("warning", control["state"])
        self.assertEqual(1, result["device_counts"]["drift"])
        self.assertEqual(1, result["device_counts"]["actionable"])
        self.assertEqual(1, result["device_counts"]["temporary"])
        self.assertEqual(1, result["device_counts"]["quota_active"])

    def test_security_write_gate_closed_is_critical(self):
        result = self._overview(
            security_posture={
                "enforcement_ready": False,
                "score": 72,
                "critical_count": 1,
                "warning_count": 2,
            }
        )
        security = next(row for row in result["areas"] if row["key"] == "security")
        self.assertEqual("critical", result["state"])
        self.assertEqual("critical", security["state"])
        self.assertIn("CLOSED", security["headline"])

    def test_telemetry_loss_is_offline_and_never_invents_zero_coverage(self):
        result = self._overview(telemetry_available=False, activity_insights={})
        activity = next(row for row in result["areas"] if row["key"] == "activity")
        self.assertEqual("offline", result["state"])
        self.assertEqual("offline", activity["state"])
        self.assertIn("classification unavailable", activity["facts"])
        self.assertNotIn("traffic 0.0% classified", activity["facts"])

    def test_database_failure_is_critical_operations_state(self):
        result = self._overview(database_integrity={"ok": False})
        operations = next(row for row in result["areas"] if row["key"] == "operations")
        self.assertEqual("critical", operations["state"])
        self.assertIn("FAILED", operations["headline"])


class ContextDestinationTests(unittest.TestCase):
    def test_audit_events_route_back_to_owning_feature(self):
        self.assertEqual("/?view=settings&section=parents#settings/parents", audit_destination("TOTP_DEVICE_ENROLLED")["href"])
        self.assertEqual("/?view=policies&section=services#policies/services", audit_destination("CUSTOM_SERVICE_PROVISIONED")["href"])
        self.assertEqual("/?view=incidents&section=active#incidents/active", audit_destination("INCIDENT_OPENED")["href"])
        self.assertEqual("/?view=settings&section=operations#settings/operations", audit_destination("CONFIG_IMPORTED")["href"])
        self.assertIsNone(audit_destination("SOMETHING_UNKNOWN"))

    def test_incident_sources_route_to_evidence_owner(self):
        self.assertEqual("/?view=settings&section=security#settings/security", incident_destination("security")["href"])
        self.assertEqual("/?view=settings&section=automation#settings/automation", incident_destination("reconciler")["href"])
        self.assertEqual("/?view=activity&section=overview#activity/overview", incident_destination("activity")["href"])
        self.assertEqual("/?view=incidents&section=active#incidents/active", incident_destination("unknown")["href"])


class UxIntegrationSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.main = (ROOT / "app/main.py").read_text()
        cls.index = (ROOT / "app/templates/index.html").read_text()
        cls.policy_summary = (ROOT / "app/templates/policy_summary.html").read_text()
        cls.activity_device = (ROOT / "app/templates/activity_device.html").read_text()
        cls.activity_service = (ROOT / "app/templates/activity_service.html").read_text()
        cls.layout = (ROOT / "app/static/layout.css").read_text()

    def test_release_is_v026_and_assets_are_cache_busted(self):
        self.assertIn('version="0.54.0"', self.main)
        self.assertIn('/static/app.css?v=0.54.0', self.index)
        self.assertNotIn('v=0.26.0', self.index)

    def test_dashboard_has_connected_health_and_exact_drilldowns(self):
        self.assertIn('Connected system health', self.index)
        self.assertIn('connected_overview.areas', self.index)
        ux = (ROOT / "app/ux.py").read_text()
        self.assertIn('/?view=devices&section=managed#devices/managed', ux)
        self.assertIn('/?view=policies&section=assignments#policies/assignments', ux)
        self.assertIn('/?view=settings&section=security#settings/security', ux)
        self.assertIn('/?view=settings&section=operations#settings/operations', ux)

    def test_context_focus_hooks_exist_for_devices_assignments_and_services(self):
        self.assertIn('data-ux-focus="device:{{d.ip}}"', self.index)
        self.assertIn('data-ux-focus="assignment:{{d.ip}}"', self.index)
        self.assertIn('data-ux-focus="service:{{svc.key}}"', self.index)
        self.assertIn("focusNode.scrollIntoView", self.index)
        self.assertIn('.context-focus', self.layout)

    def test_post_actions_return_to_exact_subsections(self):
        for fragment in (
            '/?view=dashboard&section=controls#dashboard/controls',
            '/?view=devices&section=managed#devices/managed',
            '/?view=devices&section=bulk#devices/bulk',
            '/?view=policies&section=profiles#policies/profiles',
            '/?view=policies&section=assignments#policies/assignments',
            '/?view=policies&section=bandwidth#policies/bandwidth',
            '/?view=policies&section=services#policies/services',
            'settings/operations',
            'settings/automation',
            'settings/security',
            'schedules/planner',
            'schedules/templates',
            'schedules/exceptions',
            'schedules/router',
        ):
            self.assertIn(fragment, self.main)
        self.assertNotIn('RedirectResponse("/#policy-studio"', self.main)

    def test_activity_drilldowns_connect_back_to_control_plane(self):
        self.assertIn('Back to Activity', self.activity_device)
        self.assertIn('Device 360', self.activity_device)
        self.assertIn('Policy', self.activity_device)
        self.assertIn('Policy definition', self.activity_service)
        self.assertIn('focus=service:{{service.key}}#policies/services', self.activity_service)

    def test_policy_summary_connects_each_device_to_policy_and_activity(self):
        self.assertIn('focus=device:{{row.ip}}#devices/managed', self.policy_summary)
        self.assertIn('focus=assignment:{{row.ip}}#policies/assignments', self.policy_summary)
        self.assertIn('/activity/device/{{row.ip}}', self.policy_summary)

    def test_audit_is_searchable_and_context_aware(self):
        self.assertIn('id="auditFilter"', self.index)
        self.assertIn('data-audit-search=', self.index)
        self.assertIn('a.context_link', self.index)
        self.assertIn('/api/audit?limit=500', self.index)

    def test_stale_user_facing_brand_is_removed(self):
        templates = "\n".join(path.read_text() for path in (ROOT / "app/templates").glob("*.html"))
        self.assertNotIn("MIKROTIK CONTROL · ACTIVITY", templates)
        self.assertNotIn("No MikroTik Control schedules yet.", templates)
        self.assertIn("ZEN CONTROL · ACTIVITY", self.activity_device)


if __name__ == "__main__":
    unittest.main()
