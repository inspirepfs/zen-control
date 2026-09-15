import importlib.util
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
import types

sys.modules.setdefault("routeros_api", types.SimpleNamespace())

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.bypass import DOH_ROUTER_RULES
from app.router import RouterOSAdapter
from app.service_catalog import SERVICE_ENFORCEMENT


class PublicReleaseClosureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.readme = (ROOT / "README.md").read_text()
        cls.public = (ROOT / "docs/PUBLIC_RELEASE.md").read_text()
        cls.install = (ROOT / "docs/INSTALL.md").read_text()
        cls.operator = (ROOT / "docs/OPERATOR_GUIDE.md").read_text()
        cls.compose = (ROOT / "docker-compose.yml").read_text()
        cls.service_bundle = (ROOT / "routeros/setup/30-built-in-services.rsc").read_text()
        cls.doh_bundle = (ROOT / "routeros/setup/40-known-doh-hardening.rsc").read_text()

    def test_release_version_and_public_closure_label(self):
        self.assertIn('version="0.59.0"', (ROOT / "app/main.py").read_text())
        self.assertIn('PWA_RELEASE = "0.59.0"', (ROOT / "app/pwa.py").read_text())
        self.assertIn("`v0.59.0.x`", self.readme)
        self.assertIn("application/PWA reports version **0.59.0**", self.readme)

    def test_agpl_license_is_selected_not_left_as_manual_gate(self):
        license_text = (ROOT / "LICENSE").read_text()
        self.assertIn("GNU AFFERO GENERAL PUBLIC LICENSE", license_text)
        self.assertIn("Version 3, 19 November 2007", license_text)
        self.assertIn("13. Remote Network Interaction", license_text)
        self.assertIn("AGPL-3.0-or-later", self.public)
        self.assertIn("AGPL-3.0-or-later", (ROOT / "CONTRIBUTING.md").read_text())


    def test_agpl_network_users_receive_source_link(self):
        repo = "https://github.com/inspirepfs/zen-control"
        self.assertIn(repo, (ROOT / "app/templates/login.html").read_text())
        index = (ROOT / "app/templates/index.html").read_text()
        self.assertIn(repo, index)
        self.assertIn("ZEN Control source code", index)

    def test_android_pwa_manual_gate_is_explicitly_open_and_non_blocking(self):
        joined = "\n".join((self.readme, self.public, self.install, self.operator))
        self.assertIn("Android installation: **proven on at least one real device**", joined)
        self.assertIn("device-local install/reinstall diagnostics: **implemented**", joined)
        self.assertIn("representative tablet/multi-device commissioning closure: **OPEN / follow-up**", joined)
        self.assertIn("installed-PWA browser-push lifecycle", joined)
        self.assertIn("non-blocking for source publication", joined)
        self.assertNotIn("Android PWA commissioning: PASS", joined)

    def test_screenshots_are_deliberately_deferred(self):
        self.assertIn("Screenshots, if added, are real sanitized captures", self.public)
        screenshots = (ROOT / "docs/screenshots/README.md").read_text()
        self.assertIn("Screenshots are **optional post-release documentation**", screenshots)
        self.assertIn("synthetic UI imagery", screenshots)

    def test_pihole_split_dns_is_parameterized_not_literal(self):
        match = re.search(r"FTLCONF_dns_hosts:\s*\|-\s*\n\s*([^\n]+)", self.compose)
        self.assertIsNotNone(match)
        row = match.group(1).strip()
        self.assertEqual(
            "${ZEN_LAN_BIND_IP:?ZEN_LAN_BIND_IP must be set} ${ZEN_LOCAL_HOST:?ZEN_LOCAL_HOST must be set}",
            row,
        )
        self.assertNotRegex(row, r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

    def test_routeros_setup_bundle_has_all_expected_files_and_fail_closed_templates(self):
        expected = [
            "10-core-authority.template.rsc", "20-global-mode.template.rsc",
            "30-built-in-services.rsc", "40-known-doh-hardening.rsc",
            "50-fasttrack.template.rsc", "60-api-user.template.rsc",
            "70-ipfix.template.rsc", "80-local-dns.template.rsc",
            "90-dhcp-reservation.template.rsc", "99-verify.rsc",
        ]
        for name in expected:
            self.assertTrue((ROOT / "routeros/setup" / name).is_file(), name)
        for name in [item for item in expected if ".template." in item]:
            text = (ROOT / "routeros/setup" / name).read_text()
            self.assertIn(":local ZEN_SETUP_CONFIRMED false", text, name)
            self.assertIn(":if (!$ZEN_SETUP_CONFIRMED) do={ :error", text, name)

    def test_core_routeros_bundle_tracks_current_authority_constants(self):
        core = (ROOT / "routeros/setup/10-core-authority.template.rsc").read_text()
        for token in (
            RouterOSAdapter.MASTER_RULE_COMMENT,
            RouterOSAdapter.DEVICE_BLOCK_RULE_COMMENT,
            RouterOSAdapter.WEB_POLICY_COMMENT,
            RouterOSAdapter.QUIC_RULE_COMMENT,
            RouterOSAdapter.DOT_RULE_COMMENT,
            RouterOSAdapter.DOQ_RULE_COMMENT,
            "RW99 - Return",
        ):
            self.assertIn(token, core)
        mode = (ROOT / "routeros/setup/20-global-mode.template.rsc").read_text()
        self.assertIn(RouterOSAdapter.SLOW_QUEUE_NAME, mode)
        for script in RouterOSAdapter.MODE_SCRIPTS.values():
            self.assertIn(script, mode)

    def test_built_in_service_bundle_mirrors_catalogue(self):
        for key, service in SERVICE_ENFORCEMENT.items():
            with self.subTest(service=key):
                self.assertIn(service["source_list"], self.service_bundle)
                for rule in service.get("rules", []):
                    self.assertIn(rule["comment"], self.service_bundle)
                    self.assertIn(rule["detector_list"], self.service_bundle)
                for learner in service.get("learners", []):
                    self.assertIn(learner["comment"], self.service_bundle)
                    self.assertIn(learner["address_list"], self.service_bundle)
                    self.assertIn(f'tls-host="{learner["tls_host"]}"', self.service_bundle)
        self.assertIn("address-list-timeout=30m", self.service_bundle)
        self.assertIn('place-before=$rwReturn', self.service_bundle)

    def test_known_doh_bundle_mirrors_current_contract(self):
        for rule in DOH_ROUTER_RULES:
            with self.subTest(comment=rule["comment"]):
                self.assertIn(rule["comment"], self.doh_bundle)
                self.assertIn(f'tls-host="{rule["tls_host"]}"', self.doh_bundle)
        self.assertIn("NOT complete coverage", self.doh_bundle)

    def test_fasttrack_template_documents_both_required_exclusions(self):
        text = (ROOT / "routeros/setup/50-fasttrack.template.rsc").read_text()
        self.assertIn("src-address-list=!Restricted_Devices", text)
        self.assertIn("dst-address-list=!Restricted_Devices", text)
        self.assertIn("action=fasttrack-connection", text)

    def test_routeros_post_setup_verifier_is_read_only(self):
        text = (ROOT / "routeros/setup/99-verify.rsc").read_text().lower()
        executable = "\n".join(
            line for line in text.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        )
        self.assertIsNone(re.search(r"\b(?:add|set|remove|move|enable|disable)\b", executable))
        self.assertIn("print", executable)

    def test_public_release_audit_supports_history_and_deployment_markers(self):
        spec = importlib.util.spec_from_file_location("zen_public_audit", ROOT / "scripts/public_release_audit.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        args = module.parse_args(["--history", "--deployment-markers"])
        self.assertTrue(args.history)
        self.assertTrue(args.deployment_markers)

        value = "router.household.local"
        findings = module.marker_findings(
            f"prefix https://{value}:443 suffix",
            "README.md",
            {"ZEN_LOCAL_HOST": value},
        )
        self.assertEqual(findings, ["deployment-value: ZEN_LOCAL_HOST: README.md:1"])
        self.assertNotIn(value, findings[0])

        with tempfile.TemporaryDirectory() as td:
            env = Path(td) / ".env"
            env.write_text(
                "ZEN_LOCAL_HOST=router.household.local\n"
                "ZEN_PUBLIC_HOST=${ZEN_PUBLIC_HOST}\n"
                "ZEN_LAN_BIND_IP=192.0.2.44\n"
                "MIKROTIK_HOST=MIKROTIK_HOST\n"
                "SESSION_SECRET=do-not-read-this-secret-value\n"
            )
            markers = module.load_deployment_markers(env)
            self.assertEqual(markers, {"ZEN_LOCAL_HOST": "router.household.local"})
            self.assertNotIn("do-not-read-this-secret-value", repr(markers))

    def test_deployment_marker_matching_is_exact_not_prefix_or_key_name(self):
        spec = importlib.util.spec_from_file_location("zen_public_audit_exact", ROOT / "scripts/public_release_audit.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        markers = {"MIKROTIK_HOST": "192.168.50.1"}
        self.assertEqual(
            module.marker_findings(
                "hosts=192.168.50.10,192.168.50.100 MIKROTIK_HOST=${MIKROTIK_HOST}",
                "tests/example.py",
                markers,
            ),
            [],
        )
        self.assertEqual(
            module.marker_findings("host=192.168.50.1:8728", "config.txt", markers),
            ["deployment-value: MIKROTIK_HOST: config.txt:1"],
        )
        self.assertEqual(
            module.marker_findings(
                'os.environ["MIKROTIK_HOST"]\nMIKROTIK_HOST=',
                "app/config.py",
                {"MIKROTIK_HOST": "MIKROTIK_HOST"},
            ),
            [],
        )

    def test_documentation_values_and_secret_values_are_never_deployment_markers(self):
        spec = importlib.util.spec_from_file_location("zen_public_audit_examples", ROOT / "scripts/public_release_audit.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        for value in ("zen.example.com", "192.0.2.12", "198.51.100.8", "203.0.113.9", "2001:db8::12"):
            with self.subTest(value=value):
                self.assertFalse(module._deployment_marker_value_is_concrete("ZEN_LOCAL_HOST", value))

        secret = "super-secret-value-that-must-not-be-printed"
        findings = module.secret_findings(f"SESSION_SECRET={secret}\n", ".env")
        self.assertTrue(findings)
        self.assertTrue(all(secret not in item for item in findings))

    def test_history_mode_finds_real_value_but_not_canonical_key_name(self):
        spec = importlib.util.spec_from_file_location("zen_public_audit_history", ROOT / "scripts/public_release_audit.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        value = "router.household.local"

        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            subprocess.run(["git", "-C", str(repo), "config", "user.email", "audit@example.invalid"], check=True)
            subprocess.run(["git", "-C", str(repo), "config", "user.name", "Audit Test"], check=True)
            note = repo / "history.md"
            note.write_text(f"legacy host={value}\n")
            subprocess.run(["git", "-C", str(repo), "add", "history.md"], check=True)
            subprocess.run(["git", "-C", str(repo), "commit", "-qm", "historical value"], check=True)
            note.write_text('key=ZEN_LOCAL_HOST\nos.environ["ZEN_LOCAL_HOST"]\n')
            subprocess.run(["git", "-C", str(repo), "commit", "-qam", "parameterize"], check=True)

            old_root = module.ROOT
            module.ROOT = repo
            try:
                blobs, problem = module.iter_git_history_text()
            finally:
                module.ROOT = old_root
            self.assertIsNone(problem)
            findings = [
                finding
                for location, text in blobs
                for finding in module.marker_findings(
                    text, location, {"ZEN_LOCAL_HOST": value}
                )
            ]
            self.assertTrue(any("deployment-value: ZEN_LOCAL_HOST" in item for item in findings))
            self.assertTrue(all(value not in item for item in findings))
            self.assertEqual(
                module.marker_findings(
                    note.read_text(), "history.md", {"ZEN_LOCAL_HOST": value}
                ),
                [],
            )

    def test_current_and_history_public_release_audits_pass(self):
        for args in ([], ["--history"]):
            proc = subprocess.run(
                [sys.executable, "scripts/public_release_audit.py", *args],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout)
            self.assertIn("PUBLIC RELEASE AUDIT: PASS", proc.stdout)


if __name__ == "__main__":
    unittest.main()
