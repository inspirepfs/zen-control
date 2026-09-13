import copy
import re
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.kid_control_cutover import build_kid_control_cutover_readiness
from app.kid_control_migration import translate_kid_control_snapshot

DAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]


def disabled_legacy_snapshot():
    profile = {
        "id": "*1",
        "name": "Kids",
        "disabled": True,
        "rate-limit": "",
        **{day: "7h-23h30m" for day in DAYS},
        **{f"tur-{day}": "" for day in DAYS},
    }
    devices = [
        {"id": "*2", "name": "Child Laptop", "mac-address": "02:00:00:00:20:01", "user": "Kids", "ip-address": "192.168.50.21"},
    ]
    return {
        "captured_at": "2026-09-12T12:00:00+00:00",
        "profiles": [profile],
        "devices": devices,
        "dhcp_leases": [{"address": "192.168.50.21", "mac": "02:00:00:00:20:01", "dynamic": False, "status": "bound"}],
        "arp_entries": [],
    }


class CommissioningSemanticsTests(unittest.TestCase):
    def test_disabled_retained_profile_is_notice_not_translation_warning(self):
        translated = translate_kid_control_snapshot(disabled_legacy_snapshot())
        profile = translated["profiles"][0]
        self.assertEqual(profile["warnings"], [])
        self.assertEqual(translated["summary"]["warnings"], 0)
        self.assertTrue(profile["notices"])
        self.assertIn("rollback copy", profile["notices"][0])

    def test_disabled_profile_still_blocks_a_new_pre_cutover_transfer(self):
        snapshot = disabled_legacy_snapshot()
        preview = translate_kid_control_snapshot(snapshot)
        staged = {
            "source": "mikrotik_kid_control",
            "source_fingerprint": preview["source_fingerprint"],
            "payload": copy.deepcopy(preview),
        }
        result = build_kid_control_cutover_readiness(
            staged=staged,
            fresh_preview=preview,
            fresh_snapshot=snapshot,
            settings={"auto_reconcile_mode": "enforce"},
            existing_profiles=[],
            existing_device_policy={},
            current_cutover=None,
        )
        self.assertFalse(result["ready"])
        gate = next(item for item in result["checks"] if item["key"] == "legacy_profiles_active")
        self.assertFalse(gate["ok"])
        self.assertIn("Disabled legacy profiles cannot be cut over", gate["detail"])

    def test_migration_ui_formalises_stage_button_fix_and_authority_summary(self):
        template = (ROOT / "app/templates/kid_control_migration.html").read_text()
        css = (ROOT / "app/static/app.css").read_text()
        self.assertIn("kid-control-stage-actions", template)
        self.assertIn(".row-actions.kid-control-stage-actions>form:first-child{display:block}", css)
        self.assertIn("ZEN AUTHORITATIVE", template)
        self.assertIn("DISABLED · RETAINED", template)
        self.assertIn("Verified devices", template)
        self.assertIn("Rollback", template)
        self.assertIn("AVAILABLE", template)
        self.assertIn("PROVENANCE RETAINED", template)
        self.assertNotIn("staged replacement remains non-active", template)

    def test_authoritative_stage_controls_are_not_offered_again(self):
        template = (ROOT / "app/templates/kid_control_migration.html").read_text()
        self.assertIn("not cutover or cutover.state not in ['prepared', 'authoritative', 'failed']", template)


class PublicRepositoryContractTests(unittest.TestCase):
    def test_release_version_is_0531(self):
        main = (ROOT / "app/main.py").read_text()
        pwa = (ROOT / "app/pwa.py").read_text()
        self.assertIn('version="0.55.2"', main)
        self.assertIn('PWA_RELEASE = "0.55.2"', pwa)

    def test_readme_is_product_first_and_changelog_owns_release_history(self):
        readme = (ROOT / "README.md").read_text()
        changelog = (ROOT / "CHANGELOG.md").read_text()
        self.assertTrue(readme.startswith("# ZEN Control\n"))
        self.assertIn("## Why ZEN exists", readme)
        self.assertIn("## Safety model", readme)
        self.assertIn("## Quick start", readme)
        self.assertIn("## v0.55.2", changelog)
        self.assertIn("## v0.53.0", changelog)

    def test_public_docs_and_security_guidance_exist(self):
        required = [
            "SECURITY.md", "CONTRIBUTING.md", "docs/ARCHITECTURE.md",
            "docs/INSTALL.md", "docs/PUBLIC_RELEASE.md", "docs/screenshots/README.md",
        ]
        for rel in required:
            with self.subTest(rel=rel):
                self.assertTrue((ROOT / rel).is_file())

    def test_routeros_public_helpers_are_read_only(self):
        for rel in ("routeros/inspect.rsc", "routeros/verify.rsc"):
            text = (ROOT / rel).read_text().lower()
            executable = "\n".join(
                line for line in text.splitlines()
                if line.strip() and not line.lstrip().startswith("#")
            )
            with self.subTest(rel=rel):
                self.assertIsNone(
                    re.search(r"/(?:add|set|remove|move|enable|disable)\b", executable),
                    f"mutation command found in {rel}",
                )
                self.assertIn("/print", executable)

    def test_env_example_exposes_local_https_parameter_without_real_secret(self):
        env = (ROOT / ".env.example").read_text()
        self.assertIn("ZEN_LOCAL_HOST=zen.example.com", env)
        self.assertIn("CADDY_CF_API_TOKEN=replace-with-cloudflare-dns-api-token", env)
        self.assertIn("ZEN_LAN_BIND_IP=192.168.1.10", env)

    def test_test_suite_is_an_explicit_package_for_clean_ci(self):
        init = ROOT / "tests/__init__.py"
        self.assertTrue(init.is_file())
        self.assertIn("test package", init.read_text().lower())

    def test_github_actions_discovers_tests_from_repository_top_level(self):
        workflow = (ROOT / ".github/workflows/quality.yml").read_text()
        self.assertIn("python3 -m unittest discover -s tests -t . -v", workflow)

    def test_public_release_audit_scans_git_visible_source_not_ignored_runtime_files(self):
        audit = (ROOT / "scripts/public_release_audit.py").read_text()
        self.assertIn('"ls-files"', audit)
        self.assertIn('"--cached"', audit)
        self.assertIn('"--others"', audit)
        self.assertIn('"--exclude-standard"', audit)

    def test_public_release_audit_passes_with_license_as_manual_gate(self):
        proc = subprocess.run(
            [sys.executable, "scripts/public_release_audit.py"],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertIn("PUBLIC RELEASE AUDIT: PASS", proc.stdout)
        self.assertIn("MANUAL GATE: choose an open-source license", proc.stdout)


if __name__ == "__main__":
    unittest.main()
