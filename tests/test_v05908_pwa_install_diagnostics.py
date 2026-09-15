import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class PwaInstallDiagnosticsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.js = (ROOT / "app/static/pwa.js").read_text()
        cls.css = (ROOT / "app/static/pwa.css").read_text()
        cls.index = (ROOT / "app/templates/index.html").read_text()
        cls.help = (ROOT / "app/help_content.py").read_text()
        cls.install = (ROOT / "docs/INSTALL.md").read_text()
        cls.operator = (ROOT / "docs/OPERATOR_GUIDE.md").read_text()
        cls.public = (ROOT / "docs/PUBLIC_RELEASE.md").read_text()
        cls.readme = (ROOT / "README.md").read_text()
        cls.workflow = (ROOT / ".github/workflows/quality.yml").read_text()

    def test_maintenance_release_stays_on_v059_runtime_line(self):
        self.assertRegex(self.readme, r"Current maintenance release: \*\*v0\.59\.0\.\d+\*\*")
        self.assertIn("application/PWA reports version **0.59.0**", self.readme)

    def test_browser_diagnostic_contract_is_device_local_and_sanitized(self):
        for token in (
            "zen_pwa_browser_diagnostics_v1",
            "window.ZEN_PWA_DIAGNOSTICS",
            "secureContext",
            "displayMode",
            "beforeInstallPromptReceived",
            "appInstalledEventReceived",
            "lastPromptOutcome",
            "serviceWorker",
            "manifest",
            "notifications",
            "push",
        ):
            self.assertIn(token, self.js)
        self.assertNotIn("navigator.userAgent", self.js)
        self.assertNotIn("localStorage", self.js)
        self.assertNotIn("sessionStorage", self.js)
        self.assertIn("no hostname, credentials, subscription endpoint, household policy or activity data", self.js)

    def test_ready_to_install_requires_real_browser_prompt_evidence(self):
        self.assertIn("if (deferredInstallPrompt)", self.js)
        self.assertIn("READY TO INSTALL", self.js)
        self.assertIn("PROMPT NOT OFFERED", self.js)
        self.assertIn("BROWSER-MANAGED", self.js)
        self.assertIn("PROMPT DISMISSED", self.js)
        self.assertIn("INSTALL ACCEPTED", self.js)
        self.assertNotIn("Installable web app ·", self.js)

    def test_install_events_record_outcome_without_persistent_latch(self):
        self.assertIn("window.addEventListener('beforeinstallprompt'", self.js)
        self.assertIn("window.addEventListener('appinstalled'", self.js)
        self.assertIn("choice?.outcome", self.js)
        self.assertIn("deferredInstallPrompt = null", self.js)
        self.assertNotIn("installedOnce", self.js)

    def test_pwa_settings_surface_exposes_refresh_and_copy_diagnostics(self):
        for token in (
            "Install / reinstall diagnostics",
            "data-pwa-diagnostics",
            "data-pwa-diagnostics-refresh",
            "data-pwa-diagnostics-copy",
            "data-pwa-diagnostics-copy-status",
        ):
            self.assertIn(token, self.index)
        for token in (".pwa-diagnostics-panel", ".pwa-diagnostic-grid", ".pwa-diagnostic-row"):
            self.assertIn(token, self.css)

    def test_documentation_explains_ambiguous_browser_install_state(self):
        for text in (self.help, self.install, self.operator):
            self.assertIn("PROMPT NOT OFFERED", text)
            self.assertIn("beforeinstallprompt", text)
        self.assertIn("device-local install/reinstall diagnostics: **implemented**", self.public)
        self.assertIn("representative tablet/multi-device commissioning closure: **OPEN / follow-up**", self.public)

    def test_ci_checks_pwa_javascript_syntax(self):
        self.assertIn("PWA JavaScript syntax", self.workflow)
        self.assertIn("node --check app/static/pwa.js", self.workflow)


if __name__ == "__main__":
    unittest.main()
