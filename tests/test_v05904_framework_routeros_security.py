import unittest
from pathlib import Path

from scripts import release_patch


ROOT = Path(__file__).resolve().parents[1]


class FrameworkRouterOSSecurityClosureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.requirements = (ROOT / "requirements.txt").read_text()
        cls.readme = (ROOT / "README.md").read_text()
        cls.setup_readme = (ROOT / "routeros" / "setup" / "README.md").read_text()
        cls.public_release = (ROOT / "docs" / "PUBLIC_RELEASE.md").read_text()

    def test_framework_security_versions_are_pinned_above_advisory_floors(self):
        self.assertIn("fastapi==0.141.1", self.requirements)
        self.assertIn("starlette==1.6.0", self.requirements)
        self.assertIn("python-multipart==0.0.32", self.requirements)
        self.assertIn("cryptography>=50.0.1,<51", self.requirements)
        self.assertNotIn("fastapi==0.116.1", self.requirements)

    def test_routeros_public_security_floor_is_documented(self):
        for document in (self.readme, self.setup_readme, self.public_release):
            self.assertIn("7.24.2+", document)
            self.assertIn("7.23.4+", document)
            self.assertIn("security-fixed", document)

    def test_requirements_change_rebuilds_application_service(self):
        self.assertEqual(
            release_patch.affected_services(["requirements.txt"]),
            ["mikrotik-control"],
        )

    def test_hotfix_does_not_bump_runtime_release(self):
        self.assertIn('version="0.59.0"', (ROOT / "app" / "main.py").read_text())
        self.assertIn('PWA_RELEASE = "0.59.0"', (ROOT / "app" / "pwa.py").read_text())


if __name__ == "__main__":
    unittest.main()
