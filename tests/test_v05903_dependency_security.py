import unittest
from pathlib import Path

from scripts import release_patch


ROOT = Path(__file__).resolve().parents[1]


class DependencySecurityClosureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.requirements = (ROOT / "requirements.txt").read_text()

    def test_public_release_dependency_security_floors(self):
        self.assertIn("python-multipart==0.0.32", self.requirements)
        self.assertIn("cryptography>=50.0.1,<51", self.requirements)
        self.assertNotIn("python-multipart==0.0.20", self.requirements)
        self.assertNotIn("cryptography>=46,<47", self.requirements)

    def test_dependency_change_rebuilds_application_service(self):
        self.assertEqual(
            release_patch.affected_services(["requirements.txt"]),
            ["mikrotik-control"],
        )

    def test_hotfix_does_not_bump_runtime_release(self):
        self.assertIn('version="0.59.0"', (ROOT / "app" / "main.py").read_text())
        self.assertIn('PWA_RELEASE = "0.59.0"', (ROOT / "app" / "pwa.py").read_text())


if __name__ == "__main__":
    unittest.main()
