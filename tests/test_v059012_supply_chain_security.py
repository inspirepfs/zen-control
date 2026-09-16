import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
USES_RE = re.compile(r"^\s*(?:-\s*)?uses:\s*([^\s@]+)@([^\s#]+)")


class SupplyChainReleaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = (ROOT / ".github/workflows/quality.yml").read_text()
        cls.dependabot = (ROOT / ".github/dependabot.yml").read_text()
        cls.validator = (ROOT / "scripts/supply_chain_validate.py").read_text()
        cls.readme = (ROOT / "README.md").read_text()
        cls.changelog = (ROOT / "CHANGELOG.md").read_text()
        cls.supply_docs = (ROOT / "docs/SUPPLY_CHAIN.md").read_text()

    def test_every_external_action_is_pinned_to_full_commit_sha(self):
        refs = []
        for path in sorted((ROOT / ".github/workflows").glob("*.y*ml")):
            for line in path.read_text().splitlines():
                match = USES_RE.match(line)
                if not match:
                    continue
                action, ref = match.groups()
                if action.startswith("./") or action.startswith("docker://"):
                    continue
                refs.append((action, ref))
        self.assertGreaterEqual(len(refs), 8)
        for action, ref in refs:
            self.assertRegex(ref, SHA_RE, msg=f"{action}@{ref} is not immutable")

    def test_node24_action_line_and_supply_chain_actions_are_current_pins(self):
        self.assertIn("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1", self.workflow)
        self.assertIn("actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97 # v7.0.0", self.workflow)
        self.assertIn("aquasecurity/trivy-action@ed142fd0673e97e23eac54620cfb913e5ce36c25 # v0.36.0", self.workflow)
        self.assertIn("actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1", self.workflow)
        self.assertNotIn("actions/checkout@v4", self.workflow)
        self.assertNotIn("actions/setup-python@v5", self.workflow)

    def test_supply_chain_job_audits_builds_scans_and_retains_sbom(self):
        for token in (
            "supply-chain:",
            "pip-audit==2.10.1",
            "docker build --pull -t zen-control:supply-chain .",
            "severity: HIGH,CRITICAL",
            "ignore-unfixed: true",
            "zen-control-image.cdx.json",
            "trivy-vulnerabilities.json",
            "retention-days: 30",
            "Enforce Python dependency audit",
            "Enforce fixed HIGH/CRITICAL container vulnerabilities",
        ):
            self.assertIn(token, self.workflow)

    def test_dependabot_covers_python_actions_docker_and_compose(self):
        self.assertIn("version: 2", self.dependabot)
        for ecosystem in ("pip", "github-actions", "docker", "docker-compose"):
            self.assertIn(f'package-ecosystem: "{ecosystem}"', self.dependabot)
        self.assertIn('timezone: "Europe/London"', self.dependabot)

    def test_primary_python_images_are_patch_pinned(self):
        self.assertIn("FROM python:3.12.14-slim", (ROOT / "Dockerfile").read_text())
        self.assertIn("FROM python:3.12.14-slim", (ROOT / "telemetry/ingest/Dockerfile").read_text())
        self.assertNotIn("FROM python:3.12-slim", (ROOT / "Dockerfile").read_text())
        self.assertNotIn("FROM python:3.12-slim", (ROOT / "telemetry/ingest/Dockerfile").read_text())

    def test_primary_python_images_refresh_fixed_os_packages(self):
        for relpath in ("Dockerfile", "telemetry/ingest/Dockerfile"):
            dockerfile = (ROOT / relpath).read_text()
            self.assertIn("apt-get update", dockerfile, msg=relpath)
            self.assertIn("apt-get upgrade -y", dockerfile, msg=relpath)
            self.assertIn("apt-get clean", dockerfile, msg=relpath)
            self.assertIn("rm -rf /var/lib/apt/lists/*", dockerfile, msg=relpath)
            self.assertLess(
                dockerfile.index("apt-get upgrade -y"),
                dockerfile.index("pip install"),
                msg=f"{relpath} must patch the OS layer before installing application dependencies",
            )

    def test_repository_validator_is_part_of_source_quality(self):
        self.assertIn("python3 scripts/supply_chain_validate.py", self.workflow)
        self.assertIn("40-hex commit SHA", self.validator)
        self.assertIn("Dependabot does not cover", self.validator)

    def test_release_docs_own_exact_current_marker_and_explain_limits(self):
        self.assertIn("Current maintenance release: **v0.59.0.12**", self.readme)
        self.assertIn("## v0.59.0.12 — Supply-Chain Security & Dependency Automation", self.changelog)
        self.assertIn("CycloneDX", self.supply_docs)
        self.assertIn("not a background maintenance task", self.supply_docs)
        self.assertIn("not claim tag monitoring is equivalent to immutable digest pinning", self.supply_docs)


if __name__ == "__main__":
    unittest.main()
