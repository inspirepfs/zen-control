#!/usr/bin/env python3
"""Validate ZEN's repository-level supply-chain controls without network access."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_DIR = ROOT / ".github" / "workflows"
DEPENDABOT = ROOT / ".github" / "dependabot.yml"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
USES_RE = re.compile(r"^\s*(?:-\s*)?uses:\s*([^\s@]+)@([^\s#]+)")


class SupplyChainContractError(RuntimeError):
    pass


def _external_action_refs() -> list[tuple[str, int, str, str]]:
    refs: list[tuple[str, int, str, str]] = []
    for path in sorted(WORKFLOW_DIR.glob("*.y*ml")):
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            match = USES_RE.match(line)
            if not match:
                continue
            action, ref = match.groups()
            if action.startswith("./") or action.startswith("docker://"):
                continue
            refs.append((str(path.relative_to(ROOT)), lineno, action, ref))
    return refs


def validate() -> list[str]:
    issues: list[str] = []
    refs = _external_action_refs()
    if not refs:
        issues.append("no external GitHub Actions references found")
    for path, lineno, action, ref in refs:
        if not SHA_RE.fullmatch(ref):
            issues.append(f"{path}:{lineno}: {action}@{ref} is not pinned to a 40-hex commit SHA")

    if not DEPENDABOT.exists():
        issues.append(".github/dependabot.yml is missing")
    else:
        cfg = DEPENDABOT.read_text(encoding="utf-8")
        for ecosystem in ("pip", "github-actions", "docker", "docker-compose"):
            if f'package-ecosystem: "{ecosystem}"' not in cfg:
                issues.append(f"Dependabot does not cover {ecosystem}")

    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    ingest_dockerfile = (ROOT / "telemetry" / "ingest" / "Dockerfile").read_text(encoding="utf-8")
    for name, text in (("Dockerfile", dockerfile), ("telemetry/ingest/Dockerfile", ingest_dockerfile)):
        if "FROM python:3.12.14-slim" not in text:
            issues.append(f"{name}: primary Python base is not patch-pinned to 3.12.14-slim")
        if "FROM python:3.12-slim" in text:
            issues.append(f"{name}: broad python:3.12-slim tag remains")

    workflow_text = "\n".join(
        path.read_text(encoding="utf-8") for path in sorted(WORKFLOW_DIR.glob("*.y*ml"))
    )
    required_tokens = (
        "pip-audit==2.10.1",
        "trivy-action@ed142fd0673e97e23eac54620cfb913e5ce36c25",
        "zen-control-image.cdx.json",
        "trivy-vulnerabilities.json",
        "PYTHON DEPENDENCY AUDIT: PASS",
    )
    for token in required_tokens:
        if token not in workflow_text:
            issues.append(f"quality workflow is missing supply-chain control: {token}")

    return issues


def main() -> int:
    issues = validate()
    if issues:
        print("SUPPLY CHAIN CONTRACT: FAIL", file=sys.stderr)
        for issue in issues:
            print(f" - {issue}", file=sys.stderr)
        return 1
    refs = _external_action_refs()
    print(
        "SUPPLY CHAIN CONTRACT: PASS · "
        f"external_actions={len(refs)} sha_pinned · dependabot=4 ecosystems · "
        "python_base=3.12.14-slim · audit=pip-audit+Trivy · sbom=CycloneDX"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
