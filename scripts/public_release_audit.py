#!/usr/bin/env python3
"""High-signal public-source hygiene checks for ZEN Control.

This is intentionally conservative and deterministic. It is not a general
secret scanner and does not replace manual review or credential rotation.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

TEXT_SUFFIXES = {
    "", ".py", ".md", ".txt", ".html", ".jinja", ".js", ".css", ".json",
    ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".rsc", ".sql",
    ".webmanifest", ".example",
}

FORBIDDEN_PARTS = {"secrets", "backup", "backups", "data"}
FORBIDDEN_SUFFIXES = {
    ".pem", ".key", ".p12", ".pfx", ".db", ".sqlite", ".sqlite3", ".log",
    ".patch", ".tgz", ".gz", ".zip",
}
FORBIDDEN_EXACT = {".env"}

SECRET_PATTERNS = (
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("github-token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})\b")),
    ("openai-token", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{24,}\b")),
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
)

PLACEHOLDER_MARKERS = (
    "replace-with-", "example.com", "example.net", "example.org", "<token>",
    "<password>", "<dns api token>", "<dns-api-token>",
)


def iter_files() -> list[Path]:
    result: list[Path] = []
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(ROOT)
        if any(part in {".git", ".venv", "__pycache__", ".pytest_cache"} for part in rel.parts):
            continue
        result.append(path)
    return sorted(result)


def is_text_candidate(path: Path) -> bool:
    if path.name in {"Dockerfile", "Caddyfile", ".gitignore", ".dockerignore"}:
        return True
    return path.suffix.lower() in TEXT_SUFFIXES


def main() -> int:
    failures: list[str] = []
    warnings: list[str] = []
    files = iter_files()

    for path in files:
        rel = path.relative_to(ROOT)
        lower_parts = {part.lower() for part in rel.parts[:-1]}
        if rel.name in FORBIDDEN_EXACT:
            failures.append(f"forbidden tracked-style file: {rel}")
        if path.suffix.lower() in FORBIDDEN_SUFFIXES:
            failures.append(f"forbidden artifact suffix: {rel}")
        if lower_parts & FORBIDDEN_PARTS and rel.parts[0] not in {"app", "telemetry"}:
            failures.append(f"review forbidden artifact directory: {rel}")

        if not is_text_candidate(path):
            continue
        try:
            text = path.read_text(errors="strict")
        except (UnicodeDecodeError, OSError):
            continue
        for label, pattern in SECRET_PATTERNS:
            for match in pattern.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                failures.append(f"{label} pattern: {rel}:{line}")

    env_example = ROOT / ".env.example"
    if not env_example.exists():
        failures.append("missing .env.example")
    else:
        for number, line in enumerate(env_example.read_text().splitlines(), 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            key, value = stripped.split("=", 1)
            upper = key.upper()
            if any(word in upper for word in ("PASSWORD", "SECRET", "TOKEN", "KEY")) and value:
                lowered = value.lower()
                if not any(marker in lowered for marker in PLACEHOLDER_MARKERS):
                    # Empty values are allowed; obvious sample defaults for non-secret identity are irrelevant.
                    failures.append(f"non-placeholder secret-like example value: .env.example:{number} ({key})")

    readme = ROOT / "README.md"
    if not readme.exists() or not readme.read_text().startswith("# ZEN Control\n"):
        failures.append("README.md must start with the product overview, not release notes")

    required = [
        "CHANGELOG.md", "SECURITY.md", "CONTRIBUTING.md",
        "docs/ARCHITECTURE.md", "docs/INSTALL.md", "docs/PUBLIC_RELEASE.md",
        "routeros/README.md", "routeros/inspect.rsc", "routeros/verify.rsc",
    ]
    for rel in required:
        if not (ROOT / rel).exists():
            failures.append(f"missing public-repository file: {rel}")

    if not (ROOT / "LICENSE").exists() and not (ROOT / "LICENSE.md").exists():
        warnings.append("MANUAL GATE: choose an open-source license before changing repository visibility to public")

    if failures:
        print("PUBLIC RELEASE AUDIT: FAIL")
        for item in failures:
            print(f"FAIL: {item}")
        for item in warnings:
            print(f"WARN: {item}")
        return 1

    print(f"PUBLIC RELEASE AUDIT: PASS · files={len(files)}")
    for item in warnings:
        print(f"WARN: {item}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
