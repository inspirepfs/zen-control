#!/usr/bin/env python3
"""High-signal public-source hygiene checks for ZEN Control.

The default scan checks exactly what Git could publish from the current tree.
``--history`` additionally scans reachable Git blobs for high-confidence secret
patterns. ``--deployment-markers`` loads selected non-secret identity values from
the ignored local ``.env`` and checks that current source does not contain them;
historical marker hits are reported as review warnings without printing values.

This is intentionally conservative and deterministic. It complements, rather
than replaces, credential rotation and manual review.
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import re
import subprocess
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
    ("totp-uri", re.compile(r"otpauth://(?:totp|hotp)/[^\s]+", re.IGNORECASE)),
    ("jwt-like-token", re.compile(r"\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b")),
)

SECRET_ASSIGNMENT = re.compile(
    r"(?m)^[ \t]*(?:export[ \t]+)?([A-Z0-9_]*(?:PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY)[A-Z0-9_]*)"
    r"[ \t]*[:=][ \t]*[\"']?([^\s\"'#]{8,})"
)

PLACEHOLDER_MARKERS = (
    "replace-with-", "example.com", "example.net", "example.org", "example.invalid",
    "example.test", "<token>", "<password>", "<dns api token>", "<dns-api-token>",
    "documentation", "dummy", "fake", "changeme", "test-secret",
)

DEPLOYMENT_MARKER_KEYS = (
    "ZEN_LOCAL_HOST",
    "ZEN_PUBLIC_HOST",
    "ZEN_LAN_BIND_IP",
    "MIKROTIK_HOST",
)

DOCUMENTATION_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
)


def _run_git(args: list[str], *, input_bytes: bytes | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(ROOT), *args],
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )


def _git_visible_files(root: Path) -> list[Path] | None:
    """Return tracked plus non-ignored untracked files when Git metadata exists."""
    try:
        proc = subprocess.run(
            [
                "git", "-C", str(root), "ls-files", "-z", "--cached", "--others",
                "--exclude-standard",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except OSError:
        return None
    if proc.returncode != 0:
        return None

    result: list[Path] = []
    for raw in proc.stdout.split(b"\0"):
        if not raw:
            continue
        rel = Path(os.fsdecode(raw))
        path = root / rel
        if path.is_file():
            result.append(path)
    return sorted(set(result))


def iter_files() -> list[Path]:
    git_files = _git_visible_files(ROOT)
    if git_files is not None:
        return git_files

    result: list[Path] = []
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(ROOT)
        if any(part in {".git", ".venv", "__pycache__", ".pytest_cache"} for part in rel.parts):
            continue
        result.append(path)
    return sorted(result)


def is_text_candidate(path: Path | str) -> bool:
    path = Path(path)
    if path.name in {"Dockerfile", "Caddyfile", ".gitignore", ".dockerignore"}:
        return True
    return path.suffix.lower() in TEXT_SUFFIXES


def _placeholder(value: str) -> bool:
    lowered = value.strip().lower()
    return (
        not lowered
        or lowered.startswith("${")
        or any(marker in lowered for marker in PLACEHOLDER_MARKERS)
    )


def secret_findings(text: str, location: str) -> list[str]:
    findings: list[str] = []
    for label, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(text):
            matched = match.group(0)
            # Source templates and tests legitimately construct/example OTP URIs;
            # only a literal URI with embedded concrete material is a finding.
            if label == "totp-uri" and (
                "{" in matched or "%" in matched or "example" in matched.lower()
                or location.startswith("tests/") or location.startswith("history:tests/")
            ):
                continue
            line = text.count("\n", 0, match.start()) + 1
            findings.append(f"{label} pattern: {location}:{line}")

    assignment_path = Path(location.split("@", 1)[0].removeprefix("history:"))
    suffix = assignment_path.suffix.lower()
    assignment_surface = (
        assignment_path.name == ".env"
        or assignment_path.name.startswith(".env.")
        or suffix in {".yaml", ".yml", ".conf", ".cfg", ".ini", ".example"}
    )
    if assignment_surface:
        for match in SECRET_ASSIGNMENT.finditer(text):
            key, value = match.group(1), match.group(2)
            if _placeholder(value):
                continue
            if value.startswith("/run/secrets/") or any(token in value for token in ("${", "{{", "}}")):
                continue
            line = text.count("\n", 0, match.start()) + 1
            findings.append(f"literal secret-like assignment ({key}): {location}:{line}")
    return findings


def _deployment_marker_value_is_concrete(key: str, value: str) -> bool:
    """Return True only for a concrete deployment identity value.

    The marker source is the ignored local .env. Canonical key names, shell
    references and documentation-only addresses are configuration syntax, not
    deployment identity. Ignoring them prevents the scanner from treating an
    identifier such as MIKROTIK_HOST as private material while retaining exact
    matching for real hostnames and LAN addresses.
    """
    value = value.strip()
    if _placeholder(value):
        return False

    normalized = value.strip('"').strip("'").strip()
    upper = normalized.upper()
    key_upper = key.upper()
    if upper in {key_upper, f"${key_upper}", f"${{{key_upper}}}"}:
        return False
    if re.fullmatch(r"\{\{\s*" + re.escape(key) + r"\s*\}\}", normalized, re.IGNORECASE):
        return False

    # RFC 5737 / RFC 3849 addresses are reserved for documentation and tests.
    candidate = normalized.strip("[]")
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        address = None
    if address is not None and any(address in network for network in DOCUMENTATION_NETWORKS):
        return False
    return True


def _deployment_marker_pattern(value: str) -> re.Pattern[str]:
    """Build an exact literal matcher that cannot hit a longer host/address."""
    escaped = re.escape(value)
    candidate = value.strip("[]")
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        address = None

    if isinstance(address, ipaddress.IPv4Address):
        return re.compile(r"(?<![0-9.])" + escaped + r"(?![0-9.])")
    if isinstance(address, ipaddress.IPv6Address):
        return re.compile(r"(?<![0-9A-Fa-f:])" + escaped + r"(?![0-9A-Fa-f:])", re.IGNORECASE)

    # Hostnames are case-insensitive and must not match a longer DNS label/name.
    if re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", value):
        return re.compile(
            r"(?<![A-Za-z0-9_.-])" + escaped + r"(?![A-Za-z0-9_.-])",
            re.IGNORECASE,
        )
    return re.compile(escaped)


def load_deployment_markers(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    parsed: dict[str, str] = {}
    for raw in path.read_text(errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key in DEPLOYMENT_MARKER_KEYS and _deployment_marker_value_is_concrete(key, value):
            parsed[key] = value
    return parsed


def marker_findings(text: str, location: str, markers: dict[str, str]) -> list[str]:
    findings: list[str] = []
    for key, value in markers.items():
        # Revalidate caller-supplied markers as a defence-in-depth guard. Tests
        # and future callers must not be able to turn a canonical key name into
        # a deployment-value finding.
        if not _deployment_marker_value_is_concrete(key, value):
            continue
        pattern = _deployment_marker_pattern(value)
        for match in pattern.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            findings.append(f"deployment-value: {key}: {location}:{line}")
    return findings


def iter_git_history_text() -> tuple[list[tuple[str, str]], str | None]:
    """Return unique reachable historical text blobs as (location, text)."""
    proc = _run_git(["rev-list", "--objects", "--all"])
    if proc.returncode != 0:
        return [], "Git history is unavailable"

    blobs: list[tuple[str, str]] = []
    seen: set[str] = set()
    for raw in proc.stdout.decode(errors="replace").splitlines():
        if not raw.strip():
            continue
        sha, _, rel = raw.partition(" ")
        if not rel or sha in seen or not is_text_candidate(rel):
            continue
        seen.add(sha)
        kind = _run_git(["cat-file", "-t", sha])
        if kind.returncode != 0 or kind.stdout.strip() != b"blob":
            continue
        content = _run_git(["cat-file", "blob", sha])
        if content.returncode != 0 or b"\x00" in content.stdout:
            continue
        try:
            text = content.stdout.decode("utf-8")
        except UnicodeDecodeError:
            continue
        blobs.append((f"history:{rel}@{sha[:12]}", text))
    return blobs, None


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--history", action="store_true", help="scan reachable Git history for high-confidence secret patterns")
    parser.add_argument(
        "--deployment-markers",
        action="store_true",
        help="load selected non-secret identity values from ignored .env and scan current source/history without printing values",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    failures: list[str] = []
    warnings: list[str] = []
    files = iter_files()
    markers = load_deployment_markers(ROOT / ".env") if args.deployment_markers else {}

    if args.deployment_markers and not (ROOT / ".env").exists():
        warnings.append("deployment-marker scan requested but local .env is absent; current source still received static hygiene checks")

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
        failures.extend(secret_findings(text, str(rel)))
        failures.extend(marker_findings(text, str(rel), markers))

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
                if not _placeholder(value):
                    failures.append(f"non-placeholder secret-like example value: .env.example:{number} ({key})")

    readme = ROOT / "README.md"
    if not readme.exists() or not readme.read_text().startswith("# ZEN Control\n"):
        failures.append("README.md must start with the product overview, not release notes")

    required = [
        "LICENSE", "CHANGELOG.md", "SECURITY.md", "CONTRIBUTING.md",
        "docs/ARCHITECTURE.md", "docs/INSTALL.md", "docs/PUBLIC_RELEASE.md",
        "docs/OPERATOR_GUIDE.md", "routeros/README.md", "routeros/inspect.rsc",
        "routeros/verify.rsc", "routeros/setup/README.md",
        "routeros/setup/10-core-authority.template.rsc",
        "routeros/setup/20-global-mode.template.rsc",
        "routeros/setup/30-built-in-services.rsc",
        "routeros/setup/40-known-doh-hardening.rsc",
        "routeros/setup/50-fasttrack.template.rsc",
        "routeros/setup/60-api-user.template.rsc",
        "routeros/setup/70-ipfix.template.rsc",
        "routeros/setup/80-local-dns.template.rsc",
        "routeros/setup/90-dhcp-reservation.template.rsc",
        "routeros/setup/99-verify.rsc",
    ]
    for rel in required:
        if not (ROOT / rel).exists():
            failures.append(f"missing public-repository file: {rel}")

    source_repo = "https://github.com/inspirepfs/zen-control"
    for rel in ("app/templates/login.html", "app/templates/index.html"):
        if source_repo not in (ROOT / rel).read_text(errors="ignore"):
            failures.append(f"AGPL network source link missing from {rel}")

    compose = (ROOT / "docker-compose.yml").read_text(errors="ignore")
    expected_split_dns = "${ZEN_LAN_BIND_IP:?ZEN_LAN_BIND_IP must be set} ${ZEN_LOCAL_HOST:?ZEN_LOCAL_HOST must be set}"
    if expected_split_dns not in compose:
        failures.append("Pi-hole split-DNS host record must use ZEN_LAN_BIND_IP + ZEN_LOCAL_HOST rather than deployment literals")

    history_count = 0
    if args.history:
        blobs, problem = iter_git_history_text()
        if problem:
            warnings.append(problem)
        else:
            history_count = len(blobs)
            for location, text in blobs:
                failures.extend(secret_findings(text, location))
                # Historical identity is a review/depersonalization signal rather
                # than a secret. Report it without values so an operator can
                # choose history rewrite or explicit acceptance before publish.
                for item in marker_findings(text, location, markers):
                    warnings.append("historical " + item)

    if failures:
        print("PUBLIC RELEASE AUDIT: FAIL")
        for item in sorted(set(failures)):
            print(f"FAIL: {item}")
        for item in sorted(set(warnings)):
            print(f"WARN: {item}")
        return 1

    suffix = f" · history_blobs={history_count}" if args.history else ""
    marker_suffix = f" · deployment_markers={len(markers)}" if args.deployment_markers else ""
    print(f"PUBLIC RELEASE AUDIT: PASS · files={len(files)}{suffix}{marker_suffix}")
    for item in sorted(set(warnings)):
        print(f"WARN: {item}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
