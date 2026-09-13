#!/usr/bin/env python3
"""Validate ZEN Control's environment-variable configuration contract.

The validator intentionally reports variable *names* and contract state only.
It never emits values from .env, so it is safe to use in release output.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_EXAMPLE = ROOT / ".env.example"
DEFAULT_LOCAL = ROOT / ".env"
COMPOSE = ROOT / "docker-compose.yml"

ENV_LINE_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$")
COMPOSE_REF_RE = re.compile(r"(?<!\$)\$\{([A-Za-z_][A-Za-z0-9_]*)(?:(:-|:\?)([^}]*))?\}")
ENV_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]+$")

# These values are secrets themselves. A path pointing at a secret file is not.
SECRET_VARS = {
    "ADMIN_PASSWORD",
    "SESSION_SECRET",
    "OTP_ENCRYPTION_KEY",
    "MIKROTIK_PASSWORD",
    "TELEMETRY_DB_PASSWORD",
    "PIHOLE_PASSWORD",
    "SUMMARY_SMTP_PASSWORD",
    "SUMMARY_WEBHOOK_TOKEN",
    "ZEN_SMTP_PASSWORD",
    "ZEN_WEBHOOK_SIGNING_SECRET",
    "CADDY_CF_API_TOKEN",
}

# Source/runtime-only variables are supplied inside Compose or have bounded
# application defaults. They are deliberately not part of the host .env contract.
INTERNAL_ENV_VARS = {
    "ADMIN_PASSWORD_HASH",
    "CLASSIFIER_STATUS_FILE",
    "CLASSIFIER_STATUS_SECONDS",
    "DNS_POLL_SECONDS",
    "DOMAIN_IP_TTL",
    "FLOW_BATCH",
    "FLOW_PIPE",
    "INGEST_STATUS_FILE",
    "INGEST_STATUS_SECONDS",
    "LAN_CIDRS",
    "MIKROTIK_DEVICE_SLOW_LIMIT",
    "PIHOLE_DB",
    "PIHOLE_DNS",
    "POLICY_DB",
    "POLICY_TIMEZONE",
    "ROUTER_TIMEZONE",
    "SERVICE_CATALOG_FILE",
    "SERVICE_CATALOG_PATH",
    "STATE_FILE",
    "TELEMETRY_DB_HOST",
    "TELEMETRY_DB_PORT",
    "TELEMETRY_DB_TIMEOUT",
    "ZEN_PUSH_VAPID_KEY_FILE",
    "ZEN_TEST_WEBHOOK_PORT",
    "ZEN_TEST_WEBHOOK_SECRET",
}

# Reserved for intentional removals that remain accepted for one or more
# releases. Empty today; keeping the class explicit prevents ad-hoc handling.
DEPRECATED_ENV_VARS: dict[str, str] = {}

# User-facing variables that are only required when the controlling feature is
# enabled. Other user-facing variables with Compose defaults are optional.
CONDITIONAL_ENV_VARS = {
    "ZEN_SMTP_HOST",
    "ZEN_SMTP_PORT",
    "ZEN_SMTP_USERNAME",
    "ZEN_SMTP_PASSWORD",
    "ZEN_SMTP_FROM",
    "ZEN_SMTP_FROM_NAME",
    "ZEN_SMTP_TO",
    "ZEN_SMTP_STARTTLS",
    "ZEN_SMTP_SSL",
    "ZEN_SMTP_TIMEOUT_SECONDS",
    "ZEN_WEBHOOK_SIGNING_SECRET",
    "ZEN_WEBHOOK_TIMEOUT_SECONDS",
    "ZEN_WEBHOOK_MAX_ATTEMPTS",
    "ZEN_WEBHOOK_ALLOW_HTTP",
    "ZEN_PUBLIC_HOST",
    "ZEN_ALLOWED_HOSTS",
    "ZEN_CLOUDFLARE_ACCESS_PROTECTED",
    "CLOUDFLARE_TUNNEL_TOKEN_FILE",
}

SAFE_SECRET_MARKERS = (
    "replace-with",
    "example",
    "change-me",
    "changeme",
    "<",
    "your-",
)

ENV_PREFIXES = (
    "ADMIN_",
    "CLASSIFIER_",
    "DNS_",
    "DOMAIN_",
    "FLOW_",
    "INGEST_",
    "LAN_",
    "MIKROTIK_",
    "OTP_",
    "PIHOLE_",
    "POLICY_",
    "ROUTER_",
    "SERVICE_",
    "SESSION_",
    "STATE_",
    "SUMMARY_",
    "TELEMETRY_",
    "ZEN_",
)


@dataclass(frozen=True)
class EnvFile:
    path: Path
    values: dict[str, str]
    duplicates: tuple[str, ...]


@dataclass(frozen=True)
class ComposeRef:
    name: str
    operator: str
    default: str

    @property
    def required(self) -> bool:
        return self.operator in {"", ":?"}


def _strip_quotes(value: str) -> str:
    text = value.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in {"'", '"'}:
        return text[1:-1]
    return text


def parse_env_file(path: Path) -> EnvFile:
    values: dict[str, str] = {}
    duplicates: list[str] = []
    if not path.exists():
        return EnvFile(path, values, ())
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = ENV_LINE_RE.match(raw)
        if not match:
            continue
        name, value = match.groups()
        if name in values and name not in duplicates:
            duplicates.append(name)
        values[name] = _strip_quotes(value)
    return EnvFile(path, values, tuple(sorted(duplicates)))


def compose_refs(path: Path = COMPOSE) -> dict[str, ComposeRef]:
    text = path.read_text(encoding="utf-8")
    refs: dict[str, ComposeRef] = {}
    for match in COMPOSE_REF_RE.finditer(text):
        name, operator, default = match.groups()
        ref = ComposeRef(name, operator or "", default or "")
        previous = refs.get(name)
        # Any required use makes the host variable required overall.
        if previous is None or (ref.required and not previous.required):
            refs[name] = ref
    return refs


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


def source_env_refs(paths: Iterable[Path] | None = None) -> set[str]:
    if paths is None:
        roots = [ROOT / item for item in ("app", "scripts", "telemetry", "test-tools")]
        paths = (
            path
            for base in roots
            if base.exists()
            for path in base.rglob("*.py")
            if path.name != "env_validate.py"
        )
    found: set[str] = set()
    for path in paths:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (SyntaxError, UnicodeError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Subscript):
                value = node.value
                if (
                    isinstance(value, ast.Attribute)
                    and value.attr == "environ"
                    and isinstance(value.value, ast.Name)
                    and value.value.id == "os"
                ):
                    target = node.slice
                    if isinstance(target, ast.Constant) and isinstance(target.value, str):
                        if ENV_NAME_RE.fullmatch(target.value):
                            found.add(target.value)
                continue
            if not isinstance(node, ast.Call) or not node.args:
                continue
            first = node.args[0]
            if not isinstance(first, ast.Constant) or not isinstance(first.value, str):
                continue
            candidate = first.value
            if not ENV_NAME_RE.fullmatch(candidate) or not candidate.startswith(ENV_PREFIXES):
                continue
            name = _call_name(node.func)
            # Environment access is sometimes wrapped in typed helpers; accepting
            # uppercase env-shaped names here lets the contract catch those too.
            if name in {
                "getenv",
                "get",
                "_env_bool",
                "_env_int",
                "_bounded_int",
                "_bounded_float",
                "_notification_external_env_bool",
            }:
                found.add(candidate)
    return found


def _truthy(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _secret_example_safe(value: str) -> bool:
    text = value.strip().lower()
    return not text or any(marker in text for marker in SAFE_SECRET_MARKERS)


def classification(name: str, required: set[str]) -> str:
    if name in DEPRECATED_ENV_VARS:
        return "deprecated"
    if name in SECRET_VARS:
        if name in required:
            return "required-secret"
        if name in CONDITIONAL_ENV_VARS:
            return "conditional-secret"
        return "optional-secret"
    if name in required:
        return "required"
    if name in CONDITIONAL_ENV_VARS:
        return "conditional"
    return "optional"


def validate_contract(example_path: Path, local_path: Path | None) -> tuple[list[str], list[str], dict]:
    errors: list[str] = []
    warnings: list[str] = []
    example = parse_env_file(example_path)
    refs = compose_refs()
    user_vars = set(example.values)
    compose_vars = set(refs)
    required = {name for name, ref in refs.items() if ref.required}
    source_refs = source_env_refs()

    if example.duplicates:
        errors.append(".env.example contains duplicate variable(s): " + ", ".join(example.duplicates))

    missing_example = sorted(compose_vars - user_vars)
    if missing_example:
        errors.append("Compose variable(s) missing from .env.example: " + ", ".join(missing_example))

    orphan_example = sorted(user_vars - compose_vars)
    if orphan_example:
        errors.append(".env.example variable(s) not consumed by Compose: " + ", ".join(orphan_example))

    undocumented_source = sorted(source_refs - user_vars - INTERNAL_ENV_VARS - set(DEPRECATED_ENV_VARS))
    if undocumented_source:
        errors.append("Source environment reference(s) missing from contract: " + ", ".join(undocumented_source))

    stale_internal = sorted(INTERNAL_ENV_VARS - source_refs)
    if stale_internal:
        errors.append("Internal environment contract entry/entries are stale: " + ", ".join(stale_internal))

    unsafe_example_secrets = sorted(
        name for name in SECRET_VARS & user_vars if not _secret_example_safe(example.values.get(name, ""))
    )
    if unsafe_example_secrets:
        errors.append(
            ".env.example contains non-placeholder secret value(s): " + ", ".join(unsafe_example_secrets)
        )

    local = parse_env_file(local_path) if local_path is not None else None
    local_checked = bool(local is not None and local.path.exists())
    if local_checked and local is not None:
        if local.duplicates:
            errors.append(f"{local.path.name} contains duplicate variable(s): " + ", ".join(local.duplicates))
        undocumented_local = sorted(set(local.values) - user_vars - set(DEPRECATED_ENV_VARS))
        if undocumented_local:
            errors.append(f"{local.path.name} contains undocumented variable(s): " + ", ".join(undocumented_local))
        missing_required = sorted(name for name in required if not local.values.get(name, "").strip())
        if missing_required:
            errors.append(f"{local.path.name} is missing required variable(s): " + ", ".join(missing_required))

        deprecated_local = sorted(set(local.values) & set(DEPRECATED_ENV_VARS))
        if deprecated_local:
            warnings.append(f"{local.path.name} contains deprecated variable(s): " + ", ".join(deprecated_local))

        values = local.values
        if _truthy(values.get("ZEN_SMTP_ENABLED")):
            smtp_required = ("ZEN_SMTP_HOST", "ZEN_SMTP_FROM", "ZEN_SMTP_TO")
            missing_smtp = [name for name in smtp_required if not values.get(name, "").strip()]
            if missing_smtp:
                errors.append("SMTP is enabled but required variable(s) are empty: " + ", ".join(missing_smtp))
            if _truthy(values.get("ZEN_SMTP_SSL")) and _truthy(values.get("ZEN_SMTP_STARTTLS")):
                errors.append("ZEN_SMTP_SSL and ZEN_SMTP_STARTTLS may not both be enabled")

        if _truthy(values.get("ZEN_WEBHOOK_ALLOW_HTTP")) and not values.get("ZEN_WEBHOOK_SIGNING_SECRET", "").strip():
            errors.append("ZEN_WEBHOOK_ALLOW_HTTP=1 requires ZEN_WEBHOOK_SIGNING_SECRET")

        if _truthy(values.get("ZEN_REMOTE_ACCESS_ENABLED")):
            remote_required = (
                "ZEN_PUBLIC_HOST",
                "ZEN_ALLOWED_HOSTS",
                "CLOUDFLARE_TUNNEL_TOKEN_FILE",
            )
            missing_remote = [name for name in remote_required if not values.get(name, "").strip()]
            if missing_remote:
                errors.append("Remote access is enabled but required variable(s) are empty: " + ", ".join(missing_remote))
            if not _truthy(values.get("ZEN_SECURE_COOKIES")):
                errors.append("ZEN_REMOTE_ACCESS_ENABLED=1 requires ZEN_SECURE_COOKIES=1")
            if not _truthy(values.get("ZEN_CLOUDFLARE_ACCESS_PROTECTED")):
                errors.append("ZEN_REMOTE_ACCESS_ENABLED=1 requires ZEN_CLOUDFLARE_ACCESS_PROTECTED=1")

    classes: dict[str, int] = {}
    for name in user_vars:
        key = classification(name, required)
        classes[key] = classes.get(key, 0) + 1

    report = {
        "schema": "zen_environment_contract_v1",
        "example_variables": len(user_vars),
        "compose_variables": len(compose_vars),
        "source_environment_references": len(source_refs),
        "internal_variables": len(INTERNAL_ENV_VARS),
        "required_variables": len(required),
        "classifications": dict(sorted(classes.items())),
        "local_env_checked": local_checked,
        "errors": len(errors),
        "warnings": len(warnings),
    }
    return errors, warnings, report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate ZEN's environment configuration contract")
    parser.add_argument("--env-file", default=str(DEFAULT_LOCAL), help="Local .env file to validate if it exists")
    parser.add_argument("--example-file", default=str(DEFAULT_EXAMPLE), help="Canonical .env.example path")
    parser.add_argument("--no-local", action="store_true", help="Run source/example/Compose checks only")
    parser.add_argument("--quiet", action="store_true", help="Print only failures/warnings")
    parser.add_argument("--json", action="store_true", help="Emit a secret-free JSON summary")
    args = parser.parse_args(argv)

    example_path = Path(args.example_file).expanduser().resolve()
    local_path = None if args.no_local else Path(args.env_file).expanduser().resolve()
    try:
        errors, warnings, report = validate_contract(example_path, local_path)
    except (OSError, UnicodeError, SyntaxError) as exc:
        print(f"Environment contract ERROR: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(report, sort_keys=True))
    elif not args.quiet:
        state = "PASS" if not errors else "FAIL"
        print(f"ZEN environment contract: {state}")
        print(
            "example={example_variables} compose={compose_variables} source_refs={source_environment_references} "
            "internal={internal_variables} required={required_variables} local_checked={local_env_checked}".format(**report)
        )
        print("classes=" + ", ".join(f"{key}:{value}" for key, value in report["classifications"].items()))

    for item in warnings:
        print(f"WARNING: {item}")
    for item in errors:
        print(f"ERROR: {item}")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
