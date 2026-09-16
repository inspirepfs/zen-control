#!/usr/bin/env python3
"""Destructive, synthetic fresh-install acceptance for ZEN Control.

This harness is intentionally separate from the ordinary runtime smoke. It owns a
throw-away Docker Compose project, proves there is no retained project state,
boots ZEN from empty volumes, validates fresh database/bootstrap state, performs
real HTTP authentication/render/support checks, confirms commissioning fails
closed while RouterOS is deliberately unreachable, then repeats the cycle.

Never point this at a production Compose project. The caller must explicitly
confirm the throw-away project name before any ``docker compose down -v`` call.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from http.cookiejar import CookieJar
from urllib import parse, request

from runtime_acceptance import AcceptanceError, _get_json, _request, _url, run_acceptance


class FreshInstallError(RuntimeError):
    """Raised when a fresh installation does not satisfy the bootstrap contract."""


FRESH_STATE_SCHEMA = "zen_fresh_install_state_v1"
MARKER_PATH = "/data/.zen-fresh-install-acceptance-marker"
FORBIDDEN_PROJECT_NAMES = {
    "zen-control",
    "zen_control",
    "production",
    "prod",
    "default",
}


FRESH_STATE_PROBE = r'''
import json
import os
import sqlite3

path = "/data/policy.db"
conn = sqlite3.connect(path)
conn.row_factory = sqlite3.Row

def count(sql):
    return int(conn.execute(sql).fetchone()[0])

mutable = {
    "profiles": count("SELECT COUNT(*) FROM profiles"),
    "device_policy": count("SELECT COUNT(*) FROM device_policy"),
    "policy_templates": count("SELECT COUNT(*) FROM policy_templates"),
    "schedule_plans": count("SELECT COUNT(*) FROM schedule_plans"),
    "schedule_templates": count("SELECT COUNT(*) FROM schedule_templates"),
    "date_exceptions": count("SELECT COUNT(*) FROM date_exceptions"),
    "service_groups": count("SELECT COUNT(*) FROM service_groups"),
    "custom_services": count("SELECT COUNT(*) FROM services WHERE builtin=0"),
    "custom_policy_groups": count("SELECT COUNT(*) FROM aggregate_policy_groups WHERE builtin=0"),
    "custom_bandwidth_presets": count("SELECT COUNT(*) FROM bandwidth_presets WHERE builtin=0"),
    "push_subscriptions": count("SELECT COUNT(*) FROM notification_push_subscriptions"),
}
user_version = int(conn.execute("PRAGMA user_version").fetchone()[0] or 0)
migrations = [int(row[0]) for row in conn.execute("SELECT version FROM schema_migrations ORDER BY version")]
revision = int(conn.execute("SELECT revision FROM config_revision_state WHERE singleton=1").fetchone()[0] or 0)
payload = {
    "schema": "zen_fresh_install_state_v1",
    "database_exists": os.path.exists(path),
    "user_version": user_version,
    "schema_migrations": migrations,
    "config_revision": revision,
    "mutable_counts": mutable,
    "builtin_services": count("SELECT COUNT(*) FROM services WHERE builtin=1"),
    "builtin_policy_groups": count("SELECT COUNT(*) FROM aggregate_policy_groups WHERE builtin=1"),
    "builtin_bandwidth_presets": count("SELECT COUNT(*) FROM bandwidth_presets WHERE builtin=1"),
    "app_settings": count("SELECT COUNT(*) FROM app_settings"),
    "marker_present": os.path.exists("/data/.zen-fresh-install-acceptance-marker"),
}
print(json.dumps(payload, sort_keys=True))
'''.strip()


def _run(command: list[str], *, env: dict[str, str] | None = None, check: bool = True) -> subprocess.CompletedProcess:
    result = subprocess.run(
        command,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    if check and result.returncode != 0:
        stdout = (result.stdout or "")[-1500:]
        stderr = (result.stderr or "")[-1500:]
        raise FreshInstallError(
            f"command failed ({result.returncode}): {' '.join(command)}\n"
            f"stdout={stdout!r}\nstderr={stderr!r}"
        )
    return result


def _compose_prefix(*, project_name: str, env_file: str, compose_file: str) -> list[str]:
    return [
        "docker",
        "compose",
        "-p",
        project_name,
        "--env-file",
        env_file,
        "-f",
        compose_file,
    ]


def _validate_destroy_scope(project_name: str, confirmation: str) -> None:
    name = str(project_name or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{2,80}", name):
        raise FreshInstallError("fresh-install project name is invalid")
    if name.lower() in FORBIDDEN_PROJECT_NAMES:
        raise FreshInstallError(f"refusing destructive fresh-install run against project {name!r}")
    if confirmation != name:
        raise FreshInstallError(
            "destructive confirmation must exactly match --project-name; "
            "this harness removes that project's containers and volumes"
        )
    lowered = name.lower()
    if not any(token in lowered for token in ("fresh", "test", "ci")):
        raise FreshInstallError(
            "throw-away project name must visibly contain fresh, test or ci"
        )


def _project_resources(project_name: str) -> dict[str, list[str]]:
    label = f"com.docker.compose.project={project_name}"
    commands = {
        "containers": ["docker", "ps", "-a", "--filter", f"label={label}", "--format", "{{.ID}}"],
        "volumes": ["docker", "volume", "ls", "--filter", f"label={label}", "--format", "{{.Name}}"],
        "networks": ["docker", "network", "ls", "--filter", f"label={label}", "--format", "{{.Name}}"],
    }
    result: dict[str, list[str]] = {}
    for kind, command in commands.items():
        output = _run(command).stdout or ""
        result[kind] = [line.strip() for line in output.splitlines() if line.strip()]
    return result


def _assert_project_clean(project_name: str) -> None:
    resources = _project_resources(project_name)
    leftovers = {key: value for key, value in resources.items() if value}
    if leftovers:
        raise FreshInstallError(
            f"throw-away Compose project still has retained resources: {leftovers}"
        )


def _destroy_project(compose: list[str]) -> None:
    _run([*compose, "down", "-v", "--remove-orphans"], check=False)


def _service_container_id(compose: list[str], service: str) -> str:
    return (_run([*compose, "ps", "-q", service]).stdout or "").strip()


def _wait_healthy(compose: list[str], service: str, *, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    last = "missing"
    while time.monotonic() < deadline:
        container_id = _service_container_id(compose, service)
        if not container_id:
            last = "container-not-created"
            time.sleep(0.5)
            continue
        result = _run(
            ["docker", "inspect", "--format", "{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}", container_id],
            check=False,
        )
        last = (result.stdout or result.stderr or "unknown").strip()
        if last == "healthy":
            return
        if last in {"unhealthy", "exited", "dead"}:
            raise FreshInstallError(f"{service} became {last}")
        time.sleep(0.5)
    raise FreshInstallError(f"{service} did not become healthy within {timeout:.1f}s (last={last})")


def _exec_json(compose: list[str], code: str) -> dict:
    result = _run([*compose, "exec", "-T", "mikrotik-control", "python", "-c", code])
    try:
        return json.loads((result.stdout or "").strip())
    except json.JSONDecodeError as exc:
        raise FreshInstallError("fresh-state probe did not return valid JSON") from exc


def _fresh_state(compose: list[str]) -> dict:
    return _exec_json(compose, FRESH_STATE_PROBE)


def _validate_fresh_state(payload: dict) -> None:
    if payload.get("schema") != FRESH_STATE_SCHEMA:
        raise FreshInstallError("fresh-state probe returned an unexpected schema")
    if payload.get("database_exists") is not True:
        raise FreshInstallError("fresh policy database was not created")
    user_version = int(payload.get("user_version") or 0)
    if user_version <= 0 or user_version not in set(payload.get("schema_migrations") or []):
        raise FreshInstallError("fresh database schema migration contract is not current")
    if int(payload.get("config_revision") or 0) != 1:
        raise FreshInstallError(
            f"fresh configuration revision should be exactly 1 after bootstrap; got {payload.get('config_revision')!r}"
        )
    dirty = {
        key: int(value or 0)
        for key, value in (payload.get("mutable_counts") or {}).items()
        if int(value or 0) != 0
    }
    if dirty:
        raise FreshInstallError(f"fresh database contains unexpected operator state: {dirty}")
    if int(payload.get("builtin_services") or 0) <= 0:
        raise FreshInstallError("fresh database contains no built-in service catalogue")
    if int(payload.get("builtin_policy_groups") or 0) <= 0:
        raise FreshInstallError("fresh database contains no built-in aggregate policy groups")
    if int(payload.get("builtin_bandwidth_presets") or 0) <= 0:
        raise FreshInstallError("fresh database contains no built-in bandwidth presets")
    if int(payload.get("app_settings") or 0) <= 0:
        raise FreshInstallError("fresh database contains no default application settings")
    if payload.get("marker_present"):
        raise FreshInstallError("fresh data volume retained the previous-cycle marker")


def _write_cycle_marker(compose: list[str], cycle: int) -> None:
    code = (
        "from pathlib import Path; "
        f"Path({MARKER_PATH!r}).write_text('cycle={int(cycle)}\\n', encoding='utf-8')"
    )
    _run([*compose, "exec", "-T", "mikrotik-control", "python", "-c", code])


def _fresh_commissioning_report(
    *,
    base_url: str,
    admin_user: str,
    admin_password: str,
    request_timeout: float,
) -> dict:
    opener = request.build_opener(request.HTTPCookieProcessor(CookieJar()))
    payload = parse.urlencode(
        {"username": admin_user, "password": admin_password, "otp": ""}
    ).encode("utf-8")
    req = request.Request(
        _url(base_url, "/login"),
        data=payload,
        method="POST",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "zen-fresh-install-acceptance/1",
        },
    )
    with _request(opener, req, timeout=request_timeout) as response:
        response.read()
    return _get_json(
        opener,
        base_url,
        "/api/operations/commissioning",
        timeout=request_timeout,
    )


def _validate_fresh_commissioning(report: dict) -> None:
    if report.get("schema") != "zen_commissioning_report_v1":
        raise FreshInstallError("fresh commissioning report schema is invalid")
    if report.get("overall") != "blocked":
        raise FreshInstallError(
            "fresh synthetic install must remain BLOCKED while RouterOS authority is deliberately unavailable"
        )
    checks = {
        str(item.get("key")): item
        for item in report.get("checks", [])
        if isinstance(item, dict)
    }
    for key in ("policy_database", "runtime_workers"):
        if (checks.get(key) or {}).get("state") != "pass":
            raise FreshInstallError(f"fresh commissioning check {key!r} did not PASS")
    for key in ("routeros_api", "security_authority"):
        state = (checks.get(key) or {}).get("state")
        if state not in {"blocked", "unavailable"}:
            raise FreshInstallError(
                f"fresh commissioning check {key!r} should fail closed; got {state!r}"
            )


def run_fresh_install_acceptance(
    *,
    project_name: str,
    confirm_destroy_project: str,
    env_file: str,
    compose_file: str,
    base_url: str,
    expected_version: str,
    admin_user: str,
    admin_password: str,
    cycles: int = 2,
    startup_timeout: float = 90.0,
    request_timeout: float = 10.0,
) -> list[str]:
    _validate_destroy_scope(project_name, confirm_destroy_project)
    cycles = max(2, min(int(cycles), 3))
    compose = _compose_prefix(
        project_name=project_name,
        env_file=env_file,
        compose_file=compose_file,
    )
    results: list[str] = []

    for cycle in range(1, cycles + 1):
        _destroy_project(compose)
        _assert_project_clean(project_name)
        results.append(f"cycle {cycle}: empty Compose project proven")

        _run([*compose, "up", "-d", "telemetry-db"])
        _wait_healthy(compose, "telemetry-db", timeout=startup_timeout)
        results.append(f"cycle {cycle}: telemetry-db healthy from empty volume")

        app_up = [*compose, "up", "-d"]
        if cycle == 1:
            app_up.append("--build")
        app_up.append("mikrotik-control")
        _run(app_up)

        try:
            runtime_results = run_acceptance(
                base_url=base_url,
                expected_version=expected_version,
                admin_user=admin_user,
                admin_password=admin_password,
                startup_timeout=startup_timeout,
                request_timeout=request_timeout,
            )
        except AcceptanceError as exc:
            raise FreshInstallError(f"cycle {cycle}: runtime acceptance failed: {exc}") from exc
        results.extend(f"cycle {cycle}: {item}" for item in runtime_results)

        state = _fresh_state(compose)
        _validate_fresh_state(state)
        results.append(
            f"cycle {cycle}: fresh database/bootstrap PASS schema={state['user_version']} revision=1"
        )

        commissioning = _fresh_commissioning_report(
            base_url=base_url,
            admin_user=admin_user,
            admin_password=admin_password,
            request_timeout=request_timeout,
        )
        _validate_fresh_commissioning(commissioning)
        results.append(
            f"cycle {cycle}: commissioning fails closed without RouterOS authority"
        )

        _write_cycle_marker(compose, cycle)
        results.append(f"cycle {cycle}: data-volume marker written for next-cycle purge proof")

        if cycle < cycles:
            _destroy_project(compose)
            _assert_project_clean(project_name)
            results.append(f"cycle {cycle}: containers, networks and volumes destroyed")

    return results


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Destructively prove ZEN can commission from empty throw-away Docker volumes. "
            "Run only on an isolated CI runner or disposable development host."
        )
    )
    parser.add_argument("--project-name", default="zen-fresh-install-ci")
    parser.add_argument(
        "--confirm-destroy-project",
        required=True,
        help="Must exactly equal --project-name before destructive down -v operations are allowed.",
    )
    parser.add_argument("--env-file", default=".env.example")
    parser.add_argument("--compose-file", default="docker-compose.yml")
    parser.add_argument("--base-url", default="http://127.0.0.1:8080")
    parser.add_argument("--expect-version", required=True)
    parser.add_argument("--admin-user", default=os.getenv("ADMIN_USER", ""))
    parser.add_argument(
        "--admin-password-env",
        default="ZEN_RUNTIME_SMOKE_PASSWORD",
        help="Environment variable containing the synthetic admin password; its value is never printed.",
    )
    parser.add_argument("--cycles", type=int, default=2)
    parser.add_argument("--startup-timeout", type=float, default=90.0)
    parser.add_argument("--request-timeout", type=float, default=10.0)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    password = os.getenv(args.admin_password_env, "")
    if not args.admin_user or not password:
        print("FRESH INSTALL ACCEPTANCE: FAIL · synthetic admin credentials are required", file=sys.stderr)
        return 1
    try:
        results = run_fresh_install_acceptance(
            project_name=args.project_name,
            confirm_destroy_project=args.confirm_destroy_project,
            env_file=args.env_file,
            compose_file=args.compose_file,
            base_url=args.base_url,
            expected_version=args.expect_version,
            admin_user=args.admin_user,
            admin_password=password,
            cycles=args.cycles,
            startup_timeout=args.startup_timeout,
            request_timeout=args.request_timeout,
        )
    except FreshInstallError as exc:
        print(f"FRESH INSTALL ACCEPTANCE: FAIL · {exc}", file=sys.stderr)
        return 1

    for result in results:
        print(f"PASS · {result}")
    print("FRESH INSTALL ACCEPTANCE: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
