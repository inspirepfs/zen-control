#!/usr/bin/env python3
"""Credential-safe runtime acceptance for the built ZEN Control application.

The probe is intentionally narrow: it validates process/runtime health, renders the
public sign-in page, performs one synthetic/admin password login, and renders the
authenticated dashboard. It does not call RouterOS endpoints or mutate policy.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
from http.cookiejar import CookieJar
from urllib import error, parse, request


class AcceptanceError(RuntimeError):
    """Raised when the rebuilt runtime does not satisfy the smoke contract."""


def _url(base_url: str, path: str) -> str:
    return f"{base_url.rstrip('/')}/{path.lstrip('/')}"


def _request(opener, req: request.Request, *, timeout: float):
    try:
        return opener.open(req, timeout=timeout)
    except error.HTTPError as exc:
        body = exc.read(512).decode("utf-8", "replace")
        raise AcceptanceError(
            f"{req.get_method()} {req.full_url} returned HTTP {exc.code}; "
            f"response={body!r}"
        ) from exc
    except error.URLError as exc:
        raise AcceptanceError(
            f"{req.get_method()} {req.full_url} failed: {exc.reason}"
        ) from exc
    except OSError as exc:
        # A freshly-started container can accept the TCP connection and then
        # reset it before Uvicorn is ready to answer HTTP. Normalize those raw
        # socket/OS transport failures into the retryable acceptance error path.
        raise AcceptanceError(
            f"{req.get_method()} {req.full_url} failed: {exc}"
        ) from exc


def _get_json(opener, base_url: str, path: str, *, timeout: float) -> dict:
    req = request.Request(
        _url(base_url, path),
        headers={"Accept": "application/json", "User-Agent": "zen-runtime-acceptance/1"},
    )
    with _request(opener, req, timeout=timeout) as response:
        if response.status != 200:
            raise AcceptanceError(f"GET {path} returned HTTP {response.status}")
        try:
            return json.loads(response.read().decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AcceptanceError(f"GET {path} did not return valid JSON") from exc


def _get_text(opener, base_url: str, path: str, *, timeout: float) -> tuple[str, str]:
    req = request.Request(
        _url(base_url, path),
        headers={"Accept": "text/html", "User-Agent": "zen-runtime-acceptance/1"},
    )
    with _request(opener, req, timeout=timeout) as response:
        if response.status != 200:
            raise AcceptanceError(f"GET {path} returned HTTP {response.status}")
        return response.geturl(), response.read().decode("utf-8", "replace")


def _wait_for_json(
    opener,
    base_url: str,
    path: str,
    *,
    timeout: float,
    request_timeout: float,
) -> dict:
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return _get_json(opener, base_url, path, timeout=request_timeout)
        except AcceptanceError as exc:
            last_error = exc
            threading.Event().wait(0.5)
    raise AcceptanceError(f"{path} did not become healthy within {timeout:.1f}s: {last_error}")


def run_acceptance(
    *,
    base_url: str,
    expected_version: str,
    admin_user: str,
    admin_password: str,
    startup_timeout: float = 60.0,
    request_timeout: float = 10.0,
) -> list[str]:
    if not admin_user:
        raise AcceptanceError("admin user is required")
    if not admin_password:
        raise AcceptanceError("admin password is required")

    opener = request.build_opener(request.HTTPCookieProcessor(CookieJar()))
    results: list[str] = []

    live = _wait_for_json(
        opener,
        base_url,
        "/health/live",
        timeout=startup_timeout,
        request_timeout=request_timeout,
    )
    if live.get("ok") is not True or live.get("status") != "alive":
        raise AcceptanceError("/health/live returned an unexpected liveness contract")
    if str(live.get("version")) != str(expected_version):
        raise AcceptanceError(
            f"/health/live version {live.get('version')!r} != expected {expected_version!r}"
        )
    results.append(f"/health/live 200 version={expected_version}")

    runtime = _wait_for_json(
        opener,
        base_url,
        "/health/runtime",
        timeout=startup_timeout,
        request_timeout=request_timeout,
    )
    if runtime.get("ok") is not True:
        raise AcceptanceError("/health/runtime did not report ok=true")
    results.append("/health/runtime 200 ok=true")

    _, login_html = _get_text(opener, base_url, "/login", timeout=request_timeout)
    if "Sign in · ZEN Control" not in login_html or 'action="/login"' not in login_html:
        raise AcceptanceError("/login rendered without the expected ZEN sign-in contract")
    results.append("/login 200 rendered")

    payload = parse.urlencode(
        {"username": admin_user, "password": admin_password, "otp": ""}
    ).encode("utf-8")
    req = request.Request(
        _url(base_url, "/login"),
        data=payload,
        method="POST",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "zen-runtime-acceptance/1",
        },
    )
    with _request(opener, req, timeout=request_timeout) as response:
        dashboard_url = response.geturl()
        dashboard_html = response.read().decode("utf-8", "replace")
        if response.status != 200:
            raise AcceptanceError(f"authenticated dashboard returned HTTP {response.status}")

    final_path = parse.urlparse(dashboard_url).path or "/"
    if final_path == "/login":
        raise AcceptanceError("synthetic login did not establish an authenticated session")
    if "<title>ZEN Control</title>" not in dashboard_html:
        raise AcceptanceError("authenticated response did not render the ZEN application template")
    if 'data-tab="dashboard"' not in dashboard_html:
        raise AcceptanceError("authenticated response did not render dashboard navigation")
    results.append("authenticated dashboard 200 rendered")

    return results


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Prove rebuilt ZEN runtime health plus public/authenticated HTML rendering."
    )
    parser.add_argument("--base-url", default="http://127.0.0.1:8080")
    parser.add_argument("--expect-version", required=True)
    parser.add_argument("--admin-user", default=os.getenv("ADMIN_USER", ""))
    parser.add_argument(
        "--admin-password-env",
        default="ZEN_RUNTIME_SMOKE_PASSWORD",
        help="Environment variable containing the login password; its value is never printed.",
    )
    parser.add_argument("--startup-timeout", type=float, default=60.0)
    parser.add_argument("--request-timeout", type=float, default=10.0)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    password = os.getenv(args.admin_password_env, "")
    try:
        results = run_acceptance(
            base_url=args.base_url,
            expected_version=args.expect_version,
            admin_user=args.admin_user,
            admin_password=password,
            startup_timeout=args.startup_timeout,
            request_timeout=args.request_timeout,
        )
    except AcceptanceError as exc:
        print(f"RUNTIME ACCEPTANCE: FAIL · {exc}", file=sys.stderr)
        return 1

    for result in results:
        print(f"PASS · {result}")
    print("RUNTIME ACCEPTANCE: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
