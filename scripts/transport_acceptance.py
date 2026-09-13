#!/usr/bin/env python3
"""Host-side secure transport and PWA server-prerequisite acceptance.

This tool deliberately accepts no credentials or tokens. Local acceptance uses
normal CA/hostname verification and proves only the HTTPS/server side of PWA
commissioning. Public acceptance reuses the unauthenticated Cloudflare Access
challenge probe; authenticated browser/PWA use remains a separate manual gate.
The probe is observation-only and has no RouterOS or policy authority.
"""

from __future__ import annotations

import argparse
import json
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import Request, build_opener, HTTPRedirectHandler

try:
    from scripts.https_acceptance import probe as probe_public
except ModuleNotFoundError:  # direct `python3 scripts/transport_acceptance.py` execution
    from https_acceptance import probe as probe_public

SCHEMA = "zen_secure_transport_acceptance_v2"


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _fetch(base_url: str, path: str, timeout: float) -> dict:
    url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    opener = build_opener(NoRedirect)
    request = Request(url, headers={"User-Agent": "ZEN-Control-Transport-Acceptance/0.56"})
    try:
        with opener.open(request, timeout=timeout) as response:
            body = response.read(1024 * 1024)
            return {
                "status": int(response.status),
                "headers": {str(k).lower(): str(v) for k, v in response.headers.items()},
                "body": body,
                "error": None,
            }
    except HTTPError as exc:
        return {
            "status": int(exc.code),
            "headers": {str(k).lower(): str(v) for k, v in exc.headers.items()},
            "body": exc.read(1024 * 1024),
            "error": None,
        }
    except (URLError, TimeoutError, OSError) as exc:
        return {"status": 0, "headers": {}, "body": b"", "error": type(exc).__name__}


def probe_local(url: str, *, timeout: float = 10.0, expect_version: str = "", require_hsts: bool = False) -> dict:
    parsed = urlparse(url)
    checks: list[dict] = []
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        return {
            "state": "fail",
            "url": url,
            "checks": [{"key": "url", "state": "fail", "reason": "local_url_must_be_https"}],
            "meaning": "Local acceptance requires an HTTPS URL with normal certificate and hostname validation.",
        }

    health = _fetch(url, "/health/live", timeout)
    health_json = {}
    if not health["error"] and health["status"] == 200:
        try:
            health_json = json.loads(health["body"].decode("utf-8"))
        except Exception:
            health_json = {}
    health_ok = bool(
        not health["error"]
        and health["status"] == 200
        and health_json.get("ok") is True
        and health_json.get("status") == "alive"
        and (not expect_version or str(health_json.get("version")) == expect_version)
    )
    checks.append({
        "key": "https_health",
        "state": "pass" if health_ok else "fail",
        "http_status": health["status"] or None,
        "version": health_json.get("version"),
        "error_type": health["error"],
    })

    headers = health["headers"]
    required_headers = {
        "x-content-type-options": "nosniff",
        "x-frame-options": "DENY",
        "referrer-policy": "same-origin",
    }
    missing = [name for name, value in required_headers.items() if headers.get(name, "").lower() != value.lower()]
    header_ok = not missing
    checks.append({
        "key": "security_headers",
        "state": "pass" if header_ok else "fail",
        "missing_or_mismatched": missing,
    })

    hsts_present = bool(headers.get("strict-transport-security"))
    checks.append({
        "key": "hsts",
        "state": "pass" if (hsts_present or not require_hsts) else "fail",
        "present": hsts_present,
        "required": bool(require_hsts),
    })

    worker = _fetch(url, "/service-worker.js", timeout)
    worker_text = worker["body"].decode("utf-8", "replace") if worker["body"] else ""
    worker_ok = bool(
        not worker["error"]
        and worker["status"] == 200
        and worker["headers"].get("service-worker-allowed") == "/"
        and "no-store" in worker["headers"].get("cache-control", "").lower()
        and "SKIP_WAITING" in worker_text
    )
    checks.append({
        "key": "service_worker",
        "state": "pass" if worker_ok else "fail",
        "http_status": worker["status"] or None,
        "error_type": worker["error"],
    })

    manifest = _fetch(url, "/static/manifest.webmanifest", timeout)
    manifest_json = {}
    if not manifest["error"] and manifest["status"] == 200:
        try:
            manifest_json = json.loads(manifest["body"].decode("utf-8"))
        except Exception:
            manifest_json = {}
    manifest_ok = bool(
        manifest["status"] == 200
        and manifest_json.get("display") == "standalone"
        and str(manifest_json.get("start_url") or "").startswith("/")
        and isinstance(manifest_json.get("icons"), list)
        and len(manifest_json.get("icons") or []) >= 2
    )
    checks.append({
        "key": "pwa_manifest",
        "state": "pass" if manifest_ok else "fail",
        "http_status": manifest["status"] or None,
        "error_type": manifest["error"],
    })

    state = "pass" if all(item["state"] == "pass" for item in checks) else "fail"
    return {
        "state": state,
        "url": url,
        "hostname": parsed.hostname,
        "checks": checks,
        "server_pwa_ready": state == "pass",
        "meaning": (
            "PASS proves normal CA/hostname-validated local HTTPS, ZEN health, security headers, service-worker delivery "
            "and manifest prerequisites. Browser install, notification permission and push subscription remain manual browser evidence."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Probe ZEN local HTTPS/PWA prerequisites and optional public Access boundary")
    parser.add_argument("--local-url", default="", help="Local HTTPS URL, for example https://zen.example.net/")
    parser.add_argument("--public-url", default="", help="Optional public HTTPS URL protected by Cloudflare Access")
    parser.add_argument("--expect-version", default="", help="Require /health/live to report this exact ZEN version")
    parser.add_argument("--require-hsts", action="store_true", help="Require Strict-Transport-Security on local HTTPS")
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args(argv)

    if not args.local_url and not args.public_url:
        parser.error("at least one of --local-url or --public-url is required")

    timeout = max(1.0, min(args.timeout, 60.0))
    local = probe_local(
        args.local_url,
        timeout=timeout,
        expect_version=str(args.expect_version or "").strip(),
        require_hsts=args.require_hsts,
    ) if args.local_url else None
    public = probe_public(args.public_url, timeout=timeout) if args.public_url else None

    states = [part["state"] for part in (local, public) if part is not None]
    overall = "pass" if states and all(state == "pass" for state in states) else "fail"
    report = {
        "schema": SCHEMA,
        "state": overall,
        "local": local,
        "public": public,
        "browser_commissioning": "manual",
        "authority": "transport-observation-only-no-routeros-authority",
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if overall == "pass" else 2


if __name__ == "__main__":
    raise SystemExit(main())
