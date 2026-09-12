#!/usr/bin/env python3
"""Unauthenticated public-edge acceptance probe for ZEN remote access.

The probe deliberately does not log in and does not accept secrets. Its job is
to prove that a public HTTPS request is challenged by Cloudflare Access rather
than reaching ZEN anonymously. Authenticated ZEN/PWA journeys remain a separate
manual commissioning step.
"""

from __future__ import annotations

import argparse
import json
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, build_opener, HTTPRedirectHandler


SCHEMA = "zen_https_acceptance_v1"


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def classify_public_response(*, url: str, status: int, location: str, headers: dict[str, str]) -> dict:
    parsed = urlparse(url)
    if parsed.scheme.lower() != "https":
        return {"state": "fail", "reason": "public_url_is_not_https"}

    location_host = (urlparse(location).hostname or "").lower() if location else ""
    access_redirect = status in {301, 302, 303, 307, 308} and (
        location_host.endswith("cloudflareaccess.com")
        or "/cdn-cgi/access/" in location
    )
    if access_redirect:
        return {"state": "pass", "reason": "cloudflare_access_challenge_seen"}

    if status == 200:
        return {"state": "fail", "reason": "public_origin_bypassed_access"}

    if status in {401, 403} and headers.get("cf-ray"):
        return {"state": "pending", "reason": "cloudflare_block_seen_but_access_challenge_not_proven"}

    return {"state": "fail", "reason": f"unexpected_public_response_{status}"}


def probe(url: str, timeout: float = 10.0) -> dict:
    opener = build_opener(NoRedirect)
    request = Request(
        url,
        method="GET",
        headers={
            "User-Agent": "ZEN-Control-HTTPS-Acceptance/0.51",
            "Accept": "text/html,application/xhtml+xml",
        },
    )
    status = 0
    response_headers: dict[str, str] = {}
    location = ""
    error = None
    try:
        with opener.open(request, timeout=timeout) as response:
            status = int(response.status)
            response_headers = {str(k).lower(): str(v) for k, v in response.headers.items()}
            location = str(response.headers.get("Location") or "")
    except HTTPError as exc:
        status = int(exc.code)
        response_headers = {str(k).lower(): str(v) for k, v in exc.headers.items()}
        location = str(exc.headers.get("Location") or "")
    except (URLError, TimeoutError, OSError) as exc:
        error = type(exc).__name__

    if error:
        result = {"state": "fail", "reason": "public_probe_failed"}
    else:
        result = classify_public_response(
            url=url,
            status=status,
            location=location,
            headers=response_headers,
        )

    return {
        "schema": SCHEMA,
        "url": url,
        "state": result["state"],
        "reason": result["reason"],
        "http_status": status or None,
        "access_location_host": (urlparse(location).hostname or None) if location else None,
        "cloudflare_edge_seen": bool(response_headers.get("cf-ray")),
        "error_type": error,
        "meaning": (
            "PASS proves an unauthenticated browser request was intercepted by Cloudflare Access. "
            "It does not prove authenticated ZEN functionality or RouterOS authority."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Probe ZEN public HTTPS/Access boundary")
    parser.add_argument("url", help="Public ZEN URL, for example https://zen.example.net/")
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args()

    report = probe(args.url, timeout=max(1.0, min(args.timeout, 60.0)))
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["state"] == "pass" else 2


if __name__ == "__main__":
    raise SystemExit(main())
