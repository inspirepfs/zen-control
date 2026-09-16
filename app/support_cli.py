"""Download a ZEN support bundle from the running local application.

Run inside the application container:
    python -m app.support_cli --output /data/zen-support.zip

The CLI authenticates to localhost using the container's existing ADMIN_* env
values. Credentials are never printed or written into the output bundle.
"""

from __future__ import annotations

import argparse
import http.cookiejar
import os
from pathlib import Path
import sys
from urllib.parse import urlencode
from urllib.request import build_opener, HTTPCookieProcessor, Request
from urllib.error import HTTPError, URLError


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Download a sanitized ZEN Control support bundle")
    parser.add_argument("--base-url", default="http://127.0.0.1:8080")
    parser.add_argument("--output", default="zen-control-support.zip")
    args = parser.parse_args(argv)

    username = os.getenv("ADMIN_USER", "admin")
    password = os.getenv("ADMIN_PASSWORD", "")
    if not password:
        print("SUPPORT BUNDLE: FAIL · ADMIN_PASSWORD is unavailable to the CLI", file=sys.stderr)
        return 2

    opener = build_opener(HTTPCookieProcessor(http.cookiejar.CookieJar()))
    login = Request(
        args.base_url.rstrip("/") + "/login",
        data=urlencode({"username": username, "password": password, "otp": ""}).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        response = opener.open(login, timeout=15)
        if response.geturl().endswith("/login"):
            print("SUPPORT BUNDLE: FAIL · login was not accepted", file=sys.stderr)
            return 3
        bundle = opener.open(args.base_url.rstrip("/") + "/local/operations/support-bundle", timeout=60).read()
    except (HTTPError, URLError, OSError) as exc:
        print(f"SUPPORT BUNDLE: FAIL · {exc.__class__.__name__}", file=sys.stderr)
        return 4

    target = Path(args.output)
    target.write_bytes(bundle)
    print(f"SUPPORT BUNDLE: PASS · {target} · {len(bundle)} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
