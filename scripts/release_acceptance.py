#!/usr/bin/env python3
"""Evaluate a ZEN v0.50 release-readiness JSON capture."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("snapshot", help="JSON file saved from /api/release-readiness")
    parser.add_argument("--allow-pending", action="store_true", help="Return success while commissioning evidence is pending")
    args = parser.parse_args()

    data = json.loads(Path(args.snapshot).read_text(encoding="utf-8"))
    if data.get("schema") != "zen_release_readiness_v1":
        raise SystemExit("Not a zen_release_readiness_v1 document")

    state = str(data.get("state") or "unknown").lower()
    print(f"ZEN Control v{data.get('version', 'unknown')} core release readiness")
    print(f"overall={state.upper()}")
    print("-")
    for row in data.get("checks") or []:
        print(f"{str(row.get('state') or 'unknown').upper():7} {row.get('label','')}: {row.get('summary','')}")
    deferred = data.get("deferred") or []
    if deferred:
        print("-")
        for row in deferred:
            print(f"DEFERRED {row.get('label','')}: {row.get('summary','')}")

    if state == "pass":
        return 0
    if state == "pending" and args.allow_pending:
        return 0
    return 2 if state == "fail" else 3


if __name__ == "__main__":
    raise SystemExit(main())
