#!/usr/bin/env python3
"""Evaluate a ZEN v0.54.5.3 final release-readiness JSON capture."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

SCHEMA = "zen_release_readiness_v2"
REQUIRED_CHECK_COUNT = 8


def _validate(data: dict) -> None:
    if data.get("schema") != SCHEMA:
        raise ValueError(f"Not a {SCHEMA} document")
    checks = list(data.get("checks") or [])
    if int(data.get("required_check_count") or 0) != REQUIRED_CHECK_COUNT:
        raise ValueError("Release-readiness document does not declare the canonical eight-check gate")
    if len(checks) != REQUIRED_CHECK_COUNT:
        raise ValueError(f"Expected exactly {REQUIRED_CHECK_COUNT} release checks, found {len(checks)}")
    counts = dict(data.get("counts") or {})
    calculated = {
        state: sum(1 for row in checks if str(row.get("state") or "").lower() == state)
        for state in ("pass", "pending", "fail")
    }
    if any(int(counts.get(state) or 0) != calculated[state] for state in calculated):
        raise ValueError("Release-readiness counts do not match check states")
    state = str(data.get("state") or "unknown").lower()
    expected = "fail" if calculated["fail"] else ("pending" if calculated["pending"] else "pass")
    if state != expected:
        raise ValueError("Overall release-readiness state contradicts check states")
    final_ready = data.get("final_ready") is True
    if final_ready != (expected == "pass"):
        raise ValueError("final_ready contradicts the canonical eight-check result")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("snapshot", help="JSON file saved from /api/release-readiness")
    parser.add_argument("--allow-pending", action="store_true", help="Return success while commissioning evidence is pending")
    args = parser.parse_args()

    try:
        data = json.loads(Path(args.snapshot).read_text(encoding="utf-8"))
        _validate(data)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"INVALID: {exc}")
        return 4

    state = str(data.get("state") or "unknown").lower()
    counts = dict(data.get("counts") or {})
    print(f"ZEN Control v{data.get('version', 'unknown')} final release readiness")
    print(
        f"overall={state.upper()} · "
        f"PASS={int(counts.get('pass') or 0)} "
        f"PENDING={int(counts.get('pending') or 0)} "
        f"FAIL={int(counts.get('fail') or 0)}"
    )
    print("-")
    for row in data.get("checks") or []:
        print(f"{str(row.get('state') or 'unknown').upper():7} {row.get('label','')}: {row.get('summary','')}")
        if row.get("key") == "live_performance":
            for finding in (row.get("evidence") or {}).get("findings") or []:
                print(f"        {str(finding.get('state') or 'unknown').upper():7} {finding.get('label','')}")
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
