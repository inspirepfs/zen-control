#!/usr/bin/env python3
"""Evaluate ZEN v0.54.4 formal performance acceptance evidence.

Historical predecessor: ZEN Control v0.39 performance acceptance.

The preferred input is a JSON snapshot saved from /api/performance. A live
snapshot can also be fetched with --url; authenticated deployments should place
the complete Cookie header value in an environment variable rather than on the
command line.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
from typing import Any
from urllib.request import Request, urlopen


def _load_snapshot(args: argparse.Namespace) -> dict[str, Any]:
    if args.url:
        request = Request(args.url, headers={"Accept": "application/json"})
        if args.cookie_env:
            cookie = os.getenv(args.cookie_env, "").strip()
            if not cookie:
                raise ValueError(f"Environment variable {args.cookie_env!r} is empty")
            request.add_header("Cookie", cookie)
        with urlopen(request, timeout=args.timeout) as response:  # nosec B310 - explicit operator URL
            data = json.loads(response.read().decode("utf-8"))
    else:
        if not args.snapshot:
            raise ValueError("Provide SNAPSHOT or --url")
        if args.snapshot == "-":
            data = json.load(sys.stdin)
        else:
            data = json.loads(Path(args.snapshot).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Performance snapshot must be a JSON object")
    return data


def _validate_contract(data: dict[str, Any]) -> tuple[dict, dict]:
    if data.get("schema") != "zen_performance_snapshot_v1":
        raise ValueError("Not a zen_performance_snapshot_v1 document")
    acceptance = data.get("acceptance") or {}
    if acceptance.get("schema") != "zen_performance_acceptance_v2":
        raise ValueError("Snapshot does not contain the v0.54.4 request acceptance contract")
    formal = data.get("formal_acceptance") or {}
    if formal.get("schema") != "zen_formal_performance_acceptance_v1":
        raise ValueError("Snapshot does not contain the v0.54.4 formal acceptance contract")

    expected = {"navigation", "local_write", "router_action", "router_read", "router_connections"}
    rows = list(acceptance.get("targets") or [])
    keys = {str(row.get("key") or "") for row in rows}
    if keys != expected:
        raise ValueError(f"Acceptance target set mismatch: expected {sorted(expected)}, got {sorted(keys)}")
    for row in rows:
        state = str(row.get("state") or "")
        if state not in {"pass", "pending", "fail"}:
            raise ValueError(f"Invalid target state for {row.get('key')}: {state!r}")
        if int(row.get("valid_samples") or 0) > int(row.get("samples") or 0):
            raise ValueError(f"Invalid sample counts for {row.get('key')}")
        if row.get("key") == "router_connections":
            missing = int(row.get("missing_evidence") or 0)
            multiple = int(row.get("multiple_connections") or 0)
            max_calls = int(row.get("max_calls") or 0)
            if state == "pass" and (missing or multiple or max_calls > 1):
                raise ValueError("RouterOS connection target claims PASS with incomplete/violating evidence")
        elif state == "pass" and float(row.get("p95_ms") or 0) > float(row.get("budget_p95_ms") or 0):
            raise ValueError(f"{row.get('key')} claims PASS while p95 exceeds budget")

    evidence = list(formal.get("evidence_targets") or [])
    evidence_keys = {str(row.get("key") or "") for row in evidence}
    required_evidence = {"threshold_profile", "prepared_views", "background_worker", "parallel_observation", "mutation_lane"}
    if evidence_keys != required_evidence:
        raise ValueError(
            f"Formal evidence target set mismatch: expected {sorted(required_evidence)}, got {sorted(evidence_keys)}"
        )
    return acceptance, formal


def _sanitized_report(data: dict, acceptance: dict, formal: dict) -> dict:
    """Retain acceptance evidence without individual request paths or household data."""
    return {
        "schema": "zen_performance_acceptance_report_v1",
        "captured_at": data.get("captured_at"),
        "reset_at": data.get("reset_at"),
        "formal_acceptance": formal,
        "request_acceptance": acceptance,
        "operational_evidence": data.get("operational_evidence") or {},
        "configuration": data.get("configuration") or {},
    }


def _print_report(acceptance: dict, formal: dict) -> None:
    print("ZEN Control v0.54.4 formal performance acceptance")
    print(f"formal={str(formal.get('state') or 'unknown').upper()} request={str(acceptance.get('state') or 'unknown').upper()}")
    print("-")
    for row in acceptance.get("targets") or []:
        state = str(row.get("state") or "unknown").upper()
        samples = int(row.get("valid_samples") or 0)
        minimum = int(row.get("min_samples") or 0)
        invalid = int(row.get("invalid_samples") or 0)
        if row.get("key") == "router_connections":
            observed = (
                f"p50={float(row.get('p50_calls') or 0):.2f} "
                f"p95={float(row.get('p95_calls') or 0):.2f} max={int(row.get('max_calls') or 0)}"
            )
            budget = "exact <= 1 connection/request"
            detail = (
                f" missing={int(row.get('missing_evidence') or 0)}"
                f" multiple={int(row.get('multiple_connections') or 0)}"
            )
        else:
            observed = (
                f"min={float(row.get('min_ms') or 0):.1f} "
                f"p50={float(row.get('p50_ms') or 0):.1f} "
                f"p95={float(row.get('p95_ms') or 0):.1f} "
                f"p99={float(row.get('p99_ms') or 0):.1f} "
                f"max={float(row.get('max_ms') or 0):.1f}ms"
            )
            budget = f"p95 <= {float(row.get('budget_p95_ms') or 0):.0f}ms"
            detail = ""
        print(
            f"{state:7} {row.get('label',''):<30} "
            f"valid={samples:>3}/{minimum:<3} invalid={invalid:<3} "
            f"{observed:<62} budget={budget}{detail}"
        )

    print("-")
    print("Operational evidence")
    for row in formal.get("evidence_targets") or []:
        state = str(row.get("state") or "unknown").upper()
        key = row.get("key")
        if key == "threshold_profile":
            observed = (
                f"min_samples={row.get('configured_min_samples')} "
                f"relaxed={','.join(row.get('relaxed') or []) or 'none'}"
            )
        elif key == "prepared_views":
            observed = f"hits={row.get('hits', 0)} misses={row.get('misses', 0)} fallbacks={row.get('fallbacks', 0)}"
        elif key == "background_worker":
            observed = f"alive={row.get('worker_alive')} last_ms={row.get('last_duration_ms')}"
        elif key == "parallel_observation":
            observed = (
                f"items={row.get('items', 0)} workers={row.get('workers', 0)} "
                f"max_active={row.get('max_active', 0)} utilisation={row.get('utilisation_percent')}% "
                f"failed={row.get('failed', 0)}"
            )
        else:
            observed = (
                f"acquisitions={row.get('acquisitions')} contentions={row.get('contentions')} "
                f"last_wait_ms={row.get('last_wait_ms')} max_wait_ms={row.get('max_wait_ms')}"
            )
        print(f"{state:7} {row.get('label',''):<34} {observed}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("snapshot", nargs="?", help="JSON file saved from /api/performance, or - for stdin")
    parser.add_argument("--url", help="Fetch a live /api/performance JSON snapshot")
    parser.add_argument(
        "--cookie-env",
        default="",
        help="Environment variable containing the Cookie header for an authenticated --url request",
    )
    parser.add_argument("--timeout", type=float, default=10.0, help="Live fetch timeout in seconds")
    parser.add_argument("--json-out", help="Write a sanitized machine-readable acceptance report")
    parser.add_argument("--allow-pending", action="store_true", help="Return success while the formal gate is PENDING")
    args = parser.parse_args()

    try:
        data = _load_snapshot(args)
        acceptance, formal = _validate_contract(data)
    except Exception as exc:
        print(f"INVALID: {exc}", file=sys.stderr)
        return 4

    _print_report(acceptance, formal)
    if args.json_out:
        Path(args.json_out).write_text(
            json.dumps(_sanitized_report(data, acceptance, formal), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    state = str(formal.get("state") or "unknown")
    if state == "pass":
        return 0
    if state == "pending" and args.allow_pending:
        return 0
    return 2 if state == "fail" else 3


if __name__ == "__main__":
    sys.exit(main())
