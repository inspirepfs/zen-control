#!/usr/bin/env python3
"""Evaluate a ZEN /api/performance JSON snapshot against v0.39 budgets."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("snapshot", help="JSON file saved from /api/performance")
    parser.add_argument("--allow-pending", action="store_true", help="Return success while targets still need samples")
    args = parser.parse_args()

    data = json.loads(Path(args.snapshot).read_text(encoding="utf-8"))
    if data.get("schema") != "zen_performance_snapshot_v1":
        raise SystemExit("Not a zen_performance_snapshot_v1 document")
    acceptance = data.get("acceptance") or {}
    if acceptance.get("schema") != "zen_performance_acceptance_v1":
        raise SystemExit("Snapshot does not contain the v0.39 performance acceptance contract")

    print("ZEN Control v0.39 performance acceptance")
    print(f"overall={str(acceptance.get('state') or 'unknown').upper()}")
    print("-")
    for row in acceptance.get("targets") or []:
        state = str(row.get("state") or "unknown").upper()
        if row.get("key") == "router_connections":
            observed = f"p95={float(row.get('p95_calls') or 0):.2f} calls max={int(row.get('max_calls') or 0)}"
            budget = f"<= {float(row.get('budget_p95_calls') or 0):.1f} calls"
        else:
            observed = f"p50={float(row.get('p50_ms') or 0):.1f}ms p95={float(row.get('p95_ms') or 0):.1f}ms"
            budget = f"p95 <= {float(row.get('budget_p95_ms') or 0):.0f}ms"
        print(
            f"{state:7} {row.get('label',''):<30} "
            f"samples={int(row.get('samples') or 0):>3}/{int(row.get('min_samples') or 0):<3} "
            f"{observed:<28} budget={budget}"
        )

    state = acceptance.get("state")
    if state == "pass":
        return 0
    if state == "pending" and args.allow_pending:
        return 0
    return 2 if state == "fail" else 3


if __name__ == "__main__":
    sys.exit(main())
