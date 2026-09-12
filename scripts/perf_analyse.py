#!/usr/bin/env python3
"""Print a compact ranking from a ZEN v0.30 performance JSON snapshot."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def ms(value) -> str:
    try:
        return f"{float(value):8.1f} ms"
    except (TypeError, ValueError):
        return "     n/a"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("snapshot", type=Path)
    parser.add_argument("--top", type=int, default=15)
    args = parser.parse_args()
    data = json.loads(args.snapshot.read_text(encoding="utf-8"))
    if data.get("schema") != "zen_performance_snapshot_v1":
        raise SystemExit("Not a zen_performance_snapshot_v1 document")
    top = max(1, min(50, args.top))

    summary = data.get("request_summary") or {}
    process = data.get("process") or {}
    print("ZEN Control v0.30 performance snapshot")
    print(f"captured={data.get('captured_at')}")
    print(
        f"requests={summary.get('retained', 0)} "
        f"avg={ms(summary.get('avg_ms'))} p95={ms(summary.get('p95_ms'))} "
        f"max={ms(summary.get('max_ms'))} slow={summary.get('slow_count', 0)}"
    )
    print(
        f"rss={process.get('current_rss_mb')}MB max_rss={process.get('max_rss_mb')}MB "
        f"threads={process.get('threads')} uptime={process.get('uptime_seconds')}s"
    )

    print("\nSlow routes")
    for row in (data.get("routes") or [])[:top]:
        print(
            f"{ms(row.get('p95_ms'))} p95 | {ms(row.get('avg_ms'))} avg | "
            f"n={row.get('count', 0):4} | {row.get('route')}"
        )
        for component in (row.get("top_components") or [])[:4]:
            print(
                f"    {ms(component.get('avg_ms_per_request'))} "
                f"{component.get('avg_calls_per_request', 0):5.1f} calls/req "
                f"{component.get('name')}"
            )

    print("\nHighest cumulative component cost")
    components = list(data.get("components") or [])
    components.sort(
        key=lambda row: float(row.get("avg_ms", 0)) * int(row.get("count", 0)),
        reverse=True,
    )
    for row in components[:top]:
        cumulative = float(row.get("avg_ms", 0)) * int(row.get("count", 0))
        print(
            f"{cumulative:10.1f} ms cumulative | {ms(row.get('p95_ms'))} p95 | "
            f"n={row.get('count', 0):5} | {row.get('name')}"
        )

    print("\nHighest cumulative PostgreSQL query cost")
    sql = list(data.get("sql") or [])
    sql.sort(
        key=lambda row: float(row.get("avg_ms", 0)) * int(row.get("count", 0)),
        reverse=True,
    )
    for row in sql[:top]:
        cumulative = float(row.get("avg_ms", 0)) * int(row.get("count", 0))
        print(
            f"{cumulative:10.1f} ms cumulative | {ms(row.get('p95_ms'))} p95 | "
            f"n={row.get('count', 0):5} | {row.get('fingerprint')} | {row.get('preview', '')}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
