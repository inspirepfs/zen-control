#!/usr/bin/env python3
"""Repeat the unittest suite and report wall-clock distribution.

This is a synthetic control, not a substitute for the live HTTP measurements
collected by ZEN Control v0.30. Use it to catch gross CPU/test-runtime changes
between releases while the in-app collector identifies production bottlenecks.
"""
from __future__ import annotations

import argparse
import statistics
import subprocess
import sys
import time
from pathlib import Path


def percentile(values: list[float], p: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return 0.0
    if len(ordered) == 1:
        return ordered[0]
    pos = (len(ordered) - 1) * p
    low = int(pos)
    high = min(low + 1, len(ordered) - 1)
    frac = pos - low
    return ordered[low] + (ordered[high] - ordered[low]) * frac


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--tests", default="tests")
    args = parser.parse_args()
    runs = max(1, min(20, args.runs))
    root = Path(__file__).resolve().parents[1]
    durations: list[float] = []

    print(f"ZEN synthetic unittest baseline: {runs} run(s)")
    print(f"root={root}")
    for index in range(1, runs + 1):
        started = time.perf_counter()
        proc = subprocess.run(
            [sys.executable, "-m", "unittest", "discover", "-s", args.tests],
            cwd=root,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        elapsed = time.perf_counter() - started
        durations.append(elapsed)
        print(f"run={index:02d} status={proc.returncode} wall={elapsed:.3f}s")
        if proc.returncode:
            print(proc.stdout)
            return proc.returncode

    print("---")
    print(f"avg={statistics.fmean(durations):.3f}s")
    print(f"p50={percentile(durations, .50):.3f}s")
    print(f"p95={percentile(durations, .95):.3f}s")
    print(f"min={min(durations):.3f}s")
    print(f"max={max(durations):.3f}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
