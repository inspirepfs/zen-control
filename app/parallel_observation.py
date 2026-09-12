from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Iterable


class ParallelObservationError(RuntimeError):
    """A bounded read-side observation batch could not be constructed."""


class ParallelObserver:
    """Bounded deterministic fan-out for read-only observation/planning.

    The executor has no RouterOS mutation dependency. Callers supply only a
    read/plan function. Results are returned in input order even though the
    underlying work may complete out of order, which keeps reconciliation and
    diagnostics deterministic while allowing safe latency overlap.
    """

    def __init__(self, *, max_workers: int = 4, name: str = "parallel-observer") -> None:
        self.max_workers = max(1, min(8, int(max_workers)))
        self.name = str(name or "parallel-observer")[:80]

    def observe(
        self,
        items: Iterable[Any],
        *,
        key: Callable[[Any], str],
        reader: Callable[[Any], Any],
    ) -> dict:
        rows = list(items)
        started = time.monotonic()
        if not rows:
            return {
                "schema": "zen_parallel_observation_v1",
                "name": self.name,
                "items": 0,
                "workers": 0,
                "max_active": 0,
                "duration_ms": 0.0,
                "results": {},
                "errors": {},
                "order": [],
            }

        keys: list[str] = []
        seen: set[str] = set()
        for item in rows:
            item_key = str(key(item) or "").strip()
            if not item_key:
                raise ParallelObservationError("Parallel observation item has no stable key")
            if item_key in seen:
                raise ParallelObservationError(
                    f"Parallel observation key {item_key!r} is duplicated"
                )
            seen.add(item_key)
            keys.append(item_key)

        workers = min(self.max_workers, len(rows))
        results_by_index: dict[int, Any] = {}
        errors_by_index: dict[int, str] = {}
        active = 0
        max_active = 0
        active_lock = threading.Lock()

        def run_one(index: int, item: Any) -> tuple[int, Any]:
            nonlocal active, max_active
            with active_lock:
                active += 1
                max_active = max(max_active, active)
            try:
                return index, reader(item)
            finally:
                with active_lock:
                    active -= 1

        if workers == 1:
            for idx, item in enumerate(rows):
                try:
                    _, value = run_one(idx, item)
                    results_by_index[idx] = value
                except Exception as exc:  # caller receives bounded per-item evidence
                    errors_by_index[idx] = str(exc)[:300]
        else:
            with ThreadPoolExecutor(
                max_workers=workers,
                thread_name_prefix=self.name[:32],
            ) as executor:
                future_to_index = {
                    executor.submit(run_one, idx, item): idx
                    for idx, item in enumerate(rows)
                }
                for future in as_completed(future_to_index):
                    idx = future_to_index[future]
                    try:
                        _, value = future.result()
                        results_by_index[idx] = value
                    except Exception as exc:
                        errors_by_index[idx] = str(exc)[:300]

        ordered_results = {
            keys[idx]: results_by_index[idx]
            for idx in range(len(rows))
            if idx in results_by_index
        }
        ordered_errors = {
            keys[idx]: errors_by_index[idx]
            for idx in range(len(rows))
            if idx in errors_by_index
        }
        return {
            "schema": "zen_parallel_observation_v1",
            "name": self.name,
            "items": len(rows),
            "workers": workers,
            "max_active": max_active,
            "duration_ms": round((time.monotonic() - started) * 1000.0, 3),
            "results": ordered_results,
            "errors": ordered_errors,
            "order": list(keys),
        }
