from __future__ import annotations

import contextlib
import contextvars
import functools
import gc
import hashlib
import inspect
import os
import platform
import resource
import statistics
import sys
import threading
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Iterator


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return str(raw).strip().lower() in {"1", "true", "yes", "on"}


def _bounded_int(name: str, default: int, low: int, high: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        value = default
    return max(low, min(high, value))


def _bounded_float(name: str, default: float, low: float, high: float) -> float:
    try:
        value = float(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        value = default
    return max(low, min(high, value))


PERF_ENABLED = _env_bool("ZEN_PERF_ENABLED", True)
PERF_SAMPLE_LIMIT = _bounded_int("ZEN_PERF_SAMPLE_LIMIT", 500, 50, 5000)
PERF_COMPONENT_LIMIT = _bounded_int("ZEN_PERF_COMPONENT_LIMIT", 2000, 100, 10000)
PERF_SLOW_MS = _bounded_float("ZEN_PERF_SLOW_MS", 1000.0, 50.0, 120000.0)
PERF_SQL_PREVIEW = _env_bool("ZEN_PERF_SQL_PREVIEW", True)
PERF_ACCEPTANCE_MIN_SAMPLES = _bounded_int("ZEN_PERF_ACCEPTANCE_MIN_SAMPLES", 5, 5, 100)
PERF_ACCEPTANCE_RECOMMENDED_SAMPLES = _bounded_int("ZEN_PERF_ACCEPTANCE_RECOMMENDED_SAMPLES", 20, 5, 200)
PERF_BUDGET_NAVIGATION_MS = _bounded_float("ZEN_PERF_BUDGET_NAVIGATION_MS", 1000.0, 100.0, 10000.0)
PERF_BUDGET_LOCAL_WRITE_MS = _bounded_float("ZEN_PERF_BUDGET_LOCAL_WRITE_MS", 750.0, 100.0, 10000.0)
PERF_BUDGET_ROUTER_ACTION_MS = _bounded_float("ZEN_PERF_BUDGET_ROUTER_ACTION_MS", 2000.0, 250.0, 20000.0)
PERF_BUDGET_ROUTER_READ_MS = _bounded_float("ZEN_PERF_BUDGET_ROUTER_READ_MS", 1500.0, 250.0, 20000.0)
LEGACY_PERFORMANCE_ACCEPTANCE_SCHEMA = "zen_performance_acceptance_v1"
FORMAL_REQUEST_ACCEPTANCE_SCHEMA = "zen_performance_acceptance_v2"
FORMAL_BUDGETS = {
    "acceptance_min_samples": 5,
    "budget_navigation_p95_ms": 1000.0,
    "budget_local_write_p95_ms": 750.0,
    "budget_router_action_p95_ms": 2000.0,
    "budget_router_read_p95_ms": 1500.0,
}

_START_MONO = time.monotonic()
_START_WALL = datetime.now(timezone.utc).astimezone()


@dataclass
class RequestSample:
    request_id: str
    method: str
    path: str
    started_mono: float
    started_at: str
    route: str = ""
    status: int = 0
    duration_ms: float = 0.0
    error: str = ""
    components: dict[str, dict[str, float]] = field(default_factory=dict)
    sql: dict[str, dict[str, Any]] = field(default_factory=dict)

    def component(self, name: str, duration_ms: float) -> None:
        item = self.components.setdefault(
            name,
            {"calls": 0, "total_ms": 0.0, "max_ms": 0.0},
        )
        item["calls"] += 1
        item["total_ms"] += float(duration_ms)
        item["max_ms"] = max(float(item["max_ms"]), float(duration_ms))

    def sql_query(self, fingerprint: str, preview: str, duration_ms: float) -> None:
        item = self.sql.setdefault(
            fingerprint,
            {
                "fingerprint": fingerprint,
                "preview": preview,
                "calls": 0,
                "total_ms": 0.0,
                "max_ms": 0.0,
            },
        )
        item["calls"] += 1
        item["total_ms"] += float(duration_ms)
        item["max_ms"] = max(float(item["max_ms"]), float(duration_ms))


_current_request: contextvars.ContextVar[RequestSample | None] = contextvars.ContextVar(
    "zen_perf_request", default=None
)
_current_scope: contextvars.ContextVar[str] = contextvars.ContextVar(
    "zen_perf_scope", default="background"
)


class PerformanceCollector:
    """Bounded in-memory performance evidence for v0.30 measurement.

    This collector deliberately does not persist measurements to SQLite or
    PostgreSQL. Performance gathering must not add another durable workload to
    the paths it is trying to measure. Restarting the application clears the
    sample set.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._samples: deque[RequestSample] = deque(maxlen=PERF_SAMPLE_LIMIT)
        self._component_calls: dict[str, deque[float]] = defaultdict(
            lambda: deque(maxlen=PERF_COMPONENT_LIMIT)
        )
        self._component_errors: dict[str, int] = defaultdict(int)
        self._component_scopes: dict[str, dict[str, int]] = defaultdict(
            lambda: defaultdict(int)
        )
        self._sql_calls: dict[str, deque[float]] = defaultdict(
            lambda: deque(maxlen=PERF_COMPONENT_LIMIT)
        )
        self._sql_previews: dict[str, str] = {}
        self._evidence_counters: dict[str, int] = defaultdict(int)
        self._reset_at = self._now_iso()
        self._request_total = 0

    @staticmethod
    def _now_iso() -> str:
        return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")

    def begin_request(self, method: str, path: str) -> tuple[RequestSample, contextvars.Token]:
        sample = RequestSample(
            request_id=uuid.uuid4().hex[:12],
            method=str(method or "GET").upper(),
            path=str(path or "/"),
            started_mono=time.perf_counter(),
            started_at=self._now_iso(),
        )
        token = _current_request.set(sample)
        return sample, token

    def finish_request(
        self,
        sample: RequestSample,
        token: contextvars.Token,
        *,
        route: str,
        status: int,
        error: str = "",
    ) -> RequestSample:
        sample.route = str(route or sample.path)
        sample.status = int(status or 0)
        sample.duration_ms = round((time.perf_counter() - sample.started_mono) * 1000.0, 3)
        sample.error = str(error or "")[:300]
        with self._lock:
            self._request_total += 1
            self._samples.append(sample)
        _current_request.reset(token)
        return sample

    def record_component(self, name: str, duration_ms: float, *, error: bool = False) -> None:
        if not PERF_ENABLED:
            return
        label = str(name or "unknown")[:180]
        value = max(0.0, float(duration_ms))
        sample = _current_request.get()
        if sample is not None:
            sample.component(label, value)
        scope = "request" if sample is not None else (_current_scope.get() or "background")
        with self._lock:
            self._component_calls[label].append(value)
            self._component_scopes[label][scope] += 1
            if error:
                self._component_errors[label] += 1

    def record_sql(self, sql: str, duration_ms: float, *, error: bool = False) -> str:
        normalized = " ".join(str(sql or "").split())
        fingerprint = hashlib.sha1(normalized.encode("utf-8")).hexdigest()[:10]
        preview = normalized[:180] if PERF_SQL_PREVIEW else ""
        sample = _current_request.get()
        if sample is not None:
            sample.sql_query(fingerprint, preview, duration_ms)
        with self._lock:
            self._sql_calls[fingerprint].append(max(0.0, float(duration_ms)))
            if preview:
                self._sql_previews[fingerprint] = preview
            if error:
                self._component_errors[f"postgres.sql.{fingerprint}"] += 1
        return fingerprint

    def record_evidence(self, name: str, count: int = 1) -> None:
        """Record a bounded, non-authoritative operational evidence counter.

        These counters make cache/prepared-view behaviour visible without
        persisting household data or granting background work any control-plane
        authority. They are reset with the rest of the in-memory performance
        evidence.
        """
        if not PERF_ENABLED:
            return
        label = str(name or "unknown").strip().lower()[:180]
        increment = max(0, int(count or 0))
        if not label or not increment:
            return
        with self._lock:
            self._evidence_counters[label] += increment

    def reset(self) -> dict:
        with self._lock:
            self._samples.clear()
            self._component_calls.clear()
            self._component_errors.clear()
            self._component_scopes.clear()
            self._sql_calls.clear()
            self._sql_previews.clear()
            self._evidence_counters.clear()
            self._request_total = 0
            self._reset_at = self._now_iso()
        return {"ok": True, "reset_at": self._reset_at}

    @staticmethod
    def _percentile(values: list[float], percentile: float) -> float:
        if not values:
            return 0.0
        ordered = sorted(float(v) for v in values)
        if len(ordered) == 1:
            return round(ordered[0], 3)
        rank = (len(ordered) - 1) * percentile
        lower = int(rank)
        upper = min(lower + 1, len(ordered) - 1)
        fraction = rank - lower
        return round(ordered[lower] + (ordered[upper] - ordered[lower]) * fraction, 3)

    @classmethod
    def _stats(cls, values: list[float]) -> dict:
        if not values:
            return {
                "count": 0,
                "min_ms": 0.0,
                "avg_ms": 0.0,
                "p50_ms": 0.0,
                "p95_ms": 0.0,
                "p99_ms": 0.0,
                "max_ms": 0.0,
            }
        return {
            "count": len(values),
            "min_ms": round(min(values), 3),
            "avg_ms": round(statistics.fmean(values), 3),
            "p50_ms": cls._percentile(values, 0.50),
            "p95_ms": cls._percentile(values, 0.95),
            "p99_ms": cls._percentile(values, 0.99),
            "max_ms": round(max(values), 3),
        }

    @staticmethod
    def _current_rss_mb() -> float | None:
        try:
            with open("/proc/self/status", "r", encoding="utf-8") as handle:
                for line in handle:
                    if line.startswith("VmRSS:"):
                        kb = int(line.split()[1])
                        return round(kb / 1024.0, 2)
        except (OSError, ValueError, IndexError):
            return None
        return None

    @staticmethod
    def _load_average() -> list[float] | None:
        try:
            return [round(value, 3) for value in os.getloadavg()]
        except (AttributeError, OSError):
            return None

    def _process_snapshot(self) -> dict:
        usage = resource.getrusage(resource.RUSAGE_SELF)
        max_rss = float(usage.ru_maxrss)
        # Linux reports KiB; macOS reports bytes. ZEN's target runtime is Linux,
        # but keep the conversion sensible for local developer qualification.
        if sys.platform == "darwin":
            max_rss_mb = max_rss / (1024.0 * 1024.0)
        else:
            max_rss_mb = max_rss / 1024.0
        return {
            "pid": os.getpid(),
            "python": platform.python_version(),
            "platform": platform.system().lower(),
            "uptime_seconds": round(time.monotonic() - _START_MONO, 1),
            "started_at": _START_WALL.isoformat(timespec="seconds"),
            "cpu_user_seconds": round(float(usage.ru_utime), 3),
            "cpu_system_seconds": round(float(usage.ru_stime), 3),
            "current_rss_mb": self._current_rss_mb(),
            "max_rss_mb": round(max_rss_mb, 2),
            "threads": threading.active_count(),
            "gc_counts": list(gc.get_count()),
            "load_average": self._load_average(),
        }

    def _acceptance_report(self, samples: list[RequestSample]) -> dict:
        """Evaluate retained live evidence against the formal responsiveness gate.

        The gate is deliberately fail-closed around evidence quality. Failed
        requests never count as healthy latency samples, and missing RouterOS
        connection instrumentation can never be interpreted as zero connections.
        """
        classes: dict[str, list[RequestSample]] = {
            "navigation": [],
            "local_write": [],
            "router_action": [],
            "router_read": [],
        }
        router_requests: list[RequestSample] = []
        for sample in samples:
            component_names = tuple(sample.components)
            uses_router = any(name.startswith("routeros.") for name in component_names)
            if uses_router:
                router_requests.append(sample)
            if sample.method == "GET" and str(sample.route).startswith("/?view="):
                classes["navigation"].append(sample)
            elif sample.method == "POST" and uses_router:
                classes["router_action"].append(sample)
            elif sample.method == "POST":
                classes["local_write"].append(sample)
            elif sample.method == "GET" and uses_router:
                classes["router_read"].append(sample)

        specs = (
            (
                "navigation", "Main navigation", PERF_BUDGET_NAVIGATION_MS,
                "Major Dashboard/Devices/Policies/Schedules/Activity/Settings navigation.",
            ),
            (
                "local_write", "Local configuration write", PERF_BUDGET_LOCAL_WRITE_MS,
                "SQLite/configuration POSTs that do not contact RouterOS.",
            ),
            (
                "router_action", "RouterOS-changing action", PERF_BUDGET_ROUTER_ACTION_MS,
                "POSTs that include RouterOS work and fresh validation.",
            ),
            (
                "router_read", "RouterOS read/drill-down", PERF_BUDGET_ROUTER_READ_MS,
                "Read-only pages such as Device 360/explainability that require RouterOS evidence.",
            ),
        )

        def valid(sample: RequestSample) -> bool:
            return not sample.error and 200 <= int(sample.status or 0) < 400

        rows = []
        invalid_total = 0
        for key, label, budget, description in specs:
            group = classes[key]
            valid_group = [sample for sample in group if valid(sample)]
            invalid = len(group) - len(valid_group)
            invalid_total += invalid
            stats = self._stats([sample.duration_ms for sample in valid_group])
            if len(valid_group) < PERF_ACCEPTANCE_MIN_SAMPLES:
                state = "pending"
                reason = "insufficient-valid-samples"
            elif invalid:
                state = "fail"
                reason = "request-errors-present"
            elif stats["p95_ms"] <= budget:
                state = "pass"
                reason = "within-budget"
            else:
                state = "fail"
                reason = "p95-budget-exceeded"
            rows.append({
                "key": key,
                "label": label,
                "description": description,
                "state": state,
                "reason": reason,
                "samples": len(group),
                "valid_samples": len(valid_group),
                "invalid_samples": invalid,
                "min_samples": PERF_ACCEPTANCE_MIN_SAMPLES,
                "recommended_samples": max(
                    PERF_ACCEPTANCE_MIN_SAMPLES, PERF_ACCEPTANCE_RECOMMENDED_SAMPLES
                ),
                "budget_p95_ms": round(float(budget), 1),
                **stats,
            })

        valid_router_requests = [sample for sample in router_requests if valid(sample)]
        invalid_router_requests = len(router_requests) - len(valid_router_requests)
        connect_counts = [
            int(sample.components.get("routeros.connect", {}).get("calls", 0))
            for sample in valid_router_requests
        ]
        missing_connect = sum(1 for value in connect_counts if value <= 0)
        multiple_connect = sum(1 for value in connect_counts if value > 1)
        connect_p95 = self._percentile([float(v) for v in connect_counts], 0.95)
        max_connect = max(connect_counts) if connect_counts else 0
        if len(valid_router_requests) < PERF_ACCEPTANCE_MIN_SAMPLES:
            connect_state = "pending"
            connect_reason = "insufficient-valid-samples"
        elif invalid_router_requests:
            connect_state = "fail"
            connect_reason = "request-errors-present"
        elif missing_connect:
            connect_state = "pending"
            connect_reason = "missing-connection-evidence"
        elif multiple_connect or max_connect > 1:
            connect_state = "fail"
            connect_reason = "connection-budget-exceeded"
        else:
            connect_state = "pass"
            connect_reason = "within-budget"
        rows.append({
            "key": "router_connections",
            "label": "RouterOS connections / request",
            "description": "Every valid RouterOS-requiring request must expose exactly one coherent transport connection.",
            "state": connect_state,
            "reason": connect_reason,
            "samples": len(router_requests),
            "valid_samples": len(valid_router_requests),
            "invalid_samples": invalid_router_requests,
            "min_samples": PERF_ACCEPTANCE_MIN_SAMPLES,
            "recommended_samples": max(
                PERF_ACCEPTANCE_MIN_SAMPLES, PERF_ACCEPTANCE_RECOMMENDED_SAMPLES
            ),
            "budget_p95_calls": 1.0,
            "p50_calls": self._percentile([float(v) for v in connect_counts], 0.50),
            "p95_calls": connect_p95,
            "max_calls": max_connect,
            "missing_evidence": missing_connect,
            "multiple_connections": multiple_connect,
        })

        states = [row["state"] for row in rows]
        overall = "fail" if "fail" in states else ("pending" if "pending" in states else "pass")
        return {
            "schema": FORMAL_REQUEST_ACCEPTANCE_SCHEMA,
            "state": overall,
            "min_samples": PERF_ACCEPTANCE_MIN_SAMPLES,
            "recommended_samples": max(
                PERF_ACCEPTANCE_MIN_SAMPLES, PERF_ACCEPTANCE_RECOMMENDED_SAMPLES
            ),
            "targets": rows,
            "evidence_integrity": {
                "invalid_class_samples": invalid_total,
                "router_missing_connection_evidence": missing_connect,
                "router_multiple_connection_requests": multiple_connect,
            },
            "meaning": {
                "pass": "Every class has enough valid samples, meets its p95 budget and satisfies applicable RouterOS connection evidence.",
                "pending": "Evidence is incomplete: a class needs valid samples or required instrumentation is missing.",
                "fail": "A measured class exceeds budget, contains failed requests after the sample floor, or violates the RouterOS connection budget.",
            },
            "notes": [
                "Acceptance is based on real retained request timings; failed requests are never converted into healthy latency samples.",
                "RouterOS connection evidence is exact-per-request: missing evidence is PENDING and more than one connection is FAIL.",
                "RouterOS action budgets retain fresh post-write validation; performance targets never authorize skipping safety reads.",
                "Percentiles include every valid retained sample; slow outliers are not discarded.",
                "Budgets are configurable by ZEN_PERF_BUDGET_* environment variables; changing them changes the gate and must be deliberate.",
            ],
        }

    def snapshot(self) -> dict:
        with self._lock:
            samples = list(self._samples)
            component_calls = {key: list(values) for key, values in self._component_calls.items()}
            component_errors = dict(self._component_errors)
            component_scopes = {
                key: dict(values) for key, values in self._component_scopes.items()
            }
            sql_calls = {key: list(values) for key, values in self._sql_calls.items()}
            sql_previews = dict(self._sql_previews)
            evidence_counters = dict(self._evidence_counters)
            reset_at = self._reset_at
            request_total = self._request_total

        routes: dict[str, list[RequestSample]] = defaultdict(list)
        for sample in samples:
            routes[f"{sample.method} {sample.route or sample.path}"].append(sample)

        route_rows = []
        for key, group in routes.items():
            durations = [sample.duration_ms for sample in group]
            status_errors = sum(1 for sample in group if sample.status >= 500 or sample.error)
            component_names = set()
            for sample in group:
                component_names.update(sample.components)
            top_components = []
            for component in component_names:
                totals = [
                    float(sample.components.get(component, {}).get("total_ms", 0.0))
                    for sample in group
                ]
                calls = [
                    int(sample.components.get(component, {}).get("calls", 0))
                    for sample in group
                ]
                top_components.append({
                    "name": component,
                    "avg_ms_per_request": round(statistics.fmean(totals), 3),
                    "p95_ms_per_request": self._percentile(totals, 0.95),
                    "avg_calls_per_request": round(statistics.fmean(calls), 2),
                })
            top_components.sort(key=lambda row: row["avg_ms_per_request"], reverse=True)
            stats = self._stats(durations)
            route_rows.append({
                "route": key,
                **stats,
                "errors": status_errors,
                "error_percent": round(status_errors * 100.0 / max(len(group), 1), 1),
                "slow_count": sum(1 for value in durations if value >= PERF_SLOW_MS),
                "top_components": top_components[:8],
            })
        route_rows.sort(key=lambda row: (row["p95_ms"], row["avg_ms"]), reverse=True)

        components = []
        for name, values in component_calls.items():
            stats = self._stats(values)
            components.append({
                "name": name,
                **stats,
                "errors": int(component_errors.get(name, 0)),
                "scopes": component_scopes.get(name, {}),
            })
        components.sort(key=lambda row: (row["avg_ms"] * row["count"], row["p95_ms"]), reverse=True)

        sql_rows = []
        for fingerprint, values in sql_calls.items():
            sql_rows.append({
                "fingerprint": fingerprint,
                "preview": sql_previews.get(fingerprint, ""),
                **self._stats(values),
                "errors": int(component_errors.get(f"postgres.sql.{fingerprint}", 0)),
            })
        sql_rows.sort(key=lambda row: (row["avg_ms"] * row["count"], row["p95_ms"]), reverse=True)

        slow_requests = sorted(samples, key=lambda sample: sample.duration_ms, reverse=True)[:20]
        recent_requests = samples[-20:][::-1]

        def sample_row(sample: RequestSample) -> dict:
            return {
                "request_id": sample.request_id,
                "started_at": sample.started_at,
                "method": sample.method,
                "path": sample.path,
                "route": sample.route or sample.path,
                "status": sample.status,
                "duration_ms": sample.duration_ms,
                "error": sample.error,
                "components": [
                    {
                        "name": name,
                        "calls": int(values.get("calls", 0)),
                        "total_ms": round(float(values.get("total_ms", 0.0)), 3),
                        "max_ms": round(float(values.get("max_ms", 0.0)), 3),
                    }
                    for name, values in sorted(
                        sample.components.items(),
                        key=lambda item: float(item[1].get("total_ms", 0.0)),
                        reverse=True,
                    )
                ],
            }

        request_values = [sample.duration_ms for sample in samples]
        acceptance = self._acceptance_report(samples)
        return {
            "schema": "zen_performance_snapshot_v1",
            "enabled": PERF_ENABLED,
            "captured_at": self._now_iso(),
            "reset_at": reset_at,
            "configuration": {
                "sample_limit": PERF_SAMPLE_LIMIT,
                "component_limit": PERF_COMPONENT_LIMIT,
                "slow_request_ms": PERF_SLOW_MS,
                "sql_preview": PERF_SQL_PREVIEW,
                "storage": "memory-only",
                "acceptance_min_samples": PERF_ACCEPTANCE_MIN_SAMPLES,
                "acceptance_recommended_samples": max(
                    PERF_ACCEPTANCE_MIN_SAMPLES, PERF_ACCEPTANCE_RECOMMENDED_SAMPLES
                ),
                "budget_navigation_p95_ms": PERF_BUDGET_NAVIGATION_MS,
                "budget_local_write_p95_ms": PERF_BUDGET_LOCAL_WRITE_MS,
                "budget_router_action_p95_ms": PERF_BUDGET_ROUTER_ACTION_MS,
                "budget_router_read_p95_ms": PERF_BUDGET_ROUTER_READ_MS,
            },
            "request_summary": {
                **self._stats(request_values),
                "recorded_total": request_total,
                "retained": len(samples),
                "slow_count": sum(1 for value in request_values if value >= PERF_SLOW_MS),
            },
            "acceptance": acceptance,
            "evidence_counters": evidence_counters,
            "routes": route_rows,
            "components": components,
            "sql": sql_rows,
            "slow_requests": [sample_row(sample) for sample in slow_requests],
            "recent_requests": [sample_row(sample) for sample in recent_requests],
            "process": self._process_snapshot(),
            "notes": [
                "Measurements are bounded, memory-only evidence and reset on application restart.",
                "Component timings are inclusive wall-clock timings and can overlap when one measured component calls another.",
                "RouterOS method timings include network round trips; routeros.connect isolates connection establishment time.",
                "PostgreSQL SQL timings identify the exact static query fingerprint used by ActivityStore.",
                "Use the v0.54.4 formal acceptance classes and multiple warm requests in a deliberate measured run before declaring responsiveness closed.",
            ],
        }


def build_formal_acceptance(snapshot: dict, operational_evidence: dict) -> dict:
    """Compose the v0.54.4 gate from latency and runtime observability evidence.

    Runtime evidence is observational only. It proves that the prepared-view,
    background-worker, parallel-observation and mutation-lane measurements are
    present; it never grants or changes RouterOS write authority.
    """
    request_acceptance = dict(snapshot.get("acceptance") or {})
    request_state = str(request_acceptance.get("state") or "pending").lower()
    counters = dict(snapshot.get("evidence_counters") or {})

    prepared_hits = int(counters.get("prepared_view.hit", 0) or 0)
    prepared_misses = int(counters.get("prepared_view.miss", 0) or 0)
    prepared_fallbacks = int(counters.get("prepared_view.fallback", 0) or 0)
    prepared_observed = prepared_hits + prepared_misses
    prepared_state = "pass" if prepared_observed > 0 else "pending"

    background = dict(operational_evidence.get("background_worker") or {})
    background_alive = background.get("worker_alive")
    background_duration = background.get("last_duration_ms")
    if background_alive is False:
        background_state = "fail"
    elif background_alive is True and background_duration is not None:
        background_state = "pass"
    else:
        background_state = "pending"

    observation = dict(operational_evidence.get("parallel_observation") or {})
    observation_items = int(observation.get("items") or 0)
    observation_workers = int(observation.get("workers") or 0)
    observation_failed = int(observation.get("failed") or 0)
    if observation_failed > 0:
        observation_state = "fail"
    elif observation_items > 0 and observation_workers > 0:
        observation_state = "pass"
    else:
        observation_state = "pending"

    mutation = dict(operational_evidence.get("mutation_lane") or {})
    acquisitions = mutation.get("acquisitions")
    if acquisitions is None:
        mutation_state = "pending"
    elif int(acquisitions or 0) > 0:
        mutation_state = "pass"
    else:
        mutation_state = "pending"

    configuration = dict(snapshot.get("configuration") or {})
    relaxed_thresholds: list[str] = []
    configured_min = int(configuration.get("acceptance_min_samples") or 0)
    if configured_min < int(FORMAL_BUDGETS["acceptance_min_samples"]):
        relaxed_thresholds.append("acceptance_min_samples")
    for key in (
        "budget_navigation_p95_ms",
        "budget_local_write_p95_ms",
        "budget_router_action_p95_ms",
        "budget_router_read_p95_ms",
    ):
        configured = float(configuration.get(key) or 0.0)
        canonical = float(FORMAL_BUDGETS[key])
        if configured <= 0.0 or configured > canonical:
            relaxed_thresholds.append(key)
    threshold_state = "fail" if relaxed_thresholds else "pass"

    evidence_targets = [
        {
            "key": "threshold_profile",
            "label": "Canonical acceptance thresholds",
            "state": threshold_state,
            "relaxed": relaxed_thresholds,
            "configured_min_samples": configured_min,
            "canonical": dict(FORMAL_BUDGETS),
            "description": "Formal PASS permits equal or stricter settings only; relaxed budgets or sample floors cannot manufacture PASS.",
        },
        {
            "key": "prepared_views",
            "label": "Prepared-view effectiveness",
            "state": prepared_state,
            "hits": prepared_hits,
            "misses": prepared_misses,
            "fallbacks": prepared_fallbacks,
            "description": "At least one prepared-view lookup must be observed; hits and live fallbacks remain distinct.",
        },
        {
            "key": "background_worker",
            "label": "Background worker timing",
            "state": background_state,
            "worker_alive": background_alive,
            "last_duration_ms": background_duration,
            "description": "The non-authoritative durable read worker must be alive and expose a completed-cycle duration.",
        },
        {
            "key": "parallel_observation",
            "label": "Parallel observation utilisation",
            "state": observation_state,
            "items": observation_items,
            "workers": observation_workers,
            "max_active": int(observation.get("max_active") or 0),
            "utilisation_percent": observation.get("utilisation_percent"),
            "failed": observation_failed,
            "description": "A real observation batch must expose worker fan-out/utilisation without creating write authority.",
        },
        {
            "key": "mutation_lane",
            "label": "Serialized mutation-lane contention",
            "state": mutation_state,
            "acquisitions": int(acquisitions or 0) if acquisitions is not None else None,
            "contentions": mutation.get("contentions"),
            "last_wait_ms": mutation.get("last_wait_ms"),
            "max_wait_ms": mutation.get("max_wait_ms"),
            "description": "At least one real mutation-lane acquisition must expose wait/contention evidence; authority remains serialized.",
        },
    ]

    states = [request_state] + [row["state"] for row in evidence_targets]
    overall = "fail" if "fail" in states else ("pending" if "pending" in states else "pass")
    return {
        "schema": "zen_formal_performance_acceptance_v1",
        "state": overall,
        "request_state": request_state,
        "request_acceptance_schema": request_acceptance.get("schema"),
        "evidence_targets": evidence_targets,
        "notes": [
            "Formal acceptance combines retained request budgets with runtime observability evidence.",
            "PENDING is never converted to PASS because evidence is missing or a counter is zero.",
            "Operational evidence is read-only and cannot authorize RouterOS mutations.",
        ],
    }


collector = PerformanceCollector()


@contextlib.contextmanager
def perf_scope(name: str) -> Iterator[None]:
    token = _current_scope.set(str(name or "background"))
    try:
        yield
    finally:
        _current_scope.reset(token)


@contextlib.contextmanager
def perf_span(name: str) -> Iterator[None]:
    if not PERF_ENABLED:
        yield
        return
    started = time.perf_counter()
    failed = False
    try:
        yield
    except Exception:
        failed = True
        raise
    finally:
        collector.record_component(
            name,
            (time.perf_counter() - started) * 1000.0,
            error=failed,
        )


@contextlib.contextmanager
def perf_sql(sql: str) -> Iterator[None]:
    if not PERF_ENABLED:
        yield
        return
    started = time.perf_counter()
    failed = False
    try:
        yield
    except Exception:
        failed = True
        raise
    finally:
        duration = (time.perf_counter() - started) * 1000.0
        collector.record_component("postgres.query", duration, error=failed)
        collector.record_sql(sql, duration, error=failed)


def timed(name: str) -> Callable:
    def decorate(func: Callable) -> Callable:
        if inspect.iscoroutinefunction(func):
            @functools.wraps(func)
            async def async_wrapper(*args, **kwargs):
                with perf_span(name):
                    return await func(*args, **kwargs)
            return async_wrapper

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            with perf_span(name):
                return func(*args, **kwargs)
        return wrapper
    return decorate


class InstrumentedProxy:
    """Measure public calls without changing the wrapped implementation.

    This intentionally measures only calls entering through the proxy. Internal
    calls made by a method on its own ``self`` are not counted as separate
    public operations, which keeps RouterOS/SQLite call counts useful for
    spotting request-level N+1 behaviour.
    """

    def __init__(self, target: Any, prefix: str):
        object.__setattr__(self, "_perf_target", target)
        object.__setattr__(self, "_perf_prefix", str(prefix))
        object.__setattr__(self, "_perf_wrappers", {})

    def __getattr__(self, name: str) -> Any:
        target = object.__getattribute__(self, "_perf_target")
        value = getattr(target, name)
        if name.startswith("_") or not callable(value):
            return value
        wrappers = object.__getattribute__(self, "_perf_wrappers")
        if name not in wrappers:
            prefix = object.__getattribute__(self, "_perf_prefix")

            @functools.wraps(value)
            def measured(*args, __value=value, __name=name, **kwargs):
                with perf_span(f"{prefix}.{__name}"):
                    return __value(*args, **kwargs)

            wrappers[name] = measured
        return wrappers[name]

    def __setattr__(self, name: str, value: Any) -> None:
        setattr(object.__getattribute__(self, "_perf_target"), name, value)

    @property
    def __wrapped__(self) -> Any:
        return object.__getattribute__(self, "_perf_target")


def instrument(target: Any, prefix: str) -> Any:
    if not PERF_ENABLED:
        return target
    return InstrumentedProxy(target, prefix)
