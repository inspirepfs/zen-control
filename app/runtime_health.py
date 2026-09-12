from __future__ import annotations

from typing import Any


WORKER_SPECS = (
    ("background", "worker_alive"),
    ("reconciler", "worker_alive"),
    ("incidents", "worker_alive"),
    ("summary_delivery", "worker_running"),
)


def _safe_snapshot(component: Any) -> dict:
    try:
        payload = component.snapshot() or {}
    except Exception:
        return {"available": False}
    return payload if isinstance(payload, dict) else {"available": False}


def build_runtime_health(
    *,
    version: str,
    background_worker: Any,
    reconciler: Any,
    incident_monitor: Any,
    summary_delivery: Any,
) -> dict:
    """Return a minimal, non-secret post-startup worker-health contract.

    This is intentionally narrower than authenticated diagnostics. It exists so
    deployment tooling can prove that the in-process workers which make ZEN a
    complete runtime survived a recreate. It exposes only booleans/counts and
    never configuration values, device evidence or credentials.
    """

    raw = {
        "background": _safe_snapshot(background_worker),
        "reconciler": _safe_snapshot(reconciler),
        "incidents": _safe_snapshot(incident_monitor),
        "summary_delivery": _safe_snapshot(summary_delivery),
    }

    workers: dict[str, dict] = {}
    for name, alive_key in WORKER_SPECS:
        snapshot = raw[name]
        available = snapshot.get("available") is not False
        alive = bool(snapshot.get(alive_key)) if available else False
        workers[name] = {
            "required": True,
            "available": available,
            "alive": alive,
        }

    reconciler_snapshot = raw["reconciler"]
    mutation = reconciler_snapshot.get("router_mutation") or {}
    mutation_available = bool(mutation.get("available", True))
    try:
        observers = int(reconciler_snapshot.get("observation_workers_configured") or 1)
    except (TypeError, ValueError):
        observers = 1
    observers = max(1, min(8, observers))

    ok = all(row["available"] and row["alive"] for row in workers.values()) and mutation_available
    return {
        "schema": "zen_runtime_health_v1",
        "ok": ok,
        "status": "healthy" if ok else "degraded",
        "version": str(version or ""),
        "workers": workers,
        "parallel_observation": {
            "configured_workers": observers,
            "model": "ephemeral-bounded",
        },
        "router_mutation_lane": {
            "available": mutation_available,
            "busy": bool(mutation.get("busy", False)),
        },
    }
