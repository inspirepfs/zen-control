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
    policy_store: Any | None = None,
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

    background_snapshot = raw["background"]
    durable = background_snapshot.get("durable") if isinstance(background_snapshot, dict) else None
    durable_exposed = isinstance(durable, dict)
    durable_available = durable_exposed and durable.get("available") is not False
    prepared_jobs = dict((durable or {}).get("prepared_jobs") or {}) if durable_available else {}
    failed_latest = int(prepared_jobs.get("failed") or 0)
    retrying_latest = int(prepared_jobs.get("retrying") or 0)
    if durable_exposed:
        prepared_work_healthy = bool(
            durable_available and failed_latest == 0 and retrying_latest == 0
        )
    else:
        # Minimal test/compatibility snapshots predate durable worker evidence.
        # The real BackgroundWorker always exposes the durable object.
        prepared_work_healthy = True

    reconciler_snapshot = raw["reconciler"]
    mutation = reconciler_snapshot.get("router_mutation") or {}
    mutation_available = bool(mutation.get("available", True))
    try:
        observers = int(reconciler_snapshot.get("observation_workers_configured") or 1)
    except (TypeError, ValueError):
        observers = 1
    observers = max(1, min(8, observers))

    database = {
        "available": False,
        "healthy": False,
        "schema_version": None,
        "schema_target": None,
        "upgrade_state": "unavailable",
        "upgrade_backup": False,
    }
    if policy_store is not None:
        try:
            integrity = policy_store.database_integrity_report() or {}
            database = {
                "available": True,
                "healthy": bool(integrity.get("ok")),
                "schema_version": integrity.get("schema_version"),
                "schema_target": integrity.get("schema_target"),
                "upgrade_state": integrity.get("upgrade_state", "unknown"),
                "upgrade_backup": bool(integrity.get("upgrade_backup")),
            }
        except Exception:
            database = {**database, "available": True}

    ok = (
        all(row["available"] and row["alive"] for row in workers.values())
        and mutation_available
        and prepared_work_healthy
        and (database["healthy"] if policy_store is not None else True)
    )
    return {
        "schema": "zen_runtime_health_v1",
        "ok": ok,
        "status": "healthy" if ok else "degraded",
        "version": str(version or ""),
        "workers": workers,
        "database": database,
        "background_read_models": {
            "durable_available": durable_available,
            "healthy": prepared_work_healthy,
            "failed_latest": failed_latest,
            "retrying_latest": retrying_latest,
            "warming_latest": int(prepared_jobs.get("warming") or 0),
            "succeeded_latest": int(prepared_jobs.get("succeeded") or 0),
        },
        "parallel_observation": {
            "configured_workers": observers,
            "model": "ephemeral-bounded",
        },
        "router_mutation_lane": {
            "available": mutation_available,
            "busy": bool(mutation.get("busy", False)),
        },
    }
