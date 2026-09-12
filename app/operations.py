from __future__ import annotations

from datetime import datetime, timezone
from threading import Lock
from typing import Any, Callable

from app.performance import timed


class OperationsMonitor:
    """Operational health, startup integrity and recovery visibility.

    This layer is read-only with respect to RouterOS. Configuration snapshots
    live in PolicyStore and contain only container-side policy configuration;
    operational reward ledgers and RouterOS state remain separate authorities.
    """

    def __init__(
        self,
        *,
        policy_store: Any,
        router: Any,
        reconciler: Any,
        audit: Callable[[str, str, str], None],
        app_version: str = "unknown",
    ) -> None:
        self.policy_store = policy_store
        self.router = router
        self.reconciler = reconciler
        self.audit = audit
        self.app_version = str(app_version or "unknown")
        self._startup_lock = Lock()
        self._startup: dict = {
            "status": "pending",
            "checked_at": None,
            "database": {"ok": False},
            "router": {"ok": False},
            "security": {"ok": False},
            "inventory": {"ok": False},
            "snapshot": None,
            "issues": ["Startup integrity checks have not run yet."],
        }

    @staticmethod
    def _now_iso() -> str:
        return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")

    @timed("worker.operations.startup")
    def startup_check(self) -> dict:
        issues: list[str] = []
        try:
            database = self.policy_store.database_integrity_report()
        except Exception:
            database = {"ok": False, "issues": ["Policy database integrity probe failed"]}
        if not database.get("ok"):
            issues.append("Policy database integrity check failed")

        try:
            router_health = self.router.health()
            router_connected = bool(router_health.get("connected"))
            router_state = {**router_health, "ok": router_connected}
            if not router_connected:
                issues.append("RouterOS unavailable: health probe reported disconnected")
        except Exception as exc:
            router_state = {"ok": False, "error": str(exc)}
            issues.append(f"RouterOS unavailable: {exc}")

        try:
            posture = self.router.get_security_posture()
            security = {
                "ok": bool(posture.get("enforcement_ready")),
                "status": posture.get("status"),
                "score": posture.get("score"),
                "critical_count": posture.get("critical_count", 0),
                "warning_count": posture.get("warning_count", 0),
            }
            if not security["ok"]:
                issues.append("RouterOS enforcement security posture is not ready")
        except Exception as exc:
            security = {"ok": False, "error": str(exc)}
            issues.append(f"Security posture unavailable: {exc}")

        try:
            inventory = self.router.get_managed_state_inventory()
            inventory_state = {
                "ok": True,
                "router": inventory.get("router"),
                "restricted_devices": inventory.get("counts", {}).get("restricted_devices", 0),
                "managed_address_entries": inventory.get("counts", {}).get("managed_address_entries", 0),
                "managed_queues": inventory.get("counts", {}).get("managed_queues", 0),
                "managed_schedulers": inventory.get("counts", {}).get("managed_schedulers", 0),
                "managed_scripts": inventory.get("counts", {}).get("managed_scripts", 0),
            }
        except Exception as exc:
            inventory_state = {"ok": False, "error": str(exc)}
            issues.append(f"Managed-state inventory unavailable: {exc}")

        try:
            snapshot = self.policy_store.create_config_snapshot(
                "system:startup",
                "Startup configuration checkpoint",
                force=False,
            )
        except Exception as exc:
            snapshot = {"created": False, "error": str(exc)}
            issues.append(f"Startup configuration checkpoint failed: {exc}")

        status = "ready" if not issues else "degraded"
        report = {
            "status": status,
            "checked_at": self._now_iso(),
            "database": database,
            "router": router_state,
            "security": security,
            "inventory": inventory_state,
            "snapshot": snapshot,
            "issues": issues,
        }
        with self._startup_lock:
            self._startup = report

        detail = (
            f"version={self.app_version} status={status} "
            f"db={'ok' if database.get('ok') else 'fail'} "
            f"router={'ok' if router_state.get('ok') else 'fail'} "
            f"security={'ok' if security.get('ok') else 'fail'} "
            f"inventory={'ok' if inventory_state.get('ok') else 'fail'} "
            f"snapshot={snapshot.get('id', 'none')} issues={len(issues)}"
        )
        self.audit(
            "STARTUP_INTEGRITY_OK" if status == "ready" else "STARTUP_INTEGRITY_DEGRADED",
            "system:startup",
            detail,
        )
        return report

    def startup_snapshot(self) -> dict:
        with self._startup_lock:
            result = dict(self._startup)
            result["issues"] = list(self._startup.get("issues") or [])
            for key in ("database", "router", "security", "inventory", "snapshot"):
                if isinstance(self._startup.get(key), dict):
                    result[key] = dict(self._startup[key])
            return result

    def readiness(self) -> dict:
        issues: list[str] = []
        try:
            database = self.policy_store.database_integrity_report()
        except Exception:
            database = {"ok": False, "issues": ["Policy database integrity probe failed"]}
        if not database.get("ok"):
            issues.append("policy database")

        try:
            router_health = self.router.health()
            router_connected = bool(router_health.get("connected"))
            router_state = {**router_health, "ok": router_connected}
            if not router_connected:
                issues.append("RouterOS API")
        except Exception:
            router_state = {"ok": False, "error": "RouterOS health probe failed"}
            issues.append("RouterOS API")

        try:
            posture = self.router.get_security_posture()
            security = {
                "ok": bool(posture.get("enforcement_ready")),
                "status": posture.get("status"),
                "score": posture.get("score"),
                "critical_count": posture.get("critical_count", 0),
            }
            if not security["ok"]:
                issues.append("RouterOS enforcement posture")
        except Exception:
            security = {"ok": False, "error": "Security posture probe failed"}
            issues.append("security posture")

        try:
            reconciler = self.reconciler.snapshot() or {}
            worker_ok = bool(reconciler.get("worker_alive"))
        except Exception:
            reconciler = {}
            worker_ok = False
        if not worker_ok:
            issues.append("reconciliation worker")

        return {
            "ok": not issues,
            "checked_at": self._now_iso(),
            "components": {
                "database": "ok" if database.get("ok") else "fail",
                "router": "ok" if router_state.get("ok") else "fail",
                "security": "ok" if security.get("ok") else "fail",
                "reconciler": "ok" if worker_ok else "fail",
            },
            "issues": issues,
            "database": database,
            "router": router_state,
            "security": security,
            "reconciler": {
                "worker_alive": worker_ok,
                "mode": reconciler.get("mode", "unknown"),
                "hold_active": reconciler.get("hold_active", False) if reconciler else "unknown",
                "last_result": (reconciler.get("last") or {}).get("result") if reconciler else None,
            },
        }

    def status(self) -> dict:
        try:
            inventory = self.router.get_managed_state_inventory()
            inventory_error = None
        except Exception as exc:
            inventory = {"counts": {}, "address_lists": [], "queues": [], "schedulers": [], "scripts": []}
            inventory_error = str(exc)

        return {
            "startup": self.startup_snapshot(),
            "readiness": self.readiness(),
            "inventory": inventory,
            "inventory_error": inventory_error,
            "snapshots": self.policy_store.list_config_snapshots(12),
            "audit_count": self.policy_store.audit_count(),
        }
