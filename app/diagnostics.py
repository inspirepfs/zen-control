from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import time
from typing import Any, Callable


DIAGNOSTIC_SCHEMA = "zen_operational_diagnostics_v1"


def _now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _check_state(*, ok: bool, warning: bool = False, offline: bool = False) -> str:
    if not ok:
        return "offline" if offline else "critical"
    if warning:
        return "warning"
    return "healthy"


def read_telemetry_ingest_status(path=None, now=None, stale_after_seconds=30) -> dict:
    """Read the sanitized traffic-ingest heartbeat without inferring source health.

    A stale/missing heartbeat means the ingest process cannot be proven alive.
    Old DNS/IPFIX source states are therefore discarded rather than carried
    forward as apparently healthy evidence. Raw parser/filesystem errors are
    intentionally not returned because this payload is used in support export.
    """
    target = Path(path or os.getenv("INGEST_STATUS_FILE", "/telemetry-state/ingest-status.json"))
    base = {
        "schema": "zen_telemetry_ingest_status_v1",
        "availability": "unavailable",
        "dns_source": "unknown",
        "ipfix_source": "unknown",
        "flow_queue_depth": None,
        "observed_at": None,
        "age_seconds": None,
    }
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
        if not isinstance(payload, dict) or payload.get("schema") != "zen_telemetry_ingest_status_v1":
            raise ValueError("Unsupported telemetry ingest status document")
        observed = datetime.fromisoformat(str(payload.get("observed_at") or ""))
        if observed.tzinfo is None:
            observed = observed.replace(tzinfo=timezone.utc)
        current = now or datetime.now(timezone.utc)
        if current.tzinfo is None:
            current = current.replace(tzinfo=timezone.utc)
        age = max(0.0, (current.astimezone(timezone.utc) - observed.astimezone(timezone.utc)).total_seconds())
        availability = "stale" if age > max(1, int(stale_after_seconds)) else "available"

        def source_state(name: str) -> str:
            state = str(payload.get(name) or "unknown").strip().lower()
            return state if state in {"available", "unavailable", "unknown"} else "unknown"

        # A live publisher is the authority for source state. Once its own
        # evidence is stale, carrying an old AVAILABLE forward would invent
        # health and defeat dependency-chaos diagnostics.
        dns_source = source_state("dns_source") if availability == "available" else "unknown"
        ipfix_source = source_state("ipfix_source") if availability == "available" else "unknown"
        return {
            "schema": "zen_telemetry_ingest_status_v1",
            "availability": availability,
            "dns_source": dns_source,
            "ipfix_source": ipfix_source,
            "flow_queue_depth": (max(0, _int(payload.get("flow_queue_depth"))) if availability == "available" else None),
            "observed_at": observed.astimezone(timezone.utc).isoformat(),
            "age_seconds": round(age, 1),
        }
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return base


class OperationalDiagnostics:
    """Compose existing read-only health authorities into a support report.

    The report is deliberately sanitized. It contains status, counts and timing
    evidence only: no device addresses, DNS names, RouterOS host/user values,
    credentials, session material or raw audit details.
    """

    def __init__(
        self,
        *,
        app_version: str,
        policy_store: Any,
        router: Any,
        activity_store: Any,
        reconciler: Any,
        incident_monitor: Any,
        summary_delivery: Any,
        performance_collector: Any,
        service_contract_loader: Callable[[], list[dict]],
        ingest_status_loader: Callable[[], dict] | None = None,
        classifier_status_loader: Callable[[], dict] | None = None,
    ) -> None:
        self.app_version = app_version
        self.policy_store = policy_store
        self.router = router
        self.activity_store = activity_store
        self.reconciler = reconciler
        self.incident_monitor = incident_monitor
        self.summary_delivery = summary_delivery
        self.performance_collector = performance_collector
        self.service_contract_loader = service_contract_loader
        self.ingest_status_loader = ingest_status_loader
        self.classifier_status_loader = classifier_status_loader

    @staticmethod
    def _timed_call(callback: Callable[[], Any]) -> tuple[Any, float, Exception | None]:
        started = time.monotonic()
        try:
            return callback(), round((time.monotonic() - started) * 1000.0, 2), None
        except Exception as exc:  # diagnostics must degrade rather than fail whole page
            return None, round((time.monotonic() - started) * 1000.0, 2), exc

    @staticmethod
    def _check(key: str, label: str, state: str, summary: str, duration_ms: float = 0.0, **facts: Any) -> dict:
        return {
            "key": key,
            "label": label,
            "state": state,
            "summary": summary,
            "duration_ms": round(float(duration_ms or 0.0), 2),
            "facts": facts,
        }

    def capture(self) -> dict:
        checks: list[dict] = []

        perf, perf_probe_ms, perf_error = self._timed_call(self.performance_collector.snapshot)
        perf = perf or {}
        process = dict(perf.get("process") or {})
        app_state = "warning" if perf_error is not None else "healthy"
        checks.append(self._check(
            "application",
            "ZEN application",
            app_state,
            (
                f"v{self.app_version} · Python {process.get('python', 'unknown')} · uptime {_int(process.get('uptime_seconds'))}s"
                if perf_error is None
                else f"v{self.app_version} · process performance evidence unavailable"
            ),
            perf_probe_ms,
            rss_mb=(round(_float(process.get("current_rss_mb")), 1) if perf_error is None else "unknown"),
            max_rss_mb=(round(_float(process.get("max_rss_mb")), 1) if perf_error is None else "unknown"),
            threads=(_int(process.get("threads")) if perf_error is None else "unknown"),
        ))

        database, db_ms, db_error = self._timed_call(self.policy_store.database_integrity_report)
        database = database or {}
        db_ok = bool(database.get("ok")) and db_error is None
        table_counts = dict(database.get("table_counts") or {})
        checks.append(self._check(
            "policy_database",
            "Policy database",
            _check_state(ok=db_ok),
            "SQLite integrity OK" if db_ok else "SQLite integrity unavailable or failed",
            db_ms,
            size_bytes=_int(database.get("size_bytes")),
            tables=len(table_counts),
            rows=sum(_int(value) for value in table_counts.values()),
            missing_tables=len(database.get("missing_tables") or []),
        ))

        router_health: dict = {}
        security: dict = {}
        inventory: dict = {}
        service_health: dict = {}
        router_error = security_error = inventory_error = service_error = None
        router_ms = security_ms = inventory_ms = service_ms = 0.0

        session_acquire_error = None
        try:
            session = self.router.coherent_session()
        except AttributeError:
            session = None
        except Exception:
            # Some adapters can fail while constructing the coherent session,
            # before __enter__ is reached. Treat that exactly like connection
            # establishment failure and keep the remainder of diagnostics alive.
            session = None
            session_acquire_error = RuntimeError("RouterOS session unavailable")

        def collect_router() -> None:
            nonlocal router_health, security, inventory, service_health
            nonlocal router_error, security_error, inventory_error, service_error
            nonlocal router_ms, security_ms, inventory_ms, service_ms
            router_health, router_ms, router_error = self._timed_call(self.router.health)
            router_health = router_health or {}
            security, security_ms, security_error = self._timed_call(self.router.get_security_posture)
            security = security or {}
            inventory, inventory_ms, inventory_error = self._timed_call(self.router.get_managed_state_inventory)
            inventory = inventory or {}
            service_health, service_ms, service_error = self._timed_call(
                lambda: self.router.get_service_contract_health(self.service_contract_loader())
            )
            service_health = service_health or {}

        if session_acquire_error is not None:
            router_error = security_error = inventory_error = service_error = session_acquire_error
        elif session is None:
            collect_router()
        else:
            try:
                with session:
                    collect_router()
            except Exception:
                # Connection establishment can fail before an individual probe
                # starts. Preserve a sanitized offline state for every RouterOS
                # diagnostic rather than surfacing the raw network exception.
                marker = RuntimeError("RouterOS session unavailable")
                router_error = router_error or marker
                security_error = security_error or marker
                inventory_error = inventory_error or marker
                service_error = service_error or marker

        router_ok = router_error is None and bool(router_health.get("connected"))
        checks.append(self._check(
            "routeros_api",
            "RouterOS API",
            _check_state(ok=router_ok, offline=not router_ok),
            "RouterOS reachable" if router_ok else "RouterOS unavailable",
            router_ms,
            connected=router_ok,
        ))

        security_ok = security_error is None and bool(security.get("enforcement_ready"))
        security_warning = security_ok and _int(security.get("warning_count")) > 0
        checks.append(self._check(
            "security_authority",
            "Security & authority",
            _check_state(ok=security_ok, warning=security_warning),
            "Write authority proven" if security_ok else "Write authority not proven",
            security_ms,
            score=_int(security.get("score")),
            critical=_int(security.get("critical_count")),
            warnings=_int(security.get("warning_count")),
        ))

        inv_counts = dict(inventory.get("counts") or {})
        inventory_ok = inventory_error is None and bool(inventory)
        checks.append(self._check(
            "managed_inventory",
            "Managed RouterOS inventory",
            _check_state(ok=inventory_ok, offline=not router_ok),
            "Managed inventory readable" if inventory_ok else "Managed inventory unavailable",
            inventory_ms,
            restricted_devices=_int(inv_counts.get("restricted_devices")),
            managed_address_entries=_int(inv_counts.get("managed_address_entries")),
            managed_queues=_int(inv_counts.get("managed_queues")),
            managed_schedulers=_int(inv_counts.get("managed_schedulers")),
            managed_scripts=_int(inv_counts.get("managed_scripts")),
            required_firewall_seen=_int(inv_counts.get("required_firewall_rules_seen")),
            required_firewall_expected=_int(inv_counts.get("required_firewall_rules_expected")),
        ))

        contracts_ok = service_error is None and bool(service_health.get("available", True))
        contracts_warning = contracts_ok and _int(service_health.get("degraded")) > 0
        checks.append(self._check(
            "service_contracts",
            "Service contracts",
            _check_state(ok=contracts_ok, warning=contracts_warning, offline=not router_ok),
            "Service contract evidence available" if contracts_ok else "Service contract evidence unavailable",
            service_ms,
            healthy=_int(service_health.get("healthy")),
            total=_int(service_health.get("total")),
            degraded=_int(service_health.get("degraded")),
            reporting_only=_int(service_health.get("reporting_only")),
            detector_addresses=_int(service_health.get("detector_addresses")),
        ))

        telemetry, telemetry_ms, telemetry_error = self._timed_call(self.activity_store.health)
        telemetry_ok = telemetry_error is None and bool(telemetry)
        checks.append(self._check(
            "telemetry",
            "Telemetry database",
            _check_state(ok=telemetry_ok, offline=not telemetry_ok),
            "PostgreSQL telemetry reachable" if telemetry_ok else "PostgreSQL telemetry unavailable",
            telemetry_ms,
            connected=telemetry_ok,
        ))

        if self.ingest_status_loader is not None:
            ingest, ingest_ms, ingest_error = self._timed_call(self.ingest_status_loader)
            ingest = ingest or {}
            ingest_availability = str(ingest.get("availability") or "unavailable")
            ingest_ok = ingest_error is None and ingest_availability == "available"
            checks.append(self._check(
                "traffic_ingest",
                "Traffic ingest",
                _check_state(ok=ingest_ok, offline=not ingest_ok),
                (
                    "Traffic-ingest heartbeat current"
                    if ingest_ok
                    else "Traffic-ingest heartbeat stale or unavailable"
                ),
                ingest_ms,
                availability=ingest_availability,
                age_seconds=ingest.get("age_seconds"),
                flow_queue_depth=(
                    max(0, _int(ingest.get("flow_queue_depth")))
                    if ingest_ok and ingest.get("flow_queue_depth") is not None else "unknown"
                ),
            ))

            for key, label, field in (
                ("dns_source", "Pi-hole DNS source", "dns_source"),
                ("ipfix_source", "IPFIX flow source", "ipfix_source"),
            ):
                source = str(ingest.get(field) or "unknown") if ingest_ok else "unknown"
                source_ok = ingest_ok and source == "available"
                if not ingest_ok:
                    summary = f"{label} cannot be proven while traffic-ingest status is unavailable"
                elif source == "available":
                    summary = f"{label} reachable by traffic-ingest"
                elif source == "unavailable":
                    summary = f"{label} unavailable to traffic-ingest"
                else:
                    summary = f"{label} state not yet proven"
                checks.append(self._check(
                    key,
                    label,
                    _check_state(ok=source_ok, offline=not source_ok),
                    summary,
                    source=source,
                ))

        if self.classifier_status_loader is not None:
            classifier, classifier_ms, classifier_error = self._timed_call(self.classifier_status_loader)
            classifier = classifier or {}
            classifier_availability = str(classifier.get("availability") or "unavailable")
            classifier_source = str(classifier.get("source") or "unknown")
            classifier_online = classifier_error is None and classifier_availability == "available"
            classifier_degraded = classifier_online and bool(classifier.get("degraded"))
            if not classifier_online:
                classifier_state = "offline"
                classifier_summary = "Classifier consumer heartbeat stale or unavailable"
            elif classifier_source == "stale_live":
                classifier_state = "warning"
                classifier_summary = "Classifier consumer retaining last-known-good live catalogue"
            elif classifier_source == "fallback":
                classifier_state = "warning"
                classifier_summary = "Classifier consumer using bootstrap fallback catalogue"
            elif classifier_degraded:
                classifier_state = "warning"
                classifier_summary = "Classifier consumer reports degraded catalogue evidence"
            else:
                classifier_state = "healthy"
                classifier_summary = "Classifier consumer live catalogue current"
            checks.append(self._check(
                "classifier_consumer",
                "Classifier consumer",
                classifier_state,
                classifier_summary,
                classifier_ms,
                availability=classifier_availability,
                source=classifier_source,
                services=(max(0, _int(classifier.get("services"))) if classifier_online else "unknown"),
                signatures=(max(0, _int(classifier.get("signatures"))) if classifier_online else "unknown"),
                has_live=(bool(classifier.get("has_live")) if classifier_online else "unknown"),
                age_seconds=classifier.get("age_seconds"),
            ))

        reconciler, reconciler_ms, reconciler_error = self._timed_call(self.reconciler.snapshot)
        reconciler = reconciler or {}
        rec_ok = reconciler_error is None and bool(reconciler.get("worker_alive"))
        rec_warning = rec_ok and (bool(reconciler.get("hold_active")) or _int(reconciler.get("consecutive_failures")) > 0)
        checks.append(self._check(
            "reconciler",
            "Reconciliation worker",
            _check_state(ok=rec_ok, warning=rec_warning),
            "Worker running" if rec_ok else "Worker unavailable or stopped",
            reconciler_ms,
            mode=(str(reconciler.get("mode") or "off") if reconciler_error is None else "unknown"),
            busy=(bool(reconciler.get("busy")) if reconciler_error is None else "unknown"),
            hold_active=(bool(reconciler.get("hold_active")) if reconciler_error is None else "unknown"),
            consecutive_failures=(_int(reconciler.get("consecutive_failures")) if reconciler_error is None else "unknown"),
            last_result=(str((reconciler.get("last") or {}).get("result") or "") if reconciler_error is None else "unknown"),
        ))

        incident, incident_ms, incident_error = self._timed_call(self.incident_monitor.snapshot)
        incident = incident or {}
        incident_enabled = bool(incident.get("enabled", True))
        incident_ok = incident_error is None and ((not incident_enabled) or bool(incident.get("worker_alive")))
        incident_counts = dict(incident.get("counts") or {})
        checks.append(self._check(
            "incidents",
            "Incident monitor",
            _check_state(ok=incident_ok, warning=_int(incident_counts.get("active")) > 0),
            "Worker running" if incident_ok else "Incident worker unavailable or stopped",
            incident_ms,
            enabled=(incident_enabled if incident_error is None else "unknown"),
            active=(_int(incident_counts.get("active")) if incident_error is None else "unknown"),
            resolved=(_int(incident_counts.get("resolved")) if incident_error is None else "unknown"),
        ))

        delivery, delivery_ms, delivery_error = self._timed_call(self.summary_delivery.snapshot)
        delivery = delivery or {}
        delivery_enabled = bool(delivery.get("enabled"))
        delivery_running = bool(delivery.get("worker_running"))
        delivery_ok = delivery_error is None and ((not delivery_enabled) or delivery_running)
        checks.append(self._check(
            "summary_delivery",
            "Parent summary delivery",
            _check_state(ok=delivery_ok),
            (
                "Delivery status unavailable" if delivery_error is not None
                else "Disabled by policy" if not delivery_enabled
                else "Worker running" if delivery_running
                else "Enabled worker stopped"
            ),
            delivery_ms,
            enabled=(delivery_enabled if delivery_error is None else "unknown"),
            worker_running=(delivery_running if delivery_error is None else "unknown"),
            pending=(_int((delivery.get("stats") or {}).get("pending")) if delivery_error is None else "unknown"),
            failed=(_int((delivery.get("stats") or {}).get("failed")) if delivery_error is None else "unknown"),
        ))

        snapshots, snapshots_ms, snapshots_error = self._timed_call(lambda: self.policy_store.list_config_snapshots(20))
        audit_count, audit_ms, audit_error = self._timed_call(self.policy_store.audit_count)
        snapshots = snapshots or []
        evidence_ok = snapshots_error is None and audit_error is None
        checks.append(self._check(
            "durable_evidence",
            "Durable evidence & recovery",
            _check_state(ok=evidence_ok, warning=evidence_ok and not snapshots),
            "Audit and recovery evidence readable" if evidence_ok else "Durable evidence unavailable",
            snapshots_ms + audit_ms,
            audit_events=_int(audit_count),
            snapshots=len(snapshots),
        ))

        counts = {
            state: sum(1 for item in checks if item["state"] == state)
            for state in ("healthy", "warning", "critical", "offline")
        }
        overall = (
            "critical" if counts["critical"] else
            "offline" if counts["offline"] else
            "warning" if counts["warning"] else
            "healthy"
        )

        perf_summary = perf.get("request_summary") or {}
        slow_routes = [
            {
                "route": str(row.get("route") or ""),
                "count": _int(row.get("count")),
                "p50_ms": _float(row.get("p50_ms")),
                "p95_ms": _float(row.get("p95_ms")),
                "max_ms": _float(row.get("max_ms")),
                "errors": _int(row.get("errors")),
            }
            for row in (perf.get("routes") or [])[:10]
        ]
        slow_components = [
            {
                "name": str(row.get("name") or ""),
                "count": _int(row.get("count")),
                "avg_ms": _float(row.get("avg_ms")),
                "p95_ms": _float(row.get("p95_ms")),
                "errors": _int(row.get("errors")),
            }
            for row in (perf.get("components") or [])[:10]
        ]

        return {
            "schema": DIAGNOSTIC_SCHEMA,
            "version": self.app_version,
            "captured_at": _now_iso(),
            "overall": overall,
            "counts": counts,
            "checks": checks,
            "performance": {
                "available": perf_error is None,
                "enabled": (bool(perf.get("enabled")) if perf_error is None else None),
                "requests": {
                    "retained": (_int(perf_summary.get("retained")) if perf_error is None else None),
                    "p50_ms": (_float(perf_summary.get("p50_ms")) if perf_error is None else None),
                    "p95_ms": (_float(perf_summary.get("p95_ms")) if perf_error is None else None),
                    "p99_ms": (_float(perf_summary.get("p99_ms")) if perf_error is None else None),
                    "max_ms": (_float(perf_summary.get("max_ms")) if perf_error is None else None),
                    "slow_count": (_int(perf_summary.get("slow_count")) if perf_error is None else None),
                },
                "slow_routes": slow_routes,
                "top_components": slow_components,
            },
            "privacy": {
                "sanitized": True,
                "omitted": [
                    "credentials and tokens",
                    "session/cookie material",
                    "RouterOS host and username",
                    "managed-device IP addresses",
                    "DNS query/domain contents",
                    "raw audit and incident details",
                    "raw exception/network error text",
                ],
            },
            "notes": [
                "Diagnostics are read-only and never repair RouterOS authority.",
                "A HEALTHY check means ZEN could prove that specific condition at capture time.",
                "Telemetry availability is evidence availability, not proof of user activity or browser history.",
                "Dependency checks are independent; one failed source never authorizes inferring another source healthy.",
                "RouterOS desired-policy history and live execution remain separate evidence boundaries.",
            ],
        }
