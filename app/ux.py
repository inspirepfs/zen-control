from __future__ import annotations

from typing import Any


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _state(*, critical: bool = False, warning: bool = False, offline: bool = False) -> str:
    if critical:
        return "critical"
    if offline:
        return "offline"
    if warning:
        return "warning"
    return "healthy"


def build_connected_overview(
    *,
    live_status: dict,
    devices: list[dict],
    policy_plans: dict[str, dict],
    security_posture: dict,
    reconciler_status: dict,
    service_contract_health: dict,
    telemetry_available: bool,
    activity_insights: dict,
    database_integrity: dict,
    operations_startup: dict,
    incident_counts: dict,
    audit_total: int,
) -> dict:
    """Compose existing controller evidence into a compact product-health view.

    This is intentionally a presentation/integration layer. It does not infer
    behaviour, mutate policy, or create RouterOS authority.
    """
    plans = [policy_plans.get(str(d.get("ip") or ""), {}) for d in devices]
    drift = sum(1 for plan in plans if plan.get("status") in {"drift", "partial"})
    errors = sum(1 for plan in plans if plan.get("status") == "error" or plan.get("error"))
    temporary = sum(1 for plan in plans if plan.get("status") == "temporary")
    quota_active = sum(1 for plan in plans if (plan.get("quota_state") or {}).get("active"))
    actionable = sum(1 for plan in plans if plan.get("policy_actionable"))

    mode = str(live_status.get("mode") or "unknown").upper()
    router_error = bool(live_status.get("error")) or mode == "ERROR"
    rec_mode = str(reconciler_status.get("mode") or "off").upper()
    rec_hold = bool(reconciler_status.get("hold_active"))
    rec_alive = bool(reconciler_status.get("worker_alive", True))

    critical_checks = _int(security_posture.get("critical_count"))
    warning_checks = _int(security_posture.get("warning_count"))
    enforcement_ready = bool(security_posture.get("enforcement_ready"))
    security_state = _state(
        critical=not enforcement_ready or critical_checks > 0,
        warning=warning_checks > 0,
    )

    contracts_total = _int(service_contract_health.get("total"))
    contracts_healthy = _int(service_contract_health.get("healthy"))
    contracts_degraded = _int(service_contract_health.get("degraded"))
    reporting_only = _int(service_contract_health.get("reporting_only"))
    service_available = bool(service_contract_health.get("available", True))
    service_state = _state(
        critical=not service_available,
        warning=contracts_degraded > 0,
    )

    managed_total = len(devices)
    managed_seen = _int(activity_insights.get("managed_devices_seen"))
    traffic_classified = activity_insights.get("traffic_classified_percent")
    dns_classified = activity_insights.get("dns_classified_percent")
    traffic_classification_status = str(
        activity_insights.get("traffic_classification_status")
        or ("measured" if traffic_classified is not None else "no_evidence")
    ).lower()
    dns_classification_status = str(
        activity_insights.get("dns_classification_status")
        or ("measured" if dns_classified is not None else "no_evidence")
    ).lower()
    unknown_domains = _int(activity_insights.get("unknown_domains"))

    def _classification_fact(label, status, value):
        if status == "measured" and value is not None:
            try:
                return f"{label} {float(value):.1f}% classified"
            except (TypeError, ValueError):
                return f"{label} UNKNOWN"
        if status == "no_evidence":
            return f"{label} NO EVIDENCE"
        if status == "unavailable":
            return f"{label} UNAVAILABLE"
        if status == "inconsistent":
            return f"{label} INCONSISTENT"
        return f"{label} UNKNOWN"

    classification_warning = any(
        status in {"unavailable", "inconsistent"}
        for status in (traffic_classification_status, dns_classification_status)
    )

    database_ok = bool(database_integrity.get("ok"))
    startup_status = str(operations_startup.get("status") or "unknown").lower()
    active_incidents = _int(incident_counts.get("active"))
    operations_state = _state(
        critical=not database_ok,
        warning=startup_status not in {"ready", "ok"} or active_incidents > 0,
    )

    areas = [
        {
            "key": "control",
            "name": "Control & policy",
            "state": _state(
                critical=router_error or errors > 0,
                warning=drift > 0 or rec_hold or not rec_alive,
            ),
            "headline": f"{mode} · {managed_total} managed device{'s' if managed_total != 1 else ''}",
            "facts": [
                f"{drift} out of sync",
                f"{actionable} actionable",
                f"{temporary} temporary",
                f"{quota_active} quota-active",
                f"reconciler {rec_mode}",
            ],
            "primary": {"label": "Managed devices", "href": "/?view=devices&section=managed#devices/managed"},
            "secondary": {"label": "Policy assignments", "href": "/?view=policies&section=assignments#policies/assignments"},
        },
        {
            "key": "security",
            "name": "Security & authority",
            "state": security_state,
            "headline": (
                "Write gate OPEN" if enforcement_ready else "Write gate CLOSED"
            ),
            "facts": [
                f"score {_int(security_posture.get('score'))}%",
                f"{critical_checks} critical",
                f"{warning_checks} warnings",
            ],
            "primary": {"label": "Security posture", "href": "/?view=settings&section=security#settings/security"},
            "secondary": {"label": "Incidents", "href": "/?view=incidents&section=active#incidents/active"},
        },
        {
            "key": "services",
            "name": "Service intelligence",
            "state": service_state,
            "headline": f"{contracts_healthy}/{contracts_total} RouterOS contracts healthy",
            "facts": [
                f"{contracts_degraded} degraded",
                f"{reporting_only} reporting-only",
                f"{_int(service_contract_health.get('detector_addresses'))} learned destinations",
            ],
            "primary": {"label": "Service contracts", "href": "/?view=policies&section=services#policies/services"},
            "secondary": {"label": "Service activity", "href": "/?view=activity&section=services#activity/services"},
        },
        {
            "key": "activity",
            "name": "Activity & analytics",
            "state": _state(
                warning=telemetry_available and classification_warning,
                offline=not telemetry_available,
            ),
            "headline": (
                f"Telemetry online · {managed_seen}/{managed_total} managed devices seen"
                if telemetry_available
                else "Telemetry unavailable"
            ),
            "facts": (
                [
                    _classification_fact("traffic", traffic_classification_status, traffic_classified),
                    _classification_fact("DNS", dns_classification_status, dns_classified),
                    (
                        f"{unknown_domains} unknown domains"
                        if dns_classification_status == "measured"
                        else f"unknown domains {dns_classification_status.replace('_', ' ').upper()}"
                    ),
                ]
                if telemetry_available
                else ["classification unavailable", "DNS evidence unavailable", "no telemetry inference"]
            ),
            "primary": {"label": "Activity overview", "href": "/?view=activity&section=overview#activity/overview"},
            "secondary": {"label": "Historical analytics", "href": "/?view=activity&section=history#activity/history"},
        },
        {
            "key": "operations",
            "name": "Operations & evidence",
            "state": operations_state,
            "headline": (
                f"Database {'OK' if database_ok else 'FAILED'} · startup {startup_status.upper()}"
            ),
            "facts": [
                f"{active_incidents} active incidents",
                f"{_int(incident_counts.get('resolved'))} resolved",
                f"{_int(audit_total)} audit events",
            ],
            "primary": {"label": "Operations", "href": "/?view=settings&section=operations#settings/operations"},
            "secondary": {"label": "Diagnostics", "href": "/diagnostics"},
        },
    ]

    counts = {name: sum(1 for area in areas if area["state"] == name) for name in ("healthy", "warning", "critical", "offline")}
    overall = "critical" if counts["critical"] else "offline" if counts["offline"] else "warning" if counts["warning"] else "healthy"
    return {
        "state": overall,
        "counts": counts,
        "areas": areas,
        "device_counts": {
            "managed": managed_total,
            "drift": drift,
            "errors": errors,
            "actionable": actionable,
            "temporary": temporary,
            "quota_active": quota_active,
        },
    }


_AUDIT_DESTINATIONS = (
    (("AUTH_", "LOGIN_", "SESSION_", "TOTP_", "RECOVERY_"), ("Parent access", "/?view=settings&section=parents#settings/parents")),
    (("MODE_", "TEMP_NORMAL", "WEB_POLICY"), ("Internet controls", "/?view=dashboard&section=controls#dashboard/controls")),
    (("DEVICE_", "LOCAL_DEVICE_", "REWARD_"), ("Managed devices", "/?view=devices&section=managed#devices/managed")),
    (("AGGREGATE_POLICY_GROUP_",), ("Aggregate policy groups", "/?view=policies&section=tools#policies/tools")),
    (("LOCAL_PROFILE_", "PROFILE_", "POLICY_"), ("Policies", "/?view=policies&section=profiles#policies/profiles")),
    (("SERVICE_", "CUSTOM_SERVICE_"), ("Services", "/?view=policies&section=services#policies/services")),
    (("SCHEDULE_", "DATE_EXCEPTION_"), ("Schedules", "/?view=schedules&section=planner#schedules/planner")),
    (("QUOTA_",), ("Quota settings", "/?view=settings&section=policy#settings/policy")),
    (("SECURITY_", "BYPASS_"), ("Security", "/?view=settings&section=security#settings/security")),
    (("INCIDENT_",), ("Incidents", "/?view=incidents&section=active#incidents/active")),
    (("RECONCILE_", "AUTO_RECONCILE_"), ("Reconciliation", "/?view=settings&section=automation#settings/automation")),
    (("SUMMARY_DELIVERY_", "SUMMARY_"), ("Summary delivery", "/?view=settings&section=automation#settings/automation")),
    (("CONFIG_", "STARTUP_", "OPERATIONS_", "ROUTER_READ_"), ("Operations", "/?view=settings&section=operations#settings/operations")),
)


def audit_destination(event: str) -> dict | None:
    key = str(event or "").upper()
    for prefixes, destination in _AUDIT_DESTINATIONS:
        if key.startswith(prefixes):
            return {"label": destination[0], "href": destination[1]}
    return None


def incident_destination(source: str) -> dict:
    key = str(source or "").lower()
    mapping = {
        "security": ("Security posture", "/?view=settings&section=security#settings/security"),
        "bypass": ("Bypass evidence", "/?view=settings&section=security#settings/security"),
        "activity": ("Activity", "/?view=activity&section=overview#activity/overview"),
        "reconciler": ("Reconciliation", "/?view=settings&section=automation#settings/automation"),
        "operations": ("Operations", "/?view=settings&section=operations#settings/operations"),
        "database": ("Operations", "/?view=settings&section=operations#settings/operations"),
        "router": ("Managed devices", "/?view=devices&section=managed#devices/managed"),
        "service": ("Service contracts", "/?view=policies&section=services#policies/services"),
    }
    label, href = mapping.get(key, ("Incident centre", "/?view=incidents&section=active#incidents/active"))
    return {"label": label, "href": href}
