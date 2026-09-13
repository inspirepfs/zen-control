"""Evidence-led household reporting helpers.

The reporting layer is deliberately read-only.  It composes retained telemetry,
local policy history and durable operations records without creating new
RouterOS authority or turning missing evidence into healthy/zero state.
"""

from __future__ import annotations

from datetime import datetime, timezone
from statistics import median

from app.activity import format_activity_bytes

REPORT_SCHEMA = "zen_reporting_overview_v1"


def _number(value) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def _pct_change(current: int, previous: int):
    current = _number(current)
    previous = _number(previous)
    if previous == 0:
        return None if current else 0.0
    return round((current - previous) * 100 / previous, 1)


def metric_change(current, previous, *, unit="count") -> dict:
    current = _number(current)
    previous = _number(previous)
    delta = current - previous
    result = {
        "current": current,
        "previous": previous,
        "delta": delta,
        "delta_percent": _pct_change(current, previous),
        "direction": "up" if delta > 0 else "down" if delta < 0 else "flat",
        "unit": unit,
    }
    if unit == "bytes":
        result.update({
            "current_human": format_activity_bytes(current),
            "previous_human": format_activity_bytes(previous),
            "delta_human": ("+" if delta > 0 else "-" if delta < 0 else "") + format_activity_bytes(abs(delta)),
        })
    return result


def rank_movers(current_rows, previous_rows, *, key, label, value="total_bytes", limit=10) -> list[dict]:
    """Compare ranked retained evidence without inventing values for missing rows."""
    current = {str(row.get(key) or ""): dict(row) for row in (current_rows or []) if str(row.get(key) or "")}
    previous = {str(row.get(key) or ""): dict(row) for row in (previous_rows or []) if str(row.get(key) or "")}
    result = []
    for identity in sorted(set(current) | set(previous)):
        now = _number(current.get(identity, {}).get(value))
        old = _number(previous.get(identity, {}).get(value))
        if now == old:
            continue
        row = current.get(identity) or previous.get(identity) or {}
        delta = now - old
        result.append({
            "key": identity,
            "label": str(row.get(label) or identity),
            "current": now,
            "previous": old,
            "delta": delta,
            "delta_percent": _pct_change(now, old),
            "current_human": format_activity_bytes(now),
            "previous_human": format_activity_bytes(old),
            "delta_human": ("+" if delta > 0 else "-") + format_activity_bytes(abs(delta)),
            "state": "new" if old == 0 and now > 0 else "inactive" if now == 0 and old > 0 else "changed",
        })
    result.sort(key=lambda item: (-abs(item["delta"]), item["label"].lower()))
    return result[: max(1, min(int(limit), 50))]


def _coverage_metric(current: dict, previous: dict, key: str, status_key: str) -> dict:
    current_status = str((current or {}).get(status_key) or "unknown")
    previous_status = str((previous or {}).get(status_key) or "unknown")
    current_value = (current or {}).get(key)
    previous_value = (previous or {}).get(key)
    if current_value is None or previous_value is None:
        delta = None
    else:
        delta = round(float(current_value) - float(previous_value), 1)
    return {
        "current": current_value,
        "previous": previous_value,
        "delta_points": delta,
        "current_status": current_status,
        "previous_status": previous_status,
    }


def build_reporting_overview(
    *,
    window: dict,
    current: dict,
    previous: dict,
    daily: list,
    current_devices: list,
    previous_devices: list,
    current_services: list,
    previous_services: list,
    new_domains: list,
    blocked_domains: list,
    classification_current: dict,
    classification_previous: dict,
    notification_report: dict,
    incident_report: dict,
    policy_history: dict,
    policy_window: dict,
    config_analytics: dict,
    generated_at: datetime | None = None,
) -> dict:
    generated_at = generated_at or datetime.now(timezone.utc)
    current = dict(current or {})
    previous = dict(previous or {})

    blocked = _number(current.get("dns_blocked"))
    dns_queries = _number(current.get("dns_queries"))
    previous_blocked = _number(previous.get("dns_blocked"))
    previous_dns = _number(previous.get("dns_queries"))
    current_block_rate = round(blocked * 100 / dns_queries, 1) if dns_queries else None
    previous_block_rate = round(previous_blocked * 100 / previous_dns, 1) if previous_dns else None

    devices = [dict(row) for row in (current_devices or [])]
    services = [dict(row) for row in (current_services or [])]
    for row in devices:
        row.setdefault("display_name", row.get("client_ip") or "Unknown")
    for row in services:
        row.setdefault("display_name", row.get("service_name") or "Other")

    report = {
        "schema": REPORT_SCHEMA,
        "generated_at": generated_at.isoformat(),
        "authority": "read-only-reporting-no-routeros-authority",
        "window": dict(window or {}),
        "evidence_note": (
            "Traffic and DNS figures are retained network evidence. Policy-history figures prove ZEN desired-policy "
            "checkpoints, not continuous historical RouterOS execution. UNKNOWN/UNAVAILABLE evidence is never converted to zero."
        ),
        "metrics": {
            "traffic": metric_change(current.get("total_bytes"), previous.get("total_bytes"), unit="bytes"),
            "download": metric_change(current.get("download_bytes"), previous.get("download_bytes"), unit="bytes"),
            "upload": metric_change(current.get("upload_bytes"), previous.get("upload_bytes"), unit="bytes"),
            "flows": metric_change(current.get("flows"), previous.get("flows")),
            "dns_queries": metric_change(current.get("dns_queries"), previous.get("dns_queries")),
            "blocked_dns": metric_change(current.get("dns_blocked"), previous.get("dns_blocked")),
            "unique_domains": metric_change(current.get("unique_domains"), previous.get("unique_domains")),
            "active_devices": metric_change(current.get("active_devices"), previous.get("active_devices")),
        },
        "classification": {
            "traffic": _coverage_metric(classification_current, classification_previous, "traffic_percent", "traffic_evidence_status"),
            "dns": _coverage_metric(classification_current, classification_previous, "dns_percent", "dns_evidence_status"),
            "current_evidence_status": str((classification_current or {}).get("evidence_status") or "unknown"),
            "previous_evidence_status": str((classification_previous or {}).get("evidence_status") or "unknown"),
        },
        "policy_signals": {
            "dns_block_rate": current_block_rate,
            "previous_dns_block_rate": previous_block_rate,
            "dns_block_rate_delta_points": (
                round(current_block_rate - previous_block_rate, 1)
                if current_block_rate is not None and previous_block_rate is not None else None
            ),
            "blocked_domains": len(blocked_domains or []),
            "new_domains": len(new_domains or []),
            "policy_history_checkpoints": _number((policy_history or {}).get("checkpoints")),
            "policy_history_addresses": _number((policy_history or {}).get("addresses")),
            "profiles": _number(((config_analytics or {}).get("counts") or {}).get("profiles")),
            "managed_devices": _number(((config_analytics or {}).get("counts") or {}).get("device_policy")),
            "services": _number(((config_analytics or {}).get("counts") or {}).get("services")),
            "window_checkpoints": _number((policy_window or {}).get("checkpoints")),
            "schedule_active_checkpoints": _number((policy_window or {}).get("schedule_active_checkpoints")),
            "blocked_mode_checkpoints": _number((policy_window or {}).get("blocked_mode_checkpoints")),
            "quota_configured_checkpoints": _number((policy_window or {}).get("quota_configured_checkpoints")),
            "quota_active_checkpoints": _number((policy_window or {}).get("quota_active_checkpoints")),
            "quota_daily_exhausted_checkpoints": _number((policy_window or {}).get("quota_daily_exhausted_checkpoints")),
            "quota_service_active_checkpoints": _number((policy_window or {}).get("quota_service_active_checkpoints")),
            "quota_unavailable_checkpoints": _number((policy_window or {}).get("quota_unavailable_checkpoints")),
        },
        "notifications": dict(notification_report or {}),
        "incidents": dict(incident_report or {}),
        "daily": list(daily or []),
        "top_devices": devices[:12],
        "top_services": services[:12],
        "device_movers": rank_movers(
            current_devices, previous_devices, key="client_ip", label="display_name", value="total_bytes", limit=10
        ),
        "service_movers": rank_movers(
            current_services, previous_services, key="service_name", label="display_name", value="total_bytes", limit=10
        ),
        "new_domains": list(new_domains or [])[:20],
        "blocked_domains": list(blocked_domains or [])[:20],
    }
    return report
