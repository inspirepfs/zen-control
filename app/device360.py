"""Read-only Device 360 composition for ZEN Control.

Device 360 deliberately composes existing evidence.  It does not decide policy,
change RouterOS, infer user identity, or turn unavailable telemetry into zeroes.
"""

from app.activity import compare_activity_totals


def _identity_tokens(address, name):
    tokens = [str(address or "").strip().lower()]
    display = str(name or "").strip().lower()
    if len(display) >= 3 and display not in tokens:
        tokens.append(display)
    return [token for token in tokens if token]


def record_mentions_device(record, address, name):
    """Return True only when a record explicitly contains device identity text."""
    record = dict(record or {})
    haystack = " ".join(
        str(record.get(key) or "")
        for key in (
            "subject", "title", "detail", "fingerprint", "source",
            "event", "actor", "user", "resolution",
        )
    ).lower()
    return any(token in haystack for token in _identity_tokens(address, name))


def filter_related_records(records, address, name, limit=10):
    """Select explicitly device-related records without fuzzy/risk inference."""
    try:
        limit = max(1, min(int(limit), 50))
    except (TypeError, ValueError):
        limit = 10
    return [
        dict(row) for row in (records or [])
        if record_mentions_device(row, address, name)
    ][:limit]


def build_device_360_snapshot(
    *,
    explanation,
    reward_account=None,
    activity=None,
    activity_error=None,
    incidents=(),
    audit_events=(),
):
    """Compose the stable read-only Device 360 contract."""
    explanation = dict(explanation or {})
    device = dict(explanation.get("device") or {})
    summary = dict(explanation.get("summary") or {})
    reward = dict(reward_account or {})
    activity = dict(activity or {})

    if activity_error:
        activity_payload = {
            "available": False,
            "error": str(activity_error),
            "current": None,
            "previous": None,
            "comparison": None,
            "services": [],
            "new_domains": [],
            "blocked_domains": [],
            "timeline": [],
        }
    else:
        current = dict(activity.get("current") or {})
        previous = dict(activity.get("previous") or {})
        activity_payload = {
            "available": True,
            "error": None,
            "window": dict(activity.get("window") or {}),
            "current": current,
            "previous": previous,
            "comparison": compare_activity_totals(current, previous),
            "services": list(activity.get("services") or []),
            "new_domains": list(activity.get("new_domains") or []),
            "blocked_domains": list(activity.get("blocked_domains") or []),
            "timeline": list(activity.get("timeline") or []),
        }

    policy_services = list(explanation.get("services") or [])
    service_counts = {
        "defined": len(policy_services),
        "blocked": sum(1 for row in policy_services if row.get("desired_blocked")),
        "requested_only": sum(1 for row in policy_services if row.get("desired") == "BLOCK REQUESTED"),
        "drift": sum(1 for row in policy_services if row.get("drift")),
        "reporting_only": sum(
            1 for row in policy_services
            if row.get("enforcement_state") == "reporting_only"
            or (not row.get("enforcement_state") and row.get("live") == "NO CONTRACT")
        ),
        "degraded": sum(
            1 for row in policy_services
            if row.get("enforcement_state") == "degraded"
            or (not row.get("enforcement_state") and row.get("live") == "DEGRADED")
        ),
        "unavailable": sum(
            1 for row in policy_services
            if row.get("enforcement_state") == "unavailable"
            or (not row.get("enforcement_state") and row.get("live") == "UNAVAILABLE")
        ),
        "unsupported": sum(
            1 for row in policy_services
            if row.get("enforcement_state") == "unsupported"
            or (not row.get("enforcement_state") and row.get("live") == "UNSUPPORTED")
        ),
        "unknown": sum(
            1 for row in policy_services
            if row.get("enforcement_state") == "unknown"
            or (not row.get("enforcement_state") and row.get("live") == "UNKNOWN")
        ),
    }
    service_attention = sorted(
        policy_services,
        key=lambda row: (
            0 if row.get("drift") else 1,
            0 if row.get("desired_blocked") else 1,
            0 if row.get("enforcement_state") == "reporting_only" or row.get("live") == "NO CONTRACT" else 1,
            0 if row.get("enforcement_state") == "unavailable" or row.get("live") == "UNAVAILABLE" else 1,
            str(row.get("name") or row.get("key") or "").lower(),
        ),
    )[:10]

    active_incidents = [row for row in incidents if row.get("status") != "resolved"]
    incident_counts = {
        "active": len(active_incidents),
        "critical": sum(1 for row in active_incidents if row.get("severity") == "critical"),
        "warning": sum(1 for row in active_incidents if row.get("severity") == "warning"),
    }

    return {
        "schema_version": "zen_device_360_v1",
        "device": device,
        "summary": summary,
        "headline": summary.get("headline") or "Device state is available from the policy explanation contract.",
        "policy": explanation,
        "desired_contract": dict(explanation.get("desired_contract") or {}),
        "access": {
            "temporary": bool(summary.get("temporary")),
            "reward": reward,
            "quota": dict(explanation.get("quota") or {}),
        },
        "service_counts": service_counts,
        "service_attention": service_attention,
        "activity": activity_payload,
        "incidents": list(incidents or []),
        "incident_counts": incident_counts,
        "audit": list(audit_events or []),
        "next_changes": list(explanation.get("next_changes") or []),
        "limitations": list(explanation.get("limitations") or []),
        "links": {
            **dict(explanation.get("links") or {}),
            "self": f"/devices/{device.get('ip', '')}",
        },
        "evidence_note": (
            "Device 360 composes ZEN policy, fresh RouterOS state when available, retained IPFIX/Pi-hole evidence, "
            "and explicit device matches in incidents/audit. It is not browser history, foreground-app time, "
            "proof of who used the device, or a behavioural/risk score."
        ),
    }
