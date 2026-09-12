"""Parent-facing daily summary composition.

This module only combines evidence already produced by ZEN Control.  It does
not infer browser history, application foreground time, user identity, or risk.
"""

from app.activity import compare_activity_totals


def _int(value):
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _delta_label(delta):
    if delta is None:
        return "new"
    if delta > 0:
        return "up"
    if delta < 0:
        return "down"
    return "flat"


def merge_attention_domains(new_domains, blocked_domains, limit=8):
    """Merge deterministic DNS signals without inventing an anomaly score.

    A domain is surfaced because it is new to the selected device/window,
    blocked by DNS policy, or both.  Missing service attribution is exposed as
    an additional evidence tag rather than treated as suspicious by itself.
    """
    limit = max(1, min(int(limit), 50))
    merged = {}

    for row in new_domains or []:
        domain = str(row.get("domain") or "").strip().lower()
        if not domain:
            continue
        item = merged.setdefault(domain, {
            "domain": domain,
            "service": str(row.get("service") or ""),
            "queries": 0,
            "blocked": 0,
            "first_seen": row.get("first_seen"),
            "last_seen": row.get("last_seen"),
            "tags": set(),
        })
        item["queries"] = max(item["queries"], _int(row.get("queries")))
        item["blocked"] = max(item["blocked"], _int(row.get("blocked")))
        item["service"] = item["service"] or str(row.get("service") or "")
        item["first_seen"] = item["first_seen"] or row.get("first_seen")
        item["last_seen"] = row.get("last_seen") or item["last_seen"]
        item["tags"].add("new")

    for row in blocked_domains or []:
        domain = str(row.get("domain") or "").strip().lower()
        if not domain:
            continue
        item = merged.setdefault(domain, {
            "domain": domain,
            "service": str(row.get("service") or ""),
            "queries": 0,
            "blocked": 0,
            "first_seen": row.get("first_seen"),
            "last_seen": row.get("last_seen"),
            "tags": set(),
        })
        item["queries"] = max(item["queries"], _int(row.get("queries")))
        item["blocked"] = max(item["blocked"], _int(row.get("blocked")))
        item["service"] = item["service"] or str(row.get("service") or "")
        item["first_seen"] = item["first_seen"] or row.get("first_seen")
        item["last_seen"] = row.get("last_seen") or item["last_seen"]
        item["tags"].add("blocked")

    rows = []
    for item in merged.values():
        if not item["service"]:
            item["tags"].add("unclassified")
        item["tags"] = sorted(item["tags"], key=lambda tag: {"blocked": 0, "new": 1, "unclassified": 2}.get(tag, 9))
        rows.append(item)

    rows.sort(key=lambda item: (
        -item["blocked"],
        0 if "new" in item["tags"] else 1,
        -item["queries"],
        item["domain"],
    ))
    return rows[:limit]


def build_parent_device_summary(
    *,
    ip,
    name,
    profile_name,
    current,
    previous,
    services,
    new_domains,
    blocked_domains,
    quota=None,
    quota_current=False,
):
    """Build a stable API/UI contract for one managed device."""
    current = dict(current or {})
    previous = dict(previous or {})
    comparison = compare_activity_totals(current, previous)
    attention_domains = merge_attention_domains(new_domains, blocked_domains, 8)
    quota = dict(quota or {})
    daily_quota = dict(quota.get("daily") or {})
    service_quotas = list(quota.get("services") or [])

    quota_warning = bool(
        quota_current
        and quota.get("configured")
        and (
            daily_quota.get("warning")
            or any(item.get("warning") for item in service_quotas)
        )
    )
    quota_exhausted = bool(
        quota_current
        and quota.get("configured")
        and (
            daily_quota.get("exhausted")
            or any(item.get("exhausted") for item in service_quotas)
        )
    )

    tags = []
    if _int(current.get("dns_blocked")):
        tags.append("blocked_dns")
    if new_domains:
        tags.append("new_domains")
    if any("unclassified" in item.get("tags", []) for item in attention_domains):
        tags.append("unclassified_new")
    if quota_warning:
        tags.append("quota_warning")
    if quota_exhausted:
        tags.append("quota_exhausted")

    total_delta = comparison.get("total_bytes", {}).get("delta_percent")
    return {
        "ip": str(ip),
        "name": str(name or ip),
        "profile_name": str(profile_name or "Unassigned"),
        "active": bool(_int(current.get("total_bytes")) or _int(current.get("dns_queries"))),
        "current": current,
        "previous": previous,
        "comparison": comparison,
        "traffic_delta_label": _delta_label(total_delta),
        "services": list(services or []),
        "new_domains": list(new_domains or []),
        "blocked_domains": list(blocked_domains or []),
        "attention_domains": attention_domains,
        "new_domain_count": len(new_domains or []),
        "unclassified_new_count": sum(1 for row in new_domains or [] if not str(row.get("service") or "").strip()),
        "signals": tags,
        "signal_count": len(tags),
        "quota": quota,
        "quota_current": bool(quota_current),
        "quota_warning": quota_warning,
        "quota_exhausted": quota_exhausted,
    }


def summarize_parent_household(device_summaries):
    """Aggregate managed-device summary facts without double-counting DNS names."""
    rows = list(device_summaries or [])
    numeric_keys = (
        "total_bytes", "download_bytes", "upload_bytes", "attributed_bytes",
        "flows", "dns_queries", "dns_blocked", "unique_domains",
    )
    current = {key: sum(_int(row.get("current", {}).get(key)) for row in rows) for key in numeric_keys}
    previous = {key: sum(_int(row.get("previous", {}).get(key)) for row in rows) for key in numeric_keys}

    current["attributed_percent"] = round(
        current["attributed_bytes"] * 100 / max(current["total_bytes"], 1), 1
    )
    previous["attributed_percent"] = round(
        previous["attributed_bytes"] * 100 / max(previous["total_bytes"], 1), 1
    )

    # Human byte labels are supplied by the ActivityStore per-device rows.  The
    # caller may add aggregate human labels with the shared activity formatter.
    new_domains = {
        str(item.get("domain") or "").lower()
        for row in rows for item in row.get("new_domains", [])
        if item.get("domain")
    }
    unclassified_new = {
        str(item.get("domain") or "").lower()
        for row in rows for item in row.get("new_domains", [])
        if item.get("domain") and not str(item.get("service") or "").strip()
    }
    blocked_domains = {
        str(item.get("domain") or "").lower()
        for row in rows for item in row.get("blocked_domains", [])
        if item.get("domain")
    }

    return {
        "managed_devices": len(rows),
        "active_devices": sum(1 for row in rows if row.get("active")),
        "devices_with_signals": sum(1 for row in rows if row.get("signal_count")),
        "quota_warnings": sum(1 for row in rows if row.get("quota_warning")),
        "quota_exhausted": sum(1 for row in rows if row.get("quota_exhausted")),
        "new_domains": len(new_domains),
        "unclassified_new_domains": len(unclassified_new),
        "blocked_domains": len(blocked_domains),
        "current": current,
        "previous": previous,
        "comparison": compare_activity_totals(current, previous),
    }
