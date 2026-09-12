"""Canonical read-only desired-policy projection shared by parity surfaces."""


def policy_parity_contract(policy):
    policy = dict(policy or {})
    quota = dict(policy.get("quota_state") or {})
    exception = dict(policy.get("active_date_exception") or {})
    return {
        "mode": str(policy.get("mode") or "normal"),
        "mode_source": str(policy.get("mode_source") or "default"),
        "base_mode": str(policy.get("base_mode") or "normal"),
        "base_mode_source": str(policy.get("base_mode_source") or "default"),
        "bandwidth_preset": str(policy.get("bandwidth_preset") or "normal"),
        "blocked_services": sorted(set(policy.get("blocked_services") or [])),
        "requested_blocked_services": sorted(set(policy.get("requested_blocked_services") or [])),
        "blocked_policy_groups": sorted(set(policy.get("blocked_policy_groups") or [])),
        "unsupported_policy_keys": sorted(set(policy.get("unsupported_policy_keys") or [])),
        "unsupported_policy_group_members": sorted(set(policy.get("unsupported_policy_group_members") or [])),
        "schedule_active": bool(policy.get("schedule_active")),
        "schedule_reason": policy.get("schedule_reason"),
        "active_date_exception": exception.get("label") if exception else None,
        "quota_configured": bool(quota.get("configured")),
        "quota_available": bool(quota.get("available", True)),
        "quota_active": bool(policy.get("quota_active") or quota.get("active")),
        "policy_at": policy.get("policy_at"),
        "policy_timezone": policy.get("policy_timezone"),
    }
