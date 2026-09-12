"""Read-only what-if composition for ZEN Control policy simulation.

Simulation compares baseline and proposed desired-policy output from the same
PolicyStore resolver used by live reconciliation.  It never writes policy or
RouterOS authority and it never predicts future telemetry/quota consumption.
"""

from app.policy_parity import policy_parity_contract


def _service_set(policy):
    return set((policy or {}).get("blocked_services") or [])


def _group_set(policy):
    return set((policy or {}).get("blocked_policy_groups") or [])


def _requested_service_set(policy):
    policy = dict(policy or {})
    groups = _group_set(policy)
    return set(policy.get("requested_blocked_services") or []) - groups


def _unsupported_set(policy):
    return set((policy or {}).get("unsupported_policy_keys") or [])


def _quota_contract(policy):
    quota = dict((policy or {}).get("quota_state") or {})
    daily = dict(quota.get("daily") or {})
    services = tuple(sorted(
        (str(row.get("key") or ""), int(row.get("limit_mb") or 0))
        for row in (quota.get("services") or [])
        if row.get("key")
    ))
    return {
        "configured": bool(quota.get("configured")),
        "enabled": bool(quota.get("enabled")),
        "available": bool(quota.get("available", True)),
        "daily_limit_mb": int(daily.get("limit_mb") or 0),
        "daily_action": str(daily.get("action") or "blocked"),
        "services": services,
    }


def _quota_label(contract):
    if not contract["configured"]:
        return "no quota"
    parts = []
    if contract["daily_limit_mb"]:
        parts.append(f"{contract['daily_limit_mb']} MiB/day → {contract['daily_action'].upper()}")
    if contract["services"]:
        parts.append(", ".join(f"{key} {limit} MiB" for key, limit in contract["services"]))
    if not contract["enabled"]:
        parts.append("engine off")
    elif not contract["available"]:
        parts.append("telemetry unavailable")
    return "; ".join(parts) or "quota configured"


def _action_label(action):
    action = dict(action or {})
    if not action:
        return None
    parts = [str(action.get("date") or "").strip(), str(action.get("time") or "").strip()]
    when = " ".join(part for part in parts if part)
    value = str(action.get("value") or "re-evaluate").upper()
    label = str(action.get("label") or "policy event")
    return f"{when} → {value} ({label})".strip()


def policy_delta(baseline, scenario):
    """Return deterministic, human-readable desired-policy deltas."""
    baseline = dict(baseline or {})
    scenario = dict(scenario or {})
    rows = []

    if baseline.get("mode") != scenario.get("mode"):
        rows.append({
            "kind": "mode",
            "label": "Device mode",
            "from": str(baseline.get("mode") or "normal").upper(),
            "to": str(scenario.get("mode") or "normal").upper(),
        })

    if baseline.get("bandwidth_preset") != scenario.get("bandwidth_preset"):
        rows.append({
            "kind": "bandwidth",
            "label": "Bandwidth",
            "from": str(baseline.get("bandwidth_name") or baseline.get("bandwidth_preset") or "Normal"),
            "to": str(scenario.get("bandwidth_name") or scenario.get("bandwidth_preset") or "Normal"),
        })

    before_services = _service_set(baseline)
    after_services = _service_set(scenario)
    added = sorted(after_services - before_services)
    removed = sorted(before_services - after_services)
    if added:
        rows.append({
            "kind": "service_block",
            "label": "Services newly blocked",
            "from": "—",
            "to": ", ".join(added),
            "items": added,
        })
    if removed:
        rows.append({
            "kind": "service_allow",
            "label": "Services newly allowed",
            "from": ", ".join(removed),
            "to": "allowed",
            "items": removed,
        })

    before_requested = _requested_service_set(baseline)
    after_requested = _requested_service_set(scenario)
    before_unsupported = _unsupported_set(baseline)
    after_unsupported = _unsupported_set(scenario)
    added_requests = sorted((after_requested - before_requested) & after_unsupported)
    removed_requests = sorted((before_requested - after_requested) & before_unsupported)
    if added_requests:
        rows.append({
            "kind": "service_request",
            "label": "Reporting-only blocks newly requested",
            "from": "—",
            "to": ", ".join(added_requests),
            "items": added_requests,
            "enforceable": False,
        })
    if removed_requests:
        rows.append({
            "kind": "service_request_removed",
            "label": "Reporting-only block requests removed",
            "from": ", ".join(removed_requests),
            "to": "not requested",
            "items": removed_requests,
            "enforceable": False,
        })

    before_groups = _group_set(baseline)
    after_groups = _group_set(scenario)
    added_groups = sorted(after_groups - before_groups)
    removed_groups = sorted(before_groups - after_groups)
    if added_groups:
        rows.append({
            "kind": "group_block",
            "label": "Policy groups newly blocked",
            "from": "—",
            "to": ", ".join(added_groups),
            "items": added_groups,
        })
    if removed_groups:
        rows.append({
            "kind": "group_allow",
            "label": "Policy groups newly allowed",
            "from": ", ".join(removed_groups),
            "to": "allowed",
            "items": removed_groups,
        })

    before_quota = _quota_contract(baseline)
    after_quota = _quota_contract(scenario)
    if before_quota != after_quota:
        rows.append({
            "kind": "quota_policy",
            "label": "Quota policy",
            "from": _quota_label(before_quota),
            "to": _quota_label(after_quota),
        })

    before_source = str(baseline.get("mode_source") or "default")
    after_source = str(scenario.get("mode_source") or "default")
    if before_source != after_source:
        rows.append({
            "kind": "source",
            "label": "Mode decision source",
            "from": before_source,
            "to": after_source,
        })

    before_next = _action_label(baseline.get("next_policy_action"))
    after_next = _action_label(scenario.get("next_policy_action"))
    if before_next != after_next:
        rows.append({
            "kind": "next_action",
            "label": "Next automatic policy event",
            "from": before_next or "none known",
            "to": after_next or "none known",
        })

    return rows


def _router_actions(live_plan):
    result = []
    for action in (live_plan or {}).get("planned_actions") or []:
        action = dict(action)
        kind = action.get("kind")
        if kind == "mode":
            label = "Device mode"
        elif kind == "service":
            label = f"Service {action.get('service', 'unknown')}"
        elif kind == "bandwidth":
            label = "Bandwidth queue"
        else:
            label = str(kind or "policy action")
        result.append({
            "kind": kind,
            "label": label,
            "from": str(action.get("from") or "unknown"),
            "to": str(action.get("to") or "unknown"),
            "supported": bool(action.get("supported", True)),
        })
    return result


def build_policy_simulation(*, address, device_name, baseline, scenario, scenario_label,
                            simulation_at, live_plan=None, live_error=None,
                            scope="device"):
    """Compose the stable zen_policy_simulation_v1 contract."""
    baseline = dict(baseline or {})
    scenario = dict(scenario or {})
    changes = policy_delta(baseline, scenario)
    live_actions = _router_actions(live_plan)
    return {
        "schema_version": "zen_policy_simulation_v1",
        "scope": scope,
        "device": {"ip": address, "name": device_name or address},
        "scenario_label": scenario_label,
        "simulation_at": simulation_at,
        "timezone": scenario.get("policy_timezone") or baseline.get("policy_timezone"),
        "baseline": baseline,
        "scenario": scenario,
        "baseline_contract": policy_parity_contract(baseline),
        "scenario_contract": policy_parity_contract(scenario),
        "changes": changes,
        "change_count": len(changes),
        "changed": bool(changes),
        "live_comparison": {
            "available": live_plan is not None,
            "error": live_error,
            "status": (live_plan or {}).get("status") if live_plan else "unavailable",
            "actions": live_actions,
            "action_count": len(live_actions),
            "note": (
                "These actions compare the simulated desired policy with RouterOS as it is now. "
                "They are not a prediction of future RouterOS state."
                if live_plan is not None else
                "No live RouterOS comparison was requested or it could not be read."
            ),
        },
        "quota_prediction": {
            "predicted": False,
            "note": (
                "Future quota consumption is not predicted. Quota enforcement in a future simulation "
                "is therefore fail-open unless explicit retained usage evidence is supplied."
            ),
        },
        "evidence_note": (
            "Simulation uses the same ZEN effective-policy resolver as reconciliation, against an in-memory "
            "proposed configuration. It does not write SQLite, RouterOS, schedules, queues, firewall rules, "
            "address lists or Kid Control."
        ),
    }


def build_profile_impact(*, profile_id, profile_name, simulation_at, rows):
    rows = list(rows or [])
    changed = [row for row in rows if row.get("changed")]
    mode_changes = sum(
        1 for row in changed
        if any(item.get("kind") == "mode" for item in row.get("changes") or [])
    )
    bandwidth_changes = sum(
        1 for row in changed
        if any(item.get("kind") == "bandwidth" for item in row.get("changes") or [])
    )
    service_changes = sum(
        1 for row in changed
        if any(str(item.get("kind") or "").startswith(("service_", "group_")) for item in row.get("changes") or [])
    )
    quota_changes = sum(
        1 for row in changed
        if any(item.get("kind") == "quota_policy" for item in row.get("changes") or [])
    )
    return {
        "schema_version": "zen_profile_impact_v1",
        "profile_id": profile_id,
        "profile_name": profile_name,
        "simulation_at": simulation_at,
        "device_count": len(rows),
        "changed_devices": len(changed),
        "unchanged_devices": len(rows) - len(changed),
        "mode_change_devices": mode_changes,
        "bandwidth_change_devices": bandwidth_changes,
        "service_change_devices": service_changes,
        "quota_change_devices": quota_changes,
        "rows": rows,
        "evidence_note": (
            "Profile impact is calculated in memory using the normal effective-policy resolver for devices "
            "currently assigned to this profile. No profile or RouterOS state is changed by previewing it."
        ),
    }
