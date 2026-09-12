"""Historical policy-state correlation for ZEN Control.

The correlation contract is deliberately evidence-led. Retained network
telemetry is aligned with durable desired-policy checkpoints captured by the
real effective-policy resolver. v0.49 additionally binds new checkpoints to a
management identity epoch so an IP address reused by different hardware cannot
silently inherit the previous device's policy history.

Legacy pre-v0.49 history remains IP-scoped and is never back-bound to a current
identity because ZEN cannot prove that the physical device was the same.
Desired-policy checkpoints are not historical RouterOS execution proof.
"""

from __future__ import annotations

from datetime import datetime, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


def _parse(value):
    if isinstance(value, datetime):
        observed = value
    else:
        observed = datetime.fromisoformat(str(value))
    if observed.tzinfo is None:
        observed = observed.replace(tzinfo=timezone.utc)
    return observed.astimezone(timezone.utc)


def _local(value, timezone_name):
    try:
        tz = ZoneInfo(timezone_name)
    except ZoneInfoNotFoundError:
        tz = ZoneInfo("UTC")
    return _parse(value).astimezone(tz).strftime("%Y-%m-%d %H:%M")


def _unknown_interval(start_dt, end_dt, *, identity_known, reason):
    return {
        "start": start_dt.isoformat(),
        "end": end_dt.isoformat(),
        "known": False,
        "identity_known": bool(identity_known),
        "gap_reason": str(reason),
        "state": None,
        "state_hash": "",
    }


def build_policy_intervals(history, start, end, identity_start=None):
    """Turn ordered checkpoints into non-overlapping correlation intervals.

    ``identity_start`` is the start of the current physical-management epoch.
    Time before that instant is explicitly ``identity_unproven``. Time inside
    the epoch but before its first desired-policy checkpoint is
    ``policy_unobserved``. Neither gap is reconstructed from later policy.

    All ordering uses physical UTC instants, never lexical ISO-8601 ordering,
    so DST/offset changes cannot reorder checkpoints.
    """
    start_dt = _parse(start)
    end_dt = _parse(end)
    if end_dt <= start_dt:
        raise ValueError("Policy correlation end must be after start")

    ordered = sorted(
        (dict(item) for item in history or []),
        key=lambda item: (_parse(item["captured_at"]), int(item.get("id") or 0)),
    )

    intervals = []
    policy_start = start_dt
    identity_start_dt = _parse(identity_start) if identity_start else None

    if identity_start_dt is not None and identity_start_dt > start_dt:
        identity_gap_end = min(identity_start_dt, end_dt)
        if identity_gap_end > start_dt:
            intervals.append(
                _unknown_interval(
                    start_dt,
                    identity_gap_end,
                    identity_known=False,
                    reason="identity_unproven",
                )
            )
        if identity_start_dt >= end_dt:
            return intervals
        policy_start = identity_start_dt

    before = [
        item for item in ordered
        if _parse(item["captured_at"]) <= policy_start
    ]
    inside = [
        item for item in ordered
        if policy_start < _parse(item["captured_at"]) < end_dt
    ]
    active = before[-1] if before else None
    cursor = policy_start

    if active is None and inside:
        first = _parse(inside[0]["captured_at"])
        if first > cursor:
            intervals.append(
                _unknown_interval(
                    cursor,
                    first,
                    identity_known=True,
                    reason="policy_unobserved",
                )
            )
        active = inside.pop(0)
        cursor = first

    if active is None and not inside:
        intervals.append(
            _unknown_interval(
                policy_start,
                end_dt,
                identity_known=True,
                reason="policy_unobserved",
            )
        )
        return intervals

    for change in inside:
        change_at = _parse(change["captured_at"])
        if change_at > cursor:
            intervals.append({
                "start": cursor.isoformat(),
                "end": change_at.isoformat(),
                "known": True,
                "identity_known": True,
                "gap_reason": "",
                "state": dict(active),
                "state_hash": str(active.get("state_hash") or ""),
            })
        active = change
        cursor = change_at

    if cursor < end_dt:
        intervals.append({
            "start": cursor.isoformat(),
            "end": end_dt.isoformat(),
            "known": True,
            "identity_known": True,
            "gap_reason": "",
            "state": dict(active),
            "state_hash": str(active.get("state_hash") or ""),
        })
    return intervals


def _aggregate_source_status(statuses):
    values = [str(item or "no_evidence").lower() for item in statuses]
    if not values:
        return "no_evidence"
    if "inconsistent" in values:
        return "inconsistent"
    unavailable = sum(value == "unavailable" for value in values)
    if unavailable == len(values):
        return "unavailable"
    if unavailable:
        return "partial"
    if "measured" in values:
        return "measured"
    if "partial" in values:
        return "partial"
    return "no_evidence"


def _aggregate_telemetry_status(traffic_status, dns_status):
    statuses = {traffic_status, dns_status}
    if "inconsistent" in statuses:
        return "inconsistent"
    if statuses == {"unavailable"}:
        return "unavailable"
    if "unavailable" in statuses or "partial" in statuses:
        return "partial"
    if "measured" in statuses:
        return "measured"
    return "no_evidence"


def _safe_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _collection_status(payload):
    payload = dict(payload or {})
    availability = str(payload.get("availability") or "unavailable").lower()
    if availability not in {"available", "stale", "unavailable"}:
        availability = "unavailable"

    def source(name):
        value = str(payload.get(name) or "unknown").lower()
        return value if value in {"available", "unavailable", "unknown"} else "unknown"

    age = payload.get("age_seconds")
    try:
        age = None if age is None else max(0.0, float(age))
    except (TypeError, ValueError):
        age = None
    return {
        "availability": availability,
        "dns_source": source("dns_source"),
        "ipfix_source": source("ipfix_source"),
        "age_seconds": age,
        "observed_at": payload.get("observed_at"),
    }


def build_policy_correlation_report(
    *,
    device_ip,
    device_name,
    history,
    usage,
    start,
    end,
    timezone_name,
    identity=None,
    collection_status=None,
):
    identity = dict(identity or {})
    identity_id = str(identity.get("identity_id") or "")
    managed_since = identity.get("managed_since")

    scoped_history = list(history or [])
    if identity_id:
        # Never mix legacy or another physical-management epoch into a current
        # identity report even if the address is identical.
        scoped_history = [
            dict(item) for item in scoped_history
            if str(item.get("identity_id") or "") == identity_id
        ]

    intervals = build_policy_intervals(
        scoped_history,
        start,
        end,
        identity_start=managed_since,
    )
    usage_by_index = {
        int(item.get("index", -1)): dict(item) for item in usage or []
    }

    total_seconds = max((_parse(end) - _parse(start)).total_seconds(), 1)
    known_seconds = 0.0
    identity_known_seconds = 0.0
    mode_bytes = {"normal": 0, "slow": 0, "blocked": 0, "unknown": 0}
    total_bytes = 0
    current_identity_bytes = 0
    identity_unproven_bytes = 0
    total_dns_blocked = 0
    state_changes = 0
    previous_hash = None
    traffic_statuses = []
    dns_statuses = []

    for index, interval in enumerate(intervals):
        start_dt = _parse(interval["start"])
        end_dt = _parse(interval["end"])
        duration_seconds = max((end_dt - start_dt).total_seconds(), 0)
        interval["index"] = index
        interval["duration_minutes"] = round(duration_seconds / 60, 1)
        interval["local_start"] = _local(start_dt, timezone_name)
        interval["local_end"] = _local(end_dt, timezone_name)

        evidence = usage_by_index.get(index, {})
        interval["usage"] = evidence
        traffic_status = str(
            evidence.get("traffic_evidence_status") or "no_evidence"
        ).lower()
        dns_status = str(
            evidence.get("dns_evidence_status") or "no_evidence"
        ).lower()
        traffic_statuses.append(traffic_status)
        dns_statuses.append(dns_status)

        bytes_value = _safe_int(evidence.get("total_bytes"))
        blocked_value = _safe_int(evidence.get("dns_blocked"))
        total_bytes += bytes_value
        total_dns_blocked += blocked_value

        if interval.get("identity_known"):
            identity_known_seconds += duration_seconds
            current_identity_bytes += bytes_value
        else:
            identity_unproven_bytes += bytes_value

        if interval.get("known") and interval.get("state"):
            known_seconds += duration_seconds
            state = interval["state"]
            mode = str(state.get("desired_mode") or "unknown").lower()
            if mode not in mode_bytes:
                mode = "unknown"
            mode_bytes[mode] += bytes_value
            current_hash = interval.get("state_hash")
            if previous_hash is not None and current_hash != previous_hash:
                state_changes += 1
            previous_hash = current_hash
            interval["historical_name"] = str(
                state.get("device_name") or device_name or device_ip
            )
        else:
            mode_bytes["unknown"] += bytes_value
            interval["historical_name"] = (
                str(identity.get("current_name") or device_name or device_ip)
                if interval.get("identity_known")
                else ""
            )

        interval["policy_evidence_kind"] = (
            "desired_policy_checkpoint" if interval.get("known") else "none"
        )
        interval["routeros_execution_proof"] = "not_recorded"

    coverage_percent = round(known_seconds * 100 / total_seconds, 1)
    identity_coverage_percent = round(
        identity_known_seconds * 100 / total_seconds, 1
    )
    known_intervals = [item for item in intervals if item.get("known")]

    checkpoint_instants = [
        _parse(item.get("captured_at")) for item in scoped_history
        if item.get("captured_at")
    ]
    first_checkpoint = (
        min(checkpoint_instants).isoformat() if checkpoint_instants else None
    )
    last_checkpoint = (
        max(checkpoint_instants).isoformat() if checkpoint_instants else None
    )

    traffic_evidence_status = _aggregate_source_status(traffic_statuses)
    dns_evidence_status = _aggregate_source_status(dns_statuses)
    telemetry_evidence_status = _aggregate_telemetry_status(
        traffic_evidence_status, dns_evidence_status
    )

    return {
        "schema": "zen_policy_correlation_v1",
        "device": {"ip": str(device_ip), "name": str(device_name or device_ip)},
        "identity": {
            "identity_id": identity_id or None,
            "managed_since": (
                _parse(managed_since).isoformat() if managed_since else None
            ),
            "current_name": str(identity.get("current_name") or ""),
            "scope": "current_management_identity" if identity_id else "ip_only",
        },
        "start": _parse(start).isoformat(),
        "end": _parse(end).isoformat(),
        "timezone": timezone_name,
        "coverage_percent": coverage_percent,
        "identity_coverage_percent": identity_coverage_percent,
        "policy_evidence_complete": coverage_percent >= 99.9,
        "identity_evidence_complete": identity_coverage_percent >= 99.9,
        "known_intervals": len(known_intervals),
        "unknown_intervals": len(intervals) - len(known_intervals),
        "identity_unproven_intervals": sum(
            1 for item in intervals if not item.get("identity_known")
        ),
        "state_changes": state_changes,
        "first_checkpoint": first_checkpoint,
        "last_checkpoint": last_checkpoint,
        "total_bytes": total_bytes,
        "current_identity_bytes": current_identity_bytes,
        "identity_unproven_bytes": identity_unproven_bytes,
        "total_dns_blocked": total_dns_blocked,
        "mode_bytes": mode_bytes,
        "traffic_evidence_status": traffic_evidence_status,
        "dns_evidence_status": dns_evidence_status,
        "telemetry_evidence_status": telemetry_evidence_status,
        "current_collection_status": _collection_status(collection_status),
        "policy_evidence_kind": "desired_policy_checkpoint",
        "routeros_execution_proof": "not_recorded",
        "historical_enforcement_proven": False,
        "intervals": intervals,
        "evidence_note": (
            "Policy checkpoints are captured by ZEN's real effective-policy resolver. "
            "They prove desired policy observed by ZEN, not historical RouterOS execution. "
            "v0.49 binds new checkpoints to the current management identity; retained "
            "evidence before that identity boundary remains IP-scoped and unproven. "
            "Legacy pre-v0.49 history is never back-bound to a current physical device."
        ),
    }
