"""Deterministic household wall-clock handling for ZEN policy decisions.

Recurring parental-control schedules are expressed as local wall times.  DST can
make a wall time ambiguous (autumn fold) or nonexistent (spring gap).  This
module makes that behaviour explicit and reusable across policy, simulation,
activity and quota windows.
"""

from __future__ import annotations

from datetime import date, datetime, time as dt_time, timedelta, timezone
from zoneinfo import ZoneInfo

UTC = timezone.utc


def utc_instant(value: datetime) -> datetime:
    """Return an aware datetime normalized to UTC for absolute comparisons."""
    if value.tzinfo is None:
        raise ValueError("Policy time comparison requires an aware datetime")
    return value.astimezone(UTC)


def _valid_wall_candidates(naive: datetime, zone: ZoneInfo) -> list[datetime]:
    candidates: list[datetime] = []
    seen_instants = set()
    for fold in (0, 1):
        aware = naive.replace(tzinfo=zone, fold=fold)
        instant = aware.astimezone(UTC)
        round_trip = instant.astimezone(zone)
        if round_trip.replace(tzinfo=None) != naive:
            continue
        marker = instant.isoformat()
        if marker in seen_instants:
            continue
        seen_instants.add(marker)
        candidates.append(aware)
    return sorted(candidates, key=utc_instant)


def resolve_local_wall_time(
    day: date,
    clock: dt_time,
    zone: ZoneInfo,
    *,
    gap_limit_minutes: int = 180,
) -> tuple[datetime, dict]:
    """Resolve one local wall time to a real instant.

    Policy contract:
    * ordinary time -> exact local wall time;
    * autumn fold -> first physical occurrence (earliest UTC instant);
    * spring gap -> first valid local instant after the gap.

    Metadata is returned so callers can surface adjustments instead of hiding
    them from explainability/simulation output.
    """
    naive = datetime.combine(day, clock.replace(tzinfo=None))
    candidates = _valid_wall_candidates(naive, zone)
    if candidates:
        chosen = candidates[0]
        ambiguous = len(candidates) > 1
        return chosen, {
            "requested_local": naive.isoformat(timespec="minutes"),
            "resolved_local": chosen.isoformat(timespec="minutes"),
            "adjusted": False,
            "kind": "ambiguous_first" if ambiguous else "exact",
            "ambiguous": ambiguous,
            "nonexistent": False,
        }

    # Nonexistent local time.  Execute at the first valid local instant after
    # the DST gap rather than silently manufacturing an impossible timestamp.
    for minutes in range(1, max(1, int(gap_limit_minutes)) + 1):
        probe = naive + timedelta(minutes=minutes)
        candidates = _valid_wall_candidates(probe, zone)
        if candidates:
            chosen = candidates[0]
            return chosen, {
                "requested_local": naive.isoformat(timespec="minutes"),
                "resolved_local": chosen.isoformat(timespec="minutes"),
                "adjusted": True,
                "kind": "nonexistent_forward",
                "ambiguous": False,
                "nonexistent": True,
                "shift_minutes": minutes,
            }
    raise ValueError(
        f"Unable to resolve local policy time {naive.isoformat(timespec='minutes')} "
        f"in timezone {zone.key}"
    )


def local_midnight(day: date, zone: ZoneInfo) -> tuple[datetime, dict]:
    return resolve_local_wall_time(day, dt_time.min, zone)


def normalize_policy_datetime(value, zone: ZoneInfo) -> tuple[datetime, dict]:
    """Normalize a policy/simulation datetime into the configured zone."""
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except ValueError as exc:
            raise ValueError("Policy date/time must be ISO formatted") from exc
    if not isinstance(value, datetime):
        raise ValueError("Unsupported policy date/time value")
    if value.tzinfo is not None:
        local = value.astimezone(zone)
        return local, {
            "requested_local": local.replace(tzinfo=None).isoformat(timespec="minutes"),
            "resolved_local": local.isoformat(timespec="minutes"),
            "adjusted": False,
            "kind": "absolute",
            "ambiguous": bool(local.fold),
            "nonexistent": False,
        }
    return resolve_local_wall_time(value.date(), value.time(), zone)
