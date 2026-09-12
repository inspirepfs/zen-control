"""Daily telemetry-backed quota helpers.

Quotas deliberately account bytes, not guessed screen time. Aggregate policy-group
quotas sum the concrete classified services in a group; they still do not invent
active/screen-time semantics.
"""

from app.policy_groups import POLICY_GROUP_KEYS, POLICY_GROUPS, group_name
from app.service_catalog import SERVICE_ENFORCEMENT, SUPPORTED_SERVICE_KEYS

MIB = 1024 * 1024
VALID_QUOTA_ACTIONS = {"slow", "blocked"}


def normalize_quota_mb(value, *, field="quota"):
    if value in (None, "", 0, "0"):
        return 0
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be a whole number of MiB") from exc
    if number < 0 or number > 1_048_576:
        raise ValueError(f"{field} must be between 0 and 1048576 MiB")
    return number


def normalize_quota_action(value):
    value = str(value or "blocked").strip().lower()
    if value not in VALID_QUOTA_ACTIONS:
        raise ValueError("Daily quota action must be slow or blocked")
    return value


def quota_key_name(key):
    if key in SERVICE_ENFORCEMENT:
        return SERVICE_ENFORCEMENT[key]["name"]
    if key in POLICY_GROUPS:
        return group_name(key)
    return key


def normalize_service_quotas(values, supported_service_keys=None):
    """Validate concrete service or live policy-group -> MiB mappings."""
    result = {}
    allowed = frozenset(supported_service_keys or SUPPORTED_SERVICE_KEYS) | POLICY_GROUP_KEYS
    for key, raw in (values or {}).items():
        key = str(key or "").strip().lower()
        if key not in allowed:
            if raw not in (None, "", 0, "0"):
                raise ValueError(
                    f"Service/group quota '{key}' is not backed by a live policy contract"
                )
            continue
        amount = normalize_quota_mb(raw, field=f"{quota_key_name(key)} quota")
        if amount:
            result[key] = amount
    return dict(sorted(result.items()))


def service_quota_pairs(keys, amounts, supported_service_keys=None):
    keys = list(keys or [])
    amounts = list(amounts or [])
    if len(keys) != len(amounts):
        raise ValueError("Service quota form is malformed")
    return normalize_service_quotas(
        dict(zip(keys, amounts)), supported_service_keys=supported_service_keys
    )


def bytes_for_mb(value):
    return int(value or 0) * MIB


def percent_used(used_bytes, limit_mb):
    limit = bytes_for_mb(limit_mb)
    if not limit:
        return 0.0
    return round(min(999.9, (int(used_bytes or 0) * 100.0) / limit), 1)


def format_bytes(value):
    number = float(int(value or 0))
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if number < 1024 or unit == "TiB":
            return f"{int(number)} {unit}" if unit == "B" else f"{number:.1f} {unit}"
        number /= 1024


def telemetry_name_to_key(name, service_defs=None):
    wanted = str(name or "").strip().casefold()
    if service_defs is not None:
        for item in service_defs:
            key = str(item.get("key") or "").strip().lower()
            display = str(item.get("name") or "").strip().casefold()
            if key and wanted in {key.casefold(), display}:
                return key
    for key, item in SERVICE_ENFORCEMENT.items():
        if item["name"].casefold() == wanted:
            return key
    return None
