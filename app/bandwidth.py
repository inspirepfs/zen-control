"""Shared bandwidth-rate helpers for policy and RouterOS reconciliation."""

from __future__ import annotations

import re
from decimal import Decimal, InvalidOperation


_RATE_RE = re.compile(r"^(?P<number>\d+(?:\.\d+)?)(?P<suffix>[kKmMgG]?)$")
_RATE_FACTORS = {
    "": Decimal(1),
    "k": Decimal(1_000),
    "m": Decimal(1_000_000),
    "g": Decimal(1_000_000_000),
}


class BandwidthRateError(ValueError):
    pass


def parse_rate_bps(value: str) -> int:
    """Parse a RouterOS-style finite rate such as 128k, 2M or 1000000."""
    raw = str(value or "").strip()
    match = _RATE_RE.fullmatch(raw)
    if not match:
        raise BandwidthRateError(
            f"Invalid bandwidth rate '{raw}'. Use values such as 128k, 2M or 100M."
        )

    try:
        number = Decimal(match.group("number"))
    except InvalidOperation as exc:
        raise BandwidthRateError(f"Invalid bandwidth rate '{raw}'") from exc

    if number <= 0:
        raise BandwidthRateError("Bandwidth rates must be greater than zero")

    factor = _RATE_FACTORS[match.group("suffix").lower()]
    bps = number * factor
    if bps != bps.to_integral_value():
        raise BandwidthRateError(
            f"Bandwidth rate '{raw}' does not resolve to a whole bit-per-second value"
        )

    return int(bps)


def normalize_rate(value: str) -> str:
    """Validate and return a compact canonical finite rate label."""
    raw = str(value or "").strip()
    bps = parse_rate_bps(raw)

    # Preserve compact human-friendly units where the value is an exact unit.
    for suffix, factor in (("G", 1_000_000_000), ("M", 1_000_000), ("k", 1_000)):
        if bps >= factor and bps % factor == 0:
            return f"{bps // factor}{suffix}"
    return str(bps)


def build_max_limit(upload: str, download: str) -> str:
    """Build RouterOS simple-queue max-limit in upload/download order."""
    return f"{normalize_rate(upload)}/{normalize_rate(download)}"


def parse_max_limit(value: str) -> tuple[int, int]:
    raw = str(value or "").strip()
    parts = raw.split("/")
    if len(parts) != 2:
        raise BandwidthRateError(
            f"Invalid RouterOS max-limit '{raw}'; expected upload/download"
        )
    return parse_rate_bps(parts[0]), parse_rate_bps(parts[1])


def limits_equal(left: str | None, right: str | None) -> bool:
    if not left or not right:
        return left == right
    try:
        return parse_max_limit(left) == parse_max_limit(right)
    except BandwidthRateError:
        return False
