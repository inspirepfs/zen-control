#!/usr/bin/env python3
"""Shared live efficiency policy for RALPH-Lite.

The policy is deliberately stored separately from controller state so an operator
can tune resource controls while an active RALPH process is updating state.json.
Every write is atomic and every model turn/efficiency decision may reload it.
"""
from __future__ import annotations

import datetime as dt
import json
import os
from pathlib import Path
from typing import Any

SCHEMA = "zen_ralph_efficiency_policy_v2"
MODES = ("STRICT", "NORMAL", "RELAXED", "OFF")
FILENAME = "efficiency-policy.json"

DEFAULT_POLICY: dict[str, Any] = {
    "schema": SCHEMA,
    "mode": "NORMAL",
    "reserve_percent": 5.0,
    "strict_prompt_command_budget": 4,
    "strict_max_commands": 6,
    "strict_max_reported_files": 6,
    "strict_max_cumulative_input": 450_000,
    "strict_max_noncached_input": 75_000,
    "normal_prompt_command_budget": 6,
    "normal_max_commands": 8,
    "normal_max_reported_files": 8,
    "normal_max_cumulative_input": 600_000,
    "normal_max_noncached_input": 100_000,
    "relaxed_prompt_command_budget": 12,
    "relaxed_max_commands": 32,
    "relaxed_max_reported_files": 32,
    "relaxed_max_cumulative_input": 2_400_000,
    "relaxed_max_noncached_input": 400_000,
    "runaway_max_commands": 40,
    "runaway_max_reported_files": 64,
    "runaway_max_cumulative_input": 3_000_000,
    "runaway_max_noncached_input": 500_000,
    "revision": 1,
    "updated_at": None,
}

_LIMIT_SUFFIXES = (
    "prompt_command_budget",
    "max_commands",
    "max_reported_files",
    "max_cumulative_input",
    "max_noncached_input",
)
_EDITABLE = {
    "mode",
    "reserve_percent",
    *(f"{prefix}_{suffix}" for prefix in ("strict", "normal", "relaxed") for suffix in _LIMIT_SUFFIXES),
    "runaway_max_commands",
    "runaway_max_reported_files",
    "runaway_max_cumulative_input",
    "runaway_max_noncached_input",
}


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def policy_path(root: Path) -> Path:
    return Path(root) / ".ralph" / FILENAME


def defaults() -> dict[str, Any]:
    return dict(DEFAULT_POLICY)


def _number(value: Any, name: str, *, minimum: float, maximum: float, integer: bool = False) -> int | float:
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be numeric") from exc
    if not minimum <= number <= maximum:
        raise ValueError(f"{name} must be between {minimum:g} and {maximum:g}")
    if integer:
        if not number.is_integer():
            raise ValueError(f"{name} must be an integer")
        return int(number)
    return float(number)


def _migrate_v1(source: dict[str, Any]) -> dict[str, Any]:
    """Translate the previous normal+multiplier layout into explicit per-mode limits."""
    migrated = dict(source)
    if not any(key.startswith("strict_") and key != "strict_multiplier" for key in source):
        try:
            strict = float(source.get("strict_multiplier", 0.75))
        except (TypeError, ValueError):
            strict = 0.75
        for suffix in _LIMIT_SUFFIXES:
            legacy_key = "prompt_command_budget" if suffix == "prompt_command_budget" else f"normal_{suffix}"
            base = source.get(legacy_key, DEFAULT_POLICY[f"normal_{suffix}"])
            try:
                value = float(base) * strict
            except (TypeError, ValueError):
                value = float(DEFAULT_POLICY[f"strict_{suffix}"])
            migrated[f"strict_{suffix}"] = max(1, int(value))
    if not any(key.startswith("relaxed_") and key != "relaxed_multiplier" for key in source):
        try:
            relaxed = float(source.get("relaxed_multiplier", 4.0))
        except (TypeError, ValueError):
            relaxed = 4.0
        for suffix in _LIMIT_SUFFIXES:
            legacy_key = "prompt_command_budget" if suffix == "prompt_command_budget" else f"normal_{suffix}"
            base = source.get(legacy_key, DEFAULT_POLICY[f"normal_{suffix}"])
            try:
                value = float(base) * relaxed
            except (TypeError, ValueError):
                value = float(DEFAULT_POLICY[f"relaxed_{suffix}"])
            migrated[f"relaxed_{suffix}"] = max(1, int(value))
    if "normal_prompt_command_budget" not in migrated and "prompt_command_budget" in source:
        migrated["normal_prompt_command_budget"] = source["prompt_command_budget"]
    return migrated


def normalize_policy(raw: dict[str, Any] | None) -> dict[str, Any]:
    source = _migrate_v1(dict(raw or {}))
    merged = defaults()
    merged.update({key: source[key] for key in _EDITABLE if key in source})

    mode = str(merged.get("mode") or "NORMAL").upper()
    if mode not in MODES:
        raise ValueError(f"mode must be one of {', '.join(MODES)}")
    merged["mode"] = mode
    merged["reserve_percent"] = _number(merged["reserve_percent"], "reserve_percent", minimum=0.0, maximum=50.0)

    for prefix in ("strict", "normal", "relaxed"):
        merged[f"{prefix}_prompt_command_budget"] = _number(
            merged[f"{prefix}_prompt_command_budget"], f"{prefix}_prompt_command_budget", minimum=1, maximum=100, integer=True
        )
        merged[f"{prefix}_max_commands"] = _number(
            merged[f"{prefix}_max_commands"], f"{prefix}_max_commands", minimum=1, maximum=200, integer=True
        )
        merged[f"{prefix}_max_reported_files"] = _number(
            merged[f"{prefix}_max_reported_files"], f"{prefix}_max_reported_files", minimum=1, maximum=500, integer=True
        )
        merged[f"{prefix}_max_cumulative_input"] = _number(
            merged[f"{prefix}_max_cumulative_input"], f"{prefix}_max_cumulative_input", minimum=1_000, maximum=50_000_000, integer=True
        )
        merged[f"{prefix}_max_noncached_input"] = _number(
            merged[f"{prefix}_max_noncached_input"], f"{prefix}_max_noncached_input", minimum=1_000, maximum=25_000_000, integer=True
        )

    merged["runaway_max_commands"] = _number(merged["runaway_max_commands"], "runaway_max_commands", minimum=1, maximum=2_000, integer=True)
    merged["runaway_max_reported_files"] = _number(merged["runaway_max_reported_files"], "runaway_max_reported_files", minimum=1, maximum=5_000, integer=True)
    merged["runaway_max_cumulative_input"] = _number(merged["runaway_max_cumulative_input"], "runaway_max_cumulative_input", minimum=1_000, maximum=250_000_000, integer=True)
    merged["runaway_max_noncached_input"] = _number(merged["runaway_max_noncached_input"], "runaway_max_noncached_input", minimum=1_000, maximum=100_000_000, integer=True)

    required = {
        "runaway_max_commands": max(int(merged[f"{prefix}_max_commands"]) for prefix in ("strict", "normal", "relaxed")),
        "runaway_max_reported_files": max(int(merged[f"{prefix}_max_reported_files"]) for prefix in ("strict", "normal", "relaxed")),
        "runaway_max_cumulative_input": max(int(merged[f"{prefix}_max_cumulative_input"]) for prefix in ("strict", "normal", "relaxed")),
        "runaway_max_noncached_input": max(int(merged[f"{prefix}_max_noncached_input"]) for prefix in ("strict", "normal", "relaxed")),
    }
    for name, floor in required.items():
        if int(merged[name]) < floor:
            raise ValueError(f"{name} must be >= {floor} so the emergency ceiling does not undercut an enabled efficiency mode")

    merged["schema"] = SCHEMA
    try:
        merged["revision"] = max(1, int(source.get("revision") or 1))
    except (TypeError, ValueError):
        merged["revision"] = 1
    merged["updated_at"] = source.get("updated_at") if isinstance(source.get("updated_at"), str) else None
    return merged


def load_policy(root: Path) -> dict[str, Any]:
    path = policy_path(root)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return normalize_policy(None)
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"cannot read {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise RuntimeError(f"{path} must contain a JSON object")
    try:
        return normalize_policy(raw)
    except ValueError as exc:
        raise RuntimeError(f"invalid {path}: {exc}") from exc


def save_policy(root: Path, values: dict[str, Any], *, replace: bool = False) -> dict[str, Any]:
    path = policy_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    current = normalize_policy(None) if replace else load_policy(root)
    candidate = defaults() if replace else dict(current)
    for key, value in dict(values or {}).items():
        if key in _EDITABLE:
            candidate[key] = value
    candidate["revision"] = int(current.get("revision") or 1) + 1
    candidate["updated_at"] = _utc_now()
    policy = normalize_policy(candidate)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(policy, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, path)
    return policy


def ensure_policy(root: Path) -> dict[str, Any]:
    path = policy_path(root)
    if path.exists():
        return load_policy(root)
    return save_policy(root, {}, replace=True)


def limits(policy: dict[str, Any], mode: str | None = None) -> dict[str, int]:
    policy = normalize_policy(policy)
    selected = str(mode or policy["mode"]).upper()
    if selected not in MODES:
        raise ValueError(f"mode must be one of {', '.join(MODES)}")
    prefix = "normal" if selected == "OFF" else selected.lower()
    return {
        "prompt_commands": int(policy[f"{prefix}_prompt_command_budget"]),
        "commands": int(policy[f"{prefix}_max_commands"]),
        "files": int(policy[f"{prefix}_max_reported_files"]),
        "cumulative": int(policy[f"{prefix}_max_cumulative_input"]),
        "noncached": int(policy[f"{prefix}_max_noncached_input"]),
    }


def runaway_limits(policy: dict[str, Any]) -> dict[str, int]:
    policy = normalize_policy(policy)
    return {
        "commands": int(policy["runaway_max_commands"]),
        "files": int(policy["runaway_max_reported_files"]),
        "cumulative": int(policy["runaway_max_cumulative_input"]),
        "noncached": int(policy["runaway_max_noncached_input"]),
    }
