#!/usr/bin/env python3
"""Project-local live model and reasoning-effort selection for RALPH-Lite.

The selected model/effort is intentionally stored under .ralph instead of
rewriting the user's global Codex config. RALPH reloads it for every new Codex
process, so web changes affect the next model turn without mutating an in-flight
turn.
"""
from __future__ import annotations

import datetime as dt
import json
import os
from pathlib import Path
from typing import Any

SCHEMA = "zen_ralph_model_policy_v2"
FILENAME = "model-policy.json"
_UNSET = object()


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def policy_path(root: Path, runtime_directory: Path | None = None) -> Path:
    return Path(runtime_directory) / FILENAME if runtime_directory is not None else Path(root) / ".ralph" / FILENAME


def _normalise_effort(value: Any) -> str | None:
    if value is None:
        return None
    effort = str(value).strip().lower()
    if not effort:
        return None
    if len(effort) > 32 or not all(ch.isalnum() or ch in "_-" for ch in effort):
        raise ValueError("reasoning_effort must be a single identifier up to 32 characters")
    return effort


def normalize_policy(raw: dict[str, Any] | None) -> dict[str, Any]:
    source = dict(raw or {})
    model = source.get("model")
    if model is not None:
        model = str(model).strip()
        if not model:
            model = None
        elif len(model) > 160 or any(ch.isspace() for ch in model):
            raise ValueError("model must be a single model identifier up to 160 characters")
    effort = _normalise_effort(source.get("reasoning_effort"))
    try:
        revision = max(1, int(source.get("revision") or 1))
    except (TypeError, ValueError):
        revision = 1
    return {
        "schema": SCHEMA,
        "model": model,
        "reasoning_effort": effort,
        "revision": revision,
        "updated_at": source.get("updated_at") if isinstance(source.get("updated_at"), str) else None,
    }


def load_policy(root: Path, *, runtime_directory: Path | None = None) -> dict[str, Any]:
    path = policy_path(root, runtime_directory)
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


def save_policy(
    root: Path,
    model: str | None | object = _UNSET,
    *,
    reasoning_effort: str | None | object = _UNSET,
    runtime_directory: Path | None = None,
) -> dict[str, Any]:
    """Atomically update one or both project-local Codex selections.

    Unspecified fields are preserved. Passing None explicitly clears that
    override and returns control to the user's Codex configuration.
    """
    path = policy_path(root, runtime_directory)
    path.parent.mkdir(parents=True, exist_ok=True)
    current = load_policy(root, runtime_directory=runtime_directory)
    next_model = current.get("model") if model is _UNSET else model
    next_effort = current.get("reasoning_effort") if reasoning_effort is _UNSET else reasoning_effort
    candidate = normalize_policy({
        "model": next_model,
        "reasoning_effort": next_effort,
        "revision": int(current.get("revision") or 1) + 1,
        "updated_at": _utc_now(),
    })
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(candidate, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, path)
    return candidate
