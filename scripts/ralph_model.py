#!/usr/bin/env python3
"""Project-local live model selection for RALPH-Lite.

The selected model is intentionally stored under .ralph instead of rewriting the
user's global Codex config. RALPH reloads it for every new Codex process, so a
web change affects the next model turn without mutating an in-flight turn.
"""
from __future__ import annotations

import datetime as dt
import json
import os
from pathlib import Path
from typing import Any

SCHEMA = "zen_ralph_model_policy_v1"
FILENAME = "model-policy.json"


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def policy_path(root: Path) -> Path:
    return Path(root) / ".ralph" / FILENAME


def normalize_policy(raw: dict[str, Any] | None) -> dict[str, Any]:
    source = dict(raw or {})
    model = source.get("model")
    if model is not None:
        model = str(model).strip()
        if not model:
            model = None
        elif len(model) > 160 or any(ch.isspace() for ch in model):
            raise ValueError("model must be a single model identifier up to 160 characters")
    try:
        revision = max(1, int(source.get("revision") or 1))
    except (TypeError, ValueError):
        revision = 1
    return {
        "schema": SCHEMA,
        "model": model,
        "revision": revision,
        "updated_at": source.get("updated_at") if isinstance(source.get("updated_at"), str) else None,
    }


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


def save_policy(root: Path, model: str | None) -> dict[str, Any]:
    path = policy_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    current = load_policy(root)
    candidate = normalize_policy({
        "model": model,
        "revision": int(current.get("revision") or 1) + 1,
        "updated_at": _utc_now(),
    })
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(candidate, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, path)
    return candidate
